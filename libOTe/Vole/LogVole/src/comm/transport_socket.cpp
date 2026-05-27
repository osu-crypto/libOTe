#include "channel_impl_factory.hpp"

#include <chrono>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <utility>

#if defined(_WIN32)

namespace loglabel::comm
{
    protocol_result<any_channel> make_uds_channel_impl(const channel_config &)
    {
        return protocol_result<any_channel>::failure(
            protocol_errc::unsupported_transport, "UDS transport is not supported on Windows");
    }

    protocol_result<any_channel> make_tcp_channel_impl(const channel_config &)
    {
        return protocol_result<any_channel>::failure(
            protocol_errc::unsupported_transport, "TCP transport is not implemented for Windows in this module");
    }

} // namespace loglabel::comm

#else

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace loglabel::comm
{
    namespace
    {
        class fd_guard
        {
        public:
            fd_guard() = default;
            explicit fd_guard(int fd) : fd_(fd)
            {}

            fd_guard(const fd_guard &) = delete;
            fd_guard &operator=(const fd_guard &) = delete;

            fd_guard(fd_guard &&other) noexcept : fd_(other.fd_)
            {
                other.fd_ = -1;
            }

            fd_guard &operator=(fd_guard &&other) noexcept
            {
                if (this != &other)
                {
                    reset();
                    fd_ = other.fd_;
                    other.fd_ = -1;
                }
                return *this;
            }

            ~fd_guard()
            {
                reset();
            }

            int get() const
            {
                return fd_;
            }

            int release()
            {
                int fd = fd_;
                fd_ = -1;
                return fd;
            }

            void reset(int new_fd = -1)
            {
                if (fd_ >= 0)
                {
                    close(fd_);
                }
                fd_ = new_fd;
            }

        private:
            int fd_ = -1;
        };

        protocol_result<void> write_all(int fd, const std::uint8_t *data, std::size_t length)
        {
            std::size_t sent = 0;
            while (sent < length)
            {
                const auto n = ::send(fd, data + sent, length - sent, 0);
                if (n < 0)
                {
                    if (errno == EINTR)
                    {
                        continue;
                    }
                    return protocol_result<void>::failure(protocol_errc::io_error, "socket send failed");
                }
                if (n == 0)
                {
                    return protocol_result<void>::failure(protocol_errc::io_error, "socket send returned zero");
                }
                sent += static_cast<std::size_t>(n);
            }
            return protocol_result<void>::success();
        }

        protocol_result<void> wait_for_read_ready(int fd, std::chrono::milliseconds timeout)
        {
            struct pollfd pfd
            {
            };
            pfd.fd = fd;
            pfd.events = POLLIN;
            pfd.revents = 0;

            const int timeout_ms = timeout.count() < 0 ? -1 : static_cast<int>(timeout.count());
            int rc = 0;
            do
            {
                rc = ::poll(&pfd, 1, timeout_ms);
            } while (rc < 0 && errno == EINTR);

            if (rc == 0)
            {
                return protocol_result<void>::failure(protocol_errc::timeout, "socket receive timeout");
            }
            if (rc < 0)
            {
                return protocol_result<void>::failure(protocol_errc::io_error, "poll failed");
            }
            if ((pfd.revents & POLLIN) == 0)
            {
                return protocol_result<void>::failure(protocol_errc::io_error, "socket not readable");
            }
            return protocol_result<void>::success();
        }

        protocol_result<void> read_exact(int fd, std::uint8_t *data, std::size_t length, std::chrono::milliseconds timeout)
        {
            auto deadline = std::chrono::steady_clock::now() + timeout;
            std::size_t read_total = 0;

            while (read_total < length)
            {
                auto remaining = timeout;
                if (timeout.count() >= 0)
                {
                    const auto now = std::chrono::steady_clock::now();
                    if (now >= deadline)
                    {
                        return protocol_result<void>::failure(protocol_errc::timeout, "socket receive timeout");
                    }
                    remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
                }

                auto ready = wait_for_read_ready(fd, remaining);
                if (!ready)
                {
                    return ready;
                }

                const auto n = ::recv(fd, data + read_total, length - read_total, 0);
                if (n < 0)
                {
                    if (errno == EINTR)
                    {
                        continue;
                    }
                    return protocol_result<void>::failure(protocol_errc::io_error, "socket recv failed");
                }
                if (n == 0)
                {
                    return protocol_result<void>::failure(protocol_errc::io_error, "socket closed by peer");
                }
                read_total += static_cast<std::size_t>(n);
            }

            return protocol_result<void>::success();
        }

        protocol_result<int> connect_uds(const std::string &path, std::chrono::milliseconds timeout)
        {
            fd_guard fd(::socket(AF_UNIX, SOCK_STREAM, 0));
            if (fd.get() < 0)
            {
                return protocol_result<int>::failure(protocol_errc::io_error, "failed to create uds socket");
            }

            struct sockaddr_un addr
            {
            };
            std::memset(&addr, 0, sizeof(addr));
            addr.sun_family = AF_UNIX;

            if (path.size() >= sizeof(addr.sun_path))
            {
                return protocol_result<int>::failure(protocol_errc::config_error, "uds socket path too long");
            }
            std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);

            const auto start = std::chrono::steady_clock::now();
            while (true)
            {
                if (::connect(fd.get(), reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) == 0)
                {
                    return protocol_result<int>::success(fd.release());
                }

                if (errno != ENOENT && errno != ECONNREFUSED)
                {
                    return protocol_result<int>::failure(protocol_errc::io_error, "uds connect failed");
                }

                if (timeout.count() >= 0 &&
                    std::chrono::steady_clock::now() - start >= timeout)
                {
                    return protocol_result<int>::failure(protocol_errc::timeout, "uds connect timeout");
                }

                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        }

        protocol_result<int> accept_uds(const std::string &path)
        {
            fd_guard listen_fd(::socket(AF_UNIX, SOCK_STREAM, 0));
            if (listen_fd.get() < 0)
            {
                return protocol_result<int>::failure(protocol_errc::io_error, "failed to create uds listen socket");
            }

            ::unlink(path.c_str());

            struct sockaddr_un addr
            {
            };
            std::memset(&addr, 0, sizeof(addr));
            addr.sun_family = AF_UNIX;

            if (path.size() >= sizeof(addr.sun_path))
            {
                return protocol_result<int>::failure(protocol_errc::config_error, "uds socket path too long");
            }
            std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);

            if (::bind(listen_fd.get(), reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) != 0)
            {
                return protocol_result<int>::failure(protocol_errc::io_error, "uds bind failed");
            }

            if (::listen(listen_fd.get(), 1) != 0)
            {
                return protocol_result<int>::failure(protocol_errc::io_error, "uds listen failed");
            }

            const int accepted_fd = ::accept(listen_fd.get(), nullptr, nullptr);
            if (accepted_fd < 0)
            {
                return protocol_result<int>::failure(protocol_errc::io_error, "uds accept failed");
            }

            return protocol_result<int>::success(accepted_fd);
        }

        protocol_result<int> connect_tcp(const std::string &host, std::uint16_t port, std::chrono::milliseconds timeout)
        {
            fd_guard fd(::socket(AF_INET, SOCK_STREAM, 0));
            if (fd.get() < 0)
            {
                return protocol_result<int>::failure(protocol_errc::io_error, "failed to create tcp socket");
            }

            struct sockaddr_in addr
            {
            };
            std::memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port);
            if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1)
            {
                return protocol_result<int>::failure(protocol_errc::config_error, "invalid tcp host");
            }

            const auto start = std::chrono::steady_clock::now();
            while (true)
            {
                if (::connect(fd.get(), reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) == 0)
                {
                    return protocol_result<int>::success(fd.release());
                }

                if (errno != ECONNREFUSED)
                {
                    return protocol_result<int>::failure(protocol_errc::io_error, "tcp connect failed");
                }

                if (timeout.count() >= 0 &&
                    std::chrono::steady_clock::now() - start >= timeout)
                {
                    return protocol_result<int>::failure(protocol_errc::timeout, "tcp connect timeout");
                }

                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        }

        protocol_result<int> accept_tcp(const std::string &host, std::uint16_t port)
        {
            fd_guard listen_fd(::socket(AF_INET, SOCK_STREAM, 0));
            if (listen_fd.get() < 0)
            {
                return protocol_result<int>::failure(protocol_errc::io_error, "failed to create tcp listen socket");
            }

            int opt = 1;
            if (::setsockopt(listen_fd.get(), SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) != 0)
            {
                return protocol_result<int>::failure(protocol_errc::io_error, "setsockopt(SO_REUSEADDR) failed");
            }

            struct sockaddr_in addr
            {
            };
            std::memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port);
            if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1)
            {
                return protocol_result<int>::failure(protocol_errc::config_error, "invalid tcp host");
            }

            if (::bind(listen_fd.get(), reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) != 0)
            {
                return protocol_result<int>::failure(protocol_errc::io_error, "tcp bind failed");
            }

            if (::listen(listen_fd.get(), 1) != 0)
            {
                return protocol_result<int>::failure(protocol_errc::io_error, "tcp listen failed");
            }

            const int accepted_fd = ::accept(listen_fd.get(), nullptr, nullptr);
            if (accepted_fd < 0)
            {
                return protocol_result<int>::failure(protocol_errc::io_error, "tcp accept failed");
            }

            return protocol_result<int>::success(accepted_fd);
        }

        class socket_channel_impl : public channel_interface
        {
        public:
            socket_channel_impl(channel_config config, int fd, std::string cleanup_path)
                : channel_interface(std::move(config)), fd_(fd), cleanup_path_(std::move(cleanup_path))
            {}

            ~socket_channel_impl() override
            {
                if (fd_.get() >= 0)
                {
                    fd_.reset();
                }
                if (!cleanup_path_.empty())
                {
                    ::unlink(cleanup_path_.c_str());
                }
            }

            protocol_result<void> send_frame(byte_buffer frame) override
            {
                if (frame.size() > config_.max_frame_size)
                {
                    return protocol_result<void>::failure(protocol_errc::config_error, "frame exceeds max_frame_size");
                }

                std::uint32_t length = static_cast<std::uint32_t>(frame.size());
                std::uint8_t prefix[4] = {
                    static_cast<std::uint8_t>(length & 0xFFu),
                    static_cast<std::uint8_t>((length >> 8u) & 0xFFu),
                    static_cast<std::uint8_t>((length >> 16u) & 0xFFu),
                    static_cast<std::uint8_t>((length >> 24u) & 0xFFu)
                };

                auto prefix_result = write_all(fd_.get(), prefix, sizeof(prefix));
                if (!prefix_result)
                {
                    return prefix_result;
                }

                if (!frame.empty())
                {
                    auto frame_result = write_all(fd_.get(), frame.data(), frame.size());
                    if (!frame_result)
                    {
                        return frame_result;
                    }
                }

                return protocol_result<void>::success();
            }

            protocol_result<byte_buffer> recv_frame() override
            {
                std::uint8_t prefix[4] = { 0, 0, 0, 0 };
                auto prefix_result = read_exact(fd_.get(), prefix, sizeof(prefix), config_.recv_timeout);
                if (!prefix_result)
                {
                    return protocol_result<byte_buffer>::failure(prefix_result.error(), prefix_result.message());
                }

                std::uint32_t length = static_cast<std::uint32_t>(prefix[0]) |
                                       (static_cast<std::uint32_t>(prefix[1]) << 8u) |
                                       (static_cast<std::uint32_t>(prefix[2]) << 16u) |
                                       (static_cast<std::uint32_t>(prefix[3]) << 24u);

                if (length > config_.max_frame_size)
                {
                    return protocol_result<byte_buffer>::failure(protocol_errc::decode_validation_failure,
                                                                 "incoming frame exceeds max_frame_size");
                }

                byte_buffer frame(length);
                if (length > 0)
                {
                    auto frame_result = read_exact(fd_.get(), frame.data(), frame.size(), config_.recv_timeout);
                    if (!frame_result)
                    {
                        return protocol_result<byte_buffer>::failure(frame_result.error(), frame_result.message());
                    }
                }

                return protocol_result<byte_buffer>::success(std::move(frame));
            }

        private:
            fd_guard fd_;
            std::string cleanup_path_;
        };

    } // namespace

    protocol_result<any_channel> make_uds_channel_impl(const channel_config &config)
    {
        if (config.kind != transport_kind::uds)
        {
            return protocol_result<any_channel>::failure(protocol_errc::config_error, "uds factory received wrong kind");
        }

        if (config.uds.socket_path.empty())
        {
            return protocol_result<any_channel>::failure(protocol_errc::config_error, "uds transport requires socket path");
        }

        protocol_result<int> socket_result = protocol_result<int>::failure(protocol_errc::io_error, "not initialized");
        std::string cleanup_path;

        if (config.uds.server)
        {
            socket_result = accept_uds(config.uds.socket_path);
            cleanup_path = config.uds.socket_path;
        }
        else
        {
            socket_result = connect_uds(config.uds.socket_path, config.recv_timeout);
        }

        if (!socket_result)
        {
            return protocol_result<any_channel>::failure(socket_result.error(), socket_result.message());
        }

        auto impl = std::make_unique<socket_channel_impl>(config, socket_result.value(), cleanup_path);
        return protocol_result<any_channel>::success(any_channel(std::move(impl)));
    }

    protocol_result<any_channel> make_tcp_channel_impl(const channel_config &config)
    {
        if (config.kind != transport_kind::tcp)
        {
            return protocol_result<any_channel>::failure(protocol_errc::config_error, "tcp factory received wrong kind");
        }

        if (config.tcp.host.empty())
        {
            return protocol_result<any_channel>::failure(protocol_errc::config_error, "tcp transport requires host");
        }

        if (config.tcp.port == 0)
        {
            return protocol_result<any_channel>::failure(protocol_errc::config_error, "tcp transport requires non-zero port");
        }

        protocol_result<int> socket_result = protocol_result<int>::failure(protocol_errc::io_error, "not initialized");

        if (config.tcp.server)
        {
            socket_result = accept_tcp(config.tcp.host, config.tcp.port);
        }
        else
        {
            socket_result = connect_tcp(config.tcp.host, config.tcp.port, config.recv_timeout);
        }

        if (!socket_result)
        {
            return protocol_result<any_channel>::failure(socket_result.error(), socket_result.message());
        }

        auto impl = std::make_unique<socket_channel_impl>(config, socket_result.value(), std::string{});
        return protocol_result<any_channel>::success(any_channel(std::move(impl)));
    }

} // namespace loglabel::comm

#endif

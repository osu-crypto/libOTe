#include "test_protocol_defs.hpp"

#include "gtest/gtest.h"

#include <cstring>
#include <thread>

#if !defined(_WIN32)
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

using namespace loglabel::comm;
using namespace loglabel::comm::test_defs;

namespace
{
#if !defined(_WIN32)
    std::uint16_t find_free_port()
    {
        const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0)
        {
            return 0;
        }

        struct sockaddr_in addr
        {
        };
        std::memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;

        if (::bind(fd, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) != 0)
        {
            ::close(fd);
            return 0;
        }

        socklen_t len = sizeof(addr);
        if (::getsockname(fd, reinterpret_cast<struct sockaddr *>(&addr), &len) != 0)
        {
            ::close(fd);
            return 0;
        }

        const std::uint16_t port = ntohs(addr.sin_port);
        ::close(fd);
        return port;
    }
#endif
} // namespace

TEST(CommTcp, PingPongOverLoopbackTcp)
{
#if defined(_WIN32)
    GTEST_SKIP() << "TCP test helper is POSIX-only in this module";
#else
    const auto port = find_free_port();
    if (port == 0u)
    {
        GTEST_SKIP() << "TCP loopback unavailable in this environment";
    }

    auto pair_result = make_tcp_channel_pair(
        "127.0.0.1", port, /*protocol_id=*/501, /*version=*/1, /*session_id=*/901,
        std::chrono::milliseconds(2000));
    if (!pair_result)
    {
        GTEST_SKIP() << "TCP unavailable in this environment: " << pair_result.message();
    }

    auto channels = std::move(pair_result.value());
    any_channel sender_channel = std::move(channels.first);
    any_channel receiver_channel = std::move(channels.second);

    protocol_result<void> sender_result = protocol_result<void>::failure(protocol_errc::io_error, "not run");
    protocol_result<void> receiver_result = protocol_result<void>::failure(protocol_errc::io_error, "not run");

    std::thread receiver_thread([ch = std::move(receiver_channel), &receiver_result]() mutable {
        protocol_engine<ping_pong_spec, role_t::receiver> engine(std::move(ch));
        receiver_result = engine.run_with(
            on_recv<0>([](const ping_msg &) {}),
            on_send<1>([]() { return pong_msg{ 1 }; }));
    });

    std::thread sender_thread([ch = std::move(sender_channel), &sender_result]() mutable {
        protocol_engine<ping_pong_spec, role_t::sender> engine(std::move(ch));
        sender_result = engine.run_with(
            on_send<0>([]() { return ping_msg{ 77 }; }),
            on_recv<1>([](const pong_msg &) {}));
    });

    sender_thread.join();
    receiver_thread.join();

    ASSERT_TRUE(sender_result) << sender_result.message();
    ASSERT_TRUE(receiver_result) << receiver_result.message();
#endif
}

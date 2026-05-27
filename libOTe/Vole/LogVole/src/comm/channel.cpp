#include "loglabel/comm/channel.hpp"

#include "channel_impl_factory.hpp"

#include <future>
#include <utility>

namespace loglabel::comm
{
    protocol_result<void> any_channel::send_frame(byte_buffer frame)
    {
        if (!impl_)
        {
            return protocol_result<void>::failure(protocol_errc::config_error, "channel has no implementation");
        }
        return impl_->send_frame(std::move(frame));
    }

    protocol_result<byte_buffer> any_channel::recv_frame()
    {
        if (!impl_)
        {
            return protocol_result<byte_buffer>::failure(protocol_errc::config_error, "channel has no implementation");
        }
        return impl_->recv_frame();
    }

    const channel_config &any_channel::config() const
    {
        return impl_->config();
    }

    protocol_result<any_channel> make_channel(const channel_config &config)
    {
        switch (config.kind)
        {
        case transport_kind::in_memory:
            return make_in_memory_channel_impl(config);
        case transport_kind::uds:
            return make_uds_channel_impl(config);
        case transport_kind::tcp:
            return make_tcp_channel_impl(config);
        default:
            return protocol_result<any_channel>::failure(protocol_errc::unsupported_transport, "unknown transport kind");
        }
    }

    std::shared_ptr<in_memory_link> make_in_memory_link()
    {
        return std::make_shared<in_memory_link>();
    }

    protocol_result<std::pair<any_channel, any_channel>> make_in_memory_channel_pair(
        std::uint32_t protocol_id, std::uint16_t version, std::uint64_t session_id, std::chrono::milliseconds recv_timeout)
    {
        auto link = make_in_memory_link();

        channel_config sender_cfg{};
        sender_cfg.kind = transport_kind::in_memory;
        sender_cfg.role = role_t::sender;
        sender_cfg.protocol_id = protocol_id;
        sender_cfg.version = version;
        sender_cfg.session_id = session_id;
        sender_cfg.recv_timeout = recv_timeout;
        sender_cfg.in_memory.link = link;

        channel_config receiver_cfg = sender_cfg;
        receiver_cfg.role = role_t::receiver;

        auto sender = make_channel(sender_cfg);
        if (!sender)
        {
            return protocol_result<std::pair<any_channel, any_channel>>::failure(sender.error(), sender.message());
        }

        auto receiver = make_channel(receiver_cfg);
        if (!receiver)
        {
            return protocol_result<std::pair<any_channel, any_channel>>::failure(receiver.error(), receiver.message());
        }

        return protocol_result<std::pair<any_channel, any_channel>>::success(
            std::make_pair(std::move(sender.value()), std::move(receiver.value())));
    }

    protocol_result<std::pair<any_channel, any_channel>> make_uds_channel_pair(
        const std::string &socket_path, std::uint32_t protocol_id, std::uint16_t version, std::uint64_t session_id,
        std::chrono::milliseconds recv_timeout)
    {
        channel_config server_cfg{};
        server_cfg.kind = transport_kind::uds;
        server_cfg.role = role_t::receiver;
        server_cfg.protocol_id = protocol_id;
        server_cfg.version = version;
        server_cfg.session_id = session_id;
        server_cfg.recv_timeout = recv_timeout;
        server_cfg.uds.socket_path = socket_path;
        server_cfg.uds.server = true;

        channel_config client_cfg = server_cfg;
        client_cfg.role = role_t::sender;
        client_cfg.uds.server = false;

        auto server_future = std::async(std::launch::async, [server_cfg]() { return make_channel(server_cfg); });
        auto client = make_channel(client_cfg);
        auto server = server_future.get();

        if (!client)
        {
            return protocol_result<std::pair<any_channel, any_channel>>::failure(client.error(), client.message());
        }
        if (!server)
        {
            return protocol_result<std::pair<any_channel, any_channel>>::failure(server.error(), server.message());
        }

        return protocol_result<std::pair<any_channel, any_channel>>::success(
            std::make_pair(std::move(client.value()), std::move(server.value())));
    }

    protocol_result<std::pair<any_channel, any_channel>> make_tcp_channel_pair(
        const std::string &host, std::uint16_t port, std::uint32_t protocol_id, std::uint16_t version,
        std::uint64_t session_id, std::chrono::milliseconds recv_timeout)
    {
        channel_config server_cfg{};
        server_cfg.kind = transport_kind::tcp;
        server_cfg.role = role_t::receiver;
        server_cfg.protocol_id = protocol_id;
        server_cfg.version = version;
        server_cfg.session_id = session_id;
        server_cfg.recv_timeout = recv_timeout;
        server_cfg.tcp.host = host;
        server_cfg.tcp.port = port;
        server_cfg.tcp.server = true;

        channel_config client_cfg = server_cfg;
        client_cfg.role = role_t::sender;
        client_cfg.tcp.server = false;

        auto server_future = std::async(std::launch::async, [server_cfg]() { return make_channel(server_cfg); });
        auto client = make_channel(client_cfg);
        auto server = server_future.get();

        if (!client)
        {
            return protocol_result<std::pair<any_channel, any_channel>>::failure(client.error(), client.message());
        }
        if (!server)
        {
            return protocol_result<std::pair<any_channel, any_channel>>::failure(server.error(), server.message());
        }

        return protocol_result<std::pair<any_channel, any_channel>>::success(
            std::make_pair(std::move(client.value()), std::move(server.value())));
    }

} // namespace loglabel::comm

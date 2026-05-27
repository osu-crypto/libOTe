#pragma once

#include "loglabel/comm/codec.hpp"
#include "loglabel/comm/types.hpp"

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <string>

namespace loglabel::comm
{
    struct in_memory_link
    {
        struct queue_state
        {
            std::mutex mutex;
            std::condition_variable cv;
            std::deque<byte_buffer> frames;
        };

        queue_state s2r;
        queue_state r2s;
    };

    struct in_memory_channel_options
    {
        std::shared_ptr<in_memory_link> link;
    };

    struct uds_channel_options
    {
        std::string socket_path;
        bool server = false;
    };

    struct tcp_channel_options
    {
        std::string host = "127.0.0.1";
        std::uint16_t port = 0;
        bool server = false;
    };

    struct channel_config
    {
        transport_kind kind = transport_kind::in_memory;
        role_t role = role_t::sender;
        std::uint32_t protocol_id = 0;
        std::uint16_t version = 1;
        std::uint64_t session_id = 0;
        std::chrono::milliseconds recv_timeout = std::chrono::milliseconds(2000);
        std::uint32_t max_frame_size = 16u * 1024u * 1024u;

        in_memory_channel_options in_memory;
        uds_channel_options uds;
        tcp_channel_options tcp;
    };

    class channel_interface
    {
    public:
        explicit channel_interface(channel_config config) : config_(std::move(config))
        {}
        virtual ~channel_interface() = default;

        channel_interface(const channel_interface &) = delete;
        channel_interface &operator=(const channel_interface &) = delete;

        channel_interface(channel_interface &&) = default;
        channel_interface &operator=(channel_interface &&) = default;

        virtual protocol_result<void> send_frame(byte_buffer frame) = 0;
        virtual protocol_result<byte_buffer> recv_frame() = 0;

        const channel_config &config() const
        {
            return config_;
        }

    protected:
        channel_config config_;
    };

    class any_channel
    {
    public:
        any_channel() = default;
        explicit any_channel(std::unique_ptr<channel_interface> impl) : impl_(std::move(impl))
        {}

        any_channel(any_channel &&) = default;
        any_channel &operator=(any_channel &&) = default;

        any_channel(const any_channel &) = delete;
        any_channel &operator=(const any_channel &) = delete;

        protocol_result<void> send_frame(byte_buffer frame);
        protocol_result<byte_buffer> recv_frame();

        bool valid() const
        {
            return static_cast<bool>(impl_);
        }

        const channel_config &config() const;

    private:
        std::unique_ptr<channel_interface> impl_;
    };

    protocol_result<any_channel> make_channel(const channel_config &config);

    std::shared_ptr<in_memory_link> make_in_memory_link();

    protocol_result<std::pair<any_channel, any_channel>> make_in_memory_channel_pair(
        std::uint32_t protocol_id, std::uint16_t version, std::uint64_t session_id,
        std::chrono::milliseconds recv_timeout = std::chrono::milliseconds(2000));

    protocol_result<std::pair<any_channel, any_channel>> make_uds_channel_pair(
        const std::string &socket_path, std::uint32_t protocol_id, std::uint16_t version, std::uint64_t session_id,
        std::chrono::milliseconds recv_timeout = std::chrono::milliseconds(2000));

    protocol_result<std::pair<any_channel, any_channel>> make_tcp_channel_pair(
        const std::string &host, std::uint16_t port, std::uint32_t protocol_id, std::uint16_t version,
        std::uint64_t session_id, std::chrono::milliseconds recv_timeout = std::chrono::milliseconds(2000));

} // namespace loglabel::comm

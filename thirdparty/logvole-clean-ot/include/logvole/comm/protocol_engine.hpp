#pragma once

#include "logvole/comm/channel.hpp"
#include "logvole/comm/codec.hpp"
#include "logvole/comm/metrics.hpp"
#include "logvole/comm/round_dsl.hpp"

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <tuple>
#include <type_traits>
#include <utility>

namespace logvole::comm
{
    namespace detail
    {
        template <typename...>
        struct dependent_false : std::false_type
        {};

        template <typename T>
        struct protocol_result_value;

        template <typename T>
        struct protocol_result_value<protocol_result<T>>
        {
            using type = T;
        };
    } // namespace detail

    template <std::size_t RoundIndex, class Fn>
    struct send_handler
    {
        static constexpr std::size_t round_index = RoundIndex;
        using fn_type = Fn;
        Fn fn;
    };

    template <std::size_t RoundIndex, class Fn>
    struct recv_handler
    {
        static constexpr std::size_t round_index = RoundIndex;
        using fn_type = Fn;
        Fn fn;
    };

    template <std::size_t RoundIndex, class Fn>
    send_handler<RoundIndex, std::decay_t<Fn>> on_send(Fn &&fn)
    {
        return send_handler<RoundIndex, std::decay_t<Fn>>{ std::forward<Fn>(fn) };
    }

    template <std::size_t RoundIndex, class Fn>
    recv_handler<RoundIndex, std::decay_t<Fn>> on_recv(Fn &&fn)
    {
        return recv_handler<RoundIndex, std::decay_t<Fn>>{ std::forward<Fn>(fn) };
    }

    template <class T>
    struct is_send_handler : std::false_type
    {};

    template <std::size_t RoundIndex, class Fn>
    struct is_send_handler<send_handler<RoundIndex, Fn>> : std::true_type
    {};

    template <class T>
    struct is_recv_handler : std::false_type
    {};

    template <std::size_t RoundIndex, class Fn>
    struct is_recv_handler<recv_handler<RoundIndex, Fn>> : std::true_type
    {};

    template <class T>
    struct is_known_handler : std::integral_constant<bool, is_send_handler<T>::value || is_recv_handler<T>::value>
    {};

    template <class T>
    inline constexpr bool is_known_handler_v = is_known_handler<T>::value;

    template <std::size_t RoundIndex, class H>
    struct is_send_handler_for_round : std::false_type
    {};

    template <std::size_t RoundIndex, std::size_t HandlerRound, class Fn>
    struct is_send_handler_for_round<RoundIndex, send_handler<HandlerRound, Fn>>
        : std::integral_constant<bool, RoundIndex == HandlerRound>
    {};

    template <std::size_t RoundIndex, class H>
    struct is_recv_handler_for_round : std::false_type
    {};

    template <std::size_t RoundIndex, std::size_t HandlerRound, class Fn>
    struct is_recv_handler_for_round<RoundIndex, recv_handler<HandlerRound, Fn>>
        : std::integral_constant<bool, RoundIndex == HandlerRound>
    {};

    template <class Spec, role_t Role, class Channel = any_channel>
    class protocol_engine
    {
    public:
        using spec_type = Spec;
        using script_type = typename Spec::script;

        static constexpr std::size_t round_count = round_script_traits<script_type>::round_count;

        explicit protocol_engine(Channel channel) : channel_(std::move(channel))
        {}

        protocol_engine(const protocol_engine &) = delete;
        protocol_engine &operator=(const protocol_engine &) = delete;

        protocol_engine(protocol_engine &&) = default;
        protocol_engine &operator=(protocol_engine &&) = default;

        template <class... Handlers>
        protocol_result<void> run_with(Handlers &&...handlers)
        {
            static_assert((is_known_handler_v<std::decay_t<Handlers>> && ...),
                          "run_with only accepts handlers created by on_send/on_recv");

            validate_handlers<std::decay_t<Handlers>...>();

            if (!channel_.valid())
            {
                return protocol_result<void>::failure(protocol_errc::config_error, "invalid channel");
            }

            if (channel_.config().role != Role)
            {
                return protocol_result<void>::failure(
                    protocol_errc::invalid_state_transition, "channel role does not match engine role");
            }

            counters_ = comm_counters{};
            next_send_seq_ = 0;
            next_recv_seq_ = 0;

            auto handler_tuple = std::make_tuple(std::forward<Handlers>(handlers)...);
            return execute_rounds(handler_tuple, std::make_index_sequence<round_count>{});
        }

        const comm_counters &counters() const
        {
            return counters_;
        }

    private:
        enum class direction
        {
            s2r,
            r2s
        };

        direction send_direction() const
        {
            return Role == role_t::sender ? direction::s2r : direction::r2s;
        }

        direction recv_direction() const
        {
            return Role == role_t::sender ? direction::r2s : direction::s2r;
        }

        template <class... Handlers>
        static constexpr void validate_handlers()
        {
            static_assert(((Handlers::round_index < round_count) && ...), "handler round index is out of range");

            (validate_handler_direction<Handlers>(), ...);
            validate_round_coverage<Handlers...>(std::make_index_sequence<round_count>{});
        }

        template <class Handler>
        static constexpr void validate_handler_direction()
        {
            using round_type = typename round_script_traits<script_type>::template round_type<Handler::round_index>;
            using action = role_round_action<round_type, Role>;

            if constexpr (is_send_handler<Handler>::value)
            {
                static_assert(action::is_send,
                              "send handler registered for a round where this role must receive");
            }
            else
            {
                static_assert(action::is_recv,
                              "recv handler registered for a round where this role must send");
            }
        }

        template <class... Handlers, std::size_t... RoundIndex>
        static constexpr void validate_round_coverage(std::index_sequence<RoundIndex...>)
        {
            (validate_single_round_coverage<RoundIndex, Handlers...>(), ...);
        }

        template <std::size_t RoundIndex, class... Handlers>
        static constexpr void validate_single_round_coverage()
        {
            using round_type = typename round_script_traits<script_type>::template round_type<RoundIndex>;
            using action = role_round_action<round_type, Role>;

            constexpr std::size_t send_count =
                (0u + ... + (is_send_handler_for_round<RoundIndex, Handlers>::value ? 1u : 0u));
            constexpr std::size_t recv_count =
                (0u + ... + (is_recv_handler_for_round<RoundIndex, Handlers>::value ? 1u : 0u));

            if constexpr (action::is_send)
            {
                static_assert(send_count == 1u, "missing or duplicate send handler for role round");
                static_assert(recv_count == 0u, "recv handler registered on role send round");
            }
            else
            {
                static_assert(recv_count == 1u, "missing or duplicate recv handler for role round");
                static_assert(send_count == 0u, "send handler registered on role recv round");
            }
        }

        template <class HandlerTuple, std::size_t... RoundIndex>
        protocol_result<void> execute_rounds(HandlerTuple &handlers, std::index_sequence<RoundIndex...>)
        {
            protocol_result<void> result = protocol_result<void>::success();
            (void)std::initializer_list<int>{
                (result ? (result = execute_single_round<RoundIndex>(handlers), 0) : 0)...
            };
            return result;
        }

        template <std::size_t RoundIndex, class HandlerTuple>
        protocol_result<void> execute_single_round(HandlerTuple &handlers)
        {
            using round_type = typename round_script_traits<script_type>::template round_type<RoundIndex>;
            using action = role_round_action<round_type, Role>;
            using message_type = typename action::message_type;

            if constexpr (action::is_send)
            {
                auto &handler = get_send_handler<RoundIndex>(handlers);
                auto send_result = invoke_send_handler<message_type>(handler.fn);
                if (!send_result)
                {
                    return protocol_result<void>::failure(send_result.error(), send_result.message());
                }

                auto payload_result = encode_message(send_result.value());
                if (!payload_result)
                {
                    return protocol_result<void>::failure(payload_result.error(), payload_result.message());
                }

                message_envelope envelope{};
                envelope.protocol_id = channel_.config().protocol_id;
                envelope.version = channel_.config().version;
                envelope.session_id = channel_.config().session_id;
                envelope.round_index = static_cast<std::uint32_t>(RoundIndex);
                envelope.sequence_number = next_send_seq_;
                envelope.payload_type = message_traits<message_type>::payload_type;
                envelope.payload_size = static_cast<std::uint32_t>(payload_result.value().size());
                envelope.payload_crc = crc32(payload_result.value().data(), payload_result.value().size());

                auto frame_result = serialize_frame(envelope, payload_result.value());
                if (!frame_result)
                {
                    return protocol_result<void>::failure(frame_result.error(), frame_result.message());
                }

                auto transport_result = channel_.send_frame(std::move(frame_result.value()));
                if (!transport_result)
                {
                    return transport_result;
                }

                ++next_send_seq_;
                add_send_counters(send_direction(), envelope.payload_size);
                ++counters_.rounds_completed;
                return protocol_result<void>::success();
            }
            else
            {
                auto frame_result = channel_.recv_frame();
                if (!frame_result)
                {
                    return protocol_result<void>::failure(frame_result.error(), frame_result.message());
                }

                auto parsed_result = deserialize_frame(frame_result.value());
                if (!parsed_result)
                {
                    return protocol_result<void>::failure(parsed_result.error(), parsed_result.message());
                }

                const auto &envelope = parsed_result.value().first;
                const auto &payload = parsed_result.value().second;

                auto validation_result = validate_incoming_envelope<message_type, RoundIndex>(envelope, payload);
                if (!validation_result)
                {
                    return validation_result;
                }

                auto message_result = decode_message<message_type>(payload);
                if (!message_result)
                {
                    return protocol_result<void>::failure(message_result.error(), message_result.message());
                }

                auto &handler = get_recv_handler<RoundIndex>(handlers);
                auto recv_result = invoke_recv_handler<message_type>(handler.fn, message_result.value());
                if (!recv_result)
                {
                    return recv_result;
                }

                ++next_recv_seq_;
                add_recv_counters(recv_direction(), envelope.payload_size);
                ++counters_.rounds_completed;
                return protocol_result<void>::success();
            }
        }

        template <class Msg, std::size_t RoundIndex>
        protocol_result<void> validate_incoming_envelope(const message_envelope &envelope, const byte_buffer &payload)
        {
            if (envelope.protocol_id != channel_.config().protocol_id || envelope.session_id != channel_.config().session_id)
            {
                return protocol_result<void>::failure(protocol_errc::flow_violation, "protocol or session mismatch");
            }

            if (envelope.version != channel_.config().version)
            {
                return protocol_result<void>::failure(
                    protocol_errc::unsupported_protocol_version, "protocol version mismatch");
            }

            if (envelope.round_index != static_cast<std::uint32_t>(RoundIndex))
            {
                return protocol_result<void>::failure(protocol_errc::flow_violation, "round index mismatch");
            }

            if (envelope.sequence_number != next_recv_seq_)
            {
                return protocol_result<void>::failure(protocol_errc::flow_violation, "non-monotonic sequence number");
            }

            if (envelope.payload_type != message_traits<Msg>::payload_type)
            {
                return protocol_result<void>::failure(protocol_errc::flow_violation, "payload type mismatch");
            }

            if (envelope.payload_size != payload.size())
            {
                return protocol_result<void>::failure(protocol_errc::decode_validation_failure, "payload size mismatch");
            }

            if (crc32(payload.data(), payload.size()) != envelope.payload_crc)
            {
                return protocol_result<void>::failure(protocol_errc::decode_validation_failure, "payload crc mismatch");
            }

            return protocol_result<void>::success();
        }

        template <class Msg, class Fn>
        static protocol_result<Msg> invoke_send_handler(Fn &fn)
        {
            using return_type = decltype(fn());

            if constexpr (is_protocol_result_v<return_type>)
            {
                using value_type = typename detail::protocol_result_value<return_type>::type;
                static_assert(std::is_same<value_type, Msg>::value,
                              "send handler protocol_result must hold the round message type");
                return fn();
            }
            else
            {
                static_assert(std::is_same<return_type, Msg>::value,
                              "send handler must return Msg or protocol_result<Msg>");
                return protocol_result<Msg>::success(fn());
            }
        }

        template <class Msg, class Fn>
        static protocol_result<void> invoke_recv_handler(Fn &fn, const Msg &message)
        {
            using return_type = decltype(fn(message));

            if constexpr (std::is_same<return_type, void>::value)
            {
                fn(message);
                return protocol_result<void>::success();
            }
            else if constexpr (std::is_same<return_type, protocol_result<void>>::value)
            {
                return fn(message);
            }
            else
            {
                static_assert(detail::dependent_false<return_type>::value,
                              "recv handler must return void or protocol_result<void>");
            }
        }

        template <std::size_t RoundIndex, std::size_t I = 0, class HandlerTuple>
        static auto &get_send_handler(HandlerTuple &handlers)
        {
            static_assert(I < std::tuple_size<HandlerTuple>::value, "missing send handler for round");

            using handler_type = std::decay_t<typename std::tuple_element<I, HandlerTuple>::type>;
            if constexpr (is_send_handler_for_round<RoundIndex, handler_type>::value)
            {
                return std::get<I>(handlers);
            }
            else
            {
                return get_send_handler<RoundIndex, I + 1>(handlers);
            }
        }

        template <std::size_t RoundIndex, std::size_t I = 0, class HandlerTuple>
        static auto &get_recv_handler(HandlerTuple &handlers)
        {
            static_assert(I < std::tuple_size<HandlerTuple>::value, "missing recv handler for round");

            using handler_type = std::decay_t<typename std::tuple_element<I, HandlerTuple>::type>;
            if constexpr (is_recv_handler_for_round<RoundIndex, handler_type>::value)
            {
                return std::get<I>(handlers);
            }
            else
            {
                return get_recv_handler<RoundIndex, I + 1>(handlers);
            }
        }

        void add_send_counters(direction dir, std::size_t payload_size)
        {
            const auto wire_size = static_cast<std::uint64_t>(envelope_wire_size + payload_size);
            const auto payload = static_cast<std::uint64_t>(payload_size);
            if (dir == direction::s2r)
            {
                ++counters_.frames_s2r_sent;
                counters_.wire_bytes_s2r_sent += wire_size;
                counters_.payload_bytes_s2r_sent += payload;
            }
            else
            {
                ++counters_.frames_r2s_sent;
                counters_.wire_bytes_r2s_sent += wire_size;
                counters_.payload_bytes_r2s_sent += payload;
            }
        }

        void add_recv_counters(direction dir, std::size_t payload_size)
        {
            const auto wire_size = static_cast<std::uint64_t>(envelope_wire_size + payload_size);
            const auto payload = static_cast<std::uint64_t>(payload_size);
            if (dir == direction::s2r)
            {
                ++counters_.frames_s2r_recv;
                counters_.wire_bytes_s2r_recv += wire_size;
                counters_.payload_bytes_s2r_recv += payload;
            }
            else
            {
                ++counters_.frames_r2s_recv;
                counters_.wire_bytes_r2s_recv += wire_size;
                counters_.payload_bytes_r2s_recv += payload;
            }
        }

        Channel channel_;
        comm_counters counters_{};
        std::uint64_t next_send_seq_ = 0;
        std::uint64_t next_recv_seq_ = 0;
    };

} // namespace logvole::comm

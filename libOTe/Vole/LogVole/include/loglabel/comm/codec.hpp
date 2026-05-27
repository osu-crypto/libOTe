#pragma once

#include "loglabel/comm/envelope.hpp"
#include "loglabel/comm/types.hpp"

#include <cstring>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace loglabel::comm
{
    using byte_buffer = std::vector<std::uint8_t>;

    protocol_result<byte_buffer> serialize_frame(const message_envelope &envelope, const byte_buffer &payload);
    protocol_result<std::pair<message_envelope, byte_buffer>> deserialize_frame(const byte_buffer &frame);

    std::uint32_t crc32(const std::uint8_t *data, std::size_t length);

    template <class Msg, class Enable = void>
    struct message_traits;

    template <class Msg>
    struct message_traits<Msg, std::enable_if_t<std::is_integral<Msg>::value>>
    {
        static constexpr std::uint32_t payload_type = 0x1000u + (static_cast<std::uint32_t>(sizeof(Msg)) << 1u) +
                                                      (std::is_signed<Msg>::value ? 1u : 0u);

        static protocol_result<byte_buffer> encode(const Msg &message)
        {
            byte_buffer payload(sizeof(Msg));
            std::memcpy(payload.data(), &message, sizeof(Msg));
            return protocol_result<byte_buffer>::success(std::move(payload));
        }

        static protocol_result<Msg> decode(const byte_buffer &payload)
        {
            if (payload.size() != sizeof(Msg))
            {
                return protocol_result<Msg>::failure(
                    protocol_errc::decode_validation_failure, "integral payload size mismatch");
            }
            Msg value{};
            std::memcpy(&value, payload.data(), sizeof(Msg));
            return protocol_result<Msg>::success(value);
        }

        static std::size_t encoded_size(const Msg &)
        {
            return sizeof(Msg);
        }
    };

    template <class Msg, std::uint32_t PayloadType>
    struct trivial_message_traits
    {
        static_assert(std::is_trivially_copyable<Msg>::value,
                      "trivial_message_traits requires a trivially copyable message type");

        static constexpr std::uint32_t payload_type = PayloadType;

        static protocol_result<byte_buffer> encode(const Msg &message)
        {
            byte_buffer payload(sizeof(Msg));
            std::memcpy(payload.data(), &message, sizeof(Msg));
            return protocol_result<byte_buffer>::success(std::move(payload));
        }

        static protocol_result<Msg> decode(const byte_buffer &payload)
        {
            if (payload.size() != sizeof(Msg))
            {
                return protocol_result<Msg>::failure(
                    protocol_errc::decode_validation_failure, "trivial payload size mismatch");
            }
            Msg message{};
            std::memcpy(&message, payload.data(), sizeof(Msg));
            return protocol_result<Msg>::success(std::move(message));
        }

        static std::size_t encoded_size(const Msg &)
        {
            return sizeof(Msg);
        }
    };

    template <class Msg>
    protocol_result<byte_buffer> encode_message(const Msg &message)
    {
        return message_traits<Msg>::encode(message);
    }

    template <class Msg>
    protocol_result<Msg> decode_message(const byte_buffer &payload)
    {
        return message_traits<Msg>::decode(payload);
    }

} // namespace loglabel::comm

#define LOGLABEL_DEFINE_TRIVIAL_MESSAGE_TRAITS(TypeName, PayloadTypeId)                                               \
    template <>                                                                                                        \
    struct loglabel::comm::message_traits<TypeName> : loglabel::comm::trivial_message_traits<TypeName, PayloadTypeId> \
    {}

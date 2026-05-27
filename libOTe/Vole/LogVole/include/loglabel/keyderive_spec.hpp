#pragma once

#include "loglabel/comm/codec.hpp"
#include "loglabel/comm/round_dsl.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <string>
#include <tuple>
#include <vector>

namespace loglabel
{
    struct keyderive_request_msg
    {
        std::uint32_t poly_modulus_degree = 0;
        std::uint32_t coeff_modulus_count = 0;
        std::uint32_t tau = 0;
        std::vector<std::uint64_t> d_coeffs{};
    };

    struct keyderive_response_msg
    {
        std::uint32_t poly_modulus_degree = 0;
        std::uint32_t coeff_modulus_count = 0;
        std::uint32_t tau = 0;
        std::vector<std::uint64_t> m_ntt_coeffs{};
    };

    struct keyderive_spec
    {
        using script = loglabel::comm::round_script<
            loglabel::comm::round_pair<
                loglabel::comm::round_send<keyderive_request_msg, loglabel::comm::role_t::receiver>,
                loglabel::comm::round_recv<keyderive_request_msg, loglabel::comm::role_t::sender>>,
            loglabel::comm::round_pair<
                loglabel::comm::round_send<keyderive_response_msg, loglabel::comm::role_t::sender>,
                loglabel::comm::round_recv<keyderive_response_msg, loglabel::comm::role_t::receiver>>>;
    };

} // namespace loglabel

namespace loglabel::comm
{
    namespace detail
    {
        inline void append_u32(byte_buffer &buffer, std::uint32_t value)
        {
            buffer.push_back(static_cast<std::uint8_t>(value & 0xFFu));
            buffer.push_back(static_cast<std::uint8_t>((value >> 8u) & 0xFFu));
            buffer.push_back(static_cast<std::uint8_t>((value >> 16u) & 0xFFu));
            buffer.push_back(static_cast<std::uint8_t>((value >> 24u) & 0xFFu));
        }

        inline void append_u64(byte_buffer &buffer, std::uint64_t value)
        {
            for (int i = 0; i < 8; ++i)
            {
                buffer.push_back(static_cast<std::uint8_t>((value >> (8u * i)) & 0xFFu));
            }
        }

        inline protocol_result<std::uint32_t> read_u32(const byte_buffer &buffer, std::size_t &offset)
        {
            if (offset + sizeof(std::uint32_t) > buffer.size())
            {
                return protocol_result<std::uint32_t>::failure(
                    protocol_errc::decode_validation_failure, "payload underflow while reading uint32");
            }

            std::uint32_t value = 0;
            for (int i = 0; i < 4; ++i)
            {
                value |= static_cast<std::uint32_t>(buffer[offset + static_cast<std::size_t>(i)]) << (8u * i);
            }
            offset += sizeof(std::uint32_t);
            return protocol_result<std::uint32_t>::success(value);
        }

        inline protocol_result<std::uint64_t> read_u64(const byte_buffer &buffer, std::size_t &offset)
        {
            if (offset + sizeof(std::uint64_t) > buffer.size())
            {
                return protocol_result<std::uint64_t>::failure(
                    protocol_errc::decode_validation_failure, "payload underflow while reading uint64");
            }

            std::uint64_t value = 0;
            for (int i = 0; i < 8; ++i)
            {
                value |= static_cast<std::uint64_t>(buffer[offset + static_cast<std::size_t>(i)]) << (8u * i);
            }
            offset += sizeof(std::uint64_t);
            return protocol_result<std::uint64_t>::success(value);
        }

        template <typename Msg>
        protocol_result<byte_buffer> encode_keyderive_msg(
            const Msg &message, const std::vector<std::uint64_t> &vector_payload)
        {
            if (vector_payload.size() > std::numeric_limits<std::uint32_t>::max())
            {
                return protocol_result<byte_buffer>::failure(
                    protocol_errc::config_error, "keyderive payload is too large");
            }

            byte_buffer out;
            out.reserve(4u * sizeof(std::uint32_t) + vector_payload.size() * sizeof(std::uint64_t));

            append_u32(out, message.poly_modulus_degree);
            append_u32(out, message.coeff_modulus_count);
            append_u32(out, message.tau);
            append_u32(out, static_cast<std::uint32_t>(vector_payload.size()));

            for (std::uint64_t value : vector_payload)
            {
                append_u64(out, value);
            }

            return protocol_result<byte_buffer>::success(std::move(out));
        }

        inline protocol_result<std::tuple<std::uint32_t, std::uint32_t, std::uint32_t, std::vector<std::uint64_t>>>
        decode_keyderive_payload(const byte_buffer &payload)
        {
            constexpr std::size_t header_bytes = 4u * sizeof(std::uint32_t);
            if (payload.size() < header_bytes)
            {
                return protocol_result<std::tuple<std::uint32_t, std::uint32_t, std::uint32_t, std::vector<std::uint64_t>>>::failure(
                    protocol_errc::decode_validation_failure, "keyderive payload is too short");
            }

            std::size_t offset = 0;

            auto poly_modulus_degree = read_u32(payload, offset);
            if (!poly_modulus_degree)
            {
                return protocol_result<std::tuple<std::uint32_t, std::uint32_t, std::uint32_t, std::vector<std::uint64_t>>>::failure(
                    poly_modulus_degree.error(), poly_modulus_degree.message());
            }

            auto coeff_modulus_count = read_u32(payload, offset);
            if (!coeff_modulus_count)
            {
                return protocol_result<std::tuple<std::uint32_t, std::uint32_t, std::uint32_t, std::vector<std::uint64_t>>>::failure(
                    coeff_modulus_count.error(), coeff_modulus_count.message());
            }

            auto tau = read_u32(payload, offset);
            if (!tau)
            {
                return protocol_result<std::tuple<std::uint32_t, std::uint32_t, std::uint32_t, std::vector<std::uint64_t>>>::failure(
                    tau.error(), tau.message());
            }

            auto vector_size = read_u32(payload, offset);
            if (!vector_size)
            {
                return protocol_result<std::tuple<std::uint32_t, std::uint32_t, std::uint32_t, std::vector<std::uint64_t>>>::failure(
                    vector_size.error(), vector_size.message());
            }

            const auto value_count = static_cast<std::size_t>(vector_size.value());
            const auto expected_size = header_bytes + value_count * sizeof(std::uint64_t);
            if (expected_size != payload.size())
            {
                return protocol_result<std::tuple<std::uint32_t, std::uint32_t, std::uint32_t, std::vector<std::uint64_t>>>::failure(
                    protocol_errc::decode_validation_failure, "keyderive payload length mismatch");
            }

            std::vector<std::uint64_t> values;
            values.reserve(value_count);
            for (std::size_t i = 0; i < value_count; ++i)
            {
                auto value = read_u64(payload, offset);
                if (!value)
                {
                    return protocol_result<std::tuple<std::uint32_t, std::uint32_t, std::uint32_t, std::vector<std::uint64_t>>>::failure(
                        value.error(), value.message());
                }
                values.push_back(value.value());
            }

            return protocol_result<std::tuple<std::uint32_t, std::uint32_t, std::uint32_t, std::vector<std::uint64_t>>>::success(
                std::make_tuple(
                    poly_modulus_degree.value(),
                    coeff_modulus_count.value(),
                    tau.value(),
                    std::move(values)));
        }

    } // namespace detail

    template <>
    struct message_traits<loglabel::keyderive_request_msg>
    {
        static constexpr std::uint32_t payload_type = 0x4001u;

        static protocol_result<byte_buffer> encode(const loglabel::keyderive_request_msg &message)
        {
            return detail::encode_keyderive_msg(message, message.d_coeffs);
        }

        static protocol_result<loglabel::keyderive_request_msg> decode(const byte_buffer &payload)
        {
            auto decoded = detail::decode_keyderive_payload(payload);
            if (!decoded)
            {
                return protocol_result<loglabel::keyderive_request_msg>::failure(decoded.error(), decoded.message());
            }

            loglabel::keyderive_request_msg message{};
            message.poly_modulus_degree = std::get<0>(decoded.value());
            message.coeff_modulus_count = std::get<1>(decoded.value());
            message.tau = std::get<2>(decoded.value());
            message.d_coeffs = std::move(std::get<3>(decoded.value()));
            return protocol_result<loglabel::keyderive_request_msg>::success(std::move(message));
        }

        static std::size_t encoded_size(const loglabel::keyderive_request_msg &message)
        {
            return 4u * sizeof(std::uint32_t) + message.d_coeffs.size() * sizeof(std::uint64_t);
        }
    };

    template <>
    struct message_traits<loglabel::keyderive_response_msg>
    {
        static constexpr std::uint32_t payload_type = 0x4002u;

        static protocol_result<byte_buffer> encode(const loglabel::keyderive_response_msg &message)
        {
            return detail::encode_keyderive_msg(message, message.m_ntt_coeffs);
        }

        static protocol_result<loglabel::keyderive_response_msg> decode(const byte_buffer &payload)
        {
            auto decoded = detail::decode_keyderive_payload(payload);
            if (!decoded)
            {
                return protocol_result<loglabel::keyderive_response_msg>::failure(decoded.error(), decoded.message());
            }

            loglabel::keyderive_response_msg message{};
            message.poly_modulus_degree = std::get<0>(decoded.value());
            message.coeff_modulus_count = std::get<1>(decoded.value());
            message.tau = std::get<2>(decoded.value());
            message.m_ntt_coeffs = std::move(std::get<3>(decoded.value()));
            return protocol_result<loglabel::keyderive_response_msg>::success(std::move(message));
        }

        static std::size_t encoded_size(const loglabel::keyderive_response_msg &message)
        {
            return 4u * sizeof(std::uint32_t) + message.m_ntt_coeffs.size() * sizeof(std::uint64_t);
        }
    };

} // namespace loglabel::comm

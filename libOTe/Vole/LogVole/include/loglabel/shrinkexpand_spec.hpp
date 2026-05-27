#pragma once

#include "loglabel/comm/codec.hpp"
#include "loglabel/comm/round_dsl.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <tuple>
#include <vector>

namespace loglabel
{
    struct shrinkexpand_offline_msg
    {
        std::uint32_t poly_modulus_degree = 0;
        std::vector<std::uint16_t> coeff_modulus_bits{};

        std::uint32_t plaintext_modulus_bits = 0;
        std::uint32_t alpha = 0;
        std::uint32_t mu = 0;
        std::uint32_t tau = 0;
        std::uint32_t gadget_log_base = 0;
        std::uint8_t mode = 0;

        std::uint64_t metadata_fingerprint = 0;

        std::uint32_t ct1_rows = 0;
        std::uint32_t ct1_cols = 0;
        std::vector<std::uint64_t> ct1_coeffs{};

        std::uint32_t lacct_width_padded = 0;
        std::uint32_t lacct_levels = 0;
        std::uint32_t lacct_ct_rows = 0;
        std::uint32_t lacct_ct_cols = 0;
        std::vector<std::uint64_t> lacct_ct_coeffs{};
    };

    struct shrinkexpand_spec
    {
        using script = loglabel::comm::round_script<
            loglabel::comm::round_pair<
                loglabel::comm::round_send<shrinkexpand_offline_msg, loglabel::comm::role_t::sender>,
                loglabel::comm::round_recv<shrinkexpand_offline_msg, loglabel::comm::role_t::receiver>>>;
    };

} // namespace loglabel

namespace loglabel::comm
{
    namespace detail
    {
        inline void append_u8(byte_buffer &buffer, std::uint8_t value)
        {
            buffer.push_back(value);
        }

        inline void append_u16(byte_buffer &buffer, std::uint16_t value)
        {
            buffer.push_back(static_cast<std::uint8_t>(value & 0xFFu));
            buffer.push_back(static_cast<std::uint8_t>((value >> 8u) & 0xFFu));
        }

        inline void append_u32(byte_buffer &buffer, std::uint32_t value)
        {
            for (int i = 0; i < 4; ++i)
            {
                buffer.push_back(static_cast<std::uint8_t>((value >> (8u * i)) & 0xFFu));
            }
        }

        inline void append_u64(byte_buffer &buffer, std::uint64_t value)
        {
            for (int i = 0; i < 8; ++i)
            {
                buffer.push_back(static_cast<std::uint8_t>((value >> (8u * i)) & 0xFFu));
            }
        }

        inline protocol_result<std::uint8_t> read_u8(const byte_buffer &buffer, std::size_t &offset)
        {
            if (offset + 1u > buffer.size())
            {
                return protocol_result<std::uint8_t>::failure(
                    protocol_errc::decode_validation_failure,
                    "payload underflow while reading uint8");
            }
            return protocol_result<std::uint8_t>::success(buffer[offset++]);
        }

        inline protocol_result<std::uint16_t> read_u16(const byte_buffer &buffer, std::size_t &offset)
        {
            if (offset + 2u > buffer.size())
            {
                return protocol_result<std::uint16_t>::failure(
                    protocol_errc::decode_validation_failure,
                    "payload underflow while reading uint16");
            }

            const std::uint16_t value = static_cast<std::uint16_t>(buffer[offset]) |
                                        (static_cast<std::uint16_t>(buffer[offset + 1u]) << 8u);
            offset += 2u;
            return protocol_result<std::uint16_t>::success(value);
        }

        inline protocol_result<std::uint32_t> read_u32(const byte_buffer &buffer, std::size_t &offset)
        {
            if (offset + 4u > buffer.size())
            {
                return protocol_result<std::uint32_t>::failure(
                    protocol_errc::decode_validation_failure,
                    "payload underflow while reading uint32");
            }

            std::uint32_t value = 0;
            for (int i = 0; i < 4; ++i)
            {
                value |= static_cast<std::uint32_t>(buffer[offset + static_cast<std::size_t>(i)]) << (8u * i);
            }
            offset += 4u;
            return protocol_result<std::uint32_t>::success(value);
        }

        inline protocol_result<std::uint64_t> read_u64(const byte_buffer &buffer, std::size_t &offset)
        {
            if (offset + 8u > buffer.size())
            {
                return protocol_result<std::uint64_t>::failure(
                    protocol_errc::decode_validation_failure,
                    "payload underflow while reading uint64");
            }

            std::uint64_t value = 0;
            for (int i = 0; i < 8; ++i)
            {
                value |= static_cast<std::uint64_t>(buffer[offset + static_cast<std::size_t>(i)]) << (8u * i);
            }
            offset += 8u;
            return protocol_result<std::uint64_t>::success(value);
        }

        inline protocol_result<void> append_u16_vector(byte_buffer &buffer, const std::vector<std::uint16_t> &values)
        {
            if (values.size() > static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max()))
            {
                return protocol_result<void>::failure(protocol_errc::config_error, "uint16 vector too large");
            }

            append_u32(buffer, static_cast<std::uint32_t>(values.size()));
            for (std::uint16_t value : values)
            {
                append_u16(buffer, value);
            }
            return protocol_result<void>::success();
        }

        inline protocol_result<void> append_u64_vector(byte_buffer &buffer, const std::vector<std::uint64_t> &values)
        {
            if (values.size() > static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max()))
            {
                return protocol_result<void>::failure(protocol_errc::config_error, "uint64 vector too large");
            }

            append_u32(buffer, static_cast<std::uint32_t>(values.size()));
            for (std::uint64_t value : values)
            {
                append_u64(buffer, value);
            }
            return protocol_result<void>::success();
        }

        inline protocol_result<std::vector<std::uint16_t>> read_u16_vector(const byte_buffer &buffer, std::size_t &offset)
        {
            auto size_result = read_u32(buffer, offset);
            if (!size_result)
            {
                return protocol_result<std::vector<std::uint16_t>>::failure(size_result.error(), size_result.message());
            }

            std::vector<std::uint16_t> out;
            out.reserve(size_result.value());
            for (std::size_t i = 0; i < size_result.value(); ++i)
            {
                auto value = read_u16(buffer, offset);
                if (!value)
                {
                    return protocol_result<std::vector<std::uint16_t>>::failure(value.error(), value.message());
                }
                out.push_back(value.value());
            }

            return protocol_result<std::vector<std::uint16_t>>::success(std::move(out));
        }

        inline protocol_result<std::vector<std::uint64_t>> read_u64_vector(const byte_buffer &buffer, std::size_t &offset)
        {
            auto size_result = read_u32(buffer, offset);
            if (!size_result)
            {
                return protocol_result<std::vector<std::uint64_t>>::failure(size_result.error(), size_result.message());
            }

            std::vector<std::uint64_t> out;
            out.reserve(size_result.value());
            for (std::size_t i = 0; i < size_result.value(); ++i)
            {
                auto value = read_u64(buffer, offset);
                if (!value)
                {
                    return protocol_result<std::vector<std::uint64_t>>::failure(value.error(), value.message());
                }
                out.push_back(value.value());
            }

            return protocol_result<std::vector<std::uint64_t>>::success(std::move(out));
        }

    } // namespace detail

    template <>
    struct message_traits<loglabel::shrinkexpand_offline_msg>
    {
        static constexpr std::uint32_t payload_type = 0x5001u;

        static protocol_result<byte_buffer> encode(const loglabel::shrinkexpand_offline_msg &message)
        {
            byte_buffer out;

            detail::append_u32(out, message.poly_modulus_degree);

            auto bits_ok = detail::append_u16_vector(out, message.coeff_modulus_bits);
            if (!bits_ok)
            {
                return protocol_result<byte_buffer>::failure(bits_ok.error(), bits_ok.message());
            }

            detail::append_u32(out, message.plaintext_modulus_bits);
            detail::append_u32(out, message.alpha);
            detail::append_u32(out, message.mu);
            detail::append_u32(out, message.tau);
            detail::append_u32(out, message.gadget_log_base);
            detail::append_u8(out, message.mode);
            detail::append_u64(out, message.metadata_fingerprint);

            detail::append_u32(out, message.ct1_rows);
            detail::append_u32(out, message.ct1_cols);
            auto ct1_ok = detail::append_u64_vector(out, message.ct1_coeffs);
            if (!ct1_ok)
            {
                return protocol_result<byte_buffer>::failure(ct1_ok.error(), ct1_ok.message());
            }

            detail::append_u32(out, message.lacct_width_padded);
            detail::append_u32(out, message.lacct_levels);
            detail::append_u32(out, message.lacct_ct_rows);
            detail::append_u32(out, message.lacct_ct_cols);
            auto lacct_ok = detail::append_u64_vector(out, message.lacct_ct_coeffs);
            if (!lacct_ok)
            {
                return protocol_result<byte_buffer>::failure(lacct_ok.error(), lacct_ok.message());
            }

            return protocol_result<byte_buffer>::success(std::move(out));
        }

        static protocol_result<loglabel::shrinkexpand_offline_msg> decode(const byte_buffer &payload)
        {
            std::size_t offset = 0;

            auto poly = detail::read_u32(payload, offset);
            if (!poly)
            {
                return protocol_result<loglabel::shrinkexpand_offline_msg>::failure(poly.error(), poly.message());
            }

            auto bits = detail::read_u16_vector(payload, offset);
            if (!bits)
            {
                return protocol_result<loglabel::shrinkexpand_offline_msg>::failure(bits.error(), bits.message());
            }

            auto plain_bits = detail::read_u32(payload, offset);
            if (!plain_bits)
            {
                return protocol_result<loglabel::shrinkexpand_offline_msg>::failure(
                    plain_bits.error(), plain_bits.message());
            }

            auto alpha = detail::read_u32(payload, offset);
            if (!alpha)
            {
                return protocol_result<loglabel::shrinkexpand_offline_msg>::failure(alpha.error(), alpha.message());
            }

            auto mu = detail::read_u32(payload, offset);
            if (!mu)
            {
                return protocol_result<loglabel::shrinkexpand_offline_msg>::failure(mu.error(), mu.message());
            }

            auto tau = detail::read_u32(payload, offset);
            if (!tau)
            {
                return protocol_result<loglabel::shrinkexpand_offline_msg>::failure(tau.error(), tau.message());
            }

            auto base = detail::read_u32(payload, offset);
            if (!base)
            {
                return protocol_result<loglabel::shrinkexpand_offline_msg>::failure(base.error(), base.message());
            }

            auto mode = detail::read_u8(payload, offset);
            if (!mode)
            {
                return protocol_result<loglabel::shrinkexpand_offline_msg>::failure(mode.error(), mode.message());
            }

            auto fingerprint = detail::read_u64(payload, offset);
            if (!fingerprint)
            {
                return protocol_result<loglabel::shrinkexpand_offline_msg>::failure(
                    fingerprint.error(), fingerprint.message());
            }

            auto ct1_rows = detail::read_u32(payload, offset);
            if (!ct1_rows)
            {
                return protocol_result<loglabel::shrinkexpand_offline_msg>::failure(
                    ct1_rows.error(), ct1_rows.message());
            }

            auto ct1_cols = detail::read_u32(payload, offset);
            if (!ct1_cols)
            {
                return protocol_result<loglabel::shrinkexpand_offline_msg>::failure(
                    ct1_cols.error(), ct1_cols.message());
            }

            auto ct1_coeffs = detail::read_u64_vector(payload, offset);
            if (!ct1_coeffs)
            {
                return protocol_result<loglabel::shrinkexpand_offline_msg>::failure(
                    ct1_coeffs.error(), ct1_coeffs.message());
            }

            auto lacct_width = detail::read_u32(payload, offset);
            if (!lacct_width)
            {
                return protocol_result<loglabel::shrinkexpand_offline_msg>::failure(
                    lacct_width.error(), lacct_width.message());
            }

            auto lacct_levels = detail::read_u32(payload, offset);
            if (!lacct_levels)
            {
                return protocol_result<loglabel::shrinkexpand_offline_msg>::failure(
                    lacct_levels.error(), lacct_levels.message());
            }

            auto lacct_rows = detail::read_u32(payload, offset);
            if (!lacct_rows)
            {
                return protocol_result<loglabel::shrinkexpand_offline_msg>::failure(
                    lacct_rows.error(), lacct_rows.message());
            }

            auto lacct_cols = detail::read_u32(payload, offset);
            if (!lacct_cols)
            {
                return protocol_result<loglabel::shrinkexpand_offline_msg>::failure(
                    lacct_cols.error(), lacct_cols.message());
            }

            auto lacct_coeffs = detail::read_u64_vector(payload, offset);
            if (!lacct_coeffs)
            {
                return protocol_result<loglabel::shrinkexpand_offline_msg>::failure(
                    lacct_coeffs.error(), lacct_coeffs.message());
            }

            if (offset != payload.size())
            {
                return protocol_result<loglabel::shrinkexpand_offline_msg>::failure(
                    protocol_errc::decode_validation_failure,
                    "shrinkexpand offline payload has trailing bytes");
            }

            loglabel::shrinkexpand_offline_msg message{};
            message.poly_modulus_degree = poly.value();
            message.coeff_modulus_bits = std::move(bits.value());
            message.plaintext_modulus_bits = plain_bits.value();
            message.alpha = alpha.value();
            message.mu = mu.value();
            message.tau = tau.value();
            message.gadget_log_base = base.value();
            message.mode = mode.value();
            message.metadata_fingerprint = fingerprint.value();
            message.ct1_rows = ct1_rows.value();
            message.ct1_cols = ct1_cols.value();
            message.ct1_coeffs = std::move(ct1_coeffs.value());
            message.lacct_width_padded = lacct_width.value();
            message.lacct_levels = lacct_levels.value();
            message.lacct_ct_rows = lacct_rows.value();
            message.lacct_ct_cols = lacct_cols.value();
            message.lacct_ct_coeffs = std::move(lacct_coeffs.value());

            return protocol_result<loglabel::shrinkexpand_offline_msg>::success(std::move(message));
        }

        static std::size_t encoded_size(const loglabel::shrinkexpand_offline_msg &message)
        {
            return sizeof(std::uint32_t) +
                   sizeof(std::uint32_t) + (message.coeff_modulus_bits.size() * sizeof(std::uint16_t)) +
                   sizeof(std::uint32_t) + sizeof(std::uint32_t) + sizeof(std::uint32_t) + sizeof(std::uint32_t) + sizeof(std::uint32_t) + sizeof(std::uint8_t) + sizeof(std::uint64_t) +
                   sizeof(std::uint32_t) + sizeof(std::uint32_t) +
                   sizeof(std::uint32_t) + (message.ct1_coeffs.size() * sizeof(std::uint64_t)) +
                   sizeof(std::uint32_t) + sizeof(std::uint32_t) + sizeof(std::uint32_t) + sizeof(std::uint32_t) +
                   sizeof(std::uint32_t) + (message.lacct_ct_coeffs.size() * sizeof(std::uint64_t));
        }
    };

} // namespace loglabel::comm

#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <tuple>
#include <vector>
#include "logvole/comm/byte_buffer_utils.hpp"
#include "logvole/comm/codec.hpp"
#include "logvole/comm/round_dsl.hpp"

namespace logvole
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
        std::uint8_t truncate_one_gadget_digit = 0;

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
        using script = logvole::comm::round_script<logvole::comm::round_pair<
            logvole::comm::round_send<shrinkexpand_offline_msg, logvole::comm::role_t::sender>,
            logvole::comm::round_recv<shrinkexpand_offline_msg, logvole::comm::role_t::receiver>>>;
    };

} // namespace logvole

namespace logvole::comm
{

    template <>
    struct message_traits<logvole::shrinkexpand_offline_msg>
    {
        static constexpr std::uint32_t payload_type = 0x5001u;

        static protocol_result<byte_buffer> encode(const logvole::shrinkexpand_offline_msg &message)
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
            detail::append_u8(out, message.truncate_one_gadget_digit);
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

        static protocol_result<logvole::shrinkexpand_offline_msg> decode(const byte_buffer &payload)
        {
            std::size_t offset = 0;

            auto poly = detail::read_u32(payload, offset);
            if (!poly)
            {
                return protocol_result<logvole::shrinkexpand_offline_msg>::failure(poly.error(), poly.message());
            }

            auto bits = detail::read_u16_vector(payload, offset);
            if (!bits)
            {
                return protocol_result<logvole::shrinkexpand_offline_msg>::failure(bits.error(), bits.message());
            }

            auto plain_bits = detail::read_u32(payload, offset);
            if (!plain_bits)
            {
                return protocol_result<logvole::shrinkexpand_offline_msg>::failure(
                    plain_bits.error(), plain_bits.message());
            }

            auto alpha = detail::read_u32(payload, offset);
            if (!alpha)
            {
                return protocol_result<logvole::shrinkexpand_offline_msg>::failure(alpha.error(), alpha.message());
            }

            auto mu = detail::read_u32(payload, offset);
            if (!mu)
            {
                return protocol_result<logvole::shrinkexpand_offline_msg>::failure(mu.error(), mu.message());
            }

            auto tau = detail::read_u32(payload, offset);
            if (!tau)
            {
                return protocol_result<logvole::shrinkexpand_offline_msg>::failure(tau.error(), tau.message());
            }

            auto base = detail::read_u32(payload, offset);
            if (!base)
            {
                return protocol_result<logvole::shrinkexpand_offline_msg>::failure(base.error(), base.message());
            }

            auto mode = detail::read_u8(payload, offset);
            if (!mode)
            {
                return protocol_result<logvole::shrinkexpand_offline_msg>::failure(mode.error(), mode.message());
            }

            auto truncate_one_gadget_digit = detail::read_u8(payload, offset);
            if (!truncate_one_gadget_digit)
            {
                return protocol_result<logvole::shrinkexpand_offline_msg>::failure(
                    truncate_one_gadget_digit.error(), truncate_one_gadget_digit.message());
            }

            auto fingerprint = detail::read_u64(payload, offset);
            if (!fingerprint)
            {
                return protocol_result<logvole::shrinkexpand_offline_msg>::failure(
                    fingerprint.error(), fingerprint.message());
            }

            auto ct1_rows = detail::read_u32(payload, offset);
            if (!ct1_rows)
            {
                return protocol_result<logvole::shrinkexpand_offline_msg>::failure(
                    ct1_rows.error(), ct1_rows.message());
            }

            auto ct1_cols = detail::read_u32(payload, offset);
            if (!ct1_cols)
            {
                return protocol_result<logvole::shrinkexpand_offline_msg>::failure(
                    ct1_cols.error(), ct1_cols.message());
            }

            auto ct1_coeffs = detail::read_u64_vector(payload, offset);
            if (!ct1_coeffs)
            {
                return protocol_result<logvole::shrinkexpand_offline_msg>::failure(
                    ct1_coeffs.error(), ct1_coeffs.message());
            }

            auto lacct_width = detail::read_u32(payload, offset);
            if (!lacct_width)
            {
                return protocol_result<logvole::shrinkexpand_offline_msg>::failure(
                    lacct_width.error(), lacct_width.message());
            }

            auto lacct_levels = detail::read_u32(payload, offset);
            if (!lacct_levels)
            {
                return protocol_result<logvole::shrinkexpand_offline_msg>::failure(
                    lacct_levels.error(), lacct_levels.message());
            }

            auto lacct_rows = detail::read_u32(payload, offset);
            if (!lacct_rows)
            {
                return protocol_result<logvole::shrinkexpand_offline_msg>::failure(
                    lacct_rows.error(), lacct_rows.message());
            }

            auto lacct_cols = detail::read_u32(payload, offset);
            if (!lacct_cols)
            {
                return protocol_result<logvole::shrinkexpand_offline_msg>::failure(
                    lacct_cols.error(), lacct_cols.message());
            }

            auto lacct_coeffs = detail::read_u64_vector(payload, offset);
            if (!lacct_coeffs)
            {
                return protocol_result<logvole::shrinkexpand_offline_msg>::failure(
                    lacct_coeffs.error(), lacct_coeffs.message());
            }

            if (offset != payload.size())
            {
                return protocol_result<logvole::shrinkexpand_offline_msg>::failure(
                    protocol_errc::decode_validation_failure, "shrinkexpand offline payload has trailing bytes");
            }

            logvole::shrinkexpand_offline_msg message{};
            message.poly_modulus_degree = poly.value();
            message.coeff_modulus_bits = std::move(bits.value());
            message.plaintext_modulus_bits = plain_bits.value();
            message.alpha = alpha.value();
            message.mu = mu.value();
            message.tau = tau.value();
            message.gadget_log_base = base.value();
            message.mode = mode.value();
            message.truncate_one_gadget_digit = truncate_one_gadget_digit.value();
            message.metadata_fingerprint = fingerprint.value();
            message.ct1_rows = ct1_rows.value();
            message.ct1_cols = ct1_cols.value();
            message.ct1_coeffs = std::move(ct1_coeffs.value());
            message.lacct_width_padded = lacct_width.value();
            message.lacct_levels = lacct_levels.value();
            message.lacct_ct_rows = lacct_rows.value();
            message.lacct_ct_cols = lacct_cols.value();
            message.lacct_ct_coeffs = std::move(lacct_coeffs.value());

            return protocol_result<logvole::shrinkexpand_offline_msg>::success(std::move(message));
        }

        static std::size_t encoded_size(const logvole::shrinkexpand_offline_msg &message)
        {
            return sizeof(std::uint32_t) + sizeof(std::uint32_t) +
                   (message.coeff_modulus_bits.size() * sizeof(std::uint16_t)) + sizeof(std::uint32_t) +
                   sizeof(std::uint32_t) + sizeof(std::uint32_t) + sizeof(std::uint32_t) + sizeof(std::uint32_t) +
                   sizeof(std::uint8_t) + sizeof(std::uint8_t) + sizeof(std::uint64_t) + sizeof(std::uint32_t) +
                   sizeof(std::uint32_t) + sizeof(std::uint32_t) +
                   (message.ct1_coeffs.size() * sizeof(std::uint64_t)) + sizeof(std::uint32_t) + sizeof(std::uint32_t) +
                   sizeof(std::uint32_t) + sizeof(std::uint32_t) + sizeof(std::uint32_t) +
                   (message.lacct_ct_coeffs.size() * sizeof(std::uint64_t));
        }
    };

} // namespace logvole::comm

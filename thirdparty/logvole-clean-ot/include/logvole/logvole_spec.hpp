#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <vector>
#include "logvole/comm/byte_buffer_utils.hpp"
#include "logvole/comm/codec.hpp"
#include "logvole/comm/round_dsl.hpp"
#include "logvole/logvole_types.hpp"

namespace logvole
{

    struct logvole_seed_msg
    {
        std::vector<std::uint8_t> seed;
    };

    struct logvole_root_offline_msg
    {
        std::uint32_t poly_modulus_degree = 0;
        std::vector<std::uint16_t> coeff_modulus_bits{};
        std::uint32_t tau_hi = 0;
        std::uint32_t gadget_log_base = 0;
        std::uint32_t plaintext_modulus_bits = 0;
        std::uint32_t left_width = 0;
        std::uint32_t randomizer_width = 0;

        std::uint32_t ct_r_rows = 0;
        std::uint32_t ct_r_cols = 0;
        std::vector<std::uint64_t> ct_r_coeffs{};

        std::uint32_t lacct_left_width_padded = 0;
        std::uint32_t lacct_left_levels = 0;
        std::uint32_t lacct_left_rows = 0;
        std::uint32_t lacct_left_cols = 0;
        std::vector<std::uint64_t> lacct_left_coeffs{};

        std::uint32_t top_ct_rows = 0;
        std::uint32_t top_ct_cols = 0;
        std::vector<std::uint64_t> top_ct_coeffs{};

        std::uint32_t public_b_star_count = 0;
        std::vector<std::uint64_t> public_b_star_coeffs{};
    };

    struct logvole_root_digest_msg
    {
        std::vector<std::uint64_t> d_prime_coeffs{};
    };

    struct logvole_root_response_msg
    {
        std::vector<std::uint8_t> seed{};
        std::vector<std::uint64_t> sk_prime_coeffs{};
    };

    struct logvole_spec
    {
        // One round specifically to send the golden seed during online phase (root level)
        using script = logvole::comm::round_script<logvole::comm::round_pair<
            logvole::comm::round_send<logvole::logvole_seed_msg, logvole::comm::role_t::sender>,
            logvole::comm::round_recv<logvole::logvole_seed_msg, logvole::comm::role_t::receiver> > >;
    };

    struct logvole_root_offline_spec
    {
        using script = logvole::comm::round_script<logvole::comm::round_pair<
            logvole::comm::round_send<logvole::logvole_root_offline_msg, logvole::comm::role_t::sender>,
            logvole::comm::round_recv<logvole::logvole_root_offline_msg, logvole::comm::role_t::receiver> > >;
    };

    struct logvole_root_online_spec
    {
        using script = logvole::comm::round_script<
            logvole::comm::round_pair<
                logvole::comm::round_send<logvole::logvole_root_digest_msg, logvole::comm::role_t::receiver>,
                logvole::comm::round_recv<logvole::logvole_root_digest_msg, logvole::comm::role_t::sender> >,
            logvole::comm::round_pair<
                logvole::comm::round_send<logvole::logvole_root_response_msg, logvole::comm::role_t::sender>,
                logvole::comm::round_recv<
                    logvole::logvole_root_response_msg, logvole::comm::role_t::receiver> > >;
    };

} // namespace logvole

namespace logvole::comm
{
    template <>
    struct message_traits<logvole::logvole_seed_msg>
    {
        static constexpr std::uint32_t payload_type = 0x6003u;

        static protocol_result<byte_buffer> encode(const logvole::logvole_seed_msg &message)
        {
            byte_buffer out;
            out.insert(out.end(), message.seed.begin(), message.seed.end());
            return protocol_result<byte_buffer>::success(std::move(out));
        }

        static protocol_result<logvole::logvole_seed_msg> decode(const byte_buffer &payload)
        {
            if (payload.empty())
            {
                return protocol_result<logvole::logvole_seed_msg>::failure(
                    protocol_errc::decode_validation_failure, "empty seed");
            }
            logvole::logvole_seed_msg msg;
            msg.seed.insert(msg.seed.end(), payload.begin(), payload.end());
            return protocol_result<logvole::logvole_seed_msg>::success(msg);
        }
    };

    template <>
    struct message_traits<logvole::logvole_root_offline_msg>
    {
        static constexpr std::uint32_t payload_type = 0x6004u;

        static protocol_result<byte_buffer> encode(const logvole::logvole_root_offline_msg &message)
        {
            byte_buffer out;
            detail::append_u32(out, message.poly_modulus_degree);
            auto bits_ok = detail::append_u16_vector(out, message.coeff_modulus_bits);
            if (!bits_ok)
            {
                return protocol_result<byte_buffer>::failure(bits_ok.error(), bits_ok.message());
            }
            detail::append_u32(out, message.tau_hi);
            detail::append_u32(out, message.gadget_log_base);
            detail::append_u32(out, message.plaintext_modulus_bits);
            detail::append_u32(out, message.left_width);
            detail::append_u32(out, message.randomizer_width);

            detail::append_u32(out, message.ct_r_rows);
            detail::append_u32(out, message.ct_r_cols);
            auto ct_r_ok = detail::append_u64_vector(out, message.ct_r_coeffs);
            if (!ct_r_ok)
            {
                return protocol_result<byte_buffer>::failure(ct_r_ok.error(), ct_r_ok.message());
            }

            detail::append_u32(out, message.lacct_left_width_padded);
            detail::append_u32(out, message.lacct_left_levels);
            detail::append_u32(out, message.lacct_left_rows);
            detail::append_u32(out, message.lacct_left_cols);
            auto lacct_ok = detail::append_u64_vector(out, message.lacct_left_coeffs);
            if (!lacct_ok)
            {
                return protocol_result<byte_buffer>::failure(lacct_ok.error(), lacct_ok.message());
            }

            detail::append_u32(out, message.top_ct_rows);
            detail::append_u32(out, message.top_ct_cols);
            auto top_ok = detail::append_u64_vector(out, message.top_ct_coeffs);
            if (!top_ok)
            {
                return protocol_result<byte_buffer>::failure(top_ok.error(), top_ok.message());
            }

            detail::append_u32(out, message.public_b_star_count);
            auto b_star_ok = detail::append_u64_vector(out, message.public_b_star_coeffs);
            if (!b_star_ok)
            {
                return protocol_result<byte_buffer>::failure(b_star_ok.error(), b_star_ok.message());
            }

            return protocol_result<byte_buffer>::success(std::move(out));
        }

        static protocol_result<logvole::logvole_root_offline_msg> decode(const byte_buffer &payload)
        {
            std::size_t offset = 0;
            auto poly = detail::read_u32(payload, offset);
            if (!poly)
                return protocol_result<logvole::logvole_root_offline_msg>::failure(poly.error(), poly.message());
            auto bits = detail::read_u16_vector(payload, offset);
            if (!bits)
                return protocol_result<logvole::logvole_root_offline_msg>::failure(bits.error(), bits.message());
            auto tau_hi = detail::read_u32(payload, offset);
            if (!tau_hi)
                return protocol_result<logvole::logvole_root_offline_msg>::failure(
                    tau_hi.error(), tau_hi.message());
            auto gadget_log_base = detail::read_u32(payload, offset);
            if (!gadget_log_base)
                return protocol_result<logvole::logvole_root_offline_msg>::failure(
                    gadget_log_base.error(), gadget_log_base.message());
            auto plaintext_modulus_bits = detail::read_u32(payload, offset);
            if (!plaintext_modulus_bits)
                return protocol_result<logvole::logvole_root_offline_msg>::failure(
                    plaintext_modulus_bits.error(), plaintext_modulus_bits.message());
            auto left_width = detail::read_u32(payload, offset);
            if (!left_width)
                return protocol_result<logvole::logvole_root_offline_msg>::failure(
                    left_width.error(), left_width.message());
            auto randomizer_width = detail::read_u32(payload, offset);
            if (!randomizer_width)
                return protocol_result<logvole::logvole_root_offline_msg>::failure(
                    randomizer_width.error(), randomizer_width.message());

            auto ct_r_rows = detail::read_u32(payload, offset);
            if (!ct_r_rows)
                return protocol_result<logvole::logvole_root_offline_msg>::failure(
                    ct_r_rows.error(), ct_r_rows.message());
            auto ct_r_cols = detail::read_u32(payload, offset);
            if (!ct_r_cols)
                return protocol_result<logvole::logvole_root_offline_msg>::failure(
                    ct_r_cols.error(), ct_r_cols.message());
            auto ct_r_coeffs = detail::read_u64_vector(payload, offset);
            if (!ct_r_coeffs)
                return protocol_result<logvole::logvole_root_offline_msg>::failure(
                    ct_r_coeffs.error(), ct_r_coeffs.message());

            auto lacct_width = detail::read_u32(payload, offset);
            if (!lacct_width)
                return protocol_result<logvole::logvole_root_offline_msg>::failure(
                    lacct_width.error(), lacct_width.message());
            auto lacct_levels = detail::read_u32(payload, offset);
            if (!lacct_levels)
                return protocol_result<logvole::logvole_root_offline_msg>::failure(
                    lacct_levels.error(), lacct_levels.message());
            auto lacct_rows = detail::read_u32(payload, offset);
            if (!lacct_rows)
                return protocol_result<logvole::logvole_root_offline_msg>::failure(
                    lacct_rows.error(), lacct_rows.message());
            auto lacct_cols = detail::read_u32(payload, offset);
            if (!lacct_cols)
                return protocol_result<logvole::logvole_root_offline_msg>::failure(
                    lacct_cols.error(), lacct_cols.message());
            auto lacct_coeffs = detail::read_u64_vector(payload, offset);
            if (!lacct_coeffs)
                return protocol_result<logvole::logvole_root_offline_msg>::failure(
                    lacct_coeffs.error(), lacct_coeffs.message());

            auto top_rows = detail::read_u32(payload, offset);
            if (!top_rows)
                return protocol_result<logvole::logvole_root_offline_msg>::failure(
                    top_rows.error(), top_rows.message());
            auto top_cols = detail::read_u32(payload, offset);
            if (!top_cols)
                return protocol_result<logvole::logvole_root_offline_msg>::failure(
                    top_cols.error(), top_cols.message());
            auto top_coeffs = detail::read_u64_vector(payload, offset);
            if (!top_coeffs)
                return protocol_result<logvole::logvole_root_offline_msg>::failure(
                    top_coeffs.error(), top_coeffs.message());

            auto b_star_count = detail::read_u32(payload, offset);
            if (!b_star_count)
                return protocol_result<logvole::logvole_root_offline_msg>::failure(
                    b_star_count.error(), b_star_count.message());
            auto b_star_coeffs = detail::read_u64_vector(payload, offset);
            if (!b_star_coeffs)
                return protocol_result<logvole::logvole_root_offline_msg>::failure(
                    b_star_coeffs.error(), b_star_coeffs.message());

            if (offset != payload.size())
            {
                return protocol_result<logvole::logvole_root_offline_msg>::failure(
                    protocol_errc::decode_validation_failure, "logvole root offline payload has trailing bytes");
            }

            logvole::logvole_root_offline_msg message{};
            message.poly_modulus_degree = poly.value();
            message.coeff_modulus_bits = std::move(bits.value());
            message.tau_hi = tau_hi.value();
            message.gadget_log_base = gadget_log_base.value();
            message.plaintext_modulus_bits = plaintext_modulus_bits.value();
            message.left_width = left_width.value();
            message.randomizer_width = randomizer_width.value();
            message.ct_r_rows = ct_r_rows.value();
            message.ct_r_cols = ct_r_cols.value();
            message.ct_r_coeffs = std::move(ct_r_coeffs.value());
            message.lacct_left_width_padded = lacct_width.value();
            message.lacct_left_levels = lacct_levels.value();
            message.lacct_left_rows = lacct_rows.value();
            message.lacct_left_cols = lacct_cols.value();
            message.lacct_left_coeffs = std::move(lacct_coeffs.value());
            message.top_ct_rows = top_rows.value();
            message.top_ct_cols = top_cols.value();
            message.top_ct_coeffs = std::move(top_coeffs.value());
            message.public_b_star_count = b_star_count.value();
            message.public_b_star_coeffs = std::move(b_star_coeffs.value());
            return protocol_result<logvole::logvole_root_offline_msg>::success(std::move(message));
        }

        static std::size_t encoded_size(const logvole::logvole_root_offline_msg &message)
        {
            return 20u * sizeof(std::uint32_t) + (message.coeff_modulus_bits.size() * sizeof(std::uint16_t)) +
                   (message.ct_r_coeffs.size() + message.lacct_left_coeffs.size() + message.top_ct_coeffs.size() +
                    message.public_b_star_coeffs.size()) *
                       sizeof(std::uint64_t);
        }
    };

    template <>
    struct message_traits<logvole::logvole_root_digest_msg>
    {
        static constexpr std::uint32_t payload_type = 0x6005u;

        static protocol_result<byte_buffer> encode(const logvole::logvole_root_digest_msg &message)
        {
            byte_buffer out;
            auto ok = detail::append_u64_vector(out, message.d_prime_coeffs);
            if (!ok)
            {
                return protocol_result<byte_buffer>::failure(ok.error(), ok.message());
            }
            return protocol_result<byte_buffer>::success(std::move(out));
        }

        static protocol_result<logvole::logvole_root_digest_msg> decode(const byte_buffer &payload)
        {
            std::size_t offset = 0;
            auto coeffs = detail::read_u64_vector(payload, offset);
            if (!coeffs)
            {
                return protocol_result<logvole::logvole_root_digest_msg>::failure(coeffs.error(), coeffs.message());
            }
            if (offset != payload.size() || coeffs.value().empty())
            {
                return protocol_result<logvole::logvole_root_digest_msg>::failure(
                    protocol_errc::decode_validation_failure, "invalid logvole root digest payload");
            }
            logvole::logvole_root_digest_msg message{};
            message.d_prime_coeffs = std::move(coeffs.value());
            return protocol_result<logvole::logvole_root_digest_msg>::success(std::move(message));
        }

        static std::size_t encoded_size(const logvole::logvole_root_digest_msg &message)
        {
            return sizeof(std::uint32_t) + message.d_prime_coeffs.size() * sizeof(std::uint64_t);
        }
    };

    template <>
    struct message_traits<logvole::logvole_root_response_msg>
    {
        static constexpr std::uint32_t payload_type = 0x6006u;

        static protocol_result<byte_buffer> encode(const logvole::logvole_root_response_msg &message)
        {
            byte_buffer out;
            if (message.seed.size() > static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max()))
            {
                return protocol_result<byte_buffer>::failure(protocol_errc::config_error, "root seed too large");
            }
            detail::append_u32(out, static_cast<std::uint32_t>(message.seed.size()));
            out.insert(out.end(), message.seed.begin(), message.seed.end());
            auto sk_ok = detail::append_u64_vector(out, message.sk_prime_coeffs);
            if (!sk_ok)
            {
                return protocol_result<byte_buffer>::failure(sk_ok.error(), sk_ok.message());
            }
            return protocol_result<byte_buffer>::success(std::move(out));
        }

        static protocol_result<logvole::logvole_root_response_msg> decode(const byte_buffer &payload)
        {
            std::size_t offset = 0;
            auto seed_size = detail::read_u32(payload, offset);
            if (!seed_size)
            {
                return protocol_result<logvole::logvole_root_response_msg>::failure(
                    seed_size.error(), seed_size.message());
            }
            if (offset + seed_size.value() > payload.size())
            {
                return protocol_result<logvole::logvole_root_response_msg>::failure(
                    protocol_errc::decode_validation_failure, "payload underflow while reading root seed");
            }
            std::vector<std::uint8_t> seed(
                payload.begin() + static_cast<std::ptrdiff_t>(offset),
                payload.begin() + static_cast<std::ptrdiff_t>(offset + seed_size.value()));
            offset += seed_size.value();
            auto sk = detail::read_u64_vector(payload, offset);
            if (!sk)
            {
                return protocol_result<logvole::logvole_root_response_msg>::failure(sk.error(), sk.message());
            }
            if (offset != payload.size() || seed.empty() || sk.value().empty())
            {
                return protocol_result<logvole::logvole_root_response_msg>::failure(
                    protocol_errc::decode_validation_failure, "invalid logvole root response payload");
            }
            logvole::logvole_root_response_msg message{};
            message.seed = std::move(seed);
            message.sk_prime_coeffs = std::move(sk.value());
            return protocol_result<logvole::logvole_root_response_msg>::success(std::move(message));
        }

        static std::size_t encoded_size(const logvole::logvole_root_response_msg &message)
        {
            return sizeof(std::uint32_t) + message.seed.size() * sizeof(std::uint8_t) + sizeof(std::uint32_t) +
                   message.sk_prime_coeffs.size() * sizeof(std::uint64_t);
        }
    };
} // namespace logvole::comm

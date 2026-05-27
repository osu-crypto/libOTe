#include "seal/util/polycore.h"
#include "seal/util/rns.h"
#include "seal/util/uintarith.h"
#include "shrinkexpand_shared_ops.hpp"
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>

namespace loglabel
{
    namespace
    {
        constexpr long double kBaseNoiseExponent = 0.1L;

        std::uint64_t mix64(std::uint64_t x)
        {
            x += 0x9E3779B97F4A7C15ull;
            x = (x ^ (x >> 30u)) * 0xBF58476D1CE4E5B9ull;
            x = (x ^ (x >> 27u)) * 0x94D049BB133111EBull;
            return x ^ (x >> 31u);
        }

        std::uint32_t log_q_bits(const ring_params &params)
        {
            std::uint32_t log_q = 0u;
            for (int bits : params.coeff_modulus_bits)
            {
                log_q += static_cast<std::uint32_t>(bits);
            }
            return log_q;
        }

        comm::protocol_result<std::int64_t> compute_base_noise_floor(const ring_params &params)
        {
            const auto log_q = static_cast<long double>(log_q_bits(params));
            const long double exponent = kBaseNoiseExponent * log_q;
            const long double base_noise = std::pow(2.0L, exponent);

            if (!std::isfinite(base_noise))
            {
                return comm::protocol_result<std::int64_t>::failure(
                    comm::protocol_errc::config_error, "q^0.1 base noise overflow");
            }

            const long double rounded_up = std::ceil(base_noise);
            if (rounded_up > static_cast<long double>(std::numeric_limits<std::int64_t>::max()))
            {
                return comm::protocol_result<std::int64_t>::failure(
                    comm::protocol_errc::config_error, "q^0.1 base noise exceeds int64 range");
            }

            const std::int64_t floor = static_cast<std::int64_t>(rounded_up);
            return comm::protocol_result<std::int64_t>::success((floor > 0) ? floor : 1);
        }

    } // namespace

    comm::protocol_result<void> validate_shrinkexpand_params(const shrinkexpand_params &params)
    {
        auto ring_ok = validate_ring_params(params.ring);
        if (!ring_ok)
        {
            return ring_ok;
        }

        if (params.alpha == 0u)
        {
            return comm::protocol_result<void>::failure(
                comm::protocol_errc::config_error, "shrinkexpand alpha must be > 0");
        }

        if (params.mu == 0u)
        {
            return comm::protocol_result<void>::failure(
                comm::protocol_errc::config_error, "shrinkexpand mu must be > 0");
        }

        if (params.tau == 0u)
        {
            return comm::protocol_result<void>::failure(
                comm::protocol_errc::config_error, "shrinkexpand tau must be > 0");
        }

        if (params.plaintext_modulus_bits == 0u)
        {
            return comm::protocol_result<void>::failure(
                comm::protocol_errc::config_error, "shrinkexpand plaintext_modulus_bits must be > 0");
        }

        const std::uint32_t log_q = log_q_bits(params.ring);

        if (log_q <= params.plaintext_modulus_bits)
        {
            return comm::protocol_result<void>::failure(
                comm::protocol_errc::config_error, "shrinkexpand requires log_q > plaintext_modulus_bits");
        }

        if (params.gadget_log_base == 0u)
        {
            return comm::protocol_result<void>::failure(
                comm::protocol_errc::config_error, "shrinkexpand gadget_log_base must be > 0");
        }

        if (params.noise_bound < 0)
        {
            return comm::protocol_result<void>::failure(
                comm::protocol_errc::config_error, "shrinkexpand noise_bound cannot be negative");
        }

        auto effective_noise = resolve_shrinkexpand_effective_noise_bound(params);
        if (!effective_noise)
        {
            return comm::protocol_result<void>::failure(effective_noise.error(), effective_noise.message());
        }

        return comm::protocol_result<void>::success();
    }

    comm::protocol_result<void> validate_shrinkexpand_sender_offline_input(
        const shrinkexpand_sender_offline_input &input)
    {
        auto params_ok = validate_shrinkexpand_params(input.params);
        if (!params_ok)
        {
            return params_ok;
        }

        if (input.s.size() != input.params.mu)
        {
            return comm::protocol_result<void>::failure(
                comm::protocol_errc::config_error, "sender offline input s size must equal mu");
        }

        return validate_ring_batch_shape(input.s, input.params.ring, "s");
    }

    comm::protocol_result<void> validate_shrinkexpand_receiver_offline_input(
        const shrinkexpand_receiver_offline_input &input)
    {
        return validate_shrinkexpand_params(input.params);
    }

    comm::protocol_result<std::int64_t> resolve_shrinkexpand_effective_noise_bound(const shrinkexpand_params &params)
    {
        if (params.mode != shrinkexpand_mode::full_noise)
        {
            return comm::protocol_result<std::int64_t>::success(params.noise_bound);
        }

        auto base_floor = compute_base_noise_floor(params.ring);
        if (!base_floor)
        {
            return comm::protocol_result<std::int64_t>::failure(base_floor.error(), base_floor.message());
        }

        const std::int64_t effective =
            (params.noise_bound > base_floor.value()) ? params.noise_bound : base_floor.value();
        return comm::protocol_result<std::int64_t>::success(effective);
    }

    std::uint64_t shrinkexpand_metadata_fingerprint(const shrinkexpand_params &params)
    {
        std::uint64_t acc = mix64(params.ring.poly_modulus_degree);
        acc ^= mix64(params.plaintext_modulus_bits);
        acc ^= mix64(params.alpha);
        acc ^= mix64(params.mu);
        acc ^= mix64(params.tau);
        acc ^= mix64(params.gadget_log_base);
        acc ^= mix64(static_cast<std::uint64_t>(params.mode));

        for (std::size_t i = 0; i < params.ring.coeff_modulus_bits.size(); ++i)
        {
            acc ^= mix64(
                static_cast<std::uint64_t>(i + 1u) * static_cast<std::uint64_t>(params.ring.coeff_modulus_bits[i]));
        }

        return acc;
    }

    std::vector<ring_rns_poly> sample_uniform_batch(
        const ring_ntt_context &ctx, std::uint32_t count, std::uint64_t seed, std::uint64_t domain_tag)
    {
        std::vector<ring_rns_poly> out;
        out.reserve(count);

        for (std::uint32_t i = 0; i < count; ++i)
        {
            const std::uint64_t nonce = seed ^ (static_cast<std::uint64_t>(i) << 1u);
            out.push_back(derive_uniform_poly_from_nonce(ctx, nonce, domain_tag, i));
        }

        return out;
    }

    comm::protocol_result<shrinkexpand_offline_msg> build_offline_message(const shrinkexpand_sender_state &state)
    {
        shrinkexpand_offline_msg msg{};
        msg.poly_modulus_degree = state.params.ring.poly_modulus_degree;
        msg.coeff_modulus_bits.reserve(state.params.ring.coeff_modulus_bits.size());
        for (const int bit : state.params.ring.coeff_modulus_bits)
        {
            msg.coeff_modulus_bits.push_back(static_cast<std::uint16_t>(bit));
        }

        msg.plaintext_modulus_bits = state.params.plaintext_modulus_bits;
        msg.alpha = state.params.alpha;
        msg.mu = state.params.mu;
        msg.tau = state.params.tau;
        msg.gadget_log_base = state.params.gadget_log_base;
        msg.mode = static_cast<std::uint8_t>(state.params.mode);
        msg.metadata_fingerprint = shrinkexpand_metadata_fingerprint(state.params);

        msg.ct1_rows = state.ct1.rows;
        msg.ct1_cols = state.ct1.cols;
        msg.ct1_coeffs = pack_ring_tensor(state.ct1);

        msg.lacct_width_padded = state.lacct.width_padded;
        msg.lacct_levels = state.lacct.levels;
        msg.lacct_ct_rows = state.lacct.ct.rows;
        msg.lacct_ct_cols = state.lacct.ct.cols;
        msg.lacct_ct_coeffs = pack_ring_tensor(state.lacct.ct);

        return comm::protocol_result<shrinkexpand_offline_msg>::success(std::move(msg));
    }

    comm::protocol_result<shrinkexpand_receiver_state> receiver_state_from_message(
        const shrinkexpand_receiver_offline_input &input, const shrinkexpand_offline_msg &message)
    {
        auto input_ok = validate_shrinkexpand_receiver_offline_input(input);
        if (!input_ok)
        {
            return comm::protocol_result<shrinkexpand_receiver_state>::failure(input_ok.error(), input_ok.message());
        }

        if (message.poly_modulus_degree != input.params.ring.poly_modulus_degree)
        {
            return comm::protocol_result<shrinkexpand_receiver_state>::failure(
                comm::protocol_errc::flow_violation, "offline message poly_modulus_degree mismatch");
        }

        if (message.coeff_modulus_bits.size() != input.params.ring.coeff_modulus_bits.size())
        {
            return comm::protocol_result<shrinkexpand_receiver_state>::failure(
                comm::protocol_errc::flow_violation, "offline message coeff_modulus_bits size mismatch");
        }

        for (std::size_t i = 0; i < message.coeff_modulus_bits.size(); ++i)
        {
            if (static_cast<int>(message.coeff_modulus_bits[i]) != input.params.ring.coeff_modulus_bits[i])
            {
                return comm::protocol_result<shrinkexpand_receiver_state>::failure(
                    comm::protocol_errc::flow_violation, "offline message coeff_modulus_bits value mismatch");
            }
        }

        if (message.plaintext_modulus_bits != input.params.plaintext_modulus_bits ||
            message.alpha != input.params.alpha || message.mu != input.params.mu || message.tau != input.params.tau ||
            message.gadget_log_base != input.params.gadget_log_base)
        {
            return comm::protocol_result<shrinkexpand_receiver_state>::failure(
                comm::protocol_errc::flow_violation, "offline message protocol shape mismatch");
        }

        if (message.mode != static_cast<std::uint8_t>(input.params.mode))
        {
            return comm::protocol_result<shrinkexpand_receiver_state>::failure(
                comm::protocol_errc::flow_violation, "offline message mode mismatch");
        }

        if (message.metadata_fingerprint != shrinkexpand_metadata_fingerprint(input.params))
        {
            return comm::protocol_result<shrinkexpand_receiver_state>::failure(
                comm::protocol_errc::flow_violation, "offline message metadata fingerprint mismatch");
        }

        const std::uint32_t coeff_mod_count = static_cast<std::uint32_t>(input.params.ring.coeff_modulus_bits.size());

        auto ct1 = unpack_ring_tensor(
            message.ct1_rows, message.ct1_cols, message.poly_modulus_degree, coeff_mod_count, message.ct1_coeffs,
            "ct1_coeffs");
        if (!ct1)
        {
            return comm::protocol_result<shrinkexpand_receiver_state>::failure(ct1.error(), ct1.message());
        }

        if (ct1.value().rows != message.mu || ct1.value().cols != message.tau)
        {
            return comm::protocol_result<shrinkexpand_receiver_state>::failure(
                comm::protocol_errc::decode_validation_failure, "ct1 tensor shape does not match mu/tau");
        }

        auto lacct_ct = unpack_ring_tensor(
            message.lacct_ct_rows, message.lacct_ct_cols, message.poly_modulus_degree, coeff_mod_count,
            message.lacct_ct_coeffs, "lacct_ct_coeffs");
        if (!lacct_ct)
        {
            return comm::protocol_result<shrinkexpand_receiver_state>::failure(lacct_ct.error(), lacct_ct.message());
        }

        if (message.lacct_width_padded == 0u || (message.lacct_width_padded & (message.lacct_width_padded - 1u)) != 0u)
        {
            return comm::protocol_result<shrinkexpand_receiver_state>::failure(
                comm::protocol_errc::decode_validation_failure, "lacct width_padded must be a power of two");
        }

        if (message.lacct_levels == 0u)
        {
            return comm::protocol_result<shrinkexpand_receiver_state>::failure(
                comm::protocol_errc::decode_validation_failure, "lacct levels must be > 0");
        }

        if (lacct_ct.value().rows != message.lacct_levels * message.lacct_width_padded ||
            lacct_ct.value().cols != 2u * message.tau)
        {
            return comm::protocol_result<shrinkexpand_receiver_state>::failure(
                comm::protocol_errc::decode_validation_failure, "lacct tensor shape mismatch");
        }

        shrinkexpand_receiver_state state{};
        state.params = input.params;
        auto effective_noise = resolve_shrinkexpand_effective_noise_bound(input.params);
        if (!effective_noise)
        {
            return comm::protocol_result<shrinkexpand_receiver_state>::failure(
                effective_noise.error(), effective_noise.message());
        }
        state.effective_noise_bound = effective_noise.value();
        state.ct1 = std::move(ct1.value());
        state.lacct.width_padded = message.lacct_width_padded;
        state.lacct.levels = message.lacct_levels;
        state.lacct.ct = std::move(lacct_ct.value());

        return comm::protocol_result<shrinkexpand_receiver_state>::success(std::move(state));
    }

    comm::protocol_result<std::vector<ring_rns_poly>> shrinkexpand_denoise_comb(
        const ring_ntt_context &ctx, const std::vector<ring_rns_poly> &tba_prime)
    {
        if (ctx.params.coeff_modulus_bits.empty() || tba_prime.size() % ctx.params.coeff_modulus_bits.size() != 0)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                comm::protocol_errc::config_error, "tba_prime size must be a multiple of rho");
        }

        const std::size_t rho = ctx.params.coeff_modulus_bits.size();
        const std::size_t n = ctx.params.poly_modulus_degree;
        const std::size_t w_prime = tba_prime.size() / rho;

        for (const auto &poly : tba_prime)
        {
            if (poly.coeffs.size() != n * rho)
            {
                return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                    comm::protocol_errc::config_error, "tba_prime polynomials must have size n * rho");
            }
        }

        auto key_context_data = ctx.context->key_context_data();
        if (!key_context_data)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                comm::protocol_errc::io_error, "failed to get key_context_data");
        }

        seal::util::RNSBase full_base(key_context_data->parms().coeff_modulus(), seal::MemoryManager::GetPool());
        auto pool = seal::MemoryManager::GetPool();

        auto composed_poly = seal::util::allocate_poly(n, rho, pool);
        auto term_mpi = seal::util::allocate_uint(rho, pool);
        auto p_j_mpi = seal::util::allocate_uint(rho, pool);
        auto p_j_half_mpi = seal::util::allocate_uint(rho, pool);
        auto mod_j_mpi = seal::util::allocate_uint(rho, pool);
        auto quotient_mpi = seal::util::allocate_uint(rho, pool);
        auto remainder_mpi = seal::util::allocate_uint(rho, pool);

        std::vector<ring_rns_poly> out;
        out.reserve(w_prime);

        for (std::size_t i = 0; i < w_prime; ++i)
        {
            ring_rns_poly poly_out;
            poly_out.coeffs.resize(n * rho, 0);

            for (std::size_t j = 0; j < rho; ++j)
            {
                const auto &poly_in = tba_prime[i * rho + j];
                std::copy(poly_in.coeffs.begin(), poly_in.coeffs.end(), composed_poly.get());

                full_base.compose_array(composed_poly.get(), n, pool);

                const auto modulus_j = full_base.base()[j];

                // compute P_j = q / q_j
                seal::util::set_uint(modulus_j.value(), rho, mod_j_mpi.get());

                seal::util::divide_uint(
                    full_base.base_prod(), mod_j_mpi.get(), rho, p_j_mpi.get(), remainder_mpi.get(), pool);

                // compute P_j / 2 for rounding
                seal::util::right_shift_uint(p_j_mpi.get(), 1, rho, p_j_half_mpi.get());

                for (std::size_t k = 0; k < n; ++k)
                {
                    const std::uint64_t *val_ptr = composed_poly.get() + k * rho;

                    // add P_j / 2 for symmetric rounding (also handles negative noise wrapping)
                    seal::util::add_uint(val_ptr, p_j_half_mpi.get(), rho, term_mpi.get());

                    seal::util::divide_uint(
                        term_mpi.get(), p_j_mpi.get(), rho, quotient_mpi.get(), remainder_mpi.get(), pool);

                    std::uint64_t scaled = quotient_mpi.get()[0];
                    if (scaled >= modulus_j.value())
                    {
                        scaled %= modulus_j.value();
                    }

                    poly_out.coeffs[j * n + k] = scaled;
                }
            }
            out.push_back(std::move(poly_out));
        }

        return comm::protocol_result<std::vector<ring_rns_poly>>::success(std::move(out));
    }

} // namespace loglabel

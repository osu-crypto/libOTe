#include "seal/util/polycore.h"
#include "seal/util/rns.h"
#include "seal/util/uintarith.h"
#include "seal/util/uintarithsmallmod.h"
#include "shrinkexpand_shared_ops.hpp"
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include "parallel_utils.hpp"
#include "simd_hints.hpp"

namespace logvole
{
    namespace
    {
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

        double eta_epsilon_ring(double n, double lambda_sec)
        {
            constexpr double pi = 3.141592653589793238462643383279502884;
            return std::sqrt((lambda_sec * std::log(2.0) + std::log(n)) / pi);
        }

        struct leaky_lwe_noise_shape
        {
            double s = -std::numeric_limits<double>::infinity();
            double sbar_over_leakage_norm = -std::numeric_limits<double>::infinity();
        };

        leaky_lwe_noise_shape compute_leaky_lwe_noise_shape(
            double s_star, double eta_eps_R, double linear_coeff, double leak_coeff)
        {
            // Leaky-LWE estimator shape used for the error-only leakage term:
            //   ||L^T L|| <= sigma_f^2 * ((s_star^2 + 2*eta^2)^-1 - s^-2).
            //
            // The estimator minimizes linear_coeff*s + leak_coeff*s_bar(s), where
            //   A = s_star^2 + 2*eta^2,
            //   s > sqrt(A),
            //   s_bar(s) = leakage_norm / sqrt(1/A - 1/s^2).
            // Writing x = s/sqrt(A), the minimizer is x = sqrt(1 + k^(2/3)).
            if (!(linear_coeff > 0.0) || !(leak_coeff > 0.0))
            {
                return {};
            }

            const double leaky_A = s_star * s_star + 2.0 * eta_eps_R * eta_eps_R;
            if (!(leaky_A > 0.0))
            {
                return {};
            }

            const double threshold = std::sqrt(leaky_A);
            const double minimizer_k = leak_coeff / linear_coeff;
            const double s_multiplier = std::sqrt(1.0 + std::pow(minimizer_k, 2.0 / 3.0));
            if (!std::isfinite(s_multiplier) || !(s_multiplier > 1.0))
            {
                return {};
            }

            leaky_lwe_noise_shape out{};
            out.s = threshold * s_multiplier;
            out.sbar_over_leakage_norm = threshold * s_multiplier / std::sqrt(s_multiplier * s_multiplier - 1.0);
            return out;
        }

        comm::protocol_result<std::int64_t> compute_base_noise_floor(const shrinkexpand_params &params)
        {
            // SEC6 noise model with the Leaky LWE refinement in compute_leaky_lwe_noise_shape.
            const double s_star = 8.0;
            const double T = 32768.0;
            const double lambda_sec = 128.0;

            // L = ceil(log2(w_prime)) + 1
            // Hardcode L = 10 for the concrete SEC6 instantiation (w'=512)
            const double L = 10.0;

            const double n = static_cast<double>(params.ring.poly_modulus_degree);
            const double m = static_cast<double>(params.tau);
            const double g = std::pow(2.0, static_cast<double>(params.gadget_log_base));
            const double gamma_R = n;

            const double eta_eps_R = eta_epsilon_ring(n, lambda_sec);
            if (!std::isfinite(eta_eps_R))
            {
                return comm::protocol_result<std::int64_t>::failure(
                    comm::protocol_errc::config_error, "SEC6 eta_epsilon(R) computation failed");
            }

            const double pref = 2.0 * std::sqrt(lambda_sec);
            const double sqrt_2mT = std::sqrt(2.0 * m * T);
            const double linear_coeff = pref * m * gamma_R * L;
            const double leak_coeff = pref * 2.0 * n * sqrt_2mT;
            const leaky_lwe_noise_shape noise_shape =
                compute_leaky_lwe_noise_shape(s_star, eta_eps_R, linear_coeff, leak_coeff);
            if (!std::isfinite(noise_shape.s) || !std::isfinite(noise_shape.sbar_over_leakage_norm))
            {
                return comm::protocol_result<std::int64_t>::failure(
                    comm::protocol_errc::config_error, "SEC6 Leaky LWE noise computation failed");
            }

            const double s = noise_shape.s;
            const double s_bar = noise_shape.sbar_over_leakage_norm * g * n * sqrt_2mT;
            const double termA = g * m * gamma_R * s * L;
            const double termB = 2.0 * s_bar;
            const double inside = termA + termB;
            const double B_total = 2.0 * std::sqrt(lambda_sec) * inside;

            if (!std::isfinite(B_total))
            {
                return comm::protocol_result<std::int64_t>::failure(
                    comm::protocol_errc::config_error, "SEC6 base noise overflow");
            }

            const double rounded_up = std::ceil(B_total);
            if (rounded_up > static_cast<double>(std::numeric_limits<std::int64_t>::max()))
            {
                return comm::protocol_result<std::int64_t>::success(std::numeric_limits<std::int64_t>::max());
            }

            const std::int64_t floor = static_cast<std::int64_t>(rounded_up);
            return comm::protocol_result<std::int64_t>::success((floor > 0) ? floor : 1);
        }

        unsigned __int128 reciprocal_2pow128(std::uint64_t modulus)
        {
            // floor(2^128 / modulus) without constructing 2^128 directly.
            const unsigned __int128 two64 = static_cast<unsigned __int128>(1) << 64;
            const std::uint64_t hi = static_cast<std::uint64_t>(two64 / modulus);
            const std::uint64_t rem = static_cast<std::uint64_t>(two64 % modulus);
            const std::uint64_t lo = static_cast<std::uint64_t>((static_cast<unsigned __int128>(rem) << 64) / modulus);
            return (static_cast<unsigned __int128>(hi) << 64) | lo;
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

        if (params.truncate_one_gadget_digit && !params.leaf_inputs_are_gadget)
        {
            const std::uint32_t supported_plaintext_bits = params.tau * params.gadget_log_base;
            if (supported_plaintext_bits < params.plaintext_modulus_bits)
            {
                return comm::protocol_result<void>::failure(
                    comm::protocol_errc::config_error,
                    "truncated shrinkexpand requires tau*gadget_log_base >= plaintext_modulus_bits");
            }
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

        auto s_shape = validate_ring_batch_shape(input.s, input.params.ring, "s");
        if (!s_shape)
        {
            return s_shape;
        }

        if (!input.fixed_sk1.empty())
        {
            if (input.fixed_sk1.size() != input.params.tau)
            {
                return comm::protocol_result<void>::failure(
                    comm::protocol_errc::config_error, "fixed sender sk1 size must equal tau");
            }

            return validate_ring_batch_shape(input.fixed_sk1, input.params.ring, "fixed_sk1");
        }

        return comm::protocol_result<void>::success();
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

        auto base_floor = compute_base_noise_floor(params);
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
        acc ^= mix64(static_cast<std::uint64_t>(params.truncate_one_gadget_digit ? 1u : 0u));
        acc ^= mix64(static_cast<std::uint64_t>(params.leaf_inputs_are_gadget ? 1u : 0u));
        acc ^= mix64(params.sampling_seeds.noise_root);
        acc ^= mix64(params.sampling_seeds.ct2_root);

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
        msg.truncate_one_gadget_digit = state.params.truncate_one_gadget_digit ? 1u : 0u;
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

        if (message.truncate_one_gadget_digit != static_cast<std::uint8_t>(input.params.truncate_one_gadget_digit))
        {
            return comm::protocol_result<shrinkexpand_receiver_state>::failure(
                comm::protocol_errc::flow_violation, "offline message truncation mode mismatch");
        }

        if (message.metadata_fingerprint != shrinkexpand_metadata_fingerprint(input.params))
        {
            return comm::protocol_result<shrinkexpand_receiver_state>::failure(
                comm::protocol_errc::flow_violation, "offline message metadata fingerprint mismatch");
        }

        const std::uint32_t coeff_mod_count = static_cast<std::uint32_t>(input.params.ring.coeff_modulus_bits.size());

        auto ct1 = unpack_ring_tensor(
            message.ct1_rows, message.ct1_cols, message.poly_modulus_degree, coeff_mod_count, message.ct1_coeffs,
            "ct1_coeffs", input.params.num_worker_threads);
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
            message.lacct_ct_coeffs, "lacct_ct_coeffs", input.params.num_worker_threads);
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

        if (message.lacct_ct_cols == 0u)
        {
            return comm::protocol_result<shrinkexpand_receiver_state>::failure(
                comm::protocol_errc::decode_validation_failure, "lacct cols must be > 0");
        }

        if (lacct_ct.value().rows != message.lacct_levels * message.lacct_width_padded ||
            lacct_ct.value().cols != message.lacct_ct_cols)
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

        auto ctx_res = make_ring_ntt_context(input.params.ring);
        if (!ctx_res)
            return comm::protocol_result<shrinkexpand_receiver_state>::failure(ctx_res.error(), ctx_res.message());
        const auto &ctx = ctx_res.value();

        state.ct1 = std::move(ct1.value());
        auto ct1_ntt_status = detail::run_parallel_tasks(
            state.ct1.polys.size(), input.params.num_worker_threads,
            [&](std::size_t poly_idx) { return forward_ntt_inplace(state.ct1.polys[poly_idx], ctx); });
        if (!ct1_ntt_status)
        {
            return comm::protocol_result<shrinkexpand_receiver_state>::failure(
                ct1_ntt_status.error(), ct1_ntt_status.message());
        }

        state.lacct.width_padded = message.lacct_width_padded;
        state.lacct.levels = message.lacct_levels;
        state.lacct.ct = std::move(lacct_ct.value());
        // LENC stores lacct rows in NTT domain; keep as-is so lenc_eval can consume directly.

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

        auto key_context_data = ctx.context->key_context_data();
        if (!key_context_data)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                comm::protocol_errc::io_error, "failed to get key_context_data");
        }

        auto pool = seal::MemoryManager::GetPool();
        seal::util::RNSBase full_base(key_context_data->parms().coeff_modulus(), pool);

        std::vector<std::uint64_t> q_i(rho);

        auto inv_punct_prod = full_base.inv_punctured_prod_mod_base_array();
        for (std::size_t i = 0; i < rho; ++i)
        {
            q_i[i] = full_base.base()[i].value();
        }

        struct denoise_recovery_constants
        {
            std::vector<std::size_t> src_limb_indices{};
            std::vector<std::uint64_t> crt_inv_punctured{};
            std::vector<std::uint64_t> punctured_prod_mod_target{};
            std::vector<unsigned __int128> frac_inv_modulus{};
            std::uint64_t delta_mod_target = 1u;
            std::uint64_t inv_delta_mod_target = 1u;
        };

        std::vector<denoise_recovery_constants> recovery(rho);
        for (std::size_t j = 0; j < rho; ++j)
        {
            const auto &mod_j = ctx.moduli[j];
            auto &constants = recovery[j];

            constants.src_limb_indices.reserve((rho > 0u) ? (rho - 1u) : 0u);
            std::vector<seal::Modulus> base_excluding_j{};
            base_excluding_j.reserve((rho > 0u) ? (rho - 1u) : 0u);

            std::uint64_t delta_mod_qj = 1u;
            for (std::size_t w = 0; w < rho; ++w)
            {
                if (w == j)
                {
                    continue;
                }
                constants.src_limb_indices.push_back(w);
                base_excluding_j.push_back(ctx.moduli[w]);
                delta_mod_qj = seal::util::multiply_uint_mod(delta_mod_qj, q_i[w], mod_j);
            }
            constants.delta_mod_target = delta_mod_qj;

            std::uint64_t inv_delta_mod_qj = 0u;
            if (!seal::util::try_invert_uint_mod(delta_mod_qj, mod_j, inv_delta_mod_qj))
            {
                return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                    comm::protocol_errc::config_error, "failed to invert Delta_j modulo q_j in denoise_comb");
            }
            constants.inv_delta_mod_target = inv_delta_mod_qj;

            if (base_excluding_j.empty())
            {
                continue;
            }

            seal::util::RNSBase reduced_base(base_excluding_j, pool);
            auto reduced_inv_punct = reduced_base.inv_punctured_prod_mod_base_array();

            const std::size_t reduced_count = constants.src_limb_indices.size();
            constants.crt_inv_punctured.resize(reduced_count, 0u);
            constants.punctured_prod_mod_target.resize(reduced_count, 0u);
            constants.frac_inv_modulus.resize(reduced_count, 0u);

            for (std::size_t idx = 0; idx < reduced_count; ++idx)
            {
                const std::size_t w = constants.src_limb_indices[idx];
                constants.crt_inv_punctured[idx] = reduced_inv_punct[idx].operand;
                constants.frac_inv_modulus[idx] = reciprocal_2pow128(q_i[w]);

                std::uint64_t punctured_mod_qj = 1u;
                for (std::size_t u = 0; u < rho; ++u)
                {
                    if (u == j || u == w)
                    {
                        continue;
                    }
                    punctured_mod_qj = seal::util::multiply_uint_mod(punctured_mod_qj, q_i[u], mod_j);
                }
                constants.punctured_prod_mod_target[idx] = punctured_mod_qj;
            }
        }

        std::vector<ring_rns_poly> out(w_prime);
        const unsigned __int128 HALF = static_cast<unsigned __int128>(1) << 127;

        auto denoise_status =
            detail::run_parallel_tasks(w_prime, 0u, [&](std::size_t i) -> comm::protocol_result<void> {
                ring_rns_poly poly_out;
                poly_out.coeffs.resize(n * rho, 0u);

                std::uint64_t *poly_out_coeffs = poly_out.coeffs.data();
                for (std::size_t j = 0; j < rho; ++j)
                {
                    const auto &poly_in = tba_prime[i * rho + j];
                    const std::uint64_t q_j = q_i[j];
                    const auto &mod_j = ctx.moduli[j];
                    const auto &constants = recovery[j];
                    const std::uint64_t *poly_in_coeffs = poly_in.coeffs.data();
                    const std::size_t reduced_count = constants.src_limb_indices.size();
                    const std::size_t *src_limb_indices = constants.src_limb_indices.data();
                    const std::uint64_t *crt_inv_punctured = constants.crt_inv_punctured.data();
                    const std::uint64_t *punctured_prod_mod_target = constants.punctured_prod_mod_target.data();
                    const unsigned __int128 *frac_inv_modulus = constants.frac_inv_modulus.data();

                    LOGVOLE_PRAGMA_IVDEP
                    for (std::size_t k = 0; k < n; ++k)
                    {
                        // Zero-BigInt Message Recovery for target limb q_j:
                        // recover e mod q_j from residues over base excluding q_j, then
                        // x_j = (t_j - e_j) * Delta_j^{-1} (mod q_j).
                        unsigned __int128 sum_frac = HALF;
                        std::uint64_t alpha = 0u;
                        std::uint64_t e_mod_qj = 0u;

                        auto consume_idx = [&](std::size_t idx) {
                            const std::size_t w = src_limb_indices[idx];
                            const std::uint64_t v_w = poly_in_coeffs[w * n + k];
                            const std::uint64_t x_w =
                                seal::util::multiply_uint_mod(v_w, crt_inv_punctured[idx], ctx.moduli[w]);

                            const unsigned __int128 term = static_cast<unsigned __int128>(x_w) * frac_inv_modulus[idx];
                            const unsigned __int128 old_frac = sum_frac;
                            sum_frac += term;
                            if (sum_frac < old_frac)
                            {
                                ++alpha;
                            }

                            const std::uint64_t x_w_mod_qj = seal::util::barrett_reduce_64(x_w, mod_j);
                            const std::uint64_t proj =
                                seal::util::multiply_uint_mod(x_w_mod_qj, punctured_prod_mod_target[idx], mod_j);
                            e_mod_qj += proj;
                            if (e_mod_qj >= q_j)
                            {
                                e_mod_qj -= q_j;
                            }
                        };

                        switch (reduced_count)
                        {
                        case 0:
                            break;
                        case 1:
                            consume_idx(0u);
                            break;
                        case 2:
                            consume_idx(0u);
                            consume_idx(1u);
                            break;
                        case 3:
                            consume_idx(0u);
                            consume_idx(1u);
                            consume_idx(2u);
                            break;
                        case 4:
                            consume_idx(0u);
                            consume_idx(1u);
                            consume_idx(2u);
                            consume_idx(3u);
                            break;
                        default:
                            LOGVOLE_PRAGMA_UNROLL
                            for (std::size_t idx = 0; idx < reduced_count; ++idx)
                            {
                                consume_idx(idx);
                            }
                            break;
                        }

                        const std::uint64_t alpha_term =
                            seal::util::multiply_uint_mod(alpha, constants.delta_mod_target, mod_j);
                        if (e_mod_qj >= alpha_term)
                        {
                            e_mod_qj -= alpha_term;
                        }
                        else
                        {
                            e_mod_qj += q_j - alpha_term;
                        }

                        const std::uint64_t v_j = poly_in_coeffs[j * n + k];
                        const std::uint64_t diff = (v_j >= e_mod_qj) ? (v_j - e_mod_qj) : (v_j + q_j - e_mod_qj);
                        const std::uint64_t x_j =
                            seal::util::multiply_uint_mod(diff, constants.inv_delta_mod_target, mod_j);
                        poly_out_coeffs[j * n + k] = x_j;
                    }
                }

                out[i] = std::move(poly_out);
                return comm::protocol_result<void>::success();
            });
        if (!denoise_status)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                denoise_status.error(), denoise_status.message());
        }

        return comm::protocol_result<std::vector<ring_rns_poly>>::success(std::move(out));
    }

} // namespace logvole

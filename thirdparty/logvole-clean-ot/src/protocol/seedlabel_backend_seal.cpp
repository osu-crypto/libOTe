#include "seal/util/rlwe.h"
#include <atomic>
#include <cmath>
#include <cstring>
#include <limits>
#include <random>
#include <shared_mutex>
#include <string>
#include <vector>
#include "lhe_ops.hpp"
#include "logvole/seedlabel_backend.hpp"
#include "logvole/ring_ops.hpp"
#include "parallel_utils.hpp"
#include "shrinkexpand_shared_ops.hpp"
#include "simd_hints.hpp"

namespace
{
    double safe_log2(double value)
    {
        return (value > 0.0) ? std::log2(value) : -std::numeric_limits<double>::infinity();
    }

    double log2_sum(double logx, double logy)
    {
        if (logx < logy)
        {
            std::swap(logx, logy);
        }

        const double diff = logx - logy;
        if (diff > 80.0)
        {
            return logx;
        }

        return logx + std::log2(1.0 + std::pow(2.0, -diff));
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

    logvole::comm::protocol_result<void> validate_plaintext_target_limb_layout(
        const logvole::seedlabel_params &params, std::size_t rho)
    {
        if (rho == 0u)
        {
            return logvole::comm::protocol_result<void>::failure(
                logvole::comm::protocol_errc::config_error, "golden-seed search requires at least one RNS limb");
        }

        const std::uint32_t mu = params.shrinkexpand.mu;
        if (mu == 0u || (mu % static_cast<std::uint32_t>(rho)) != 0u)
        {
            return logvole::comm::protocol_result<void>::failure(
                logvole::comm::protocol_errc::config_error,
                "golden-seed search requires mu to be a positive multiple of rho");
        }

        return logvole::comm::protocol_result<void>::success();
    }

    logvole::comm::protocol_result<std::size_t> resolve_plaintext_target_limb_for_sampled_poly(
        const logvole::seedlabel_params &params, std::size_t sampled_poly_idx, std::size_t rho)
    {
        auto layout_ok = validate_plaintext_target_limb_layout(params, rho);
        if (!layout_ok)
        {
            return logvole::comm::protocol_result<std::size_t>::failure(layout_ok.error(), layout_ok.message());
        }

        // The recursive RingLabel packing follows the paper's tau*rho layout: each
        // row inside a mu-sized sampled block corresponds to one plaintext modulus q_j,
        // so the active target limb is the row's position modulo rho.
        const std::size_t row_idx = sampled_poly_idx % static_cast<std::size_t>(params.shrinkexpand.mu);
        return logvole::comm::protocol_result<std::size_t>::success(row_idx % rho);
    }

    double estimate_reuse_count_log2(const logvole::seedlabel_params &params)
    {
        const double n = static_cast<double>(params.shrinkexpand.ring.poly_modulus_degree);
        const double mu = static_cast<double>(params.shrinkexpand.mu);
        if (!(n > 0.0) || !(mu > 0.0))
        {
            return -std::numeric_limits<double>::infinity();
        }

        const double log2_total_label_count = (params.total_label_count > 0u)
                                                  ? safe_log2(static_cast<double>(params.total_label_count))
                                                  : (safe_log2(n) + safe_log2(static_cast<double>(params.w)));
        const double log2_optimizer_width = safe_log2(n) + safe_log2(mu);
        const double log2_T = log2_total_label_count - log2_optimizer_width;
        return (log2_T > 0.0) ? log2_T : 0.0;
    }

    double estimate_noise_bound_log2_impl(const logvole::seedlabel_params &params)
    {
        // Match the optimizer-backed recursive LogVOLE/SysLabel model: the public
        // noise estimate is per shrinkexpand instance, with reuse count T = N / w
        // where N is the total label count and optimizer-width w = n * mu.
        // L = ceil(log2(mu)) + 1.
        constexpr double lambda_sec = 128.0;
        constexpr double s_star = 8.0;

        const double n = static_cast<double>(params.shrinkexpand.ring.poly_modulus_degree);
        const double m = static_cast<double>(params.shrinkexpand.tau);
        const double mu = static_cast<double>(params.shrinkexpand.mu);
        const double log_g = static_cast<double>(params.shrinkexpand.gadget_log_base);
        if (!(n > 0.0) || !(m > 0.0) || !(mu > 0.0) || !(log_g > 0.0))
        {
            return -std::numeric_limits<double>::infinity();
        }
        const double eta_eps_R = eta_epsilon_ring(n, lambda_sec);
        if (!std::isfinite(eta_eps_R))
        {
            return -std::numeric_limits<double>::infinity();
        }
        const double log2_T = estimate_reuse_count_log2(params);
        if (!std::isfinite(log2_T))
        {
            return -std::numeric_limits<double>::infinity();
        }
        const double L = (mu > 1.0) ? (std::ceil(std::log2(mu)) + 1.0) : 1.0;

        const double log2_mu = safe_log2(mu);
        const double log2_pref = 1.0 + 0.5 * safe_log2(lambda_sec);
        const double pref = 2.0 * std::sqrt(lambda_sec);
        const double sqrt_2mT = std::sqrt(2.0 * m) * std::pow(2.0, 0.5 * log2_T);
        double linear_coeff = pref * m * n * L;
        if (params.shrinkexpand.truncate_one_gadget_digit && params.shrinkexpand.mu > 0u)
        {
            linear_coeff += n * (1.0 + log2_mu);
        }

        const double leak_coeff = pref * 2.0 * n * sqrt_2mT;
        const leaky_lwe_noise_shape noise_shape =
            compute_leaky_lwe_noise_shape(s_star, eta_eps_R, linear_coeff, leak_coeff);
        if (!std::isfinite(noise_shape.s) || !std::isfinite(noise_shape.sbar_over_leakage_norm))
        {
            return -std::numeric_limits<double>::infinity();
        }

        const double s = noise_shape.s;
        const double log2_termA = log_g + safe_log2(m) + safe_log2(n) + safe_log2(s) + safe_log2(L);
        const double log2_sbar =
            safe_log2(noise_shape.sbar_over_leakage_norm) + log_g + safe_log2(n) + 0.5 * (safe_log2(2.0 * m) + log2_T);
        const double log2_termB = 1.0 + log2_sbar;
        const double log2_inside = log2_sum(log2_termA, log2_termB);

        double log2_B = log2_pref + log2_inside;

        if (params.shrinkexpand.truncate_one_gadget_digit && params.shrinkexpand.mu > 0u)
        {
            // App. truncation proof adds ng(max D)(1 + log2(mu)) to the rounding margin.
            // In the SEC6 estimator, s is the bound used for the short LacE r masks.
            const double log2_trunc = log_g + safe_log2(n) + safe_log2(s) + safe_log2(1.0 + safe_log2(mu));
            log2_B = log2_sum(log2_B, log2_trunc);
        }

        return log2_B;
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

    unsigned __int128 floor_to_u128(long double value)
    {
        if (!(value > 0.0L))
        {
            return 0;
        }

        constexpr long double two64_ld = 18446744073709551616.0L; // 2^64
        const long double hi_ld = std::floor(value / two64_ld);
        if (hi_ld >= two64_ld)
        {
            return ~static_cast<unsigned __int128>(0);
        }

        const auto hi = static_cast<std::uint64_t>(hi_ld);
        const long double lo_ld = std::floor(value - hi_ld * two64_ld);
        const auto lo = static_cast<std::uint64_t>((lo_ld > 0.0L) ? lo_ld : 0.0L);
        return (static_cast<unsigned __int128>(hi) << 64) | static_cast<unsigned __int128>(lo);
    }

    logvole::comm::protocol_result<void> validate_golden_seed_search_budget(
        const logvole::seedlabel_params &params, const logvole::ring_ntt_context &ctx)
    {
        const std::size_t rho = ctx.moduli.size();
        auto layout_ok = validate_plaintext_target_limb_layout(params, rho);
        if (!layout_ok)
        {
            return logvole::comm::protocol_result<void>::failure(
                layout_ok.error(), layout_ok.message());
        }
        const std::size_t n = params.shrinkexpand.ring.poly_modulus_degree;
        const std::uint32_t mu = params.shrinkexpand.mu;

        const std::uint64_t w_double_prime = static_cast<std::uint64_t>((params.w + mu - 1u) / mu);
        const std::uint64_t sampled_poly_count = w_double_prime * static_cast<std::uint64_t>(mu);
        if (sampled_poly_count == 0u)
        {
            return logvole::comm::protocol_result<void>::failure(
                logvole::comm::protocol_errc::config_error, "golden-seed search has zero sampled_poly_count");
        }

        const double log2_B = estimate_noise_bound_log2_impl(params);
        if (!std::isfinite(log2_B))
        {
            return logvole::comm::protocol_result<void>::failure(
                logvole::comm::protocol_errc::config_error, "invalid log-domain golden-seed bounds");
        }

        const double log2_sampled_coeff_count =
            safe_log2(static_cast<double>(n)) + safe_log2(static_cast<double>(sampled_poly_count));
        if (!std::isfinite(log2_sampled_coeff_count))
        {
            return logvole::comm::protocol_result<void>::failure(
                logvole::comm::protocol_errc::config_error, "invalid sampled coefficient count in golden-seed search");
        }

        double min_log2_delta_j = std::numeric_limits<double>::infinity();
        for (std::size_t j = 0; j < rho; ++j)
        {
            double log2_delta_j = 0.0;
            for (std::size_t w = 0; w < rho; ++w)
            {
                if (w == j)
                {
                    continue;
                }

                log2_delta_j += safe_log2(static_cast<double>(ctx.moduli[w].value()));
            }

            if (!std::isfinite(log2_delta_j) || log2_B > (log2_delta_j - 1.0))
            {
                return logvole::comm::protocol_result<void>::failure(
                    logvole::comm::protocol_errc::config_error,
                    "Noise B exceeds Delta_j/2. Impossible to find golden seed.");
            }
            min_log2_delta_j = std::min(min_log2_delta_j, log2_delta_j);
        }

        constexpr int k_max_seed_attempts = 100;
        const double log2_retry_budget = safe_log2(std::log(static_cast<double>(k_max_seed_attempts)));
        const double log2_retry_exponent = 1.0 + log2_B + log2_sampled_coeff_count - min_log2_delta_j;
        if (!std::isfinite(log2_retry_exponent) || log2_retry_exponent > log2_retry_budget)
        {
            const double margin_bits = min_log2_delta_j - (1.0 + log2_B + log2_sampled_coeff_count);
            return logvole::comm::protocol_result<void>::failure(
                logvole::comm::protocol_errc::config_error,
                std::string(
                    "Global golden-seed search exceeds the configured 100-attempt budget (log2(Delta_j/(2*B*N))=") +
                    std::to_string(margin_bits) + " bits).");
        }

        return logvole::comm::protocol_result<void>::success();
    }

    struct rounding_check_constants
    {
        std::size_t target_limb_index = 0u;
        std::vector<std::size_t> src_limb_indices{};
        std::vector<std::uint64_t> crt_inv_punctured{};
        std::vector<unsigned __int128> frac_inv_modulus{};
        unsigned __int128 margin = 0u;
    };

    logvole::comm::protocol_result<std::vector<rounding_check_constants>> build_rounding_check_constants(
        const logvole::seedlabel_params &params, const logvole::ring_ntt_context &ctx)
    {
        auto context_data = ctx.context->key_context_data();
        if (!context_data)
        {
            return logvole::comm::protocol_result<std::vector<rounding_check_constants>>::failure(
                logvole::comm::protocol_errc::io_error, "no key context");
        }

        auto budget_ok = validate_golden_seed_search_budget(params, ctx);
        if (!budget_ok)
        {
            return logvole::comm::protocol_result<std::vector<rounding_check_constants>>::failure(
                budget_ok.error(), budget_ok.message());
        }

        const std::size_t rho = ctx.moduli.size();
        auto layout_ok = validate_plaintext_target_limb_layout(params, rho);
        if (!layout_ok)
        {
            return logvole::comm::protocol_result<std::vector<rounding_check_constants>>::failure(
                layout_ok.error(), layout_ok.message());
        }
        auto pool = seal::MemoryManager::GetPool();
        seal::util::RNSBase full_base(context_data->parms().coeff_modulus(), pool);
        const double log2_B = estimate_noise_bound_log2_impl(params);
        if (!std::isfinite(log2_B))
        {
            return logvole::comm::protocol_result<std::vector<rounding_check_constants>>::failure(
                logvole::comm::protocol_errc::config_error, "invalid log-domain golden-seed bounds");
        }

        std::vector<rounding_check_constants> rounding(rho);
        for (std::size_t j = 0; j < rho; ++j)
        {
            auto &constants = rounding[j];
            constants.target_limb_index = j;
            constants.src_limb_indices.reserve((rho > 0u) ? (rho - 1u) : 0u);

            std::vector<seal::Modulus> base_excluding_j{};
            base_excluding_j.reserve((rho > 0u) ? (rho - 1u) : 0u);

            double log2_delta_j = 0.0;
            for (std::size_t w = 0; w < rho; ++w)
            {
                if (w == j)
                {
                    continue;
                }

                constants.src_limb_indices.push_back(w);
                base_excluding_j.push_back(full_base.base()[w]);
                log2_delta_j += safe_log2(static_cast<double>(full_base.base()[w].value()));
            }

            if (!std::isfinite(log2_delta_j) || log2_B > (log2_delta_j - 1.0))
            {
                return logvole::comm::protocol_result<std::vector<rounding_check_constants>>::failure(
                    logvole::comm::protocol_errc::config_error,
                    "Noise B exceeds Delta_j/2. Impossible to find golden seed.");
            }

            if (!base_excluding_j.empty())
            {
                seal::util::RNSBase reduced_base(base_excluding_j, pool);
                auto reduced_inv_punct = reduced_base.inv_punctured_prod_mod_base_array();
                const std::size_t reduced_count = constants.src_limb_indices.size();
                constants.crt_inv_punctured.resize(reduced_count, 0u);
                constants.frac_inv_modulus.resize(reduced_count, 0u);

                for (std::size_t idx = 0; idx < reduced_count; ++idx)
                {
                    const std::size_t w = constants.src_limb_indices[idx];
                    constants.crt_inv_punctured[idx] = reduced_inv_punct[idx].operand;
                    constants.frac_inv_modulus[idx] = reciprocal_2pow128(full_base.base()[w].value());
                }
            }

            const long double margin_exp = static_cast<long double>(log2_B - log2_delta_j + 128.0);
            const long double margin_double = std::exp2(margin_exp);
            constants.margin = floor_to_u128(margin_double);
        }

        return logvole::comm::protocol_result<std::vector<rounding_check_constants>>::success(std::move(rounding));
    }

    logvole::comm::protocol_result<bool> validate_golden_seed_candidate_impl(
        const logvole::seedlabel_params &params, const std::vector<logvole::ring_rns_poly> &tbk_per_sampled_poly,
        const logvole::ring_ntt_context &ctx)
    {
        auto tbk_shape =
            logvole::validate_ring_batch_shape(tbk_per_sampled_poly, params.shrinkexpand.ring, "tbk_per_sampled_poly");
        if (!tbk_shape)
        {
            return logvole::comm::protocol_result<bool>::failure(tbk_shape.error(), tbk_shape.message());
        }

        const std::uint32_t mu = params.shrinkexpand.mu;
        if (mu == 0u)
        {
            return logvole::comm::protocol_result<bool>::failure(
                logvole::comm::protocol_errc::config_error, "shrinkexpand mu must be > 0 in golden-seed search");
        }

        const std::size_t expected_count =
            static_cast<std::size_t>((params.w + mu - 1u) / mu) * static_cast<std::size_t>(mu);
        if (tbk_per_sampled_poly.size() != expected_count)
        {
            return logvole::comm::protocol_result<bool>::failure(
                logvole::comm::protocol_errc::config_error, "tbk_per_sampled_poly size must match ceil(w/mu) * mu");
        }

        auto rounding_result = build_rounding_check_constants(params, ctx);
        if (!rounding_result)
        {
            return logvole::comm::protocol_result<bool>::failure(rounding_result.error(), rounding_result.message());
        }

        const auto &rounding = rounding_result.value();
        const std::size_t n = params.shrinkexpand.ring.poly_modulus_degree;
        const std::size_t rho = ctx.moduli.size();
        const unsigned __int128 HALF = static_cast<unsigned __int128>(1) << 127;
        const std::uint32_t worker_threads = params.shrinkexpand.num_worker_threads;
        std::vector<const rounding_check_constants *> rounding_by_limb(rho, nullptr);
        for (const auto &constants : rounding)
        {
            rounding_by_limb[constants.target_limb_index] = &constants;
        }

        std::atomic<bool> ok{ true };
        auto status = logvole::detail::run_parallel_tasks(
            tbk_per_sampled_poly.size(), worker_threads,
            [&](std::size_t sampled_poly_idx) -> logvole::comm::protocol_result<void> {
                if (!ok.load(std::memory_order_acquire))
                {
                    return logvole::comm::protocol_result<void>::success();
                }

                const logvole::ring_rns_poly &tbk = tbk_per_sampled_poly[sampled_poly_idx];
                const std::uint64_t *V = tbk.coeffs.data();
                auto target_limb_result = resolve_plaintext_target_limb_for_sampled_poly(params, sampled_poly_idx, rho);
                if (!target_limb_result)
                {
                    return logvole::comm::protocol_result<void>::failure(
                        target_limb_result.error(), target_limb_result.message());
                }
                const rounding_check_constants *selected_constants = rounding_by_limb[target_limb_result.value()];
                if (!selected_constants)
                {
                    return logvole::comm::protocol_result<void>::failure(
                        logvole::comm::protocol_errc::invalid_state_transition,
                        "missing rounding constants for selected plaintext target limb");
                }

                LOGVOLE_PRAGMA_IVDEP
                for (std::size_t k = 0; k < n; ++k)
                {
                    const auto check_one_constants =
                        [&](const rounding_check_constants &constants) -> logvole::comm::protocol_result<void> {
                        unsigned __int128 sum_frac = HALF;
                        const std::size_t reduced_count = constants.src_limb_indices.size();
                        for (std::size_t idx = 0; idx < reduced_count; ++idx)
                        {
                            const std::size_t w = constants.src_limb_indices[idx];
                            const std::uint64_t v_w = V[w * n + k];
                            const std::uint64_t x_w =
                                seal::util::multiply_uint_mod(v_w, constants.crt_inv_punctured[idx], ctx.moduli[w]);
                            sum_frac += static_cast<unsigned __int128>(x_w) * constants.frac_inv_modulus[idx];
                        }

                        const unsigned __int128 distance_to_top = -sum_frac;
                        if (sum_frac < constants.margin || distance_to_top < constants.margin)
                        {
                            ok.store(false, std::memory_order_release);
                        }
                        return logvole::comm::protocol_result<void>::success();
                    };

                    auto one_ok = check_one_constants(*selected_constants);
                    if (!one_ok)
                    {
                        return one_ok;
                    }
                    if (!ok.load(std::memory_order_acquire))
                    {
                        return logvole::comm::protocol_result<void>::success();
                    }
                }

                return logvole::comm::protocol_result<void>::success();
            });
        if (!status)
        {
            return logvole::comm::protocol_result<bool>::failure(status.error(), status.message());
        }

        return logvole::comm::protocol_result<bool>::success(ok.load(std::memory_order_acquire));
    }
} // namespace

namespace logvole
{

    seedlabel_seal_backend::seedlabel_seal_backend() : se_backend_()
    {}

    const shrinkexpand_backend &seedlabel_seal_backend::get_shrinkexpand_backend() const
    {
        return se_backend_;
    }

    comm::protocol_result<void> seedlabel_seal_backend::validate_golden_seed_search(
        const seedlabel_params &params) const
    {
        auto ctx_result = get_ntt_context(params.shrinkexpand.ring);
        if (!ctx_result)
        {
            return comm::protocol_result<void>::failure(ctx_result.error(), ctx_result.message());
        }

        return validate_golden_seed_search_budget(params, ctx_result.value());
    }

    comm::protocol_result<ring_ntt_context> seedlabel_seal_backend::get_ntt_context(const ring_params &ring) const
    {
        {
            std::shared_lock<std::shared_mutex> read_lock(cache_mutex_);
            if (cached_ring_ && *cached_ring_ == ring)
            {
                return comm::protocol_result<ring_ntt_context>::success(ring_ntt_context(*cached_ctx_));
            }
        }

        std::unique_lock<std::shared_mutex> write_lock(cache_mutex_);
        if (cached_ring_ && *cached_ring_ == ring)
        {
            return comm::protocol_result<ring_ntt_context>::success(ring_ntt_context(*cached_ctx_));
        }

        auto ctx_result = make_ring_ntt_context(ring);
        if (!ctx_result)
        {
            return ctx_result;
        }

        cached_ring_ = ring;
        cached_ctx_ = ctx_result.value();
        return comm::protocol_result<ring_ntt_context>::success(ring_ntt_context(*cached_ctx_));
    }

    comm::protocol_result<std::vector<ring_rns_poly>> seedlabel_seal_backend::agg(
        const std::vector<ring_rns_poly> &input_hat, std::uint32_t out_count, std::uint32_t tau,
        const ring_params &ring) const
    {
        auto_timer timer(global_timing_stats.agg_time_us);
        if (input_hat.size() != out_count * tau)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                comm::protocol_errc::config_error, "seedlabel agg input hat shape mismatch");
        }

        auto ctx_result = get_ntt_context(ring);
        if (!ctx_result)
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(ctx_result.error(), ctx_result.message());
        const auto &ctx = ctx_result.value();

        std::vector<ring_rns_poly> out;
        out.reserve(out_count);

        for (std::uint32_t i = 0; i < out_count; ++i)
        {
            ring_rns_poly sum = input_hat[i * tau];
            LOGVOLE_PRAGMA_UNROLL
            for (std::uint32_t j = 1; j < tau; ++j)
            {
                auto add_ok = logvole::ring_add_inplace(sum, input_hat[i * tau + j], ctx);
                if (!add_ok)
                {
                    return comm::protocol_result<std::vector<ring_rns_poly>>::failure(add_ok.error(), add_ok.message());
                }
            }
            out.push_back(std::move(sum));
        }

        return comm::protocol_result<std::vector<ring_rns_poly>>::success(std::move(out));
    }

    comm::protocol_result<std::vector<ring_rns_poly>> seedlabel_seal_backend::gdecomp_and_unbundle(
        const ring_rns_poly &digest, std::uint32_t gadget_log_base, std::uint32_t tau, const ring_params &ring) const
    {
        auto_timer timer(global_timing_stats.gdecomp_unbundle_time_us);
        auto ctx_result = get_ntt_context(ring);
        if (!ctx_result)
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(ctx_result.error(), ctx_result.message());

        auto dec = logvole::gadget_decompose_bits(digest, gadget_log_base, tau, ctx_result.value());
        if (!dec)
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(dec.error(), dec.message());

        return comm::protocol_result<std::vector<ring_rns_poly>>::success(std::move(dec.value()));
    }

    comm::protocol_result<std::vector<ring_rns_poly>> seedlabel_seal_backend::gdecomp_hi_and_unbundle(
        const ring_rns_poly &digest, std::uint32_t gadget_log_base, std::uint32_t tau_hi, const ring_params &ring) const
    {
        auto_timer timer(global_timing_stats.gdecomp_unbundle_time_us);
        if (tau_hi == 0u)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                comm::protocol_errc::config_error, "gdecomp_hi_and_unbundle requires tau_hi > 0");
        }

        auto ctx_result = get_ntt_context(ring);
        if (!ctx_result)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(ctx_result.error(), ctx_result.message());
        }

        auto dec =
            logvole::gadget_decompose_bits_range_centered(digest, gadget_log_base, 1u, tau_hi, ctx_result.value());
        if (!dec)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(dec.error(), dec.message());
        }

        const auto &ctx = ctx_result.value();
        const std::size_t rho = ctx.moduli.size();
        const std::size_t n = ring.poly_modulus_degree;

        // Canonical per-limb lift factor Delta_j = Q / q_j represented modulo q_j.
        std::vector<std::uint64_t> delta_j_mod_qj(rho, 1u);
        for (std::size_t j = 0; j < rho; ++j)
        {
            std::uint64_t dj = 1u;
            LOGVOLE_PRAGMA_UNROLL
            for (std::size_t k = 0; k < rho; ++k)
            {
                if (k == j)
                {
                    continue;
                }
                dj = seal::util::multiply_uint_mod(dj, ctx.moduli[k].value(), ctx.moduli[j]);
            }
            delta_j_mod_qj[j] = dj;
        }

        const auto &digits = dec.value();
        std::vector<ring_rns_poly> unbundled;
        unbundled.reserve(digits.size() * rho);

        for (const auto &digit : digits)
        {
            for (std::size_t j = 0; j < rho; ++j)
            {
                ring_rns_poly lifted{};
                lifted.coeffs.assign(n * rho, 0u);
                const std::size_t limb_offset = j * n;
                const std::uint64_t *digit_coeffs = digit.coeffs.data();
                std::uint64_t *lifted_coeffs = lifted.coeffs.data();

                LOGVOLE_PRAGMA_IVDEP
                for (std::size_t c = 0; c < n; ++c)
                {
                    const std::uint64_t v_j = digit_coeffs[limb_offset + c];
                    lifted_coeffs[limb_offset + c] =
                        seal::util::multiply_uint_mod(v_j, delta_j_mod_qj[j], ctx.moduli[j]);
                }

                unbundled.push_back(std::move(lifted));
            }
        }

        return comm::protocol_result<std::vector<ring_rns_poly>>::success(std::move(unbundled));
    }

    comm::protocol_result<std::vector<ring_rns_poly>> seedlabel_seal_backend::denoise_tbm(
        const std::vector<ring_rns_poly> &tbm_prime, std::uint32_t w_prime, std::uint32_t tau,
        const ring_params &ring) const
    {
        auto_timer timer(global_timing_stats.denoise_tbm_time_us);
        auto ctx_result = get_ntt_context(ring);
        if (!ctx_result)
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(ctx_result.error(), ctx_result.message());

        return logvole::shrinkexpand_denoise_comb(ctx_result.value(), tbm_prime);
    }

    comm::protocol_result<std::vector<ring_rns_poly>> seedlabel_seal_backend::rep_offline_sender_input(
        const std::vector<ring_rns_poly> &s, std::uint32_t gamma, std::uint32_t alpha, std::uint32_t tau,
        const ring_params &ring) const
    {
        std::uint32_t rho = static_cast<std::uint32_t>(ring.coeff_modulus_bits.size());
        std::uint32_t mu = alpha * tau * rho;

        std::vector<ring_rns_poly> out;
        out.reserve(mu);

        if (gamma == 1)
        {
            if (s.empty())
                return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                    comm::protocol_errc::config_error, "s is empty for rep_offline_sender_input");

            for (std::uint32_t a = 0; a < mu; ++a)
            {
                out.push_back(s[0]);
            }
            return comm::protocol_result<std::vector<ring_rns_poly>>::success(std::move(out));
        }

        if (gamma != tau)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                comm::protocol_errc::config_error, "gamma must be 1 or tau in rep_offline_sender_input");
        }

        if (s.size() < tau)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                comm::protocol_errc::config_error, "s size mismatch for rep_offline_sender_input");
        }

        auto ctx_result = get_ntt_context(ring);
        if (!ctx_result)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(ctx_result.error(), ctx_result.message());
        }
        const auto &ctx = ctx_result.value();

        std::vector<std::uint64_t> delta_j_mod_qj(rho, 1);
        for (std::size_t j = 0; j < rho; ++j)
        {
            seal::Modulus q_j = ctx.moduli[j];
            std::uint64_t dj = 1;
            LOGVOLE_PRAGMA_UNROLL
            for (std::size_t k = 0; k < rho; ++k)
            {
                if (k == j)
                    continue;
                dj = seal::util::multiply_uint_mod(dj, ctx.moduli[k].value(), q_j);
            }
            delta_j_mod_qj[j] = dj;
        }

        std::vector<ring_rns_poly> inner;
        inner.reserve(rho * tau);
        for (std::size_t i = 0; i < tau; ++i)
        {
            for (std::size_t j = 0; j < rho; ++j)
            {
                ring_rns_poly p = s[i];
                std::uint64_t *p_coeffs = p.coeffs.data();
                for (std::size_t k = 0; k < rho; ++k)
                {
                    if (k != j)
                    {
                        std::memset(
                            &p_coeffs[k * ring.poly_modulus_degree], 0,
                            ring.poly_modulus_degree * sizeof(std::uint64_t));
                    }
                    else
                    {
                        LOGVOLE_PRAGMA_IVDEP
                        for (std::size_t c = 0; c < ring.poly_modulus_degree; ++c)
                        {
                            const std::size_t idx = j * ring.poly_modulus_degree + c;
                            p_coeffs[idx] =
                                seal::util::multiply_uint_mod(p_coeffs[idx], delta_j_mod_qj[j], ctx.moduli[j]);
                        }
                    }
                }
                inner.push_back(std::move(p));
            }
        }

        LOGVOLE_PRAGMA_UNROLL
        for (std::uint32_t a = 0; a < alpha; ++a)
        {
            for (const auto &p : inner)
            {
                out.push_back(p);
            }
        }

        return comm::protocol_result<std::vector<ring_rns_poly>>::success(std::move(out));
    }

    comm::protocol_result<golden_seed_search_output> seedlabel_seal_backend::find_golden_seed(
        const seedlabel_params &params, const std::vector<ring_rns_poly> &sk2_per_instance) const
    {
        auto_timer total_sampling_timer(global_timing_stats.seed_sampling_time_us);
        auto_timer gold_sampling_timer(global_timing_stats.gold_sampling_time_us);
        if (sk2_per_instance.empty())
        {
            return comm::protocol_result<golden_seed_search_output>::failure(
                comm::protocol_errc::config_error, "sk2_per_instance is empty");
        }

        auto ctx_result = get_ntt_context(params.shrinkexpand.ring);
        if (!ctx_result)
        {
            return comm::protocol_result<golden_seed_search_output>::failure(ctx_result.error(), ctx_result.message());
        }

        const auto &ctx = ctx_result.value();
        auto seed_budget_ok = validate_golden_seed_search_budget(params, ctx);
        if (!seed_budget_ok)
        {
            return comm::protocol_result<golden_seed_search_output>::failure(
                seed_budget_ok.error(), seed_budget_ok.message());
        }
        const std::size_t rho = ctx.moduli.size();
        const std::size_t n = params.shrinkexpand.ring.poly_modulus_degree;
        const std::size_t coeff_count = n * rho;

        auto sk2_shape = validate_ring_batch_shape(sk2_per_instance, params.shrinkexpand.ring, "sk2_per_instance");
        if (!sk2_shape)
        {
            return comm::protocol_result<golden_seed_search_output>::failure(sk2_shape.error(), sk2_shape.message());
        }

        const std::uint32_t mu = params.shrinkexpand.mu;
        if (mu == 0u)
        {
            return comm::protocol_result<golden_seed_search_output>::failure(
                comm::protocol_errc::config_error, "shrinkexpand mu must be > 0 in golden-seed search");
        }

        const std::uint64_t w_double_prime = static_cast<std::uint64_t>((params.w + mu - 1u) / mu);
        if (sk2_per_instance.size() != w_double_prime)
        {
            return comm::protocol_result<golden_seed_search_output>::failure(
                comm::protocol_errc::config_error, "sk2_per_instance size must match ceil(w/mu)");
        }

        const std::uint64_t sampled_poly_count = w_double_prime * static_cast<std::uint64_t>(mu);
        if (sampled_poly_count == 0u)
        {
            return comm::protocol_result<golden_seed_search_output>::failure(
                comm::protocol_errc::config_error, "golden-seed search has zero sampled_poly_count");
        }
        if (sampled_poly_count > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
        {
            return comm::protocol_result<golden_seed_search_output>::failure(
                comm::protocol_errc::config_error, "sampled_poly_count exceeds platform size_t range");
        }
        const std::size_t sampled_poly_count_sz = static_cast<std::size_t>(sampled_poly_count);

        auto a_result = build_lhe_public_a_ntt(ctx, mu);
        if (!a_result)
        {
            return comm::protocol_result<golden_seed_search_output>::failure(a_result.error(), a_result.message());
        }
        const auto &public_a_ntt = a_result.value();
        const std::uint32_t worker_threads = params.shrinkexpand.num_worker_threads;
        constexpr int k_max_seed_attempts = 100;

        std::vector<ring_rns_poly> ask_per_sampled_poly;
        ask_per_sampled_poly.resize(sampled_poly_count_sz);
        auto ask_status = detail::run_parallel_tasks(
            sk2_per_instance.size(), worker_threads, [&](std::size_t instance_idx) -> comm::protocol_result<void> {
                const auto &sk2 = sk2_per_instance[instance_idx];
                ring_rns_poly sk2_ntt = sk2;
                auto sk2_ntt_ok = forward_ntt_inplace(sk2_ntt, ctx);
                if (!sk2_ntt_ok)
                {
                    return comm::protocol_result<void>::failure(sk2_ntt_ok.error(), sk2_ntt_ok.message());
                }

                for (std::uint32_t row_idx = 0; row_idx < mu; ++row_idx)
                {
                    ring_rns_poly ask_ntt{};
                    ask_ntt.coeffs.assign(coeff_count, 0u);
                    auto mul_ok = dyadic_multiply_add_ntt_inplace(public_a_ntt[row_idx], sk2_ntt, ask_ntt, ctx);
                    if (!mul_ok)
                    {
                        return comm::protocol_result<void>::failure(mul_ok.error(), mul_ok.message());
                    }

                    auto ask_ok = inverse_ntt_inplace(ask_ntt, ctx);
                    if (!ask_ok)
                    {
                        return comm::protocol_result<void>::failure(ask_ok.error(), ask_ok.message());
                    }

                    const std::size_t sampled_poly_idx = instance_idx * static_cast<std::size_t>(mu) + row_idx;
                    ask_per_sampled_poly[sampled_poly_idx] = std::move(ask_ntt);
                }

                return comm::protocol_result<void>::success();
            });
        if (!ask_status)
        {
            return comm::protocol_result<golden_seed_search_output>::failure(ask_status.error(), ask_status.message());
        }

        std::vector<std::uint8_t> seed(16);
        const std::uint64_t sk2_head = !sk2_per_instance[0].coeffs.empty() ? sk2_per_instance[0].coeffs[0] : 0u;
        const std::uint64_t seed_material = derive_deterministic_seed_material(
            params.shrinkexpand.sampling_seeds.ct2_root, 0x5345414C47534544ull, sampled_poly_count, mu,
            w_double_prime, sk2_head);
        std::mt19937_64 gen(seed_material);
        std::uniform_int_distribution<std::uint8_t> dist_bytes(0, 255);

        bool found = false;
        std::vector<ring_rns_poly> tbk_per_sampled_poly;
        std::vector<ring_rns_poly> attempt_ct2_per_sampled_poly(sampled_poly_count_sz);
        std::vector<std::uint64_t> attempt_instance_nonces(sk2_per_instance.size());

        for (int attempt = 0; attempt < k_max_seed_attempts && !found; ++attempt)
        {
            LOGVOLE_PRAGMA_UNROLL
            for (int i = 0; i < 16; ++i)
            {
                seed[i] = dist_bytes(gen);
            }

            for (std::size_t sampled_instance_idx = 0; sampled_instance_idx < sk2_per_instance.size();
                 ++sampled_instance_idx)
            {
                const std::uint64_t instance_idx = static_cast<std::uint64_t>(sampled_instance_idx);
                attempt_instance_nonces[sampled_instance_idx] =
                    derive_ct2_nonce(
                        params.shrinkexpand.sampling_seeds,
                        derive_seed_instance_nonce(params.shrinkexpand.sampling_seeds, seed, instance_idx), mu);
            }

            const std::uint32_t sampling_workers = (worker_threads <= 1u) ? 0u : worker_threads;
            auto ct2_status = derive_uniform_poly_batch_from_nonce_list_inplace(
                ctx, attempt_instance_nonces, 0xC720AA55u, mu, attempt_ct2_per_sampled_poly, sampling_workers);
            if (!ct2_status)
            {
                return comm::protocol_result<golden_seed_search_output>::failure(
                    ct2_status.error(), ct2_status.message());
            }
            if (attempt_ct2_per_sampled_poly.size() != sampled_poly_count_sz)
            {
                return comm::protocol_result<golden_seed_search_output>::failure(
                    comm::protocol_errc::flow_violation, "ct2 batch sampling size mismatch in golden-seed search");
            }

            auto subtract_status = detail::run_parallel_tasks(
                sk2_per_instance.size(), worker_threads,
                [&](std::size_t sampled_instance_idx) -> comm::protocol_result<void> {
                    for (std::uint32_t row_idx = 0; row_idx < mu; ++row_idx)
                    {
                        const std::size_t sampled_poly_idx =
                            sampled_instance_idx * static_cast<std::size_t>(mu) + row_idx;
                        auto sub_ok = ring_sub_inplace(
                            attempt_ct2_per_sampled_poly[sampled_poly_idx], ask_per_sampled_poly[sampled_poly_idx],
                            ctx);
                        if (!sub_ok)
                        {
                            return comm::protocol_result<void>::failure(sub_ok.error(), sub_ok.message());
                        }
                    }
                    return comm::protocol_result<void>::success();
                });
            if (!subtract_status)
            {
                return comm::protocol_result<golden_seed_search_output>::failure(
                    subtract_status.error(), subtract_status.message());
            }

            auto candidate_ok = validate_golden_seed_candidate_impl(params, attempt_ct2_per_sampled_poly, ctx);
            if (!candidate_ok)
            {
                return comm::protocol_result<golden_seed_search_output>::failure(
                    candidate_ok.error(), candidate_ok.message());
            }

            if (candidate_ok.value())
            {
                found = true;
                tbk_per_sampled_poly = std::move(attempt_ct2_per_sampled_poly);
            }
        }

        if (!found)
        {
            return comm::protocol_result<golden_seed_search_output>::failure(
                comm::protocol_errc::flow_violation, "Failed to find golden seed within 100 attempts.");
        }

        golden_seed_search_output output{};
        output.seed = std::move(seed);
        output.tbk_per_sampled_poly = std::move(tbk_per_sampled_poly);
        return comm::protocol_result<golden_seed_search_output>::success(std::move(output));
    }

    comm::protocol_result<bool> seedlabel_seal_backend::validate_golden_seed_candidate(
        const seedlabel_params &params, const std::vector<ring_rns_poly> &tbk_per_sampled_poly) const
    {
        auto ctx_result = get_ntt_context(params.shrinkexpand.ring);
        if (!ctx_result)
        {
            return comm::protocol_result<bool>::failure(ctx_result.error(), ctx_result.message());
        }

        return validate_golden_seed_candidate_impl(params, tbk_per_sampled_poly, ctx_result.value());
    }

    comm::protocol_result<std::vector<ring_rns_poly>> seedlabel_seal_backend::sample_ct2_from_seed(
        const sampling_seed_config &sampling_seeds, const std::vector<std::uint8_t> &seed, std::uint32_t instance_idx,
        std::uint32_t coeff_count, const ring_params &ring) const
    {
        auto ctx_result = get_ntt_context(ring);
        if (!ctx_result)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(ctx_result.error(), ctx_result.message());
        }

        const std::uint64_t instance_nonce =
            derive_seed_instance_nonce(sampling_seeds, seed, static_cast<std::uint64_t>(instance_idx));
        return build_hashed_ct2(ctx_result.value(), coeff_count, sampling_seeds, instance_nonce);
    }

} // namespace logvole

#include "seal/util/uintarithsmallmod.h"
#include "logvole/logvole_protocol.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstring>
#include <future>
#include <limits>
#include <optional>
#include <random>
#include <thread>
#include <vector>
#include "lenc_ops.hpp"
#include "lhe_ops.hpp"
#include "logvole/comm/protocol_engine.hpp"
#include "logvole/comm/subchannel_wrapper.hpp"
#include "logvole/seedlabel_types.hpp"
#include "logvole/shrinkexpand_noise.hpp"
#include "logvole/shrinkexpand_protocol.hpp"
#include "logvole/logvole_shared_ops.hpp"
#include "logvole/logvole_spec.hpp"
#include "parallel_utils.hpp"
#include "runtime_cache_scope.hpp"
#include "shrinkexpand_shared_ops.hpp"

namespace logvole
{
    namespace
    {
        ring_rns_poly make_zero_poly(const ring_params &ring)
        {
            ring_rns_poly zero_poly{};
            zero_poly.coeffs.assign(
                ring.poly_modulus_degree * ring.coeff_modulus_bits.size(), static_cast<std::uint64_t>(0u));
            return zero_poly;
        }

        std::uint64_t pow2_mod(std::uint64_t exp, std::uint64_t mod)
        {
            std::uint64_t result = 1u;
            std::uint64_t base = 2u % mod;
            while (exp > 0u)
            {
                if ((exp & 1u) != 0u)
                {
                    const auto mul = static_cast<unsigned __int128>(result) * base;
                    result = static_cast<std::uint64_t>(mul % mod);
                }
                const auto sq = static_cast<unsigned __int128>(base) * base;
                base = static_cast<std::uint64_t>(sq % mod);
                exp >>= 1u;
            }
            return result;
        }

        std::uint32_t root_randomizer_width(std::uint32_t tau_full)
        {
            return std::max<std::uint32_t>(3u, tau_full + 1u);
        }

        std::uint32_t root_left_width(std::uint32_t tau_hi, std::uint32_t rho)
        {
            return tau_hi * rho;
        }

        double root_noise_sigma(const shrinkexpand_params &params, double factor)
        {
            if (params.mode != shrinkexpand_mode::full_noise)
            {
                return 0.0;
            }
            return shrinkexpand_noise_params::std_s * ((factor > 1.0) ? factor : 1.0);
        }

        double root_noise_max_deviation(double sigma)
        {
            return (sigma > 0.0) ? (std::sqrt(shrinkexpand_noise_params::lambda) * sigma) : 0.0;
        }

        lenc_lacct to_lenc_lacct(const shrinkexpand_lacct &in)
        {
            lenc_lacct out{};
            out.width_padded = in.width_padded;
            out.levels = in.levels;
            out.ct = in.ct;
            return out;
        }

        comm::protocol_result<std::uint32_t> compute_tau_hi(std::uint32_t tau_full)
        {
            if (tau_full < 2u)
            {
                return comm::protocol_result<std::uint32_t>::failure(
                    comm::protocol_errc::config_error, "logvole requires shrinkexpand.tau >= 2");
            }
            return comm::protocol_result<std::uint32_t>::success(tau_full - 1u);
        }

        comm::protocol_result<shrinkexpand_params> make_trunc_shrinkexpand_params(
            const logvole_params &params, bool leaf_inputs_are_gadget)
        {
            auto tau_hi_res = compute_tau_hi(params.shrinkexpand.tau);
            if (!tau_hi_res)
            {
                return comm::protocol_result<shrinkexpand_params>::failure(tau_hi_res.error(), tau_hi_res.message());
            }

            const std::uint32_t tau_hi = tau_hi_res.value();
            const std::uint32_t rho = static_cast<std::uint32_t>(params.shrinkexpand.ring.coeff_modulus_bits.size());
            if (rho == 0u)
            {
                return comm::protocol_result<shrinkexpand_params>::failure(
                    comm::protocol_errc::config_error, "logvole requires non-empty coeff_modulus_bits");
            }

            shrinkexpand_params se_params = params.shrinkexpand;
            se_params.tau = tau_hi;
            se_params.mu = se_params.alpha * tau_hi * rho;
            se_params.truncate_one_gadget_digit = true;
            se_params.leaf_inputs_are_gadget = leaf_inputs_are_gadget;
            return comm::protocol_result<shrinkexpand_params>::success(std::move(se_params));
        }

        seedlabel_params make_seed_params(const logvole_params &params, const shrinkexpand_params &se_params)
        {
            seedlabel_params seed_params{};
            seed_params.shrinkexpand = se_params;
            seed_params.w = params.w;
            seed_params.gamma = params.gamma;
            seed_params.total_label_count = params.total_label_count;
            return seed_params;
        }

        comm::protocol_result<void> prewarm_seed_public_a_cache(const ring_params &ring, std::uint32_t mu)
        {
            auto ctx_result = make_ring_ntt_context(ring);
            if (!ctx_result)
            {
                return comm::protocol_result<void>::failure(ctx_result.error(), ctx_result.message());
            }

            auto public_a_result = build_lhe_public_a_ntt(ctx_result.value(), mu);
            if (!public_a_result)
            {
                return comm::protocol_result<void>::failure(public_a_result.error(), public_a_result.message());
            }

            return comm::protocol_result<void>::success();
        }

        comm::protocol_result<std::vector<ring_rns_poly>> gdecomp_hi_and_unbundle(
            const logvole_backend &backend, const ring_rns_poly &poly, std::uint32_t gadget_log_base,
            std::uint32_t tau_hi, const ring_params &ring)
        {
            if (tau_hi == 0u)
            {
                return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                    comm::protocol_errc::config_error, "gdecomp_hi_and_unbundle requires tau_hi > 0");
            }

            // LogVOLE only needs the high gadget digits, but the recursive state still
            // needs the per-limb CRT unbundling expected by the backend unwind.
            auto hi_dec = backend.gdecomp_hi_and_unbundle(poly, gadget_log_base, tau_hi, ring);
            if (!hi_dec)
            {
                return comm::protocol_result<std::vector<ring_rns_poly>>::failure(hi_dec.error(), hi_dec.message());
            }
            return comm::protocol_result<std::vector<ring_rns_poly>>::success(std::move(hi_dec.value()));
        }

        comm::protocol_result<std::vector<ring_rns_poly>> replicate_root_hi_key_by_limb(
            const ring_ntt_context &ctx, const std::vector<ring_rns_poly> &sk_hi, std::uint32_t tau_hi)
        {
            if (tau_hi == 0u || sk_hi.size() != tau_hi || ctx.moduli.empty())
            {
                return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                    comm::protocol_errc::config_error, "root key replication requires sk_hi size == tau_hi > 0");
            }

            auto shape = validate_ring_batch_shape(sk_hi, ctx.params, "root_sk_hi");
            if (!shape)
            {
                return comm::protocol_result<std::vector<ring_rns_poly>>::failure(shape.error(), shape.message());
            }

            std::vector<ring_rns_poly> out;
            out.reserve(static_cast<std::size_t>(tau_hi) * ctx.moduli.size());
            for (std::uint32_t digit = 0u; digit < tau_hi; ++digit)
            {
                for (std::size_t limb = 0u; limb < ctx.moduli.size(); ++limb)
                {
                    (void)limb;
                    out.push_back(sk_hi[digit]);
                }
            }
            return comm::protocol_result<std::vector<ring_rns_poly>>::success(std::move(out));
        }

        comm::protocol_result<std::vector<ring_rns_poly>> sample_root_error_batch(
            const ring_ntt_context &ctx, std::uint32_t count, const sampling_seed_config &sampling_seeds,
            std::uint64_t domain, double sigma, double max_deviation, bool output_ntt, std::uint32_t requested_workers)
        {
            if (count == 0u)
            {
                return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                    comm::protocol_errc::config_error, "root error sampler requires count > 0");
            }

            std::vector<ring_rns_poly> out(count);
            auto sample_status = detail::run_parallel_tasks(
                count, requested_workers, [&](std::size_t idx) -> comm::protocol_result<void> {
                    ring_rns_poly poly{};
                    poly.coeffs.assign(ring_poly_coeff_count(ctx.params), 0u);
                    if (sigma > 0.0)
                    {
                        const std::uint64_t seed = derive_noise_seed(
                            sampling_seeds, domain, static_cast<std::uint64_t>(idx), count,
                            static_cast<std::uint64_t>(ctx.moduli.size()));
                        auto noise_ok = add_poly_error(poly, sigma, max_deviation, seed, 0u, ctx);
                        if (!noise_ok)
                        {
                            return comm::protocol_result<void>::failure(noise_ok.error(), noise_ok.message());
                        }
                    }
                    if (output_ntt)
                    {
                        auto ntt_ok = forward_ntt_inplace(poly, ctx);
                        if (!ntt_ok)
                        {
                            return comm::protocol_result<void>::failure(ntt_ok.error(), ntt_ok.message());
                        }
                    }
                    out[idx] = std::move(poly);
                    return comm::protocol_result<void>::success();
                });
            if (!sample_status)
            {
                return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                    sample_status.error(), sample_status.message());
            }
            return comm::protocol_result<std::vector<ring_rns_poly>>::success(std::move(out));
        }

        comm::protocol_result<void> add_scaled_ntt_inplace(
            ring_rns_poly &acc_ntt, const ring_rns_poly &poly_ntt, std::uint32_t gadget_log_base, std::uint32_t power,
            const ring_ntt_context &ctx, bool subtract)
        {
            if (acc_ntt.coeffs.size() != poly_ntt.coeffs.size())
            {
                return comm::protocol_result<void>::failure(
                    comm::protocol_errc::config_error, "scaled NTT add shape mismatch");
            }

            const auto shift = static_cast<std::uint64_t>(gadget_log_base) * static_cast<std::uint64_t>(power);
            const std::size_t n = ctx.params.poly_modulus_degree;
            for (std::size_t mod_idx = 0; mod_idx < ctx.moduli.size(); ++mod_idx)
            {
                const auto &modulus = ctx.moduli[mod_idx];
                const std::uint64_t mod = modulus.value();
                const std::uint64_t factor = pow2_mod(shift, mod);
                const std::size_t offset = mod_idx * n;
                for (std::size_t coeff_idx = 0; coeff_idx < n; ++coeff_idx)
                {
                    const std::size_t idx = offset + coeff_idx;
                    const std::uint64_t scaled = seal::util::multiply_uint_mod(poly_ntt.coeffs[idx], factor, modulus);
                    if (subtract)
                    {
                        acc_ntt.coeffs[idx] = (acc_ntt.coeffs[idx] >= scaled) ? (acc_ntt.coeffs[idx] - scaled)
                                                                              : (acc_ntt.coeffs[idx] + mod - scaled);
                    }
                    else
                    {
                        std::uint64_t sum = acc_ntt.coeffs[idx] + scaled;
                        if (sum >= mod)
                        {
                            sum -= mod;
                        }
                        acc_ntt.coeffs[idx] = sum;
                    }
                }
            }

            return comm::protocol_result<void>::success();
        }

        void negate_ntt_inplace(ring_rns_poly &poly_ntt, const ring_ntt_context &ctx)
        {
            const std::size_t n = ctx.params.poly_modulus_degree;
            for (std::size_t mod_idx = 0; mod_idx < ctx.moduli.size(); ++mod_idx)
            {
                const std::uint64_t mod = ctx.moduli[mod_idx].value();
                const std::size_t offset = mod_idx * n;
                for (std::size_t coeff_idx = 0; coeff_idx < n; ++coeff_idx)
                {
                    const std::size_t idx = offset + coeff_idx;
                    if (poly_ntt.coeffs[idx] != 0u)
                    {
                        poly_ntt.coeffs[idx] = mod - poly_ntt.coeffs[idx];
                    }
                }
            }
        }

        using uint128 = unsigned __int128;

        std::uint64_t uint128_mod(uint128 value, const seal::Modulus &modulus)
        {
            const std::uint64_t mod = modulus.value();
            const std::uint64_t lo = static_cast<std::uint64_t>(value);
            const std::uint64_t hi = static_cast<std::uint64_t>(value >> 64u);
            const std::uint64_t two64_mod = static_cast<std::uint64_t>((uint128{ 1u } << 64u) % mod);
            const auto hi_term = static_cast<uint128>(hi % mod) * two64_mod;
            return static_cast<std::uint64_t>((hi_term + (lo % mod)) % mod);
        }

        std::uint64_t fresh_root_zeta_seed()
        {
            static std::atomic<std::uint64_t> counter{ 0u };
            std::uint64_t seed = combine_seed_public(counter.fetch_add(1u, std::memory_order_relaxed));
            seed ^= combine_seed_public(
                static_cast<std::uint64_t>(std::chrono::high_resolution_clock::now().time_since_epoch().count()));

            std::random_device rd;
            for (std::uint32_t idx = 0u; idx < 4u; ++idx)
            {
                const std::uint64_t lo = static_cast<std::uint64_t>(rd());
                const std::uint64_t hi = static_cast<std::uint64_t>(rd());
                seed = combine_seed_public(seed ^ (hi << 32u) ^ lo ^ static_cast<std::uint64_t>(idx));
            }
            return seed;
        }

        comm::protocol_result<ring_tensor> build_root_top_ct(
            const ring_ntt_context &ctx, const std::vector<ring_rns_poly> &r1, const std::vector<ring_rns_poly> &r2_ntt,
            const std::vector<ring_rns_poly> &public_b_root_ntt, const std::vector<ring_rns_poly> &public_b_star_ntt,
            std::uint32_t gadget_log_base, std::uint32_t gadget_power_offset,
            const sampling_seed_config &sampling_seeds, double noise_standard_deviation, double noise_max_deviation,
            std::uint32_t requested_workers)
        {
            const std::uint32_t left_width = static_cast<std::uint32_t>(r1.size());
            const std::uint32_t tau_hi = static_cast<std::uint32_t>(public_b_root_ntt.size());
            const std::uint32_t randomizer = static_cast<std::uint32_t>(public_b_star_ntt.size());
            if (left_width == 0u || r2_ntt.size() != left_width || tau_hi == 0u || randomizer == 0u)
            {
                return comm::protocol_result<ring_tensor>::failure(
                    comm::protocol_errc::config_error, "invalid root top wrapper dimensions");
            }

            auto r1_shape = validate_ring_batch_shape(r1, ctx.params, "root_r1");
            if (!r1_shape)
            {
                return comm::protocol_result<ring_tensor>::failure(r1_shape.error(), r1_shape.message());
            }
            auto r2_shape = validate_ring_batch_shape(r2_ntt, ctx.params, "root_r2_ntt");
            if (!r2_shape)
            {
                return comm::protocol_result<ring_tensor>::failure(r2_shape.error(), r2_shape.message());
            }
            auto b_root_shape = validate_ring_batch_shape(public_b_root_ntt, ctx.params, "root_public_b_ntt");
            if (!b_root_shape)
            {
                return comm::protocol_result<ring_tensor>::failure(b_root_shape.error(), b_root_shape.message());
            }
            auto b_star_shape = validate_ring_batch_shape(public_b_star_ntt, ctx.params, "root_public_b_star_ntt");
            if (!b_star_shape)
            {
                return comm::protocol_result<ring_tensor>::failure(b_star_shape.error(), b_star_shape.message());
            }

            std::vector<ring_rns_poly> r1_ntt = r1;
            auto r1_ntt_status = detail::run_parallel_tasks(r1_ntt.size(), requested_workers, [&](std::size_t idx) {
                return forward_ntt_inplace(r1_ntt[idx], ctx);
            });
            if (!r1_ntt_status)
            {
                return comm::protocol_result<ring_tensor>::failure(r1_ntt_status.error(), r1_ntt_status.message());
            }

            ring_tensor top_ct{};
            top_ct.rows = left_width;
            top_ct.cols = tau_hi + randomizer;
            top_ct.polys.resize(ring_tensor_size(top_ct));

            auto fill_status = detail::run_parallel_tasks(
                static_cast<std::size_t>(left_width), requested_workers,
                [&](std::size_t row_idx) -> comm::protocol_result<void> {
                    const std::uint32_t row = static_cast<std::uint32_t>(row_idx);
                    for (std::uint32_t col = 0u; col < top_ct.cols; ++col)
                    {
                        const ring_rns_poly &b_ntt =
                            (col < tau_hi) ? public_b_root_ntt[col] : public_b_star_ntt[col - tau_hi];
                        ring_rns_poly cell_ntt{};
                        cell_ntt.coeffs.assign(ring_poly_coeff_count(ctx.params), 0u);
                        auto mul_ok = dyadic_multiply_add_ntt_inplace(r1_ntt[row], b_ntt, cell_ntt, ctx);
                        if (!mul_ok)
                        {
                            return comm::protocol_result<void>::failure(mul_ok.error(), mul_ok.message());
                        }
                        // Local LEnc digests are stored with the opposite sign from
                        // the paper notation. The published d'_rt is negated below
                        // as well, so the root-wrapper identity is unchanged.
                        negate_ntt_inplace(cell_ntt, ctx);
                        if (col < tau_hi)
                        {
                            auto sub_ok = add_scaled_ntt_inplace(
                                cell_ntt, r2_ntt[row], gadget_log_base, gadget_power_offset + col, ctx, true);
                            if (!sub_ok)
                            {
                                return sub_ok;
                            }
                        }
                        if (noise_standard_deviation > 0.0)
                        {
                            const std::uint64_t stream_id =
                                (static_cast<std::uint64_t>(row) << 32u) ^ static_cast<std::uint64_t>(col);
                            const std::uint64_t noise_seed = derive_noise_seed(
                                sampling_seeds, 0x5254544F504E5A45ull, stream_id, left_width, top_ct.cols);
                            ring_rns_poly noise{};
                            noise.coeffs.assign(ring_poly_coeff_count(ctx.params), 0u);
                            auto noise_ok = add_poly_error(
                                noise, noise_standard_deviation, noise_max_deviation, noise_seed, 0u, ctx);
                            if (!noise_ok)
                            {
                                return comm::protocol_result<void>::failure(noise_ok.error(), noise_ok.message());
                            }
                            auto ntt_ok = forward_ntt_inplace(noise, ctx);
                            if (!ntt_ok)
                            {
                                return comm::protocol_result<void>::failure(ntt_ok.error(), ntt_ok.message());
                            }
                            auto add_ok = ring_add_inplace(cell_ntt, noise, ctx);
                            if (!add_ok)
                            {
                                return comm::protocol_result<void>::failure(add_ok.error(), add_ok.message());
                            }
                        }
                        top_ct.polys[ring_tensor_index(top_ct, row, col)] = std::move(cell_ntt);
                    }
                    return comm::protocol_result<void>::success();
                });
            if (!fill_status)
            {
                return comm::protocol_result<ring_tensor>::failure(fill_status.error(), fill_status.message());
            }

            return comm::protocol_result<ring_tensor>::success(std::move(top_ct));
        }

        comm::protocol_result<std::vector<ring_rns_poly>> sample_root_zeta(
            const ring_ntt_context &ctx, std::uint32_t randomizer_width, std::uint32_t gadget_log_base)
        {
            if (randomizer_width == 0u)
            {
                return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                    comm::protocol_errc::config_error, "root randomizer width must be > 0");
            }
            if (gadget_log_base == 0u || gadget_log_base > 127u)
            {
                return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                    comm::protocol_errc::config_error, "root zeta sampler requires 0 < gadget_log_base <= 127");
            }

            const std::size_t n = ctx.params.poly_modulus_degree;
            const std::size_t rho = ctx.moduli.size();
            std::uint64_t seed = derive_deterministic_seed_material(
                fresh_root_zeta_seed(), 0x52544E5A455441ull, ctx.params.poly_modulus_degree, randomizer_width,
                gadget_log_base, rho);
            const uint128 eta = (uint128{ 1u } << gadget_log_base) - 1u;
            const std::uint32_t sample_bits = gadget_log_base + 1u;
            const uint128 sample_mask = (sample_bits == 128u) ? ~uint128{ 0u } : ((uint128{ 1u } << sample_bits) - 1u);

            std::vector<ring_rns_poly> zeta(randomizer_width);
            for (std::uint32_t poly_idx = 0u; poly_idx < randomizer_width; ++poly_idx)
            {
                ring_rns_poly poly{};
                poly.coeffs.assign(n * rho, 0u);
                for (std::size_t coeff_idx = 0u; coeff_idx < n; ++coeff_idx)
                {
                    uint128 raw = 0u;
                    do
                    {
                        seed = combine_seed_public(
                            seed ^ (static_cast<std::uint64_t>(poly_idx) << 32u) ^
                            static_cast<std::uint64_t>(coeff_idx));
                        const std::uint64_t lo = seed;
                        seed = combine_seed_public(seed + 0x9E3779B97F4A7C15ull);
                        const std::uint64_t hi = seed;
                        raw = ((static_cast<uint128>(hi) << 64u) | lo) & sample_mask;
                    } while (raw == sample_mask);

                    const bool negative = raw <= eta;
                    const uint128 magnitude = negative ? (eta - raw) : (raw - eta);
                    for (std::size_t mod_idx = 0u; mod_idx < rho; ++mod_idx)
                    {
                        const std::size_t out_idx = mod_idx * n + coeff_idx;
                        const std::uint64_t mod = ctx.moduli[mod_idx].value();
                        const std::uint64_t reduced = uint128_mod(magnitude, ctx.moduli[mod_idx]);
                        poly.coeffs[out_idx] = (negative && reduced != 0u) ? (mod - reduced) : reduced;
                    }
                }
                zeta[poly_idx] = std::move(poly);
            }

            return comm::protocol_result<std::vector<ring_rns_poly>>::success(std::move(zeta));
        }

        comm::protocol_result<ring_rns_poly> root_inner_product_ntt(
            const ring_ntt_context &ctx, const std::vector<ring_rns_poly> &left_ntt,
            const std::vector<ring_rns_poly> &right_coeff, std::uint32_t requested_workers)
        {
            if (left_ntt.size() != right_coeff.size() || left_ntt.empty())
            {
                return comm::protocol_result<ring_rns_poly>::failure(
                    comm::protocol_errc::config_error, "root inner product requires equal non-empty vectors");
            }

            std::vector<ring_rns_poly> right_ntt = right_coeff;
            auto ntt_status = detail::run_parallel_tasks(right_ntt.size(), requested_workers, [&](std::size_t idx) {
                return forward_ntt_inplace(right_ntt[idx], ctx);
            });
            if (!ntt_status)
            {
                return comm::protocol_result<ring_rns_poly>::failure(ntt_status.error(), ntt_status.message());
            }

            ring_rns_poly acc_ntt{};
            acc_ntt.coeffs.assign(ring_poly_coeff_count(ctx.params), 0u);
            for (std::size_t idx = 0u; idx < left_ntt.size(); ++idx)
            {
                auto mul_ok = dyadic_multiply_add_ntt_inplace(left_ntt[idx], right_ntt[idx], acc_ntt, ctx);
                if (!mul_ok)
                {
                    return comm::protocol_result<ring_rns_poly>::failure(mul_ok.error(), mul_ok.message());
                }
            }

            auto intt_ok = inverse_ntt_inplace(acc_ntt, ctx);
            if (!intt_ok)
            {
                return comm::protocol_result<ring_rns_poly>::failure(intt_ok.error(), intt_ok.message());
            }
            return comm::protocol_result<ring_rns_poly>::success(std::move(acc_ntt));
        }

        struct logvole_shrink_chunk_result
        {
            ring_rns_poly digest{};
            std::shared_ptr<digest_tree> tree{};
            std::vector<ring_rns_poly> digest_decomp{};
        };

        struct logvole_seeded_eval_output
        {
            bool valid = false;
            std::vector<ring_rns_poly> tbk{};
        };

        using logvole_sender_precompute_future =
            std::shared_future<comm::protocol_result<logvole_sender_precompute_output>>;

        void accumulate_counters(comm::comm_counters &dst, const comm::comm_counters &src)
        {
            dst.frames_s2r_sent += src.frames_s2r_sent;
            dst.frames_s2r_recv += src.frames_s2r_recv;
            dst.frames_r2s_sent += src.frames_r2s_sent;
            dst.frames_r2s_recv += src.frames_r2s_recv;
            dst.wire_bytes_s2r_sent += src.wire_bytes_s2r_sent;
            dst.wire_bytes_s2r_recv += src.wire_bytes_s2r_recv;
            dst.wire_bytes_r2s_sent += src.wire_bytes_r2s_sent;
            dst.wire_bytes_r2s_recv += src.wire_bytes_r2s_recv;
            dst.payload_bytes_s2r_sent += src.payload_bytes_s2r_sent;
            dst.payload_bytes_s2r_recv += src.payload_bytes_s2r_recv;
            dst.payload_bytes_r2s_sent += src.payload_bytes_r2s_sent;
            dst.payload_bytes_r2s_recv += src.payload_bytes_r2s_recv;
            dst.rounds_completed += src.rounds_completed;
        }

        std::uint32_t compute_logvole_mu_hi(const logvole_params &params)
        {
            const auto tau_hi_res = compute_tau_hi(params.shrinkexpand.tau);
            if (!tau_hi_res)
            {
                return 0u;
            }
            const std::uint32_t rho = static_cast<std::uint32_t>(params.shrinkexpand.ring.coeff_modulus_bits.size());
            return params.shrinkexpand.alpha * tau_hi_res.value() * rho;
        }

        std::uint32_t compute_logvole_w_double_prime(const logvole_params &params)
        {
            const std::uint32_t mu_hi = compute_logvole_mu_hi(params);
            return mu_hi == 0u ? 0u : (params.w + mu_hi - 1u) / mu_hi;
        }

        comm::protocol_result<logvole_root_offline_msg> setup_logvole_root_wrapper_sender(
            logvole_sender_state &state, const logvole_backend &backend)
        {
            (void)backend;
            auto tau_hi_res = compute_tau_hi(state.params.shrinkexpand.tau);
            if (!tau_hi_res)
            {
                return comm::protocol_result<logvole_root_offline_msg>::failure(
                    tau_hi_res.error(), tau_hi_res.message());
            }

            const std::uint32_t tau_hi = tau_hi_res.value();
            const std::uint32_t tau_full = tau_hi + 1u;
            const std::uint32_t rho =
                static_cast<std::uint32_t>(state.params.shrinkexpand.ring.coeff_modulus_bits.size());
            const std::uint32_t left_width = root_left_width(tau_hi, rho);
            const std::uint32_t randomizer = root_randomizer_width(tau_full);
            const std::uint32_t worker_threads = state.shrinkexpand_state.params.num_worker_threads;

            if (state.shrinkexpand_state.sk1.size() != tau_hi)
            {
                return comm::protocol_result<logvole_root_offline_msg>::failure(
                    comm::protocol_errc::invalid_state_transition, "root wrapper requires level-1 sk1");
            }

            auto ctx_result = make_ring_ntt_context(state.params.shrinkexpand.ring);
            if (!ctx_result)
            {
                return comm::protocol_result<logvole_root_offline_msg>::failure(
                    ctx_result.error(), ctx_result.message());
            }
            const auto &ctx = ctx_result.value();

            auto root_sk_hi = replicate_root_hi_key_by_limb(ctx, state.shrinkexpand_state.sk1, tau_hi);
            if (!root_sk_hi)
            {
                return comm::protocol_result<logvole_root_offline_msg>::failure(
                    root_sk_hi.error(), root_sk_hi.message());
            }
            if (root_sk_hi.value().size() != left_width)
            {
                return comm::protocol_result<logvole_root_offline_msg>::failure(
                    comm::protocol_errc::flow_violation, "root wrapper lifted secret width mismatch");
            }

            const auto public_b_full_ntt = build_lenc_public_b_ntt(ctx, tau_full);
            if (public_b_full_ntt.size() < 2u * tau_full)
            {
                return comm::protocol_result<logvole_root_offline_msg>::failure(
                    comm::protocol_errc::config_error, "root wrapper public B size mismatch");
            }
            std::vector<ring_rns_poly> public_b_root_ntt;
            public_b_root_ntt.reserve(tau_hi);
            for (std::uint32_t idx = 0u; idx < tau_hi; ++idx)
            {
                public_b_root_ntt.push_back(public_b_full_ntt[1u + idx]);
            }

            const double lenc_sigma =
                root_noise_sigma(state.params.shrinkexpand, std::sqrt(static_cast<double>(tau_hi)));
            const double lenc_max_dev = root_noise_max_deviation(lenc_sigma);
            auto left_lenc_res = lenc_enc_trunc(
                ctx, root_sk_hi.value(), tau_hi, state.params.shrinkexpand.gadget_log_base,
                state.params.shrinkexpand.plaintext_modulus_bits, state.params.shrinkexpand.sampling_seeds, lenc_sigma,
                lenc_max_dev, 0u, false, true, &public_b_full_ntt, worker_threads);
            if (!left_lenc_res)
            {
                return comm::protocol_result<logvole_root_offline_msg>::failure(
                    left_lenc_res.error(), left_lenc_res.message());
            }
            auto left_lenc = std::move(left_lenc_res.value());

            std::vector<ring_rns_poly> public_b_star_ntt;
            public_b_star_ntt.reserve(randomizer);
            for (std::uint32_t idx = 0u; idx < randomizer; ++idx)
            {
                public_b_star_ntt.push_back(
                    derive_uniform_poly_from_nonce_ntt(ctx, 0x52544E43524F4F54ull, 0xB57A52u, idx));
            }

            auto r1_res = sample_root_error_batch(
                ctx, left_width, state.params.shrinkexpand.sampling_seeds, 0x5254523154524E43ull, lenc_sigma,
                lenc_max_dev, false, worker_threads);
            if (!r1_res)
            {
                return comm::protocol_result<logvole_root_offline_msg>::failure(r1_res.error(), r1_res.message());
            }
            std::vector<ring_rns_poly> r1 = std::move(r1_res.value());

            const std::uint64_t sk_r_seed = derive_noise_seed(
                state.params.shrinkexpand.sampling_seeds, 0x5254534B52544Dull, left_width, tau_hi, randomizer);
            std::vector<ring_rns_poly> sk_r_rt = sample_uniform_batch(ctx, tau_hi, sk_r_seed, 0x5254534Bu);

            const double lhe_sigma = root_noise_sigma(
                state.params.shrinkexpand, std::sqrt(static_cast<double>(left_lenc.lacct.width_padded)));
            const double lhe_max_dev = root_noise_max_deviation(lhe_sigma);
            auto ct_r_res = lhe_enc1_trunc(
                ctx, r1, sk_r_rt, state.params.shrinkexpand.gadget_log_base, lhe_sigma, lhe_max_dev,
                state.params.shrinkexpand.sampling_seeds, false, nullptr, worker_threads);
            if (!ct_r_res)
            {
                return comm::protocol_result<logvole_root_offline_msg>::failure(
                    ct_r_res.error(), ct_r_res.message());
            }

            auto top_ct_res = build_root_top_ct(
                ctx, r1, left_lenc.r_ntt, public_b_root_ntt, public_b_star_ntt,
                state.params.shrinkexpand.gadget_log_base, 1u, state.params.shrinkexpand.sampling_seeds, lenc_sigma,
                lenc_max_dev, worker_threads);
            if (!top_ct_res)
            {
                return comm::protocol_result<logvole_root_offline_msg>::failure(
                    top_ct_res.error(), top_ct_res.message());
            }

            state.root_sk_r_rt = std::move(sk_r_rt);
            state.root_r1_rt = std::move(r1);
            state.root_randomizer_width = randomizer;

            logvole_root_offline_msg message{};
            message.poly_modulus_degree = state.params.shrinkexpand.ring.poly_modulus_degree;
            message.coeff_modulus_bits.reserve(state.params.shrinkexpand.ring.coeff_modulus_bits.size());
            for (int bit : state.params.shrinkexpand.ring.coeff_modulus_bits)
            {
                message.coeff_modulus_bits.push_back(static_cast<std::uint16_t>(bit));
            }
            message.tau_hi = tau_hi;
            message.gadget_log_base = state.params.shrinkexpand.gadget_log_base;
            message.plaintext_modulus_bits = state.params.shrinkexpand.plaintext_modulus_bits;
            message.left_width = left_width;
            message.randomizer_width = randomizer;

            const ring_tensor ct_r = std::move(ct_r_res.value());
            message.ct_r_rows = ct_r.rows;
            message.ct_r_cols = ct_r.cols;
            message.ct_r_coeffs = pack_ring_tensor(ct_r);

            message.lacct_left_width_padded = left_lenc.lacct.width_padded;
            message.lacct_left_levels = left_lenc.lacct.levels;
            message.lacct_left_rows = left_lenc.lacct.ct.rows;
            message.lacct_left_cols = left_lenc.lacct.ct.cols;
            message.lacct_left_coeffs = pack_ring_tensor(left_lenc.lacct.ct);

            const ring_tensor top_ct = std::move(top_ct_res.value());
            message.top_ct_rows = top_ct.rows;
            message.top_ct_cols = top_ct.cols;
            message.top_ct_coeffs = pack_ring_tensor(top_ct);

            message.public_b_star_count = randomizer;
            message.public_b_star_coeffs = pack_ring_batch(public_b_star_ntt);

            return comm::protocol_result<logvole_root_offline_msg>::success(std::move(message));
        }

        comm::protocol_result<void> finalize_logvole_root_wrapper_receiver(
            logvole_receiver_state &state, const logvole_root_offline_msg &message)
        {
            auto tau_hi_res = compute_tau_hi(state.params.shrinkexpand.tau);
            if (!tau_hi_res)
            {
                return comm::protocol_result<void>::failure(tau_hi_res.error(), tau_hi_res.message());
            }

            const std::uint32_t tau_hi = tau_hi_res.value();
            const std::uint32_t tau_full = tau_hi + 1u;
            const std::uint32_t rho =
                static_cast<std::uint32_t>(state.params.shrinkexpand.ring.coeff_modulus_bits.size());
            const std::uint32_t left_width = root_left_width(tau_hi, rho);
            const std::uint32_t randomizer = root_randomizer_width(tau_full);
            const std::uint32_t coeff_mod_count = rho;
            const std::uint32_t worker_threads = state.shrinkexpand_state.params.num_worker_threads;

            if (message.poly_modulus_degree != state.params.shrinkexpand.ring.poly_modulus_degree ||
                message.coeff_modulus_bits.size() != state.params.shrinkexpand.ring.coeff_modulus_bits.size() ||
                message.tau_hi != tau_hi || message.gadget_log_base != state.params.shrinkexpand.gadget_log_base ||
                message.plaintext_modulus_bits != state.params.shrinkexpand.plaintext_modulus_bits ||
                message.left_width != left_width || message.randomizer_width != randomizer)
            {
                return comm::protocol_result<void>::failure(
                    comm::protocol_errc::flow_violation, "root wrapper offline metadata mismatch");
            }
            for (std::size_t idx = 0u; idx < message.coeff_modulus_bits.size(); ++idx)
            {
                if (static_cast<int>(message.coeff_modulus_bits[idx]) !=
                    state.params.shrinkexpand.ring.coeff_modulus_bits[idx])
                {
                    return comm::protocol_result<void>::failure(
                        comm::protocol_errc::flow_violation, "root wrapper coeff modulus mismatch");
                }
            }

            auto ctx_result = make_ring_ntt_context(state.params.shrinkexpand.ring);
            if (!ctx_result)
            {
                return comm::protocol_result<void>::failure(ctx_result.error(), ctx_result.message());
            }
            const auto &ctx = ctx_result.value();

            auto ct_r = unpack_ring_tensor(
                message.ct_r_rows, message.ct_r_cols, message.poly_modulus_degree, coeff_mod_count, message.ct_r_coeffs,
                "root_ct_r", worker_threads);
            if (!ct_r)
            {
                return comm::protocol_result<void>::failure(ct_r.error(), ct_r.message());
            }
            if (ct_r.value().rows != left_width || ct_r.value().cols != tau_hi)
            {
                return comm::protocol_result<void>::failure(
                    comm::protocol_errc::decode_validation_failure, "root ct_r tensor shape mismatch");
            }
            auto ct_r_ntt_status =
                detail::run_parallel_tasks(ct_r.value().polys.size(), worker_threads, [&](std::size_t poly_idx) {
                    return forward_ntt_inplace(ct_r.value().polys[poly_idx], ctx);
                });
            if (!ct_r_ntt_status)
            {
                return comm::protocol_result<void>::failure(ct_r_ntt_status.error(), ct_r_ntt_status.message());
            }

            auto lacct_left = unpack_ring_tensor(
                message.lacct_left_rows, message.lacct_left_cols, message.poly_modulus_degree, coeff_mod_count,
                message.lacct_left_coeffs, "root_lacct_left", worker_threads);
            if (!lacct_left)
            {
                return comm::protocol_result<void>::failure(lacct_left.error(), lacct_left.message());
            }
            if (message.lacct_left_width_padded == 0u ||
                (message.lacct_left_width_padded & (message.lacct_left_width_padded - 1u)) != 0u ||
                lacct_left.value().rows != message.lacct_left_width_padded * message.lacct_left_levels ||
                lacct_left.value().cols != message.lacct_left_cols)
            {
                return comm::protocol_result<void>::failure(
                    comm::protocol_errc::decode_validation_failure, "root left LacE tensor shape mismatch");
            }

            auto top_ct = unpack_ring_tensor(
                message.top_ct_rows, message.top_ct_cols, message.poly_modulus_degree, coeff_mod_count,
                message.top_ct_coeffs, "root_top_ct", worker_threads);
            if (!top_ct)
            {
                return comm::protocol_result<void>::failure(top_ct.error(), top_ct.message());
            }
            if (top_ct.value().rows != left_width || top_ct.value().cols != tau_hi + randomizer)
            {
                return comm::protocol_result<void>::failure(
                    comm::protocol_errc::decode_validation_failure, "root top tensor shape mismatch");
            }

            auto b_star = unpack_ring_batch(
                message.public_b_star_count, message.poly_modulus_degree, coeff_mod_count, message.public_b_star_coeffs,
                "root_public_b_star", worker_threads);
            if (!b_star)
            {
                return comm::protocol_result<void>::failure(b_star.error(), b_star.message());
            }
            if (b_star.value().size() != randomizer)
            {
                return comm::protocol_result<void>::failure(
                    comm::protocol_errc::decode_validation_failure, "root public B* width mismatch");
            }

            state.root_ct_r_rt = std::move(ct_r.value());
            state.root_lacct_left.width_padded = message.lacct_left_width_padded;
            state.root_lacct_left.levels = message.lacct_left_levels;
            state.root_lacct_left.ct = std::move(lacct_left.value());
            state.root_top_ct = std::move(top_ct.value());
            state.root_public_b_star_ntt = std::move(b_star.value());
            state.root_randomizer_width = randomizer;
            return comm::protocol_result<void>::success();
        }

        std::uint64_t count_logvole_seed_instances(const logvole_sender_state &state)
        {
            const auto tau_hi_res = compute_tau_hi(state.params.shrinkexpand.tau);
            if (!tau_hi_res)
            {
                return 0u;
            }

            const auto mode = eval_logvole_mode(
                state.params.w, state.params.shrinkexpand.alpha, tau_hi_res.value(),
                static_cast<std::uint32_t>(state.params.shrinkexpand.ring.coeff_modulus_bits.size()));
            if (mode == logvole_mode::root)
            {
                return 1u;
            }
            if (!state.next_level_state)
            {
                return 0u;
            }

            return count_logvole_seed_instances(*state.next_level_state) +
                   compute_logvole_w_double_prime(state.params);
        }

        std::uint64_t count_logvole_seed_instances(const logvole_receiver_state &state)
        {
            const auto tau_hi_res = compute_tau_hi(state.params.shrinkexpand.tau);
            if (!tau_hi_res)
            {
                return 0u;
            }

            const auto mode = eval_logvole_mode(
                state.params.w, state.params.shrinkexpand.alpha, tau_hi_res.value(),
                static_cast<std::uint32_t>(state.params.shrinkexpand.ring.coeff_modulus_bits.size()));
            if (mode == logvole_mode::root)
            {
                return 1u;
            }
            if (!state.next_level_state)
            {
                return 0u;
            }

            return count_logvole_seed_instances(*state.next_level_state) +
                   compute_logvole_w_double_prime(state.params);
        }

        comm::protocol_result<std::vector<std::uint8_t>> resolve_cached_logvole_receiver_seed(
            const logvole_receiver_state &state)
        {
            if (!state.golden_seed.empty())
            {
                return comm::protocol_result<std::vector<std::uint8_t>>::success(state.golden_seed);
            }
            if (state.next_level_state)
            {
                return resolve_cached_logvole_receiver_seed(*state.next_level_state);
            }
            return comm::protocol_result<std::vector<std::uint8_t>>::failure(
                comm::protocol_errc::invalid_state_transition, "missing randomized root seed");
        }

        comm::protocol_result<ring_rns_poly> ensure_logvole_root_k_prime(const logvole_sender_state &state)
        {
            if (state.root_k_prime_rt)
            {
                return comm::protocol_result<ring_rns_poly>::success(*state.root_k_prime_rt);
            }

            auto ctx_result = make_ring_ntt_context(state.params.shrinkexpand.ring);
            if (!ctx_result)
            {
                return comm::protocol_result<ring_rns_poly>::failure(ctx_result.error(), ctx_result.message());
            }

            const std::uint64_t seed_material = derive_deterministic_seed_material(
                state.params.shrinkexpand.sampling_seeds.ct2_root, 0x52544B5052494D45ull, state.params.w,
                compute_logvole_mu_hi(state.params), state.root_randomizer_width,
                state.root_sk_r_rt.empty() || state.root_sk_r_rt[0].coeffs.empty() ? 0u
                                                                                   : state.root_sk_r_rt[0].coeffs[0]);
            ring_rns_poly k_prime = derive_uniform_poly_from_nonce(ctx_result.value(), seed_material, 0x52544B50u, 0u);
            state.root_k_prime_rt = std::make_shared<ring_rns_poly>(k_prime);
            return comm::protocol_result<ring_rns_poly>::success(std::move(k_prime));
        }

        std::uint64_t derive_root_derand_nonce(
            const sampling_seed_config &sampling_seeds, const std::vector<std::uint8_t> &seed)
        {
            return derive_seed_instance_nonce(sampling_seeds, seed, 0u, 0xD37A4D5EEDu);
        }

        comm::protocol_result<ring_rns_poly> compute_logvole_root_sender_key(
            const logvole_sender_state &state, const logvole_backend &backend,
            const std::vector<std::uint8_t> &seed)
        {
            auto tau_hi_res = compute_tau_hi(state.params.shrinkexpand.tau);
            if (!tau_hi_res)
            {
                return comm::protocol_result<ring_rns_poly>::failure(tau_hi_res.error(), tau_hi_res.message());
            }

            if (state.root_k_rt && !state.golden_seed.empty() && state.golden_seed == seed)
            {
                return comm::protocol_result<ring_rns_poly>::success(*state.root_k_rt);
            }

            const std::uint32_t tau_hi = tau_hi_res.value();
            const std::uint32_t rho =
                static_cast<std::uint32_t>(state.params.shrinkexpand.ring.coeff_modulus_bits.size());
            const std::uint32_t left_width = root_left_width(tau_hi, rho);
            auto k_prime_res = ensure_logvole_root_k_prime(state);
            if (!k_prime_res)
            {
                return k_prime_res;
            }

            auto ctx_result = make_ring_ntt_context(state.params.shrinkexpand.ring);
            if (!ctx_result)
            {
                return comm::protocol_result<ring_rns_poly>::failure(ctx_result.error(), ctx_result.message());
            }

            auto ct_k = build_hashed_ct2(
                ctx_result.value(), left_width, state.params.shrinkexpand.sampling_seeds,
                derive_root_derand_nonce(state.params.shrinkexpand.sampling_seeds, seed));
            if (!ct_k)
            {
                return comm::protocol_result<ring_rns_poly>::failure(ct_k.error(), ct_k.message());
            }

            auto tbk_rt = lhe_dec(
                ctx_result.value(), ct_k.value(), k_prime_res.value(), nullptr, false, false,
                state.shrinkexpand_state.params.num_worker_threads);
            if (!tbk_rt)
            {
                return comm::protocol_result<ring_rns_poly>::failure(tbk_rt.error(), tbk_rt.message());
            }

            auto denoised = backend.denoise_tbm(tbk_rt.value(), 1u, tau_hi, state.params.shrinkexpand.ring);
            if (!denoised)
            {
                return comm::protocol_result<ring_rns_poly>::failure(denoised.error(), denoised.message());
            }

            auto aggregated = backend.agg(denoised.value(), 1u, tau_hi, state.params.shrinkexpand.ring);
            if (!aggregated)
            {
                return comm::protocol_result<ring_rns_poly>::failure(aggregated.error(), aggregated.message());
            }
            if (aggregated.value().size() != 1u)
            {
                return comm::protocol_result<ring_rns_poly>::failure(
                    comm::protocol_errc::flow_violation, "root sender key aggregation produced wrong width");
            }

            return comm::protocol_result<ring_rns_poly>::success(std::move(aggregated.value()[0]));
        }

        comm::protocol_result<void> validate_recursive_logvole_seed_search(
            const logvole_sender_state &state, const logvole_backend &backend)
        {
            auto tau_hi_res = compute_tau_hi(state.params.shrinkexpand.tau);
            if (!tau_hi_res)
            {
                return comm::protocol_result<void>::failure(tau_hi_res.error(), tau_hi_res.message());
            }

            const auto mode = eval_logvole_mode(
                state.params.w, state.params.shrinkexpand.alpha, tau_hi_res.value(),
                static_cast<std::uint32_t>(state.params.shrinkexpand.ring.coeff_modulus_bits.size()));
            const auto seed_params = make_seed_params(state.params, state.shrinkexpand_state.params);
            auto seed_budget_ok = backend.validate_golden_seed_search(seed_params);
            if (!seed_budget_ok)
            {
                return comm::protocol_result<void>::failure(seed_budget_ok.error(), seed_budget_ok.message());
            }

            if (mode == logvole_mode::root)
            {
                const std::uint32_t mu_hi = compute_logvole_mu_hi(state.params);
                if (state.params.w != mu_hi)
                {
                    return comm::protocol_result<void>::failure(
                        comm::protocol_errc::config_error,
                        "randomized-root LogVOLE requires the terminal width to equal mu_hi");
                }
                if (state.shrinkexpand_state.params.mu != mu_hi || state.root_sk_r_rt.empty())
                {
                    return comm::protocol_result<void>::failure(
                        comm::protocol_errc::invalid_state_transition, "missing root wrapper sender state");
                }
                return comm::protocol_result<void>::success();
            }
            if (!state.next_level_state)
            {
                return comm::protocol_result<void>::failure(
                    comm::protocol_errc::invalid_state_transition, "Missing next_level_state in sender_online");
            }

            return validate_recursive_logvole_seed_search(*state.next_level_state, backend);
        }

        comm::protocol_result<logvole_seeded_eval_output> evaluate_logvole_sender_seed_candidate(
            const logvole_sender_state &state, const logvole_backend &backend,
            const std::vector<std::uint8_t> &seed)
        {
            auto tau_hi_res = compute_tau_hi(state.params.shrinkexpand.tau);
            if (!tau_hi_res)
            {
                return comm::protocol_result<logvole_seeded_eval_output>::failure(
                    tau_hi_res.error(), tau_hi_res.message());
            }

            const std::uint32_t tau_hi = tau_hi_res.value();
            const std::uint32_t w = state.params.w;
            const std::uint32_t alpha = state.params.shrinkexpand.alpha;
            const std::uint32_t rho =
                static_cast<std::uint32_t>(state.params.shrinkexpand.ring.coeff_modulus_bits.size());
            const auto mode = eval_logvole_mode(w, alpha, tau_hi, rho);

            if (mode == logvole_mode::root)
            {
                const std::uint32_t mu_hi = compute_logvole_mu_hi(state.params);
                if (w != mu_hi)
                {
                    return comm::protocol_result<logvole_seeded_eval_output>::failure(
                        comm::protocol_errc::config_error,
                        "randomized-root LogVOLE terminal width must equal mu_hi");
                }

                auto root_key = compute_logvole_root_sender_key(state, backend, seed);
                if (!root_key)
                {
                    return comm::protocol_result<logvole_seeded_eval_output>::failure(
                        root_key.error(), root_key.message());
                }

                shrinkexpand_expand_sender_input se_exp_in{};
                se_exp_in.nonce = derive_seed_instance_nonce(state.params.shrinkexpand.sampling_seeds, seed, 0u);
                se_exp_in.tbk_prime = root_key.value();

                auto se_exp_out =
                    shrinkexpand_expand_sender(state.shrinkexpand_state, se_exp_in, backend.get_shrinkexpand_backend());
                if (!se_exp_out)
                {
                    return comm::protocol_result<logvole_seeded_eval_output>::failure(
                        se_exp_out.error(), se_exp_out.message());
                }

                auto seed_params = make_seed_params(state.params, state.shrinkexpand_state.params);
                auto candidate_ok = backend.validate_golden_seed_candidate(seed_params, se_exp_out.value().tbk);
                if (!candidate_ok)
                {
                    return comm::protocol_result<logvole_seeded_eval_output>::failure(
                        candidate_ok.error(), candidate_ok.message());
                }
                if (!candidate_ok.value())
                {
                    return comm::protocol_result<logvole_seeded_eval_output>::success(
                        logvole_seeded_eval_output{});
                }

                state.golden_seed = seed;
                state.root_k_rt = std::make_shared<ring_rns_poly>(root_key.value());
                logvole_seeded_eval_output output{};
                output.valid = true;
                output.tbk = std::move(se_exp_out.value().tbk);
                return comm::protocol_result<logvole_seeded_eval_output>::success(std::move(output));
            }

            if (!state.next_level_state)
            {
                return comm::protocol_result<logvole_seeded_eval_output>::failure(
                    comm::protocol_errc::invalid_state_transition, "Missing next_level_state in sender_online");
            }

            auto child_eval = evaluate_logvole_sender_seed_candidate(*state.next_level_state, backend, seed);
            if (!child_eval)
            {
                return child_eval;
            }
            if (!child_eval.value().valid)
            {
                return comm::protocol_result<logvole_seeded_eval_output>::success(logvole_seeded_eval_output{});
            }

            const std::uint32_t w_prime = (w + alpha - 1u) / alpha;
            const std::uint32_t mu_hi = compute_logvole_mu_hi(state.params);
            const std::uint32_t w_double_prime = compute_logvole_w_double_prime(state.params);

            auto k_prime_hat_res =
                backend.denoise_tbm(child_eval.value().tbk, w_prime, tau_hi, state.params.shrinkexpand.ring);
            if (!k_prime_hat_res)
            {
                return comm::protocol_result<logvole_seeded_eval_output>::failure(
                    k_prime_hat_res.error(), k_prime_hat_res.message());
            }

            auto k_prime_res =
                backend.agg(k_prime_hat_res.value(), w_double_prime, tau_hi, state.params.shrinkexpand.ring);
            if (!k_prime_res)
            {
                return comm::protocol_result<logvole_seeded_eval_output>::failure(
                    k_prime_res.error(), k_prime_res.message());
            }

            const auto &k_prime = k_prime_res.value();
            const std::uint64_t instance_base = count_logvole_seed_instances(*state.next_level_state);
            const std::uint32_t worker_threads = state.shrinkexpand_state.params.num_worker_threads;

            std::vector<ring_rns_poly> final_tbk(static_cast<std::size_t>(w));
            std::vector<ring_rns_poly> sampled_tbk(
                static_cast<std::size_t>(w_double_prime) * static_cast<std::size_t>(mu_hi));
            auto expand_status = detail::run_parallel_tasks(
                w_double_prime, worker_threads, [&](std::size_t chunk_idx) -> comm::protocol_result<void> {
                    shrinkexpand_expand_sender_input se_exp_in{};
                    se_exp_in.nonce = derive_seed_instance_nonce(
                        state.params.shrinkexpand.sampling_seeds, seed, instance_base + chunk_idx);
                    se_exp_in.tbk_prime = k_prime[chunk_idx];

                    auto se_exp_out = shrinkexpand_expand_sender(
                        state.shrinkexpand_state, se_exp_in, backend.get_shrinkexpand_backend());
                    if (!se_exp_out)
                    {
                        return comm::protocol_result<void>::failure(se_exp_out.error(), se_exp_out.message());
                    }

                    const std::size_t sampled_start = chunk_idx * static_cast<std::size_t>(mu_hi);
                    auto se_exp_value = std::move(se_exp_out.value());
                    for (std::size_t item_idx = 0; item_idx < se_exp_value.tbk.size(); ++item_idx)
                    {
                        sampled_tbk[sampled_start + item_idx] = se_exp_value.tbk[item_idx];
                    }

                    const std::size_t start = chunk_idx * static_cast<std::size_t>(mu_hi);
                    const std::size_t end =
                        std::min(start + static_cast<std::size_t>(mu_hi), static_cast<std::size_t>(w));
                    const std::size_t items_to_add = end - start;
                    for (std::size_t item_idx = 0; item_idx < items_to_add; ++item_idx)
                    {
                        final_tbk[start + item_idx] = std::move(se_exp_value.tbk[item_idx]);
                    }
                    return comm::protocol_result<void>::success();
                });
            if (!expand_status)
            {
                return comm::protocol_result<logvole_seeded_eval_output>::failure(
                    expand_status.error(), expand_status.message());
            }

            const auto seed_params = make_seed_params(state.params, state.shrinkexpand_state.params);
            auto candidate_ok = backend.validate_golden_seed_candidate(seed_params, sampled_tbk);
            if (!candidate_ok)
            {
                return comm::protocol_result<logvole_seeded_eval_output>::failure(
                    candidate_ok.error(), candidate_ok.message());
            }
            if (!candidate_ok.value())
            {
                return comm::protocol_result<logvole_seeded_eval_output>::success(logvole_seeded_eval_output{});
            }

            logvole_seeded_eval_output output{};
            output.valid = true;
            output.tbk = std::move(final_tbk);
            return comm::protocol_result<logvole_seeded_eval_output>::success(std::move(output));
        }

        comm::protocol_result<logvole_seeded_eval_output> find_logvole_root_seed_and_evaluate(
            const logvole_sender_state &state, const logvole_backend &backend)
        {
            auto_timer total_sampling_timer(global_timing_stats.seed_sampling_time_us);
            auto_timer gold_sampling_timer(global_timing_stats.gold_sampling_time_us);

            constexpr int k_max_seed_attempts = 100;
            std::vector<std::uint8_t> seed(16u, 0u);
            const std::uint64_t sk1_head =
                (!state.sk1.empty() && !state.sk1[0].coeffs.empty()) ? state.sk1[0].coeffs[0] : 0u;
            const std::uint64_t seed_material = derive_deterministic_seed_material(
                state.params.shrinkexpand.sampling_seeds.ct2_root, 0x54524E4353454544ull,
                count_logvole_seed_instances(state), state.params.w, compute_logvole_mu_hi(state.params),
                sk1_head);

            std::mt19937_64 gen(seed_material);
            std::uniform_int_distribution<std::uint8_t> dist_bytes(0u, 255u);
            for (int attempt = 0; attempt < k_max_seed_attempts; ++attempt)
            {
                const auto attempt_start = std::chrono::steady_clock::now();
                for (auto &byte : seed)
                {
                    byte = dist_bytes(gen);
                }

                auto eval = evaluate_logvole_sender_seed_candidate(state, backend, seed);
                const auto attempt_elapsed_us =
                    static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
                                                   std::chrono::steady_clock::now() - attempt_start)
                                                   .count());
                global_timing_stats.seed_attempt_time_us.fetch_add(attempt_elapsed_us, std::memory_order_relaxed);
                global_timing_stats.seed_attempt_count.fetch_add(1u, std::memory_order_relaxed);
                if (!eval)
                {
                    return eval;
                }
                if (!eval.value().valid)
                {
                    continue;
                }

                state.golden_seed = seed;
                return eval;
            }

            return comm::protocol_result<logvole_seeded_eval_output>::failure(
                comm::protocol_errc::flow_violation, "Failed to find recursive golden seed within 100 attempts.");
        }

        comm::protocol_result<logvole_sender_precompute_output> ensure_logvole_sender_precompute(
            const logvole_sender_state &state, const logvole_backend &backend)
        {
            if (state.precomputed_tbk)
            {
                logvole_sender_precompute_output output{};
                output.golden_seed = state.golden_seed;
                output.root_k_prime_rt = state.root_k_prime_rt;
                output.root_k_rt = state.root_k_rt;
                output.tbk = state.precomputed_tbk;
                return comm::protocol_result<logvole_sender_precompute_output>::success(std::move(output));
            }

            comm::protocol_result<logvole_seeded_eval_output> eval_result =
                state.golden_seed.empty()
                    ? find_logvole_root_seed_and_evaluate(state, backend)
                    : evaluate_logvole_sender_seed_candidate(state, backend, state.golden_seed);
            if (!eval_result)
            {
                return comm::protocol_result<logvole_sender_precompute_output>::failure(
                    eval_result.error(), eval_result.message());
            }
            if (!eval_result.value().valid)
            {
                return comm::protocol_result<logvole_sender_precompute_output>::failure(
                    comm::protocol_errc::flow_violation, "recursive logvole seed candidate unexpectedly invalid");
            }

            state.precomputed_tbk = std::make_shared<std::vector<ring_rns_poly>>(std::move(eval_result.value().tbk));

            logvole_sender_precompute_output output{};
            output.golden_seed = state.golden_seed;
            output.root_k_prime_rt = state.root_k_prime_rt;
            output.root_k_rt = state.root_k_rt;
            output.tbk = state.precomputed_tbk;
            return comm::protocol_result<logvole_sender_precompute_output>::success(std::move(output));
        }

        comm::protocol_result<logvole_root_response_msg> prepare_logvole_root_response_sender(
            const logvole_sender_state &state, const logvole_backend &backend,
            const logvole_root_digest_msg &request, const logvole_sender_precompute_future *precompute_future)
        {
            auto tau_hi_res = compute_tau_hi(state.params.shrinkexpand.tau);
            if (!tau_hi_res)
            {
                return comm::protocol_result<logvole_root_response_msg>::failure(
                    tau_hi_res.error(), tau_hi_res.message());
            }

            if (precompute_future != nullptr)
            {
                const auto wait_start = std::chrono::steady_clock::now();
                auto precompute_result = precompute_future->get();
                const auto wait_end = std::chrono::steady_clock::now();
                global_timing_stats.sender_async_wait_time_us.fetch_add(
                    static_cast<std::uint64_t>(
                        std::chrono::duration_cast<std::chrono::microseconds>(wait_end - wait_start).count()),
                    std::memory_order_relaxed);
                if (!precompute_result)
                {
                    return comm::protocol_result<logvole_root_response_msg>::failure(
                        precompute_result.error(), precompute_result.message());
                }
            }
            else
            {
                auto precompute_result = ensure_logvole_sender_precompute(state, backend);
                if (!precompute_result)
                {
                    return comm::protocol_result<logvole_root_response_msg>::failure(
                        precompute_result.error(), precompute_result.message());
                }
            }

            if (!state.root_k_prime_rt || state.golden_seed.empty())
            {
                return comm::protocol_result<logvole_root_response_msg>::failure(
                    comm::protocol_errc::invalid_state_transition, "root sender precompute did not cache k'_rt");
            }

            auto ctx_result = make_ring_ntt_context(state.params.shrinkexpand.ring);
            if (!ctx_result)
            {
                return comm::protocol_result<logvole_root_response_msg>::failure(
                    ctx_result.error(), ctx_result.message());
            }
            const std::uint32_t coeff_mod_count =
                static_cast<std::uint32_t>(state.params.shrinkexpand.ring.coeff_modulus_bits.size());
            auto d_prime_batch = unpack_ring_batch(
                1u, state.params.shrinkexpand.ring.poly_modulus_degree, coeff_mod_count, request.d_prime_coeffs,
                "root d'_rt", state.shrinkexpand_state.params.num_worker_threads);
            if (!d_prime_batch)
            {
                return comm::protocol_result<logvole_root_response_msg>::failure(
                    d_prime_batch.error(), d_prime_batch.message());
            }

            auto sk_prime = derive_skx_trunc(
                ctx_result.value(), state.root_sk_r_rt, d_prime_batch.value()[0], *state.root_k_prime_rt,
                state.params.shrinkexpand.gadget_log_base, tau_hi_res.value());
            if (!sk_prime)
            {
                return comm::protocol_result<logvole_root_response_msg>::failure(
                    sk_prime.error(), sk_prime.message());
            }

            logvole_root_response_msg response{};
            response.seed = state.golden_seed;
            response.sk_prime_coeffs = pack_ring_batch(std::vector<ring_rns_poly>{ std::move(sk_prime.value()) });
            return comm::protocol_result<logvole_root_response_msg>::success(std::move(response));
        }

        struct logvole_rand_root_digest_output
        {
            ring_rns_poly d_rt{};
            ring_rns_poly y_left{};
            ring_rns_poly d_prime{};
            std::vector<ring_rns_poly> hat_d_rt{};
            std::vector<ring_rns_poly> zeta{};
            std::shared_ptr<digest_tree> root_tree{};
        };

        comm::protocol_result<logvole_rand_root_digest_output> compute_logvole_rand_root_digest_receiver(
            const logvole_receiver_state &state, const logvole_receiver_online_input &input,
            const logvole_backend &backend)
        {
            auto tau_hi_res = compute_tau_hi(state.params.shrinkexpand.tau);
            if (!tau_hi_res)
            {
                return comm::protocol_result<logvole_rand_root_digest_output>::failure(
                    tau_hi_res.error(), tau_hi_res.message());
            }

            const std::uint32_t tau_hi = tau_hi_res.value();
            const std::uint32_t tau_full = tau_hi + 1u;
            const std::uint32_t mu_hi = compute_logvole_mu_hi(state.params);
            if (state.params.w != mu_hi || input.x.size() > mu_hi)
            {
                return comm::protocol_result<logvole_rand_root_digest_output>::failure(
                    comm::protocol_errc::config_error, "root digest input must fit exactly one mu_hi block");
            }

            std::vector<ring_rns_poly> x_root = input.x;
            while (x_root.size() < static_cast<std::size_t>(mu_hi))
            {
                x_root.push_back(make_zero_poly(state.params.shrinkexpand.ring));
            }

            auto shrink_res = shrinkexpand_shrink(state.shrinkexpand_state, x_root, backend.get_shrinkexpand_backend());
            if (!shrink_res)
            {
                return comm::protocol_result<logvole_rand_root_digest_output>::failure(
                    shrink_res.error(), shrink_res.message());
            }

            auto ctx_result = make_ring_ntt_context(state.params.shrinkexpand.ring);
            if (!ctx_result)
            {
                return comm::protocol_result<logvole_rand_root_digest_output>::failure(
                    ctx_result.error(), ctx_result.message());
            }
            const auto &ctx = ctx_result.value();

            auto hat_d = gdecomp_hi_and_unbundle(
                backend, shrink_res.value().digest, state.params.shrinkexpand.gadget_log_base, tau_hi,
                state.params.shrinkexpand.ring);
            if (!hat_d)
            {
                return comm::protocol_result<logvole_rand_root_digest_output>::failure(
                    hat_d.error(), hat_d.message());
            }

            const std::uint32_t left_width = static_cast<std::uint32_t>(hat_d.value().size());
            auto y_left = lenc_digest_trunc(
                ctx, hat_d.value(), tau_hi, state.params.shrinkexpand.gadget_log_base,
                state.params.shrinkexpand.plaintext_modulus_bits, state.root_lacct_left.width_padded, true);
            if (!y_left)
            {
                return comm::protocol_result<logvole_rand_root_digest_output>::failure(
                    y_left.error(), y_left.message());
            }

            auto y_decomp = gadget_decompose_bits_range_centered(
                y_left.value(), state.params.shrinkexpand.gadget_log_base, 1u, tau_hi, ctx,
                state.shrinkexpand_state.params.num_worker_threads);
            if (!y_decomp)
            {
                return comm::protocol_result<logvole_rand_root_digest_output>::failure(
                    y_decomp.error(), y_decomp.message());
            }

            const auto public_b_full_ntt = build_lenc_public_b_ntt(ctx, tau_full);
            std::vector<ring_rns_poly> public_b_root_ntt;
            public_b_root_ntt.reserve(tau_hi);
            for (std::uint32_t idx = 0u; idx < tau_hi; ++idx)
            {
                public_b_root_ntt.push_back(public_b_full_ntt[1u + idx]);
            }

            auto left_term = root_inner_product_ntt(
                ctx, public_b_root_ntt, y_decomp.value(), state.shrinkexpand_state.params.num_worker_threads);
            if (!left_term)
            {
                return comm::protocol_result<logvole_rand_root_digest_output>::failure(
                    left_term.error(), left_term.message());
            }

            auto zeta = sample_root_zeta(ctx, state.root_randomizer_width, state.params.shrinkexpand.gadget_log_base);
            if (!zeta)
            {
                return comm::protocol_result<logvole_rand_root_digest_output>::failure(zeta.error(), zeta.message());
            }
            auto right_term = root_inner_product_ntt(
                ctx, state.root_public_b_star_ntt, zeta.value(), state.shrinkexpand_state.params.num_worker_threads);
            if (!right_term)
            {
                return comm::protocol_result<logvole_rand_root_digest_output>::failure(
                    right_term.error(), right_term.message());
            }

            auto d_prime = ring_add(left_term.value(), right_term.value(), ctx);
            if (!d_prime)
            {
                return comm::protocol_result<logvole_rand_root_digest_output>::failure(
                    d_prime.error(), d_prime.message());
            }
            // Match the sign convention used by local LEnc digest/eval. This is
            // -d'_rt relative to rootdigest.tex, paired with the negated top
            // wrapper rows above.
            ring_rns_poly zero = make_zero_poly(state.params.shrinkexpand.ring);
            auto neg_d_prime = ring_sub(zero, d_prime.value(), ctx);
            if (!neg_d_prime)
            {
                return comm::protocol_result<logvole_rand_root_digest_output>::failure(
                    neg_d_prime.error(), neg_d_prime.message());
            }

            logvole_rand_root_digest_output out{};
            out.d_rt = std::move(shrink_res.value().digest);
            out.root_tree = std::move(shrink_res.value().tree);
            out.hat_d_rt = std::move(hat_d.value());
            out.y_left = std::move(y_left.value());
            out.zeta = std::move(zeta.value());
            out.d_prime = std::move(neg_d_prime.value());
            if (left_width != root_left_width(tau_hi, static_cast<std::uint32_t>(ctx.moduli.size())))
            {
                return comm::protocol_result<logvole_rand_root_digest_output>::failure(
                    comm::protocol_errc::flow_violation, "root digest lifted width mismatch");
            }
            return comm::protocol_result<logvole_rand_root_digest_output>::success(std::move(out));
        }

        comm::protocol_result<std::vector<ring_rns_poly>> eval_logvole_root_top_ct_ntt(
            const logvole_receiver_state &state, const ring_ntt_context &ctx, const ring_rns_poly &y_left,
            const std::vector<ring_rns_poly> &zeta)
        {
            auto tau_hi_res = compute_tau_hi(state.params.shrinkexpand.tau);
            if (!tau_hi_res)
            {
                return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                    tau_hi_res.error(), tau_hi_res.message());
            }
            const std::uint32_t tau_hi = tau_hi_res.value();
            if (state.root_top_ct.rows == 0u || state.root_top_ct.cols != tau_hi + state.root_randomizer_width ||
                zeta.size() != state.root_randomizer_width)
            {
                return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                    comm::protocol_errc::invalid_state_transition, "root top wrapper state shape mismatch");
            }

            auto y_decomp = gadget_decompose_bits_range_centered(
                y_left, state.params.shrinkexpand.gadget_log_base, 1u, tau_hi, ctx,
                state.shrinkexpand_state.params.num_worker_threads);
            if (!y_decomp)
            {
                return comm::protocol_result<std::vector<ring_rns_poly>>::failure(y_decomp.error(), y_decomp.message());
            }

            std::vector<ring_rns_poly> inputs = std::move(y_decomp.value());
            inputs.insert(inputs.end(), zeta.begin(), zeta.end());
            auto ntt_status = detail::run_parallel_tasks(
                inputs.size(), state.shrinkexpand_state.params.num_worker_threads,
                [&](std::size_t idx) { return forward_ntt_inplace(inputs[idx], ctx); });
            if (!ntt_status)
            {
                return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                    ntt_status.error(), ntt_status.message());
            }

            std::vector<ring_rns_poly> out(state.root_top_ct.rows);
            auto eval_status = detail::run_parallel_tasks(
                static_cast<std::size_t>(state.root_top_ct.rows), state.shrinkexpand_state.params.num_worker_threads,
                [&](std::size_t row_idx) -> comm::protocol_result<void> {
                    const std::uint32_t row = static_cast<std::uint32_t>(row_idx);
                    ring_rns_poly acc_ntt{};
                    acc_ntt.coeffs.assign(ring_poly_coeff_count(ctx.params), 0u);
                    for (std::uint32_t col = 0u; col < state.root_top_ct.cols; ++col)
                    {
                        const auto &ct_poly = state.root_top_ct.polys[ring_tensor_index(state.root_top_ct, row, col)];
                        auto mul_ok = dyadic_multiply_add_ntt_inplace(ct_poly, inputs[col], acc_ntt, ctx);
                        if (!mul_ok)
                        {
                            return comm::protocol_result<void>::failure(mul_ok.error(), mul_ok.message());
                        }
                    }
                    out[row] = std::move(acc_ntt);
                    return comm::protocol_result<void>::success();
                });
            if (!eval_status)
            {
                return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                    eval_status.error(), eval_status.message());
            }
            return comm::protocol_result<std::vector<ring_rns_poly>>::success(std::move(out));
        }

        comm::protocol_result<ring_rns_poly> derand_logvole_root_receiver(
            const logvole_receiver_state &state, const logvole_backend &backend,
            const logvole_rand_root_digest_output &root_digest, const logvole_root_response_msg &response)
        {
            auto tau_hi_res = compute_tau_hi(state.params.shrinkexpand.tau);
            if (!tau_hi_res)
            {
                return comm::protocol_result<ring_rns_poly>::failure(tau_hi_res.error(), tau_hi_res.message());
            }
            const std::uint32_t tau_hi = tau_hi_res.value();
            const std::uint32_t rho =
                static_cast<std::uint32_t>(state.params.shrinkexpand.ring.coeff_modulus_bits.size());
            const std::uint32_t left_width = root_left_width(tau_hi, rho);
            auto ctx_result = make_ring_ntt_context(state.params.shrinkexpand.ring);
            if (!ctx_result)
            {
                return comm::protocol_result<ring_rns_poly>::failure(ctx_result.error(), ctx_result.message());
            }
            const auto &ctx = ctx_result.value();

            auto sk_prime_batch = unpack_ring_batch(
                1u, state.params.shrinkexpand.ring.poly_modulus_degree, rho, response.sk_prime_coeffs, "root sk'_rt",
                state.shrinkexpand_state.params.num_worker_threads);
            if (!sk_prime_batch)
            {
                return comm::protocol_result<ring_rns_poly>::failure(sk_prime_batch.error(), sk_prime_batch.message());
            }

            if (root_digest.hat_d_rt.size() != left_width)
            {
                return comm::protocol_result<ring_rns_poly>::failure(
                    comm::protocol_errc::invalid_state_transition, "root digest lifted width mismatch");
            }

            auto ct_r_applied = lhe_apply_ct1_trunc(
                ctx, state.root_ct_r_rt, root_digest.d_prime, state.params.shrinkexpand.gadget_log_base, tau_hi, true,
                state.shrinkexpand_state.params.num_worker_threads);
            if (!ct_r_applied)
            {
                return comm::protocol_result<ring_rns_poly>::failure(ct_r_applied.error(), ct_r_applied.message());
            }

            auto dec_partial_ntt = lhe_dec(
                ctx, ct_r_applied.value(), sk_prime_batch.value()[0], nullptr, true, true,
                state.shrinkexpand_state.params.num_worker_threads);
            if (!dec_partial_ntt)
            {
                return comm::protocol_result<ring_rns_poly>::failure(
                    dec_partial_ntt.error(), dec_partial_ntt.message());
            }

            auto top_eval_ntt = eval_logvole_root_top_ct_ntt(state, ctx, root_digest.y_left, root_digest.zeta);
            if (!top_eval_ntt)
            {
                return comm::protocol_result<ring_rns_poly>::failure(top_eval_ntt.error(), top_eval_ntt.message());
            }

            auto left_eval_ntt = lenc_eval_trunc(
                ctx, to_lenc_lacct(state.root_lacct_left), root_digest.hat_d_rt, left_width, tau_hi,
                state.params.shrinkexpand.gadget_log_base, state.params.shrinkexpand.plaintext_modulus_bits, true,
                state.shrinkexpand_state.params.num_worker_threads, true);
            if (!left_eval_ntt)
            {
                return comm::protocol_result<ring_rns_poly>::failure(left_eval_ntt.error(), left_eval_ntt.message());
            }

            if (dec_partial_ntt.value().size() != left_width || top_eval_ntt.value().size() != left_width ||
                left_eval_ntt.value().size() != left_width)
            {
                return comm::protocol_result<ring_rns_poly>::failure(
                    comm::protocol_errc::flow_violation, "root derandomization vector width mismatch");
            }

            auto ct_k = build_hashed_ct2(
                ctx, left_width, state.params.shrinkexpand.sampling_seeds,
                derive_root_derand_nonce(state.params.shrinkexpand.sampling_seeds, response.seed));
            if (!ct_k)
            {
                return comm::protocol_result<ring_rns_poly>::failure(ct_k.error(), ct_k.message());
            }

            std::vector<ring_rns_poly> tbm_vec(left_width);
            for (std::uint32_t row = 0u; row < left_width; ++row)
            {
                ring_rns_poly phi_ntt = std::move(top_eval_ntt.value()[row]);
                auto phi_add = ring_add_inplace(phi_ntt, left_eval_ntt.value()[row], ctx);
                if (!phi_add)
                {
                    return comm::protocol_result<ring_rns_poly>::failure(phi_add.error(), phi_add.message());
                }

                ring_rns_poly tbm_ntt = std::move(dec_partial_ntt.value()[row]);
                auto sub_ok = ring_sub_inplace(tbm_ntt, phi_ntt, ctx);
                if (!sub_ok)
                {
                    return comm::protocol_result<ring_rns_poly>::failure(sub_ok.error(), sub_ok.message());
                }
                auto intt_ok = inverse_ntt_inplace(tbm_ntt, ctx);
                if (!intt_ok)
                {
                    return comm::protocol_result<ring_rns_poly>::failure(intt_ok.error(), intt_ok.message());
                }
                auto add_ct = ring_add_inplace(tbm_ntt, ct_k.value()[row], ctx);
                if (!add_ct)
                {
                    return comm::protocol_result<ring_rns_poly>::failure(add_ct.error(), add_ct.message());
                }
                tbm_vec[row] = std::move(tbm_ntt);
            }

            state.golden_seed = response.seed;
            auto denoised = backend.denoise_tbm(tbm_vec, 1u, tau_hi, state.params.shrinkexpand.ring);
            if (!denoised)
            {
                return comm::protocol_result<ring_rns_poly>::failure(denoised.error(), denoised.message());
            }
            auto aggregated = backend.agg(denoised.value(), 1u, tau_hi, state.params.shrinkexpand.ring);
            if (!aggregated)
            {
                return comm::protocol_result<ring_rns_poly>::failure(aggregated.error(), aggregated.message());
            }
            if (aggregated.value().size() != 1u)
            {
                return comm::protocol_result<ring_rns_poly>::failure(
                    comm::protocol_errc::flow_violation, "root receiver key aggregation produced wrong width");
            }
            return comm::protocol_result<ring_rns_poly>::success(std::move(aggregated.value()[0]));
        }

        comm::protocol_result<comm::comm_counters> run_logvole_sender_online_service(
            comm::channel_interface *channel, std::uint64_t session_id, const logvole_sender_state &state,
            const logvole_backend &backend, const logvole_sender_precompute_future *precompute_future)
        {
            auto tau_hi_res = compute_tau_hi(state.params.shrinkexpand.tau);
            if (!tau_hi_res)
            {
                return comm::protocol_result<comm::comm_counters>::failure(tau_hi_res.error(), tau_hi_res.message());
            }

            const auto mode = eval_logvole_mode(
                state.params.w, state.params.shrinkexpand.alpha, tau_hi_res.value(),
                static_cast<std::uint32_t>(state.params.shrinkexpand.ring.coeff_modulus_bits.size()));

            if (mode == logvole_mode::root)
            {
                auto root_wrap_ptr = std::make_unique<comm::subchannel_wrapper>(channel, session_id + 50);
                comm::any_channel root_channel(std::move(root_wrap_ptr));
                comm::protocol_engine<logvole_root_online_spec, comm::role_t::sender> engine(
                    std::move(root_channel));
                std::optional<logvole_root_response_msg> response{};
                auto run_result = engine.run_with(
                    comm::on_recv<0>([&](const logvole_root_digest_msg &request) -> comm::protocol_result<void> {
                        auto prepared =
                            prepare_logvole_root_response_sender(state, backend, request, precompute_future);
                        if (!prepared)
                        {
                            return comm::protocol_result<void>::failure(prepared.error(), prepared.message());
                        }
                        response = std::move(prepared.value());
                        return comm::protocol_result<void>::success();
                    }),
                    comm::on_send<1>([&]() -> comm::protocol_result<logvole_root_response_msg> {
                        if (!response)
                        {
                            return comm::protocol_result<logvole_root_response_msg>::failure(
                                comm::protocol_errc::invalid_state_transition, "root response not prepared");
                        }
                        return comm::protocol_result<logvole_root_response_msg>::success(*response);
                    }));
                if (!run_result)
                {
                    return comm::protocol_result<comm::comm_counters>::failure(
                        run_result.error(), run_result.message());
                }
                return comm::protocol_result<comm::comm_counters>::success(engine.counters());
            }

            if (!state.next_level_state)
            {
                return comm::protocol_result<comm::comm_counters>::failure(
                    comm::protocol_errc::invalid_state_transition, "Missing next_level_state in sender_online");
            }

            auto si_wrap_ptr = std::make_unique<comm::subchannel_wrapper>(channel, session_id + 2);
            auto child_result = run_logvole_sender_online_service(
                si_wrap_ptr.get(), si_wrap_ptr->config().session_id, *state.next_level_state, backend,
                precompute_future);
            if (!child_result)
            {
                return child_result;
            }

            comm::comm_counters counters{};
            accumulate_counters(counters, child_result.value());
            return comm::protocol_result<comm::comm_counters>::success(std::move(counters));
        }

        comm::protocol_result<logvole_receiver_online_output> run_logvole_receiver_online_impl(
            comm::channel_interface *channel, std::uint64_t session_id, const logvole_receiver_state &state,
            const logvole_receiver_online_input &input, const logvole_backend &backend)
        {
            logvole_receiver_online_output output{};

            auto tau_hi_res = compute_tau_hi(state.params.shrinkexpand.tau);
            if (!tau_hi_res)
            {
                return comm::protocol_result<logvole_receiver_online_output>::failure(
                    tau_hi_res.error(), tau_hi_res.message());
            }

            const std::uint32_t tau_hi = tau_hi_res.value();
            const std::uint32_t w = state.params.w;
            const std::uint32_t alpha = state.params.shrinkexpand.alpha;
            const std::uint32_t rho =
                static_cast<std::uint32_t>(state.params.shrinkexpand.ring.coeff_modulus_bits.size());
            const std::uint32_t mu_hi = compute_logvole_mu_hi(state.params);
            const auto mode = eval_logvole_mode(w, alpha, tau_hi, rho);

            if (mode == logvole_mode::root)
            {
                auto root_digest = compute_logvole_rand_root_digest_receiver(state, input, backend);
                if (!root_digest)
                {
                    return comm::protocol_result<logvole_receiver_online_output>::failure(
                        root_digest.error(), root_digest.message());
                }

                logvole_root_response_msg response{};
                auto root_wrap_ptr = std::make_unique<comm::subchannel_wrapper>(channel, session_id + 50);
                comm::any_channel root_channel(std::move(root_wrap_ptr));
                comm::protocol_engine<logvole_root_online_spec, comm::role_t::receiver> engine(
                    std::move(root_channel));
                auto run_result = engine.run_with(
                    comm::on_send<0>([&]() -> comm::protocol_result<logvole_root_digest_msg> {
                        logvole_root_digest_msg message{};
                        message.d_prime_coeffs =
                            pack_ring_batch(std::vector<ring_rns_poly>{ root_digest.value().d_prime });
                        return comm::protocol_result<logvole_root_digest_msg>::success(std::move(message));
                    }),
                    comm::on_recv<1>([&](const logvole_root_response_msg &message) -> comm::protocol_result<void> {
                        response = message;
                        return comm::protocol_result<void>::success();
                    }));
                if (!run_result)
                {
                    return comm::protocol_result<logvole_receiver_online_output>::failure(
                        run_result.error(), run_result.message());
                }
                accumulate_counters(output.counters, engine.counters());

                auto sk_rt = derand_logvole_root_receiver(state, backend, root_digest.value(), response);
                if (!sk_rt)
                {
                    return comm::protocol_result<logvole_receiver_online_output>::failure(
                        sk_rt.error(), sk_rt.message());
                }

                shrinkexpand_expand_receiver_input se_exp_in{};
                se_exp_in.nonce =
                    derive_seed_instance_nonce(state.params.shrinkexpand.sampling_seeds, response.seed, 0u);
                se_exp_in.tree = root_digest.value().root_tree;
                se_exp_in.digest = root_digest.value().d_rt;
                se_exp_in.sk_x = std::move(sk_rt.value());

                auto se_exp_out = shrinkexpand_expand_receiver(
                    state.shrinkexpand_state, se_exp_in, backend.get_shrinkexpand_backend());
                if (!se_exp_out)
                {
                    return comm::protocol_result<logvole_receiver_online_output>::failure(
                        se_exp_out.error(), se_exp_out.message());
                }

                output.tbm = std::move(se_exp_out.value().tbm);
                if (output.tbm.size() > input.x.size())
                {
                    output.tbm.resize(input.x.size());
                }
                return comm::protocol_result<logvole_receiver_online_output>::success(std::move(output));
            }

            const std::uint32_t w_prime = (w + alpha - 1u) / alpha;
            const std::uint32_t w_double_prime = compute_logvole_w_double_prime(state.params);
            const std::size_t w_next = static_cast<std::size_t>(w_double_prime) * tau_hi * rho;
            const std::uint32_t worker_threads = state.shrinkexpand_state.params.num_worker_threads;

            std::vector<logvole_shrink_chunk_result> shrink_chunks(w_double_prime);
            auto shrink_status = detail::run_parallel_tasks(
                w_double_prime, worker_threads, [&](std::size_t chunk_idx) -> comm::protocol_result<void> {
                    const std::size_t start = chunk_idx * static_cast<std::size_t>(mu_hi);
                    const std::size_t end = std::min(start + static_cast<std::size_t>(mu_hi), input.x.size());

                    std::vector<ring_rns_poly> x_chunk(input.x.begin() + start, input.x.begin() + end);
                    while (x_chunk.size() < static_cast<std::size_t>(mu_hi))
                    {
                        x_chunk.push_back(make_zero_poly(state.params.shrinkexpand.ring));
                    }

                    auto shrink_res =
                        shrinkexpand_shrink(state.shrinkexpand_state, x_chunk, backend.get_shrinkexpand_backend());
                    if (!shrink_res)
                    {
                        return comm::protocol_result<void>::failure(shrink_res.error(), shrink_res.message());
                    }

                    auto shrink_value = std::move(shrink_res.value());
                    auto digest_decomp = gdecomp_hi_and_unbundle(
                        backend, shrink_value.digest, state.params.shrinkexpand.gadget_log_base, tau_hi,
                        state.params.shrinkexpand.ring);
                    if (!digest_decomp)
                    {
                        return comm::protocol_result<void>::failure(digest_decomp.error(), digest_decomp.message());
                    }
                    const std::size_t expected_unbundled =
                        static_cast<std::size_t>(tau_hi) * static_cast<std::size_t>(rho);
                    if (digest_decomp.value().size() != expected_unbundled)
                    {
                        return comm::protocol_result<void>::failure(
                            comm::protocol_errc::flow_violation,
                            "logvole expected tau_hi*rho unbundled gadget outputs");
                    }

                    auto &chunk_result = shrink_chunks[chunk_idx];
                    chunk_result.digest = std::move(shrink_value.digest);
                    chunk_result.tree = std::move(shrink_value.tree);
                    chunk_result.digest_decomp = std::move(digest_decomp.value());
                    return comm::protocol_result<void>::success();
                });
            if (!shrink_status)
            {
                return comm::protocol_result<logvole_receiver_online_output>::failure(
                    shrink_status.error(), shrink_status.message());
            }

            std::vector<ring_rns_poly> d_hat;
            d_hat.reserve(w_next);
            std::vector<ring_rns_poly> digests;
            digests.reserve(w_double_prime);
            std::vector<std::shared_ptr<digest_tree>> stored_trees;
            stored_trees.reserve(w_double_prime);

            for (std::uint32_t i = 0; i < w_double_prime; ++i)
            {
                auto &chunk_result = shrink_chunks[i];
                digests.push_back(std::move(chunk_result.digest));
                stored_trees.push_back(std::move(chunk_result.tree));

                for (auto &poly : chunk_result.digest_decomp)
                {
                    if (d_hat.size() < w_next)
                    {
                        d_hat.push_back(std::move(poly));
                    }
                }
            }

            logvole_receiver_online_input rec_in{};
            rec_in.x = std::move(d_hat);

            if (!state.next_level_state)
            {
                return comm::protocol_result<logvole_receiver_online_output>::failure(
                    comm::protocol_errc::invalid_state_transition, "Missing next_level_state in receiver_online");
            }

            auto si_demux_anchor = std::make_unique<comm::subchannel_wrapper>(channel, session_id + 2);
            auto si_wrap_ptr = std::make_unique<comm::subchannel_wrapper>(channel, session_id + 2);
            auto si_out = run_logvole_receiver_online_impl(
                si_wrap_ptr.get(), si_wrap_ptr->config().session_id, *state.next_level_state, rec_in, backend);
            if (!si_out)
            {
                return comm::protocol_result<logvole_receiver_online_output>::failure(
                    si_out.error(), si_out.message());
            }

            accumulate_counters(output.counters, si_out.value().counters);

            auto sk_x_hat_res =
                backend.denoise_tbm(si_out.value().tbm, w_prime, tau_hi, state.params.shrinkexpand.ring);
            if (!sk_x_hat_res)
            {
                return comm::protocol_result<logvole_receiver_online_output>::failure(
                    sk_x_hat_res.error(), sk_x_hat_res.message());
            }

            auto sk_x_res = backend.agg(sk_x_hat_res.value(), w_double_prime, tau_hi, state.params.shrinkexpand.ring);
            if (!sk_x_res)
            {
                return comm::protocol_result<logvole_receiver_online_output>::failure(
                    sk_x_res.error(), sk_x_res.message());
            }
            const auto &sk_x = sk_x_res.value();

            auto resolved_seed = resolve_cached_logvole_receiver_seed(state);
            if (!resolved_seed)
            {
                return comm::protocol_result<logvole_receiver_online_output>::failure(
                    resolved_seed.error(), resolved_seed.message());
            }
            const std::vector<std::uint8_t> active_seed = std::move(resolved_seed.value());
            const std::uint64_t instance_base = count_logvole_seed_instances(*state.next_level_state);

            std::vector<ring_rns_poly> final_tbm(static_cast<std::size_t>(w));
            auto expand_status = detail::run_parallel_tasks(
                w_double_prime, worker_threads, [&](std::size_t chunk_idx) -> comm::protocol_result<void> {
                    shrinkexpand_expand_receiver_input se_exp_in{};
                    se_exp_in.nonce = derive_seed_instance_nonce(
                        state.params.shrinkexpand.sampling_seeds, active_seed, instance_base + chunk_idx);

                    const std::size_t start = chunk_idx * static_cast<std::size_t>(mu_hi);
                    const std::size_t end = std::min(start + static_cast<std::size_t>(mu_hi), input.x.size());
                    se_exp_in.tree = stored_trees[chunk_idx];
                    if (!se_exp_in.tree)
                    {
                        se_exp_in.x = std::vector<ring_rns_poly>(input.x.begin() + start, input.x.begin() + end);
                        while (se_exp_in.x.size() < static_cast<std::size_t>(mu_hi))
                        {
                            se_exp_in.x.push_back(make_zero_poly(state.params.shrinkexpand.ring));
                        }
                    }

                    se_exp_in.digest = digests[chunk_idx];
                    se_exp_in.sk_x = sk_x[chunk_idx];

                    auto se_exp_out = shrinkexpand_expand_receiver(
                        state.shrinkexpand_state, se_exp_in, backend.get_shrinkexpand_backend());
                    if (!se_exp_out)
                    {
                        return comm::protocol_result<void>::failure(se_exp_out.error(), se_exp_out.message());
                    }

                    const std::size_t items_to_add = end - start;
                    auto se_exp_value = std::move(se_exp_out.value());
                    for (std::size_t item_idx = 0; item_idx < items_to_add; ++item_idx)
                    {
                        final_tbm[start + item_idx] = std::move(se_exp_value.tbm[item_idx]);
                    }
                    return comm::protocol_result<void>::success();
                });
            if (!expand_status)
            {
                return comm::protocol_result<logvole_receiver_online_output>::failure(
                    expand_status.error(), expand_status.message());
            }

            output.tbm = std::move(final_tbm);
            return comm::protocol_result<logvole_receiver_online_output>::success(std::move(output));
        }

        bool ring_batch_equal(const std::vector<ring_rns_poly> &lhs, const std::vector<ring_rns_poly> &rhs)
        {
            if (lhs.size() != rhs.size())
            {
                return false;
            }

            for (std::size_t i = 0; i < lhs.size(); ++i)
            {
                if (lhs[i].coeffs != rhs[i].coeffs)
                {
                    return false;
                }
            }

            return true;
        }

        bool shrinkexpand_params_equal(const shrinkexpand_params &lhs, const shrinkexpand_params &rhs)
        {
            return lhs.ring == rhs.ring && lhs.plaintext_modulus_bits == rhs.plaintext_modulus_bits &&
                   lhs.alpha == rhs.alpha && lhs.mu == rhs.mu && lhs.gadget_log_base == rhs.gadget_log_base &&
                   lhs.tau == rhs.tau && lhs.num_worker_threads == rhs.num_worker_threads &&
                   lhs.truncate_one_gadget_digit == rhs.truncate_one_gadget_digit &&
                   lhs.leaf_inputs_are_gadget == rhs.leaf_inputs_are_gadget && lhs.mode == rhs.mode &&
                   lhs.sampling_seeds.noise_root == rhs.sampling_seeds.noise_root &&
                   lhs.sampling_seeds.ct2_root == rhs.sampling_seeds.ct2_root && lhs.noise_bound == rhs.noise_bound;
        }

        comm::protocol_result<void> validate_reusable_logvole_sender_state(
            const shrinkexpand_sender_state &shared_state, const shrinkexpand_params &expected_params,
            const std::vector<ring_rns_poly> &expected_sk1)
        {
            if (!shrinkexpand_params_equal(shared_state.params, expected_params))
            {
                return comm::protocol_result<void>::failure(
                    comm::protocol_errc::invalid_state_transition,
                    "reusable LogVOLE shrinkexpand sender state parameter mismatch");
            }

            if (!ring_batch_equal(shared_state.sk1, expected_sk1))
            {
                return comm::protocol_result<void>::failure(
                    comm::protocol_errc::invalid_state_transition,
                    "reusable LogVOLE shrinkexpand sender sk1 mismatch");
            }

            return comm::protocol_result<void>::success();
        }

        comm::protocol_result<void> validate_reusable_logvole_receiver_state(
            const shrinkexpand_receiver_state &shared_state, const shrinkexpand_params &expected_params)
        {
            if (!shrinkexpand_params_equal(shared_state.params, expected_params))
            {
                return comm::protocol_result<void>::failure(
                    comm::protocol_errc::invalid_state_transition,
                    "reusable LogVOLE shrinkexpand receiver state parameter mismatch");
            }

            return comm::protocol_result<void>::success();
        }

        comm::protocol_result<logvole_sender_offline_output> run_logvole_sender_offline_impl(
            comm::channel_interface *channel, std::uint64_t session_id, const logvole_sender_offline_input &input,
            const logvole_backend &backend, bool is_top_level,
            const shrinkexpand_sender_state *reusable_internal_state)
        {
            logvole_params params = input.params;
            if (params.total_label_count == 0u)
            {
                params.total_label_count =
                    static_cast<std::uint64_t>(params.shrinkexpand.ring.poly_modulus_degree) * params.w;
            }

            logvole_sender_offline_output output{};
            output.state.params = params;
            output.state.sk1 = input.sk1;

            auto tau_hi_res = compute_tau_hi(params.shrinkexpand.tau);
            if (!tau_hi_res)
            {
                return comm::protocol_result<logvole_sender_offline_output>::failure(
                    tau_hi_res.error(), tau_hi_res.message());
            }

            const std::uint32_t tau_hi = tau_hi_res.value();
            const std::uint32_t w = params.w;
            const std::uint32_t alpha = params.shrinkexpand.alpha;
            const std::uint32_t rho = static_cast<std::uint32_t>(params.shrinkexpand.ring.coeff_modulus_bits.size());
            const std::uint32_t mu_hi = alpha * tau_hi * rho;
            const std::uint32_t w_double_prime = (w + mu_hi - 1u) / mu_hi;
            const auto mode = eval_logvole_mode(w, alpha, tau_hi, rho);

            if (mode == logvole_mode::root && w != mu_hi)
            {
                return comm::protocol_result<logvole_sender_offline_output>::failure(
                    comm::protocol_errc::config_error, "randomized-root LogVOLE terminal width must equal mu_hi");
            }

            auto se_params_res = make_trunc_shrinkexpand_params(params, input.leaf_inputs_are_gadget);
            if (!se_params_res)
            {
                return comm::protocol_result<logvole_sender_offline_output>::failure(
                    se_params_res.error(), se_params_res.message());
            }
            const auto &se_params = se_params_res.value();

            const shrinkexpand_sender_state *child_reusable_state = reusable_internal_state;
            if (reusable_internal_state != nullptr)
            {
                auto reusable_ok =
                    validate_reusable_logvole_sender_state(*reusable_internal_state, se_params, input.sk1);
                if (!reusable_ok)
                {
                    return comm::protocol_result<logvole_sender_offline_output>::failure(
                        reusable_ok.error(), reusable_ok.message());
                }

                output.state.shrinkexpand_state = *reusable_internal_state;
            }
            else
            {
                shrinkexpand_sender_offline_input se_in{};
                se_in.params = se_params;

                auto rep_out = backend.rep_offline_sender_input(
                    input.sk1, params.gamma, params.shrinkexpand.alpha, tau_hi, params.shrinkexpand.ring);
                if (!rep_out)
                {
                    return comm::protocol_result<logvole_sender_offline_output>::failure(
                        rep_out.error(), rep_out.message());
                }
                se_in.s = std::move(rep_out.value());
                if (!is_top_level)
                {
                    se_in.fixed_sk1 = input.sk1;
                }

                auto se_wrap_ptr = std::make_unique<comm::subchannel_wrapper>(channel, session_id + 1);
                comm::any_channel any_se(std::move(se_wrap_ptr));
                auto se_out = run_shrinkexpand_sender(std::move(any_se), se_in, backend.get_shrinkexpand_backend());
                if (!se_out)
                {
                    return comm::protocol_result<logvole_sender_offline_output>::failure(
                        se_out.error(), se_out.message());
                }

                output.state.shrinkexpand_state = std::move(se_out.value().state);
                accumulate_counters(output.counters, se_out.value().counters);

                if (!is_top_level)
                {
                    child_reusable_state = &output.state.shrinkexpand_state;
                }
            }

            if (mode == logvole_mode::root)
            {
                auto root_msg = setup_logvole_root_wrapper_sender(output.state, backend);
                if (!root_msg)
                {
                    return comm::protocol_result<logvole_sender_offline_output>::failure(
                        root_msg.error(), root_msg.message());
                }

                auto root_wrap_ptr = std::make_unique<comm::subchannel_wrapper>(channel, session_id + 3);
                comm::any_channel root_channel(std::move(root_wrap_ptr));
                comm::protocol_engine<logvole_root_offline_spec, comm::role_t::sender> root_engine(
                    std::move(root_channel));
                auto root_run =
                    root_engine.run_with(comm::on_send<0>([&]() -> comm::protocol_result<logvole_root_offline_msg> {
                        return comm::protocol_result<logvole_root_offline_msg>::success(std::move(root_msg.value()));
                    }));
                if (!root_run)
                {
                    return comm::protocol_result<logvole_sender_offline_output>::failure(
                        root_run.error(), root_run.message());
                }
                accumulate_counters(output.counters, root_engine.counters());
                return comm::protocol_result<logvole_sender_offline_output>::success(std::move(output));
            }

            logvole_sender_offline_input rec_in{};
            rec_in.params = params;
            rec_in.leaf_inputs_are_gadget = true;
            rec_in.params.w = w_double_prime * tau_hi * rho;
            rec_in.params.gamma = tau_hi;
            rec_in.sk1 = output.state.shrinkexpand_state.sk1;

            auto si_wrap_ptr = std::make_unique<comm::subchannel_wrapper>(channel, session_id + 2);
            auto si_out = run_logvole_sender_offline_impl(
                si_wrap_ptr.get(), si_wrap_ptr->config().session_id, rec_in, backend, false, child_reusable_state);
            if (!si_out)
            {
                return comm::protocol_result<logvole_sender_offline_output>::failure(
                    si_out.error(), si_out.message());
            }

            output.state.next_level_state = std::make_unique<logvole_sender_state>(std::move(si_out.value().state));
            accumulate_counters(output.counters, si_out.value().counters);

            return comm::protocol_result<logvole_sender_offline_output>::success(std::move(output));
        }

        comm::protocol_result<logvole_receiver_offline_output> run_logvole_receiver_offline_impl(
            comm::channel_interface *channel, std::uint64_t session_id, const logvole_receiver_offline_input &input,
            const logvole_backend &backend, bool is_top_level,
            const shrinkexpand_receiver_state *reusable_internal_state)
        {
            logvole_params params = input.params;
            if (params.total_label_count == 0u)
            {
                params.total_label_count =
                    static_cast<std::uint64_t>(params.shrinkexpand.ring.poly_modulus_degree) * params.w;
            }

            logvole_receiver_offline_output output{};
            output.state.params = params;

            auto tau_hi_res = compute_tau_hi(params.shrinkexpand.tau);
            if (!tau_hi_res)
            {
                return comm::protocol_result<logvole_receiver_offline_output>::failure(
                    tau_hi_res.error(), tau_hi_res.message());
            }

            const std::uint32_t tau_hi = tau_hi_res.value();
            const std::uint32_t w = params.w;
            const std::uint32_t alpha = params.shrinkexpand.alpha;
            const std::uint32_t rho = static_cast<std::uint32_t>(params.shrinkexpand.ring.coeff_modulus_bits.size());
            const std::uint32_t mu_hi = alpha * tau_hi * rho;
            const auto mode = eval_logvole_mode(w, alpha, tau_hi, rho);

            if (mode == logvole_mode::root && w != mu_hi)
            {
                return comm::protocol_result<logvole_receiver_offline_output>::failure(
                    comm::protocol_errc::config_error, "randomized-root LogVOLE terminal width must equal mu_hi");
            }

            auto se_params_res = make_trunc_shrinkexpand_params(params, input.leaf_inputs_are_gadget);
            if (!se_params_res)
            {
                return comm::protocol_result<logvole_receiver_offline_output>::failure(
                    se_params_res.error(), se_params_res.message());
            }
            const auto &se_params = se_params_res.value();

            const shrinkexpand_receiver_state *child_reusable_state = reusable_internal_state;
            if (reusable_internal_state != nullptr)
            {
                auto reusable_ok = validate_reusable_logvole_receiver_state(*reusable_internal_state, se_params);
                if (!reusable_ok)
                {
                    return comm::protocol_result<logvole_receiver_offline_output>::failure(
                        reusable_ok.error(), reusable_ok.message());
                }

                output.state.shrinkexpand_state = *reusable_internal_state;
            }
            else
            {
                shrinkexpand_receiver_offline_input se_in{};
                se_in.params = se_params;

                auto se_wrap_ptr = std::make_unique<comm::subchannel_wrapper>(channel, session_id + 1);
                comm::any_channel any_se(std::move(se_wrap_ptr));
                auto se_out = run_shrinkexpand_receiver(std::move(any_se), se_in, backend.get_shrinkexpand_backend());
                if (!se_out)
                {
                    return comm::protocol_result<logvole_receiver_offline_output>::failure(
                        se_out.error(), se_out.message());
                }

                output.state.shrinkexpand_state = std::move(se_out.value().state);
                accumulate_counters(output.counters, se_out.value().counters);

                if (!is_top_level)
                {
                    child_reusable_state = &output.state.shrinkexpand_state;
                }
            }

            if (mode == logvole_mode::root)
            {
                std::optional<logvole_root_offline_msg> root_msg{};
                auto root_wrap_ptr = std::make_unique<comm::subchannel_wrapper>(channel, session_id + 3);
                comm::any_channel root_channel(std::move(root_wrap_ptr));
                comm::protocol_engine<logvole_root_offline_spec, comm::role_t::receiver> root_engine(
                    std::move(root_channel));
                auto root_run = root_engine.run_with(
                    comm::on_recv<0>([&](const logvole_root_offline_msg &message) -> comm::protocol_result<void> {
                        root_msg = message;
                        return comm::protocol_result<void>::success();
                    }));
                if (!root_run)
                {
                    return comm::protocol_result<logvole_receiver_offline_output>::failure(
                        root_run.error(), root_run.message());
                }
                if (!root_msg)
                {
                    return comm::protocol_result<logvole_receiver_offline_output>::failure(
                        comm::protocol_errc::invalid_state_transition, "missing root wrapper offline message");
                }
                auto root_ok = finalize_logvole_root_wrapper_receiver(output.state, *root_msg);
                if (!root_ok)
                {
                    return comm::protocol_result<logvole_receiver_offline_output>::failure(
                        root_ok.error(), root_ok.message());
                }
                accumulate_counters(output.counters, root_engine.counters());
                return comm::protocol_result<logvole_receiver_offline_output>::success(std::move(output));
            }

            logvole_receiver_offline_input rec_in{};
            rec_in.params = params;
            rec_in.leaf_inputs_are_gadget = true;
            const std::uint32_t w_double_prime = (w + mu_hi - 1u) / mu_hi;
            rec_in.params.w = w_double_prime * tau_hi * rho;
            rec_in.params.gamma = tau_hi;

            auto si_wrap_ptr = std::make_unique<comm::subchannel_wrapper>(channel, session_id + 2);
            auto si_out = run_logvole_receiver_offline_impl(
                si_wrap_ptr.get(), si_wrap_ptr->config().session_id, rec_in, backend, false, child_reusable_state);
            if (!si_out)
            {
                return comm::protocol_result<logvole_receiver_offline_output>::failure(
                    si_out.error(), si_out.message());
            }

            output.state.next_level_state =
                std::make_unique<logvole_receiver_state>(std::move(si_out.value().state));
            accumulate_counters(output.counters, si_out.value().counters);

            return comm::protocol_result<logvole_receiver_offline_output>::success(std::move(output));
        }

    } // namespace

    comm::protocol_result<logvole_sender_offline_output> run_logvole_sender_offline(
        comm::any_channel channel, const logvole_sender_offline_input &input, const logvole_backend &backend)
    {
        return run_logvole_sender_offline_impl(
            channel.get(), channel.config().session_id, input, backend, true, nullptr);
    }

    comm::protocol_result<logvole_receiver_offline_output> run_logvole_receiver_offline(
        comm::any_channel channel, const logvole_receiver_offline_input &input, const logvole_backend &backend)
    {
        return run_logvole_receiver_offline_impl(
            channel.get(), channel.config().session_id, input, backend, true, nullptr);
    }

    comm::protocol_result<logvole_receiver_online_output> run_logvole_receiver_online(
        comm::any_channel channel, const logvole_receiver_state &state,
        const logvole_receiver_online_input &input, const logvole_backend &backend)
    {
        if (!channel.valid())
        {
            return comm::protocol_result<logvole_receiver_online_output>::failure(
                comm::protocol_errc::config_error, "channel has no implementation");
        }

        auto output =
            run_logvole_receiver_online_impl(channel.get(), channel.config().session_id, state, input, backend);

        return output;
    }

    comm::protocol_result<logvole_sender_precompute_output> run_logvole_sender_precompute(
        const logvole_sender_state &state, const logvole_backend &backend)
    {
        auto validate_ok = validate_recursive_logvole_seed_search(state, backend);
        if (!validate_ok)
        {
            return comm::protocol_result<logvole_sender_precompute_output>::failure(
                validate_ok.error(), validate_ok.message());
        }

        return ensure_logvole_sender_precompute(state, backend);
    }

    comm::protocol_result<logvole_sender_online_output> run_logvole_sender_online(
        comm::any_channel channel, const logvole_sender_state &state, const logvole_sender_online_input &input,
        const logvole_backend &backend)
    {
        if (!channel.valid())
        {
            return comm::protocol_result<logvole_sender_online_output>::failure(
                comm::protocol_errc::config_error, "channel has no implementation");
        }

        auto validate_ok = validate_recursive_logvole_seed_search(state, backend);
        if (!validate_ok)
        {
            return comm::protocol_result<logvole_sender_online_output>::failure(
                validate_ok.error(), validate_ok.message());
        }

        std::promise<comm::protocol_result<logvole_sender_precompute_output>> precompute_promise{};
        logvole_sender_precompute_future precompute_future = precompute_promise.get_future().share();
        std::thread service_thread{};
        comm::protocol_result<comm::comm_counters> service_result =
            comm::protocol_result<comm::comm_counters>::failure(comm::protocol_errc::io_error, "not run");

        service_thread = std::thread([&]() mutable {
            service_result = run_logvole_sender_online_service(
                channel.get(), channel.config().session_id, state, backend, &precompute_future);
        });

        logvole_sender_online_output output{};
        auto precompute_result = ensure_logvole_sender_precompute(state, backend);
        if (precompute_result)
        {
            precompute_promise.set_value(
                comm::protocol_result<logvole_sender_precompute_output>::success(precompute_result.value()));
        }
        else
        {
            precompute_promise.set_value(comm::protocol_result<logvole_sender_precompute_output>::failure(
                precompute_result.error(), precompute_result.message()));
        }

        if (service_thread.joinable())
        {
            service_thread.join();
        }

        if (!precompute_result)
        {
            return comm::protocol_result<logvole_sender_online_output>::failure(
                precompute_result.error(), precompute_result.message());
        }
        if (!service_result)
        {
            return comm::protocol_result<logvole_sender_online_output>::failure(
                service_result.error(), service_result.message());
        }

        if (!input.skip_tbk_output)
        {
            output.tbk = *precompute_result.value().tbk;
        }
        output.counters = service_result.value();
        return comm::protocol_result<logvole_sender_online_output>::success(std::move(output));
    }

} // namespace logvole

#include "lhe_ops.hpp"
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <future>
#include <limits>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#include "cache_test_hooks.hpp"
#include "parallel_utils.hpp"
#include "runtime_cache_scope.hpp"
#include "simd_hints.hpp"

namespace logvole
{
    namespace
    {
        constexpr std::uint64_t k_lhe_noise_domain = 0x4C48454E4F495345ull;

        std::uint64_t pow2_mod(std::uint64_t exp, std::uint64_t mod)
        {
            std::uint64_t result = 1u;
            std::uint64_t base = 2u % mod;
            std::uint64_t e = exp;
            while (e > 0u)
            {
                if ((e & 1u) != 0u)
                {
                    const auto mul = static_cast<unsigned __int128>(result) * base;
                    result = static_cast<std::uint64_t>(mul % mod);
                }
                const auto sq = static_cast<unsigned __int128>(base) * base;
                base = static_cast<std::uint64_t>(sq % mod);
                e >>= 1u;
            }
            return result;
        }

        comm::protocol_result<void> validate_scalar_poly(
            const ring_ntt_context &ctx, const ring_rns_poly &poly, const char *name)
        {
            auto shape = validate_ring_poly_shape(poly, ctx.params, name);
            if (!shape)
            {
                return shape;
            }
            return comm::protocol_result<void>::success();
        }

        comm::protocol_result<void> validate_public_a_ntt(
            const ring_ntt_context &ctx, const std::vector<ring_rns_poly> &public_a_ntt, std::uint32_t expected_count)
        {
            if (public_a_ntt.size() != expected_count)
            {
                return comm::protocol_result<void>::failure(
                    comm::protocol_errc::config_error, "LHE public a size mismatch");
            }

            auto shape = validate_ring_batch_shape(public_a_ntt, ctx.params, "public_a_ntt");
            if (!shape)
            {
                return comm::protocol_result<void>::failure(shape.error(), shape.message());
            }

            return comm::protocol_result<void>::success();
        }

        struct public_a_cache_key
        {
            ring_params ring{};
            std::uint32_t count = 0;
            std::uint64_t run_id = 0;

            bool operator==(const public_a_cache_key &other) const
            {
                return ring == other.ring && count == other.count && run_id == other.run_id;
            }
        };

        struct public_a_cache_key_hash
        {
            std::size_t operator()(const public_a_cache_key &key) const
            {
                std::size_t h = std::hash<std::uint32_t>{}(key.ring.poly_modulus_degree);
                h ^= std::hash<std::uint32_t>{}(key.count) + 0x9e3779b9u + (h << 6u) + (h >> 2u);
                h ^= std::hash<std::uint64_t>{}(key.run_id) + 0x9e3779b9u + (h << 6u) + (h >> 2u);
                for (int bits : key.ring.coeff_modulus_bits)
                {
                    const std::size_t b = std::hash<int>{}(bits);
                    h ^= b + 0x9e3779b9u + (h << 6u) + (h >> 2u);
                }
                return h;
            }
        };

        std::unordered_map<
            public_a_cache_key, std::shared_ptr<const std::vector<ring_rns_poly>>, public_a_cache_key_hash>
            public_a_cache{};
        std::mutex public_a_cache_mutex{};

        comm::protocol_result<std::shared_ptr<const std::vector<ring_rns_poly>>> get_or_create_cached_public_a_ntt(
            const ring_ntt_context &ctx, std::uint32_t mu)
        {
            if (mu == 0u)
            {
                return comm::protocol_result<std::shared_ptr<const std::vector<ring_rns_poly>>>::failure(
                    comm::protocol_errc::config_error, "LHE public a requires mu>0");
            }

            public_a_cache_key key{};
            key.ring = ctx.params;
            key.count = mu;
            const auto scope = current_protocol_cache_scope();
            key.run_id = scope.run_id;

            std::lock_guard<std::mutex> lock(public_a_cache_mutex);
            auto it = public_a_cache.find(key);
            if (it != public_a_cache.end())
            {
                return comm::protocol_result<std::shared_ptr<const std::vector<ring_rns_poly>>>::success(it->second);
            }

            std::vector<ring_rns_poly> a =
                derive_uniform_poly_batch_from_nonce_ntt(ctx, 0xA11ACE5Eull, 0xA110CA7Aull, mu);
            auto candidate = std::make_shared<const std::vector<ring_rns_poly>>(std::move(a));
            auto [insert_it, _inserted] = public_a_cache.emplace(std::move(key), candidate);
            return comm::protocol_result<std::shared_ptr<const std::vector<ring_rns_poly>>>::success(insert_it->second);
        }

        comm::protocol_result<ring_rns_poly> zero_poly(const ring_ntt_context &ctx)
        {
            ring_rns_poly out{};
            out.coeffs.assign(ring_poly_coeff_count(ctx.params), 0u);
            return comm::protocol_result<ring_rns_poly>::success(std::move(out));
        }

    } // namespace

    void clear_lhe_public_a_cache_for_testing()
    {
        std::lock_guard<std::mutex> lock(public_a_cache_mutex);
        public_a_cache.clear();
    }

    comm::protocol_result<std::vector<ring_rns_poly>> build_lhe_public_a_ntt(
        const ring_ntt_context &ctx, std::uint32_t mu)
    {
        auto cached = get_or_create_cached_public_a_ntt(ctx, mu);
        if (!cached)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(cached.error(), cached.message());
        }

        return comm::protocol_result<std::vector<ring_rns_poly>>::success(*cached.value());
    }

    comm::protocol_result<ring_rns_poly> multiply_by_g_power(
        const ring_ntt_context &ctx, const ring_rns_poly &poly, std::uint32_t gadget_log_base, std::uint32_t power)
    {
        auto shape = validate_ring_poly_shape(poly, ctx.params, "poly");
        if (!shape)
        {
            return comm::protocol_result<ring_rns_poly>::failure(shape.error(), shape.message());
        }

        const auto shift_u64 = static_cast<std::uint64_t>(gadget_log_base) * static_cast<std::uint64_t>(power);
        if (shift_u64 > static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max()))
        {
            return comm::protocol_result<ring_rns_poly>::failure(
                comm::protocol_errc::config_error, "gadget_log_base*power exceeds supported exponent range");
        }

        ring_rns_poly out = poly;
        const std::size_t n = ctx.params.poly_modulus_degree;
        for (std::size_t mod_idx = 0; mod_idx < ctx.moduli.size(); ++mod_idx)
        {
            const std::uint64_t mod = ctx.moduli[mod_idx].value();
            const std::size_t offset = mod_idx * n;
            const std::uint64_t factor = pow2_mod(shift_u64, mod);
            for (std::size_t i = 0; i < n; ++i)
            {
                const std::size_t idx = offset + i;
                const auto mul = static_cast<unsigned __int128>(out.coeffs[idx] % mod) * factor;
                out.coeffs[idx] = static_cast<std::uint64_t>(mul % mod);
            }
        }

        return comm::protocol_result<ring_rns_poly>::success(std::move(out));
    }

    comm::protocol_result<ring_tensor> lhe_enc1(
        const ring_ntt_context &ctx, const std::vector<ring_rns_poly> &r, const std::vector<ring_rns_poly> &sk1,
        std::uint32_t gadget_log_base, double noise_standard_deviation, double noise_max_deviation,
        const sampling_seed_config &sampling_seeds, bool r_input_is_ntt, const std::vector<ring_rns_poly> *public_a_ntt,
        std::uint32_t requested_workers)
    {
        if (r.empty() || sk1.empty())
        {
            return comm::protocol_result<ring_tensor>::failure(
                comm::protocol_errc::config_error, "LHE enc1 requires non-empty r and sk1");
        }
        if (noise_standard_deviation < 0)
        {
            return comm::protocol_result<ring_tensor>::failure(
                comm::protocol_errc::config_error, "LHE enc1 noise_standard_deviation cannot be negative");
        }

        // #include <iostream>
        //         std::cout << "lhe_enc1 noise_standard_deviation=" << noise_standard_deviation
        //                   << " noise_max_deviation=" << noise_max_deviation << std::endl;

        auto r_shape = validate_ring_batch_shape(r, ctx.params, "r");
        if (!r_shape)
        {
            return comm::protocol_result<ring_tensor>::failure(r_shape.error(), r_shape.message());
        }

        auto sk1_shape = validate_ring_batch_shape(sk1, ctx.params, "sk1");
        if (!sk1_shape)
        {
            return comm::protocol_result<ring_tensor>::failure(sk1_shape.error(), sk1_shape.message());
        }

        std::shared_ptr<const std::vector<ring_rns_poly>> cached_public_a_ntt;
        const auto expected_public_count = static_cast<std::uint32_t>(r.size());
        if (public_a_ntt)
        {
            auto public_ok = validate_public_a_ntt(ctx, *public_a_ntt, expected_public_count);
            if (!public_ok)
            {
                return comm::protocol_result<ring_tensor>::failure(public_ok.error(), public_ok.message());
            }
        }
        else
        {
            auto cached_public_a_result = get_or_create_cached_public_a_ntt(ctx, expected_public_count);
            if (!cached_public_a_result)
            {
                return comm::protocol_result<ring_tensor>::failure(
                    cached_public_a_result.error(), cached_public_a_result.message());
            }
            cached_public_a_ntt = std::move(cached_public_a_result.value());
            public_a_ntt = cached_public_a_ntt.get();
        }

        ring_tensor ct1{};
        ct1.rows = static_cast<std::uint32_t>(r.size());
        ct1.cols = static_cast<std::uint32_t>(sk1.size());
        ct1.polys.resize(static_cast<std::size_t>(ct1.rows) * ct1.cols);

        std::vector<ring_rns_poly> sk1_ntt = sk1;
        auto sk1_ntt_status = detail::run_parallel_tasks(sk1_ntt.size(), requested_workers, [&](std::size_t poly_idx) {
            return forward_ntt_inplace(sk1_ntt[poly_idx], ctx);
        });
        if (!sk1_ntt_status)
        {
            return comm::protocol_result<ring_tensor>::failure(sk1_ntt_status.error(), sk1_ntt_status.message());
        }

        std::vector<ring_rns_poly> r_ntt = r;
        if (!r_input_is_ntt)
        {
            auto r_ntt_status = detail::run_parallel_tasks(r_ntt.size(), requested_workers, [&](std::size_t poly_idx) {
                return forward_ntt_inplace(r_ntt[poly_idx], ctx);
            });
            if (!r_ntt_status)
            {
                return comm::protocol_result<ring_tensor>::failure(r_ntt_status.error(), r_ntt_status.message());
            }
        }

        const std::size_t n = ctx.params.poly_modulus_degree;
        auto fill_status = detail::run_parallel_tasks(
            static_cast<std::size_t>(ct1.rows), requested_workers,
            [&](std::size_t row_idx) -> comm::protocol_result<void> {
                const std::uint32_t row = static_cast<std::uint32_t>(row_idx);
                const ring_rns_poly &a_ntt = (*public_a_ntt)[row];
                for (std::uint32_t col = 0u; col < ct1.cols; ++col)
                {
                    ring_rns_poly ask_ntt{};
                    ask_ntt.coeffs.assign(ring_poly_coeff_count(ctx.params), 0u);
                    auto ask_res = dyadic_multiply_add_ntt_inplace(a_ntt, sk1_ntt[col], ask_ntt, ctx);
                    if (!ask_res)
                    {
                        return comm::protocol_result<void>::failure(ask_res.error(), ask_res.message());
                    }

                    ring_rns_poly res_ntt = r_ntt[row];
                    const auto shift_u64 =
                        static_cast<std::uint64_t>(gadget_log_base) * static_cast<std::uint64_t>(col);
                    for (std::size_t mod_idx = 0; mod_idx < ctx.moduli.size(); ++mod_idx)
                    {
                        const std::uint64_t mod = ctx.moduli[mod_idx].value();
                        const std::size_t offset = mod_idx * n;
                        const std::uint64_t factor = pow2_mod(shift_u64, mod);
                        for (std::size_t i = 0; i < n; ++i)
                        {
                            const std::size_t idx = offset + i;
                            const auto scaled_ri = static_cast<unsigned __int128>(res_ntt.coeffs[idx]) * factor;
                            res_ntt.coeffs[idx] =
                                (static_cast<std::uint64_t>(scaled_ri % mod) + ask_ntt.coeffs[idx]) % mod;
                        }
                    }

                    auto ires = inverse_ntt_inplace(res_ntt, ctx);
                    if (!ires)
                    {
                        return comm::protocol_result<void>::failure(ires.error(), ires.message());
                    }

                    if (noise_standard_deviation > 0)
                    {
                        const std::uint64_t stream_id =
                            (static_cast<std::uint64_t>(row) << 32u) ^ static_cast<std::uint64_t>(col);
                        const std::uint64_t seed = derive_noise_seed(
                            sampling_seeds, k_lhe_noise_domain, stream_id, gadget_log_base, ct1.cols);
                        auto noise_ok = add_poly_error(
                            res_ntt, noise_standard_deviation, noise_max_deviation, seed, 0u, ctx);
                        if (!noise_ok)
                        {
                            return comm::protocol_result<void>::failure(noise_ok.error(), noise_ok.message());
                        }
                    }

                    ct1.polys[static_cast<std::size_t>(row) * ct1.cols + col] = std::move(res_ntt);
                }
                return comm::protocol_result<void>::success();
            });
        if (!fill_status)
        {
            return comm::protocol_result<ring_tensor>::failure(fill_status.error(), fill_status.message());
        }

        return comm::protocol_result<ring_tensor>::success(std::move(ct1));
    }

    comm::protocol_result<ring_tensor> lhe_enc1_trunc(
        const ring_ntt_context &ctx, const std::vector<ring_rns_poly> &r, const std::vector<ring_rns_poly> &sk1,
        std::uint32_t gadget_log_base, double noise_standard_deviation, double noise_max_deviation,
        const sampling_seed_config &sampling_seeds, bool r_input_is_ntt, const std::vector<ring_rns_poly> *public_a_ntt,
        std::uint32_t requested_workers)
    {
        if (r.empty() || sk1.empty())
        {
            return comm::protocol_result<ring_tensor>::failure(
                comm::protocol_errc::config_error, "LHE trunc enc1 requires non-empty r and sk1");
        }

        std::vector<ring_rns_poly> shifted_r;
        shifted_r.reserve(r.size());
        for (const auto &poly : r)
        {
            auto shifted = multiply_by_g_power(ctx, poly, gadget_log_base, 1u);
            if (!shifted)
            {
                return comm::protocol_result<ring_tensor>::failure(shifted.error(), shifted.message());
            }
            shifted_r.push_back(std::move(shifted.value()));
        }

        return lhe_enc1(
            ctx, shifted_r, sk1, gadget_log_base, noise_standard_deviation, noise_max_deviation, sampling_seeds,
            r_input_is_ntt, public_a_ntt, requested_workers);
    }

    comm::protocol_result<std::vector<ring_rns_poly>> lhe_apply_ct1(
        const ring_ntt_context &ctx, const ring_tensor &ct1, const ring_rns_poly &digest, std::uint32_t gadget_log_base,
        std::uint32_t tau, bool output_ntt, std::uint32_t requested_workers)
    {
        if (ct1.rows == 0u || ct1.cols == 0u || ct1.cols != tau)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                comm::protocol_errc::config_error, "LHE ct1 shape mismatch");
        }

        if (ring_tensor_size(ct1) != ct1.polys.size())
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                comm::protocol_errc::config_error, "LHE ct1 tensor payload mismatch");
        }

        auto digest_ok = validate_scalar_poly(ctx, digest, "digest");
        if (!digest_ok)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(digest_ok.error(), digest_ok.message());
        }

        auto ct_shape = validate_ring_batch_shape(ct1.polys, ctx.params, "ct1.polys");
        if (!ct_shape)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(ct_shape.error(), ct_shape.message());
        }

        auto u = gadget_decompose_bits(digest, gadget_log_base, tau, ctx, requested_workers);
        if (!u)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(u.error(), u.message());
        }

        std::vector<ring_rns_poly> u_ntt = u.value();
        for (auto &p : u_ntt)
        {
            auto res = forward_ntt_inplace(p, ctx);
            if (!res)
                return comm::protocol_result<std::vector<ring_rns_poly>>::failure(res.error(), res.message());
        }

        std::vector<ring_rns_poly> out(ct1.rows);
        auto apply_status = detail::run_parallel_tasks(
            static_cast<std::size_t>(ct1.rows), requested_workers,
            [&](std::size_t row_idx) -> comm::protocol_result<void> {
                const std::uint32_t row = static_cast<std::uint32_t>(row_idx);
                ring_rns_poly acc_ntt{};
                acc_ntt.coeffs.assign(ring_poly_coeff_count(ctx.params), 0u);

                LOGVOLE_PRAGMA_UNROLL
                for (std::uint32_t col = 0; col < tau; ++col)
                {
                    const ring_rns_poly &c_ntt = ct1.polys[row * ct1.cols + col];
                    auto res_mul = dyadic_multiply_add_ntt_inplace(c_ntt, u_ntt[col], acc_ntt, ctx);
                    if (!res_mul)
                    {
                        return comm::protocol_result<void>::failure(res_mul.error(), res_mul.message());
                    }
                }

                if (!output_ntt)
                {
                    auto res = inverse_ntt_inplace(acc_ntt, ctx);
                    if (!res)
                    {
                        return comm::protocol_result<void>::failure(res.error(), res.message());
                    }
                }
                out[row] = std::move(acc_ntt);
                return comm::protocol_result<void>::success();
            });
        if (!apply_status)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                apply_status.error(), apply_status.message());
        }

        return comm::protocol_result<std::vector<ring_rns_poly>>::success(std::move(out));
    }

    comm::protocol_result<std::vector<ring_rns_poly>> lhe_apply_ct1_trunc(
        const ring_ntt_context &ctx, const ring_tensor &ct1, const ring_rns_poly &digest, std::uint32_t gadget_log_base,
        std::uint32_t tau_hi, bool output_ntt, std::uint32_t requested_workers)
    {
        if (tau_hi == 0u || ct1.rows == 0u || ct1.cols != tau_hi)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                comm::protocol_errc::config_error, "LHE trunc ct1 shape mismatch");
        }

        if (ring_tensor_size(ct1) != ct1.polys.size())
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                comm::protocol_errc::config_error, "LHE trunc ct1 tensor payload mismatch");
        }

        auto digest_ok = validate_scalar_poly(ctx, digest, "digest");
        if (!digest_ok)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(digest_ok.error(), digest_ok.message());
        }

        auto ct_shape = validate_ring_batch_shape(ct1.polys, ctx.params, "ct1.polys");
        if (!ct_shape)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(ct_shape.error(), ct_shape.message());
        }

        auto hi_decomp =
            gadget_decompose_bits_range_centered(digest, gadget_log_base, 1u, tau_hi, ctx, requested_workers);
        if (!hi_decomp)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(hi_decomp.error(), hi_decomp.message());
        }

        std::vector<ring_rns_poly> u_hi_ntt;
        u_hi_ntt.reserve(tau_hi);
        for (std::uint32_t i = 0u; i < tau_hi; ++i)
        {
            ring_rns_poly digit_ntt = std::move(hi_decomp.value()[i]);
            auto ok = forward_ntt_inplace(digit_ntt, ctx);
            if (!ok)
            {
                return comm::protocol_result<std::vector<ring_rns_poly>>::failure(ok.error(), ok.message());
            }
            u_hi_ntt.push_back(std::move(digit_ntt));
        }

        std::vector<ring_rns_poly> out(ct1.rows);
        auto apply_status = detail::run_parallel_tasks(
            static_cast<std::size_t>(ct1.rows), requested_workers,
            [&](std::size_t row_idx) -> comm::protocol_result<void> {
                const std::uint32_t row = static_cast<std::uint32_t>(row_idx);
                ring_rns_poly acc_ntt{};
                acc_ntt.coeffs.assign(ring_poly_coeff_count(ctx.params), 0u);

                LOGVOLE_PRAGMA_UNROLL
                for (std::uint32_t col = 0; col < tau_hi; ++col)
                {
                    const ring_rns_poly &c_ntt = ct1.polys[row * ct1.cols + col];
                    auto res_mul = dyadic_multiply_add_ntt_inplace(c_ntt, u_hi_ntt[col], acc_ntt, ctx);
                    if (!res_mul)
                    {
                        return comm::protocol_result<void>::failure(res_mul.error(), res_mul.message());
                    }
                }

                if (!output_ntt)
                {
                    auto res = inverse_ntt_inplace(acc_ntt, ctx);
                    if (!res)
                    {
                        return comm::protocol_result<void>::failure(res.error(), res.message());
                    }
                }
                out[row] = std::move(acc_ntt);
                return comm::protocol_result<void>::success();
            });
        if (!apply_status)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                apply_status.error(), apply_status.message());
        }

        return comm::protocol_result<std::vector<ring_rns_poly>>::success(std::move(out));
    }

    comm::protocol_result<std::vector<ring_rns_poly>> build_hashed_ct2(
        const ring_ntt_context &ctx, std::uint32_t mu, const sampling_seed_config &sampling_seeds, std::uint64_t nonce)
    {
        if (mu == 0u)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                comm::protocol_errc::config_error, "ct2 requires mu>0");
        }

        const std::uint64_t ct2_nonce = derive_ct2_nonce(sampling_seeds, nonce, mu);

        // Batch sampling avoids per-poly PRNG initialization overhead in the online hot path.
        return comm::protocol_result<std::vector<ring_rns_poly>>::success(
            derive_uniform_poly_batch_from_nonce(ctx, ct2_nonce, 0xC720AA55u, mu));
    }

    comm::protocol_result<std::vector<ring_rns_poly>> lhe_dec(
        const ring_ntt_context &ctx, const std::vector<ring_rns_poly> &cipher, const ring_rns_poly &sk,
        const std::vector<ring_rns_poly> *public_a_ntt, bool cipher_input_is_ntt, bool output_ntt,
        std::uint32_t requested_workers)
    {
        if (cipher.empty())
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                comm::protocol_errc::config_error, "LHE dec requires non-empty ciphertext vector");
        }

        auto c_shape = validate_ring_batch_shape(cipher, ctx.params, "cipher");
        if (!c_shape)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(c_shape.error(), c_shape.message());
        }

        auto sk_ok = validate_scalar_poly(ctx, sk, "sk");
        if (!sk_ok)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(sk_ok.error(), sk_ok.message());
        }

        std::shared_ptr<const std::vector<ring_rns_poly>> cached_public_a_ntt;
        const auto expected_public_count = static_cast<std::uint32_t>(cipher.size());
        if (public_a_ntt)
        {
            auto public_ok = validate_public_a_ntt(ctx, *public_a_ntt, expected_public_count);
            if (!public_ok)
            {
                return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                    public_ok.error(), public_ok.message());
            }
        }
        else
        {
            auto cached_public_a_result = get_or_create_cached_public_a_ntt(ctx, expected_public_count);
            if (!cached_public_a_result)
            {
                return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                    cached_public_a_result.error(), cached_public_a_result.message());
            }
            cached_public_a_ntt = std::move(cached_public_a_result.value());
            public_a_ntt = cached_public_a_ntt.get();
        }

        ring_rns_poly sk_ntt = sk;
        auto sk_ntt_ok = forward_ntt_inplace(sk_ntt, ctx);
        if (!sk_ntt_ok)
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(sk_ntt_ok.error(), sk_ntt_ok.message());

        std::vector<ring_rns_poly> out(cipher.size());
        const std::size_t n = ctx.params.poly_modulus_degree;
        auto dec_status = detail::run_parallel_tasks(
            cipher.size(), requested_workers, [&](std::size_t i) -> comm::protocol_result<void> {
                ring_rns_poly ask_ntt{};
                ask_ntt.coeffs.assign(ring_poly_coeff_count(ctx.params), 0u);
                auto ask_ok = dyadic_multiply_add_ntt_inplace((*public_a_ntt)[i], sk_ntt, ask_ntt, ctx);
                if (!ask_ok)
                {
                    return comm::protocol_result<void>::failure(ask_ok.error(), ask_ok.message());
                }

                ring_rns_poly c_ntt = cipher[i];
                if (!cipher_input_is_ntt)
                {
                    auto res = forward_ntt_inplace(c_ntt, ctx);
                    if (!res)
                    {
                        return comm::protocol_result<void>::failure(res.error(), res.message());
                    }
                }

                for (std::size_t mod_idx = 0; mod_idx < ctx.moduli.size(); ++mod_idx)
                {
                    const std::uint64_t mod = ctx.moduli[mod_idx].value();
                    const std::size_t offset = mod_idx * n;
                    LOGVOLE_PRAGMA_IVDEP
                    for (std::size_t k = 0; k < n; ++k)
                    {
                        const std::size_t idx = offset + k;
                        if (c_ntt.coeffs[idx] >= ask_ntt.coeffs[idx])
                        {
                            c_ntt.coeffs[idx] -= ask_ntt.coeffs[idx];
                        }
                        else
                        {
                            c_ntt.coeffs[idx] = mod - (ask_ntt.coeffs[idx] - c_ntt.coeffs[idx]);
                        }
                    }
                }

                if (!output_ntt)
                {
                    auto ires = inverse_ntt_inplace(c_ntt, ctx);
                    if (!ires)
                    {
                        return comm::protocol_result<void>::failure(ires.error(), ires.message());
                    }
                }
                out[i] = std::move(c_ntt);
                return comm::protocol_result<void>::success();
            });
        if (!dec_status)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(dec_status.error(), dec_status.message());
        }

        return comm::protocol_result<std::vector<ring_rns_poly>>::success(std::move(out));
    }

    comm::protocol_result<ring_rns_poly> derive_skx(
        const ring_ntt_context &ctx, const std::vector<ring_rns_poly> &sk1, const ring_rns_poly &digest,
        const ring_rns_poly &tbk_prime, std::uint32_t gadget_log_base, std::uint32_t tau)
    {
        if (sk1.size() != tau)
        {
            return comm::protocol_result<ring_rns_poly>::failure(
                comm::protocol_errc::config_error, "derive_skx requires sk1 size == tau");
        }

        auto sk1_shape = validate_ring_batch_shape(sk1, ctx.params, "sk1");
        if (!sk1_shape)
        {
            return comm::protocol_result<ring_rns_poly>::failure(sk1_shape.error(), sk1_shape.message());
        }

        auto digest_ok = validate_scalar_poly(ctx, digest, "digest");
        if (!digest_ok)
        {
            return comm::protocol_result<ring_rns_poly>::failure(digest_ok.error(), digest_ok.message());
        }

        auto tbk_ok = validate_scalar_poly(ctx, tbk_prime, "tbk_prime");
        if (!tbk_ok)
        {
            return comm::protocol_result<ring_rns_poly>::failure(tbk_ok.error(), tbk_ok.message());
        }

        auto u = gadget_decompose_bits(digest, gadget_log_base, tau, ctx);
        if (!u)
        {
            return comm::protocol_result<ring_rns_poly>::failure(u.error(), u.message());
        }

        ring_rns_poly acc = tbk_prime;
        for (std::uint32_t i = 0; i < tau; ++i)
        {
            auto term = ring_multiply(sk1[i], u.value()[i], ctx);
            if (!term)
            {
                return comm::protocol_result<ring_rns_poly>::failure(term.error(), term.message());
            }

            auto next = ring_add(acc, term.value(), ctx);
            if (!next)
            {
                return comm::protocol_result<ring_rns_poly>::failure(next.error(), next.message());
            }
            acc = std::move(next.value());
        }

        return comm::protocol_result<ring_rns_poly>::success(std::move(acc));
    }

    comm::protocol_result<ring_rns_poly> derive_skx_trunc(
        const ring_ntt_context &ctx, const std::vector<ring_rns_poly> &sk1, const ring_rns_poly &digest,
        const ring_rns_poly &tbk_prime, std::uint32_t gadget_log_base, std::uint32_t tau_hi)
    {
        if (tau_hi == 0u || sk1.size() != tau_hi)
        {
            return comm::protocol_result<ring_rns_poly>::failure(
                comm::protocol_errc::config_error, "derive_skx_trunc requires sk1 size == tau_hi > 0");
        }

        auto sk1_shape = validate_ring_batch_shape(sk1, ctx.params, "sk1");
        if (!sk1_shape)
        {
            return comm::protocol_result<ring_rns_poly>::failure(sk1_shape.error(), sk1_shape.message());
        }

        auto digest_ok = validate_scalar_poly(ctx, digest, "digest");
        if (!digest_ok)
        {
            return comm::protocol_result<ring_rns_poly>::failure(digest_ok.error(), digest_ok.message());
        }

        auto tbk_ok = validate_scalar_poly(ctx, tbk_prime, "tbk_prime");
        if (!tbk_ok)
        {
            return comm::protocol_result<ring_rns_poly>::failure(tbk_ok.error(), tbk_ok.message());
        }

        auto hi_decomp = gadget_decompose_bits_range_centered(digest, gadget_log_base, 1u, tau_hi, ctx);
        if (!hi_decomp)
        {
            return comm::protocol_result<ring_rns_poly>::failure(hi_decomp.error(), hi_decomp.message());
        }

        ring_rns_poly acc = tbk_prime;
        LOGVOLE_PRAGMA_UNROLL
        for (std::uint32_t i = 0; i < tau_hi; ++i)
        {
            auto term = ring_multiply(sk1[i], hi_decomp.value()[i], ctx);
            if (!term)
            {
                return comm::protocol_result<ring_rns_poly>::failure(term.error(), term.message());
            }

            auto next = ring_add(acc, term.value(), ctx);
            if (!next)
            {
                return comm::protocol_result<ring_rns_poly>::failure(next.error(), next.message());
            }
            acc = std::move(next.value());
        }

        return comm::protocol_result<ring_rns_poly>::success(std::move(acc));
    }

} // namespace logvole

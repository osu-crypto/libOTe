#include "seal/util/uintarithsmallmod.h"
#include "lenc_ops.hpp"
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>
#include "lhe_ops.hpp"
#include "parallel_utils.hpp"
#include "simd_hints.hpp"

namespace logvole
{
    namespace
    {
        constexpr std::uint64_t k_lenc_r_domain = 0x4C454E43525F4E43ull;
        constexpr std::uint64_t k_lenc_ct_noise_domain = 0x4C454E4343544552ull;
        constexpr std::uint64_t k_lenc_trunc_r_domain = 0x4C454E4354524E43ull;
        constexpr std::uint64_t k_lenc_trunc_ct_noise_domain = 0x4C454E4354544552ull;

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

        std::uint32_t next_power_of_two(std::uint32_t value)
        {
            std::uint32_t out = 1u;
            while (out < value)
            {
                out <<= 1u;
            }
            return out;
        }

        std::uint32_t ilog2_exact(std::uint32_t power_of_two)
        {
            std::uint32_t out = 0u;
            while ((1u << out) < power_of_two)
            {
                ++out;
            }
            return out;
        }

        comm::protocol_result<ring_rns_poly> zero_poly(const ring_ntt_context &ctx)
        {
            ring_rns_poly out{};
            out.coeffs.assign(ring_poly_coeff_count(ctx.params), 0u);
            return comm::protocol_result<ring_rns_poly>::success(std::move(out));
        }

        comm::protocol_result<ring_rns_poly> negate_poly(const ring_ntt_context &ctx, const ring_rns_poly &poly)
        {
            auto z = zero_poly(ctx);
            if (!z)
            {
                return comm::protocol_result<ring_rns_poly>::failure(z.error(), z.message());
            }

            auto neg = ring_sub(z.value(), poly, ctx);
            if (!neg)
            {
                return comm::protocol_result<ring_rns_poly>::failure(neg.error(), neg.message());
            }
            return comm::protocol_result<ring_rns_poly>::success(std::move(neg.value()));
        }

        std::vector<ring_rns_poly> pad_batch(
            const ring_ntt_context &ctx, const std::vector<ring_rns_poly> &in, std::uint32_t width_padded)
        {
            std::vector<ring_rns_poly> out = in;
            out.reserve(width_padded);
            for (std::uint32_t i = static_cast<std::uint32_t>(out.size()); i < width_padded; ++i)
            {
                ring_rns_poly zero{};
                zero.coeffs.assign(ring_poly_coeff_count(ctx.params), 0u);
                out.push_back(std::move(zero));
            }
            return out;
        }

        std::vector<ring_rns_poly> build_lenc_public_b_ntt_impl(const ring_ntt_context &ctx, std::uint32_t tau)
        {
            std::vector<ring_rns_poly> b;
            b.reserve(2u * tau);
            for (std::uint32_t i = 0; i < 2u * tau; ++i)
            {
                b.push_back(derive_uniform_poly_from_nonce_ntt(ctx, 0xC0DEC0DEull, 0x1EEC0DEu, i));
            }
            return b;
        }

        struct public_b_cache_key
        {
            ring_params ring{};
            std::uint32_t tau = 0;

            bool operator==(const public_b_cache_key &other) const
            {
                return ring == other.ring && tau == other.tau;
            }
        };

        struct public_b_cache_key_hash
        {
            std::size_t operator()(const public_b_cache_key &key) const
            {
                std::size_t h = std::hash<std::uint32_t>{}(key.ring.poly_modulus_degree);
                h ^= std::hash<std::uint32_t>{}(key.tau) + 0x9e3779b9u + (h << 6u) + (h >> 2u);
                for (int bits : key.ring.coeff_modulus_bits)
                {
                    const std::size_t b = std::hash<int>{}(bits);
                    h ^= b + 0x9e3779b9u + (h << 6u) + (h >> 2u);
                }
                return h;
            }
        };

        std::unordered_map<
            public_b_cache_key, std::shared_ptr<const std::vector<ring_rns_poly>>, public_b_cache_key_hash>
            public_b_cache{};
        std::mutex public_b_cache_mutex{};

        std::shared_ptr<const std::vector<ring_rns_poly>> get_or_create_cached_public_b_ntt(
            const ring_ntt_context &ctx, std::uint32_t tau)
        {
            public_b_cache_key key{};
            key.ring = ctx.params;
            key.tau = tau;

            {
                std::lock_guard<std::mutex> lock(public_b_cache_mutex);
                auto it = public_b_cache.find(key);
                if (it != public_b_cache.end())
                {
                    return it->second;
                }
            }

            auto candidate = std::make_shared<const std::vector<ring_rns_poly>>(build_lenc_public_b_ntt_impl(ctx, tau));

            std::lock_guard<std::mutex> lock(public_b_cache_mutex);
            auto [it, _inserted] = public_b_cache.emplace(std::move(key), candidate);
            return it->second;
        }

        comm::protocol_result<void> validate_public_b_ntt(
            const ring_ntt_context &ctx, const std::vector<ring_rns_poly> &public_b_ntt, std::uint32_t tau)
        {
            if (public_b_ntt.size() != 2u * tau)
            {
                return comm::protocol_result<void>::failure(
                    comm::protocol_errc::config_error, "lenc public b size mismatch");
            }

            auto shape = validate_ring_batch_shape(public_b_ntt, ctx.params, "public_b_ntt");
            if (!shape)
            {
                return comm::protocol_result<void>::failure(shape.error(), shape.message());
            }

            return comm::protocol_result<void>::success();
        }

        comm::protocol_result<ring_rns_poly> inner_product(
            const ring_ntt_context &ctx, const std::vector<ring_rns_poly> &left,
            const std::vector<ring_rns_poly> &right)
        {
            if (left.size() != right.size() || left.empty())
            {
                return comm::protocol_result<ring_rns_poly>::failure(
                    comm::protocol_errc::config_error, "inner_product requires equal non-empty vectors");
            }

            auto l_shape = validate_ring_batch_shape(left, ctx.params, "left");
            if (!l_shape)
            {
                return comm::protocol_result<ring_rns_poly>::failure(l_shape.error(), l_shape.message());
            }

            auto r_shape = validate_ring_batch_shape(right, ctx.params, "right");
            if (!r_shape)
            {
                return comm::protocol_result<ring_rns_poly>::failure(r_shape.error(), r_shape.message());
            }

            auto acc = zero_poly(ctx);
            if (!acc)
            {
                return comm::protocol_result<ring_rns_poly>::failure(acc.error(), acc.message());
            }

            for (std::size_t i = 0; i < left.size(); ++i)
            {
                auto mul = ring_multiply(left[i], right[i], ctx);
                if (!mul)
                {
                    return comm::protocol_result<ring_rns_poly>::failure(mul.error(), mul.message());
                }

                auto next = ring_add(acc.value(), mul.value(), ctx);
                if (!next)
                {
                    return comm::protocol_result<ring_rns_poly>::failure(next.error(), next.message());
                }
                acc = comm::protocol_result<ring_rns_poly>::success(std::move(next.value()));
            }

            return comm::protocol_result<ring_rns_poly>::success(std::move(acc.value()));
        }

        comm::protocol_result<ring_rns_poly> inner_product_ntt_to_std_ptrs(
            const ring_ntt_context &ctx, const ring_rns_poly *const *left_ptrs, const ring_rns_poly *const *right_ptrs,
            std::size_t size)
        {
            if (size == 0)
            {
                return comm::protocol_result<ring_rns_poly>::failure(
                    comm::protocol_errc::config_error, "inner_product_ntt_to_std_ptrs requires size > 0");
            }
            auto acc_ntt_res = zero_poly(ctx);
            if (!acc_ntt_res)
                return acc_ntt_res;
            auto acc_ntt = acc_ntt_res.value();

            for (std::size_t i = 0; i < size; ++i)
            {
                auto res_mul = dyadic_multiply_add_ntt_inplace(*left_ptrs[i], *right_ptrs[i], acc_ntt, ctx);
                if (!res_mul)
                    return comm::protocol_result<ring_rns_poly>::failure(res_mul.error(), res_mul.message());
            }

            auto intt_ok = inverse_ntt_inplace(acc_ntt, ctx);
            if (!intt_ok)
                return comm::protocol_result<ring_rns_poly>::failure(intt_ok.error(), intt_ok.message());

            return comm::protocol_result<ring_rns_poly>::success(std::move(acc_ntt));
        }

        std::uint32_t compute_leaf_tau(std::uint32_t plaintext_modulus_bits, std::uint32_t gadget_log_base)
        {
            if (plaintext_modulus_bits == 0u || gadget_log_base == 0u)
            {
                return 0u;
            }
            return (plaintext_modulus_bits + gadget_log_base - 1u) / gadget_log_base;
        }

        std::uint32_t compute_trunc_leaf_tau(
            std::uint32_t tau_hi, std::uint32_t plaintext_modulus_bits, std::uint32_t gadget_log_base,
            bool leaf_inputs_are_gadget)
        {
            if (leaf_inputs_are_gadget)
            {
                // Recursive LogVOLE feeds the next level one CRT-lifted high digit per input,
                // so the truncated LacE leaf can consume it directly as a single leaf digit.
                return 1u;
            }
            return compute_leaf_tau(plaintext_modulus_bits, gadget_log_base);
        }

        ring_rns_poly zero_poly_raw(const ring_ntt_context &ctx)
        {
            ring_rns_poly zero{};
            zero.coeffs.assign(ring_poly_coeff_count(ctx.params), 0u);
            return zero;
        }

        struct recursive_leaf_scaling
        {
            std::vector<std::uint64_t> delta_mod_qj{};
            std::vector<std::uint64_t> inv_delta_mod_qj{};
        };

        comm::protocol_result<recursive_leaf_scaling> build_recursive_leaf_scaling(const ring_ntt_context &ctx)
        {
            const std::size_t rho = ctx.moduli.size();
            recursive_leaf_scaling scaling{};
            scaling.delta_mod_qj.resize(rho, 1u);
            scaling.inv_delta_mod_qj.resize(rho, 1u);

            for (std::size_t j = 0; j < rho; ++j)
            {
                const auto &mod_j = ctx.moduli[j];
                std::uint64_t delta_mod_qj = 1u;
                for (std::size_t w = 0; w < rho; ++w)
                {
                    if (w == j)
                    {
                        continue;
                    }
                    delta_mod_qj = seal::util::multiply_uint_mod(delta_mod_qj, ctx.moduli[w].value(), mod_j);
                }
                scaling.delta_mod_qj[j] = delta_mod_qj;

                std::uint64_t inv_delta_mod_qj = 0u;
                if (!seal::util::try_invert_uint_mod(delta_mod_qj, mod_j, inv_delta_mod_qj))
                {
                    return comm::protocol_result<recursive_leaf_scaling>::failure(
                        comm::protocol_errc::config_error, "failed to invert Delta_j modulo q_j for recursive leaf");
                }
                scaling.inv_delta_mod_qj[j] = inv_delta_mod_qj;
            }

            return comm::protocol_result<recursive_leaf_scaling>::success(std::move(scaling));
        }

        ring_rns_poly select_and_scale_limb_ntt(
            const ring_ntt_context &ctx, const ring_rns_poly &poly_ntt, std::uint32_t limb_idx,
            std::uint64_t scale_mod_qj)
        {
            ring_rns_poly out{};
            out.coeffs.assign(ring_poly_coeff_count(ctx.params), 0u);

            const std::size_t n = ctx.params.poly_modulus_degree;
            const auto &modulus = ctx.moduli[limb_idx];
            const std::size_t offset = static_cast<std::size_t>(limb_idx) * n;
            for (std::size_t c = 0; c < n; ++c)
            {
                out.coeffs[offset + c] =
                    seal::util::multiply_uint_mod(poly_ntt.coeffs[offset + c], scale_mod_qj, modulus);
            }

            return out;
        }

        comm::protocol_result<ring_rns_poly> recursive_leaf_pair_inner_product_ntt_to_std(
            const ring_ntt_context &ctx, const ring_rns_poly &left_b_ntt, std::uint32_t left_limb,
            std::uint64_t left_scale_mod_qj, const ring_rns_poly &left_digit_ntt, const ring_rns_poly &right_b_ntt,
            std::uint32_t right_limb, std::uint64_t right_scale_mod_qj, const ring_rns_poly &right_digit_ntt)
        {
            const std::size_t coeff_count = ring_poly_coeff_count(ctx.params);
            if (left_b_ntt.coeffs.size() != coeff_count || left_digit_ntt.coeffs.size() != coeff_count ||
                right_b_ntt.coeffs.size() != coeff_count || right_digit_ntt.coeffs.size() != coeff_count ||
                left_limb >= ctx.moduli.size() || right_limb >= ctx.moduli.size())
            {
                return comm::protocol_result<ring_rns_poly>::failure(
                    comm::protocol_errc::config_error, "recursive leaf inner product shape mismatch");
            }

            ring_rns_poly acc_ntt{};
            acc_ntt.coeffs.assign(coeff_count, 0u);

            const std::size_t n = ctx.params.poly_modulus_degree;
            auto accumulate_limb = [&](const ring_rns_poly &b_ntt, std::uint32_t limb, std::uint64_t scale_mod_qj,
                                       const ring_rns_poly &digit_ntt) {
                const auto &modulus = ctx.moduli[limb];
                const std::size_t offset = static_cast<std::size_t>(limb) * n;
                LOGVOLE_PRAGMA_IVDEP
                for (std::size_t c = 0; c < n; ++c)
                {
                    const std::size_t idx = offset + c;
                    const std::uint64_t scaled_b =
                        seal::util::multiply_uint_mod(b_ntt.coeffs[idx], scale_mod_qj, modulus);
                    const std::uint64_t prod = seal::util::multiply_uint_mod(scaled_b, digit_ntt.coeffs[idx], modulus);
                    acc_ntt.coeffs[idx] = seal::util::add_uint_mod(acc_ntt.coeffs[idx], prod, modulus);
                }
            };

            accumulate_limb(left_b_ntt, left_limb, left_scale_mod_qj, left_digit_ntt);
            accumulate_limb(right_b_ntt, right_limb, right_scale_mod_qj, right_digit_ntt);

            auto intt_ok = inverse_ntt_inplace(acc_ntt, ctx);
            if (!intt_ok)
            {
                return comm::protocol_result<ring_rns_poly>::failure(intt_ok.error(), intt_ok.message());
            }

            return comm::protocol_result<ring_rns_poly>::success(std::move(acc_ntt));
        }

        std::vector<ring_rns_poly> make_public_b_internal_hi(
            const ring_ntt_context &ctx, const std::vector<ring_rns_poly> &public_b_full_ntt, std::uint32_t tau_hi)
        {
            const std::uint32_t full_tau = tau_hi + 1u;
            std::vector<ring_rns_poly> out;
            out.reserve(2u * tau_hi);
            for (std::uint32_t i = 0; i < tau_hi; ++i)
            {
                out.push_back(public_b_full_ntt[1u + i]);
            }
            for (std::uint32_t i = 0; i < tau_hi; ++i)
            {
                out.push_back(public_b_full_ntt[full_tau + 1u + i]);
            }
            (void)ctx;
            return out;
        }

        std::vector<ring_rns_poly> make_public_b_leaf(
            const ring_ntt_context &ctx, const std::vector<ring_rns_poly> &public_b_full_ntt, std::uint32_t tau_hi,
            std::uint32_t tau_leaf)
        {
            const std::uint32_t full_tau = tau_hi + 1u;
            std::vector<ring_rns_poly> out(2u * tau_leaf, zero_poly_raw(ctx));
            for (std::uint32_t i = 0; i < tau_leaf; ++i)
            {
                out[i] = public_b_full_ntt[i];
                out[tau_leaf + i] = public_b_full_ntt[full_tau + i];
            }
            return out;
        }

        comm::protocol_result<std::vector<ring_rns_poly>> decompose_hi_ntt(
            const ring_ntt_context &ctx, const ring_rns_poly &poly, std::uint32_t tau_hi, std::uint32_t gadget_log_base)
        {
            auto hi_dec = gadget_decompose_bits_range_centered(poly, gadget_log_base, 1u, tau_hi, ctx, 1u);
            if (!hi_dec)
            {
                return comm::protocol_result<std::vector<ring_rns_poly>>::failure(hi_dec.error(), hi_dec.message());
            }

            std::vector<ring_rns_poly> out;
            out.reserve(tau_hi);
            for (std::uint32_t i = 0u; i < tau_hi; ++i)
            {
                ring_rns_poly digit_ntt = std::move(hi_dec.value()[i]);
                auto ok = forward_ntt_inplace(digit_ntt, ctx);
                if (!ok)
                {
                    return comm::protocol_result<std::vector<ring_rns_poly>>::failure(ok.error(), ok.message());
                }
                out.push_back(std::move(digit_ntt));
            }
            return comm::protocol_result<std::vector<ring_rns_poly>>::success(std::move(out));
        }

        comm::protocol_result<std::vector<ring_rns_poly>> decompose_leaf_padded_ntt(
            const ring_ntt_context &ctx, const ring_rns_poly &poly, std::uint32_t tau_hi, std::uint32_t tau_leaf,
            std::uint32_t gadget_log_base)
        {
            auto leaf_dec = gadget_decompose_bits(poly, gadget_log_base, tau_leaf, ctx, 1u);
            if (!leaf_dec)
            {
                return comm::protocol_result<std::vector<ring_rns_poly>>::failure(leaf_dec.error(), leaf_dec.message());
            }

            std::vector<ring_rns_poly> out;
            out.reserve(tau_hi);
            for (std::uint32_t i = 0u; i < tau_leaf; ++i)
            {
                ring_rns_poly digit_ntt = leaf_dec.value()[i];
                auto ok = forward_ntt_inplace(digit_ntt, ctx);
                if (!ok)
                {
                    return comm::protocol_result<std::vector<ring_rns_poly>>::failure(ok.error(), ok.message());
                }
                out.push_back(std::move(digit_ntt));
            }

            while (out.size() < tau_hi)
            {
                out.push_back(zero_poly_raw(ctx));
            }
            return comm::protocol_result<std::vector<ring_rns_poly>>::success(std::move(out));
        }

        comm::protocol_result<std::vector<ring_rns_poly>> decompose_leaf_padded_ntt_centered(
            const ring_ntt_context &ctx, const ring_rns_poly &poly, std::uint32_t tau_hi, std::uint32_t tau_leaf,
            std::uint32_t gadget_log_base)
        {
            auto leaf_dec = gadget_decompose_bits_range_centered(poly, gadget_log_base, 0u, tau_leaf, ctx, 1u);
            if (!leaf_dec)
            {
                return comm::protocol_result<std::vector<ring_rns_poly>>::failure(leaf_dec.error(), leaf_dec.message());
            }

            std::vector<ring_rns_poly> out;
            out.reserve(tau_hi);
            for (std::uint32_t i = 0u; i < tau_leaf; ++i)
            {
                ring_rns_poly digit_ntt = std::move(leaf_dec.value()[i]);
                auto ok = forward_ntt_inplace(digit_ntt, ctx);
                if (!ok)
                {
                    return comm::protocol_result<std::vector<ring_rns_poly>>::failure(ok.error(), ok.message());
                }
                out.push_back(std::move(digit_ntt));
            }

            while (out.size() < tau_hi)
            {
                out.push_back(zero_poly_raw(ctx));
            }
            return comm::protocol_result<std::vector<ring_rns_poly>>::success(std::move(out));
        }

        comm::protocol_result<std::vector<ring_rns_poly>> decompose_recursive_leaf_single_digit_ntt(
            const ring_ntt_context &ctx, const ring_rns_poly &lifted_poly, std::uint32_t limb_idx,
            std::uint64_t inv_delta_mod_qj)
        {
            ring_rns_poly plain_poly{};
            plain_poly.coeffs.assign(ring_poly_coeff_count(ctx.params), 0u);

            const std::size_t n = ctx.params.poly_modulus_degree;
            const auto &modulus = ctx.moduli[limb_idx];
            const std::size_t offset = static_cast<std::size_t>(limb_idx) * n;
            for (std::size_t c = 0; c < n; ++c)
            {
                const std::uint64_t reduced =
                    seal::util::multiply_uint_mod(lifted_poly.coeffs[offset + c], inv_delta_mod_qj, modulus);
                const std::int64_t centered = (reduced > (modulus.value() >> 1u))
                                                  ? -static_cast<std::int64_t>(modulus.value() - reduced)
                                                  : static_cast<std::int64_t>(reduced);

                for (std::size_t mod_idx = 0; mod_idx < ctx.moduli.size(); ++mod_idx)
                {
                    const auto &mod_k = ctx.moduli[mod_idx];
                    const std::size_t mod_offset = mod_idx * n + c;
                    if (centered < 0)
                    {
                        plain_poly.coeffs[mod_offset] = mod_k.value() - static_cast<std::uint64_t>(-centered);
                    }
                    else
                    {
                        plain_poly.coeffs[mod_offset] = static_cast<std::uint64_t>(centered);
                    }
                }
            }

            auto ok = forward_ntt_inplace(plain_poly, ctx);
            if (!ok)
            {
                return comm::protocol_result<std::vector<ring_rns_poly>>::failure(ok.error(), ok.message());
            }

            std::vector<ring_rns_poly> out;
            out.push_back(std::move(plain_poly));
            return comm::protocol_result<std::vector<ring_rns_poly>>::success(std::move(out));
        }

        comm::protocol_result<ring_rns_poly> derive_error_poly_from_nonce_ntt(
            const ring_ntt_context &ctx, std::uint64_t seed, std::uint64_t stream_id, double noise_standard_deviation,
            double noise_max_deviation)
        {
            ring_rns_poly noise{};
            noise.coeffs.assign(ring_poly_coeff_count(ctx.params), 0u);
            auto noise_ok = add_poly_error(noise, noise_standard_deviation, noise_max_deviation, seed, stream_id, ctx);
            if (!noise_ok)
            {
                return comm::protocol_result<ring_rns_poly>::failure(noise_ok.error(), noise_ok.message());
            }

            auto ntt_ok = forward_ntt_inplace(noise, ctx);
            if (!ntt_ok)
            {
                return comm::protocol_result<ring_rns_poly>::failure(ntt_ok.error(), ntt_ok.message());
            }
            return comm::protocol_result<ring_rns_poly>::success(std::move(noise));
        }

        template <typename LeafAccessor>
        comm::protocol_result<digest_tree> build_digest_tree_trunc_impl(
            const ring_ntt_context &ctx, std::uint32_t x_count, LeafAccessor leaf_at, std::uint32_t tau_hi,
            std::uint32_t gadget_log_base, std::uint32_t plaintext_modulus_bits, std::uint32_t requested_width_padded,
            bool leaf_inputs_are_gadget, const std::vector<ring_rns_poly> *public_b_ntt,
            std::uint32_t requested_workers)
        {
            if (x_count == 0u)
            {
                return comm::protocol_result<digest_tree>::failure(
                    comm::protocol_errc::config_error, "lenc trunc digest requires non-empty x");
            }

            if (tau_hi == 0u)
            {
                return comm::protocol_result<digest_tree>::failure(
                    comm::protocol_errc::config_error, "lenc trunc digest requires tau_hi>0");
            }

            const std::uint32_t tau_leaf =
                compute_trunc_leaf_tau(tau_hi, plaintext_modulus_bits, gadget_log_base, leaf_inputs_are_gadget);
            const std::uint32_t full_tau = tau_hi + 1u;
            if (tau_leaf == 0u || tau_leaf > full_tau)
            {
                return comm::protocol_result<digest_tree>::failure(
                    comm::protocol_errc::config_error, "lenc trunc digest requires 0<tau_leaf<=tau_hi+1");
            }

            std::uint32_t width = requested_width_padded;
            if (width == 0u)
            {
                width = next_power_of_two(x_count);
            }
            if (width < x_count || (width & (width - 1u)) != 0u)
            {
                return comm::protocol_result<digest_tree>::failure(
                    comm::protocol_errc::config_error, "width_padded must be a power-of-two >= x.size");
            }

            const std::uint32_t levels = ilog2_exact(width);
            const std::uint32_t node_count = (2u * width) - 1u;

            std::shared_ptr<const std::vector<ring_rns_poly>> cached_public_b_ntt;
            if (public_b_ntt)
            {
                auto public_ok = validate_public_b_ntt(ctx, *public_b_ntt, full_tau);
                if (!public_ok)
                {
                    return comm::protocol_result<digest_tree>::failure(public_ok.error(), public_ok.message());
                }
            }
            else
            {
                cached_public_b_ntt = get_or_create_cached_public_b_ntt(ctx, full_tau);
                public_b_ntt = cached_public_b_ntt.get();
            }

            const auto public_b_internal_hi = make_public_b_internal_hi(ctx, *public_b_ntt, tau_hi);
            const auto public_b_leaf = make_public_b_leaf(ctx, *public_b_ntt, tau_hi, tau_leaf);
            recursive_leaf_scaling leaf_scaling{};
            if (leaf_inputs_are_gadget)
            {
                auto scaling_res = build_recursive_leaf_scaling(ctx);
                if (!scaling_res)
                {
                    return comm::protocol_result<digest_tree>::failure(scaling_res.error(), scaling_res.message());
                }
                leaf_scaling = std::move(scaling_res.value());
            }

            digest_tree tree{};
            tree.width_padded = width;
            tree.levels = levels;
            tree.node_decomp_ntt.resize(node_count);

            ring_rns_poly zero_padding{};
            if (width > x_count)
            {
                zero_padding.coeffs.assign(ring_poly_coeff_count(ctx.params), 0u);
            }

            const std::size_t width_count = static_cast<std::size_t>(width);
            auto leaf_status = detail::run_parallel_tasks(
                width_count, requested_workers, [&](std::size_t leaf_idx) -> comm::protocol_result<void> {
                    const std::uint32_t leaf = static_cast<std::uint32_t>(leaf_idx);
                    const std::uint32_t node = (width - 1u) + leaf;
                    const ring_rns_poly &leaf_poly =
                        (leaf_idx < static_cast<std::size_t>(x_count)) ? leaf_at(leaf_idx) : zero_padding;
                    auto dec =
                        leaf_inputs_are_gadget
                            ? decompose_recursive_leaf_single_digit_ntt(
                                  ctx, leaf_poly, leaf % static_cast<std::uint32_t>(ctx.moduli.size()),
                                  leaf_scaling.inv_delta_mod_qj[leaf % static_cast<std::uint32_t>(ctx.moduli.size())])
                            : decompose_leaf_padded_ntt(ctx, leaf_poly, tau_leaf, tau_leaf, gadget_log_base);
                    if (!dec)
                    {
                        return comm::protocol_result<void>::failure(dec.error(), dec.message());
                    }
                    tree.node_decomp_ntt[node] = std::move(dec.value());
                    return comm::protocol_result<void>::success();
                });
            if (!leaf_status)
            {
                return comm::protocol_result<digest_tree>::failure(leaf_status.error(), leaf_status.message());
            }

            for (int depth = static_cast<int>(levels) - 1; depth >= 0; --depth)
            {
                const bool use_leaf_level = (depth == static_cast<int>(levels) - 1);
                const auto &b_level = use_leaf_level ? public_b_leaf : public_b_internal_hi;
                const std::uint32_t active_tau = use_leaf_level ? tau_leaf : tau_hi;

                std::vector<const ring_rns_poly *> b_ptrs;
                if (!(use_leaf_level && leaf_inputs_are_gadget))
                {
                    b_ptrs.reserve(2u * active_tau);
                    for (const auto &poly : b_level)
                    {
                        b_ptrs.push_back(&poly);
                    }
                }

                const std::uint32_t nodes_at_depth = static_cast<std::uint32_t>(1u << depth);
                const std::uint32_t first_node = nodes_at_depth - 1u;
                auto depth_status = detail::run_parallel_tasks(
                    static_cast<std::size_t>(nodes_at_depth), requested_workers,
                    [&](std::size_t depth_idx) -> comm::protocol_result<void> {
                        const std::uint32_t p = first_node + static_cast<std::uint32_t>(depth_idx);
                        const std::uint32_t left = (2u * p) + 1u;
                        const std::uint32_t right = left + 1u;

                        std::vector<const ring_rns_poly *> pair_ptrs(2u * active_tau, nullptr);
                        LOGVOLE_PRAGMA_UNROLL
                        for (std::uint32_t i = 0; i < active_tau; ++i)
                        {
                            pair_ptrs[i] = &tree.node_decomp_ntt[left][i];
                            pair_ptrs[active_tau + i] = &tree.node_decomp_ntt[right][i];
                        }

                        auto dot = [&]() -> comm::protocol_result<ring_rns_poly> {
                            if (use_leaf_level && leaf_inputs_are_gadget)
                            {
                                const std::uint32_t left_leaf = left - (width - 1u);
                                const std::uint32_t right_leaf = right - (width - 1u);
                                const std::uint32_t left_limb =
                                    left_leaf % static_cast<std::uint32_t>(ctx.moduli.size());
                                const std::uint32_t right_limb =
                                    right_leaf % static_cast<std::uint32_t>(ctx.moduli.size());

                                return recursive_leaf_pair_inner_product_ntt_to_std(
                                    ctx, (*public_b_ntt)[0u], left_limb, leaf_scaling.delta_mod_qj[left_limb],
                                    *pair_ptrs[0], (*public_b_ntt)[full_tau], right_limb,
                                    leaf_scaling.delta_mod_qj[right_limb], *pair_ptrs[1]);
                            }

                            return inner_product_ntt_to_std_ptrs(ctx, b_ptrs.data(), pair_ptrs.data(), 2u * active_tau);
                        }();
                        if (!dot)
                        {
                            return comm::protocol_result<void>::failure(dot.error(), dot.message());
                        }

                        auto node_value = negate_poly(ctx, dot.value());
                        if (!node_value)
                        {
                            return comm::protocol_result<void>::failure(node_value.error(), node_value.message());
                        }
                        ring_rns_poly node_poly = std::move(node_value.value());

                        if (p == 0u)
                        {
                            tree.digest = std::move(node_poly);
                            return comm::protocol_result<void>::success();
                        }

                        auto dec_hi = decompose_hi_ntt(ctx, node_poly, tau_hi, gadget_log_base);
                        if (!dec_hi)
                        {
                            return comm::protocol_result<void>::failure(dec_hi.error(), dec_hi.message());
                        }
                        tree.node_decomp_ntt[p] = std::move(dec_hi.value());
                        return comm::protocol_result<void>::success();
                    });
                if (!depth_status)
                {
                    return comm::protocol_result<digest_tree>::failure(depth_status.error(), depth_status.message());
                }
            }

            return comm::protocol_result<digest_tree>::success(std::move(tree));
        }

    } // namespace

    std::vector<ring_rns_poly> build_lenc_public_b_ntt(const ring_ntt_context &ctx, std::uint32_t tau)
    {
        auto cached = get_or_create_cached_public_b_ntt(ctx, tau);
        return *cached;
    }

    comm::protocol_result<digest_tree> build_digest_tree(
        const ring_ntt_context &ctx, const std::vector<ring_rns_poly> &x, std::uint32_t tau,
        std::uint32_t gadget_log_base, std::uint32_t requested_width_padded,
        const std::vector<ring_rns_poly> *public_b_ntt, std::uint32_t requested_workers)
    {
        if (x.empty())
        {
            return comm::protocol_result<digest_tree>::failure(
                comm::protocol_errc::config_error, "lenc digest requires non-empty x");
        }

        auto x_shape = validate_ring_batch_shape(x, ctx.params, "x");
        if (!x_shape)
        {
            return comm::protocol_result<digest_tree>::failure(x_shape.error(), x_shape.message());
        }

        if (tau == 0u)
        {
            return comm::protocol_result<digest_tree>::failure(
                comm::protocol_errc::config_error, "lenc digest requires tau>0");
        }

        std::uint32_t width = requested_width_padded;
        if (width == 0u)
        {
            width = next_power_of_two(static_cast<std::uint32_t>(x.size()));
        }
        if (width < x.size() || (width & (width - 1u)) != 0u)
        {
            return comm::protocol_result<digest_tree>::failure(
                comm::protocol_errc::config_error, "width_padded must be a power-of-two >= x.size");
        }

        const std::uint32_t levels = ilog2_exact(width);
        const std::uint32_t node_count = (2u * width) - 1u;

        std::shared_ptr<const std::vector<ring_rns_poly>> cached_public_b_ntt;
        if (public_b_ntt)
        {
            auto public_ok = validate_public_b_ntt(ctx, *public_b_ntt, tau);
            if (!public_ok)
            {
                return comm::protocol_result<digest_tree>::failure(public_ok.error(), public_ok.message());
            }
        }
        else
        {
            cached_public_b_ntt = get_or_create_cached_public_b_ntt(ctx, tau);
            public_b_ntt = cached_public_b_ntt.get();
        }

        digest_tree tree{};
        tree.width_padded = width;
        tree.levels = levels;
        tree.node_decomp_ntt.resize(node_count);
        std::vector<const ring_rns_poly *> b_ptrs;
        b_ptrs.reserve(2u * tau);
        for (const auto &poly : *public_b_ntt)
        {
            b_ptrs.push_back(&poly);
        }

        ring_rns_poly zero_padding{};
        if (width > x.size())
        {
            zero_padding.coeffs.assign(ring_poly_coeff_count(ctx.params), 0u);
        }

        const std::size_t width_count = static_cast<std::size_t>(width);
        auto leaf_status = detail::run_parallel_tasks(
            width_count, requested_workers, [&](std::size_t leaf_idx) -> comm::protocol_result<void> {
                const std::uint32_t leaf = static_cast<std::uint32_t>(leaf_idx);
                const std::uint32_t node = (width - 1u) + leaf;
                const ring_rns_poly &leaf_poly = (leaf_idx < x.size()) ? x[leaf_idx] : zero_padding;
                auto dec = gadget_decompose_bits(leaf_poly, gadget_log_base, tau, ctx, 1u);
                if (!dec)
                {
                    return comm::protocol_result<void>::failure(dec.error(), dec.message());
                }
                auto dec_val = std::move(dec.value());
                for (auto &poly : dec_val)
                {
                    auto ok = forward_ntt_inplace(poly, ctx);
                    if (!ok)
                    {
                        return comm::protocol_result<void>::failure(ok.error(), ok.message());
                    }
                }
                tree.node_decomp_ntt[node] = std::move(dec_val);
                return comm::protocol_result<void>::success();
            });
        if (!leaf_status)
        {
            return comm::protocol_result<digest_tree>::failure(leaf_status.error(), leaf_status.message());
        }

        for (int depth = static_cast<int>(levels) - 1; depth >= 0; --depth)
        {
            const std::uint32_t nodes_at_depth = static_cast<std::uint32_t>(1u << depth);
            const std::uint32_t first_node = nodes_at_depth - 1u;
            auto depth_status = detail::run_parallel_tasks(
                static_cast<std::size_t>(nodes_at_depth), requested_workers,
                [&](std::size_t depth_idx) -> comm::protocol_result<void> {
                    const std::uint32_t p = first_node + static_cast<std::uint32_t>(depth_idx);
                    const std::uint32_t left = (2u * p) + 1u;
                    const std::uint32_t right = left + 1u;

                    std::vector<const ring_rns_poly *> pair_ptrs(2u * tau, nullptr);
                    for (std::uint32_t i = 0; i < tau; ++i)
                    {
                        pair_ptrs[i] = &tree.node_decomp_ntt[left][i];
                        pair_ptrs[tau + i] = &tree.node_decomp_ntt[right][i];
                    }

                    auto dot = inner_product_ntt_to_std_ptrs(ctx, b_ptrs.data(), pair_ptrs.data(), 2u * tau);
                    if (!dot)
                    {
                        return comm::protocol_result<void>::failure(dot.error(), dot.message());
                    }

                    auto node_value = negate_poly(ctx, dot.value());
                    if (!node_value)
                    {
                        return comm::protocol_result<void>::failure(node_value.error(), node_value.message());
                    }
                    ring_rns_poly node_poly = std::move(node_value.value());

                    if (p == 0u)
                    {
                        tree.digest = std::move(node_poly);
                        return comm::protocol_result<void>::success();
                    }

                    auto dec = gadget_decompose_bits(node_poly, gadget_log_base, tau, ctx, 1u);
                    if (!dec)
                    {
                        return comm::protocol_result<void>::failure(dec.error(), dec.message());
                    }
                    auto dec_val = std::move(dec.value());
                    for (auto &poly : dec_val)
                    {
                        auto ok = forward_ntt_inplace(poly, ctx);
                        if (!ok)
                        {
                            return comm::protocol_result<void>::failure(ok.error(), ok.message());
                        }
                    }
                    tree.node_decomp_ntt[p] = std::move(dec_val);
                    return comm::protocol_result<void>::success();
                });
            if (!depth_status)
            {
                return comm::protocol_result<digest_tree>::failure(depth_status.error(), depth_status.message());
            }
        }

        return comm::protocol_result<digest_tree>::success(std::move(tree));
    }

    namespace
    {
        std::size_t ct_row_index(std::uint32_t level, std::uint32_t leaf, std::uint32_t width)
        {
            return static_cast<std::size_t>(level) * width + leaf;
        }

    } // namespace

    comm::protocol_result<lenc_enc_output> lenc_enc(
        const ring_ntt_context &ctx, const std::vector<ring_rns_poly> &s, std::uint32_t tau,
        std::uint32_t gadget_log_base, const sampling_seed_config &sampling_seeds, double noise_standard_deviation,
        double noise_max_deviation, std::uint32_t requested_width_padded, bool emit_r_coeff_domain,
        const std::vector<ring_rns_poly> *public_b_ntt, std::uint32_t requested_workers)
    {
        if (s.empty() || tau == 0u)
        {
            return comm::protocol_result<lenc_enc_output>::failure(
                comm::protocol_errc::config_error, "lenc_enc requires non-empty s and tau>0");
        }
        if (noise_standard_deviation < 0)
        {
            return comm::protocol_result<lenc_enc_output>::failure(
                comm::protocol_errc::config_error, "lenc_enc noise_standard_deviation cannot be negative");
        }

        auto s_shape = validate_ring_batch_shape(s, ctx.params, "s");
        if (!s_shape)
        {
            return comm::protocol_result<lenc_enc_output>::failure(s_shape.error(), s_shape.message());
        }

        const std::uint32_t mu = static_cast<std::uint32_t>(s.size());
        std::uint32_t width = requested_width_padded;
        if (width == 0u)
        {
            width = next_power_of_two(mu);
        }
        if (width < mu || (width & (width - 1u)) != 0u)
        {
            return comm::protocol_result<lenc_enc_output>::failure(
                comm::protocol_errc::config_error, "width_padded must be a power-of-two >= s.size");
        }

        const std::uint32_t levels = ilog2_exact(width);

        std::shared_ptr<const std::vector<ring_rns_poly>> cached_public_b_ntt;
        if (public_b_ntt)
        {
            auto public_ok = validate_public_b_ntt(ctx, *public_b_ntt, tau);
            if (!public_ok)
            {
                return comm::protocol_result<lenc_enc_output>::failure(public_ok.error(), public_ok.message());
            }
        }
        else
        {
            cached_public_b_ntt = get_or_create_cached_public_b_ntt(ctx, tau);
            public_b_ntt = cached_public_b_ntt.get();
        }

        std::vector<std::vector<ring_rns_poly>> r_layers_ntt(levels, std::vector<ring_rns_poly>(width));
        const std::size_t level_count = static_cast<std::size_t>(levels);
        const std::size_t width_count = static_cast<std::size_t>(width);

        auto r_sample_status = detail::run_parallel_tasks(
            level_count * width_count, requested_workers, [&](std::size_t task_idx) -> comm::protocol_result<void> {
                const std::uint32_t level = static_cast<std::uint32_t>(task_idx / width_count);
                const std::uint32_t leaf = static_cast<std::uint32_t>(task_idx % width_count);
                const std::uint64_t nonce = derive_noise_seed(
                    sampling_seeds, k_lenc_r_domain,
                    (static_cast<std::uint64_t>(level) << 32u) ^ static_cast<std::uint64_t>(leaf), width, tau);
                r_layers_ntt[level][leaf] = derive_uniform_poly_from_nonce_ntt(ctx, nonce, 0x1EC0DEDu, leaf);
                return comm::protocol_result<void>::success();
            });
        if (!r_sample_status)
        {
            return comm::protocol_result<lenc_enc_output>::failure(r_sample_status.error(), r_sample_status.message());
        }

        auto s_pad = pad_batch(ctx, s, width);
        std::vector<ring_rns_poly> s_pad_ntt = s_pad;
        auto s_ntt_status = detail::run_parallel_tasks(
            width_count, requested_workers, [&](std::size_t idx) -> comm::protocol_result<void> {
                auto ok = forward_ntt_inplace(s_pad_ntt[idx], ctx);
                if (!ok)
                {
                    return comm::protocol_result<void>::failure(ok.error(), ok.message());
                }
                return comm::protocol_result<void>::success();
            });
        if (!s_ntt_status)
        {
            return comm::protocol_result<lenc_enc_output>::failure(s_ntt_status.error(), s_ntt_status.message());
        }

        ring_tensor ct{};
        ct.rows = levels * width;
        ct.cols = 2u * tau;
        ct.polys.resize(ring_tensor_size(ct));

        const std::size_t n = ctx.params.poly_modulus_degree;
        auto ct_fill_status = detail::run_parallel_tasks(
            level_count * width_count, requested_workers, [&](std::size_t task_idx) -> comm::protocol_result<void> {
                const std::uint32_t level = static_cast<std::uint32_t>(task_idx / width_count);
                const std::uint32_t leaf = static_cast<std::uint32_t>(task_idx % width_count);

                const ring_rns_poly &r_ntt = r_layers_ntt[level][leaf];
                const std::uint32_t bit = (leaf >> (levels - 1u - level)) & 1u;
                const ring_rns_poly &ri_ntt = (level == levels - 1u) ? s_pad_ntt[leaf] : r_layers_ntt[level + 1u][leaf];

                for (std::uint32_t k = 0; k < (2u * tau); ++k)
                {
                    ring_rns_poly row_k_ntt{};
                    row_k_ntt.coeffs.assign(ring_poly_coeff_count(ctx.params), 0u);
                    auto mul_ntt_res = dyadic_multiply_add_ntt_inplace(r_ntt, (*public_b_ntt)[k], row_k_ntt, ctx);
                    if (!mul_ntt_res)
                    {
                        return comm::protocol_result<void>::failure(mul_ntt_res.error(), mul_ntt_res.message());
                    }

                    if (k >= bit * tau && k < (bit + 1) * tau)
                    {
                        std::uint32_t t = k - bit * tau;
                        const auto shift_u64 =
                            static_cast<std::uint64_t>(gadget_log_base) * static_cast<std::uint64_t>(t);
                        for (std::size_t mod_idx = 0; mod_idx < ctx.moduli.size(); ++mod_idx)
                        {
                            const std::uint64_t mod = ctx.moduli[mod_idx].value();
                            const std::size_t offset = mod_idx * n;
                            const std::uint64_t factor = pow2_mod(shift_u64, mod);
                            for (std::size_t i = 0; i < n; ++i)
                            {
                                const std::size_t idx = offset + i;
                                const auto scaled_ri = static_cast<unsigned __int128>(ri_ntt.coeffs[idx]) * factor;
                                row_k_ntt.coeffs[idx] =
                                    (row_k_ntt.coeffs[idx] + static_cast<std::uint64_t>(scaled_ri % mod)) % mod;
                            }
                        }
                    }

                    if (noise_standard_deviation > 0)
                    {
                        // Keep lacct rows in NTT domain. Add NTT(noise) directly so lenc_eval can consume
                        // the ciphertext without any domain conversion.
                        const std::uint64_t stream_id = (static_cast<std::uint64_t>(level) << 48u) ^
                                                        (static_cast<std::uint64_t>(leaf) << 16u) ^
                                                        static_cast<std::uint64_t>(k);
                        const std::uint64_t noise_seed =
                            derive_noise_seed(sampling_seeds, k_lenc_ct_noise_domain, stream_id, width, tau);
                        ring_rns_poly noise{};
                        noise.coeffs.assign(ring_poly_coeff_count(ctx.params), 0u);
                        auto noise_ok =
                            add_poly_error(noise, noise_standard_deviation, noise_max_deviation, noise_seed, 0u, ctx);
                        if (!noise_ok)
                        {
                            return comm::protocol_result<void>::failure(noise_ok.error(), noise_ok.message());
                        }

                        auto ntt_ok = forward_ntt_inplace(noise, ctx);
                        if (!ntt_ok)
                        {
                            return comm::protocol_result<void>::failure(ntt_ok.error(), ntt_ok.message());
                        }

                        auto add_ok = ring_add_inplace(row_k_ntt, noise, ctx);
                        if (!add_ok)
                        {
                            return comm::protocol_result<void>::failure(add_ok.error(), add_ok.message());
                        }
                    }
                    ct.polys[ct_row_index(level, leaf, width) * ct.cols + k] = std::move(row_k_ntt);
                }

                return comm::protocol_result<void>::success();
            });
        if (!ct_fill_status)
        {
            return comm::protocol_result<lenc_enc_output>::failure(ct_fill_status.error(), ct_fill_status.message());
        }

        lenc_enc_output out{};
        out.r_ntt.reserve(mu);
        for (std::uint32_t i = 0; i < mu; ++i)
        {
            out.r_ntt.push_back(std::move(r_layers_ntt[0][i]));
        }

        if (emit_r_coeff_domain)
        {
            out.r.reserve(mu);
            for (std::uint32_t i = 0; i < mu; ++i)
            {
                ring_rns_poly r_i = out.r_ntt[i];
                auto ok = inverse_ntt_inplace(r_i, ctx);
                if (!ok)
                    return comm::protocol_result<lenc_enc_output>::failure(ok.error(), ok.message());
                out.r.push_back(std::move(r_i));
            }
        }

        out.lacct.width_padded = width;
        out.lacct.levels = levels;
        out.lacct.ct = std::move(ct);

        return comm::protocol_result<lenc_enc_output>::success(std::move(out));
    }

    comm::protocol_result<ring_rns_poly> lenc_digest(
        const ring_ntt_context &ctx, const std::vector<ring_rns_poly> &x, std::uint32_t tau,
        std::uint32_t gadget_log_base, std::uint32_t width_padded)
    {
        auto tree = build_digest_tree(ctx, x, tau, gadget_log_base, width_padded, nullptr, 1u);
        if (!tree)
        {
            return comm::protocol_result<ring_rns_poly>::failure(tree.error(), tree.message());
        }
        return comm::protocol_result<ring_rns_poly>::success(std::move(tree.value().digest));
    }

    comm::protocol_result<std::vector<ring_rns_poly>> lenc_eval(
        const ring_ntt_context &ctx, const lenc_lacct &lacct, const std::vector<ring_rns_poly> &x, std::uint32_t mu,
        std::uint32_t tau, std::uint32_t gadget_log_base, bool output_ntt, std::uint32_t requested_workers)
    {
        if (x.size() != mu)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                comm::protocol_errc::config_error, "lenc_eval x size must equal mu");
        }

        auto tree = build_digest_tree(ctx, x, tau, gadget_log_base, lacct.width_padded, nullptr, requested_workers);
        if (!tree)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(tree.error(), tree.message());
        }

        return lenc_eval(ctx, lacct, tree.value(), mu, tau, gadget_log_base, output_ntt, requested_workers);
    }

    comm::protocol_result<std::vector<ring_rns_poly>> lenc_eval(
        const ring_ntt_context &ctx, const lenc_lacct &lacct, const digest_tree &tree, std::uint32_t mu,
        std::uint32_t tau, std::uint32_t gadget_log_base, bool output_ntt, std::uint32_t requested_workers)
    {
        (void)gadget_log_base;

        if (mu == 0u || tau == 0u || lacct.width_padded == 0u)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                comm::protocol_errc::config_error, "lenc_eval requires valid mu/tau/width_padded");
        }

        if (lacct.ct.rows != lacct.levels * lacct.width_padded || lacct.ct.cols != 2u * tau)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                comm::protocol_errc::config_error, "lenc_eval lacct tensor shape mismatch");
        }

        if (ring_tensor_size(lacct.ct) != lacct.ct.polys.size())
        {
            std::cerr << "DEBUG: lenc_eval mismatch: ring_tensor_size=" << ring_tensor_size(lacct.ct)
                      << " polys.size=" << lacct.ct.polys.size() << std::endl;
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                comm::protocol_errc::config_error, "lenc_eval lacct tensor payload mismatch");
        }

        auto ct_shape = validate_ring_batch_shape(lacct.ct.polys, ctx.params, "lacct.ct.polys");
        if (!ct_shape)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(ct_shape.error(), ct_shape.message());
        }

        if (tree.levels != lacct.levels || tree.width_padded != lacct.width_padded)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                comm::protocol_errc::flow_violation, "lenc_eval tree shape mismatch with lacct");
        }

        const std::uint32_t node_count = (2u * tree.width_padded) - 1u;
        if (tree.node_decomp_ntt.size() != node_count)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                comm::protocol_errc::config_error, "lenc_eval tree node decomposition count mismatch");
        }

        for (std::uint32_t node = 1u; node < node_count; ++node)
        {
            if (tree.node_decomp_ntt[node].size() != tau)
            {
                return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                    comm::protocol_errc::config_error, "lenc_eval tree digit level mismatch");
            }
            auto node_shape =
                validate_ring_batch_shape(tree.node_decomp_ntt[node], ctx.params, "tree.node_decomp_ntt[node]");
            if (!node_shape)
            {
                return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                    node_shape.error(), node_shape.message());
            }
        }

        const std::vector<ring_rns_poly> &lacct_polys_ntt = lacct.ct.polys;

        std::vector<ring_rns_poly> out(mu);
        auto eval_status = detail::run_parallel_tasks(
            static_cast<std::size_t>(mu), requested_workers, [&](std::size_t leaf_idx) -> comm::protocol_result<void> {
                const std::uint32_t leaf = static_cast<std::uint32_t>(leaf_idx);
                ring_rns_poly acc_ntt{};
                acc_ntt.coeffs.assign(ring_poly_coeff_count(ctx.params), 0u);

                std::uint32_t parent = 0u;
                for (std::uint32_t level = 0; level < lacct.levels; ++level)
                {
                    const std::uint32_t left = (2u * parent) + 1u;
                    const std::uint32_t right = left + 1u;

                    const std::size_t row = ct_row_index(level, leaf, lacct.width_padded);
                    for (std::uint32_t c = 0; c < tau; ++c)
                    {
                        const auto &ct_poly_l_ntt =
                            lacct_polys_ntt[ring_tensor_index(lacct.ct, static_cast<std::uint32_t>(row), c)];
                        const auto &node_poly_l_ntt = tree.node_decomp_ntt[left][c];

                        auto res_l = dyadic_multiply_add_ntt_inplace(ct_poly_l_ntt, node_poly_l_ntt, acc_ntt, ctx);
                        if (!res_l)
                        {
                            return comm::protocol_result<void>::failure(res_l.error(), res_l.message());
                        }

                        const auto &ct_poly_r_ntt =
                            lacct_polys_ntt[ring_tensor_index(lacct.ct, static_cast<std::uint32_t>(row), tau + c)];
                        const auto &node_poly_r_ntt = tree.node_decomp_ntt[right][c];

                        auto res_r = dyadic_multiply_add_ntt_inplace(ct_poly_r_ntt, node_poly_r_ntt, acc_ntt, ctx);
                        if (!res_r)
                        {
                            return comm::protocol_result<void>::failure(res_r.error(), res_r.message());
                        }
                    }

                    const std::uint32_t bit = (leaf >> (lacct.levels - 1u - level)) & 1u;
                    parent = (bit == 0u) ? left : right;
                }

                if (!output_ntt)
                {
                    auto intt_ok = inverse_ntt_inplace(acc_ntt, ctx);
                    if (!intt_ok)
                    {
                        return comm::protocol_result<void>::failure(intt_ok.error(), intt_ok.message());
                    }
                }

                // Negate result. This works in both coefficient and NTT domains.
                const std::size_t n = ctx.params.poly_modulus_degree;
                for (std::size_t mod_idx = 0; mod_idx < ctx.moduli.size(); ++mod_idx)
                {
                    const std::uint64_t mod = ctx.moduli[mod_idx].value();
                    const std::size_t offset = mod_idx * n;
                    LOGVOLE_PRAGMA_IVDEP
                    for (std::size_t i = 0; i < n; ++i)
                    {
                        if (acc_ntt.coeffs[offset + i] != 0)
                        {
                            acc_ntt.coeffs[offset + i] = mod - acc_ntt.coeffs[offset + i];
                        }
                    }
                }

                out[leaf] = std::move(acc_ntt);
                return comm::protocol_result<void>::success();
            });
        if (!eval_status)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                eval_status.error(), eval_status.message());
        }

        return comm::protocol_result<std::vector<ring_rns_poly>>::success(std::move(out));
    }

    comm::protocol_result<digest_tree> build_digest_tree_trunc(
        const ring_ntt_context &ctx, const std::vector<ring_rns_poly> &x, std::uint32_t tau_hi,
        std::uint32_t gadget_log_base, std::uint32_t plaintext_modulus_bits, std::uint32_t requested_width_padded,
        bool leaf_inputs_are_gadget, const std::vector<ring_rns_poly> *public_b_ntt, std::uint32_t requested_workers)
    {
        if (x.empty())
        {
            return comm::protocol_result<digest_tree>::failure(
                comm::protocol_errc::config_error, "lenc trunc digest requires non-empty x");
        }

        auto x_shape = validate_ring_batch_shape(x, ctx.params, "x");
        if (!x_shape)
        {
            return comm::protocol_result<digest_tree>::failure(x_shape.error(), x_shape.message());
        }

        return build_digest_tree_trunc_impl(
            ctx, static_cast<std::uint32_t>(x.size()), [&](std::size_t idx) -> const ring_rns_poly & { return x[idx]; },
            tau_hi, gadget_log_base, plaintext_modulus_bits, requested_width_padded, leaf_inputs_are_gadget,
            public_b_ntt, requested_workers);
    }

    comm::protocol_result<lenc_enc_output> lenc_enc_trunc(
        const ring_ntt_context &ctx, const std::vector<ring_rns_poly> &s, std::uint32_t tau_hi,
        std::uint32_t gadget_log_base, std::uint32_t plaintext_modulus_bits, const sampling_seed_config &sampling_seeds,
        double noise_standard_deviation, double noise_max_deviation, std::uint32_t requested_width_padded,
        bool emit_r_coeff_domain, bool leaf_inputs_are_gadget, const std::vector<ring_rns_poly> *public_b_ntt,
        std::uint32_t requested_workers)
    {
        if (s.empty() || tau_hi == 0u)
        {
            return comm::protocol_result<lenc_enc_output>::failure(
                comm::protocol_errc::config_error, "lenc_enc_trunc requires non-empty s and tau_hi>0");
        }
        if (noise_standard_deviation < 0)
        {
            return comm::protocol_result<lenc_enc_output>::failure(
                comm::protocol_errc::config_error, "lenc_enc_trunc noise_standard_deviation cannot be negative");
        }

        const std::uint32_t tau_leaf =
            compute_trunc_leaf_tau(tau_hi, plaintext_modulus_bits, gadget_log_base, leaf_inputs_are_gadget);
        const std::uint32_t full_tau = tau_hi + 1u;
        if (tau_leaf == 0u || tau_leaf > full_tau)
        {
            return comm::protocol_result<lenc_enc_output>::failure(
                comm::protocol_errc::config_error, "lenc_enc_trunc requires 0<tau_leaf<=tau_hi+1");
        }

        auto s_shape = validate_ring_batch_shape(s, ctx.params, "s");
        if (!s_shape)
        {
            return comm::protocol_result<lenc_enc_output>::failure(s_shape.error(), s_shape.message());
        }

        const std::uint32_t mu = static_cast<std::uint32_t>(s.size());
        std::uint32_t width = requested_width_padded;
        if (width == 0u)
        {
            width = next_power_of_two(mu);
        }
        if (width < mu || (width & (width - 1u)) != 0u)
        {
            return comm::protocol_result<lenc_enc_output>::failure(
                comm::protocol_errc::config_error, "width_padded must be a power-of-two >= s.size");
        }

        const std::uint32_t levels = ilog2_exact(width);
        const std::uint32_t ct_tau_max = std::max(tau_hi, tau_leaf);

        std::shared_ptr<const std::vector<ring_rns_poly>> cached_public_b_ntt;
        if (public_b_ntt)
        {
            auto public_ok = validate_public_b_ntt(ctx, *public_b_ntt, full_tau);
            if (!public_ok)
            {
                return comm::protocol_result<lenc_enc_output>::failure(public_ok.error(), public_ok.message());
            }
        }
        else
        {
            cached_public_b_ntt = get_or_create_cached_public_b_ntt(ctx, full_tau);
            public_b_ntt = cached_public_b_ntt.get();
        }

        const auto public_b_internal_hi = make_public_b_internal_hi(ctx, *public_b_ntt, tau_hi);
        const auto public_b_leaf = make_public_b_leaf(ctx, *public_b_ntt, tau_hi, tau_leaf);
        recursive_leaf_scaling leaf_scaling{};
        if (leaf_inputs_are_gadget)
        {
            auto scaling_res = build_recursive_leaf_scaling(ctx);
            if (!scaling_res)
            {
                return comm::protocol_result<lenc_enc_output>::failure(scaling_res.error(), scaling_res.message());
            }
            leaf_scaling = std::move(scaling_res.value());
        }

        std::vector<std::vector<ring_rns_poly>> r_layers_ntt(levels, std::vector<ring_rns_poly>(width));
        const std::size_t level_count = static_cast<std::size_t>(levels);
        const std::size_t width_count = static_cast<std::size_t>(width);

        auto r_sample_status = detail::run_parallel_tasks(
            level_count * width_count, requested_workers, [&](std::size_t task_idx) -> comm::protocol_result<void> {
                const std::uint32_t level = static_cast<std::uint32_t>(task_idx / width_count);
                const std::uint32_t leaf = static_cast<std::uint32_t>(task_idx % width_count);
                const std::uint64_t stream_id =
                    (static_cast<std::uint64_t>(level) << 32u) ^ static_cast<std::uint64_t>(leaf);
                const std::uint64_t seed =
                    derive_noise_seed(sampling_seeds, k_lenc_trunc_r_domain, stream_id, plaintext_modulus_bits, tau_hi);
                auto error_ntt =
                    derive_error_poly_from_nonce_ntt(ctx, seed, 0u, noise_standard_deviation, noise_max_deviation);
                if (!error_ntt)
                {
                    return comm::protocol_result<void>::failure(error_ntt.error(), error_ntt.message());
                }
                r_layers_ntt[level][leaf] = std::move(error_ntt.value());
                return comm::protocol_result<void>::success();
            });
        if (!r_sample_status)
        {
            return comm::protocol_result<lenc_enc_output>::failure(r_sample_status.error(), r_sample_status.message());
        }

        auto s_pad = pad_batch(ctx, s, width);
        std::vector<ring_rns_poly> s_pad_ntt = s_pad;
        auto s_ntt_status = detail::run_parallel_tasks(
            width_count, requested_workers, [&](std::size_t idx) -> comm::protocol_result<void> {
                auto ok = forward_ntt_inplace(s_pad_ntt[idx], ctx);
                if (!ok)
                {
                    return comm::protocol_result<void>::failure(ok.error(), ok.message());
                }
                return comm::protocol_result<void>::success();
            });
        if (!s_ntt_status)
        {
            return comm::protocol_result<lenc_enc_output>::failure(s_ntt_status.error(), s_ntt_status.message());
        }

        ring_tensor ct{};
        ct.rows = levels * width;
        ct.cols = 2u * ct_tau_max;
        ct.polys.resize(ring_tensor_size(ct));

        const std::size_t n = ctx.params.poly_modulus_degree;
        auto ct_fill_status = detail::run_parallel_tasks(
            level_count * width_count, requested_workers, [&](std::size_t task_idx) -> comm::protocol_result<void> {
                const std::uint32_t level = static_cast<std::uint32_t>(task_idx / width_count);
                const std::uint32_t leaf = static_cast<std::uint32_t>(task_idx % width_count);

                const ring_rns_poly &r_ntt = r_layers_ntt[level][leaf];
                const std::uint32_t bit = (leaf >> (levels - 1u - level)) & 1u;
                const ring_rns_poly &ri_ntt = (level == levels - 1u) ? s_pad_ntt[leaf] : r_layers_ntt[level + 1u][leaf];

                const bool is_leaf_level = (level == levels - 1u);
                const std::vector<ring_rns_poly> &b_level = is_leaf_level ? public_b_leaf : public_b_internal_hi;
                const std::uint32_t active_tau = is_leaf_level ? tau_leaf : tau_hi;
                const std::uint32_t power_offset = is_leaf_level ? 0u : 1u;
                const std::uint32_t leaf_pair_base = leaf & ~1u;
                const std::uint32_t left_limb = leaf_pair_base % static_cast<std::uint32_t>(ctx.moduli.size());
                const std::uint32_t right_limb = (leaf_pair_base + 1u) % static_cast<std::uint32_t>(ctx.moduli.size());

                for (std::uint32_t side = 0; side < 2u; ++side)
                {
                    for (std::uint32_t t = 0; t < ct_tau_max; ++t)
                    {
                        ring_rns_poly row_k_ntt{};
                        row_k_ntt.coeffs.assign(ring_poly_coeff_count(ctx.params), 0u);

                        if (t < active_tau)
                        {
                            const auto &b_poly = b_level[side * active_tau + t];
                            ring_rns_poly scaled_b_poly{};
                            const ring_rns_poly *b_poly_ptr = &b_poly;
                            if (is_leaf_level && leaf_inputs_are_gadget)
                            {
                                const std::uint32_t limb = (side == 0u) ? left_limb : right_limb;
                                const std::uint32_t full_tau_side_offset = (side == 0u) ? 0u : full_tau;
                                scaled_b_poly = select_and_scale_limb_ntt(
                                    ctx, (*public_b_ntt)[full_tau_side_offset], limb, leaf_scaling.delta_mod_qj[limb]);
                                b_poly_ptr = &scaled_b_poly;
                            }
                            auto mul_ntt_res = dyadic_multiply_add_ntt_inplace(r_ntt, *b_poly_ptr, row_k_ntt, ctx);
                            if (!mul_ntt_res)
                            {
                                return comm::protocol_result<void>::failure(mul_ntt_res.error(), mul_ntt_res.message());
                            }

                            if (side == bit)
                            {
                                const auto shift_u64 = static_cast<std::uint64_t>(gadget_log_base) *
                                                       static_cast<std::uint64_t>(t + power_offset);
                                ring_rns_poly scaled_ri_ntt{};
                                const ring_rns_poly *ri_poly_ptr = &ri_ntt;
                                if (is_leaf_level && leaf_inputs_are_gadget)
                                {
                                    const std::uint32_t limb = (side == 0u) ? left_limb : right_limb;
                                    scaled_ri_ntt =
                                        select_and_scale_limb_ntt(ctx, ri_ntt, limb, leaf_scaling.delta_mod_qj[limb]);
                                    ri_poly_ptr = &scaled_ri_ntt;
                                }
                                const std::uint64_t *ri_coeffs = ri_poly_ptr->coeffs.data();
                                std::uint64_t *row_coeffs = row_k_ntt.coeffs.data();
                                LOGVOLE_PRAGMA_UNROLL
                                for (std::size_t mod_idx = 0; mod_idx < ctx.moduli.size(); ++mod_idx)
                                {
                                    const auto &modulus = ctx.moduli[mod_idx];
                                    const std::uint64_t mod = modulus.value();
                                    const std::size_t offset = mod_idx * n;
                                    const std::uint64_t factor = pow2_mod(shift_u64, mod);
                                    LOGVOLE_PRAGMA_IVDEP
                                    for (std::size_t i = 0; i < n; ++i)
                                    {
                                        const std::size_t idx = offset + i;
                                        const std::uint64_t scaled =
                                            seal::util::multiply_uint_mod(ri_coeffs[idx], factor, modulus);
                                        std::uint64_t sum = row_coeffs[idx] + scaled;
                                        if (sum >= mod)
                                        {
                                            sum -= mod;
                                        }
                                        row_coeffs[idx] = sum;
                                    }
                                }
                            }
                        }

                        if (noise_standard_deviation > 0 && t < active_tau)
                        {
                            const std::uint64_t slot = side * static_cast<std::uint64_t>(ct_tau_max) + t;
                            const std::uint64_t stream_id = (static_cast<std::uint64_t>(level) << 48u) ^
                                                            (static_cast<std::uint64_t>(leaf) << 16u) ^ slot;
                            const std::uint64_t noise_seed = derive_noise_seed(
                                sampling_seeds, k_lenc_trunc_ct_noise_domain, stream_id, plaintext_modulus_bits,
                                ct_tau_max);
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

                            auto add_ok = ring_add_inplace(row_k_ntt, noise, ctx);
                            if (!add_ok)
                            {
                                return comm::protocol_result<void>::failure(add_ok.error(), add_ok.message());
                            }
                        }

                        const std::uint32_t slot = side * ct_tau_max + t;
                        ct.polys[ct_row_index(level, leaf, width) * ct.cols + slot] = std::move(row_k_ntt);
                    }
                }

                return comm::protocol_result<void>::success();
            });
        if (!ct_fill_status)
        {
            return comm::protocol_result<lenc_enc_output>::failure(ct_fill_status.error(), ct_fill_status.message());
        }

        lenc_enc_output out{};
        out.r_ntt.reserve(mu);
        for (std::uint32_t i = 0; i < mu; ++i)
        {
            out.r_ntt.push_back(std::move(r_layers_ntt[0][i]));
        }

        if (emit_r_coeff_domain)
        {
            out.r.reserve(mu);
            for (std::uint32_t i = 0; i < mu; ++i)
            {
                ring_rns_poly r_i = out.r_ntt[i];
                auto ok = inverse_ntt_inplace(r_i, ctx);
                if (!ok)
                {
                    return comm::protocol_result<lenc_enc_output>::failure(ok.error(), ok.message());
                }
                out.r.push_back(std::move(r_i));
            }
        }

        out.lacct.width_padded = width;
        out.lacct.levels = levels;
        out.lacct.ct = std::move(ct);
        return comm::protocol_result<lenc_enc_output>::success(std::move(out));
    }

    comm::protocol_result<ring_rns_poly> lenc_digest_trunc(
        const ring_ntt_context &ctx, const std::vector<ring_rns_poly> &x, std::uint32_t tau_hi,
        std::uint32_t gadget_log_base, std::uint32_t plaintext_modulus_bits, std::uint32_t width_padded,
        bool leaf_inputs_are_gadget)
    {
        auto tree = build_digest_tree_trunc(
            ctx, x, tau_hi, gadget_log_base, plaintext_modulus_bits, width_padded, leaf_inputs_are_gadget, nullptr, 1u);
        if (!tree)
        {
            return comm::protocol_result<ring_rns_poly>::failure(tree.error(), tree.message());
        }
        return comm::protocol_result<ring_rns_poly>::success(std::move(tree.value().digest));
    }

    comm::protocol_result<std::vector<ring_rns_poly>> lenc_eval_trunc(
        const ring_ntt_context &ctx, const lenc_lacct &lacct, const std::vector<ring_rns_poly> &x, std::uint32_t mu,
        std::uint32_t tau_hi, std::uint32_t gadget_log_base, std::uint32_t plaintext_modulus_bits, bool output_ntt,
        std::uint32_t requested_workers, bool leaf_inputs_are_gadget)
    {
        if (x.size() != mu)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                comm::protocol_errc::config_error, "lenc_eval_trunc x size must equal mu");
        }

        auto tree = build_digest_tree_trunc(
            ctx, x, tau_hi, gadget_log_base, plaintext_modulus_bits, lacct.width_padded, leaf_inputs_are_gadget,
            nullptr, requested_workers);
        if (!tree)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(tree.error(), tree.message());
        }

        return lenc_eval_trunc(
            ctx, lacct, tree.value(), mu, tau_hi, gadget_log_base, plaintext_modulus_bits, output_ntt,
            requested_workers, leaf_inputs_are_gadget);
    }

    comm::protocol_result<std::vector<ring_rns_poly>> lenc_eval_trunc(
        const ring_ntt_context &ctx, const lenc_lacct &lacct, const digest_tree &tree, std::uint32_t mu,
        std::uint32_t tau_hi, std::uint32_t gadget_log_base, std::uint32_t plaintext_modulus_bits, bool output_ntt,
        std::uint32_t requested_workers, bool leaf_inputs_are_gadget)
    {
        if (mu == 0u || tau_hi == 0u)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                comm::protocol_errc::config_error, "lenc_eval_trunc requires mu>0 and tau_hi>0");
        }

        if (lacct.ct.rows != lacct.levels * lacct.width_padded)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                comm::protocol_errc::config_error, "lenc_eval_trunc lacct tensor row mismatch");
        }

        const std::uint32_t tau_leaf =
            compute_trunc_leaf_tau(tau_hi, plaintext_modulus_bits, gadget_log_base, leaf_inputs_are_gadget);
        const std::uint32_t full_tau = tau_hi + 1u;
        if (tau_leaf == 0u || tau_leaf > full_tau)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                comm::protocol_errc::config_error, "lenc_eval_trunc requires 0<tau_leaf<=tau_hi+1");
        }

        const std::uint32_t ct_tau_max = std::max(tau_hi, tau_leaf);
        if (lacct.ct.cols != 2u * ct_tau_max)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                comm::protocol_errc::config_error, "lenc_eval_trunc lacct tensor col mismatch");
        }

        if (ring_tensor_size(lacct.ct) != lacct.ct.polys.size())
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                comm::protocol_errc::config_error, "lenc_eval_trunc lacct tensor payload mismatch");
        }

        auto ct_shape = validate_ring_batch_shape(lacct.ct.polys, ctx.params, "lacct.ct.polys");
        if (!ct_shape)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(ct_shape.error(), ct_shape.message());
        }

        if (tree.levels != lacct.levels || tree.width_padded != lacct.width_padded)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                comm::protocol_errc::flow_violation, "lenc_eval_trunc tree shape mismatch with lacct");
        }

        const std::uint32_t node_count = (2u * tree.width_padded) - 1u;
        if (tree.node_decomp_ntt.size() != node_count)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                comm::protocol_errc::config_error, "lenc_eval_trunc tree node decomposition count mismatch");
        }

        const std::uint32_t first_leaf = tree.width_padded - 1u;
        for (std::uint32_t node = 1u; node < node_count; ++node)
        {
            const std::uint32_t expected_tau = (node >= first_leaf) ? tau_leaf : tau_hi;
            if (tree.node_decomp_ntt[node].size() != expected_tau)
            {
                return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                    comm::protocol_errc::config_error, "lenc_eval_trunc tree digit level mismatch");
            }

            auto node_shape =
                validate_ring_batch_shape(tree.node_decomp_ntt[node], ctx.params, "tree.node_decomp_ntt[node]");
            if (!node_shape)
            {
                return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                    node_shape.error(), node_shape.message());
            }
        }

        const std::vector<ring_rns_poly> &lacct_polys_ntt = lacct.ct.polys;
        std::vector<ring_rns_poly> out(mu);
        auto eval_status = detail::run_parallel_tasks(
            static_cast<std::size_t>(mu), requested_workers, [&](std::size_t leaf_idx) -> comm::protocol_result<void> {
                const std::uint32_t leaf = static_cast<std::uint32_t>(leaf_idx);
                ring_rns_poly acc_ntt{};
                acc_ntt.coeffs.assign(ring_poly_coeff_count(ctx.params), 0u);

                std::uint32_t parent = 0u;
                for (std::uint32_t level = 0; level < lacct.levels; ++level)
                {
                    const std::uint32_t left = (2u * parent) + 1u;
                    const std::uint32_t right = left + 1u;
                    const std::uint32_t active_tau = (level == lacct.levels - 1u) ? tau_leaf : tau_hi;
                    const std::size_t row = ct_row_index(level, leaf, lacct.width_padded);

                    for (std::uint32_t c = 0; c < active_tau; ++c)
                    {
                        const auto &ct_poly_l_ntt =
                            lacct_polys_ntt[ring_tensor_index(lacct.ct, static_cast<std::uint32_t>(row), c)];
                        const auto &node_poly_l_ntt = tree.node_decomp_ntt[left][c];
                        auto res_l = dyadic_multiply_add_ntt_inplace(ct_poly_l_ntt, node_poly_l_ntt, acc_ntt, ctx);
                        if (!res_l)
                        {
                            return comm::protocol_result<void>::failure(res_l.error(), res_l.message());
                        }

                        const auto &ct_poly_r_ntt = lacct_polys_ntt[ring_tensor_index(
                            lacct.ct, static_cast<std::uint32_t>(row), ct_tau_max + c)];
                        const auto &node_poly_r_ntt = tree.node_decomp_ntt[right][c];
                        auto res_r = dyadic_multiply_add_ntt_inplace(ct_poly_r_ntt, node_poly_r_ntt, acc_ntt, ctx);
                        if (!res_r)
                        {
                            return comm::protocol_result<void>::failure(res_r.error(), res_r.message());
                        }
                    }

                    const std::uint32_t bit = (leaf >> (lacct.levels - 1u - level)) & 1u;
                    parent = (bit == 0u) ? left : right;
                }

                if (!output_ntt)
                {
                    auto intt_ok = inverse_ntt_inplace(acc_ntt, ctx);
                    if (!intt_ok)
                    {
                        return comm::protocol_result<void>::failure(intt_ok.error(), intt_ok.message());
                    }
                }

                const std::size_t n = ctx.params.poly_modulus_degree;
                for (std::size_t mod_idx = 0; mod_idx < ctx.moduli.size(); ++mod_idx)
                {
                    const std::uint64_t mod = ctx.moduli[mod_idx].value();
                    const std::size_t offset = mod_idx * n;
                    LOGVOLE_PRAGMA_IVDEP
                    for (std::size_t i = 0; i < n; ++i)
                    {
                        if (acc_ntt.coeffs[offset + i] != 0)
                        {
                            acc_ntt.coeffs[offset + i] = mod - acc_ntt.coeffs[offset + i];
                        }
                    }
                }

                out[leaf] = std::move(acc_ntt);
                return comm::protocol_result<void>::success();
            });
        if (!eval_status)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                eval_status.error(), eval_status.message());
        }

        return comm::protocol_result<std::vector<ring_rns_poly>>::success(std::move(out));
    }

} // namespace logvole

#include "lhe_ops.hpp"
#include "seal/util/uintarithsmallmod.h"
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>

namespace loglabel
{
    namespace
    {
        std::uint64_t pow2_mod(std::uint64_t exp, std::uint64_t mod)
        {
            seal::Modulus modulus(mod);
            std::uint64_t result = 1u;
            std::uint64_t base = 2u % mod;
            std::uint64_t e = exp;
            while (e > 0u)
            {
                if ((e & 1u) != 0u)
                {
                    result = seal::util::multiply_uint_mod(result, base, modulus);
                }
                base = seal::util::multiply_uint_mod(base, base, modulus);
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

        comm::protocol_result<ring_rns_poly> zero_poly(const ring_ntt_context &ctx)
        {
            ring_rns_poly out{};
            out.coeffs.assign(ring_poly_coeff_count(ctx.params), 0u);
            return comm::protocol_result<ring_rns_poly>::success(std::move(out));
        }

    } // namespace

    comm::protocol_result<std::vector<ring_rns_poly>> build_lhe_public_a(const ring_ntt_context &ctx, std::uint32_t mu)
    {
        if (mu == 0u)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                comm::protocol_errc::config_error, "LHE public a requires mu>0");
        }

        std::vector<ring_rns_poly> a;
        a.reserve(mu);
        for (std::uint32_t i = 0; i < mu; ++i)
        {
            a.push_back(derive_uniform_poly_from_nonce(ctx, 0xA11ACE5Eull, 0xA110CA7Aull, i));
        }
        return comm::protocol_result<std::vector<ring_rns_poly>>::success(std::move(a));
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
            const auto &modulus = ctx.moduli[mod_idx];
            const std::uint64_t mod = modulus.value();
            const std::size_t offset = mod_idx * n;
            const std::uint64_t factor = pow2_mod(shift_u64, mod);
            for (std::size_t i = 0; i < n; ++i)
            {
                const std::size_t idx = offset + i;
                out.coeffs[idx] = seal::util::multiply_uint_mod(out.coeffs[idx] % mod, factor, modulus);
            }
        }

        return comm::protocol_result<ring_rns_poly>::success(std::move(out));
    }

    comm::protocol_result<ring_tensor> lhe_enc1(
        const ring_ntt_context &ctx, const std::vector<ring_rns_poly> &r, const std::vector<ring_rns_poly> &sk1,
        std::uint32_t gadget_log_base, double noise_standard_deviation, double noise_max_deviation,
        std::uint64_t encryption_noise_seed)
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

        auto a_result = build_lhe_public_a(ctx, static_cast<std::uint32_t>(r.size()));
        if (!a_result)
        {
            return comm::protocol_result<ring_tensor>::failure(a_result.error(), a_result.message());
        }

        ring_tensor ct1{};
        ct1.rows = static_cast<std::uint32_t>(r.size());
        ct1.cols = static_cast<std::uint32_t>(sk1.size());
        ct1.polys.reserve(static_cast<std::size_t>(ct1.rows) * ct1.cols);

        for (std::uint32_t row = 0; row < ct1.rows; ++row)
        {
            for (std::uint32_t col = 0; col < ct1.cols; ++col)
            {
                auto ask = ring_multiply(a_result.value()[row], sk1[col], ctx);
                if (!ask)
                {
                    return comm::protocol_result<ring_tensor>::failure(ask.error(), ask.message());
                }

                auto rg = multiply_by_g_power(ctx, r[row], gadget_log_base, col);
                if (!rg)
                {
                    return comm::protocol_result<ring_tensor>::failure(rg.error(), rg.message());
                }

                auto c = ring_add(ask.value(), rg.value(), ctx);
                if (!c)
                {
                    return comm::protocol_result<ring_tensor>::failure(c.error(), c.message());
                }
                ring_rns_poly c_noisy = std::move(c.value());
                if (noise_standard_deviation > 0)
                {
                    const std::uint64_t stream_id =
                        (static_cast<std::uint64_t>(row) << 32u) ^ static_cast<std::uint64_t>(col);
                    auto noise_ok = add_poly_error(
                        c_noisy, noise_standard_deviation, noise_max_deviation, encryption_noise_seed, stream_id, ctx);
                    if (!noise_ok)
                    {
                        return comm::protocol_result<ring_tensor>::failure(noise_ok.error(), noise_ok.message());
                    }
                }

                ct1.polys.push_back(std::move(c_noisy));
            }
        }

        return comm::protocol_result<ring_tensor>::success(std::move(ct1));
    }

    comm::protocol_result<std::vector<ring_rns_poly>> lhe_apply_ct1(
        const ring_ntt_context &ctx, const ring_tensor &ct1, const ring_rns_poly &digest, std::uint32_t gadget_log_base,
        std::uint32_t tau)
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

        auto u = gadget_decompose_bits(digest, gadget_log_base, tau, ctx);
        if (!u)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(u.error(), u.message());
        }

        std::vector<ring_rns_poly> out;
        out.reserve(ct1.rows);

        for (std::uint32_t row = 0; row < ct1.rows; ++row)
        {
            auto acc = zero_poly(ctx);
            if (!acc)
            {
                return comm::protocol_result<std::vector<ring_rns_poly>>::failure(acc.error(), acc.message());
            }

            for (std::uint32_t col = 0; col < tau; ++col)
            {
                const auto &c = ct1.polys[ring_tensor_index(ct1, row, col)];
                auto term = ring_multiply(c, u.value()[col], ctx);
                if (!term)
                {
                    return comm::protocol_result<std::vector<ring_rns_poly>>::failure(term.error(), term.message());
                }

                auto next = ring_add(acc.value(), term.value(), ctx);
                if (!next)
                {
                    return comm::protocol_result<std::vector<ring_rns_poly>>::failure(next.error(), next.message());
                }
                acc = comm::protocol_result<ring_rns_poly>::success(std::move(next.value()));
            }

            out.push_back(std::move(acc.value()));
        }

        return comm::protocol_result<std::vector<ring_rns_poly>>::success(std::move(out));
    }

    comm::protocol_result<std::vector<ring_rns_poly>> build_hashed_ct2(
        const ring_ntt_context &ctx, std::uint32_t mu, std::uint64_t nonce)
    {
        if (mu == 0u)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                comm::protocol_errc::config_error, "ct2 requires mu>0");
        }

        std::vector<ring_rns_poly> out;
        out.reserve(mu);
        for (std::uint32_t j = 0; j < mu; ++j)
        {
            out.push_back(derive_uniform_poly_from_nonce(ctx, nonce, 0xC720AA55u, j));
        }
        return comm::protocol_result<std::vector<ring_rns_poly>>::success(std::move(out));
    }

    comm::protocol_result<std::vector<ring_rns_poly>> lhe_dec(
        const ring_ntt_context &ctx, const std::vector<ring_rns_poly> &cipher, const ring_rns_poly &sk)
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

        auto a_result = build_lhe_public_a(ctx, static_cast<std::uint32_t>(cipher.size()));
        if (!a_result)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(a_result.error(), a_result.message());
        }

        std::vector<ring_rns_poly> out;
        out.reserve(cipher.size());
        for (std::size_t i = 0; i < cipher.size(); ++i)
        {
            auto ask = ring_multiply(a_result.value()[i], sk, ctx);
            if (!ask)
            {
                return comm::protocol_result<std::vector<ring_rns_poly>>::failure(ask.error(), ask.message());
            }

            auto dec = ring_sub(cipher[i], ask.value(), ctx);
            if (!dec)
            {
                return comm::protocol_result<std::vector<ring_rns_poly>>::failure(dec.error(), dec.message());
            }
            out.push_back(std::move(dec.value()));
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

} // namespace loglabel

#include "lenc_ops.hpp"
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include "lhe_ops.hpp"

namespace loglabel
{
    namespace
    {
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

        std::vector<ring_rns_poly> derive_lenc_public_b(const ring_ntt_context &ctx, std::uint32_t tau)
        {
            std::vector<ring_rns_poly> b;
            b.reserve(2u * tau);
            for (std::uint32_t i = 0; i < 2u * tau; ++i)
            {
                b.push_back(derive_uniform_poly_from_nonce(ctx, 0xC0DEC0DEull, 0x1EEC0DEu, i));
            }
            return b;
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

        struct digest_tree
        {
            std::uint32_t width_padded = 0;
            std::uint32_t levels = 0;
            ring_rns_poly digest{};
            std::vector<std::vector<ring_rns_poly>> node_decomp{};
        };

        comm::protocol_result<digest_tree> build_digest_tree(
            const ring_ntt_context &ctx, const std::vector<ring_rns_poly> &x, std::uint32_t tau,
            std::uint32_t gadget_log_base, std::uint32_t requested_width_padded)
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

            auto b = derive_lenc_public_b(ctx, tau);

            digest_tree tree{};
            tree.width_padded = width;
            tree.levels = levels;
            tree.node_decomp.resize(node_count);

            auto x_pad = pad_batch(ctx, x, width);

            for (std::uint32_t leaf = 0; leaf < width; ++leaf)
            {
                const std::uint32_t node = (width - 1u) + leaf;
                auto dec = gadget_decompose_bits(x_pad[leaf], gadget_log_base, tau, ctx);
                if (!dec)
                {
                    return comm::protocol_result<digest_tree>::failure(dec.error(), dec.message());
                }
                tree.node_decomp[node] = std::move(dec.value());
            }

            for (std::int64_t parent = static_cast<std::int64_t>(width) - 2; parent >= 0; --parent)
            {
                const std::uint32_t p = static_cast<std::uint32_t>(parent);
                const std::uint32_t left = (2u * p) + 1u;
                const std::uint32_t right = left + 1u;

                std::vector<ring_rns_poly> pair;
                pair.reserve(2u * tau);
                for (std::uint32_t i = 0; i < tau; ++i)
                {
                    pair.push_back(tree.node_decomp[left][i]);
                }
                for (std::uint32_t i = 0; i < tau; ++i)
                {
                    pair.push_back(tree.node_decomp[right][i]);
                }

                auto dot = inner_product(ctx, b, pair);
                if (!dot)
                {
                    return comm::protocol_result<digest_tree>::failure(dot.error(), dot.message());
                }

                auto node_value = negate_poly(ctx, dot.value());
                if (!node_value)
                {
                    return comm::protocol_result<digest_tree>::failure(node_value.error(), node_value.message());
                }

                if (p == 0u)
                {
                    tree.digest = std::move(node_value.value());
                }
                else
                {
                    auto dec = gadget_decompose_bits(node_value.value(), gadget_log_base, tau, ctx);
                    if (!dec)
                    {
                        return comm::protocol_result<digest_tree>::failure(dec.error(), dec.message());
                    }
                    tree.node_decomp[p] = std::move(dec.value());
                }
            }

            return comm::protocol_result<digest_tree>::success(std::move(tree));
        }

        std::size_t ct_row_index(std::uint32_t level, std::uint32_t leaf, std::uint32_t width)
        {
            return static_cast<std::size_t>(level) * width + leaf;
        }

    } // namespace

    comm::protocol_result<lenc_enc_output> lenc_enc(
        const ring_ntt_context &ctx, const std::vector<ring_rns_poly> &s, std::uint32_t tau,
        std::uint32_t gadget_log_base, std::uint64_t seed, double noise_standard_deviation, double noise_max_deviation,
        std::uint64_t encryption_noise_seed)
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

        // #include <iostream>
        //         std::cout << "lenc_enc noise_standard_deviation=" << noise_standard_deviation
        //                   << " noise_max_deviation=" << noise_max_deviation << std::endl;

        auto s_shape = validate_ring_batch_shape(s, ctx.params, "s");
        if (!s_shape)
        {
            return comm::protocol_result<lenc_enc_output>::failure(s_shape.error(), s_shape.message());
        }

        const std::uint32_t mu = static_cast<std::uint32_t>(s.size());
        const std::uint32_t width = next_power_of_two(mu);
        const std::uint32_t levels = ilog2_exact(width);

        auto b = derive_lenc_public_b(ctx, tau);
        auto s_pad = pad_batch(ctx, s, width);

        std::vector<std::vector<ring_rns_poly>> r_layers;
        r_layers.resize(levels);
        for (std::uint32_t level = 0; level < levels; ++level)
        {
            r_layers[level].reserve(width);
            for (std::uint32_t leaf = 0; leaf < width; ++leaf)
            {
                const std::uint64_t nonce =
                    seed ^ (static_cast<std::uint64_t>(level) << 32u) ^ static_cast<std::uint64_t>(leaf);
                r_layers[level].push_back(derive_uniform_poly_from_nonce(ctx, nonce, 0x1EC0DEDu, leaf));
            }
        }

        ring_tensor ct{};
        ct.rows = levels * width;
        ct.cols = 2u * tau;
        ct.polys.reserve(ring_tensor_size(ct));

        for (std::uint32_t level = 0; level < levels; ++level)
        {
            for (std::uint32_t leaf = 0; leaf < width; ++leaf)
            {
                const ring_rns_poly &r_cur = r_layers[level][leaf];
                std::vector<ring_rns_poly> row;
                row.reserve(2u * tau);

                for (std::uint32_t k = 0; k < (2u * tau); ++k)
                {
                    auto mul = ring_multiply(r_cur, b[k], ctx);
                    if (!mul)
                    {
                        return comm::protocol_result<lenc_enc_output>::failure(mul.error(), mul.message());
                    }
                    row.push_back(std::move(mul.value()));
                }

                const std::uint32_t bit = (leaf >> (levels - 1u - level)) & 1u;
                const ring_rns_poly &ri = (level == levels - 1u) ? s_pad[leaf] : r_layers[level + 1u][leaf];

                for (std::uint32_t t = 0; t < tau; ++t)
                {
                    auto gpow = multiply_by_g_power(ctx, ri, gadget_log_base, t);
                    if (!gpow)
                    {
                        return comm::protocol_result<lenc_enc_output>::failure(gpow.error(), gpow.message());
                    }

                    const std::uint32_t idx = (bit * tau) + t;
                    auto add = ring_add(row[idx], gpow.value(), ctx);
                    if (!add)
                    {
                        return comm::protocol_result<lenc_enc_output>::failure(add.error(), add.message());
                    }
                    row[idx] = std::move(add.value());
                }

                for (std::uint32_t k = 0; k < static_cast<std::uint32_t>(row.size()); ++k)
                {
                    ring_rns_poly poly = std::move(row[k]);
                    if (noise_standard_deviation > 0)
                    {
                        const std::uint64_t stream_id = (static_cast<std::uint64_t>(level) << 48u) ^
                                                        (static_cast<std::uint64_t>(leaf) << 16u) ^
                                                        static_cast<std::uint64_t>(k);
                        auto noise_ok = add_poly_error(
                            poly, noise_standard_deviation, noise_max_deviation, encryption_noise_seed, stream_id, ctx);
                        if (!noise_ok)
                        {
                            return comm::protocol_result<lenc_enc_output>::failure(
                                noise_ok.error(), noise_ok.message());
                        }
                    }
                    ct.polys.push_back(std::move(poly));
                }
            }
        }

        lenc_enc_output out{};
        out.r.reserve(mu);
        for (std::uint32_t i = 0; i < mu; ++i)
        {
            out.r.push_back(r_layers[0][i]);
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
        auto tree = build_digest_tree(ctx, x, tau, gadget_log_base, width_padded);
        if (!tree)
        {
            return comm::protocol_result<ring_rns_poly>::failure(tree.error(), tree.message());
        }
        return comm::protocol_result<ring_rns_poly>::success(std::move(tree.value().digest));
    }

    comm::protocol_result<std::vector<ring_rns_poly>> lenc_eval(
        const ring_ntt_context &ctx, const lenc_lacct &lacct, const std::vector<ring_rns_poly> &x, std::uint32_t mu,
        std::uint32_t tau, std::uint32_t gadget_log_base)
    {
        if (mu == 0u || tau == 0u || lacct.width_padded == 0u)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                comm::protocol_errc::config_error, "lenc_eval requires valid mu/tau/width_padded");
        }

        if (x.size() != mu)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                comm::protocol_errc::config_error, "lenc_eval x size must equal mu");
        }

        if (lacct.ct.rows != lacct.levels * lacct.width_padded || lacct.ct.cols != 2u * tau)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                comm::protocol_errc::config_error, "lenc_eval lacct tensor shape mismatch");
        }

        if (ring_tensor_size(lacct.ct) != lacct.ct.polys.size())
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                comm::protocol_errc::config_error, "lenc_eval lacct tensor payload mismatch");
        }

        auto ct_shape = validate_ring_batch_shape(lacct.ct.polys, ctx.params, "lacct.ct.polys");
        if (!ct_shape)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(ct_shape.error(), ct_shape.message());
        }

        auto tree = build_digest_tree(ctx, x, tau, gadget_log_base, lacct.width_padded);
        if (!tree)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(tree.error(), tree.message());
        }

        if (tree.value().levels != lacct.levels)
        {
            return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                comm::protocol_errc::flow_violation, "lenc_eval levels mismatch between lacct and digest tree");
        }

        std::vector<ring_rns_poly> out;
        out.reserve(mu);

        for (std::uint32_t leaf = 0; leaf < mu; ++leaf)
        {
            auto acc = zero_poly(ctx);
            if (!acc)
            {
                return comm::protocol_result<std::vector<ring_rns_poly>>::failure(acc.error(), acc.message());
            }

            std::uint32_t parent = 0u;
            for (std::uint32_t level = 0; level < lacct.levels; ++level)
            {
                const std::uint32_t left = (2u * parent) + 1u;
                const std::uint32_t right = left + 1u;

                std::vector<ring_rns_poly> pair;
                pair.reserve(2u * tau);
                for (std::uint32_t i = 0; i < tau; ++i)
                {
                    pair.push_back(tree.value().node_decomp[left][i]);
                }
                for (std::uint32_t i = 0; i < tau; ++i)
                {
                    pair.push_back(tree.value().node_decomp[right][i]);
                }

                std::vector<ring_rns_poly> ct_row;
                ct_row.reserve(2u * tau);
                const std::size_t row = ct_row_index(level, leaf, lacct.width_padded);
                for (std::uint32_t c = 0; c < (2u * tau); ++c)
                {
                    ct_row.push_back(lacct.ct.polys[ring_tensor_index(lacct.ct, static_cast<std::uint32_t>(row), c)]);
                }

                auto dot = inner_product(ctx, ct_row, pair);
                if (!dot)
                {
                    return comm::protocol_result<std::vector<ring_rns_poly>>::failure(dot.error(), dot.message());
                }

                auto next = ring_add(acc.value(), dot.value(), ctx);
                if (!next)
                {
                    return comm::protocol_result<std::vector<ring_rns_poly>>::failure(next.error(), next.message());
                }
                acc = comm::protocol_result<ring_rns_poly>::success(std::move(next.value()));

                const std::uint32_t bit = (leaf >> (lacct.levels - 1u - level)) & 1u;
                parent = (bit == 0u) ? left : right;
            }

            auto neg = negate_poly(ctx, acc.value());
            if (!neg)
            {
                return comm::protocol_result<std::vector<ring_rns_poly>>::failure(neg.error(), neg.message());
            }
            out.push_back(std::move(neg.value()));
        }

        return comm::protocol_result<std::vector<ring_rns_poly>>::success(std::move(out));
    }

} // namespace loglabel

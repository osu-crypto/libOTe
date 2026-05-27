#include <cmath>
#include <cstddef>
#include <cstdint>
#include <vector>
#include "lenc_ops.hpp"
#include "lhe_ops.hpp"
#include "loglabel/shrinkexpand_backend.hpp"
#include "loglabel/shrinkexpand_noise.hpp"
#include "loglabel/shrinkexpand_spec.hpp"
#include "shrinkexpand_shared_ops.hpp"

namespace loglabel
{
    namespace
    {
        bool polys_equal(const ring_rns_poly &a, const ring_rns_poly &b)
        {
            if (a.coeffs.size() != b.coeffs.size())
            {
                return false;
            }
            for (std::size_t i = 0; i < a.coeffs.size(); ++i)
            {
                if (a.coeffs[i] != b.coeffs[i])
                {
                    return false;
                }
            }
            return true;
        }

        lenc_lacct to_lenc_lacct(const shrinkexpand_lacct &in)
        {
            lenc_lacct out{};
            out.width_padded = in.width_padded;
            out.levels = in.levels;
            out.ct = in.ct;
            return out;
        }

        double compute_sigma(const shrinkexpand_params &params, double factor)
        {
            double log_q = 0.0;
            for (int bits : params.ring.coeff_modulus_bits)
            {
                log_q += bits;
            }
            // double q = std::pow(2.0, log_q);

            // Allow flexibility for future formula changes
            double std_s = shrinkexpand_noise_params::std_s;
            double std_g = std::pow(2.0, static_cast<double>(params.gadget_log_base));
            double std_n = static_cast<double>(params.ring.poly_modulus_degree);
            (void)std_s;
            (void)std_g;
            (void)std_n;
            (void)factor;

            return 3.0 * std::pow(2.0, log_q * 0.1);
            // return 1.0;
        }

    } // namespace

    comm::protocol_result<shrinkexpand_offline_msg> shrinkexpand_seal_backend::prepare_offline_sender(
        const shrinkexpand_sender_offline_input &input, shrinkexpand_sender_state &sender_state) const
    {
        auto input_ok = validate_shrinkexpand_sender_offline_input(input);
        if (!input_ok)
        {
            return comm::protocol_result<shrinkexpand_offline_msg>::failure(input_ok.error(), input_ok.message());
        }

        auto ctx_result = make_ring_ntt_context(input.params.ring);
        if (!ctx_result)
        {
            return comm::protocol_result<shrinkexpand_offline_msg>::failure(ctx_result.error(), ctx_result.message());
        }

        const auto &ctx = ctx_result.value();

        sender_state = shrinkexpand_sender_state{};
        sender_state.params = input.params;
        auto effective_noise = resolve_shrinkexpand_effective_noise_bound(input.params);
        if (!effective_noise)
        {
            return comm::protocol_result<shrinkexpand_offline_msg>::failure(
                effective_noise.error(), effective_noise.message());
        }
        sender_state.effective_noise_bound = effective_noise.value();
        const std::int64_t encryption_noise_bound =
            (input.params.mode == shrinkexpand_mode::full_noise) ? sender_state.effective_noise_bound : 0;
        sender_state.s = input.s;
        sender_state.sk1 = sample_uniform_batch(ctx, input.params.tau, input.params.noise_seed, 0xA002u);

        double lenc_sigma = (input.params.mode == shrinkexpand_mode::full_noise)
                                ? compute_sigma(input.params, std::sqrt(static_cast<double>(input.params.tau)))
                                : 0.0;

        double lambda = shrinkexpand_noise_params::lambda;
        double lenc_max_dev =
            (input.params.mode == shrinkexpand_mode::full_noise) ? std::sqrt(lambda) * lenc_sigma : 0.0;

        auto lenc = lenc_enc(
            ctx, input.s, input.params.tau, input.params.gadget_log_base, input.params.noise_seed ^ 0x1A2B3C4Dull,
            lenc_sigma, lenc_max_dev, input.params.noise_seed ^ 0x1EC0DEC0ull);
        if (!lenc)
        {
            return comm::protocol_result<shrinkexpand_offline_msg>::failure(lenc.error(), lenc.message());
        }

        sender_state.r = lenc.value().r;
        sender_state.lacct.width_padded = lenc.value().lacct.width_padded;
        sender_state.lacct.levels = lenc.value().lacct.levels;
        sender_state.lacct.ct = std::move(lenc.value().lacct.ct);

        double lhe_sigma =
            (input.params.mode == shrinkexpand_mode::full_noise)
                ? compute_sigma(input.params, std::sqrt(static_cast<double>(sender_state.lacct.width_padded)))
                : 0.0;

        double lhe_max_dev = (input.params.mode == shrinkexpand_mode::full_noise) ? std::sqrt(lambda) * lhe_sigma : 0.0;

        auto ct1 = lhe_enc1(
            ctx, sender_state.r, sender_state.sk1, input.params.gadget_log_base, lhe_sigma, lhe_max_dev,
            input.params.noise_seed ^ 0x1A1100E5ull);
        if (!ct1)
        {
            return comm::protocol_result<shrinkexpand_offline_msg>::failure(ct1.error(), ct1.message());
        }
        sender_state.ct1 = std::move(ct1.value());

        return build_offline_message(sender_state);
    }

    comm::protocol_result<shrinkexpand_receiver_state> shrinkexpand_seal_backend::finalize_offline_receiver(
        const shrinkexpand_receiver_offline_input &input, const shrinkexpand_offline_msg &message) const
    {
        return receiver_state_from_message(input, message);
    }

    comm::protocol_result<ring_rns_poly> shrinkexpand_seal_backend::shrink(
        const shrinkexpand_receiver_state &state, const std::vector<ring_rns_poly> &x) const
    {
        if (x.size() != state.params.mu)
        {
            return comm::protocol_result<ring_rns_poly>::failure(
                comm::protocol_errc::config_error, "shrink input x size must match mu");
        }

        auto ctx_result = make_ring_ntt_context(state.params.ring);
        if (!ctx_result)
        {
            return comm::protocol_result<ring_rns_poly>::failure(ctx_result.error(), ctx_result.message());
        }

        return lenc_digest(
            ctx_result.value(), x, state.params.tau, state.params.gadget_log_base, state.lacct.width_padded);
    }

    comm::protocol_result<shrinkexpand_sender_expand_output> shrinkexpand_seal_backend::expand_sender(
        const shrinkexpand_sender_state &state, const shrinkexpand_expand_sender_input &input) const
    {
        auto ctx_result = make_ring_ntt_context(state.params.ring);
        if (!ctx_result)
        {
            return comm::protocol_result<shrinkexpand_sender_expand_output>::failure(
                ctx_result.error(), ctx_result.message());
        }

        auto tbkp_shape = validate_ring_poly_shape(input.tbk_prime, state.params.ring, "tbk_prime");
        if (!tbkp_shape)
        {
            return comm::protocol_result<shrinkexpand_sender_expand_output>::failure(
                tbkp_shape.error(), tbkp_shape.message());
        }

        auto ct2 = build_hashed_ct2(ctx_result.value(), state.params.mu, input.nonce);
        if (!ct2)
        {
            return comm::protocol_result<shrinkexpand_sender_expand_output>::failure(ct2.error(), ct2.message());
        }

        auto tbk_result = lhe_dec(ctx_result.value(), ct2.value(), input.tbk_prime);
        if (!tbk_result)
        {
            return comm::protocol_result<shrinkexpand_sender_expand_output>::failure(
                tbk_result.error(), tbk_result.message());
        }

        shrinkexpand_sender_expand_output output{};
        output.tbk = std::move(tbk_result.value());
        return comm::protocol_result<shrinkexpand_sender_expand_output>::success(std::move(output));
    }

    comm::protocol_result<shrinkexpand_receiver_expand_output> shrinkexpand_seal_backend::expand_receiver(
        const shrinkexpand_receiver_state &state, const shrinkexpand_expand_receiver_input &input) const
    {
        if (input.x.size() != state.params.mu)
        {
            return comm::protocol_result<shrinkexpand_receiver_expand_output>::failure(
                comm::protocol_errc::config_error, "receiver expand x size must match mu");
        }

        auto ctx_result = make_ring_ntt_context(state.params.ring);
        if (!ctx_result)
        {
            return comm::protocol_result<shrinkexpand_receiver_expand_output>::failure(
                ctx_result.error(), ctx_result.message());
        }

        const auto &ctx = ctx_result.value();

        auto x_shape = validate_ring_batch_shape(input.x, state.params.ring, "x");
        if (!x_shape)
        {
            return comm::protocol_result<shrinkexpand_receiver_expand_output>::failure(
                x_shape.error(), x_shape.message());
        }

        auto digest_shape = validate_ring_poly_shape(input.digest, state.params.ring, "digest");
        if (!digest_shape)
        {
            return comm::protocol_result<shrinkexpand_receiver_expand_output>::failure(
                digest_shape.error(), digest_shape.message());
        }

        auto skx_shape = validate_ring_poly_shape(input.sk_x, state.params.ring, "sk_x");
        if (!skx_shape)
        {
            return comm::protocol_result<shrinkexpand_receiver_expand_output>::failure(
                skx_shape.error(), skx_shape.message());
        }

        auto digest_recomputed =
            lenc_digest(ctx, input.x, state.params.tau, state.params.gadget_log_base, state.lacct.width_padded);
        if (!digest_recomputed)
        {
            return comm::protocol_result<shrinkexpand_receiver_expand_output>::failure(
                digest_recomputed.error(), digest_recomputed.message());
        }

        if (!polys_equal(digest_recomputed.value(), input.digest))
        {
            return comm::protocol_result<shrinkexpand_receiver_expand_output>::failure(
                comm::protocol_errc::flow_violation, "receiver expand digest mismatch with lenc.digest(x)");
        }

        auto ct2 = build_hashed_ct2(ctx, state.params.mu, input.nonce);
        if (!ct2)
        {
            return comm::protocol_result<shrinkexpand_receiver_expand_output>::failure(ct2.error(), ct2.message());
        }

        auto ct1_applied = lhe_apply_ct1(ctx, state.ct1, input.digest, state.params.gadget_log_base, state.params.tau);
        if (!ct1_applied)
        {
            return comm::protocol_result<shrinkexpand_receiver_expand_output>::failure(
                ct1_applied.error(), ct1_applied.message());
        }

        std::vector<ring_rns_poly> ct_res;
        ct_res.reserve(state.params.mu);
        for (std::size_t i = 0; i < state.params.mu; ++i)
        {
            auto c = ring_add(ct1_applied.value()[i], ct2.value()[i], ctx);
            if (!c)
            {
                return comm::protocol_result<shrinkexpand_receiver_expand_output>::failure(c.error(), c.message());
            }
            ct_res.push_back(std::move(c.value()));
        }

        auto dec_ct_res = lhe_dec(ctx, ct_res, input.sk_x);
        if (!dec_ct_res)
        {
            return comm::protocol_result<shrinkexpand_receiver_expand_output>::failure(
                dec_ct_res.error(), dec_ct_res.message());
        }

        auto eval = lenc_eval(
            ctx, to_lenc_lacct(state.lacct), input.x, state.params.mu, state.params.tau, state.params.gadget_log_base);
        if (!eval)
        {
            return comm::protocol_result<shrinkexpand_receiver_expand_output>::failure(eval.error(), eval.message());
        }

        shrinkexpand_receiver_expand_output output{};
        output.tbm.reserve(state.params.mu);

        for (std::size_t row = 0; row < state.params.mu; ++row)
        {
            auto tbm = ring_sub(dec_ct_res.value()[row], eval.value()[row], ctx);
            if (!tbm)
            {
                return comm::protocol_result<shrinkexpand_receiver_expand_output>::failure(tbm.error(), tbm.message());
            }

            output.tbm.push_back(std::move(tbm.value()));
        }

        return comm::protocol_result<shrinkexpand_receiver_expand_output>::success(std::move(output));
    }

} // namespace loglabel

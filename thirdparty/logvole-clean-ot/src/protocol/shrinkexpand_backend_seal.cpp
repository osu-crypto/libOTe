#include <atomic>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>
#include "cache_test_hooks.hpp"
#include "lenc_ops.hpp"
#include "lhe_ops.hpp"
#include "logvole/shrinkexpand_backend.hpp"
#include "logvole/shrinkexpand_noise.hpp"
#include "logvole/shrinkexpand_spec.hpp"
#include "runtime_cache_scope.hpp"
#include "shrinkexpand_shared_ops.hpp"

namespace logvole
{
    namespace
    {
        struct ct2_cache_entry
        {
            bool valid = false;
            ring_params ring{};
            std::uint32_t mu = 0;
            std::uint64_t nonce = 0;
            std::uint64_t ct2_root = 0;
            std::uint64_t run_id = 0;
            protocol_cache_role role = protocol_cache_role::unspecified;
            std::vector<ring_rns_poly> ct2{};
        };

        comm::protocol_result<std::shared_ptr<const std::vector<ring_rns_poly>>> resample_public_a_ntt(
            const ring_ntt_context &ctx, std::uint32_t mu)
        {
            if (mu == 0u)
            {
                return comm::protocol_result<std::shared_ptr<const std::vector<ring_rns_poly>>>::failure(
                    comm::protocol_errc::config_error, "shrinkexpand public a requires mu>0");
            }

            auto public_a = derive_uniform_poly_batch_from_nonce_ntt(ctx, 0xA11ACE5Eull, 0xA110CA7Aull, mu);
            auto shape_ok = validate_ring_batch_shape(public_a, ctx.params, "public_a_ntt");
            if (!shape_ok)
            {
                return comm::protocol_result<std::shared_ptr<const std::vector<ring_rns_poly>>>::failure(
                    shape_ok.error(), shape_ok.message());
            }

            return comm::protocol_result<std::shared_ptr<const std::vector<ring_rns_poly>>>::success(
                std::make_shared<const std::vector<ring_rns_poly>>(std::move(public_a)));
        }

        comm::protocol_result<std::shared_ptr<const std::vector<ring_rns_poly>>> resample_public_b_ntt(
            const ring_ntt_context &ctx, std::uint32_t tau)
        {
            if (tau == 0u)
            {
                return comm::protocol_result<std::shared_ptr<const std::vector<ring_rns_poly>>>::failure(
                    comm::protocol_errc::config_error, "shrinkexpand public b requires tau>0");
            }

            std::vector<ring_rns_poly> public_b_ntt;
            public_b_ntt.reserve(static_cast<std::size_t>(2u * tau));
            for (std::uint32_t i = 0; i < (2u * tau); ++i)
            {
                public_b_ntt.push_back(derive_uniform_poly_from_nonce_ntt(ctx, 0xC0DEC0DEull, 0x1EEC0DEu, i));
            }

            auto shape_ok = validate_ring_batch_shape(public_b_ntt, ctx.params, "public_b_ntt");
            if (!shape_ok)
            {
                return comm::protocol_result<std::shared_ptr<const std::vector<ring_rns_poly>>>::failure(
                    shape_ok.error(), shape_ok.message());
            }

            return comm::protocol_result<std::shared_ptr<const std::vector<ring_rns_poly>>>::success(
                std::make_shared<const std::vector<ring_rns_poly>>(std::move(public_b_ntt)));
        }

        bool matches_ct2_cache(
            const ct2_cache_entry &cache, const ring_params &ring, std::uint32_t mu, std::uint64_t nonce,
            std::uint64_t ct2_root, const protocol_cache_scope &scope)
        {
            return cache.valid && cache.ring == ring && cache.mu == mu && cache.nonce == nonce &&
                   cache.ct2_root == ct2_root && cache.run_id == scope.run_id && cache.role == scope.role;
        }

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
            (void)params;
            const double normalized_factor = (factor > 1.0) ? factor : 1.0;
            // Keep the flooding noise proportional to the active aggregation width instead of
            // tying it directly to q. The decode side already enforces the configured tolerance.
            return shrinkexpand_noise_params::std_s * normalized_factor;
        }

        comm::protocol_result<digest_tree> build_receiver_digest_tree(
            const ring_ntt_context &ctx, const shrinkexpand_receiver_state &state, const std::vector<ring_rns_poly> &x,
            std::uint32_t requested_workers)
        {
            const std::vector<ring_rns_poly> *public_b_ntt = state.public_b_ntt ? state.public_b_ntt.get() : nullptr;
            if (state.params.truncate_one_gadget_digit)
            {
                return build_digest_tree_trunc(
                    ctx, x, state.params.tau, state.params.gadget_log_base, state.params.plaintext_modulus_bits,
                    state.lacct.width_padded, state.params.leaf_inputs_are_gadget, public_b_ntt, requested_workers);
            }

            return build_digest_tree(
                ctx, x, state.params.tau, state.params.gadget_log_base, state.lacct.width_padded, public_b_ntt,
                requested_workers);
        }

        comm::protocol_result<std::shared_ptr<digest_tree>> ensure_receiver_digest_tree(
            const ring_ntt_context &ctx, const shrinkexpand_receiver_state &state, const std::vector<ring_rns_poly> *x,
            const ring_rns_poly &digest, const std::shared_ptr<digest_tree> &tree, std::uint32_t requested_workers)
        {
            if (tree)
            {
                return comm::protocol_result<std::shared_ptr<digest_tree>>::success(tree);
            }

            if (x == nullptr || x->size() != state.params.mu)
            {
                return comm::protocol_result<std::shared_ptr<digest_tree>>::failure(
                    comm::protocol_errc::config_error, "receiver expand x size must match mu");
            }

            auto x_shape = validate_ring_batch_shape(*x, state.params.ring, "x");
            if (!x_shape)
            {
                return comm::protocol_result<std::shared_ptr<digest_tree>>::failure(x_shape.error(), x_shape.message());
            }

            auto tree_res = build_receiver_digest_tree(ctx, state, *x, requested_workers);
            if (!tree_res)
            {
                return comm::protocol_result<std::shared_ptr<digest_tree>>::failure(
                    tree_res.error(), tree_res.message());
            }

            if (!polys_equal(tree_res.value().digest, digest))
            {
                return comm::protocol_result<std::shared_ptr<digest_tree>>::failure(
                    comm::protocol_errc::flow_violation, "receiver expand digest mismatch with lenc.digest(x)");
            }

            return comm::protocol_result<std::shared_ptr<digest_tree>>::success(
                std::make_shared<digest_tree>(std::move(tree_res.value())));
        }

        comm::protocol_result<std::vector<ring_rns_poly>> expand_receiver_chunk(
            const ring_ntt_context &ctx, const shrinkexpand_receiver_state &state, std::uint64_t nonce,
            const std::vector<ring_rns_poly> *x, const ring_rns_poly &digest, const ring_rns_poly &sk_x,
            const std::shared_ptr<digest_tree> &tree, std::uint32_t requested_workers)
        {
            auto digest_shape = validate_ring_poly_shape(digest, state.params.ring, "digest");
            if (!digest_shape)
            {
                return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                    digest_shape.error(), digest_shape.message());
            }

            auto skx_shape = validate_ring_poly_shape(sk_x, state.params.ring, "sk_x");
            if (!skx_shape)
            {
                return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                    skx_shape.error(), skx_shape.message());
            }

            auto tree_res = ensure_receiver_digest_tree(ctx, state, x, digest, tree, requested_workers);
            if (!tree_res)
            {
                return comm::protocol_result<std::vector<ring_rns_poly>>::failure(tree_res.error(), tree_res.message());
            }

            const auto scope = current_protocol_cache_scope();
            thread_local ct2_cache_entry receiver_ct2_cache{};
            if (!matches_ct2_cache(
                    receiver_ct2_cache, state.params.ring, state.params.mu, nonce, state.params.sampling_seeds.ct2_root,
                    scope))
            {
                auto ct2 = build_hashed_ct2(ctx, state.params.mu, state.params.sampling_seeds, nonce);
                if (!ct2)
                {
                    return comm::protocol_result<std::vector<ring_rns_poly>>::failure(ct2.error(), ct2.message());
                }

                receiver_ct2_cache.valid = true;
                receiver_ct2_cache.ring = state.params.ring;
                receiver_ct2_cache.mu = state.params.mu;
                receiver_ct2_cache.nonce = nonce;
                receiver_ct2_cache.ct2_root = state.params.sampling_seeds.ct2_root;
                receiver_ct2_cache.run_id = scope.run_id;
                receiver_ct2_cache.role = scope.role;
                receiver_ct2_cache.ct2 = std::move(ct2.value());
            }

            auto ct1_applied = [&]() {
                auto_timer timer(global_timing_stats.lhe_dec_time_us);
                if (state.params.truncate_one_gadget_digit)
                {
                    return lhe_apply_ct1_trunc(
                        ctx, state.ct1, digest, state.params.gadget_log_base, state.params.tau, true,
                        requested_workers);
                }

                return lhe_apply_ct1(
                    ctx, state.ct1, digest, state.params.gadget_log_base, state.params.tau, true, requested_workers);
            }();
            if (!ct1_applied)
            {
                return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                    ct1_applied.error(), ct1_applied.message());
            }

            const std::vector<ring_rns_poly> *public_a_ntt = state.public_a_ntt ? state.public_a_ntt.get() : nullptr;
            auto dec_partial_ntt_res = [&]() {
                auto_timer timer(global_timing_stats.lhe_dec_time_us);
                return lhe_dec(ctx, ct1_applied.value(), sk_x, public_a_ntt, true, true, requested_workers);
            }();
            if (!dec_partial_ntt_res)
            {
                return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                    dec_partial_ntt_res.error(), dec_partial_ntt_res.message());
            }

            auto eval_ntt_res = [&]() {
                auto_timer timer(global_timing_stats.lenc_dec_time_us);
                if (state.params.truncate_one_gadget_digit)
                {
                    return lenc_eval_trunc(
                        ctx, to_lenc_lacct(state.lacct), *tree_res.value(), state.params.mu, state.params.tau,
                        state.params.gadget_log_base, state.params.plaintext_modulus_bits, true, requested_workers,
                        state.params.leaf_inputs_are_gadget);
                }

                return lenc_eval(
                    ctx, to_lenc_lacct(state.lacct), *tree_res.value(), state.params.mu, state.params.tau,
                    state.params.gadget_log_base, true, requested_workers);
            }();
            if (!eval_ntt_res)
            {
                return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                    eval_ntt_res.error(), eval_ntt_res.message());
            }

            auto dec_partial_ntt = std::move(dec_partial_ntt_res.value());
            auto eval_ntt = std::move(eval_ntt_res.value());
            const std::size_t mu = static_cast<std::size_t>(state.params.mu);
            if (dec_partial_ntt.size() != mu || eval_ntt.size() != mu || receiver_ct2_cache.ct2.size() != mu)
            {
                return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                    comm::protocol_errc::flow_violation, "receiver expand chunk output size mismatch");
            }

            std::vector<ring_rns_poly> tbm(mu);
            for (std::size_t row = 0; row < mu; ++row)
            {
                tbm[row] = std::move(dec_partial_ntt[row]);
                auto sub_ok = ring_sub_inplace(tbm[row], eval_ntt[row], ctx);
                if (!sub_ok)
                {
                    return comm::protocol_result<std::vector<ring_rns_poly>>::failure(sub_ok.error(), sub_ok.message());
                }

                auto intt_ok = inverse_ntt_inplace(tbm[row], ctx);
                if (!intt_ok)
                {
                    return comm::protocol_result<std::vector<ring_rns_poly>>::failure(
                        intt_ok.error(), intt_ok.message());
                }

                auto add_ok = ring_add_inplace(tbm[row], receiver_ct2_cache.ct2[row], ctx);
                if (!add_ok)
                {
                    return comm::protocol_result<std::vector<ring_rns_poly>>::failure(add_ok.error(), add_ok.message());
                }
            }

            return comm::protocol_result<std::vector<ring_rns_poly>>::success(std::move(tbm));
        }

    } // namespace

    void clear_shrinkexpand_runtime_caches_for_testing()
    {
        // Caches are backend-instance local and lock-free; no global cache to clear.
    }

    comm::protocol_result<ring_ntt_context> shrinkexpand_seal_backend::get_ntt_context(const ring_params &ring) const
    {
        auto cached_ring = std::atomic_load_explicit(&cached_ring_, std::memory_order_acquire);
        auto cached_ctx = std::atomic_load_explicit(&cached_ctx_, std::memory_order_acquire);
        if (cached_ring && cached_ctx && *cached_ring == ring)
        {
            return comm::protocol_result<ring_ntt_context>::success(ring_ntt_context(*cached_ctx));
        }

        auto ctx_result = make_ring_ntt_context(ring);
        if (!ctx_result)
        {
            return ctx_result;
        }

        std::atomic_store_explicit(&cached_ring_, std::make_shared<const ring_params>(ring), std::memory_order_release);
        std::atomic_store_explicit(
            &cached_ctx_, std::make_shared<const ring_ntt_context>(ctx_result.value()), std::memory_order_release);
        return comm::protocol_result<ring_ntt_context>::success(ctx_result.value());
    }

    comm::protocol_result<shrinkexpand_offline_msg> shrinkexpand_seal_backend::prepare_offline_sender(
        const shrinkexpand_sender_offline_input &input, shrinkexpand_sender_state &sender_state) const
    {
        auto input_ok = validate_shrinkexpand_sender_offline_input(input);
        if (!input_ok)
        {
            return comm::protocol_result<shrinkexpand_offline_msg>::failure(input_ok.error(), input_ok.message());
        }

        auto ctx_result = get_ntt_context(input.params.ring);
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
        if (!input.fixed_sk1.empty())
        {
            sender_state.sk1 = input.fixed_sk1;
        }
        else
        {
            const std::uint64_t sk1_seed =
                derive_noise_seed(input.params.sampling_seeds, 0xA002u, input.params.tau, input.params.mu, 0u);
            sender_state.sk1 = sample_uniform_batch(ctx, input.params.tau, sk1_seed, 0xA002u);
        }
        const std::uint32_t public_b_tau =
            input.params.truncate_one_gadget_digit ? (input.params.tau + 1u) : input.params.tau;
        auto public_a = resample_public_a_ntt(ctx, input.params.mu);
        if (!public_a)
        {
            return comm::protocol_result<shrinkexpand_offline_msg>::failure(public_a.error(), public_a.message());
        }
        auto public_b = resample_public_b_ntt(ctx, public_b_tau);
        if (!public_b)
        {
            return comm::protocol_result<shrinkexpand_offline_msg>::failure(public_b.error(), public_b.message());
        }
        sender_state.public_a_ntt = std::move(public_a.value());
        sender_state.public_b_ntt = std::move(public_b.value());

        double lenc_sigma = (input.params.mode == shrinkexpand_mode::full_noise)
                                ? compute_sigma(input.params, std::sqrt(static_cast<double>(input.params.tau)))
                                : 0.0;

        double lambda = shrinkexpand_noise_params::lambda;
        double lenc_max_dev =
            (input.params.mode == shrinkexpand_mode::full_noise) ? std::sqrt(lambda) * lenc_sigma : 0.0;

        auto lenc = [&]() {
            auto_timer timer(global_timing_stats.lenc_enc_time_us);
            if (input.params.truncate_one_gadget_digit)
            {
                return lenc_enc_trunc(
                    ctx, input.s, input.params.tau, input.params.gadget_log_base, input.params.plaintext_modulus_bits,
                    input.params.sampling_seeds, lenc_sigma, lenc_max_dev, 0u, false,
                    input.params.leaf_inputs_are_gadget, sender_state.public_b_ntt.get(),
                    input.params.num_worker_threads);
            }

            return lenc_enc(
                ctx, input.s, input.params.tau, input.params.gadget_log_base, input.params.sampling_seeds, lenc_sigma,
                lenc_max_dev, 0u, false, sender_state.public_b_ntt.get(), input.params.num_worker_threads);
        }();

        if (!lenc)
        {
            return comm::protocol_result<shrinkexpand_offline_msg>::failure(lenc.error(), lenc.message());
        }

        auto lenc_out = std::move(lenc.value());
        sender_state.r = std::move(lenc_out.r);
        sender_state.lacct.width_padded = lenc_out.lacct.width_padded;
        sender_state.lacct.levels = lenc_out.lacct.levels;
        sender_state.lacct.ct = std::move(lenc_out.lacct.ct);

        double lhe_sigma =
            (input.params.mode == shrinkexpand_mode::full_noise)
                ? compute_sigma(input.params, std::sqrt(static_cast<double>(sender_state.lacct.width_padded)))
                : 0.0;

        double lhe_max_dev = (input.params.mode == shrinkexpand_mode::full_noise) ? std::sqrt(lambda) * lhe_sigma : 0.0;

        auto ct1 = [&]() {
            auto_timer timer(global_timing_stats.lhe_enc_time_us);
            if (input.params.truncate_one_gadget_digit)
            {
                return lhe_enc1_trunc(
                    ctx, lenc_out.r_ntt, sender_state.sk1, input.params.gadget_log_base, lhe_sigma, lhe_max_dev,
                    input.params.sampling_seeds, true, sender_state.public_a_ntt.get(),
                    input.params.num_worker_threads);
            }

            return lhe_enc1(
                ctx, lenc_out.r_ntt, sender_state.sk1, input.params.gadget_log_base, lhe_sigma, lhe_max_dev,
                input.params.sampling_seeds, true, sender_state.public_a_ntt.get(), input.params.num_worker_threads);
        }();

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
        auto receiver_state = receiver_state_from_message(input, message);
        if (!receiver_state)
        {
            return receiver_state;
        }

        auto ctx_result = get_ntt_context(input.params.ring);
        if (!ctx_result)
        {
            return comm::protocol_result<shrinkexpand_receiver_state>::failure(
                ctx_result.error(), ctx_result.message());
        }

        const std::uint32_t public_b_tau =
            input.params.truncate_one_gadget_digit ? (input.params.tau + 1u) : input.params.tau;
        auto public_a = resample_public_a_ntt(ctx_result.value(), input.params.mu);
        if (!public_a)
        {
            return comm::protocol_result<shrinkexpand_receiver_state>::failure(public_a.error(), public_a.message());
        }
        auto public_b = resample_public_b_ntt(ctx_result.value(), public_b_tau);
        if (!public_b)
        {
            return comm::protocol_result<shrinkexpand_receiver_state>::failure(public_b.error(), public_b.message());
        }
        receiver_state.value().public_a_ntt = std::move(public_a.value());
        receiver_state.value().public_b_ntt = std::move(public_b.value());
        return receiver_state;
    }

    comm::protocol_result<shrinkexpand_shrink_output> shrinkexpand_seal_backend::shrink(
        const shrinkexpand_receiver_state &state, const std::vector<ring_rns_poly> &x) const
    {
        if (x.size() != state.params.mu)
        {
            return comm::protocol_result<shrinkexpand_shrink_output>::failure(
                comm::protocol_errc::config_error, "shrink input x size must match mu");
        }

        auto_timer timer_shrink(global_timing_stats.shrink_time_us);
        const std::uint32_t worker_threads = state.params.num_worker_threads;

        auto ctx_result = get_ntt_context(state.params.ring);
        if (!ctx_result)
        {
            return comm::protocol_result<shrinkexpand_shrink_output>::failure(ctx_result.error(), ctx_result.message());
        }

        auto tree_res = build_receiver_digest_tree(ctx_result.value(), state, x, worker_threads);
        if (!tree_res)
        {
            return comm::protocol_result<shrinkexpand_shrink_output>::failure(tree_res.error(), tree_res.message());
        }

        shrinkexpand_shrink_output output{};
        output.digest = tree_res.value().digest;
        output.tree = std::make_shared<digest_tree>(std::move(tree_res.value()));
        return comm::protocol_result<shrinkexpand_shrink_output>::success(std::move(output));
    }

    comm::protocol_result<shrinkexpand_sender_expand_output> shrinkexpand_seal_backend::expand_sender(
        const shrinkexpand_sender_state &state, const shrinkexpand_expand_sender_input &input) const
    {
        auto ctx_result = get_ntt_context(state.params.ring);
        if (!ctx_result)
        {
            return comm::protocol_result<shrinkexpand_sender_expand_output>::failure(
                ctx_result.error(), ctx_result.message());
        }

        auto_timer timer_expand(global_timing_stats.expand_time_us);
        const std::uint32_t worker_threads = state.params.num_worker_threads;

        auto tbkp_shape = validate_ring_poly_shape(input.tbk_prime, state.params.ring, "tbk_prime");
        if (!tbkp_shape)
        {
            return comm::protocol_result<shrinkexpand_sender_expand_output>::failure(
                tbkp_shape.error(), tbkp_shape.message());
        }

        const auto scope = current_protocol_cache_scope();
        thread_local ct2_cache_entry sender_ct2_cache{};
        if (!matches_ct2_cache(
                sender_ct2_cache, state.params.ring, state.params.mu, input.nonce, state.params.sampling_seeds.ct2_root,
                scope))
        {
            auto ct2 = build_hashed_ct2(ctx_result.value(), state.params.mu, state.params.sampling_seeds, input.nonce);
            if (!ct2)
            {
                return comm::protocol_result<shrinkexpand_sender_expand_output>::failure(ct2.error(), ct2.message());
            }

            sender_ct2_cache.valid = true;
            sender_ct2_cache.ring = state.params.ring;
            sender_ct2_cache.mu = state.params.mu;
            sender_ct2_cache.nonce = input.nonce;
            sender_ct2_cache.ct2_root = state.params.sampling_seeds.ct2_root;
            sender_ct2_cache.run_id = scope.run_id;
            sender_ct2_cache.role = scope.role;
            sender_ct2_cache.ct2 = std::move(ct2.value());
        }

        const std::vector<ring_rns_poly> *public_a_ntt = state.public_a_ntt ? state.public_a_ntt.get() : nullptr;
        auto tbk_result = [&]() {
            auto_timer timer(global_timing_stats.lhe_dec_time_us);
            return lhe_dec(
                ctx_result.value(), sender_ct2_cache.ct2, input.tbk_prime, public_a_ntt, false, false, worker_threads);
        }();
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
        if (!input.tree && input.x.size() != state.params.mu)
        {
            return comm::protocol_result<shrinkexpand_receiver_expand_output>::failure(
                comm::protocol_errc::config_error, "receiver expand x size must match mu");
        }

        auto ctx_result = get_ntt_context(state.params.ring);
        if (!ctx_result)
        {
            return comm::protocol_result<shrinkexpand_receiver_expand_output>::failure(
                ctx_result.error(), ctx_result.message());
        }

        auto_timer timer_expand(global_timing_stats.expand_time_us);
        const std::uint32_t worker_threads = state.params.num_worker_threads;

        const auto &ctx = ctx_result.value();
        const std::vector<ring_rns_poly> *x = input.tree ? nullptr : &input.x;
        auto tbm_res =
            expand_receiver_chunk(ctx, state, input.nonce, x, input.digest, input.sk_x, input.tree, worker_threads);
        if (!tbm_res)
        {
            return comm::protocol_result<shrinkexpand_receiver_expand_output>::failure(
                tbm_res.error(), tbm_res.message());
        }

        shrinkexpand_receiver_expand_output output{};
        output.tbm = std::move(tbm_res.value());
        return comm::protocol_result<shrinkexpand_receiver_expand_output>::success(std::move(output));
    }

} // namespace logvole

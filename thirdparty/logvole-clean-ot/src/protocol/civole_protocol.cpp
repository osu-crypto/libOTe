#include "logvole/civole_protocol.hpp"
#include <algorithm>
#include <chrono>
#include <limits>
#include <memory>
#include <string>
#include "logvole/comm/byte_buffer_utils.hpp"
#include "logvole/comm/protocol_engine.hpp"
#include "logvole/comm/subchannel_wrapper.hpp"
#include "logvole/logvole_protocol.hpp"
#include "logvole/zp_crt_helpers.hpp"

namespace logvole
{
    namespace detail
    {
        struct civole_offl_msg
        {
            std::uint64_t w = 0u;
        };

        struct civole_offl_spec
        {
            using script = comm::round_script<comm::round_pair<
                comm::round_send<civole_offl_msg, comm::role_t::sender>,
                comm::round_recv<civole_offl_msg, comm::role_t::receiver>>>;
        };
    } // namespace detail

    namespace comm
    {
        template <>
        struct message_traits<logvole::detail::civole_offl_msg>
        {
            static constexpr std::uint32_t payload_type = 0x7001u;

            static protocol_result<byte_buffer> encode(const logvole::detail::civole_offl_msg &message)
            {
                byte_buffer out;
                detail::append_u64(out, message.w);
                return protocol_result<byte_buffer>::success(std::move(out));
            }

            static protocol_result<logvole::detail::civole_offl_msg> decode(const byte_buffer &payload)
            {
                std::size_t offset = 0u;
                auto w = detail::read_u64(payload, offset);
                if (!w)
                {
                    return protocol_result<logvole::detail::civole_offl_msg>::failure(w.error(), w.message());
                }
                if (offset != payload.size())
                {
                    return protocol_result<logvole::detail::civole_offl_msg>::failure(
                        protocol_errc::decode_validation_failure, "CI-VOLE offl payload has trailing bytes");
                }
                return protocol_result<logvole::detail::civole_offl_msg>::success(
                    logvole::detail::civole_offl_msg{ w.value() });
            }
        };
    } // namespace comm

    namespace
    {
        constexpr std::uint64_t k_civole_offl_metadata_session_offset = 100u;
        constexpr std::uint64_t k_civole_logvole_offline_session_offset = 1000u;
        constexpr std::uint64_t k_civole_sid_domain = 0x4349564F4C455349ull;

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

        ring_rns_poly make_zero_poly(const ring_params &ring)
        {
            ring_rns_poly zero{};
            zero.coeffs.assign(static_cast<std::size_t>(ring.poly_modulus_degree) * ring.coeff_modulus_bits.size(), 0u);
            return zero;
        }

        comm::protocol_result<std::uint32_t> compute_mu_hi(const logvole_params &params)
        {
            if (params.shrinkexpand.tau < 2u)
            {
                return comm::protocol_result<std::uint32_t>::failure(
                    comm::protocol_errc::config_error, "CI-VOLE requires shrinkexpand.tau >= 2");
            }
            const std::uint32_t rho = static_cast<std::uint32_t>(params.shrinkexpand.ring.coeff_modulus_bits.size());
            if (rho == 0u)
            {
                return comm::protocol_result<std::uint32_t>::failure(
                    comm::protocol_errc::config_error, "CI-VOLE requires non-empty coeff_modulus_bits");
            }
            const std::uint32_t tau_hi = params.shrinkexpand.tau - 1u;
            return comm::protocol_result<std::uint32_t>::success(params.shrinkexpand.alpha * tau_hi * rho);
        }

        comm::protocol_result<std::uint32_t> compute_internal_ring_width(
            const logvole_params &params, const zp_crt_context &ctx, std::size_t label_count)
        {
            if (label_count == 0u)
            {
                return comm::protocol_result<std::uint32_t>::failure(
                    comm::protocol_errc::config_error, "CI-VOLE w must be > 0");
            }

            const std::size_t packed_width = zp_ring_label_count(ctx, label_count);
            if (packed_width == 0u)
            {
                return comm::protocol_result<std::uint32_t>::failure(
                    comm::protocol_errc::config_error, "CI-VOLE packed ring width must be > 0");
            }

            auto mu_hi = compute_mu_hi(params);
            if (!mu_hi)
            {
                return comm::protocol_result<std::uint32_t>::failure(mu_hi.error(), mu_hi.message());
            }

            const std::size_t padded_width = std::max<std::size_t>(packed_width, mu_hi.value());
            if (padded_width > static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max()))
            {
                return comm::protocol_result<std::uint32_t>::failure(
                    comm::protocol_errc::config_error, "CI-VOLE packed ring width exceeds uint32_t");
            }
            return comm::protocol_result<std::uint32_t>::success(static_cast<std::uint32_t>(padded_width));
        }

        comm::protocol_result<zp_crt_context> make_context(const civole_params &params)
        {
            return make_zp_crt_context(
                params.logvole.shrinkexpand.ring, params.logvole.shrinkexpand.plaintext_modulus_bits);
        }

        sampling_seed_config derive_sid_sampling_seeds(const sampling_seed_config &base, civole_sid sid)
        {
            sampling_seed_config out = base;
            out.ct2_root = derive_deterministic_seed_material(base.ct2_root, k_civole_sid_domain, sid, 0u, 0u, 0u);
            return out;
        }

        void apply_sampling_seeds(logvole_sender_state &state, const sampling_seed_config &seeds)
        {
            state.params.shrinkexpand.sampling_seeds = seeds;
            state.shrinkexpand_state.params.sampling_seeds = seeds;
            if (state.next_level_state)
            {
                apply_sampling_seeds(*state.next_level_state, seeds);
            }
        }

        void apply_sampling_seeds(logvole_receiver_state &state, const sampling_seed_config &seeds)
        {
            state.params.shrinkexpand.sampling_seeds = seeds;
            state.shrinkexpand_state.params.sampling_seeds = seeds;
            if (state.next_level_state)
            {
                apply_sampling_seeds(*state.next_level_state, seeds);
            }
        }

        void clear_sender_cached_outputs(logvole_sender_state &state)
        {
            state.golden_seed.clear();
            state.root_k_prime_rt.reset();
            state.root_k_rt.reset();
            state.precomputed_tbk.reset();
            if (state.next_level_state)
            {
                clear_sender_cached_outputs(*state.next_level_state);
            }
        }

        void clear_receiver_cached_outputs(logvole_receiver_state &state)
        {
            state.golden_seed.clear();
            if (state.next_level_state)
            {
                clear_receiver_cached_outputs(*state.next_level_state);
            }
        }

        bool contains_sid(const std::vector<civole_sid> &sids, civole_sid sid)
        {
            return std::find(sids.begin(), sids.end(), sid) != sids.end();
        }

        comm::protocol_result<void> prepare_sender_sid_for_releasek(civole_sender_state &state, civole_sid sid)
        {
            if (contains_sid(state.used_sids, sid))
            {
                return comm::protocol_result<void>::failure(
                    comm::protocol_errc::invalid_state_transition, "CI-VOLE sender sid has already been used");
            }
            if (state.has_active_sid && state.active_sid != sid && state.key_released && !state.release_int_used)
            {
                return comm::protocol_result<void>::failure(
                    comm::protocol_errc::invalid_state_transition,
                    "CI-VOLE sender has a prior sid pending release-int");
            }
            if (state.has_active_sid && state.active_sid == sid)
            {
                return comm::protocol_result<void>::success();
            }

            clear_sender_cached_outputs(state.logvole_state);
            const auto seeds = derive_sid_sampling_seeds(state.base_sampling_seeds, sid);
            apply_sampling_seeds(state.logvole_state, seeds);
            state.has_active_sid = true;
            state.active_sid = sid;
            state.key_released = false;
            state.release_int_used = false;
            state.released_keys.clear();
            return comm::protocol_result<void>::success();
        }

        comm::protocol_result<void> prepare_receiver_sid_for_setx(civole_receiver_state &state, civole_sid sid)
        {
            if (contains_sid(state.used_sids, sid))
            {
                return comm::protocol_result<void>::failure(
                    comm::protocol_errc::invalid_state_transition, "CI-VOLE receiver sid has already been used");
            }

            state.used_sids.push_back(sid);
            clear_receiver_cached_outputs(state.logvole_state);
            const auto seeds = derive_sid_sampling_seeds(state.base_sampling_seeds, sid);
            apply_sampling_seeds(state.logvole_state, seeds);
            return comm::protocol_result<void>::success();
        }

        comm::protocol_result<void> validate_zp_values(
            const std::vector<std::uint64_t> &values, std::uint64_t modulus, const char *name)
        {
            for (std::size_t idx = 0; idx < values.size(); ++idx)
            {
                if (values[idx] >= modulus)
                {
                    return comm::protocol_result<void>::failure(
                        comm::protocol_errc::config_error,
                        std::string(name) + "[" + std::to_string(idx) + "] must be in Zp");
                }
            }
            return comm::protocol_result<void>::success();
        }
    } // namespace

    comm::protocol_result<civole_params> make_default_civole_params(std::uint32_t worker_threads)
    {
        civole_params params{};
        params.logvole.shrinkexpand.ring.poly_modulus_degree = 8192;
        params.logvole.shrinkexpand.ring.coeff_modulus_bits = { 55, 55, 55, 55 };
        params.logvole.shrinkexpand.plaintext_modulus_bits = 55;
        params.logvole.shrinkexpand.mode = shrinkexpand_mode::full_noise;
        params.logvole.shrinkexpand.sampling_seeds.noise_root = 0xBAD5EEDu;
        params.logvole.shrinkexpand.noise_bound = 2;
        params.logvole.shrinkexpand.alpha = 2;
        params.logvole.shrinkexpand.gadget_log_base = 110;
        params.logvole.shrinkexpand.num_worker_threads = worker_threads;

        std::uint32_t log_q = 0u;
        for (int bits : params.logvole.shrinkexpand.ring.coeff_modulus_bits)
        {
            log_q += static_cast<std::uint32_t>(bits);
        }
        params.logvole.shrinkexpand.tau =
            (log_q + params.logvole.shrinkexpand.gadget_log_base - 1u) / params.logvole.shrinkexpand.gadget_log_base;
        const std::uint32_t rho =
            static_cast<std::uint32_t>(params.logvole.shrinkexpand.ring.coeff_modulus_bits.size());
        params.logvole.shrinkexpand.mu = params.logvole.shrinkexpand.alpha * params.logvole.shrinkexpand.tau * rho;
        params.logvole.gamma = 1u;
        return comm::protocol_result<civole_params>::success(std::move(params));
    }

    comm::protocol_result<std::uint64_t> resolve_civole_modulus(const civole_params &params)
    {
        auto ctx = make_context(params);
        if (!ctx)
        {
            return comm::protocol_result<std::uint64_t>::failure(ctx.error(), ctx.message());
        }
        return comm::protocol_result<std::uint64_t>::success(ctx.value().plaintext_modulus);
    }

    comm::protocol_result<civole_sender_offl_output> run_civole_sender_offl(
        comm::any_channel channel, const civole_sender_offl_input &input, const logvole_backend &backend)
    {
        const auto start = std::chrono::steady_clock::now();
        if (!channel.valid())
        {
            return comm::protocol_result<civole_sender_offl_output>::failure(
                comm::protocol_errc::config_error, "channel has no implementation");
        }

        auto ctx = make_context(input.params);
        if (!ctx)
        {
            return comm::protocol_result<civole_sender_offl_output>::failure(ctx.error(), ctx.message());
        }
        if (input.delta == 0u || input.delta >= ctx.value().plaintext_modulus)
        {
            return comm::protocol_result<civole_sender_offl_output>::failure(
                comm::protocol_errc::config_error, "CI-VOLE Delta must be a non-zero Zp element");
        }

        auto ring_width = compute_internal_ring_width(input.params.logvole, ctx.value(), input.w);
        if (!ring_width)
        {
            return comm::protocol_result<civole_sender_offl_output>::failure(ring_width.error(), ring_width.message());
        }

        auto params = input.params.logvole;
        params.w = ring_width.value();
        params.total_label_count = input.w;

        auto wrapped_delta =
            wrap_zp_constant_crt(ctx.value(), input.delta, true, input.params.logvole.shrinkexpand.num_worker_threads);
        if (!wrapped_delta)
        {
            return comm::protocol_result<civole_sender_offl_output>::failure(
                wrapped_delta.error(), wrapped_delta.message());
        }

        comm::comm_counters counters{};
        const std::uint64_t session_id = channel.config().session_id;
        auto metadata_channel = comm::any_channel(std::make_unique<comm::subchannel_wrapper>(
            channel.get(), session_id + k_civole_offl_metadata_session_offset));
        comm::protocol_engine<detail::civole_offl_spec, comm::role_t::sender> metadata_engine(
            std::move(metadata_channel));
        auto metadata_ok = metadata_engine.run_with(comm::on_send<0>([&]() {
            return comm::protocol_result<detail::civole_offl_msg>::success(detail::civole_offl_msg{ input.w });
        }));
        if (!metadata_ok)
        {
            return comm::protocol_result<civole_sender_offl_output>::failure(
                metadata_ok.error(), metadata_ok.message());
        }
        accumulate_counters(counters, metadata_engine.counters());

        logvole_sender_offline_input offline_input{};
        offline_input.params = params;
        offline_input.sk1.resize(params.gamma, std::move(wrapped_delta.value()));
        auto offline_channel = comm::any_channel(std::make_unique<comm::subchannel_wrapper>(
            channel.get(), session_id + k_civole_logvole_offline_session_offset));
        auto offline = run_logvole_sender_offline(std::move(offline_channel), offline_input, backend);
        if (!offline)
        {
            return comm::protocol_result<civole_sender_offl_output>::failure(offline.error(), offline.message());
        }
        accumulate_counters(counters, offline.value().counters);

        civole_sender_offl_output out{};
        out.state.params = input.params;
        out.state.modulus = ctx.value().plaintext_modulus;
        out.state.delta = input.delta;
        out.state.w = input.w;
        out.state.ring_width = params.w;
        out.state.base_sampling_seeds = params.shrinkexpand.sampling_seeds;
        out.state.logvole_state = std::move(offline.value().state);
        out.offl.counters = counters;
        out.offl.wall_us = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start).count());
        out.counters = counters;
        return comm::protocol_result<civole_sender_offl_output>::success(std::move(out));
    }

    comm::protocol_result<civole_receiver_offl_output> run_civole_receiver_offl(
        comm::any_channel channel, const civole_receiver_offl_input &input, const logvole_backend &backend)
    {
        const auto start = std::chrono::steady_clock::now();
        if (!channel.valid())
        {
            return comm::protocol_result<civole_receiver_offl_output>::failure(
                comm::protocol_errc::config_error, "channel has no implementation");
        }

        comm::comm_counters counters{};
        const std::uint64_t session_id = channel.config().session_id;
        auto metadata_channel = comm::any_channel(std::make_unique<comm::subchannel_wrapper>(
            channel.get(), session_id + k_civole_offl_metadata_session_offset));
        comm::protocol_engine<detail::civole_offl_spec, comm::role_t::receiver> metadata_engine(
            std::move(metadata_channel));
        std::uint64_t label_count = 0u;
        auto metadata_ok = metadata_engine.run_with(
            comm::on_recv<0>([&](const detail::civole_offl_msg &message) -> comm::protocol_result<void> {
                label_count = message.w;
                return comm::protocol_result<void>::success();
            }));
        if (!metadata_ok)
        {
            return comm::protocol_result<civole_receiver_offl_output>::failure(
                metadata_ok.error(), metadata_ok.message());
        }
        accumulate_counters(counters, metadata_engine.counters());

        auto ctx = make_context(input.params);
        if (!ctx)
        {
            return comm::protocol_result<civole_receiver_offl_output>::failure(ctx.error(), ctx.message());
        }
        auto ring_width = compute_internal_ring_width(input.params.logvole, ctx.value(), label_count);
        if (!ring_width)
        {
            return comm::protocol_result<civole_receiver_offl_output>::failure(
                ring_width.error(), ring_width.message());
        }

        auto params = input.params.logvole;
        params.w = ring_width.value();
        params.total_label_count = label_count;

        logvole_receiver_offline_input offline_input{};
        offline_input.params = params;
        auto offline_channel = comm::any_channel(std::make_unique<comm::subchannel_wrapper>(
            channel.get(), session_id + k_civole_logvole_offline_session_offset));
        auto offline = run_logvole_receiver_offline(std::move(offline_channel), offline_input, backend);
        if (!offline)
        {
            return comm::protocol_result<civole_receiver_offl_output>::failure(offline.error(), offline.message());
        }
        accumulate_counters(counters, offline.value().counters);

        civole_receiver_offl_output out{};
        out.state.params = input.params;
        out.state.modulus = ctx.value().plaintext_modulus;
        out.state.w = label_count;
        out.state.ring_width = params.w;
        out.state.base_sampling_seeds = params.shrinkexpand.sampling_seeds;
        out.state.logvole_state = std::move(offline.value().state);
        out.offl.counters = counters;
        out.offl.wall_us = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start).count());
        out.counters = counters;
        return comm::protocol_result<civole_receiver_offl_output>::success(std::move(out));
    }

    comm::protocol_result<civole_releasek_output> run_civole_sender_releasek_int(
        civole_sender_state &state, civole_sid sid, const logvole_backend &backend)
    {
        const auto start = std::chrono::steady_clock::now();
        auto sid_ok = prepare_sender_sid_for_releasek(state, sid);
        if (!sid_ok)
        {
            return comm::protocol_result<civole_releasek_output>::failure(sid_ok.error(), sid_ok.message());
        }
        auto precompute = run_logvole_sender_precompute(state.logvole_state, backend);
        if (!precompute)
        {
            return comm::protocol_result<civole_releasek_output>::failure(precompute.error(), precompute.message());
        }
        if (!precompute.value().tbk)
        {
            return comm::protocol_result<civole_releasek_output>::failure(
                comm::protocol_errc::invalid_state_transition, "CI-VOLE releasek missing sender key batch");
        }

        auto ctx = make_context(state.params);
        if (!ctx)
        {
            return comm::protocol_result<civole_releasek_output>::failure(ctx.error(), ctx.message());
        }
        auto keys = unwrap_ring_labels_crt(
            ctx.value(), *precompute.value().tbk, state.w, true, state.params.logvole.shrinkexpand.num_worker_threads);
        if (!keys)
        {
            return comm::protocol_result<civole_releasek_output>::failure(keys.error(), keys.message());
        }

        state.key_released = true;
        state.used_sids.push_back(sid);
        state.released_keys = std::move(keys.value());

        civole_releasek_output out{};
        out.sid = sid;
        out.modulus = state.modulus;
        out.keys = state.released_keys;
        out.releasek.wall_us = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start).count());
        return comm::protocol_result<civole_releasek_output>::success(std::move(out));
    }

    comm::protocol_result<civole_sender_release_output> run_civole_sender_release_int(
        comm::any_channel channel, civole_sender_state &state, civole_sid sid, const logvole_backend &backend)
    {
        const auto start = std::chrono::steady_clock::now();
        if (!channel.valid())
        {
            return comm::protocol_result<civole_sender_release_output>::failure(
                comm::protocol_errc::config_error, "channel has no implementation");
        }
        if (!state.has_active_sid || state.active_sid != sid || !state.key_released)
        {
            return comm::protocol_result<civole_sender_release_output>::failure(
                comm::protocol_errc::invalid_state_transition,
                "CI-VOLE release-int requires a matching prior releasek-int");
        }
        if (state.release_int_used)
        {
            return comm::protocol_result<civole_sender_release_output>::failure(
                comm::protocol_errc::invalid_state_transition, "CI-VOLE release-int sid has already been used");
        }
        state.release_int_used = true;

        logvole_sender_online_input online_input{};
        online_input.nonce = sid;
        online_input.skip_tbk_output = true;
        auto online = run_logvole_sender_online(std::move(channel), state.logvole_state, online_input, backend);
        if (!online)
        {
            return comm::protocol_result<civole_sender_release_output>::failure(online.error(), online.message());
        }

        civole_sender_release_output out{};
        out.sid = sid;
        out.release.counters = online.value().counters;
        out.release.wall_us = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start).count());
        return comm::protocol_result<civole_sender_release_output>::success(std::move(out));
    }

    comm::protocol_result<civole_receiver_setx_output> run_civole_receiver_setx_int(
        comm::any_channel channel, civole_receiver_state &state, civole_sid sid, const std::vector<std::uint64_t> &x,
        const logvole_backend &backend)
    {
        const auto start = std::chrono::steady_clock::now();
        if (!channel.valid())
        {
            return comm::protocol_result<civole_receiver_setx_output>::failure(
                comm::protocol_errc::config_error, "channel has no implementation");
        }
        if (x.size() != state.w)
        {
            return comm::protocol_result<civole_receiver_setx_output>::failure(
                comm::protocol_errc::config_error, "CI-VOLE setx vector size must equal w from offl");
        }
        auto values_ok = validate_zp_values(x, state.modulus, "x");
        if (!values_ok)
        {
            return comm::protocol_result<civole_receiver_setx_output>::failure(values_ok.error(), values_ok.message());
        }

        auto sid_ok = prepare_receiver_sid_for_setx(state, sid);
        if (!sid_ok)
        {
            return comm::protocol_result<civole_receiver_setx_output>::failure(sid_ok.error(), sid_ok.message());
        }
        auto ctx = make_context(state.params);
        if (!ctx)
        {
            return comm::protocol_result<civole_receiver_setx_output>::failure(ctx.error(), ctx.message());
        }
        auto wrapped =
            wrap_zp_labels_crt(ctx.value(), x, false, 0u, state.params.logvole.shrinkexpand.num_worker_threads);
        if (!wrapped)
        {
            return comm::protocol_result<civole_receiver_setx_output>::failure(wrapped.error(), wrapped.message());
        }
        while (wrapped.value().size() < state.logvole_state.params.w)
        {
            wrapped.value().push_back(make_zero_poly(state.logvole_state.params.shrinkexpand.ring));
        }

        logvole_receiver_online_input online_input{};
        online_input.x = std::move(wrapped.value());
        auto online = run_logvole_receiver_online(std::move(channel), state.logvole_state, online_input, backend);
        if (!online)
        {
            return comm::protocol_result<civole_receiver_setx_output>::failure(online.error(), online.message());
        }

        auto macs = unwrap_ring_labels_crt(
            ctx.value(), online.value().tbm, state.w, true, state.params.logvole.shrinkexpand.num_worker_threads);
        if (!macs)
        {
            return comm::protocol_result<civole_receiver_setx_output>::failure(macs.error(), macs.message());
        }

        civole_receiver_setx_output out{};
        out.sid = sid;
        out.modulus = state.modulus;
        out.values = x;
        out.macs = std::move(macs.value());
        out.setx.counters = online.value().counters;
        out.setx.wall_us = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start).count());
        return comm::protocol_result<civole_receiver_setx_output>::success(std::move(out));
    }
} // namespace logvole

#include <benchmark/benchmark.h>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <thread>
#include <vector>
#include "../src/protocol/shrinkexpand_shared_ops.hpp"
#include "loglabel/ring_ops.hpp"
#include "loglabel/shrinkexpand_protocol.hpp"

namespace
{
    using namespace loglabel;
    using namespace loglabel::comm;

    struct offline_exchange_output
    {
        shrinkexpand_sender_offline_output sender{};
        shrinkexpand_receiver_offline_output receiver{};
    };

    shrinkexpand_params make_params()
    {
        shrinkexpand_params params{};
        params.ring.poly_modulus_degree = 16384;
        params.ring.coeff_modulus_bits = { 54, 54, 54, 54, 54, 54, 54 };
        params.plaintext_modulus_bits = 54;
        params.alpha = 2;
        params.mu = 3;
        params.tau = 3;
        params.gadget_log_base = 126;
        params.mode = shrinkexpand_mode::deterministic;
        params.noise_seed = 0x12345678u;
        params.noise_bound = 2;
        return params;
    }

    std::vector<ring_rns_poly> sample_batch(const ring_ntt_context &ctx, std::uint32_t count, std::uint64_t seed)
    {
        std::vector<ring_rns_poly> out;
        out.reserve(count);
        for (std::uint32_t i = 0; i < count; ++i)
        {
            out.push_back(derive_uniform_poly_from_nonce(ctx, seed, 0xAAA0u, i));
        }
        return out;
    }

    ring_rns_poly sample_scalar_poly(const ring_ntt_context &ctx, std::uint64_t seed)
    {
        return derive_uniform_poly_from_nonce(ctx, seed, 0xAAA0u, 0u);
    }

    std::int64_t effective_noise_bound(const shrinkexpand_params &params)
    {
        if (params.mode != shrinkexpand_mode::full_noise)
        {
            return params.noise_bound;
        }

        std::uint32_t log_q = 0u;
        for (int bits : params.ring.coeff_modulus_bits)
        {
            log_q += static_cast<std::uint32_t>(bits);
        }

        const long double base = std::pow(2.0L, 0.1L * static_cast<long double>(log_q));
        const std::int64_t floor = static_cast<std::int64_t>(std::ceil(base));
        const std::int64_t base_floor = (floor > 0) ? floor : 1;
        return (params.noise_bound > base_floor) ? params.noise_bound : base_floor;
    }

    protocol_result<ring_rns_poly> build_sk_x(
        const shrinkexpand_sender_state &sender_state, const ring_rns_poly &digest, const ring_rns_poly &tbk_prime)
    {
        auto ctx_result = make_ring_ntt_context(sender_state.params.ring);
        if (!ctx_result)
        {
            return protocol_result<ring_rns_poly>::failure(ctx_result.error(), ctx_result.message());
        }
        const auto &ctx = ctx_result.value();

        auto u = gadget_decompose_bits(digest, sender_state.params.gadget_log_base, sender_state.params.tau, ctx);
        if (!u)
        {
            return protocol_result<ring_rns_poly>::failure(u.error(), u.message());
        }

        ring_rns_poly out = tbk_prime;
        for (std::size_t i = 0; i < sender_state.params.tau; ++i)
        {
            auto sk1u = ring_multiply(sender_state.sk1[i], u.value()[i], ctx);
            if (!sk1u)
            {
                return protocol_result<ring_rns_poly>::failure(sk1u.error(), sk1u.message());
            }

            auto key = ring_add(sk1u.value(), out, ctx);
            if (!key)
            {
                return protocol_result<ring_rns_poly>::failure(key.error(), key.message());
            }
            out = std::move(key.value());
        }

        return protocol_result<ring_rns_poly>::success(std::move(out));
    }

    protocol_result<offline_exchange_output> run_offline_once(
        std::uint64_t protocol_id, std::uint64_t version, std::uint64_t session_id, std::chrono::milliseconds timeout,
        const shrinkexpand_sender_offline_input &sender_input,
        const shrinkexpand_receiver_offline_input &receiver_input, const shrinkexpand_seal_backend &backend)
    {
        auto pair_result = make_in_memory_channel_pair(protocol_id, version, session_id, timeout);
        if (!pair_result)
        {
            return protocol_result<offline_exchange_output>::failure(pair_result.error(), pair_result.message());
        }

        auto channels = std::move(pair_result.value());
        any_channel sender_channel = std::move(channels.first);
        any_channel receiver_channel = std::move(channels.second);

        protocol_result<shrinkexpand_sender_offline_output> sender_offline =
            protocol_result<shrinkexpand_sender_offline_output>::failure(protocol_errc::io_error, "not run");
        protocol_result<shrinkexpand_receiver_offline_output> receiver_offline =
            protocol_result<shrinkexpand_receiver_offline_output>::failure(protocol_errc::io_error, "not run");

        std::thread receiver_thread([&]() mutable {
            receiver_offline = run_shrinkexpand_receiver(std::move(receiver_channel), receiver_input, backend);
        });

        std::thread sender_thread([&]() mutable {
            sender_offline = run_shrinkexpand_sender(std::move(sender_channel), sender_input, backend);
        });

        sender_thread.join();
        receiver_thread.join();

        if (!sender_offline)
        {
            return protocol_result<offline_exchange_output>::failure(sender_offline.error(), sender_offline.message());
        }
        if (!receiver_offline)
        {
            return protocol_result<offline_exchange_output>::failure(
                receiver_offline.error(), receiver_offline.message());
        }

        offline_exchange_output output{};
        output.sender = std::move(sender_offline.value());
        output.receiver = std::move(receiver_offline.value());
        return protocol_result<offline_exchange_output>::success(std::move(output));
    }

    void set_common_param_counters(benchmark::State &state, const shrinkexpand_params &params)
    {
        state.counters["ring_n"] = params.ring.poly_modulus_degree;
        state.counters["log_p"] = params.plaintext_modulus_bits;
        state.counters["alpha"] = params.alpha;
        state.counters["mu"] = params.mu;
        state.counters["tau"] = params.tau;
        state.counters["gadget_log_base"] = params.gadget_log_base;
    }

    void finalize_timing_counters(
        benchmark::State &state, std::uint64_t total_bytes_s2r, std::uint64_t total_bytes_r2s,
        std::uint64_t total_rounds, std::chrono::steady_clock::time_point wall_start)
    {
        const auto wall_elapsed_us =
            std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - wall_start);

        const double iterations = static_cast<double>(state.iterations());
        const double total_wall_ms = static_cast<double>(wall_elapsed_us.count()) / 1000.0;
        const double avg_wall_ms = total_wall_ms / iterations;

        state.counters["bytes_s2r"] = total_bytes_s2r / iterations;
        state.counters["bytes_r2s"] = total_bytes_r2s / iterations;
        state.counters["bits_s2r"] = (total_bytes_s2r * 8.0) / iterations;
        state.counters["bits_r2s"] = (total_bytes_r2s * 8.0) / iterations;
        state.counters["round_count"] = total_rounds / iterations;
        state.counters["avg_wall_ms"] = avg_wall_ms;
        state.counters["total_wall_ms"] = total_wall_ms;
        state.counters["instances_per_sec"] =
            benchmark::Counter(static_cast<double>(state.iterations()), benchmark::Counter::kIsRate);
    }

    void bench_shrinkexpand_offline_online(benchmark::State &state)
    {
        constexpr std::uint64_t protocol_id = 0x7001u;
        constexpr std::uint64_t version = 1u;
        constexpr std::uint64_t seed_s = 0x1111u;
        constexpr std::uint64_t seed_x = 0x2222u;
        constexpr std::uint64_t seed_tbk_prime = 0x3333u;
        constexpr std::uint64_t nonce_base = 0xCAFEu;

        const auto params = make_params();
        auto ctx_result = make_ring_ntt_context(params.ring);
        if (!ctx_result)
        {
            state.SkipWithError(ctx_result.message().c_str());
            return;
        }
        const auto &ctx = ctx_result.value();

        shrinkexpand_sender_offline_input sender_input{};
        sender_input.params = params;
        sender_input.s = sample_batch(ctx, params.mu, seed_s);

        shrinkexpand_receiver_offline_input receiver_input{};
        receiver_input.params = params;

        const auto x = sample_batch(ctx, params.mu, seed_x);
        const auto tbk_prime = sample_scalar_poly(ctx, seed_tbk_prime);

        shrinkexpand_seal_backend backend{};

        std::uint64_t total_bytes_s2r = 0;
        std::uint64_t total_bytes_r2s = 0;
        std::uint64_t total_rounds = 0;
        std::uint64_t iter = 0;

        const auto wall_start = std::chrono::steady_clock::now();

        for (auto _ : state)
        {
            (void)_;

            const auto offline = run_offline_once(
                protocol_id, version, 1000u + iter, std::chrono::milliseconds(2000), sender_input, receiver_input,
                backend);
            if (!offline)
            {
                state.SkipWithError(offline.message().c_str());
                return;
            }

            auto digest = shrinkexpand_shrink(offline.value().receiver.state, x, backend);
            if (!digest)
            {
                state.SkipWithError(digest.message().c_str());
                return;
            }

            auto sk_x = build_sk_x(offline.value().sender.state, digest.value(), tbk_prime);
            if (!sk_x)
            {
                state.SkipWithError(sk_x.message().c_str());
                return;
            }

            shrinkexpand_expand_sender_input sender_expand_input{};
            sender_expand_input.nonce = nonce_base + iter;
            sender_expand_input.tbk_prime = tbk_prime;

            shrinkexpand_expand_receiver_input receiver_expand_input{};
            receiver_expand_input.nonce = sender_expand_input.nonce;
            receiver_expand_input.x = x;
            receiver_expand_input.digest = digest.value();
            receiver_expand_input.sk_x = sk_x.value();

            auto sender_expand = shrinkexpand_expand_sender(offline.value().sender.state, sender_expand_input, backend);
            if (!sender_expand)
            {
                state.SkipWithError(sender_expand.message().c_str());
                return;
            }

            auto receiver_expand =
                shrinkexpand_expand_receiver(offline.value().receiver.state, receiver_expand_input, backend);
            if (!receiver_expand)
            {
                state.SkipWithError(receiver_expand.message().c_str());
                return;
            }

            benchmark::DoNotOptimize(sender_expand.value().tbk);
            benchmark::DoNotOptimize(receiver_expand.value().tbm);

            total_bytes_s2r += offline.value().sender.counters.wire_bytes_s2r_sent;
            total_bytes_r2s += offline.value().sender.counters.wire_bytes_r2s_sent;
            total_rounds += offline.value().sender.counters.rounds_completed;
            ++iter;
        }

        finalize_timing_counters(state, total_bytes_s2r, total_bytes_r2s, total_rounds, wall_start);
        set_common_param_counters(state, params);
    }

    void bench_shrinkexpand_offline_only(benchmark::State &state)
    {
        constexpr std::uint64_t protocol_id = 0x7002u;
        constexpr std::uint64_t version = 1u;
        constexpr std::uint64_t seed_s = 0x1111u;

        const auto params = make_params();
        auto ctx_result = make_ring_ntt_context(params.ring);
        if (!ctx_result)
        {
            state.SkipWithError(ctx_result.message().c_str());
            return;
        }
        const auto &ctx = ctx_result.value();

        shrinkexpand_sender_offline_input sender_input{};
        sender_input.params = params;
        sender_input.s = sample_batch(ctx, params.mu, seed_s);

        shrinkexpand_receiver_offline_input receiver_input{};
        receiver_input.params = params;

        shrinkexpand_seal_backend backend{};

        std::uint64_t total_bytes_s2r = 0;
        std::uint64_t total_bytes_r2s = 0;
        std::uint64_t total_rounds = 0;
        std::uint64_t iter = 0;

        const auto wall_start = std::chrono::steady_clock::now();

        for (auto _ : state)
        {
            (void)_;

            const auto offline = run_offline_once(
                protocol_id, version, 2000u + iter, std::chrono::milliseconds(2000), sender_input, receiver_input,
                backend);
            if (!offline)
            {
                state.SkipWithError(offline.message().c_str());
                return;
            }

            benchmark::DoNotOptimize(offline.value().sender.state.ct1);
            benchmark::DoNotOptimize(offline.value().receiver.state.ct1);

            total_bytes_s2r += offline.value().sender.counters.wire_bytes_s2r_sent;
            total_bytes_r2s += offline.value().sender.counters.wire_bytes_r2s_sent;
            total_rounds += offline.value().sender.counters.rounds_completed;
            ++iter;
        }

        finalize_timing_counters(state, total_bytes_s2r, total_bytes_r2s, total_rounds, wall_start);
        set_common_param_counters(state, params);
    }

    void bench_shrinkexpand_online_only(benchmark::State &state)
    {
        constexpr std::uint64_t protocol_id = 0x7003u;
        constexpr std::uint64_t version = 1u;
        constexpr std::uint64_t seed_s = 0x1111u;
        constexpr std::uint64_t seed_x = 0x2222u;
        constexpr std::uint64_t seed_tbk_prime = 0x3333u;
        constexpr std::uint64_t nonce_base = 0xCAFEu;

        const auto params = make_params();
        auto ctx_result = make_ring_ntt_context(params.ring);
        if (!ctx_result)
        {
            state.SkipWithError(ctx_result.message().c_str());
            return;
        }
        const auto &ctx = ctx_result.value();

        shrinkexpand_sender_offline_input sender_input{};
        sender_input.params = params;
        sender_input.s = sample_batch(ctx, params.mu, seed_s);

        shrinkexpand_receiver_offline_input receiver_input{};
        receiver_input.params = params;

        const auto x = sample_batch(ctx, params.mu, seed_x);
        const auto tbk_prime = sample_scalar_poly(ctx, seed_tbk_prime);

        shrinkexpand_seal_backend backend{};

        const auto offline = run_offline_once(
            protocol_id, version, 3000u, std::chrono::milliseconds(2000), sender_input, receiver_input, backend);
        if (!offline)
        {
            state.SkipWithError(offline.message().c_str());
            return;
        }

        const auto &sender_state = offline.value().sender.state;
        const auto &receiver_state = offline.value().receiver.state;

        std::uint64_t iter = 0;
        const auto wall_start = std::chrono::steady_clock::now();

        for (auto _ : state)
        {
            (void)_;

            auto digest = shrinkexpand_shrink(receiver_state, x, backend);
            if (!digest)
            {
                state.SkipWithError(digest.message().c_str());
                return;
            }

            auto sk_x = build_sk_x(sender_state, digest.value(), tbk_prime);
            if (!sk_x)
            {
                state.SkipWithError(sk_x.message().c_str());
                return;
            }

            shrinkexpand_expand_sender_input sender_expand_input{};
            sender_expand_input.nonce = nonce_base + iter;
            sender_expand_input.tbk_prime = tbk_prime;

            shrinkexpand_expand_receiver_input receiver_expand_input{};
            receiver_expand_input.nonce = sender_expand_input.nonce;
            receiver_expand_input.x = x;
            receiver_expand_input.digest = digest.value();
            receiver_expand_input.sk_x = sk_x.value();

            auto sender_expand = shrinkexpand_expand_sender(sender_state, sender_expand_input, backend);
            if (!sender_expand)
            {
                state.SkipWithError(sender_expand.message().c_str());
                return;
            }

            auto receiver_expand = shrinkexpand_expand_receiver(receiver_state, receiver_expand_input, backend);
            if (!receiver_expand)
            {
                state.SkipWithError(receiver_expand.message().c_str());
                return;
            }

            benchmark::DoNotOptimize(sender_expand.value().tbk);
            benchmark::DoNotOptimize(receiver_expand.value().tbm);
            ++iter;
        }

        finalize_timing_counters(state, 0u, 0u, 0u, wall_start);
        set_common_param_counters(state, params);
    }

    void bench_shrinkexpand_denoise_comb(benchmark::State &state)
    {
        const auto params = make_params();
        auto ctx_result = make_ring_ntt_context(params.ring);
        if (!ctx_result)
        {
            state.SkipWithError(ctx_result.message().c_str());
            return;
        }
        const auto &ctx = ctx_result.value();

        const std::size_t n = params.ring.poly_modulus_degree;
        const std::size_t rho = params.ring.coeff_modulus_bits.size();
        const std::size_t w_prime = params.alpha * params.tau;

        std::vector<ring_rns_poly> tba_prime;
        tba_prime.reserve(w_prime * rho);
        for (std::size_t i = 0; i < w_prime * rho; ++i)
        {
            ring_rns_poly poly;
            poly.coeffs.resize(n * rho, 1ULL);
            tba_prime.push_back(std::move(poly));
        }

        const auto wall_start = std::chrono::steady_clock::now();

        for (auto _ : state)
        {
            auto out = shrinkexpand_denoise_comb(ctx, tba_prime);
            if (!out)
            {
                state.SkipWithError(out.message().c_str());
                return;
            }
            benchmark::DoNotOptimize(out.value());
        }

        finalize_timing_counters(state, 0u, 0u, 0u, wall_start);
        set_common_param_counters(state, params);
    }

    BENCHMARK(bench_shrinkexpand_offline_online)->Name("ShrinkExpandOfflineOnline")->Unit(benchmark::kMillisecond);

    BENCHMARK(bench_shrinkexpand_offline_only)->Name("ShrinkExpandOfflineOnly")->Unit(benchmark::kMillisecond);

    BENCHMARK(bench_shrinkexpand_online_only)->Name("ShrinkExpandOnlineOnly")->Unit(benchmark::kMillisecond);

    BENCHMARK(bench_shrinkexpand_denoise_comb)->Name("ShrinkExpandDenoiseComb")->Unit(benchmark::kMillisecond);

} // namespace

BENCHMARK_MAIN();

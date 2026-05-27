#include "loglabel/ring_ops.hpp"

#include "../src/protocol/lenc_ops.hpp"

#include <benchmark/benchmark.h>

#include <cstddef>
#include <cstdint>
#include <vector>

namespace
{
    using namespace loglabel;

    struct lenc_bench_params
    {
        ring_params ring{};
        std::uint32_t mu = 3;
        std::uint32_t tau = 3;
        std::uint32_t gadget_log_base = 126;
    };

    lenc_bench_params make_params()
    {
        lenc_bench_params p{};
        p.ring.poly_modulus_degree = 16384;
        p.ring.coeff_modulus_bits = { 54, 54, 54, 54, 54, 54, 54 };
        return p;
    }

    std::vector<ring_rns_poly> sample_batch(const ring_ntt_context &ctx, std::uint32_t count, std::uint64_t seed)
    {
        std::vector<ring_rns_poly> out;
        out.reserve(count);
        for (std::uint32_t i = 0; i < count; ++i)
        {
            out.push_back(derive_uniform_poly_from_nonce(ctx, seed, 0x1E2C0002u, i));
        }
        return out;
    }

    void bench_lenc_enc_digest_eval(benchmark::State &state)
    {
        constexpr std::uint64_t seed_s = 0x1111u;
        constexpr std::uint64_t seed_x = 0x2222u;
        constexpr std::uint64_t seed_enc = 0x3333u;

        const auto params = make_params();
        auto ctx_result = make_ring_ntt_context(params.ring);
        if (!ctx_result)
        {
            state.SkipWithError(ctx_result.message().c_str());
            return;
        }
        const auto &ctx = ctx_result.value();

        auto s = sample_batch(ctx, params.mu, seed_s);
        auto x = sample_batch(ctx, params.mu, seed_x);

        for (auto _ : state)
        {
            (void)_;

            auto enc = lenc_enc(ctx, s, params.tau, params.gadget_log_base, seed_enc);
            if (!enc)
            {
                state.SkipWithError(enc.message().c_str());
                return;
            }

            auto digest = lenc_digest(ctx, x, params.tau, params.gadget_log_base, enc.value().lacct.width_padded);
            if (!digest)
            {
                state.SkipWithError(digest.message().c_str());
                return;
            }

            auto eval = lenc_eval(ctx, enc.value().lacct, x, params.mu, params.tau, params.gadget_log_base);
            if (!eval)
            {
                state.SkipWithError(eval.message().c_str());
                return;
            }

            benchmark::DoNotOptimize(digest.value());
            benchmark::DoNotOptimize(eval.value());
        }

        state.counters["ring_n"] = params.ring.poly_modulus_degree;
        state.counters["log_p"] = 54;
        state.counters["mu"] = params.mu;
        state.counters["tau"] = params.tau;
        state.counters["gadget_log_base"] = params.gadget_log_base;
    }

    BENCHMARK(bench_lenc_enc_digest_eval)
        ->Name("LencEncDigestEval")
        ->Unit(benchmark::kMillisecond);

} // namespace

BENCHMARK_MAIN();

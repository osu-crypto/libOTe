#include "loglabel/keyderive_protocol.hpp"

#include "loglabel/comm/envelope.hpp"
#include "seal/seal.h"

#include <benchmark/benchmark.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <random>
#include <thread>
#include <vector>

namespace
{
    using namespace loglabel;
    using namespace loglabel::comm;

    keyderive_params make_bench_params()
    {
        keyderive_params params{};
        params.poly_modulus_degree = 1024;
        params.coeff_modulus_bits = { 30, 30 };
        return params;
    }

    std::vector<seal::Modulus> make_moduli(const keyderive_params &params)
    {
        return seal::CoeffModulus::Create(params.poly_modulus_degree, params.coeff_modulus_bits);
    }

    std::vector<ring_rns_poly> sample_ring_batch(
        std::size_t tau, const keyderive_params &params, const std::vector<seal::Modulus> &moduli,
        std::uint64_t seed)
    {
        std::mt19937_64 rng(seed);
        const std::size_t n = params.poly_modulus_degree;
        const std::size_t mod_count = moduli.size();

        std::vector<ring_rns_poly> out;
        out.reserve(tau);

        for (std::size_t t = 0; t < tau; ++t)
        {
            ring_rns_poly poly{};
            poly.coeffs.resize(n * mod_count);
            for (std::size_t mod_idx = 0; mod_idx < mod_count; ++mod_idx)
            {
                const auto mod = moduli[mod_idx].value();
                std::uniform_int_distribution<std::uint64_t> dist(0, mod - 1u);
                const std::size_t offset = mod_idx * n;
                for (std::size_t i = 0; i < n; ++i)
                {
                    poly.coeffs[offset + i] = dist(rng);
                }
            }
            out.push_back(std::move(poly));
        }

        return out;
    }

    void bench_keyderive_e2e(benchmark::State &state)
    {
        const auto params = make_bench_params();
        const auto moduli = make_moduli(params);
        const std::size_t tau = 3;
        const std::size_t payload_elems = tau * params.poly_modulus_degree * params.coeff_modulus_bits.size();
        const std::uint64_t request_payload = 4u * sizeof(std::uint32_t) + payload_elems * sizeof(std::uint64_t);
        const std::uint64_t response_payload = 4u * sizeof(std::uint32_t) + payload_elems * sizeof(std::uint64_t);

        keyderive_sender_input sender_input{};
        sender_input.params = params;
        sender_input.sk1 = sample_ring_batch(tau, params, moduli, 0x1111u);
        sender_input.sk2 = sample_ring_batch(tau, params, moduli, 0x2222u);

        keyderive_receiver_input receiver_input{};
        receiver_input.params = params;
        receiver_input.d = sample_ring_batch(tau, params, moduli, 0x3333u);

        keyderive_seal_ntt_backend backend{};

        std::uint64_t total_bytes_s2r = 0;
        std::uint64_t total_bytes_r2s = 0;
        std::uint64_t total_rounds = 0;
        const auto wall_start = std::chrono::steady_clock::now();

        for (auto _ : state)
        {
            (void)_;
            auto pair_result = make_in_memory_channel_pair(
                /*protocol_id=*/0x4B44u, /*version=*/1u,
                /*session_id=*/static_cast<std::uint64_t>(state.iterations() + 1000),
                std::chrono::milliseconds(2000));
            if (!pair_result)
            {
                state.SkipWithError(pair_result.message().c_str());
                return;
            }

            auto channels = std::move(pair_result.value());
            any_channel sender_channel = std::move(channels.first);
            any_channel receiver_channel = std::move(channels.second);

            protocol_result<keyderive_sender_output> sender_result =
                protocol_result<keyderive_sender_output>::failure(protocol_errc::io_error, "not run");
            protocol_result<keyderive_receiver_output> receiver_result =
                protocol_result<keyderive_receiver_output>::failure(protocol_errc::io_error, "not run");

            std::thread receiver_thread(
                [ch = std::move(receiver_channel), &receiver_result, &receiver_input, &backend]() mutable {
                    receiver_result = run_keyderive_receiver(std::move(ch), receiver_input, backend);
                });

            std::thread sender_thread(
                [ch = std::move(sender_channel), &sender_result, &sender_input, &backend]() mutable {
                    sender_result = run_keyderive_sender(std::move(ch), sender_input, backend);
                });

            sender_thread.join();
            receiver_thread.join();

            if (!sender_result)
            {
                state.SkipWithError(sender_result.message().c_str());
                return;
            }

            if (!receiver_result)
            {
                state.SkipWithError(receiver_result.message().c_str());
                return;
            }

            total_bytes_s2r += envelope_wire_size + response_payload;
            total_bytes_r2s += envelope_wire_size + request_payload;
            total_rounds += 2u;
        }

        const auto wall_elapsed_us = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - wall_start);
        const double iterations = static_cast<double>(state.iterations());
        const double total_wall_ms = static_cast<double>(wall_elapsed_us.count()) / 1000.0;
        const double avg_wall_ms = total_wall_ms / iterations;

        state.counters["bytes_s2r"] = total_bytes_s2r / iterations;
        state.counters["bytes_r2s"] = total_bytes_r2s / iterations;
        state.counters["bits_s2r"] = (total_bytes_s2r * 8.0) / iterations;
        state.counters["bits_r2s"] = (total_bytes_r2s * 8.0) / iterations;
        state.counters["round_count"] = total_rounds / iterations;
        state.counters["poly_modulus_degree"] = static_cast<double>(params.poly_modulus_degree);
        state.counters["coeff_mod_count"] = static_cast<double>(params.coeff_modulus_bits.size());
        state.counters["tau"] = static_cast<double>(tau);
        state.counters["avg_wall_ms"] = avg_wall_ms;
        state.counters["total_wall_ms"] = total_wall_ms;
        state.counters["instances_per_sec"] = benchmark::Counter(
            static_cast<double>(state.iterations()), benchmark::Counter::kIsRate);
    }

    BENCHMARK(bench_keyderive_e2e)->Name("KeyderiveE2E")->Unit(benchmark::kMillisecond);

} // namespace

BENCHMARK_MAIN();

#include <algorithm>
#include <benchmark/benchmark.h>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <limits>
#include <string>
#include <thread>
#include <vector>
#include "logvole/civole_protocol.hpp"

using namespace logvole;
using namespace logvole::comm;

namespace
{
#if !defined(LOGVOLE_HEXL_ENABLED)
#define LOGVOLE_HEXL_ENABLED 0
#endif

#if !defined(LOGVOLE_HEXL_ISA)
#define LOGVOLE_HEXL_ISA "unknown"
#endif

    std::uint32_t parse_worker_threads_env(std::uint32_t default_value)
    {
        const char *raw = std::getenv("LOGVOLE_BENCH_WORKER_THREADS");
        if (!raw || !*raw)
        {
            raw = std::getenv("LOGVOLE_BENCH_SENDER_THREADS");
        }
        if (!raw || !*raw)
        {
            return default_value;
        }

        errno = 0;
        char *end = nullptr;
        const unsigned long parsed = std::strtoul(raw, &end, 10);
        if (errno != 0 || end == raw || *end != '\0' ||
            parsed > static_cast<unsigned long>(std::numeric_limits<std::uint32_t>::max()))
        {
            return default_value;
        }
        return static_cast<std::uint32_t>(parsed);
    }

    std::uint64_t parse_benchmark_iterations_env(std::uint64_t default_value)
    {
        const char *raw = std::getenv("LOGVOLE_BENCH_ITERATIONS");
        if (!raw || !*raw)
        {
            return default_value;
        }

        errno = 0;
        char *end = nullptr;
        const unsigned long long parsed = std::strtoull(raw, &end, 10);
        if (errno != 0 || end == raw || *end != '\0' || parsed == 0ull ||
            parsed > static_cast<unsigned long long>(std::numeric_limits<std::int64_t>::max()))
        {
            return default_value;
        }
        return static_cast<std::uint64_t>(parsed);
    }

    void add_counters(comm_counters &dst, const comm_counters &src)
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

    std::string build_label()
    {
        std::string label = "HEXL=";
        label += LOGVOLE_HEXL_ENABLED ? "ON" : "OFF";
        label += ", ISA=";
        label += LOGVOLE_HEXL_ISA;
        return label;
    }

    std::vector<std::uint64_t> make_values(std::size_t count, std::uint64_t modulus)
    {
        std::vector<std::uint64_t> values(count);
        for (std::size_t i = 0; i < count; ++i)
        {
            values[i] = static_cast<std::uint64_t>((3u * i + 11u) % modulus);
        }
        return values;
    }
} // namespace

static void run_public_civole_bench(benchmark::State &state, std::size_t label_count, std::uint32_t default_threads = 1u)
{
    state.SetLabel(build_label());
    const std::uint32_t worker_threads = parse_worker_threads_env(default_threads);
    auto params_result = make_default_civole_params(worker_threads);
    if (!params_result)
    {
        state.SkipWithError(params_result.message().c_str());
        return;
    }
    civole_params params = std::move(params_result.value());

    auto modulus_result = resolve_civole_modulus(params);
    if (!modulus_result)
    {
        state.SkipWithError(modulus_result.message().c_str());
        return;
    }
    const std::uint64_t modulus = modulus_result.value();
    const std::uint64_t delta = 17u % modulus;
    const auto x = make_values(label_count, modulus);

    std::uint64_t session_id = 0xB000u;
    std::uint64_t total_offl_sender_us = 0u;
    std::uint64_t total_offl_receiver_us = 0u;
    std::uint64_t total_releasek_us = 0u;
    std::uint64_t total_release_sender_us = 0u;
    std::uint64_t total_setx_receiver_us = 0u;
    comm_counters total_counters{};
    comm_counters total_offl_counters{};
    comm_counters total_online_counters{};
    std::uint32_t ring_width = 0u;

    for (auto _ : state)
    {
        auto offl_channels =
            make_in_memory_channel_pair(0xC170u, 1u, session_id++, std::chrono::milliseconds(600000));
        if (!offl_channels)
        {
            state.SkipWithError(offl_channels.message().c_str());
            return;
        }

        auto pair = std::move(offl_channels.value());
        logvole_seal_backend sender_backend{};
        logvole_seal_backend receiver_backend{};
        auto sender_offl =
            protocol_result<civole_sender_offl_output>::failure(protocol_errc::io_error, "not run");
        auto receiver_offl =
            protocol_result<civole_receiver_offl_output>::failure(protocol_errc::io_error, "not run");

        std::thread receiver_offl_thread([&]() mutable {
            civole_receiver_offl_input input{};
            input.params = params;
            receiver_offl = run_civole_receiver_offl(std::move(pair.second), input, receiver_backend);
        });
        std::thread sender_offl_thread([&]() mutable {
            civole_sender_offl_input input{};
            input.params = params;
            input.delta = delta;
            input.w = label_count;
            sender_offl = run_civole_sender_offl(std::move(pair.first), input, sender_backend);
        });
        sender_offl_thread.join();
        receiver_offl_thread.join();
        if (!sender_offl || !receiver_offl)
        {
            const std::string err = sender_offl.message() + " / " + receiver_offl.message();
            state.SkipWithError(err.c_str());
            return;
        }

        constexpr civole_sid sid = 1u;
        auto releasek = run_civole_sender_releasek_int(sender_offl.value().state, sid, sender_backend);
        if (!releasek)
        {
            state.SkipWithError(releasek.message().c_str());
            return;
        }

        auto online_channels =
            make_in_memory_channel_pair(0xC170u, 1u, session_id++, std::chrono::milliseconds(600000));
        if (!online_channels)
        {
            state.SkipWithError(online_channels.message().c_str());
            return;
        }
        auto online_pair = std::move(online_channels.value());
        auto sender_release =
            protocol_result<civole_sender_release_output>::failure(protocol_errc::io_error, "not run");
        auto receiver_setx =
            protocol_result<civole_receiver_setx_output>::failure(protocol_errc::io_error, "not run");

        std::thread receiver_online_thread([&]() mutable {
            receiver_setx = run_civole_receiver_setx_int(
                std::move(online_pair.second), receiver_offl.value().state, sid, x, receiver_backend);
        });
        std::thread sender_online_thread([&]() mutable {
            sender_release = run_civole_sender_release_int(
                std::move(online_pair.first), sender_offl.value().state, sid, sender_backend);
        });
        sender_online_thread.join();
        receiver_online_thread.join();
        if (!sender_release || !receiver_setx)
        {
            const std::string err = sender_release.message() + " / " + receiver_setx.message();
            state.SkipWithError(err.c_str());
            return;
        }

        total_offl_sender_us += sender_offl.value().offl.wall_us;
        total_offl_receiver_us += receiver_offl.value().offl.wall_us;
        total_releasek_us += releasek.value().releasek.wall_us;
        total_release_sender_us += sender_release.value().release.wall_us;
        total_setx_receiver_us += receiver_setx.value().setx.wall_us;
        add_counters(total_offl_counters, sender_offl.value().counters);
        add_counters(total_offl_counters, receiver_offl.value().counters);
        add_counters(total_online_counters, sender_release.value().release.counters);
        add_counters(total_online_counters, receiver_setx.value().setx.counters);
        add_counters(total_counters, sender_offl.value().counters);
        add_counters(total_counters, receiver_offl.value().counters);
        add_counters(total_counters, sender_release.value().release.counters);
        add_counters(total_counters, receiver_setx.value().setx.counters);
        ring_width = sender_offl.value().state.ring_width;
    }

    const double iterations = static_cast<double>(state.iterations());
    const double offl_e2e_ms =
        std::max(total_offl_sender_us, total_offl_receiver_us) / 1000.0 / iterations;
    const double online_e2e_ms =
        std::max(total_release_sender_us, total_setx_receiver_us) / 1000.0 / iterations;
    const double total_e2e_ms = offl_e2e_ms + (total_releasek_us / 1000.0 / iterations) + online_e2e_ms;
    const double labels = static_cast<double>(label_count);

    state.counters["N_labels"] = labels;
    state.counters["w"] = static_cast<double>(ring_width);
    state.counters["modulus"] = static_cast<double>(modulus);
    state.counters["worker_threads"] = worker_threads;
    state.counters["bytes_s2r"] = total_counters.wire_bytes_s2r_sent / iterations;
    state.counters["bytes_r2s"] = total_counters.wire_bytes_r2s_sent / iterations;
    state.counters["round_count"] = total_counters.rounds_completed / iterations;
    state.counters["phase_time/offline_e2e_ms"] = offl_e2e_ms;
    state.counters["phase_time/releasek_ms"] = (total_releasek_us / 1000.0) / iterations;
    state.counters["phase_time/online_e2e_ms"] = online_e2e_ms;
    state.counters["phase_time/e2e_ms"] = total_e2e_ms;
    state.counters["phase_comm/offline_bytes_total"] =
        (total_offl_counters.wire_bytes_s2r_sent + total_offl_counters.wire_bytes_r2s_sent) / iterations;
    state.counters["phase_comm/online_bytes_total"] =
        (total_online_counters.wire_bytes_s2r_sent + total_online_counters.wire_bytes_r2s_sent) / iterations;
    if (online_e2e_ms > 0.0)
    {
        state.counters["tp/online_labels_per_s"] = labels * 1000.0 / online_e2e_ms;
    }
    if (total_e2e_ms > 0.0)
    {
        state.counters["tp/e2e_labels_per_s"] = labels * 1000.0 / total_e2e_ms;
    }
}

static void BM_LogVOLE_2Level(benchmark::State &state)
{
    run_public_civole_bench(state, 8192u);
}

static void BM_LogVOLE_3Level(benchmark::State &state)
{
    run_public_civole_bench(state, 65536u);
}

static void BM_LogVOLE_5Level_W256(benchmark::State &state)
{
    run_public_civole_bench(state, 2097152u);
}

static void BM_LogVOLE_N2Pow24(benchmark::State &state)
{
    run_public_civole_bench(state, 1ull << 24u, 4u);
}

static void BM_LogVOLE_N2Pow25(benchmark::State &state)
{
    run_public_civole_bench(state, 1ull << 25u, 4u);
}

const std::uint64_t k_benchmark_iterations = parse_benchmark_iterations_env(1u);
BENCHMARK(BM_LogVOLE_2Level)
    ->Unit(benchmark::kMillisecond)
    ->Iterations(static_cast<std::int64_t>(k_benchmark_iterations));
BENCHMARK(BM_LogVOLE_3Level)
    ->Unit(benchmark::kMillisecond)
    ->Iterations(static_cast<std::int64_t>(k_benchmark_iterations));
BENCHMARK(BM_LogVOLE_5Level_W256)
    ->Unit(benchmark::kMillisecond)
    ->Iterations(static_cast<std::int64_t>(k_benchmark_iterations));
BENCHMARK(BM_LogVOLE_N2Pow24)
    ->Unit(benchmark::kMillisecond)
    ->Iterations(static_cast<std::int64_t>(k_benchmark_iterations));
BENCHMARK(BM_LogVOLE_N2Pow25)
    ->Unit(benchmark::kMillisecond)
    ->Iterations(static_cast<std::int64_t>(k_benchmark_iterations));

BENCHMARK_MAIN();

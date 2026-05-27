#include "loglabel/comm/protocol_engine.hpp"

#include <benchmark/benchmark.h>

#include <thread>

namespace
{
    using namespace loglabel::comm;

    struct ping_msg
    {
        std::uint64_t nonce = 0;
    };

    struct pong_msg
    {
        std::uint32_t ok = 0;
    };

    struct ping_pong_spec
    {
        using script = round_script<
            round_pair<round_send<ping_msg, role_t::sender>, round_recv<ping_msg, role_t::receiver>>,
            round_pair<round_send<pong_msg, role_t::receiver>, round_recv<pong_msg, role_t::sender>>>;
    };
} // namespace

LOGLABEL_DEFINE_TRIVIAL_MESSAGE_TRAITS(ping_msg, 0x3001u);
LOGLABEL_DEFINE_TRIVIAL_MESSAGE_TRAITS(pong_msg, 0x3002u);

namespace
{
    void bench_inmemory_pingpong(benchmark::State &state)
    {
        std::uint64_t total_bytes_s2r = 0;
        std::uint64_t total_bytes_r2s = 0;
        std::uint64_t total_rounds = 0;

        for (auto _ : state)
        {
            (void)_;
            auto pair_result = make_in_memory_channel_pair(/*protocol_id=*/901, /*version=*/1, /*session_id=*/1001);
            if (!pair_result)
            {
                state.SkipWithError(pair_result.message().c_str());
                return;
            }

            auto channels = std::move(pair_result.value());
            any_channel sender_channel = std::move(channels.first);
            any_channel receiver_channel = std::move(channels.second);

            protocol_result<void> sender_result = protocol_result<void>::failure(protocol_errc::io_error, "not run");
            protocol_result<void> receiver_result = protocol_result<void>::failure(protocol_errc::io_error, "not run");

            comm_counters sender_counters{};

            std::thread receiver_thread([ch = std::move(receiver_channel), &receiver_result]() mutable {
                protocol_engine<ping_pong_spec, role_t::receiver> engine(std::move(ch));
                receiver_result = engine.run_with(
                    on_recv<0>([](const ping_msg &) {}),
                    on_send<1>([]() { return pong_msg{ 1 }; }));
            });

            std::thread sender_thread([ch = std::move(sender_channel), &sender_result, &sender_counters]() mutable {
                protocol_engine<ping_pong_spec, role_t::sender> engine(std::move(ch));
                sender_result = engine.run_with(
                    on_send<0>([]() { return ping_msg{ 42 }; }),
                    on_recv<1>([](const pong_msg &) {}));
                sender_counters = engine.counters();
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

            total_bytes_s2r += sender_counters.wire_bytes_s2r_sent;
            total_bytes_r2s += sender_counters.wire_bytes_r2s_recv;
            total_rounds += sender_counters.rounds_completed;
        }

        const double iterations = static_cast<double>(state.iterations());
        state.counters["bytes_s2r"] = total_bytes_s2r / iterations;
        state.counters["bytes_r2s"] = total_bytes_r2s / iterations;
        state.counters["bits_s2r"] = (total_bytes_s2r * 8.0) / iterations;
        state.counters["bits_r2s"] = (total_bytes_r2s * 8.0) / iterations;
        state.counters["round_count"] = total_rounds / iterations;
        state.counters["instances_per_sec"] = benchmark::Counter(
            static_cast<double>(state.iterations()), benchmark::Counter::kIsRate);
    }

    BENCHMARK(bench_inmemory_pingpong)->Name("InMemoryPingPong")->Unit(benchmark::kMicrosecond);
} // namespace

BENCHMARK_MAIN();

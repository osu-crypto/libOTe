#include "test_protocol_defs.hpp"

#include "libOTe_Tests/LogVole_TestUtil.h"

#include <thread>

using namespace loglabel::comm;
using namespace loglabel::comm::test_defs;

void LogVole_CommCounters_ExactByteAndBitAccounting(const oc::CLP&)
{
    auto pair_result = make_in_memory_channel_pair(/*protocol_id=*/88, /*version=*/1, /*session_id=*/444);
    LOGVOLE_REQUIRE_TRUE(pair_result) << pair_result.message();

    auto channels = std::move(pair_result.value());
    any_channel sender_channel = std::move(channels.first);
    any_channel receiver_channel = std::move(channels.second);

    protocol_result<void> sender_result = protocol_result<void>::failure(protocol_errc::io_error, "not run");
    protocol_result<void> receiver_result = protocol_result<void>::failure(protocol_errc::io_error, "not run");

    comm_counters sender_counters{};
    comm_counters receiver_counters{};

    std::thread receiver_thread([ch = std::move(receiver_channel), &receiver_result, &receiver_counters]() mutable {
        protocol_engine<ping_pong_spec, role_t::receiver> engine(std::move(ch));
        receiver_result = engine.run_with(
            on_recv<0>([](const ping_msg &) {}),
            on_send<1>([]() { return pong_msg{ 7 }; }));
        receiver_counters = engine.counters();
    });
    tests_libOTe::logvole_test::thread_join_guard receiver_guard(receiver_thread);

    std::thread sender_thread([ch = std::move(sender_channel), &sender_result, &sender_counters]() mutable {
        protocol_engine<ping_pong_spec, role_t::sender> engine(std::move(ch));
        sender_result = engine.run_with(
            on_send<0>([]() { return ping_msg{ 21 }; }),
            on_recv<1>([](const pong_msg &) {}));
        sender_counters = engine.counters();
    });
    tests_libOTe::logvole_test::thread_join_guard sender_guard(sender_thread);

    sender_guard.join();
    receiver_guard.join();

    LOGVOLE_REQUIRE_TRUE(sender_result) << sender_result.message();
    LOGVOLE_REQUIRE_TRUE(receiver_result) << receiver_result.message();

    const std::uint64_t expected_wire_s2r = envelope_wire_size + sizeof(ping_msg);
    const std::uint64_t expected_wire_r2s = envelope_wire_size + sizeof(pong_msg);

    LOGVOLE_EXPECT_EQ(sender_counters.wire_bytes_s2r_sent, expected_wire_s2r);
    LOGVOLE_EXPECT_EQ(sender_counters.wire_bytes_r2s_recv, expected_wire_r2s);
    LOGVOLE_EXPECT_EQ(receiver_counters.wire_bytes_s2r_recv, expected_wire_s2r);
    LOGVOLE_EXPECT_EQ(receiver_counters.wire_bytes_r2s_sent, expected_wire_r2s);

    LOGVOLE_EXPECT_EQ(sender_counters.payload_bytes_s2r_sent, sizeof(ping_msg));
    LOGVOLE_EXPECT_EQ(sender_counters.payload_bytes_r2s_recv, sizeof(pong_msg));
    LOGVOLE_EXPECT_EQ(receiver_counters.payload_bytes_s2r_recv, sizeof(ping_msg));
    LOGVOLE_EXPECT_EQ(receiver_counters.payload_bytes_r2s_sent, sizeof(pong_msg));

    LOGVOLE_EXPECT_EQ(sender_counters.bits_s2r_sent(), expected_wire_s2r * 8);
    LOGVOLE_EXPECT_EQ(receiver_counters.bits_r2s_sent(), expected_wire_r2s * 8);

    LOGVOLE_EXPECT_EQ(sender_counters.rounds_completed, 2u);
    LOGVOLE_EXPECT_EQ(receiver_counters.rounds_completed, 2u);
}

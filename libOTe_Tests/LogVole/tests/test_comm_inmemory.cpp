#include "test_protocol_defs.hpp"

#include "gtest/gtest.h"

#include <atomic>
#include <thread>

using namespace loglabel::comm;
using namespace loglabel::comm::test_defs;

TEST(CommInMemory, PingPongHappyPath)
{
    auto pair_result = make_in_memory_channel_pair(/*protocol_id=*/42, /*version=*/1, /*session_id=*/777);
    ASSERT_TRUE(pair_result) << pair_result.message();

    auto channels = std::move(pair_result.value());
    any_channel sender_channel = std::move(channels.first);
    any_channel receiver_channel = std::move(channels.second);

    std::atomic<std::uint64_t> observed_nonce{ 0 };
    std::atomic<std::uint32_t> observed_ack{ 0 };

    protocol_result<void> sender_result = protocol_result<void>::failure(protocol_errc::io_error, "not run");
    protocol_result<void> receiver_result = protocol_result<void>::failure(protocol_errc::io_error, "not run");

    comm_counters sender_counters{};
    comm_counters receiver_counters{};

    std::thread receiver_thread([ch = std::move(receiver_channel), &receiver_result, &receiver_counters, &observed_nonce]() mutable {
        protocol_engine<ping_pong_spec, role_t::receiver> engine(std::move(ch));
        receiver_result = engine.run_with(
            on_recv<0>([&observed_nonce](const ping_msg &message) { observed_nonce.store(message.nonce); }),
            on_send<1>([]() { return pong_msg{ 1 }; }));
        receiver_counters = engine.counters();
    });

    std::thread sender_thread([ch = std::move(sender_channel), &sender_result, &sender_counters, &observed_ack]() mutable {
        protocol_engine<ping_pong_spec, role_t::sender> engine(std::move(ch));
        sender_result = engine.run_with(
            on_send<0>([]() { return ping_msg{ 1234 }; }),
            on_recv<1>([&observed_ack](const pong_msg &message) { observed_ack.store(message.ok); }));
        sender_counters = engine.counters();
    });

    sender_thread.join();
    receiver_thread.join();

    ASSERT_TRUE(sender_result) << sender_result.message();
    ASSERT_TRUE(receiver_result) << receiver_result.message();

    EXPECT_EQ(observed_nonce.load(), 1234u);
    EXPECT_EQ(observed_ack.load(), 1u);

    EXPECT_EQ(sender_counters.frames_s2r_sent, 1u);
    EXPECT_EQ(receiver_counters.frames_s2r_recv, 1u);
    EXPECT_EQ(sender_counters.frames_r2s_recv, 1u);
    EXPECT_EQ(receiver_counters.frames_r2s_sent, 1u);
}

#include "test_protocol_defs.hpp"

#include "gtest/gtest.h"

#include <thread>

using namespace loglabel::comm;
using namespace loglabel::comm::test_defs;

TEST(CommValidation, PayloadTypeMismatchFails)
{
    auto pair_result = make_in_memory_channel_pair(
        /*protocol_id=*/55, /*version=*/1, /*session_id=*/222, std::chrono::milliseconds(500));
    ASSERT_TRUE(pair_result) << pair_result.message();

    auto channels = std::move(pair_result.value());
    any_channel sender_channel = std::move(channels.first);
    any_channel receiver_channel = std::move(channels.second);

    protocol_result<void> sender_result = protocol_result<void>::failure(protocol_errc::io_error, "not run");
    protocol_result<void> receiver_result = protocol_result<void>::failure(protocol_errc::io_error, "not run");

    std::thread receiver_thread([ch = std::move(receiver_channel), &receiver_result]() mutable {
        protocol_engine<one_round_wrong_ping_spec, role_t::receiver> engine(std::move(ch));
        receiver_result = engine.run_with(on_recv<0>([](const wrong_ping_msg &) {}));
    });

    std::thread sender_thread([ch = std::move(sender_channel), &sender_result]() mutable {
        protocol_engine<one_round_ping_spec, role_t::sender> engine(std::move(ch));
        sender_result = engine.run_with(on_send<0>([]() { return ping_msg{ 99 }; }));
    });

    sender_thread.join();
    receiver_thread.join();

    ASSERT_TRUE(sender_result) << sender_result.message();
    ASSERT_FALSE(receiver_result);
    EXPECT_EQ(receiver_result.error(), protocol_errc::flow_violation);
}

TEST(CommValidation, WrongRoundIndexFails)
{
    auto pair_result = make_in_memory_channel_pair(
        /*protocol_id=*/77, /*version=*/1, /*session_id=*/333, std::chrono::milliseconds(500));
    ASSERT_TRUE(pair_result) << pair_result.message();

    auto channels = std::move(pair_result.value());
    any_channel sender_channel = std::move(channels.first);
    any_channel receiver_channel = std::move(channels.second);

    protocol_result<void> receiver_result = protocol_result<void>::failure(protocol_errc::io_error, "not run");

    std::thread receiver_thread([ch = std::move(receiver_channel), &receiver_result]() mutable {
        protocol_engine<one_round_ping_spec, role_t::receiver> engine(std::move(ch));
        receiver_result = engine.run_with(on_recv<0>([](const ping_msg &) {}));
    });

    auto payload_result = encode_message(ping_msg{ 11 });
    ASSERT_TRUE(payload_result) << payload_result.message();

    message_envelope envelope{};
    envelope.protocol_id = 77;
    envelope.version = 1;
    envelope.session_id = 333;
    envelope.round_index = 5; // Intentional mismatch.
    envelope.sequence_number = 0;
    envelope.payload_type = message_traits<ping_msg>::payload_type;
    envelope.payload_size = static_cast<std::uint32_t>(payload_result.value().size());
    envelope.payload_crc = crc32(payload_result.value().data(), payload_result.value().size());

    auto frame_result = serialize_frame(envelope, payload_result.value());
    ASSERT_TRUE(frame_result) << frame_result.message();

    auto send_result = sender_channel.send_frame(std::move(frame_result.value()));
    ASSERT_TRUE(send_result) << send_result.message();

    receiver_thread.join();

    ASSERT_FALSE(receiver_result);
    EXPECT_EQ(receiver_result.error(), protocol_errc::flow_violation);
}

#include "test_protocol_defs.hpp"

#include "gtest/gtest.h"

#include <chrono>
#include <string>
#include <thread>

#if !defined(_WIN32)
#include <unistd.h>
#endif

using namespace loglabel::comm;
using namespace loglabel::comm::test_defs;

TEST(CommUds, PingPongOverUnixDomainSocket)
{
#if defined(_WIN32)
    GTEST_SKIP() << "UDS not supported on Windows";
#else
    const auto timestamp = static_cast<long long>(
        std::chrono::steady_clock::now().time_since_epoch().count());
    const std::string socket_path =
        "/tmp/loglabel_comm_" + std::to_string(static_cast<long long>(::getpid())) + "_" +
        std::to_string(timestamp) + ".sock";

    auto pair_result = make_uds_channel_pair(
        socket_path, /*protocol_id=*/123, /*version=*/1, /*session_id=*/456, std::chrono::milliseconds(1000));
    if (!pair_result)
    {
        GTEST_SKIP() << "UDS unavailable in this environment: " << pair_result.message();
    }

    auto channels = std::move(pair_result.value());
    any_channel sender_channel = std::move(channels.first);
    any_channel receiver_channel = std::move(channels.second);

    protocol_result<void> sender_result = protocol_result<void>::failure(protocol_errc::io_error, "not run");
    protocol_result<void> receiver_result = protocol_result<void>::failure(protocol_errc::io_error, "not run");

    std::thread receiver_thread([ch = std::move(receiver_channel), &receiver_result]() mutable {
        protocol_engine<ping_pong_spec, role_t::receiver> engine(std::move(ch));
        receiver_result = engine.run_with(
            on_recv<0>([](const ping_msg &) {}),
            on_send<1>([]() { return pong_msg{ 1 }; }));
    });

    std::thread sender_thread([ch = std::move(sender_channel), &sender_result]() mutable {
        protocol_engine<ping_pong_spec, role_t::sender> engine(std::move(ch));
        sender_result = engine.run_with(
            on_send<0>([]() { return ping_msg{ 10 }; }),
            on_recv<1>([](const pong_msg &) {}));
    });

    sender_thread.join();
    receiver_thread.join();

    ASSERT_TRUE(sender_result) << sender_result.message();
    ASSERT_TRUE(receiver_result) << receiver_result.message();
#endif
}

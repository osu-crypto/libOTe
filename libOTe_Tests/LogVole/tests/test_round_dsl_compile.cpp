#include "test_protocol_defs.hpp"

#include "libOTe_Tests/LogVole_TestUtil.h"

#include <thread>

using namespace loglabel::comm;
using namespace loglabel::comm::test_defs;

void LogVole_RoundDslCompile_ScriptShapeAndHandlersCompile(const oc::CLP&)
{
    static_assert(round_script_traits<ping_pong_spec::script>::round_count == 2, "unexpected round count");

    auto pair_result = make_in_memory_channel_pair(/*protocol_id=*/10, /*version=*/1, /*session_id=*/101);
    LOGVOLE_REQUIRE_TRUE(pair_result) << pair_result.message();

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
    tests_libOTe::logvole_test::thread_join_guard receiver_guard(receiver_thread);

    std::thread sender_thread([ch = std::move(sender_channel), &sender_result]() mutable {
        protocol_engine<ping_pong_spec, role_t::sender> engine(std::move(ch));
        sender_result = engine.run_with(
            on_send<0>([]() { return ping_msg{ 9 }; }),
            on_recv<1>([](const pong_msg &) {}));
    });
    tests_libOTe::logvole_test::thread_join_guard sender_guard(sender_thread);

    sender_guard.join();
    receiver_guard.join();

    LOGVOLE_REQUIRE_TRUE(sender_result) << sender_result.message();
    LOGVOLE_REQUIRE_TRUE(receiver_result) << receiver_result.message();
}

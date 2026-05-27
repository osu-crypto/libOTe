#include "loglabel/comm/protocol_engine.hpp"

#include <thread>

namespace
{
    using namespace loglabel::comm;

    struct open_msg
    {
        std::uint64_t nonce = 0;
    };

    struct ack_msg
    {
        std::uint32_t ok = 0;
    };

    struct demo_spec
    {
        using script = round_script<
            round_pair<round_send<open_msg, role_t::sender>, round_recv<open_msg, role_t::receiver>>,
            round_pair<round_send<ack_msg, role_t::receiver>, round_recv<ack_msg, role_t::sender>>>;
    };
} // namespace

LOGLABEL_DEFINE_TRIVIAL_MESSAGE_TRAITS(open_msg, 0x4001u);
LOGLABEL_DEFINE_TRIVIAL_MESSAGE_TRAITS(ack_msg, 0x4002u);

int main()
{
    using namespace loglabel::comm;

    auto pair = make_in_memory_channel_pair(/*protocol_id=*/7, /*version=*/1, /*session_id=*/42);
    if (!pair)
    {
        return 1;
    }

    auto channels = std::move(pair.value());
    any_channel sender_channel = std::move(channels.first);
    any_channel receiver_channel = std::move(channels.second);

    protocol_result<void> sender_result = protocol_result<void>::failure(protocol_errc::io_error, "not run");
    protocol_result<void> receiver_result = protocol_result<void>::failure(protocol_errc::io_error, "not run");

    std::thread receiver_thread([ch = std::move(receiver_channel), &receiver_result]() mutable {
        protocol_engine<demo_spec, role_t::receiver> engine(std::move(ch));
        receiver_result = engine.run_with(
            on_recv<0>([](const open_msg &) {}),
            on_send<1>([]() { return ack_msg{ 1 }; }));
    });

    std::thread sender_thread([ch = std::move(sender_channel), &sender_result]() mutable {
        protocol_engine<demo_spec, role_t::sender> engine(std::move(ch));
        sender_result = engine.run_with(
            on_send<0>([]() { return open_msg{ 123 }; }),
            on_recv<1>([](const ack_msg &) {}));
    });

    sender_thread.join();
    receiver_thread.join();

    return (sender_result && receiver_result) ? 0 : 2;
}

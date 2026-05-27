#pragma once

#include "loglabel/comm/channel.hpp"
#include "loglabel/comm/types.hpp"
#include "loglabel/keyderive_backend.hpp"
#include "loglabel/keyderive_types.hpp"

#include <type_traits>

namespace loglabel
{
    comm::protocol_result<keyderive_sender_output> run_keyderive_sender(
        comm::any_channel channel, const keyderive_sender_input &input, const keyderive_backend &backend);

    comm::protocol_result<keyderive_receiver_output> run_keyderive_receiver(
        comm::any_channel channel, const keyderive_receiver_input &input, const keyderive_backend &backend);

    using run_keyderive_sender_signature = comm::protocol_result<keyderive_sender_output> (*) (
        comm::any_channel, const keyderive_sender_input &, const keyderive_backend &);

    using run_keyderive_receiver_signature = comm::protocol_result<keyderive_receiver_output> (*) (
        comm::any_channel, const keyderive_receiver_input &, const keyderive_backend &);

    static_assert(std::is_same<decltype(&run_keyderive_sender), run_keyderive_sender_signature>::value,
                  "run_keyderive_sender signature mismatch");

    static_assert(std::is_same<decltype(&run_keyderive_receiver), run_keyderive_receiver_signature>::value,
                  "run_keyderive_receiver signature mismatch");

} // namespace loglabel

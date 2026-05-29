#pragma once

#include <memory>
#include <type_traits>
#include "logvole/comm/channel.hpp"
#include "logvole/comm/types.hpp"
#include "logvole/logvole_backend.hpp"
#include "logvole/logvole_types.hpp"

namespace logvole
{
    comm::protocol_result<logvole_sender_offline_output> run_logvole_sender_offline(
        comm::any_channel channel, const logvole_sender_offline_input &input, const logvole_backend &backend);

    comm::protocol_result<logvole_receiver_offline_output> run_logvole_receiver_offline(
        comm::any_channel channel, const logvole_receiver_offline_input &input, const logvole_backend &backend);

    comm::protocol_result<logvole_sender_precompute_output> run_logvole_sender_precompute(
        const logvole_sender_state &state, const logvole_backend &backend);

    comm::protocol_result<logvole_receiver_online_output> run_logvole_receiver_online(
        comm::any_channel channel, const logvole_receiver_state &state,
        const logvole_receiver_online_input &input, const logvole_backend &backend);

    comm::protocol_result<logvole_sender_online_output> run_logvole_sender_online(
        comm::any_channel channel, const logvole_sender_state &state, const logvole_sender_online_input &input,
        const logvole_backend &backend);

} // namespace logvole

#pragma once

#include "loglabel/comm/channel.hpp"
#include "loglabel/comm/types.hpp"
#include "loglabel/shrinkexpand_backend.hpp"
#include "loglabel/shrinkexpand_types.hpp"

#include <type_traits>

namespace loglabel
{
    comm::protocol_result<shrinkexpand_sender_offline_output> run_shrinkexpand_sender(
        comm::any_channel channel, const shrinkexpand_sender_offline_input &input, const shrinkexpand_backend &backend);

    comm::protocol_result<shrinkexpand_receiver_offline_output> run_shrinkexpand_receiver(
        comm::any_channel channel, const shrinkexpand_receiver_offline_input &input, const shrinkexpand_backend &backend);

    comm::protocol_result<ring_rns_poly> shrinkexpand_shrink(
        const shrinkexpand_receiver_state &state, const std::vector<ring_rns_poly> &x,
        const shrinkexpand_backend &backend);

    comm::protocol_result<shrinkexpand_sender_expand_output> shrinkexpand_expand_sender(
        const shrinkexpand_sender_state &state,
        const shrinkexpand_expand_sender_input &input,
        const shrinkexpand_backend &backend);

    comm::protocol_result<shrinkexpand_receiver_expand_output> shrinkexpand_expand_receiver(
        const shrinkexpand_receiver_state &state,
        const shrinkexpand_expand_receiver_input &input,
        const shrinkexpand_backend &backend);

    using run_shrinkexpand_sender_signature = comm::protocol_result<shrinkexpand_sender_offline_output> (*) (
        comm::any_channel, const shrinkexpand_sender_offline_input &, const shrinkexpand_backend &);

    using run_shrinkexpand_receiver_signature = comm::protocol_result<shrinkexpand_receiver_offline_output> (*) (
        comm::any_channel, const shrinkexpand_receiver_offline_input &, const shrinkexpand_backend &);

    using shrinkexpand_shrink_signature = comm::protocol_result<ring_rns_poly> (*) (
        const shrinkexpand_receiver_state &, const std::vector<ring_rns_poly> &, const shrinkexpand_backend &);

    using shrinkexpand_expand_sender_signature = comm::protocol_result<shrinkexpand_sender_expand_output> (*) (
        const shrinkexpand_sender_state &, const shrinkexpand_expand_sender_input &, const shrinkexpand_backend &);

    using shrinkexpand_expand_receiver_signature = comm::protocol_result<shrinkexpand_receiver_expand_output> (*) (
        const shrinkexpand_receiver_state &, const shrinkexpand_expand_receiver_input &, const shrinkexpand_backend &);

    static_assert(std::is_same<decltype(&run_shrinkexpand_sender), run_shrinkexpand_sender_signature>::value,
                  "run_shrinkexpand_sender signature mismatch");

    static_assert(std::is_same<decltype(&run_shrinkexpand_receiver), run_shrinkexpand_receiver_signature>::value,
                  "run_shrinkexpand_receiver signature mismatch");

    static_assert(std::is_same<decltype(&shrinkexpand_shrink), shrinkexpand_shrink_signature>::value,
                  "shrinkexpand_shrink signature mismatch");

    static_assert(std::is_same<decltype(&shrinkexpand_expand_sender), shrinkexpand_expand_sender_signature>::value,
                  "shrinkexpand_expand_sender signature mismatch");

    static_assert(std::is_same<decltype(&shrinkexpand_expand_receiver), shrinkexpand_expand_receiver_signature>::value,
                  "shrinkexpand_expand_receiver signature mismatch");

} // namespace loglabel

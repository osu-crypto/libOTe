#pragma once

#include "loglabel/comm/types.hpp"
#include "loglabel/shrinkexpand_types.hpp"

namespace loglabel
{
    struct shrinkexpand_offline_msg;

    class shrinkexpand_backend
    {
    public:
        virtual ~shrinkexpand_backend() = default;

        virtual comm::protocol_result<shrinkexpand_offline_msg> prepare_offline_sender(
            const shrinkexpand_sender_offline_input &input,
            shrinkexpand_sender_state &sender_state) const = 0;

        virtual comm::protocol_result<shrinkexpand_receiver_state> finalize_offline_receiver(
            const shrinkexpand_receiver_offline_input &input,
            const shrinkexpand_offline_msg &message) const = 0;

        virtual comm::protocol_result<ring_rns_poly> shrink(
            const shrinkexpand_receiver_state &state,
            const std::vector<ring_rns_poly> &x) const = 0;

        virtual comm::protocol_result<shrinkexpand_sender_expand_output> expand_sender(
            const shrinkexpand_sender_state &state,
            const shrinkexpand_expand_sender_input &input) const = 0;

        virtual comm::protocol_result<shrinkexpand_receiver_expand_output> expand_receiver(
            const shrinkexpand_receiver_state &state,
            const shrinkexpand_expand_receiver_input &input) const = 0;
    };

    class shrinkexpand_seal_backend final : public shrinkexpand_backend
    {
    public:
        comm::protocol_result<shrinkexpand_offline_msg> prepare_offline_sender(
            const shrinkexpand_sender_offline_input &input,
            shrinkexpand_sender_state &sender_state) const override;

        comm::protocol_result<shrinkexpand_receiver_state> finalize_offline_receiver(
            const shrinkexpand_receiver_offline_input &input,
            const shrinkexpand_offline_msg &message) const override;

        comm::protocol_result<ring_rns_poly> shrink(
            const shrinkexpand_receiver_state &state,
            const std::vector<ring_rns_poly> &x) const override;

        comm::protocol_result<shrinkexpand_sender_expand_output> expand_sender(
            const shrinkexpand_sender_state &state,
            const shrinkexpand_expand_sender_input &input) const override;

        comm::protocol_result<shrinkexpand_receiver_expand_output> expand_receiver(
            const shrinkexpand_receiver_state &state,
            const shrinkexpand_expand_receiver_input &input) const override;
    };

} // namespace loglabel

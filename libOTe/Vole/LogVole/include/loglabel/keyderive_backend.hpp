#pragma once

#include "loglabel/comm/types.hpp"
#include "loglabel/keyderive_spec.hpp"
#include "loglabel/keyderive_types.hpp"

namespace loglabel
{
    class keyderive_backend
    {
    public:
        virtual ~keyderive_backend() = default;

        virtual comm::protocol_result<keyderive_response_msg> process_request_sender(
            const keyderive_sender_input &sender_input, const keyderive_request_msg &request,
            keyderive_sender_output &sender_output) const = 0;

        virtual comm::protocol_result<keyderive_receiver_output> finalize_response_receiver(
            const keyderive_receiver_input &receiver_input, const keyderive_response_msg &response) const = 0;
    };

    class keyderive_seal_ntt_backend final : public keyderive_backend
    {
    public:
        comm::protocol_result<keyderive_response_msg> process_request_sender(
            const keyderive_sender_input &sender_input, const keyderive_request_msg &request,
            keyderive_sender_output &sender_output) const override;

        comm::protocol_result<keyderive_receiver_output> finalize_response_receiver(
            const keyderive_receiver_input &receiver_input, const keyderive_response_msg &response) const override;
    };

} // namespace loglabel

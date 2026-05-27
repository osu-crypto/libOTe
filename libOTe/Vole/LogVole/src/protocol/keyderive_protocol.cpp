#include "loglabel/keyderive_protocol.hpp"

#include "loglabel/comm/protocol_engine.hpp"
#include "loglabel/keyderive_shared_ops.hpp"
#include "loglabel/keyderive_spec.hpp"

#include <optional>
#include <utility>

namespace loglabel
{
    comm::protocol_result<keyderive_sender_output> run_keyderive_sender(
        comm::any_channel channel, const keyderive_sender_input &input, const keyderive_backend &backend)
    {
        auto input_ok = validate_keyderive_sender_input_internal(input);
        if (!input_ok)
        {
            return comm::protocol_result<keyderive_sender_output>::failure(input_ok.error(), input_ok.message());
        }

        std::optional<keyderive_response_msg> response;
        std::optional<keyderive_sender_output> sender_output;

        comm::protocol_engine<keyderive_spec, comm::role_t::sender> engine(std::move(channel));
        auto run_result = engine.run_with(
            comm::on_recv<0>([&](const keyderive_request_msg &request) -> comm::protocol_result<void> {
                keyderive_sender_output prepared_output{};
                auto response_result = backend.process_request_sender(input, request, prepared_output);
                if (!response_result)
                {
                    return comm::protocol_result<void>::failure(
                        response_result.error(), response_result.message());
                }

                response = std::move(response_result.value());
                sender_output = std::move(prepared_output);
                return comm::protocol_result<void>::success();
            }),
            comm::on_send<1>([&]() -> comm::protocol_result<keyderive_response_msg> {
                if (!response || !sender_output)
                {
                    return comm::protocol_result<keyderive_response_msg>::failure(
                        comm::protocol_errc::invalid_state_transition,
                        "sender response/state not prepared before round 1");
                }
                return comm::protocol_result<keyderive_response_msg>::success(*response);
            }));

        if (!run_result)
        {
            return comm::protocol_result<keyderive_sender_output>::failure(
                run_result.error(), run_result.message());
        }

        if (!sender_output)
        {
            return comm::protocol_result<keyderive_sender_output>::failure(
                comm::protocol_errc::invalid_state_transition,
                "sender output missing after successful keyderive execution");
        }

        return comm::protocol_result<keyderive_sender_output>::success(std::move(*sender_output));
    }

    comm::protocol_result<keyderive_receiver_output> run_keyderive_receiver(
        comm::any_channel channel, const keyderive_receiver_input &input, const keyderive_backend &backend)
    {
        auto input_ok = validate_keyderive_receiver_input_internal(input);
        if (!input_ok)
        {
            return comm::protocol_result<keyderive_receiver_output>::failure(input_ok.error(), input_ok.message());
        }

        auto request_result = prepare_keyderive_request_receiver_internal(input);
        if (!request_result)
        {
            return comm::protocol_result<keyderive_receiver_output>::failure(
                request_result.error(), request_result.message());
        }

        keyderive_request_msg request = std::move(request_result.value());
        std::optional<keyderive_receiver_output> receiver_output;

        comm::protocol_engine<keyderive_spec, comm::role_t::receiver> engine(std::move(channel));
        auto run_result = engine.run_with(
            comm::on_send<0>([&]() -> comm::protocol_result<keyderive_request_msg> {
                return comm::protocol_result<keyderive_request_msg>::success(request);
            }),
            comm::on_recv<1>([&](const keyderive_response_msg &response) -> comm::protocol_result<void> {
                auto finalize_result = backend.finalize_response_receiver(input, response);
                if (!finalize_result)
                {
                    return comm::protocol_result<void>::failure(
                        finalize_result.error(), finalize_result.message());
                }

                receiver_output = std::move(finalize_result.value());
                return comm::protocol_result<void>::success();
            }));

        if (!run_result)
        {
            return comm::protocol_result<keyderive_receiver_output>::failure(
                run_result.error(), run_result.message());
        }

        if (!receiver_output)
        {
            return comm::protocol_result<keyderive_receiver_output>::failure(
                comm::protocol_errc::invalid_state_transition,
                "receiver output missing after successful keyderive execution");
        }

        return comm::protocol_result<keyderive_receiver_output>::success(std::move(*receiver_output));
    }

} // namespace loglabel

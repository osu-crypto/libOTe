#include "loglabel/shrinkexpand_protocol.hpp"

#include "loglabel/comm/protocol_engine.hpp"
#include "loglabel/shrinkexpand_spec.hpp"

#include "shrinkexpand_shared_ops.hpp"

#include <optional>
#include <utility>

namespace loglabel
{
    comm::protocol_result<shrinkexpand_sender_offline_output> run_shrinkexpand_sender(
        comm::any_channel channel, const shrinkexpand_sender_offline_input &input, const shrinkexpand_backend &backend)
    {
        auto input_ok = validate_shrinkexpand_sender_offline_input(input);
        if (!input_ok)
        {
            return comm::protocol_result<shrinkexpand_sender_offline_output>::failure(input_ok.error(), input_ok.message());
        }

        std::optional<shrinkexpand_offline_msg> message;
        std::optional<shrinkexpand_sender_state> sender_state;

        comm::protocol_engine<shrinkexpand_spec, comm::role_t::sender> engine(std::move(channel));
        auto run_result = engine.run_with(
            comm::on_send<0>([&]() -> comm::protocol_result<shrinkexpand_offline_msg> {
                shrinkexpand_sender_state prepared_state{};
                auto prepared = backend.prepare_offline_sender(input, prepared_state);
                if (!prepared)
                {
                    return comm::protocol_result<shrinkexpand_offline_msg>::failure(
                        prepared.error(), prepared.message());
                }

                message = prepared.value();
                sender_state = std::move(prepared_state);
                return comm::protocol_result<shrinkexpand_offline_msg>::success(*message);
            }));

        if (!run_result)
        {
            return comm::protocol_result<shrinkexpand_sender_offline_output>::failure(
                run_result.error(), run_result.message());
        }

        if (!sender_state)
        {
            return comm::protocol_result<shrinkexpand_sender_offline_output>::failure(
                comm::protocol_errc::invalid_state_transition,
                "sender state missing after successful shrinkexpand offline run");
        }

        shrinkexpand_sender_offline_output output{};
        output.state = std::move(*sender_state);
        output.counters = engine.counters();
        return comm::protocol_result<shrinkexpand_sender_offline_output>::success(std::move(output));
    }

    comm::protocol_result<shrinkexpand_receiver_offline_output> run_shrinkexpand_receiver(
        comm::any_channel channel, const shrinkexpand_receiver_offline_input &input, const shrinkexpand_backend &backend)
    {
        auto input_ok = validate_shrinkexpand_receiver_offline_input(input);
        if (!input_ok)
        {
            return comm::protocol_result<shrinkexpand_receiver_offline_output>::failure(input_ok.error(), input_ok.message());
        }

        std::optional<shrinkexpand_receiver_state> receiver_state;

        comm::protocol_engine<shrinkexpand_spec, comm::role_t::receiver> engine(std::move(channel));
        auto run_result = engine.run_with(
            comm::on_recv<0>([&](const shrinkexpand_offline_msg &message) -> comm::protocol_result<void> {
                auto finalized = backend.finalize_offline_receiver(input, message);
                if (!finalized)
                {
                    return comm::protocol_result<void>::failure(finalized.error(), finalized.message());
                }

                receiver_state = std::move(finalized.value());
                return comm::protocol_result<void>::success();
            }));

        if (!run_result)
        {
            return comm::protocol_result<shrinkexpand_receiver_offline_output>::failure(
                run_result.error(), run_result.message());
        }

        if (!receiver_state)
        {
            return comm::protocol_result<shrinkexpand_receiver_offline_output>::failure(
                comm::protocol_errc::invalid_state_transition,
                "receiver state missing after successful shrinkexpand offline run");
        }

        shrinkexpand_receiver_offline_output output{};
        output.state = std::move(*receiver_state);
        output.counters = engine.counters();
        return comm::protocol_result<shrinkexpand_receiver_offline_output>::success(std::move(output));
    }

    comm::protocol_result<ring_rns_poly> shrinkexpand_shrink(
        const shrinkexpand_receiver_state &state, const std::vector<ring_rns_poly> &x,
        const shrinkexpand_backend &backend)
    {
        return backend.shrink(state, x);
    }

    comm::protocol_result<shrinkexpand_sender_expand_output> shrinkexpand_expand_sender(
        const shrinkexpand_sender_state &state,
        const shrinkexpand_expand_sender_input &input,
        const shrinkexpand_backend &backend)
    {
        return backend.expand_sender(state, input);
    }

    comm::protocol_result<shrinkexpand_receiver_expand_output> shrinkexpand_expand_receiver(
        const shrinkexpand_receiver_state &state,
        const shrinkexpand_expand_receiver_input &input,
        const shrinkexpand_backend &backend)
    {
        return backend.expand_receiver(state, input);
    }

} // namespace loglabel

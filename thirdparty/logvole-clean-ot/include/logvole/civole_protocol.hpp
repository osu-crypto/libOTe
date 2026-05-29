#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>
#include "logvole/comm/channel.hpp"
#include "logvole/comm/metrics.hpp"
#include "logvole/comm/types.hpp"
#include "logvole/logvole_backend.hpp"
#include "logvole/logvole_types.hpp"

namespace logvole
{
    using civole_sid = std::uint64_t;

    struct civole_params
    {
        logvole_params logvole{};
    };

    struct civole_phase_metrics
    {
        comm::comm_counters counters{};
        std::uint64_t wall_us = 0u;
    };

    struct civole_sender_offl_input
    {
        civole_params params{};
        std::uint64_t delta = 0u;
        std::size_t w = 0u;
    };

    struct civole_receiver_offl_input
    {
        civole_params params{};
    };

    struct civole_sender_state
    {
        civole_params params{};
        std::uint64_t modulus = 0u;
        std::uint64_t delta = 0u;
        std::size_t w = 0u;
        std::uint32_t ring_width = 0u;
        sampling_seed_config base_sampling_seeds{};
        logvole_sender_state logvole_state{};

        bool has_active_sid = false;
        civole_sid active_sid = 0u;
        bool key_released = false;
        bool release_int_used = false;
        std::vector<civole_sid> used_sids{};
        std::vector<std::uint64_t> released_keys{};
    };

    struct civole_receiver_state
    {
        civole_params params{};
        std::uint64_t modulus = 0u;
        std::size_t w = 0u;
        std::uint32_t ring_width = 0u;
        sampling_seed_config base_sampling_seeds{};
        logvole_receiver_state logvole_state{};
        std::vector<civole_sid> used_sids{};
    };

    struct civole_sender_offl_output
    {
        civole_sender_state state{};
        civole_phase_metrics offl{};
        comm::comm_counters counters{};
    };

    struct civole_receiver_offl_output
    {
        civole_receiver_state state{};
        civole_phase_metrics offl{};
        comm::comm_counters counters{};
    };

    struct civole_releasek_output
    {
        civole_sid sid = 0u;
        std::uint64_t modulus = 0u;
        std::vector<std::uint64_t> keys{};
        civole_phase_metrics releasek{};
    };

    struct civole_sender_release_output
    {
        civole_sid sid = 0u;
        civole_phase_metrics release{};
    };

    struct civole_receiver_setx_output
    {
        civole_sid sid = 0u;
        std::uint64_t modulus = 0u;
        std::vector<std::uint64_t> values{};
        std::vector<std::uint64_t> macs{};
        civole_phase_metrics setx{};
    };

    comm::protocol_result<civole_params> make_default_civole_params(std::uint32_t worker_threads = 1u);

    comm::protocol_result<std::uint64_t> resolve_civole_modulus(const civole_params &params);

    comm::protocol_result<civole_sender_offl_output> run_civole_sender_offl(
        comm::any_channel channel, const civole_sender_offl_input &input, const logvole_backend &backend);

    comm::protocol_result<civole_receiver_offl_output> run_civole_receiver_offl(
        comm::any_channel channel, const civole_receiver_offl_input &input, const logvole_backend &backend);

    comm::protocol_result<civole_releasek_output> run_civole_sender_releasek_int(
        civole_sender_state &state, civole_sid sid, const logvole_backend &backend);

    comm::protocol_result<civole_sender_release_output> run_civole_sender_release_int(
        comm::any_channel channel, civole_sender_state &state, civole_sid sid, const logvole_backend &backend);

    comm::protocol_result<civole_receiver_setx_output> run_civole_receiver_setx_int(
        comm::any_channel channel, civole_receiver_state &state, civole_sid sid, const std::vector<std::uint64_t> &x,
        const logvole_backend &backend);
} // namespace logvole

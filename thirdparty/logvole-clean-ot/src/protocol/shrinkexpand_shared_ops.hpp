#pragma once

#include <cstdint>
#include <vector>
#include "logvole/comm/types.hpp"
#include "logvole/ring_ops.hpp"
#include "logvole/shrinkexpand_spec.hpp"
#include "logvole/shrinkexpand_types.hpp"

namespace logvole
{
    comm::protocol_result<void> validate_shrinkexpand_params(const shrinkexpand_params &params);

    comm::protocol_result<void> validate_shrinkexpand_sender_offline_input(
        const shrinkexpand_sender_offline_input &input);

    comm::protocol_result<void> validate_shrinkexpand_receiver_offline_input(
        const shrinkexpand_receiver_offline_input &input);

    comm::protocol_result<std::int64_t> resolve_shrinkexpand_effective_noise_bound(const shrinkexpand_params &params);

    std::uint64_t shrinkexpand_metadata_fingerprint(const shrinkexpand_params &params);

    std::vector<ring_rns_poly> sample_uniform_batch(
        const ring_ntt_context &ctx, std::uint32_t count, std::uint64_t seed, std::uint64_t domain_tag);

    comm::protocol_result<shrinkexpand_offline_msg> build_offline_message(const shrinkexpand_sender_state &state);

    comm::protocol_result<shrinkexpand_receiver_state> receiver_state_from_message(
        const shrinkexpand_receiver_offline_input &input, const shrinkexpand_offline_msg &message);

    comm::protocol_result<std::vector<ring_rns_poly>> shrinkexpand_denoise_comb(
        const ring_ntt_context &ctx, const std::vector<ring_rns_poly> &tba_prime);

} // namespace logvole

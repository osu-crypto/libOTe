#pragma once

#include "loglabel/comm/types.hpp"
#include "loglabel/keyderive_spec.hpp"
#include "loglabel/keyderive_types.hpp"

#include <cstdint>
#include <vector>

namespace loglabel
{
    comm::protocol_result<void> validate_keyderive_params_internal(const keyderive_params &params);

    comm::protocol_result<void> validate_keyderive_sender_input_internal(const keyderive_sender_input &input);

    comm::protocol_result<void> validate_keyderive_receiver_input_internal(const keyderive_receiver_input &input);

    comm::protocol_result<keyderive_request_msg> prepare_keyderive_request_receiver_internal(
        const keyderive_receiver_input &input);

    std::vector<std::uint64_t> pack_ring_batch_internal(const std::vector<ring_rns_poly> &polys);

    comm::protocol_result<std::vector<ring_rns_poly>> unpack_ring_batch_internal(
        std::uint32_t tau, std::uint32_t poly_modulus_degree, std::uint32_t coeff_modulus_count,
        const std::vector<std::uint64_t> &flat, const char *field_name);

} // namespace loglabel

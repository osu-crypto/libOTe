#pragma once

#include "seal/seal.h"
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>
#include "logvole/comm/types.hpp"
#include "logvole/ring_ops.hpp"

namespace logvole
{
    struct zp_crt_context
    {
        ring_ntt_context ring{};
        std::uint32_t plaintext_modulus_bits = 0;
        std::uint64_t plaintext_modulus = 0;
        std::vector<std::uint64_t> delta_mod_qj{};
        std::shared_ptr<seal::SEALContext> batching_context{};
    };

    std::size_t zp_slot_count(const zp_crt_context &ctx);

    std::size_t zp_ring_label_count(const zp_crt_context &ctx, std::size_t zp_label_count);

    comm::protocol_result<zp_crt_context> make_zp_crt_context(
        const ring_params &ring, std::uint32_t plaintext_modulus_bits);

    comm::protocol_result<ring_rns_poly> wrap_zp_batch_crt(
        const zp_crt_context &ctx, const std::vector<std::uint64_t> &labels, bool multiply_by_delta = false,
        std::uint64_t pad_value = 0u, std::uint32_t requested_workers = 1u);

    comm::protocol_result<ring_rns_poly> wrap_zp_constant_crt(
        const zp_crt_context &ctx, std::uint64_t value, bool multiply_by_delta = false,
        std::uint32_t requested_workers = 1u);

    comm::protocol_result<std::vector<ring_rns_poly>> wrap_zp_labels_crt(
        const zp_crt_context &ctx, const std::vector<std::uint64_t> &labels, bool multiply_by_delta = false,
        std::uint64_t pad_value = 0u, std::uint32_t requested_workers = 1u);

    comm::protocol_result<std::vector<std::uint64_t>> unwrap_ring_labels_crt(
        const zp_crt_context &ctx, const std::vector<ring_rns_poly> &labels, std::size_t zp_label_count,
        bool scale_and_round = true, std::uint32_t requested_workers = 1u);
} // namespace logvole

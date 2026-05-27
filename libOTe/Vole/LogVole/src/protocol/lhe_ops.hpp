#pragma once

#include <cstdint>
#include <vector>
#include "loglabel/comm/types.hpp"
#include "loglabel/ring_ops.hpp"

namespace loglabel
{
    comm::protocol_result<std::vector<ring_rns_poly>> build_lhe_public_a(const ring_ntt_context &ctx, std::uint32_t mu);

    comm::protocol_result<ring_rns_poly> multiply_by_g_power(
        const ring_ntt_context &ctx, const ring_rns_poly &poly, std::uint32_t gadget_log_base, std::uint32_t power);

    comm::protocol_result<ring_tensor> lhe_enc1(
        const ring_ntt_context &ctx, const std::vector<ring_rns_poly> &r, const std::vector<ring_rns_poly> &sk1,
        std::uint32_t gadget_log_base, double noise_standard_deviation = 0.0, double noise_max_deviation = 0.0,
        std::uint64_t encryption_noise_seed = 0);

    comm::protocol_result<std::vector<ring_rns_poly>> lhe_apply_ct1(
        const ring_ntt_context &ctx, const ring_tensor &ct1, const ring_rns_poly &digest, std::uint32_t gadget_log_base,
        std::uint32_t tau);

    comm::protocol_result<std::vector<ring_rns_poly>> build_hashed_ct2(
        const ring_ntt_context &ctx, std::uint32_t mu, std::uint64_t nonce);

    comm::protocol_result<std::vector<ring_rns_poly>> lhe_dec(
        const ring_ntt_context &ctx, const std::vector<ring_rns_poly> &cipher, const ring_rns_poly &sk);

    comm::protocol_result<ring_rns_poly> derive_skx(
        const ring_ntt_context &ctx, const std::vector<ring_rns_poly> &sk1, const ring_rns_poly &digest,
        const ring_rns_poly &tbk_prime, std::uint32_t gadget_log_base, std::uint32_t tau);

} // namespace loglabel

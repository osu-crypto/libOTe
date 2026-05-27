#pragma once

#include <cstdint>
#include <vector>
#include "loglabel/comm/types.hpp"
#include "loglabel/ring_ops.hpp"

namespace loglabel
{
    struct lenc_lacct
    {
        std::uint32_t width_padded = 0;
        std::uint32_t levels = 0;
        ring_tensor ct{};
    };

    struct lenc_enc_output
    {
        std::vector<ring_rns_poly> r{};
        lenc_lacct lacct{};
    };

    comm::protocol_result<lenc_enc_output> lenc_enc(
        const ring_ntt_context &ctx, const std::vector<ring_rns_poly> &s, std::uint32_t tau,
        std::uint32_t gadget_log_base, std::uint64_t seed, double noise_standard_deviation = 0.0,
        double noise_max_deviation = 0.0, std::uint64_t encryption_noise_seed = 0);

    comm::protocol_result<ring_rns_poly> lenc_digest(
        const ring_ntt_context &ctx, const std::vector<ring_rns_poly> &x, std::uint32_t tau,
        std::uint32_t gadget_log_base, std::uint32_t width_padded = 0);

    comm::protocol_result<std::vector<ring_rns_poly>> lenc_eval(
        const ring_ntt_context &ctx, const lenc_lacct &lacct, const std::vector<ring_rns_poly> &x, std::uint32_t mu,
        std::uint32_t tau, std::uint32_t gadget_log_base);

} // namespace loglabel

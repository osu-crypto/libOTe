#pragma once

#include "seal/seal.h"
#include <cstdint>
#include <memory>
#include <vector>
#include "loglabel/comm/types.hpp"
#include "loglabel/ring_types.hpp"

namespace loglabel
{
    struct ring_ntt_context
    {
        ring_params params{};
        std::vector<seal::Modulus> moduli{};
        std::shared_ptr<seal::SEALContext> context{};
    };

    comm::protocol_result<void> validate_ring_params(const ring_params &params);

    comm::protocol_result<void> validate_ring_poly_shape(
        const ring_rns_poly &poly, const ring_params &params, const char *name);

    comm::protocol_result<void> validate_ring_batch_shape(
        const std::vector<ring_rns_poly> &polys, const ring_params &params, const char *name);

    comm::protocol_result<ring_ntt_context> make_ring_ntt_context(const ring_params &params);

    comm::protocol_result<void> canonicalize_poly_inplace(ring_rns_poly &poly, const ring_ntt_context &ctx);

    comm::protocol_result<void> forward_ntt_inplace(ring_rns_poly &poly, const ring_ntt_context &ctx);

    comm::protocol_result<void> inverse_ntt_inplace(ring_rns_poly &poly, const ring_ntt_context &ctx);

    comm::protocol_result<ring_rns_poly> dyadic_multiply_add_ntt(
        const ring_rns_poly &a_ntt, const ring_rns_poly &b_ntt, const ring_rns_poly &c_ntt,
        const ring_ntt_context &ctx);

    comm::protocol_result<ring_rns_poly> ring_add(
        const ring_rns_poly &a, const ring_rns_poly &b, const ring_ntt_context &ctx);

    comm::protocol_result<ring_rns_poly> ring_sub(
        const ring_rns_poly &a, const ring_rns_poly &b, const ring_ntt_context &ctx);

    comm::protocol_result<ring_rns_poly> ring_multiply(
        const ring_rns_poly &a, const ring_rns_poly &b, const ring_ntt_context &ctx);

    comm::protocol_result<ring_rns_poly> ring_multiply_scalar(
        const ring_rns_poly &a, std::uint64_t scalar, const ring_ntt_context &ctx);

    comm::protocol_result<std::vector<ring_rns_poly>> gadget_decompose(
        const ring_rns_poly &poly, std::uint32_t base, std::uint32_t tau, const ring_ntt_context &ctx);

    comm::protocol_result<ring_rns_poly> gadget_recompose(
        const std::vector<ring_rns_poly> &digits, std::uint32_t base, const ring_ntt_context &ctx);

    comm::protocol_result<std::vector<ring_rns_poly>> gadget_decompose_bits(
        const ring_rns_poly &poly, std::uint32_t digit_bits, std::uint32_t levels, const ring_ntt_context &ctx);

    comm::protocol_result<ring_rns_poly> gadget_recompose_bits(
        const std::vector<ring_rns_poly> &digits, std::uint32_t digit_bits, const ring_ntt_context &ctx);

    std::vector<std::uint64_t> pack_ring_batch(const std::vector<ring_rns_poly> &polys);

    comm::protocol_result<std::vector<ring_rns_poly>> unpack_ring_batch(
        std::uint32_t count, std::uint32_t poly_modulus_degree, std::uint32_t coeff_modulus_count,
        const std::vector<std::uint64_t> &flat, const char *field_name);

    std::vector<std::uint64_t> pack_ring_tensor(const ring_tensor &tensor);

    comm::protocol_result<ring_tensor> unpack_ring_tensor(
        std::uint32_t rows, std::uint32_t cols, std::uint32_t poly_modulus_degree, std::uint32_t coeff_modulus_count,
        const std::vector<std::uint64_t> &flat, const char *field_name);

    ring_rns_poly derive_uniform_poly_from_nonce(
        const ring_ntt_context &ctx, std::uint64_t nonce, std::uint64_t domain_tag, std::uint32_t index);

    comm::protocol_result<void> add_gaussian_noise_inplace(
        ring_rns_poly &poly, double noise_standard_deviation, double noise_max_deviation, std::uint64_t seed,
        std::uint64_t stream_id, const ring_ntt_context &ctx);

    comm::protocol_result<void> add_poly_error(
        ring_rns_poly &poly, double noise_standard_deviation, double noise_max_deviation, std::uint64_t seed,
        std::uint64_t stream_id, const ring_ntt_context &ctx);

} // namespace loglabel

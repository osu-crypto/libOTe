#pragma once

#include <cstdint>
#include <memory>
#include <vector>
#include "logvole/comm/types.hpp"
#include "logvole/ring_ops.hpp"
#include "logvole/shrinkexpand_types.hpp"

namespace logvole
{
    namespace detail
    {
        struct gpulabel_cuda_stage1_tree_device;
    }

    struct lenc_lacct
    {
        std::uint32_t width_padded = 0;
        std::uint32_t levels = 0;
        ring_tensor ct{};
    };

    struct lenc_enc_output
    {
        std::vector<ring_rns_poly> r{};
        std::vector<ring_rns_poly> r_ntt{};
        lenc_lacct lacct{};
    };

    struct digest_tree
    {
        std::uint32_t width_padded = 0;
        std::uint32_t levels = 0;
        ring_rns_poly digest{};
        std::vector<std::vector<ring_rns_poly>> node_decomp_ntt{};
        std::shared_ptr<detail::gpulabel_cuda_stage1_tree_device> gpu_stage1_tree{};
    };

    std::vector<ring_rns_poly> build_lenc_public_b_ntt(const ring_ntt_context &ctx, std::uint32_t tau);

    comm::protocol_result<digest_tree> build_digest_tree(
        const ring_ntt_context &ctx, const std::vector<ring_rns_poly> &x, std::uint32_t tau,
        std::uint32_t gadget_log_base, std::uint32_t requested_width_padded = 0u,
        const std::vector<ring_rns_poly> *public_b_ntt = nullptr, std::uint32_t requested_workers = 1u);

    comm::protocol_result<lenc_enc_output> lenc_enc(
        const ring_ntt_context &ctx, const std::vector<ring_rns_poly> &s, std::uint32_t tau,
        std::uint32_t gadget_log_base, const sampling_seed_config &sampling_seeds,
        double noise_standard_deviation = 0.0, double noise_max_deviation = 0.0,
        std::uint32_t requested_width_padded = 0u, bool emit_r_coeff_domain = true,
        const std::vector<ring_rns_poly> *public_b_ntt = nullptr, std::uint32_t requested_workers = 1u);

    comm::protocol_result<ring_rns_poly> lenc_digest(
        const ring_ntt_context &ctx, const std::vector<ring_rns_poly> &x, std::uint32_t tau,
        std::uint32_t gadget_log_base, std::uint32_t width_padded = 0);

    comm::protocol_result<digest_tree> build_digest_tree_trunc(
        const ring_ntt_context &ctx, const std::vector<ring_rns_poly> &x, std::uint32_t tau_hi,
        std::uint32_t gadget_log_base, std::uint32_t plaintext_modulus_bits, std::uint32_t requested_width_padded = 0u,
        bool leaf_inputs_are_gadget = false, const std::vector<ring_rns_poly> *public_b_ntt = nullptr,
        std::uint32_t requested_workers = 1u);

    comm::protocol_result<lenc_enc_output> lenc_enc_trunc(
        const ring_ntt_context &ctx, const std::vector<ring_rns_poly> &s, std::uint32_t tau_hi,
        std::uint32_t gadget_log_base, std::uint32_t plaintext_modulus_bits,
        const sampling_seed_config &sampling_seeds,
        double noise_standard_deviation = 0.0, double noise_max_deviation = 0.0,
        std::uint32_t requested_width_padded = 0u, bool emit_r_coeff_domain = true,
        bool leaf_inputs_are_gadget = false,
        const std::vector<ring_rns_poly> *public_b_ntt = nullptr,
        std::uint32_t requested_workers = 1u);

    comm::protocol_result<ring_rns_poly> lenc_digest_trunc(
        const ring_ntt_context &ctx, const std::vector<ring_rns_poly> &x, std::uint32_t tau_hi,
        std::uint32_t gadget_log_base, std::uint32_t plaintext_modulus_bits, std::uint32_t width_padded = 0,
        bool leaf_inputs_are_gadget = false);

    comm::protocol_result<std::vector<ring_rns_poly>> lenc_eval_trunc(
        const ring_ntt_context &ctx, const lenc_lacct &lacct, const std::vector<ring_rns_poly> &x, std::uint32_t mu,
        std::uint32_t tau_hi, std::uint32_t gadget_log_base, std::uint32_t plaintext_modulus_bits,
        bool output_ntt = false, std::uint32_t requested_workers = 1u, bool leaf_inputs_are_gadget = false);

    comm::protocol_result<std::vector<ring_rns_poly>> lenc_eval_trunc(
        const ring_ntt_context &ctx, const lenc_lacct &lacct, const digest_tree &tree, std::uint32_t mu,
        std::uint32_t tau_hi, std::uint32_t gadget_log_base, std::uint32_t plaintext_modulus_bits,
        bool output_ntt = false, std::uint32_t requested_workers = 1u, bool leaf_inputs_are_gadget = false);

    comm::protocol_result<std::vector<ring_rns_poly>> lenc_eval(
        const ring_ntt_context &ctx, const lenc_lacct &lacct, const std::vector<ring_rns_poly> &x, std::uint32_t mu,
        std::uint32_t tau, std::uint32_t gadget_log_base, bool output_ntt = false,
        std::uint32_t requested_workers = 1u);

    comm::protocol_result<std::vector<ring_rns_poly>> lenc_eval(
        const ring_ntt_context &ctx, const lenc_lacct &lacct, const digest_tree &tree, std::uint32_t mu,
        std::uint32_t tau, std::uint32_t gadget_log_base, bool output_ntt = false,
        std::uint32_t requested_workers = 1u);

} // namespace logvole

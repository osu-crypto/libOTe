#pragma once

#include "loglabel/comm/metrics.hpp"
#include "loglabel/ring_types.hpp"

#include <cstdint>
#include <vector>

namespace loglabel
{
    enum class shrinkexpand_mode
    {
        deterministic = 0,
        full_noise = 1
    };

    struct shrinkexpand_params
    {
        ring_params ring{};
        std::uint32_t plaintext_modulus_bits = 0;
        std::uint32_t alpha = 2;
        std::uint32_t mu = 0;
        std::uint32_t gadget_log_base = 0;
        std::uint32_t tau = 0;
        shrinkexpand_mode mode = shrinkexpand_mode::deterministic;
        std::uint64_t noise_seed = 0x5EEDBEEF1234ull;
        std::int64_t noise_bound = 2;
    };

    struct shrinkexpand_lacct
    {
        std::uint32_t width_padded = 0;
        std::uint32_t levels = 0;
        ring_tensor ct{};
    };

    struct shrinkexpand_sender_offline_input
    {
        shrinkexpand_params params{};
        std::vector<ring_rns_poly> s{};
    };

    struct shrinkexpand_receiver_offline_input
    {
        shrinkexpand_params params{};
    };

    struct shrinkexpand_sender_state
    {
        shrinkexpand_params params{};
        std::int64_t effective_noise_bound = 0;
        std::vector<ring_rns_poly> s{};
        std::vector<ring_rns_poly> r{};
        std::vector<ring_rns_poly> sk1{};
        ring_tensor ct1{};
        shrinkexpand_lacct lacct{};
    };

    struct shrinkexpand_receiver_state
    {
        shrinkexpand_params params{};
        std::int64_t effective_noise_bound = 0;
        ring_tensor ct1{};
        shrinkexpand_lacct lacct{};
    };

    struct shrinkexpand_sender_offline_output
    {
        shrinkexpand_sender_state state{};
        comm::comm_counters counters{};
    };

    struct shrinkexpand_receiver_offline_output
    {
        shrinkexpand_receiver_state state{};
        comm::comm_counters counters{};
    };

    struct shrinkexpand_expand_sender_input
    {
        std::uint64_t nonce = 0;
        ring_rns_poly tbk_prime{};
    };

    struct shrinkexpand_expand_receiver_input
    {
        std::uint64_t nonce = 0;
        std::vector<ring_rns_poly> x{};
        ring_rns_poly digest{};
        ring_rns_poly sk_x{};
    };

    struct shrinkexpand_sender_expand_output
    {
        std::vector<ring_rns_poly> tbk{};
    };

    struct shrinkexpand_receiver_expand_output
    {
        std::vector<ring_rns_poly> tbm{};
    };

} // namespace loglabel

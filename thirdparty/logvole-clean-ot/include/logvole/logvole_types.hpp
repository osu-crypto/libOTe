#pragma once

#include <cstdint>
#include <memory>
#include <vector>
#include "logvole/comm/types.hpp"
#include "logvole/ring_types.hpp"
#include "logvole/shrinkexpand_types.hpp"

namespace logvole
{

    struct logvole_params
    {
        shrinkexpand_params shrinkexpand;
        std::uint32_t w = 0;
        std::uint32_t gamma = 0;
        std::uint64_t total_label_count = 0;
    };

    struct logvole_sender_offline_input
    {
        logvole_params params{};
        bool leaf_inputs_are_gadget = false;
        std::vector<ring_rns_poly> sk1{}; // size: gamma (or tau if non-leaf)
    };

    struct logvole_receiver_offline_input
    {
        logvole_params params{};
        bool leaf_inputs_are_gadget = false;
    };

    struct logvole_sender_state
    {
        logvole_params params{};
        std::vector<ring_rns_poly> sk1{};
        shrinkexpand_sender_state shrinkexpand_state{};
        std::vector<ring_rns_poly> root_sk_r_rt{};
        std::vector<ring_rns_poly> root_r1_rt{};
        std::uint32_t root_randomizer_width = 0;
        mutable std::vector<std::uint8_t> golden_seed{};
        mutable std::shared_ptr<ring_rns_poly> root_k_prime_rt{};
        mutable std::shared_ptr<ring_rns_poly> root_k_rt{};
        mutable std::shared_ptr<std::vector<ring_rns_poly>> precomputed_tbk{};
        mutable bool golden_seed_transmitted = false;
        std::unique_ptr<logvole_sender_state> next_level_state;
    };

    struct logvole_receiver_state
    {
        logvole_params params{};
        shrinkexpand_receiver_state shrinkexpand_state{};
        ring_tensor root_ct_r_rt{};
        shrinkexpand_lacct root_lacct_left{};
        ring_tensor root_top_ct{};
        std::vector<ring_rns_poly> root_public_b_star_ntt{};
        std::uint32_t root_randomizer_width = 0;
        mutable std::vector<std::uint8_t> golden_seed{};
        std::unique_ptr<logvole_receiver_state> next_level_state;
    };

    struct logvole_sender_offline_output
    {
        logvole_sender_state state{};
        comm::comm_counters counters{};
    };

    struct logvole_receiver_offline_output
    {
        logvole_receiver_state state{};
        comm::comm_counters counters{};
    };

    struct logvole_sender_precompute_output
    {
        std::vector<std::uint8_t> golden_seed{};
        std::shared_ptr<ring_rns_poly> root_k_prime_rt{};
        std::shared_ptr<ring_rns_poly> root_k_rt{};
        std::shared_ptr<std::vector<ring_rns_poly>> tbk{};
    };

    struct logvole_sender_online_input
    {
        std::uint64_t nonce = 0;
        bool skip_tbk_output = false;
    };

    struct logvole_receiver_online_input
    {
        std::vector<ring_rns_poly> x{}; // size w
    };

    struct logvole_sender_online_output
    {
        comm::comm_counters counters{};
        std::vector<ring_rns_poly> tbk{}; // size w
    };

    struct logvole_receiver_online_output
    {
        comm::comm_counters counters{};
        std::vector<ring_rns_poly> tbm{}; // size w
    };

} // namespace logvole

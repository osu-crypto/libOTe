#pragma once

#include <cstdint>
#include <memory>
#include <vector>
#include "logvole/comm/types.hpp"
#include "logvole/ring_types.hpp"
#include "logvole/shrinkexpand_types.hpp"

namespace logvole
{

    struct seedlabel_params
    {
        shrinkexpand_params shrinkexpand;
        std::uint32_t w = 0;
        std::uint32_t gamma = 0;
        std::uint64_t total_label_count = 0;
    };

    struct seedlabel_sender_offline_input
    {
        seedlabel_params params{};
        std::vector<ring_rns_poly> sk1{}; // size: gamma (or tau if non-leaf)
    };

    struct seedlabel_receiver_offline_input
    {
        seedlabel_params params{};
    };

    struct seedlabel_sender_state
    {
        seedlabel_params params{};
        std::vector<ring_rns_poly> sk1{};
        shrinkexpand_sender_state shrinkexpand_state{};
        mutable std::vector<std::uint8_t> golden_seed{};
        mutable std::shared_ptr<std::vector<ring_rns_poly>> precomputed_tbk{};
        mutable bool golden_seed_transmitted = false;
        std::unique_ptr<seedlabel_sender_state> next_level_state;
    };

    struct seedlabel_receiver_state
    {
        seedlabel_params params{};
        shrinkexpand_receiver_state shrinkexpand_state{};
        mutable std::vector<std::uint8_t> golden_seed{};
        std::unique_ptr<seedlabel_receiver_state> next_level_state;
    };

    struct seedlabel_sender_offline_output
    {
        seedlabel_sender_state state{};
        comm::comm_counters counters{};
    };

    struct seedlabel_receiver_offline_output
    {
        seedlabel_receiver_state state{};
        comm::comm_counters counters{};
    };

    struct seedlabel_sender_precompute_output
    {
        std::vector<std::uint8_t> golden_seed{};
        std::shared_ptr<std::vector<ring_rns_poly>> tbk{};
    };

    struct seedlabel_sender_online_input
    {
        std::uint64_t nonce = 0;
        bool skip_tbk_output = false;
    };

    struct seedlabel_receiver_online_input
    {
        std::vector<ring_rns_poly> x{}; // size w
    };

    struct seedlabel_sender_online_output
    {
        comm::comm_counters counters{};
        std::vector<ring_rns_poly> tbk{}; // size w
    };

    struct seedlabel_receiver_online_output
    {
        comm::comm_counters counters{};
        std::vector<ring_rns_poly> tbm{}; // size w
    };

} // namespace logvole

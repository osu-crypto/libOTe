#pragma once

#include <cstdint>
#include <memory>
#include <vector>
#include "logvole/comm/metrics.hpp"
#include "logvole/comm/types.hpp"
#include "logvole/ring_types.hpp"

namespace logvole
{
    struct digest_tree;

    enum class shrinkexpand_mode
    {
        deterministic = 0,
        full_noise = 1
    };

    struct sampling_seed_config
    {
        static constexpr std::uint64_t default_noise_root = 0x5EEDBEEF1234ull;
        static constexpr std::uint64_t default_ct2_root = 0xB720AA55D1CE5EEDull;

        std::uint64_t noise_root = default_noise_root;
        std::uint64_t ct2_root = default_ct2_root;
    };

    struct shrinkexpand_params
    {
        ring_params ring{};
        std::uint32_t plaintext_modulus_bits = 0;
        std::uint32_t alpha = 2;
        std::uint32_t mu = 0;
        std::uint32_t gadget_log_base = 0;
        std::uint32_t tau = 0;
        std::uint32_t num_worker_threads = 1; // 1 = single-threaded, 0 = auto (hardware concurrency)
        bool truncate_one_gadget_digit = false;
        bool leaf_inputs_are_gadget = false;
        shrinkexpand_mode mode = shrinkexpand_mode::deterministic;
        sampling_seed_config sampling_seeds{};
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
        std::vector<ring_rns_poly> fixed_sk1{};
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
        std::shared_ptr<const std::vector<ring_rns_poly>> public_a_ntt{};
        std::shared_ptr<const std::vector<ring_rns_poly>> public_b_ntt{};
        ring_tensor ct1{};
        shrinkexpand_lacct lacct{};
    };

    struct shrinkexpand_receiver_state
    {
        shrinkexpand_params params{};
        std::int64_t effective_noise_bound = 0;
        std::shared_ptr<const std::vector<ring_rns_poly>> public_a_ntt{};
        std::shared_ptr<const std::vector<ring_rns_poly>> public_b_ntt{};
        ring_tensor ct1{};
        shrinkexpand_lacct lacct{};
    };

    struct shrinkexpand_shrink_output
    {
        ring_rns_poly digest{};
        std::shared_ptr<digest_tree> tree{};
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
        std::shared_ptr<digest_tree> tree{};
    };

    struct shrinkexpand_sender_expand_output
    {
        std::vector<ring_rns_poly> tbk{}; // size w
        comm::comm_counters counters{};
    };

    struct shrinkexpand_receiver_expand_output
    {
        std::vector<ring_rns_poly> tbm{}; // size w
        comm::comm_counters counters{};
    };

} // namespace logvole

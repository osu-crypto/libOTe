#pragma once

#include <shared_mutex>
#include "logvole/comm/types.hpp"
#include "logvole/seedlabel_types.hpp"
#include "logvole/ring_ops.hpp"
#include "logvole/shrinkexpand_backend.hpp"

namespace logvole
{
    struct golden_seed_search_output
    {
        std::vector<std::uint8_t> seed{};
        std::vector<ring_rns_poly> tbk_per_sampled_poly{};
    };

    class seedlabel_backend
    {
    public:
        virtual ~seedlabel_backend() = default;

        virtual const shrinkexpand_backend &get_shrinkexpand_backend() const = 0;

        virtual comm::protocol_result<std::vector<ring_rns_poly>> agg(
            const std::vector<ring_rns_poly> &hat, std::uint32_t w_prime, std::uint32_t tau,
            const ring_params &ring) const = 0;

        virtual comm::protocol_result<std::vector<ring_rns_poly>> gdecomp_and_unbundle(
            const ring_rns_poly &poly, std::uint32_t gadget_log_base, std::uint32_t tau,
            const ring_params &ring) const = 0;

        virtual comm::protocol_result<std::vector<ring_rns_poly>> gdecomp_hi_and_unbundle(
            const ring_rns_poly &poly, std::uint32_t gadget_log_base, std::uint32_t tau_hi,
            const ring_params &ring) const = 0;

        virtual comm::protocol_result<std::vector<ring_rns_poly>> denoise_tbm(
            const std::vector<ring_rns_poly> &tbm_prime, std::uint32_t w_prime, std::uint32_t tau,
            const ring_params &ring) const = 0;

        virtual comm::protocol_result<std::vector<ring_rns_poly>> rep_offline_sender_input(
            const std::vector<ring_rns_poly> &s, std::uint32_t gamma, std::uint32_t alpha, std::uint32_t tau,
            const ring_params &ring) const = 0;

        // Golden seed routines
        virtual comm::protocol_result<void> validate_golden_seed_search(const seedlabel_params &params) const = 0;

        virtual comm::protocol_result<golden_seed_search_output> find_golden_seed(
            const seedlabel_params &params, const std::vector<ring_rns_poly> &sk2_per_instance) const = 0;

        virtual comm::protocol_result<bool> validate_golden_seed_candidate(
            const seedlabel_params &params, const std::vector<ring_rns_poly> &tbk_per_sampled_poly) const = 0;

        virtual comm::protocol_result<std::vector<ring_rns_poly>> sample_ct2_from_seed(
            const sampling_seed_config &sampling_seeds, const std::vector<std::uint8_t> &seed,
            std::uint32_t instance_idx, std::uint32_t coeff_count, const ring_params &ring) const = 0;
    };

    class seedlabel_seal_backend : public seedlabel_backend
    {
    public:
        seedlabel_seal_backend();

        virtual ~seedlabel_seal_backend() = default;

        const shrinkexpand_backend &get_shrinkexpand_backend() const override;

        comm::protocol_result<std::vector<ring_rns_poly>> agg(
            const std::vector<ring_rns_poly> &hat, std::uint32_t w_prime, std::uint32_t tau,
            const ring_params &ring) const override;

        comm::protocol_result<std::vector<ring_rns_poly>> gdecomp_and_unbundle(
            const ring_rns_poly &poly, std::uint32_t gadget_log_base, std::uint32_t tau,
            const ring_params &ring) const override;

        comm::protocol_result<std::vector<ring_rns_poly>> gdecomp_hi_and_unbundle(
            const ring_rns_poly &poly, std::uint32_t gadget_log_base, std::uint32_t tau_hi,
            const ring_params &ring) const override;

        comm::protocol_result<std::vector<ring_rns_poly>> denoise_tbm(
            const std::vector<ring_rns_poly> &tbm_prime, std::uint32_t w_prime, std::uint32_t tau,
            const ring_params &ring) const override;

        comm::protocol_result<std::vector<ring_rns_poly>> rep_offline_sender_input(
            const std::vector<ring_rns_poly> &s, std::uint32_t gamma, std::uint32_t alpha, std::uint32_t tau,
            const ring_params &ring) const override;

        comm::protocol_result<void> validate_golden_seed_search(const seedlabel_params &params) const override;

        comm::protocol_result<golden_seed_search_output> find_golden_seed(
            const seedlabel_params &params, const std::vector<ring_rns_poly> &sk2_per_instance) const override;

        comm::protocol_result<bool> validate_golden_seed_candidate(
            const seedlabel_params &params, const std::vector<ring_rns_poly> &tbk_per_sampled_poly) const override;

        comm::protocol_result<std::vector<ring_rns_poly>> sample_ct2_from_seed(
            const sampling_seed_config &sampling_seeds, const std::vector<std::uint8_t> &seed,
            std::uint32_t instance_idx, std::uint32_t coeff_count, const ring_params &ring) const override;

    private:
        comm::protocol_result<ring_ntt_context> get_ntt_context(const ring_params &ring) const;

        const shrinkexpand_seal_backend se_backend_;

        mutable std::optional<ring_params> cached_ring_;
        mutable std::optional<ring_ntt_context> cached_ctx_;
        mutable std::shared_mutex cache_mutex_;
    };

} // namespace logvole

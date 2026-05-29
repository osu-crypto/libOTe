#pragma once

#include "seal/seal.h"
#include <atomic>
#include <cstdint>
#include <memory>
#include <vector>
#include "logvole/comm/types.hpp"
#include "logvole/ring_types.hpp"

namespace logvole
{
    struct sampling_seed_config;

    struct ring_ops_stats
    {
        static inline std::atomic<std::uint64_t> reset_epoch{ 0u };

        std::atomic<std::uint64_t> ntt_count{ 0 };
        std::atomic<std::uint64_t> intt_count{ 0 };
        std::atomic<std::uint64_t> add_count{ 0 };
        std::atomic<std::uint64_t> sub_count{ 0 };
        std::atomic<std::uint64_t> mul_count{ 0 };
        std::atomic<std::uint64_t> mul_scalar_count{ 0 };
        std::atomic<std::uint64_t> dyadic_mul_add_count{ 0 };
        std::atomic<std::uint64_t> gadget_decompose_count{ 0 };
        std::atomic<std::uint64_t> gadget_recompose_count{ 0 };
        std::atomic<std::uint64_t> prng_poly_count{ 0 };
        std::atomic<std::uint64_t> error_add_count{ 0 };

        void reset()
        {
            ntt_count.store(0u, std::memory_order_relaxed);
            intt_count.store(0u, std::memory_order_relaxed);
            add_count.store(0u, std::memory_order_relaxed);
            sub_count.store(0u, std::memory_order_relaxed);
            mul_count.store(0u, std::memory_order_relaxed);
            mul_scalar_count.store(0u, std::memory_order_relaxed);
            dyadic_mul_add_count.store(0u, std::memory_order_relaxed);
            gadget_decompose_count.store(0u, std::memory_order_relaxed);
            gadget_recompose_count.store(0u, std::memory_order_relaxed);
            prng_poly_count.store(0u, std::memory_order_relaxed);
            error_add_count.store(0u, std::memory_order_relaxed);
            reset_epoch.fetch_add(1u, std::memory_order_relaxed);
        }
    };

    inline ring_ops_stats global_ring_ops_stats;

    void flush_ring_ops_thread_local_stats();

    struct timing_stats
    {
        std::atomic<std::uint64_t> sender_wait_time_us{ 0 };
        std::atomic<std::uint64_t> receiver_wait_time_us{ 0 };
        std::atomic<std::uint64_t> sender_async_wait_time_us{ 0 };
        std::atomic<std::uint64_t> receiver_async_wait_time_us{ 0 };
        std::atomic<std::uint64_t> sender_compute_time_us{ 0 };
        std::atomic<std::uint64_t> receiver_compute_time_us{ 0 };

        std::atomic<std::uint64_t> lenc_enc_time_us{ 0 };
        std::atomic<std::uint64_t> lenc_dec_time_us{ 0 };
        std::atomic<std::uint64_t> lhe_enc_time_us{ 0 };
        std::atomic<std::uint64_t> lhe_dec_time_us{ 0 };
        std::atomic<std::uint64_t> shrink_time_us{ 0 };
        std::atomic<std::uint64_t> expand_time_us{ 0 };
        std::atomic<std::uint64_t> poly_sampling_time_us{ 0 };
        std::atomic<std::uint64_t> gold_sampling_time_us{ 0 };
        std::atomic<std::uint64_t> seed_sampling_time_us{ 0 };
        std::atomic<std::uint64_t> seed_attempt_time_us{ 0 };
        std::atomic<std::uint64_t> seed_attempt_count{ 0 };

        std::atomic<std::uint64_t> gdecomp_unbundle_time_us{ 0 };
        std::atomic<std::uint64_t> denoise_tbm_time_us{ 0 };
        std::atomic<std::uint64_t> agg_time_us{ 0 };

        void reset()
        {
            sender_wait_time_us.store(0u, std::memory_order_relaxed);
            receiver_wait_time_us.store(0u, std::memory_order_relaxed);
            sender_async_wait_time_us.store(0u, std::memory_order_relaxed);
            receiver_async_wait_time_us.store(0u, std::memory_order_relaxed);
            sender_compute_time_us.store(0u, std::memory_order_relaxed);
            receiver_compute_time_us.store(0u, std::memory_order_relaxed);
            lenc_enc_time_us.store(0u, std::memory_order_relaxed);
            lenc_dec_time_us.store(0u, std::memory_order_relaxed);
            lhe_enc_time_us.store(0u, std::memory_order_relaxed);
            lhe_dec_time_us.store(0u, std::memory_order_relaxed);
            shrink_time_us.store(0u, std::memory_order_relaxed);
            expand_time_us.store(0u, std::memory_order_relaxed);
            poly_sampling_time_us.store(0u, std::memory_order_relaxed);
            gold_sampling_time_us.store(0u, std::memory_order_relaxed);
            seed_sampling_time_us.store(0u, std::memory_order_relaxed);
            seed_attempt_time_us.store(0u, std::memory_order_relaxed);
            seed_attempt_count.store(0u, std::memory_order_relaxed);
            gdecomp_unbundle_time_us.store(0u, std::memory_order_relaxed);
            denoise_tbm_time_us.store(0u, std::memory_order_relaxed);
            agg_time_us.store(0u, std::memory_order_relaxed);
        }
    };

    inline timing_stats global_timing_stats;

    struct auto_timer
    {
        std::atomic<std::uint64_t> &stat;
        std::chrono::steady_clock::time_point start;
        auto_timer(std::atomic<std::uint64_t> &s) : stat(s), start(std::chrono::steady_clock::now())
        {}
        ~auto_timer()
        {
            auto end = std::chrono::steady_clock::now();
            stat.fetch_add(
                static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(end - start).count()),
                std::memory_order_relaxed);
        }
    };

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

    comm::protocol_result<void> dyadic_multiply_add_ntt_inplace(
        const ring_rns_poly &a_ntt, const ring_rns_poly &b_ntt, ring_rns_poly &c_ntt, const ring_ntt_context &ctx);

    comm::protocol_result<ring_rns_poly> ring_add(
        const ring_rns_poly &a, const ring_rns_poly &b, const ring_ntt_context &ctx);

    comm::protocol_result<void> ring_add_inplace(ring_rns_poly &a, const ring_rns_poly &b, const ring_ntt_context &ctx);

    comm::protocol_result<ring_rns_poly> ring_sub(
        const ring_rns_poly &a, const ring_rns_poly &b, const ring_ntt_context &ctx);

    comm::protocol_result<void> ring_sub_inplace(ring_rns_poly &a, const ring_rns_poly &b, const ring_ntt_context &ctx);

    comm::protocol_result<ring_rns_poly> ring_multiply(
        const ring_rns_poly &a, const ring_rns_poly &b, const ring_ntt_context &ctx);

    comm::protocol_result<void> ring_multiply_inplace(
        ring_rns_poly &a, const ring_rns_poly &b, const ring_ntt_context &ctx);

    comm::protocol_result<ring_rns_poly> ring_multiply_scalar(
        const ring_rns_poly &a, std::uint64_t scalar, const ring_ntt_context &ctx);

    comm::protocol_result<void> ring_multiply_scalar_inplace(
        ring_rns_poly &a, std::uint64_t scalar, const ring_ntt_context &ctx);

    comm::protocol_result<std::vector<ring_rns_poly>> gadget_decompose(
        const ring_rns_poly &poly, std::uint32_t base, std::uint32_t tau, const ring_ntt_context &ctx);

    comm::protocol_result<ring_rns_poly> gadget_recompose(
        const std::vector<ring_rns_poly> &digits, std::uint32_t base, const ring_ntt_context &ctx);

    comm::protocol_result<std::vector<ring_rns_poly>> gadget_decompose_bits(
        const ring_rns_poly &poly, std::uint32_t digit_bits, std::uint32_t levels, const ring_ntt_context &ctx,
        std::uint32_t requested_workers = 1u);

    comm::protocol_result<std::vector<ring_rns_poly>> gadget_decompose_bits_range(
        const ring_rns_poly &poly, std::uint32_t digit_bits, std::uint32_t start_level, std::uint32_t levels,
        const ring_ntt_context &ctx, std::uint32_t requested_workers = 1u);

    comm::protocol_result<std::vector<ring_rns_poly>> gadget_decompose_bits_range_centered(
        const ring_rns_poly &poly, std::uint32_t digit_bits, std::uint32_t start_level, std::uint32_t levels,
        const ring_ntt_context &ctx, std::uint32_t requested_workers = 1u);

    comm::protocol_result<ring_rns_poly> gadget_recompose_bits(
        const std::vector<ring_rns_poly> &digits, std::uint32_t digit_bits, const ring_ntt_context &ctx);

    std::vector<std::uint64_t> pack_ring_batch(const std::vector<ring_rns_poly> &polys);

    comm::protocol_result<std::vector<ring_rns_poly>> unpack_ring_batch(
        std::uint32_t count, std::uint32_t poly_modulus_degree, std::uint32_t coeff_modulus_count,
        const std::vector<std::uint64_t> &flat, const char *field_name, std::uint32_t requested_workers = 1u);

    std::vector<std::uint64_t> pack_ring_tensor(const ring_tensor &tensor);

    comm::protocol_result<ring_tensor> unpack_ring_tensor(
        std::uint32_t rows, std::uint32_t cols, std::uint32_t poly_modulus_degree, std::uint32_t coeff_modulus_count,
        const std::vector<std::uint64_t> &flat, const char *field_name, std::uint32_t requested_workers = 1u);

    ring_rns_poly derive_uniform_poly_from_nonce(
        const ring_ntt_context &ctx, std::uint64_t nonce, std::uint64_t domain_tag, std::uint32_t index);

    ring_rns_poly derive_uniform_poly_from_nonce_ntt(
        const ring_ntt_context &ctx, std::uint64_t nonce, std::uint64_t domain_tag, std::uint32_t index);

    std::vector<ring_rns_poly> derive_uniform_poly_batch_from_nonce(
        const ring_ntt_context &ctx, std::uint64_t nonce, std::uint64_t domain_tag, std::uint32_t count);

    std::vector<ring_rns_poly> derive_uniform_poly_batch_from_nonce_ntt(
        const ring_ntt_context &ctx, std::uint64_t nonce, std::uint64_t domain_tag, std::uint32_t count);

    std::vector<ring_rns_poly> derive_uniform_poly_batch_from_nonce_list(
        const ring_ntt_context &ctx, const std::vector<std::uint64_t> &nonces, std::uint64_t domain_tag,
        std::uint32_t per_nonce_count, std::uint32_t requested_workers = 0u);

    comm::protocol_result<void> derive_uniform_poly_batch_from_nonce_list_inplace(
        const ring_ntt_context &ctx, const std::vector<std::uint64_t> &nonces, std::uint64_t domain_tag,
        std::uint32_t per_nonce_count, std::vector<ring_rns_poly> &out, std::uint32_t requested_workers = 0u);

    std::uint64_t combine_seed_public(std::uint64_t value);
    std::uint64_t derive_deterministic_seed_material(
        std::uint64_t root, std::uint64_t domain_tag, std::uint64_t value0 = 0u, std::uint64_t value1 = 0u,
        std::uint64_t value2 = 0u, std::uint64_t value3 = 0u);
    std::uint64_t derive_noise_seed(
        const sampling_seed_config &config, std::uint64_t domain_tag, std::uint64_t stream_id = 0u,
        std::uint64_t salt0 = 0u, std::uint64_t salt1 = 0u);
    std::uint64_t derive_ct2_nonce(
        const sampling_seed_config &config, std::uint64_t nonce, std::uint64_t coeff_count = 0u);
    std::uint64_t derive_seed_instance_nonce(
        const sampling_seed_config &config, const std::vector<std::uint8_t> &seed, std::uint64_t instance_idx,
        std::uint64_t fallback_nonce = 0u);

    comm::protocol_result<void> add_gaussian_noise_inplace(
        ring_rns_poly &poly, double noise_standard_deviation, double noise_max_deviation, std::uint64_t seed,
        std::uint64_t stream_id, const ring_ntt_context &ctx);

    comm::protocol_result<void> add_poly_error(
        ring_rns_poly &poly, double noise_standard_deviation, double noise_max_deviation, std::uint64_t seed,
        std::uint64_t stream_id, const ring_ntt_context &ctx);

} // namespace logvole

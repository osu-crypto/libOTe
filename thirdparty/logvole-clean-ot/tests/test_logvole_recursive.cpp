#include "seal/util/rns.h"
#include <algorithm>
#include <atomic>
#include <cmath>
#include <gtest/gtest.h>
#include <limits>
#include <thread>
#include "../src/protocol/cache_test_hooks.hpp"
#include "../src/protocol/lhe_ops.hpp"
#include "../src/protocol/runtime_cache_scope.hpp"
#include "logvole/comm/channel.hpp"
#include "logvole/ring_ops.hpp"
#include "logvole/shrinkexpand_noise.hpp"
#include "logvole/shrinkexpand_protocol.hpp"
#include "logvole/shrinkexpand_spec.hpp"
#include "logvole/logvole_backend.hpp"
#include "logvole/logvole_protocol.hpp"

using namespace logvole;
using namespace logvole::comm;

namespace
{
    logvole_params make_params(std::uint32_t num_levels, std::uint32_t worker_threads = 1u)
    {
        logvole_params params{};

        // Best feasible profile from logvole_optimizer.py:
        // n=8192, log_q=220, log_p=55, log_g=110, m=2.
        params.shrinkexpand.ring.poly_modulus_degree = 8192;
        params.shrinkexpand.ring.coeff_modulus_bits = { 55, 55, 55, 55 };
        params.shrinkexpand.plaintext_modulus_bits = 55;
        params.shrinkexpand.mode = shrinkexpand_mode::full_noise;
        params.shrinkexpand.sampling_seeds.noise_root = 0xBAD5EEDu;
        params.shrinkexpand.noise_bound = 2;

        params.shrinkexpand.alpha = 2;
        params.shrinkexpand.gadget_log_base = 110;
        params.shrinkexpand.num_worker_threads = worker_threads;

        std::uint32_t log_q = 0;
        for (auto bits : params.shrinkexpand.ring.coeff_modulus_bits)
        {
            log_q += bits;
        }

        params.shrinkexpand.tau =
            (log_q + params.shrinkexpand.gadget_log_base - 1) / params.shrinkexpand.gadget_log_base;
        std::uint32_t rho = params.shrinkexpand.ring.coeff_modulus_bits.size();
        params.shrinkexpand.mu = params.shrinkexpand.alpha * params.shrinkexpand.tau * rho;
        const std::uint32_t tau_hi = params.shrinkexpand.tau - 1u;
        const std::uint32_t mu_hi = params.shrinkexpand.alpha * tau_hi * rho;

        std::uint32_t w_prime = 1;
        for (std::uint32_t i = 1; i < num_levels; ++i)
        {
            w_prime *= params.shrinkexpand.alpha;
        }
        params.w = w_prime * mu_hi;

        params.gamma = 1;

        return params;
    }

    logvole_params make_leaf_tau_one_params()
    {
        logvole_params params{};
        params.shrinkexpand.ring.poly_modulus_degree = 16384;
        params.shrinkexpand.ring.coeff_modulus_bits = { 55, 55, 55, 55, 55 };
        params.shrinkexpand.plaintext_modulus_bits = 55;
        params.shrinkexpand.mode = shrinkexpand_mode::deterministic;
        params.shrinkexpand.sampling_seeds.noise_root = 0xBAD5EEDu;
        params.shrinkexpand.noise_bound = 0;
        params.shrinkexpand.alpha = 2;
        params.shrinkexpand.gadget_log_base = 110;
        params.shrinkexpand.num_worker_threads = 1u;

        std::uint32_t log_q = 0u;
        for (int bits : params.shrinkexpand.ring.coeff_modulus_bits)
        {
            log_q += static_cast<std::uint32_t>(bits);
        }

        params.shrinkexpand.tau =
            (log_q + params.shrinkexpand.gadget_log_base - 1u) / params.shrinkexpand.gadget_log_base;
        const std::uint32_t rho = static_cast<std::uint32_t>(params.shrinkexpand.ring.coeff_modulus_bits.size());
        params.shrinkexpand.mu = params.shrinkexpand.alpha * params.shrinkexpand.tau * rho;
        params.w = 6u;
        params.gamma = 1u;
        return params;
    }

    protocol_result<std::vector<ring_rns_poly>> subtract_batches(
        const ring_ntt_context &ctx, const std::vector<ring_rns_poly> &a, const std::vector<ring_rns_poly> &b);

    bool ring_batches_equal(const std::vector<ring_rns_poly> &a, const std::vector<ring_rns_poly> &b)
    {
        if (a.size() != b.size())
        {
            return false;
        }

        for (std::size_t i = 0; i < a.size(); ++i)
        {
            if (a[i].coeffs != b[i].coeffs)
            {
                return false;
            }
        }

        return true;
    }

    protocol_result<std::vector<ring_rns_poly>> negate_batch(
        const ring_ntt_context &ctx, const std::vector<ring_rns_poly> &in)
    {
        std::vector<ring_rns_poly> out;
        out.reserve(in.size());
        ring_rns_poly zero{};
        zero.coeffs.assign(ring_poly_coeff_count(ctx.params), 0u);
        for (const auto &poly : in)
        {
            auto neg = ring_sub(zero, poly, ctx);
            if (!neg)
            {
                return protocol_result<std::vector<ring_rns_poly>>::failure(neg.error(), neg.message());
            }
            out.push_back(std::move(neg.value()));
        }
        return protocol_result<std::vector<ring_rns_poly>>::success(std::move(out));
    }

    ring_rns_poly sample_small_plain_poly(
        const ring_ntt_context &ctx, std::uint64_t seed, std::uint32_t poly_idx, std::uint32_t bit_count)
    {
        ring_rns_poly out{};
        const std::size_t n = ctx.params.poly_modulus_degree;
        const std::size_t rho = ctx.moduli.size();
        out.coeffs.assign(n * rho, 0u);

        const std::uint64_t mask = (bit_count >= 63u) ? std::numeric_limits<std::uint64_t>::max()
                                                      : ((static_cast<std::uint64_t>(1u) << bit_count) - 1u);
        std::uint64_t state = combine_seed_public(seed ^ static_cast<std::uint64_t>(poly_idx));
        for (std::size_t coeff_idx = 0; coeff_idx < n; ++coeff_idx)
        {
            state = combine_seed_public(state + static_cast<std::uint64_t>(coeff_idx) + 0x9E3779B97F4A7C15ull);
            const std::uint64_t value = state & mask;
            for (std::size_t mod_idx = 0; mod_idx < rho; ++mod_idx)
            {
                out.coeffs[mod_idx * n + coeff_idx] = value % ctx.moduli[mod_idx].value();
            }
        }

        return out;
    }

    void check_noise_tolerance(
        const ring_ntt_context &ctx, const std::vector<ring_rns_poly> &actual,
        const std::vector<ring_rns_poly> &expected, const logvole_params &params)
    {
        const std::size_t n = params.shrinkexpand.ring.poly_modulus_degree;
        const std::size_t coeff_mod_count = params.shrinkexpand.ring.coeff_modulus_bits.size();

        auto context_data = ctx.context->key_context_data();
        seal::util::RNSBase full_base(context_data->parms().coeff_modulus(), seal::MemoryManager::GetPool());
        seal::util::Pointer<std::uint64_t> composed_poly =
            seal::util::allocate_poly(n, coeff_mod_count, seal::MemoryManager::GetPool());
        auto coeff_mpi = seal::util::allocate_uint(coeff_mod_count, seal::MemoryManager::GetPool());
        auto compute_max_log2 = [&](const std::vector<ring_rns_poly> &batch) -> long double {
            long double max_log2 = 0.0L;
            for (const auto &poly : batch)
            {
                std::copy(poly.coeffs.begin(), poly.coeffs.end(), composed_poly.get());
                full_base.compose_array(composed_poly.get(), n, seal::MemoryManager::GetPool());
                for (std::size_t i = 0; i < n; ++i)
                {
                    const std::uint64_t *val_ptr = composed_poly.get() + i * coeff_mod_count;
                    int bit_count_pos = seal::util::get_significant_bit_count_uint(val_ptr, coeff_mod_count);

                    seal::util::sub_uint(full_base.base_prod(), val_ptr, coeff_mod_count, coeff_mpi.get());
                    int bit_count_neg = seal::util::get_significant_bit_count_uint(coeff_mpi.get(), coeff_mod_count);

                    int bit_count = std::min(bit_count_pos, bit_count_neg);
                    max_log2 = std::max<long double>(max_log2, bit_count);
                }
            }
            return max_log2;
        };

        auto residual = subtract_batches(ctx, actual, expected);
        ASSERT_TRUE(residual) << residual.message();
        const long double max_log2_pos = compute_max_log2(residual.value());

        auto expected_neg = negate_batch(ctx, expected);
        ASSERT_TRUE(expected_neg) << expected_neg.message();
        auto residual_neg = subtract_batches(ctx, actual, expected_neg.value());
        ASSERT_TRUE(residual_neg) << residual_neg.message();
        const long double max_log2_neg = compute_max_log2(residual_neg.value());

        const long double max_log2 = std::min(max_log2_pos, max_log2_neg);

        std::uint32_t log_q = 0u;
        for (int bits : params.shrinkexpand.ring.coeff_modulus_bits)
        {
            log_q += static_cast<std::uint32_t>(bits);
        }

        ASSERT_LT(params.shrinkexpand.plaintext_modulus_bits, log_q);
        double max_noise_allowed = static_cast<double>(log_q - params.shrinkexpand.plaintext_modulus_bits);
        if (params.shrinkexpand.mode == shrinkexpand_mode::deterministic)
        {
            const std::uint32_t tau_hi = (params.shrinkexpand.tau > 0u) ? (params.shrinkexpand.tau - 1u) : 0u;
            const std::uint32_t rho = static_cast<std::uint32_t>(params.shrinkexpand.ring.coeff_modulus_bits.size());
            const std::uint32_t mu_hi = params.shrinkexpand.alpha * tau_hi * rho;
            const long double path_len = 1.0L + std::log2((mu_hi > 1u) ? static_cast<long double>(mu_hi) : 1.0L);
            const long double truncation_bound_log2 = static_cast<long double>(params.shrinkexpand.gadget_log_base) +
                                                      std::log2(static_cast<long double>(n)) + std::log2(path_len);
            EXPECT_LT(max_log2, truncation_bound_log2 + 1.0L);
        }
        else
        {
            EXPECT_GT(max_log2, 0);
            EXPECT_LT(max_log2, max_noise_allowed);
        }
    }

    protocol_result<std::vector<ring_rns_poly>> compute_expected_s_mul_x(
        const ring_ntt_context &ctx, const std::vector<ring_rns_poly> &s, const std::vector<ring_rns_poly> &x)
    {
        std::vector<ring_rns_poly> out;
        out.reserve(s.size());
        for (std::size_t i = 0; i < s.size(); ++i)
        {
            auto prod = ring_multiply(s[i], x[i], ctx);
            if (!prod)
                return protocol_result<std::vector<ring_rns_poly>>::failure(prod.error(), prod.message());
            out.push_back(std::move(prod.value()));
        }
        return protocol_result<std::vector<ring_rns_poly>>::success(std::move(out));
    }

    protocol_result<std::vector<ring_rns_poly>> subtract_batches(
        const ring_ntt_context &ctx, const std::vector<ring_rns_poly> &a, const std::vector<ring_rns_poly> &b)
    {
        std::vector<ring_rns_poly> out;
        out.reserve(a.size());
        for (std::size_t i = 0; i < a.size(); ++i)
        {
            auto sub = ring_sub(a[i], b[i], ctx);
            if (!sub)
                return protocol_result<std::vector<ring_rns_poly>>::failure(sub.error(), sub.message());
            out.push_back(std::move(sub.value()));
        }
        return protocol_result<std::vector<ring_rns_poly>>::success(std::move(out));
    }
} // namespace

void run_logvole_test(
    std::uint32_t num_levels, std::uint32_t worker_threads = 1u, std::uint64_t expected_sender_online_rounds = 0u,
    bool enable_precompute = false)
{
    constexpr std::uint64_t protocol_id = 0x78u;
    constexpr std::uint64_t version = 1u;
    static std::atomic<std::uint64_t> session_cnt{ 0x889u };
    std::uint64_t session_id = session_cnt++;
    const auto timeout = std::chrono::milliseconds(600000);

    auto params = make_params(num_levels, worker_threads);

    auto pair_result = make_in_memory_channel_pair(protocol_id, version, session_id, timeout);
    ASSERT_TRUE(pair_result) << pair_result.message();

    auto channels = std::move(pair_result.value());
    any_channel sender_channel = std::move(channels.first);
    any_channel receiver_channel = std::move(channels.second);

    const std::uint64_t cache_run_id = allocate_protocol_cache_run_id();
    logvole_seal_backend sender_backend{};
    logvole_seal_backend receiver_backend{};

    auto ctx_result = make_ring_ntt_context(params.shrinkexpand.ring);
    ASSERT_TRUE(ctx_result) << ctx_result.message();

    logvole_sender_offline_input sender_input{};
    sender_input.params = params;
    const std::uint32_t keys_to_gen = std::max<std::uint32_t>(1u, params.gamma);
    for (std::uint32_t i = 0; i < keys_to_gen; ++i)
    {
        sender_input.sk1.push_back(derive_uniform_poly_from_nonce(ctx_result.value(), 0x1111u, 0xAAA0u, i));
    }

    logvole_receiver_offline_input receiver_input{};
    receiver_input.params = params;

    protocol_result<logvole_sender_offline_output> sender_offline =
        protocol_result<logvole_sender_offline_output>::failure(protocol_errc::io_error, "not run");
    protocol_result<logvole_receiver_offline_output> receiver_offline =
        protocol_result<logvole_receiver_offline_output>::failure(protocol_errc::io_error, "not run");

    std::thread receiver_thread([&]() mutable {
        scoped_protocol_cache_scope cache_scope(protocol_cache_role::receiver, cache_run_id);
        receiver_offline =
            run_logvole_receiver_offline(std::move(receiver_channel), receiver_input, receiver_backend);
    });

    std::thread sender_thread([&]() mutable {
        scoped_protocol_cache_scope cache_scope(protocol_cache_role::sender, cache_run_id);
        sender_offline = run_logvole_sender_offline(std::move(sender_channel), sender_input, sender_backend);
    });

    sender_thread.join();
    receiver_thread.join();

    ASSERT_TRUE(sender_offline) << sender_offline.message();
    ASSERT_TRUE(receiver_offline) << receiver_offline.message();

    EXPECT_EQ(sender_offline.value().state.params.w, params.w);
    EXPECT_EQ(receiver_offline.value().state.params.w, params.w);

    if (enable_precompute)
    {
        auto sender_precompute = run_logvole_sender_precompute(sender_offline.value().state, sender_backend);
        ASSERT_TRUE(sender_precompute) << sender_precompute.message();
        ASSERT_FALSE(sender_precompute.value().golden_seed.empty());
        ASSERT_TRUE(static_cast<bool>(sender_precompute.value().tbk));
        ASSERT_EQ(sender_precompute.value().tbk->size(), params.w);

        auto sender_precompute_cached = run_logvole_sender_precompute(sender_offline.value().state, sender_backend);
        ASSERT_TRUE(sender_precompute_cached) << sender_precompute_cached.message();
        ASSERT_EQ(sender_precompute_cached.value().golden_seed, sender_precompute.value().golden_seed);
        ASSERT_EQ(sender_precompute_cached.value().tbk.get(), sender_precompute.value().tbk.get());
    }

    logvole_sender_online_input sender_online_input{};
    logvole_receiver_online_input receiver_online_input{};

    receiver_online_input.x.resize(params.w);
    const std::uint32_t plain_sample_bits = std::min<std::uint32_t>(20u, params.shrinkexpand.plaintext_modulus_bits);
    for (std::uint32_t i = 0; i < params.w; ++i)
    {
        receiver_online_input.x[i] = sample_small_plain_poly(ctx_result.value(), 0x2222u, i, plain_sample_bits);
    }

    protocol_result<logvole_sender_online_output> sender_online =
        protocol_result<logvole_sender_online_output>::failure(protocol_errc::io_error, "not run");
    protocol_result<logvole_receiver_online_output> receiver_online =
        protocol_result<logvole_receiver_online_output>::failure(protocol_errc::io_error, "not run");

    auto pair_result_online = make_in_memory_channel_pair(protocol_id, version, session_id + 1000, timeout);
    ASSERT_TRUE(pair_result_online) << pair_result_online.message();

    auto channels_online = std::move(pair_result_online.value());
    any_channel sender_channel_online = std::move(channels_online.first);
    any_channel receiver_channel_online = std::move(channels_online.second);

    std::thread receiver_online_thread([&]() mutable {
        scoped_protocol_cache_scope cache_scope(protocol_cache_role::receiver, cache_run_id);
        receiver_online = run_logvole_receiver_online(
            std::move(receiver_channel_online), receiver_offline.value().state, receiver_online_input,
            receiver_backend);
    });

    std::thread sender_online_thread([&]() mutable {
        scoped_protocol_cache_scope cache_scope(protocol_cache_role::sender, cache_run_id);
        sender_online = run_logvole_sender_online(
            std::move(sender_channel_online), sender_offline.value().state, sender_online_input, sender_backend);
    });

    sender_online_thread.join();
    receiver_online_thread.join();

    ASSERT_TRUE(sender_online) << sender_online.message();
    ASSERT_TRUE(receiver_online) << receiver_online.message();

    if (expected_sender_online_rounds != 0u)
    {
        EXPECT_EQ(sender_online.value().counters.rounds_completed, expected_sender_online_rounds);
    }
    if (enable_precompute)
    {
        EXPECT_GT(sender_online.value().counters.rounds_completed, 0u);
        EXPECT_GT(sender_online.value().counters.wire_bytes_s2r_sent, 0u);
        EXPECT_GT(sender_online.value().counters.wire_bytes_r2s_recv, 0u);
    }

    auto tbm_minus_tbk = subtract_batches(ctx_result.value(), receiver_online.value().tbm, sender_online.value().tbk);
    ASSERT_TRUE(tbm_minus_tbk) << tbm_minus_tbk.message();

    std::vector<ring_rns_poly> sk1_w;
    const std::uint32_t tau_hi = params.shrinkexpand.tau - 1u;
    const std::uint32_t rho = static_cast<std::uint32_t>(params.shrinkexpand.ring.coeff_modulus_bits.size());
    const std::uint32_t mu_hi = params.shrinkexpand.alpha * tau_hi * rho;
    auto rep_out = sender_backend.rep_offline_sender_input(
        sender_input.sk1, params.gamma, params.shrinkexpand.alpha, tau_hi, params.shrinkexpand.ring);
    ASSERT_TRUE(rep_out) << rep_out.message();

    std::uint32_t w_double_prime = (params.w + mu_hi - 1u) / mu_hi;
    for (std::uint32_t i = 0; i < w_double_prime; ++i)
    {
        for (const auto &p : rep_out.value())
        {
            if (sk1_w.size() < params.w)
                sk1_w.push_back(p);
        }
    }

    const std::size_t out_w = tbm_minus_tbk.value().size();
    if (sk1_w.size() > out_w)
    {
        sk1_w.resize(out_w);
    }

    std::vector<ring_rns_poly> x_w;
    for (std::size_t i = 0; i < out_w; ++i)
    {
        x_w.push_back(receiver_online_input.x[i]);
    }

    auto expected = compute_expected_s_mul_x(ctx_result.value(), sk1_w, x_w);
    ASSERT_TRUE(expected) << expected.message();

    check_noise_tolerance(ctx_result.value(), tbm_minus_tbk.value(), expected.value(), params);
}

void run_logvole_repeated_online_test(std::uint32_t num_levels, std::uint32_t worker_threads = 1u)
{
    constexpr std::uint64_t protocol_id = 0x7Bu;
    constexpr std::uint64_t version = 1u;
    static std::atomic<std::uint64_t> session_cnt{ 0xA77u };
    std::uint64_t session_id = session_cnt++;
    const auto timeout = std::chrono::milliseconds(600000);

    auto params = make_params(num_levels, worker_threads);

    auto pair_result = make_in_memory_channel_pair(protocol_id, version, session_id, timeout);
    ASSERT_TRUE(pair_result) << pair_result.message();

    auto channels = std::move(pair_result.value());
    any_channel sender_channel = std::move(channels.first);
    any_channel receiver_channel = std::move(channels.second);

    const std::uint64_t cache_run_id = allocate_protocol_cache_run_id();
    logvole_seal_backend sender_backend{};
    logvole_seal_backend receiver_backend{};

    auto ctx_result = make_ring_ntt_context(params.shrinkexpand.ring);
    ASSERT_TRUE(ctx_result) << ctx_result.message();

    logvole_sender_offline_input sender_input{};
    sender_input.params = params;
    const std::uint32_t keys_to_gen = std::max<std::uint32_t>(1u, params.gamma);
    for (std::uint32_t i = 0; i < keys_to_gen; ++i)
    {
        sender_input.sk1.push_back(derive_uniform_poly_from_nonce(ctx_result.value(), 0x1111u, 0xAAA0u, i));
    }

    logvole_receiver_offline_input receiver_input{};
    receiver_input.params = params;

    auto sender_offline =
        protocol_result<logvole_sender_offline_output>::failure(protocol_errc::io_error, "not run");
    auto receiver_offline =
        protocol_result<logvole_receiver_offline_output>::failure(protocol_errc::io_error, "not run");

    std::thread receiver_thread([&]() mutable {
        scoped_protocol_cache_scope cache_scope(protocol_cache_role::receiver, cache_run_id);
        receiver_offline =
            run_logvole_receiver_offline(std::move(receiver_channel), receiver_input, receiver_backend);
    });

    std::thread sender_thread([&]() mutable {
        scoped_protocol_cache_scope cache_scope(protocol_cache_role::sender, cache_run_id);
        sender_offline = run_logvole_sender_offline(std::move(sender_channel), sender_input, sender_backend);
    });

    sender_thread.join();
    receiver_thread.join();

    ASSERT_TRUE(sender_offline) << sender_offline.message();
    ASSERT_TRUE(receiver_offline) << receiver_offline.message();

    const auto verify_online = [&](std::uint64_t online_session_offset, std::uint64_t input_seed_offset,
                                   std::uint64_t &sender_rounds_out) {
        logvole_sender_online_input sender_online_input{};
        sender_online_input.nonce = input_seed_offset;

        logvole_receiver_online_input receiver_online_input{};
        receiver_online_input.x.resize(params.w);
        const std::uint32_t plain_sample_bits =
            std::min<std::uint32_t>(20u, params.shrinkexpand.plaintext_modulus_bits);
        for (std::uint32_t i = 0; i < params.w; ++i)
        {
            receiver_online_input.x[i] =
                sample_small_plain_poly(ctx_result.value(), 0x2222u + input_seed_offset, i, plain_sample_bits);
        }

        auto pair_result_online =
            make_in_memory_channel_pair(protocol_id, version, session_id + online_session_offset, timeout);
        ASSERT_TRUE(pair_result_online) << pair_result_online.message();

        auto channels_online = std::move(pair_result_online.value());
        any_channel sender_channel_online = std::move(channels_online.first);
        any_channel receiver_channel_online = std::move(channels_online.second);

        auto sender_online =
            protocol_result<logvole_sender_online_output>::failure(protocol_errc::io_error, "not run");
        auto receiver_online =
            protocol_result<logvole_receiver_online_output>::failure(protocol_errc::io_error, "not run");

        std::thread receiver_online_thread([&]() mutable {
            scoped_protocol_cache_scope cache_scope(protocol_cache_role::receiver, cache_run_id);
            receiver_online = run_logvole_receiver_online(
                std::move(receiver_channel_online), receiver_offline.value().state, receiver_online_input,
                receiver_backend);
        });

        std::thread sender_online_thread([&]() mutable {
            scoped_protocol_cache_scope cache_scope(protocol_cache_role::sender, cache_run_id);
            sender_online = run_logvole_sender_online(
                std::move(sender_channel_online), sender_offline.value().state, sender_online_input, sender_backend);
        });

        sender_online_thread.join();
        receiver_online_thread.join();

        ASSERT_TRUE(sender_online) << sender_online.message();
        ASSERT_TRUE(receiver_online) << receiver_online.message();

        auto tbm_minus_tbk =
            subtract_batches(ctx_result.value(), receiver_online.value().tbm, sender_online.value().tbk);
        ASSERT_TRUE(tbm_minus_tbk) << tbm_minus_tbk.message();

        std::vector<ring_rns_poly> sk1_w;
        const std::uint32_t tau_hi = params.shrinkexpand.tau - 1u;
        const std::uint32_t rho = static_cast<std::uint32_t>(params.shrinkexpand.ring.coeff_modulus_bits.size());
        const std::uint32_t mu_hi = params.shrinkexpand.alpha * tau_hi * rho;
        auto rep_out = sender_backend.rep_offline_sender_input(
            sender_input.sk1, params.gamma, params.shrinkexpand.alpha, tau_hi, params.shrinkexpand.ring);
        ASSERT_TRUE(rep_out) << rep_out.message();

        const std::uint32_t w_double_prime = (params.w + mu_hi - 1u) / mu_hi;
        for (std::uint32_t i = 0; i < w_double_prime; ++i)
        {
            for (const auto &p : rep_out.value())
            {
                if (sk1_w.size() < params.w)
                {
                    sk1_w.push_back(p);
                }
            }
        }

        const std::size_t out_w = tbm_minus_tbk.value().size();
        if (sk1_w.size() > out_w)
        {
            sk1_w.resize(out_w);
        }

        std::vector<ring_rns_poly> x_w;
        for (std::size_t i = 0; i < out_w; ++i)
        {
            x_w.push_back(receiver_online_input.x[i]);
        }

        auto expected = compute_expected_s_mul_x(ctx_result.value(), sk1_w, x_w);
        ASSERT_TRUE(expected) << expected.message();
        check_noise_tolerance(ctx_result.value(), tbm_minus_tbk.value(), expected.value(), params);

        sender_rounds_out = sender_online.value().counters.rounds_completed;
    };

    std::uint64_t first_rounds = 0u;
    std::uint64_t second_rounds = 0u;
    verify_online(1000u, 1u, first_rounds);
    verify_online(2000u, 2u, second_rounds);
    EXPECT_EQ(second_rounds, first_rounds);
    EXPECT_GT(first_rounds, 0u);
}

void run_logvole_internal_setup_reuse_test()
{
    constexpr std::uint64_t protocol_id = 0x7Cu;
    constexpr std::uint64_t version = 1u;
    static std::atomic<std::uint64_t> session_cnt{ 0xB77u };
    std::uint64_t session_id = session_cnt++;
    const auto timeout = std::chrono::milliseconds(600000);

    auto params = make_params(3u);

    auto pair_result = make_in_memory_channel_pair(protocol_id, version, session_id, timeout);
    ASSERT_TRUE(pair_result) << pair_result.message();

    auto channels = std::move(pair_result.value());
    any_channel sender_channel = std::move(channels.first);
    any_channel receiver_channel = std::move(channels.second);

    const std::uint64_t cache_run_id = allocate_protocol_cache_run_id();
    logvole_seal_backend sender_backend{};
    logvole_seal_backend receiver_backend{};

    auto ctx_result = make_ring_ntt_context(params.shrinkexpand.ring);
    ASSERT_TRUE(ctx_result) << ctx_result.message();

    logvole_sender_offline_input sender_input{};
    sender_input.params = params;
    for (std::uint32_t i = 0; i < std::max<std::uint32_t>(1u, params.gamma); ++i)
    {
        sender_input.sk1.push_back(derive_uniform_poly_from_nonce(ctx_result.value(), 0x1111u, 0xAAA0u, i));
    }

    logvole_receiver_offline_input receiver_input{};
    receiver_input.params = params;

    auto sender_offline =
        protocol_result<logvole_sender_offline_output>::failure(protocol_errc::io_error, "not run");
    auto receiver_offline =
        protocol_result<logvole_receiver_offline_output>::failure(protocol_errc::io_error, "not run");

    std::thread receiver_thread([&]() mutable {
        scoped_protocol_cache_scope cache_scope(protocol_cache_role::receiver, cache_run_id);
        receiver_offline =
            run_logvole_receiver_offline(std::move(receiver_channel), receiver_input, receiver_backend);
    });

    std::thread sender_thread([&]() mutable {
        scoped_protocol_cache_scope cache_scope(protocol_cache_role::sender, cache_run_id);
        sender_offline = run_logvole_sender_offline(std::move(sender_channel), sender_input, sender_backend);
    });

    sender_thread.join();
    receiver_thread.join();

    ASSERT_TRUE(sender_offline) << sender_offline.message();
    ASSERT_TRUE(receiver_offline) << receiver_offline.message();

    ASSERT_TRUE(static_cast<bool>(sender_offline.value().state.next_level_state));
    ASSERT_TRUE(static_cast<bool>(sender_offline.value().state.next_level_state->next_level_state));

    const auto &top_package = sender_offline.value().state.shrinkexpand_state;
    const auto &first_internal = sender_offline.value().state.next_level_state->shrinkexpand_state;
    const auto &reused_root_package =
        sender_offline.value().state.next_level_state->next_level_state->shrinkexpand_state;

    EXPECT_TRUE(ring_batches_equal(top_package.sk1, first_internal.sk1));
    EXPECT_TRUE(ring_batches_equal(first_internal.sk1, reused_root_package.sk1));
    EXPECT_EQ(sender_offline.value().counters.rounds_completed, 3u);
    EXPECT_EQ(receiver_offline.value().counters.rounds_completed, 3u);
}

void run_logvole_recursive_gadget_subproblem_test(bool deterministic)
{
    constexpr std::uint64_t protocol_id = 0x79u;
    constexpr std::uint64_t version = 1u;
    static std::atomic<std::uint64_t> session_cnt{ 0x98Au };
    const std::uint64_t session_id = session_cnt++;
    const auto timeout = std::chrono::milliseconds(600000);

    auto params = make_params(2u);
    params.shrinkexpand.mode = deterministic ? shrinkexpand_mode::deterministic : shrinkexpand_mode::full_noise;
    params.shrinkexpand.noise_bound = deterministic ? 0 : 2;

    auto pair_result = make_in_memory_channel_pair(protocol_id, version, session_id, timeout);
    ASSERT_TRUE(pair_result) << pair_result.message();

    auto channels = std::move(pair_result.value());
    any_channel sender_channel = std::move(channels.first);
    any_channel receiver_channel = std::move(channels.second);

    const std::uint64_t cache_run_id = allocate_protocol_cache_run_id();
    logvole_seal_backend sender_backend{};
    logvole_seal_backend receiver_backend{};

    auto ctx_result = make_ring_ntt_context(params.shrinkexpand.ring);
    ASSERT_TRUE(ctx_result) << ctx_result.message();

    logvole_sender_offline_input sender_input{};
    sender_input.params = params;
    sender_input.sk1.push_back(derive_uniform_poly_from_nonce(ctx_result.value(), 0x1111u, 0xAAA0u, 0u));

    logvole_receiver_offline_input receiver_input{};
    receiver_input.params = params;

    protocol_result<logvole_sender_offline_output> sender_offline =
        protocol_result<logvole_sender_offline_output>::failure(protocol_errc::io_error, "not run");
    protocol_result<logvole_receiver_offline_output> receiver_offline =
        protocol_result<logvole_receiver_offline_output>::failure(protocol_errc::io_error, "not run");

    std::thread receiver_thread([&]() mutable {
        scoped_protocol_cache_scope cache_scope(protocol_cache_role::receiver, cache_run_id);
        receiver_offline =
            run_logvole_receiver_offline(std::move(receiver_channel), receiver_input, receiver_backend);
    });

    std::thread sender_thread([&]() mutable {
        scoped_protocol_cache_scope cache_scope(protocol_cache_role::sender, cache_run_id);
        sender_offline = run_logvole_sender_offline(std::move(sender_channel), sender_input, sender_backend);
    });

    sender_thread.join();
    receiver_thread.join();

    ASSERT_TRUE(sender_offline) << sender_offline.message();
    ASSERT_TRUE(receiver_offline) << receiver_offline.message();
    ASSERT_TRUE(static_cast<bool>(sender_offline.value().state.next_level_state));
    ASSERT_TRUE(static_cast<bool>(receiver_offline.value().state.next_level_state));

    std::vector<ring_rns_poly> x(params.w);
    const std::uint32_t plain_sample_bits = std::min<std::uint32_t>(20u, params.shrinkexpand.plaintext_modulus_bits);
    for (std::uint32_t i = 0; i < params.w; ++i)
    {
        x[i] = sample_small_plain_poly(ctx_result.value(), 0x3333u, i, plain_sample_bits);
    }

    const std::uint32_t tau_hi = params.shrinkexpand.tau - 1u;
    const std::uint32_t rho = static_cast<std::uint32_t>(params.shrinkexpand.ring.coeff_modulus_bits.size());
    const std::uint32_t mu_hi = params.shrinkexpand.alpha * tau_hi * rho;
    const std::uint32_t w_double_prime = (params.w + mu_hi - 1u) / mu_hi;

    std::vector<ring_rns_poly> d_hat;
    d_hat.reserve(static_cast<std::size_t>(w_double_prime) * tau_hi * rho);
    for (std::uint32_t chunk_idx = 0; chunk_idx < w_double_prime; ++chunk_idx)
    {
        const std::size_t start = static_cast<std::size_t>(chunk_idx) * static_cast<std::size_t>(mu_hi);
        const std::size_t end = std::min(start + static_cast<std::size_t>(mu_hi), x.size());

        std::vector<ring_rns_poly> x_chunk(x.begin() + start, x.begin() + end);
        while (x_chunk.size() < static_cast<std::size_t>(mu_hi))
        {
            ring_rns_poly zero{};
            zero.coeffs.assign(ring_poly_coeff_count(params.shrinkexpand.ring), 0u);
            x_chunk.push_back(std::move(zero));
        }

        auto shrink_res = shrinkexpand_shrink(
            receiver_offline.value().state.shrinkexpand_state, x_chunk, receiver_backend.get_shrinkexpand_backend());
        ASSERT_TRUE(static_cast<bool>(shrink_res)) << shrink_res.message();

        auto decomp_res = receiver_backend.gdecomp_hi_and_unbundle(
            shrink_res.value().digest, params.shrinkexpand.gadget_log_base, tau_hi, params.shrinkexpand.ring);
        ASSERT_TRUE(static_cast<bool>(decomp_res)) << decomp_res.message();
        ASSERT_EQ(decomp_res.value().size(), static_cast<std::size_t>(tau_hi) * static_cast<std::size_t>(rho));

        for (const auto &poly : decomp_res.value())
        {
            d_hat.push_back(poly);
        }
    }

    auto pair_result_online = make_in_memory_channel_pair(protocol_id, version, session_id + 1000u, timeout);
    ASSERT_TRUE(pair_result_online) << pair_result_online.message();

    auto channels_online = std::move(pair_result_online.value());
    any_channel sender_channel_online = std::move(channels_online.first);
    any_channel receiver_channel_online = std::move(channels_online.second);

    logvole_sender_online_input sender_online_input{};
    logvole_receiver_online_input receiver_online_input{};
    receiver_online_input.x = d_hat;

    protocol_result<logvole_sender_online_output> sender_online =
        protocol_result<logvole_sender_online_output>::failure(protocol_errc::io_error, "not run");
    protocol_result<logvole_receiver_online_output> receiver_online =
        protocol_result<logvole_receiver_online_output>::failure(protocol_errc::io_error, "not run");

    std::thread receiver_online_thread([&]() mutable {
        scoped_protocol_cache_scope cache_scope(protocol_cache_role::receiver, cache_run_id);
        receiver_online = run_logvole_receiver_online(
            std::move(receiver_channel_online), *receiver_offline.value().state.next_level_state, receiver_online_input,
            receiver_backend);
    });

    std::thread sender_online_thread([&]() mutable {
        scoped_protocol_cache_scope cache_scope(protocol_cache_role::sender, cache_run_id);
        sender_online = run_logvole_sender_online(
            std::move(sender_channel_online), *sender_offline.value().state.next_level_state, sender_online_input,
            sender_backend);
    });

    sender_online_thread.join();
    receiver_online_thread.join();

    ASSERT_TRUE(sender_online) << sender_online.message();
    ASSERT_TRUE(receiver_online) << receiver_online.message();

    auto tbm_minus_tbk = subtract_batches(ctx_result.value(), receiver_online.value().tbm, sender_online.value().tbk);
    ASSERT_TRUE(tbm_minus_tbk) << tbm_minus_tbk.message();

    const auto &next_params = sender_offline.value().state.next_level_state->params;
    auto next_rep = sender_backend.rep_offline_sender_input(
        sender_offline.value().state.next_level_state->sk1, next_params.gamma, next_params.shrinkexpand.alpha, tau_hi,
        next_params.shrinkexpand.ring);
    ASSERT_TRUE(next_rep) << next_rep.message();

    std::vector<ring_rns_poly> sk1_w;
    const std::uint32_t next_w = next_params.w;
    const std::uint32_t next_w_double_prime = (next_w + mu_hi - 1u) / mu_hi;
    for (std::uint32_t i = 0; i < next_w_double_prime; ++i)
    {
        for (const auto &p : next_rep.value())
        {
            if (sk1_w.size() < next_w)
            {
                sk1_w.push_back(p);
            }
        }
    }

    auto expected = compute_expected_s_mul_x(ctx_result.value(), sk1_w, d_hat);
    ASSERT_TRUE(expected) << expected.message();
    check_noise_tolerance(ctx_result.value(), tbm_minus_tbk.value(), expected.value(), next_params);
}

void run_logvole_leaf_tau_one_test()
{
    constexpr std::uint64_t protocol_id = 0x7Au;
    constexpr std::uint64_t version = 1u;
    static std::atomic<std::uint64_t> session_cnt{ 0xA11u };
    const std::uint64_t session_id = session_cnt++;
    const auto timeout = std::chrono::milliseconds(600000);

    auto params = make_leaf_tau_one_params();

    auto pair_result = make_in_memory_channel_pair(protocol_id, version, session_id, timeout);
    ASSERT_TRUE(pair_result) << pair_result.message();

    auto channels = std::move(pair_result.value());
    any_channel sender_channel = std::move(channels.first);
    any_channel receiver_channel = std::move(channels.second);

    const std::uint64_t cache_run_id = allocate_protocol_cache_run_id();
    logvole_seal_backend sender_backend{};
    logvole_seal_backend receiver_backend{};

    auto ctx_result = make_ring_ntt_context(params.shrinkexpand.ring);
    ASSERT_TRUE(ctx_result) << ctx_result.message();

    logvole_sender_offline_input sender_input{};
    sender_input.params = params;
    sender_input.sk1.push_back(derive_uniform_poly_from_nonce(ctx_result.value(), 0x4444u, 0xBBB0u, 0u));

    logvole_receiver_offline_input receiver_input{};
    receiver_input.params = params;

    const std::uint32_t tau_hi = params.shrinkexpand.tau - 1u;
    const std::uint32_t rho = static_cast<std::uint32_t>(params.shrinkexpand.ring.coeff_modulus_bits.size());
    const std::uint32_t mu_hi = params.shrinkexpand.alpha * tau_hi * rho;
    ASSERT_LT(params.w, mu_hi);

    {
        scoped_protocol_cache_scope cache_scope(protocol_cache_role::sender, cache_run_id);
        auto sender_offline = run_logvole_sender_offline(std::move(sender_channel), sender_input, sender_backend);
        ASSERT_FALSE(sender_offline);
    }
    {
        scoped_protocol_cache_scope cache_scope(protocol_cache_role::receiver, cache_run_id);
        auto receiver_offline =
            run_logvole_receiver_offline(std::move(receiver_channel), receiver_input, receiver_backend);
        ASSERT_FALSE(receiver_offline);
    }
}

class LogVOLETest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        global_timing_stats.reset();
        clear_protocol_cache_scope();
        clear_protocol_runtime_caches_for_testing();
    }

    void TearDown() override
    {
        global_timing_stats.reset();
        clear_protocol_cache_scope();
        clear_protocol_runtime_caches_for_testing();
    }
};

TEST_F(LogVOLETest, TwoLevelExecution)
{
    run_logvole_test(2);
}

TEST_F(LogVOLETest, ThreeLevelExecution)
{
    run_logvole_test(3);
}

TEST_F(LogVOLETest, ThreeLevelExecutionUsesRecursiveOnlineRounds)
{
    run_logvole_test(3, 1u, 2u);
}

TEST_F(LogVOLETest, ThreeLevelExecutionMultiThread)
{
    run_logvole_test(3, 4u);
}

TEST_F(LogVOLETest, ThreeLevelExecutionWithSenderPrecompute)
{
    run_logvole_test(3, 1u, 0u, true);
}

TEST_F(LogVOLETest, ThreeLevelExecutionReusesCachedRootSeed)
{
    run_logvole_repeated_online_test(3);
}

TEST_F(LogVOLETest, ThreeLevelOfflineReusesInternalSetup)
{
    run_logvole_internal_setup_reuse_test();
}

TEST_F(LogVOLETest, RecursiveGadgetInputSubproblemW8)
{
    run_logvole_recursive_gadget_subproblem_test(true);
}

TEST_F(LogVOLETest, RecursiveGadgetInputSubproblemW8FullNoise)
{
    run_logvole_recursive_gadget_subproblem_test(false);
}

TEST_F(LogVOLETest, RejectsWidthsBelowRandomizedRootBlock)
{
    run_logvole_leaf_tau_one_test();
}

TEST_F(LogVOLETest, DISABLED_FiveLevelExecutionW256)
{
    run_logvole_test(5);
}

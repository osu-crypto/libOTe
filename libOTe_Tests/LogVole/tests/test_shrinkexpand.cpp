#include "seal/seal.h"
#include "seal/util/rns.h"
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include "../src/protocol/shrinkexpand_shared_ops.hpp"
#include "gtest/gtest.h"
#include "loglabel/comm/codec.hpp"
#include "loglabel/ring_ops.hpp"
#include "loglabel/shrinkexpand_protocol.hpp"
#include "loglabel/shrinkexpand_spec.hpp"

using namespace loglabel;
using namespace loglabel::comm;

namespace
{
    shrinkexpand_params make_params(shrinkexpand_mode mode)
    {
        shrinkexpand_params params{};
        params.ring.poly_modulus_degree = 16384;
        params.ring.coeff_modulus_bits = { 54, 54, 54, 54, 54, 54, 54 };
        params.plaintext_modulus_bits = 54;
        params.alpha = 2;
        params.mu = 3;
        params.tau = 3;
        params.gadget_log_base = 126;
        params.mode = mode;
        params.noise_seed = 0xBAD5EEDu;
        params.noise_bound = 2;
        return params;
    }

    std::vector<ring_rns_poly> sample_batch(const ring_ntt_context &ctx, std::uint32_t count, std::uint64_t seed)
    {
        std::vector<ring_rns_poly> out;
        out.reserve(count);
        for (std::uint32_t i = 0; i < count; ++i)
        {
            out.push_back(derive_uniform_poly_from_nonce(ctx, seed, 0xABCDu, i));
        }
        return out;
    }

    ring_rns_poly sample_scalar_poly(const ring_ntt_context &ctx, std::uint64_t seed)
    {
        return derive_uniform_poly_from_nonce(ctx, seed, 0xABCDu, 0u);
    }

    void expect_poly_equal(const ring_rns_poly &a, const ring_rns_poly &b)
    {
        ASSERT_EQ(a.coeffs.size(), b.coeffs.size());
        for (std::size_t i = 0; i < a.coeffs.size(); ++i)
        {
            EXPECT_EQ(a.coeffs[i], b.coeffs[i]) << "coeff idx " << i;
        }
    }

    void expect_batch_equal(const std::vector<ring_rns_poly> &a, const std::vector<ring_rns_poly> &b)
    {
        ASSERT_EQ(a.size(), b.size());
        for (std::size_t i = 0; i < a.size(); ++i)
        {
            expect_poly_equal(a[i], b[i]);
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
            {
                return protocol_result<std::vector<ring_rns_poly>>::failure(prod.error(), prod.message());
            }
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
            {
                return protocol_result<std::vector<ring_rns_poly>>::failure(sub.error(), sub.message());
            }
            out.push_back(std::move(sub.value()));
        }
        return protocol_result<std::vector<ring_rns_poly>>::success(std::move(out));
    }

    protocol_result<ring_rns_poly> build_sk_x(
        const shrinkexpand_sender_state &sender_state, const ring_rns_poly &digest, const ring_rns_poly &tbk_prime)
    {
        auto ctx_result = make_ring_ntt_context(sender_state.params.ring);
        if (!ctx_result)
        {
            return protocol_result<ring_rns_poly>::failure(ctx_result.error(), ctx_result.message());
        }
        const auto &ctx = ctx_result.value();

        auto u = gadget_decompose_bits(digest, sender_state.params.gadget_log_base, sender_state.params.tau, ctx);
        if (!u)
        {
            return protocol_result<ring_rns_poly>::failure(u.error(), u.message());
        }

        ring_rns_poly sk_x = tbk_prime;

        for (std::size_t i = 0; i < sender_state.params.tau; ++i)
        {
            auto term = ring_multiply(sender_state.sk1[i], u.value()[i], ctx);
            if (!term)
            {
                return protocol_result<ring_rns_poly>::failure(term.error(), term.message());
            }

            auto key = ring_add(sk_x, term.value(), ctx);
            if (!key)
            {
                return protocol_result<ring_rns_poly>::failure(key.error(), key.message());
            }
            sk_x = std::move(key.value());
        }

        return protocol_result<ring_rns_poly>::success(std::move(sk_x));
    }

    std::int64_t centered_abs(std::uint64_t value, std::uint64_t modulus)
    {
        const std::uint64_t reduced = value % modulus;
        if (reduced <= (modulus / 2u))
        {
            return static_cast<std::int64_t>(reduced);
        }
        return static_cast<std::int64_t>(modulus - reduced);
    }

    const char *mode_to_cstr(shrinkexpand_mode mode)
    {
        switch (mode)
        {
        case shrinkexpand_mode::deterministic:
            return "deterministic";
        case shrinkexpand_mode::full_noise:
            return "full_noise";
        default:
            return "unknown";
        }
    }

    std::string to_hex(std::uint64_t value)
    {
        std::ostringstream stream;
        stream << "0x" << std::hex << std::uppercase << value;
        return stream.str();
    }

    std::uint32_t log_q_bits(const shrinkexpand_params &params)
    {
        std::uint32_t log_q = 0u;
        for (int bits : params.ring.coeff_modulus_bits)
        {
            log_q += static_cast<std::uint32_t>(bits);
        }
        return log_q;
    }

    std::int64_t base_noise_floor(const shrinkexpand_params &params)
    {
        const long double exponent = 0.1L * static_cast<long double>(log_q_bits(params));
        const long double bound = std::pow(2.0L, exponent);
        const auto ceil_bound = static_cast<std::int64_t>(std::ceil(bound));
        return (ceil_bound > 0) ? ceil_bound : 1;
    }

    void print_test_setup(
        const char *test_name, const shrinkexpand_params &params, std::uint64_t protocol_id, std::uint64_t version,
        std::uint64_t session_id, std::chrono::milliseconds timeout)
    {
        (void)test_name;
        (void)params;
        (void)protocol_id;
        (void)version;
        (void)session_id;
        (void)timeout;
        /*
        std::cout << "INFO " << test_name << ": "
                  << "mode=" << mode_to_cstr(params.mode) << " poly_modulus_degree=" << params.ring.poly_modulus_degree
                  << " log_p=" << params.plaintext_modulus_bits << " alpha=" << params.alpha << " coeff_modulus_bits=[";
        for (std::size_t i = 0; i < params.ring.coeff_modulus_bits.size(); ++i)
        {
            if (i != 0)
            {
                std::cout << ",";
            }
            std::cout << params.ring.coeff_modulus_bits[i];
        }
        std::cout << "]"
                  << " mu=" << params.mu << " tau=" << params.tau << " gadget_log_base=" << params.gadget_log_base
                  << " noise_seed=" << to_hex(params.noise_seed) << " noise_bound=" << params.noise_bound;
        const std::int64_t effective_noise_bound =
            (params.mode == shrinkexpand_mode::full_noise)
                ? ((base_noise_floor(params) > params.noise_bound) ? base_noise_floor(params) : params.noise_bound)
                : params.noise_bound;
        std::cout << " effective_noise_bound=" << effective_noise_bound << " protocol_id=" << to_hex(protocol_id)
                  << " version=" << version << " session_id=" << to_hex(session_id) << " timeout_ms=" << timeout.count()
                  << std::endl;
        */
    }

    void print_hex_value(const char *test_name, const char *name, std::uint64_t value)
    {
        (void)test_name;
        (void)name;
        (void)value;
        // std::cout << "INFO " << test_name << ": " << name << "=" << to_hex(value) << std::endl;
    }

    void print_dec_value(const char *test_name, const char *name, std::uint64_t value)
    {
        (void)test_name;
        (void)name;
        (void)value;
        // std::cout << "INFO " << test_name << ": " << name << "=" << value << std::endl;
    }

} // namespace

TEST(ShrinkExpandOps, DenoiseCombExactness)
{
    constexpr const char *test_name = "ShrinkExpandOps.DenoiseCombExactness";
    constexpr std::uint64_t seed_x = 0x8888;
    constexpr std::uint64_t seed_noise = 0x9999;

    auto params = make_params(shrinkexpand_mode::full_noise);
    auto ctx_result = make_ring_ntt_context(params.ring);
    ASSERT_TRUE(ctx_result) << ctx_result.message();
    const auto &ctx = ctx_result.value();

    const std::size_t n = params.ring.poly_modulus_degree;
    const std::size_t rho = params.ring.coeff_modulus_bits.size();
    const std::size_t w_prime = 2; // Test with 2 elements

    auto x_batch = sample_batch(ctx, w_prime, seed_x);

    std::vector<ring_rns_poly> tba_prime;
    tba_prime.reserve(w_prime * rho);

    auto key_context_data = ctx.context->key_context_data();
    seal::util::RNSBase full_base(key_context_data->parms().coeff_modulus(), seal::MemoryManager::GetPool());
    auto pool = seal::MemoryManager::GetPool();

    auto p_j_mpi = seal::util::allocate_uint(rho, pool);
    auto p_j_half_mpi = seal::util::allocate_uint(rho, pool);
    auto mod_j_mpi = seal::util::allocate_uint(rho, pool);
    auto remainder_mpi = seal::util::allocate_uint(rho, pool);
    auto val_mpi = seal::util::allocate_uint(rho, pool);
    auto noise_mpi = seal::util::allocate_uint(rho, pool);

    std::mt19937_64 prng(seed_noise);

    for (std::size_t i = 0; i < w_prime; ++i)
    {
        for (std::size_t j = 0; j < rho; ++j)
        {
            ring_rns_poly poly_j;
            poly_j.coeffs.resize(n * rho, 0);

            const auto modulus_j = full_base.base()[j];
            seal::util::set_uint(modulus_j.value(), rho, mod_j_mpi.get());

            seal::util::divide_uint(
                full_base.base_prod(), mod_j_mpi.get(), rho, p_j_mpi.get(), remainder_mpi.get(), pool);

            seal::util::right_shift_uint(p_j_mpi.get(), 1, rho, p_j_half_mpi.get());

            for (std::size_t k = 0; k < n; ++k)
            {
                std::uint64_t x_k_j = x_batch[i].coeffs[j * n + k];

                seal::util::set_uint(x_k_j, rho, val_mpi.get());
                seal::util::multiply_uint(val_mpi.get(), p_j_mpi.get(), rho, val_mpi.get());

                std::uint64_t noise_val = (prng() % 1000) + 1;
                bool negative = (prng() % 2) == 1;

                if (!negative)
                {
                    seal::util::set_uint(noise_val, rho, noise_mpi.get());
                    seal::util::add_uint(val_mpi.get(), noise_mpi.get(), rho, val_mpi.get());
                }
                else
                {
                    seal::util::set_uint(noise_val, rho, noise_mpi.get());
                    seal::util::sub_uint(val_mpi.get(), noise_mpi.get(), rho, val_mpi.get());
                }

                seal::util::divide_uint(
                    val_mpi.get(), full_base.base_prod(), rho, p_j_half_mpi.get(), remainder_mpi.get(), pool);

                for (std::size_t mod_idx = 0; mod_idx < rho; ++mod_idx)
                {
                    std::uint64_t rns_val =
                        seal::util::modulo_uint(remainder_mpi.get(), rho, full_base.base()[mod_idx]);
                    poly_j.coeffs[mod_idx * n + k] = rns_val;
                }
            }
            tba_prime.push_back(std::move(poly_j));
        }
    }

    auto out_result = shrinkexpand_denoise_comb(ctx, tba_prime);
    ASSERT_TRUE(out_result) << out_result.message();

    const auto &out_batch = out_result.value();
    ASSERT_EQ(out_batch.size(), w_prime);

    for (std::size_t i = 0; i < w_prime; ++i)
    {
        for (std::size_t j = 0; j < rho; ++j)
        {
            for (std::size_t k = 0; k < n; ++k)
            {
                ASSERT_EQ(out_batch[i].coeffs[j * n + k], x_batch[i].coeffs[j * n + k])
                    << "Mismatch at i=" << i << ", j=" << j << ", k=" << k;
            }
        }
    }
}

TEST(ShrinkExpandOffline, HappyPathAndCounters)
{
    constexpr const char *test_name = "ShrinkExpandOffline.HappyPathAndCounters";
    constexpr std::uint64_t protocol_id = 0x51u;
    constexpr std::uint64_t version = 1u;
    constexpr std::uint64_t session_id = 0x111u;
    constexpr std::uint64_t seed_s = 0x1111u;
    const auto timeout = std::chrono::milliseconds(10000);

    const auto params = make_params(shrinkexpand_mode::deterministic);
    print_test_setup(test_name, params, protocol_id, version, session_id, timeout);
    print_hex_value(test_name, "seed_s", seed_s);

    auto ctx_result = make_ring_ntt_context(params.ring);
    ASSERT_TRUE(ctx_result) << ctx_result.message();
    const auto &ctx = ctx_result.value();

    shrinkexpand_sender_offline_input sender_input{};
    sender_input.params = params;
    sender_input.s = sample_batch(ctx, params.mu, seed_s);

    shrinkexpand_receiver_offline_input receiver_input{};
    receiver_input.params = params;

    auto pair_result = make_in_memory_channel_pair(protocol_id, version, session_id, timeout);
    ASSERT_TRUE(pair_result) << pair_result.message();

    auto channels = std::move(pair_result.value());
    any_channel sender_channel = std::move(channels.first);
    any_channel receiver_channel = std::move(channels.second);

    shrinkexpand_seal_backend backend{};

    protocol_result<shrinkexpand_sender_offline_output> sender_result =
        protocol_result<shrinkexpand_sender_offline_output>::failure(protocol_errc::io_error, "not run");
    protocol_result<shrinkexpand_receiver_offline_output> receiver_result =
        protocol_result<shrinkexpand_receiver_offline_output>::failure(protocol_errc::io_error, "not run");

    std::thread receiver_thread([&]() mutable {
        receiver_result = run_shrinkexpand_receiver(std::move(receiver_channel), receiver_input, backend);
    });

    std::thread sender_thread(
        [&]() mutable { sender_result = run_shrinkexpand_sender(std::move(sender_channel), sender_input, backend); });

    sender_thread.join();
    receiver_thread.join();

    ASSERT_TRUE(sender_result) << sender_result.message();
    ASSERT_TRUE(receiver_result) << receiver_result.message();

    EXPECT_EQ(sender_result.value().counters.frames_s2r_sent, 1u);
    EXPECT_EQ(sender_result.value().counters.frames_r2s_sent, 0u);
    EXPECT_EQ(sender_result.value().counters.rounds_completed, 1u);

    EXPECT_EQ(receiver_result.value().counters.frames_s2r_recv, 1u);
    EXPECT_EQ(receiver_result.value().counters.frames_r2s_recv, 0u);
    EXPECT_EQ(receiver_result.value().counters.rounds_completed, 1u);

    EXPECT_EQ(sender_result.value().counters.wire_bytes_s2r_sent, receiver_result.value().counters.wire_bytes_s2r_recv);
    EXPECT_GT(sender_result.value().counters.wire_bytes_s2r_sent, 0u);

    print_dec_value(test_name, "wire_bytes_s2r_sent", sender_result.value().counters.wire_bytes_s2r_sent);
    print_dec_value(test_name, "rounds_completed", sender_result.value().counters.rounds_completed);
}

TEST(ShrinkExpandOnline, DeterministicRelationExact)
{
    constexpr const char *test_name = "ShrinkExpandOnline.DeterministicRelationExact";
    constexpr std::uint64_t protocol_id = 0x52u;
    constexpr std::uint64_t version = 1u;
    constexpr std::uint64_t session_id = 0x222u;
    constexpr std::uint64_t seed_s = 0x2001u;
    constexpr std::uint64_t seed_x = 0x3001u;
    constexpr std::uint64_t seed_tbk_prime = 0x4001u;
    constexpr std::uint64_t nonce = 0x999u;
    const auto timeout = std::chrono::milliseconds(10000);

    const auto params = make_params(shrinkexpand_mode::deterministic);
    print_test_setup(test_name, params, protocol_id, version, session_id, timeout);
    print_hex_value(test_name, "seed_s", seed_s);
    print_hex_value(test_name, "seed_x", seed_x);
    print_hex_value(test_name, "seed_tbk_prime", seed_tbk_prime);
    print_hex_value(test_name, "nonce", nonce);

    auto ctx_result = make_ring_ntt_context(params.ring);
    ASSERT_TRUE(ctx_result) << ctx_result.message();
    const auto &ctx = ctx_result.value();

    shrinkexpand_sender_offline_input sender_input{};
    sender_input.params = params;
    sender_input.s = sample_batch(ctx, params.mu, seed_s);

    shrinkexpand_receiver_offline_input receiver_input{};
    receiver_input.params = params;

    auto pair_result = make_in_memory_channel_pair(protocol_id, version, session_id, timeout);
    ASSERT_TRUE(pair_result) << pair_result.message();

    auto channels = std::move(pair_result.value());
    any_channel sender_channel = std::move(channels.first);
    any_channel receiver_channel = std::move(channels.second);

    shrinkexpand_seal_backend backend{};

    protocol_result<shrinkexpand_sender_offline_output> sender_offline =
        protocol_result<shrinkexpand_sender_offline_output>::failure(protocol_errc::io_error, "not run");
    protocol_result<shrinkexpand_receiver_offline_output> receiver_offline =
        protocol_result<shrinkexpand_receiver_offline_output>::failure(protocol_errc::io_error, "not run");

    std::thread receiver_thread([&]() mutable {
        receiver_offline = run_shrinkexpand_receiver(std::move(receiver_channel), receiver_input, backend);
    });

    std::thread sender_thread(
        [&]() mutable { sender_offline = run_shrinkexpand_sender(std::move(sender_channel), sender_input, backend); });

    sender_thread.join();
    receiver_thread.join();

    ASSERT_TRUE(sender_offline) << sender_offline.message();
    ASSERT_TRUE(receiver_offline) << receiver_offline.message();

    auto x = sample_batch(ctx, params.mu, seed_x);
    auto digest = shrinkexpand_shrink(receiver_offline.value().state, x, backend);
    ASSERT_TRUE(digest) << digest.message();

    auto tbk_prime = sample_scalar_poly(ctx, seed_tbk_prime);
    auto sk_x = build_sk_x(sender_offline.value().state, digest.value(), tbk_prime);
    ASSERT_TRUE(sk_x) << sk_x.message();

    shrinkexpand_expand_sender_input sender_expand_input{};
    sender_expand_input.nonce = nonce;
    sender_expand_input.tbk_prime = tbk_prime;

    shrinkexpand_expand_receiver_input receiver_expand_input{};
    receiver_expand_input.nonce = sender_expand_input.nonce;
    receiver_expand_input.x = x;
    receiver_expand_input.digest = digest.value();
    receiver_expand_input.sk_x = sk_x.value();

    auto sender_expand = shrinkexpand_expand_sender(sender_offline.value().state, sender_expand_input, backend);
    ASSERT_TRUE(sender_expand) << sender_expand.message();

    auto receiver_expand = shrinkexpand_expand_receiver(receiver_offline.value().state, receiver_expand_input, backend);
    ASSERT_TRUE(receiver_expand) << receiver_expand.message();

    auto tbm_minus_tbk = subtract_batches(ctx, receiver_expand.value().tbm, sender_expand.value().tbk);
    ASSERT_TRUE(tbm_minus_tbk) << tbm_minus_tbk.message();

    auto expected = compute_expected_s_mul_x(ctx, sender_input.s, x);
    ASSERT_TRUE(expected) << expected.message();

    expect_batch_equal(tbm_minus_tbk.value(), expected.value());
    // std::cout << "INFO " << test_name << ": relation tbm-tbk==s*x verified exactly" << std::endl;
}

TEST(ShrinkExpandOnline, FullNoiseTolerance)
{
    constexpr const char *test_name = "ShrinkExpandOnline.FullNoiseTolerance";
    constexpr std::uint64_t protocol_id = 0x53u;
    constexpr std::uint64_t version = 1u;
    constexpr std::uint64_t session_id = 0x333u;
    constexpr std::uint64_t seed_s = 0x5001u;
    constexpr std::uint64_t seed_x = 0x6001u;
    constexpr std::uint64_t seed_tbk_prime = 0x7001u;
    constexpr std::uint64_t nonce = 0xAAA1u;
    const auto timeout = std::chrono::milliseconds(10000);

    auto params = make_params(shrinkexpand_mode::full_noise);
    params.noise_bound = 2;
    print_test_setup(test_name, params, protocol_id, version, session_id, timeout);
    print_hex_value(test_name, "seed_s", seed_s);
    print_hex_value(test_name, "seed_x", seed_x);
    print_hex_value(test_name, "seed_tbk_prime", seed_tbk_prime);
    print_hex_value(test_name, "nonce", nonce);

    auto ctx_result = make_ring_ntt_context(params.ring);
    ASSERT_TRUE(ctx_result) << ctx_result.message();
    const auto &ctx = ctx_result.value();

    shrinkexpand_sender_offline_input sender_input{};
    sender_input.params = params;
    sender_input.s = sample_batch(ctx, params.mu, seed_s);

    shrinkexpand_receiver_offline_input receiver_input{};
    receiver_input.params = params;

    auto pair_result = make_in_memory_channel_pair(protocol_id, version, session_id, timeout);
    ASSERT_TRUE(pair_result) << pair_result.message();

    auto channels = std::move(pair_result.value());
    any_channel sender_channel = std::move(channels.first);
    any_channel receiver_channel = std::move(channels.second);

    shrinkexpand_seal_backend backend{};

    protocol_result<shrinkexpand_sender_offline_output> sender_offline =
        protocol_result<shrinkexpand_sender_offline_output>::failure(protocol_errc::io_error, "not run");
    protocol_result<shrinkexpand_receiver_offline_output> receiver_offline =
        protocol_result<shrinkexpand_receiver_offline_output>::failure(protocol_errc::io_error, "not run");

    std::thread receiver_thread([&]() mutable {
        receiver_offline = run_shrinkexpand_receiver(std::move(receiver_channel), receiver_input, backend);
    });

    std::thread sender_thread(
        [&]() mutable { sender_offline = run_shrinkexpand_sender(std::move(sender_channel), sender_input, backend); });

    sender_thread.join();
    receiver_thread.join();

    ASSERT_TRUE(sender_offline) << sender_offline.message();
    ASSERT_TRUE(receiver_offline) << receiver_offline.message();
    const std::int64_t expected_base_noise = base_noise_floor(params);
    print_dec_value(test_name, "noise_base_q_pow_01_floor", static_cast<std::uint64_t>(expected_base_noise));
    ASSERT_GT(expected_base_noise, params.noise_bound);
    ASSERT_EQ(sender_offline.value().state.effective_noise_bound, expected_base_noise);
    ASSERT_EQ(receiver_offline.value().state.effective_noise_bound, expected_base_noise);
    print_dec_value(
        test_name, "effective_noise_bound",
        static_cast<std::uint64_t>(receiver_offline.value().state.effective_noise_bound));

    auto x = sample_batch(ctx, params.mu, seed_x);
    auto digest = shrinkexpand_shrink(receiver_offline.value().state, x, backend);
    ASSERT_TRUE(digest) << digest.message();

    auto tbk_prime = sample_scalar_poly(ctx, seed_tbk_prime);
    auto sk_x = build_sk_x(sender_offline.value().state, digest.value(), tbk_prime);
    ASSERT_TRUE(sk_x) << sk_x.message();

    shrinkexpand_expand_sender_input sender_expand_input{};
    sender_expand_input.nonce = nonce;
    sender_expand_input.tbk_prime = tbk_prime;

    shrinkexpand_expand_receiver_input receiver_expand_input{};
    receiver_expand_input.nonce = sender_expand_input.nonce;
    receiver_expand_input.x = x;
    receiver_expand_input.digest = digest.value();
    receiver_expand_input.sk_x = sk_x.value();

    auto sender_expand = shrinkexpand_expand_sender(sender_offline.value().state, sender_expand_input, backend);
    ASSERT_TRUE(sender_expand) << sender_expand.message();

    auto receiver_expand = shrinkexpand_expand_receiver(receiver_offline.value().state, receiver_expand_input, backend);
    ASSERT_TRUE(receiver_expand) << receiver_expand.message();

    auto tbm_minus_tbk = subtract_batches(ctx, receiver_expand.value().tbm, sender_expand.value().tbk);
    ASSERT_TRUE(tbm_minus_tbk) << tbm_minus_tbk.message();

    auto expected = compute_expected_s_mul_x(ctx, sender_input.s, x);
    ASSERT_TRUE(expected) << expected.message();

    auto residual = subtract_batches(ctx, tbm_minus_tbk.value(), expected.value());
    ASSERT_TRUE(residual) << residual.message();

    const std::size_t n = params.ring.poly_modulus_degree;
    const std::size_t coeff_mod_count = params.ring.coeff_modulus_bits.size();
    const auto effective_bound = receiver_offline.value().state.effective_noise_bound;

    // We must use an RNSBase containing the FULL set of coefficient moduli to properly compose the 7-prime RNS output.
    auto context_data = ctx.context->key_context_data();
    seal::util::RNSBase full_base(context_data->parms().coeff_modulus(), seal::MemoryManager::GetPool());

    long double max_log2 = 0.0L;

    // Memory for the BigInt reconstruction
    seal::util::Pointer<std::uint64_t> composed_poly =
        seal::util::allocate_poly(n, coeff_mod_count, seal::MemoryManager::GetPool());
    auto coeff_mpi = seal::util::allocate_uint(coeff_mod_count, seal::MemoryManager::GetPool());

    for (auto &poly : residual.value())
    {
        // Residual is already in normal form because `tbm` and `tbk` are natively normal form.

        // Copy the RNS coefficients
        std::copy(poly.coeffs.begin(), poly.coeffs.end(), composed_poly.get());

        // Compose the array into multi-precision integers using the FULL base
        full_base.compose_array(composed_poly.get(), n, seal::MemoryManager::GetPool());

        for (std::size_t i = 0; i < n; ++i)
        {
            // The value is stored tightly packed by full_base.size() after compose_array.
            const std::uint64_t *val_ptr = composed_poly.get() + i * coeff_mod_count;

            int bit_count_pos = seal::util::get_significant_bit_count_uint(val_ptr, coeff_mod_count);

            // Calculate distance from Q_full for negative values (centered representation)
            seal::util::sub_uint(full_base.base_prod(), val_ptr, coeff_mod_count, coeff_mpi.get());
            int bit_count_neg = seal::util::get_significant_bit_count_uint(coeff_mpi.get(), coeff_mod_count);

            int bit_count = std::min(bit_count_pos, bit_count_neg);

            // max_log2 += bit_count;
            if (bit_count > max_log2)
            {
                max_log2 = bit_count;
            }
        }
    }

    // print_dec_value(test_name, "effective_noise_bound", static_cast<std::uint64_t>(effective_bound));
    // std::cout << "INFO " << test_name << ": estimated_final_noise_log2_max=" << max_log2 << std::endl;

    double max_noise_allowed = log_q_bits(params) - params.ring.coeff_modulus_bits.back();
    EXPECT_GT(max_log2, 0);
    EXPECT_LT(max_log2, max_noise_allowed);
}

TEST(ShrinkExpandValidation, PayloadTypeMismatchRejected)
{
    constexpr std::uint64_t protocol_id = 0x54u;
    constexpr std::uint64_t version = 1u;
    constexpr std::uint64_t session_id = 0x444u;
    constexpr std::uint64_t seed_s = 0x8001u;
    constexpr std::uint64_t mismatched_payload_type = 0xDEADBEEFu;
    const auto timeout = std::chrono::milliseconds(10000);

    const auto params = make_params(shrinkexpand_mode::deterministic);

    auto ctx_result = make_ring_ntt_context(params.ring);
    ASSERT_TRUE(ctx_result) << ctx_result.message();
    const auto &ctx = ctx_result.value();

    shrinkexpand_sender_offline_input sender_input{};
    sender_input.params = params;
    sender_input.s = sample_batch(ctx, params.mu, seed_s);

    shrinkexpand_receiver_offline_input receiver_input{};
    receiver_input.params = params;

    auto pair_result = make_in_memory_channel_pair(protocol_id, version, session_id, timeout);
    ASSERT_TRUE(pair_result) << pair_result.message();
    auto channels = std::move(pair_result.value());
    any_channel sender_channel = std::move(channels.first);
    any_channel receiver_channel = std::move(channels.second);

    shrinkexpand_seal_backend backend{};

    protocol_result<shrinkexpand_receiver_offline_output> receiver_result =
        protocol_result<shrinkexpand_receiver_offline_output>::failure(protocol_errc::io_error, "not run");

    std::thread receiver_thread([&]() mutable {
        receiver_result = run_shrinkexpand_receiver(std::move(receiver_channel), receiver_input, backend);
    });

    shrinkexpand_sender_state sender_state{};
    auto message = backend.prepare_offline_sender(sender_input, sender_state);
    ASSERT_TRUE(message) << message.message();

    auto payload = encode_message(message.value());
    ASSERT_TRUE(payload) << payload.message();

    message_envelope envelope{};
    envelope.protocol_id = sender_channel.config().protocol_id;
    envelope.version = sender_channel.config().version;
    envelope.session_id = sender_channel.config().session_id;
    envelope.round_index = 0;
    envelope.sequence_number = 0;
    envelope.payload_type = mismatched_payload_type;
    envelope.payload_size = static_cast<std::uint32_t>(payload.value().size());
    envelope.payload_crc = crc32(payload.value().data(), payload.value().size());

    auto frame = serialize_frame(envelope, payload.value());
    ASSERT_TRUE(frame) << frame.message();

    auto send = sender_channel.send_frame(std::move(frame.value()));
    ASSERT_TRUE(send) << send.message();

    receiver_thread.join();

    ASSERT_FALSE(receiver_result);
    EXPECT_EQ(receiver_result.error(), protocol_errc::flow_violation);
}

TEST(ShrinkExpandValidation, MalformedPayloadRejected)
{
    constexpr std::uint64_t protocol_id = 0x55u;
    constexpr std::uint64_t version = 1u;
    constexpr std::uint64_t session_id = 0x445u;
    constexpr std::uint64_t seed_s = 0x8101u;
    const auto timeout = std::chrono::milliseconds(10000);

    const auto params = make_params(shrinkexpand_mode::deterministic);

    auto ctx_result = make_ring_ntt_context(params.ring);
    ASSERT_TRUE(ctx_result) << ctx_result.message();
    const auto &ctx = ctx_result.value();

    shrinkexpand_sender_offline_input sender_input{};
    sender_input.params = params;
    sender_input.s = sample_batch(ctx, params.mu, seed_s);

    shrinkexpand_receiver_offline_input receiver_input{};
    receiver_input.params = params;

    auto pair_result = make_in_memory_channel_pair(protocol_id, version, session_id, timeout);
    ASSERT_TRUE(pair_result) << pair_result.message();
    auto channels = std::move(pair_result.value());
    any_channel sender_channel = std::move(channels.first);
    any_channel receiver_channel = std::move(channels.second);

    shrinkexpand_seal_backend backend{};

    protocol_result<shrinkexpand_receiver_offline_output> receiver_result =
        protocol_result<shrinkexpand_receiver_offline_output>::failure(protocol_errc::io_error, "not run");

    std::thread receiver_thread([&]() mutable {
        receiver_result = run_shrinkexpand_receiver(std::move(receiver_channel), receiver_input, backend);
    });

    shrinkexpand_sender_state sender_state{};
    auto message = backend.prepare_offline_sender(sender_input, sender_state);
    ASSERT_TRUE(message) << message.message();

    auto payload = encode_message(message.value());
    ASSERT_TRUE(payload) << payload.message();

    auto malformed = payload.value();
    ASSERT_FALSE(malformed.empty());
    malformed.pop_back();

    message_envelope envelope{};
    envelope.protocol_id = sender_channel.config().protocol_id;
    envelope.version = sender_channel.config().version;
    envelope.session_id = sender_channel.config().session_id;
    envelope.round_index = 0;
    envelope.sequence_number = 0;
    envelope.payload_type = message_traits<shrinkexpand_offline_msg>::payload_type;
    envelope.payload_size = static_cast<std::uint32_t>(malformed.size());
    envelope.payload_crc = crc32(malformed.data(), malformed.size());

    auto frame = serialize_frame(envelope, malformed);
    ASSERT_TRUE(frame) << frame.message();

    auto send = sender_channel.send_frame(std::move(frame.value()));
    ASSERT_TRUE(send) << send.message();

    receiver_thread.join();

    ASSERT_FALSE(receiver_result);
    EXPECT_EQ(receiver_result.error(), protocol_errc::decode_validation_failure);
}

TEST(ShrinkExpandValidation, VersionMismatchRejected)
{
    constexpr std::uint64_t protocol_id = 0x56u;
    constexpr std::uint64_t version = 1u;
    constexpr std::uint64_t session_id = 0x446u;
    constexpr std::uint64_t seed_s = 0x8201u;
    constexpr std::uint64_t bad_version = 9u;
    const auto timeout = std::chrono::milliseconds(10000);

    const auto params = make_params(shrinkexpand_mode::deterministic);

    auto ctx_result = make_ring_ntt_context(params.ring);
    ASSERT_TRUE(ctx_result) << ctx_result.message();
    const auto &ctx = ctx_result.value();

    shrinkexpand_sender_offline_input sender_input{};
    sender_input.params = params;
    sender_input.s = sample_batch(ctx, params.mu, seed_s);

    shrinkexpand_receiver_offline_input receiver_input{};
    receiver_input.params = params;

    auto pair_result = make_in_memory_channel_pair(protocol_id, version, session_id, timeout);
    ASSERT_TRUE(pair_result) << pair_result.message();
    auto channels = std::move(pair_result.value());
    any_channel sender_channel = std::move(channels.first);
    any_channel receiver_channel = std::move(channels.second);

    shrinkexpand_seal_backend backend{};

    protocol_result<shrinkexpand_receiver_offline_output> receiver_result =
        protocol_result<shrinkexpand_receiver_offline_output>::failure(protocol_errc::io_error, "not run");

    std::thread receiver_thread([&]() mutable {
        receiver_result = run_shrinkexpand_receiver(std::move(receiver_channel), receiver_input, backend);
    });

    shrinkexpand_sender_state sender_state{};
    auto message = backend.prepare_offline_sender(sender_input, sender_state);
    ASSERT_TRUE(message) << message.message();

    auto payload = encode_message(message.value());
    ASSERT_TRUE(payload) << payload.message();

    message_envelope envelope{};
    envelope.protocol_id = sender_channel.config().protocol_id;
    envelope.version = bad_version;
    envelope.session_id = sender_channel.config().session_id;
    envelope.round_index = 0;
    envelope.sequence_number = 0;
    envelope.payload_type = message_traits<shrinkexpand_offline_msg>::payload_type;
    envelope.payload_size = static_cast<std::uint32_t>(payload.value().size());
    envelope.payload_crc = crc32(payload.value().data(), payload.value().size());

    auto frame = serialize_frame(envelope, payload.value());
    ASSERT_TRUE(frame) << frame.message();

    auto send = sender_channel.send_frame(std::move(frame.value()));
    ASSERT_TRUE(send) << send.message();

    receiver_thread.join();

    ASSERT_FALSE(receiver_result);
    EXPECT_EQ(receiver_result.error(), protocol_errc::unsupported_protocol_version);
}

TEST(ShrinkExpandValidation, SessionMismatchRejected)
{
    constexpr std::uint64_t protocol_id = 0x57u;
    constexpr std::uint64_t version = 1u;
    constexpr std::uint64_t session_id = 0x447u;
    constexpr std::uint64_t seed_s = 0x8301u;
    const auto timeout = std::chrono::milliseconds(10000);

    const auto params = make_params(shrinkexpand_mode::deterministic);

    auto ctx_result = make_ring_ntt_context(params.ring);
    ASSERT_TRUE(ctx_result) << ctx_result.message();
    const auto &ctx = ctx_result.value();

    shrinkexpand_sender_offline_input sender_input{};
    sender_input.params = params;
    sender_input.s = sample_batch(ctx, params.mu, seed_s);

    shrinkexpand_receiver_offline_input receiver_input{};
    receiver_input.params = params;

    auto pair_result = make_in_memory_channel_pair(protocol_id, version, session_id, timeout);
    ASSERT_TRUE(pair_result) << pair_result.message();
    auto channels = std::move(pair_result.value());
    any_channel sender_channel = std::move(channels.first);
    any_channel receiver_channel = std::move(channels.second);

    shrinkexpand_seal_backend backend{};

    protocol_result<shrinkexpand_receiver_offline_output> receiver_result =
        protocol_result<shrinkexpand_receiver_offline_output>::failure(protocol_errc::io_error, "not run");

    std::thread receiver_thread([&]() mutable {
        receiver_result = run_shrinkexpand_receiver(std::move(receiver_channel), receiver_input, backend);
    });

    shrinkexpand_sender_state sender_state{};
    auto message = backend.prepare_offline_sender(sender_input, sender_state);
    ASSERT_TRUE(message) << message.message();

    auto payload = encode_message(message.value());
    ASSERT_TRUE(payload) << payload.message();

    message_envelope envelope{};
    envelope.protocol_id = sender_channel.config().protocol_id;
    envelope.version = sender_channel.config().version;
    envelope.session_id = sender_channel.config().session_id + 1u;
    envelope.round_index = 0;
    envelope.sequence_number = 0;
    envelope.payload_type = message_traits<shrinkexpand_offline_msg>::payload_type;
    envelope.payload_size = static_cast<std::uint32_t>(payload.value().size());
    envelope.payload_crc = crc32(payload.value().data(), payload.value().size());

    auto frame = serialize_frame(envelope, payload.value());
    ASSERT_TRUE(frame) << frame.message();

    auto send = sender_channel.send_frame(std::move(frame.value()));
    ASSERT_TRUE(send) << send.message();

    receiver_thread.join();

    ASSERT_FALSE(receiver_result);
    EXPECT_EQ(receiver_result.error(), protocol_errc::flow_violation);
}

TEST(ShrinkExpandValidation, RingMetadataMismatchRejected)
{
    constexpr std::uint64_t protocol_id = 0x58u;
    constexpr std::uint64_t version = 1u;
    constexpr std::uint64_t session_id = 0x448u;
    constexpr std::uint64_t seed_s = 0x9001u;
    const auto timeout = std::chrono::milliseconds(10000);

    auto sender_params = make_params(shrinkexpand_mode::deterministic);
    auto receiver_params = sender_params;
    receiver_params.ring.coeff_modulus_bits = { 30, 29 };

    auto sender_ctx_result = make_ring_ntt_context(sender_params.ring);
    ASSERT_TRUE(sender_ctx_result) << sender_ctx_result.message();

    shrinkexpand_sender_offline_input sender_input{};
    sender_input.params = sender_params;
    sender_input.s = sample_batch(sender_ctx_result.value(), sender_params.mu, seed_s);

    shrinkexpand_receiver_offline_input receiver_input{};
    receiver_input.params = receiver_params;

    auto pair_result = make_in_memory_channel_pair(protocol_id, version, session_id, timeout);
    ASSERT_TRUE(pair_result) << pair_result.message();

    auto channels = std::move(pair_result.value());
    any_channel sender_channel = std::move(channels.first);
    any_channel receiver_channel = std::move(channels.second);

    shrinkexpand_seal_backend backend{};

    protocol_result<shrinkexpand_sender_offline_output> sender_result =
        protocol_result<shrinkexpand_sender_offline_output>::failure(protocol_errc::io_error, "not run");
    protocol_result<shrinkexpand_receiver_offline_output> receiver_result =
        protocol_result<shrinkexpand_receiver_offline_output>::failure(protocol_errc::io_error, "not run");

    std::thread receiver_thread([&]() mutable {
        receiver_result = run_shrinkexpand_receiver(std::move(receiver_channel), receiver_input, backend);
    });

    std::thread sender_thread(
        [&]() mutable { sender_result = run_shrinkexpand_sender(std::move(sender_channel), sender_input, backend); });

    sender_thread.join();
    receiver_thread.join();

    ASSERT_TRUE(sender_result) << sender_result.message();
    ASSERT_FALSE(receiver_result);
    EXPECT_EQ(receiver_result.error(), protocol_errc::flow_violation);
}

TEST(ShrinkExpandOnline, OfflineStateReuseAcrossQueries)
{
    constexpr std::uint64_t protocol_id = 0x59u;
    constexpr std::uint64_t version = 1u;
    constexpr std::uint64_t session_id = 0x449u;
    constexpr std::uint64_t seed_s = 0xA001u;
    const auto timeout = std::chrono::milliseconds(10000);

    const auto params = make_params(shrinkexpand_mode::deterministic);

    auto ctx_result = make_ring_ntt_context(params.ring);
    ASSERT_TRUE(ctx_result) << ctx_result.message();
    const auto &ctx = ctx_result.value();

    shrinkexpand_sender_offline_input sender_input{};
    sender_input.params = params;
    sender_input.s = sample_batch(ctx, params.mu, seed_s);

    shrinkexpand_receiver_offline_input receiver_input{};
    receiver_input.params = params;

    auto pair_result = make_in_memory_channel_pair(protocol_id, version, session_id, timeout);
    ASSERT_TRUE(pair_result) << pair_result.message();

    auto channels = std::move(pair_result.value());
    any_channel sender_channel = std::move(channels.first);
    any_channel receiver_channel = std::move(channels.second);

    shrinkexpand_seal_backend backend{};

    protocol_result<shrinkexpand_sender_offline_output> sender_offline =
        protocol_result<shrinkexpand_sender_offline_output>::failure(protocol_errc::io_error, "not run");
    protocol_result<shrinkexpand_receiver_offline_output> receiver_offline =
        protocol_result<shrinkexpand_receiver_offline_output>::failure(protocol_errc::io_error, "not run");

    std::thread receiver_thread([&]() mutable {
        receiver_offline = run_shrinkexpand_receiver(std::move(receiver_channel), receiver_input, backend);
    });

    std::thread sender_thread(
        [&]() mutable { sender_offline = run_shrinkexpand_sender(std::move(sender_channel), sender_input, backend); });

    sender_thread.join();
    receiver_thread.join();

    ASSERT_TRUE(sender_offline) << sender_offline.message();
    ASSERT_TRUE(receiver_offline) << receiver_offline.message();

    for (std::uint64_t iter = 0; iter < 3; ++iter)
    {
        const auto seed_x = static_cast<std::uint64_t>(0xB000u + iter);
        const auto seed_tbk_prime = static_cast<std::uint64_t>(0xC000u + iter);
        const auto nonce = static_cast<std::uint64_t>(0xD000u + iter);

        auto x = sample_batch(ctx, params.mu, seed_x);
        auto digest = shrinkexpand_shrink(receiver_offline.value().state, x, backend);
        ASSERT_TRUE(digest) << digest.message();

        auto tbk_prime = sample_scalar_poly(ctx, seed_tbk_prime);
        auto sk_x = build_sk_x(sender_offline.value().state, digest.value(), tbk_prime);
        ASSERT_TRUE(sk_x) << sk_x.message();

        shrinkexpand_expand_sender_input sender_expand_input{};
        sender_expand_input.nonce = nonce;
        sender_expand_input.tbk_prime = tbk_prime;

        shrinkexpand_expand_receiver_input receiver_expand_input{};
        receiver_expand_input.nonce = sender_expand_input.nonce;
        receiver_expand_input.x = x;
        receiver_expand_input.digest = digest.value();
        receiver_expand_input.sk_x = sk_x.value();

        auto sender_expand = shrinkexpand_expand_sender(sender_offline.value().state, sender_expand_input, backend);
        ASSERT_TRUE(sender_expand) << sender_expand.message();

        auto receiver_expand =
            shrinkexpand_expand_receiver(receiver_offline.value().state, receiver_expand_input, backend);
        ASSERT_TRUE(receiver_expand) << receiver_expand.message();

        auto tbm_minus_tbk = subtract_batches(ctx, receiver_expand.value().tbm, sender_expand.value().tbk);
        ASSERT_TRUE(tbm_minus_tbk) << tbm_minus_tbk.message();

        auto expected = compute_expected_s_mul_x(ctx, sender_input.s, x);
        ASSERT_TRUE(expected) << expected.message();

        expect_batch_equal(tbm_minus_tbk.value(), expected.value());
    }
}

#include "loglabel/keyderive_protocol.hpp"

#include "loglabel/comm/codec.hpp"
#include "loglabel/keyderive_spec.hpp"
#include "seal/seal.h"
#include "seal/util/uintarithsmallmod.h"

#include "gtest/gtest.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <random>
#include <thread>
#include <vector>

using namespace loglabel;
using namespace loglabel::comm;

namespace
{
    keyderive_params make_test_params()
    {
        keyderive_params params{};
        params.poly_modulus_degree = 1024;
        params.coeff_modulus_bits = { 30, 30 };
        return params;
    }

    std::vector<seal::Modulus> make_moduli(const keyderive_params &params)
    {
        return seal::CoeffModulus::Create(params.poly_modulus_degree, params.coeff_modulus_bits);
    }

    std::vector<ring_rns_poly> sample_ring_batch(
        std::size_t tau, const keyderive_params &params, const std::vector<seal::Modulus> &moduli,
        std::uint64_t seed)
    {
        std::mt19937_64 rng(seed);
        const std::size_t n = params.poly_modulus_degree;
        const std::size_t mod_count = moduli.size();

        std::vector<ring_rns_poly> out;
        out.reserve(tau);

        for (std::size_t t = 0; t < tau; ++t)
        {
            ring_rns_poly poly{};
            poly.coeffs.resize(n * mod_count);
            for (std::size_t mod_idx = 0; mod_idx < mod_count; ++mod_idx)
            {
                const auto mod = moduli[mod_idx].value();
                std::uniform_int_distribution<std::uint64_t> dist(0, mod - 1u);
                const std::size_t offset = mod_idx * n;
                for (std::size_t i = 0; i < n; ++i)
                {
                    poly.coeffs[offset + i] = dist(rng);
                }
            }
            out.push_back(std::move(poly));
        }

        return out;
    }

    std::uint64_t add_mod(std::uint64_t lhs, std::uint64_t rhs, const seal::Modulus &modulus)
    {
        const auto mod = modulus.value();
        lhs %= mod;
        rhs %= mod;
        const auto sum = lhs + rhs;
        return sum >= mod ? sum - mod : sum;
    }

    ring_rns_poly reference_mul_add(
        const ring_rns_poly &sk1, const ring_rns_poly &d, const ring_rns_poly &sk2, const keyderive_params &params,
        const std::vector<seal::Modulus> &moduli)
    {
        const std::size_t n = params.poly_modulus_degree;
        const std::size_t mod_count = moduli.size();

        ring_rns_poly out{};
        out.coeffs.assign(n * mod_count, 0u);

        for (std::size_t mod_idx = 0; mod_idx < mod_count; ++mod_idx)
        {
            const auto &modulus = moduli[mod_idx];
            const std::size_t offset = mod_idx * n;
            std::vector<std::uint64_t> accum(n, 0u);

            for (std::size_t i = 0; i < n; ++i)
            {
                for (std::size_t j = 0; j < n; ++j)
                {
                    std::size_t idx = i + j;
                    const auto term = seal::util::multiply_uint_mod(
                        sk1.coeffs[offset + i] % modulus.value(), d.coeffs[offset + j] % modulus.value(), modulus);

                    if (idx < n)
                    {
                        accum[idx] = add_mod(accum[idx], term, modulus);
                    }
                    else
                    {
                        idx -= n;
                        const std::uint64_t neg_term = (term == 0u) ? 0u : (modulus.value() - term);
                        accum[idx] = add_mod(accum[idx], neg_term, modulus);
                    }
                }
            }

            for (std::size_t i = 0; i < n; ++i)
            {
                out.coeffs[offset + i] = add_mod(accum[i], sk2.coeffs[offset + i], modulus);
            }
        }

        return out;
    }

    std::vector<ring_rns_poly> reference_mul_add_batch(
        const std::vector<ring_rns_poly> &sk1, const std::vector<ring_rns_poly> &d,
        const std::vector<ring_rns_poly> &sk2, const keyderive_params &params,
        const std::vector<seal::Modulus> &moduli)
    {
        std::vector<ring_rns_poly> out;
        out.reserve(sk1.size());
        for (std::size_t i = 0; i < sk1.size(); ++i)
        {
            out.push_back(reference_mul_add(sk1[i], d[i], sk2[i], params, moduli));
        }
        return out;
    }

    void expect_ring_batch_equal(const std::vector<ring_rns_poly> &a, const std::vector<ring_rns_poly> &b)
    {
        ASSERT_EQ(a.size(), b.size());
        for (std::size_t i = 0; i < a.size(); ++i)
        {
            ASSERT_EQ(a[i].coeffs.size(), b[i].coeffs.size()) << "at batch index " << i;
            for (std::size_t j = 0; j < a[i].coeffs.size(); ++j)
            {
                EXPECT_EQ(a[i].coeffs[j], b[i].coeffs[j]) << "at batch=" << i << ", coeff=" << j;
            }
        }
    }

    keyderive_response_msg make_zero_response(std::uint32_t tau, const keyderive_params &params)
    {
        keyderive_response_msg response{};
        response.poly_modulus_degree = params.poly_modulus_degree;
        response.coeff_modulus_count = static_cast<std::uint32_t>(params.coeff_modulus_bits.size());
        response.tau = tau;
        response.m_ntt_coeffs.assign(
            static_cast<std::size_t>(tau) * params.poly_modulus_degree * params.coeff_modulus_bits.size(), 0u);
        return response;
    }

    void print_test_banner(const char *test_name, const keyderive_params &params, std::size_t tau)
    {
        std::cout << "[keyderive-test] " << test_name
                  << " params{poly_modulus_degree=" << params.poly_modulus_degree
                  << ", coeff_modulus_bits=[";
        for (std::size_t i = 0; i < params.coeff_modulus_bits.size(); ++i)
        {
            if (i > 0)
            {
                std::cout << ",";
            }
            std::cout << params.coeff_modulus_bits[i];
        }
        std::cout << "], tau=" << tau << "}" << std::endl;
    }

    void print_test_elapsed(const char *test_name, std::chrono::steady_clock::time_point start)
    {
        const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - start);
        std::cout << "[keyderive-test] " << test_name
                  << " elapsed_ms=" << std::fixed << std::setprecision(3)
                  << (static_cast<double>(elapsed.count()) / 1000.0) << std::endl;
    }

} // namespace

TEST(KeyderiveProtocol, HappyPathAndAlgebraicRelation)
{
    const auto start = std::chrono::steady_clock::now();
    const auto params = make_test_params();
    const auto moduli = make_moduli(params);
    const std::size_t tau = 3;
    print_test_banner("KeyderiveProtocol.HappyPathAndAlgebraicRelation", params, tau);

    keyderive_sender_input sender_input{};
    sender_input.params = params;
    sender_input.sk1 = sample_ring_batch(tau, params, moduli, 0x1111u);
    sender_input.sk2 = sample_ring_batch(tau, params, moduli, 0x2222u);

    keyderive_receiver_input receiver_input{};
    receiver_input.params = params;
    receiver_input.d = sample_ring_batch(tau, params, moduli, 0x3333u);

    auto pair_result = make_in_memory_channel_pair(
        /*protocol_id=*/0x4B44u, /*version=*/1u, /*session_id=*/0x99u, std::chrono::milliseconds(1000));
    ASSERT_TRUE(pair_result) << pair_result.message();

    auto channels = std::move(pair_result.value());
    any_channel sender_channel = std::move(channels.first);
    any_channel receiver_channel = std::move(channels.second);

    keyderive_seal_ntt_backend backend{};

    protocol_result<keyderive_sender_output> sender_result =
        protocol_result<keyderive_sender_output>::failure(protocol_errc::io_error, "not run");
    protocol_result<keyderive_receiver_output> receiver_result =
        protocol_result<keyderive_receiver_output>::failure(protocol_errc::io_error, "not run");

    std::thread receiver_thread([ch = std::move(receiver_channel), &receiver_result, &receiver_input, &backend]() mutable {
        receiver_result = run_keyderive_receiver(std::move(ch), receiver_input, backend);
    });

    std::thread sender_thread([ch = std::move(sender_channel), &sender_result, &sender_input, &backend]() mutable {
        sender_result = run_keyderive_sender(std::move(ch), sender_input, backend);
    });

    sender_thread.join();
    receiver_thread.join();

    ASSERT_TRUE(sender_result) << sender_result.message();
    ASSERT_TRUE(receiver_result) << receiver_result.message();

    expect_ring_batch_equal(sender_result.value().k, sender_input.sk2);

    auto expected_m = reference_mul_add_batch(sender_input.sk1, receiver_input.d, sender_input.sk2, params, moduli);
    expect_ring_batch_equal(receiver_result.value().m, expected_m);
    print_test_elapsed("KeyderiveProtocol.HappyPathAndAlgebraicRelation", start);
}

TEST(KeyderiveProtocol, DeterministicRegressionSeeds)
{
    const auto start = std::chrono::steady_clock::now();
    const auto params = make_test_params();
    const auto moduli = make_moduli(params);
    const std::size_t tau = 2;
    const std::vector<std::uint64_t> seeds = { 0x10u, 0x20u, 0x30u, 0x40u };
    print_test_banner("KeyderiveProtocol.DeterministicRegressionSeeds", params, tau);
    std::cout << "[keyderive-test] seeds=[0x10,0x20,0x30,0x40]" << std::endl;

    keyderive_seal_ntt_backend backend{};

    for (std::uint64_t seed : seeds)
    {
        keyderive_sender_input sender_input{};
        sender_input.params = params;
        sender_input.sk1 = sample_ring_batch(tau, params, moduli, seed + 1u);
        sender_input.sk2 = sample_ring_batch(tau, params, moduli, seed + 2u);

        keyderive_receiver_input receiver_input{};
        receiver_input.params = params;
        receiver_input.d = sample_ring_batch(tau, params, moduli, seed + 3u);

        auto pair_result = make_in_memory_channel_pair(
            /*protocol_id=*/0x4B44u, /*version=*/1u, /*session_id=*/seed + 99u, std::chrono::milliseconds(1000));
        ASSERT_TRUE(pair_result) << pair_result.message();

        auto channels = std::move(pair_result.value());
        any_channel sender_channel = std::move(channels.first);
        any_channel receiver_channel = std::move(channels.second);

        protocol_result<keyderive_sender_output> sender_result =
            protocol_result<keyderive_sender_output>::failure(protocol_errc::io_error, "not run");
        protocol_result<keyderive_receiver_output> receiver_result =
            protocol_result<keyderive_receiver_output>::failure(protocol_errc::io_error, "not run");

        std::thread receiver_thread([ch = std::move(receiver_channel), &receiver_result, &receiver_input, &backend]() mutable {
            receiver_result = run_keyderive_receiver(std::move(ch), receiver_input, backend);
        });

        std::thread sender_thread([ch = std::move(sender_channel), &sender_result, &sender_input, &backend]() mutable {
            sender_result = run_keyderive_sender(std::move(ch), sender_input, backend);
        });

        sender_thread.join();
        receiver_thread.join();

        ASSERT_TRUE(sender_result) << sender_result.message();
        ASSERT_TRUE(receiver_result) << receiver_result.message();

        auto expected_m = reference_mul_add_batch(sender_input.sk1, receiver_input.d, sender_input.sk2, params, moduli);
        expect_ring_batch_equal(receiver_result.value().m, expected_m);
    }
    print_test_elapsed("KeyderiveProtocol.DeterministicRegressionSeeds", start);
}

TEST(KeyderiveValidation, PayloadTypeMismatchFails)
{
    const auto start = std::chrono::steady_clock::now();
    const auto params = make_test_params();
    const auto moduli = make_moduli(params);
    print_test_banner("KeyderiveValidation.PayloadTypeMismatchFails", params, 1);

    keyderive_receiver_input receiver_input{};
    receiver_input.params = params;
    receiver_input.d = sample_ring_batch(1, params, moduli, 0xABCu);

    auto pair_result = make_in_memory_channel_pair(
        /*protocol_id=*/0x888u, /*version=*/1u, /*session_id=*/0x123u, std::chrono::milliseconds(1000));
    ASSERT_TRUE(pair_result) << pair_result.message();

    auto channels = std::move(pair_result.value());
    any_channel sender_channel = std::move(channels.first);
    any_channel receiver_channel = std::move(channels.second);

    keyderive_seal_ntt_backend backend{};
    protocol_result<keyderive_receiver_output> receiver_result =
        protocol_result<keyderive_receiver_output>::failure(protocol_errc::io_error, "not run");

    std::thread receiver_thread([ch = std::move(receiver_channel), &receiver_result, &receiver_input, &backend]() mutable {
        receiver_result = run_keyderive_receiver(std::move(ch), receiver_input, backend);
    });

    auto req_frame = sender_channel.recv_frame();
    ASSERT_TRUE(req_frame) << req_frame.message();

    auto response = make_zero_response(1u, params);
    auto payload = encode_message(response);
    ASSERT_TRUE(payload) << payload.message();

    message_envelope envelope{};
    envelope.protocol_id = sender_channel.config().protocol_id;
    envelope.version = sender_channel.config().version;
    envelope.session_id = sender_channel.config().session_id;
    envelope.round_index = 1;
    envelope.sequence_number = 0;
    envelope.payload_type = 0xDEADBEEFu; // Intentional mismatch.
    envelope.payload_size = static_cast<std::uint32_t>(payload.value().size());
    envelope.payload_crc = crc32(payload.value().data(), payload.value().size());

    auto frame_result = serialize_frame(envelope, payload.value());
    ASSERT_TRUE(frame_result) << frame_result.message();

    auto send_result = sender_channel.send_frame(std::move(frame_result.value()));
    ASSERT_TRUE(send_result) << send_result.message();

    receiver_thread.join();

    ASSERT_FALSE(receiver_result);
    EXPECT_EQ(receiver_result.error(), protocol_errc::flow_violation);
    print_test_elapsed("KeyderiveValidation.PayloadTypeMismatchFails", start);
}

TEST(KeyderiveValidation, MalformedPayloadFails)
{
    const auto start = std::chrono::steady_clock::now();
    const auto params = make_test_params();
    const auto moduli = make_moduli(params);
    print_test_banner("KeyderiveValidation.MalformedPayloadFails", params, 1);

    keyderive_receiver_input receiver_input{};
    receiver_input.params = params;
    receiver_input.d = sample_ring_batch(1, params, moduli, 0xDEFu);

    auto pair_result = make_in_memory_channel_pair(
        /*protocol_id=*/0x889u, /*version=*/1u, /*session_id=*/0x124u, std::chrono::milliseconds(1000));
    ASSERT_TRUE(pair_result) << pair_result.message();

    auto channels = std::move(pair_result.value());
    any_channel sender_channel = std::move(channels.first);
    any_channel receiver_channel = std::move(channels.second);

    keyderive_seal_ntt_backend backend{};
    protocol_result<keyderive_receiver_output> receiver_result =
        protocol_result<keyderive_receiver_output>::failure(protocol_errc::io_error, "not run");

    std::thread receiver_thread([ch = std::move(receiver_channel), &receiver_result, &receiver_input, &backend]() mutable {
        receiver_result = run_keyderive_receiver(std::move(ch), receiver_input, backend);
    });

    auto req_frame = sender_channel.recv_frame();
    ASSERT_TRUE(req_frame) << req_frame.message();

    auto response = make_zero_response(1u, params);
    auto payload = encode_message(response);
    ASSERT_TRUE(payload) << payload.message();

    auto malformed = payload.value();
    ASSERT_FALSE(malformed.empty());
    malformed.pop_back();

    message_envelope envelope{};
    envelope.protocol_id = sender_channel.config().protocol_id;
    envelope.version = sender_channel.config().version;
    envelope.session_id = sender_channel.config().session_id;
    envelope.round_index = 1;
    envelope.sequence_number = 0;
    envelope.payload_type = message_traits<keyderive_response_msg>::payload_type;
    envelope.payload_size = static_cast<std::uint32_t>(malformed.size());
    envelope.payload_crc = crc32(malformed.data(), malformed.size());

    auto frame_result = serialize_frame(envelope, malformed);
    ASSERT_TRUE(frame_result) << frame_result.message();

    auto send_result = sender_channel.send_frame(std::move(frame_result.value()));
    ASSERT_TRUE(send_result) << send_result.message();

    receiver_thread.join();

    ASSERT_FALSE(receiver_result);
    EXPECT_EQ(receiver_result.error(), protocol_errc::decode_validation_failure);
    print_test_elapsed("KeyderiveValidation.MalformedPayloadFails", start);
}

TEST(KeyderiveValidation, VersionMismatchFails)
{
    const auto start = std::chrono::steady_clock::now();
    const auto params = make_test_params();
    const auto moduli = make_moduli(params);
    print_test_banner("KeyderiveValidation.VersionMismatchFails", params, 1);

    keyderive_receiver_input receiver_input{};
    receiver_input.params = params;
    receiver_input.d = sample_ring_batch(1, params, moduli, 0xFEDu);

    auto pair_result = make_in_memory_channel_pair(
        /*protocol_id=*/0x88Au, /*version=*/1u, /*session_id=*/0x125u, std::chrono::milliseconds(1000));
    ASSERT_TRUE(pair_result) << pair_result.message();

    auto channels = std::move(pair_result.value());
    any_channel sender_channel = std::move(channels.first);
    any_channel receiver_channel = std::move(channels.second);

    keyderive_seal_ntt_backend backend{};
    protocol_result<keyderive_receiver_output> receiver_result =
        protocol_result<keyderive_receiver_output>::failure(protocol_errc::io_error, "not run");

    std::thread receiver_thread([ch = std::move(receiver_channel), &receiver_result, &receiver_input, &backend]() mutable {
        receiver_result = run_keyderive_receiver(std::move(ch), receiver_input, backend);
    });

    auto req_frame = sender_channel.recv_frame();
    ASSERT_TRUE(req_frame) << req_frame.message();

    auto response = make_zero_response(1u, params);
    auto payload = encode_message(response);
    ASSERT_TRUE(payload) << payload.message();

    message_envelope envelope{};
    envelope.protocol_id = sender_channel.config().protocol_id;
    envelope.version = 9; // Intentional mismatch.
    envelope.session_id = sender_channel.config().session_id;
    envelope.round_index = 1;
    envelope.sequence_number = 0;
    envelope.payload_type = message_traits<keyderive_response_msg>::payload_type;
    envelope.payload_size = static_cast<std::uint32_t>(payload.value().size());
    envelope.payload_crc = crc32(payload.value().data(), payload.value().size());

    auto frame_result = serialize_frame(envelope, payload.value());
    ASSERT_TRUE(frame_result) << frame_result.message();

    auto send_result = sender_channel.send_frame(std::move(frame_result.value()));
    ASSERT_TRUE(send_result) << send_result.message();

    receiver_thread.join();

    ASSERT_FALSE(receiver_result);
    EXPECT_EQ(receiver_result.error(), protocol_errc::unsupported_protocol_version);
    print_test_elapsed("KeyderiveValidation.VersionMismatchFails", start);
}

TEST(KeyderiveValidation, SessionMismatchFails)
{
    const auto start = std::chrono::steady_clock::now();
    const auto params = make_test_params();
    const auto moduli = make_moduli(params);
    print_test_banner("KeyderiveValidation.SessionMismatchFails", params, 1);

    keyderive_receiver_input receiver_input{};
    receiver_input.params = params;
    receiver_input.d = sample_ring_batch(1, params, moduli, 0xAABBu);

    auto pair_result = make_in_memory_channel_pair(
        /*protocol_id=*/0x88Bu, /*version=*/1u, /*session_id=*/0x126u, std::chrono::milliseconds(1000));
    ASSERT_TRUE(pair_result) << pair_result.message();

    auto channels = std::move(pair_result.value());
    any_channel sender_channel = std::move(channels.first);
    any_channel receiver_channel = std::move(channels.second);

    keyderive_seal_ntt_backend backend{};
    protocol_result<keyderive_receiver_output> receiver_result =
        protocol_result<keyderive_receiver_output>::failure(protocol_errc::io_error, "not run");

    std::thread receiver_thread([ch = std::move(receiver_channel), &receiver_result, &receiver_input, &backend]() mutable {
        receiver_result = run_keyderive_receiver(std::move(ch), receiver_input, backend);
    });

    auto req_frame = sender_channel.recv_frame();
    ASSERT_TRUE(req_frame) << req_frame.message();

    auto response = make_zero_response(1u, params);
    auto payload = encode_message(response);
    ASSERT_TRUE(payload) << payload.message();

    message_envelope envelope{};
    envelope.protocol_id = sender_channel.config().protocol_id;
    envelope.version = sender_channel.config().version;
    envelope.session_id = sender_channel.config().session_id + 1u; // Intentional mismatch.
    envelope.round_index = 1;
    envelope.sequence_number = 0;
    envelope.payload_type = message_traits<keyderive_response_msg>::payload_type;
    envelope.payload_size = static_cast<std::uint32_t>(payload.value().size());
    envelope.payload_crc = crc32(payload.value().data(), payload.value().size());

    auto frame_result = serialize_frame(envelope, payload.value());
    ASSERT_TRUE(frame_result) << frame_result.message();

    auto send_result = sender_channel.send_frame(std::move(frame_result.value()));
    ASSERT_TRUE(send_result) << send_result.message();

    receiver_thread.join();

    ASSERT_FALSE(receiver_result);
    EXPECT_EQ(receiver_result.error(), protocol_errc::flow_violation);
    print_test_elapsed("KeyderiveValidation.SessionMismatchFails", start);
}

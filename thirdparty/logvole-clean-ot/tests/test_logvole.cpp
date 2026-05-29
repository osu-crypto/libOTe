#include <atomic>
#include <chrono>
#include <cstdint>
#include <gtest/gtest.h>
#include <thread>
#include <vector>
#include "logvole/civole_protocol.hpp"

using namespace logvole;
using namespace logvole::comm;

namespace
{
    struct offl_pair_result
    {
        protocol_result<civole_sender_offl_output> sender =
            protocol_result<civole_sender_offl_output>::failure(protocol_errc::io_error, "not run");
        protocol_result<civole_receiver_offl_output> receiver =
            protocol_result<civole_receiver_offl_output>::failure(protocol_errc::io_error, "not run");
    };

    struct online_pair_result
    {
        protocol_result<civole_releasek_output> releasek =
            protocol_result<civole_releasek_output>::failure(protocol_errc::io_error, "not run");
        protocol_result<civole_sender_release_output> sender_release =
            protocol_result<civole_sender_release_output>::failure(protocol_errc::io_error, "not run");
        protocol_result<civole_receiver_setx_output> receiver_setx =
            protocol_result<civole_receiver_setx_output>::failure(protocol_errc::io_error, "not run");
    };

    civole_params make_params(std::uint32_t worker_threads = 1u)
    {
        auto params = make_default_civole_params(worker_threads);
        EXPECT_TRUE(params) << params.message();
        return params.value();
    }

    std::uint64_t resolve_modulus(const civole_params &params)
    {
        auto modulus = resolve_civole_modulus(params);
        EXPECT_TRUE(modulus) << modulus.message();
        return modulus ? modulus.value() : 0u;
    }

    offl_pair_result run_offl_pair(const civole_params &params, std::uint64_t delta, std::size_t w)
    {
        static std::atomic<std::uint64_t> session_counter{ 0xC100u };
        const std::uint64_t session_id = session_counter.fetch_add(1u);
        auto channels = make_in_memory_channel_pair(0xC170u, 1u, session_id, std::chrono::milliseconds(600000));
        EXPECT_TRUE(channels) << channels.message();
        if (!channels)
        {
            return {};
        }

        auto pair = std::move(channels.value());
        logvole_seal_backend sender_backend{};
        logvole_seal_backend receiver_backend{};
        offl_pair_result out{};

        std::thread receiver_thread([&]() mutable {
            civole_receiver_offl_input input{};
            input.params = params;
            out.receiver = run_civole_receiver_offl(std::move(pair.second), input, receiver_backend);
        });
        std::thread sender_thread([&]() mutable {
            civole_sender_offl_input input{};
            input.params = params;
            input.delta = delta;
            input.w = w;
            out.sender = run_civole_sender_offl(std::move(pair.first), input, sender_backend);
        });

        sender_thread.join();
        receiver_thread.join();
        return out;
    }

    online_pair_result run_online_pair(
        civole_sender_state &sender_state, civole_receiver_state &receiver_state, civole_sid sid,
        const std::vector<std::uint64_t> &x)
    {
        static std::atomic<std::uint64_t> session_counter{ 0xD100u };
        const std::uint64_t session_id = session_counter.fetch_add(1u);
        auto channels = make_in_memory_channel_pair(0xC170u, 1u, session_id, std::chrono::milliseconds(600000));
        EXPECT_TRUE(channels) << channels.message();
        if (!channels)
        {
            return {};
        }

        logvole_seal_backend sender_backend{};
        logvole_seal_backend receiver_backend{};
        online_pair_result out{};
        out.releasek = run_civole_sender_releasek_int(sender_state, sid, sender_backend);
        if (!out.releasek)
        {
            return out;
        }

        auto pair = std::move(channels.value());
        std::thread receiver_thread([&]() mutable {
            out.receiver_setx =
                run_civole_receiver_setx_int(std::move(pair.second), receiver_state, sid, x, receiver_backend);
        });
        std::thread sender_thread([&]() mutable {
            out.sender_release =
                run_civole_sender_release_int(std::move(pair.first), sender_state, sid, sender_backend);
        });

        sender_thread.join();
        receiver_thread.join();
        return out;
    }

    void expect_vole_relation(
        const std::vector<std::uint64_t> &x, std::uint64_t delta, const std::vector<std::uint64_t> &keys,
        const std::vector<std::uint64_t> &macs, std::uint64_t modulus)
    {
        ASSERT_EQ(keys.size(), x.size());
        ASSERT_EQ(macs.size(), x.size());
        for (std::size_t idx = 0; idx < x.size(); ++idx)
        {
            const auto prod = static_cast<unsigned __int128>(x[idx]) * delta;
            const std::uint64_t expected = static_cast<std::uint64_t>((keys[idx] + prod) % modulus);
            EXPECT_EQ(macs[idx], expected) << "VOLE relation mismatch at index " << idx;
        }
    }
} // namespace

TEST(CivolePublicApiTest, ProducesDecodedZpVoleInvariant)
{
    const auto params = make_params();
    const std::uint64_t modulus = resolve_modulus(params);
    const std::uint64_t delta = 17u % modulus;
    const std::vector<std::uint64_t> x{ 2u, 3u, 5u, 7u, 11u, 13u, 17u, 19u, 23u };

    auto offl = run_offl_pair(params, delta, x.size());
    ASSERT_TRUE(offl.sender) << offl.sender.message();
    ASSERT_TRUE(offl.receiver) << offl.receiver.message();
    EXPECT_EQ(offl.sender.value().state.w, x.size());
    EXPECT_EQ(offl.receiver.value().state.w, x.size());
    EXPECT_EQ(offl.sender.value().state.modulus, modulus);
    EXPECT_EQ(offl.receiver.value().state.modulus, modulus);

    auto online = run_online_pair(offl.sender.value().state, offl.receiver.value().state, 101u, x);
    ASSERT_TRUE(online.releasek) << online.releasek.message();
    ASSERT_TRUE(online.sender_release) << online.sender_release.message();
    ASSERT_TRUE(online.receiver_setx) << online.receiver_setx.message();
    expect_vole_relation(x, delta, online.releasek.value().keys, online.receiver_setx.value().macs, modulus);
}

TEST(CivolePublicApiTest, ReleaseIntRequiresPriorReleasek)
{
    const auto params = make_params();
    const std::uint64_t modulus = resolve_modulus(params);
    auto offl = run_offl_pair(params, 5u % modulus, 8u);
    ASSERT_TRUE(offl.sender) << offl.sender.message();

    auto channels = make_in_memory_channel_pair(0xC170u, 1u, 0xE001u, std::chrono::milliseconds(600000));
    ASSERT_TRUE(channels) << channels.message();
    logvole_seal_backend backend{};
    auto result =
        run_civole_sender_release_int(std::move(channels.value().first), offl.sender.value().state, 9u, backend);
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error(), protocol_errc::invalid_state_transition);
}

TEST(CivolePublicApiTest, RejectsZeroDelta)
{
    const auto params = make_params();
    auto channels = make_in_memory_channel_pair(0xC170u, 1u, 0xE101u, std::chrono::milliseconds(600000));
    ASSERT_TRUE(channels) << channels.message();
    logvole_seal_backend backend{};

    civole_sender_offl_input input{};
    input.params = params;
    input.delta = 0u;
    input.w = 8u;
    auto result = run_civole_sender_offl(std::move(channels.value().first), input, backend);
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error(), protocol_errc::config_error);
    EXPECT_NE(result.message().find("Delta"), std::string::npos);
}

TEST(CivolePublicApiTest, RejectsOutOfFieldReceiverValue)
{
    const auto params = make_params();
    const std::uint64_t modulus = resolve_modulus(params);
    auto offl = run_offl_pair(params, 3u % modulus, 8u);
    ASSERT_TRUE(offl.sender) << offl.sender.message();
    ASSERT_TRUE(offl.receiver) << offl.receiver.message();

    auto channels = make_in_memory_channel_pair(0xC170u, 1u, 0xE201u, std::chrono::milliseconds(600000));
    ASSERT_TRUE(channels) << channels.message();
    logvole_seal_backend backend{};
    std::vector<std::uint64_t> x(8u, 1u);
    x[0] = modulus;

    auto result =
        run_civole_receiver_setx_int(std::move(channels.value().second), offl.receiver.value().state, 11u, x, backend);
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error(), protocol_errc::config_error);
    EXPECT_NE(result.message().find("x[0]"), std::string::npos);
}

TEST(CivolePublicApiTest, SupportsSequentialSids)
{
    const auto params = make_params();
    const std::uint64_t modulus = resolve_modulus(params);
    const std::uint64_t delta = 9u % modulus;
    auto offl = run_offl_pair(params, delta, 8u);
    ASSERT_TRUE(offl.sender) << offl.sender.message();
    ASSERT_TRUE(offl.receiver) << offl.receiver.message();

    const std::vector<std::uint64_t> x1{ 1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u };
    auto first = run_online_pair(offl.sender.value().state, offl.receiver.value().state, 501u, x1);
    ASSERT_TRUE(first.releasek) << first.releasek.message();
    ASSERT_TRUE(first.sender_release) << first.sender_release.message();
    ASSERT_TRUE(first.receiver_setx) << first.receiver_setx.message();
    expect_vole_relation(x1, delta, first.releasek.value().keys, first.receiver_setx.value().macs, modulus);

    const std::vector<std::uint64_t> x2{ 8u, 7u, 6u, 5u, 4u, 3u, 2u, 1u };
    auto second = run_online_pair(offl.sender.value().state, offl.receiver.value().state, 502u, x2);
    ASSERT_TRUE(second.releasek) << second.releasek.message();
    ASSERT_TRUE(second.sender_release) << second.sender_release.message();
    ASSERT_TRUE(second.receiver_setx) << second.receiver_setx.message();
    expect_vole_relation(x2, delta, second.releasek.value().keys, second.receiver_setx.value().macs, modulus);
}

TEST(CivolePublicApiTest, RejectsSameSidReuseByEitherParty)
{
    const auto params = make_params();
    const std::uint64_t modulus = resolve_modulus(params);
    const std::uint64_t delta = 13u % modulus;
    constexpr civole_sid sid = 901u;
    auto offl = run_offl_pair(params, delta, 8u);
    ASSERT_TRUE(offl.sender) << offl.sender.message();
    ASSERT_TRUE(offl.receiver) << offl.receiver.message();

    const std::vector<std::uint64_t> x1{ 1u, 1u, 2u, 3u, 5u, 8u, 13u, 21u };
    auto first = run_online_pair(offl.sender.value().state, offl.receiver.value().state, sid, x1);
    ASSERT_TRUE(first.releasek) << first.releasek.message();
    ASSERT_TRUE(first.sender_release) << first.sender_release.message();
    ASSERT_TRUE(first.receiver_setx) << first.receiver_setx.message();
    expect_vole_relation(x1, delta, first.releasek.value().keys, first.receiver_setx.value().macs, modulus);

    logvole_seal_backend sender_backend{};
    auto releasek_again = run_civole_sender_releasek_int(offl.sender.value().state, sid, sender_backend);
    ASSERT_FALSE(releasek_again);
    EXPECT_EQ(releasek_again.error(), protocol_errc::invalid_state_transition);

    auto sender_channels = make_in_memory_channel_pair(0xC170u, 1u, 0xE301u, std::chrono::milliseconds(600000));
    ASSERT_TRUE(sender_channels) << sender_channels.message();
    auto release_again = run_civole_sender_release_int(
        std::move(sender_channels.value().first), offl.sender.value().state, sid, sender_backend);
    ASSERT_FALSE(release_again);
    EXPECT_EQ(release_again.error(), protocol_errc::invalid_state_transition);

    logvole_seal_backend receiver_backend{};
    auto receiver_channels = make_in_memory_channel_pair(0xC170u, 1u, 0xE302u, std::chrono::milliseconds(600000));
    ASSERT_TRUE(receiver_channels) << receiver_channels.message();
    const std::vector<std::uint64_t> x2{ 21u, 13u, 8u, 5u, 3u, 2u, 1u, 1u };
    auto setx_again = run_civole_receiver_setx_int(
        std::move(receiver_channels.value().second), offl.receiver.value().state, sid, x2, receiver_backend);
    ASSERT_FALSE(setx_again);
    EXPECT_EQ(setx_again.error(), protocol_errc::invalid_state_transition);
}

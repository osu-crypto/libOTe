#include "libOTe/Vole/LogVole/LogVoleCivole.h"

#include "libOTe_Tests/LogVole_TestUtil.h"

#include "coproto/Socket/LocalAsyncSock.h"
#include "macoro/sync_wait.h"
#include "macoro/when_all.h"

#include <stdexcept>
#include <span>
#include <tuple>
#include <vector>

using namespace osuCrypto::LogVole;
using osuCrypto::u64;

namespace
{
    CivoleParams make_params()
    {
        CivoleParams params{};
        LOGVOLE_REQUIRE_TRUE(makeDefaultCivoleParams(params));
        return params;
    }

    u64 resolve_modulus(const CivoleParams& params)
    {
        u64 modulus = 0;
        LOGVOLE_REQUIRE_TRUE(resolveCivoleModulus(params, modulus));
        return modulus;
    }

    void run_offline_pair(
        const CivoleParams& params,
        u64 delta,
        u64 w,
        CivoleSenderState& senderState,
        CivoleReceiverState& receiverState)
    {
        CivoleSenderOfflineInput senderInput{};
        senderInput.mParams = params;
        senderInput.mDelta = delta;
        senderInput.mW = w;

        CivoleReceiverOfflineInput receiverInput{};
        receiverInput.mParams = params;

        auto sockets = coproto::LocalAsyncSocket::makePair();
        auto result = macoro::sync_wait(macoro::when_all_ready(
            civoleSenderOffline(senderInput, senderState, sockets[0]),
            civoleReceiverOffline(receiverInput, receiverState, sockets[1])));
        std::get<0>(result).result();
        std::get<1>(result).result();
    }

    void run_online_pair(
        CivoleSenderState& senderState,
        CivoleReceiverState& receiverState,
        CivoleSid sid,
        const std::vector<u64>& x,
        CivoleReleaseKOutput& releaseK,
        CivoleSenderReleaseOutput& senderRelease,
        CivoleReceiverSetXOutput& receiverSetX)
    {
        LOGVOLE_REQUIRE_TRUE(civoleSenderReleaseK(senderState, sid, releaseK));

        auto sockets = coproto::LocalAsyncSocket::makePair();
        auto result = macoro::sync_wait(macoro::when_all_ready(
            civoleSenderRelease(senderState, sid, senderRelease, sockets[0]),
            civoleReceiverSetX(receiverState, sid, x, receiverSetX, sockets[1])));
        std::get<0>(result).result();
        std::get<1>(result).result();
    }

    void expect_vole_relation(
        std::span<const u64> x,
        u64 delta,
        std::span<const u64> keys,
        std::span<const u64> macs,
        u64 modulus)
    {
        LOGVOLE_REQUIRE_EQ(keys.size(), x.size());
        LOGVOLE_REQUIRE_EQ(macs.size(), x.size());
        for (std::size_t idx = 0; idx < x.size(); ++idx)
        {
            const auto prod = static_cast<unsigned __int128>(x[idx]) * delta;
            const u64 expected = static_cast<u64>((keys[idx] + prod) % modulus);
            LOGVOLE_EXPECT_EQ(macs[idx], expected) << "VOLE relation mismatch at index " << idx;
        }
    }
}

void LogVole_Civole_PublicApiInvariant(const oc::CLP&)
{
    const auto params = make_params();
    const u64 modulus = resolve_modulus(params);
    const u64 delta = 17 % modulus;
    const std::vector<u64> x{ 2, 3, 5, 7, 11, 13, 17, 19, 23 };

    CivoleSenderState senderState{};
    CivoleReceiverState receiverState{};
    run_offline_pair(params, delta, x.size(), senderState, receiverState);
    LOGVOLE_EXPECT_EQ(senderState.mW, x.size());
    LOGVOLE_EXPECT_EQ(receiverState.mW, x.size());
    LOGVOLE_EXPECT_EQ(senderState.mModulus, modulus);
    LOGVOLE_EXPECT_EQ(receiverState.mModulus, modulus);

    CivoleReleaseKOutput releaseK{};
    CivoleSenderReleaseOutput senderRelease{};
    CivoleReceiverSetXOutput receiverSetX{};
    run_online_pair(senderState, receiverState, 101, x, releaseK, senderRelease, receiverSetX);
    expect_vole_relation(x, delta, releaseK.mKeys, receiverSetX.mMacs, modulus);
}

void LogVole_Civole_ReleaseRequiresPriorReleaseK(const oc::CLP&)
{
    const auto params = make_params();
    const u64 modulus = resolve_modulus(params);

    CivoleSenderState senderState{};
    CivoleReceiverState receiverState{};
    run_offline_pair(params, 5 % modulus, 8, senderState, receiverState);

    CivoleSenderReleaseOutput senderRelease{};
    auto sockets = coproto::LocalAsyncSocket::makePair();
    bool threw = false;
    try
    {
        macoro::sync_wait(civoleSenderRelease(senderState, 9, senderRelease, sockets[0]));
    }
    catch (const std::runtime_error&)
    {
        threw = true;
    }
    LOGVOLE_EXPECT_TRUE(threw);
}

void LogVole_Civole_RejectsZeroDelta(const oc::CLP&)
{
    const auto params = make_params();

    CivoleSenderOfflineInput senderInput{};
    senderInput.mParams = params;
    senderInput.mDelta = 0;
    senderInput.mW = 8;

    CivoleSenderState senderState{};
    auto sockets = coproto::LocalAsyncSocket::makePair();
    bool threw = false;
    try
    {
        macoro::sync_wait(civoleSenderOffline(senderInput, senderState, sockets[0]));
    }
    catch (const std::runtime_error&)
    {
        threw = true;
    }
    LOGVOLE_EXPECT_TRUE(threw);
}

void LogVole_Civole_RejectsOutOfFieldReceiverValue(const oc::CLP&)
{
    const auto params = make_params();
    const u64 modulus = resolve_modulus(params);

    CivoleSenderState senderState{};
    CivoleReceiverState receiverState{};
    run_offline_pair(params, 3 % modulus, 8, senderState, receiverState);

    std::vector<u64> x(8, 1);
    x[0] = modulus;

    CivoleReceiverSetXOutput receiverSetX{};
    auto sockets = coproto::LocalAsyncSocket::makePair();
    bool threw = false;
    try
    {
        macoro::sync_wait(civoleReceiverSetX(receiverState, 11, x, receiverSetX, sockets[1]));
    }
    catch (const std::runtime_error&)
    {
        threw = true;
    }
    LOGVOLE_EXPECT_TRUE(threw);
}

void LogVole_Civole_SupportsSequentialSids(const oc::CLP&)
{
    const auto params = make_params();
    const u64 modulus = resolve_modulus(params);
    const u64 delta = 9 % modulus;

    CivoleSenderState senderState{};
    CivoleReceiverState receiverState{};
    run_offline_pair(params, delta, 8, senderState, receiverState);

    const std::vector<u64> x1{ 1, 2, 3, 4, 5, 6, 7, 8 };
    CivoleReleaseKOutput releaseK1{};
    CivoleSenderReleaseOutput senderRelease1{};
    CivoleReceiverSetXOutput receiverSetX1{};
    run_online_pair(senderState, receiverState, 501, x1, releaseK1, senderRelease1, receiverSetX1);
    expect_vole_relation(x1, delta, releaseK1.mKeys, receiverSetX1.mMacs, modulus);

    const std::vector<u64> x2{ 8, 7, 6, 5, 4, 3, 2, 1 };
    CivoleReleaseKOutput releaseK2{};
    CivoleSenderReleaseOutput senderRelease2{};
    CivoleReceiverSetXOutput receiverSetX2{};
    run_online_pair(senderState, receiverState, 502, x2, releaseK2, senderRelease2, receiverSetX2);
    expect_vole_relation(x2, delta, releaseK2.mKeys, receiverSetX2.mMacs, modulus);
}

void LogVole_Civole_StateMachineAutoSidSequential(const oc::CLP&)
{
    CivoleSender sender{};
    CivoleReceiver receiver{};

    constexpr u64 n = 8;
    sender.configure(n);
    receiver.configure(n);
    const u64 modulus = sender.modulus();
    LOGVOLE_EXPECT_EQ(receiver.modulus(), modulus);

    const u64 delta = 11 % modulus;
    auto offlineSockets = coproto::LocalAsyncSocket::makePair();
    auto offlineResult = macoro::sync_wait(macoro::when_all_ready(
        sender.offline(delta, offlineSockets[0]),
        receiver.offline(offlineSockets[1])));
    std::get<0>(offlineResult).result();
    std::get<1>(offlineResult).result();

    LOGVOLE_EXPECT_TRUE(sender.hasOffline());
    LOGVOLE_EXPECT_TRUE(receiver.hasOffline());
    LOGVOLE_EXPECT_EQ(sender.mNextSid, 0ull);
    LOGVOLE_EXPECT_EQ(receiver.mNextSid, 0ull);

    const std::vector<u64> x1{ 1, 2, 3, 4, 5, 6, 7, 8 };
    std::vector<u64> b1(n);
    std::vector<u64> a1(n);
    auto onlineSockets1 = coproto::LocalAsyncSocket::makePair();
    auto onlineResult1 = macoro::sync_wait(macoro::when_all_ready(
        sender.send(b1, onlineSockets1[0]),
        receiver.receive(x1, a1, onlineSockets1[1])));
    std::get<0>(onlineResult1).result();
    std::get<1>(onlineResult1).result();

    expect_vole_relation(x1, delta, b1, a1, modulus);
    LOGVOLE_EXPECT_EQ(sender.mNextSid, 1ull);
    LOGVOLE_EXPECT_EQ(receiver.mNextSid, 1ull);

    const std::vector<u64> x2{ 8, 7, 6, 5, 4, 3, 2, 1 };
    std::vector<u64> b2(n);
    std::vector<u64> a2(n);
    auto onlineSockets2 = coproto::LocalAsyncSocket::makePair();
    auto onlineResult2 = macoro::sync_wait(macoro::when_all_ready(
        sender.send(b2, onlineSockets2[0]),
        receiver.receive(x2, a2, onlineSockets2[1])));
    std::get<0>(onlineResult2).result();
    std::get<1>(onlineResult2).result();

    expect_vole_relation(x2, delta, b2, a2, modulus);
    LOGVOLE_EXPECT_EQ(sender.mNextSid, 2ull);
    LOGVOLE_EXPECT_EQ(receiver.mNextSid, 2ull);
}

void LogVole_Civole_StateMachineOneShotAutoOffline(const oc::CLP&)
{
    CivoleSender sender{};
    CivoleReceiver receiver{};

    const std::vector<u64> x{ 2, 4, 6, 8, 10, 12, 14, 16 };
    std::vector<u64> b(x.size());
    std::vector<u64> a(x.size());

    const u64 delta = 7;
    auto sockets = coproto::LocalAsyncSocket::makePair();
    auto result = macoro::sync_wait(macoro::when_all_ready(
        sender.send(delta, b, sockets[0]),
        receiver.receive(x, a, sockets[1])));
    std::get<0>(result).result();
    std::get<1>(result).result();

    LOGVOLE_EXPECT_TRUE(sender.hasOffline());
    LOGVOLE_EXPECT_TRUE(receiver.hasOffline());
    LOGVOLE_EXPECT_EQ(sender.mNextSid, 1ull);
    LOGVOLE_EXPECT_EQ(receiver.mNextSid, 1ull);
    LOGVOLE_EXPECT_EQ(sender.modulus(), receiver.modulus());
    expect_vole_relation(x, delta, b, a, sender.modulus());
}

void LogVole_Civole_RejectsSameSidReuseByEitherParty(const oc::CLP&)
{
    const auto params = make_params();
    const u64 modulus = resolve_modulus(params);
    const u64 delta = 13 % modulus;
    constexpr CivoleSid sid = 901;

    CivoleSenderState senderState{};
    CivoleReceiverState receiverState{};
    run_offline_pair(params, delta, 8, senderState, receiverState);

    const std::vector<u64> x1{ 1, 1, 2, 3, 5, 8, 13, 21 };
    CivoleReleaseKOutput releaseK{};
    CivoleSenderReleaseOutput senderRelease{};
    CivoleReceiverSetXOutput receiverSetX{};
    run_online_pair(senderState, receiverState, sid, x1, releaseK, senderRelease, receiverSetX);
    expect_vole_relation(x1, delta, releaseK.mKeys, receiverSetX.mMacs, modulus);

    CivoleReleaseKOutput releaseKAgain{};
    LOGVOLE_EXPECT_FALSE(civoleSenderReleaseK(senderState, sid, releaseKAgain));

    auto senderSockets = coproto::LocalAsyncSocket::makePair();
    bool senderThrew = false;
    try
    {
        CivoleSenderReleaseOutput releaseAgain{};
        macoro::sync_wait(civoleSenderRelease(senderState, sid, releaseAgain, senderSockets[0]));
    }
    catch (const std::runtime_error&)
    {
        senderThrew = true;
    }
    LOGVOLE_EXPECT_TRUE(senderThrew);

    auto receiverSockets = coproto::LocalAsyncSocket::makePair();
    bool receiverThrew = false;
    try
    {
        const std::vector<u64> x2{ 21, 13, 8, 5, 3, 2, 1, 1 };
        CivoleReceiverSetXOutput setXAgain{};
        macoro::sync_wait(civoleReceiverSetX(receiverState, sid, x2, setXAgain, receiverSockets[1]));
    }
    catch (const std::runtime_error&)
    {
        receiverThrew = true;
    }
    LOGVOLE_EXPECT_TRUE(receiverThrew);
}

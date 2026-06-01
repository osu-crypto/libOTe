#include "libOTe/Vole/LogVole2/LogVole2Civole.h"

#include "libOTe_Tests/LogVole_TestUtil.h"

#include "coproto/Socket/LocalAsyncSock.h"
#include "macoro/sync_wait.h"
#include "macoro/when_all.h"

#include <stdexcept>
#include <tuple>
#include <vector>

using namespace osuCrypto::LogVole2;
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
        const std::vector<u64>& x,
        u64 delta,
        const std::vector<u64>& keys,
        const std::vector<u64>& macs,
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

void LogVole2_Civole_PublicApiInvariant(const oc::CLP&)
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

void LogVole2_Civole_ReleaseRequiresPriorReleaseK(const oc::CLP&)
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

void LogVole2_Civole_RejectsZeroDelta(const oc::CLP&)
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

void LogVole2_Civole_RejectsOutOfFieldReceiverValue(const oc::CLP&)
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

void LogVole2_Civole_SupportsSequentialSids(const oc::CLP&)
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

void LogVole2_Civole_RejectsSameSidReuseByEitherParty(const oc::CLP&)
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

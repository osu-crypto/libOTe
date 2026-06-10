#include "libOTe/Vole/LogVole/LogVole.h"
#include "libOTe/Vole/LogVole/LogVoleArithmetic.h"

#include "libOTe_Tests/LogVole_TestUtil.h"

#include "coproto/Socket/LocalAsyncSock.h"
#include "macoro/sync_wait.h"
#include "macoro/when_all.h"

#include <stdexcept>
#include <span>
#include <tuple>
#include <vector>

using namespace osuCrypto::LogVole;
using osuCrypto::LogVoleReceiver;
using osuCrypto::LogVoleSender;
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
        oc::PRNG senderPrng(oc::block(11, 22));
        CivoleSenderOfflineInput senderInput{};
        senderInput.mParams = params;
        senderInput.mDelta = delta;
        senderInput.mW = w;

        CivoleReceiverOfflineInput receiverInput{};
        receiverInput.mParams = params;

        auto sockets = coproto::LocalAsyncSocket::makePair();
        auto result = macoro::sync_wait(macoro::when_all_ready(
            civoleSenderOffline(senderInput, senderState, senderPrng, sockets[0]),
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
        oc::PRNG senderPrng(oc::block(33, sid));
        oc::PRNG receiverPrng(oc::block(44, sid));
        auto sockets = coproto::LocalAsyncSocket::makePair();
        auto result = macoro::sync_wait(macoro::when_all_ready(
            civoleSenderRelease(senderState, sid, senderRelease, senderPrng, sockets[0]),
            civoleReceiverSetX(receiverState, sid, x, receiverSetX, receiverPrng, sockets[1])));
        std::get<0>(result).result();
        std::get<1>(result).result();

        releaseK.mSid = sid;
        releaseK.mModulus = senderState.mModulus;
        releaseK.mKeys = senderState.mReleasedKeys;
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
        const seal::Modulus mod(modulus);
        for (std::size_t idx = 0; idx < x.size(); ++idx)
        {
            const u64 expected = mulAddMod(x[idx], delta, keys[idx], mod);
            LOGVOLE_EXPECT_EQ(macs[idx], expected) << "VOLE relation mismatch at index " << idx;
        }
    }
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
    oc::PRNG prng(oc::block(55, 66));
    bool threw = false;
    try
    {
        macoro::sync_wait(civoleSenderOffline(senderInput, senderState, prng, sockets[0]));
    }
    catch (const std::runtime_error&)
    {
        threw = true;
    }
    LOGVOLE_EXPECT_TRUE(threw);
}

void LogVole_Civole_ValidationAndSidReuse(const oc::CLP&)
{
    const auto params = make_params();
    const u64 modulus = resolve_modulus(params);
    const u64 delta = 13 % modulus;
    constexpr CivoleSid sid = 901;

    CivoleSenderState senderState{};
    CivoleReceiverState receiverState{};
    run_offline_pair(params, delta, 8, senderState, receiverState);
    LOGVOLE_EXPECT_EQ(senderState.mW, 8ull);
    LOGVOLE_EXPECT_EQ(receiverState.mW, 8ull);
    LOGVOLE_EXPECT_EQ(senderState.mModulus, modulus);
    LOGVOLE_EXPECT_EQ(receiverState.mModulus, modulus);

    std::vector<u64> invalidX(7, 1);
    auto invalidSockets = coproto::LocalAsyncSocket::makePair();
    bool invalidXThrew = false;
    try
    {
        CivoleReceiverSetXOutput receiverSetX{};
        oc::PRNG receiverPrng(oc::block(77, 88));
        macoro::sync_wait(civoleReceiverSetX(receiverState, 900, invalidX, receiverSetX, receiverPrng, invalidSockets[1]));
    }
    catch (const std::runtime_error&)
    {
        invalidXThrew = true;
    }
    LOGVOLE_EXPECT_TRUE(invalidXThrew);

    const std::vector<u64> x{ 1, 1, 2, 3, 5, 8, 13, 21 };
    CivoleReleaseKOutput releaseK{};
    CivoleSenderReleaseOutput senderRelease{};
    CivoleReceiverSetXOutput receiverSetX{};
    run_online_pair(senderState, receiverState, sid, x, releaseK, senderRelease, receiverSetX);
    expect_vole_relation(x, delta, releaseK.mKeys, receiverSetX.mMacs, modulus);

    CivoleReleaseKOutput releaseKAgain{};
    LOGVOLE_EXPECT_FALSE(civoleSenderReleaseK(senderState, sid, releaseKAgain));

    auto senderSockets = coproto::LocalAsyncSocket::makePair();
    bool senderThrew = false;
    try
    {
        CivoleSenderReleaseOutput releaseAgain{};
        oc::PRNG senderPrng(oc::block(99, 100));
        macoro::sync_wait(civoleSenderRelease(senderState, sid, releaseAgain, senderPrng, senderSockets[0]));
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
        oc::PRNG receiverPrng(oc::block(101, 102));
        macoro::sync_wait(civoleReceiverSetX(receiverState, sid, x2, setXAgain, receiverPrng, receiverSockets[1]));
    }
    catch (const std::runtime_error&)
    {
        receiverThrew = true;
    }
    LOGVOLE_EXPECT_TRUE(receiverThrew);
}

void LogVole_Civole_StateMachineAutoOfflineSequentialSids(const oc::CLP&)
{
    LogVoleSender sender{};
    LogVoleReceiver receiver{};

    const std::vector<u64> x1{ 1, 2, 3, 4, 5, 6, 7, 8 };
    std::vector<u64> b1(x1.size());
    std::vector<u64> a1(x1.size());
    const u64 delta = 11;
    oc::PRNG senderPrng(oc::block(121, 122));
    oc::PRNG receiverPrng(oc::block(123, 124));
    auto onlineSockets1 = coproto::LocalAsyncSocket::makePair();
    auto onlineResult1 = macoro::sync_wait(macoro::when_all_ready(
        sender.send(delta, b1, senderPrng, onlineSockets1[0]),
        receiver.receive(x1, a1, receiverPrng, onlineSockets1[1])));
    std::get<0>(onlineResult1).result();
    std::get<1>(onlineResult1).result();

    LOGVOLE_EXPECT_TRUE(sender.hasOffline());
    LOGVOLE_EXPECT_TRUE(receiver.hasOffline());
    LOGVOLE_EXPECT_EQ(sender.modulus(), receiver.modulus());
    expect_vole_relation(x1, delta, b1, a1, sender.modulus());
    LOGVOLE_EXPECT_EQ(sender.mNextSid, 1ull);
    LOGVOLE_EXPECT_EQ(receiver.mNextSid, 1ull);

    const std::vector<u64> x2{ 8, 7, 6, 5, 4, 3, 2, 1 };
    std::vector<u64> b2(x2.size());
    std::vector<u64> a2(x2.size());
    auto onlineSockets2 = coproto::LocalAsyncSocket::makePair();
    auto onlineResult2 = macoro::sync_wait(macoro::when_all_ready(
        sender.send(b2, senderPrng, onlineSockets2[0]),
        receiver.receive(x2, a2, receiverPrng, onlineSockets2[1])));
    std::get<0>(onlineResult2).result();
    std::get<1>(onlineResult2).result();

    expect_vole_relation(x2, delta, b2, a2, sender.modulus());
    LOGVOLE_EXPECT_EQ(sender.mNextSid, 2ull);
    LOGVOLE_EXPECT_EQ(receiver.mNextSid, 2ull);
}

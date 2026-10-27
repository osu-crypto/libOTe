#include "libOTe/Vole/LogVole/LogVole.h"
#include "libOTe/Vole/LogVole/LogVoleArithmetic.h"
#include "libOTe/Vole/LogVole/LogVoleEncoding.h"
#include "libOTe/Vole/LogVole/LogVoleRuntime.h"
#include "libOTe/config.h"
#if defined(ENABLE_LOGVOLE_CUDA)
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuProtocol.h"
#endif

#include "libOTe_Tests/LogVole_TestUtil.h"
#include "cryptoTools/Common/CLP.h"
#include "cryptoTools/Crypto/RandomOracle.h"

#include "coproto/Socket/LocalAsyncSock.h"
#include "coproto/Socket/BufferingSocket.h"
#include "macoro/sync_wait.h"
#include "macoro/when_all.h"

#include <array>
#include <stdexcept>
#include <algorithm>
#include <array>
#include <cstdlib>
#include <span>
#include <type_traits>
#include <string>
#include <tuple>
#include <utility>
#include <vector>
#include <cstdint>

using namespace osuCrypto::LogVole;
using osuCrypto::LogVoleReceiver;
using osuCrypto::LogVoleSender;
using osuCrypto::u64;

namespace
{
    class ScopedEnvironmentValue
    {
    public:
        ScopedEnvironmentValue(const char* name, const char* value) : mName(name)
        {
            if (const char* old = std::getenv(name)) { mHadOld = true; mOld = old; }
            if (value) ::tests_libOTe::logvole_test::setEnvironment(name, value, 1); else ::tests_libOTe::logvole_test::unsetEnvironment(name);
        }
        ~ScopedEnvironmentValue()
        {
            if (mHadOld) ::tests_libOTe::logvole_test::setEnvironment(mName.c_str(), mOld.c_str(), 1); else ::tests_libOTe::logvole_test::unsetEnvironment(mName.c_str());
        }
    private:
        std::string mName, mOld;
        bool mHadOld = false;
    };
#if defined(ENABLE_LOGVOLE_CUDA)
    struct ScopedGpuEnabled
    {
        bool mPrevious = gpu::enabled();
        explicit ScopedGpuEnabled(bool enabled) { gpu::setEnabled(enabled); }
        ~ScopedGpuEnabled() { gpu::setEnabled(mPrevious); }
    };
#endif

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
        receiverInput.mW = w;

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

    macoro::task<> send_offline_meta(coproto::Socket& sock, u64 labelCount)
    {
        std::array<osuCrypto::u8, 2 * sizeof(u64)> payload{};
        for (std::size_t i = 0; i < sizeof(u64); ++i)
        {
            payload[i] = static_cast<osuCrypto::u8>(labelCount >> (8 * i));
        }

        auto metaSock = sock.fork();
        co_await metaSock.send(coproto::copy(payload));
    }
}

static_assert(!std::is_copy_constructible_v<LogVoleSender>);
static_assert(!std::is_copy_assignable_v<LogVoleSender>);
static_assert(std::is_move_constructible_v<LogVoleSender>);
static_assert(std::is_move_assignable_v<LogVoleSender>);
static_assert(!std::is_copy_constructible_v<LogVoleReceiver>);
static_assert(!std::is_copy_assignable_v<LogVoleReceiver>);
static_assert(std::is_move_constructible_v<LogVoleReceiver>);
static_assert(std::is_move_assignable_v<LogVoleReceiver>);
void LogVole_Civole_GpuSetupDeltaParity(const oc::CLP& cmd)
{
#if defined(ENABLE_LOGVOLE_CUDA)
    const bool requested = cmd.getOr("gpu", 0) != 0;
    ScopedGpuEnabled enabled(requested);
    if (requested) LOGVOLE_REQUIRE_TRUE(gpu::enabled());
    if (!gpu::enabled()) { LOGVOLE_SKIP() << "requires -gpu 1"; return; }
    ScopedEnvironmentValue option("LV_GPU_SETUP_DELTA_DEVICE", "1");
    ScopedEnvironmentValue strict("LV_GPU_SETUP_DELTA_DEVICE_STRICT", "1");
    ScopedEnvironmentValue decline("LV_GPU_SETUP_DELTA_DEVICE_FORCE_DECLINE", "0");
    const auto checkRing = [&](const ZpCrtContext& ctx) {
        const u64 p = ctx.mPlaintextModulus;
        const std::array<u64, 3> pattern{1u, p - 1u, 13u};
        const auto count = zpSlotCount(ctx);
        std::vector<u64> slots(count, 0);
        for (std::size_t i = 0; i < count / 3u * 3u; ++i) slots[i] = pattern[i % 3u];
        for (u64 scalar : {u64{1}, p - 1u})
        {
            RnsPoly expected;
            {
                ScopedGpuEnabled cpuReference(false);
                LOGVOLE_REQUIRE_TRUE(wrapZpConstantCrt(ctx, scalar, true, 1u, expected));
            }
            for (const char* lightweight : {"1", "0"})
            for (const char* direct : {"1", "0"})
            for (const char* smallDownload : {"0", "1"})
            {
                ScopedEnvironmentValue lightweightMode("LV_GPU_SETUP_DELTA_LIGHTWEIGHT", lightweight);
                ScopedEnvironmentValue directConstant("LV_GPU_SETUP_DELTA_CONSTANT_DIRECT", direct);
                ScopedEnvironmentValue downloadMode("LV_GPU_SETUP_DELTA_SMALL_DOWNLOAD", smallDownload);
                RnsPoly actual;
                LOGVOLE_REQUIRE_TRUE(gpu::wrapSetupDeltaDevice(ctx, scalar, {}, nullptr, actual));
                LOGVOLE_REQUIRE_TRUE(rangesEqual(actual.mCoeffs, expected.mCoeffs));
            }
        }
        for (unsigned mode = 0; mode < 3; ++mode)
        {
            // The third case preserves the general caller-provided slot API,
            // including zeros and a non-periodic final slot.
            if (mode == 2u) { slots[0] = 0; slots.back() = p - 2u; }
            RnsPoly expected, actual;
            {
                ScopedGpuEnabled cpuReference(false);
                LOGVOLE_REQUIRE_TRUE(mode == 0u
                    ? wrapZpConstantCrt(ctx, p - 1u, true, 1u, expected)
                    : wrapZpBatchCrt(ctx, slots, true, 0u, 1u, expected));
            }
            for (const char* lightweight : {"1", "0"})
            for (const char* smallDownload : {"0", "1"})
            {
                ScopedEnvironmentValue lightweightMode("LV_GPU_SETUP_DELTA_LIGHTWEIGHT", lightweight);
                ScopedEnvironmentValue downloadMode("LV_GPU_SETUP_DELTA_SMALL_DOWNLOAD", smallDownload);
                LOGVOLE_REQUIRE_TRUE(gpu::wrapSetupDeltaDevice(ctx, mode == 0u ? p - 1u : 0u,
                    mode == 2u ? std::span<const u64>(slots) : std::span<const u64>{},
                    mode == 1u ? &pattern : nullptr, actual));
                LOGVOLE_REQUIRE_TRUE(rangesEqual(expected.mCoeffs, actual.mCoeffs));
            }
            const auto saved = actual;
            const auto* storage = actual.mCoeffs.data();
            {
                ScopedEnvironmentValue forced("LV_GPU_SETUP_DELTA_DEVICE_FORCE_DECLINE", "1");
                LOGVOLE_REQUIRE_FALSE(gpu::wrapSetupDeltaDevice(ctx, p - 1u, {}, nullptr, actual));
            }
            LOGVOLE_REQUIRE_TRUE(actual.mCoeffs.data() == storage);
            LOGVOLE_REQUIRE_TRUE(rangesEqual(saved.mCoeffs, actual.mCoeffs));
        }
        RnsPoly rejected;
        rejected.mCoeffs.resize(1);
        rejected.mCoeffs[0] = 0xBADu;
        auto invalidPattern = pattern;
        invalidPattern[1] = 0;
        LOGVOLE_REQUIRE_FALSE(gpu::wrapSetupDeltaDevice(ctx, 0, {}, &invalidPattern, rejected));
        invalidPattern[1] = p;
        LOGVOLE_REQUIRE_FALSE(gpu::wrapSetupDeltaDevice(ctx, 0, {}, &invalidPattern, rejected));
        LOGVOLE_REQUIRE_FALSE(gpu::wrapSetupDeltaDevice(ctx, 1, {}, &pattern, rejected));
        LOGVOLE_REQUIRE_FALSE(gpu::wrapSetupDeltaDevice(ctx, 0, slots, &pattern, rejected));
        LOGVOLE_REQUIRE_FALSE(gpu::wrapSetupDeltaDevice(ctx, 1, slots, nullptr, rejected));
        LOGVOLE_REQUIRE_FALSE(gpu::wrapSetupDeltaDevice(ctx, 0, {}, nullptr, rejected));
        LOGVOLE_REQUIRE_FALSE(gpu::wrapSetupDeltaDevice(ctx, p, {}, nullptr, rejected));
        LOGVOLE_REQUIRE_FALSE(gpu::wrapSetupDeltaDevice(ctx, 0,
            std::span<const u64>(slots).first(count - 1u), nullptr, rejected));
        std::fill(slots.begin(), slots.end(), 0u);
        LOGVOLE_REQUIRE_FALSE(gpu::wrapSetupDeltaDevice(ctx, 0, slots, nullptr, rejected));
        slots[0] = p;
        LOGVOLE_REQUIRE_FALSE(gpu::wrapSetupDeltaDevice(ctx, 0, slots, nullptr, rejected));
        LOGVOLE_REQUIRE_EQ(rejected.mCoeffs.size(), 1u);
        LOGVOLE_REQUIRE_EQ(rejected.mCoeffs[0], 0xBADu);
    };
    RingParams small;
    small.mPolyModulusDegree = 1024;
    assignValues<int>(small.mCoeffModulusBits, {30, 30});
    ZpCrtContext smallContext;
    LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(small, 20u, smallContext));
    checkRing(smallContext);
    for (auto setting : {CivoleSetting::GoldenSeed, CivoleSetting::NoGoldenSeed})
    {
        CivoleParams params;
        LOGVOLE_REQUIRE_TRUE(makeCivoleParams(setting, params, 4u));
        ZpCrtContext ctx;
        LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(params.mLogVole.mShrinkExpand.mRing,
            params.mLogVole.mShrinkExpand.mPlaintextModulusBits, ctx));
        checkRing(ctx);
        const std::array<u64, 3> pattern{1u, ctx.mPlaintextModulus - 1u, 13u};
        std::vector<u64> slots(zpSlotCount(ctx), 0);
        for (std::size_t i = 0; i < slots.size() / 3u * 3u; ++i) slots[i] = pattern[i % 3u];
        for (bool patterned : {false, true})
        {
            CivoleSenderOfflineInput referenceInput;
            referenceInput.mParams = params;
            referenceInput.mW = (u64{1} << 18) + 3u;
            referenceInput.mDelta = patterned ? 0u : 13u;
            if (patterned) referenceInput.mDeltaSlots = slots;
            auto actualInput = referenceInput;
            if (patterned)
            {
                actualInput.mDeltaSlots = {};
                actualInput.mGarbledDeltaPattern = pattern;
            }
            const oc::block seed(0x44454c5441574952ULL, patterned);
            oc::PRNG referencePrng(seed, 3);
            CivoleSenderState expected;
            coproto::BufferingSocket referenceSocket;
            {
                ScopedGpuEnabled cpuReference(false);
                macoro::sync_wait(civoleSenderOffline(referenceInput, expected, referencePrng, referenceSocket));
                macoro::sync_wait(referenceSocket.flush());
            }
            auto expectedWire = referenceSocket.getOutbound();
            LOGVOLE_REQUIRE_TRUE(expectedWire && !expectedWire->empty());
            std::array<u64, 16> expectedRandom;
            referencePrng.get(expectedRandom.data(), expectedRandom.size());
            const auto replay = [&](bool forcedFallback) {
                ScopedEnvironmentValue forced("LV_GPU_SETUP_DELTA_DEVICE_FORCE_DECLINE", forcedFallback ? "1" : "0");
                ScopedEnvironmentValue requireGpu("LV_GPU_SETUP_DELTA_DEVICE_STRICT", forcedFallback ? "0" : "1");
                oc::PRNG actualPrng(seed, 3);
                CivoleSenderState actual;
                coproto::BufferingSocket actualSocket;
                macoro::sync_wait(civoleSenderOffline(actualInput, actual, actualPrng, actualSocket));
                macoro::sync_wait(actualSocket.flush());
                auto actualWire = actualSocket.getOutbound();
                LOGVOLE_REQUIRE_TRUE(actualWire && rangesEqual(*expectedWire, *actualWire));
                std::array<u64, 16> actualRandom;
                actualPrng.get(actualRandom.data(), actualRandom.size());
                LOGVOLE_REQUIRE_TRUE(actualRandom == expectedRandom);
                LOGVOLE_REQUIRE_EQ(actual.mLogVoleState.mSk1.size(), expected.mLogVoleState.mSk1.size());
                for (std::size_t i = 0; i < expected.mLogVoleState.mSk1.size(); ++i)
                    LOGVOLE_REQUIRE_TRUE(rangesEqual(actual.mLogVoleState.mSk1[i].mCoeffs,
                        expected.mLogVoleState.mSk1[i].mCoeffs));
                CivoleReceiverOfflineInput receiverInput;
                receiverInput.mParams = params;
                receiverInput.mW = referenceInput.mW;
                CivoleReceiverState receiver;
                coproto::BufferingSocket import;
                import.processInbound(*actualWire);
                macoro::sync_wait(civoleReceiverOffline(receiverInput, receiver, import));
                LOGVOLE_REQUIRE_EQ(receiver.mW, referenceInput.mW);
            };
            replay(false);
            if (patterned && setting == CivoleSetting::NoGoldenSeed) replay(true);
            if (!patterned && setting == CivoleSetting::GoldenSeed)
            {
                ScopedEnvironmentValue rollback("LV_GPU_SETUP_DELTA_DEVICE", "0");
                replay(false);
            }
        }
        CivoleSenderOfflineInput invalid;
        invalid.mParams = params;
        invalid.mW = 8u;
        invalid.mGarbledDeltaPattern = pattern;
        for (unsigned failure = 0; failure < 5; ++failure)
        {
            ScopedEnvironmentValue forced("LV_GPU_SETUP_DELTA_DEVICE_FORCE_DECLINE", failure == 4u ? "1" : "0");
            auto candidate = invalid;
            if (failure == 0u) candidate.mDelta = 1u;
            if (failure == 1u) candidate.mDeltaSlots = slots;
            if (failure == 2u) (*candidate.mGarbledDeltaPattern)[1] = 0u;
            if (failure == 3u) (*candidate.mGarbledDeltaPattern)[1] = ctx.mPlaintextModulus;
            oc::PRNG prng(oc::block(3, 4), 3), expectedPrng(oc::block(3, 4), 3);
            CivoleSenderState unchanged;
            unchanged.mW = 777u;
            coproto::BufferingSocket socket;
            bool threw = false;
            try { macoro::sync_wait(civoleSenderOffline(candidate, unchanged, prng, socket)); }
            catch (const std::runtime_error&) { threw = true; }
            LOGVOLE_REQUIRE_TRUE(threw);
            LOGVOLE_REQUIRE_EQ(socket.bytesSent(), 0u);
            LOGVOLE_REQUIRE_EQ(unchanged.mW, 777u);
            LOGVOLE_REQUIRE_EQ(prng.get<oc::block>(), expectedPrng.get<oc::block>());
        }
    }
#else
    (void)cmd;
    LOGVOLE_SKIP() << "requires ENABLE_LOGVOLE_CUDA";
#endif
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

void LogVole_Civole_RejectsPeerOfflineWidth(const oc::CLP&)
{
    CivoleReceiverOfflineInput input{};
    input.mParams = make_params();
    input.mW = 8;

    CivoleReceiverState state{};
    auto sockets = coproto::LocalAsyncSocket::makePair();
    auto result = macoro::sync_wait(macoro::when_all_ready(
        civoleReceiverOffline(input, state, sockets[0]),
        send_offline_meta(sockets[1], input.mW + 1)));

    bool threw = false;
    try
    {
        std::get<0>(result).result();
    }
    catch (const std::runtime_error&)
    {
        threw = true;
    }
    std::get<1>(result).result();

    LOGVOLE_EXPECT_TRUE(threw);
    LOGVOLE_EXPECT_EQ(state.mW, 0ull);
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

void LogVole_Civole_RejectedHostInputPreservesSid(const oc::CLP&)
{
    for (const auto setting : {CivoleSetting::GoldenSeed, CivoleSetting::NoGoldenSeed})
    {
        LogVoleSender sender;
        LogVoleReceiver receiver;
        constexpr u64 count = 1, delta = 19;
        sender.configure(count, 55, 1, setting);
        receiver.configure(count, 55, 1, setting);
        oc::PRNG senderPrng(oc::block(1, 2)), receiverPrng(oc::block(3, 4));
        auto sockets = coproto::LocalAsyncSocket::makePair();
        auto setup = macoro::sync_wait(macoro::when_all_ready(
            sender.offline(delta, senderPrng, sockets[0]), receiver.offline(sockets[1])));
        std::get<0>(setup).result();
        std::get<1>(setup).result();

        std::vector<u64> x{receiver.modulus()}, macs(count), keys(count);
        auto invalidSockets = coproto::LocalAsyncSocket::makePair();
        bool rejected = false;
        try
        {
            macoro::sync_wait(receiver.receive(x, macs, receiverPrng, invalidSockets[1]));
        }
        catch (const std::runtime_error&)
        {
            rejected = true;
        }
        LOGVOLE_REQUIRE_TRUE(rejected);
        LOGVOLE_REQUIRE_EQ(receiver.mNextSid, sender.mNextSid);
        LOGVOLE_REQUIRE_TRUE(receiver.mOfflineState.mUsedSids.empty());

        for (u64 query = 0; query < 2; ++query)
        {
            x[0] = 7 + query;
            auto online = coproto::LocalAsyncSocket::makePair();
            auto result = macoro::sync_wait(macoro::when_all_ready(
                sender.send(keys, senderPrng, online[0]),
                receiver.receive(x, macs, receiverPrng, online[1])));
            std::get<0>(result).result();
            std::get<1>(result).result();
            expect_vole_relation(x, delta, keys, macs, sender.modulus());
            LOGVOLE_EXPECT_EQ(receiver.mNextSid, query + 1);
            LOGVOLE_EXPECT_EQ(sender.mNextSid, receiver.mNextSid);
        }

        // A transport error after validation consumes the SID even though the
        // coroutine does not return an output. Retrying it could reuse masks.
        const auto failedSid = receiver.mNextSid;
        auto failedSockets = coproto::LocalAsyncSocket::makePair();
        macoro::sync_wait(failedSockets[1].close());
        bool transportFailed = false;
        try
        {
            macoro::sync_wait(receiver.receive(x, macs, receiverPrng, failedSockets[1]));
        }
        catch (const std::exception&)
        {
            transportFailed = true;
        }
        LOGVOLE_REQUIRE_TRUE(transportFailed);
        LOGVOLE_EXPECT_EQ(receiver.mNextSid, failedSid + 1);
        LOGVOLE_EXPECT_TRUE(std::find(receiver.mOfflineState.mUsedSids.begin(),
            receiver.mOfflineState.mUsedSids.end(), failedSid) !=
            receiver.mOfflineState.mUsedSids.end());
    }
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

    oc::Timer senderTimer;
    oc::Timer receiverTimer;
    sender.setTimer(senderTimer);
    receiver.setTimer(receiverTimer);

    LogVoleSender movedSender{};
    movedSender = std::move(sender);
    LogVoleReceiver movedReceiver(std::move(receiver));

    LOGVOLE_EXPECT_FALSE(sender.isConfigured());
    LOGVOLE_EXPECT_FALSE(receiver.isConfigured());
    LOGVOLE_EXPECT_EQ(sender.mRequestSize, 0ull);
    LOGVOLE_EXPECT_EQ(receiver.mRequestSize, 0ull);
    LOGVOLE_EXPECT_EQ(sender.mModulus, 0ull);
    LOGVOLE_EXPECT_EQ(receiver.mModulus, 0ull);
    LOGVOLE_EXPECT_EQ(sender.mOfflineState.mW, 0ull);
    LOGVOLE_EXPECT_EQ(receiver.mOfflineState.mW, 0ull);
    LOGVOLE_EXPECT_TRUE(sender.mOfflineState.mUsedSids.empty());
    LOGVOLE_EXPECT_TRUE(receiver.mOfflineState.mUsedSids.empty());
    LOGVOLE_EXPECT_FALSE(sender.mOfflineState.mLogVoleState.mNextLevelState);
    LOGVOLE_EXPECT_FALSE(receiver.mOfflineState.mLogVoleState.mNextLevelState);
    LOGVOLE_EXPECT_EQ(sender.mTimer, nullptr);
    LOGVOLE_EXPECT_EQ(receiver.mTimer, nullptr);
    LOGVOLE_EXPECT_TRUE(movedSender.hasOffline());
    LOGVOLE_EXPECT_TRUE(movedReceiver.hasOffline());
    LOGVOLE_EXPECT_EQ(movedSender.mNextSid, 2ull);
    LOGVOLE_EXPECT_EQ(movedReceiver.mNextSid, 2ull);
    LOGVOLE_EXPECT_EQ(movedSender.mTimer, &senderTimer);
    LOGVOLE_EXPECT_EQ(movedReceiver.mTimer, &receiverTimer);

    const std::vector<u64> x3{ 2, 3, 5, 7, 11, 13, 17, 19 };
    std::vector<u64> b3(x3.size());
    std::vector<u64> a3(x3.size());
    auto onlineSockets3 = coproto::LocalAsyncSocket::makePair();
    auto onlineResult3 = macoro::sync_wait(macoro::when_all_ready(
        movedSender.send(b3, senderPrng, onlineSockets3[0]),
        movedReceiver.receive(x3, a3, receiverPrng, onlineSockets3[1])));
    std::get<0>(onlineResult3).result();
    std::get<1>(onlineResult3).result();

    expect_vole_relation(x3, delta, b3, a3, movedSender.modulus());
    LOGVOLE_EXPECT_EQ(movedSender.mNextSid, 3ull);
    LOGVOLE_EXPECT_EQ(movedReceiver.mNextSid, 3ull);
}

void LogVole_Civole_NonInteractiveOracleAndMask(const oc::CLP&)
{
    CivoleParams civole{};
    LOGVOLE_REQUIRE_TRUE(makeNoGoldenSeedCivoleParams(civole));
    auto params = civole.mLogVole;
    params.mOnlineMode = OnlineMode::NonInteractive;
    params.mSessionId = 101;
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mShrinkExpand.mRing, ctx));
    oc::PRNG prng(oc::block(918, 231));
    const auto digest = sampleUniformPoly(ctx, prng);
    RootResponseMessage expected{}, repeated{}, changed{};
    LOGVOLE_REQUIRE_TRUE(deriveNonInteractiveRootResponse(params, digest, expected));
    LOGVOLE_REQUIRE_TRUE(deriveNonInteractiveRootResponse(params, digest, repeated));
    LOGVOLE_REQUIRE_TRUE(rangesEqual(expected.mSkPrimeCoeffs, repeated.mSkPrimeCoeffs));
    LOGVOLE_EXPECT_TRUE(expected.mSeed.empty());
    ++params.mSessionId;
    LOGVOLE_REQUIRE_TRUE(deriveNonInteractiveRootResponse(params, digest, changed));
    LOGVOLE_EXPECT_FALSE(rangesEqual(expected.mSkPrimeCoeffs, changed.mSkPrimeCoeffs));
    --params.mSessionId;
    auto otherDigest = digest;
    otherDigest.mCoeffs[0] = (otherDigest.mCoeffs[0] + 1) % ringModulusValue(ctx, 0);
    LOGVOLE_REQUIRE_TRUE(deriveNonInteractiveRootResponse(params, otherDigest, changed));
    LOGVOLE_EXPECT_FALSE(rangesEqual(expected.mSkPrimeCoeffs, changed.mSkPrimeCoeffs));
    otherDigest.mCoeffs[0] = ringModulusValue(ctx, 0);
    LOGVOLE_EXPECT_FALSE(deriveNonInteractiveRootResponse(params, otherDigest, changed));
    otherDigest.mCoeffs.resize(3);
    LOGVOLE_EXPECT_FALSE(deriveNonInteractiveRootResponse(params, otherDigest, changed));

    std::array<oc::u8, 16> interactiveSeed{}, nonInteractiveSeed{};
    derivePublicCt2Seed(params.mSessionId, hashSeedDigest(digest), interactiveSeed);
    derivePublicCt2Seed(params.mSessionId, hashSeedDigest(digest), nonInteractiveSeed,
        OnlineMode::NonInteractive);
    LOGVOLE_EXPECT_FALSE(interactiveSeed == nonInteractiveSeed);

    SenderState sender{};
    sender.mParams = params;
    ShrinkExpandParams trunc{};
    LOGVOLE_REQUIRE_TRUE(makeTruncShrinkExpandParams(params, false, trunc));
    const oc::u32 tauHi = trunc.mTau;
    for (oc::u32 i = 0; i < tauHi; ++i)
        sender.mRootSkRRt.push_back(sampleUniformPoly(ctx, prng));
    RootDigestMessage request{};
    request.mDPrimeCoeffs = digest.mCoeffs;

#if defined(ENABLE_LOGVOLE_CUDA)
    struct RestoreGpu
    {
        bool mEnabled = gpu::enabled();
        ~RestoreGpu() { gpu::setEnabled(mEnabled); }
    } restoreGpu;
    gpu::setEnabled(false);
#endif
    RootResponseMessage cpuResponse{};
    LOGVOLE_REQUIRE_TRUE(prepareRootResponseSender(sender, request, prng, cpuResponse,
        nullptr, nullptr, true));
    LOGVOLE_REQUIRE_TRUE(rangesEqual(cpuResponse.mSkPrimeCoeffs, expected.mSkPrimeCoeffs));
    const auto cpuMask = *sender.mRootKPrimeRt;
    RnsPoly recovered{};
    LOGVOLE_REQUIRE_TRUE(deriveSkxTrunc(ctx, sender.mRootSkRRt, digest, cpuMask,
        params.mShrinkExpand.mGadgetLogBase, tauHi, recovered));
    LOGVOLE_EXPECT_TRUE(rangesEqual(recovered.mCoeffs, expected.mSkPrimeCoeffs));

#if defined(ENABLE_LOGVOLE_CUDA)
    gpu::setEnabled(true);
    if (gpu::enabled())
    {
        RootResponseMessage gpuResponse{};
        // A different sender PRNG state must still produce the same mask.
        oc::PRNG anotherPrng(oc::block(121, 998));
        LOGVOLE_REQUIRE_TRUE(prepareRootResponseSender(sender, request, anotherPrng, gpuResponse,
            nullptr, nullptr, true));
        LOGVOLE_EXPECT_TRUE(rangesEqual(gpuResponse.mSkPrimeCoeffs, cpuResponse.mSkPrimeCoeffs));
        LOGVOLE_EXPECT_TRUE(rangesEqual(sender.mRootKPrimeRt->mCoeffs, cpuMask.mCoeffs));
        LOGVOLE_REQUIRE_TRUE(sender.mRootKPrimeRtDevice);
        std::vector<RnsPoly> deviceMask;
        const auto device = std::static_pointer_cast<gpu::DeviceBatch>(sender.mRootKPrimeRtDevice);
        LOGVOLE_REQUIRE_TRUE(gpu::download(*device, deviceMask, 1));
        LOGVOLE_EXPECT_TRUE(rangesEqual(deviceMask[0].mCoeffs, cpuMask.mCoeffs));
    }
#endif
    params.mCt2SeedMode = Ct2SeedMode::GoldenSeed;
    LOGVOLE_EXPECT_FALSE(deriveNonInteractiveRootResponse(params, digest, changed));
    LOGVOLE_EXPECT_FALSE(validateCt2SeedMode(params));
    bool rejected = false;
    try
    {
        LogVoleReceiver receiver;
        receiver.configure(8, 55, 1, CivoleSetting::GoldenSeed, OnlineMode::NonInteractive);
    }
    catch (const std::runtime_error&) { rejected = true; }
    LOGVOLE_EXPECT_TRUE(rejected);
}

void LogVole_Civole_NonInteractivePublicKeyAndSequentialQueries(const oc::CLP& cmd)
{
#if defined(ENABLE_LOGVOLE_CUDA)
    struct RestoreGpu
    {
        bool mEnabled = gpu::enabled();
        ~RestoreGpu() { gpu::setEnabled(mEnabled); }
    } restoreGpu;
    const bool wantGpu = cmd.getOr("gpu", 0) != 0;
    gpu::setEnabled(wantGpu);
    if (wantGpu) LOGVOLE_REQUIRE_TRUE(gpu::enabled());
#endif
    // Cross a full root block and leave a partial CRT batch at the end.
    constexpr u64 n = (1ull << 18) + 3, delta = 13;
    LogVoleSender sender;
    sender.configure(n, 52, 4, CivoleSetting::NoGoldenSeed, OnlineMode::NonInteractive);
    oc::PRNG senderPrng(oc::block(411, 522));
    coproto::BufferingSocket publish;
    // This must complete before any receiver exists.
    macoro::sync_wait(sender.offline(delta, senderPrng, publish));
    macoro::sync_wait(publish.flush());
    auto publicKey = publish.getOutbound();
    LOGVOLE_REQUIRE_TRUE(publicKey && !publicKey->empty());
    LOGVOLE_EXPECT_EQ(publish.bytesReceived(), 0ull);

    CivoleReleaseKOutput staged;
    LOGVOLE_EXPECT_FALSE(civoleSenderReleaseK(sender.mOfflineState, 0, staged));
    std::vector<u64> x(n), a(n), b(n), previousKeys;
    for (u64 client = 0; client < 2; ++client)
    {
        LogVoleReceiver receiver;
        receiver.configure(n, 52, 4, CivoleSetting::NoGoldenSeed, OnlineMode::NonInteractive);
        coproto::BufferingSocket import;
        import.processInbound(*publicKey);
        macoro::sync_wait(receiver.offline(import));
        LOGVOLE_EXPECT_EQ(import.bytesSent(), 0ull);
        receiver.mNextSid = client * 2;
        oc::PRNG receiverPrng(oc::block(633, 744 + client));
        for (u64 round = 0; round < 2; ++round)
        {
            for (u64 i = 0; i < n; ++i)
                x[i] = i % 3 == 0 ? 0 : (i % 3 == 1 ? sender.modulus() - 1 : i + round);
            coproto::BufferingSocket query;
            // No sender coroutine is running, and no inbound message is supplied.
            macoro::sync_wait(receiver.receive(x, a, receiverPrng, query));
            macoro::sync_wait(query.flush());
            LOGVOLE_EXPECT_EQ(query.bytesReceived(), 0ull);
            LOGVOLE_EXPECT_EQ(receiver.mLastOnlineComm.mBytesReceived, 0ull);
            auto message = query.getOutbound();
            LOGVOLE_REQUIRE_TRUE(message && !message->empty());

            coproto::BufferingSocket recover;
            recover.processInbound(*message);
            macoro::sync_wait(sender.send(b, senderPrng, recover));
            macoro::sync_wait(recover.flush());
            LOGVOLE_EXPECT_EQ(recover.bytesSent(), 0ull);
            LOGVOLE_EXPECT_EQ(sender.mLastOnlineComm.mBytesSent, 0ull);
            LOGVOLE_EXPECT_EQ(sender.mLastOnlineComm.mBytesReceived,
                receiver.mLastOnlineComm.mBytesSent);
            expect_vole_relation(x, delta, b, a, sender.modulus());
            if (!previousKeys.empty()) LOGVOLE_EXPECT_FALSE(b == previousKeys);
            previousKeys = b;
        }
    }
    // A repeated SID is rejected before reading a message.
    sender.mNextSid = 0;
    bool replayRejected = false;
    try
    {
        coproto::BufferingSocket replay;
        macoro::sync_wait(sender.send(b, senderPrng, replay));
    }
    catch (const std::runtime_error&) { replayRejected = true; }
    LOGVOLE_EXPECT_TRUE(replayRejected);
    // Public parameters cannot be imported under a different protocol mode.
    bool modeRejected = false;
    try
    {
        LogVoleReceiver mismatch;
        mismatch.configure(n, 52, 4, CivoleSetting::NoGoldenSeed);
        coproto::BufferingSocket import;
        import.processInbound(*publicKey);
        macoro::sync_wait(mismatch.offline(import));
    }
    catch (const std::runtime_error&) { modeRejected = true; }
    LOGVOLE_EXPECT_TRUE(modeRejected);
}

void LogVole_Civole_ReceiverFirstQueryAllocationOverlapParity(const oc::CLP& cmd)
{
#if defined(ENABLE_LOGVOLE_CUDA)
    ScopedGpuEnabled gpuEnabled(cmd.getOr("gpu", 0) != 0);
    if (!gpu::enabled()) { LOGVOLE_SKIP() << "requires -gpu 1"; return; }
    constexpr u64 n = u64{1} << 25;
    constexpr u64 delta = 19;
    // The first device-only query uses no host input or output allocation;
    // the exact relation is fetched only after the query completes.
    std::vector<u64> x, a, b;
    struct Summary
    {
        std::array<std::array<oc::u8, 32>, 2> mOutputs{};
        std::array<oc::block, 3> mPrngContinuation{};
    };

    // One indexed root is intentionally paired across the three exact-path
    // controls; independent benchmark repetitions use fresh suite roots.
    const auto run = [&](const char* overlap, const char* forceDecline) {
        ScopedEnvironmentValue selected(
            "LV_GPU_RECEIVER_FIRST_QUERY_ALLOC_OVERLAP", overlap);
        ScopedEnvironmentValue declined(
            "LV_GPU_RECEIVER_FIRST_QUERY_ALLOC_FORCE_DECLINE", forceDecline);
        LogVoleSender sender;
        LogVoleReceiver receiver;
        sender.configure(n, 52u, 4u, CivoleSetting::NoGoldenSeed);
        receiver.configure(n, 52u, 4u, CivoleSetting::NoGoldenSeed);
        sender.mKeepOutputOnDevice = true;
        receiver.mKeepOutputOnDevice = true;
        receiver.mInputDevice = gpu::sampleScalarsFromSeed(
            oc::block(0x1939u, 0x2748u), n, receiver.modulus());
        LOGVOLE_REQUIRE_TRUE(receiver.mInputDevice);
        auto inputDevice = std::static_pointer_cast<gpu::DeviceScalars>(
            receiver.mInputDevice);
        LOGVOLE_REQUIRE_TRUE(gpu::waitScalars(*inputDevice));

        oc::PRNG senderOfflinePrng(oc::block(0x3344u, 0x5566u));
        auto offlineSockets = coproto::LocalAsyncSocket::makePair();
        auto offline = macoro::sync_wait(macoro::when_all_ready(
            sender.offline(delta, senderOfflinePrng, offlineSockets[0]),
            receiver.offline(offlineSockets[1])));
        std::get<0>(offline).result();
        std::get<1>(offline).result();

        auto plan = std::static_pointer_cast<gpu::ReceiverFirstQueryAllocations>(
            receiver.mOfflineState.mFirstQueryGpuAllocations);
        if (overlap[0] == '1' && forceDecline[0] == '0')
        {
            LOGVOLE_REQUIRE_TRUE(plan);
            bool ready = false, wrapSelected = false, nodesSelected = false;
            LOGVOLE_REQUIRE_TRUE(gpu::receiverFirstQueryAllocationStatus(
                plan, ready, wrapSelected, nodesSelected));
            LOGVOLE_REQUIRE_TRUE(ready);
            LOGVOLE_EXPECT_FALSE(wrapSelected);
            LOGVOLE_EXPECT_FALSE(nodesSelected);
            {
                ScopedProtocolCacheScope receiverRole(ProtocolCacheRole::Receiver, 0u);
                LOGVOLE_EXPECT_FALSE(gpu::bindReceiverFirstQueryAllocations(
                    plan, &sender.mOfflineState, 0u));
            }
            {
                ScopedProtocolCacheScope wrongRole(ProtocolCacheRole::Sender, 0u);
                LOGVOLE_EXPECT_FALSE(gpu::bindReceiverFirstQueryAllocations(
                    plan, &sender.mOfflineState, 0u));
            }
        }
        else LOGVOLE_EXPECT_FALSE(plan);

        Summary summary{};
        summary.mPrngContinuation[0] = senderOfflinePrng.get<oc::block>();
        for (u64 query = 0; query < 2u; ++query)
        {
            oc::PRNG senderPrng(oc::block(0x7788u, query + 0x99u));
            oc::PRNG receiverPrng(oc::block(0xAABBu, query + 0xCCu));
            auto onlineSockets = coproto::LocalAsyncSocket::makePair();
            auto online = macoro::sync_wait(macoro::when_all_ready(
                sender.send(query == 0u ? std::span<u64>{} : std::span<u64>(b),
                    senderPrng, onlineSockets[0]),
                receiver.receive(
                    query == 0u ? std::span<const u64>{} : std::span<const u64>(x),
                    query == 0u ? std::span<u64>{} : std::span<u64>(a),
                    receiverPrng, onlineSockets[1])));
            std::get<0>(online).result();
            std::get<1>(online).result();

            auto senderOutput = std::static_pointer_cast<gpu::DeviceScalars>(
                sender.outputDevice());
            auto receiverOutput = std::static_pointer_cast<gpu::DeviceScalars>(
                receiver.outputDevice());
            LOGVOLE_REQUIRE_TRUE(senderOutput && receiverOutput);
            if (query == 0u)
            {
                x.resize(n);
                a.resize(n);
                b.resize(n);
            }
            LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(
                *senderOutput, std::span<u64>(b.data(), b.size())));
            LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(
                *receiverOutput, std::span<u64>(a.data(), a.size())));
            if (query == 0u)
                LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(
                    *inputDevice, std::span<u64>(x.data(), x.size())));
            const seal::Modulus modulus(receiver.modulus());
            for (std::size_t i = 0; i < x.size(); ++i)
                if (a[i] != mulAddMod(x[i], delta, b[i], modulus))
                    throw std::runtime_error("receiver first-query overlap VOLE relation mismatch");
            oc::RandomOracle digest(32u);
            digest.Update(b.data(), static_cast<u64>(b.size()));
            digest.Update(a.data(), static_cast<u64>(a.size()));
            digest.Final(summary.mOutputs[query]);
            summary.mPrngContinuation[query + 1u] = senderPrng.get<oc::block>();

            if (plan)
            {
                bool ready = false, wrapSelected = false, nodesSelected = false;
                LOGVOLE_REQUIRE_TRUE(gpu::receiverFirstQueryAllocationStatus(
                    plan, ready, wrapSelected, nodesSelected));
                LOGVOLE_REQUIRE_TRUE(ready && wrapSelected && nodesSelected);
                ScopedProtocolCacheScope receiverRole(ProtocolCacheRole::Receiver, query);
                LOGVOLE_EXPECT_FALSE(gpu::bindReceiverFirstQueryAllocations(
                    plan, &sender.mOfflineState, query));
            }
        }
        return summary;
    };

    const auto control = run("0", "0");
    const auto overlapped = run("1", "0");
    const auto forcedDecline = run("1", "1");
    LOGVOLE_EXPECT_TRUE(control.mOutputs == overlapped.mOutputs);
    LOGVOLE_EXPECT_TRUE(control.mOutputs == forcedDecline.mOutputs);
    LOGVOLE_EXPECT_TRUE(control.mPrngContinuation == overlapped.mPrngContinuation);
    LOGVOLE_EXPECT_TRUE(control.mPrngContinuation == forcedDecline.mPrngContinuation);
#else
    (void)cmd;
    LOGVOLE_SKIP() << "requires ENABLE_LOGVOLE_CUDA";
#endif
}

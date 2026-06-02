#pragma once

#include "libOTe/Tools/Coproto.h"
#include "libOTe/Vole/LogVole/LogVoleRingReceiver.h"
#include "libOTe/Vole/LogVole/LogVoleRing.h"
#include "libOTe/Vole/LogVole/LogVoleRingSender.h"

#include "cryptoTools/Common/Timer.h"

#include "seal/seal.h"

#include <memory>
#include <vector>

namespace osuCrypto::LogVole
{
    using CivoleSid = u64;

    struct ZpCrtContext
    {
        RingNttContext mRing;
        u32 mPlaintextModulusBits = 0;
        u64 mPlaintextModulus = 0;
        AlignedUnVec<u64> mDeltaModQj;
        std::shared_ptr<seal::SEALContext> mBatchingContext;
    };

    struct CivoleParams
    {
        Params mLogVole;
    };

    struct CivoleSenderOfflineInput
    {
        CivoleParams mParams;
        u64 mDelta = 0;
        u64 mW = 0;
    };

    struct CivoleReceiverOfflineInput
    {
        CivoleParams mParams;
    };

    struct CivoleSenderState
    {
        CivoleParams mParams;
        u64 mModulus = 0;
        u64 mDelta = 0;
        u64 mW = 0;
        u32 mRingWidth = 0;
        SamplingSeedConfig mBaseSamplingSeeds;
        SenderState mLogVoleState;

        bool mHasActiveSid = false;
        CivoleSid mActiveSid = 0;
        bool mKeyReleased = false;
        bool mReleaseIntUsed = false;
        AlignedUnVec<CivoleSid> mUsedSids;
        AlignedUnVec<u64> mReleasedKeys;
    };

    struct CivoleReceiverState
    {
        CivoleParams mParams;
        u64 mModulus = 0;
        u64 mW = 0;
        u32 mRingWidth = 0;
        SamplingSeedConfig mBaseSamplingSeeds;
        ReceiverState mLogVoleState;
        AlignedUnVec<CivoleSid> mUsedSids;
    };

    struct CivoleReleaseKOutput
    {
        CivoleSid mSid = 0;
        u64 mModulus = 0;
        AlignedUnVec<u64> mKeys;
    };

    struct CivoleSenderReleaseOutput
    {
        CivoleSid mSid = 0;
        CommunicationStats mComm;
    };

    struct CivoleReceiverSetXOutput
    {
        CivoleSid mSid = 0;
        u64 mModulus = 0;
        AlignedUnVec<u64> mValues;
        AlignedUnVec<u64> mMacs;
        CommunicationStats mComm;
    };

}

namespace osuCrypto
{
    class LogVoleSender : public TimerAdapter
    {
    public:
        enum class State
        {
            Default,
            Configured,
            Offline
        };

        u64 mRequestSize = 0;
        u32 mPlaintextModulusBits = 55;
        u64 mModulus = 0;
        u64 mDelta = 0;
        u32 mNumThreads = 1;
        LogVole::CivoleSid mNextSid = 0;
        LogVole::CommunicationStats mLastOnlineComm;
        State mState = State::Default;
        LogVole::CivoleParams mParams;
        LogVole::CivoleSenderState mOfflineState;

        void configure(
            u64 n,
            u32 plaintextModulusBits = 55,
            u32 numThreads = 1);

        bool isConfigured() const { return mState != State::Default; }
        bool hasOffline() const { return mState == State::Offline; }
        u64 modulus() const { return mModulus; }

        task<> offline(
            u64 delta,
            Socket& sock);

        task<> send(
            span<u64> b,
            Socket& sock);

        task<> send(
            u64 delta,
            span<u64> b,
            Socket& sock);

        void clear();
    };

    class LogVoleReceiver : public TimerAdapter
    {
    public:
        enum class State
        {
            Default,
            Configured,
            Offline
        };

        u64 mRequestSize = 0;
        u32 mPlaintextModulusBits = 55;
        u64 mModulus = 0;
        u32 mNumThreads = 1;
        LogVole::CivoleSid mNextSid = 0;
        LogVole::CommunicationStats mLastOnlineComm;
        State mState = State::Default;
        LogVole::CivoleParams mParams;
        LogVole::CivoleReceiverState mOfflineState;

        void configure(
            u64 n,
            u32 plaintextModulusBits = 55,
            u32 numThreads = 1);

        bool isConfigured() const { return mState != State::Default; }
        bool hasOffline() const { return mState == State::Offline; }
        u64 modulus() const { return mModulus; }

        task<> offline(Socket& sock);

        task<> receive(
            span<const u64> x,
            span<u64> a,
            Socket& sock);

        void clear();
    };
}

namespace osuCrypto::LogVole
{

    bool makeDefaultCivoleParams(CivoleParams& out, u32 workerThreads = 1);
    bool resolveCivoleModulus(const CivoleParams& params, u64& out);

    u64 zpSlotCount(const ZpCrtContext& ctx);
    u64 zpRingLabelCount(const ZpCrtContext& ctx, u64 zpLabelCount);
    bool makeZpCrtContext(const RingParams& ring, u32 plaintextModulusBits, ZpCrtContext& out);

    bool wrapZpBatchCrt(
        const ZpCrtContext& ctx,
        std::span<const u64> labels,
        bool multiplyByDelta,
        u64 padValue,
        u32 requestedWorkers,
        RnsPoly& out);

    bool wrapZpConstantCrt(
        const ZpCrtContext& ctx,
        u64 value,
        bool multiplyByDelta,
        u32 requestedWorkers,
        RnsPoly& out);

    bool wrapZpLabelsCrt(
        const ZpCrtContext& ctx,
        std::span<const u64> labels,
        bool multiplyByDelta,
        u64 padValue,
        u32 requestedWorkers,
        std::vector<RnsPoly>& out);

    bool unwrapRingLabelsCrt(
        const ZpCrtContext& ctx,
        const std::vector<RnsPoly>& labels,
        u64 zpLabelCount,
        bool scaleAndRound,
        u32 requestedWorkers,
        AlignedUnVec<u64>& out);

    task<> civoleSenderOffline(
        const CivoleSenderOfflineInput& input,
        CivoleSenderState& state,
        Socket& sock);

    task<> civoleReceiverOffline(
        const CivoleReceiverOfflineInput& input,
        CivoleReceiverState& state,
        Socket& sock);

    bool civoleSenderReleaseK(
        CivoleSenderState& state,
        CivoleSid sid,
        CivoleReleaseKOutput& output);

    task<> civoleSenderRelease(
        CivoleSenderState& state,
        CivoleSid sid,
        CivoleSenderReleaseOutput& output,
        Socket& sock);

    task<> civoleReceiverSetX(
        CivoleReceiverState& state,
        CivoleSid sid,
        std::span<const u64> x,
        CivoleReceiverSetXOutput& output,
        Socket& sock);
}

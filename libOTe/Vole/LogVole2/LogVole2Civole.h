#pragma once

#include "libOTe/Tools/Coproto.h"
#include "libOTe/Vole/LogVole2/LogVole2Receiver.h"
#include "libOTe/Vole/LogVole2/LogVole2Ring.h"
#include "libOTe/Vole/LogVole2/LogVole2Sender.h"

#include "seal/seal.h"

#include <memory>
#include <vector>

namespace osuCrypto::LogVole2
{
    using CivoleSid = u64;

    struct ZpCrtContext
    {
        RingNttContext mRing;
        u32 mPlaintextModulusBits = 0;
        u64 mPlaintextModulus = 0;
        std::vector<u64> mDeltaModQj;
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
        std::vector<CivoleSid> mUsedSids;
        std::vector<u64> mReleasedKeys;
    };

    struct CivoleReceiverState
    {
        CivoleParams mParams;
        u64 mModulus = 0;
        u64 mW = 0;
        u32 mRingWidth = 0;
        SamplingSeedConfig mBaseSamplingSeeds;
        ReceiverState mLogVoleState;
        std::vector<CivoleSid> mUsedSids;
    };

    struct CivoleReleaseKOutput
    {
        CivoleSid mSid = 0;
        u64 mModulus = 0;
        std::vector<u64> mKeys;
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
        std::vector<u64> mValues;
        std::vector<u64> mMacs;
        CommunicationStats mComm;
    };

    bool makeDefaultCivoleParams(CivoleParams& out, u32 workerThreads = 1);
    bool resolveCivoleModulus(const CivoleParams& params, u64& out);

    u64 zpSlotCount(const ZpCrtContext& ctx);
    u64 zpRingLabelCount(const ZpCrtContext& ctx, u64 zpLabelCount);
    bool makeZpCrtContext(const RingParams& ring, u32 plaintextModulusBits, ZpCrtContext& out);

    bool wrapZpBatchCrt(
        const ZpCrtContext& ctx,
        const std::vector<u64>& labels,
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
        const std::vector<u64>& labels,
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
        std::vector<u64>& out);

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
        const std::vector<u64>& x,
        CivoleReceiverSetXOutput& output,
        Socket& sock);
}

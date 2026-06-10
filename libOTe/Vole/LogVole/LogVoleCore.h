#pragma once

#include "libOTe/Vole/LogVole/LogVoleEncoding.h"
#include "libOTe/Vole/LogVole/LogVoleShrinkExpand.h"

#include "cryptoTools/Crypto/PRNG.h"

#include <memory>
#include <vector>

namespace osuCrypto::LogVole
{
    enum class SeedLabelMode : u8
    {
        Leaf = 0,
        Internal = 1
    };

    enum class RecursiveMode : u8
    {
        Root = 0,
        Internal = 1
    };

    struct GoldenSeedSearchOutput
    {
        AlignedUnVec<u8> mSeed;
        std::vector<RnsPoly> mTbkPerSampledPoly;
    };

    struct RootDigestState
    {
        RnsPoly mDRt;
        RnsPoly mYLeft;
        RnsPoly mDPrime;
        std::vector<RnsPoly> mHatDRt;
        std::vector<RnsPoly> mZeta;
        std::shared_ptr<DigestTree> mRootTree;
    };

    struct SenderOfflineInput
    {
        Params mParams;
        std::vector<RnsPoly> mSk1;
        bool mLeafInputsAreGadget = false;
    };

    struct OfflineMessage
    {
        bool mHasShrinkExpandMessage = true;
        ShrinkExpandOfflineMessage mShrinkExpandMessage;
        RootOfflineMessage mRootMessage;
        std::unique_ptr<OfflineMessage> mNextLevel;
    };

    struct SenderOfflineOutput
    {
        SenderState mState;
        OfflineMessage mMessage;
        ShrinkExpandOfflineMessage mShrinkExpandMessage;
        RootOfflineMessage mRootMessage;
    };

    struct ReceiverOfflineInput
    {
        Params mParams;
        bool mLeafInputsAreGadget = false;
    };

    struct ReceiverOfflineOutput
    {
        ReceiverState mState;
    };

    struct CommunicationStats
    {
        u64 mBytesSent = 0;
        u64 mBytesReceived = 0;
    };

    struct SenderOnlineOutput
    {
        std::vector<RnsPoly> mTbk;
        AlignedUnVec<u8> mSeed;
        CommunicationStats mComm;
    };

    struct SenderOnlineOptions
    {
        u64 mSid = 0;
        bool mSkipTbkOutput = false;
    };

    struct ReceiverOnlineInput
    {
        u64 mSid = 0;
        std::vector<RnsPoly> mX;
    };

    struct ReceiverOnlineOutput
    {
        std::vector<RnsPoly> mTbm;
        AlignedUnVec<u8> mSeed;
        CommunicationStats mComm;
    };

    u32 rootRandomizerWidth(const ShrinkExpandParams& params);
    u32 rootLeftWidth(u32 tauHi, u32 rho);
    double rootNoiseSigma(const ShrinkExpandParams& params, double factor);
    double rootNoiseMaxDeviation(double sigma);

    SeedLabelMode evalSeedLabelMode(u32 w, u32 alpha, u32 tau, u32 rho);
    RecursiveMode evalRecursiveMode(u32 w, u32 alpha, u32 tau, u32 rho);

    bool makeTruncShrinkExpandParams(
        const Params& params,
        bool leafInputsAreGadget,
        ShrinkExpandParams& out);

    bool replicateRootHiKeyByLimb(
        const std::vector<RnsPoly>& skHi,
        u32 tauHi,
        const RingParams& ring,
        std::vector<RnsPoly>& out);

    bool sampleRootErrorBatch(
        const RingNttContext& ctx,
        u32 count,
        PRNG& prng,
        double sigma,
        double maxDeviation,
        bool outputNtt,
        std::vector<RnsPoly>& out);

    bool addScaledNttInplace(
        RnsPoly& accNtt,
        const RnsPoly& polyNtt,
        u32 gadgetLogBase,
        u32 power,
        const RingNttContext& ctx,
        bool subtract);

    bool negateNttInplace(RnsPoly& polyNtt, const RingNttContext& ctx);

    bool buildRootTopCt(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& r1,
        const std::vector<RnsPoly>& r2Ntt,
        const std::vector<RnsPoly>& publicBRootNtt,
        const std::vector<RnsPoly>& publicBStarNtt,
        u32 gadgetLogBase,
        u32 gadgetPowerOffset,
        PRNG& prng,
        double noiseStandardDeviation,
        double noiseMaxDeviation,
        RingTensor& out);

    bool sampleRootZeta(
        const RingNttContext& ctx,
        u32 randomizerWidth,
        u32 gadgetLogBase,
        PRNG& prng,
        std::vector<RnsPoly>& out);

    bool rootInnerProductNtt(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& leftNtt,
        const std::vector<RnsPoly>& rightCoeff,
        RnsPoly& out);

    bool prepareRootOfflineSender(
        SenderState& state,
        PRNG& prng,
        RootOfflineMessage& message);

    bool finalizeRootOfflineReceiver(
        ReceiverState& state,
        const RootOfflineMessage& message);

    bool prepareRootDigestReceiver(
        const ReceiverState& state,
        const std::vector<RnsPoly>& x,
        PRNG& prng,
        RootDigestState& digestState,
        RootDigestMessage& message);

    bool prepareRootResponseSender(
        const SenderState& state,
        const RootDigestMessage& request,
        PRNG& prng,
        RootResponseMessage& response,
        const SenderState* precomputeRoot = nullptr);

    bool finalizeRootResponseReceiver(
        ReceiverState& state,
        const RootDigestState& digestState,
        const RootResponseMessage& response,
        RnsPoly& rootKey);

    bool computeRootSenderKey(
        const SenderState& state,
        std::span<const u8> seed,
        RnsPoly& rootKey);

    bool prepareSenderOffline(
        const SenderOfflineInput& input,
        PRNG& prng,
        SenderOfflineOutput& out);

    bool finalizeReceiverOffline(
        const ReceiverOfflineInput& input,
        const OfflineMessage& message,
        ReceiverOfflineOutput& out);

    bool finalizeReceiverOffline(
        const ReceiverOfflineInput& input,
        const ShrinkExpandOfflineMessage& shrinkExpandMessage,
        const RootOfflineMessage& rootMessage,
        ReceiverOfflineOutput& out);

    bool ensureSenderPrecompute(
        const SenderState& state);

    bool ensureRootSenderPrecompute(
        const SenderState& state);

    bool runLocalOnline(
        SenderState& sender,
        ReceiverState& receiver,
        const ReceiverOnlineInput& input,
        PRNG& senderPrng,
        PRNG& receiverPrng,
        SenderOnlineOutput& senderOut,
        ReceiverOnlineOutput& receiverOut);

    bool prepareRootOnlineSender(
        SenderState& state,
        const RootDigestMessage& request,
        PRNG& prng,
        RootResponseMessage& response,
        SenderOnlineOutput& out);

    bool finalizeRootOnlineReceiver(
        ReceiverState& state,
        const ReceiverOnlineInput& input,
        const RootDigestState& digestState,
        const RootResponseMessage& response,
        ReceiverOnlineOutput& out);

    bool seedLabelAgg(
        const std::vector<RnsPoly>& inputHat,
        u32 outCount,
        u32 tau,
        const RingParams& ring,
        std::vector<RnsPoly>& out);

    bool seedLabelGadgetDecomposeAndUnbundle(
        const RnsPoly& digest,
        u32 gadgetLogBase,
        u32 tau,
        const RingParams& ring,
        std::vector<RnsPoly>& out);

    bool seedLabelGadgetDecomposeHiAndUnbundle(
        const RnsPoly& digest,
        u32 gadgetLogBase,
        u32 tauHi,
        const RingParams& ring,
        std::vector<RnsPoly>& out);

    bool seedLabelDenoiseTbm(
        const std::vector<RnsPoly>& tbmPrime,
        u32 wPrime,
        u32 tau,
        const RingParams& ring,
        std::vector<RnsPoly>& out);

    bool seedLabelRepOfflineSenderInput(
        const std::vector<RnsPoly>& s,
        u32 gamma,
        u32 alpha,
        u32 tau,
        const RingParams& ring,
        std::vector<RnsPoly>& out);

    bool seedLabelSampleCt2FromSeed(
        std::span<const u8> seed,
        u64 sid,
        const RnsPoly& digest,
        u32 instanceIdx,
        u32 coeffCount,
        const RingParams& ring,
        std::vector<RnsPoly>& out);

    bool validateGoldenSeedSearch(const Params& params);

    bool validateGoldenSeedCandidate(
        const Params& params,
        const std::vector<RnsPoly>& tbkPerSampledPoly,
        bool& out);

    bool findGoldenSeed(
        const Params& params,
        const std::vector<RnsPoly>& sk2PerInstance,
        const RnsPoly& digest,
        PRNG& prng,
        GoldenSeedSearchOutput& out);
}

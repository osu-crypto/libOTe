#pragma once

#include "libOTe/Vole/LogVole/LogVoleEncoding.h"
#include "libOTe/Vole/LogVole/LogVoleRing.h"

#include <cryptoTools/Common/Defines.h>

#include <vector>

namespace osuCrypto::LogVole
{
    enum class ShrinkExpandMode : u8
    {
        Deterministic = 0,
        FullNoise = 1
    };

    struct LencLacct
    {
        u32 mWidthPadded = 0;
        u32 mLevels = 0;
        RingTensor mCt;
    };

    struct LencEncodeOutput
    {
        std::vector<RnsPoly> mR;
        LencLacct mLacct;
    };

    bool lencEnc(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& s,
        u32 tau,
        u32 gadgetLogBase,
        u64 seed,
        LencEncodeOutput& out,
        double noiseStandardDeviation = 0.0,
        double noiseMaxDeviation = 0.0,
        u64 encryptionNoiseSeed = 0);

    bool lencDigest(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& x,
        u32 tau,
        u32 gadgetLogBase,
        RnsPoly& out,
        u32 widthPadded = 0);

    bool lencEval(
        const RingNttContext& ctx,
        const LencLacct& lacct,
        const std::vector<RnsPoly>& x,
        u32 mu,
        u32 tau,
        u32 gadgetLogBase,
        std::vector<RnsPoly>& out);

    struct KeyDeriveSenderInput
    {
        RingParams mParams;
        std::vector<RnsPoly> mSk1;
        std::vector<RnsPoly> mSk2;
    };

    struct KeyDeriveReceiverInput
    {
        RingParams mParams;
        std::vector<RnsPoly> mD;
    };

    struct KeyDeriveSenderOutput
    {
        std::vector<RnsPoly> mK;
    };

    struct KeyDeriveReceiverOutput
    {
        std::vector<RnsPoly> mM;
    };

    bool prepareKeyDeriveRequest(
        const KeyDeriveReceiverInput& input,
        KeyDeriveRequest& out);

    bool processKeyDeriveRequest(
        const KeyDeriveSenderInput& input,
        const KeyDeriveRequest& request,
        KeyDeriveResponse& response,
        KeyDeriveSenderOutput& output);

    bool finalizeKeyDeriveResponse(
        const KeyDeriveReceiverInput& input,
        const KeyDeriveResponse& response,
        KeyDeriveReceiverOutput& output);

    struct ShrinkExpandParams
    {
        RingParams mRing;
        u32 mPlaintextModulusBits = 0;
        u32 mAlpha = 2;
        u32 mMu = 0;
        u32 mGadgetLogBase = 0;
        u32 mTau = 0;
        ShrinkExpandMode mMode = ShrinkExpandMode::Deterministic;
        u64 mNoiseSeed = 0x5EEDBEEF1234ull;
        i64 mNoiseBound = 2;
    };

    struct ShrinkExpandSenderOfflineInput
    {
        ShrinkExpandParams mParams;
        std::vector<RnsPoly> mS;
    };

    struct ShrinkExpandReceiverOfflineInput
    {
        ShrinkExpandParams mParams;
    };

    struct ShrinkExpandSenderState
    {
        ShrinkExpandParams mParams;
        i64 mEffectiveNoiseBound = 0;
        std::vector<RnsPoly> mS;
        std::vector<RnsPoly> mR;
        std::vector<RnsPoly> mSk1;
        RingTensor mCt1;
        LencLacct mLacct;
    };

    struct ShrinkExpandReceiverState
    {
        ShrinkExpandParams mParams;
        i64 mEffectiveNoiseBound = 0;
        RingTensor mCt1;
        LencLacct mLacct;
    };

    struct ShrinkExpandSenderExpandInput
    {
        u64 mNonce = 0;
        RnsPoly mTbkPrime;
    };

    struct ShrinkExpandReceiverExpandInput
    {
        u64 mNonce = 0;
        std::vector<RnsPoly> mX;
        RnsPoly mDigest;
        RnsPoly mSkX;
    };

    struct ShrinkExpandSenderExpandOutput
    {
        std::vector<RnsPoly> mTbk;
    };

    struct ShrinkExpandReceiverExpandOutput
    {
        std::vector<RnsPoly> mTbm;
    };

    bool validateParams(const ShrinkExpandParams& params);
    bool resolveEffectiveNoiseBound(const ShrinkExpandParams& params, i64& out);
    u64 metadataFingerprint(const ShrinkExpandParams& params);

    bool prepareSenderOffline(
        const ShrinkExpandSenderOfflineInput& input,
        ShrinkExpandOfflineMessage& message,
        ShrinkExpandSenderState& state);

    bool finalizeReceiverOffline(
        const ShrinkExpandReceiverOfflineInput& input,
        const ShrinkExpandOfflineMessage& message,
        ShrinkExpandReceiverState& state);

    bool shrink(
        const ShrinkExpandReceiverState& state,
        const std::vector<RnsPoly>& x,
        RnsPoly& digest);

    bool deriveSkX(
        const ShrinkExpandSenderState& state,
        const RnsPoly& digest,
        const RnsPoly& tbkPrime,
        RnsPoly& out);

    bool expandSender(
        const ShrinkExpandSenderState& state,
        const ShrinkExpandSenderExpandInput& input,
        ShrinkExpandSenderExpandOutput& output);

    bool expandReceiver(
        const ShrinkExpandReceiverState& state,
        const ShrinkExpandReceiverExpandInput& input,
        ShrinkExpandReceiverExpandOutput& output);
}

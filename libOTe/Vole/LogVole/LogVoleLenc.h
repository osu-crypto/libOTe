#pragma once

#include "libOTe/Vole/LogVole/LogVoleEncoding.h"
#include "libOTe/Vole/LogVole/LogVoleRing.h"

#include <cryptoTools/Common/Defines.h>

#include <vector>

namespace osuCrypto
{
    enum class LogVoleShrinkExpandMode : u8
    {
        Deterministic = 0,
        FullNoise = 1
    };

    struct LogVoleLencLacct
    {
        u32 mWidthPadded = 0;
        u32 mLevels = 0;
        LogVoleRingTensor mCt;
    };

    struct LogVoleLencEncodeOutput
    {
        std::vector<LogVoleRnsPoly> mR;
        LogVoleLencLacct mLacct;
    };

    bool logVoleLencEnc(
        const LogVoleRingNttContext& ctx,
        const std::vector<LogVoleRnsPoly>& s,
        u32 tau,
        u32 gadgetLogBase,
        u64 seed,
        LogVoleLencEncodeOutput& out,
        double noiseStandardDeviation = 0.0,
        double noiseMaxDeviation = 0.0,
        u64 encryptionNoiseSeed = 0);

    bool logVoleLencDigest(
        const LogVoleRingNttContext& ctx,
        const std::vector<LogVoleRnsPoly>& x,
        u32 tau,
        u32 gadgetLogBase,
        LogVoleRnsPoly& out,
        u32 widthPadded = 0);

    bool logVoleLencEval(
        const LogVoleRingNttContext& ctx,
        const LogVoleLencLacct& lacct,
        const std::vector<LogVoleRnsPoly>& x,
        u32 mu,
        u32 tau,
        u32 gadgetLogBase,
        std::vector<LogVoleRnsPoly>& out);

    struct LogVoleKeyDeriveSenderInput
    {
        LogVoleRingParams mParams;
        std::vector<LogVoleRnsPoly> mSk1;
        std::vector<LogVoleRnsPoly> mSk2;
    };

    struct LogVoleKeyDeriveReceiverInput
    {
        LogVoleRingParams mParams;
        std::vector<LogVoleRnsPoly> mD;
    };

    struct LogVoleKeyDeriveSenderOutput
    {
        std::vector<LogVoleRnsPoly> mK;
    };

    struct LogVoleKeyDeriveReceiverOutput
    {
        std::vector<LogVoleRnsPoly> mM;
    };

    bool logVolePrepareKeyDeriveRequest(
        const LogVoleKeyDeriveReceiverInput& input,
        LogVoleKeyDeriveRequest& out);

    bool logVoleProcessKeyDeriveRequest(
        const LogVoleKeyDeriveSenderInput& input,
        const LogVoleKeyDeriveRequest& request,
        LogVoleKeyDeriveResponse& response,
        LogVoleKeyDeriveSenderOutput& output);

    bool logVoleFinalizeKeyDeriveResponse(
        const LogVoleKeyDeriveReceiverInput& input,
        const LogVoleKeyDeriveResponse& response,
        LogVoleKeyDeriveReceiverOutput& output);

    struct LogVoleShrinkExpandParams
    {
        LogVoleRingParams mRing;
        u32 mPlaintextModulusBits = 0;
        u32 mAlpha = 2;
        u32 mMu = 0;
        u32 mGadgetLogBase = 0;
        u32 mTau = 0;
        LogVoleShrinkExpandMode mMode = LogVoleShrinkExpandMode::Deterministic;
        u64 mNoiseSeed = 0x5EEDBEEF1234ull;
        i64 mNoiseBound = 2;
    };

    struct LogVoleShrinkExpandSenderOfflineInput
    {
        LogVoleShrinkExpandParams mParams;
        std::vector<LogVoleRnsPoly> mS;
    };

    struct LogVoleShrinkExpandReceiverOfflineInput
    {
        LogVoleShrinkExpandParams mParams;
    };

    struct LogVoleShrinkExpandSenderState
    {
        LogVoleShrinkExpandParams mParams;
        i64 mEffectiveNoiseBound = 0;
        std::vector<LogVoleRnsPoly> mS;
        std::vector<LogVoleRnsPoly> mR;
        std::vector<LogVoleRnsPoly> mSk1;
        LogVoleRingTensor mCt1;
        LogVoleLencLacct mLacct;
    };

    struct LogVoleShrinkExpandReceiverState
    {
        LogVoleShrinkExpandParams mParams;
        i64 mEffectiveNoiseBound = 0;
        LogVoleRingTensor mCt1;
        LogVoleLencLacct mLacct;
    };
}

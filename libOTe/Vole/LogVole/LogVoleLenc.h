#pragma once

#include "libOTe/Vole/LogVole/LogVoleRing.h"

#include "cryptoTools/Crypto/PRNG.h"

#include <memory>
#include <span>
#include <vector>

namespace osuCrypto::LogVole
{
    struct LencLacct
    {
        u32 mWidthPadded = 0;
        u32 mLevels = 0;
        RingTensor mCt;
    };

    struct LencEncodeOutput
    {
        std::vector<RnsPoly> mR;
        std::vector<RnsPoly> mRNtt;
        LencLacct mLacct;
    };

    struct KeyDeriveRequest
    {
        u32 mPolyModulusDegree = 0;
        u32 mCoeffModulusCount = 0;
        u32 mTau = 0;
        AlignedUnVec<u64> mDCoeffs;
    };

    struct KeyDeriveResponse
    {
        u32 mPolyModulusDegree = 0;
        u32 mCoeffModulusCount = 0;
        u32 mTau = 0;
        AlignedUnVec<u64> mMNttCoeffs;
    };

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

    struct DigestTree
    {
        u32 mWidthPadded = 0;
        u32 mLevels = 0;
        RnsPoly mDigest;
        std::vector<std::vector<RnsPoly>> mNodeDecompNtt;
    };

    std::vector<RnsPoly> buildLencPublicBNtt(const RingNttContext& ctx, u32 tau);

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

    bool buildDigestTree(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& x,
        u32 tau,
        u32 gadgetLogBase,
        DigestTree& out,
        u32 requestedWidthPadded = 0,
        const std::vector<RnsPoly>* publicBNtt = nullptr,
        u32 requestedWorkers = 1);

    bool buildDigestTree(
        const RingNttContext& ctx,
        std::span<const RnsPoly> x,
        u32 tau,
        u32 gadgetLogBase,
        DigestTree& out,
        u32 requestedWidthPadded = 0,
        const std::vector<RnsPoly>* publicBNtt = nullptr,
        u32 requestedWorkers = 1);

    bool lencEnc(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& s,
        u32 tau,
        u32 gadgetLogBase,
        PRNG& prng,
        LencEncodeOutput& out,
        double noiseStandardDeviation = 0.0,
        double noiseMaxDeviation = 0.0,
        u32 requestedWidthPadded = 0,
        bool emitRCoeffDomain = true,
        const std::vector<RnsPoly>* publicBNtt = nullptr,
        u32 requestedWorkers = 1);

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
        std::vector<RnsPoly>& out,
        bool outputNtt = false,
        u32 requestedWorkers = 1);

    bool lencEval(
        const RingNttContext& ctx,
        const LencLacct& lacct,
        const DigestTree& tree,
        u32 mu,
        u32 tau,
        u32 gadgetLogBase,
        std::vector<RnsPoly>& out,
        bool outputNtt = false,
        u32 requestedWorkers = 1);

    bool buildDigestTreeTrunc(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& x,
        u32 tauHi,
        u32 gadgetLogBase,
        u32 plaintextModulusBits,
        DigestTree& out,
        u32 requestedWidthPadded = 0,
        bool leafInputsAreGadget = false,
        const std::vector<RnsPoly>* publicBNtt = nullptr,
        u32 requestedWorkers = 1);

    bool buildDigestTreeTrunc(
        const RingNttContext& ctx,
        std::span<const RnsPoly> x,
        u32 tauHi,
        u32 gadgetLogBase,
        u32 plaintextModulusBits,
        DigestTree& out,
        u32 requestedWidthPadded = 0,
        bool leafInputsAreGadget = false,
        const std::vector<RnsPoly>* publicBNtt = nullptr,
        u32 requestedWorkers = 1);

    bool lencEncTrunc(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& s,
        u32 tauHi,
        u32 gadgetLogBase,
        u32 plaintextModulusBits,
        PRNG& prng,
        LencEncodeOutput& out,
        double noiseStandardDeviation = 0.0,
        double noiseMaxDeviation = 0.0,
        u32 requestedWidthPadded = 0,
        bool emitRCoeffDomain = true,
        bool leafInputsAreGadget = false,
        const std::vector<RnsPoly>* publicBNtt = nullptr,
        u32 requestedWorkers = 1);

    bool lencDigestTrunc(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& x,
        u32 tauHi,
        u32 gadgetLogBase,
        u32 plaintextModulusBits,
        RnsPoly& out,
        u32 widthPadded = 0,
        bool leafInputsAreGadget = false);

    bool lencEvalTrunc(
        const RingNttContext& ctx,
        const LencLacct& lacct,
        const std::vector<RnsPoly>& x,
        u32 mu,
        u32 tauHi,
        u32 gadgetLogBase,
        u32 plaintextModulusBits,
        std::vector<RnsPoly>& out,
        bool outputNtt = false,
        u32 requestedWorkers = 1,
        bool leafInputsAreGadget = false);

    bool lencEvalTrunc(
        const RingNttContext& ctx,
        const LencLacct& lacct,
        const DigestTree& tree,
        u32 mu,
        u32 tauHi,
        u32 gadgetLogBase,
        u32 plaintextModulusBits,
        std::vector<RnsPoly>& out,
        bool outputNtt = false,
        u32 requestedWorkers = 1,
        bool leafInputsAreGadget = false);
}

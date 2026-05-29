#include "libOTe/Vole/LogVole2/LogVole2ShrinkExpand.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <limits>
#include <memory>

namespace osuCrypto::LogVole2
{
    namespace
    {
        constexpr double kNoiseStdS = 3.19;
        constexpr double kNoiseLambda = 128.0;

        u32 logQBits(const RingParams& params)
        {
            u32 logQ = 0;
            for (int bits : params.mCoeffModulusBits)
            {
                logQ += static_cast<u32>(bits);
            }
            return logQ;
        }

        bool computeBaseNoiseFloor(const ShrinkExpandParams& params, i64& out)
        {
            const double logQ = static_cast<double>(logQBits(params.mRing));
            const double baseNoise = std::pow(2.0, 0.1 * logQ);
            if (!std::isfinite(baseNoise) || baseNoise > static_cast<double>(std::numeric_limits<i64>::max()))
            {
                return false;
            }

            const auto floor = static_cast<i64>(std::ceil(baseNoise));
            out = (floor > 0) ? floor : 1;
            return true;
        }

        double computeSigma(double factor)
        {
            const double normalizedFactor = (factor > 1.0) ? factor : 1.0;
            return kNoiseStdS * normalizedFactor;
        }

        LencLacct toLencLacct(const ShrinkExpandLacct& in)
        {
            LencLacct out{};
            out.mWidthPadded = in.mWidthPadded;
            out.mLevels = in.mLevels;
            out.mCt = in.mCt;
            return out;
        }

        bool buildReceiverDigestTree(
            const RingNttContext& ctx,
            const ShrinkExpandReceiverState& state,
            const std::vector<RnsPoly>& x,
            DigestTree& out)
        {
            const std::vector<RnsPoly>* publicBNtt = state.mPublicBNtt ? state.mPublicBNtt.get() : nullptr;
            if (state.mParams.mTruncateOneGadgetDigit)
            {
                return buildDigestTreeTrunc(
                    ctx,
                    x,
                    state.mParams.mTau,
                    state.mParams.mGadgetLogBase,
                    state.mParams.mPlaintextModulusBits,
                    out,
                    state.mLacct.mWidthPadded,
                    state.mParams.mLeafInputsAreGadget,
                    publicBNtt,
                    state.mParams.mNumWorkerThreads);
            }

            return buildDigestTree(
                ctx,
                x,
                state.mParams.mTau,
                state.mParams.mGadgetLogBase,
                out,
                state.mLacct.mWidthPadded,
                publicBNtt,
                state.mParams.mNumWorkerThreads);
        }

        bool ensureReceiverDigestTree(
            const RingNttContext& ctx,
            const ShrinkExpandReceiverState& state,
            const ShrinkExpandExpandReceiverInput& input,
            std::shared_ptr<DigestTree>& out)
        {
            if (input.mTree)
            {
                out = input.mTree;
                return true;
            }

            if (input.mX.size() != state.mParams.mMu)
            {
                return false;
            }

            DigestTree tree{};
            if (!buildReceiverDigestTree(ctx, state, input.mX, tree) ||
                tree.mDigest.mCoeffs != input.mDigest.mCoeffs)
            {
                return false;
            }

            out = std::make_shared<DigestTree>(std::move(tree));
            return true;
        }

        bool validateStateParamsMatch(const ShrinkExpandParams& expected, const ShrinkExpandParams& actual)
        {
            return expected.mRing == actual.mRing &&
                   expected.mPlaintextModulusBits == actual.mPlaintextModulusBits &&
                   expected.mAlpha == actual.mAlpha &&
                   expected.mMu == actual.mMu &&
                   expected.mGadgetLogBase == actual.mGadgetLogBase &&
                   expected.mTau == actual.mTau &&
                   expected.mTruncateOneGadgetDigit == actual.mTruncateOneGadgetDigit &&
                   expected.mLeafInputsAreGadget == actual.mLeafInputsAreGadget &&
                   expected.mMode == actual.mMode &&
                   expected.mSamplingSeeds.mNoiseRoot == actual.mSamplingSeeds.mNoiseRoot &&
                   expected.mSamplingSeeds.mCt2Root == actual.mSamplingSeeds.mCt2Root &&
                   expected.mNoiseBound == actual.mNoiseBound;
        }
    }

    bool validateShrinkExpandParams(const ShrinkExpandParams& params)
    {
        if (!validateRingParams(params.mRing) ||
            params.mAlpha == 0 ||
            params.mMu == 0 ||
            params.mTau == 0 ||
            params.mPlaintextModulusBits == 0 ||
            params.mGadgetLogBase == 0 ||
            params.mNoiseBound < 0)
        {
            return false;
        }

        if (logQBits(params.mRing) <= params.mPlaintextModulusBits)
        {
            return false;
        }

        if (params.mTruncateOneGadgetDigit && !params.mLeafInputsAreGadget)
        {
            const u32 supportedPlaintextBits = params.mTau * params.mGadgetLogBase;
            if (supportedPlaintextBits < params.mPlaintextModulusBits)
            {
                return false;
            }
        }

        i64 ignored = 0;
        return resolveShrinkExpandEffectiveNoiseBound(params, ignored);
    }

    bool validateShrinkExpandSenderOfflineInput(const ShrinkExpandSenderOfflineInput& input)
    {
        if (!validateShrinkExpandParams(input.mParams) ||
            input.mS.size() != input.mParams.mMu ||
            !validateRingBatchShape(input.mS, input.mParams.mRing))
        {
            return false;
        }

        if (!input.mFixedSk1.empty() &&
            (input.mFixedSk1.size() != input.mParams.mTau ||
             !validateRingBatchShape(input.mFixedSk1, input.mParams.mRing)))
        {
            return false;
        }

        return true;
    }

    bool validateShrinkExpandReceiverOfflineInput(const ShrinkExpandReceiverOfflineInput& input)
    {
        return validateShrinkExpandParams(input.mParams);
    }

    bool resolveShrinkExpandEffectiveNoiseBound(const ShrinkExpandParams& params, i64& out)
    {
        if (params.mMode != ShrinkExpandMode::FullNoise)
        {
            out = params.mNoiseBound;
            return true;
        }

        i64 baseFloor = 0;
        if (!computeBaseNoiseFloor(params, baseFloor))
        {
            return false;
        }
        out = (params.mNoiseBound > baseFloor) ? params.mNoiseBound : baseFloor;
        return true;
    }

    std::vector<RnsPoly> sampleUniformBatch(const RingNttContext& ctx, u32 count, u64 seed, u64 domainTag)
    {
        std::vector<RnsPoly> out;
        out.reserve(count);
        for (u32 i = 0; i < count; ++i)
        {
            const u64 nonce = seed ^ (static_cast<u64>(i) << 1u);
            out.push_back(deriveUniformPolyFromNonce(ctx, nonce, domainTag, i));
        }
        return out;
    }

    bool prepareShrinkExpandSenderOffline(
        const ShrinkExpandSenderOfflineInput& input,
        ShrinkExpandSenderState& senderState)
    {
        if (!validateShrinkExpandSenderOfflineInput(input))
        {
            return false;
        }

        RingNttContext ctx{};
        if (!makeRingNttContext(input.mParams.mRing, ctx))
        {
            return false;
        }

        ShrinkExpandSenderState next{};
        next.mParams = input.mParams;
        if (!resolveShrinkExpandEffectiveNoiseBound(input.mParams, next.mEffectiveNoiseBound))
        {
            return false;
        }

        next.mS = input.mS;
        if (!input.mFixedSk1.empty())
        {
            next.mSk1 = input.mFixedSk1;
        }
        else
        {
            const u64 sk1Seed = deriveNoiseSeed(input.mParams.mSamplingSeeds, 0xA002u, input.mParams.mTau, input.mParams.mMu);
            next.mSk1 = sampleUniformBatch(ctx, input.mParams.mTau, sk1Seed, 0xA002u);
        }

        std::vector<RnsPoly> publicA;
        if (!buildLhePublicANtt(ctx, input.mParams.mMu, publicA))
        {
            return false;
        }
        next.mPublicANtt = std::make_shared<const std::vector<RnsPoly>>(std::move(publicA));

        const u32 publicBTau = input.mParams.mTruncateOneGadgetDigit ? (input.mParams.mTau + 1u) : input.mParams.mTau;
        next.mPublicBNtt = std::make_shared<const std::vector<RnsPoly>>(buildLencPublicBNtt(ctx, publicBTau));

        const bool fullNoise = input.mParams.mMode == ShrinkExpandMode::FullNoise;
        const double lencSigma = fullNoise ? computeSigma(std::sqrt(static_cast<double>(input.mParams.mTau))) : 0.0;
        const double lencMaxDev = fullNoise ? std::sqrt(kNoiseLambda) * lencSigma : 0.0;

        LencEncodeOutput lenc{};
        bool lencOk = false;
        if (input.mParams.mTruncateOneGadgetDigit)
        {
            lencOk = lencEncTrunc(
                ctx,
                input.mS,
                input.mParams.mTau,
                input.mParams.mGadgetLogBase,
                input.mParams.mPlaintextModulusBits,
                input.mParams.mSamplingSeeds,
                lenc,
                lencSigma,
                lencMaxDev,
                0,
                true,
                input.mParams.mLeafInputsAreGadget,
                next.mPublicBNtt.get(),
                input.mParams.mNumWorkerThreads);
        }
        else
        {
            lencOk = lencEnc(
                ctx,
                input.mS,
                input.mParams.mTau,
                input.mParams.mGadgetLogBase,
                input.mParams.mSamplingSeeds,
                lenc,
                lencSigma,
                lencMaxDev,
                0,
                true,
                next.mPublicBNtt.get(),
                input.mParams.mNumWorkerThreads);
        }
        if (!lencOk)
        {
            return false;
        }

        next.mR = std::move(lenc.mR);
        next.mLacct.mWidthPadded = lenc.mLacct.mWidthPadded;
        next.mLacct.mLevels = lenc.mLacct.mLevels;
        next.mLacct.mCt = std::move(lenc.mLacct.mCt);

        const double lheSigma = fullNoise ? computeSigma(std::sqrt(static_cast<double>(next.mLacct.mWidthPadded))) : 0.0;
        const double lheMaxDev = fullNoise ? std::sqrt(kNoiseLambda) * lheSigma : 0.0;

        bool ct1Ok = false;
        if (input.mParams.mTruncateOneGadgetDigit)
        {
            ct1Ok = lheEnc1Trunc(
                ctx,
                lenc.mRNtt,
                next.mSk1,
                input.mParams.mGadgetLogBase,
                next.mCt1,
                lheSigma,
                lheMaxDev,
                input.mParams.mSamplingSeeds,
                true,
                next.mPublicANtt.get(),
                input.mParams.mNumWorkerThreads);
        }
        else
        {
            ct1Ok = lheEnc1(
                ctx,
                lenc.mRNtt,
                next.mSk1,
                input.mParams.mGadgetLogBase,
                next.mCt1,
                lheSigma,
                lheMaxDev,
                input.mParams.mSamplingSeeds,
                true,
                next.mPublicANtt.get(),
                input.mParams.mNumWorkerThreads);
        }
        if (!ct1Ok)
        {
            return false;
        }

        senderState = std::move(next);
        return true;
    }

    bool finalizeShrinkExpandReceiverOffline(
        const ShrinkExpandReceiverOfflineInput& input,
        const ShrinkExpandSenderState& senderState,
        ShrinkExpandReceiverState& receiverState)
    {
        if (!validateShrinkExpandReceiverOfflineInput(input) ||
            !validateStateParamsMatch(input.mParams, senderState.mParams))
        {
            return false;
        }

        RingNttContext ctx{};
        if (!makeRingNttContext(input.mParams.mRing, ctx))
        {
            return false;
        }

        ShrinkExpandReceiverState next{};
        next.mParams = input.mParams;
        if (!resolveShrinkExpandEffectiveNoiseBound(input.mParams, next.mEffectiveNoiseBound))
        {
            return false;
        }

        next.mPublicANtt = senderState.mPublicANtt;
        next.mPublicBNtt = senderState.mPublicBNtt;
        next.mCt1 = senderState.mCt1;
        for (auto& poly : next.mCt1.mPolys)
        {
            if (!forwardNtt(poly, ctx))
            {
                return false;
            }
        }
        next.mLacct = senderState.mLacct;

        receiverState = std::move(next);
        return true;
    }

    bool shrinkExpandShrink(
        const ShrinkExpandReceiverState& state,
        const std::vector<RnsPoly>& x,
        ShrinkExpandShrinkOutput& out)
    {
        if (x.size() != state.mParams.mMu || !validateRingBatchShape(x, state.mParams.mRing))
        {
            return false;
        }

        RingNttContext ctx{};
        if (!makeRingNttContext(state.mParams.mRing, ctx))
        {
            return false;
        }

        DigestTree tree{};
        if (!buildReceiverDigestTree(ctx, state, x, tree))
        {
            return false;
        }

        ShrinkExpandShrinkOutput next{};
        next.mDigest = tree.mDigest;
        next.mTree = std::make_shared<DigestTree>(std::move(tree));
        out = std::move(next);
        return true;
    }

    bool shrinkExpandExpandSender(
        const ShrinkExpandSenderState& state,
        const ShrinkExpandExpandSenderInput& input,
        ShrinkExpandSenderExpandOutput& out)
    {
        if (!validateRingPolyShape(input.mTbkPrime, state.mParams.mRing))
        {
            return false;
        }

        RingNttContext ctx{};
        if (!makeRingNttContext(state.mParams.mRing, ctx))
        {
            return false;
        }

        std::vector<RnsPoly> ct2;
        if (!buildHashedCt2(ctx, state.mParams.mMu, state.mParams.mSamplingSeeds, input.mNonce, ct2))
        {
            return false;
        }

        ShrinkExpandSenderExpandOutput next{};
        if (!lheDec(
                ctx,
                ct2,
                input.mTbkPrime,
                next.mTbk,
                state.mPublicANtt ? state.mPublicANtt.get() : nullptr,
                false,
                false,
                state.mParams.mNumWorkerThreads))
        {
            return false;
        }

        out = std::move(next);
        return true;
    }

    bool shrinkExpandExpandReceiver(
        const ShrinkExpandReceiverState& state,
        const ShrinkExpandExpandReceiverInput& input,
        ShrinkExpandReceiverExpandOutput& out)
    {
        if ((!input.mTree && input.mX.size() != state.mParams.mMu) ||
            !validateRingPolyShape(input.mDigest, state.mParams.mRing) ||
            !validateRingPolyShape(input.mSkX, state.mParams.mRing))
        {
            return false;
        }

        RingNttContext ctx{};
        if (!makeRingNttContext(state.mParams.mRing, ctx))
        {
            return false;
        }

        std::shared_ptr<DigestTree> tree;
        if (!ensureReceiverDigestTree(ctx, state, input, tree))
        {
            return false;
        }

        std::vector<RnsPoly> ct2;
        if (!buildHashedCt2(ctx, state.mParams.mMu, state.mParams.mSamplingSeeds, input.mNonce, ct2))
        {
            return false;
        }

        std::vector<RnsPoly> ct1AppliedNtt;
        bool applyOk = false;
        if (state.mParams.mTruncateOneGadgetDigit)
        {
            applyOk = lheApplyCt1Trunc(
                ctx,
                state.mCt1,
                input.mDigest,
                state.mParams.mGadgetLogBase,
                state.mParams.mTau,
                ct1AppliedNtt,
                true,
                state.mParams.mNumWorkerThreads);
        }
        else
        {
            applyOk = lheApplyCt1(
                ctx,
                state.mCt1,
                input.mDigest,
                state.mParams.mGadgetLogBase,
                state.mParams.mTau,
                ct1AppliedNtt,
                true,
                state.mParams.mNumWorkerThreads);
        }
        if (!applyOk)
        {
            return false;
        }

        std::vector<RnsPoly> decPartialNtt;
        if (!lheDec(
                ctx,
                ct1AppliedNtt,
                input.mSkX,
                decPartialNtt,
                state.mPublicANtt ? state.mPublicANtt.get() : nullptr,
                true,
                true,
                state.mParams.mNumWorkerThreads))
        {
            return false;
        }

        std::vector<RnsPoly> evalNtt;
        bool evalOk = false;
        if (state.mParams.mTruncateOneGadgetDigit)
        {
            evalOk = lencEvalTrunc(
                ctx,
                toLencLacct(state.mLacct),
                *tree,
                state.mParams.mMu,
                state.mParams.mTau,
                state.mParams.mGadgetLogBase,
                state.mParams.mPlaintextModulusBits,
                evalNtt,
                true,
                state.mParams.mNumWorkerThreads,
                state.mParams.mLeafInputsAreGadget);
        }
        else
        {
            evalOk = lencEval(
                ctx,
                toLencLacct(state.mLacct),
                *tree,
                state.mParams.mMu,
                state.mParams.mTau,
                state.mParams.mGadgetLogBase,
                evalNtt,
                true,
                state.mParams.mNumWorkerThreads);
        }
        if (!evalOk ||
            decPartialNtt.size() != state.mParams.mMu ||
            evalNtt.size() != state.mParams.mMu ||
            ct2.size() != state.mParams.mMu)
        {
            return false;
        }

        ShrinkExpandReceiverExpandOutput next{};
        next.mTbm.resize(state.mParams.mMu);
        for (u32 row = 0; row < state.mParams.mMu; ++row)
        {
            RnsPoly tbm = std::move(decPartialNtt[row]);
            if (!ringSubInplace(tbm, evalNtt[row], ctx) ||
                !inverseNtt(tbm, ctx) ||
                !ringAddInplace(tbm, ct2[row], ctx))
            {
                return false;
            }
            next.mTbm[row] = std::move(tbm);
        }

        out = std::move(next);
        return true;
    }
}

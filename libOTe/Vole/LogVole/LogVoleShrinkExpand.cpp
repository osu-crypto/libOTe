#include "libOTe/Vole/LogVole/LogVoleShrinkExpand.h"
#include "libOTe/Vole/LogVole/LogVoleArithmetic.h"
#include "libOTe/Vole/LogVole/LogVoleRuntime.h"

#include "seal/util/rns.h"
#include "seal/util/uintarithsmallmod.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <memory>

namespace osuCrypto::LogVole
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

        struct Ct2CacheEntry
        {
            bool mValid = false;
            RingParams mRing;
            u32 mMu = 0;
            u64 mNonce = 0;
            u64 mSid = 0;
            u64 mRunId = 0;
            ProtocolCacheRole mRole = ProtocolCacheRole::Unspecified;
            std::vector<RnsPoly> mCt2;
        };

        bool matchesCt2Cache(
            const Ct2CacheEntry& cache,
            const RingParams& ring,
            u32 mu,
            u64 nonce,
            u64 sid,
            ProtocolCacheScope scope)
        {
            (void)cache;
            (void)ring;
            (void)mu;
            (void)nonce;
            (void)sid;
            (void)scope;
            return false;
#if 0
            return cache.mValid &&
                   cache.mRing == ring &&
                   cache.mMu == mu &&
                   cache.mNonce == nonce &&
                   cache.mSid == sid &&
                   cache.mRunId == scope.mRunId &&
                   cache.mRole == scope.mRole;
#endif
        }

        bool getOrBuildCachedCt2(
            const RingNttContext& ctx,
            const ShrinkExpandParams& params,
            std::span<const u8> seed,
            u64 sid,
            const RnsPoly& digest,
            u64 instanceIdx,
            u64 nonce,
            Ct2CacheEntry& cache)
        {
            const auto scope = currentProtocolCacheScope();
            if (matchesCt2Cache(cache, params.mRing, params.mMu, nonce, sid, scope))
            {
                return true;
            }

            std::vector<RnsPoly> ct2;
            if (!buildHashedCt2(ctx, params.mMu, seed, sid, digest, instanceIdx, ct2))
            {
                return false;
            }

            cache.mValid = true;
            cache.mRing = params.mRing;
            cache.mMu = params.mMu;
            cache.mNonce = nonce;
            cache.mSid = sid;
            cache.mRunId = scope.mRunId;
            cache.mRole = scope.mRole;
            cache.mCt2 = std::move(ct2);
            return true;
        }

        double computeSigma(double factor)
        {
            const double normalizedFactor = (factor > 1.0) ? factor : 1.0;
            return kNoiseStdS * normalizedFactor;
        }

        bool isValidShrinkExpandMode(ShrinkExpandMode mode)
        {
            switch (mode)
            {
            case ShrinkExpandMode::FullNoise:
                return true;
#ifdef LIBOTE_LOGVOLE_ENABLE_INSECURE_NOISELESS
            case ShrinkExpandMode::Deterministic:
                return true;
#endif
            default:
                return false;
            }
        }

        bool usesFullNoise(const ShrinkExpandParams& params)
        {
#ifdef LIBOTE_LOGVOLE_ENABLE_INSECURE_NOISELESS
            return params.mMode == ShrinkExpandMode::FullNoise;
#else
            (void)params;
            return true;
#endif
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
            std::span<const RnsPoly> x,
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
                !rangesEqual(tree.mDigest.mCoeffs, input.mDigest.mCoeffs))
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
            !isValidShrinkExpandMode(params.mMode) ||
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

        return true;
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

    std::vector<RnsPoly> sampleUniformBatch(const RingNttContext& ctx, u32 count, PRNG& prng)
    {
        std::vector<RnsPoly> out(count);
        for (u32 i = 0; i < count; ++i)
        {
            out[i] = sampleUniformPoly(ctx, prng);
        }
        return out;
    }

    bool prepareShrinkExpandSenderOffline(
        const ShrinkExpandSenderOfflineInput& input,
        PRNG& prng,
        ShrinkExpandOfflineMessage& message,
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
        next.mS = input.mS;
        if (!input.mFixedSk1.empty())
        {
            next.mSk1 = input.mFixedSk1;
        }
        else
        {
            next.mSk1 = sampleUniformBatch(ctx, input.mParams.mTau, prng);
        }

        std::vector<RnsPoly> publicA;
        if (!buildLhePublicANtt(ctx, input.mParams.mMu, publicA))
        {
            return false;
        }
        next.mPublicANtt = std::make_shared<const std::vector<RnsPoly>>(std::move(publicA));

        const u32 publicBTau = input.mParams.mTruncateOneGadgetDigit ? (input.mParams.mTau + 1u) : input.mParams.mTau;
        next.mPublicBNtt = std::make_shared<const std::vector<RnsPoly>>(buildLencPublicBNtt(ctx, publicBTau));

        const bool fullNoise = usesFullNoise(input.mParams);
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
                prng,
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
                prng,
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
                &prng,
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
                &prng,
                true,
                next.mPublicANtt.get(),
                input.mParams.mNumWorkerThreads);
        }
        if (!ct1Ok)
        {
            return false;
        }

        ShrinkExpandOfflineMessage nextMessage{};
        nextMessage.mParams = next.mParams;
        nextMessage.mCt1 = next.mCt1;
        nextMessage.mLacct = next.mLacct;

        message = std::move(nextMessage);
        senderState = std::move(next);
        return true;
    }

    bool prepareShrinkExpandSenderOffline(
        const ShrinkExpandSenderOfflineInput& input,
        PRNG& prng,
        ShrinkExpandSenderState& senderState)
    {
        ShrinkExpandOfflineMessage ignored{};
        return prepareShrinkExpandSenderOffline(input, prng, ignored, senderState);
    }

    bool finalizeShrinkExpandReceiverOffline(
        const ShrinkExpandReceiverOfflineInput& input,
        const ShrinkExpandOfflineMessage& message,
        ShrinkExpandReceiverState& receiverState)
    {
        if (!validateShrinkExpandReceiverOfflineInput(input) ||
            !validateStateParamsMatch(input.mParams, message.mParams))
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
        std::vector<RnsPoly> publicA;
        if (!buildLhePublicANtt(ctx, input.mParams.mMu, publicA))
        {
            return false;
        }
        next.mPublicANtt = std::make_shared<const std::vector<RnsPoly>>(std::move(publicA));

        const u32 publicBTau = input.mParams.mTruncateOneGadgetDigit ? (input.mParams.mTau + 1u) : input.mParams.mTau;
        next.mPublicBNtt = std::make_shared<const std::vector<RnsPoly>>(buildLencPublicBNtt(ctx, publicBTau));

        next.mCt1 = message.mCt1;
        if (next.mCt1.mRows != input.mParams.mMu ||
            next.mCt1.mCols != input.mParams.mTau ||
            ringTensorSize(next.mCt1) != next.mCt1.mPolys.size() ||
            !validateRingBatchShape(next.mCt1.mPolys, input.mParams.mRing))
        {
            return false;
        }

        for (auto& poly : next.mCt1.mPolys)
        {
            if (!forwardNtt(poly, ctx))
            {
                return false;
            }
        }
        next.mLacct = message.mLacct;
        if (next.mLacct.mWidthPadded == 0 ||
            next.mLacct.mLevels == 0 ||
            next.mLacct.mCt.mRows != next.mLacct.mLevels * next.mLacct.mWidthPadded ||
            ringTensorSize(next.mLacct.mCt) != next.mLacct.mCt.mPolys.size() ||
            !validateRingBatchShape(next.mLacct.mCt.mPolys, input.mParams.mRing))
        {
            return false;
        }

        receiverState = std::move(next);
        return true;
    }

    bool finalizeShrinkExpandReceiverOffline(
        const ShrinkExpandReceiverOfflineInput& input,
        const ShrinkExpandSenderState& senderState,
        ShrinkExpandReceiverState& receiverState)
    {
        ShrinkExpandOfflineMessage message{};
        message.mParams = senderState.mParams;
        message.mCt1 = senderState.mCt1;
        message.mLacct = senderState.mLacct;
        return finalizeShrinkExpandReceiverOffline(input, message, receiverState);
    }

    bool shrinkExpandShrink(
        const ShrinkExpandReceiverState& state,
        const std::vector<RnsPoly>& x,
        ShrinkExpandShrinkOutput& out)
    {
        return shrinkExpandShrink(state, std::span<const RnsPoly>(x.data(), x.size()), out);
    }

    bool shrinkExpandShrink(
        const ShrinkExpandReceiverState& state,
        std::span<const RnsPoly> x,
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
        if (!validateRingPolyShape(input.mTbkPrime, state.mParams.mRing) ||
            !validateRingPolyShape(input.mDigest, state.mParams.mRing) ||
            (!input.mMaskDigest.mCoeffs.empty() &&
                !validateRingPolyShape(input.mMaskDigest, state.mParams.mRing)) ||
            input.mSeed.empty())
        {
            return false;
        }

        RingNttContext ctx{};
        if (!makeRingNttContext(state.mParams.mRing, ctx))
        {
            return false;
        }

        const RnsPoly& maskDigest = input.mMaskDigest.mCoeffs.empty() ? input.mDigest : input.mMaskDigest;
        thread_local Ct2CacheEntry senderCt2Cache{};
        if (!getOrBuildCachedCt2(
                ctx,
                state.mParams,
                input.mSeed,
                input.mSid,
                maskDigest,
                input.mNonce,
                input.mNonce,
                senderCt2Cache))
        {
            return false;
        }

        ShrinkExpandSenderExpandOutput next{};
        if (!lheDec(
                ctx,
                senderCt2Cache.mCt2,
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
            (!input.mMaskDigest.mCoeffs.empty() &&
                !validateRingPolyShape(input.mMaskDigest, state.mParams.mRing)) ||
            !validateRingPolyShape(input.mSkX, state.mParams.mRing) ||
            input.mSeed.empty())
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

        const RnsPoly& maskDigest = input.mMaskDigest.mCoeffs.empty() ? input.mDigest : input.mMaskDigest;
        thread_local Ct2CacheEntry receiverCt2Cache{};
        if (!getOrBuildCachedCt2(
                ctx,
                state.mParams,
                input.mSeed,
                input.mSid,
                maskDigest,
                input.mNonce,
                input.mNonce,
                receiverCt2Cache))
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
            receiverCt2Cache.mCt2.size() != state.mParams.mMu)
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
                !ringAddInplace(tbm, receiverCt2Cache.mCt2[row], ctx))
            {
                return false;
            }
            next.mTbm[row] = std::move(tbm);
        }

        out = std::move(next);
        return true;
    }

    bool shrinkExpandDenoiseComb(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& tbaPrime,
        std::vector<RnsPoly>& out)
    {
        if (ctx.mParams.mCoeffModulusBits.empty() ||
            tbaPrime.size() % ctx.mParams.mCoeffModulusBits.size() != 0 ||
            !validateRingBatchShape(tbaPrime, ctx.mParams))
        {
            return false;
        }

        auto keyContextData = ctx.mContext ? ctx.mContext->key_context_data() : nullptr;
        if (!keyContextData)
        {
            return false;
        }

        const std::size_t rho = ctx.mParams.mCoeffModulusBits.size();
        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        const std::size_t wPrime = tbaPrime.size() / rho;

        auto pool = seal::MemoryManager::GetPool();
        seal::util::RNSBase fullBase(keyContextData->parms().coeff_modulus(), pool);

        AlignedUnVec<u64> q(rho);
        for (std::size_t i = 0; i < rho; ++i)
        {
            q[i] = fullBase.base()[i].value();
        }

        struct RecoveryConstants
        {
            AlignedUnVec<std::size_t> mSrcLimbIndices;
            AlignedUnVec<u64> mCrtInvPunctured;
            AlignedUnVec<u64> mPuncturedProdModTarget;
            AlignedUnVec<wideU64> mFracInvModulus;
            u64 mCrtLiftModTarget = 1;
            u64 mInvCrtLiftModTarget = 1;
        };

        std::vector<RecoveryConstants> recovery(rho);
        for (std::size_t j = 0; j < rho; ++j)
        {
            const auto& modJ = ctx.mModuli[j];
            auto& constants = recovery[j];
            constants.mSrcLimbIndices.resize((rho > 0) ? (rho - 1) : 0);
            std::size_t srcLimbIdx = 0;

            std::vector<seal::Modulus> baseExcludingJ;
            baseExcludingJ.reserve((rho > 0) ? (rho - 1) : 0);

            u64 crtLiftModQj = 1;
            for (std::size_t w = 0; w < rho; ++w)
            {
                if (w == j)
                {
                    continue;
                }
                constants.mSrcLimbIndices[srcLimbIdx++] = w;
                baseExcludingJ.push_back(ctx.mModuli[w]);
                crtLiftModQj = seal::util::multiply_uint_mod(crtLiftModQj, q[w], modJ);
            }
            constants.mCrtLiftModTarget = crtLiftModQj;

            u64 invCrtLiftModQj = 0;
            if (!seal::util::try_invert_uint_mod(crtLiftModQj, modJ, invCrtLiftModQj))
            {
                return false;
            }
            constants.mInvCrtLiftModTarget = invCrtLiftModQj;

            if (baseExcludingJ.empty())
            {
                continue;
            }

            seal::util::RNSBase reducedBase(baseExcludingJ, pool);
            auto reducedInvPunct = reducedBase.inv_punctured_prod_mod_base_array();

            const std::size_t reducedCount = constants.mSrcLimbIndices.size();
            resizeZero(constants.mCrtInvPunctured, reducedCount);
            resizeZero(constants.mPuncturedProdModTarget, reducedCount);
            resizeZero(constants.mFracInvModulus, reducedCount);

            for (std::size_t idx = 0; idx < reducedCount; ++idx)
            {
                const std::size_t w = constants.mSrcLimbIndices[idx];
                constants.mCrtInvPunctured[idx] = reducedInvPunct[idx].operand;
                constants.mFracInvModulus[idx] = reciprocal2Pow128Wide(q[w]);

                u64 puncturedModQj = 1;
                for (std::size_t u = 0; u < rho; ++u)
                {
                    if (u == j || u == w)
                    {
                        continue;
                    }
                    puncturedModQj = seal::util::multiply_uint_mod(puncturedModQj, q[u], modJ);
                }
                constants.mPuncturedProdModTarget[idx] = puncturedModQj;
            }
        }

        std::vector<RnsPoly> result(wPrime);
        const wideU64 half = wideU64OneShift(127);

        for (std::size_t i = 0; i < wPrime; ++i)
        {
            RnsPoly polyOut{};
            resizeZero(polyOut.mCoeffs, n * rho);

            for (std::size_t j = 0; j < rho; ++j)
            {
                const auto& polyIn = tbaPrime[i * rho + j];
                const u64 qj = q[j];
                const auto& modJ = ctx.mModuli[j];
                const auto& constants = recovery[j];
                const std::size_t reducedCount = constants.mSrcLimbIndices.size();

                for (std::size_t k = 0; k < n; ++k)
                {
                    wideU64 sumFrac = half;
                    u64 alpha = 0;
                    u64 eModQj = 0;

                    auto consumeIdx = [&](std::size_t idx) {
                        const std::size_t w = constants.mSrcLimbIndices[idx];
                        const u64 vw = polyIn.mCoeffs[w * n + k];
                        const u64 xw = seal::util::multiply_uint_mod(vw, constants.mCrtInvPunctured[idx], ctx.mModuli[w]);

                        unsigned char carry = 0;
                        sumFrac = wideU64Add(
                            sumFrac,
                            wideU64MulLow(xw, constants.mFracInvModulus[idx]),
                            &carry);
                        if (carry)
                        {
                            ++alpha;
                        }

                        const u64 xwModQj = seal::util::barrett_reduce_64(xw, modJ);
                        const u64 proj =
                            seal::util::multiply_uint_mod(xwModQj, constants.mPuncturedProdModTarget[idx], modJ);
                        eModQj += proj;
                        if (eModQj >= qj)
                        {
                            eModQj -= qj;
                        }
                    };

                    switch (reducedCount)
                    {
                    case 0:
                        break;
                    case 1:
                        consumeIdx(0);
                        break;
                    case 2:
                        consumeIdx(0);
                        consumeIdx(1);
                        break;
                    case 3:
                        consumeIdx(0);
                        consumeIdx(1);
                        consumeIdx(2);
                        break;
                    case 4:
                        consumeIdx(0);
                        consumeIdx(1);
                        consumeIdx(2);
                        consumeIdx(3);
                        break;
                    default:
                        for (std::size_t idx = 0; idx < reducedCount; ++idx)
                        {
                            consumeIdx(idx);
                        }
                        break;
                    }

                    const u64 alphaTerm =
                        seal::util::multiply_uint_mod(alpha, constants.mCrtLiftModTarget, modJ);
                    if (eModQj >= alphaTerm)
                    {
                        eModQj -= alphaTerm;
                    }
                    else
                    {
                        eModQj += qj - alphaTerm;
                    }

                    const u64 vj = polyIn.mCoeffs[j * n + k];
                    const u64 diff = (vj >= eModQj) ? (vj - eModQj) : (vj + qj - eModQj);
                    polyOut.mCoeffs[j * n + k] =
                        seal::util::multiply_uint_mod(diff, constants.mInvCrtLiftModTarget, modJ);
                }
            }

            result[i] = std::move(polyOut);
        }

        out = std::move(result);
        return true;
    }
}

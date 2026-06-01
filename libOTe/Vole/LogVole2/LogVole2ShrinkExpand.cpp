#include "libOTe/Vole/LogVole2/LogVole2ShrinkExpand.h"
#include "libOTe/Vole/LogVole2/LogVole2Runtime.h"

#include "seal/util/rns.h"
#include "seal/util/uintarithsmallmod.h"

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

        double etaEpsilonRing(double n, double lambdaSec)
        {
            constexpr double pi = 3.141592653589793238462643383279502884;
            return std::sqrt((lambdaSec * std::log(2.0) + std::log(n)) / pi);
        }

        struct LeakyLweNoiseShape
        {
            double mS = -std::numeric_limits<double>::infinity();
            double mSbarOverLeakageNorm = -std::numeric_limits<double>::infinity();
        };

        struct Ct2CacheEntry
        {
            bool mValid = false;
            RingParams mRing;
            u32 mMu = 0;
            u64 mNonce = 0;
            u64 mCt2Root = 0;
            u64 mRunId = 0;
            ProtocolCacheRole mRole = ProtocolCacheRole::Unspecified;
            std::vector<RnsPoly> mCt2;
        };

        bool matchesCt2Cache(
            const Ct2CacheEntry& cache,
            const RingParams& ring,
            u32 mu,
            u64 nonce,
            u64 ct2Root,
            ProtocolCacheScope scope)
        {
            return cache.mValid &&
                   cache.mRing == ring &&
                   cache.mMu == mu &&
                   cache.mNonce == nonce &&
                   cache.mCt2Root == ct2Root &&
                   cache.mRunId == scope.mRunId &&
                   cache.mRole == scope.mRole;
        }

        bool getOrBuildCachedCt2(
            const RingNttContext& ctx,
            const ShrinkExpandParams& params,
            u64 nonce,
            Ct2CacheEntry& cache)
        {
            const auto scope = currentProtocolCacheScope();
            if (matchesCt2Cache(cache, params.mRing, params.mMu, nonce, params.mSamplingSeeds.mCt2Root, scope))
            {
                return true;
            }

            std::vector<RnsPoly> ct2;
            if (!buildHashedCt2(ctx, params.mMu, params.mSamplingSeeds, nonce, ct2))
            {
                return false;
            }

            cache.mValid = true;
            cache.mRing = params.mRing;
            cache.mMu = params.mMu;
            cache.mNonce = nonce;
            cache.mCt2Root = params.mSamplingSeeds.mCt2Root;
            cache.mRunId = scope.mRunId;
            cache.mRole = scope.mRole;
            cache.mCt2 = std::move(ct2);
            return true;
        }

        LeakyLweNoiseShape computeLeakyLweNoiseShape(
            double sStar,
            double etaEpsR,
            double linearCoeff,
            double leakCoeff)
        {
            if (!(linearCoeff > 0.0) || !(leakCoeff > 0.0))
            {
                return {};
            }

            const double leakyA = sStar * sStar + 2.0 * etaEpsR * etaEpsR;
            if (!(leakyA > 0.0))
            {
                return {};
            }

            const double threshold = std::sqrt(leakyA);
            const double minimizerK = leakCoeff / linearCoeff;
            const double sMultiplier = std::sqrt(1.0 + std::pow(minimizerK, 2.0 / 3.0));
            if (!std::isfinite(sMultiplier) || !(sMultiplier > 1.0))
            {
                return {};
            }

            LeakyLweNoiseShape out{};
            out.mS = threshold * sMultiplier;
            out.mSbarOverLeakageNorm = threshold * sMultiplier / std::sqrt(sMultiplier * sMultiplier - 1.0);
            return out;
        }

        bool computeBaseNoiseFloor(const ShrinkExpandParams& params, i64& out)
        {
            const double sStar = 8.0;
            const double T = 32768.0;
            const double lambdaSec = 128.0;
            const double L = 10.0;

            const double n = static_cast<double>(params.mRing.mPolyModulusDegree);
            const double m = static_cast<double>(params.mTau);
            const double g = std::pow(2.0, static_cast<double>(params.mGadgetLogBase));
            const double gammaR = n;

            const double etaEpsR = etaEpsilonRing(n, lambdaSec);
            if (!std::isfinite(etaEpsR))
            {
                return false;
            }

            const double pref = 2.0 * std::sqrt(lambdaSec);
            const double sqrt2mT = std::sqrt(2.0 * m * T);
            const double linearCoeff = pref * m * gammaR * L;
            const double leakCoeff = pref * 2.0 * n * sqrt2mT;
            const auto noiseShape = computeLeakyLweNoiseShape(sStar, etaEpsR, linearCoeff, leakCoeff);
            if (!std::isfinite(noiseShape.mS) || !std::isfinite(noiseShape.mSbarOverLeakageNorm))
            {
                return false;
            }

            const double s = noiseShape.mS;
            const double sBar = noiseShape.mSbarOverLeakageNorm * g * n * sqrt2mT;
            const double termA = g * m * gammaR * s * L;
            const double termB = 2.0 * sBar;
            const double total = 2.0 * std::sqrt(lambdaSec) * (termA + termB);
            if (!std::isfinite(total))
            {
                return false;
            }

            const double roundedUp = std::ceil(total);
            if (roundedUp > static_cast<double>(std::numeric_limits<i64>::max()))
            {
                out = std::numeric_limits<i64>::max();
                return true;
            }

            const auto floor = static_cast<i64>(roundedUp);
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

        unsigned __int128 reciprocal2Pow128(u64 modulus)
        {
            const unsigned __int128 two64 = static_cast<unsigned __int128>(1) << 64;
            const u64 hi = static_cast<u64>(two64 / modulus);
            const u64 rem = static_cast<u64>(two64 % modulus);
            const u64 lo = static_cast<u64>((static_cast<unsigned __int128>(rem) << 64) / modulus);
            return (static_cast<unsigned __int128>(hi) << 64) | lo;
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
        ShrinkExpandSenderState& senderState)
    {
        ShrinkExpandOfflineMessage ignored{};
        return prepareShrinkExpandSenderOffline(input, ignored, senderState);
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
        if (!resolveShrinkExpandEffectiveNoiseBound(input.mParams, next.mEffectiveNoiseBound))
        {
            return false;
        }

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

        thread_local Ct2CacheEntry senderCt2Cache{};
        if (!getOrBuildCachedCt2(ctx, state.mParams, input.mNonce, senderCt2Cache))
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

        thread_local Ct2CacheEntry receiverCt2Cache{};
        if (!getOrBuildCachedCt2(ctx, state.mParams, input.mNonce, receiverCt2Cache))
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

        std::vector<u64> q(rho);
        for (std::size_t i = 0; i < rho; ++i)
        {
            q[i] = fullBase.base()[i].value();
        }

        struct RecoveryConstants
        {
            std::vector<std::size_t> mSrcLimbIndices;
            std::vector<u64> mCrtInvPunctured;
            std::vector<u64> mPuncturedProdModTarget;
            std::vector<unsigned __int128> mFracInvModulus;
            u64 mDeltaModTarget = 1;
            u64 mInvDeltaModTarget = 1;
        };

        std::vector<RecoveryConstants> recovery(rho);
        for (std::size_t j = 0; j < rho; ++j)
        {
            const auto& modJ = ctx.mModuli[j];
            auto& constants = recovery[j];
            constants.mSrcLimbIndices.reserve((rho > 0) ? (rho - 1) : 0);

            std::vector<seal::Modulus> baseExcludingJ;
            baseExcludingJ.reserve((rho > 0) ? (rho - 1) : 0);

            u64 deltaModQj = 1;
            for (std::size_t w = 0; w < rho; ++w)
            {
                if (w == j)
                {
                    continue;
                }
                constants.mSrcLimbIndices.push_back(w);
                baseExcludingJ.push_back(ctx.mModuli[w]);
                deltaModQj = seal::util::multiply_uint_mod(deltaModQj, q[w], modJ);
            }
            constants.mDeltaModTarget = deltaModQj;

            u64 invDeltaModQj = 0;
            if (!seal::util::try_invert_uint_mod(deltaModQj, modJ, invDeltaModQj))
            {
                return false;
            }
            constants.mInvDeltaModTarget = invDeltaModQj;

            if (baseExcludingJ.empty())
            {
                continue;
            }

            seal::util::RNSBase reducedBase(baseExcludingJ, pool);
            auto reducedInvPunct = reducedBase.inv_punctured_prod_mod_base_array();

            const std::size_t reducedCount = constants.mSrcLimbIndices.size();
            constants.mCrtInvPunctured.resize(reducedCount, 0);
            constants.mPuncturedProdModTarget.resize(reducedCount, 0);
            constants.mFracInvModulus.resize(reducedCount, 0);

            for (std::size_t idx = 0; idx < reducedCount; ++idx)
            {
                const std::size_t w = constants.mSrcLimbIndices[idx];
                constants.mCrtInvPunctured[idx] = reducedInvPunct[idx].operand;
                constants.mFracInvModulus[idx] = reciprocal2Pow128(q[w]);

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
        const unsigned __int128 half = static_cast<unsigned __int128>(1) << 127;

        for (std::size_t i = 0; i < wPrime; ++i)
        {
            RnsPoly polyOut{};
            polyOut.mCoeffs.resize(n * rho, 0);

            for (std::size_t j = 0; j < rho; ++j)
            {
                const auto& polyIn = tbaPrime[i * rho + j];
                const u64 qj = q[j];
                const auto& modJ = ctx.mModuli[j];
                const auto& constants = recovery[j];
                const std::size_t reducedCount = constants.mSrcLimbIndices.size();

                for (std::size_t k = 0; k < n; ++k)
                {
                    unsigned __int128 sumFrac = half;
                    u64 alpha = 0;
                    u64 eModQj = 0;

                    auto consumeIdx = [&](std::size_t idx) {
                        const std::size_t w = constants.mSrcLimbIndices[idx];
                        const u64 vw = polyIn.mCoeffs[w * n + k];
                        const u64 xw = seal::util::multiply_uint_mod(vw, constants.mCrtInvPunctured[idx], ctx.mModuli[w]);

                        const unsigned __int128 term =
                            static_cast<unsigned __int128>(xw) * constants.mFracInvModulus[idx];
                        const unsigned __int128 oldFrac = sumFrac;
                        sumFrac += term;
                        if (sumFrac < oldFrac)
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
                        seal::util::multiply_uint_mod(alpha, constants.mDeltaModTarget, modJ);
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
                        seal::util::multiply_uint_mod(diff, constants.mInvDeltaModTarget, modJ);
                }
            }

            result[i] = std::move(polyOut);
        }

        out = std::move(result);
        return true;
    }
}

#include "libOTe/Vole/LogVole/LogVoleCore.h"

#include "libOTe/Vole/LogVole/LogVoleArithmetic.h"
#include "libOTe/Vole/LogVole/LogVoleEncoding.h"
#include "libOTe/Vole/LogVole/LogVoleParallel.h"

#include "seal/util/rns.h"
#include "seal/util/uintarithsmallmod.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <limits>
#include <span>
#include <utility>

namespace osuCrypto::LogVole
{
    namespace
    {
        bool makeContext(const RingParams& ring, RingNttContext& ctx)
        {
            return makeRingNttContext(ring, ctx);
        }

        u64 pow2Mod(u64 exp, u64 mod)
        {
            const seal::Modulus modulus(mod);
            u64 result = 1;
            u64 base = 2 % mod;
            while (exp > 0)
            {
                if ((exp & 1) != 0)
                {
                    result = mulMod(result, base, modulus);
                }

                base = mulMod(base, base, modulus);
                exp >>= 1;
            }

            return result;
        }

        double safeLog2(double value)
        {
            return (value > 0.0) ? std::log2(value) : -std::numeric_limits<double>::infinity();
        }

        double log2Sum(double logX, double logY)
        {
            if (logX < logY)
            {
                std::swap(logX, logY);
            }

            const double diff = logX - logY;
            if (diff > 80.0)
            {
                return logX;
            }

            return logX + std::log2(1.0 + std::pow(2.0, -diff));
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
            out.mSbarOverLeakageNorm =
                threshold * sMultiplier / std::sqrt(sMultiplier * sMultiplier - 1.0);
            return out;
        }

        bool validatePlaintextTargetLimbLayout(const Params& params, std::size_t rho)
        {
            if (rho == 0)
            {
                return false;
            }

            const u32 mu = params.mShrinkExpand.mMu;
            return mu != 0 && (mu % static_cast<u32>(rho)) == 0;
        }

        bool resolvePlaintextTargetLimbForSampledPoly(
            const Params& params,
            std::size_t sampledPolyIdx,
            std::size_t rho,
            std::size_t& out)
        {
            if (!validatePlaintextTargetLimbLayout(params, rho))
            {
                return false;
            }

            const std::size_t rowIdx = sampledPolyIdx % static_cast<std::size_t>(params.mShrinkExpand.mMu);
            out = rowIdx % rho;
            return true;
        }

        double estimateReuseCountLog2(const Params& params)
        {
            const double n = static_cast<double>(params.mShrinkExpand.mRing.mPolyModulusDegree);
            const double mu = static_cast<double>(params.mShrinkExpand.mMu);
            if (!(n > 0.0) || !(mu > 0.0))
            {
                return -std::numeric_limits<double>::infinity();
            }

            const double log2TotalLabelCount =
                (params.mTotalLabelCount > 0)
                    ? safeLog2(static_cast<double>(params.mTotalLabelCount))
                    : (safeLog2(n) + safeLog2(static_cast<double>(params.mW)));
            const double log2OptimizerWidth = safeLog2(n) + safeLog2(mu);
            const double log2T = log2TotalLabelCount - log2OptimizerWidth;
            return (log2T > 0.0) ? log2T : 0.0;
        }

        double estimateNoiseBoundLog2(const Params& params)
        {
            constexpr double lambdaSec = 128.0;
            constexpr double sStar = 8.0;

            const double n = static_cast<double>(params.mShrinkExpand.mRing.mPolyModulusDegree);
            const double m = static_cast<double>(params.mShrinkExpand.mTau);
            const double mu = static_cast<double>(params.mShrinkExpand.mMu);
            const double logG = static_cast<double>(params.mShrinkExpand.mGadgetLogBase);
            if (!(n > 0.0) || !(m > 0.0) || !(mu > 0.0) || !(logG > 0.0))
            {
                return -std::numeric_limits<double>::infinity();
            }

            const double etaEpsR = etaEpsilonRing(n, lambdaSec);
            const double log2T = estimateReuseCountLog2(params);
            if (!std::isfinite(etaEpsR) || !std::isfinite(log2T))
            {
                return -std::numeric_limits<double>::infinity();
            }

            const double pathLen = (mu > 1.0) ? (std::ceil(std::log2(mu)) + 1.0) : 1.0;
            const double log2Mu = safeLog2(mu);
            const double log2Pref = 1.0 + 0.5 * safeLog2(lambdaSec);
            const double pref = 2.0 * std::sqrt(lambdaSec);
            const double sqrt2mT = std::sqrt(2.0 * m) * std::pow(2.0, 0.5 * log2T);
            double linearCoeff = pref * m * n * pathLen;
            if (params.mShrinkExpand.mTruncateOneGadgetDigit && params.mShrinkExpand.mMu > 0)
            {
                linearCoeff += n * (1.0 + log2Mu);
            }

            const double leakCoeff = pref * 2.0 * n * sqrt2mT;
            const LeakyLweNoiseShape noiseShape =
                computeLeakyLweNoiseShape(sStar, etaEpsR, linearCoeff, leakCoeff);
            if (!std::isfinite(noiseShape.mS) || !std::isfinite(noiseShape.mSbarOverLeakageNorm))
            {
                return -std::numeric_limits<double>::infinity();
            }

            const double log2TermA =
                logG + safeLog2(m) + safeLog2(n) + safeLog2(noiseShape.mS) + safeLog2(pathLen);
            const double log2Sbar =
                safeLog2(noiseShape.mSbarOverLeakageNorm) +
                logG +
                safeLog2(n) +
                0.5 * (safeLog2(2.0 * m) + log2T);
            const double log2TermB = 1.0 + log2Sbar;
            double log2B = log2Pref + log2Sum(log2TermA, log2TermB);

            if (params.mShrinkExpand.mTruncateOneGadgetDigit && params.mShrinkExpand.mMu > 0)
            {
                const double log2Trunc =
                    logG + safeLog2(n) + safeLog2(noiseShape.mS) + safeLog2(1.0 + safeLog2(mu));
                log2B = log2Sum(log2B, log2Trunc);
            }

            return log2B;
        }

        bool validateGoldenSeedSearchBudget(const Params& params, const RingNttContext& ctx)
        {
            const std::size_t rho = ctx.mModuli.size();
            if (!validatePlaintextTargetLimbLayout(params, rho))
            {
                return false;
            }

            const std::size_t n = params.mShrinkExpand.mRing.mPolyModulusDegree;
            const u32 mu = params.mShrinkExpand.mMu;
            const u64 wDoublePrime = static_cast<u64>((params.mW + mu - 1) / mu);
            const u64 sampledPolyCount = wDoublePrime * static_cast<u64>(mu);
            if (sampledPolyCount == 0)
            {
                return false;
            }

            const double log2B = estimateNoiseBoundLog2(params);
            const double log2SampledCoeffCount =
                safeLog2(static_cast<double>(n)) + safeLog2(static_cast<double>(sampledPolyCount));
            if (!std::isfinite(log2B) || !std::isfinite(log2SampledCoeffCount))
            {
                return false;
            }

            double minLog2DeltaJ = std::numeric_limits<double>::infinity();
            for (std::size_t j = 0; j < rho; ++j)
            {
                double log2DeltaJ = 0.0;
                for (std::size_t w = 0; w < rho; ++w)
                {
                    if (w != j)
                    {
                        log2DeltaJ += safeLog2(static_cast<double>(ctx.mModuli[w].value()));
                    }
                }

                if (!std::isfinite(log2DeltaJ) || log2B > (log2DeltaJ - 1.0))
                {
                    return false;
                }
                minLog2DeltaJ = std::min(minLog2DeltaJ, log2DeltaJ);
            }

            constexpr int maxSeedAttempts = 100;
            const double log2RetryBudget = safeLog2(std::log(static_cast<double>(maxSeedAttempts)));
            const double log2RetryExponent = 1.0 + log2B + log2SampledCoeffCount - minLog2DeltaJ;
            return std::isfinite(log2RetryExponent) && log2RetryExponent <= log2RetryBudget;
        }

        struct RoundingCheckConstants
        {
            std::size_t mTargetLimbIndex = 0;
            AlignedUnVec<std::size_t> mSrcLimbIndices;
            AlignedUnVec<u64> mCrtInvPunctured;
            AlignedUnVec<wideU64> mFracInvModulus;
            wideU64 mMargin{};
        };

        bool buildRoundingCheckConstants(
            const Params& params,
            const RingNttContext& ctx,
            std::vector<RoundingCheckConstants>& out)
        {
            auto contextData = ctx.mContext ? ctx.mContext->key_context_data() : nullptr;
            if (!contextData || !validateGoldenSeedSearchBudget(params, ctx))
            {
                return false;
            }

            const std::size_t rho = ctx.mModuli.size();
            auto pool = seal::MemoryManager::GetPool();
            seal::util::RNSBase fullBase(contextData->parms().coeff_modulus(), pool);
            const double log2B = estimateNoiseBoundLog2(params);
            if (!std::isfinite(log2B))
            {
                return false;
            }

            std::vector<RoundingCheckConstants> rounding(rho);
            for (std::size_t j = 0; j < rho; ++j)
            {
                auto& constants = rounding[j];
                constants.mTargetLimbIndex = j;
                constants.mSrcLimbIndices.resize((rho > 0) ? (rho - 1) : 0);
                std::size_t srcLimbIdx = 0;

                std::vector<seal::Modulus> baseExcludingJ;
                baseExcludingJ.reserve((rho > 0) ? (rho - 1) : 0);

                double log2DeltaJ = 0.0;
                for (std::size_t w = 0; w < rho; ++w)
                {
                    if (w == j)
                    {
                        continue;
                    }
                    constants.mSrcLimbIndices[srcLimbIdx++] = w;
                    baseExcludingJ.push_back(fullBase.base()[w]);
                    log2DeltaJ += safeLog2(static_cast<double>(fullBase.base()[w].value()));
                }

                if (!std::isfinite(log2DeltaJ) || log2B > (log2DeltaJ - 1.0))
                {
                    return false;
                }

                if (!baseExcludingJ.empty())
                {
                    seal::util::RNSBase reducedBase(baseExcludingJ, pool);
                    auto reducedInvPunct = reducedBase.inv_punctured_prod_mod_base_array();
                    const std::size_t reducedCount = constants.mSrcLimbIndices.size();
                    resizeZero(constants.mCrtInvPunctured, reducedCount);
                    resizeZero(constants.mFracInvModulus, reducedCount);

                    for (std::size_t idx = 0; idx < reducedCount; ++idx)
                    {
                        const std::size_t w = constants.mSrcLimbIndices[idx];
                        constants.mCrtInvPunctured[idx] = reducedInvPunct[idx].operand;
                        constants.mFracInvModulus[idx] = reciprocal2Pow128Wide(fullBase.base()[w].value());
                    }
                }

                const long double marginExp = static_cast<long double>(log2B - log2DeltaJ + 128.0);
                constants.mMargin = floorToWideU64(std::exp2(marginExp));
            }

            out = std::move(rounding);
            return true;
        }

        bool computeTauHi(const Params& params, u32& out)
        {
            if (params.mShrinkExpand.mTau < 2)
            {
                return false;
            }

            out = params.mShrinkExpand.mTau - 1;
            return true;
        }

        bool rootMetadataMatches(const ReceiverState& state, const RootOfflineMessage& message)
        {
            u32 tauHi = 0;
            if (!computeTauHi(state.mParams, tauHi))
            {
                return false;
            }

            const u32 rho = static_cast<u32>(state.mParams.mShrinkExpand.mRing.mCoeffModulusBits.size());
            return message.mRing == state.mParams.mShrinkExpand.mRing &&
                   message.mTauHi == tauHi &&
                   message.mGadgetLogBase == state.mParams.mShrinkExpand.mGadgetLogBase &&
                   message.mPlaintextModulusBits == state.mParams.mShrinkExpand.mPlaintextModulusBits &&
                   message.mLeftWidth == rootLeftWidth(tauHi, rho) &&
                   message.mRandomizerWidth == rootRandomizerWidth(state.mParams.mShrinkExpand);
        }

        RnsPoly makeZeroPoly(const RingParams& ring)
        {
            RnsPoly zero{};
            resizeZero(zero.mCoeffs, ringPolyCoeffCount(ring));
            return zero;
        }

        LencLacct toLencLacct(const ShrinkExpandLacct& in)
        {
            LencLacct out{};
            out.mWidthPadded = in.mWidthPadded;
            out.mLevels = in.mLevels;
            out.mCt = in.mCt;
            return out;
        }

        bool unpackSinglePoly(
            const RingParams& ring,
            std::span<const u64> coeffs,
            RnsPoly& out)
        {
            if (coeffs.size() != static_cast<std::size_t>(ringPolyCoeffCount(ring)))
            {
                return false;
            }

            assignRange(out.mCoeffs, coeffs.begin(), coeffs.end());
            return true;
        }

        bool sampleRootKPrime(const SenderState& state, PRNG& prng, RnsPoly& out)
        {
            RingNttContext ctx{};
            if (!makeContext(state.mParams.mShrinkExpand.mRing, ctx))
            {
                return false;
            }

            out = sampleUniformPoly(ctx, prng);
            return true;
        }

        bool denoiseAndAggRootKey(
            const RingNttContext& ctx,
            const std::vector<RnsPoly>& input,
            u32 tauHi,
            RnsPoly& out)
        {
            std::vector<RnsPoly> denoised;
            if (!shrinkExpandDenoiseComb(ctx, input, denoised))
            {
                return false;
            }

            std::vector<RnsPoly> aggregated;
            if (!seedLabelAgg(denoised, 1, tauHi, ctx.mParams, aggregated) ||
                aggregated.size() != 1)
            {
                return false;
            }

            out = std::move(aggregated[0]);
            return true;
        }

        bool computeMuHi(const Params& params, u32& out)
        {
            u32 tauHi = 0;
            if (!computeTauHi(params, tauHi))
            {
                return false;
            }

            const u32 rho = static_cast<u32>(params.mShrinkExpand.mRing.mCoeffModulusBits.size());
            if (rho == 0)
            {
                return false;
            }

            out = params.mShrinkExpand.mAlpha * tauHi * rho;
            return true;
        }

        u32 computeWDoublePrime(const Params& params, u32 muHi)
        {
            return (muHi == 0) ? 0 : ((params.mW + muHi - 1u) / muHi);
        }

        bool makeChildParams(const Params& params, Params& child)
        {
            u32 tauHi = 0;
            u32 muHi = 0;
            if (!computeTauHi(params, tauHi) || !computeMuHi(params, muHi))
            {
                return false;
            }

            const u32 rho = static_cast<u32>(params.mShrinkExpand.mRing.mCoeffModulusBits.size());
            const u32 wDoublePrime = computeWDoublePrime(params, muHi);
            if (rho == 0 || wDoublePrime == 0)
            {
                return false;
            }

            child = params;
            child.mW = wDoublePrime * tauHi * rho;
            child.mGamma = tauHi;
            return true;
        }

        u64 countSeedInstances(const SenderState& state)
        {
            u32 tauHi = 0;
            u32 muHi = 0;
            if (!computeTauHi(state.mParams, tauHi) || !computeMuHi(state.mParams, muHi))
            {
                return 0;
            }

            const u32 rho = static_cast<u32>(state.mParams.mShrinkExpand.mRing.mCoeffModulusBits.size());
            if (evalRecursiveMode(state.mParams.mW, state.mParams.mShrinkExpand.mAlpha, tauHi, rho) ==
                RecursiveMode::Root)
            {
                return 1;
            }

            if (!state.mNextLevelState)
            {
                return 0;
            }

            return countSeedInstances(*state.mNextLevelState) + computeWDoublePrime(state.mParams, muHi);
        }

        const RnsPoly* resolveRootMaskDigest(const SenderState& state)
        {
            if (state.mRootDPrimeRt)
            {
                return state.mRootDPrimeRt.get();
            }

            return state.mNextLevelState ? resolveRootMaskDigest(*state.mNextLevelState) : nullptr;
        }

        const RnsPoly* resolveRootMaskDigest(const ReceiverState& state)
        {
            if (state.mRootDPrimeRt)
            {
                return state.mRootDPrimeRt.get();
            }

            return state.mNextLevelState ? resolveRootMaskDigest(*state.mNextLevelState) : nullptr;
        }

        struct RecursiveSeedEvalOutput
        {
            bool mValid = false;
            std::vector<RnsPoly> mTbk;
        };

        bool ensureSenderPrecomputeImpl(
            const SenderState& state,
            PRNG& prng);

        Params makeSeedParams(const Params& params, const ShrinkExpandParams& seParams)
        {
            Params seedParams = params;
            seedParams.mShrinkExpand = seParams;
            return seedParams;
        }

        void applySessionId(SenderState& state, u64 sid)
        {
            state.mParams.mSessionId = sid;
            if (state.mNextLevelState)
            {
                applySessionId(*state.mNextLevelState, sid);
            }
        }

        void applySessionId(ReceiverState& state, u64 sid)
        {
            state.mParams.mSessionId = sid;
            if (state.mNextLevelState)
            {
                applySessionId(*state.mNextLevelState, sid);
            }
        }

        bool evalRootTopCtNtt(
            const ReceiverState& state,
            const RingNttContext& ctx,
            const RnsPoly& yLeft,
            const std::vector<RnsPoly>& zeta,
            std::vector<RnsPoly>& out)
        {
            u32 tauHi = 0;
            if (!computeTauHi(state.mParams, tauHi) ||
                state.mRootTopCt.mRows == 0 ||
                state.mRootTopCt.mCols != tauHi + state.mRootRandomizerWidth ||
                zeta.size() != state.mRootRandomizerWidth ||
                !validateRingBatchShape(state.mRootTopCt.mPolys, ctx.mParams))
            {
                return false;
            }

            std::vector<RnsPoly> yDecomp;
            if (!gadgetDecomposeBitsRangeCentered(
                    yLeft,
                    state.mParams.mShrinkExpand.mGadgetLogBase,
                    1,
                    tauHi,
                    ctx,
                    yDecomp,
                    state.mShrinkExpandState.mParams.mNumWorkerThreads))
            {
                return false;
            }

            std::vector<RnsPoly> inputs(yDecomp.size() + zeta.size());
            for (std::size_t idx = 0; idx < yDecomp.size(); ++idx)
            {
                inputs[idx] = std::move(yDecomp[idx]);
            }
            for (std::size_t idx = 0; idx < zeta.size(); ++idx)
            {
                inputs[yDecomp.size() + idx] = zeta[idx];
            }
            for (auto& poly : inputs)
            {
                if (!forwardNtt(poly, ctx))
                {
                    return false;
                }
            }

            std::vector<RnsPoly> next(state.mRootTopCt.mRows);
            for (u32 row = 0; row < state.mRootTopCt.mRows; ++row)
            {
                RnsPoly acc{};
                resizeZero(acc.mCoeffs, ringPolyCoeffCount(ctx.mParams));
                for (u32 col = 0; col < state.mRootTopCt.mCols; ++col)
                {
                    const auto& ctPoly = state.mRootTopCt.mPolys[ringTensorIndex(state.mRootTopCt, row, col)];
                    if (!dyadicMultiplyAddNttInplace(ctPoly, inputs[col], acc, ctx))
                    {
                        return false;
                    }
                }
                next[row] = std::move(acc);
            }

            out = std::move(next);
            return true;
        }
    }

    u32 rootRandomizerWidth(const ShrinkExpandParams& params)
    {
        constexpr u32 statSec = 40;
        const double n = static_cast<double>(params.mRing.mPolyModulusDegree);
        const double gadgetBits = static_cast<double>(params.mGadgetLogBase);
        if (!(n > 1.0) || !(gadgetBits > 0.0))
        {
            return 0;
        }

        const double requiredSlack =
            (2.0 * static_cast<double>(statSec) + std::ceil(std::log2(n)) + 1.0) / gadgetBits;
        const u32 slack = std::max<u32>(1, static_cast<u32>(std::ceil(requiredSlack)));
        return params.mTau + slack;
    }

    u32 rootLeftWidth(u32 tauHi, u32 rho)
    {
        return tauHi * rho;
    }

    double rootNoiseSigma(const ShrinkExpandParams& params, double factor)
    {
#ifdef LIBOTE_LOGVOLE_ENABLE_INSECURE_NOISELESS
        if (params.mMode != ShrinkExpandMode::FullNoise)
        {
            return 0.0;
        }
#else
        (void)params;
#endif

        constexpr double stdS = 3.19;
        return stdS * ((factor > 1.0) ? factor : 1.0);
    }

    double rootNoiseMaxDeviation(double sigma)
    {
        constexpr double lambda = 128.0;
        return (sigma > 0.0) ? (std::sqrt(lambda) * sigma) : 0.0;
    }

    SeedLabelMode evalSeedLabelMode(u32 w, u32 alpha, u32 tau, u32 rho)
    {
        (void)alpha;
        return (w <= tau * rho) ? SeedLabelMode::Leaf : SeedLabelMode::Internal;
    }

    RecursiveMode evalRecursiveMode(u32 w, u32 alpha, u32 tau, u32 rho)
    {
        return (w <= alpha * tau * rho) ? RecursiveMode::Root : RecursiveMode::Internal;
    }

    bool makeTruncShrinkExpandParams(
        const Params& params,
        bool leafInputsAreGadget,
        ShrinkExpandParams& out)
    {
        if (params.mShrinkExpand.mTau < 2 || params.mShrinkExpand.mAlpha == 0 ||
            params.mShrinkExpand.mRing.mCoeffModulusBits.empty())
        {
            return false;
        }

        const u32 tauHi = params.mShrinkExpand.mTau - 1;
        const u32 rho = static_cast<u32>(params.mShrinkExpand.mRing.mCoeffModulusBits.size());
        ShrinkExpandParams next = params.mShrinkExpand;
        next.mTau = tauHi;
        next.mMu = next.mAlpha * tauHi * rho;
        next.mTruncateOneGadgetDigit = true;
        next.mLeafInputsAreGadget = leafInputsAreGadget;
        out = std::move(next);
        return true;
    }

    bool replicateRootHiKeyByLimb(
        const std::vector<RnsPoly>& skHi,
        u32 tauHi,
        const RingParams& ring,
        std::vector<RnsPoly>& out)
    {
        if (tauHi == 0 || skHi.size() != tauHi || ring.mCoeffModulusBits.empty() ||
            !validateRingBatchShape(skHi, ring))
        {
            return false;
        }

        const std::size_t rho = ring.mCoeffModulusBits.size();
        std::vector<RnsPoly> next(static_cast<std::size_t>(tauHi) * rho);
        std::size_t outIdx = 0;
        for (u32 digit = 0; digit < tauHi; ++digit)
        {
            for (std::size_t limb = 0; limb < rho; ++limb)
            {
                (void)limb;
                next[outIdx++] = skHi[digit];
            }
        }

        out = std::move(next);
        return true;
    }

    bool sampleRootErrorBatch(
        const RingNttContext& ctx,
        u32 count,
        PRNG& prng,
        double sigma,
        double maxDeviation,
        bool outputNtt,
        std::vector<RnsPoly>& out)
    {
        if (count == 0 || sigma < 0.0 || maxDeviation < 0.0)
        {
            return false;
        }

        std::vector<RnsPoly> next(count);
        for (u32 idx = 0; idx < count; ++idx)
        {
            RnsPoly poly{};
            resizeZero(poly.mCoeffs, ringPolyCoeffCount(ctx.mParams));
            if (sigma > 0.0)
            {
                if (!addPolyError(poly, sigma, maxDeviation, prng, ctx))
                {
                    return false;
                }
            }

            if (outputNtt && !forwardNtt(poly, ctx))
            {
                return false;
            }

            next[idx] = std::move(poly);
        }

        out = std::move(next);
        return true;
    }

    bool addScaledNttInplace(
        RnsPoly& accNtt,
        const RnsPoly& polyNtt,
        u32 gadgetLogBase,
        u32 power,
        const RingNttContext& ctx,
        bool subtract)
    {
        if (!validateRingPolyShape(accNtt, ctx.mParams) ||
            !validateRingPolyShape(polyNtt, ctx.mParams))
        {
            return false;
        }

        const u64 shift = static_cast<u64>(gadgetLogBase) * power;
        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        for (std::size_t modIdx = 0; modIdx < ctx.mModuli.size(); ++modIdx)
        {
            const auto& modulus = ctx.mModuli[modIdx];
            const u64 mod = modulus.value();
            const u64 factor = pow2Mod(shift, mod);
            const std::size_t offset = modIdx * n;
            for (std::size_t coeffIdx = 0; coeffIdx < n; ++coeffIdx)
            {
                const std::size_t idx = offset + coeffIdx;
                const u64 scaled = seal::util::multiply_uint_mod(polyNtt.mCoeffs[idx], factor, modulus);
                if (subtract)
                {
                    accNtt.mCoeffs[idx] = (accNtt.mCoeffs[idx] >= scaled)
                                               ? (accNtt.mCoeffs[idx] - scaled)
                                               : (accNtt.mCoeffs[idx] + mod - scaled);
                }
                else
                {
                    u64 sum = accNtt.mCoeffs[idx] + scaled;
                    if (sum >= mod)
                    {
                        sum -= mod;
                    }
                    accNtt.mCoeffs[idx] = sum;
                }
            }
        }

        return true;
    }

    bool negateNttInplace(RnsPoly& polyNtt, const RingNttContext& ctx)
    {
        if (!validateRingPolyShape(polyNtt, ctx.mParams))
        {
            return false;
        }

        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        for (std::size_t modIdx = 0; modIdx < ctx.mModuli.size(); ++modIdx)
        {
            const u64 mod = ctx.mModuli[modIdx].value();
            const std::size_t offset = modIdx * n;
            for (std::size_t coeffIdx = 0; coeffIdx < n; ++coeffIdx)
            {
                const std::size_t idx = offset + coeffIdx;
                if (polyNtt.mCoeffs[idx] != 0)
                {
                    polyNtt.mCoeffs[idx] = mod - polyNtt.mCoeffs[idx];
                }
            }
        }

        return true;
    }

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
        RingTensor& out)
    {
        const u32 leftWidth = static_cast<u32>(r1.size());
        const u32 tauHi = static_cast<u32>(publicBRootNtt.size());
        const u32 randomizer = static_cast<u32>(publicBStarNtt.size());
        if (leftWidth == 0 || r2Ntt.size() != leftWidth || tauHi == 0 || randomizer == 0 ||
            !validateRingBatchShape(r1, ctx.mParams) ||
            !validateRingBatchShape(r2Ntt, ctx.mParams) ||
            !validateRingBatchShape(publicBRootNtt, ctx.mParams) ||
            !validateRingBatchShape(publicBStarNtt, ctx.mParams))
        {
            return false;
        }

        std::vector<RnsPoly> r1Ntt = r1;
        for (auto& poly : r1Ntt)
        {
            if (!forwardNtt(poly, ctx))
            {
                return false;
            }
        }

        RingTensor next{};
        next.mRows = leftWidth;
        next.mCols = tauHi + randomizer;
        next.mPolys.resize(ringTensorSize(next));

        for (u32 row = 0; row < leftWidth; ++row)
        {
            for (u32 col = 0; col < next.mCols; ++col)
            {
                const RnsPoly& bNtt = (col < tauHi) ? publicBRootNtt[col] : publicBStarNtt[col - tauHi];
                RnsPoly cellNtt{};
                resizeZero(cellNtt.mCoeffs, ringPolyCoeffCount(ctx.mParams));
                if (!dyadicMultiplyAddNttInplace(r1Ntt[row], bNtt, cellNtt, ctx) ||
                    !negateNttInplace(cellNtt, ctx))
                {
                    return false;
                }

                if (col < tauHi &&
                    !addScaledNttInplace(cellNtt, r2Ntt[row], gadgetLogBase, gadgetPowerOffset + col, ctx, true))
                {
                    return false;
                }

                if (noiseStandardDeviation > 0.0)
                {
                    RnsPoly noise{};
                    resizeZero(noise.mCoeffs, ringPolyCoeffCount(ctx.mParams));
                    if (!addPolyError(noise, noiseStandardDeviation, noiseMaxDeviation, prng, ctx) ||
                        !forwardNtt(noise, ctx) ||
                        !ringAddInplace(cellNtt, noise, ctx))
                    {
                        return false;
                    }
                }

                next.mPolys[ringTensorIndex(next, row, col)] = std::move(cellNtt);
            }
        }

        out = std::move(next);
        return true;
    }

    bool sampleRootZeta(
        const RingNttContext& ctx,
        u32 randomizerWidth,
        u32 gadgetLogBase,
        PRNG& prng,
        std::vector<RnsPoly>& out)
    {
        if (randomizerWidth == 0 || gadgetLogBase == 0 || gadgetLogBase > 127)
        {
            return false;
        }

        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        const std::size_t rho = ctx.mModuli.size();
        const wideU64 eta = wideU64Sub(wideU64OneShift(gadgetLogBase), makeWideU64(1, 0));
        const u32 sampleBits = gadgetLogBase + 1;
        const wideU64 sampleMask = wideU64Mask(sampleBits);

        std::vector<RnsPoly> zeta(randomizerWidth);
        for (u32 polyIdx = 0; polyIdx < randomizerWidth; ++polyIdx)
        {
            RnsPoly poly{};
            resizeZero(poly.mCoeffs, n * rho);
            for (std::size_t coeffIdx = 0; coeffIdx < n; ++coeffIdx)
            {
                wideU64 raw{};
                do
                {
                    const u64 lo = prng.get<u64>();
                    const u64 hi = prng.get<u64>();
                    raw = wideU64And(makeWideU64(lo, hi), sampleMask);
                } while (wideU64Equal(raw, sampleMask));

                const bool negative = wideU64LessEq(raw, eta);
                const wideU64 magnitude = negative ? wideU64Sub(eta, raw) : wideU64Sub(raw, eta);
                for (std::size_t modIdx = 0; modIdx < rho; ++modIdx)
                {
                    const std::size_t outIdx = modIdx * n + coeffIdx;
                    const u64 mod = ctx.mModuli[modIdx].value();
                    const u64 reduced = wideU64Mod(magnitude, ctx.mModuli[modIdx]);
                    poly.mCoeffs[outIdx] = (negative && reduced != 0) ? (mod - reduced) : reduced;
                }
            }

            zeta[polyIdx] = std::move(poly);
        }

        out = std::move(zeta);
        return true;
    }

    bool rootInnerProductNtt(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& leftNtt,
        const std::vector<RnsPoly>& rightCoeff,
        RnsPoly& out)
    {
        if (leftNtt.size() != rightCoeff.size() || leftNtt.empty() ||
            !validateRingBatchShape(leftNtt, ctx.mParams) ||
            !validateRingBatchShape(rightCoeff, ctx.mParams))
        {
            return false;
        }

        std::vector<RnsPoly> rightNtt = rightCoeff;
        for (auto& poly : rightNtt)
        {
            if (!forwardNtt(poly, ctx))
            {
                return false;
            }
        }

        RnsPoly accNtt{};
        resizeZero(accNtt.mCoeffs, ringPolyCoeffCount(ctx.mParams));
        for (std::size_t idx = 0; idx < leftNtt.size(); ++idx)
        {
            if (!dyadicMultiplyAddNttInplace(leftNtt[idx], rightNtt[idx], accNtt, ctx))
            {
                return false;
            }
        }

        if (!inverseNtt(accNtt, ctx))
        {
            return false;
        }

        out = std::move(accNtt);
        return true;
    }

    bool prepareRootOfflineSender(
        SenderState& state,
        PRNG& prng,
        RootOfflineMessage& message)
    {
        u32 tauHi = 0;
        if (!computeTauHi(state.mParams, tauHi))
        {
            return false;
        }

        const u32 tauFull = tauHi + 1;
        const auto& se = state.mParams.mShrinkExpand;
        const u32 rho = static_cast<u32>(se.mRing.mCoeffModulusBits.size());
        const u32 leftWidth = rootLeftWidth(tauHi, rho);
        const u32 randomizer = rootRandomizerWidth(se);
        const u32 workerThreads = state.mShrinkExpandState.mParams.mNumWorkerThreads;

        if (rho == 0 ||
            state.mShrinkExpandState.mSk1.size() != tauHi ||
            !validateRingBatchShape(state.mShrinkExpandState.mSk1, se.mRing))
        {
            return false;
        }

        RingNttContext ctx{};
        if (!makeContext(se.mRing, ctx))
        {
            return false;
        }

        std::vector<RnsPoly> rootSkHi;
        if (!replicateRootHiKeyByLimb(state.mShrinkExpandState.mSk1, tauHi, se.mRing, rootSkHi) ||
            rootSkHi.size() != leftWidth)
        {
            return false;
        }

        const auto publicBFullNtt = buildLencPublicBNtt(ctx, tauFull);
        if (publicBFullNtt.size() < static_cast<std::size_t>(2) * tauFull)
        {
            return false;
        }

        std::vector<RnsPoly> publicBRootNtt(tauHi);
        for (u32 idx = 0; idx < tauHi; ++idx)
        {
            publicBRootNtt[idx] = publicBFullNtt[1 + idx];
        }

        const double lencSigma = rootNoiseSigma(se, std::sqrt(static_cast<double>(tauHi)));
        const double lencMaxDev = rootNoiseMaxDeviation(lencSigma);
        LencEncodeOutput leftLenc{};
        if (!lencEncTrunc(
                ctx,
                rootSkHi,
                tauHi,
                se.mGadgetLogBase,
                se.mPlaintextModulusBits,
                prng,
                leftLenc,
                lencSigma,
                lencMaxDev,
                0,
                false,
                true,
                &publicBFullNtt,
                workerThreads))
        {
            return false;
        }

        std::vector<RnsPoly> publicBStarNtt(randomizer);
        for (u32 idx = 0; idx < randomizer; ++idx)
        {
            publicBStarNtt[idx] = deriveUniformPolyFromNonceNtt(ctx, 0x52544E43524F4F54ull, 0xB57A52u, idx);
        }

        std::vector<RnsPoly> r1;
        if (!sampleRootErrorBatch(
                ctx,
                leftWidth,
                prng,
                lencSigma,
                lencMaxDev,
                false,
                r1))
        {
            return false;
        }

        std::vector<RnsPoly> skRRt = sampleUniformBatch(ctx, tauHi, prng);
        if (!validateRingBatchShape(skRRt, se.mRing))
        {
            return false;
        }

        const double lheSigma =
            rootNoiseSigma(se, std::sqrt(static_cast<double>(leftLenc.mLacct.mWidthPadded)));
        const double lheMaxDev = rootNoiseMaxDeviation(lheSigma);
        RingTensor ctR{};
        if (!lheEnc1Trunc(
                ctx,
                r1,
                skRRt,
                se.mGadgetLogBase,
                ctR,
                lheSigma,
                lheMaxDev,
                &prng,
                false,
                nullptr,
                workerThreads))
        {
            return false;
        }

        RingTensor topCt{};
        if (!buildRootTopCt(
                ctx,
                r1,
                leftLenc.mRNtt,
                publicBRootNtt,
                publicBStarNtt,
                se.mGadgetLogBase,
                1,
                prng,
                lencSigma,
                lencMaxDev,
                topCt))
        {
            return false;
        }

        state.mRootSkRRt = std::move(skRRt);
        state.mRootR1Rt = std::move(r1);
        state.mRootRandomizerWidth = randomizer;

        RootOfflineMessage next{};
        next.mRing = se.mRing;
        next.mTauHi = tauHi;
        next.mGadgetLogBase = se.mGadgetLogBase;
        next.mPlaintextModulusBits = se.mPlaintextModulusBits;
        next.mLeftWidth = leftWidth;
        next.mRandomizerWidth = randomizer;
        next.mCtR = std::move(ctR);
        next.mLacctLeft.mWidthPadded = leftLenc.mLacct.mWidthPadded;
        next.mLacctLeft.mLevels = leftLenc.mLacct.mLevels;
        next.mLacctLeft.mCt = std::move(leftLenc.mLacct.mCt);
        next.mTopCt = std::move(topCt);
        next.mPublicBStarNtt = std::move(publicBStarNtt);
        message = std::move(next);
        return true;
    }

    bool finalizeRootOfflineReceiver(
        ReceiverState& state,
        const RootOfflineMessage& message)
    {
        u32 tauHi = 0;
        if (!computeTauHi(state.mParams, tauHi) ||
            !rootMetadataMatches(state, message))
        {
            return false;
        }

        const u32 rho = static_cast<u32>(state.mParams.mShrinkExpand.mRing.mCoeffModulusBits.size());
        const u32 leftWidth = rootLeftWidth(tauHi, rho);
        const u32 randomizer = rootRandomizerWidth(state.mParams.mShrinkExpand);

        if (rho == 0 ||
            message.mCtR.mRows != leftWidth ||
            message.mCtR.mCols != tauHi ||
            ringTensorSize(message.mCtR) != message.mCtR.mPolys.size() ||
            !validateRingBatchShape(message.mCtR.mPolys, message.mRing) ||
            message.mLacctLeft.mWidthPadded == 0 ||
            (message.mLacctLeft.mWidthPadded & (message.mLacctLeft.mWidthPadded - 1)) != 0 ||
            message.mLacctLeft.mCt.mRows != message.mLacctLeft.mWidthPadded * message.mLacctLeft.mLevels ||
            ringTensorSize(message.mLacctLeft.mCt) != message.mLacctLeft.mCt.mPolys.size() ||
            !validateRingBatchShape(message.mLacctLeft.mCt.mPolys, message.mRing) ||
            message.mTopCt.mRows != leftWidth ||
            message.mTopCt.mCols != tauHi + randomizer ||
            ringTensorSize(message.mTopCt) != message.mTopCt.mPolys.size() ||
            !validateRingBatchShape(message.mTopCt.mPolys, message.mRing) ||
            message.mPublicBStarNtt.size() != randomizer ||
            !validateRingBatchShape(message.mPublicBStarNtt, message.mRing))
        {
            return false;
        }

        RingNttContext ctx{};
        if (!makeContext(message.mRing, ctx))
        {
            return false;
        }

        RingTensor ctR = message.mCtR;
        for (auto& poly : ctR.mPolys)
        {
            if (!forwardNtt(poly, ctx))
            {
                return false;
            }
        }

        state.mRootCtRRt = std::move(ctR);
        state.mRootLacctLeft = message.mLacctLeft;
        state.mRootTopCt = message.mTopCt;
        state.mRootPublicBStarNtt = message.mPublicBStarNtt;
        state.mRootRandomizerWidth = randomizer;
        return true;
    }

    bool prepareRootDigestReceiver(
        const ReceiverState& state,
        const std::vector<RnsPoly>& x,
        PRNG& prng,
        RootDigestState& digestState,
        RootDigestMessage& message)
    {
        u32 tauHi = 0;
        if (!computeTauHi(state.mParams, tauHi))
        {
            return false;
        }

        const u32 tauFull = tauHi + 1;
        const u32 rho = static_cast<u32>(state.mParams.mShrinkExpand.mRing.mCoeffModulusBits.size());
        const u32 muHi = state.mParams.mShrinkExpand.mAlpha * tauHi * rho;
        if (rho == 0 ||
            state.mParams.mW != muHi ||
            x.size() > muHi ||
            state.mRootRandomizerWidth != rootRandomizerWidth(state.mParams.mShrinkExpand))
        {
            return false;
        }

        RingNttContext ctx{};
        if (!makeContext(state.mParams.mShrinkExpand.mRing, ctx))
        {
            return false;
        }

        std::vector<RnsPoly> xRoot(muHi);
        for (std::size_t idx = 0; idx < x.size(); ++idx)
        {
            xRoot[idx] = x[idx];
        }
        for (std::size_t idx = x.size(); idx < xRoot.size(); ++idx)
        {
            xRoot[idx] = makeZeroPoly(state.mParams.mShrinkExpand.mRing);
        }

        ShrinkExpandShrinkOutput shrink{};
        if (!shrinkExpandShrink(state.mShrinkExpandState, xRoot, shrink))
        {
            return false;
        }

        std::vector<RnsPoly> hatD;
        if (!seedLabelGadgetDecomposeHiAndUnbundle(
                shrink.mDigest,
                state.mParams.mShrinkExpand.mGadgetLogBase,
                tauHi,
                state.mParams.mShrinkExpand.mRing,
                hatD))
        {
            return false;
        }

        const u32 leftWidth = rootLeftWidth(tauHi, rho);
        if (hatD.size() != leftWidth)
        {
            return false;
        }

        RnsPoly yLeft{};
        if (!lencDigestTrunc(
                ctx,
                hatD,
                tauHi,
                state.mParams.mShrinkExpand.mGadgetLogBase,
                state.mParams.mShrinkExpand.mPlaintextModulusBits,
                yLeft,
                state.mRootLacctLeft.mWidthPadded,
                true))
        {
            return false;
        }

        std::vector<RnsPoly> yDecomp;
        if (!gadgetDecomposeBitsRangeCentered(
                yLeft,
                state.mParams.mShrinkExpand.mGadgetLogBase,
                1,
                tauHi,
                ctx,
                yDecomp,
                state.mShrinkExpandState.mParams.mNumWorkerThreads))
        {
            return false;
        }

        const auto publicBFullNtt = buildLencPublicBNtt(ctx, tauFull);
        if (publicBFullNtt.size() < static_cast<std::size_t>(2) * tauFull)
        {
            return false;
        }

        std::vector<RnsPoly> publicBRootNtt(tauHi);
        for (u32 idx = 0; idx < tauHi; ++idx)
        {
            publicBRootNtt[idx] = publicBFullNtt[1 + idx];
        }

        RnsPoly leftTerm{};
        if (!rootInnerProductNtt(ctx, publicBRootNtt, yDecomp, leftTerm))
        {
            return false;
        }

        std::vector<RnsPoly> zeta;
        if (!sampleRootZeta(
                ctx,
                state.mRootRandomizerWidth,
                state.mParams.mShrinkExpand.mGadgetLogBase,
                prng,
                zeta))
        {
            return false;
        }

        RnsPoly rightTerm{};
        if (!rootInnerProductNtt(ctx, state.mRootPublicBStarNtt, zeta, rightTerm))
        {
            return false;
        }

        RnsPoly dPrime{};
        RnsPoly negDPrime{};
        RnsPoly zero = makeZeroPoly(state.mParams.mShrinkExpand.mRing);
        if (!ringAdd(leftTerm, rightTerm, ctx, dPrime) ||
            !ringSub(zero, dPrime, ctx, negDPrime))
        {
            return false;
        }

        RootDigestState nextState{};
        nextState.mDRt = std::move(shrink.mDigest);
        nextState.mRootTree = std::move(shrink.mTree);
        nextState.mHatDRt = std::move(hatD);
        nextState.mYLeft = std::move(yLeft);
        nextState.mZeta = std::move(zeta);
        nextState.mDPrime = std::move(negDPrime);

        RootDigestMessage nextMessage{};
        assignRange(nextMessage.mDPrimeCoeffs, nextState.mDPrime.mCoeffs.begin(), nextState.mDPrime.mCoeffs.end());

        digestState = std::move(nextState);
        message = std::move(nextMessage);
        return true;
    }

    bool prepareRootResponseSender(
        const SenderState& state,
        const RootDigestMessage& request,
        PRNG& prng,
        RootResponseMessage& response,
        const SenderState* precomputeRoot)
    {
        u32 tauHi = 0;
        if (!computeTauHi(state.mParams, tauHi) ||
            state.mRootSkRRt.size() != tauHi ||
            !validateRingBatchShape(state.mRootSkRRt, state.mParams.mShrinkExpand.mRing))
        {
            return false;
        }

        RingNttContext ctx{};
        if (!makeContext(state.mParams.mShrinkExpand.mRing, ctx))
        {
            return false;
        }

        RnsPoly dPrime{};
        RnsPoly kPrime{};
        RnsPoly skPrime{};
        if (!unpackSinglePoly(state.mParams.mShrinkExpand.mRing, request.mDPrimeCoeffs, dPrime) ||
            !sampleRootKPrime(state, prng, kPrime) ||
            !deriveSkxTrunc(
                ctx,
                state.mRootSkRRt,
                dPrime,
                kPrime,
                state.mParams.mShrinkExpand.mGadgetLogBase,
                tauHi,
                skPrime))
        {
            return false;
        }

        state.mRootKPrimeRt = std::make_shared<RnsPoly>(kPrime);
        state.mRootDPrimeRt = std::make_shared<RnsPoly>(dPrime);

        const SenderState& precomputeState = precomputeRoot ? *precomputeRoot : state;
        if (!ensureSenderPrecomputeImpl(precomputeState, prng) ||
            state.mGoldenSeed.empty())
        {
            return false;
        }

        RootResponseMessage next{};
        assignRange(next.mSeed, state.mGoldenSeed.begin(), state.mGoldenSeed.end());
        assignRange(next.mSkPrimeCoeffs, skPrime.mCoeffs.begin(), skPrime.mCoeffs.end());
        response = std::move(next);
        return true;
    }

    bool computeRootSenderKey(
        const SenderState& state,
        std::span<const u8> seed,
        RnsPoly& rootKey)
    {
        u32 tauHi = 0;
        if (!computeTauHi(state.mParams, tauHi) ||
            seed.empty())
        {
            return false;
        }

        const u32 rho = static_cast<u32>(state.mParams.mShrinkExpand.mRing.mCoeffModulusBits.size());
        const u32 leftWidth = rootLeftWidth(tauHi, rho);
        RingNttContext ctx{};
        if (rho == 0 ||
            !makeContext(state.mParams.mShrinkExpand.mRing, ctx))
        {
            return false;
        }

        std::vector<RnsPoly> ctK;
        std::vector<RnsPoly> tbkRt;
        if (!state.mRootKPrimeRt || !state.mRootDPrimeRt)
        {
            return false;
        }
        if (
            !buildHashedCt2(
                ctx,
                leftWidth,
                seed,
                state.mParams.mSessionId,
                *state.mRootDPrimeRt,
                0,
                ctK) ||
            !lheDec(
                ctx,
                ctK,
                *state.mRootKPrimeRt,
                tbkRt,
                nullptr,
                false,
                false,
                state.mShrinkExpandState.mParams.mNumWorkerThreads))
        {
            return false;
        }

        return denoiseAndAggRootKey(ctx, tbkRt, tauHi, rootKey);
    }

    namespace
    {
        bool evaluateSenderSeedCandidate(
            const SenderState& state,
            std::span<const u8> seed,
            RecursiveSeedEvalOutput& out)
        {
            u32 tauHi = 0;
            u32 muHi = 0;
            if (!computeTauHi(state.mParams, tauHi) ||
                !computeMuHi(state.mParams, muHi) ||
                seed.empty())
            {
                return false;
            }

            const u32 alpha = state.mParams.mShrinkExpand.mAlpha;
            const u32 rho = static_cast<u32>(state.mParams.mShrinkExpand.mRing.mCoeffModulusBits.size());
            if (rho == 0)
            {
                return false;
            }

            const RecursiveMode mode =
                evalRecursiveMode(state.mParams.mW, alpha, tauHi, rho);
            if (mode == RecursiveMode::Root)
            {
                if (state.mParams.mW != muHi ||
                    !state.mRootKPrimeRt ||
                    !state.mRootDPrimeRt)
                {
                    return false;
                }

                RnsPoly rootKey{};
                if (!computeRootSenderKey(state, seed, rootKey))
                {
                    return false;
                }

                ShrinkExpandExpandSenderInput expandInput{};
                assignRange(expandInput.mSeed, seed.begin(), seed.end());
                expandInput.mSid = state.mParams.mSessionId;
                expandInput.mDigest = *state.mRootDPrimeRt;
                expandInput.mMaskDigest = *state.mRootDPrimeRt;
                expandInput.mTbkPrime = rootKey;

                ShrinkExpandSenderExpandOutput expandOutput{};
                const Params seedParams = makeSeedParams(state.mParams, state.mShrinkExpandState.mParams);
                bool candidateOk = false;
                if (!shrinkExpandExpandSender(state.mShrinkExpandState, expandInput, expandOutput) ||
                    !validateGoldenSeedCandidate(seedParams, expandOutput.mTbk, candidateOk))
                {
                    return false;
                }

                RecursiveSeedEvalOutput next{};
                if (!candidateOk)
                {
                    out = std::move(next);
                    return true;
                }

                state.mGoldenSeed = expandInput.mSeed;
                next.mValid = true;
                next.mTbk = std::move(expandOutput.mTbk);
                out = std::move(next);
                return true;
            }

            if (!state.mNextLevelState)
            {
                return false;
            }

            RecursiveSeedEvalOutput childEval{};
            if (!evaluateSenderSeedCandidate(*state.mNextLevelState, seed, childEval))
            {
                return false;
            }
            if (!childEval.mValid)
            {
                out = RecursiveSeedEvalOutput{};
                return true;
            }

            const u32 wPrime =
                (state.mParams.mW + state.mParams.mShrinkExpand.mAlpha - 1u) /
                state.mParams.mShrinkExpand.mAlpha;
            const u32 wDoublePrime = computeWDoublePrime(state.mParams, muHi);
            const RnsPoly* rootMaskDigest = resolveRootMaskDigest(state);
            if (wDoublePrime == 0 || rootMaskDigest == nullptr)
            {
                return false;
            }

            std::vector<RnsPoly> kPrimeHat;
            std::vector<RnsPoly> kPrime;
            if (!seedLabelDenoiseTbm(
                    childEval.mTbk,
                    wPrime,
                    tauHi,
                    state.mParams.mShrinkExpand.mRing,
                    kPrimeHat) ||
                !seedLabelAgg(
                    kPrimeHat,
                    wDoublePrime,
                    tauHi,
                    state.mParams.mShrinkExpand.mRing,
                    kPrime) ||
                kPrime.size() != wDoublePrime)
            {
                return false;
            }

            const u64 instanceBase = countSeedInstances(*state.mNextLevelState);
            std::vector<RnsPoly> finalTbk(state.mParams.mW);
            std::vector<RnsPoly> sampledTbk(static_cast<std::size_t>(wDoublePrime) * muHi);
            if (!detail::runParallelTasks(
                    wDoublePrime,
                    state.mShrinkExpandState.mParams.mNumWorkerThreads,
                    [&](std::size_t taskIdx) {
                        const auto chunkIdx = static_cast<u32>(taskIdx);
                        const std::size_t start = static_cast<std::size_t>(chunkIdx) * muHi;
                        const std::size_t end =
                            std::min(start + static_cast<std::size_t>(muHi), static_cast<std::size_t>(state.mParams.mW));

                        ShrinkExpandExpandSenderInput expandInput{};
                        assignRange(expandInput.mSeed, seed.begin(), seed.end());
                        expandInput.mSid = state.mParams.mSessionId;
                        expandInput.mNonce = instanceBase + chunkIdx;
                        expandInput.mDigest = *rootMaskDigest;
                        expandInput.mMaskDigest = *rootMaskDigest;
                        expandInput.mTbkPrime = kPrime[chunkIdx];

                        ShrinkExpandSenderExpandOutput expandOutput{};
                        if (!shrinkExpandExpandSender(state.mShrinkExpandState, expandInput, expandOutput) ||
                            expandOutput.mTbk.size() != muHi)
                        {
                            return false;
                        }

                        const std::size_t sampledStart = static_cast<std::size_t>(chunkIdx) * muHi;
                        for (std::size_t idx = 0; idx < expandOutput.mTbk.size(); ++idx)
                        {
                            sampledTbk[sampledStart + idx] = expandOutput.mTbk[idx];
                        }

                        for (std::size_t idx = 0; idx < end - start; ++idx)
                        {
                            finalTbk[start + idx] = std::move(expandOutput.mTbk[idx]);
                        }
                        return true;
                    }))
            {
                return false;
            }

            bool candidateOk = false;
            const Params seedParams = makeSeedParams(state.mParams, state.mShrinkExpandState.mParams);
            if (!validateGoldenSeedCandidate(seedParams, sampledTbk, candidateOk))
            {
                return false;
            }

            RecursiveSeedEvalOutput next{};
            if (!candidateOk)
            {
                out = std::move(next);
                return true;
            }

            next.mValid = true;
            state.mPrecomputedTbk = std::make_shared<std::vector<RnsPoly>>(finalTbk);
            next.mTbk = std::move(finalTbk);
            out = std::move(next);
            return true;
        }

        bool findRecursiveGoldenSeedAndEvaluate(
            const SenderState& state,
            PRNG& prng,
            RecursiveSeedEvalOutput& out)
        {
            constexpr int maxSeedAttempts = 100;
            for (int attempt = 0; attempt < maxSeedAttempts; ++attempt)
            {
                AlignedUnVec<u8> seed(16);
                prng.get(seed.data(), seed.size());

                RecursiveSeedEvalOutput eval{};
                if (!evaluateSenderSeedCandidate(state, seed, eval))
                {
                    return false;
                }
                if (!eval.mValid)
                {
                    continue;
                }

                state.mGoldenSeed = std::move(seed);
                out = std::move(eval);
                return true;
            }

            return false;
        }

        bool ensureSenderPrecomputeImpl(
            const SenderState& state,
            PRNG& prng)
        {
            if (state.mPrecomputedTbk)
            {
                return true;
            }

            RecursiveSeedEvalOutput eval{};
            const bool ok = state.mGoldenSeed.empty() ?
                findRecursiveGoldenSeedAndEvaluate(state, prng, eval) :
                evaluateSenderSeedCandidate(state, state.mGoldenSeed, eval);
            if (!ok || !eval.mValid)
            {
                return false;
            }

            state.mPrecomputedTbk = std::make_shared<std::vector<RnsPoly>>(std::move(eval.mTbk));
            return true;
        }

        bool shrinkExpandParamsEqual(const ShrinkExpandParams& lhs, const ShrinkExpandParams& rhs)
        {
            return lhs.mRing == rhs.mRing &&
                   lhs.mPlaintextModulusBits == rhs.mPlaintextModulusBits &&
                   lhs.mAlpha == rhs.mAlpha &&
                   lhs.mMu == rhs.mMu &&
                   lhs.mGadgetLogBase == rhs.mGadgetLogBase &&
                   lhs.mTau == rhs.mTau &&
                   lhs.mNumWorkerThreads == rhs.mNumWorkerThreads &&
                   lhs.mTruncateOneGadgetDigit == rhs.mTruncateOneGadgetDigit &&
                   lhs.mLeafInputsAreGadget == rhs.mLeafInputsAreGadget &&
                   lhs.mMode == rhs.mMode &&
                   lhs.mNoiseBound == rhs.mNoiseBound;
        }

        bool rnsBatchEqual(const std::vector<RnsPoly>& lhs, const std::vector<RnsPoly>& rhs)
        {
            if (lhs.size() != rhs.size())
            {
                return false;
            }
            for (std::size_t idx = 0; idx < lhs.size(); ++idx)
            {
                if (!rangesEqual(lhs[idx].mCoeffs, rhs[idx].mCoeffs))
                {
                    return false;
                }
            }
            return true;
        }

        bool prepareSenderOfflineImpl(
            const SenderOfflineInput& input,
            PRNG& prng,
            SenderState& state,
            OfflineMessage& message,
            bool isTopLevel,
            const ShrinkExpandSenderState* reusableInternalState)
        {
            u32 tauHi = 0;
            u32 muHi = 0;
            const u32 rho = static_cast<u32>(input.mParams.mShrinkExpand.mRing.mCoeffModulusBits.size());
            if (!computeTauHi(input.mParams, tauHi) ||
                !computeMuHi(input.mParams, muHi) ||
                input.mSk1.empty() ||
                !validateRingBatchShape(input.mSk1, input.mParams.mShrinkExpand.mRing))
            {
                return false;
            }

            const RecursiveMode mode =
                evalRecursiveMode(input.mParams.mW, input.mParams.mShrinkExpand.mAlpha, tauHi, rho);

            ShrinkExpandParams seParams{};
            if (!makeTruncShrinkExpandParams(input.mParams, input.mLeafInputsAreGadget, seParams))
            {
                return false;
            }

            ShrinkExpandSenderState seState{};
            const ShrinkExpandSenderState* childReusableState = reusableInternalState;
            OfflineMessage nextMessage{};
            if (reusableInternalState != nullptr)
            {
                if (!shrinkExpandParamsEqual(reusableInternalState->mParams, seParams) ||
                    !rnsBatchEqual(reusableInternalState->mSk1, input.mSk1))
                {
                    return false;
                }
                seState = *reusableInternalState;
                nextMessage.mHasShrinkExpandMessage = false;
            }
            else
            {
                std::vector<RnsPoly> sRep;
                if (!seedLabelRepOfflineSenderInput(
                        input.mSk1,
                        input.mParams.mGamma,
                        input.mParams.mShrinkExpand.mAlpha,
                        tauHi,
                        input.mParams.mShrinkExpand.mRing,
                        sRep))
                {
                    return false;
                }

                ShrinkExpandSenderOfflineInput seInput{};
                seInput.mParams = seParams;
                seInput.mS = std::move(sRep);
                if (!isTopLevel)
                {
                    seInput.mFixedSk1 = input.mSk1;
                }

                ShrinkExpandOfflineMessage seMessage{};
                if (!prepareShrinkExpandSenderOffline(seInput, prng, seMessage, seState))
                {
                    return false;
                }

                nextMessage.mShrinkExpandMessage = std::move(seMessage);
            }

            SenderState nextState{};
            nextState.mParams = input.mParams;
            nextState.mSk1 = input.mSk1;
            nextState.mShrinkExpandState = std::move(seState);
            if (reusableInternalState == nullptr && !isTopLevel)
            {
                childReusableState = &nextState.mShrinkExpandState;
            }

            if (mode == RecursiveMode::Root)
            {
                if (input.mParams.mW != muHi ||
                    !prepareRootOfflineSender(nextState, prng, nextMessage.mRootMessage))
                {
                    return false;
                }
            }
            else
            {
                Params childParams{};
                if (!makeChildParams(input.mParams, childParams))
                {
                    return false;
                }

                SenderOfflineInput childInput{};
                childInput.mParams = std::move(childParams);
                childInput.mSk1 = nextState.mShrinkExpandState.mSk1;
                childInput.mLeafInputsAreGadget = true;

                auto childMessage = std::make_unique<OfflineMessage>();
                auto childState = std::make_unique<SenderState>();
                if (!prepareSenderOfflineImpl(childInput, prng, *childState, *childMessage, false, childReusableState))
                {
                    return false;
                }

                nextState.mNextLevelState = std::move(childState);
                nextMessage.mNextLevel = std::move(childMessage);
            }

            state = std::move(nextState);
            message = std::move(nextMessage);
            return true;
        }

        bool finalizeReceiverOfflineImpl(
            const ReceiverOfflineInput& input,
            const OfflineMessage& message,
            ReceiverState& state,
            bool isTopLevel,
            const ShrinkExpandReceiverState* reusableInternalState)
        {
            u32 tauHi = 0;
            u32 muHi = 0;
            const u32 rho = static_cast<u32>(input.mParams.mShrinkExpand.mRing.mCoeffModulusBits.size());
            if (!computeTauHi(input.mParams, tauHi) ||
                !computeMuHi(input.mParams, muHi))
            {
                return false;
            }

            const RecursiveMode mode =
                evalRecursiveMode(input.mParams.mW, input.mParams.mShrinkExpand.mAlpha, tauHi, rho);

            ShrinkExpandParams seParams{};
            if (!makeTruncShrinkExpandParams(input.mParams, input.mLeafInputsAreGadget, seParams))
            {
                return false;
            }

            ShrinkExpandReceiverState seState{};
            const ShrinkExpandReceiverState* childReusableState = reusableInternalState;
            if (reusableInternalState != nullptr)
            {
                if (message.mHasShrinkExpandMessage ||
                    !shrinkExpandParamsEqual(reusableInternalState->mParams, seParams))
                {
                    return false;
                }
                seState = *reusableInternalState;
            }
            else
            {
                if (!message.mHasShrinkExpandMessage)
                {
                    return false;
                }

                ShrinkExpandReceiverOfflineInput seInput{};
                seInput.mParams = seParams;

                if (!finalizeShrinkExpandReceiverOffline(seInput, message.mShrinkExpandMessage, seState))
                {
                    return false;
                }
            }

            ReceiverState nextState{};
            nextState.mParams = input.mParams;
            nextState.mShrinkExpandState = std::move(seState);
            if (reusableInternalState == nullptr && !isTopLevel)
            {
                childReusableState = &nextState.mShrinkExpandState;
            }

            if (mode == RecursiveMode::Root)
            {
                if (input.mParams.mW != muHi ||
                    !finalizeRootOfflineReceiver(nextState, message.mRootMessage))
                {
                    return false;
                }
            }
            else
            {
                Params childParams{};
                if (!message.mNextLevel || !makeChildParams(input.mParams, childParams))
                {
                    return false;
                }

                ReceiverOfflineInput childInput{};
                childInput.mParams = std::move(childParams);
                childInput.mLeafInputsAreGadget = true;

                auto childState = std::make_unique<ReceiverState>();
                if (!finalizeReceiverOfflineImpl(childInput, *message.mNextLevel, *childState, false, childReusableState))
                {
                    return false;
                }

                nextState.mNextLevelState = std::move(childState);
            }

            state = std::move(nextState);
            return true;
        }
    }

    bool prepareSenderOffline(
        const SenderOfflineInput& input,
        PRNG& prng,
        SenderOfflineOutput& out)
    {
        SenderState state{};
        OfflineMessage message{};
        if (!prepareSenderOfflineImpl(input, prng, state, message, true, nullptr))
        {
            return false;
        }

        SenderOfflineOutput next{};
        next.mState = std::move(state);
        next.mShrinkExpandMessage = message.mShrinkExpandMessage;
        next.mRootMessage = message.mRootMessage;
        next.mMessage = std::move(message);
        out = std::move(next);
        return true;
    }

    bool finalizeReceiverOffline(
        const ReceiverOfflineInput& input,
        const OfflineMessage& message,
        ReceiverOfflineOutput& out)
    {
        ReceiverState state{};
        if (!finalizeReceiverOfflineImpl(input, message, state, true, nullptr))
        {
            return false;
        }

        ReceiverOfflineOutput next{};
        next.mState = std::move(state);
        out = std::move(next);
        return true;
    }

    bool finalizeReceiverOffline(
        const ReceiverOfflineInput& input,
        const ShrinkExpandOfflineMessage& shrinkExpandMessage,
        const RootOfflineMessage& rootMessage,
        ReceiverOfflineOutput& out)
    {
        OfflineMessage message{};
        message.mShrinkExpandMessage = shrinkExpandMessage;
        message.mRootMessage = rootMessage;
        return finalizeReceiverOffline(input, message, out);
    }

    bool ensureSenderPrecompute(
        const SenderState& state)
    {
        (void)state;
        return true;
    }

    bool ensureRootSenderPrecompute(
        const SenderState& state)
    {
        (void)state;
        return true;
    }

    bool prepareRecursiveSenderExpansionLocal(
        SenderState& state,
        std::span<const RnsPoly> digests)
    {
        u32 muHi = 0;
        if (!computeMuHi(state.mParams, muHi) ||
            !state.mNextLevelState)
        {
            return false;
        }

        const u32 wDoublePrime = computeWDoublePrime(state.mParams, muHi);
        if (digests.size() != wDoublePrime ||
            !state.mPrecomputedTbk)
        {
            return false;
        }

        return true;
    }

    bool prepareRootOnlineSender(
        SenderState& state,
        const RootDigestMessage& request,
        PRNG& prng,
        RootResponseMessage& response,
        SenderOnlineOutput& out)
    {
        if (!ensureRootSenderPrecompute(state) ||
            !prepareRootResponseSender(state, request, prng, response) ||
            !state.mPrecomputedTbk)
        {
            return false;
        }

        SenderOnlineOutput next{};
        next.mSeed = response.mSeed;
        next.mTbk = *state.mPrecomputedTbk;
        out = std::move(next);
        return true;
    }

    namespace
    {
        bool runLocalOnlineImpl(
            SenderState& sender,
            SenderState& precomputeRoot,
            ReceiverState& receiver,
            const ReceiverOnlineInput& input,
            PRNG& senderPrng,
            PRNG& receiverPrng,
            SenderOnlineOutput& senderOut,
            ReceiverOnlineOutput& receiverOut);
    }

    bool runLocalOnline(
        SenderState& sender,
        ReceiverState& receiver,
        const ReceiverOnlineInput& input,
        PRNG& senderPrng,
        PRNG& receiverPrng,
        SenderOnlineOutput& senderOut,
        ReceiverOnlineOutput& receiverOut)
    {
        return runLocalOnlineImpl(sender, sender, receiver, input, senderPrng, receiverPrng, senderOut, receiverOut);
    }

    namespace
    {
        bool runLocalOnlineImpl(
            SenderState& sender,
            SenderState& precomputeRoot,
            ReceiverState& receiver,
            const ReceiverOnlineInput& input,
            PRNG& senderPrng,
            PRNG& receiverPrng,
            SenderOnlineOutput& senderOut,
            ReceiverOnlineOutput& receiverOut)
    {
        u32 tauHi = 0;
        u32 muHi = 0;
        if (!computeTauHi(sender.mParams, tauHi) ||
            !computeMuHi(sender.mParams, muHi) ||
            sender.mParams.mW != receiver.mParams.mW ||
            !(sender.mParams.mShrinkExpand.mRing == receiver.mParams.mShrinkExpand.mRing))
        {
            return false;
        }

        const u32 rho = static_cast<u32>(sender.mParams.mShrinkExpand.mRing.mCoeffModulusBits.size());
        const RecursiveMode mode =
            evalRecursiveMode(sender.mParams.mW, sender.mParams.mShrinkExpand.mAlpha, tauHi, rho);

        applySessionId(sender, input.mSid);
        applySessionId(receiver, input.mSid);

        if (!ensureSenderPrecompute(sender))
        {
            return false;
        }

        if (mode == RecursiveMode::Root)
        {
            RootDigestState digestState{};
            RootDigestMessage digestMessage{};
            RootResponseMessage response{};
            if (!prepareRootDigestReceiver(receiver, input.mX, receiverPrng, digestState, digestMessage) ||
                !prepareRootResponseSender(sender, digestMessage, senderPrng, response, &precomputeRoot) ||
                !finalizeRootOnlineReceiver(receiver, input, digestState, response, receiverOut))
            {
                return false;
            }

            SenderOnlineOutput nextSender{};
            nextSender.mSeed = response.mSeed;
            if (sender.mPrecomputedTbk)
            {
                nextSender.mTbk = *sender.mPrecomputedTbk;
                if (nextSender.mTbk.size() > receiverOut.mTbm.size())
                {
                    nextSender.mTbk.resize(receiverOut.mTbm.size());
                }
            }
            else if (&sender == &precomputeRoot)
            {
                return false;
            }
            senderOut = std::move(nextSender);
            return true;
        }

        if (!sender.mNextLevelState ||
            !receiver.mNextLevelState ||
            input.mX.size() != sender.mParams.mW)
        {
            return false;
        }

        const u32 wDoublePrime = computeWDoublePrime(sender.mParams, muHi);
        const u32 wNext = wDoublePrime * tauHi * rho;
        const u32 wPrime =
            (sender.mParams.mW + sender.mParams.mShrinkExpand.mAlpha - 1u) /
            sender.mParams.mShrinkExpand.mAlpha;

        std::vector<std::vector<RnsPoly>> dHatChunks(wDoublePrime);
        std::vector<RnsPoly> digests(wDoublePrime);
        std::vector<std::shared_ptr<DigestTree>> trees(wDoublePrime);

        if (!detail::runParallelTasks(
                wDoublePrime,
                sender.mParams.mShrinkExpand.mNumWorkerThreads,
                [&](std::size_t taskIdx) {
                    const auto chunkIdx = static_cast<u32>(taskIdx);
                    const std::size_t start = static_cast<std::size_t>(chunkIdx) * muHi;
                    const std::size_t end =
                        std::min(start + static_cast<std::size_t>(muHi), input.mX.size());
                    if (start > end)
                    {
                        return false;
                    }

                    const std::size_t chunkSize = end - start;
                    std::vector<RnsPoly> paddedChunk;
                    std::span<const RnsPoly> chunk;
                    if (chunkSize == static_cast<std::size_t>(muHi))
                    {
                        chunk = std::span<const RnsPoly>(input.mX.data() + start, chunkSize);
                    }
                    else
                    {
                        paddedChunk.resize(muHi);
                        for (std::size_t i = 0; i < chunkSize; ++i)
                        {
                            paddedChunk[i] = input.mX[start + i];
                        }
                        for (std::size_t i = chunkSize; i < paddedChunk.size(); ++i)
                        {
                            resizeZero(
                                paddedChunk[i].mCoeffs,
                                ringPolyCoeffCount(sender.mParams.mShrinkExpand.mRing));
                        }
                        chunk = std::span<const RnsPoly>(paddedChunk.data(), paddedChunk.size());
                    }

                    ShrinkExpandShrinkOutput shrink{};
                    std::vector<RnsPoly> decomposed;
                    if (!shrinkExpandShrink(receiver.mShrinkExpandState, chunk, shrink) ||
                        !seedLabelGadgetDecomposeHiAndUnbundle(
                            shrink.mDigest,
                            sender.mParams.mShrinkExpand.mGadgetLogBase,
                            tauHi,
                            sender.mParams.mShrinkExpand.mRing,
                            decomposed) ||
                        decomposed.size() != static_cast<std::size_t>(tauHi) * rho)
                    {
                        return false;
                    }

                    digests[chunkIdx] = std::move(shrink.mDigest);
                    trees[chunkIdx] = std::move(shrink.mTree);
                    dHatChunks[chunkIdx] = std::move(decomposed);
                    return true;
                }))
        {
            return false;
        }

        std::vector<RnsPoly> dHat(wNext);
        std::size_t dHatIdx = 0;
        for (auto& chunk : dHatChunks)
        {
            if (chunk.size() != static_cast<std::size_t>(tauHi) * rho ||
                dHatIdx + chunk.size() > dHat.size())
            {
                return false;
            }
            for (auto& poly : chunk)
            {
                dHat[dHatIdx++] = std::move(poly);
            }
        }

        if (dHatIdx != dHat.size())
        {
            return false;
        }

        ReceiverOnlineInput childInput{};
        childInput.mSid = input.mSid;
        childInput.mX = std::move(dHat);

        SenderOnlineOutput childSenderOut{};
        ReceiverOnlineOutput childReceiverOut{};
        if (!runLocalOnlineImpl(
                *sender.mNextLevelState,
                precomputeRoot,
                *receiver.mNextLevelState,
                childInput,
                senderPrng,
                receiverPrng,
                childSenderOut,
                childReceiverOut))
        {
            return false;
        }

        if (!prepareRecursiveSenderExpansionLocal(sender, digests))
        {
            return false;
        }

        std::vector<RnsPoly> skXHat;
        std::vector<RnsPoly> skX;
        if (!seedLabelDenoiseTbm(
                childReceiverOut.mTbm,
                wPrime,
                tauHi,
                sender.mParams.mShrinkExpand.mRing,
                skXHat) ||
            !seedLabelAgg(
                skXHat,
                wDoublePrime,
                tauHi,
                sender.mParams.mShrinkExpand.mRing,
                skX) ||
            skX.size() != wDoublePrime)
        {
            return false;
        }

        const u64 instanceBase = countSeedInstances(*sender.mNextLevelState);
        const RnsPoly* rootMaskDigest = resolveRootMaskDigest(receiver);
        if (rootMaskDigest == nullptr)
        {
            return false;
        }

        std::vector<RnsPoly> finalTbm(sender.mParams.mW);
        if (!detail::runParallelTasks(
                wDoublePrime,
                sender.mParams.mShrinkExpand.mNumWorkerThreads,
                [&](std::size_t taskIdx) {
                    const auto chunkIdx = static_cast<u32>(taskIdx);
                    const std::size_t start = static_cast<std::size_t>(chunkIdx) * muHi;
                    const std::size_t end =
                        std::min(start + static_cast<std::size_t>(muHi), input.mX.size());

                    ShrinkExpandExpandReceiverInput expandInput{};
                    expandInput.mSeed = childReceiverOut.mSeed;
                    expandInput.mSid = input.mSid;
                    expandInput.mNonce = instanceBase + chunkIdx;
                    expandInput.mDigest = digests[chunkIdx];
                    expandInput.mMaskDigest = *rootMaskDigest;
                    expandInput.mSkX = skX[chunkIdx];
                    expandInput.mTree = trees[chunkIdx];

                    ShrinkExpandReceiverExpandOutput expandOutput{};
                    if (!shrinkExpandExpandReceiver(receiver.mShrinkExpandState, expandInput, expandOutput) ||
                        expandOutput.mTbm.size() < end - start)
                    {
                        return false;
                    }

                    for (std::size_t itemIdx = 0; itemIdx < end - start; ++itemIdx)
                    {
                        finalTbm[start + itemIdx] = std::move(expandOutput.mTbm[itemIdx]);
                    }
                    return true;
                }))
        {
            return false;
        }

        SenderOnlineOutput nextSender{};
        nextSender.mSeed = sender.mGoldenSeed;
        nextSender.mTbk = *sender.mPrecomputedTbk;

        ReceiverOnlineOutput nextReceiver{};
        nextReceiver.mSeed = childReceiverOut.mSeed;
        nextReceiver.mTbm = std::move(finalTbm);

        senderOut = std::move(nextSender);
        receiverOut = std::move(nextReceiver);
        return true;
    }
    }

    bool finalizeRootOnlineReceiver(
        ReceiverState& state,
        const ReceiverOnlineInput& input,
        const RootDigestState& digestState,
        const RootResponseMessage& response,
        ReceiverOnlineOutput& out)
    {
        RnsPoly receiverKey{};
        if (!finalizeRootResponseReceiver(state, digestState, response, receiverKey))
        {
            return false;
        }

        ShrinkExpandExpandReceiverInput expandInput{};
        expandInput.mSeed = response.mSeed;
        expandInput.mSid = input.mSid;
        expandInput.mNonce = 0;
        expandInput.mX = input.mX;
        expandInput.mDigest = digestState.mDRt;
        expandInput.mMaskDigest = digestState.mDPrime;
        expandInput.mSkX = std::move(receiverKey);
        expandInput.mTree = digestState.mRootTree;

        ShrinkExpandReceiverExpandOutput expandOutput{};
        if (!shrinkExpandExpandReceiver(state.mShrinkExpandState, expandInput, expandOutput) ||
            expandOutput.mTbm.size() < input.mX.size())
        {
            return false;
        }

        if (expandOutput.mTbm.size() > input.mX.size())
        {
            expandOutput.mTbm.resize(input.mX.size());
        }

        state.mRootDPrimeRt = std::make_shared<RnsPoly>(digestState.mDPrime);

        ReceiverOnlineOutput next{};
        next.mSeed = response.mSeed;
        next.mTbm = std::move(expandOutput.mTbm);
        out = std::move(next);
        return true;
    }

    bool finalizeRootResponseReceiver(
        ReceiverState& state,
        const RootDigestState& digestState,
        const RootResponseMessage& response,
        RnsPoly& rootKey)
    {
        u32 tauHi = 0;
        if (!computeTauHi(state.mParams, tauHi) ||
            response.mSeed.empty())
        {
            return false;
        }

        const u32 rho = static_cast<u32>(state.mParams.mShrinkExpand.mRing.mCoeffModulusBits.size());
        const u32 leftWidth = rootLeftWidth(tauHi, rho);
        RingNttContext ctx{};
        if (rho == 0 ||
            digestState.mHatDRt.size() != leftWidth ||
            !makeContext(state.mParams.mShrinkExpand.mRing, ctx))
        {
            return false;
        }

        RnsPoly skPrime{};
        std::vector<RnsPoly> ctRApplied;
        std::vector<RnsPoly> decPartialNtt;
        std::vector<RnsPoly> topEvalNtt;
        std::vector<RnsPoly> leftEvalNtt;
        std::vector<RnsPoly> ctK;
        if (!unpackSinglePoly(state.mParams.mShrinkExpand.mRing, response.mSkPrimeCoeffs, skPrime) ||
            !lheApplyCt1Trunc(
                ctx,
                state.mRootCtRRt,
                digestState.mDPrime,
                state.mParams.mShrinkExpand.mGadgetLogBase,
                tauHi,
                ctRApplied,
                true,
                state.mShrinkExpandState.mParams.mNumWorkerThreads) ||
            !lheDec(
                ctx,
                ctRApplied,
                skPrime,
                decPartialNtt,
                nullptr,
                true,
                true,
                state.mShrinkExpandState.mParams.mNumWorkerThreads) ||
            !evalRootTopCtNtt(state, ctx, digestState.mYLeft, digestState.mZeta, topEvalNtt) ||
            !lencEvalTrunc(
                ctx,
                toLencLacct(state.mRootLacctLeft),
                digestState.mHatDRt,
                leftWidth,
                tauHi,
                state.mParams.mShrinkExpand.mGadgetLogBase,
                state.mParams.mShrinkExpand.mPlaintextModulusBits,
                leftEvalNtt,
                true,
                state.mShrinkExpandState.mParams.mNumWorkerThreads,
                true) ||
            !buildHashedCt2(
                ctx,
                leftWidth,
                response.mSeed,
                state.mParams.mSessionId,
                digestState.mDPrime,
                0,
                ctK))
        {
            return false;
        }

        if (decPartialNtt.size() != leftWidth ||
            topEvalNtt.size() != leftWidth ||
            leftEvalNtt.size() != leftWidth ||
            ctK.size() != leftWidth)
        {
            return false;
        }

        std::vector<RnsPoly> tbmVec(leftWidth);
        for (u32 row = 0; row < leftWidth; ++row)
        {
            RnsPoly phiNtt = std::move(topEvalNtt[row]);
            RnsPoly tbmNtt = std::move(decPartialNtt[row]);
            if (!ringAddInplace(phiNtt, leftEvalNtt[row], ctx) ||
                !ringSubInplace(tbmNtt, phiNtt, ctx) ||
                !inverseNtt(tbmNtt, ctx) ||
                !ringAddInplace(tbmNtt, ctK[row], ctx))
            {
                return false;
            }
            tbmVec[row] = std::move(tbmNtt);
        }

        state.mGoldenSeed = response.mSeed;
        return denoiseAndAggRootKey(ctx, tbmVec, tauHi, rootKey);
    }

    bool seedLabelAgg(
        const std::vector<RnsPoly>& inputHat,
        u32 outCount,
        u32 tau,
        const RingParams& ring,
        std::vector<RnsPoly>& out)
    {
        if (tau == 0 || inputHat.size() != static_cast<std::size_t>(outCount) * tau ||
            !validateRingBatchShape(inputHat, ring))
        {
            return false;
        }

        RingNttContext ctx{};
        if (!makeContext(ring, ctx))
        {
            return false;
        }

        std::vector<RnsPoly> next(outCount);
        for (u32 i = 0; i < outCount; ++i)
        {
            RnsPoly sum = inputHat[static_cast<std::size_t>(i) * tau];
            for (u32 j = 1; j < tau; ++j)
            {
                if (!ringAddInplace(sum, inputHat[static_cast<std::size_t>(i) * tau + j], ctx))
                {
                    return false;
                }
            }
            next[i] = std::move(sum);
        }

        out = std::move(next);
        return true;
    }

    bool seedLabelGadgetDecomposeAndUnbundle(
        const RnsPoly& digest,
        u32 gadgetLogBase,
        u32 tau,
        const RingParams& ring,
        std::vector<RnsPoly>& out)
    {
        RingNttContext ctx{};
        if (!makeContext(ring, ctx))
        {
            return false;
        }

        return gadgetDecomposeBits(digest, gadgetLogBase, tau, ctx, out);
    }

    bool seedLabelGadgetDecomposeHiAndUnbundle(
        const RnsPoly& digest,
        u32 gadgetLogBase,
        u32 tauHi,
        const RingParams& ring,
        std::vector<RnsPoly>& out)
    {
        if (tauHi == 0)
        {
            return false;
        }

        RingNttContext ctx{};
        if (!makeContext(ring, ctx))
        {
            return false;
        }

        std::vector<RnsPoly> digits;
        if (!gadgetDecomposeBitsRangeCentered(digest, gadgetLogBase, 1, tauHi, ctx, digits))
        {
            return false;
        }

        const std::size_t rho = ctx.mModuli.size();
        const std::size_t n = ring.mPolyModulusDegree;

        AlignedUnVec<u64> crtLiftJModQj;
        resizeFill<u64>(crtLiftJModQj, rho, 1);
        for (std::size_t j = 0; j < rho; ++j)
        {
            u64 crtLift = 1;
            for (std::size_t k = 0; k < rho; ++k)
            {
                if (k != j)
                {
                    crtLift = seal::util::multiply_uint_mod(crtLift, ctx.mModuli[k].value(), ctx.mModuli[j]);
                }
            }
            crtLiftJModQj[j] = crtLift;
        }

        std::vector<RnsPoly> unbundled(digits.size() * rho);
        std::size_t outIdx = 0;

        for (const auto& digit : digits)
        {
            for (std::size_t j = 0; j < rho; ++j)
            {
                RnsPoly lifted{};
                resizeZero(lifted.mCoeffs, n * rho);
                const std::size_t limbOffset = j * n;
                const u64* digitCoeffs = digit.mCoeffs.data();
                u64* liftedCoeffs = lifted.mCoeffs.data();

                for (std::size_t c = 0; c < n; ++c)
                {
                    const u64 value = digitCoeffs[limbOffset + c];
                    liftedCoeffs[limbOffset + c] =
                        seal::util::multiply_uint_mod(value, crtLiftJModQj[j], ctx.mModuli[j]);
                }

                unbundled[outIdx++] = std::move(lifted);
            }
        }

        out = std::move(unbundled);
        return true;
    }

    bool seedLabelDenoiseTbm(
        const std::vector<RnsPoly>& tbmPrime,
        u32 wPrime,
        u32 tau,
        const RingParams& ring,
        std::vector<RnsPoly>& out)
    {
        (void)wPrime;
        if (tau == 0 || tbmPrime.empty() || !validateRingBatchShape(tbmPrime, ring))
        {
            return false;
        }

        RingNttContext ctx{};
        if (!makeContext(ring, ctx))
        {
            return false;
        }

        return shrinkExpandDenoiseComb(ctx, tbmPrime, out);
    }

    bool seedLabelRepOfflineSenderInput(
        const std::vector<RnsPoly>& s,
        u32 gamma,
        u32 alpha,
        u32 tau,
        const RingParams& ring,
        std::vector<RnsPoly>& out)
    {
        const u32 rho = static_cast<u32>(ring.mCoeffModulusBits.size());
        if (alpha == 0 || tau == 0 || rho == 0)
        {
            return false;
        }

        const u32 mu = alpha * tau * rho;
        std::vector<RnsPoly> next(mu);

        if (gamma == 1)
        {
            if (s.empty() || !validateRingPolyShape(s[0], ring))
            {
                return false;
            }

            for (u32 i = 0; i < mu; ++i)
            {
                next[i] = s[0];
            }
            out = std::move(next);
            return true;
        }

        if (gamma != tau || s.size() < tau || !validateRingBatchShape(s, ring))
        {
            return false;
        }

        std::vector<RnsPoly> inner(static_cast<std::size_t>(rho) * tau);
        std::size_t innerIdx = 0;
        for (u32 i = 0; i < tau; ++i)
        {
            for (std::size_t j = 0; j < rho; ++j)
            {
                RnsPoly poly = s[i];
                u64* coeffs = poly.mCoeffs.data();
                for (std::size_t k = 0; k < rho; ++k)
                {
                    const std::size_t offset = k * ring.mPolyModulusDegree;
                    if (k != j)
                    {
                        std::memset(
                            coeffs + offset,
                            0,
                            static_cast<std::size_t>(ring.mPolyModulusDegree) * sizeof(u64));
                    }
                }
                inner[innerIdx++] = std::move(poly);
            }
        }

        std::size_t nextIdx = 0;
        for (u32 i = 0; i < alpha; ++i)
        {
            for (const auto& poly : inner)
            {
                next[nextIdx++] = poly;
            }
        }

        out = std::move(next);
        return true;
    }

    bool seedLabelSampleCt2FromSeed(
        std::span<const u8> seed,
        u64 sid,
        const RnsPoly& digest,
        u32 instanceIdx,
        u32 coeffCount,
        const RingParams& ring,
        std::vector<RnsPoly>& out)
    {
        RingNttContext ctx{};
        if (!makeContext(ring, ctx))
        {
            return false;
        }

        return buildHashedCt2(ctx, coeffCount, seed, sid, digest, static_cast<u64>(instanceIdx), out);
    }

    bool validateGoldenSeedSearch(const Params& params)
    {
        RingNttContext ctx{};
        return makeContext(params.mShrinkExpand.mRing, ctx) && validateGoldenSeedSearchBudget(params, ctx);
    }

    bool validateGoldenSeedCandidate(
        const Params& params,
        const std::vector<RnsPoly>& tbkPerSampledPoly,
        bool& out)
    {
        if (!validateRingBatchShape(tbkPerSampledPoly, params.mShrinkExpand.mRing))
        {
            return false;
        }

        const u32 mu = params.mShrinkExpand.mMu;
        if (mu == 0)
        {
            return false;
        }

        const std::size_t expectedCount =
            static_cast<std::size_t>((params.mW + mu - 1) / mu) * static_cast<std::size_t>(mu);
        if (tbkPerSampledPoly.size() != expectedCount)
        {
            return false;
        }

        RingNttContext ctx{};
        if (!makeContext(params.mShrinkExpand.mRing, ctx))
        {
            return false;
        }

        std::vector<RoundingCheckConstants> rounding;
        if (!buildRoundingCheckConstants(params, ctx, rounding))
        {
            return false;
        }

        const std::size_t n = params.mShrinkExpand.mRing.mPolyModulusDegree;
        const std::size_t rho = ctx.mModuli.size();
        const wideU64 half = wideU64OneShift(127);
        AlignedUnVec<const RoundingCheckConstants*> roundingByLimb;
        resizeFill<const RoundingCheckConstants*>(
            roundingByLimb,
            rho,
            static_cast<const RoundingCheckConstants*>(nullptr));
        for (const auto& constants : rounding)
        {
            roundingByLimb[constants.mTargetLimbIndex] = &constants;
        }

        bool ok = true;
        for (std::size_t sampledPolyIdx = 0; sampledPolyIdx < tbkPerSampledPoly.size() && ok; ++sampledPolyIdx)
        {
            const auto& tbk = tbkPerSampledPoly[sampledPolyIdx];
            const u64* values = tbk.mCoeffs.data();
            std::size_t targetLimb = 0;
            if (!resolvePlaintextTargetLimbForSampledPoly(params, sampledPolyIdx, rho, targetLimb) ||
                targetLimb >= roundingByLimb.size() ||
                roundingByLimb[targetLimb] == nullptr)
            {
                return false;
            }

            const auto& constants = *roundingByLimb[targetLimb];
            for (std::size_t coeffIdx = 0; coeffIdx < n; ++coeffIdx)
            {
                wideU64 sumFrac = half;
                const std::size_t reducedCount = constants.mSrcLimbIndices.size();
                for (std::size_t idx = 0; idx < reducedCount; ++idx)
                {
                    const std::size_t w = constants.mSrcLimbIndices[idx];
                    const u64 vw = values[w * n + coeffIdx];
                    const u64 xw =
                        seal::util::multiply_uint_mod(vw, constants.mCrtInvPunctured[idx], ctx.mModuli[w]);
                    sumFrac = wideU64Add(sumFrac, wideU64MulLow(xw, constants.mFracInvModulus[idx]));
                }

                const wideU64 distanceToTop = wideU64Negate(sumFrac);
                if (wideU64Less(sumFrac, constants.mMargin) ||
                    wideU64Less(distanceToTop, constants.mMargin))
                {
                    ok = false;
                    break;
                }
            }
        }

        out = ok;
        return true;
    }

    bool findGoldenSeed(
        const Params& params,
        const std::vector<RnsPoly>& sk2PerInstance,
        const RnsPoly& digest,
        PRNG& prng,
        GoldenSeedSearchOutput& out)
    {
        if (sk2PerInstance.empty() ||
            !validateRingBatchShape(sk2PerInstance, params.mShrinkExpand.mRing) ||
            !validateRingPolyShape(digest, params.mShrinkExpand.mRing))
        {
            return false;
        }

        RingNttContext ctx{};
        if (!makeContext(params.mShrinkExpand.mRing, ctx) ||
            !validateGoldenSeedSearchBudget(params, ctx))
        {
            return false;
        }

        const std::size_t rho = ctx.mModuli.size();
        const std::size_t n = params.mShrinkExpand.mRing.mPolyModulusDegree;
        const std::size_t coeffCount = n * rho;
        const u32 mu = params.mShrinkExpand.mMu;
        if (mu == 0)
        {
            return false;
        }

        const u64 wDoublePrime = static_cast<u64>((params.mW + mu - 1) / mu);
        if (sk2PerInstance.size() != wDoublePrime)
        {
            return false;
        }

        const u64 sampledPolyCount = wDoublePrime * static_cast<u64>(mu);
        if (sampledPolyCount == 0 ||
            sampledPolyCount > static_cast<u64>(std::numeric_limits<std::size_t>::max()))
        {
            return false;
        }
        const std::size_t sampledPolyCountSize = static_cast<std::size_t>(sampledPolyCount);

        std::vector<RnsPoly> publicANtt;
        if (!buildLhePublicANtt(ctx, mu, publicANtt))
        {
            return false;
        }

        std::vector<RnsPoly> askPerSampledPoly(sampledPolyCountSize);
        for (std::size_t instanceIdx = 0; instanceIdx < sk2PerInstance.size(); ++instanceIdx)
        {
            RnsPoly sk2Ntt = sk2PerInstance[instanceIdx];
            if (!forwardNtt(sk2Ntt, ctx))
            {
                return false;
            }

            for (u32 rowIdx = 0; rowIdx < mu; ++rowIdx)
            {
                RnsPoly askNtt{};
                resizeZero(askNtt.mCoeffs, coeffCount);
                if (!dyadicMultiplyAddNttInplace(publicANtt[rowIdx], sk2Ntt, askNtt, ctx) ||
                    !inverseNtt(askNtt, ctx))
                {
                    return false;
                }

                const std::size_t sampledPolyIdx = instanceIdx * static_cast<std::size_t>(mu) + rowIdx;
                askPerSampledPoly[sampledPolyIdx] = std::move(askNtt);
            }
        }

        constexpr int maxSeedAttempts = 100;
        std::vector<RnsPoly> attemptCt2PerSampledPoly(sampledPolyCountSize);
        std::vector<block> attemptInstanceSeeds(sk2PerInstance.size());

        for (int attempt = 0; attempt < maxSeedAttempts; ++attempt)
        {
            AlignedUnVec<u8> seed(16);
            prng.get(seed.data(), seed.size());

            for (std::size_t instanceIdx = 0; instanceIdx < sk2PerInstance.size(); ++instanceIdx)
            {
                attemptInstanceSeeds[instanceIdx] = deriveSeedInstanceBlock(
                    seed,
                    params.mSessionId,
                    digest,
                    static_cast<u64>(instanceIdx),
                    mu);
            }

            if (!deriveUniformPolyBatchFromSeedListInplace(
                    ctx,
                    attemptInstanceSeeds,
                    0xC720AA55u,
                    mu,
                    attemptCt2PerSampledPoly,
                    params.mShrinkExpand.mNumWorkerThreads <= 1 ? 0 : params.mShrinkExpand.mNumWorkerThreads) ||
                attemptCt2PerSampledPoly.size() != sampledPolyCountSize)
            {
                return false;
            }

            for (std::size_t instanceIdx = 0; instanceIdx < sk2PerInstance.size(); ++instanceIdx)
            {
                for (u32 rowIdx = 0; rowIdx < mu; ++rowIdx)
                {
                    const std::size_t sampledPolyIdx = instanceIdx * static_cast<std::size_t>(mu) + rowIdx;
                    if (!ringSubInplace(
                            attemptCt2PerSampledPoly[sampledPolyIdx],
                            askPerSampledPoly[sampledPolyIdx],
                            ctx))
                    {
                        return false;
                    }
                }
            }

            bool candidateOk = false;
            if (!validateGoldenSeedCandidate(params, attemptCt2PerSampledPoly, candidateOk))
            {
                return false;
            }

            if (candidateOk)
            {
                GoldenSeedSearchOutput next{};
                next.mSeed = std::move(seed);
                next.mTbkPerSampledPoly = std::move(attemptCt2PerSampledPoly);
                out = std::move(next);
                return true;
            }
        }

        return false;
    }
}

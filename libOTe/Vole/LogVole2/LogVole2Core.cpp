#include "libOTe/Vole/LogVole2/LogVole2Core.h"

#include "libOTe/Vole/LogVole2/LogVole2Encoding.h"
#include "libOTe/Vole/LogVole2/LogVole2Parallel.h"

#include "seal/util/rns.h"
#include "seal/util/uintarithsmallmod.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstring>
#include <limits>
#include <random>
#include <span>
#include <utility>

namespace osuCrypto::LogVole2
{
    namespace
    {
        bool makeContext(const RingParams& ring, RingNttContext& ctx)
        {
            return makeRingNttContext(ring, ctx);
        }

        u64 pow2Mod(u64 exp, u64 mod)
        {
            u64 result = 1;
            u64 base = 2 % mod;
            while (exp > 0)
            {
                if ((exp & 1) != 0)
                {
                    const auto mul = static_cast<unsigned __int128>(result) * base;
                    result = static_cast<u64>(mul % mod);
                }

                const auto sq = static_cast<unsigned __int128>(base) * base;
                base = static_cast<u64>(sq % mod);
                exp >>= 1;
            }

            return result;
        }

        u64 uint128Mod(unsigned __int128 value, const seal::Modulus& modulus)
        {
            const u64 mod = modulus.value();
            const u64 lo = static_cast<u64>(value);
            const u64 hi = static_cast<u64>(value >> 64);
            const u64 two64Mod = static_cast<u64>((static_cast<unsigned __int128>(1) << 64) % mod);
            const auto hiTerm = static_cast<unsigned __int128>(hi % mod) * two64Mod;
            return static_cast<u64>((hiTerm + (lo % mod)) % mod);
        }

        u64 freshRootZetaSeed()
        {
            static std::atomic<u64> counter{ 0 };
            u64 seed = combineSeedPublic(counter.fetch_add(1, std::memory_order_relaxed));
            seed ^= combineSeedPublic(
                static_cast<u64>(std::chrono::high_resolution_clock::now().time_since_epoch().count()));

            std::random_device rd;
            for (u32 idx = 0; idx < 4; ++idx)
            {
                const u64 lo = static_cast<u64>(rd());
                const u64 hi = static_cast<u64>(rd());
                seed = combineSeedPublic(seed ^ (hi << 32) ^ lo ^ static_cast<u64>(idx));
            }

            return seed;
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

        unsigned __int128 reciprocal2Pow128(u64 modulus)
        {
            const unsigned __int128 two64 = static_cast<unsigned __int128>(1) << 64;
            const u64 hi = static_cast<u64>(two64 / modulus);
            const u64 rem = static_cast<u64>(two64 % modulus);
            const u64 lo = static_cast<u64>((static_cast<unsigned __int128>(rem) << 64) / modulus);
            return (static_cast<unsigned __int128>(hi) << 64) | lo;
        }

        unsigned __int128 floorToU128(long double value)
        {
            if (!(value > 0.0L))
            {
                return 0;
            }

            constexpr long double two64 = 18446744073709551616.0L;
            const long double hiLd = std::floor(value / two64);
            if (hiLd >= two64)
            {
                return ~static_cast<unsigned __int128>(0);
            }

            const u64 hi = static_cast<u64>(hiLd);
            const long double loLd = std::floor(value - hiLd * two64);
            const u64 lo = static_cast<u64>((loLd > 0.0L) ? loLd : 0.0L);
            return (static_cast<unsigned __int128>(hi) << 64) | static_cast<unsigned __int128>(lo);
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
            AlignedUnVec<unsigned __int128> mFracInvModulus;
            unsigned __int128 mMargin = 0;
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
                        constants.mFracInvModulus[idx] = reciprocal2Pow128(fullBase.base()[w].value());
                    }
                }

                const long double marginExp = static_cast<long double>(log2B - log2DeltaJ + 128.0);
                constants.mMargin = floorToU128(std::exp2(marginExp));
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

            const u32 tauFull = tauHi + 1;
            const u32 rho = static_cast<u32>(state.mParams.mShrinkExpand.mRing.mCoeffModulusBits.size());
            return message.mRing == state.mParams.mShrinkExpand.mRing &&
                   message.mTauHi == tauHi &&
                   message.mGadgetLogBase == state.mParams.mShrinkExpand.mGadgetLogBase &&
                   message.mPlaintextModulusBits == state.mParams.mShrinkExpand.mPlaintextModulusBits &&
                   message.mLeftWidth == rootLeftWidth(tauHi, rho) &&
                   message.mRandomizerWidth == rootRandomizerWidth(tauFull);
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

        u64 deriveRootDerandNonce(const SamplingSeedConfig& samplingSeeds, std::span<const u8> seed)
        {
            return deriveSeedInstanceNonce(samplingSeeds, seed, 0, 0xD37A4D5EEDull);
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

        bool ensureRootKPrime(const SenderState& state, RnsPoly& out)
        {
            if (state.mRootKPrimeRt)
            {
                out = *state.mRootKPrimeRt;
                return true;
            }

            RingNttContext ctx{};
            if (!makeContext(state.mParams.mShrinkExpand.mRing, ctx))
            {
                return false;
            }

            const u64 rootSkHead =
                (!state.mRootSkRRt.empty() && !state.mRootSkRRt[0].mCoeffs.empty())
                    ? state.mRootSkRRt[0].mCoeffs[0]
                    : 0;
            u32 tauHi = 0;
            if (!computeTauHi(state.mParams, tauHi))
            {
                return false;
            }
            const u32 rho =
                static_cast<u32>(state.mParams.mShrinkExpand.mRing.mCoeffModulusBits.size());
            const u32 muHi = state.mParams.mShrinkExpand.mAlpha * tauHi * rho;
            const u64 seedMaterial = deriveDeterministicSeedMaterial(
                state.mParams.mShrinkExpand.mSamplingSeeds.mCt2Root,
                0x52544B5052494D45ull,
                state.mParams.mW,
                muHi,
                state.mRootRandomizerWidth,
                rootSkHead);
            out = deriveUniformPolyFromNonce(ctx, seedMaterial, 0x52544B50u, 0);
            state.mRootKPrimeRt = std::make_shared<RnsPoly>(out);
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

    u32 rootRandomizerWidth(u32 tauFull)
    {
        return std::max<u32>(3, tauFull + 1);
    }

    u32 rootLeftWidth(u32 tauHi, u32 rho)
    {
        return tauHi * rho;
    }

    double rootNoiseSigma(const ShrinkExpandParams& params, double factor)
    {
        if (params.mMode != ShrinkExpandMode::FullNoise)
        {
            return 0.0;
        }

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
        const SamplingSeedConfig& samplingSeeds,
        u64 domain,
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
                const u64 noiseSeed =
                    deriveNoiseSeed(samplingSeeds, domain, idx, count, ctx.mModuli.size());
                if (!addPolyError(poly, sigma, maxDeviation, noiseSeed, 0, ctx))
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
        const SamplingSeedConfig& samplingSeeds,
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
                    const u64 streamId = (static_cast<u64>(row) << 32) ^ col;
                    const u64 noiseSeed =
                        deriveNoiseSeed(samplingSeeds, 0x5254544F504E5A45ull, streamId, leftWidth, next.mCols);
                    RnsPoly noise{};
                    resizeZero(noise.mCoeffs, ringPolyCoeffCount(ctx.mParams));
                    if (!addPolyError(noise, noiseStandardDeviation, noiseMaxDeviation, noiseSeed, 0, ctx) ||
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
        std::vector<RnsPoly>& out)
    {
        if (randomizerWidth == 0 || gadgetLogBase == 0 || gadgetLogBase > 127)
        {
            return false;
        }

        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        const std::size_t rho = ctx.mModuli.size();
        u64 seed = deriveDeterministicSeedMaterial(
            freshRootZetaSeed(),
            0x52544E5A455441ull,
            ctx.mParams.mPolyModulusDegree,
            randomizerWidth,
            gadgetLogBase,
            rho);
        const unsigned __int128 eta = (static_cast<unsigned __int128>(1) << gadgetLogBase) - 1;
        const u32 sampleBits = gadgetLogBase + 1;
        const unsigned __int128 sampleMask = (sampleBits == 128)
                                                 ? ~static_cast<unsigned __int128>(0)
                                                 : ((static_cast<unsigned __int128>(1) << sampleBits) - 1);

        std::vector<RnsPoly> zeta(randomizerWidth);
        for (u32 polyIdx = 0; polyIdx < randomizerWidth; ++polyIdx)
        {
            RnsPoly poly{};
            resizeZero(poly.mCoeffs, n * rho);
            for (std::size_t coeffIdx = 0; coeffIdx < n; ++coeffIdx)
            {
                unsigned __int128 raw = 0;
                do
                {
                    seed = combineSeedPublic(seed ^ (static_cast<u64>(polyIdx) << 32) ^ coeffIdx);
                    const u64 lo = seed;
                    seed = combineSeedPublic(seed + 0x9E3779B97F4A7C15ull);
                    const u64 hi = seed;
                    raw = ((static_cast<unsigned __int128>(hi) << 64) | lo) & sampleMask;
                } while (raw == sampleMask);

                const bool negative = raw <= eta;
                const unsigned __int128 magnitude = negative ? (eta - raw) : (raw - eta);
                for (std::size_t modIdx = 0; modIdx < rho; ++modIdx)
                {
                    const std::size_t outIdx = modIdx * n + coeffIdx;
                    const u64 mod = ctx.mModuli[modIdx].value();
                    const u64 reduced = uint128Mod(magnitude, ctx.mModuli[modIdx]);
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
        const u32 randomizer = rootRandomizerWidth(tauFull);
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
                se.mSamplingSeeds,
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
                se.mSamplingSeeds,
                0x5254523154524E43ull,
                lencSigma,
                lencMaxDev,
                false,
                r1))
        {
            return false;
        }

        const u64 skRSeed = deriveNoiseSeed(se.mSamplingSeeds, 0x5254534B52544Dull, leftWidth, tauHi, randomizer);
        std::vector<RnsPoly> skRRt = sampleUniformBatch(ctx, tauHi, skRSeed, 0x5254534Bu);
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
                se.mSamplingSeeds,
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
                se.mSamplingSeeds,
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

        const u32 tauFull = tauHi + 1;
        const u32 rho = static_cast<u32>(state.mParams.mShrinkExpand.mRing.mCoeffModulusBits.size());
        const u32 leftWidth = rootLeftWidth(tauHi, rho);
        const u32 randomizer = rootRandomizerWidth(tauFull);

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
            state.mRootRandomizerWidth != rootRandomizerWidth(tauFull))
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
        RootResponseMessage& response)
    {
        u32 tauHi = 0;
        if (!computeTauHi(state.mParams, tauHi) ||
            state.mGoldenSeed.empty() ||
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
            !ensureRootKPrime(state, kPrime) ||
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

        RnsPoly kPrime{};
        std::vector<RnsPoly> ctK;
        std::vector<RnsPoly> tbkRt;
        if (!ensureRootKPrime(state, kPrime) ||
            !buildHashedCt2(
                ctx,
                leftWidth,
                state.mParams.mShrinkExpand.mSamplingSeeds,
                deriveRootDerandNonce(state.mParams.mShrinkExpand.mSamplingSeeds, seed),
                ctK) ||
            !lheDec(
                ctx,
                ctK,
                kPrime,
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
        bool samplingSeedsEqual(const SamplingSeedConfig& lhs, const SamplingSeedConfig& rhs)
        {
            return lhs.mNoiseRoot == rhs.mNoiseRoot &&
                   lhs.mCt2Root == rhs.mCt2Root;
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
                   lhs.mNoiseBound == rhs.mNoiseBound &&
                   samplingSeedsEqual(lhs.mSamplingSeeds, rhs.mSamplingSeeds);
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
                if (!prepareShrinkExpandSenderOffline(seInput, seMessage, seState))
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
                    !prepareRootOfflineSender(nextState, nextMessage.mRootMessage))
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
                if (!prepareSenderOfflineImpl(childInput, *childState, *childMessage, false, childReusableState))
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
        SenderOfflineOutput& out)
    {
        SenderState state{};
        OfflineMessage message{};
        if (!prepareSenderOfflineImpl(input, state, message, true, nullptr))
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

    namespace
    {
        struct SeedEvalOutput
        {
            bool mValid = false;
            std::vector<RnsPoly> mTbk;
        };

        bool evaluateSenderSeedCandidate(
            const SenderState& state,
            std::span<const u8> seed,
            SeedEvalOutput& out)
        {
            u32 tauHi = 0;
            u32 muHi = 0;
            if (!computeTauHi(state.mParams, tauHi) || !computeMuHi(state.mParams, muHi))
            {
                return false;
            }

            const u32 rho = static_cast<u32>(state.mParams.mShrinkExpand.mRing.mCoeffModulusBits.size());
            const u32 wDoublePrime = computeWDoublePrime(state.mParams, muHi);
            const RecursiveMode mode =
                evalRecursiveMode(state.mParams.mW, state.mParams.mShrinkExpand.mAlpha, tauHi, rho);

            Params candidateParams = state.mParams;
            candidateParams.mShrinkExpand = state.mShrinkExpandState.mParams;

            if (mode == RecursiveMode::Root)
            {
                if (state.mParams.mW != muHi)
                {
                    return false;
                }

                RnsPoly rootKey{};
                if (!computeRootSenderKey(state, seed, rootKey))
                {
                    return false;
                }

                ShrinkExpandExpandSenderInput expandInput{};
                expandInput.mNonce = deriveSeedInstanceNonce(state.mParams.mShrinkExpand.mSamplingSeeds, seed, 0);
                expandInput.mTbkPrime = rootKey;

                ShrinkExpandSenderExpandOutput expandOutput{};
                bool candidateOk = false;
                if (!shrinkExpandExpandSender(state.mShrinkExpandState, expandInput, expandOutput) ||
                    !validateGoldenSeedCandidate(candidateParams, expandOutput.mTbk, candidateOk))
                {
                    return false;
                }

                if (candidateOk)
                {
                    assignSpan(state.mGoldenSeed, seed);
                    state.mRootKRt = std::make_shared<RnsPoly>(std::move(rootKey));
                    state.mPrecomputedTbk =
                        std::make_shared<std::vector<RnsPoly>>(expandOutput.mTbk);
                }

                SeedEvalOutput next{};
                next.mValid = candidateOk;
                next.mTbk = std::move(expandOutput.mTbk);
                out = std::move(next);
                return true;
            }

            if (!state.mNextLevelState || wDoublePrime == 0)
            {
                return false;
            }

            SeedEvalOutput childEval{};
            if (!evaluateSenderSeedCandidate(*state.mNextLevelState, seed, childEval))
            {
                return false;
            }
            if (!childEval.mValid)
            {
                out = {};
                return true;
            }

            const u32 wPrime =
                (state.mParams.mW + state.mParams.mShrinkExpand.mAlpha - 1u) /
                state.mParams.mShrinkExpand.mAlpha;
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
                        ShrinkExpandExpandSenderInput expandInput{};
                        expandInput.mNonce = deriveSeedInstanceNonce(
                            state.mParams.mShrinkExpand.mSamplingSeeds,
                            seed,
                            instanceBase + chunkIdx);
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

                        const std::size_t start = static_cast<std::size_t>(chunkIdx) * muHi;
                        const std::size_t end = std::min(
                            start + static_cast<std::size_t>(muHi),
                            static_cast<std::size_t>(state.mParams.mW));
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
            if (!validateGoldenSeedCandidate(candidateParams, sampledTbk, candidateOk))
            {
                return false;
            }

            if (candidateOk)
            {
                assignSpan(state.mGoldenSeed, seed);
                state.mPrecomputedTbk = std::make_shared<std::vector<RnsPoly>>(finalTbk);
            }

            SeedEvalOutput next{};
            next.mValid = candidateOk;
            next.mTbk = std::move(finalTbk);
            out = std::move(next);
            return true;
        }
    }

    bool ensureSenderPrecompute(
        const SenderState& state)
    {
        if (state.mPrecomputedTbk && !state.mGoldenSeed.empty())
        {
            return true;
        }

        u32 tauHi = 0;
        u32 muHi = 0;
        if (!computeTauHi(state.mParams, tauHi) || !computeMuHi(state.mParams, muHi))
        {
            return false;
        }

        Params candidateParams = state.mParams;
        candidateParams.mShrinkExpand = state.mShrinkExpandState.mParams;
        if (!validateGoldenSeedSearch(candidateParams))
        {
            return false;
        }

        if (!state.mGoldenSeed.empty())
        {
            SeedEvalOutput eval{};
            return evaluateSenderSeedCandidate(state, state.mGoldenSeed, eval) && eval.mValid;
        }

        const u64 skHead =
            (!state.mSk1.empty() && !state.mSk1[0].mCoeffs.empty()) ? state.mSk1[0].mCoeffs[0] : 0;
        const u64 seedMaterial = deriveDeterministicSeedMaterial(
            state.mParams.mShrinkExpand.mSamplingSeeds.mCt2Root,
            0x54524E4353454544ull,
            countSeedInstances(state),
            state.mParams.mW,
            muHi,
            skHead);
        std::mt19937_64 gen(seedMaterial);
        std::uniform_int_distribution<int> distBytes(0, 255);

        constexpr int maxSeedAttempts = 100;
        AlignedUnVec<u8> seed(16);
        for (int attempt = 0; attempt < maxSeedAttempts; ++attempt)
        {
            for (u8& byte : seed)
            {
                byte = static_cast<u8>(distBytes(gen));
            }

            SeedEvalOutput eval{};
            if (!evaluateSenderSeedCandidate(state, seed, eval))
            {
                return false;
            }
            if (eval.mValid)
            {
                state.mGoldenSeed = std::move(seed);
                state.mPrecomputedTbk = std::make_shared<std::vector<RnsPoly>>(std::move(eval.mTbk));
                return true;
            }
        }

        return false;
    }

    bool ensureRootSenderPrecompute(
        const SenderState& state)
    {
        if (state.mPrecomputedTbk && !state.mGoldenSeed.empty())
        {
            return true;
        }

        u32 tauHi = 0;
        u32 muHi = 0;
        const u32 rho = static_cast<u32>(state.mParams.mShrinkExpand.mRing.mCoeffModulusBits.size());
        if (!computeTauHi(state.mParams, tauHi) ||
            !computeMuHi(state.mParams, muHi) ||
            state.mParams.mW != muHi ||
            evalRecursiveMode(state.mParams.mW, state.mParams.mShrinkExpand.mAlpha, tauHi, rho) !=
                RecursiveMode::Root ||
            state.mRootSkRRt.empty())
        {
            return false;
        }

        Params candidateParams = state.mParams;
        candidateParams.mShrinkExpand = state.mShrinkExpandState.mParams;
        if (!validateGoldenSeedSearch(candidateParams))
        {
            return false;
        }

        auto evaluate = [&](std::span<const u8> seed, RnsPoly& rootKey, std::vector<RnsPoly>& tbk, bool& valid) {
            if (!computeRootSenderKey(state, seed, rootKey))
            {
                return false;
            }

            ShrinkExpandExpandSenderInput expandInput{};
            expandInput.mNonce = deriveSeedInstanceNonce(state.mParams.mShrinkExpand.mSamplingSeeds, seed, 0);
            expandInput.mTbkPrime = rootKey;

            ShrinkExpandSenderExpandOutput expandOutput{};
            if (!shrinkExpandExpandSender(state.mShrinkExpandState, expandInput, expandOutput) ||
                !validateGoldenSeedCandidate(candidateParams, expandOutput.mTbk, valid))
            {
                return false;
            }

            tbk = std::move(expandOutput.mTbk);
            return true;
        };

        if (!state.mGoldenSeed.empty())
        {
            RnsPoly rootKey{};
            std::vector<RnsPoly> tbk;
            bool valid = false;
            if (!evaluate(state.mGoldenSeed, rootKey, tbk, valid) || !valid)
            {
                return false;
            }

            state.mRootKRt = std::make_shared<RnsPoly>(std::move(rootKey));
            state.mPrecomputedTbk = std::make_shared<std::vector<RnsPoly>>(std::move(tbk));
            return true;
        }

        const u64 skHead =
            (!state.mSk1.empty() && !state.mSk1[0].mCoeffs.empty()) ? state.mSk1[0].mCoeffs[0] : 0;
        const u64 seedMaterial = deriveDeterministicSeedMaterial(
            state.mParams.mShrinkExpand.mSamplingSeeds.mCt2Root,
            0x54524E4353454544ull,
            1,
            state.mParams.mW,
            muHi,
            skHead);
        std::mt19937_64 gen(seedMaterial);
        std::uniform_int_distribution<int> distBytes(0, 255);

        constexpr int maxSeedAttempts = 100;
        AlignedUnVec<u8> seed(16);
        for (int attempt = 0; attempt < maxSeedAttempts; ++attempt)
        {
            for (u8& byte : seed)
            {
                byte = static_cast<u8>(distBytes(gen));
            }

            RnsPoly rootKey{};
            std::vector<RnsPoly> tbk;
            bool valid = false;
            if (!evaluate(seed, rootKey, tbk, valid))
            {
                return false;
            }
            if (!valid)
            {
                continue;
            }

            state.mGoldenSeed = std::move(seed);
            state.mRootKRt = std::make_shared<RnsPoly>(std::move(rootKey));
            state.mPrecomputedTbk = std::make_shared<std::vector<RnsPoly>>(std::move(tbk));
            return true;
        }

        return false;
    }

    bool prepareRootOnlineSender(
        SenderState& state,
        const RootDigestMessage& request,
        RootResponseMessage& response,
        SenderOnlineOutput& out)
    {
        if (!ensureRootSenderPrecompute(state) ||
            !prepareRootResponseSender(state, request, response) ||
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

    bool runLocalOnline(
        const SenderState& sender,
        ReceiverState& receiver,
        const ReceiverOnlineInput& input,
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

        if (!ensureSenderPrecompute(sender) || !sender.mPrecomputedTbk)
        {
            return false;
        }

        if (mode == RecursiveMode::Root)
        {
            RootDigestState digestState{};
            RootDigestMessage digestMessage{};
            RootResponseMessage response{};
            if (!prepareRootDigestReceiver(receiver, input.mX, digestState, digestMessage) ||
                !prepareRootResponseSender(sender, digestMessage, response) ||
                !finalizeRootOnlineReceiver(receiver, input, digestState, response, receiverOut))
            {
                return false;
            }

            SenderOnlineOutput nextSender{};
            nextSender.mSeed = response.mSeed;
            nextSender.mTbk = *sender.mPrecomputedTbk;
            if (nextSender.mTbk.size() > receiverOut.mTbm.size())
            {
                nextSender.mTbk.resize(receiverOut.mTbm.size());
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
        childInput.mX = std::move(dHat);

        SenderOnlineOutput childSenderOut{};
        ReceiverOnlineOutput childReceiverOut{};
        if (!runLocalOnline(
                *sender.mNextLevelState,
                *receiver.mNextLevelState,
                childInput,
                childSenderOut,
                childReceiverOut))
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
                    expandInput.mNonce = deriveSeedInstanceNonce(
                        sender.mParams.mShrinkExpand.mSamplingSeeds,
                        childReceiverOut.mSeed,
                        instanceBase + chunkIdx);
                    expandInput.mDigest = digests[chunkIdx];
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
        expandInput.mNonce = deriveSeedInstanceNonce(state.mParams.mShrinkExpand.mSamplingSeeds, response.mSeed, 0);
        expandInput.mX = input.mX;
        expandInput.mDigest = digestState.mDRt;
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
                state.mParams.mShrinkExpand.mSamplingSeeds,
                deriveRootDerandNonce(state.mParams.mShrinkExpand.mSamplingSeeds, response.mSeed),
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

        AlignedUnVec<u64> deltaJModQj;
        resizeFill<u64>(deltaJModQj, rho, 1);
        for (std::size_t j = 0; j < rho; ++j)
        {
            u64 delta = 1;
            for (std::size_t k = 0; k < rho; ++k)
            {
                if (k != j)
                {
                    delta = seal::util::multiply_uint_mod(delta, ctx.mModuli[k].value(), ctx.mModuli[j]);
                }
            }
            deltaJModQj[j] = delta;
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
                        seal::util::multiply_uint_mod(value, deltaJModQj[j], ctx.mModuli[j]);
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

        RingNttContext ctx{};
        if (!makeContext(ring, ctx))
        {
            return false;
        }

        AlignedUnVec<u64> deltaJModQj;
        resizeFill<u64>(deltaJModQj, rho, 1);
        for (std::size_t j = 0; j < rho; ++j)
        {
            u64 delta = 1;
            for (std::size_t k = 0; k < rho; ++k)
            {
                if (k != j)
                {
                    delta = seal::util::multiply_uint_mod(delta, ctx.mModuli[k].value(), ctx.mModuli[j]);
                }
            }
            deltaJModQj[j] = delta;
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
                    else
                    {
                        for (std::size_t c = 0; c < ring.mPolyModulusDegree; ++c)
                        {
                            const std::size_t idx = offset + c;
                            coeffs[idx] =
                                seal::util::multiply_uint_mod(coeffs[idx], deltaJModQj[j], ctx.mModuli[j]);
                        }
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
        const SamplingSeedConfig& samplingSeeds,
        std::span<const u8> seed,
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

        const u64 instanceNonce =
            deriveSeedInstanceNonce(samplingSeeds, seed, static_cast<u64>(instanceIdx));
        return buildHashedCt2(ctx, coeffCount, samplingSeeds, instanceNonce, out);
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
        const unsigned __int128 half = static_cast<unsigned __int128>(1) << 127;
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
                unsigned __int128 sumFrac = half;
                const std::size_t reducedCount = constants.mSrcLimbIndices.size();
                for (std::size_t idx = 0; idx < reducedCount; ++idx)
                {
                    const std::size_t w = constants.mSrcLimbIndices[idx];
                    const u64 vw = values[w * n + coeffIdx];
                    const u64 xw =
                        seal::util::multiply_uint_mod(vw, constants.mCrtInvPunctured[idx], ctx.mModuli[w]);
                    sumFrac += static_cast<unsigned __int128>(xw) * constants.mFracInvModulus[idx];
                }

                const unsigned __int128 distanceToTop = -sumFrac;
                if (sumFrac < constants.mMargin || distanceToTop < constants.mMargin)
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
        GoldenSeedSearchOutput& out)
    {
        if (sk2PerInstance.empty() ||
            !validateRingBatchShape(sk2PerInstance, params.mShrinkExpand.mRing))
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

        AlignedUnVec<u8> seed(16);
        const u64 sk2Head = !sk2PerInstance[0].mCoeffs.empty() ? sk2PerInstance[0].mCoeffs[0] : 0;
        const u64 seedMaterial = deriveDeterministicSeedMaterial(
            params.mShrinkExpand.mSamplingSeeds.mCt2Root,
            0x5345414C47534544ull,
            sampledPolyCount,
            mu,
            wDoublePrime,
            sk2Head);
        std::mt19937_64 gen(seedMaterial);
        std::uniform_int_distribution<int> distBytes(0, 255);

        constexpr int maxSeedAttempts = 100;
        std::vector<RnsPoly> attemptCt2PerSampledPoly(sampledPolyCountSize);
        AlignedUnVec<u64> attemptInstanceNonces(sk2PerInstance.size());

        for (int attempt = 0; attempt < maxSeedAttempts; ++attempt)
        {
            for (u8& byte : seed)
            {
                byte = static_cast<u8>(distBytes(gen));
            }

            for (std::size_t instanceIdx = 0; instanceIdx < sk2PerInstance.size(); ++instanceIdx)
            {
                const u64 seedNonce = deriveSeedInstanceNonce(
                    params.mShrinkExpand.mSamplingSeeds,
                    seed,
                    static_cast<u64>(instanceIdx));
                attemptInstanceNonces[instanceIdx] =
                    deriveCt2Nonce(params.mShrinkExpand.mSamplingSeeds, seedNonce, mu);
            }

            if (!deriveUniformPolyBatchFromNonceListInplace(
                    ctx,
                    attemptInstanceNonces,
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

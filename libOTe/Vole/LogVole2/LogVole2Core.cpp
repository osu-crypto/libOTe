#include "libOTe/Vole/LogVole2/LogVole2Core.h"

#include "seal/util/rns.h"
#include "seal/util/uintarithsmallmod.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <limits>
#include <random>
#include <utility>

namespace osuCrypto::LogVole2
{
    namespace
    {
        bool makeContext(const RingParams& ring, RingNttContext& ctx)
        {
            return makeRingNttContext(ring, ctx);
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
            std::vector<std::size_t> mSrcLimbIndices;
            std::vector<u64> mCrtInvPunctured;
            std::vector<unsigned __int128> mFracInvModulus;
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
                constants.mSrcLimbIndices.reserve((rho > 0) ? (rho - 1) : 0);

                std::vector<seal::Modulus> baseExcludingJ;
                baseExcludingJ.reserve((rho > 0) ? (rho - 1) : 0);

                double log2DeltaJ = 0.0;
                for (std::size_t w = 0; w < rho; ++w)
                {
                    if (w == j)
                    {
                        continue;
                    }
                    constants.mSrcLimbIndices.push_back(w);
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
                    constants.mCrtInvPunctured.resize(reducedCount, 0);
                    constants.mFracInvModulus.resize(reducedCount, 0);

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

        std::vector<RnsPoly> next;
        next.reserve(outCount);
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
            next.push_back(std::move(sum));
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

        std::vector<u64> deltaJModQj(rho, 1);
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

        std::vector<RnsPoly> unbundled;
        unbundled.reserve(digits.size() * rho);

        for (const auto& digit : digits)
        {
            for (std::size_t j = 0; j < rho; ++j)
            {
                RnsPoly lifted{};
                lifted.mCoeffs.assign(n * rho, 0);
                const std::size_t limbOffset = j * n;
                const u64* digitCoeffs = digit.mCoeffs.data();
                u64* liftedCoeffs = lifted.mCoeffs.data();

                for (std::size_t c = 0; c < n; ++c)
                {
                    const u64 value = digitCoeffs[limbOffset + c];
                    liftedCoeffs[limbOffset + c] =
                        seal::util::multiply_uint_mod(value, deltaJModQj[j], ctx.mModuli[j]);
                }

                unbundled.push_back(std::move(lifted));
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
        if (tau == 0 || tbmPrime.size() != static_cast<std::size_t>(wPrime) * tau)
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
        std::vector<RnsPoly> next;
        next.reserve(mu);

        if (gamma == 1)
        {
            if (s.empty() || !validateRingPolyShape(s[0], ring))
            {
                return false;
            }

            for (u32 i = 0; i < mu; ++i)
            {
                next.push_back(s[0]);
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

        std::vector<u64> deltaJModQj(rho, 1);
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

        std::vector<RnsPoly> inner;
        inner.reserve(static_cast<std::size_t>(rho) * tau);
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
                inner.push_back(std::move(poly));
            }
        }

        for (u32 i = 0; i < alpha; ++i)
        {
            for (const auto& poly : inner)
            {
                next.push_back(poly);
            }
        }

        out = std::move(next);
        return true;
    }

    bool seedLabelSampleCt2FromSeed(
        const SamplingSeedConfig& samplingSeeds,
        const std::vector<u8>& seed,
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
        std::vector<const RoundingCheckConstants*> roundingByLimb(rho, nullptr);
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
                askNtt.mCoeffs.assign(coeffCount, 0);
                if (!dyadicMultiplyAddNttInplace(publicANtt[rowIdx], sk2Ntt, askNtt, ctx) ||
                    !inverseNtt(askNtt, ctx))
                {
                    return false;
                }

                const std::size_t sampledPolyIdx = instanceIdx * static_cast<std::size_t>(mu) + rowIdx;
                askPerSampledPoly[sampledPolyIdx] = std::move(askNtt);
            }
        }

        std::vector<u8> seed(16);
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
        std::vector<u64> attemptInstanceNonces(sk2PerInstance.size());

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

#include "libOTe/Vole/LogVole2/LogVole2Core.h"

#include "seal/util/rns.h"
#include "seal/util/uintarithsmallmod.h"

#include <algorithm>
#include <atomic>
#include <chrono>
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
        std::vector<RnsPoly> next;
        next.reserve(static_cast<std::size_t>(tauHi) * rho);
        for (u32 digit = 0; digit < tauHi; ++digit)
        {
            for (std::size_t limb = 0; limb < rho; ++limb)
            {
                (void)limb;
                next.push_back(skHi[digit]);
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
            poly.mCoeffs.assign(ringPolyCoeffCount(ctx.mParams), 0);
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
                cellNtt.mCoeffs.assign(ringPolyCoeffCount(ctx.mParams), 0);
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
                    noise.mCoeffs.assign(ringPolyCoeffCount(ctx.mParams), 0);
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
            poly.mCoeffs.assign(n * rho, 0);
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
        accNtt.mCoeffs.assign(ringPolyCoeffCount(ctx.mParams), 0);
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

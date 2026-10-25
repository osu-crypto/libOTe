#include "libOTe/Vole/LogVole/LogVoleCore.h"

#include "libOTe/config.h"

#include "libOTe/Vole/LogVole/LogVole.h"
#include "libOTe/Vole/LogVole/LogVoleArithmetic.h"
#include "libOTe/Vole/LogVole/LogVoleCpuArithmetic.h"
#include "libOTe/Vole/LogVole/LogVoleEncoding.h"
#include "libOTe/Vole/LogVole/LogVoleParallel.h"

#if defined(ENABLE_LOGVOLE_CUDA)
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuProtocol.h"
#endif

#include "seal/util/rns.h"
#include "seal/util/uintarithsmallmod.h"
#include "cryptoTools/Crypto/RandomOracle.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstring>
#include <limits>
#include <mutex>
#include <span>
#include <stdexcept>
#include <utility>

namespace osuCrypto::LogVole
{
    namespace
    {
        // Temporary: per-step timing for the Root recursion level, dumped at exit
        // when LV_ROOT_PROFILE is set. The Root is a chain of small dependent
        // operations and the existing mRootReceiverHostUs timer brackets the whole
        // thing, so it cannot say which step to attack.
        struct RootStepProfiler
        {
            struct Entry
            {
                const char* mName;
                std::atomic<u64> mUs{ 0 };
                std::atomic<u64> mCount{ 0 };
                // First call and worst call, because a one-time device cache
                // upload inside a step is indistinguishable from a per-query cost
                // in the mean.
                std::atomic<u64> mFirstUs{ 0 };
                std::atomic<u64> mMaxUs{ 0 };
            };
            static constexpr u32 kMax = 32;
            Entry mEntries[kMax]{};
            std::atomic<u32> mUsed{ 0 };

            ~RootStepProfiler()
            {
                if (!std::getenv("LV_ROOT_PROFILE")) return;
                const u32 n = mUsed.load();
                std::fprintf(stderr, "\n[root] per-step host time\n");
                u64 total = 0;
                for (u32 i = 0; i < n; ++i) total += mEntries[i].mUs.load();
                for (u32 i = 0; i < n; ++i)
                {
                    const u64 us = mEntries[i].mUs.load();
                    const u64 cnt = mEntries[i].mCount.load();
                    const u64 first = mEntries[i].mFirstUs.load();
                    const double rest =
                        cnt > 1 ? double(us - first) / double(cnt - 1) / 1000.0 : 0.0;
                    std::fprintf(
                        stderr,
                        "[root] %-34s %8.3f ms  x%-4llu %5.1f%%  first %7.3f  max %7.3f  "
                        "mean-after-first %7.3f\n",
                        mEntries[i].mName, double(us) / 1000.0, (unsigned long long)cnt,
                        total ? 100.0 * double(us) / double(total) : 0.0, double(first) / 1000.0,
                        double(mEntries[i].mMaxUs.load()) / 1000.0, rest);
                }
                std::fprintf(stderr, "[root] %-34s %8.3f ms\n", "TOTAL", double(total) / 1000.0);
            }

            Entry& slot(const char* name)
            {
                const u32 n = mUsed.load(std::memory_order_acquire);
                for (u32 i = 0; i < n; ++i)
                {
                    if (mEntries[i].mName == name) return mEntries[i];
                }
                const u32 idx = mUsed.fetch_add(1);
                if (idx >= kMax) return mEntries[kMax - 1];
                mEntries[idx].mName = name;
                return mEntries[idx];
            }
        };

        RootStepProfiler& rootProfiler()
        {
            static RootStepProfiler p;
            return p;
        }

        struct RootStep
        {
            RootStepProfiler::Entry* mEntry = nullptr;
            std::chrono::steady_clock::time_point mStart;

            explicit RootStep(const char* name)
            {
                static const bool on = std::getenv("LV_ROOT_PROFILE") != nullptr;
                if (!on) return;
                mEntry = &rootProfiler().slot(name);
                mStart = std::chrono::steady_clock::now();
            }
            ~RootStep()
            {
                if (!mEntry) return;
                const auto us = std::chrono::duration_cast<std::chrono::microseconds>(
                                    std::chrono::steady_clock::now() - mStart)
                                    .count();
                mEntry->mUs.fetch_add(static_cast<u64>(us));
                const u64 prior = mEntry->mCount.fetch_add(1);
                if (prior == 0) mEntry->mFirstUs.store(static_cast<u64>(us));
                u64 seen = mEntry->mMaxUs.load();
                while (static_cast<u64>(us) > seen &&
                       !mEntry->mMaxUs.compare_exchange_weak(seen, static_cast<u64>(us)))
                {
                }
            }
        };

        bool setupBatchNttEnabled()
        {
#if defined(ENABLE_LOGVOLE_CUDA)
            const char* value = std::getenv("LV_GPU_SETUP_BATCH_NTT");
            return (!value || value[0] != '0') && gpu::enabled();
#else
            return false;
#endif
        }

        bool setupForwardNtt(std::span<RnsPoly> polys, const RingNttContext& ctx)
        {
            if (setupBatchNttEnabled()) return forwardNttBatch(polys, ctx);
            for (auto& poly : polys)
            {
                if (!forwardNtt(poly, ctx)) return false;
            }
            return true;
        }

        // The Root socket frame contains CtR in coefficient domain. Keep its
        // exact receiver-owned bytes available for a direct device upload, but
        // publish the same NTT-domain host view as the eager setup when a real
        // device decline reaches the CPU path. Per-poly forwardNtt is explicitly
        // host-only, so a failed GPU attempt cannot be replayed on the device.
        class RootCtRNttWireState final : public LazyRingTensorHostState
        {
        public:
            RootCtRNttWireState(std::shared_ptr<const LazyRingTensorHostState> wire,
                RingNttContext ctx)
                : mWire(std::move(wire)), mCtx(std::move(ctx)) {}

            std::span<const u8> encodedCoefficients() const override
            {
                return mWire->encodedCoefficients();
            }

            const RingTensor& get() const override
            {
                std::call_once(mOnce, [&] {
                    HostStep phase("setup root: CtR host forward NTT fallback");
                    mHost = mWire->get();
                    for (auto& poly : mHost.mPolys)
                    {
                        if (!forwardNtt(poly, mCtx))
                            throw std::runtime_error("LogVole CtR host NTT fallback failed");
                    }
                });
                return mHost;
            }

        private:
            std::shared_ptr<const LazyRingTensorHostState> mWire;
            RingNttContext mCtx;
            mutable std::once_flag mOnce;
            mutable RingTensor mHost;
        };

        double safeLog2(double value)
        {
            return (value > 0.0) ? std::log2(value) : -std::numeric_limits<double>::infinity();
        }

        // words = 2^bits - 1, i.e. the low `bits` bits set.
        void setLowBitMask(u64* words, std::size_t wordCount, u32 bits)
        {
            for (std::size_t w = 0; w < wordCount; ++w)
            {
                const u64 offset = static_cast<u64>(w) * 64;
                if (offset >= bits)
                {
                    words[w] = 0;
                }
                else if (offset + 64 <= bits)
                {
                    words[w] = ~u64(0);
                }
                else
                {
                    words[w] = (u64(1) << (bits - static_cast<u32>(offset))) - 1;
                }
            }
        }

        void maskLowBitsInplace(u64* words, std::size_t wordCount, u32 bits)
        {
            for (std::size_t w = 0; w < wordCount; ++w)
            {
                const u64 offset = static_cast<u64>(w) * 64;
                if (offset >= bits)
                {
                    words[w] = 0;
                }
                else if (offset + 64 > bits)
                {
                    words[w] &= (u64(1) << (bits - static_cast<u32>(offset))) - 1;
                }
            }
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
            const std::size_t rho = ringModulusCount(ctx);
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
                        log2DeltaJ += safeLog2(static_cast<double>(ringModulusValue(ctx, w)));
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

        // Ct2SeedMode::PublicSeed feasibility. With no grinding, a sampled ct2
        // coefficient is bad exactly when its CRT lift lands in a window of length
        // 2B inside a Delta_j-sized residue interval, which for a random-oracle
        // seed happens with probability at most 2B / Delta_j. Requiring that to be
        // at most 2^-lambda for every limb is the whole correctness condition, and
        // it replaces both the golden-seed retry budget and the per-attempt
        // rounding check.
        // -log2 of the worst-case probability that a sampled ct2 coefficient is
        // bad, i.e. min_j (log2(Delta_j) - log2(2B)). Returns -inf when the noise
        // bound or the limb layout is unusable.
        double noGoldenSeedFailureBitsImpl(const Params& params, const RingNttContext& ctx)
        {
            const std::size_t rho = ringModulusCount(ctx);
            if (!validatePlaintextTargetLimbLayout(params, rho))
            {
                return -std::numeric_limits<double>::infinity();
            }

            const double log2B = estimateNoiseBoundLog2(params);
            if (!std::isfinite(log2B))
            {
                return -std::numeric_limits<double>::infinity();
            }

            double worst = std::numeric_limits<double>::infinity();
            for (std::size_t j = 0; j < rho; ++j)
            {
                double log2DeltaJ = 0.0;
                for (std::size_t w = 0; w < rho; ++w)
                {
                    if (w != j)
                    {
                        log2DeltaJ += safeLog2(static_cast<double>(ringModulusValue(ctx, w)));
                    }
                }

                if (!std::isfinite(log2DeltaJ))
                {
                    return -std::numeric_limits<double>::infinity();
                }
                worst = std::min(worst, log2DeltaJ - (log2B + 1.0));
            }
            return worst;
        }

        bool validateNoGoldenSeedBudgetImpl(const Params& params, const RingNttContext& ctx)
        {
            const double failureBits = noGoldenSeedFailureBitsImpl(params, ctx);
            return std::isfinite(failureBits) &&
                   failureBits >= static_cast<double>(params.mCt2StatBits);
        }

        struct RoundingCheckConstants
        {
            std::size_t mTargetLimbIndex = 0;
            AlignedUnVec<std::size_t> mSrcLimbIndices;
            std::vector<seal::util::MultiplyUIntModOperand> mCrtInvPunctured;
            AlignedUnVec<wideU64> mFracInvModulus;
            wideU64 mMargin{};
        };

        bool buildRoundingCheckConstants(
            const Params& params,
            const RingNttContext& ctx,
            std::vector<RoundingCheckConstants>& out)
        {
            const auto hostContext = getRingHostContext(ctx);
            auto contextData = hostContext ? hostContext->key_context_data() : nullptr;
            if (!contextData || !validateGoldenSeedSearchBudget(params, ctx))
            {
                return false;
            }

            const std::size_t rho = ringModulusCount(ctx);
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
                    constants.mCrtInvPunctured.resize(reducedCount);
                    resizeZero(constants.mFracInvModulus, reducedCount);

                    for (std::size_t idx = 0; idx < reducedCount; ++idx)
                    {
                        const std::size_t w = constants.mSrcLimbIndices[idx];
                        constants.mCrtInvPunctured[idx] = reducedInvPunct[idx];
                        constants.mFracInvModulus[idx] = reciprocal2Pow128Wide(fullBase.base()[w].value());
                    }
                }

                const long double marginExp = static_cast<long double>(log2B - log2DeltaJ + 128.0);
                constants.mMargin = floorToWideU64(std::exp2(marginExp));
            }

            out = std::move(rounding);
            return true;
        }

        bool buildLeafRoundingCheckConstants(const Params& params, const RingNttContext& ctx,
            RoundingCheckConstants& out)
        {
            LeafGoldenSeedRoundingConstants leaf;
            if (!leafGoldenSeedRoundingConstants(params, ctx, leaf)) return false;
            const auto& moduli = getRingHostModuli(ctx);
            if (moduli.size() != leaf.mInverse.size()) return false;
            out.mSrcLimbIndices.resize(moduli.size());
            out.mCrtInvPunctured.resize(moduli.size());
            out.mFracInvModulus.resize(moduli.size());
            out.mMargin = makeWideU64(leaf.mMarginLo, leaf.mMarginHi);
            for (std::size_t i = 0; i < moduli.size(); ++i)
            {
                out.mSrcLimbIndices[i] = i;
                out.mCrtInvPunctured[i].set(leaf.mInverse[i], moduli[i]);
                out.mFracInvModulus[i] = makeWideU64(leaf.mReciprocalLo[i], leaf.mReciprocalHi[i]);
            }
            return true;
        }

        bool checkRoundingPolynomial(const RingNttContext& ctx,
            const RoundingCheckConstants& constants, const RnsPoly& poly, bool& accepted)
        {
            const auto& hostModuli = getRingHostModuli(ctx);
            if (!validateRingPolyShape(poly, ctx.mParams) ||
                hostModuli.size() != ringModulusCount(ctx)) return false;
            const auto n = ctx.mParams.mPolyModulusDegree;
            const u64* values = poly.mCoeffs.data();
            if (detail::cpuCheckRoundingMargin(values, n, hostModuli,
                constants.mSrcLimbIndices, constants.mCrtInvPunctured,
                constants.mFracInvModulus, constants.mMargin, accepted)) return true;
            accepted = true;
            for (std::size_t coeffIdx = 0; coeffIdx < n; ++coeffIdx)
            {
                wideU64 sumFrac = wideU64OneShift(127);
                for (std::size_t idx = 0; idx < constants.mSrcLimbIndices.size(); ++idx)
                {
                    const std::size_t w = constants.mSrcLimbIndices[idx];
                    const u64 xw = seal::util::multiply_uint_mod(
                        values[w*n+coeffIdx], constants.mCrtInvPunctured[idx], hostModuli[w]);
                    sumFrac = wideU64Add(sumFrac, wideU64MulLow(xw, constants.mFracInvModulus[idx]));
                }
                if (wideU64Less(sumFrac, constants.mMargin) ||
                    wideU64Less(wideU64Negate(sumFrac), constants.mMargin))
                {
                    accepted = false;
                    break;
                }
            }
            return true;
        }

        bool checkGoldenPolynomial(const Params& params, const RingNttContext& ctx,
            const std::vector<RoundingCheckConstants>& rounding, const RnsPoly& poly,
            std::size_t sampledPolyIdx, bool& accepted)
        {
            std::size_t target = 0;
            if (!resolvePlaintextTargetLimbForSampledPoly(params, sampledPolyIdx, ringModulusCount(ctx), target) ||
                target >= rounding.size() || rounding[target].mTargetLimbIndex != target) return false;
            return checkRoundingPolynomial(ctx, rounding[target], poly, accepted);
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

        LencLacct toLencLacct(const ReceiverState& state)
        {
            const auto& lacct = state.mRootLacctLeft;
            LencLacct out{};
            out.mWidthPadded = lacct.mWidthPadded;
            out.mLevels = lacct.mLevels;
            if (state.mRootLacctLeftWire)
            {
                HostStep phase("setup root: Lacct host fallback");
                out.mCt = state.mRootLacctLeftWire->get();
            }
            else out.mCt = lacct.mCt;
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
            if (!makeRingNttContext(state.mParams.mShrinkExpand.mRing, ctx))
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
#if defined(ENABLE_LOGVOLE_CUDA)
            // Same economics as the gadget decomposition: denoiseComb is 128-bit
            // fixed-point CRT per coefficient, so it is instruction bound and the
            // arithmetic covers the round trip even at the Root's 4 polynomials.
            if (gpu::enabled() && !input.empty())
            {
                if (auto dev = gpu::upload(ctx, std::span<const RnsPoly>(input.data(), input.size())))
                {
                    gpu::DeviceBatchPtr aggDev;
                    std::vector<RnsPoly> aggHost;
                    if (gpu::denoiseAndAggDevice(ctx, *dev, tauHi, aggDev) && aggDev &&
                        gpu::download(*aggDev, aggHost, 1) && aggHost.size() == 1)
                    {
                        out = std::move(aggHost[0]);
                        return true;
                    }
                }
            }
#endif
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

        // Experimental support for a final recursive Root whose logical width is
        // smaller than the truncated shrink/expand block.  The established Root
        // shape remains the only accepted one unless the switch is explicitly
        // enabled; in particular, exact-width alpha=2/alpha=4 runs do not consult
        // the environment or take a different path.
        bool partialRootWidthEnabled()
        {
            const char* value = std::getenv("LV_PARTIAL_ROOT_WIDTH");
            return value != nullptr && std::strcmp(value, "1") == 0;
        }

        bool validRootWidth(u32 w, u32 muHi)
        {
            return w == muHi ||
                   (w != 0u && w < muHi && partialRootWidthEnabled());
        }

#if defined(ENABLE_LOGVOLE_CUDA)
        u32 defaultPublicSenderCt2PrefetchLevels(const SenderState& state)
        {
            // Bound the extra live sampler outputs to the measured H200
            // PublicSeed geometry. Other requests keep the established order.
            const auto& params = state.mParams;
            const auto& se = params.mShrinkExpand;
            const auto& ring = se.mRing;
            if (params.mCt2SeedMode != Ct2SeedMode::PublicSeed ||
                params.mCt2StatBits != 127u ||
                (params.mTotalLabelCount != (u64{1} << 24u) &&
                 params.mTotalLabelCount != (u64{1} << 25u)) ||
                se.mNumWorkerThreads != 8u || se.mAlpha != 2u ||
                se.mPlaintextModulusBits != 52u || se.mGadgetLogBase != 208u ||
                ring.mPolyModulusDegree != 16384u || ring.mCoeffModulusBits.size() != 8u ||
                !std::all_of(ring.mCoeffModulusBits.begin(), ring.mCoeffModulusBits.end(),
                    [](int bits) { return bits == 52; }))
            {
                return 0u;
            }
            static const bool h200 = gpu::deviceDescription().find("H200") != std::string::npos;
            return h200 ? 2u : 0u;
        }

        // Depth three is a small but repeatable win at the measured 2^24 and
        // 2^25 request sizes. Keep every other size on the established
        // two-level schedule, and independently cap the exact extra ct2 output
        // that the third recursive frame would keep live. The environment
        // override is applied later by topSenderCt2PrefetchLevels().
        u32 defaultTopSenderCt2PrefetchLevels(const SenderState& state)
        {
            constexpr u32 kBaselineLevels = 2u;
            constexpr u32 kAdaptiveLevels = 3u;
            constexpr u64 kLabels24 = u64{ 1 } << 24;
            constexpr u64 kLabels25 = u64{ 1 } << 25;
            constexpr u64 kMaxThirdOutputBytes = u64{ 256 } << 20;

            if (state.mParams.mTotalLabelCount != kLabels24 &&
                state.mParams.mTotalLabelCount != kLabels25)
            {
                return kBaselineLevels;
            }

            // The budget counts the current frame, so follow two child links to
            // find the frame whose ct2 becomes the third prefetched output.
            const SenderState* third = &state;
            for (u32 depth = 1u; depth < kAdaptiveLevels; ++depth)
            {
                if (!third->mNextLevelState) return kBaselineLevels;
                third = third->mNextLevelState.get();
            }
            // Root frames do not prefetch: there must be another child for this
            // frame to enter the internal recursion path.
            if (!third->mNextLevelState) return kBaselineLevels;

            u32 muHi = 0;
            if (!computeMuHi(third->mParams, muHi)) return kBaselineLevels;
            const u32 chunkCount = computeWDoublePrime(third->mParams, muHi);
            const u32 sampleMu = third->mShrinkExpandState.mParams.mMu;
            const u64 polyWords = ringPolyCoeffCount(
                third->mShrinkExpandState.mParams.mRing);
            if (chunkCount == 0u || sampleMu == 0u || polyWords == 0u ||
                polyWords > kMaxThirdOutputBytes / sizeof(u64))
            {
                return kBaselineLevels;
            }

            // This mirrors sampleCt2BatchWithScratch exactly: the allocation is
            // chunkCount * sampler-mu full RNS polynomials, including padding.
            const u64 rows = static_cast<u64>(chunkCount) * sampleMu;
            const u64 maxRows =
                kMaxThirdOutputBytes / (polyWords * sizeof(u64));
            return rows <= maxRows ? kAdaptiveLevels : kBaselineLevels;
        }
#endif

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

        // Same 16 bytes the golden-seed search draws, so everything downstream of
        // the seed - the instance derivation, the ct2 sampler, the wire format -
        // is unchanged; only where the seed comes from differs.
        constexpr std::size_t kCt2SeedBytes = 16;

        const RnsPoly* resolveRootMaskDigest(const SenderState& state)
        {
            if (state.mRootDPrimeRt)
            {
                return state.mRootDPrimeRt.get();
            }

            return state.mNextLevelState ? resolveRootMaskDigest(*state.mNextLevelState) : nullptr;
        }

        const block* resolveRootMaskDigestHash(const SenderState& state)
        {
            if (state.mRootDPrimeRt && state.mRootDPrimeHashValid)
            {
                return &state.mRootDPrimeHash;
            }

            return state.mNextLevelState ? resolveRootMaskDigestHash(*state.mNextLevelState) : nullptr;
        }

        const RnsPoly* resolveRootMaskDigest(const ReceiverState& state)
        {
            if (state.mRootDPrimeRt)
            {
                return state.mRootDPrimeRt.get();
            }

            return state.mNextLevelState ? resolveRootMaskDigest(*state.mNextLevelState) : nullptr;
        }

        // The PublicSeed ct2 seed, from the two things both parties hold once the
        // root digest has been exchanged: the session id and the root digest
        // itself. The receiver derives the identical bytes in
        // finalizeRootResponseReceiver.
        bool derivePublicCt2SeedForState(const SenderState& state, AlignedUnVec<u8>& out)
        {
            const block* rootMaskDigestHash = resolveRootMaskDigestHash(state);
            if (rootMaskDigestHash == nullptr)
            {
                return false;
            }

            AlignedUnVec<u8> seed(kCt2SeedBytes);
            derivePublicCt2Seed(
                state.mParams.mSessionId,
                *rootMaskDigestHash,
                std::span<u8>(seed.data(), seed.size()),
                state.mParams.mOnlineMode);
            out = std::move(seed);
            return true;
        }

        struct RecursiveSeedEvalOutput
        {
            bool mValid = false;
            std::vector<RnsPoly> mTbk;
#if defined(ENABLE_LOGVOLE_CUDA)
            // When the GPU backend is active the tbk chain is passed between
            // recursion levels as a device buffer and mTbk stays empty until the
            // top level needs it on the host. Downloading it at every level was
            // measured to be the single largest cost of the online phase.
            gpu::DeviceBatchPtr mTbkDevice;
            // The deferred GoldenSeed path has produced this batch but has not
            // yet read its predicate. Its parent must fuse that check into the
            // denoise consuming the batch; only the top batch is checked alone.
            bool mValidationPending = false;
#endif
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

        bool evalRootTopCtNtt(
            const ReceiverState& state,
            const RingNttContext& ctx,
            const RnsPoly& yLeft,
            const std::vector<RnsPoly>& zeta,
            const std::vector<RnsPoly>& cachedInputsNtt,
            std::vector<RnsPoly>& out)
        {
            // Socket setup keeps TopCt in the independently owned received
            // frame until a declined GPU path actually needs host polynomials.
            const RingTensor* topCtView = &state.mRootTopCt;
            if (state.mRootTopCtWire)
            {
                HostStep phase("setup root: TopCt host fallback");
                topCtView = &state.mRootTopCtWire->get();
            }
            const RingTensor& topCt = *topCtView;
            u32 tauHi = 0;
            if (!computeTauHi(state.mParams, tauHi) ||
                topCt.mRows == 0 ||
                topCt.mCols != tauHi + state.mRootRandomizerWidth ||
                zeta.size() != state.mRootRandomizerWidth ||
                !validateRingBatchShape(topCt.mPolys, ctx.mParams))
            {
                return false;
            }

            // The digest step already built NTT(gadget(yLeft) ++ zeta) to form its
            // own inner products, in this exact order. Recomputing it here was a
            // gadget decomposition and four forward transforms per query.
            std::vector<RnsPoly> owned;
            const std::vector<RnsPoly>* inputsNtt = &cachedInputsNtt;
            if (cachedInputsNtt.size() != static_cast<std::size_t>(tauHi) + zeta.size())
            {
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

                owned.resize(yDecomp.size() + zeta.size());
                for (std::size_t idx = 0; idx < yDecomp.size(); ++idx)
                {
                    owned[idx] = std::move(yDecomp[idx]);
                }
                for (std::size_t idx = 0; idx < zeta.size(); ++idx)
                {
                    owned[yDecomp.size() + idx] = zeta[idx];
                }
                // yDecomp and zeta concatenated. All independent, so batch them into
                // one dispatch instead of a transform per polynomial.
                if (!forwardNttBatch(owned, ctx))
                {
                    return false;
                }
                inputsNtt = &owned;
            }
            const std::vector<RnsPoly>& inputs = *inputsNtt;

            std::vector<RnsPoly> next(topCt.mRows);
            for (u32 row = 0; row < topCt.mRows; ++row)
            {
                RnsPoly acc{};
                resizeZero(acc.mCoeffs, ringPolyCoeffCount(ctx.mParams));
                for (u32 col = 0; col < topCt.mCols; ++col)
                {
                    const auto& ctPoly = topCt.mPolys[ringTensorIndex(topCt, row, col)];
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
        std::vector<RnsPoly>& out,
        u32 requestedWorkers)
    {
        if (count == 0 || sigma < 0.0 || maxDeviation < 0.0)
        {
            return false;
        }

        std::vector<RnsPoly> next(count);
#if defined(ENABLE_LOGVOLE_CUDA)
        const char* compactSetting = std::getenv("LV_GPU_SETUP_ROOT_COMPACT_NOISE");
        const bool compactRequested = gpu::enabled() && (!compactSetting || compactSetting[0] != '0');
        const char* strictSetting = std::getenv("LV_GPU_SETUP_ROOT_COMPACT_NOISE_STRICT");
        const bool compactStrict = compactRequested && strictSetting && strictSetting[0] != '0';
        if (gpu::enabled() && (sigma > 0.0 || compactRequested) && canSamplePolyErrorCompact(ctx, sigma, maxDeviation))
        {
            HostStep step("setup: root compact error sampling");
            std::vector<seal::prng_seed_type> seeds(count);
            if (sigma > 0.0)
                for (auto& seed : seeds) prng.get(seed.data(), seed.size());
            const std::size_t n = ctx.mParams.mPolyModulusDegree;
            if (!n || count > std::numeric_limits<std::size_t>::max() / n) return false;
            std::vector<u64> compact;
            std::shared_ptr<gpu::DeviceScalars> residentNoise;
            if (sigma > 0.0)
            {
                if (!samplePolyErrorCompactBatchForSetup(compact, residentNoise, sigma, maxDeviation,
                        seeds, ctx, requestedWorkers)) return false;
            }
            else compact.resize(static_cast<std::size_t>(count) * n, 0);
            if (compactRequested)
            {
                const char* decline = std::getenv("LV_GPU_SETUP_ROOT_COMPACT_NOISE_FORCE_DECLINE");
                if ((!decline || decline[0] != '1') && (residentNoise
                        ? gpu::expandErrorCompactDevice(ctx, *residentNoise, outputNtt, next, 0, requestedWorkers)
                        : gpu::expandRootErrorCompactDevice(ctx, compact, outputNtt, next, requestedWorkers)))
                {
                    out = std::move(next);
                    return true;
                }
                if (compactStrict) return false;
            }
            if (residentNoise && !materializePolyErrorCompactBatchForSetup(compact, residentNoise,
                    sigma, maxDeviation, seeds, ctx, requestedWorkers)) return false;
            if (!detail::runParallelTasks(count, requestedWorkers, [&](std::size_t i) {
                    return expandPolyErrorCompact(std::span<const u64>(compact).subspan(i * n, n), next[i], ctx);
                }) || (outputNtt && !forwardNttBatch(next, ctx))) return false;
            out = std::move(next);
            return true;
        }
        if (compactStrict) return false;
#endif
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

    bool sampleRootErrorBatch(
        const RingNttContext& ctx, u32 count, PRNG& prng, double sigma,
        double maxDeviation, bool outputNtt, std::vector<RnsPoly>& out)
    {
        return sampleRootErrorBatch(ctx, count, prng, sigma, maxDeviation, outputNtt, out, 1);
    }

#if defined(ENABLE_LOGVOLE_CUDA)
    namespace
    {
        class SeededRootErrorHostState final : public LazyRootErrorHostState
        {
        public:
            SeededRootErrorHostState(RingNttContext ctx, std::size_t count,
                double sigma, double clip, u32 workers,
                std::vector<seal::prng_seed_type> seeds,
                std::vector<u64> compact, std::shared_ptr<gpu::DeviceScalars> resident)
                : mCtx(std::move(ctx)), mCount(count), mSigma(sigma), mClip(clip),
                  mWorkers(workers), mSeeds(std::move(seeds)),
                  mCompact(std::move(compact)), mResident(std::move(resident)) {}

            std::size_t count() const override { return mCount; }
            bool matches(const RingParams& params) const override
            {
                return mCtx.mParams == params;
            }
            const std::vector<RnsPoly>& hostCoefficients() const override
            {
                std::call_once(mOnce, [&] {
                    HostStep hostStep("setup: root r1 explicit host fallback");
                    const std::size_t n = mCtx.mParams.mPolyModulusDegree;
                    if (!n || mCount > std::numeric_limits<std::size_t>::max() / n)
                        throw std::runtime_error("invalid Root r1 shape");
                    if (mSigma > 0.0 &&
                        !materializePolyErrorCompactBatchForSetup(mCompact,
                            mResident, mSigma, mClip, mSeeds, mCtx, mWorkers))
                        throw std::runtime_error("Root r1 compact host fallback failed");
                    if (mCompact.size() != mCount * n)
                        throw std::runtime_error("invalid Root r1 compact size");
                    std::vector<RnsPoly> next(mCount);
                    if (!detail::runParallelTasks(mCount, mWorkers, [&](std::size_t row) {
                            return expandPolyErrorCompact(
                                std::span<const u64>(mCompact).subspan(row * n, n),
                                next[row], mCtx);
                        })) throw std::runtime_error("Root r1 host expansion failed");
                    mHost = std::move(next);
                });
                return mHost;
            }

        private:
            RingNttContext mCtx;
            std::size_t mCount = 0;
            double mSigma = 0.0;
            double mClip = 0.0;
            u32 mWorkers = 1;
            std::vector<seal::prng_seed_type> mSeeds;
            mutable std::vector<u64> mCompact;
            std::shared_ptr<gpu::DeviceScalars> mResident;
            mutable std::once_flag mOnce;
            mutable std::vector<RnsPoly> mHost;
        };

        class SeededRootSecretHostState final : public LazyRootSecretHostState
        {
        public:
            SeededRootSecretHostState(RingNttContext ctx,
                std::vector<seal::prng_seed_type> rowSeeds)
                : mCtx(std::move(ctx)), mRowSeeds(std::move(rowSeeds)) {}

            std::size_t count() const override { return mRowSeeds.size(); }
            bool matches(const RingParams& params) const override
            {
                return mCtx.mParams == params;
            }
            const std::vector<RnsPoly>& hostCoefficients() const override
            {
                std::call_once(mOnce, [&] {
                    HostStep step("setup: root skRRt explicit host fallback");
                    std::vector<RnsPoly> next(mRowSeeds.size());
                    for (std::size_t row = 0; row < mRowSeeds.size(); ++row)
                        next[row] = sampleUniformPolyFromSeed(mCtx, mRowSeeds[row]);
                    if (!validateRingBatchShape(next, mCtx.mParams))
                        throw std::runtime_error("Root skRRt seed replay failed");
                    mHost = std::move(next);
                });
                return mHost;
            }

        private:
            RingNttContext mCtx;
            std::vector<seal::prng_seed_type> mRowSeeds;
            mutable std::once_flag mOnce;
            mutable std::vector<RnsPoly> mHost;
        };

        bool sampleRootErrorBatchResident(
            const RingNttContext& ctx, u32 count, PRNG& prng, double sigma,
            double clip, u32 workers,
            std::shared_ptr<const LazyRootErrorHostState>& hostState,
            gpu::DeviceBatchPtr& device)
        {
            if (!count || !canSamplePolyErrorCompact(ctx, sigma, clip) ||
                !ctx.mParams.mPolyModulusDegree ||
                count > std::numeric_limits<std::size_t>::max() /
                    ctx.mParams.mPolyModulusDegree) return false;
            HostStep step("setup: root compact error sampling");
            std::vector<seal::prng_seed_type> seeds(count);
            if (sigma > 0.0)
                for (auto& seed : seeds) prng.get(seed.data(), seed.size());
            std::vector<u64> compact;
            std::shared_ptr<gpu::DeviceScalars> resident;
            if (sigma > 0.0)
            {
                if (!samplePolyErrorCompactBatchForSetup(compact, resident, sigma,
                        clip, seeds, ctx, workers)) return false;
            }
            else compact.resize(static_cast<std::size_t>(count) *
                ctx.mParams.mPolyModulusDegree, 0);
            device = gpu::expandRootErrorCompactToBatch(ctx, compact,
                resident.get(), count);
            hostState = std::make_shared<SeededRootErrorHostState>(ctx, count,
                sigma, clip, workers, std::move(seeds), std::move(compact),
                std::move(resident));
            return true;
        }
    }
#endif

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

        const auto& hostModuli = getRingHostModuli(ctx);
        if (hostModuli.size() != ringModulusCount(ctx)) return false;
        const u64 shift = static_cast<u64>(gadgetLogBase) * power;
        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        for (std::size_t modIdx = 0; modIdx < hostModuli.size(); ++modIdx)
        {
            const auto& modulus = hostModuli[modIdx];
            const u64 mod = modulus.value();
            const u64 factor = detail::pow2Mod(shift, mod);
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
        for (std::size_t modIdx = 0; modIdx < ringModulusCount(ctx); ++modIdx)
        {
            const u64 mod = ringModulusValue(ctx, modIdx);
            if (mod < 2) return false;
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

    namespace
    {
        constexpr u64 kRootBStarPublicNonce = 0x52544E43524F4F54ull;
        constexpr u64 kRootBStarPublicDomain = 0xB57A52u;
    }

    bool buildRootTopCt(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& r1,
        const std::vector<RnsPoly>& r2NttInput,
        const std::vector<RnsPoly>& publicBRootNtt,
        const std::vector<RnsPoly>& publicBStarNtt,
        u32 gadgetLogBase,
        u32 gadgetPowerOffset,
        PRNG& prng,
        double noiseStandardDeviation,
        double noiseMaxDeviation,
        RingTensor& out,
        u32 requestedWorkers,
        std::shared_ptr<const LazyLencRandomizerState> randomizers,
        std::shared_ptr<const LazyRingTensorHostState>* deferredCiphertext,
        const gpu::RetainedPublicUniform* retainedPublicBFullNtt,
        const gpu::DeviceBatch* rootR1Device,
        const LazyRootErrorHostState* rootR1Host,
        const gpu::RetainedPublicUniform* retainedBStarNtt)
    {
        HostStep setupStep("setup: root ciphertext");
        const auto r1Count = rootR1Host ? rootR1Host->count() : r1.size();
        if (r1Count > std::numeric_limits<u32>::max()) return false;
        const u32 leftWidth = static_cast<u32>(r1Count);
#if defined(ENABLE_LOGVOLE_CUDA)
        const bool rootBatchValid = !rootR1Device || !gpu::enabled() ||
            (rootR1Host && gpu::rootErrorBatchMatches(ctx, *rootR1Device, leftWidth));
#else
        const bool rootBatchValid = !rootR1Device;
#endif
        u32 tauHi = static_cast<u32>(publicBRootNtt.size());
        if (publicBStarNtt.size() > std::numeric_limits<u32>::max())
            return false;
        u32 randomizer = static_cast<u32>(publicBStarNtt.size());
#if defined(ENABLE_LOGVOLE_CUDA)
        if (retainedBStarNtt)
        {
            if (retainedBStarNtt->count() > std::numeric_limits<u32>::max())
                return false;
            randomizer = static_cast<u32>(retainedBStarNtt->count());
        }
#endif
        if (publicBRootNtt.size() > std::numeric_limits<u32>::max()) return false;
#if defined(ENABLE_LOGVOLE_CUDA)
        if (retainedPublicBFullNtt)
        {
            const std::size_t fullCount = retainedPublicBFullNtt->count();
            if (!publicBRootNtt.empty() || fullCount < 4u || (fullCount & 1u) != 0 ||
                fullCount / 2u - 1u >= std::numeric_limits<u32>::max() ||
                !gpu::retainedPublicUniformMatches(ctx, *retainedPublicBFullNtt,
                    fullCount, true) ||
                retainedLencPublicBNtt(ctx, static_cast<u32>(fullCount / 2u)).get() !=
                    retainedPublicBFullNtt) return false;
            tauHi = static_cast<u32>(fullCount / 2u - 1u);
        }
#else
        if (retainedPublicBFullNtt) return false;
#endif
#if defined(ENABLE_LOGVOLE_CUDA)
        const bool bStarOwnerValid = !retainedBStarNtt ||
            (publicBStarNtt.empty() && gpu::retainedRootBStarNttMatches(
                ctx, *retainedBStarNtt, randomizer));
#else
        const bool bStarOwnerValid = !retainedBStarNtt;
#endif
        if (leftWidth == 0 || (randomizers ? randomizers->count() : r2NttInput.size()) != leftWidth || tauHi == 0 || randomizer == 0 ||
            (rootR1Host && (!r1.empty() || !rootR1Host->matches(ctx.mParams) ||
                rootR1Host->count() != leftWidth)) ||
            !rootBatchValid ||
            (!rootR1Host && !validateRingBatchShape(r1, ctx.mParams)) ||
            (randomizers ? (!r2NttInput.empty() || !randomizers->matches(ctx.mParams))
                         : !validateRingBatchShape(r2NttInput, ctx.mParams)) ||
            (!retainedPublicBFullNtt && !validateRingBatchShape(publicBRootNtt, ctx.mParams)) ||
            !bStarOwnerValid ||
            (!retainedBStarNtt &&
                !validateRingBatchShape(publicBStarNtt, ctx.mParams)))
        {
            return false;
        }

#if defined(ENABLE_LOGVOLE_CUDA)
        const char* deviceSetting = std::getenv("LV_GPU_SETUP_ROOT_DEVICE");
        const bool deviceRequested = (!deviceSetting || deviceSetting[0] != '0') && gpu::enabled();
        const char* compactSetting = std::getenv("LV_GPU_SETUP_ROOT_COMPACT_NOISE");
        const bool compactRequested = deviceRequested && (!compactSetting || compactSetting[0] != '0');
        const char* compactStrictSetting = std::getenv("LV_GPU_SETUP_ROOT_COMPACT_NOISE_STRICT");
        const bool compactStrict = compactRequested && compactStrictSetting && compactStrictSetting[0] != '0';
        const bool compactNoise = compactRequested &&
            canSamplePolyErrorCompact(ctx, noiseStandardDeviation, noiseMaxDeviation);
        if (compactStrict && !compactNoise) return false;
#else
        constexpr bool deviceRequested = false;
        constexpr bool compactNoise = false;
#endif
        std::vector<RnsPoly> publicBRootFallback;
        std::vector<RnsPoly> publicBStarFallback;
        const auto ensurePublicBRootHost = [&] {
            if (!retainedPublicBFullNtt || !publicBRootFallback.empty()) return true;
            const auto full = sharedLencPublicBNtt(ctx, tauHi + 1u);
            if (!full || full->size() != 2u * static_cast<std::size_t>(tauHi + 1u) ||
                !validateRingBatchShape(*full, ctx.mParams)) return false;
            publicBRootFallback.assign(full->begin() + 1, full->begin() + 1 + tauHi);
            return true;
        };
        const auto ensurePublicBStarHost = [&] {
            if (!retainedBStarNtt || !publicBStarFallback.empty()) return true;
            HostStep fallbackStep("setup root: BStar exact host fallback");
            publicBStarFallback = deriveUniformPolyBatchFromNonce(
                ctx, kRootBStarPublicNonce, kRootBStarPublicDomain,
                randomizer, true);
            return publicBStarFallback.size() == randomizer &&
                validateRingBatchShape(publicBStarFallback, ctx.mParams);
        };
        if (!deviceRequested && !ensurePublicBRootHost()) return false;
        const std::vector<RnsPoly>* r1Host = &r1;
        std::vector<RnsPoly> r1Ntt;
        if (!deviceRequested)
        {
            if (rootR1Host) r1Host = &rootR1Host->hostCoefficients();
            r1Ntt = *r1Host;
            if (!setupForwardNtt(r1Ntt, ctx)) return false;
        }

        RingTensor next{};
        next.mRows = leftWidth;
        next.mCols = tauHi + randomizer;
        next.mPolys.resize(ringTensorSize(next));

        // Draw error seeds in the original row-major order, sample each error
        // independently, then transform them in one device batch. This preserves
        // every error and the caller's PRNG position. Reuse the output slots as
        // temporary error storage.
        const bool batchSetup = setupBatchNttEnabled() || deviceRequested;
        const bool batchNoise = noiseStandardDeviation > 0.0 && batchSetup;
        std::vector<u64> compact;
        std::shared_ptr<gpu::DeviceScalars> residentNoise;
        std::vector<seal::prng_seed_type> compactNoiseSeeds;
        if (compactNoise)
        {
            const std::size_t n = ctx.mParams.mPolyModulusDegree;
            if (!n || next.mPolys.size() > std::numeric_limits<std::size_t>::max() / n) return false;
            // Zero noise draws no seeds in the established root protocol.
            if (batchNoise)
            {
                auto& noiseSeeds = compactNoiseSeeds;
                noiseSeeds.resize(next.mPolys.size());
                for (auto& seed : noiseSeeds) prng.get(seed.data(), seed.size());
                if (!samplePolyErrorCompactBatchForSetup(compact, residentNoise, noiseStandardDeviation,
                        noiseMaxDeviation, noiseSeeds, ctx, requestedWorkers)) return false;
            }
            else compact.resize(next.mPolys.size() * n, 0);
        }
        else if (batchNoise)
        {
            std::vector<seal::prng_seed_type> noiseSeeds(next.mPolys.size());
            for (auto& seed : noiseSeeds) prng.get(seed.data(), seed.size());
            if (!detail::runParallelTasks(next.mPolys.size(), requestedWorkers,
                    [&](std::size_t idx) {
                        auto& noise = next.mPolys[idx];
                        resizeZero(noise.mCoeffs, ringPolyCoeffCount(ctx.mParams));
                        return addPolyErrorFromSeed(noise, noiseStandardDeviation,
                            noiseMaxDeviation, noiseSeeds[idx], ctx);
                    })) return false;
            if (!deviceRequested && !forwardNttBatch(next.mPolys, ctx)) return false;
        }

#if defined(ENABLE_LOGVOLE_CUDA)
        if (deviceRequested)
        {
            if (rootR1Host && !rootR1Device)
                r1Host = &rootR1Host->hostCoefficients();
            if (!batchNoise && !compactNoise && !detail::runParallelTasks(next.mPolys.size(), requestedWorkers,
                    [&](std::size_t idx) {
                        resizeZero(next.mPolys[idx].mCoeffs, ringPolyCoeffCount(ctx.mParams));
                        return true;
                    })) return false;
            if (gpu::assembleRootTopCtDevice(ctx, *r1Host, r2NttInput, publicBRootNtt,
                    publicBStarNtt, gadgetLogBase, gadgetPowerOffset, next.mPolys, next.mPolys,
                    compact, residentNoise.get(), requestedWorkers, randomizers.get(),
                    deferredCiphertext, retainedPublicBFullNtt,
                    rootR1Device, retainedBStarNtt))
            {
                out = std::move(next);
                return true;
            }
            const char* strict = std::getenv("LV_GPU_SETUP_ROOT_DEVICE_STRICT");
            if ((strict && strict[0] != '0') || compactStrict) return false;
            if (residentNoise && !materializePolyErrorCompactBatchForSetup(compact, residentNoise,
                    noiseStandardDeviation, noiseMaxDeviation, compactNoiseSeeds, ctx, requestedWorkers)) return false;
            // A declined device attempt preserves the exact sampled noise in
            // coefficient form. Transform it without drawing any new seeds.
            if (compactNoise && batchNoise &&
                !detail::runParallelTasks(next.mPolys.size(), requestedWorkers, [&](std::size_t i) {
                    const std::size_t n = ctx.mParams.mPolyModulusDegree;
                    return expandPolyErrorCompact(std::span<const u64>(compact).subspan(i * n, n), next.mPolys[i], ctx);
                })) return false;
            if (batchNoise && !forwardNttBatch(next.mPolys, ctx)) return false;
            if (rootR1Host) r1Host = &rootR1Host->hostCoefficients();
            r1Ntt = *r1Host;
            if (!setupForwardNtt(r1Ntt, ctx)) return false;
        }
#endif

        if (!ensurePublicBRootHost() || !ensurePublicBStarHost()) return false;
        const auto& publicBRootHost = retainedPublicBFullNtt
            ? publicBRootFallback : publicBRootNtt;
        const auto& publicBStarHost = retainedBStarNtt
            ? publicBStarFallback : publicBStarNtt;
        const auto& r2Ntt = randomizers ? randomizers->hostNtt() : r2NttInput;
        if (r2Ntt.size() != leftWidth || !validateRingBatchShape(r2Ntt, ctx.mParams)) return false;
        if (!detail::runParallelTasks(next.mPolys.size(), batchSetup ? requestedWorkers : 1,
            [&](std::size_t idx) {
                const u32 row = static_cast<u32>(idx / next.mCols);
                const u32 col = static_cast<u32>(idx % next.mCols);
                const RnsPoly& bNtt = (col < tauHi) ? publicBRootHost[col] : publicBStarHost[col - tauHi];
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

                if (batchNoise)
                {
                    if (!ringAddInplace(cellNtt, next.mPolys[ringTensorIndex(next, row, col)], ctx))
                        return false;
                }
                else if (noiseStandardDeviation > 0.0)
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

                next.mPolys[idx] = std::move(cellNtt);
                return true;
            })) return false;

        out = std::move(next);
        return true;
    }

    namespace
    {
        bool sampleRootZetaImpl(
            const RingNttContext& ctx,
            u32 randomizerWidth,
            u32 gadgetLogBase,
            PRNG* serialSource,
            std::span<const block> taskSeeds,
            u32 rangesPerPoly,
            std::vector<RnsPoly>& out,
            u32 requestedWorkers,
            bool forceFirstReject)
        {
            if (randomizerWidth == 0 || gadgetLogBase == 0 || rangesPerPoly == 0)
            {
                return false;
            }
            if (serialSource)
            {
                if (rangesPerPoly != 1u || !taskSeeds.empty() || forceFirstReject)
                    return false;
            }
            else if (taskSeeds.size() !=
                     static_cast<std::size_t>(randomizerWidth) * rangesPerPoly)
            {
                return false;
            }

            const std::size_t n = ctx.mParams.mPolyModulusDegree;
            const auto& hostModuli = getRingHostModuli(ctx);
            const std::size_t rho = hostModuli.size();
            if (rho != ringModulusCount(ctx)) return false;

            // A draw is gadgetLogBase + 1 bits wide, so the buffers are sized to that
            // and everything below is multi-precision. This used to be a pair of u64
            // and therefore capped the gadget base at 127 bits, which the no-golden-seed
            // parameter set (g = 208) exceeds. For g <= 127 the word count, the draw
            // order and the resulting values are unchanged.
            const u32 sampleBits = gadgetLogBase + 1;
            const std::size_t wordCount =
                (static_cast<std::size_t>(sampleBits) + 63) / 64;

            std::vector<RnsPoly> zeta(randomizerWidth);
            for (auto& poly : zeta)
            {
                resizeZero(poly.mCoeffs, n * rho);
            }

            // One coefficient range of one polynomial. The multi-precision
            // temporaries are per call so that ranges can run concurrently.
            const auto fillRange = [&](PRNG& source,
                                       u32 polyIdx,
                                       std::size_t coeffBegin,
                                       std::size_t coeffEnd,
                                       bool forceFirstCandidate) {
                auto pool = seal::MemoryManager::GetPool();
                auto eta = seal::util::allocate_zero_uint(wordCount, pool);
                auto sampleMask = seal::util::allocate_zero_uint(wordCount, pool);
                auto raw = seal::util::allocate_zero_uint(wordCount, pool);
                auto magnitude = seal::util::allocate_zero_uint(wordCount, pool);
                // eta = 2^gadgetLogBase - 1, sampleMask = 2^(gadgetLogBase+1) - 1.
                setLowBitMask(eta.get(), wordCount, gadgetLogBase);
                setLowBitMask(sampleMask.get(), wordCount, sampleBits);

                u64* coeffs = zeta[polyIdx].mCoeffs.data();
                for (std::size_t coeffIdx = coeffBegin; coeffIdx < coeffEnd; ++coeffIdx)
                {
                    bool rejected = false;
                    do
                    {
                        for (std::size_t w = 0; w < wordCount; ++w)
                        {
                            raw[w] = source.get<u64>();
                        }
                        maskLowBitsInplace(raw.get(), wordCount, sampleBits);
                        rejected = forceFirstCandidate ||
                            seal::util::is_equal_uint(
                                raw.get(), sampleMask.get(), wordCount);
                        forceFirstCandidate = false;
                    } while (rejected);

                    // Uniform on [-eta, eta]: one of the 2^(g+1) draws is rejected so
                    // that the remaining 2^(g+1)-1 map onto the interval bijectively.
                    const bool negative =
                        !seal::util::is_greater_than_uint(raw.get(), eta.get(), wordCount);
                    if (negative)
                    {
                        seal::util::sub_uint(eta.get(), raw.get(), wordCount, magnitude.get());
                    }
                    else
                    {
                        seal::util::sub_uint(raw.get(), eta.get(), wordCount, magnitude.get());
                    }

                    for (std::size_t modIdx = 0; modIdx < rho; ++modIdx)
                    {
                        const u64 mod = hostModuli[modIdx].value();
                        const u64 reduced =
                            seal::util::modulo_uint(magnitude.get(), wordCount, hostModuli[modIdx]);
                        coeffs[modIdx * n + coeffIdx] =
                            (negative && reduced != 0) ? (mod - reduced) : reduced;
                    }
                }
            };

            if (serialSource)
            {
                for (u32 polyIdx = 0; polyIdx < randomizerWidth; ++polyIdx)
                {
                    fillRange(*serialSource, polyIdx, 0, n, false);
                }
                out = std::move(zeta);
                return true;
            }

            const std::size_t taskCount = taskSeeds.size();
            const std::size_t chunk = (n + rangesPerPoly - 1) / rangesPerPoly;
            const bool ran = detail::runParallelTasks(
                taskCount,
                requestedWorkers,
                [&](std::size_t taskIdx) {
                    const u32 polyIdx =
                        static_cast<u32>(taskIdx / rangesPerPoly);
                    const std::size_t rangeIdx = taskIdx % rangesPerPoly;
                    const std::size_t begin = rangeIdx * chunk;
                    if (begin >= n) return true;
                    const std::size_t end = std::min(begin + chunk, n);
                    PRNG local(taskSeeds[taskIdx]);
                    fillRange(
                        local, polyIdx, begin, end,
                        forceFirstReject && taskIdx == 0u);
                    return true;
                });
            if (!ran)
            {
                return false;
            }

            out = std::move(zeta);
            return true;
        }
    }

    bool sampleRootZetaFromTaskSeeds(
        const RingNttContext& ctx,
        u32 randomizerWidth,
        u32 gadgetLogBase,
        std::span<const block> taskSeeds,
        u32 rangesPerPoly,
        std::vector<RnsPoly>& out,
        u32 requestedWorkers,
        bool forceFirstReject)
    {
        return sampleRootZetaImpl(
            ctx, randomizerWidth, gadgetLogBase, nullptr, taskSeeds,
            rangesPerPoly, out, requestedWorkers, forceFirstReject);
    }

    bool sampleRootZeta(
        const RingNttContext& ctx,
        u32 randomizerWidth,
        u32 gadgetLogBase,
        PRNG& prng,
        std::vector<RnsPoly>& out,
        u32 requestedWorkers)
    {
        const u32 workers = (requestedWorkers > 1u) ? requestedWorkers : 1u;
        if (workers == 1u)
        {
            return sampleRootZetaImpl(
                ctx, randomizerWidth, gadgetLogBase, &prng, {}, 1u, out,
                1u, false);
        }

        // Draw every task key from the parent before any parallel work. This is
        // the authoritative parent-stream consumption and is exactly the layout
        // accepted by sampleRootZetaFromTaskSeeds and the GPU hot path.
        std::vector<block> taskSeeds(
            static_cast<std::size_t>(randomizerWidth) * workers);
        prng.get(taskSeeds.data(), taskSeeds.size());
        return sampleRootZetaFromTaskSeeds(
            ctx, randomizerWidth, gadgetLogBase, taskSeeds, workers, out,
            workers, false);
    }

    bool rootInnerProductNtt(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& leftNtt,
        const std::vector<RnsPoly>& rightCoeff,
        RnsPoly& out,
        bool outputNtt)
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

        if (!outputNtt && !inverseNtt(accNtt, ctx))
        {
            return false;
        }

        out = std::move(accNtt);
        return true;
    }

#if defined(ENABLE_LOGVOLE_CUDA)
    class ReplicatedTopSecretHostState final : public LazySeedLabelHostState
    {
    public:
        ReplicatedTopSecretHostState(RingNttContext ctx,
            gpu::DeviceBatchPtr device,
            std::shared_ptr<const LazyRootSecretHostState> keyHost,
            u32 alpha, u32 tau, u64 ownerRunId, bool rootHi)
            : mCtx(std::move(ctx)), mDevice(std::move(device)),
              mKeyHost(std::move(keyHost)), mAlpha(alpha), mTau(tau),
              mOwnerRunId(ownerRunId), mRootHi(rootHi) {}
        std::size_t count() const override
        {
            return static_cast<std::size_t>(mRootHi ? 1u : mAlpha) *
                mTau * ringModulusCount(mCtx);
        }
        bool matches(const RingParams& params) const override
        {
            return mCtx.mParams == params;
        }
        const std::vector<RnsPoly>& hostCoefficients() const override
        {
            std::call_once(mOnce, [&] {
                if (currentProtocolCacheScope().mRole == ProtocolCacheRole::Receiver)
                    throw std::runtime_error("receiver cannot inspect sender top key");
                HostStep step(mRootHi ? "setup sender: Root high-key explicit host view"
                                      : "setup sender: top seed-label explicit host view");
                if (mDevice && gpu::enabled())
                {
                    ScopedProtocolCacheScope ownerScope(
                        ProtocolCacheRole::Sender, mOwnerRunId);
                    std::vector<RnsPoly> exact;
                    const bool matches = mRootHi
                        ? gpu::rootHiRepBatchMatches(mCtx, *mDevice,
                            count(), mOwnerRunId)
                        : gpu::setupSeedLabelRepBatchMatches(mCtx, *mDevice,
                            count(), mOwnerRunId);
                    if (matches && gpu::download(*mDevice, exact, count()) &&
                        validateRingBatchShape(exact, mCtx.mParams))
                    {
                        mHost = std::move(exact);
                        return;
                    }
                }
                if (!mKeyHost || mKeyHost->count() != mTau ||
                    !mKeyHost->matches(mCtx.mParams))
                    throw std::runtime_error("top-key host replay provenance failed");
                const auto& key = mKeyHost->hostCoefficients();
                const bool ok = mRootHi
                    ? replicateRootHiKeyByLimb(key, mTau, mCtx.mParams, mHost)
                    : seedLabelRepOfflineSenderInput(key, mTau, mAlpha,
                        mTau, mCtx.mParams, mHost);
                if (!ok || mHost.size() != count())
                    throw std::runtime_error("top-key repetition fallback failed");
            });
            return mHost;
        }
    private:
        RingNttContext mCtx;
        gpu::DeviceBatchPtr mDevice;
        std::shared_ptr<const LazyRootSecretHostState> mKeyHost;
        u32 mAlpha;
        u32 mTau;
        u64 mOwnerRunId;
        bool mRootHi;
        mutable std::once_flag mOnce;
        mutable std::vector<RnsPoly> mHost;
    };
#endif

    bool prepareRootOfflineSender(
        SenderState& state,
        PRNG& prng,
        RootOfflineMessage& message,
        bool deferRandomizerHost)
    {
        HostStep setupStep("setup sender: root total");
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

        const bool residentTopSk1 = deferRandomizerHost &&
            state.mShrinkExpandState.mSk1.empty() &&
            state.mShrinkExpandState.mTopSk1Device &&
            state.mShrinkExpandState.mLazyTopSk1 &&
            state.mShrinkExpandState.mLazyTopSk1->count() == tauHi &&
            state.mShrinkExpandState.mLazyTopSk1->matches(se.mRing);
        if (rho == 0 || (!residentTopSk1 &&
            (state.mShrinkExpandState.mSk1.size() != tauHi ||
             !validateRingBatchShape(state.mShrinkExpandState.mSk1, se.mRing))))
        {
            return false;
        }

        RingNttContext ctx{};
        if (!makeRingNttContext(se.mRing, ctx))
        {
            return false;
        }

        std::vector<RnsPoly> rootSkHi;
        std::shared_ptr<gpu::DeviceBatch> residentRootSkHi;
        std::shared_ptr<const LazySeedLabelHostState> lazyRootSkHi;
#if defined(ENABLE_LOGVOLE_CUDA)
        const u64 topOwnerRunId = state.mShrinkExpandState.mTopSk1OwnerRunId;
        if (residentTopSk1)
        {
            if (!gpu::topSecretUniformBatchMatches(ctx,
                    *state.mShrinkExpandState.mTopSk1Device,
                    tauHi, topOwnerRunId)) return false;
            const char* decline = std::getenv("LV_GPU_SETUP_TOP_SK1_ROOT_FORCE_DECLINE");
            const char* strict = std::getenv("LV_GPU_SETUP_TOP_SK1_CONSUMER_STRICT");
            if (!decline || decline[0] != '1')
                residentRootSkHi = gpu::rootHiReplicateResident(ctx,
                    *state.mShrinkExpandState.mTopSk1Device, tauHi);
            if (residentRootSkHi && !gpu::rootHiRepBatchMatches(ctx,
                    *residentRootSkHi, leftWidth, topOwnerRunId)) return false;
            if (!residentRootSkHi && strict && strict[0] != '0') return false;
            if (residentRootSkHi)
                lazyRootSkHi = std::make_shared<ReplicatedTopSecretHostState>(
                    ctx, residentRootSkHi,
                    state.mShrinkExpandState.mLazyTopSk1,
                    1u, tauHi, topOwnerRunId, true);
        }
#else
        if (residentTopSk1) return false;
#endif
        if (!residentRootSkHi)
        {
            const auto& hostKey = residentTopSk1
                ? state.mShrinkExpandState.mLazyTopSk1->hostCoefficients()
                : state.mShrinkExpandState.mSk1;
            if (!replicateRootHiKeyByLimb(hostKey, tauHi, se.mRing,
                    rootSkHi) || rootSkHi.size() != leftWidth) return false;
        }

        // The transport path needs B only on the GPU for LENC and TopCt.
        // Keep the direct/public Root API's eager host operands and let either
        // device consumer materialize the exact cached nonce values on decline.
        const char* rootTokenOption = std::getenv("LV_GPU_SETUP_ROOT_PUBLIC_B_TOKEN");
        const bool retainRootPublicB = deferRandomizerHost &&
            (!rootTokenOption || rootTokenOption[0] != '0');
        const auto retainedPublicBFullNtt = retainRootPublicB
            ? retainedLencPublicBNtt(ctx, tauFull) : nullptr;
        const auto sharedPublicBFullNtt = retainedPublicBFullNtt
            ? std::shared_ptr<const std::vector<RnsPoly>>{}
            : sharedLencPublicBNtt(ctx, tauFull);
        if (!retainedPublicBFullNtt && (!sharedPublicBFullNtt ||
            sharedPublicBFullNtt->size() != static_cast<std::size_t>(2) * tauFull))
            return false;

        std::vector<RnsPoly> publicBRootNtt;
        if (sharedPublicBFullNtt)
        {
            publicBRootNtt.resize(tauHi);
            for (u32 idx = 0; idx < tauHi; ++idx)
                publicBRootNtt[idx] = (*sharedPublicBFullNtt)[1 + idx];
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
                sharedPublicBFullNtt.get(),
                workerThreads, deferRandomizerHost, deferRandomizerHost,
                residentRootSkHi.get(), lazyRootSkHi.get()))
        {
            return false;
        }

        std::vector<RnsPoly> publicBStarNtt;
        std::shared_ptr<const gpu::RetainedPublicUniform> retainedBStarNtt;
        const bool batchPublicB = setupBatchNttEnabled();
#if defined(ENABLE_LOGVOLE_CUDA)
        const char* bStarOption = std::getenv("LV_GPU_SETUP_ROOT_BSTAR_DEVICE");
        const char* bStarStrictOption =
            std::getenv("LV_GPU_SETUP_ROOT_BSTAR_DEVICE_STRICT");
        const bool bStarRequested = deferRandomizerHost && batchPublicB &&
            gpu::enabled() &&
            currentProtocolCacheScope().mRole == ProtocolCacheRole::Sender &&
            (!bStarOption || bStarOption[0] != '0');
        const bool bStarStrict = bStarRequested && bStarStrictOption &&
            bStarStrictOption[0] != '0';
#endif
        {
        HostStep bStarStep("setup sender: root BStar public uniform sampling");
#if defined(ENABLE_LOGVOLE_CUDA)
        if (bStarRequested)
        {
            retainedBStarNtt = gpu::retainRootBStarNttDevice(ctx, randomizer);
            if (bStarStrict && !retainedBStarNtt) return false;
        }
        if (!retainedBStarNtt && batchPublicB && gpu::setupUniformSamplingEnabled())
        {
            publicBStarNtt = deriveUniformPolyBatchFromNonce(
                ctx, kRootBStarPublicNonce, kRootBStarPublicDomain,
                randomizer, true);
            if (publicBStarNtt.size() != randomizer) return false;
        }
        else if (!retainedBStarNtt)
#endif
        {
            publicBStarNtt.resize(randomizer);
            for (u32 idx = 0; idx < randomizer; ++idx)
            {
                publicBStarNtt[idx] = batchPublicB
                    ? deriveUniformPolyFromNonce(ctx, kRootBStarPublicNonce,
                        kRootBStarPublicDomain, idx)
                    : deriveUniformPolyFromNonceNtt(ctx, kRootBStarPublicNonce,
                        kRootBStarPublicDomain, idx);
            }
            if (batchPublicB && !forwardNttBatch(publicBStarNtt, ctx)) return false;
        }
        }

        std::vector<RnsPoly> r1;
        std::shared_ptr<const LazyRootErrorHostState> lazyR1;
        std::shared_ptr<gpu::DeviceBatch> residentR1;
#if defined(ENABLE_LOGVOLE_CUDA)
        const char* r1Option = std::getenv("LV_GPU_SETUP_ROOT_R1_DEVICE");
        const char* r1StrictOption = std::getenv("LV_GPU_SETUP_ROOT_R1_DEVICE_STRICT");
        const bool r1Requested = deferRandomizerHost && gpu::enabled() &&
            (!r1Option || r1Option[0] != '0');
        const bool r1Strict = r1Requested && r1StrictOption && r1StrictOption[0] != '0';
        const bool r1Eligible = r1Requested &&
            canSamplePolyErrorCompact(ctx, lencSigma, lencMaxDev);
        if (r1Strict && !r1Eligible) return false;
        if (r1Eligible)
        {
            if (!sampleRootErrorBatchResident(ctx, leftWidth, prng, lencSigma,
                    lencMaxDev, workerThreads, lazyR1, residentR1) ||
                (r1Strict && !residentR1)) return false;
        }
        else
#endif
        if (!sampleRootErrorBatch(ctx, leftWidth, prng, lencSigma,
                lencMaxDev, false, r1, workerThreads)) return false;

        std::vector<RnsPoly> skRRt;
        std::shared_ptr<const LazyRootSecretHostState> lazySkRRt;
        std::shared_ptr<gpu::DeviceBatch> residentSkRRt;
        const u64 skRRtOwnerRunId = currentProtocolCacheScope().mRunId;
        {
            HostStep step("setup sender: root skRRt sampling");
#if defined(ENABLE_LOGVOLE_CUDA)
            const char* skOption = std::getenv("LV_GPU_SETUP_ROOT_SKRR_DEVICE");
            const char* skStrictOption =
                std::getenv("LV_GPU_SETUP_ROOT_SKRR_DEVICE_STRICT");
            const bool skRequested = deferRandomizerHost && gpu::enabled() &&
                (!skOption || skOption[0] != '0');
            const bool skStrict = skRequested && skStrictOption &&
                skStrictOption[0] != '0';
            if (skRequested && gpu::setupUniformSamplingEnabled())
            {
                std::vector<seal::prng_seed_type> rowSeeds(tauHi);
                // One SEAL seed per row, in exactly the old sampler order.
                for (auto& seed : rowSeeds) prng.get(seed.data(), seed.size());
                residentSkRRt = gpu::sampleRootSecretUniformToDevice(ctx, rowSeeds);
                lazySkRRt = std::make_shared<SeededRootSecretHostState>(
                    ctx, std::move(rowSeeds));
                if (!residentSkRRt)
                {
                    if (skStrict) return false;
                    skRRt = lazySkRRt->hostCoefficients();
                }
            }
            else
            {
                if (skStrict) return false;
                skRRt = sampleUniformBatch(ctx, tauHi, prng);
            }
#else
            skRRt = sampleUniformBatch(ctx, tauHi, prng);
#endif
        }
        if ((residentSkRRt && (!lazySkRRt ||
                lazySkRRt->count() != tauHi ||
                !lazySkRRt->matches(se.mRing))) ||
            (!residentSkRRt && !validateRingBatchShape(skRRt, se.mRing)))
        {
            return false;
        }

        const double lheSigma =
            rootNoiseSigma(se, std::sqrt(static_cast<double>(leftLenc.mLacct.mWidthPadded)));
        const double lheMaxDev = rootNoiseMaxDeviation(lheSigma);
        RingTensor ctR{};
        std::shared_ptr<const LazyRingTensorHostState> lazyCtR;
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
                workerThreads,
                deferRandomizerHost ? &lazyCtR : nullptr, {},
                residentR1.get(), lazyR1.get(),
                residentSkRRt.get(), residentSkRRt ? lazySkRRt.get() : nullptr,
                skRRtOwnerRunId))
        {
            return false;
        }

        RingTensor topCt{};
        std::shared_ptr<const LazyRingTensorHostState> lazyTopCt;
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
                topCt,
                workerThreads, leftLenc.mLazyRandomizers,
                deferRandomizerHost ? &lazyTopCt : nullptr,
                retainedPublicBFullNtt.get(), residentR1.get(), lazyR1.get(),
                retainedBStarNtt.get()))
        {
            return false;
        }

#if defined(ENABLE_LOGVOLE_CUDA)
        if (retainedBStarNtt)
        {
            // The copied TCP wire still needs these exact public coefficients.
            // Publish them only after TopCt has consumed the sender-owned NTT
            // batch on the GPU; no host-to-device return trip remains.
            HostStep wireStep("setup sender: root BStar wire materialization");
            if (!gpu::retainedRootBStarNttMatches(ctx, *retainedBStarNtt,
                    randomizer) ||
                !gpu::fetchRetainedPublicUniform(*retainedBStarNtt,
                    publicBStarNtt))
            {
                if (bStarStrict) return false;
                publicBStarNtt = deriveUniformPolyBatchFromNonce(
                    ctx, kRootBStarPublicNonce, kRootBStarPublicDomain,
                    randomizer, true);
            }
            if (publicBStarNtt.size() != randomizer ||
                !validateRingBatchShape(publicBStarNtt, se.mRing)) return false;
        }
#endif

        // A reused state must never retain a device transform of the previous
        // offline secret. The residency cache is rebuilt lazily from this value.
        state.mRootSkRRtNttDevice.reset();
        state.mRootSkRRt = std::move(skRRt);
        state.mRootSkRRtDevice = std::move(residentSkRRt);
        state.mLazyRootSkRRt = std::move(lazySkRRt);
        state.mRootSkRRtOwnerRunId = skRRtOwnerRunId;
        if (lazyR1 && !residentR1)
            r1 = lazyR1->hostCoefficients();
        state.mRootR1Rt = std::move(r1);
        state.mRootR1RtDevice = std::move(residentR1);
        state.mLazyRootR1Rt = std::move(lazyR1);
        state.mRootRandomizerWidth = randomizer;

        RootOfflineMessage next{};
        next.mRing = se.mRing;
        next.mTauHi = tauHi;
        next.mGadgetLogBase = se.mGadgetLogBase;
        next.mPlaintextModulusBits = se.mPlaintextModulusBits;
        next.mLeftWidth = leftWidth;
        next.mRandomizerWidth = randomizer;
        next.mCtR = std::move(ctR);
        next.mLazyCtR = std::move(lazyCtR);
        next.mLacctLeft.mWidthPadded = leftLenc.mLacct.mWidthPadded;
        next.mLacctLeft.mLevels = leftLenc.mLacct.mLevels;
        next.mLacctLeft.mCt = std::move(leftLenc.mLacct.mCt);
        next.mLazyLacctLeft = std::move(leftLenc.mLazyCt);
        next.mTopCt = std::move(topCt);
        next.mLazyTopCt = std::move(lazyTopCt);
        next.mPublicBStarNtt = std::move(publicBStarNtt);
        message = std::move(next);
        return true;
    }

    template <typename Message>
    static bool finalizeRootOfflineReceiverImpl(
        ReceiverState& state,
        Message&& message)
    {
        HostStep setupStep("setup receiver: root total");
        u32 tauHi = 0;
        if (!computeTauHi(state.mParams, tauHi) ||
            !rootMetadataMatches(state, message))
        {
            return false;
        }

        const u32 rho = static_cast<u32>(state.mParams.mShrinkExpand.mRing.mCoeffModulusBits.size());
        const u32 leftWidth = rootLeftWidth(tauHi, rho);
        const u32 randomizer = rootRandomizerWidth(state.mParams.mShrinkExpand);
        // A caller of the direct Root API may hand back an internal deferred
        // message without passing through its wire codec. Preserve that host
        // API by materializing only these explicitly requested tensor views.
        const bool ownedCtRWire = message.mOwnedCtRWire &&
            message.mOwnedCtRWire == message.mLazyCtR;
        const RingTensor& ctRView = ownedCtRWire ? message.mCtR
            : message.mLazyCtR ? message.mLazyCtR->get() : message.mCtR;
        const bool ownedLacctWire = message.mOwnedLacctLeftWire &&
            message.mOwnedLacctLeftWire == message.mLazyLacctLeft;
        const RingTensor& lacctView = ownedLacctWire ? message.mLacctLeft.mCt
            : message.mLazyLacctLeft ? message.mLazyLacctLeft->get() : message.mLacctLeft.mCt;
        const bool ownedTopCtWire = message.mOwnedTopCtWire &&
            message.mOwnedTopCtWire == message.mLazyTopCt;
        const RingTensor& topCtView = ownedTopCtWire ? message.mTopCt
            : message.mLazyTopCt ? message.mLazyTopCt->get() : message.mTopCt;
        const bool ownedPublicBStarWire = message.mOwnedPublicBStarWire &&
            message.mOwnedPublicBStarWire == message.mLazyPublicBStar;
        const auto& publicBStarView = ownedPublicBStarWire ? message.mPublicBStarNtt
            : message.mLazyPublicBStar ? message.mLazyPublicBStar->get().mPolys
            : message.mPublicBStarNtt;
        const auto topCtWireBytes = ownedTopCtWire
            ? message.mOwnedTopCtWire->encodedCoefficients() : std::span<const u8>{};
        const auto lacctWireBytes = ownedLacctWire
            ? message.mOwnedLacctLeftWire->encodedCoefficients() : std::span<const u8>{};
        const auto ctRWireBytes = ownedCtRWire
            ? message.mOwnedCtRWire->encodedCoefficients() : std::span<const u8>{};
        const auto publicBStarWireBytes = ownedPublicBStarWire
            ? message.mOwnedPublicBStarWire->encodedCoefficients() : std::span<const u8>{};
        const u64 rootPolyWords = ringPolyCoeffCount(message.mRing);
        const u64 ctRWireWords = ctRWireBytes.size() / sizeof(u64);
        const u64 lacctWireWords = lacctWireBytes.size() / sizeof(u64);
        const u64 topCtWireWords = topCtWireBytes.size() / sizeof(u64);
        const u64 publicBStarWireWords = publicBStarWireBytes.size() / sizeof(u64);

        if (rho == 0 ||
            (message.mOwnedCtRWire && !ownedCtRWire) ||
            (message.mOwnedLacctLeftWire && !ownedLacctWire) ||
            (message.mOwnedTopCtWire && !ownedTopCtWire) ||
            (message.mOwnedPublicBStarWire && !ownedPublicBStarWire) ||
            ctRView.mRows != leftWidth ||
            ctRView.mCols != tauHi ||
            (ownedCtRWire
                ? (!ctRView.mPolys.empty() ||
                   ctRWireBytes.size() % sizeof(u64) != 0 || !rootPolyWords ||
                   ringTensorSize(ctRView) > ctRWireWords / rootPolyWords ||
                   ringTensorSize(ctRView) * rootPolyWords != ctRWireWords)
                : (ringTensorSize(ctRView) != ctRView.mPolys.size() ||
                   !validateRingBatchShape(ctRView.mPolys, message.mRing))) ||
            message.mLacctLeft.mWidthPadded == 0 ||
            (message.mLacctLeft.mWidthPadded & (message.mLacctLeft.mWidthPadded - 1)) != 0 ||
            static_cast<u64>(lacctView.mRows) !=
                static_cast<u64>(message.mLacctLeft.mWidthPadded) * message.mLacctLeft.mLevels ||
            (ownedLacctWire
                ? (!lacctView.mPolys.empty() ||
                   lacctWireBytes.size() % sizeof(u64) != 0 || !rootPolyWords ||
                   ringTensorSize(lacctView) > lacctWireWords / rootPolyWords ||
                   ringTensorSize(lacctView) * rootPolyWords != lacctWireWords)
                : (ringTensorSize(lacctView) != lacctView.mPolys.size() ||
                   !validateRingBatchShape(lacctView.mPolys, message.mRing))) ||
            topCtView.mRows != leftWidth ||
            topCtView.mCols != tauHi + randomizer ||
            (ownedTopCtWire
                ? (!topCtView.mPolys.empty() ||
                   topCtWireBytes.size() % sizeof(u64) != 0 || !rootPolyWords ||
                   ringTensorSize(topCtView) > topCtWireWords / rootPolyWords ||
                   ringTensorSize(topCtView) * rootPolyWords != topCtWireWords)
                : (ringTensorSize(topCtView) != topCtView.mPolys.size() ||
                   !validateRingBatchShape(topCtView.mPolys, message.mRing))) ||
            (ownedPublicBStarWire
                ? (!publicBStarView.empty() || message.mPublicBStarCount != randomizer ||
                   publicBStarWireBytes.size() % sizeof(u64) != 0 || !rootPolyWords ||
                   static_cast<u64>(randomizer) > publicBStarWireWords / rootPolyWords ||
                   static_cast<u64>(randomizer) * rootPolyWords != publicBStarWireWords)
                : (publicBStarView.size() != randomizer ||
                   !validateRingBatchShape(publicBStarView, message.mRing))))
        {
            return false;
        }

        RingNttContext ctx{};
        if (!makeRingNttContext(message.mRing, ctx))
        {
            return false;
        }

        RingTensor ctR{};
        std::shared_ptr<const LazyRingTensorHostState> ctRWire;
        if (ownedCtRWire)
        {
            ctR = std::forward<Message>(message).mCtR;
            ctRWire = std::make_shared<RootCtRNttWireState>(
                std::forward<Message>(message).mOwnedCtRWire, ctx);
        }
        else
        {
            if (message.mLazyCtR) ctR = ctRView;
            else ctR = std::forward<Message>(message).mCtR;
            if (!setupForwardNtt(ctR.mPolys, ctx)) return false;
        }

        state.mRootCtRRt = std::move(ctR);
        state.mRootCtRWire = std::move(ctRWire);
        state.mRootLacctLeft = std::forward<Message>(message).mLacctLeft;
        state.mRootLacctLeftWire.reset();
        if (ownedLacctWire)
            state.mRootLacctLeftWire = std::forward<Message>(message).mOwnedLacctLeftWire;
        else if (message.mLazyLacctLeft) state.mRootLacctLeft.mCt = lacctView;
        if (ownedTopCtWire)
        {
            state.mRootTopCt = std::forward<Message>(message).mTopCt;
            state.mRootTopCtWire = std::forward<Message>(message).mOwnedTopCtWire;
        }
        else if (message.mLazyTopCt) state.mRootTopCt = topCtView;
        else state.mRootTopCt = std::forward<Message>(message).mTopCt;
        state.mRootPublicBStarWire.reset();
        if (ownedPublicBStarWire)
        {
            state.mRootPublicBStarNtt = std::forward<Message>(message).mPublicBStarNtt;
            state.mRootPublicBStarWire =
                std::forward<Message>(message).mOwnedPublicBStarWire;
        }
        else if (message.mLazyPublicBStar)
            state.mRootPublicBStarNtt = publicBStarView;
        else state.mRootPublicBStarNtt =
            std::forward<Message>(message).mPublicBStarNtt;
        state.mRootRandomizerWidth = randomizer;
        return true;
    }

    bool finalizeRootOfflineReceiver(
        ReceiverState& state,
        const RootOfflineMessage& message)
    {
        return finalizeRootOfflineReceiverImpl(state, message);
    }

    bool finalizeRootOfflineReceiver(
        ReceiverState& state,
        RootOfflineMessage&& message)
    {
        return finalizeRootOfflineReceiverImpl(state, std::move(message));
    }

    bool prepareRootDigestReceiver(
        const ReceiverState& state,
        const std::vector<RnsPoly>& x,
        PRNG& prng,
        RootDigestState& digestState,
        RootDigestMessage& message,
        const std::shared_ptr<void>& xDevice,
        u64 xDeviceCount,
        bool deferDPrimeHash)
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
            !validRootWidth(state.mParams.mW, muHi) ||
            (xDevice ? xDeviceCount > state.mParams.mW
                     : x.size() > state.mParams.mW) ||
            state.mRootRandomizerWidth != rootRandomizerWidth(state.mParams.mShrinkExpand))
        {
            return false;
        }

        RingNttContext ctx{};
        if (!makeRingNttContext(state.mParams.mShrinkExpand.mRing, ctx))
        {
            return false;
        }

        // Zero-padded host copy of the level's input. Only the host path and the
        // host-input device path read it; when the caller hands over a device batch
        // the device shrink reads that directly, so building this was muHi
        // allocations and 2 MiB of zeroing for nothing.
        std::vector<RnsPoly> xRoot;
        const auto buildXRoot = [&]() {
            if (!xRoot.empty()) return;
            RootStep step("prep: xRoot pad");
            xRoot.resize(muHi);
            for (std::size_t idx = 0; idx < x.size(); ++idx)
            {
                xRoot[idx] = x[idx];
            }
            for (std::size_t idx = x.size(); idx < xRoot.size(); ++idx)
            {
                xRoot[idx] = makeZeroPoly(state.mParams.mShrinkExpand.mRing);
            }
        };

        const u32 leftWidth = rootLeftWidth(tauHi, rho);

        // The Root is a single chunk of muHi labels, which is exactly the shape
        // shrinkChunksDevice already handles for every other level. Running it there
        // keeps the digest tree in device memory, which is what lets the matching
        // expand in finalizeRootOnlineReceiver stay on the device too - the tree is
        // the only thing that forced the Root's expand onto the host.
        std::vector<RnsPoly> hatD;
        RnsPoly rootDigest{};
        std::shared_ptr<DigestTree> rootTree;
        std::shared_ptr<void> gpuSessionOut;
#if defined(ENABLE_LOGVOLE_CUDA)
        if (gpu::enabled() && std::getenv("LV_ROOT_PROFILE"))
        {
            // Diagnostic only: drain whatever the outer levels still have queued
            // before the Root's own timers start, so that the Root's first
            // synchronise is not credited with their work.
            RootStep step("prep: pre-shrink drain (diagnostic)");
            gpu::syncStream();
        }
        gpu::DeviceBatchPtr hatDDev;
        if (gpu::enabled())
        {
            RootStep step("prep: shrink");
            auto session = std::make_shared<gpu::LevelSession>();
            gpu::DeviceBatchPtr dHatDev;
            // Prefer the caller's device batch: the Root's input is already there,
            // so downloading it just to hand it back was a pure round trip.
            auto xDev = std::static_pointer_cast<gpu::DeviceBatch>(xDevice);
            if (!xDev) buildXRoot();
            if (gpu::shrinkChunksDevice(
                    state.mShrinkExpandState,
                    xDev ? std::span<const RnsPoly>()
                         : std::span<const RnsPoly>(xRoot.data(), xRoot.size()),
                    xDev.get(),
                    xDev ? static_cast<u32>(xDeviceCount) : muHi,
                    muHi,
                    tauHi,
                    *session,
                    dHatDev) &&
                dHatDev && dHatDev->count() >= leftWidth)
            {
                // hatD stays on the device. It used to be downloaded here and handed
                // straight back to buildDigestTreeChunkDevice, which re-uploaded it:
                // leftWidth ring elements each way, plus the host allocation and the
                // pageable-copy staging that goes with them.
                hatDDev = std::move(dHatDev);
                gpuSessionOut = std::move(session);
            }
        }
#endif
        if (!gpuSessionOut)
        {
            buildXRoot();
            ShrinkExpandShrinkOutput shrink{};
            if (!shrinkExpandShrink(state.mShrinkExpandState, xRoot, shrink))
            {
                return false;
            }

            if (!seedLabelGadgetDecomposeHiAndUnbundle(
                    shrink.mDigest,
                    state.mParams.mShrinkExpand.mGadgetLogBase,
                    tauHi,
                    state.mParams.mShrinkExpand.mRing,
                    hatD))
            {
                return false;
            }
            rootDigest = std::move(shrink.mDigest);
            rootTree = std::move(shrink.mTree);
        }

#if defined(ENABLE_LOGVOLE_CUDA)
        const bool hatDOnDevice = static_cast<bool>(hatDDev);
#else
        constexpr bool hatDOnDevice = false;
#endif
        if (!hatDOnDevice && hatD.size() != leftWidth)
        {
            return false;
        }

        // Build the tree, not just its root. lencDigestTrunc returns only the
        // digest and drops the tree, and finalizeRootResponseReceiver then rebuilt
        // the identical tree from the identical input - the single largest
        // redundancy in the Root. Keeping it costs one shared_ptr in a state object
        // that already survives the wire exchange. `requestedWorkers` also gets
        // through here, where lencDigestTrunc hard-coded one thread.
        auto leftTree = std::make_shared<DigestTree>();
        std::shared_ptr<void> leftTreeSession;
        bool leftTreeDone = false;
#if defined(ENABLE_LOGVOLE_CUDA)
        if (gpu::enabled())
        {
            RootStep step("prep: buildDigestTree(left, device)");
            u32 maxTau = 0;
            RnsPoly deviceDigest{};
            std::vector<RnsPoly> nodesFlat;
            // The host tree is only the fallback for the host key derivation, and
            // that runs only if this device path fails. So it is requested only when
            // the leaves are on the host, which is the same condition.
            const bool wantHostTree = !hatDOnDevice;
            if (gpu::buildDigestTreeChunkDevice(
                    state.mShrinkExpandState,
                    std::span<const RnsPoly>(hatD.data(), hatD.size()),
                    hatDDev.get(),
                    state.mRootLacctLeft.mWidthPadded,
                    tauHi,
                    true,
                    wantHostTree,
                    maxTau,
                    deviceDigest,
                    nodesFlat,
                    leftTreeSession) &&
                maxTau != 0 && !wantHostTree)
            {
                // Device session only; nothing below reads mLeftTree or yLeft,
                // because rootDigestReceiverDevice evaluates against the session.
                leftTreeDone = true;
            }
            else if (maxTau != 0 && wantHostTree)
            {
                // Reshape the flat [node][digit] device layout into the host tree.
                // The leaf level carries tauLeaf digits and the internal levels
                // tauHi; the device buffer is sized for max(tauHi, tauLeaf), so the
                // per-node slice is trimmed to what that level actually uses.
                const u32 width = state.mRootLacctLeft.mWidthPadded;
                const u32 nodeCount = (2u * width) - 1u;
                const u32 firstLeaf = width - 1u;
                // computeTruncLeafTau is 1 whenever the leaves are gadget digits,
                // which they always are here (the leaves are hatD).
                constexpr u32 tauLeaf = 1;
                u32 levels = 0;
                while ((1u << levels) < width) ++levels;
                if (nodesFlat.size() >= static_cast<std::size_t>(nodeCount) * maxTau &&
                    (1u << levels) == width)
                {
                    leftTree->mWidthPadded = width;
                    leftTree->mLevels = levels;
                    leftTree->mDigest = std::move(deviceDigest);
                    leftTree->mNodeDecompNtt.assign(nodeCount, {});
                    for (u32 node = 1; node < nodeCount; ++node)
                    {
                        const u32 tau = (node >= firstLeaf) ? tauLeaf : tauHi;
                        leftTree->mNodeDecompNtt[node].resize(tau);
                        for (u32 d = 0; d < tau; ++d)
                        {
                            leftTree->mNodeDecompNtt[node][d] =
                                std::move(nodesFlat[static_cast<std::size_t>(node) * maxTau + d]);
                        }
                    }
                    leftTreeDone = true;
                }
            }
        }
#endif
        if (!leftTreeDone)
        {
            RootStep step("prep: buildDigestTreeTrunc(left, host)");
            if (!buildDigestTreeTrunc(
                    ctx,
                    hatD,
                    tauHi,
                    state.mParams.mShrinkExpand.mGadgetLogBase,
                    state.mParams.mShrinkExpand.mPlaintextModulusBits,
                    *leftTree,
                    state.mRootLacctLeft.mWidthPadded,
                    true,
                    nullptr,
                    state.mShrinkExpandState.mParams.mNumWorkerThreads))
            {
                return false;
            }
        }
        // Only the host digest path below reads yLeft, and it is a full ring element,
        // so it is not copied when the device chain will run.
        RnsPoly yLeft;
        if (!leftTreeSession)
        {
            yLeft = leftTree->mDigest;
        }

        std::vector<RnsPoly> zeta;
        const u32 zetaWorkers =
            state.mShrinkExpandState.mParams.mNumWorkerThreads > 1u
            ? state.mShrinkExpandState.mParams.mNumWorkerThreads
            : 1u;
        std::vector<block> zetaTaskSeeds;
        const bool seededZeta = zetaWorkers > 1u;
        const bool forceFirstZetaReject = [] {
            // Validation only. Both the GPU ordered repair and the seeded CPU
            // fallback discard task zero's AES counter zero when enabled.
            const char* v = std::getenv("LV_GPU_ROOT_ZETA_FORCE_REJECT");
            return v && v[0] == '1';
        }();
        {
            RootStep step("prep: sampleRootZeta");
            if (seededZeta)
            {
                // This is exactly sampleRootZeta's historical parent-stream
                // consumption: randomizerWidth*workers consecutive block keys,
                // all drawn before any task starts. From here on every path,
                // including CUDA failure, is a replay of these same keys.
                zetaTaskSeeds.resize(
                    static_cast<std::size_t>(state.mRootRandomizerWidth) *
                    zetaWorkers);
                prng.get(zetaTaskSeeds.data(), zetaTaskSeeds.size());
            }
            else if (!sampleRootZeta(
                         ctx,
                         state.mRootRandomizerWidth,
                         state.mParams.mShrinkExpand.mGadgetLogBase,
                         prng,
                         zeta,
                         1u))
            {
                return false;
            }
        }

        if (state.mRootPublicBStarWire
                ? state.mRootPublicBStarWire->encodedCoefficients().empty()
                : state.mRootPublicBStarNtt.size() != state.mRootRandomizerWidth)
            return false;

        RnsPoly negDPrime{};
        std::vector<RnsPoly> topInputsNtt;
        std::shared_ptr<void> topInputsDev;
        std::shared_ptr<void> dPrimeDev;
        bool digestDone = false;
#if defined(ENABLE_LOGVOLE_CUDA)
        // Everything from the tree's digest to d' as one kernel sequence. yLeft is
        // the tree's own digest and is already on the device, so the only things
        // that cross are zeta in (it comes from the host PRNG) and d' out (it goes
        // on the wire).
        if (gpu::enabled() && leftTreeSession)
        {
            RootStep step("prep: device chain");
            gpu::DeviceBatchPtr topDev;
            gpu::DeviceBatchPtr retainedDPrime;
            bool deviceOk = false;
            if (seededZeta)
            {
                deviceOk = gpu::rootDigestReceiverDeviceFromZetaSeeds(
                    state, ctx, leftTreeSession, zetaTaskSeeds, zetaWorkers,
                    tauHi, forceFirstZetaReject, negDPrime, topDev,
                    &retainedDPrime);
            }
            if (deviceOk && topDev)
            {
                topInputsDev = std::move(topDev);
                dPrimeDev = std::move(retainedDPrime);
                digestDone = true;
            }
        }
#endif

        // The GPU path is allowed to decline at any point, but it is never
        // allowed to consume fresh protocol randomness. Recreate the exact host
        // zeta from the already-consumed task keys before taking either fallback.
        if (!digestDone && zeta.empty() && seededZeta)
        {
            RootStep step("prep: sampleRootZeta seeded fallback");
            if (!sampleRootZetaFromTaskSeeds(
                    ctx,
                    state.mRootRandomizerWidth,
                    state.mParams.mShrinkExpand.mGadgetLogBase,
                    zetaTaskSeeds,
                    zetaWorkers,
                    zeta,
                    zetaWorkers,
                    forceFirstZetaReject))
            {
                return false;
            }
        }

#if defined(ENABLE_LOGVOLE_CUDA)
        // Roll back only the sampling experiment while retaining the established
        // device digest chain. This is also the LV_GPU_ROOT_ZETA=0 path.
        if (!digestDone && gpu::enabled() && leftTreeSession)
        {
            RootStep step("prep: device chain (host zeta)");
            gpu::DeviceBatchPtr topDev;
            gpu::DeviceBatchPtr retainedDPrime;
            if (gpu::rootDigestReceiverDevice(
                    state, ctx, leftTreeSession, zeta, tauHi, negDPrime,
                    topDev, &retainedDPrime) &&
                topDev)
            {
                topInputsDev = std::move(topDev);
                dPrimeDev = std::move(retainedDPrime);
                digestDone = true;
            }
        }
#endif

        // One batched transform for both inner products, instead of
        // rootInnerProductNtt transforming its right operand one polynomial at a
        // time in two separate calls. tauHi + randomizerWidth is 4 at the real
        // parameters, which is exactly the batch size at which forwardNttBatch
        // reaches the GPU - two calls of 1 and 3 never did.
        //
        // The concatenation order matches evalRootTopCtNtt's own `inputs` array
        // exactly, so the same array serves as its input later (mTopInputsNtt) and
        // that step's gadget decomposition and transform disappear.
        std::vector<RnsPoly> yDecomp;
        std::vector<RnsPoly> publicBRootNtt;
        if (!digestDone)
        {
            RootStep step("prep: gadget(yLeft)");
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
            publicBRootNtt.resize(tauHi);
            for (u32 idx = 0; idx < tauHi; ++idx)
            {
                publicBRootNtt[idx] = publicBFullNtt[1 + idx];
            }
        }

        if (!digestDone)
        {
            RootStep step("prep: forwardNttBatch(yDecomp++zeta)");
            topInputsNtt.resize(yDecomp.size() + zeta.size());
            for (std::size_t idx = 0; idx < yDecomp.size(); ++idx)
                topInputsNtt[idx] = yDecomp[idx];
            for (std::size_t idx = 0; idx < zeta.size(); ++idx)
                topInputsNtt[yDecomp.size() + idx] = zeta[idx];
            if (!forwardNttBatch(topInputsNtt, ctx))
            {
                return false;
            }
        }

        RnsPoly dPrime{};
        if (!digestDone)
        {
            RootStep step("prep: two inner products + INTT + negate");
            const auto& publicBStarNtt = state.mRootPublicBStarWire
                ? state.mRootPublicBStarWire->get().mPolys
                : state.mRootPublicBStarNtt;
            if (publicBStarNtt.size() != zeta.size()) return false;
            // Both inner products stay in the evaluation domain and are summed
            // there, so the pair costs one inverse transform instead of two. The sum
            // is linear, so INTT(a + b) == INTT(a) + INTT(b) exactly. Accumulating
            // straight into one polynomial in publicB-then-bStar order is the same
            // sequence of dyadicMultiplyAddNttInplace calls the two
            // rootInnerProductNtt calls made, followed by the ringAdd of their
            // results - modular addition is associative, so this is bit-identical.
            RnsPoly accNtt{};
            resizeZero(accNtt.mCoeffs, ringPolyCoeffCount(ctx.mParams));
            for (u32 idx = 0; idx < tauHi; ++idx)
            {
                if (!dyadicMultiplyAddNttInplace(publicBRootNtt[idx], topInputsNtt[idx], accNtt, ctx))
                {
                    return false;
                }
            }
            for (std::size_t idx = 0; idx < zeta.size(); ++idx)
            {
                if (!dyadicMultiplyAddNttInplace(
                        publicBStarNtt[idx], topInputsNtt[tauHi + idx], accNtt, ctx))
                {
                    return false;
                }
            }

            RnsPoly zero = makeZeroPoly(state.mParams.mShrinkExpand.mRing);
            dPrime = std::move(accNtt);
            if (!inverseNtt(dPrime, ctx) || !ringSub(zero, dPrime, ctx, negDPrime))
            {
                return false;
            }
        }

        RootDigestState nextState{};
        nextState.mDRt = std::move(rootDigest);
        nextState.mRootTree = std::move(rootTree);
        nextState.mGpuSession = std::move(gpuSessionOut);
        nextState.mHatDRt = std::move(hatD);
        nextState.mYLeft = std::move(yLeft);
        nextState.mZeta = std::move(zeta);
        nextState.mZetaTaskSeeds = std::move(zetaTaskSeeds);
        nextState.mZetaRangesPerPoly = seededZeta ? zetaWorkers : 0u;
        nextState.mZetaForceFirstReject =
            seededZeta && forceFirstZetaReject;
        nextState.mDPrime = std::move(negDPrime);
        nextState.mDPrimeGpu = std::move(dPrimeDev);
        if (!deferDPrimeHash)
        {
            RootStep step("prep: hash dPrime");
            if (!finishRootDigestHash(nextState)) return false;
        }
        nextState.mLeftTree = std::move(leftTree);
        nextState.mTopInputsNtt = std::move(topInputsNtt);
        nextState.mTopInputsNttGpu = std::move(topInputsDev);
        nextState.mLeftTreeGpu = std::move(leftTreeSession);

        RootDigestMessage nextMessage{};
        assignRange(nextMessage.mDPrimeCoeffs, nextState.mDPrime.mCoeffs.begin(), nextState.mDPrime.mCoeffs.end());

        digestState = std::move(nextState);
        message = std::move(nextMessage);
        return true;
    }

    bool finishRootDigestHash(RootDigestState& digestState)
    {
        if (digestState.mDPrimeHashValid)
        {
            return true;
        }
        if (digestState.mDPrime.mCoeffs.empty())
        {
            return false;
        }

        RootStep step("wire: hash dPrime after send");
#if defined(ENABLE_LOGVOLE_CUDA)
        if (gpu::rootDigestHashEnabled() && digestState.mDPrimeGpu)
        {
            const auto device = std::static_pointer_cast<gpu::DeviceBatch>(digestState.mDPrimeGpu);
            if (gpu::hashRootDigestDevice(*device, digestState.mDPrimeHash))
            {
                digestState.mDPrimeHashValid = true;
                return true;
            }
        }
#endif
        digestState.mDPrimeHash = hashSeedDigest(digestState.mDPrime);
        digestState.mDPrimeHashValid = true;
        return true;
    }

    bool deriveNonInteractiveRootResponse(
        const Params& params,
        const RnsPoly& dPrime,
        RootResponseMessage& response)
    {
        RingNttContext ctx{};
        if (params.mOnlineMode != OnlineMode::NonInteractive ||
            params.mCt2SeedMode != Ct2SeedMode::PublicSeed ||
            !makeRingNttContext(params.mShrinkExpand.mRing, ctx) ||
            !validateRingPolyShape(dPrime, ctx.mParams)) return false;
        const u64 degree = ctx.mParams.mPolyModulusDegree;
        for (std::size_t limb = 0; limb < ringModulusCount(ctx); ++limb)
            for (u64 c = 0; c < degree; ++c)
                if (dPrime.mCoeffs[limb * degree + c] >= ringModulusValue(ctx, limb))
                    return false;

        std::array<u64, 8> seed{};
        RandomOracle ro(sizeof(seed));
        constexpr u64 domain = 0x4C564E49524F3031ull; // "LVNIRO01"
        const u64 rho = ringModulusCount(ctx);
        ro.Update(&domain, 1);
        ro.Update(&params.mSessionId, 1);
        ro.Update(&degree, 1);
        ro.Update(&rho, 1);
        for (std::size_t limb = 0; limb < rho; ++limb)
        {
            const u64 q = ringModulusValue(ctx, limb);
            ro.Update(&q, 1);
        }
        ro.Update(&params.mShrinkExpand.mGadgetLogBase, 1);
        ro.Update(dPrime.mCoeffs.data(), dPrime.mCoeffs.size());
        ro.Final(reinterpret_cast<u8*>(seed.data()));
        // Rejection sampling through the existing SEAL sampler, without a
        // biased reduction of hash words modulo the RNS primes.
        auto skPrime = sampleUniformPolyFromSeed(ctx, seed);
        if (!validateRingPolyShape(skPrime, ctx.mParams)) return false;
        RootResponseMessage next{};
        next.mSkPrimeCoeffs = std::move(skPrime.mCoeffs);
        response = std::move(next);
        return true;
    }

    static void clearSenderExpansionCaches(const SenderState& state)
    {
        state.mGoldenSeed.clear();
        state.mPrecomputedTbk.reset();
        state.mPrecomputedTbkDevice.reset();
        state.mPrecomputedTbkCount = 0;
        if (state.mNextLevelState)
            clearSenderExpansionCaches(*state.mNextLevelState);
    }

    static bool prepareRootResponseSenderImpl(
        const SenderState& state,
        const RootDigestMessage& request,
        RootDigestMessage* ownedRequest,
        PRNG& prng,
        RootResponseMessage& response,
        const SenderState* precomputeRoot,
        const RnsPoly* preSampledKPrime,
        bool deferPrecompute,
        const std::shared_ptr<void>& preSampledKPrimeDevice)
    {
        // Never let a failed new response attempt retain ownership of an older
        // query's device k'. New successful state below publishes either a
        // complete host key or a synchronized fresh device key and lazy mirror.
        state.mRootKPrimeRtDevice.reset();
        const bool nonInteractive = state.mParams.mOnlineMode == OnlineMode::NonInteractive;
        if (nonInteractive && (state.mParams.mCt2SeedMode != Ct2SeedMode::PublicSeed ||
                               preSampledKPrime || preSampledKPrimeDevice)) return false;

        u32 tauHi = 0;
        if (!computeTauHi(state.mParams, tauHi)) return false;
        const bool secretHostValid = state.mRootSkRRt.size() == tauHi &&
            validateRingBatchShape(state.mRootSkRRt,
                state.mParams.mShrinkExpand.mRing);
        const bool secretLazyValid = state.mRootSkRRt.empty() &&
            state.mRootSkRRtDevice && state.mLazyRootSkRRt &&
            state.mLazyRootSkRRt->count() == tauHi &&
            state.mLazyRootSkRRt->matches(state.mParams.mShrinkExpand.mRing);
        if (!secretHostValid && !secretLazyValid)
        {
            return false;
        }

        RingNttContext ctx{};
        if (!makeRingNttContext(state.mParams.mShrinkExpand.mRing, ctx))
        {
            return false;
        }

#if defined(ENABLE_LOGVOLE_CUDA)
        const auto residentSkCoeffs =
            std::static_pointer_cast<gpu::DeviceBatch>(state.mRootSkRRtDevice);
        if (secretLazyValid && gpu::enabled() &&
            !gpu::rootSecretUniformBatchMatches(ctx, *residentSkCoeffs,
                tauHi, state.mRootSkRRtOwnerRunId)) return false;
#endif

        RnsPoly dPrime{};
        RnsPoly kPrime{};
        RnsPoly skPrime{};
        block deviceDigestHash{};
        bool haveDeviceDigestHash = false;
#if defined(ENABLE_LOGVOLE_CUDA)
        gpu::DeviceBatchPtr residentKPrime;
        const auto preparedSkNtt =
            std::static_pointer_cast<gpu::DeviceBatch>(
                state.mRootSkRRtNttDevice);
        const auto preparedKPrimeDev = preSampledKPrime
            ? std::static_pointer_cast<gpu::DeviceBatch>(
                  preSampledKPrimeDevice)
            : gpu::DeviceBatchPtr{};
#endif
        {
            HostStep step("send: root unpack d'");
            if (ownedRequest)
            {
                if (ownedRequest->mDPrimeCoeffs.size() !=
                    static_cast<std::size_t>(
                        ringPolyCoeffCount(state.mParams.mShrinkExpand.mRing)))
                {
                    return false;
                }
                dPrime.mCoeffs = std::move(ownedRequest->mDPrimeCoeffs);
            }
            else if (!unpackSinglePoly(
                         state.mParams.mShrinkExpand.mRing,
                         request.mDPrimeCoeffs,
                         dPrime))
            {
                return false;
            }
        }
        {
            HostStep step("send: root sample k'");
            if (nonInteractive)
            {
                RootResponseMessage oracle{};
                if (!deriveNonInteractiveRootResponse(state.mParams, dPrime, oracle)) return false;
                skPrime.mCoeffs = std::move(oracle.mSkPrimeCoeffs);
            }
            else if (preSampledKPrime)
            {
                kPrime = *preSampledKPrime;
            }
            else if (!sampleRootKPrime(state, prng, kPrime))
            {
                return false;
            }
        }
        {
            HostStep step("send: root deriveSkx");
            bool skxDone = false;
#if defined(ENABLE_LOGVOLE_CUDA)
            // On the critical path of both parties and independent of the label
            // count: a gadget decomposition and a ring multiplication over full
            // ring elements, which is 8 ms of host time at the no-golden-seed
            // parameters against a fraction of that on the device.
            if (gpu::enabled())
            {
                skxDone = gpu::rootSkxSenderDevice(
                    ctx,
                    state.mRootSkRRt,
                    dPrime,
                    nonInteractive ? skPrime : kPrime,
                    state.mParams.mShrinkExpand.mGadgetLogBase,
                    tauHi,
                    nonInteractive ? kPrime : skPrime,
                    &residentKPrime,
                    preparedSkNtt,
                    preparedKPrimeDev,
                    gpu::rootDigestHashEnabled() ? &deviceDigestHash : nullptr,
                    nonInteractive,
                    residentSkCoeffs,
                    state.mRootSkRRtOwnerRunId);
                haveDeviceDigestHash = skxDone && gpu::rootDigestHashEnabled();
            }
#endif
            // A successful device pre-sample deliberately has no host mirror.
            // Materialize only if this response actually needs the CPU path.
#if defined(ENABLE_LOGVOLE_CUDA)
            if (!skxDone && kPrime.mCoeffs.empty() && preparedKPrimeDev)
            {
                std::vector<RnsPoly> host;
                if (!gpu::download(*preparedKPrimeDev, host, 1u) || host.size() != 1u ||
                    !validateRingPolyShape(host[0], ctx.mParams)) return false;
                kPrime = std::move(host[0]);
                residentKPrime = preparedKPrimeDev;
            }
#endif
            if (!skxDone && nonInteractive)
            {
                const auto& hostSk = secretLazyValid
                    ? state.mLazyRootSkRRt->hostCoefficients()
                    : state.mRootSkRRt;
                if (hostSk.size() != tauHi ||
                    !validateRingBatchShape(hostSk, ctx.mParams)) return false;
                RnsPoly inner{};
                const auto zero = makeZeroPoly(ctx.mParams);
                if (!deriveSkxTrunc(ctx, hostSk, dPrime, zero,
                        state.mParams.mShrinkExpand.mGadgetLogBase, tauHi, inner) ||
                    !ringSub(skPrime, inner, ctx, kPrime)) return false;
                skxDone = true;
            }
            if (!skxDone &&
                !deriveSkxTrunc(
                    ctx,
                    secretLazyValid ? state.mLazyRootSkRRt->hostCoefficients()
                        : state.mRootSkRRt,
                    dPrime,
                    kPrime,
                    state.mParams.mShrinkExpand.mGadgetLogBase,
                    tauHi,
                    skPrime))
            {
                return false;
            }
        }

        // GoldenSeed's reply carries the seed the search settled on, so the
        // expansion has to finish first. PublicSeed's does not.
        const bool defer =
            deferPrecompute &&
            state.mParams.mCt2SeedMode == Ct2SeedMode::PublicSeed;

        // Every response fixes a new root key and digest. Any expansion kept
        // from the preceding query, including intermediate recursion levels,
        // belongs to those old inputs even if the caller reused the same SID.
        // A deferred response clears once here; finishRootSenderPrecompute can
        // then reuse its completed result while releasing this query's keys.
        clearSenderExpansionCaches(precomputeRoot ? *precomputeRoot : state);

        // The host mirror is empty for a device-generated key and is filled
        // only by an actual CPU fallback. Other paths move the full polynomial.
        state.mRootKPrimeRt = std::make_shared<RnsPoly>(std::move(kPrime));
#if defined(ENABLE_LOGVOLE_CUDA)
        // A null handle leaves the full host polynomial authoritative. A fresh
        // device-only key has a non-null synchronized handle on every success.
        state.mRootKPrimeRtDevice = std::move(residentKPrime);
#else
        state.mRootKPrimeRtDevice.reset();
#endif
        state.mRootDPrimeHash = haveDeviceDigestHash ? deviceDigestHash : hashSeedDigest(dPrime);
        state.mRootDPrimeHashValid = true;
        state.mRootDPrimeRt = std::make_shared<RnsPoly>(std::move(dPrime));
        if (!defer && !finishRootSenderPrecompute(state, prng, precomputeRoot))
        {
            return false;
        }

        RootResponseMessage next{};
        // PublicSeed sends no seed: the receiver derives the same bytes from the
        // transcript. This is the "zero ct2 communication" the setting is named
        // for; GoldenSeed has to ship the seed it settled on.
        if (state.mParams.mCt2SeedMode != Ct2SeedMode::PublicSeed)
        {
            assignRange(next.mSeed, state.mGoldenSeed.begin(), state.mGoldenSeed.end());
        }
        {
            HostStep step("send: root pack skPrime");
            if (ownedRequest)
            {
                next.mSkPrimeCoeffs = std::move(skPrime.mCoeffs);
            }
            else
            {
                assignRange(
                    next.mSkPrimeCoeffs,
                    skPrime.mCoeffs.begin(),
                    skPrime.mCoeffs.end());
            }
        }
        response = std::move(next);
        return true;
    }

    bool prepareRootResponseSender(
        const SenderState& state,
        const RootDigestMessage& request,
        PRNG& prng,
        RootResponseMessage& response,
        const SenderState* precomputeRoot,
        const RnsPoly* preSampledKPrime,
        bool deferPrecompute,
        const std::shared_ptr<void>& preSampledKPrimeDevice)
    {
        return prepareRootResponseSenderImpl(
            state,
            request,
            nullptr,
            prng,
            response,
            precomputeRoot,
            preSampledKPrime,
            deferPrecompute,
            preSampledKPrimeDevice);
    }

    bool prepareRootResponseSender(
        const SenderState& state,
        RootDigestMessage&& request,
        PRNG& prng,
        RootResponseMessage& response,
        const SenderState* precomputeRoot,
        const RnsPoly* preSampledKPrime,
        bool deferPrecompute,
        const std::shared_ptr<void>& preSampledKPrimeDevice)
    {
        return prepareRootResponseSenderImpl(
            state,
            request,
            &request,
            prng,
            response,
            precomputeRoot,
            preSampledKPrime,
            deferPrecompute,
            preSampledKPrimeDevice);
    }

    bool sampleRootResponseKPrime(const SenderState& state, PRNG& prng, RnsPoly& out,
        std::shared_ptr<void>* deviceOut)
    {
        if (deviceOut) deviceOut->reset();
#if defined(ENABLE_LOGVOLE_CUDA)
        if (deviceOut && gpu::rootKPrimeSamplingEnabled())
        {
            RingNttContext ctx{};
            if (!makeRingNttContext(state.mParams.mShrinkExpand.mRing, ctx)) return false;
            const bool production =
                (ctx.mParams.mPolyModulusDegree == 16384u && ringModulusCount(ctx) == 8u) ||
                (ctx.mParams.mPolyModulusDegree == 8192u && ringModulusCount(ctx) == 4u);
            if (production)
            {
                std::array<u64, 8> seed{};
                prng.get(seed.data(), seed.size());
                gpu::DeviceBatchPtr sampled;
                if (gpu::sampleRootKPrimeDevice(ctx, seed, sampled) && sampled)
                {
                    out.mCoeffs.clear();
                    *deviceOut = std::move(sampled);
                    return true;
                }
                // Failure must replay exactly the seed already consumed, not
                // sample a different key from the parent's next 64 bytes.
                out = sampleUniformPolyFromSeed(ctx, seed);
                return validateRingPolyShape(out, ctx.mParams);
            }
        }
#endif
        return sampleRootKPrime(state, prng, out);
    }

    bool prepareRootResponseDeviceOperands(
        const SenderState& state,
        const RnsPoly& kPrime,
        std::shared_ptr<void>& preparedKPrimeDevice)
    {
        preparedKPrimeDevice.reset();
#if defined(ENABLE_LOGVOLE_CUDA)
        gpu::DeviceBatchPtr prepared;
        const bool preparedAny =
            gpu::prepareRootSenderOperandsDevice(state, kPrime, prepared);
        if (prepared)
        {
            preparedKPrimeDevice = std::move(prepared);
        }
        return preparedAny;
#else
        (void)state;
        (void)kPrime;
#endif
        return false;
    }

    bool finishRootSenderPrecompute(
        const SenderState& state,
        PRNG& prng,
        const SenderState* precomputeRoot)
    {
        HostStep step("send: ensurePrecompute");
        const SenderState& precomputeState = precomputeRoot ? *precomputeRoot : state;
        return ensureSenderPrecomputeImpl(precomputeState, prng) && !state.mGoldenSeed.empty();
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
            !makeRingNttContext(state.mParams.mShrinkExpand.mRing, ctx))
        {
            return false;
        }

        std::vector<RnsPoly> ctK;
        std::vector<RnsPoly> tbkRt;
        if (!state.mRootKPrimeRt || !state.mRootDPrimeRt)
        {
            return false;
        }
#if defined(ENABLE_LOGVOLE_CUDA)
        if (state.mRootKPrimeRt->mCoeffs.empty() && state.mRootKPrimeRtDevice)
        {
            std::vector<RnsPoly> host;
            const auto device = std::static_pointer_cast<gpu::DeviceBatch>(state.mRootKPrimeRtDevice);
            if (!gpu::download(*device, host, 1u) || host.size() != 1u ||
                !validateRingPolyShape(host[0], ctx.mParams)) return false;
            *state.mRootKPrimeRt = std::move(host[0]);
        }
#endif
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
        bool evaluateSenderSeedCandidateImpl(
            const SenderState& state,
            std::span<const u8> seed,
            RecursiveSeedEvalOutput& out,
            bool isLeaf,
            bool deferGoldenValidation,
            u32 ct2PrefetchLevelsRemaining = 0u,
            bool retainHostCache = false)
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
                if (!validRootWidth(state.mParams.mW, muHi) ||
                    !state.mRootKPrimeRt ||
                    !state.mRootDPrimeRt ||
                    !state.mRootDPrimeHashValid)
                {
                    return false;
                }

                const Params rootSeedParams =
                    makeSeedParams(state.mParams, state.mShrinkExpandState.mParams);
                const bool rootPublicSeed =
                    state.mParams.mCt2SeedMode == Ct2SeedMode::PublicSeed;
                const bool deferRootValidation = deferGoldenValidation && !rootPublicSeed;

#if defined(ENABLE_LOGVOLE_CUDA)
                // The Root's key derivation and its expand as one device chain. On
                // the host this pair was ~85% of the sender's per-query time and
                // none of it depends on the label count, so it capped every size:
                // two megabyte Blake2xb expansions plus 24 SEAL transforms, and
                // then the level above uploaded the 16 MiB result it produced.
                if (gpu::enabled())
                {
                    HostStep step("send: root (device)");
                    RingNttContext rootCtx{};
                    gpu::DeviceBatchPtr rootTbkDev;
                    const auto rootKPrimeDev =
                        std::static_pointer_cast<gpu::DeviceBatch>(
                            state.mRootKPrimeRtDevice);
                    bool rootOkDev = rootPublicSeed || deferRootValidation;
                    if (makeRingNttContext(state.mParams.mShrinkExpand.mRing, rootCtx) &&
                        gpu::rootSenderTbkDevice(
                            state.mShrinkExpandState, rootCtx, seed, state.mParams.mSessionId,
                            *state.mRootDPrimeRt, state.mRootDPrimeHash, *state.mRootKPrimeRt,
                            rootKPrimeDev.get(),
                            rootLeftWidth(tauHi, rho), tauHi, rootTbkDev) &&
                        rootTbkDev &&
                        rootTbkDev->count() == state.mShrinkExpandState.mParams.mMu &&
                        (rootPublicSeed || deferRootValidation ||
                         (isLeaf ? gpu::validateLeafGoldenSeedDevice(rootSeedParams, *rootTbkDev, rootOkDev)
                                 : gpu::validateGoldenSeedDevice(rootSeedParams, *rootTbkDev, rootOkDev))))
                    {
                        RecursiveSeedEvalOutput next{};
                        if (!rootOkDev)
                        {
                            out = std::move(next);
                            return true;
                        }
                        if (!deferRootValidation)
                            assignRange(state.mGoldenSeed, seed.begin(), seed.end());
                        next.mValid = true;
                        next.mTbkDevice = std::move(rootTbkDev);
                        next.mValidationPending = deferRootValidation;
                        out = std::move(next);
                        return true;
                    }
                    // A deferred attempt is transactional and device-only. If a
                    // fast-path primitive declines, the outer wrapper drains it
                    // and reruns this seed through the exact legacy path.
                    if (deferRootValidation) return false;
                    // fall through to the host path on any failure
                }
#endif

                RnsPoly rootKey{};
                {
                    HostStep step("send: root key (host)");
                    if (!computeRootSenderKey(state, seed, rootKey))
                    {
                        return false;
                    }
                }

                ShrinkExpandExpandSenderInput expandInput{};
                assignRange(expandInput.mSeed, seed.begin(), seed.end());
                expandInput.mSid = state.mParams.mSessionId;
                expandInput.mDigest = *state.mRootDPrimeRt;
                expandInput.mMaskDigest = *state.mRootDPrimeRt;
                expandInput.mTbkPrime = rootKey;

                ShrinkExpandSenderExpandOutput expandOutput{};
                const Params& seedParams = rootSeedParams;
                const bool publicSeed = rootPublicSeed;
                bool candidateOk = publicSeed;
                {
                    HostStep step("send: root expand (host)");
                    if (!shrinkExpandExpandSender(state.mShrinkExpandState, expandInput, expandOutput))
                    {
                        return false;
                    }
                }
                // PublicSeed accepts by construction: there is no seed to reject,
                // so the rounding predicate is not evaluated at all.
                if (isLeaf && expandOutput.mTbk.size() > state.mParams.mW)
                    expandOutput.mTbk.resize(state.mParams.mW);
                if (!publicSeed &&
                    !(isLeaf ? validateLeafGoldenSeedCandidate(seedParams, expandOutput.mTbk, candidateOk)
                             : validateGoldenSeedCandidate(seedParams, expandOutput.mTbk, candidateOk)))
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
                // Intermediate Root expansions check the complete muHi block;
                // a Root that is also the leaf checks only its logical output.
                if (expandOutput.mTbk.size() > state.mParams.mW)
                {
                    expandOutput.mTbk.resize(state.mParams.mW);
                }
                next.mTbk = std::move(expandOutput.mTbk);
                out = std::move(next);
                return true;
            }

            if (!state.mNextLevelState)
            {
                return false;
            }

#if defined(ENABLE_LOGVOLE_CUDA)
            gpu::PreparedSenderCt2Ptr senderCt2Prefetch;
            if (ct2PrefetchLevelsRemaining != 0u &&
                (deferGoldenValidation || state.mParams.mCt2SeedMode == Ct2SeedMode::PublicSeed) &&
                gpu::enabled() &&
                gpu::topSenderCt2PrefetchEnabled())
            {
                const u32 prefetchChunkCount = computeWDoublePrime(state.mParams, muHi);
                const RnsPoly* prefetchRootDigest = resolveRootMaskDigest(state);
                const block* prefetchRootDigestHash = resolveRootMaskDigestHash(state);
                if (prefetchChunkCount != 0u && prefetchRootDigest && prefetchRootDigestHash)
                {
                    // All inputs to this level's ct2 are fixed before its child
                    // key exists. Failure to prepare is deliberately non-fatal:
                    // expandSenderChunks below queues the established main-stream
                    // sampler when the handle remains null.
                    (void)gpu::prefetchSenderCt2(
                        state.mShrinkExpandState, seed, state.mParams.mSessionId,
                        countSeedInstances(*state.mNextLevelState),
                        *prefetchRootDigestHash, prefetchChunkCount, senderCt2Prefetch);
                }
            }
#endif

            RecursiveSeedEvalOutput childEval{};
            {
                HostStep step("send: child eval", state.mParams.mW);
                if (!evaluateSenderSeedCandidateImpl(
                        *state.mNextLevelState, seed, childEval, false, deferGoldenValidation,
                        ct2PrefetchLevelsRemaining == 0u
                            ? 0u
                            : ct2PrefetchLevelsRemaining - 1u, true))
                {
                    return false;
                }
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
            const block* rootMaskDigestHash = resolveRootMaskDigestHash(state);
            if (wDoublePrime == 0 || rootMaskDigest == nullptr || rootMaskDigestHash == nullptr)
            {
                return false;
            }

            const u64 instanceBase = countSeedInstances(*state.mNextLevelState);

#if defined(ENABLE_LOGVOLE_CUDA)
            // Fully device-resident path: denoise + aggregate the child's tbk,
            // expand, and validate the candidate without ever moving a
            // polynomial to the host. Only an accepted top-level result is
            // downloaded, by the caller.
            if (gpu::enabled())
            {
                HostStep step("send: level expand (device)", state.mParams.mW);
                RingNttContext gpuCtx{};
                if (!makeRingNttContext(state.mParams.mShrinkExpand.mRing, gpuCtx))
                {
                    return false;
                }

                gpu::DeviceBatchPtr childDev = childEval.mTbkDevice;
                if (childEval.mValidationPending && !childDev)
                {
                    return false;
                }
                if (!childDev)
                {
                    HostStep up("send: upload child tbk (host->dev)", state.mParams.mW);
                    childDev = gpu::upload(
                        gpuCtx, std::span<const RnsPoly>(childEval.mTbk.data(), childEval.mTbk.size()));
                }

                gpu::DeviceBatchPtr kPrimeDev;
                gpu::DeviceBatchPtr tbkDev;
                const bool publicSeedDev =
                    state.mParams.mCt2SeedMode == Ct2SeedMode::PublicSeed;
                const bool deferThisValidation = deferGoldenValidation && !publicSeedDev;
                bool candidateOkDev = publicSeedDev || deferThisValidation;
                const Params seedParamsDev =
                    makeSeedParams(state.mParams, state.mShrinkExpandState.mParams);
                const Params childSeedParamsDev = makeSeedParams(
                    state.mNextLevelState->mParams,
                    state.mNextLevelState->mShrinkExpandState.mParams);

                if (childDev &&
                    (childEval.mValidationPending
                         ? gpu::denoiseAndAggValidateDevice(
                               gpuCtx, *childDev, tauHi, childSeedParamsDev, kPrimeDev,
                               state.mNextLevelState->mParams.mW)
                         : gpu::denoiseAndAggDevice(
                               gpuCtx, *childDev, tauHi, kPrimeDev,
                               state.mNextLevelState->mParams.mW)) &&
                    kPrimeDev && kPrimeDev->count() == wDoublePrime &&
                    gpu::expandSenderChunks(
                        state.mShrinkExpandState,
                        std::span<const RnsPoly>(),
                        kPrimeDev.get(),
                        std::span<const u8>(seed.data(), seed.size()),
                        state.mParams.mSessionId,
                        instanceBase,
                        *rootMaskDigestHash,
                        tbkDev,
                        senderCt2Prefetch.get()) &&
                    tbkDev && tbkDev->count() == static_cast<std::size_t>(wDoublePrime) * muHi &&
                    (publicSeedDev || deferThisValidation ||
                     (isLeaf ? gpu::validateLeafGoldenSeedDevice(seedParamsDev, *tbkDev, candidateOkDev)
                             : gpu::validateGoldenSeedDevice(seedParamsDev, *tbkDev, candidateOkDev))))
                {
                    RecursiveSeedEvalOutput next{};
                    if (!candidateOkDev)
                    {
                        out = std::move(next);
                        return true;
                    }

                    next.mValid = true;
                    next.mTbkDevice = tbkDev;
                    next.mValidationPending = deferThisValidation;
                    // mPrecomputedTbk only has to be non-null for the levels
                    // below the top; the top level's host copy is materialised by
                    // ensureSenderPrecomputeImpl.
                    if (!deferThisValidation)
                        state.mPrecomputedTbk = std::make_shared<std::vector<RnsPoly>>();
                    out = std::move(next);
                    return true;
                }
                if (deferGoldenValidation) return false;
                // fall through to the host path on any failure
            }
#endif

            std::vector<RnsPoly> kPrimeHat;
            std::vector<RnsPoly> kPrime;
            if (!seedLabelDenoiseTbm(
                    childEval.mTbk,
                    wPrime,
                    tauHi,
                    state.mParams.mShrinkExpand.mRing,
                    kPrimeHat,
                    state.mParams.mShrinkExpand.mNumWorkerThreads) ||
                !seedLabelAgg(
                    std::move(kPrimeHat),
                    wDoublePrime,
                    tauHi,
                    state.mParams.mShrinkExpand.mRing,
                    kPrime) ||
                kPrime.size() != wDoublePrime)
            {
                return false;
            }

            const bool publicSeed = state.mParams.mCt2SeedMode == Ct2SeedMode::PublicSeed;
            const Params seedParams = makeSeedParams(state.mParams, state.mShrinkExpandState.mParams);
            const bool earlyCheckEnabled = [] {
                const char* value = std::getenv("LV_CPU_EARLY_GOLDEN_CHECK");
                return !value || value[0] != '0';
            }();
            const auto workers = state.mShrinkExpandState.mParams.mNumWorkerThreads;
            const bool earlyCheck = !publicSeed && earlyCheckEnabled && workers >= 1 && workers <= 4;
            RingNttContext checkCtx{};
            std::vector<RoundingCheckConstants> rounding;
            RoundingCheckConstants leafRounding;
            if (earlyCheck && (!makeRingNttContext(seedParams.mShrinkExpand.mRing, checkCtx) ||
                !(isLeaf ? buildLeafRoundingCheckConstants(seedParams, checkCtx, leafRounding)
                         : buildRoundingCheckConstants(seedParams, checkCtx, rounding)))) return false;
            std::atomic<bool> candidateValid{true};
            // Only intermediate GoldenSeed levels validate the padded suffix.
            // The leaf checks exactly the coefficients sent to the Z_p decoder.
            std::vector<RnsPoly> finalTbk((publicSeed || isLeaf) ? state.mParams.mW :
                static_cast<std::size_t>(wDoublePrime) * muHi);

            {
            if (!detail::runParallelTasks(
                    wDoublePrime,
                    state.mShrinkExpandState.mParams.mNumWorkerThreads,
                    [&](std::size_t taskIdx) {
                        if (earlyCheck && !candidateValid.load(std::memory_order_relaxed)) return true;
                        const auto chunkIdx = static_cast<u32>(taskIdx);
                        const std::size_t start = static_cast<std::size_t>(chunkIdx) * muHi;
                        const std::size_t end =
                            std::min(start + static_cast<std::size_t>(muHi), finalTbk.size());

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

                        if (earlyCheck)
                        {
                            HostStep step("cpu sender detail: golden validation");
                            // Keep this level's margins and global polynomial
                            // indices. The leaf excludes the unused padded tail.
                            for (std::size_t idx = 0; idx < end - start; ++idx)
                            {
                                bool accepted = false;
                                if (!(isLeaf
                                        ? checkRoundingPolynomial(checkCtx, leafRounding, expandOutput.mTbk[idx], accepted)
                                        : checkGoldenPolynomial(seedParams, checkCtx, rounding,
                                            expandOutput.mTbk[idx], start + idx, accepted))) return false;
                                if (!accepted)
                                {
                                    candidateValid.store(false, std::memory_order_relaxed);
                                    return true;
                                }
                            }
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
            }

            bool candidateOk = publicSeed || (earlyCheck && candidateValid.load(std::memory_order_relaxed));
            if (!publicSeed && !earlyCheck &&
                !(isLeaf ? validateLeafGoldenSeedCandidate(seedParams, finalTbk, candidateOk)
                         : validateGoldenSeedCandidate(seedParams, finalTbk, candidateOk)))
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
            finalTbk.resize(state.mParams.mW);
            // Child caches support the recursive precompute API. At the top,
            // ensureSenderPrecomputeImpl immediately takes ownership of mTbk;
            // making another copy here only to overwrite it was redundant.
            if (retainHostCache)
                state.mPrecomputedTbk = std::make_shared<std::vector<RnsPoly>>(finalTbk);
            next.mTbk = std::move(finalTbk);
            out = std::move(next);
            return true;
        }

#if defined(ENABLE_LOGVOLE_CUDA)
        bool commitDeferredGoldenEvaluation(
            const SenderState& state,
            std::span<const u8> seed)
        {
            u32 tauHi = 0;
            if (!computeTauHi(state.mParams, tauHi))
                return false;
            const u32 rho = static_cast<u32>(
                state.mParams.mShrinkExpand.mRing.mCoeffModulusBits.size());
            if (rho == 0) return false;

            if (evalRecursiveMode(
                    state.mParams.mW, state.mParams.mShrinkExpand.mAlpha,
                    tauHi, rho) == RecursiveMode::Root)
            {
                // This is the only recursive state that historically published
                // the seed itself; the outer search publishes it on the top state.
                assignRange(state.mGoldenSeed, seed.begin(), seed.end());
                return true;
            }

            if (!state.mNextLevelState ||
                !commitDeferredGoldenEvaluation(*state.mNextLevelState, seed))
                return false;

            // Preserve the device path's existing marker semantics, but publish
            // it only after the conjunction of every level's predicate passed.
            state.mPrecomputedTbk = std::make_shared<std::vector<RnsPoly>>();
            return true;
        }
#endif

        bool evaluateSenderSeedCandidate(
            const SenderState& state,
            std::span<const u8> seed,
            RecursiveSeedEvalOutput& out)
        {
#if defined(ENABLE_LOGVOLE_CUDA)
            // PublicSeed has no candidate search, but once the Root digest and
            // public seed are authoritative its ancestor samplers are just as
            // independent of the child key as in GoldenSeed. Default only the
            // measured H200 geometry to two levels; 0 explicitly rolls it back.
            static const int publicPrefetchOverride = [] {
                const char* v = std::getenv("LV_GPU_NOGOLD_SENDER_CT2_PREFETCH");
                if (!v) return -1;
                return v && v[0] >= '1' && v[0] <= '3' && v[1] == '\0'
                    ? static_cast<int>(v[0] - '0') : 0;
            }();
            const u32 publicPrefetchLevels = publicPrefetchOverride >= 0
                ? static_cast<u32>(publicPrefetchOverride)
                : gpu::enabled() ? defaultPublicSenderCt2PrefetchLevels(state) : 0u;
            if (publicPrefetchLevels && gpu::enabled() && seed.size() == 16u &&
                state.mParams.mCt2SeedMode == Ct2SeedMode::PublicSeed &&
                gpu::topSenderCt2PrefetchEnabled())
            {
                return evaluateSenderSeedCandidateImpl(
                    state, seed, out, true, false, publicPrefetchLevels);
            }
            if (gpu::enabled() &&
                state.mParams.mCt2SeedMode == Ct2SeedMode::GoldenSeed &&
                gpu::deferredGoldenValidationEnabled())
            {
                RingNttContext ctx{};
                if (makeRingNttContext(state.mParams.mShrinkExpand.mRing, ctx) &&
                    gpu::beginGoldenValidationAttempt(ctx))
                {
                    RecursiveSeedEvalOutput deferred{};
                    const bool evaluated = evaluateSenderSeedCandidateImpl(
                        state, seed, deferred, true, true,
                        gpu::topSenderCt2PrefetchLevels(
                            defaultTopSenderCt2PrefetchLevels(state)));
                    if (!evaluated || !deferred.mValid ||
                        !deferred.mValidationPending || !deferred.mTbkDevice)
                    {
                        // No deferred state was published. Drain scratch and rerun
                        // the exact same supplied seed through the legacy path.
                        if (!gpu::abortGoldenValidationAttempt()) return false;
                        return evaluateSenderSeedCandidateImpl(
                            state, seed, out, true, false);
                    }

                    const Params topSeedParams = makeSeedParams(
                        state.mParams, state.mShrinkExpandState.mParams);
                    if (!gpu::queueLeafGoldenSeedValidation(
                            topSeedParams, *deferred.mTbkDevice))
                    {
                        if (!gpu::abortGoldenValidationAttempt()) return false;
                        return evaluateSenderSeedCandidateImpl(
                            state, seed, out, true, false);
                    }

                    bool accepted = false;
                    if (!gpu::finishGoldenValidationAttempt(accepted)) return false;
                    if (!accepted)
                    {
                        out = RecursiveSeedEvalOutput{};
                        return true;
                    }

                    if (!commitDeferredGoldenEvaluation(state, seed)) return false;
                    deferred.mValidationPending = false;
                    out = std::move(deferred);
                    return true;
                }
            }
#endif
            return evaluateSenderSeedCandidateImpl(state, seed, out, true, false);
        }

        bool findRecursiveGoldenSeedAndEvaluate(
            const SenderState& state,
            PRNG& prng,
            RecursiveSeedEvalOutput& out)
        {
            constexpr int maxSeedAttempts = 100;
            AutoTimer searchTimer(globalTimingStats.mSeedAttemptTimeUs);
            HostStep searchPhase("cpu sender: seed search and expansion");
            for (int attempt = 0; attempt < maxSeedAttempts; ++attempt)
            {
                AlignedUnVec<u8> seed(16);
                prng.get(seed.data(), seed.size());

                globalTimingStats.mSeedAttemptCount.fetch_add(1, std::memory_order_relaxed);

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
            if (state.mPrecomputedTbk &&
                (!state.mPrecomputedTbk->empty() || state.mPrecomputedTbkDevice))
            {
                return true;
            }

            RecursiveSeedEvalOutput eval{};
            bool ok = false;
            if (state.mParams.mCt2SeedMode == Ct2SeedMode::PublicSeed)
            {
                // No search: one seed, derived from the transcript, evaluated once.
                if (!state.mGoldenSeed.empty())
                {
                    ok = evaluateSenderSeedCandidate(state, state.mGoldenSeed, eval);
                }
                else
                {
                    AlignedUnVec<u8> seed;
                    if (!derivePublicCt2SeedForState(state, seed))
                    {
                        return false;
                    }
                    // mSeedAttemptCount stays at zero: there is no search here, so
                    // "attempts" is not a meaningful quantity for this mode. The
                    // timer is still used, because what it measures - the one
                    // recursive sender expansion - is work both modes have to do;
                    // GoldenSeed just repeats it until a seed is accepted.
                    AutoTimer expandTimer(globalTimingStats.mSeedAttemptTimeUs);
                    HostStep expandPhase("cpu sender: public-seed expansion");
                    ok = evaluateSenderSeedCandidate(state, seed, eval);
                    if (ok && eval.mValid)
                    {
                        state.mGoldenSeed = std::move(seed);
                    }
                }
            }
            else
            {
                ok = state.mGoldenSeed.empty() ?
                    findRecursiveGoldenSeedAndEvaluate(state, prng, eval) :
                    evaluateSenderSeedCandidate(state, state.mGoldenSeed, eval);
            }
            if (!ok || !eval.mValid)
            {
                return false;
            }

#if defined(ENABLE_LOGVOLE_CUDA)
            // GoldenSeed drains the stream when it reads the final validation
            // verdict (one accumulated flag in the deferred path), which also makes
            // the device keys safe to hand on. PublicSeed runs no validation, so the
            // drain has to be explicit: the keys are consumed by
            // whichever thread resumes the sender coroutine after the next socket
            // wait, and threadStream() is keyed on the thread, so stream ordering
            // alone does not guarantee the expansion has landed.
            if (state.mParams.mCt2SeedMode == Ct2SeedMode::PublicSeed &&
                gpu::enabled() && eval.mTbkDevice && !gpu::syncStream())
            {
                return false;
            }

            // The keys never have to reach the host: unwrapRingLabelsCrt has a
            // device path that reads them straight out of this buffer, so the
            // handle is parked in the state instead of a 256 KiB-per-key
            // download.
            if (eval.mTbk.empty() && eval.mTbkDevice &&
                eval.mTbkDevice->count() >= state.mParams.mW)
            {
                state.mPrecomputedTbk = std::make_shared<std::vector<RnsPoly>>();
                state.mPrecomputedTbkDevice = eval.mTbkDevice;
                state.mPrecomputedTbkCount = state.mParams.mW;
                return true;
            }
            if (eval.mTbk.empty() && eval.mTbkDevice)
            {
                if (!gpu::download(*eval.mTbkDevice, eval.mTbk, state.mParams.mW))
                {
                    return false;
                }
            }
#endif
            if (eval.mTbk.size() < state.mParams.mW)
            {
                return false;
            }
            eval.mTbk.resize(state.mParams.mW);

            state.mPrecomputedTbk = std::make_shared<std::vector<RnsPoly>>(std::move(eval.mTbk));
            state.mPrecomputedTbkDevice.reset();
            state.mPrecomputedTbkCount = 0;
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

        bool setupParallelCopyEnabled()
        {
#if defined(ENABLE_LOGVOLE_CUDA)
            const char* value = std::getenv("LV_GPU_SETUP_PARALLEL_COPY");
            return (!value || value[0] != '0') && gpu::enabled();
#else
            return false;
#endif
        }

        bool sharedSetupStateEnabled(bool requested)
        {
#if defined(ENABLE_LOGVOLE_CUDA)
            const char* value = std::getenv("LV_GPU_SETUP_SHARED_STATE");
            return requested && (!value || value[0] != '0') && gpu::enabled();
#else
            (void)requested;
            return false;
#endif
        }

        struct SetupPolyCopy
        {
            const std::vector<RnsPoly>* mSource;
            std::vector<RnsPoly>* mDestination;
        };

        bool copySetupPolys(std::initializer_list<SetupPolyCopy> batches, u32 workers)
        {
            std::size_t taskCount = 0;
            for (const auto& batch : batches)
            {
                batch.mDestination->resize(batch.mSource->size());
                taskCount += batch.mSource->size();
            }
            return detail::runParallelTasks(taskCount, workers, [&](std::size_t idx) {
                for (const auto& batch : batches)
                {
                    if (idx < batch.mSource->size())
                    {
                        (*batch.mDestination)[idx] = (*batch.mSource)[idx];
                        return true;
                    }
                    idx -= batch.mSource->size();
                }
                return false;
            });
        }

        template <typename State>
        void copySetupMetadata(const State& source, State& destination)
        {
            destination.mParams = source.mParams;
            destination.mPublicANtt = source.mPublicANtt;
            destination.mPublicBNtt = source.mPublicBNtt;
            if constexpr (requires { source.mPublicANttDevice; })
            {
                destination.mPublicANttDevice = source.mPublicANttDevice;
                destination.mPublicBNttDevice = source.mPublicBNttDevice;
                destination.mLazyPublicUniformHosts = source.mLazyPublicUniformHosts;
                if constexpr (requires { source.mPublicUniformRunId; })
                    destination.mPublicUniformRunId = source.mPublicUniformRunId;
            }
            destination.mCt1.mRows = source.mCt1.mRows;
            destination.mCt1.mCols = source.mCt1.mCols;
            destination.mLacct.mWidthPadded = source.mLacct.mWidthPadded;
            destination.mLacct.mLevels = source.mLacct.mLevels;
            destination.mLacct.mCt.mRows = source.mLacct.mCt.mRows;
            destination.mLacct.mCt.mCols = source.mLacct.mCt.mCols;
            // Ordinary state copying shares the lazy device mirror. Retain that
            // identity while every mutable host polynomial remains independent.
            destination.mGpuCache = source.mGpuCache;
            if constexpr (requires { source.mLazyS; })
                destination.mLazyS = source.mLazyS;
            if constexpr (requires { source.mTopSk1Device; })
            {
                destination.mTopSk1Device = source.mTopSk1Device;
                destination.mLazyTopSk1 = source.mLazyTopSk1;
                destination.mTopSk1OwnerRunId = source.mTopSk1OwnerRunId;
            }
            destination.mLazyLacct = source.mLazyLacct;
            if constexpr (requires { source.mLazyCt1; })
            {
                destination.mLazyCt1 = source.mLazyCt1;
                destination.mLazyRandomizers = source.mLazyRandomizers;
            }
            else
                destination.mLazyCt1Ntt = source.mLazyCt1Ntt;
        }

        bool copyReusableSetupState(
            const ShrinkExpandSenderState& source,
            ShrinkExpandSenderState& destination)
        {
            HostStep setupStep("setup sender: reusable state copy");
            if (source.mSharedHostState)
            {
                ShrinkExpandSenderState next{};
                copySetupMetadata(source, next);
                next.mSk1 = source.mSk1;
                next.mSharedHostState = source.mSharedHostState;
                destination = std::move(next);
                return true;
            }
            if (!setupParallelCopyEnabled())
            {
                destination = source;
                return true;
            }
            ShrinkExpandSenderState next{};
            copySetupMetadata(source, next);
            if (!copySetupPolys({
                    { &source.mS, &next.mS },
                    { &source.mR, &next.mR },
                    { &source.mSk1, &next.mSk1 },
                    { &source.mCt1.mPolys, &next.mCt1.mPolys },
                    { &source.mLacct.mCt.mPolys, &next.mLacct.mCt.mPolys }
                }, source.mParams.mNumWorkerThreads)) return false;
            destination = std::move(next);
            return true;
        }

        bool copyReusableSetupState(
            const ShrinkExpandReceiverState& source,
            ShrinkExpandReceiverState& destination)
        {
            HostStep setupStep("setup receiver: reusable state copy");
            if (source.mSharedHostState)
            {
                ShrinkExpandReceiverState next{};
                copySetupMetadata(source, next);
                next.mSharedHostState = source.mSharedHostState;
                destination = std::move(next);
                return true;
            }
            if (!setupParallelCopyEnabled())
            {
                destination = source;
                return true;
            }
            ShrinkExpandReceiverState next{};
            copySetupMetadata(source, next);
            if (!copySetupPolys({
                    { &source.mCt1.mPolys, &next.mCt1.mPolys },
                    { &source.mLacct.mCt.mPolys, &next.mLacct.mCt.mPolys }
                }, source.mParams.mNumWorkerThreads)) return false;
            destination = std::move(next);
            return true;
        }

        void shareCompletedSetupState(ShrinkExpandSenderState& state)
        {
            // Move the only full package into immutable ownership. Every view
            // retains the small key required by recursive Root setup; the
            // large S/R/ciphertext vectors are never cloned here.
            ShrinkExpandSenderState next{};
            copySetupMetadata(state, next);
            next.mSk1 = state.mSk1;
            next.mSharedHostState = std::make_shared<const ShrinkExpandSenderState>(std::move(state));
            state = std::move(next);
        }

        void shareCompletedSetupState(ShrinkExpandReceiverState& state)
        {
            ShrinkExpandReceiverState next{};
            copySetupMetadata(state, next);
            next.mSharedHostState = std::make_shared<const ShrinkExpandReceiverState>(std::move(state));
            state = std::move(next);
        }

#if defined(ENABLE_LOGVOLE_CUDA)
        class ResidentSeedLabelHostState final : public LazySeedLabelHostState
        {
        public:
            ResidentSeedLabelHostState(RingNttContext ctx,
                gpu::DeviceBatchPtr device, u32 gamma, u32 alpha, u32 tau,
                u64 ownerRunId, std::function<bool(RnsPoly&)> deltaFallback)
                : mCtx(std::move(ctx)), mDevice(std::move(device)),
                  mGamma(gamma), mAlpha(alpha), mTau(tau),
                  mOwnerRunId(ownerRunId),
                  mDeltaFallback(std::move(deltaFallback)) {}

            std::size_t count() const override
            {
                return static_cast<std::size_t>(mAlpha) * mTau *
                    ringModulusCount(mCtx);
            }
            bool matches(const RingParams& ring) const override
            {
                return mCtx.mParams == ring;
            }
            const std::vector<RnsPoly>& hostCoefficients() const override
            {
                std::call_once(mOnce, [&] {
                    if (currentProtocolCacheScope().mRole ==
                            ProtocolCacheRole::Receiver)
                        throw std::runtime_error(
                            "receiver cannot materialize sender seed-label state");
                    HostStep step("setup sender: seed-label explicit host view");
                    if (mDevice && gpu::enabled())
                    {
                        ScopedProtocolCacheScope ownerScope(
                            ProtocolCacheRole::Sender, mOwnerRunId);
                        std::vector<RnsPoly> exact;
                        if (gpu::setupSeedLabelRepBatchMatches(mCtx,
                                *mDevice, count(), mOwnerRunId) &&
                            gpu::download(*mDevice, exact, count()) &&
                            validateRingBatchShape(exact, mCtx.mParams))
                        {
                            mHost = std::move(exact);
                            return;
                        }
                    }
                    // A true GPU decline still has the original compact
                    // delta inputs. Replaying them never consumes the parent
                    // protocol PRNG or borrows another party's device state.
                    RnsPoly delta{};
                    if (!mDeltaFallback || !mDeltaFallback(delta) ||
                        !validateRingPolyShape(delta, mCtx.mParams) ||
                        !seedLabelRepOfflineSenderInput(std::vector<RnsPoly>{delta}, mGamma,
                            mAlpha, mTau, mCtx.mParams, mHost) ||
                        mHost.size() != count())
                        throw std::runtime_error(
                            "sender seed-label host fallback failed");
                });
                return mHost;
            }

        private:
            RingNttContext mCtx;
            gpu::DeviceBatchPtr mDevice;
            u32 mGamma;
            u32 mAlpha;
            u32 mTau;
            u64 mOwnerRunId;
            std::function<bool(RnsPoly&)> mDeltaFallback;
            mutable std::once_flag mOnce;
            mutable std::vector<RnsPoly> mHost;
        };
#endif

        bool materializeTopSk1HostViewsImpl(SenderState& state)
        {
            const auto& top = state.mShrinkExpandState;
            if (!top.mTopSk1Device) return true;
            if (!top.mLazyTopSk1 || !top.mLazyTopSk1->matches(top.mParams.mRing) ||
                top.mLazyTopSk1->count() != top.mParams.mTau) return false;
            std::vector<RnsPoly> exact;
#if defined(ENABLE_LOGVOLE_CUDA)
            RingNttContext ctx{};
            if (!makeRingNttContext(top.mParams.mRing, ctx) ||
                !gpu::topSecretUniformBatchMatches(ctx, *top.mTopSk1Device,
                    top.mParams.mTau, top.mTopSk1OwnerRunId)) return false;
            HostStep step("setup sender: top sk1 final public host view");
            if (!gpu::download(*top.mTopSk1Device, exact, top.mParams.mTau) ||
                !validateRingBatchShape(exact, ctx.mParams))
            {
                const char* strict = std::getenv("LV_GPU_SETUP_TOP_SK1_CONSUMER_STRICT");
                if (strict && strict[0] != '0') return false;
                exact = top.mLazyTopSk1->hostCoefficients();
            }
#else
            return false;
#endif
            const auto owner = top.mTopSk1Device.get();
            const auto fill = [&](auto&& self, SenderState& level,
                                  bool first) -> bool
            {
                auto& seState = level.mShrinkExpandState;
                if (seState.mTopSk1Device.get() != owner ||
                    seState.mTopSk1OwnerRunId != top.mTopSk1OwnerRunId ||
                    !seState.mLazyTopSk1 ||
                    seState.mLazyTopSk1->count() != exact.size() ||
                    !seState.mLazyTopSk1->matches(top.mParams.mRing)) return false;
                if (seState.mSk1.empty()) seState.mSk1 = exact;
                else if (!rnsBatchEqual(seState.mSk1, exact)) return false;
                if (!first)
                {
                    if (level.mSk1.empty()) level.mSk1 = exact;
                    else if (!rnsBatchEqual(level.mSk1, exact)) return false;
                }
                return !level.mNextLevelState ||
                    self(self, *level.mNextLevelState, false);
            };
            return fill(fill, state, true);
        }

        bool prepareSenderOfflineImpl(
            const SenderOfflineInput& input,
            PRNG& prng,
            SenderState& state,
            OfflineMessage& message,
            bool isTopLevel,
            const ShrinkExpandSenderState* reusableInternalState,
            bool encodeTransportMessages)
        {
            u32 tauHi = 0;
            u32 muHi = 0;
            const u32 rho = static_cast<u32>(input.mParams.mShrinkExpand.mRing.mCoeffModulusBits.size());
            const bool internalWrappedDelta = input.mSk1.empty() &&
                input.mWrappedDeltaDevice && input.mWrappedDeltaHostFallback &&
                input.mUseGpuResidentInternalState && isTopLevel &&
                encodeTransportMessages && input.mParams.mGamma == 1u;
            const bool internalTopSecret = input.mSk1.empty() &&
                input.mTopSk1Device && input.mLazyTopSk1 &&
                input.mUseGpuResidentInternalState && !isTopLevel &&
                encodeTransportMessages &&
                input.mParams.mShrinkExpand.mTau >= 2u &&
                input.mParams.mGamma == input.mParams.mShrinkExpand.mTau - 1u;
            if (!computeTauHi(input.mParams, tauHi) ||
                !computeMuHi(input.mParams, muHi) ||
                (!internalWrappedDelta && !internalTopSecret && input.mSk1.empty()) ||
                (!input.mSk1.empty() && !validateRingBatchShape(input.mSk1,
                    input.mParams.mShrinkExpand.mRing)) ||
                (input.mWrappedDeltaDevice && !internalWrappedDelta) ||
                (input.mTopSk1Device && !internalTopSecret) ||
                (input.mLazyTopSk1 && !internalTopSecret))
            {
                return false;
            }

            std::vector<RnsPoly> eagerSk1 = input.mSk1;
            std::shared_ptr<gpu::DeviceBatch> residentS;
            std::shared_ptr<const LazySeedLabelHostState> lazyS;
            const u64 deltaOwnerRunId = currentProtocolCacheScope().mRunId;
#if defined(ENABLE_LOGVOLE_CUDA)
            RingNttContext deltaCtx{};
            const char* chainOption = std::getenv("LV_GPU_SETUP_DELTA_CHAIN_DEVICE");
            const char* chainDecline = std::getenv("LV_GPU_SETUP_DELTA_CHAIN_FORCE_DECLINE");
            const char* chainStrictOption = std::getenv("LV_GPU_SETUP_DELTA_CHAIN_STRICT");
            const bool chainRequested = internalWrappedDelta && gpu::enabled() &&
                (!chainOption || chainOption[0] != '0');
            const bool chainStrict = chainRequested && chainStrictOption &&
                chainStrictOption[0] == '1';
            if (internalWrappedDelta)
            {
                if (!makeRingNttContext(input.mParams.mShrinkExpand.mRing,
                        deltaCtx) ||
                    !gpu::setupDeltaBatchMatches(deltaCtx,
                        *input.mWrappedDeltaDevice, 1u, deltaOwnerRunId))
                    return false;
            }
            if (internalTopSecret)
            {
                if (!makeRingNttContext(input.mParams.mShrinkExpand.mRing,
                        deltaCtx) ||
                    input.mSenderOwnerRunId != deltaOwnerRunId ||
                    input.mLazyTopSk1->count() != tauHi ||
                    !input.mLazyTopSk1->matches(deltaCtx.mParams) ||
                    !gpu::topSecretUniformBatchMatches(deltaCtx,
                        *input.mTopSk1Device, tauHi, deltaOwnerRunId))
                    return false;
                const char* topRepOption = std::getenv("LV_GPU_SETUP_TOP_SK1_REP_DEVICE");
                const char* topRepDecline = std::getenv("LV_GPU_SETUP_TOP_SK1_REP_FORCE_DECLINE");
                const char* topStrict = std::getenv("LV_GPU_SETUP_TOP_SK1_CONSUMER_STRICT");
                const bool topRepRequested = gpu::enabled() &&
                    (!topRepOption || topRepOption[0] != '0');
                if (topRepRequested && (!topRepDecline || topRepDecline[0] != '1'))
                    residentS = gpu::topSecretSeedLabelRepResident(deltaCtx,
                        *input.mTopSk1Device,
                        input.mParams.mShrinkExpand.mAlpha, tauHi);
                const std::size_t expected = static_cast<std::size_t>(
                    input.mParams.mShrinkExpand.mAlpha) * tauHi * rho;
                if (residentS && !gpu::setupSeedLabelRepBatchMatches(deltaCtx,
                        *residentS, expected, deltaOwnerRunId)) return false;
                if (!residentS && topRepRequested && topStrict && topStrict[0] != '0')
                    return false;
                if (residentS)
                    lazyS = std::make_shared<ReplicatedTopSecretHostState>(
                        deltaCtx, residentS, input.mLazyTopSk1,
                        input.mParams.mShrinkExpand.mAlpha, tauHi,
                        deltaOwnerRunId, false);
            }
            if (chainRequested && (!chainDecline || chainDecline[0] != '1'))
            {
                residentS = gpu::seedLabelRepResident(deltaCtx,
                    *input.mWrappedDeltaDevice, input.mParams.mGamma,
                    input.mParams.mShrinkExpand.mAlpha,
                    tauHi);
                const std::size_t expected = static_cast<std::size_t>(
                    input.mParams.mShrinkExpand.mAlpha) *
                    tauHi * rho;
                if (residentS && !gpu::setupSeedLabelRepBatchMatches(
                        deltaCtx, *residentS, expected, deltaOwnerRunId))
                    return false;
                if (chainStrict && !residentS) return false;
                if (residentS)
                    lazyS = std::make_shared<ResidentSeedLabelHostState>(
                        deltaCtx, residentS, input.mParams.mGamma,
                        input.mParams.mShrinkExpand.mAlpha,
                        tauHi, deltaOwnerRunId,
                        input.mWrappedDeltaHostFallback);
            }
#else
            if (internalWrappedDelta || internalTopSecret) return false;
#endif

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
                    (internalTopSecret
                        ? reusableInternalState->mTopSk1Device.get() !=
                            input.mTopSk1Device.get()
                        : !rnsBatchEqual(reusableInternalState->mSk1,
                            input.mSk1)))
                {
                    return false;
                }
                if (!copyReusableSetupState(*reusableInternalState, seState)) return false;
                nextMessage.mHasShrinkExpandMessage = false;
            }
            else
            {
                std::vector<RnsPoly> sRep;
                if (!residentS)
                {
                    if (internalTopSecret && eagerSk1.empty())
                        eagerSk1 = input.mLazyTopSk1->hostCoefficients();
                    if (eagerSk1.empty())
                    {
                        RnsPoly replay{};
                        if (!input.mWrappedDeltaHostFallback ||
                            !input.mWrappedDeltaHostFallback(replay) ||
                            !validateRingPolyShape(replay,
                                input.mParams.mShrinkExpand.mRing)) return false;
                        eagerSk1.push_back(std::move(replay));
                    }
                    if (!seedLabelRepOfflineSenderInput(
                            eagerSk1, input.mParams.mGamma,
                            input.mParams.mShrinkExpand.mAlpha, tauHi,
                            input.mParams.mShrinkExpand.mRing, sRep)) return false;
                }

                ShrinkExpandSenderOfflineInput seInput{};
                seInput.mParams = seParams;
                seInput.mS = std::move(sRep);
                seInput.mSDevice = residentS;
                seInput.mLazyS = lazyS;
                const char* deferCiphertexts = std::getenv("LV_GPU_SETUP_LAZY_CIPHERTEXTS");
                seInput.mDeferHostCiphertexts = encodeTransportMessages &&
                    (!deferCiphertexts || deferCiphertexts[0] != '0');
                if (!isTopLevel)
                {
                    if (internalTopSecret)
                    {
                        seInput.mFixedSk1Device = input.mTopSk1Device;
                        seInput.mLazyFixedSk1 = input.mLazyTopSk1;
                        seInput.mFixedSk1OwnerRunId = deltaOwnerRunId;
                    }
                    else seInput.mFixedSk1 = input.mSk1;
                }
                seInput.mDeferTopSk1Host = encodeTransportMessages &&
                    input.mUseGpuResidentInternalState;

                ShrinkExpandOfflineMessage seMessage{};
                if (encodeTransportMessages)
                {
                    if (!prepareShrinkExpandSenderOffline(seInput, prng, seState)) return false;
                    nextMessage.mEncodedShrinkExpandMessage =
                        encodeShrinkExpandOfflineState(seState, seParams.mNumWorkerThreads);
                }
                else
                {
                    if (!prepareShrinkExpandSenderOffline(seInput, prng, seMessage, seState)) return false;
                    nextMessage.mShrinkExpandMessage = std::move(seMessage);
                }
            }

#if defined(ENABLE_LOGVOLE_CUDA)
            if (internalWrappedDelta && eagerSk1.empty())
            {
                // mSk1 is an eager mutable field of the public CI-VOLE state.
                // Publish its one exact host polynomial only after the sender
                // device has completed seed-label repetition and LENC.
                HostStep hostStep("setup sender: wrapped delta public host view");
                std::vector<RnsPoly> exact;
                if (gpu::setupDeltaBatchMatches(deltaCtx,
                        *input.mWrappedDeltaDevice, 1u, deltaOwnerRunId) &&
                    gpu::download(*input.mWrappedDeltaDevice, exact, 1u) &&
                    exact.size() == 1u &&
                    validateRingPolyShape(exact[0], deltaCtx.mParams))
                    eagerSk1 = std::move(exact);
                else
                {
                    if (chainStrict) return false;
                    RnsPoly replay{};
                    if (!input.mWrappedDeltaHostFallback ||
                        !input.mWrappedDeltaHostFallback(replay) ||
                        !validateRingPolyShape(replay, deltaCtx.mParams))
                        return false;
                    eagerSk1.push_back(std::move(replay));
                }
            }
#endif
            SenderState nextState{};
            nextState.mParams = input.mParams;
            nextState.mSk1 = std::move(eagerSk1);
            nextState.mShrinkExpandState = std::move(seState);
            if (reusableInternalState == nullptr && !isTopLevel)
            {
#if defined(ENABLE_LOGVOLE_CUDA)
                if (mode != RecursiveMode::Root)
                    (void)gpu::prepareReusableSenderCache(nextState.mShrinkExpandState);
#endif
                if (sharedSetupStateEnabled(input.mUseGpuResidentInternalState) &&
                    nextState.mShrinkExpandState.mGpuCache)
                    shareCompletedSetupState(nextState.mShrinkExpandState);
                childReusableState = &nextState.mShrinkExpandState;
            }

            if (mode == RecursiveMode::Root)
            {
                if (!validRootWidth(input.mParams.mW, muHi) ||
                    !prepareRootOfflineSender(nextState, prng, nextMessage.mRootMessage, encodeTransportMessages))
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
                if (nextState.mShrinkExpandState.mTopSk1Device)
                {
                    childInput.mTopSk1Device =
                        nextState.mShrinkExpandState.mTopSk1Device;
                    childInput.mLazyTopSk1 =
                        nextState.mShrinkExpandState.mLazyTopSk1;
                    childInput.mSenderOwnerRunId =
                        nextState.mShrinkExpandState.mTopSk1OwnerRunId;
                }
                else childInput.mSk1 = nextState.mShrinkExpandState.mSk1;
                childInput.mLeafInputsAreGadget = true;
                childInput.mUseGpuResidentInternalState = input.mUseGpuResidentInternalState;

                auto childMessage = std::make_unique<OfflineMessage>();
                auto childState = std::make_unique<SenderState>();
                if (!prepareSenderOfflineImpl(childInput, prng, *childState, *childMessage,
                        false, childReusableState, encodeTransportMessages))
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

        template <typename Message>
        bool finalizeReceiverOfflineImpl(
            const ReceiverOfflineInput& input,
            Message&& message,
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
                if (!copyReusableSetupState(*reusableInternalState, seState)) return false;
            }
            else
            {
                if (!message.mHasShrinkExpandMessage)
                {
                    return false;
                }

                ShrinkExpandReceiverOfflineInput seInput{};
                seInput.mParams = seParams;
                seInput.mDeferHostSnapshot = input.mUseGpuResidentInternalState;

                if (!finalizeShrinkExpandReceiverOffline(seInput, std::forward<Message>(message).mShrinkExpandMessage, seState))
                {
                    return false;
                }
            }

            ReceiverState nextState{};
            nextState.mParams = input.mParams;
            nextState.mShrinkExpandState = std::move(seState);
            if (reusableInternalState == nullptr && !isTopLevel)
            {
#if defined(ENABLE_LOGVOLE_CUDA)
                // Descendants copy this exact receiver package. Publish one
                // completed immutable device mirror before those copies, so
                // each level does not upload the same ciphertexts separately.
                // A failed eager upload retains the established lazy fallback.
                if (mode != RecursiveMode::Root)
                    (void)gpu::prepareReusableReceiverCache(nextState.mShrinkExpandState);
#endif
                if (sharedSetupStateEnabled(input.mUseGpuResidentInternalState) &&
                    nextState.mShrinkExpandState.mGpuCache)
                    shareCompletedSetupState(nextState.mShrinkExpandState);
                childReusableState = &nextState.mShrinkExpandState;
            }

            if (mode == RecursiveMode::Root)
            {
                if (!validRootWidth(input.mParams.mW, muHi) ||
                    !finalizeRootOfflineReceiver(nextState, std::forward<Message>(message).mRootMessage))
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
                childInput.mUseGpuResidentInternalState = input.mUseGpuResidentInternalState;

                auto childState = std::make_unique<ReceiverState>();
                if (!finalizeReceiverOfflineImpl(childInput, std::forward<Message>(*message.mNextLevel), *childState, false, childReusableState))
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
        if (!prepareSenderOfflineImpl(input, prng, state, message, true, nullptr, false))
        {
            return false;
        }

        SenderOfflineOutput next{};
        next.mState = std::move(state);
        next.mMessage = std::move(message);
        out = std::move(next);
        return true;
    }

    bool materializeSenderTopSk1HostViews(SenderState& state)
    {
        if (currentProtocolCacheScope().mRole == ProtocolCacheRole::Receiver)
            return false;
        if (!state.mShrinkExpandState.mTopSk1Device) return true;
        const u64 runId = state.mShrinkExpandState.mTopSk1OwnerRunId;
        if (!runId) return false;
        ScopedProtocolCacheScope senderScope(ProtocolCacheRole::Sender, runId);
        return materializeTopSk1HostViewsImpl(state);
    }

    bool detail::prepareSenderOfflineForTransport(
        const SenderOfflineInput& input,
        PRNG& prng,
        SenderOfflineOutput& out)
    {
        bool directEncoding = false;
#if defined(ENABLE_LOGVOLE_CUDA)
        {
            ScopedProtocolCacheScope senderScope(
                ProtocolCacheRole::Sender, currentProtocolCacheScope().mRunId);
            const char* setting = std::getenv("LV_GPU_SETUP_DIRECT_WIRE");
            directEncoding = input.mUseGpuResidentInternalState && gpu::enabled() &&
                (!setting || setting[0] != '0');
        }
#endif
        if (!directEncoding)
        {
            if (!input.mWrappedDeltaDevice)
                return prepareSenderOffline(input, prng, out);
            if (!input.mSk1.empty() || !input.mWrappedDeltaHostFallback ||
                input.mParams.mGamma != 1u) return false;
            SenderOfflineInput eager = input;
            RnsPoly replay{};
            if (!eager.mWrappedDeltaHostFallback(replay) ||
                !validateRingPolyShape(replay,
                    eager.mParams.mShrinkExpand.mRing)) return false;
            eager.mSk1.push_back(std::move(replay));
            eager.mWrappedDeltaDevice.reset();
            eager.mWrappedDeltaHostFallback = {};
            return prepareSenderOffline(eager, prng, out);
        }

        SenderOfflineOutput next{};
        if (!prepareSenderOfflineImpl(input, prng, next.mState, next.mMessage,
                true, nullptr, true)) return false;
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
        OfflineMessage&& message,
        ReceiverOfflineOutput& out)
    {
        ReceiverState state{};
        if (!finalizeReceiverOfflineImpl(input, std::move(message), state, true, nullptr))
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

    bool goldenSeedRoundingMargins(
        const Params& params,
        const RingNttContext& ctx,
        std::vector<u64>& marginLo,
        std::vector<u64>& marginHi)
    {
        if (ctx.mGpuLightweight)
        {
            // GPU validation consumes only the per-target error margins. The
            // previous route built SEALContext and every reduced RNS base even
            // though their CRT operands are used solely by the CPU validator.
            // Derive the identical margins directly from the audited moduli;
            // the resulting four words are uploaded with the attempt state.
            if (!validateRingContextMetadata(ctx) ||
                !validateGoldenSeedSearchBudget(params, ctx)) return false;
            const double log2B = estimateNoiseBoundLog2(params);
            if (!std::isfinite(log2B)) return false;
            const std::size_t rho = ringModulusCount(ctx);
            marginLo.assign(rho, 0);
            marginHi.assign(rho, 0);
            for (std::size_t target = 0; target < rho; ++target)
            {
                double log2Delta = 0.0;
                for (std::size_t limb = 0; limb < rho; ++limb)
                    if (limb != target)
                        log2Delta += safeLog2(
                            static_cast<double>(ringModulusValue(ctx, limb)));
                if (!std::isfinite(log2Delta) || log2B > log2Delta - 1.0)
                    return false;
                const auto margin = floorToWideU64(std::exp2(
                    static_cast<long double>(log2B - log2Delta + 128.0)));
                marginLo[target] = margin.mLo;
                marginHi[target] = margin.mHi;
            }
            return true;
        }

        std::vector<RoundingCheckConstants> rounding;
        if (!buildRoundingCheckConstants(params, ctx, rounding))
        {
            return false;
        }

        const auto& hostModuli = getRingHostModuli(ctx);
        const std::size_t rho = hostModuli.size();
        if (rho != ringModulusCount(ctx)) return false;
        marginLo.assign(rho, 0);
        marginHi.assign(rho, 0);
        for (const auto& constants : rounding)
        {
            if (constants.mTargetLimbIndex >= rho)
            {
                return false;
            }
            marginLo[constants.mTargetLimbIndex] = constants.mMargin.mLo;
            marginHi[constants.mTargetLimbIndex] = constants.mMargin.mHi;
        }
        return true;
    }

    bool senderPrecompute(SenderState& state, PRNG& prng)
    {
        return ensureSenderPrecomputeImpl(state, prng);
    }

    bool senderHasPrecompute(const SenderState& state)
    {
        return static_cast<bool>(state.mPrecomputedTbk) && !state.mGoldenSeed.empty();
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
        // The seed the levels above this one expand with. Taken from the state
        // rather than the response because PublicSeed puts nothing in the
        // response; both modes leave the active seed in mGoldenSeed.
        next.mSeed = state.mGoldenSeed;
        next.mTbk = *state.mPrecomputedTbk;
        next.mTbkDevice = state.mPrecomputedTbkDevice;
        next.mTbkCount = state.mPrecomputedTbkCount;
        out = std::move(next);
        return true;
    }

    static bool finalizeRootOnlineReceiverImpl(
        ReceiverState& state,
        const ReceiverOnlineInput& input,
        const RootDigestState& digestState,
        const RootResponseMessage& response,
        RootResponseMessage* ownedResponse,
        ReceiverOnlineOutput& out)
    {
        RnsPoly receiverKey{};
        std::shared_ptr<void> receiverKeyDevice;
#if defined(ENABLE_LOGVOLE_CUDA)
        // Ask for the key on the device only when the expand below can take it there,
        // which is exactly when the shrink left its digest tree on the device.
        std::shared_ptr<void>* keyDevSlot =
            (gpu::enabled() && digestState.mGpuSession) ? &receiverKeyDevice : nullptr;
#else
        std::shared_ptr<void>* keyDevSlot = nullptr;
#endif
        const bool keyOk = ownedResponse
            ? finalizeRootResponseReceiver(
                  state,
                  digestState,
                  std::move(*ownedResponse),
                  receiverKey,
                  keyDevSlot)
            : finalizeRootResponseReceiver(
                  state,
                  digestState,
                  response,
                  receiverKey,
                  keyDevSlot);
        if (!keyOk)
        {
            return false;
        }

        ReceiverOnlineOutput next{};
        // finalizeRootResponseReceiver has just resolved the active seed into the
        // state: the sender's seed in GoldenSeed, the transcript-derived one in
        // PublicSeed, where the response carries none.
        next.mSeed = state.mGoldenSeed;

#if defined(ENABLE_LOGVOLE_CUDA)
        // If the shrink ran on the device its digest tree is still there, so the
        // expand runs there too and the result is handed up device-resident. This is
        // the whole point of carrying mGpuSession across the wire exchange: the
        // Root's expand used to be the one level that fell back to the host purely
        // because its tree lived in host memory.
        if (auto session = std::static_pointer_cast<gpu::LevelSession>(digestState.mGpuSession))
        {
            u32 muHiDev = 0;
            RingNttContext devCtx{};
            if (!computeMuHi(state.mParams, muHiDev) ||
                !makeRingNttContext(state.mParams.mShrinkExpand.mRing, devCtx))
            {
                return false;
            }

            // Already on the device when the key derivation ran there.
            auto skXDev = receiverKeyDevice
                ? std::static_pointer_cast<gpu::DeviceBatch>(receiverKeyDevice)
                : gpu::upload(devCtx, std::span<const RnsPoly>(&receiverKey, 1));
            gpu::DeviceBatchPtr tbmDev;
            if (!skXDev ||
                !gpu::expandReceiverChunksDevice(
                    state.mShrinkExpandState,
                    *session,
                    *skXDev,
                    std::span<const u8>(state.mGoldenSeed.data(), state.mGoldenSeed.size()),
                    input.mSid,
                    0,
                    digestState.mDPrimeHash,
                    muHiDev,
                    static_cast<u32>(receiverInputCount(input)),
                    tbmDev) ||
                !tbmDev)
            {
                return false;
            }

            // The consumer of this batch may not run on this thread: the receiver
            // coroutine suspends on the socket between the digest and the response,
            // and threadStream() is keyed on the thread, so stream ordering alone
            // does not guarantee the expand has landed. One drain per query.
            if (!gpu::syncStream())
            {
                return false;
            }

            state.mRootDPrimeRt = std::make_shared<RnsPoly>(digestState.mDPrime);
            state.mRootDPrimeHash = digestState.mDPrimeHash;
            state.mRootDPrimeHashValid = true;
            next.mTbmDevice = tbmDev;
            next.mTbmCount = receiverInputCount(input);
            out = std::move(next);
            return true;
        }
#endif

        ShrinkExpandExpandReceiverInput expandInput{};
        expandInput.mSeed = state.mGoldenSeed;
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
        state.mRootDPrimeHash = digestState.mDPrimeHash;
        state.mRootDPrimeHashValid = true;
        next.mTbm = std::move(expandOutput.mTbm);
        out = std::move(next);
        return true;
    }

    bool finalizeRootOnlineReceiver(
        ReceiverState& state,
        const ReceiverOnlineInput& input,
        const RootDigestState& digestState,
        const RootResponseMessage& response,
        ReceiverOnlineOutput& out)
    {
        return finalizeRootOnlineReceiverImpl(
            state, input, digestState, response, nullptr, out);
    }

    bool finalizeRootOnlineReceiver(
        ReceiverState& state,
        const ReceiverOnlineInput& input,
        const RootDigestState& digestState,
        RootResponseMessage&& response,
        ReceiverOnlineOutput& out)
    {
        return finalizeRootOnlineReceiverImpl(
            state, input, digestState, response, &response, out);
    }

    static bool finalizeRootResponseReceiverImpl(
        ReceiverState& state,
        const RootDigestState& digestState,
        const RootResponseMessage& response,
        RootResponseMessage* ownedResponse,
        RnsPoly& rootKey,
        std::shared_ptr<void>* rootKeyDevice)
    {
        u32 tauHi = 0;
        if (!digestState.mDPrimeHashValid ||
            !computeTauHi(state.mParams, tauHi))
        {
            return false;
        }

        // An owned message is all-or-nothing: reject malformed polynomial
        // metadata before consuming either field, so callers retain the exact
        // decoded frame on validation failure and can use the const diagnostic
        // path if desired.
        if (ownedResponse &&
            ownedResponse->mSkPrimeCoeffs.size() !=
                static_cast<std::size_t>(
                    ringPolyCoeffCount(state.mParams.mShrinkExpand.mRing)))
        {
            return false;
        }

        // In PublicSeed the response carries no seed and the receiver derives the
        // same bytes the sender used, from the session id and the root digest it
        // sent. A seed arriving in PublicSeed mode, or a missing one in GoldenSeed
        // mode, means the peer is running the other setting; fail rather than
        // silently produce garbage keys.
        AlignedUnVec<u8> ct2Seed;
        if (state.mParams.mCt2SeedMode == Ct2SeedMode::PublicSeed)
        {
            if (!response.mSeed.empty())
            {
                return false;
            }
            ct2Seed.resize(kCt2SeedBytes);
            derivePublicCt2Seed(
                state.mParams.mSessionId,
                digestState.mDPrimeHash,
                std::span<u8>(ct2Seed.data(), ct2Seed.size()),
                state.mParams.mOnlineMode);
        }
        else
        {
            if (response.mSeed.empty())
            {
                return false;
            }
            if (ownedResponse)
            {
                ct2Seed = std::move(ownedResponse->mSeed);
            }
            else
            {
                assignRange(ct2Seed, response.mSeed.begin(), response.mSeed.end());
            }
        }

        const u32 rho = static_cast<u32>(state.mParams.mShrinkExpand.mRing.mCoeffModulusBits.size());
        const u32 leftWidth = rootLeftWidth(tauHi, rho);
        RingNttContext ctx{};
        // hatD is only read by the host chain below. The device chain evaluates
        // against the device-resident left tree instead, and in that case hatD was
        // never brought to the host, so its absence is not an error.
        const bool haveHostHatD = digestState.mHatDRt.size() == leftWidth;
        const bool haveDeviceTree = static_cast<bool>(digestState.mLeftTreeGpu);
        if (rho == 0 ||
            (!haveHostHatD && !haveDeviceTree) ||
            !makeRingNttContext(state.mParams.mShrinkExpand.mRing, ctx))
        {
            return false;
        }

        RnsPoly skPrime{};
        bool skPrimeReady = false;
        const auto prepareSkPrime = [&]() {
            if (skPrimeReady) return true;
            if (ownedResponse)
            {
                if (ownedResponse->mSkPrimeCoeffs.size() !=
                    static_cast<std::size_t>(
                        ringPolyCoeffCount(state.mParams.mShrinkExpand.mRing)))
                {
                    return false;
                }
                skPrime.mCoeffs = std::move(ownedResponse->mSkPrimeCoeffs);
            }
            else if (!unpackSinglePoly(
                         state.mParams.mShrinkExpand.mRing,
                         response.mSkPrimeCoeffs,
                         skPrime))
            {
                return false;
            }
            skPrimeReady = true;
            return true;
        };

#if defined(ENABLE_LOGVOLE_CUDA)
        // The whole chain below as one kernel sequence. Only worth taking when the
        // caller can consume the key on the device, which the device expand can.
        if (rootKeyDevice && gpu::enabled() && digestState.mLeftTreeGpu &&
            (!digestState.mTopInputsNtt.empty() || digestState.mTopInputsNttGpu) &&
            prepareSkPrime())
        {
            RootStep step("final: device chain");
            gpu::DeviceBatchPtr keyDev;
            const auto topDev =
                std::static_pointer_cast<gpu::DeviceBatch>(digestState.mTopInputsNttGpu);
            const auto dPrimeDev =
                std::static_pointer_cast<gpu::DeviceBatch>(
                    digestState.mDPrimeGpu);
            const auto prepared =
                std::static_pointer_cast<gpu::PreparedRootFinalize>(
                    digestState.mRootFinalizePrefetch);
            bool finalized = gpu::rootFinalizeReceiverDevice(
                    state,
                    ctx,
                    digestState.mDPrime,
                    digestState.mDPrimeHash,
                    skPrime,
                    digestState.mTopInputsNtt,
                    topDev.get(),
                    digestState.mLeftTreeGpu,
                    std::span<const u8>(ct2Seed.data(), ct2Seed.size()),
                    state.mParams.mSessionId,
                    tauHi,
                    leftWidth,
                    keyDev,
                    prepared.get(),
                    dPrimeDev.get());
            // Allocation/metadata/event/launch failure in the experiment never
            // changes protocol state or consumes the host response. Re-run the
            // exact established monolithic device chain before considering the
            // much slower host fallback (whose device-only tree may not have a
            // host materialization).
            if (!finalized && prepared)
            {
                keyDev.reset();
                finalized = gpu::rootFinalizeReceiverDevice(
                    state,
                    ctx,
                    digestState.mDPrime,
                    digestState.mDPrimeHash,
                    skPrime,
                    digestState.mTopInputsNtt,
                    topDev.get(),
                    digestState.mLeftTreeGpu,
                    std::span<const u8>(ct2Seed.data(), ct2Seed.size()),
                    state.mParams.mSessionId,
                    tauHi,
                    leftWidth,
                    keyDev,
                    nullptr,
                    dPrimeDev.get());
            }
            if (finalized && keyDev)
            {
                state.mGoldenSeed = std::move(ct2Seed);
                *rootKeyDevice = std::move(keyDev);
                return true;
            }
        }
#endif
        std::vector<RnsPoly> replayedZeta;
        const std::vector<RnsPoly>* hostZeta = &digestState.mZeta;
        if (hostZeta->empty() && !digestState.mZetaTaskSeeds.empty())
        {
            RootStep step("final: replay root zeta fallback");
            if (!sampleRootZetaFromTaskSeeds(
                    ctx,
                    state.mRootRandomizerWidth,
                    state.mParams.mShrinkExpand.mGadgetLogBase,
                    digestState.mZetaTaskSeeds,
                    digestState.mZetaRangesPerPoly,
                    replayedZeta,
                    state.mShrinkExpandState.mParams.mNumWorkerThreads,
                    digestState.mZetaForceFirstReject))
            {
                return false;
            }
            hostZeta = &replayedZeta;
        }

        std::vector<RnsPoly> replayedTopInputs;
        const std::vector<RnsPoly>* hostTopInputs = &digestState.mTopInputsNtt;
#if defined(ENABLE_LOGVOLE_CUDA)
        if (hostTopInputs->empty() && digestState.mTopInputsNttGpu)
        {
            const auto topDev =
                std::static_pointer_cast<gpu::DeviceBatch>(digestState.mTopInputsNttGpu);
            if (topDev && gpu::download(*topDev, replayedTopInputs))
                hostTopInputs = &replayedTopInputs;
        }
#endif
        std::vector<RnsPoly> ctRApplied;
        std::vector<RnsPoly> decPartialNtt;
        std::vector<RnsPoly> topEvalNtt;
        std::vector<RnsPoly> leftEvalNtt;
        std::vector<RnsPoly> ctK;
        if (!prepareSkPrime())
        {
            return false;
        }
        {
            RootStep step("final: lheApplyCt1Trunc");
            const RingTensor* ctRView = &state.mRootCtRRt;
            if (state.mRootCtRWire)
            {
                HostStep phase("setup root: CtR host fallback");
                ctRView = &state.mRootCtRWire->get();
            }
            if (!lheApplyCt1Trunc(
                    ctx,
                    *ctRView,
                    digestState.mDPrime,
                    state.mParams.mShrinkExpand.mGadgetLogBase,
                    tauHi,
                    ctRApplied,
                    true,
                    state.mShrinkExpandState.mParams.mNumWorkerThreads))
            {
                return false;
            }
        }
        {
            RootStep step("final: lheDec");
            if (!lheDec(
                    ctx,
                    ctRApplied,
                    skPrime,
                    decPartialNtt,
                    nullptr,
                    true,
                    true,
                    state.mShrinkExpandState.mParams.mNumWorkerThreads))
            {
                return false;
            }
        }
        {
            RootStep step("final: evalRootTopCtNtt");
            if (!evalRootTopCtNtt(
                    state, ctx, digestState.mYLeft, *hostZeta, *hostTopInputs,
                    topEvalNtt))
            {
                return false;
            }
        }
        {
            RootStep step("final: lencEvalTrunc");
            // Reuse the tree the digest step built over the same hatD, when it kept
            // it. The overload without a tree rebuilds it, which is the single
            // largest host cost in the Root and is pure duplicate work.
            const bool ok = digestState.mLeftTree
                ? lencEvalTrunc(
                      ctx,
                      toLencLacct(state),
                      *digestState.mLeftTree,
                      leftWidth,
                      tauHi,
                      state.mParams.mShrinkExpand.mGadgetLogBase,
                      state.mParams.mShrinkExpand.mPlaintextModulusBits,
                      leftEvalNtt,
                      true,
                      state.mShrinkExpandState.mParams.mNumWorkerThreads,
                      true)
                : lencEvalTrunc(
                      ctx,
                      toLencLacct(state),
                      digestState.mHatDRt,
                      leftWidth,
                      tauHi,
                      state.mParams.mShrinkExpand.mGadgetLogBase,
                      state.mParams.mShrinkExpand.mPlaintextModulusBits,
                      leftEvalNtt,
                      true,
                      state.mShrinkExpandState.mParams.mNumWorkerThreads,
                      true);
            if (!ok)
            {
                return false;
            }
        }
        {
            RootStep step("final: buildHashedCt2");
            if (!buildHashedCt2(
                    ctx,
                    leftWidth,
                    ct2Seed,
                    state.mParams.mSessionId,
                    digestState.mDPrime,
                    0,
                    ctK))
            {
                return false;
            }
        }

        if (decPartialNtt.size() != leftWidth ||
            topEvalNtt.size() != leftWidth ||
            leftEvalNtt.size() != leftWidth ||
            ctK.size() != leftWidth)
        {
            return false;
        }

        // All the evaluation-domain arithmetic first, then ONE batched inverse
        // transform, then the coefficient-domain add. The row loop used to call
        // inverseNtt per row, which is below the batch threshold and so always ran
        // on the host; leftWidth is exactly kNttBatchGpuThreshold, so batching
        // hands these transforms to the GPU instead. Bit-identical: the transform
        // is the same one, only the dispatch granularity changes.
        std::vector<RnsPoly> tbmVec(leftWidth);
        {
            RootStep step("final: row combine");
            for (u32 row = 0; row < leftWidth; ++row)
            {
                RnsPoly phiNtt = std::move(topEvalNtt[row]);
                RnsPoly tbmNtt = std::move(decPartialNtt[row]);
                if (!ringAddInplace(phiNtt, leftEvalNtt[row], ctx) ||
                    !ringSubInplace(tbmNtt, phiNtt, ctx))
                {
                    return false;
                }
                tbmVec[row] = std::move(tbmNtt);
            }
        }

        {
            RootStep step("final: inverseNttBatch");
            if (!inverseNttBatch(tbmVec, ctx))
            {
                return false;
            }
        }

        {
            RootStep step("final: add ctK");
            for (u32 row = 0; row < leftWidth; ++row)
            {
                if (!ringAddInplace(tbmVec[row], ctK[row], ctx))
                {
                    return false;
                }
            }
        }

        state.mGoldenSeed = std::move(ct2Seed);
        RootStep step("final: denoiseAndAgg");
        return denoiseAndAggRootKey(ctx, tbmVec, tauHi, rootKey);
    }

    bool finalizeRootResponseReceiver(
        ReceiverState& state,
        const RootDigestState& digestState,
        const RootResponseMessage& response,
        RnsPoly& rootKey,
        std::shared_ptr<void>* rootKeyDevice)
    {
        return finalizeRootResponseReceiverImpl(
            state, digestState, response, nullptr, rootKey, rootKeyDevice);
    }

    bool finalizeRootResponseReceiver(
        ReceiverState& state,
        const RootDigestState& digestState,
        RootResponseMessage&& response,
        RnsPoly& rootKey,
        std::shared_ptr<void>* rootKeyDevice)
    {
        return finalizeRootResponseReceiverImpl(
            state, digestState, response, &response, rootKey, rootKeyDevice);
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
        if (!makeRingNttContext(ring, ctx))
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

    bool seedLabelAgg(
        std::vector<RnsPoly>&& inputHat,
        u32 outCount,
        u32 tau,
        const RingParams& ring,
        std::vector<RnsPoly>& out)
    {
        if (tau != 1) return seedLabelAgg(inputHat, outCount, tau, ring, out);
        if (inputHat.size() != outCount || !validateRingBatchShape(inputHat, ring)) return false;
        if (&out != &inputHat) out = std::move(inputHat);
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
        if (!makeRingNttContext(ring, ctx))
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
        if (!makeRingNttContext(ring, ctx))
        {
            return false;
        }

        std::vector<RnsPoly> digits;
        if (!gadgetDecomposeBitsRangeCentered(digest, gadgetLogBase, 1, tauHi, ctx, digits))
        {
            return false;
        }

        const auto& hostModuli = getRingHostModuli(ctx);
        const std::size_t rho = hostModuli.size();
        if (rho != ringModulusCount(ctx)) return false;
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
                    crtLift = seal::util::multiply_uint_mod(
                        crtLift, hostModuli[k].value(), hostModuli[j]);
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
                seal::util::MultiplyUIntModOperand lift;
                lift.set(crtLiftJModQj[j], hostModuli[j]);
                const u64* digitCoeffs = digit.mCoeffs.data();
                u64* liftedCoeffs = lifted.mCoeffs.data();

                for (std::size_t c = 0; c < n; ++c)
                {
                    const u64 value = digitCoeffs[limbOffset + c];
                    liftedCoeffs[limbOffset + c] =
                        seal::util::multiply_uint_mod(value, lift, hostModuli[j]);
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
        std::vector<RnsPoly>& out,
        u32 requestedWorkers)
    {
        (void)wPrime;
        if (tau == 0 || tbmPrime.empty() || !validateRingBatchShape(tbmPrime, ring))
        {
            return false;
        }

        RingNttContext ctx{};
        if (!makeRingNttContext(ring, ctx))
        {
            return false;
        }

#if defined(ENABLE_LOGVOLE_CUDA)
        if (gpu::enabled() && gpu::denoiseCombBatch(ctx, tbmPrime, out))
        {
            return true;
        }
#endif

        return shrinkExpandDenoiseComb(ctx, tbmPrime, out, requestedWorkers);
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

        const u64 alphaTau = static_cast<u64>(alpha) * tau;
        if (alphaTau > std::numeric_limits<u32>::max() / rho) return false;
        const u32 mu = static_cast<u32>(alphaTau * rho);
#if defined(ENABLE_LOGVOLE_CUDA)
        const char* device = std::getenv("LV_GPU_SETUP_SEED_LABEL_REP");
        if ((!device || device[0] != '0') && gpu::enabled())
        {
            RingNttContext ctx{};
            if (makeRingNttContext(ring, ctx) &&
                gpu::seedLabelRepDevice(ctx, s, gamma, alpha, tau, out)) return true;
            const char* strict = std::getenv("LV_GPU_SETUP_SEED_LABEL_REP_STRICT");
            if (strict && strict[0] == '1') return false;
        }
#endif
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
        if (!makeRingNttContext(ring, ctx))
        {
            return false;
        }

        return buildHashedCt2(ctx, coeffCount, seed, sid, digest, static_cast<u64>(instanceIdx), out);
    }

    bool validateGoldenSeedSearch(const Params& params)
    {
        RingNttContext ctx{};
        return makeRingNttContext(params.mShrinkExpand.mRing, ctx) && validateGoldenSeedSearchBudget(params, ctx);
    }

    double noiseBoundLog2(const Params& params)
    {
        return estimateNoiseBoundLog2(params);
    }

    bool leafGoldenSeedRoundingConstants(
        const Params& params, const RingNttContext& ctx, LeafGoldenSeedRoundingConstants& out)
    {
        ZpCrtContext zp{};
        const double log2B = estimateNoiseBoundLog2(params);
        const std::size_t rho = ringModulusCount(ctx);
        if (!rho || !validateRingContextMetadata(ctx) ||
            !(ctx.mParams == params.mShrinkExpand.mRing) || !std::isfinite(log2B) ||
            !makeZpCrtContext(params.mShrinkExpand.mRing, params.mShrinkExpand.mPlaintextModulusBits, zp))
            return false;

        const u64 p = zp.mPlaintextModulus;
        const double log2P = safeLog2(static_cast<double>(p));
        double log2Q = 0;
        wideU64 undershoot{};
        for (std::size_t i = 0; i < rho; ++i)
        {
            const u64 q = ringModulusValue(ctx, i);
            log2Q += safeLog2(static_cast<double>(q));
            undershoot = wideU64Add(undershoot, makeWideU64(q, 0));
        }
        // CI-VOLE multiplies floor(Q/p)*Delta by a plaintext coefficient x.
        // With r=Q mod p and M=Delta*x, p*floor(Q/p)*M/Q=M-r*M/Q.
        // M <= (p-1)^2 < p^2, so the product contributes less than p^3/Q.
        // Together with noise, use p*(B+p^2)/Q. Each reciprocal sum undershoots
        // by <sum(q_i) ulps; one allowance bounds the difference between the
        // predicate's and decoder's downward errors on either side.
        const double log2Margin = log2Sum(log2B, 2.0 * log2P) + log2P - log2Q;
        if (!std::isfinite(log2Margin) || log2Margin > -1.0) return false;
        constexpr double exponentSlack = 0x1p-32;
        const wideU64 margin = wideU64Add(wideU64Add(
            floorToWideU64(std::exp2(static_cast<long double>(log2Margin + exponentSlack + 128.0))),
            makeWideU64(1, 0)), undershoot);
        if (!wideU64Less(margin, wideU64OneShift(127))) return false;

        LeafGoldenSeedRoundingConstants next;
        next.mInverse.resize(rho);
        next.mReciprocalLo.resize(rho);
        next.mReciprocalHi.resize(rho);
        next.mMarginLo = margin.mLo;
        next.mMarginHi = margin.mHi;
        // Work directly with the certified primes. Constructing a seal::Modulus
        // here would repeat its primality test for every seed candidate; asking
        // for host moduli would also materialize NTT tables on lightweight GPU
        // contexts. The products below are below 2^122 (SEAL primes are <=61 bits),
        // within divModWide128's exact range.
        for (std::size_t i = 0; i < rho; ++i)
        {
            const u64 qi = ringModulusValue(ctx, i);
            if (qi < 2 || qi >> 61) return false;
            const auto reciprocal = reciprocal2Pow128Wide(qi);
            const auto multiplyMod = [&](u64 a, u64 b) {
                wideU64 quotient{};
                u64 remainder = 0;
                divModWide128(wideU64Mul(a, b), qi, reciprocal, quotient, remainder);
                return remainder;
            };
            u64 punctured = 1;
            for (std::size_t j = 0; j < rho; ++j)
                if (j != i) punctured = multiplyMod(punctured, ringModulusValue(ctx, j));
            u64 inverse = 0;
            if (!seal::util::try_invert_uint_mod(punctured, qi, inverse)) return false;
            next.mInverse[i] = multiplyMod(inverse, p);
            next.mReciprocalLo[i] = reciprocal.mLo;
            next.mReciprocalHi[i] = reciprocal.mHi;
        }
        out = std::move(next);
        return true;
    }

    bool validateLeafGoldenSeedCandidate(
        const Params& params, const std::vector<RnsPoly>& tbk, bool& out)
    {
        HostStep validationStep("cpu sender detail: golden validation");
        if (!params.mW || tbk.size() != params.mW ||
            !validateRingBatchShape(tbk, params.mShrinkExpand.mRing)) return false;
        RingNttContext ctx{};
        RoundingCheckConstants constants;
        if (!makeRingNttContext(params.mShrinkExpand.mRing, ctx) ||
            !buildLeafRoundingCheckConstants(params, ctx, constants)) return false;
        std::atomic<bool> accepted{true};
        if (!detail::runParallelTasks(tbk.size(), params.mShrinkExpand.mNumWorkerThreads,
                [&](std::size_t i) {
                    if (!accepted.load(std::memory_order_relaxed)) return true;
                    bool ok = false;
                    if (!checkRoundingPolynomial(ctx, constants, tbk[i], ok)) return false;
                    if (!ok) accepted.store(false, std::memory_order_relaxed);
                    return true;
                })) return false;
        out = accepted.load(std::memory_order_relaxed);
        return true;
    }

    bool validateNoGoldenSeedBudget(const Params& params)
    {
        RingNttContext ctx{};
        return makeRingNttContext(params.mShrinkExpand.mRing, ctx) && validateNoGoldenSeedBudgetImpl(params, ctx);
    }

    double noGoldenSeedFailureBits(const Params& params)
    {
        RingNttContext ctx{};
        if (!makeRingNttContext(params.mShrinkExpand.mRing, ctx))
        {
            return -std::numeric_limits<double>::infinity();
        }
        return noGoldenSeedFailureBitsImpl(params, ctx);
    }

    bool makeEffectiveTruncParams(const Params& params, Params& out)
    {
        ShrinkExpandParams trunc{};
        if (!makeTruncShrinkExpandParams(params, params.mShrinkExpand.mLeafInputsAreGadget, trunc))
        {
            return false;
        }
        Params effective = params;
        effective.mShrinkExpand = trunc;
        out = std::move(effective);
        return true;
    }

    bool validateCt2SeedMode(const Params& params)
    {
        if ((params.mOnlineMode != OnlineMode::Interactive &&
             params.mOnlineMode != OnlineMode::NonInteractive) ||
            (params.mOnlineMode == OnlineMode::NonInteractive &&
             params.mCt2SeedMode != Ct2SeedMode::PublicSeed)) return false;
        // The truncated set is what the recursion actually runs, and it is what
        // the noise bound is stated over, so the check has to be made against it.
        Params effective{};
        if (!makeEffectiveTruncParams(params, effective))
        {
            return false;
        }

        return params.mCt2SeedMode == Ct2SeedMode::PublicSeed
            ? validateNoGoldenSeedBudget(effective)
            : validateGoldenSeedSearch(effective);
    }

    bool validateGoldenSeedCandidate(
        const Params& params,
        const std::vector<RnsPoly>& tbkPerSampledPoly,
        bool& out)
    {
        HostStep validationStep("cpu sender detail: golden validation");
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
        if (!makeRingNttContext(params.mShrinkExpand.mRing, ctx))
        {
            return false;
        }

        std::vector<RoundingCheckConstants> rounding;
        if (!buildRoundingCheckConstants(params, ctx, rounding))
        {
            return false;
        }

        // Sampled polynomials have independent predicates. The same helper is
        // used by incremental CPU candidate evaluation, with global indices.
        std::atomic<bool> ok{ true };
        std::atomic<bool> shapeError{ false };
        const bool ran = detail::runParallelTasks(tbkPerSampledPoly.size(),
            params.mShrinkExpand.mNumWorkerThreads, [&](std::size_t sampledPolyIdx) {
                if (!ok.load(std::memory_order_relaxed)) return true;
                bool accepted = false;
                if (!checkGoldenPolynomial(params, ctx, rounding,
                    tbkPerSampledPoly[sampledPolyIdx], sampledPolyIdx, accepted))
                {
                    shapeError.store(true);
                    return false;
                }
                if (!accepted) ok.store(false, std::memory_order_relaxed);
                return true;
            });

        if (!ran || shapeError.load())
        {
            return false;
        }

        out = ok.load();
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
        if (!makeRingNttContext(params.mShrinkExpand.mRing, ctx) ||
            !validateGoldenSeedSearchBudget(params, ctx))
        {
            return false;
        }

        const std::size_t rho = ringModulusCount(ctx);
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

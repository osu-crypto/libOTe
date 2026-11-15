#include "libOTe/Vole/LogVole/LogVoleCpuRows.h"
#include "libOTe/Vole/LogVole/LogVoleRing.h"
#include "libOTe/Vole/LogVole/LogVolePublicCache.h"

// config.h defines ENABLE_LOGVOLE_CUDA and is not pulled in by LogVoleRing.h,
// so it has to precede the guard below or the GPU path silently compiles away.
#include "libOTe/config.h"
#include "libOTe/Vole/LogVole/LogVoleArithmetic.h"
#include "libOTe/Vole/LogVole/LogVoleCpuArithmetic.h"
#include "libOTe/Vole/LogVole/LogVoleCpuSampler.h"
#include "libOTe/Vole/LogVole/LogVoleRuntime.h"
#if defined(ENABLE_LOGVOLE_CUDA)
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuGaussian.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuBackend.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuProtocol.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuKernels.h"
#endif

#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Crypto/RandomOracle.h"

#include "seal/util/clipnormal.h"
#include "seal/util/common.h"
#include "seal/util/iterator.h"
#include "seal/util/ntt.h"
#include "seal/util/polyarithsmallmod.h"
#include "seal/util/rlwe.h"
#include "seal/util/uintarithsmallmod.h"
#include "seal/util/uintcore.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <functional>
#include <limits>
#include <mutex>
#include <string>
#include <stdexcept>
#include <tuple>
#include <unordered_map>
#include <vector>

namespace osuCrypto::LogVole
{
    struct RingHostContextCache
    {
        RingParams mParams;
        std::shared_ptr<const RingModulusMetadata> mRawModuli;
        ProtocolCacheRole mRole = ProtocolCacheRole::Unspecified;
        bool mExpandModChain = false;
        std::once_flag mOnce;
        std::shared_ptr<seal::SEALContext> mContext;
    };

    namespace
    {
        bool validateLightweightRingContext(const RingNttContext& ctx);
        // Exact 64-bit reduction, equal to `value % modulus.value()` for every
        // 64-bit value, but multiply based rather than divide based.
        inline u64 reduceU64(u64 value, const seal::Modulus& modulus)
        {
            return (value < modulus.value()) ? value : seal::util::barrett_reduce_64(value, modulus);
        }

        bool isPowerOfTwo(u32 value)
        {
            return value > 0 && (value & (value - 1u)) == 0u;
        }

        bool validateShapeAgainstContext(const RnsPoly& poly, const RingNttContext& ctx)
        {
            return (!ctx.mGpuLightweight || validateLightweightRingContext(ctx)) &&
                poly.mCoeffs.size() == ringPolyCoeffCount(ctx.mParams);
        }

        u64 basePowMod(u64 base, u32 exp, u64 mod)
        {
            seal::Modulus modulus(mod);
            u64 result = 1;
            u64 power = base % mod;
            u32 e = exp;
            while (e > 0)
            {
                if ((e & 1u) != 0)
                {
                    result = mulMod(result, power, modulus);
                }
                power = mulMod(power, power, modulus);
                e >>= 1;
            }
            return result;
        }

        bool highBitSet(const u64* value, std::size_t limbCount)
        {
            return limbCount != 0 && ((value[limbCount - 1] >> 63) != 0);
        }

        void arithmeticRightShift(u64* value, u32 shift, std::size_t limbCount)
        {
            if (limbCount == 0 || shift == 0)
            {
                return;
            }

            const bool negative = highBitSet(value, limbCount);
            const u64 totalBits = static_cast<u64>(limbCount) * 64;
            if (shift >= totalBits)
            {
                std::fill(value, value + limbCount, negative ? ~u64(0) : u64(0));
                return;
            }

            seal::util::right_shift_uint(value, static_cast<int>(shift), limbCount, value);
            if (!negative)
            {
                return;
            }

            const u64 firstFillBit = totalBits - shift;
            const std::size_t firstFillLimb = static_cast<std::size_t>(firstFillBit / 64);
            const u32 firstFillOffset = static_cast<u32>(firstFillBit % 64);
            if (firstFillLimb < limbCount)
            {
                if (firstFillOffset != 0)
                {
                    value[firstFillLimb] |= ~u64(0) << firstFillOffset;
                    for (std::size_t limbIdx = firstFillLimb + 1; limbIdx < limbCount; ++limbIdx)
                    {
                        value[limbIdx] = ~u64(0);
                    }
                }
                else
                {
                    for (std::size_t limbIdx = firstFillLimb; limbIdx < limbCount; ++limbIdx)
                    {
                        value[limbIdx] = ~u64(0);
                    }
                }
            }
        }

        void maskLowBits(u64* value, std::size_t limbCount, u32 bitCount)
        {
            for (std::size_t limbIdx = 0; limbIdx < limbCount; ++limbIdx)
            {
                const u64 bitOffset = static_cast<u64>(limbIdx) * 64;
                if (bitOffset >= bitCount)
                {
                    value[limbIdx] = 0;
                }
                else if (bitOffset + 64 > bitCount)
                {
                    const u32 remainingBits = bitCount - static_cast<u32>(bitOffset);
                    value[limbIdx] &= (u64(1) << remainingBits) - 1;
                }
            }
        }

        void setPowerOfTwo(u64* value, std::size_t limbCount, u32 bit)
        {
            std::fill(value, value + limbCount, u64(0));
            const std::size_t limbIdx = bit / 64;
            if (limbIdx < limbCount)
            {
                value[limbIdx] = u64(1) << (bit % 64);
            }
        }

        // SEAL's normal distribution consumes u32 words. PRNG's default
        // operator() is u64, so adapt the width explicitly without buffering,
        // allocation, locks or virtual dispatch in the sampling loop.
        struct AesNormalEngine
        {
            using result_type = u32;
            PRNG& source;
            static constexpr result_type min() { return 0; }
            static constexpr result_type max() { return ~result_type{0}; }
            result_type operator()() { return source.get<result_type>(); }
        };

        template<bool Add = false, typename Engine>
        void samplePolyNormal(
            Engine& engine,
            const seal::EncryptionParameters& parms,
            u64* destination,
            double noiseStandardDeviation,
            double noiseMaxDeviation,
            bool firstLimbOnly = false)
        {
            const auto& coeffModulus = parms.coeff_modulus();
            const std::size_t coeffModulusSize = firstLimbOnly ? 1u : coeffModulus.size();
            const std::size_t coeffCount = parms.poly_modulus_degree();
            seal::util::ClippedNormalDistribution dist(0, noiseStandardDeviation, noiseMaxDeviation);

            SEAL_ITERATE(seal::util::iter(destination), coeffCount, [&](auto& I) {
                const i64 noise = static_cast<i64>(dist(engine));
                const u64 flag = static_cast<u64>(-static_cast<i64>(noise < 0));
                SEAL_ITERATE(
                    seal::util::iter(seal::util::StrideIter<u64*>(&I, coeffCount), coeffModulus),
                    coeffModulusSize,
                    [&](auto J) {
                        auto& value = *::std::get<0>(J);
                        const auto& modulus = ::std::get<1>(J);
                        const u64 addend = static_cast<u64>(noise) + (flag & modulus.value());
                        if constexpr (Add)
                            value = seal::util::add_uint_mod(value, addend, modulus);
                        else
                            value = addend;
                    });
            });
        }

        seal::prng_seed_type sealSeedFromPrng(PRNG& prng)
        {
            seal::prng_seed_type seed{};
            prng.get(seed.data(), seed.size());
            return seed;
        }

        seal::prng_seed_type sealSeedFromBlock(block seedBlock)
        {
            // The first four cryptoTools counter blocks are exactly the old
            // PRNG(seedBlock) expansion, without allocating a PRNG buffer.
            alignas(16) std::array<block, 4> blocks;
            AES(seedBlock).ecbEncCounterMode(0, blocks.size(), blocks.data());
            seal::prng_seed_type seed;
            std::memcpy(seed.data(), blocks.data(), sizeof(seed));
            return seed;
        }

        template<typename T>
        void roUpdatePod(RandomOracle& ro, const T& value)
        {
            ro.Update(&value, 1);
        }

        block derivePublicSeedBlock(u64 domainTag, u64 value0, u64 value1, u64 value2, u64 value3)
        {
            block out{};
            RandomOracle ro(sizeof(out));
            constexpr u64 label = 0x4C4F47564F4C4552ull;
            roUpdatePod(ro, label);
            roUpdatePod(ro, domainTag);
            roUpdatePod(ro, value0);
            roUpdatePod(ro, value1);
            roUpdatePod(ro, value2);
            roUpdatePod(ro, value3);
            ro.Final(out);
            return out;
        }

        // Keep reset and flush in the public counters' established order.
        constexpr std::array ringOpCounters{
            &RingOpsStats::mNttCount,
            &RingOpsStats::mInttCount,
            &RingOpsStats::mAddCount,
            &RingOpsStats::mSubCount,
            &RingOpsStats::mMulCount,
            &RingOpsStats::mMulScalarCount,
            &RingOpsStats::mDyadicMulAddCount,
            &RingOpsStats::mGadgetDecomposeCount,
            &RingOpsStats::mGadgetRecomposeCount,
            &RingOpsStats::mPrngPolyCount,
            &RingOpsStats::mErrorAddCount
        };
        static_assert(ringOpCounters.size() == static_cast<std::size_t>(RingOp::Count));

        thread_local PendingRingOpsStats tlsRingOpsStats{&globalRingOpsStats};

        void bumpRingStat(RingOp operation, PendingRingOpsStats* stats)
        {
            if (stats) stats->bump(operation);
        }

        bool centeredDecomposeSlow(
            const RnsPoly& canonical,
            u32 digitBits,
            u32 startLevel,
            u32 levels,
            const RingNttContext& ctx,
            std::vector<RnsPoly>& out)
        {
            const auto& moduli = getRingHostModuli(ctx);
            if (moduli.empty() || moduli.size() != ringModulusCount(ctx)) return false;

            out.assign(levels, {});
            for (auto& digit : out)
            {
                resizeZero(digit.mCoeffs, canonical.mCoeffs.size());
            }

            const std::size_t n = ctx.mParams.mPolyModulusDegree;
            const std::size_t coeffModCount = moduli.size();
            // A balanced digit's magnitude has at most digitBits bits. Avoid
            // reducing the known-zero high words of the full CRT integer.
            const std::size_t digitWords = std::min<std::size_t>(
                coeffModCount, (static_cast<u64>(digitBits) + 63) / 64);
            const auto hostContext = getRingHostContext(ctx);
            auto contextData = hostContext ? hostContext->key_context_data() : nullptr;
            if (!contextData)
            {
                return false;
            }

            if (startLevel == 1 && levels == 1 && cpuCenteredHighDigit(ctx.mCpuCapabilities,
                canonical.mCoeffs.data(), out[0].mCoeffs.data(), n, digitBits,
                *contextData->rns_tool()->base_q())) return true;

            // All scratch dies on this thread before return. A private SEAL
            // pool avoids contention between independent shrink chunks.
            auto pool = seal::MemoryPoolHandle::ThreadLocal();
            seal::util::Pointer<u64> composedPoly =
                seal::util::allocate_poly(n, coeffModCount, pool);
            const auto& baseQ = *contextData->rns_tool()->base_q();
            if (!cpuComposeRns(ctx.mCpuCapabilities, canonical.mCoeffs.data(), composedPoly.get(), n, baseQ))
            {
                std::copy(canonical.mCoeffs.begin(), canonical.mCoeffs.end(), composedPoly.get());
                baseQ.compose_array(composedPoly.get(), n, pool);
            }

            const u64* q = contextData->rns_tool()->base_q()->base_prod();
            auto qHalf = seal::util::allocate_uint(coeffModCount, pool);
            seal::util::right_shift_uint(q, 1, coeffModCount, qHalf.get());
            auto value = seal::util::allocate_uint(coeffModCount, pool);
            auto digit = seal::util::allocate_uint(coeffModCount, pool);
            auto digitAbs = seal::util::allocate_uint(coeffModCount, pool);
            auto base = seal::util::allocate_uint(coeffModCount, pool);
            auto halfBase = seal::util::allocate_uint(coeffModCount, pool);

            setPowerOfTwo(base.get(), coeffModCount, digitBits);
            setPowerOfTwo(halfBase.get(), coeffModCount, digitBits - 1);

            for (std::size_t coeffIdx = 0; coeffIdx < n; ++coeffIdx)
            {
                seal::util::set_uint(composedPoly.get() + (coeffIdx * coeffModCount), coeffModCount, value.get());
                if (seal::util::is_greater_than_uint(value.get(), qHalf.get(), coeffModCount))
                {
                    seal::util::sub_uint(value.get(), q, coeffModCount, value.get());
                }

                for (u32 level = 0; level < (startLevel + levels); ++level)
                {
                    seal::util::set_uint(value.get(), coeffModCount, digit.get());
                    maskLowBits(digit.get(), coeffModCount, digitBits);
                    arithmeticRightShift(value.get(), digitBits, coeffModCount);

                    const bool digitIsNegative =
                        seal::util::is_greater_than_or_equal_uint(digit.get(), halfBase.get(), coeffModCount);
                    if (digitIsNegative)
                    {
                        seal::util::sub_uint(base.get(), digit.get(), coeffModCount, digitAbs.get());
                        seal::util::add_uint(value.get(), coeffModCount, u64(1), value.get());
                    }
                    else
                    {
                        seal::util::set_uint(digit.get(), coeffModCount, digitAbs.get());
                    }

                    if (level < startLevel)
                    {
                        continue;
                    }

                    const std::size_t outLevel = level - startLevel;
                    for (std::size_t modIdx = 0; modIdx < coeffModCount; ++modIdx)
                    {
                        const u64 reduced =
                            seal::util::modulo_uint(digitAbs.get(), digitWords, moduli[modIdx]);
                        out[outLevel].mCoeffs[modIdx * n + coeffIdx] =
                            (digitIsNegative && reduced != 0) ? (moduli[modIdx].value() - reduced) : reduced;
                    }
                }
            }

            return true;
        }
    }

    void RingOpsStats::reset()
    {
        for (auto counter : ringOpCounters)
            (this->*counter).store(0, std::memory_order_relaxed);
        mResetEpoch.fetch_add(1, std::memory_order_relaxed);
    }

    PendingRingOpsStats::PendingRingOpsStats(RingOpsStats* sink) noexcept
        : mSink(sink), mEpoch(sink ? sink->mResetEpoch.load(std::memory_order_relaxed) : 0) {}

    void PendingRingOpsStats::syncEpoch() noexcept
    {
        const auto epoch = mSink->mResetEpoch.load(std::memory_order_relaxed);
        if (mEpoch != epoch) { mCounts.fill(0); mEpoch = epoch; }
    }

    void PendingRingOpsStats::bump(RingOp operation) noexcept
    {
        if (!mSink) return;
        syncEpoch();
        const auto index = static_cast<std::size_t>(operation);
        auto& count = mCounts[index];
        if (++count >= 256)
        {
            (mSink->*ringOpCounters[index]).fetch_add(count, std::memory_order_relaxed);
            count = 0;
        }
    }

    void PendingRingOpsStats::flush() noexcept
    {
        if (!mSink) return;
        syncEpoch();
        for (std::size_t i = 0; i != mCounts.size(); ++i)
        {
            if (mCounts[i]) (mSink->*ringOpCounters[i]).fetch_add(mCounts[i], std::memory_order_relaxed);
            mCounts[i] = 0;
        }
    }

    PendingRingOpsStats::~PendingRingOpsStats() noexcept { flush(); }
    PendingRingOpsStats* legacyRingOpsThreadLocalStats() noexcept { return &tlsRingOpsStats; }

    void flushRingOpsThreadLocalStats()
    {
        tlsRingOpsStats.flush();
    }

    void TimingStats::reset()
    {
        mSenderWaitUs.store(0, std::memory_order_relaxed);
        mReceiverWaitUs.store(0, std::memory_order_relaxed);
        mRootReceiverHostUs.store(0, std::memory_order_relaxed);
        mRootSenderHostUs.store(0, std::memory_order_relaxed);
        mRootSerializeUs.store(0, std::memory_order_relaxed);
        mSenderWaitTimeUs.store(0, std::memory_order_relaxed);
        mReceiverWaitTimeUs.store(0, std::memory_order_relaxed);
        mSenderAsyncWaitTimeUs.store(0, std::memory_order_relaxed);
        mReceiverAsyncWaitTimeUs.store(0, std::memory_order_relaxed);
        mSenderComputeTimeUs.store(0, std::memory_order_relaxed);
        mReceiverComputeTimeUs.store(0, std::memory_order_relaxed);
        mLencEncTimeUs.store(0, std::memory_order_relaxed);
        mLencDecTimeUs.store(0, std::memory_order_relaxed);
        mLheEncTimeUs.store(0, std::memory_order_relaxed);
        mLheDecTimeUs.store(0, std::memory_order_relaxed);
        mShrinkTimeUs.store(0, std::memory_order_relaxed);
        mExpandTimeUs.store(0, std::memory_order_relaxed);
        mPolySamplingTimeUs.store(0, std::memory_order_relaxed);
        mGoldSamplingTimeUs.store(0, std::memory_order_relaxed);
        mSeedSamplingTimeUs.store(0, std::memory_order_relaxed);
        mSeedAttemptTimeUs.store(0, std::memory_order_relaxed);
        mSeedAttemptCount.store(0, std::memory_order_relaxed);
        mGdecompUnbundleTimeUs.store(0, std::memory_order_relaxed);
        mDenoiseTbmTimeUs.store(0, std::memory_order_relaxed);
        mAggTimeUs.store(0, std::memory_order_relaxed);
        mWrapTimeUs.store(0, std::memory_order_relaxed);
        mUnwrapTimeUs.store(0, std::memory_order_relaxed);
        mGpuShrinkTimeUs.store(0, std::memory_order_relaxed);
        mGpuExpandTimeUs.store(0, std::memory_order_relaxed);
        mGpuSenderTimeUs.store(0, std::memory_order_relaxed);
        mGpuMiscTimeUs.store(0, std::memory_order_relaxed);
    }

    TimingStats* timingStats(const RingNttContext& ctx) noexcept
    {
        return gpu::enabled(ctx) ? &globalTimingStats : ctx.mExecutionOptions.mTimingStats;
    }

    AutoTimer::AutoTimer(std::atomic<u64>* stat)
        : mStat(stat),
          mStart(stat ? std::chrono::steady_clock::now() : std::chrono::steady_clock::time_point{})
    {}

    AutoTimer::AutoTimer(std::atomic<u64>& stat)
        : AutoTimer(&stat)
    {}

    AutoTimer::~AutoTimer()
    {
        if (!mStat) return;
        const auto end = std::chrono::steady_clock::now();
        mStat->fetch_add(
            static_cast<u64>(std::chrono::duration_cast<std::chrono::microseconds>(end - mStart).count()),
            std::memory_order_relaxed);
    }

    u64 combineSeedPublic(u64 value)
    {
        value += 0x9E3779B97F4A7C15ull;
        value = (value ^ (value >> 30)) * 0xBF58476D1CE4E5B9ull;
        value = (value ^ (value >> 27)) * 0x94D049BB133111EBull;
        return value ^ (value >> 31);
    }

    u64 deriveDeterministicSeedMaterial(u64 root, u64 domainTag, u64 value0, u64 value1, u64 value2, u64 value3)
    {
        u64 mixed = combineSeedPublic(root);
        mixed = combineSeedPublic(mixed ^ combineSeedPublic(domainTag));
        mixed = combineSeedPublic(mixed ^ combineSeedPublic(value0));
        mixed = combineSeedPublic(mixed ^ combineSeedPublic(value1));
        mixed = combineSeedPublic(mixed ^ combineSeedPublic(value2));
        mixed = combineSeedPublic(mixed ^ combineSeedPublic(value3));
        return mixed;
    }

    block hashSeedDigest(const RnsPoly& digest)
    {
        block out{};
        RandomOracle ro(sizeof(out));
        constexpr u64 label = 0x4C56444947455354ull;   // "LVDIGEST"
        roUpdatePod(ro, label);
        const u64 coeffSize = static_cast<u64>(digest.mCoeffs.size());
        roUpdatePod(ro, coeffSize);
        if (!digest.mCoeffs.empty())
        {
            ro.Update(digest.mCoeffs.data(), digest.mCoeffs.size());
        }
        ro.Final(out);
        return out;
    }

    block deriveSeedInstanceBlockFromDigestHash(
        std::span<const u8> seed,
        u64 sid,
        block digestHash,
        u64 instanceIdx,
        u64 fallbackNonce)
    {
        block out{};
        RandomOracle ro(sizeof(out));
        constexpr u64 label = 0x4C4F47564F4C4354ull;
        roUpdatePod(ro, label);
        roUpdatePod(ro, sid);
        roUpdatePod(ro, fallbackNonce);
        roUpdatePod(ro, instanceIdx);
        const u64 seedSize = static_cast<u64>(seed.size());
        roUpdatePod(ro, seedSize);
        roUpdatePod(ro, digestHash);
        if (!seed.empty())
        {
            ro.Update(seed.data(), seed.size());
        }
        ro.Final(out);
        return out;
    }

    void derivePublicCt2Seed(u64 sid, block digestHash, std::span<u8> out, OnlineMode mode)
    {
        // Ct2SeedMode::PublicSeed. The seed is a public function of material both
        // parties already hold at this point - the session id and the receiver's
        // root digest - so neither the seed nor any rejection counter has to be
        // sent, and the sender has nothing to grind. Domain separated from
        // deriveSeedInstanceBlockFromDigestHash so that a seed can never collide
        // with a per-instance derivation.
        if (out.empty())
        {
            return;
        }

        RandomOracle ro(out.size());
        const u64 label = mode == OnlineMode::NonInteractive
            ? 0x4C564E4943543253ull  // "LVNICT2S": independent of the root-response oracle
            : 0x4C564E4F474F4C44ull; // "LVNOGOLD"
        roUpdatePod(ro, label);
        roUpdatePod(ro, sid);
        roUpdatePod(ro, digestHash);
        ro.Final(out.data());
    }

    void derivePublicCt2Seed(u64 sid, const RnsPoly& digest, std::span<u8> out)
    {
        derivePublicCt2Seed(sid, hashSeedDigest(digest), out);
    }

    block deriveSeedInstanceBlock(
        std::span<const u8> seed,
        u64 sid,
        const RnsPoly& digest,
        u64 instanceIdx,
        u64 fallbackNonce)
    {
        // Two-stage: commit to the digest once, then bind the instance index to
        // that commitment. Hashing the digest inline made every instance cost a
        // full pass over a 256 KiB ring element even though the digest is the
        // same for every instance of a level, which was the single largest cost
        // of the online phase. Composition of random oracles, so the security
        // argument is unchanged; the derived values differ from the one-stage
        // version, and both parties derive them identically.
        return deriveSeedInstanceBlockFromDigestHash(
            seed, sid, hashSeedDigest(digest), instanceIdx, fallbackNonce);
    }

    bool validateRingParams(const RingParams& params)
    {
        if (!isPowerOfTwo(params.mPolyModulusDegree) || params.mPolyModulusDegree < 1024)
        {
            return false;
        }

        if (params.mCoeffModulusBits.empty())
        {
            return false;
        }

        if (params.mCoeffModulusBits.size() > static_cast<std::size_t>(std::numeric_limits<u32>::max()))
        {
            return false;
        }

        for (const int bits : params.mCoeffModulusBits)
        {
            if (bits < 2 || bits > 60)
            {
                return false;
            }
        }

        return true;
    }

    bool validateRingPolyShape(const RnsPoly& poly, const RingParams& params)
    {
        return poly.mCoeffs.size() == ringPolyCoeffCount(params);
    }

    bool validateRingBatchShape(const std::vector<RnsPoly>& polys, const RingParams& params)
    {
        return validateRingBatchShape(std::span<const RnsPoly>(polys.data(), polys.size()), params);
    }

    bool validateRingBatchShape(std::span<const RnsPoly> polys, const RingParams& params)
    {
        for (const auto& poly : polys)
        {
            if (!validateRingPolyShape(poly, params))
            {
                return false;
            }
        }
        return true;
    }

    namespace
    {
        std::span<const u64> productionRingModuli(const RingParams& params)
        {
            // Exact ordered SEAL 4.1.1 CoeffModulus::Create outputs.
            // The native SEAL bundle tests check these against stock SEAL.
            static constexpr std::array<u64, 4> golden{
                36028797017276417ULL, 36028797017456641ULL,
                36028797017571329ULL, 36028797018652673ULL };
            static constexpr std::array<u64, 8> noGolden{
                4503599623864321ULL, 4503599624716289ULL,
                4503599624847361ULL, 4503599625404417ULL,
                4503599625535489ULL, 4503599625830401ULL,
                4503599626321921ULL, 4503599626682369ULL };
            if (params.mPolyModulusDegree == 8192 && params.mCoeffModulusBits.size() == golden.size() &&
                std::all_of(params.mCoeffModulusBits.begin(), params.mCoeffModulusBits.end(),
                    [](int bits) { return bits == 55; })) return golden;
            if (params.mPolyModulusDegree == 16384 && params.mCoeffModulusBits.size() == noGolden.size() &&
                std::all_of(params.mCoeffModulusBits.begin(), params.mCoeffModulusBits.end(),
                    [](int bits) { return bits == 52; })) return noGolden;
            return {};
        }

        bool validateLightweightRingContext(const RingNttContext& ctx)
        {
            if (!ctx.mGpuLightweight || ctx.mContext || !ctx.mHostContextCache ||
                !ctx.mModuli.empty() || !ctx.mRawModuli ||
                ctx.mHostContextCache->mRawModuli != ctx.mRawModuli ||
                ctx.mHostContextCache->mParams != ctx.mParams ||
                ctx.mHostContextCache->mRole != ctx.mResourceScope.mRole) return false;
            if (ctx.mRawModuli->mValues.size() != ctx.mParams.mCoeffModulusBits.size() ||
                ctx.mRawModuli->mBitCounts.size() != ctx.mParams.mCoeffModulusBits.size()) return false;
            const auto primes = productionRingModuli(ctx.mParams);
            if (!primes.empty())
            {
                if (primes.size() != ctx.mRawModuli->mValues.size()) return false;
                for (std::size_t i = 0; i < primes.size(); ++i)
                    if (ctx.mRawModuli->mValues[i] != primes[i] ||
                        ctx.mRawModuli->mBitCounts[i] != ctx.mParams.mCoeffModulusBits[i]) return false;
            }
            else
            {
#if defined(ENABLE_LOGVOLE_CUDA)
                if (!ctx.mRawModuli->mDynamicGpuCertificate) return false;
                for (std::size_t i = 0; i < ctx.mRawModuli->mValues.size(); ++i)
                    if (ctx.mRawModuli->mBitCounts[i] != ctx.mParams.mCoeffModulusBits[i]) return false;
#else
                return false;
#endif
            }
#if defined(ENABLE_LOGVOLE_CUDA)
            if (const auto& certificate = ctx.mRawModuli->mDynamicGpuCertificate)
            {
                if (!gpu::dynamicSealSetupSupported(ctx.mParams) ||
                    certificate->rawOwnerRole() != ctx.mHostContextCache->mRole ||
                    (certificate->nativeSealBundleOwner() && !ctx.mResourceScope.mNativeGpuTables) ||
                    certificate->n() != ctx.mParams.mPolyModulusDegree ||
                    certificate->rho() != ctx.mRawModuli->mValues.size() ||
                    certificate->hostModuli() != ctx.mRawModuli->mValues)
                    return false;
            }
#else
            if (ctx.mRawModuli->mDynamicGpuCertificate) return false;
#endif
            return true;
        }

        // Building a seal::SEALContext computes the NTT tables and RNS bases for
        // every limb, which costs milliseconds. The protocol asks for a context
        // per chunk in the online path, so the results are memoised. A
        // RingNttContext is immutable once built. The role is still part of the
        // key so co-located parties never alias its backing allocations.
        struct RingContextCacheKey
        {
            u32 mDegree = 0;
            std::vector<int> mBits;
            bool mExpandModChain = true;
            bool mGpuLightweight = false;
            bool mNativeSealBundleRequested = false;
            ProtocolCacheRole mRole = ProtocolCacheRole::Unspecified;

            bool operator==(const RingContextCacheKey& other) const
            {
                return mDegree == other.mDegree && mBits == other.mBits &&
                    mExpandModChain == other.mExpandModChain &&
                    mGpuLightweight == other.mGpuLightweight &&
                    mNativeSealBundleRequested == other.mNativeSealBundleRequested &&
                    mRole == other.mRole;
            }
        };

        struct RingContextCacheKeyHash
        {
            std::size_t operator()(const RingContextCacheKey& key) const
            {
                std::size_t h = std::hash<u32>{}(key.mDegree);
                for (int bits : key.mBits)
                {
                    h ^= std::hash<int>{}(bits) + 0x9e3779b9u + (h << 6) + (h >> 2);
                }
                h ^= std::hash<bool>{}(key.mExpandModChain) + 0x9e3779b9u + (h << 6) + (h >> 2);
                h ^= std::hash<bool>{}(key.mGpuLightweight) + 0x9e3779b9u + (h << 6) + (h >> 2);
                h ^= std::hash<bool>{}(key.mNativeSealBundleRequested) +
                    0x9e3779b9u + (h << 6) + (h >> 2);
                h ^= std::hash<u8>{}(static_cast<u8>(key.mRole)) + 0x9e3779b9u + (h << 6) + (h >> 2);
                return h;
            }
        };

        using RingContextCache = std::
            unordered_map<RingContextCacheKey, std::weak_ptr<const RingNttContext>, RingContextCacheKeyHash>;

        bool makeRingNttContextUncached(const RingParams& params, bool expandModChain, RingNttContext& out, HostStepProfiler* profile);
    }

    struct RingContextFactory::Impl
    {
        RingContextCache mCache;
        std::mutex mMutex;
        std::unique_ptr<RootStepProfiler> mRootProfiler;
        std::shared_ptr<HostStepProfiler> mHostProfiler;
    };

    RingContextFactory::RingContextFactory(LogVoleExecutionOptions options,
        std::shared_ptr<const ProtocolCacheService> service)
        : mProtocolService(service ? std::move(service) : ProtocolCacheService::create()),
          mImpl(std::make_unique<Impl>()), mExecutionOptions(options),
#if defined(ENABLE_LOGVOLE_CUDA)
          mGpuAvailable(options.mUseGpu && gpu::available())
#else
          mGpuAvailable(false)
#endif
    {
        if (!mExecutionOptions.valid()) throw std::invalid_argument("Invalid LogVole advanced options");
        if (mExecutionOptions.mAdvanced.mHostStepProfile)
            mImpl->mHostProfiler = std::make_shared<HostStepProfiler>();
        if (mExecutionOptions.mAdvanced.mProtocol.mRootProfile)
            mImpl->mRootProfiler = std::make_unique<RootStepProfiler>();
    }
    RootStepProfiler* RingContextFactory::rootProfiler() const noexcept
    {
        return mImpl->mRootProfiler.get();
    }
    HostStepProfiler* RingContextFactory::hostProfiler() const noexcept
    {
        return mImpl->mHostProfiler.get();
    }
    const std::shared_ptr<HostStepProfiler>& RingContextFactory::hostProfilerOwner() const noexcept
    {
        return mImpl->mHostProfiler;
    }
    RingContextFactory::~RingContextFactory() = default;

    bool RingContextFactory::make(const RingParams& params, RingNttContext& out,
        bool lightweight, const std::shared_ptr<RingContextFactory>& owner, ProtocolCacheScopeView scope)
    {
        const auto operationId = scope.mRunId;
        if (operationId.mService && operationId.mService != mProtocolService.get()) return false;

        if (!validateRingParams(params))
        {
            return false;
        }

        RingContextCacheKey key{};
        key.mDegree = params.mPolyModulusDegree;
        key.mBits.assign(params.mCoeffModulusBits.begin(), params.mCoeffModulusBits.end());
        key.mRole = scope.mRole;
        key.mGpuLightweight = lightweight;
#if defined(ENABLE_LOGVOLE_CUDA)
        key.mExpandModChain = !gpuEnabled() || mExecutionOptions.mAdvanced.mContexts.mFullModChain;
        key.mNativeSealBundleRequested = lightweight && !key.mExpandModChain &&
            gpu::dynamicSealSetupSupported(params) &&
            gpu::nativeSealBundleCacheRequested(key.mRole, mExecutionOptions, gpuEnabled());
#endif

        {
            std::lock_guard<std::mutex> lock(mImpl->mMutex);
            auto it = mImpl->mCache.find(key);
            if (it != mImpl->mCache.end())
            {
                if (auto record = it->second.lock())
                {
                    out = *record;
                    out.mFactoryOwner = std::move(record);
                    return true;
                }
                mImpl->mCache.erase(it);
            }
        }

        RingResourceScope resources{key.mRole, key.mNativeSealBundleRequested};
#if defined(ENABLE_LOGVOLE_CUDA)
        resources.mTables = std::make_shared<gpu::GpuTableCache>(mExecutionOptions, hostProfilerOwner(), mGpuAvailable);
#endif
        RingNttContext built{};
        if (lightweight)
        {
            HostStep contextStep(hostProfiler(), "setup: lightweight ring context");
            const auto primes = productionRingModuli(params);
            built.mParams = params;
#if defined(ENABLE_LOGVOLE_CUDA)
            built.mGpuSetup = std::make_shared<gpu::GpuSetupContext>(mExecutionOptions, hostProfilerOwner(), mProtocolService, mGpuAvailable);
#endif
            auto metadata = std::make_shared<RingModulusMetadata>();
            if (!primes.empty()) metadata->mValues.assign(primes.begin(), primes.end());
            else
            {
#if defined(ENABLE_LOGVOLE_CUDA)
                if (!gpu::selectSealCoeffModuliDevice(params, metadata->mValues, built.mGpuSetup, {})) return false;
                metadata->mDynamicGpuCertificate =
                    gpu::GpuRing::getRaw(params, metadata->mValues,
                        resources, built.mGpuSetup, {});
                if (!metadata->mDynamicGpuCertificate) return false;
                built.mGpuSetup = metadata->mDynamicGpuCertificate->setupContext();
#else
                return false;
#endif
            }
            metadata->mBitCounts.assign(params.mCoeffModulusBits.begin(), params.mCoeffModulusBits.end());
            built.mRawModuli = std::move(metadata);
            built.mGpuLightweight = true;
            built.mHostContextCache = std::make_shared<RingHostContextCache>();
            built.mHostContextCache->mParams = params;
            built.mHostContextCache->mRawModuli = built.mRawModuli;
            built.mHostContextCache->mRole = key.mRole;
            built.mHostContextCache->mExpandModChain = key.mExpandModChain;
        }
        else if (!makeRingNttContextUncached(params, key.mExpandModChain, built, hostProfiler()))
        {
            return false;
        }

        built.mExecutionOptions = mExecutionOptions;
        built.mGpuAvailable = mGpuAvailable;
        built.mHostProfiler = hostProfilerOwner();
        built.mCpuCapabilities = CpuCapabilities{};
        built.mFactory = owner;
        built.mResourceScope = std::move(resources);
        built.mPublicCache = std::make_shared<PublicPolynomialCache>();
#if defined(ENABLE_LOGVOLE_CUDA)
        if (!built.mGpuSetup) built.mGpuSetup = std::make_shared<gpu::GpuSetupContext>(mExecutionOptions, hostProfilerOwner(), mProtocolService, mGpuAvailable);
        built.mGpuExecution = std::make_shared<gpu::GpuExecutionContext>(mExecutionOptions, hostProfilerOwner(), mProtocolService, mGpuAvailable);
#endif
        auto shared = std::make_shared<const RingNttContext>(built);
        {
            std::lock_guard<std::mutex> lock(mImpl->mMutex);
            std::erase_if(mImpl->mCache, [](const auto& entry) { return entry.second.expired(); });
            auto& slot = mImpl->mCache[key];
            if (auto existing = slot.lock()) shared = std::move(existing);
            else slot = shared;
            out = *shared;
            out.mFactoryOwner = std::move(shared);
        }
        return true;
    }

    bool makeRingNttContext(const RingParams& params, RingNttContext& out,
        std::shared_ptr<RingContextFactory> factory, ProtocolCacheScopeView scope)
    {
        if (!factory) factory = out.mFactory;
        if (!factory) factory = std::make_shared<RingContextFactory>(osuCrypto::LogVoleExecutionOptions{}, scope.mRunId.serviceOwner());
        bool lightweight = false;
#if defined(ENABLE_LOGVOLE_CUDA)
        const auto& options = factory->executionOptions().mAdvanced.mContexts;
        lightweight = factory->gpuEnabled() && options.mLightweightRing &&
            !options.mFullModChain &&
            (!productionRingModuli(params).empty() ||
                (gpu::dynamicSealSetupSupported(params) && gpu::currentDeviceOrdinal() == 0));
#endif

        return factory->make(params, out, lightweight, factory, scope);
    }

    bool makeRingNttContext(const RingParams& params, RingNttContext& out,
        const std::shared_ptr<const RingNttContext>& retained, ProtocolCacheScopeView scope)
    {
        if (retained && retained->mParams == params)
        {
            // retained may refer to out.mFactoryOwner itself.
            auto owner = retained;
            RingNttContext selected = *owner;
#if defined(ENABLE_LOGVOLE_CUDA)
            if (!gpu::enabled(selected) && selected.mGpuLightweight)
#else
            if (selected.mGpuLightweight)
#endif
            {
                selected.mContext = getRingHostContext(selected);
                if (!selected.mContext || !selected.mContext->key_context_data()) return false;
                selected.mModuli = selected.mContext->key_context_data()->parms().coeff_modulus();
                selected.mGpuLightweight = false;
                selected.mRawModuli.reset();
            }
            selected.mFactoryOwner = std::move(owner);
            out = std::move(selected);
            return true;
        }
        return makeRingNttContext(params, out,
            retained ? retained->mFactory : std::shared_ptr<RingContextFactory>{}, scope);
    }

    bool makeGpuRingNttContext(const RingParams& params, RingNttContext& out, ProtocolCacheScopeView scope)
    {
        LogVoleExecutionOptions options;
        options.mUseGpu = true;
        auto factory = out.mFactory ? out.mFactory : std::make_shared<RingContextFactory>(options, scope.mRunId.serviceOwner());
        if (productionRingModuli(params).empty())
        {
#if defined(ENABLE_LOGVOLE_CUDA)
            if (!factory->gpuEnabled() || gpu::currentDeviceOrdinal() != 0 ||
                !gpu::dynamicSealSetupSupported(params)) return false;
#else
            return false;
#endif
        }
        return factory->make(params, out, true, factory, scope);
    }

    bool makeNativeGpuRingNttContextFromCertificate(
        const RingParams& params, std::span<const u64> orderedPrimes,
        std::shared_ptr<gpu::GpuRing> certificate, RingNttContext& out, ProtocolCacheScopeView scope)
    {
#if defined(ENABLE_LOGVOLE_CUDA)
        if (!validateRingParams(params) ||
            !gpu::dynamicSealSetupSupported(params) ||
            !certificate ||
            certificate->rawOwnerRole() != scope.mRole ||
            certificate->n() != params.mPolyModulusDegree ||
            certificate->rho() != orderedPrimes.size() ||
            certificate->hostModuli().size() != orderedPrimes.size() ||
            !std::equal(orderedPrimes.begin(), orderedPrimes.end(),
                certificate->hostModuli().begin()))
            return false;
        RingNttContext built{};
        built.mParams = params;
        built.mCpuCapabilities = CpuCapabilities{};
        built.mPublicCache = std::make_shared<PublicPolynomialCache>();
        auto metadata = std::make_shared<RingModulusMetadata>();
        metadata->mValues.assign(orderedPrimes.begin(), orderedPrimes.end());
        metadata->mBitCounts.assign(params.mCoeffModulusBits.begin(),
            params.mCoeffModulusBits.end());
        built.mGpuSetup = certificate->setupContext();
        built.mExecutionOptions = built.mGpuSetup->executionOptions();
        built.mGpuAvailable = built.mGpuSetup->gpuAvailable();
        built.mHostProfiler = built.mGpuSetup->hostProfilerOwner();
        built.mGpuExecution = std::make_shared<gpu::GpuExecutionContext>(built.mExecutionOptions, built.mHostProfiler, built.mFactory ? built.mFactory->protocolService() : certificate->setupContext()->protocolService(), built.mGpuAvailable);
        built.mResourceScope = {certificate->rawOwnerRole(), certificate->nativeSealBundleOwner(),
            std::make_shared<gpu::GpuTableCache>(built.mExecutionOptions, built.mHostProfiler, built.mGpuAvailable)};
        metadata->mDynamicGpuCertificate = std::move(certificate);
        built.mRawModuli = std::move(metadata);
        built.mGpuLightweight = true;
        built.mHostContextCache = std::make_shared<RingHostContextCache>();
        built.mHostContextCache->mParams = params;
        built.mHostContextCache->mRawModuli = built.mRawModuli;
        built.mHostContextCache->mRole = built.mResourceScope.mRole;
        built.mHostContextCache->mExpandModChain = false;
        if (!validateRingContextMetadata(built)) return false;
        out = std::move(built);
        return true;
#else
        (void)params;
        (void)orderedPrimes;
        (void)certificate;
        (void)out;
        return false;
#endif
    }

    bool publishNativeGpuRingNttContext(RingNttContext& ready)
    {
        auto factory = ready.mFactory;
        return factory && factory->publish(ready);
    }

    bool RingContextFactory::publish(RingNttContext& ready)
    {
#if defined(ENABLE_LOGVOLE_CUDA)
        HostStep publicationStep(hostProfiler(), "setup: native ring context publication");
        const auto owner = ready.mResourceScope;
        if (ready.mExecutionOptions != mExecutionOptions ||
            !gpu::nativeSealBundleCacheRequested(owner.mRole, mExecutionOptions, gpuEnabled()) ||
            !ready.mGpuLightweight || !ready.mRawModuli ||
            !ready.mRawModuli->mDynamicGpuCertificate ||
            !ready.mRawModuli->mDynamicGpuCertificate->nativeSealBundleOwner() ||
            ready.mRawModuli->mDynamicGpuCertificate->rawOwnerRole() != owner.mRole ||
            !validateRingContextMetadata(ready)) return false;
        try
        {
            RingContextCacheKey key{};
            key.mDegree = ready.mParams.mPolyModulusDegree;
            key.mBits.assign(ready.mParams.mCoeffModulusBits.begin(),
                ready.mParams.mCoeffModulusBits.end());
            key.mRole = owner.mRole;
            key.mGpuLightweight = true;
            key.mExpandModChain = false;
            key.mNativeSealBundleRequested = true;
            RingNttContext record = ready;
            record.mFactoryOwner.reset();
            auto shared = std::make_shared<const RingNttContext>(std::move(record));
            ready.mFactoryOwner = shared;
            std::lock_guard<std::mutex> lock(mImpl->mMutex);
            std::erase_if(mImpl->mCache, [](const auto& entry) { return entry.second.expired(); });
            if (auto it = mImpl->mCache.find(key);
                it != mImpl->mCache.end())
            {
                // The static lightweight context can have been cached by a
                // standalone budget check before the combined GPU factory.
                // Prior users retain that immutable context through shared_ptr.
                it->second = std::move(shared);
                return true;
            }
            mImpl->mCache.emplace(std::move(key), std::move(shared));
            return true;
        }
        catch (...) { return false; }
#else
        (void)ready;
        return false;
#endif
    }

    std::size_t ringModulusCount(const RingNttContext& ctx)
    {
        return ctx.mGpuLightweight ? (ctx.mRawModuli ? ctx.mRawModuli->mValues.size() : 0u)
                                   : ctx.mModuli.size();
    }

    u64 ringModulusValue(const RingNttContext& ctx, std::size_t limb)
    {
        if (ctx.mGpuLightweight)
            return ctx.mRawModuli && limb < ctx.mRawModuli->mValues.size()
                ? ctx.mRawModuli->mValues[limb] : 0u;
        return limb < ctx.mModuli.size() ? ctx.mModuli[limb].value() : 0u;
    }

    int ringModulusBitCount(const RingNttContext& ctx, std::size_t limb)
    {
        if (ctx.mGpuLightweight)
            return ctx.mRawModuli && limb < ctx.mRawModuli->mBitCounts.size()
                ? ctx.mRawModuli->mBitCounts[limb] : 0;
        return limb < ctx.mModuli.size() ? ctx.mModuli[limb].bit_count() : 0;
    }

    bool validateRingContextMetadata(const RingNttContext& ctx)
    {
        if (ctx.mGpuLightweight) return validateLightweightRingContext(ctx);
        if (ctx.mRawModuli || ctx.mModuli.size() != ctx.mParams.mCoeffModulusBits.size()) return false;
        for (std::size_t j = 0; j < ctx.mModuli.size(); ++j)
            if (ctx.mModuli[j].bit_count() != ctx.mParams.mCoeffModulusBits[j]) return false;
        return true;
    }

    std::shared_ptr<seal::SEALContext> getRingHostContext(const RingNttContext& ctx)
    {
        if (!ctx.mGpuLightweight) return ctx.mContext;
        if (!validateLightweightRingContext(ctx)) return nullptr;
        const auto& cache = *ctx.mHostContextCache;
        try
        {
            std::call_once(ctx.mHostContextCache->mOnce, [&] {
                HostStep fallbackStep(hostProfiler(ctx), "setup: ring host fallback materialization");
                std::vector<seal::Modulus> moduli;
                moduli.reserve(cache.mRawModuli->mValues.size());
                for (u64 prime : cache.mRawModuli->mValues) moduli.emplace_back(prime);
                seal::EncryptionParameters parms(seal::scheme_type::ckks);
                parms.set_poly_modulus_degree(cache.mParams.mPolyModulusDegree);
                parms.set_coeff_modulus(moduli);
                parms.set_random_generator(detail::makeAesPrngFactory());
                auto host = std::make_shared<seal::SEALContext>(
                    parms, cache.mExpandModChain, seal::sec_level_type::none);
                if (!host->key_context_data() ||
                    host->key_context_data()->parms().coeff_modulus() != moduli)
                    throw std::runtime_error("lightweight ring host fallback parameters changed");
                ctx.mHostContextCache->mContext = std::move(host);
            });
        }
        catch (const std::exception&)
        {
            return nullptr;
        }
        return cache.mContext;
    }

    std::span<const seal::Modulus> getRingHostModuli(const RingNttContext& ctx)
    {
        if (!ctx.mGpuLightweight) return ctx.mModuli;
        const auto host = getRingHostContext(ctx);
        if (host && host->key_context_data()) return host->key_context_data()->parms().coeff_modulus();
        return {};
    }

    namespace
    {
    bool makeRingNttContextUncached(const RingParams& params, bool expandModChain, RingNttContext& out, HostStepProfiler* profile)
    {
        HostStep contextStep(profile, "setup: ring context build");
        if (!validateRingParams(params))
        {
            return false;
        }

        std::vector<seal::Modulus> moduli;
        try
        {
            HostStep primesStep(profile, "setup: ring modulus generation");
            std::vector<int> coeffModulusBits(
                params.mCoeffModulusBits.begin(),
                params.mCoeffModulusBits.end());
            moduli = seal::CoeffModulus::Create(params.mPolyModulusDegree, coeffModulusBits);
        }
        catch (const std::exception&)
        {
            return false;
        }

        if (moduli.size() != params.mCoeffModulusBits.size())
        {
            return false;
        }

        seal::EncryptionParameters parms(seal::scheme_type::ckks);
        parms.set_poly_modulus_degree(params.mPolyModulusDegree);
        parms.set_coeff_modulus(moduli);
        parms.set_random_generator(detail::makeAesPrngFactory());

        RingNttContext next{};
        next.mParams = params;
        next.mModuli = std::move(moduli);
        {
            HostStep sealStep(profile, "setup: ring SEAL context");
            // LogVole consumes the key-level NTT/RNS tables and never modulus
            // switches. SEAL still constructs its original key and first data
            // contexts when expansion is disabled; only unused lower levels
            // are omitted. Their arithmetic parameters remain identical.
            next.mContext = std::make_shared<seal::SEALContext>(parms, expandModChain, seal::sec_level_type::none);
        }
        if (!next.mContext || !next.mContext->key_context_data())
        {
            return false;
        }

        if (next.mContext->key_context_data()->parms().coeff_modulus().size() != params.mCoeffModulusBits.size())
        {
            return false;
        }

        out = std::move(next);
        return true;
    }
    }

    bool canonicalizePoly(RnsPoly& poly, const RingNttContext& ctx)
    {
        const auto& moduli = getRingHostModuli(ctx);
        if (moduli.empty() || moduli.size() != ringModulusCount(ctx)) return false;

        if (!validateShapeAgainstContext(poly, ctx))
        {
            return false;
        }

        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        for (std::size_t j = 0; j < moduli.size(); ++j)
        {
            auto* coeffs = poly.mCoeffs.data() + j * n;
            if (!cpuReduceMod(ctx.mCpuCapabilities, coeffs, coeffs, n, moduli[j]))
                seal::util::modulo_poly_coeffs(coeffs, n, moduli[j], coeffs);
        }
        return true;
    }

    static bool forwardNttImpl(RnsPoly& poly, const RingNttContext& ctx, bool reduceInput, PendingRingOpsStats* stats)
    {
        const auto hostContext = getRingHostContext(ctx);
        if (!hostContext || !hostContext->key_context_data() ||
            !(reduceInput ? canonicalizePoly(poly, ctx) : validateShapeAgainstContext(poly, ctx)))
        {
            return false;
        }

        // Measured and rejected: routing this through gpu::nttHostBatch one
        // polynomial at a time cost 44.0 -> 39.0 M/s. A single-polynomial round
        // trip ends in a stream synchronise, which drains *everything* queued on
        // that stream, so a small Root-level transform ends up waiting on a large
        // pending expand. Batching the Root level and keeping it device resident
        // would work; per-call offload does not.
        const auto& tables = hostContext->key_context_data()->small_ntt_tables();
        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        for (std::size_t modIdx = 0; modIdx < ringModulusCount(ctx); ++modIdx)
        {
            seal::util::ntt_negacyclic_harvey(poly.mCoeffs.data() + (modIdx * n), tables[modIdx]);
        }

        bumpRingStat(RingOp::Ntt, stats);
        return true;
    }

    bool forwardNtt(RnsPoly& poly, const RingNttContext& ctx, PendingRingOpsStats* stats)
    {
        return forwardNttImpl(poly, ctx, true, stats);
    }

    bool forwardNttCanonical(RnsPoly& poly, const RingNttContext& ctx, PendingRingOpsStats* stats)
    {
        return forwardNttImpl(poly, ctx, false, stats);
    }

    bool inverseNtt(RnsPoly& poly, const RingNttContext& ctx, PendingRingOpsStats* stats)
    {
        const auto hostContext = getRingHostContext(ctx);
        if (!validateShapeAgainstContext(poly, ctx) || !hostContext || !hostContext->key_context_data())
        {
            return false;
        }

        // See forwardNtt: per-call GPU offload of the Root level is a net loss.
        const auto& tables = hostContext->key_context_data()->small_ntt_tables();
        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        for (std::size_t modIdx = 0; modIdx < ringModulusCount(ctx); ++modIdx)
        {
            seal::util::inverse_ntt_negacyclic_harvey(poly.mCoeffs.data() + (modIdx * n), tables[modIdx]);
        }

        bumpRingStat(RingOp::Intt, stats);
        // SEAL's non-lazy inverse already returns coefficients in [0, q).
        return true;
    }

    // Batched transforms. A GPU round trip has to synchronise to hand the result
    // back, and a synchronise drains the stream, so the fixed cost has to be
    // amortised over several polynomials to pay. Above the crossover these run on
    // the device; below it, and without CUDA, they are just the per-polynomial
    // loop. Results are bit-identical either way.
    namespace
    {
        // One 4-limb polynomial is 256 KiB. Below a handful of them the drain
        // dominates; the Root level works on mu = 8 at a time.
        // Measured at 1, 2, 4 and 8 with the drain removed: 159.4, 158.7, 159.4
        // and 152.0 M/s. Everything at or below 4 is the same, so the crossover is
        // not where the cost is - 8 is simply high enough to push work the device
        // should be doing back onto the CPU.
        constexpr std::size_t kNttBatchGpuThreshold = 4;
    }

    bool forwardNttBatch(std::span<RnsPoly> polys, const RingNttContext& ctx, PendingRingOpsStats* stats)
    {
        if (polys.empty()) return true;
        // Validate the complete batch before a transform or reduction changes
        // any input; a declined device attempt must remain safe to replay.
        if (ctx.mGpuLightweight ? !validateLightweightRingContext(ctx) :
            (!ctx.mContext || !ctx.mContext->key_context_data())) return false;
        for (const auto& poly : polys)
            if (!validateShapeAgainstContext(poly, ctx)) return false;
#if defined(ENABLE_LOGVOLE_CUDA)
        const bool deviceCanonicalize = (ctx.mGpuLightweight || polys.size() >= kNttBatchGpuThreshold) && gpu::enabled(ctx) &&
            ctx.mExecutionOptions.mAdvanced.mProtocol.mNttCanonicalize;
        if (deviceCanonicalize)
        {
            if (gpu::nttHostBatch(ctx, polys, false, true))
            {
                for (std::size_t i = 0; i < polys.size(); ++i)
                    bumpRingStat(RingOp::Ntt, stats);
                return true;
            }
            if (ctx.mExecutionOptions.mAdvanced.mProtocol.mNttCanonicalizeStrict) return false;
            // The helper left every host input unchanged. Replay the CPU
            // reduction and transform without making another device attempt.
        }
#endif
        for (auto& poly : polys)
        {
            if (!canonicalizePoly(poly, ctx)) return false;
        }
#if defined(ENABLE_LOGVOLE_CUDA)
        if (!deviceCanonicalize && (ctx.mGpuLightweight || polys.size() >= kNttBatchGpuThreshold) &&
            gpu::nttHostBatch(ctx, polys, false))
        {
            for (std::size_t i = 0; i < polys.size(); ++i)
            {
                bumpRingStat(RingOp::Ntt, stats);
            }
            return true;
        }
#endif
        for (auto& poly : polys)
        {
            if (!forwardNttCanonical(poly, ctx, stats)) return false;
        }
        return true;
    }

    bool inverseNttBatch(std::span<RnsPoly> polys, const RingNttContext& ctx, PendingRingOpsStats* stats)
    {
        if (polys.empty()) return true;
        if (ctx.mGpuLightweight ? !validateLightweightRingContext(ctx) :
            (!ctx.mContext || !ctx.mContext->key_context_data())) return false;
        for (const auto& poly : polys)
            if (!validateShapeAgainstContext(poly, ctx)) return false;
#if defined(ENABLE_LOGVOLE_CUDA)
        if (ctx.mGpuLightweight || polys.size() >= kNttBatchGpuThreshold)
        {
            const bool deviceCanonicalize = gpu::enabled(ctx) &&
                ctx.mExecutionOptions.mAdvanced.mProtocol.mNttCanonicalize;
            if (gpu::nttHostBatch(ctx, polys, true, deviceCanonicalize))
            {
                for (auto& poly : polys)
                {
                    bumpRingStat(RingOp::Intt, stats);
                    if (!deviceCanonicalize && !canonicalizePoly(poly, ctx)) return false;
                }
                return true;
            }
            if (deviceCanonicalize && ctx.mExecutionOptions.mAdvanced.mProtocol.mNttCanonicalizeStrict) return false;
        }
#endif
        for (auto& poly : polys)
        {
            if (!inverseNtt(poly, ctx, stats)) return false;
        }
        return true;
    }

    bool dyadicMultiplyAddNtt(
        const RnsPoly& aNtt,
        const RnsPoly& bNtt,
        const RnsPoly& cNtt,
        const RingNttContext& ctx,
        RnsPoly& out, PendingRingOpsStats* stats)
    {
        out = cNtt;
        return dyadicMultiplyAddNttInplace(aNtt, bNtt, out, ctx, stats);
    }

    bool dyadicMultiplyAddNttInplace(const RnsPoly& aNtt, const RnsPoly& bNtt, RnsPoly& cNtt, const RingNttContext& ctx, PendingRingOpsStats* stats)
    {
        const auto& moduli = getRingHostModuli(ctx);
        if (moduli.empty() || moduli.size() != ringModulusCount(ctx)) return false;

        if (!validateShapeAgainstContext(aNtt, ctx) ||
            !validateShapeAgainstContext(bNtt, ctx) ||
            !validateShapeAgainstContext(cNtt, ctx))
        {
            return false;
        }

        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        for (std::size_t modIdx = 0; modIdx < moduli.size(); ++modIdx)
        {
            const auto& modulus = moduli[modIdx];
            const std::size_t offset = modIdx * n;
            if (cpuDyadicMultiplyAdd(ctx.mCpuCapabilities, aNtt.mCoeffs.data() + offset,
                bNtt.mCoeffs.data() + offset, cNtt.mCoeffs.data() + offset, n, modulus))
                continue;
            // barrett_reduce_64 computes x mod q exactly for any 64-bit x, so
            // this is bit-identical to `x % mod` but avoids three hardware
            // 64-bit divisions per coefficient. Those divisions dominated the
            // online phase before this change.
            for (std::size_t i = 0; i < n; ++i)
            {
                const std::size_t idx = offset + i;
                cNtt.mCoeffs[idx] =
                    mulAddMod(
                        reduceU64(aNtt.mCoeffs[idx], modulus),
                        reduceU64(bNtt.mCoeffs[idx], modulus),
                        reduceU64(cNtt.mCoeffs[idx], modulus),
                        modulus);
            }
        }

        bumpRingStat(RingOp::DyadicMulAdd, stats);
        return true;
    }

    bool dyadicInnerProductNttInplace(
        std::span<const RnsPoly* const> left, std::span<const RnsPoly* const> right,
        RnsPoly& accumulator, const RingNttContext& ctx, PendingRingOpsStats* stats)
    {
        const auto& moduli = getRingHostModuli(ctx);
        if (moduli.empty() || moduli.size() != ringModulusCount(ctx)) return false;

        if (left.size() != right.size() || !validateShapeAgainstContext(accumulator, ctx)) return false;
        for (std::size_t t = 0; t < left.size(); ++t)
            if (!left[t] || !right[t] || left[t] == &accumulator || right[t] == &accumulator ||
                !validateShapeAgainstContext(*left[t], ctx) ||
                !validateShapeAgainstContext(*right[t], ctx)) return false;
        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        for (std::size_t j = 0; j < moduli.size(); ++j)
        for (std::size_t first = 0; first < left.size(); first += 32)
        {
            const auto terms = std::min<std::size_t>(32, left.size() - first);
            const auto& modulus = moduli[j];
            auto* c = accumulator.mCoeffs.data() + j * n;
            const u64* a[32];
            const u64* b[32];
            for (std::size_t t = 0; t < terms; ++t)
            {
                a[t] = left[first+t]->mCoeffs.data() + j * n;
                b[t] = right[first+t]->mCoeffs.data() + j * n;
            }
            if (cpuDyadicInnerProduct(ctx.mCpuCapabilities, a, b, terms, c, n, modulus)) continue;
            for (std::size_t t = 0; t < terms; ++t)
                if (!cpuDyadicMultiplyAdd(ctx.mCpuCapabilities, a[t], b[t], c, n, modulus))
                    for (std::size_t i = 0; i < n; ++i)
                        c[i] = mulAddMod(reduceU64(a[t][i], modulus), reduceU64(b[t][i], modulus),
                            reduceU64(c[i], modulus), modulus);
        }
        for (std::size_t t = 0; t < left.size(); ++t)
            bumpRingStat(RingOp::DyadicMulAdd, stats);
        return true;
    }

    bool ringAddInplace(RnsPoly& a, const RnsPoly& b, const RingNttContext& ctx, PendingRingOpsStats* stats)
    {
        const auto& moduli = getRingHostModuli(ctx);
        if (moduli.empty() || moduli.size() != ringModulusCount(ctx)) return false;

        if (!validateShapeAgainstContext(a, ctx) || !validateShapeAgainstContext(b, ctx))
        {
            return false;
        }

        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        seal::util::PolyIter aIter(a.mCoeffs.data(), n, moduli.size());
        seal::util::ConstPolyIter bIter(b.mCoeffs.data(), n, moduli.size());
        seal::util::add_poly_coeffmod(aIter[0], bIter[0], moduli.size(), moduli.data(), aIter[0]);
        bumpRingStat(RingOp::Add, stats);
        return true;
    }

    bool ringAdd(const RnsPoly& a, const RnsPoly& b, const RingNttContext& ctx, RnsPoly& out, PendingRingOpsStats* stats)
    {
        out = a;
        return ringAddInplace(out, b, ctx, stats);
    }

    bool ringSubInplace(RnsPoly& a, const RnsPoly& b, const RingNttContext& ctx, PendingRingOpsStats* stats)
    {
        const auto& moduli = getRingHostModuli(ctx);
        if (moduli.empty() || moduli.size() != ringModulusCount(ctx)) return false;

        if (!validateShapeAgainstContext(a, ctx) || !validateShapeAgainstContext(b, ctx))
        {
            return false;
        }

        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        seal::util::PolyIter aIter(a.mCoeffs.data(), n, moduli.size());
        seal::util::ConstPolyIter bIter(b.mCoeffs.data(), n, moduli.size());
        seal::util::sub_poly_coeffmod(aIter[0], bIter[0], moduli.size(), moduli.data(), aIter[0]);
        bumpRingStat(RingOp::Sub, stats);
        return true;
    }

    bool ringSub(const RnsPoly& a, const RnsPoly& b, const RingNttContext& ctx, RnsPoly& out, PendingRingOpsStats* stats)
    {
        out = a;
        return ringSubInplace(out, b, ctx, stats);
    }

    bool ringMultiplyInplace(RnsPoly& a, const RnsPoly& b, const RingNttContext& ctx, PendingRingOpsStats* stats)
    {
        if (!validateShapeAgainstContext(a, ctx) || !validateShapeAgainstContext(b, ctx))
        {
            return false;
        }

        RnsPoly aNtt = a;
        RnsPoly bNtt = b;
        RnsPoly zero{};
        resizeZero(zero.mCoeffs, a.mCoeffs.size());
        if (!forwardNtt(aNtt, ctx, stats) || !forwardNtt(bNtt, ctx, stats) ||
            !dyadicMultiplyAddNtt(aNtt, bNtt, zero, ctx, a, stats) ||
            !inverseNtt(a, ctx, stats))
        {
            return false;
        }

        bumpRingStat(RingOp::Mul, stats);
        return true;
    }

    bool ringMultiply(const RnsPoly& a, const RnsPoly& b, const RingNttContext& ctx, RnsPoly& out, PendingRingOpsStats* stats)
    {
        out = a;
        return ringMultiplyInplace(out, b, ctx, stats);
    }

    bool ringMultiplyScalarInplace(RnsPoly& a, u64 scalar, const RingNttContext& ctx, PendingRingOpsStats* stats)
    {
        const auto& moduli = getRingHostModuli(ctx);
        if (moduli.empty() || moduli.size() != ringModulusCount(ctx)) return false;

        if (!validateShapeAgainstContext(a, ctx))
        {
            return false;
        }

        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        for (std::size_t modIdx = 0; modIdx < moduli.size(); ++modIdx)
        {
            const auto& modulus = moduli[modIdx];
            const u64 mod = modulus.value();
            const u64 scalarMod = scalar % mod;
            const std::size_t offset = modIdx * n;
            for (std::size_t i = 0; i < n; ++i)
            {
                const std::size_t idx = offset + i;
                a.mCoeffs[idx] = mulMod(reduceU64(a.mCoeffs[idx], modulus), scalarMod, modulus);
            }
        }

        bumpRingStat(RingOp::MulScalar, stats);
        return true;
    }

    bool ringMultiplyScalar(const RnsPoly& a, u64 scalar, const RingNttContext& ctx, RnsPoly& out, PendingRingOpsStats* stats)
    {
        out = a;
        return ringMultiplyScalarInplace(out, scalar, ctx, stats);
    }

    bool gadgetDecompose(const RnsPoly& poly, u32 base, u32 tau, const RingNttContext& ctx, std::vector<RnsPoly>& out, PendingRingOpsStats* stats)
    {
        if (base < 2 || tau == 0 || !validateShapeAgainstContext(poly, ctx))
        {
            return false;
        }

        RnsPoly canonical = poly;
        if (!canonicalizePoly(canonical, ctx))
        {
            return false;
        }

        out.assign(tau, {});
        for (auto& digit : out)
        {
            resizeZero(digit.mCoeffs, canonical.mCoeffs.size());
        }

        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        const u64 baseU64 = base;
        for (std::size_t modIdx = 0; modIdx < ringModulusCount(ctx); ++modIdx)
        {
            const u64 mod = ringModulusValue(ctx, modIdx);
            const std::size_t offset = modIdx * n;
            for (std::size_t i = 0; i < n; ++i)
            {
                u64 value = canonical.mCoeffs[offset + i] % mod;
                for (u32 j = 0; j < tau; ++j)
                {
                    out[j].mCoeffs[offset + i] = value % baseU64;
                    value /= baseU64;
                }
            }
        }

        bumpRingStat(RingOp::GadgetDecompose, stats);
        return true;
    }

    bool gadgetRecompose(const std::vector<RnsPoly>& digits, u32 base, const RingNttContext& ctx, RnsPoly& out, PendingRingOpsStats* stats)
    {
        const auto& moduli = getRingHostModuli(ctx);
        if (moduli.empty() || moduli.size() != ringModulusCount(ctx)) return false;

        if (digits.empty() || base < 2)
        {
            return false;
        }

        for (const auto& digit : digits)
        {
            if (!validateShapeAgainstContext(digit, ctx))
            {
                return false;
            }
        }

        resizeZero(out.mCoeffs, digits[0].mCoeffs.size());
        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        for (std::size_t modIdx = 0; modIdx < moduli.size(); ++modIdx)
        {
            const u64 mod = moduli[modIdx].value();
            const std::size_t offset = modIdx * n;

            AlignedUnVec<u64> basePows;
            resizeFill<u64>(basePows, digits.size(), 1);
            for (std::size_t j = 0; j < digits.size(); ++j)
            {
                basePows[j] = basePowMod(base, static_cast<u32>(j), mod);
            }

            for (std::size_t i = 0; i < n; ++i)
            {
                u64 acc = 0;
                for (std::size_t j = 0; j < digits.size(); ++j)
                {
                    acc = mulAddMod(
                        reduceU64(digits[j].mCoeffs[offset + i], moduli[modIdx]),
                        basePows[j],
                        acc,
                        moduli[modIdx]);
                }
                out.mCoeffs[offset + i] = acc;
            }
        }

        bumpRingStat(RingOp::GadgetRecompose, stats);
        return true;
    }

    bool gadgetDecomposeBitsRange(
        const RnsPoly& poly,
        u32 digitBits,
        u32 startLevel,
        u32 levels,
        const RingNttContext& ctx,
        std::vector<RnsPoly>& out,
        u32, PendingRingOpsStats* stats)
    {
        const auto& moduli = getRingHostModuli(ctx);
        if (moduli.empty() || moduli.size() != ringModulusCount(ctx)) return false;

        if (digitBits == 0 || levels == 0 || !validateShapeAgainstContext(poly, ctx))
        {
            return false;
        }

        RnsPoly canonical = poly;
        if (!canonicalizePoly(canonical, ctx))
        {
            return false;
        }

        const auto hostContext = getRingHostContext(ctx);
        auto contextData = hostContext ? hostContext->key_context_data() : nullptr;
        if (!contextData)
        {
            return false;
        }

        const u64 startShift = static_cast<u64>(startLevel) * digitBits;
        const u64 endShift = static_cast<u64>(startLevel + levels - 1) * digitBits;
        if (startShift > std::numeric_limits<int>::max() || endShift > std::numeric_limits<int>::max())
        {
            return false;
        }

        out.assign(levels, {});
        for (auto& digit : out)
        {
            resizeZero(digit.mCoeffs, canonical.mCoeffs.size());
        }

        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        const std::size_t coeffModCount = moduli.size();
        const std::size_t digitWords = std::min<std::size_t>(
            coeffModCount, (static_cast<u64>(digitBits) + 63) / 64);
        const auto& baseQ = *contextData->rns_tool()->base_q();
        if (startLevel == 0 && levels == 1 && cpuLowDigitRns(ctx.mCpuCapabilities,
            canonical.mCoeffs.data(), out[0].mCoeffs.data(), n, digitBits, baseQ))
        {
            bumpRingStat(RingOp::GadgetDecompose, stats);
            return true;
        }
        auto pool = seal::MemoryPoolHandle::ThreadLocal();
        seal::util::Pointer<u64> composedPoly =
            seal::util::allocate_poly(n, coeffModCount, pool);
        if (!cpuComposeRns(ctx.mCpuCapabilities, canonical.mCoeffs.data(), composedPoly.get(), n, baseQ))
        {
            std::copy(canonical.mCoeffs.begin(), canonical.mCoeffs.end(), composedPoly.get());
            baseQ.compose_array(composedPoly.get(), n, pool);
        }

        auto tempMpi = seal::util::allocate_uint(coeffModCount, pool);
        for (std::size_t i = 0; i < n; ++i)
        {
            u64* valuePtr = composedPoly.get() + i * coeffModCount;
            if (startShift >= static_cast<u64>(coeffModCount) * 64)
                std::fill_n(valuePtr, coeffModCount, u64{0});
            else seal::util::right_shift_uint(valuePtr, static_cast<int>(startShift), coeffModCount, valuePtr);

            for (u32 level = 0; level < levels; ++level)
            {
                seal::util::set_uint(valuePtr, coeffModCount, tempMpi.get());

                for (std::size_t w = 0; w < coeffModCount; ++w)
                {
                    const u64 bitOffset = static_cast<u64>(w) * 64;
                    if (bitOffset >= digitBits)
                    {
                        tempMpi[w] = 0;
                    }
                    else if (bitOffset + 64 > digitBits)
                    {
                        const u32 remainingBits = digitBits - static_cast<u32>(bitOffset);
                        const u64 mask = remainingBits == 64 ? ~u64(0) : ((u64(1) << remainingBits) - 1);
                        tempMpi[w] &= mask;
                    }
                }

                for (std::size_t modIdx = 0; modIdx < coeffModCount; ++modIdx)
                {
                    out[level].mCoeffs[modIdx * n + i] =
                        seal::util::modulo_uint(tempMpi.get(), digitWords, moduli[modIdx]);
                }

                // No next digit needs the final shift. Larger shifts represent
                // zero; SEAL's shift primitive requires a smaller bit count.
                if (level + 1 < levels)
                {
                    if (digitBits >= static_cast<u64>(coeffModCount) * 64)
                        std::fill_n(valuePtr, coeffModCount, u64{0});
                    else seal::util::right_shift_uint(valuePtr, static_cast<int>(digitBits), coeffModCount, valuePtr);
                }
            }
        }

        bumpRingStat(RingOp::GadgetDecompose, stats);
        return true;
    }

    bool gadgetDecomposeBits(
        const RnsPoly& poly,
        u32 digitBits,
        u32 levels,
        const RingNttContext& ctx,
        std::vector<RnsPoly>& out,
        u32 requestedWorkers, PendingRingOpsStats* stats)
    {
        return gadgetDecomposeBitsRange(poly, digitBits, 0, levels, ctx, out, requestedWorkers, stats);
    }

    bool gadgetDecomposeBitsRangeCentered(
        const RnsPoly& poly,
        u32 digitBits,
        u32 startLevel,
        u32 levels,
        const RingNttContext& ctx,
        std::vector<RnsPoly>& out,
        u32, PendingRingOpsStats* stats)
    {
        if (digitBits == 0 || levels == 0 || !validateShapeAgainstContext(poly, ctx))
        {
            return false;
        }

        RnsPoly canonical = poly;
        if (!canonicalizePoly(canonical, ctx))
        {
            return false;
        }

#if defined(ENABLE_LOGVOLE_CUDA)
        // The Root level's single-polynomial decompositions are the largest host
        // cost left in it (6.1% of process cycles). Unlike a transform this is
        // worth a round trip on its own: centeredDecomposeSlow does a 256-bit CRT
        // compose per coefficient, so the work per byte moved is high.
        if (gpu::gadgetDecomposeHost(ctx, canonical, digitBits, startLevel, levels, true, out))
        {
            bumpRingStat(RingOp::GadgetDecompose, stats);
            return true;
        }
#endif
        const bool ok = centeredDecomposeSlow(canonical, digitBits, startLevel, levels, ctx, out);
        if (ok)
        {
            bumpRingStat(RingOp::GadgetDecompose, stats);
        }
        return ok;
    }

    bool gadgetRecomposeBits(const std::vector<RnsPoly>& digits, u32 digitBits, const RingNttContext& ctx, RnsPoly& out, PendingRingOpsStats* stats)
    {
        const auto& moduli = getRingHostModuli(ctx);
        if (moduli.empty() || moduli.size() != ringModulusCount(ctx)) return false;

        if (digits.empty() || digitBits == 0)
        {
            return false;
        }

        for (const auto& digit : digits)
        {
            if (!validateShapeAgainstContext(digit, ctx))
            {
                return false;
            }
        }

        resizeZero(out.mCoeffs, digits[0].mCoeffs.size());
        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        for (std::size_t modIdx = 0; modIdx < moduli.size(); ++modIdx)
        {
            const u64 mod = moduli[modIdx].value();
            const std::size_t offset = modIdx * n;

            AlignedUnVec<u64> pow2Shifts;
            resizeZero(pow2Shifts, digits.size());
            for (std::size_t level = 0; level < digits.size(); ++level)
            {
                const u64 shiftU64 = static_cast<u64>(level) * digitBits;
                if (shiftU64 > std::numeric_limits<u32>::max())
                {
                    return false;
                }
                pow2Shifts[level] = basePowMod(2, static_cast<u32>(shiftU64), mod);
            }

            for (std::size_t i = 0; i < n; ++i)
            {
                u64 acc = 0;
                for (std::size_t level = 0; level < digits.size(); ++level)
                {
                    acc = mulAddMod(
                        reduceU64(digits[level].mCoeffs[offset + i], moduli[modIdx]),
                        pow2Shifts[level],
                        acc,
                        moduli[modIdx]);
                }
                out.mCoeffs[offset + i] = acc;
            }
        }

        bumpRingStat(RingOp::GadgetRecompose, stats);
        return true;
    }

    AlignedUnVec<u64> packRingBatch(const std::vector<RnsPoly>& polys)
    {
        std::size_t total = 0;
        for (const auto& poly : polys)
        {
            total += poly.mCoeffs.size();
        }

        AlignedUnVec<u64> out(total);
        auto* outIter = out.data();
        for (const auto& poly : polys)
        {
            outIter = std::copy(poly.mCoeffs.begin(), poly.mCoeffs.end(), outIter);
        }
        return out;
    }

    bool unpackRingBatch(
        u32 count,
        u32 polyModulusDegree,
        u32 coeffModulusCount,
        std::span<const u64> flat,
        std::vector<RnsPoly>& out,
        u32)
    {
        if (polyModulusDegree == 0 || coeffModulusCount == 0)
        {
            return false;
        }

        const std::size_t perPoly = static_cast<std::size_t>(polyModulusDegree) * coeffModulusCount;
        if (perPoly == 0 || count > std::numeric_limits<std::size_t>::max() / perPoly)
        {
            return false;
        }

        const std::size_t expected = static_cast<std::size_t>(count) * perPoly;
        if (flat.size() != expected)
        {
            return false;
        }

        out.resize(count);
        for (std::size_t i = 0; i < count; ++i)
        {
            const auto begin = flat.begin() + static_cast<std::ptrdiff_t>(i * perPoly);
            const auto end = begin + static_cast<std::ptrdiff_t>(perPoly);
            assignRange(out[i].mCoeffs, begin, end);
        }
        return true;
    }

    AlignedUnVec<u64> packRingTensor(const RingTensor& tensor)
    {
        return packRingBatch(tensor.mPolys);
    }

    bool unpackRingTensor(
        u32 rows,
        u32 cols,
        u32 polyModulusDegree,
        u32 coeffModulusCount,
        std::span<const u64> flat,
        RingTensor& out,
        u32 requestedWorkers)
    {
        if (rows > 0 && cols > std::numeric_limits<u32>::max() / rows)
        {
            return false;
        }

        std::vector<RnsPoly> polys;
        if (!unpackRingBatch(rows * cols, polyModulusDegree, coeffModulusCount, flat, polys, requestedWorkers))
        {
            return false;
        }

        out.mRows = rows;
        out.mCols = cols;
        out.mPolys = std::move(polys);
        return true;
    }

    static block deriveUniformPolySeed(
        const RingNttContext& ctx, block seed, u64 domainTag, u32 index)
    {
        block polySeed{};
        RandomOracle ro(sizeof(polySeed));
        constexpr u64 label = 0x4C4F47564F4C5059ull;
        roUpdatePod(ro, label);
        roUpdatePod(ro, seed);
        roUpdatePod(ro, domainTag);
        roUpdatePod(ro, index);
        roUpdatePod(ro, ctx.mParams.mPolyModulusDegree);
        const u64 modulusCount = static_cast<u64>(ctx.mParams.mCoeffModulusBits.size());
        roUpdatePod(ro, modulusCount);
        ro.Final(polySeed);
        return polySeed;
    }

    static void deriveUniformPolyFromSeedInplace(
        const RingNttContext& ctx, block seed, u64 domainTag, u32 index, RnsPoly& out, PRNG& prng, PendingRingOpsStats* stats)
    {
        auto* timing = timingStats(ctx);
        AutoTimer totalSamplingTimer(timing ? &timing->mSeedSamplingTimeUs : nullptr);
        AutoTimer polySamplingTimer(timing ? &timing->mPolySamplingTimeUs : nullptr);

        // Every coefficient is overwritten by the sampler. Retain the backing
        // allocation when resampling an existing polynomial.
        out.mCoeffs.resize(ringPolyCoeffCount(ctx.mParams));
        const block polySeed = deriveUniformPolySeed(ctx, seed, domainTag, index);

        const auto hostContext = getRingHostContext(ctx);
        auto contextData = hostContext ? hostContext->key_context_data() : nullptr;
        if (contextData)
        {
            prng.SetSeed(detail::aesPrngKey(sealSeedFromBlock(polySeed)));
            detail::cpuSamplePolyUniform(ctx.mCpuCapabilities, prng, contextData->parms(), out.mCoeffs.data());
            bumpRingStat(RingOp::PrngPoly, stats);
            return;
        }

        if (ctx.mGpuLightweight)
            throw std::runtime_error("lightweight ring uniform sampler could not materialize its exact host context");

        PRNG rng(polySeed);
        std::fill(out.mCoeffs.begin(), out.mCoeffs.end(), u64{0});
        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        for (std::size_t modIdx = 0; modIdx < ringModulusCount(ctx); ++modIdx)
        {
            const u64 mod = ringModulusValue(ctx, modIdx);
            const std::size_t offset = modIdx * n;
            for (std::size_t i = 0; i < n; ++i)
            {
                out.mCoeffs[offset + i] = rng.get<u64>() % mod;
            }
        }
        bumpRingStat(RingOp::PrngPoly, stats);
    }

    RnsPoly deriveUniformPolyFromSeed(const RingNttContext& ctx, block seed, u64 domainTag, u32 index, PendingRingOpsStats* stats)
    {
        RnsPoly out{};
        PRNG prng(ZeroBlock);
        deriveUniformPolyFromSeedInplace(ctx, seed, domainTag, index, out, prng, stats);
        return out;
    }

    RnsPoly deriveUniformPolyFromSeedNtt(const RingNttContext& ctx, block seed, u64 domainTag, u32 index, PendingRingOpsStats* stats)
    {
        RnsPoly out = deriveUniformPolyFromSeed(ctx, seed, domainTag, index, stats);
        (void)forwardNttCanonical(out, ctx, stats);
        return out;
    }

    RnsPoly sampleUniformPolyFromSeed(
        const RingNttContext& ctx, const std::array<u64, 8>& seed, PendingRingOpsStats* stats)
    {
        RnsPoly out{};
        const auto hostContext = getRingHostContext(ctx);
        const auto data = hostContext ? hostContext->key_context_data() : nullptr;
        if (!data && ctx.mGpuLightweight)
            throw std::runtime_error("lightweight ring uniform sampler could not materialize its exact host context");
        if (!data) return out;
        resizeZero(out.mCoeffs, ringPolyCoeffCount(ctx.mParams));
        PRNG source(detail::aesPrngKey(seed));
        detail::cpuSamplePolyUniform(ctx.mCpuCapabilities, source, data->parms(), out.mCoeffs.data());
        bumpRingStat(RingOp::PrngPoly, stats);
        return out;
    }

#if defined(ENABLE_LOGVOLE_CUDA)
    static bool useDeviceUniformSetup(const RingNttContext& ctx)
    {
        if (!gpu::enabled(ctx)) return false;
        const bool available = gpu::setupUniformSamplingEnabled(ctx.mExecutionOptions, gpu::enabled(ctx)) &&
            (ctx.mGpuLightweight ? validateLightweightRingContext(ctx) :
                (ctx.mContext && ctx.mContext->key_context_data()));
        if (!available && ctx.mExecutionOptions.mAdvanced.mProtocol.mUniformSampling &&
            ctx.mExecutionOptions.mAdvanced.mProtocol.mUniformSamplingStrict)
            throw std::runtime_error("setup uniform device sampler is unavailable");
        return available;
    }

    class SeededTopSecretHostState final : public LazyRootSecretHostState
    {
    public:
        SeededTopSecretHostState(RingNttContext ctx,
            std::vector<seal::prng_seed_type> rowSeeds)
            : mCtx(std::move(ctx)), mSeeds(std::move(rowSeeds)) {}
        std::size_t count() const override { return mSeeds.size(); }
        bool matches(const RingParams& params) const override
        {
            return mCtx.mParams == params;
        }
        const std::vector<RnsPoly>& hostCoefficients() const override
        {
            PendingRingOpsStats stats(gpu::enabled(mCtx) ? nullptr : mCtx.mExecutionOptions.mRingOpsStats);
            return hostCoefficients(gpu::enabled(mCtx) ? legacyRingOpsThreadLocalStats() : &stats);
        }
        const std::vector<RnsPoly>& hostCoefficients(PendingRingOpsStats* stats) const
        {
            std::call_once(mOnce, [&] {
                HostStep step(hostProfiler(mCtx), "setup sender: top sk1 exact seed replay");
                std::vector<RnsPoly> next(mSeeds.size());
                for (std::size_t row = 0; row < mSeeds.size(); ++row)
                    next[row] = sampleUniformPolyFromSeed(mCtx, mSeeds[row], stats);
                if (!validateRingBatchShape(next, mCtx.mParams))
                    throw std::runtime_error("top sk1 seed replay failed");
                mHost = std::move(next);
            });
            return mHost;
        }
    private:
        RingNttContext mCtx;
        std::vector<seal::prng_seed_type> mSeeds;
        mutable std::once_flag mOnce;
        mutable std::vector<RnsPoly> mHost;
    };

    static std::vector<RnsPoly> sampleUniformSetupSeeds(
        const RingNttContext& ctx, std::span<const std::array<u64, 8>> seeds, bool actualNtt,
        std::shared_ptr<const gpu::RetainedPublicUniform>* captured,
        ProtocolCacheScopeView scope, PendingRingOpsStats* stats)
    {
        std::vector<RnsPoly> out;
        if (gpu::sampleUniformBatchFromSeedsDevice(ctx, seeds, actualNtt, out, captured, scope) &&
            out.size() == seeds.size())
        {
            for (std::size_t i = 0; i < seeds.size(); ++i)
            {
                bumpRingStat(RingOp::PrngPoly, stats);
                if (actualNtt)
                    bumpRingStat(RingOp::Ntt, stats);
            }
            return out;
        }
        if (ctx.mExecutionOptions.mAdvanced.mProtocol.mUniformSamplingStrict)
            throw std::runtime_error("setup uniform device sampler failed");
        if (captured) captured->reset();
        // The parent stream has already advanced. Replay precisely those SEAL
        // seeds, including after an allocation or device launch failure.
        out.resize(seeds.size());
        for (std::size_t i = 0; i < seeds.size(); ++i)
        {
            out[i] = sampleUniformPolyFromSeed(ctx, seeds[i], stats);
            if (actualNtt) (void)forwardNttCanonical(out[i], ctx, stats);
        }
        return out;
    }
#endif

    RnsPoly sampleUniformPoly(const RingNttContext& ctx, PRNG& prng, PendingRingOpsStats* stats)
    {
        const auto hostContext = getRingHostContext(ctx);
        auto contextData = hostContext ? hostContext->key_context_data() : nullptr;
        if (contextData)
        {
            return sampleUniformPolyFromSeed(ctx, sealSeedFromPrng(prng), stats);
        }

        if (ctx.mGpuLightweight)
            throw std::runtime_error("lightweight ring uniform sampler could not materialize its exact host context");

        RnsPoly out{};
        resizeZero(out.mCoeffs, ringPolyCoeffCount(ctx.mParams));
        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        for (std::size_t modIdx = 0; modIdx < ringModulusCount(ctx); ++modIdx)
        {
            const u64 mod = ringModulusValue(ctx, modIdx);
            const std::size_t offset = modIdx * n;
            for (std::size_t i = 0; i < n; ++i)
            {
                out.mCoeffs[offset + i] = prng.get<u64>() % mod;
            }
        }
        bumpRingStat(RingOp::PrngPoly, stats);
        return out;
    }

    RnsPoly sampleUniformPolyNtt(const RingNttContext& ctx, PRNG& prng, PendingRingOpsStats* stats)
    {
        RnsPoly out = sampleUniformPoly(ctx, prng, stats);
        (void)forwardNttCanonical(out, ctx, stats);
        return out;
    }

    std::vector<RnsPoly> sampleUniformPolyBatch(const RingNttContext& ctx, u32 count, PRNG& prng, ProtocolCacheScopeView scope, PendingRingOpsStats* stats)
    {
        if (count == 0) return {};
#if defined(ENABLE_LOGVOLE_CUDA)
        if (useDeviceUniformSetup(ctx))
        {
            std::vector<std::array<u64, 8>> seeds(count);
            // Separate scalar-sized draws preserve PRNG refill behavior even
            // when a caller uses a non-default, very small AES buffer.
            for (u32 i = 0; i < count; ++i) seeds[i] = sealSeedFromPrng(prng);
            return sampleUniformSetupSeeds(ctx, seeds, false, nullptr, scope, stats);
        }
#endif
        std::vector<RnsPoly> out(count);
        for (u32 i = 0; i < count; ++i) out[i] = sampleUniformPoly(ctx, prng, stats);
        return out;
    }

    bool sampleTopSecretUniformBatch(const RingNttContext& ctx, u32 count,
        PRNG& prng, std::vector<RnsPoly>& eager,
        std::shared_ptr<gpu::DeviceBatch>& resident,
        std::shared_ptr<const LazyRootSecretHostState>& lazy, ProtocolCacheScopeView scope, PendingRingOpsStats* stats)
    {
        if (!count) return false;
#if defined(ENABLE_LOGVOLE_CUDA)
        const bool requested = gpu::enabled(ctx) &&
            scope.mRole == ProtocolCacheRole::Sender &&
            scope.mRunId &&
            ctx.mExecutionOptions.mAdvanced.mProtocol.mTopSecretDevice;
        const bool strict = requested && ctx.mExecutionOptions.mAdvanced.mProtocol.mTopSecretDeviceStrict;
        if (requested && useDeviceUniformSetup(ctx))
        {
            std::vector<seal::prng_seed_type> seeds(count);
            // Scalar-sized, row-ordered SEAL draws match sampleUniformPolyBatch,
            // including callers with small parent PRNG buffers.
            for (auto& seed : seeds) seed = sealSeedFromPrng(prng);
            auto next = gpu::sampleTopSecretUniformToDevice(ctx, seeds, scope);
            auto host = std::make_shared<SeededTopSecretHostState>(ctx, std::move(seeds));
            if (next && gpu::topSecretUniformBatchMatches(ctx, *next, count,
                    scope.mRunId, scope))
            {
                for (u32 row = 0; row < count; ++row)
                    bumpRingStat(RingOp::PrngPoly, stats);
                resident = std::move(next);
                lazy = std::move(host);
                eager.clear();
                return true;
            }
            if (strict) return false;
            eager = host->hostCoefficients(stats);
            resident.reset();
            lazy.reset();
            return eager.size() == count;
        }
        if (strict) return false;
#endif
        eager = sampleUniformPolyBatch(ctx, count, prng, scope, stats);
        resident.reset();
        lazy.reset();
        return eager.size() == count;
    }

    RnsPoly deriveUniformPolyFromNonce(const RingNttContext& ctx, u64 nonce, u64 domainTag, u32 index, PendingRingOpsStats* stats)
    {
        return deriveUniformPolyFromSeed(
            ctx,
            derivePublicSeedBlock(
                domainTag,
                nonce,
                index,
                ctx.mParams.mPolyModulusDegree,
                static_cast<u64>(ctx.mParams.mCoeffModulusBits.size())),
            domainTag,
            index, stats);
    }

    RnsPoly deriveUniformPolyFromNonceNtt(const RingNttContext& ctx, u64 nonce, u64 domainTag, u32 index, PendingRingOpsStats* stats)
    {
        RnsPoly out = deriveUniformPolyFromNonce(ctx, nonce, domainTag, index, stats);
        (void)forwardNttCanonical(out, ctx, stats);
        return out;
    }

    void deriveUniformPolyBatchFromSeedInplace(
        const RingNttContext& ctx,
        block seed,
        u64 domainTag,
        u32 count,
        std::vector<RnsPoly>& out, PendingRingOpsStats* stats)
    {
        auto* timing = timingStats(ctx);
        AutoTimer totalSamplingTimer(timing ? &timing->mSeedSamplingTimeUs : nullptr);
        AutoTimer polySamplingTimer(timing ? &timing->mPolySamplingTimeUs : nullptr);

#if defined(ENABLE_LOGVOLE_CUDA)
        // Batched sampling amortises the device round trip. CPU and CUDA use
        // the same domain-separated AES counter stream.
        if (count >= 4)
        {
            std::vector<RnsPoly> gpuOut;
            if (gpu::deriveUniformPolyBatchDevice(ctx, seed, domainTag, count, gpuOut) &&
                gpuOut.size() == count)
            {
                for (u32 i = 0; i < count; ++i)
                {
                    bumpRingStat(RingOp::PrngPoly, stats);
                }
                out = std::move(gpuOut);
                return;
            }
        }
#endif
        out.resize(count);
        PRNG prng(ZeroBlock);
        for (u32 i = 0; i < count; ++i)
        {
            deriveUniformPolyFromSeedInplace(ctx, seed, domainTag, i, out[i], prng, stats);
        }
    }

    std::vector<RnsPoly> deriveUniformPolyBatchFromSeed(
        const RingNttContext& ctx, block seed, u64 domainTag, u32 count, PendingRingOpsStats* stats)
    {
        std::vector<RnsPoly> out;
        deriveUniformPolyBatchFromSeedInplace(ctx, seed, domainTag, count, out, stats);
        return out;
    }

    std::vector<RnsPoly> deriveUniformPolyBatchFromNonce(const RingNttContext& ctx, u64 nonce, u64 domainTag, u32 count, ProtocolCacheScopeView scope, PendingRingOpsStats* stats)
    {
        return deriveUniformPolyBatchFromNonce(ctx, nonce, domainTag, count, false, scope, stats);
    }

    std::vector<RnsPoly> deriveUniformPolyBatchFromNonce(
        const RingNttContext& ctx, u64 nonce, u64 domainTag, u32 count, bool actualNtt, ProtocolCacheScopeView scope, PendingRingOpsStats* stats)
    {
        return deriveUniformPolyBatchFromNonce(ctx, nonce, domainTag, count, actualNtt, nullptr, scope, stats);
    }

    std::vector<RnsPoly> deriveUniformPolyBatchFromNonce(
        const RingNttContext& ctx, u64 nonce, u64 domainTag, u32 count, bool actualNtt,
        std::shared_ptr<const gpu::RetainedPublicUniform>* captured, ProtocolCacheScopeView scope, PendingRingOpsStats* stats)
    {
        auto* timing = timingStats(ctx);
        AutoTimer totalSamplingTimer(timing ? &timing->mSeedSamplingTimeUs : nullptr);
        AutoTimer polySamplingTimer(timing ? &timing->mPolySamplingTimeUs : nullptr);
        if (count == 0)
        {
            if (captured) captured->reset();
            return {};
        }
#if defined(ENABLE_LOGVOLE_CUDA)
        if (useDeviceUniformSetup(ctx))
        {
            std::vector<std::array<u64, 8>> seeds(count);
            for (u32 i = 0; i < count; ++i)
            {
                const block publicSeed = derivePublicSeedBlock(domainTag, nonce, i,
                    ctx.mParams.mPolyModulusDegree,
                    static_cast<u64>(ctx.mParams.mCoeffModulusBits.size()));
                seeds[i] = sealSeedFromBlock(deriveUniformPolySeed(ctx, publicSeed, domainTag, i));
            }
            return sampleUniformSetupSeeds(ctx, seeds, actualNtt, captured, scope, stats);
        }
#endif
        if (captured) captured->reset();
        std::vector<RnsPoly> out(count);
        for (u32 i = 0; i < count; ++i)
        {
            out[i] = deriveUniformPolyFromNonce(ctx, nonce, domainTag, i, stats);
            if (actualNtt) (void)forwardNttCanonical(out[i], ctx, stats);
        }
        return out;
    }

    bool retainUniformPolyBatchFromNonce(
        const RingNttContext& ctx, u64 nonce, u64 domainTag, u32 count,
        bool actualNtt, std::shared_ptr<const gpu::RetainedPublicUniform>& out, ProtocolCacheScopeView scope, PendingRingOpsStats* stats)
    {
#if defined(ENABLE_LOGVOLE_CUDA)
        if (!count || !useDeviceUniformSetup(ctx)) return false;
        AutoTimer totalSamplingTimer(globalTimingStats.mSeedSamplingTimeUs);
        AutoTimer polySamplingTimer(globalTimingStats.mPolySamplingTimeUs);
        std::vector<std::array<u64, 8>> seeds(count);
        for (u32 i = 0; i < count; ++i)
        {
            const block publicSeed = derivePublicSeedBlock(domainTag, nonce, i,
                ctx.mParams.mPolyModulusDegree,
                static_cast<u64>(ctx.mParams.mCoeffModulusBits.size()));
            seeds[i] = sealSeedFromBlock(deriveUniformPolySeed(ctx, publicSeed, domainTag, i));
        }
        std::shared_ptr<const gpu::RetainedPublicUniform> next;
        if (!gpu::retainUniformBatchFromSeedsDevice(ctx, seeds, actualNtt, next, scope) ||
            !next || next->count() != count) return false;
        for (u32 i = 0; i < count; ++i)
        {
            bumpRingStat(RingOp::PrngPoly, stats);
            if (actualNtt)
                bumpRingStat(RingOp::Ntt, stats);
        }
        out = std::move(next);
        return true;
#else
        (void)ctx;
        (void)nonce;
        (void)domainTag;
        (void)count;
        (void)actualNtt;
        (void)out;
        return false;
#endif
    }

    std::vector<RnsPoly> deriveUniformPolyBatchFromSeedNtt(
        const RingNttContext& ctx,
        block seed,
        u64 domainTag,
        u32 count, PendingRingOpsStats* stats)
    {
        return deriveUniformPolyBatchFromSeed(ctx, seed, domainTag, count, stats);
    }

    std::vector<RnsPoly> deriveUniformPolyBatchFromNonceNtt(
        const RingNttContext& ctx,
        u64 nonce,
        u64 domainTag,
        u32 count, PendingRingOpsStats* stats)
    {
        return deriveUniformPolyBatchFromNonce(ctx, nonce, domainTag, count, {}, stats);
    }

    bool deriveUniformPolyBatchFromSeedListInplace(
        const RingNttContext& ctx,
        std::span<const block> seeds,
        u64 domainTag,
        u32 perSeedCount,
        std::vector<RnsPoly>& out,
        u32 requestedWorkers, PendingRingOpsStats* stats)
    {
        if (perSeedCount != 0 && seeds.size() > std::numeric_limits<std::size_t>::max() / perSeedCount)
        {
            return false;
        }

        const std::size_t totalCount = seeds.size() * static_cast<std::size_t>(perSeedCount);
        out.resize(totalCount);
        (void)requestedWorkers;
        PRNG prng(ZeroBlock);
        for (std::size_t seedIdx = 0; seedIdx < seeds.size(); ++seedIdx)
        {
            for (u32 polyIdx = 0; polyIdx < perSeedCount; ++polyIdx)
            {
                deriveUniformPolyFromSeedInplace(ctx, seeds[seedIdx], domainTag, polyIdx,
                    out[seedIdx * static_cast<std::size_t>(perSeedCount) + polyIdx], prng, stats);
            }
        }
        return true;
    }

    std::vector<RnsPoly> deriveUniformPolyBatchFromSeedList(
        const RingNttContext& ctx,
        std::span<const block> seeds,
        u64 domainTag,
        u32 perSeedCount,
        u32 requestedWorkers, PendingRingOpsStats* stats)
    {
        std::vector<RnsPoly> out;
        (void)deriveUniformPolyBatchFromSeedListInplace(ctx, seeds, domainTag, perSeedCount, out, requestedWorkers, stats);
        return out;
    }

    bool deriveUniformPolyBatchFromNonceListInplace(
        const RingNttContext& ctx,
        std::span<const u64> nonces,
        u64 domainTag,
        u32 perNonceCount,
        std::vector<RnsPoly>& out,
        u32, PendingRingOpsStats* stats)
    {
        if (perNonceCount != 0 && nonces.size() > std::numeric_limits<std::size_t>::max() / perNonceCount)
        {
            return false;
        }

        const std::size_t totalCount = nonces.size() * static_cast<std::size_t>(perNonceCount);
        out.resize(totalCount);
        for (std::size_t nonceIdx = 0; nonceIdx < nonces.size(); ++nonceIdx)
        {
            for (u32 polyIdx = 0; polyIdx < perNonceCount; ++polyIdx)
            {
                out[nonceIdx * perNonceCount + polyIdx] =
                    deriveUniformPolyFromNonce(ctx, nonces[nonceIdx], domainTag, polyIdx, stats);
            }
        }
        return true;
    }

    std::vector<RnsPoly> deriveUniformPolyBatchFromNonceList(
        const RingNttContext& ctx,
        std::span<const u64> nonces,
        u64 domainTag,
        u32 perNonceCount,
        u32 requestedWorkers, PendingRingOpsStats* stats)
    {
        std::vector<RnsPoly> out;
        (void)deriveUniformPolyBatchFromNonceListInplace(ctx, nonces, domainTag, perNonceCount, out, requestedWorkers, stats);
        return out;
    }

    bool canSamplePolyErrorCompact(
        const RingNttContext& ctx, double noiseStandardDeviation, double noiseMaxDeviation)
    {
        if (!std::isfinite(noiseStandardDeviation) || noiseStandardDeviation < 0 ||
            !std::isfinite(noiseMaxDeviation) || noiseMaxDeviation < 0 ||
            !ringModulusCount(ctx)) return false;
        if (ctx.mGpuLightweight)
        {
            // Gaussian GPU eligibility needs only the exact ring shape and
            // ordered moduli; it must not construct CPU NTT/RNS tables.
            if (!validateLightweightRingContext(ctx)) return false;
        }
        else
        {
            if (!ctx.mContext || !ctx.mContext->key_context_data()) return false;
            const auto& parms = ctx.mContext->key_context_data()->parms();
            if (parms.poly_modulus_degree() != ctx.mParams.mPolyModulusDegree ||
                parms.coeff_modulus().size() != ringModulusCount(ctx) ||
                ctx.mParams.mCoeffModulusBits.size() != ringModulusCount(ctx)) return false;
            for (std::size_t j = 0; j < ringModulusCount(ctx); ++j)
                if (parms.coeff_modulus()[j].value() != ringModulusValue(ctx, j)) return false;
        }
        // The centered load recovers the sign using q0 and broadcasts the
        // magnitude without a general modular reduction in the target limbs.
        const long double clip = noiseMaxDeviation;
        if (clip >= static_cast<long double>(ringModulusValue(ctx, 0) >> 1u)) return false;
        for (std::size_t j = 0; j < ringModulusCount(ctx); ++j)
            if (clip >= static_cast<long double>(ringModulusValue(ctx, j))) return false;
        return true;
    }

    bool samplePolyErrorCompactFromSeed(
        std::span<u64> limb0, double noiseStandardDeviation, double noiseMaxDeviation,
        const seal::prng_seed_type& seed, const RingNttContext& ctx, PendingRingOpsStats* stats)
    {
        if (!canSamplePolyErrorCompact(ctx, noiseStandardDeviation, noiseMaxDeviation) ||
            limb0.size() != ctx.mParams.mPolyModulusDegree) return false;
        const auto hostContext = getRingHostContext(ctx);
        if (!hostContext || !hostContext->key_context_data()) return false;
        PRNG prng(detail::aesPrngKey(seed));
        AesNormalEngine engine{prng};
        samplePolyNormal(engine, hostContext->key_context_data()->parms(),
            limb0.data(), noiseStandardDeviation, noiseMaxDeviation, true);
        bumpRingStat(RingOp::ErrorAdd, stats);
        return true;
    }

    namespace
    {
        // The downloaded prefix and the CPU tail are the same AES stream.
        // Borrow both; prefixOwner in the enclosing operation keeps the pinned
        // bytes alive until the blocking CPU task group has joined.
        class GaussianPrefixEngine
        {
        public:
            using result_type = u32;
            GaussianPrefixEngine(PRNG& source, std::span<const u64> prefix)
                : mSource(source), mPrefix(prefix) {}
            static constexpr result_type min() { return 0; }
            static constexpr result_type max() { return ~result_type{0}; }
            result_type operator()()
            {
                if (mNext < mPrefix.size() * 2u)
                {
                    const u64 word = mPrefix[mNext / 2u];
                    const auto shift = static_cast<unsigned>((mNext++ & 1u) * 32u);
                    return static_cast<u32>(word >> shift);
                }
                if (!mTail)
                {
                    // cryptoTools PRNG exposes its AES counter and refill API.
                    // Prefixes contain whole counter blocks: jump directly to
                    // the next one instead of regenerating the prefix on CPU.
                    mSource.mBlockIdx = mPrefix.size() / 2u;
                    mSource.refillBuffer();
                    mTail = true;
                }
                return mSource.get<result_type>();
            }
        private:
            PRNG& mSource;
            std::span<const u64> mPrefix;
            std::size_t mNext = 0;
            bool mTail = false;
        };
    }

    macoro::task<bool> samplePolyErrorCompactBatchFromSeeds(
        macoro::thread_pool &executor, std::span<u8> setupResults, std::span<u64> limb0,
        double noiseStandardDeviation, double noiseMaxDeviation, std::span<const seal::prng_seed_type> seeds,
        const RingNttContext &ctx, u32 requestedWorkers, std::span<const u8> active,
        CpuBenchmarkState cpuBenchmark)
    {
        if (setupResults.empty()) co_return false;
        if (!gpu::enabled(ctx)) requestedWorkers = std::max(1u, requestedWorkers);
        if (!cpuBenchmark.mContext) cpuBenchmark.mContext = cpuBenchmarkContext(ctx);
        if (cpuBenchmark.mContext && gpu::enabled(ctx))
        {
            const auto& limits = *cpuBenchmark.mContext;
            const auto capacity = std::max<std::size_t>(1, limits.mWorkerLimit
                ? std::min(limits.mWorkerLimit, limits.mCpus.size()) : limits.mCpus.size());
            setupResults = setupResults.first(std::min(setupResults.size(), capacity));
        }
        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        if (!canSamplePolyErrorCompact(ctx, noiseStandardDeviation, noiseMaxDeviation) || !n ||
            seeds.size() > std::numeric_limits<std::size_t>::max() / n || limb0.size() != seeds.size() * n ||
            (!active.empty() && active.size() != seeds.size()))
            co_return false;
        std::vector<std::size_t> activeRows;
        activeRows.reserve(seeds.size());
        for (std::size_t i = 0; i < seeds.size(); ++i)
            if (active.empty() || active[i]) activeRows.push_back(i);
        if (activeRows.empty()) co_return true;
        if (!gpu::enabled(ctx) && setupResults.size() <
            std::min(std::size_t(requestedWorkers), activeRows.size())) co_return false;

        std::shared_ptr<const u64> prefixOwner;
        std::span<const u64> prefixes;
        std::size_t wordsPerPrefix = 0;
        bool devicePrefixes = false;
#if defined(ENABLE_LOGVOLE_CUDA)
        if (gpu::enabled(ctx) && ctx.mExecutionOptions.mAdvanced.mProtocol.mGaussianTransform)
        {
            const bool strict = ctx.mExecutionOptions.mAdvanced.mProtocol.mGaussianTransformStrict;
            const u64 blocks = ctx.mExecutionOptions.mAdvanced.mProtocol.mGaussianTransformPrefixBlocks;
            const bool validPrefix = blocks <= std::numeric_limits<u32>::max() / 512u;
            gpu::GaussianSampleBuffer sampled;
            bool transformed = false;
            if (validPrefix && n <= std::numeric_limits<u32>::max() &&
                ctx.mGpuExecution && ctx.mGpuExecution->gaussianCompatibility().compatible())
            {
                std::vector<seal::prng_seed_type> activeSeeds(activeRows.size());
                for (std::size_t i = 0; i < activeRows.size(); ++i)
                    activeSeeds[i] = seeds[activeRows[i]];
                transformed = gpu::sampleGaussianCompactDevice(
                    gpu::contextSampleStream(ctx), activeSeeds, static_cast<u32>(n),
                    noiseStandardDeviation, noiseMaxDeviation, ringModulusValue(ctx, 0), sampled,
                    static_cast<u32>(blocks * 512u), ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures);
            }
            // A declined strict transform must not publish any destination
            // samples. Successful finite prefixes may still require exact
            // replay of individual rows from the unchanged original seed.
            if (!transformed && strict) co_return false;
            if (transformed)
            {
                const auto taskCount = activeRows.size();
                auto chunks = setupResults.first(
                    std::min({setupResults.size(), static_cast<std::size_t>(taskCount),
                              static_cast<std::size_t>((requestedWorkers) ? (requestedWorkers)
                                                                          : setupResults.size())}));
                if (taskCount && chunks.empty()) co_return false;
                std::fill(chunks.begin(), chunks.end(), u8{1});
                auto item = [&](std::size_t task, CpuBenchmarkState& cpuBenchmark, PendingRingOpsStats* stats) {
                    const auto row = activeRows[task];
                    auto destination = limb0.subspan(row * n, n);
                    if (!sampled.mComplete[task])
                    {
                        HostStep replayStep(hostProfiler(ctx), "setup: Gaussian CPU replay", &cpuBenchmark);
                        return samplePolyErrorCompactFromSeed(destination, noiseStandardDeviation,
                                                              noiseMaxDeviation, seeds[row], ctx, stats);
                    }
                    std::memcpy(destination.data(), sampled.mValues.mData.get() + task * n,
                                destination.size_bytes());
                    bumpRingStat(RingOp::ErrorAdd, stats);
                    return true;
                };
                auto runChunk = [&](std::size_t begin, std::size_t end, u8 &ok) {
                    CpuBenchmarkState worker =
                        chunks.size() > 1 ? CpuBenchmarkState{cpuBenchmark.mContext, true} : cpuBenchmark;
                    CpuBenchmarkWorkerScope timing(chunks.size() > 1 ? worker.mContext : nullptr);
                    CpuBenchmarkTaskScope metrics(worker);
                    PendingRingOpsStats pending(gpu::enabled(ctx) ? nullptr : ctx.mExecutionOptions.mRingOpsStats);
                    auto* stats = gpu::enabled(ctx) ? legacyRingOpsThreadLocalStats() : &pending;
                    struct FlushStats
                    {
                        bool legacy;
                        ~FlushStats()
                        {
                            if (legacy) flushRingOpsThreadLocalStats();
                        }
                    } flush{gpu::enabled(ctx)};
                    for (auto i = begin; i != end; ++i)
                        if (!item(i, worker, stats))
                        {
                            ok = 0;
                            break;
                        }
                };
                if (chunks.size() == 1) runChunk(0, taskCount, chunks[0]);
                else if (taskCount)
                {
                    co_await macoro::bulk_chunked(executor, taskCount, chunks, runChunk);
                }
                const bool phaseOk = std::all_of(chunks.begin(), chunks.end(), [](u8 ok) { return ok != 0; });
                co_return phaseOk;
            }
        }
        const bool requested = gpu::enabled(ctx) && ctx.mExecutionOptions.mAdvanced.mProtocol.mGaussianPrg;
        if (requested)
        {
            const bool strict = ctx.mExecutionOptions.mAdvanced.mProtocol.mGaussianPrgStrict;
            // Three u32 words per coefficient exceed the normal polar sampler's
            // expected consumption; arbitrary clipping still has exact CPU
            // continuation when that finite prefix is exhausted.
            const u64 defaultBlocks = (static_cast<u64>(n) * 3u + 1023u) / 1024u;
            const u64 blocks = ctx.mExecutionOptions.mAdvanced.mProtocol.mGaussianPrgPrefixBlocks
                ? ctx.mExecutionOptions.mAdvanced.mProtocol.mGaussianPrgPrefixBlocks : defaultBlocks;
            if (blocks <= std::numeric_limits<u32>::max() / 512u)
            {
                wordsPerPrefix = static_cast<std::size_t>(blocks) * 512u;
                std::vector<seal::prng_seed_type> activeSeeds(activeRows.size());
                for (std::size_t i = 0; i < activeRows.size(); ++i) activeSeeds[i] = seeds[activeRows[i]];
                gpu::GaussianPrngPrefixBuffer downloaded;
                devicePrefixes = gpu::sampleGaussianPrngPrefixesDevice(
                    gpu::contextSampleStream(ctx), activeSeeds, static_cast<u32>(wordsPerPrefix), downloaded, ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures);
                if (devicePrefixes)
                {
                    prefixOwner = std::move(downloaded.mData);
                    prefixes = std::span<const u64>(prefixOwner.get(), downloaded.mWords);
                }
            }
            if (!devicePrefixes && strict) co_return false;
        }
#endif
        {
            const auto taskCount = activeRows.size();
            auto chunks = setupResults.first(std::min(
                {setupResults.size(), static_cast<std::size_t>(taskCount),
                 static_cast<std::size_t>((requestedWorkers) ? (requestedWorkers) : setupResults.size())}));
            if (taskCount && chunks.empty()) co_return false;
            std::fill(chunks.begin(), chunks.end(), u8{1});
            auto item = [&](std::size_t task, CpuBenchmarkState& cpuBenchmark, PendingRingOpsStats* stats) {
                const auto row = activeRows[task];
                auto destination = limb0.subspan(row * n, n);
                if (!devicePrefixes)
                    return samplePolyErrorCompactFromSeed(destination, noiseStandardDeviation,
                                                          noiseMaxDeviation, seeds[row], ctx, stats);
                PRNG prng(detail::aesPrngKey(seeds[row]));
                GaussianPrefixEngine source(prng, prefixes.subspan(task * wordsPerPrefix, wordsPerPrefix));
                const auto hostContext = getRingHostContext(ctx);
                if (!hostContext || !hostContext->key_context_data()) return false;
                samplePolyNormal(source, hostContext->key_context_data()->parms(), destination.data(),
                                 noiseStandardDeviation, noiseMaxDeviation, true);
                bumpRingStat(RingOp::ErrorAdd, stats);
                return true;
            };
            auto runChunk = [&](std::size_t begin, std::size_t end, u8 &ok) {
                CpuBenchmarkState worker =
                    chunks.size() > 1 ? CpuBenchmarkState{cpuBenchmark.mContext, true} : cpuBenchmark;
                CpuBenchmarkWorkerScope timing(chunks.size() > 1 ? worker.mContext : nullptr);
                CpuBenchmarkTaskScope metrics(worker);
                PendingRingOpsStats pending(gpu::enabled(ctx) ? nullptr : ctx.mExecutionOptions.mRingOpsStats);
                auto* stats = gpu::enabled(ctx) ? legacyRingOpsThreadLocalStats() : &pending;
                struct FlushStats
                {
                    bool legacy;
                    ~FlushStats()
                    {
                        if (legacy) flushRingOpsThreadLocalStats();
                    }
                } flush{gpu::enabled(ctx)};
                for (auto i = begin; i != end; ++i)
                    if (!item(i, worker, stats))
                    {
                        ok = 0;
                        break;
                    }
            };
            if (chunks.size() == 1) runChunk(0, taskCount, chunks[0]);
            else if (taskCount)
            {
                co_await macoro::bulk_chunked(executor, taskCount, chunks, runChunk);
            }
            const bool phaseOk = std::all_of(chunks.begin(), chunks.end(), [](u8 ok) { return ok != 0; });
            co_return phaseOk;
        }
    }

    macoro::task<bool> samplePolyErrorCompactBatchForSetup(
        macoro::thread_pool &executor, std::span<u8> setupResults, std::vector<u64> &host,
        std::shared_ptr<gpu::DeviceScalars> &device, double sigma, double clip,
        std::span<const seal::prng_seed_type> seeds, const RingNttContext &ctx, u32 requestedWorkers,
        std::span<const u8> active, CpuBenchmarkState cpuBenchmark)
    {
        if (setupResults.empty()) co_return false;
        if (!gpu::enabled(ctx)) requestedWorkers = std::max(1u, requestedWorkers);
        if (!cpuBenchmark.mContext) cpuBenchmark.mContext = cpuBenchmarkContext(ctx);
        if (cpuBenchmark.mContext && gpu::enabled(ctx))
        {
            const auto& limits = *cpuBenchmark.mContext;
            const auto capacity = std::max<std::size_t>(1, limits.mWorkerLimit
                ? std::min(limits.mWorkerLimit, limits.mCpus.size()) : limits.mCpus.size());
            setupResults = setupResults.first(std::min(setupResults.size(), capacity));
        }
        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        if (!canSamplePolyErrorCompact(ctx, sigma, clip) || !n ||
            seeds.size() > std::numeric_limits<std::size_t>::max() / n ||
            (!active.empty() && active.size() != seeds.size()))
            co_return false;
        if (seeds.empty())
        {
            host.clear();
            device.reset();
            co_return true;
        }
        if (!gpu::enabled(ctx))
        {
            const auto activeCount = active.empty() ? seeds.size() :
                std::size_t(std::count_if(active.begin(), active.end(), [](u8 value) { return value != 0; }));
            if (setupResults.size() < std::min(std::size_t(requestedWorkers), activeCount)) co_return false;
        }
#if defined(ENABLE_LOGVOLE_CUDA)
        if (gpu::enabled(ctx) && ctx.mExecutionOptions.mAdvanced.mProtocol.mGaussianResident)
        {
            const bool strict = ctx.mExecutionOptions.mAdvanced.mProtocol.mGaussianResidentStrict;
            const u64 blocks = ctx.mExecutionOptions.mAdvanced.mProtocol.mGaussianTransformPrefixBlocks;
            const bool validPrefix = blocks <= std::numeric_limits<u32>::max() / 512u;
            gpu::GaussianDeviceSampleBuffer sampled;
            bool ready = ctx.mExecutionOptions.mAdvanced.mProtocol.mGaussianTransform && validPrefix &&
                n <= std::numeric_limits<u32>::max() && ctx.mGpuExecution && ctx.mGpuExecution->gaussianCompatibility().compatible() &&
                gpu::sampleGaussianCompactResidentDevice(
                    gpu::contextSampleStream(ctx), seeds, static_cast<u32>(n), sigma, clip,
                    ringModulusValue(ctx, 0), sampled, static_cast<u32>(blocks * 512u), active, ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures);
            if (ready)
            {
                std::vector<std::size_t> incomplete;
                for (std::size_t row = 0; row < seeds.size(); ++row)
                    if (!sampled.mComplete[row]) incomplete.push_back(row);
                // A finite first prefix can exhaust on only a few rows. Retry
                // those original seeds on the owning GPU before considering
                // exact host replay and an H2D repair of whole coefficient rows.
                const u64 defaultWords = ((static_cast<u64>(n) * 3u + 1023u) / 1024u) * 512u;
                u64 retryWords = std::max<u64>(defaultWords, blocks ? blocks * 1024u : defaultWords * 2u);
                for (u32 attempt = 0; ready && !incomplete.empty() &&
                        attempt < 8u && retryWords <= std::numeric_limits<u32>::max();
                        ++attempt)
                {
                    HostStep retryStep(hostProfiler(ctx), "setup: Gaussian resident GPU repair retry", &cpuBenchmark);
                    std::vector<seal::prng_seed_type> retrySeeds;
                    retrySeeds.reserve(incomplete.size());
                    for (const auto row : incomplete) retrySeeds.push_back(seeds[row]);
                    gpu::GaussianDeviceSampleBuffer retried;
                    if (!gpu::sampleGaussianCompactResidentDevice(
                            gpu::contextSampleStream(ctx), retrySeeds, static_cast<u32>(n), sigma, clip,
                            ringModulusValue(ctx, 0), retried,
                            static_cast<u32>(retryWords), {}, ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures)) break;
                    auto& stream = gpu::contextSampleStream(ctx);
                    gpu::StreamDrain drain{stream};
                    std::vector<std::size_t> remaining;
                    for (std::size_t i = 0; i < incomplete.size(); ++i)
                    {
                        const auto row = incomplete[i];
                        if (!retried.mComplete[i])
                        {
                            remaining.push_back(row);
                            continue;
                        }
                        if (!gpu::gpuMemcpyD2D(
                                sampled.mValues->data() + row * n,
                                retried.mValues->data() + i * n,
                                n * sizeof(u64), stream.raw()))
                        {
                            ready = false;
                            break;
                        }
                        sampled.mComplete[row] = 1;
                    }
                    ready = stream.sync() && ready;
                    if (!ready) break;
                    incomplete = std::move(remaining);
                    if (retryWords > std::numeric_limits<u32>::max() / 2u) break;
                    retryWords *= 2u;
                }
                std::vector<std::vector<u64>> repaired(incomplete.size());
                if (ready)
                {
                    const auto taskCount = incomplete.size();
                    auto chunks = setupResults.first(
                        std::min({setupResults.size(), static_cast<std::size_t>(taskCount),
                                  static_cast<std::size_t>((requestedWorkers) ? (requestedWorkers)
                                                                              : setupResults.size())}));
                    if (taskCount && chunks.empty()) co_return false;
                    std::fill(chunks.begin(), chunks.end(), u8{1});
                    auto item = [&](std::size_t i, CpuBenchmarkState& cpuBenchmark, PendingRingOpsStats* stats) {
                        HostStep repairStep(hostProfiler(ctx), "setup: Gaussian resident CPU repair",
                                            &cpuBenchmark);
                        repaired[i].resize(n);
                        return samplePolyErrorCompactFromSeed(repaired[i], sigma, clip, seeds[incomplete[i]],
                                                              ctx, stats);
                    };
                    auto runChunk = [&](std::size_t begin, std::size_t end, u8 &ok) {
                        CpuBenchmarkState worker =
                            chunks.size() > 1 ? CpuBenchmarkState{cpuBenchmark.mContext, true} : cpuBenchmark;
                        CpuBenchmarkWorkerScope timing(chunks.size() > 1 ? worker.mContext : nullptr);
                        CpuBenchmarkTaskScope metrics(worker);
                        PendingRingOpsStats pending(gpu::enabled(ctx) ? nullptr : ctx.mExecutionOptions.mRingOpsStats);
                        auto* stats = gpu::enabled(ctx) ? legacyRingOpsThreadLocalStats() : &pending;
                        struct FlushStats
                        {
                            bool legacy;
                            ~FlushStats()
                            {
                                if (legacy) flushRingOpsThreadLocalStats();
                            }
                        } flush{gpu::enabled(ctx)};
                        for (auto i = begin; i != end; ++i)
                            if (!item(i, worker, stats))
                            {
                                ok = 0;
                                break;
                            }
                    };
                    if (chunks.size() == 1) runChunk(0, taskCount, chunks[0]);
                    else if (taskCount)
                    {
                        co_await macoro::bulk_chunked(executor, taskCount, chunks, runChunk);
                    }
                    const bool phaseOk =
                        std::all_of(chunks.begin(), chunks.end(), [](u8 ok) { return ok != 0; });
                    ready = phaseOk;
                }
                if (ready && !incomplete.empty())
                {
                    auto& stream = gpu::contextSampleStream(ctx);
                    gpu::StreamDrain drain{stream};
                    for (std::size_t i = 0; ready && i < incomplete.size(); ++i)
                        ready = gpu::gpuMemcpyH2D(sampled.mValues->data() + incomplete[i] * n,
                            repaired[i].data(), n * sizeof(u64), stream.raw());
                    ready = stream.sync() && ready;
                }
                if (ready)
                {
                    for (std::size_t row = 0; row < seeds.size(); ++row)
                        if ((active.empty() || active[row]) && sampled.mComplete[row])
                            bumpRingStat(RingOp::ErrorAdd, legacyRingOpsThreadLocalStats());
                    host.clear();
                    device = std::move(sampled.mValues);
                    co_return true;
                }
            }
            if (strict) co_return false;
        }
#endif
        std::vector<u64> next(seeds.size() * n, 0);
        {
            const bool setupOk = co_await samplePolyErrorCompactBatchFromSeeds(executor, setupResults, next, sigma, clip, seeds, ctx,
                                                     requestedWorkers, active, cpuBenchmark);
            if (!setupOk) co_return false;
        }
        host = std::move(next);
        device.reset();
        co_return true;
    }

    macoro::task<bool> materializePolyErrorCompactBatchForSetup(
        macoro::thread_pool &executor, std::span<u8> setupResults, std::vector<u64> &host,
        const std::shared_ptr<gpu::DeviceScalars> &device, double sigma, double clip,
        std::span<const seal::prng_seed_type> seeds, const RingNttContext &ctx, u32 requestedWorkers,
        std::span<const u8> active, CpuBenchmarkState cpuBenchmark)
    {
        if (setupResults.empty()) co_return false;
        if (!gpu::enabled(ctx)) requestedWorkers = std::max(1u, requestedWorkers);
        if (!cpuBenchmark.mContext) cpuBenchmark.mContext = cpuBenchmarkContext(ctx);
        if (cpuBenchmark.mContext && gpu::enabled(ctx))
        {
            const auto& limits = *cpuBenchmark.mContext;
            const auto capacity = std::max<std::size_t>(1, limits.mWorkerLimit
                ? std::min(limits.mWorkerLimit, limits.mCpus.size()) : limits.mCpus.size());
            setupResults = setupResults.first(std::min(setupResults.size(), capacity));
        }
        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        if (!canSamplePolyErrorCompact(ctx, sigma, clip) || !n ||
            seeds.size() > std::numeric_limits<std::size_t>::max() / n ||
            (!active.empty() && active.size() != seeds.size()))
            co_return false;
        const auto words = seeds.size() * n;
        if (!device && host.size() == words) co_return true;
        if (!gpu::enabled(ctx) && setupResults.size() <
            std::min(std::size_t(requestedWorkers), seeds.size())) co_return false;
        std::vector<u64> next(words, 0);
#if defined(ENABLE_LOGVOLE_CUDA)
        if (device)
        {
            if (device->count() != words) co_return false;
            if (gpu::enabled(ctx) && gpu::fetchScalars(*device, next, gpu::contextStream(ctx)))
            {
                host = std::move(next);
                co_return true;
            }
            // A declined asynchronous fetch must drain before CPU replay can
            // reuse its destination, including copy/sync error exits.
            if (gpu::enabled(ctx)) gpu::contextStream(ctx).sync();
            std::fill(next.begin(), next.end(), 0);
        }
#else
        if (device) co_return false;
#endif
        {
            const auto taskCount = seeds.size();
            auto chunks = setupResults.first(std::min(
                {setupResults.size(), static_cast<std::size_t>(taskCount),
                 static_cast<std::size_t>((requestedWorkers) ? (requestedWorkers) : setupResults.size())}));
            if (taskCount && chunks.empty()) co_return false;
            std::fill(chunks.begin(), chunks.end(), u8{1});
            auto item = [&](std::size_t row, CpuBenchmarkState& cpuBenchmark, PendingRingOpsStats* stats) {
                return (!active.empty() && !active[row]) ||
                       samplePolyErrorCompactFromSeed(std::span<u64>(next).subspan(row * n, n), sigma, clip,
                                                      seeds[row], ctx, stats);
            };
            auto runChunk = [&](std::size_t begin, std::size_t end, u8 &ok) {
                CpuBenchmarkState worker =
                    chunks.size() > 1 ? CpuBenchmarkState{cpuBenchmark.mContext, true} : cpuBenchmark;
                CpuBenchmarkWorkerScope timing(chunks.size() > 1 ? worker.mContext : nullptr);
                CpuBenchmarkTaskScope metrics(worker);
                PendingRingOpsStats pending(gpu::enabled(ctx) ? nullptr : ctx.mExecutionOptions.mRingOpsStats);
                auto* stats = gpu::enabled(ctx) ? legacyRingOpsThreadLocalStats() : &pending;
                struct FlushStats
                {
                    bool legacy;
                    ~FlushStats()
                    {
                        if (legacy) flushRingOpsThreadLocalStats();
                    }
                } flush{gpu::enabled(ctx)};
                for (auto i = begin; i != end; ++i)
                    if (!item(i, worker, stats))
                    {
                        ok = 0;
                        break;
                    }
            };
            if (chunks.size() == 1) runChunk(0, taskCount, chunks[0]);
            else if (taskCount)
            {
                co_await macoro::bulk_chunked(executor, taskCount, chunks, runChunk);
            }
            const bool phaseOk = std::all_of(chunks.begin(), chunks.end(), [](u8 ok) { return ok != 0; });
            if (!phaseOk) co_return false;
        }
        host = std::move(next);
        co_return true;
    }

    // Legacy synchronous replay for lazy GPU host getters. No async caller uses this boundary.
    bool materializePolyErrorCompactBatchForSetupLegacy(
        std::vector<u64>& host, const std::shared_ptr<gpu::DeviceScalars>& device,
        double sigma, double clip, std::span<const seal::prng_seed_type> seeds,
        const RingNttContext& ctx, u32 requestedWorkers, std::span<const u8> active, CpuBenchmarkState cpuBenchmark, detail::CpuRowScratch* cpuSetupScratch)
    {
        detail::CpuRowScratch localSetupScratch;
        auto& setupScratch = cpuSetupScratch ? *cpuSetupScratch : localSetupScratch;
        if (!cpuBenchmark.mContext) cpuBenchmark.mContext = cpuBenchmarkContext(ctx);
        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        if (!canSamplePolyErrorCompact(ctx, sigma, clip) || !n ||
            seeds.size() > std::numeric_limits<std::size_t>::max() / n ||
            (!active.empty() && active.size() != seeds.size())) return false;
        const auto words = seeds.size() * n;
        if (!device && host.size() == words) return true;
        std::vector<u64> next(words, 0);
#if defined(ENABLE_LOGVOLE_CUDA)
        if (device)
        {
            if (device->count() != words) return false;
            if (gpu::enabled(ctx) && gpu::fetchScalars(*device, next, gpu::contextStream(ctx))) { host = std::move(next); return true; }
            // A declined asynchronous fetch must drain before CPU replay can
            // reuse its destination, including copy/sync error exits.
            if (gpu::enabled(ctx)) gpu::contextStream(ctx).sync();
            std::fill(next.begin(), next.end(), 0);
        }
#else
        if (device) return false;
#endif
        if (!setupScratch.runBulkChunked(seeds.size(), requestedWorkers,
            [&](std::size_t begin, std::size_t end, CpuBenchmarkState&) {
                struct FlushStats {
                    bool mEnabled;
                    ~FlushStats() { if (mEnabled) flushRingOpsThreadLocalStats(); }
                } flush{gpu::enabled(ctx)};
                PendingRingOpsStats pending(ctx.mExecutionOptions.mRingOpsStats);
                auto* stats = gpu::enabled(ctx) ? legacyRingOpsThreadLocalStats() :
                    ctx.mExecutionOptions.mRingOpsStats ? &pending : nullptr;
                for (auto row = begin; row != end; ++row)
                    if ((active.empty() || active[row]) &&
                        !samplePolyErrorCompactFromSeed(std::span<u64>(next).subspan(row * n, n),
                            sigma, clip, seeds[row], ctx, stats)) return false;
                return true;
            }, cpuBenchmark)) return false;
        host = std::move(next);
        return true;
    }

    bool expandPolyErrorCompact(
        std::span<const u64> limb0, RnsPoly& out, const RingNttContext& ctx)
    {
        if ((ctx.mGpuLightweight && !validateLightweightRingContext(ctx)) ||
            !ringModulusCount(ctx) || limb0.empty() ||
            ctx.mParams.mCoeffModulusBits.size() != ringModulusCount(ctx) ||
            limb0.size() != ctx.mParams.mPolyModulusDegree) return false;
        const u64 q0 = ringModulusValue(ctx, 0);
        u64 minQ = q0;
        for (std::size_t j = 0; j < ringModulusCount(ctx); ++j)
            minQ = std::min(minQ, ringModulusValue(ctx, j));
        for (u64 value : limb0)
        {
            if (value >= q0) return false;
            const u64 magnitude = value > (q0 >> 1u) ? q0 - value : value;
            if (magnitude >= minQ) return false;
        }
        RnsPoly next;
        next.mCoeffs.resize(ringPolyCoeffCount(ctx.mParams));
        for (std::size_t j = 0; j < ringModulusCount(ctx); ++j)
            for (std::size_t i = 0; i < limb0.size(); ++i)
            {
                const u64 value = limb0[i];
                next.mCoeffs[j * limb0.size() + i] = value > (q0 >> 1u)
                    ? ringModulusValue(ctx, j) - (q0 - value) : value;
            }
        out = std::move(next);
        return true;
    }

    static bool addPolyErrorCanonicalFromSeed(
        RnsPoly& poly,
        double noiseStandardDeviation,
        double noiseMaxDeviation,
        const seal::prng_seed_type& seed,
        const RingNttContext& ctx, PendingRingOpsStats* stats)
    {
        const auto hostContext = getRingHostContext(ctx);
        if (!hostContext || !hostContext->key_context_data()) return false;
        PRNG prng(detail::aesPrngKey(seed));
        AesNormalEngine engine{prng};
        // Apply each sampled error directly. This keeps the coefficient/limb
        // traversal and removes the full-RNS temporary and SEAL TLS pool borrow.
        samplePolyNormal<true>(engine, hostContext->key_context_data()->parms(),
            poly.mCoeffs.data(), noiseStandardDeviation, noiseMaxDeviation);

        bumpRingStat(RingOp::ErrorAdd, stats);
        return true;
    }

    bool addPolyError(
        RnsPoly& poly,
        double noiseStandardDeviation,
        double noiseMaxDeviation,
        PRNG& prng,
        const RingNttContext& ctx, PendingRingOpsStats* stats)
    {
        const auto hostContext = getRingHostContext(ctx);
        if (noiseStandardDeviation < 0 || !canonicalizePoly(poly, ctx) ||
            !hostContext || !hostContext->key_context_data())
        {
            return false;
        }
        return addPolyErrorCanonicalFromSeed(
            poly, noiseStandardDeviation, noiseMaxDeviation, sealSeedFromPrng(prng), ctx, stats);
    }

    bool addPolyErrorFromSeed(
        RnsPoly& poly,
        double noiseStandardDeviation,
        double noiseMaxDeviation,
        const seal::prng_seed_type& seed,
        const RingNttContext& ctx, PendingRingOpsStats* stats)
    {
        const auto hostContext = getRingHostContext(ctx);
        if (noiseStandardDeviation < 0 || !canonicalizePoly(poly, ctx) ||
            !hostContext || !hostContext->key_context_data())
        {
            return false;
        }
        return addPolyErrorCanonicalFromSeed(poly, noiseStandardDeviation, noiseMaxDeviation, seed, ctx, stats);
    }
}

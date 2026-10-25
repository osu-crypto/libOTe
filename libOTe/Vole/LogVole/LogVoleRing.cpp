#include "libOTe/Vole/LogVole/LogVoleRing.h"

// config.h defines ENABLE_LOGVOLE_CUDA and is not pulled in by LogVoleRing.h,
// so it has to precede the guard below or the GPU path silently compiles away.
#include "libOTe/config.h"
#include "libOTe/Vole/LogVole/LogVoleArithmetic.h"
#include "libOTe/Vole/LogVole/LogVoleCpuArithmetic.h"
#include "libOTe/Vole/LogVole/LogVoleCpuSampler.h"
#include "libOTe/Vole/LogVole/LogVoleParallel.h"
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

        class BufferedNormalEngine
        {
        public:
            using result_type = seal::RandomToStandardAdapter::result_type;
            explicit BufferedNormalEngine(std::shared_ptr<seal::UniformRandomGenerator> source)
                : mSource(std::move(source)) {}
            ~BufferedNormalEngine() { seal::util::seal_memzero(mBuffer.data(), sizeof(mBuffer)); }
            static constexpr result_type min() { return std::numeric_limits<result_type>::min(); }
            static constexpr result_type max() { return std::numeric_limits<result_type>::max(); }
            result_type operator()()
            {
                if (mNext == mBuffer.size())
                {
                    mSource->generate(sizeof(mBuffer), reinterpret_cast<seal::seal_byte*>(mBuffer.data()));
                    mNext = 0;
                }
                return mBuffer[mNext++];
            }
        private:
            std::shared_ptr<seal::UniformRandomGenerator> mSource;
            std::array<result_type, 1024> mBuffer;
            std::size_t mNext = mBuffer.size();
        };

        void samplePolyNormal(
            std::shared_ptr<seal::UniformRandomGenerator> prng,
            const seal::EncryptionParameters& parms,
            u64* destination,
            double noiseStandardDeviation,
            double noiseMaxDeviation,
            bool firstLimbOnly = false)
        {
            auto& coeffModulus = parms.coeff_modulus();
            const std::size_t coeffModulusSize = firstLimbOnly ? 1u : coeffModulus.size();
            const std::size_t coeffCount = parms.poly_modulus_degree();

            auto sample = [&](auto& engine) {
                seal::util::ClippedNormalDistribution dist(0, noiseStandardDeviation, noiseMaxDeviation);

                SEAL_ITERATE(seal::util::iter(destination), coeffCount, [&](auto& I) {
                    const i64 noise = static_cast<i64>(dist(engine));
                    const u64 flag = static_cast<u64>(-static_cast<i64>(noise < 0));
                    SEAL_ITERATE(
                        seal::util::iter(seal::util::StrideIter<u64*>(&I, coeffCount), coeffModulus),
                        coeffModulusSize,
                        [&](auto J) {
                            *::std::get<0>(J) = static_cast<u64>(noise) + (flag & ::std::get<1>(J).value());
                        });
                });
            };
            static const bool buffered = [] {
                const char* value = std::getenv("LV_CPU_BUFFERED_ERROR");
                return !value || value[0] != '0';
            }();
            if (buffered)
            {
                // This PRNG is local to one error polynomial. Buffering keeps
                // the same u32 sequence and distribution, and avoids a mutex
                // acquisition for every four random bytes. Unused tail bytes
                // are discarded with this local PRNG, never the parent PRNG.
                BufferedNormalEngine engine(prng);
                sample(engine);
            }
            else
            {
                seal::RandomToStandardAdapter engine(prng);
                sample(engine);
            }
        }

        std::shared_ptr<seal::UniformRandomGeneratorFactory> polySamplingPrngFactory()
        {
#ifdef SEAL_USE_AES_CTR_DRBG
            static const auto factory = std::make_shared<seal::AesCtrDrbgPRNGFactory>();
#else
            static const auto factory = detail::cpuDefaultPrngFactory();
#endif
            return factory;
        }

        seal::prng_seed_type sealSeedFromPrng(PRNG& prng)
        {
            seal::prng_seed_type seed{};
            prng.get(seed.data(), seed.size());
            return seed;
        }

        seal::prng_seed_type sealSeedFromBlock(block seedBlock)
        {
            PRNG prng(seedBlock);
            return sealSeedFromPrng(prng);
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

        struct PendingRingOpsStats
        {
            u64 mEpoch = 0;
            bool mEpochInitialized = false;
            u64 mNttCount = 0;
            u64 mInttCount = 0;
            u64 mAddCount = 0;
            u64 mSubCount = 0;
            u64 mMulCount = 0;
            u64 mMulScalarCount = 0;
            u64 mDyadicMulAddCount = 0;
            u64 mGadgetDecomposeCount = 0;
            u64 mGadgetRecomposeCount = 0;
            u64 mPrngPolyCount = 0;
            u64 mErrorAddCount = 0;

            void clear()
            {
                mNttCount = 0;
                mInttCount = 0;
                mAddCount = 0;
                mSubCount = 0;
                mMulCount = 0;
                mMulScalarCount = 0;
                mDyadicMulAddCount = 0;
                mGadgetDecomposeCount = 0;
                mGadgetRecomposeCount = 0;
                mPrngPolyCount = 0;
                mErrorAddCount = 0;
            }

            void syncEpoch()
            {
                const u64 globalEpoch = RingOpsStats::resetEpoch.load(std::memory_order_relaxed);
                if (!mEpochInitialized)
                {
                    mEpoch = globalEpoch;
                    mEpochInitialized = true;
                    return;
                }

                if (mEpoch != globalEpoch)
                {
                    clear();
                    mEpoch = globalEpoch;
                }
            }

            void flush()
            {
                if (mNttCount)
                {
                    globalRingOpsStats.mNttCount.fetch_add(mNttCount, std::memory_order_relaxed);
                    mNttCount = 0;
                }
                if (mInttCount)
                {
                    globalRingOpsStats.mInttCount.fetch_add(mInttCount, std::memory_order_relaxed);
                    mInttCount = 0;
                }
                if (mAddCount)
                {
                    globalRingOpsStats.mAddCount.fetch_add(mAddCount, std::memory_order_relaxed);
                    mAddCount = 0;
                }
                if (mSubCount)
                {
                    globalRingOpsStats.mSubCount.fetch_add(mSubCount, std::memory_order_relaxed);
                    mSubCount = 0;
                }
                if (mMulCount)
                {
                    globalRingOpsStats.mMulCount.fetch_add(mMulCount, std::memory_order_relaxed);
                    mMulCount = 0;
                }
                if (mMulScalarCount)
                {
                    globalRingOpsStats.mMulScalarCount.fetch_add(mMulScalarCount, std::memory_order_relaxed);
                    mMulScalarCount = 0;
                }
                if (mDyadicMulAddCount)
                {
                    globalRingOpsStats.mDyadicMulAddCount.fetch_add(mDyadicMulAddCount, std::memory_order_relaxed);
                    mDyadicMulAddCount = 0;
                }
                if (mGadgetDecomposeCount)
                {
                    globalRingOpsStats.mGadgetDecomposeCount.fetch_add(mGadgetDecomposeCount, std::memory_order_relaxed);
                    mGadgetDecomposeCount = 0;
                }
                if (mGadgetRecomposeCount)
                {
                    globalRingOpsStats.mGadgetRecomposeCount.fetch_add(mGadgetRecomposeCount, std::memory_order_relaxed);
                    mGadgetRecomposeCount = 0;
                }
                if (mPrngPolyCount)
                {
                    globalRingOpsStats.mPrngPolyCount.fetch_add(mPrngPolyCount, std::memory_order_relaxed);
                    mPrngPolyCount = 0;
                }
                if (mErrorAddCount)
                {
                    globalRingOpsStats.mErrorAddCount.fetch_add(mErrorAddCount, std::memory_order_relaxed);
                    mErrorAddCount = 0;
                }
            }

            ~PendingRingOpsStats()
            {
                flush();
            }
        };

        thread_local PendingRingOpsStats tlsRingOpsStats{};

        void bumpRingStat(std::atomic<u64>& global, u64& local)
        {
            constexpr u64 flushThreshold = 256;
            tlsRingOpsStats.syncEpoch();
            ++local;
            if (local >= flushThreshold)
            {
                global.fetch_add(local, std::memory_order_relaxed);
                local = 0;
            }
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

            if (startLevel == 1 && levels == 1 && detail::cpuCenteredHighDigit(
                canonical.mCoeffs.data(), out[0].mCoeffs.data(), n, digitBits,
                *contextData->rns_tool()->base_q())) return true;

            // All scratch dies on this thread before return. A private SEAL
            // pool avoids contention between independent shrink chunks.
            auto pool = seal::MemoryPoolHandle::ThreadLocal();
            seal::util::Pointer<u64> composedPoly =
                seal::util::allocate_poly(n, coeffModCount, pool);
            const auto& baseQ = *contextData->rns_tool()->base_q();
            if (!detail::cpuComposeRns(canonical.mCoeffs.data(), composedPoly.get(), n, baseQ))
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
        mNttCount.store(0, std::memory_order_relaxed);
        mInttCount.store(0, std::memory_order_relaxed);
        mAddCount.store(0, std::memory_order_relaxed);
        mSubCount.store(0, std::memory_order_relaxed);
        mMulCount.store(0, std::memory_order_relaxed);
        mMulScalarCount.store(0, std::memory_order_relaxed);
        mDyadicMulAddCount.store(0, std::memory_order_relaxed);
        mGadgetDecomposeCount.store(0, std::memory_order_relaxed);
        mGadgetRecomposeCount.store(0, std::memory_order_relaxed);
        mPrngPolyCount.store(0, std::memory_order_relaxed);
        mErrorAddCount.store(0, std::memory_order_relaxed);
        resetEpoch.fetch_add(1, std::memory_order_relaxed);
    }

    void flushRingOpsThreadLocalStats()
    {
        tlsRingOpsStats.syncEpoch();
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

    AutoTimer::AutoTimer(std::atomic<u64>& stat)
        : mStat(stat),
          mStart(std::chrono::steady_clock::now())
    {}

    AutoTimer::~AutoTimer()
    {
        const auto end = std::chrono::steady_clock::now();
        mStat.fetch_add(
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
                ctx.mHostContextCache->mParams != ctx.mParams) return false;
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
            unordered_map<RingContextCacheKey, std::shared_ptr<const RingNttContext>, RingContextCacheKeyHash>;

        // Never destroyed, on purpose: the cached RingNttContext owns a
        // seal::SEALContext whose allocations come from SEAL's global memory
        // pool, and there is no static-destruction ordering guarantee between
        // the two. Releasing after the pool is gone aborts inside
        // MemoryPoolHeadMT::~MemoryPoolHeadMT.
        RingContextCache& ringContextCache()
        {
            static RingContextCache* cache = new RingContextCache();
            return *cache;
        }
        std::mutex ringContextCacheMutex;

        bool makeRingNttContextUncached(const RingParams& params, bool expandModChain, RingNttContext& out);
    }

    static bool makeRingNttContextCached(const RingParams& params, RingNttContext& out, bool lightweight)
    {
        if (!validateRingParams(params))
        {
            return false;
        }

        RingContextCacheKey key{};
        key.mDegree = params.mPolyModulusDegree;
        key.mBits.assign(params.mCoeffModulusBits.begin(), params.mCoeffModulusBits.end());
        key.mRole = currentProtocolCacheScope().mRole;
        key.mGpuLightweight = lightweight;
#if defined(ENABLE_LOGVOLE_CUDA)
        const char* fullChain = std::getenv("LV_GPU_SETUP_FULL_MOD_CHAIN");
        key.mExpandModChain = !gpu::enabled() || (fullChain && fullChain[0] == '1');
        key.mNativeSealBundleRequested = lightweight && !key.mExpandModChain &&
            gpu::dynamicSealSetupSupported(params) &&
            gpu::nativeSealBundleCacheRequested();
#endif

        {
            std::lock_guard<std::mutex> lock(ringContextCacheMutex);
            auto it = ringContextCache().find(key);
            if (it != ringContextCache().end())
            {
                out = *it->second;
                return true;
            }
        }

        RingNttContext built{};
        if (lightweight)
        {
            HostStep contextStep("setup: lightweight ring context");
            const auto primes = productionRingModuli(params);
            built.mParams = params;
            auto metadata = std::make_shared<RingModulusMetadata>();
            if (!primes.empty()) metadata->mValues.assign(primes.begin(), primes.end());
            else
            {
#if defined(ENABLE_LOGVOLE_CUDA)
                if (!gpu::selectSealCoeffModuliDevice(params, metadata->mValues)) return false;
                metadata->mDynamicGpuCertificate =
                    gpu::GpuRing::getRaw(params, metadata->mValues);
                if (!metadata->mDynamicGpuCertificate) return false;
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
        else if (!makeRingNttContextUncached(params, key.mExpandModChain, built))
        {
            return false;
        }

        auto shared = std::make_shared<const RingNttContext>(built);
        {
            std::lock_guard<std::mutex> lock(ringContextCacheMutex);
            auto [it, inserted] = ringContextCache().emplace(std::move(key), shared);
            (void)inserted;
            out = *it->second;
        }
        return true;
    }

    bool makeRingNttContext(const RingParams& params, RingNttContext& out)
    {
        bool lightweight = false;
#if defined(ENABLE_LOGVOLE_CUDA)
        const char* setting = std::getenv("LV_GPU_SETUP_LIGHTWEIGHT_RING");
        const char* fullChain = std::getenv("LV_GPU_SETUP_FULL_MOD_CHAIN");
        lightweight = gpu::enabled() && (!setting || setting[0] != '0') &&
            (!fullChain || fullChain[0] != '1') &&
            (!productionRingModuli(params).empty() ||
                (gpu::dynamicSealSetupSupported(params) && gpu::currentDeviceOrdinal() == 0));
#endif
        return makeRingNttContextCached(params, out, lightweight);
    }

    bool makeGpuRingNttContext(const RingParams& params, RingNttContext& out)
    {
        if (productionRingModuli(params).empty())
        {
#if defined(ENABLE_LOGVOLE_CUDA)
            if (!gpu::enabled() || gpu::currentDeviceOrdinal() != 0 ||
                !gpu::dynamicSealSetupSupported(params)) return false;
#else
            return false;
#endif
        }
        return makeRingNttContextCached(params, out, true);
    }

    bool makeNativeGpuRingNttContextFromCertificate(
        const RingParams& params, std::span<const u64> orderedPrimes,
        std::shared_ptr<gpu::GpuRing> certificate, RingNttContext& out)
    {
#if defined(ENABLE_LOGVOLE_CUDA)
        if (!validateRingParams(params) ||
            !gpu::dynamicSealSetupSupported(params) ||
            !certificate ||
            certificate->rawOwnerRole() != currentProtocolCacheScope().mRole ||
            certificate->n() != params.mPolyModulusDegree ||
            certificate->rho() != orderedPrimes.size() ||
            certificate->hostModuli().size() != orderedPrimes.size() ||
            !std::equal(orderedPrimes.begin(), orderedPrimes.end(),
                certificate->hostModuli().begin()))
            return false;
        RingNttContext built{};
        built.mParams = params;
        auto metadata = std::make_shared<RingModulusMetadata>();
        metadata->mValues.assign(orderedPrimes.begin(), orderedPrimes.end());
        metadata->mBitCounts.assign(params.mCoeffModulusBits.begin(),
            params.mCoeffModulusBits.end());
        metadata->mDynamicGpuCertificate = std::move(certificate);
        built.mRawModuli = std::move(metadata);
        built.mGpuLightweight = true;
        built.mHostContextCache = std::make_shared<RingHostContextCache>();
        built.mHostContextCache->mParams = params;
        built.mHostContextCache->mRawModuli = built.mRawModuli;
        built.mHostContextCache->mRole = currentProtocolCacheScope().mRole;
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

    bool publishNativeGpuRingNttContext(const RingNttContext& ready)
    {
#if defined(ENABLE_LOGVOLE_CUDA)
        HostStep publicationStep("setup: native ring context publication");
        const auto owner = currentProtocolCacheScope();
        if (!gpu::nativeSealBundleCacheRequested() ||
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
            auto shared = std::make_shared<const RingNttContext>(ready);
            std::lock_guard<std::mutex> lock(ringContextCacheMutex);
            if (auto it = ringContextCache().find(key);
                it != ringContextCache().end())
            {
                // The static lightweight context can have been cached by a
                // standalone budget check before the combined GPU factory.
                // Prior users retain that immutable context through shared_ptr.
                it->second = std::move(shared);
                return true;
            }
            ringContextCache().emplace(std::move(key), std::move(shared));
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
                HostStep fallbackStep("setup: ring host fallback materialization");
                std::vector<seal::Modulus> moduli;
                moduli.reserve(cache.mRawModuli->mValues.size());
                for (u64 prime : cache.mRawModuli->mValues) moduli.emplace_back(prime);
                seal::EncryptionParameters parms(seal::scheme_type::ckks);
                parms.set_poly_modulus_degree(cache.mParams.mPolyModulusDegree);
                parms.set_coeff_modulus(moduli);
                parms.set_random_generator(polySamplingPrngFactory());
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

    const std::vector<seal::Modulus>& getRingHostModuli(const RingNttContext& ctx)
    {
        if (!ctx.mGpuLightweight) return ctx.mModuli;
        const auto host = getRingHostContext(ctx);
        if (host && host->key_context_data()) return host->key_context_data()->parms().coeff_modulus();
        static const std::vector<seal::Modulus> empty;
        return empty;
    }

    namespace
    {
    bool makeRingNttContextUncached(const RingParams& params, bool expandModChain, RingNttContext& out)
    {
        HostStep contextStep("setup: ring context build");
        if (!validateRingParams(params))
        {
            return false;
        }

        std::vector<seal::Modulus> moduli;
        try
        {
            HostStep primesStep("setup: ring modulus generation");
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
        parms.set_random_generator(polySamplingPrngFactory());

        RingNttContext next{};
        next.mParams = params;
        next.mModuli = std::move(moduli);
        {
            HostStep sealStep("setup: ring SEAL context");
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
            if (!detail::cpuReduceMod(coeffs, coeffs, n, moduli[j]))
                seal::util::modulo_poly_coeffs(coeffs, n, moduli[j], coeffs);
        }
        return true;
    }

    static bool forwardNttImpl(RnsPoly& poly, const RingNttContext& ctx, bool reduceInput)
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

        bumpRingStat(globalRingOpsStats.mNttCount, tlsRingOpsStats.mNttCount);
        return true;
    }

    bool forwardNtt(RnsPoly& poly, const RingNttContext& ctx)
    {
        return forwardNttImpl(poly, ctx, true);
    }

    bool forwardNttCanonical(RnsPoly& poly, const RingNttContext& ctx)
    {
        static const bool enabled = [] {
            const char* value = std::getenv("LV_CPU_SKIP_REDUNDANT_REDUCE");
            return !value || value[0] != '0';
        }();
        return forwardNttImpl(poly, ctx, !enabled);
    }

    bool inverseNtt(RnsPoly& poly, const RingNttContext& ctx)
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

        bumpRingStat(globalRingOpsStats.mInttCount, tlsRingOpsStats.mInttCount);
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

    bool forwardNttBatch(std::span<RnsPoly> polys, const RingNttContext& ctx)
    {
        if (polys.empty()) return true;
        // Validate the complete batch before a transform or reduction changes
        // any input; a declined device attempt must remain safe to replay.
        if (ctx.mGpuLightweight ? !validateLightweightRingContext(ctx) :
            (!ctx.mContext || !ctx.mContext->key_context_data())) return false;
        for (const auto& poly : polys)
            if (!validateShapeAgainstContext(poly, ctx)) return false;
#if defined(ENABLE_LOGVOLE_CUDA)
        const char* canonicalizeSetting = std::getenv("LV_GPU_SETUP_NTT_CANONICALIZE");
        const bool deviceCanonicalize = (ctx.mGpuLightweight || polys.size() >= kNttBatchGpuThreshold) && gpu::enabled() &&
            (!canonicalizeSetting || canonicalizeSetting[0] != '0');
        if (deviceCanonicalize)
        {
            if (gpu::nttHostBatch(ctx, polys, false, true))
            {
                for (std::size_t i = 0; i < polys.size(); ++i)
                    bumpRingStat(globalRingOpsStats.mNttCount, tlsRingOpsStats.mNttCount);
                return true;
            }
            const char* strict = std::getenv("LV_GPU_SETUP_NTT_CANONICALIZE_STRICT");
            if (strict && strict[0] != '0') return false;
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
                bumpRingStat(globalRingOpsStats.mNttCount, tlsRingOpsStats.mNttCount);
            }
            return true;
        }
#endif
        for (auto& poly : polys)
        {
            if (!forwardNttCanonical(poly, ctx)) return false;
        }
        return true;
    }

    bool inverseNttBatch(std::span<RnsPoly> polys, const RingNttContext& ctx)
    {
        if (polys.empty()) return true;
        if (ctx.mGpuLightweight ? !validateLightweightRingContext(ctx) :
            (!ctx.mContext || !ctx.mContext->key_context_data())) return false;
        for (const auto& poly : polys)
            if (!validateShapeAgainstContext(poly, ctx)) return false;
#if defined(ENABLE_LOGVOLE_CUDA)
        if (ctx.mGpuLightweight || polys.size() >= kNttBatchGpuThreshold)
        {
            const char* canonicalizeSetting = std::getenv("LV_GPU_SETUP_NTT_CANONICALIZE");
            const bool deviceCanonicalize = gpu::enabled() &&
                (!canonicalizeSetting || canonicalizeSetting[0] != '0');
            if (gpu::nttHostBatch(ctx, polys, true, deviceCanonicalize))
            {
                for (auto& poly : polys)
                {
                    bumpRingStat(globalRingOpsStats.mInttCount, tlsRingOpsStats.mInttCount);
                    if (!deviceCanonicalize && !canonicalizePoly(poly, ctx)) return false;
                }
                return true;
            }
            const char* strict = std::getenv("LV_GPU_SETUP_NTT_CANONICALIZE_STRICT");
            if (deviceCanonicalize && strict && strict[0] != '0') return false;
        }
#endif
        for (auto& poly : polys)
        {
            if (!inverseNtt(poly, ctx)) return false;
        }
        return true;
    }

    bool dyadicMultiplyAddNtt(
        const RnsPoly& aNtt,
        const RnsPoly& bNtt,
        const RnsPoly& cNtt,
        const RingNttContext& ctx,
        RnsPoly& out)
    {
        out = cNtt;
        return dyadicMultiplyAddNttInplace(aNtt, bNtt, out, ctx);
    }

    bool dyadicMultiplyAddNttInplace(const RnsPoly& aNtt, const RnsPoly& bNtt, RnsPoly& cNtt, const RingNttContext& ctx)
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
            if (detail::cpuDyadicMultiplyAdd(aNtt.mCoeffs.data() + offset,
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

        bumpRingStat(globalRingOpsStats.mDyadicMulAddCount, tlsRingOpsStats.mDyadicMulAddCount);
        return true;
    }

    bool dyadicInnerProductNttInplace(
        std::span<const RnsPoly* const> left, std::span<const RnsPoly* const> right,
        RnsPoly& accumulator, const RingNttContext& ctx)
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
            if (detail::cpuDyadicInnerProduct(a, b, terms, c, n, modulus)) continue;
            for (std::size_t t = 0; t < terms; ++t)
                if (!detail::cpuDyadicMultiplyAdd(a[t], b[t], c, n, modulus))
                    for (std::size_t i = 0; i < n; ++i)
                        c[i] = mulAddMod(reduceU64(a[t][i], modulus), reduceU64(b[t][i], modulus),
                            reduceU64(c[i], modulus), modulus);
        }
        for (std::size_t t = 0; t < left.size(); ++t)
            bumpRingStat(globalRingOpsStats.mDyadicMulAddCount, tlsRingOpsStats.mDyadicMulAddCount);
        return true;
    }

    bool ringAddInplace(RnsPoly& a, const RnsPoly& b, const RingNttContext& ctx)
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
        seal::util::add_poly_coeffmod(aIter[0], bIter[0], moduli.size(), moduli, aIter[0]);
        bumpRingStat(globalRingOpsStats.mAddCount, tlsRingOpsStats.mAddCount);
        return true;
    }

    bool ringAdd(const RnsPoly& a, const RnsPoly& b, const RingNttContext& ctx, RnsPoly& out)
    {
        out = a;
        return ringAddInplace(out, b, ctx);
    }

    bool ringSubInplace(RnsPoly& a, const RnsPoly& b, const RingNttContext& ctx)
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
        seal::util::sub_poly_coeffmod(aIter[0], bIter[0], moduli.size(), moduli, aIter[0]);
        bumpRingStat(globalRingOpsStats.mSubCount, tlsRingOpsStats.mSubCount);
        return true;
    }

    bool ringSub(const RnsPoly& a, const RnsPoly& b, const RingNttContext& ctx, RnsPoly& out)
    {
        out = a;
        return ringSubInplace(out, b, ctx);
    }

    bool ringMultiplyInplace(RnsPoly& a, const RnsPoly& b, const RingNttContext& ctx)
    {
        if (!validateShapeAgainstContext(a, ctx) || !validateShapeAgainstContext(b, ctx))
        {
            return false;
        }

        RnsPoly aNtt = a;
        RnsPoly bNtt = b;
        RnsPoly zero{};
        resizeZero(zero.mCoeffs, a.mCoeffs.size());
        if (!forwardNtt(aNtt, ctx) || !forwardNtt(bNtt, ctx) ||
            !dyadicMultiplyAddNtt(aNtt, bNtt, zero, ctx, a) ||
            !inverseNtt(a, ctx))
        {
            return false;
        }

        bumpRingStat(globalRingOpsStats.mMulCount, tlsRingOpsStats.mMulCount);
        return true;
    }

    bool ringMultiply(const RnsPoly& a, const RnsPoly& b, const RingNttContext& ctx, RnsPoly& out)
    {
        out = a;
        return ringMultiplyInplace(out, b, ctx);
    }

    bool ringMultiplyScalarInplace(RnsPoly& a, u64 scalar, const RingNttContext& ctx)
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

        bumpRingStat(globalRingOpsStats.mMulScalarCount, tlsRingOpsStats.mMulScalarCount);
        return true;
    }

    bool ringMultiplyScalar(const RnsPoly& a, u64 scalar, const RingNttContext& ctx, RnsPoly& out)
    {
        out = a;
        return ringMultiplyScalarInplace(out, scalar, ctx);
    }

    bool gadgetDecompose(const RnsPoly& poly, u32 base, u32 tau, const RingNttContext& ctx, std::vector<RnsPoly>& out)
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

        bumpRingStat(globalRingOpsStats.mGadgetDecomposeCount, tlsRingOpsStats.mGadgetDecomposeCount);
        return true;
    }

    bool gadgetRecompose(const std::vector<RnsPoly>& digits, u32 base, const RingNttContext& ctx, RnsPoly& out)
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

        bumpRingStat(globalRingOpsStats.mGadgetRecomposeCount, tlsRingOpsStats.mGadgetRecomposeCount);
        return true;
    }

    bool gadgetDecomposeBitsRange(
        const RnsPoly& poly,
        u32 digitBits,
        u32 startLevel,
        u32 levels,
        const RingNttContext& ctx,
        std::vector<RnsPoly>& out,
        u32)
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
        if (startLevel == 0 && levels == 1 && detail::cpuLowDigitRns(
            canonical.mCoeffs.data(), out[0].mCoeffs.data(), n, digitBits, baseQ))
        {
            bumpRingStat(globalRingOpsStats.mGadgetDecomposeCount, tlsRingOpsStats.mGadgetDecomposeCount);
            return true;
        }
        auto pool = seal::MemoryPoolHandle::ThreadLocal();
        seal::util::Pointer<u64> composedPoly =
            seal::util::allocate_poly(n, coeffModCount, pool);
        if (!detail::cpuComposeRns(canonical.mCoeffs.data(), composedPoly.get(), n, baseQ))
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

        bumpRingStat(globalRingOpsStats.mGadgetDecomposeCount, tlsRingOpsStats.mGadgetDecomposeCount);
        return true;
    }

    bool gadgetDecomposeBits(
        const RnsPoly& poly,
        u32 digitBits,
        u32 levels,
        const RingNttContext& ctx,
        std::vector<RnsPoly>& out,
        u32 requestedWorkers)
    {
        return gadgetDecomposeBitsRange(poly, digitBits, 0, levels, ctx, out, requestedWorkers);
    }

    bool gadgetDecomposeBitsRangeCentered(
        const RnsPoly& poly,
        u32 digitBits,
        u32 startLevel,
        u32 levels,
        const RingNttContext& ctx,
        std::vector<RnsPoly>& out,
        u32)
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
            bumpRingStat(globalRingOpsStats.mGadgetDecomposeCount, tlsRingOpsStats.mGadgetDecomposeCount);
            return true;
        }
#endif
        const bool ok = centeredDecomposeSlow(canonical, digitBits, startLevel, levels, ctx, out);
        if (ok)
        {
            bumpRingStat(globalRingOpsStats.mGadgetDecomposeCount, tlsRingOpsStats.mGadgetDecomposeCount);
        }
        return ok;
    }

    bool gadgetRecomposeBits(const std::vector<RnsPoly>& digits, u32 digitBits, const RingNttContext& ctx, RnsPoly& out)
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

        bumpRingStat(globalRingOpsStats.mGadgetRecomposeCount, tlsRingOpsStats.mGadgetRecomposeCount);
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
        const RingNttContext& ctx, block seed, u64 domainTag, u32 index, RnsPoly& out)
    {
        AutoTimer totalSamplingTimer(globalTimingStats.mSeedSamplingTimeUs);
        AutoTimer polySamplingTimer(globalTimingStats.mPolySamplingTimeUs);

        // Every coefficient is overwritten by the sampler. Retain the backing
        // allocation when resampling an existing polynomial.
        out.mCoeffs.resize(ringPolyCoeffCount(ctx.mParams));
        const block polySeed = deriveUniformPolySeed(ctx, seed, domainTag, index);

        const auto hostContext = getRingHostContext(ctx);
        auto contextData = hostContext ? hostContext->key_context_data() : nullptr;
        if (contextData)
        {
            auto prng = polySamplingPrngFactory()->create(sealSeedFromBlock(polySeed));
            detail::cpuSamplePolyUniform(prng, contextData->parms(), out.mCoeffs.data());
            bumpRingStat(globalRingOpsStats.mPrngPolyCount, tlsRingOpsStats.mPrngPolyCount);
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
        bumpRingStat(globalRingOpsStats.mPrngPolyCount, tlsRingOpsStats.mPrngPolyCount);
    }

    RnsPoly deriveUniformPolyFromSeed(const RingNttContext& ctx, block seed, u64 domainTag, u32 index)
    {
        RnsPoly out{};
        deriveUniformPolyFromSeedInplace(ctx, seed, domainTag, index, out);
        return out;
    }

    RnsPoly deriveUniformPolyFromSeedNtt(const RingNttContext& ctx, block seed, u64 domainTag, u32 index)
    {
        RnsPoly out = deriveUniformPolyFromSeed(ctx, seed, domainTag, index);
        (void)forwardNttCanonical(out, ctx);
        return out;
    }

    RnsPoly sampleUniformPolyFromSeed(
        const RingNttContext& ctx, const std::array<u64, 8>& seed)
    {
        RnsPoly out{};
        const auto hostContext = getRingHostContext(ctx);
        const auto data = hostContext ? hostContext->key_context_data() : nullptr;
        if (!data && ctx.mGpuLightweight)
            throw std::runtime_error("lightweight ring uniform sampler could not materialize its exact host context");
        if (!data) return out;
        resizeZero(out.mCoeffs, ringPolyCoeffCount(ctx.mParams));
        auto source = polySamplingPrngFactory()->create(seed);
        detail::cpuSamplePolyUniform(source, data->parms(), out.mCoeffs.data());
        bumpRingStat(globalRingOpsStats.mPrngPolyCount, tlsRingOpsStats.mPrngPolyCount);
        return out;
    }

#if defined(ENABLE_LOGVOLE_CUDA)
    static bool useDeviceUniformSetup(const RingNttContext& ctx)
    {
        if (!gpu::enabled()) return false;
        const bool available = gpu::setupUniformSamplingEnabled() &&
            (ctx.mGpuLightweight ? validateLightweightRingContext(ctx) :
                (ctx.mContext && ctx.mContext->key_context_data()));
        const char* requested = std::getenv("LV_GPU_SETUP_UNIFORM_DEVICE");
        const char* strict = std::getenv("LV_GPU_SETUP_UNIFORM_DEVICE_STRICT");
        if (!available && (!requested || requested[0] != '0') && strict && strict[0] == '1')
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
            std::call_once(mOnce, [&] {
                HostStep step("setup sender: top sk1 exact seed replay");
                std::vector<RnsPoly> next(mSeeds.size());
                for (std::size_t row = 0; row < mSeeds.size(); ++row)
                    next[row] = sampleUniformPolyFromSeed(mCtx, mSeeds[row]);
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
        std::shared_ptr<const gpu::RetainedPublicUniform>* captured = nullptr)
    {
        std::vector<RnsPoly> out;
        if (gpu::sampleUniformBatchFromSeedsDevice(ctx, seeds, actualNtt, out, captured) &&
            out.size() == seeds.size())
        {
            for (std::size_t i = 0; i < seeds.size(); ++i)
            {
                bumpRingStat(globalRingOpsStats.mPrngPolyCount, tlsRingOpsStats.mPrngPolyCount);
                if (actualNtt)
                    bumpRingStat(globalRingOpsStats.mNttCount, tlsRingOpsStats.mNttCount);
            }
            return out;
        }
        const char* strict = std::getenv("LV_GPU_SETUP_UNIFORM_DEVICE_STRICT");
        if (strict && strict[0] == '1')
            throw std::runtime_error("setup uniform device sampler failed");
        if (captured) captured->reset();
        // The parent stream has already advanced. Replay precisely those SEAL
        // seeds, including after an allocation or device launch failure.
        out.resize(seeds.size());
        for (std::size_t i = 0; i < seeds.size(); ++i)
        {
            out[i] = sampleUniformPolyFromSeed(ctx, seeds[i]);
            if (actualNtt) (void)forwardNttCanonical(out[i], ctx);
        }
        return out;
    }
#endif

    RnsPoly sampleUniformPoly(const RingNttContext& ctx, PRNG& prng)
    {
        const auto hostContext = getRingHostContext(ctx);
        auto contextData = hostContext ? hostContext->key_context_data() : nullptr;
        if (contextData)
        {
            return sampleUniformPolyFromSeed(ctx, sealSeedFromPrng(prng));
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
        bumpRingStat(globalRingOpsStats.mPrngPolyCount, tlsRingOpsStats.mPrngPolyCount);
        return out;
    }

    RnsPoly sampleUniformPolyNtt(const RingNttContext& ctx, PRNG& prng)
    {
        RnsPoly out = sampleUniformPoly(ctx, prng);
        (void)forwardNttCanonical(out, ctx);
        return out;
    }

    std::vector<RnsPoly> sampleUniformPolyBatch(const RingNttContext& ctx, u32 count, PRNG& prng)
    {
        if (count == 0) return {};
#if defined(ENABLE_LOGVOLE_CUDA)
        if (useDeviceUniformSetup(ctx))
        {
            std::vector<std::array<u64, 8>> seeds(count);
            // Separate scalar-sized draws preserve PRNG refill behavior even
            // when a caller uses a non-default, very small AES buffer.
            for (u32 i = 0; i < count; ++i) seeds[i] = sealSeedFromPrng(prng);
            return sampleUniformSetupSeeds(ctx, seeds, false);
        }
#endif
        std::vector<RnsPoly> out(count);
        for (u32 i = 0; i < count; ++i) out[i] = sampleUniformPoly(ctx, prng);
        return out;
    }

    bool sampleTopSecretUniformBatch(const RingNttContext& ctx, u32 count,
        PRNG& prng, std::vector<RnsPoly>& eager,
        std::shared_ptr<gpu::DeviceBatch>& resident,
        std::shared_ptr<const LazyRootSecretHostState>& lazy)
    {
        if (!count) return false;
#if defined(ENABLE_LOGVOLE_CUDA)
        const char* option = std::getenv("LV_GPU_SETUP_TOP_SK1_DEVICE");
        const char* strictOption = std::getenv("LV_GPU_SETUP_TOP_SK1_DEVICE_STRICT");
        const bool requested = gpu::enabled() &&
            currentProtocolCacheScope().mRole == ProtocolCacheRole::Sender &&
            currentProtocolCacheScope().mRunId &&
            (!option || option[0] != '0');
        const bool strict = requested && strictOption && strictOption[0] != '0';
        if (requested && useDeviceUniformSetup(ctx))
        {
            std::vector<seal::prng_seed_type> seeds(count);
            // Scalar-sized, row-ordered SEAL draws match sampleUniformPolyBatch,
            // including callers with small parent PRNG buffers.
            for (auto& seed : seeds) seed = sealSeedFromPrng(prng);
            auto next = gpu::sampleTopSecretUniformToDevice(ctx, seeds);
            auto host = std::make_shared<SeededTopSecretHostState>(ctx, std::move(seeds));
            if (next && gpu::topSecretUniformBatchMatches(ctx, *next, count,
                    currentProtocolCacheScope().mRunId))
            {
                for (u32 row = 0; row < count; ++row)
                    bumpRingStat(globalRingOpsStats.mPrngPolyCount,
                        tlsRingOpsStats.mPrngPolyCount);
                resident = std::move(next);
                lazy = std::move(host);
                eager.clear();
                return true;
            }
            if (strict) return false;
            eager = host->hostCoefficients();
            resident.reset();
            lazy.reset();
            return eager.size() == count;
        }
        if (strict) return false;
#endif
        eager = sampleUniformPolyBatch(ctx, count, prng);
        resident.reset();
        lazy.reset();
        return eager.size() == count;
    }

    RnsPoly deriveUniformPolyFromNonce(const RingNttContext& ctx, u64 nonce, u64 domainTag, u32 index)
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
            index);
    }

    RnsPoly deriveUniformPolyFromNonceNtt(const RingNttContext& ctx, u64 nonce, u64 domainTag, u32 index)
    {
        RnsPoly out = deriveUniformPolyFromNonce(ctx, nonce, domainTag, index);
        (void)forwardNttCanonical(out, ctx);
        return out;
    }

    void deriveUniformPolyBatchFromSeedInplace(
        const RingNttContext& ctx,
        block seed,
        u64 domainTag,
        u32 count,
        std::vector<RnsPoly>& out)
    {
        AutoTimer totalSamplingTimer(globalTimingStats.mSeedSamplingTimeUs);
        AutoTimer polySamplingTimer(globalTimingStats.mPolySamplingTimeUs);

#if defined(ENABLE_LOGVOLE_CUDA)
        // This is a batch, so the round trip amortises: the host alternative is
        // `count` separate Blake2xb XOF streams through SEAL at roughly 0.26 ms
        // each. It is the Root recursion level's ct2 sampling, which was the last
        // Blake2xb left on the host (4.7% of host cycles).
        if (count >= 4)
        {
            std::vector<RnsPoly> gpuOut;
            if (gpu::deriveUniformPolyBatchDevice(ctx, seed, domainTag, count, gpuOut) &&
                gpuOut.size() == count)
            {
                for (u32 i = 0; i < count; ++i)
                {
                    bumpRingStat(globalRingOpsStats.mPrngPolyCount, tlsRingOpsStats.mPrngPolyCount);
                }
                out = std::move(gpuOut);
                return;
            }
        }
#endif
        out.resize(count);
        for (u32 i = 0; i < count; ++i)
        {
            deriveUniformPolyFromSeedInplace(ctx, seed, domainTag, i, out[i]);
        }
    }

    std::vector<RnsPoly> deriveUniformPolyBatchFromSeed(
        const RingNttContext& ctx, block seed, u64 domainTag, u32 count)
    {
        std::vector<RnsPoly> out;
        deriveUniformPolyBatchFromSeedInplace(ctx, seed, domainTag, count, out);
        return out;
    }

    std::vector<RnsPoly> deriveUniformPolyBatchFromNonce(const RingNttContext& ctx, u64 nonce, u64 domainTag, u32 count)
    {
        return deriveUniformPolyBatchFromNonce(ctx, nonce, domainTag, count, false);
    }

    std::vector<RnsPoly> deriveUniformPolyBatchFromNonce(
        const RingNttContext& ctx, u64 nonce, u64 domainTag, u32 count, bool actualNtt)
    {
        return deriveUniformPolyBatchFromNonce(ctx, nonce, domainTag, count, actualNtt, nullptr);
    }

    std::vector<RnsPoly> deriveUniformPolyBatchFromNonce(
        const RingNttContext& ctx, u64 nonce, u64 domainTag, u32 count, bool actualNtt,
        std::shared_ptr<const gpu::RetainedPublicUniform>* captured)
    {
        AutoTimer totalSamplingTimer(globalTimingStats.mSeedSamplingTimeUs);
        AutoTimer polySamplingTimer(globalTimingStats.mPolySamplingTimeUs);
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
            return sampleUniformSetupSeeds(ctx, seeds, actualNtt, captured);
        }
#endif
        if (captured) captured->reset();
        std::vector<RnsPoly> out(count);
        for (u32 i = 0; i < count; ++i)
        {
            out[i] = deriveUniformPolyFromNonce(ctx, nonce, domainTag, i);
            if (actualNtt) (void)forwardNttCanonical(out[i], ctx);
        }
        return out;
    }

    bool retainUniformPolyBatchFromNonce(
        const RingNttContext& ctx, u64 nonce, u64 domainTag, u32 count,
        bool actualNtt, std::shared_ptr<const gpu::RetainedPublicUniform>& out)
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
        if (!gpu::retainUniformBatchFromSeedsDevice(ctx, seeds, actualNtt, next) ||
            !next || next->count() != count) return false;
        for (u32 i = 0; i < count; ++i)
        {
            bumpRingStat(globalRingOpsStats.mPrngPolyCount, tlsRingOpsStats.mPrngPolyCount);
            if (actualNtt)
                bumpRingStat(globalRingOpsStats.mNttCount, tlsRingOpsStats.mNttCount);
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
        u32 count)
    {
        return deriveUniformPolyBatchFromSeed(ctx, seed, domainTag, count);
    }

    std::vector<RnsPoly> deriveUniformPolyBatchFromNonceNtt(
        const RingNttContext& ctx,
        u64 nonce,
        u64 domainTag,
        u32 count)
    {
        return deriveUniformPolyBatchFromNonce(ctx, nonce, domainTag, count);
    }

    bool deriveUniformPolyBatchFromSeedListInplace(
        const RingNttContext& ctx,
        std::span<const block> seeds,
        u64 domainTag,
        u32 perSeedCount,
        std::vector<RnsPoly>& out,
        u32 requestedWorkers)
    {
        if (perSeedCount != 0 && seeds.size() > std::numeric_limits<std::size_t>::max() / perSeedCount)
        {
            return false;
        }

        const std::size_t totalCount = seeds.size() * static_cast<std::size_t>(perSeedCount);
        out.resize(totalCount);
        (void)requestedWorkers;
        for (std::size_t seedIdx = 0; seedIdx < seeds.size(); ++seedIdx)
        {
            for (u32 polyIdx = 0; polyIdx < perSeedCount; ++polyIdx)
            {
                deriveUniformPolyFromSeedInplace(ctx, seeds[seedIdx], domainTag, polyIdx,
                    out[seedIdx * static_cast<std::size_t>(perSeedCount) + polyIdx]);
            }
        }
        return true;
    }

    std::vector<RnsPoly> deriveUniformPolyBatchFromSeedList(
        const RingNttContext& ctx,
        std::span<const block> seeds,
        u64 domainTag,
        u32 perSeedCount,
        u32 requestedWorkers)
    {
        std::vector<RnsPoly> out;
        (void)deriveUniformPolyBatchFromSeedListInplace(ctx, seeds, domainTag, perSeedCount, out, requestedWorkers);
        return out;
    }

    bool deriveUniformPolyBatchFromNonceListInplace(
        const RingNttContext& ctx,
        std::span<const u64> nonces,
        u64 domainTag,
        u32 perNonceCount,
        std::vector<RnsPoly>& out,
        u32)
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
                    deriveUniformPolyFromNonce(ctx, nonces[nonceIdx], domainTag, polyIdx);
            }
        }
        return true;
    }

    std::vector<RnsPoly> deriveUniformPolyBatchFromNonceList(
        const RingNttContext& ctx,
        std::span<const u64> nonces,
        u64 domainTag,
        u32 perNonceCount,
        u32 requestedWorkers)
    {
        std::vector<RnsPoly> out;
        (void)deriveUniformPolyBatchFromNonceListInplace(ctx, nonces, domainTag, perNonceCount, out, requestedWorkers);
        return out;
    }

    static std::shared_ptr<seal::UniformRandomGeneratorFactory> errorSamplingPrngFactory()
    {
        static const bool vectorError = [] {
            const char* value = std::getenv("LV_CPU_VECTOR_ERROR");
            return !value || value[0] != '0';
        }();
        // The error distribution and all random draws stay unchanged. This
        // also respects a SEAL build whose default PRNG is not BLAKE2xb.
        return vectorError ? detail::cpuDefaultPrngFactory()
                           : seal::UniformRandomGeneratorFactory::DefaultFactory();
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
        const seal::prng_seed_type& seed, const RingNttContext& ctx)
    {
        if (!canSamplePolyErrorCompact(ctx, noiseStandardDeviation, noiseMaxDeviation) ||
            limb0.size() != ctx.mParams.mPolyModulusDegree) return false;
        const auto hostContext = getRingHostContext(ctx);
        if (!hostContext || !hostContext->key_context_data()) return false;
        auto sealPrng = errorSamplingPrngFactory()->create(seed);
        samplePolyNormal(sealPrng, hostContext->key_context_data()->parms(),
            limb0.data(), noiseStandardDeviation, noiseMaxDeviation, true);
        bumpRingStat(globalRingOpsStats.mErrorAddCount, tlsRingOpsStats.mErrorAddCount);
        return true;
    }

    namespace
    {
        // Keep samplePolyNormal unchanged: replacing its byte source leaves
        // the standard library's cached normal samples, clipping and floating
        // point operations exactly as before.
        class GaussianPrefixPrng final : public seal::UniformRandomGenerator
        {
        public:
            GaussianPrefixPrng(const seal::prng_seed_type& seed, std::span<const u64> prefix)
                : UniformRandomGenerator(seed), mPrefix(prefix) {}

        protected:
            seal::prng_type type() const noexcept override { return seal::prng_type::blake2xb; }
            void refill_buffer() override
            {
                if (mPrefixBytesUsed < mPrefix.size_bytes())
                {
                    std::memcpy(buffer_begin_,
                        reinterpret_cast<const u8*>(mPrefix.data()) + mPrefixBytesUsed, buffer_size_);
                    mPrefixBytesUsed += buffer_size_;
                    return;
                }
                if (!mContinuation)
                {
                    mContinuation = errorSamplingPrngFactory()->create(seed());
                    // Recreate the precise next SEAL refill. Prefixes are local
                    // to one polynomial; this never touches the parent PRNG.
                    for (std::size_t skipped = 0; skipped < mPrefix.size_bytes(); skipped += buffer_size_)
                        mContinuation->generate(buffer_size_, buffer_begin_);
                }
                mContinuation->generate(buffer_size_, buffer_begin_);
            }

        private:
            std::span<const u64> mPrefix;
            std::size_t mPrefixBytesUsed = 0;
            std::shared_ptr<seal::UniformRandomGenerator> mContinuation;
        };
    }

    bool samplePolyErrorCompactBatchFromSeeds(
        std::span<u64> limb0, double noiseStandardDeviation, double noiseMaxDeviation,
        std::span<const seal::prng_seed_type> seeds, const RingNttContext& ctx,
        u32 requestedWorkers, std::span<const u8> active)
    {
        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        if (!canSamplePolyErrorCompact(ctx, noiseStandardDeviation, noiseMaxDeviation) ||
            !n || seeds.size() > std::numeric_limits<std::size_t>::max() / n ||
            limb0.size() != seeds.size() * n || (!active.empty() && active.size() != seeds.size()))
            return false;
        std::vector<std::size_t> activeRows;
        activeRows.reserve(seeds.size());
        for (std::size_t i = 0; i < seeds.size(); ++i)
            if (active.empty() || active[i]) activeRows.push_back(i);
        if (activeRows.empty()) return true;

        std::shared_ptr<const u64> prefixOwner;
        std::span<const u64> prefixes;
        std::size_t wordsPerPrefix = 0;
        bool devicePrefixes = false;
#if defined(ENABLE_LOGVOLE_CUDA)
        static const bool compatibleFactory = errorSamplingPrngFactory()->create(
            seal::prng_seed_type{})->info().type() == seal::prng_type::blake2xb;
        const char* transformSetting = std::getenv("LV_GPU_SETUP_GAUSSIAN_TRANSFORM");
        if (gpu::enabled() && (!transformSetting || transformSetting[0] != '0'))
        {
            const char* strictSetting = std::getenv("LV_GPU_SETUP_GAUSSIAN_TRANSFORM_STRICT");
            const bool strict = strictSetting && strictSetting[0] != '0';
            u64 blocks = 0;
            bool validPrefix = true;
            if (const char* overrideBlocks = std::getenv("LV_GPU_SETUP_GAUSSIAN_TRANSFORM_PREFIX_BLOCKS"))
            {
                char* end = nullptr;
                blocks = std::strtoull(overrideBlocks, &end, 10);
                validPrefix = end != overrideBlocks && *end == '\0' &&
                    blocks <= std::numeric_limits<u32>::max() / 512u;
            }
            gpu::GaussianSampleBuffer sampled;
            bool transformed = false;
            if (compatibleFactory && validPrefix && n <= std::numeric_limits<u32>::max())
            {
                std::vector<seal::prng_seed_type> activeSeeds(activeRows.size());
                for (std::size_t i = 0; i < activeRows.size(); ++i)
                    activeSeeds[i] = seeds[activeRows[i]];
                transformed = gpu::sampleGaussianCompactDevice(activeSeeds, static_cast<u32>(n),
                    noiseStandardDeviation, noiseMaxDeviation, ringModulusValue(ctx, 0), sampled,
                    static_cast<u32>(blocks * 512u));
            }
            // A declined strict transform must not publish any destination
            // samples. Successful finite prefixes may still require exact
            // replay of individual rows from the unchanged original seed.
            if (!transformed && strict) return false;
            if (transformed)
                return detail::runParallelTasks(activeRows.size(), requestedWorkers, [&](std::size_t task) {
                    const auto row = activeRows[task];
                    auto destination = limb0.subspan(row * n, n);
                    if (!sampled.mComplete[task])
                    {
                        HostStep replayStep("setup: Gaussian CPU replay");
                        return samplePolyErrorCompactFromSeed(destination, noiseStandardDeviation,
                            noiseMaxDeviation, seeds[row], ctx);
                    }
                    std::memcpy(destination.data(), sampled.mValues.mData.get() + task * n,
                        destination.size_bytes());
                    bumpRingStat(globalRingOpsStats.mErrorAddCount, tlsRingOpsStats.mErrorAddCount);
                    return true;
                });
        }
        const char* setting = std::getenv("LV_GPU_SETUP_GAUSSIAN_PRG");
        const bool requested = gpu::enabled() && (!setting || setting[0] != '0');
        if (requested)
        {
            const char* strictSetting = std::getenv("LV_GPU_SETUP_GAUSSIAN_PRG_STRICT");
            const bool strict = strictSetting && strictSetting[0] != '0';
            // Three u32 words per coefficient exceed the normal polar sampler's
            // expected consumption; arbitrary clipping still has exact CPU
            // continuation when that finite prefix is exhausted.
            const u64 defaultBlocks = (static_cast<u64>(n) * 3u + 1023u) / 1024u;
            u64 blocks = defaultBlocks;
            if (const char* overrideBlocks = std::getenv("LV_GPU_SETUP_GAUSSIAN_PRG_PREFIX_BLOCKS"))
            {
                char* end = nullptr;
                const auto parsed = std::strtoull(overrideBlocks, &end, 10);
                if (end != overrideBlocks && *end == '\0' && parsed) blocks = parsed;
            }
            if (compatibleFactory && blocks <= std::numeric_limits<u32>::max() / 512u)
            {
                wordsPerPrefix = static_cast<std::size_t>(blocks) * 512u;
                std::vector<seal::prng_seed_type> activeSeeds(activeRows.size());
                for (std::size_t i = 0; i < activeRows.size(); ++i) activeSeeds[i] = seeds[activeRows[i]];
                gpu::GaussianPrngPrefixBuffer downloaded;
                devicePrefixes = gpu::sampleGaussianPrngPrefixesDevice(
                    activeSeeds, static_cast<u32>(wordsPerPrefix), downloaded);
                if (devicePrefixes)
                {
                    prefixOwner = std::move(downloaded.mData);
                    prefixes = std::span<const u64>(prefixOwner.get(), downloaded.mWords);
                }
            }
            if (!devicePrefixes && strict) return false;
        }
#endif
        return detail::runParallelTasks(activeRows.size(), requestedWorkers, [&](std::size_t task) {
            const auto row = activeRows[task];
            auto destination = limb0.subspan(row * n, n);
            if (!devicePrefixes)
                return samplePolyErrorCompactFromSeed(destination, noiseStandardDeviation,
                    noiseMaxDeviation, seeds[row], ctx);
            auto source = std::make_shared<GaussianPrefixPrng>(seeds[row],
                prefixes.subspan(task * wordsPerPrefix, wordsPerPrefix));
            const auto hostContext = getRingHostContext(ctx);
            if (!hostContext || !hostContext->key_context_data()) return false;
            samplePolyNormal(source, hostContext->key_context_data()->parms(),
                destination.data(), noiseStandardDeviation, noiseMaxDeviation, true);
            bumpRingStat(globalRingOpsStats.mErrorAddCount, tlsRingOpsStats.mErrorAddCount);
            return true;
        });
    }

    bool samplePolyErrorCompactBatchForSetup(
        std::vector<u64>& host, std::shared_ptr<gpu::DeviceScalars>& device,
        double sigma, double clip, std::span<const seal::prng_seed_type> seeds,
        const RingNttContext& ctx, u32 requestedWorkers, std::span<const u8> active)
    {
        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        if (!canSamplePolyErrorCompact(ctx, sigma, clip) || !n ||
            seeds.size() > std::numeric_limits<std::size_t>::max() / n ||
            (!active.empty() && active.size() != seeds.size())) return false;
        if (seeds.empty()) { host.clear(); device.reset(); return true; }
#if defined(ENABLE_LOGVOLE_CUDA)
        const char* resident = std::getenv("LV_GPU_SETUP_GAUSSIAN_RESIDENT");
        if (gpu::enabled() && (!resident || resident[0] != '0'))
        {
            const char* strictSetting = std::getenv("LV_GPU_SETUP_GAUSSIAN_RESIDENT_STRICT");
            const bool strict = strictSetting && strictSetting[0] != '0';
            const char* transform = std::getenv("LV_GPU_SETUP_GAUSSIAN_TRANSFORM");
            static const bool compatibleFactory = errorSamplingPrngFactory()->create(
                seal::prng_seed_type{})->info().type() == seal::prng_type::blake2xb;
            u64 blocks = 0;
            bool validPrefix = true;
            if (const char* setting = std::getenv("LV_GPU_SETUP_GAUSSIAN_TRANSFORM_PREFIX_BLOCKS"))
            {
                char* end = nullptr;
                blocks = std::strtoull(setting, &end, 10);
                validPrefix = end != setting && *end == '\0' && blocks <= std::numeric_limits<u32>::max() / 512u;
            }
            gpu::GaussianDeviceSampleBuffer sampled;
            bool ready = (!transform || transform[0] != '0') && compatibleFactory && validPrefix &&
                n <= std::numeric_limits<u32>::max() &&
                gpu::sampleGaussianCompactResidentDevice(seeds, static_cast<u32>(n), sigma, clip,
                    ringModulusValue(ctx, 0), sampled, static_cast<u32>(blocks * 512u), active);
            if (ready)
            {
                std::vector<std::size_t> incomplete;
                for (std::size_t row = 0; row < seeds.size(); ++row)
                    if (!sampled.mComplete[row]) incomplete.push_back(row);
                // A finite first prefix can exhaust on only a few rows. Retry
                // those original seeds on the owning GPU before considering
                // exact host replay and an H2D repair of whole coefficient rows.
                const u64 defaultWords =
                    ((static_cast<u64>(n) * 3u + 1023u) / 1024u) * 512u;
                u64 retryWords = std::max<u64>(defaultWords,
                    blocks ? blocks * 1024u : defaultWords * 2u);
                for (u32 attempt = 0; ready && !incomplete.empty() &&
                        attempt < 8u && retryWords <= std::numeric_limits<u32>::max();
                        ++attempt)
                {
                    HostStep retryStep("setup: Gaussian resident GPU repair retry");
                    std::vector<seal::prng_seed_type> retrySeeds;
                    retrySeeds.reserve(incomplete.size());
                    for (const auto row : incomplete) retrySeeds.push_back(seeds[row]);
                    gpu::GaussianDeviceSampleBuffer retried;
                    if (!gpu::sampleGaussianCompactResidentDevice(
                            retrySeeds, static_cast<u32>(n), sigma, clip,
                            ringModulusValue(ctx, 0), retried,
                            static_cast<u32>(retryWords))) break;
                    auto& stream = gpu::threadSampleStream();
                    struct Drain { gpu::GpuStream& stream; ~Drain() { stream.sync(); } } drain{stream};
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
                ready = ready && detail::runParallelTasks(incomplete.size(), requestedWorkers, [&](std::size_t i) {
                    HostStep repairStep("setup: Gaussian resident CPU repair");
                    repaired[i].resize(n);
                    return samplePolyErrorCompactFromSeed(repaired[i], sigma, clip, seeds[incomplete[i]], ctx);
                });
                if (ready && !incomplete.empty())
                {
                    auto& stream = gpu::threadSampleStream();
                    struct Drain { gpu::GpuStream& stream; ~Drain() { stream.sync(); } } drain{stream};
                    for (std::size_t i = 0; ready && i < incomplete.size(); ++i)
                        ready = gpu::gpuMemcpyH2D(sampled.mValues->data() + incomplete[i] * n,
                            repaired[i].data(), n * sizeof(u64), stream.raw());
                    ready = stream.sync() && ready;
                }
                if (ready)
                {
                    for (std::size_t row = 0; row < seeds.size(); ++row)
                        if ((active.empty() || active[row]) && sampled.mComplete[row])
                            bumpRingStat(globalRingOpsStats.mErrorAddCount, tlsRingOpsStats.mErrorAddCount);
                    host.clear();
                    device = std::move(sampled.mValues);
                    return true;
                }
            }
            if (strict) return false;
        }
#endif
        std::vector<u64> next(seeds.size() * n, 0);
        if (!samplePolyErrorCompactBatchFromSeeds(next, sigma, clip, seeds, ctx, requestedWorkers, active)) return false;
        host = std::move(next);
        device.reset();
        return true;
    }

    bool materializePolyErrorCompactBatchForSetup(
        std::vector<u64>& host, const std::shared_ptr<gpu::DeviceScalars>& device,
        double sigma, double clip, std::span<const seal::prng_seed_type> seeds,
        const RingNttContext& ctx, u32 requestedWorkers, std::span<const u8> active)
    {
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
            if (gpu::enabled() && gpu::fetchScalars(*device, next)) { host = std::move(next); return true; }
            // A declined asynchronous fetch must drain before CPU replay can
            // reuse its destination, including copy/sync error exits.
            if (gpu::enabled()) gpu::threadStream().sync();
            std::fill(next.begin(), next.end(), 0);
        }
#else
        if (device) return false;
#endif
        if (!detail::runParallelTasks(seeds.size(), requestedWorkers, [&](std::size_t row) {
                return (!active.empty() && !active[row]) ||
                    samplePolyErrorCompactFromSeed(std::span<u64>(next).subspan(row * n, n), sigma, clip, seeds[row], ctx);
            })) return false;
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
        const RingNttContext& ctx)
    {
        const auto hostContext = getRingHostContext(ctx);
        if (!hostContext || !hostContext->key_context_data()) return false;
        auto sealPrng = errorSamplingPrngFactory()->create(seed);

        auto& contextData = *hostContext->key_context_data();
        auto& parms = contextData.parms();
        auto& coeffModulus = parms.coeff_modulus();
        const std::size_t coeffModulusSize = coeffModulus.size();
        const std::size_t coeffCount = parms.poly_modulus_degree();

        seal::util::Pointer<u64> temp =
            seal::util::allocate_poly(coeffCount, coeffModulusSize, seal::MemoryPoolHandle::ThreadLocal());
        seal::util::RNSIter tempIter(temp.get(), coeffCount);

        samplePolyNormal(sealPrng, parms, temp.get(), noiseStandardDeviation, noiseMaxDeviation);

        seal::util::PolyIter destinationIter(poly.mCoeffs.data(), coeffCount, coeffModulusSize);
        seal::util::add_poly_coeffmod(destinationIter[0], tempIter, coeffModulusSize, coeffModulus, destinationIter[0]);

        bumpRingStat(globalRingOpsStats.mErrorAddCount, tlsRingOpsStats.mErrorAddCount);
        return true;
    }

    bool addPolyError(
        RnsPoly& poly,
        double noiseStandardDeviation,
        double noiseMaxDeviation,
        PRNG& prng,
        const RingNttContext& ctx)
    {
        const auto hostContext = getRingHostContext(ctx);
        if (noiseStandardDeviation < 0 || !canonicalizePoly(poly, ctx) ||
            !hostContext || !hostContext->key_context_data())
        {
            return false;
        }
        return addPolyErrorCanonicalFromSeed(
            poly, noiseStandardDeviation, noiseMaxDeviation, sealSeedFromPrng(prng), ctx);
    }

    bool addPolyErrorFromSeed(
        RnsPoly& poly,
        double noiseStandardDeviation,
        double noiseMaxDeviation,
        const seal::prng_seed_type& seed,
        const RingNttContext& ctx)
    {
        const auto hostContext = getRingHostContext(ctx);
        if (noiseStandardDeviation < 0 || !canonicalizePoly(poly, ctx) ||
            !hostContext || !hostContext->key_context_data())
        {
            return false;
        }
        return addPolyErrorCanonicalFromSeed(poly, noiseStandardDeviation, noiseMaxDeviation, seed, ctx);
    }
}

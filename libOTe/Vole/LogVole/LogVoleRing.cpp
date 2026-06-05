#include "libOTe/Vole/LogVole/LogVoleRing.h"

#include "libOTe/Vole/LogVole/LogVoleArithmetic.h"

#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Crypto/RandomOracle.h"

#include "seal/util/clipnormal.h"
#include "seal/util/iterator.h"
#include "seal/util/ntt.h"
#include "seal/util/polyarithsmallmod.h"
#include "seal/util/rlwe.h"
#include "seal/util/uintarithsmallmod.h"
#include "seal/util/uintcore.h"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <exception>
#include <limits>
#include <string>
#include <tuple>

namespace osuCrypto::LogVole
{
    namespace
    {
        bool isPowerOfTwo(u32 value)
        {
            return value > 0 && (value & (value - 1u)) == 0u;
        }

        bool validateShapeAgainstContext(const RnsPoly& poly, const RingNttContext& ctx)
        {
            return poly.mCoeffs.size() == ringPolyCoeffCount(ctx.mParams);
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

        void samplePolyNormal(
            std::shared_ptr<seal::UniformRandomGenerator> prng,
            const seal::EncryptionParameters& parms,
            u64* destination,
            double noiseStandardDeviation,
            double noiseMaxDeviation)
        {
            auto& coeffModulus = parms.coeff_modulus();
            const std::size_t coeffModulusSize = coeffModulus.size();
            const std::size_t coeffCount = parms.poly_modulus_degree();

            seal::RandomToStandardAdapter engine(prng);
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
        }

        std::shared_ptr<seal::UniformRandomGeneratorFactory> polySamplingPrngFactory()
        {
#ifdef SEAL_USE_AES_CTR_DRBG
            static const auto factory = std::make_shared<seal::AesCtrDrbgPRNGFactory>();
#else
            static const auto factory = seal::UniformRandomGeneratorFactory::DefaultFactory();
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
            out.assign(levels, {});
            for (auto& digit : out)
            {
                resizeZero(digit.mCoeffs, canonical.mCoeffs.size());
            }

            const std::size_t n = ctx.mParams.mPolyModulusDegree;
            const std::size_t coeffModCount = ctx.mModuli.size();
            auto contextData = ctx.mContext ? ctx.mContext->key_context_data() : nullptr;
            if (!contextData)
            {
                return false;
            }

            seal::util::Pointer<u64> composedPoly =
                seal::util::allocate_poly(n, coeffModCount, seal::MemoryManager::GetPool());
            std::copy(canonical.mCoeffs.begin(), canonical.mCoeffs.end(), composedPoly.get());
            contextData->rns_tool()->base_q()->compose_array(composedPoly.get(), n, seal::MemoryManager::GetPool());

            auto pool = seal::MemoryManager::GetPool();
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
                            seal::util::modulo_uint(digitAbs.get(), coeffModCount, ctx.mModuli[modIdx]);
                        out[outLevel].mCoeffs[modIdx * n + coeffIdx] =
                            (digitIsNegative && reduced != 0) ? (ctx.mModuli[modIdx].value() - reduced) : reduced;
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

    block deriveSeedInstanceBlock(
        std::span<const u8> seed,
        u64 sid,
        const RnsPoly& digest,
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
        const u64 coeffSize = static_cast<u64>(digest.mCoeffs.size());
        roUpdatePod(ro, seedSize);
        roUpdatePod(ro, coeffSize);
        if (!seed.empty())
        {
            ro.Update(seed.data(), seed.size());
        }
        if (!digest.mCoeffs.empty())
        {
            ro.Update(digest.mCoeffs.data(), digest.mCoeffs.size());
        }
        ro.Final(out);
        return out;
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

    bool makeRingNttContext(const RingParams& params, RingNttContext& out)
    {
        if (!validateRingParams(params))
        {
            return false;
        }

        std::vector<seal::Modulus> moduli;
        try
        {
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
        next.mContext = std::make_shared<seal::SEALContext>(parms, true, seal::sec_level_type::none);
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

    bool canonicalizePoly(RnsPoly& poly, const RingNttContext& ctx)
    {
        if (!validateShapeAgainstContext(poly, ctx))
        {
            return false;
        }

        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        seal::util::PolyIter polyIter(poly.mCoeffs.data(), n, ctx.mModuli.size());
        seal::util::modulo_poly_coeffs(polyIter[0], ctx.mModuli.size(), ctx.mModuli, polyIter[0]);
        return true;
    }

    bool forwardNtt(RnsPoly& poly, const RingNttContext& ctx)
    {
        if (!canonicalizePoly(poly, ctx) || !ctx.mContext || !ctx.mContext->key_context_data())
        {
            return false;
        }

        const auto& tables = ctx.mContext->key_context_data()->small_ntt_tables();
        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        for (std::size_t modIdx = 0; modIdx < ctx.mModuli.size(); ++modIdx)
        {
            seal::util::ntt_negacyclic_harvey(poly.mCoeffs.data() + (modIdx * n), tables[modIdx]);
        }

        bumpRingStat(globalRingOpsStats.mNttCount, tlsRingOpsStats.mNttCount);
        return true;
    }

    bool inverseNtt(RnsPoly& poly, const RingNttContext& ctx)
    {
        if (!validateShapeAgainstContext(poly, ctx) || !ctx.mContext || !ctx.mContext->key_context_data())
        {
            return false;
        }

        const auto& tables = ctx.mContext->key_context_data()->small_ntt_tables();
        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        for (std::size_t modIdx = 0; modIdx < ctx.mModuli.size(); ++modIdx)
        {
            seal::util::inverse_ntt_negacyclic_harvey(poly.mCoeffs.data() + (modIdx * n), tables[modIdx]);
        }

        bumpRingStat(globalRingOpsStats.mInttCount, tlsRingOpsStats.mInttCount);
        return canonicalizePoly(poly, ctx);
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
        if (!validateShapeAgainstContext(aNtt, ctx) ||
            !validateShapeAgainstContext(bNtt, ctx) ||
            !validateShapeAgainstContext(cNtt, ctx))
        {
            return false;
        }

        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        for (std::size_t modIdx = 0; modIdx < ctx.mModuli.size(); ++modIdx)
        {
            const auto& modulus = ctx.mModuli[modIdx];
            const u64 mod = modulus.value();
            const std::size_t offset = modIdx * n;
            for (std::size_t i = 0; i < n; ++i)
            {
                const std::size_t idx = offset + i;
                cNtt.mCoeffs[idx] =
                    mulAddMod(
                        aNtt.mCoeffs[idx] % mod,
                        bNtt.mCoeffs[idx] % mod,
                        cNtt.mCoeffs[idx] % mod,
                        modulus);
            }
        }

        bumpRingStat(globalRingOpsStats.mDyadicMulAddCount, tlsRingOpsStats.mDyadicMulAddCount);
        return true;
    }

    bool ringAddInplace(RnsPoly& a, const RnsPoly& b, const RingNttContext& ctx)
    {
        if (!validateShapeAgainstContext(a, ctx) || !validateShapeAgainstContext(b, ctx))
        {
            return false;
        }

        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        seal::util::PolyIter aIter(a.mCoeffs.data(), n, ctx.mModuli.size());
        seal::util::ConstPolyIter bIter(b.mCoeffs.data(), n, ctx.mModuli.size());
        seal::util::add_poly_coeffmod(aIter[0], bIter[0], ctx.mModuli.size(), ctx.mModuli, aIter[0]);
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
        if (!validateShapeAgainstContext(a, ctx) || !validateShapeAgainstContext(b, ctx))
        {
            return false;
        }

        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        seal::util::PolyIter aIter(a.mCoeffs.data(), n, ctx.mModuli.size());
        seal::util::ConstPolyIter bIter(b.mCoeffs.data(), n, ctx.mModuli.size());
        seal::util::sub_poly_coeffmod(aIter[0], bIter[0], ctx.mModuli.size(), ctx.mModuli, aIter[0]);
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
        if (!validateShapeAgainstContext(a, ctx))
        {
            return false;
        }

        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        for (std::size_t modIdx = 0; modIdx < ctx.mModuli.size(); ++modIdx)
        {
            const auto& modulus = ctx.mModuli[modIdx];
            const u64 mod = modulus.value();
            const u64 scalarMod = scalar % mod;
            const std::size_t offset = modIdx * n;
            for (std::size_t i = 0; i < n; ++i)
            {
                const std::size_t idx = offset + i;
                a.mCoeffs[idx] = mulMod(a.mCoeffs[idx] % mod, scalarMod, modulus);
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
        for (std::size_t modIdx = 0; modIdx < ctx.mModuli.size(); ++modIdx)
        {
            const u64 mod = ctx.mModuli[modIdx].value();
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
        for (std::size_t modIdx = 0; modIdx < ctx.mModuli.size(); ++modIdx)
        {
            const u64 mod = ctx.mModuli[modIdx].value();
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
                        digits[j].mCoeffs[offset + i] % mod,
                        basePows[j],
                        acc,
                        ctx.mModuli[modIdx]);
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
        if (digitBits == 0 || levels == 0 || !validateShapeAgainstContext(poly, ctx))
        {
            return false;
        }

        RnsPoly canonical = poly;
        if (!canonicalizePoly(canonical, ctx))
        {
            return false;
        }

        auto contextData = ctx.mContext ? ctx.mContext->key_context_data() : nullptr;
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
        const std::size_t coeffModCount = ctx.mModuli.size();
        seal::util::Pointer<u64> composedPoly =
            seal::util::allocate_poly(n, coeffModCount, seal::MemoryManager::GetPool());
        std::copy(canonical.mCoeffs.begin(), canonical.mCoeffs.end(), composedPoly.get());
        contextData->rns_tool()->base_q()->compose_array(composedPoly.get(), n, seal::MemoryManager::GetPool());

        auto tempMpi = seal::util::allocate_uint(coeffModCount, seal::MemoryManager::GetPool());
        for (std::size_t i = 0; i < n; ++i)
        {
            u64* valuePtr = composedPoly.get() + i * coeffModCount;
            seal::util::right_shift_uint(valuePtr, static_cast<int>(startShift), coeffModCount, valuePtr);

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
                        seal::util::modulo_uint(tempMpi.get(), coeffModCount, ctx.mModuli[modIdx]);
                }

                seal::util::right_shift_uint(valuePtr, static_cast<int>(digitBits), coeffModCount, valuePtr);
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

        const bool ok = centeredDecomposeSlow(canonical, digitBits, startLevel, levels, ctx, out);
        if (ok)
        {
            bumpRingStat(globalRingOpsStats.mGadgetDecomposeCount, tlsRingOpsStats.mGadgetDecomposeCount);
        }
        return ok;
    }

    bool gadgetRecomposeBits(const std::vector<RnsPoly>& digits, u32 digitBits, const RingNttContext& ctx, RnsPoly& out)
    {
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
        for (std::size_t modIdx = 0; modIdx < ctx.mModuli.size(); ++modIdx)
        {
            const u64 mod = ctx.mModuli[modIdx].value();
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
                        digits[level].mCoeffs[offset + i] % mod,
                        pow2Shifts[level],
                        acc,
                        ctx.mModuli[modIdx]);
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

    RnsPoly deriveUniformPolyFromSeed(const RingNttContext& ctx, block seed, u64 domainTag, u32 index)
    {
        AutoTimer totalSamplingTimer(globalTimingStats.mSeedSamplingTimeUs);
        AutoTimer polySamplingTimer(globalTimingStats.mPolySamplingTimeUs);

        RnsPoly out{};
        resizeZero(out.mCoeffs, ringPolyCoeffCount(ctx.mParams));

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

        auto contextData = ctx.mContext ? ctx.mContext->key_context_data() : nullptr;
        if (contextData)
        {
            auto prng = polySamplingPrngFactory()->create(sealSeedFromBlock(polySeed));
            seal::util::sample_poly_uniform(prng, contextData->parms(), out.mCoeffs.data());
            bumpRingStat(globalRingOpsStats.mPrngPolyCount, tlsRingOpsStats.mPrngPolyCount);
            return out;
        }

        PRNG rng(polySeed);
        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        for (std::size_t modIdx = 0; modIdx < ctx.mModuli.size(); ++modIdx)
        {
            const u64 mod = ctx.mModuli[modIdx].value();
            const std::size_t offset = modIdx * n;
            for (std::size_t i = 0; i < n; ++i)
            {
                out.mCoeffs[offset + i] = rng.get<u64>() % mod;
            }
        }
        bumpRingStat(globalRingOpsStats.mPrngPolyCount, tlsRingOpsStats.mPrngPolyCount);
        return out;
    }

    RnsPoly deriveUniformPolyFromSeedNtt(const RingNttContext& ctx, block seed, u64 domainTag, u32 index)
    {
        RnsPoly out = deriveUniformPolyFromSeed(ctx, seed, domainTag, index);
        (void)forwardNtt(out, ctx);
        return out;
    }

    RnsPoly sampleUniformPoly(const RingNttContext& ctx, PRNG& prng)
    {
        RnsPoly out{};
        resizeZero(out.mCoeffs, ringPolyCoeffCount(ctx.mParams));

        auto contextData = ctx.mContext ? ctx.mContext->key_context_data() : nullptr;
        if (contextData)
        {
            auto sealPrng = polySamplingPrngFactory()->create(sealSeedFromPrng(prng));
            seal::util::sample_poly_uniform(sealPrng, contextData->parms(), out.mCoeffs.data());
            bumpRingStat(globalRingOpsStats.mPrngPolyCount, tlsRingOpsStats.mPrngPolyCount);
            return out;
        }

        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        for (std::size_t modIdx = 0; modIdx < ctx.mModuli.size(); ++modIdx)
        {
            const u64 mod = ctx.mModuli[modIdx].value();
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
        (void)forwardNtt(out, ctx);
        return out;
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
        (void)forwardNtt(out, ctx);
        return out;
    }

    std::vector<RnsPoly> deriveUniformPolyBatchFromSeed(
        const RingNttContext& ctx,
        block seed,
        u64 domainTag,
        u32 count)
    {
        AutoTimer totalSamplingTimer(globalTimingStats.mSeedSamplingTimeUs);
        AutoTimer polySamplingTimer(globalTimingStats.mPolySamplingTimeUs);

        std::vector<RnsPoly> out(count);
        for (u32 i = 0; i < count; ++i)
        {
            out[i] = deriveUniformPolyFromSeed(ctx, seed, domainTag, i);
        }
        return out;
    }

    std::vector<RnsPoly> deriveUniformPolyBatchFromNonce(const RingNttContext& ctx, u64 nonce, u64 domainTag, u32 count)
    {
        AutoTimer totalSamplingTimer(globalTimingStats.mSeedSamplingTimeUs);
        AutoTimer polySamplingTimer(globalTimingStats.mPolySamplingTimeUs);

        std::vector<RnsPoly> out(count);
        for (u32 i = 0; i < count; ++i)
        {
            out[i] = deriveUniformPolyFromNonce(ctx, nonce, domainTag, i);
        }
        return out;
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
                out[seedIdx * static_cast<std::size_t>(perSeedCount) + polyIdx] =
                    deriveUniformPolyFromSeed(ctx, seeds[seedIdx], domainTag, polyIdx);
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

    bool addPolyError(
        RnsPoly& poly,
        double noiseStandardDeviation,
        double noiseMaxDeviation,
        PRNG& prng,
        const RingNttContext& ctx)
    {
        if (noiseStandardDeviation < 0 || !canonicalizePoly(poly, ctx))
        {
            return false;
        }

        auto contextDataPtr = ctx.mContext ? ctx.mContext->key_context_data() : nullptr;
        if (!contextDataPtr)
        {
            return false;
        }

        auto sealPrng = seal::UniformRandomGeneratorFactory::DefaultFactory()->create(sealSeedFromPrng(prng));

        auto& contextData = *contextDataPtr;
        auto& parms = contextData.parms();
        auto& coeffModulus = parms.coeff_modulus();
        const std::size_t coeffModulusSize = coeffModulus.size();
        const std::size_t coeffCount = parms.poly_modulus_degree();

        seal::util::Pointer<u64> temp =
            seal::util::allocate_poly(coeffCount, coeffModulusSize, seal::MemoryManager::GetPool());
        seal::util::RNSIter tempIter(temp.get(), coeffCount);

        samplePolyNormal(sealPrng, parms, temp.get(), noiseStandardDeviation, noiseMaxDeviation);

        seal::util::PolyIter destinationIter(poly.mCoeffs.data(), coeffCount, coeffModulusSize);
        seal::util::add_poly_coeffmod(destinationIter[0], tempIter, coeffModulusSize, coeffModulus, destinationIter[0]);

        bumpRingStat(globalRingOpsStats.mErrorAddCount, tlsRingOpsStats.mErrorAddCount);
        return true;
    }
}

#pragma once

#include "libOTe/Vole/LogVole/LogVoleTypes.h"

#include "cryptoTools/Crypto/PRNG.h"

#include "seal/seal.h"

#include <atomic>
#include <chrono>
#include <memory>
#include <span>
#include <vector>

namespace osuCrypto::LogVole
{
    struct RingOpsStats
    {
        static inline std::atomic<u64> resetEpoch{ 0u };

        std::atomic<u64> mNttCount{ 0 };
        std::atomic<u64> mInttCount{ 0 };
        std::atomic<u64> mAddCount{ 0 };
        std::atomic<u64> mSubCount{ 0 };
        std::atomic<u64> mMulCount{ 0 };
        std::atomic<u64> mMulScalarCount{ 0 };
        std::atomic<u64> mDyadicMulAddCount{ 0 };
        std::atomic<u64> mGadgetDecomposeCount{ 0 };
        std::atomic<u64> mGadgetRecomposeCount{ 0 };
        std::atomic<u64> mPrngPolyCount{ 0 };
        std::atomic<u64> mErrorAddCount{ 0 };

        void reset();
    };

    inline RingOpsStats globalRingOpsStats;

    void flushRingOpsThreadLocalStats();

    struct TimingStats
    {
        std::atomic<u64> mSenderWaitTimeUs{ 0 };
        std::atomic<u64> mReceiverWaitTimeUs{ 0 };
        std::atomic<u64> mSenderAsyncWaitTimeUs{ 0 };
        std::atomic<u64> mReceiverAsyncWaitTimeUs{ 0 };
        std::atomic<u64> mSenderComputeTimeUs{ 0 };
        std::atomic<u64> mReceiverComputeTimeUs{ 0 };
        std::atomic<u64> mLencEncTimeUs{ 0 };
        std::atomic<u64> mLencDecTimeUs{ 0 };
        std::atomic<u64> mLheEncTimeUs{ 0 };
        std::atomic<u64> mLheDecTimeUs{ 0 };
        std::atomic<u64> mShrinkTimeUs{ 0 };
        std::atomic<u64> mExpandTimeUs{ 0 };
        std::atomic<u64> mPolySamplingTimeUs{ 0 };
        std::atomic<u64> mGoldSamplingTimeUs{ 0 };
        std::atomic<u64> mSeedSamplingTimeUs{ 0 };
        std::atomic<u64> mSeedAttemptTimeUs{ 0 };
        std::atomic<u64> mSeedAttemptCount{ 0 };
        std::atomic<u64> mGdecompUnbundleTimeUs{ 0 };
        std::atomic<u64> mDenoiseTbmTimeUs{ 0 };
        std::atomic<u64> mAggTimeUs{ 0 };

        void reset();
    };

    inline TimingStats globalTimingStats;

    struct AutoTimer
    {
        std::atomic<u64>& mStat;
        std::chrono::steady_clock::time_point mStart;

        AutoTimer(std::atomic<u64>& stat);
        ~AutoTimer();
    };

    struct RingNttContext
    {
        RingParams mParams;
        std::vector<seal::Modulus> mModuli;
        std::shared_ptr<seal::SEALContext> mContext;
    };

    bool validateRingParams(const RingParams& params);
    bool validateRingPolyShape(const RnsPoly& poly, const RingParams& params);
    bool validateRingBatchShape(const std::vector<RnsPoly>& polys, const RingParams& params);
    bool validateRingBatchShape(std::span<const RnsPoly> polys, const RingParams& params);
    bool makeRingNttContext(const RingParams& params, RingNttContext& out);

    bool canonicalizePoly(RnsPoly& poly, const RingNttContext& ctx);
    bool forwardNtt(RnsPoly& poly, const RingNttContext& ctx);
    bool inverseNtt(RnsPoly& poly, const RingNttContext& ctx);

    bool dyadicMultiplyAddNtt(
        const RnsPoly& aNtt,
        const RnsPoly& bNtt,
        const RnsPoly& cNtt,
        const RingNttContext& ctx,
        RnsPoly& out);

    bool dyadicMultiplyAddNttInplace(
        const RnsPoly& aNtt,
        const RnsPoly& bNtt,
        RnsPoly& cNtt,
        const RingNttContext& ctx);

    bool ringAdd(const RnsPoly& a, const RnsPoly& b, const RingNttContext& ctx, RnsPoly& out);
    bool ringAddInplace(RnsPoly& a, const RnsPoly& b, const RingNttContext& ctx);
    bool ringSub(const RnsPoly& a, const RnsPoly& b, const RingNttContext& ctx, RnsPoly& out);
    bool ringSubInplace(RnsPoly& a, const RnsPoly& b, const RingNttContext& ctx);
    bool ringMultiply(const RnsPoly& a, const RnsPoly& b, const RingNttContext& ctx, RnsPoly& out);
    bool ringMultiplyInplace(RnsPoly& a, const RnsPoly& b, const RingNttContext& ctx);
    bool ringMultiplyScalar(const RnsPoly& a, u64 scalar, const RingNttContext& ctx, RnsPoly& out);
    bool ringMultiplyScalarInplace(RnsPoly& a, u64 scalar, const RingNttContext& ctx);

    bool gadgetDecompose(
        const RnsPoly& poly,
        u32 base,
        u32 tau,
        const RingNttContext& ctx,
        std::vector<RnsPoly>& out);

    bool gadgetRecompose(
        const std::vector<RnsPoly>& digits,
        u32 base,
        const RingNttContext& ctx,
        RnsPoly& out);

    bool gadgetDecomposeBits(
        const RnsPoly& poly,
        u32 digitBits,
        u32 levels,
        const RingNttContext& ctx,
        std::vector<RnsPoly>& out,
        u32 requestedWorkers = 1);

    bool gadgetDecomposeBitsRange(
        const RnsPoly& poly,
        u32 digitBits,
        u32 startLevel,
        u32 levels,
        const RingNttContext& ctx,
        std::vector<RnsPoly>& out,
        u32 requestedWorkers = 1);

    bool gadgetDecomposeBitsRangeCentered(
        const RnsPoly& poly,
        u32 digitBits,
        u32 startLevel,
        u32 levels,
        const RingNttContext& ctx,
        std::vector<RnsPoly>& out,
        u32 requestedWorkers = 1);

    bool gadgetRecomposeBits(
        const std::vector<RnsPoly>& digits,
        u32 digitBits,
        const RingNttContext& ctx,
        RnsPoly& out);

    AlignedUnVec<u64> packRingBatch(const std::vector<RnsPoly>& polys);
    bool unpackRingBatch(
        u32 count,
        u32 polyModulusDegree,
        u32 coeffModulusCount,
        std::span<const u64> flat,
        std::vector<RnsPoly>& out,
        u32 requestedWorkers = 1);

    AlignedUnVec<u64> packRingTensor(const RingTensor& tensor);
    bool unpackRingTensor(
        u32 rows,
        u32 cols,
        u32 polyModulusDegree,
        u32 coeffModulusCount,
        std::span<const u64> flat,
        RingTensor& out,
        u32 requestedWorkers = 1);

    RnsPoly deriveUniformPolyFromSeed(const RingNttContext& ctx, block seed, u64 domainTag, u32 index);
    RnsPoly deriveUniformPolyFromSeedNtt(const RingNttContext& ctx, block seed, u64 domainTag, u32 index);
    RnsPoly sampleUniformPoly(const RingNttContext& ctx, PRNG& prng);
    RnsPoly sampleUniformPolyNtt(const RingNttContext& ctx, PRNG& prng);
    RnsPoly deriveUniformPolyFromNonce(const RingNttContext& ctx, u64 nonce, u64 domainTag, u32 index);
    RnsPoly deriveUniformPolyFromNonceNtt(const RingNttContext& ctx, u64 nonce, u64 domainTag, u32 index);
    std::vector<RnsPoly> deriveUniformPolyBatchFromSeed(
        const RingNttContext& ctx,
        block seed,
        u64 domainTag,
        u32 count);
    std::vector<RnsPoly> deriveUniformPolyBatchFromNonce(
        const RingNttContext& ctx,
        u64 nonce,
        u64 domainTag,
        u32 count);
    std::vector<RnsPoly> deriveUniformPolyBatchFromSeedNtt(
        const RingNttContext& ctx,
        block seed,
        u64 domainTag,
        u32 count);
    std::vector<RnsPoly> deriveUniformPolyBatchFromNonceNtt(
        const RingNttContext& ctx,
        u64 nonce,
        u64 domainTag,
        u32 count);
    std::vector<RnsPoly> deriveUniformPolyBatchFromSeedList(
        const RingNttContext& ctx,
        std::span<const block> seeds,
        u64 domainTag,
        u32 perSeedCount,
        u32 requestedWorkers = 0);
    bool deriveUniformPolyBatchFromSeedListInplace(
        const RingNttContext& ctx,
        std::span<const block> seeds,
        u64 domainTag,
        u32 perSeedCount,
        std::vector<RnsPoly>& out,
        u32 requestedWorkers = 0);
    std::vector<RnsPoly> deriveUniformPolyBatchFromNonceList(
        const RingNttContext& ctx,
        std::span<const u64> nonces,
        u64 domainTag,
        u32 perNonceCount,
        u32 requestedWorkers = 0);
    bool deriveUniformPolyBatchFromNonceListInplace(
        const RingNttContext& ctx,
        std::span<const u64> nonces,
        u64 domainTag,
        u32 perNonceCount,
        std::vector<RnsPoly>& out,
        u32 requestedWorkers = 0);

    u64 combineSeedPublic(u64 value);
    u64 deriveDeterministicSeedMaterial(
        u64 root,
        u64 domainTag,
        u64 value0 = 0,
        u64 value1 = 0,
        u64 value2 = 0,
        u64 value3 = 0);
    block deriveSeedInstanceBlock(
        std::span<const u8> seed,
        u64 sid,
        const RnsPoly& digest,
        u64 instanceIdx,
        u64 fallbackNonce = 0);

    bool addPolyError(
        RnsPoly& poly,
        double noiseStandardDeviation,
        double noiseMaxDeviation,
        PRNG& prng,
        const RingNttContext& ctx);
}

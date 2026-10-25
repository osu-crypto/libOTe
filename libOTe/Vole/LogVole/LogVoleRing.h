#pragma once

#include "libOTe/Vole/LogVole/LogVoleTypes.h"

#include "cryptoTools/Crypto/PRNG.h"

#include "seal/seal.h"

#include <atomic>
#include <array>
#include <chrono>
#include <memory>
#include <span>
#include <vector>

namespace osuCrypto::LogVole
{
    namespace gpu { class DeviceScalars; class RetainedPublicUniform; class GpuRing; }
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

        // Zp <-> ring CRT packing, and the GPU fast paths.
        std::atomic<u64> mWrapTimeUs{ 0 };
        std::atomic<u64> mUnwrapTimeUs{ 0 };
        std::atomic<u64> mGpuShrinkTimeUs{ 0 };
        std::atomic<u64> mGpuExpandTimeUs{ 0 };
        std::atomic<u64> mGpuSenderTimeUs{ 0 };
        std::atomic<u64> mGpuMiscTimeUs{ 0 };

        // Time each party spends blocked in recvFrame, i.e. waiting for the peer.
        // This is what separates a party's own cost from the cost the protocol's
        // round structure imposes on it.
        std::atomic<u64> mSenderWaitUs{ 0 };
        std::atomic<u64> mReceiverWaitUs{ 0 };

        // Ablation counters: host time spent inside the Root recursion level, and
        // time spent serialising / deserialising the Root's two wire messages.
        // Subtracting these from a party's wall time gives the ceiling that would
        // be reached if the Root were device resident and the exchange free.
        std::atomic<u64> mRootReceiverHostUs{ 0 };
        std::atomic<u64> mRootSenderHostUs{ 0 };
        std::atomic<u64> mRootSerializeUs{ 0 };

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

    struct RingHostContextCache;

    struct RingModulusMetadata
    {
        std::vector<u64> mValues;
        std::vector<int> mBitCounts;
        // Only dynamic GPU-created metadata holds this immutable, role-local
        // ring whose raw setup kernels certified primality and exact tables.
        std::shared_ptr<gpu::GpuRing> mDynamicGpuCertificate;
    };

    struct RingNttContext
    {
        RingParams mParams;
        // Legacy host storage. Lightweight contexts keep this empty; explicit
        // host access materializes SEAL objects in the shared fallback owner.
        std::vector<seal::Modulus> mModuli;
        std::shared_ptr<seal::SEALContext> mContext;
        std::shared_ptr<const RingModulusMetadata> mRawModuli;
        // A production GPU context owns exact ordered moduli but no SEALContext.
        // Copies share only this party's immutable, explicitly materialized
        // host fallback. mContext stays null even after materialization.
        bool mGpuLightweight = false;
        std::shared_ptr<RingHostContextCache> mHostContextCache;
    };

    bool validateRingParams(const RingParams& params);
    // Metadata access never constructs SEAL objects or touches the GPU.
    std::size_t ringModulusCount(const RingNttContext& ctx);
    u64 ringModulusValue(const RingNttContext& ctx, std::size_t limb);
    int ringModulusBitCount(const RingNttContext& ctx, std::size_t limb);
    bool validateRingContextMetadata(const RingNttContext& ctx);
    // Stable immutable SEAL storage, constructed only on explicit CPU access.
    // An invalid lightweight context or failed materialization returns empty.
    const std::vector<seal::Modulus>& getRingHostModuli(const RingNttContext& ctx);
    bool validateRingPolyShape(const RnsPoly& poly, const RingParams& params);
    bool validateRingBatchShape(const std::vector<RnsPoly>& polys, const RingParams& params);
    bool validateRingBatchShape(std::span<const RnsPoly> polys, const RingParams& params);
    bool makeRingNttContext(const RingParams& params, RingNttContext& out);
    // Production tuples use audited metadata without device work. Other raw
    // GPU-supported tuples construct and certify metadata on the device before
    // publication. Unsupported parameters leave out unchanged.
    bool makeGpuRingNttContext(const RingParams& params, RingNttContext& out);
    // Constructs a private lightweight context from a fully sealed dynamic
    // GPU ring certificate. The caller owns the larger ring/CRT publication
    // transaction; this helper does not insert a partial ring cache entry.
    bool makeNativeGpuRingNttContextFromCertificate(
        const RingParams& params, std::span<const u64> orderedPrimes,
        std::shared_ptr<gpu::GpuRing> certificate, RingNttContext& out);
    // Admit a validated native certificate into the standalone role-local
    // Ring factory after its combined CRT setup has fully committed.
    bool publishNativeGpuRingNttContext(const RingNttContext& ready);
    // Explicit, cached exact CPU fallback. Never changes a lightweight context
    // into the legacy null-context sampler or publishes through mContext.
    std::shared_ptr<seal::SEALContext> getRingHostContext(const RingNttContext& ctx);

    bool canonicalizePoly(RnsPoly& poly, const RingNttContext& ctx);
    bool forwardNtt(RnsPoly& poly, const RingNttContext& ctx);
    // Internal fast path for coefficients already proven to be in [0,q_j).
    // Call forwardNtt for arbitrary-u64 input that still needs normalization.
    bool forwardNttCanonical(RnsPoly& poly, const RingNttContext& ctx);
    bool inverseNtt(RnsPoly& poly, const RingNttContext& ctx);

    // Batched equivalents. Prefer these wherever several independent transforms
    // are done back to back: with the CUDA backend they amortise one device round
    // trip over the whole batch instead of paying a stream drain per polynomial.
    // Bit-identical to calling the single-polynomial versions in order.
    bool forwardNttBatch(std::span<RnsPoly> polys, const RingNttContext& ctx);
    bool inverseNttBatch(std::span<RnsPoly> polys, const RingNttContext& ctx);

    bool dyadicMultiplyAddNtt(
        const RnsPoly& aNtt,
        const RnsPoly& bNtt,
        const RnsPoly& cNtt,
        const RingNttContext& ctx,
        RnsPoly& out);

    // Inputs are borrowed and must not alias the accumulator.
    bool dyadicInnerProductNttInplace(
        std::span<const RnsPoly* const> left, std::span<const RnsPoly* const> right,
        RnsPoly& accumulator, const RingNttContext& ctx);

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
    // Resample all coefficients, preserving existing CPU allocations where possible.
    void deriveUniformPolyBatchFromSeedInplace(
        const RingNttContext& ctx, block seed, u64 domainTag, u32 count,
        std::vector<RnsPoly>& out);
    RnsPoly sampleUniformPoly(const RingNttContext& ctx, PRNG& prng);
    RnsPoly sampleUniformPolyNtt(const RingNttContext& ctx, PRNG& prng);
    // Exactly the scalar sampler's seed order, including a device fallback.
    std::vector<RnsPoly> sampleUniformPolyBatch(const RingNttContext& ctx, u32 count, PRNG& prng);
    // Selected private top HE key; same ordered SEAL draws as ordinary setup.
    // A device decline replays these rows exactly on the host.
    bool sampleTopSecretUniformBatch(const RingNttContext& ctx, u32 count,
        PRNG& prng, std::vector<RnsPoly>& eager,
        std::shared_ptr<gpu::DeviceBatch>& resident,
        std::shared_ptr<const LazyRootSecretHostState>& lazy);
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
    // Explicit actual transform; legacy BatchFromNonceNtt returns raw samples.
    std::vector<RnsPoly> deriveUniformPolyBatchFromNonce(
        const RingNttContext& ctx,
        u64 nonce,
        u64 domainTag,
        u32 count,
        bool actualNtt);
    // Optional immutable device capture; the host result is unchanged. Move
    // it directly into a const owner before registering it for public reuse.
    std::vector<RnsPoly> deriveUniformPolyBatchFromNonce(
        const RingNttContext& ctx, u64 nonce, u64 domainTag, u32 count,
        bool actualNtt, std::shared_ptr<const gpu::RetainedPublicUniform>* captured);

    // Internal setup form which consumes no protocol PRNG and keeps the exact
    // deterministic batch exclusively on the current CUDA device. Returns
    // false without changing out when the retained path is unavailable.
    bool retainUniformPolyBatchFromNonce(
        const RingNttContext& ctx, u64 nonce, u64 domainTag, u32 count,
        bool actualNtt, std::shared_ptr<const gpu::RetainedPublicUniform>& out);
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
    // Commitment to a ring element, used to bind ct2 seeds to a level's digest
    // without re-reading the digest for every instance.
    block hashSeedDigest(const RnsPoly& digest);

    // Exact replay of sampleUniformPoly from its already-consumed 64-byte
    // SEAL seed; used when a device sample declines without advancing the PRNG.
    RnsPoly sampleUniformPolyFromSeed(
        const RingNttContext& ctx, const std::array<u64, 8>& seed);

    // Instance seed derived from a digest *commitment*. Callers that derive many
    // instances from one digest should hash it once and use this.
    block deriveSeedInstanceBlockFromDigestHash(
        std::span<const u8> seed,
        u64 sid,
        block digestHash,
        u64 instanceIdx,
        u64 fallbackNonce = 0);

    // Convenience wrapper: hashSeedDigest followed by the above.
    block deriveSeedInstanceBlock(
        std::span<const u8> seed,
        u64 sid,
        const RnsPoly& digest,
        u64 instanceIdx,
        u64 fallbackNonce = 0);

    // The ct2 seed used by Ct2SeedMode::PublicSeed: a random oracle applied to
    // the session id and a commitment to the receiver's root digest. Both parties
    // derive it independently, so it is never sent, and the sender never grinds.
    void derivePublicCt2Seed(u64 sid, block digestHash, std::span<u8> out,
        OnlineMode mode = OnlineMode::Interactive);
    void derivePublicCt2Seed(u64 sid, const RnsPoly& digest, std::span<u8> out);

    bool addPolyError(
        RnsPoly& poly,
        double noiseStandardDeviation,
        double noiseMaxDeviation,
        PRNG& prng,
        const RingNttContext& ctx);

    // Same error sampler with an already-drawn SEAL seed. Callers can draw
    // seeds in protocol order, then sample independent polynomials in parallel
    // without sharing or changing the protocol PRNG stream.
    bool addPolyErrorFromSeed(
        RnsPoly& poly,
        double noiseStandardDeviation,
        double noiseMaxDeviation,
        const seal::prng_seed_type& seed,
        const RingNttContext& ctx);

    // Exact existing Gaussian draws represented by only their canonical q0
    // limb. Eligible bounds allow centered broadcast to every RNS modulus.
    bool canSamplePolyErrorCompact(
        const RingNttContext& ctx, double noiseStandardDeviation, double noiseMaxDeviation);
    bool samplePolyErrorCompactFromSeed(
        std::span<u64> limb0, double noiseStandardDeviation, double noiseMaxDeviation,
        const seal::prng_seed_type& seed, const RingNttContext& ctx);
    // Batched exact Gaussian draws. The GPU may expand BLAKE2xb prefixes;
    // the unchanged CPU normal transform consumes them, with exact continuation
    // from the original seed if a prefix runs out. Inactive rows are untouched.
    bool samplePolyErrorCompactBatchFromSeeds(
        std::span<u64> limb0, double noiseStandardDeviation, double noiseMaxDeviation,
        std::span<const seal::prng_seed_type> seeds, const RingNttContext& ctx,
        u32 requestedWorkers = 1, std::span<const u8> active = {});
    // Owned setup samples: resident selection publishes an empty host vector
    // and a completed device buffer; fallback publishes host data and no device.
    // Inactive rows are zero. Invalid/strict failure preserves both outputs.
    bool samplePolyErrorCompactBatchForSetup(
        std::vector<u64>& host, std::shared_ptr<gpu::DeviceScalars>& device,
        double sigma, double clip, std::span<const seal::prng_seed_type> seeds,
        const RingNttContext& ctx, u32 requestedWorkers = 1, std::span<const u8> active = {});
    // Materialize only when a downstream device operation declined. A failed
    // device fetch replays these original seeds on CPU without parent draws.
    bool materializePolyErrorCompactBatchForSetup(
        std::vector<u64>& host, const std::shared_ptr<gpu::DeviceScalars>& device,
        double sigma, double clip, std::span<const seal::prng_seed_type> seeds,
        const RingNttContext& ctx, u32 requestedWorkers = 1, std::span<const u8> active = {});
    // Reconstruct the same full coefficient polynomial without any PRNG draws.
    bool expandPolyErrorCompact(
        std::span<const u64> limb0, RnsPoly& out, const RingNttContext& ctx);
}

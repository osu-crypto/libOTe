#pragma once

// Host-side glue between the LogVole CPU data structures and the CUDA kernels.
//
// GpuRing owns the device-resident constant tables for one RingParams (moduli,
// NTT root powers in SEAL's exact orderings, and the multi-precision CRT
// constants used by gadget decomposition). GpuPolyBuffer is a device array of
// RnsPoly-shaped polynomials.
//
// All operations are bit-identical to the CPU routines in LogVoleRing.cpp; the
// unit tests in libOTe_Tests/LogVole/tests/test_gpu_ring.cpp check this by
// exact comparison.

#include "libOTe/Vole/LogVole/LogVoleRing.h"
#include "libOTe/Vole/LogVole/LogVoleRuntime.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuKernels.h"

#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace osuCrypto::LogVole::gpu
{
    bool available();
    std::string deviceDescription();
    // Returns -1 if the current CUDA device cannot be queried.
    int currentDeviceOrdinal();

    // Dynamic, SEAL-compatible setup for the raw backend's supported geometry.
    // The device performs prime search/primality and multiprecision lift
    // arithmetic; only the small immutable API metadata is copied to host.
    bool dynamicSealSetupSupported(const RingParams& params);
    bool selectSealCoeffModuliDevice(const RingParams& params,
        std::vector<u64>& orderedPrimes);
    bool selectSealPlainModulusDevice(u32 n, u32 requestedBits, u64 minimumQ,
        u64& selectedPrime, u32& selectedBits);
    class GpuRing;
    class GpuPlainNtt;
    struct NativeSealSetupBundle;
    // Private cold producer for callers that know both coefficient geometry
    // and requested plaintext width. It constructs both immutable GPU table
    // owners and downloads one q/p/lift/status record. No cache or caller
    // output changes on decline; the caller publishes contexts after success.
    bool buildNativeSealSetupBundleDevice(const RingParams& params,
        u32 requestedPlaintextBits, NativeSealSetupBundle& out);
    bool preparePlaintextLiftDevice(const GpuRing& ring, u64 plaintextPrime,
        AlignedUnVec<u64>& residues);

    // A stream plus a small scratch allocator for index arrays.
    class GpuStream
    {
    public:
        GpuStream();
        // A lean non-blocking stream at the device's greatest supported
        // priority. It deliberately has no allocation/index scratch: callers
        // must prepare all storage on an ordinary registered stream before
        // launching work here. Returns null when the device exposes no useful
        // priority range or stream creation fails.
        static std::unique_ptr<GpuStream> createHighestPriority();
        ~GpuStream();
        GpuStream(const GpuStream&) = delete;
        GpuStream& operator=(const GpuStream&) = delete;

        void* raw() const { return mStream; }
        bool sync() const;

        // Upload a small u32 index array and return a device pointer valid
        // until the next reset(). Uses a bump allocator on pinned + device
        // memory so index uploads do not allocate.
        const u32* uploadIdx(std::span<const u32> idx);
        void reset();

        // Pinned staging area used to coalesce many per-polynomial copies into
        // a few large transfers. Returns nullptr if it cannot be grown.
        u8* staging(std::size_t bytes);
        std::size_t stagingCapacity() const { return mStagingBytes; }
        // Borrow without allocating or growing. The owning stream must order
        // every access, and the pointer expires on staging growth/destruction.
        u8* existingStaging(std::size_t bytes) const
        {
            return bytes <= mStagingBytes ? mStaging : nullptr;
        }

    private:
        GpuStream(bool highestPriority, bool allocateScratch);

        void* mStream = nullptr;
        bool mHighestPriority = false;
        u32* mDeviceScratch = nullptr;
        u32* mHostScratch = nullptr;
        std::size_t mScratchWords = 0;
        std::size_t mScratchUsed = 0;
        u8* mStaging = nullptr;
        std::size_t mStagingBytes = 0;
    };

    // Stream for the calling thread *and protocol role*, so the sender and the
    // receiver do not serialise on one stream when they are interleaved
    // coroutines on the same host thread. Also publishes the stream to the
    // caching allocator via gpuSetCurrentStream.
    GpuStream& threadStream();
    // Second stream for the calling role, for work independent of the main chain.
    GpuStream& threadSampleStream();

    // 0 = unspecified, 1 = sender, 2 = receiver. Any per-thread scratch that is
    // touched by device work must be indexed by this too, otherwise two streams
    // would share one buffer.
    u32 threadStreamSlot();
    constexpr u32 kStreamSlots = 3;

    // Copies `bytes` from a device pointer into ordinary (pageable) host memory
    // at full PCIe speed.
    //
    // cudaMemcpyAsync straight into pageable memory is ~2 GB/s on this machine
    // against ~13 GB/s for a pinned destination, because the driver stages it
    // internally and serialises. This routes the transfer through a bounded pair
    // of pinned buffers and overlaps the host-side copy out of buffer k with the
    // device-to-host copy into buffer k+1.
    bool downloadToHost(void* dst, const void* deviceSrc, std::size_t bytes, GpuStream& stream);

    // Copies ordinary pageable host memory to the device. The default uses CUDA's
    // direct pageable path; LV_GPU_PIPELINED_UPLOAD=1 opts into a double-buffered
    // pinned pipeline that can help platforms with a slower driver staging path.
    // The returned copy remains stream ordered and is not synchronised here.
    bool uploadFromHost(void* deviceDst, const void* src, std::size_t bytes, GpuStream& stream);

    // Setup-wire H2D sources of at least 1 MiB are registered after population
    // and retained when their storage comes from the reusable wire pool. Fresh
    // pool-owned D2H destinations attempt persistent registration and direct
    // transfer; unsupported or failed registration uses bounded staging.
    // LV_GPU_SETUP_DIRECT_WIRE_DOWNLOAD=0 restores the prior fresh-D2H staging
    // policy for A/B profiling. Blocks registered by prior H2D reuse transfer
    // directly in either direction. LV_GPU_SETUP_PINNED_WIRE=0 restores ordinary
    // staged helpers. Both directions drain before returning, including failure,
    // and before releasing any temporary registration for external storage.
    bool downloadSetupWire(void* hostDst, const void* deviceSrc, std::size_t bytes, GpuStream& stream);
    bool uploadSetupWire(void* deviceDst, const void* hostSrc, std::size_t bytes, GpuStream& stream);

    // Explicit native setup selects a role-local cache lane on device 0.
    // Factory construction still requires a nonzero owned protocol run.
    bool nativeSealBundleCacheRequested();

    // Upload a compact host matrix into pitched device rows. The caller keeps
    // src alive until stream completion; untouched device columns stay unused.
    bool uploadRowsFromHost(void* deviceDst, std::size_t dstPitch, const void* src,
        std::size_t rowBytes, std::size_t rows, GpuStream& stream);
    // Device source is a completed contiguous compact matrix; its owner must
    // survive the queued pitched D2D copy.
    bool copyRowsFromDevice(void* deviceDst, std::size_t dstPitch, const void* src,
        std::size_t rowBytes, std::size_t rows, GpuStream& stream);

    class GpuRing
    {
    public:
        // Cached per RingParams; never returns null on success.
        static std::shared_ptr<GpuRing> get(const RingNttContext& ctx);

        // SEAL-independent initialization. Exact ordered prime values are part
        // of the role-local cache key; device kernels validate primes and
        // construct SEAL-compatible NTT, CRT, and denoise constants.
        // Returns null for unsupported/malformed parameters or CUDA failure.
        static std::shared_ptr<GpuRing> getRaw(
            const RingParams& params, std::span<const u64> orderedPrimes);
        // Publish an already certified native ring into the matching raw
        // role/mode lane. Existing sequential owners stay alive for borrowers.
        static bool publishRaw(const RingParams& params,
            std::span<const u64> orderedPrimes,
            const std::shared_ptr<GpuRing>& ready);

        ~GpuRing();
        GpuRing(const GpuRing&) = delete;
        GpuRing& operator=(const GpuRing&) = delete;

        u32 n() const { return mView.mN; }
        u32 rho() const { return mView.mRho; }
        std::size_t polyWords() const { return static_cast<std::size_t>(mView.mN) * mView.mRho; }
        std::size_t polyBytes() const { return polyWords() * sizeof(u64); }
        const RingConstView& view() const { return mView; }
        const DenoiseConstView& denoiseView() const { return mDenoise; }
        bool denoiseReady() const { return mDenoiseReady; }

        // 2^shiftBits mod q_j for every limb, uploaded and cached on demand.
        // Mirrors scaleByGPowerInplace's per-limb factor.
        const u64* pow2Factors(u32 shiftBits);
        // Device-generated immutable constants, cached per plaintext modulus.
        // Drains initialization before returning; leaves out unchanged on failure.
        bool scaleRoundConstants(u64 plaintextModulus, ScaleRoundConstView& out);

        // Per-limb prod_{w != j} q_w mod q_j and its inverse, used by the
        // recursive-leaf path (buildRecursiveLeafScaling).
        const u64* crtLiftFactors() const { return mCrtLift; }
        const u64* invCrtLiftFactors() const { return mInvCrtLift; }

        const std::vector<u64>& hostModuli() const { return mHostModuli; }
        ProtocolCacheRole rawOwnerRole() const { return mRawOwnerRole; }
        bool nativeSealBundleOwner() const
        {
            return static_cast<bool>(mNativeSealBundleStorage);
        }
        const u64* sampleMaxMultiple() const { return mSampleMaxMultiple; }

    private:
        GpuRing() = default;
        friend bool buildNativeSealSetupBundleDevice(const RingParams&,
            u32, NativeSealSetupBundle&);
        bool init(const RingNttContext& ctx);
        bool initRaw(const RingParams& params, std::span<const u64> orderedPrimes);
        bool initDenoise(const RingNttContext& ctx);

        RingConstView mView{};
        DenoiseConstView mDenoise{};
        bool mDenoiseReady = false;

        std::vector<void*> mOwned;
        // A cold native bundle can own ring and plaintext tables as two
        // disjoint slices of one allocation. Each immutable owner retains it.
        std::shared_ptr<void> mNativeSealBundleStorage;
        std::vector<std::pair<u32, const u64*>> mPow2Cache;
        std::vector<std::pair<u64, ScaleRoundConstView>> mScaleRoundCache;
        std::mutex mPow2Mutex;
        bool mRaw = false;
        ProtocolCacheRole mRawOwnerRole = ProtocolCacheRole::Unspecified;
        const u64* mCrtLift = nullptr;
        const u64* mInvCrtLift = nullptr;
        const u64* mSampleMaxMultiple = nullptr;
        std::vector<u64> mHostModuli;
        std::vector<HostModulus> mHostModulusData;
        RingParams mParams{};
    };

    // GPU first-use overlap (LV_GPU_SETUP_INIT_OVERLAP=0 disables). Declare this
    // inside the timed setup scope, before independent CPU work. It owns a
    // context copy and joins on destruction, including early returns. Normal
    // GpuRing::get calls remain the synchronization/fallback boundary.
    class GpuRingSetupPrefetch
    {
    public:
        GpuRingSetupPrefetch(const RingNttContext& ctx, bool gpuEnabled);
        ~GpuRingSetupPrefetch();
        GpuRingSetupPrefetch(const GpuRingSetupPrefetch&) = delete;
        GpuRingSetupPrefetch& operator=(const GpuRingSetupPrefetch&) = delete;
        bool wait() noexcept;

    private:
        struct Impl;
        std::unique_ptr<Impl> mImpl;
    };

    // Device tables for the *plaintext* modulus NTT that seal::BatchEncoder
    // uses, plus the slot permutation that decode() applies afterwards.
    //
    // The plaintext ring is Z_p[X]/(X^N+1) with a single 55-bit prime, so it is
    // just a RingConstView with rho == 1 and the NTT kernels can be reused
    // verbatim. That is the whole trick behind running BatchEncoder::decode on
    // the GPU.
    class GpuPlainNtt
    {
    public:
        // Cached per (N, plaintext modulus). Returns null on failure.
        static std::shared_ptr<GpuPlainNtt> get(
            const seal::SEALContext& batchingContext, const seal::BatchEncoder& encoder);
        // Builds the plaintext NTT and SEAL batching permutation on the device.
        static std::shared_ptr<GpuPlainNtt> getRaw(u32 degree, u64 plaintextPrime);
        // Admit a fully sealed private native-bundle owner into the immutable
        // role-keyed raw table cache. Call only at the host context commit
        // boundary; no table construction or D2H occurs here.
        static bool publishRaw(u32 degree, u64 plaintextPrime,
            const std::shared_ptr<GpuPlainNtt>& ready);

        ~GpuPlainNtt();
        GpuPlainNtt(const GpuPlainNtt&) = delete;
        GpuPlainNtt& operator=(const GpuPlainNtt&) = delete;

        const RingConstView& view() const { return mView; }
        u32 n() const { return mView.mN; }
        u32 slotCount() const { return mSlotCount; }
        ProtocolCacheRole nativeBundleOwnerRole() const
        {
            return mNativeBundleOwnerRole;
        }
        // Device array of `slotCount` gather indices, i.e. SEAL's
        // matrix_reps_index_map_.
        const u32* slotMap() const { return mSlotMap; }
        // Inverse permutation: coefficient k is decoded into slot
        // inverseSlotMap()[k]. This lets the forward NTT write decoded scalars
        // directly instead of materialising and gathering a plaintext batch.
        const u32* inverseSlotMap() const { return mInverseSlotMap; }

    private:
        GpuPlainNtt() = default;
        friend bool buildNativeSealSetupBundleDevice(const RingParams&,
            u32, NativeSealSetupBundle&);
        bool init(const seal::SEALContext& batchingContext, const seal::BatchEncoder& encoder);
        bool initRaw(u32 degree, u64 plaintextPrime);

        RingConstView mView{};
        const u32* mSlotMap = nullptr;
        const u32* mInverseSlotMap = nullptr;
        u32 mSlotCount = 0;
        std::vector<void*> mOwned;
        std::shared_ptr<void> mNativeSealBundleStorage;
        ProtocolCacheRole mNativeBundleOwnerRole = ProtocolCacheRole::Unspecified;
    };

    struct NativeSealSetupBundle
    {
        std::vector<u64> mOrderedPrimes;
        u64 mPlaintextPrime = 0;
        u32 mSelectedPlaintextBits = 0;
        AlignedUnVec<u64> mPlaintextLift;
        std::shared_ptr<GpuRing> mRing;
        std::shared_ptr<GpuPlainNtt> mPlainNtt;
        ProtocolCacheRole mOwnerRole = ProtocolCacheRole::Unspecified;
        u64 mOwnerRunId = 0;
    };

    // Device array of `count` polynomials laid out exactly like a
    // std::vector<RnsPoly> flattened, i.e. count * rho * N u64.
    class GpuPolyBuffer
    {
    public:
        GpuPolyBuffer() = default;
        explicit GpuPolyBuffer(const GpuRing& ring, std::size_t count);
        ~GpuPolyBuffer();
        GpuPolyBuffer(GpuPolyBuffer&& other) noexcept;
        GpuPolyBuffer& operator=(GpuPolyBuffer&& other) noexcept;
        GpuPolyBuffer(const GpuPolyBuffer&) = delete;
        GpuPolyBuffer& operator=(const GpuPolyBuffer&) = delete;

        bool resize(const GpuRing& ring, std::size_t count);
        // Layout-only operations do not need NTT/CRT tables. Validate the word
        // count and allocation size without bootstrapping a GpuRing.
        bool resizeWords(std::size_t polyWords, std::size_t count);
        void release();

        u64* data() const { return mData; }
        u64* poly(std::size_t idx) const { return mData + idx * mPolyWords; }
        std::size_t count() const { return mCount; }
        std::size_t polyWords() const { return mPolyWords; }
        std::size_t bytes() const { return mCount * mPolyWords * sizeof(u64); }
        bool empty() const { return mCount == 0; }

        // The span overload coalesces through shared pinned staging and drains
        // that staging before returning. The single-polynomial overload only
        // queues the H2D; its source must outlive the copy on `stream`.
        bool upload(std::span<const RnsPoly> polys, GpuStream& stream, std::size_t dstOffset = 0);
        bool upload(const RnsPoly& poly, std::size_t dstIdx, GpuStream& stream);

        // Queues the copies and synchronises before returning.
        bool download(std::vector<RnsPoly>& polys, GpuStream& stream, std::size_t srcOffset = 0,
                      std::size_t count = 0) const;
        // Optional setup path: bounded pinned DMA overlapped with parallel
        // materialization into independently owned host polynomials. Publishes
        // only after the complete batch succeeds; unchanged output on failure.
        bool downloadPipelined(std::vector<RnsPoly>& polys, GpuStream& stream, u32 workers,
                               std::size_t srcOffset = 0, std::size_t count = 0) const;
        // Queues the copy without synchronising; the caller must sync.
        bool downloadAsync(RnsPoly& poly, std::size_t srcIdx, GpuStream& stream) const;
        bool zero(GpuStream& stream);

    private:
        u64* mData = nullptr;
        std::size_t mCount = 0;
        std::size_t mPolyWords = 0;
        std::size_t mCapacity = 0;
    };

    // ---- primitive wrappers ----------------------------------------------
    // Each of these mirrors the identically named CPU routine.

    bool nttForward(const GpuRing& ring, u64* polys, u32 count, GpuStream& stream);
    bool nttInverse(const GpuRing& ring, u64* polys, u32 count, GpuStream& stream);

    bool innerProduct(
        const GpuRing& ring,
        const u64* aBase,
        const u64* bBase,
        std::span<const u32> aIdx,
        std::span<const u32> bIdx,
        u32 terms,
        u64* out,
        u32 outCount,
        bool accumulate,
        bool negate,
        GpuStream& stream);

    bool gadgetDecomposeBits(
        const GpuRing& ring,
        const u64* in,
        u32 inCount,
        u32 digitBits,
        u32 startLevel,
        u32 levels,
        bool centered,
        u64* out,
        GpuStream& stream);

    bool elementwise(
        const GpuRing& ring,
        const u64* aBase,
        const u64* bBase,
        u64* out,
        u32 outCount,
        ElemOp op,
        GpuStream& stream);

    bool denoiseComb(const GpuRing& ring, const u64* in, u64* out, u32 outCount, GpuStream& stream);
}

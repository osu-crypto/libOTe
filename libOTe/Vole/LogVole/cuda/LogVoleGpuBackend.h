#pragma once
#include "libOTe/Vole/LogVole/LogVoleIdentity.h"
#include "libOTe/Vole/LogVole/LogVoleCpuBenchmark.h"

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
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuMemory.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuGaussian.h"

#include <atomic>
#include <memory>
#include <exception>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace osuCrypto::LogVole::gpu
{
    // Explicit GPU resource constructors discover once when no captured fact is supplied.
    // CPU factories pass false, and derived owners forward their existing fact.
    // Caller-owned reuse of ring and plaintext tables. Table owners retain
    // setup resources independently, with no reference back to this cache.
    class GpuTableCache
    {
    public:
        explicit GpuTableCache(LogVoleExecutionOptions options = {},
            std::shared_ptr<HostStepProfiler> profiler = {},
            std::optional<bool> gpuAvailable = {});
        const LogVoleExecutionOptions& executionOptions() const { return mExecutionOptions; }
        bool gpuAvailable() const noexcept { return mGpuAvailable; }
        bool gpuEnabled() const noexcept { return mExecutionOptions.mUseGpu && mGpuAvailable; }
        HostStepProfiler* hostProfiler() const { return mHostProfiler.get(); }
        const std::shared_ptr<HostStepProfiler>& hostProfilerOwner() const { return mHostProfiler; }
        ~GpuTableCache();
        GpuTableCache(const GpuTableCache&) = delete;
        GpuTableCache& operator=(const GpuTableCache&) = delete;
    private:
        friend class GpuRing;
        friend class GpuPlainNtt;
        friend class GpuRingSetupPrefetch;
        struct Impl;
        std::shared_ptr<HostStepProfiler> mHostProfiler;
        std::unique_ptr<Impl> mImpl;
        const LogVoleExecutionOptions mExecutionOptions;
        const bool mGpuAvailable;
    };
    // Explicit cold-setup execution domain. Copies of ring/CRT resources can
    // retain this domain; it owns reusable per-worker streams without TLS.
    // Callers must join all factory users before releasing their last owner.
    class GpuSetupContext
    {
    public:
        explicit GpuSetupContext(LogVoleExecutionOptions options = {},
            std::shared_ptr<HostStepProfiler> profiler = {},
            std::shared_ptr<const ProtocolCacheService> service = {},
            std::optional<bool> gpuAvailable = {});
        const LogVoleExecutionOptions& executionOptions() const { return mExecutionOptions; }
        bool gpuAvailable() const noexcept { return mGpuAvailable; }
        bool gpuEnabled() const noexcept { return mExecutionOptions.mUseGpu && mGpuAvailable; }
        HostStepProfiler* hostProfiler() const { return mHostProfiler.get(); }
        const std::shared_ptr<HostStepProfiler>& hostProfilerOwner() const { return mHostProfiler; }
        const std::shared_ptr<const ProtocolCacheService>& protocolService() const noexcept { return mProtocolService; }
        ~GpuSetupContext();
        GpuSetupContext(const GpuSetupContext&) = delete;
        GpuSetupContext& operator=(const GpuSetupContext&) = delete;
        std::shared_ptr<OwnedGpuStream> stream();
    private:
        struct Impl;
        const std::shared_ptr<const ProtocolCacheService> mProtocolService;
        std::shared_ptr<HostStepProfiler> mHostProfiler;
        std::unique_ptr<Impl> mImpl;
        const LogVoleExecutionOptions mExecutionOptions;
        const bool mGpuAvailable;
    };

    // Uncached device discovery, for explicit cold construction/diagnostics only.
    bool available();
    std::string deviceDescription();
    // Returns -1 if the current CUDA device cannot be queried.
    int currentDeviceOrdinal();

    // Dynamic, SEAL-compatible setup for the raw backend's supported geometry.
    // The device performs prime search/primality and multiprecision lift
    // arithmetic; only the small immutable API metadata is copied to host.
    bool dynamicSealSetupSupported(const RingParams& params);
    // Explicit execution owns its service. Only null-execution callers use
    // fallbackService; defaults temporarily support unmigrated direct callers.
    bool selectSealCoeffModuliDevice(const RingParams& params,
        std::vector<u64>& orderedPrimes, std::shared_ptr<GpuSetupContext> execution = {},
        const std::shared_ptr<const ProtocolCacheService>& fallbackService = {});
    bool selectSealPlainModulusDevice(u32 n, u32 requestedBits, u64 minimumQ,
        u64& selectedPrime, u32& selectedBits, std::shared_ptr<GpuSetupContext> execution = {},
        const std::shared_ptr<const ProtocolCacheService>& fallbackService = {});
    class GpuRing;
    class GpuPlainNtt;
    struct NativeSealSetupBundle;
    // Private cold producer for callers that know both coefficient geometry
    // and requested plaintext width. It constructs both immutable GPU table
    // owners and downloads one q/p/lift/status record. No cache or caller
    // output changes on decline; the caller publishes contexts after success.
    bool buildNativeSealSetupBundleDevice(const RingParams& params,
        u32 requestedPlaintextBits, NativeSealSetupBundle& out, std::shared_ptr<GpuSetupContext> execution = {},
        ProtocolCacheScopeView scope = {});
    bool preparePlaintextLiftDevice(const GpuRing& ring, u64 plaintextPrime,
        AlignedUnVec<u64>& residues);

    struct GpuProtocolScratch;
    struct GpuProtocolScratchDeleter
    {
        void operator()(GpuProtocolScratch* scratch) const noexcept;
    };
    struct GpuTransferScratch;
    struct GpuTransferScratchDeleter
    {
        void operator()(GpuTransferScratch* scratch) const noexcept;
    };
    struct GpuGaussianScratch;
    struct GpuGaussianScratchDeleter
    {
        void operator()(GpuGaussianScratch* scratch) const noexcept;
    };
    struct GpuZkScratch;
    struct GpuZkScratchDeleter
    {
        void operator()(GpuZkScratch* scratch) const noexcept;
    };

    class GpuTableReadState;
    class GpuTableReads;

    // A stream plus its reusable scratch. Scratch is released after draining
    // this stream and before releasing the native stream owner.
    class GpuStream
    {
    public:
        enum class RegionKind : u8 { Upload, Kernel, Download };
        // Debug timing belongs to this stream and is reported after it drains.
        std::atomic<u64>& regionCounter(RegionKind kind)
        {
            return mRegionUs[static_cast<unsigned>(kind)];
        }

        GpuStream();
        explicit GpuStream(LogVoleGpuStreamOptions options, std::shared_ptr<HostStepProfiler> profile = {});
        const LogVoleGpuStreamOptions& options() const { return mOptions; }
        HostStepProfiler* hostProfiler() const { return mHostProfiler.get(); }
        const std::shared_ptr<HostStepProfiler>& hostProfilerOwner() const { return mHostProfiler; }
        explicit GpuStream(std::shared_ptr<GpuMemoryPool> memory, LogVoleGpuStreamOptions options = {}, std::shared_ptr<HostStepProfiler> profile = {});
        // A lean non-blocking stream at the device's greatest supported
        // priority. It has no default index scratch; callers prepare their
        // workspace storage explicitly before query submission. Returns null
        // when the device exposes no useful
        // priority range or stream creation fails.
        static std::unique_ptr<GpuStream> createHighestPriority(LogVoleGpuStreamOptions options = {}, std::shared_ptr<HostStepProfiler> profile = {});
        ~GpuStream();
        GpuStream(const GpuStream&) = delete;
        GpuStream& operator=(const GpuStream&) = delete;

        void* raw() const { return mStream; }
        bool sync() const;
        // Explicit allocation owner retained by buffers and protocol scratch.
        const std::shared_ptr<OwnedGpuStream>& allocationOwner();
        GpuProtocolScratch& protocolScratch();
        GpuTransferScratch& transferScratch();
        GpuGaussianScratch& gaussianScratch();
        GaussianHostCompatibility& gaussianCompatibility() { return *mGaussianCompatibility; }
        GpuZkScratch& zkScratch();
        bool pipelinedUploadEnabled() const { return mPipelinedUpload; }

        // Upload a small u32 index array and return a device pointer valid
        // until the ring wraps. Wrap drains prior work on this stream before
        // reusing storage; ordinary index uploads do not allocate or wait.
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
        friend class GpuTableReads;
        friend class GpuExecutionContext;
        void recordTableRead(const std::shared_ptr<GpuTableReadState>& table);
        GpuStream(bool highestPriority, bool allocateScratch,
            std::shared_ptr<GpuMemoryPool> memory = {}, LogVoleGpuStreamOptions options = {}, std::shared_ptr<HostStepProfiler> profile = {},
            GaussianHostCompatibility* gaussianCompatibility = nullptr);
        bool ensureIndexScratch();

        // Execution-owned streams borrow the stable execution Impl's cache;
        // direct streams use their inline owner. Both outlive stream scratch.
        GaussianHostCompatibility mOwnedGaussianCompatibility;
        GaussianHostCompatibility* mGaussianCompatibility;
        std::atomic<u64> mRegionUs[3]{};
        const LogVoleGpuStreamOptions mOptions;
        const std::shared_ptr<HostStepProfiler> mHostProfiler;
        void* mStream = nullptr;
        std::shared_ptr<GpuMemoryPool> mMemory;
        std::shared_ptr<OwnedGpuStream> mAllocationOwner;
        // Weak reverse registrations let teardown release completed readers
        // from shared immutable tables without retaining those tables.
        std::vector<std::weak_ptr<GpuTableReadState>> mTableReads;
        std::unique_ptr<GpuProtocolScratch, GpuProtocolScratchDeleter> mProtocolScratch;
        std::unique_ptr<GpuTransferScratch, GpuTransferScratchDeleter> mTransferScratch;
        std::unique_ptr<GpuGaussianScratch, GpuGaussianScratchDeleter> mGaussianScratch;
        std::unique_ptr<GpuZkScratch, GpuZkScratchDeleter> mZkScratch;
        bool mHighestPriority = false;
        bool mPipelinedUpload = false;
        OwnedGpuBuffer mDeviceScratchStorage;
        PinnedHostBuffer mHostScratchStorage;
        PinnedHostBuffer mStagingStorage;
        u32* mDeviceScratch = nullptr;
        u32* mHostScratch = nullptr;
        std::size_t mScratchWords = 0;
        std::size_t mScratchUsed = 0;
        u8* mStaging = nullptr;
        std::size_t mStagingBytes = 0;
    };

    // Computation streams and scratch belong to this execution domain. Each
    // host worker has lazy main/sampling/readback streams, sharing one private
    // allocation pool. Join all users before releasing the last domain owner.
    // Native stream/buffer owners never refer back to this object.
    class GpuExecutionContext
    {
    public:
        explicit GpuExecutionContext(LogVoleExecutionOptions options = {},
            std::shared_ptr<HostStepProfiler> profiler = {},
            std::shared_ptr<const ProtocolCacheService> service = {},
            std::optional<bool> gpuAvailable = {});
        const LogVoleExecutionOptions& executionOptions() const { return mExecutionOptions; }
        bool gpuAvailable() const noexcept { return mGpuAvailable; }
        bool gpuEnabled() const noexcept { return mExecutionOptions.mUseGpu && mGpuAvailable; }
        HostStepProfiler* hostProfiler() const { return mHostProfiler.get(); }
        const std::shared_ptr<HostStepProfiler>& hostProfilerOwner() const { return mHostProfiler; }
        const std::shared_ptr<const ProtocolCacheService>& protocolService() const noexcept { return mProtocolService; }
        // Preserves the prefetch policy's device-zero name match, captured at
        // construction only for a GPU-enabled domain; not a current-device query.
        bool isH200() const noexcept;
        GaussianHostCompatibility& gaussianCompatibility();
        ~GpuExecutionContext();
        GpuExecutionContext(const GpuExecutionContext&) = delete;
        GpuExecutionContext& operator=(const GpuExecutionContext&) = delete;
        GpuStream& mainStream();
        GpuStream& sampleStream();
        // Readback does not allocate the compute lanes' index scratch.
        GpuStream& readbackStream();
        // Synchronous host materialization borrows its initiating worker's
        // lazy CPU partition. All children join before the caller reuses it.
        detail::CpuRowScratch& transferCpuScratch();
    private:
        friend bool bindContextExecution(RingNttContext& ctx,
            const std::shared_ptr<GpuExecutionContext>& execution);
        enum class Lane { Main, Sample, Readback };
        GpuStream& stream(Lane lane);
        struct Impl;
        const std::shared_ptr<const ProtocolCacheService> mProtocolService;
        std::shared_ptr<HostStepProfiler> mHostProfiler;
        std::unique_ptr<Impl> mImpl;
        const LogVoleExecutionOptions mExecutionOptions;
        const bool mGpuAvailable;
    };

    GpuStream& contextStream(const RingNttContext& ctx);
    GpuStream& contextSampleStream(const RingNttContext& ctx);

    // Select a session's execution and public operand owners while retaining
    // the immutable math record. Rebinding the same record in one domain
    // reuses its selected record; the domain's lookup owns only weak entries.
    bool bindContextExecution(RingNttContext& ctx,
        const std::shared_ptr<GpuExecutionContext>& execution);

    // Preserve the boolean failure convention of the protocol entry points.
    // The returned allocation retains its explicit stream even on early exit.
    inline OwnedGpuBuffer tryAllocateGpuBuffer(GpuStream& stream, std::size_t bytes)
    {
        try { return OwnedGpuBuffer(stream.allocationOwner(), bytes); }
        catch (...) { return {}; }
    }

    struct StreamDrain
    {
        GpuStream& mStream;
        bool mPending = true;
        // Use at the final completion boundary; no more work may be submitted
        // under this guard after a successful sync.
        bool sync()
        {
            const bool ok = mStream.sync();
            if (ok) mPending = false;
            return ok;
        }
        ~StreamDrain()
        {
            // Borrowed host backing may expire immediately after this guard.
            // A failed drain cannot safely return control to its destructors.
            if (mPending && !mStream.sync()) std::terminate();
        }
    };

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
    // direct pageable path; mPipelinedUpload opts into a double-buffered
    // pinned pipeline that can help platforms with a slower driver staging path.
    // The returned copy remains stream ordered and is not synchronised here.
    bool uploadFromHost(void* deviceDst, const void* src, std::size_t bytes, GpuStream& stream);

    // Setup-wire H2D sources of at least 1 MiB are registered after population
    // and retained when their storage comes from the reusable wire pool. Fresh
    // pool-owned D2H destinations attempt persistent registration and direct
    // transfer; unsupported or failed registration uses bounded staging.
    // Disabling mDirectDownload restores the prior fresh-D2H staging
    // policy for A/B profiling. Blocks registered by prior H2D reuse transfer
    // directly in either direction. Disabling mPinned restores ordinary
    // staged helpers. Both directions drain before returning, including failure,
    // and before releasing any temporary registration for external storage.
    bool downloadSetupWire(WireView wire, const void* deviceSrc, GpuStream& stream,
        const LogVoleWireOptions& options = {});
    bool uploadSetupWire(void* deviceDst, ConstWireView wire, GpuStream& stream,
        const LogVoleWireOptions& options = {});

    // Explicit native setup selects a role-local cache lane on device 0.
    // Factory construction still requires a nonzero owned protocol run.
    bool nativeSealBundleCacheRequested(ProtocolCacheRole role, const LogVoleExecutionOptions& settings, bool selectedGpu);

    // Upload a compact host matrix into pitched device rows. The caller keeps
    // src alive until stream completion; untouched device columns stay unused.
    bool uploadRowsFromHost(void* deviceDst, std::size_t dstPitch, const void* src,
        std::size_t rowBytes, std::size_t rows, GpuStream& stream);
    // Device source is a completed contiguous compact matrix; its owner must
    // survive the queued pitched D2D copy.
    bool copyRowsFromDevice(void* deviceDst, std::size_t dstPitch, const void* src,
        std::size_t rowBytes, std::size_t rows, GpuStream& stream);

    // Immutable constants may be read concurrently on several streams. Retain
    // native owners (never their scratch/context) and drain only at teardown.
    // The repeated-stream fast path performs no lock or allocation.
    class GpuTableReadState
    {
        friend class GpuTableReads;
        friend class GpuStream;
        void retire(OwnedGpuStream* stream) noexcept;
        std::atomic<OwnedGpuStream*> mRecent{nullptr};
        std::mutex mMutex;
        std::vector<std::shared_ptr<OwnedGpuStream>> mStreams;
    };

    class GpuTableReads
    {
    public:
        GpuTableReads() = default;
        GpuTableReads(const GpuTableReads&) = delete;
        GpuTableReads& operator=(const GpuTableReads&) = delete;
        void record(GpuStream& stream) const
        {
            const auto& owner = stream.allocationOwner();
            if (mState->mRecent.load(std::memory_order_acquire) != owner.get()) recordNew(stream, owner);
        }
        void wait() const noexcept;
    private:
        void recordNew(GpuStream& stream, const std::shared_ptr<OwnedGpuStream>& owner) const;
        std::shared_ptr<GpuTableReadState> mState = std::make_shared<GpuTableReadState>();
    };

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
            const RingParams& params, std::span<const u64> orderedPrimes,
            const RingResourceScope& owner, std::shared_ptr<GpuSetupContext> execution = {},
            const std::shared_ptr<const ProtocolCacheService>& fallbackService = {});
        // Publish an already certified native ring into the matching raw
        // role/mode lane. Existing sequential owners stay alive for borrowers.
        static bool publishRaw(const RingParams& params,
            std::span<const u64> orderedPrimes,
            const std::shared_ptr<GpuRing>& ready, const RingResourceScope& owner);

        ~GpuRing();
        GpuRing(const GpuRing&) = delete;
        GpuRing& operator=(const GpuRing&) = delete;

        u32 n() const { return mView.mN; }
        u32 rho() const { return mView.mRho; }
        std::size_t polyWords() const { return static_cast<std::size_t>(mView.mN) * mView.mRho; }
        std::size_t polyBytes() const { return polyWords() * sizeof(u64); }
        const LogVoleExecutionOptions& executionOptions() const { return mSetup->executionOptions(); }
        HostStepProfiler* hostProfiler() const { return mSetup->hostProfiler(); }
        const LogVoleGpuKernelOptions& kernelOptions() const { return mView.mKernelOptions; }
        const RingConstView& view(GpuStream& stream) const
        {
            mReads.record(stream);
            return mView;
        }
        // Host metadata inspection does not submit device reads.
        const RingConstView& metadata() const { return mView; }
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
        const std::shared_ptr<GpuSetupContext>& setupContext() const { return mSetup; }
        bool gpuEnabled() const noexcept { return mSetup && mSetup->gpuEnabled(); }

    private:
        GpuRing() = default;
        GpuTableReads mReads;
        friend bool buildNativeSealSetupBundleDevice(const RingParams&,
            u32, NativeSealSetupBundle&, std::shared_ptr<GpuSetupContext>, ProtocolCacheScopeView);
        bool init(const RingNttContext& ctx);
        bool initRaw(const RingParams& params, std::span<const u64> orderedPrimes);
        bool initDenoise(const RingNttContext& ctx);

        std::shared_ptr<GpuSetupContext> mSetup;
        KernelInitializationState mKernelInitialization;
        RingConstView mView{};
        DenoiseConstView mDenoise{};
        bool mDenoiseReady = false;

        std::vector<OwnedGpuBuffer> mOwned;
        // A cold native bundle can own ring and plaintext tables as two
        // disjoint slices of one allocation. Each immutable owner retains it.
        std::shared_ptr<OwnedGpuBuffer> mNativeSealBundleStorage;
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

    // GPU first-use overlap, selected by mContexts.mInitOverlap. Declare this
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
            const seal::SEALContext& batchingContext, const seal::BatchEncoder& encoder,
            const RingResourceScope& owner, ProtocolCacheScopeView scope = {});
        // Builds the plaintext NTT and SEAL batching permutation on the device.
        static std::shared_ptr<GpuPlainNtt> getRaw(u32 degree, u64 plaintextPrime,
            const RingResourceScope& owner, std::shared_ptr<GpuSetupContext> execution = {}, ProtocolCacheScopeView scope = {});
        // Admit a fully sealed private native-bundle owner into the immutable
        // role-keyed raw table cache. Call only at the host context commit
        // boundary; no table construction or D2H occurs here.
        static bool publishRaw(u32 degree, u64 plaintextPrime,
            const std::shared_ptr<GpuPlainNtt>& ready, const RingResourceScope& owner);

        ~GpuPlainNtt();
        GpuPlainNtt(const GpuPlainNtt&) = delete;
        GpuPlainNtt& operator=(const GpuPlainNtt&) = delete;

        const LogVoleExecutionOptions& executionOptions() const { return mSetup->executionOptions(); }
        HostStepProfiler* hostProfiler() const { return mSetup->hostProfiler(); }
        const LogVoleGpuKernelOptions& kernelOptions() const { return mView.mKernelOptions; }
        const RingConstView& view(GpuStream& stream) const
        {
            mReads.record(stream);
            return mView;
        }
        const RingConstView& metadata() const { return mView; }
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
        GpuTableReads mReads;
        friend bool buildNativeSealSetupBundleDevice(const RingParams&,
            u32, NativeSealSetupBundle&, std::shared_ptr<GpuSetupContext>, ProtocolCacheScopeView);
        bool init(const seal::SEALContext& batchingContext, const seal::BatchEncoder& encoder);
        bool initRaw(u32 degree, u64 plaintextPrime);

        std::shared_ptr<GpuSetupContext> mSetup;
        KernelInitializationState mKernelInitialization;
        RingConstView mView{};
        const u32* mSlotMap = nullptr;
        const u32* mInverseSlotMap = nullptr;
        u32 mSlotCount = 0;
        std::vector<OwnedGpuBuffer> mOwned;
        std::shared_ptr<OwnedGpuBuffer> mNativeSealBundleStorage;
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
        ProtocolCacheRunId mOwnerRunId = 0;
        std::shared_ptr<const ProtocolCacheService> mIdentityService;
    };

    // Device array of `count` polynomials laid out exactly like a
    // std::vector<RnsPoly> flattened, i.e. count * rho * N u64.
    class GpuPolyBuffer
    {
    public:
        GpuPolyBuffer() = default;
        explicit GpuPolyBuffer(const GpuRing& ring, std::size_t count, GpuStream& stream);
        ~GpuPolyBuffer();
        GpuPolyBuffer(GpuPolyBuffer&& other) noexcept;
        GpuPolyBuffer& operator=(GpuPolyBuffer&& other) noexcept;
        GpuPolyBuffer(const GpuPolyBuffer&) = delete;
        GpuPolyBuffer& operator=(const GpuPolyBuffer&) = delete;

        bool resize(const GpuRing& ring, std::size_t count, GpuStream& stream);
        // Layout-only operations do not need NTT/CRT tables. Validate the word
        // count and allocation size without bootstrapping a GpuRing.
        bool resizeWords(std::size_t polyWords, std::size_t count, GpuStream& stream);
        void release();

        // Host access is serialized by the caller. A new stream orders its use
        // after earlier uses and is retained through release, including reads.
        // A borrowed pointer may be queued on secondary streams only if those
        // uses are joined back to this stream before returning or unwinding.
        u64* data(GpuStream& stream) const
        {
            if (mData && mStorage.stream()->raw() != stream.raw())
                mStorage.handoff(stream.allocationOwner());
            return mData;
        }
        u64* poly(std::size_t idx, GpuStream& stream) const
        { return data(stream) + idx * mPolyWords; }
        // Identity/availability inspection only; does not authorize device use.
        const void* address() const { return mData; }
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
        bool downloadPipelined(std::vector<RnsPoly>& polys, GpuStream& stream, u32 workers, detail::CpuRowScratch& cpuScratch,
                               std::size_t srcOffset = 0, std::size_t count = 0, CpuBenchmarkState cpuBenchmark = {}) const;
        // Queues the copy without synchronising; the caller must sync.
        bool downloadAsync(RnsPoly& poly, std::size_t srcIdx, GpuStream& stream) const;
        bool zero(GpuStream& stream);

    private:
        mutable OwnedGpuBuffer mStorage;
        u64* mData = nullptr;
        std::size_t mCount = 0;
        std::size_t mPolyWords = 0;
        std::size_t mCapacity = 0;
    };

    // ---- primitive wrappers ----------------------------------------------
    // Each of these mirrors the identically named CPU routine.

    bool nttForward(const GpuRing& ring, u64* polys, u32 count, GpuStream& stream);
    bool nttInverse(const GpuRing& ring, u64* polys, u32 count, GpuStream& stream);

    bool denoiseComb(const GpuRing& ring, const u64* in, u64* out, u32 outCount, GpuStream& stream);
}

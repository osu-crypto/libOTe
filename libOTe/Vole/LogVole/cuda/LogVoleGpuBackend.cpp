#include "libOTe/Vole/LogVole/cuda/LogVoleGpuBackend.h"

#include "libOTe/Vole/LogVole/LogVoleArithmetic.h"
#include "libOTe/Vole/LogVole/LogVoleEncoding.h"
#include "libOTe/Vole/LogVole/LogVoleRuntime.h"
#include "libOTe/Vole/LogVole/LogVoleParallel.h"
#include "libOTe/Vole/LogVole/LogVolePublicCache.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuProtocol.h"

#include "seal/util/ntt.h"
#include "seal/util/rns.h"
#include "seal/util/uintarith.h"
#include "seal/util/uintarithmod.h"
#include "seal/util/uintarithsmallmod.h"
#include "seal/util/uintcore.h"

#include <cuda_runtime_api.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <thread>
#include <limits>
#include <map>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <tuple>
#include <unordered_map>

namespace osuCrypto::LogVole::gpu
{
    int currentDeviceOrdinal()
    {
        int device = -1;
        return cudaGetDevice(&device) == cudaSuccess ? device : -1;
    }

    namespace
    {
        bool h200LazyResourcesDefault()
        {
            int device = 0;
            cudaDeviceProp prop{};
            return cudaGetDevice(&device) == cudaSuccess &&
                cudaGetDeviceProperties(&prop, device) == cudaSuccess &&
                prop.major == 9 && std::strstr(prop.name, "H200") != nullptr;
        }

        LogVoleGpuStreamOptions captureStreamOptions(LogVoleGpuStreamOptions options)
        {
            if (!options.valid()) throw std::invalid_argument("Invalid LogVole GPU stream options");
            if (options.mLazyIndexScratch == LogVoleChoice::Automatic)
                options.mLazyIndexScratch = h200LazyResourcesDefault()
                    ? LogVoleChoice::Enabled : LogVoleChoice::Disabled;
            return options;
        }

        std::size_t alignUp(std::size_t v, std::size_t a)
        {
            return (v + a - 1) / a * a;
        }

        struct RingCacheKey
        {
            u32 mDegree = 0;
            std::vector<int> mBits;
            ProtocolCacheRole mRole = ProtocolCacheRole::Unspecified;

            bool operator==(const RingCacheKey& o) const
            {
                return mDegree == o.mDegree && mBits == o.mBits && mRole == o.mRole;
            }
        };

        struct RingCacheKeyHash
        {
            std::size_t operator()(const RingCacheKey& k) const
            {
                std::size_t h = std::hash<u32>{}(k.mDegree);
                h ^= std::hash<u8>{}(static_cast<u8>(k.mRole)) +
                    0x9e3779b9u + (h << 6) + (h >> 2);
                for (int b : k.mBits)
                {
                    h ^= std::hash<int>{}(b) + 0x9e3779b9u + (h << 6) + (h >> 2);
                }
                return h;
            }
        };

        using RingCache = std::unordered_map<RingCacheKey, std::shared_ptr<GpuRing>, RingCacheKeyHash>;

        struct RawRingCacheKey
        {
            u32 mDegree = 0;
            std::vector<u64> mPrimes;
            ProtocolCacheRole mRole = ProtocolCacheRole::Unspecified;
            bool mNativeRequested = false;
            bool operator==(const RawRingCacheKey& other) const
            {
                return mDegree == other.mDegree && mPrimes == other.mPrimes &&
                    mRole == other.mRole && mNativeRequested == other.mNativeRequested;
            }
        };

        struct RawRingCacheKeyHash
        {
            std::size_t operator()(const RawRingCacheKey& key) const
            {
                std::size_t h = std::hash<u32>{}(key.mDegree);
                h ^= std::hash<u8>{}(static_cast<u8>(key.mRole)) + 0x9e3779b9u + (h << 6) + (h >> 2);
                h ^= std::hash<bool>{}(key.mNativeRequested) +
                    0x9e3779b9u + (h << 6) + (h >> 2);
                for (u64 q : key.mPrimes)
                    h ^= std::hash<u64>{}(q) + 0x9e3779b9u + (h << 6) + (h >> 2);
                return h;
            }
        };

        using RawRingCache = std::unordered_map<RawRingCacheKey, std::shared_ptr<GpuRing>, RawRingCacheKeyHash>;
        using PlainKey = std::tuple<u64, u64, ProtocolCacheRole>;
        using PlainCache = std::vector<std::pair<PlainKey, std::shared_ptr<GpuPlainNtt>>>;
        using RawPlainKey = std::tuple<u32, u64, ProtocolCacheRole, bool>;
        using RawPlainCache = std::vector<std::pair<RawPlainKey, std::shared_ptr<GpuPlainNtt>>>;

        bool validRawPrimes(u32 n, std::span<const u64> primes)
        {
            if (n < 2 || n > 131072 || (n & (n - 1u)) || primes.empty() || primes.size() > 16) return false;
            for (std::size_t j = 0; j < primes.size(); ++j)
            {
                const u64 q = primes[j];
                if (q <= 2u * n || q >= (u64{1} << 60) || (q - 1u) % (2u * n)) return false;
                for (std::size_t k = 0; k < j; ++k)
                    if (primes[k] == q) return false;
            }
            return true;
        }

        // Setup needs no per-query index/staging scratch. Each explicit setup
        // domain retains reusable worker streams. Factory guards complete all
        // submitted work before releasing their borrows, so successive scratch
        // allocations can reuse the same stream's pool buckets. Distinct
        // domains and workers have independent streams.
        struct RawSetupStream
        {
            std::shared_ptr<GpuSetupContext> mExecution;
            std::shared_ptr<OwnedGpuStream> mOwner;
            void* mStream = nullptr;
            const std::shared_ptr<OwnedGpuStream>& allocationOwner() { return mOwner; }
            explicit RawSetupStream(std::shared_ptr<GpuSetupContext> execution,
                std::shared_ptr<const ProtocolCacheService> service = {})
            {
                try
                {
                    mExecution = execution ? std::move(execution) : std::make_shared<GpuSetupContext>(osuCrypto::LogVoleExecutionOptions{}, nullptr, std::move(service));
                    mOwner = mExecution->stream();
                    mStream = mOwner->raw();
                }
                catch (...)
                {
                    // Factory callers use a null stream as a clean decline.
                    mOwner.reset();
                    mExecution.reset();
                }
            }
            RawSetupStream(const RawSetupStream&) = delete;
            RawSetupStream& operator=(const RawSetupStream&) = delete;
            ~RawSetupStream()
            {
                // A failed launch/copy must drain before an arena or temporary
                // host record expires. The owner retains its native stream.
                if (mStream && !gpuStreamSync(mStream)) std::terminate();
            }
            bool sync() const { return mStream && gpuStreamSync(mStream); }
        };

        // Temporary setup records never escape their synchronized producer.
        // Reuse the explicit stream pool without consulting the ambient allocator.
        class RawScratchArena
        {
            OwnedGpuBuffer mStorage;
            std::size_t mUsed = 0;
        public:
            RawScratchArena(std::size_t bytes, RawSetupStream& stream)
            {
                try { mStorage = OwnedGpuBuffer(stream.allocationOwner(), bytes); }
                catch (...) {}
            }
            template<typename T> T* take(std::size_t count)
            {
                const auto offset = alignUp(mUsed, std::max<std::size_t>(alignof(T), 16u));
                if (!mStorage || offset > mStorage.size() || count > (mStorage.size() - offset) / sizeof(T))
                    return nullptr;
                mUsed = offset + count * sizeof(T);
                return reinterpret_cast<T*>(static_cast<u8*>(mStorage.data()) + offset);
            }
        };

        // One allocation keeps the generated tables contiguous and removes the
        // many small allocations/uploads in the host-built constant path.
        class RawConstantArena
        {
        public:
            RawConstantArena(std::size_t bytes, RawSetupStream& stream)
            {
                try { mStorage = OwnedGpuBuffer(stream.allocationOwner(), bytes); }
                catch (...) {}
            }
            explicit operator bool() const { return static_cast<bool>(mStorage); }
            template<typename T> T* take(std::size_t count)
            {
                // Some NTT kernels vector-load HostShoupOperand as
                // ulonglong2. Keep every suballocation at least 16-byte
                // aligned within the owning CUDA allocation.
                const auto offset = alignUp(mUsed,
                    std::max<std::size_t>(alignof(T), 16u));
                if (!mStorage || offset > mStorage.size() || count > (mStorage.size() - offset) / sizeof(T)) return nullptr;
                mUsed = offset + count * sizeof(T);
                return reinterpret_cast<T*>(static_cast<u8*>(mStorage.data()) + offset);
            }
            void publish(std::vector<OwnedGpuBuffer>& owned)
            {
                owned.push_back(std::move(mStorage));
            }
            OwnedGpuBuffer release()
            {
                return std::move(mStorage);
            }
        private:
            OwnedGpuBuffer mStorage;
            std::size_t mUsed = 0;
        };

        void allocateRawNttView(RawConstantArena& arena, RingConstView& view,
            u32 n, u32 rho)
        {
            view.mN = n;
            view.mRho = rho;
            while ((1u << view.mLogN) < n) ++view.mLogN;
            view.mMods = arena.take<HostModulus>(rho);
            const std::size_t words = static_cast<std::size_t>(rho) * n;
            view.mRoots = arena.take<HostShoupOperand>(words);
            view.mInvRoots = arena.take<HostShoupOperand>(words);
            view.mInvDegree = arena.take<HostShoupOperand>(rho);
            view.mScaledInvRoot = arena.take<HostShoupOperand>(rho);
        }

        void allocateRawNttView(RawConstantArena& arena, RingConstView& view,
            u32 n, std::span<const u64> primes)
        {
            allocateRawNttView(arena, view, n, static_cast<u32>(primes.size()));
            view.mMinModulus = *std::min_element(primes.begin(), primes.end());
            view.mMaxModulus = *std::max_element(primes.begin(), primes.end());
        }

        HostModulus toHostModulus(const seal::Modulus& m)
        {
            HostModulus h{};
            h.mValue = m.value();
            h.mRatio0 = m.const_ratio()[0];
            h.mRatio1 = m.const_ratio()[1];
            return h;
        }

        HostShoupOperand toHostShoup(const seal::util::MultiplyUIntModOperand& op)
        {
            HostShoupOperand h{};
            h.mOperand = op.operand;
            h.mQuotient = op.quotient;
            return h;
        }

        template<typename T>
        void* uploadVector(const std::vector<T>& host, std::vector<OwnedGpuBuffer>& owned,
            RawSetupStream& stream)
        {
            if (host.empty()) return nullptr;
            HostStep allocationStep(stream.mExecution->hostProfiler(), "setup GPU constants allocate");
            OwnedGpuBuffer storage;
            try { storage = OwnedGpuBuffer(stream.allocationOwner(), host.size() * sizeof(T)); }
            catch (...) { return nullptr; }
            void* d = storage.data();
            allocationStep.stop();
            if (!d) return nullptr;
            HostStep uploadStep(stream.mExecution->hostProfiler(), "setup GPU constants upload");
            if (!gpuMemcpyH2D(d, host.data(), host.size() * sizeof(T), stream.mStream)) return nullptr;
            owned.push_back(std::move(storage));
            return d;
        }
    }

    struct GpuTableCache::Impl
    {
        std::mutex ringMutex, rawRingMutex, plainMutex, rawPlainMutex;
        RingCache rings;
        RawRingCache rawRings;
        PlainCache plains;
        RawPlainCache rawPlains;
    };

    GpuTableCache::GpuTableCache(LogVoleExecutionOptions options, std::shared_ptr<HostStepProfiler> profiler)
        : mHostProfiler(options.mAdvanced.mHostStepProfile ? std::move(profiler) : nullptr),
          mImpl(std::make_unique<Impl>()), mExecutionOptions(options)
    {
        if (!mExecutionOptions.valid()) throw std::invalid_argument("Invalid LogVole advanced options");
        if (!mHostProfiler && mExecutionOptions.mAdvanced.mHostStepProfile)
            mHostProfiler = std::make_shared<HostStepProfiler>();
    }
    GpuTableCache::~GpuTableCache() = default;

    struct GpuSetupContext::Impl
    {
        std::mutex mutex;
        int device = -1;
        std::shared_ptr<GpuMemoryPool> memory;
        std::unordered_map<std::thread::id, std::shared_ptr<OwnedGpuStream>> workers;
    };

    GpuSetupContext::GpuSetupContext(LogVoleExecutionOptions options, std::shared_ptr<HostStepProfiler> profiler,
        std::shared_ptr<const ProtocolCacheService> service)
        : mProtocolService(service ? std::move(service) : ProtocolCacheService::create()),
          mHostProfiler(options.mAdvanced.mHostStepProfile ? std::move(profiler) : nullptr),
          mImpl(std::make_unique<Impl>()), mExecutionOptions(options)
    {
        if (!mExecutionOptions.valid()) throw std::invalid_argument("Invalid LogVole advanced options");
        if (!mHostProfiler && mExecutionOptions.mAdvanced.mHostStepProfile)
            mHostProfiler = std::make_shared<HostStepProfiler>();
    }
    GpuSetupContext::~GpuSetupContext() = default;

    std::shared_ptr<OwnedGpuStream> GpuSetupContext::stream()
    {
        std::lock_guard lock(mImpl->mutex);
        const int device = currentDeviceOrdinal();
        if (device < 0 || (mImpl->device >= 0 && device != mImpl->device))
            throw std::runtime_error("CUDA setup context device mismatch");
        // Bind before allocation: a failed pool creation can leave a native stream to reuse.
        mImpl->device = device;
        if (!mImpl->memory) mImpl->memory = std::make_shared<GpuMemoryPool>(device);
        auto& owner = mImpl->workers[std::this_thread::get_id()];
        if (!owner) owner = std::make_shared<OwnedGpuStream>(mImpl->memory);
        return owner;
    }

    bool dynamicSealSetupSupported(const RingParams& params)
    {
        if (params.mPolyModulusDegree < 1024u ||
            params.mPolyModulusDegree > 131072u ||
            (params.mPolyModulusDegree & (params.mPolyModulusDegree - 1u)) ||
            params.mCoeffModulusBits.empty() || params.mCoeffModulusBits.size() > 16u)
            return false;
        return std::all_of(params.mCoeffModulusBits.begin(), params.mCoeffModulusBits.end(),
            [](int bits) { return bits >= 2 && bits <= 60; });
    }

    bool nativeSealBundleCacheRequested(ProtocolCacheRole role, const LogVoleExecutionOptions& settings)
    {
        const auto& options = settings.mAdvanced.mContexts;
        if (!enabled(settings) ||
            (role != ProtocolCacheRole::Sender && role != ProtocolCacheRole::Receiver)) return false;
        return options.mNativeSealBundle &&
            available() && currentDeviceOrdinal() == 0;
    }

    bool selectSealCoeffModuliDevice(const RingParams& params,
        std::vector<u64>& orderedPrimes, std::shared_ptr<GpuSetupContext> execution)
    {
        HostStep step(execution ? execution->hostProfiler() : nullptr, "setup: dynamic GPU ring prime selection");
        if (!dynamicSealSetupSupported(params) || !available() || currentDeviceOrdinal() != 0)
            return false;
        const u32 rho = static_cast<u32>(params.mCoeffModulusBits.size());
        std::array<u8, 16u * sizeof(u64) + sizeof(u32)> hostRecord{};
        RawSetupStream stream(execution, execution ? nullptr : currentProtocolCacheScope().mRunId.serviceOwner());
        if (!stream.mStream) return false;
        RawScratchArena arena(256u, stream);
        auto* bits = arena.take<int>(rho);
        const std::size_t recordBytes = static_cast<std::size_t>(rho) * sizeof(u64) + sizeof(u32);
        auto* record = arena.take<u8>(recordBytes);
        auto* primes = reinterpret_cast<u64*>(record);
        auto* status = record ? reinterpret_cast<u32*>(record + rho * sizeof(u64)) : nullptr;
        if (!bits || !primes || !status ||
            !gpuMemcpyH2D(bits, params.mCoeffModulusBits.data(), rho * sizeof(int), stream.mStream) ||
            !launchSelectSealCoeffModuli(params.mPolyModulusDegree, bits, rho,
                primes, status, stream.mStream)) return false;
        std::vector<u64> next(rho);
        u32 result = ~u32{0};
        if (!gpuMemcpyD2H(hostRecord.data(), record, recordBytes, stream.mStream) ||
            !stream.sync()) return false;
        std::memcpy(next.data(), hostRecord.data(), rho * sizeof(u64));
        std::memcpy(&result, hostRecord.data() + rho * sizeof(u64), sizeof(result));
        if (result) return false;
        orderedPrimes = std::move(next);
        return true;
    }

    bool selectSealPlainModulusDevice(u32 n, u32 requestedBits, u64 minimumQ,
        u64& selectedPrime, u32& selectedBits, std::shared_ptr<GpuSetupContext> execution)
    {
        HostStep step(execution ? execution->hostProfiler() : nullptr, "setup: dynamic GPU plaintext prime selection");
        if (n < 1024u || n > 131072u || (n & (n - 1u)) || !requestedBits ||
            minimumQ <= 2u * n || !available() || currentDeviceOrdinal() != 0)
            return false;
        std::array<u8, sizeof(u64) + 2u * sizeof(u32)> hostRecord{};
        RawSetupStream stream(execution, execution ? nullptr : currentProtocolCacheScope().mRunId.serviceOwner());
        if (!stream.mStream) return false;
        RawScratchArena arena(128u, stream);
        auto* record = arena.take<u8>(sizeof(u64) + 2u * sizeof(u32));
        auto* prime = reinterpret_cast<u64*>(record);
        auto* bits = record ? reinterpret_cast<u32*>(record + sizeof(u64)) : nullptr;
        auto* status = record ? reinterpret_cast<u32*>(record + sizeof(u64) + sizeof(u32)) : nullptr;
        if (!prime || !bits || !status ||
            !launchSelectSealPlainModulus(n, requestedBits, minimumQ,
                prime, bits, status, stream.mStream)) return false;
        u64 nextPrime = 0;
        u32 nextBits = 0, result = ~u32{0};
        if (!gpuMemcpyD2H(hostRecord.data(), record, hostRecord.size(), stream.mStream) ||
            !stream.sync()) return false;
        std::memcpy(&nextPrime, hostRecord.data(), sizeof(nextPrime));
        std::memcpy(&nextBits, hostRecord.data() + sizeof(u64), sizeof(nextBits));
        std::memcpy(&result, hostRecord.data() + sizeof(u64) + sizeof(u32), sizeof(result));
        if (result || !nextPrime || !nextBits) return false;
        selectedPrime = nextPrime;
        selectedBits = nextBits;
        return true;
    }

    bool preparePlaintextLiftDevice(const GpuRing& ring, u64 plaintextPrime,
        AlignedUnVec<u64>& residues)
    {
        HostStep step(ring.hostProfiler(), "setup: dynamic GPU plaintext lift");
        const auto& view = ring.metadata();
        if (!ring.n() || !ring.rho() || ring.rho() > 16u ||
            plaintextPrime <= 2u * ring.n() || plaintextPrime >= view.mMinModulus ||
            !view.mBaseProd || !available() || currentDeviceOrdinal() != 0) return false;
        std::array<u8, 16u * sizeof(u64) + sizeof(u32)> hostRecord{};
        RawSetupStream stream(ring.setupContext());
        if (!stream.mStream) return false;
        RawScratchArena arena(256u, stream);
        const std::size_t recordBytes = static_cast<std::size_t>(ring.rho()) * sizeof(u64) + sizeof(u32);
        auto* record = arena.take<u8>(recordBytes);
        auto* output = reinterpret_cast<u64*>(record);
        auto* status = record ? reinterpret_cast<u32*>(record + ring.rho() * sizeof(u64)) : nullptr;
        if (!output || !status ||
            !launchPreparePlaintextLift(view, plaintextPrime, output, status, stream.mStream))
            return false;
        std::vector<u64> next(ring.rho());
        u32 result = ~u32{0};
        if (!gpuMemcpyD2H(hostRecord.data(), record, recordBytes, stream.mStream) ||
            !stream.sync()) return false;
        std::memcpy(next.data(), hostRecord.data(), next.size() * sizeof(u64));
        std::memcpy(&result, hostRecord.data() + next.size() * sizeof(u64), sizeof(result));
        if (result) return false;
        residues.resize(next.size());
        std::copy(next.begin(), next.end(), residues.begin());
        return true;
    }

    bool buildNativeSealSetupBundleDevice(const RingParams& params,
        u32 requestedPlaintextBits, NativeSealSetupBundle& out, std::shared_ptr<GpuSetupContext> execution,
        ProtocolCacheScopeView scope)
    {
        HostStep step(execution ? execution->hostProfiler() : nullptr, "setup: bundled native GPU SEAL factories");
        const LogVoleGpuContextOptions defaults;
        const auto& options = execution ? execution->executionOptions().mAdvanced.mContexts : defaults;
        if (!options.mNativeSealBundle || !options.mLightweightRing ||
            !options.mLightweightCrt || options.mFullModChain || !options.mBatchingSingleLimb ||
            !dynamicSealSetupSupported(params) ||
            requestedPlaintextBits < 2u || !available() ||
            currentDeviceOrdinal() != 0) return false;
        const auto ownerScope = scope;
        if ((ownerScope.mRole != ProtocolCacheRole::Sender &&
             ownerScope.mRole != ProtocolCacheRole::Receiver) ||
            !ownerScope.mRunId) return false;
        if (execution && execution->protocolService().get() != ownerScope.mRunId.mService) return false;
        const u32 n = params.mPolyModulusDegree;
        const u32 rho = static_cast<u32>(params.mCoeffModulusBits.size());
        const std::size_t words = static_cast<std::size_t>(n) * rho;
        // One arena contains the ring and plaintext NTT/CRT tables, ephemeral
        // stage scratch, and the single required q/p/lift/status host record.
        // Its bound is the sum of the previously independent raw arenas plus
        // room for aligned metadata and optional H200 gadget constants.
        const std::size_t ringBytes =
            words * (2u * sizeof(HostShoupOperand) + 2u * sizeof(double)) + 16384u;
        const std::size_t plainBytes =
            static_cast<std::size_t>(n) *
                (2u * sizeof(HostShoupOperand) + 2u * sizeof(u32)) + 1024u;
        const std::size_t capacity = ringBytes + plainBytes + 4096u;
        try
        {
            constexpr std::size_t maxRecordBytes =
                16u * 2u * sizeof(u64) + sizeof(u64) + 6u * sizeof(u32);
            std::array<u8, maxRecordBytes> hostRecord{};
            RawSetupStream stream(execution, execution ? nullptr : ownerScope.mRunId.serviceOwner());
            if (!stream.mStream) return false;
            RawConstantArena arena(capacity, stream);
            if (!arena) return false;
            const std::size_t recordBytes =
                static_cast<std::size_t>(rho) * 2u * sizeof(u64) +
                sizeof(u64) + 6u * sizeof(u32);
            auto* record = arena.take<u8>(recordBytes);
            if (!record) return false;
            auto* orderedQ = reinterpret_cast<u64*>(record);
            auto* selectedP = orderedQ + rho;
            auto* lift = selectedP + 1u;
            auto* selectedBits = reinterpret_cast<u32*>(lift + rho);
            auto* fiveStatuses = selectedBits + 1u;

            std::shared_ptr<GpuRing> ring(new GpuRing());
            std::shared_ptr<GpuPlainNtt> plain(new GpuPlainNtt());
            if (!prepareKernelDispatch(ring->mView, stream.mExecution->executionOptions().mAdvanced.mKernels) ||
                !prepareKernelDispatch(plain->mView, stream.mExecution->executionOptions().mAdvanced.mKernels)) return false;
            ring->mParams = params;
            allocateRawNttView(arena, ring->mView, n, rho);
            auto* ringScratch = arena.take<u64>(3u * rho);
            ring->mView.mBaseProd = arena.take<u64>(rho);
            ring->mView.mBaseProdHalf = arena.take<u64>(rho);
            ring->mView.mPuncturedProd = arena.take<u64>(rho * rho);
            ring->mView.mInvPuncturedProd = arena.take<HostShoupOperand>(rho);
            ring->mView.mGarnerInv = arena.take<HostShoupOperand>(rho * rho);
            ring->mCrtLift = arena.take<u64>(rho);
            ring->mInvCrtLift = arena.take<u64>(rho);
            ring->mSampleMaxMultiple = arena.take<u64>(rho);
            ring->mDenoise.mQ = orderedQ;
            ring->mDenoise.mMods = ring->mView.mMods;
            ring->mDenoise.mCrtLiftModTarget = ring->mCrtLift;
            ring->mDenoise.mInvCrtLiftModTarget = ring->mInvCrtLift;
            if (rho > 1u)
            {
                const std::size_t reducedWords = rho * (rho - 1u);
                ring->mDenoise.mSrcLimb = arena.take<u32>(reducedWords);
                ring->mDenoise.mCrtInvPunctured = arena.take<u64>(reducedWords);
                ring->mDenoise.mPuncturedProdModTarget = arena.take<u64>(reducedWords);
                ring->mDenoise.mCrtInvPuncturedShoup =
                    arena.take<HostShoupOperand>(reducedWords);
                ring->mDenoise.mScaledPuncturedShoup =
                    arena.take<HostShoupOperand>(reducedWords);
                ring->mDenoise.mFracInvLo = arena.take<u64>(reducedWords);
                ring->mDenoise.mFracInvHi = arena.take<u64>(reducedWords);
                ring->mDenoise.mInvCrtLiftShoup = arena.take<HostShoupOperand>(rho);
            }
            const bool fp52Shape = h200LazyResourcesDefault() &&
                n == 16384u && rho == 8u &&
                std::all_of(params.mCoeffModulusBits.begin(),
                    params.mCoeffModulusBits.end(),
                    [](int bits) { return bits == 52; });
            const u32 packedMode = ring->mView.mKernelOptions.mNoGoldH200PackedRoots;
            if (fp52Shape)
            {
                if (packedMode & 1u)
                    ring->mView.mFp52InvRoots = arena.take<double>(words);
                if (packedMode & 2u)
                    ring->mView.mFp52Roots = arena.take<double>(words);
            }
            allocateRawNttView(arena, plain->mView, n, 1u);
            auto* plainScratch = arena.take<u64>(3u);
            auto* slotMap = arena.take<u32>(n);
            auto* inverseSlotMap = arena.take<u32>(n);
            if (!ringScratch || !ring->mView.mBaseProd ||
                !ring->mView.mBaseProdHalf || !ring->mView.mPuncturedProd ||
                !ring->mView.mInvPuncturedProd || !ring->mView.mGarnerInv ||
                !ring->mCrtLift || !ring->mInvCrtLift ||
                !ring->mSampleMaxMultiple || !plainScratch ||
                !slotMap || !inverseSlotMap)
                return false;
            if (!launchNativeSealSetupBundle(
                    ring->mView, ring->mDenoise, plain->mView,
                    params.mCoeffModulusBits.data(), rho,
                    requestedPlaintextBits, orderedQ, selectedP, selectedBits,
                    lift, fiveStatuses, ringScratch, plainScratch,
                    const_cast<u64*>(ring->mCrtLift),
                    const_cast<u64*>(ring->mInvCrtLift),
                    const_cast<u64*>(ring->mSampleMaxMultiple),
                    slotMap, inverseSlotMap, stream.mStream))
                return false;
            if (!gpuMemcpyD2H(hostRecord.data(), record, recordBytes,
                    stream.mStream) || !stream.sync())
                return false;
            std::vector<u64> hostQ(rho);
            std::vector<u64> hostLift(rho);
            u64 hostP = 0;
            u32 hostBits = 0;
            std::array<u32, 5> hostStatuses{};
            std::memcpy(hostQ.data(), hostRecord.data(), rho * sizeof(u64));
            std::memcpy(&hostP, hostRecord.data() + rho * sizeof(u64),
                sizeof(hostP));
            std::memcpy(hostLift.data(),
                hostRecord.data() + (rho + 1u) * sizeof(u64),
                rho * sizeof(u64));
            std::memcpy(&hostBits,
                hostRecord.data() + (2u * rho + 1u) * sizeof(u64),
                sizeof(hostBits));
            std::memcpy(hostStatuses.data(),
                hostRecord.data() + (2u * rho + 1u) * sizeof(u64) +
                    sizeof(hostBits),
                hostStatuses.size() * sizeof(u32));
            if (std::any_of(hostStatuses.begin(), hostStatuses.end(),
                    [](u32 status) { return status != 0; }) ||
                !validRawPrimes(n, hostQ) ||
                !validRawPrimes(n, std::span<const u64>(&hostP, 1u)) ||
                !hostBits || hostBits > requestedPlaintextBits ||
                hostP >= *std::min_element(hostQ.begin(), hostQ.end()) ||
                hostLift.size() != rho)
                return false;
            for (u32 j = 0; j < rho; ++j)
                if (hostLift[j] >= hostQ[j]) return false;
            for (u32 j = 0; j < rho; ++j)
            {
                u32 actualBits = 0;
                for (u64 value = hostQ[j]; value; value >>= 1) ++actualBits;
                if (actualBits != static_cast<u32>(params.mCoeffModulusBits[j]))
                    return false;
            }
            u32 actualPlainBits = 0;
            for (u64 value = hostP; value; value >>= 1) ++actualPlainBits;
            // The supplied view is immutable throughout this synchronous call.
            if (actualPlainBits != hostBits)
                return false;

            ring->mView.mMinModulus =
                *std::min_element(hostQ.begin(), hostQ.end());
            ring->mView.mMaxModulus =
                *std::max_element(hostQ.begin(), hostQ.end());
            plain->mView.mMinModulus = hostP;
            plain->mView.mMaxModulus = hostP;
            ring->mHostModuli = hostQ;
            plain->mSlotMap = slotMap;
            plain->mInverseSlotMap = inverseSlotMap;
            plain->mSlotCount = n;
            if (fp52Shape && h200Fp52GadgetConstantsEnabled(ring->mView.mKernelOptions))
            {
                const bool prediv = h200Fp52GadgetPredivEnabled(ring->mView.mKernelOptions);
                auto* constants = arena.take<double>(prediv ? 144u : 80u);
                if (!constants) return false;
                auto* ratios = prediv ? constants + 80u : nullptr;
                if (!launchPrepareH200Fp52GadgetConstants(
                        ring->mView, constants, stream.mStream, ratios))
                    return false;
                ring->mView.mFp52GadgetConstants = constants;
                ring->mView.mFp52GadgetRatios = ratios;
            }
            if (!prepareH200RootPersistence(ring->mView) || !stream.sync())
                return false;
            // Only after the final status/owner check and all stream work
            // complete can the shared immutable allocation leave the arena.
            auto storage = std::make_shared<OwnedGpuBuffer>(arena.release());
            ring->mSetup = stream.mExecution;
            plain->mSetup = stream.mExecution;
            ring->mNativeSealBundleStorage = storage;
            plain->mNativeSealBundleStorage = std::move(storage);
            ring->mDenoiseReady = rho > 1u;
            ring->mRaw = true;
            ring->mRawOwnerRole = ownerScope.mRole;
            plain->mNativeBundleOwnerRole = ownerScope.mRole;
            NativeSealSetupBundle next{};
            next.mOrderedPrimes = std::move(hostQ);
            next.mPlaintextPrime = hostP;
            next.mSelectedPlaintextBits = hostBits;
            next.mPlaintextLift.resize(hostLift.size());
            std::copy(hostLift.begin(), hostLift.end(),
                next.mPlaintextLift.begin());
            next.mRing = std::move(ring);
            next.mPlainNtt = std::move(plain);
            next.mOwnerRole = ownerScope.mRole;
            next.mOwnerRunId = ownerScope.mRunId;
            next.mIdentityService = ownerScope.mRunId.serviceOwner();
            out = std::move(next);
            return true;
        }
        catch (...) { return false; }
    }

    bool available()
    {
        static const bool ok = gpuDeviceAvailable();
        return ok;
    }

    std::string deviceDescription()
    {
        if (!available()) return "no CUDA device";
        return gpuDeviceName();
    }

    namespace
    {
        struct TransferStaging
        {
            PinnedHostBuffer mStorage;
            u8* mPinned = nullptr;
            void* mEvent[2]{nullptr, nullptr};
            bool mPending[2]{false, false};

            ~TransferStaging()
            {
                // GpuStream drains before destroying any transfer scratch.
                gpuEventDestroy(mEvent[0]);
                gpuEventDestroy(mEvent[1]);
            }
            bool prepareEvents()
            {
                for (auto& event : mEvent) if (!event) event = gpuEventCreate();
                return mEvent[0] && mEvent[1];
            }
            bool reserve(GpuStream& stream, std::size_t bytes, std::size_t minimum = 4096)
            {
                if (!stream.raw()) return false;
                if (bytes > mStorage.size())
                {
                    std::size_t wanted = std::max(minimum, mStorage.size());
                    while (wanted < bytes)
                    {
                        if (wanted > std::numeric_limits<std::size_t>::max() / 2) return false;
                        wanted *= 2;
                    }
                    try
                    {
                        PinnedHostBuffer next(wanted);
                        if (mStorage.data() && !stream.sync()) return false;
                        mStorage = std::move(next);
                        mPinned = static_cast<u8*>(mStorage.data());
                        mPending[0] = mPending[1] = false;
                    }
                    catch (...) { return false; }
                }
                return mPinned && prepareEvents();
            }
        };

        struct DrainTransferOnFailure
        {
            GpuStream& stream;
            bool completed = false;
            ~DrainTransferOnFailure()
            {
                if (!completed && !stream.sync()) std::terminate();
            }
        };
    }

    struct GpuTransferScratch
    {
        TransferStaging download;
        TransferStaging upload;
        TransferStaging polynomials;
    };

    void GpuTransferScratchDeleter::operator()(GpuTransferScratch* scratch) const noexcept
    {
        delete scratch;
    }

    GpuTransferScratch& GpuStream::transferScratch()
    {
        if (!mTransferScratch) mTransferScratch.reset(new GpuTransferScratch());
        return *mTransferScratch;
    }

    // ---- GpuStream --------------------------------------------------------

    GpuStream::GpuStream() : GpuStream(false, true) {}

    GpuStream::GpuStream(LogVoleGpuStreamOptions options, std::shared_ptr<HostStepProfiler> profile)
        : GpuStream(false, true, {}, options, profile) {}

    GpuStream::GpuStream(std::shared_ptr<GpuMemoryPool> memory, LogVoleGpuStreamOptions options, std::shared_ptr<HostStepProfiler> profile)
        : GpuStream(false, true, std::move(memory), options, profile) {}

    GpuStream::GpuStream(bool highestPriority, bool allocateScratch,
        std::shared_ptr<GpuMemoryPool> memory, LogVoleGpuStreamOptions options, std::shared_ptr<HostStepProfiler> profile)
        : mOptions(captureStreamOptions(options)), mHostProfiler(std::move(profile)), mMemory(std::move(memory))
    {
        if (highestPriority)
        {
            int leastPriority = 0;
            int greatestPriority = 0;
            cudaStream_t stream = nullptr;
            if (cudaDeviceGetStreamPriorityRange(&leastPriority, &greatestPriority) == cudaSuccess &&
                greatestPriority < leastPriority &&
                cudaStreamCreateWithPriority(
                    &stream, cudaStreamNonBlocking, greatestPriority) == cudaSuccess)
            {
                mStream = stream;
                mHighestPriority = true;
            }
        }
        else
        {
            mStream = gpuStreamCreate();
        }
        mPipelinedUpload = mOptions.mPipelinedUpload;
        if (!mStream || !allocateScratch) return;
        mScratchWords = std::size_t(mOptions.mIndexScratchKiB) * 256u;
        if (mOptions.mLazyIndexScratch == LogVoleChoice::Disabled) (void)ensureIndexScratch();
    }

    std::unique_ptr<GpuStream> GpuStream::createHighestPriority(LogVoleGpuStreamOptions options, std::shared_ptr<HostStepProfiler> profile)
    {
        auto stream = std::unique_ptr<GpuStream>(new GpuStream(true, false, {}, options, profile));
        if (!stream->mStream || !stream->mHighestPriority) return nullptr;
        return stream;
    }

    GpuStream::~GpuStream()
    {
        if (!mStream) return;
        if (!gpuStreamSync(mStream)) std::terminate();
        // Every registered table read completed before its native owner is
        // released. Shared tables must not accumulate streams from past sessions.
        for (const auto& weak : mTableReads)
            if (auto table = weak.lock()) table->retire(mAllocationOwner.get());
        mTableReads.clear();
        // Explicit dependency order, independent of which scratch accessor was
        // called first. No scratch destructor can observe a destroyed stream.
        mProtocolScratch.reset();
        mTransferScratch.reset();
        mGaussianScratch.reset();
        mZkScratch.reset();
        mDeviceScratchStorage.reset();
        mHostScratchStorage.reset();
        mStagingStorage.reset();
        if (!mAllocationOwner) gpuStreamDestroy(mStream);
    }

    const std::shared_ptr<OwnedGpuStream>& GpuStream::allocationOwner()
    {
        if (!mAllocationOwner)
        {
            if (!mStream) throw std::runtime_error("CUDA stream is unavailable");
            const int device = currentDeviceOrdinal();
            if (device < 0) throw std::runtime_error("CUDA device is unavailable");
            if (!mMemory) mMemory = std::make_shared<GpuMemoryPool>(device);
            if (mMemory->device() != device)
                throw std::runtime_error("CUDA stream allocation device mismatch");
            mAllocationOwner = std::make_shared<OwnedGpuStream>(mMemory, mStream);
        }
        return mAllocationOwner;
    }

    void GpuStream::recordTableRead(const std::shared_ptr<GpuTableReadState>& table)
    {
        // Long-lived streams may see short-lived operand tables. Do not retain
        // their expired weak control blocks for the rest of the session.
        mTableReads.erase(std::remove_if(mTableReads.begin(), mTableReads.end(),
            [](const auto& weak) { return weak.expired(); }), mTableReads.end());
        mTableReads.emplace_back(table);
    }

    bool GpuStream::ensureIndexScratch()
    {
        if (mDeviceScratch && mHostScratch) return true;
        if (!mScratchWords) return false;
        try
        {
            const auto bytes = mScratchWords * sizeof(u32);
            PinnedHostBuffer host(bytes);
            OwnedGpuBuffer device(allocationOwner(), bytes);
            mHostScratchStorage = std::move(host);
            mDeviceScratchStorage = std::move(device);
            mHostScratch = static_cast<u32*>(mHostScratchStorage.data());
            mDeviceScratch = static_cast<u32*>(mDeviceScratchStorage.data());
            return true;
        }
        catch (...) { return false; }
    }

    u8* GpuStream::staging(std::size_t bytes)
    {
        if (!mStream) return nullptr;
        if (bytes <= mStagingBytes) return mStaging;
        // Preserve geometric reuse without routing through a process-wide pool.
        std::size_t want = mStagingBytes ? mStagingBytes : (std::size_t(8) << 20);
        while (want < bytes)
        {
            if (want > std::numeric_limits<std::size_t>::max() / 2) return nullptr;
            want *= 2;
        }
        try
        {
            PinnedHostBuffer next(want);
            if (mStaging && !sync()) return nullptr;
            mStagingStorage = std::move(next);
            mStaging = static_cast<u8*>(mStagingStorage.data());
            mStagingBytes = want;
            return mStaging;
        }
        catch (...) { return nullptr; }
    }

    bool GpuStream::sync() const
    {
        return gpuStreamSync(mStream);
    }

    void GpuStream::reset()
    {
        // Deliberately does *not* synchronise or rewind.
        //
        // It used to drain the stream so the index ring buffer could be rewound
        // safely, but it is called at the top of every GPU entry point, so that
        // was a full device wait per call - 209 stream synchronises totalling
        // 234 ms in one query. The buffer does not need rewinding here: it is a
        // ring, and uploadIdx already drains and rewinds when an upload would
        // actually wrap past the end, which is rare because index arrays are
        // tiny. Same invariant, paid only when it is needed.
    }

    const u32* GpuStream::uploadIdx(std::span<const u32> idx)
    {
        if (idx.empty()) return nullptr;
        // Most sampler/worker streams never upload an index array. Avoid
        // allocating and pinning their ring until it is actually needed.
        // Highest-priority lean streams have mScratchWords==0 and stay lean.
        if (idx.size() > mScratchWords || !ensureIndexScratch()) return nullptr;
        if (idx.size() > mScratchWords - mScratchUsed)
        {
            // Wrapping must finish reads of both the host and device ring.
            if (!sync()) return nullptr;
            mScratchUsed = 0;
        }
        const std::size_t off = mScratchUsed;
        std::copy(idx.begin(), idx.end(), mHostScratch + off);
        if (!gpuMemcpyH2D(mDeviceScratch + off, mHostScratch + off, idx.size() * sizeof(u32), mStream))
        {
            return nullptr;
        }
        mScratchUsed = alignUp(off + idx.size(), 4);
        return mDeviceScratch + off;
    }

    struct GpuExecutionContext::Impl
    {
        struct Worker
        {
            std::unique_ptr<GpuStream> main, sample, readback;
        };
        std::mutex mutex;
        int device = -1;
        std::shared_ptr<GpuMemoryPool> memory;
        std::unordered_map<std::thread::id, Worker> workers;
        using Record = std::weak_ptr<const RingNttContext>;
        std::map<Record, Record, std::owner_less<Record>> contexts;
    };

    GpuExecutionContext::GpuExecutionContext(LogVoleExecutionOptions options, std::shared_ptr<HostStepProfiler> profiler,
        std::shared_ptr<const ProtocolCacheService> service)
        : mProtocolService(service ? std::move(service) : ProtocolCacheService::create()),
          mHostProfiler(options.mAdvanced.mHostStepProfile ? std::move(profiler) : nullptr),
          mImpl(std::make_unique<Impl>()), mExecutionOptions(options)
    {
        if (!mExecutionOptions.valid()) throw std::invalid_argument("Invalid LogVole advanced options");
        if (!mHostProfiler && mExecutionOptions.mAdvanced.mHostStepProfile)
            mHostProfiler = std::make_shared<HostStepProfiler>();
    }
    GpuExecutionContext::~GpuExecutionContext() = default;

    GpuStream& GpuExecutionContext::stream(Lane lane)
    {
        std::lock_guard lock(mImpl->mutex);
        const int device = currentDeviceOrdinal();
        if (device < 0 || (mImpl->device >= 0 && mImpl->device != device))
            throw std::runtime_error("CUDA execution context device mismatch");
        mImpl->device = device;
        if (!mImpl->memory) mImpl->memory = std::make_shared<GpuMemoryPool>(device);
        auto& worker = mImpl->workers[std::this_thread::get_id()];
        auto& stream = lane == Lane::Readback ? worker.readback :
            lane == Lane::Sample ? worker.sample : worker.main;
        if (!stream)
            stream.reset(new GpuStream(false, lane != Lane::Readback, mImpl->memory, mExecutionOptions.mAdvanced.mStreams, mHostProfiler));
        return *stream;
    }

    GpuStream& GpuExecutionContext::mainStream() { return stream(Lane::Main); }
    GpuStream& GpuExecutionContext::sampleStream() { return stream(Lane::Sample); }
    GpuStream& GpuExecutionContext::readbackStream() { return stream(Lane::Readback); }

    bool bindContextExecution(RingNttContext& ctx,
        const std::shared_ptr<GpuExecutionContext>& execution)
    {
        if (!execution || !ctx.mFactory ||
            execution->protocolService() != ctx.mFactory->protocolService() ||
            execution->executionOptions() != ctx.mExecutionOptions ||
            !validateRingContextMetadata(ctx)) return false;
        if (ctx.mFactoryOwner && ctx.mFactoryOwner->mGpuExecution == execution &&
            ctx.mGpuExecution == execution) return true;

        // Selected records may retain a math parent, but neither a domain nor
        // its native streams owns a selected record. Unwrap previous selections
        // so rebinding never retains another session's execution or public cache.
        auto base = ctx.mFactoryOwner;
        while (base && base->mFactoryOwner) base = base->mFactoryOwner;
        if (!base)
        {
            auto privateMath = ctx;
            privateMath.mGpuExecution.reset();
            privateMath.mPublicCache.reset();
            base = std::make_shared<const RingNttContext>(std::move(privateMath));
        }

        std::shared_ptr<const RingNttContext> selected;
        {
            std::lock_guard lock(execution->mImpl->mutex);
            auto& records = execution->mImpl->contexts;
            for (auto it = records.begin(); it != records.end(); )
                if (it->first.expired() || it->second.expired()) it = records.erase(it);
                else ++it;
            auto& slot = records[base];
            selected = slot.lock();
            if (!selected)
            {
                auto next = *base;
                next.mFactoryOwner = base;
                next.mCrtFactory = ctx.mCrtFactory;
                next.mGpuExecution = execution;
                next.mHostProfiler = execution->hostProfilerOwner();
                next.mPublicCache = std::make_shared<PublicPolynomialCache>();
                selected = std::make_shared<const RingNttContext>(std::move(next));
                slot = selected;
            }
        }
        // Preserve the factory's exact CPU view when the backend is disabled.
        return makeRingNttContext(ctx.mParams, ctx, selected);
    }

    GpuStream& contextStream(const RingNttContext& ctx)
    {
        if (!ctx.mGpuExecution) throw std::invalid_argument("Missing CUDA execution owner");
        return ctx.mGpuExecution->mainStream();
    }

    GpuStream& contextSampleStream(const RingNttContext& ctx)
    {
        if (!ctx.mGpuExecution) throw std::invalid_argument("Missing CUDA execution owner");
        return ctx.mGpuExecution->sampleStream();
    }

    bool downloadToHost(void* dst, const void* deviceSrc, std::size_t bytes, GpuStream& stream)
    {
        if (bytes == 0) return true;
        if (!dst || !deviceSrc || !stream.raw()) return false;

        // 16 MiB per buffer keeps the pinned footprint at 32 MiB while still
        // being large enough that each transfer reaches peak PCIe bandwidth.
        // These buffers are dedicated to downloads rather than shared with
        // GpuStream::staging, which is sized by the largest polynomial batch and
        // would otherwise be reallocated back and forth between the two sizes.
        constexpr std::size_t kChunk = std::size_t(16) << 20;

        auto& staging = stream.transferScratch().download;

        if (!staging.reserve(stream, bytes <= kChunk ? bytes : 2 * kChunk))
        {
            // No pinned memory available; the slow path is still correct.
            StreamDrain drain{stream};
            const bool copied = gpuMemcpyD2H(dst, deviceSrc, bytes, stream.raw());
            const bool complete = drain.sync();
            return copied && complete;
        }
        DrainTransferOnFailure drain{stream};
        u8* pinned = staging.mPinned;
        auto& events = staging;

        if (bytes <= kChunk)
        {
            if (!gpuMemcpyD2H(pinned, deviceSrc, bytes, stream.raw()) || !stream.sync()) return false;
            std::memcpy(dst, pinned, bytes);
            drain.completed = true;
            return true;
        }

        const auto* src = static_cast<const u8*>(deviceSrc);
        auto* out = static_cast<u8*>(dst);

        // Queue the copy for chunk i, then drain chunk i-1 on the host while the
        // device is still working on i.
        std::size_t queuedOff = 0;
        std::size_t queuedLen = 0;
        u32 queuedSlot = 0;
        bool haveQueued = false;

        for (std::size_t off = 0; off < bytes; off += kChunk)
        {
            const std::size_t len = std::min(kChunk, bytes - off);
            const u32 slot = static_cast<u32>((off / kChunk) & 1u);
            if (!gpuMemcpyD2H(pinned + slot * kChunk, src + off, len, stream.raw()) ||
                !gpuEventRecord(events.mEvent[slot], stream.raw()))
            {
                return false;
            }
            if (haveQueued)
            {
                if (!gpuEventSync(events.mEvent[queuedSlot])) return false;
                std::memcpy(out + queuedOff, pinned + queuedSlot * kChunk, queuedLen);
            }
            queuedOff = off;
            queuedLen = len;
            queuedSlot = slot;
            haveQueued = true;
        }
        if (haveQueued)
        {
            if (!gpuEventSync(events.mEvent[queuedSlot])) return false;
            std::memcpy(out + queuedOff, pinned + queuedSlot * kChunk, queuedLen);
        }
        drain.completed = true;
        return true;
    }

    bool uploadFromHost(void* deviceDst, const void* src, std::size_t bytes, GpuStream& stream)
    {
        if (bytes == 0) return true;
        if (!deviceDst || !src || !stream.raw()) return false;

        // Explicit opt-in: on H200 the CUDA driver's pageable-copy staging is
        // faster than an extra host memcpy through our pinned buffers. Keep the
        // pipeline available for platforms where that trade-off is reversed.
        constexpr std::size_t kChunk = std::size_t(16) << 20;
        if (!stream.pipelinedUploadEnabled() || bytes <= kChunk)
        {
            return gpuMemcpyH2D(deviceDst, src, bytes, stream.raw());
        }

        auto& staging = stream.transferScratch().upload;

        if (!staging.reserve(stream, 2 * kChunk))
        {
            return gpuMemcpyH2D(deviceDst, src, bytes, stream.raw());
        }

        DrainTransferOnFailure drain{stream};
        const auto* in = static_cast<const u8*>(src);
        auto* dst = static_cast<u8*>(deviceDst);
        for (std::size_t off = 0; off < bytes; off += kChunk)
        {
            const std::size_t len = std::min(kChunk, bytes - off);
            const u32 slot = static_cast<u32>((off / kChunk) & 1u);
            if (staging.mPending[slot])
            {
                if (!gpuEventSync(staging.mEvent[slot])) return false;
                staging.mPending[slot] = false;
            }
            std::memcpy(staging.mPinned + slot * kChunk, in + off, len);
            if (!gpuMemcpyH2D(dst + off, staging.mPinned + slot * kChunk, len, stream.raw()) ||
                !gpuEventRecord(staging.mEvent[slot], stream.raw()))
            {
                return false;
            }
            staging.mPending[slot] = true;
        }
        drain.completed = true;
        return true;
    }

    namespace
    {
        struct SetupWireTransfer
        {
            GpuStream& mStream;
            void* mRegistered = nullptr;
            bool mFinished = false;

            bool finish()
            {
                // Never short-circuit the drain or unregister after an enqueue
                // failure. The caller may release the span as soon as we return.
                const bool completed = mStream.sync();
                const bool released = !mRegistered || gpuUnregisterHost(mRegistered);
                mRegistered = nullptr;
                mFinished = true;
                return completed && released;
            }

            ~SetupWireTransfer()
            {
                if (!mFinished) (void)finish();
            }
        };

        template <typename DirectCopy, typename FallbackCopy>
        bool transferSetupWire(ConstWireView wire, GpuStream& stream,
            bool registerFresh, bool fallbackOnPoolPinFailure, const LogVoleWireOptions& options,
            const DirectCopy& directCopy, const FallbackCopy& fallbackCopy,
            bool* cudaOwnedDirectCompleted = nullptr)
        {
            void* host = const_cast<u8*>(wire.data());
            const auto bytes = wire.size();
            auto* memory = wire.mMemory;
            if (cudaOwnedDirectCompleted) *cudaOwnedDirectCompleted = false;
            SetupWireTransfer transfer{stream};
            const bool usePinned = options.mPinned;
            // This exact sender-owned Root wire is backed by cudaHostAlloc,
            // not by the lazily registered setup pool. Its allocator tracks
            // the active range until coproto finishes the borrowed TCP send.
            const bool cudaOwnedRoot = usePinned &&
                isRootCudaWireHostRange(wire);
            const bool pooledOwner = usePinned && memory && memory->contains(host, bytes) && !cudaOwnedRoot;
            bool pooled = pooledOwner && memory->isPinned(host, bytes);
            if (pooledOwner && !pooled && registerFresh)
            {
                HostStep registerStep(stream.hostProfiler(), "setup: persistent wire registration");
                if (!memory->pin(host, bytes, pooled) &&
                    !fallbackOnPoolPinFailure) return false;
            }
            if (!pooledOwner && !cudaOwnedRoot &&
                bytes >= (std::size_t{1} << 20) &&
                usePinned && registerFresh)
            {
                HostStep registerStep(stream.hostProfiler(), "setup: wire host registration");
                bool registered = false;
                if (!gpuTryRegisterHost(host, bytes, registered)) return false;
                if (registered) transfer.mRegistered = host;
            }
            HostStep copyStep(stream.hostProfiler(), cudaOwnedRoot ? "setup: CUDA-owned Root wire transfer" : pooled
                ? "setup: pooled pinned wire transfer" : transfer.mRegistered
                ? "setup: registered wire transfer" : "setup: staged wire transfer");
            const bool copied = (cudaOwnedRoot || pooled || transfer.mRegistered)
                ? directCopy() : fallbackCopy();
            const bool completed = transfer.finish();
            if (cudaOwnedDirectCompleted)
                *cudaOwnedDirectCompleted = cudaOwnedRoot && copied && completed;
            return copied && completed;
        }
    }

    bool downloadSetupWire(WireView wire, const void* deviceSrc, GpuStream& stream,
        const LogVoleWireOptions& options)
    {
        void* hostDst = wire.data();
        const auto bytes = wire.size();
        if (!bytes) return stream.sync();
        if (!hostDst || !deviceSrc ||
            reinterpret_cast<std::uintptr_t>(hostDst) >
                std::numeric_limits<std::uintptr_t>::max() - bytes)
        {
            (void)stream.sync();
            return false;
        }
        // Register only an active, process-owned setup wire allocation. If CUDA
        // declines or fails to pin it, keep the bounded staged copy; never
        // attempt to register an arbitrary external destination on this path.
        // The opt-out restores the previous fresh-D2H staging policy for A/B
        // profiling. A previously registered pool block remains direct.
        const bool pinFreshPool = options.mDirectDownload &&
            (wire.mMemory && wire.mMemory->contains(hostDst, bytes));
        bool cudaOwnedDirectCompleted = false;
        const bool completed = transferSetupWire(wire, stream,
            pinFreshPool, true, options,
            [&] { return gpuMemcpyD2H(hostDst, deviceSrc, bytes, stream.raw()); },
            [&] { return downloadToHost(hostDst, deviceSrc, bytes, stream); },
            &cudaOwnedDirectCompleted);
        recordRootCudaWireDirectDownload(wire, cudaOwnedDirectCompleted);
        return completed;
    }

    bool uploadSetupWire(void* deviceDst, ConstWireView wire, GpuStream& stream,
        const LogVoleWireOptions& options)
    {
        const void* hostSrc = wire.data();
        const auto bytes = wire.size();
        if (!bytes) return stream.sync();
        if (!deviceDst || !hostSrc ||
            reinterpret_cast<std::uintptr_t>(hostSrc) >
                std::numeric_limits<std::uintptr_t>::max() - bytes)
        {
            (void)stream.sync();
            return false;
        }
        // TCP receive/host encoding has already populated an H2D source. Pin it
        // once here and retain that registration for later reuse.
        return transferSetupWire(wire, stream, true, false, options,
            [&] { return gpuMemcpyH2D(deviceDst, hostSrc, bytes, stream.raw()); },
            [&] { return uploadFromHost(deviceDst, hostSrc, bytes, stream); });
    }

    bool uploadRowsFromHost(void* deviceDst, std::size_t dstPitch, const void* src,
        std::size_t rowBytes, std::size_t rows, GpuStream& stream)
    {
        if (!rows || !rowBytes) return true;
        if (!deviceDst || !src || rowBytes > dstPitch ||
            rows > std::numeric_limits<std::size_t>::max() / dstPitch ||
            rows > std::numeric_limits<std::size_t>::max() / rowBytes) return false;
        return cudaMemcpy2DAsync(deviceDst, dstPitch, src, rowBytes, rowBytes, rows,
            cudaMemcpyHostToDevice, static_cast<cudaStream_t>(stream.raw())) == cudaSuccess;
    }

    bool copyRowsFromDevice(void* deviceDst, std::size_t dstPitch, const void* src,
        std::size_t rowBytes, std::size_t rows, GpuStream& stream)
    {
        if (!rows || !rowBytes) return true;
        if (!deviceDst || !src || rowBytes > dstPitch ||
            rows > std::numeric_limits<std::size_t>::max() / dstPitch ||
            rows > std::numeric_limits<std::size_t>::max() / rowBytes) return false;
        return cudaMemcpy2DAsync(deviceDst, dstPitch, src, rowBytes, rowBytes, rows,
            cudaMemcpyDeviceToDevice, static_cast<cudaStream_t>(stream.raw())) == cudaSuccess;
    }

    // ---- GpuRing ----------------------------------------------------------

    void GpuTableReads::recordNew(GpuStream& stream, const std::shared_ptr<OwnedGpuStream>& owner) const
    {
        std::lock_guard lock(mState->mMutex);
        auto& readers = mState->mStreams;
        if (std::find(readers.begin(), readers.end(), owner) == readers.end())
        {
            // Register the weak reverse edge first: if either allocation
            // throws, stream teardown can still safely visit this table state.
            stream.recordTableRead(mState);
            readers.push_back(owner);
        }
        mState->mRecent.store(owner.get(), std::memory_order_release);
    }

    void GpuTableReadState::retire(OwnedGpuStream* stream) noexcept
    {
        std::lock_guard lock(mMutex);
        if (mRecent.load(std::memory_order_relaxed) == stream)
            mRecent.store(nullptr, std::memory_order_release);
        mStreams.erase(std::remove_if(mStreams.begin(), mStreams.end(),
            [stream](const auto& owner) { return owner.get() == stream; }), mStreams.end());
    }

    void GpuTableReads::wait() const noexcept
    {
        // No reader can register after the last shared table owner is released.
        // Retirement holds the same lock until a completed reader is removed;
        // unfinished readers retain their native streams through this wait.
        try
        {
            std::lock_guard lock(mState->mMutex);
            for (const auto& stream : mState->mStreams) stream->synchronize();
        }
        catch (...) { std::terminate(); }
    }

    GpuRing::~GpuRing()
    {
        mReads.wait();
    }

    std::shared_ptr<GpuRing> GpuRing::get(const RingNttContext& ctx)
    {
        if (!ctx.mResourceScope.mTables) return nullptr;
        HostStep getStep(osuCrypto::LogVole::hostProfiler(ctx), "setup GPU ring get");
        if (ctx.mGpuLightweight)
        {
            if (!validateRingContextMetadata(ctx)) return nullptr;
            // A combined native setup publishes a fully certified owner only
            // after the final device status record validates. Reuse that exact
            // owner instead of constructing a second raw ring from host q.
            if (ctx.mRawModuli && ctx.mRawModuli->mDynamicGpuCertificate)
            {
                const auto& certificate =
                    ctx.mRawModuli->mDynamicGpuCertificate;
                return available() && currentDeviceOrdinal() == 0 &&
                    certificate->rawOwnerRole() == ctx.mResourceScope.mRole
                    ? certificate : nullptr;
            }
            return getRaw(ctx.mParams, ctx.mRawModuli->mValues, ctx.mResourceScope, ctx.mGpuSetup);
        }
        if (!available()) return nullptr;

        RingCacheKey key{};
        key.mDegree = ctx.mParams.mPolyModulusDegree;
        key.mBits.assign(ctx.mParams.mCoeffModulusBits.begin(), ctx.mParams.mCoeffModulusBits.end());
        key.mRole = ctx.mResourceScope.mRole;

        auto& cache = *ctx.mResourceScope.mTables->mImpl;
        std::lock_guard<std::mutex> lock(cache.ringMutex);
        auto it = cache.rings.find(key);
        if (it != cache.rings.end()) return it->second;

        std::shared_ptr<GpuRing> ring(new GpuRing());
        ring->mSetup = ctx.mGpuSetup;
        if (!ring->init(ctx)) return nullptr;
        cache.rings.emplace(std::move(key), ring);
        return ring;
    }

    std::shared_ptr<GpuRing> GpuRing::getRaw(const RingParams& params, std::span<const u64> primes,
        const RingResourceScope& owner, std::shared_ptr<GpuSetupContext> execution)
    {
        HostStep getStep(owner.mTables ? owner.mTables->hostProfiler() : nullptr, "setup GPU raw ring get");
        if (!owner.mTables ||
            !validRawPrimes(params.mPolyModulusDegree, primes) ||
            params.mCoeffModulusBits.size() != primes.size()) return nullptr;
        for (std::size_t j = 0; j < primes.size(); ++j)
        {
            u32 bits = 0;
            for (u64 value = primes[j]; value; value >>= 1) ++bits;
            if (params.mCoeffModulusBits[j] != static_cast<int>(bits)) return nullptr;
        }
        // The caching allocator currently selects device 0's memory pool.
        if (!available() || currentDeviceOrdinal() != 0) return nullptr;
        try
        {
            RawRingCacheKey key{params.mPolyModulusDegree,
                std::vector<u64>(primes.begin(), primes.end()),
                owner.mRole, owner.mNativeGpuTables};
            auto& cache = *owner.mTables->mImpl;
            std::lock_guard<std::mutex> lock(cache.rawRingMutex);
            if (auto it = cache.rawRings.find(key); it != cache.rawRings.end())
            {
                if (execution && execution != it->second->mSetup &&
                    execution->executionOptions() != owner.mTables->executionOptions()) return nullptr;
                return it->second;
            }
            if (execution && execution->executionOptions() != owner.mTables->executionOptions()) return nullptr;
            std::shared_ptr<GpuRing> ring(new GpuRing());
            ring->mSetup = execution ? std::move(execution) :
                std::make_shared<GpuSetupContext>(owner.mTables->executionOptions(), owner.mTables->hostProfilerOwner(), currentProtocolCacheScope().mRunId.serviceOwner());
            ring->mRawOwnerRole = owner.mRole;
            if (!ring->initRaw(params, primes)) return nullptr;
            cache.rawRings.emplace(std::move(key), ring);
            return ring;
        }
        catch (...) { return nullptr; }
    }

    bool GpuRing::publishRaw(const RingParams& params,
        std::span<const u64> orderedPrimes,
        const std::shared_ptr<GpuRing>& ready, const RingResourceScope& owner)
    {
        if (!ready || !ready->mNativeSealBundleStorage || !ready->mRaw ||
            !ready->mDenoiseReady || !ready->mSampleMaxMultiple ||
            !owner.mTables || !ready->mSetup ||
            ready->mSetup->executionOptions() != owner.mTables->executionOptions() ||
            !owner.mNativeGpuTables || owner.mRole != ready->mRawOwnerRole ||
            !(ready->mParams == params) ||
            ready->n() != params.mPolyModulusDegree ||
            ready->rho() != orderedPrimes.size() ||
            ready->mHostModuli.size() != orderedPrimes.size() ||
            !std::equal(orderedPrimes.begin(), orderedPrimes.end(),
                ready->mHostModuli.begin()) ||
            !validRawPrimes(params.mPolyModulusDegree, orderedPrimes) ||
            params.mCoeffModulusBits.size() != orderedPrimes.size())
            return false;
        for (std::size_t j = 0; j < orderedPrimes.size(); ++j)
        {
            u32 bits = 0;
            for (u64 value = orderedPrimes[j]; value; value >>= 1) ++bits;
            if (params.mCoeffModulusBits[j] != static_cast<int>(bits))
                return false;
        }
        try
        {
            RawRingCacheKey key{params.mPolyModulusDegree,
                std::vector<u64>(orderedPrimes.begin(), orderedPrimes.end()),
                ready->mRawOwnerRole, true};
            auto& cache = *owner.mTables->mImpl;
            std::lock_guard<std::mutex> lock(cache.rawRingMutex);
            if (auto it = cache.rawRings.find(key); it != cache.rawRings.end())
            {
                // A same-role sequential table may have been built before the
                // combined factory committed. A shared_ptr already borrowed
                // by that earlier caller remains valid after replacement.
                it->second = ready;
                return true;
            }
            cache.rawRings.emplace(std::move(key), ready);
            return true;
        }
        catch (...) { return false; }
    }

    bool GpuRing::initRaw(const RingParams& params, std::span<const u64> primes)
    {
        if (!mSetup || !prepareKernelDispatch(mView, mSetup->executionOptions().mAdvanced.mKernels)) return false;
        HostStep setupStep(mSetup->hostProfiler(), "setup GPU raw ring init");
        const u32 n = params.mPolyModulusDegree;
        const u32 rho = static_cast<u32>(primes.size());
        const std::size_t words = static_cast<std::size_t>(n) * rho;
        mParams = params;
        mHostModuli.assign(primes.begin(), primes.end());

        // Status and prime owners outlive every asynchronous operation, even
        // when launch/allocation fails before the normal publication boundary.
        u32 status = ~u32{0};
        RawSetupStream stream(mSetup);
        if (!stream.mStream) return false;
        RawConstantArena arena(words * (2 * sizeof(HostShoupOperand) + 2 * sizeof(double)) + 16384, stream);
        if (!arena) return false;
        allocateRawNttView(arena, mView, n, primes);
        auto* devicePrimes = arena.take<u64>(rho);
        auto* scratch = arena.take<u64>(3u * rho);
        auto* deviceStatus = arena.take<u32>(1);
        mView.mBaseProd = arena.take<u64>(rho);
        mView.mBaseProdHalf = arena.take<u64>(rho);
        mView.mPuncturedProd = arena.take<u64>(rho * rho);
        mView.mInvPuncturedProd = arena.take<HostShoupOperand>(rho);
        mView.mGarnerInv = arena.take<HostShoupOperand>(rho * rho);
        mCrtLift = arena.take<u64>(rho);
        mInvCrtLift = arena.take<u64>(rho);
        mSampleMaxMultiple = arena.take<u64>(rho);
        mDenoise.mQ = devicePrimes;
        mDenoise.mMods = mView.mMods;
        mDenoise.mCrtLiftModTarget = mCrtLift;
        mDenoise.mInvCrtLiftModTarget = mInvCrtLift;
        if (rho > 1)
        {
            const std::size_t reducedWords = rho * (rho - 1u);
            mDenoise.mSrcLimb = arena.take<u32>(reducedWords);
            mDenoise.mCrtInvPunctured = arena.take<u64>(reducedWords);
            mDenoise.mPuncturedProdModTarget = arena.take<u64>(reducedWords);
            mDenoise.mCrtInvPuncturedShoup = arena.take<HostShoupOperand>(reducedWords);
            mDenoise.mScaledPuncturedShoup = arena.take<HostShoupOperand>(reducedWords);
            mDenoise.mFracInvLo = arena.take<u64>(reducedWords);
            mDenoise.mFracInvHi = arena.take<u64>(reducedWords);
            mDenoise.mInvCrtLiftShoup = arena.take<HostShoupOperand>(rho);
        }
        const bool fp52Shape = h200LazyResourcesDefault() && n == 16384u && rho == 8u &&
            mView.mMinModulus > (u64{1} << 51u) && mView.mMaxModulus < (u64{1} << 52u);
        const u32 packedMode = mView.mKernelOptions.mNoGoldH200PackedRoots;
        if (fp52Shape)
        {
            if (packedMode & 1u) mView.mFp52InvRoots = arena.take<double>(words);
            if (packedMode & 2u) mView.mFp52Roots = arena.take<double>(words);
        }
        if (!devicePrimes || !scratch || !deviceStatus ||
            !gpuMemcpyH2D(devicePrimes, mHostModuli.data(), rho * sizeof(u64), stream.mStream) ||
            !launchPrepareRawNttTables(mView, devicePrimes, scratch, deviceStatus, stream.mStream) ||
            !launchPrepareRawCrtConstants(mView, mDenoise, const_cast<u64*>(mCrtLift),
                const_cast<u64*>(mInvCrtLift), const_cast<u64*>(mSampleMaxMultiple), deviceStatus, stream.mStream) ||
            !gpuMemcpyD2H(&status, deviceStatus, sizeof(status), stream.mStream) ||
            !stream.sync() || status != 0) return false;
        if (fp52Shape && h200Fp52GadgetConstantsEnabled(mView.mKernelOptions))
        {
            const bool prediv = h200Fp52GadgetPredivEnabled(mView.mKernelOptions);
            auto* constants = arena.take<double>(prediv ? 144u : 80u);
            if (!constants) return false;
            auto* ratios = prediv ? constants + 80u : nullptr;
            if (!launchPrepareH200Fp52GadgetConstants(mView, constants, stream.mStream, ratios)) return false;
            mView.mFp52GadgetConstants = constants;
            mView.mFp52GadgetRatios = ratios;
        }
        if (!prepareH200RootPersistence(mView) || !stream.sync()) return false;
        arena.publish(mOwned);
        mDenoiseReady = rho > 1;
        mRaw = true;
        return true;
    }

    bool GpuRing::init(const RingNttContext& ctx)
    {
        if (!prepareKernelDispatch(mView, ctx.mExecutionOptions.mAdvanced.mKernels)) return false;
        HostStep initStep(osuCrypto::LogVole::hostProfiler(ctx), "setup GPU ring init");
        auto keyData = ctx.mContext ? ctx.mContext->key_context_data() : nullptr;
        if (!keyData) return false;

        HostStep hostTablesStep(osuCrypto::LogVole::hostProfiler(ctx), "setup GPU ring host tables");

        const u32 n = ctx.mParams.mPolyModulusDegree;
        const u32 rho = static_cast<u32>(ctx.mModuli.size());
        if (n == 0 || rho == 0 || (n & (n - 1u)) != 0) return false;

        mParams = ctx.mParams;
        mView.mN = n;
        mView.mRho = rho;
        u32 logN = 0;
        while ((1u << logN) < n) ++logN;
        mView.mLogN = logN;

        const auto& tables = keyData->small_ntt_tables();

        std::vector<HostModulus> mods(rho);
        std::vector<HostShoupOperand> roots(static_cast<std::size_t>(rho) * n);
        std::vector<HostShoupOperand> invRoots(static_cast<std::size_t>(rho) * n);
        std::vector<HostShoupOperand> invDegree(rho);
        std::vector<HostShoupOperand> scaledInvRoot(rho);

        mHostModuli.resize(rho);
        for (u32 j = 0; j < rho; ++j)
        {
            mHostModuli[j] = ctx.mModuli[j].value();
        }
        mView.mMinModulus = *std::min_element(mHostModuli.begin(), mHostModuli.end());
        mView.mMaxModulus = *std::max_element(mHostModuli.begin(), mHostModuli.end());

        for (u32 j = 0; j < rho; ++j)
        {
            mods[j] = toHostModulus(ctx.mModuli[j]);
            const auto& tbl = tables[j];
            for (u32 i = 0; i < n; ++i)
            {
                roots[static_cast<std::size_t>(j) * n + i] = toHostShoup(tbl.get_from_root_powers(i));
                invRoots[static_cast<std::size_t>(j) * n + i] = toHostShoup(tbl.get_from_inv_root_powers(i));
            }
            invDegree[j] = toHostShoup(tbl.inv_degree_modulo());

            // Last-stage root of the inverse transform pre-multiplied by 1/n,
            // matching DWTHandler::mul_root_scalar.
            seal::util::MultiplyUIntModOperand scaled{};
            const auto lastRoot = tbl.get_from_inv_root_powers(n - 1);
            scaled.set(
                seal::util::multiply_uint_mod(lastRoot.operand, tbl.inv_degree_modulo(), ctx.mModuli[j]),
                ctx.mModuli[j]);
            scaledInvRoot[j] = toHostShoup(scaled);
        }

        // Multi-precision CRT constants, mirroring seal::util::RNSBase.
        auto pool = seal::MemoryManager::GetPool();
        seal::util::RNSBase base(keyData->parms().coeff_modulus(), pool);
        if (base.size() != rho) return false;

        std::vector<u64> baseProd(rho);
        std::copy(base.base_prod(), base.base_prod() + rho, baseProd.begin());

        std::vector<u64> baseProdHalf(rho);
        seal::util::right_shift_uint(baseProd.data(), 1, rho, baseProdHalf.data());

        std::vector<u64> punctured(static_cast<std::size_t>(rho) * rho);
        std::copy(base.punctured_prod_array(), base.punctured_prod_array() + punctured.size(), punctured.begin());

        std::vector<HostShoupOperand> invPunctured(rho);
        for (u32 j = 0; j < rho; ++j)
        {
            invPunctured[j] = toHostShoup(base.inv_punctured_prod_mod_base_array()[j]);
        }

        // Garner constants for the alternative composition: garnerInv[i*rho + j] is
        // q_j^-1 mod q_i, used for j < i only. Shoup form so the mixed-radix pass is
        // multiply-high plus subtract with no division.
        std::vector<HostShoupOperand> garnerInv(static_cast<std::size_t>(rho) * rho);
        for (u32 i = 0; i < rho; ++i)
        {
            for (u32 j = 0; j < rho; ++j)
            {
                seal::util::MultiplyUIntModOperand op{};
                if (j < i)
                {
                    std::uint64_t inv = 0;
                    const std::uint64_t qj = seal::util::barrett_reduce_64(
                        ctx.mModuli[j].value(), ctx.mModuli[i]);
                    if (!seal::util::try_invert_uint_mod(qj, ctx.mModuli[i], inv))
                    {
                        return false;
                    }
                    op.set(inv, ctx.mModuli[i]);
                }
                garnerInv[static_cast<std::size_t>(i) * rho + j] = toHostShoup(op);
            }
        }

        // Immutable SEAL uniform-sampling rejection thresholds. A fresh Root
        // key only uploads its 64-byte seed, not new per-limb metadata.
        std::vector<u64> sampleMax(rho);
        for (u32 j = 0u; j < rho; ++j)
            sampleMax[j] = ~u64(0) -
                seal::util::barrett_reduce_64(~u64(0), ctx.mModuli[j]) - 1u;

        // Mirrors buildRecursiveLeafScaling: prod_{w != j} q_w mod q_j and its
        // multiplicative inverse.
        std::vector<u64> lift(rho, 1);
        std::vector<u64> invLift(rho, 1);
        for (u32 j = 0; j < rho; ++j)
        {
            const auto& modJ = ctx.mModuli[j];
            u64 acc = 1;
            for (u32 w = 0; w < rho; ++w)
            {
                if (w == j) continue;
                acc = seal::util::multiply_uint_mod(acc, ctx.mModuli[w].value(), modJ);
            }
            lift[j] = acc;
            if (!seal::util::try_invert_uint_mod(acc, modJ, invLift[j])) return false;
        }

        std::vector<double> compact;
        RawSetupStream stream(mSetup);
        if (!stream.mStream) return false;
        hostTablesStep.stop();
        HostStep constantsStep(osuCrypto::LogVole::hostProfiler(ctx), "setup GPU ring constants");
        mView.mMods = uploadVector(mods, mOwned, stream);
        mView.mRoots = uploadVector(roots, mOwned, stream);
        mView.mInvRoots = uploadVector(invRoots, mOwned, stream);
        mView.mInvDegree = uploadVector(invDegree, mOwned, stream);
        mView.mScaledInvRoot = uploadVector(scaledInvRoot, mOwned, stream);
        mView.mBaseProd = static_cast<const u64*>(uploadVector(baseProd, mOwned, stream));
        mView.mBaseProdHalf = static_cast<const u64*>(uploadVector(baseProdHalf, mOwned, stream));
        mView.mPuncturedProd = static_cast<const u64*>(uploadVector(punctured, mOwned, stream));
        mView.mInvPuncturedProd = uploadVector(invPunctured, mOwned, stream);
        mView.mGarnerInv = uploadVector(garnerInv, mOwned, stream);

        // Compact inverse twiddles are immutable, prepared once with the ring
        // outside the online query, and never replace the integer fallback.
        // Forward packing remains opt-in: it did not win at both query sizes.
        const u32 packedMode = mView.mKernelOptions.mNoGoldH200PackedRoots;
        if (packedMode && h200LazyResourcesDefault() && n == 16384u && rho == 8u &&
            mView.mMinModulus > (u64{1} << 51u) && mView.mMaxModulus < (u64{1} << 52u))
        {
            compact.resize(roots.size());
            if (packedMode & 1u)
            {
                std::transform(invRoots.begin(), invRoots.end(), compact.begin(),
                    [](const HostShoupOperand& root) { return static_cast<double>(root.mOperand); });
                mView.mFp52InvRoots = static_cast<const double*>(uploadVector(compact, mOwned, stream));
                if (!mView.mFp52InvRoots) return false;
            }
            if (packedMode & 2u)
            {
                // The same host buffer backs the preceding upload.
                if ((packedMode & 1u) && !stream.sync()) return false;
                std::transform(roots.begin(), roots.end(), compact.begin(),
                    [](const HostShoupOperand& root) { return static_cast<double>(root.mOperand); });
                mView.mFp52Roots = static_cast<const double*>(uploadVector(compact, mOwned, stream));
                if (!mView.mFp52Roots) return false;
            }
        }

        mSampleMaxMultiple = static_cast<const u64*>(uploadVector(sampleMax, mOwned, stream));

        if (!mView.mMods || !mView.mRoots || !mView.mInvRoots || !mView.mInvDegree ||
            !mView.mScaledInvRoot || !mView.mBaseProd || !mView.mBaseProdHalf ||
            !mView.mPuncturedProd || !mView.mInvPuncturedProd || !mView.mGarnerInv ||
            !mSampleMaxMultiple)
        {
            return false;
        }

        mHostModulusData = std::move(mods);

        mCrtLift = static_cast<const u64*>(uploadVector(lift, mOwned, stream));
        mInvCrtLift = static_cast<const u64*>(uploadVector(invLift, mOwned, stream));
        if (!mCrtLift || !mInvCrtLift) return false;

        constantsStep.stop();
        {
            HostStep denoiseStep(osuCrypto::LogVole::hostProfiler(ctx), "setup GPU ring denoise constants");
            mDenoiseReady = initDenoise(ctx);
        }
        HostStep gadgetStep(osuCrypto::LogVole::hostProfiler(ctx), "setup GPU ring gadget constants");
        if (h200Fp52GadgetConstantsEnabled(mView.mKernelOptions) &&
            h200LazyResourcesDefault() && n == 16384u && rho == 8u &&
            mView.mMinModulus > (u64{1} << 51u) && mView.mMaxModulus < (u64{1} << 52u))
        {
            const bool prediv = h200Fp52GadgetPredivEnabled(mView.mKernelOptions);
            RawConstantArena arena((prediv ? 144u : 80u) * sizeof(double), stream);
            auto* constants = arena.take<double>(prediv ? 144u : 80u);
            if (!constants) return false;
            arena.publish(mOwned);
            double* ratios = prediv ? constants + 80u : nullptr;
            if (!launchPrepareH200Fp52GadgetConstants(mView, constants, stream.mStream, ratios)) return false;
            mView.mFp52GadgetConstants = constants;
            mView.mFp52GadgetRatios = ratios;
        }
        gadgetStep.stop();
        {
            HostStep persistenceStep(osuCrypto::LogVole::hostProfiler(ctx), "setup GPU ring L2 persistence");
            if (!prepareH200RootPersistence(mView)) return false;
        }
        // Also completes the optional setup kernel before cache publication.
        HostStep syncStep(osuCrypto::LogVole::hostProfiler(ctx), "setup GPU ring final sync");
        return stream.sync();
    }

    struct GpuRingSetupPrefetch::Impl
    {
        // Own the OS thread: MSVC std::async uses persistent pool threads,
        // whose thread-local CUDA scratch need not be destroyed on future.get().
        std::thread mWorker;
        bool mSuccess = false;
        ~Impl() { if (mWorker.joinable()) mWorker.join(); }
    };

    GpuRingSetupPrefetch::GpuRingSetupPrefetch(const RingNttContext& ctx, bool gpuEnabled)
    {
        CpuBenchmarkState cpuBenchmark{cpuBenchmarkContext(ctx)};
        if (!gpuEnabled || !ctx.mResourceScope.mTables ||
            !ctx.mExecutionOptions.mAdvanced.mContexts.mInitOverlap || (!ctx.mContext && !ctx.mGpuLightweight)) return;
        HostStep startStep(osuCrypto::LogVole::hostProfiler(ctx), "setup GPU ring prefetch start", &cpuBenchmark);
        int device = 0;
        if (cudaGetDevice(&device) != cudaSuccess) return;
        // The existing caching allocator selects device 0's memory pool. Do
        // not extend its single-device assumptions to another current device.
        if (device != 0) return;

        try
        {
            auto& cache = *ctx.mResourceScope.mTables->mImpl;
            if (ctx.mGpuLightweight)
            {
                if (!validateRingContextMetadata(ctx)) return;
                RawRingCacheKey key;
                key.mDegree = ctx.mParams.mPolyModulusDegree;
                key.mRole = ctx.mResourceScope.mRole;
                key.mPrimes = ctx.mRawModuli->mValues;
                key.mNativeRequested = ctx.mResourceScope.mNativeGpuTables;
                if (!validRawPrimes(key.mDegree, key.mPrimes) ||
                    key.mPrimes.size() != ctx.mParams.mCoeffModulusBits.size()) return;
                std::unique_lock<std::mutex> lock(cache.rawRingMutex, std::try_to_lock);
                if (!lock.owns_lock() || cache.rawRings.find(key) != cache.rawRings.end()) return;
            }
            else
            {
                RingCacheKey key{};
                key.mDegree = ctx.mParams.mPolyModulusDegree;
                key.mBits.assign(ctx.mParams.mCoeffModulusBits.begin(), ctx.mParams.mCoeffModulusBits.end());
                key.mRole = ctx.mResourceScope.mRole;
                // Avoid spawning a worker for warm rings or waiting here while
                // another thread already initializes one. The regular get
                // path holds this mutex through initialization/publication.
                std::unique_lock<std::mutex> lock(cache.ringMutex, std::try_to_lock);
                if (!lock.owns_lock() || cache.rings.find(key) != cache.rings.end()) return;
            }
            auto protocolScope = currentProtocolCacheScope();
            protocolScope.mRole = ctx.mResourceScope.mRole;
            auto* benchmarkContext = cpuBenchmark.mContext;
            auto next = std::make_unique<Impl>();
            next->mWorker = std::thread(
                [ownedContext = ctx, protocolScope, benchmarkContext, device, state = next.get()]() {
                    try
                    {
                        ScopedProtocolCacheScope scope(protocolScope);
                        CpuBenchmarkWorkerScope workerScope(benchmarkContext);
                        CpuBenchmarkState cpuBenchmark{benchmarkContext, true};
                        CpuBenchmarkTaskScope taskScope(cpuBenchmark);
                        HostStep workerStep(hostProfiler(ownedContext), "setup GPU ring prefetch worker", &cpuBenchmark);
                        {
                            HostStep deviceStep(hostProfiler(ownedContext), "setup GPU ring select device", &cpuBenchmark);
                            if (cudaSetDevice(device) != cudaSuccess) return false;
                        }
                        // Both table paths use their owned setup domain and
                        // never borrow mutable query scratch.
                        state->mSuccess = static_cast<bool>(GpuRing::get(ownedContext));
                        return state->mSuccess;
                    }
                    catch (...)
                    {
                        // Opportunistic setup cannot suppress a later ordinary
                        // get/retry. The outer RAII object still joins the task.
                        return false;
                    }
                });
            mImpl = std::move(next);
        }
        catch (...)
        {
            // Thread creation or context-copy allocation failure keeps setup on
            // its normal synchronous path.
        }
    }

    GpuRingSetupPrefetch::~GpuRingSetupPrefetch()
    {
        (void)wait();
    }

    bool GpuRingSetupPrefetch::wait() noexcept
    {
        if (!mImpl) return true;
        if (mImpl->mWorker.joinable())
        {
            mImpl->mWorker.join();
        }
        return mImpl->mSuccess;
    }

    bool GpuRing::initDenoise(const RingNttContext& ctx)
    {
        // Mirrors the RecoveryConstants block of shrinkExpandDenoiseComb.
        auto keyData = ctx.mContext ? ctx.mContext->key_context_data() : nullptr;
        if (!keyData) return false;

        const u32 rho = mView.mRho;
        if (rho < 2) return false;
        const u32 reduced = rho - 1u;

        auto pool = seal::MemoryManager::GetPool();
        seal::util::RNSBase fullBase(keyData->parms().coeff_modulus(), pool);

        std::vector<u64> q(rho);
        std::vector<HostModulus> mods(rho);
        for (u32 i = 0; i < rho; ++i)
        {
            q[i] = fullBase.base()[i].value();
            mods[i] = toHostModulus(ctx.mModuli[i]);
        }

        std::vector<u32> srcLimb(static_cast<std::size_t>(rho) * reduced);
        std::vector<u64> crtInvPunctured(srcLimb.size());
        std::vector<u64> puncturedProdModTarget(srcLimb.size());
        std::vector<HostShoupOperand> crtInvPuncturedShoup(srcLimb.size());
        std::vector<HostShoupOperand> scaledPuncturedShoup(srcLimb.size());
        std::vector<u64> fracInvLo(srcLimb.size());
        std::vector<u64> fracInvHi(srcLimb.size());
        std::vector<u64> crtLift(rho);
        std::vector<u64> invCrtLift(rho);
        std::vector<HostShoupOperand> invCrtLiftShoup(rho);

        for (u32 j = 0; j < rho; ++j)
        {
            const auto& modJ = ctx.mModuli[j];
            std::vector<seal::Modulus> baseExcludingJ;
            baseExcludingJ.reserve(reduced);
            u32 idx = 0;
            u64 crtLiftModQj = 1;
            for (u32 w = 0; w < rho; ++w)
            {
                if (w == j) continue;
                srcLimb[static_cast<std::size_t>(j) * reduced + idx] = w;
                baseExcludingJ.push_back(ctx.mModuli[w]);
                crtLiftModQj = seal::util::multiply_uint_mod(crtLiftModQj, q[w], modJ);
                ++idx;
            }
            crtLift[j] = crtLiftModQj;
            if (!seal::util::try_invert_uint_mod(crtLiftModQj, modJ, invCrtLift[j])) return false;
            seal::util::MultiplyUIntModOperand invLiftOp{};
            invLiftOp.set(invCrtLift[j], modJ);
            invCrtLiftShoup[j] = toHostShoup(invLiftOp);

            seal::util::RNSBase reducedBase(baseExcludingJ, pool);
            auto reducedInvPunct = reducedBase.inv_punctured_prod_mod_base_array();
            for (u32 i = 0; i < reduced; ++i)
            {
                const std::size_t ci = static_cast<std::size_t>(j) * reduced + i;
                const u32 w = srcLimb[ci];
                crtInvPunctured[ci] = reducedInvPunct[i].operand;
                crtInvPuncturedShoup[ci] = toHostShoup(reducedInvPunct[i]);

                const wideU64 frac = reciprocal2Pow128Wide(q[w]);
                fracInvLo[ci] = frac.mLo;
                fracInvHi[ci] = frac.mHi;

                u64 puncturedModQj = 1;
                for (u32 u = 0; u < rho; ++u)
                {
                    if (u == j || u == w) continue;
                    puncturedModQj = seal::util::multiply_uint_mod(puncturedModQj, q[u], modJ);
                }
                puncturedProdModTarget[ci] = puncturedModQj;
                const u64 scaledPunctured =
                    seal::util::multiply_uint_mod(puncturedModQj, invLiftOp, modJ);
                seal::util::MultiplyUIntModOperand scaledPuncturedOp{};
                scaledPuncturedOp.set(scaledPunctured, modJ);
                scaledPuncturedShoup[ci] = toHostShoup(scaledPuncturedOp);
            }
        }

        RawSetupStream stream(mSetup);
        if (!stream.mStream) return false;
        mDenoise.mQ = static_cast<const u64*>(uploadVector(q, mOwned, stream));
        mDenoise.mMods = uploadVector(mods, mOwned, stream);
        mDenoise.mSrcLimb = static_cast<const u32*>(uploadVector(srcLimb, mOwned, stream));
        mDenoise.mCrtInvPunctured = static_cast<const u64*>(uploadVector(crtInvPunctured, mOwned, stream));
        mDenoise.mPuncturedProdModTarget =
            static_cast<const u64*>(uploadVector(puncturedProdModTarget, mOwned, stream));
        mDenoise.mCrtInvPuncturedShoup = uploadVector(crtInvPuncturedShoup, mOwned, stream);
        mDenoise.mScaledPuncturedShoup = uploadVector(scaledPuncturedShoup, mOwned, stream);
        mDenoise.mFracInvLo = static_cast<const u64*>(uploadVector(fracInvLo, mOwned, stream));
        mDenoise.mFracInvHi = static_cast<const u64*>(uploadVector(fracInvHi, mOwned, stream));
        mDenoise.mCrtLiftModTarget = static_cast<const u64*>(uploadVector(crtLift, mOwned, stream));
        mDenoise.mInvCrtLiftModTarget = static_cast<const u64*>(uploadVector(invCrtLift, mOwned, stream));
        mDenoise.mInvCrtLiftShoup = uploadVector(invCrtLiftShoup, mOwned, stream);

        return mDenoise.mQ && mDenoise.mMods && mDenoise.mSrcLimb && mDenoise.mCrtInvPunctured &&
               mDenoise.mPuncturedProdModTarget && mDenoise.mCrtInvPuncturedShoup &&
               mDenoise.mScaledPuncturedShoup && mDenoise.mFracInvLo && mDenoise.mFracInvHi &&
               mDenoise.mCrtLiftModTarget && mDenoise.mInvCrtLiftModTarget &&
               mDenoise.mInvCrtLiftShoup;
    }

    const u64* GpuRing::pow2Factors(u32 shiftBits)
    {
        std::lock_guard<std::mutex> lock(mPow2Mutex);
        for (const auto& [bits, ptr] : mPow2Cache)
        {
            if (bits == shiftBits) return ptr;
        }

        if (mRaw)
        {
            RawSetupStream stream(mSetup);
            if (!stream.mStream) return nullptr;
            RawConstantArena arena(mView.mRho * sizeof(u64), stream);
            auto* factors = arena.take<u64>(mView.mRho);
            if (!factors || !launchPreparePow2Factors(mView, shiftBits, factors, stream.mStream) ||
                !stream.sync()) return nullptr;
            // Reserve before publishing ownership so allocation exceptions
            // cannot expose an uncached partial result.
            mPow2Cache.reserve(mPow2Cache.size() + 1);
            arena.publish(mOwned);
            mPow2Cache.emplace_back(shiftBits, factors);
            return factors;
        }

        // Mirrors pow2Mod in LogVoleRing.cpp: 2^shiftBits mod q_j.
        std::vector<u64> factors(mView.mRho);
        for (u32 j = 0; j < mView.mRho; ++j)
        {
            const seal::Modulus mod(mHostModuli[j]);
            u64 acc = 1 % mHostModuli[j];
            const u64 two = 2 % mHostModuli[j];
            u64 base = two;
            u64 exp = shiftBits;
            while (exp)
            {
                if (exp & 1u) acc = seal::util::multiply_uint_mod(acc, base, mod);
                base = seal::util::multiply_uint_mod(base, base, mod);
                exp >>= 1;
            }
            factors[j] = acc;
        }

        RawSetupStream stream(mSetup);
        if (!stream.mStream) return nullptr;
        mPow2Cache.reserve(mPow2Cache.size() + 1);
        const u64* d = static_cast<const u64*>(uploadVector(factors, mOwned, stream));
        if (!d) return nullptr;
        mPow2Cache.emplace_back(shiftBits, d);
        return d;
    }

    bool GpuRing::scaleRoundConstants(u64 p, ScaleRoundConstView& out)
    {
        if (!p || p >= mView.mMinModulus) return false;
        std::lock_guard<std::mutex> lock(mPow2Mutex);
        for (const auto& [cachedP, view] : mScaleRoundCache)
        {
            if (cachedP == p) { out = view; return true; }
        }
        try
        {
            HostStep setupStep(mSetup->hostProfiler(), "setup GPU scale round constants");
            RawSetupStream stream(mSetup);
            if (!stream.mStream) return false;
            RawConstantArena arena(mView.mRho *
                (5 * sizeof(u64) + sizeof(ScaleRoundFastLimb)) + 6u * 16u,
                stream);
            ScaleRoundConstView view;
            view.mCrtInvPunctured = arena.take<u64>(mView.mRho);
            view.mQ = arena.take<u64>(mView.mRho);
            view.mPShoup = arena.take<u64>(mView.mRho);
            view.mFracLo = arena.take<u64>(mView.mRho);
            view.mFracHi = arena.take<u64>(mView.mRho);
            view.mFastLimbs = arena.take<ScaleRoundFastLimb>(mView.mRho);
            if (!launchPrepareScaleRoundConstants(mView, p, view, stream.mStream) || !stream.sync()) return false;
            mScaleRoundCache.reserve(mScaleRoundCache.size() + 1);
            arena.publish(mOwned);
            mScaleRoundCache.emplace_back(p, view);
            out = view;
            return true;
        }
        catch (...) { return false; }
    }

    // ---- GpuPlainNtt ------------------------------------------------------

    GpuPlainNtt::~GpuPlainNtt()
    {
        mReads.wait();
    }

    std::shared_ptr<GpuPlainNtt> GpuPlainNtt::get(
        const seal::SEALContext& batchingContext, const seal::BatchEncoder& encoder,
        const RingResourceScope& owner, ProtocolCacheScopeView scope)
    {
        if (!owner.mTables || !available()) return nullptr;

        auto data = batchingContext.first_context_data();
        if (!data) return nullptr;
        const u64 p = data->parms().plain_modulus().value();
        const u64 degree = data->parms().poly_modulus_degree();
        const auto key = std::tuple{degree, p, owner.mRole};

        auto& cache = *owner.mTables->mImpl;
        std::lock_guard<std::mutex> lock(cache.plainMutex);
        for (const auto& [k, v] : cache.plains)
        {
            if (k == key) return v;
        }

        std::shared_ptr<GpuPlainNtt> tables(new GpuPlainNtt());
        tables->mSetup = std::make_shared<GpuSetupContext>(owner.mTables->executionOptions(), owner.mTables->hostProfilerOwner(), scope.mRunId.serviceOwner());
        if (!tables->init(batchingContext, encoder)) return nullptr;
        cache.plains.emplace_back(key, tables);
        return tables;
    }

    std::shared_ptr<GpuPlainNtt> GpuPlainNtt::getRaw(u32 n, u64 p,
        const RingResourceScope& owner, std::shared_ptr<GpuSetupContext> execution, ProtocolCacheScopeView scope)
    {
        if (!owner.mTables ||
            !validRawPrimes(n, std::span<const u64>(&p, 1)) ||
            !available() || currentDeviceOrdinal() != 0) return nullptr;
        try
        {
            const RawPlainKey key{n, p, owner.mRole, owner.mNativeGpuTables};
            auto& cache = *owner.mTables->mImpl;
            std::lock_guard<std::mutex> lock(cache.rawPlainMutex);
            for (const auto& [cachedKey, value] : cache.rawPlains)
                if (cachedKey == key)
                {
                    if (execution && execution != value->mSetup &&
                        execution->executionOptions() != owner.mTables->executionOptions()) return nullptr;
                    return value;
                }
            if (execution && execution->executionOptions() != owner.mTables->executionOptions()) return nullptr;
            std::shared_ptr<GpuPlainNtt> tables(new GpuPlainNtt());
            tables->mSetup = execution ? std::move(execution) :
                std::make_shared<GpuSetupContext>(owner.mTables->executionOptions(), owner.mTables->hostProfilerOwner(), scope.mRunId.serviceOwner());
            if (!tables->initRaw(n, p)) return nullptr;
            cache.rawPlains.emplace_back(key, tables);
            return tables;
        }
        catch (...) { return nullptr; }
    }

    bool GpuPlainNtt::publishRaw(u32 n, u64 p,
        const std::shared_ptr<GpuPlainNtt>& ready, const RingResourceScope& owner)
    {
        if (!ready || !ready->mNativeSealBundleStorage ||
            !owner.mTables || !ready->mSetup ||
            ready->mSetup->executionOptions() != owner.mTables->executionOptions() ||
            !owner.mNativeGpuTables || owner.mRole != ready->mNativeBundleOwnerRole ||
            ready->mView.mN != n || ready->mView.mRho != 1u ||
            ready->mView.mMinModulus != p ||
            ready->mView.mMaxModulus != p ||
            ready->mSlotCount != n || !ready->mSlotMap ||
            !ready->mInverseSlotMap ||
            !validRawPrimes(n, std::span<const u64>(&p, 1u)))
            return false;
        try
        {
            const RawPlainKey key{n, p, ready->mNativeBundleOwnerRole,
                true};
            auto& cache = *owner.mTables->mImpl;
            std::lock_guard<std::mutex> lock(cache.rawPlainMutex);
            for (auto& [cachedKey, value] : cache.rawPlains)
                if (cachedKey == key)
                {
                    // A sequential opt-out may have populated this role's raw
                    // table first. Publish the native bundle's owner so later
                    // getRaw users share the committed device allocation;
                    // existing shared owners remain valid until released.
                    value = ready;
                    return true;
                }
            cache.rawPlains.emplace_back(key, ready);
            return true;
        }
        catch (...) { return false; }
    }

    bool GpuPlainNtt::initRaw(u32 n, u64 p)
    {
        if (!mSetup || !prepareKernelDispatch(mView, mSetup->executionOptions().mAdvanced.mKernels)) return false;
        HostStep setupStep(mSetup->hostProfiler(), "setup GPU raw plaintext NTT init");
        u32 status = ~u32{0};
        RawSetupStream stream(mSetup);
        if (!stream.mStream) return false;
        RawConstantArena arena(static_cast<std::size_t>(n) *
            (2 * sizeof(HostShoupOperand) + 2 * sizeof(u32)) + 1024, stream);
        if (!arena) return false;
        allocateRawNttView(arena, mView, n, std::span<const u64>(&p, 1));
        auto* devicePrime = arena.take<u64>(1);
        auto* scratch = arena.take<u64>(3);
        auto* deviceStatus = arena.take<u32>(1);
        auto* map = arena.take<u32>(n);
        auto* inverseMap = arena.take<u32>(n);
        if (!devicePrime || !scratch || !deviceStatus ||
            !gpuMemcpyH2D(devicePrime, &p, sizeof(p), stream.mStream) ||
            !launchPrepareRawNttTables(mView, devicePrime, scratch, deviceStatus, stream.mStream) ||
            !launchPrepareRawSlotMaps(n, map, inverseMap, stream.mStream) ||
            !gpuMemcpyD2H(&status, deviceStatus, sizeof(status), stream.mStream) ||
            !stream.sync() || status != 0) return false;
        arena.publish(mOwned);
        mSlotMap = map;
        mInverseSlotMap = inverseMap;
        mSlotCount = n;
        return true;
    }

    bool GpuPlainNtt::init(const seal::SEALContext& batchingContext, const seal::BatchEncoder& encoder)
    {
        if (!mSetup || !prepareKernelDispatch(mView, mSetup->executionOptions().mAdvanced.mKernels)) return false;
        auto data = batchingContext.first_context_data();
        if (!data || !data->plain_ntt_tables()) return false;

        const seal::Modulus& p = data->parms().plain_modulus();
        const u32 n = static_cast<u32>(data->parms().poly_modulus_degree());
        if (n == 0 || (n & (n - 1u)) != 0 || p.value() == 0) return false;
        if (encoder.slot_count() != n) return false;

        mView.mN = n;
        mView.mRho = 1;
        mView.mMinModulus = p.value();
        mView.mMaxModulus = p.value();
        u32 logN = 0;
        while ((1u << logN) < n) ++logN;
        mView.mLogN = logN;
        mSlotCount = n;

        const seal::util::NTTTables& tbl = *data->plain_ntt_tables();

        std::vector<HostModulus> mods{ toHostModulus(p) };
        std::vector<HostShoupOperand> roots(n), invRoots(n);
        for (u32 i = 0; i < n; ++i)
        {
            roots[i] = toHostShoup(tbl.get_from_root_powers(i));
            invRoots[i] = toHostShoup(tbl.get_from_inv_root_powers(i));
        }
        std::vector<HostShoupOperand> invDegree{ toHostShoup(tbl.inv_degree_modulo()) };

        seal::util::MultiplyUIntModOperand scaled{};
        scaled.set(
            seal::util::multiply_uint_mod(
                tbl.get_from_inv_root_powers(n - 1).operand, tbl.inv_degree_modulo(), p),
            p);
        std::vector<HostShoupOperand> scaledInvRoot{ toHostShoup(scaled) };

        // SEAL keeps matrix_reps_index_map_ private, so it is recovered through
        // the public API instead of being reimplemented (which would silently
        // drift if SEAL ever changed it).
        //
        // decode(plain) computes t = NTT_p(plain) and returns
        // slots[i] = t[map[i]]. Feeding it plain = INTT_p(t) for the marker
        // sequence t[k] = k + 1 therefore yields slots[i] = map[i] + 1.
        std::vector<u64> marker(n);
        for (u32 k = 0; k < n; ++k) marker[k] = static_cast<u64>(k) + 1;
        if (marker[n - 1] >= p.value()) return false;   // needs p > N, true for 55-bit p
        seal::util::inverse_ntt_negacyclic_harvey(marker.data(), tbl);

        seal::Plaintext probe;
        probe.resize(n);
        for (u32 k = 0; k < n; ++k) probe[k] = marker[k];

        std::vector<u64> decoded;
        try
        {
            encoder.decode(probe, decoded);
        }
        catch (const std::exception&)
        {
            return false;
        }
        if (decoded.size() != n) return false;

        std::vector<u32> map(n), inverseMap(n);
        std::vector<bool> seen(n, false);
        for (u32 i = 0; i < n; ++i)
        {
            if (decoded[i] == 0 || decoded[i] > n) return false;
            const u32 src = static_cast<u32>(decoded[i] - 1);
            if (seen[src]) return false;                // must be a permutation
            seen[src] = true;
            map[i] = src;
            inverseMap[src] = i;
        }

        RawSetupStream stream(mSetup);
        if (!stream.mStream) return false;
        mView.mMods = uploadVector(mods, mOwned, stream);
        mView.mRoots = uploadVector(roots, mOwned, stream);
        mView.mInvRoots = uploadVector(invRoots, mOwned, stream);
        mView.mInvDegree = uploadVector(invDegree, mOwned, stream);
        mView.mScaledInvRoot = uploadVector(scaledInvRoot, mOwned, stream);
        mSlotMap = static_cast<const u32*>(uploadVector(map, mOwned, stream));
        mInverseSlotMap = static_cast<const u32*>(uploadVector(inverseMap, mOwned, stream));
        // The CRT fields stay null: with rho == 1 no kernel that uses them is
        // ever launched against this view.
        if (!mView.mMods || !mView.mRoots || !mView.mInvRoots || !mView.mInvDegree ||
            !mView.mScaledInvRoot || !mSlotMap || !mInverseSlotMap)
        {
            return false;
        }
        return stream.sync();
    }

    // ---- GpuPolyBuffer ----------------------------------------------------

    GpuPolyBuffer::GpuPolyBuffer(const GpuRing& ring, std::size_t count, GpuStream& stream)
    {
        if (!resize(ring, count, stream)) throw std::runtime_error("CUDA polynomial allocation failed");
    }

    GpuPolyBuffer::~GpuPolyBuffer()
    {
        release();
    }

    GpuPolyBuffer::GpuPolyBuffer(GpuPolyBuffer&& other) noexcept
        : mStorage(std::move(other.mStorage)), mData(other.mData), mCount(other.mCount),
          mPolyWords(other.mPolyWords), mCapacity(other.mCapacity)
    {
        other.mData = nullptr;
        other.mCount = 0;
        other.mCapacity = 0;
    }

    GpuPolyBuffer& GpuPolyBuffer::operator=(GpuPolyBuffer&& other) noexcept
    {
        if (this != &other)
        {
            release();
            mStorage = std::move(other.mStorage);
            mData = other.mData;
            mCount = other.mCount;
            mPolyWords = other.mPolyWords;
            mCapacity = other.mCapacity;
            other.mData = nullptr;
            other.mCount = 0;
            other.mCapacity = 0;
        }
        return *this;
    }

    void GpuPolyBuffer::release()
    {
        mStorage.reset();
        mData = nullptr;
        mCount = 0;
        mCapacity = 0;
    }

    bool GpuPolyBuffer::resize(const GpuRing& ring, std::size_t count, GpuStream& stream)
    {
        return resizeWords(ring.polyWords(), count, stream);
    }

    bool GpuPolyBuffer::resizeWords(std::size_t polyWords, std::size_t count, GpuStream& stream)
    {
        if (!polyWords || polyWords > std::numeric_limits<std::size_t>::max() / sizeof(u64) ||
            count > std::numeric_limits<std::size_t>::max() / sizeof(u64) / polyWords) return false;
        if (!count)
        {
            release();
            mPolyWords = polyWords;
            return true;
        }
        try
        {
            if (polyWords == mPolyWords && count <= mCapacity)
            {
                (void)data(stream);
                mCount = count;
                return true;
            }
            // Allocate first, preserving the old buffer on allocation failure.
            OwnedGpuBuffer next(stream.allocationOwner(), count * polyWords * sizeof(u64));
            mStorage = std::move(next);
            mData = static_cast<u64*>(mStorage.data());
            mPolyWords = polyWords;
            mCount = mCapacity = count;
            return true;
        }
        catch (...) { return false; }
    }

    bool GpuPolyBuffer::upload(std::span<const RnsPoly> polys, GpuStream& stream, std::size_t dstOffset)
    {
        if (polys.empty()) return true;
        if (dstOffset > mCount || polys.size() > mCount - dstOffset) return false;
        const std::size_t polyBytes = mPolyWords * sizeof(u64);

        // Coalesce the per-polynomial copies through pinned staging: one large
        // H2D beats hundreds of 256 KiB pageable transfers.
        const std::size_t maxRun = std::max<std::size_t>(1,
            (std::size_t(stream.options().mPolyStageMiB) << 20) / polyBytes);
        u8* stage = stream.staging(std::min(polys.size(), maxRun) * polyBytes);
        if (!stage)
        {
            for (std::size_t i = 0; i < polys.size(); ++i)
            {
                if (!upload(polys[i], dstOffset + i, stream)) return false;
            }
            return true;
        }

        std::size_t done = 0;
        while (done < polys.size())
        {
            // Wait only when the staging buffer is actually about to be overwritten,
            // The drain below protects the staging buffer, which download() and the
            // single-polynomial upload also share. Deferring it to the next use was
            // tried and broke correctness for exactly that reason: those other users
            // do not claim the buffer, so they overwrite bytes a queued copy is still
            // reading. Making it deferrable needs per-user staging or CUDA events.
            const std::size_t run = std::min(maxRun, polys.size() - done);
            for (std::size_t i = 0; i < run; ++i)
            {
                if (polys[done + i].mCoeffs.size() != mPolyWords) return false;
                std::memcpy(stage + i * polyBytes, polys[done + i].mCoeffs.data(), polyBytes);
            }
            if (!gpuMemcpyH2D(poly(dstOffset + done, stream), stage, run * polyBytes, stream.raw()) ||
                !stream.sync())
            {
                return false;
            }
            done += run;
        }
        return true;
    }

    bool GpuPolyBuffer::upload(const RnsPoly& p, std::size_t dstIdx, GpuStream& stream)
    {
        if (dstIdx >= mCount) return false;
        if (p.mCoeffs.size() != mPolyWords) return false;
        return gpuMemcpyH2D(poly(dstIdx, stream), p.mCoeffs.data(), mPolyWords * sizeof(u64), stream.raw());
    }

    bool GpuPolyBuffer::download(
        std::vector<RnsPoly>& polys, GpuStream& stream, std::size_t srcOffset, std::size_t count) const
    {
        if (srcOffset > mCount || count > mCount - srcOffset) return false;
        const std::size_t num = count ? count : (mCount - srcOffset);
        polys.resize(num);
        if (num == 0) return true;

        const std::size_t polyBytes = mPolyWords * sizeof(u64);
        const std::size_t maxRun = std::max<std::size_t>(1,
            (std::size_t(stream.options().mPolyStageMiB) << 20) / polyBytes);
        u8* stage = stream.staging(std::min(num, maxRun) * polyBytes);

        std::size_t done = 0;
        while (done < num)
        {
            const std::size_t run = std::min(maxRun, num - done);
            for (std::size_t i = 0; i < run; ++i)
            {
                if (polys[done + i].mCoeffs.size() != mPolyWords)
                {
                    polys[done + i].mCoeffs.resize(mPolyWords);
                }
            }
            if (stage)
            {
                if (!gpuMemcpyD2H(stage, poly(srcOffset + done, stream), run * polyBytes, stream.raw()) ||
                    !stream.sync())
                {
                    return false;
                }
                for (std::size_t i = 0; i < run; ++i)
                {
                    std::memcpy(polys[done + i].mCoeffs.data(), stage + i * polyBytes, polyBytes);
                }
            }
            else
            {
                // A later failed copy must not leave earlier writes using
                // the caller's host coefficients after this function returns.
                StreamDrain drain{stream};
                for (std::size_t i = 0; i < run; ++i)
                {
                    if (!gpuMemcpyD2H(
                            polys[done + i].mCoeffs.data(), poly(srcOffset + done + i, stream), polyBytes,
                            stream.raw()))
                    {
                        return false;
                    }
                }
                if (!drain.sync()) return false;
            }
            done += run;
        }
        return true;
    }

    bool GpuPolyBuffer::downloadPipelined(
        std::vector<RnsPoly>& polys, GpuStream& stream, u32 workers,
        std::size_t srcOffset, std::size_t count, CpuBenchmarkState cpuBenchmark) const
    {
        if (srcOffset > mCount || count > mCount - srcOffset ||
            !mPolyWords || mPolyWords > std::numeric_limits<std::size_t>::max() / sizeof(u64)) return false;
        const std::size_t num = count ? count : mCount - srcOffset;
        const std::size_t polyBytes = mPolyWords * sizeof(u64);
        constexpr std::size_t maxSlotBytes = std::size_t(32) << 20;
        if (polyBytes > maxSlotBytes || mCount > std::numeric_limits<std::size_t>::max() / polyBytes ||
            (num && !mData)) return false;
        HostStep totalStep(stream.hostProfiler(), "setup: pipelined batch download", &cpuBenchmark);
        std::vector<RnsPoly> next(num);
        if (!num)
        {
            polys = std::move(next);
            return true;
        }
        const std::size_t targetSlotBytes = (std::size_t(stream.options().mDownloadSlotMiB) << 20);
        const std::size_t runPolys = std::min(num, std::max<std::size_t>(1, targetSlotBytes / polyBytes));
        const std::size_t slotBytes = runPolys * polyBytes;
        auto& staging = stream.transferScratch().polynomials;
        StreamDrain drain{stream};
        u8* selected = nullptr;
        {
            HostStep stagingStep(stream.hostProfiler(), "setup: pipelined download pinned allocation", &cpuBenchmark);
            if (stream.options().mReuseDownloadStaging) selected = stream.existingStaging(2u * slotBytes);
            if (selected)
            {
                // Prior H2D reads and these D2H writes use the same stream.
                // Every CPU reader waits for its chunk event; joined workers
                // finish before either slot is reused. Never own/grow/free the
                // stream's borrowed buffer through the separate transfer scratch.
                if (!staging.prepareEvents()) return false;
            }
            else
            {
                if (!staging.reserve(stream, 2u * slotBytes, std::size_t(1) << 20)) return false;
                selected = staging.mPinned;
            }
        }
        // Workers borrow this stream's selected storage until their join.
        u8* const pinned = selected;
        struct CopyPool
        {
            macoro::thread_pool::work work;
            macoro::thread_pool pool;
            explicit CopyPool(std::size_t threads)
            {
                work = pool.make_work();
                try { pool.create_threads(threads); }
                catch (...) { stop(); throw; }
            }
            void stop()
            {
                work.reset();
                pool.join();
            }
            ~CopyPool() { stop(); }
        };
        std::unique_ptr<detail::ParallelWorkerSlotGuard> copySlots;
        std::unique_ptr<CopyPool> copyPool;
        std::size_t copyWorkers = 1;
        const auto requested = detail::resolveWorkerCount(workers, runPolys);
        if (stream.options().mDownloadReuseWorkers && num > runPolys && requested > 1)
        {
            HostStep workersStep(stream.hostProfiler(), "setup: pipelined download worker pool", &cpuBenchmark);
            // Reserve the same bounded worker budget once for this synchronous
            // download. No pool or reserved worker survives its return.
            copySlots = std::make_unique<detail::ParallelWorkerSlotGuard>(requested, cpuBenchmark.mContext);
            copyWorkers = std::min(requested, copySlots->grantedWorkers());
            if (copyWorkers > 1) copyPool = std::make_unique<CopyPool>(copyWorkers - 1);
        }
        auto materialize = [&](std::size_t offset, std::size_t length, u32 slot) {
            {
                HostStep waitStep(stream.hostProfiler(), "setup: pipelined download DMA wait", &cpuBenchmark);
                if (!gpuEventSync(staging.mEvent[slot])) return false;
            }
            HostStep copyStep(stream.hostProfiler(), "setup: pipelined download host copy", &cpuBenchmark);
            auto copyOne = [&](std::size_t i) {
                auto& coefficients = next[offset + i].mCoeffs;
                coefficients.resize(mPolyWords);
                std::memcpy(coefficients.data(), pinned + slot * slotBytes + i * polyBytes, polyBytes);
                return true;
            };
            if (!copyPool)
                return detail::runParallelTasks(length, copySlots ? 1 : workers, copyOne, false, &cpuBenchmark);

            const auto activeWorkers = std::min(copyWorkers, length);
            detail::ParallelWorkerCapScope capScope(activeWorkers);
            const auto cacheScope = currentProtocolCacheScope();
            auto worker = [&](std::size_t workerIdx, CpuBenchmarkState& cpuBenchmark) {
                CpuBenchmarkTaskScope taskScope(cpuBenchmark);
                ScopedProtocolCacheScope scopedCache(cacheScope);
                const auto begin = workerIdx * length / activeWorkers;
                const auto end = (workerIdx + 1) * length / activeWorkers;
                for (auto i = begin; i < end; ++i) (void)copyOne(i);
            };
            std::vector<macoro::eager_task<>> tasks;
            tasks.reserve(activeWorkers - 1);
            // On scheduling, allocation, or copy exceptions, finish every
            // queued worker before tasks, worker, or its borrowed storage die.
            // Individual waits keep the owning task vector intact even if an
            // awaiter allocation fails; all tasks already run concurrently.
            struct JoinOnFailure
            {
                CopyPool& pool;
                bool completed = false;
                ~JoinOnFailure() { if (!completed) pool.stop(); }
            } join{*copyPool};
            for (std::size_t i = 1; i < activeWorkers; ++i)
                tasks.push_back(detail::runPoolWorker(copyPool->pool, worker, i,
                    cacheScope, cpuBenchmark.mContext) | macoro::make_eager());
            worker(0, cpuBenchmark);
            for (auto& task : tasks) macoro::sync_wait(task);
            join.completed = true;
            return true;
        };
        std::size_t previousOffset = 0, previousLength = 0;
        u32 previousSlot = 0;
        for (std::size_t offset = 0; offset < num; offset += runPolys)
        {
            const std::size_t length = std::min(runPolys, num - offset);
            const u32 slot = static_cast<u32>((offset / runPolys) & 1u);
            // Slot i is reused only after its prior CPU copy finished. Queue
            // the next DMA before joining the previous chunk's host workers.
            if (!gpuMemcpyD2H(pinned + slot * slotBytes, poly(srcOffset + offset, stream),
                    length * polyBytes, stream.raw()) ||
                !gpuEventRecord(staging.mEvent[slot], stream.raw())) return false;
            if (previousLength && !materialize(previousOffset, previousLength, previousSlot)) return false;
            previousOffset = offset;
            previousLength = length;
            previousSlot = slot;
        }
        if (!materialize(previousOffset, previousLength, previousSlot) || !drain.sync()) return false;
        polys = std::move(next);
        return true;
    }

    bool GpuPolyBuffer::downloadAsync(RnsPoly& p, std::size_t srcIdx, GpuStream& stream) const
    {
        if (srcIdx >= mCount) return false;
        if (p.mCoeffs.size() != mPolyWords)
        {
            resizeZero(p.mCoeffs, mPolyWords);
        }
        return gpuMemcpyD2H(p.mCoeffs.data(), poly(srcIdx, stream), mPolyWords * sizeof(u64), stream.raw());
    }

    bool GpuPolyBuffer::zero(GpuStream& stream)
    {
        return gpuMemsetZero(data(stream), bytes(), stream.raw());
    }

    // ---- primitive wrappers ----------------------------------------------

    bool nttForward(const GpuRing& ring, u64* polys, u32 count, GpuStream& stream)
    {
        return launchNttForward(ring.view(stream), polys, count, nullptr, stream.raw());
    }

    bool nttInverse(const GpuRing& ring, u64* polys, u32 count, GpuStream& stream)
    {
        return launchNttInverse(ring.view(stream), polys, count, nullptr, stream.raw());
    }

    bool denoiseComb(const GpuRing& ring, const u64* in, u64* out, u32 outCount, GpuStream& stream)
    {
        if (!ring.denoiseReady()) return false;
        return launchDenoiseComb(ring.view(stream), ring.denoiseView(), in, out, outCount, stream.raw());
    }
}

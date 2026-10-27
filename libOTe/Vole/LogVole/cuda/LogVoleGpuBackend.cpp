#include "libOTe/Vole/LogVole/cuda/LogVoleGpuBackend.h"

#include "libOTe/Vole/LogVole/LogVoleArithmetic.h"
#include "libOTe/Vole/LogVole/LogVoleEncoding.h"
#include "libOTe/Vole/LogVole/LogVoleRuntime.h"
#include "libOTe/Vole/LogVole/LogVoleParallel.h"
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
#include <future>
#include <limits>
#include <mutex>
#include <sstream>
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
        std::size_t boundedStageBytes(const char* name, unsigned defaultMiB, unsigned maxMiB)
        {
            unsigned long value = defaultMiB;
            if (const char* setting = std::getenv(name))
            {
                char* end = nullptr;
                const auto parsed = std::strtoul(setting, &end, 10);
                if (end != setting && *end == '\0' && parsed >= 1u && parsed <= maxMiB)
                    value = parsed;
            }
            return static_cast<std::size_t>(value) << 20;
        }

        bool h200LazyResourcesDefault()
        {
            static const bool on = [] {
                int device = 0;
                cudaDeviceProp prop{};
                return cudaGetDevice(&device) == cudaSuccess &&
                    cudaGetDeviceProperties(&prop, device) == cudaSuccess &&
                    prop.major == 9 && std::strstr(prop.name, "H200") != nullptr;
            }();
            return on;
        }

        bool lazyRoleStreamsEnabled()
        {
            static const bool on = [] {
                const char* v = std::getenv("LV_GPU_LAZY_ROLE_STREAMS");
                return v ? std::strcmp(v, "1") == 0 : h200LazyResourcesDefault();
            }();
            return on;
        }

        bool lazyIndexScratchEnabled()
        {
            static const bool on = [] {
                const char* v = std::getenv("LV_GPU_LAZY_INDEX_SCRATCH");
                return v ? std::strcmp(v, "1") == 0 : h200LazyResourcesDefault();
            }();
            return on;
        }

        std::size_t indexScratchWords()
        {
            static const std::size_t words = [] {
                const char* v = std::getenv("LV_GPU_INDEX_SCRATCH_KIB");
                const unsigned long kib = v ? std::strtoul(v, nullptr, 10) : 4096u;
                return std::size_t(kib >= 256u && kib <= 4096u && (kib & (kib - 1u)) == 0u
                    ? kib : 4096u) * 256u;
            }();
            return words;
        }

        void* allocateIndexScratch(std::size_t bytes, void* stream)
        {
            struct RestoreStream
            {
                void* previous = gpuCurrentStream();
                ~RestoreStream() { gpuSetCurrentStream(previous); }
            } restore;
            // Direct GpuStream users need not have selected this stream in
            // threadStream(). Queue allocator reuse dependencies on the actual
            // H2D destination stream, without changing the caller's context.
            gpuSetCurrentStream(stream);
            return gpuMalloc(bytes);
        }

        // Keep main and sampler stream families independent. A role-specific
        // call constructs only its own thread-local stream, not two unrelated
        // streams and their pinned index buffers. Destruction retains the same
        // GpuStream drain/allocator-forget protocol.
        template<bool SampleLane>
        GpuStream& lazyRoleStream()
        {
            switch (currentProtocolCacheScope().mRole)
            {
            case ProtocolCacheRole::Sender:
            {
                thread_local GpuStream sender;
                return sender;
            }
            case ProtocolCacheRole::Receiver:
            {
                thread_local GpuStream receiver;
                return receiver;
            }
            default:
            {
                thread_local GpuStream unspecified;
                return unspecified;
            }
            }
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

        // Immortal for the same reason as the device allocator: GpuRing's
        // destructor calls gpuFree, and the two sets of statics live in
        // different translation units with no destruction-order guarantee.
        using RingCache = std::unordered_map<RingCacheKey, std::shared_ptr<GpuRing>, RingCacheKeyHash>;
        RingCache& ringCache()
        {
            static auto* c = new RingCache();
            return *c;
        }
        std::mutex gRingCacheMutex;

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
        RawRingCache& rawRingCache()
        {
            static auto* cache = new RawRingCache();
            return *cache;
        }
        std::mutex gRawRingCacheMutex;

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

        // Setup needs no per-query index/staging scratch. A thread owns one
        // registered stream per role, constructed on its first timed use. This
        // keeps consecutive raw factories on the same stream: tiny metadata
        // blocks return to the allocator's same-stream bucket without a new
        // cudaMallocAsync or a cross-stream event handoff. Different parties
        // and worker threads never share a mutable stream.
        struct RawSetupStreamOwner
        {
            void* mStream = nullptr;
            void* ensureStream()
            {
                // A transient creation failure must not poison later raw
                // factories in this thread and role.
                if (!mStream) mStream = gpuStreamCreate();
                return mStream;
            }
            ~RawSetupStreamOwner()
            {
                if (!mStream) return;
                gpuStreamSync(mStream);
                gpuSetCurrentStream(nullptr);
                gpuForgetStream(mStream);
                gpuStreamDestroy(mStream);
            }
        };

        RawSetupStreamOwner& roleRawSetupStream()
        {
            switch (currentProtocolCacheScope().mRole)
            {
            case ProtocolCacheRole::Sender:
            {
                thread_local RawSetupStreamOwner sender;
                return sender;
            }
            case ProtocolCacheRole::Receiver:
            {
                thread_local RawSetupStreamOwner receiver;
                return receiver;
            }
            default:
            {
                thread_local RawSetupStreamOwner unspecified;
                return unspecified;
            }
            }
        }

        struct RawSetupStream
        {
            void* mPrevious = gpuCurrentStream();
            void* mStream = roleRawSetupStream().ensureStream();
            RawSetupStream() { if (mStream) gpuSetCurrentStream(mStream); }
            ~RawSetupStream()
            {
                // A failed launch/copy must drain before an arena or temporary
                // host record expires. The owner keeps the stream registered.
                if (mStream) gpuStreamSync(mStream);
                gpuSetCurrentStream(mPrevious);
            }
            bool sync() const { return mStream && gpuStreamSync(mStream); }
        };

        // One allocation keeps the generated tables contiguous and removes the
        // many small allocations/uploads in the host-built constant path.
        class RawConstantArena
        {
        public:
            RawConstantArena(std::size_t bytes, void* stream)
                : mData(static_cast<u8*>(gpuMalloc(bytes))), mCapacity(bytes), mStream(stream) {}
            ~RawConstantArena()
            {
                if (mData) { gpuStreamSync(mStream); gpuFree(mData); }
            }
            explicit operator bool() const { return mData != nullptr; }
            template<typename T> T* take(std::size_t count)
            {
                // Some NTT kernels vector-load HostShoupOperand as
                // ulonglong2. Keep every suballocation at least 16-byte
                // aligned so raw tables retain cudaMalloc's alignment.
                const auto offset = alignUp(mUsed,
                    std::max<std::size_t>(alignof(T), 16u));
                if (!mData || offset > mCapacity || count > (mCapacity - offset) / sizeof(T)) return nullptr;
                mUsed = offset + count * sizeof(T);
                return reinterpret_cast<T*>(mData + offset);
            }
            void publish(std::vector<void*>& owned)
            {
                owned.push_back(mData);
                mData = nullptr;
            }
            void* release()
            {
                void* owned = mData;
                mData = nullptr;
                return owned;
            }
        private:
            u8* mData = nullptr;
            std::size_t mCapacity = 0;
            std::size_t mUsed = 0;
            void* mStream = nullptr;
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
        void* uploadVector(const std::vector<T>& host, std::vector<void*>& owned)
        {
            if (host.empty()) return nullptr;
            HostStep allocationStep("setup GPU constants allocate");
            void* d = gpuMalloc(host.size() * sizeof(T));
            allocationStep.stop();
            if (!d) return nullptr;
            HostStep uploadStep("setup GPU constants upload");
            if (!gpuMemcpyH2D(d, host.data(), host.size() * sizeof(T), nullptr))
            {
                gpuFree(d);
                return nullptr;
            }
            owned.push_back(d);
            return d;
        }
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

    bool nativeSealBundleCacheRequested()
    {
        const auto owner = currentProtocolCacheScope();
        if (!enabled() ||
            (owner.mRole != ProtocolCacheRole::Sender &&
                owner.mRole != ProtocolCacheRole::Receiver)) return false;
        const char* optIn = std::getenv("LV_GPU_NATIVE_SEAL_BUNDLE");
        return optIn && std::strcmp(optIn, "1") == 0 &&
            available() && currentDeviceOrdinal() == 0;
    }

    bool selectSealCoeffModuliDevice(const RingParams& params,
        std::vector<u64>& orderedPrimes)
    {
        HostStep step("setup: dynamic GPU ring prime selection");
        if (!dynamicSealSetupSupported(params) || !available() || currentDeviceOrdinal() != 0)
            return false;
        const u32 rho = static_cast<u32>(params.mCoeffModulusBits.size());
        RawSetupStream stream;
        if (!stream.mStream) return false;
        RawConstantArena arena(256u, stream.mStream);
        auto* bits = arena.take<int>(rho);
        const std::size_t recordBytes = static_cast<std::size_t>(rho) * sizeof(u64) + sizeof(u32);
        auto* record = arena.take<u8>(recordBytes);
        auto* primes = reinterpret_cast<u64*>(record);
        auto* status = record ? reinterpret_cast<u32*>(record + rho * sizeof(u64)) : nullptr;
        if (!bits || !primes || !status ||
            !gpuMemcpyH2D(bits, params.mCoeffModulusBits.data(), rho * sizeof(int), stream.mStream) ||
            !launchSelectSealCoeffModuli(params.mPolyModulusDegree, bits, rho,
                primes, status, stream.mStream)) return false;
        std::array<u8, 16u * sizeof(u64) + sizeof(u32)> hostRecord{};
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
        u64& selectedPrime, u32& selectedBits)
    {
        HostStep step("setup: dynamic GPU plaintext prime selection");
        if (n < 1024u || n > 131072u || (n & (n - 1u)) || !requestedBits ||
            minimumQ <= 2u * n || !available() || currentDeviceOrdinal() != 0)
            return false;
        RawSetupStream stream;
        if (!stream.mStream) return false;
        RawConstantArena arena(128u, stream.mStream);
        auto* record = arena.take<u8>(sizeof(u64) + 2u * sizeof(u32));
        auto* prime = reinterpret_cast<u64*>(record);
        auto* bits = record ? reinterpret_cast<u32*>(record + sizeof(u64)) : nullptr;
        auto* status = record ? reinterpret_cast<u32*>(record + sizeof(u64) + sizeof(u32)) : nullptr;
        if (!prime || !bits || !status ||
            !launchSelectSealPlainModulus(n, requestedBits, minimumQ,
                prime, bits, status, stream.mStream)) return false;
        std::array<u8, sizeof(u64) + 2u * sizeof(u32)> hostRecord{};
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
        HostStep step("setup: dynamic GPU plaintext lift");
        const auto& view = ring.view();
        if (!ring.n() || !ring.rho() || ring.rho() > 16u ||
            plaintextPrime <= 2u * ring.n() || plaintextPrime >= view.mMinModulus ||
            !view.mBaseProd || !available() || currentDeviceOrdinal() != 0) return false;
        RawSetupStream stream;
        if (!stream.mStream) return false;
        RawConstantArena arena(256u, stream.mStream);
        const std::size_t recordBytes = static_cast<std::size_t>(ring.rho()) * sizeof(u64) + sizeof(u32);
        auto* record = arena.take<u8>(recordBytes);
        auto* output = reinterpret_cast<u64*>(record);
        auto* status = record ? reinterpret_cast<u32*>(record + ring.rho() * sizeof(u64)) : nullptr;
        if (!output || !status ||
            !launchPreparePlaintextLift(view, plaintextPrime, output, status, stream.mStream))
            return false;
        std::array<u8, 16u * sizeof(u64) + sizeof(u32)> hostRecord{};
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
        u32 requestedPlaintextBits, NativeSealSetupBundle& out)
    {
        HostStep step("setup: bundled native GPU SEAL factories");
        const char* optIn = std::getenv("LV_GPU_NATIVE_SEAL_BUNDLE");
        const char* ringOpt = std::getenv("LV_GPU_SETUP_LIGHTWEIGHT_RING");
        const char* crtOpt = std::getenv("LV_GPU_SETUP_LIGHTWEIGHT_CRT");
        const char* fullChain = std::getenv("LV_GPU_SETUP_FULL_MOD_CHAIN");
        const char* singleLimb = std::getenv("LV_GPU_SETUP_BATCHING_SINGLE_LIMB");
        if (!optIn || std::strcmp(optIn, "1") != 0 ||
            (ringOpt && ringOpt[0] == '0') ||
            (crtOpt && crtOpt[0] == '0') ||
            (fullChain && fullChain[0] == '1') ||
            (singleLimb && singleLimb[0] == '0') ||
            !dynamicSealSetupSupported(params) ||
            requestedPlaintextBits < 2u || !available() ||
            currentDeviceOrdinal() != 0) return false;
        const auto ownerScope = currentProtocolCacheScope();
        if ((ownerScope.mRole != ProtocolCacheRole::Sender &&
             ownerScope.mRole != ProtocolCacheRole::Receiver) ||
            !ownerScope.mRunId) return false;
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
            RawSetupStream stream;
            if (!stream.mStream) return false;
            RawConstantArena arena(capacity, stream.mStream);
            if (!arena) return false;
            constexpr std::size_t maxRecordBytes =
                16u * 2u * sizeof(u64) + sizeof(u64) + 6u * sizeof(u32);
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
            const char* packedSetting =
                std::getenv("LV_GPU_NOGOLD_H200_FP52_PACKED_ROOTS");
            const u32 packedMode = !packedSetting ? 1u :
                packedSetting[0] >= '1' && packedSetting[0] <= '3' &&
                packedSetting[1] == '\0'
                    ? static_cast<u32>(packedSetting[0] - '0') : 0u;
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
            std::array<u8, maxRecordBytes> hostRecord{};
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
            if (actualPlainBits != hostBits ||
                currentProtocolCacheScope().mRole != ownerScope.mRole ||
                currentProtocolCacheScope().mRunId != ownerScope.mRunId)
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
            if (fp52Shape && h200Fp52GadgetConstantsEnabled())
            {
                const bool prediv = h200Fp52GadgetPredivEnabled();
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
            std::shared_ptr<void> storage(arena.release(),
                [](void* p) { gpuFree(p); });
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

    // ---- GpuStream --------------------------------------------------------

    GpuStream::GpuStream() : GpuStream(false, true) {}

    GpuStream::GpuStream(bool highestPriority, bool allocateScratch)
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
        if (!mStream || !allocateScratch) return;
        mScratchWords = indexScratchWords(); // default 4 MiB
        if (lazyIndexScratchEnabled()) return;
        mDeviceScratch = static_cast<u32*>(allocateIndexScratch(mScratchWords * sizeof(u32), mStream));
        mHostScratch = static_cast<u32*>(gpuMallocHost(mScratchWords * sizeof(u32)));
    }

    std::unique_ptr<GpuStream> GpuStream::createHighestPriority()
    {
        auto stream = std::unique_ptr<GpuStream>(new GpuStream(true, false));
        if (!stream->mStream || !stream->mHighestPriority) return nullptr;
        return stream;
    }

    GpuStream::~GpuStream()
    {
        if (!mStream) return;
        gpuStreamSync(mStream);
        if (mHighestPriority)
        {
            // This lean stream never owns allocator-managed storage and is not
            // registered with the allocator. Destroy it without publishing it
            // as the allocation stream, even transiently.
            gpuStreamDestroy(mStream);
            return;
        }
        // Release this stream's own buffers *as* this stream. gpuFree tags a block
        // with gCurrentStream, and at thread exit that can name a sibling
        // thread_local GpuStream that was already destroyed. The allocator refuses
        // to touch a stream it has not been told about, but pointing it at the live
        // handle here keeps the tagging honest as well as safe.
        gpuSetCurrentStream(mStream);
        gpuFree(mDeviceScratch);
        gpuFreeHost(mHostScratch);
        gpuFreeHost(mStaging);
        gpuSetCurrentStream(nullptr);
        // The frees above return blocks to the caching allocator tagged with this
        // stream. It is about to stop existing, so the allocator has to forget it
        // first - the driver reuses cudaStream_t values, and a block left tagged
        // with a dead handle would be mistaken for one belonging to whichever new
        // stream inherits it.
        gpuForgetStream(mStream);
        gpuStreamDestroy(mStream);
    }

    u8* GpuStream::staging(std::size_t bytes)
    {
        if (bytes <= mStagingBytes) return mStaging;
        // Pinning is expensive, so grow in large steps and never shrink.
        std::size_t want = mStagingBytes ? mStagingBytes : (std::size_t(8) << 20);
        while (want < bytes) want *= 2;
        gpuStreamSync(mStream);
        gpuFreeHost(mStaging);
        mStaging = static_cast<u8*>(gpuMallocHost(want));
        mStagingBytes = mStaging ? want : 0;
        return mStaging;
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
        if (lazyIndexScratchEnabled() && mScratchWords != 0u)
        {
            if (!mDeviceScratch)
                mDeviceScratch = static_cast<u32*>(allocateIndexScratch(mScratchWords * sizeof(u32), mStream));
            if (!mHostScratch)
                mHostScratch = static_cast<u32*>(gpuMallocHost(mScratchWords * sizeof(u32)));
        }
        if (!mDeviceScratch || !mHostScratch) return nullptr;
        if (mScratchUsed + idx.size() > mScratchWords)
        {
            // Wrapping would corrupt in-flight work, so make sure the stream is
            // drained first. Index arrays are tiny; this path is rare.
            gpuStreamSync(mStream);
            mScratchUsed = 0;
            if (idx.size() > mScratchWords) return nullptr;
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

    GpuStream& threadStream()
    {
        if (lazyRoleStreamsEnabled())
        {
            auto& stream = lazyRoleStream<false>();
            gpuSetCurrentStream(stream.raw());
            return stream;
        }
        // Keyed on the protocol role as well as the thread. The sender and the
        // receiver run as interleaved coroutines on one host thread, so a purely
        // thread-local stream serialised two parties whose GPU work is completely
        // independent: nsys showed every kernel of a run on a single stream with
        // the device idle 41% of the time. Their device buffers are disjoint, so
        // separate streams are safe once the caching allocator is stream-aware.
        thread_local GpuStream unspecified;
        thread_local GpuStream sender;
        thread_local GpuStream receiver;

        GpuStream* s = &unspecified;
        switch (currentProtocolCacheScope().mRole)
        {
        case ProtocolCacheRole::Sender:
            s = &sender;
            break;
        case ProtocolCacheRole::Receiver:
            s = &receiver;
            break;
        default:
            break;
        }
        gpuSetCurrentStream(s->raw());
        return *s;
    }

    GpuStream& threadSampleStream()
    {
        if (lazyRoleStreamsEnabled()) return lazyRoleStream<true>();
        // A second stream per role, used only for work independent of the main
        // chain, so an instruction-bound kernel can overlap a bandwidth-bound one.
        // Keyed the same way as threadStream so the two parties do not share it.
        thread_local GpuStream unspecified;
        thread_local GpuStream sender;
        thread_local GpuStream receiver;

        switch (currentProtocolCacheScope().mRole)
        {
        case ProtocolCacheRole::Sender:
            return sender;
        case ProtocolCacheRole::Receiver:
            return receiver;
        default:
            return unspecified;
        }
    }

    u32 threadStreamSlot()
    {
        switch (currentProtocolCacheScope().mRole)
        {
        case ProtocolCacheRole::Sender:
            return 1;
        case ProtocolCacheRole::Receiver:
            return 2;
        default:
            return 0;
        }
    }

    bool downloadToHost(void* dst, const void* deviceSrc, std::size_t bytes, GpuStream& stream)
    {
        if (bytes == 0) return true;
        if (!dst || !deviceSrc) return false;

        // 16 MiB per buffer keeps the pinned footprint at 32 MiB while still
        // being large enough that each transfer reaches peak PCIe bandwidth.
        // These buffers are dedicated to downloads rather than shared with
        // GpuStream::staging, which is sized by the largest polynomial batch and
        // would otherwise be reallocated back and forth between the two sizes.
        constexpr std::size_t kChunk = std::size_t(16) << 20;

        thread_local struct DownloadStaging
        {
            u8* mPinned = nullptr;
            void* mEvent[2]{ nullptr, nullptr };

            DownloadStaging()
            {
                mPinned = static_cast<u8*>(gpuMallocHost(2 * kChunk));
                mEvent[0] = gpuEventCreate();
                mEvent[1] = gpuEventCreate();
            }
            ~DownloadStaging()
            {
                gpuFreeHost(mPinned);
                gpuEventDestroy(mEvent[0]);
                gpuEventDestroy(mEvent[1]);
            }
            bool ready() const { return mPinned && mEvent[0] && mEvent[1]; }
        } staging;

        if (!staging.ready())
        {
            // No pinned memory available; the slow path is still correct.
            return gpuMemcpyD2H(dst, deviceSrc, bytes, stream.raw()) && stream.sync();
        }
        u8* pinned = staging.mPinned;
        auto& events = staging;

        if (bytes <= kChunk)
        {
            if (!gpuMemcpyD2H(pinned, deviceSrc, bytes, stream.raw()) || !stream.sync()) return false;
            std::memcpy(dst, pinned, bytes);
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
        return true;
    }

    bool uploadFromHost(void* deviceDst, const void* src, std::size_t bytes, GpuStream& stream)
    {
        if (bytes == 0) return true;
        if (!deviceDst || !src) return false;

        // Explicit opt-in: on H200 the CUDA driver's pageable-copy staging is
        // faster than an extra host memcpy through our pinned buffers. Keep the
        // pipeline available for platforms where that trade-off is reversed.
        static const bool enabled = [] {
            const char* v = std::getenv("LV_GPU_PIPELINED_UPLOAD");
            return v && v[0] == '1';
        }();
        constexpr std::size_t kChunk = std::size_t(16) << 20;
        if (!enabled || bytes <= kChunk)
        {
            return gpuMemcpyH2D(deviceDst, src, bytes, stream.raw());
        }

        thread_local struct UploadStaging
        {
            u8* mPinned = nullptr;
            void* mEvent[2]{ nullptr, nullptr };
            bool mPending[2]{ false, false };

            UploadStaging()
            {
                mPinned = static_cast<u8*>(gpuMallocHost(2 * kChunk));
                mEvent[0] = gpuEventCreate();
                mEvent[1] = gpuEventCreate();
            }
            ~UploadStaging()
            {
                for (u32 i = 0; i < 2; ++i)
                    if (mPending[i] && mEvent[i]) gpuEventSync(mEvent[i]);
                gpuFreeHost(mPinned);
                gpuEventDestroy(mEvent[0]);
                gpuEventDestroy(mEvent[1]);
            }
            bool ready() const { return mPinned && mEvent[0] && mEvent[1]; }
        } staging;

        if (!staging.ready())
        {
            return gpuMemcpyH2D(deviceDst, src, bytes, stream.raw());
        }

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
        bool transferSetupWire(void* host, std::size_t bytes, GpuStream& stream,
            bool registerFresh, bool fallbackOnPoolPinFailure,
            const DirectCopy& directCopy, const FallbackCopy& fallbackCopy,
            bool* cudaOwnedDirectCompleted = nullptr)
        {
            if (cudaOwnedDirectCompleted) *cudaOwnedDirectCompleted = false;
            SetupWireTransfer transfer{stream};
            const char* enabled = std::getenv("LV_GPU_SETUP_PINNED_WIRE");
            const bool usePinned = !enabled || enabled[0] != '0';
            // This exact sender-owned Root wire is backed by cudaHostAlloc,
            // not by the lazily registered setup pool. Its allocator tracks
            // the active range until coproto finishes the borrowed TCP send.
            const bool cudaOwnedRoot = usePinned &&
                isRootCudaWireHostRange(host, bytes);
            const bool pooledOwner = usePinned && gpuIsSetupWireHostRange(host, bytes);
            bool pooled = pooledOwner && gpuIsSetupWirePinnedHostRange(host, bytes);
            if (pooledOwner && !pooled && registerFresh)
            {
                HostStep registerStep("setup: persistent wire registration");
                if (!gpuTryPinSetupWireHostRange(host, bytes, pooled) &&
                    !fallbackOnPoolPinFailure) return false;
            }
            if (!pooledOwner && !cudaOwnedRoot &&
                bytes >= (std::size_t{1} << 20) &&
                usePinned && registerFresh)
            {
                HostStep registerStep("setup: wire host registration");
                bool registered = false;
                if (!gpuTryRegisterHost(host, bytes, registered)) return false;
                if (registered) transfer.mRegistered = host;
            }
            HostStep copyStep(cudaOwnedRoot ? "setup: CUDA-owned Root wire transfer" : pooled
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

    bool downloadSetupWire(void* hostDst, const void* deviceSrc, std::size_t bytes, GpuStream& stream)
    {
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
        const char* direct = std::getenv("LV_GPU_SETUP_DIRECT_WIRE_DOWNLOAD");
        const bool pinFreshPool = (!direct || direct[0] != '0') &&
            gpuIsSetupWireHostRange(hostDst, bytes);
        bool cudaOwnedDirectCompleted = false;
        const bool completed = transferSetupWire(hostDst, bytes, stream,
            pinFreshPool, true,
            [&] { return gpuMemcpyD2H(hostDst, deviceSrc, bytes, stream.raw()); },
            [&] { return downloadToHost(hostDst, deviceSrc, bytes, stream); },
            &cudaOwnedDirectCompleted);
        recordRootCudaWireDirectDownload(hostDst, bytes, cudaOwnedDirectCompleted);
        return completed;
    }

    bool uploadSetupWire(void* deviceDst, const void* hostSrc, std::size_t bytes, GpuStream& stream)
    {
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
        return transferSetupWire(const_cast<void*>(hostSrc), bytes, stream, true, false,
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

    GpuRing::~GpuRing()
    {
        for (void* p : mOwned) gpuFree(p);
    }

    std::shared_ptr<GpuRing> GpuRing::get(const RingNttContext& ctx)
    {
        HostStep getStep("setup GPU ring get");
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
                    certificate->rawOwnerRole() ==
                        currentProtocolCacheScope().mRole
                    ? certificate : nullptr;
            }
            return getRaw(ctx.mParams, ctx.mRawModuli->mValues);
        }
        if (!available()) return nullptr;

        RingCacheKey key{};
        key.mDegree = ctx.mParams.mPolyModulusDegree;
        key.mBits.assign(ctx.mParams.mCoeffModulusBits.begin(), ctx.mParams.mCoeffModulusBits.end());
        key.mRole = currentProtocolCacheScope().mRole;

        std::lock_guard<std::mutex> lock(gRingCacheMutex);
        auto it = ringCache().find(key);
        if (it != ringCache().end()) return it->second;

        std::shared_ptr<GpuRing> ring(new GpuRing());
        if (!ring->init(ctx)) return nullptr;
        ringCache().emplace(std::move(key), ring);
        return ring;
    }

    std::shared_ptr<GpuRing> GpuRing::getRaw(const RingParams& params, std::span<const u64> primes)
    {
        HostStep getStep("setup GPU raw ring get");
        if (!validRawPrimes(params.mPolyModulusDegree, primes) ||
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
                currentProtocolCacheScope().mRole,
                nativeSealBundleCacheRequested()};
            std::lock_guard<std::mutex> lock(gRawRingCacheMutex);
            if (auto it = rawRingCache().find(key); it != rawRingCache().end()) return it->second;
            std::shared_ptr<GpuRing> ring(new GpuRing());
            if (!ring->initRaw(params, primes)) return nullptr;
            rawRingCache().emplace(std::move(key), ring);
            return ring;
        }
        catch (...) { return nullptr; }
    }

    bool GpuRing::publishRaw(const RingParams& params,
        std::span<const u64> orderedPrimes,
        const std::shared_ptr<GpuRing>& ready)
    {
        if (!ready || !ready->mNativeSealBundleStorage || !ready->mRaw ||
            !ready->mDenoiseReady || !ready->mSampleMaxMultiple ||
            !nativeSealBundleCacheRequested() ||
            ready->mRawOwnerRole != currentProtocolCacheScope().mRole ||
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
                currentProtocolCacheScope().mRole, true};
            std::lock_guard<std::mutex> lock(gRawRingCacheMutex);
            if (auto it = rawRingCache().find(key); it != rawRingCache().end())
            {
                // A same-role sequential table may have been built before the
                // combined factory committed. A shared_ptr already borrowed
                // by that earlier caller remains valid after replacement.
                it->second = ready;
                return true;
            }
            rawRingCache().emplace(std::move(key), ready);
            return true;
        }
        catch (...) { return false; }
    }

    bool GpuRing::initRaw(const RingParams& params, std::span<const u64> primes)
    {
        HostStep setupStep("setup GPU raw ring init");
        const u32 n = params.mPolyModulusDegree;
        const u32 rho = static_cast<u32>(primes.size());
        const std::size_t words = static_cast<std::size_t>(n) * rho;
        mParams = params;
        mRawOwnerRole = currentProtocolCacheScope().mRole;
        mHostModuli.assign(primes.begin(), primes.end());

        // Status and prime owners outlive every asynchronous operation, even
        // when launch/allocation fails before the normal publication boundary.
        u32 status = ~u32{0};
        RawSetupStream stream;
        if (!stream.mStream) return false;
        RawConstantArena arena(words * (2 * sizeof(HostShoupOperand) + 2 * sizeof(double)) + 16384, stream.mStream);
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
        const char* packedSetting = std::getenv("LV_GPU_NOGOLD_H200_FP52_PACKED_ROOTS");
        const u32 packedMode = !packedSetting ? 1u : packedSetting[0] >= '1' &&
            packedSetting[0] <= '3' && packedSetting[1] == '\0'
            ? static_cast<u32>(packedSetting[0] - '0') : 0u;
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
        if (fp52Shape && h200Fp52GadgetConstantsEnabled())
        {
            const bool prediv = h200Fp52GadgetPredivEnabled();
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
        HostStep initStep("setup GPU ring init");
        auto keyData = ctx.mContext ? ctx.mContext->key_context_data() : nullptr;
        if (!keyData) return false;

        HostStep hostTablesStep("setup GPU ring host tables");

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

        hostTablesStep.stop();
        HostStep constantsStep("setup GPU ring constants");
        mView.mMods = uploadVector(mods, mOwned);
        mView.mRoots = uploadVector(roots, mOwned);
        mView.mInvRoots = uploadVector(invRoots, mOwned);
        mView.mInvDegree = uploadVector(invDegree, mOwned);
        mView.mScaledInvRoot = uploadVector(scaledInvRoot, mOwned);
        mView.mBaseProd = static_cast<const u64*>(uploadVector(baseProd, mOwned));
        mView.mBaseProdHalf = static_cast<const u64*>(uploadVector(baseProdHalf, mOwned));
        mView.mPuncturedProd = static_cast<const u64*>(uploadVector(punctured, mOwned));
        mView.mInvPuncturedProd = uploadVector(invPunctured, mOwned);
        mView.mGarnerInv = uploadVector(garnerInv, mOwned);

        // Compact inverse twiddles are immutable, prepared once with the ring
        // outside the online query, and never replace the integer fallback.
        // Forward packing remains opt-in: it did not win at both query sizes.
        const char* packedSetting = std::getenv("LV_GPU_NOGOLD_H200_FP52_PACKED_ROOTS");
        const u32 packedMode = !packedSetting ? 1u : packedSetting[0] >= '1' &&
            packedSetting[0] <= '3' && packedSetting[1] == '\0'
            ? static_cast<u32>(packedSetting[0] - '0') : 0u;
        if (packedMode && h200LazyResourcesDefault() && n == 16384u && rho == 8u &&
            mView.mMinModulus > (u64{1} << 51u) && mView.mMaxModulus < (u64{1} << 52u))
        {
            std::vector<double> compact(roots.size());
            if (packedMode & 1u)
            {
                std::transform(invRoots.begin(), invRoots.end(), compact.begin(),
                    [](const HostShoupOperand& root) { return static_cast<double>(root.mOperand); });
                mView.mFp52InvRoots = static_cast<const double*>(uploadVector(compact, mOwned));
                if (!mView.mFp52InvRoots) return false;
            }
            if (packedMode & 2u)
            {
                std::transform(roots.begin(), roots.end(), compact.begin(),
                    [](const HostShoupOperand& root) { return static_cast<double>(root.mOperand); });
                mView.mFp52Roots = static_cast<const double*>(uploadVector(compact, mOwned));
                if (!mView.mFp52Roots) return false;
            }
        }

        // Immutable SEAL uniform-sampling rejection thresholds. A fresh Root
        // key only uploads its 64-byte seed, not new per-limb metadata.
        std::vector<u64> sampleMax(rho);
        for (u32 j = 0u; j < rho; ++j)
            sampleMax[j] = ~u64(0) -
                seal::util::barrett_reduce_64(~u64(0), ctx.mModuli[j]) - 1u;
        mSampleMaxMultiple = static_cast<const u64*>(uploadVector(sampleMax, mOwned));

        if (!mView.mMods || !mView.mRoots || !mView.mInvRoots || !mView.mInvDegree ||
            !mView.mScaledInvRoot || !mView.mBaseProd || !mView.mBaseProdHalf ||
            !mView.mPuncturedProd || !mView.mInvPuncturedProd || !mView.mGarnerInv ||
            !mSampleMaxMultiple)
        {
            return false;
        }

        mHostModulusData = std::move(mods);

        // Mirrors buildRecursiveLeafScaling: prod_{w != j} q_w mod q_j and its
        // multiplicative inverse.
        {
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
            mCrtLift = static_cast<const u64*>(uploadVector(lift, mOwned));
            mInvCrtLift = static_cast<const u64*>(uploadVector(invLift, mOwned));
            if (!mCrtLift || !mInvCrtLift) return false;
        }

        constantsStep.stop();
        {
            HostStep denoiseStep("setup GPU ring denoise constants");
            mDenoiseReady = initDenoise(ctx);
        }
        HostStep gadgetStep("setup GPU ring gadget constants");
        if (h200Fp52GadgetConstantsEnabled() &&
            h200LazyResourcesDefault() && n == 16384u && rho == 8u &&
            mView.mMinModulus > (u64{1} << 51u) && mView.mMaxModulus < (u64{1} << 52u))
        {
            double* constants = nullptr;
            const bool prediv = h200Fp52GadgetPredivEnabled();
            {
                struct RestoreStream
                {
                    void* previous = gpuCurrentStream();
                    ~RestoreStream() { gpuSetCurrentStream(previous); }
                } restore;
                // Match caching-allocator reuse dependencies to the setup
                // stream, which also carries the preceding constant uploads.
                gpuSetCurrentStream(nullptr);
                constants = static_cast<double*>(gpuMalloc((prediv ? 144u : 80u) * sizeof(double)));
            }
            if (!constants) return false;
            mOwned.push_back(constants);
            double* ratios = prediv ? constants + 80u : nullptr;
            if (!launchPrepareH200Fp52GadgetConstants(mView, constants, nullptr, ratios)) return false;
            mView.mFp52GadgetConstants = constants;
            mView.mFp52GadgetRatios = ratios;
        }
        gadgetStep.stop();
        {
            HostStep persistenceStep("setup GPU ring L2 persistence");
            if (!prepareH200RootPersistence(mView)) return false;
        }
        // Also completes the optional setup kernel before cache publication.
        HostStep syncStep("setup GPU ring final sync");
        return gpuDeviceSync();
    }

    struct GpuRingSetupPrefetch::Impl
    {
        std::future<bool> mFuture;
        bool mSuccess = false;
    };

    GpuRingSetupPrefetch::GpuRingSetupPrefetch(const RingNttContext& ctx, bool gpuEnabled)
    {
        const char* value = std::getenv("LV_GPU_SETUP_INIT_OVERLAP");
        if (!gpuEnabled || (value && value[0] == '0') || (!ctx.mContext && !ctx.mGpuLightweight)) return;
        HostStep startStep("setup GPU ring prefetch start");
        int device = 0;
        if (cudaGetDevice(&device) != cudaSuccess) return;
        // The existing caching allocator selects device 0's memory pool. Do
        // not extend its single-device assumptions to another current device.
        if (device != 0) return;

        try
        {
            if (ctx.mGpuLightweight)
            {
                if (!validateRingContextMetadata(ctx)) return;
                RawRingCacheKey key;
                key.mDegree = ctx.mParams.mPolyModulusDegree;
                key.mRole = currentProtocolCacheScope().mRole;
                key.mPrimes = ctx.mRawModuli->mValues;
                key.mNativeRequested = nativeSealBundleCacheRequested();
                if (!validRawPrimes(key.mDegree, key.mPrimes) ||
                    key.mPrimes.size() != ctx.mParams.mCoeffModulusBits.size()) return;
                std::unique_lock<std::mutex> lock(gRawRingCacheMutex, std::try_to_lock);
                if (!lock.owns_lock() || rawRingCache().find(key) != rawRingCache().end()) return;
            }
            else
            {
                RingCacheKey key{};
                key.mDegree = ctx.mParams.mPolyModulusDegree;
                key.mBits.assign(ctx.mParams.mCoeffModulusBits.begin(), ctx.mParams.mCoeffModulusBits.end());
                key.mRole = currentProtocolCacheScope().mRole;
                // Avoid spawning a worker for warm rings or waiting here while
                // another thread already initializes one. The regular get
                // path holds this mutex through initialization/publication.
                std::unique_lock<std::mutex> lock(gRingCacheMutex, std::try_to_lock);
                if (!lock.owns_lock() || ringCache().find(key) != ringCache().end()) return;
            }
            const auto protocolScope = currentProtocolCacheScope();
            auto* benchmarkContext = tCpuBenchmarkContext;
            auto next = std::make_unique<Impl>();
            next->mFuture = std::async(std::launch::async,
                [ownedContext = ctx, protocolScope, benchmarkContext, device]() {
                    try
                    {
                        ScopedProtocolCacheScope scope(protocolScope);
                        CpuBenchmarkWorkerScope workerScope(benchmarkContext);
                        CpuBenchmarkTaskScope taskScope;
                        HostStep workerStep("setup GPU ring prefetch worker");
                        {
                            HostStep deviceStep("setup GPU ring select device");
                            if (cudaSetDevice(device) != cudaSuccess) return false;
                        }
                        // Host initialization uses the default stream; raw
                        // initialization creates its own stream. Neither
                        // shares mutable query scratch.
                        gpuSetCurrentStream(nullptr);
                        return static_cast<bool>(GpuRing::get(ownedContext));
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
        if (mImpl->mFuture.valid())
        {
            try { mImpl->mSuccess = mImpl->mFuture.get(); }
            catch (...) { mImpl->mSuccess = false; }
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

        mDenoise.mQ = static_cast<const u64*>(uploadVector(q, mOwned));
        mDenoise.mMods = uploadVector(mods, mOwned);
        mDenoise.mSrcLimb = static_cast<const u32*>(uploadVector(srcLimb, mOwned));
        mDenoise.mCrtInvPunctured = static_cast<const u64*>(uploadVector(crtInvPunctured, mOwned));
        mDenoise.mPuncturedProdModTarget =
            static_cast<const u64*>(uploadVector(puncturedProdModTarget, mOwned));
        mDenoise.mCrtInvPuncturedShoup = uploadVector(crtInvPuncturedShoup, mOwned);
        mDenoise.mScaledPuncturedShoup = uploadVector(scaledPuncturedShoup, mOwned);
        mDenoise.mFracInvLo = static_cast<const u64*>(uploadVector(fracInvLo, mOwned));
        mDenoise.mFracInvHi = static_cast<const u64*>(uploadVector(fracInvHi, mOwned));
        mDenoise.mCrtLiftModTarget = static_cast<const u64*>(uploadVector(crtLift, mOwned));
        mDenoise.mInvCrtLiftModTarget = static_cast<const u64*>(uploadVector(invCrtLift, mOwned));
        mDenoise.mInvCrtLiftShoup = uploadVector(invCrtLiftShoup, mOwned);

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
            RawSetupStream stream;
            if (!stream.mStream) return nullptr;
            RawConstantArena arena(mView.mRho * sizeof(u64), stream.mStream);
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

        const u64* d = static_cast<const u64*>(uploadVector(factors, mOwned));
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
            HostStep setupStep("setup GPU scale round constants");
            RawSetupStream stream;
            if (!stream.mStream) return false;
            RawConstantArena arena(mView.mRho *
                (5 * sizeof(u64) + sizeof(ScaleRoundFastLimb)) + 6u * 16u,
                stream.mStream);
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
        for (void* p : mOwned) gpuFree(p);
    }

    std::shared_ptr<GpuPlainNtt> GpuPlainNtt::get(
        const seal::SEALContext& batchingContext, const seal::BatchEncoder& encoder)
    {
        if (!available()) return nullptr;

        auto data = batchingContext.first_context_data();
        if (!data) return nullptr;
        const u64 p = data->parms().plain_modulus().value();
        const u64 degree = data->parms().poly_modulus_degree();
        const auto key = std::tuple{degree, p, currentProtocolCacheScope().mRole};

        using PlainKey = std::tuple<u64, u64, ProtocolCacheRole>;
        using PlainCache = std::vector<std::pair<PlainKey, std::shared_ptr<GpuPlainNtt>>>;
        static std::mutex mutex;
        static auto* cache = new PlainCache();   // immortal, see ringCache()

        std::lock_guard<std::mutex> lock(mutex);
        for (const auto& [k, v] : *cache)
        {
            if (k == key) return v;
        }

        std::shared_ptr<GpuPlainNtt> tables(new GpuPlainNtt());
        if (!tables->init(batchingContext, encoder)) return nullptr;
        cache->emplace_back(key, tables);
        return tables;
    }

    namespace
    {
        using RawPlainKey = std::tuple<u32, u64, ProtocolCacheRole, bool>;
        using RawPlainCache =
            std::vector<std::pair<RawPlainKey, std::shared_ptr<GpuPlainNtt>>>;
        RawPlainCache& rawPlainCache()
        {
            static auto* cache = new RawPlainCache();
            return *cache;
        }
        std::mutex& rawPlainCacheMutex()
        {
            static auto* mutex = new std::mutex();
            return *mutex;
        }
    }

    std::shared_ptr<GpuPlainNtt> GpuPlainNtt::getRaw(u32 n, u64 p)
    {
        if (!validRawPrimes(n, std::span<const u64>(&p, 1)) ||
            !available() || currentDeviceOrdinal() != 0) return nullptr;
        try
        {
            const RawPlainKey key{n, p, currentProtocolCacheScope().mRole,
                nativeSealBundleCacheRequested()};
            std::lock_guard<std::mutex> lock(rawPlainCacheMutex());
            for (const auto& [cachedKey, value] : rawPlainCache())
                if (cachedKey == key) return value;
            std::shared_ptr<GpuPlainNtt> tables(new GpuPlainNtt());
            if (!tables->initRaw(n, p)) return nullptr;
            rawPlainCache().emplace_back(key, tables);
            return tables;
        }
        catch (...) { return nullptr; }
    }

    bool GpuPlainNtt::publishRaw(u32 n, u64 p,
        const std::shared_ptr<GpuPlainNtt>& ready)
    {
        if (!ready || !ready->mNativeSealBundleStorage ||
            !nativeSealBundleCacheRequested() ||
            ready->mNativeBundleOwnerRole != currentProtocolCacheScope().mRole ||
            ready->mView.mN != n || ready->mView.mRho != 1u ||
            ready->mView.mMinModulus != p ||
            ready->mView.mMaxModulus != p ||
            ready->mSlotCount != n || !ready->mSlotMap ||
            !ready->mInverseSlotMap ||
            !validRawPrimes(n, std::span<const u64>(&p, 1u)))
            return false;
        try
        {
            const RawPlainKey key{n, p, currentProtocolCacheScope().mRole,
                true};
            std::lock_guard<std::mutex> lock(rawPlainCacheMutex());
            for (auto& [cachedKey, value] : rawPlainCache())
                if (cachedKey == key)
                {
                    // A sequential opt-out may have populated this role's raw
                    // table first. Publish the native bundle's owner so later
                    // getRaw users share the committed device allocation;
                    // existing shared owners remain valid until released.
                    value = ready;
                    return true;
                }
            rawPlainCache().emplace_back(key, ready);
            return true;
        }
        catch (...) { return false; }
    }

    bool GpuPlainNtt::initRaw(u32 n, u64 p)
    {
        HostStep setupStep("setup GPU raw plaintext NTT init");
        u32 status = ~u32{0};
        RawSetupStream stream;
        if (!stream.mStream) return false;
        RawConstantArena arena(static_cast<std::size_t>(n) *
            (2 * sizeof(HostShoupOperand) + 2 * sizeof(u32)) + 1024, stream.mStream);
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

        mView.mMods = uploadVector(mods, mOwned);
        mView.mRoots = uploadVector(roots, mOwned);
        mView.mInvRoots = uploadVector(invRoots, mOwned);
        mView.mInvDegree = uploadVector(invDegree, mOwned);
        mView.mScaledInvRoot = uploadVector(scaledInvRoot, mOwned);
        mSlotMap = static_cast<const u32*>(uploadVector(map, mOwned));
        mInverseSlotMap = static_cast<const u32*>(uploadVector(inverseMap, mOwned));
        // The CRT fields stay null: with rho == 1 no kernel that uses them is
        // ever launched against this view.
        if (!mView.mMods || !mView.mRoots || !mView.mInvRoots || !mView.mInvDegree ||
            !mView.mScaledInvRoot || !mSlotMap || !mInverseSlotMap)
        {
            return false;
        }
        return gpuDeviceSync();
    }

    // ---- GpuPolyBuffer ----------------------------------------------------

    GpuPolyBuffer::GpuPolyBuffer(const GpuRing& ring, std::size_t count)
    {
        resize(ring, count);
    }

    GpuPolyBuffer::~GpuPolyBuffer()
    {
        release();
    }

    GpuPolyBuffer::GpuPolyBuffer(GpuPolyBuffer&& other) noexcept
        : mData(other.mData), mCount(other.mCount), mPolyWords(other.mPolyWords), mCapacity(other.mCapacity)
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
        gpuFree(mData);
        mData = nullptr;
        mCount = 0;
        mCapacity = 0;
    }

    bool GpuPolyBuffer::resize(const GpuRing& ring, std::size_t count)
    {
        return resizeWords(ring.polyWords(), count);
    }

    bool GpuPolyBuffer::resizeWords(std::size_t polyWords, std::size_t count)
    {
        if (!polyWords || polyWords > std::numeric_limits<std::size_t>::max() / sizeof(u64) ||
            count > std::numeric_limits<std::size_t>::max() / sizeof(u64) / polyWords) return false;
        if (polyWords == mPolyWords && count <= mCapacity)
        {
            mCount = count;
            return true;
        }
        if (!count)
        {
            release();
            mPolyWords = polyWords;
            return true;
        }
        // Allocate first, preserving the old buffer on allocation failure.
        auto* next = static_cast<u64*>(gpuMalloc(count * polyWords * sizeof(u64)));
        if (!next) return false;
        gpuFree(mData);
        mData = next;
        mPolyWords = polyWords;
        mCount = mCapacity = count;
        return true;
    }

    bool GpuPolyBuffer::upload(std::span<const RnsPoly> polys, GpuStream& stream, std::size_t dstOffset)
    {
        if (polys.empty()) return true;
        const std::size_t polyBytes = mPolyWords * sizeof(u64);

        // Coalesce the per-polynomial copies through pinned staging: one large
        // H2D beats hundreds of 256 KiB pageable transfers.
        const std::size_t maxRun = std::max<std::size_t>(1,
            boundedStageBytes("LV_GPU_SETUP_POLY_STAGE_MIB", 8, 64) / polyBytes);
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
            if (!gpuMemcpyH2D(poly(dstOffset + done), stage, run * polyBytes, stream.raw()) ||
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
        return gpuMemcpyH2D(poly(dstIdx), p.mCoeffs.data(), mPolyWords * sizeof(u64), stream.raw());
    }

    bool GpuPolyBuffer::download(
        std::vector<RnsPoly>& polys, GpuStream& stream, std::size_t srcOffset, std::size_t count) const
    {
        const std::size_t num = count ? count : (mCount - srcOffset);
        polys.resize(num);
        if (num == 0) return true;

        const std::size_t polyBytes = mPolyWords * sizeof(u64);
        const std::size_t maxRun = std::max<std::size_t>(1,
            boundedStageBytes("LV_GPU_SETUP_POLY_STAGE_MIB", 8, 64) / polyBytes);
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
                if (!gpuMemcpyD2H(stage, poly(srcOffset + done), run * polyBytes, stream.raw()) ||
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
                for (std::size_t i = 0; i < run; ++i)
                {
                    if (!gpuMemcpyD2H(
                            polys[done + i].mCoeffs.data(), poly(srcOffset + done + i), polyBytes,
                            stream.raw()))
                    {
                        return false;
                    }
                }
                if (!stream.sync()) return false;
            }
            done += run;
        }
        return true;
    }

    bool GpuPolyBuffer::downloadPipelined(
        std::vector<RnsPoly>& polys, GpuStream& stream, u32 workers,
        std::size_t srcOffset, std::size_t count) const
    {
        if (srcOffset > mCount || count > mCount - srcOffset ||
            !mPolyWords || mPolyWords > std::numeric_limits<std::size_t>::max() / sizeof(u64)) return false;
        const std::size_t num = count ? count : mCount - srcOffset;
        const std::size_t polyBytes = mPolyWords * sizeof(u64);
        constexpr std::size_t maxSlotBytes = std::size_t(32) << 20;
        if (polyBytes > maxSlotBytes || mCount > std::numeric_limits<std::size_t>::max() / polyBytes ||
            (num && !mData)) return false;
        HostStep totalStep("setup: pipelined batch download");
        std::vector<RnsPoly> next(num);
        if (!num)
        {
            polys = std::move(next);
            return true;
        }
        const std::size_t targetSlotBytes = boundedStageBytes("LV_GPU_SETUP_DOWNLOAD_SLOT_MIB", 8, 32);
        const std::size_t runPolys = std::min(num, std::max<std::size_t>(1, targetSlotBytes / polyBytes));
        const std::size_t slotBytes = runPolys * polyBytes;
        struct PinnedDownload
        {
            u8* data = nullptr;
            std::size_t capacity = 0;
            void* events[2] = {nullptr, nullptr};
            ~PinnedDownload()
            {
                gpuFreeHost(data);
                gpuEventDestroy(events[0]);
                gpuEventDestroy(events[1]);
            }
            bool prepareEvents()
            {
                for (auto& event : events) if (!event) event = gpuEventCreate();
                return events[0] && events[1];
            }
            bool reserve(std::size_t bytes)
            {
                if (capacity < bytes)
                {
                    std::size_t wanted = std::size_t(1) << 20;
                    while (wanted < bytes) wanted *= 2u;
                    // Every preceding invocation drained its stream before
                    // returning, so this thread's old slots have no readers.
                    gpuFreeHost(data);
                    data = static_cast<u8*>(gpuMallocHost(wanted));
                    capacity = data ? wanted : 0;
                }
                return data && prepareEvents();
            }
        };
        // One allocation per host thread, reused safely across roles because
        // this synchronous API drains every transfer before returning.
        thread_local PinnedDownload staging;
        StreamDrain drain{stream};
        u8* selected = nullptr;
        {
            HostStep stagingStep("setup: pipelined download pinned allocation");
            const char* reuse = std::getenv("LV_GPU_SETUP_REUSE_DOWNLOAD_STAGING");
            if (!reuse || reuse[0] != '0') selected = stream.existingStaging(2u * slotBytes);
            if (selected)
            {
                // Prior H2D reads and these D2H writes use the same stream.
                // Every CPU reader waits for its chunk event; joined workers
                // finish before either slot is reused. Never own/grow/free the
                // stream's borrowed buffer through this private TLS cache.
                if (!staging.prepareEvents()) return false;
            }
            else
            {
                if (!staging.reserve(2u * slotBytes)) return false;
                selected = staging.data;
            }
        }
        // Capture the caller's storage as an ordinary pointer. Referring to a
        // thread_local object inside a pool worker would select its own cache.
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
        const char* reuseWorkers = std::getenv("LV_GPU_SETUP_DOWNLOAD_REUSE_WORKERS");
        const auto requested = detail::resolveWorkerCount(workers, runPolys);
        if ((!reuseWorkers || reuseWorkers[0] != '0') && num > runPolys && requested > 1)
        {
            HostStep workersStep("setup: pipelined download worker pool");
            // Reserve the same bounded worker budget once for this synchronous
            // download. No pool or reserved worker survives its return.
            copySlots = std::make_unique<detail::ParallelWorkerSlotGuard>(requested);
            copyWorkers = std::min(requested, copySlots->grantedWorkers());
            if (copyWorkers > 1) copyPool = std::make_unique<CopyPool>(copyWorkers - 1);
        }
        auto materialize = [&](std::size_t offset, std::size_t length, u32 slot) {
            {
                HostStep waitStep("setup: pipelined download DMA wait");
                if (!gpuEventSync(staging.events[slot])) return false;
            }
            HostStep copyStep("setup: pipelined download host copy");
            auto copyOne = [&](std::size_t i) {
                auto& coefficients = next[offset + i].mCoeffs;
                coefficients.resize(mPolyWords);
                std::memcpy(coefficients.data(), pinned + slot * slotBytes + i * polyBytes, polyBytes);
                return true;
            };
            if (!copyPool)
                return detail::runParallelTasks(length, copySlots ? 1 : workers, copyOne);

            const auto activeWorkers = std::min(copyWorkers, length);
            detail::ParallelWorkerCapScope capScope(activeWorkers);
            const auto cacheScope = currentProtocolCacheScope();
            auto worker = [&](std::size_t workerIdx) {
                CpuBenchmarkTaskScope taskScope;
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
                    cacheScope, tCpuBenchmarkContext) | macoro::make_eager());
            worker(0);
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
            if (!gpuMemcpyD2H(pinned + slot * slotBytes, poly(srcOffset + offset),
                    length * polyBytes, stream.raw()) ||
                !gpuEventRecord(staging.events[slot], stream.raw())) return false;
            if (previousLength && !materialize(previousOffset, previousLength, previousSlot)) return false;
            previousOffset = offset;
            previousLength = length;
            previousSlot = slot;
        }
        if (!materialize(previousOffset, previousLength, previousSlot) || !stream.sync()) return false;
        polys = std::move(next);
        return true;
    }

    bool GpuPolyBuffer::downloadAsync(RnsPoly& p, std::size_t srcIdx, GpuStream& stream) const
    {
        if (p.mCoeffs.size() != mPolyWords)
        {
            resizeZero(p.mCoeffs, mPolyWords);
        }
        return gpuMemcpyD2H(p.mCoeffs.data(), poly(srcIdx), mPolyWords * sizeof(u64), stream.raw());
    }

    bool GpuPolyBuffer::zero(GpuStream& stream)
    {
        return gpuMemsetZero(mData, bytes(), stream.raw());
    }

    // ---- primitive wrappers ----------------------------------------------

    bool nttForward(const GpuRing& ring, u64* polys, u32 count, GpuStream& stream)
    {
        return launchNttForward(ring.view(), polys, count, nullptr, stream.raw());
    }

    bool nttInverse(const GpuRing& ring, u64* polys, u32 count, GpuStream& stream)
    {
        return launchNttInverse(ring.view(), polys, count, nullptr, stream.raw());
    }

    bool denoiseComb(const GpuRing& ring, const u64* in, u64* out, u32 outCount, GpuStream& stream)
    {
        if (!ring.denoiseReady()) return false;
        return launchDenoiseComb(ring.view(), ring.denoiseView(), in, out, outCount, stream.raw());
    }
}

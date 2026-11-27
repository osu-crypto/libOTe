#include "libOTe/Vole/LogVole/cuda/LogVoleGpuProtocol.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuBackend.h"

#include "libOTe/Vole/LogVole/LogVole.h"
#include "libOTe/Vole/LogVole/LogVoleArithmetic.h"
#include "libOTe/Vole/LogVole/LogVoleCore.h"
#include "libOTe/Vole/LogVole/LogVoleLenc.h"
#include "libOTe/Vole/LogVole/LogVoleLhe.h"
#include "libOTe/Vole/LogVole/LogVolePublicCache.h"
#include "libOTe/Vole/LogVole/LogVoleRuntime.h"

#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Crypto/RandomOracle.h"

#include "seal/util/uintarithsmallmod.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <bit>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <new>
#include <stdexcept>
#include <thread>

namespace osuCrypto::LogVole::gpu
{
    namespace
    {
        std::atomic<u64>* timingCounter(TimingStats* stats, std::atomic<u64> TimingStats::* counter) noexcept
        {
            return stats ? &(stats->*counter) : nullptr;
        }
    }

    struct RetainedPublicUniform::Impl
    {
        std::shared_ptr<GpuRing> mRing;
        GpuPolyBuffer mValues;
        RingParams mParams;
        std::vector<std::array<u64, 8>> mSeeds;
        bool mOutputNtt = false;
        const RnsPoly* mHostData = nullptr;
        std::vector<const u64*> mHostCoefficients;
        mutable std::mutex mHostMutex;
        mutable std::mutex mDeviceUseMutex;
        mutable std::weak_ptr<const std::vector<RnsPoly>> mHostSnapshot;
        ProtocolCacheRole mRole = ProtocolCacheRole::Unspecified;
        ProtocolCacheRunId mRunId = 0;
        std::shared_ptr<const ProtocolCacheService> mIdentityService;
        int mDevice = -1;
        // Set once, before a Root BStar owner is published. Generic public
        // uniform tokens cannot substitute for this exact wire operand.
        bool mRootBStarNtt = false;
        u64 mRootBStarNonce = 0;
        u64 mRootBStarDomain = 0;
    };

    RetainedPublicUniform::RetainedPublicUniform() : mImpl(std::make_unique<Impl>()) {}
    RetainedPublicUniform::~RetainedPublicUniform() = default;
    std::size_t RetainedPublicUniform::count() const { return mImpl->mValues.count(); }

    namespace
    {
        constexpr std::size_t publicRetentionByteLimit = std::size_t(256) << 20;
        bool retentionContextMatches(const RingNttContext& ctx,
            const RetainedPublicUniform::Impl& value, ProtocolCacheScopeView scope)
        {
            if (!value.mRing || value.mDevice < 0 || currentDeviceOrdinal() != value.mDevice ||
                value.mRole != scope.mRole ||
                value.mRunId != scope.mRunId ||
                !(value.mParams == ctx.mParams) || value.mRing->rho() != ringModulusCount(ctx)) return false;
            const auto& moduli = value.mRing->hostModuli();
            for (std::size_t limb = 0; limb < moduli.size(); ++limb)
                if (moduli[limb] != ringModulusValue(ctx, limb)) return false;
            return GpuRing::get(ctx).get() == value.mRing.get();
        }

        bool retentionHostMatches(const std::vector<RnsPoly>& host,
            const RetainedPublicUniform::Impl& value)
        {
            if (host.data() != value.mHostData || host.size() != value.mValues.count() ||
                host.size() != value.mHostCoefficients.size()) return false;
            for (std::size_t i = 0; i < host.size(); ++i)
                if (host[i].mCoeffs.data() != value.mHostCoefficients[i] ||
                    host[i].mCoeffs.size() != value.mValues.polyWords()) return false;
            return true;
        }

        bool uploadPublicUniformOrHost(const RingNttContext& ctx, GpuPolyBuffer& destination,
            std::span<const RnsPoly> host, GpuStream& stream, ProtocolCacheScopeView scope)
        {
            auto retained = findPublicUniformRetention(ctx, host, scope);
            if (!retained) return destination.upload(host, stream);
            const auto& values = retained->mImpl->mValues;
            if (destination.count() < values.count() ||
                destination.polyWords() != values.polyWords()) return false;
            HostStep copyStep(hostProfiler(ctx), "setup public uniform: retained D2D");
            std::lock_guard use(retained->mImpl->mDeviceUseMutex);
            // Finish the copy while the registry handle is alive. A concurrent
            // cache eviction can then release the source without racing DMA.
            const bool queued = gpuMemcpyD2D(destination.data(stream), values.data(stream), values.bytes(), stream.raw());
            const bool completed = stream.sync();
            if (!queued || !completed) return false;
            if (ctx.mPublicCache)
            {
                auto& counters = ctx.mPublicCache->mRetentionCounters;
                counters.mCopies.fetch_add(1, std::memory_order_relaxed);
                counters.mCopiedBytes.fetch_add(values.bytes(), std::memory_order_relaxed);
            }
            return true;
        }

        bool copyRetainedPublicUniform(const RingNttContext& ctx,
            GpuPolyBuffer& destination, const RetainedPublicUniform& source,
            std::size_t sourceOffset, std::size_t count, bool outputNtt,
            GpuStream& stream, ProtocolCacheScopeView scope)
        {
            if (!count || sourceOffset > source.count() ||
                count > source.count() - sourceOffset ||
                !retainedPublicUniformMatches(ctx, source, source.count(), outputNtt, scope) ||
                destination.count() < count ||
                destination.polyWords() != source.mImpl->mValues.polyWords()) return false;
            const std::size_t words = count * destination.polyWords();
            if (words > std::numeric_limits<std::size_t>::max() / sizeof(u64)) return false;
            HostStep copyStep(hostProfiler(ctx), "setup public uniform: retained D2D");
            std::lock_guard use(source.mImpl->mDeviceUseMutex);
            const bool queued = gpuMemcpyD2D(destination.data(stream),
                source.mImpl->mValues.data(stream) + sourceOffset * destination.polyWords(),
                words * sizeof(u64), stream.raw());
            const bool completed = stream.sync();
            if (!queued || !completed) return false;
            if (ctx.mPublicCache)
            {
                auto& counters = ctx.mPublicCache->mRetentionCounters;
                counters.mCopies.fetch_add(1, std::memory_order_relaxed);
                counters.mCopiedBytes.fetch_add(words * sizeof(u64), std::memory_order_relaxed);
            }
            return true;
        }
    }

    bool publicUniformRetentionEnabled(const LogVoleExecutionOptions& options, bool selectedGpu)
    {
        const bool decline = options.mAdvanced.mProtocol.mFailures.mPublicRetain;
        return options.mAdvanced.mProtocol.mPublicUniformRetention && !(decline) && (options.mUseGpu && selectedGpu);
    }

    bool registerPublicUniformRetention(const RingNttContext& ctx,
        const std::shared_ptr<const std::vector<RnsPoly>>& host,
        const RetainedPublicUniformPtr& captured, ProtocolCacheScopeView scope)
    {
        if (!ctx.mPublicCache || !publicUniformRetentionEnabled(ctx.mExecutionOptions, enabled(ctx)) || !host || !captured || captured->count() == 0 ||
            !retentionContextMatches(ctx, *captured->mImpl, scope) ||
            !retentionHostMatches(*host, *captured->mImpl)) return false;
        const auto bytes = captured->mImpl->mValues.bytes();
        if (bytes > publicRetentionByteLimit) return false;
        auto& retention = ctx.mPublicCache->mRetention;
        std::lock_guard<std::mutex> lock(retention.mMutex);
        std::size_t retainedBytes = 0;
        for (auto it = retention.mEntries.begin(); it != retention.mEntries.end();)
        {
            if (it->mHost.expired()) it = retention.mEntries.erase(it);
            else
            {
                auto previousHost = it->mHost.lock();
                if (previousHost == host && it->mDevice == captured) return true;
                retainedBytes += it->mDevice->mImpl->mValues.bytes();
                ++it;
            }
        }
        while (!retention.mEntries.empty() && retainedBytes > publicRetentionByteLimit - bytes)
        {
            retainedBytes -= retention.mEntries.front().mDevice->mImpl->mValues.bytes();
            retention.mEntries.erase(retention.mEntries.begin());
        }
        retention.mEntries.push_back({host, captured});
        return true;
    }

    RetainedPublicUniformPtr findPublicUniformRetention(
        const RingNttContext& ctx, std::span<const RnsPoly> host, ProtocolCacheScopeView scope)
    {
        if (!ctx.mPublicCache || !publicUniformRetentionEnabled(ctx.mExecutionOptions, enabled(ctx)) || host.empty()) return {};
        auto& retention = ctx.mPublicCache->mRetention;
        RetainedPublicUniformPtr candidate;
        std::shared_ptr<const std::vector<RnsPoly>> owner;
        {
            std::lock_guard<std::mutex> lock(retention.mMutex);
            for (auto it = retention.mEntries.begin(); it != retention.mEntries.end();)
            {
                auto live = it->mHost.lock();
                if (!live) { it = retention.mEntries.erase(it); continue; }
                if (live->data() == host.data() && live->size() == host.size())
                {
                    owner = std::move(live);
                    candidate = it->mDevice;
                    break;
                }
                ++it;
            }
        }
        // Do not inspect a borrowed span until its registered owner is locked.
        if (candidate && retentionContextMatches(ctx, *candidate->mImpl, scope) &&
            retentionHostMatches(*owner, *candidate->mImpl)) return candidate;
        if (ctx.mPublicCache)
        {
            auto& counters = ctx.mPublicCache->mRetentionCounters;
            counters.mMisses.fetch_add(1, std::memory_order_relaxed);
        }
        return {};
    }

    bool fetchRetainedPublicUniform(const RetainedPublicUniform& source,
        std::vector<RnsPoly>& out, GpuStream& stream, ProtocolCacheScopeView scope)
    {
        if (!stream.raw() || source.count() == 0 ||
            source.mImpl->mDevice != currentDeviceOrdinal() ||
            source.mImpl->mRole != scope.mRole || source.mImpl->mRunId != scope.mRunId)
            return false;
        std::lock_guard use(source.mImpl->mDeviceUseMutex);
        return source.mImpl->mValues.download(out, stream);
    }

    bool retainedPublicUniformMatches(const RingNttContext& ctx,
        const RetainedPublicUniform& source, std::size_t expectedCount,
        bool outputNtt, ProtocolCacheScopeView scope)
    {
        return expectedCount != 0 && source.count() == expectedCount &&
            source.mImpl->mSeeds.size() == expectedCount &&
            source.mImpl->mOutputNtt == outputNtt &&
            retentionContextMatches(ctx, *source.mImpl, scope);
    }

    RetainedPublicUniformPtr retainRootBStarNttDevice(
        const RingNttContext& ctx, u32 count, ProtocolCacheScopeView scope)
    {
        if (scope.mRole != ProtocolCacheRole::Sender ||
            count == 0) return {};
        const bool decline = ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mRootBStarDevice;
        if (decline) return {};
        PendingRingOpsStats pending(ctx.mExecutionOptions.mRingOpsStats);
        auto* stats = ctx.mExecutionOptions.mRingOpsStats ? &pending : nullptr;
        RetainedPublicUniformPtr next;
        if (!retainUniformPolyBatchFromNonce(ctx, kRootBStarNonce,
                kRootBStarDomain, count, true, next, scope, stats) || !next ||
            !retainedPublicUniformMatches(ctx, *next, count, true, scope) ||
            next.use_count() != 1) return {};
        auto producer = std::const_pointer_cast<RetainedPublicUniform>(next);
        producer->mImpl->mRootBStarNtt = true;
        producer->mImpl->mRootBStarNonce = kRootBStarNonce;
        producer->mImpl->mRootBStarDomain = kRootBStarDomain;
        return next;
    }

    bool retainedRootBStarNttMatches(const RingNttContext& ctx,
        const RetainedPublicUniform& source, std::size_t expectedCount, ProtocolCacheScopeView scope)
    {
        return source.mImpl->mRootBStarNtt &&
            source.mImpl->mRootBStarNonce == kRootBStarNonce &&
            source.mImpl->mRootBStarDomain == kRootBStarDomain &&
            source.mImpl->mRole == ProtocolCacheRole::Sender &&
            retainedPublicUniformMatches(ctx, source, expectedCount, true, scope);
    }

    bool materializeRetainedPublicUniform(const RingNttContext& ctx,
        const RetainedPublicUniformPtr& source,
        std::shared_ptr<const std::vector<RnsPoly>>& out, ProtocolCacheScopeView scope)
    {
        if (!source || !retainedPublicUniformMatches(
                ctx, *source, source->count(), source->mImpl->mOutputNtt, scope)) return false;
        auto& value = *source->mImpl;
        std::lock_guard<std::mutex> lock(value.mHostMutex);
        if (auto snapshot = value.mHostSnapshot.lock())
        {
            out = std::move(snapshot);
            return true;
        }

        HostStep materializeStep(hostProfiler(ctx), "setup: public uniform host materialization");
        std::vector<RnsPoly> next;
        bool downloaded = false;
        if (enabled(ctx) && currentDeviceOrdinal() == value.mDevice)
        {
            auto& stream = contextSampleStream(ctx);
            std::lock_guard use(value.mDeviceUseMutex);
            downloaded = value.mValues.download(next, stream, 0, value.mValues.count());
        }
        if (!downloaded)
        {
            // The deterministic seeds were consumed before the retained GPU
            // attempt. Replaying them neither advances nor aliases a protocol
            // PRNG, so forced CPU rollback remains exact.
            try
            {
                PendingRingOpsStats pending(ctx.mExecutionOptions.mRingOpsStats);
                auto* stats = ctx.mExecutionOptions.mRingOpsStats ? &pending : nullptr;
                next.resize(value.mSeeds.size());
                for (std::size_t i = 0; i < value.mSeeds.size(); ++i)
                {
                    next[i] = sampleUniformPolyFromSeed(ctx, value.mSeeds[i], stats);
                    if (value.mOutputNtt && !forwardNttCanonical(next[i], ctx, stats)) return false;
                }
            }
            catch (...)
            {
                return false;
            }
        }
        if (next.size() != value.mValues.count() ||
            !validateRingBatchShape(next, ctx.mParams)) return false;
        auto snapshot = std::make_shared<const std::vector<RnsPoly>>(std::move(next));
        value.mHostData = snapshot->data();
        value.mHostCoefficients.clear();
        value.mHostCoefficients.reserve(snapshot->size());
        for (const auto& poly : *snapshot)
            value.mHostCoefficients.push_back(poly.mCoeffs.data());
        value.mHostSnapshot = snapshot;
        if (ctx.mPublicCache)
        {
            auto& counters = ctx.mPublicCache->mRetentionCounters;
            counters.mHostMaterializations.fetch_add(1, std::memory_order_relaxed);
            counters.mHostMaterializedBytes.fetch_add(
                value.mValues.bytes(), std::memory_order_relaxed);
        }
        out = std::move(snapshot);
        return true;
    }

    PublicUniformRetentionStats publicUniformRetentionStats(const RingNttContext& ctx)
    {
        if (!ctx.mPublicCache) return {};
        const auto& counters = ctx.mPublicCache->mRetentionCounters;
        return {counters.mCaptures.load(std::memory_order_relaxed),
            counters.mCopies.load(std::memory_order_relaxed),
            counters.mCopiedBytes.load(std::memory_order_relaxed),
            counters.mMisses.load(std::memory_order_relaxed),
            counters.mHostMaterializations.load(std::memory_order_relaxed),
            counters.mHostMaterializedBytes.load(std::memory_order_relaxed)};
    }

    namespace
    {
        u32 ilog2(u32 v)
        {
            u32 r = 0;
            while ((1u << r) < v) ++r;
            return r;
        }

        u32 bitWidth(u64 v)
        {
            u32 bits = 0;
            while (v)
            {
                ++bits;
                v >>= 1;
            }
            return bits;
        }

        bool debugEnabled(const RingNttContext& ctx)
        {
            return ctx.mExecutionOptions.mAdvanced.mStreams.mDebug;
        }

        bool debugEnabled(const std::shared_ptr<const RingNttContext>& owner)
        {
            return owner && debugEnabled(*owner);
        }

        bool rootSkNttResidentEnabled(const LogVoleGpuProtocolOptions& options)
        {
            return options.mRootSkNttResident;
        }

        bool rootDPrimeResidentEnabled(const LogVoleGpuProtocolOptions& options)
        {
            return options.mRootDPrimeResident;
        }

        // Highest-priority Root prefetch, enabled by default after the Stage-92
        // two-size A/B/A validation. Its storage and stream are prepared with
        // the Root device cache before the wire exchange; after send it queues
        // only the immutable index upload (once per cache) and the six
        // response-independent kernels. mProtocol.mRootFinalizePriorityPrefetch=0
        // restores the monolithic path.
        bool rootFinalizePriorityPrefetchEnabledImpl(const LogVoleGpuProtocolOptions& options)
        {
            return options.mRootFinalizePriorityPrefetch;
        }

        // Default on; mProtocol.mIdentityLeaf=0 preserves the materialized gadget
        // path for controlled benchmarking and emergency rollback.
        bool identityLeafEnabled(const LogVoleGpuProtocolOptions& options)
        {
            return options.mIdentityLeaf;
        }

        // The common wrapped plaintext has byte-identical canonical values in
        // all four RNS limbs. Materialize limb 0 only and let the immediately
        // following identity-leaf forward transform broadcast that source on
        // load. Default on after exact/resource/sanitizer and both-size A/B
        // gates; mProtocol.mPlainBroadcastSingleLimb=0 preserves the accepted full-RNS
        // representation as the code-generation-stable rollback.
        bool plainBroadcastSingleLimbEnabled(const LogVoleGpuProtocolOptions& options)
        {
            return options.mPlainBroadcastSingleLimb;
        }

        // The high digest digits used to form dHat are needed again by the
        // matching expand. Keep them coefficient-domain until then instead of
        // performing the same gadget decomposition twice. Default on;
        // mProtocol.mReuseHiDigits=0 is the controlled fallback.
        bool reuseHiDigitsEnabled(const LogVoleGpuProtocolOptions& options)
        {
            return options.mReuseHiDigits;
        }

        // Skip materializing recursive dHat's sparse CRT-lifted polynomials.
        // The child leaf NTT can reconstruct the same limb-specific centred
        // representatives directly from the retained high digits.
        bool directRecursiveLeafEnabled(const LogVoleGpuProtocolOptions& options)
        {
            return options.mDirectRecursiveLeaf;
        }

        // Reuse compact recursive leaf diagonals for both the leaf-pair product
        // and the producer's later expand. Default on; disable for A/B testing.
        bool recursiveDiagonalEnabled(const LogVoleGpuProtocolOptions& options)
        {
            return options.mRecursiveDiagonal;
        }

        // In the fixed rho=4/full-eight-leaf recursive shape, every sibling can
        // initialize one missing parent limb while writing its diagonal product.
        // Zero retains the bulk memset plus accepted diagonal kernel as the
        // exact rollback.
        bool recursiveLeafSelfZeroEnabled(const LogVoleGpuProtocolOptions& options)
        {
            return options.mRecursiveLeafSelfZero;
        }

        // In the fixed full-eight-leaf recursive shape, consume each retained
        // diagonal limb directly in inverse S0. This replaces the diagonal
        // materialization plus the following four-limb inverse with one
        // active-limb transform while still caching the packed diagonal and
        // explicitly initializing its complementary output limb. Default on;
        // zero retains the accepted two-launch chain as the exact rollback.
        bool recursiveLeafSparseInverseEnabled(const LogVoleGpuProtocolOptions& options)
        {
            return options.mRecursiveLeafSparseInverse;
        }

        // The final plaintext NTT store already owns every transformed
        // coefficient, so apply BatchEncoder's inverse slot permutation there
        // instead of writing and gathering a full intermediate batch. Default
        // on; mProtocol.mFusedUnwrap=0 preserves the two-launch path.
        bool fusedUnwrapEnabled(const LogVoleGpuProtocolOptions& options)
        {
            return options.mFusedUnwrap;
        }

        // The fixed Golden geometry keeps scale-and-round's plaintext
        // coefficients in the forward NTT block's shared tile and gathers the
        // final slots directly. Structural and lower-level toggle eligibility
        // is checked by canLaunchScaleNttForwardGather. Zero is the full exact
        // rollback to the established scratch allocation and split launch chain.
        bool fusedScaleUnwrapEnabled(const LogVoleGpuProtocolOptions& options)
        {
            return options.mFusedScaleUnwrap;
        }

        // The common wrap is an unscaled plaintext broadcast. When its inverse
        // NTT fits in one shared-memory tile, load BatchEncoder's slot permutation
        // at the transform boundary and publish directly to the ring limbs. This
        // removes the plaintext scratch batch entirely. mProtocol.mFusedWrap=0 keeps
        // the complete scatter -> inverse -> lift chain for exact A/B rollback.
        bool fusedWrapEnabled(const LogVoleGpuProtocolOptions& options)
        {
            return options.mFusedWrap;
        }

        // Sample the fixed Golden Root randomizer from its already-consumed
        // per-range PRNG keys directly into the device top-input batch. The host
        // seeded replay remains the exact fallback.
        bool rootZetaEnabled(const LogVoleGpuProtocolOptions& options)
        {
            return options.mRootZeta;
        }

        bool noGoldRootZetaEnabled(const LogVoleGpuProtocolOptions& options)
        {
            return options.mNoGoldRootZeta;
        }

        bool noGoldRootPinnedSeedsEnabled(const LogVoleGpuProtocolOptions& options)
        {
            return options.mNoGoldRootPinnedSeeds;
        }

        // Sender expansion consumes its recursive key. Transforming that device
        // buffer in place removes a full D2D copy and one live allocation.
        bool senderInplaceKeyEnabled(const LogVoleGpuProtocolOptions& options)
        {
            return options.mSenderInplaceKey;
        }

        // Sampling a sender level is independent of its complete child
        // recursion. Queue it on the role's secondary stream so those kernels
        // can overlap, then make that level's expansion wait on a device event.
        // The caller selects the measured size-dependent default; the switch
        // remains the complete rollback and the level count permits exact A/Bs.
        bool topSenderCt2PrefetchEnabledImpl(const LogVoleGpuProtocolOptions& options)
        {
            return options.mTopSenderCt2Prefetch;
        }

        u32 topSenderCt2PrefetchLevelsImpl(u32 adaptiveDefault, const LogVoleGpuProtocolOptions& options)
        {
            if (!options.mTopSenderCt2Prefetch) return 0u;
            return options.mSenderCt2PrefetchLevels >= 1
                ? static_cast<u32>(options.mSenderCt2PrefetchLevels)
                : std::clamp<u32>(adaptiveDefault, 1u, 3u);
        }

        LogVoleChoice receiverCt2PrefetchMode(const LogVoleGpuProtocolOptions& options)
        {
            return options.mReceiverCt2Prefetch;
        }

        // A sampled batch is checked again arithmetically by the next level's
        // denoise. Accumulate those exact checks on the device and read one flag
        // after the top level instead of draining the stream at every level.
        bool deferredGoldenValidationEnabledImpl(const LogVoleGpuProtocolOptions& options)
        {
            return options.mDeferredGoldenValidation;
        }

        // With one retained high digit, gadget decomposition has the same input
        // and output shape. The kernel reconstructs a coefficient completely
        // before storing it, so the digest allocation can become the digit
        // allocation in place. Disable only for same-binary A/B testing.
        bool inplaceHiDigitEnabled(const LogVoleGpuProtocolOptions& options)
        {
            return options.mInplaceHiDigit;
        }

        template<class Context>
        bool bail(const Context& context, const char* why)
        {
            if (debugEnabled(context))
            {
                std::fprintf(stderr, "[logvole-gpu] declined: %s\n", why);
            }
            return false;
        }

        // Syncs the stream so the measurement attributes GPU work correctly.
        // Only active when tracing; otherwise it is a no-op and does not perturb
        // the pipeline.
        struct Region
        {
            std::atomic<u64>* mSink;
            void* mStream;
            std::chrono::steady_clock::time_point mStart;

            Region(GpuStream::RegionKind kind, GpuStream& stream) : mSink(nullptr), mStream(stream.raw())
            {
                if (!stream.options().mDebug) return;
                mSink = &stream.regionCounter(kind);
                gpuStreamSync(mStream);
                mStart = std::chrono::steady_clock::now();
            }

            Region(const Region&) = delete;
            Region& operator=(const Region&) = delete;

            ~Region() { stop(); }

            void stop()
            {
                if (!mSink) return;
                gpuStreamSync(mStream);
                mSink->fetch_add(
                    static_cast<u64>(std::chrono::duration_cast<std::chrono::microseconds>(
                                         std::chrono::steady_clock::now() - mStart)
                                         .count()),
                    std::memory_order_relaxed);
                mSink = nullptr;
            }
        };

        u32 leafTau(u32 plaintextModulusBits, u32 gadgetLogBase, bool leafInputsAreGadget)
        {
            if (leafInputsAreGadget) return 1;
            return (plaintextModulusBits + gadgetLogBase - 1u) / gadgetLogBase;
        }

        // Mirrors buildLencPublicBNttImpl's slicing helpers so the GPU sees the
        // same public matrices.
        struct PublicBSlices
        {
            // Internal levels use publicB[1 .. tauHi] and
            // publicB[fullTau+1 .. fullTau+tauHi].
            std::vector<u32> mInternal;
            // The leaf level uses publicB[0 .. tauLeaf-1] and
            // publicB[fullTau .. fullTau+tauLeaf-1].
            std::vector<u32> mLeaf;
        };

        PublicBSlices makePublicBSlices(u32 tauHi, u32 tauLeaf)
        {
            const u32 fullTau = tauHi + 1u;
            PublicBSlices s{};
            s.mInternal.reserve(2u * tauHi);
            for (u32 i = 0; i < tauHi; ++i) s.mInternal.push_back(1u + i);
            for (u32 i = 0; i < tauHi; ++i) s.mInternal.push_back(fullTau + 1u + i);
            s.mLeaf.reserve(2u * tauLeaf);
            for (u32 i = 0; i < tauLeaf; ++i) s.mLeaf.push_back(i);
            for (u32 i = 0; i < tauLeaf; ++i) s.mLeaf.push_back(fullTau + i);
            return s;
        }

        // ---- geometry-derived index arrays ----------------------------------
        // The gather/scatter and inner-product index arrays are pure functions of
        // a level's shape: widths, tau counts, node-buffer strides and the leaf
        // bit patterns. None of them depend on the query. They were being rebuilt
        // with nested host loops and re-uploaded on every call, which is host time
        // and PCIe traffic on the critical path for something that never changes.
        //
        // Cache immutable geometry on its consuming stream. Secondary-stream
        // borrowers must join back to that stream before returning or unwinding.
        struct IdxCache
        {
            std::unordered_map<u64, OwnedGpuBuffer> mMap;
        };

        IdxCache& idxCache(GpuStream& stream);

        // FNV-1a over the geometry values, with a per-site tag so two sites that
        // happen to share a shape cannot collide.
        template<typename... Vals>
        u64 idxKey(ProtocolCacheRole role, u64 siteTag, Vals... vals)
        {
            u64 h = 1469598103934665603ull ^ siteTag;
            h ^= static_cast<u64>(role);
            h *= 1099511628211ull;
            const u64 parts[] = { static_cast<u64>(vals)... };
            for (u64 v : parts)
            {
                h ^= v;
                h *= 1099511628211ull;
            }
            return h;
        }

        template<typename BuildFn>
        const u32* cachedIdx(u64 key, std::size_t count, GpuStream& stream, BuildFn&& build)
        {
            if (!count || count > std::numeric_limits<std::size_t>::max() / sizeof(u32))
                return nullptr;
            auto& cache = idxCache(stream);
            auto found = cache.mMap.find(key);
            if (found != cache.mMap.end())
                return static_cast<const u32*>(found->second.data());

            std::vector<u32> host(count);
            build(host);
            auto storage = tryAllocateGpuBuffer(stream, count * sizeof(u32));
            if (!storage) return nullptr;
            // The cold upload must finish before its host vector is destroyed.
            // Cache hits only look up the existing allocation.
            const bool copied = gpuMemcpyH2D(storage.data(), host.data(), count * sizeof(u32), stream.raw());
            const bool complete = stream.sync();
            if (!copied || !complete) return nullptr;
            auto it = cache.mMap.emplace(key, std::move(storage)).first;
            return static_cast<const u32*>(it->second.data());
        }

        // Device mirror of a party's offline tensors. Uploaded once per state.
        struct OfflineCache
        {
            std::shared_ptr<GpuRing> mRing;
            GpuPolyBuffer mPublicA;    // [mu]
            GpuPolyBuffer mPublicB;    // [2*fullTau]
            // The two public-B columns used by recursive gadget leaves, with
            // each RNS limb multiplied by prod_{w != limb} q_w mod q_limb.
            GpuPolyBuffer mRecursiveLeafB; // [left, right]
            GpuPolyBuffer mCt1;        // [mu * tauCols] (NTT domain)
            GpuPolyBuffer mLacct;      // [levels*width * 2*ctTauMax] (NTT domain)
            u32 mCt1Cols = 0;
            u32 mLacctCols = 0;
            const u64* mMaxMultiple = nullptr;   // [rho], owned by mRing
        };

        bool downloadReceiverCt1Snapshot(const RingNttContext& ctx, const OfflineCache& cache,
            std::vector<RnsPoly>& out, GpuStream& stream, u32 workers)
        {
            CpuBenchmarkState cpuBenchmark{cache.mRing->executionOptions().mCpuBenchmark};
            const auto setting = cache.mRing->executionOptions().mAdvanced.mProtocol.mReceiverPipelinedDownload;
            const bool usePipeline = setting == LogVoleChoice::Enabled ||
                (setting == LogVoleChoice::Automatic && cache.mCt1.bytes() >= (std::size_t(16) << 20));
            return (usePipeline ? cache.mCt1.downloadPipelined(out, stream, workers, ctx.mGpuExecution->transferCpuScratch(), 0, 0, cpuBenchmark)
                                : cache.mCt1.download(out, stream)) && stream.sync();
        }

        // Only explicit internal states use this owner. The source is the
        // receiver's own decoded coefficients or immutable received wire; the
        // synchronized mirror is never borrowed from the sender. get() can run
        // concurrently, including after the protocol switches to CPU fallback.
        class ReceiverCt1HostState final : public LazyRingTensorHostState
        {
        public:
            ReceiverCt1HostState(const RingNttContext& ctx,
                std::shared_ptr<OfflineCache> cache, u32 rows, u32 cols,
                u32 workers, int device, ProtocolCacheRunId runId,
                std::shared_ptr<const LazyRingTensorHostState> encoded)
                : mContext(ctx), mCache(std::move(cache)), mWorkers(workers),
                  mDevice(device), mRunId(runId), mIdentityService(runId.serviceOwner()), mEncoded(std::move(encoded))
            {
                mCoefficients.mRows = rows;
                mCoefficients.mCols = cols;
            }

            void takeCoefficients(std::vector<RnsPoly>&& coefficients) noexcept
            {
                mCoefficients.mPolys = std::move(coefficients);
            }

            const RingTensor& get() const override
            {
                std::call_once(mOnce, [&] {
                    HostStep materializeStep(hostProfiler(mContext), "setup receiver: lazy NTT host materialization");
                    RingTensor next{};
                    next.mRows = mCoefficients.mRows;
                    next.mCols = mCoefficients.mCols;
                    bool downloaded = false;
                    {
                        if (enabled(mContext) && currentDeviceOrdinal() == mDevice)
                        {
                            auto& stream = contextStream(mContext);
                            StreamDrain drain{stream};
                            HostStep downloadStep(hostProfiler(mContext), "setup receiver: lazy NTT host download");
                            downloaded = downloadReceiverCt1Snapshot(mContext, *mCache, next.mPolys, stream, mWorkers);
                        }
                    }
                    // A failed transfer has drained before next is reused.
                    // The coefficient backup is not changed until success, so
                    // a throwing allocation leaves call_once retryable.
                    if (!downloaded)
                    {
                        HostStep fallbackStep(hostProfiler(mContext), "setup receiver: lazy NTT CPU fallback");
                        const auto& coefficients = mEncoded ? mEncoded->get() : mCoefficients;
                        if (coefficients.mRows != next.mRows || coefficients.mCols != next.mCols ||
                            ringTensorSize(coefficients) != coefficients.mPolys.size() ||
                            !validateRingBatchShape(coefficients.mPolys, mContext.mParams))
                            throw std::runtime_error("LogVole receiver lazy Ct1 has invalid coefficient backing");
                        next = coefficients;
                        PendingRingOpsStats pending(mContext.mExecutionOptions.mRingOpsStats);
                        auto* stats = mContext.mExecutionOptions.mRingOpsStats ? &pending : nullptr;
                        for (auto& poly : next.mPolys)
                            if (!forwardNtt(poly, mContext, stats))
                                throw std::runtime_error("LogVole receiver lazy Ct1 host NTT failed");
                    }
                    mNtt = std::move(next);
                    mCoefficients.mPolys.clear();
                    mEncoded.reset();
                });
                return mNtt;
            }

        private:
            RingNttContext mContext;
            std::shared_ptr<OfflineCache> mCache;
            u32 mWorkers;
            int mDevice;
            ProtocolCacheRunId mRunId;
            std::shared_ptr<const ProtocolCacheService> mIdentityService;
            mutable std::shared_ptr<const LazyRingTensorHostState> mEncoded;
            mutable RingTensor mCoefficients;
            mutable RingTensor mNtt;
            mutable std::once_flag mOnce;
        };

        std::shared_ptr<OfflineCache> buildOfflineCache(
            const RingNttContext& ctx,
            const std::vector<RnsPoly>* publicA,
            const std::vector<RnsPoly>* publicB,
            const RetainedPublicUniform* retainedPublicA,
            const RetainedPublicUniform* retainedPublicB,
            const RingTensor& ct1,
            const ShrinkExpandLacct& lacct,
            bool ct1IsNtt,
            const LogVoleWireOptions& wireOptions, ProtocolCacheScopeView scope,
            ConstWireView encodedCt1 = {},
            ConstWireView encodedLacct = {})
        {
            auto ring = GpuRing::get(ctx);
            if (!ring) return nullptr;

            if ((publicA && retainedPublicA) || (publicB && retainedPublicB)) return nullptr;
            const std::size_t publicACount = publicA ? publicA->size()
                : retainedPublicA ? retainedPublicA->count() : 0;
            const std::size_t publicBCount = publicB ? publicB->size()
                : retainedPublicB ? retainedPublicB->count() : 0;
            if ((retainedPublicA && !retainedPublicUniformMatches(
                    ctx, *retainedPublicA, publicACount, false, scope)) ||
                (retainedPublicB && !retainedPublicUniformMatches(
                    ctx, *retainedPublicB, publicBCount, true, scope))) return nullptr;

            if (ring->polyWords() > std::numeric_limits<std::size_t>::max() / sizeof(u64)) return nullptr;
            const std::size_t polyBytes = ring->polyWords() * sizeof(u64);
            if (!polyBytes) return nullptr;
            const u64 ct1Count = encodedCt1.empty() ? ct1.mPolys.size() : ringTensorSize(ct1);
            const u64 lacctCount = encodedLacct.empty() ? lacct.mCt.mPolys.size() : ringTensorSize(lacct.mCt);
            if (ct1Count > std::numeric_limits<u32>::max() ||
                lacctCount > std::numeric_limits<u32>::max() ||
                ct1Count > std::numeric_limits<std::size_t>::max() / polyBytes ||
                lacctCount > std::numeric_limits<std::size_t>::max() / polyBytes ||
                (!encodedCt1.empty() && (!ct1.mPolys.empty() || encodedCt1.size() != ct1Count * polyBytes)) ||
                (!encodedLacct.empty() && (!lacct.mCt.mPolys.empty() || encodedLacct.size() != lacctCount * polyBytes)))
                return nullptr;
            if constexpr (std::endian::native != std::endian::little)
                if (!encodedCt1.empty() || !encodedLacct.empty()) return nullptr;

            auto cache = std::make_shared<OfflineCache>();
            cache->mRing = ring;
            auto& stream = contextStream(ctx);
            std::vector<u64> recursiveFactors;
            std::vector<RnsPoly> recursiveLeafB;
            std::array<u32, 2> recursiveInputs{};
            OwnedGpuBuffer deviceRecursiveInputs;
            // Metadata uploads and all cache buffers must outlive queued work,
            // including a later allocation or launch failure.
            struct DrainStream
            {
                GpuStream& stream;
                bool armed = true;
                ~DrainStream() { if (armed) stream.sync(); }
            } drainStream{ stream };

            if (publicACount)
            {
                if (!cache->mPublicA.resize(*ring, publicACount, stream) ||
                    !(retainedPublicA
                        ? copyRetainedPublicUniform(ctx, cache->mPublicA,
                            *retainedPublicA, 0, publicACount, false, stream, scope)
                        : uploadPublicUniformOrHost(ctx, cache->mPublicA, *publicA, stream, scope)))
                    return nullptr;
            }
            if (publicBCount)
            {
                if (!cache->mPublicB.resize(*ring, publicBCount, stream) ||
                    !(retainedPublicB
                        ? copyRetainedPublicUniform(ctx, cache->mPublicB,
                            *retainedPublicB, 0, publicBCount, true, stream, scope)
                        : uploadPublicUniformOrHost(ctx, cache->mPublicB, *publicB, stream, scope)))
                    return nullptr;

                HostStep leafStep(hostProfiler(ctx), "gpu: prepare recursive public B");
                // Only these two public columns are needed at recursive leaves.
                // The ring already owns the exact per-limb lift factors.
                if (publicBCount < 2u || (publicBCount & 1u) != 0u)
                    return nullptr;
                const std::size_t fullTau = publicBCount / 2u;
                if (fullTau > std::numeric_limits<u32>::max()) return nullptr;
                if (ctx.mExecutionOptions.mAdvanced.mProtocol.mLeafBDevice)
                {
                    recursiveInputs = { 0u, static_cast<u32>(fullTau) };
                    deviceRecursiveInputs = tryAllocateGpuBuffer(stream, sizeof(recursiveInputs));
                    if (!ring->crtLiftFactors() || !deviceRecursiveInputs ||
                        !cache->mRecursiveLeafB.resize(*ring, 2u, stream) ||
                        !gpuMemcpyH2D(deviceRecursiveInputs.data(), recursiveInputs.data(),
                            sizeof(recursiveInputs), stream.raw()) ||
                        !launchScaleByPow2(ring->view(stream), cache->mPublicB.data(stream),
                            static_cast<const u32*>(deviceRecursiveInputs.data()),
                            cache->mRecursiveLeafB.data(stream), nullptr, 2u,
                            ring->crtLiftFactors(), stream.raw()))
                        return nullptr;
                }
                else
                {
                    // This rollback explicitly requests host leaf preparation;
                    // a retained-only caller materializes atomically before its
                    // exact CPU fallback instead of reading placeholder data.
                    if (!publicB) return nullptr;
                    const auto& moduli = getRingHostModuli(ctx);
                    if (moduli.size() != ring->rho()) return nullptr;
                    recursiveFactors.resize(moduli.size());
                    for (std::size_t limb = 0; limb < moduli.size(); ++limb)
                    {
                        u64 lift = 1;
                        for (std::size_t w = 0; w < moduli.size(); ++w)
                            if (w != limb) lift = seal::util::multiply_uint_mod(lift, moduli[w].value(), moduli[limb]);
                        recursiveFactors[limb] = lift;
                    }
                    recursiveLeafB = { (*publicB)[0], (*publicB)[fullTau] };
                    const std::size_t n = ctx.mParams.mPolyModulusDegree;
                    for (std::size_t limb = 0; limb < moduli.size(); ++limb)
                    {
                        const std::size_t offset = limb * n;
                        for (auto& b : recursiveLeafB)
                        {
                            for (std::size_t coeff = 0; coeff < n; ++coeff)
                            {
                                const std::size_t idx = offset + coeff;
                                b.mCoeffs[idx] = seal::util::multiply_uint_mod(
                                    b.mCoeffs[idx], recursiveFactors[limb], moduli[limb]);
                            }
                        }
                    }
                    if (!cache->mRecursiveLeafB.resize(*ring, recursiveLeafB.size(), stream) ||
                        !cache->mRecursiveLeafB.upload(recursiveLeafB, stream))
                        return nullptr;
                }
            }

            if (ct1Count)
            {
                cache->mCt1Cols = ct1.mCols;
                if (!cache->mCt1.resize(*ring, ct1Count, stream) ||
                    !(encodedCt1.empty() ? cache->mCt1.upload(ct1.mPolys, stream)
                        : uploadSetupWire(cache->mCt1.data(stream), encodedCt1, stream, wireOptions)))
                    return nullptr;
                if (!ct1IsNtt &&
                    (!launchCanonicalize(ring->view(stream), cache->mCt1.data(stream), nullptr,
                         static_cast<u32>(ct1Count), stream.raw()) ||
                     !nttForward(*ring, cache->mCt1.data(stream), static_cast<u32>(ct1Count), stream)))
                    return nullptr;
            }

            if (lacctCount)
            {
                cache->mLacctCols = lacct.mCt.mCols;
                if (!cache->mLacct.resize(*ring, lacctCount, stream) ||
                    !(encodedLacct.empty() ? cache->mLacct.upload(lacct.mCt.mPolys, stream)
                        : uploadSetupWire(cache->mLacct.data(stream), encodedLacct, stream, wireOptions)))
                    return nullptr;
            }

            // Identical SEAL rejection thresholds are already immutable ring
            // constants. Retaining mRing keeps this shared device array alive.
            cache->mMaxMultiple = ring->sampleMaxMultiple();
            if (!cache->mMaxMultiple) return nullptr;

            if (!stream.sync()) return nullptr;
            return cache;
        }

        std::shared_ptr<OfflineCache> receiverCache(const ShrinkExpandReceiverState& state,
            ProtocolCacheScopeView scope)
        {
            if (state.mGpuCache)
            {
                return std::static_pointer_cast<OfflineCache>(state.mGpuCache);
            }
            // Built lazily, so the first query against a state pays for it. Worth
            // watching: it is tens of milliseconds at the no-golden-seed
            // parameters, and a state whose cache is rebuilt per query (which is
            // what a temporary ShrinkExpandReceiverState would cause) reads as a
            // per-query cost several times the rest of the level put together.
            HostStep miss(hostProfiler(state.mRingFactoryOwner), "gpu: receiverCache build");
            RingNttContext ctx{};
            if (!makeRingNttContext(state.mParams.mRing, ctx, state.mRingFactoryOwner, scope)) return nullptr;
            auto cache = buildOfflineCache(
                ctx, state.mPublicANtt.get(), state.mPublicBNtt.get(),
                state.mPublicANttDevice.get(), state.mPublicBNttDevice.get(),
                state.hostCt1(), state.hostLacct(), true, state.mParams.mTransport.mEncoding.mWire, scope);
            if (cache) state.mGpuCache = cache;
            return cache;
        }

        std::shared_ptr<OfflineCache> senderCache(const ShrinkExpandSenderState& state,
            ProtocolCacheScopeView scope)
        {
            if (state.mGpuCache)
            {
                return std::static_pointer_cast<OfflineCache>(state.mGpuCache);
            }
            HostStep miss(hostProfiler(state.mRingFactoryOwner), "gpu: senderCache build");
            // Offline retained operands belong to the sender state, not the
            // current online sid. Borrow that state's original scope solely
            // while validating and copying its immutable GPU tokens.
            scope = {state.mPublicANttDevice ? state.mPublicUniformRunId : scope.mRunId,
                ProtocolCacheRole::Sender};
            RingNttContext ctx{};
            if (!makeRingNttContext(state.mParams.mRing, ctx, state.mRingFactoryOwner, scope)) return nullptr;
            ShrinkExpandLacct empty{};
            RingTensor noCt1{};
            // Sender expansion and Root key derivation read only public A and
            // sampler thresholds; public B is exclusively a receiver operand.
            const bool includePublicB = !ctx.mExecutionOptions.mAdvanced.mProtocol.mSenderPublicAOnly;
            const auto* publicB = includePublicB ? state.mPublicBNtt.get() : nullptr;
            const auto* retainedPublicB = includePublicB
                ? state.mPublicBNttDevice.get() : nullptr;
            auto cache = buildOfflineCache(
                ctx, state.mPublicANtt.get(), publicB,
                state.mPublicANttDevice.get(), retainedPublicB,
                noCt1, empty, true, state.mParams.mTransport.mEncoding.mWire, scope);
            if (cache) state.mGpuCache = cache;
            return cache;
        }

        // Host-side derivation of the SEAL prng seeds that
        // deriveUniformPolyBatchFromSeed would use, so the GPU can expand them.
        // Mirrors deriveSeedInstanceBlockFromDigestHash +
        // deriveUniformPolyFromSeed.
        template<typename T>
        void roUpdate(RandomOracle& ro, const T& value)
        {
            ro.Update(reinterpret_cast<const u8*>(&value), sizeof(T));
        }

        void appendPolySeeds(
            const RingParams& params, block ct2Seed, u64 domainTag, u32 count, std::vector<u64>& out)
        {
            for (u32 index = 0; index < count; ++index)
            {
                block polySeed{};
                RandomOracle ro(sizeof(polySeed));
                constexpr u64 label = 0x4C4F47564F4C5059ull;
                roUpdate(ro, label);
                roUpdate(ro, ct2Seed);
                roUpdate(ro, domainTag);
                roUpdate(ro, index);
                roUpdate(ro, params.mPolyModulusDegree);
                const u64 modulusCount = static_cast<u64>(params.mCoeffModulusBits.size());
                roUpdate(ro, modulusCount);
                ro.Final(polySeed);

                PRNG prng(polySeed);
                std::array<u64, 8> sealSeed{};
                prng.get(sealSeed.data(), sealSeed.size());
                out.insert(out.end(), sealSeed.begin(), sealSeed.end());
            }
        }

        constexpr u64 kCt2DomainTag = 0xC720AA55ull;

        // Per-stream AES sampling scratch and the 512-bit polynomial seeds.
        // Sized once and reused so that repeated golden-seed attempts do not
        // churn hundreds of megabytes of device memory.
        struct SampleScratch
        {
            explicit SampleScratch(GpuStream& owner) : mOwner(owner) {}
            GpuStream& mOwner;
            enum Slot { Seeds, Prefix, Ct2Seeds, RoundKeys, RejectEpochs, RootZetaRejects };
            std::array<OwnedGpuBuffer, 6> mStorage;

            template<typename T>
            T* allocate(Slot slot, std::size_t count)
            {
                mStorage[slot].reset();
                if (count > std::numeric_limits<std::size_t>::max() / sizeof(T)) return nullptr;
                try
                {
                    mStorage[slot] = OwnedGpuBuffer(mOwner.allocationOwner(), count * sizeof(T));
                    return static_cast<T*>(mStorage[slot].data());
                }
                catch (const std::bad_alloc&) { return nullptr; }
            }

            u64* mSeeds = nullptr;
            std::size_t mSeedWords = 0;
            // ct2 seed derivation: the 9-word RO prefix and the per-chunk
            // 16-byte instance seeds.
            u64* mPrefix = nullptr;
            u64* mCt2Seeds = nullptr;
            std::size_t mCt2SeedWords = 0;
            unsigned char* mRoundKeys = nullptr;
            std::size_t mRoundKeyBytes = 0;
            // Rejection flags are stamped with a host-issued epoch, so the
            // no-rejection case needs neither a clear nor a device-to-host read.
            // SampleScratch is stream-slot-local, making reuse stream ordered.
            u32* mRejectEpochs = nullptr;
            std::size_t mRejectCapacity = 0;
            u32 mRejectEpoch = 0;
            // Root-zeta stores an actual first rejected coefficient rather than
            // an epoch. Keep it separate: sharing mRejectEpochs would make a
            // later epoch equal to a stale coefficient and spuriously replay a
            // uniform polynomial.
            u32* mRootZetaFirstReject = nullptr;
            std::size_t mRootZetaRejectCapacity = 0;

            bool ensureSeeds(std::size_t words)
            {
                if (words <= mSeedWords) return true;
                mSeeds = allocate<u64>(Seeds, words);
                mSeedWords = mSeeds ? words : 0;
                return mSeeds != nullptr;
            }

            bool ensurePrefix()
            {
                if (mPrefix) return true;
                mPrefix = allocate<u64>(Prefix, 9);
                return mPrefix != nullptr;
            }

            bool uploadPrefix(const u64* words, std::size_t wordCount, void* stream)
            {
                if (stream != mOwner.raw() || !mPrefix || !words || wordCount == 0 ||
                    wordCount > 9u)
                    return false;
                return gpuMemcpyH2D(
                    mPrefix, words, wordCount * sizeof(u64), stream);
            }

            bool ensureCt2Seeds(std::size_t words)
            {
                if (words <= mCt2SeedWords) return true;
                mCt2Seeds = allocate<u64>(Ct2Seeds, words);
                mCt2SeedWords = mCt2Seeds ? words : 0;
                return mCt2Seeds != nullptr;
            }

            bool ensureRoundKeys(std::size_t bytes)
            {
                if (bytes <= mRoundKeyBytes) return true;
                mRoundKeys = allocate<unsigned char>(RoundKeys, bytes);
                mRoundKeyBytes = mRoundKeys ? bytes : 0;
                return mRoundKeys != nullptr;
            }

            bool nextRejectEpoch(
                std::size_t count, void* stream, u32*& rejectEpochs, u32& rejectEpoch)
            {
                rejectEpochs = nullptr;
                rejectEpoch = 0;
                if (stream != mOwner.raw()) return false;
                if (count == 0) return true;

                if (count > mRejectCapacity)
                {
                    mRejectEpochs = allocate<u32>(RejectEpochs, count);
                    mRejectCapacity = mRejectEpochs ? count : 0;
                    mRejectEpoch = 0;
                    if (!mRejectEpochs) return false;
                    if (!gpuMemsetZero(mRejectEpochs, count * sizeof(u32), stream))
                    {
                        mStorage[RejectEpochs].reset();
                        mRejectEpochs = nullptr;
                        mRejectCapacity = 0;
                        return false;
                    }
                }

                // Epoch zero is reserved for freshly cleared storage. On wrap,
                // enqueue the clear after all earlier users of this stream-local
                // buffer and before publishing epoch one again.
                if (mRejectEpoch == std::numeric_limits<u32>::max())
                {
                    if (!gpuMemsetZero(
                            mRejectEpochs, mRejectCapacity * sizeof(u32), stream))
                        return false;
                    mRejectEpoch = 1;
                }
                else
                {
                    ++mRejectEpoch;
                }

                rejectEpochs = mRejectEpochs;
                rejectEpoch = mRejectEpoch;
                return true;
            }

            bool ensureRootZetaRejects(std::size_t count)
            {
                if (count <= mRootZetaRejectCapacity) return true;
                mRootZetaFirstReject = allocate<u32>(RootZetaRejects, count);
                mRootZetaRejectCapacity = mRootZetaFirstReject ? count : 0;
                return mRootZetaFirstReject != nullptr;
            }

        };

        // Tiny persistent scratch for the golden-seed check.
        struct ValidateScratch
        {
            u64* mMarginLo = nullptr;
            u64* mMarginHi = nullptr;
            LeafGoldenSeedLimb* mLeaf = nullptr;
            u32* mFlag = nullptr;
            u32 mRho = 0;
            bool mAttemptActive = false;
            void* mAttemptStream = nullptr;
            u32 mAttemptRho = 0;

            explicit ValidateScratch(GpuStream& owner) : mOwner(owner) {}
            GpuStream& mOwner;
            std::array<OwnedGpuBuffer, 4> mStorage;

            bool ensure(u32 rho)
            {
                if (!rho) return false;
                if (rho <= mRho && mFlag) return true;
                try
                {
                    const auto& owner = mOwner.allocationOwner();
                    // Build a complete replacement before publishing pointers.
                    // The old scratch stays usable if allocation fails.
                    std::array<OwnedGpuBuffer, 4> next;
                    next[0] = OwnedGpuBuffer(owner, rho * sizeof(u64));
                    next[1] = OwnedGpuBuffer(owner, rho * sizeof(u64));
                    next[2] = OwnedGpuBuffer(owner, rho * sizeof(LeafGoldenSeedLimb));
                    next[3] = OwnedGpuBuffer(owner, sizeof(u32));
                    mStorage = std::move(next);
                    mMarginLo = static_cast<u64*>(mStorage[0].data());
                    mMarginHi = static_cast<u64*>(mStorage[1].data());
                    mLeaf = static_cast<LeafGoldenSeedLimb*>(mStorage[2].data());
                    mFlag = static_cast<u32*>(mStorage[3].data());
                    mRho = rho;
                    return mRho != 0;
                }
                catch (const std::bad_alloc&) { return false; }
            }
        };
    }

    struct GpuProtocolScratch
    {
        // Keep each sampling family separate even when it uses the same stream.
        // Main and prefetch streams have distinct owners, so their asynchronous
        // seed, prefix, and rejection writes cannot alias one another.
        explicit GpuProtocolScratch(GpuStream& stream)
            : sample(stream), senderPrefetch(stream), receiverPrefetch(stream),
              setup(stream), validation(stream) {}
        SampleScratch sample;
        SampleScratch senderPrefetch;
        SampleScratch receiverPrefetch;
        SampleScratch setup;
        ValidateScratch validation;
        IdxCache indices;
        std::vector<std::pair<std::vector<u64>, OwnedGpuBuffer>> plaintextLifts;
    };

    void GpuProtocolScratchDeleter::operator()(GpuProtocolScratch* scratch) const noexcept
    {
        delete scratch;
    }

    GpuProtocolScratch& GpuStream::protocolScratch()
    {
        if (!mProtocolScratch) mProtocolScratch.reset(new GpuProtocolScratch(*this));
        return *mProtocolScratch;
    }

    namespace
    {
        IdxCache& idxCache(GpuStream& stream) { return stream.protocolScratch().indices; }
        SampleScratch& sampleScratch(GpuStream& stream) { return stream.protocolScratch().sample; }
        SampleScratch& senderPrefetchSampleScratch(GpuStream& stream)
        { return stream.protocolScratch().senderPrefetch; }
        SampleScratch& receiverPrefetchSampleScratch(GpuStream& stream)
        { return stream.protocolScratch().receiverPrefetch; }
        ValidateScratch& validateScratch(GpuStream& stream) { return stream.protocolScratch().validation; }

        bool goldenSeedMargins(
            const Params& params, const RingNttContext& ctx, std::vector<u64>& lo, std::vector<u64>& hi)
        {
            return goldenSeedRoundingMargins(params, ctx, lo, hi);
        }

        bool uploadGoldenMargins(
            const Params& params,
            const RingNttContext& ctx,
            const GpuRing& ring,
            ValidateScratch& scratch,
            GpuStream& stream)
        {
            if (!scratch.mAttemptActive || scratch.mAttemptStream != stream.raw() ||
                scratch.mAttemptRho != ring.rho() ||
                params.mCt2SeedMode != Ct2SeedMode::GoldenSeed ||
                !(params.mShrinkExpand.mRing == ctx.mParams))
            {
                return false;
            }

            std::vector<u64> marginLo(ring.rho()), marginHi(ring.rho());
            if (!goldenSeedMargins(params, ctx, marginLo, marginHi)) return false;
            return gpuMemcpyH2D(
                       scratch.mMarginLo, marginLo.data(), ring.rho() * sizeof(u64), stream.raw()) &&
                   gpuMemcpyH2D(
                       scratch.mMarginHi, marginHi.data(), ring.rho() * sizeof(u64), stream.raw());
        }
    }


    // deviceDescription() is defined by LogVoleGpuBackend.cpp; the declaration
    // is repeated in LogVoleGpuProtocol.h so that callers only need one header.

    bool prepareReusableSenderCache(ShrinkExpandSenderState& state, ProtocolCacheScopeView scope)
    {
        const LogVoleGpuProtocolOptions defaults;
        const auto& options = state.mRingFactoryOwner
            ? state.mRingFactoryOwner->mExecutionOptions.mAdvanced.mProtocol : defaults;
        if (!options.mShareCache || !options.mShareSenderCache) return false;
        scope.mRole = ProtocolCacheRole::Sender;
        if (!enabled(state.mRingFactoryOwner)) return false;
        HostStep setupStep(hostProfiler(state.mRingFactoryOwner), "setup sender: shared device cache");
        // Publish only after buildOfflineCache completes its stream. Mutable
        // query buffers and sampler scratch remain outside the shared mirror.
        return static_cast<bool>(senderCache(state, scope));
    }

    bool prepareReusableReceiverCache(ShrinkExpandReceiverState& state, ProtocolCacheScopeView scope)
    {
        const LogVoleGpuProtocolOptions defaults;
        const auto& options = state.mRingFactoryOwner
            ? state.mRingFactoryOwner->mExecutionOptions.mAdvanced.mProtocol : defaults;
        if (!options.mShareCache) return false;

        // The direct Core API can arrive without a protocol role. Keep these
        // receiver tensors on the receiver stream even in that case.
        scope.mRole = ProtocolCacheRole::Receiver;
        if (!enabled(state.mRingFactoryOwner)) return false;
        HostStep setupStep(hostProfiler(state.mRingFactoryOwner), "setup receiver: shared device cache");
        // buildOfflineCache synchronizes before receiverCache publishes the
        // pointer. Only immutable buffers are shared; LevelSession and sampler
        // scratch remain separate for each query and stream.
        return static_cast<bool>(receiverCache(state, scope));
    }

    bool finalizeReceiverSetupDevice(
        const RingNttContext& ctx, ShrinkExpandReceiverState& state,
        bool deferHostSnapshot,
        std::shared_ptr<const LazyRingTensorHostState> encodedCt1,
        std::shared_ptr<const LazyLacctHostState> encodedLacct, ProtocolCacheScopeView scope)
    {
        scope.mRole = ProtocolCacheRole::Receiver;
        const bool hostA = static_cast<bool>(state.mPublicANtt);
        const bool hostB = static_cast<bool>(state.mPublicBNtt);
        const bool deviceA = static_cast<bool>(state.mPublicANttDevice);
        const bool deviceB = static_cast<bool>(state.mPublicBNttDevice);
        if (!enabled(ctx) || (!ctx.mContext && !ctx.mGpuLightweight) || !ringModulusCount(ctx) ||
            state.mGpuCache || state.mSharedHostState || state.mLazyCt1Ntt || state.mLazyLacct ||
            ctx.mParams != state.mParams.mRing || hostA == deviceA || hostB == deviceB)
            return false;
        const auto& ct1 = state.mCt1;
        const auto& lacct = state.mLacct;
        const u64 polyWords = ringPolyCoeffCount(ctx.mParams);
        if (!polyWords || polyWords > std::numeric_limits<std::size_t>::max() / sizeof(u64)) return false;
        const std::size_t polyBytes = static_cast<std::size_t>(polyWords) * sizeof(u64);
        const u64 ct1Count = ringTensorSize(ct1);
        const u64 lacctCount = ringTensorSize(lacct.mCt);
        if (ct1Count > std::numeric_limits<u32>::max() ||
            lacctCount > std::numeric_limits<u32>::max() ||
            ct1Count > std::numeric_limits<std::size_t>::max() / polyBytes ||
            lacctCount > std::numeric_limits<std::size_t>::max() / polyBytes) return false;
        const auto ct1Bytes = encodedCt1 ? encodedCt1->encodedCoefficients() : ConstWireView{};
        const auto lacctBytes = encodedLacct ? encodedLacct->encodedCoefficients() : ConstWireView{};
        const bool ct1InputValid = encodedCt1
            ? ct1.mPolys.empty() && ct1Bytes.size() == ct1Count * polyBytes
            : ct1.mPolys.size() == ct1Count && validateRingBatchShape(ct1.mPolys, ctx.mParams);
        const bool lacctInputValid = encodedLacct
            ? lacct.mCt.mPolys.empty() && lacctBytes.size() == lacctCount * polyBytes
            : lacct.mCt.mPolys.size() == lacctCount && validateRingBatchShape(lacct.mCt.mPolys, ctx.mParams);
        const std::size_t publicBTau = static_cast<std::size_t>(state.mParams.mTau) +
            (state.mParams.mTruncateOneGadgetDigit ? 1u : 0u);
        if (publicBTau > std::numeric_limits<std::size_t>::max() / 2u) return false;
        const std::size_t expectedBCount = 2u * publicBTau;
        const bool publicAValid = hostA
            ? state.mPublicANtt->size() == state.mParams.mMu &&
                validateRingBatchShape(*state.mPublicANtt, ctx.mParams)
            : retainedPublicUniformMatches(ctx, *state.mPublicANttDevice,
                state.mParams.mMu, false, scope);
        const bool publicBValid = hostB
            ? state.mPublicBNtt->size() == expectedBCount &&
                validateRingBatchShape(*state.mPublicBNtt, ctx.mParams)
            : retainedPublicUniformMatches(ctx, *state.mPublicBNttDevice,
                expectedBCount, true, scope);
        if (!ct1.mRows || !ct1.mCols || ct1.mRows != state.mParams.mMu ||
            ct1.mCols != state.mParams.mTau ||
            !lacct.mWidthPadded || !lacct.mLevels || !lacct.mCt.mCols ||
            static_cast<std::size_t>(lacct.mLevels) * lacct.mWidthPadded != lacct.mCt.mRows ||
            !publicAValid || !publicBValid || !ct1InputValid || !lacctInputValid) return false;
        const auto decline = ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mReceiverResidentNtt;
        if (decline == LogVoleFailureStage::BeforeWork) return false;

        HostStep totalStep(hostProfiler(ctx), "setup receiver: resident ciphertext NTT");
        // These are receiver-owned decoded tensors. No sender device buffer or
        // transport shortcut participates in constructing this mirror.
        auto cache = buildOfflineCache(ctx, state.mPublicANtt.get(), state.mPublicBNtt.get(),
            state.mPublicANttDevice.get(), state.mPublicBNttDevice.get(),
            ct1, lacct, false, state.mParams.mTransport.mEncoding.mWire,
            scope, ct1Bytes, lacctBytes);
        if (!cache) return false;
        // Regression hook: decline after the complete device transform, before
        // either host state or the synchronized cache has been published.
        if (decline == LogVoleFailureStage::AfterWork) return false;

        if (deferHostSnapshot && (ctx.mExecutionOptions.mAdvanced.mProtocol.mReceiverLazyNtt))
        {
            auto owner = std::make_shared<ReceiverCt1HostState>(ctx, cache,
                ct1.mRows, ct1.mCols, state.mParams.mNumWorkerThreads,
                currentDeviceOrdinal(), scope.mRunId, encodedCt1);
            // Every allocation completed before consuming the only mutable
            // coefficient backing. Metadata remains available without get().
            owner->takeCoefficients(std::move(state.mCt1.mPolys));
            state.mLazyCt1Ntt = std::move(owner);
            state.mLazyLacct = std::move(encodedLacct);
            state.mGpuCache = std::move(cache);
            return true;
        }

        // Encoded callers that explicitly request public/eager output retain
        // the same complete Lacct snapshot. Internal callers can keep its wire
        // owner even when the Ct1-laziness ablation requests an eager NTT.
        ShrinkExpandLacct nextLacct;
        if (encodedLacct && !deferHostSnapshot) nextLacct = encodedLacct->get();
        std::vector<RnsPoly> nextCt1;
        auto& stream = contextStream(ctx);
        StreamDrain drain{stream};
        {
            HostStep downloadStep(hostProfiler(ctx), "setup receiver: resident NTT host snapshot");
            if (!downloadReceiverCt1Snapshot(ctx, *cache, nextCt1, stream, state.mParams.mNumWorkerThreads)) return false;
        }
        // Atomic publication preserves coefficient-domain fallback even if a
        // later download fails after the cache's NTT has completed.
        state.mCt1.mPolys = std::move(nextCt1);
        if (encodedLacct)
        {
            if (deferHostSnapshot) state.mLazyLacct = std::move(encodedLacct);
            else state.mLacct = std::move(nextLacct);
        }
        state.mGpuCache = std::move(cache);
        return true;
    }

    bool lencRandomizerResidencyEnabled(const LogVoleExecutionOptions& options, bool selectedGpu)
    {
        return (options.mUseGpu && selectedGpu) && options.mAdvanced.mProtocol.mLencRandomizerResidency;
    }

    namespace
    {
        class GpuLencRandomizers final : public LazyLencRandomizerState
        {
        public:
            GpuLencRandomizers(const RingNttContext& ctx, std::shared_ptr<GpuRing> ring,
                GpuPolyBuffer&& ntt, ProtocolCacheRole role)
                : mContext(ctx), mRing(std::move(ring)), mNtt(std::move(ntt)),
                  mDevice(currentDeviceOrdinal()), mRole(role) {}

            std::size_t count() const override { return mNtt.count(); }
            bool matches(const RingParams& params) const override { return params == mContext.mParams; }
            const GpuPolyBuffer* deviceNtt(const RingNttContext& ctx, ProtocolCacheRole role) const
            {
                if (!matches(ctx.mParams) || currentDeviceOrdinal() != mDevice ||
                    role != mRole ||
                    ringModulusCount(ctx) != ringModulusCount(mContext)) return nullptr;
                for (std::size_t i = 0; i < ringModulusCount(ctx); ++i)
                    if (ringModulusValue(ctx, i) != ringModulusValue(mContext, i)) return nullptr;
                return &mNtt;
            }

            const std::vector<RnsPoly>& hostNtt() const override
            {
                std::call_once(mNttOnce, [&] { materialize(false, mHostNtt); });
                return mHostNtt;
            }

            const std::vector<RnsPoly>& hostCoefficients() const override
            {
                std::call_once(mCoeffOnce, [&] { materialize(true, mHostCoefficients); });
                return mHostCoefficients;
            }

        private:
            void materialize(bool coefficients, std::vector<RnsPoly>& out) const
            {
                // The two lazy host views have independent once_flags. Order
                // their device reads even when host callers request both views.
                std::lock_guard use(mMaterializeMutex);
                HostStep step(hostProfiler(mContext), coefficients ? "setup: deferred LENC R coefficients" : "setup: deferred LENC R NTT");
                if (currentDeviceOrdinal() != mDevice)
                    throw std::runtime_error("LogVole randomizers requested on a different CUDA device");
                GpuStream stream(mContext.mExecutionOptions.mAdvanced.mStreams, mContext.mHostProfiler);
                GpuPolyBuffer coeff;
                std::vector<RnsPoly> next;
                StreamDrain drain{stream};
                const GpuPolyBuffer* source = &mNtt;
                if (coefficients)
                {
                    if (!coeff.resize(*mRing, count(), stream) ||
                        !gpuMemcpyD2D(coeff.data(stream), mNtt.data(stream), mNtt.bytes(), stream.raw()) ||
                        !launchNttInverse(mRing->view(stream), coeff.data(stream), static_cast<u32>(count()), nullptr, stream.raw()))
                        throw std::runtime_error("LogVole deferred randomizer inverse transform failed");
                    source = &coeff;
                }
                if (!source->download(next, stream) || !stream.sync())
                    throw std::runtime_error("LogVole deferred randomizer download failed");
                out = std::move(next);
            }

            RingNttContext mContext;
            std::shared_ptr<GpuRing> mRing;
            GpuPolyBuffer mNtt;
            mutable std::mutex mMaterializeMutex;
            int mDevice;
            ProtocolCacheRole mRole;
            mutable std::once_flag mNttOnce, mCoeffOnce;
            mutable std::vector<RnsPoly> mHostNtt, mHostCoefficients;
        };

        const GpuPolyBuffer* lencRandomizerDeviceNtt(
            const RingNttContext& ctx, const LazyLencRandomizerState* state, ProtocolCacheScopeView scope)
        {
            const auto* owner = dynamic_cast<const GpuLencRandomizers*>(state);
            return owner ? owner->deviceNtt(ctx, scope.mRole) : nullptr;
        }

        // A completed ciphertext remains in its producer's allocation. Wire
        // encoding can copy the contiguous coefficient array without building
        // thousands of host polynomials; an actual CPU consumer gets a stable,
        // independently owned snapshot on its first request.
        class GpuSetupTensorHostState final : public LazyRingTensorHostState
        {
        public:
            GpuSetupTensorHostState(std::shared_ptr<GpuRing> ring,
                std::shared_ptr<GpuExecutionContext> execution, GpuPolyBuffer&& buffer,
                u32 rows, u32 cols)
                : mRing(std::move(ring)), mExecution(std::move(execution)), mBuffer(std::move(buffer)),
                  mDevice(currentDeviceOrdinal())
            {
                mHost.mRows = rows;
                mHost.mCols = cols;
            }

            const RingTensor& get() const override
            {
                std::call_once(mOnce, [&] {
                    std::lock_guard use(mDeviceUseMutex);
                    HostStep step(mExecution->hostProfiler(), "setup: deferred sender tensor materialization");
                    if (currentDeviceOrdinal() != mDevice)
                        throw std::runtime_error("LogVole deferred tensor requested on a different CUDA device");
                    auto& stream = mExecution->sampleStream();
                    std::vector<RnsPoly> next;
                    StreamDrain drain{stream};
                    const bool downloaded = mBuffer.download(next, stream);
                    if (!stream.sync() || !downloaded)
                        throw std::runtime_error("LogVole deferred tensor download failed");
                    mHost.mPolys = std::move(next);
                });
                return mHost;
            }

            bool copyCoefficientsTo(WireView destination, const LogVoleWireOptions& options) const override
            {
                std::lock_guard use(mDeviceUseMutex);
                if (destination.size() != mBuffer.bytes() || currentDeviceOrdinal() != mDevice)
                    return false;
                HostStep step(mExecution->hostProfiler(), "setup: device ciphertext to wire");
                auto& stream = mExecution->sampleStream();
                const bool copied = downloadSetupWire(destination, mBuffer.data(stream), stream, options);
                return stream.sync() && copied;
            }

        private:
            std::shared_ptr<GpuRing> mRing;
            std::shared_ptr<GpuExecutionContext> mExecution;
            GpuPolyBuffer mBuffer;
            mutable std::mutex mDeviceUseMutex;
            int mDevice;
            mutable std::once_flag mOnce;
            mutable RingTensor mHost;
        };
    }

    std::shared_ptr<const LazyRingTensorHostState> makeGpuSetupTensorHostState(
        const RingNttContext& ctx, GpuPolyBuffer&& buffer, u32 rows, u32 cols)
    {
        auto ring = GpuRing::get(ctx);
        if (!ctx.mGpuExecution || !ring || !rows || !cols || buffer.count() != static_cast<std::size_t>(rows) * cols ||
            buffer.polyWords() != ring->polyWords()) return {};
        return std::make_shared<GpuSetupTensorHostState>(std::move(ring),
            ctx.mGpuExecution, std::move(buffer), rows, cols);
    }

    // ---- DeviceBatch ------------------------------------------------------

    struct DeviceBatch::Impl
    {
        std::shared_ptr<GpuRing> mRing;
        GpuPolyBuffer mBuf;
        // A recursive dHat batch may keep one full-RNS high digit in mBuf for
        // every rho logical single-limb values. count() still reports the
        // protocol-visible logical shape.
        std::size_t mLogicalCount = 0;
        u32 mRecursiveHiRepeat = 0;
        bool mRecursiveHiNtt = false;
        // Nonzero only when every coefficient is proven to be the same canonical
        // plaintext value in every RNS limb, bounded by this many bits. This
        // provenance enables an exact identity-gadget fast path; arbitrary uploads
        // and all derived ring batches deliberately leave it zero.
        u32 mPlainBroadcastBits = 0;
        // True only when the logical broadcast above is physically present in
        // limb 0 and limbs 1..3 must either be broadcast on the identity-forward
        // load or materialized before another consumer observes the batch.
        bool mPlainBroadcastSingleLimb = false;
        // Provenance for a synchronized, device-generated fresh Root key.
        // Unlike an optional host mirror, this may be its only materialization.
        bool mFreshRootKPrime = false;
        // Completed coefficient-domain Root r1 sampled for the sender's
        // offline run. This provenance is required before a device consumer
        // borrows its bytes: ordinary DeviceBatch uploads have no such scope.
        bool mRootErrorCoefficients = false;
        ProtocolCacheRole mRootErrorRole = ProtocolCacheRole::Unspecified;
        ProtocolCacheRunId mRootErrorRunId = 0;
        std::shared_ptr<const ProtocolCacheService> mIdentityService;
        int mRootErrorDevice = -1;
        // Private, immutable sender Root skRRt. A transformed copy retains the
        // same offline provenance and sets mRootSecretNtt; it is never a public
        // uniform token and must never be mutated by a consumer.
        bool mRootSecretUniform = false;
        bool mTopSecretUniform = false;
        bool mRootSecretNtt = false;
        ProtocolCacheRole mRootSecretRole = ProtocolCacheRole::Unspecified;
        ProtocolCacheRunId mRootSecretRunId = 0;
        int mRootSecretDevice = -1;
        // CI-VOLE's private wrapped delta and its exact seed-label repetition
        // remain coefficient-domain sender operands until the first LENC
        // consumer. An ordinary upload lacks these producer-only markers.
        bool mSetupDeltaCoefficients = false;
        bool mSetupSeedLabelRepCoefficients = false;
        bool mTopSeedLabelRepCoefficients = false;
        bool mRootHiRepCoefficients = false;
        ProtocolCacheRole mSetupSenderRole = ProtocolCacheRole::Unspecified;
        ProtocolCacheRunId mSetupSenderRunId = 0;
        int mSetupSenderDevice = -1;
    };

    // First-query allocation overlap is deliberately narrow: only the
    // production NoGoldenSeed N=16384/rho=8, W=2048, n=2^25 geometry. These
    // buffers are owned by one receiver state, reserved after its application
    // total timer starts, and transferred only to that state's first query.
    class ReceiverFirstQueryAllocations
    {
    public:
        explicit ReceiverFirstQueryAllocations(LogVoleGpuStreamOptions options, std::shared_ptr<HostStepProfiler> profile)
            : mStreamOptions(options), mHostProfiler(std::move(profile)) {}
        const LogVoleGpuStreamOptions mStreamOptions;
        const std::shared_ptr<HostStepProfiler> mHostProfiler;
        RingParams mRingParams;
        std::vector<u64> mOrderedPrimes;
        u64 mLabelCount = 0;
        u32 mRingWidth = 0;
        int mDevice = -1;
        ProtocolCacheRunId mOfflineRunId = 0;
        std::shared_ptr<const ProtocolCacheService> mIdentityService;
        std::thread mWorker;
        GpuPolyBuffer mWrap;
        GpuPolyBuffer mNodes;
        void* mReadyEvent = nullptr;
        bool mReady = false;
        const void* mOfflineOwner = nullptr;
        bool mBound = false;
        bool mWrapUsed = false;
        bool mNodesUsed = false;
        const void* mOwner = nullptr;
        u64 mSid = 0;
        ProtocolCacheRunId mOnlineRunId = 0;
        std::mutex mMutex;
        std::mutex mJoinMutex;

        ~ReceiverFirstQueryAllocations()
        {
            finish();
            gpuEventDestroy(mReadyEvent);
        }

        void finish()
        {
            std::lock_guard<std::mutex> lock(mJoinMutex);
            if (mWorker.joinable()) mWorker.join();
        }

        void reserve()
        {
            if (currentDeviceOrdinal() != mDevice) return;
            GpuStream stream(mStreamOptions, mHostProfiler);
            if (!stream.raw()) return;
            bool ok = false;
            try
            {
                HostStep step(mHostProfiler.get(), "recv: overlap first-query GPU allocation");
                const std::size_t polyWords =
                    static_cast<std::size_t>(mRingParams.mPolyModulusDegree) *
                    mRingParams.mCoeffModulusBits.size();
                const std::size_t nodeCount =
                    (static_cast<std::size_t>(mRingWidth) / 16u) * 31u + 1u;
                ok = mWrap.resizeWords(polyWords, mRingWidth, stream) &&
                    mNodes.resizeWords(polyWords, nodeCount, stream);
                if (ok)
                {
                    mReadyEvent = gpuEventCreate();
                    ok = mReadyEvent && gpuEventRecord(mReadyEvent, stream.raw());
                }
            }
            catch (...) { ok = false; }
            const bool complete = stream.sync();
            mReady = ok && complete;
            if (!mReady)
            {
                mWrap.release();
                mNodes.release();
            }
        }
    };

    ReceiverFirstQueryAllocationsPtr beginReceiverFirstQueryAllocations(
        const Params& params, const std::shared_ptr<const RingNttContext>& ringOwner, ProtocolCacheScopeView scope)
    {
        const LogVoleGpuProtocolOptions defaults;
        const auto& options = ringOwner ? ringOwner->mExecutionOptions.mAdvanced.mProtocol : defaults;
        const bool forcedDecline = options.mFailures.mReceiverFirstQueryAlloc;
        if (!options.mReceiverFirstQueryAllocationOverlap ||
            (forcedDecline) || !enabled(ringOwner) ||
            scope.mRole != ProtocolCacheRole::Receiver ||
            currentDeviceOrdinal() != 0 || params.mW != 2048u ||
            params.mTotalLabelCount != (u64{1} << 25) ||
            params.mCt2SeedMode != Ct2SeedMode::PublicSeed)
            return {};
        const auto& se = params.mShrinkExpand;
        if (se.mRing.mPolyModulusDegree != 16384u ||
            se.mRing.mCoeffModulusBits.size() != 8u ||
            !std::all_of(se.mRing.mCoeffModulusBits.begin(),
                se.mRing.mCoeffModulusBits.end(), [](int bits) { return bits == 52; }) ||
            se.mAlpha != 2u || se.mMu != 32u || se.mTau != 2u ||
            se.mGadgetLogBase != 208u || se.mTruncateOneGadgetDigit)
            return {};

        RingNttContext ctx{};
        if (!makeRingNttContext(se.mRing, ctx, ringOwner, scope) || ringModulusCount(ctx) != 8u)
            return {};
        auto plan = std::make_shared<ReceiverFirstQueryAllocations>(ctx.mExecutionOptions.mAdvanced.mStreams, ctx.mHostProfiler);
        plan->mRingParams = se.mRing;
        plan->mOrderedPrimes.reserve(8u);
        for (std::size_t i = 0; i < 8u; ++i)
            plan->mOrderedPrimes.push_back(ringModulusValue(ctx, i));
        plan->mLabelCount = params.mTotalLabelCount;
        plan->mRingWidth = params.mW;
        plan->mDevice = currentDeviceOrdinal();
        plan->mOfflineRunId = scope.mRunId;
        if (plan->mOfflineRunId)
            plan->mIdentityService = plan->mOfflineRunId.serviceOwner();
        else if (ctx.mFactory)
            plan->mIdentityService = ctx.mFactory->protocolService();
        else if (ctx.mGpuSetup)
            plan->mIdentityService = ctx.mGpuSetup->protocolService();
        else if (ctx.mGpuExecution)
            plan->mIdentityService = ctx.mGpuExecution->protocolService();
        if (!plan->mIdentityService) return {};
        try { plan->mWorker = std::thread([raw = plan.get()] {
            try { raw->reserve(); } catch (...) { raw->mReady = false; }
        }); }
        catch (const std::system_error&) { return {}; }
        return plan;
    }

    void finishReceiverFirstQueryAllocations(
        const ReceiverFirstQueryAllocationsPtr& plan)
    {
        if (plan) plan->finish();
    }

    bool sealReceiverFirstQueryAllocationOwner(
        const ReceiverFirstQueryAllocationsPtr& plan, const void* owner, ProtocolCacheScopeView scope)
    {
        if (!plan || !owner ||
            scope.mRole != ProtocolCacheRole::Receiver ||
            currentDeviceOrdinal() != plan->mDevice) return false;
        plan->finish();
        std::lock_guard<std::mutex> lock(plan->mMutex);
        if (!plan->mReady || plan->mOfflineOwner || plan->mBound ||
            plan->mOfflineRunId != scope.mRunId)
            return false;
        plan->mOfflineOwner = owner;
        return true;
    }

    bool bindReceiverFirstQueryAllocations(
        const ReceiverFirstQueryAllocationsPtr& plan, const void* owner, u64 sid, ProtocolCacheScopeView scope)
    {
        if (!plan || !owner || scope.mRole != ProtocolCacheRole::Receiver ||
            currentDeviceOrdinal() != plan->mDevice) return false;
        plan->finish();
        std::lock_guard<std::mutex> lock(plan->mMutex);
        if (!plan->mReady || plan->mBound || plan->mOfflineOwner != owner ||
            scope.mRunId.mValue != sid) return false;
        plan->mBound = true;
        plan->mOwner = owner;
        plan->mSid = sid;
        return true;
    }

    void bindReceiverFirstQueryOnlineRun(
        const ReceiverFirstQueryAllocationsPtr& plan, const void* owner, u64 sid,
        ProtocolCacheRunId runId, ProtocolCacheScopeView scope)
    {
        if (!plan || !owner || !runId ||
            runId.mService != plan->mIdentityService.get() ||
            scope.mRole != ProtocolCacheRole::Receiver ||
            currentDeviceOrdinal() != plan->mDevice) return;
        std::lock_guard<std::mutex> lock(plan->mMutex);
        if (plan->mReady && plan->mBound && plan->mOwner == owner &&
            plan->mOfflineOwner == owner &&
            plan->mSid == sid && !plan->mOnlineRunId)
        {
            if (scope.mRunId == runId)
                plan->mOnlineRunId = runId;
        }
    }

    bool receiverFirstQueryAllocationStatus(
        const ReceiverFirstQueryAllocationsPtr& plan,
        bool& ready, bool& wrapSelected, bool& nodesSelected)
    {
        ready = wrapSelected = nodesSelected = false;
        if (!plan) return false;
        plan->finish();
        std::lock_guard<std::mutex> lock(plan->mMutex);
        ready = plan->mReady;
        wrapSelected = plan->mWrapUsed;
        nodesSelected = plan->mNodesUsed;
        return true;
    }

    namespace
    {
        bool receiverFirstQueryRingMatches(
            const ReceiverFirstQueryAllocations& plan, const GpuRing& ring,
            const RingParams& params)
        {
            return plan.mRingParams == params &&
                ring.n() == params.mPolyModulusDegree &&
                ring.rho() == params.mCoeffModulusBits.size() &&
                ring.hostModuli() == plan.mOrderedPrimes;
        }

        bool takeReceiverFirstQueryWrap(
            ReceiverFirstQueryAllocations* plan, const GpuRing& ring,
            const RingParams& params, std::size_t labelCount,
            std::size_t total, bool garbledInput, const void* owner,
            u64 sid, GpuPolyBuffer& out, GpuStream& stream, ProtocolCacheScopeView scope)
        {
            if (!plan || !owner || garbledInput ||
                scope.mRole != ProtocolCacheRole::Receiver ||
                scope.mRunId.mValue != sid ||
                currentDeviceOrdinal() != plan->mDevice ||
                labelCount != plan->mLabelCount || total != plan->mRingWidth ||
                !receiverFirstQueryRingMatches(*plan, ring, params)) return false;
            std::lock_guard<std::mutex> lock(plan->mMutex);
            if (!plan->mReady || !plan->mBound ||
                plan->mOfflineOwner != owner || plan->mOwner != owner ||
                plan->mSid != sid || plan->mWrapUsed ||
                plan->mWrap.count() != total || !plan->mReadyEvent ||
                !gpuStreamWaitEvent(stream.raw(), plan->mReadyEvent)) return false;
            out = std::move(plan->mWrap);
            plan->mWrapUsed = true;
            return true;
        }

        bool takeReceiverFirstQueryNodes(
            ReceiverFirstQueryAllocations* plan, const GpuRing& ring,
            const RingParams& params, u32 xCount, u32 muHi, u32 tauHi,
            u32 width, u32 maxTau, std::size_t nodeCount,
            const void* owner, u64 sid, GpuPolyBuffer& out, GpuStream& stream, ProtocolCacheScopeView scope)
        {
            if (!plan || !owner ||
                scope.mRole != ProtocolCacheRole::Receiver ||
                currentDeviceOrdinal() != plan->mDevice ||
                xCount != 2048u || muHi != 16u || tauHi != 1u ||
                width != 16u || maxTau != 1u || nodeCount != 3969u ||
                !receiverFirstQueryRingMatches(*plan, ring, params)) return false;
            std::lock_guard<std::mutex> lock(plan->mMutex);
            if (!plan->mReady || !plan->mBound ||
                plan->mOfflineOwner != owner || plan->mOwner != owner ||
                plan->mSid != sid || !plan->mOnlineRunId ||
                plan->mOnlineRunId != scope.mRunId ||
                plan->mNodesUsed ||
                plan->mNodes.count() != nodeCount || !plan->mReadyEvent ||
                !gpuStreamWaitEvent(stream.raw(), plan->mReadyEvent)) return false;
            out = std::move(plan->mNodes);
            plan->mNodesUsed = true;
            return true;
        }
    }

    struct PreparedSenderCt2::Impl
    {
        const ShrinkExpandSenderState* mState = nullptr;
        std::shared_ptr<GpuRing> mRing;
        GpuPolyBuffer mCt2;
        std::vector<u8> mSeed;
        u64 mSid = 0;
        u64 mInstanceBase = 0;
        block mMaskDigestHash{};
        u32 mChunkCount = 0;
        u32 mMu = 0;
        // Retain the native stream even if the context is released before
        // an abandoned plan finishes cleanup. Never retain context scratch.
        std::shared_ptr<OwnedGpuStream> mProducerOwner;
        void* mReadyEvent = nullptr;
        bool mEventRecorded = false;
        bool mConsumed = false;

        ~Impl()
        {
            // On the success path expandSenderChunks first queues a wait on the
            // main stream and moves mCt2 into its ordinary local buffer. On any
            // other path (invalid candidate, deferred retry, allocation/launch
            // failure), do not release storage that the secondary stream may
            // still be writing.
            if (!mConsumed && mProducerOwner)
            {
                const bool eventDone =
                    mEventRecorded && mReadyEvent && gpuEventSync(mReadyEvent);
                if (!eventDone && !gpuStreamSync(mProducerOwner->raw())) std::terminate();
            }
            gpuEventDestroy(mReadyEvent);
        }
    };

    struct PreparedReceiverCt2::Impl
    {
        const ShrinkExpandReceiverState* mState = nullptr;
        std::shared_ptr<GpuRing> mRing;
        GpuPolyBuffer mCt2;
        std::vector<u8> mSeed;
        u64 mSid = 0;
        u64 mInstanceBase = 0;
        block mMaskDigestHash{};
        u32 mChunkCount = 0;
        u32 mMu = 0;
        // Retain the native stream even if the context is released before
        // an abandoned plan finishes cleanup. Never retain context scratch.
        std::shared_ptr<OwnedGpuStream> mProducerOwner;
        void* mReadyEvent = nullptr;
        bool mEventRecorded = false;
        bool mConsumed = false;

        ~Impl()
        {
            // A plan may be abandoned because an ancestor took the CPU fallback,
            // metadata stopped matching, or a later prefetch failed. Its storage
            // is still owned here, so do not release it while the secondary stream
            // may be writing it.
            if (!mConsumed && mProducerOwner)
            {
                const bool eventDone =
                    mEventRecorded && mReadyEvent && gpuEventSync(mReadyEvent);
                if (!eventDone && !gpuStreamSync(mProducerOwner->raw())) std::terminate();
            }
            gpuEventDestroy(mReadyEvent);
        }
    };

    struct PreparedRootFinalize::Impl
    {
        const ReceiverState* mState = nullptr;
        std::shared_ptr<GpuRing> mRing;
        std::shared_ptr<void> mRootCacheOwner;
        std::shared_ptr<void> mLevelCacheOwner;
        std::shared_ptr<LevelSession> mTree;
        DeviceBatchPtr mTopInputs;
        // The priority candidate reads the already synchronized coefficient-
        // domain dPrime directly. Retain its owner across the socket wait and
        // every abandoned-work cleanup path.
        DeviceBatchPtr mDPrime;
        // The concrete workspace is owned by mRootCacheOwner and declared
        // with RootDeviceCache below.
        void* mPriorityWorkspace = nullptr;
        u32 mTauHi = 0;
        u32 mLeftWidth = 0;
        u32 mTopCols = 0;
        void* mProducerStream = nullptr;
        void* mReadyEvent = nullptr;
        bool mWorkQueued = false;
        bool mEventRecorded = false;
        bool mReady = false;
        bool mConsumed = false;
        bool mProducerKnownComplete = false;

        ~Impl()
        {
            // A successful suffix first transfers the dependency to its stream
            // and moves both outputs into ordinary locals. Every other path --
            // allocation/launch failure, metadata miss, socket exception, or an
            // unconsumed test handle -- must finish the producer before these
            // owned buffers and input owners are released.
            if (!mProducerKnownComplete && mWorkQueued && mProducerStream)
            {
                const bool eventDone =
                    mEventRecorded && mReadyEvent && gpuEventSync(mReadyEvent);
                if (!eventDone) gpuStreamSync(mProducerStream);
            }
            gpuEventDestroy(mReadyEvent);
        }
    };

    DeviceBatch::DeviceBatch() : mImpl(std::make_unique<Impl>()) {}
    DeviceBatch::~DeviceBatch() = default;

    PreparedSenderCt2::PreparedSenderCt2() : mImpl(std::make_unique<Impl>()) {}
    PreparedSenderCt2::~PreparedSenderCt2() = default;

    PreparedReceiverCt2::PreparedReceiverCt2() : mImpl(std::make_unique<Impl>()) {}
    PreparedReceiverCt2::~PreparedReceiverCt2() = default;

    PreparedRootFinalize::PreparedRootFinalize() : mImpl(std::make_unique<Impl>()) {}
    PreparedRootFinalize::~PreparedRootFinalize() = default;

    void DeviceScalars::finishForeignUse()
    {
        if (mProducerStream && mLastUse != mStorage.stream())
            mLastUse->synchronize();
    }

    DeviceScalars::~DeviceScalars()
    {
        // A foreign use must complete before the allocation is returned to
        // its original stream's cache. The common same-stream path just queues
        // a release event and does not introduce a host synchronization.
        try { finishForeignUse(); }
        catch (...) { std::terminate(); }
    }

    bool DeviceScalars::prepareUse(GpuStream& stream) const
    {
        if (empty()) return false;
        try
        {
            const auto& next = stream.allocationOwner();
            if (next != mLastUse)
            {
                if (mProducerStream) mLastUse->synchronize();
                mLastUse = next;
            }
            mProducerStream = next->raw();
            return true;
        }
        catch (const std::bad_alloc&) { return false; }
    }

    bool DeviceScalars::resize(std::size_t count, GpuStream& stream)
    {
        if (count > std::numeric_limits<std::size_t>::max() / sizeof(u64)) return false;
        try
        {
            if (!count)
            {
                finishForeignUse();
                mStorage.reset();
                mLastUse.reset();
                mData = nullptr;
                mCount = 0;
                mProducerStream = nullptr;
                return true;
            }
            const auto& owner = stream.allocationOwner();
            if (count == mCount && mStorage.stream() == owner) return prepareUse(stream);
            // Construct before replacing the old output. Allocation failure
            // leaves its contents and completion owner intact.
            OwnedGpuBuffer next(owner, count * sizeof(u64));
            finishForeignUse();
            mStorage = std::move(next);
            mLastUse = owner;
            mData = static_cast<u64*>(mStorage.data());
            mCount = count;
            mProducerStream = stream.raw();
            return true;
        }
        catch (const std::bad_alloc&) { return false; }
    }

    bool syncStream(const RingNttContext& ctx)
    {
        if (!enabled(ctx)) return true;
        return contextStream(ctx).sync();
    }

    bool nttHostBatch(const RingNttContext& ctx, std::span<RnsPoly> polys, bool inverse)
    {
        return nttHostBatch(ctx, polys, inverse, false);
    }

    bool nttHostBatch(const RingNttContext& ctx, std::span<RnsPoly> polys,
        bool inverse, bool canonicalizeOnDevice)
    {
        if (!enabled(ctx) || polys.empty()) return false;
        const auto forcedDecline = canonicalizeOnDevice
            ? ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mNttCanonicalize : LogVoleFailureStage::None;
        if (forcedDecline == LogVoleFailureStage::BeforeWork) return false;
        HostStep totalStep(hostProfiler(ctx), "setup batch NTT total");
        auto ring = GpuRing::get(ctx);
        if (!ring) return false;
        if (polys.size() > std::numeric_limits<u32>::max() ||
            ring->polyWords() > std::numeric_limits<std::size_t>::max() / sizeof(u64)) return false;
        const std::size_t polyBytes = ring->polyWords() * sizeof(u64);
        if (polyBytes == 0 || polys.size() > std::numeric_limits<std::size_t>::max() / polyBytes)
            return false;

        // GpuPolyBuffer::upload copies polyWords() per polynomial straight out of
        // mCoeffs without checking its length, so a short polynomial here is an
        // out-of-bounds read rather than a failure. The host forwardNtt path
        // validates shape per call and returns false, so a caller switched from the
        // per-polynomial loop to this batch entry point silently loses that check.
        // Decline instead, which falls back to the host loop.
        for (const auto& poly : polys)
        {
            if (poly.mCoeffs.size() != ring->polyWords()) return false;
        }

        // The secondary stream, not the main one. This entry point is host-in and
        // host-out: it uploads, transforms and downloads a buffer of its own, with
        // no ordering relationship to anything already queued. On the main stream
        // its closing download drains whatever the level above still has in flight -
        // hundreds of megabytes of expand work stuck behind a four-polynomial
        // transform - which is why routing the Root's transforms through here used
        // to lose (44.0 -> 39.0 M/s) and why they mostly stayed on the CPU. The
        // caching allocator now expresses cross-stream reuse as an event wait rather
        // than a host synchronise, so a second stream no longer reintroduces the
        // same drain by the back door.
        auto& stream = contextSampleStream(ctx);
        GpuPolyBuffer buf;
        // Keep fallback download destinations alive until the failure guard
        // drains any queued DMA, including a failed later download chunk.
        std::vector<RnsPoly> out;
        bool completed = false;
        struct FinishBeforeRelease
        {
            GpuStream& stream;
            bool& completed;
            ~FinishBeforeRelease() { if (!completed) stream.sync(); }
        } finishBeforeRelease{stream, completed};
        {
            HostStep uploadStep(hostProfiler(ctx), "setup batch NTT upload");
            if (!buf.resize(*ring, polys.size(), stream)) return false;
            if (!buf.upload(std::span<const RnsPoly>(polys.data(), polys.size()), stream)) return false;
        }

        {
            // This is launch time only; download includes the device wait.
            HostStep launchStep(hostProfiler(ctx), "setup batch NTT launch");
            if (canonicalizeOnDevice && !inverse &&
                !launchCanonicalize(ring->view(stream), buf.data(stream), nullptr,
                    static_cast<u32>(polys.size()), stream.raw())) return false;
            const bool ok = inverse
                ? launchNttInverse(
                      ring->view(stream), buf.data(stream), static_cast<u32>(polys.size()), nullptr, stream.raw())
                : launchNttForward(
                      ring->view(stream), buf.data(stream), static_cast<u32>(polys.size()), nullptr, stream.raw());
            if (!ok) return false;
            if (canonicalizeOnDevice && inverse &&
                !launchCanonicalize(ring->view(stream), buf.data(stream), nullptr,
                    static_cast<u32>(polys.size()), stream.raw())) return false;
        }
        // Test rollback after queued reduction/NTT work, before host publication.
        if (forcedDecline == LogVoleFailureStage::AfterWork) return false;

        HostStep downloadStep(hostProfiler(ctx), "setup batch NTT download");
        const bool reuseHost = ctx.mExecutionOptions.mAdvanced.mProtocol.mNttReuseHost;
        // Bound per-stream pinned retention; larger batches keep the existing
        // chunked download into a temporary host matrix.
        constexpr std::size_t maxReuseBytes = std::size_t(512) << 20;
        const std::size_t bytes = polys.size() * polyBytes;
        if (reuseHost && bytes <= maxReuseBytes)
        {
            // Complete the entire download before changing any input. A failed
            // batch must leave all polynomials in their original domain so the
            // caller can safely fall back to CPU transforms. Chunked writes
            // into polys would violate that guarantee after a later failure.
            if (auto* stage = stream.staging(bytes))
            {
                if (!gpuMemcpyD2H(stage, buf.data(stream), bytes, stream.raw()) || !stream.sync()) return false;
                completed = true;
                // Every allocation already has exactly polyWords() entries.
                // Reuse them instead of allocating a second full host matrix.
                for (std::size_t i = 0; i < polys.size(); ++i)
                    std::memcpy(polys[i].mCoeffs.data(), stage + i * polyBytes, polyBytes);
                return true;
            }
        }

        // Retain the original path if explicitly disabled or pinning fails.
        const bool got = buf.download(out, stream, 0, polys.size()) && out.size() == polys.size();
        if (!got) return false;
        completed = true;
        for (std::size_t i = 0; i < polys.size(); ++i) polys[i] = std::move(out[i]);
        return true;
    }

    bool gadgetDecomposeHost(
        const RingNttContext& ctx,
        const RnsPoly& in,
        u32 digitBits,
        u32 startLevel,
        u32 levels,
        bool centered,
        std::vector<RnsPoly>& out)
    {
        if (!enabled(ctx) || levels == 0) return false;
        auto ring = GpuRing::get(ctx);
        if (!ring) return false;

        // Secondary stream, for the same reason as nttHostBatch above: host in,
        // host out, nothing queued to order against.
        auto& stream = contextSampleStream(ctx);
        GpuPolyBuffer src;
        GpuPolyBuffer dst;
        bool ok = src.resize(*ring, 1, stream) && dst.resize(*ring, levels, stream) &&
                  src.upload(std::span<const RnsPoly>(&in, 1), stream) &&
                  launchGadgetDecompose(
                      ring->view(stream), src.data(stream), nullptr, 1, digitBits, startLevel, levels, centered,
                      dst.data(stream), nullptr, stream.raw());

        // download() queues the copies and synchronises.
        if (ok) ok = dst.download(out, stream, 0, levels) && out.size() == levels;
        return ok;
    }

    bool setupUniformSamplingEnabled(const LogVoleExecutionOptions& options, bool selectedGpu)
    {
        return options.mAdvanced.mProtocol.mUniformSampling && (options.mUseGpu && selectedGpu);
    }

    namespace
    {
        bool sampleUniformBatchOwner(const RingNttContext& ctx,
            std::span<const std::array<u64, 8>> seeds, bool outputNtt,
            bool synchronize, std::shared_ptr<RetainedPublicUniform>& out, ProtocolCacheScopeView scope)
        {
            HostStep totalStep(hostProfiler(ctx), "setup: uniform device total");
            if (!setupUniformSamplingEnabled(ctx.mExecutionOptions, enabled(ctx)) || seeds.empty() ||
                seeds.size() > std::numeric_limits<u32>::max()) return false;
            const bool decline = ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mUniform;
            if (decline) return false;
            auto ring = GpuRing::get(ctx);
            if (!ring || !ring->sampleMaxMultiple() ||
                ring->polyWords() > std::numeric_limits<u32>::max()) return false;
            const u32 count = static_cast<u32>(seeds.size());
            if (seeds.size() > std::numeric_limits<std::size_t>::max() /
                    (ring->polyWords() * sizeof(u64))) return false;

            auto& stream = contextSampleStream(ctx);
            // Setup uses the secondary stream. Its scratch must not alias the
            // online sampler or either prefetch sampler on another stream.
            auto& scratch = stream.protocolScratch().setup;
            GpuPolyBuffer sampled;
            struct DrainStream
            {
                GpuStream& stream;
                bool armed = true;
                ~DrainStream() { if (armed) stream.sync(); }
            } drainStream{ stream };

            if (!sampled.resize(*ring, count, stream) || !scratch.ensureSeeds(seeds.size() * 8u) ||
                !scratch.ensureRoundKeys(seeds.size() * 176u)) return false;
            u32* rejectEpochs = nullptr;
            u32 rejectEpoch = 0;
            if (!scratch.nextRejectEpoch(count, stream.raw(), rejectEpochs, rejectEpoch))
                return false;
            {
                HostStep launchStep(hostProfiler(ctx), "setup: uniform device sample and NTT");
                if (!gpuMemcpyH2D(scratch.mSeeds, seeds.data(), seeds.size_bytes(), stream.raw()) ||
                    !launchSampleUniformPolyAes(ring->view(stream), scratch.mSeeds,
                        ring->sampleMaxMultiple(), sampled.data(stream), nullptr, count,
                        scratch.mRoundKeys, scratch.mRoundKeyBytes, rejectEpochs, rejectEpoch, stream.raw()) ||
                    (outputNtt && !launchNttForward(
                        ring->view(stream), sampled.data(stream), count, nullptr, stream.raw()))) return false;
            }
            if (synchronize)
            {
                HostStep retainStep(hostProfiler(ctx), "setup: uniform device retain");
                if (!stream.sync()) return false;
            }

            auto next = std::make_shared<RetainedPublicUniform>();
            auto& value = *next->mImpl;
            value.mRing = ring;
            value.mParams = ctx.mParams;
            value.mSeeds.assign(seeds.begin(), seeds.end());
            value.mOutputNtt = outputNtt;
            value.mRole = scope.mRole;
            value.mRunId = scope.mRunId;
            value.mIdentityService = value.mRunId.serviceOwner();
            value.mDevice = currentDeviceOrdinal();
            value.mValues = std::move(sampled);
            out = std::move(next);
            // From here the completed retained owner (synchronized form), or
            // its immediate eager downloader, owns the queued work. Draining
            // remains necessary only on earlier failure exits.
            drainStream.armed = false;
            return true;
        }
    }

    bool retainUniformBatchFromSeedsDevice(
        const RingNttContext& ctx, std::span<const std::array<u64, 8>> seeds,
        bool outputNtt, RetainedPublicUniformPtr& out, ProtocolCacheScopeView scope)
    {
        if (!publicUniformRetentionEnabled(ctx.mExecutionOptions, enabled(ctx))) return false;
        const std::size_t polyWords = ringPolyCoeffCount(ctx.mParams);
        if (!polyWords || seeds.size() > publicRetentionByteLimit / sizeof(u64) / polyWords)
            return false;
        std::shared_ptr<RetainedPublicUniform> next;
        if (!sampleUniformBatchOwner(ctx, seeds, outputNtt, true, next, scope) ||
            next->mImpl->mValues.bytes() > publicRetentionByteLimit) return false;
        if (ctx.mPublicCache)
        {
            auto& counters = ctx.mPublicCache->mRetentionCounters;
            counters.mCaptures.fetch_add(1, std::memory_order_relaxed);
        }
        out = std::move(next);
        return true;
    }

    DeviceBatchPtr sampleRootSecretUniformToDevice(
        const RingNttContext& ctx,
        std::span<const std::array<u64, 8>> rowSeeds, ProtocolCacheScopeView scope)
    {
        const bool decline = ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mRootSkRRDevice;
        if (scope.mRole != ProtocolCacheRole::Sender ||
            (decline)) return {};
        std::shared_ptr<RetainedPublicUniform> privateSample;
        if (!sampleUniformBatchOwner(ctx, rowSeeds, false, true, privateSample, scope) ||
            !privateSample || privateSample->count() != rowSeeds.size()) return {};
        auto next = std::make_shared<DeviceBatch>();
        next->mImpl->mRing = privateSample->mImpl->mRing;
        next->mImpl->mBuf = std::move(privateSample->mImpl->mValues);
        next->mImpl->mRootSecretUniform = true;
        next->mImpl->mRootSecretNtt = false;
        next->mImpl->mRootSecretRole = scope.mRole;
        next->mImpl->mRootSecretRunId = scope.mRunId;
        next->mImpl->mIdentityService = (scope.mRunId).serviceOwner();
        next->mImpl->mRootSecretDevice = currentDeviceOrdinal();
        return next;
    }

    DeviceBatchPtr sampleTopSecretUniformToDevice(
        const RingNttContext& ctx,
        std::span<const std::array<u64, 8>> rowSeeds, ProtocolCacheScopeView scope)
    {
        const bool decline = ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mTopSk1Device;
        if (scope.mRole != ProtocolCacheRole::Sender || !scope.mRunId ||
            (decline)) return {};
        std::shared_ptr<RetainedPublicUniform> privateSample;
        if (!sampleUniformBatchOwner(ctx, rowSeeds, false, true, privateSample, scope) ||
            !privateSample || privateSample->count() != rowSeeds.size()) return {};
        auto next = std::make_shared<DeviceBatch>();
        next->mImpl->mRing = privateSample->mImpl->mRing;
        next->mImpl->mBuf = std::move(privateSample->mImpl->mValues);
        next->mImpl->mTopSecretUniform = true;
        next->mImpl->mRootSecretNtt = false;
        next->mImpl->mRootSecretRole = scope.mRole;
        next->mImpl->mRootSecretRunId = scope.mRunId;
        next->mImpl->mIdentityService = (scope.mRunId).serviceOwner();
        next->mImpl->mRootSecretDevice = currentDeviceOrdinal();
        return next;
    }

    bool sampleUniformBatchFromSeedsDevice(
        const RingNttContext& ctx,
        std::span<const std::array<u64, 8>> seeds,
        bool outputNtt,
        std::vector<RnsPoly>& out, ProtocolCacheScopeView scope)
    {
        return sampleUniformBatchFromSeedsDevice(ctx, seeds, outputNtt, out, nullptr, scope);
    }

    bool sampleUniformBatchFromSeedsDevice(
        const RingNttContext& ctx, std::span<const std::array<u64, 8>> seeds,
        bool outputNtt, std::vector<RnsPoly>& out, RetainedPublicUniformPtr* captured, ProtocolCacheScopeView scope)
    {
        std::shared_ptr<RetainedPublicUniform> retained;
        if (!sampleUniformBatchOwner(ctx, seeds, outputNtt, false, retained, scope)) return false;
        std::vector<RnsPoly> next;
        {
            HostStep downloadStep(hostProfiler(ctx), "setup: uniform device download");
            auto& stream = contextSampleStream(ctx);
            if (!retained->mImpl->mValues.download(next, stream, 0, retained->count()) ||
                next.size() != seeds.size()) return false;
        }
        const bool keep = captured && publicUniformRetentionEnabled(ctx.mExecutionOptions, enabled(ctx)) &&
            retained->mImpl->mValues.bytes() <= publicRetentionByteLimit;
        if (keep)
        {
            auto& value = *retained->mImpl;
            value.mHostData = next.data();
            value.mHostCoefficients.reserve(next.size());
            for (const auto& poly : next)
                value.mHostCoefficients.push_back(poly.mCoeffs.data());
            if (ctx.mPublicCache)
            {
                auto& counters = ctx.mPublicCache->mRetentionCounters;
                counters.mCaptures.fetch_add(1, std::memory_order_relaxed);
            }
        }
        out = std::move(next);
        if (captured)
            *captured = keep ? RetainedPublicUniformPtr(std::move(retained)) : RetainedPublicUniformPtr{};
        return true;
    }

    bool deriveUniformPolyBatchDevice(
        const RingNttContext& ctx,
        block seed,
        u64 domainTag,
        u32 count,
        std::vector<RnsPoly>& out)
    {
        if (!enabled(ctx) || count == 0) return false;
        auto ring = GpuRing::get(ctx);
        if (!ring || !ring->sampleMaxMultiple()) return false;

        auto& stream = contextStream(ctx);
        auto& scratch = sampleScratch(stream);
        if (!scratch.ensureSeeds(static_cast<std::size_t>(count) * 8) ||
            !scratch.ensureRoundKeys(static_cast<std::size_t>(count) * 176) ||
            !scratch.ensurePrefix()) return false;
        u32* rejectEpochs = nullptr;
        u32 rejectEpoch = 0;
        if (!scratch.nextRejectEpoch(count, stream.raw(), rejectEpochs, rejectEpoch)) return false;

        // scratch.mPrefix is 9 words, so it comfortably holds the 2-word seed.
        u64 seedWords[2];
        std::memcpy(seedWords, &seed, sizeof(seedWords));

        GpuPolyBuffer dst;
        bool ok = dst.resize(*ring, count, stream) &&
                  scratch.uploadPrefix(seedWords, 2u, stream.raw()) &&
                  launchPolySeeds(
                      scratch.mPrefix, 1, count, domainTag, ctx.mParams.mPolyModulusDegree,
                      static_cast<u64>(ctx.mParams.mCoeffModulusBits.size()), scratch.mSeeds,
                      scratch.mRoundKeys,
                      stream.raw()) &&
                  launchSampleUniformPolyAes(
                      ring->view(stream), scratch.mSeeds, ring->sampleMaxMultiple(), dst.data(stream), nullptr,
                      count, scratch.mRoundKeys, scratch.mRoundKeyBytes, rejectEpochs, rejectEpoch, stream.raw());

        if (ok) ok = dst.download(out, stream, 0, count);
        // Partial launch failures must drain before the output allocation dies.
        if (!stream.sync()) return false;
        return ok;
    }

    bool seedLabelRepDevice(const RingNttContext& ctx, std::span<const RnsPoly> input,
        u32 gamma, u32 alpha, u32 tau, std::vector<RnsPoly>& out)
    {
        const auto rho = ringModulusCount(ctx);
        const u64 alphaTau = static_cast<u64>(alpha) * tau;
        if (!rho || rho != ctx.mParams.mCoeffModulusBits.size() ||
            alphaTau > std::numeric_limits<u32>::max() / rho) return false;
        const u64 count = alphaTau * rho;
        const u64 words = static_cast<u64>(ctx.mParams.mPolyModulusDegree) * rho;
        if (!enabled(ctx) || !alpha || !tau || !rho || !words ||
            count > std::numeric_limits<u32>::max() ||
            count > (std::size_t(512) << 20) / sizeof(u64) / words ||
            (gamma != 1u && gamma != tau) || input.size() < (gamma == 1u ? 1u : tau)) return false;
        // The gamma-one CPU contract inspects only input[0]. Other modes
        // validate the complete supplied span, including unused tail entries.
        if (gamma == 1u ? !validateRingPolyShape(input[0], ctx.mParams)
                        : !validateRingBatchShape(input, ctx.mParams)) return false;
        HostStep step(hostProfiler(ctx), "setup: seed label repetition device");
        // This is a bitwise layout operation: constructing NTT/CRT tables here
        // would serialize their bootstrap before ordinary setup can prefetch it.
        RingConstView layout{};
        layout.mN = ctx.mParams.mPolyModulusDegree;
        layout.mRho = static_cast<u32>(rho);
        auto& stream = contextStream(ctx);
        GpuPolyBuffer source, result;
        std::vector<RnsPoly> next;
        StreamDrain drain{stream};
        const u32 sources = gamma == 1u ? 1u : tau;
        if (!source.resizeWords(words, sources, stream) || !result.resizeWords(words, count, stream) ||
            !source.upload(input.first(sources), stream) ||
            !launchSeedLabelRep(layout, source.data(stream), result.data(stream), tau,
                static_cast<u32>(count), gamma == 1u, stream.raw()) ||
            !result.download(next, stream) || !stream.sync()) return false;
        out = std::move(next);
        return true;
    }

    namespace
    {
        bool setupCoefficientBatchMatches(const RingNttContext& ctx,
            const DeviceBatch& source, std::size_t expectedCount,
            ProtocolCacheRunId ownerRunId, bool delta, bool rootHi, ProtocolCacheScopeView scope)
        {
            if (!enabled(ctx) || !source.mImpl || !source.mImpl->mRing ||
                !expectedCount || source.count() != expectedCount ||
                source.mImpl->mBuf.count() != expectedCount ||
                source.mImpl->mLogicalCount ||
                source.mImpl->mPlainBroadcastSingleLimb ||
                (rootHi ? !source.mImpl->mRootHiRepCoefficients
                        : delta ? !source.mImpl->mSetupDeltaCoefficients
                                : !source.mImpl->mSetupSeedLabelRepCoefficients) ||
                source.mImpl->mSetupSenderRole != ProtocolCacheRole::Sender ||
                scope.mRole != ProtocolCacheRole::Sender ||
                scope.mRunId != ownerRunId ||
                source.mImpl->mSetupSenderRunId != ownerRunId ||
                source.mImpl->mSetupSenderDevice != currentDeviceOrdinal() ||
                !validateRingContextMetadata(ctx) ||
                source.mImpl->mRing->n() != ctx.mParams.mPolyModulusDegree ||
                source.mImpl->mRing->rho() != ringModulusCount(ctx) ||
                source.mImpl->mBuf.polyWords() !=
                    source.mImpl->mRing->polyWords()) return false;
            const auto& ordered = source.mImpl->mRing->hostModuli();
            if (ordered.size() != ringModulusCount(ctx)) return false;
            for (std::size_t i = 0; i < ordered.size(); ++i)
                if (ordered[i] != ringModulusValue(ctx, i)) return false;
            return true;
        }
    }

    bool setupDeltaBatchMatches(const RingNttContext& ctx,
        const DeviceBatch& source, std::size_t expectedCount,
        ProtocolCacheRunId ownerRunId, ProtocolCacheScopeView scope)
    {
        return setupCoefficientBatchMatches(ctx, source, expectedCount,
            ownerRunId, true, false, scope);
    }

    bool setupSeedLabelRepBatchMatches(const RingNttContext& ctx,
        const DeviceBatch& source, std::size_t expectedCount,
        ProtocolCacheRunId ownerRunId, ProtocolCacheScopeView scope)
    {
        return setupCoefficientBatchMatches(ctx, source, expectedCount,
            ownerRunId, false, false, scope);
    }

    bool rootHiRepBatchMatches(const RingNttContext& ctx,
        const DeviceBatch& source, std::size_t expectedCount, ProtocolCacheRunId ownerRunId, ProtocolCacheScopeView scope)
    {
        return setupCoefficientBatchMatches(ctx, source, expectedCount,
            ownerRunId, false, true, scope);
    }

    bool setupLencInputBatchMatches(const RingNttContext& ctx,
        const DeviceBatch& source, std::size_t expectedCount, ProtocolCacheRunId ownerRunId, ProtocolCacheScopeView scope)
    {
        return setupSeedLabelRepBatchMatches(ctx, source, expectedCount,
            ownerRunId, scope) || rootHiRepBatchMatches(ctx, source, expectedCount,
            ownerRunId, scope);
    }

    DeviceBatchPtr seedLabelRepResident(const RingNttContext& ctx,
        const DeviceBatch& delta, u32 gamma, u32 alpha, u32 tau, ProtocolCacheScopeView scope)
    {
        const auto ownerRunId = scope.mRunId;
        const auto rho = ringModulusCount(ctx);
        const u64 count = static_cast<u64>(alpha) * tau * rho;
        if (gamma != 1u || !alpha || !tau || !rho ||
            !setupDeltaBatchMatches(ctx, delta, 1u, ownerRunId, scope) ||
            count > std::numeric_limits<u32>::max() ||
            !delta.mImpl->mRing ||
            delta.mImpl->mRing->polyWords() == 0 ||
            count > (std::size_t{512} << 20) /
                delta.mImpl->mRing->polyBytes()) return {};
        HostStep step(hostProfiler(ctx), "setup sender: resident seed-label repetition");
        RingConstView layout{};
        layout.mN = ctx.mParams.mPolyModulusDegree;
        layout.mRho = static_cast<u32>(rho);
        auto& stream = contextStream(ctx);
        GpuPolyBuffer result;
        if (!result.resizeWords(delta.mImpl->mRing->polyWords(), count, stream) ||
            !launchSeedLabelRep(layout, delta.mImpl->mBuf.data(stream),
                result.data(stream), tau, static_cast<u32>(count), true,
                stream.raw()) || !stream.sync()) return {};
        auto owner = std::make_shared<DeviceBatch>();
        owner->mImpl->mRing = delta.mImpl->mRing;
        owner->mImpl->mBuf = std::move(result);
        owner->mImpl->mSetupSeedLabelRepCoefficients = true;
        owner->mImpl->mSetupSenderRole = ProtocolCacheRole::Sender;
        owner->mImpl->mSetupSenderRunId = ownerRunId;
        owner->mImpl->mIdentityService = (ownerRunId).serviceOwner();
        owner->mImpl->mSetupSenderDevice = currentDeviceOrdinal();
        return owner;
    }

    DeviceBatchPtr topSecretSeedLabelRepResident(const RingNttContext& ctx,
        const DeviceBatch& topSecret, u32 alpha, u32 tau, ProtocolCacheScopeView scope)
    {
        const ProtocolCacheRunId runId = scope.mRunId;
        const auto rho = ringModulusCount(ctx);
        const u64 count = static_cast<u64>(alpha) * tau * rho;
        if (!alpha || !tau || !rho || !runId ||
            !topSecretUniformBatchMatches(ctx, topSecret, tau, runId, scope) ||
            count > std::numeric_limits<u32>::max() ||
            !topSecret.mImpl->mRing ||
            count > (std::size_t{512} << 20) /
                topSecret.mImpl->mRing->polyBytes()) return {};
        HostStep step(hostProfiler(ctx), "setup sender: resident top-key seed-label repetition");
        RingConstView layout{};
        layout.mN = ctx.mParams.mPolyModulusDegree;
        layout.mRho = static_cast<u32>(rho);
        auto& stream = contextStream(ctx);
        GpuPolyBuffer result;
        if (!result.resizeWords(topSecret.mImpl->mRing->polyWords(), count, stream) ||
            !launchSeedLabelRep(layout, topSecret.mImpl->mBuf.data(stream),
                result.data(stream), tau, static_cast<u32>(count), tau == 1u,
                stream.raw()) || !stream.sync())
        {
            // A launched kernel may still refer to result on a failed sync.
            (void)stream.sync();
            return {};
        }
        auto owner = std::make_shared<DeviceBatch>();
        owner->mImpl->mRing = topSecret.mImpl->mRing;
        owner->mImpl->mBuf = std::move(result);
        owner->mImpl->mSetupSeedLabelRepCoefficients = true;
        owner->mImpl->mTopSeedLabelRepCoefficients = true;
        owner->mImpl->mSetupSenderRole = ProtocolCacheRole::Sender;
        owner->mImpl->mSetupSenderRunId = runId;
        owner->mImpl->mIdentityService = (runId).serviceOwner();
        owner->mImpl->mSetupSenderDevice = currentDeviceOrdinal();
        return owner;
    }

    DeviceBatchPtr rootHiReplicateResident(const RingNttContext& ctx,
        const DeviceBatch& topSecret, u32 tauHi, ProtocolCacheScopeView scope)
    {
        const ProtocolCacheRunId runId = scope.mRunId;
        const auto rho = ringModulusCount(ctx);
        const u64 count = static_cast<u64>(tauHi) * rho;
        if (!tauHi || !rho || !runId ||
            !topSecretUniformBatchMatches(ctx, topSecret, tauHi, runId, scope) ||
            count > std::numeric_limits<u32>::max() ||
            !topSecret.mImpl->mRing ||
            count > (std::size_t{512} << 20) /
                topSecret.mImpl->mRing->polyBytes()) return {};
        HostStep step(hostProfiler(ctx), "setup sender: resident Root high-key replication");
        auto& stream = contextStream(ctx);
        const std::size_t bytes = topSecret.mImpl->mRing->polyBytes();
        GpuPolyBuffer result;
        if (!result.resizeWords(topSecret.mImpl->mRing->polyWords(), count, stream)) return {};
        bool queued = false;
        for (u32 digit = 0; digit < tauHi; ++digit)
        {
            for (std::size_t limb = 0; limb < rho; ++limb)
            {
                const std::size_t row = static_cast<std::size_t>(digit) * rho + limb;
                if (!gpuMemcpyD2D(result.data(stream) + row * topSecret.mImpl->mRing->polyWords(),
                    topSecret.mImpl->mBuf.data(stream) + static_cast<std::size_t>(digit) *
                        topSecret.mImpl->mRing->polyWords(), bytes, stream.raw()))
                {
                    if (queued) (void)stream.sync();
                    return {};
                }
                queued = true;
            }
        }
        if (!stream.sync()) { (void)stream.sync(); return {}; }
        auto owner = std::make_shared<DeviceBatch>();
        owner->mImpl->mRing = topSecret.mImpl->mRing;
        owner->mImpl->mBuf = std::move(result);
        owner->mImpl->mRootHiRepCoefficients = true;
        owner->mImpl->mSetupSenderRole = ProtocolCacheRole::Sender;
        owner->mImpl->mSetupSenderRunId = runId;
        owner->mImpl->mIdentityService = (runId).serviceOwner();
        owner->mImpl->mSetupSenderDevice = currentDeviceOrdinal();
        return owner;
    }

    bool fetchScalars(const DeviceScalars& src, std::span<u64> dst, GpuStream& stream)
    {
        if (src.empty() || dst.size() < src.count()) return false;
        if (!src.prepareUse(stream)) return false;
        StreamDrain drain{stream};
        const bool copied = gpuMemcpyD2H(dst.data(), src.data(), src.count() * sizeof(u64), stream.raw());
        const bool synced = drain.sync();
        const bool ok = copied && synced;
        if (ok) src.markReady();
        return ok;
    }

    bool waitScalars(DeviceScalars& src)
    {
        if (src.empty()) return false;
        if (auto* ps = src.producerStream())
        {
            if (!gpuStreamSync(ps)) return false;
            // The owner still retains the stream. A completed dependency needs
            // no additional wait when this result moves to its next consumer.
            src.markReady();
        }
        return true;
    }

    std::size_t DeviceBatch::count() const
    {
        if (!mImpl) return 0;
        return mImpl->mLogicalCount ? mImpl->mLogicalCount : mImpl->mBuf.count();
    }

    bool DeviceBatch::empty() const
    {
        return count() == 0;
    }

    static bool ensurePlainBroadcastMaterialized(
        DeviceBatch::Impl& impl, GpuStream& stream)
    {
        if (!impl.mPlainBroadcastSingleLimb) return true;
        if (!impl.mRing || impl.mBuf.empty() ||
            impl.mBuf.count() > std::numeric_limits<u32>::max())
            return false;
        if (!launchMaterializePlainBroadcast(
                impl.mRing->view(stream), impl.mBuf.data(stream),
                static_cast<u32>(impl.mBuf.count()),
                stream.raw()))
            return false;
        // The queued broadcast precedes every subsequent consumer on this
        // stream, so the ordinary full-RNS logical representation is restored.
        impl.mPlainBroadcastSingleLimb = false;
        return true;
    }

    bool download(const DeviceBatch& batch, std::vector<RnsPoly>& out,
        GpuStream& stream, std::size_t count)
    {
        if (!batch.mImpl || batch.count() == 0) return false;
        // The compact recursive representation is intentionally device-only;
        // downloading it as if physical and logical counts matched would read
        // past the allocation and would not reconstruct the CRT-lifted values.
        if (batch.mImpl->mLogicalCount &&
            batch.mImpl->mLogicalCount != batch.mImpl->mBuf.count())
            return false;
        if (!ensurePlainBroadcastMaterialized(*batch.mImpl, stream)) return false;
        Region regDown(GpuStream::RegionKind::Download, stream);
        return batch.mImpl->mBuf.download(out, stream, 0, count ? count : batch.count());
    }

    DeviceBatchPtr upload(const RingNttContext& ctx, std::span<const RnsPoly> polys)
    {
        if (!enabled(ctx) || polys.empty()) return nullptr;
        auto ring = GpuRing::get(ctx);
        if (!ring) return nullptr;
        auto batch = std::make_shared<DeviceBatch>();
        batch->mImpl->mRing = ring;
        auto& stream = contextStream(ctx);
        Region regUp(GpuStream::RegionKind::Upload, stream);
        if (!batch->mImpl->mBuf.resize(*ring, polys.size(), stream) ||
            !batch->mImpl->mBuf.upload(polys, stream))
        {
            return nullptr;
        }
        return batch;
    }

    static bool expandErrorCompactImpl(const RingNttContext& ctx,
        std::span<const u64> compactLimb0, const DeviceScalars* deviceCompact,
        u32 requestedCount, bool outputNtt, std::vector<RnsPoly>* out,
        DeviceBatchPtr* residentOut, u32 requestedWorkers, CpuBenchmarkState cpuBenchmark, ProtocolCacheScopeView scope)
    {
        if (!cpuBenchmark.mContext) cpuBenchmark.mContext = cpuBenchmarkContext(ctx);
        if (!enabled(ctx) || !ringModulusCount(ctx)) return false;
        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        const auto words = deviceCompact ? deviceCompact->count() : compactLimb0.size();
        if (!n || !words || words % n || words / n > std::numeric_limits<u32>::max() ||
            (deviceCompact && (!compactLimb0.empty() || deviceCompact->producerStream())) ||
            requestedCount > words / n) return false;
        HostStep totalStep(hostProfiler(ctx), "setup: compact GPU expansion", &cpuBenchmark);
        const u32 count = requestedCount ? requestedCount : static_cast<u32>(words / n);
        auto ring = GpuRing::get(ctx);
        constexpr std::size_t maxBytes = std::size_t{512} << 20;
        if (!ring || ring->rho() != ringModulusCount(ctx) || !ring->polyWords() ||
            ring->polyWords() > maxBytes / sizeof(u64) ||
            count > maxBytes / (ring->polyWords() * sizeof(u64))) return false;
        auto& stream = contextSampleStream(ctx);
        GpuPolyBuffer samples;
        OwnedGpuBuffer selectors, scales, denseInput;
        std::vector<u32> limbs;
        std::vector<u64> ones;
        std::vector<RnsPoly> next;
        StreamDrain drain{stream};
        if (!samples.resize(*ring, count, stream)) return false;
        if (ctx.mExecutionOptions.mAdvanced.mProtocol.mCompactExpandDirect)
        {
            HostStep directStep(hostProfiler(ctx), "setup: direct compact GPU expansion", &cpuBenchmark);
            const u64* source = deviceCompact ? deviceCompact->data() : nullptr;
            if (deviceCompact && !source) return false;
            if (!source)
            {
                const std::size_t bytes = static_cast<std::size_t>(count) * n * sizeof(u64);
                denseInput = tryAllocateGpuBuffer(stream, bytes);
                if (!denseInput || !gpuMemcpyH2D(denseInput.data(), compactLimb0.data(), bytes, stream.raw()))
                    return false;
                source = static_cast<const u64*>(denseInput.data());
            }
            if (!launchExpandCenteredCompact(ring->view(stream), source, samples.data(stream), count, stream.raw()))
                return false;
        }
        else
        {
            limbs.assign(count, 0);
            ones.assign(ring->rho(), 1);
            selectors = tryAllocateGpuBuffer(stream, limbs.size() * sizeof(u32));
            scales = tryAllocateGpuBuffer(stream, ones.size() * sizeof(u64));
            if (!selectors || !scales || !(deviceCompact
                ? copyRowsFromDevice(samples.data(stream), ring->polyWords() * sizeof(u64),
                    deviceCompact->data(), n * sizeof(u64), count, stream)
                : uploadRowsFromHost(samples.data(stream), ring->polyWords() * sizeof(u64),
                    compactLimb0.data(), n * sizeof(u64), count, stream)) ||
                !gpuMemcpyH2D(selectors.data(), limbs.data(), limbs.size() * sizeof(u32), stream.raw()) ||
                !gpuMemcpyH2D(scales.data(), ones.data(), ones.size() * sizeof(u64), stream.raw()) ||
                !launchLiftCenteredLimb(ring->view(stream), samples.data(stream), nullptr,
                    static_cast<const u32*>(selectors.data()), static_cast<const u64*>(scales.data()),
                    samples.data(stream), nullptr, count, stream.raw())) return false;
        }
        if (outputNtt && !launchNttForward(ring->view(stream), samples.data(stream), count, nullptr, stream.raw()))
            return false;
        if (residentOut)
        {
            // A coroutine may resume either consumer on a different host
            // thread. Publish a completed immutable owner rather than a
            // thread-stream dependency whose lifetime can be lost.
            if (outputNtt || !stream.sync()) return false;
            auto batch = std::make_shared<DeviceBatch>();
            batch->mImpl->mRing = std::move(ring);
            batch->mImpl->mBuf = std::move(samples);
            batch->mImpl->mRootErrorCoefficients = true;
            batch->mImpl->mRootErrorRole = scope.mRole;
            batch->mImpl->mRootErrorRunId = scope.mRunId;
            batch->mImpl->mIdentityService = scope.mRunId.serviceOwner();
            batch->mImpl->mRootErrorDevice = currentDeviceOrdinal();
            *residentOut = std::move(batch);
            return true;
        }
        const bool pipelineRequested = ctx.mExecutionOptions.mAdvanced.mProtocol.mCompactPipelinedDownload && count >= 4;
        if (!(pipelineRequested
                ? samples.downloadPipelined(next, stream, requestedWorkers, ctx.mGpuExecution->transferCpuScratch(), 0, 0, cpuBenchmark)
                : samples.download(next, stream)) || next.size() != count) return false;
        if (!out) return false;
        *out = std::move(next);
        return true;
    }

    bool expandErrorCompactDevice(const RingNttContext& ctx,
        std::span<const u64> compactLimb0, bool outputNtt, std::vector<RnsPoly>& out, CpuBenchmarkState cpuBenchmark)
    {
        if (!cpuBenchmark.mContext) cpuBenchmark.mContext = cpuBenchmarkContext(ctx);
        return expandErrorCompactDevice(ctx, compactLimb0, outputNtt, out, 1, cpuBenchmark);
    }

    bool expandErrorCompactDevice(const RingNttContext& ctx,
        std::span<const u64> compactLimb0, bool outputNtt, std::vector<RnsPoly>& out,
        u32 requestedWorkers, CpuBenchmarkState cpuBenchmark)
    {
        if (!cpuBenchmark.mContext) cpuBenchmark.mContext = cpuBenchmarkContext(ctx);
        return expandErrorCompactImpl(ctx, compactLimb0, nullptr, 0, outputNtt, &out, nullptr, requestedWorkers, cpuBenchmark, {});
    }

    bool expandErrorCompactDevice(const RingNttContext& ctx,
        const DeviceScalars& compactLimb0, bool outputNtt, std::vector<RnsPoly>& out, u32 polyCount, CpuBenchmarkState cpuBenchmark)
    {
        if (!cpuBenchmark.mContext) cpuBenchmark.mContext = cpuBenchmarkContext(ctx);
        return expandErrorCompactDevice(ctx, compactLimb0, outputNtt, out, polyCount, 1, cpuBenchmark);
    }

    bool expandErrorCompactDevice(const RingNttContext& ctx,
        const DeviceScalars& compactLimb0, bool outputNtt, std::vector<RnsPoly>& out,
        u32 polyCount, u32 requestedWorkers, CpuBenchmarkState cpuBenchmark)
    {
        if (!cpuBenchmark.mContext) cpuBenchmark.mContext = cpuBenchmarkContext(ctx);
        return expandErrorCompactImpl(ctx, {}, &compactLimb0, polyCount, outputNtt, &out, nullptr, requestedWorkers, cpuBenchmark, {});
    }

    bool expandRootErrorCompactDevice(const RingNttContext& ctx,
        std::span<const u64> compactLimb0, bool outputNtt, std::vector<RnsPoly>& out, CpuBenchmarkState cpuBenchmark)
    {
        if (!cpuBenchmark.mContext) cpuBenchmark.mContext = cpuBenchmarkContext(ctx);
        return expandRootErrorCompactDevice(ctx, compactLimb0, outputNtt, out, 1, cpuBenchmark);
    }

    bool expandRootErrorCompactDevice(const RingNttContext& ctx,
        std::span<const u64> compactLimb0, bool outputNtt, std::vector<RnsPoly>& out,
        u32 requestedWorkers, CpuBenchmarkState cpuBenchmark)
    {
        if (!cpuBenchmark.mContext) cpuBenchmark.mContext = cpuBenchmarkContext(ctx);
        const bool decline = ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mRootCompactNoise;
        if (decline) return false;
        return expandErrorCompactDevice(ctx, compactLimb0, outputNtt, out, requestedWorkers, cpuBenchmark);
    }

    DeviceBatchPtr expandRootErrorCompactToBatch(const RingNttContext& ctx,
        std::span<const u64> compactLimb0, const DeviceScalars* deviceCompact,
        u32 polyCount, CpuBenchmarkState cpuBenchmark, ProtocolCacheScopeView scope)
    {
        if (!cpuBenchmark.mContext) cpuBenchmark.mContext = cpuBenchmarkContext(ctx);
        const bool decline = ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mRootR1Device;
        const bool compactDecline = ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mRootCompactNoise;
        if ((decline) ||
            (compactDecline) ||
            scope.mRole != ProtocolCacheRole::Sender) return {};
        DeviceBatchPtr out;
        if (!expandErrorCompactImpl(ctx, compactLimb0, deviceCompact, polyCount,
                false, nullptr, &out, 1, cpuBenchmark, scope) ||
            !out || !rootErrorBatchMatches(ctx, *out, polyCount, scope)) return {};
        return out;
    }

    bool rootErrorBatchMatches(const RingNttContext& ctx,
        const DeviceBatch& source, std::size_t expectedCount, ProtocolCacheScopeView scope)
    {
        if (!enabled(ctx) || !source.mImpl || !source.mImpl->mRing || !expectedCount ||
            !source.mImpl->mRootErrorCoefficients ||
            source.mImpl->mLogicalCount || source.mImpl->mBuf.count() != expectedCount ||
            source.mImpl->mRootErrorRole != ProtocolCacheRole::Sender ||
            source.mImpl->mRootErrorRole != scope.mRole ||
            source.mImpl->mRootErrorRunId != scope.mRunId ||
            source.mImpl->mRootErrorDevice != currentDeviceOrdinal()) return false;
        if (!validateRingContextMetadata(ctx) ||
            ringModulusCount(ctx) != source.mImpl->mRing->rho()) return false;
        const auto& sourcePrimes = source.mImpl->mRing->hostModuli();
        for (std::size_t limb = 0; limb < sourcePrimes.size(); ++limb)
            if (ringModulusValue(ctx, limb) != sourcePrimes[limb]) return false;
        const auto ring = GpuRing::get(ctx);
        // Legacy SEAL and GPU-lightweight contexts can build separate role-
        // local GpuRing objects for the same mathematical ring. Coefficient
        // rows are compatible only when their exact ordered primes and physical
        // layout agree; pointer equality alone would reject a correct eager
        // API consumer of the transport token.
        return ring && source.mImpl->mRing &&
            source.mImpl->mRing->n() == ring->n() &&
            source.mImpl->mRing->rho() == ring->rho() &&
            source.mImpl->mRing->hostModuli() == ring->hostModuli() &&
            source.mImpl->mBuf.polyWords() == ring->polyWords();
    }

    static bool privateSecretUniformBatchMatches(const RingNttContext& ctx,
        const DeviceBatch& source, std::size_t expectedCount,
        ProtocolCacheRunId ownerRunId, bool outputNtt, bool topSecret, ProtocolCacheScopeView scope)
    {
        if (!enabled(ctx) || !source.mImpl || !source.mImpl->mRing || !expectedCount ||
            (topSecret ? !source.mImpl->mTopSecretUniform
                       : !source.mImpl->mRootSecretUniform) ||
            source.mImpl->mRootSecretNtt != outputNtt ||
            source.mImpl->mLogicalCount ||
            source.mImpl->mBuf.count() != expectedCount ||
            source.mImpl->mRootSecretRole != ProtocolCacheRole::Sender ||
            scope.mRole != ProtocolCacheRole::Sender ||
            (topSecret && (!ownerRunId || scope.mRunId != ownerRunId)) ||
            source.mImpl->mRootSecretRunId != ownerRunId ||
            source.mImpl->mRootSecretDevice != currentDeviceOrdinal() ||
            !validateRingContextMetadata(ctx) ||
            ringModulusCount(ctx) != source.mImpl->mRing->rho()) return false;
        const auto& sourcePrimes = source.mImpl->mRing->hostModuli();
        for (std::size_t limb = 0; limb < sourcePrimes.size(); ++limb)
            if (ringModulusValue(ctx, limb) != sourcePrimes[limb]) return false;
        const auto ring = GpuRing::get(ctx);
        return ring && source.mImpl->mRing->n() == ring->n() &&
            source.mImpl->mRing->rho() == ring->rho() &&
            source.mImpl->mRing->hostModuli() == ring->hostModuli() &&
            source.mImpl->mBuf.polyWords() == ring->polyWords();
    }

    bool rootSecretUniformBatchMatches(const RingNttContext& ctx,
        const DeviceBatch& source, std::size_t expectedCount,
        ProtocolCacheRunId ownerRunId, bool outputNtt, ProtocolCacheScopeView scope)
    {
        return privateSecretUniformBatchMatches(ctx, source, expectedCount,
            ownerRunId, outputNtt, false, scope);
    }

    bool topSecretUniformBatchMatches(const RingNttContext& ctx,
        const DeviceBatch& source, std::size_t expectedCount, ProtocolCacheRunId ownerRunId, ProtocolCacheScopeView scope)
    {
        return privateSecretUniformBatchMatches(ctx, source, expectedCount,
            ownerRunId, false, true, scope);
    }

    bool assembleRootTopCtDevice(
        const RingNttContext& ctx, std::span<const RnsPoly> r1Coeffs,
        std::span<const RnsPoly> r2Ntt, std::span<const RnsPoly> publicBRootNtt,
        std::span<const RnsPoly> publicBStarNtt, u32 gadgetLogBase, u32 gadgetPowerOffset,
        std::span<const RnsPoly> noiseCoeffs, std::vector<RnsPoly>& outCtNtt,
        std::span<const u64> compactNoiseLimb0, CpuBenchmarkState cpuBenchmark, ProtocolCacheScopeView scope)
    {
        if (!cpuBenchmark.mContext) cpuBenchmark.mContext = cpuBenchmarkContext(ctx);
        return assembleRootTopCtDevice(ctx, r1Coeffs, r2Ntt, publicBRootNtt, publicBStarNtt,
            gadgetLogBase, gadgetPowerOffset, noiseCoeffs, outCtNtt, compactNoiseLimb0, nullptr, cpuBenchmark, scope);
    }

    bool assembleRootTopCtDevice(
        const RingNttContext& ctx, std::span<const RnsPoly> r1Coeffs,
        std::span<const RnsPoly> r2Ntt, std::span<const RnsPoly> publicBRootNtt,
        std::span<const RnsPoly> publicBStarNtt, u32 gadgetLogBase, u32 gadgetPowerOffset,
        std::span<const RnsPoly> noiseCoeffs, std::vector<RnsPoly>& outCtNtt,
        std::span<const u64> compactNoiseLimb0, const DeviceScalars* compactNoiseDevice, CpuBenchmarkState cpuBenchmark, ProtocolCacheScopeView scope)
    {
        if (!cpuBenchmark.mContext) cpuBenchmark.mContext = cpuBenchmarkContext(ctx);
        return assembleRootTopCtDevice(ctx, r1Coeffs, r2Ntt, publicBRootNtt, publicBStarNtt,
            gadgetLogBase, gadgetPowerOffset, noiseCoeffs, outCtNtt, compactNoiseLimb0,
            compactNoiseDevice, 1, nullptr, nullptr, nullptr, nullptr, nullptr, cpuBenchmark, scope);
    }

    bool assembleRootTopCtDevice(
        const RingNttContext& ctx,
        std::span<const RnsPoly> r1Coeffs,
        std::span<const RnsPoly> r2Ntt,
        std::span<const RnsPoly> publicBRootNtt,
        std::span<const RnsPoly> publicBStarNtt,
        u32 gadgetLogBase, u32 gadgetPowerOffset,
        std::span<const RnsPoly> noiseCoeffs,
        std::vector<RnsPoly>& outCtNtt,
        std::span<const u64> compactNoiseLimb0,
        const DeviceScalars* compactNoiseDevice,
        u32 requestedWorkers,
        const LazyLencRandomizerState* randomizers,
        std::shared_ptr<const LazyRingTensorHostState>* deferredCiphertext,
        const RetainedPublicUniform* retainedPublicBFullNtt,
        const DeviceBatch* rootR1Device,
        const RetainedPublicUniform* retainedBStarNtt, CpuBenchmarkState cpuBenchmark, ProtocolCacheScopeView scope)
    {
        if (!cpuBenchmark.mContext) cpuBenchmark.mContext = cpuBenchmarkContext(ctx);
        const auto* retainedR = randomizers ? lencRandomizerDeviceNtt(ctx, randomizers, scope) : nullptr;
        if (randomizers && (!retainedR || !r2Ntt.empty())) return false;
        const bool compactNoise = !compactNoiseLimb0.empty() || compactNoiseDevice;
        if (compactNoiseDevice && (!compactNoiseLimb0.empty() || compactNoiseDevice->producerStream())) return false;
        const bool decline = ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mRootDevice;
        const bool compactDecline = ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mRootCompactNoise;
        if ((decline) ||
            (compactNoise && compactDecline)) return false;
        if (publicBRootNtt.size() > std::numeric_limits<u32>::max()) return false;
        u32 tauHi = static_cast<u32>(publicBRootNtt.size());
        if (retainedPublicBFullNtt)
        {
            const std::size_t fullCount = retainedPublicBFullNtt->count();
            if (!publicBRootNtt.empty() || fullCount < 4u || (fullCount & 1u) != 0 ||
                fullCount / 2u - 1u >= std::numeric_limits<u32>::max() ||
                !retainedPublicUniformMatches(ctx, *retainedPublicBFullNtt,
                    fullCount, true, scope)) return false;
            tauHi = static_cast<u32>(fullCount / 2u - 1u);
        }
        const auto r1Count = rootR1Device ? rootR1Device->count() : r1Coeffs.size();
        const auto bStarCount = retainedBStarNtt
            ? retainedBStarNtt->count() : publicBStarNtt.size();
        if (!enabled(ctx) || !r1Count || tauHi == 0 || bStarCount == 0 ||
            r1Count > std::numeric_limits<u32>::max() / 2u ||
            bStarCount > std::numeric_limits<u32>::max() - tauHi ||
            (retainedR ? retainedR->count() : r2Ntt.size()) != r1Count ||
            (retainedBStarNtt && (!publicBStarNtt.empty() ||
                !retainedRootBStarNttMatches(ctx, *retainedBStarNtt,
                    bStarCount, scope))) ||
            (rootR1Device && (!r1Coeffs.empty() ||
                !rootErrorBatchMatches(ctx, *rootR1Device, r1Count, scope)))) return false;
        HostStep totalStep(hostProfiler(ctx), "setup: root device assembly", &cpuBenchmark);
        const u32 rows = static_cast<u32>(r1Count);
        const u32 cols = static_cast<u32>(tauHi + bStarCount);
        const u64 count64 = static_cast<u64>(rows) * cols;
        if (count64 > std::numeric_limits<u32>::max() || noiseCoeffs.size() != count64 ||
            (!rootR1Device && !validateRingBatchShape(r1Coeffs, ctx.mParams)) ||
            (!retainedR && !validateRingBatchShape(r2Ntt, ctx.mParams)) ||
            (!retainedPublicBFullNtt && !validateRingBatchShape(publicBRootNtt, ctx.mParams)) ||
            (!retainedBStarNtt &&
                !validateRingBatchShape(publicBStarNtt, ctx.mParams)) ||
            (!compactNoise && !validateRingBatchShape(noiseCoeffs, ctx.mParams))) return false;
        auto ring = GpuRing::get(ctx);
        if (!ring || ring->rho() != ringModulusCount(ctx) ||
            ring->polyWords() > std::numeric_limits<std::size_t>::max() / sizeof(u64)) return false;
        const auto polyBytes = ring->polyWords() * sizeof(u64);
        if (!polyBytes || count64 > std::numeric_limits<std::size_t>::max() / polyBytes) return false;
        const u32 count = static_cast<u32>(count64);
        const u32 rho = ring->rho();
        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        if (compactNoise && (!n || count64 > std::numeric_limits<std::size_t>::max() / n ||
                (compactNoiseDevice ? compactNoiseDevice->count() : compactNoiseLimb0.size()) != count64 * n ||
                count64 > (std::size_t{512} << 20) / polyBytes)) return false;

        // Two gather arrays for the Cartesian product, followed by one output
        // index list per scaled root column. All output indices are unique
        // within a launch; later column launches run in the same stream.
        const u64 limbOffset = u64{2} * count + static_cast<u64>(tauHi) * rows;
        const u64 indexCount64 = limbOffset + (compactNoise ? count : 0u);
        if (indexCount64 > std::numeric_limits<std::size_t>::max() / sizeof(u32) ||
            static_cast<u64>(tauHi) * rho > std::numeric_limits<std::size_t>::max() / sizeof(u64)) return false;
        std::vector<u32> indices(static_cast<std::size_t>(indexCount64));
        for (u32 row = 0; row < rows; ++row)
            for (u32 col = 0; col < cols; ++col)
            {
                const u32 output = row * cols + col;
                indices[output] = row;
                indices[static_cast<std::size_t>(count) + output] = col;
                if (col < tauHi)
                    indices[std::size_t{2} * count + static_cast<std::size_t>(col) * rows + row] = output;
            }
        std::vector<const u64*> factors(tauHi);
        for (u32 col = 0; col < tauHi; ++col)
        {
            const u32 power = gadgetPowerOffset + col;
            const u64 bits = static_cast<u64>(gadgetLogBase) * power;
            if (bits > std::numeric_limits<u32>::max() ||
                !(factors[col] = ring->pow2Factors(static_cast<u32>(bits)))) return false;
        }

        auto& stream = contextSampleStream(ctx);
        GpuPolyBuffer rBuffer, bBuffer, ctBuffer, scaledBuffer, compactNoiseSource;
        OwnedGpuBuffer deviceIndices;
        std::vector<RnsPoly> next;
        // Drain before destroying metadata, pageable download destinations, or
        // device allocations on any launch/copy failure.
        struct DrainStream
        {
            GpuStream& stream;
            ~DrainStream() { stream.sync(); }
        } drainStream{ stream };
        {
            HostStep uploadStep(hostProfiler(ctx), "setup: root device upload", &cpuBenchmark);
            if (!rBuffer.resize(*ring, 2u * rows, stream) || !bBuffer.resize(*ring, cols, stream) ||
                !ctBuffer.resize(*ring, count, stream) || !scaledBuffer.resize(*ring, rows, stream) ||
                !(rootR1Device
                    ? gpuMemcpyD2D(rBuffer.data(stream), rootR1Device->mImpl->mBuf.data(stream),
                        static_cast<std::size_t>(rows) * polyBytes, stream.raw())
                    : rBuffer.upload(r1Coeffs, stream)) ||
                !(retainedR ? gpuMemcpyD2D(rBuffer.poly(rows, stream), retainedR->data(stream), retainedR->bytes(), stream.raw())
                            : rBuffer.upload(r2Ntt, stream, rows)) ||
                !(retainedPublicBFullNtt
                    ? copyRetainedPublicUniform(ctx, bBuffer, *retainedPublicBFullNtt,
                        1u, tauHi, true, stream, scope)
                    : bBuffer.upload(publicBRootNtt, stream)) ||
                !(retainedBStarNtt
                    ? ([&] {
                        HostStep copyStep(hostProfiler(ctx), "setup root: BStar retained D2D", &cpuBenchmark);
                        std::lock_guard use(retainedBStarNtt->mImpl->mDeviceUseMutex);
                        const std::size_t bytes = bStarCount * polyBytes;
                        const bool queued = gpuMemcpyD2D(
                            bBuffer.poly(tauHi, stream),
                            retainedBStarNtt->mImpl->mValues.data(stream),
                            bytes, stream.raw());
                        const bool completed = stream.sync();
                        return queued && completed;
                    })()
                    : bBuffer.upload(publicBStarNtt, stream, tauHi))) return false;
            if (compactNoise)
            {
                if (!compactNoiseSource.resize(*ring, count, stream) ||
                    !(compactNoiseDevice
                        ? copyRowsFromDevice(compactNoiseSource.data(stream), polyBytes, compactNoiseDevice->data(), n * sizeof(u64), count, stream)
                        : uploadRowsFromHost(compactNoiseSource.data(stream), polyBytes, compactNoiseLimb0.data(), n * sizeof(u64), count, stream))) return false;
            }
            else if (!ctBuffer.upload(noiseCoeffs, stream)) return false;
            deviceIndices = tryAllocateGpuBuffer(stream, indices.size() * sizeof(u32));
            if (!deviceIndices ||
                !gpuMemcpyH2D(deviceIndices.data(), indices.data(), indices.size() * sizeof(u32), stream.raw())) return false;
        }
        const auto* idx = static_cast<const u32*>(deviceIndices.data());
        {
            HostStep kernelStep(hostProfiler(ctx), "setup: root device launches", &cpuBenchmark);
            if (!launchCanonicalize(ring->view(stream), rBuffer.data(stream), nullptr, 2u * rows, stream.raw()) ||
                !launchCanonicalize(ring->view(stream), bBuffer.data(stream), nullptr, cols, stream.raw()) ||
                !launchNttForward(ring->view(stream), rBuffer.data(stream), rows, nullptr, stream.raw())) return false;
            if (compactNoise)
            {
                if (!launchNttForwardCenteredLimbFrom(ring->view(stream), compactNoiseSource.data(stream), nullptr,
                        idx + static_cast<std::size_t>(limbOffset), ctBuffer.data(stream), nullptr, count, stream.raw())) return false;
            }
            else if (!launchCanonicalize(ring->view(stream), ctBuffer.data(stream), nullptr, count, stream.raw()) ||
                !launchNttForward(ring->view(stream), ctBuffer.data(stream), count, nullptr, stream.raw())) return false;
            if (!launchInnerProduct(ring->view(stream), rBuffer.data(stream), bBuffer.data(stream), idx, idx + count,
                    1u, ctBuffer.data(stream), nullptr, count, false, false, stream.raw(), true)) return false;
            for (u32 col = 0; col < tauHi; ++col)
            {
                const auto* outputIndices = idx + std::size_t{2} * count + static_cast<std::size_t>(col) * rows;
                if (!launchScaleByPow2(ring->view(stream), rBuffer.poly(rows, stream), nullptr,
                        scaledBuffer.data(stream), nullptr, rows, factors[col],
                        stream.raw()) ||
                    !launchElementwise(ring->view(stream), ctBuffer.data(stream), outputIndices,
                        scaledBuffer.data(stream), nullptr, ctBuffer.data(stream), outputIndices,
                        rows, ElemOp::Sub, stream.raw())) return false;
            }
        }
        if (deferredCiphertext)
        {
            // Top ciphertexts are already in NTT form. Keep that exact buffer
            // until an explicit host consumer or the encoded wire needs it.
            if (!stream.sync()) return false;
            auto lazy = makeGpuSetupTensorHostState(ctx, std::move(ctBuffer), rows, cols);
            if (!lazy) return false;
            outCtNtt.clear();
            *deferredCiphertext = std::move(lazy);
            return true;
        }
        HostStep downloadStep(hostProfiler(ctx), "setup: root device download", &cpuBenchmark);
        if ((ctx.mExecutionOptions.mAdvanced.mProtocol.mExtraPipelinedDownload) && count >= 4)
        {
            if (!ctBuffer.downloadPipelined(next, stream, requestedWorkers, ctx.mGpuExecution->transferCpuScratch(), 0, 0, cpuBenchmark) || next.size() != count)
                return false;
            outCtNtt = std::move(next);
            return true;
        }
        const auto bytes = static_cast<std::size_t>(count) * polyBytes;
        constexpr std::size_t maxReuseBytes = std::size_t(512) << 20;
        if (bytes <= maxReuseBytes && outCtNtt.size() == count && validateRingBatchShape(outCtNtt, ctx.mParams))
        {
            if (auto* stage = stream.staging(bytes))
            {
                if (!gpuMemcpyD2H(stage, ctBuffer.data(stream), bytes, stream.raw()) || !stream.sync()) return false;
                for (std::size_t i = 0; i < outCtNtt.size(); ++i)
                    std::memcpy(outCtNtt[i].mCoeffs.data(), stage + i * polyBytes, polyBytes);
                return true;
            }
        }
        if (!ctBuffer.download(next, stream) || next.size() != count) return false;
        outCtNtt = std::move(next);
        return true;
    }

    bool assembleLencTruncDevice(
        const RingNttContext& ctx, const std::vector<std::vector<RnsPoly>>& rLayersNtt,
        std::span<const RnsPoly> sPadNtt, std::span<const RnsPoly> publicBNtt,
        u32 tauHi, u32 tauLeaf, u32 gadgetLogBase, bool gadgetLeaves,
        std::span<const u64> crtLiftModQj, std::span<const RnsPoly> noiseCoeffs,
        std::vector<RnsPoly>& outCtNtt, std::vector<RnsPoly>* outFirstRNtt,
        std::span<const u64> compactNoiseLimb0, std::span<const u64> compactRandomizerLimb0,
        u32 requestedWorkers, bool devicePadding, CpuBenchmarkState cpuBenchmark, ProtocolCacheScopeView scope)
    {
        if (!cpuBenchmark.mContext) cpuBenchmark.mContext = cpuBenchmarkContext(ctx);
        return assembleLencTruncDevice(ctx, rLayersNtt, sPadNtt, publicBNtt, tauHi, tauLeaf,
            gadgetLogBase, gadgetLeaves, crtLiftModQj, noiseCoeffs, outCtNtt, outFirstRNtt,
            compactNoiseLimb0, compactRandomizerLimb0, requestedWorkers, devicePadding, nullptr, nullptr,
            nullptr, 0, nullptr, nullptr, nullptr, cpuBenchmark, scope);
    }

    bool assembleLencTruncDevice(
        const RingNttContext& ctx,
        const std::vector<std::vector<RnsPoly>>& rLayersNtt,
        std::span<const RnsPoly> sPadNtt,
        std::span<const RnsPoly> publicBNtt,
        u32 tauHi, u32 tauLeaf, u32 gadgetLogBase, bool gadgetLeaves,
        std::span<const u64> crtLiftModQj,
        std::span<const RnsPoly> noiseCoeffs,
        std::vector<RnsPoly>& outCtNtt,
        std::vector<RnsPoly>* outFirstRNtt,
        std::span<const u64> compactNoiseLimb0,
        std::span<const u64> compactRandomizerLimb0,
        u32 requestedWorkers,
        bool devicePadding,
        const DeviceScalars* compactNoiseDevice,
        const DeviceScalars* compactRandomizerDevice,
        std::shared_ptr<const LazyRingTensorHostState>* deferredCiphertext,
        u32 retainedRandomizerCount,
        std::shared_ptr<const LazyLencRandomizerState>* retainedRandomizers,
        const RetainedPublicUniform* retainedPublicB,
        const DeviceBatch* seedLabelDevice, CpuBenchmarkState cpuBenchmark, ProtocolCacheScopeView scope)
    {
        if (!cpuBenchmark.mContext) cpuBenchmark.mContext = cpuBenchmarkContext(ctx);
        if (outFirstRNtt == &outCtNtt) return false;
        if ((compactNoiseDevice && (!compactNoiseLimb0.empty() || compactNoiseDevice->producerStream())) ||
            (compactRandomizerDevice && (!compactRandomizerLimb0.empty() || compactRandomizerDevice->producerStream()))) return false;
        const bool decline = ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mLencDevice;
        const bool topDecline = ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mTopSk1Lenc;
        if ((decline) ||
            (seedLabelDevice && topDecline &&
                seedLabelDevice->mImpl &&
                (seedLabelDevice->mImpl->mTopSeedLabelRepCoefficients ||
                 seedLabelDevice->mImpl->mRootHiRepCoefficients))) return false;
        if (!enabled(ctx) || rLayersNtt.empty() || rLayersNtt.size() >= 32u ||
            tauHi == 0 || tauHi == std::numeric_limits<u32>::max() ||
            tauLeaf == 0 || tauLeaf > tauHi + 1u || gadgetLogBase == 0)
            return false;
        HostStep totalStep(hostProfiler(ctx), "setup: lenc device assembly", &cpuBenchmark);
        const u32 levels = static_cast<u32>(rLayersNtt.size());
        const u32 width = u32{1} << levels;
        const u32 rho = static_cast<u32>(ringModulusCount(ctx));
        if ((retainedRandomizers && (!outFirstRNtt || !retainedRandomizerCount || retainedRandomizerCount > width)) ||
            (!retainedRandomizers && retainedRandomizerCount)) return false;
        const u32 fullTau = tauHi + 1u;
        const u32 ctTau = std::max(tauHi, tauLeaf);
        const u64 rows64 = static_cast<u64>(levels) * width;
        const u64 cols64 = u64{2} * ctTau;
        if (rows64 > std::numeric_limits<u32>::max() ||
            cols64 > std::numeric_limits<u32>::max()) return false;
        const u64 count64 = rows64 * cols64;
        const u64 baseRCount64 = (static_cast<u64>(levels) + 1u) * width;
        const u64 baseBCount64 = u64{2} * fullTau;
        const u64 rCount64 = baseRCount64 + (gadgetLeaves ? width : 0u);
        const u64 bCount64 = baseBCount64 + (gadgetLeaves ? u64{2} * rho : 0u);
        const std::size_t seedLabelCount = seedLabelDevice
            ? seedLabelDevice->count() : sPadNtt.size();
        if (!rho || rows64 > std::numeric_limits<u32>::max() ||
            cols64 > std::numeric_limits<u32>::max() ||
            count64 > std::numeric_limits<u32>::max() ||
            rCount64 > std::numeric_limits<u32>::max() ||
            bCount64 > std::numeric_limits<u32>::max() ||
            (devicePadding ? (!seedLabelCount || seedLabelCount > width || !outFirstRNtt)
                           : sPadNtt.size() != width) ||
            (seedLabelDevice && (!devicePadding || !sPadNtt.empty() ||
                !setupLencInputBatchMatches(ctx, *seedLabelDevice,
                    seedLabelCount, scope.mRunId, scope))) ||
            (retainedPublicB ? (!publicBNtt.empty() ||
                !retainedPublicUniformMatches(ctx, *retainedPublicB,
                    static_cast<std::size_t>(baseBCount64), true, scope))
                : publicBNtt.size() != baseBCount64) ||
            (compactNoiseLimb0.empty() && !compactNoiseDevice && noiseCoeffs.size() != count64) ||
            (gadgetLeaves && (retainedRandomizers ? !crtLiftModQj.empty() : crtLiftModQj.size() != rho))) return false;
        const bool compactRandomizers = !compactRandomizerLimb0.empty() || compactRandomizerDevice;
        if (compactRandomizers && !outFirstRNtt) return false;
        for (const auto& layer : rLayersNtt)
            if (layer.size() != width ||
                (!compactRandomizers && !validateRingBatchShape(layer, ctx.mParams))) return false;
        if ((!seedLabelDevice && !validateRingBatchShape(sPadNtt, ctx.mParams)) ||
            (!retainedPublicB && !validateRingBatchShape(publicBNtt, ctx.mParams)) ||
            (compactNoiseLimb0.empty() && !compactNoiseDevice && !validateRingBatchShape(noiseCoeffs, ctx.mParams))) return false;
        auto ring = GpuRing::get(ctx);
        if (!ring || ring->rho() != rho || ring->polyWords() >
            std::numeric_limits<std::size_t>::max() / sizeof(u64)) return false;
        const std::size_t polyBytes = ring->polyWords() * sizeof(u64);
        if (!polyBytes || count64 > std::numeric_limits<std::size_t>::max() / polyBytes) return false;

        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        const bool compactNoise = !compactNoiseLimb0.empty() || compactNoiseDevice;
        // Keep the extra disjoint full-stride device source bounded. Only its
        // q0 limbs are initialized and read by the centered forward transform.
        if (compactNoise && ((compactNoiseDevice ? compactNoiseDevice->count() : compactNoiseLimb0.size()) != count64 * n ||
                count64 * polyBytes > (std::size_t(512) << 20))) return false;
        if (compactRandomizers && ((compactRandomizerDevice ? compactRandomizerDevice->count() : compactRandomizerLimb0.size()) != rows64 * n ||
                rows64 > std::numeric_limits<std::size_t>::max() / polyBytes ||
                (rows64 + (compactNoise ? count64 : 0u)) >
                    (std::size_t(512) << 20) / polyBytes)) return false;

        const u32 rows = static_cast<u32>(rows64);
        const u32 cols = static_cast<u32>(cols64);
        const u32 count = static_cast<u32>(count64);
        const u32 baseRCount = static_cast<u32>(baseRCount64);
        const u32 baseBCount = static_cast<u32>(baseBCount64);
        std::vector<u32> productR, productB, productOut;
        struct ScaledTermGroup
        {
            std::vector<u32> mInput;
            std::vector<u32> mOutput;
            std::size_t mInputOffset = 0;
            std::size_t mOutputOffset = 0;
        };
        std::vector<ScaledTermGroup> groups(fullTau);
        for (u32 row = 0; row < rows; ++row)
        {
            const u32 level = row / width;
            const u32 leaf = row % width;
            const bool isLeaf = level + 1u == levels;
            const u32 activeTau = isLeaf ? tauLeaf : tauHi;
            const u32 bit = (leaf >> (levels - 1u - level)) & 1u;
            for (u32 side = 0; side < 2u; ++side)
            {
                const u32 limb = ((leaf & ~1u) + side) % rho;
                for (u32 t = 0; t < activeTau; ++t)
                {
                    const u32 output = row * cols + side * ctTau + t;
                    productR.push_back(row);
                    productB.push_back(isLeaf && gadgetLeaves
                        ? baseBCount + side * rho + limb
                        : side * fullTau + t + (isLeaf ? 0u : 1u));
                    productOut.push_back(output);
                    if (side == bit)
                    {
                        auto& group = groups[t + (isLeaf ? 0u : 1u)];
                        group.mInput.push_back(isLeaf && gadgetLeaves
                            ? baseRCount + leaf : (level + 1u) * width + leaf);
                        group.mOutput.push_back(output);
                    }
                }
            }
        }

        std::vector<u32> indices;
        auto appendIndices = [&](const std::vector<u32>& values) {
            const auto offset = indices.size();
            indices.insert(indices.end(), values.begin(), values.end());
            return offset;
        };
        const auto productROffset = appendIndices(productR);
        const auto productBOffset = appendIndices(productB);
        const auto productOutOffset = appendIndices(productOut);
        std::size_t maxGroup = 0;
        for (auto& group : groups)
        {
            group.mInputOffset = appendIndices(group.mInput);
            group.mOutputOffset = appendIndices(group.mOutput);
            maxGroup = std::max(maxGroup, group.mInput.size());
        }
        std::vector<u32> selectBInput, selectBOutput, selectBLimb;
        std::vector<u32> selectRInput, selectROutput, selectRLimb;
        if (gadgetLeaves)
        {
            for (u32 side = 0; side < 2u; ++side)
                for (u32 limb = 0; limb < rho; ++limb)
                {
                    selectBInput.push_back(side * fullTau);
                    selectBOutput.push_back(baseBCount + side * rho + limb);
                    selectBLimb.push_back(limb);
                }
            for (u32 leaf = 0; leaf < width; ++leaf)
            {
                selectRInput.push_back(levels * width + leaf);
                selectROutput.push_back(baseRCount + leaf);
                // At the leaf level the selected side is the leaf's low bit.
                selectRLimb.push_back(leaf % rho);
            }
        }
        const auto selectBInputOffset = appendIndices(selectBInput);
        const auto selectBOutputOffset = appendIndices(selectBOutput);
        const auto selectBLimbOffset = appendIndices(selectBLimb);
        const auto selectRInputOffset = appendIndices(selectRInput);
        const auto selectROutputOffset = appendIndices(selectROutput);
        const auto selectRLimbOffset = appendIndices(selectRLimb);
        const auto compactNoiseLimbOffset = indices.size();
        if (compactNoise) indices.resize(indices.size() + count, 0u);
        const auto compactRandomizerLimbOffset = indices.size();
        if (compactRandomizers) indices.resize(indices.size() + rows, 0u);
        std::vector<const u64*> factors(fullTau);
        for (u32 power = 0; power < fullTau; ++power)
        {
            const u64 bits = static_cast<u64>(gadgetLogBase) * power;
            if (bits > std::numeric_limits<u32>::max() ||
                !(factors[power] = ring->pow2Factors(static_cast<u32>(bits)))) return false;
        }

        auto& stream = contextSampleStream(ctx);
        GpuPolyBuffer rBuffer, bBuffer, ctBuffer, scaledBuffer, compactNoiseSource, compactRandomizerSource;
        OwnedGpuBuffer deviceIndices, deviceFactors;
        std::vector<RnsPoly> next, firstRNtt;
        GpuPolyBuffer retainedNtt;
        std::shared_ptr<const LazyLencRandomizerState> randomizerOwner;
        // All host staging remains alive until queued work is drained, including
        // error exits. Buffers are then released on their owning stream.
        struct DrainStream
        {
            GpuStream& stream;
            ~DrainStream() { stream.sync(); }
        } drainStream{stream};
        {
            HostStep uploadStep(hostProfiler(ctx), "setup: lenc device upload", &cpuBenchmark);
            if (!rBuffer.resize(*ring, static_cast<u32>(rCount64), stream) ||
                !bBuffer.resize(*ring, static_cast<u32>(bCount64), stream) ||
                !ctBuffer.resize(*ring, count, stream) || !scaledBuffer.resize(*ring, maxGroup, stream)) return false;
            if (compactRandomizers)
            {
                if (!compactRandomizerSource.resize(*ring, rows, stream) ||
                    !(compactRandomizerDevice
                        ? copyRowsFromDevice(compactRandomizerSource.data(stream), polyBytes, compactRandomizerDevice->data(), n * sizeof(u64), rows, stream)
                        : uploadRowsFromHost(compactRandomizerSource.data(stream), polyBytes, compactRandomizerLimb0.data(), n * sizeof(u64), rows, stream))) return false;
            }
            else
                for (u32 level = 0; level < levels; ++level)
                    if (!rBuffer.upload(rLayersNtt[level], stream, static_cast<std::size_t>(level) * width)) return false;
            const auto copiedSeedLabels = seedLabelDevice
                ? ([&] {
                    HostStep copyStep(hostProfiler(ctx), "setup: LENC seed-label retained D2D", &cpuBenchmark);
                    return gpuMemcpyD2D(
                        rBuffer.poly(static_cast<std::size_t>(levels) * width, stream),
                        seedLabelDevice->mImpl->mBuf.data(stream),
                        seedLabelDevice->mImpl->mBuf.bytes(), stream.raw());
                })()
                : rBuffer.upload(sPadNtt, stream,
                    static_cast<std::size_t>(levels) * width);
            if (!copiedSeedLabels ||
                !(retainedPublicB
                    ? copyRetainedPublicUniform(ctx, bBuffer, *retainedPublicB,
                        0, baseBCount, true, stream, scope)
                    : uploadPublicUniformOrHost(ctx, bBuffer, publicBNtt, stream, scope))) return false;
            if (devicePadding && seedLabelCount < width &&
                !gpuMemsetZero(rBuffer.poly(
                        static_cast<std::size_t>(levels) * width + seedLabelCount, stream),
                    (width - seedLabelCount) * polyBytes, stream.raw())) return false;
            if (compactNoise)
            {
                if (!compactNoiseSource.resize(*ring, count, stream) ||
                    !(compactNoiseDevice
                        ? copyRowsFromDevice(compactNoiseSource.data(stream), polyBytes, compactNoiseDevice->data(), n * sizeof(u64), count, stream)
                        : uploadRowsFromHost(compactNoiseSource.data(stream), polyBytes, compactNoiseLimb0.data(), n * sizeof(u64), count, stream))) return false;
            }
            else if (!ctBuffer.upload(noiseCoeffs, stream)) return false;
            deviceIndices = tryAllocateGpuBuffer(stream, indices.size() * sizeof(u32));
            if (!deviceIndices ||
                !gpuMemcpyH2D(deviceIndices.data(), indices.data(), indices.size() * sizeof(u32), stream.raw())) return false;
            // Internal retained setup uses the ring's GPU-derived lift. Keep
            // custom caller-supplied lift factors for the public eager API.
            if (gadgetLeaves && !retainedRandomizers)
            {
                deviceFactors = tryAllocateGpuBuffer(stream, crtLiftModQj.size_bytes());
                if (!deviceFactors || !gpuMemcpyH2D(deviceFactors.data(), crtLiftModQj.data(),
                        crtLiftModQj.size_bytes(), stream.raw())) return false;
            }
        }
        const auto* idx = static_cast<const u32*>(deviceIndices.data());
        const auto* scalar = retainedRandomizers ? ring->crtLiftFactors() : static_cast<const u64*>(deviceFactors.data());
        {
            HostStep kernelStep(hostProfiler(ctx), "setup: lenc device launches", &cpuBenchmark);
            if (compactRandomizers)
            {
                // Read q0 from a disjoint source while producing all RNS limbs.
                // The padded input is a general polynomial and transforms on
                // its own; only randomizer layers use the centered expansion.
                if (!launchNttForwardCenteredLimbFrom(ring->view(stream),
                        compactRandomizerSource.data(stream), nullptr, idx + compactRandomizerLimbOffset,
                        rBuffer.data(stream), nullptr, rows, stream.raw()) ||
                    !launchCanonicalize(ring->view(stream), rBuffer.poly(rows, stream), nullptr, width, stream.raw()) ||
                    !launchNttForward(ring->view(stream), rBuffer.poly(rows, stream), width, nullptr, stream.raw())) return false;
            }
            else if (outFirstRNtt &&
                (!launchCanonicalize(ring->view(stream), rBuffer.data(stream), nullptr, baseRCount, stream.raw()) ||
                 !launchNttForward(ring->view(stream), rBuffer.data(stream), baseRCount, nullptr, stream.raw()))) return false;
            if (compactNoise)
            {
                // Out-of-place is essential: an output limb may otherwise
                // overwrite q0 while a different limb's block still reads it.
                if (!launchNttForwardCenteredLimbFrom(ring->view(stream),
                        compactNoiseSource.data(stream), nullptr, idx + compactNoiseLimbOffset,
                        ctBuffer.data(stream), nullptr, count, stream.raw())) return false;
            }
            else if (!launchCanonicalize(ring->view(stream), ctBuffer.data(stream), nullptr, count, stream.raw()) ||
                !launchNttForward(ring->view(stream), ctBuffer.data(stream), count, nullptr, stream.raw())) return false;
            if (gadgetLeaves)
            {
                if (!launchSelectScaleLimb(ring->view(stream), bBuffer.data(stream), idx + selectBInputOffset,
                        idx + selectBLimbOffset, scalar, bBuffer.data(stream), idx + selectBOutputOffset,
                        static_cast<u32>(selectBInput.size()), stream.raw()) ||
                    !launchSelectScaleLimb(ring->view(stream), rBuffer.data(stream), idx + selectRInputOffset,
                        idx + selectRLimbOffset, scalar, rBuffer.data(stream), idx + selectROutputOffset,
                        width, stream.raw())) return false;
            }
            if (!launchInnerProduct(ring->view(stream), rBuffer.data(stream), bBuffer.data(stream),
                    idx + productROffset, idx + productBOffset, 1u, ctBuffer.data(stream),
                    idx + productOutOffset, static_cast<u32>(productR.size()), true, false, stream.raw())) return false;
            for (u32 power = 0; power < fullTau; ++power)
            {
                const auto& group = groups[power];
                if (group.mInput.empty()) continue;
                const auto groupCount = static_cast<u32>(group.mInput.size());
                if (!launchScaleByPow2(ring->view(stream), rBuffer.data(stream), idx + group.mInputOffset,
                        scaledBuffer.data(stream), nullptr, groupCount,
                        factors[power], stream.raw()) ||
                    !launchElementwise(ring->view(stream), ctBuffer.data(stream), idx + group.mOutputOffset,
                        scaledBuffer.data(stream), nullptr, ctBuffer.data(stream), idx + group.mOutputOffset,
                        groupCount, ElemOp::Add, stream.raw())) return false;
            }
        }
        if (retainedRandomizers)
        {
            HostStep retainStep(hostProfiler(ctx), "setup: LENC randomizer retain", &cpuBenchmark);
            if (!retainedNtt.resize(*ring, retainedRandomizerCount, stream) ||
                !gpuMemcpyD2D(retainedNtt.data(stream), rBuffer.data(stream), retainedNtt.bytes(), stream.raw()) ||
                !launchCanonicalize(ring->view(stream), retainedNtt.data(stream), nullptr, retainedRandomizerCount, stream.raw()) ||
                !stream.sync()) return false;
            randomizerOwner = std::make_shared<GpuLencRandomizers>(ctx, ring, std::move(retainedNtt), scope.mRole);
        }
        else if (outFirstRNtt)
        {
            HostStep downloadStep(hostProfiler(ctx), "setup: LENC randomizer host download", &cpuBenchmark);
            if (!rBuffer.download(firstRNtt, stream, 0, width)) return false;
        }
        if (deferredCiphertext)
        {
            // The first randomizer layer is still needed by LHE. Ciphertext
            // coefficients remain in their completed NTT-domain allocation.
            if (!stream.sync()) return false;
            auto lazy = makeGpuSetupTensorHostState(ctx, std::move(ctBuffer), rows, cols);
            if (!lazy) return false;
            outCtNtt.clear();
            if (outFirstRNtt) *outFirstRNtt = std::move(firstRNtt);
            *deferredCiphertext = std::move(lazy);
            if (retainedRandomizers) *retainedRandomizers = std::move(randomizerOwner);
            return true;
        }
        HostStep downloadStep(hostProfiler(ctx), "setup: lenc device download", &cpuBenchmark);
        if (ctx.mExecutionOptions.mAdvanced.mProtocol.mPipelinedDownload)
        {
            if (!ctBuffer.downloadPipelined(outCtNtt, stream, requestedWorkers, ctx.mGpuExecution->transferCpuScratch(), 0, 0, cpuBenchmark)) return false;
            if (outFirstRNtt) *outFirstRNtt = std::move(firstRNtt);
            if (retainedRandomizers) *retainedRandomizers = std::move(randomizerOwner);
            return true;
        }
        if (ctx.mExecutionOptions.mAdvanced.mProtocol.mDirectDownload)
        {
            // Download into independently owned, uninitialized destinations.
            // This avoids staging then copying the full ciphertext on the CPU.
            // Neither output nor any aliased fallback source changes until all
            // transfers complete; next remains alive through DrainStream.
            next.resize(count);
            for (std::size_t i = 0; i < next.size(); ++i)
            {
                next[i].mCoeffs.resize(ring->polyWords());
                if (!gpuMemcpyD2H(next[i].mCoeffs.data(), ctBuffer.poly(i, stream),
                        polyBytes, stream.raw())) return false;
            }
            if (!stream.sync()) return false;
            outCtNtt = std::move(next);
            if (outFirstRNtt) *outFirstRNtt = std::move(firstRNtt);
            if (retainedRandomizers) *retainedRandomizers = std::move(randomizerOwner);
            return true;
        }
        constexpr std::size_t maxReuseBytes = std::size_t(512) << 20;
        const std::size_t bytes = static_cast<std::size_t>(count) * polyBytes;
        if (bytes <= maxReuseBytes)
        {
            if (auto* stage = stream.staging(bytes))
            {
                // Do not touch even one host coefficient until the entire
                // transfer succeeds, preserving coefficient-noise fallback.
                if (!gpuMemcpyD2H(stage, ctBuffer.data(stream), bytes, stream.raw()) || !stream.sync()) return false;
                if (outCtNtt.size() == count && validateRingBatchShape(outCtNtt, ctx.mParams))
                {
                    for (std::size_t i = 0; i < outCtNtt.size(); ++i)
                        std::memcpy(outCtNtt[i].mCoeffs.data(), stage + i * polyBytes, polyBytes);
                }
                else
                {
                    // Compact sampling has no full-size host ciphertext yet.
                    // Allocate uninitialized destinations only after the entire
                    // device download succeeds, then publish them atomically.
                    next.resize(count);
                    for (std::size_t i = 0; i < next.size(); ++i)
                    {
                        next[i].mCoeffs.resize(ring->polyWords());
                        std::memcpy(next[i].mCoeffs.data(), stage + i * polyBytes, polyBytes);
                    }
                    outCtNtt = std::move(next);
                }
                if (outFirstRNtt) *outFirstRNtt = std::move(firstRNtt);
                if (retainedRandomizers) *retainedRandomizers = std::move(randomizerOwner);
                return true;
            }
        }
        if (!ctBuffer.download(next, stream) || next.size() != count) return false;
        outCtNtt = std::move(next);
        if (outFirstRNtt) *outFirstRNtt = std::move(firstRNtt);
        if (retainedRandomizers) *retainedRandomizers = std::move(randomizerOwner);
        return true;
    }

    bool assembleLheCiphertextDevice(
        const RingNttContext& ctx, std::span<const RnsPoly> r,
        std::span<const RnsPoly> sk1, std::span<const RnsPoly> publicANtt,
        u32 gadgetLogBase, bool rInputIsNtt, u32 rPowerOffset,
        std::vector<RnsPoly>& outCoeffs, std::span<const u64> compactNoiseLimb0, CpuBenchmarkState cpuBenchmark, ProtocolCacheScopeView scope)
    {
        if (!cpuBenchmark.mContext) cpuBenchmark.mContext = cpuBenchmarkContext(ctx);
        return assembleLheCiphertextDevice(ctx, r, sk1, publicANtt, gadgetLogBase,
            rInputIsNtt, rPowerOffset, outCoeffs, compactNoiseLimb0, nullptr, cpuBenchmark, scope);
    }

    bool assembleLheCiphertextDevice(
        const RingNttContext& ctx, std::span<const RnsPoly> r,
        std::span<const RnsPoly> sk1, std::span<const RnsPoly> publicANtt,
        u32 gadgetLogBase, bool rInputIsNtt, u32 rPowerOffset,
        std::vector<RnsPoly>& outCoeffs, std::span<const u64> compactNoiseLimb0,
        const DeviceScalars* compactNoiseDevice, CpuBenchmarkState cpuBenchmark, ProtocolCacheScopeView scope)
    {
        if (!cpuBenchmark.mContext) cpuBenchmark.mContext = cpuBenchmarkContext(ctx);
        return assembleLheCiphertextDevice(ctx, r, sk1, publicANtt, gadgetLogBase,
            rInputIsNtt, rPowerOffset, outCoeffs, compactNoiseLimb0, compactNoiseDevice, 1,
            nullptr, nullptr, nullptr, nullptr, nullptr, 0, false, cpuBenchmark, scope);
    }

    bool assembleLheCiphertextDevice(
        const RingNttContext& ctx,
        std::span<const RnsPoly> r,
        std::span<const RnsPoly> sk1,
        std::span<const RnsPoly> publicANtt,
        u32 gadgetLogBase, bool rInputIsNtt, u32 rPowerOffset,
        std::vector<RnsPoly>& outCoeffs,
        std::span<const u64> compactNoiseLimb0,
        const DeviceScalars* compactNoiseDevice,
        u32 requestedWorkers,
        std::shared_ptr<const LazyRingTensorHostState>* deferredCiphertext,
        const LazyLencRandomizerState* randomizers,
        const RetainedPublicUniform* retainedPublicA,
        const DeviceBatch* rootR1Device,
        const DeviceBatch* rootSecretDevice,
        ProtocolCacheRunId rootSecretOwnerRunId,
        bool topSecretDomain, CpuBenchmarkState cpuBenchmark, ProtocolCacheScopeView scope)
    {
        if (!cpuBenchmark.mContext) cpuBenchmark.mContext = cpuBenchmarkContext(ctx);
        const auto* retainedR = randomizers ? lencRandomizerDeviceNtt(ctx, randomizers, scope) : nullptr;
        const auto rCount = retainedR ? retainedR->count()
            : rootR1Device ? rootR1Device->count() : r.size();
        const auto skCount = rootSecretDevice ? rootSecretDevice->count() : sk1.size();
        if (!enabled(ctx) || !rCount || !skCount || rPowerOffset > 1u ||
            (randomizers && (!retainedR || !r.empty() || !rInputIsNtt)) ||
            (rootR1Device && (randomizers || !r.empty() || rInputIsNtt ||
                !rootErrorBatchMatches(ctx, *rootR1Device, rCount, scope))) ||
            (rootSecretDevice && (!sk1.empty() ||
                !(topSecretDomain
                    ? topSecretUniformBatchMatches(ctx, *rootSecretDevice,
                        skCount, rootSecretOwnerRunId, scope)
                    : rootSecretUniformBatchMatches(ctx, *rootSecretDevice,
                        skCount, rootSecretOwnerRunId, false, scope)))) ||
            rCount > std::numeric_limits<u32>::max() ||
            skCount > std::numeric_limits<u32>::max() ||
            (retainedPublicA ? (!publicANtt.empty() ||
                !retainedPublicUniformMatches(ctx, *retainedPublicA, rCount, false, scope))
                : publicANtt.size() != rCount) ||
            (!retainedR && !rootR1Device && !validateRingBatchShape(r, ctx.mParams)) ||
            (!rootSecretDevice && !validateRingBatchShape(sk1, ctx.mParams)) ||
            (!retainedPublicA && !validateRingBatchShape(publicANtt, ctx.mParams))) return false;
        const u64 count64 = static_cast<u64>(rCount) * skCount;
        if (count64 > std::numeric_limits<u32>::max() ||
            static_cast<u64>(gadgetLogBase) * (skCount - 1u) >
                std::numeric_limits<u32>::max()) return false;
        const bool forceDecline = ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mLheDevice;
        const bool topDecline = ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mTopSk1Lhe;
        if ((forceDecline) ||
            (topSecretDomain && topDecline)) return false;
        HostStep totalStep(hostProfiler(ctx), "setup: lhe device assembly", &cpuBenchmark);
        auto ring = GpuRing::get(ctx);
        if (!ring || !ring->rho() || ring->rho() != ringModulusCount(ctx) ||
            ring->polyWords() > std::numeric_limits<std::size_t>::max() / sizeof(u64)) return false;
        const std::size_t polyBytes = ring->polyWords() * sizeof(u64);
        if (!polyBytes || count64 > std::numeric_limits<std::size_t>::max() / polyBytes) return false;
        const u32 rows = static_cast<u32>(rCount);
        const u32 cols = static_cast<u32>(skCount);
        const u32 count = static_cast<u32>(count64);
        const std::size_t noiseDegree = ctx.mParams.mPolyModulusDegree;
        const bool compactNoise = !compactNoiseLimb0.empty() || compactNoiseDevice;
        if (compactNoiseDevice && (!compactNoiseLimb0.empty() || compactNoiseDevice->producerStream())) return false;
        if (compactNoise && ((compactNoiseDevice ? compactNoiseDevice->count() : compactNoiseLimb0.size()) != count64 * noiseDegree ||
                count64 * polyBytes > (std::size_t(512) << 20))) return false;

        // Indices are grouped by column for r*g^(column+offset), followed by
        // row-major A and secret-key indices for one batched product addition.
        std::vector<u32> indices(static_cast<std::size_t>(count) * (compactNoise ? 4u : 3u), 0u);
        for (u32 row = 0; row < rows; ++row)
            for (u32 col = 0; col < cols; ++col)
            {
                const std::size_t output = static_cast<std::size_t>(row) * cols + col;
                indices[static_cast<std::size_t>(col) * rows + row] = static_cast<u32>(output);
                indices[static_cast<std::size_t>(count) + output] = row;
                indices[static_cast<std::size_t>(count) * 2u + output] = col;
            }
        std::vector<const u64*> factors(cols);
        for (u32 col = 0; col < cols; ++col)
        {
            const u64 bits = static_cast<u64>(gadgetLogBase) * (static_cast<u64>(col) + rPowerOffset);
            if (bits > std::numeric_limits<u32>::max() ||
                !(factors[col] = ring->pow2Factors(static_cast<u32>(bits)))) return false;
        }
        const auto* ones = compactNoise ? ring->pow2Factors(0) : nullptr;
        if (compactNoise && !ones) return false;

        auto& stream = contextSampleStream(ctx);
        GpuPolyBuffer rBuffer, skBuffer, aBuffer, ctBuffer, noiseBuffer;
        OwnedGpuBuffer deviceIndices;
        std::vector<RnsPoly> next;
        // Declare this after every queued source/destination owner so even a
        // partial upload/download failure drains before any owner is destroyed.
        struct DrainStream
        {
            GpuStream& stream;
            ~DrainStream() { stream.sync(); }
        } drainStream{stream};
        {
            HostStep uploadStep(hostProfiler(ctx), "setup: lhe device upload", &cpuBenchmark);
            if ((!retainedR && !rBuffer.resize(*ring, rows, stream)) || !skBuffer.resize(*ring, cols, stream) ||
                !aBuffer.resize(*ring, rows, stream) || !ctBuffer.resize(*ring, count, stream) ||
                (!retainedR && !(rootR1Device
                    ? gpuMemcpyD2D(rBuffer.data(stream), rootR1Device->mImpl->mBuf.data(stream),
                        static_cast<std::size_t>(rows) * polyBytes, stream.raw())
                    : rBuffer.upload(r, stream))) ||
                !(rootSecretDevice
                    ? gpuMemcpyD2D(skBuffer.data(stream),
                        rootSecretDevice->mImpl->mBuf.data(stream),
                        static_cast<std::size_t>(cols) * polyBytes, stream.raw())
                    : skBuffer.upload(sk1, stream)) ||
                !(retainedPublicA
                    ? copyRetainedPublicUniform(ctx, aBuffer, *retainedPublicA,
                        0, rows, false, stream, scope)
                    : uploadPublicUniformOrHost(ctx, aBuffer, publicANtt, stream, scope))) return false;
            if (compactNoise && (!noiseBuffer.resize(*ring, count, stream) ||
                    !(compactNoiseDevice
                        ? copyRowsFromDevice(noiseBuffer.data(stream), polyBytes, compactNoiseDevice->data(), noiseDegree * sizeof(u64), count, stream)
                        : uploadRowsFromHost(noiseBuffer.data(stream), polyBytes, compactNoiseLimb0.data(), noiseDegree * sizeof(u64), count, stream)))) return false;
            deviceIndices = tryAllocateGpuBuffer(stream, indices.size() * sizeof(u32));
            if (!deviceIndices ||
                !gpuMemcpyH2D(deviceIndices.data(), indices.data(), indices.size() * sizeof(u32), stream.raw())) return false;
        }
        const auto* idx = static_cast<const u32*>(deviceIndices.data());
        const auto* rData = retainedR ? retainedR->data(stream) : rBuffer.data(stream);
        {
            HostStep kernelStep(hostProfiler(ctx), "setup: lhe device launches", &cpuBenchmark);
            // CPU scalar/NTT helpers reduce arbitrary u64 input coefficients.
            // Reduce on the device before entering canonical NTT/add kernels.
            if ((!retainedR && !launchCanonicalize(ring->view(stream), rBuffer.data(stream), nullptr, rows, stream.raw())) ||
                !launchCanonicalize(ring->view(stream), skBuffer.data(stream), nullptr, cols, stream.raw()) ||
                !launchCanonicalize(ring->view(stream), aBuffer.data(stream), nullptr, rows, stream.raw()) ||
                !launchNttForward(ring->view(stream), skBuffer.data(stream), cols, nullptr, stream.raw())) return false;
            if (!rInputIsNtt &&
                !launchNttForward(ring->view(stream), rBuffer.data(stream), rows, nullptr, stream.raw())) return false;
            for (u32 col = 0; col < cols; ++col)
            {
                const auto* outputIndices = idx + static_cast<std::size_t>(col) * rows;
                if ((col == 0u && rPowerOffset == 0u) || gadgetLogBase == 0u)
                {
                    if (!launchElementwise(ring->view(stream), rData, nullptr, nullptr, nullptr,
                            ctBuffer.data(stream), outputIndices, rows, ElemOp::Copy, stream.raw())) return false;
                }
                else if (!launchScaleByPow2(ring->view(stream), rData, nullptr,
                        ctBuffer.data(stream), outputIndices, rows,
                        factors[col], stream.raw())) return false;
            }
            if (!launchInnerProduct(ring->view(stream), aBuffer.data(stream), skBuffer.data(stream),
                    idx + count, idx + static_cast<std::size_t>(count) * 2u, 1u,
                    ctBuffer.data(stream), nullptr, count, true, false, stream.raw()) ||
                !launchNttInverse(ring->view(stream), ctBuffer.data(stream), count, nullptr, stream.raw())) return false;
            if (compactNoise)
            {
                // This lift is safely in-place: one thread loads one q0
                // coefficient before writing that coefficient in every limb.
                if (!launchLiftCenteredLimb(ring->view(stream), noiseBuffer.data(stream), nullptr,
                        idx + static_cast<std::size_t>(count) * 3u,
                        ones,
                        noiseBuffer.data(stream), nullptr, count, stream.raw()) ||
                    !launchElementwise(ring->view(stream), ctBuffer.data(stream), nullptr,
                        noiseBuffer.data(stream), nullptr, ctBuffer.data(stream), nullptr,
                        count, ElemOp::Add, stream.raw())) return false;
            }
        }
        if (deferredCiphertext)
        {
            // The final inverse transform and any compact noise addition have
            // completed before ownership leaves this producer stream.
            if (!stream.sync()) return false;
            auto lazy = makeGpuSetupTensorHostState(ctx, std::move(ctBuffer), rows, cols);
            if (!lazy) return false;
            outCoeffs.clear();
            *deferredCiphertext = std::move(lazy);
            return true;
        }
        HostStep downloadStep(hostProfiler(ctx), "setup: lhe device download", &cpuBenchmark);
        if ((ctx.mExecutionOptions.mAdvanced.mProtocol.mExtraPipelinedDownload) && count >= 4)
        {
            if (!ctBuffer.downloadPipelined(next, stream, requestedWorkers, ctx.mGpuExecution->transferCpuScratch(), 0, 0, cpuBenchmark) || next.size() != count)
                return false;
            outCoeffs = std::move(next);
            return true;
        }
        constexpr std::size_t maxReuseBytes = std::size_t(512) << 20;
        const std::size_t bytes = static_cast<std::size_t>(count) * polyBytes;
        if (bytes <= maxReuseBytes && outCoeffs.size() == count &&
            validateRingBatchShape(outCoeffs, ctx.mParams))
        {
            if (auto* stage = stream.staging(bytes))
            {
                if (!gpuMemcpyD2H(stage, ctBuffer.data(stream), bytes, stream.raw()) || !stream.sync()) return false;
                for (std::size_t i = 0; i < outCoeffs.size(); ++i)
                    std::memcpy(outCoeffs[i].mCoeffs.data(), stage + i * polyBytes, polyBytes);
                return true;
            }
        }
        if (!ctBuffer.download(next, stream) || next.size() != count) return false;
        outCoeffs = std::move(next);
        return true;
    }

    // ---- LevelSession -----------------------------------------------------

    struct LevelSession::Impl
    {
        std::shared_ptr<GpuRing> mRing;
        std::shared_ptr<OfflineCache> mCache;

        u32 mChunkCount = 0;
        u32 mWidth = 0;
        u32 mLevels = 0;
        u32 mNodeCount = 0;
        u32 mTauHi = 0;
        u32 mTauLeaf = 0;
        u32 mMaxTau = 0;
        bool mLeafInputsAreGadget = false;

        GpuPolyBuffer mX;        // [chunkCount * width]; unused on the aliased path
        // Where the leaf kernels actually read their input. Normally mX.data(), but
        // when the caller's device batch already has the exact layout the gather
        // would produce, this points straight at it and mX is left unallocated - see
        // the contiguous case in shrinkChunksImpl. Read-only either way.
        const u64* mXSrc = nullptr;
        // Actual tree nodes followed by one shared zero polynomial used by
        // padded inner-product terms.
        GpuPolyBuffer mNodes;    // [chunkCount * nodeCount * maxTau + 1]
        GpuPolyBuffer mDigest;   // [chunkCount]
        // Centred high digits of mDigest in the coefficient domain. Producing
        // dHat already computes these; expand consumes the identical values.
        // Shared because the compact device dHat representation is this buffer.
        DeviceBatchPtr mHiDigits; // physical [chunkCount * tauHi]
        GpuPolyBuffer mScratch;  // [chunkCount * max(nodesAtDepth) * maxTau]
        GpuPolyBuffer mCt2;      // [chunkCount * mu]
        GpuPolyBuffer mAcc;      // [chunkCount * mu]


        std::size_t nodeSlot(u32 chunk, u32 node, u32 digit) const
        {
            return (static_cast<std::size_t>(chunk) * mNodeCount + node) * mMaxTau + digit;
        }

        std::size_t nodeDataCount() const
        {
            return static_cast<std::size_t>(mChunkCount) * mNodeCount * mMaxTau;
        }

        std::size_t zeroNodeSlot() const { return nodeDataCount(); }
    };

    LevelSession::LevelSession() = default;
    LevelSession::~LevelSession() = default;

    bool LevelSession::valid() const
    {
        return mImpl != nullptr;
    }

    void LevelSession::reset()
    {
        mImpl.reset();
    }

    // ---- shrink -----------------------------------------------------------

    namespace
    {
    // Overrides for a shrink that is not a recursion level.
    //
    // The Root's *left* digest tree (buildDigestTreeTrunc over hatD, driven by
    // mRootLacctLeft) is structurally the same computation as a level's shrink, but
    // its width comes from a different accumulator and its leaves are always gadget
    // digits. Only the geometry differs, so it is worth parameterising rather than
    // duplicating the ladder.
    struct ShrinkOverride
    {
        // 0 takes state.mLacct.mWidthPadded, as a level does.
        u32 mWidthPadded = 0;
        // -1 takes state.mParams.mLeafInputsAreGadget.
        int mLeafInputsAreGadget = -1;
        // The unbundled child input. A tree build does not want it.
        bool mWantDHat = true;
    };


    // Shared implementation. Exactly one of xHost / xDev supplies the level
    // input. When wantHostOutputs is false the digests and the child input stay
    // on the device and only `dHatDev` is produced.
    bool shrinkChunksImpl(
        const ShrinkExpandReceiverState& state,
        std::span<const RnsPoly> xHost,
        const DeviceBatch* xDev,
        u32 xCount,
        u32 muHi,
        u32 tauHi,
        LevelSession& session,
        bool wantHostOutputs,
        std::vector<RnsPoly>& digests,
        std::vector<std::vector<RnsPoly>>& dHatChunks,
        DeviceBatchPtr& dHatDev,
        ReceiverFirstQueryAllocations* firstQueryAllocations,
        const void* firstQueryOwner, u64 firstQuerySid,
        const ShrinkOverride& ov, ProtocolCacheScopeView scope)
    {
        AutoTimer timer(timingCounter(timingStats(state.mRingFactoryOwner), &TimingStats::mGpuShrinkTimeUs));
        const std::span<const RnsPoly> x = xHost;
        if (!enabled(state.mRingFactoryOwner) || muHi == 0 || tauHi == 0) return bail(state.mRingFactoryOwner, "disabled or degenerate sizes");
        if (state.mParams.mTau != tauHi) return bail(state.mRingFactoryOwner, "tau mismatch");
        if (!state.mParams.mTruncateOneGadgetDigit) return bail(state.mRingFactoryOwner, "non-truncated parameters");

        auto cache = receiverCache(state, scope);
        if (!cache) return bail(state.mRingFactoryOwner, "offline cache upload failed");
        auto ring = cache->mRing;
        const u32 rho = ring->rho();

        const u32 chunkCount = (xCount + muHi - 1u) / muHi;
        if (chunkCount == 0) return bail(state.mRingFactoryOwner, "no chunks");

        const u32 width = ov.mWidthPadded ? ov.mWidthPadded : state.mLacct.mWidthPadded;
        const u32 levels = ilog2(width);
        if (width == 0 || (width & (width - 1u)) != 0 || width < muHi) return bail(state.mRingFactoryOwner, "lacct geometry");
        if (!ov.mWidthPadded && levels != state.mLacct.mLevels) return bail(state.mRingFactoryOwner, "lacct geometry");
        const u32 nodeCount = (2u * width) - 1u;

        const bool leafInputsAreGadget = ov.mLeafInputsAreGadget < 0
            ? state.mParams.mLeafInputsAreGadget
            : (ov.mLeafInputsAreGadget != 0);
        const u32 tauLeafCount = leafTau(
            state.mParams.mPlaintextModulusBits, state.mParams.mGadgetLogBase, leafInputsAreGadget);
        const u32 fullTau = tauHi + 1u;
        if (tauLeafCount == 0 || tauLeafCount > fullTau) return bail(state.mRingFactoryOwner, "leaf tau");
        const u32 maxTau = std::max(tauHi, tauLeafCount);
        const u32 inputPlainBroadcastBits =
            xDev ? xDev->mImpl->mPlainBroadcastBits : 0u;
        const bool inputPlainBroadcastSingleLimb =
            xDev && xDev->mImpl->mPlainBroadcastSingleLimb;
        const bool recursiveHiInput = xDev && xDev->mImpl->mRecursiveHiRepeat != 0u;
        if (recursiveHiInput &&
            (xDev->mImpl->mRecursiveHiRepeat != rho ||
             xDev->mImpl->mLogicalCount != xCount ||
             xDev->mImpl->mBuf.count() * rho != xCount ||
             (muHi % rho) != 0u || xDev->mImpl->mRecursiveHiNtt))
            return bail(state.mRingFactoryOwner, "recursive high-digit shape");
        const bool directRecursiveLeaves =
            recursiveHiInput && directRecursiveLeafEnabled(ring->executionOptions().mAdvanced.mProtocol) && leafInputsAreGadget &&
            tauLeafCount == 1u && ring->n() <= 2u * 8192u;

        auto impl = std::make_unique<LevelSession::Impl>();
        impl->mRing = ring;
        impl->mCache = cache;
        impl->mChunkCount = chunkCount;
        impl->mWidth = width;
        impl->mLevels = levels;
        impl->mNodeCount = nodeCount;
        impl->mTauHi = tauHi;
        impl->mTauLeaf = tauLeafCount;
        impl->mMaxTau = maxTau;
        impl->mLeafInputsAreGadget = leafInputsAreGadget;

        if (!state.mRingFactoryOwner || !state.mRingFactoryOwner->mGpuExecution) return false;
        auto& stream = contextStream(*state.mRingFactoryOwner);
        stream.reset();

        // ---- upload the leaves, zero padded ----
        // The leaf layout is chunkCount blocks of `width` polynomials, of which the
        // first muHi carry input and the rest are zero padding. When width equals
        // muHi and the input covers every chunk there is no padding at all, so the
        // destination layout is *identical* to the caller's device batch and the
        // gather degenerates to copying a buffer onto an identical one. The leaf
        // kernels only read it, so alias the caller's buffer and skip the allocation,
        // the zero fill and the copy. That is the common case and it was ~1 GB of
        // device-to-device traffic per query at n = 2^24, summed over the levels as
        // the sizes halve (512, 256, 128, ... MB).
        //
        // Safe because `xDev` outlives this level - the caller holds it across the
        // shrink and the matching expand - and nothing here writes through mXSrc.
        const bool contiguous = xDev && !recursiveHiInput && width == muHi &&
                                xCount >= static_cast<std::size_t>(chunkCount) * muHi;

        const bool singleLimbIdentityEligible =
            inputPlainBroadcastSingleLimb && contiguous &&
            identityLeafEnabled(ring->executionOptions().mAdvanced.mProtocol) && !leafInputsAreGadget &&
            tauLeafCount == 1u && inputPlainBroadcastBits != 0u &&
            inputPlainBroadcastBits <= state.mParams.mGadgetLogBase &&
            canLaunchNttForwardFromPlainBroadcast(ring->view(stream));
        // Any path that can copy, decompose, or otherwise expose a full RNS
        // polynomial first restores the opaque DeviceBatch's logical layout.
        // This must precede the noncontiguous whole-poly D2D copies below.
        if (inputPlainBroadcastSingleLimb && !singleLimbIdentityEligible &&
            !ensurePlainBroadcastMaterialized(*xDev->mImpl, stream))
            return false;

        Region regUp(GpuStream::RegionKind::Upload, stream);

        if (directRecursiveLeaves)
        {
            // mBuf stores one full-RNS high digit per rho logical child
            // leaves. The leaf NTT below reconstructs the distinct centred
            // representative selected by each logical leaf directly.
            impl->mXSrc = xDev->mImpl->mBuf.data(stream);
        }
        else if (recursiveHiInput)
        {
            // Controlled fallback: recreate the old sparse CRT-lifted dHat
            // layout when the fused leaf load is disabled or unsupported.
            if (!impl->mX.resize(*ring, static_cast<std::size_t>(chunkCount) * width, stream))
                return false;
            if (!impl->mX.zero(stream)) return false;
            impl->mXSrc = impl->mX.data(stream);

            const std::size_t idxCount = xCount;
            const u64 geo = idxKey(scope.mRole, 0xD4A8u, xCount, muHi, width, rho, chunkCount);
            const u32* dAll = cachedIdx(geo, 3 * idxCount, stream, [&](std::vector<u32>& v)
            {
                u32* srcIdx = v.data();
                u32* dstIdx = srcIdx + idxCount;
                u32* limbSel = dstIdx + idxCount;
                for (u32 i = 0; i < xCount; ++i)
                {
                    const u32 chunk = i / muHi;
                    const u32 leaf = i - chunk * muHi;
                    srcIdx[i] = i / rho;
                    dstIdx[i] = chunk * width + leaf;
                    limbSel[i] = leaf % rho;
                }
            });
            if (!dAll) return false;
            if (!launchSelectScaleLimb(
                    ring->view(stream), xDev->mImpl->mBuf.data(stream), dAll,
                    dAll + idxCount * 2u, ring->crtLiftFactors(), impl->mX.data(stream),
                    dAll + idxCount, xCount, stream.raw()))
                return false;
        }
        else if (contiguous)
        {
            impl->mXSrc = xDev->mImpl->mBuf.data(stream);
        }
        else
        {
            if (!impl->mX.resize(*ring, static_cast<std::size_t>(chunkCount) * width, stream)) return false;
            if (!impl->mX.zero(stream)) return false;
            impl->mXSrc = impl->mX.data(stream);
            for (u32 c = 0; c < chunkCount; ++c)
            {
                const std::size_t start = static_cast<std::size_t>(c) * muHi;
                const std::size_t end = std::min<std::size_t>(start + muHi, xCount);
                if (end <= start) continue;
                const std::size_t run = end - start;
                if (xDev)
                {
                    if (!gpuMemcpyD2D(
                            impl->mX.poly(static_cast<std::size_t>(c) * width, stream),
                            xDev->mImpl->mBuf.poly(start, stream),
                            run * ring->polyBytes(),
                            stream.raw()))
                        return false;
                }
                else
                {
                    for (std::size_t i = start; i < end; ++i)
                    {
                        if (!impl->mX.upload(x[i], static_cast<std::size_t>(c) * width + (i - start), stream))
                            return false;
                    }
                }
            }
        }

        regUp.stop();
        Region regKern(GpuStream::RegionKind::Kernel, stream);

        const std::size_t totalNodes =
            static_cast<std::size_t>(chunkCount) * nodeCount * maxTau + 1u;
        const bool reservedNodes = takeReceiverFirstQueryNodes(
            firstQueryAllocations, *ring, state.mParams.mRing, xCount,
            muHi, tauHi, width, maxTau, totalNodes,
            firstQueryOwner, firstQuerySid, impl->mNodes, stream, scope);
        if (!reservedNodes && !impl->mNodes.resize(*ring, totalNodes, stream))
            return false;
        // Every real node slot is overwritten before use. Only padding terms need
        // zero, so clear one shared sentinel instead of the entire tree buffer.
        if (!gpuMemsetZero(
                impl->mNodes.poly(impl->zeroNodeSlot(), stream), ring->polyBytes(), stream.raw()))
            return false;
        if (!impl->mDigest.resize(*ring, chunkCount, stream)) return false;

        const std::size_t maxNodesAtDepth = static_cast<std::size_t>(chunkCount) * (width / 2u);
        if (!impl->mScratch.resize(*ring, std::max<std::size_t>(maxNodesAtDepth, chunkCount), stream)) return false;


        // ---- leaf level ----
        bool recursiveLeafPairReady = false;
        bool recursiveLeafInverseDone = false;
        // Set only after the no-zero sparse inverse has queued. At leaf gadget
        // time this makes the two-term consumer mandatory: a dense fallback
        // would read the deliberately unmaterialized complementary limbs.
        bool recursiveLeafSparsePairRequired = false;
        {
            const std::size_t srcCount = static_cast<std::size_t>(chunkCount) * width;
            if (directRecursiveLeaves)
            {
                // dHat's old selectScaleLimb -> liftCenteredLimb chain cancels
                // algebraically, but each source limb must still choose its own
                // centred representative. Fuse that exact reconstruction into
                // the out-of-place transform load and materialize every raw leaf
                // slot, including padded zeros.
                const u64 geo = idxKey(scope.mRole,
                    0xD1ECu, xCount, muHi, chunkCount, width, rho,
                    impl->mNodeCount, impl->mMaxTau);
                const u32* dAll = cachedIdx(geo, 3 * srcCount, stream, [&](std::vector<u32>& v)
                {
                    u32* srcIdx = v.data();
                    u32* dstIdx = srcIdx + srcCount;
                    u32* limbSel = dstIdx + srcCount;
                    for (u32 c = 0; c < chunkCount; ++c)
                    {
                        for (u32 leaf = 0; leaf < width; ++leaf)
                        {
                            const std::size_t slot = static_cast<std::size_t>(c) * width + leaf;
                            const std::size_t logical = static_cast<std::size_t>(c) * muHi + leaf;
                            const bool valid = leaf < muHi && logical < xCount;
                            srcIdx[slot] = valid ? static_cast<u32>(logical / rho) : 0u;
                            dstIdx[slot] = static_cast<u32>(
                                impl->nodeSlot(c, (width - 1u) + leaf, 0));
                            limbSel[slot] = valid ? (leaf % rho) : rho;
                        }
                    }
                });
                if (!dAll) return false;
                if (!launchNttForwardCenteredLimbFrom(
                        ring->view(stream), impl->mXSrc, dAll, dAll + 2 * srcCount,
                        impl->mNodes.data(stream), dAll + srcCount,
                        static_cast<u32>(srcCount), stream.raw()))
                    return false;

                if (recursiveDiagonalEnabled(ring->executionOptions().mAdvanced.mProtocol) && rho > 1u && levels > 0u)
                {
                    const u32 leafParentCount = chunkCount * (width / 2u);
                    u64* leafParent =
                        (levels == 1u && !ring->kernelOptions().mFusedIp)
                            ? impl->mDigest.data(stream)
                            : impl->mScratch.data(stream);
                    const bool recursiveLeafSelfZero =
                        recursiveLeafSelfZeroEnabled(ring->executionOptions().mAdvanced.mProtocol) && ring->n() == 8192u &&
                        rho == 4u && width == 8u && muHi == 8u &&
                        static_cast<u64>(xCount) ==
                            static_cast<u64>(chunkCount) * muHi;
                    if (!recursiveLeafSelfZero &&
                        !gpuMemsetZero(
                            leafParent,
                            static_cast<std::size_t>(leafParentCount) * ring->polyBytes(),
                            stream.raw()))
                        return false;

                    // Resource-validated production envelope: the three
                    // n=2^24 shapes plus the next full level reached at n=2^25.
                    // Lower recursive levels retain the accepted diagonal plus
                    // full inverse.
                    bool sparseInverseLaunched = false;
                    const bool sparseInverseEligible =
                        recursiveLeafSparseInverseEnabled(ring->executionOptions().mAdvanced.mProtocol) &&
                        recursiveLeafSelfZero && !ring->kernelOptions().mFusedIp &&
                        ring->n() == 8192u && rho == 4u && width == 8u &&
                        muHi == 8u && levels == 3u && nodeCount == 15u &&
                        tauHi == 1u && tauLeafCount == 1u && maxTau == 1u &&
                        xCount >= 256u && xCount <= 2048u &&
                        static_cast<u64>(xCount) ==
                            static_cast<u64>(chunkCount) * muHi;
                    // Eligibility is committed before zero elision.
                    const bool sparsePairEligible =
                        sparseInverseEligible &&
                        state.mParams.mGadgetLogBase == 110u &&
                        state.mParams.mPlaintextModulusBits == 55u &&
                        canLaunchGadgetDecomposeHi110RecursiveLeafSparsePair(
                            ring->view(stream), leafParent, leafParentCount,
                            impl->mNodes.data(stream));
                    if (sparsePairEligible)
                    {
                        if (!tryLaunchNttInverseRecursiveLeafSparseNegateNoZero(
                            ring->view(stream), impl->mNodes.data(stream),
                            cache->mRecursiveLeafB.poly(0, stream),
                            cache->mRecursiveLeafB.poly(1, stream),
                            xDev->mImpl->mBuf.data(stream), leafParent, xCount,
                            stream.raw(), sparseInverseLaunched))
                            return false;
                        recursiveLeafSparsePairRequired = sparseInverseLaunched;
                    }
                    if (sparseInverseEligible && !sparseInverseLaunched &&
                        !tryLaunchNttInverseRecursiveLeafSparseNegate(
                            ring->view(stream), impl->mNodes.data(stream),
                            cache->mRecursiveLeafB.poly(0, stream),
                            cache->mRecursiveLeafB.poly(1, stream),
                            xDev->mImpl->mBuf.data(stream), leafParent, xCount,
                            stream.raw(), sparseInverseLaunched))
                        return false;

                    if (sparseInverseLaunched)
                    {
                        xDev->mImpl->mRecursiveHiNtt = true;
                        recursiveLeafPairReady = true;
                        recursiveLeafInverseDone = true;
                    }
                    else
                    {
                        const u64 diagGeo = idxKey(scope.mRole,
                            0xD1A6u, xCount, muHi, chunkCount, width, rho,
                            impl->mNodeCount, impl->mMaxTau);
                        const u32* dDiag = cachedIdx(
                            diagGeo, 2 * static_cast<std::size_t>(xCount), stream,
                            [&](std::vector<u32>& v)
                        {
                            u32* nodeIdx = v.data();
                            u32* parentAndSide = nodeIdx + xCount;
                            for (u32 logical = 0; logical < xCount; ++logical)
                            {
                                const u32 c = logical / muHi;
                                const u32 leaf = logical - c * muHi;
                                const u32 parent =
                                    c * (width / 2u) + (leaf >> 1u);
                                nodeIdx[logical] = static_cast<u32>(
                                    impl->nodeSlot(c, (width - 1u) + leaf, 0));
                                parentAndSide[logical] =
                                    parent | ((leaf & 1u) << 31u);
                            }
                        });
                        if (!dDiag) return false;
                        if (!launchRecursiveLeafDiagonal(
                                ring->view(stream), impl->mNodes.data(stream), dDiag,
                                dDiag + xCount,
                                cache->mRecursiveLeafB.poly(0, stream),
                                cache->mRecursiveLeafB.poly(1, stream),
                                xDev->mImpl->mBuf.data(stream), leafParent,
                                xCount, recursiveLeafSelfZero, stream.raw()))
                            return false;
                        xDev->mImpl->mRecursiveHiNtt = true;
                        recursiveLeafPairReady = true;
                    }
                }
            }
            else
            {
            const std::size_t dstCount = srcCount * tauLeafCount;
            const u64 geo = idxKey(scope.mRole,
                0x1EAFull, chunkCount, width, tauLeafCount, rho, nodeCount, maxTau);
            const u32* dAll = cachedIdx(
                geo, 2 * srcCount + dstCount, stream, [&](std::vector<u32>& v)
            {
                u32* srcIdx = v.data();
                u32* dstIdx = srcIdx + srcCount;
                u32* limbSel = dstIdx + dstCount;
                for (u32 c = 0; c < chunkCount; ++c)
                {
                    for (u32 leaf = 0; leaf < width; ++leaf)
                    {
                        const std::size_t slot = static_cast<std::size_t>(c) * width + leaf;
                        srcIdx[slot] = static_cast<u32>(slot);
                        limbSel[slot] = leaf % rho;
                        for (u32 d = 0; d < tauLeafCount; ++d)
                        {
                            dstIdx[slot * tauLeafCount + d] =
                                static_cast<u32>(impl->nodeSlot(c, (width - 1u) + leaf, d));
                        }
                    }
                }
            });
            if (!dAll) return false;
            const u32* dSrc = dAll;
            const u32* dDst = dSrc + srcCount;
            const u32* dLimb = dDst + dstCount;

            bool leafNttDone = false;
            if (identityLeafEnabled(ring->executionOptions().mAdvanced.mProtocol) && !impl->mLeafInputsAreGadget && tauLeafCount == 1u &&
                inputPlainBroadcastBits != 0u &&
                inputPlainBroadcastBits <= state.mParams.mGadgetLogBase &&
                ring->n() <= 2u * 8192u)
            {
                // A wrapped, unscaled plaintext batch broadcasts canonical c<p
                // to every RNS limb. With c < 2^g and one level, the non-centred
                // gadget decomposition is exactly the identity. Transform from
                // the input directly into the leaf slots, deleting the full
                // intermediate gadget write/read while retaining every limb for
                // the later expand/LENC evaluation.
                const bool forwardOk = singleLimbIdentityEligible
                    ? launchNttForwardFromPlainBroadcast(
                          ring->view(stream), impl->mXSrc, dSrc,
                          impl->mNodes.data(stream), dDst,
                          static_cast<u32>(srcCount), stream.raw())
                    : launchNttForwardFrom(
                          ring->view(stream), impl->mXSrc, dSrc,
                          impl->mNodes.data(stream), dDst,
                          static_cast<u32>(srcCount), stream.raw());
                if (!forwardOk)
                    return false;
                leafNttDone = true;
            }
            else if (impl->mLeafInputsAreGadget)
            {
                if (!launchLiftCenteredLimb(
                        ring->view(stream), impl->mXSrc, dSrc, dLimb, ring->invCrtLiftFactors(),
                        impl->mNodes.data(stream), dDst, static_cast<u32>(srcCount), stream.raw()))
                    return false;
            }
            else if (!launchGadgetDecompose(
                         ring->view(stream), impl->mXSrc, dSrc, static_cast<u32>(srcCount),
                         state.mParams.mGadgetLogBase, 0, tauLeafCount, false, impl->mNodes.data(stream), dDst,
                         stream.raw()))
            {
                return false;
            }

            if (!leafNttDone && !launchNttForward(
                    ring->view(stream), impl->mNodes.data(stream), static_cast<u32>(dstCount), dDst, stream.raw()))
                return false;
            }

            // Every possible reader of the owned leaf input is now ahead of this
            // stream-ordered free. Returning the often-huge buffer to the cache
            // here lets deeper recursion reuse it instead of retaining one copy
            // per level until the matching expand.
            impl->mX.release();
            impl->mXSrc = nullptr;
        }

        // ---- internal levels, bottom up ----
        const auto slices = makePublicBSlices(tauHi, tauLeafCount);
        for (int depth = static_cast<int>(levels) - 1; depth >= 0; --depth)
        {
            const bool leafLevel = depth == static_cast<int>(levels) - 1;
            const u32 activeTau = leafLevel ? tauLeafCount : tauHi;
            const auto& bSlice = leafLevel ? slices.mLeaf : slices.mInternal;
            const u32 nodesAtDepth = 1u << depth;
            const u32 firstNode = nodesAtDepth - 1u;
            const u32 outCount = chunkCount * nodesAtDepth;
            // Set when the inner product is folded into the inverse transform
            // below instead of being launched as its own kernel.
            NttFusedIp fusedIp{};
            const bool fuseIp = ring->kernelOptions().mFusedIp;
            bool inverseDone = leafLevel && recursiveLeafInverseDone;
            // On the shipped separate-IP path the root level can write directly
            // into mDigest, avoiding a terminal D2D copy of every chunk.
            u64* levelOut = (depth == 0 && !fuseIp)
                ? impl->mDigest.data(stream)
                : impl->mScratch.data(stream);

            if (leafLevel && impl->mLeafInputsAreGadget)
            {
                if (!recursiveLeafPairReady)
                {
                // The recursive-leaf pairing scales each side by the CRT lift of
                // its own limb; see recursiveLeafPairInnerProductNttToStd.
                const std::size_t idxCount = outCount;
                const u64 geo = idxKey(scope.mRole,
                    0x1EA2u, chunkCount, nodesAtDepth, firstNode, width, rho,
                    impl->mNodeCount, impl->mMaxTau);
                const u32* dAll = cachedIdx(geo, 4 * idxCount, stream, [&](std::vector<u32>& v)
                {
                    u32* leftIdx = v.data();
                    u32* rightIdx = leftIdx + idxCount;
                    u32* leftLimb = rightIdx + idxCount;
                    u32* rightLimb = leftLimb + idxCount;
                    for (u32 c = 0; c < chunkCount; ++c)
                    {
                        for (u32 k = 0; k < nodesAtDepth; ++k)
                        {
                            const u32 p = firstNode + k;
                            const u32 left = 2u * p + 1u;
                            const u32 right = left + 1u;
                            const std::size_t o = static_cast<std::size_t>(c) * nodesAtDepth + k;
                            leftIdx[o] = static_cast<u32>(impl->nodeSlot(c, left, 0));
                            rightIdx[o] = static_cast<u32>(impl->nodeSlot(c, right, 0));
                            leftLimb[o] = (left - (width - 1u)) % rho;
                            rightLimb[o] = (right - (width - 1u)) % rho;
                        }
                    }
                });
                if (!dAll) return false;
                const u32* dL = dAll;
                const u32* dR = dL + idxCount;
                const u32* dLL = dR + idxCount;
                const u32* dRL = dLL + idxCount;
                if (!launchLeafPairScaled(
                        ring->view(stream), cache->mRecursiveLeafB.poly(0, stream),
                        cache->mRecursiveLeafB.poly(1, stream), impl->mNodes.data(stream), dL, dR, dLL, dRL,
                        levelOut, nullptr, outCount, stream.raw()))
                    return false;
                }
            }
            else
            {
                bool fixedIpLaunched = false;
                if (!fuseIp && tauHi == 1u && tauLeafCount == 1u &&
                    impl->mMaxTau == 1u && activeTau == 1u &&
                    cache->mPublicB.count() >= 4u)
                {
                    if (!tryLaunchNttInverseTreePairNegate(
                            ring->view(stream), levelOut, cache->mPublicB.data(stream),
                            impl->mNodes.data(stream), outCount, static_cast<u32>(depth),
                            impl->mNodeCount, leafLevel ? 0u : 1u, stream.raw(),
                            fixedIpLaunched, state.mParams.mAlpha == 2u))
                        return false;
                }
                if (fixedIpLaunched)
                {
                    inverseDone = true;
                }
                else
                {
                const u32 terms = 2u * activeTau;
                const std::size_t idxCount = static_cast<std::size_t>(outCount) * terms;
                const u64 geo = idxKey(scope.mRole,
                    0x1A11u, chunkCount, nodesAtDepth, firstNode, activeTau, terms,
                    impl->mNodeCount, impl->mMaxTau, tauHi, tauLeafCount, fullTau,
                    static_cast<u32>(leafLevel));
                const u32* dPair = cachedIdx(geo, 2 * idxCount, stream, [&](std::vector<u32>& v)
                {
                    u32* aIdx = v.data();
                    u32* bIdx = v.data() + idxCount;
                    for (u32 c = 0; c < chunkCount; ++c)
                    {
                        for (u32 k = 0; k < nodesAtDepth; ++k)
                        {
                            const u32 p = firstNode + k;
                            const u32 left = 2u * p + 1u;
                            const u32 right = left + 1u;
                            const std::size_t o = static_cast<std::size_t>(c) * nodesAtDepth + k;
                            for (u32 i = 0; i < activeTau; ++i)
                            {
                                aIdx[o * terms + i] = bSlice[i];
                                bIdx[o * terms + i] = static_cast<u32>(impl->nodeSlot(c, left, i));
                                aIdx[o * terms + activeTau + i] = bSlice[activeTau + i];
                                bIdx[o * terms + activeTau + i] =
                                    static_cast<u32>(impl->nodeSlot(c, right, i));
                            }
                        }
                    }
                });
                if (!dPair) return false;
                const u32* dA = dPair;
                const u32* dB = dPair + idxCount;
                // The product array was written only for the inverse transform
                // below to read it straight back, so it is folded into that
                // transform's load instead. Saves two polynomials of traffic per
                // node, and the transform is at the memory roof, so traffic is all
                // there is left to cut.
                if (fuseIp)
                {
                    fusedIp.mA = cache->mPublicB.data(stream);
                    fusedIp.mB = impl->mNodes.data(stream);
                    fusedIp.mAIdx = dA;
                    fusedIp.mBIdx = dB;
                    fusedIp.mTerms = terms;
                    fusedIp.mMode = NttFusedIp::Replace;
                }
                else
                {
                    if (!launchInnerProduct(
                            ring->view(stream), cache->mPublicB.data(stream), impl->mNodes.data(stream), dA, dB, terms,
                            levelOut, nullptr, outCount, false, false, stream.raw()))
                    {
                        return false;
                    }
                }
                }
            }

            // Back to the coefficient domain and negate, matching
            // innerProductNttToStdPtrs followed by negatePoly.
            // Negation folded into the transform's store.
            if (!inverseDone && !launchNttInverseFused(
                    ring->view(stream), levelOut, outCount, nullptr, kElemOpNoneHost, nullptr,
                    static_cast<u32>(ElemOp::Negate), nullptr, stream.raw(), fusedIp,
                    state.mParams.mAlpha == 2u))
                return false;

            if (depth == 0)
            {
                // The default separate-IP path already targeted mDigest. The
                // optional fused path still transforms mScratch in place.
                if (levelOut != impl->mDigest.address() &&
                    !gpuMemcpyD2D(
                        impl->mDigest.data(stream), levelOut,
                        static_cast<std::size_t>(chunkCount) * ring->polyBytes(), stream.raw()))
                    return false;
                break;
            }

            // decomposeHiNtt: centred high digits, then forward NTT.
            const std::size_t dstCount = static_cast<std::size_t>(outCount) * tauHi;
            const u64 dstGeo = idxKey(scope.mRole,
                0xD37Au, chunkCount, nodesAtDepth, firstNode, tauHi,
                impl->mNodeCount, impl->mMaxTau);
            const u32* dDst = cachedIdx(dstGeo, dstCount, stream, [&](std::vector<u32>& dstIdx)
            {
                for (u32 c = 0; c < chunkCount; ++c)
                {
                    for (u32 k = 0; k < nodesAtDepth; ++k)
                    {
                        const u32 p = firstNode + k;
                        const std::size_t o = static_cast<std::size_t>(c) * nodesAtDepth + k;
                        for (u32 i = 0; i < tauHi; ++i)
                        {
                            dstIdx[o * tauHi + i] = static_cast<u32>(impl->nodeSlot(c, p, i));
                        }
                    }
                }
            });
            if (!dDst) return false;
            bool sparsePairDecomposed = false;
            if (leafLevel && recursiveLeafSparsePairRequired)
            {
                // No dense fallback is valid here: the producer intentionally
                // left two CRT limbs per parent unmaterialized.
                if (!launchGadgetDecomposeHi110RecursiveLeafSparsePair(
                        ring->view(stream), impl->mScratch.data(stream), outCount,
                        impl->mNodes.data(stream), dDst, stream.raw()))
                    return false;
                sparsePairDecomposed = true;
                recursiveLeafSparsePairRequired = false;
            }
            if (!sparsePairDecomposed)
            {
                if (!launchGadgetDecompose(
                        ring->view(stream), impl->mScratch.data(stream), nullptr, outCount,
                        state.mParams.mGadgetLogBase, 1, tauHi, true,
                        impl->mNodes.data(stream), dDst, stream.raw()))
                    return false;
            }
            if (!launchNttForward(
                    ring->view(stream), impl->mNodes.data(stream), static_cast<u32>(dstCount),
                    dDst, stream.raw()))
                return false;
        }

        regKern.stop();
        // The tree ladder has queued its final read/write of this coefficient
        // scratch. Return it to the stream-ordered cache before descending into
        // recursion so deeper levels can reuse hundreds of MiB rather than grow
        // one retained scratch allocation per session.
        impl->mScratch.release();

        // ---- digests and the child input ----
        if (wantHostOutputs)
        {
            Region regDown(GpuStream::RegionKind::Download, stream);
            if (!impl->mDigest.download(digests, stream, 0, chunkCount)) return false;
        }

        // seedLabelGadgetDecomposeHiAndUnbundle: one centred high digit per
        // digest, then split into rho single-limb polynomials.
        if (ov.mWantDHat)
        {
            auto hiDigits = std::make_shared<DeviceBatch>();
            hiDigits->mImpl->mRing = ring;
            const bool decomposeInPlace =
                inplaceHiDigitEnabled(ring->executionOptions().mAdvanced.mProtocol) && reuseHiDigitsEnabled(ring->executionOptions().mAdvanced.mProtocol) && tauHi == 1u &&
                impl->mDigest.count() == chunkCount;
            // Capture the allocation's address before moving its ownership. The
            // raw address stays valid and becomes both source and destination.
            u64* digestData = impl->mDigest.data(stream);
            if (decomposeInPlace)
                hiDigits->mImpl->mBuf = std::move(impl->mDigest);
            else if (!hiDigits->mImpl->mBuf.resize(
                         *ring, static_cast<std::size_t>(chunkCount) * tauHi, stream))
                return false;
            if (!launchGadgetDecompose(
                    ring->view(stream), digestData, nullptr, chunkCount, state.mParams.mGadgetLogBase, 1,
                    tauHi, true, hiDigits->mImpl->mBuf.data(stream), nullptr, stream.raw()))
                return false;

            const std::size_t outCount = static_cast<std::size_t>(chunkCount) * tauHi * rho;
            const bool compactDeviceDHat =
                !wantHostOutputs && directRecursiveLeafEnabled(ring->executionOptions().mAdvanced.mProtocol) &&
                ring->n() <= 2u * 8192u;
            if (compactDeviceDHat)
            {
                // Device-only recursive consumers understand this provenance and
                // reconstruct the exact limb-specific centred values in their
                // leaf NTT load. The logical shape remains the old rho-expanded
                // dHat shape for protocol geometry and validation.
                hiDigits->mImpl->mLogicalCount = outCount;
                hiDigits->mImpl->mRecursiveHiRepeat = rho;
                dHatDev = hiDigits;
            }
            else
            {
                GpuPolyBuffer unbundled;
                if (!unbundled.resize(*ring, outCount, stream)) return false;

                const u64 geo = idxKey(scope.mRole, 0xD4A7u, chunkCount, tauHi, rho);
                const u32* dPair = cachedIdx(geo, 2 * outCount, stream, [&](std::vector<u32>& v)
                {
                    u32* srcIdx = v.data();
                    u32* limbSel = v.data() + outCount;
                    for (u32 c = 0; c < chunkCount; ++c)
                    {
                        for (u32 d = 0; d < tauHi; ++d)
                        {
                            for (u32 limb = 0; limb < rho; ++limb)
                            {
                                const std::size_t o =
                                    ((static_cast<std::size_t>(c) * tauHi) + d) * rho + limb;
                                srcIdx[o] = static_cast<u32>(
                                    static_cast<std::size_t>(c) * tauHi + d);
                                limbSel[o] = limb;
                            }
                        }
                    }
                });
                if (!dPair) return false;
                if (!launchSelectScaleLimb(
                        ring->view(stream), hiDigits->mImpl->mBuf.data(stream), dPair,
                        dPair + outCount, ring->crtLiftFactors(), unbundled.data(stream),
                        nullptr, static_cast<u32>(outCount), stream.raw()))
                    return false;

                if (wantHostOutputs)
                {
                    std::vector<RnsPoly> flat;
                    {
                        Region regDown(GpuStream::RegionKind::Download, stream);
                        if (!unbundled.download(flat, stream, 0, outCount)) return false;
                    }

                    dHatChunks.assign(chunkCount, {});
                    for (u32 c = 0; c < chunkCount; ++c)
                    {
                        dHatChunks[c].resize(static_cast<std::size_t>(tauHi) * rho);
                        for (std::size_t i = 0; i < dHatChunks[c].size(); ++i)
                        {
                            dHatChunks[c][i] = std::move(
                                flat[static_cast<std::size_t>(c) * tauHi * rho + i]);
                        }
                    }
                }
                else
                {
                    auto out = std::make_shared<DeviceBatch>();
                    out->mImpl->mRing = ring;
                    out->mImpl->mBuf = std::move(unbundled);
                    dHatDev = std::move(out);
                }
            }

            if (reuseHiDigitsEnabled(ring->executionOptions().mAdvanced.mProtocol))
            {
                impl->mHiDigits = std::move(hiDigits);
                // The retained digits are now the expand input; after their
                // queued decomposition read, the original digest has no later
                // consumer in a regular shrink session.
                impl->mDigest.release();
            }
        }

        session.mImpl = std::move(impl);
        // No synchronise: the outputs are device resident and every consumer
        // enqueues on this same stream, so ordering is already guaranteed.
        // Draining here just idled the device until the host caught up.
        return true;
    }
    }

    bool shrinkChunks(
        const ShrinkExpandReceiverState& state,
        std::span<const RnsPoly> x,
        u32 muHi,
        u32 tauHi,
        LevelSession& session,
        std::vector<RnsPoly>& digests,
        std::vector<std::vector<RnsPoly>>& dHatChunks, ProtocolCacheScopeView scope)
    {
        DeviceBatchPtr unused;
        return shrinkChunksImpl(
            state, x, nullptr, static_cast<u32>(x.size()), muHi, tauHi, session, true, digests, dHatChunks,
            unused, nullptr, nullptr, 0, ShrinkOverride{}, scope);
    }

    bool shrinkChunksDevice(
        const ShrinkExpandReceiverState& state,
        std::span<const RnsPoly> xHost,
        const DeviceBatch* xDev,
        u32 xCount,
        u32 muHi,
        u32 tauHi,
        LevelSession& session,
        DeviceBatchPtr& dHat,
        ReceiverFirstQueryAllocations* firstQueryAllocations,
        const void* firstQueryOwner, u64 firstQuerySid, ProtocolCacheScopeView scope)
    {
        std::vector<RnsPoly> digests;
        std::vector<std::vector<RnsPoly>> dHatChunks;
        return shrinkChunksImpl(
            state, xHost, xDev, xCount, muHi, tauHi, session, false, digests,
            dHatChunks, dHat, firstQueryAllocations,
            firstQueryOwner, firstQuerySid, ShrinkOverride{}, scope);
    }

    bool buildDigestTreeChunkDevice(
        const ShrinkExpandReceiverState& state,
        std::span<const RnsPoly> x,
        const DeviceBatch* xDev,
        u32 widthPadded,
        u32 tauHi,
        bool leafInputsAreGadget,
        bool wantHostTree,
        u32& maxTauOut,
        RnsPoly& digest,
        std::vector<RnsPoly>& nodesFlat,
        std::shared_ptr<void>& sessionOut, ProtocolCacheScopeView scope)
    {
        const u32 xCount = xDev ? static_cast<u32>(xDev->count()) : static_cast<u32>(x.size());
        if (!enabled(state.mRingFactoryOwner) || xCount == 0 || widthPadded == 0 || tauHi == 0) return false;

        ShrinkOverride ov{};
        ov.mWidthPadded = widthPadded;
        ov.mLeafInputsAreGadget = leafInputsAreGadget ? 1 : 0;
        ov.mWantDHat = false;

        auto session = std::make_shared<LevelSession>();
        std::vector<RnsPoly> digests;
        std::vector<std::vector<RnsPoly>> dHatChunks;
        DeviceBatchPtr unused;
        // One chunk covering the whole input, so muHi == the input count and the
        // ladder runs exactly once. The leaves are taken from device memory when the
        // caller has them there, which for the Root is always: they are the output of
        // the shrink that ran immediately before.
        if (!shrinkChunksImpl(
                state, xDev ? std::span<const RnsPoly>() : x, xDev, xCount, xCount, tauHi,
                *session, false, digests, dHatChunks, unused,
                nullptr, nullptr, 0, ov, scope) ||
            !session->mImpl)
        {
            return false;
        }

        auto& impl = *session->mImpl;
        maxTauOut = impl.mMaxTau;

        // Only the host key-derivation fallback reads the tree. When the caller can
        // use the device session - and the Root always can, since the session is
        // what its device chain evaluates against - downloading it is a pure round
        // trip: 2*widthPadded-1 ring elements out and nothing that reads them.
        if (wantHostTree)
        {
            if (!state.mRingFactoryOwner || !state.mRingFactoryOwner->mGpuExecution) return false;
            auto& stream = contextStream(*state.mRingFactoryOwner);
            std::vector<RnsPoly> digestOut;
            if (!impl.mDigest.download(digestOut, stream, 0, 1) || digestOut.size() != 1) return false;
            if (!impl.mNodes.download(nodesFlat, stream, 0, impl.nodeDataCount())) return false;
            digest = std::move(digestOut[0]);
        }
        else
        {
            nodesFlat.clear();
        }

        sessionOut = std::move(session);
        return true;
    }

    // ---- Root device key derivation ---------------------------------------

    namespace
    {
        // Defined further down with the expand it was written for. buildHashedCt2 and
        // the expand's ct2 are the same derivation, so the Root reuses it rather than
        // growing a second copy.
        bool sampleCt2Batch(
            const GpuRing& ring,
            const OfflineCache& cache,
            const RingParams& params,
            u32 chunkCount,
            u32 mu,
            std::span<const u8> seed,
            u64 sid,
            u64 instanceBase,
            block maskDigestHash,
            GpuPolyBuffer& out,
            GpuStream& stream);

        constexpr u32 kRootPriorityN = 8192u;
        constexpr u32 kRootPriorityRho = 4u;
        constexpr u32 kRootPriorityTauHi = 1u;
        constexpr u32 kRootPriorityLeftWidth = 4u;
        constexpr u32 kRootPriorityGadgetBits = 110u;

        bool rootPriorityNoGoldGeometry(u32 n, u32 rho, u32 gadgetBits,
            const LogVoleGpuProtocolOptions& options)
        {
            return options.mNoGoldRootPriorityPrefetch && n == 16384u && rho == 8u && gadgetBits == 208u;
        }

        // Polynomial workspaces are allocated on the ordinary Root stream and
        // completed by rootCache's existing sync.
        // The priority stream's index allocation is prepared here as well, so
        // query submission does not construct a pool or allocate its storage.
        struct RootFinalizePriorityWorkspace
        {
            struct IndexPair
            {
                std::size_t mAOffset = 0;
                std::size_t mBOffset = 0;
                std::size_t mCount = 0;
                u32 mTerms = 0;
            };

            std::unique_ptr<GpuStream> mStream;
            GpuPolyBuffer mUHi;
            GpuPolyBuffer mAcc;
            GpuPolyBuffer mPhi;
            GpuPolyBuffer mLeftEval;
            OwnedGpuBuffer mIndexStorage;
            u32* mIndices = nullptr;
            std::vector<u32> mHostIndices;
            IndexPair mCtRPair;
            IndexPair mTopPair;
            IndexPair mLeftPair;
            u32 mTauLeaf = 0;
            u32 mMaxTau = 0;
            u32 mNodeCount = 0;
            u32 mZeroNodeSlot = 0;
            bool mIndicesReady = false;

            ~RootFinalizePriorityWorkspace()
            {
                // Normally every prefix has already been transferred to the
                // receiver stream through its ready event. On teardown or an
                // abandoned attempt, finish the dedicated producer before its
                // cache-owned storage is returned to the allocator.
                if (mStream && !mStream->sync()) std::terminate();
                // Each allocation retains its own origin and last-use streams;
                // suffix work may have moved to another receiver thread.
                mUHi.release();
                mAcc.release();
                mPhi.release();
                mLeftEval.release();
                mIndexStorage.reset();
                mIndices = nullptr;
                mStream.reset();
            }

            bool init(
                const GpuRing& ring,
                u32 tauHi,
                u32 leftWidth,
                u32 topCols,
                u32 levels,
                u32 lacctCols, GpuStream& stream)
            {
                if (tauHi == 0u || leftWidth == 0u || topCols == 0u ||
                    levels == 0u || lacctCols == 0u || (lacctCols & 1u))
                    return false;

                mStream = GpuStream::createHighestPriority(stream.options(), stream.hostProfilerOwner());
                if (!mStream) return false;

                if (!mUHi.resize(ring, tauHi, stream) ||
                    !mAcc.resize(ring, leftWidth, stream) ||
                    !mPhi.resize(ring, leftWidth, stream) ||
                    !mLeftEval.resize(ring, leftWidth, stream))
                    return false;

                const std::size_t ctRCount =
                    static_cast<std::size_t>(leftWidth) * tauHi;
                const std::size_t topCount =
                    static_cast<std::size_t>(leftWidth) * topCols;
                const u32 leftTerms = levels * lacctCols;
                const std::size_t leftCount =
                    static_cast<std::size_t>(leftWidth) * leftTerms;

                std::size_t offset = 0;
                const auto reservePair = [&](IndexPair& pair, std::size_t count, u32 terms) {
                    pair.mAOffset = offset;
                    offset += count;
                    pair.mBOffset = offset;
                    offset += count;
                    pair.mCount = count;
                    pair.mTerms = terms;
                };
                reservePair(mCtRPair, ctRCount, tauHi);
                reservePair(mTopPair, topCount, topCols);
                reservePair(mLeftPair, leftCount, leftTerms);

                mIndexStorage = OwnedGpuBuffer(mStream->allocationOwner(), offset * sizeof(u32));
                mIndices = static_cast<u32*>(mIndexStorage.data());
                mHostIndices.resize(offset);

                // Submit one marker now, then join it to rootCache's ordinary
                // stream. The cache's existing final sync completes this warmup
                // before send without adding another host synchronization.
                void* warm = gpuEventCreate();
                if (!warm) return false;
                const bool warmQueued =
                    gpuEventRecord(warm, mStream->raw()) &&
                    gpuStreamWaitEvent(stream.raw(), warm);
                gpuEventDestroy(warm);
                return warmQueued;
            }

            const u32* a(const IndexPair& pair) const
            {
                return mIndices + pair.mAOffset;
            }

            const u32* b(const IndexPair& pair) const
            {
                return mIndices + pair.mBOffset;
            }
        };

        // The Root's three offline tensors in device memory. They depend only on the
        // parameter set, so this is built once per ReceiverState and reused.
        struct RootDeviceCache
        {
            std::shared_ptr<GpuRing> mRing;
            GpuPolyBuffer mCtR;         // [leftWidth][ctRCols]      NTT domain
            GpuPolyBuffer mTopCt;       // [leftWidth][topCols]      NTT domain
            GpuPolyBuffer mLacctLeft;   // [levels*width][2*ctTauMax] NTT domain
            GpuPolyBuffer mPublicBStar; // [randomizerWidth]         NTT domain
            u32 mCtRCols = 0;
            u32 mTopCols = 0;
            u32 mLacctCols = 0;
            u32 mWidth = 0;
            u32 mLevels = 0;
            std::unique_ptr<RootFinalizePriorityWorkspace> mPriorityWorkspace;
        };

        std::shared_ptr<RootDeviceCache> rootCache(
            const ReceiverState& state, const RingNttContext& ctx, CpuBenchmarkState cpuBenchmark = {})
        {
            if (!cpuBenchmark.mContext) cpuBenchmark.mContext = cpuBenchmarkContext(ctx);
            if (state.mRootGpuCache)
            {
                return std::static_pointer_cast<RootDeviceCache>(state.mRootGpuCache);
            }
            if ((state.mRootCtRRt.mPolys.empty() && !state.mRootCtRWire) ||
                (state.mRootTopCt.mPolys.empty() && !state.mRootTopCtWire) ||
                (state.mRootLacctLeft.mCt.mPolys.empty() && !state.mRootLacctLeftWire))
            {
                return nullptr;
            }

            auto ring = GpuRing::get(ctx);
            if (!ring) return nullptr;

            auto cache = std::make_shared<RootDeviceCache>();
            cache->mRing = ring;
            auto& stream = contextStream(ctx);

            const auto upload = [&](const RingTensor& t, GpuPolyBuffer& dst, u32& cols) {
                cols = t.mCols;
                return dst.resize(*ring, t.mPolys.size(), stream) && dst.upload(t.mPolys, stream);
            };
            const auto uploadCtR = [&] {
                if (!state.mRootCtRWire)
                {
                    HostStep phase(hostProfiler(ctx), "setup root: CtR upload host NTT", &cpuBenchmark);
                    return upload(state.mRootCtRRt, cache->mCtR, cache->mCtRCols);
                }
                HostStep phase(hostProfiler(ctx), "setup root: CtR upload encoded wire and NTT", &cpuBenchmark);
                cache->mCtRCols = state.mRootCtRRt.mCols;
                const auto count = ringTensorSize(state.mRootCtRRt);
                if (!count || count > std::numeric_limits<u32>::max() ||
                    !cache->mCtR.resize(*ring, static_cast<std::size_t>(count), stream))
                    return false;
                const auto encoded = state.mRootCtRWire->encodedCoefficients();
                return encoded.size() == cache->mCtR.bytes() &&
                    uploadSetupWire(cache->mCtR.data(stream), encoded, stream,
                        state.mParams.mShrinkExpand.mTransport.mEncoding.mWire) &&
                    launchCanonicalize(ring->view(stream), cache->mCtR.data(stream), nullptr,
                        static_cast<u32>(count), stream.raw()) &&
                    nttForward(*ring, cache->mCtR.data(stream), static_cast<u32>(count), stream);
            };
            const auto uploadTopCt = [&] {
                if (!state.mRootTopCtWire)
                {
                    HostStep phase(hostProfiler(ctx), "setup root: TopCt upload host scatter", &cpuBenchmark);
                    return upload(state.mRootTopCt, cache->mTopCt, cache->mTopCols);
                }
                HostStep phase(hostProfiler(ctx), "setup root: TopCt upload encoded wire", &cpuBenchmark);
                cache->mTopCols = state.mRootTopCt.mCols;
                const auto count = ringTensorSize(state.mRootTopCt);
                if (count > std::numeric_limits<std::size_t>::max() ||
                    !cache->mTopCt.resize(*ring, static_cast<std::size_t>(count), stream))
                    return false;
                const auto encoded = state.mRootTopCtWire->encodedCoefficients();
                return encoded.size() == cache->mTopCt.bytes() &&
                    uploadSetupWire(cache->mTopCt.data(stream), encoded, stream,
                        state.mParams.mShrinkExpand.mTransport.mEncoding.mWire);
            };
            const auto uploadLacct = [&] {
                if (!state.mRootLacctLeftWire)
                {
                    HostStep phase(hostProfiler(ctx), "setup root: Lacct upload host scatter", &cpuBenchmark);
                    return upload(state.mRootLacctLeft.mCt, cache->mLacctLeft, cache->mLacctCols);
                }
                HostStep phase(hostProfiler(ctx), "setup root: Lacct upload encoded wire", &cpuBenchmark);
                cache->mLacctCols = state.mRootLacctLeft.mCt.mCols;
                const auto count = ringTensorSize(state.mRootLacctLeft.mCt);
                if (count > std::numeric_limits<std::size_t>::max() ||
                    !cache->mLacctLeft.resize(*ring, static_cast<std::size_t>(count), stream))
                    return false;
                const auto encoded = state.mRootLacctLeftWire->encodedCoefficients();
                return encoded.size() == cache->mLacctLeft.bytes() &&
                    uploadSetupWire(cache->mLacctLeft.data(stream), encoded, stream,
                        state.mParams.mShrinkExpand.mTransport.mEncoding.mWire);
            };
            const auto uploadPublicBStar = [&] {
                if (!state.mRootPublicBStarWire)
                {
                    HostStep phase(hostProfiler(ctx), "setup root: BStar upload host scatter", &cpuBenchmark);
                    return cache->mPublicBStar.resize(*ring, state.mRootPublicBStarNtt.size(), stream) &&
                        cache->mPublicBStar.upload(state.mRootPublicBStarNtt, stream);
                }
                HostStep phase(hostProfiler(ctx), "setup root: BStar upload encoded wire", &cpuBenchmark);
                if (!cache->mPublicBStar.resize(*ring, state.mRootRandomizerWidth, stream))
                    return false;
                const auto encoded = state.mRootPublicBStarWire->encodedCoefficients();
                return encoded.size() == cache->mPublicBStar.bytes() &&
                    uploadSetupWire(cache->mPublicBStar.data(stream), encoded, stream,
                        state.mParams.mShrinkExpand.mTransport.mEncoding.mWire);
            };

            if (!uploadCtR() ||
                !uploadTopCt() ||
                !uploadLacct() ||
                !uploadPublicBStar())
            {
                return nullptr;
            }
            cache->mWidth = state.mRootLacctLeft.mWidthPadded;
            cache->mLevels = state.mRootLacctLeft.mLevels;

            const bool goldenPriorityGeometry =
                ring->n() == kRootPriorityN && ring->rho() == kRootPriorityRho &&
                state.mParams.mShrinkExpand.mGadgetLogBase ==
                    kRootPriorityGadgetBits;
            const bool noGoldPriorityGeometry = rootPriorityNoGoldGeometry(
                ring->n(), ring->rho(), state.mParams.mShrinkExpand.mGadgetLogBase, ctx.mExecutionOptions.mAdvanced.mProtocol);
            const u32 priorityLeftWidth = noGoldPriorityGeometry
                ? 8u : kRootPriorityLeftWidth;
            if (rootFinalizePriorityPrefetchEnabledImpl(ctx.mExecutionOptions.mAdvanced.mProtocol) &&
                (goldenPriorityGeometry || noGoldPriorityGeometry) &&
                state.mRootRandomizerWidth == 3u &&
                cache->mCtRCols == kRootPriorityTauHi &&
                cache->mTopCols == kRootPriorityTauHi +
                    state.mRootRandomizerWidth &&
                cache->mWidth >= priorityLeftWidth)
            {
                auto workspace =
                    std::make_unique<RootFinalizePriorityWorkspace>();
                if (workspace->init(
                        *ring, kRootPriorityTauHi, priorityLeftWidth,
                        cache->mTopCols, cache->mLevels,
                        cache->mLacctCols, stream))
                {
                    cache->mPriorityWorkspace = std::move(workspace);
                }
            }

            // This pre-existing cache-construction drain also makes every
            // priority-workspace allocation globally ready. No incoming event
            // or host wait is needed when the post-send prefix starts.
            if (!stream.sync()) return nullptr;

            state.mRootGpuCache = cache;
            return cache;
        }

        bool ensureRootFinalizePriorityIndices(
            RootFinalizePriorityWorkspace& workspace,
            const RootDeviceCache& cache,
            const LevelSession::Impl& tree,
            u32 tauHi,
            u32 leftWidth,
            u32 topCols)
        {
            if (!workspace.mStream || !workspace.mIndices ||
                tree.mRing.get() != cache.mRing.get() ||
                tree.mChunkCount != 1u || tree.mMaxTau == 0u ||
                tree.mTauLeaf > tree.mMaxTau || tauHi > tree.mMaxTau ||
                cache.mLacctCols != 2u * tree.mMaxTau ||
                cache.mLevels != tree.mLevels || cache.mWidth < leftWidth)
                return false;

            const std::size_t zeroNodeSlot = tree.zeroNodeSlot();
            if (zeroNodeSlot > std::numeric_limits<u32>::max()) return false;
            if (workspace.mIndicesReady)
            {
                return workspace.mTauLeaf == tree.mTauLeaf &&
                       workspace.mMaxTau == tree.mMaxTau &&
                       workspace.mNodeCount == tree.mNodeCount &&
                       workspace.mZeroNodeSlot ==
                           static_cast<u32>(zeroNodeSlot);
            }

            const auto& ctRPair = workspace.mCtRPair;
            const auto& topPair = workspace.mTopPair;
            const auto& leftPair = workspace.mLeftPair;
            if (ctRPair.mTerms != tauHi ||
                ctRPair.mCount != static_cast<std::size_t>(leftWidth) * tauHi ||
                topPair.mTerms != topCols ||
                topPair.mCount != static_cast<std::size_t>(leftWidth) * topCols ||
                leftPair.mTerms != 2u * cache.mLevels * tree.mMaxTau ||
                leftPair.mCount !=
                    static_cast<std::size_t>(leftWidth) * leftPair.mTerms)
                return false;

            auto& host = workspace.mHostIndices;
            for (u32 row = 0; row < leftWidth; ++row)
            {
                for (u32 col = 0; col < tauHi; ++col)
                {
                    const std::size_t i =
                        static_cast<std::size_t>(row) * tauHi + col;
                    host[ctRPair.mAOffset + i] =
                        row * cache.mCtRCols + col;
                    host[ctRPair.mBOffset + i] = col;
                }
                for (u32 col = 0; col < topCols; ++col)
                {
                    const std::size_t i =
                        static_cast<std::size_t>(row) * topCols + col;
                    host[topPair.mAOffset + i] = row * topCols + col;
                    host[topPair.mBOffset + i] = col;
                }
            }

            const u32 terms = leftPair.mTerms;
            for (u32 leaf = 0; leaf < leftWidth; ++leaf)
            {
                u32 parent = 0u;
                u32 t = 0u;
                for (u32 levelIdx = 0; levelIdx < cache.mLevels; ++levelIdx)
                {
                    const u32 left = 2u * parent + 1u;
                    const u32 right = left + 1u;
                    const u32 activeTau =
                        levelIdx == cache.mLevels - 1u ? tree.mTauLeaf : tauHi;
                    const u32 row = levelIdx * cache.mWidth + leaf;
                    for (u32 col = 0; col < activeTau; ++col)
                    {
                        const std::size_t leftSlot =
                            tree.nodeSlot(0u, left, col);
                        const std::size_t rightSlot =
                            tree.nodeSlot(0u, right, col);
                        if (leftSlot > std::numeric_limits<u32>::max() ||
                            rightSlot > std::numeric_limits<u32>::max())
                            return false;
                        const std::size_t first =
                            static_cast<std::size_t>(leaf) * terms + t++;
                        host[leftPair.mAOffset + first] =
                            row * cache.mLacctCols + col;
                        host[leftPair.mBOffset + first] =
                            static_cast<u32>(leftSlot);
                        const std::size_t second =
                            static_cast<std::size_t>(leaf) * terms + t++;
                        host[leftPair.mAOffset + second] =
                            row * cache.mLacctCols + tree.mMaxTau + col;
                        host[leftPair.mBOffset + second] =
                            static_cast<u32>(rightSlot);
                    }
                    const u32 bit =
                        (leaf >> (cache.mLevels - 1u - levelIdx)) & 1u;
                    parent = bit == 0u ? left : right;
                }
                for (; t < terms; ++t)
                {
                    const std::size_t i =
                        static_cast<std::size_t>(leaf) * terms + t;
                    host[leftPair.mAOffset + i] = 0u;
                    host[leftPair.mBOffset + i] =
                        static_cast<u32>(zeroNodeSlot);
                }
            }

            if (!gpuMemcpyH2D(
                    workspace.mIndices, host.data(),
                    host.size() * sizeof(u32), workspace.mStream->raw()))
                return false;

            workspace.mTauLeaf = tree.mTauLeaf;
            workspace.mMaxTau = tree.mMaxTau;
            workspace.mNodeCount = tree.mNodeCount;
            workspace.mZeroNodeSlot = static_cast<u32>(zeroNodeSlot);
            workspace.mIndicesReady = true;
            return true;
        }
    }

    namespace
    {
    bool rootDigestReceiverDeviceImpl(
        const ReceiverState& state,
        const RingNttContext& ctx,
        const std::shared_ptr<void>& leftTreeSession,
        const std::vector<RnsPoly>* zeta,
        std::span<const block> zetaTaskSeeds,
        u32 rangesPerPoly,
        u32 tauHi,
        bool forceFirstReject,
        RnsPoly& negDPrime,
        DeviceBatchPtr& topInputsNtt,
        DeviceBatchPtr* negDPrimeDevice, CpuBenchmarkState cpuBenchmark, ProtocolCacheScopeView scope)
    {
        if (!cpuBenchmark.mContext) cpuBenchmark.mContext = cpuBenchmarkContext(ctx);
        AutoTimer timer(timingCounter(timingStats(ctx), &TimingStats::mGpuMiscTimeUs));
        if (negDPrimeDevice) negDPrimeDevice->reset();
        const bool seededZeta = !zetaTaskSeeds.empty();
        const u32 randomizerWidth = seededZeta
            ? state.mRootRandomizerWidth
            : (zeta ? static_cast<u32>(zeta->size()) : 0u);
        if (!enabled(ctx) || tauHi == 0 || randomizerWidth == 0u ||
            (!seededZeta && !zeta))
            return bail(ctx, "rootDigest: sizes");
        const bool goldenZetaGeometry =
            ctx.mParams.mPolyModulusDegree == 8192u && ringModulusCount(ctx) == 4u &&
            state.mParams.mShrinkExpand.mGadgetLogBase == 110u &&
            rangesPerPoly >= 2u && rangesPerPoly <= 32u;
        const bool noGoldZetaGeometry = noGoldRootZetaEnabled(ctx.mExecutionOptions.mAdvanced.mProtocol) &&
            ctx.mParams.mPolyModulusDegree == 16384u && ringModulusCount(ctx) == 8u &&
            state.mParams.mShrinkExpand.mGadgetLogBase == 208u &&
            rangesPerPoly >= 2u && rangesPerPoly <= 32u;
        if (seededZeta &&
            (!rootZetaEnabled(ctx.mExecutionOptions.mAdvanced.mProtocol) || (!goldenZetaGeometry && !noGoldZetaGeometry) ||
             [&] {
                 for (std::size_t limb = 0; limb < ringModulusCount(ctx); ++limb)
                     if (ringModulusValue(ctx, limb) >= (u64(1) << 63u)) return true;
                 return false;
             }() ||
             randomizerWidth != 3u ||
             zetaTaskSeeds.size() != 3u * rangesPerPoly))
            return bail(ctx, "rootDigest: root zeta geometry");

        auto tree = std::static_pointer_cast<LevelSession>(leftTreeSession);
        if (!tree || !tree->mImpl) return bail(ctx, "rootDigest: no device left tree");
        auto& treeImpl = *tree->mImpl;

        auto cache = rootCache(state, ctx, cpuBenchmark);
        if (!cache || cache->mPublicBStar.count() != randomizerWidth)
            return bail(ctx, "rootDigest: offline tensors");
        auto ring = cache->mRing;

        auto level = receiverCache(state.mShrinkExpandState, scope);
        // publicB[1 .. tauHi] are the Root's left public matrices, the same slice
        // prepareRootDigestReceiver takes out of buildLencPublicBNtt.
        if (!level || level->mPublicB.count() < static_cast<std::size_t>(1) + tauHi)
            return bail(ctx, "rootDigest: publicB too short");

        const u32 topCols = tauHi + randomizerWidth;
        auto& stream = contextStream(ctx);
        struct PinnedSeedGuard
        {
            GpuStream& mStream;
            bool mPending = false;
            ~PinnedSeedGuard()
            {
                // Error exits may immediately take a host-upload fallback that
                // overwrites staging. Protect that path too, without imposing
                // an extra sync on a successful Root chain.
                if (mPending) mStream.sync();
            }
        } pinnedSeeds{stream};
        Region regKern(GpuStream::RegionKind::Kernel, stream);

        // gadget(yLeft) straight into the first tauHi slots, then zeta into the rest.
        // yLeft is the tree's digest and is already here, so it never crosses.
        auto inputs = std::make_shared<DeviceBatch>();
        inputs->mImpl->mRing = ring;
        if (!inputs->mImpl->mBuf.resize(*ring, topCols, stream)) return false;
        u64* inputsData = inputs->mImpl->mBuf.data(stream);

        if (!launchGadgetDecompose(
                ring->view(stream), treeImpl.mDigest.data(stream), nullptr, 1,
                state.mParams.mShrinkExpand.mGadgetLogBase, 1, tauHi, true, inputsData, nullptr,
                stream.raw()))
            return false;
        if (seededZeta)
        {
            auto& scratch = sampleScratch(stream);
            if (!scratch.ensureCt2Seeds(2u * zetaTaskSeeds.size()) ||
                !scratch.ensureRoundKeys(176u * zetaTaskSeeds.size()) ||
                !scratch.ensureRootZetaRejects(zetaTaskSeeds.size()))
                return false;
            {
                Region regUp(GpuStream::RegionKind::Upload, stream);
                const void* source = zetaTaskSeeds.data();
                if (noGoldZetaGeometry && noGoldRootPinnedSeedsEnabled(ctx.mExecutionOptions.mAdvanced.mProtocol))
                {
                    // No intervening operation writes host staging: the next
                    // user is acc.download below, which queues a D2H AFTER this
                    // H2D on the same stream and then synchronizes. Thus a tiny
                    // pinned copy needs neither an event nor a host drain here.
                    if (u8* pinned = stream.staging(zetaTaskSeeds.size_bytes()))
                    {
                        std::memcpy(pinned, source, zetaTaskSeeds.size_bytes());
                        source = pinned;
                        pinnedSeeds.mPending = true;
                    }
                }
                if (!gpuMemcpyH2D(
                        scratch.mCt2Seeds, source,
                        zetaTaskSeeds.size_bytes(), stream.raw()))
                    return false;
            }
            const std::size_t perPoly =
                static_cast<std::size_t>(ring->rho()) * ring->n();
            u64* zetaOut = inputsData + static_cast<std::size_t>(tauHi) * perPoly;
            const bool sampled = noGoldZetaGeometry
                ? launchRootZetaRho8(
                    ring->view(stream), scratch.mCt2Seeds, scratch.mRoundKeys,
                    scratch.mRootZetaFirstReject, zetaOut,
                    rangesPerPoly, forceFirstReject, stream.raw())
                : launchRootZetaRho4(
                    ring->view(stream), scratch.mCt2Seeds, scratch.mRoundKeys,
                    scratch.mRootZetaFirstReject, zetaOut,
                    rangesPerPoly, forceFirstReject, stream.raw());
            if (!sampled)
                return false;
        }
        else
        {
            Region regUp(GpuStream::RegionKind::Upload, stream);
            if (!inputs->mImpl->mBuf.upload(*zeta, stream, tauHi)) return false;
        }
        if (!launchNttForward(ring->view(stream), inputsData, topCols, nullptr, stream.raw())) return false;

        // Two inner products summed in the evaluation domain, publicB terms first,
        // then bStar - the same order and the same mulAddMod chain the host used,
        // and modular addition is associative so splitting them into two launches
        // gives the same words.
        GpuPolyBuffer acc;
        if (!acc.resize(*ring, 1, stream)) return false;
        {
            std::vector<u32> aIdx(tauHi);
            std::vector<u32> bIdx(tauHi);
            for (u32 i = 0; i < tauHi; ++i)
            {
                aIdx[i] = 1u + i;
                bIdx[i] = i;
            }
            const u32* dA = stream.uploadIdx(aIdx);
            const u32* dB = stream.uploadIdx(bIdx);
            if (!dA || !dB) return false;
            if (!launchInnerProduct(
                    ring->view(stream), level->mPublicB.data(stream), inputsData, dA, dB, tauHi, acc.data(stream),
                    nullptr, 1, false, false, stream.raw()))
                return false;
        }
        {
            const u32 rw = randomizerWidth;
            std::vector<u32> aIdx(rw);
            std::vector<u32> bIdx(rw);
            for (u32 j = 0; j < rw; ++j)
            {
                aIdx[j] = j;
                bIdx[j] = tauHi + j;
            }
            const u32* dA = stream.uploadIdx(aIdx);
            const u32* dB = stream.uploadIdx(bIdx);
            if (!dA || !dB) return false;
            if (!launchInnerProduct(
                    ring->view(stream), cache->mPublicBStar.data(stream), inputsData, dA, dB, rw, acc.data(stream),
                    nullptr, 1, true, false, stream.raw()))
                return false;
        }

        // INTT with the negation folded into the store, matching
        // inverseNtt followed by ringSub(zero, .).
        if (!launchNttInverseFused(
                ring->view(stream), acc.data(stream), 1, nullptr, kElemOpNoneHost, nullptr,
                static_cast<u32>(ElemOp::Negate), nullptr, stream.raw()))
            return false;

        regKern.stop();

        // d' is the one value that has to reach the host: it goes on the wire.
        std::vector<RnsPoly> out;
        {
            Region regDown(GpuStream::RegionKind::Download, stream);
            if (!acc.download(out, stream, 0, 1) || out.size() != 1) return false;
            pinnedSeeds.mPending = false;
        }
        negDPrime = std::move(out[0]);
        if (negDPrimeDevice && rootDPrimeResidentEnabled(ctx.mExecutionOptions.mAdvanced.mProtocol))
        {
            // download() drained this stream, so the coefficient-domain buffer
            // is complete before its owner crosses the socket suspension. The
            // later finalizer may therefore read it from another stream without
            // an event or an extra H2D.
            auto resident = std::make_shared<DeviceBatch>();
            resident->mImpl->mRing = ring;
            resident->mImpl->mBuf = std::move(acc);
            *negDPrimeDevice = std::move(resident);
        }
        topInputsNtt = std::move(inputs);
        return true;
    }
    }

    bool rootDigestReceiverDevice(
        const ReceiverState& state,
        const RingNttContext& ctx,
        const std::shared_ptr<void>& leftTreeSession,
        const std::vector<RnsPoly>& zeta,
        u32 tauHi,
        RnsPoly& negDPrime,
        DeviceBatchPtr& topInputsNtt,
        DeviceBatchPtr* negDPrimeDevice, CpuBenchmarkState cpuBenchmark, ProtocolCacheScopeView scope)
    {
        if (!cpuBenchmark.mContext) cpuBenchmark.mContext = cpuBenchmarkContext(ctx);
        return rootDigestReceiverDeviceImpl(
            state, ctx, leftTreeSession, &zeta, {}, 0u, tauHi, false,
            negDPrime, topInputsNtt, negDPrimeDevice, cpuBenchmark, scope);
    }

    bool rootDigestReceiverDeviceFromZetaSeeds(
        const ReceiverState& state,
        const RingNttContext& ctx,
        const std::shared_ptr<void>& leftTreeSession,
        std::span<const block> taskSeeds,
        u32 rangesPerPoly,
        u32 tauHi,
        bool forceFirstReject,
        RnsPoly& negDPrime,
        DeviceBatchPtr& topInputsNtt,
        DeviceBatchPtr* negDPrimeDevice, CpuBenchmarkState cpuBenchmark, ProtocolCacheScopeView scope)
    {
        if (!cpuBenchmark.mContext) cpuBenchmark.mContext = cpuBenchmarkContext(ctx);
        return rootDigestReceiverDeviceImpl(
            state, ctx, leftTreeSession, nullptr, taskSeeds, rangesPerPoly,
            tauHi, forceFirstReject, negDPrime, topInputsNtt,
            negDPrimeDevice, cpuBenchmark, scope);
    }

    namespace
    {
        bool prefetchRootFinalizeReceiverPriorityDevice(
            const ReceiverState& state,
            const std::shared_ptr<RootDeviceCache>& cache,
            const std::shared_ptr<OfflineCache>& level,
            const std::shared_ptr<LevelSession>& tree,
            const DeviceBatchPtr& topInputsNttDev,
            const DeviceBatchPtr& dPrimeDevice,
            u32 tauHi,
            u32 leftWidth,
            u32 topCols,
            PreparedRootFinalizePtr& prepared)
        {
            auto* workspace = cache->mPriorityWorkspace.get();
            if (!workspace || !workspace->mStream ||
                workspace->mUHi.count() != tauHi ||
                workspace->mAcc.count() != leftWidth ||
                workspace->mPhi.count() != leftWidth ||
                workspace->mLeftEval.count() != leftWidth ||
                !topInputsNttDev || !topInputsNttDev->mImpl ||
                topInputsNttDev->mImpl->mLogicalCount != 0u ||
                topInputsNttDev->mImpl->mRing.get() != cache->mRing.get() ||
                topInputsNttDev->mImpl->mBuf.count() != topCols ||
                !dPrimeDevice || !dPrimeDevice->mImpl ||
                dPrimeDevice->mImpl->mLogicalCount != 0u ||
                dPrimeDevice->mImpl->mRing.get() != cache->mRing.get() ||
                dPrimeDevice->mImpl->mBuf.count() != 1u)
                return bail(state.mShrinkExpandState.mRingFactoryOwner, "root priority prefetch: retained inputs");

            auto& treeImpl = *tree->mImpl;
            auto next = std::make_shared<PreparedRootFinalize>();
            auto& impl = *next->mImpl;
            impl.mState = &state;
            impl.mRing = cache->mRing;
            impl.mRootCacheOwner = cache;
            impl.mLevelCacheOwner = level;
            impl.mTree = tree;
            impl.mTopInputs = topInputsNttDev;
            impl.mDPrime = dPrimeDevice;
            impl.mPriorityWorkspace = workspace;
            impl.mTauHi = tauHi;
            impl.mLeftWidth = leftWidth;
            impl.mTopCols = topCols;
            impl.mProducerStream = workspace->mStream->raw();
            impl.mReadyEvent = gpuEventCreate();
            prepared = std::move(next);
            if (!impl.mReadyEvent) return false;

            // The device allocation and host backing of these immutable pairs
            // were prepared before send. The first call fills them once on this
            // stream; later Root queries issue no index copies at all.
            {
                Region regUp(GpuStream::RegionKind::Upload, *workspace->mStream);
                impl.mWorkQueued = true;
                if (!ensureRootFinalizePriorityIndices(
                        *workspace, *cache, treeImpl, tauHi, leftWidth,
                        topCols))
                    return false;
            }

            Region regKern(
                GpuStream::RegionKind::Kernel, *workspace->mStream);
            const auto& ring = *cache->mRing;

            if (!launchGadgetDecompose(
                    ring.view(*workspace->mStream), dPrimeDevice->mImpl->mBuf.data(*workspace->mStream), nullptr, 1u,
                    state.mParams.mShrinkExpand.mGadgetLogBase, 1u, tauHi,
                    true, workspace->mUHi.data(*workspace->mStream), nullptr,
                    workspace->mStream->raw()) ||
                !launchNttForward(
                    ring.view(*workspace->mStream), workspace->mUHi.data(*workspace->mStream), tauHi, nullptr,
                    workspace->mStream->raw()) ||
                !launchInnerProduct(
                    ring.view(*workspace->mStream), cache->mCtR.data(*workspace->mStream), workspace->mUHi.data(*workspace->mStream),
                    workspace->a(workspace->mCtRPair),
                    workspace->b(workspace->mCtRPair), tauHi,
                    workspace->mAcc.data(*workspace->mStream), nullptr, leftWidth, false, false,
                    workspace->mStream->raw()) ||
                !launchInnerProduct(
                    ring.view(*workspace->mStream), cache->mTopCt.data(*workspace->mStream),
                    topInputsNttDev->mImpl->mBuf.data(*workspace->mStream),
                    workspace->a(workspace->mTopPair),
                    workspace->b(workspace->mTopPair), topCols,
                    workspace->mPhi.data(*workspace->mStream), nullptr, leftWidth, false, false,
                    workspace->mStream->raw()) ||
                !launchInnerProduct(
                    ring.view(*workspace->mStream), cache->mLacctLeft.data(*workspace->mStream),
                    treeImpl.mNodes.data(*workspace->mStream), workspace->a(workspace->mLeftPair),
                    workspace->b(workspace->mLeftPair),
                    workspace->mLeftPair.mTerms,
                    workspace->mLeftEval.data(*workspace->mStream), nullptr, leftWidth, false,
                    true, workspace->mStream->raw()) ||
                !launchElementwise(
                    ring.view(*workspace->mStream), workspace->mPhi.data(*workspace->mStream), nullptr,
                    workspace->mLeftEval.data(*workspace->mStream), nullptr,
                    workspace->mPhi.data(*workspace->mStream), nullptr, leftWidth, ElemOp::Add,
                    workspace->mStream->raw()))
            {
                return false;
            }

            regKern.stop();
            if (!gpuEventRecord(
                    impl.mReadyEvent, workspace->mStream->raw()))
                return false;
            impl.mEventRecorded = true;
            impl.mReady = true;
            return true;
        }
    }

    bool rootFinalizeReceiverPrefetchEnabled(const LogVoleGpuProtocolOptions& options)
    {
        return rootFinalizePriorityPrefetchEnabledImpl(options);
    }

    bool prefetchRootFinalizeReceiverDevice(
        const ReceiverState& state,
        const RingNttContext& ctx,
        const RnsPoly& dPrime,
        const DeviceBatchPtr& topInputsNttDev,
        const std::shared_ptr<void>& leftTreeSession,
        u32 tauHi,
        u32 leftWidth,
        PreparedRootFinalizePtr& prepared,
        const DeviceBatchPtr& dPrimeDevice, CpuBenchmarkState cpuBenchmark, ProtocolCacheScopeView scope)
    {
        if (!cpuBenchmark.mContext) cpuBenchmark.mContext = cpuBenchmarkContext(ctx);
        AutoTimer timer(timingCounter(timingStats(ctx), &TimingStats::mGpuMiscTimeUs));
        prepared.reset();
        if (!enabled(ctx) || !rootFinalizePriorityPrefetchEnabledImpl(ctx.mExecutionOptions.mAdvanced.mProtocol))
            return false;

        // Extend the accepted GoldenSeed priority prefix to the exact
        // NoGoldenSeed shape. The six prefix operations and index construction
        // already use runtime ring dimensions; only their admission was fixed.
        constexpr u32 kProductionN = 8192u;
        constexpr u32 kProductionRho = 4u;
        constexpr u32 kProductionTauHi = 1u;
        constexpr u32 kProductionLeftWidth = 4u;
        constexpr u32 kProductionGadgetBits = 110u;
        const bool goldenGeometry =
            ctx.mParams.mPolyModulusDegree == kProductionN &&
            ringModulusCount(ctx) == kProductionRho &&
            leftWidth == kProductionLeftWidth &&
            state.mParams.mShrinkExpand.mGadgetLogBase == kProductionGadgetBits;
        const bool noGoldGeometry = leftWidth == 8u &&
            rootPriorityNoGoldGeometry(ctx.mParams.mPolyModulusDegree,
                static_cast<u32>(ringModulusCount(ctx)),
                state.mParams.mShrinkExpand.mGadgetLogBase, ctx.mExecutionOptions.mAdvanced.mProtocol);
        if ((!goldenGeometry && !noGoldGeometry) ||
            tauHi != kProductionTauHi ||
            state.mRootRandomizerWidth != 3u ||
            !validateRingPolyShape(dPrime, ctx.mParams))
        {
            return bail(ctx, "root prefetch: production geometry");
        }

        auto tree = std::static_pointer_cast<LevelSession>(leftTreeSession);
        if (!tree || !tree->mImpl || !topInputsNttDev || !topInputsNttDev->mImpl)
            return bail(ctx, "root prefetch: missing device inputs");

        auto cache = rootCache(state, ctx, cpuBenchmark);
        auto level = receiverCache(state.mShrinkExpandState, scope);
        if (!cache || !level || !cache->mRing)
            return bail(ctx, "root prefetch: device caches");
        const u32 topCols = cache->mTopCols;
        if (topCols != tauHi + state.mRootRandomizerWidth ||
            topInputsNttDev->count() != topCols ||
            cache->mCtRCols != tauHi ||
            cache->mTopCt.count() != static_cast<std::size_t>(leftWidth) * topCols ||
            cache->mCtR.count() != static_cast<std::size_t>(leftWidth) * tauHi ||
            level->mPublicA.count() < leftWidth)
        {
            return bail(ctx, "root prefetch: tensor shapes");
        }

        return prefetchRootFinalizeReceiverPriorityDevice(
            state, cache, level, tree, topInputsNttDev, dPrimeDevice,
            tauHi, leftWidth, topCols, prepared);
    }

    bool rootFinalizeReceiverDevice(
        const ReceiverState& state,
        const RingNttContext& ctx,
        const RnsPoly& dPrime,
        block dPrimeHash,
        const RnsPoly& skPrime,
        const std::vector<RnsPoly>& topInputsNtt,
        const DeviceBatch* topInputsNttDev,
        const std::shared_ptr<void>& leftTreeSession,
        std::span<const u8> seed,
        u64 sid,
        u32 tauHi,
        u32 leftWidth,
        DeviceBatchPtr& rootKey,
        PreparedRootFinalize* prepared,
        const DeviceBatch* dPrimeDevice, CpuBenchmarkState cpuBenchmark, ProtocolCacheScopeView scope)
    {
        if (!cpuBenchmark.mContext) cpuBenchmark.mContext = cpuBenchmarkContext(ctx);
        AutoTimer timer(timingCounter(timingStats(ctx), &TimingStats::mGpuMiscTimeUs));
        if (!enabled(ctx) || tauHi == 0 || leftWidth == 0 || seed.empty()) return bail(ctx, "root: sizes");

        auto tree = std::static_pointer_cast<LevelSession>(leftTreeSession);
        if (!tree || !tree->mImpl) return bail(ctx, "root: no device left tree");
        auto& treeImpl = *tree->mImpl;

        auto cache = rootCache(state, ctx, cpuBenchmark);
        if (!cache) return bail(ctx, "root: offline tensor upload failed");
        auto ring = cache->mRing;
        const u32 rho = ring->rho();

        // publicA is derived from a fixed nonce with the row index as the only
        // varying input, so the level cache's mu-row table has the Root's leftWidth
        // rows as its prefix - the same table lheDec would have built for
        // publicCount = leftWidth.
        auto level = receiverCache(state.mShrinkExpandState, scope);
        if (!level || level->mPublicA.count() < leftWidth) return bail(ctx, "root: publicA too short");

        const u32 topCols = cache->mTopCols;
        const bool haveTopDev = topInputsNttDev && topInputsNttDev->count() == topCols;
        if (topCols != tauHi + state.mRootRandomizerWidth ||
            (!haveTopDev && topInputsNtt.size() != topCols) ||
            cache->mCtRCols != tauHi ||
            cache->mTopCt.count() != static_cast<std::size_t>(leftWidth) * topCols ||
            cache->mCtR.count() != static_cast<std::size_t>(leftWidth) * tauHi)
        {
            return bail(ctx, "root: tensor shapes");
        }

        auto& stream = contextStream(ctx);
        Region regKern(GpuStream::RegionKind::Kernel, stream);

        GpuPolyBuffer acc;
        GpuPolyBuffer phi;
        struct ReturnPriorityWorkspaceBuffers
        {
            RootFinalizePriorityWorkspace* mWorkspace = nullptr;
            GpuPolyBuffer* mAcc = nullptr;
            GpuPolyBuffer* mPhi = nullptr;

            ~ReturnPriorityWorkspaceBuffers()
            {
                if (!mWorkspace) return;
                mWorkspace->mAcc = std::move(*mAcc);
                mWorkspace->mPhi = std::move(*mPhi);
            }
        } returnPriorityBuffers{ nullptr, &acc, &phi };
        bool havePreparedBase = false;
        PreparedRootFinalize::Impl* consumedPrepared = nullptr;
        if (prepared && prepared->mImpl)
        {
            auto& p = *prepared->mImpl;
            auto* priorityWorkspace = static_cast<
                RootFinalizePriorityWorkspace*>(p.mPriorityWorkspace);
            const bool buffersMatch = priorityWorkspace &&
                cache->mPriorityWorkspace.get() == priorityWorkspace &&
                priorityWorkspace->mAcc.count() == leftWidth &&
                priorityWorkspace->mPhi.count() == leftWidth &&
                p.mDPrime.get() == dPrimeDevice;
            const bool metadataMatches =
                p.mReady && !p.mConsumed && p.mEventRecorded && p.mReadyEvent &&
                p.mState == &state && p.mRing.get() == ring.get() &&
                p.mRootCacheOwner.get() == cache.get() &&
                p.mLevelCacheOwner.get() == level.get() &&
                p.mTree.get() == tree.get() &&
                p.mTopInputs.get() == topInputsNttDev &&
                p.mTauHi == tauHi && p.mLeftWidth == leftWidth &&
                p.mTopCols == topCols && buffersMatch;
            if (metadataMatches &&
                gpuStreamWaitEvent(stream.raw(), p.mReadyEvent))
            {
                // The event wait transfers both buffers to this stream. Their
                // suffix use is ordered exactly like ordinary monolithic
                // locals. The prefetch leases cache-owned buffers and returns
                // their ownership on every success/failure exit.
                // The coroutine may resume on another host thread and thus
                // another registered receiver stream. Future releases must
                // be ordered on the stream that now owns every suffix use.
                acc = std::move(priorityWorkspace->mAcc);
                phi = std::move(priorityWorkspace->mPhi);
                returnPriorityBuffers.mWorkspace = priorityWorkspace;
                p.mConsumed = true;
                consumedPrepared = &p;
                havePreparedBase = true;
            }
        }

        // Per-query inputs. dPrime and skPrime come off the wire; topInputsNtt is
        // NTT(gadget(yLeft) ++ zeta), which the digest step already built. With
        // operand residency, dPrime is the synchronized coefficient-domain
        // buffer retained by the digest step and only skPrime is uploaded here.
        const bool haveResidentDPrime =
            !havePreparedBase && rootDPrimeResidentEnabled(ctx.mExecutionOptions.mAdvanced.mProtocol) &&
            dPrimeDevice && dPrimeDevice->mImpl &&
            !dPrimeDevice->mImpl->mLogicalCount &&
            dPrimeDevice->mImpl->mRing == ring &&
            dPrimeDevice->mImpl->mBuf.count() == 1u &&
            dPrime.mCoeffs.size() == ring->polyWords();
        GpuPolyBuffer scalars;   // legacy: [dPrime, skPrime], resident: [skPrime]
        GpuPolyBuffer topInOwned;
        const u32 skPrimeSlot =
            (havePreparedBase || haveResidentDPrime) ? 0u : 1u;
        if (!scalars.resize(
                *ring, (havePreparedBase || haveResidentDPrime) ? 1u : 2u, stream))
            return false;
        {
            Region regUp(GpuStream::RegionKind::Upload, stream);
            if (havePreparedBase || haveResidentDPrime)
            {
                if (!scalars.upload(
                        std::span<const RnsPoly>(&skPrime, 1u), stream))
                    return false;
                if (havePreparedBase)
                {
                    // The upload drain consumes the prefetch producer event, so
                    // its abandoned-work cleanup no longer needs a later sync.
                    consumedPrepared->mProducerKnownComplete = true;
                }
            }
            else
            {
                // Exact legacy path: one batched upload rather than two
                // single-polynomial uploads that would drain between them.
                const RnsPoly pair[2] = { dPrime, skPrime };
                if (!scalars.upload(std::span<const RnsPoly>(pair, 2), stream))
                    return false;
            }
            // Normally the digest step left these on the device; the upload is only
            // for a caller that ran that step on the host.
            if (!havePreparedBase && !haveTopDev &&
                (!topInOwned.resize(*ring, topCols, stream) || !topInOwned.upload(topInputsNtt, stream)))
                return false;
        }
        const u64* topInData =
            haveTopDev ? topInputsNttDev->mImpl->mBuf.data(stream) : topInOwned.data(stream);

        // ---- lheApplyCt1Trunc: acc[row] = sum_col ctR[row][col] * NTT(u[col]) ----
        GpuPolyBuffer uHi;
        if (!havePreparedBase)
        {
            const u64* dPrimeData = haveResidentDPrime
                ? dPrimeDevice->mImpl->mBuf.data(stream)
                : scalars.data(stream);
            if (!uHi.resize(*ring, tauHi, stream) ||
                !launchGadgetDecompose(
                    ring->view(stream), dPrimeData, nullptr, 1,
                    state.mParams.mShrinkExpand.mGadgetLogBase, 1, tauHi,
                    true, uHi.data(stream), nullptr, stream.raw()) ||
                !launchNttForward(
                    ring->view(stream), uHi.data(stream), tauHi, nullptr, stream.raw()) ||
                !acc.resize(*ring, leftWidth, stream))
            {
                return false;
            }
            {
                std::vector<u32> aIdx(
                    static_cast<std::size_t>(leftWidth) * tauHi);
                std::vector<u32> bIdx(aIdx.size());
                for (u32 row = 0; row < leftWidth; ++row)
                {
                    for (u32 col = 0; col < tauHi; ++col)
                    {
                        aIdx[row * tauHi + col] =
                            row * cache->mCtRCols + col;
                        bIdx[row * tauHi + col] = col;
                    }
                }
                const u32* dA = stream.uploadIdx(aIdx);
                const u32* dB = stream.uploadIdx(bIdx);
                if (!dA || !dB ||
                    !launchInnerProduct(
                        ring->view(stream), cache->mCtR.data(stream), uHi.data(stream), dA,
                        dB, tauHi, acc.data(stream), nullptr, leftWidth, false,
                        false, stream.raw()))
                {
                    return false;
                }
            }
        }

        // ---- lheDec: acc[row] -= publicA[row] * NTT(skPrime) ----
        // skPrime is transformed in place; nothing reads its coefficient form
        // again. In the monolithic layout it remains slot 1 (dPrime is slot 0),
        // while the split suffix needs only the single slot 0 upload.
        {
            const std::vector<u32> skSlot{ skPrimeSlot };
            const u32* dSk = stream.uploadIdx(skSlot);
            if (!dSk) return false;
            if (!launchNttForward(ring->view(stream), scalars.data(stream), 1, dSk, stream.raw())) return false;
        }

        {
            std::vector<u32> aIdx(leftWidth);
            std::vector<u32> bIdx(leftWidth);
            for (u32 row = 0; row < leftWidth; ++row)
            {
                aIdx[row] = row;
                bIdx[row] = skPrimeSlot; // skPrime, now in the NTT domain
            }
            const u32* dA = stream.uploadIdx(aIdx);
            const u32* dB = stream.uploadIdx(bIdx);
            if (!dA || !dB) return false;
            if (!launchInnerProduct(
                    ring->view(stream), level->mPublicA.data(stream), scalars.data(stream), dA, dB, 1, acc.data(stream), nullptr,
                    leftWidth, false, false, stream.raw(), true))
                return false;
        }

        // ---- evalRootTopCtNtt: phi[row] = sum_col topCt[row][col] * topIn[col] ----
        if (!havePreparedBase)
        {
            if (!phi.resize(*ring, leftWidth, stream)) return false;
            {
                std::vector<u32> aIdx(
                    static_cast<std::size_t>(leftWidth) * topCols);
                std::vector<u32> bIdx(aIdx.size());
                for (u32 row = 0; row < leftWidth; ++row)
                {
                    for (u32 col = 0; col < topCols; ++col)
                    {
                        aIdx[row * topCols + col] = row * topCols + col;
                        bIdx[row * topCols + col] = col;
                    }
                }
                const u32* dA = stream.uploadIdx(aIdx);
                const u32* dB = stream.uploadIdx(bIdx);
                if (!dA || !dB ||
                    !launchInnerProduct(
                        ring->view(stream), cache->mTopCt.data(stream), topInData, dA,
                        dB, topCols, phi.data(stream), nullptr, leftWidth, false,
                        false, stream.raw()))
                {
                    return false;
                }
            }
        }

        // ---- lencEvalTrunc over the device-resident left tree, negated ----
        // The same per-leaf root-path walk lencEvalTrunc does, expressed as one
        // inner product per leaf. `negate` reproduces its explicit q - c loop.
        GpuPolyBuffer leftEval;
        if (!havePreparedBase)
        {
            if (!leftEval.resize(*ring, leftWidth, stream)) return false;
            {
                const u32 levels = cache->mLevels;
                const u32 width = cache->mWidth;
                const u32 tauLeaf = treeImpl.mTauLeaf;
                const u32 ctTauMax = treeImpl.mMaxTau;
                if (levels == 0 || width < leftWidth)
                    return bail(ctx, "root: left lacct geometry");

                const u32 terms = 2u * levels * ctTauMax;
                std::vector<u32> aIdx(
                    static_cast<std::size_t>(leftWidth) * terms, 0);
                std::vector<u32> bIdx(aIdx.size(), 0);
                for (u32 leaf = 0; leaf < leftWidth; ++leaf)
                {
                    u32 parent = 0;
                    u32 t = 0;
                    for (u32 levelIdx = 0; levelIdx < levels; ++levelIdx)
                    {
                        const u32 left = (2u * parent) + 1u;
                        const u32 right = left + 1u;
                        const u32 activeTau =
                            (levelIdx == levels - 1u) ? tauLeaf : tauHi;
                        const u32 row = levelIdx * width + leaf;
                        for (u32 c = 0; c < activeTau; ++c)
                        {
                            aIdx[leaf * terms + t] =
                                row * cache->mLacctCols + c;
                            bIdx[leaf * terms + t] = static_cast<u32>(
                                treeImpl.nodeSlot(0, left, c));
                            ++t;
                            aIdx[leaf * terms + t] =
                                row * cache->mLacctCols + ctTauMax + c;
                            bIdx[leaf * terms + t] = static_cast<u32>(
                                treeImpl.nodeSlot(0, right, c));
                            ++t;
                        }
                        const u32 bit =
                            (leaf >> (levels - 1u - levelIdx)) & 1u;
                        parent = bit == 0u ? left : right;
                    }
                    // Pad against the ladder's permanent zero node exactly as
                    // the monolithic path did.
                    for (; t < terms; ++t)
                    {
                        aIdx[leaf * terms + t] = 0;
                        bIdx[leaf * terms + t] = static_cast<u32>(
                            treeImpl.zeroNodeSlot());
                    }
                }
                const u32* dA = stream.uploadIdx(aIdx);
                const u32* dB = stream.uploadIdx(bIdx);
                if (!dA || !dB ||
                    !launchInnerProduct(
                        ring->view(stream), cache->mLacctLeft.data(stream),
                        treeImpl.mNodes.data(stream), dA, dB, terms,
                        leftEval.data(stream), nullptr, leftWidth, false, true,
                        stream.raw()))
                {
                    return false;
                }
            }

            if (!launchElementwise(
                    ring->view(stream), phi.data(stream), nullptr, leftEval.data(stream), nullptr,
                    phi.data(stream), nullptr, leftWidth, ElemOp::Add,
                    stream.raw()))
            {
                return false;
            }
        }

        // ---- the row loop: tbm = acc - (top + left) -----------------------
        if (!launchElementwise(
                ring->view(stream), acc.data(stream), nullptr, phi.data(stream), nullptr, acc.data(stream), nullptr, leftWidth,
                ElemOp::Sub, stream.raw()))
            return false;

        // ---- buildHashedCt2, then the inverse transform with the add folded in ----
        GpuPolyBuffer ctK;
        if (!sampleCt2Batch(
                *ring, *level, state.mParams.mShrinkExpand.mRing, 1, leftWidth, seed, sid, 0,
                dPrimeHash, ctK, stream))
            return false;
        if (!launchNttInverseFused(
                ring->view(stream), acc.data(stream), leftWidth, nullptr, kElemOpNoneHost, nullptr,
                static_cast<u32>(ElemOp::Add), ctK.data(stream), stream.raw()))
            return false;

        // ---- denoise comb + aggregate ----
        if (leftWidth % rho != 0) return bail(ctx, "root: leftWidth not a multiple of rho");
        const std::size_t denoised = leftWidth / rho;
        if (denoised % tauHi != 0) return bail(ctx, "root: denoised count not a multiple of tau");
        const std::size_t aggCount = denoised / tauHi;
        if (!ring->denoiseReady()) return bail(ctx, "root: denoise tables unavailable");

        GpuPolyBuffer mid;
        if (!mid.resize(*ring, denoised, stream)) return false;
        if (!denoiseComb(*ring, acc.data(stream), mid.data(stream), static_cast<u32>(denoised), stream))
            return false;

        auto result = std::make_shared<DeviceBatch>();
        result->mImpl->mRing = ring;
        if (tauHi == 1)
        {
            // seedLabelAgg with tau == 1 is the identity.
            result->mImpl->mBuf = std::move(mid);
        }
        else
        {
            if (!result->mImpl->mBuf.resize(*ring, aggCount, stream)) return false;
            if (!launchAggregate(
                    ring->view(stream), mid.data(stream), tauHi, result->mImpl->mBuf.data(stream),
                    static_cast<u32>(aggCount), stream.raw()))
                return false;
        }

        regKern.stop();
        rootKey = std::move(result);
        return true;
    }

    // ---- ct2 sampling -----------------------------------------------------

    namespace
    {
        bool sampleCt2BatchWithScratch(
            const GpuRing& ring,
            const OfflineCache& cache,
            const RingParams& params,
            u32 chunkCount,
            u32 mu,
            std::span<const u8> seed,
            u64 sid,
            u64 instanceBase,
            block maskDigestHash,
            GpuPolyBuffer& out,
            GpuStream& stream,
            SampleScratch& scratch)
        {
            const std::size_t total = static_cast<std::size_t>(chunkCount) * mu;
            if (!out.resize(ring, total, stream)) return false;

            if (total > std::numeric_limits<u32>::max() ||
                !scratch.ensureSeeds(total * 8) || !scratch.ensureRoundKeys(total * 176)) return false;
            u32* rejectEpochs = nullptr;
            u32 rejectEpoch = 0;
            if (!scratch.nextRejectEpoch(total, stream.raw(), rejectEpochs, rejectEpoch)) return false;

            // The 16-byte commitment is computed once when the Root digest becomes
            // authoritative and reused at every recursion level. The remaining
            // per-chunk derivations are independent GPU threads.
            if (seed.size() == 16)
            {
                if (!scratch.ensurePrefix() ||
                    !scratch.ensureCt2Seeds(static_cast<std::size_t>(chunkCount) * 2))
                    return false;

                // A single Blake2b chain over the 256 KiB digest takes ~0.26 ms,
                // so repeating it here starved the device before small levels.
                // Field order and widths mirror
                // deriveSeedInstanceBlockFromDigestHash exactly. fallbackNonce is
                // mu, matching buildHashedCt2; slot 3 is filled per chunk.
                u64 prefix[9];
                prefix[0] = 0x4C4F47564F4C4354ull;              // label
                prefix[1] = sid;
                prefix[2] = static_cast<u64>(mu);               // fallbackNonce
                prefix[3] = 0;                                  // instanceIdx
                prefix[4] = static_cast<u64>(seed.size());
                std::memcpy(&prefix[5], &maskDigestHash, 16);
                std::memcpy(&prefix[7], seed.data(), 16);

                if (!scratch.uploadPrefix(prefix, 9u, stream.raw()))
                    return false;

                if (!launchCt2Seeds(
                        scratch.mPrefix, instanceBase, chunkCount, mu, kCt2DomainTag,
                        params.mPolyModulusDegree,
                        static_cast<u64>(params.mCoeffModulusBits.size()), scratch.mCt2Seeds,
                        scratch.mSeeds, scratch.mRoundKeys, stream.raw()))
                    return false;
            }
            else
            {
                // Fallback for seed sizes the aligned kernel does not handle.
                std::vector<u64> seeds;
                seeds.reserve(total * 8);
                for (u32 c = 0; c < chunkCount; ++c)
                {
                    const u64 nonce = instanceBase + c;
                    const block ct2Seed = deriveSeedInstanceBlockFromDigestHash(
                        seed, sid, maskDigestHash, nonce, mu);
                    appendPolySeeds(params, ct2Seed, kCt2DomainTag, mu, seeds);
                }
                if (seeds.size() != total * 8) return false;
                if (!gpuMemcpyH2D(
                        scratch.mSeeds, seeds.data(), seeds.size() * sizeof(u64), stream.raw()))
                    return false;
            }

            return launchSampleUniformPolyAes(
                ring.view(stream), scratch.mSeeds, cache.mMaxMultiple, out.data(stream), nullptr,
                static_cast<u32>(total), scratch.mRoundKeys, scratch.mRoundKeyBytes,
                rejectEpochs, rejectEpoch, stream.raw());
        }

        bool sampleCt2Batch(
            const GpuRing& ring,
            const OfflineCache& cache,
            const RingParams& params,
            u32 chunkCount,
            u32 mu,
            std::span<const u8> seed,
            u64 sid,
            u64 instanceBase,
            block maskDigestHash,
            GpuPolyBuffer& out,
            GpuStream& stream)
        {
            return sampleCt2BatchWithScratch(
                ring, cache, params, chunkCount, mu, seed, sid, instanceBase,
                maskDigestHash, out, stream, sampleScratch(stream));
        }
    }

    bool topSenderCt2PrefetchEnabled(const LogVoleGpuProtocolOptions& options)
    {
        return topSenderCt2PrefetchEnabledImpl(options);
    }

    u32 topSenderCt2PrefetchLevels(u32 adaptiveDefault, const LogVoleGpuProtocolOptions& options)
    {
        return topSenderCt2PrefetchLevelsImpl(adaptiveDefault, options);
    }

    bool prefetchSenderCt2(
        const ShrinkExpandSenderState& state,
        std::span<const u8> seed,
        u64 sid,
        u64 instanceBase,
        block maskDigestHash,
        u32 chunkCount,
        PreparedSenderCt2Ptr& prepared, ProtocolCacheScopeView scope)
    {
        const LogVoleGpuProtocolOptions defaults;
        const auto& options = state.mRingFactoryOwner ? state.mRingFactoryOwner->mExecutionOptions.mAdvanced.mProtocol : defaults;
        AutoTimer timer(timingCounter(timingStats(state.mRingFactoryOwner), &TimingStats::mGpuSenderTimeUs));
        prepared.reset();
        if (!enabled(state.mRingFactoryOwner) || !topSenderCt2PrefetchEnabledImpl(options) || seed.size() != 16u ||
            chunkCount == 0u)
        {
            return false;
        }

        auto cache = senderCache(state, scope);
        if (!cache || !cache->mRing) return false;
        auto ring = cache->mRing;
        const u32 mu = state.mParams.mMu;
        if (mu == 0u || cache->mPublicA.count() != mu) return false;

        if (!state.mRingFactoryOwner || !state.mRingFactoryOwner->mGpuExecution) return false;
        auto& sampleStream = contextSampleStream(*state.mRingFactoryOwner);

        auto next = std::make_unique<PreparedSenderCt2>();
        auto& impl = *next->mImpl;
        impl.mState = &state;
        impl.mRing = ring;
        impl.mSeed.assign(seed.begin(), seed.end());
        impl.mSid = sid;
        impl.mInstanceBase = instanceBase;
        impl.mMaskDigestHash = maskDigestHash;
        impl.mChunkCount = chunkCount;
        impl.mMu = mu;
        impl.mProducerOwner = sampleStream.allocationOwner();
        impl.mReadyEvent = gpuEventCreate();
        if (!impl.mReadyEvent) return false;

        Region regKern(GpuStream::RegionKind::Kernel, sampleStream);
        if (!sampleCt2BatchWithScratch(
                *ring, *cache, state.mParams.mRing, chunkCount, mu, seed, sid,
                instanceBase, maskDigestHash, impl.mCt2, sampleStream,
                senderPrefetchSampleScratch(sampleStream)) ||
            !gpuEventRecord(impl.mReadyEvent, sampleStream.raw()))
        {
            return false;
        }
        impl.mEventRecorded = true;
        prepared = std::move(next);
        return true;
    }

    namespace
    {
        constexpr u64 kReceiverPrefetchMaxTrackedBytes = u64{ 2 } << 30;
        constexpr u32 kReceiverPrefetchAdaptiveLevels = 3u;

        bool checkedMul(u64 a, u64 b, u64& out)
        {
            if (a != 0u && b > std::numeric_limits<u64>::max() / a) return false;
            out = a * b;
            return true;
        }

        // DeviceAllocator rounds every request to a power-of-two bucket with a
        // 4 KiB floor. Account for exactly the allocation retained by each live
        // prefetch output/scratch pointer rather than only its logical payload.
        bool addTrackedAllocation(u64 requested, u64& total)
        {
            if (requested == 0u) return true;
            constexpr u64 kMinBucket = u64{ 1 } << 12;
            constexpr u64 kMaxBucket = u64{ 1 } << 39;
            u64 bucket = kMinBucket;
            while (bucket < requested && bucket < kMaxBucket) bucket <<= 1u;
            if (bucket < requested || total > std::numeric_limits<u64>::max() - bucket)
                return false;
            total += bucket;
            return true;
        }

        bool receiverCt2TrackedAllocation(
            std::span<const ShrinkExpandReceiverState* const> states,
            std::span<const u32> chunkCounts,
            u32 levels,
            u64& trackedBytes)
        {
            trackedBytes = 0u;
            if (levels == 0u || states.size() < levels || chunkCounts.size() < levels)
                return false;

            u64 seedBytes = 0u;
            u64 ct2SeedBytes = 0u;
            u64 roundKeyBytes = 0u;
            u64 rejectBytes = 0u;

            for (u32 level = 0; level < levels; ++level)
            {
                const auto* state = states[level];
                const u32 chunks = chunkCounts[level];
                if (!state || chunks == 0u) return false;

                const auto& ringParams = state->mParams.mRing;
                const u32 mu = state->mParams.mMu;
                const u64 polyWords = static_cast<u64>(ringPolyCoeffCount(ringParams));
                if (mu == 0u || polyWords == 0u) return false;

                u64 rows = 0u;
                u64 outputBytes = 0u;
                if (!checkedMul(chunks, mu, rows) ||
                    rows > std::numeric_limits<u32>::max() ||
                    !checkedMul(rows, polyWords, outputBytes) ||
                    !checkedMul(outputBytes, sizeof(u64), outputBytes) ||
                    !addTrackedAllocation(outputBytes, trackedBytes))
                {
                    return false;
                }

                u64 request = 0u;
                if (!checkedMul(rows, 8u * sizeof(u64), request)) return false;
                seedBytes = std::max(seedBytes, request);
                if (!checkedMul(rows, 176u, request)) return false;
                roundKeyBytes = std::max(roundKeyBytes, request);
                if (!checkedMul(chunks, 2u * sizeof(u64), request)) return false;
                ct2SeedBytes = std::max(ct2SeedBytes, request);

                if (polyWords > std::numeric_limits<u32>::max()) return false;
                if (!checkedMul(rows, sizeof(u32), request)) return false;
                rejectBytes = std::max(rejectBytes, request);
            }

            // The 16-byte online seed path always creates the fixed nine-word
            // prefix. Every other scratch field grows to the maximum required by
            // the FIFO sequence and remains one live allocation.
            return addTrackedAllocation(9u * sizeof(u64), trackedBytes) &&
                   addTrackedAllocation(seedBytes, trackedBytes) &&
                   addTrackedAllocation(ct2SeedBytes, trackedBytes) &&
                   addTrackedAllocation(roundKeyBytes, trackedBytes) &&
                   addTrackedAllocation(rejectBytes, trackedBytes);
        }

    }

    u32 receiverCt2PrefetchLevels(
        u64 totalLabelCount,
        std::span<const ShrinkExpandReceiverState* const> states,
        std::span<const u32> chunkCounts, const LogVoleGpuProtocolOptions& options)
    {
        const auto mode = receiverCt2PrefetchMode(options);
        if (mode == LogVoleChoice::Disabled) return 0u;

        const auto levels = options.mReceiverCt2PrefetchLevels;
        if (mode == LogVoleChoice::Enabled)
        {
            return levels >= 1
                ? static_cast<u32>(levels)
                : kReceiverPrefetchAdaptiveLevels;
        }

        constexpr u64 kLabels24 = u64{ 1 } << 24;
        constexpr u64 kLabels25 = u64{ 1 } << 25;
        if (totalLabelCount != kLabels24 && totalLabelCount != kLabels25)
            return 0u;

        u64 trackedBytes = 0u;
        if (!receiverCt2TrackedAllocation(
                states, chunkCounts, kReceiverPrefetchAdaptiveLevels,
                trackedBytes) ||
            trackedBytes > kReceiverPrefetchMaxTrackedBytes)
        {
            return 0u;
        }
        return levels >= 1
            ? static_cast<u32>(levels)
            : kReceiverPrefetchAdaptiveLevels;
    }

    bool prefetchReceiverCt2(
        const ShrinkExpandReceiverState& state,
        std::span<const u8> seed,
        u64 sid,
        u64 instanceBase,
        block maskDigestHash,
        u32 chunkCount,
        PreparedReceiverCt2Ptr& prepared, ProtocolCacheScopeView scope)
    {
        const LogVoleGpuProtocolOptions defaults;
        const auto& options = state.mRingFactoryOwner ? state.mRingFactoryOwner->mExecutionOptions.mAdvanced.mProtocol : defaults;
        AutoTimer timer(timingCounter(timingStats(state.mRingFactoryOwner), &TimingStats::mGpuExpandTimeUs));
        prepared.reset();
        if (!enabled(state.mRingFactoryOwner) || receiverCt2PrefetchMode(options) == LogVoleChoice::Disabled ||
            seed.size() != 16u ||
            chunkCount == 0u)
        {
            return false;
        }

        auto cache = receiverCache(state, scope);
        if (!cache || !cache->mRing) return false;
        auto ring = cache->mRing;
        const u32 mu = state.mParams.mMu;
        if (mu == 0u || cache->mPublicA.count() != mu) return false;

        if (!state.mRingFactoryOwner || !state.mRingFactoryOwner->mGpuExecution) return false;
        auto& sampleStream = contextSampleStream(*state.mRingFactoryOwner);

        auto next = std::make_unique<PreparedReceiverCt2>();
        auto& impl = *next->mImpl;
        impl.mState = &state;
        impl.mRing = ring;
        impl.mSeed.assign(seed.begin(), seed.end());
        impl.mSid = sid;
        impl.mInstanceBase = instanceBase;
        impl.mMaskDigestHash = maskDigestHash;
        impl.mChunkCount = chunkCount;
        impl.mMu = mu;
        impl.mProducerOwner = sampleStream.allocationOwner();
        impl.mReadyEvent = gpuEventCreate();
        if (!impl.mReadyEvent) return false;

        Region regKern(GpuStream::RegionKind::Kernel, sampleStream);
        if (!sampleCt2BatchWithScratch(
                *ring, *cache, state.mParams.mRing, chunkCount, mu, seed, sid,
                instanceBase, maskDigestHash, impl.mCt2, sampleStream,
                receiverPrefetchSampleScratch(sampleStream)) ||
            !gpuEventRecord(impl.mReadyEvent, sampleStream.raw()))
        {
            return false;
        }
        impl.mEventRecorded = true;
        prepared = std::move(next);
        return true;
    }

    // ---- receiver expand --------------------------------------------------

    namespace
    {
    bool expandReceiverChunksImpl(
        const ShrinkExpandReceiverState& state,
        LevelSession& session,
        std::span<const RnsPoly> skXHost,
        DeviceBatch* skXDev,
        std::span<const u8> seed,
        u64 sid,
        u64 instanceBase,
        block maskDigestHash,
        u32 outPerChunk,
        u32 totalOut,
        bool wantHostOutput,
        std::vector<RnsPoly>& tbm,
        DeviceBatchPtr& tbmDev,
        PreparedReceiverCt2* preparedCt2, ProtocolCacheScopeView scope)
    {
        AutoTimer timer(timingCounter(timingStats(state.mRingFactoryOwner), &TimingStats::mGpuExpandTimeUs));
        const std::span<const RnsPoly> skX = skXHost;
        if (!enabled(state.mRingFactoryOwner) || !session.valid()) return false;
        auto& impl = *session.mImpl;
        auto ring = impl.mRing;
        auto cache = impl.mCache;
        const u32 chunkCount = impl.mChunkCount;
        const u32 mu = state.mParams.mMu;
        const u32 tauHi = impl.mTauHi;
        const u32 rho = ring->rho();
        const u32 skXCount = skXDev ? static_cast<u32>(skXDev->count()) : static_cast<u32>(skX.size());
        if (skXCount != chunkCount || mu == 0)
        {
            if (debugEnabled(state.mRingFactoryOwner))
            {
                std::fprintf(
                    stderr, "[logvole-gpu] expand: skXCount=%u chunkCount=%u mu=%u totalOut=%u\n",
                    skXCount, chunkCount, mu, totalOut);
            }
            return bail(state.mRingFactoryOwner, "expand: skX count mismatch");
        }
        if (cache->mCt1Cols != tauHi) return bail(state.mRingFactoryOwner, "expand: ct1 cols mismatch");

        if (!state.mRingFactoryOwner || !state.mRingFactoryOwner->mGpuExecution) return false;
        auto& stream = contextStream(*state.mRingFactoryOwner);
        stream.reset();

        Region regKern(GpuStream::RegionKind::Kernel, stream);

        // ct2 sampling is independent of this level's arithmetic chain. A
        // recycled sampler buffer still needs the write-after-read edge from
        // its previous consumer. Cross-recursion prefetch instead owns separate
        // output until this exact ancestor consumes it; a mismatch or failed
        // event wait falls back to the same seeded synchronous sampling path.
        bool havePreparedCt2 = false;
        if (preparedCt2 && preparedCt2->mImpl)
        {
            auto& prepared = *preparedCt2->mImpl;
            const bool sameSeed = prepared.mSeed.size() == seed.size() &&
                                  std::equal(seed.begin(), seed.end(), prepared.mSeed.begin());
            const std::size_t expectedCount = static_cast<std::size_t>(chunkCount) * mu;
            const bool metadataMatches =
                !prepared.mConsumed && prepared.mEventRecorded && prepared.mReadyEvent &&
                prepared.mState == &state && prepared.mRing.get() == ring.get() &&
                prepared.mChunkCount == chunkCount && prepared.mMu == mu &&
                prepared.mSid == sid && prepared.mInstanceBase == instanceBase && sameSeed &&
                std::memcmp(
                    &prepared.mMaskDigestHash, &maskDigestHash, sizeof(maskDigestHash)) == 0 &&
                prepared.mCt2.count() == expectedCount;
            if (metadataMatches && gpuStreamWaitEvent(stream.raw(), prepared.mReadyEvent))
            {
                impl.mCt2 = std::move(prepared.mCt2);
                prepared.mConsumed = true;
                havePreparedCt2 = true;
            }
        }
        if (!havePreparedCt2 &&
            !sampleCt2Batch(
                *ring, *cache, state.mParams.mRing, chunkCount, mu, seed, sid, instanceBase,
                maskDigestHash, impl.mCt2, stream))
        {
            return false;
        }

        // ---- lheApplyCt1Trunc ----
        // u = centred high gadget digits of the chunk digest, NTT'd; then
        // acc[row] = sum_col ct1[row][col] * u[col].
        GpuPolyBuffer uDigitsOwned;
        u64* uDigits = nullptr;
        bool uDigitsNtt = false;
        const std::size_t uDigitCount = static_cast<std::size_t>(chunkCount) * tauHi;
        if (reuseHiDigitsEnabled(ring->executionOptions().mAdvanced.mProtocol) && impl.mHiDigits &&
            impl.mHiDigits->mImpl->mBuf.count() == uDigitCount)
        {
            // Every child operation that reads dHat has already been enqueued on
            // this stream before its parent expand. The compact leaf-diagonal
            // path may already have filled this exact buffer in NTT form.
            uDigits = impl.mHiDigits->mImpl->mBuf.data(stream);
            uDigitsNtt = impl.mHiDigits->mImpl->mRecursiveHiNtt;
        }
        else
        {
            if (!uDigitsOwned.resize(*ring, uDigitCount, stream)) return false;
            uDigits = uDigitsOwned.data(stream);
            if (!launchGadgetDecompose(
                    ring->view(stream), impl.mDigest.data(stream), nullptr, chunkCount,
                    state.mParams.mGadgetLogBase, 1, tauHi, true, uDigits, nullptr,
                    stream.raw()))
                return false;
        }
        if (!uDigitsNtt && !launchNttForward(
                ring->view(stream), uDigits, static_cast<u32>(uDigitCount), nullptr, stream.raw()))
            return false;

        const std::size_t rowsTotal = static_cast<std::size_t>(chunkCount) * mu;
        if (!impl.mAcc.resize(*ring, rowsTotal, stream)) return false;

        const u32 treeTerms = 2u * impl.mLevels * impl.mMaxTau;
        const bool combineExpandAccumulator =
            !ring->kernelOptions().mFusedIp && tauHi == 1u && rowsTotal <= 65535u &&
            canLaunchExpandAccumulatorTau1(
                ring->view(stream), mu, treeTerms,
                static_cast<u32>(rowsTotal));

        // skX is independent of the ct1 product. Transforming it before the
        // pointwise work lets the production geometry combine both products and
        // the tree sum into a single high-occupancy accumulator kernel below.
        GpuPolyBuffer skXNttOwned;
        u64* skXNtt = nullptr;
        if (skXDev)
        {
            // The device key is consumed by this expand. Transform it in place
            // instead of copying one polynomial per chunk into scratch first.
            skXNtt = skXDev->mImpl->mBuf.data(stream);
        }
        else
        {
            if (!skXNttOwned.resize(*ring, chunkCount, stream) || !skXNttOwned.upload(skX, stream))
                return false;
            skXNtt = skXNttOwned.data(stream);
        }
        if (!launchNttForward(ring->view(stream), skXNtt, chunkCount, nullptr, stream.raw()))
            return false;

        // Three inner products below all target impl.mAcc, and the only reader of
        // the result is the inverse transform at the end of this function, so on
        // paper all three should fold into that transform's load and save six
        // polynomials of accumulator traffic per output row.
        //
        // Measured: folding all three is **slower** than folding only the last one,
        // 167.2 against 170.4 M/s. The transform runs 1024 threads on 64 KiB of
        // shared memory, which is one block per SM, and that is a bad place to do a
        // scattered gather - there is no second block to hide the latency behind.
        // `innerProductKernel` runs 256-thread blocks at high occupancy and absorbs
        // it. So the rule that came out of this is: fold the inner product that
        // feeds the transform, because that saves a full write and read, but leave
        // the ones that only touch the accumulator where they are.
        NttFusedIp fusedIp{};
        if (!combineExpandAccumulator)
        {
            const std::size_t idxCount = rowsTotal * tauHi;
            const u64 geo = idxKey(scope.mRole, 0xC711u, chunkCount, mu, tauHi, cache->mCt1Cols);
            const u32* dPair = cachedIdx(geo, 2 * idxCount, stream, [&](std::vector<u32>& v)
            {
                u32* aIdx = v.data();
                u32* bIdx = v.data() + idxCount;
                for (u32 c = 0; c < chunkCount; ++c)
                {
                    for (u32 row = 0; row < mu; ++row)
                    {
                        const std::size_t o = static_cast<std::size_t>(c) * mu + row;
                        for (u32 col = 0; col < tauHi; ++col)
                        {
                            aIdx[o * tauHi + col] = row * cache->mCt1Cols + col;
                            bIdx[o * tauHi + col] = static_cast<u32>(c * tauHi + col);
                        }
                    }
                }
            });
            if (!dPair) return false;
            const u32* dA = dPair;
            const u32* dB = dPair + idxCount;
            if (!launchInnerProduct(
                    ring->view(stream), cache->mCt1.data(stream), uDigits, dA, dB, tauHi,
                    impl.mAcc.data(stream), nullptr, static_cast<u32>(rowsTotal), false, false,
                    stream.raw()))
            {
                return false;
            }
        }

        // ---- lheDec: acc[row] -= publicA[row] * NTT(skX[chunk]) ----
        if (!combineExpandAccumulator)
        {
            const std::size_t idxCount = rowsTotal;
            const u64 geo = idxKey(scope.mRole, 0xA5C1u, chunkCount, mu);
            const u32* dPair = cachedIdx(geo, 2 * idxCount, stream, [&](std::vector<u32>& v)
            {
                u32* aIdx = v.data();
                u32* bIdx = v.data() + idxCount;
                for (u32 c = 0; c < chunkCount; ++c)
                {
                    for (u32 row = 0; row < mu; ++row)
                    {
                        const std::size_t o = static_cast<std::size_t>(c) * mu + row;
                        aIdx[o] = row;
                        bIdx[o] = c;
                    }
                }
            });
            if (!dPair) return false;
            const u32* dA = dPair;
            const u32* dB = dPair + idxCount;
            // acc -= publicA . skXNtt, straight into the accumulator. Previously
            // this wrote a full rowsTotal-polynomial temporary and then ran an
            // elementwise subtraction over it.
            if (!launchInnerProduct(
                    ring->view(stream), cache->mPublicA.data(stream), skXNtt, dA, dB, 1,
                    impl.mAcc.data(stream), nullptr, static_cast<u32>(rowsTotal), false, false,
                    stream.raw(), true))
            {
                return false;
            }
        }


        // ---- lencEvalTrunc, output in the NTT domain and negated ----
        {
            const u32 levels = impl.mLevels;
            const u32 width = impl.mWidth;
            const u32 ctTauMax = impl.mMaxTau;
            const u32 terms = treeTerms;   // activeTau is 1 per level here

                // Both arrays are geometry only, so they are built once per shape and
                // then reused. This is the largest of them: rowsTotal * terms entries,
                // rebuilt and re-uploaded on every call before being cached.
                // One cached allocation holding both arrays back to back, so the tree
                // walk runs once and there is a single device buffer per geometry.
                const std::size_t idxCount = static_cast<std::size_t>(rowsTotal) * terms;
                const u64 geo = idxKey(scope.mRole,
                    0xE7A1u, chunkCount, mu, levels, width, ctTauMax, impl.mTauHi, impl.mTauLeaf,
                    cache->mLacctCols, impl.mNodeCount, impl.mMaxTau);
                const u32* dPair = cachedIdx(geo, 2 * idxCount, stream, [&](std::vector<u32>& v)
                {
                    u32* aIdx = v.data();
                    u32* bIdx = v.data() + idxCount;
                    for (u32 c = 0; c < chunkCount; ++c)
                    {
                        for (u32 leaf = 0; leaf < mu; ++leaf)
                        {
                            const std::size_t o = static_cast<std::size_t>(c) * mu + leaf;
                            u32 parent = 0;
                            u32 t = 0;
                            for (u32 level = 0; level < levels; ++level)
                            {
                                const u32 left = 2u * parent + 1u;
                                const u32 right = left + 1u;
                                const u32 activeTau = (level == levels - 1u) ? impl.mTauLeaf : impl.mTauHi;
                                const u32 row = level * width + leaf;
                                for (u32 col = 0; col < activeTau; ++col)
                                {
                                    aIdx[o * terms + t] = row * cache->mLacctCols + col;
                                    bIdx[o * terms + t] = static_cast<u32>(impl.nodeSlot(c, left, col));
                                    ++t;
                                    aIdx[o * terms + t] = row * cache->mLacctCols + ctTauMax + col;
                                    bIdx[o * terms + t] = static_cast<u32>(impl.nodeSlot(c, right, col));
                                    ++t;
                                }
                                const u32 bit = (leaf >> (levels - 1u - level)) & 1u;
                                parent = (bit == 0) ? left : right;
                            }
                            // Pad any unused term slots with a zero-valued product by
                            // pointing both operands at slot 0 of a zero polynomial.
                            for (; t < terms; ++t)
                            {
                                aIdx[o * terms + t] = 0;
                                bIdx[o * terms + t] = static_cast<u32>(impl.zeroNodeSlot());
                            }
                        }
                    }
                });
                if (!dPair) return false;
                const u32* dA = dPair;
                const u32* dB = dPair + idxCount;

                // tbm = (decPartial - evalNtt), where evalNtt is the negated inner
                // product. Subtracting a negated sum is adding the sum, so this
                // accumulates directly and drops another rowsTotal-polynomial
                // temporary along with its elementwise pass.
                if (combineExpandAccumulator)
                {
                    if (!launchExpandAccumulatorTau1(
                            ring->view(stream), cache->mCt1.data(stream), uDigits, cache->mPublicA.data(stream),
                            skXNtt, cache->mLacct.data(stream), impl.mNodes.data(stream), dA, dB, mu,
                            treeTerms, impl.mAcc.data(stream), static_cast<u32>(rowsTotal),
                            stream.raw(), state.mParams.mAlpha == 2u))
                    {
                        return false;
                    }
                }
                else if (ring->kernelOptions().mFusedIp)
                {
                    fusedIp.mA = cache->mLacct.data(stream);
                    fusedIp.mB = impl.mNodes.data(stream);
                    fusedIp.mAIdx = dA;
                    fusedIp.mBIdx = dB;
                    fusedIp.mTerms = terms;
                    fusedIp.mMode = NttFusedIp::Accumulate;
                }
                else
                {
                    if (!launchInnerProduct(
                            ring->view(stream), cache->mLacct.data(stream), impl.mNodes.data(stream), dA, dB, terms,
                            impl.mAcc.data(stream), nullptr, static_cast<u32>(rowsTotal), true, false,
                            stream.raw()))
                    {
                        return false;
                    }
                }
        }

        // ... then INTT and + ct2, both folded into the transform's store.
        if (!launchNttInverseFused(
                ring->view(stream), impl.mAcc.data(stream), static_cast<u32>(rowsTotal), nullptr, kElemOpNoneHost,
                nullptr, static_cast<u32>(ElemOp::Add), impl.mCt2.data(stream), stream.raw(), fusedIp,
                state.mParams.mAlpha == 2u))
            return false;

        regKern.stop();

        if (!wantHostOutput)
        {
            // outPerChunk == mu here, so the accumulator already holds exactly
            // the level's output in order and can be handed over untouched.
            if (outPerChunk != mu) return bail(state.mRingFactoryOwner, "expand: outPerChunk != mu");
            auto out = std::make_shared<DeviceBatch>();
            out->mImpl->mRing = ring;
            out->mImpl->mBuf = std::move(impl.mAcc);
            tbmDev = std::move(out);
            (void)rho;
            return true;   // device resident, same stream: no drain needed
        }

        // ---- download the used outputs ----
        Region regDown(GpuStream::RegionKind::Download, stream);
        tbm.resize(totalOut);
        for (u32 c = 0; c < chunkCount; ++c)
        {
            const std::size_t start = static_cast<std::size_t>(c) * outPerChunk;
            if (start >= totalOut) break;
            const std::size_t count = std::min<std::size_t>(outPerChunk, totalOut - start);
            for (std::size_t i = 0; i < count; ++i)
            {
                if (!impl.mAcc.downloadAsync(tbm[start + i], static_cast<std::size_t>(c) * mu + i, stream))
                    return false;
            }
        }
        (void)rho;
        return stream.sync();
    }
    }

    bool expandReceiverChunks(
        const ShrinkExpandReceiverState& state,
        LevelSession& session,
        std::span<const RnsPoly> skX,
        std::span<const u8> seed,
        u64 sid,
        u64 instanceBase,
        block maskDigestHash,
        u32 outPerChunk,
        u32 totalOut,
        std::vector<RnsPoly>& tbm,
        PreparedReceiverCt2* preparedCt2, ProtocolCacheScopeView scope)
    {
        DeviceBatchPtr unused;
        return expandReceiverChunksImpl(
            state, session, skX, nullptr, seed, sid, instanceBase, maskDigestHash, outPerChunk,
            totalOut, true, tbm, unused, preparedCt2, scope);
    }

    bool expandReceiverChunksDevice(
        const ShrinkExpandReceiverState& state,
        LevelSession& session,
        DeviceBatch& skX,
        std::span<const u8> seed,
        u64 sid,
        u64 instanceBase,
        block maskDigestHash,
        u32 outPerChunk,
        u32 totalOut,
        DeviceBatchPtr& tbm,
        PreparedReceiverCt2* preparedCt2, ProtocolCacheScopeView scope)
    {
        std::vector<RnsPoly> unused;
        return expandReceiverChunksImpl(
            state, session, std::span<const RnsPoly>(), &skX, seed, sid, instanceBase,
            maskDigestHash, outPerChunk, totalOut, false, unused, tbm, preparedCt2, scope);
    }

    // ---- sender expand ----------------------------------------------------

    bool expandSenderChunks(
        const ShrinkExpandSenderState& state,
        std::span<const RnsPoly> tbkPrimeHost,
        DeviceBatch* tbkPrimeDev,
        std::span<const u8> seed,
        u64 sid,
        u64 instanceBase,
        block maskDigestHash,
        DeviceBatchPtr& tbkAll,
        PreparedSenderCt2* preparedCt2, ProtocolCacheScopeView scope)
    {
        AutoTimer timer(timingCounter(timingStats(state.mRingFactoryOwner), &TimingStats::mGpuSenderTimeUs));
        if (!enabled(state.mRingFactoryOwner)) return false;
        const bool haveDev = tbkPrimeDev != nullptr && !tbkPrimeDev->empty();
        if (haveDev == !tbkPrimeHost.empty()) return false;   // exactly one source

        auto cache = senderCache(state, scope);
        if (!cache) return false;
        auto ring = cache->mRing;
        const u32 mu = state.mParams.mMu;
        if (mu == 0 || cache->mPublicA.count() != mu) return false;

        const u32 chunkCount =
            haveDev ? static_cast<u32>(tbkPrimeDev->count()) : static_cast<u32>(tbkPrimeHost.size());
        if (chunkCount == 0) return false;
        const std::size_t rowsTotal = static_cast<std::size_t>(chunkCount) * mu;

        if (!state.mRingFactoryOwner || !state.mRingFactoryOwner->mGpuExecution) return false;
        auto& stream = contextStream(*state.mRingFactoryOwner);

        Region regKern(GpuStream::RegionKind::Kernel, stream);

        GpuPolyBuffer ct2;
        if (preparedCt2)
        {
            auto* prepared = preparedCt2->mImpl.get();
            const bool sameSeed = prepared && prepared->mSeed.size() == seed.size() &&
                                  std::equal(seed.begin(), seed.end(), prepared->mSeed.begin());
            if (!prepared || prepared->mConsumed || !prepared->mEventRecorded ||
                !prepared->mReadyEvent || prepared->mState != &state ||
                prepared->mRing.get() != ring.get() || prepared->mChunkCount != chunkCount ||
                prepared->mMu != mu || prepared->mSid != sid ||
                prepared->mInstanceBase != instanceBase || !sameSeed ||
                std::memcmp(
                    &prepared->mMaskDigestHash, &maskDigestHash,
                    sizeof(maskDigestHash)) != 0 ||
                prepared->mCt2.count() != rowsTotal ||
                !gpuStreamWaitEvent(stream.raw(), prepared->mReadyEvent))
            {
                return false;
            }

            // The wait above transfers the output's dependency to the main
            // chain. Moving it into the ordinary local gives it exactly the
            // same lifetime as a synchronously queued sampleCt2Batch result:
            // its eventual gpuFree is tagged after the inverse consumer.
            ct2 = std::move(prepared->mCt2);
            prepared->mConsumed = true;
        }
        else if (!sampleCt2Batch(
                     *ring, *cache, state.mParams.mRing, chunkCount, mu, seed, sid,
                     instanceBase, maskDigestHash, ct2, stream))
        {
            return false;
        }

        // lheDec with cipherInputIsNtt = false and outputNtt = false. By
        // linearity,
        //   INTT(NTT(ct2) - A*NTT(sk)) = ct2 - INTT(A*NTT(sk)).
        // Keeping ct2 in coefficient form deletes one full forward transform per
        // recursion level; the reverse subtraction is folded into the inverse
        // transform's store.
        GpuPolyBuffer skNttOwned;
        u64* skNtt = nullptr;
        if (haveDev && senderInplaceKeyEnabled(ring->executionOptions().mAdvanced.mProtocol))
        {
            skNtt = tbkPrimeDev->mImpl->mBuf.data(stream);
        }
        else
        {
            if (!skNttOwned.resize(*ring, chunkCount, stream)) return false;
            skNtt = skNttOwned.data(stream);
            if (haveDev && !gpuMemcpyD2D(
                    skNtt, tbkPrimeDev->mImpl->mBuf.data(stream),
                    static_cast<std::size_t>(chunkCount) * ring->polyBytes(), stream.raw()))
                return false;
            if (!haveDev && !skNttOwned.upload(tbkPrimeHost, stream)) return false;
        }
        if (!launchNttForward(ring->view(stream), skNtt, chunkCount, nullptr, stream.raw()))
            return false;

        GpuPolyBuffer product;
        if (!product.resize(*ring, rowsTotal, stream)) return false;

        {
            bool productDone = false;
            if (mu == 8u || mu == 16u)
            {
                if (!tryLaunchInnerProductOuterMuRowReuse(
                        ring->view(stream), cache->mPublicA.data(stream), skNtt,
                        product.data(stream), mu, chunkCount, stream.raw(), productDone))
                {
                    return false;
                }
            }
            else if (mu == 32u || mu == 64u || mu == 128u)
            {
                if (!tryLaunchInnerProductOuterWideMuRowReuse(
                        ring->view(stream), cache->mPublicA.data(stream), skNtt,
                        product.data(stream), mu, chunkCount, stream.raw(),
                        productDone))
                {
                    return false;
                }
            }
            if (!productDone)
            {
                std::vector<u32> aIdx(rowsTotal);
                std::vector<u32> bIdx(rowsTotal);
                for (u32 c = 0; c < chunkCount; ++c)
                {
                    for (u32 row = 0; row < mu; ++row)
                    {
                        const std::size_t o = static_cast<std::size_t>(c) * mu + row;
                        aIdx[o] = row;
                        bIdx[o] = c;
                    }
                }
                const u32* dA = stream.uploadIdx(aIdx);
                const u32* dB = stream.uploadIdx(bIdx);
                if (!dA || !dB) return false;
                // product = publicA . skNtt in the NTT domain.
                if (!launchInnerProduct(
                        ring->view(stream), cache->mPublicA.data(stream), skNtt, dA, dB, 1,
                        product.data(stream), nullptr, static_cast<u32>(rowsTotal), false,
                        false, stream.raw()))
                    return false;
            }
            if (!launchNttInverseFused(
                    ring->view(stream), product.data(stream), static_cast<u32>(rowsTotal), nullptr,
                    kElemOpNoneHost, nullptr, static_cast<u32>(ElemOp::ReverseSub), ct2.data(stream),
                    stream.raw(), NttFusedIp{}, state.mParams.mAlpha == 2u))
                return false;
        }

        regKern.stop();

        // The result stays on the device; the caller decides whether it is ever
        // needed on the host.
        auto out = std::make_shared<DeviceBatch>();
        out->mImpl->mRing = ring;
        out->mImpl->mBuf = std::move(product);
        tbkAll = std::move(out);
        return true;   // device resident, same stream: no drain needed
    }

    // ---- sender Root ------------------------------------------------------

    bool rootKPrimeSamplingEnabled(const LogVoleExecutionOptions& options, bool selectedGpu)
    {
        return (options.mUseGpu && selectedGpu) && options.mAdvanced.mProtocol.mRootKPrimeSampling;
    }

    bool sampleRootKPrimeDevice(const RingNttContext& ctx,
        const std::array<u64, 8>& seed, DeviceBatchPtr& out)
    {
        out.reset();
        if (!rootKPrimeSamplingEnabled(ctx.mExecutionOptions, enabled(ctx))) return false;
        // Validation hook: Core must replay its already-consumed seed if the
        // device path declines. Never draw substitute parent randomness.
        const bool decline = ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mRootKPrime;
        if (decline) return false;
        auto ring = GpuRing::get(ctx);
        if (!ring || !ring->sampleMaxMultiple() ||
            !((ring->n() == 16384u && ring->rho() == 8u) ||
              (ring->n() == 8192u && ring->rho() == 4u))) return false;
        auto& stream = contextStream(ctx);
        auto& scratch = sampleScratch(stream);
        auto sampled = std::make_shared<DeviceBatch>();
        sampled->mImpl->mRing = ring;
        if (!sampled->mImpl->mBuf.resize(*ring, 1u, stream) || !scratch.ensureSeeds(8u) ||
            !scratch.ensureRoundKeys(176u)) return false;
        u32* rejectEpochs = nullptr;
        u32 rejectEpoch = 0u;
        if (!scratch.nextRejectEpoch(1u, stream.raw(), rejectEpochs, rejectEpoch)) return false;
        const bool queued =
            gpuMemcpyH2D(scratch.mSeeds, seed.data(), sizeof(seed), stream.raw()) &&
            launchSampleUniformPolyAes(ring->view(stream), scratch.mSeeds,
                ring->sampleMaxMultiple(), sampled->mImpl->mBuf.data(stream), nullptr, 1u,
                scratch.mRoundKeys, scratch.mRoundKeyBytes, rejectEpochs, rejectEpoch, stream.raw());
        // The producer must be complete before crossing a coroutine suspension.
        // No full-polynomial download or upload is performed on success. Drain
        // failed enqueues too, before the caller replays the same seed on CPU.
        const bool complete = stream.sync();
        if (!queued || !complete) return false;
        sampled->mImpl->mFreshRootKPrime = true;
        out = std::move(sampled);
        return true;
    }

    bool prepareRootSenderOperandsDevice(
        const SenderState& state,
        ProtocolCacheScopeView scope)
    {
        const LogVoleGpuProtocolOptions defaults;
        const auto& options = state.mShrinkExpandState.mRingFactoryOwner ? state.mShrinkExpandState.mRingFactoryOwner->mExecutionOptions.mAdvanced.mProtocol : defaults;
        AutoTimer timer(timingCounter(timingStats(state.mShrinkExpandState.mRingFactoryOwner), &TimingStats::mGpuSenderTimeUs));
        const bool prepareSk = rootSkNttResidentEnabled(options);
        if (!enabled(state.mShrinkExpandState.mRingFactoryOwner) || !prepareSk) return false;

        RingNttContext ctx{};
        if (!makeRingNttContext(state.mParams.mShrinkExpand.mRing, ctx,
                state.mShrinkExpandState.mRingFactoryOwner, scope))
            return bail(ctx, "root operands: context");
        auto ring = GpuRing::get(ctx);
        if (!ring)
            return bail(ctx, "root operands: ring");

        u32 tauHi = 0u;
        const auto secretCoeffs = std::static_pointer_cast<DeviceBatch>(
            state.mRootSkRRtDevice);
        const bool secretDevice = static_cast<bool>(secretCoeffs);
        if (prepareSk)
        {
            const u32 fullTau = state.mParams.mShrinkExpand.mTau;
            if (fullTau < 2u)
                return bail(ctx, "root operands: shape");
            tauHi = fullTau - 1u;
            if (secretDevice ?
                    (!state.mRootSkRRt.empty() || !state.mLazyRootSkRRt ||
                     state.mLazyRootSkRRt->count() != tauHi ||
                     !state.mLazyRootSkRRt->matches(ctx.mParams) ||
                     !rootSecretUniformBatchMatches(ctx, *secretCoeffs,
                         tauHi, state.mRootSkRRtOwnerRunId, false, scope))
                    : state.mRootSkRRt.size() != tauHi)
                return bail(ctx, "root operands: shape");
            for (const auto& sk : state.mRootSkRRt)
            {
                if (sk.mCoeffs.size() != ring->polyWords())
                    return bail(ctx, "root operands: sk shape");
            }
        }

        auto& stream = contextStream(ctx);
        if (prepareSk)
        {
            auto skNtt = std::static_pointer_cast<DeviceBatch>(
                state.mRootSkRRtNttDevice);
            const bool cachedSkValid =
                skNtt && skNtt->mImpl && !skNtt->mImpl->mLogicalCount &&
                (secretDevice ?
                    rootSecretUniformBatchMatches(ctx, *skNtt,
                        tauHi, state.mRootSkRRtOwnerRunId, true, scope)
                    : skNtt->mImpl->mRing == ring &&
                      skNtt->mImpl->mBuf.count() == tauHi);
            if (!cachedSkValid)
            {
                skNtt = std::make_shared<DeviceBatch>();
                skNtt->mImpl->mRing = ring;
                if (secretDevice)
                {
                    skNtt->mImpl->mRootSecretUniform = true;
                    skNtt->mImpl->mRootSecretNtt = true;
                    skNtt->mImpl->mRootSecretRole = ProtocolCacheRole::Sender;
                    skNtt->mImpl->mRootSecretRunId = state.mRootSkRRtOwnerRunId;
        skNtt->mImpl->mIdentityService = (state.mRootSkRRtOwnerRunId).serviceOwner();
                    skNtt->mImpl->mRootSecretDevice = currentDeviceOrdinal();
                }
                if (!skNtt->mImpl->mBuf.resize(*ring, tauHi, stream))
                    return bail(ctx, "root operands: sk alloc");
                {
                    Region regUp(GpuStream::RegionKind::Upload, stream);
                    if (!(secretDevice
                            ? gpuMemcpyD2D(skNtt->mImpl->mBuf.data(stream),
                                secretCoeffs->mImpl->mBuf.data(stream),
                                tauHi * ring->polyWords() * sizeof(u64),
                                stream.raw())
                            : skNtt->mImpl->mBuf.upload(
                                std::span<const RnsPoly>(
                                    state.mRootSkRRt.data(), state.mRootSkRRt.size()),
                                stream)))
                        return bail(ctx, "root operands: sk upload");
                }
                {
                    Region regKern(GpuStream::RegionKind::Kernel, stream);
                    if (!launchNttForward(
                            ring->view(stream), skNtt->mImpl->mBuf.data(stream), tauHi,
                            nullptr, stream.raw()) ||
                        !stream.sync())
                        return bail(ctx, "root operands: sk ntt");
                }
                // Publish only after the immutable NTT buffer is complete. Future
                // queries and a coroutine resuming on another thread may read it
                // without an event.
                state.mRootSkRRtNttDevice = skNtt;
            }
        }

        return true;
    }

    bool rootSkxSenderDevice(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& sk1,
        const RnsPoly& digest,
        const RnsPoly& tbkPrime,
        u32 gadgetLogBase,
        u32 tauHi,
        RnsPoly& out, ProtocolCacheScopeView scope,
        DeviceBatchPtr* residentKPrime,
        const DeviceBatchPtr& preparedSkNtt,
        const DeviceBatchPtr& preparedKPrime,
        bool recoverNonInteractiveMask,
        const DeviceBatchPtr& rootSecretCoeffs,
        ProtocolCacheRunId rootSecretOwnerRunId)
    {
        AutoTimer timer(timingCounter(timingStats(ctx), &TimingStats::mGpuSenderTimeUs));
        if (residentKPrime) residentKPrime->reset();
        const bool forceDecline = ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mRootSkX;
        if (!enabled(ctx) || tauHi == 0 ||
            (forceDecline) ||
            (rootSecretCoeffs ?
                (!sk1.empty() || !rootSecretUniformBatchMatches(ctx,
                    *rootSecretCoeffs, tauHi, rootSecretOwnerRunId, false, scope))
                : sk1.size() != tauHi)) return bail(ctx, "skx: shape");
        auto ring = GpuRing::get(ctx);
        if (!ring) return bail(ctx, "skx: ring");
        const bool havePreparedKPrime =
            preparedKPrime && preparedKPrime->mImpl &&
            preparedKPrime->mImpl->mFreshRootKPrime &&
            !preparedKPrime->mImpl->mLogicalCount &&
            preparedKPrime->mImpl->mRing == ring &&
            preparedKPrime->mImpl->mBuf.count() == 1u;
        if (digest.mCoeffs.size() != ring->polyWords() ||
            (tbkPrime.mCoeffs.size() != ring->polyWords() &&
             !(havePreparedKPrime && preparedKPrime->mImpl->mFreshRootKPrime &&
               tbkPrime.mCoeffs.empty())) ||
            (!rootSecretCoeffs && std::any_of(sk1.begin(), sk1.end(), [&](const RnsPoly& sk) {
                return sk.mCoeffs.size() != ring->polyWords();
            })))
            return bail(ctx, "skx: host input shape");

        auto& stream = contextStream(ctx);
        Region regKern(GpuStream::RegionKind::Kernel, stream);

        const bool havePreparedSk =
            rootSkNttResidentEnabled(ctx.mExecutionOptions.mAdvanced.mProtocol) &&
            preparedSkNtt && preparedSkNtt->mImpl &&
            !preparedSkNtt->mImpl->mLogicalCount &&
            (rootSecretCoeffs ?
                rootSecretUniformBatchMatches(ctx, *preparedSkNtt,
                    tauHi, rootSecretOwnerRunId, true, scope)
                : preparedSkNtt->mImpl->mRing == ring &&
                  preparedSkNtt->mImpl->mBuf.count() == tauHi);
        GpuPolyBuffer sk;
        // The established path packs digest and k' together. A device-generated
        // k' has its own one-poly owner, so dAcc then holds
        // only the digest and can die without taking retained k' with it.
        GpuPolyBuffer dAcc;
        GpuPolyBuffer uHi;
        GpuPolyBuffer term;
        const std::size_t dAccCount = havePreparedKPrime ? 1u : 2u;
        if ((!havePreparedSk && !sk.resize(*ring, tauHi, stream)) ||
            !dAcc.resize(*ring, dAccCount, stream) ||
            !uHi.resize(*ring, tauHi, stream) ||
            !term.resize(*ring, 1, stream))
            return bail(ctx, "skx: alloc");
        const bool inputsUploaded = [&] {
            if (!havePreparedSk)
            {
                if (rootSecretCoeffs)
                {
                    if (!gpuMemcpyD2D(sk.data(stream),
                            rootSecretCoeffs->mImpl->mBuf.data(stream),
                            tauHi * ring->polyWords() * sizeof(u64),
                            stream.raw())) return false;
                }
                else
                {
                    if (!sk.upload(
                            std::span<const RnsPoly>(sk1.data(), sk1.size()),
                            stream))
                        return false;
                }
            }

            const bool digestUploaded = dAcc.upload(
                std::span<const RnsPoly>(&digest, 1), stream, 0);
            if (!digestUploaded || havePreparedKPrime) return digestUploaded;
            return dAcc.upload(
                std::span<const RnsPoly>(&tbkPrime, 1), stream, 1);
        }();
        if (!inputsUploaded)
            return bail(ctx, "skx: upload");

        // gadgetDecomposeBitsRangeCentered(digest, gadgetLogBase, 1, tauHi)
        if (!launchGadgetDecompose(
                ring->view(stream), dAcc.data(stream), nullptr, 1, gadgetLogBase, 1, tauHi, true, uHi.data(stream), nullptr,
                stream.raw()))
            return bail(ctx, "skx: gadget");

        if ((!havePreparedSk &&
             !launchNttForward(
                 ring->view(stream), sk.data(stream), tauHi, nullptr, stream.raw())) ||
            !launchNttForward(
                ring->view(stream), uHi.data(stream), tauHi, nullptr, stream.raw()))
            return bail(ctx, "skx: ntt");

        const u64* skNttData = havePreparedSk
            ? preparedSkNtt->mImpl->mBuf.data(stream)
            : sk.data(stream);
        const u64* kPrimeData = havePreparedKPrime
            ? preparedKPrime->mImpl->mBuf.data(stream)
            : dAcc.poly(1, stream);

        std::vector<u32> idx(tauHi);
        for (u32 i = 0; i < tauHi; ++i) idx[i] = i;
        const u32* dIdx = stream.uploadIdx(idx);
        if (!dIdx) return bail(ctx, "skx: idx");

        // One transform: the inner product is folded into its load and the
        // addition of tbkPrime into its store.
        NttFusedIp ip{};
        if (ring->kernelOptions().mFusedIp)
        {
            ip.mA = skNttData;
            ip.mB = uHi.data(stream);
            ip.mAIdx = dIdx;
            ip.mBIdx = dIdx;
            ip.mTerms = tauHi;
            ip.mMode = NttFusedIp::Replace;
        }
        else if (!launchInnerProduct(
                     ring->view(stream), skNttData, uHi.data(stream), dIdx, dIdx, tauHi, term.data(stream), nullptr, 1, false,
                     false, stream.raw()))
        {
            return bail(ctx, "skx: inner product");
        }
        if (!launchNttInverseFused(
                ring->view(stream), term.data(stream), 1, nullptr, kElemOpNoneHost, nullptr,
                static_cast<u32>(recoverNonInteractiveMask ? ElemOp::ReverseSub : ElemOp::Add),
                kPrimeData,
                stream.raw(), ip))
            return bail(ctx, "skx: intt+add");

        std::vector<RnsPoly> hostOut;
        if (!term.download(hostOut, stream, 0, 1) || hostOut.size() != 1) return bail(ctx, "skx: download");
        out = std::move(hostOut[0]);
        // download() above drains this producer stream, including the final read
        // of k'. Publishing needs no cross-stream event and remains safe if the
        // coroutine later resumes on another host thread.
        if (residentKPrime)
        {
            if (recoverNonInteractiveMask)
            {
                // In NI mode term is H(id,d') - <sk,g^-1(d')>. Retain this
                // computed mask, never the public oracle response input.
                auto mask = std::make_shared<DeviceBatch>();
                mask->mImpl->mRing = ring;
                mask->mImpl->mBuf = std::move(term);
                *residentKPrime = std::move(mask);
            }
            else if (havePreparedKPrime)
                *residentKPrime = preparedKPrime;
        }
        return true;
    }

    bool rootSenderTbkDevice(
        const ShrinkExpandSenderState& state,
        const RingNttContext& ctx,
        std::span<const u8> seed,
        u64 sid,
        const RnsPoly& dPrimeRt,
        block dPrimeHash,
        const RnsPoly& kPrimeRt,
        const DeviceBatch* kPrimeRtDevice,
        u32 leftWidth,
        u32 tauHi,
        DeviceBatchPtr& tbk, ProtocolCacheScopeView scope)
    {
        // Use the sender operation role. senderCache separately selects the
        // retained offline run for immutable public operands.
        scope.mRole = ProtocolCacheRole::Sender;
        AutoTimer timer(timingCounter(timingStats(ctx), &TimingStats::mGpuSenderTimeUs));
        if (!enabled(ctx) || seed.empty() || leftWidth == 0 || tauHi == 0) return bail(ctx, "root sender: shape");

        auto cache = senderCache(state, scope);
        if (!cache) return bail(ctx, "root sender: offline cache");
        auto ring = cache->mRing;
        const u32 rho = ring->rho();
        if (rho == 0 || leftWidth != tauHi * rho) return bail(ctx, "root sender: leftWidth");
        const bool haveResidentKPrime =
            kPrimeRtDevice && kPrimeRtDevice->mImpl &&
            kPrimeRtDevice->mImpl->mFreshRootKPrime &&
            !kPrimeRtDevice->mImpl->mLogicalCount &&
            kPrimeRtDevice->mImpl->mRing == ring &&
            kPrimeRtDevice->mImpl->mBuf.count() == 1u;
        if (kPrimeRt.mCoeffs.size() != ring->polyWords() &&
            !(haveResidentKPrime && kPrimeRtDevice->mImpl->mFreshRootKPrime &&
              kPrimeRt.mCoeffs.empty()))
            return bail(ctx, "root sender: k' host shape");
        // lheDec takes publicA[0 .. cipher.size()-1]; the cache holds mu rows and
        // the rows do not depend on the count, so leftWidth of them must be there.
        if (cache->mPublicA.count() < leftWidth) return bail(ctx, "root sender: publicA rows");
        if (!ring->denoiseReady()) return bail(ctx, "root sender: denoise tables");

        auto& stream = contextStream(ctx);
        Region regKern(GpuStream::RegionKind::Kernel, stream);

        // ---- buildHashedCt2(ctx, leftWidth, seed, sid, d'_Rt, 0) ----
        GpuPolyBuffer ctK;
        if (!sampleCt2Batch(
                *ring, *cache, state.mParams.mRing, 1, leftWidth, seed, sid, 0, dPrimeHash, ctK,
                stream))
            return bail(ctx, "root sender: ct2");

        // ---- lheDec(ctK, k'_Rt): ctK - INTT(publicA*NTT(k')) ----
        //
        // k' is *not* offline data: prepareRootResponseSender draws a fresh k'_Rt
        // from the PRNG for every query, so the transform cannot be cached in the
        // offline cache. Device-generated keys avoid its second host upload; each
        // seed candidate still needs one device copy and one transform.
        GpuPolyBuffer skNtt;
        if (!skNtt.resize(*ring, 1, stream)) return bail(ctx, "root sender: k' alloc");

        // The retained source remains in coefficient form across GoldenSeed
        // retries. Copy it into this call's destructive NTT scratch rather than
        // transforming the shared handle in place. rootSkxSenderDevice publishes
        // the handle only after synchronizing its producer stream, so this D2D is
        // safe even if the coroutine resumed on another thread/stream.
        bool kPrimeReady = false;
        if (haveResidentKPrime)
        {
            kPrimeReady = gpuMemcpyD2D(
                skNtt.data(stream), kPrimeRtDevice->mImpl->mBuf.data(stream), ring->polyBytes(),
                stream.raw());
        }
        if (!kPrimeReady)
        {
            // Exact host-key fallback. Device-generated keys have no host
            // mirror here: a failed D2D causes this helper to decline, after
            // which Core materializes the synchronized source for CPU replay.
            kPrimeReady = skNtt.upload(
                std::span<const RnsPoly>(&kPrimeRt, 1), stream);
        }
        if (!kPrimeReady ||
            !launchNttForward(ring->view(stream), skNtt.data(stream), 1, nullptr, stream.raw()))
            return bail(ctx, "root sender: k' upload");

        GpuPolyBuffer product;
        if (!product.resize(*ring, leftWidth, stream)) return bail(ctx, "root sender: product");
        {
            std::vector<u32> aIdx(leftWidth);
            std::vector<u32> bIdx(leftWidth, 0);
            for (u32 row = 0; row < leftWidth; ++row) aIdx[row] = row;
            const u32* dA = stream.uploadIdx(aIdx);
            const u32* dB = stream.uploadIdx(bIdx);
            if (!dA || !dB) return bail(ctx, "root sender: idx");
            if (!launchInnerProduct(
                    ring->view(stream), cache->mPublicA.data(stream), skNtt.data(stream), dA, dB, 1, product.data(stream),
                    nullptr, leftWidth, false, false, stream.raw()))
                return bail(ctx, "root sender: a.sk");
            if (!launchNttInverseFused(
                    ring->view(stream), product.data(stream), leftWidth, nullptr, kElemOpNoneHost, nullptr,
                    static_cast<u32>(ElemOp::ReverseSub), ctK.data(stream), stream.raw()))
                return bail(ctx, "root sender: ct2 intt");
        }

        // ---- denoiseAndAggRootKey: rho limbs combined, then tauHi digits summed ----
        auto tbkRt = std::make_shared<DeviceBatch>();
        tbkRt->mImpl->mRing = ring;
        tbkRt->mImpl->mBuf = std::move(product);

        DeviceBatchPtr rootKey;
        if (!denoiseAndAggDevice(ctx, *tbkRt, tauHi, rootKey) || !rootKey || rootKey->count() != 1)
            return bail(ctx, "root sender: denoise+agg");

        // ---- the Root's own expand, one chunk with nonce 0 ----
        return expandSenderChunks(
            state, std::span<const RnsPoly>(), rootKey.get(), seed, sid, 0, dPrimeHash, tbk, nullptr, scope);
    }

    // ---- device-side denoise + aggregate ----------------------------------

    bool deferredGoldenValidationEnabled(const LogVoleGpuProtocolOptions& options)
    {
        return deferredGoldenValidationEnabledImpl(options);
    }

    GoldenValidationAttempt::~GoldenValidationAttempt()
    {
        if (!abort()) std::terminate();
    }

    bool GoldenValidationAttempt::begin(const RingNttContext& ctx)
    {
        if (mStream || !ctx.mGpuExecution || !enabled(ctx) ||
            !deferredGoldenValidationEnabledImpl(ctx.mExecutionOptions.mAdvanced.mProtocol)) return false;
        auto ring = GpuRing::get(ctx);
        if (!ring || !ring->denoiseReady()) return false;

        auto& stream = contextStream(ctx);
        auto& scratch = validateScratch(stream);
        if (scratch.mAttemptActive || !scratch.ensure(ring->rho()) ||
            !gpuMemsetZero(scratch.mFlag, sizeof(u32), stream.raw()))
        {
            return false;
        }
        scratch.mAttemptActive = true;
        scratch.mAttemptStream = stream.raw();
        scratch.mAttemptRho = ring->rho();
        mExecution = ctx.mGpuExecution;
        mStream = &stream;
        return true;
    }

    bool GoldenValidationAttempt::abort()
    {
        if (!mStream) return true;
        auto& stream = *mStream;
        auto& scratch = validateScratch(stream);
        if (!scratch.mAttemptActive || scratch.mAttemptStream != stream.raw() ||
            !stream.sync()) return false;
        scratch.mAttemptActive = false;
        scratch.mAttemptStream = nullptr;
        scratch.mAttemptRho = 0;
        mStream = nullptr;
        mExecution.reset();
        return true;
    }

    bool GoldenValidationAttempt::finish(bool& ok)
    {
        if (!mStream) return false;
        auto& stream = *mStream;
        auto& scratch = validateScratch(stream);
        if (!scratch.mAttemptActive) return false;
        if (scratch.mAttemptStream != stream.raw()) return false;

        u32 fail = 0;
        // Keep the host destination alive even if the first drain fails.
        StreamDrain drain{stream};
        const bool copied = gpuMemcpyD2H(&fail, scratch.mFlag, sizeof(u32), stream.raw());
        if (!drain.sync()) return false;
        scratch.mAttemptActive = false;
        scratch.mAttemptStream = nullptr;
        scratch.mAttemptRho = 0;
        // The execution domain must outlive the drain guard's stream borrow.
        // Release it when this attempt is destroyed or is begun again.
        mStream = nullptr;
        if (!copied) return false;
        ok = (fail == 0);
        return true;
    }

    bool denoiseAndAggDevice(
        const RingNttContext& ctx,
        const DeviceBatch& in,
        u32 tau,
        DeviceBatchPtr& out,
        u64 logicalInputCount)
    {
        AutoTimer timer(timingCounter(timingStats(ctx), &TimingStats::mGpuMiscTimeUs));
        if (!enabled(ctx) || in.empty() || tau == 0) return false;
        auto ring = GpuRing::get(ctx);
        if (!ring || !ring->denoiseReady() || !in.mImpl || in.mImpl->mRing != ring ||
            in.mImpl->mBuf.count() != in.count())
            return false;
        const u32 rho = ring->rho();
        if (in.count() % rho != 0) return false;

        if (logicalInputCount > std::numeric_limits<std::size_t>::max()) return false;
        const std::size_t logicalCount = logicalInputCount == 0u
            ? in.count()
            : static_cast<std::size_t>(logicalInputCount);
        if (logicalCount > in.count() || (logicalCount % rho) != 0) return false;

        const std::size_t denoised = logicalCount / rho;
        if (denoised % tau != 0) return false;
        const std::size_t aggCount = denoised / tau;

        auto& stream = contextStream(ctx);
        Region regKern(GpuStream::RegionKind::Kernel, stream);

        GpuPolyBuffer mid;
        if (!mid.resize(*ring, denoised, stream)) return false;
        if (!denoiseComb(
                *ring, in.mImpl->mBuf.data(stream), mid.data(stream),
                static_cast<u32>(denoised), stream))
            return false;

        auto result = std::make_shared<DeviceBatch>();
        result->mImpl->mRing = ring;
        if (tau == 1)
        {
            // seedLabelAgg with tau == 1 is the identity; skip the copy entirely.
            result->mImpl->mBuf = std::move(mid);
        }
        else
        {
            if (!result->mImpl->mBuf.resize(*ring, aggCount, stream)) return false;
            if (!launchAggregate(
                    ring->view(stream), mid.data(stream), tau, result->mImpl->mBuf.data(stream),
                    static_cast<u32>(aggCount), stream.raw()))
                return false;
        }

        out = std::move(result);
        return true;
    }

    bool denoiseAndAggValidateDevice(
        GoldenValidationAttempt& attempt,
        const RingNttContext& ctx,
        const DeviceBatch& in,
        u32 tau,
        const Params& validatedLevelParams,
        DeviceBatchPtr& out,
        u64 logicalInputCount)
    {
        AutoTimer timer(timingCounter(timingStats(ctx), &TimingStats::mGpuMiscTimeUs));
        if (!enabled(ctx) || in.empty() || tau == 0 ||
            validatedLevelParams.mCt2SeedMode != Ct2SeedMode::GoldenSeed)
            return false;
        auto ring = GpuRing::get(ctx);
        if (!ring || !ring->denoiseReady() || !in.mImpl || in.mImpl->mRing != ring ||
            in.mImpl->mBuf.count() != in.count())
            return false;

        const u32 rho = ring->rho();
        const u32 mu = validatedLevelParams.mShrinkExpand.mMu;
        if (rho == 0 || mu == 0 || (mu % rho) != 0) return false;
        const std::size_t expected =
            ((static_cast<std::size_t>(validatedLevelParams.mW) + mu - 1u) / mu) * mu;
        if (in.count() != expected || (in.count() % rho) != 0) return false;

        if (logicalInputCount > std::numeric_limits<std::size_t>::max()) return false;
        const std::size_t logicalCount = logicalInputCount == 0u
            ? in.count()
            : static_cast<std::size_t>(logicalInputCount);
        if (logicalCount > in.count() || (logicalCount % rho) != 0) return false;

        const std::size_t physicalDenoised = in.count() / rho;
        const std::size_t logicalDenoised = logicalCount / rho;
        if ((logicalDenoised % tau) != 0) return false;
        const std::size_t aggCount = logicalDenoised / tau;

        if (!attempt.stream()) return false;
        auto& stream = *attempt.stream();
        auto& scratch = validateScratch(stream);
        if (!uploadGoldenMargins(
                validatedLevelParams, ctx, *ring, scratch, stream))
            return false;

        Region regKern(GpuStream::RegionKind::Kernel, stream);
        GpuPolyBuffer mid;
        if (!mid.resize(*ring, physicalDenoised, stream) ||
            !launchDenoiseCombValidate(
                ring->view(stream), ring->denoiseView(), in.mImpl->mBuf.data(stream), mid.data(stream),
                static_cast<u32>(physicalDenoised), scratch.mMarginLo, scratch.mMarginHi,
                scratch.mFlag, stream.raw()))
            return false;

        auto result = std::make_shared<DeviceBatch>();
        result->mImpl->mRing = ring;
        if (tau == 1)
        {
            if (logicalDenoised == physicalDenoised)
            {
                result->mImpl->mBuf = std::move(mid);
            }
            else if (!result->mImpl->mBuf.resize(*ring, logicalDenoised, stream) ||
                     !gpuMemcpyD2D(
                         result->mImpl->mBuf.data(stream), mid.data(stream),
                         logicalDenoised * ring->polyBytes(), stream.raw()))
            {
                return false;
            }
        }
        else
        {
            if (!result->mImpl->mBuf.resize(*ring, aggCount, stream) ||
                !launchAggregate(
                    ring->view(stream), mid.data(stream), tau, result->mImpl->mBuf.data(stream),
                    static_cast<u32>(aggCount), stream.raw()))
                return false;
        }

        out = std::move(result);
        return true;
    }

    // ---- device-side golden-seed validation -------------------------------

    bool validateGoldenSeedDevice(const Params& params, const RingNttContext& ctx,
        const DeviceBatch& tbk, bool& ok)
    {
        AutoTimer timer(timingCounter(timingStats(ctx), &TimingStats::mGpuMiscTimeUs));
        if (!enabled(ctx) || tbk.empty() || params.mCt2SeedMode != Ct2SeedMode::GoldenSeed)
            return false;

        if (ctx.mParams != params.mShrinkExpand.mRing) return false;
        auto ring = GpuRing::get(ctx);
        if (!ring || !ring->denoiseReady()) return false;

        const u32 mu = params.mShrinkExpand.mMu;
        const u32 rho = ring->rho();
        if (rho == 0 || mu == 0 || (mu % rho) != 0) return false;
        const std::size_t expected =
            ((static_cast<std::size_t>(params.mW) + mu - 1u) / mu) * mu;
        if (tbk.count() != expected) return false;

        // The margins depend on the noise-bound estimate, which depends on the
        // level's parameters, so they are rebuilt per call. rho values, tiny.
        std::vector<u64> marginLo(rho), marginHi(rho);
        if (!goldenSeedMargins(params, ctx, marginLo, marginHi)) return false;

        auto& stream = contextStream(ctx);
        Region regKern(GpuStream::RegionKind::Kernel, stream);

        auto& scratch = validateScratch(stream);
        if (scratch.mAttemptActive || !scratch.ensure(rho)) return false;
        u32 fail = 0;
        StreamDrain drain{stream};
        if (!gpuMemcpyH2D(scratch.mMarginLo, marginLo.data(), rho * sizeof(u64), stream.raw()) ||
            !gpuMemcpyH2D(scratch.mMarginHi, marginHi.data(), rho * sizeof(u64), stream.raw()) ||
            !gpuMemsetZero(scratch.mFlag, sizeof(u32), stream.raw()))
        {
            return false;
        }

        if (!launchValidateGoldenSeed(
                ring->view(stream), ring->denoiseView(), tbk.mImpl->mBuf.data(stream),
                static_cast<u32>(tbk.count()), mu, scratch.mMarginLo, scratch.mMarginHi, scratch.mFlag,
                stream.raw()))
        {
            return false;
        }

        if (!gpuMemcpyD2H(&fail, scratch.mFlag, sizeof(u32), stream.raw()) || !drain.sync())
        {
            return false;
        }
        ok = (fail == 0);
        return true;
    }

    namespace
    {
        bool enqueueLeafGoldenValidation(const Params& params, const RingNttContext& ctx,
            const DeviceBatch& tbk, GpuStream& stream, bool deferred)
        {
            HostStep validationStep(hostProfiler(ctx), "gpu: leaf golden enqueue");
            if (!enabled(ctx) || !params.mW || !params.mShrinkExpand.mMu || tbk.empty() ||
                params.mCt2SeedMode != Ct2SeedMode::GoldenSeed) return false;
            if (ctx.mParams != params.mShrinkExpand.mRing) return false;
            auto ring = GpuRing::get(ctx);
            const std::size_t mu = params.mShrinkExpand.mMu;
            const std::size_t padded = ((static_cast<std::size_t>(params.mW) + mu - 1) / mu) * mu;
            if (!ring || !tbk.mImpl || tbk.mImpl->mRing != ring ||
                tbk.mImpl->mBuf.count() < tbk.count() ||
                (tbk.count() != params.mW && tbk.count() != padded)) return false;

            auto& scratch = validateScratch(stream);
            if (deferred)
            {
                if (!scratch.mAttemptActive || scratch.mAttemptStream != stream.raw() ||
                    scratch.mAttemptRho != ring->rho()) return false;
            }
            else if (scratch.mAttemptActive || !scratch.ensure(ring->rho()) ||
                !gpuMemsetZero(scratch.mFlag, sizeof(u32), stream.raw())) return false;

            LeafGoldenSeedRoundingConstants constants;
            {
                HostStep constantsStep(hostProfiler(ctx), "gpu: leaf golden constants");
                if (!leafGoldenSeedRoundingConstants(params, ctx, constants)) return false;
            }
            std::vector<LeafGoldenSeedLimb> limbs(ring->rho());
            for (std::size_t i = 0; i < limbs.size(); ++i)
            {
                auto& limb = limbs[i];
                limb.mQ = ringModulusValue(ctx, i);
                // Same quotient as MultiplyUIntModOperand::set, without
                // constructing a Modulus and repeating its primality test.
                u64 numerator[2]{0, constants.mInverse[i]};
                u64 quotient[2]{};
                seal::util::divide_uint128_inplace(numerator, limb.mQ, quotient);
                limb.mInverse = {constants.mInverse[i], quotient[0]};
                limb.mReciprocalLo = constants.mReciprocalLo[i];
                limb.mReciprocalHi = constants.mReciprocalHi[i];
            }
            if (!gpuMemcpyH2D(scratch.mLeaf, limbs.data(), limbs.size() * sizeof(LeafGoldenSeedLimb),
                    stream.raw())) return false;
            Region regKern(GpuStream::RegionKind::Kernel, stream);
            return launchValidateLeafGoldenSeed(ring->view(stream), scratch.mLeaf, tbk.mImpl->mBuf.data(stream),
                params.mW, constants.mMarginLo, constants.mMarginHi, scratch.mFlag, stream.raw());
        }
    }

    bool queueLeafGoldenSeedValidation(GoldenValidationAttempt& attempt,
        const Params& params, const RingNttContext& ctx,
        const DeviceBatch& tbk)
    {
        AutoTimer timer(timingCounter(timingStats(ctx), &TimingStats::mGpuMiscTimeUs));
        return attempt.stream() &&
            enqueueLeafGoldenValidation(params, ctx, tbk, *attempt.stream(), true);
    }

    bool validateLeafGoldenSeedDevice(const Params& params, const RingNttContext& ctx,
        const DeviceBatch& tbk, bool& ok)
    {
        AutoTimer timer(timingCounter(timingStats(ctx), &TimingStats::mGpuMiscTimeUs));
        if (!enabled(ctx) || !ctx.mGpuExecution) return false;
        auto& stream = contextStream(ctx);
        if (!enqueueLeafGoldenValidation(params, ctx, tbk, stream, false)) return false;
        u32 failed = 0;
        StreamDrain drain{stream};
        const bool copied = gpuMemcpyD2H(&failed, validateScratch(stream).mFlag, sizeof(u32), stream.raw());
        const bool synced = drain.sync();
        if (!copied || !synced) return false;
        ok = failed == 0;
        return true;
    }

    // ---- denoise ----------------------------------------------------------

    bool denoiseCombBatch(
        const RingNttContext& ctx, const std::vector<RnsPoly>& in, std::vector<RnsPoly>& out)
    {
        AutoTimer timer(timingCounter(timingStats(ctx), &TimingStats::mGpuMiscTimeUs));
        if (!enabled(ctx)) return false;
        auto ring = GpuRing::get(ctx);
        if (!ring || !ring->denoiseReady()) return false;
        const u32 rho = ring->rho();
        if (rho == 0 || in.empty() || in.size() % rho != 0) return false;

        const std::size_t outCount = in.size() / rho;
        auto& stream = contextStream(ctx);
        stream.reset();

        GpuPolyBuffer src;
        GpuPolyBuffer dst;
        if (!src.resize(*ring, in.size(), stream) || !dst.resize(*ring, outCount, stream)) return false;
        {
            Region regUp(GpuStream::RegionKind::Upload, stream);
            if (!src.upload(in, stream)) return false;
        }
        {
            Region regKern(GpuStream::RegionKind::Kernel, stream);
            if (!denoiseComb(*ring, src.data(stream), dst.data(stream), static_cast<u32>(outCount), stream))
                return false;
        }
        Region regDown(GpuStream::RegionKind::Download, stream);
        return dst.download(out, stream, 0, outCount);
    }

    bool sampleUniformFromSeedsForTest(
        const RingNttContext& ctx,
        std::span<const block> seeds,
        u64 domainTag,
        u32 index,
        std::vector<RnsPoly>& out,
        std::span<const u64> maxMultipleOverride)
    {
        if (!enabled(ctx) || seeds.empty()) return false;
        auto ring = GpuRing::get(ctx);
        if (!ring) return false;

        // Mirror deriveUniformPolyFromSeed's seed derivation on the host.
        std::vector<u64> sealSeeds;
        sealSeeds.reserve(seeds.size() * 8);
        for (block seed : seeds)
        {
            block polySeed{};
            RandomOracle ro(sizeof(polySeed));
            constexpr u64 label = 0x4C4F47564F4C5059ull;
            roUpdate(ro, label);
            roUpdate(ro, seed);
            roUpdate(ro, domainTag);
            roUpdate(ro, index);
            roUpdate(ro, ctx.mParams.mPolyModulusDegree);
            const u64 modulusCount = static_cast<u64>(ctx.mParams.mCoeffModulusBits.size());
            roUpdate(ro, modulusCount);
            ro.Final(polySeed);

            PRNG prng(polySeed);
            std::array<u64, 8> s{};
            prng.get(s.data(), s.size());
            sealSeeds.insert(sealSeeds.end(), s.begin(), s.end());
        }

        std::vector<u64> maxMultiple(ring->rho());
        constexpr u64 maxRandom = ~u64(0);
        for (u32 j = 0; j < ring->rho(); ++j)
        {
            const seal::Modulus mod(ring->hostModuli()[j]);
            maxMultiple[j] = maxRandom - seal::util::barrett_reduce_64(maxRandom, mod) - 1;
        }
        if (!maxMultipleOverride.empty())
        {
            if (maxMultipleOverride.size() != maxMultiple.size()) return false;
            std::copy(maxMultipleOverride.begin(), maxMultipleOverride.end(), maxMultiple.begin());
        }

        auto& stream = contextStream(ctx);
        StreamDrain drain{stream};
        auto& scratch = sampleScratch(stream);
        if (!scratch.ensureSeeds(sealSeeds.size()) ||
            !scratch.ensureRoundKeys(seeds.size() * 176u)) return false;
        u32* rejectEpochs = nullptr;
        u32 rejectEpoch = 0;
        if (!scratch.nextRejectEpoch(seeds.size(), stream.raw(), rejectEpochs, rejectEpoch)) return false;

        auto maxStorage = tryAllocateGpuBuffer(stream, maxMultiple.size() * sizeof(u64));
        auto* dMax = static_cast<u64*>(maxStorage.data());
        GpuPolyBuffer dst;
        if (!dMax || !dst.resize(*ring, seeds.size(), stream))
        {
            return false;
        }

        bool ok =
            gpuMemcpyH2D(scratch.mSeeds, sealSeeds.data(), sealSeeds.size() * sizeof(u64), stream.raw()) &&
            gpuMemcpyH2D(dMax, maxMultiple.data(), maxMultiple.size() * sizeof(u64), stream.raw()) &&
            launchSampleUniformPolyAes(
                ring->view(stream), scratch.mSeeds, dMax, dst.data(stream), nullptr,
                static_cast<u32>(seeds.size()), scratch.mRoundKeys, scratch.mRoundKeyBytes,
                rejectEpochs, rejectEpoch, stream.raw());

        if (ok) ok = dst.download(out, stream, 0, seeds.size());
        return ok;
    }

    bool ct2BatchForTest(
        const RingNttContext& ctx,
        u32 mu,
        std::span<const u8> seed,
        u64 sid,
        const RnsPoly& digest,
        u64 instanceBase,
        u32 chunkCount,
        std::vector<RnsPoly>& out)
    {
        if (!enabled(ctx) || mu == 0 || chunkCount == 0) return false;
        auto ring = GpuRing::get(ctx);
        if (!ring) return false;

        std::vector<u64> maxMultiple(ring->rho());
        constexpr u64 maxRandom = ~u64(0);
        for (u32 j = 0; j < ring->rho(); ++j)
        {
            const seal::Modulus mod(ring->hostModuli()[j]);
            maxMultiple[j] = maxRandom - seal::util::barrett_reduce_64(maxRandom, mod) - 1;
        }
        auto& stream = contextStream(ctx);
        StreamDrain drain{stream};
        auto maxStorage = tryAllocateGpuBuffer(stream, maxMultiple.size() * sizeof(u64));
        auto* dMax = static_cast<u64*>(maxStorage.data());
        if (!dMax) return false;

        OfflineCache cache{};
        cache.mMaxMultiple = dMax;

        GpuPolyBuffer dst;
        bool ok = gpuMemcpyH2D(dMax, maxMultiple.data(), maxMultiple.size() * sizeof(u64), stream.raw()) &&
                  sampleCt2Batch(
                      *ring, cache, ctx.mParams, chunkCount, mu, seed, sid, instanceBase,
                      hashSeedDigest(digest), dst, stream);
        if (ok) ok = dst.download(out, stream, 0, static_cast<std::size_t>(chunkCount) * mu);
        return ok;
    }

    namespace
    {
        std::shared_ptr<GpuPlainNtt> gpuPlainTables(const ZpCrtContext& zp, ProtocolCacheScopeView scope)
        {
            if (zp.mGpuLightweight)
                return GpuPlainNtt::getRaw(
                    zp.mRing.mParams.mPolyModulusDegree, zp.mPlaintextModulus,
                    zp.mRing.mResourceScope, zp.mRing.mGpuSetup, scope);
            if (!zp.mBatchingContext || !zp.mBatchEncoder) return nullptr;
            return GpuPlainNtt::get(*zp.mBatchingContext, *zp.mBatchEncoder, zp.mRing.mResourceScope, scope);
        }
    }

    namespace
    {
        // scale-and-round -> plaintext NTT -> slot gather, leaving the scalars on
        // the device. `out` receives them; when `host` is non-null they are also
        // copied there.
        bool unwrapFromDevice(
            const ZpCrtContext& zp,
            GpuRing& ring,
            const u64* labels,
            u64 chunkCount,
            u64 zpLabelCount,
            u64* host,
            DeviceScalarsPtr* deviceOut, ProtocolCacheScopeView scope)
        {
            if (chunkCount == 0 || zpLabelCount == 0) return false;
            if (chunkCount > std::numeric_limits<u32>::max()) return false;
            auto plain = gpuPlainTables(zp, scope);
            if (!plain || plain->n() != ring.n()) return false;

            const u32 n = ring.n();
            const u32 slots = plain->slotCount();
            if (zpLabelCount > static_cast<u64>(chunkCount) * slots) return false;

            ScaleRoundConstView consts{};
            if (!ring.scaleRoundConstants(zp.mPlaintextModulus, consts)) return false;

            auto& stream = contextStream(zp.mRing);
            const auto chunks = static_cast<u32>(chunkCount);

            // The scalar array is owned by a DeviceScalars when the caller wants
            // to keep it, and is scratch otherwise.
            auto scalars = std::make_shared<DeviceScalars>();
            if (!scalars->resize(static_cast<std::size_t>(zpLabelCount), stream))
                return false;
            u64* flat = scalars->data();

            // In the fixed production geometry the scale result can stay in the
            // plaintext NTT's shared tile. Decide before allocating coeffs so the
            // fused path removes the full chunks*N scratch buffer, while every
            // ineligible/toggled-off case retains the established launch chain.
            const bool fusedScale =
                fusedScaleUnwrapEnabled(zp.mRing.mExecutionOptions.mAdvanced.mProtocol) && fusedUnwrapEnabled(zp.mRing.mExecutionOptions.mAdvanced.mProtocol) &&
                canLaunchScaleNttForwardGather(
                    ring.view(stream), plain->view(stream), labels, chunks,
                    zp.mPlaintextModulus, consts.mFastLimbs,
                    plain->inverseSlotMap(), slots, flat, zpLabelCount);
            OwnedGpuBuffer coefficientStorage;
            u64* coeffs = nullptr;
            if (!fusedScale)
            {
                const std::size_t coeffWords = static_cast<std::size_t>(chunks) * n;
                coefficientStorage = tryAllocateGpuBuffer(stream, coeffWords * sizeof(u64));
                coeffs = static_cast<u64*>(coefficientStorage.data());
                if (!coeffs) return false;
            }

            bool ok = true;
            {
                Region regKern(GpuStream::RegionKind::Kernel, stream);
                if (fusedScale)
                {
                    ok = launchScaleNttForwardGather(
                        ring.view(stream), plain->view(stream), labels, chunks,
                        zp.mPlaintextModulus, consts.mFastLimbs,
                        plain->inverseSlotMap(), plain->slotMap(), slots, flat,
                        zpLabelCount, stream.raw());
                }
                else
                {
                    ok = launchScaleAndRound(
                        ring.view(stream), labels, chunks, zp.mPlaintextModulus,
                        consts.mCrtInvPunctured, consts.mQ, consts.mPShoup,
                        consts.mFracLo, consts.mFracHi, consts.mFastLimbs,
                        coeffs, stream.raw());
                    if (ok && fusedUnwrapEnabled(zp.mRing.mExecutionOptions.mAdvanced.mProtocol))
                    {
                        ok = launchNttForwardGather(
                            plain->view(stream), coeffs, chunks,
                            plain->inverseSlotMap(), slots, flat,
                            zpLabelCount, stream.raw());
                    }
                    else if (ok)
                    {
                        // BatchEncoder::decode's ntt_negacyclic_harvey, followed by
                        // its matrix_reps_index_map_ permutation.
                        ok = launchNttForward(
                                 plain->view(stream), coeffs, chunks, nullptr,
                                 stream.raw()) &&
                             launchGatherSlots(
                                 coeffs, n, plain->slotMap(), slots, chunks,
                                 flat, zpLabelCount, stream.raw());
                    }
                }
            }
            if (ok && host)
            {
                // A plain pageable copy is the right choice here and was measured
                // against the alternatives (see -lvgpu "D2H" rows). The driver
                // faults the destination pages in bulk and reaches 12.9 GB/s;
                // staging through pinned buffers and copying on the host only
                // reaches 5.1 GB/s on a fresh destination because the explicit
                // memcpy faults page by page.
                Region regDown(GpuStream::RegionKind::Download, stream);
                ok = gpuMemcpyD2H(
                         host, flat, static_cast<std::size_t>(zpLabelCount) * sizeof(u64), stream.raw()) &&
                     stream.sync();
            }
            else if (ok)
            {
                // Device-output path: the caller receives a handle, not host bytes,
                // so there is nothing to wait for here. Record the producing stream
                // and let whoever eventually reads it order against that.
                // resize() retained this stream before work was submitted.
            }
            if (ok && deviceOut) *deviceOut = std::move(scalars);
            return ok;
        }
    }

    bool unwrapLabelsDevice(
        const ZpCrtContext& zp,
        const DeviceBatch& labels,
        u64 chunkCount,
        u64 zpLabelCount,
        u64* out, ProtocolCacheScopeView scope)
    {
        AutoTimer timer(timingCounter(timingStats(zp.mRing), &TimingStats::mGpuMiscTimeUs));
        if (!enabled(zp.mRing) || labels.empty() || !out) return false;
        auto ring = GpuRing::get(zp.mRing);
        if (!ring) return false;
        if (labels.count() < chunkCount) return false;
        return unwrapFromDevice(
            zp, *ring, labels.mImpl->mBuf.data(contextStream(zp.mRing)), chunkCount, zpLabelCount, out, nullptr, scope);
    }

    DeviceScalarsPtr unwrapLabelsToDevice(
        const ZpCrtContext& zp,
        const DeviceBatch& labels,
        u64 chunkCount,
        u64 zpLabelCount, ProtocolCacheScopeView scope)
    {
        AutoTimer timer(timingCounter(timingStats(zp.mRing), &TimingStats::mGpuMiscTimeUs));
        if (!enabled(zp.mRing) || labels.empty()) return nullptr;
        auto ring = GpuRing::get(zp.mRing);
        if (!ring) return nullptr;
        if (labels.count() < chunkCount) return nullptr;
        DeviceScalarsPtr out;
        if (!unwrapFromDevice(
                zp, *ring, labels.mImpl->mBuf.data(contextStream(zp.mRing)), chunkCount, zpLabelCount, nullptr, &out, scope))
        {
            return nullptr;
        }
        return out;
    }

    bool unwrapLabelsBatch(
        const ZpCrtContext& zp,
        const std::vector<RnsPoly>& labels,
        u64 zpLabelCount,
        u64* out, ProtocolCacheScopeView scope)
    {
        AutoTimer timer(timingCounter(timingStats(zp.mRing), &TimingStats::mGpuMiscTimeUs));
        if (!enabled(zp.mRing) || labels.empty() || !out) return false;
        auto ring = GpuRing::get(zp.mRing);
        if (!ring) return false;

        auto& stream = contextStream(zp.mRing);
        GpuPolyBuffer src;
        {
            Region regUp(GpuStream::RegionKind::Upload, stream);
            if (!src.resize(*ring, labels.size(), stream) || !src.upload(labels, stream)) return false;
        }
        return unwrapFromDevice(zp, *ring, src.data(stream), labels.size(), zpLabelCount, out, nullptr, scope);
    }

    bool unwrapLabelsBatchUnscaled(
        const ZpCrtContext& zp,
        const std::vector<RnsPoly>& labels,
        u64 chunkCount,
        u64 zpLabelCount,
        u64* out, ProtocolCacheScopeView scope)
    {
        AutoTimer timer(timingCounter(timingStats(zp.mRing), &TimingStats::mGpuMiscTimeUs));
        if (!enabled(zp.mRing) || !chunkCount || !zpLabelCount || !out ||
            chunkCount > labels.size() ||
            chunkCount > std::numeric_limits<u32>::max()) return false;
        auto ring = GpuRing::get(zp.mRing);
        auto plain = gpuPlainTables(zp, scope);
        if (!ring || !plain || plain->n() != ring->n() ||
            plain->slotCount() != ring->n() ||
            plain->metadata().mMinModulus != zp.mPlaintextModulus ||
            zpLabelCount > chunkCount * static_cast<u64>(plain->slotCount()))
            return false;

        auto& stream = contextStream(zp.mRing);
        GpuPolyBuffer source;
        OwnedGpuBuffer coefficients, scalars;
        // Every queued operation must finish before source and scratch owners
        // release their role-local bytes, including an error after submission.
        StreamDrain drain{stream};
        const std::size_t coeffCount = static_cast<std::size_t>(chunkCount) * ring->n();
        coefficients = tryAllocateGpuBuffer(stream, coeffCount * sizeof(u64));
        scalars = tryAllocateGpuBuffer(stream, static_cast<std::size_t>(zpLabelCount) * sizeof(u64));
        if (!coefficients || !scalars || !source.resize(*ring, chunkCount, stream))
            return false;
        {
            Region upload(GpuStream::RegionKind::Upload, stream);
            if (!source.upload(
                    std::span<const RnsPoly>(labels.data(),
                        static_cast<std::size_t>(chunkCount)), stream)) return false;
        }
        auto* coeff = static_cast<u64*>(coefficients.data());
        auto* flat = static_cast<u64*>(scalars.data());
        const u32 chunks = static_cast<u32>(chunkCount);
        bool ok = false;
        {
            Region kernels(GpuStream::RegionKind::Kernel, stream);
            ok = launchComposeReducePlain(
                ring->view(stream), plain->view(stream), source.data(stream), chunks,
                coeff, stream.raw());
            if (ok && fusedUnwrapEnabled(zp.mRing.mExecutionOptions.mAdvanced.mProtocol))
                ok = launchNttForwardGather(
                    plain->view(stream), coeff, chunks,
                    plain->inverseSlotMap(), plain->slotCount(), flat,
                    zpLabelCount, stream.raw());
            else if (ok)
                ok = launchNttForward(
                         plain->view(stream), coeff, chunks, nullptr,
                         stream.raw()) &&
                     launchGatherSlots(
                         coeff, ring->n(), plain->slotMap(),
                         plain->slotCount(), chunks, flat,
                         zpLabelCount, stream.raw());
        }
        if (!ok) return false;
        {
            Region download(GpuStream::RegionKind::Download, stream);
            return gpuMemcpyD2H(
                       out, flat, static_cast<std::size_t>(zpLabelCount) * sizeof(u64),
                       stream.raw()) && stream.sync();
        }
    }

    namespace
    {
        // Everything wrapLabelsDevice does once the scalars are in device memory.
        // `scalars` is borrowed, never freed here, so the same pipeline serves a
        // host input that was just uploaded and an input that a previous GPU
        // stage produced.
        DeviceBatchPtr wrapScalarsOnDevice(
            const ZpCrtContext& zp,
            const u64* scalars,
            std::size_t labelCount,
            bool multiplyByDelta,
            u64 padValue,
            u64 padChunks,
            bool garbledInput,
            ReceiverFirstQueryAllocations* firstQueryAllocations,
            const void* firstQueryOwner, u64 firstQuerySid, ProtocolCacheScopeView scope)
    {
        if (!enabled(zp.mRing) || !scalars || labelCount == 0) return nullptr;
        auto ring = GpuRing::get(zp.mRing);
        if (!ring) return nullptr;
        auto plain = gpuPlainTables(zp, scope);
        if (!plain || plain->n() != ring->n()) return nullptr;

        const u32 n = ring->n();
        const u32 rho = ring->rho();
        const u32 slots = plain->slotCount();
        const u64 perRing = garbledInput ? slots / 3 : slots;
        if (!perRing || (garbledInput && (multiplyByDelta || padValue))) return nullptr;
        const u64 chunkCount = labelCount / perRing + (labelCount % perRing != 0);
        const u64 total = std::max<u64>(chunkCount, padChunks);
        if (total == 0 || total > std::numeric_limits<u32>::max()) return nullptr;

        // A/B reference: materialize x' on the GPU. The default reads x directly
        // in the inverse-NTT load, eliminating an allocation and a write/read of
        // the entire threefold input (about 512 MiB at 2^25 scalar slots).
        if (garbledInput && !zp.mRing.mExecutionOptions.mAdvanced.mProtocol.mGarbledFusedInput)
        {
            auto& repeatStream = contextStream(zp.mRing);
            auto repeated = std::make_shared<DeviceScalars>();
            if (!repeated->resize(chunkCount * slots, repeatStream) ||
                !launchRepeatGarbledInputs(scalars, labelCount, slots,
                    static_cast<u32>(chunkCount), repeated->data(), repeatStream.raw()))
                return nullptr;
            return wrapScalarsOnDevice(zp, repeated->data(), chunkCount * slots,
                false, 0, padChunks, false, nullptr, nullptr, 0, scope);
        }

        auto& stream = contextStream(zp.mRing);
        // Each stream retains its immutable lift factors until all queued uses
        // finish. No process-wide owner or default-stream upload is involved.
        const u64* lift = nullptr;
        if (multiplyByDelta)
        {
            if (zp.mPlaintextLiftModQj.size() != rho) return nullptr;
            auto& liftCache = stream.protocolScratch().plaintextLifts;
            for (const auto& [key, storage] : liftCache)
            {
                if (key.size() == rho && std::equal(key.begin(), key.end(), zp.mPlaintextLiftModQj.begin()))
                {
                    lift = static_cast<const u64*>(storage.data());
                    break;
                }
            }
            if (!lift)
            {
                std::vector<u64> key(zp.mPlaintextLiftModQj.begin(), zp.mPlaintextLiftModQj.end());
                auto storage = tryAllocateGpuBuffer(stream, key.size() * sizeof(u64));
                if (!storage) return nullptr;
                const bool copied = gpuMemcpyH2D(storage.data(), key.data(), key.size() * sizeof(u64), stream.raw());
                const bool complete = stream.sync();
                if (!copied || !complete) return nullptr;
                lift = static_cast<const u64*>(storage.data());
                liftCache.emplace_back(std::move(key), std::move(storage));
            }
        }

        auto out = std::make_shared<DeviceBatch>();
        out->mImpl->mRing = ring;
        if (!multiplyByDelta)
            out->mImpl->mPlainBroadcastBits = bitWidth(zp.mPlaintextModulus - 1u);
        const bool reservedWrap = !multiplyByDelta && !padValue &&
            takeReceiverFirstQueryWrap(
                firstQueryAllocations, *ring, zp.mRing.mParams,
                labelCount, static_cast<std::size_t>(total), garbledInput,
                firstQueryOwner, firstQuerySid, out->mImpl->mBuf, stream, scope);
        if (!reservedWrap && !out->mImpl->mBuf.resize(
                *ring, static_cast<std::size_t>(total), stream)) return nullptr;
        // Chunks past the real input are all-zero ring elements, matching the
        // explicit padding in civoleReceiverSetX.
        if (total > chunkCount && !out->mImpl->mBuf.zero(stream)) return nullptr;

        const auto chunks = static_cast<u32>(chunkCount);
        const bool fusedWrap =
            fusedWrapEnabled(zp.mRing.mExecutionOptions.mAdvanced.mProtocol) && !multiplyByDelta &&
            canLaunchNttInverseScatterBroadcast(plain->view(stream), ring->view(stream));
        const bool singleLimbWrap =
            fusedWrap && plainBroadcastSingleLimbEnabled(zp.mRing.mExecutionOptions.mAdvanced.mProtocol) &&
            canLaunchNttInverseScatterSingleLimb(
                plain->view(stream), ring->view(stream));
        out->mImpl->mPlainBroadcastSingleLimb = singleLimbWrap;

        // The fused path consumes scalars directly and writes the ring batch, so
        // only the exact legacy path needs the N-word-per-chunk plaintext scratch.
        OwnedGpuBuffer coefficientStorage;
        u64* coeffs = nullptr;
        if (!fusedWrap)
        {
            const std::size_t coeffWords = static_cast<std::size_t>(chunkCount) * n;
            coefficientStorage = tryAllocateGpuBuffer(stream, coeffWords * sizeof(u64));
            coeffs = static_cast<u64*>(coefficientStorage.data());
            if (!coeffs) return nullptr;
        }

        bool ok = false;
        {
            Region regKern(GpuStream::RegionKind::Kernel, stream);
            if (fusedWrap)
            {
                ok = singleLimbWrap
                    ? launchNttInverseScatterSingleLimb(
                          plain->view(stream), ring->view(stream), scalars, labelCount,
                          padValue, plain->inverseSlotMap(), chunks,
                          out->mImpl->mBuf.data(stream), stream.raw(), garbledInput)
                    : launchNttInverseScatterBroadcast(
                          plain->view(stream), ring->view(stream), scalars, labelCount,
                          padValue, plain->inverseSlotMap(), chunks,
                          out->mImpl->mBuf.data(stream), stream.raw(), garbledInput);
            }
            else
            {
                ok = launchScatterSlots(
                         scalars, labelCount, padValue, plain->slotMap(), slots, chunks, coeffs, n,
                         stream.raw(), garbledInput) &&
                     // BatchEncoder::encode's inverse_ntt_negacyclic_harvey.
                     launchNttInverse(plain->view(stream), coeffs, chunks, nullptr, stream.raw()) &&
                     launchLiftPlainToRing(
                         ring->view(stream), coeffs, chunks, lift, out->mImpl->mBuf.data(stream), stream.raw());
            }
            // No drain: the wrapped input is device resident and is consumed on
            // this stream. Owned scratch releases remain stream ordered.
        }
        return ok ? out : nullptr;
    }
    }

    DeviceBatchPtr wrapLabelsDevice(
        const ZpCrtContext& zp,
        std::span<const u64> labels,
        bool multiplyByDelta,
        u64 padValue,
        u64 padChunks,
        bool garbledInput, ProtocolCacheScopeView scope)
    {
        AutoTimer timer(timingCounter(timingStats(zp.mRing), &TimingStats::mGpuMiscTimeUs));
        if (!enabled(zp.mRing) || labels.empty()) return nullptr;

        auto& stream = contextStream(zp.mRing);
        auto scalarStorage = tryAllocateGpuBuffer(stream, labels.size_bytes());
        auto* scalars = static_cast<u64*>(scalarStorage.data());
        if (!scalars) return nullptr;

        bool ok = false;
        {
            Region regUp(GpuStream::RegionKind::Upload, stream);
            ok = uploadFromHost(scalars, labels.data(), labels.size() * sizeof(u64), stream);
        }
        DeviceBatchPtr out = ok
            ? wrapScalarsOnDevice(
                  zp, scalars, labels.size(), multiplyByDelta, padValue, padChunks,
                  garbledInput, nullptr, nullptr, 0, scope)
            : nullptr;
        // Stream ordered, like the scratch frees inside the helper.
        return out;
    }

    DeviceBatchPtr wrapDeviceLabels(
        const ZpCrtContext& zp,
        const DeviceScalars& labels,
        u64 labelCount,
        bool multiplyByDelta,
        u64 padValue,
        u64 padChunks,
        bool garbledInput,
        ReceiverFirstQueryAllocations* firstQueryAllocations,
        const void* firstQueryOwner, u64 firstQuerySid, ProtocolCacheScopeView scope)
    {
        AutoTimer timer(timingCounter(timingStats(zp.mRing), &TimingStats::mGpuMiscTimeUs));
        if (!enabled(zp.mRing) || labels.empty()) return nullptr;
        const std::size_t count = labelCount
            ? std::min<std::size_t>(static_cast<std::size_t>(labelCount), labels.count())
            : labels.count();
        // This consumer returns before its read completes. Retain and record
        // its stream before submission, even though the input is immutable.
        if (!labels.prepareUse(contextStream(zp.mRing))) return nullptr;
        return wrapScalarsOnDevice(
            zp, labels.data(), count, multiplyByDelta, padValue, padChunks,
            garbledInput, firstQueryAllocations,
            firstQueryOwner, firstQuerySid, scope);
    }

    DeviceBatchPtr wrapSetupDeltaResident(const ZpCrtContext& ctx, u64 delta,
        std::span<const u64> deltaSlots, const std::array<u64, 3>* garbledDeltas, ProtocolCacheScopeView scope)
    {
        if (!enabled(ctx.mRing) || scope.mRole != ProtocolCacheRole::Sender ||
            !scope.mRunId || !ctx.mGpuLightweight || !ctx.mRing.mGpuLightweight ||
            ctx.mPlaintextModulus < 2 || !ringModulusCount(ctx.mRing)) return {};
        const auto slots = static_cast<std::size_t>(ctx.mRing.mParams.mPolyModulusDegree);
        const auto rho = ringModulusCount(ctx.mRing);
        constexpr std::size_t maxBytes = std::size_t{64} << 20;
        if (!slots || (slots & (slots - 1)) || slots > std::numeric_limits<u32>::max() ||
            rho > std::numeric_limits<u32>::max() ||
            slots > maxBytes / sizeof(u64) ||
            rho > maxBytes / (slots * sizeof(u64)) ||
            ctx.mPlaintextLiftModQj.size() != rho) return {};
        const auto nonzeroScalar = [&](u64 value) {
            return value != 0 && value < ctx.mPlaintextModulus;
        };
        if (garbledDeltas)
        {
            if (delta != 0 || !deltaSlots.empty() || slots < 3 ||
                !std::all_of(garbledDeltas->begin(), garbledDeltas->end(),
                    nonzeroScalar)) return {};
        }
        else if (!deltaSlots.empty())
        {
            if (delta != 0 || deltaSlots.size() != slots ||
                std::any_of(deltaSlots.begin(), deltaSlots.end(),
                    [&](u64 value) { return value >= ctx.mPlaintextModulus; }) ||
                std::all_of(deltaSlots.begin(), deltaSlots.end(),
                    [](u64 value) { return value == 0; })) return {};
        }
        else if (!nonzeroScalar(delta)) return {};
        const bool decline = ctx.mRing.mExecutionOptions.mAdvanced.mProtocol.mFailures.mDeltaDevice;
        const bool chainDecline = ctx.mRing.mExecutionOptions.mAdvanced.mProtocol.mFailures.mDeltaChain;
        if ((decline) ||
            (chainDecline)) return {};

        HostStep step(hostProfiler(ctx.mRing), "setup sender: resident wrapped delta");
        auto& stream = contextStream(ctx.mRing);
        auto ring = GpuRing::get(ctx.mRing);
        if (!ring || ring->n() != slots || ring->rho() != rho) return {};
        auto owner = std::make_shared<DeviceBatch>();
        GpuPolyBuffer output;
        OwnedGpuBuffer lift, values, coefficients;
        std::shared_ptr<GpuPlainNtt> plain;
        // This guard is deliberately constructed after every GPU allocation
        // owner, including slot scratch. An early post-submit decline must
        // finish queued work before any of those owners release their bytes.
        StreamDrain drain{stream};
        if (!output.resize(*ring, 1, stream)) return {};
        lift = tryAllocateGpuBuffer(stream, rho * sizeof(u64));
        if (!lift || !gpuMemcpyH2D(lift.data(),
                ctx.mPlaintextLiftModQj.data(), rho * sizeof(u64), stream.raw())) return {};
        const auto view = ring->view(stream);
        if (!garbledDeltas && deltaSlots.empty() &&
            ctx.mRing.mExecutionOptions.mAdvanced.mProtocol.mDeltaConstantDirect)
        {
            if (!launchPrepareConstantDelta(view, delta,
                    static_cast<const u64*>(lift.data()), output.data(stream),
                    stream.raw())) return {};
        }
        else
        {
            plain = gpuPlainTables(ctx, scope);
            if (!plain || plain->n() != slots ||
                plain->metadata().mMinModulus != ctx.mPlaintextModulus) return {};
            values = tryAllocateGpuBuffer(stream, slots * sizeof(u64));
            coefficients = tryAllocateGpuBuffer(stream, slots * sizeof(u64));
            if (!values || !coefficients) return {};
            auto* slotValues = static_cast<u64*>(values.data());
            auto* plainCoefficients = static_cast<u64*>(coefficients.data());
            if (!deltaSlots.empty())
            {
                if (!gpuMemcpyH2D(slotValues, deltaSlots.data(),
                        slots * sizeof(u64), stream.raw())) return {};
            }
            else if (!launchPrepareDeltaSlots(
                    garbledDeltas ? (*garbledDeltas)[0] : delta,
                    garbledDeltas ? (*garbledDeltas)[1] : 0,
                    garbledDeltas ? (*garbledDeltas)[2] : 0,
                    view.mN, garbledDeltas != nullptr, slotValues,
                    stream.raw())) return {};
            if (!launchScatterSlots(slotValues, slots, 0,
                    plain->slotMap(), view.mN, 1, plainCoefficients,
                    view.mN, stream.raw(), false) ||
                !launchNttInverse(plain->view(stream), plainCoefficients,
                    1, nullptr, stream.raw()) ||
                !launchLiftPlainToRing(view, plainCoefficients, 1,
                    static_cast<const u64*>(lift.data()), output.data(stream),
                    stream.raw())) return {};
        }
        if (!stream.sync()) return {};
        owner->mImpl->mRing = std::move(ring);
        owner->mImpl->mBuf = std::move(output);
        owner->mImpl->mSetupDeltaCoefficients = true;
        owner->mImpl->mSetupSenderRole = ProtocolCacheRole::Sender;
        owner->mImpl->mSetupSenderRunId = scope.mRunId;
        owner->mImpl->mIdentityService = (scope.mRunId).serviceOwner();
        owner->mImpl->mSetupSenderDevice = currentDeviceOrdinal();
        return owner;
    }

    bool wrapSetupDeltaDevice(const ZpCrtContext& ctx, u64 delta,
        std::span<const u64> deltaSlots, const std::array<u64, 3>* garbledDeltas,
        RnsPoly& out, ProtocolCacheScopeView scope)
    {
        if (!enabled(ctx.mRing) || ctx.mPlaintextModulus < 2 || !ringModulusCount(ctx.mRing) ||
            (ctx.mGpuLightweight
                ? !ctx.mRing.mGpuLightweight
                : (!ctx.mBatchingContext || !ctx.mBatchEncoder))) return false;
        const auto slots = ctx.mGpuLightweight
            ? static_cast<std::size_t>(ctx.mRing.mParams.mPolyModulusDegree)
            : ctx.mBatchEncoder->slot_count();
        if (!slots || slots != ctx.mRing.mParams.mPolyModulusDegree ||
            slots > std::numeric_limits<u32>::max()) return false;
        const auto nonzeroScalar = [&](u64 value) {
            return value != 0 && value < ctx.mPlaintextModulus;
        };
        if (garbledDeltas)
        {
            if (delta != 0 || !deltaSlots.empty() || slots < 3 ||
                !std::all_of(garbledDeltas->begin(), garbledDeltas->end(), nonzeroScalar)) return false;
        }
        else if (!deltaSlots.empty())
        {
            if (delta != 0 || deltaSlots.size() != slots ||
                std::any_of(deltaSlots.begin(), deltaSlots.end(),
                    [&](u64 value) { return value >= ctx.mPlaintextModulus; }) ||
                std::all_of(deltaSlots.begin(), deltaSlots.end(), [](u64 value) { return value == 0; })) return false;
        }
        else if (!nonzeroScalar(delta)) return false;
        const bool decline = ctx.mRing.mExecutionOptions.mAdvanced.mProtocol.mFailures.mDeltaDevice;
        if (decline) return false;

        HostStep deltaStep(hostProfiler(ctx.mRing), "setup: delta GPU preparation");
        auto& stream = contextStream(ctx.mRing);
        if (ctx.mRing.mExecutionOptions.mAdvanced.mProtocol.mDeltaLightweight)
        {
            HostStep lightweightStep(hostProfiler(ctx.mRing), "setup: delta lightweight GPU preparation");
            const auto key = ctx.mRing.mContext ? ctx.mRing.mContext->key_context_data() : nullptr;
            const auto rho = ringModulusCount(ctx.mRing);
            constexpr std::size_t maxBytes = std::size_t(64) << 20;
            if ((!ctx.mRing.mGpuLightweight && !key) || (slots & (slots - 1)) || rho == 0 ||
                rho > std::numeric_limits<u32>::max() ||
                slots > maxBytes / sizeof(u64) || rho > maxBytes / (slots * sizeof(u64)) ||
                (!ctx.mRing.mGpuLightweight &&
                    (key->parms().poly_modulus_degree() != slots ||
                     key->parms().coeff_modulus().size() != rho)) ||
                ctx.mPlaintextLiftModQj.size() != rho) return false;

            // Raw GPU setup already owns validated device modulus ratios.
            // Reuse them without materializing any host SEAL modulus objects.
            auto ring = GpuRing::get(ctx.mRing);
            if (!ring || ring->n() != slots || ring->rho() != rho) return false;
            const auto view = ring->view(stream);
            OwnedGpuBuffer deviceLift;
            OwnedGpuBuffer deviceOutput, deviceSlots, devicePlain;
            std::shared_ptr<GpuPlainNtt> plain;
            RnsPoly next;
            StreamDrain drain{stream};
            const std::size_t words = slots * rho;
            const std::size_t bytes = words * sizeof(u64);
            deviceLift = tryAllocateGpuBuffer(stream, rho * sizeof(u64));
            deviceOutput = tryAllocateGpuBuffer(stream, bytes);
            if (!deviceLift || !deviceOutput ||
                !gpuMemcpyH2D(deviceLift.data(), ctx.mPlaintextLiftModQj.data(), rho * sizeof(u64), stream.raw())) return false;
            auto* destination = static_cast<u64*>(deviceOutput.data());
            const auto* lift = static_cast<const u64*>(deviceLift.data());
            if (!garbledDeltas && deltaSlots.empty() && ctx.mRing.mExecutionOptions.mAdvanced.mProtocol.mDeltaConstantDirect)
            {
                if (!launchPrepareConstantDelta(view, delta, lift, destination, stream.raw())) return false;
            }
            else
            {
                plain = gpuPlainTables(ctx, scope);
                if (!plain || plain->n() != slots || plain->metadata().mMinModulus != ctx.mPlaintextModulus)
                    return false;
                deviceSlots = tryAllocateGpuBuffer(stream, slots * sizeof(u64));
                devicePlain = tryAllocateGpuBuffer(stream, slots * sizeof(u64));
                if (!deviceSlots || !devicePlain) return false;
                auto* values = static_cast<u64*>(deviceSlots.data());
                auto* coefficients = static_cast<u64*>(devicePlain.data());
                if (!deltaSlots.empty())
                {
                    if (!gpuMemcpyH2D(values, deltaSlots.data(), slots * sizeof(u64), stream.raw())) return false;
                }
                else if (!launchPrepareDeltaSlots(
                    garbledDeltas ? (*garbledDeltas)[0] : delta,
                    garbledDeltas ? (*garbledDeltas)[1] : 0,
                    garbledDeltas ? (*garbledDeltas)[2] : 0,
                    view.mN, garbledDeltas != nullptr, values, stream.raw())) return false;
                if (!launchScatterSlots(values, slots, 0, plain->slotMap(), view.mN, 1,
                        coefficients, view.mN, stream.raw(), false) ||
                    !launchNttInverse(plain->view(stream), coefficients, 1, nullptr, stream.raw()) ||
                    !launchLiftPlainToRing(view, coefficients, 1, lift, destination, stream.raw())) return false;
            }
            next.mCoeffs.resize(words);
            if (ctx.mRing.mExecutionOptions.mAdvanced.mProtocol.mDeltaSmallDownload)
            {
                if (!gpuMemcpyD2H(next.mCoeffs.data(), destination, bytes, stream.raw()) || !stream.sync())
                    return false;
            }
            else
            {
                auto* stage = stream.staging(bytes);
                if (!stage || !gpuMemcpyD2H(stage, destination, bytes, stream.raw()) || !stream.sync())
                    return false;
                std::memcpy(next.mCoeffs.data(), stage, bytes);
            }
            out = std::move(next);
            return true;
        }
        DeviceScalarsPtr prepared;
        DeviceBatchPtr wrapped;
        std::shared_ptr<GpuRing> constantRing;
        GpuPolyBuffer constantPoly;
        OwnedGpuBuffer constantLift;
        std::vector<RnsPoly> next;
        StreamDrain drain{stream};
        auto downloadDelta = [&](const GpuPolyBuffer& values) {
            constexpr std::size_t maxSmallBytes = std::size_t(1) << 20;
            if (ctx.mRing.mExecutionOptions.mAdvanced.mProtocol.mDeltaSmallDownload && values.count() == 1 &&
                values.data(stream) && values.polyWords() &&
                values.polyWords() <= maxSmallBytes / sizeof(u64))
            {
                HostStep downloadStep(hostProfiler(ctx.mRing), "setup: delta small host snapshot");
                // One <=1 MiB result does not need the stream's minimum 8 MiB
                // pinned staging allocation. Allocate without a CPU fill and
                // preserve the completed host snapshot inside the setup timer.
                next.resize(1);
                next[0].mCoeffs.resize(values.polyWords());
                return gpuMemcpyD2H(next[0].mCoeffs.data(), values.data(stream),
                    values.polyWords() * sizeof(u64), stream.raw()) && stream.sync();
            }
            return values.download(next, stream) && next.size() == 1;
        };
        if (!garbledDeltas && deltaSlots.empty() && ctx.mRing.mExecutionOptions.mAdvanced.mProtocol.mDeltaConstantDirect)
        {
            HostStep directStep(hostProfiler(ctx.mRing), "setup: constant delta GPU polynomial");
            constantRing = GpuRing::get(ctx.mRing);
            if (!constantRing || ctx.mPlaintextLiftModQj.size() != constantRing->rho() ||
                !constantPoly.resize(*constantRing, 1, stream)) return false;
            const auto bytes = ctx.mPlaintextLiftModQj.size() * sizeof(u64);
            constantLift = tryAllocateGpuBuffer(stream, bytes);
            if (!constantLift || !gpuMemcpyH2D(constantLift.data(), ctx.mPlaintextLiftModQj.data(), bytes, stream.raw()) ||
                !launchPrepareConstantDelta(constantRing->view(stream), delta,
                    static_cast<const u64*>(constantLift.data()), constantPoly.data(stream), stream.raw()) ||
                !downloadDelta(constantPoly)) return false;
            out = std::move(next[0]);
            return true;
        }
        if (!deltaSlots.empty())
        {
            wrapped = wrapLabelsDevice(ctx, deltaSlots, true, 0, 1, false, scope);
        }
        else
        {
            prepared = std::make_shared<DeviceScalars>();
            if (!prepared->resize(slots, stream) || !launchPrepareDeltaSlots(
                    garbledDeltas ? (*garbledDeltas)[0] : delta,
                    garbledDeltas ? (*garbledDeltas)[1] : 0,
                    garbledDeltas ? (*garbledDeltas)[2] : 0,
                    static_cast<u32>(slots), garbledDeltas != nullptr, prepared->data(), stream.raw())) return false;
            wrapped = wrapDeviceLabels(ctx, *prepared, slots, true, 0, 1, false, nullptr, nullptr, 0, scope);
        }
        if (!wrapped || !wrapped->mImpl || wrapped->count() != 1 ||
            (wrapped->mImpl->mLogicalCount &&
                wrapped->mImpl->mLogicalCount != wrapped->mImpl->mBuf.count()) ||
            !ensurePlainBroadcastMaterialized(*wrapped->mImpl, stream) ||
            !downloadDelta(wrapped->mImpl->mBuf)) return false;
        out = std::move(next[0]);
        return true;
    }

    DeviceScalarsPtr uploadScalars(std::span<const u64> src, GpuStream& stream)
    {
        if (!stream.raw() || src.empty()) return nullptr;
        // Allocator reuse dependencies must be recorded on the stream that
        // will receive the upload, including after a protocol-role switch.
        auto out = std::make_shared<DeviceScalars>();
        if (!out->resize(src.size(), stream)) return nullptr;
        StreamDrain drain{stream};
        if (!gpuMemcpyH2D(out->data(), src.data(), src.size() * sizeof(u64), stream.raw()) ||
            !drain.sync())
        {
            return nullptr;
        }
        // The upload is complete. The token retains native allocation ownership,
        // independently of the producing execution context and host worker.
        out->markReady();
        return out;
    }

    DeviceScalarsPtr sampleScalarsFromSeed(block seed, u64 count, u64 modulus, GpuStream& stream)
    {
        if (!stream.raw() || !count || !modulus ||
            count > std::numeric_limits<std::size_t>::max() / sizeof(u64)) return nullptr;
        HostStep sampleStep(stream.hostProfiler(), "gpu: sample input scalars");
        auto out = std::make_shared<DeviceScalars>();
        std::array<u64, 2> seedWords{};
        std::memcpy(seedWords.data(), &seed, sizeof(seedWords));
        OwnedGpuBuffer deviceSeed;
        StreamDrain drain{stream};
        if (!out->resize(static_cast<std::size_t>(count), stream)) return nullptr;
        deviceSeed = tryAllocateGpuBuffer(stream, sizeof(seedWords));
        if (!deviceSeed || !gpuMemcpyH2D(deviceSeed.data(), seedWords.data(), sizeof(seedWords), stream.raw()) ||
            !launchAesCtrScalars(static_cast<const u64*>(deviceSeed.data()), out->data(),
                count, modulus, stream.raw()) || !drain.sync()) return nullptr;
        // Work is complete, so consumers need no dependency on this thread's
        // stream and may keep the result after the producing thread exits.
        out->markReady();
        return out;
    }
}

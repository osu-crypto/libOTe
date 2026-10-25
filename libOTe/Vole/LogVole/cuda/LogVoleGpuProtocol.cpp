#include "libOTe/Vole/LogVole/cuda/LogVoleGpuProtocol.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuBackend.h"

#include "libOTe/Vole/LogVole/LogVole.h"
#include "libOTe/Vole/LogVole/LogVoleArithmetic.h"
#include "libOTe/Vole/LogVole/LogVoleCore.h"
#include "libOTe/Vole/LogVole/LogVoleLenc.h"
#include "libOTe/Vole/LogVole/LogVoleLhe.h"
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
#include <stdexcept>
#include <thread>

namespace osuCrypto::LogVole::gpu
{
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
        mutable std::weak_ptr<const std::vector<RnsPoly>> mHostSnapshot;
        ProtocolCacheRole mRole = ProtocolCacheRole::Unspecified;
        u64 mRunId = 0;
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
        struct PublicRetentionEntry
        {
            std::weak_ptr<const std::vector<RnsPoly>> mHost;
            RetainedPublicUniformPtr mDevice;
        };
        std::mutex publicRetentionMutex;
        std::vector<PublicRetentionEntry> publicRetentionEntries;
        std::atomic<u64> publicRetentionCaptures{0}, publicRetentionCopies{0};
        std::atomic<u64> publicRetentionCopiedBytes{0}, publicRetentionMisses{0};
        std::atomic<u64> publicRetentionHostMaterializations{0};
        std::atomic<u64> publicRetentionHostMaterializedBytes{0};

        bool retentionContextMatches(const RingNttContext& ctx,
            const RetainedPublicUniform::Impl& value)
        {
            if (!value.mRing || value.mDevice < 0 || currentDeviceOrdinal() != value.mDevice ||
                value.mRole != currentProtocolCacheScope().mRole ||
                value.mRunId != currentProtocolCacheScope().mRunId ||
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
            std::span<const RnsPoly> host, GpuStream& stream)
        {
            auto retained = findPublicUniformRetention(ctx, host);
            if (!retained) return destination.upload(host, stream);
            const auto& values = retained->mImpl->mValues;
            if (destination.count() < values.count() ||
                destination.polyWords() != values.polyWords()) return false;
            HostStep copyStep("setup public uniform: retained D2D");
            // Finish the copy while the registry handle is alive. A concurrent
            // cache eviction can then release the source without racing DMA.
            const bool queued = gpuMemcpyD2D(destination.data(), values.data(), values.bytes(), stream.raw());
            const bool completed = stream.sync();
            if (!queued || !completed) return false;
            publicRetentionCopies.fetch_add(1, std::memory_order_relaxed);
            publicRetentionCopiedBytes.fetch_add(values.bytes(), std::memory_order_relaxed);
            return true;
        }

        bool copyRetainedPublicUniform(const RingNttContext& ctx,
            GpuPolyBuffer& destination, const RetainedPublicUniform& source,
            std::size_t sourceOffset, std::size_t count, bool outputNtt,
            GpuStream& stream)
        {
            if (!count || sourceOffset > source.count() ||
                count > source.count() - sourceOffset ||
                !retainedPublicUniformMatches(ctx, source, source.count(), outputNtt) ||
                destination.count() < count ||
                destination.polyWords() != source.mImpl->mValues.polyWords()) return false;
            const std::size_t words = count * destination.polyWords();
            if (words > std::numeric_limits<std::size_t>::max() / sizeof(u64)) return false;
            HostStep copyStep("setup public uniform: retained D2D");
            const bool queued = gpuMemcpyD2D(destination.data(),
                source.mImpl->mValues.data() + sourceOffset * destination.polyWords(),
                words * sizeof(u64), stream.raw());
            const bool completed = stream.sync();
            if (!queued || !completed) return false;
            publicRetentionCopies.fetch_add(1, std::memory_order_relaxed);
            publicRetentionCopiedBytes.fetch_add(words * sizeof(u64), std::memory_order_relaxed);
            return true;
        }
    }

    bool publicUniformRetentionEnabled()
    {
        const char* value = std::getenv("LV_GPU_SETUP_PUBLIC_RETAIN");
        const char* decline = std::getenv("LV_GPU_SETUP_PUBLIC_RETAIN_FORCE_DECLINE");
        return (!value || value[0] != '0') && !(decline && decline[0] == '1') && enabled();
    }

    bool registerPublicUniformRetention(const RingNttContext& ctx,
        const std::shared_ptr<const std::vector<RnsPoly>>& host,
        const RetainedPublicUniformPtr& captured)
    {
        if (!publicUniformRetentionEnabled() || !host || !captured || captured->count() == 0 ||
            !retentionContextMatches(ctx, *captured->mImpl) ||
            !retentionHostMatches(*host, *captured->mImpl)) return false;
        const auto bytes = captured->mImpl->mValues.bytes();
        if (bytes > publicRetentionByteLimit) return false;
        std::lock_guard<std::mutex> lock(publicRetentionMutex);
        std::size_t retainedBytes = 0;
        for (auto it = publicRetentionEntries.begin(); it != publicRetentionEntries.end();)
        {
            if (it->mHost.expired()) it = publicRetentionEntries.erase(it);
            else
            {
                auto previousHost = it->mHost.lock();
                if (previousHost == host && it->mDevice == captured) return true;
                retainedBytes += it->mDevice->mImpl->mValues.bytes();
                ++it;
            }
        }
        while (!publicRetentionEntries.empty() && retainedBytes > publicRetentionByteLimit - bytes)
        {
            retainedBytes -= publicRetentionEntries.front().mDevice->mImpl->mValues.bytes();
            publicRetentionEntries.erase(publicRetentionEntries.begin());
        }
        publicRetentionEntries.push_back({host, captured});
        return true;
    }

    RetainedPublicUniformPtr findPublicUniformRetention(
        const RingNttContext& ctx, std::span<const RnsPoly> host)
    {
        if (!publicUniformRetentionEnabled() || host.empty()) return {};
        RetainedPublicUniformPtr candidate;
        std::shared_ptr<const std::vector<RnsPoly>> owner;
        {
            std::lock_guard<std::mutex> lock(publicRetentionMutex);
            for (auto it = publicRetentionEntries.begin(); it != publicRetentionEntries.end();)
            {
                auto live = it->mHost.lock();
                if (!live) { it = publicRetentionEntries.erase(it); continue; }
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
        if (candidate && retentionContextMatches(ctx, *candidate->mImpl) &&
            retentionHostMatches(*owner, *candidate->mImpl)) return candidate;
        publicRetentionMisses.fetch_add(1, std::memory_order_relaxed);
        return {};
    }

    bool fetchRetainedPublicUniform(const RetainedPublicUniform& source, std::vector<RnsPoly>& out)
    {
        const auto scope = currentProtocolCacheScope();
        if (!enabled() || source.count() == 0 ||
            source.mImpl->mDevice != currentDeviceOrdinal() ||
            source.mImpl->mRole != scope.mRole || source.mImpl->mRunId != scope.mRunId)
            return false;
        auto& stream = threadStream();
        return source.mImpl->mValues.download(out, stream);
    }

    bool retainedPublicUniformMatches(const RingNttContext& ctx,
        const RetainedPublicUniform& source, std::size_t expectedCount,
        bool outputNtt)
    {
        return expectedCount != 0 && source.count() == expectedCount &&
            source.mImpl->mSeeds.size() == expectedCount &&
            source.mImpl->mOutputNtt == outputNtt &&
            retentionContextMatches(ctx, *source.mImpl);
    }

    RetainedPublicUniformPtr retainRootBStarNttDevice(
        const RingNttContext& ctx, u32 count)
    {
        if (currentProtocolCacheScope().mRole != ProtocolCacheRole::Sender ||
            count == 0) return {};
        const char* decline = std::getenv("LV_GPU_SETUP_ROOT_BSTAR_DEVICE_FORCE_DECLINE");
        if (decline && decline[0] == '1') return {};
        RetainedPublicUniformPtr next;
        if (!retainUniformPolyBatchFromNonce(ctx, kRootBStarNonce,
                kRootBStarDomain, count, true, next) || !next ||
            !retainedPublicUniformMatches(ctx, *next, count, true) ||
            next.use_count() != 1) return {};
        auto producer = std::const_pointer_cast<RetainedPublicUniform>(next);
        producer->mImpl->mRootBStarNtt = true;
        producer->mImpl->mRootBStarNonce = kRootBStarNonce;
        producer->mImpl->mRootBStarDomain = kRootBStarDomain;
        return next;
    }

    bool retainedRootBStarNttMatches(const RingNttContext& ctx,
        const RetainedPublicUniform& source, std::size_t expectedCount)
    {
        return source.mImpl->mRootBStarNtt &&
            source.mImpl->mRootBStarNonce == kRootBStarNonce &&
            source.mImpl->mRootBStarDomain == kRootBStarDomain &&
            source.mImpl->mRole == ProtocolCacheRole::Sender &&
            retainedPublicUniformMatches(ctx, source, expectedCount, true);
    }

    bool materializeRetainedPublicUniform(const RingNttContext& ctx,
        const RetainedPublicUniformPtr& source,
        std::shared_ptr<const std::vector<RnsPoly>>& out)
    {
        if (!source || !retainedPublicUniformMatches(
                ctx, *source, source->count(), source->mImpl->mOutputNtt)) return false;
        auto& value = *source->mImpl;
        std::lock_guard<std::mutex> lock(value.mHostMutex);
        if (auto snapshot = value.mHostSnapshot.lock())
        {
            out = std::move(snapshot);
            return true;
        }

        HostStep materializeStep("setup: public uniform host materialization");
        std::vector<RnsPoly> next;
        bool downloaded = false;
        if (enabled() && currentDeviceOrdinal() == value.mDevice)
        {
            auto& stream = threadSampleStream();
            downloaded = value.mValues.download(next, stream, 0, value.mValues.count());
        }
        if (!downloaded)
        {
            // The deterministic seeds were consumed before the retained GPU
            // attempt. Replaying them neither advances nor aliases a protocol
            // PRNG, so forced CPU rollback remains exact.
            try
            {
                next.resize(value.mSeeds.size());
                for (std::size_t i = 0; i < value.mSeeds.size(); ++i)
                {
                    next[i] = sampleUniformPolyFromSeed(ctx, value.mSeeds[i]);
                    if (value.mOutputNtt && !forwardNttCanonical(next[i], ctx)) return false;
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
        publicRetentionHostMaterializations.fetch_add(1, std::memory_order_relaxed);
        publicRetentionHostMaterializedBytes.fetch_add(
            value.mValues.bytes(), std::memory_order_relaxed);
        out = std::move(snapshot);
        return true;
    }

    PublicUniformRetentionStats publicUniformRetentionStats()
    {
        return {publicRetentionCaptures.load(std::memory_order_relaxed),
            publicRetentionCopies.load(std::memory_order_relaxed),
            publicRetentionCopiedBytes.load(std::memory_order_relaxed),
            publicRetentionMisses.load(std::memory_order_relaxed),
            publicRetentionHostMaterializations.load(std::memory_order_relaxed),
            publicRetentionHostMaterializedBytes.load(std::memory_order_relaxed)};
    }

    namespace
    {
        std::atomic<bool> gEnabled{ false };
        std::atomic<bool> gProbed{ false };
        std::atomic<bool> gHaveDevice{ false };

        bool haveDevice()
        {
            if (!gProbed.load())
            {
                gHaveDevice.store(available());
                gProbed.store(true);
            }
            return gHaveDevice.load();
        }

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

        // Set LOGVOLE_GPU_DEBUG=1 to see why a GPU fast path declined.
        bool debugEnabled()
        {
            static const bool on = [] {
                const char* v = std::getenv("LOGVOLE_GPU_DEBUG");
                return v && v[0] != '\0' && v[0] != '0';
            }();
            return on;
        }

        // Root's online inputs remain alive until the queued device chain has
        // consumed them. Opt in to queue those one-polynomial H2Ds directly,
        // instead of routing each through the stream's shared pinned staging
        // buffer and draining the stream after every copy. Keeping this separate
        // from the general upload switches gives the critical path an exact
        // rollback while its end-to-end benefit is measured.
        bool rootDirectUploadEnabled()
        {
            static const bool on = [] {
                const char* v = std::getenv("LV_GPU_ROOT_DIRECT_UPLOAD");
                return v && v[0] == '1';
            }();
            return on;
        }

        // Fresh Root k' is uploaded once while deriving the response sk'. Keep
        // that coefficient-domain polynomial alive for the later Root seed
        // evaluation so each GoldenSeed candidate can D2D-copy it before its
        // destructive forward NTT. Default off while the end-to-end effect is
        // measured; the null-handle path is the exact prior H2D path.
        bool rootKPrimeResidentEnabled()
        {
            static const bool on = [] {
                const char* v = std::getenv("LV_GPU_ROOT_KPRIME_RESIDENT");
                return v && v[0] == '1';
            }();
            return on;
        }

        // Compatibility alias for the original all-in-one Root operand bundle.
        // The three component switches below permit isolated A/Bs; setting this
        // alias still enables every component for exact reproduction.
        bool rootOperandResidencyEnabled()
        {
            static const bool on = [] {
                const char* v = std::getenv("LV_GPU_ROOT_OPERAND_RESIDENCY");
                return v && v[0] == '1';
            }();
            return on;
        }

        bool rootSkNttResidentEnabled()
        {
            static const bool on = [] {
                const char* v = std::getenv("LV_GPU_ROOT_SK_NTT_RESIDENT");
                return !(v && v[0] == '0');
            }();
            return on || rootOperandResidencyEnabled();
        }

        bool rootKPrimePreuploadEnabled()
        {
            static const bool on = [] {
                const char* v = std::getenv("LV_GPU_ROOT_KPRIME_PREUPLOAD");
                return v && v[0] == '1';
            }();
            return on || rootOperandResidencyEnabled();
        }

        bool rootDPrimeResidentEnabled()
        {
            static const bool on = [] {
                const char* v = std::getenv("LV_GPU_ROOT_DPRIME_RESIDENT");
                return !(v && v[0] == '0');
            }();
            return on || rootOperandResidencyEnabled();
        }

        // Queue the receiver Root finalization's response-independent prefix
        // while the sender is preparing its reply. The complete monolithic
        // chain remains the default and exact rollback until the event/launch
        // overhead is shown to beat the small overlap ceiling.
        bool rootFinalizePrefetchEnabledImpl()
        {
            static const bool on = [] {
                const char* v = std::getenv("LV_GPU_ROOT_FINALIZE_PREFETCH");
                return v && v[0] == '1';
            }();
            return on;
        }

        // Highest-priority Root prefetch, enabled by default after the Stage-92
        // two-size A/B/A validation. Its storage and stream are prepared with
        // the Root device cache before the wire exchange; after send it queues
        // only the immutable index upload (once per cache) and the six
        // response-independent kernels. LV_GPU_ROOT_FINALIZE_PRIORITY_PREFETCH=0
        // restores the monolithic path. Keep the rejected equal-priority
        // LV_GPU_ROOT_FINALIZE_PREFETCH opt-in independent and default-off.
        bool rootFinalizePriorityPrefetchEnabledImpl()
        {
            static const bool on = [] {
                const char* v =
                    std::getenv("LV_GPU_ROOT_FINALIZE_PRIORITY_PREFETCH");
                return !(v && v[0] == '0');
            }();
            return on;
        }

        // Default on; LV_GPU_IDENTITY_LEAF=0 preserves the materialized gadget
        // path for controlled benchmarking and emergency rollback.
        bool identityLeafEnabled()
        {
            static const bool on = [] {
                const char* v = std::getenv("LV_GPU_IDENTITY_LEAF");
                return !(v && v[0] == '0');
            }();
            return on;
        }

        // The common wrapped plaintext has byte-identical canonical values in
        // all four RNS limbs. Materialize limb 0 only and let the immediately
        // following identity-leaf forward transform broadcast that source on
        // load. Default on after exact/resource/sanitizer and both-size A/B
        // gates; LV_GPU_WRAP_SINGLE_LIMB=0 preserves the accepted full-RNS
        // representation as the code-generation-stable rollback.
        bool plainBroadcastSingleLimbEnabled()
        {
            static const bool on = [] {
                const char* v = std::getenv("LV_GPU_WRAP_SINGLE_LIMB");
                return !(v && v[0] == '0');
            }();
            return on;
        }

        // The high digest digits used to form dHat are needed again by the
        // matching expand. Keep them coefficient-domain until then instead of
        // performing the same gadget decomposition twice. Default on;
        // LV_GPU_REUSE_HI_DIGITS=0 is the controlled fallback.
        bool reuseHiDigitsEnabled()
        {
            static const bool on = [] {
                const char* v = std::getenv("LV_GPU_REUSE_HI_DIGITS");
                return !(v && v[0] == '0');
            }();
            return on;
        }

        // Skip materializing recursive dHat's sparse CRT-lifted polynomials.
        // The child leaf NTT can reconstruct the same limb-specific centred
        // representatives directly from the retained high digits.
        bool directRecursiveLeafEnabled()
        {
            static const bool on = [] {
                const char* v = std::getenv("LV_GPU_DIRECT_RECURSIVE_LEAF");
                return !(v && v[0] == '0');
            }();
            return on;
        }

        // Reuse compact recursive leaf diagonals for both the leaf-pair product
        // and the producer's later expand. Default on; disable for A/B testing.
        bool recursiveDiagonalEnabled()
        {
            static const bool on = [] {
                const char* v = std::getenv("LV_GPU_RECURSIVE_DIAGONAL");
                return !(v && v[0] == '0');
            }();
            return on;
        }

        // In the fixed rho=4/full-eight-leaf recursive shape, every sibling can
        // initialize one missing parent limb while writing its diagonal product.
        // Zero retains the bulk memset plus accepted diagonal kernel as the
        // exact rollback.
        bool recursiveLeafSelfZeroEnabled()
        {
            static const bool on = [] {
                const char* v =
                    std::getenv("LV_GPU_RECURSIVE_LEAF_SELF_ZERO");
                return !(v && v[0] == '0');
            }();
            return on;
        }

        // In the fixed full-eight-leaf recursive shape, consume each retained
        // diagonal limb directly in inverse S0. This replaces the diagonal
        // materialization plus the following four-limb inverse with one
        // active-limb transform while still caching the packed diagonal and
        // explicitly initializing its complementary output limb. Default on;
        // zero retains the accepted two-launch chain as the exact rollback.
        bool recursiveLeafSparseInverseEnabled()
        {
            static const bool on = [] {
                const char* v =
                    std::getenv("LV_GPU_RECURSIVE_LEAF_SPARSE_INVERSE");
                return !(v && v[0] == '0');
            }();
            return on;
        }

        // The final plaintext NTT store already owns every transformed
        // coefficient, so apply BatchEncoder's inverse slot permutation there
        // instead of writing and gathering a full intermediate batch. Default
        // on; LV_GPU_FUSED_UNWRAP=0 preserves the two-launch path.
        bool fusedUnwrapEnabled()
        {
            static const bool on = [] {
                const char* v = std::getenv("LV_GPU_FUSED_UNWRAP");
                return !(v && v[0] == '0');
            }();
            return on;
        }

        // The fixed Golden geometry keeps scale-and-round's plaintext
        // coefficients in the forward NTT block's shared tile and gathers the
        // final slots directly. Structural and lower-level toggle eligibility
        // is checked by canLaunchScaleNttForwardGather. Zero is the full exact
        // rollback to the established scratch allocation and split launch chain.
        bool fusedScaleUnwrapEnabled()
        {
            static const bool on = [] {
                const char* v = std::getenv("LV_GPU_FUSED_SCALE_UNWRAP");
                return !(v && v[0] == '0');
            }();
            return on;
        }

        // The common wrap is an unscaled plaintext broadcast. When its inverse
        // NTT fits in one shared-memory tile, load BatchEncoder's slot permutation
        // at the transform boundary and publish directly to the ring limbs. This
        // removes the plaintext scratch batch entirely. LV_GPU_FUSED_WRAP=0 keeps
        // the complete scatter -> inverse -> lift chain for exact A/B rollback.
        bool fusedWrapEnabled()
        {
            static const bool on = [] {
                const char* v = std::getenv("LV_GPU_FUSED_WRAP");
                return !(v && v[0] == '0');
            }();
            return on;
        }

        // Sample the fixed Golden Root randomizer from its already-consumed
        // per-range PRNG keys directly into the device top-input batch. The host
        // seeded replay remains the exact fallback.
        bool rootZetaEnabled()
        {
            static const bool on = [] {
                const char* v = std::getenv("LV_GPU_ROOT_ZETA");
                return !(v && v[0] == '0');
            }();
            return on;
        }

        bool noGoldRootZetaEnabled()
        {
            static const bool on = [] {
                const char* v = std::getenv("LV_GPU_NOGOLD_ROOT_ZETA");
                return !(v && v[0] == '0');
            }();
            return on;
        }

        bool noGoldRootPinnedSeedsEnabled()
        {
            static const bool on = [] {
                const char* v = std::getenv("LV_GPU_NOGOLD_ROOT_PINNED_SEEDS");
                return !(v && v[0] == '0');
            }();
            return on;
        }

        // Sender expansion consumes its recursive key. Transforming that device
        // buffer in place removes a full D2D copy and one live allocation.
        bool senderInplaceKeyEnabled()
        {
            static const bool on = [] {
                const char* v = std::getenv("LV_GPU_SENDER_INPLACE_KEY");
                return !(v && v[0] == '0');
            }();
            return on;
        }

        // The nine-word CT2 random-oracle prefix is immutable across recursion
        // levels on one sampling lane; only instanceBase changes, and that is a
        // kernel argument. Memoize the last prefix queued to each stream-local
        // SampleScratch so repeated levels do not enqueue another tiny pageable
        // H2D. Keep this opt-in while its host-scheduling benefit is measured.
        bool ct2PrefixCacheEnabled()
        {
            static const bool on = [] {
                const char* v = std::getenv("LV_GPU_CT2_PREFIX_CACHE");
                return v && v[0] == '1';
            }();
            return on;
        }

        // Sampling a sender level is independent of its complete child
        // recursion. Queue it on the role's secondary stream so those kernels
        // can overlap, then make that level's expansion wait on a device event.
        // The caller selects the measured size-dependent default; the switch
        // remains the complete rollback and the level count permits exact A/Bs.
        bool topSenderCt2PrefetchEnabledImpl()
        {
            static const bool on = [] {
                const char* v = std::getenv("LV_GPU_TOP_CT2_PREFETCH");
                return !(v && v[0] == '0');
            }();
            return on;
        }

        u32 topSenderCt2PrefetchLevelsImpl(u32 adaptiveDefault)
        {
            if (!topSenderCt2PrefetchEnabledImpl()) return 0u;
            struct LevelOverride
            {
                bool mPresent = false;
                u32 mLevels = 0u;
            };
            static const LevelOverride levelOverride = [] {
                constexpr u32 kMaxLevels = 3u;
                const char* v = std::getenv("LV_GPU_TOP_CT2_PREFETCH_LEVELS");
                if (!v || v[0] == '\0' || v[0] == '-') return LevelOverride{};
                char* end = nullptr;
                const unsigned long parsed = std::strtoul(v, &end, 10);
                if (end == v || *end != '\0') return LevelOverride{};
                return LevelOverride{
                    true,
                    static_cast<u32>(
                        std::clamp<unsigned long>(parsed, 1ul, kMaxLevels))
                };
            }();
            if (levelOverride.mPresent) return levelOverride.mLevels;
            return std::clamp<u32>(adaptiveDefault, 1u, 3u);
        }

        enum class ReceiverCt2PrefetchMode
        {
            Adaptive,
            Disabled,
            Forced
        };

        ReceiverCt2PrefetchMode receiverCt2PrefetchMode()
        {
            // Only the process-wide environment choice is cached. The adaptive
            // answer depends on the current request's label count and recursion
            // geometry and is deliberately computed by receiverCt2PrefetchLevels
            // for every top-level online call.
            static const ReceiverCt2PrefetchMode mode = [] {
                const char* v = std::getenv("LV_GPU_RECEIVER_CT2_PREFETCH");
                if (!v || v[0] == '\0') return ReceiverCt2PrefetchMode::Adaptive;
                if (v[0] == '0') return ReceiverCt2PrefetchMode::Disabled;
                if (v[0] == '1') return ReceiverCt2PrefetchMode::Forced;
                return ReceiverCt2PrefetchMode::Disabled;
            }();
            return mode;
        }

        struct ReceiverCt2LevelOverride
        {
            bool mPresent = false;
            u32 mLevels = 0u;
        };

        const ReceiverCt2LevelOverride& receiverCt2LevelOverride()
        {
            static const ReceiverCt2LevelOverride levelOverride = [] {
                constexpr unsigned long kMaxLevels = 3ul;
                const char* v = std::getenv("LV_GPU_RECEIVER_CT2_PREFETCH_LEVELS");
                if (!v || v[0] == '\0' || v[0] == '-')
                    return ReceiverCt2LevelOverride{};
                char* end = nullptr;
                const unsigned long parsed = std::strtoul(v, &end, 10);
                if (end == v || *end != '\0') return ReceiverCt2LevelOverride{};
                return ReceiverCt2LevelOverride{
                    true,
                    static_cast<u32>(
                        std::clamp<unsigned long>(parsed, 1ul, kMaxLevels))
                };
            }();
            return levelOverride;
        }

        // Pipeline only explicitly selected receiver shrink levels. The legacy
        // single-stream gadget -> NTT chain remains the complete default and
        // rollback while the additional launch/event overhead is measured.
        bool receiverShrinkTilePipelineEnabled()
        {
            static const bool on = [] {
                const char* v = std::getenv("LV_GPU_RECEIVER_SHRINK_TILE_PIPELINE");
                return v && v[0] == '1';
            }();
            return on;
        }

        u32 receiverShrinkTileCount()
        {
            static const u32 tiles = [] {
                constexpr u32 kDefaultTiles = 4u;
                const char* v = std::getenv("LV_GPU_RECEIVER_SHRINK_TILES");
                if (!v || v[0] == '\0' || v[0] == '-') return kDefaultTiles;
                char* end = nullptr;
                const unsigned long parsed = std::strtoul(v, &end, 10);
                if (end == v || *end != '\0') return kDefaultTiles;
                return parsed <= 2ul ? 2u : 4u;
            }();
            return tiles;
        }

        // A sampled batch is checked again arithmetically by the next level's
        // denoise. Accumulate those exact checks on the device and read one flag
        // after the top level instead of draining the stream at every level.
        bool deferredGoldenValidationEnabledImpl()
        {
            static const bool on = [] {
                const char* v = std::getenv("LV_GPU_DEFER_GOLDEN_VALIDATION");
                return !(v && v[0] == '0');
            }();
            return on;
        }

        // With one retained high digit, gadget decomposition has the same input
        // and output shape. The kernel reconstructs a coefficient completely
        // before storing it, so the digest allocation can become the digit
        // allocation in place. Disable only for same-binary A/B testing.
        bool inplaceHiDigitEnabled()
        {
            static const bool on = [] {
                const char* v = std::getenv("LV_GPU_INPLACE_HI_DIGIT");
                return !(v && v[0] == '0');
            }();
            return on;
        }

        bool bail(const char* why)
        {
            if (debugEnabled())
            {
                std::fprintf(stderr, "[logvole-gpu] declined: %s\n", why);
            }
            return false;
        }

        // Region timer used to separate kernel time from transfer time and host
        // glue. Accumulates into process-wide totals printed at exit under
        // LOGVOLE_GPU_DEBUG=1.
        struct RegionTotals
        {
            std::atomic<u64> mUploadUs{ 0 };
            std::atomic<u64> mKernelUs{ 0 };
            std::atomic<u64> mDownloadUs{ 0 };
            std::atomic<u64> mHostUs{ 0 };

            ~RegionTotals()
            {
                if (!debugEnabled()) return;
                std::fprintf(
                    stderr,
                    "[logvole-gpu] totals: upload %.1f ms, kernels %.1f ms, download %.1f ms, host %.1f ms\n",
                    mUploadUs.load() / 1000.0, mKernelUs.load() / 1000.0, mDownloadUs.load() / 1000.0,
                    mHostUs.load() / 1000.0);
            }
        };

        RegionTotals& regions()
        {
            static RegionTotals r;
            return r;
        }

        // Syncs the stream so the measurement attributes GPU work correctly.
        // Only active when tracing; otherwise it is a no-op and does not perturb
        // the pipeline.
        struct Region
        {
            std::atomic<u64>* mSink;
            void* mStream;
            std::chrono::steady_clock::time_point mStart;

            Region(std::atomic<u64>& sink, void* stream) : mSink(&sink), mStream(stream)
            {
                if (!debugEnabled()) { mSink = nullptr; return; }
                gpuStreamSync(mStream);
                mStart = std::chrono::steady_clock::now();
            }

            ~Region()
            {
                if (!mSink) return;
                gpuStreamSync(mStream);
                mSink->fetch_add(
                    static_cast<u64>(std::chrono::duration_cast<std::chrono::microseconds>(
                                         std::chrono::steady_clock::now() - mStart)
                                         .count()),
                    std::memory_order_relaxed);
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
        // They are cached on the device, keyed by the geometry they were built
        // from, so a repeat call with the same shape is a map lookup. The cache is
        // deliberately immortal: entries outlive the SEAL memory pool and the
        // allocator's bookkeeping, and freeing them at exit reintroduces the
        // destruction-order crash documented in 3.5.
        struct IdxCache
        {
            std::mutex mMutex;
            std::unordered_map<u64, u32*> mMap;
        };

        IdxCache& idxCache()
        {
            static IdxCache* cache = new IdxCache();
            return *cache;
        }

        // FNV-1a over the geometry values, with a per-site tag so two sites that
        // happen to share a shape cannot collide.
        template<typename... Vals>
        u64 idxKey(u64 siteTag, Vals... vals)
        {
            u64 h = 1469598103934665603ull ^ siteTag;
            h ^= static_cast<u64>(currentProtocolCacheScope().mRole);
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
            if (count == 0) return nullptr;
            auto& cache = idxCache();
            {
                std::lock_guard<std::mutex> lock(cache.mMutex);
                auto it = cache.mMap.find(key);
                if (it != cache.mMap.end()) return it->second;
            }

            std::vector<u32> host(count);
            build(host);

            auto* dev = static_cast<u32*>(gpuMalloc(count * sizeof(u32)));
            if (!dev) return nullptr;
            // Synchronise once here so the array is durable before any other
            // stream reads it; this is a one-off per geometry.
            if (!gpuMemcpyH2D(dev, host.data(), count * sizeof(u32), stream.raw()) || !stream.sync())
            {
                return nullptr;
            }

            std::lock_guard<std::mutex> lock(cache.mMutex);
            auto [it, inserted] = cache.mMap.emplace(key, dev);
            if (!inserted) gpuFree(dev);   // lost a race; keep the winner
            return it->second;
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
            u32 mWidth = 0;
            u32 mLevels = 0;
            const u64* mMaxMultiple = nullptr;   // [rho], owned by mRing
        };

        bool downloadReceiverCt1Snapshot(const OfflineCache& cache,
            std::vector<RnsPoly>& out, GpuStream& stream, u32 workers)
        {
            const char* setting = std::getenv("LV_GPU_SETUP_RECEIVER_PIPELINED_DOWNLOAD");
            const bool usePipeline = setting
                ? setting[0] != '0'
                : cache.mCt1.bytes() >= (std::size_t(16) << 20);
            return (usePipeline ? cache.mCt1.downloadPipelined(out, stream, workers)
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
                u32 workers, int device, u64 runId,
                std::shared_ptr<const LazyRingTensorHostState> encoded)
                : mContext(ctx), mCache(std::move(cache)), mWorkers(workers),
                  mDevice(device), mRunId(runId), mEncoded(std::move(encoded))
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
                    HostStep materializeStep("setup receiver: lazy NTT host materialization");
                    RingTensor next{};
                    next.mRows = mCoefficients.mRows;
                    next.mCols = mCoefficients.mCols;
                    bool downloaded = false;
                    {
                        ScopedProtocolCacheScope roleScope(ProtocolCacheRole::Receiver, mRunId);
                        if (enabled() && currentDeviceOrdinal() == mDevice)
                        {
                            struct RestoreStream
                            {
                                void* previous = gpuCurrentStream();
                                ~RestoreStream() { gpuSetCurrentStream(previous); }
                            } restoreStream;
                            auto& stream = threadStream();
                            struct DrainStream
                            {
                                GpuStream& stream;
                                ~DrainStream() { stream.sync(); }
                            } drain{stream};
                            HostStep downloadStep("setup receiver: lazy NTT host download");
                            downloaded = downloadReceiverCt1Snapshot(*mCache, next.mPolys, stream, mWorkers);
                        }
                    }
                    // A failed transfer has drained before next is reused.
                    // The coefficient backup is not changed until success, so
                    // a throwing allocation leaves call_once retryable.
                    if (!downloaded)
                    {
                        HostStep fallbackStep("setup receiver: lazy NTT CPU fallback");
                        const auto& coefficients = mEncoded ? mEncoded->get() : mCoefficients;
                        if (coefficients.mRows != next.mRows || coefficients.mCols != next.mCols ||
                            ringTensorSize(coefficients) != coefficients.mPolys.size() ||
                            !validateRingBatchShape(coefficients.mPolys, mContext.mParams))
                            throw std::runtime_error("LogVole receiver lazy Ct1 has invalid coefficient backing");
                        next = coefficients;
                        for (auto& poly : next.mPolys)
                            if (!forwardNtt(poly, mContext))
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
            u64 mRunId;
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
            std::span<const u8> encodedCt1 = {},
            std::span<const u8> encodedLacct = {})
        {
            auto ring = GpuRing::get(ctx);
            if (!ring) return nullptr;

            if ((publicA && retainedPublicA) || (publicB && retainedPublicB)) return nullptr;
            const std::size_t publicACount = publicA ? publicA->size()
                : retainedPublicA ? retainedPublicA->count() : 0;
            const std::size_t publicBCount = publicB ? publicB->size()
                : retainedPublicB ? retainedPublicB->count() : 0;
            if ((retainedPublicA && !retainedPublicUniformMatches(
                    ctx, *retainedPublicA, publicACount, false)) ||
                (retainedPublicB && !retainedPublicUniformMatches(
                    ctx, *retainedPublicB, publicBCount, true))) return nullptr;

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
            auto& stream = threadStream();
            std::vector<u64> recursiveFactors;
            std::vector<RnsPoly> recursiveLeafB;
            std::array<u32, 2> recursiveInputs{};
            using DeviceAllocation = std::unique_ptr<void, decltype(&gpuFree)>;
            DeviceAllocation deviceRecursiveInputs(nullptr, gpuFree);
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
                if (!cache->mPublicA.resize(*ring, publicACount) ||
                    !(retainedPublicA
                        ? copyRetainedPublicUniform(ctx, cache->mPublicA,
                            *retainedPublicA, 0, publicACount, false, stream)
                        : uploadPublicUniformOrHost(ctx, cache->mPublicA, *publicA, stream)))
                    return nullptr;
            }
            if (publicBCount)
            {
                if (!cache->mPublicB.resize(*ring, publicBCount) ||
                    !(retainedPublicB
                        ? copyRetainedPublicUniform(ctx, cache->mPublicB,
                            *retainedPublicB, 0, publicBCount, true, stream)
                        : uploadPublicUniformOrHost(ctx, cache->mPublicB, *publicB, stream)))
                    return nullptr;

                HostStep leafStep("gpu: prepare recursive public B");
                // Only these two public columns are needed at recursive leaves.
                // The ring already owns the exact per-limb lift factors.
                if (publicBCount < 2u || (publicBCount & 1u) != 0u)
                    return nullptr;
                const std::size_t fullTau = publicBCount / 2u;
                if (fullTau > std::numeric_limits<u32>::max()) return nullptr;
                const char* deviceLeafB = std::getenv("LV_GPU_SETUP_LEAF_B_DEVICE");
                if (!deviceLeafB || deviceLeafB[0] != '0')
                {
                    recursiveInputs = { 0u, static_cast<u32>(fullTau) };
                    deviceRecursiveInputs.reset(gpuMalloc(sizeof(recursiveInputs)));
                    if (!ring->crtLiftFactors() || !deviceRecursiveInputs ||
                        !cache->mRecursiveLeafB.resize(*ring, 2u) ||
                        !gpuMemcpyH2D(deviceRecursiveInputs.get(), recursiveInputs.data(),
                            sizeof(recursiveInputs), stream.raw()) ||
                        !launchScaleByPow2(ring->view(), cache->mPublicB.data(),
                            static_cast<const u32*>(deviceRecursiveInputs.get()),
                            cache->mRecursiveLeafB.data(), nullptr, 2u,
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
                    if (!cache->mRecursiveLeafB.resize(*ring, recursiveLeafB.size()) ||
                        !cache->mRecursiveLeafB.upload(recursiveLeafB, stream))
                        return nullptr;
                }
            }

            if (ct1Count)
            {
                cache->mCt1Cols = ct1.mCols;
                if (!cache->mCt1.resize(*ring, ct1Count) ||
                    !(encodedCt1.empty() ? cache->mCt1.upload(ct1.mPolys, stream)
                        : uploadSetupWire(cache->mCt1.data(), encodedCt1.data(), encodedCt1.size(), stream)))
                    return nullptr;
                if (!ct1IsNtt &&
                    (!launchCanonicalize(ring->view(), cache->mCt1.data(), nullptr,
                         static_cast<u32>(ct1Count), stream.raw()) ||
                     !nttForward(*ring, cache->mCt1.data(), static_cast<u32>(ct1Count), stream)))
                    return nullptr;
            }

            if (lacctCount)
            {
                cache->mLacctCols = lacct.mCt.mCols;
                cache->mWidth = lacct.mWidthPadded;
                cache->mLevels = lacct.mLevels;
                if (!cache->mLacct.resize(*ring, lacctCount) ||
                    !(encodedLacct.empty() ? cache->mLacct.upload(lacct.mCt.mPolys, stream)
                        : uploadSetupWire(cache->mLacct.data(), encodedLacct.data(), encodedLacct.size(), stream)))
                    return nullptr;
            }

            // Identical SEAL rejection thresholds are already immutable ring
            // constants. Retaining mRing keeps this shared device array alive.
            cache->mMaxMultiple = ring->sampleMaxMultiple();
            if (!cache->mMaxMultiple) return nullptr;

            if (!stream.sync()) return nullptr;
            return cache;
        }

        std::shared_ptr<OfflineCache> receiverCache(const ShrinkExpandReceiverState& state)
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
            HostStep miss("gpu: receiverCache build");
            RingNttContext ctx{};
            if (!makeRingNttContext(state.mParams.mRing, ctx)) return nullptr;
            auto cache = buildOfflineCache(
                ctx, state.mPublicANtt.get(), state.mPublicBNtt.get(),
                state.mPublicANttDevice.get(), state.mPublicBNttDevice.get(),
                state.hostCt1(), state.hostLacct(), true);
            if (cache) state.mGpuCache = cache;
            return cache;
        }

        std::shared_ptr<OfflineCache> senderCache(const ShrinkExpandSenderState& state)
        {
            if (state.mGpuCache)
            {
                return std::static_pointer_cast<OfflineCache>(state.mGpuCache);
            }
            HostStep miss("gpu: senderCache build");
            // Offline retained operands belong to the sender state, not the
            // current online sid. Borrow that state's original scope solely
            // while validating and copying its immutable GPU tokens.
            ScopedProtocolCacheScope tokenScope(
                ProtocolCacheRole::Sender,
                state.mPublicANttDevice ? state.mPublicUniformRunId
                    : currentProtocolCacheScope().mRunId);
            RingNttContext ctx{};
            if (!makeRingNttContext(state.mParams.mRing, ctx)) return nullptr;
            ShrinkExpandLacct empty{};
            RingTensor noCt1{};
            const char* publicAOnly = std::getenv("LV_GPU_SETUP_SENDER_PUBLIC_A_ONLY");
            // Sender expansion and Root key derivation read only public A and
            // sampler thresholds; public B is exclusively a receiver operand.
            const bool includePublicB = publicAOnly && publicAOnly[0] == '0';
            const auto* publicB = includePublicB ? state.mPublicBNtt.get() : nullptr;
            const auto* retainedPublicB = includePublicB
                ? state.mPublicBNttDevice.get() : nullptr;
            auto cache = buildOfflineCache(
                ctx, state.mPublicANtt.get(), publicB,
                state.mPublicANttDevice.get(), retainedPublicB,
                noCt1, empty, true);
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

        // Per-thread scratch for the Blake2xb stream and the SEAL prng seeds.
        // Sized once and reused so that repeated golden-seed attempts do not
        // churn hundreds of megabytes of device memory.
        struct SampleScratch
        {
            u64* mStream = nullptr;
            std::size_t mStreamWords = 0;
            u64* mSeeds = nullptr;
            std::size_t mSeedWords = 0;
            // ct2 seed derivation: the 9-word RO prefix and the per-chunk
            // 16-byte instance seeds.
            u64* mPrefix = nullptr;
            std::array<u64, 9> mPrefixHost{};
            std::size_t mPrefixHostWords = 0;
            void* mPrefixHostStream = nullptr;
            bool mPrefixHostValid = false;
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

            ~SampleScratch()
            {
                gpuFree(mStream);
                gpuFree(mSeeds);
                gpuFree(mPrefix);
                gpuFree(mCt2Seeds);
                gpuFree(mRoundKeys);
                gpuFree(mRejectEpochs);
                gpuFree(mRootZetaFirstReject);
            }

            bool ensureStream(std::size_t words)
            {
                if (words <= mStreamWords) return true;
                gpuFree(mStream);
                mStream = static_cast<u64*>(gpuMalloc(words * sizeof(u64)));
                mStreamWords = mStream ? words : 0;
                return mStream != nullptr;
            }

            bool ensureSeeds(std::size_t words)
            {
                if (words <= mSeedWords) return true;
                gpuFree(mSeeds);
                mSeeds = static_cast<u64*>(gpuMalloc(words * sizeof(u64)));
                mSeedWords = mSeeds ? words : 0;
                return mSeeds != nullptr;
            }

            bool ensurePrefix()
            {
                if (mPrefix) return true;
                invalidatePrefixUpload();
                mPrefix = static_cast<u64*>(gpuMalloc(9 * sizeof(u64)));
                return mPrefix != nullptr;
            }

            void invalidatePrefixUpload()
            {
                mPrefixHostWords = 0;
                mPrefixHostStream = nullptr;
                mPrefixHostValid = false;
            }

            bool uploadPrefix(const u64* words, std::size_t wordCount, void* stream)
            {
                if (!mPrefix || !words || wordCount == 0 ||
                    wordCount > mPrefixHost.size())
                {
                    invalidatePrefixUpload();
                    return false;
                }

                const bool cache = ct2PrefixCacheEnabled();
                if (!cache)
                {
                    // Preserve the established path exactly when the experiment
                    // is disabled; cached metadata is never populated in this
                    // process because the environment choice is immutable.
                    return gpuMemcpyH2D(
                        mPrefix, words, wordCount * sizeof(u64), stream);
                }
                if (mPrefixHostValid && mPrefixHostWords == wordCount &&
                    mPrefixHostStream == stream &&
                    std::memcmp(
                        mPrefixHost.data(), words, wordCount * sizeof(u64)) == 0)
                {
                    return true;
                }

                // Invalidate before the enqueue: a failed upload must never
                // leave metadata that can turn a later retry into a false hit.
                invalidatePrefixUpload();
                if (!gpuMemcpyH2D(
                        mPrefix, words, wordCount * sizeof(u64), stream))
                {
                    return false;
                }

                // cudaMemcpyAsync accepted the write. The source bytes are now
                // the exact contents ordered before later work on this stream.
                // Record them only after that successful enqueue.
                std::copy_n(words, wordCount, mPrefixHost.begin());
                mPrefixHostWords = wordCount;
                mPrefixHostStream = stream;
                mPrefixHostValid = true;
                return true;
            }

            bool ensureCt2Seeds(std::size_t words)
            {
                if (words <= mCt2SeedWords) return true;
                gpuFree(mCt2Seeds);
                mCt2Seeds = static_cast<u64*>(gpuMalloc(words * sizeof(u64)));
                mCt2SeedWords = mCt2Seeds ? words : 0;
                return mCt2Seeds != nullptr;
            }

            bool ensureRoundKeys(std::size_t bytes)
            {
                if (bytes <= mRoundKeyBytes) return true;
                gpuFree(mRoundKeys);
                mRoundKeys = static_cast<unsigned char*>(gpuMalloc(bytes));
                mRoundKeyBytes = mRoundKeys ? bytes : 0;
                return mRoundKeys != nullptr;
            }

            bool nextRejectEpoch(
                std::size_t count, void* stream, u32*& rejectEpochs, u32& rejectEpoch)
            {
                rejectEpochs = nullptr;
                rejectEpoch = 0;
                if (count == 0) return true;

                if (count > mRejectCapacity)
                {
                    gpuFree(mRejectEpochs);
                    mRejectEpochs = static_cast<u32*>(gpuMalloc(count * sizeof(u32)));
                    mRejectCapacity = mRejectEpochs ? count : 0;
                    mRejectEpoch = 0;
                    if (!mRejectEpochs) return false;
                    if (!gpuMemsetZero(mRejectEpochs, count * sizeof(u32), stream))
                    {
                        gpuFree(mRejectEpochs);
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
                gpuFree(mRootZetaFirstReject);
                mRootZetaFirstReject =
                    static_cast<u32*>(gpuMalloc(count * sizeof(u32)));
                mRootZetaRejectCapacity = mRootZetaFirstReject ? count : 0;
                return mRootZetaFirstReject != nullptr;
            }

        };

        // Indexed by stream slot: these buffers are read and written by device
        // work, so the sender and the receiver must not share them now that they
        // run on separate streams.
        SampleScratch& sampleScratch()
        {
            thread_local SampleScratch s[kStreamSlots];
            return s[threadStreamSlot()];
        }

        // Separate from sampleScratch(), not merely another reference indexed by
        // the same role. The main and secondary streams execute concurrently;
        // sharing any of the prefix, seed, round-key, stream, or reject buffers
        // would turn the prefetch into a write-after-read race.
        SampleScratch& senderPrefetchSampleScratch()
        {
            thread_local SampleScratch s[kStreamSlots];
            return s[threadStreamSlot()];
        }

        // The receiver may queue several ancestor ct2 batches FIFO on its
        // secondary stream while the ordinary receiver sampler continues on the
        // main stream. Never alias either lane's prefix, seed, round-key, stream,
        // or rejection storage: all are rewritten for the next sampled batch.
        SampleScratch& receiverPrefetchSampleScratch()
        {
            thread_local SampleScratch s[kStreamSlots];
            return s[threadStreamSlot()];
        }

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

            ~ValidateScratch()
            {
                // Core normally finishes or aborts every attempt. This is only a
                // last-resort lifetime guard for an exception/thread exit.
                if (mAttemptActive && mAttemptStream) gpuStreamSync(mAttemptStream);
                gpuFree(mMarginLo);
                gpuFree(mMarginHi);
                gpuFree(mLeaf);
                gpuFree(mFlag);
            }

            bool ensure(u32 rho)
            {
                if (rho <= mRho && mFlag) return true;
                gpuFree(mMarginLo);
                gpuFree(mMarginHi);
                gpuFree(mLeaf);
                gpuFree(mFlag);
                mMarginLo = static_cast<u64*>(gpuMalloc(rho * sizeof(u64)));
                mMarginHi = static_cast<u64*>(gpuMalloc(rho * sizeof(u64)));
                mLeaf = static_cast<LeafGoldenSeedLimb*>(gpuMalloc(rho * sizeof(LeafGoldenSeedLimb)));
                mFlag = static_cast<u32*>(gpuMalloc(sizeof(u32)));
                mRho = (mMarginLo && mMarginHi && mLeaf && mFlag) ? rho : 0;
                return mRho != 0;
            }
        };

        ValidateScratch& validateScratch()
        {
            thread_local ValidateScratch s[kStreamSlots];
            return s[threadStreamSlot()];
        }

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

        // Uploads a small constant array that lives for the process lifetime.
        template<typename T>
        const void* uploadPersistent(const std::vector<T>& host)
        {
            if (host.empty()) return nullptr;
            void* d = gpuMalloc(host.size() * sizeof(T));
            if (!d) return nullptr;
            if (!gpuMemcpyH2D(d, host.data(), host.size() * sizeof(T), nullptr) || !gpuDeviceSync())
            {
                gpuFree(d);
                return nullptr;
            }
            return d;
        }
    }

    void setEnabled(bool on)
    {
        gEnabled.store(on && haveDevice());
    }

    bool enabled()
    {
        if (!gEnabled.load() || !haveDevice()) return false;

        // Bisection aid: LV_GPU_ROLE=sender|receiver restricts the device paths to
        // one party, which is what separates "the sender's device result differs"
        // from "the receiver's does" when a query comes out wrong. Both parties run
        // on their own thread and the role is thread local, so this is exact.
        static const char* role = std::getenv("LV_GPU_ROLE");
        if (!role) return true;
        const auto current = currentProtocolCacheScope().mRole;
        if (current == ProtocolCacheRole::Unspecified) return true;
        if (std::strcmp(role, "sender") == 0) return current == ProtocolCacheRole::Sender;
        if (std::strcmp(role, "receiver") == 0) return current == ProtocolCacheRole::Receiver;
        return true;
    }

    // deviceDescription() is defined by LogVoleGpuBackend.cpp; the declaration
    // is repeated in LogVoleGpuProtocol.h so that callers only need one header.

    bool prepareReusableSenderCache(ShrinkExpandSenderState& state)
    {
        const char* shared = std::getenv("LV_GPU_SETUP_SHARE_CACHE");
        const char* senderShared = std::getenv("LV_GPU_SETUP_SHARE_SENDER_CACHE");
        if ((shared && shared[0] == '0') || (senderShared && senderShared[0] == '0')) return false;
        ScopedProtocolCacheScope roleScope(
            ProtocolCacheRole::Sender, currentProtocolCacheScope().mRunId);
        if (!enabled()) return false;
        struct RestoreStream
        {
            void* previous = gpuCurrentStream();
            ~RestoreStream() { gpuSetCurrentStream(previous); }
        } restoreStream;
        HostStep setupStep("setup sender: shared device cache");
        // Publish only after buildOfflineCache completes its stream. Mutable
        // query buffers and sampler scratch remain outside the shared mirror.
        return static_cast<bool>(senderCache(state));
    }

    bool prepareReusableReceiverCache(ShrinkExpandReceiverState& state)
    {
        const char* value = std::getenv("LV_GPU_SETUP_SHARE_CACHE");
        if (value && value[0] == '0') return false;

        // The direct Core API can arrive without a protocol role. Keep these
        // receiver tensors on the receiver stream even in that case, and honor
        // LV_GPU_ROLE after selecting the role.
        ScopedProtocolCacheScope roleScope(
            ProtocolCacheRole::Receiver, currentProtocolCacheScope().mRunId);
        if (!enabled()) return false;
        struct RestoreStream
        {
            void* previous = gpuCurrentStream();
            ~RestoreStream() { gpuSetCurrentStream(previous); }
        } restoreStream;
        HostStep setupStep("setup receiver: shared device cache");
        // buildOfflineCache synchronizes before receiverCache publishes the
        // pointer. Only immutable buffers are shared; LevelSession and sampler
        // scratch remain separate for each query and stream.
        return static_cast<bool>(receiverCache(state));
    }

    bool finalizeReceiverSetupDevice(
        const RingNttContext& ctx, ShrinkExpandReceiverState& state,
        bool deferHostSnapshot,
        std::shared_ptr<const LazyRingTensorHostState> encodedCt1,
        std::shared_ptr<const LazyLacctHostState> encodedLacct)
    {
        ScopedProtocolCacheScope roleScope(
            ProtocolCacheRole::Receiver, currentProtocolCacheScope().mRunId);
        const bool hostA = static_cast<bool>(state.mPublicANtt);
        const bool hostB = static_cast<bool>(state.mPublicBNtt);
        const bool deviceA = static_cast<bool>(state.mPublicANttDevice);
        const bool deviceB = static_cast<bool>(state.mPublicBNttDevice);
        if (!enabled() || (!ctx.mContext && !ctx.mGpuLightweight) || !ringModulusCount(ctx) ||
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
        const auto ct1Bytes = encodedCt1 ? encodedCt1->encodedCoefficients() : std::span<const u8>{};
        const auto lacctBytes = encodedLacct ? encodedLacct->encodedCoefficients() : std::span<const u8>{};
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
                state.mParams.mMu, false);
        const bool publicBValid = hostB
            ? state.mPublicBNtt->size() == expectedBCount &&
                validateRingBatchShape(*state.mPublicBNtt, ctx.mParams)
            : retainedPublicUniformMatches(ctx, *state.mPublicBNttDevice,
                expectedBCount, true);
        if (!ct1.mRows || !ct1.mCols || ct1.mRows != state.mParams.mMu ||
            ct1.mCols != state.mParams.mTau ||
            !lacct.mWidthPadded || !lacct.mLevels || !lacct.mCt.mCols ||
            static_cast<std::size_t>(lacct.mLevels) * lacct.mWidthPadded != lacct.mCt.mRows ||
            !publicAValid || !publicBValid || !ct1InputValid || !lacctInputValid) return false;
        const char* decline = std::getenv("LV_GPU_SETUP_RECEIVER_RESIDENT_NTT_FORCE_DECLINE");
        if (decline && decline[0] == '1') return false;

        HostStep totalStep("setup receiver: resident ciphertext NTT");
        struct RestoreStream
        {
            void* previous = gpuCurrentStream();
            ~RestoreStream() { gpuSetCurrentStream(previous); }
        } restoreStream;
        // These are receiver-owned decoded tensors. No sender device buffer or
        // transport shortcut participates in constructing this mirror.
        auto cache = buildOfflineCache(ctx, state.mPublicANtt.get(), state.mPublicBNtt.get(),
            state.mPublicANttDevice.get(), state.mPublicBNttDevice.get(),
            ct1, lacct, false, ct1Bytes, lacctBytes);
        if (!cache) return false;
        // Regression hook: decline after the complete device transform, before
        // either host state or the synchronized cache has been published.
        if (decline && decline[0] == '2') return false;

        const char* lazyNtt = std::getenv("LV_GPU_SETUP_RECEIVER_LAZY_NTT");
        if (deferHostSnapshot && (!lazyNtt || lazyNtt[0] != '0'))
        {
            auto owner = std::make_shared<ReceiverCt1HostState>(ctx, cache,
                ct1.mRows, ct1.mCols, state.mParams.mNumWorkerThreads,
                currentDeviceOrdinal(), currentProtocolCacheScope().mRunId, encodedCt1);
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
        auto& stream = threadStream();
        struct DrainStream
        {
            GpuStream& stream;
            ~DrainStream() { stream.sync(); }
        } drain{stream};
        {
            HostStep downloadStep("setup receiver: resident NTT host snapshot");
            if (!downloadReceiverCt1Snapshot(*cache, nextCt1, stream, state.mParams.mNumWorkerThreads)) return false;
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

    bool lencRandomizerResidencyEnabled()
    {
        const char* value = std::getenv("LV_GPU_SETUP_LENC_RANDOMIZER_RESIDENT");
        return enabled() && (!value || value[0] != '0');
    }

    namespace
    {
        class GpuLencRandomizers final : public LazyLencRandomizerState
        {
        public:
            GpuLencRandomizers(const RingNttContext& ctx, std::shared_ptr<GpuRing> ring,
                GpuPolyBuffer&& ntt)
                : mContext(ctx), mRing(std::move(ring)), mNtt(std::move(ntt)),
                  mDevice(currentDeviceOrdinal()), mRole(currentProtocolCacheScope().mRole) {}

            std::size_t count() const override { return mNtt.count(); }
            bool matches(const RingParams& params) const override { return params == mContext.mParams; }
            const GpuPolyBuffer* deviceNtt(const RingNttContext& ctx) const
            {
                if (!matches(ctx.mParams) || currentDeviceOrdinal() != mDevice ||
                    currentProtocolCacheScope().mRole != mRole ||
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
                HostStep step(coefficients ? "setup: deferred LENC R coefficients" : "setup: deferred LENC R NTT");
                if (currentDeviceOrdinal() != mDevice)
                    throw std::runtime_error("LogVole randomizers requested on a different CUDA device");
                struct RestoreStream
                {
                    void* previous = gpuCurrentStream();
                    ~RestoreStream() { gpuSetCurrentStream(previous); }
                } restore;
                GpuStream stream;
                gpuSetCurrentStream(stream.raw());
                GpuPolyBuffer coeff;
                std::vector<RnsPoly> next;
                struct DrainStream
                {
                    GpuStream& stream;
                    ~DrainStream() { stream.sync(); }
                } drain{stream};
                const GpuPolyBuffer* source = &mNtt;
                if (coefficients)
                {
                    if (!coeff.resize(*mRing, count()) ||
                        !gpuMemcpyD2D(coeff.data(), mNtt.data(), mNtt.bytes(), stream.raw()) ||
                        !launchNttInverse(mRing->view(), coeff.data(), static_cast<u32>(count()), nullptr, stream.raw()))
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
            int mDevice;
            ProtocolCacheRole mRole;
            mutable std::once_flag mNttOnce, mCoeffOnce;
            mutable std::vector<RnsPoly> mHostNtt, mHostCoefficients;
        };

        const GpuPolyBuffer* lencRandomizerDeviceNtt(
            const RingNttContext& ctx, const LazyLencRandomizerState* state)
        {
            const auto* owner = dynamic_cast<const GpuLencRandomizers*>(state);
            return owner ? owner->deviceNtt(ctx) : nullptr;
        }

        // A completed ciphertext remains in its producer's allocation. Wire
        // encoding can copy the contiguous coefficient array without building
        // thousands of host polynomials; an actual CPU consumer gets a stable,
        // independently owned snapshot on its first request.
        class GpuSetupTensorHostState final : public LazyRingTensorHostState
        {
        public:
            GpuSetupTensorHostState(std::shared_ptr<GpuRing> ring, GpuPolyBuffer&& buffer,
                u32 rows, u32 cols)
                : mRing(std::move(ring)), mBuffer(std::move(buffer)),
                  mDevice(currentDeviceOrdinal())
            {
                mHost.mRows = rows;
                mHost.mCols = cols;
            }

            const RingTensor& get() const override
            {
                std::call_once(mOnce, [&] {
                    HostStep step("setup: deferred sender tensor materialization");
                    if (currentDeviceOrdinal() != mDevice)
                        throw std::runtime_error("LogVole deferred tensor requested on a different CUDA device");
                    struct RestoreStream
                    {
                        void* previous = gpuCurrentStream();
                        ~RestoreStream() { gpuSetCurrentStream(previous); }
                    } restore;
                    GpuStream stream;
                    gpuSetCurrentStream(stream.raw());
                    std::vector<RnsPoly> next;
                    struct DrainStream
                    {
                        GpuStream& stream;
                        ~DrainStream() { stream.sync(); }
                    } drain{stream};
                    const bool downloaded = mBuffer.download(next, stream);
                    if (!stream.sync() || !downloaded)
                        throw std::runtime_error("LogVole deferred tensor download failed");
                    mHost.mPolys = std::move(next);
                });
                return mHost;
            }

            bool copyCoefficientsTo(std::span<u8> destination) const override
            {
                if (destination.size() != mBuffer.bytes() || currentDeviceOrdinal() != mDevice)
                    return false;
                HostStep step("setup: device ciphertext to wire");
                struct RestoreStream
                {
                    void* previous = gpuCurrentStream();
                    ~RestoreStream() { gpuSetCurrentStream(previous); }
                } restore;
                auto& stream = threadSampleStream();
                gpuSetCurrentStream(stream.raw());
                const bool copied = downloadSetupWire(destination.data(), mBuffer.data(),
                    destination.size(), stream);
                return stream.sync() && copied;
            }

        private:
            std::shared_ptr<GpuRing> mRing;
            GpuPolyBuffer mBuffer;
            int mDevice;
            mutable std::once_flag mOnce;
            mutable RingTensor mHost;
        };
    }

    std::shared_ptr<const LazyRingTensorHostState> makeGpuSetupTensorHostState(
        const RingNttContext& ctx, GpuPolyBuffer&& buffer, u32 rows, u32 cols)
    {
        auto ring = GpuRing::get(ctx);
        if (!ring || !rows || !cols || buffer.count() != static_cast<std::size_t>(rows) * cols ||
            buffer.polyWords() != ring->polyWords()) return {};
        return std::make_shared<GpuSetupTensorHostState>(std::move(ring),
            std::move(buffer), rows, cols);
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
        u64 mRootErrorRunId = 0;
        int mRootErrorDevice = -1;
        // Private, immutable sender Root skRRt. A transformed copy retains the
        // same offline provenance and sets mRootSecretNtt; it is never a public
        // uniform token and must never be mutated by a consumer.
        bool mRootSecretUniform = false;
        bool mTopSecretUniform = false;
        bool mRootSecretNtt = false;
        ProtocolCacheRole mRootSecretRole = ProtocolCacheRole::Unspecified;
        u64 mRootSecretRunId = 0;
        int mRootSecretDevice = -1;
        // CI-VOLE's private wrapped delta and its exact seed-label repetition
        // remain coefficient-domain sender operands until the first LENC
        // consumer. An ordinary upload lacks these producer-only markers.
        bool mSetupDeltaCoefficients = false;
        bool mSetupSeedLabelRepCoefficients = false;
        bool mTopSeedLabelRepCoefficients = false;
        bool mRootHiRepCoefficients = false;
        ProtocolCacheRole mSetupSenderRole = ProtocolCacheRole::Unspecified;
        u64 mSetupSenderRunId = 0;
        int mSetupSenderDevice = -1;
    };

    // First-query allocation overlap is deliberately narrow: only the
    // production NoGoldenSeed N=16384/rho=8, W=2048, n=2^25 geometry. These
    // buffers are owned by one receiver state, reserved after its application
    // total timer starts, and transferred only to that state's first query.
    class ReceiverFirstQueryAllocations
    {
    public:
        RingParams mRingParams;
        std::vector<u64> mOrderedPrimes;
        u64 mLabelCount = 0;
        u32 mRingWidth = 0;
        int mDevice = -1;
        u64 mOfflineRunId = 0;
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
        u64 mOnlineRunId = 0;
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
            ScopedProtocolCacheScope receiverScope(
                ProtocolCacheRole::Receiver, mOfflineRunId);
            if (!enabled() || currentDeviceOrdinal() != mDevice) return;
            void* stream = gpuStreamCreate();
            if (!stream) return;
            void* previous = gpuCurrentStream();
            gpuSetCurrentStream(stream);
            bool ok = false;
            try
            {
                HostStep step("recv: overlap first-query GPU allocation");
                const std::size_t polyWords =
                    static_cast<std::size_t>(mRingParams.mPolyModulusDegree) *
                    mRingParams.mCoeffModulusBits.size();
                const std::size_t nodeCount =
                    (static_cast<std::size_t>(mRingWidth) / 16u) * 31u + 1u;
                ok = mWrap.resizeWords(polyWords, mRingWidth) &&
                    mNodes.resizeWords(polyWords, nodeCount);
                if (ok)
                {
                    mReadyEvent = gpuEventCreate();
                    ok = mReadyEvent && gpuEventRecord(mReadyEvent, stream);
                }
            }
            catch (...) { ok = false; }
            const bool complete = gpuStreamSync(stream);
            mReady = ok && complete;
            if (!mReady)
            {
                mWrap.release();
                mNodes.release();
            }
            gpuSetCurrentStream(previous);
            gpuForgetStream(stream);
            gpuStreamDestroy(stream);
        }
    };

    ReceiverFirstQueryAllocationsPtr beginReceiverFirstQueryAllocations(
        const Params& params)
    {
        const char* enabledFlag = std::getenv("LV_GPU_RECEIVER_FIRST_QUERY_ALLOC_OVERLAP");
        const char* forcedDecline = std::getenv("LV_GPU_RECEIVER_FIRST_QUERY_ALLOC_FORCE_DECLINE");
        if (!enabledFlag || enabledFlag[0] != '1' ||
            (forcedDecline && forcedDecline[0] == '1') || !enabled() ||
            currentProtocolCacheScope().mRole != ProtocolCacheRole::Receiver ||
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
        if (!makeRingNttContext(se.mRing, ctx) || ringModulusCount(ctx) != 8u)
            return {};
        auto plan = std::make_shared<ReceiverFirstQueryAllocations>();
        plan->mRingParams = se.mRing;
        plan->mOrderedPrimes.reserve(8u);
        for (std::size_t i = 0; i < 8u; ++i)
            plan->mOrderedPrimes.push_back(ringModulusValue(ctx, i));
        plan->mLabelCount = params.mTotalLabelCount;
        plan->mRingWidth = params.mW;
        plan->mDevice = currentDeviceOrdinal();
        plan->mOfflineRunId = currentProtocolCacheScope().mRunId;
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
        const ReceiverFirstQueryAllocationsPtr& plan, const void* owner)
    {
        if (!plan || !owner ||
            currentProtocolCacheScope().mRole != ProtocolCacheRole::Receiver ||
            currentDeviceOrdinal() != plan->mDevice) return false;
        plan->finish();
        std::lock_guard<std::mutex> lock(plan->mMutex);
        if (!plan->mReady || plan->mOfflineOwner || plan->mBound ||
            plan->mOfflineRunId != currentProtocolCacheScope().mRunId)
            return false;
        plan->mOfflineOwner = owner;
        return true;
    }

    bool bindReceiverFirstQueryAllocations(
        const ReceiverFirstQueryAllocationsPtr& plan, const void* owner, u64 sid)
    {
        if (!plan || !owner || currentProtocolCacheScope().mRole != ProtocolCacheRole::Receiver ||
            currentDeviceOrdinal() != plan->mDevice) return false;
        plan->finish();
        std::lock_guard<std::mutex> lock(plan->mMutex);
        if (!plan->mReady || plan->mBound || plan->mOfflineOwner != owner ||
            currentProtocolCacheScope().mRunId != sid) return false;
        plan->mBound = true;
        plan->mOwner = owner;
        plan->mSid = sid;
        return true;
    }

    void bindReceiverFirstQueryOnlineRun(
        const ReceiverFirstQueryAllocationsPtr& plan, const void* owner, u64 sid,
        u64 runId)
    {
        if (!plan || !owner || !runId ||
            currentProtocolCacheScope().mRole != ProtocolCacheRole::Receiver ||
            currentDeviceOrdinal() != plan->mDevice) return;
        std::lock_guard<std::mutex> lock(plan->mMutex);
        if (plan->mReady && plan->mBound && plan->mOwner == owner &&
            plan->mOfflineOwner == owner &&
            plan->mSid == sid && !plan->mOnlineRunId)
        {
            if (currentProtocolCacheScope().mRunId == runId)
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
            u64 sid, GpuPolyBuffer& out, GpuStream& stream)
        {
            if (!plan || !owner || garbledInput ||
                currentProtocolCacheScope().mRole != ProtocolCacheRole::Receiver ||
                currentProtocolCacheScope().mRunId != sid ||
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
            const void* owner, u64 sid, GpuPolyBuffer& out, GpuStream& stream)
        {
            if (!plan || !owner ||
                currentProtocolCacheScope().mRole != ProtocolCacheRole::Receiver ||
                currentDeviceOrdinal() != plan->mDevice ||
                xCount != 2048u || muHi != 16u || tauHi != 1u ||
                width != 16u || maxTau != 1u || nodeCount != 3969u ||
                !receiverFirstQueryRingMatches(*plan, ring, params)) return false;
            std::lock_guard<std::mutex> lock(plan->mMutex);
            if (!plan->mReady || !plan->mBound ||
                plan->mOfflineOwner != owner || plan->mOwner != owner ||
                plan->mSid != sid || !plan->mOnlineRunId ||
                plan->mOnlineRunId != currentProtocolCacheScope().mRunId ||
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
        void* mProducerStream = nullptr;
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
            if (!mConsumed && mProducerStream)
            {
                const bool eventDone =
                    mEventRecorded && mReadyEvent && gpuEventSync(mReadyEvent);
                if (!eventDone) gpuStreamSync(mProducerStream);
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
        void* mProducerStream = nullptr;
        void* mReadyEvent = nullptr;
        bool mEventRecorded = false;
        bool mConsumed = false;

        ~Impl()
        {
            // A plan may be abandoned because an ancestor took the CPU fallback,
            // metadata stopped matching, or a later prefetch failed. Its storage
            // is still owned here, so do not release it while the secondary stream
            // may be writing it.
            if (!mConsumed && mProducerStream)
            {
                const bool eventDone =
                    mEventRecorded && mReadyEvent && gpuEventSync(mReadyEvent);
                if (!eventDone) gpuStreamSync(mProducerStream);
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
        // Non-null only for the priority candidate. The concrete workspace is
        // owned by mRootCacheOwner and declared with RootDeviceCache below.
        void* mPriorityWorkspace = nullptr;
        GpuPolyBuffer mAcc;
        GpuPolyBuffer mPhi;
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

    DeviceScalars::~DeviceScalars()
    {
        gpuFree(mData);
    }

    bool DeviceScalars::resize(std::size_t count)
    {
        if (count == mCount) return true;
        gpuFree(mData);
        mData = nullptr;
        mCount = 0;
        if (count == 0) return true;
        mData = static_cast<u64*>(gpuMalloc(count * sizeof(u64)));
        if (!mData) return false;
        mCount = count;
        return true;
    }

    bool syncStream()
    {
        if (!enabled()) return true;
        return threadStream().sync();
    }

    bool nttHostBatch(const RingNttContext& ctx, std::span<RnsPoly> polys, bool inverse)
    {
        return nttHostBatch(ctx, polys, inverse, false);
    }

    bool nttHostBatch(const RingNttContext& ctx, std::span<RnsPoly> polys,
        bool inverse, bool canonicalizeOnDevice)
    {
        if (!enabled() || polys.empty()) return false;
        const char* forcedDecline = canonicalizeOnDevice
            ? std::getenv("LV_GPU_SETUP_NTT_CANONICALIZE_FORCE_DECLINE") : nullptr;
        if (forcedDecline && forcedDecline[0] == '1') return false;
        HostStep totalStep("setup batch NTT total");
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
        auto& stream = threadSampleStream();
        // Keep allocator ownership attached to this stream through buf's
        // destruction, including failures that leave the host inputs intact.
        struct RestoreStream
        {
            void* previous = gpuCurrentStream();
            ~RestoreStream() { gpuSetCurrentStream(previous); }
        } restoreStream;
        gpuSetCurrentStream(stream.raw());
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
            HostStep uploadStep("setup batch NTT upload");
            if (!buf.resize(*ring, polys.size())) return false;
            if (!buf.upload(std::span<const RnsPoly>(polys.data(), polys.size()), stream)) return false;
        }

        {
            // This is launch time only; download includes the device wait.
            HostStep launchStep("setup batch NTT launch");
            if (canonicalizeOnDevice && !inverse &&
                !launchCanonicalize(ring->view(), buf.data(), nullptr,
                    static_cast<u32>(polys.size()), stream.raw())) return false;
            const bool ok = inverse
                ? launchNttInverse(
                      ring->view(), buf.data(), static_cast<u32>(polys.size()), nullptr, stream.raw())
                : launchNttForward(
                      ring->view(), buf.data(), static_cast<u32>(polys.size()), nullptr, stream.raw());
            if (!ok) return false;
            if (canonicalizeOnDevice && inverse &&
                !launchCanonicalize(ring->view(), buf.data(), nullptr,
                    static_cast<u32>(polys.size()), stream.raw())) return false;
        }
        // Test rollback after queued reduction/NTT work, before host publication.
        if (forcedDecline && forcedDecline[0] == '2') return false;

        HostStep downloadStep("setup batch NTT download");
        static const bool reuseHost = [] {
            const char* value = std::getenv("LV_GPU_NTT_REUSE_HOST");
            return !value || value[0] != '0';
        }();
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
                if (!gpuMemcpyD2H(stage, buf.data(), bytes, stream.raw()) || !stream.sync()) return false;
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
        if (!enabled() || levels == 0) return false;
        auto ring = GpuRing::get(ctx);
        if (!ring) return false;

        // Secondary stream, for the same reason as nttHostBatch above: host in,
        // host out, nothing queued to order against.
        auto& stream = threadSampleStream();
        gpuSetCurrentStream(stream.raw());
        GpuPolyBuffer src;
        GpuPolyBuffer dst;
        bool ok = src.resize(*ring, 1) && dst.resize(*ring, levels) &&
                  src.upload(std::span<const RnsPoly>(&in, 1), stream) &&
                  launchGadgetDecompose(
                      ring->view(), src.data(), nullptr, 1, digitBits, startLevel, levels, centered,
                      dst.data(), nullptr, stream.raw());

        // download() queues the copies and synchronises.
        if (ok) ok = dst.download(out, stream, 0, levels) && out.size() == levels;
        gpuSetCurrentStream(threadStream().raw());
        return ok;
    }

    bool setupUniformSamplingEnabled()
    {
#ifdef SEAL_USE_AES_CTR_DRBG
        return false;
#else
        const char* value = std::getenv("LV_GPU_SETUP_UNIFORM_DEVICE");
        if ((value && value[0] == '0') || !enabled()) return false;
        static const bool compatibleFactory =
            seal::UniformRandomGeneratorFactory::DefaultFactory()->create(
                seal::prng_seed_type{})->info().type() == seal::prng_type::blake2xb;
        return compatibleFactory;
#endif
    }

    namespace
    {
        bool sampleUniformBatchOwner(const RingNttContext& ctx,
            std::span<const std::array<u64, 8>> seeds, bool outputNtt,
            bool synchronize, std::shared_ptr<RetainedPublicUniform>& out)
        {
            HostStep totalStep("setup: uniform device total");
            if (!setupUniformSamplingEnabled() || seeds.empty() ||
                seeds.size() > std::numeric_limits<u32>::max()) return false;
            const char* decline = std::getenv("LV_GPU_SETUP_UNIFORM_FORCE_DECLINE");
            if (decline && decline[0] == '1') return false;
            auto ring = GpuRing::get(ctx);
            if (!ring || !ring->sampleMaxMultiple() ||
                ring->polyWords() > std::numeric_limits<u32>::max() - kSampleSlackWords)
                return false;
            const u32 count = static_cast<u32>(seeds.size());
            const u32 streamWords = static_cast<u32>(ring->polyWords() + kSampleSlackWords);
            if (seeds.size() > std::numeric_limits<std::size_t>::max() /
                    (static_cast<std::size_t>(streamWords) * sizeof(u64))) return false;

            auto& stream = threadSampleStream();
            struct RestoreStream
            {
                void* previous = gpuCurrentStream();
                ~RestoreStream() { gpuSetCurrentStream(previous); }
            } restoreStream;
            gpuSetCurrentStream(stream.raw());
            // Setup uses the secondary stream. Its scratch must not alias the
            // online sampler or either prefetch sampler on another stream.
            thread_local SampleScratch setupScratch[kStreamSlots];
            auto& scratch = setupScratch[threadStreamSlot()];
            GpuPolyBuffer sampled;
            struct DrainStream
            {
                GpuStream& stream;
                bool armed = true;
                ~DrainStream() { if (armed) stream.sync(); }
            } drainStream{ stream };
            const bool needStream = !gpuFusedSamplerActive(ring->n(), streamWords, count);
            const bool needEpoch = gpuFusedSamplerNeedsRejectEpoch(ring->n(), streamWords, count) ||
                (needStream && gpuRejectReduceFusionActive());
            if (!sampled.resize(*ring, count) || !scratch.ensureSeeds(seeds.size() * 8u) ||
                (needStream && !scratch.ensureStream(seeds.size() * streamWords))) return false;
            u32* rejectEpochs = nullptr;
            u32 rejectEpoch = 0;
            if (needEpoch && !scratch.nextRejectEpoch(count, stream.raw(), rejectEpochs, rejectEpoch))
                return false;
            {
                HostStep launchStep("setup: uniform device sample and NTT");
                if (!gpuMemcpyH2D(scratch.mSeeds, seeds.data(), seeds.size_bytes(), stream.raw()) ||
                    !launchSampleUniformPolyBlake2xb(ring->view(), scratch.mSeeds, scratch.mStream,
                        streamWords, ring->sampleMaxMultiple(), sampled.data(), nullptr, count,
                        rejectEpochs, rejectEpoch, true, stream.raw()) ||
                    (outputNtt && !launchNttForward(
                        ring->view(), sampled.data(), count, nullptr, stream.raw()))) return false;
            }
            if (synchronize)
            {
                HostStep retainStep("setup: uniform device retain");
                if (!stream.sync()) return false;
            }

            auto next = std::make_shared<RetainedPublicUniform>();
            auto& value = *next->mImpl;
            value.mRing = ring;
            value.mParams = ctx.mParams;
            value.mSeeds.assign(seeds.begin(), seeds.end());
            value.mOutputNtt = outputNtt;
            value.mRole = currentProtocolCacheScope().mRole;
            value.mRunId = currentProtocolCacheScope().mRunId;
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
        bool outputNtt, RetainedPublicUniformPtr& out)
    {
        if (!publicUniformRetentionEnabled()) return false;
        const std::size_t polyWords = ringPolyCoeffCount(ctx.mParams);
        if (!polyWords || seeds.size() > publicRetentionByteLimit / sizeof(u64) / polyWords)
            return false;
        std::shared_ptr<RetainedPublicUniform> next;
        if (!sampleUniformBatchOwner(ctx, seeds, outputNtt, true, next) ||
            next->mImpl->mValues.bytes() > publicRetentionByteLimit) return false;
        publicRetentionCaptures.fetch_add(1, std::memory_order_relaxed);
        out = std::move(next);
        return true;
    }

    DeviceBatchPtr sampleRootSecretUniformToDevice(
        const RingNttContext& ctx,
        std::span<const std::array<u64, 8>> rowSeeds)
    {
        const auto scope = currentProtocolCacheScope();
        const char* decline = std::getenv("LV_GPU_SETUP_ROOT_SKRR_DEVICE_FORCE_DECLINE");
        if (scope.mRole != ProtocolCacheRole::Sender ||
            (decline && decline[0] == '1')) return {};
        std::shared_ptr<RetainedPublicUniform> privateSample;
        if (!sampleUniformBatchOwner(ctx, rowSeeds, false, true, privateSample) ||
            !privateSample || privateSample->count() != rowSeeds.size()) return {};
        auto next = std::make_shared<DeviceBatch>();
        next->mImpl->mRing = privateSample->mImpl->mRing;
        next->mImpl->mBuf = std::move(privateSample->mImpl->mValues);
        next->mImpl->mRootSecretUniform = true;
        next->mImpl->mRootSecretNtt = false;
        next->mImpl->mRootSecretRole = scope.mRole;
        next->mImpl->mRootSecretRunId = scope.mRunId;
        next->mImpl->mRootSecretDevice = currentDeviceOrdinal();
        return next;
    }

    DeviceBatchPtr sampleTopSecretUniformToDevice(
        const RingNttContext& ctx,
        std::span<const std::array<u64, 8>> rowSeeds)
    {
        const auto scope = currentProtocolCacheScope();
        const char* decline = std::getenv("LV_GPU_SETUP_TOP_SK1_DEVICE_FORCE_DECLINE");
        if (scope.mRole != ProtocolCacheRole::Sender || !scope.mRunId ||
            (decline && decline[0] == '1')) return {};
        std::shared_ptr<RetainedPublicUniform> privateSample;
        if (!sampleUniformBatchOwner(ctx, rowSeeds, false, true, privateSample) ||
            !privateSample || privateSample->count() != rowSeeds.size()) return {};
        auto next = std::make_shared<DeviceBatch>();
        next->mImpl->mRing = privateSample->mImpl->mRing;
        next->mImpl->mBuf = std::move(privateSample->mImpl->mValues);
        next->mImpl->mTopSecretUniform = true;
        next->mImpl->mRootSecretNtt = false;
        next->mImpl->mRootSecretRole = scope.mRole;
        next->mImpl->mRootSecretRunId = scope.mRunId;
        next->mImpl->mRootSecretDevice = currentDeviceOrdinal();
        return next;
    }

    bool sampleUniformBatchFromSeedsDevice(
        const RingNttContext& ctx,
        std::span<const std::array<u64, 8>> seeds,
        bool outputNtt,
        std::vector<RnsPoly>& out)
    {
        return sampleUniformBatchFromSeedsDevice(ctx, seeds, outputNtt, out, nullptr);
    }

    bool sampleUniformBatchFromSeedsDevice(
        const RingNttContext& ctx, std::span<const std::array<u64, 8>> seeds,
        bool outputNtt, std::vector<RnsPoly>& out, RetainedPublicUniformPtr* captured)
    {
        std::shared_ptr<RetainedPublicUniform> retained;
        if (!sampleUniformBatchOwner(ctx, seeds, outputNtt, false, retained)) return false;
        std::vector<RnsPoly> next;
        {
            HostStep downloadStep("setup: uniform device download");
            auto& stream = threadSampleStream();
            if (!retained->mImpl->mValues.download(next, stream, 0, retained->count()) ||
                next.size() != seeds.size()) return false;
        }
        const bool keep = captured && publicUniformRetentionEnabled() &&
            retained->mImpl->mValues.bytes() <= publicRetentionByteLimit;
        if (keep)
        {
            auto& value = *retained->mImpl;
            value.mHostData = next.data();
            value.mHostCoefficients.reserve(next.size());
            for (const auto& poly : next)
                value.mHostCoefficients.push_back(poly.mCoeffs.data());
            publicRetentionCaptures.fetch_add(1, std::memory_order_relaxed);
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
        if (!enabled() || count == 0) return false;
        auto ring = GpuRing::get(ctx);
        if (!ring || !ring->sampleMaxMultiple()) return false;

        auto& stream = threadStream();
        auto& scratch = sampleScratch();
        const std::size_t streamWords = ring->polyWords() + kSampleSlackWords;
        const bool fusedSamplerNeedsEpoch =
            gpuFusedSamplerNeedsRejectEpoch(ring->n(), static_cast<u32>(streamWords), count);
        const bool needStream =
            !gpuFusedSamplerActive(ring->n(), static_cast<u32>(streamWords), count);
        const bool needRejectEpoch =
            fusedSamplerNeedsEpoch || (needStream && gpuRejectReduceFusionActive());
        if (!scratch.ensureSeeds(static_cast<std::size_t>(count) * 8) ||
            !scratch.ensureRoundKeys(static_cast<std::size_t>(count) * 176) ||
            (needStream &&
             !scratch.ensureStream(static_cast<std::size_t>(count) * streamWords)) ||
            !scratch.ensurePrefix())
        {
            return false;
        }
        u32* rejectEpochs = nullptr;
        u32 rejectEpoch = 0;
        if (needRejectEpoch &&
            !scratch.nextRejectEpoch(count, stream.raw(), rejectEpochs, rejectEpoch))
            return false;

        // scratch.mPrefix is 9 words, so it comfortably holds the 2-word seed.
        u64 seedWords[2];
        std::memcpy(seedWords, &seed, sizeof(seedWords));

        GpuPolyBuffer dst;
        bool ok = dst.resize(*ring, count) &&
                  scratch.uploadPrefix(seedWords, 2u, stream.raw()) &&
                  launchPolySeeds(
                      scratch.mPrefix, 1, count, domainTag, ctx.mParams.mPolyModulusDegree,
                      static_cast<u64>(ctx.mParams.mCoeffModulusBits.size()), scratch.mSeeds,
                      scratch.mRoundKeys,
                      stream.raw()) &&
                  launchSampleUniformPolyBlake2xb(
                      ring->view(), scratch.mSeeds, scratch.mStream, static_cast<u32>(streamWords),
                      ring->sampleMaxMultiple(), dst.data(), nullptr, count, rejectEpochs, rejectEpoch, true,
                      stream.raw());

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
        if (!enabled() || !alpha || !tau || !rho || !words ||
            count > std::numeric_limits<u32>::max() ||
            count > (std::size_t(512) << 20) / sizeof(u64) / words ||
            (gamma != 1u && gamma != tau) || input.size() < (gamma == 1u ? 1u : tau)) return false;
        // The gamma-one CPU contract inspects only input[0]. Other modes
        // validate the complete supplied span, including unused tail entries.
        if (gamma == 1u ? !validateRingPolyShape(input[0], ctx.mParams)
                        : !validateRingBatchShape(input, ctx.mParams)) return false;
        HostStep step("setup: seed label repetition device");
        // This is a bitwise layout operation: constructing NTT/CRT tables here
        // would serialize their bootstrap before ordinary setup can prefetch it.
        RingConstView layout{};
        layout.mN = ctx.mParams.mPolyModulusDegree;
        layout.mRho = static_cast<u32>(rho);
        auto& stream = threadStream();
        GpuPolyBuffer source, result;
        std::vector<RnsPoly> next;
        struct DrainStream
        {
            GpuStream& stream;
            ~DrainStream() { stream.sync(); }
        } drain{stream};
        const u32 sources = gamma == 1u ? 1u : tau;
        if (!source.resizeWords(words, sources) || !result.resizeWords(words, count) ||
            !source.upload(input.first(sources), stream) ||
            !launchSeedLabelRep(layout, source.data(), result.data(), tau,
                static_cast<u32>(count), gamma == 1u, stream.raw()) ||
            !result.download(next, stream) || !stream.sync()) return false;
        out = std::move(next);
        return true;
    }

    namespace
    {
        bool setupCoefficientBatchMatches(const RingNttContext& ctx,
            const DeviceBatch& source, std::size_t expectedCount,
            u64 ownerRunId, bool delta, bool rootHi = false)
        {
            const auto scope = currentProtocolCacheScope();
            if (!enabled() || !source.mImpl || !source.mImpl->mRing ||
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
        u64 ownerRunId)
    {
        return setupCoefficientBatchMatches(ctx, source, expectedCount,
            ownerRunId, true);
    }

    bool setupSeedLabelRepBatchMatches(const RingNttContext& ctx,
        const DeviceBatch& source, std::size_t expectedCount,
        u64 ownerRunId)
    {
        return setupCoefficientBatchMatches(ctx, source, expectedCount,
            ownerRunId, false);
    }

    bool rootHiRepBatchMatches(const RingNttContext& ctx,
        const DeviceBatch& source, std::size_t expectedCount, u64 ownerRunId)
    {
        return setupCoefficientBatchMatches(ctx, source, expectedCount,
            ownerRunId, false, true);
    }

    bool setupLencInputBatchMatches(const RingNttContext& ctx,
        const DeviceBatch& source, std::size_t expectedCount, u64 ownerRunId)
    {
        return setupSeedLabelRepBatchMatches(ctx, source, expectedCount,
            ownerRunId) || rootHiRepBatchMatches(ctx, source, expectedCount,
            ownerRunId);
    }

    DeviceBatchPtr seedLabelRepResident(const RingNttContext& ctx,
        const DeviceBatch& delta, u32 gamma, u32 alpha, u32 tau)
    {
        const auto ownerRunId = currentProtocolCacheScope().mRunId;
        const auto rho = ringModulusCount(ctx);
        const u64 count = static_cast<u64>(alpha) * tau * rho;
        if (gamma != 1u || !alpha || !tau || !rho ||
            !setupDeltaBatchMatches(ctx, delta, 1u, ownerRunId) ||
            count > std::numeric_limits<u32>::max() ||
            !delta.mImpl->mRing ||
            delta.mImpl->mRing->polyWords() == 0 ||
            count > (std::size_t{512} << 20) /
                delta.mImpl->mRing->polyBytes()) return {};
        HostStep step("setup sender: resident seed-label repetition");
        RingConstView layout{};
        layout.mN = ctx.mParams.mPolyModulusDegree;
        layout.mRho = static_cast<u32>(rho);
        auto& stream = threadStream();
        GpuPolyBuffer result;
        if (!result.resizeWords(delta.mImpl->mRing->polyWords(), count) ||
            !launchSeedLabelRep(layout, delta.mImpl->mBuf.data(),
                result.data(), tau, static_cast<u32>(count), true,
                stream.raw()) || !stream.sync()) return {};
        auto owner = std::make_shared<DeviceBatch>();
        owner->mImpl->mRing = delta.mImpl->mRing;
        owner->mImpl->mBuf = std::move(result);
        owner->mImpl->mSetupSeedLabelRepCoefficients = true;
        owner->mImpl->mSetupSenderRole = ProtocolCacheRole::Sender;
        owner->mImpl->mSetupSenderRunId = ownerRunId;
        owner->mImpl->mSetupSenderDevice = currentDeviceOrdinal();
        return owner;
    }

    DeviceBatchPtr topSecretSeedLabelRepResident(const RingNttContext& ctx,
        const DeviceBatch& topSecret, u32 alpha, u32 tau)
    {
        const u64 runId = currentProtocolCacheScope().mRunId;
        const auto rho = ringModulusCount(ctx);
        const u64 count = static_cast<u64>(alpha) * tau * rho;
        if (!alpha || !tau || !rho || !runId ||
            !topSecretUniformBatchMatches(ctx, topSecret, tau, runId) ||
            count > std::numeric_limits<u32>::max() ||
            !topSecret.mImpl->mRing ||
            count > (std::size_t{512} << 20) /
                topSecret.mImpl->mRing->polyBytes()) return {};
        HostStep step("setup sender: resident top-key seed-label repetition");
        RingConstView layout{};
        layout.mN = ctx.mParams.mPolyModulusDegree;
        layout.mRho = static_cast<u32>(rho);
        auto& stream = threadStream();
        GpuPolyBuffer result;
        if (!result.resizeWords(topSecret.mImpl->mRing->polyWords(), count) ||
            !launchSeedLabelRep(layout, topSecret.mImpl->mBuf.data(),
                result.data(), tau, static_cast<u32>(count), tau == 1u,
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
        owner->mImpl->mSetupSenderDevice = currentDeviceOrdinal();
        return owner;
    }

    DeviceBatchPtr rootHiReplicateResident(const RingNttContext& ctx,
        const DeviceBatch& topSecret, u32 tauHi)
    {
        const u64 runId = currentProtocolCacheScope().mRunId;
        const auto rho = ringModulusCount(ctx);
        const u64 count = static_cast<u64>(tauHi) * rho;
        if (!tauHi || !rho || !runId ||
            !topSecretUniformBatchMatches(ctx, topSecret, tauHi, runId) ||
            count > std::numeric_limits<u32>::max() ||
            !topSecret.mImpl->mRing ||
            count > (std::size_t{512} << 20) /
                topSecret.mImpl->mRing->polyBytes()) return {};
        HostStep step("setup sender: resident Root high-key replication");
        auto& stream = threadStream();
        const std::size_t bytes = topSecret.mImpl->mRing->polyBytes();
        GpuPolyBuffer result;
        if (!result.resizeWords(topSecret.mImpl->mRing->polyWords(), count)) return {};
        bool queued = false;
        for (u32 digit = 0; digit < tauHi; ++digit)
        {
            for (std::size_t limb = 0; limb < rho; ++limb)
            {
                const std::size_t row = static_cast<std::size_t>(digit) * rho + limb;
                if (!gpuMemcpyD2D(result.data() + row * topSecret.mImpl->mRing->polyWords(),
                    topSecret.mImpl->mBuf.data() + static_cast<std::size_t>(digit) *
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
        owner->mImpl->mSetupSenderDevice = currentDeviceOrdinal();
        return owner;
    }

    bool fetchScalars(const DeviceScalars& src, std::span<u64> dst)
    {
        if (src.empty() || dst.size() < src.count()) return false;
        // Order against the stream that produced the data before reading it. The
        // producer no longer drains eagerly, because a caller that keeps the result
        // on the device has no reason to wait for it.
        if (auto* ps = src.producerStream(); ps && ps != threadStream().raw())
        {
            if (!gpuStreamSync(ps)) return false;
        }
        auto& stream = threadStream();
        return gpuMemcpyD2H(dst.data(), src.data(), src.count() * sizeof(u64), stream.raw()) &&
               stream.sync();
    }

    bool waitScalars(DeviceScalars& src)
    {
        if (src.empty()) return false;
        if (auto* ps = src.producerStream())
        {
            if (!gpuStreamSync(ps)) return false;
            // The producing thread may now exit and destroy its thread-local
            // stream. Marking the handle ready prevents a later fetch from
            // trying to synchronize that stale cudaStream_t.
            src.setProducerStream(nullptr);
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
                impl.mRing->view(), impl.mBuf.data(),
                static_cast<u32>(impl.mBuf.count()),
                stream.raw()))
            return false;
        // The queued broadcast precedes every subsequent consumer on this
        // stream, so the ordinary full-RNS logical representation is restored.
        impl.mPlainBroadcastSingleLimb = false;
        return true;
    }

    bool download(const DeviceBatch& batch, std::vector<RnsPoly>& out, std::size_t count)
    {
        if (!batch.mImpl || batch.count() == 0) return false;
        // The compact recursive representation is intentionally device-only;
        // downloading it as if physical and logical counts matched would read
        // past the allocation and would not reconstruct the CRT-lifted values.
        if (batch.mImpl->mLogicalCount &&
            batch.mImpl->mLogicalCount != batch.mImpl->mBuf.count())
            return false;
        auto& stream = threadStream();
        if (!ensurePlainBroadcastMaterialized(*batch.mImpl, stream)) return false;
        Region regDown(regions().mDownloadUs, stream.raw());
        return batch.mImpl->mBuf.download(out, stream, 0, count ? count : batch.count());
    }

    DeviceBatchPtr upload(const RingNttContext& ctx, std::span<const RnsPoly> polys)
    {
        if (!enabled() || polys.empty()) return nullptr;
        auto ring = GpuRing::get(ctx);
        if (!ring) return nullptr;
        auto batch = std::make_shared<DeviceBatch>();
        batch->mImpl->mRing = ring;
        auto& stream = threadStream();
        Region regUp(regions().mUploadUs, stream.raw());
        if (!batch->mImpl->mBuf.resize(*ring, polys.size()) ||
            !batch->mImpl->mBuf.upload(polys, stream))
        {
            return nullptr;
        }
        return batch;
    }

    static bool expandErrorCompactImpl(const RingNttContext& ctx,
        std::span<const u64> compactLimb0, const DeviceScalars* deviceCompact,
        u32 requestedCount, bool outputNtt, std::vector<RnsPoly>* out,
        DeviceBatchPtr* residentOut, u32 requestedWorkers)
    {
        if (!enabled() || !ringModulusCount(ctx)) return false;
        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        const auto words = deviceCompact ? deviceCompact->count() : compactLimb0.size();
        if (!n || !words || words % n || words / n > std::numeric_limits<u32>::max() ||
            (deviceCompact && (!compactLimb0.empty() || deviceCompact->producerStream())) ||
            requestedCount > words / n) return false;
        HostStep totalStep("setup: compact GPU expansion");
        const u32 count = requestedCount ? requestedCount : static_cast<u32>(words / n);
        auto ring = GpuRing::get(ctx);
        constexpr std::size_t maxBytes = std::size_t{512} << 20;
        if (!ring || ring->rho() != ringModulusCount(ctx) || !ring->polyWords() ||
            ring->polyWords() > maxBytes / sizeof(u64) ||
            count > maxBytes / (ring->polyWords() * sizeof(u64))) return false;
        auto& stream = threadSampleStream();
        struct RestoreStream { void* previous = gpuCurrentStream(); ~RestoreStream() { gpuSetCurrentStream(previous); } } restore;
        gpuSetCurrentStream(stream.raw());
        GpuPolyBuffer samples;
        using Allocation = std::unique_ptr<void, decltype(&gpuFree)>;
        Allocation selectors(nullptr, gpuFree), scales(nullptr, gpuFree), denseInput(nullptr, gpuFree);
        std::vector<u32> limbs;
        std::vector<u64> ones;
        std::vector<RnsPoly> next;
        struct DrainStream { GpuStream& stream; ~DrainStream() { stream.sync(); } } drain{stream};
        if (!samples.resize(*ring, count)) return false;
        const char* directSetting = std::getenv("LV_GPU_SETUP_COMPACT_EXPAND_DIRECT");
        if (!directSetting || directSetting[0] != '0')
        {
            HostStep directStep("setup: direct compact GPU expansion");
            const u64* source = deviceCompact ? deviceCompact->data() : nullptr;
            if (deviceCompact && !source) return false;
            if (!source)
            {
                const std::size_t bytes = static_cast<std::size_t>(count) * n * sizeof(u64);
                denseInput.reset(gpuMalloc(bytes));
                if (!denseInput || !gpuMemcpyH2D(denseInput.get(), compactLimb0.data(), bytes, stream.raw()))
                    return false;
                source = static_cast<const u64*>(denseInput.get());
            }
            if (!launchExpandCenteredCompact(ring->view(), source, samples.data(), count, stream.raw()))
                return false;
        }
        else
        {
            limbs.assign(count, 0);
            ones.assign(ring->rho(), 1);
            selectors.reset(gpuMalloc(limbs.size() * sizeof(u32)));
            scales.reset(gpuMalloc(ones.size() * sizeof(u64)));
            if (!selectors || !scales || !(deviceCompact
                ? copyRowsFromDevice(samples.data(), ring->polyWords() * sizeof(u64),
                    deviceCompact->data(), n * sizeof(u64), count, stream)
                : uploadRowsFromHost(samples.data(), ring->polyWords() * sizeof(u64),
                    compactLimb0.data(), n * sizeof(u64), count, stream)) ||
                !gpuMemcpyH2D(selectors.get(), limbs.data(), limbs.size() * sizeof(u32), stream.raw()) ||
                !gpuMemcpyH2D(scales.get(), ones.data(), ones.size() * sizeof(u64), stream.raw()) ||
                !launchLiftCenteredLimb(ring->view(), samples.data(), nullptr,
                    static_cast<const u32*>(selectors.get()), static_cast<const u64*>(scales.get()),
                    samples.data(), nullptr, count, stream.raw())) return false;
        }
        if (outputNtt && !launchNttForward(ring->view(), samples.data(), count, nullptr, stream.raw()))
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
            batch->mImpl->mRootErrorRole = currentProtocolCacheScope().mRole;
            batch->mImpl->mRootErrorRunId = currentProtocolCacheScope().mRunId;
            batch->mImpl->mRootErrorDevice = currentDeviceOrdinal();
            *residentOut = std::move(batch);
            return true;
        }
        const char* pipeline = std::getenv("LV_GPU_SETUP_COMPACT_PIPELINED_DOWNLOAD");
        const bool pipelineRequested = (!pipeline || pipeline[0] != '0') && count >= 4;
        if (!(pipelineRequested
                ? samples.downloadPipelined(next, stream, requestedWorkers)
                : samples.download(next, stream)) || next.size() != count) return false;
        if (!out) return false;
        *out = std::move(next);
        return true;
    }

    bool expandErrorCompactDevice(const RingNttContext& ctx,
        std::span<const u64> compactLimb0, bool outputNtt, std::vector<RnsPoly>& out)
    {
        return expandErrorCompactDevice(ctx, compactLimb0, outputNtt, out, 1);
    }

    bool expandErrorCompactDevice(const RingNttContext& ctx,
        std::span<const u64> compactLimb0, bool outputNtt, std::vector<RnsPoly>& out,
        u32 requestedWorkers)
    {
        return expandErrorCompactImpl(ctx, compactLimb0, nullptr, 0, outputNtt, &out, nullptr, requestedWorkers);
    }

    bool expandErrorCompactDevice(const RingNttContext& ctx,
        const DeviceScalars& compactLimb0, bool outputNtt, std::vector<RnsPoly>& out, u32 polyCount)
    {
        return expandErrorCompactDevice(ctx, compactLimb0, outputNtt, out, polyCount, 1);
    }

    bool expandErrorCompactDevice(const RingNttContext& ctx,
        const DeviceScalars& compactLimb0, bool outputNtt, std::vector<RnsPoly>& out,
        u32 polyCount, u32 requestedWorkers)
    {
        return expandErrorCompactImpl(ctx, {}, &compactLimb0, polyCount, outputNtt, &out, nullptr, requestedWorkers);
    }

    bool expandRootErrorCompactDevice(const RingNttContext& ctx,
        std::span<const u64> compactLimb0, bool outputNtt, std::vector<RnsPoly>& out)
    {
        return expandRootErrorCompactDevice(ctx, compactLimb0, outputNtt, out, 1);
    }

    bool expandRootErrorCompactDevice(const RingNttContext& ctx,
        std::span<const u64> compactLimb0, bool outputNtt, std::vector<RnsPoly>& out,
        u32 requestedWorkers)
    {
        const char* decline = std::getenv("LV_GPU_SETUP_ROOT_COMPACT_NOISE_FORCE_DECLINE");
        if (decline && decline[0] == '1') return false;
        return expandErrorCompactDevice(ctx, compactLimb0, outputNtt, out, requestedWorkers);
    }

    DeviceBatchPtr expandRootErrorCompactToBatch(const RingNttContext& ctx,
        std::span<const u64> compactLimb0, const DeviceScalars* deviceCompact,
        u32 polyCount)
    {
        const char* decline = std::getenv("LV_GPU_SETUP_ROOT_R1_DEVICE_FORCE_DECLINE");
        const char* compactDecline = std::getenv("LV_GPU_SETUP_ROOT_COMPACT_NOISE_FORCE_DECLINE");
        if ((decline && decline[0] == '1') ||
            (compactDecline && compactDecline[0] == '1') ||
            currentProtocolCacheScope().mRole != ProtocolCacheRole::Sender) return {};
        DeviceBatchPtr out;
        if (!expandErrorCompactImpl(ctx, compactLimb0, deviceCompact, polyCount,
                false, nullptr, &out, 1) ||
            !out || !rootErrorBatchMatches(ctx, *out, polyCount)) return {};
        return out;
    }

    bool rootErrorBatchMatches(const RingNttContext& ctx,
        const DeviceBatch& source, std::size_t expectedCount)
    {
        if (!enabled() || !source.mImpl || !source.mImpl->mRing || !expectedCount ||
            !source.mImpl->mRootErrorCoefficients ||
            source.mImpl->mLogicalCount || source.mImpl->mBuf.count() != expectedCount ||
            source.mImpl->mRootErrorRole != ProtocolCacheRole::Sender ||
            source.mImpl->mRootErrorRole != currentProtocolCacheScope().mRole ||
            source.mImpl->mRootErrorRunId != currentProtocolCacheScope().mRunId ||
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
        u64 ownerRunId, bool outputNtt, bool topSecret)
    {
        const auto scope = currentProtocolCacheScope();
        if (!enabled() || !source.mImpl || !source.mImpl->mRing || !expectedCount ||
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
        u64 ownerRunId, bool outputNtt)
    {
        return privateSecretUniformBatchMatches(ctx, source, expectedCount,
            ownerRunId, outputNtt, false);
    }

    bool topSecretUniformBatchMatches(const RingNttContext& ctx,
        const DeviceBatch& source, std::size_t expectedCount, u64 ownerRunId)
    {
        return privateSecretUniformBatchMatches(ctx, source, expectedCount,
            ownerRunId, false, true);
    }

    bool assembleRootTopCtDevice(
        const RingNttContext& ctx, std::span<const RnsPoly> r1Coeffs,
        std::span<const RnsPoly> r2Ntt, std::span<const RnsPoly> publicBRootNtt,
        std::span<const RnsPoly> publicBStarNtt, u32 gadgetLogBase, u32 gadgetPowerOffset,
        std::span<const RnsPoly> noiseCoeffs, std::vector<RnsPoly>& outCtNtt,
        std::span<const u64> compactNoiseLimb0)
    {
        return assembleRootTopCtDevice(ctx, r1Coeffs, r2Ntt, publicBRootNtt, publicBStarNtt,
            gadgetLogBase, gadgetPowerOffset, noiseCoeffs, outCtNtt, compactNoiseLimb0, nullptr);
    }

    bool assembleRootTopCtDevice(
        const RingNttContext& ctx, std::span<const RnsPoly> r1Coeffs,
        std::span<const RnsPoly> r2Ntt, std::span<const RnsPoly> publicBRootNtt,
        std::span<const RnsPoly> publicBStarNtt, u32 gadgetLogBase, u32 gadgetPowerOffset,
        std::span<const RnsPoly> noiseCoeffs, std::vector<RnsPoly>& outCtNtt,
        std::span<const u64> compactNoiseLimb0, const DeviceScalars* compactNoiseDevice)
    {
        return assembleRootTopCtDevice(ctx, r1Coeffs, r2Ntt, publicBRootNtt, publicBStarNtt,
            gadgetLogBase, gadgetPowerOffset, noiseCoeffs, outCtNtt, compactNoiseLimb0,
            compactNoiseDevice, 1);
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
        const RetainedPublicUniform* retainedBStarNtt)
    {
        const auto* retainedR = randomizers ? lencRandomizerDeviceNtt(ctx, randomizers) : nullptr;
        if (randomizers && (!retainedR || !r2Ntt.empty())) return false;
        const bool compactNoise = !compactNoiseLimb0.empty() || compactNoiseDevice;
        if (compactNoiseDevice && (!compactNoiseLimb0.empty() || compactNoiseDevice->producerStream())) return false;
        const char* decline = std::getenv("LV_GPU_SETUP_ROOT_DEVICE_FORCE_DECLINE");
        const char* compactDecline = std::getenv("LV_GPU_SETUP_ROOT_COMPACT_NOISE_FORCE_DECLINE");
        if ((decline && decline[0] == '1') ||
            (compactNoise && compactDecline && compactDecline[0] == '1')) return false;
        if (publicBRootNtt.size() > std::numeric_limits<u32>::max()) return false;
        u32 tauHi = static_cast<u32>(publicBRootNtt.size());
        if (retainedPublicBFullNtt)
        {
            const std::size_t fullCount = retainedPublicBFullNtt->count();
            if (!publicBRootNtt.empty() || fullCount < 4u || (fullCount & 1u) != 0 ||
                fullCount / 2u - 1u >= std::numeric_limits<u32>::max() ||
                !retainedPublicUniformMatches(ctx, *retainedPublicBFullNtt,
                    fullCount, true)) return false;
            tauHi = static_cast<u32>(fullCount / 2u - 1u);
        }
        const auto r1Count = rootR1Device ? rootR1Device->count() : r1Coeffs.size();
        const auto bStarCount = retainedBStarNtt
            ? retainedBStarNtt->count() : publicBStarNtt.size();
        if (!enabled() || !r1Count || tauHi == 0 || bStarCount == 0 ||
            r1Count > std::numeric_limits<u32>::max() / 2u ||
            bStarCount > std::numeric_limits<u32>::max() - tauHi ||
            (retainedR ? retainedR->count() : r2Ntt.size()) != r1Count ||
            (retainedBStarNtt && (!publicBStarNtt.empty() ||
                !retainedRootBStarNttMatches(ctx, *retainedBStarNtt,
                    bStarCount))) ||
            (rootR1Device && (!r1Coeffs.empty() ||
                !rootErrorBatchMatches(ctx, *rootR1Device, r1Count)))) return false;
        HostStep totalStep("setup: root device assembly");
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

        auto& stream = threadSampleStream();
        struct RestoreStream
        {
            void* previous = gpuCurrentStream();
            ~RestoreStream() { gpuSetCurrentStream(previous); }
        } restoreStream;
        gpuSetCurrentStream(stream.raw());
        GpuPolyBuffer rBuffer, bBuffer, ctBuffer, scaledBuffer, compactNoiseSource;
        using DeviceAllocation = std::unique_ptr<void, decltype(&gpuFree)>;
        DeviceAllocation deviceIndices(nullptr, gpuFree);
        std::vector<RnsPoly> next;
        // Drain before destroying metadata, pageable download destinations, or
        // device allocations on any launch/copy failure.
        struct DrainStream
        {
            GpuStream& stream;
            ~DrainStream() { stream.sync(); }
        } drainStream{ stream };
        {
            HostStep uploadStep("setup: root device upload");
            if (!rBuffer.resize(*ring, 2u * rows) || !bBuffer.resize(*ring, cols) ||
                !ctBuffer.resize(*ring, count) || !scaledBuffer.resize(*ring, rows) ||
                !(rootR1Device
                    ? gpuMemcpyD2D(rBuffer.data(), rootR1Device->mImpl->mBuf.data(),
                        static_cast<std::size_t>(rows) * polyBytes, stream.raw())
                    : rBuffer.upload(r1Coeffs, stream)) ||
                !(retainedR ? gpuMemcpyD2D(rBuffer.poly(rows), retainedR->data(), retainedR->bytes(), stream.raw())
                            : rBuffer.upload(r2Ntt, stream, rows)) ||
                !(retainedPublicBFullNtt
                    ? copyRetainedPublicUniform(ctx, bBuffer, *retainedPublicBFullNtt,
                        1u, tauHi, true, stream)
                    : bBuffer.upload(publicBRootNtt, stream)) ||
                !(retainedBStarNtt
                    ? ([&] {
                        HostStep copyStep("setup root: BStar retained D2D");
                        const std::size_t bytes = bStarCount * polyBytes;
                        const bool queued = gpuMemcpyD2D(
                            bBuffer.poly(tauHi),
                            retainedBStarNtt->mImpl->mValues.data(),
                            bytes, stream.raw());
                        const bool completed = stream.sync();
                        return queued && completed;
                    })()
                    : bBuffer.upload(publicBStarNtt, stream, tauHi))) return false;
            if (compactNoise)
            {
                if (!compactNoiseSource.resize(*ring, count) ||
                    !(compactNoiseDevice
                        ? copyRowsFromDevice(compactNoiseSource.data(), polyBytes, compactNoiseDevice->data(), n * sizeof(u64), count, stream)
                        : uploadRowsFromHost(compactNoiseSource.data(), polyBytes, compactNoiseLimb0.data(), n * sizeof(u64), count, stream))) return false;
            }
            else if (!ctBuffer.upload(noiseCoeffs, stream)) return false;
            deviceIndices.reset(gpuMalloc(indices.size() * sizeof(u32)));
            if (!deviceIndices ||
                !gpuMemcpyH2D(deviceIndices.get(), indices.data(), indices.size() * sizeof(u32), stream.raw())) return false;
        }
        const auto* idx = static_cast<const u32*>(deviceIndices.get());
        {
            HostStep kernelStep("setup: root device launches");
            if (!launchCanonicalize(ring->view(), rBuffer.data(), nullptr, 2u * rows, stream.raw()) ||
                !launchCanonicalize(ring->view(), bBuffer.data(), nullptr, cols, stream.raw()) ||
                !launchNttForward(ring->view(), rBuffer.data(), rows, nullptr, stream.raw())) return false;
            if (compactNoise)
            {
                if (!launchNttForwardCenteredLimbFrom(ring->view(), compactNoiseSource.data(), nullptr,
                        idx + static_cast<std::size_t>(limbOffset), ctBuffer.data(), nullptr, count, stream.raw())) return false;
            }
            else if (!launchCanonicalize(ring->view(), ctBuffer.data(), nullptr, count, stream.raw()) ||
                !launchNttForward(ring->view(), ctBuffer.data(), count, nullptr, stream.raw())) return false;
            if (!launchInnerProduct(ring->view(), rBuffer.data(), bBuffer.data(), idx, idx + count,
                    1u, ctBuffer.data(), nullptr, count, false, false, stream.raw(), true)) return false;
            for (u32 col = 0; col < tauHi; ++col)
            {
                const auto* outputIndices = idx + std::size_t{2} * count + static_cast<std::size_t>(col) * rows;
                if (!launchScaleByPow2(ring->view(), rBuffer.poly(rows), nullptr,
                        scaledBuffer.data(), nullptr, rows, factors[col],
                        stream.raw()) ||
                    !launchElementwise(ring->view(), ctBuffer.data(), outputIndices,
                        scaledBuffer.data(), nullptr, ctBuffer.data(), outputIndices,
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
        HostStep downloadStep("setup: root device download");
        const char* pipeline = std::getenv("LV_GPU_SETUP_EXTRA_PIPELINED_DOWNLOAD");
        if ((!pipeline || pipeline[0] != '0') && count >= 4)
        {
            if (!ctBuffer.downloadPipelined(next, stream, requestedWorkers) || next.size() != count)
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
                if (!gpuMemcpyD2H(stage, ctBuffer.data(), bytes, stream.raw()) || !stream.sync()) return false;
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
        u32 requestedWorkers, bool devicePadding)
    {
        return assembleLencTruncDevice(ctx, rLayersNtt, sPadNtt, publicBNtt, tauHi, tauLeaf,
            gadgetLogBase, gadgetLeaves, crtLiftModQj, noiseCoeffs, outCtNtt, outFirstRNtt,
            compactNoiseLimb0, compactRandomizerLimb0, requestedWorkers, devicePadding, nullptr, nullptr);
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
        const DeviceBatch* seedLabelDevice)
    {
        if (outFirstRNtt == &outCtNtt) return false;
        if ((compactNoiseDevice && (!compactNoiseLimb0.empty() || compactNoiseDevice->producerStream())) ||
            (compactRandomizerDevice && (!compactRandomizerLimb0.empty() || compactRandomizerDevice->producerStream()))) return false;
        const char* decline = std::getenv("LV_GPU_SETUP_LENC_DEVICE_FORCE_DECLINE");
        const char* topDecline = std::getenv("LV_GPU_SETUP_TOP_SK1_LENC_FORCE_DECLINE");
        if ((decline && decline[0] == '1') ||
            (seedLabelDevice && topDecline && topDecline[0] == '1' &&
                seedLabelDevice->mImpl &&
                (seedLabelDevice->mImpl->mTopSeedLabelRepCoefficients ||
                 seedLabelDevice->mImpl->mRootHiRepCoefficients))) return false;
        if (!enabled() || rLayersNtt.empty() || rLayersNtt.size() >= 32u ||
            tauHi == 0 || tauHi == std::numeric_limits<u32>::max() ||
            tauLeaf == 0 || tauLeaf > tauHi + 1u || gadgetLogBase == 0)
            return false;
        HostStep totalStep("setup: lenc device assembly");
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
                    seedLabelCount, currentProtocolCacheScope().mRunId))) ||
            (retainedPublicB ? (!publicBNtt.empty() ||
                !retainedPublicUniformMatches(ctx, *retainedPublicB,
                    static_cast<std::size_t>(baseBCount64), true))
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

        auto& stream = threadSampleStream();
        struct RestoreStream
        {
            void* previous = gpuCurrentStream();
            ~RestoreStream() { gpuSetCurrentStream(previous); }
        } restoreStream;
        gpuSetCurrentStream(stream.raw());
        GpuPolyBuffer rBuffer, bBuffer, ctBuffer, scaledBuffer, compactNoiseSource, compactRandomizerSource;
        using DeviceAllocation = std::unique_ptr<void, decltype(&gpuFree)>;
        DeviceAllocation deviceIndices(nullptr, gpuFree), deviceFactors(nullptr, gpuFree);
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
            HostStep uploadStep("setup: lenc device upload");
            if (!rBuffer.resize(*ring, static_cast<u32>(rCount64)) ||
                !bBuffer.resize(*ring, static_cast<u32>(bCount64)) ||
                !ctBuffer.resize(*ring, count) || !scaledBuffer.resize(*ring, maxGroup)) return false;
            if (compactRandomizers)
            {
                if (!compactRandomizerSource.resize(*ring, rows) ||
                    !(compactRandomizerDevice
                        ? copyRowsFromDevice(compactRandomizerSource.data(), polyBytes, compactRandomizerDevice->data(), n * sizeof(u64), rows, stream)
                        : uploadRowsFromHost(compactRandomizerSource.data(), polyBytes, compactRandomizerLimb0.data(), n * sizeof(u64), rows, stream))) return false;
            }
            else
                for (u32 level = 0; level < levels; ++level)
                    if (!rBuffer.upload(rLayersNtt[level], stream, static_cast<std::size_t>(level) * width)) return false;
            const auto copiedSeedLabels = seedLabelDevice
                ? ([&] {
                    HostStep copyStep("setup: LENC seed-label retained D2D");
                    return gpuMemcpyD2D(
                        rBuffer.poly(static_cast<std::size_t>(levels) * width),
                        seedLabelDevice->mImpl->mBuf.data(),
                        seedLabelDevice->mImpl->mBuf.bytes(), stream.raw());
                })()
                : rBuffer.upload(sPadNtt, stream,
                    static_cast<std::size_t>(levels) * width);
            if (!copiedSeedLabels ||
                !(retainedPublicB
                    ? copyRetainedPublicUniform(ctx, bBuffer, *retainedPublicB,
                        0, baseBCount, true, stream)
                    : uploadPublicUniformOrHost(ctx, bBuffer, publicBNtt, stream))) return false;
            if (devicePadding && seedLabelCount < width &&
                !gpuMemsetZero(rBuffer.poly(
                        static_cast<std::size_t>(levels) * width + seedLabelCount),
                    (width - seedLabelCount) * polyBytes, stream.raw())) return false;
            if (compactNoise)
            {
                if (!compactNoiseSource.resize(*ring, count) ||
                    !(compactNoiseDevice
                        ? copyRowsFromDevice(compactNoiseSource.data(), polyBytes, compactNoiseDevice->data(), n * sizeof(u64), count, stream)
                        : uploadRowsFromHost(compactNoiseSource.data(), polyBytes, compactNoiseLimb0.data(), n * sizeof(u64), count, stream))) return false;
            }
            else if (!ctBuffer.upload(noiseCoeffs, stream)) return false;
            deviceIndices.reset(gpuMalloc(indices.size() * sizeof(u32)));
            if (!deviceIndices ||
                !gpuMemcpyH2D(deviceIndices.get(), indices.data(), indices.size() * sizeof(u32), stream.raw())) return false;
            // Internal retained setup uses the ring's GPU-derived lift. Keep
            // custom caller-supplied lift factors for the public eager API.
            if (gadgetLeaves && !retainedRandomizers)
            {
                deviceFactors.reset(gpuMalloc(crtLiftModQj.size_bytes()));
                if (!deviceFactors || !gpuMemcpyH2D(deviceFactors.get(), crtLiftModQj.data(),
                        crtLiftModQj.size_bytes(), stream.raw())) return false;
            }
        }
        const auto* idx = static_cast<const u32*>(deviceIndices.get());
        const auto* scalar = retainedRandomizers ? ring->crtLiftFactors() : static_cast<const u64*>(deviceFactors.get());
        {
            HostStep kernelStep("setup: lenc device launches");
            if (compactRandomizers)
            {
                // Read q0 from a disjoint source while producing all RNS limbs.
                // The padded input is a general polynomial and transforms on
                // its own; only randomizer layers use the centered expansion.
                if (!launchNttForwardCenteredLimbFrom(ring->view(),
                        compactRandomizerSource.data(), nullptr, idx + compactRandomizerLimbOffset,
                        rBuffer.data(), nullptr, rows, stream.raw()) ||
                    !launchCanonicalize(ring->view(), rBuffer.poly(rows), nullptr, width, stream.raw()) ||
                    !launchNttForward(ring->view(), rBuffer.poly(rows), width, nullptr, stream.raw())) return false;
            }
            else if (outFirstRNtt &&
                (!launchCanonicalize(ring->view(), rBuffer.data(), nullptr, baseRCount, stream.raw()) ||
                 !launchNttForward(ring->view(), rBuffer.data(), baseRCount, nullptr, stream.raw()))) return false;
            if (compactNoise)
            {
                // Out-of-place is essential: an output limb may otherwise
                // overwrite q0 while a different limb's block still reads it.
                if (!launchNttForwardCenteredLimbFrom(ring->view(),
                        compactNoiseSource.data(), nullptr, idx + compactNoiseLimbOffset,
                        ctBuffer.data(), nullptr, count, stream.raw())) return false;
            }
            else if (!launchCanonicalize(ring->view(), ctBuffer.data(), nullptr, count, stream.raw()) ||
                !launchNttForward(ring->view(), ctBuffer.data(), count, nullptr, stream.raw())) return false;
            if (gadgetLeaves)
            {
                if (!launchSelectScaleLimb(ring->view(), bBuffer.data(), idx + selectBInputOffset,
                        idx + selectBLimbOffset, scalar, bBuffer.data(), idx + selectBOutputOffset,
                        static_cast<u32>(selectBInput.size()), stream.raw()) ||
                    !launchSelectScaleLimb(ring->view(), rBuffer.data(), idx + selectRInputOffset,
                        idx + selectRLimbOffset, scalar, rBuffer.data(), idx + selectROutputOffset,
                        width, stream.raw())) return false;
            }
            if (!launchInnerProduct(ring->view(), rBuffer.data(), bBuffer.data(),
                    idx + productROffset, idx + productBOffset, 1u, ctBuffer.data(),
                    idx + productOutOffset, static_cast<u32>(productR.size()), true, false, stream.raw())) return false;
            for (u32 power = 0; power < fullTau; ++power)
            {
                const auto& group = groups[power];
                if (group.mInput.empty()) continue;
                const auto groupCount = static_cast<u32>(group.mInput.size());
                if (!launchScaleByPow2(ring->view(), rBuffer.data(), idx + group.mInputOffset,
                        scaledBuffer.data(), nullptr, groupCount,
                        factors[power], stream.raw()) ||
                    !launchElementwise(ring->view(), ctBuffer.data(), idx + group.mOutputOffset,
                        scaledBuffer.data(), nullptr, ctBuffer.data(), idx + group.mOutputOffset,
                        groupCount, ElemOp::Add, stream.raw())) return false;
            }
        }
        if (retainedRandomizers)
        {
            HostStep retainStep("setup: LENC randomizer retain");
            if (!retainedNtt.resize(*ring, retainedRandomizerCount) ||
                !gpuMemcpyD2D(retainedNtt.data(), rBuffer.data(), retainedNtt.bytes(), stream.raw()) ||
                !launchCanonicalize(ring->view(), retainedNtt.data(), nullptr, retainedRandomizerCount, stream.raw()) ||
                !stream.sync()) return false;
            randomizerOwner = std::make_shared<GpuLencRandomizers>(ctx, ring, std::move(retainedNtt));
        }
        else if (outFirstRNtt)
        {
            HostStep downloadStep("setup: LENC randomizer host download");
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
        HostStep downloadStep("setup: lenc device download");
        const char* pipelinedDownload = std::getenv("LV_GPU_SETUP_PIPELINED_DOWNLOAD");
        if (!pipelinedDownload || pipelinedDownload[0] != '0')
        {
            if (!ctBuffer.downloadPipelined(outCtNtt, stream, requestedWorkers)) return false;
            if (outFirstRNtt) *outFirstRNtt = std::move(firstRNtt);
            if (retainedRandomizers) *retainedRandomizers = std::move(randomizerOwner);
            return true;
        }
        const char* directDownload = std::getenv("LV_GPU_SETUP_DIRECT_DOWNLOAD");
        if (!directDownload || directDownload[0] != '0')
        {
            // Download into independently owned, uninitialized destinations.
            // This avoids staging then copying the full ciphertext on the CPU.
            // Neither output nor any aliased fallback source changes until all
            // transfers complete; next remains alive through DrainStream.
            next.resize(count);
            for (std::size_t i = 0; i < next.size(); ++i)
            {
                next[i].mCoeffs.resize(ring->polyWords());
                if (!gpuMemcpyD2H(next[i].mCoeffs.data(), ctBuffer.poly(i),
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
                if (!gpuMemcpyD2H(stage, ctBuffer.data(), bytes, stream.raw()) || !stream.sync()) return false;
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
        std::vector<RnsPoly>& outCoeffs, std::span<const u64> compactNoiseLimb0)
    {
        return assembleLheCiphertextDevice(ctx, r, sk1, publicANtt, gadgetLogBase,
            rInputIsNtt, rPowerOffset, outCoeffs, compactNoiseLimb0, nullptr);
    }

    bool assembleLheCiphertextDevice(
        const RingNttContext& ctx, std::span<const RnsPoly> r,
        std::span<const RnsPoly> sk1, std::span<const RnsPoly> publicANtt,
        u32 gadgetLogBase, bool rInputIsNtt, u32 rPowerOffset,
        std::vector<RnsPoly>& outCoeffs, std::span<const u64> compactNoiseLimb0,
        const DeviceScalars* compactNoiseDevice)
    {
        return assembleLheCiphertextDevice(ctx, r, sk1, publicANtt, gadgetLogBase,
            rInputIsNtt, rPowerOffset, outCoeffs, compactNoiseLimb0, compactNoiseDevice, 1);
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
        u64 rootSecretOwnerRunId,
        bool topSecretDomain)
    {
        const auto* retainedR = randomizers ? lencRandomizerDeviceNtt(ctx, randomizers) : nullptr;
        const auto rCount = retainedR ? retainedR->count()
            : rootR1Device ? rootR1Device->count() : r.size();
        const auto skCount = rootSecretDevice ? rootSecretDevice->count() : sk1.size();
        if (!enabled() || !rCount || !skCount || rPowerOffset > 1u ||
            (randomizers && (!retainedR || !r.empty() || !rInputIsNtt)) ||
            (rootR1Device && (randomizers || !r.empty() || rInputIsNtt ||
                !rootErrorBatchMatches(ctx, *rootR1Device, rCount))) ||
            (rootSecretDevice && (!sk1.empty() ||
                !(topSecretDomain
                    ? topSecretUniformBatchMatches(ctx, *rootSecretDevice,
                        skCount, rootSecretOwnerRunId)
                    : rootSecretUniformBatchMatches(ctx, *rootSecretDevice,
                        skCount, rootSecretOwnerRunId)))) ||
            rCount > std::numeric_limits<u32>::max() ||
            skCount > std::numeric_limits<u32>::max() ||
            (retainedPublicA ? (!publicANtt.empty() ||
                !retainedPublicUniformMatches(ctx, *retainedPublicA, rCount, false))
                : publicANtt.size() != rCount) ||
            (!retainedR && !rootR1Device && !validateRingBatchShape(r, ctx.mParams)) ||
            (!rootSecretDevice && !validateRingBatchShape(sk1, ctx.mParams)) ||
            (!retainedPublicA && !validateRingBatchShape(publicANtt, ctx.mParams))) return false;
        const u64 count64 = static_cast<u64>(rCount) * skCount;
        if (count64 > std::numeric_limits<u32>::max() ||
            static_cast<u64>(gadgetLogBase) * (skCount - 1u) >
                std::numeric_limits<u32>::max()) return false;
        const char* forceDecline = std::getenv("LV_GPU_SETUP_LHE_DEVICE_FORCE_DECLINE");
        const char* topDecline = std::getenv("LV_GPU_SETUP_TOP_SK1_LHE_FORCE_DECLINE");
        if ((forceDecline && forceDecline[0] == '1') ||
            (topSecretDomain && topDecline && topDecline[0] == '1')) return false;
        HostStep totalStep("setup: lhe device assembly");
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

        auto& stream = threadSampleStream();
        struct RestoreStream
        {
            void* previous = gpuCurrentStream();
            ~RestoreStream() { gpuSetCurrentStream(previous); }
        } restoreStream;
        gpuSetCurrentStream(stream.raw());
        GpuPolyBuffer rBuffer, skBuffer, aBuffer, ctBuffer, noiseBuffer;
        using DeviceAllocation = std::unique_ptr<void, decltype(&gpuFree)>;
        DeviceAllocation deviceIndices(nullptr, gpuFree);
        std::vector<RnsPoly> next;
        // Declare this after every queued source/destination owner so even a
        // partial upload/download failure drains before any owner is destroyed.
        struct DrainStream
        {
            GpuStream& stream;
            ~DrainStream() { stream.sync(); }
        } drainStream{stream};
        {
            HostStep uploadStep("setup: lhe device upload");
            if ((!retainedR && !rBuffer.resize(*ring, rows)) || !skBuffer.resize(*ring, cols) ||
                !aBuffer.resize(*ring, rows) || !ctBuffer.resize(*ring, count) ||
                (!retainedR && !(rootR1Device
                    ? gpuMemcpyD2D(rBuffer.data(), rootR1Device->mImpl->mBuf.data(),
                        static_cast<std::size_t>(rows) * polyBytes, stream.raw())
                    : rBuffer.upload(r, stream))) ||
                !(rootSecretDevice
                    ? gpuMemcpyD2D(skBuffer.data(),
                        rootSecretDevice->mImpl->mBuf.data(),
                        static_cast<std::size_t>(cols) * polyBytes, stream.raw())
                    : skBuffer.upload(sk1, stream)) ||
                !(retainedPublicA
                    ? copyRetainedPublicUniform(ctx, aBuffer, *retainedPublicA,
                        0, rows, false, stream)
                    : uploadPublicUniformOrHost(ctx, aBuffer, publicANtt, stream))) return false;
            if (compactNoise && (!noiseBuffer.resize(*ring, count) ||
                    !(compactNoiseDevice
                        ? copyRowsFromDevice(noiseBuffer.data(), polyBytes, compactNoiseDevice->data(), noiseDegree * sizeof(u64), count, stream)
                        : uploadRowsFromHost(noiseBuffer.data(), polyBytes, compactNoiseLimb0.data(), noiseDegree * sizeof(u64), count, stream)))) return false;
            deviceIndices.reset(gpuMalloc(indices.size() * sizeof(u32)));
            if (!deviceIndices ||
                !gpuMemcpyH2D(deviceIndices.get(), indices.data(), indices.size() * sizeof(u32), stream.raw())) return false;
        }
        const auto* idx = static_cast<const u32*>(deviceIndices.get());
        const auto* rData = retainedR ? retainedR->data() : rBuffer.data();
        {
            HostStep kernelStep("setup: lhe device launches");
            // CPU scalar/NTT helpers reduce arbitrary u64 input coefficients.
            // Reduce on the device before entering canonical NTT/add kernels.
            if ((!retainedR && !launchCanonicalize(ring->view(), rBuffer.data(), nullptr, rows, stream.raw())) ||
                !launchCanonicalize(ring->view(), skBuffer.data(), nullptr, cols, stream.raw()) ||
                !launchCanonicalize(ring->view(), aBuffer.data(), nullptr, rows, stream.raw()) ||
                !launchNttForward(ring->view(), skBuffer.data(), cols, nullptr, stream.raw())) return false;
            if (!rInputIsNtt &&
                !launchNttForward(ring->view(), rBuffer.data(), rows, nullptr, stream.raw())) return false;
            for (u32 col = 0; col < cols; ++col)
            {
                const auto* outputIndices = idx + static_cast<std::size_t>(col) * rows;
                if ((col == 0u && rPowerOffset == 0u) || gadgetLogBase == 0u)
                {
                    if (!launchElementwise(ring->view(), rData, nullptr, nullptr, nullptr,
                            ctBuffer.data(), outputIndices, rows, ElemOp::Copy, stream.raw())) return false;
                }
                else if (!launchScaleByPow2(ring->view(), rData, nullptr,
                        ctBuffer.data(), outputIndices, rows,
                        factors[col], stream.raw())) return false;
            }
            if (!launchInnerProduct(ring->view(), aBuffer.data(), skBuffer.data(),
                    idx + count, idx + static_cast<std::size_t>(count) * 2u, 1u,
                    ctBuffer.data(), nullptr, count, true, false, stream.raw()) ||
                !launchNttInverse(ring->view(), ctBuffer.data(), count, nullptr, stream.raw())) return false;
            if (compactNoise)
            {
                // This lift is safely in-place: one thread loads one q0
                // coefficient before writing that coefficient in every limb.
                if (!launchLiftCenteredLimb(ring->view(), noiseBuffer.data(), nullptr,
                        idx + static_cast<std::size_t>(count) * 3u,
                        ones,
                        noiseBuffer.data(), nullptr, count, stream.raw()) ||
                    !launchElementwise(ring->view(), ctBuffer.data(), nullptr,
                        noiseBuffer.data(), nullptr, ctBuffer.data(), nullptr,
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
        HostStep downloadStep("setup: lhe device download");
        const char* pipeline = std::getenv("LV_GPU_SETUP_EXTRA_PIPELINED_DOWNLOAD");
        if ((!pipeline || pipeline[0] != '0') && count >= 4)
        {
            if (!ctBuffer.downloadPipelined(next, stream, requestedWorkers) || next.size() != count)
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
                if (!gpuMemcpyD2H(stage, ctBuffer.data(), bytes, stream.raw()) || !stream.sync()) return false;
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

    struct ReceiverShrinkTileEvents
    {
        explicit ReceiverShrinkTileEvents(GpuStream& producer)
            : mProducer(producer)
        {
        }

        ~ReceiverShrinkTileEvents()
        {
            // A failed event record/wait or kernel launch may leave coefficient
            // writes queued on the secondary stream without a main-stream wait.
            // Do not let the caller's session buffers unwind under those writes.
            if (mUnsafe) mProducer.sync();
            for (u32 i = 0; i < mEventCount; ++i) gpuEventDestroy(mEvents[i]);
        }

        bool create(u32 count)
        {
            if (count > mEvents.size()) return false;
            while (mEventCount < count)
            {
                void* event = gpuEventCreate();
                if (!event) return false;
                mEvents[mEventCount++] = event;
            }
            return true;
        }

        bool drain()
        {
            if (mUnsafe && !mProducer.sync()) return false;
            mUnsafe = false;
            return true;
        }

        GpuStream& mProducer;
        std::array<void*, 5> mEvents{};
        u32 mEventCount = 0u;
        bool mUnsafe = false;
    };

    // Split one coefficient-domain centred decomposition into disjoint input and
    // output-index slices. The producer queues tile i+1 while the main stream
    // transforms tile i. `completed=false` is a soft miss: all producer work has
    // been drained and the caller can enqueue the original whole-batch chain.
    bool tryReceiverShrinkGadgetNttTiles(
        const GpuRing& ring,
        const ShrinkExpandReceiverState& state,
        const u64* input,
        u32 inputCount,
        u32 levels,
        u64* output,
        const u32* outputIdx,
        GpuStream& mainStream,
        bool& completed)
    {
        completed = false;
        const u32 tiles = receiverShrinkTileCount();
        if ((tiles != 2u && tiles != 4u) || inputCount == 0u || levels == 0u ||
            (inputCount % tiles) != 0u || inputCount / tiles < 32u)
        {
            return true;
        }

        auto& producer = threadSampleStream();
        ReceiverShrinkTileEvents owned(producer);
        if (!owned.create(tiles + 1u)) return true;

        // The inverse transform that produced `input`, the mNodes allocation and
        // the persistent output-index upload all precede this marker on main.
        if (!gpuEventRecord(owned.mEvents[0], mainStream.raw()) ||
            !gpuStreamWaitEvent(producer.raw(), owned.mEvents[0]))
        {
            return true;
        }

        const u32 tileInputs = inputCount / tiles;
        const u32 tileOutputs = tileInputs * levels;
        for (u32 tile = 0; tile < tiles; ++tile)
        {
            const std::size_t inputOffset =
                static_cast<std::size_t>(tile) * tileInputs;
            const std::size_t outputOffset = inputOffset * levels;

            // Set this before the launch: even a host-side launch error must take
            // the conservative drain path before the synchronous overwrite.
            owned.mUnsafe = true;
            if (!launchGadgetDecompose(
                    ring.view(), input + inputOffset * ring.polyWords(), nullptr,
                    tileInputs, state.mParams.mGadgetLogBase, 1u, levels, true,
                    output, outputIdx + outputOffset, producer.raw()) ||
                !gpuEventRecord(owned.mEvents[tile + 1u], producer.raw()) ||
                !gpuStreamWaitEvent(mainStream.raw(), owned.mEvents[tile + 1u]) ||
                !launchNttForward(
                    ring.view(), output, tileOutputs,
                    outputIdx + outputOffset, mainStream.raw()))
            {
                // Previous main-stream tile transforms, if any, are harmless:
                // the legacy fallback below is queued after them and overwrites
                // every coefficient-domain destination before transforming all.
                return owned.drain();
            }
        }

        // Every producer write now has a matching wait and consumer on main.
        // CUDA event waits capture the record, so the handles can be destroyed
        // without a host synchronisation while the streams finish asynchronously.
        owned.mUnsafe = false;
        completed = true;
        return true;
    }

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
        bool allowTilePipeline,
        ReceiverFirstQueryAllocations* firstQueryAllocations,
        const void* firstQueryOwner = nullptr, u64 firstQuerySid = 0,
        const ShrinkOverride& ov = ShrinkOverride{})
    {
        AutoTimer timer(globalTimingStats.mGpuShrinkTimeUs);
        const std::span<const RnsPoly> x = xHost;
        if (!enabled() || muHi == 0 || tauHi == 0) return bail("disabled or degenerate sizes");
        if (state.mParams.mTau != tauHi) return bail("tau mismatch");
        if (!state.mParams.mTruncateOneGadgetDigit) return bail("non-truncated parameters");

        auto cache = receiverCache(state);
        if (!cache) return bail("offline cache upload failed");
        auto ring = cache->mRing;
        const u32 rho = ring->rho();

        const u32 chunkCount = (xCount + muHi - 1u) / muHi;
        if (chunkCount == 0) return bail("no chunks");

        const u32 width = ov.mWidthPadded ? ov.mWidthPadded : state.mLacct.mWidthPadded;
        const u32 levels = ilog2(width);
        if (width == 0 || (width & (width - 1u)) != 0 || width < muHi) return bail("lacct geometry");
        if (!ov.mWidthPadded && levels != state.mLacct.mLevels) return bail("lacct geometry");
        const u32 nodeCount = (2u * width) - 1u;

        const bool leafInputsAreGadget = ov.mLeafInputsAreGadget < 0
            ? state.mParams.mLeafInputsAreGadget
            : (ov.mLeafInputsAreGadget != 0);
        const u32 tauLeafCount = leafTau(
            state.mParams.mPlaintextModulusBits, state.mParams.mGadgetLogBase, leafInputsAreGadget);
        const u32 fullTau = tauHi + 1u;
        if (tauLeafCount == 0 || tauLeafCount > fullTau) return bail("leaf tau");
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
            return bail("recursive high-digit shape");
        const bool directRecursiveLeaves =
            recursiveHiInput && directRecursiveLeafEnabled() && leafInputsAreGadget &&
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

        auto& stream = threadStream();
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
            identityLeafEnabled() && !leafInputsAreGadget &&
            tauLeafCount == 1u && inputPlainBroadcastBits != 0u &&
            inputPlainBroadcastBits <= state.mParams.mGadgetLogBase &&
            canLaunchNttForwardFromPlainBroadcast(ring->view());
        // Any path that can copy, decompose, or otherwise expose a full RNS
        // polynomial first restores the opaque DeviceBatch's logical layout.
        // This must precede the noncontiguous whole-poly D2D copies below.
        if (inputPlainBroadcastSingleLimb && !singleLimbIdentityEligible &&
            !ensurePlainBroadcastMaterialized(*xDev->mImpl, stream))
            return false;

        Region* regUp = new Region(regions().mUploadUs, stream.raw());

        if (directRecursiveLeaves)
        {
            // mBuf stores one full-RNS high digit per rho logical child
            // leaves. The leaf NTT below reconstructs the distinct centred
            // representative selected by each logical leaf directly.
            impl->mXSrc = xDev->mImpl->mBuf.data();
        }
        else if (recursiveHiInput)
        {
            // Controlled fallback: recreate the old sparse CRT-lifted dHat
            // layout when the fused leaf load is disabled or unsupported.
            if (!impl->mX.resize(*ring, static_cast<std::size_t>(chunkCount) * width))
                return false;
            if (!impl->mX.zero(stream)) return false;
            impl->mXSrc = impl->mX.data();

            const std::size_t idxCount = xCount;
            const u64 geo = idxKey(0xD4A8u, xCount, muHi, width, rho, chunkCount);
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
                    ring->view(), xDev->mImpl->mBuf.data(), dAll,
                    dAll + idxCount * 2u, ring->crtLiftFactors(), impl->mX.data(),
                    dAll + idxCount, xCount, stream.raw()))
                return false;
        }
        else if (contiguous)
        {
            impl->mXSrc = xDev->mImpl->mBuf.data();
        }
        else
        {
            if (!impl->mX.resize(*ring, static_cast<std::size_t>(chunkCount) * width)) return false;
            if (!impl->mX.zero(stream)) return false;
            impl->mXSrc = impl->mX.data();
            for (u32 c = 0; c < chunkCount; ++c)
            {
                const std::size_t start = static_cast<std::size_t>(c) * muHi;
                const std::size_t end = std::min<std::size_t>(start + muHi, xCount);
                if (end <= start) continue;
                const std::size_t run = end - start;
                if (xDev)
                {
                    if (!gpuMemcpyD2D(
                            impl->mX.poly(static_cast<std::size_t>(c) * width),
                            xDev->mImpl->mBuf.poly(start),
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

        delete regUp;
        auto regKern = std::make_unique<Region>(regions().mKernelUs, stream.raw());

        const std::size_t totalNodes =
            static_cast<std::size_t>(chunkCount) * nodeCount * maxTau + 1u;
        const bool reservedNodes = takeReceiverFirstQueryNodes(
            firstQueryAllocations, *ring, state.mParams.mRing, xCount,
            muHi, tauHi, width, maxTau, totalNodes,
            firstQueryOwner, firstQuerySid, impl->mNodes, stream);
        if (!reservedNodes && !impl->mNodes.resize(*ring, totalNodes))
            return false;
        // Every real node slot is overwritten before use. Only padding terms need
        // zero, so clear one shared sentinel instead of the entire tree buffer.
        if (!gpuMemsetZero(
                impl->mNodes.poly(impl->zeroNodeSlot()), ring->polyBytes(), stream.raw()))
            return false;
        if (!impl->mDigest.resize(*ring, chunkCount)) return false;

        const std::size_t maxNodesAtDepth = static_cast<std::size_t>(chunkCount) * (width / 2u);
        if (!impl->mScratch.resize(*ring, std::max<std::size_t>(maxNodesAtDepth, chunkCount))) return false;

        // Initial experiment scope: only regular device-resident recursive
        // receiver shrinks in the fixed N=8192/rho=4/tauHi=1 tree, only among
        // the caller-designated outer three frames, and only with at least 64
        // complete eight-leaf chunks. Those constraints make both decomposition
        // pairs evenly tileable and keep the narrowest four-way NTT at 32 polys.
        const bool receiverShrinkTilePipeline =
            allowTilePipeline && receiverShrinkTilePipelineEnabled() &&
            !wantHostOutputs && xDev && ov.mWidthPadded == 0u &&
            ov.mLeafInputsAreGadget < 0 && ov.mWantDHat &&
            ring->n() == 8192u && rho == 4u && tauHi == 1u &&
            tauLeafCount == 1u && maxTau == 1u && muHi == 8u && width == 8u &&
            levels == 3u && state.mParams.mGadgetLogBase == 110u &&
            state.mParams.mPlaintextModulusBits == 55u &&
            state.mParams.mRing.mCoeffModulusBits.size() == 4u &&
            std::all_of(
                state.mParams.mRing.mCoeffModulusBits.begin(),
                state.mParams.mRing.mCoeffModulusBits.end(),
                [](int bits) { return bits == 55; }) &&
            chunkCount >= 64u &&
            static_cast<u64>(xCount) == static_cast<u64>(chunkCount) * muHi;

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
                const u64 geo = idxKey(
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
                        ring->view(), impl->mXSrc, dAll, dAll + 2 * srcCount,
                        impl->mNodes.data(), dAll + srcCount,
                        static_cast<u32>(srcCount), stream.raw()))
                    return false;

                if (recursiveDiagonalEnabled() && rho > 1u && levels > 0u)
                {
                    const u32 leafParentCount = chunkCount * (width / 2u);
                    u64* leafParent =
                        (levels == 1u && !gpuFusedIpActive())
                            ? impl->mDigest.data()
                            : impl->mScratch.data();
                    const bool recursiveLeafSelfZero =
                        recursiveLeafSelfZeroEnabled() && ring->n() == 8192u &&
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
                        recursiveLeafSparseInverseEnabled() &&
                        recursiveLeafSelfZero && !gpuFusedIpActive() &&
                        ring->n() == 8192u && rho == 4u && width == 8u &&
                        muHi == 8u && levels == 3u && nodeCount == 15u &&
                        tauHi == 1u && tauLeafCount == 1u && maxTau == 1u &&
                        xCount >= 256u && xCount <= 2048u &&
                        static_cast<u64>(xCount) ==
                            static_cast<u64>(chunkCount) * muHi;
                    // Eligibility is committed before zero elision. The tiled
                    // secondary-stream path still invokes a dense gadget and is
                    // therefore excluded from this first sparse-pair experiment.
                    const bool sparsePairEligible =
                        sparseInverseEligible && !receiverShrinkTilePipeline &&
                        state.mParams.mGadgetLogBase == 110u &&
                        state.mParams.mPlaintextModulusBits == 55u &&
                        canLaunchGadgetDecomposeHi110RecursiveLeafSparsePair(
                            ring->view(), leafParent, leafParentCount,
                            impl->mNodes.data());
                    if (sparsePairEligible)
                    {
                        if (!tryLaunchNttInverseRecursiveLeafSparseNegateNoZero(
                            ring->view(), impl->mNodes.data(),
                            cache->mRecursiveLeafB.poly(0),
                            cache->mRecursiveLeafB.poly(1),
                            xDev->mImpl->mBuf.data(), leafParent, xCount,
                            stream.raw(), sparseInverseLaunched))
                            return false;
                        recursiveLeafSparsePairRequired = sparseInverseLaunched;
                    }
                    if (sparseInverseEligible && !sparseInverseLaunched &&
                        !tryLaunchNttInverseRecursiveLeafSparseNegate(
                            ring->view(), impl->mNodes.data(),
                            cache->mRecursiveLeafB.poly(0),
                            cache->mRecursiveLeafB.poly(1),
                            xDev->mImpl->mBuf.data(), leafParent, xCount,
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
                        const u64 diagGeo = idxKey(
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
                                ring->view(), impl->mNodes.data(), dDiag,
                                dDiag + xCount,
                                cache->mRecursiveLeafB.poly(0),
                                cache->mRecursiveLeafB.poly(1),
                                xDev->mImpl->mBuf.data(), leafParent,
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
            const u64 geo = idxKey(
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
            if (identityLeafEnabled() && !impl->mLeafInputsAreGadget && tauLeafCount == 1u &&
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
                          ring->view(), impl->mXSrc, dSrc,
                          impl->mNodes.data(), dDst,
                          static_cast<u32>(srcCount), stream.raw())
                    : launchNttForwardFrom(
                          ring->view(), impl->mXSrc, dSrc,
                          impl->mNodes.data(), dDst,
                          static_cast<u32>(srcCount), stream.raw());
                if (!forwardOk)
                    return false;
                leafNttDone = true;
            }
            else if (impl->mLeafInputsAreGadget)
            {
                if (!launchLiftCenteredLimb(
                        ring->view(), impl->mXSrc, dSrc, dLimb, ring->invCrtLiftFactors(),
                        impl->mNodes.data(), dDst, static_cast<u32>(srcCount), stream.raw()))
                    return false;
            }
            else if (!launchGadgetDecompose(
                         ring->view(), impl->mXSrc, dSrc, static_cast<u32>(srcCount),
                         state.mParams.mGadgetLogBase, 0, tauLeafCount, false, impl->mNodes.data(), dDst,
                         stream.raw()))
            {
                return false;
            }

            if (!leafNttDone && !launchNttForward(
                    ring->view(), impl->mNodes.data(), static_cast<u32>(dstCount), dDst, stream.raw()))
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
            const bool fuseIp = gpuFusedIpActive();
            bool inverseDone = leafLevel && recursiveLeafInverseDone;
            // On the shipped separate-IP path the root level can write directly
            // into mDigest, avoiding a terminal D2D copy of every chunk.
            u64* levelOut = (depth == 0 && !fuseIp)
                ? impl->mDigest.data()
                : impl->mScratch.data();

            if (leafLevel && impl->mLeafInputsAreGadget)
            {
                if (!recursiveLeafPairReady)
                {
                // The recursive-leaf pairing scales each side by the CRT lift of
                // its own limb; see recursiveLeafPairInnerProductNttToStd.
                const std::size_t idxCount = outCount;
                const u64 geo = idxKey(
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
                        ring->view(), cache->mRecursiveLeafB.poly(0),
                        cache->mRecursiveLeafB.poly(1), impl->mNodes.data(), dL, dR, dLL, dRL,
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
                            ring->view(), levelOut, cache->mPublicB.data(),
                            impl->mNodes.data(), outCount, static_cast<u32>(depth),
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
                const u64 geo = idxKey(
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
                    fusedIp.mA = cache->mPublicB.data();
                    fusedIp.mB = impl->mNodes.data();
                    fusedIp.mAIdx = dA;
                    fusedIp.mBIdx = dB;
                    fusedIp.mTerms = terms;
                    fusedIp.mMode = NttFusedIp::Replace;
                }
                else
                {
                    if (!launchInnerProduct(
                            ring->view(), cache->mPublicB.data(), impl->mNodes.data(), dA, dB, terms,
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
                    ring->view(), levelOut, outCount, nullptr, kElemOpNoneHost, nullptr,
                    static_cast<u32>(ElemOp::Negate), nullptr, stream.raw(), fusedIp,
                    state.mParams.mAlpha == 2u))
                return false;

            if (depth == 0)
            {
                // The default separate-IP path already targeted mDigest. The
                // optional fused path still transforms mScratch in place.
                if (levelOut != impl->mDigest.data() &&
                    !gpuMemcpyD2D(
                        impl->mDigest.data(), levelOut,
                        static_cast<std::size_t>(chunkCount) * ring->polyBytes(), stream.raw()))
                    return false;
                break;
            }

            // decomposeHiNtt: centred high digits, then forward NTT.
            const std::size_t dstCount = static_cast<std::size_t>(outCount) * tauHi;
            const u64 dstGeo = idxKey(
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
                        ring->view(), impl->mScratch.data(), outCount,
                        impl->mNodes.data(), dDst, stream.raw()))
                    return false;
                sparsePairDecomposed = true;
                recursiveLeafSparsePairRequired = false;
            }
            bool tiled = false;
            if (!sparsePairDecomposed && receiverShrinkTilePipeline &&
                !tryReceiverShrinkGadgetNttTiles(
                    *ring, state, impl->mScratch.data(), outCount, tauHi,
                    impl->mNodes.data(), dDst, stream, tiled))
            {
                return false;
            }
            if (!sparsePairDecomposed && !tiled)
            {
                if (!launchGadgetDecompose(
                        ring->view(), impl->mScratch.data(), nullptr, outCount,
                        state.mParams.mGadgetLogBase, 1, tauHi, true,
                        impl->mNodes.data(), dDst, stream.raw()))
                    return false;
            }
            if (!tiled)
            {
                if (!launchNttForward(
                        ring->view(), impl->mNodes.data(), static_cast<u32>(dstCount),
                        dDst, stream.raw()))
                    return false;
            }
        }

        regKern.reset();
        // The tree ladder has queued its final read/write of this coefficient
        // scratch. Return it to the stream-ordered cache before descending into
        // recursion so deeper levels can reuse hundreds of MiB rather than grow
        // one retained scratch allocation per session.
        impl->mScratch.release();

        // ---- digests and the child input ----
        if (wantHostOutputs)
        {
            Region regDown(regions().mDownloadUs, stream.raw());
            if (!impl->mDigest.download(digests, stream, 0, chunkCount)) return false;
        }

        // seedLabelGadgetDecomposeHiAndUnbundle: one centred high digit per
        // digest, then split into rho single-limb polynomials.
        if (ov.mWantDHat)
        {
            auto hiDigits = std::make_shared<DeviceBatch>();
            hiDigits->mImpl->mRing = ring;
            const bool decomposeInPlace =
                inplaceHiDigitEnabled() && reuseHiDigitsEnabled() && tauHi == 1u &&
                impl->mDigest.count() == chunkCount;
            // Capture the allocation's address before moving its ownership. The
            // raw address stays valid and becomes both source and destination.
            u64* digestData = impl->mDigest.data();
            if (decomposeInPlace)
                hiDigits->mImpl->mBuf = std::move(impl->mDigest);
            else if (!hiDigits->mImpl->mBuf.resize(
                         *ring, static_cast<std::size_t>(chunkCount) * tauHi))
                return false;
            if (!launchGadgetDecompose(
                    ring->view(), digestData, nullptr, chunkCount, state.mParams.mGadgetLogBase, 1,
                    tauHi, true, hiDigits->mImpl->mBuf.data(), nullptr, stream.raw()))
                return false;

            const std::size_t outCount = static_cast<std::size_t>(chunkCount) * tauHi * rho;
            const bool compactDeviceDHat =
                !wantHostOutputs && directRecursiveLeafEnabled() &&
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
                if (!unbundled.resize(*ring, outCount)) return false;

                const u64 geo = idxKey(0xD4A7u, chunkCount, tauHi, rho);
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
                        ring->view(), hiDigits->mImpl->mBuf.data(), dPair,
                        dPair + outCount, ring->crtLiftFactors(), unbundled.data(),
                        nullptr, static_cast<u32>(outCount), stream.raw()))
                    return false;

                if (wantHostOutputs)
                {
                    std::vector<RnsPoly> flat;
                    {
                        Region regDown(regions().mDownloadUs, stream.raw());
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

            if (reuseHiDigitsEnabled())
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
        std::vector<std::vector<RnsPoly>>& dHatChunks)
    {
        DeviceBatchPtr unused;
        return shrinkChunksImpl(
            state, x, nullptr, static_cast<u32>(x.size()), muHi, tauHi, session, true, digests, dHatChunks,
            unused, false, nullptr);
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
        bool allowTilePipeline,
        ReceiverFirstQueryAllocations* firstQueryAllocations,
        const void* firstQueryOwner, u64 firstQuerySid)
    {
        std::vector<RnsPoly> digests;
        std::vector<std::vector<RnsPoly>> dHatChunks;
        return shrinkChunksImpl(
            state, xHost, xDev, xCount, muHi, tauHi, session, false, digests,
            dHatChunks, dHat, allowTilePipeline, firstQueryAllocations,
            firstQueryOwner, firstQuerySid);
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
        std::shared_ptr<void>& sessionOut)
    {
        const u32 xCount = xDev ? static_cast<u32>(xDev->count()) : static_cast<u32>(x.size());
        if (!enabled() || xCount == 0 || widthPadded == 0 || tauHi == 0) return false;

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
                *session, false, digests, dHatChunks, unused, false,
                nullptr, nullptr, 0, ov) ||
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
            auto& stream = threadStream();
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

        bool rootPriorityNoGoldGeometry(u32 n, u32 rho, u32 gadgetBits)
        {
            static const bool on = [] {
                const char* v = std::getenv("LV_GPU_NOGOLD_ROOT_PRIORITY_PREFETCH");
                return !(v && v[0] == '0');
            }();
            return on && n == 16384u && rho == 8u && gadgetBits == 208u;
        }

        // Everything the priority prefix may write is allocated on the ordinary
        // registered Root stream and completed by rootCache's existing sync.
        // The high-priority stream is intentionally allocation-free: it is
        // created directly through cudart in the host backend and therefore is
        // not part of the .cu allocator's live-stream registry.
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
            void* mOwnerStream = nullptr;
            GpuPolyBuffer mUHi;
            GpuPolyBuffer mAcc;
            GpuPolyBuffer mPhi;
            GpuPolyBuffer mLeftEval;
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
                void* previous = gpuCurrentStream();
                void* priority = mStream ? mStream->raw() : nullptr;
                if (mStream) mStream->sync();
                // These allocations belong to the ordinary registered Root
                // stream. Never hand allocator bookkeeping the dedicated raw
                // priority stream, which intentionally is not registered.
                gpuSetCurrentStream(mOwnerStream);
                mUHi.release();
                mAcc.release();
                mPhi.release();
                mLeftEval.release();
                gpuFree(mIndices);
                mIndices = nullptr;
                mStream.reset();
                gpuSetCurrentStream(previous == priority ? mOwnerStream : previous);
            }

            bool init(
                const GpuRing& ring,
                u32 tauHi,
                u32 leftWidth,
                u32 topCols,
                u32 levels,
                u32 lacctCols)
            {
                if (tauHi == 0u || leftWidth == 0u || topCols == 0u ||
                    levels == 0u || lacctCols == 0u || (lacctCols & 1u))
                    return false;

                mOwnerStream = gpuCurrentStream();
                mStream = GpuStream::createHighestPriority();
                if (!mStream) return false;

                if (!mUHi.resize(ring, tauHi) ||
                    !mAcc.resize(ring, leftWidth) ||
                    !mPhi.resize(ring, leftWidth) ||
                    !mLeftEval.resize(ring, leftWidth))
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

                mIndices = static_cast<u32*>(gpuMalloc(offset * sizeof(u32)));
                if (!mIndices) return false;
                mHostIndices.resize(offset);

                // Submit one marker now, then join it to rootCache's ordinary
                // stream. The cache's existing final sync completes this warmup
                // before send without adding another host synchronization.
                void* warm = gpuEventCreate();
                if (!warm) return false;
                const bool warmQueued =
                    gpuEventRecord(warm, mStream->raw()) &&
                    gpuStreamWaitEvent(mOwnerStream, warm);
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
            const ReceiverState& state, const RingNttContext& ctx)
        {
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
            auto& stream = threadStream();

            const auto upload = [&](const RingTensor& t, GpuPolyBuffer& dst, u32& cols) {
                cols = t.mCols;
                return dst.resize(*ring, t.mPolys.size()) && dst.upload(t.mPolys, stream);
            };
            const auto uploadCtR = [&] {
                if (!state.mRootCtRWire)
                {
                    HostStep phase("setup root: CtR upload host NTT");
                    return upload(state.mRootCtRRt, cache->mCtR, cache->mCtRCols);
                }
                HostStep phase("setup root: CtR upload encoded wire and NTT");
                cache->mCtRCols = state.mRootCtRRt.mCols;
                const auto count = ringTensorSize(state.mRootCtRRt);
                if (!count || count > std::numeric_limits<u32>::max() ||
                    !cache->mCtR.resize(*ring, static_cast<std::size_t>(count)))
                    return false;
                const auto encoded = state.mRootCtRWire->encodedCoefficients();
                return encoded.size() == cache->mCtR.bytes() &&
                    uploadSetupWire(cache->mCtR.data(), encoded.data(), encoded.size(), stream) &&
                    launchCanonicalize(ring->view(), cache->mCtR.data(), nullptr,
                        static_cast<u32>(count), stream.raw()) &&
                    nttForward(*ring, cache->mCtR.data(), static_cast<u32>(count), stream);
            };
            const auto uploadTopCt = [&] {
                if (!state.mRootTopCtWire)
                {
                    HostStep phase("setup root: TopCt upload host scatter");
                    return upload(state.mRootTopCt, cache->mTopCt, cache->mTopCols);
                }
                HostStep phase("setup root: TopCt upload encoded wire");
                cache->mTopCols = state.mRootTopCt.mCols;
                const auto count = ringTensorSize(state.mRootTopCt);
                if (count > std::numeric_limits<std::size_t>::max() ||
                    !cache->mTopCt.resize(*ring, static_cast<std::size_t>(count)))
                    return false;
                const auto encoded = state.mRootTopCtWire->encodedCoefficients();
                return encoded.size() == cache->mTopCt.bytes() &&
                    uploadSetupWire(cache->mTopCt.data(), encoded.data(), encoded.size(), stream);
            };
            const auto uploadLacct = [&] {
                if (!state.mRootLacctLeftWire)
                {
                    HostStep phase("setup root: Lacct upload host scatter");
                    return upload(state.mRootLacctLeft.mCt, cache->mLacctLeft, cache->mLacctCols);
                }
                HostStep phase("setup root: Lacct upload encoded wire");
                cache->mLacctCols = state.mRootLacctLeft.mCt.mCols;
                const auto count = ringTensorSize(state.mRootLacctLeft.mCt);
                if (count > std::numeric_limits<std::size_t>::max() ||
                    !cache->mLacctLeft.resize(*ring, static_cast<std::size_t>(count)))
                    return false;
                const auto encoded = state.mRootLacctLeftWire->encodedCoefficients();
                return encoded.size() == cache->mLacctLeft.bytes() &&
                    uploadSetupWire(cache->mLacctLeft.data(), encoded.data(), encoded.size(), stream);
            };
            const auto uploadPublicBStar = [&] {
                if (!state.mRootPublicBStarWire)
                {
                    HostStep phase("setup root: BStar upload host scatter");
                    return cache->mPublicBStar.resize(*ring, state.mRootPublicBStarNtt.size()) &&
                        cache->mPublicBStar.upload(state.mRootPublicBStarNtt, stream);
                }
                HostStep phase("setup root: BStar upload encoded wire");
                if (!cache->mPublicBStar.resize(*ring, state.mRootRandomizerWidth))
                    return false;
                const auto encoded = state.mRootPublicBStarWire->encodedCoefficients();
                return encoded.size() == cache->mPublicBStar.bytes() &&
                    uploadSetupWire(cache->mPublicBStar.data(), encoded.data(), encoded.size(), stream);
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
                ring->n(), ring->rho(), state.mParams.mShrinkExpand.mGadgetLogBase);
            const u32 priorityLeftWidth = noGoldPriorityGeometry
                ? 8u : kRootPriorityLeftWidth;
            if (rootFinalizePriorityPrefetchEnabledImpl() &&
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
                        cache->mLacctCols))
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
        DeviceBatchPtr* negDPrimeDevice)
    {
        AutoTimer timer(globalTimingStats.mGpuMiscTimeUs);
        if (negDPrimeDevice) negDPrimeDevice->reset();
        const bool seededZeta = !zetaTaskSeeds.empty();
        const u32 randomizerWidth = seededZeta
            ? state.mRootRandomizerWidth
            : (zeta ? static_cast<u32>(zeta->size()) : 0u);
        if (!enabled() || tauHi == 0 || randomizerWidth == 0u ||
            (!seededZeta && !zeta))
            return bail("rootDigest: sizes");
        const bool goldenZetaGeometry =
            ctx.mParams.mPolyModulusDegree == 8192u && ringModulusCount(ctx) == 4u &&
            state.mParams.mShrinkExpand.mGadgetLogBase == 110u &&
            rangesPerPoly >= 2u && rangesPerPoly <= 32u;
        const bool noGoldZetaGeometry = noGoldRootZetaEnabled() &&
            ctx.mParams.mPolyModulusDegree == 16384u && ringModulusCount(ctx) == 8u &&
            state.mParams.mShrinkExpand.mGadgetLogBase == 208u &&
            rangesPerPoly >= 2u && rangesPerPoly <= 32u;
        if (seededZeta &&
            (!rootZetaEnabled() || (!goldenZetaGeometry && !noGoldZetaGeometry) ||
             [&] {
                 for (std::size_t limb = 0; limb < ringModulusCount(ctx); ++limb)
                     if (ringModulusValue(ctx, limb) >= (u64(1) << 63u)) return true;
                 return false;
             }() ||
             randomizerWidth != 3u ||
             zetaTaskSeeds.size() != 3u * rangesPerPoly))
            return bail("rootDigest: root zeta geometry");

        auto tree = std::static_pointer_cast<LevelSession>(leftTreeSession);
        if (!tree || !tree->mImpl) return bail("rootDigest: no device left tree");
        auto& treeImpl = *tree->mImpl;

        auto cache = rootCache(state, ctx);
        if (!cache || cache->mPublicBStar.count() != randomizerWidth)
            return bail("rootDigest: offline tensors");
        auto ring = cache->mRing;

        auto level = receiverCache(state.mShrinkExpandState);
        // publicB[1 .. tauHi] are the Root's left public matrices, the same slice
        // prepareRootDigestReceiver takes out of buildLencPublicBNtt.
        if (!level || level->mPublicB.count() < static_cast<std::size_t>(1) + tauHi)
            return bail("rootDigest: publicB too short");

        const u32 topCols = tauHi + randomizerWidth;
        auto& stream = threadStream();
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
        auto regKern = std::make_unique<Region>(regions().mKernelUs, stream.raw());

        // gadget(yLeft) straight into the first tauHi slots, then zeta into the rest.
        // yLeft is the tree's digest and is already here, so it never crosses.
        auto inputs = std::make_shared<DeviceBatch>();
        inputs->mImpl->mRing = ring;
        if (!inputs->mImpl->mBuf.resize(*ring, topCols)) return false;
        u64* inputsData = inputs->mImpl->mBuf.data();

        if (!launchGadgetDecompose(
                ring->view(), treeImpl.mDigest.data(), nullptr, 1,
                state.mParams.mShrinkExpand.mGadgetLogBase, 1, tauHi, true, inputsData, nullptr,
                stream.raw()))
            return false;
        if (seededZeta)
        {
            auto& scratch = sampleScratch();
            if (!scratch.ensureCt2Seeds(2u * zetaTaskSeeds.size()) ||
                !scratch.ensureRoundKeys(176u * zetaTaskSeeds.size()) ||
                !scratch.ensureRootZetaRejects(zetaTaskSeeds.size()))
                return false;
            {
                Region regUp(regions().mUploadUs, stream.raw());
                const void* source = zetaTaskSeeds.data();
                if (noGoldZetaGeometry && noGoldRootPinnedSeedsEnabled())
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
                    ring->view(), scratch.mCt2Seeds, scratch.mRoundKeys,
                    scratch.mRootZetaFirstReject, zetaOut,
                    rangesPerPoly, forceFirstReject, stream.raw())
                : launchRootZetaRho4(
                    ring->view(), scratch.mCt2Seeds, scratch.mRoundKeys,
                    scratch.mRootZetaFirstReject, zetaOut,
                    rangesPerPoly, forceFirstReject, stream.raw());
            if (!sampled)
                return false;
        }
        else
        {
            Region regUp(regions().mUploadUs, stream.raw());
            if (!inputs->mImpl->mBuf.upload(*zeta, stream, tauHi)) return false;
        }
        if (!launchNttForward(ring->view(), inputsData, topCols, nullptr, stream.raw())) return false;

        // Two inner products summed in the evaluation domain, publicB terms first,
        // then bStar - the same order and the same mulAddMod chain the host used,
        // and modular addition is associative so splitting them into two launches
        // gives the same words.
        GpuPolyBuffer acc;
        if (!acc.resize(*ring, 1)) return false;
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
                    ring->view(), level->mPublicB.data(), inputsData, dA, dB, tauHi, acc.data(),
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
                    ring->view(), cache->mPublicBStar.data(), inputsData, dA, dB, rw, acc.data(),
                    nullptr, 1, true, false, stream.raw()))
                return false;
        }

        // INTT with the negation folded into the store, matching
        // inverseNtt followed by ringSub(zero, .).
        if (!launchNttInverseFused(
                ring->view(), acc.data(), 1, nullptr, kElemOpNoneHost, nullptr,
                static_cast<u32>(ElemOp::Negate), nullptr, stream.raw()))
            return false;

        regKern.reset();

        // d' is the one value that has to reach the host: it goes on the wire.
        std::vector<RnsPoly> out;
        {
            Region regDown(regions().mDownloadUs, stream.raw());
            if (!acc.download(out, stream, 0, 1) || out.size() != 1) return false;
            pinnedSeeds.mPending = false;
        }
        negDPrime = std::move(out[0]);
        if (negDPrimeDevice && rootDPrimeResidentEnabled())
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
        DeviceBatchPtr* negDPrimeDevice)
    {
        return rootDigestReceiverDeviceImpl(
            state, ctx, leftTreeSession, &zeta, {}, 0u, tauHi, false,
            negDPrime, topInputsNtt, negDPrimeDevice);
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
        DeviceBatchPtr* negDPrimeDevice)
    {
        return rootDigestReceiverDeviceImpl(
            state, ctx, leftTreeSession, nullptr, taskSeeds, rangesPerPoly,
            tauHi, forceFirstReject, negDPrime, topInputsNtt,
            negDPrimeDevice);
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
                return bail("root priority prefetch: retained inputs");

            auto& treeImpl = *tree->mImpl;
            auto& ordinaryStream = threadStream();
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

            struct RestoreCurrentStream
            {
                void* mPrevious;
                ~RestoreCurrentStream() { gpuSetCurrentStream(mPrevious); }
            } restore{ ordinaryStream.raw() };
            gpuSetCurrentStream(workspace->mStream->raw());

            // The device allocation and host backing of these immutable pairs
            // were prepared before send. The first call fills them once on this
            // stream; later Root queries issue no index copies at all.
            {
                Region regUp(regions().mUploadUs, workspace->mStream->raw());
                impl.mWorkQueued = true;
                if (!ensureRootFinalizePriorityIndices(
                        *workspace, *cache, treeImpl, tauHi, leftWidth,
                        topCols))
                    return false;
            }

            auto regKern = std::make_unique<Region>(
                regions().mKernelUs, workspace->mStream->raw());
            const auto& ring = *cache->mRing;

            if (!launchGadgetDecompose(
                    ring.view(), dPrimeDevice->mImpl->mBuf.data(), nullptr, 1u,
                    state.mParams.mShrinkExpand.mGadgetLogBase, 1u, tauHi,
                    true, workspace->mUHi.data(), nullptr,
                    workspace->mStream->raw()) ||
                !launchNttForward(
                    ring.view(), workspace->mUHi.data(), tauHi, nullptr,
                    workspace->mStream->raw()) ||
                !launchInnerProduct(
                    ring.view(), cache->mCtR.data(), workspace->mUHi.data(),
                    workspace->a(workspace->mCtRPair),
                    workspace->b(workspace->mCtRPair), tauHi,
                    workspace->mAcc.data(), nullptr, leftWidth, false, false,
                    workspace->mStream->raw()) ||
                !launchInnerProduct(
                    ring.view(), cache->mTopCt.data(),
                    topInputsNttDev->mImpl->mBuf.data(),
                    workspace->a(workspace->mTopPair),
                    workspace->b(workspace->mTopPair), topCols,
                    workspace->mPhi.data(), nullptr, leftWidth, false, false,
                    workspace->mStream->raw()) ||
                !launchInnerProduct(
                    ring.view(), cache->mLacctLeft.data(),
                    treeImpl.mNodes.data(), workspace->a(workspace->mLeftPair),
                    workspace->b(workspace->mLeftPair),
                    workspace->mLeftPair.mTerms,
                    workspace->mLeftEval.data(), nullptr, leftWidth, false,
                    true, workspace->mStream->raw()) ||
                !launchElementwise(
                    ring.view(), workspace->mPhi.data(), nullptr,
                    workspace->mLeftEval.data(), nullptr,
                    workspace->mPhi.data(), nullptr, leftWidth, ElemOp::Add,
                    workspace->mStream->raw()))
            {
                return false;
            }

            regKern.reset();
            if (!gpuEventRecord(
                    impl.mReadyEvent, workspace->mStream->raw()))
                return false;
            impl.mEventRecorded = true;
            impl.mReady = true;
            return true;
        }
    }

    bool rootFinalizeReceiverPrefetchEnabled()
    {
        return rootFinalizePrefetchEnabledImpl() ||
               rootFinalizePriorityPrefetchEnabledImpl();
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
        const DeviceBatchPtr& dPrimeDevice)
    {
        AutoTimer timer(globalTimingStats.mGpuMiscTimeUs);
        prepared.reset();
        const bool priorityPrefetch =
            rootFinalizePriorityPrefetchEnabledImpl();
        if (!enabled() ||
            (!rootFinalizePrefetchEnabledImpl() && !priorityPrefetch))
            return false;

        // Extend the accepted GoldenSeed priority prefix to the exact
        // NoGoldenSeed shape. The six prefix operations and index construction
        // already use runtime ring dimensions; only their admission was fixed.
        // Leave the rejected equal-priority prefetch GoldenSeed-only.
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
        const bool noGoldGeometry = priorityPrefetch && leftWidth == 8u &&
            rootPriorityNoGoldGeometry(ctx.mParams.mPolyModulusDegree,
                static_cast<u32>(ringModulusCount(ctx)),
                state.mParams.mShrinkExpand.mGadgetLogBase);
        if ((!goldenGeometry && !noGoldGeometry) ||
            tauHi != kProductionTauHi ||
            state.mRootRandomizerWidth != 3u ||
            !validateRingPolyShape(dPrime, ctx.mParams))
        {
            return bail("root prefetch: production geometry");
        }

        auto tree = std::static_pointer_cast<LevelSession>(leftTreeSession);
        if (!tree || !tree->mImpl || !topInputsNttDev || !topInputsNttDev->mImpl)
            return bail("root prefetch: missing device inputs");
        auto& treeImpl = *tree->mImpl;

        auto cache = rootCache(state, ctx);
        auto level = receiverCache(state.mShrinkExpandState);
        if (!cache || !level || !cache->mRing)
            return bail("root prefetch: device caches");
        auto ring = cache->mRing;
        const u32 topCols = cache->mTopCols;
        if (topCols != tauHi + state.mRootRandomizerWidth ||
            topInputsNttDev->count() != topCols ||
            cache->mCtRCols != tauHi ||
            cache->mTopCt.count() != static_cast<std::size_t>(leftWidth) * topCols ||
            cache->mCtR.count() != static_cast<std::size_t>(leftWidth) * tauHi ||
            level->mPublicA.count() < leftWidth)
        {
            return bail("root prefetch: tensor shapes");
        }

        if (priorityPrefetch)
        {
            return prefetchRootFinalizeReceiverPriorityDevice(
                state, cache, level, tree, topInputsNttDev, dPrimeDevice,
                tauHi, leftWidth, topCols, prepared);
        }

        auto& stream = threadStream();
        auto next = std::make_shared<PreparedRootFinalize>();
        auto& impl = *next->mImpl;
        impl.mState = &state;
        impl.mRing = ring;
        impl.mRootCacheOwner = cache;
        impl.mLevelCacheOwner = level;
        impl.mTree = tree;
        impl.mTopInputs = topInputsNttDev;
        impl.mTauHi = tauHi;
        impl.mLeftWidth = leftWidth;
        impl.mTopCols = topCols;
        impl.mProducerStream = stream.raw();
        impl.mReadyEvent = gpuEventCreate();
        prepared = std::move(next);
        if (!impl.mReadyEvent) return false;

        GpuPolyBuffer dPrimeDev;
        if (!dPrimeDev.resize(*ring, 1u)) return false;
        {
            Region regUp(regions().mUploadUs, stream.raw());
            impl.mWorkQueued = true;
            if (!dPrimeDev.upload(dPrime, 0u, stream)) return false;
        }

        auto regKern = std::make_unique<Region>(regions().mKernelUs, stream.raw());

        // ---- lheApplyCt1Trunc response-independent prefix -----------------
        GpuPolyBuffer uHi;
        if (!uHi.resize(*ring, tauHi) ||
            !launchGadgetDecompose(
                ring->view(), dPrimeDev.data(), nullptr, 1,
                state.mParams.mShrinkExpand.mGadgetLogBase, 1, tauHi, true,
                uHi.data(), nullptr, stream.raw()) ||
            !launchNttForward(
                ring->view(), uHi.data(), tauHi, nullptr, stream.raw()) ||
            !impl.mAcc.resize(*ring, leftWidth))
        {
            return false;
        }
        {
            std::vector<u32> aIdx(static_cast<std::size_t>(leftWidth) * tauHi);
            std::vector<u32> bIdx(aIdx.size());
            for (u32 row = 0; row < leftWidth; ++row)
            {
                for (u32 col = 0; col < tauHi; ++col)
                {
                    aIdx[row * tauHi + col] = row * cache->mCtRCols + col;
                    bIdx[row * tauHi + col] = col;
                }
            }
            const u32* dA = stream.uploadIdx(aIdx);
            const u32* dB = stream.uploadIdx(bIdx);
            if (!dA || !dB ||
                !launchInnerProduct(
                    ring->view(), cache->mCtR.data(), uHi.data(), dA, dB,
                    tauHi, impl.mAcc.data(), nullptr, leftWidth, false, false,
                    stream.raw()))
            {
                return false;
            }
        }

        // ---- evalRootTopCtNtt --------------------------------------------
        if (!impl.mPhi.resize(*ring, leftWidth)) return false;
        {
            std::vector<u32> aIdx(static_cast<std::size_t>(leftWidth) * topCols);
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
                    ring->view(), cache->mTopCt.data(),
                    topInputsNttDev->mImpl->mBuf.data(), dA, dB, topCols,
                    impl.mPhi.data(), nullptr, leftWidth, false, false,
                    stream.raw()))
            {
                return false;
            }
        }

        // ---- lencEvalTrunc over the retained left tree, then phi += left ---
        GpuPolyBuffer leftEval;
        if (!leftEval.resize(*ring, leftWidth)) return false;
        {
            const u32 levels = cache->mLevels;
            const u32 width = cache->mWidth;
            const u32 tauLeaf = treeImpl.mTauLeaf;
            const u32 ctTauMax = treeImpl.mMaxTau;
            if (levels == 0u || width < leftWidth)
                return bail("root prefetch: left lacct geometry");

            const u32 terms = 2u * levels * ctTauMax;
            std::vector<u32> aIdx(static_cast<std::size_t>(leftWidth) * terms, 0u);
            std::vector<u32> bIdx(aIdx.size(), 0u);
            for (u32 leaf = 0; leaf < leftWidth; ++leaf)
            {
                u32 parent = 0u;
                u32 t = 0u;
                for (u32 levelIdx = 0; levelIdx < levels; ++levelIdx)
                {
                    const u32 left = (2u * parent) + 1u;
                    const u32 right = left + 1u;
                    const u32 activeTau =
                        (levelIdx == levels - 1u) ? tauLeaf : tauHi;
                    const u32 row = levelIdx * width + leaf;
                    for (u32 c = 0; c < activeTau; ++c)
                    {
                        aIdx[leaf * terms + t] = row * cache->mLacctCols + c;
                        bIdx[leaf * terms + t] =
                            static_cast<u32>(treeImpl.nodeSlot(0, left, c));
                        ++t;
                        aIdx[leaf * terms + t] =
                            row * cache->mLacctCols + ctTauMax + c;
                        bIdx[leaf * terms + t] =
                            static_cast<u32>(treeImpl.nodeSlot(0, right, c));
                        ++t;
                    }
                    const u32 bit =
                        (leaf >> (levels - 1u - levelIdx)) & 1u;
                    parent = bit == 0u ? left : right;
                }
                for (; t < terms; ++t)
                {
                    aIdx[leaf * terms + t] = 0u;
                    bIdx[leaf * terms + t] =
                        static_cast<u32>(treeImpl.zeroNodeSlot());
                }
            }
            const u32* dA = stream.uploadIdx(aIdx);
            const u32* dB = stream.uploadIdx(bIdx);
            if (!dA || !dB ||
                !launchInnerProduct(
                    ring->view(), cache->mLacctLeft.data(),
                    treeImpl.mNodes.data(), dA, dB, terms, leftEval.data(),
                    nullptr, leftWidth, false, true, stream.raw()))
            {
                return false;
            }
        }
        if (!launchElementwise(
                ring->view(), impl.mPhi.data(), nullptr, leftEval.data(), nullptr,
                impl.mPhi.data(), nullptr, leftWidth, ElemOp::Add,
                stream.raw()))
        {
            return false;
        }

        regKern.reset();
        if (!gpuEventRecord(impl.mReadyEvent, stream.raw())) return false;
        impl.mEventRecorded = true;
        impl.mReady = true;
        return true;
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
        const DeviceBatch* dPrimeDevice)
    {
        AutoTimer timer(globalTimingStats.mGpuMiscTimeUs);
        if (!enabled() || tauHi == 0 || leftWidth == 0 || seed.empty()) return bail("root: sizes");

        auto tree = std::static_pointer_cast<LevelSession>(leftTreeSession);
        if (!tree || !tree->mImpl) return bail("root: no device left tree");
        auto& treeImpl = *tree->mImpl;

        auto cache = rootCache(state, ctx);
        if (!cache) return bail("root: offline tensor upload failed");
        auto ring = cache->mRing;
        const u32 rho = ring->rho();

        // publicA is derived from a fixed nonce with the row index as the only
        // varying input, so the level cache's mu-row table has the Root's leftWidth
        // rows as its prefix - the same table lheDec would have built for
        // publicCount = leftWidth.
        auto level = receiverCache(state.mShrinkExpandState);
        if (!level || level->mPublicA.count() < leftWidth) return bail("root: publicA too short");

        const u32 topCols = cache->mTopCols;
        const bool haveTopDev = topInputsNttDev && topInputsNttDev->count() == topCols;
        if (topCols != tauHi + state.mRootRandomizerWidth ||
            (!haveTopDev && topInputsNtt.size() != topCols) ||
            cache->mCtRCols != tauHi ||
            cache->mTopCt.count() != static_cast<std::size_t>(leftWidth) * topCols ||
            cache->mCtR.count() != static_cast<std::size_t>(leftWidth) * tauHi)
        {
            return bail("root: tensor shapes");
        }

        auto& stream = threadStream();
        auto regKern = std::make_unique<Region>(regions().mKernelUs, stream.raw());

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
            const bool buffersMatch = priorityWorkspace
                ? cache->mPriorityWorkspace.get() == priorityWorkspace &&
                      priorityWorkspace->mAcc.count() == leftWidth &&
                      priorityWorkspace->mPhi.count() == leftWidth &&
                      p.mDPrime.get() == dPrimeDevice
                : p.mAcc.count() == leftWidth &&
                      p.mPhi.count() == leftWidth;
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
                // locals. The priority candidate leases cache-owned buffers
                // and returns their ownership on every success/failure exit;
                // the original candidate retains its move-only behavior.
                if (priorityWorkspace)
                {
                    // The coroutine may resume on another host thread and thus
                    // another registered receiver stream. Future releases must
                    // be ordered on the stream that now owns every suffix use.
                    priorityWorkspace->mOwnerStream = stream.raw();
                    acc = std::move(priorityWorkspace->mAcc);
                    phi = std::move(priorityWorkspace->mPhi);
                    returnPriorityBuffers.mWorkspace = priorityWorkspace;
                }
                else
                {
                    acc = std::move(p.mAcc);
                    phi = std::move(p.mPhi);
                }
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
            !havePreparedBase && rootDPrimeResidentEnabled() &&
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
                *ring, (havePreparedBase || haveResidentDPrime) ? 1u : 2u))
            return false;
        {
            Region regUp(regions().mUploadUs, stream.raw());
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
                (!topInOwned.resize(*ring, topCols) || !topInOwned.upload(topInputsNtt, stream)))
                return false;
        }
        const u64* topInData =
            haveTopDev ? topInputsNttDev->mImpl->mBuf.data() : topInOwned.data();

        // ---- lheApplyCt1Trunc: acc[row] = sum_col ctR[row][col] * NTT(u[col]) ----
        GpuPolyBuffer uHi;
        if (!havePreparedBase)
        {
            const u64* dPrimeData = haveResidentDPrime
                ? dPrimeDevice->mImpl->mBuf.data()
                : scalars.data();
            if (!uHi.resize(*ring, tauHi) ||
                !launchGadgetDecompose(
                    ring->view(), dPrimeData, nullptr, 1,
                    state.mParams.mShrinkExpand.mGadgetLogBase, 1, tauHi,
                    true, uHi.data(), nullptr, stream.raw()) ||
                !launchNttForward(
                    ring->view(), uHi.data(), tauHi, nullptr, stream.raw()) ||
                !acc.resize(*ring, leftWidth))
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
                        ring->view(), cache->mCtR.data(), uHi.data(), dA,
                        dB, tauHi, acc.data(), nullptr, leftWidth, false,
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
            if (!launchNttForward(ring->view(), scalars.data(), 1, dSk, stream.raw())) return false;
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
                    ring->view(), level->mPublicA.data(), scalars.data(), dA, dB, 1, acc.data(), nullptr,
                    leftWidth, false, false, stream.raw(), true))
                return false;
        }

        // ---- evalRootTopCtNtt: phi[row] = sum_col topCt[row][col] * topIn[col] ----
        if (!havePreparedBase)
        {
            if (!phi.resize(*ring, leftWidth)) return false;
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
                        ring->view(), cache->mTopCt.data(), topInData, dA,
                        dB, topCols, phi.data(), nullptr, leftWidth, false,
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
            if (!leftEval.resize(*ring, leftWidth)) return false;
            {
                const u32 levels = cache->mLevels;
                const u32 width = cache->mWidth;
                const u32 tauLeaf = treeImpl.mTauLeaf;
                const u32 ctTauMax = treeImpl.mMaxTau;
                if (levels == 0 || width < leftWidth)
                    return bail("root: left lacct geometry");

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
                        ring->view(), cache->mLacctLeft.data(),
                        treeImpl.mNodes.data(), dA, dB, terms,
                        leftEval.data(), nullptr, leftWidth, false, true,
                        stream.raw()))
                {
                    return false;
                }
            }

            if (!launchElementwise(
                    ring->view(), phi.data(), nullptr, leftEval.data(), nullptr,
                    phi.data(), nullptr, leftWidth, ElemOp::Add,
                    stream.raw()))
            {
                return false;
            }
        }

        // ---- the row loop: tbm = acc - (top + left) -----------------------
        if (!launchElementwise(
                ring->view(), acc.data(), nullptr, phi.data(), nullptr, acc.data(), nullptr, leftWidth,
                ElemOp::Sub, stream.raw()))
            return false;

        // ---- buildHashedCt2, then the inverse transform with the add folded in ----
        GpuPolyBuffer ctK;
        if (!sampleCt2Batch(
                *ring, *level, state.mParams.mShrinkExpand.mRing, 1, leftWidth, seed, sid, 0,
                dPrimeHash, ctK, stream))
            return false;
        if (!launchNttInverseFused(
                ring->view(), acc.data(), leftWidth, nullptr, kElemOpNoneHost, nullptr,
                static_cast<u32>(ElemOp::Add), ctK.data(), stream.raw()))
            return false;

        // ---- denoise comb + aggregate ----
        if (leftWidth % rho != 0) return bail("root: leftWidth not a multiple of rho");
        const std::size_t denoised = leftWidth / rho;
        if (denoised % tauHi != 0) return bail("root: denoised count not a multiple of tau");
        const std::size_t aggCount = denoised / tauHi;
        if (!ring->denoiseReady()) return bail("root: denoise tables unavailable");

        GpuPolyBuffer mid;
        if (!mid.resize(*ring, denoised)) return false;
        if (!denoiseComb(*ring, acc.data(), mid.data(), static_cast<u32>(denoised), stream))
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
            if (!result->mImpl->mBuf.resize(*ring, aggCount)) return false;
            if (!launchAggregate(
                    ring->view(), mid.data(), tauHi, result->mImpl->mBuf.data(),
                    static_cast<u32>(aggCount), stream.raw()))
                return false;
        }

        regKern.reset();
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
            if (!out.resize(ring, total)) return false;

            const std::size_t streamWords = ring.polyWords() + kSampleSlackWords;
            if (!scratch.ensureSeeds(total * 8) ||
                !scratch.ensureRoundKeys(total * 176)) return false;
            const bool fusedSamplerNeedsEpoch = gpuFusedSamplerNeedsRejectEpoch(
                ring.n(), static_cast<u32>(streamWords), static_cast<u32>(total));
            const bool needStream = !gpuFusedSamplerActive(
                ring.n(), static_cast<u32>(streamWords), static_cast<u32>(total));
            if (needStream && !scratch.ensureStream(total * streamWords))
                return false;
            u32* rejectEpochs = nullptr;
            u32 rejectEpoch = 0;
            if ((fusedSamplerNeedsEpoch || (needStream && gpuRejectReduceFusionActive())) &&
                !scratch.nextRejectEpoch(total, stream.raw(), rejectEpochs, rejectEpoch))
                return false;

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

            return launchSampleUniformPolyBlake2xb(
                ring.view(), scratch.mSeeds, scratch.mStream, static_cast<u32>(streamWords),
                cache.mMaxMultiple, out.data(), nullptr, static_cast<u32>(total), rejectEpochs,
                rejectEpoch, true, stream.raw());
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
                maskDigestHash, out, stream, sampleScratch());
        }
    }

    bool topSenderCt2PrefetchEnabled()
    {
        return topSenderCt2PrefetchEnabledImpl();
    }

    u32 topSenderCt2PrefetchLevels(u32 adaptiveDefault)
    {
        return topSenderCt2PrefetchLevelsImpl(adaptiveDefault);
    }

    bool prefetchSenderCt2(
        const ShrinkExpandSenderState& state,
        std::span<const u8> seed,
        u64 sid,
        u64 instanceBase,
        block maskDigestHash,
        u32 chunkCount,
        PreparedSenderCt2Ptr& prepared)
    {
        AutoTimer timer(globalTimingStats.mGpuSenderTimeUs);
        prepared.reset();
        if (!enabled() || !topSenderCt2PrefetchEnabledImpl() || seed.size() != 16u ||
            chunkCount == 0u)
        {
            return false;
        }

        auto cache = senderCache(state);
        if (!cache || !cache->mRing) return false;
        auto ring = cache->mRing;
        const u32 mu = state.mParams.mMu;
        if (mu == 0u || cache->mPublicA.count() != mu) return false;

        // threadStream() both obtains the main stream and publishes it to the
        // caching allocator. Restore that publication on every exit; all
        // allocations made while the prefetch is queued must instead be tagged
        // with the secondary stream.
        auto& mainStream = threadStream();
        auto& sampleStream = threadSampleStream();
        struct RestoreCurrentStream
        {
            void* mStream;
            ~RestoreCurrentStream() { gpuSetCurrentStream(mStream); }
        } restore{ mainStream.raw() };
        gpuSetCurrentStream(sampleStream.raw());

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
        impl.mProducerStream = sampleStream.raw();
        impl.mReadyEvent = gpuEventCreate();
        if (!impl.mReadyEvent) return false;

        Region regKern(regions().mKernelUs, sampleStream.raw());
        if (!sampleCt2BatchWithScratch(
                *ring, *cache, state.mParams.mRing, chunkCount, mu, seed, sid,
                instanceBase, maskDigestHash, impl.mCt2, sampleStream,
                senderPrefetchSampleScratch()) ||
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
            u64 streamBytes = 0u;
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

                if (polyWords > std::numeric_limits<u32>::max() - kSampleSlackWords)
                    return false;
                const u32 wordsPerStream =
                    static_cast<u32>(polyWords) + kSampleSlackWords;
                const u32 rowCount = static_cast<u32>(rows);
                const bool fused = gpuFusedSamplerActive(
                    ringParams.mPolyModulusDegree, wordsPerStream, rowCount);
                const bool needStream = !fused;
                const bool needRejectEpoch =
                    gpuFusedSamplerNeedsRejectEpoch(
                        ringParams.mPolyModulusDegree, wordsPerStream, rowCount) ||
                    (needStream && gpuRejectReduceFusionActive());
                if (needStream)
                {
                    if (!checkedMul(rows, wordsPerStream, request) ||
                        !checkedMul(request, sizeof(u64), request))
                        return false;
                    streamBytes = std::max(streamBytes, request);
                }
                if (needRejectEpoch)
                {
                    if (!checkedMul(rows, sizeof(u32), request)) return false;
                    rejectBytes = std::max(rejectBytes, request);
                }
            }

            // The 16-byte online seed path always creates the fixed nine-word
            // prefix. Every other scratch field grows to the maximum required by
            // the FIFO sequence and remains one live allocation.
            return addTrackedAllocation(9u * sizeof(u64), trackedBytes) &&
                   addTrackedAllocation(seedBytes, trackedBytes) &&
                   addTrackedAllocation(streamBytes, trackedBytes) &&
                   addTrackedAllocation(ct2SeedBytes, trackedBytes) &&
                   addTrackedAllocation(roundKeyBytes, trackedBytes) &&
                   addTrackedAllocation(rejectBytes, trackedBytes);
        }

    }

    u32 receiverCt2PrefetchLevels(
        u64 totalLabelCount,
        std::span<const ShrinkExpandReceiverState* const> states,
        std::span<const u32> chunkCounts)
    {
        const auto mode = receiverCt2PrefetchMode();
        if (mode == ReceiverCt2PrefetchMode::Disabled) return 0u;

        const auto& levelOverride = receiverCt2LevelOverride();
        if (mode == ReceiverCt2PrefetchMode::Forced)
        {
            return levelOverride.mPresent
                ? levelOverride.mLevels
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
        return levelOverride.mPresent
            ? levelOverride.mLevels
            : kReceiverPrefetchAdaptiveLevels;
    }

    bool prefetchReceiverCt2(
        const ShrinkExpandReceiverState& state,
        std::span<const u8> seed,
        u64 sid,
        u64 instanceBase,
        block maskDigestHash,
        u32 chunkCount,
        PreparedReceiverCt2Ptr& prepared)
    {
        AutoTimer timer(globalTimingStats.mGpuExpandTimeUs);
        prepared.reset();
        if (!enabled() || receiverCt2PrefetchMode() == ReceiverCt2PrefetchMode::Disabled ||
            seed.size() != 16u ||
            chunkCount == 0u)
        {
            return false;
        }

        auto cache = receiverCache(state);
        if (!cache || !cache->mRing) return false;
        auto ring = cache->mRing;
        const u32 mu = state.mParams.mMu;
        if (mu == 0u || cache->mPublicA.count() != mu) return false;

        // Allocation ownership must be tagged to the producer stream. As with
        // sender prefetch, restore the role's main stream on every exit so later
        // allocations do not silently inherit the secondary stream.
        auto& mainStream = threadStream();
        auto& sampleStream = threadSampleStream();
        struct RestoreCurrentStream
        {
            void* mStream;
            ~RestoreCurrentStream() { gpuSetCurrentStream(mStream); }
        } restore{ mainStream.raw() };
        gpuSetCurrentStream(sampleStream.raw());

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
        impl.mProducerStream = sampleStream.raw();
        impl.mReadyEvent = gpuEventCreate();
        if (!impl.mReadyEvent) return false;

        Region regKern(regions().mKernelUs, sampleStream.raw());
        if (!sampleCt2BatchWithScratch(
                *ring, *cache, state.mParams.mRing, chunkCount, mu, seed, sid,
                instanceBase, maskDigestHash, impl.mCt2, sampleStream,
                receiverPrefetchSampleScratch()) ||
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
        PreparedReceiverCt2* preparedCt2)
    {
        AutoTimer timer(globalTimingStats.mGpuExpandTimeUs);
        const std::span<const RnsPoly> skX = skXHost;
        if (!enabled() || !session.valid()) return false;
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
            if (debugEnabled())
            {
                std::fprintf(
                    stderr, "[logvole-gpu] expand: skXCount=%u chunkCount=%u mu=%u totalOut=%u\n",
                    skXCount, chunkCount, mu, totalOut);
            }
            return bail("expand: skX count mismatch");
        }
        if (cache->mCt1Cols != tauHi) return bail("expand: ct1 cols mismatch");

        auto& stream = threadStream();
        stream.reset();

        auto regKern = std::make_unique<Region>(regions().mKernelUs, stream.raw());

        // ct2 for every chunk.
        //
        // This is the one part of the expand that depends on nothing else here and
        // is not consumed until the fused inverse transform at the end. It is also
        // the opposite kind of kernel from everything in between: one block per
        // polynomial walking a Blake2xb stream, so a level with few chunks leaves
        // most of the device idle (22 GB/s at 8 polynomials against 305 at 256),
        // while the gadget/transform/inner-product chain around it is bandwidth
        // bound. Overlapping the two is therefore the textbook case, and it needs no
        // change to what ct2 *is*: same seed, same session id, same root digest,
        // same instance index, same per-row derivation.
        //
        // A first attempt measured neutral and was reverted, with the cause
        // identified as the caching allocator: reusing a block another stream last
        // used costs a device-side dependency on that stream, so the sampler's
        // buffers kept re-joining the compute stream. DeviceAllocator::alloc now
        // prefers a fresh pool allocation over a foreign block, which removes that
        // edge, so the overlap is enabled here. LV_GPU_CT2_OVERLAP=0 disables it.
        // Re-measured with both known obstacles removed, and it is still not worth
        // it: **+0.5%** (40.12 against 39.93 M VOLE/s per party at 2^22, three runs
        // each), 93.7 against 93.1 at 2^24.
        //
        // Two things had to be fixed to measure it honestly. The caching allocator
        // handed the sampler blocks the compute stream had last used, which costs a
        // device-side dependency and silently serialised the two streams; and the
        // overlap needs a *write-after-read* edge as well, because the ct2 buffer is
        // recycled memory the previous level's transform may still be reading, and
        // cudaMallocAsync memory is only valid on a second stream behind a
        // dependency. Without that edge the second half of the output was wrong at
        // 2^22 while 2^20 passed.
        //
        // With the edge in place the sampler cannot start until the compute stream
        // has drained its earlier reads, and a level's own chain is a dependency
        // chain, so there is little independent work left to hide the sampler
        // behind. That is the reason the overlap does not pay, not the allocator.
        //
        // The opt-in cross-recursion experiment avoids that edge: its output is a
        // separately owned allocation queued after Root and retained until this
        // exact ancestor consumes it. Treat every mismatch or failed event wait as
        // a soft miss and run this established synchronous path unchanged.
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
        if (reuseHiDigitsEnabled() && impl.mHiDigits &&
            impl.mHiDigits->mImpl->mBuf.count() == uDigitCount)
        {
            // Every child operation that reads dHat has already been enqueued on
            // this stream before its parent expand. The compact leaf-diagonal
            // path may already have filled this exact buffer in NTT form.
            uDigits = impl.mHiDigits->mImpl->mBuf.data();
            uDigitsNtt = impl.mHiDigits->mImpl->mRecursiveHiNtt;
        }
        else
        {
            if (!uDigitsOwned.resize(*ring, uDigitCount)) return false;
            uDigits = uDigitsOwned.data();
            if (!launchGadgetDecompose(
                    ring->view(), impl.mDigest.data(), nullptr, chunkCount,
                    state.mParams.mGadgetLogBase, 1, tauHi, true, uDigits, nullptr,
                    stream.raw()))
                return false;
        }
        if (!uDigitsNtt && !launchNttForward(
                ring->view(), uDigits, static_cast<u32>(uDigitCount), nullptr, stream.raw()))
            return false;

        const std::size_t rowsTotal = static_cast<std::size_t>(chunkCount) * mu;
        if (!impl.mAcc.resize(*ring, rowsTotal)) return false;

        const u32 treeTerms = 2u * impl.mLevels * impl.mMaxTau;
        const bool combineExpandAccumulator =
            !gpuFusedIpActive() && tauHi == 1u && rowsTotal <= 65535u &&
            canLaunchExpandAccumulatorTau1(
                ring->view(), mu, treeTerms,
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
            skXNtt = skXDev->mImpl->mBuf.data();
        }
        else
        {
            if (!skXNttOwned.resize(*ring, chunkCount) || !skXNttOwned.upload(skX, stream))
                return false;
            skXNtt = skXNttOwned.data();
        }
        if (!launchNttForward(ring->view(), skXNtt, chunkCount, nullptr, stream.raw()))
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
            const u64 geo = idxKey(0xC711u, chunkCount, mu, tauHi, cache->mCt1Cols);
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
                    ring->view(), cache->mCt1.data(), uDigits, dA, dB, tauHi,
                    impl.mAcc.data(), nullptr, static_cast<u32>(rowsTotal), false, false,
                    stream.raw()))
            {
                return false;
            }
        }

        // ---- lheDec: acc[row] -= publicA[row] * NTT(skX[chunk]) ----
        if (!combineExpandAccumulator)
        {
            const std::size_t idxCount = rowsTotal;
            const u64 geo = idxKey(0xA5C1u, chunkCount, mu);
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
                    ring->view(), cache->mPublicA.data(), skXNtt, dA, dB, 1,
                    impl.mAcc.data(), nullptr, static_cast<u32>(rowsTotal), false, false,
                    stream.raw(), true))
            {
                return false;
            }
        }

        bool inverseDone = false;

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
                const u64 geo = idxKey(
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
                    // The inverse-fused peer is the accepted mu=8/six-term symbol.
                    // Wider alpha tuples use the high-occupancy pointwise candidate
                    // below and retain the established inverse transform.
                    if (treeTerms == 6u &&
                        !tryLaunchNttInverseExpandAccumulatorTau1Add(
                            ring->view(), impl.mAcc.data(), cache->mCt1.data(),
                            uDigits, cache->mPublicA.data(), skXNtt,
                            cache->mLacct.data(), impl.mNodes.data(), dA, dB, mu,
                            static_cast<u32>(rowsTotal), impl.mCt2.data(),
                            stream.raw(), inverseDone))
                    {
                        return false;
                    }
                    if (!inverseDone && !launchExpandAccumulatorTau1(
                            ring->view(), cache->mCt1.data(), uDigits, cache->mPublicA.data(),
                            skXNtt, cache->mLacct.data(), impl.mNodes.data(), dA, dB, mu,
                            treeTerms, impl.mAcc.data(), static_cast<u32>(rowsTotal),
                            stream.raw(), state.mParams.mAlpha == 2u))
                    {
                        return false;
                    }
                }
                else if (gpuFusedIpActive())
                {
                    fusedIp.mA = cache->mLacct.data();
                    fusedIp.mB = impl.mNodes.data();
                    fusedIp.mAIdx = dA;
                    fusedIp.mBIdx = dB;
                    fusedIp.mTerms = terms;
                    fusedIp.mMode = NttFusedIp::Accumulate;
                }
                else
                {
                    if (!launchInnerProduct(
                            ring->view(), cache->mLacct.data(), impl.mNodes.data(), dA, dB, terms,
                            impl.mAcc.data(), nullptr, static_cast<u32>(rowsTotal), true, false,
                            stream.raw()))
                    {
                        return false;
                    }
                }
        }

        // ... then INTT and + ct2, both folded into the transform's store.
        if (!inverseDone && !launchNttInverseFused(
                ring->view(), impl.mAcc.data(), static_cast<u32>(rowsTotal), nullptr, kElemOpNoneHost,
                nullptr, static_cast<u32>(ElemOp::Add), impl.mCt2.data(), stream.raw(), fusedIp,
                state.mParams.mAlpha == 2u))
            return false;

        regKern.reset();

        if (!wantHostOutput)
        {
            // outPerChunk == mu here, so the accumulator already holds exactly
            // the level's output in order and can be handed over untouched.
            if (outPerChunk != mu) return bail("expand: outPerChunk != mu");
            auto out = std::make_shared<DeviceBatch>();
            out->mImpl->mRing = ring;
            out->mImpl->mBuf = std::move(impl.mAcc);
            tbmDev = std::move(out);
            (void)rho;
            return true;   // device resident, same stream: no drain needed
        }

        // ---- download the used outputs ----
        Region regDown(regions().mDownloadUs, stream.raw());
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
        PreparedReceiverCt2* preparedCt2)
    {
        DeviceBatchPtr unused;
        return expandReceiverChunksImpl(
            state, session, skX, nullptr, seed, sid, instanceBase, maskDigestHash, outPerChunk,
            totalOut, true, tbm, unused, preparedCt2);
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
        PreparedReceiverCt2* preparedCt2)
    {
        std::vector<RnsPoly> unused;
        return expandReceiverChunksImpl(
            state, session, std::span<const RnsPoly>(), &skX, seed, sid, instanceBase,
            maskDigestHash, outPerChunk, totalOut, false, unused, tbm, preparedCt2);
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
        PreparedSenderCt2* preparedCt2)
    {
        AutoTimer timer(globalTimingStats.mGpuSenderTimeUs);
        if (!enabled()) return false;
        const bool haveDev = tbkPrimeDev != nullptr && !tbkPrimeDev->empty();
        if (haveDev == !tbkPrimeHost.empty()) return false;   // exactly one source

        auto cache = senderCache(state);
        if (!cache) return false;
        auto ring = cache->mRing;
        const u32 mu = state.mParams.mMu;
        if (mu == 0 || cache->mPublicA.count() != mu) return false;

        const u32 chunkCount =
            haveDev ? static_cast<u32>(tbkPrimeDev->count()) : static_cast<u32>(tbkPrimeHost.size());
        if (chunkCount == 0) return false;
        const std::size_t rowsTotal = static_cast<std::size_t>(chunkCount) * mu;

        auto& stream = threadStream();

        auto regKern = std::make_unique<Region>(regions().mKernelUs, stream.raw());

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
        if (haveDev && senderInplaceKeyEnabled())
        {
            skNtt = tbkPrimeDev->mImpl->mBuf.data();
        }
        else
        {
            if (!skNttOwned.resize(*ring, chunkCount)) return false;
            skNtt = skNttOwned.data();
            if (haveDev && !gpuMemcpyD2D(
                    skNtt, tbkPrimeDev->mImpl->mBuf.data(),
                    static_cast<std::size_t>(chunkCount) * ring->polyBytes(), stream.raw()))
                return false;
            if (!haveDev && !skNttOwned.upload(tbkPrimeHost, stream)) return false;
        }
        if (!launchNttForward(ring->view(), skNtt, chunkCount, nullptr, stream.raw()))
            return false;

        GpuPolyBuffer product;
        if (!product.resize(*ring, rowsTotal)) return false;

        bool inverseDone = false;
        if (!gpuFusedIpActive() && (mu == 8u || mu == 16u))
        {
            if (!tryLaunchNttInverseOuterMuReverseSub(
                    ring->view(), product.data(), cache->mPublicA.data(), skNtt,
                    mu, static_cast<u32>(rowsTotal), ct2.data(), stream.raw(), inverseDone))
                return false;
        }
        else if (!gpuFusedIpActive() && mu == 4u)
        {
            if (!tryLaunchNttInverseOuterMu4ReverseSub(
                    ring->view(), product.data(), cache->mPublicA.data(), skNtt,
                    static_cast<u32>(rowsTotal), ct2.data(), stream.raw(), inverseDone))
                return false;
        }

        if (!inverseDone)
        {
            bool productDone = false;
            if (mu == 8u || mu == 16u)
            {
                if (!tryLaunchInnerProductOuterMuRowReuse(
                        ring->view(), cache->mPublicA.data(), skNtt,
                        product.data(), mu, chunkCount, stream.raw(), productDone))
                {
                    return false;
                }
            }
            else if (mu == 32u || mu == 64u || mu == 128u)
            {
                if (!tryLaunchInnerProductOuterWideMuRowReuse(
                        ring->view(), cache->mPublicA.data(), skNtt,
                        product.data(), mu, chunkCount, stream.raw(),
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
                        ring->view(), cache->mPublicA.data(), skNtt, dA, dB, 1,
                        product.data(), nullptr, static_cast<u32>(rowsTotal), false,
                        false, stream.raw()))
                    return false;
            }
            if (!launchNttInverseFused(
                    ring->view(), product.data(), static_cast<u32>(rowsTotal), nullptr,
                    kElemOpNoneHost, nullptr, static_cast<u32>(ElemOp::ReverseSub), ct2.data(),
                    stream.raw(), NttFusedIp{}, state.mParams.mAlpha == 2u))
                return false;
        }

        regKern.reset();

        // The result stays on the device; the caller decides whether it is ever
        // needed on the host.
        auto out = std::make_shared<DeviceBatch>();
        out->mImpl->mRing = ring;
        out->mImpl->mBuf = std::move(product);
        tbkAll = std::move(out);
        return true;   // device resident, same stream: no drain needed
    }

    // ---- sender Root ------------------------------------------------------

    bool rootDigestHashEnabled()
    {
        // Exact sequential BLAKE2b is much slower on GPU for these messages.
        // Expose the requested CPU-offload mode without silently making the
        // throughput default slower. No tree hashing or transcript change.
        static const bool on = [] {
            const char* v = std::getenv("LV_GPU_ROOT_DIGEST_HASH");
            return v && v[0] == '1';
        }();
        return on && enabled();
    }

    namespace
    {
        bool hashRootWordsDevice(const u64* words, u32 count, block& out, GpuStream& stream)
        {
            auto* result = static_cast<u64*>(gpuMalloc(sizeof(block)));
            if (!result) return false;
            u8* pinned = stream.staging(sizeof(block));
            const bool queued = pinned && launchRootDigestHash(words, count, result, stream.raw()) &&
                gpuMemcpyD2H(pinned, result, sizeof(block), stream.raw());
            const bool complete = stream.sync();
            if (queued && complete) std::memcpy(&out, pinned, sizeof(block));
            gpuFree(result);
            return queued && complete;
        }
    }

    bool hashRootDigestDevice(const DeviceBatch& digest, block& out)
    {
        if (!rootDigestHashEnabled() || !digest.mImpl ||
            digest.mImpl->mLogicalCount || digest.mImpl->mBuf.count() != 1u ||
            !digest.mImpl->mRing || digest.mImpl->mRing->polyWords() >
                std::numeric_limits<u32>::max()) return false;
        return hashRootWordsDevice(digest.mImpl->mBuf.data(),
            static_cast<u32>(digest.mImpl->mRing->polyWords()), out, threadStream());
    }

    bool rootKPrimeSamplingEnabled()
    {
#ifdef SEAL_USE_AES_CTR_DRBG
        return false; // The device sampler reproduces SEAL's Blake2xb stream.
#else
        static const bool on = [] {
            const char* v = std::getenv("LV_GPU_ROOT_KPRIME_SAMPLE");
            if (v && v[0] == '0') return false;
            return seal::UniformRandomGeneratorFactory::DefaultFactory()->create(
                seal::prng_seed_type{})->info().type() == seal::prng_type::blake2xb;
        }();
        return on && enabled();
#endif
    }

    bool sampleRootKPrimeDevice(const RingNttContext& ctx,
        const std::array<u64, 8>& seed, DeviceBatchPtr& out)
    {
        out.reset();
        if (!rootKPrimeSamplingEnabled()) return false;
        // Validation hook: Core must replay its already-consumed seed if the
        // device path declines. Never draw substitute parent randomness.
        const char* decline = std::getenv("LV_GPU_ROOT_KPRIME_FORCE_DECLINE");
        if (decline && decline[0] == '1') return false;
        auto ring = GpuRing::get(ctx);
        if (!ring || !ring->sampleMaxMultiple() ||
            !((ring->n() == 16384u && ring->rho() == 8u) ||
              (ring->n() == 8192u && ring->rho() == 4u))) return false;
        auto& stream = threadStream();
        auto& scratch = sampleScratch();
        auto sampled = std::make_shared<DeviceBatch>();
        sampled->mImpl->mRing = ring;
        const u32 streamWords = static_cast<u32>(ring->polyWords() + kSampleSlackWords);
        const bool needStream = !gpuFusedSamplerActive(ring->n(), streamWords, 1u);
        const bool needEpoch = gpuFusedSamplerNeedsRejectEpoch(ring->n(), streamWords, 1u) ||
            (needStream && gpuRejectReduceFusionActive());
        if (!sampled->mImpl->mBuf.resize(*ring, 1u) || !scratch.ensureSeeds(8u) ||
            (needStream && !scratch.ensureStream(streamWords))) return false;
        u32* rejectEpochs = nullptr;
        u32 rejectEpoch = 0u;
        if (needEpoch && !scratch.nextRejectEpoch(1u, stream.raw(), rejectEpochs, rejectEpoch))
            return false;
        const bool queued =
            gpuMemcpyH2D(scratch.mSeeds, seed.data(), sizeof(seed), stream.raw()) &&
            launchSampleUniformPolyBlake2xb(ring->view(), scratch.mSeeds, scratch.mStream,
                streamWords, ring->sampleMaxMultiple(), sampled->mImpl->mBuf.data(),
                nullptr, 1u, rejectEpochs, rejectEpoch, true, stream.raw());
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
        const RnsPoly& kPrime,
        DeviceBatchPtr& preparedKPrime)
    {
        AutoTimer timer(globalTimingStats.mGpuSenderTimeUs);
        preparedKPrime.reset();
        const bool prepareSk = rootSkNttResidentEnabled();
        // A device-generated key intentionally has no host polynomial to
        // preupload. It must not suppress preparation of the independent,
        // immutable SK cache when the legacy preupload switch is also enabled.
        const bool prepareKPrime = rootKPrimePreuploadEnabled() && !kPrime.mCoeffs.empty();
        if (!enabled() || (!prepareSk && !prepareKPrime)) return false;

        RingNttContext ctx{};
        if (!makeRingNttContext(state.mParams.mShrinkExpand.mRing, ctx))
            return bail("root operands: context");
        auto ring = GpuRing::get(ctx);
        if (!ring ||
            (prepareKPrime && kPrime.mCoeffs.size() != ring->polyWords()))
            return bail("root operands: ring");

        u32 tauHi = 0u;
        const auto secretCoeffs = std::static_pointer_cast<DeviceBatch>(
            state.mRootSkRRtDevice);
        const bool secretDevice = static_cast<bool>(secretCoeffs);
        if (prepareSk)
        {
            const u32 fullTau = state.mParams.mShrinkExpand.mTau;
            if (fullTau < 2u)
                return bail("root operands: shape");
            tauHi = fullTau - 1u;
            if (secretDevice ?
                    (!state.mRootSkRRt.empty() || !state.mLazyRootSkRRt ||
                     state.mLazyRootSkRRt->count() != tauHi ||
                     !state.mLazyRootSkRRt->matches(ctx.mParams) ||
                     !rootSecretUniformBatchMatches(ctx, *secretCoeffs,
                         tauHi, state.mRootSkRRtOwnerRunId))
                    : state.mRootSkRRt.size() != tauHi)
                return bail("root operands: shape");
            for (const auto& sk : state.mRootSkRRt)
            {
                if (sk.mCoeffs.size() != ring->polyWords())
                    return bail("root operands: sk shape");
            }
        }

        auto& stream = threadStream();
        if (prepareSk)
        {
            auto skNtt = std::static_pointer_cast<DeviceBatch>(
                state.mRootSkRRtNttDevice);
            const bool cachedSkValid =
                skNtt && skNtt->mImpl && !skNtt->mImpl->mLogicalCount &&
                (secretDevice ?
                    rootSecretUniformBatchMatches(ctx, *skNtt,
                        tauHi, state.mRootSkRRtOwnerRunId, true)
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
                    skNtt->mImpl->mRootSecretDevice = currentDeviceOrdinal();
                }
                if (!skNtt->mImpl->mBuf.resize(*ring, tauHi))
                    return bail("root operands: sk alloc");
                {
                    Region regUp(regions().mUploadUs, stream.raw());
                    if (!(secretDevice
                            ? gpuMemcpyD2D(skNtt->mImpl->mBuf.data(),
                                secretCoeffs->mImpl->mBuf.data(),
                                tauHi * ring->polyWords() * sizeof(u64),
                                stream.raw())
                            : skNtt->mImpl->mBuf.upload(
                                std::span<const RnsPoly>(
                                    state.mRootSkRRt.data(), state.mRootSkRRt.size()),
                                stream)))
                        return bail("root operands: sk upload");
                }
                {
                    Region regKern(regions().mKernelUs, stream.raw());
                    if (!launchNttForward(
                            ring->view(), skNtt->mImpl->mBuf.data(), tauHi,
                            nullptr, stream.raw()) ||
                        !stream.sync())
                        return bail("root operands: sk ntt");
                }
                // Publish only after the immutable NTT buffer is complete. Future
                // queries and a coroutine resuming on another thread may read it
                // without an event.
                state.mRootSkRRtNttDevice = skNtt;
            }
        }

        if (prepareKPrime)
        {
            auto kPrimeDevice = std::make_shared<DeviceBatch>();
            kPrimeDevice->mImpl->mRing = ring;
            if (!kPrimeDevice->mImpl->mBuf.resize(*ring, 1u))
                return bail("root operands: kPrime alloc");
            {
                Region regUp(regions().mUploadUs, stream.raw());
                // The span upload drains its staging buffer. That is intentional:
                // the owner can safely cross recvFrame without retaining the host
                // source or a producer-stream event.
                if (!kPrimeDevice->mImpl->mBuf.upload(
                        std::span<const RnsPoly>(&kPrime, 1u), stream))
                    return bail("root operands: kPrime upload");
            }
            preparedKPrime = std::move(kPrimeDevice);
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
        RnsPoly& out,
        DeviceBatchPtr* residentKPrime,
        const DeviceBatchPtr& preparedSkNtt,
        const DeviceBatchPtr& preparedKPrime,
        block* digestHash,
        bool recoverNonInteractiveMask,
        const DeviceBatchPtr& rootSecretCoeffs,
        u64 rootSecretOwnerRunId)
    {
        AutoTimer timer(globalTimingStats.mGpuSenderTimeUs);
        if (residentKPrime) residentKPrime->reset();
        const char* forceDecline = std::getenv("LV_GPU_ROOT_SKX_FORCE_DECLINE");
        if (!enabled() || tauHi == 0 ||
            (forceDecline && forceDecline[0] == '1') ||
            (rootSecretCoeffs ?
                (!sk1.empty() || !rootSecretUniformBatchMatches(ctx,
                    *rootSecretCoeffs, tauHi, rootSecretOwnerRunId))
                : sk1.size() != tauHi)) return bail("skx: shape");
        auto ring = GpuRing::get(ctx);
        if (!ring) return bail("skx: ring");
        const bool havePreparedKPrime =
            preparedKPrime && preparedKPrime->mImpl &&
            (rootKPrimePreuploadEnabled() || preparedKPrime->mImpl->mFreshRootKPrime) &&
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
            return bail("skx: host input shape");

        auto& stream = threadStream();
        Region regKern(regions().mKernelUs, stream.raw());

        const bool havePreparedSk =
            rootSkNttResidentEnabled() &&
            preparedSkNtt && preparedSkNtt->mImpl &&
            !preparedSkNtt->mImpl->mLogicalCount &&
            (rootSecretCoeffs ?
                rootSecretUniformBatchMatches(ctx, *preparedSkNtt,
                    tauHi, rootSecretOwnerRunId, true)
                : preparedSkNtt->mImpl->mRing == ring &&
                  preparedSkNtt->mImpl->mBuf.count() == tauHi);
        GpuPolyBuffer sk;
        // The established path packs digest and k' together. A preuploaded or
        // explicitly retained k' has its own one-poly owner, so dAcc then holds
        // only the digest and can die without taking retained k' with it.
        GpuPolyBuffer dAcc;
        GpuPolyBuffer uHi;
        GpuPolyBuffer term;
        DeviceBatchPtr retainedKPrime;
        if (!recoverNonInteractiveMask && !havePreparedKPrime && residentKPrime &&
            rootKPrimeResidentEnabled())
        {
            retainedKPrime = std::make_shared<DeviceBatch>();
            retainedKPrime->mImpl->mRing = ring;
            if (!retainedKPrime->mImpl->mBuf.resize(*ring, 1))
            {
                // Residency is an optimization only. Allocation pressure must
                // not turn a successful Root response into a protocol failure.
                retainedKPrime.reset();
            }
        }
        const bool haveRetainedKPrime = static_cast<bool>(retainedKPrime);
        const std::size_t dAccCount =
            (havePreparedKPrime || haveRetainedKPrime) ? 1u : 2u;
        if ((!havePreparedSk && !sk.resize(*ring, tauHi)) ||
            !dAcc.resize(*ring, dAccCount) ||
            !uHi.resize(*ring, tauHi) ||
            !term.resize(*ring, 1))
            return bail("skx: alloc");
        const bool inputsUploaded = [&] {
            const bool direct = rootDirectUploadEnabled();
            if (!havePreparedSk)
            {
                if (rootSecretCoeffs)
                {
                    if (!gpuMemcpyD2D(sk.data(),
                            rootSecretCoeffs->mImpl->mBuf.data(),
                            tauHi * ring->polyWords() * sizeof(u64),
                            stream.raw())) return false;
                }
                else if (!direct)
                {
                    if (!sk.upload(
                            std::span<const RnsPoly>(sk1.data(), sk1.size()),
                            stream))
                        return false;
                }
                else
                {
                    for (u32 i = 0; i < tauHi; ++i)
                    {
                        if (!sk.upload(sk1[i], i, stream)) return false;
                    }
                }
            }

            const bool digestUploaded = direct
                ? dAcc.upload(digest, 0, stream)
                : dAcc.upload(
                      std::span<const RnsPoly>(&digest, 1), stream, 0);
            if (!digestUploaded || havePreparedKPrime) return digestUploaded;

            if (haveRetainedKPrime)
            {
                auto& kPrime = retainedKPrime->mImpl->mBuf;
                return direct
                    ? kPrime.upload(tbkPrime, 0, stream)
                    : kPrime.upload(
                          std::span<const RnsPoly>(&tbkPrime, 1), stream);
            }

            // sk1, digest, and tbkPrime are references owned by the caller. This
            // function's final download synchronises the same stream before any
            // of them can leave scope, so no temporary host storage is involved.
            return direct
                ? dAcc.upload(tbkPrime, 1, stream)
                : dAcc.upload(
                      std::span<const RnsPoly>(&tbkPrime, 1), stream, 1);
        }();
        if (!inputsUploaded)
            return bail("skx: upload");

        // gadgetDecomposeBitsRangeCentered(digest, gadgetLogBase, 1, tauHi)
        if (!launchGadgetDecompose(
                ring->view(), dAcc.data(), nullptr, 1, gadgetLogBase, 1, tauHi, true, uHi.data(), nullptr,
                stream.raw()))
            return bail("skx: gadget");

        if ((!havePreparedSk &&
             !launchNttForward(
                 ring->view(), sk.data(), tauHi, nullptr, stream.raw())) ||
            !launchNttForward(
                ring->view(), uHi.data(), tauHi, nullptr, stream.raw()))
            return bail("skx: ntt");

        const u64* skNttData = havePreparedSk
            ? preparedSkNtt->mImpl->mBuf.data()
            : sk.data();
        const u64* kPrimeData = havePreparedKPrime
            ? preparedKPrime->mImpl->mBuf.data()
            : (haveRetainedKPrime
                   ? retainedKPrime->mImpl->mBuf.data()
                   : dAcc.poly(1));

        std::vector<u32> idx(tauHi);
        for (u32 i = 0; i < tauHi; ++i) idx[i] = i;
        const u32* dIdx = stream.uploadIdx(idx);
        if (!dIdx) return bail("skx: idx");

        // One transform: the inner product is folded into its load and the
        // addition of tbkPrime into its store.
        NttFusedIp ip{};
        if (gpuFusedIpActive())
        {
            ip.mA = skNttData;
            ip.mB = uHi.data();
            ip.mAIdx = dIdx;
            ip.mBIdx = dIdx;
            ip.mTerms = tauHi;
            ip.mMode = NttFusedIp::Replace;
        }
        else if (!launchInnerProduct(
                     ring->view(), skNttData, uHi.data(), dIdx, dIdx, tauHi, term.data(), nullptr, 1, false,
                     false, stream.raw()))
        {
            return bail("skx: inner product");
        }
        if (!launchNttInverseFused(
                ring->view(), term.data(), 1, nullptr, kElemOpNoneHost, nullptr,
                static_cast<u32>(recoverNonInteractiveMask ? ElemOp::ReverseSub : ElemOp::Add),
                kPrimeData,
                stream.raw(), ip))
            return bail("skx: intt+add");

        if (digestHash && !hashRootWordsDevice(dAcc.data(),
                static_cast<u32>(ring->polyWords()), *digestHash, stream))
            return bail("skx: digest hash");
        std::vector<RnsPoly> hostOut;
        if (!term.download(hostOut, stream, 0, 1) || hostOut.size() != 1) return bail("skx: download");
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
            else if (haveRetainedKPrime)
                *residentKPrime = std::move(retainedKPrime);
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
        DeviceBatchPtr& tbk)
    {
        // A same-process socket test may resume the sender coroutine on a
        // thread whose current role is Receiver. Keep every ring lookup and
        // device operand in this sender's role for the whole Root chain;
        // senderCache separately borrows the token's offline run ID only for
        // its immutable public-operand copy.
        ScopedProtocolCacheScope senderScope(
            ProtocolCacheRole::Sender, currentProtocolCacheScope().mRunId);
        AutoTimer timer(globalTimingStats.mGpuSenderTimeUs);
        if (!enabled() || seed.empty() || leftWidth == 0 || tauHi == 0) return bail("root sender: shape");

        auto cache = senderCache(state);
        if (!cache) return bail("root sender: offline cache");
        auto ring = cache->mRing;
        const u32 rho = ring->rho();
        if (rho == 0 || leftWidth != tauHi * rho) return bail("root sender: leftWidth");
        const bool haveResidentKPrime =
            kPrimeRtDevice && kPrimeRtDevice->mImpl &&
            (rootKPrimeResidentEnabled() || rootKPrimePreuploadEnabled() ||
             kPrimeRtDevice->mImpl->mFreshRootKPrime) &&
            !kPrimeRtDevice->mImpl->mLogicalCount &&
            kPrimeRtDevice->mImpl->mRing == ring &&
            kPrimeRtDevice->mImpl->mBuf.count() == 1u;
        if (kPrimeRt.mCoeffs.size() != ring->polyWords() &&
            !(haveResidentKPrime && kPrimeRtDevice->mImpl->mFreshRootKPrime &&
              kPrimeRt.mCoeffs.empty()))
            return bail("root sender: k' host shape");
        // lheDec takes publicA[0 .. cipher.size()-1]; the cache holds mu rows and
        // the rows do not depend on the count, so leftWidth of them must be there.
        if (cache->mPublicA.count() < leftWidth) return bail("root sender: publicA rows");
        if (!ring->denoiseReady()) return bail("root sender: denoise tables");

        auto& stream = threadStream();
        Region regKern(regions().mKernelUs, stream.raw());

        // ---- buildHashedCt2(ctx, leftWidth, seed, sid, d'_Rt, 0) ----
        GpuPolyBuffer ctK;
        if (!sampleCt2Batch(
                *ring, *cache, state.mParams.mRing, 1, leftWidth, seed, sid, 0, dPrimeHash, ctK,
                stream))
            return bail("root sender: ct2");

        // ---- lheDec(ctK, k'_Rt): ctK - INTT(publicA*NTT(k')) ----
        //
        // k' is *not* offline data: prepareRootResponseSender draws a fresh k'_Rt
        // from the PRNG for every query, so the transform cannot be cached in the
        // offline cache. Device-generated keys and opt-in host-key residency
        // avoid its second host upload; each seed candidate still needs one
        // device copy and one transform.
        GpuPolyBuffer skNtt;
        if (!skNtt.resize(*ring, 1)) return bail("root sender: k' alloc");

        // The retained source remains in coefficient form across GoldenSeed
        // retries. Copy it into this call's destructive NTT scratch rather than
        // transforming the shared handle in place. rootSkxSenderDevice publishes
        // the handle only after synchronizing its producer stream, so this D2D is
        // safe even if the coroutine resumed on another thread/stream.
        bool kPrimeReady = false;
        if (haveResidentKPrime)
        {
            kPrimeReady = gpuMemcpyD2D(
                skNtt.data(), kPrimeRtDevice->mImpl->mBuf.data(), ring->polyBytes(),
                stream.raw());
        }
        if (!kPrimeReady)
        {
            // Exact host-key fallback. Device-generated keys have no host
            // mirror here: a failed D2D causes this helper to decline, after
            // which Core materializes the synchronized source for CPU replay.
            kPrimeReady = rootDirectUploadEnabled()
                              ? skNtt.upload(kPrimeRt, 0, stream)
                              : skNtt.upload(
                                    std::span<const RnsPoly>(&kPrimeRt, 1), stream);
        }
        if (!kPrimeReady ||
            !launchNttForward(ring->view(), skNtt.data(), 1, nullptr, stream.raw()))
            return bail("root sender: k' upload");

        GpuPolyBuffer product;
        if (!product.resize(*ring, leftWidth)) return bail("root sender: product");
        bool inverseDone = false;
        if (!gpuFusedIpActive() && tauHi == 1u && leftWidth == 4u)
        {
            if (!tryLaunchNttInverseOuterMu4ReverseSub(
                    ring->view(), product.data(), cache->mPublicA.data(), skNtt.data(),
                    leftWidth, ctK.data(), stream.raw(), inverseDone))
                return bail("root sender: fixed a.sk+intt");
        }
        if (!inverseDone)
        {
            std::vector<u32> aIdx(leftWidth);
            std::vector<u32> bIdx(leftWidth, 0);
            for (u32 row = 0; row < leftWidth; ++row) aIdx[row] = row;
            const u32* dA = stream.uploadIdx(aIdx);
            const u32* dB = stream.uploadIdx(bIdx);
            if (!dA || !dB) return bail("root sender: idx");
            if (!launchInnerProduct(
                    ring->view(), cache->mPublicA.data(), skNtt.data(), dA, dB, 1, product.data(),
                    nullptr, leftWidth, false, false, stream.raw()))
                return bail("root sender: a.sk");
            if (!launchNttInverseFused(
                    ring->view(), product.data(), leftWidth, nullptr, kElemOpNoneHost, nullptr,
                    static_cast<u32>(ElemOp::ReverseSub), ctK.data(), stream.raw()))
                return bail("root sender: ct2 intt");
        }

        // ---- denoiseAndAggRootKey: rho limbs combined, then tauHi digits summed ----
        auto tbkRt = std::make_shared<DeviceBatch>();
        tbkRt->mImpl->mRing = ring;
        tbkRt->mImpl->mBuf = std::move(product);

        DeviceBatchPtr rootKey;
        if (!denoiseAndAggDevice(ctx, *tbkRt, tauHi, rootKey) || !rootKey || rootKey->count() != 1)
            return bail("root sender: denoise+agg");

        // ---- the Root's own expand, one chunk with nonce 0 ----
        return expandSenderChunks(
            state, std::span<const RnsPoly>(), rootKey.get(), seed, sid, 0, dPrimeHash, tbk);
    }

    // ---- device-side denoise + aggregate ----------------------------------

    bool deferredGoldenValidationEnabled()
    {
        return deferredGoldenValidationEnabledImpl();
    }

    bool beginGoldenValidationAttempt(const RingNttContext& ctx)
    {
        if (!enabled() || !deferredGoldenValidationEnabledImpl()) return false;
        auto ring = GpuRing::get(ctx);
        if (!ring || !ring->denoiseReady()) return false;

        auto& stream = threadStream();
        auto& scratch = validateScratch();
        if (scratch.mAttemptActive || !scratch.ensure(ring->rho()) ||
            !gpuMemsetZero(scratch.mFlag, sizeof(u32), stream.raw()))
        {
            return false;
        }
        scratch.mAttemptActive = true;
        scratch.mAttemptStream = stream.raw();
        scratch.mAttemptRho = ring->rho();
        return true;
    }

    bool abortGoldenValidationAttempt()
    {
        auto& scratch = validateScratch();
        if (!scratch.mAttemptActive) return true;
        auto& stream = threadStream();
        if (scratch.mAttemptStream != stream.raw()) return false;
        const bool ok = stream.sync();
        scratch.mAttemptActive = false;
        scratch.mAttemptStream = nullptr;
        scratch.mAttemptRho = 0;
        return ok;
    }

    bool finishGoldenValidationAttempt(bool& ok)
    {
        auto& scratch = validateScratch();
        if (!scratch.mAttemptActive) return false;
        auto& stream = threadStream();
        if (scratch.mAttemptStream != stream.raw()) return false;

        u32 fail = 0;
        const bool copied = gpuMemcpyD2H(&fail, scratch.mFlag, sizeof(u32), stream.raw());
        const bool synced = stream.sync();
        scratch.mAttemptActive = false;
        scratch.mAttemptStream = nullptr;
        scratch.mAttemptRho = 0;
        if (!copied || !synced) return false;
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
        AutoTimer timer(globalTimingStats.mGpuMiscTimeUs);
        if (!enabled() || in.empty() || tau == 0) return false;
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

        auto& stream = threadStream();
        Region regKern(regions().mKernelUs, stream.raw());

        GpuPolyBuffer mid;
        if (!mid.resize(*ring, denoised)) return false;
        if (!denoiseComb(
                *ring, in.mImpl->mBuf.data(), mid.data(),
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
            if (!result->mImpl->mBuf.resize(*ring, aggCount)) return false;
            if (!launchAggregate(
                    ring->view(), mid.data(), tau, result->mImpl->mBuf.data(),
                    static_cast<u32>(aggCount), stream.raw()))
                return false;
        }

        out = std::move(result);
        return true;
    }

    bool denoiseAndAggValidateDevice(
        const RingNttContext& ctx,
        const DeviceBatch& in,
        u32 tau,
        const Params& validatedLevelParams,
        DeviceBatchPtr& out,
        u64 logicalInputCount)
    {
        AutoTimer timer(globalTimingStats.mGpuMiscTimeUs);
        if (!enabled() || in.empty() || tau == 0 ||
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

        auto& stream = threadStream();
        auto& scratch = validateScratch();
        if (!uploadGoldenMargins(
                validatedLevelParams, ctx, *ring, scratch, stream))
            return false;

        Region regKern(regions().mKernelUs, stream.raw());
        GpuPolyBuffer mid;
        if (!mid.resize(*ring, physicalDenoised) ||
            !launchDenoiseCombValidate(
                ring->view(), ring->denoiseView(), in.mImpl->mBuf.data(), mid.data(),
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
            else if (!result->mImpl->mBuf.resize(*ring, logicalDenoised) ||
                     !gpuMemcpyD2D(
                         result->mImpl->mBuf.data(), mid.data(),
                         logicalDenoised * ring->polyBytes(), stream.raw()))
            {
                return false;
            }
        }
        else
        {
            if (!result->mImpl->mBuf.resize(*ring, aggCount) ||
                !launchAggregate(
                    ring->view(), mid.data(), tau, result->mImpl->mBuf.data(),
                    static_cast<u32>(aggCount), stream.raw()))
                return false;
        }

        out = std::move(result);
        return true;
    }

    // ---- device-side golden-seed validation -------------------------------

    bool queueGoldenSeedValidation(const Params& params, const DeviceBatch& tbk)
    {
        AutoTimer timer(globalTimingStats.mGpuMiscTimeUs);
        if (!enabled() || tbk.empty() || params.mCt2SeedMode != Ct2SeedMode::GoldenSeed)
            return false;

        RingNttContext ctx{};
        if (!makeRingNttContext(params.mShrinkExpand.mRing, ctx)) return false;
        auto ring = GpuRing::get(ctx);
        if (!ring || !ring->denoiseReady() || !tbk.mImpl || tbk.mImpl->mRing != ring ||
            tbk.mImpl->mBuf.count() != tbk.count())
            return false;

        const u32 mu = params.mShrinkExpand.mMu;
        const u32 rho = ring->rho();
        if (rho == 0 || mu == 0 || (mu % rho) != 0) return false;
        const std::size_t expected =
            ((static_cast<std::size_t>(params.mW) + mu - 1u) / mu) * mu;
        if (tbk.count() != expected) return false;

        auto& stream = threadStream();
        auto& scratch = validateScratch();
        if (!uploadGoldenMargins(params, ctx, *ring, scratch, stream)) return false;

        Region regKern(regions().mKernelUs, stream.raw());
        return launchValidateGoldenSeed(
            ring->view(), ring->denoiseView(), tbk.mImpl->mBuf.data(),
            static_cast<u32>(tbk.count()), mu, scratch.mMarginLo, scratch.mMarginHi,
            scratch.mFlag, stream.raw());
    }

    bool validateGoldenSeedDevice(const Params& params, const DeviceBatch& tbk, bool& ok)
    {
        AutoTimer timer(globalTimingStats.mGpuMiscTimeUs);
        if (!enabled() || tbk.empty() || params.mCt2SeedMode != Ct2SeedMode::GoldenSeed)
            return false;

        RingNttContext ctx{};
        if (!makeRingNttContext(params.mShrinkExpand.mRing, ctx)) return false;
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

        auto& stream = threadStream();
        Region regKern(regions().mKernelUs, stream.raw());

        auto& scratch = validateScratch();
        if (scratch.mAttemptActive || !scratch.ensure(rho)) return false;
        if (!gpuMemcpyH2D(scratch.mMarginLo, marginLo.data(), rho * sizeof(u64), stream.raw()) ||
            !gpuMemcpyH2D(scratch.mMarginHi, marginHi.data(), rho * sizeof(u64), stream.raw()) ||
            !gpuMemsetZero(scratch.mFlag, sizeof(u32), stream.raw()))
        {
            return false;
        }

        if (!launchValidateGoldenSeed(
                ring->view(), ring->denoiseView(), tbk.mImpl->mBuf.data(),
                static_cast<u32>(tbk.count()), mu, scratch.mMarginLo, scratch.mMarginHi, scratch.mFlag,
                stream.raw()))
        {
            return false;
        }

        u32 fail = 0;
        if (!gpuMemcpyD2H(&fail, scratch.mFlag, sizeof(u32), stream.raw()) || !stream.sync())
        {
            return false;
        }
        ok = (fail == 0);
        return true;
    }

    namespace
    {
        bool enqueueLeafGoldenValidation(const Params& params, const DeviceBatch& tbk, bool deferred)
        {
            HostStep validationStep("gpu: leaf golden enqueue");
            if (!enabled() || !params.mW || !params.mShrinkExpand.mMu || tbk.empty() ||
                params.mCt2SeedMode != Ct2SeedMode::GoldenSeed) return false;
            RingNttContext ctx{};
            if (!makeRingNttContext(params.mShrinkExpand.mRing, ctx)) return false;
            auto ring = GpuRing::get(ctx);
            const std::size_t mu = params.mShrinkExpand.mMu;
            const std::size_t padded = ((static_cast<std::size_t>(params.mW) + mu - 1) / mu) * mu;
            if (!ring || !tbk.mImpl || tbk.mImpl->mRing != ring ||
                tbk.mImpl->mBuf.count() < tbk.count() ||
                (tbk.count() != params.mW && tbk.count() != padded)) return false;

            auto& stream = threadStream();
            auto& scratch = validateScratch();
            if (deferred)
            {
                if (!scratch.mAttemptActive || scratch.mAttemptStream != stream.raw() ||
                    scratch.mAttemptRho != ring->rho()) return false;
            }
            else if (scratch.mAttemptActive || !scratch.ensure(ring->rho()) ||
                !gpuMemsetZero(scratch.mFlag, sizeof(u32), stream.raw())) return false;

            LeafGoldenSeedRoundingConstants constants;
            {
                HostStep constantsStep("gpu: leaf golden constants");
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
            Region regKern(regions().mKernelUs, stream.raw());
            return launchValidateLeafGoldenSeed(ring->view(), scratch.mLeaf, tbk.mImpl->mBuf.data(),
                params.mW, constants.mMarginLo, constants.mMarginHi, scratch.mFlag, stream.raw());
        }
    }

    bool queueLeafGoldenSeedValidation(const Params& params, const DeviceBatch& tbk)
    {
        AutoTimer timer(globalTimingStats.mGpuMiscTimeUs);
        return enqueueLeafGoldenValidation(params, tbk, true);
    }

    bool validateLeafGoldenSeedDevice(const Params& params, const DeviceBatch& tbk, bool& ok)
    {
        AutoTimer timer(globalTimingStats.mGpuMiscTimeUs);
        if (!enqueueLeafGoldenValidation(params, tbk, false)) return false;
        auto& stream = threadStream();
        u32 failed = 0;
        const bool copied = gpuMemcpyD2H(&failed, validateScratch().mFlag, sizeof(u32), stream.raw());
        const bool synced = stream.sync();
        if (!copied || !synced) return false;
        ok = failed == 0;
        return true;
    }

    // ---- denoise ----------------------------------------------------------

    bool denoiseCombBatch(
        const RingNttContext& ctx, const std::vector<RnsPoly>& in, std::vector<RnsPoly>& out)
    {
        AutoTimer timer(globalTimingStats.mGpuMiscTimeUs);
        if (!enabled()) return false;
        auto ring = GpuRing::get(ctx);
        if (!ring || !ring->denoiseReady()) return false;
        const u32 rho = ring->rho();
        if (rho == 0 || in.empty() || in.size() % rho != 0) return false;

        const std::size_t outCount = in.size() / rho;
        auto& stream = threadStream();
        stream.reset();

        GpuPolyBuffer src;
        GpuPolyBuffer dst;
        if (!src.resize(*ring, in.size()) || !dst.resize(*ring, outCount)) return false;
        {
            Region regUp(regions().mUploadUs, stream.raw());
            if (!src.upload(in, stream)) return false;
        }
        {
            Region regKern(regions().mKernelUs, stream.raw());
            if (!denoiseComb(*ring, src.data(), dst.data(), static_cast<u32>(outCount), stream))
                return false;
        }
        Region regDown(regions().mDownloadUs, stream.raw());
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
        if (!enabled() || seeds.empty()) return false;
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

        auto& stream = threadStream();
        auto& scratch = sampleScratch();
        const std::size_t streamWords = ring->polyWords() + kSampleSlackWords;
        if (!scratch.ensureSeeds(sealSeeds.size())) return false;
        const bool fusedSamplerNeedsEpoch = gpuFusedSamplerNeedsRejectEpoch(
            ring->n(), static_cast<u32>(streamWords), static_cast<u32>(seeds.size()));
        const bool needStream = !gpuFusedSamplerActive(
            ring->n(), static_cast<u32>(streamWords), static_cast<u32>(seeds.size()));
        if (needStream && !scratch.ensureStream(seeds.size() * streamWords))
            return false;
        u32* rejectEpochs = nullptr;
        u32 rejectEpoch = 0;
        if ((fusedSamplerNeedsEpoch || (needStream && gpuRejectReduceFusionActive())) &&
            !scratch.nextRejectEpoch(seeds.size(), stream.raw(), rejectEpochs, rejectEpoch))
            return false;

        u64* dMax = static_cast<u64*>(gpuMalloc(maxMultiple.size() * sizeof(u64)));
        GpuPolyBuffer dst;
        if (!dMax || !dst.resize(*ring, seeds.size()))
        {
            gpuFree(dMax);
            return false;
        }

        bool ok =
            gpuMemcpyH2D(scratch.mSeeds, sealSeeds.data(), sealSeeds.size() * sizeof(u64), stream.raw()) &&
            gpuMemcpyH2D(dMax, maxMultiple.data(), maxMultiple.size() * sizeof(u64), stream.raw()) &&
            launchSampleUniformPolyBlake2xb(
                ring->view(), scratch.mSeeds, scratch.mStream, static_cast<u32>(streamWords), dMax,
                dst.data(), nullptr, static_cast<u32>(seeds.size()), rejectEpochs, rejectEpoch,
                maxMultipleOverride.empty(), stream.raw());

        if (ok) ok = dst.download(out, stream, 0, seeds.size());
        gpuFree(dMax);
        return ok;
    }

    bool sampleRootZetaFromSeedsForTest(
        const RingNttContext& ctx,
        std::span<const block> taskSeeds,
        bool forceFirstReject,
        std::vector<RnsPoly>& out,
        u32 rangesPerPoly)
    {
        if (!enabled() || rangesPerPoly < 2u || rangesPerPoly > 32u ||
            taskSeeds.size() != 3u * rangesPerPoly) return false;
        auto ring = GpuRing::get(ctx);
        if (!ring) return false;
        const bool noGold = ring->n() == 16384u && ring->rho() == 8u;
        if (!noGold && (ring->n() != 8192u || ring->rho() != 4u)) return false;

        auto& stream = threadStream();
        auto& scratch = sampleScratch();
        if (!scratch.ensureCt2Seeds(2u * taskSeeds.size()) ||
            !scratch.ensureRoundKeys(176u * taskSeeds.size()) ||
            !scratch.ensureRootZetaRejects(taskSeeds.size()))
            return false;

        GpuPolyBuffer dst;
        if (!dst.resize(*ring, 3u)) return false;
        if (!gpuMemcpyH2D(
                            scratch.mCt2Seeds, taskSeeds.data(),
                            taskSeeds.size_bytes(), stream.raw())) return false;
        const bool ok = noGold
            ? launchRootZetaRho8(
                ring->view(), scratch.mCt2Seeds, scratch.mRoundKeys,
                scratch.mRootZetaFirstReject, dst.data(), rangesPerPoly,
                forceFirstReject, stream.raw())
            : launchRootZetaRho4(
                ring->view(), scratch.mCt2Seeds, scratch.mRoundKeys,
                scratch.mRootZetaFirstReject, dst.data(), rangesPerPoly,
                forceFirstReject, stream.raw());
        return ok && dst.download(out, stream, 0, 3u);
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
        if (!enabled() || mu == 0 || chunkCount == 0) return false;
        auto ring = GpuRing::get(ctx);
        if (!ring) return false;

        std::vector<u64> maxMultiple(ring->rho());
        constexpr u64 maxRandom = ~u64(0);
        for (u32 j = 0; j < ring->rho(); ++j)
        {
            const seal::Modulus mod(ring->hostModuli()[j]);
            maxMultiple[j] = maxRandom - seal::util::barrett_reduce_64(maxRandom, mod) - 1;
        }
        u64* dMax = static_cast<u64*>(gpuMalloc(maxMultiple.size() * sizeof(u64)));
        if (!dMax) return false;

        auto& stream = threadStream();
        OfflineCache cache{};
        cache.mMaxMultiple = dMax;

        GpuPolyBuffer dst;
        bool ok = gpuMemcpyH2D(dMax, maxMultiple.data(), maxMultiple.size() * sizeof(u64), stream.raw()) &&
                  sampleCt2Batch(
                      *ring, cache, ctx.mParams, chunkCount, mu, seed, sid, instanceBase,
                      hashSeedDigest(digest), dst, stream);
        if (ok) ok = dst.download(out, stream, 0, static_cast<std::size_t>(chunkCount) * mu);
        gpuFree(dMax);
        return ok;
    }

    namespace
    {
        std::shared_ptr<GpuPlainNtt> gpuPlainTables(const ZpCrtContext& zp)
        {
            if (zp.mGpuLightweight)
                return GpuPlainNtt::getRaw(
                    zp.mRing.mParams.mPolyModulusDegree, zp.mPlaintextModulus);
            if (!zp.mBatchingContext || !zp.mBatchEncoder) return nullptr;
            return GpuPlainNtt::get(*zp.mBatchingContext, *zp.mBatchEncoder);
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
            DeviceScalarsPtr* deviceOut)
        {
            if (chunkCount == 0 || zpLabelCount == 0) return false;
            if (chunkCount > std::numeric_limits<u32>::max()) return false;
            auto plain = gpuPlainTables(zp);
            if (!plain || plain->n() != ring.n()) return false;

            const u32 n = ring.n();
            const u32 slots = plain->slotCount();
            if (zpLabelCount > static_cast<u64>(chunkCount) * slots) return false;

            ScaleRoundConstView consts{};
            if (!ring.scaleRoundConstants(zp.mPlaintextModulus, consts)) return false;

            auto& stream = threadStream();
            const auto chunks = static_cast<u32>(chunkCount);

            // The scalar array is owned by a DeviceScalars when the caller wants
            // to keep it, and is scratch otherwise.
            auto scalars = std::make_shared<DeviceScalars>();
            if (!scalars->resize(static_cast<std::size_t>(zpLabelCount)))
                return false;
            u64* flat = scalars->data();

            // In the fixed production geometry the scale result can stay in the
            // plaintext NTT's shared tile. Decide before allocating coeffs so the
            // fused path removes the full chunks*N scratch buffer, while every
            // ineligible/toggled-off case retains the established launch chain.
            const bool fusedScale =
                fusedScaleUnwrapEnabled() && fusedUnwrapEnabled() &&
                canLaunchScaleNttForwardGather(
                    ring.view(), plain->view(), labels, chunks,
                    zp.mPlaintextModulus, consts.mFastLimbs,
                    plain->inverseSlotMap(), slots, flat, zpLabelCount);
            u64* coeffs = nullptr;
            if (!fusedScale)
            {
                const std::size_t coeffWords = static_cast<std::size_t>(chunks) * n;
                coeffs = static_cast<u64*>(gpuMalloc(coeffWords * sizeof(u64)));
                if (!coeffs) return false;
            }

            bool ok = true;
            {
                Region regKern(regions().mKernelUs, stream.raw());
                if (fusedScale)
                {
                    ok = launchScaleNttForwardGather(
                        ring.view(), plain->view(), labels, chunks,
                        zp.mPlaintextModulus, consts.mFastLimbs,
                        plain->inverseSlotMap(), plain->slotMap(), slots, flat,
                        zpLabelCount, stream.raw());
                }
                else
                {
                    ok = launchScaleAndRound(
                        ring.view(), labels, chunks, zp.mPlaintextModulus,
                        consts.mCrtInvPunctured, consts.mQ, consts.mPShoup,
                        consts.mFracLo, consts.mFracHi, consts.mFastLimbs,
                        coeffs, stream.raw());
                    if (ok && fusedUnwrapEnabled())
                    {
                        ok = launchNttForwardGather(
                            plain->view(), coeffs, chunks,
                            plain->inverseSlotMap(), slots, flat,
                            zpLabelCount, stream.raw());
                    }
                    else if (ok)
                    {
                        // BatchEncoder::decode's ntt_negacyclic_harvey, followed by
                        // its matrix_reps_index_map_ permutation.
                        ok = launchNttForward(
                                 plain->view(), coeffs, chunks, nullptr,
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
                Region regDown(regions().mDownloadUs, stream.raw());
                ok = gpuMemcpyD2H(
                         host, flat, static_cast<std::size_t>(zpLabelCount) * sizeof(u64), stream.raw()) &&
                     stream.sync();
            }
            else if (ok)
            {
                // Device-output path: the caller receives a handle, not host bytes,
                // so there is nothing to wait for here. Record the producing stream
                // and let whoever eventually reads it order against that.
                scalars->setProducerStream(stream.raw());
            }
            if (coeffs) gpuFree(coeffs);
            if (ok && deviceOut) *deviceOut = std::move(scalars);
            return ok;
        }
    }

    bool unwrapLabelsDevice(
        const ZpCrtContext& zp,
        const DeviceBatch& labels,
        u64 chunkCount,
        u64 zpLabelCount,
        u64* out)
    {
        AutoTimer timer(globalTimingStats.mGpuMiscTimeUs);
        if (!enabled() || labels.empty() || !out) return false;
        auto ring = GpuRing::get(zp.mRing);
        if (!ring) return false;
        if (labels.count() < chunkCount) return false;
        return unwrapFromDevice(
            zp, *ring, labels.mImpl->mBuf.data(), chunkCount, zpLabelCount, out, nullptr);
    }

    DeviceScalarsPtr unwrapLabelsToDevice(
        const ZpCrtContext& zp,
        const DeviceBatch& labels,
        u64 chunkCount,
        u64 zpLabelCount)
    {
        AutoTimer timer(globalTimingStats.mGpuMiscTimeUs);
        if (!enabled() || labels.empty()) return nullptr;
        auto ring = GpuRing::get(zp.mRing);
        if (!ring) return nullptr;
        if (labels.count() < chunkCount) return nullptr;
        DeviceScalarsPtr out;
        if (!unwrapFromDevice(
                zp, *ring, labels.mImpl->mBuf.data(), chunkCount, zpLabelCount, nullptr, &out))
        {
            return nullptr;
        }
        return out;
    }

    bool unwrapLabelsBatch(
        const ZpCrtContext& zp,
        const std::vector<RnsPoly>& labels,
        u64 zpLabelCount,
        u64* out)
    {
        AutoTimer timer(globalTimingStats.mGpuMiscTimeUs);
        if (!enabled() || labels.empty() || !out) return false;
        auto ring = GpuRing::get(zp.mRing);
        if (!ring) return false;

        auto& stream = threadStream();
        GpuPolyBuffer src;
        {
            Region regUp(regions().mUploadUs, stream.raw());
            if (!src.resize(*ring, labels.size()) || !src.upload(labels, stream)) return false;
        }
        return unwrapFromDevice(zp, *ring, src.data(), labels.size(), zpLabelCount, out, nullptr);
    }

    bool unwrapLabelsBatchUnscaled(
        const ZpCrtContext& zp,
        const std::vector<RnsPoly>& labels,
        u64 chunkCount,
        u64 zpLabelCount,
        u64* out)
    {
        AutoTimer timer(globalTimingStats.mGpuMiscTimeUs);
        if (!enabled() || !chunkCount || !zpLabelCount || !out ||
            chunkCount > labels.size() ||
            chunkCount > std::numeric_limits<u32>::max()) return false;
        auto ring = GpuRing::get(zp.mRing);
        auto plain = gpuPlainTables(zp);
        if (!ring || !plain || plain->n() != ring->n() ||
            plain->slotCount() != ring->n() ||
            plain->view().mMinModulus != zp.mPlaintextModulus ||
            zpLabelCount > chunkCount * static_cast<u64>(plain->slotCount()))
            return false;

        auto& stream = threadStream();
        GpuPolyBuffer source;
        using Allocation = std::unique_ptr<void, decltype(&gpuFree)>;
        Allocation coefficients(nullptr, gpuFree), scalars(nullptr, gpuFree);
        // Every queued operation must finish before source and scratch owners
        // release their role-local bytes, including an error after submission.
        struct DrainStream
        {
            GpuStream& stream;
            ~DrainStream() { stream.sync(); }
        } drain{stream};
        const std::size_t coeffCount = static_cast<std::size_t>(chunkCount) * ring->n();
        coefficients.reset(gpuMalloc(coeffCount * sizeof(u64)));
        scalars.reset(gpuMalloc(static_cast<std::size_t>(zpLabelCount) * sizeof(u64)));
        if (!coefficients || !scalars || !source.resize(*ring, chunkCount))
            return false;
        {
            Region upload(regions().mUploadUs, stream.raw());
            if (!source.upload(
                    std::span<const RnsPoly>(labels.data(),
                        static_cast<std::size_t>(chunkCount)), stream)) return false;
        }
        auto* coeff = static_cast<u64*>(coefficients.get());
        auto* flat = static_cast<u64*>(scalars.get());
        const u32 chunks = static_cast<u32>(chunkCount);
        bool ok = false;
        {
            Region kernels(regions().mKernelUs, stream.raw());
            ok = launchComposeReducePlain(
                ring->view(), plain->view(), source.data(), chunks,
                coeff, stream.raw());
            if (ok && fusedUnwrapEnabled())
                ok = launchNttForwardGather(
                    plain->view(), coeff, chunks,
                    plain->inverseSlotMap(), plain->slotCount(), flat,
                    zpLabelCount, stream.raw());
            else if (ok)
                ok = launchNttForward(
                         plain->view(), coeff, chunks, nullptr,
                         stream.raw()) &&
                     launchGatherSlots(
                         coeff, ring->n(), plain->slotMap(),
                         plain->slotCount(), chunks, flat,
                         zpLabelCount, stream.raw());
        }
        if (!ok) return false;
        {
            Region download(regions().mDownloadUs, stream.raw());
            return gpuMemcpyD2H(
                       out, flat, static_cast<std::size_t>(zpLabelCount) * sizeof(u64),
                       stream.raw()) && stream.sync();
        }
    }

    bool scaleNttForwardGatherSlotOwnedForTest(
        const ZpCrtContext& zp,
        const std::vector<RnsPoly>& labels,
        u64 zpLabelCount,
        std::vector<u64>& coefficientOwned,
        std::vector<u64>& slotOwned)
    {
        if (!enabled() || labels.empty() || zpLabelCount == 0u ||
            labels.size() > std::numeric_limits<u32>::max() ||
            zp.mPlaintextModulus < 2)
        {
            return false;
        }

        auto ring = GpuRing::get(zp.mRing);
        if (!ring) return false;
        auto plain = gpuPlainTables(zp);
        if (!plain || plain->n() != ring->n() ||
            zpLabelCount > static_cast<u64>(labels.size()) * plain->slotCount())
        {
            return false;
        }

        ScaleRoundConstView consts{};
        if (!ring->scaleRoundConstants(zp.mPlaintextModulus, consts))
        {
            return false;
        }

        auto& stream = threadStream();
        GpuPolyBuffer src;
        DeviceScalars accepted;
        DeviceScalars candidate;
        if (!src.resize(*ring, labels.size()) || !src.upload(labels, stream) ||
            !accepted.resize(static_cast<std::size_t>(zpLabelCount)) ||
            !candidate.resize(static_cast<std::size_t>(zpLabelCount)))
        {
            return false;
        }

        const u32 chunks = static_cast<u32>(labels.size());
        bool ok = launchScaleNttForwardGatherHiCarryForTest(
            ring->view(), plain->view(), src.data(), chunks,
            zp.mPlaintextModulus, consts.mFastLimbs,
            plain->inverseSlotMap(), plain->slotMap(), plain->slotCount(),
            accepted.data(), zpLabelCount, false, stream.raw());
        ok = launchScaleNttForwardGatherHiCarryForTest(
                 ring->view(), plain->view(), src.data(), chunks,
                 zp.mPlaintextModulus, consts.mFastLimbs,
                 plain->inverseSlotMap(), plain->slotMap(), plain->slotCount(),
                 candidate.data(), zpLabelCount, true, stream.raw()) &&
            ok;
        if (!ok) return false;

        coefficientOwned.resize(static_cast<std::size_t>(zpLabelCount));
        slotOwned.resize(static_cast<std::size_t>(zpLabelCount));
        return gpuMemcpyD2H(
                   coefficientOwned.data(), accepted.data(),
                   coefficientOwned.size() * sizeof(u64), stream.raw()) &&
            gpuMemcpyD2H(
                   slotOwned.data(), candidate.data(),
                   slotOwned.size() * sizeof(u64), stream.raw()) &&
            stream.sync();
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
            const void* firstQueryOwner = nullptr, u64 firstQuerySid = 0)
    {
        if (!enabled() || !scalars || labelCount == 0) return nullptr;
        auto ring = GpuRing::get(zp.mRing);
        if (!ring) return nullptr;
        auto plain = gpuPlainTables(zp);
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
        const char* fuse = std::getenv("LV_GPU_GARBLED_FUSED_INPUT");
        if (garbledInput && fuse && std::string(fuse) == "0")
        {
            auto repeated = std::make_shared<DeviceScalars>();
            if (!repeated->resize(chunkCount * slots) ||
                !launchRepeatGarbledInputs(scalars, labelCount, slots,
                    static_cast<u32>(chunkCount), repeated->data(), threadStream().raw()))
                return nullptr;
            return wrapScalarsOnDevice(zp, repeated->data(), chunkCount * slots,
                false, 0, padChunks, false, nullptr);
        }

        // Delta lift factors per limb, cached with the ring tables.
        const u64* lift = nullptr;
        if (multiplyByDelta)
        {
            if (zp.mPlaintextLiftModQj.size() != rho) return nullptr;
            static std::mutex liftMutex;
            using LiftKey = std::pair<std::vector<u64>, ProtocolCacheRole>;
            static std::vector<std::pair<LiftKey, const u64*>> liftCache;
            std::vector<u64> host(zp.mPlaintextLiftModQj.begin(), zp.mPlaintextLiftModQj.end());
            LiftKey key{host, currentProtocolCacheScope().mRole};
            std::lock_guard<std::mutex> lock(liftMutex);
            for (const auto& [k, v] : liftCache)
            {
                if (k == key)
                {
                    lift = v;
                    break;
                }
            }
            if (!lift)
            {
                lift = static_cast<const u64*>(uploadPersistent(host));
                if (!lift) return nullptr;
                liftCache.emplace_back(std::move(key), lift);
            }
        }

        auto& stream = threadStream();
        auto out = std::make_shared<DeviceBatch>();
        out->mImpl->mRing = ring;
        if (!multiplyByDelta)
            out->mImpl->mPlainBroadcastBits = bitWidth(zp.mPlaintextModulus - 1u);
        const bool reservedWrap = !multiplyByDelta && !padValue &&
            takeReceiverFirstQueryWrap(
                firstQueryAllocations, *ring, zp.mRing.mParams,
                labelCount, static_cast<std::size_t>(total), garbledInput,
                firstQueryOwner, firstQuerySid, out->mImpl->mBuf, stream);
        if (!reservedWrap && !out->mImpl->mBuf.resize(
                *ring, static_cast<std::size_t>(total))) return nullptr;
        // Chunks past the real input are all-zero ring elements, matching the
        // explicit padding in civoleReceiverSetX.
        if (total > chunkCount && !out->mImpl->mBuf.zero(stream)) return nullptr;

        const auto chunks = static_cast<u32>(chunkCount);
        const bool fusedWrap =
            fusedWrapEnabled() && !multiplyByDelta &&
            canLaunchNttInverseScatterBroadcast(plain->view(), ring->view());
        const bool singleLimbWrap =
            fusedWrap && plainBroadcastSingleLimbEnabled() &&
            canLaunchNttInverseScatterSingleLimb(
                plain->view(), ring->view());
        out->mImpl->mPlainBroadcastSingleLimb = singleLimbWrap;

        // The fused path consumes scalars directly and writes the ring batch, so
        // only the exact legacy path needs the N-word-per-chunk plaintext scratch.
        u64* coeffs = nullptr;
        if (!fusedWrap)
        {
            const std::size_t coeffWords = static_cast<std::size_t>(chunkCount) * n;
            coeffs = static_cast<u64*>(gpuMalloc(coeffWords * sizeof(u64)));
            if (!coeffs) return nullptr;
        }

        bool ok = false;
        {
            Region regKern(regions().mKernelUs, stream.raw());
            if (fusedWrap)
            {
                ok = singleLimbWrap
                    ? launchNttInverseScatterSingleLimb(
                          plain->view(), ring->view(), scalars, labelCount,
                          padValue, plain->inverseSlotMap(), chunks,
                          out->mImpl->mBuf.data(), stream.raw(), garbledInput)
                    : launchNttInverseScatterBroadcast(
                          plain->view(), ring->view(), scalars, labelCount,
                          padValue, plain->inverseSlotMap(), chunks,
                          out->mImpl->mBuf.data(), stream.raw(), garbledInput);
            }
            else
            {
                ok = launchScatterSlots(
                         scalars, labelCount, padValue, plain->slotMap(), slots, chunks, coeffs, n,
                         stream.raw(), garbledInput) &&
                     // BatchEncoder::encode's inverse_ntt_negacyclic_harvey.
                     launchNttInverse(plain->view(), coeffs, chunks, nullptr, stream.raw()) &&
                     launchLiftPlainToRing(
                         ring->view(), coeffs, chunks, lift, out->mImpl->mBuf.data(), stream.raw());
            }
            // No drain: the wrapped input is device resident and is consumed on
            // this stream. Legacy scratch frees below remain stream ordered.
        }
        if (coeffs) gpuFree(coeffs);
        return ok ? out : nullptr;
    }
    }

    DeviceBatchPtr wrapLabelsDevice(
        const ZpCrtContext& zp,
        std::span<const u64> labels,
        bool multiplyByDelta,
        u64 padValue,
        u64 padChunks,
        bool garbledInput)
    {
        AutoTimer timer(globalTimingStats.mGpuMiscTimeUs);
        if (!enabled() || labels.empty()) return nullptr;

        auto& stream = threadStream();
        u64* scalars = static_cast<u64*>(gpuMalloc(labels.size() * sizeof(u64)));
        if (!scalars) return nullptr;

        bool ok = false;
        {
            Region regUp(regions().mUploadUs, stream.raw());
            ok = uploadFromHost(scalars, labels.data(), labels.size() * sizeof(u64), stream);
        }
        DeviceBatchPtr out = ok
            ? wrapScalarsOnDevice(
                  zp, scalars, labels.size(), multiplyByDelta, padValue, padChunks,
                  garbledInput, nullptr)
            : nullptr;
        // Stream ordered, like the scratch frees inside the helper.
        gpuFree(scalars);
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
        const void* firstQueryOwner, u64 firstQuerySid)
    {
        AutoTimer timer(globalTimingStats.mGpuMiscTimeUs);
        if (!enabled() || labels.empty()) return nullptr;
        const std::size_t count = labelCount
            ? std::min<std::size_t>(static_cast<std::size_t>(labelCount), labels.count())
            : labels.count();
        // The caller may have produced the input on another thread's stream.
        if (auto* ps = labels.producerStream(); ps && ps != threadStream().raw())
        {
            if (!gpuStreamSync(ps)) return nullptr;
        }
        return wrapScalarsOnDevice(
            zp, labels.data(), count, multiplyByDelta, padValue, padChunks,
            garbledInput, firstQueryAllocations,
            firstQueryOwner, firstQuerySid);
    }

    DeviceBatchPtr wrapSetupDeltaResident(const ZpCrtContext& ctx, u64 delta,
        std::span<const u64> deltaSlots, const std::array<u64, 3>* garbledDeltas)
    {
        const auto scope = currentProtocolCacheScope();
        if (!enabled() || scope.mRole != ProtocolCacheRole::Sender ||
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
        const char* decline = std::getenv("LV_GPU_SETUP_DELTA_DEVICE_FORCE_DECLINE");
        const char* chainDecline = std::getenv("LV_GPU_SETUP_DELTA_CHAIN_FORCE_DECLINE");
        if ((decline && decline[0] == '1') ||
            (chainDecline && chainDecline[0] == '1')) return {};

        HostStep step("setup sender: resident wrapped delta");
        struct RestoreStream
        {
            void* previous = gpuCurrentStream();
            ~RestoreStream() { gpuSetCurrentStream(previous); }
        } restore;
        auto& stream = threadStream();
        gpuSetCurrentStream(stream.raw());
        auto ring = GpuRing::get(ctx.mRing);
        if (!ring || ring->n() != slots || ring->rho() != rho) return {};
        auto owner = std::make_shared<DeviceBatch>();
        GpuPolyBuffer output;
        using Allocation = std::unique_ptr<void, decltype(&gpuFree)>;
        Allocation lift(nullptr, gpuFree), values(nullptr, gpuFree),
            coefficients(nullptr, gpuFree);
        std::shared_ptr<GpuPlainNtt> plain;
        // This guard is deliberately constructed after every GPU allocation
        // owner, including slot scratch. An early post-submit decline must
        // finish queued work before any of those owners release their bytes.
        struct DrainStream
        {
            GpuStream& stream;
            ~DrainStream() { stream.sync(); }
        } drain{stream};
        if (!output.resize(*ring, 1)) return {};
        lift.reset(gpuMalloc(rho * sizeof(u64)));
        if (!lift || !gpuMemcpyH2D(lift.get(),
                ctx.mPlaintextLiftModQj.data(), rho * sizeof(u64), stream.raw())) return {};
        const auto view = ring->view();
        const char* directConstant = std::getenv("LV_GPU_SETUP_DELTA_CONSTANT_DIRECT");
        if (!garbledDeltas && deltaSlots.empty() &&
            (!directConstant || directConstant[0] != '0'))
        {
            if (!launchPrepareConstantDelta(view, delta,
                    static_cast<const u64*>(lift.get()), output.data(),
                    stream.raw())) return {};
        }
        else
        {
            plain = gpuPlainTables(ctx);
            if (!plain || plain->n() != slots ||
                plain->view().mMinModulus != ctx.mPlaintextModulus) return {};
            values.reset(gpuMalloc(slots * sizeof(u64)));
            coefficients.reset(gpuMalloc(slots * sizeof(u64)));
            if (!values || !coefficients) return {};
            auto* slotValues = static_cast<u64*>(values.get());
            auto* plainCoefficients = static_cast<u64*>(coefficients.get());
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
                !launchNttInverse(plain->view(), plainCoefficients,
                    1, nullptr, stream.raw()) ||
                !launchLiftPlainToRing(view, plainCoefficients, 1,
                    static_cast<const u64*>(lift.get()), output.data(),
                    stream.raw())) return {};
        }
        if (!stream.sync()) return {};
        owner->mImpl->mRing = std::move(ring);
        owner->mImpl->mBuf = std::move(output);
        owner->mImpl->mSetupDeltaCoefficients = true;
        owner->mImpl->mSetupSenderRole = ProtocolCacheRole::Sender;
        owner->mImpl->mSetupSenderRunId = scope.mRunId;
        owner->mImpl->mSetupSenderDevice = currentDeviceOrdinal();
        return owner;
    }

    bool wrapSetupDeltaDevice(const ZpCrtContext& ctx, u64 delta,
        std::span<const u64> deltaSlots, const std::array<u64, 3>* garbledDeltas,
        RnsPoly& out)
    {
        if (!enabled() || ctx.mPlaintextModulus < 2 || !ringModulusCount(ctx.mRing) ||
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
        const char* decline = std::getenv("LV_GPU_SETUP_DELTA_DEVICE_FORCE_DECLINE");
        if (decline && decline[0] == '1') return false;

        HostStep deltaStep("setup: delta GPU preparation");
        struct RestoreStream { void* previous = gpuCurrentStream(); ~RestoreStream() { gpuSetCurrentStream(previous); } } restore;
        auto& stream = threadStream();
        gpuSetCurrentStream(stream.raw());
        const char* lightweight = std::getenv("LV_GPU_SETUP_DELTA_LIGHTWEIGHT");
        if (!lightweight || lightweight[0] != '0')
        {
            HostStep lightweightStep("setup: delta lightweight GPU preparation");
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
            const auto view = ring->view();
            using Allocation = std::unique_ptr<void, decltype(&gpuFree)>;
            Allocation deviceLift(nullptr, gpuFree);
            Allocation deviceOutput(nullptr, gpuFree), deviceSlots(nullptr, gpuFree), devicePlain(nullptr, gpuFree);
            std::shared_ptr<GpuPlainNtt> plain;
            RnsPoly next;
            struct DrainStream { GpuStream& stream; ~DrainStream() { stream.sync(); } } drain{stream};
            const std::size_t words = slots * rho;
            const std::size_t bytes = words * sizeof(u64);
            deviceLift.reset(gpuMalloc(rho * sizeof(u64)));
            deviceOutput.reset(gpuMalloc(bytes));
            if (!deviceLift || !deviceOutput ||
                !gpuMemcpyH2D(deviceLift.get(), ctx.mPlaintextLiftModQj.data(), rho * sizeof(u64), stream.raw())) return false;
            auto* destination = static_cast<u64*>(deviceOutput.get());
            const auto* lift = static_cast<const u64*>(deviceLift.get());
            const char* directConstant = std::getenv("LV_GPU_SETUP_DELTA_CONSTANT_DIRECT");
            if (!garbledDeltas && deltaSlots.empty() && (!directConstant || directConstant[0] != '0'))
            {
                if (!launchPrepareConstantDelta(view, delta, lift, destination, stream.raw())) return false;
            }
            else
            {
                plain = gpuPlainTables(ctx);
                if (!plain || plain->n() != slots || plain->view().mMinModulus != ctx.mPlaintextModulus)
                    return false;
                deviceSlots.reset(gpuMalloc(slots * sizeof(u64)));
                devicePlain.reset(gpuMalloc(slots * sizeof(u64)));
                if (!deviceSlots || !devicePlain) return false;
                auto* values = static_cast<u64*>(deviceSlots.get());
                auto* coefficients = static_cast<u64*>(devicePlain.get());
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
                    !launchNttInverse(plain->view(), coefficients, 1, nullptr, stream.raw()) ||
                    !launchLiftPlainToRing(view, coefficients, 1, lift, destination, stream.raw())) return false;
            }
            next.mCoeffs.resize(words);
            const char* smallDownload = std::getenv("LV_GPU_SETUP_DELTA_SMALL_DOWNLOAD");
            if (!smallDownload || smallDownload[0] != '0')
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
        std::unique_ptr<void, decltype(&gpuFree)> constantLift(nullptr, gpuFree);
        std::vector<RnsPoly> next;
        struct DrainStream { GpuStream& stream; ~DrainStream() { stream.sync(); } } drain{stream};
        auto downloadDelta = [&](const GpuPolyBuffer& values) {
            const char* smallDownload = std::getenv("LV_GPU_SETUP_DELTA_SMALL_DOWNLOAD");
            constexpr std::size_t maxSmallBytes = std::size_t(1) << 20;
            if ((!smallDownload || smallDownload[0] != '0') && values.count() == 1 &&
                values.data() && values.polyWords() &&
                values.polyWords() <= maxSmallBytes / sizeof(u64))
            {
                HostStep downloadStep("setup: delta small host snapshot");
                // One <=1 MiB result does not need the stream's minimum 8 MiB
                // pinned staging allocation. Allocate without a CPU fill and
                // preserve the completed host snapshot inside the setup timer.
                next.resize(1);
                next[0].mCoeffs.resize(values.polyWords());
                return gpuMemcpyD2H(next[0].mCoeffs.data(), values.data(),
                    values.polyWords() * sizeof(u64), stream.raw()) && stream.sync();
            }
            return values.download(next, stream) && next.size() == 1;
        };
        const char* directConstant = std::getenv("LV_GPU_SETUP_DELTA_CONSTANT_DIRECT");
        if (!garbledDeltas && deltaSlots.empty() && (!directConstant || directConstant[0] != '0'))
        {
            HostStep directStep("setup: constant delta GPU polynomial");
            constantRing = GpuRing::get(ctx.mRing);
            if (!constantRing || ctx.mPlaintextLiftModQj.size() != constantRing->rho() ||
                !constantPoly.resize(*constantRing, 1)) return false;
            const auto bytes = ctx.mPlaintextLiftModQj.size() * sizeof(u64);
            constantLift.reset(gpuMalloc(bytes));
            if (!constantLift || !gpuMemcpyH2D(constantLift.get(), ctx.mPlaintextLiftModQj.data(), bytes, stream.raw()) ||
                !launchPrepareConstantDelta(constantRing->view(), delta,
                    static_cast<const u64*>(constantLift.get()), constantPoly.data(), stream.raw()) ||
                !downloadDelta(constantPoly)) return false;
            out = std::move(next[0]);
            return true;
        }
        if (!deltaSlots.empty())
        {
            wrapped = wrapLabelsDevice(ctx, deltaSlots, true, 0, 1);
        }
        else
        {
            prepared = std::make_shared<DeviceScalars>();
            if (!prepared->resize(slots) || !launchPrepareDeltaSlots(
                    garbledDeltas ? (*garbledDeltas)[0] : delta,
                    garbledDeltas ? (*garbledDeltas)[1] : 0,
                    garbledDeltas ? (*garbledDeltas)[2] : 0,
                    static_cast<u32>(slots), garbledDeltas != nullptr, prepared->data(), stream.raw())) return false;
            wrapped = wrapDeviceLabels(ctx, *prepared, slots, true, 0, 1);
        }
        if (!wrapped || !wrapped->mImpl || wrapped->count() != 1 ||
            (wrapped->mImpl->mLogicalCount &&
                wrapped->mImpl->mLogicalCount != wrapped->mImpl->mBuf.count()) ||
            !ensurePlainBroadcastMaterialized(*wrapped->mImpl, stream) ||
            !downloadDelta(wrapped->mImpl->mBuf)) return false;
        out = std::move(next[0]);
        return true;
    }

    DeviceScalarsPtr uploadScalars(std::span<const u64> src)
    {
        if (!enabled() || src.empty()) return nullptr;
        // Allocator reuse dependencies must be recorded on the stream that
        // will receive the upload, including after a protocol-role switch.
        auto& stream = threadStream();
        auto out = std::make_shared<DeviceScalars>();
        if (!out->resize(src.size())) return nullptr;
        if (!gpuMemcpyH2D(out->data(), src.data(), src.size() * sizeof(u64), stream.raw()) ||
            !stream.sync())
        {
            return nullptr;
        }
        // The upload is complete. Do not retain a thread-local stream handle
        // that becomes invalid if this token outlives the producing thread.
        out->setProducerStream(nullptr);
        return out;
    }

    DeviceScalarsPtr sampleScalarsFromSeed(block seed, u64 count, u64 modulus)
    {
        if (!enabled() || !count || !modulus ||
            count > std::numeric_limits<std::size_t>::max() / sizeof(u64)) return nullptr;
        HostStep sampleStep("gpu: sample input scalars");
        struct RestoreStream
        {
            void* previous = gpuCurrentStream();
            ~RestoreStream() { gpuSetCurrentStream(previous); }
        } restoreStream;
        auto& stream = threadStream();
        auto out = std::make_shared<DeviceScalars>();
        std::array<u64, 2> seedWords{};
        std::memcpy(seedWords.data(), &seed, sizeof(seedWords));
        using DeviceAllocation = std::unique_ptr<void, decltype(&gpuFree)>;
        DeviceAllocation deviceSeed(nullptr, gpuFree);
        struct DrainStream
        {
            GpuStream& stream;
            ~DrainStream() { stream.sync(); }
        } drainStream{ stream };
        if (!out->resize(static_cast<std::size_t>(count))) return nullptr;
        deviceSeed.reset(gpuMalloc(sizeof(seedWords)));
        if (!deviceSeed || !gpuMemcpyH2D(deviceSeed.get(), seedWords.data(), sizeof(seedWords), stream.raw()) ||
            !launchAesCtrScalars(static_cast<const u64*>(deviceSeed.get()), out->data(),
                count, modulus, stream.raw()) || !stream.sync()) return nullptr;
        // Work is complete, so consumers need no dependency on this thread's
        // stream and may keep the result after the producing thread exits.
        out->setProducerStream(nullptr);
        return out;
    }
}

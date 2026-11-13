#include "libOTe/Vole/LogVole/LogVoleGpuCompatibility.h"
#include "libOTe/Vole/LogVole/LogVoleCpuRows.h"
#include "libOTe/Vole/LogVole/LogVoleLhe.h"
#include "libOTe/Vole/LogVole/LogVoleArithmetic.h"
#include "libOTe/Vole/LogVole/LogVolePublicCache.h"
#include "libOTe/Vole/LogVole/LogVoleCpuArithmetic.h"
#include "libOTe/Vole/LogVole/LogVoleCpuExecutor.h"
#include "libOTe/Vole/LogVole/LogVoleParallel.h"
#include "libOTe/Vole/LogVole/LogVoleRuntime.h"
#include "libOTe/config.h"
#include "seal/util/polyarithsmallmod.h"
#if defined(ENABLE_LOGVOLE_CUDA)
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuBackend.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuProtocol.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuKernels.h"
#endif

#include <algorithm>
#include <cstddef>
#include <cstdlib>
#include <limits>
#include <memory>
#include <mutex>

namespace osuCrypto::LogVole
{
    namespace
    {
        bool parallelLheSetupEnabled(const LogVoleGpuSetupOptions& options, const RingNttContext& ctx)
        {
            // Explicit 1 also permits CPU-only equivalence tests. The default
            // applies only to GPU protocols; 0 restores the serial setup.
            if (options.mParallelLhe != LogVoleChoice::Automatic)
                return options.mParallelLhe == LogVoleChoice::Enabled;
#if defined(ENABLE_LOGVOLE_CUDA)
            return gpu::enabled(ctx);
#else
            return false;
#endif
        }

        bool deviceLheSetupEnabled(const LogVoleGpuSetupOptions& options, const RingNttContext& ctx)
        {
#if defined(ENABLE_LOGVOLE_CUDA)
            return options.mLheDevice && gpu::enabled(ctx);
#else
            return false;
#endif
        }

        using PublicACacheKey = PublicPolynomialCache::Key;
        using PublicACacheEntry = PublicPolynomialCache::Entry;

        std::vector<RnsPoly> buildLhePublicANttImpl(const RingNttContext& ctx, u32 mu,
            std::shared_ptr<const gpu::RetainedPublicUniform>* captured, ProtocolCacheScopeView scope, PendingRingOpsStats* stats = legacyRingOpsThreadLocalStats())
        {
            // Legacy public A deliberately uses raw uniform residues despite
            // its Ntt suffix; retaining it must not introduce a transform.
            return deriveUniformPolyBatchFromNonce(ctx, 0xA11ACE5Eull, 0xA110CA7Aull, mu, false, captured, scope, stats);
        }

        std::shared_ptr<PublicACacheEntry> getOrCreateCachedPublicAEntry(
            const RingNttContext& ctx, u32 mu, ProtocolCacheScopeView scope, PendingRingOpsStats* stats = legacyRingOpsThreadLocalStats())
        {
            if (!ctx.mPublicCache) return {};
            auto& cache = ctx.mPublicCache->mLhe;
            PublicACacheKey key{};
            key.mRing = ctx.mParams;
            key.mCount = mu;
            key.mRunId = scope.mRunId;
            key.mRole = scope.mRole;
#if defined(ENABLE_LOGVOLE_CUDA)
            if (gpu::publicUniformRetentionEnabled(ctx.mExecutionOptions)) key.mDevice = gpu::currentDeviceOrdinal();
#endif

            {
                std::lock_guard<std::mutex> lock(cache.mMutex);
#if defined(ENABLE_LOGVOLE_CUDA)
                if (gpu::publicUniformRetentionEnabled(ctx.mExecutionOptions) && key.mRunId != 0)
                {
                    // A completed run's otherwise unowned host snapshot can
                    // retire; the retention registry holds only a weak owner.
                    for (auto entry = cache.mEntries.begin(); entry != cache.mEntries.end();)
                    {
                        if (entry->first.mRunId != 0 && entry->first.mRunId != key.mRunId &&
                            entry->second.use_count() == 1)
                            entry = cache.mEntries.erase(entry);
                        else ++entry;
                    }
                }
#endif
                auto it = cache.mEntries.find(key);
                if (it != cache.mEntries.end())
                {
                    return it->second;
                }
            }

            auto candidate = std::make_shared<PublicACacheEntry>();
            candidate->mIdentityService = key.mRunId.serviceOwner();
#if defined(ENABLE_LOGVOLE_CUDA)
            (void)retainUniformPolyBatchFromNonce(ctx, 0xA11ACE5Eull,
                0xA110CA7Aull, mu, false, candidate->mDevice, scope, stats);
#endif
            if (!candidate->mDevice)
            {
                std::shared_ptr<const gpu::RetainedPublicUniform> captured;
                candidate->mHost = std::make_shared<const std::vector<RnsPoly>>(
                    buildLhePublicANttImpl(ctx, mu, &captured, scope, stats));
                candidate->mDevice = std::move(captured);
#if defined(ENABLE_LOGVOLE_CUDA)
                if (candidate->mDevice)
                    (void)gpu::registerPublicUniformRetention(ctx, candidate->mHost, candidate->mDevice, scope);
#endif
            }

            std::lock_guard<std::mutex> lock(cache.mMutex);
            auto [it, inserted] = cache.mEntries.emplace(std::move(key), candidate);
            (void)inserted;
            return it->second;
        }

        std::shared_ptr<const std::vector<RnsPoly>> getOrCreateCachedPublicANtt(
            const RingNttContext& ctx, u32 mu, ProtocolCacheScopeView scope, PendingRingOpsStats* stats = legacyRingOpsThreadLocalStats())
        {
            auto entry = getOrCreateCachedPublicAEntry(ctx, mu, scope, stats);
            if (!entry) return {};
            std::lock_guard<std::mutex> lock(entry->mMutex);
            if (entry->mHost) return entry->mHost;
            std::shared_ptr<const std::vector<RnsPoly>> materialized;
#if defined(ENABLE_LOGVOLE_CUDA)
            if (entry->mDevice)
                (void)gpu::materializeRetainedPublicUniform(ctx, entry->mDevice, materialized, scope);
#endif
            if (!materialized)
                materialized = std::make_shared<const std::vector<RnsPoly>>(
                    buildLhePublicANttImpl(ctx, mu, nullptr, scope, stats));
            if (!materialized || materialized->size() != mu ||
                !validateRingBatchShape(*materialized, ctx.mParams)) return {};
            entry->mHost = std::move(materialized);
#if defined(ENABLE_LOGVOLE_CUDA)
            if (entry->mDevice)
                (void)gpu::registerPublicUniformRetention(ctx, entry->mHost, entry->mDevice, scope);
#endif
            return entry->mHost;
        }

        bool validatePublicANtt(const RingNttContext& ctx, const std::vector<RnsPoly>& publicANtt, u32 expectedCount)
        {
            return publicANtt.size() == expectedCount && validateRingBatchShape(publicANtt, ctx.mParams);
        }

        bool scaleByGPowerInplace(const RingNttContext& ctx, RnsPoly& poly, u32 gadgetLogBase, u32 power)
        {
            const auto& moduli = getRingHostModuli(ctx);
            if (moduli.empty()) return false;
            const u64 shift = static_cast<u64>(gadgetLogBase) * static_cast<u64>(power);
            if (shift > static_cast<u64>(std::numeric_limits<u32>::max()))
            {
                return false;
            }

            const std::size_t n = ctx.mParams.mPolyModulusDegree;
            for (std::size_t modIdx = 0; modIdx < moduli.size(); ++modIdx)
            {
                const u64 mod = moduli[modIdx].value();
                const std::size_t offset = modIdx * n;
                const u64 factor = detail::pow2Mod(shift, mod);
                for (std::size_t i = 0; i < n; ++i)
                {
                    const std::size_t idx = offset + i;
                    const u64 value = poly.mCoeffs[idx];
                    poly.mCoeffs[idx] = mulMod(
                        (value < mod) ? value : seal::util::barrett_reduce_64(value, moduli[modIdx]),
                        factor,
                        moduli[modIdx]);
                }
            }
            return true;
        }

        bool validateCt1Ntt(
            const RingNttContext& ctx,
            const RingTensor& ct1,
            u32 expectedCols)
        {
            return ct1.mRows != 0 &&
                   ct1.mCols == expectedCols &&
                   ringTensorSize(ct1) == ct1.mPolys.size() &&
                   validateRingBatchShape(ct1.mPolys, ctx.mParams);
        }
    }

    std::shared_ptr<const std::vector<RnsPoly>> sharedLhePublicANtt(
        const RingNttContext& ctx, u32 mu, ProtocolCacheScopeView scope, PendingRingOpsStats* stats)
    {
        return mu ? getOrCreateCachedPublicANtt(ctx, mu, scope, stats) : nullptr;
    }

    std::shared_ptr<const gpu::RetainedPublicUniform> retainedLhePublicANtt(
        const RingNttContext& ctx, u32 mu, ProtocolCacheScopeView scope, PendingRingOpsStats* stats)
    {
#if defined(ENABLE_LOGVOLE_CUDA)
        if (mu)
        {
            auto entry = getOrCreateCachedPublicAEntry(ctx, mu, scope, stats);
            if (entry && entry->mDevice && gpu::retainedPublicUniformMatches(
                    ctx, *entry->mDevice, mu, false, scope)) return entry->mDevice;
        }
#else
        (void)ctx;
        (void)mu;
#endif
        return {};
    }

    bool buildLhePublicANtt(const RingNttContext& ctx, u32 mu, std::vector<RnsPoly>& out, ProtocolCacheScopeView scope, PendingRingOpsStats* stats)
    {
        if (mu == 0)
        {
            return false;
        }
        out = *getOrCreateCachedPublicANtt(ctx, mu, scope, stats);
        return true;
    }

    bool multiplyByGPower(
        const RingNttContext& ctx,
        const RnsPoly& poly,
        u32 gadgetLogBase,
        u32 power,
        RnsPoly& out)
    {
        if (!validateRingPolyShape(poly, ctx.mParams))
        {
            return false;
        }

        out = poly;
        return scaleByGPowerInplace(ctx, out, gadgetLogBase, power);
    }

    static macoro::task<bool> lheEnc1Impl(
        macoro::thread_pool &executor, std::span<u8> setupResults, const RingNttContext &ctx,
        const std::vector<RnsPoly> &rInput, const std::vector<RnsPoly> &sk1, u32 gadgetLogBase,
        RingTensor &out, double noiseStandardDeviation, double noiseMaxDeviation, PRNG *prng,
        bool rInputIsNtt, const std::vector<RnsPoly> *publicANtt, u32 requestedWorkers, u32 rPowerOffset,
        std::shared_ptr<const LazyRingTensorHostState> *deferredCiphertext,
        std::shared_ptr<const LazyLencRandomizerState> randomizers, const gpu::DeviceBatch *rootR1Device,
        const LazyRootErrorHostState *rootR1Host, const gpu::DeviceBatch *rootSecretDevice,
        const LazyRootSecretHostState *rootSecretHost, ProtocolCacheRunId rootSecretOwnerRunId, bool topSecretDomain,
        LogVoleGpuSetupOptions options, CpuBenchmarkState cpuBenchmark, ProtocolCacheScope setupScope)
    {
        if (setupResults.empty()) co_return false;
        if (!cpuBenchmark.mContext) cpuBenchmark.mContext = cpuBenchmarkContext(ctx);
        if (cpuBenchmark.mContext && gpu::enabled(ctx))
        {
            const auto& limits = *cpuBenchmark.mContext;
            const auto capacity = std::max<std::size_t>(1, limits.mWorkerLimit
                ? std::min(limits.mWorkerLimit, limits.mCpus.size()) : limits.mCpus.size());
            setupResults = setupResults.first(std::min(setupResults.size(), capacity));
        }
        HostStep setupStep(hostProfiler(ctx), "setup: lhe ciphertext", &cpuBenchmark);
        const auto rCount = randomizers ? randomizers->count()
            : rootR1Host ? rootR1Host->count() : rInput.size();
        const auto skCount = rootSecretHost ? rootSecretHost->count() : sk1.size();
#if defined(ENABLE_LOGVOLE_CUDA)
        const bool rootBatchValid = !rootR1Device || !gpu::enabled(ctx) ||
            (rootR1Host && gpu::rootErrorBatchMatches(ctx, *rootR1Device, rCount, setupScope));
        const bool rootSecretValid = !rootSecretDevice || !gpu::enabled(ctx) ||
            (rootSecretHost && (topSecretDomain
                ? gpu::topSecretUniformBatchMatches(ctx, *rootSecretDevice,
                    skCount, rootSecretOwnerRunId, setupScope)
                : gpu::rootSecretUniformBatchMatches(ctx, *rootSecretDevice,
                    skCount, rootSecretOwnerRunId, false, setupScope)));
#else
        const bool rootBatchValid = !rootR1Device;
        const bool rootSecretValid = !rootSecretDevice;
#endif
        if (!rCount || rCount > std::numeric_limits<u32>::max() || !skCount ||
            skCount > std::numeric_limits<u32>::max() || noiseStandardDeviation < 0 ||
            (noiseStandardDeviation > 0 && !prng) || !rootBatchValid || !rootSecretValid ||
            (rootSecretHost ? (!sk1.empty() || !rootSecretHost->matches(ctx.mParams))
                            : !validateRingBatchShape(sk1, ctx.mParams)) ||
            (randomizers
                 ? (rootR1Host || !rInput.empty() || !rInputIsNtt || !randomizers->matches(ctx.mParams))
             : rootR1Host ? (!rInput.empty() || rInputIsNtt || !rootR1Host->matches(ctx.mParams))
                          : !validateRingBatchShape(rInput, ctx.mParams)) ||
            (rootSecretDevice && !rootSecretHost))
        {
            co_return false;
        }

        std::shared_ptr<const std::vector<RnsPoly>> cachedPublicANtt;
        std::shared_ptr<const gpu::RetainedPublicUniform> retainedPublicANtt;
        const u32 publicCount = static_cast<u32>(rCount);
        if (publicANtt)
        {
            if (!validatePublicANtt(ctx, *publicANtt, publicCount))
            {
                co_return false;
            }
        }
        else
        {
#if defined(ENABLE_LOGVOLE_CUDA)
            if (deviceLheSetupEnabled(options, ctx))
                retainedPublicANtt = [&]() {
                    PendingRingOpsStats pending(ctx.mExecutionOptions.mRingOpsStats);
                    auto* stats = gpu::enabled(ctx) ? legacyRingOpsThreadLocalStats()
                        : ctx.mExecutionOptions.mRingOpsStats ? &pending : nullptr;
                    return retainedLhePublicANtt(ctx, publicCount, setupScope, stats);
                }();
#endif
            if (!retainedPublicANtt)
            {
                cachedPublicANtt = [&]() {
                    PendingRingOpsStats pending(ctx.mExecutionOptions.mRingOpsStats);
                    auto* stats = gpu::enabled(ctx) ? legacyRingOpsThreadLocalStats()
                        : ctx.mExecutionOptions.mRingOpsStats ? &pending : nullptr;
                    return getOrCreateCachedPublicANtt(ctx, publicCount, setupScope, stats);
                }();
                publicANtt = cachedPublicANtt.get();
                if (!publicANtt || !validatePublicANtt(ctx, *publicANtt, publicCount)) co_return false;
            }
        }

        if (!gpu::enabled(ctx))
        {
            requestedWorkers = std::max(1u, requestedWorkers);
            if (parallelLheSetupEnabled(options, ctx) && setupResults.size() <
                std::min(std::size_t(requestedWorkers), rCount * skCount)) co_return false;
        }
        RingTensor ct1{};
        ct1.mRows = publicCount;
        ct1.mCols = static_cast<u32>(skCount);
        ct1.mPolys.resize(ringTensorSize(ct1));
        std::shared_ptr<const LazyRingTensorHostState> lazyCiphertext;
        std::vector<u64> compactNoise;
        std::shared_ptr<gpu::DeviceScalars> residentNoise;
        std::vector<seal::prng_seed_type> compactNoiseSeeds;
        const std::size_t noiseDegree = ctx.mParams.mPolyModulusDegree;
        const auto addCompactNoise = [&](std::size_t idx, RnsPoly& poly, PendingRingOpsStats* stats) {
            RnsPoly error;
            return expandPolyErrorCompact(
                    std::span<const u64>(compactNoise).subspan(idx * noiseDegree, noiseDegree), error, ctx) &&
                ringAddInplace(poly, error, ctx, stats);
        };
#if defined(ENABLE_LOGVOLE_CUDA)
        if (deviceLheSetupEnabled(options, ctx))
        {
            // An initial r1 residency decline still keeps the already-drawn
            // row seeds. Only that decline materializes host rows for the
            // ordinary GPU upload; successful token consumers see no host r1.
            const auto &deviceR = rootR1Host && !rootR1Device ? rootR1Host->hostCoefficients() : rInput;
            const auto& deviceSk = rootSecretHost && !rootSecretDevice
                ? rootSecretHost->hostCoefficients() : sk1;
            // Keep compact errors through GPU expansion and addition. Exact
            // resident sampling avoids a q0 download/upload between helpers.
            const bool compactRequested = options.mCompactNoise;
            const bool compactStrict = compactRequested && options.mCompactNoiseStrict;
            const bool compactEnabled = compactRequested &&
                canSamplePolyErrorCompact(ctx, noiseStandardDeviation, noiseMaxDeviation);
            if (compactStrict && !compactEnabled) co_return false;
            if (compactEnabled && noiseStandardDeviation > 0)
            {
                if (!noiseDegree || ct1.mPolys.size() > std::numeric_limits<std::size_t>::max() / noiseDegree)
                    co_return false;
                auto &noiseSeeds = compactNoiseSeeds;
                noiseSeeds.resize(ct1.mPolys.size());
                for (auto &seed : noiseSeeds) prng->get(seed.data(), seed.size());
                {
                    const bool setupOk = co_await samplePolyErrorCompactBatchForSetup(
                        executor, setupResults, compactNoise, residentNoise, noiseStandardDeviation,
                        noiseMaxDeviation, noiseSeeds, ctx, requestedWorkers, {}, cpuBenchmark);
                    if (!setupOk) co_return false;
                }
            }
            // A coefficient tensor can stay on device only after its noise is
            // complete. Unsupported compact samplers still add errors below
            // on the host, so keep their existing eager output.
            const bool deferCompletedCiphertext = deferredCiphertext &&
                (noiseStandardDeviation == 0 || !compactNoise.empty() || residentNoise);
            const bool assembled = gpu::assembleLheCiphertextDevice(
                ctx, deviceR, deviceSk,
                publicANtt ? std::span<const RnsPoly>{*publicANtt} : std::span<const RnsPoly>{},
                gadgetLogBase, rInputIsNtt,
                rPowerOffset, ct1.mPolys, compactNoise, residentNoise.get(), requestedWorkers,
                deferCompletedCiphertext ? &lazyCiphertext : nullptr, randomizers.get(),
                retainedPublicANtt.get(), rootR1Device,
                rootSecretDevice, rootSecretOwnerRunId, topSecretDomain, cpuBenchmark, setupScope);
            if (assembled)
            {
                // Keep the exact existing Gaussian sampler and row-major
                // parent seeds; device arithmetic consumes no protocol PRNG.
                if (noiseStandardDeviation > 0 && compactNoise.empty() && !residentNoise)
                {
                    std::vector<seal::prng_seed_type> noiseSeeds(ct1.mPolys.size());
                    for (auto &seed : noiseSeeds) prng->get(seed.data(), seed.size());
                    {
                        const auto taskCount = ct1.mPolys.size();
                        auto chunks = setupResults.first(
                            std::min({setupResults.size(), static_cast<std::size_t>(taskCount),
                                      static_cast<std::size_t>((requestedWorkers) ? (requestedWorkers)
                                                                                  : setupResults.size())}));
                        if (taskCount && chunks.empty()) co_return false;
                        std::fill(chunks.begin(), chunks.end(), u8{1});
                        auto item = [&](std::size_t idx, CpuBenchmarkState& cpuBenchmark, PendingRingOpsStats* stats) {
                            return addPolyErrorFromSeed(ct1.mPolys[idx], noiseStandardDeviation,
                                                        noiseMaxDeviation, noiseSeeds[idx], ctx, stats);
                        };
                        auto runChunk = [&](std::size_t begin, std::size_t end, u8 &ok) {
                            PendingRingOpsStats pending(ctx.mExecutionOptions.mRingOpsStats);
                            auto* stats = gpu::enabled(ctx) ? legacyRingOpsThreadLocalStats()
                                : ctx.mExecutionOptions.mRingOpsStats ? &pending : nullptr;
                            struct FlushLegacyStats
                            {
                                bool mEnabled;
                                ~FlushLegacyStats() { if (mEnabled) flushRingOpsThreadLocalStats(); }
                            } flushLegacy{gpu::enabled(ctx)};
                            CpuBenchmarkState worker = chunks.size() > 1
                                ? CpuBenchmarkState{cpuBenchmark.mContext, true} : cpuBenchmark;
                            CpuBenchmarkWorkerScope timing(chunks.size() > 1 ? worker.mContext : nullptr);
                            CpuBenchmarkTaskScope metrics(worker);
                            for (auto i = begin; i != end; ++i)
                                if (!item(i, worker, stats))
                                {
                                    ok = 0;
                                    break;
                                }
                        };
                        if (chunks.size() == 1) runChunk(0, taskCount, chunks[0]);
                        else if (taskCount)
                        {
                            co_await macoro::bulk_chunked(executor, taskCount, chunks, runChunk);
                        }
                        const bool phaseOk =
                            std::all_of(chunks.begin(), chunks.end(), [](u8 ok) { return ok != 0; });
                        if (!phaseOk) co_return false;
                    }
                }
                out = std::move(ct1);
                if (deferredCiphertext) *deferredCiphertext = std::move(lazyCiphertext);
                co_return true;
            }
            if (compactStrict || options.mLheDeviceStrict ||
                (topSecretDomain && options.mTopSecretConsumerStrict))
                co_return false;
        }
#endif
        if (residentNoise)
        {
            const bool setupOk = co_await materializePolyErrorCompactBatchForSetup(
                executor, setupResults, compactNoise, residentNoise, noiseStandardDeviation,
                noiseMaxDeviation, compactNoiseSeeds, ctx, requestedWorkers, {}, cpuBenchmark);
            if (!setupOk) co_return false;
        }
        if (!publicANtt)
        {
            // A device decline keeps PRNG consumption unchanged, then builds
            // the exact host fallback operand only when it is consumed.
            cachedPublicANtt = [&]() {
                PendingRingOpsStats pending(ctx.mExecutionOptions.mRingOpsStats);
                auto* stats = gpu::enabled(ctx) ? legacyRingOpsThreadLocalStats()
                        : ctx.mExecutionOptions.mRingOpsStats ? &pending : nullptr;
                return getOrCreateCachedPublicANtt(ctx, publicCount, setupScope, stats);
            }();
            publicANtt = cachedPublicANtt.get();
        }
        if (!publicANtt || !validatePublicANtt(ctx, *publicANtt, publicCount)) co_return false;
        // Device decline preserves r/sk and any sampled compact noise. Replay
        // those exact errors without drawing any additional parent seeds.
        const auto& r = randomizers ? randomizers->hostNtt()
            : rootR1Host ? rootR1Host->hostCoefficients() : rInput;
        const auto &sk = rootSecretHost ? rootSecretHost->hostCoefficients() : sk1;
        if (r.size() != rCount || !validateRingBatchShape(r, ctx.mParams)) co_return false;
        if (sk.size() != skCount || !validateRingBatchShape(sk, ctx.mParams)) co_return false;
        const auto &moduli = getRingHostModuli(ctx);
        if (moduli.empty()) co_return false;
        std::vector<RnsPoly> shiftedR;
        const std::vector<RnsPoly> *rSource = &r;
        if (rPowerOffset)
        {
            shiftedR.resize(r.size());
            const u32 shiftWorkers = parallelLheSetupEnabled(options, ctx) ? requestedWorkers : 1;
            {
                const auto taskCount = r.size();
                auto chunks = setupResults.first(std::min(
                    {setupResults.size(), static_cast<std::size_t>(taskCount),
                     static_cast<std::size_t>((shiftWorkers) ? (shiftWorkers) : setupResults.size())}));
                if (taskCount && chunks.empty()) co_return false;
                std::fill(chunks.begin(), chunks.end(), u8{1});
                auto item = [&](std::size_t i, CpuBenchmarkState& cpuBenchmark) {
                    return multiplyByGPower(ctx, r[i], gadgetLogBase, rPowerOffset, shiftedR[i]);
                };
                auto runChunk = [&](std::size_t begin, std::size_t end, u8 &ok) {
                    struct FlushLegacyStats
                    {
                        bool mEnabled;
                        ~FlushLegacyStats() { if (mEnabled) flushRingOpsThreadLocalStats(); }
                    } flushLegacy{gpu::enabled(ctx)};
                    CpuBenchmarkState worker = chunks.size() > 1
                        ? CpuBenchmarkState{cpuBenchmark.mContext, true} : cpuBenchmark;
                    CpuBenchmarkWorkerScope timing(chunks.size() > 1 ? worker.mContext : nullptr);
                    CpuBenchmarkTaskScope metrics(worker);
                    for (auto i = begin; i != end; ++i)
                        if (!item(i, worker))
                        {
                            ok = 0;
                            break;
                        }
                };
                if (chunks.size() == 1) runChunk(0, taskCount, chunks[0]);
                else if (taskCount)
                {
                    co_await macoro::bulk_chunked(executor, taskCount, chunks, runChunk);
                }
                const bool phaseOk = std::all_of(chunks.begin(), chunks.end(), [](u8 ok) { return ok != 0; });
                if (!phaseOk) co_return false;
            }
            rSource = &shiftedR;
        }

        // Both sets are independent transforms, so each goes as a single batch.
        std::vector<RnsPoly> sk1Ntt = sk;
        if (![&]() {
            PendingRingOpsStats pending(ctx.mExecutionOptions.mRingOpsStats);
            auto* stats = gpu::enabled(ctx) ? legacyRingOpsThreadLocalStats()
                        : ctx.mExecutionOptions.mRingOpsStats ? &pending : nullptr;
            return forwardNttBatch(sk1Ntt, ctx, stats);
        }())
        {
            co_return false;
        }

        std::vector<RnsPoly> rNtt = *rSource;
        if (!rInputIsNtt && ![&]() {
            PendingRingOpsStats pending(ctx.mExecutionOptions.mRingOpsStats);
            auto* stats = gpu::enabled(ctx) ? legacyRingOpsThreadLocalStats()
                        : ctx.mExecutionOptions.mRingOpsStats ? &pending : nullptr;
            return forwardNttBatch(rNtt, ctx, stats);
        }())
        {
            co_return false;
        }

        if (parallelLheSetupEnabled(options, ctx))
        {
            // Canonicalize each source once. Column zero then needs only a
            // copy; the remaining columns use SEAL's precomputed scalar
            // multiplier instead of a full modular multiply per coefficient.
            {
                const auto taskCount = rNtt.size();
                auto chunks = setupResults.first(
                    std::min({setupResults.size(), static_cast<std::size_t>(taskCount),
                              static_cast<std::size_t>((requestedWorkers) ? (requestedWorkers)
                                                                          : setupResults.size())}));
                if (taskCount && chunks.empty()) co_return false;
                std::fill(chunks.begin(), chunks.end(), u8{1});
                auto item = [&](std::size_t row, CpuBenchmarkState &cpuBenchmark) {
                    return canonicalizePoly(rNtt[row], ctx);
                };
                auto runChunk = [&](std::size_t begin, std::size_t end, u8 &ok) {
                    struct FlushLegacyStats
                    {
                        bool mEnabled;
                        ~FlushLegacyStats() { if (mEnabled) flushRingOpsThreadLocalStats(); }
                    } flushLegacy{gpu::enabled(ctx)};
                    CpuBenchmarkState worker = chunks.size() > 1
                        ? CpuBenchmarkState{cpuBenchmark.mContext, true} : cpuBenchmark;
                    CpuBenchmarkWorkerScope timing(chunks.size() > 1 ? worker.mContext : nullptr);
                    CpuBenchmarkTaskScope metrics(worker);
                    for (auto i = begin; i != end; ++i)
                        if (!item(i, worker))
                        {
                            ok = 0;
                            break;
                        }
                };
                if (chunks.size() == 1) runChunk(0, taskCount, chunks[0]);
                else if (taskCount)
                {
                    co_await macoro::bulk_chunked(executor, taskCount, chunks, runChunk);
                }
                const bool phaseOk = std::all_of(chunks.begin(), chunks.end(), [](u8 ok) { return ok != 0; });
                if (!phaseOk)
                {
                    co_return false;
                }
            }
            std::vector<std::vector<seal::util::MultiplyUIntModOperand>> factors(ct1.mCols);
            for (u32 col = 1; col < ct1.mCols; ++col)
            {
                const u64 shift = static_cast<u64>(gadgetLogBase) * col;
                if (shift > std::numeric_limits<u32>::max()) co_return false;
                factors[col].resize(moduli.size());
                for (std::size_t j = 0; j < moduli.size(); ++j)
                    factors[col][j].set(detail::pow2Mod(shift, moduli[j].value()), moduli[j]);
            }

            {
                const auto taskCount = ct1.mPolys.size();
                auto chunks = setupResults.first(
                    std::min({setupResults.size(), static_cast<std::size_t>(taskCount),
                              static_cast<std::size_t>((requestedWorkers) ? (requestedWorkers)
                                                                          : setupResults.size())}));
                if (taskCount && chunks.empty()) co_return false;
                std::fill(chunks.begin(), chunks.end(), u8{1});
                auto item = [&](std::size_t idx, CpuBenchmarkState& cpuBenchmark, PendingRingOpsStats* stats) {
                    const auto row = idx / ct1.mCols;
                    const auto col = idx % ct1.mCols;
                    auto& cNtt = ct1.mPolys[idx];
                    cNtt = rNtt[row];
                    if (col != 0)
                    {
                        const auto n = ctx.mParams.mPolyModulusDegree;
                        for (std::size_t j = 0; j < moduli.size(); ++j)
                        {
                            auto* coeffs = cNtt.mCoeffs.data() + j * n;
                            seal::util::multiply_poly_scalar_coeffmod(coeffs, n, factors[col][j], moduli[j],
                                                                      coeffs);
                        }
                    }
                    return dyadicMultiplyAddNttInplace((*publicANtt)[row], sk1Ntt[col], cNtt, ctx, stats);
                };
                auto runChunk = [&](std::size_t begin, std::size_t end, u8 &ok) {
                    PendingRingOpsStats pending(ctx.mExecutionOptions.mRingOpsStats);
                    auto* stats = gpu::enabled(ctx) ? legacyRingOpsThreadLocalStats()
                        : ctx.mExecutionOptions.mRingOpsStats ? &pending : nullptr;
                    struct FlushLegacyStats
                    {
                        bool mEnabled;
                        ~FlushLegacyStats() { if (mEnabled) flushRingOpsThreadLocalStats(); }
                    } flushLegacy{gpu::enabled(ctx)};
                    CpuBenchmarkState worker = chunks.size() > 1
                        ? CpuBenchmarkState{cpuBenchmark.mContext, true} : cpuBenchmark;
                    CpuBenchmarkWorkerScope timing(chunks.size() > 1 ? worker.mContext : nullptr);
                    CpuBenchmarkTaskScope metrics(worker);
                    for (auto i = begin; i != end; ++i)
                        if (!item(i, worker, stats))
                        {
                            ok = 0;
                            break;
                        }
                };
                if (chunks.size() == 1) runChunk(0, taskCount, chunks[0]);
                else if (taskCount)
                {
                    co_await macoro::bulk_chunked(executor, taskCount, chunks, runChunk);
                }
                const bool phaseOk = std::all_of(chunks.begin(), chunks.end(), [](u8 ok) { return ok != 0; });
                if (!phaseOk)
                {
                    co_return false;
                }
            }

            // The old inner loop ran one CPU inverse transform per ciphertext.
            // A batch amortizes the GPU transfer and launches over the matrix.
            if (![&]() {
                PendingRingOpsStats pending(ctx.mExecutionOptions.mRingOpsStats);
                auto* stats = gpu::enabled(ctx) ? legacyRingOpsThreadLocalStats()
                        : ctx.mExecutionOptions.mRingOpsStats ? &pending : nullptr;
                return inverseNttBatch(ct1.mPolys, ctx, stats);
            }()) co_return false;

            if (noiseStandardDeviation > 0)
            {
                // Preserve exactly the old row-major seed draws. Only the
                // independent SEAL samplers run concurrently; the protocol PRNG
                // is never touched by a worker.
                std::vector<seal::prng_seed_type> noiseSeeds;
                if (compactNoise.empty())
                {
                    noiseSeeds.resize(ct1.mPolys.size());
                    for (auto& seed : noiseSeeds) prng->get(seed.data(), seed.size());
                }
                {
                    const auto taskCount = ct1.mPolys.size();
                    auto chunks = setupResults.first(
                        std::min({setupResults.size(), static_cast<std::size_t>(taskCount),
                                  static_cast<std::size_t>((requestedWorkers) ? (requestedWorkers)
                                                                              : setupResults.size())}));
                    if (taskCount && chunks.empty()) co_return false;
                    std::fill(chunks.begin(), chunks.end(), u8{1});
                    auto item = [&](std::size_t idx, CpuBenchmarkState& cpuBenchmark, PendingRingOpsStats* stats) {
                        if (!compactNoise.empty()) return addCompactNoise(idx, ct1.mPolys[idx], stats);
                        return addPolyErrorFromSeed(ct1.mPolys[idx], noiseStandardDeviation,
                                                    noiseMaxDeviation, noiseSeeds[idx], ctx, stats);
                    };
                    auto runChunk = [&](std::size_t begin, std::size_t end, u8 &ok) {
                        PendingRingOpsStats pending(ctx.mExecutionOptions.mRingOpsStats);
                        auto* stats = gpu::enabled(ctx) ? legacyRingOpsThreadLocalStats()
                            : ctx.mExecutionOptions.mRingOpsStats ? &pending : nullptr;
                        struct FlushLegacyStats
                        {
                            bool mEnabled;
                            ~FlushLegacyStats() { if (mEnabled) flushRingOpsThreadLocalStats(); }
                        } flushLegacy{gpu::enabled(ctx)};
                        CpuBenchmarkState worker = chunks.size() > 1
                            ? CpuBenchmarkState{cpuBenchmark.mContext, true} : cpuBenchmark;
                        CpuBenchmarkWorkerScope timing(chunks.size() > 1 ? worker.mContext : nullptr);
                        CpuBenchmarkTaskScope metrics(worker);
                        for (auto i = begin; i != end; ++i)
                            if (!item(i, worker, stats))
                            {
                                ok = 0;
                                break;
                            }
                    };
                    if (chunks.size() == 1) runChunk(0, taskCount, chunks[0]);
                    else if (taskCount)
                    {
                        co_await macoro::bulk_chunked(executor, taskCount, chunks, runChunk);
                    }
                    const bool phaseOk =
                        std::all_of(chunks.begin(), chunks.end(), [](u8 ok) { return ok != 0; });
                    if (!phaseOk)
                    {
                        co_return false;
                    }
                }
            }
            out = std::move(ct1);
            if (deferredCiphertext) *deferredCiphertext = std::move(lazyCiphertext);
            co_return true;
        }

        {
            PendingRingOpsStats pending(ctx.mExecutionOptions.mRingOpsStats);
            auto* stats = gpu::enabled(ctx) ? legacyRingOpsThreadLocalStats()
                        : ctx.mExecutionOptions.mRingOpsStats ? &pending : nullptr;
            for (u32 row = 0; row < ct1.mRows; ++row)
            {
                const RnsPoly &aNtt = (*publicANtt)[row];
                for (u32 col = 0; col < ct1.mCols; ++col)
                {
                    RnsPoly cNtt = rNtt[row];
                    if (!scaleByGPowerInplace(ctx, cNtt, gadgetLogBase, col) ||
                        !dyadicMultiplyAddNttInplace(aNtt, sk1Ntt[col], cNtt, ctx, stats) || !inverseNtt(cNtt, ctx, stats))
                    {
                        co_return false;
                    }

                    if (noiseStandardDeviation > 0)
                    {
                        const auto idx = ringTensorIndex(ct1, row, col);
                        if (!(compactNoise.empty()
                                  ? addPolyError(cNtt, noiseStandardDeviation, noiseMaxDeviation, *prng, ctx, stats)
                                  : addCompactNoise(idx, cNtt, stats)))
                        {
                            co_return false;
                        }
                    }

                    ct1.mPolys[ringTensorIndex(ct1, row, col)] = std::move(cNtt);
                }
            }

        }

        out = std::move(ct1);
        if (deferredCiphertext) *deferredCiphertext = std::move(lazyCiphertext);
        co_return true;
    }

    macoro::task<bool> lheEnc1(macoro::thread_pool &executor, std::span<u8> setupResults,
                               const RingNttContext &ctx, const std::vector<RnsPoly> &r,
                               const std::vector<RnsPoly> &sk1, u32 gadgetLogBase, RingTensor &out,
                               double noiseStandardDeviation, double noiseMaxDeviation, PRNG *prng,
                               bool rInputIsNtt, const std::vector<RnsPoly> *publicANtt, u32 requestedWorkers,
                               std::shared_ptr<const LazyRingTensorHostState> *deferredCiphertext,
                               std::shared_ptr<const LazyLencRandomizerState> randomizers,
                               LogVoleGpuSetupOptions options, CpuBenchmarkState cpuBenchmark,
                               ProtocolCacheScope setupScope)
    {
        if (setupResults.empty()) co_return false;
        if (!cpuBenchmark.mContext) cpuBenchmark.mContext = cpuBenchmarkContext(ctx);
        {
            co_return co_await lheEnc1Impl(
                executor, setupResults, ctx, r, sk1, gadgetLogBase, out, noiseStandardDeviation,
                noiseMaxDeviation, prng, rInputIsNtt, publicANtt, requestedWorkers, 0u, deferredCiphertext,
                randomizers, nullptr, nullptr, nullptr, nullptr, 0, false, options, cpuBenchmark, setupScope);
        }
    }

    macoro::task<bool> lheEnc1Trunc(
        macoro::thread_pool &executor, std::span<u8> setupResults, const RingNttContext &ctx,
        const std::vector<RnsPoly> &r, const std::vector<RnsPoly> &sk1, u32 gadgetLogBase, RingTensor &out,
        double noiseStandardDeviation, double noiseMaxDeviation, PRNG *prng, bool rInputIsNtt,
        const std::vector<RnsPoly> *publicANtt, u32 requestedWorkers,
        std::shared_ptr<const LazyRingTensorHostState> *deferredCiphertext,
        std::shared_ptr<const LazyLencRandomizerState> randomizers, const gpu::DeviceBatch *rootR1Device,
        const LazyRootErrorHostState *rootR1Host, const gpu::DeviceBatch *rootSecretDevice,
        const LazyRootSecretHostState *rootSecretHost, ProtocolCacheRunId rootSecretOwnerRunId, bool topSecretDomain,
        LogVoleGpuSetupOptions options, CpuBenchmarkState cpuBenchmark, ProtocolCacheScope setupScope)
    {
        if (setupResults.empty()) co_return false;
        if (!cpuBenchmark.mContext) cpuBenchmark.mContext = cpuBenchmarkContext(ctx);
        {
            co_return co_await lheEnc1Impl(executor, setupResults, ctx, r, sk1, gadgetLogBase, out, noiseStandardDeviation,
                            noiseMaxDeviation, prng, rInputIsNtt, publicANtt, requestedWorkers, 1u,
                            deferredCiphertext, randomizers, rootR1Device, rootR1Host, rootSecretDevice,
                            rootSecretHost, rootSecretOwnerRunId, topSecretDomain, options, cpuBenchmark, setupScope);
        }
    }

    bool lheApplyCt1(
        const RingNttContext& ctx,
        const RingTensor& ct1,
        const RnsPoly& digest,
        u32 gadgetLogBase,
        u32 tau,
        std::vector<RnsPoly>& out,
        bool outputNtt,
        u32 requestedWorkers, PendingRingOpsStats* stats)
    {
        if (tau == 0 || !validateCt1Ntt(ctx, ct1, tau) || !validateRingPolyShape(digest, ctx.mParams))
        {
            return false;
        }

        std::vector<RnsPoly> u;
        if (!gadgetDecomposeBits(digest, gadgetLogBase, tau, ctx, u, requestedWorkers, stats))
        {
            return false;
        }
        // tau independent digit transforms; batch them.
        if (!forwardNttBatch(u, ctx, stats))
        {
            return false;
        }

        std::vector<RnsPoly> result(ct1.mRows);
        for (u32 row = 0; row < ct1.mRows; ++row)
        {
            RnsPoly accNtt{};
            resizeZero(accNtt.mCoeffs, ringPolyCoeffCount(ctx.mParams));

            for (u32 col = 0; col < tau; ++col)
            {
                const auto& cNtt = ct1.mPolys[ringTensorIndex(ct1, row, col)];
                if (!dyadicMultiplyAddNttInplace(cNtt, u[col], accNtt, ctx, stats))
                {
                    return false;
                }
            }

            if (!outputNtt && !inverseNtt(accNtt, ctx, stats))
            {
                return false;
            }
            result[row] = std::move(accNtt);
        }

        out = std::move(result);
        return true;
    }

    bool lheApplyCt1Trunc(
        const RingNttContext& ctx,
        const RingTensor& ct1,
        const RnsPoly& digest,
        u32 gadgetLogBase,
        u32 tauHi,
        std::vector<RnsPoly>& out,
        bool outputNtt,
        u32 requestedWorkers, PendingRingOpsStats* stats)
    {
        if (tauHi == 0 || !validateCt1Ntt(ctx, ct1, tauHi) || !validateRingPolyShape(digest, ctx.mParams))
        {
            return false;
        }

        std::vector<RnsPoly> uHi;
        if (!gadgetDecomposeBitsRangeCentered(digest, gadgetLogBase, 1, tauHi, ctx, uHi, requestedWorkers, stats))
        {
            return false;
        }
        for (auto& digit : uHi)
        {
            if (!forwardNtt(digit, ctx, stats))
            {
                return false;
            }
        }

        std::vector<RnsPoly> result(ct1.mRows);
        for (u32 row = 0; row < ct1.mRows; ++row)
        {
            RnsPoly accNtt{};
            resizeZero(accNtt.mCoeffs, ringPolyCoeffCount(ctx.mParams));

            for (u32 col = 0; col < tauHi; ++col)
            {
                const auto& cNtt = ct1.mPolys[ringTensorIndex(ct1, row, col)];
                if (!dyadicMultiplyAddNttInplace(cNtt, uHi[col], accNtt, ctx, stats))
                {
                    return false;
                }
            }

            if (!outputNtt && !inverseNtt(accNtt, ctx, stats))
            {
                return false;
            }
            result[row] = std::move(accNtt);
        }

        out = std::move(result);
        return true;
    }

    bool buildHashedCt2(
        const RingNttContext& ctx,
        u32 mu,
        std::span<const u8> seed,
        u64 sid,
        const RnsPoly& digest,
        u64 instanceIdx,
        std::vector<RnsPoly>& out, PendingRingOpsStats* stats)
    {
        if (mu == 0 || !validateRingPolyShape(digest, ctx.mParams))
        {
            return false;
        }

        const block ct2Seed = deriveSeedInstanceBlock(seed, sid, digest, instanceIdx, mu);
        deriveUniformPolyBatchFromSeedInplace(ctx, ct2Seed, 0xC720AA55u, mu, out, stats);
        return true;
    }

    // Synchronous row scheduling shared by both LHE representations. The
    // caller's lease owns the pool and locals until all partitions have joined.
    template<typename RowFn>
    static bool runLheRows(const RingNttContext& ctx, std::size_t rowCount,
        u32 requestedWorkers, CpuBenchmarkState cpuBenchmark,
        detail::CpuRowScratch* cpuScratch, std::size_t productWords,
        bool flushStats, RowFn&& decryptRow)
    {
        struct FlushStats
        {
            bool mEnabled;
            ~FlushStats() { if (mEnabled) flushRingOpsThreadLocalStats(); }
        };
        bool rowsOk = true;
        bool useCpuScratch = cpuScratch != nullptr;
#if defined(ENABLE_LOGVOLE_CUDA)
        useCpuScratch = useCpuScratch && !gpu::enabled(ctx);
#endif
        if (!useCpuScratch)
        {
            rowsOk = detail::runParallelTasks(rowCount, requestedWorkers,
                [&](std::size_t row, CpuBenchmarkState&) {
                    RnsPoly product;
                    return decryptRow(row, product);
                }, false, &cpuBenchmark);
        }
        else
        {
            const auto hardware = requestedWorkers == 1 ? std::size_t{1} :
                std::max<std::size_t>(1, std::thread::hardware_concurrency());
            auto capacity = hardware;
            if (const auto* benchmark = cpuBenchmark.mContext)
                capacity = std::max<std::size_t>(1, benchmark->mWorkerLimit
                    ? std::min(benchmark->mWorkerLimit, benchmark->mCpus.size()) : benchmark->mCpus.size());
            const auto workers = std::min({rowCount, capacity,
                requestedWorkers ? std::size_t(requestedWorkers) : hardware});
            if (workers == 1 && productWords == 0)
            {
                // No pool, partition metadata, or unused product allocation.
                CpuBenchmarkTaskScope metrics(cpuBenchmark);
                FlushStats flush{flushStats};
                RnsPoly unused;
                for (std::size_t row = 0; row < rowCount && rowsOk; ++row)
                    rowsOk = decryptRow(row, unused);
            }
            else
            {
                auto& scratch = *cpuScratch;
                auto locals = scratch.prepare(workers, productWords,
                    cpuBenchmark.mContext);
                const auto width = rowCount / workers;
                const auto extra = rowCount % workers;
                auto runPartition = [&](std::size_t partition, detail::CpuRowScratch::Local& local) {
                    // Persistent workers do not flush ring counters on thread
                    // exit between queries. Publish once per partition, also
                    // on failure, before bulk signals completion.
                    FlushStats flush{flushStats};
                    const auto begin = partition * width + std::min(partition, extra);
                    const auto end = begin + width + (partition < extra);
                    for (auto row = begin; row < end && local.mOk; ++row)
                        local.mOk = decryptRow(row, local.mProduct);
                };
                if (workers == 1)
                {
                    CpuBenchmarkTaskScope metrics(cpuBenchmark);
                    runPartition(0, locals[0]);
                }
                else scratch.executor()->runBulk(workers, locals, runPartition);
                for (const auto& local : locals) rowsOk &= local.mOk;
            }
        }
        return rowsOk;
    }

    // Shared row arithmetic for the async API and the deprecated entry points.
    static bool decryptLheRow(
        const RingNttContext& ctx, std::span<const seal::Modulus> moduli,
        const RnsPoly& publicA, const RnsPoly& skNtt, const RnsPoly& cipher,
        RnsPoly& result, RnsPoly& product, LheDomain domain, bool fused,
        PendingRingOpsStats* stats = legacyRingOpsThreadLocalStats())
    {
        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        if (domain == LheDomain::Ntt && fused)
        {
            for (std::size_t j = 0; j < moduli.size(); ++j)
            {
                const auto& modulus = moduli[j];
                const auto* a = publicA.mCoeffs.data() + j*n;
                const auto* b = skNtt.mCoeffs.data() + j*n;
                auto* c = result.mCoeffs.data() + j*n;
                if (!cpuDyadicMultiplySubtract(ctx.mCpuCapabilities, a, b, c, n, modulus))
                    for (std::size_t i = 0; i < n; ++i)
                        c[i] = seal::util::sub_uint_mod(seal::util::barrett_reduce_64(c[i], modulus),
                            mulMod(seal::util::barrett_reduce_64(a[i], modulus), b[i], modulus), modulus);
            }
            if (stats) { stats->bump(RingOp::DyadicMulAdd); stats->bump(RingOp::Sub); }
            return true;
        }
        product.mCoeffs.resize(ringPolyCoeffCount(ctx.mParams));
        std::fill(product.mCoeffs.begin(), product.mCoeffs.end(), u64{0});
        if (!dyadicMultiplyAddNttInplace(publicA, skNtt, product, ctx, stats)) return false;
        if (domain == LheDomain::Ntt) return ringSubInplace(result, product, ctx, stats);
        // cipher - INTT(A * NTT(sk)): retain the coefficient-domain shortcut.
        if (!inverseNtt(product, ctx, stats)) return false;
        for (std::size_t j = 0; j < moduli.size(); ++j)
        for (std::size_t k = 0; k < n; ++k)
        {
            const auto i = j*n + k;
            result.mCoeffs[i] = seal::util::sub_uint_mod(
                seal::util::barrett_reduce_64(cipher.mCoeffs[i], moduli[j]),
                product.mCoeffs[i], moduli[j]);
        }
        return true;
    }

    static bool lheDecImpl(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& cipher,
        const RnsPoly& sk,
        std::vector<RnsPoly>& out,
        const std::vector<RnsPoly>* publicANtt,
        bool cipherInputIsNtt,
        bool outputNtt,
        u32 requestedWorkers,
        std::vector<RnsPoly>* ownedCipher, CpuBenchmarkState cpuBenchmark, detail::CpuRowScratch* cpuScratch, ProtocolCacheScopeView scope)
    {
        if (!cpuBenchmark.mContext) cpuBenchmark.mContext = cpuBenchmarkContext(ctx);
        if (cipher.empty() || !validateRingBatchShape(cipher, ctx.mParams) || !validateRingPolyShape(sk, ctx.mParams))
        {
            return false;
        }
        const auto& moduli = getRingHostModuli(ctx);
        if (moduli.empty()) return false;

        std::shared_ptr<const std::vector<RnsPoly>> cachedPublicANtt;
        const u32 publicCount = static_cast<u32>(cipher.size());
        if (publicANtt)
        {
            if (!validatePublicANtt(ctx, *publicANtt, publicCount))
            {
                return false;
            }
        }
        else
        {
            // A device decline keeps PRNG consumption unchanged, then builds
            // the exact host fallback operand only when it is consumed.
            cachedPublicANtt = getOrCreateCachedPublicANtt(ctx, publicCount, scope);
            publicANtt = cachedPublicANtt.get();
        }

        RnsPoly skNtt = sk;
        if (!forwardNtt(skNtt, ctx))
        {
            return false;
        }

        if (!cipherInputIsNtt && !outputNtt)
        {
            // Linearity: INTT(NTT(cipher) - A*NTT(sk)) is exactly
            // cipher - INTT(A*NTT(sk)). The masks stay in coefficient form,
            // saving a forward transform per row. Each task owns its result;
            // the small root also gets parallel inverse transforms here.
            std::vector<RnsPoly> result(cipher.size());
            if (!runLheRows(ctx, result.size(), requestedWorkers, cpuBenchmark, cpuScratch, 0, true,
                [&](std::size_t row, RnsPoly&) {
                    return decryptLheRow(ctx, moduli, (*publicANtt)[row], skNtt, cipher[row],
                        result[row], result[row], LheDomain::Coefficient, false);
                })) return false;
            out = std::move(result);
            return true;
        }

        // The rows are independent, so both transforms are hoisted out of the loop
        // and batched. This is the Root recursion level's hot path, and it used to
        // pay one transform per row per direction; batching lets the CUDA backend
        // amortise a single device round trip over all of them.
        const bool inplace = ctx.mExecutionOptions.mAdvanced.mCpu.mInplaceLhe;
        std::vector<RnsPoly> result = inplace && ownedCipher && publicANtt != ownedCipher
            ? std::move(*ownedCipher) : std::vector<RnsPoly>(cipher.begin(), cipher.end());
        if (!cipherInputIsNtt && !forwardNttBatch(result, ctx))
        {
            return false;
        }

        auto decryptRow = [&](std::size_t row, RnsPoly& product) {
            return decryptLheRow(ctx, moduli, (*publicANtt)[row], skNtt, result[row],
                result[row], product, LheDomain::Ntt, inplace);
        };
        if (!runLheRows(ctx, result.size(), requestedWorkers, cpuBenchmark,
            cpuScratch, inplace ? 0 : ringPolyCoeffCount(ctx.mParams), true, decryptRow))
        {
            return false;
        }

        if (!outputNtt && !inverseNttBatch(result, ctx))
        {
            return false;
        }

        out = std::move(result);
        return true;
    }

    macoro::task<bool> lheDec(
        macoro::thread_pool& executor, std::span<LheDecryptBuffer> buffers,
        const RingNttContext& ctx, std::vector<RnsPoly>& ciphertextAndOutput,
        const RnsPoly& sk, const std::vector<RnsPoly>& publicANtt,
        LheDomain domain, CpuBenchmarkState cpuBenchmark)
    {
        if (gpu::enabled(ctx) || buffers.empty() || ciphertextAndOutput.empty() ||
            (domain != LheDomain::Coefficient && domain != LheDomain::Ntt) ||
            !validateRingBatchShape(ciphertextAndOutput, ctx.mParams) ||
            !validateRingPolyShape(sk, ctx.mParams) ||
            !validatePublicANtt(ctx, publicANtt, static_cast<u32>(ciphertextAndOutput.size())))
            co_return false;
        const auto& moduli = getRingHostModuli(ctx);
        if (moduli.empty()) co_return false;
        const bool fused = ctx.mExecutionOptions.mAdvanced.mCpu.mInplaceLhe;
        auto chunks = buffers.first(std::min(buffers.size(), ciphertextAndOutput.size()));
        if (domain == LheDomain::Coefficient || !fused)
            for (const auto& chunk : chunks)
                if (chunk.mProduct.mCoeffs.size() != ringPolyCoeffCount(ctx.mParams)) co_return false;
        if (!cpuBenchmark.mContext) cpuBenchmark.mContext = cpuBenchmarkContext(ctx);
        RnsPoly skNtt = sk;
        {
            PendingRingOpsStats pending(ctx.mExecutionOptions.mRingOpsStats);
            if (!forwardNtt(skNtt, ctx, ctx.mExecutionOptions.mRingOpsStats ? &pending : nullptr)) co_return false;
        }
        for (auto& chunk : chunks) chunk.mOk = true;
        auto decryptChunk = [&](std::size_t begin, std::size_t end, LheDecryptBuffer& chunk) {
            CpuBenchmarkState worker = chunks.size() > 1
                ? CpuBenchmarkState{cpuBenchmark.mContext, true} : cpuBenchmark;
            CpuBenchmarkWorkerScope timing(chunks.size() > 1 ? worker.mContext : nullptr);
            CpuBenchmarkTaskScope metrics(worker);
            PendingRingOpsStats pending(ctx.mExecutionOptions.mRingOpsStats);
            auto* stats = ctx.mExecutionOptions.mRingOpsStats ? &pending : nullptr;
            for (auto row = begin; row != end; ++row)
            {
                auto& value = ciphertextAndOutput[row];
                if (!decryptLheRow(ctx, moduli, publicANtt[row], skNtt, value,
                    value, chunk.mProduct, domain, fused, stats))
                {
                    chunk.mOk = false;
                    break;
                }
            }
        };
        if (chunks.size() == 1) decryptChunk(0, ciphertextAndOutput.size(), chunks[0]);
        else co_await macoro::bulk_chunked(executor, ciphertextAndOutput.size(), chunks, decryptChunk);
        for (const auto& chunk : chunks) if (!chunk.mOk) co_return false;
        co_return true;
    }

    bool detail::gpuLegacyLheDec(
        const RingNttContext& ctx, const std::vector<RnsPoly>& cipher, const RnsPoly& sk,
        std::vector<RnsPoly>& out, const std::vector<RnsPoly>* publicANtt,
        bool cipherInputIsNtt, bool outputNtt, u32 requestedWorkers, CpuBenchmarkState cpuBenchmark,
        detail::CpuRowScratch* cpuScratch, ProtocolCacheScopeView scope)
    {
        if (!cpuBenchmark.mContext) cpuBenchmark.mContext = cpuBenchmarkContext(ctx);
        return lheDecImpl(ctx, cipher, sk, out, publicANtt, cipherInputIsNtt, outputNtt, requestedWorkers, nullptr, cpuBenchmark, cpuScratch, scope);
    }

    bool detail::gpuLegacyLheDec(
        const RingNttContext& ctx, std::vector<RnsPoly>&& cipher, const RnsPoly& sk,
        std::vector<RnsPoly>& out, const std::vector<RnsPoly>* publicANtt,
        bool cipherInputIsNtt, bool outputNtt, u32 requestedWorkers, CpuBenchmarkState cpuBenchmark,
        detail::CpuRowScratch* cpuScratch, ProtocolCacheScopeView scope)
    {
        if (!cpuBenchmark.mContext) cpuBenchmark.mContext = cpuBenchmarkContext(ctx);
        return lheDecImpl(ctx, cipher, sk, out, publicANtt, cipherInputIsNtt, outputNtt, requestedWorkers, &cipher, cpuBenchmark, cpuScratch, scope);
    }

    bool deriveSkx(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& sk1,
        const RnsPoly& digest,
        const RnsPoly& tbkPrime,
        u32 gadgetLogBase,
        u32 tau,
        RnsPoly& out, PendingRingOpsStats* stats)
    {
        if (sk1.size() != tau ||
            !validateRingBatchShape(sk1, ctx.mParams) ||
            !validateRingPolyShape(digest, ctx.mParams) ||
            !validateRingPolyShape(tbkPrime, ctx.mParams))
        {
            return false;
        }

        std::vector<RnsPoly> u;
        if (!gadgetDecomposeBits(digest, gadgetLogBase, tau, ctx, u, 1, stats))
        {
            return false;
        }

        RnsPoly acc = tbkPrime;
        for (u32 i = 0; i < tau; ++i)
        {
            RnsPoly term{};
            if (!ringMultiply(sk1[i], u[i], ctx, term, stats) ||
                !ringAddInplace(acc, term, ctx, stats))
            {
                return false;
            }
        }

        out = std::move(acc);
        return true;
    }

    bool deriveSkxTrunc(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& sk1,
        const RnsPoly& digest,
        const RnsPoly& tbkPrime,
        u32 gadgetLogBase,
        u32 tauHi,
        RnsPoly& out, PendingRingOpsStats* stats)
    {
        if (tauHi == 0 || sk1.size() != tauHi ||
            !validateRingBatchShape(sk1, ctx.mParams) ||
            !validateRingPolyShape(digest, ctx.mParams) ||
            !validateRingPolyShape(tbkPrime, ctx.mParams))
        {
            return false;
        }

        std::vector<RnsPoly> uHi;
        if (!gadgetDecomposeBitsRangeCentered(digest, gadgetLogBase, 1, tauHi, ctx, uHi, 1, stats))
        {
            return false;
        }

        RnsPoly acc = tbkPrime;
        for (u32 i = 0; i < tauHi; ++i)
        {
            RnsPoly term{};
            if (!ringMultiply(sk1[i], uHi[i], ctx, term, stats) ||
                !ringAddInplace(acc, term, ctx, stats))
            {
                return false;
            }
        }

        out = std::move(acc);
        return true;
    }
}

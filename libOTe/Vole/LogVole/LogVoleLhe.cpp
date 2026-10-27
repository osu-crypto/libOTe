#include "libOTe/Vole/LogVole/LogVoleLhe.h"
#include "libOTe/Vole/LogVole/LogVoleArithmetic.h"
#include "libOTe/Vole/LogVole/LogVoleCpuArithmetic.h"
#include "libOTe/Vole/LogVole/LogVoleParallel.h"
#include "libOTe/Vole/LogVole/LogVoleRuntime.h"
#include "libOTe/config.h"
#include "seal/util/polyarithsmallmod.h"
#if defined(ENABLE_LOGVOLE_CUDA)
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuBackend.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuProtocol.h"
#endif

#include <algorithm>
#include <cstddef>
#include <cstdlib>
#include <limits>
#include <memory>
#include <mutex>
#include <unordered_map>

namespace osuCrypto::LogVole
{
    namespace
    {
        bool parallelLheSetupEnabled()
        {
            // Explicit 1 also permits CPU-only equivalence tests. The default
            // applies only to GPU protocols; 0 restores the serial setup.
            const char* value = std::getenv("LV_GPU_SETUP_LHE");
            if (value) return value[0] != '0';
#if defined(ENABLE_LOGVOLE_CUDA)
            return gpu::enabled();
#else
            return false;
#endif
        }

        bool deviceLheSetupEnabled()
        {
#if defined(ENABLE_LOGVOLE_CUDA)
            const char* value = std::getenv("LV_GPU_SETUP_LHE_DEVICE");
            return (!value || value[0] != '0') && gpu::enabled();
#else
            return false;
#endif
        }

        struct PublicACacheKey
        {
            RingParams mRing;
            u32 mCount = 0;
            u64 mRunId = 0;
            ProtocolCacheRole mRole = ProtocolCacheRole::Unspecified;
            int mDevice = -1;

            bool operator==(const PublicACacheKey& other) const
            {
                return mRing == other.mRing && mCount == other.mCount &&
                    mRunId == other.mRunId && mRole == other.mRole &&
                    mDevice == other.mDevice;
            }
        };

        struct PublicACacheKeyHash
        {
            std::size_t operator()(const PublicACacheKey& key) const
            {
                std::size_t h = std::hash<u32>{}(key.mRing.mPolyModulusDegree);
                h ^= std::hash<u32>{}(key.mCount) + 0x9e3779b9u + (h << 6u) + (h >> 2u);
                h ^= std::hash<u64>{}(key.mRunId) + 0x9e3779b9u + (h << 6u) + (h >> 2u);
                h ^= std::hash<u8>{}(static_cast<u8>(key.mRole)) +
                    0x9e3779b9u + (h << 6u) + (h >> 2u);
                h ^= std::hash<int>{}(key.mDevice) + 0x9e3779b9u + (h << 6u) + (h >> 2u);
                for (int bits : key.mRing.mCoeffModulusBits)
                {
                    const std::size_t b = std::hash<int>{}(bits);
                    h ^= b + 0x9e3779b9u + (h << 6u) + (h >> 2u);
                }
                return h;
            }
        };

        struct PublicACacheEntry
        {
            std::mutex mMutex;
            std::shared_ptr<const std::vector<RnsPoly>> mHost;
            std::shared_ptr<const gpu::RetainedPublicUniform> mDevice;
        };

        std::unordered_map<PublicACacheKey, std::shared_ptr<PublicACacheEntry>, PublicACacheKeyHash>
            publicACache;
        std::mutex publicACacheMutex;

        std::vector<RnsPoly> buildLhePublicANttImpl(const RingNttContext& ctx, u32 mu,
            std::shared_ptr<const gpu::RetainedPublicUniform>* captured = nullptr)
        {
            // Legacy public A deliberately uses raw uniform residues despite
            // its Ntt suffix; retaining it must not introduce a transform.
            return deriveUniformPolyBatchFromNonce(ctx, 0xA11ACE5Eull, 0xA110CA7Aull, mu, false, captured);
        }

        std::shared_ptr<PublicACacheEntry> getOrCreateCachedPublicAEntry(
            const RingNttContext& ctx, u32 mu)
        {
            PublicACacheKey key{};
            key.mRing = ctx.mParams;
            key.mCount = mu;
            const auto scope = currentProtocolCacheScope();
            key.mRunId = scope.mRunId;
            key.mRole = scope.mRole;
#if defined(ENABLE_LOGVOLE_CUDA)
            if (gpu::publicUniformRetentionEnabled()) key.mDevice = gpu::currentDeviceOrdinal();
#endif

            {
                std::lock_guard<std::mutex> lock(publicACacheMutex);
#if defined(ENABLE_LOGVOLE_CUDA)
                if (gpu::publicUniformRetentionEnabled() && key.mRunId != 0)
                {
                    // A completed run's otherwise unowned host snapshot can
                    // retire; the retention registry holds only a weak owner.
                    for (auto entry = publicACache.begin(); entry != publicACache.end();)
                    {
                        if (entry->first.mRunId != 0 && entry->first.mRunId != key.mRunId &&
                            entry->second.use_count() == 1)
                            entry = publicACache.erase(entry);
                        else ++entry;
                    }
                }
#endif
                auto it = publicACache.find(key);
                if (it != publicACache.end())
                {
                    return it->second;
                }
            }

            auto candidate = std::make_shared<PublicACacheEntry>();
#if defined(ENABLE_LOGVOLE_CUDA)
            (void)retainUniformPolyBatchFromNonce(ctx, 0xA11ACE5Eull,
                0xA110CA7Aull, mu, false, candidate->mDevice);
#endif
            if (!candidate->mDevice)
            {
                std::shared_ptr<const gpu::RetainedPublicUniform> captured;
                candidate->mHost = std::make_shared<const std::vector<RnsPoly>>(
                    buildLhePublicANttImpl(ctx, mu, &captured));
                candidate->mDevice = std::move(captured);
#if defined(ENABLE_LOGVOLE_CUDA)
                if (candidate->mDevice)
                    (void)gpu::registerPublicUniformRetention(ctx, candidate->mHost, candidate->mDevice);
#endif
            }

            std::lock_guard<std::mutex> lock(publicACacheMutex);
            auto [it, inserted] = publicACache.emplace(std::move(key), candidate);
            (void)inserted;
            return it->second;
        }

        std::shared_ptr<const std::vector<RnsPoly>> getOrCreateCachedPublicANtt(
            const RingNttContext& ctx, u32 mu)
        {
            auto entry = getOrCreateCachedPublicAEntry(ctx, mu);
            if (!entry) return {};
            std::lock_guard<std::mutex> lock(entry->mMutex);
            if (entry->mHost) return entry->mHost;
            std::shared_ptr<const std::vector<RnsPoly>> materialized;
#if defined(ENABLE_LOGVOLE_CUDA)
            if (entry->mDevice)
                (void)gpu::materializeRetainedPublicUniform(ctx, entry->mDevice, materialized);
#endif
            if (!materialized)
                materialized = std::make_shared<const std::vector<RnsPoly>>(
                    buildLhePublicANttImpl(ctx, mu));
            if (!materialized || materialized->size() != mu ||
                !validateRingBatchShape(*materialized, ctx.mParams)) return {};
            entry->mHost = std::move(materialized);
#if defined(ENABLE_LOGVOLE_CUDA)
            if (entry->mDevice)
                (void)gpu::registerPublicUniformRetention(ctx, entry->mHost, entry->mDevice);
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
        const RingNttContext& ctx, u32 mu)
    {
        return mu ? getOrCreateCachedPublicANtt(ctx, mu) : nullptr;
    }

    std::shared_ptr<const gpu::RetainedPublicUniform> retainedLhePublicANtt(
        const RingNttContext& ctx, u32 mu)
    {
#if defined(ENABLE_LOGVOLE_CUDA)
        if (mu)
        {
            auto entry = getOrCreateCachedPublicAEntry(ctx, mu);
            if (entry && entry->mDevice && gpu::retainedPublicUniformMatches(
                    ctx, *entry->mDevice, mu, false)) return entry->mDevice;
        }
#else
        (void)ctx;
        (void)mu;
#endif
        return {};
    }

    bool buildLhePublicANtt(const RingNttContext& ctx, u32 mu, std::vector<RnsPoly>& out)
    {
        if (mu == 0)
        {
            return false;
        }
        out = *getOrCreateCachedPublicANtt(ctx, mu);
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

    static bool lheEnc1Impl(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& rInput,
        const std::vector<RnsPoly>& sk1,
        u32 gadgetLogBase,
        RingTensor& out,
        double noiseStandardDeviation,
        double noiseMaxDeviation,
        PRNG* prng,
        bool rInputIsNtt,
        const std::vector<RnsPoly>* publicANtt,
        u32 requestedWorkers,
        u32 rPowerOffset,
        std::shared_ptr<const LazyRingTensorHostState>* deferredCiphertext,
        const std::shared_ptr<const LazyLencRandomizerState>& randomizers,
        const gpu::DeviceBatch* rootR1Device,
        const LazyRootErrorHostState* rootR1Host,
        const gpu::DeviceBatch* rootSecretDevice,
        const LazyRootSecretHostState* rootSecretHost,
        u64 rootSecretOwnerRunId,
        bool topSecretDomain)
    {
        HostStep setupStep("setup: lhe ciphertext");
        const auto rCount = randomizers ? randomizers->count()
            : rootR1Host ? rootR1Host->count() : rInput.size();
        const auto skCount = rootSecretHost ? rootSecretHost->count() : sk1.size();
#if defined(ENABLE_LOGVOLE_CUDA)
        const bool rootBatchValid = !rootR1Device || !gpu::enabled() ||
            (rootR1Host && gpu::rootErrorBatchMatches(ctx, *rootR1Device, rCount));
        const bool rootSecretValid = !rootSecretDevice || !gpu::enabled() ||
            (rootSecretHost && (topSecretDomain
                ? gpu::topSecretUniformBatchMatches(ctx, *rootSecretDevice,
                    skCount, rootSecretOwnerRunId)
                : gpu::rootSecretUniformBatchMatches(ctx, *rootSecretDevice,
                    skCount, rootSecretOwnerRunId)));
#else
        const bool rootBatchValid = !rootR1Device;
        const bool rootSecretValid = !rootSecretDevice;
#endif
        if (!rCount || rCount > std::numeric_limits<u32>::max() ||
            !skCount || skCount > std::numeric_limits<u32>::max() ||
            noiseStandardDeviation < 0 ||
            (noiseStandardDeviation > 0 && !prng) ||
            !rootBatchValid || !rootSecretValid ||
            (rootSecretHost ? (!sk1.empty() ||
                    !rootSecretHost->matches(ctx.mParams))
                            : !validateRingBatchShape(sk1, ctx.mParams)) ||
            (randomizers ? (rootR1Host || !rInput.empty() || !rInputIsNtt ||
                    !randomizers->matches(ctx.mParams))
                         : rootR1Host ? (!rInput.empty() || rInputIsNtt ||
                                !rootR1Host->matches(ctx.mParams))
                         : !validateRingBatchShape(rInput, ctx.mParams)) ||
            (rootSecretDevice && !rootSecretHost))
        {
            return false;
        }

        std::shared_ptr<const std::vector<RnsPoly>> cachedPublicANtt;
        std::shared_ptr<const gpu::RetainedPublicUniform> retainedPublicANtt;
        const u32 publicCount = static_cast<u32>(rCount);
        if (publicANtt)
        {
            if (!validatePublicANtt(ctx, *publicANtt, publicCount))
            {
                return false;
            }
        }
        else
        {
#if defined(ENABLE_LOGVOLE_CUDA)
            if (deviceLheSetupEnabled())
                retainedPublicANtt = retainedLhePublicANtt(ctx, publicCount);
#endif
            if (!retainedPublicANtt)
            {
                cachedPublicANtt = getOrCreateCachedPublicANtt(ctx, publicCount);
                publicANtt = cachedPublicANtt.get();
                if (!publicANtt || !validatePublicANtt(ctx, *publicANtt, publicCount)) return false;
            }
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
        const auto addCompactNoise = [&](std::size_t idx, RnsPoly& poly) {
            RnsPoly error;
            return expandPolyErrorCompact(
                    std::span<const u64>(compactNoise).subspan(idx * noiseDegree, noiseDegree), error, ctx) &&
                ringAddInplace(poly, error, ctx);
        };
#if defined(ENABLE_LOGVOLE_CUDA)
        if (deviceLheSetupEnabled())
        {
            // An initial r1 residency decline still keeps the already-drawn
            // row seeds. Only that decline materializes host rows for the
            // ordinary GPU upload; successful token consumers see no host r1.
            const auto& deviceR = rootR1Host && !rootR1Device
                ? rootR1Host->hostCoefficients() : rInput;
            const auto& deviceSk = rootSecretHost && !rootSecretDevice
                ? rootSecretHost->hostCoefficients() : sk1;
            const char* compactFlag = std::getenv("LV_GPU_SETUP_COMPACT_NOISE");
            const char* compactStrictFlag = std::getenv("LV_GPU_SETUP_COMPACT_NOISE_STRICT");
            // Keep compact errors through GPU expansion and addition. Exact
            // resident sampling avoids a q0 download/upload between helpers.
            const bool compactRequested = !compactFlag || compactFlag[0] != '0';
            const bool compactStrict = compactRequested && compactStrictFlag && compactStrictFlag[0] != '0';
            const bool compactEnabled = compactRequested &&
                canSamplePolyErrorCompact(ctx, noiseStandardDeviation, noiseMaxDeviation);
            if (compactStrict && !compactEnabled) return false;
            if (compactEnabled && noiseStandardDeviation > 0)
            {
                if (!noiseDegree || ct1.mPolys.size() >
                        std::numeric_limits<std::size_t>::max() / noiseDegree) return false;
                auto& noiseSeeds = compactNoiseSeeds;
                noiseSeeds.resize(ct1.mPolys.size());
                for (auto& seed : noiseSeeds) prng->get(seed.data(), seed.size());
                if (!samplePolyErrorCompactBatchForSetup(compactNoise, residentNoise, noiseStandardDeviation,
                    noiseMaxDeviation, noiseSeeds, ctx, requestedWorkers)) return false;
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
                rootSecretDevice, rootSecretOwnerRunId, topSecretDomain);
            if (assembled)
            {
                // Keep the exact existing Gaussian sampler and row-major
                // parent seeds; device arithmetic consumes no protocol PRNG.
                if (noiseStandardDeviation > 0 && compactNoise.empty() && !residentNoise)
                {
                    std::vector<seal::prng_seed_type> noiseSeeds(ct1.mPolys.size());
                    for (auto& seed : noiseSeeds) prng->get(seed.data(), seed.size());
                    if (!detail::runParallelTasks(ct1.mPolys.size(), requestedWorkers,
                        [&](std::size_t idx) {
                            return addPolyErrorFromSeed(ct1.mPolys[idx], noiseStandardDeviation,
                                noiseMaxDeviation, noiseSeeds[idx], ctx);
                        })) return false;
                }
                out = std::move(ct1);
                if (deferredCiphertext) *deferredCiphertext = std::move(lazyCiphertext);
                return true;
            }
            const char* strict = std::getenv("LV_GPU_SETUP_LHE_DEVICE_STRICT");
            const char* topStrict = std::getenv("LV_GPU_SETUP_TOP_SK1_CONSUMER_STRICT");
            if (compactStrict || (strict && strict[0] != '0') ||
                (topSecretDomain && topStrict && topStrict[0] != '0')) return false;
        }
#endif
        if (residentNoise && !materializePolyErrorCompactBatchForSetup(compactNoise, residentNoise,
                noiseStandardDeviation, noiseMaxDeviation, compactNoiseSeeds, ctx, requestedWorkers)) return false;
        if (!publicANtt)
        {
            // A device decline keeps PRNG consumption unchanged, then builds
            // the exact host fallback operand only when it is consumed.
            cachedPublicANtt = getOrCreateCachedPublicANtt(ctx, publicCount);
            publicANtt = cachedPublicANtt.get();
        }
        if (!publicANtt || !validatePublicANtt(ctx, *publicANtt, publicCount)) return false;
        // Device decline preserves r/sk and any sampled compact noise. Replay
        // those exact errors without drawing any additional parent seeds.
        const auto& r = randomizers ? randomizers->hostNtt()
            : rootR1Host ? rootR1Host->hostCoefficients() : rInput;
        const auto& sk = rootSecretHost ? rootSecretHost->hostCoefficients() : sk1;
        if (r.size() != rCount || !validateRingBatchShape(r, ctx.mParams)) return false;
        if (sk.size() != skCount || !validateRingBatchShape(sk, ctx.mParams)) return false;
        const auto& moduli = getRingHostModuli(ctx);
        if (moduli.empty()) return false;
        std::vector<RnsPoly> shiftedR;
        const std::vector<RnsPoly>* rSource = &r;
        if (rPowerOffset)
        {
            shiftedR.resize(r.size());
            const u32 shiftWorkers = parallelLheSetupEnabled() ? requestedWorkers : 1;
            if (!detail::runParallelTasks(r.size(), shiftWorkers, [&](std::size_t i) {
                    return multiplyByGPower(ctx, r[i], gadgetLogBase, rPowerOffset, shiftedR[i]);
                })) return false;
            rSource = &shiftedR;
        }

        // Both sets are independent transforms, so each goes as a single batch.
        std::vector<RnsPoly> sk1Ntt = sk;
        if (!forwardNttBatch(sk1Ntt, ctx))
        {
            return false;
        }

        std::vector<RnsPoly> rNtt = *rSource;
        if (!rInputIsNtt && !forwardNttBatch(rNtt, ctx))
        {
            return false;
        }


        if (parallelLheSetupEnabled())
        {
            // Canonicalize each source once. Column zero then needs only a
            // copy; the remaining columns use SEAL's precomputed scalar
            // multiplier instead of a full modular multiply per coefficient.
            if (!detail::runParallelTasks(rNtt.size(), requestedWorkers,
                    [&](std::size_t row) { return canonicalizePoly(rNtt[row], ctx); }))
            {
                return false;
            }
            std::vector<std::vector<seal::util::MultiplyUIntModOperand>> factors(ct1.mCols);
            for (u32 col = 1; col < ct1.mCols; ++col)
            {
                const u64 shift = static_cast<u64>(gadgetLogBase) * col;
                if (shift > std::numeric_limits<u32>::max()) return false;
                factors[col].resize(moduli.size());
                for (std::size_t j = 0; j < moduli.size(); ++j)
                    factors[col][j].set(detail::pow2Mod(shift, moduli[j].value()), moduli[j]);
            }

            if (!detail::runParallelTasks(ct1.mPolys.size(), requestedWorkers,
                [&](std::size_t idx) {
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
                            seal::util::multiply_poly_scalar_coeffmod(
                                coeffs, n, factors[col][j], moduli[j], coeffs);
                        }
                    }
                    return dyadicMultiplyAddNttInplace((*publicANtt)[row], sk1Ntt[col], cNtt, ctx);
                }))
            {
                return false;
            }

            // The old inner loop ran one CPU inverse transform per ciphertext.
            // A batch amortizes the GPU transfer and launches over the matrix.
            if (!inverseNttBatch(ct1.mPolys, ctx)) return false;

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
                if (!detail::runParallelTasks(ct1.mPolys.size(), requestedWorkers,
                    [&](std::size_t idx) {
                        if (!compactNoise.empty()) return addCompactNoise(idx, ct1.mPolys[idx]);
                        return addPolyErrorFromSeed(ct1.mPolys[idx], noiseStandardDeviation,
                            noiseMaxDeviation, noiseSeeds[idx], ctx);
                    }))
                {
                    return false;
                }
            }
            out = std::move(ct1);
            if (deferredCiphertext) *deferredCiphertext = std::move(lazyCiphertext);
            return true;
        }

        for (u32 row = 0; row < ct1.mRows; ++row)
        {
            const RnsPoly& aNtt = (*publicANtt)[row];
            for (u32 col = 0; col < ct1.mCols; ++col)
            {
                RnsPoly cNtt = rNtt[row];
                if (!scaleByGPowerInplace(ctx, cNtt, gadgetLogBase, col) ||
                    !dyadicMultiplyAddNttInplace(aNtt, sk1Ntt[col], cNtt, ctx) ||
                    !inverseNtt(cNtt, ctx))
                {
                    return false;
                }

                if (noiseStandardDeviation > 0)
                {
                    const auto idx = ringTensorIndex(ct1, row, col);
                    if (!(compactNoise.empty()
                            ? addPolyError(cNtt, noiseStandardDeviation, noiseMaxDeviation, *prng, ctx)
                            : addCompactNoise(idx, cNtt)))
                    {
                        return false;
                    }
                }

                ct1.mPolys[ringTensorIndex(ct1, row, col)] = std::move(cNtt);
            }
        }

        out = std::move(ct1);
        if (deferredCiphertext) *deferredCiphertext = std::move(lazyCiphertext);
        return true;
    }

    bool lheEnc1(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& r,
        const std::vector<RnsPoly>& sk1,
        u32 gadgetLogBase,
        RingTensor& out,
        double noiseStandardDeviation,
        double noiseMaxDeviation,
        PRNG* prng,
        bool rInputIsNtt,
        const std::vector<RnsPoly>* publicANtt,
        u32 requestedWorkers,
        std::shared_ptr<const LazyRingTensorHostState>* deferredCiphertext,
        std::shared_ptr<const LazyLencRandomizerState> randomizers)
    {
        return lheEnc1Impl(ctx, r, sk1, gadgetLogBase, out, noiseStandardDeviation,
            noiseMaxDeviation, prng, rInputIsNtt, publicANtt, requestedWorkers, 0u,
            deferredCiphertext, randomizers, nullptr, nullptr,
            nullptr, nullptr, 0, false);
    }

    bool lheEnc1Trunc(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& r,
        const std::vector<RnsPoly>& sk1,
        u32 gadgetLogBase,
        RingTensor& out,
        double noiseStandardDeviation,
        double noiseMaxDeviation,
        PRNG* prng,
        bool rInputIsNtt,
        const std::vector<RnsPoly>* publicANtt,
        u32 requestedWorkers,
        std::shared_ptr<const LazyRingTensorHostState>* deferredCiphertext,
        std::shared_ptr<const LazyLencRandomizerState> randomizers,
        const gpu::DeviceBatch* rootR1Device,
        const LazyRootErrorHostState* rootR1Host,
        const gpu::DeviceBatch* rootSecretDevice,
        const LazyRootSecretHostState* rootSecretHost,
        u64 rootSecretOwnerRunId,
        bool topSecretDomain)
    {
        return lheEnc1Impl(ctx, r, sk1, gadgetLogBase, out, noiseStandardDeviation,
            noiseMaxDeviation, prng, rInputIsNtt, publicANtt, requestedWorkers, 1u,
            deferredCiphertext, randomizers, rootR1Device, rootR1Host,
            rootSecretDevice, rootSecretHost, rootSecretOwnerRunId,
            topSecretDomain);
    }

    bool lheApplyCt1(
        const RingNttContext& ctx,
        const RingTensor& ct1,
        const RnsPoly& digest,
        u32 gadgetLogBase,
        u32 tau,
        std::vector<RnsPoly>& out,
        bool outputNtt,
        u32 requestedWorkers)
    {
        if (tau == 0 || !validateCt1Ntt(ctx, ct1, tau) || !validateRingPolyShape(digest, ctx.mParams))
        {
            return false;
        }

        std::vector<RnsPoly> u;
        if (!gadgetDecomposeBits(digest, gadgetLogBase, tau, ctx, u, requestedWorkers))
        {
            return false;
        }
        // tau independent digit transforms; batch them.
        if (!forwardNttBatch(u, ctx))
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
                if (!dyadicMultiplyAddNttInplace(cNtt, u[col], accNtt, ctx))
                {
                    return false;
                }
            }

            if (!outputNtt && !inverseNtt(accNtt, ctx))
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
        u32 requestedWorkers)
    {
        if (tauHi == 0 || !validateCt1Ntt(ctx, ct1, tauHi) || !validateRingPolyShape(digest, ctx.mParams))
        {
            return false;
        }

        std::vector<RnsPoly> uHi;
        if (!gadgetDecomposeBitsRangeCentered(digest, gadgetLogBase, 1, tauHi, ctx, uHi, requestedWorkers))
        {
            return false;
        }
        for (auto& digit : uHi)
        {
            if (!forwardNtt(digit, ctx))
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
                if (!dyadicMultiplyAddNttInplace(cNtt, uHi[col], accNtt, ctx))
                {
                    return false;
                }
            }

            if (!outputNtt && !inverseNtt(accNtt, ctx))
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
        std::vector<RnsPoly>& out)
    {
        if (mu == 0 || !validateRingPolyShape(digest, ctx.mParams))
        {
            return false;
        }

        const block ct2Seed = deriveSeedInstanceBlock(seed, sid, digest, instanceIdx, mu);
        deriveUniformPolyBatchFromSeedInplace(ctx, ct2Seed, 0xC720AA55u, mu, out);
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
        std::vector<RnsPoly>* ownedCipher)
    {
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
            cachedPublicANtt = getOrCreateCachedPublicANtt(ctx, publicCount);
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
            if (!detail::runParallelTasks(result.size(), requestedWorkers,
                [&](std::size_t row) {
                    auto& product = result[row];
                    resizeZero(product.mCoeffs, ringPolyCoeffCount(ctx.mParams));
                    if (!dyadicMultiplyAddNttInplace((*publicANtt)[row], skNtt, product, ctx) ||
                        !inverseNtt(product, ctx)) return false;
                    // The former forward transform canonicalized arbitrary
                    // input coefficients. Preserve that contract explicitly.
                    const std::size_t n = ctx.mParams.mPolyModulusDegree;
                    for (std::size_t j = 0; j < moduli.size(); ++j)
                    for (std::size_t k = 0; k < n; ++k)
                    {
                        const std::size_t i = j * n + k;
                        product.mCoeffs[i] = seal::util::sub_uint_mod(
                            seal::util::barrett_reduce_64(cipher[row].mCoeffs[i], moduli[j]),
                            product.mCoeffs[i], moduli[j]);
                    }
                    return true;
                })) return false;
            out = std::move(result);
            return true;
        }

        // The rows are independent, so both transforms are hoisted out of the loop
        // and batched. This is the Root recursion level's hot path, and it used to
        // pay one transform per row per direction; batching lets the CUDA backend
        // amortise a single device round trip over all of them.
        static const bool inplace = [] {
            const char* value = std::getenv("LV_CPU_INPLACE_LHE");
            return !value || value[0] != '0';
        }();
        std::vector<RnsPoly> result = inplace && ownedCipher && publicANtt != ownedCipher
            ? std::move(*ownedCipher) : std::vector<RnsPoly>(cipher.begin(), cipher.end());
        if (!cipherInputIsNtt && !forwardNttBatch(result, ctx))
        {
            return false;
        }

        // Rows are independent: each reads publicANtt[row] and skNtt and writes
        // only result[row]. Bit-identical, and it was serial.
        const bool rowsOk = detail::runParallelTasks(
            result.size(),
            requestedWorkers,
            [&](std::size_t row) -> bool
        {
            if (inplace)
            {
                const std::size_t n = ctx.mParams.mPolyModulusDegree;
                for (std::size_t j = 0; j < moduli.size(); ++j)
                {
                    const auto& modulus = moduli[j];
                    const auto* a = (*publicANtt)[row].mCoeffs.data() + j*n;
                    const auto* b = skNtt.mCoeffs.data() + j*n;
                    auto* c = result[row].mCoeffs.data() + j*n;
                    if (!detail::cpuDyadicMultiplySubtract(a, b, c, n, modulus))
                        for (std::size_t i = 0; i < n; ++i)
                            c[i] = seal::util::sub_uint_mod(seal::util::barrett_reduce_64(c[i], modulus),
                                mulMod(seal::util::barrett_reduce_64(a[i], modulus), b[i], modulus), modulus);
                }
                globalRingOpsStats.mDyadicMulAddCount.fetch_add(1, std::memory_order_relaxed);
                globalRingOpsStats.mSubCount.fetch_add(1, std::memory_order_relaxed);
                return true;
            }
            RnsPoly askNtt{};
            resizeZero(askNtt.mCoeffs, ringPolyCoeffCount(ctx.mParams));
            return dyadicMultiplyAddNttInplace((*publicANtt)[row], skNtt, askNtt, ctx) &&
                   ringSubInplace(result[row], askNtt, ctx);
        });
        if (!rowsOk)
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

    bool lheDec(
        const RingNttContext& ctx, const std::vector<RnsPoly>& cipher, const RnsPoly& sk,
        std::vector<RnsPoly>& out, const std::vector<RnsPoly>* publicANtt,
        bool cipherInputIsNtt, bool outputNtt, u32 requestedWorkers)
    {
        return lheDecImpl(ctx, cipher, sk, out, publicANtt, cipherInputIsNtt, outputNtt, requestedWorkers, nullptr);
    }

    bool lheDec(
        const RingNttContext& ctx, std::vector<RnsPoly>&& cipher, const RnsPoly& sk,
        std::vector<RnsPoly>& out, const std::vector<RnsPoly>* publicANtt,
        bool cipherInputIsNtt, bool outputNtt, u32 requestedWorkers)
    {
        return lheDecImpl(ctx, cipher, sk, out, publicANtt, cipherInputIsNtt, outputNtt, requestedWorkers, &cipher);
    }

    bool deriveSkx(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& sk1,
        const RnsPoly& digest,
        const RnsPoly& tbkPrime,
        u32 gadgetLogBase,
        u32 tau,
        RnsPoly& out)
    {
        if (sk1.size() != tau ||
            !validateRingBatchShape(sk1, ctx.mParams) ||
            !validateRingPolyShape(digest, ctx.mParams) ||
            !validateRingPolyShape(tbkPrime, ctx.mParams))
        {
            return false;
        }

        std::vector<RnsPoly> u;
        if (!gadgetDecomposeBits(digest, gadgetLogBase, tau, ctx, u))
        {
            return false;
        }

        RnsPoly acc = tbkPrime;
        for (u32 i = 0; i < tau; ++i)
        {
            RnsPoly term{};
            if (!ringMultiply(sk1[i], u[i], ctx, term) ||
                !ringAddInplace(acc, term, ctx))
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
        RnsPoly& out)
    {
        if (tauHi == 0 || sk1.size() != tauHi ||
            !validateRingBatchShape(sk1, ctx.mParams) ||
            !validateRingPolyShape(digest, ctx.mParams) ||
            !validateRingPolyShape(tbkPrime, ctx.mParams))
        {
            return false;
        }

        std::vector<RnsPoly> uHi;
        if (!gadgetDecomposeBitsRangeCentered(digest, gadgetLogBase, 1, tauHi, ctx, uHi))
        {
            return false;
        }

        RnsPoly acc = tbkPrime;
        for (u32 i = 0; i < tauHi; ++i)
        {
            RnsPoly term{};
            if (!ringMultiply(sk1[i], uHi[i], ctx, term) ||
                !ringAddInplace(acc, term, ctx))
            {
                return false;
            }
        }

        out = std::move(acc);
        return true;
    }
}

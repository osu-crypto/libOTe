#include "libOTe/Vole/LogVole/LogVoleCpuRows.h"
#include "libOTe/Vole/LogVole/LogVoleCpuExecutor.h"
#include "libOTe/Vole/LogVole/LogVoleLenc.h"
#include "libOTe/config.h"
#include "libOTe/Vole/LogVole/LogVoleArithmetic.h"
#include "libOTe/Vole/LogVole/LogVolePublicCache.h"
#include "libOTe/Vole/LogVole/LogVoleCpuArithmetic.h"
#include "libOTe/Vole/LogVole/LogVoleParallel.h"
#include "libOTe/Vole/LogVole/LogVoleRuntime.h"

#if defined(ENABLE_LOGVOLE_CUDA)
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuBackend.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuProtocol.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuKernels.h"
#endif

#include "seal/util/uintarithsmallmod.h"
#include "seal/util/ntt.h"
#include "seal/util/polyarithsmallmod.h"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <cstddef>
#include <exception>
#include <limits>
#include <mutex>

namespace osuCrypto::LogVole
{
    namespace
    {
        bool gpuSetupLencEnabled(const LogVoleGpuSetupOptions& options, const RingNttContext& ctx)
        {
            if (options.mParallelLenc != LogVoleChoice::Automatic)
                return options.mParallelLenc == LogVoleChoice::Enabled;
#if defined(ENABLE_LOGVOLE_CUDA)
            return gpu::enabled(ctx);
#else
            return false;
#endif
        }

        bool gpuSetupLencDeviceEnabled(const LogVoleGpuSetupOptions& options, const RingNttContext& ctx)
        {
#if defined(ENABLE_LOGVOLE_CUDA)
            return options.mLencDevice && gpu::enabled(ctx);
#else
            return false;
#endif
        }

        bool lencTreeWidth(std::size_t count, u32 requested, u32& width)
        {
            // A LENC tree needs an internal node for its digest and its first
            // randomizer layer. Pad a singleton with one zero leaf.
            if (count == 0 || count > (u64(1) << 31)) return false;
            width = requested;
            if (width == 0)
            {
                width = 2;
                while (width < count) width <<= 1;
            }
            return width >= 2 && width >= count && (width & (width - 1u)) == 0;
        }

        u32 ilog2Exact(u32 powerOfTwo)
        {
            u32 out = 0;
            while ((1u << out) < powerOfTwo)
            {
                ++out;
            }
            return out;
        }

        bool validateKeyDeriveSenderInput(const KeyDeriveSenderInput& input)
        {
            return validateRingParams(input.mParams) &&
                   !input.mSk1.empty() &&
                   input.mSk1.size() == input.mSk2.size() &&
                   validateRingBatchShape(input.mSk1, input.mParams) &&
                   validateRingBatchShape(input.mSk2, input.mParams);
        }

        bool validateKeyDeriveReceiverInput(const KeyDeriveReceiverInput& input)
        {
            return validateRingParams(input.mParams) &&
                   !input.mD.empty() &&
                   validateRingBatchShape(input.mD, input.mParams);
        }

        RnsPoly zeroPolyRaw(const RingNttContext& ctx)
        {
            RnsPoly out{};
            resizeZero(out.mCoeffs, ringPolyCoeffCount(ctx.mParams));
            return out;
        }

        bool negatePoly(const RingNttContext& ctx, RnsPoly poly, RnsPoly& out)
        {
            if (!validateRingPolyShape(poly, ctx.mParams)) return false;
            const auto& moduli = getRingHostModuli(ctx);
            if (moduli.empty()) return false;
            // The preceding inverse transform produced canonical coefficients.
            // Consume its buffer instead of allocating and copying a zero
            // polynomial for 0 - poly at every internal digest-tree node.
            const std::size_t n = ctx.mParams.mPolyModulusDegree;
            for (std::size_t j = 0; j < moduli.size(); ++j)
            {
                auto* coefficients = poly.mCoeffs.data() + j * n;
                seal::util::negate_poly_coeffmod(coefficients, n, moduli[j], coefficients);
            }
            globalRingOpsStats.mSubCount.fetch_add(1, std::memory_order_relaxed);
            out = std::move(poly);
            return true;
        }

        bool buildPaddedNttBatch(
            const RingNttContext& ctx,
            const std::vector<RnsPoly>& in,
            u32 widthPadded,
            std::vector<RnsPoly>& out,
            bool transformToNtt = true)
        {
            if (in.size() > widthPadded)
            {
                return false;
            }

            std::vector<RnsPoly> next(widthPadded);
            for (std::size_t i = 0; i < in.size(); ++i)
            {
                next[i] = in[i];
            }
            for (u32 i = static_cast<u32>(in.size()); i < widthPadded; ++i)
            {
                resizeZero(next[i].mCoeffs, ringPolyCoeffCount(ctx.mParams));
            }
            // widthPadded independent transforms, dispatched as a single batch.
            if (transformToNtt && !forwardNttBatch(next, ctx))
            {
                return false;
            }

            out = std::move(next);
            return true;
        }

        std::vector<RnsPoly> buildLencPublicBNttImpl(const RingNttContext& ctx, u32 tau,
            std::shared_ptr<const gpu::RetainedPublicUniform>* captured, ProtocolCacheScopeView scope)
        {
            return deriveUniformPolyBatchFromNonce(
                ctx, 0xC0DEC0DEull, 0x1EEC0DEu, 2u * tau, true, captured, scope);
        }

        using PublicBCacheKey = PublicPolynomialCache::Key;
        using PublicBCacheEntry = PublicPolynomialCache::Entry;

        std::shared_ptr<PublicBCacheEntry> getOrCreateCachedPublicBEntry(
            const RingNttContext& ctx, u32 tau, ProtocolCacheScopeView scope)
        {
            if (!ctx.mPublicCache) return {};
            auto& cache = ctx.mPublicCache->mLenc;
            PublicBCacheKey key{};
            key.mRing = ctx.mParams;
            key.mCount = tau;
            key.mRole = scope.mRole;
#if defined(ENABLE_LOGVOLE_CUDA)
            // Retained device operands belong to one cold protocol run. Keep
            // the old host-only cache scope when this feature is disabled.
            if (gpu::publicUniformRetentionEnabled(ctx.mExecutionOptions))
            {
                key.mRunId = scope.mRunId;
                key.mDevice = gpu::currentDeviceOrdinal();
            }
#endif

            {
                std::lock_guard<std::mutex> lock(cache.mMutex);
                // Run-scoped device retention must not accumulate a new full
                // host snapshot forever. Keep entries used by a concurrent
                // lookup, plus entries used outside a protocol run. Exported
                // results retain their own backing independently.
                if (key.mRunId != 0)
                {
                    for (auto entry = cache.mEntries.begin(); entry != cache.mEntries.end();)
                    {
                        if (entry->first.mRunId != 0 && entry->first.mRunId != key.mRunId &&
                            entry->second.use_count() == 1)
                            entry = cache.mEntries.erase(entry);
                        else ++entry;
                    }
                }
                auto it = cache.mEntries.find(key);
                if (it != cache.mEntries.end())
                {
                    return it->second;
                }
            }

            auto candidate = std::make_shared<PublicBCacheEntry>();
            candidate->mIdentityService = key.mRunId.serviceOwner();
#if defined(ENABLE_LOGVOLE_CUDA)
            (void)retainUniformPolyBatchFromNonce(ctx, 0xC0DEC0DEull,
                0x1EEC0DEu, 2u * tau, true, candidate->mDevice, scope);
#endif
            if (!candidate->mDevice)
            {
                std::shared_ptr<const gpu::RetainedPublicUniform> captured;
                candidate->mHost = std::make_shared<const std::vector<RnsPoly>>(
                    buildLencPublicBNttImpl(ctx, tau, &captured, scope));
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

        std::shared_ptr<const std::vector<RnsPoly>> getOrCreateCachedPublicBNtt(
            const RingNttContext& ctx, u32 tau, ProtocolCacheScopeView scope)
        {
            auto entry = getOrCreateCachedPublicBEntry(ctx, tau, scope);
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
                    buildLencPublicBNttImpl(ctx, tau, nullptr, scope));
            if (!materialized || materialized->size() != 2u * tau ||
                !validateRingBatchShape(*materialized, ctx.mParams)) return {};
            entry->mHost = std::move(materialized);
#if defined(ENABLE_LOGVOLE_CUDA)
            if (entry->mDevice)
                (void)gpu::registerPublicUniformRetention(ctx, entry->mHost, entry->mDevice, scope);
#endif
            return entry->mHost;
        }

        bool validatePublicBNtt(const RingNttContext& ctx, const std::vector<RnsPoly>& publicBNtt, u32 tau)
        {
            return publicBNtt.size() == 2u * tau && validateRingBatchShape(publicBNtt, ctx.mParams);
        }

        bool innerProductNttToStdPtrs(
            const RingNttContext& ctx,
            const RnsPoly* const* leftPtrs,
            const RnsPoly* const* rightPtrs,
            std::size_t size,
            RnsPoly& out)
        {
            if (size == 0)
            {
                return false;
            }

            RnsPoly accNtt{};
            resizeZero(accNtt.mCoeffs, ringPolyCoeffCount(ctx.mParams));

            if (!dyadicInnerProductNttInplace({leftPtrs, size}, {rightPtrs, size}, accNtt, ctx))
                return false;

            if (!inverseNtt(accNtt, ctx))
            {
                return false;
            }

            out = std::move(accNtt);
            return true;
        }

        u32 computeLeafTau(u32 plaintextModulusBits, u32 gadgetLogBase)
        {
            if (plaintextModulusBits == 0 || gadgetLogBase == 0)
            {
                return 0;
            }
            return (plaintextModulusBits + gadgetLogBase - 1u) / gadgetLogBase;
        }

        u32 computeTruncLeafTau(u32, u32 plaintextModulusBits, u32 gadgetLogBase, bool leafInputsAreGadget)
        {
            if (leafInputsAreGadget)
            {
                return 1;
            }
            return computeLeafTau(plaintextModulusBits, gadgetLogBase);
        }

        struct RecursiveLeafScaling
        {
            AlignedUnVec<u64> mCrtLiftModQj;
            AlignedUnVec<u64> mInvCrtLiftModQj;
        };

        bool buildRecursiveLeafScaling(const RingNttContext& ctx, RecursiveLeafScaling& out)
        {
            const auto& moduli = getRingHostModuli(ctx);
            const std::size_t rho = moduli.size();
            if (!rho) return false;
            RecursiveLeafScaling scaling{};
            resizeFill<u64>(scaling.mCrtLiftModQj, rho, 1);
            resizeFill<u64>(scaling.mInvCrtLiftModQj, rho, 1);

            for (std::size_t j = 0; j < rho; ++j)
            {
                const auto& modJ = moduli[j];
                u64 crtLiftModQj = 1;
                for (std::size_t w = 0; w < rho; ++w)
                {
                    if (w == j)
                    {
                        continue;
                    }
                    crtLiftModQj = seal::util::multiply_uint_mod(crtLiftModQj, moduli[w].value(), modJ);
                }
                scaling.mCrtLiftModQj[j] = crtLiftModQj;

                u64 invCrtLiftModQj = 0;
                if (!seal::util::try_invert_uint_mod(crtLiftModQj, modJ, invCrtLiftModQj))
                {
                    return false;
                }
                scaling.mInvCrtLiftModQj[j] = invCrtLiftModQj;
            }

            out = std::move(scaling);
            return true;
        }

        RnsPoly selectAndScaleLimbNtt(const RingNttContext& ctx, const RnsPoly& polyNtt, u32 limbIdx, u64 scaleModQj)
        {
            const auto& moduli = getRingHostModuli(ctx);
            if (limbIdx >= moduli.size()) return {};
            RnsPoly out{};
            resizeZero(out.mCoeffs, ringPolyCoeffCount(ctx.mParams));

            const std::size_t n = ctx.mParams.mPolyModulusDegree;
            const auto& modulus = moduli[limbIdx];
            const std::size_t offset = static_cast<std::size_t>(limbIdx) * n;
            for (std::size_t c = 0; c < n; ++c)
            {
                out.mCoeffs[offset + c] =
                    seal::util::multiply_uint_mod(polyNtt.mCoeffs[offset + c], scaleModQj, modulus);
            }

            return out;
        }

        bool recursiveLeafPairInnerProductNttToStd(
            const RingNttContext& ctx,
            const RnsPoly& leftBNtt,
            u32 leftLimb,
            u64 leftScaleModQj,
            const RnsPoly& leftDigitNtt,
            const RnsPoly& rightBNtt,
            u32 rightLimb,
            u64 rightScaleModQj,
            const RnsPoly& rightDigitNtt,
            RnsPoly& out)
        {
            const std::size_t coeffCount = ringPolyCoeffCount(ctx.mParams);
            if (leftBNtt.mCoeffs.size() != coeffCount || leftDigitNtt.mCoeffs.size() != coeffCount ||
                rightBNtt.mCoeffs.size() != coeffCount || rightDigitNtt.mCoeffs.size() != coeffCount ||
                leftLimb >= ringModulusCount(ctx) || rightLimb >= ringModulusCount(ctx))
            {
                return false;
            }

            RnsPoly accNtt{};
            resizeZero(accNtt.mCoeffs, coeffCount);
            const auto& moduli = getRingHostModuli(ctx);
            if (moduli.empty()) return false;

            const std::size_t n = ctx.mParams.mPolyModulusDegree;
            auto accumulateLimb = [&](const RnsPoly& bNtt, u32 limb, u64 scaleModQj, const RnsPoly& digitNtt) {
                const auto& modulus = moduli[limb];
                const std::size_t offset = static_cast<std::size_t>(limb) * n;
                AlignedUnVec<u64> scaled(n);
                seal::util::multiply_poly_scalar_coeffmod(
                    bNtt.mCoeffs.data() + offset, n, scaleModQj, modulus, scaled.data());
                if (cpuDyadicMultiplyAdd(ctx.mCpuCapabilities, scaled.data(), digitNtt.mCoeffs.data() + offset,
                    accNtt.mCoeffs.data() + offset, n, modulus)) return;
                for (std::size_t c = 0; c < n; ++c)
                {
                    const std::size_t idx = offset + c;
                    const u64 prod = seal::util::multiply_uint_mod(scaled[c], digitNtt.mCoeffs[idx], modulus);
                    accNtt.mCoeffs[idx] = seal::util::add_uint_mod(accNtt.mCoeffs[idx], prod, modulus);
                }
            };

            accumulateLimb(leftBNtt, leftLimb, leftScaleModQj, leftDigitNtt);
            accumulateLimb(rightBNtt, rightLimb, rightScaleModQj, rightDigitNtt);

            // The CRT-lifted leaves populate only these two limbs. Every other
            // limb is exactly zero and its inverse transform is also zero.
            const auto hostContext = getRingHostContext(ctx);
            if (!hostContext || !hostContext->key_context_data()) return false;
            const auto* tables = hostContext->key_context_data()->small_ntt_tables();
            seal::util::inverse_ntt_negacyclic_harvey(
                accNtt.mCoeffs.data() + leftLimb * n, tables[leftLimb]);
            if (rightLimb != leftLimb)
                seal::util::inverse_ntt_negacyclic_harvey(
                    accNtt.mCoeffs.data() + rightLimb * n, tables[rightLimb]);
            globalRingOpsStats.mInttCount.fetch_add(1, std::memory_order_relaxed);

            out = std::move(accNtt);
            return true;
        }

        std::vector<const RnsPoly*> makePublicBInternalHi(const std::vector<RnsPoly>& publicBFullNtt, u32 tauHi)
        {
            const u32 fullTau = tauHi + 1u;
            std::vector<const RnsPoly*> out(2u * tauHi);
            for (u32 i = 0; i < tauHi; ++i)
            {
                out[i] = &publicBFullNtt[1u + i];
            }
            for (u32 i = 0; i < tauHi; ++i)
            {
                out[tauHi + i] = &publicBFullNtt[fullTau + 1u + i];
            }
            return out;
        }

        std::vector<const RnsPoly*> makePublicBLeaf(
            const std::vector<RnsPoly>& publicBFullNtt,
            u32 tauHi,
            u32 tauLeaf)
        {
            const u32 fullTau = tauHi + 1u;
            std::vector<const RnsPoly*> out(2u * tauLeaf);
            for (u32 i = 0; i < tauLeaf; ++i)
            {
                out[i] = &publicBFullNtt[i];
                out[tauLeaf + i] = &publicBFullNtt[fullTau + i];
            }
            return out;
        }

        bool decomposeHiNtt(
            const RingNttContext& ctx,
            const RnsPoly& poly,
            u32 tauHi,
            u32 gadgetLogBase,
            std::vector<RnsPoly>& out)
        {
            std::vector<RnsPoly> hiDec;
            if (!gadgetDecomposeBitsRangeCentered(poly, gadgetLogBase, 1u, tauHi, ctx, hiDec, 1))
            {
                return false;
            }

            out.resize(tauHi);
            for (u32 i = 0; i < tauHi; ++i)
            {
                RnsPoly digitNtt = std::move(hiDec[i]);
                if (!forwardNttCanonical(digitNtt, ctx))
                {
                    return false;
                }
                out[i] = std::move(digitNtt);
            }
            return true;
        }

        bool decomposeLeafPaddedNtt(
            const RingNttContext& ctx,
            const RnsPoly& poly,
            u32 tauHi,
            u32 tauLeaf,
            u32 gadgetLogBase,
            std::vector<RnsPoly>& out)
        {
            std::vector<RnsPoly> leafDec;
            if (!gadgetDecomposeBits(poly, gadgetLogBase, tauLeaf, ctx, leafDec, 1))
            {
                return false;
            }

            out.resize(tauHi);
            for (u32 i = 0; i < tauLeaf; ++i)
            {
                RnsPoly digitNtt = std::move(leafDec[i]);
                if (!forwardNttCanonical(digitNtt, ctx))
                {
                    return false;
                }
                out[i] = std::move(digitNtt);
            }

            for (u32 i = tauLeaf; i < tauHi; ++i)
            {
                out[i] = zeroPolyRaw(ctx);
            }
            return true;
        }

        bool decomposeRecursiveLeafSingleDigitNtt(
            const RingNttContext& ctx,
            const RnsPoly& liftedPoly,
            u32 limbIdx,
            u64 invCrtLiftModQj,
            std::vector<RnsPoly>& out)
        {
            const auto& moduli = getRingHostModuli(ctx);
            if (limbIdx >= moduli.size()) return false;
            RnsPoly plainPoly{};
            plainPoly.mCoeffs.resize(ringPolyCoeffCount(ctx.mParams));

            const std::size_t n = ctx.mParams.mPolyModulusDegree;
            const auto& modulus = moduli[limbIdx];
            seal::util::MultiplyUIntModOperand inverseLift;
            inverseLift.set(invCrtLiftModQj, modulus);
            const std::size_t offset = static_cast<std::size_t>(limbIdx) * n;
            const bool vectorized = cpuUnliftCenteredRns(ctx.mCpuCapabilities,
                liftedPoly.mCoeffs.data() + offset, plainPoly.mCoeffs.data(), n,
                modulus, invCrtLiftModQj, moduli);
            for (std::size_t c = 0; !vectorized && c < n; ++c)
            {
                const u64 reduced =
                    seal::util::multiply_uint_mod(liftedPoly.mCoeffs[offset + c], inverseLift, modulus);
                const i64 centered = (reduced > (modulus.value() >> 1u))
                                         ? -static_cast<i64>(modulus.value() - reduced)
                                         : static_cast<i64>(reduced);

                for (std::size_t modIdx = 0; modIdx < moduli.size(); ++modIdx)
                {
                    const auto& modK = moduli[modIdx];
                    const std::size_t modOffset = modIdx * n + c;
                    if (centered < 0)
                    {
                        plainPoly.mCoeffs[modOffset] = modK.value() - static_cast<u64>(-centered);
                    }
                    else
                    {
                        plainPoly.mCoeffs[modOffset] = static_cast<u64>(centered);
                    }
                }
            }

            if (!(vectorized ? forwardNttCanonical(plainPoly, ctx) : forwardNtt(plainPoly, ctx)))
            {
                return false;
            }

            out.resize(1);
            out[0] = std::move(plainPoly);
            return true;
        }

        bool sampleErrorPolyNtt(
            const RingNttContext& ctx,
            PRNG& prng,
            double noiseStandardDeviation,
            double noiseMaxDeviation,
            RnsPoly& out)
        {
            RnsPoly noise{};
            resizeZero(noise.mCoeffs, ringPolyCoeffCount(ctx.mParams));
            const bool canonicalNoise = noiseMaxDeviation >= 0 &&
                [&] {
                    for (std::size_t limb = 0; limb < ringModulusCount(ctx); ++limb)
                        if (!(noiseMaxDeviation < static_cast<double>(ringModulusValue(ctx, limb)))) return false;
                    return true;
                }();
            if (!addPolyError(noise, noiseStandardDeviation, noiseMaxDeviation, prng, ctx) ||
                !(canonicalNoise ? forwardNttCanonical(noise, ctx) : forwardNtt(noise, ctx)))
            {
                return false;
            }
            out = std::move(noise);
            return true;
        }

        template<typename LeafAccessor>
        bool buildDigestTreeTruncImpl(
            const RingNttContext& ctx,
            u32 xCount,
            LeafAccessor leafAt,
            u32 tauHi,
            u32 gadgetLogBase,
            u32 plaintextModulusBits,
            u32 requestedWidthPadded,
            bool leafInputsAreGadget,
            const std::vector<RnsPoly>* publicBNtt,
            u32,
            DigestTree& out)
        {
            if (xCount == 0 || tauHi == 0)
            {
                return false;
            }

            const u32 tauLeaf = computeTruncLeafTau(tauHi, plaintextModulusBits, gadgetLogBase, leafInputsAreGadget);
            const u32 fullTau = tauHi + 1u;
            if (tauLeaf == 0 || tauLeaf > fullTau)
            {
                return false;
            }

            u32 width = 0;
            if (!lencTreeWidth(xCount, requestedWidthPadded, width)) return false;

            std::shared_ptr<const std::vector<RnsPoly>> cachedPublicBNtt;
            if (publicBNtt)
            {
                if (!validatePublicBNtt(ctx, *publicBNtt, fullTau))
                {
                    return false;
                }
            }
            else
            {
                cachedPublicBNtt = getOrCreateCachedPublicBNtt(ctx, fullTau, currentProtocolCacheScope());
                publicBNtt = cachedPublicBNtt.get();
            }

            const auto publicBInternalHi = makePublicBInternalHi(*publicBNtt, tauHi);
            const auto publicBLeaf = makePublicBLeaf(*publicBNtt, tauHi, tauLeaf);
            RecursiveLeafScaling leafScaling{};
            if (leafInputsAreGadget && !buildRecursiveLeafScaling(ctx, leafScaling))
            {
                return false;
            }

            const u32 levels = ilog2Exact(width);
            const u32 nodeCount = (2u * width) - 1u;

            DigestTree tree{};
            tree.mWidthPadded = width;
            tree.mLevels = levels;
            tree.mNodeDecompNtt.resize(nodeCount);

            RnsPoly zeroPadding{};
            if (width > xCount)
            {
                resizeZero(zeroPadding.mCoeffs, ringPolyCoeffCount(ctx.mParams));
            }

            HostStep leafStep(hostProfiler(ctx), leafInputsAreGadget
                ? "cpu shrink detail: recursive leaves" : "cpu shrink detail: initial leaves");
            for (u32 leaf = 0; leaf < width; ++leaf)
            {
                const u32 node = (width - 1u) + leaf;
                const RnsPoly& leafPoly = (leaf < xCount) ? leafAt(leaf) : zeroPadding;
                const u32 limb = leaf % static_cast<u32>(ringModulusCount(ctx));
                if (leafInputsAreGadget)
                {
                    if (!decomposeRecursiveLeafSingleDigitNtt(
                            ctx, leafPoly, limb, leafScaling.mInvCrtLiftModQj[limb], tree.mNodeDecompNtt[node]))
                    {
                        return false;
                    }
                }
                else if (!decomposeLeafPaddedNtt(ctx, leafPoly, tauLeaf, tauLeaf, gadgetLogBase, tree.mNodeDecompNtt[node]))
                {
                    return false;
                }
            }

            leafStep.stop();
            HostStep internalStep(hostProfiler(ctx), "cpu shrink detail: internal nodes");
            const u32 maxActiveTau = std::max(tauLeaf, tauHi);
            AlignedUnVec<const RnsPoly*> bPtrs(2u * maxActiveTau);
            AlignedUnVec<const RnsPoly*> pairPtrs(2u * maxActiveTau);

            for (int depth = static_cast<int>(levels) - 1; depth >= 0; --depth)
            {
                const bool useLeafLevel = depth == static_cast<int>(levels) - 1;
                const auto& bLevel = useLeafLevel ? publicBLeaf : publicBInternalHi;
                const u32 activeTau = useLeafLevel ? tauLeaf : tauHi;

                if (!(useLeafLevel && leafInputsAreGadget))
                {
                    if (bLevel.size() != 2u * activeTau)
                    {
                        return false;
                    }
                    for (std::size_t idx = 0; idx < bLevel.size(); ++idx)
                    {
                        bPtrs[idx] = bLevel[idx];
                    }
                }

                const u32 nodesAtDepth = static_cast<u32>(1u << depth);
                const u32 firstNode = nodesAtDepth - 1u;
                for (u32 depthIdx = 0; depthIdx < nodesAtDepth; ++depthIdx)
                {
                    const u32 p = firstNode + depthIdx;
                    const u32 left = (2u * p) + 1u;
                    const u32 right = left + 1u;

                    for (u32 i = 0; i < activeTau; ++i)
                    {
                        pairPtrs[i] = &tree.mNodeDecompNtt[left][i];
                        pairPtrs[activeTau + i] = &tree.mNodeDecompNtt[right][i];
                    }

                    RnsPoly dot{};
                    if (useLeafLevel && leafInputsAreGadget)
                    {
                        const u32 leftLeaf = left - (width - 1u);
                        const u32 rightLeaf = right - (width - 1u);
                        const u32 leftLimb = leftLeaf % static_cast<u32>(ringModulusCount(ctx));
                        const u32 rightLimb = rightLeaf % static_cast<u32>(ringModulusCount(ctx));
                        if (!recursiveLeafPairInnerProductNttToStd(
                                ctx, (*publicBNtt)[0], leftLimb, leafScaling.mCrtLiftModQj[leftLimb], *pairPtrs[0],
                                (*publicBNtt)[fullTau], rightLimb, leafScaling.mCrtLiftModQj[rightLimb], *pairPtrs[1],
                                dot))
                        {
                            return false;
                        }
                    }
                    else if (!innerProductNttToStdPtrs(ctx, bPtrs.data(), pairPtrs.data(), 2u * activeTau, dot))
                    {
                        return false;
                    }

                    RnsPoly nodeValue{};
                    if (!negatePoly(ctx, std::move(dot), nodeValue))
                    {
                        return false;
                    }

                    if (p == 0)
                    {
                        tree.mDigest = std::move(nodeValue);
                        continue;
                    }

                    if (!decomposeHiNtt(ctx, nodeValue, tauHi, gadgetLogBase, tree.mNodeDecompNtt[p]))
                    {
                        return false;
                    }
                }
            }

            out = std::move(tree);
            return true;
        }

        std::size_t ctRowIndex(u32 level, u32 leaf, u32 width)
        {
            return static_cast<std::size_t>(level) * width + leaf;
        }
    }

    bool prepareKeyDeriveRequest(
        const KeyDeriveReceiverInput& input,
        KeyDeriveRequest& out)
    {
        if (!validateKeyDeriveReceiverInput(input) ||
            input.mD.size() > static_cast<std::size_t>(std::numeric_limits<u32>::max()))
        {
            return false;
        }

        KeyDeriveRequest next{};
        next.mPolyModulusDegree = input.mParams.mPolyModulusDegree;
        next.mCoeffModulusCount = static_cast<u32>(input.mParams.mCoeffModulusBits.size());
        next.mTau = static_cast<u32>(input.mD.size());
        next.mDCoeffs = packRingBatch(input.mD);

        out = std::move(next);
        return true;
    }

    bool processKeyDeriveRequest(
        const KeyDeriveSenderInput& input,
        const KeyDeriveRequest& request,
        KeyDeriveResponse& response,
        KeyDeriveSenderOutput& output, ProtocolCacheScopeView scope)
    {
        if (!validateKeyDeriveSenderInput(input))
        {
            return false;
        }

        const u32 expectedModCount = static_cast<u32>(input.mParams.mCoeffModulusBits.size());
        if (request.mPolyModulusDegree != input.mParams.mPolyModulusDegree ||
            request.mCoeffModulusCount != expectedModCount ||
            request.mTau != input.mSk1.size())
        {
            return false;
        }

        std::vector<RnsPoly> dBatch;
        if (!unpackRingBatch(
                request.mTau,
                request.mPolyModulusDegree,
                request.mCoeffModulusCount,
                request.mDCoeffs,
                dBatch))
        {
            return false;
        }

        RingNttContext ctx{};
        if (!makeRingNttContext(input.mParams, ctx, std::shared_ptr<RingContextFactory>{}, scope))
        {
            return false;
        }

        std::vector<RnsPoly> mNttBatch(request.mTau);

        for (std::size_t i = 0; i < request.mTau; ++i)
        {
            RnsPoly sk1 = input.mSk1[i];
            RnsPoly sk2 = input.mSk2[i];
            RnsPoly d = std::move(dBatch[i]);

            if (!forwardNtt(sk1, ctx) ||
                !forwardNtt(sk2, ctx) ||
                !forwardNtt(d, ctx))
            {
                return false;
            }

            RnsPoly mNtt{};
            if (!dyadicMultiplyAddNtt(sk1, d, sk2, ctx, mNtt))
            {
                return false;
            }
            mNttBatch[i] = std::move(mNtt);
        }

        KeyDeriveResponse nextResponse{};
        nextResponse.mPolyModulusDegree = request.mPolyModulusDegree;
        nextResponse.mCoeffModulusCount = request.mCoeffModulusCount;
        nextResponse.mTau = request.mTau;
        nextResponse.mMNttCoeffs = packRingBatch(mNttBatch);

        KeyDeriveSenderOutput nextOutput{};
        nextOutput.mK = input.mSk2;

        response = std::move(nextResponse);
        output = std::move(nextOutput);
        return true;
    }

    bool finalizeKeyDeriveResponse(
        const KeyDeriveReceiverInput& input,
        const KeyDeriveResponse& response,
        KeyDeriveReceiverOutput& output, ProtocolCacheScopeView scope)
    {
        if (!validateKeyDeriveReceiverInput(input))
        {
            return false;
        }

        const u32 expectedModCount = static_cast<u32>(input.mParams.mCoeffModulusBits.size());
        if (response.mPolyModulusDegree != input.mParams.mPolyModulusDegree ||
            response.mCoeffModulusCount != expectedModCount ||
            response.mTau != input.mD.size())
        {
            return false;
        }

        std::vector<RnsPoly> mNttBatch;
        if (!unpackRingBatch(
                response.mTau,
                response.mPolyModulusDegree,
                response.mCoeffModulusCount,
                response.mMNttCoeffs,
                mNttBatch))
        {
            return false;
        }

        RingNttContext ctx{};
        if (!makeRingNttContext(input.mParams, ctx, std::shared_ptr<RingContextFactory>{}, scope))
        {
            return false;
        }

        KeyDeriveReceiverOutput next{};
        next.mM.resize(response.mTau);

        for (std::size_t i = 0; i < mNttBatch.size(); ++i)
        {
            auto& poly = mNttBatch[i];
            if (!canonicalizePoly(poly, ctx) ||
                !inverseNtt(poly, ctx))
            {
                return false;
            }
            next.mM[i] = std::move(poly);
        }

        output = std::move(next);
        return true;
    }

    std::shared_ptr<const std::vector<RnsPoly>> sharedLencPublicBNtt(
        const RingNttContext& ctx, u32 tau, ProtocolCacheScopeView scope)
    {
        return getOrCreateCachedPublicBNtt(ctx, tau, scope);
    }

    std::shared_ptr<const gpu::RetainedPublicUniform> retainedLencPublicBNtt(
        const RingNttContext& ctx, u32 tau, ProtocolCacheScopeView scope)
    {
#if defined(ENABLE_LOGVOLE_CUDA)
        auto entry = getOrCreateCachedPublicBEntry(ctx, tau, scope);
        if (entry && entry->mDevice && gpu::retainedPublicUniformMatches(
                ctx, *entry->mDevice, 2u * tau, true, scope)) return entry->mDevice;
#else
        (void)ctx;
        (void)tau;
#endif
        return {};
    }

    std::vector<RnsPoly> buildLencPublicBNtt(const RingNttContext& ctx, u32 tau, ProtocolCacheScopeView scope)
    {
        auto cached = getOrCreateCachedPublicBNtt(ctx, tau, scope);
        return *cached;
    }

    bool buildDigestTree(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& x,
        u32 tau,
        u32 gadgetLogBase,
        DigestTree& out,
        u32 requestedWidthPadded,
        const std::vector<RnsPoly>* publicBNtt,
        u32 requestedWorkers)
    {
        return buildDigestTree(
            ctx,
            std::span<const RnsPoly>(x.data(), x.size()),
            tau,
            gadgetLogBase,
            out,
            requestedWidthPadded,
            publicBNtt,
            requestedWorkers);
    }

    bool buildDigestTree(
        const RingNttContext& ctx,
        std::span<const RnsPoly> x,
        u32 tau,
        u32 gadgetLogBase,
        DigestTree& out,
        u32 requestedWidthPadded,
        const std::vector<RnsPoly>* publicBNtt,
        u32)
    {
        if (x.empty() || tau == 0 || !validateRingBatchShape(x, ctx.mParams))
        {
            return false;
        }

        u32 width = 0;
        if (!lencTreeWidth(x.size(), requestedWidthPadded, width)) return false;

        std::shared_ptr<const std::vector<RnsPoly>> cachedPublicBNtt;
        if (publicBNtt)
        {
            if (!validatePublicBNtt(ctx, *publicBNtt, tau))
            {
                return false;
            }
        }
        else
        {
            cachedPublicBNtt = getOrCreateCachedPublicBNtt(ctx, tau, currentProtocolCacheScope());
            publicBNtt = cachedPublicBNtt.get();
        }

        const u32 levels = ilog2Exact(width);
        const u32 nodeCount = (2u * width) - 1u;

        DigestTree tree{};
        tree.mWidthPadded = width;
        tree.mLevels = levels;
        tree.mNodeDecompNtt.resize(nodeCount);

        AlignedUnVec<const RnsPoly*> bPtrs(2u * tau);
        for (std::size_t idx = 0; idx < publicBNtt->size(); ++idx)
        {
            bPtrs[idx] = &(*publicBNtt)[idx];
        }

        RnsPoly zeroPadding{};
        if (width > x.size())
        {
            resizeZero(zeroPadding.mCoeffs, ringPolyCoeffCount(ctx.mParams));
        }

        for (u32 leaf = 0; leaf < width; ++leaf)
        {
            const u32 node = (width - 1u) + leaf;
            const RnsPoly& leafPoly = (leaf < x.size()) ? x[leaf] : zeroPadding;
            if (!gadgetDecomposeBits(leafPoly, gadgetLogBase, tau, ctx, tree.mNodeDecompNtt[node], 1))
            {
                return false;
            }
            for (auto& poly : tree.mNodeDecompNtt[node])
            {
                if (!forwardNtt(poly, ctx))
                {
                    return false;
                }
            }
        }

        AlignedUnVec<const RnsPoly*> pairPtrs(2u * tau);
        for (int depth = static_cast<int>(levels) - 1; depth >= 0; --depth)
        {
            const u32 nodesAtDepth = static_cast<u32>(1u << depth);
            const u32 firstNode = nodesAtDepth - 1u;
            for (u32 depthIdx = 0; depthIdx < nodesAtDepth; ++depthIdx)
            {
                const u32 p = firstNode + depthIdx;
                const u32 left = (2u * p) + 1u;
                const u32 right = left + 1u;

                for (u32 i = 0; i < tau; ++i)
                {
                    pairPtrs[i] = &tree.mNodeDecompNtt[left][i];
                    pairPtrs[tau + i] = &tree.mNodeDecompNtt[right][i];
                }

                RnsPoly dot{};
                RnsPoly nodeValue{};
                if (!innerProductNttToStdPtrs(ctx, bPtrs.data(), pairPtrs.data(), 2u * tau, dot) ||
                    !negatePoly(ctx, std::move(dot), nodeValue))
                {
                    return false;
                }

                if (p == 0)
                {
                    tree.mDigest = std::move(nodeValue);
                    continue;
                }

                if (!gadgetDecomposeBits(nodeValue, gadgetLogBase, tau, ctx, tree.mNodeDecompNtt[p], 1))
                {
                    return false;
                }
                for (auto& poly : tree.mNodeDecompNtt[p])
                {
                    if (!forwardNtt(poly, ctx))
                    {
                        return false;
                    }
                }
            }
        }

        out = std::move(tree);
        return true;
    }

    bool lencEnc(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& s,
        u32 tau,
        u32 gadgetLogBase,
        PRNG& prng,
        LencEncodeOutput& out,
        double noiseStandardDeviation,
        double noiseMaxDeviation,
        u32 requestedWidthPadded,
        bool emitRCoeffDomain,
        const std::vector<RnsPoly>* publicBNtt,
        u32,
        bool /*deferCiphertextHost*/, ProtocolCacheScopeView scope)
    {
        if (s.empty() || tau == 0 || noiseStandardDeviation < 0 || !validateRingBatchShape(s, ctx.mParams))
        {
            return false;
        }

        const auto& moduli = getRingHostModuli(ctx);
        if (moduli.empty()) return false;
        u32 width = 0;
        if (!lencTreeWidth(s.size(), requestedWidthPadded, width)) return false;
        const u32 mu = static_cast<u32>(s.size());

        std::shared_ptr<const std::vector<RnsPoly>> cachedPublicBNtt;
        if (publicBNtt)
        {
            if (!validatePublicBNtt(ctx, *publicBNtt, tau))
            {
                return false;
            }
        }
        else
        {
            cachedPublicBNtt = getOrCreateCachedPublicBNtt(ctx, tau, scope);
            publicBNtt = cachedPublicBNtt.get();
        }

        const u32 levels = ilog2Exact(width);
        std::vector<std::vector<RnsPoly>> rLayersNtt(levels, std::vector<RnsPoly>(width));

        for (u32 level = 0; level < levels; ++level)
        {
            for (u32 leaf = 0; leaf < width; ++leaf)
            {
                rLayersNtt[level][leaf] = sampleUniformPolyNtt(ctx, prng);
            }
        }

        std::vector<RnsPoly> sPadNtt;
        if (!buildPaddedNttBatch(ctx, s, width, sPadNtt))
        {
            return false;
        }

        RingTensor ct{};
        ct.mRows = levels * width;
        ct.mCols = 2u * tau;
        ct.mPolys.resize(ringTensorSize(ct));

        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        for (u32 level = 0; level < levels; ++level)
        {
            for (u32 leaf = 0; leaf < width; ++leaf)
            {
                const RnsPoly& rNtt = rLayersNtt[level][leaf];
                const u32 bit = (leaf >> (levels - 1u - level)) & 1u;
                const RnsPoly& riNtt = (level == levels - 1u) ? sPadNtt[leaf] : rLayersNtt[level + 1u][leaf];

                for (u32 k = 0; k < (2u * tau); ++k)
                {
                    RnsPoly rowKNtt{};
                    resizeZero(rowKNtt.mCoeffs, ringPolyCoeffCount(ctx.mParams));
                    if (!dyadicMultiplyAddNttInplace(rNtt, (*publicBNtt)[k], rowKNtt, ctx))
                    {
                        return false;
                    }

                    if (k >= bit * tau && k < (bit + 1u) * tau)
                    {
                        const u32 t = k - bit * tau;
                        const u64 shift = static_cast<u64>(gadgetLogBase) * t;
                        for (std::size_t modIdx = 0; modIdx < moduli.size(); ++modIdx)
                        {
                            const u64 mod = moduli[modIdx].value();
                            const std::size_t offset = modIdx * n;
                            const u64 factor = detail::pow2Mod(shift, mod);
                            for (std::size_t i = 0; i < n; ++i)
                            {
                                const std::size_t idx = offset + i;
                                const u64 value = riNtt.mCoeffs[idx];
                                rowKNtt.mCoeffs[idx] =
                                    mulAddMod(
                                        (value < mod)
                                            ? value
                                            : seal::util::barrett_reduce_64(value, moduli[modIdx]),
                                        factor,
                                        rowKNtt.mCoeffs[idx],
                                        moduli[modIdx]);
                            }
                        }
                    }

                    if (noiseStandardDeviation > 0)
                    {
                        RnsPoly noise{};
                        resizeZero(noise.mCoeffs, ringPolyCoeffCount(ctx.mParams));
                        if (!addPolyError(noise, noiseStandardDeviation, noiseMaxDeviation, prng, ctx) ||
                            !forwardNtt(noise, ctx) ||
                            !ringAddInplace(rowKNtt, noise, ctx))
                        {
                            return false;
                        }
                    }

                    ct.mPolys[ctRowIndex(level, leaf, width) * ct.mCols + k] = std::move(rowKNtt);
                }
            }
        }

        LencEncodeOutput next{};
        next.mRNtt.resize(mu);
        for (u32 i = 0; i < mu; ++i)
        {
            next.mRNtt[i] = std::move(rLayersNtt[0][i]);
        }

        if (emitRCoeffDomain)
        {
            // mu independent inverse transforms; one batch rather than mu calls.
            next.mR.resize(mu);
            for (u32 i = 0; i < mu; ++i)
            {
                next.mR[i] = next.mRNtt[i];
            }
            if (!inverseNttBatch(next.mR, ctx))
            {
                return false;
            }
        }

        next.mLacct.mWidthPadded = width;
        next.mLacct.mLevels = levels;
        next.mLacct.mCt = std::move(ct);

        out = std::move(next);
        return true;
    }

    bool lencDigest(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& x,
        u32 tau,
        u32 gadgetLogBase,
        RnsPoly& out,
        u32 widthPadded)
    {
        DigestTree tree{};
        if (!buildDigestTree(ctx, x, tau, gadgetLogBase, tree, widthPadded, nullptr, 1))
        {
            return false;
        }
        out = std::move(tree.mDigest);
        return true;
    }

    bool lencEval(
        const RingNttContext& ctx,
        const LencLacct& lacct,
        const std::vector<RnsPoly>& x,
        u32 mu,
        u32 tau,
        u32 gadgetLogBase,
        std::vector<RnsPoly>& out,
        bool outputNtt,
        u32 requestedWorkers)
    {
        if (x.size() != mu)
        {
            return false;
        }

        DigestTree tree{};
        if (!buildDigestTree(ctx, x, tau, gadgetLogBase, tree, lacct.mWidthPadded, nullptr, requestedWorkers))
        {
            return false;
        }

        return lencEval(ctx, lacct, tree, mu, tau, gadgetLogBase, out, outputNtt, requestedWorkers);
    }

    bool lencEval(
        const RingNttContext& ctx,
        const LencLacct& lacct,
        const DigestTree& tree,
        u32 mu,
        u32 tau,
        u32,
        std::vector<RnsPoly>& out,
        bool outputNtt,
        u32)
    {
        if (mu == 0 || tau == 0 || lacct.mWidthPadded == 0)
        {
            return false;
        }

        if (lacct.mCt.mRows != lacct.mLevels * lacct.mWidthPadded ||
            lacct.mCt.mCols != 2u * tau ||
            ringTensorSize(lacct.mCt) != lacct.mCt.mPolys.size() ||
            !validateRingBatchShape(lacct.mCt.mPolys, ctx.mParams))
        {
            return false;
        }

        if (tree.mLevels != lacct.mLevels || tree.mWidthPadded != lacct.mWidthPadded)
        {
            return false;
        }

        const u32 nodeCount = (2u * tree.mWidthPadded) - 1u;
        if (tree.mNodeDecompNtt.size() != nodeCount)
        {
            return false;
        }

        for (u32 node = 1; node < nodeCount; ++node)
        {
            if (tree.mNodeDecompNtt[node].size() != tau ||
                !validateRingBatchShape(tree.mNodeDecompNtt[node], ctx.mParams))
            {
                return false;
            }
        }

        out.resize(mu);
        for (u32 leaf = 0; leaf < mu; ++leaf)
        {
            RnsPoly accNtt{};
            resizeZero(accNtt.mCoeffs, ringPolyCoeffCount(ctx.mParams));

            u32 parent = 0;
            for (u32 level = 0; level < lacct.mLevels; ++level)
            {
                const u32 left = (2u * parent) + 1u;
                const u32 right = left + 1u;
                const std::size_t row = ctRowIndex(level, leaf, lacct.mWidthPadded);

                for (u32 c = 0; c < tau; ++c)
                {
                    const auto& ctPolyLNtt =
                        lacct.mCt.mPolys[ringTensorIndex(lacct.mCt, static_cast<u32>(row), c)];
                    const auto& nodePolyLNtt = tree.mNodeDecompNtt[left][c];
                    if (!dyadicMultiplyAddNttInplace(ctPolyLNtt, nodePolyLNtt, accNtt, ctx))
                    {
                        return false;
                    }

                    const auto& ctPolyRNtt =
                        lacct.mCt.mPolys[ringTensorIndex(lacct.mCt, static_cast<u32>(row), tau + c)];
                    const auto& nodePolyRNtt = tree.mNodeDecompNtt[right][c];
                    if (!dyadicMultiplyAddNttInplace(ctPolyRNtt, nodePolyRNtt, accNtt, ctx))
                    {
                        return false;
                    }
                }

                const u32 bit = (leaf >> (lacct.mLevels - 1u - level)) & 1u;
                parent = (bit == 0) ? left : right;
            }

            if (!outputNtt && !inverseNtt(accNtt, ctx))
            {
                return false;
            }

            const std::size_t n = ctx.mParams.mPolyModulusDegree;
            for (std::size_t modIdx = 0; modIdx < ringModulusCount(ctx); ++modIdx)
            {
                const u64 mod = ringModulusValue(ctx, modIdx);
                const std::size_t offset = modIdx * n;
                for (std::size_t i = 0; i < n; ++i)
                {
                    const std::size_t idx = offset + i;
                    if (accNtt.mCoeffs[idx] != 0)
                    {
                        accNtt.mCoeffs[idx] = mod - accNtt.mCoeffs[idx];
                    }
                }
            }

            out[leaf] = std::move(accNtt);
        }

        return true;
    }

    bool buildDigestTreeTrunc(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& x,
        u32 tauHi,
        u32 gadgetLogBase,
        u32 plaintextModulusBits,
        DigestTree& out,
        u32 requestedWidthPadded,
        bool leafInputsAreGadget,
        const std::vector<RnsPoly>* publicBNtt,
        u32 requestedWorkers)
    {
        return buildDigestTreeTrunc(
            ctx,
            std::span<const RnsPoly>(x.data(), x.size()),
            tauHi,
            gadgetLogBase,
            plaintextModulusBits,
            out,
            requestedWidthPadded,
            leafInputsAreGadget,
            publicBNtt,
            requestedWorkers);
    }

    bool buildDigestTreeTrunc(
        const RingNttContext& ctx,
        std::span<const RnsPoly> x,
        u32 tauHi,
        u32 gadgetLogBase,
        u32 plaintextModulusBits,
        DigestTree& out,
        u32 requestedWidthPadded,
        bool leafInputsAreGadget,
        const std::vector<RnsPoly>* publicBNtt,
        u32 requestedWorkers)
    {
        if (x.empty() || !validateRingBatchShape(x, ctx.mParams))
        {
            return false;
        }

        return buildDigestTreeTruncImpl(
            ctx,
            static_cast<u32>(x.size()),
            [&](std::size_t idx) -> const RnsPoly& { return x[idx]; },
            tauHi,
            gadgetLogBase,
            plaintextModulusBits,
            requestedWidthPadded,
            leafInputsAreGadget,
            publicBNtt,
            requestedWorkers,
            out);
    }



    macoro::task<bool> lencEncTrunc(macoro::thread_pool &executor, std::span<u8> setupResults,
                                    const RingNttContext &ctx, const std::vector<RnsPoly> &s, u32 tauHi,
                                    u32 gadgetLogBase, u32 plaintextModulusBits, PRNG &prng,
                                    LencEncodeOutput &out, double noiseStandardDeviation,
                                    double noiseMaxDeviation, u32 requestedWidthPadded, bool emitRCoeffDomain,
                                    bool leafInputsAreGadget, const std::vector<RnsPoly> *publicBNtt,
                                    u32 requestedWorkers, bool deferCiphertextHost, bool deferRandomizerHost,
                                    const gpu::DeviceBatch *seedLabelDevice,
                                    const LazySeedLabelHostState *seedLabelHost,
                                    LogVoleGpuSetupOptions options, CpuBenchmarkState cpuBenchmark,
                                    ProtocolCacheScope setupScope)
    {
        if (setupResults.empty()) co_return false;
        if (!cpuBenchmark.mContext) cpuBenchmark.mContext = cpuBenchmarkContext(ctx);
        if (cpuBenchmark.mContext)
        {
            const auto& limits = *cpuBenchmark.mContext;
            const auto capacity = std::max<std::size_t>(1, limits.mWorkerLimit
                ? std::min(limits.mWorkerLimit, limits.mCpus.size()) : limits.mCpus.size());
            setupResults = setupResults.first(std::min(setupResults.size(), capacity));
        }
        HostStep setupStep(hostProfiler(ctx), "setup: lenc truncated", &cpuBenchmark);
        const auto sCount = seedLabelHost ? seedLabelHost->count() : s.size();
        if (!sCount || sCount > std::numeric_limits<u32>::max() || tauHi == 0 || noiseStandardDeviation < 0 ||
            (seedLabelDevice ? (!s.empty() || !seedLabelHost || !seedLabelHost->matches(ctx.mParams))
                             : !validateRingBatchShape(s, ctx.mParams)))
        {
            co_return false;
        }
#if defined(ENABLE_LOGVOLE_CUDA)
        if (seedLabelDevice && !gpu::setupLencInputBatchMatches(ctx, *seedLabelDevice, sCount,
                                                                setupScope.mRunId, setupScope))
            co_return false;
#else
        if (seedLabelDevice) co_return false;
#endif

        const std::vector<RnsPoly> *sHost = &s;
        const auto materializeS = [&] {
            if (!seedLabelDevice) return true;
            try
            {
                sHost = &seedLabelHost->hostCoefficients(setupScope);
            }
            catch (const std::exception&)
            {
                return false;
            }
            if (sHost->size() != sCount ||
                !validateRingBatchShape(*sHost, ctx.mParams)) return false;
            return true;
        };

        const u32 tauLeaf =
            computeTruncLeafTau(tauHi, plaintextModulusBits, gadgetLogBase, leafInputsAreGadget);
        const u32 fullTau = tauHi + 1u;
        if (tauLeaf == 0 || tauLeaf > fullTau)
        {
            co_return false;
        }

        const u32 mu = static_cast<u32>(sCount);
        u32 width = 0;
        if (!lencTreeWidth(sCount, requestedWidthPadded, width)) co_return false;

        const bool deviceAssemblyRequested = gpuSetupLencDeviceEnabled(options, ctx);
        std::shared_ptr<const std::vector<RnsPoly>> cachedPublicBNtt;
        std::shared_ptr<const gpu::RetainedPublicUniform> retainedPublicBNtt;
        if (publicBNtt)
        {
            if (!validatePublicBNtt(ctx, *publicBNtt, fullTau))
            {
                co_return false;
            }
        }
        else
        {
#if defined(ENABLE_LOGVOLE_CUDA)
            if (deviceAssemblyRequested) retainedPublicBNtt = retainedLencPublicBNtt(ctx, fullTau, setupScope);
#endif
            if (!retainedPublicBNtt)
            {
                cachedPublicBNtt = getOrCreateCachedPublicBNtt(ctx, fullTau, setupScope);
                publicBNtt = cachedPublicBNtt.get();
                if (!publicBNtt || !validatePublicBNtt(ctx, *publicBNtt, fullTau)) co_return false;
            }
        }

        std::vector<const RnsPoly *> publicBInternalHi, publicBLeaf;
        bool retainRandomizers = false;
#if defined(ENABLE_LOGVOLE_CUDA)
        retainRandomizers = deferRandomizerHost && gpuSetupLencDeviceEnabled(options, ctx) &&
                            gpu::lencRandomizerResidencyEnabled(ctx.mExecutionOptions);
#endif
        RecursiveLeafScaling leafScaling{};
        if (leafInputsAreGadget && !retainRandomizers && !buildRecursiveLeafScaling(ctx, leafScaling))
        {
            co_return false;
        }

        const u32 levels = ilog2Exact(width);
        const u32 ctTauMax = std::max(tauHi, tauLeaf);
        std::vector<std::vector<RnsPoly>> rLayersNtt(levels, std::vector<RnsPoly>(width));

        const bool devicePadding = deviceAssemblyRequested && options.mLencDevicePadding;
        const bool setupBatch = gpuSetupLencEnabled(options, ctx) || deviceAssemblyRequested;
        // Keep errors compact through GPU expansion. Exact Gaussian sampling
        // can retain q0 on device; original seeds support every fallback.
        const bool compactRequested = deviceAssemblyRequested && options.mCompactNoise;
        const bool compactStrict = compactRequested && options.mCompactNoiseStrict;
        const bool compactNoiseEnabled = compactRequested &&
            canSamplePolyErrorCompact(ctx, noiseStandardDeviation, noiseMaxDeviation);
        if (compactStrict && !compactNoiseEnabled) co_return false;
        const std::size_t randomizerN = ctx.mParams.mPolyModulusDegree;
        std::vector<u64> compactRandomizers;
        std::shared_ptr<gpu::DeviceScalars> residentRandomizers;
        std::vector<seal::prng_seed_type> randomizerSeeds;
        if (compactNoiseEnabled)
        {
            const std::size_t count = static_cast<std::size_t>(levels) * width;
            if (!randomizerN || count > std::numeric_limits<std::size_t>::max() / randomizerN)
                co_return false;
        }
        if (setupBatch)
        {
            // Draw the identical parent seeds in level/leaf order before any
            // worker runs. Each local error sampler then owns its PRNG stream.
            auto &seeds = randomizerSeeds;
            seeds.resize(static_cast<std::size_t>(levels) * width);
            for (auto &seed : seeds) prng.get(seed.data(), seed.size());
            if (compactNoiseEnabled)
            {
                {
                    const bool setupOk = co_await samplePolyErrorCompactBatchForSetup(
                        executor, setupResults, compactRandomizers, residentRandomizers,
                        noiseStandardDeviation, noiseMaxDeviation, seeds, ctx, requestedWorkers, {},
                        cpuBenchmark, setupScope);
                    if (!setupOk) co_return false;
                }
            }
            else
            {
                const auto taskCount = seeds.size();
                auto chunks = setupResults.first(
                    std::min({setupResults.size(), static_cast<std::size_t>(taskCount),
                              static_cast<std::size_t>((requestedWorkers) ? (requestedWorkers)
                                                                          : setupResults.size())}));
                if (taskCount && chunks.empty()) co_return false;
                std::fill(chunks.begin(), chunks.end(), u8{1});
                auto item = [&](std::size_t idx, CpuBenchmarkState& cpuBenchmark) {
                    auto& poly = rLayersNtt[idx / width][idx % width];
                    resizeZero(poly.mCoeffs, ringPolyCoeffCount(ctx.mParams));
                    return addPolyErrorFromSeed(poly, noiseStandardDeviation, noiseMaxDeviation, seeds[idx],
                                                ctx);
                };
                auto runChunk = [&](std::size_t begin, std::size_t end, u8 &ok) {
                    CpuBenchmarkState worker = chunks.size() > 1
                        ? CpuBenchmarkState{cpuBenchmark.mContext, true} : cpuBenchmark;
                    CpuBenchmarkWorkerScope timing(chunks.size() > 1 ? worker.mContext : nullptr);
                    CpuBenchmarkTaskScope metrics(worker);
                    struct FlushStats
                    {
                        ~FlushStats()
                        {
                            flushRingOpsThreadLocalStats();
                        }
                    } flush;
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
            if (!deviceAssemblyRequested)
                for (auto &layer : rLayersNtt)
                    if (!forwardNttBatch(layer, ctx)) co_return false;
        }
        else
        {
            for (u32 level = 0; level < levels; ++level)
            {
                for (u32 leaf = 0; leaf < width; ++leaf)
                {
                    if (!sampleErrorPolyNtt(ctx, prng, noiseStandardDeviation, noiseMaxDeviation,
                                            rLayersNtt[level][leaf]))
                    {
                        co_return false;
                    }
                }
            }
        }

        std::vector<RnsPoly> sPadNtt;
        if (!devicePadding &&
            (!materializeS() || !buildPaddedNttBatch(ctx, *sHost, width, sPadNtt, !deviceAssemblyRequested)))
        {
            co_return false;
        }

        std::vector<RnsPoly> deviceFirstRNtt;
        RingTensor ct{};
        ct.mRows = levels * width;
        ct.mCols = 2u * ctTauMax;
        ct.mPolys.resize(ringTensorSize(ct));

        bool deviceAssembled = false;
        std::shared_ptr<const LazyRingTensorHostState> lazyCiphertext;
        std::shared_ptr<const LazyLencRandomizerState> lazyRandomizers;
        if (setupBatch)
        {
            // Keep identical parent seed order while optionally sampling only
            // q0: the device broadcasts these signed values during its NTT.
            const std::size_t n = ctx.mParams.mPolyModulusDegree;
            std::vector<u64> compactNoise;
            std::shared_ptr<gpu::DeviceScalars> residentNoise;
            if (compactNoiseEnabled)
            {
                if (!n || ct.mPolys.size() > std::numeric_limits<std::size_t>::max() / n) co_return false;
            }
            std::vector<std::array<u64, 8>> seeds(ct.mPolys.size());
            std::vector<u8> activeNoiseRows(seeds.size(), 0u);
            for (std::size_t idx = 0; idx < seeds.size(); ++idx)
            {
                const u32 level = static_cast<u32>(idx / ct.mCols / width);
                const u32 activeTau = level == levels - 1u ? tauLeaf : tauHi;
                if (noiseStandardDeviation > 0 && idx % ctTauMax < activeTau)
                {
                    prng.get(seeds[idx].data(), seeds[idx].size());
                    activeNoiseRows[idx] = 1u;
                }
            }
            if (compactNoiseEnabled)
            {
                {
                    const bool setupOk = co_await samplePolyErrorCompactBatchForSetup(
                        executor, setupResults, compactNoise, residentNoise, noiseStandardDeviation,
                        noiseMaxDeviation, seeds, ctx, requestedWorkers, activeNoiseRows, cpuBenchmark, setupScope);
                    if (!setupOk) co_return false;
                }
            }
            else
            {
                const auto taskCount = ct.mPolys.size();
                auto chunks = setupResults.first(
                    std::min({setupResults.size(), static_cast<std::size_t>(taskCount),
                              static_cast<std::size_t>((requestedWorkers) ? (requestedWorkers)
                                                                          : setupResults.size())}));
                if (taskCount && chunks.empty()) co_return false;
                std::fill(chunks.begin(), chunks.end(), u8{1});
                auto item = [&](std::size_t idx, CpuBenchmarkState& cpuBenchmark) {
                    const bool activeNoise = activeNoiseRows[idx] != 0;
                    auto& poly = ct.mPolys[idx];
                    resizeZero(poly.mCoeffs, ringPolyCoeffCount(ctx.mParams));
                    return !activeNoise || addPolyErrorFromSeed(poly, noiseStandardDeviation,
                                                                noiseMaxDeviation, seeds[idx], ctx);
                };
                auto runChunk = [&](std::size_t begin, std::size_t end, u8 &ok) {
                    CpuBenchmarkState worker = chunks.size() > 1
                        ? CpuBenchmarkState{cpuBenchmark.mContext, true} : cpuBenchmark;
                    CpuBenchmarkWorkerScope timing(chunks.size() > 1 ? worker.mContext : nullptr);
                    CpuBenchmarkTaskScope metrics(worker);
                    struct FlushStats
                    {
                        ~FlushStats()
                        {
                            flushRingOpsThreadLocalStats();
                        }
                    } flush;
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
#if defined(ENABLE_LOGVOLE_CUDA)
            if (deviceAssemblyRequested)
            {
                deviceAssembled = gpu::assembleLencTruncDevice(
                    ctx, rLayersNtt, devicePadding
                        ? std::span<const RnsPoly>{s}
                        : std::span<const RnsPoly>{sPadNtt},
                    publicBNtt ? std::span<const RnsPoly>{*publicBNtt} : std::span<const RnsPoly>{},
                    tauHi, tauLeaf,
                    gadgetLogBase, leafInputsAreGadget, leafScaling.mCrtLiftModQj,
                    compactNoiseEnabled ? std::span<const RnsPoly>{} : std::span<const RnsPoly>{ct.mPolys},
                    ct.mPolys, &deviceFirstRNtt, compactNoise, compactRandomizers, requestedWorkers, devicePadding,
                    residentNoise.get(), residentRandomizers.get(),
                    deferCiphertextHost ? &lazyCiphertext : nullptr,
                    retainRandomizers ? mu : 0u, retainRandomizers ? &lazyRandomizers : nullptr,
                    retainedPublicBNtt.get(),
                    devicePadding ? seedLabelDevice : nullptr, cpuBenchmark, setupScope);
                if (!deviceAssembled && (compactStrict || options.mLencDeviceStrict)) co_return false;
            }
#endif
            if (compactNoiseEnabled && !deviceAssembled)
            {
                const bool setupOk = co_await materializePolyErrorCompactBatchForSetup(
                    executor, setupResults, compactNoise, residentNoise, noiseStandardDeviation,
                    noiseMaxDeviation, seeds, ctx, requestedWorkers, activeNoiseRows, cpuBenchmark, setupScope);
                if (!setupOk) co_return false;
            }
            if (compactNoiseEnabled && !deviceAssembled)
            {
                const auto taskCount = ct.mPolys.size();
                auto chunks = setupResults.first(
                    std::min({setupResults.size(), static_cast<std::size_t>(taskCount),
                              static_cast<std::size_t>((requestedWorkers) ? (requestedWorkers)
                                                                          : setupResults.size())}));
                if (taskCount && chunks.empty()) co_return false;
                std::fill(chunks.begin(), chunks.end(), u8{1});
                auto item = [&](std::size_t idx, CpuBenchmarkState& cpuBenchmark) {
                    return expandPolyErrorCompact(std::span<const u64>(compactNoise).subspan(idx * n, n),
                                                  ct.mPolys[idx], ctx);
                };
                auto runChunk = [&](std::size_t begin, std::size_t end, u8 &ok) {
                    CpuBenchmarkState worker = chunks.size() > 1
                        ? CpuBenchmarkState{cpuBenchmark.mContext, true} : cpuBenchmark;
                    CpuBenchmarkWorkerScope timing(chunks.size() > 1 ? worker.mContext : nullptr);
                    CpuBenchmarkTaskScope metrics(worker);
                    struct FlushStats
                    {
                        ~FlushStats()
                        {
                            flushRingOpsThreadLocalStats();
                        }
                    } flush;
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
            // The device path keeps randomizer layers and padded input in
            // coefficient form on the host and transforms them only on device.
            // A declined attempt must prepare them before the established path.
            if (deviceAssemblyRequested && !deviceAssembled)
            {
                // Device padding borrows the original input. Materialize the
                // host coefficient copy only when an exact fallback needs it.
                if (devicePadding &&
                    (!materializeS() || !buildPaddedNttBatch(ctx, *sHost, width, sPadNtt, false)))
                    co_return false;
                if (compactNoiseEnabled)
                {
                    const bool setupOk = co_await materializePolyErrorCompactBatchForSetup(
                        executor, setupResults, compactRandomizers, residentRandomizers,
                        noiseStandardDeviation, noiseMaxDeviation, randomizerSeeds, ctx, requestedWorkers, {},
                        cpuBenchmark, setupScope);
                    if (!setupOk) co_return false;
                }
                if (compactNoiseEnabled)
                {
                    const auto taskCount = static_cast<std::size_t>(levels) * width;
                    auto chunks = setupResults.first(
                        std::min({setupResults.size(), static_cast<std::size_t>(taskCount),
                                  static_cast<std::size_t>((requestedWorkers) ? (requestedWorkers)
                                                                              : setupResults.size())}));
                    if (taskCount && chunks.empty()) co_return false;
                    std::fill(chunks.begin(), chunks.end(), u8{1});
                    auto item = [&](std::size_t idx, CpuBenchmarkState& cpuBenchmark) {
                        return expandPolyErrorCompact(
                            std::span<const u64>(compactRandomizers).subspan(idx * n, n),
                            rLayersNtt[idx / width][idx % width], ctx);
                    };
                    auto runChunk = [&](std::size_t begin, std::size_t end, u8 &ok) {
                        CpuBenchmarkState worker = chunks.size() > 1
                            ? CpuBenchmarkState{cpuBenchmark.mContext, true} : cpuBenchmark;
                        CpuBenchmarkWorkerScope timing(chunks.size() > 1 ? worker.mContext : nullptr);
                        CpuBenchmarkTaskScope metrics(worker);
                        struct FlushStats
                        {
                            ~FlushStats()
                            {
                                flushRingOpsThreadLocalStats();
                            }
                        } flush;
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
                    const bool phaseOk =
                        std::all_of(chunks.begin(), chunks.end(), [](u8 ok) { return ok != 0; });
                    if (!phaseOk) co_return false;
                }
                for (auto &layer : rLayersNtt)
                    if (!forwardNttBatch(layer, ctx)) co_return false;
                if (!forwardNttBatch(sPadNtt, ctx)) co_return false;
            }
            // Noise also remains in coefficient form on failure; replay uses
            // the same sampled values without consuming any more PRNG seeds.
            if (!deviceAssembled && noiseStandardDeviation > 0 && !forwardNttBatch(ct.mPolys, ctx))
                co_return false;
        }

        if (!deviceAssembled)
        {
            // The ordinary API and a declined GPU attempt need the exact host
            // operands. Successful retained-only assembly never downloads B.
            if (!publicBNtt)
            {
                cachedPublicBNtt = getOrCreateCachedPublicBNtt(ctx, fullTau, setupScope);
                publicBNtt = cachedPublicBNtt.get();
            }
            if (!publicBNtt || !validatePublicBNtt(ctx, *publicBNtt, fullTau)) co_return false;
            publicBInternalHi = makePublicBInternalHi(*publicBNtt, tauHi);
            publicBLeaf = makePublicBLeaf(*publicBNtt, tauHi, tauLeaf);
        }
        if (!deviceAssembled && retainRandomizers && leafInputsAreGadget &&
            !buildRecursiveLeafScaling(ctx, leafScaling))
            co_return false;
        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        auto buildRow = [&](std::size_t row) {
            const auto& moduli = getRingHostModuli(ctx);
            if (moduli.empty()) return false;
            const u32 level = static_cast<u32>(row / width);
            const u32 leaf = static_cast<u32>(row % width);
            const RnsPoly& rNtt = rLayersNtt[level][leaf];
            const u32 bit = (leaf >> (levels - 1u - level)) & 1u;
            const RnsPoly& riNtt = (level == levels - 1u) ? sPadNtt[leaf] : rLayersNtt[level + 1u][leaf];

            const bool isLeafLevel = level == levels - 1u;
            const auto& bLevel = isLeafLevel ? publicBLeaf : publicBInternalHi;
            const u32 activeTau = isLeafLevel ? tauLeaf : tauHi;
            const u32 powerOffset = isLeafLevel ? 0u : 1u;
            const u32 leafPairBase = leaf & ~1u;
            const u32 leftLimb = leafPairBase % static_cast<u32>(moduli.size());
            const u32 rightLimb = (leafPairBase + 1u) % static_cast<u32>(moduli.size());

            for (u32 side = 0; side < 2u; ++side)
            {
                for (u32 t = 0; t < ctTauMax; ++t)
                {
                    const u32 slot = side * ctTauMax + t;
                    const std::size_t outputIdx = ctRowIndex(level, leaf, width) * ct.mCols + slot;
                    RnsPoly rowKNtt{};
                    if (setupBatch) rowKNtt = std::move(ct.mPolys[outputIdx]);
                    else resizeZero(rowKNtt.mCoeffs, ringPolyCoeffCount(ctx.mParams));

                    if (t < activeTau)
                    {
                        const auto& bPoly = *bLevel[side * activeTau + t];
                        RnsPoly scaledBPoly{};
                        const RnsPoly* bPolyPtr = &bPoly;
                        if (isLeafLevel && leafInputsAreGadget)
                        {
                            const u32 limb = (side == 0) ? leftLimb : rightLimb;
                            const u32 fullTauSideOffset = (side == 0) ? 0u : fullTau;
                            scaledBPoly = selectAndScaleLimbNtt(
                                ctx, (*publicBNtt)[fullTauSideOffset], limb, leafScaling.mCrtLiftModQj[limb]);
                            bPolyPtr = &scaledBPoly;
                        }

                        if (!dyadicMultiplyAddNttInplace(rNtt, *bPolyPtr, rowKNtt, ctx))
                        {
                            return false;
                        }

                        if (side == bit)
                        {
                            const u64 shift = static_cast<u64>(gadgetLogBase) * static_cast<u64>(t + powerOffset);
                            RnsPoly scaledRiNtt{};
                            const RnsPoly* riPolyPtr = &riNtt;
                            if (isLeafLevel && leafInputsAreGadget)
                            {
                                const u32 limb = (side == 0) ? leftLimb : rightLimb;
                                scaledRiNtt =
                                    selectAndScaleLimbNtt(ctx, riNtt, limb, leafScaling.mCrtLiftModQj[limb]);
                                riPolyPtr = &scaledRiNtt;
                            }

                            for (std::size_t modIdx = 0; modIdx < moduli.size(); ++modIdx)
                            {
                                const auto& modulus = moduli[modIdx];
                                const u64 mod = modulus.value();
                                const std::size_t offset = modIdx * n;
                                const u64 factor = detail::pow2Mod(shift, mod);
                                seal::util::MultiplyUIntModOperand operand;
                                if (setupBatch) operand.set(factor, modulus);
                                for (std::size_t i = 0; i < n; ++i)
                                {
                                    const std::size_t idx = offset + i;
                                    const u64 scaled = setupBatch
                                        ? seal::util::multiply_uint_mod(riPolyPtr->mCoeffs[idx], operand, modulus)
                                        : seal::util::multiply_uint_mod(riPolyPtr->mCoeffs[idx], factor, modulus);
                                    rowKNtt.mCoeffs[idx] =
                                        seal::util::add_uint_mod(rowKNtt.mCoeffs[idx], scaled, modulus);
                                }
                            }
                        }
                    }

                    if (!setupBatch && noiseStandardDeviation > 0 && t < activeTau)
                    {
                        RnsPoly noise{};
                        resizeZero(noise.mCoeffs, ringPolyCoeffCount(ctx.mParams));
                        if (!addPolyError(noise, noiseStandardDeviation, noiseMaxDeviation, prng, ctx) ||
                            !forwardNtt(noise, ctx) ||
                            !ringAddInplace(rowKNtt, noise, ctx))
                        {
                            return false;
                        }
                    }

                    ct.mPolys[outputIdx] = std::move(rowKNtt);
                }
            }
            return true;
        };
        if (!deviceAssembled)
        {
            const auto taskCount = ct.mRows;
            auto chunks = setupResults.first(
                std::min({setupResults.size(), static_cast<std::size_t>(taskCount),
                          static_cast<std::size_t>((setupBatch ? requestedWorkers : 1)
                                                       ? (setupBatch ? requestedWorkers : 1)
                                                       : setupResults.size())}));
            if (taskCount && chunks.empty()) co_return false;
            std::fill(chunks.begin(), chunks.end(), u8{1});
            auto item = [&](std::size_t row, CpuBenchmarkState &) { return buildRow(row); };
            auto runChunk = [&](std::size_t begin, std::size_t end, u8 &ok) {
                CpuBenchmarkState worker = chunks.size() > 1
                    ? CpuBenchmarkState{cpuBenchmark.mContext, true} : cpuBenchmark;
                CpuBenchmarkWorkerScope timing(chunks.size() > 1 ? worker.mContext : nullptr);
                CpuBenchmarkTaskScope metrics(worker);
                struct FlushStats
                {
                    ~FlushStats()
                    {
                        flushRingOpsThreadLocalStats();
                    }
                } flush;
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

        LencEncodeOutput next{};
        next.mLazyRandomizers = std::move(lazyRandomizers);
        if (!next.mLazyRandomizers)
        {
            next.mRNtt.resize(mu);
            for (u32 i = 0; i < mu; ++i)
                next.mRNtt[i] = deviceAssembled
                    ? std::move(deviceFirstRNtt[i]) : std::move(rLayersNtt[0][i]);
        }

        if (emitRCoeffDomain && !next.mLazyRandomizers)
        {
            next.mR.resize(mu);
            if (deviceAssembled && compactNoiseEnabled)
            {
                // Only the first coefficient layer is part of the public
                // state. All other RNS expansion took place on the device.
                bool deviceExpanded = false;
#if defined(ENABLE_LOGVOLE_CUDA)
                if (gpu::enabled(ctx) && options.mLencRandomizerOutput)
                {
                    HostStep outputStep(hostProfiler(ctx), "setup: lenc randomizer GPU output",
                                        &cpuBenchmark);
                    const bool decline =
                        ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mLencRandomizerOutput;
                    if (!decline)
                        deviceExpanded = residentRandomizers
                            ? gpu::expandErrorCompactDevice(ctx, *residentRandomizers, false, next.mR, mu, requestedWorkers, cpuBenchmark)
                            : gpu::expandErrorCompactDevice(ctx,
                                std::span<const u64>(compactRandomizers).first(static_cast<std::size_t>(mu) * n),
                                false, next.mR, requestedWorkers, cpuBenchmark);
                    if (!deviceExpanded && options.mLencRandomizerOutputStrict) co_return false;
                }
#endif
                if (!deviceExpanded)
                {
                    const bool setupOk = co_await materializePolyErrorCompactBatchForSetup(
                        executor, setupResults, compactRandomizers, residentRandomizers,
                        noiseStandardDeviation, noiseMaxDeviation, randomizerSeeds, ctx, requestedWorkers, {},
                        cpuBenchmark, setupScope);
                    if (!setupOk) co_return false;
                }
                if (!deviceExpanded)
                {
                    const auto taskCount = mu;
                    auto chunks = setupResults.first(
                        std::min({setupResults.size(), static_cast<std::size_t>(taskCount),
                                  static_cast<std::size_t>((requestedWorkers) ? (requestedWorkers)
                                                                              : setupResults.size())}));
                    if (taskCount && chunks.empty()) co_return false;
                    std::fill(chunks.begin(), chunks.end(), u8{1});
                    auto item = [&](std::size_t i, CpuBenchmarkState& cpuBenchmark) {
                        return expandPolyErrorCompact(
                            std::span<const u64>(compactRandomizers).subspan(i * n, n), next.mR[i], ctx);
                    };
                    auto runChunk = [&](std::size_t begin, std::size_t end, u8 &ok) {
                        CpuBenchmarkState worker = chunks.size() > 1
                            ? CpuBenchmarkState{cpuBenchmark.mContext, true} : cpuBenchmark;
                        CpuBenchmarkWorkerScope timing(chunks.size() > 1 ? worker.mContext : nullptr);
                        CpuBenchmarkTaskScope metrics(worker);
                        struct FlushStats
                        {
                            ~FlushStats()
                            {
                                flushRingOpsThreadLocalStats();
                            }
                        } flush;
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
                    const bool phaseOk =
                        std::all_of(chunks.begin(), chunks.end(), [](u8 ok) { return ok != 0; });
                    if (!phaseOk) co_return false;
                }
            }
            else
                for (u32 i = 0; i < mu; ++i)
                    next.mR[i] = deviceAssembled
                        ? std::move(rLayersNtt[0][i]) : next.mRNtt[i];
            if (!deviceAssembled && !inverseNttBatch(next.mR, ctx))
            {
                co_return false;
            }
        }

        next.mLacct.mWidthPadded = width;
        next.mLacct.mLevels = levels;
        next.mLacct.mCt = std::move(ct);
        next.mLazyCt = std::move(lazyCiphertext);
        out = std::move(next);
        co_return true;
    }

    bool lencDigestTrunc(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& x,
        u32 tauHi,
        u32 gadgetLogBase,
        u32 plaintextModulusBits,
        RnsPoly& out,
        u32 widthPadded,
        bool leafInputsAreGadget)
    {
        DigestTree tree{};
        if (!buildDigestTreeTrunc(
                ctx, x, tauHi, gadgetLogBase, plaintextModulusBits, tree, widthPadded, leafInputsAreGadget, nullptr, 1))
        {
            return false;
        }
        out = std::move(tree.mDigest);
        return true;
    }

    bool lencEvalTrunc(
        const RingNttContext& ctx,
        const LencLacct& lacct,
        const std::vector<RnsPoly>& x,
        u32 mu,
        u32 tauHi,
        u32 gadgetLogBase,
        u32 plaintextModulusBits,
        std::vector<RnsPoly>& out,
        bool outputNtt,
        u32 requestedWorkers,
        bool leafInputsAreGadget, CpuBenchmarkState cpuBenchmark, detail::CpuRowScratch* cpuScratch)
    {
        if (!cpuBenchmark.mContext) cpuBenchmark.mContext = cpuBenchmarkContext(ctx);
        if (x.size() != mu)
        {
            return false;
        }

        DigestTree tree{};
        if (!buildDigestTreeTrunc(
                ctx, x, tauHi, gadgetLogBase, plaintextModulusBits, tree, lacct.mWidthPadded, leafInputsAreGadget,
                nullptr, requestedWorkers))
        {
            return false;
        }

        return lencEvalTrunc(
            ctx, lacct, tree, mu, tauHi, gadgetLogBase, plaintextModulusBits, out, outputNtt, requestedWorkers,
            leafInputsAreGadget, cpuBenchmark, cpuScratch);
    }

    static bool validateLencTruncEvaluation(
        const RingNttContext& ctx, const LencLacct& lacct, const DigestTree& tree,
        u32 mu, u32 tauHi, u32 gadgetLogBase, u32 plaintextModulusBits,
        bool leafInputsAreGadget, u32& tauLeaf, u32& ctTauMax)
    {
        if (mu == 0 || tauHi == 0 || lacct.mWidthPadded == 0 || mu > lacct.mWidthPadded)
        {
            return false;
        }

        tauLeaf = computeTruncLeafTau(tauHi, plaintextModulusBits, gadgetLogBase, leafInputsAreGadget);
        const u32 fullTau = tauHi + 1u;
        if (tauLeaf == 0 || tauLeaf > fullTau)
        {
            return false;
        }

        ctTauMax = std::max(tauHi, tauLeaf);
        if (lacct.mCt.mRows != lacct.mLevels * lacct.mWidthPadded ||
            lacct.mCt.mCols != 2u * ctTauMax ||
            ringTensorSize(lacct.mCt) != lacct.mCt.mPolys.size() ||
            !validateRingBatchShape(lacct.mCt.mPolys, ctx.mParams))
        {
            return false;
        }

        if (tree.mLevels != lacct.mLevels || tree.mWidthPadded != lacct.mWidthPadded)
        {
            return false;
        }

        const u32 nodeCount = (2u * tree.mWidthPadded) - 1u;
        if (tree.mNodeDecompNtt.size() != nodeCount)
        {
            return false;
        }

        const u32 firstLeaf = tree.mWidthPadded - 1u;
        for (u32 node = 1; node < nodeCount; ++node)
        {
            const u32 expectedTau = (node >= firstLeaf) ? tauLeaf : tauHi;
            if (tree.mNodeDecompNtt[node].size() != expectedTau ||
                !validateRingBatchShape(tree.mNodeDecompNtt[node], ctx.mParams))
            {
                return false;
            }
        }

        return true;
    }

    // Synchronous leaf arithmetic shared by both scheduling interfaces.
    template<typename Local>
    static bool evalLencTruncLeaf(
        const RingNttContext& ctx, const LencLacct& lacct, const DigestTree& tree,
        u32 tauHi, u32 tauLeaf, u32 ctTauMax, std::vector<RnsPoly>& out,
        bool outputNtt, bool subtractFromOutput, std::size_t leafIdx, Local& local)
    {
        const auto leaf = static_cast<u32>(leafIdx);
        auto& accNtt = out[leaf];
        if (!subtractFromOutput) resizeFill(accNtt.mCoeffs, ringPolyCoeffCount(ctx.mParams), u64{0});

        auto& ciphertexts = local.mCiphertexts;
        auto& nodes = local.mNodes;
        // Retain capacity, but never retain borrowed tree/ciphertext pointers
        // after the leaf completes, including on failure or exception.
        struct ClearPointers
        {
            Local& mLocal;
            ~ClearPointers() { mLocal.mCiphertexts.clear(); mLocal.mNodes.clear(); }
        } clear{local};
        ciphertexts.clear();
        nodes.clear();
        u32 parent = 0;
        for (u32 level = 0; level < lacct.mLevels; ++level)
        {
            const u32 left = (2u * parent) + 1u;
            const u32 right = left + 1u;
            const u32 activeTau = (level == lacct.mLevels - 1u) ? tauLeaf : tauHi;
            const std::size_t row = ctRowIndex(level, leaf, lacct.mWidthPadded);

            for (u32 c = 0; c < activeTau; ++c)
            {
                const auto& ctPolyLNtt =
                    lacct.mCt.mPolys[ringTensorIndex(lacct.mCt, static_cast<u32>(row), c)];
                const auto& nodePolyLNtt = tree.mNodeDecompNtt[left][c];
                ciphertexts.push_back(&ctPolyLNtt);
                nodes.push_back(&nodePolyLNtt);

                const auto& ctPolyRNtt =
                    lacct.mCt.mPolys[ringTensorIndex(lacct.mCt, static_cast<u32>(row), ctTauMax + c)];
                const auto& nodePolyRNtt = tree.mNodeDecompNtt[right][c];
                ciphertexts.push_back(&ctPolyRNtt);
                nodes.push_back(&nodePolyRNtt);
            }

            const u32 bit = (leaf >> (lacct.mLevels - 1u - level)) & 1u;
            parent = (bit == 0) ? left : right;
        }

        if (!dyadicInnerProductNttInplace(ciphertexts, nodes, accNtt, ctx)) return false;

        // Eval is the negative path sum. Subtracting it adds the products
        // directly to the existing NTT row, avoiding a separate zeroed
        // batch, negation pass and subsequent ring subtraction.
        if (subtractFromOutput)
        {
            globalRingOpsStats.mSubCount.fetch_add(1, std::memory_order_relaxed);
            return true;
        }

        if (!outputNtt && !inverseNtt(accNtt, ctx))
        {
            return false;
        }

        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        for (std::size_t modIdx = 0; modIdx < ringModulusCount(ctx); ++modIdx)
        {
            const u64 mod = ringModulusValue(ctx, modIdx);
            const std::size_t offset = modIdx * n;
            for (std::size_t i = 0; i < n; ++i)
            {
                const std::size_t idx = offset + i;
                if (accNtt.mCoeffs[idx] != 0)
                {
                    accNtt.mCoeffs[idx] = mod - accNtt.mCoeffs[idx];
                }
            }
        }

        return true;
    }

    static bool lencEvalTruncImpl(
        const RingNttContext& ctx,
        const LencLacct& lacct,
        const DigestTree& tree,
        u32 mu,
        u32 tauHi,
        u32 gadgetLogBase,
        u32 plaintextModulusBits,
        std::vector<RnsPoly>& out,
        bool outputNtt,
        u32 requestedWorkers,
        bool leafInputsAreGadget,
        bool subtractFromOutput, CpuBenchmarkState cpuBenchmark, detail::CpuRowScratch* cpuScratch)
    {
        if (!cpuBenchmark.mContext) cpuBenchmark.mContext = cpuBenchmarkContext(ctx);
        u32 tauLeaf = 0, ctTauMax = 0;
        if (!validateLencTruncEvaluation(ctx, lacct, tree, mu, tauHi, gadgetLogBase,
                plaintextModulusBits, leafInputsAreGadget, tauLeaf, ctTauMax)) return false;

        // One leaf per task. Leaves are independent - each walks its own root path
        // and writes only out[leaf], with no reduction between them - so the result
        // is bit-identical. This matters because it is the Root recursion level,
        // whose host cost is fixed in n, and it was running single threaded while
        // the other cores sat idle.
        if (subtractFromOutput && (out.size() != mu || !outputNtt ||
            !validateRingBatchShape(out, ctx.mParams))) return false;
        out.resize(mu);
        const auto terms = std::size_t{2} * lacct.mLevels * ctTauMax;
        auto evalLeaf = [&](std::size_t leafIdx, detail::CpuRowScratch::Local& local) {
            return evalLencTruncLeaf(ctx, lacct, tree, tauHi, tauLeaf, ctTauMax,
                out, outputNtt, subtractFromOutput, leafIdx, local);
        };
        bool useCpuScratch = cpuScratch != nullptr;
#if defined(ENABLE_LOGVOLE_CUDA)
        useCpuScratch = useCpuScratch && !gpu::enabled(ctx);
#endif
        if (!useCpuScratch)
            return detail::runParallelTasks(mu, requestedWorkers, [&](std::size_t leaf, CpuBenchmarkState&) {
                detail::CpuRowScratch::Local local;
                local.mCiphertexts.reserve(terms);
                local.mNodes.reserve(terms);
                return evalLeaf(leaf, local);
            }, false, &cpuBenchmark);

        const auto hardware = requestedWorkers == 1 ? std::size_t{1} :
            std::max<std::size_t>(1, std::thread::hardware_concurrency());
        auto capacity = hardware;
        if (const auto* benchmark = cpuBenchmark.mContext)
            capacity = std::max<std::size_t>(1, benchmark->mWorkerLimit
                ? std::min(benchmark->mWorkerLimit, benchmark->mCpus.size()) : benchmark->mCpus.size());
        const auto workers = std::min({std::size_t(mu), capacity,
            requestedWorkers ? std::size_t(requestedWorkers) : hardware});
        auto locals = cpuScratch->prepare(workers, 0, cpuBenchmark.mContext, terms);
        const auto width = mu / workers;
        const auto extra = mu % workers;
        auto evalPartition = [&](std::size_t partition, detail::CpuRowScratch::Local& local) {
            struct FlushStats { ~FlushStats() { flushRingOpsThreadLocalStats(); } } flush;
            const auto begin = partition * width + std::min(partition, extra);
            const auto end = begin + width + (partition < extra);
            for (auto leaf = begin; leaf < end && local.mOk; ++leaf)
                local.mOk = evalLeaf(leaf, local);
        };
        if (workers == 1)
        {
            CpuBenchmarkTaskScope metrics(cpuBenchmark);
            evalPartition(0, locals[0]);
        }
        else cpuScratch->executor()->runBulk(workers, locals, evalPartition);
        for (const auto& local : locals) if (!local.mOk) return false;
        return true;
    }

    macoro::task<bool> lencEvalTrunc(
        macoro::thread_pool& executor, std::span<LencEvalBuffer> buffers,
        const RingNttContext& ctx, const LencLacct& lacct, const DigestTree& tree,
        u32 mu, u32 tauHi, u32 gadgetLogBase, u32 plaintextModulusBits,
        std::vector<RnsPoly>& out, LencEvalMode mode,
        bool leafInputsAreGadget, CpuBenchmarkState cpuBenchmark)
    {
        u32 tauLeaf = 0, ctTauMax = 0;
        if (gpu::enabled(ctx) || buffers.empty() ||
            (mode != LencEvalMode::Coefficient && mode != LencEvalMode::Ntt && mode != LencEvalMode::SubtractNtt) ||
            !validateLencTruncEvaluation(ctx, lacct, tree, mu, tauHi, gadgetLogBase,
                plaintextModulusBits, leafInputsAreGadget, tauLeaf, ctTauMax) ||
            out.size() != mu || !validateRingBatchShape(out, ctx.mParams)) co_return false;
        const auto terms = std::size_t{2} * lacct.mLevels * ctTauMax;
        auto chunks = buffers.first(std::min(buffers.size(), std::size_t(mu)));
        for (const auto& chunk : chunks)
            if (chunk.mCiphertexts.capacity() < terms || chunk.mNodes.capacity() < terms) co_return false;
        if (!cpuBenchmark.mContext) cpuBenchmark.mContext = cpuBenchmarkContext(ctx);
        for (auto& chunk : chunks) chunk.mOk = true;
        auto evalChunk = [&](std::size_t begin, std::size_t end, LencEvalBuffer& chunk) {
            CpuBenchmarkState worker = chunks.size() > 1
                ? CpuBenchmarkState{cpuBenchmark.mContext, true} : cpuBenchmark;
            CpuBenchmarkWorkerScope timing(chunks.size() > 1 ? worker.mContext : nullptr);
            CpuBenchmarkTaskScope metrics(worker);
            struct FlushStats { ~FlushStats() { flushRingOpsThreadLocalStats(); } } flush;
            for (auto leaf = begin; leaf != end; ++leaf)
            {
                if (!evalLencTruncLeaf(ctx, lacct, tree, tauHi, tauLeaf, ctTauMax, out,
                    mode != LencEvalMode::Coefficient, mode == LencEvalMode::SubtractNtt, leaf, chunk))
                {
                    chunk.mOk = false;
                    break;
                }
            }
        };
        if (chunks.size() == 1) evalChunk(0, mu, chunks[0]);
        else co_await macoro::bulk_chunked(executor, mu, chunks, evalChunk);
        for (const auto& chunk : chunks) if (!chunk.mOk) co_return false;
        co_return true;
    }

    bool lencEvalTrunc(
        const RingNttContext& ctx, const LencLacct& lacct, const DigestTree& tree,
        u32 mu, u32 tauHi, u32 gadgetLogBase, u32 plaintextModulusBits,
        std::vector<RnsPoly>& out, bool outputNtt, u32 requestedWorkers, bool leafInputsAreGadget, CpuBenchmarkState cpuBenchmark, detail::CpuRowScratch* cpuScratch)
    {
        if (!cpuBenchmark.mContext) cpuBenchmark.mContext = cpuBenchmarkContext(ctx);
        return lencEvalTruncImpl(ctx, lacct, tree, mu, tauHi, gadgetLogBase, plaintextModulusBits,
            out, outputNtt, requestedWorkers, leafInputsAreGadget, false, cpuBenchmark, cpuScratch);
    }

    bool lencSubtractEvalTruncNttInplace(
        const RingNttContext& ctx, const LencLacct& lacct, const DigestTree& tree,
        u32 mu, u32 tauHi, u32 gadgetLogBase, u32 plaintextModulusBits,
        std::vector<RnsPoly>& out, u32 requestedWorkers, bool leafInputsAreGadget, CpuBenchmarkState cpuBenchmark, detail::CpuRowScratch* cpuScratch)
    {
        if (!cpuBenchmark.mContext) cpuBenchmark.mContext = cpuBenchmarkContext(ctx);
        return lencEvalTruncImpl(ctx, lacct, tree, mu, tauHi, gadgetLogBase, plaintextModulusBits,
            out, true, requestedWorkers, leafInputsAreGadget, true, cpuBenchmark, cpuScratch);
    }
}

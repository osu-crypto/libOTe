#include "libOTe/Vole/LogVole/LogVoleLenc.h"
#include "libOTe/Vole/LogVole/LogVoleArithmetic.h"

#include "seal/util/uintarithsmallmod.h"

#include <algorithm>
#include <cstddef>
#include <limits>
#include <mutex>
#include <unordered_map>

namespace osuCrypto::LogVole
{
    namespace
    {
        u64 pow2Mod(u64 exp, u64 mod)
        {
            const seal::Modulus modulus(mod);
            u64 result = 1;
            u64 base = 2 % mod;
            u64 e = exp;
            while (e > 0)
            {
                if ((e & 1u) != 0)
                {
                    result = mulMod(result, base, modulus);
                }
                base = mulMod(base, base, modulus);
                e >>= 1;
            }
            return result;
        }

        u32 nextPowerOfTwo(u32 value)
        {
            u32 out = 1;
            while (out < value)
            {
                out <<= 1;
            }
            return out;
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

        bool zeroPoly(const RingNttContext& ctx, RnsPoly& out)
        {
            resizeZero(out.mCoeffs, ringPolyCoeffCount(ctx.mParams));
            return true;
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

        bool negatePoly(const RingNttContext& ctx, const RnsPoly& poly, RnsPoly& out)
        {
            RnsPoly zero{};
            return zeroPoly(ctx, zero) && ringSub(zero, poly, ctx, out);
        }

        bool buildPaddedNttBatch(
            const RingNttContext& ctx,
            const std::vector<RnsPoly>& in,
            u32 widthPadded,
            std::vector<RnsPoly>& out)
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
            for (auto& poly : next)
            {
                if (!forwardNtt(poly, ctx))
                {
                    return false;
                }
            }

            out = std::move(next);
            return true;
        }

        std::vector<RnsPoly> buildLencPublicBNttImpl(const RingNttContext& ctx, u32 tau)
        {
            std::vector<RnsPoly> b(2u * tau);
            for (u32 i = 0; i < 2u * tau; ++i)
            {
                b[i] = deriveUniformPolyFromNonceNtt(ctx, 0xC0DEC0DEull, 0x1EEC0DEu, i);
            }
            return b;
        }

        struct PublicBCacheKey
        {
            RingParams mRing;
            u32 mTau = 0;

            bool operator==(const PublicBCacheKey& other) const
            {
                return mRing == other.mRing && mTau == other.mTau;
            }
        };

        struct PublicBCacheKeyHash
        {
            std::size_t operator()(const PublicBCacheKey& key) const
            {
                std::size_t h = std::hash<u32>{}(key.mRing.mPolyModulusDegree);
                h ^= std::hash<u32>{}(key.mTau) + 0x9e3779b9u + (h << 6u) + (h >> 2u);
                for (int bits : key.mRing.mCoeffModulusBits)
                {
                    const std::size_t b = std::hash<int>{}(bits);
                    h ^= b + 0x9e3779b9u + (h << 6u) + (h >> 2u);
                }
                return h;
            }
        };

        std::unordered_map<PublicBCacheKey, std::shared_ptr<const std::vector<RnsPoly>>, PublicBCacheKeyHash>
            publicBCache;
        std::mutex publicBCacheMutex;

        std::shared_ptr<const std::vector<RnsPoly>> getOrCreateCachedPublicBNtt(const RingNttContext& ctx, u32 tau)
        {
            PublicBCacheKey key{};
            key.mRing = ctx.mParams;
            key.mTau = tau;

            {
                std::lock_guard<std::mutex> lock(publicBCacheMutex);
                auto it = publicBCache.find(key);
                if (it != publicBCache.end())
                {
                    return it->second;
                }
            }

            auto candidate = std::make_shared<const std::vector<RnsPoly>>(buildLencPublicBNttImpl(ctx, tau));

            std::lock_guard<std::mutex> lock(publicBCacheMutex);
            auto [it, inserted] = publicBCache.emplace(std::move(key), candidate);
            (void)inserted;
            return it->second;
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
            if (!zeroPoly(ctx, accNtt))
            {
                return false;
            }

            for (std::size_t i = 0; i < size; ++i)
            {
                if (!dyadicMultiplyAddNttInplace(*leftPtrs[i], *rightPtrs[i], accNtt, ctx))
                {
                    return false;
                }
            }

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
            const std::size_t rho = ctx.mModuli.size();
            RecursiveLeafScaling scaling{};
            resizeFill<u64>(scaling.mCrtLiftModQj, rho, 1);
            resizeFill<u64>(scaling.mInvCrtLiftModQj, rho, 1);

            for (std::size_t j = 0; j < rho; ++j)
            {
                const auto& modJ = ctx.mModuli[j];
                u64 crtLiftModQj = 1;
                for (std::size_t w = 0; w < rho; ++w)
                {
                    if (w == j)
                    {
                        continue;
                    }
                    crtLiftModQj = seal::util::multiply_uint_mod(crtLiftModQj, ctx.mModuli[w].value(), modJ);
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
            RnsPoly out{};
            resizeZero(out.mCoeffs, ringPolyCoeffCount(ctx.mParams));

            const std::size_t n = ctx.mParams.mPolyModulusDegree;
            const auto& modulus = ctx.mModuli[limbIdx];
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
                leftLimb >= ctx.mModuli.size() || rightLimb >= ctx.mModuli.size())
            {
                return false;
            }

            RnsPoly accNtt{};
            resizeZero(accNtt.mCoeffs, coeffCount);

            const std::size_t n = ctx.mParams.mPolyModulusDegree;
            auto accumulateLimb = [&](const RnsPoly& bNtt, u32 limb, u64 scaleModQj, const RnsPoly& digitNtt) {
                const auto& modulus = ctx.mModuli[limb];
                const std::size_t offset = static_cast<std::size_t>(limb) * n;
                for (std::size_t c = 0; c < n; ++c)
                {
                    const std::size_t idx = offset + c;
                    const u64 scaledB = seal::util::multiply_uint_mod(bNtt.mCoeffs[idx], scaleModQj, modulus);
                    const u64 prod = seal::util::multiply_uint_mod(scaledB, digitNtt.mCoeffs[idx], modulus);
                    accNtt.mCoeffs[idx] = seal::util::add_uint_mod(accNtt.mCoeffs[idx], prod, modulus);
                }
            };

            accumulateLimb(leftBNtt, leftLimb, leftScaleModQj, leftDigitNtt);
            accumulateLimb(rightBNtt, rightLimb, rightScaleModQj, rightDigitNtt);

            if (!inverseNtt(accNtt, ctx))
            {
                return false;
            }

            out = std::move(accNtt);
            return true;
        }

        std::vector<RnsPoly> makePublicBInternalHi(const std::vector<RnsPoly>& publicBFullNtt, u32 tauHi)
        {
            const u32 fullTau = tauHi + 1u;
            std::vector<RnsPoly> out(2u * tauHi);
            for (u32 i = 0; i < tauHi; ++i)
            {
                out[i] = publicBFullNtt[1u + i];
            }
            for (u32 i = 0; i < tauHi; ++i)
            {
                out[tauHi + i] = publicBFullNtt[fullTau + 1u + i];
            }
            return out;
        }

        std::vector<RnsPoly> makePublicBLeaf(
            const RingNttContext& ctx,
            const std::vector<RnsPoly>& publicBFullNtt,
            u32 tauHi,
            u32 tauLeaf)
        {
            const u32 fullTau = tauHi + 1u;
            std::vector<RnsPoly> out(2u * tauLeaf, zeroPolyRaw(ctx));
            for (u32 i = 0; i < tauLeaf; ++i)
            {
                out[i] = publicBFullNtt[i];
                out[tauLeaf + i] = publicBFullNtt[fullTau + i];
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
                if (!forwardNtt(digitNtt, ctx))
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
                if (!forwardNtt(digitNtt, ctx))
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
            RnsPoly plainPoly{};
            resizeZero(plainPoly.mCoeffs, ringPolyCoeffCount(ctx.mParams));

            const std::size_t n = ctx.mParams.mPolyModulusDegree;
            const auto& modulus = ctx.mModuli[limbIdx];
            const std::size_t offset = static_cast<std::size_t>(limbIdx) * n;
            for (std::size_t c = 0; c < n; ++c)
            {
                const u64 reduced =
                    seal::util::multiply_uint_mod(liftedPoly.mCoeffs[offset + c], invCrtLiftModQj, modulus);
                const i64 centered = (reduced > (modulus.value() >> 1u))
                                         ? -static_cast<i64>(modulus.value() - reduced)
                                         : static_cast<i64>(reduced);

                for (std::size_t modIdx = 0; modIdx < ctx.mModuli.size(); ++modIdx)
                {
                    const auto& modK = ctx.mModuli[modIdx];
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

            if (!forwardNtt(plainPoly, ctx))
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
            if (!addPolyError(noise, noiseStandardDeviation, noiseMaxDeviation, prng, ctx) ||
                !forwardNtt(noise, ctx))
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

            u32 width = requestedWidthPadded;
            if (width == 0)
            {
                width = nextPowerOfTwo(xCount);
            }
            if (width < xCount || (width & (width - 1u)) != 0)
            {
                return false;
            }

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
                cachedPublicBNtt = getOrCreateCachedPublicBNtt(ctx, fullTau);
                publicBNtt = cachedPublicBNtt.get();
            }

            const auto publicBInternalHi = makePublicBInternalHi(*publicBNtt, tauHi);
            const auto publicBLeaf = makePublicBLeaf(ctx, *publicBNtt, tauHi, tauLeaf);
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

            for (u32 leaf = 0; leaf < width; ++leaf)
            {
                const u32 node = (width - 1u) + leaf;
                const RnsPoly& leafPoly = (leaf < xCount) ? leafAt(leaf) : zeroPadding;
                const u32 limb = leaf % static_cast<u32>(ctx.mModuli.size());
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
                        bPtrs[idx] = &bLevel[idx];
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
                        const u32 leftLimb = leftLeaf % static_cast<u32>(ctx.mModuli.size());
                        const u32 rightLimb = rightLeaf % static_cast<u32>(ctx.mModuli.size());
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
                    if (!negatePoly(ctx, dot, nodeValue))
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
        KeyDeriveSenderOutput& output)
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
        if (!makeRingNttContext(input.mParams, ctx))
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
        KeyDeriveReceiverOutput& output)
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
        if (!makeRingNttContext(input.mParams, ctx))
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

    std::vector<RnsPoly> buildLencPublicBNtt(const RingNttContext& ctx, u32 tau)
    {
        auto cached = getOrCreateCachedPublicBNtt(ctx, tau);
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

        u32 width = requestedWidthPadded;
        if (width == 0)
        {
            width = nextPowerOfTwo(static_cast<u32>(x.size()));
        }
        if (width < x.size() || (width & (width - 1u)) != 0)
        {
            return false;
        }

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
            cachedPublicBNtt = getOrCreateCachedPublicBNtt(ctx, tau);
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
                    !negatePoly(ctx, dot, nodeValue))
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
        u32)
    {
        if (s.empty() || tau == 0 || noiseStandardDeviation < 0 || !validateRingBatchShape(s, ctx.mParams))
        {
            return false;
        }

        const u32 mu = static_cast<u32>(s.size());
        u32 width = requestedWidthPadded;
        if (width == 0)
        {
            width = nextPowerOfTwo(mu);
        }
        if (width < mu || (width & (width - 1u)) != 0)
        {
            return false;
        }

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
            cachedPublicBNtt = getOrCreateCachedPublicBNtt(ctx, tau);
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
                        for (std::size_t modIdx = 0; modIdx < ctx.mModuli.size(); ++modIdx)
                        {
                            const u64 mod = ctx.mModuli[modIdx].value();
                            const std::size_t offset = modIdx * n;
                            const u64 factor = pow2Mod(shift, mod);
                            for (std::size_t i = 0; i < n; ++i)
                            {
                                const std::size_t idx = offset + i;
                                rowKNtt.mCoeffs[idx] =
                                    mulAddMod(
                                        riNtt.mCoeffs[idx] % mod,
                                        factor,
                                        rowKNtt.mCoeffs[idx],
                                        ctx.mModuli[modIdx]);
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
            next.mR.resize(mu);
            for (u32 i = 0; i < mu; ++i)
            {
                RnsPoly r = next.mRNtt[i];
                if (!inverseNtt(r, ctx))
                {
                    return false;
                }
                next.mR[i] = std::move(r);
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
            for (std::size_t modIdx = 0; modIdx < ctx.mModuli.size(); ++modIdx)
            {
                const u64 mod = ctx.mModuli[modIdx].value();
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

    bool lencEncTrunc(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& s,
        u32 tauHi,
        u32 gadgetLogBase,
        u32 plaintextModulusBits,
        PRNG& prng,
        LencEncodeOutput& out,
        double noiseStandardDeviation,
        double noiseMaxDeviation,
        u32 requestedWidthPadded,
        bool emitRCoeffDomain,
        bool leafInputsAreGadget,
        const std::vector<RnsPoly>* publicBNtt,
        u32)
    {
        if (s.empty() || tauHi == 0 || noiseStandardDeviation < 0 || !validateRingBatchShape(s, ctx.mParams))
        {
            return false;
        }

        const u32 tauLeaf = computeTruncLeafTau(tauHi, plaintextModulusBits, gadgetLogBase, leafInputsAreGadget);
        const u32 fullTau = tauHi + 1u;
        if (tauLeaf == 0 || tauLeaf > fullTau)
        {
            return false;
        }

        const u32 mu = static_cast<u32>(s.size());
        u32 width = requestedWidthPadded;
        if (width == 0)
        {
            width = nextPowerOfTwo(mu);
        }
        if (width < mu || (width & (width - 1u)) != 0)
        {
            return false;
        }

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
            cachedPublicBNtt = getOrCreateCachedPublicBNtt(ctx, fullTau);
            publicBNtt = cachedPublicBNtt.get();
        }

        const auto publicBInternalHi = makePublicBInternalHi(*publicBNtt, tauHi);
        const auto publicBLeaf = makePublicBLeaf(ctx, *publicBNtt, tauHi, tauLeaf);
        RecursiveLeafScaling leafScaling{};
        if (leafInputsAreGadget && !buildRecursiveLeafScaling(ctx, leafScaling))
        {
            return false;
        }

        const u32 levels = ilog2Exact(width);
        const u32 ctTauMax = std::max(tauHi, tauLeaf);
        std::vector<std::vector<RnsPoly>> rLayersNtt(levels, std::vector<RnsPoly>(width));

        for (u32 level = 0; level < levels; ++level)
        {
            for (u32 leaf = 0; leaf < width; ++leaf)
            {
                if (!sampleErrorPolyNtt(ctx, prng, noiseStandardDeviation, noiseMaxDeviation, rLayersNtt[level][leaf]))
                {
                    return false;
                }
            }
        }

        std::vector<RnsPoly> sPadNtt;
        if (!buildPaddedNttBatch(ctx, s, width, sPadNtt))
        {
            return false;
        }

        RingTensor ct{};
        ct.mRows = levels * width;
        ct.mCols = 2u * ctTauMax;
        ct.mPolys.resize(ringTensorSize(ct));

        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        for (u32 level = 0; level < levels; ++level)
        {
            for (u32 leaf = 0; leaf < width; ++leaf)
            {
                const RnsPoly& rNtt = rLayersNtt[level][leaf];
                const u32 bit = (leaf >> (levels - 1u - level)) & 1u;
                const RnsPoly& riNtt = (level == levels - 1u) ? sPadNtt[leaf] : rLayersNtt[level + 1u][leaf];

                const bool isLeafLevel = level == levels - 1u;
                const std::vector<RnsPoly>& bLevel = isLeafLevel ? publicBLeaf : publicBInternalHi;
                const u32 activeTau = isLeafLevel ? tauLeaf : tauHi;
                const u32 powerOffset = isLeafLevel ? 0u : 1u;
                const u32 leafPairBase = leaf & ~1u;
                const u32 leftLimb = leafPairBase % static_cast<u32>(ctx.mModuli.size());
                const u32 rightLimb = (leafPairBase + 1u) % static_cast<u32>(ctx.mModuli.size());

                for (u32 side = 0; side < 2u; ++side)
                {
                    for (u32 t = 0; t < ctTauMax; ++t)
                    {
                        RnsPoly rowKNtt{};
                        resizeZero(rowKNtt.mCoeffs, ringPolyCoeffCount(ctx.mParams));

                        if (t < activeTau)
                        {
                            const auto& bPoly = bLevel[side * activeTau + t];
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

                                for (std::size_t modIdx = 0; modIdx < ctx.mModuli.size(); ++modIdx)
                                {
                                    const auto& modulus = ctx.mModuli[modIdx];
                                    const u64 mod = modulus.value();
                                    const std::size_t offset = modIdx * n;
                                    const u64 factor = pow2Mod(shift, mod);
                                    for (std::size_t i = 0; i < n; ++i)
                                    {
                                        const std::size_t idx = offset + i;
                                        const u64 scaled =
                                            seal::util::multiply_uint_mod(riPolyPtr->mCoeffs[idx], factor, modulus);
                                        rowKNtt.mCoeffs[idx] =
                                            seal::util::add_uint_mod(rowKNtt.mCoeffs[idx], scaled, modulus);
                                    }
                                }
                            }
                        }

                        if (noiseStandardDeviation > 0 && t < activeTau)
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

                        const u32 slot = side * ctTauMax + t;
                        ct.mPolys[ctRowIndex(level, leaf, width) * ct.mCols + slot] = std::move(rowKNtt);
                    }
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
            next.mR.resize(mu);
            for (u32 i = 0; i < mu; ++i)
            {
                RnsPoly r = next.mRNtt[i];
                if (!inverseNtt(r, ctx))
                {
                    return false;
                }
                next.mR[i] = std::move(r);
            }
        }

        next.mLacct.mWidthPadded = width;
        next.mLacct.mLevels = levels;
        next.mLacct.mCt = std::move(ct);
        out = std::move(next);
        return true;
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
        bool leafInputsAreGadget)
    {
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
            leafInputsAreGadget);
    }

    bool lencEvalTrunc(
        const RingNttContext& ctx,
        const LencLacct& lacct,
        const DigestTree& tree,
        u32 mu,
        u32 tauHi,
        u32 gadgetLogBase,
        u32 plaintextModulusBits,
        std::vector<RnsPoly>& out,
        bool outputNtt,
        u32,
        bool leafInputsAreGadget)
    {
        if (mu == 0 || tauHi == 0 || lacct.mWidthPadded == 0)
        {
            return false;
        }

        const u32 tauLeaf = computeTruncLeafTau(tauHi, plaintextModulusBits, gadgetLogBase, leafInputsAreGadget);
        const u32 fullTau = tauHi + 1u;
        if (tauLeaf == 0 || tauLeaf > fullTau)
        {
            return false;
        }

        const u32 ctTauMax = std::max(tauHi, tauLeaf);
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
                const u32 activeTau = (level == lacct.mLevels - 1u) ? tauLeaf : tauHi;
                const std::size_t row = ctRowIndex(level, leaf, lacct.mWidthPadded);

                for (u32 c = 0; c < activeTau; ++c)
                {
                    const auto& ctPolyLNtt =
                        lacct.mCt.mPolys[ringTensorIndex(lacct.mCt, static_cast<u32>(row), c)];
                    const auto& nodePolyLNtt = tree.mNodeDecompNtt[left][c];
                    if (!dyadicMultiplyAddNttInplace(ctPolyLNtt, nodePolyLNtt, accNtt, ctx))
                    {
                        return false;
                    }

                    const auto& ctPolyRNtt =
                        lacct.mCt.mPolys[ringTensorIndex(lacct.mCt, static_cast<u32>(row), ctTauMax + c)];
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
            for (std::size_t modIdx = 0; modIdx < ctx.mModuli.size(); ++modIdx)
            {
                const u64 mod = ctx.mModuli[modIdx].value();
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
}

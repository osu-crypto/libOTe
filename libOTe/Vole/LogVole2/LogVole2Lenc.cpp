#include "libOTe/Vole/LogVole2/LogVole2Lenc.h"

#include <algorithm>
#include <cstddef>
#include <limits>
#include <mutex>
#include <unordered_map>

namespace osuCrypto::LogVole2
{
    namespace
    {
        constexpr u64 kLencRDomain = 0x4C454E43525F4E43ull;
        constexpr u64 kLencCtNoiseDomain = 0x4C454E4343544552ull;

        u64 pow2Mod(u64 exp, u64 mod)
        {
            u64 result = 1;
            u64 base = 2 % mod;
            u64 e = exp;
            while (e > 0)
            {
                if ((e & 1u) != 0)
                {
                    const auto mul = static_cast<unsigned __int128>(result) * base;
                    result = static_cast<u64>(mul % mod);
                }
                const auto sq = static_cast<unsigned __int128>(base) * base;
                base = static_cast<u64>(sq % mod);
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
            out.mCoeffs.assign(ringPolyCoeffCount(ctx.mParams), 0);
            return true;
        }

        bool negatePoly(const RingNttContext& ctx, const RnsPoly& poly, RnsPoly& out)
        {
            RnsPoly zero{};
            return zeroPoly(ctx, zero) && ringSub(zero, poly, ctx, out);
        }

        std::vector<RnsPoly> padBatch(const RingNttContext& ctx, const std::vector<RnsPoly>& in, u32 widthPadded)
        {
            std::vector<RnsPoly> out = in;
            out.reserve(widthPadded);
            for (u32 i = static_cast<u32>(out.size()); i < widthPadded; ++i)
            {
                RnsPoly zero{};
                zero.mCoeffs.assign(ringPolyCoeffCount(ctx.mParams), 0);
                out.push_back(std::move(zero));
            }
            return out;
        }

        std::vector<RnsPoly> buildLencPublicBNttImpl(const RingNttContext& ctx, u32 tau)
        {
            std::vector<RnsPoly> b;
            b.reserve(2u * tau);
            for (u32 i = 0; i < 2u * tau; ++i)
            {
                b.push_back(deriveUniformPolyFromNonceNtt(ctx, 0xC0DEC0DEull, 0x1EEC0DEu, i));
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

        std::size_t ctRowIndex(u32 level, u32 leaf, u32 width)
        {
            return static_cast<std::size_t>(level) * width + leaf;
        }
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

        std::vector<const RnsPoly*> bPtrs;
        bPtrs.reserve(2u * tau);
        for (const auto& poly : *publicBNtt)
        {
            bPtrs.push_back(&poly);
        }

        RnsPoly zeroPadding{};
        if (width > x.size())
        {
            zeroPadding.mCoeffs.assign(ringPolyCoeffCount(ctx.mParams), 0);
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

        for (int depth = static_cast<int>(levels) - 1; depth >= 0; --depth)
        {
            const u32 nodesAtDepth = static_cast<u32>(1u << depth);
            const u32 firstNode = nodesAtDepth - 1u;
            for (u32 depthIdx = 0; depthIdx < nodesAtDepth; ++depthIdx)
            {
                const u32 p = firstNode + depthIdx;
                const u32 left = (2u * p) + 1u;
                const u32 right = left + 1u;

                std::vector<const RnsPoly*> pairPtrs(2u * tau, nullptr);
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
        const SamplingSeedConfig& samplingSeeds,
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
                const u64 nonce = deriveNoiseSeed(
                    samplingSeeds,
                    kLencRDomain,
                    (static_cast<u64>(level) << 32u) ^ static_cast<u64>(leaf),
                    width,
                    tau);
                rLayersNtt[level][leaf] = deriveUniformPolyFromNonceNtt(ctx, nonce, 0x1EC0DEDu, leaf);
            }
        }

        auto sPad = padBatch(ctx, s, width);
        std::vector<RnsPoly> sPadNtt = sPad;
        for (auto& poly : sPadNtt)
        {
            if (!forwardNtt(poly, ctx))
            {
                return false;
            }
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
                    rowKNtt.mCoeffs.assign(ringPolyCoeffCount(ctx.mParams), 0);
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
                                const auto scaled = static_cast<unsigned __int128>(riNtt.mCoeffs[idx]) * factor;
                                rowKNtt.mCoeffs[idx] =
                                    (rowKNtt.mCoeffs[idx] + static_cast<u64>(scaled % mod)) % mod;
                            }
                        }
                    }

                    if (noiseStandardDeviation > 0)
                    {
                        const u64 streamId = (static_cast<u64>(level) << 48u) ^
                                             (static_cast<u64>(leaf) << 16u) ^
                                             static_cast<u64>(k);
                        const u64 noiseSeed =
                            deriveNoiseSeed(samplingSeeds, kLencCtNoiseDomain, streamId, width, tau);
                        RnsPoly noise{};
                        noise.mCoeffs.assign(ringPolyCoeffCount(ctx.mParams), 0);
                        if (!addPolyError(noise, noiseStandardDeviation, noiseMaxDeviation, noiseSeed, 0, ctx) ||
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
        next.mRNtt.reserve(mu);
        for (u32 i = 0; i < mu; ++i)
        {
            next.mRNtt.push_back(std::move(rLayersNtt[0][i]));
        }

        if (emitRCoeffDomain)
        {
            next.mR.reserve(mu);
            for (u32 i = 0; i < mu; ++i)
            {
                RnsPoly r = next.mRNtt[i];
                if (!inverseNtt(r, ctx))
                {
                    return false;
                }
                next.mR.push_back(std::move(r));
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
            accNtt.mCoeffs.assign(ringPolyCoeffCount(ctx.mParams), 0);

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
}

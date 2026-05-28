#include "libOTe/Vole/LogVole/LogVoleLenc.h"

#include "seal/util/uintarithsmallmod.h"

#include <cstddef>
#include <limits>

namespace osuCrypto
{
    namespace
    {
        u32 logVoleNextPowerOfTwo(u32 value)
        {
            u32 out = 1u;
            while (out < value)
            {
                out <<= 1u;
            }
            return out;
        }

        u32 logVoleIlog2Exact(u32 powerOfTwo)
        {
            u32 out = 0u;
            while ((1u << out) < powerOfTwo)
            {
                ++out;
            }
            return out;
        }

        u64 logVolePow2Mod(u64 exp, u64 mod)
        {
            seal::Modulus modulus(mod);
            u64 result = 1u;
            u64 base = 2u % mod;
            u64 e = exp;
            while (e > 0u)
            {
                if ((e & 1u) != 0u)
                {
                    result = seal::util::multiply_uint_mod(result, base, modulus);
                }
                base = seal::util::multiply_uint_mod(base, base, modulus);
                e >>= 1u;
            }
            return result;
        }

        bool logVoleZeroPoly(const LogVoleRingNttContext& ctx, LogVoleRnsPoly& out)
        {
            out.mCoeffs.assign(logVolePolyCoeffCount(ctx.mParams), 0u);
            return true;
        }

        bool logVoleNegatePoly(const LogVoleRingNttContext& ctx, const LogVoleRnsPoly& poly, LogVoleRnsPoly& out)
        {
            LogVoleRnsPoly zero{};
            logVoleZeroPoly(ctx, zero);
            return logVoleRingSub(zero, poly, ctx, out);
        }

        std::vector<LogVoleRnsPoly> logVolePadBatch(
            const LogVoleRingNttContext& ctx,
            const std::vector<LogVoleRnsPoly>& in,
            u32 widthPadded)
        {
            std::vector<LogVoleRnsPoly> out = in;
            out.reserve(widthPadded);
            for (u32 i = static_cast<u32>(out.size()); i < widthPadded; ++i)
            {
                LogVoleRnsPoly zero{};
                zero.mCoeffs.assign(logVolePolyCoeffCount(ctx.mParams), 0u);
                out.push_back(std::move(zero));
            }
            return out;
        }

        std::vector<LogVoleRnsPoly> logVoleDeriveLencPublicB(const LogVoleRingNttContext& ctx, u32 tau)
        {
            std::vector<LogVoleRnsPoly> b;
            b.reserve(2u * tau);
            for (u32 i = 0; i < 2u * tau; ++i)
            {
                b.push_back(logVoleDeriveUniformPolyFromNonce(ctx, 0xC0DEC0DEull, 0x1EEC0DEu, i));
            }
            return b;
        }

        bool logVoleMultiplyByGPower(
            const LogVoleRingNttContext& ctx,
            const LogVoleRnsPoly& poly,
            u32 gadgetLogBase,
            u32 power,
            LogVoleRnsPoly& out)
        {
            if (!logVoleValidateRingPolyShape(poly, ctx.mParams))
            {
                return false;
            }

            const u64 shift = static_cast<u64>(gadgetLogBase) * static_cast<u64>(power);
            if (shift > static_cast<u64>(std::numeric_limits<u32>::max()))
            {
                return false;
            }

            LogVoleRnsPoly next = poly;
            const std::size_t n = ctx.mParams.mPolyModulusDegree;
            for (std::size_t modIdx = 0; modIdx < ctx.mModuli.size(); ++modIdx)
            {
                const auto& modulus = ctx.mModuli[modIdx];
                const u64 mod = modulus.value();
                const u64 factor = logVolePow2Mod(shift, mod);
                const std::size_t offset = modIdx * n;
                for (std::size_t i = 0; i < n; ++i)
                {
                    const std::size_t idx = offset + i;
                    next.mCoeffs[idx] = seal::util::multiply_uint_mod(next.mCoeffs[idx] % mod, factor, modulus);
                }
            }

            out = std::move(next);
            return true;
        }

        bool logVoleInnerProduct(
            const LogVoleRingNttContext& ctx,
            const std::vector<LogVoleRnsPoly>& left,
            const std::vector<LogVoleRnsPoly>& right,
            LogVoleRnsPoly& out)
        {
            if (left.size() != right.size() || left.empty() ||
                !logVoleValidateRingBatchShape(left, ctx.mParams) ||
                !logVoleValidateRingBatchShape(right, ctx.mParams))
            {
                return false;
            }

            LogVoleRnsPoly acc{};
            logVoleZeroPoly(ctx, acc);

            for (std::size_t i = 0; i < left.size(); ++i)
            {
                LogVoleRnsPoly mul{};
                LogVoleRnsPoly next{};
                if (!logVoleRingMultiply(left[i], right[i], ctx, mul) ||
                    !logVoleRingAdd(acc, mul, ctx, next))
                {
                    return false;
                }
                acc = std::move(next);
            }

            out = std::move(acc);
            return true;
        }

        struct LogVoleDigestTree
        {
            u32 mWidthPadded = 0;
            u32 mLevels = 0;
            LogVoleRnsPoly mDigest;
            std::vector<std::vector<LogVoleRnsPoly>> mNodeDecomp;
        };

        bool logVoleBuildDigestTree(
            const LogVoleRingNttContext& ctx,
            const std::vector<LogVoleRnsPoly>& x,
            u32 tau,
            u32 gadgetLogBase,
            u32 requestedWidthPadded,
            LogVoleDigestTree& out)
        {
            if (x.empty() || tau == 0u || !logVoleValidateRingBatchShape(x, ctx.mParams))
            {
                return false;
            }

            u32 width = requestedWidthPadded;
            if (width == 0u)
            {
                width = logVoleNextPowerOfTwo(static_cast<u32>(x.size()));
            }

            if (width < x.size() || (width & (width - 1u)) != 0u)
            {
                return false;
            }

            const u32 levels = logVoleIlog2Exact(width);
            const u32 nodeCount = (2u * width) - 1u;
            const auto b = logVoleDeriveLencPublicB(ctx, tau);
            auto xPad = logVolePadBatch(ctx, x, width);

            LogVoleDigestTree tree{};
            tree.mWidthPadded = width;
            tree.mLevels = levels;
            tree.mNodeDecomp.resize(nodeCount);

            for (u32 leaf = 0; leaf < width; ++leaf)
            {
                const u32 node = (width - 1u) + leaf;
                if (!logVoleGadgetDecomposeBits(xPad[leaf], gadgetLogBase, tau, ctx, tree.mNodeDecomp[node]))
                {
                    return false;
                }
            }

            for (i64 parent = static_cast<i64>(width) - 2; parent >= 0; --parent)
            {
                const u32 p = static_cast<u32>(parent);
                const u32 left = (2u * p) + 1u;
                const u32 right = left + 1u;

                std::vector<LogVoleRnsPoly> pair;
                pair.reserve(2u * tau);
                for (u32 i = 0; i < tau; ++i)
                {
                    pair.push_back(tree.mNodeDecomp[left][i]);
                }
                for (u32 i = 0; i < tau; ++i)
                {
                    pair.push_back(tree.mNodeDecomp[right][i]);
                }

                LogVoleRnsPoly dot{};
                LogVoleRnsPoly nodeValue{};
                if (!logVoleInnerProduct(ctx, b, pair, dot) ||
                    !logVoleNegatePoly(ctx, dot, nodeValue))
                {
                    return false;
                }

                if (p == 0u)
                {
                    tree.mDigest = std::move(nodeValue);
                }
                else if (!logVoleGadgetDecomposeBits(nodeValue, gadgetLogBase, tau, ctx, tree.mNodeDecomp[p]))
                {
                    return false;
                }
            }

            out = std::move(tree);
            return true;
        }

        std::size_t logVoleCtRowIndex(u32 level, u32 leaf, u32 width)
        {
            return static_cast<std::size_t>(level) * width + leaf;
        }
    }

    bool logVoleLencEnc(
        const LogVoleRingNttContext& ctx,
        const std::vector<LogVoleRnsPoly>& s,
        u32 tau,
        u32 gadgetLogBase,
        u64 seed,
        LogVoleLencEncodeOutput& out,
        double noiseStandardDeviation,
        double noiseMaxDeviation,
        u64 encryptionNoiseSeed)
    {
        if (s.empty() || tau == 0u || noiseStandardDeviation < 0 ||
            !logVoleValidateRingBatchShape(s, ctx.mParams))
        {
            return false;
        }

        const u32 mu = static_cast<u32>(s.size());
        const u32 width = logVoleNextPowerOfTwo(mu);
        const u32 levels = logVoleIlog2Exact(width);
        const auto b = logVoleDeriveLencPublicB(ctx, tau);
        auto sPad = logVolePadBatch(ctx, s, width);

        std::vector<std::vector<LogVoleRnsPoly>> rLayers(levels);
        for (u32 level = 0; level < levels; ++level)
        {
            rLayers[level].reserve(width);
            for (u32 leaf = 0; leaf < width; ++leaf)
            {
                const u64 nonce = seed ^ (static_cast<u64>(level) << 32u) ^ static_cast<u64>(leaf);
                rLayers[level].push_back(logVoleDeriveUniformPolyFromNonce(ctx, nonce, 0x1EC0DEDu, leaf));
            }
        }

        LogVoleRingTensor ct{};
        ct.mRows = levels * width;
        ct.mCols = 2u * tau;
        ct.mPolys.reserve(logVoleTensorSize(ct));

        for (u32 level = 0; level < levels; ++level)
        {
            for (u32 leaf = 0; leaf < width; ++leaf)
            {
                const LogVoleRnsPoly& rCur = rLayers[level][leaf];
                std::vector<LogVoleRnsPoly> row;
                row.reserve(2u * tau);

                for (u32 k = 0; k < (2u * tau); ++k)
                {
                    LogVoleRnsPoly mul{};
                    if (!logVoleRingMultiply(rCur, b[k], ctx, mul))
                    {
                        return false;
                    }
                    row.push_back(std::move(mul));
                }

                const u32 bit = (leaf >> (levels - 1u - level)) & 1u;
                const LogVoleRnsPoly& ri = (level == levels - 1u) ? sPad[leaf] : rLayers[level + 1u][leaf];

                for (u32 t = 0; t < tau; ++t)
                {
                    LogVoleRnsPoly gpow{};
                    LogVoleRnsPoly add{};
                    const u32 idx = (bit * tau) + t;
                    if (!logVoleMultiplyByGPower(ctx, ri, gadgetLogBase, t, gpow) ||
                        !logVoleRingAdd(row[idx], gpow, ctx, add))
                    {
                        return false;
                    }
                    row[idx] = std::move(add);
                }

                for (u32 k = 0; k < static_cast<u32>(row.size()); ++k)
                {
                    LogVoleRnsPoly poly = std::move(row[k]);
                    if (noiseStandardDeviation > 0)
                    {
                        const u64 streamId =
                            (static_cast<u64>(level) << 48u) ^ (static_cast<u64>(leaf) << 16u) ^ static_cast<u64>(k);
                        if (!logVoleAddPolyError(
                                poly,
                                noiseStandardDeviation,
                                noiseMaxDeviation,
                                encryptionNoiseSeed,
                                streamId,
                                ctx))
                        {
                            return false;
                        }
                    }
                    ct.mPolys.push_back(std::move(poly));
                }
            }
        }

        LogVoleLencEncodeOutput next{};
        next.mR.reserve(mu);
        for (u32 i = 0; i < mu; ++i)
        {
            next.mR.push_back(rLayers[0][i]);
        }

        next.mLacct.mWidthPadded = width;
        next.mLacct.mLevels = levels;
        next.mLacct.mCt = std::move(ct);
        out = std::move(next);
        return true;
    }

    bool logVoleLencDigest(
        const LogVoleRingNttContext& ctx,
        const std::vector<LogVoleRnsPoly>& x,
        u32 tau,
        u32 gadgetLogBase,
        LogVoleRnsPoly& out,
        u32 widthPadded)
    {
        LogVoleDigestTree tree{};
        if (!logVoleBuildDigestTree(ctx, x, tau, gadgetLogBase, widthPadded, tree))
        {
            return false;
        }

        out = std::move(tree.mDigest);
        return true;
    }

    bool logVoleLencEval(
        const LogVoleRingNttContext& ctx,
        const LogVoleLencLacct& lacct,
        const std::vector<LogVoleRnsPoly>& x,
        u32 mu,
        u32 tau,
        u32 gadgetLogBase,
        std::vector<LogVoleRnsPoly>& out)
    {
        if (mu == 0u || tau == 0u || lacct.mWidthPadded == 0u || x.size() != mu ||
            lacct.mCt.mRows != lacct.mLevels * lacct.mWidthPadded || lacct.mCt.mCols != 2u * tau ||
            logVoleTensorSize(lacct.mCt) != lacct.mCt.mPolys.size() ||
            !logVoleValidateRingBatchShape(lacct.mCt.mPolys, ctx.mParams))
        {
            return false;
        }

        LogVoleDigestTree tree{};
        if (!logVoleBuildDigestTree(ctx, x, tau, gadgetLogBase, lacct.mWidthPadded, tree) ||
            tree.mLevels != lacct.mLevels)
        {
            return false;
        }

        std::vector<LogVoleRnsPoly> nextOut;
        nextOut.reserve(mu);

        for (u32 leaf = 0; leaf < mu; ++leaf)
        {
            LogVoleRnsPoly acc{};
            logVoleZeroPoly(ctx, acc);

            u32 parent = 0u;
            for (u32 level = 0; level < lacct.mLevels; ++level)
            {
                const u32 left = (2u * parent) + 1u;
                const u32 right = left + 1u;

                std::vector<LogVoleRnsPoly> pair;
                pair.reserve(2u * tau);
                for (u32 i = 0; i < tau; ++i)
                {
                    pair.push_back(tree.mNodeDecomp[left][i]);
                }
                for (u32 i = 0; i < tau; ++i)
                {
                    pair.push_back(tree.mNodeDecomp[right][i]);
                }

                std::vector<LogVoleRnsPoly> ctRow;
                ctRow.reserve(2u * tau);
                const auto row = logVoleCtRowIndex(level, leaf, lacct.mWidthPadded);
                for (u32 c = 0; c < 2u * tau; ++c)
                {
                    ctRow.push_back(lacct.mCt.mPolys[logVoleTensorIndex(
                        lacct.mCt, static_cast<u32>(row), c)]);
                }

                LogVoleRnsPoly dot{};
                LogVoleRnsPoly next{};
                if (!logVoleInnerProduct(ctx, ctRow, pair, dot) ||
                    !logVoleRingAdd(acc, dot, ctx, next))
                {
                    return false;
                }
                acc = std::move(next);

                const u32 bit = (leaf >> (lacct.mLevels - 1u - level)) & 1u;
                parent = (bit == 0u) ? left : right;
            }

            LogVoleRnsPoly neg{};
            if (!logVoleNegatePoly(ctx, acc, neg))
            {
                return false;
            }
            nextOut.push_back(std::move(neg));
        }

        out = std::move(nextOut);
        return true;
    }
}

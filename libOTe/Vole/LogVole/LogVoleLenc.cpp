#include "libOTe/Vole/LogVole/LogVoleLenc.h"

#include "seal/util/uintarithsmallmod.h"

#include <cstddef>
#include <limits>

namespace osuCrypto::LogVole
{
    namespace
    {
        u32 nextPowerOfTwo(u32 value)
        {
            u32 out = 1u;
            while (out < value)
            {
                out <<= 1u;
            }
            return out;
        }

        u32 ilog2Exact(u32 powerOfTwo)
        {
            u32 out = 0u;
            while ((1u << out) < powerOfTwo)
            {
                ++out;
            }
            return out;
        }

        u64 pow2Mod(u64 exp, u64 mod)
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

        bool zeroPoly(const RingNttContext& ctx, RnsPoly& out)
        {
            out.mCoeffs.assign(polyCoeffCount(ctx.mParams), 0u);
            return true;
        }

        bool negatePoly(const RingNttContext& ctx, const RnsPoly& poly, RnsPoly& out)
        {
            RnsPoly zero{};
            zeroPoly(ctx, zero);
            return ringSub(zero, poly, ctx, out);
        }

        std::vector<RnsPoly> padBatch(
            const RingNttContext& ctx,
            const std::vector<RnsPoly>& in,
            u32 widthPadded)
        {
            std::vector<RnsPoly> out = in;
            out.reserve(widthPadded);
            for (u32 i = static_cast<u32>(out.size()); i < widthPadded; ++i)
            {
                RnsPoly zero{};
                zero.mCoeffs.assign(polyCoeffCount(ctx.mParams), 0u);
                out.push_back(std::move(zero));
            }
            return out;
        }

        std::vector<RnsPoly> deriveLencPublicB(const RingNttContext& ctx, u32 tau)
        {
            std::vector<RnsPoly> b;
            b.reserve(2u * tau);
            for (u32 i = 0; i < 2u * tau; ++i)
            {
                b.push_back(deriveUniformPolyFromNonce(ctx, 0xC0DEC0DEull, 0x1EEC0DEu, i));
            }
            return b;
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

            const u64 shift = static_cast<u64>(gadgetLogBase) * static_cast<u64>(power);
            if (shift > static_cast<u64>(std::numeric_limits<u32>::max()))
            {
                return false;
            }

            RnsPoly next = poly;
            const std::size_t n = ctx.mParams.mPolyModulusDegree;
            for (std::size_t modIdx = 0; modIdx < ctx.mModuli.size(); ++modIdx)
            {
                const auto& modulus = ctx.mModuli[modIdx];
                const u64 mod = modulus.value();
                const u64 factor = pow2Mod(shift, mod);
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

        bool innerProduct(
            const RingNttContext& ctx,
            const std::vector<RnsPoly>& left,
            const std::vector<RnsPoly>& right,
            RnsPoly& out)
        {
            if (left.size() != right.size() || left.empty() ||
                !validateRingBatchShape(left, ctx.mParams) ||
                !validateRingBatchShape(right, ctx.mParams))
            {
                return false;
            }

            RnsPoly acc{};
            zeroPoly(ctx, acc);

            for (std::size_t i = 0; i < left.size(); ++i)
            {
                RnsPoly mul{};
                RnsPoly next{};
                if (!ringMultiply(left[i], right[i], ctx, mul) ||
                    !ringAdd(acc, mul, ctx, next))
                {
                    return false;
                }
                acc = std::move(next);
            }

            out = std::move(acc);
            return true;
        }

        struct DigestTree
        {
            u32 mWidthPadded = 0;
            u32 mLevels = 0;
            RnsPoly mDigest;
            std::vector<std::vector<RnsPoly>> mNodeDecomp;
        };

        bool buildDigestTree(
            const RingNttContext& ctx,
            const std::vector<RnsPoly>& x,
            u32 tau,
            u32 gadgetLogBase,
            u32 requestedWidthPadded,
            DigestTree& out)
        {
            if (x.empty() || tau == 0u || !validateRingBatchShape(x, ctx.mParams))
            {
                return false;
            }

            u32 width = requestedWidthPadded;
            if (width == 0u)
            {
                width = nextPowerOfTwo(static_cast<u32>(x.size()));
            }

            if (width < x.size() || (width & (width - 1u)) != 0u)
            {
                return false;
            }

            const u32 levels = ilog2Exact(width);
            const u32 nodeCount = (2u * width) - 1u;
            const auto b = deriveLencPublicB(ctx, tau);
            auto xPad = padBatch(ctx, x, width);

            DigestTree tree{};
            tree.mWidthPadded = width;
            tree.mLevels = levels;
            tree.mNodeDecomp.resize(nodeCount);

            for (u32 leaf = 0; leaf < width; ++leaf)
            {
                const u32 node = (width - 1u) + leaf;
                if (!gadgetDecomposeBits(xPad[leaf], gadgetLogBase, tau, ctx, tree.mNodeDecomp[node]))
                {
                    return false;
                }
            }

            for (i64 parent = static_cast<i64>(width) - 2; parent >= 0; --parent)
            {
                const u32 p = static_cast<u32>(parent);
                const u32 left = (2u * p) + 1u;
                const u32 right = left + 1u;

                std::vector<RnsPoly> pair;
                pair.reserve(2u * tau);
                for (u32 i = 0; i < tau; ++i)
                {
                    pair.push_back(tree.mNodeDecomp[left][i]);
                }
                for (u32 i = 0; i < tau; ++i)
                {
                    pair.push_back(tree.mNodeDecomp[right][i]);
                }

                RnsPoly dot{};
                RnsPoly nodeValue{};
                if (!innerProduct(ctx, b, pair, dot) ||
                    !negatePoly(ctx, dot, nodeValue))
                {
                    return false;
                }

                if (p == 0u)
                {
                    tree.mDigest = std::move(nodeValue);
                }
                else if (!gadgetDecomposeBits(nodeValue, gadgetLogBase, tau, ctx, tree.mNodeDecomp[p]))
                {
                    return false;
                }
            }

            out = std::move(tree);
            return true;
        }

        std::size_t ctRowIndex(u32 level, u32 leaf, u32 width)
        {
            return static_cast<std::size_t>(level) * width + leaf;
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

        std::vector<RnsPoly> mNttBatch;
        mNttBatch.reserve(request.mTau);

        for (std::size_t i = 0; i < request.mTau; ++i)
        {
            RnsPoly sk1 = input.mSk1[i];
            RnsPoly sk2 = input.mSk2[i];
            RnsPoly d = dBatch[i];

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
            mNttBatch.push_back(std::move(mNtt));
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
        next.mM.reserve(response.mTau);

        for (auto& poly : mNttBatch)
        {
            if (!canonicalizePoly(poly, ctx) ||
                !inverseNtt(poly, ctx))
            {
                return false;
            }
            next.mM.push_back(std::move(poly));
        }

        output = std::move(next);
        return true;
    }

    bool lencEnc(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& s,
        u32 tau,
        u32 gadgetLogBase,
        u64 seed,
        LencEncodeOutput& out,
        double noiseStandardDeviation,
        double noiseMaxDeviation,
        u64 encryptionNoiseSeed)
    {
        if (s.empty() || tau == 0u || noiseStandardDeviation < 0 ||
            !validateRingBatchShape(s, ctx.mParams))
        {
            return false;
        }

        const u32 mu = static_cast<u32>(s.size());
        const u32 width = nextPowerOfTwo(mu);
        const u32 levels = ilog2Exact(width);
        const auto b = deriveLencPublicB(ctx, tau);
        auto sPad = padBatch(ctx, s, width);

        std::vector<std::vector<RnsPoly>> rLayers(levels);
        for (u32 level = 0; level < levels; ++level)
        {
            rLayers[level].reserve(width);
            for (u32 leaf = 0; leaf < width; ++leaf)
            {
                const u64 nonce = seed ^ (static_cast<u64>(level) << 32u) ^ static_cast<u64>(leaf);
                rLayers[level].push_back(deriveUniformPolyFromNonce(ctx, nonce, 0x1EC0DEDu, leaf));
            }
        }

        RingTensor ct{};
        ct.mRows = levels * width;
        ct.mCols = 2u * tau;
        ct.mPolys.reserve(tensorSize(ct));

        for (u32 level = 0; level < levels; ++level)
        {
            for (u32 leaf = 0; leaf < width; ++leaf)
            {
                const RnsPoly& rCur = rLayers[level][leaf];
                std::vector<RnsPoly> row;
                row.reserve(2u * tau);

                for (u32 k = 0; k < (2u * tau); ++k)
                {
                    RnsPoly mul{};
                    if (!ringMultiply(rCur, b[k], ctx, mul))
                    {
                        return false;
                    }
                    row.push_back(std::move(mul));
                }

                const u32 bit = (leaf >> (levels - 1u - level)) & 1u;
                const RnsPoly& ri = (level == levels - 1u) ? sPad[leaf] : rLayers[level + 1u][leaf];

                for (u32 t = 0; t < tau; ++t)
                {
                    RnsPoly gpow{};
                    RnsPoly add{};
                    const u32 idx = (bit * tau) + t;
                    if (!multiplyByGPower(ctx, ri, gadgetLogBase, t, gpow) ||
                        !ringAdd(row[idx], gpow, ctx, add))
                    {
                        return false;
                    }
                    row[idx] = std::move(add);
                }

                for (u32 k = 0; k < static_cast<u32>(row.size()); ++k)
                {
                    RnsPoly poly = std::move(row[k]);
                    if (noiseStandardDeviation > 0)
                    {
                        const u64 streamId =
                            (static_cast<u64>(level) << 48u) ^ (static_cast<u64>(leaf) << 16u) ^ static_cast<u64>(k);
                        if (!addPolyError(
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

        LencEncodeOutput next{};
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

    bool lencDigest(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& x,
        u32 tau,
        u32 gadgetLogBase,
        RnsPoly& out,
        u32 widthPadded)
    {
        DigestTree tree{};
        if (!buildDigestTree(ctx, x, tau, gadgetLogBase, widthPadded, tree))
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
        std::vector<RnsPoly>& out)
    {
        if (mu == 0u || tau == 0u || lacct.mWidthPadded == 0u || x.size() != mu ||
            lacct.mCt.mRows != lacct.mLevels * lacct.mWidthPadded || lacct.mCt.mCols != 2u * tau ||
            tensorSize(lacct.mCt) != lacct.mCt.mPolys.size() ||
            !validateRingBatchShape(lacct.mCt.mPolys, ctx.mParams))
        {
            return false;
        }

        DigestTree tree{};
        if (!buildDigestTree(ctx, x, tau, gadgetLogBase, lacct.mWidthPadded, tree) ||
            tree.mLevels != lacct.mLevels)
        {
            return false;
        }

        std::vector<RnsPoly> nextOut;
        nextOut.reserve(mu);

        for (u32 leaf = 0; leaf < mu; ++leaf)
        {
            RnsPoly acc{};
            zeroPoly(ctx, acc);

            u32 parent = 0u;
            for (u32 level = 0; level < lacct.mLevels; ++level)
            {
                const u32 left = (2u * parent) + 1u;
                const u32 right = left + 1u;

                std::vector<RnsPoly> pair;
                pair.reserve(2u * tau);
                for (u32 i = 0; i < tau; ++i)
                {
                    pair.push_back(tree.mNodeDecomp[left][i]);
                }
                for (u32 i = 0; i < tau; ++i)
                {
                    pair.push_back(tree.mNodeDecomp[right][i]);
                }

                std::vector<RnsPoly> ctRow;
                ctRow.reserve(2u * tau);
                const auto row = ctRowIndex(level, leaf, lacct.mWidthPadded);
                for (u32 c = 0; c < 2u * tau; ++c)
                {
                    ctRow.push_back(lacct.mCt.mPolys[tensorIndex(
                        lacct.mCt, static_cast<u32>(row), c)]);
                }

                RnsPoly dot{};
                RnsPoly next{};
                if (!innerProduct(ctx, ctRow, pair, dot) ||
                    !ringAdd(acc, dot, ctx, next))
                {
                    return false;
                }
                acc = std::move(next);

                const u32 bit = (leaf >> (lacct.mLevels - 1u - level)) & 1u;
                parent = (bit == 0u) ? left : right;
            }

            RnsPoly neg{};
            if (!negatePoly(ctx, acc, neg))
            {
                return false;
            }
            nextOut.push_back(std::move(neg));
        }

        out = std::move(nextOut);
        return true;
    }
}

#include "libOTe/Vole/LogVole/LogVoleLenc.h"

#include "seal/util/polycore.h"
#include "seal/util/rns.h"
#include "seal/util/uintarith.h"
#include "seal/util/uintarithsmallmod.h"

#include <algorithm>
#include <cmath>
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

        u64 mix64(u64 x)
        {
            x += 0x9E3779B97F4A7C15ull;
            x = (x ^ (x >> 30u)) * 0xBF58476D1CE4E5B9ull;
            x = (x ^ (x >> 27u)) * 0x94D049BB133111EBull;
            return x ^ (x >> 31u);
        }

        u32 logQBits(const RingParams& params)
        {
            u32 logQ = 0u;
            for (const int bits : params.mCoeffModulusBits)
            {
                logQ += static_cast<u32>(bits);
            }
            return logQ;
        }

        bool computeBaseNoiseFloor(const RingParams& params, i64& out)
        {
            constexpr long double kBaseNoiseExponent = 0.1L;
            const auto logQ = static_cast<long double>(logQBits(params));
            const long double baseNoise = std::pow(2.0L, kBaseNoiseExponent * logQ);

            if (!std::isfinite(baseNoise) ||
                baseNoise > static_cast<long double>(std::numeric_limits<i64>::max()))
            {
                return false;
            }

            const auto floor = static_cast<i64>(std::ceil(baseNoise));
            out = (floor > 0) ? floor : 1;
            return true;
        }

        double computeSigma(const ShrinkExpandParams& params)
        {
            return 3.0 * std::pow(2.0, static_cast<double>(logQBits(params.mRing)) * 0.1);
        }

        std::vector<RnsPoly> sampleUniformBatch(
            const RingNttContext& ctx,
            u32 count,
            u64 seed,
            u64 domainTag)
        {
            std::vector<RnsPoly> out;
            out.reserve(count);
            for (u32 i = 0; i < count; ++i)
            {
                const u64 nonce = seed ^ (static_cast<u64>(i) << 1u);
                out.push_back(deriveUniformPolyFromNonce(ctx, nonce, domainTag, i));
            }
            return out;
        }

        bool polysEqual(const RnsPoly& a, const RnsPoly& b)
        {
            return a.mCoeffs == b.mCoeffs;
        }

        bool buildLhePublicA(const RingNttContext& ctx, u32 mu, std::vector<RnsPoly>& out)
        {
            if (mu == 0u)
            {
                return false;
            }

            std::vector<RnsPoly> a;
            a.reserve(mu);
            for (u32 i = 0; i < mu; ++i)
            {
                a.push_back(deriveUniformPolyFromNonce(ctx, 0xA11ACE5Eull, 0xA110CA7Aull, i));
            }

            out = std::move(a);
            return true;
        }

        bool lheEnc1(
            const RingNttContext& ctx,
            const std::vector<RnsPoly>& r,
            const std::vector<RnsPoly>& sk1,
            u32 gadgetLogBase,
            RingTensor& out,
            double noiseStandardDeviation = 0.0,
            double noiseMaxDeviation = 0.0,
            u64 encryptionNoiseSeed = 0)
        {
            if (r.empty() || sk1.empty() || noiseStandardDeviation < 0 ||
                !validateRingBatchShape(r, ctx.mParams) ||
                !validateRingBatchShape(sk1, ctx.mParams))
            {
                return false;
            }

            std::vector<RnsPoly> a;
            if (!buildLhePublicA(ctx, static_cast<u32>(r.size()), a))
            {
                return false;
            }

            RingTensor ct1{};
            ct1.mRows = static_cast<u32>(r.size());
            ct1.mCols = static_cast<u32>(sk1.size());
            ct1.mPolys.reserve(static_cast<std::size_t>(ct1.mRows) * ct1.mCols);

            for (u32 row = 0; row < ct1.mRows; ++row)
            {
                for (u32 col = 0; col < ct1.mCols; ++col)
                {
                    RnsPoly ask{};
                    RnsPoly rg{};
                    RnsPoly c{};
                    if (!ringMultiply(a[row], sk1[col], ctx, ask) ||
                        !multiplyByGPower(ctx, r[row], gadgetLogBase, col, rg) ||
                        !ringAdd(ask, rg, ctx, c))
                    {
                        return false;
                    }

                    if (noiseStandardDeviation > 0)
                    {
                        const u64 streamId = (static_cast<u64>(row) << 32u) ^ static_cast<u64>(col);
                        if (!addPolyError(c, noiseStandardDeviation, noiseMaxDeviation, encryptionNoiseSeed, streamId, ctx))
                        {
                            return false;
                        }
                    }

                    ct1.mPolys.push_back(std::move(c));
                }
            }

            out = std::move(ct1);
            return true;
        }

        bool lheApplyCt1(
            const RingNttContext& ctx,
            const RingTensor& ct1,
            const RnsPoly& digest,
            u32 gadgetLogBase,
            u32 tau,
            std::vector<RnsPoly>& out)
        {
            if (ct1.mRows == 0u || ct1.mCols == 0u || ct1.mCols != tau ||
                tensorSize(ct1) != ct1.mPolys.size() ||
                !validateRingPolyShape(digest, ctx.mParams) ||
                !validateRingBatchShape(ct1.mPolys, ctx.mParams))
            {
                return false;
            }

            std::vector<RnsPoly> u;
            if (!gadgetDecomposeBits(digest, gadgetLogBase, tau, ctx, u))
            {
                return false;
            }

            std::vector<RnsPoly> result;
            result.reserve(ct1.mRows);
            for (u32 row = 0; row < ct1.mRows; ++row)
            {
                RnsPoly acc{};
                zeroPoly(ctx, acc);

                for (u32 col = 0; col < tau; ++col)
                {
                    const auto& c = ct1.mPolys[tensorIndex(ct1, row, col)];
                    RnsPoly term{};
                    RnsPoly next{};
                    if (!ringMultiply(c, u[col], ctx, term) ||
                        !ringAdd(acc, term, ctx, next))
                    {
                        return false;
                    }
                    acc = std::move(next);
                }
                result.push_back(std::move(acc));
            }

            out = std::move(result);
            return true;
        }

        bool buildHashedCt2(const RingNttContext& ctx, u32 mu, u64 nonce, std::vector<RnsPoly>& out)
        {
            if (mu == 0u)
            {
                return false;
            }

            std::vector<RnsPoly> result;
            result.reserve(mu);
            for (u32 j = 0; j < mu; ++j)
            {
                result.push_back(deriveUniformPolyFromNonce(ctx, nonce, 0xC720AA55u, j));
            }

            out = std::move(result);
            return true;
        }

        bool lheDec(
            const RingNttContext& ctx,
            const std::vector<RnsPoly>& cipher,
            const RnsPoly& sk,
            std::vector<RnsPoly>& out)
        {
            if (cipher.empty() ||
                !validateRingBatchShape(cipher, ctx.mParams) ||
                !validateRingPolyShape(sk, ctx.mParams))
            {
                return false;
            }

            std::vector<RnsPoly> a;
            if (!buildLhePublicA(ctx, static_cast<u32>(cipher.size()), a))
            {
                return false;
            }

            std::vector<RnsPoly> result;
            result.reserve(cipher.size());
            for (std::size_t i = 0; i < cipher.size(); ++i)
            {
                RnsPoly ask{};
                RnsPoly dec{};
                if (!ringMultiply(a[i], sk, ctx, ask) ||
                    !ringSub(cipher[i], ask, ctx, dec))
                {
                    return false;
                }
                result.push_back(std::move(dec));
            }

            out = std::move(result);
            return true;
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

    bool validateParams(const ShrinkExpandParams& params)
    {
        if (!validateRingParams(params.mRing) ||
            params.mAlpha == 0u ||
            params.mMu == 0u ||
            params.mTau == 0u ||
            params.mPlaintextModulusBits == 0u ||
            params.mGadgetLogBase == 0u ||
            params.mNoiseBound < 0)
        {
            return false;
        }

        if (logQBits(params.mRing) <= params.mPlaintextModulusBits)
        {
            return false;
        }

        i64 ignored = 0;
        return resolveEffectiveNoiseBound(params, ignored);
    }

    bool resolveEffectiveNoiseBound(const ShrinkExpandParams& params, i64& out)
    {
        if (params.mMode != ShrinkExpandMode::FullNoise)
        {
            out = params.mNoiseBound;
            return true;
        }

        i64 baseFloor = 0;
        if (!computeBaseNoiseFloor(params.mRing, baseFloor))
        {
            return false;
        }

        out = (params.mNoiseBound > baseFloor) ? params.mNoiseBound : baseFloor;
        return true;
    }

    u64 metadataFingerprint(const ShrinkExpandParams& params)
    {
        u64 acc = mix64(params.mRing.mPolyModulusDegree);
        acc ^= mix64(params.mPlaintextModulusBits);
        acc ^= mix64(params.mAlpha);
        acc ^= mix64(params.mMu);
        acc ^= mix64(params.mTau);
        acc ^= mix64(params.mGadgetLogBase);
        acc ^= mix64(static_cast<u64>(params.mMode));

        for (std::size_t i = 0; i < params.mRing.mCoeffModulusBits.size(); ++i)
        {
            acc ^= mix64(static_cast<u64>(i + 1u) * static_cast<u64>(params.mRing.mCoeffModulusBits[i]));
        }

        return acc;
    }

    bool prepareSenderOffline(
        const ShrinkExpandSenderOfflineInput& input,
        ShrinkExpandOfflineMessage& message,
        ShrinkExpandSenderState& state)
    {
        if (!validateParams(input.mParams) ||
            input.mS.size() != input.mParams.mMu ||
            !validateRingBatchShape(input.mS, input.mParams.mRing))
        {
            return false;
        }

        RingNttContext ctx{};
        if (!makeRingNttContext(input.mParams.mRing, ctx))
        {
            return false;
        }

        ShrinkExpandSenderState nextState{};
        nextState.mParams = input.mParams;
        if (!resolveEffectiveNoiseBound(input.mParams, nextState.mEffectiveNoiseBound))
        {
            return false;
        }

        nextState.mS = input.mS;
        nextState.mSk1 = sampleUniformBatch(ctx, input.mParams.mTau, input.mParams.mNoiseSeed, 0xA002u);

        constexpr double kNoiseLambda = 128.0;
        const bool fullNoise = input.mParams.mMode == ShrinkExpandMode::FullNoise;
        const double lencSigma = fullNoise ? computeSigma(input.mParams) : 0.0;
        const double lencMaxDev = fullNoise ? std::sqrt(kNoiseLambda) * lencSigma : 0.0;

        LencEncodeOutput lenc{};
        if (!lencEnc(
                ctx,
                input.mS,
                input.mParams.mTau,
                input.mParams.mGadgetLogBase,
                input.mParams.mNoiseSeed ^ 0x1A2B3C4Dull,
                lenc,
                lencSigma,
                lencMaxDev,
                input.mParams.mNoiseSeed ^ 0x1EC0DEC0ull))
        {
            return false;
        }

        nextState.mR = std::move(lenc.mR);
        nextState.mLacct = std::move(lenc.mLacct);

        const double lheSigma = fullNoise ? computeSigma(input.mParams) : 0.0;
        const double lheMaxDev = fullNoise ? std::sqrt(kNoiseLambda) * lheSigma : 0.0;
        if (!lheEnc1(
                ctx,
                nextState.mR,
                nextState.mSk1,
                input.mParams.mGadgetLogBase,
                nextState.mCt1,
                lheSigma,
                lheMaxDev,
                input.mParams.mNoiseSeed ^ 0x1A1100E5ull))
        {
            return false;
        }

        ShrinkExpandOfflineMessage nextMessage{};
        nextMessage.mPolyModulusDegree = input.mParams.mRing.mPolyModulusDegree;
        nextMessage.mCoeffModulusBits.reserve(input.mParams.mRing.mCoeffModulusBits.size());
        for (const int bit : input.mParams.mRing.mCoeffModulusBits)
        {
            nextMessage.mCoeffModulusBits.push_back(static_cast<u16>(bit));
        }
        nextMessage.mPlaintextModulusBits = input.mParams.mPlaintextModulusBits;
        nextMessage.mAlpha = input.mParams.mAlpha;
        nextMessage.mMu = input.mParams.mMu;
        nextMessage.mTau = input.mParams.mTau;
        nextMessage.mGadgetLogBase = input.mParams.mGadgetLogBase;
        nextMessage.mMode = static_cast<u8>(input.mParams.mMode);
        nextMessage.mMetadataFingerprint = metadataFingerprint(input.mParams);
        nextMessage.mCt1Rows = nextState.mCt1.mRows;
        nextMessage.mCt1Cols = nextState.mCt1.mCols;
        nextMessage.mCt1Coeffs = packRingTensor(nextState.mCt1);
        nextMessage.mLacctWidthPadded = nextState.mLacct.mWidthPadded;
        nextMessage.mLacctLevels = nextState.mLacct.mLevels;
        nextMessage.mLacctCtRows = nextState.mLacct.mCt.mRows;
        nextMessage.mLacctCtCols = nextState.mLacct.mCt.mCols;
        nextMessage.mLacctCtCoeffs = packRingTensor(nextState.mLacct.mCt);

        state = std::move(nextState);
        message = std::move(nextMessage);
        return true;
    }

    bool finalizeReceiverOffline(
        const ShrinkExpandReceiverOfflineInput& input,
        const ShrinkExpandOfflineMessage& message,
        ShrinkExpandReceiverState& state)
    {
        if (!validateParams(input.mParams) ||
            message.mPolyModulusDegree != input.mParams.mRing.mPolyModulusDegree ||
            message.mCoeffModulusBits.size() != input.mParams.mRing.mCoeffModulusBits.size() ||
            message.mPlaintextModulusBits != input.mParams.mPlaintextModulusBits ||
            message.mAlpha != input.mParams.mAlpha ||
            message.mMu != input.mParams.mMu ||
            message.mTau != input.mParams.mTau ||
            message.mGadgetLogBase != input.mParams.mGadgetLogBase ||
            message.mMode != static_cast<u8>(input.mParams.mMode) ||
            message.mMetadataFingerprint != metadataFingerprint(input.mParams))
        {
            return false;
        }

        for (std::size_t i = 0; i < message.mCoeffModulusBits.size(); ++i)
        {
            if (static_cast<int>(message.mCoeffModulusBits[i]) != input.mParams.mRing.mCoeffModulusBits[i])
            {
                return false;
            }
        }

        const u32 coeffModCount = static_cast<u32>(input.mParams.mRing.mCoeffModulusBits.size());
        RingTensor ct1{};
        RingTensor lacctCt{};
        if (!unpackRingTensor(
                message.mCt1Rows,
                message.mCt1Cols,
                message.mPolyModulusDegree,
                coeffModCount,
                message.mCt1Coeffs,
                ct1) ||
            ct1.mRows != message.mMu ||
            ct1.mCols != message.mTau ||
            !unpackRingTensor(
                message.mLacctCtRows,
                message.mLacctCtCols,
                message.mPolyModulusDegree,
                coeffModCount,
                message.mLacctCtCoeffs,
                lacctCt))
        {
            return false;
        }

        if (message.mLacctWidthPadded == 0u ||
            (message.mLacctWidthPadded & (message.mLacctWidthPadded - 1u)) != 0u ||
            message.mLacctLevels == 0u ||
            lacctCt.mRows != message.mLacctLevels * message.mLacctWidthPadded ||
            lacctCt.mCols != 2u * message.mTau)
        {
            return false;
        }

        ShrinkExpandReceiverState next{};
        next.mParams = input.mParams;
        if (!resolveEffectiveNoiseBound(input.mParams, next.mEffectiveNoiseBound))
        {
            return false;
        }
        next.mCt1 = std::move(ct1);
        next.mLacct.mWidthPadded = message.mLacctWidthPadded;
        next.mLacct.mLevels = message.mLacctLevels;
        next.mLacct.mCt = std::move(lacctCt);

        state = std::move(next);
        return true;
    }

    bool shrink(
        const ShrinkExpandReceiverState& state,
        const std::vector<RnsPoly>& x,
        RnsPoly& digest)
    {
        if (x.size() != state.mParams.mMu)
        {
            return false;
        }

        RingNttContext ctx{};
        return makeRingNttContext(state.mParams.mRing, ctx) &&
               lencDigest(ctx, x, state.mParams.mTau, state.mParams.mGadgetLogBase, digest, state.mLacct.mWidthPadded);
    }

    bool deriveSkX(
        const ShrinkExpandSenderState& state,
        const RnsPoly& digest,
        const RnsPoly& tbkPrime,
        RnsPoly& out)
    {
        if (state.mSk1.size() != state.mParams.mTau)
        {
            return false;
        }

        RingNttContext ctx{};
        if (!makeRingNttContext(state.mParams.mRing, ctx) ||
            !validateRingBatchShape(state.mSk1, state.mParams.mRing) ||
            !validateRingPolyShape(digest, state.mParams.mRing) ||
            !validateRingPolyShape(tbkPrime, state.mParams.mRing))
        {
            return false;
        }

        std::vector<RnsPoly> u;
        if (!gadgetDecomposeBits(digest, state.mParams.mGadgetLogBase, state.mParams.mTau, ctx, u))
        {
            return false;
        }

        RnsPoly acc = tbkPrime;
        for (u32 i = 0; i < state.mParams.mTau; ++i)
        {
            RnsPoly term{};
            RnsPoly next{};
            if (!ringMultiply(state.mSk1[i], u[i], ctx, term) ||
                !ringAdd(acc, term, ctx, next))
            {
                return false;
            }
            acc = std::move(next);
        }

        out = std::move(acc);
        return true;
    }

    bool expandSender(
        const ShrinkExpandSenderState& state,
        const ShrinkExpandSenderExpandInput& input,
        ShrinkExpandSenderExpandOutput& output)
    {
        RingNttContext ctx{};
        if (!makeRingNttContext(state.mParams.mRing, ctx) ||
            !validateRingPolyShape(input.mTbkPrime, state.mParams.mRing))
        {
            return false;
        }

        std::vector<RnsPoly> ct2;
        std::vector<RnsPoly> tbk;
        if (!buildHashedCt2(ctx, state.mParams.mMu, input.mNonce, ct2) ||
            !lheDec(ctx, ct2, input.mTbkPrime, tbk))
        {
            return false;
        }

        ShrinkExpandSenderExpandOutput next{};
        next.mTbk = std::move(tbk);
        output = std::move(next);
        return true;
    }

    bool expandReceiver(
        const ShrinkExpandReceiverState& state,
        const ShrinkExpandReceiverExpandInput& input,
        ShrinkExpandReceiverExpandOutput& output)
    {
        if (input.mX.size() != state.mParams.mMu)
        {
            return false;
        }

        RingNttContext ctx{};
        if (!makeRingNttContext(state.mParams.mRing, ctx) ||
            !validateRingBatchShape(input.mX, state.mParams.mRing) ||
            !validateRingPolyShape(input.mDigest, state.mParams.mRing) ||
            !validateRingPolyShape(input.mSkX, state.mParams.mRing))
        {
            return false;
        }

        RnsPoly digestRecomputed{};
        if (!lencDigest(
                ctx,
                input.mX,
                state.mParams.mTau,
                state.mParams.mGadgetLogBase,
                digestRecomputed,
                state.mLacct.mWidthPadded) ||
            !polysEqual(digestRecomputed, input.mDigest))
        {
            return false;
        }

        std::vector<RnsPoly> ct2;
        std::vector<RnsPoly> ct1Applied;
        if (!buildHashedCt2(ctx, state.mParams.mMu, input.mNonce, ct2) ||
            !lheApplyCt1(ctx, state.mCt1, input.mDigest, state.mParams.mGadgetLogBase, state.mParams.mTau, ct1Applied))
        {
            return false;
        }

        std::vector<RnsPoly> ctRes;
        ctRes.reserve(state.mParams.mMu);
        for (std::size_t i = 0; i < state.mParams.mMu; ++i)
        {
            RnsPoly c{};
            if (!ringAdd(ct1Applied[i], ct2[i], ctx, c))
            {
                return false;
            }
            ctRes.push_back(std::move(c));
        }

        std::vector<RnsPoly> decCtRes;
        std::vector<RnsPoly> eval;
        if (!lheDec(ctx, ctRes, input.mSkX, decCtRes) ||
            !lencEval(
                ctx,
                state.mLacct,
                input.mX,
                state.mParams.mMu,
                state.mParams.mTau,
                state.mParams.mGadgetLogBase,
                eval))
        {
            return false;
        }

        ShrinkExpandReceiverExpandOutput next{};
        next.mTbm.reserve(state.mParams.mMu);
        for (std::size_t row = 0; row < state.mParams.mMu; ++row)
        {
            RnsPoly tbm{};
            if (!ringSub(decCtRes[row], eval[row], ctx, tbm))
            {
                return false;
            }
            next.mTbm.push_back(std::move(tbm));
        }

        output = std::move(next);
        return true;
    }

    bool denoiseComb(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& tbaPrime,
        std::vector<RnsPoly>& out)
    {
        if (ctx.mParams.mCoeffModulusBits.empty() ||
            tbaPrime.size() % ctx.mParams.mCoeffModulusBits.size() != 0)
        {
            return false;
        }

        const std::size_t rho = ctx.mParams.mCoeffModulusBits.size();
        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        const std::size_t wPrime = tbaPrime.size() / rho;

        for (const auto& poly : tbaPrime)
        {
            if (poly.mCoeffs.size() != n * rho)
            {
                return false;
            }
        }

        auto keyContextData = ctx.mContext ? ctx.mContext->key_context_data() : nullptr;
        if (!keyContextData)
        {
            return false;
        }

        seal::util::RNSBase fullBase(keyContextData->parms().coeff_modulus(), seal::MemoryManager::GetPool());
        auto pool = seal::MemoryManager::GetPool();

        auto composedPoly = seal::util::allocate_poly(n, rho, pool);
        auto termMpi = seal::util::allocate_uint(rho, pool);
        auto pJMpi = seal::util::allocate_uint(rho, pool);
        auto pJHalfMpi = seal::util::allocate_uint(rho, pool);
        auto modJMpi = seal::util::allocate_uint(rho, pool);
        auto quotientMpi = seal::util::allocate_uint(rho, pool);
        auto remainderMpi = seal::util::allocate_uint(rho, pool);

        std::vector<RnsPoly> result;
        result.reserve(wPrime);

        for (std::size_t i = 0; i < wPrime; ++i)
        {
            RnsPoly polyOut{};
            polyOut.mCoeffs.resize(n * rho, 0);

            for (std::size_t j = 0; j < rho; ++j)
            {
                const auto& polyIn = tbaPrime[i * rho + j];
                std::copy(polyIn.mCoeffs.begin(), polyIn.mCoeffs.end(), composedPoly.get());

                fullBase.compose_array(composedPoly.get(), n, pool);

                const auto modulusJ = fullBase.base()[j];
                seal::util::set_uint(modulusJ.value(), rho, modJMpi.get());

                seal::util::divide_uint(
                    fullBase.base_prod(), modJMpi.get(), rho, pJMpi.get(), remainderMpi.get(), pool);

                seal::util::right_shift_uint(pJMpi.get(), 1, rho, pJHalfMpi.get());

                for (std::size_t k = 0; k < n; ++k)
                {
                    const u64* valPtr = composedPoly.get() + k * rho;

                    seal::util::add_uint(valPtr, pJHalfMpi.get(), rho, termMpi.get());
                    seal::util::divide_uint(
                        termMpi.get(), pJMpi.get(), rho, quotientMpi.get(), remainderMpi.get(), pool);

                    u64 scaled = quotientMpi.get()[0];
                    if (scaled >= modulusJ.value())
                    {
                        scaled %= modulusJ.value();
                    }

                    polyOut.mCoeffs[j * n + k] = scaled;
                }
            }

            result.push_back(std::move(polyOut));
        }

        out = std::move(result);
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

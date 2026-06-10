#include "libOTe/Vole/LogVole/LogVoleLhe.h"
#include "libOTe/Vole/LogVole/LogVoleArithmetic.h"
#include "libOTe/Vole/LogVole/LogVoleRuntime.h"

#include <algorithm>
#include <cstddef>
#include <limits>
#include <memory>
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

        bool zeroPoly(const RingNttContext& ctx, RnsPoly& out)
        {
            resizeZero(out.mCoeffs, ringPolyCoeffCount(ctx.mParams));
            return true;
        }

        struct PublicACacheKey
        {
            RingParams mRing;
            u32 mCount = 0;
            u64 mRunId = 0;

            bool operator==(const PublicACacheKey& other) const
            {
                return mRing == other.mRing && mCount == other.mCount && mRunId == other.mRunId;
            }
        };

        struct PublicACacheKeyHash
        {
            std::size_t operator()(const PublicACacheKey& key) const
            {
                std::size_t h = std::hash<u32>{}(key.mRing.mPolyModulusDegree);
                h ^= std::hash<u32>{}(key.mCount) + 0x9e3779b9u + (h << 6u) + (h >> 2u);
                h ^= std::hash<u64>{}(key.mRunId) + 0x9e3779b9u + (h << 6u) + (h >> 2u);
                for (int bits : key.mRing.mCoeffModulusBits)
                {
                    const std::size_t b = std::hash<int>{}(bits);
                    h ^= b + 0x9e3779b9u + (h << 6u) + (h >> 2u);
                }
                return h;
            }
        };

        std::unordered_map<PublicACacheKey, std::shared_ptr<const std::vector<RnsPoly>>, PublicACacheKeyHash>
            publicACache;
        std::mutex publicACacheMutex;

        std::vector<RnsPoly> buildLhePublicANttImpl(const RingNttContext& ctx, u32 mu)
        {
            return deriveUniformPolyBatchFromNonceNtt(ctx, 0xA11ACE5Eull, 0xA110CA7Aull, mu);
        }

        std::shared_ptr<const std::vector<RnsPoly>> getOrCreateCachedPublicANtt(const RingNttContext& ctx, u32 mu)
        {
            PublicACacheKey key{};
            key.mRing = ctx.mParams;
            key.mCount = mu;
            key.mRunId = currentProtocolCacheScope().mRunId;

            {
                std::lock_guard<std::mutex> lock(publicACacheMutex);
                auto it = publicACache.find(key);
                if (it != publicACache.end())
                {
                    return it->second;
                }
            }

            auto candidate = std::make_shared<const std::vector<RnsPoly>>(buildLhePublicANttImpl(ctx, mu));

            std::lock_guard<std::mutex> lock(publicACacheMutex);
            auto [it, inserted] = publicACache.emplace(std::move(key), candidate);
            (void)inserted;
            return it->second;
        }

        bool validatePublicANtt(const RingNttContext& ctx, const std::vector<RnsPoly>& publicANtt, u32 expectedCount)
        {
            return publicANtt.size() == expectedCount && validateRingBatchShape(publicANtt, ctx.mParams);
        }

        bool scaleByGPowerInplace(const RingNttContext& ctx, RnsPoly& poly, u32 gadgetLogBase, u32 power)
        {
            const u64 shift = static_cast<u64>(gadgetLogBase) * static_cast<u64>(power);
            if (shift > static_cast<u64>(std::numeric_limits<u32>::max()))
            {
                return false;
            }

            const std::size_t n = ctx.mParams.mPolyModulusDegree;
            for (std::size_t modIdx = 0; modIdx < ctx.mModuli.size(); ++modIdx)
            {
                const u64 mod = ctx.mModuli[modIdx].value();
                const std::size_t offset = modIdx * n;
                const u64 factor = pow2Mod(shift, mod);
                for (std::size_t i = 0; i < n; ++i)
                {
                    const std::size_t idx = offset + i;
                    poly.mCoeffs[idx] = mulMod(poly.mCoeffs[idx] % mod, factor, ctx.mModuli[modIdx]);
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
        u32)
    {
        if (r.empty() || sk1.empty() || noiseStandardDeviation < 0 ||
            (noiseStandardDeviation > 0 && !prng) ||
            !validateRingBatchShape(r, ctx.mParams) ||
            !validateRingBatchShape(sk1, ctx.mParams))
        {
            return false;
        }

        std::shared_ptr<const std::vector<RnsPoly>> cachedPublicANtt;
        const u32 publicCount = static_cast<u32>(r.size());
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

        std::vector<RnsPoly> sk1Ntt = sk1;
        for (auto& poly : sk1Ntt)
        {
            if (!forwardNtt(poly, ctx))
            {
                return false;
            }
        }

        std::vector<RnsPoly> rNtt = r;
        if (!rInputIsNtt)
        {
            for (auto& poly : rNtt)
            {
                if (!forwardNtt(poly, ctx))
                {
                    return false;
                }
            }
        }

        RingTensor ct1{};
        ct1.mRows = publicCount;
        ct1.mCols = static_cast<u32>(sk1.size());
        ct1.mPolys.resize(ringTensorSize(ct1));

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
                    if (!addPolyError(cNtt, noiseStandardDeviation, noiseMaxDeviation, *prng, ctx))
                    {
                        return false;
                    }
                }

                ct1.mPolys[ringTensorIndex(ct1, row, col)] = std::move(cNtt);
            }
        }

        out = std::move(ct1);
        return true;
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
        u32 requestedWorkers)
    {
        if (r.empty() || sk1.empty())
        {
            return false;
        }

        std::vector<RnsPoly> shiftedR(r.size());
        for (std::size_t i = 0; i < r.size(); ++i)
        {
            if (!multiplyByGPower(ctx, r[i], gadgetLogBase, 1, shiftedR[i]))
            {
                return false;
            }
        }

        return lheEnc1(
            ctx,
            shiftedR,
            sk1,
            gadgetLogBase,
            out,
            noiseStandardDeviation,
            noiseMaxDeviation,
            prng,
            rInputIsNtt,
            publicANtt,
            requestedWorkers);
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
        for (auto& digit : u)
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
            if (!zeroPoly(ctx, accNtt))
            {
                return false;
            }

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
            if (!zeroPoly(ctx, accNtt))
            {
                return false;
            }

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
        out = deriveUniformPolyBatchFromSeed(ctx, ct2Seed, 0xC720AA55u, mu);
        return true;
    }

    bool lheDec(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& cipher,
        const RnsPoly& sk,
        std::vector<RnsPoly>& out,
        const std::vector<RnsPoly>* publicANtt,
        bool cipherInputIsNtt,
        bool outputNtt,
        u32)
    {
        if (cipher.empty() || !validateRingBatchShape(cipher, ctx.mParams) || !validateRingPolyShape(sk, ctx.mParams))
        {
            return false;
        }

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

        std::vector<RnsPoly> result(cipher.size());
        for (std::size_t row = 0; row < cipher.size(); ++row)
        {
            RnsPoly askNtt{};
            if (!zeroPoly(ctx, askNtt) ||
                !dyadicMultiplyAddNttInplace((*publicANtt)[row], skNtt, askNtt, ctx))
            {
                return false;
            }

            RnsPoly cNtt = cipher[row];
            if (!cipherInputIsNtt && !forwardNtt(cNtt, ctx))
            {
                return false;
            }

            if (!ringSubInplace(cNtt, askNtt, ctx))
            {
                return false;
            }

            if (!outputNtt && !inverseNtt(cNtt, ctx))
            {
                return false;
            }
            result[row] = std::move(cNtt);
        }

        out = std::move(result);
        return true;
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

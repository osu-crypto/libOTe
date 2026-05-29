#include "libOTe/Vole/LogVole2/LogVole2Core.h"

#include "seal/util/uintarithsmallmod.h"

#include <cstring>
#include <utility>

namespace osuCrypto::LogVole2
{
    namespace
    {
        bool makeContext(const RingParams& ring, RingNttContext& ctx)
        {
            return makeRingNttContext(ring, ctx);
        }
    }

    SeedLabelMode evalSeedLabelMode(u32 w, u32 alpha, u32 tau, u32 rho)
    {
        (void)alpha;
        return (w <= tau * rho) ? SeedLabelMode::Leaf : SeedLabelMode::Internal;
    }

    RecursiveMode evalRecursiveMode(u32 w, u32 alpha, u32 tau, u32 rho)
    {
        return (w <= alpha * tau * rho) ? RecursiveMode::Root : RecursiveMode::Internal;
    }

    bool seedLabelAgg(
        const std::vector<RnsPoly>& inputHat,
        u32 outCount,
        u32 tau,
        const RingParams& ring,
        std::vector<RnsPoly>& out)
    {
        if (tau == 0 || inputHat.size() != static_cast<std::size_t>(outCount) * tau ||
            !validateRingBatchShape(inputHat, ring))
        {
            return false;
        }

        RingNttContext ctx{};
        if (!makeContext(ring, ctx))
        {
            return false;
        }

        std::vector<RnsPoly> next;
        next.reserve(outCount);
        for (u32 i = 0; i < outCount; ++i)
        {
            RnsPoly sum = inputHat[static_cast<std::size_t>(i) * tau];
            for (u32 j = 1; j < tau; ++j)
            {
                if (!ringAddInplace(sum, inputHat[static_cast<std::size_t>(i) * tau + j], ctx))
                {
                    return false;
                }
            }
            next.push_back(std::move(sum));
        }

        out = std::move(next);
        return true;
    }

    bool seedLabelGadgetDecomposeAndUnbundle(
        const RnsPoly& digest,
        u32 gadgetLogBase,
        u32 tau,
        const RingParams& ring,
        std::vector<RnsPoly>& out)
    {
        RingNttContext ctx{};
        if (!makeContext(ring, ctx))
        {
            return false;
        }

        return gadgetDecomposeBits(digest, gadgetLogBase, tau, ctx, out);
    }

    bool seedLabelGadgetDecomposeHiAndUnbundle(
        const RnsPoly& digest,
        u32 gadgetLogBase,
        u32 tauHi,
        const RingParams& ring,
        std::vector<RnsPoly>& out)
    {
        if (tauHi == 0)
        {
            return false;
        }

        RingNttContext ctx{};
        if (!makeContext(ring, ctx))
        {
            return false;
        }

        std::vector<RnsPoly> digits;
        if (!gadgetDecomposeBitsRangeCentered(digest, gadgetLogBase, 1, tauHi, ctx, digits))
        {
            return false;
        }

        const std::size_t rho = ctx.mModuli.size();
        const std::size_t n = ring.mPolyModulusDegree;

        std::vector<u64> deltaJModQj(rho, 1);
        for (std::size_t j = 0; j < rho; ++j)
        {
            u64 delta = 1;
            for (std::size_t k = 0; k < rho; ++k)
            {
                if (k != j)
                {
                    delta = seal::util::multiply_uint_mod(delta, ctx.mModuli[k].value(), ctx.mModuli[j]);
                }
            }
            deltaJModQj[j] = delta;
        }

        std::vector<RnsPoly> unbundled;
        unbundled.reserve(digits.size() * rho);

        for (const auto& digit : digits)
        {
            for (std::size_t j = 0; j < rho; ++j)
            {
                RnsPoly lifted{};
                lifted.mCoeffs.assign(n * rho, 0);
                const std::size_t limbOffset = j * n;
                const u64* digitCoeffs = digit.mCoeffs.data();
                u64* liftedCoeffs = lifted.mCoeffs.data();

                for (std::size_t c = 0; c < n; ++c)
                {
                    const u64 value = digitCoeffs[limbOffset + c];
                    liftedCoeffs[limbOffset + c] =
                        seal::util::multiply_uint_mod(value, deltaJModQj[j], ctx.mModuli[j]);
                }

                unbundled.push_back(std::move(lifted));
            }
        }

        out = std::move(unbundled);
        return true;
    }

    bool seedLabelDenoiseTbm(
        const std::vector<RnsPoly>& tbmPrime,
        u32 wPrime,
        u32 tau,
        const RingParams& ring,
        std::vector<RnsPoly>& out)
    {
        if (tau == 0 || tbmPrime.size() != static_cast<std::size_t>(wPrime) * tau)
        {
            return false;
        }

        RingNttContext ctx{};
        if (!makeContext(ring, ctx))
        {
            return false;
        }

        return shrinkExpandDenoiseComb(ctx, tbmPrime, out);
    }

    bool seedLabelRepOfflineSenderInput(
        const std::vector<RnsPoly>& s,
        u32 gamma,
        u32 alpha,
        u32 tau,
        const RingParams& ring,
        std::vector<RnsPoly>& out)
    {
        const u32 rho = static_cast<u32>(ring.mCoeffModulusBits.size());
        if (alpha == 0 || tau == 0 || rho == 0)
        {
            return false;
        }

        const u32 mu = alpha * tau * rho;
        std::vector<RnsPoly> next;
        next.reserve(mu);

        if (gamma == 1)
        {
            if (s.empty() || !validateRingPolyShape(s[0], ring))
            {
                return false;
            }

            for (u32 i = 0; i < mu; ++i)
            {
                next.push_back(s[0]);
            }
            out = std::move(next);
            return true;
        }

        if (gamma != tau || s.size() < tau || !validateRingBatchShape(s, ring))
        {
            return false;
        }

        RingNttContext ctx{};
        if (!makeContext(ring, ctx))
        {
            return false;
        }

        std::vector<u64> deltaJModQj(rho, 1);
        for (std::size_t j = 0; j < rho; ++j)
        {
            u64 delta = 1;
            for (std::size_t k = 0; k < rho; ++k)
            {
                if (k != j)
                {
                    delta = seal::util::multiply_uint_mod(delta, ctx.mModuli[k].value(), ctx.mModuli[j]);
                }
            }
            deltaJModQj[j] = delta;
        }

        std::vector<RnsPoly> inner;
        inner.reserve(static_cast<std::size_t>(rho) * tau);
        for (u32 i = 0; i < tau; ++i)
        {
            for (std::size_t j = 0; j < rho; ++j)
            {
                RnsPoly poly = s[i];
                u64* coeffs = poly.mCoeffs.data();
                for (std::size_t k = 0; k < rho; ++k)
                {
                    const std::size_t offset = k * ring.mPolyModulusDegree;
                    if (k != j)
                    {
                        std::memset(
                            coeffs + offset,
                            0,
                            static_cast<std::size_t>(ring.mPolyModulusDegree) * sizeof(u64));
                    }
                    else
                    {
                        for (std::size_t c = 0; c < ring.mPolyModulusDegree; ++c)
                        {
                            const std::size_t idx = offset + c;
                            coeffs[idx] =
                                seal::util::multiply_uint_mod(coeffs[idx], deltaJModQj[j], ctx.mModuli[j]);
                        }
                    }
                }
                inner.push_back(std::move(poly));
            }
        }

        for (u32 i = 0; i < alpha; ++i)
        {
            for (const auto& poly : inner)
            {
                next.push_back(poly);
            }
        }

        out = std::move(next);
        return true;
    }

    bool seedLabelSampleCt2FromSeed(
        const SamplingSeedConfig& samplingSeeds,
        const std::vector<u8>& seed,
        u32 instanceIdx,
        u32 coeffCount,
        const RingParams& ring,
        std::vector<RnsPoly>& out)
    {
        RingNttContext ctx{};
        if (!makeContext(ring, ctx))
        {
            return false;
        }

        const u64 instanceNonce =
            deriveSeedInstanceNonce(samplingSeeds, seed, static_cast<u64>(instanceIdx));
        return buildHashedCt2(ctx, coeffCount, samplingSeeds, instanceNonce, out);
    }
}

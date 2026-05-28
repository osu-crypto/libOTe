#include "libOTe/Vole/LogVole/LogVoleRing.h"

#include "seal/util/clipnormal.h"
#include "seal/util/iterator.h"
#include "seal/util/ntt.h"
#include "seal/util/polyarithsmallmod.h"
#include "seal/util/uintarithsmallmod.h"

#include <algorithm>
#include <cstddef>
#include <exception>
#include <limits>
#include <random>

namespace osuCrypto
{
    namespace
    {
        bool logVoleIsPowerOfTwo(u32 value)
        {
            return value > 0 && (value & (value - 1u)) == 0u;
        }

        bool logVoleValidateShapeAgainstContext(const LogVoleRnsPoly& poly, const LogVoleRingNttContext& ctx)
        {
            return poly.mCoeffs.size() == logVolePolyCoeffCount(ctx.mParams);
        }

        u64 logVoleCombineSeed(u64 value)
        {
            value += 0x9E3779B97F4A7C15ull;
            value = (value ^ (value >> 30u)) * 0xBF58476D1CE4E5B9ull;
            value = (value ^ (value >> 27u)) * 0x94D049BB133111EBull;
            return value ^ (value >> 31u);
        }

        u64 logVoleBasePowMod(u64 base, u32 exp, u64 mod)
        {
            seal::Modulus modulus(mod);
            u64 result = 1u;
            u64 power = base % mod;
            u32 e = exp;
            while (e > 0u)
            {
                if ((e & 1u) != 0u)
                {
                    result = seal::util::multiply_uint_mod(result, power, modulus);
                }
                power = seal::util::multiply_uint_mod(power, power, modulus);
                e >>= 1u;
            }
            return result;
        }

        u64 logVoleAddMod(u64 lhs, u64 rhs, u64 mod)
        {
            const u64 sum = lhs + rhs;
            return (sum >= mod) ? (sum - mod) : sum;
        }

        void logVoleSamplePolyNormal(
            std::shared_ptr<seal::UniformRandomGenerator> prng,
            const seal::EncryptionParameters& parms,
            u64* destination,
            double noiseStandardDeviation,
            double noiseMaxDeviation)
        {
            auto& coeffModulus = parms.coeff_modulus();
            const std::size_t coeffModulusSize = coeffModulus.size();
            const std::size_t coeffCount = parms.poly_modulus_degree();

            seal::RandomToStandardAdapter engine(prng);
            seal::util::ClippedNormalDistribution dist(0, noiseStandardDeviation, noiseMaxDeviation);

            SEAL_ITERATE(seal::util::iter(destination), coeffCount, [&](auto& I) {
                const i64 noise = static_cast<i64>(dist(engine));
                const u64 flag = static_cast<u64>(-static_cast<i64>(noise < 0));
                SEAL_ITERATE(
                    seal::util::iter(seal::util::StrideIter<u64*>(&I, coeffCount), coeffModulus),
                    coeffModulusSize,
                    [&](auto J) {
                        *::std::get<0>(J) = static_cast<u64>(noise) + (flag & ::std::get<1>(J).value());
                    });
            });
        }
    }

    bool logVoleValidateRingParams(const LogVoleRingParams& params)
    {
        if (!logVoleIsPowerOfTwo(params.mPolyModulusDegree) || params.mPolyModulusDegree < 1024u)
        {
            return false;
        }

        if (params.mCoeffModulusBits.empty())
        {
            return false;
        }

        if (params.mCoeffModulusBits.size() > static_cast<std::size_t>(std::numeric_limits<u32>::max()))
        {
            return false;
        }

        for (const int bits : params.mCoeffModulusBits)
        {
            if (bits < 2 || bits > 60)
            {
                return false;
            }
        }

        return true;
    }

    bool logVoleValidateRingPolyShape(const LogVoleRnsPoly& poly, const LogVoleRingParams& params)
    {
        return poly.mCoeffs.size() == logVolePolyCoeffCount(params);
    }

    bool logVoleValidateRingBatchShape(const std::vector<LogVoleRnsPoly>& polys, const LogVoleRingParams& params)
    {
        for (const auto& poly : polys)
        {
            if (!logVoleValidateRingPolyShape(poly, params))
            {
                return false;
            }
        }
        return true;
    }

    bool logVoleMakeRingNttContext(const LogVoleRingParams& params, LogVoleRingNttContext& ctx)
    {
        if (!logVoleValidateRingParams(params))
        {
            return false;
        }

        std::vector<seal::Modulus> moduli;
        try
        {
            moduli = seal::CoeffModulus::Create(params.mPolyModulusDegree, params.mCoeffModulusBits);
        }
        catch (const std::exception&)
        {
            return false;
        }

        if (moduli.size() != params.mCoeffModulusBits.size())
        {
            return false;
        }

        seal::EncryptionParameters parms(seal::scheme_type::ckks);
        parms.set_poly_modulus_degree(params.mPolyModulusDegree);
        parms.set_coeff_modulus(moduli);

        LogVoleRingNttContext next{};
        next.mParams = params;
        next.mModuli = std::move(moduli);
        next.mContext = std::make_shared<seal::SEALContext>(parms, true, seal::sec_level_type::none);
        if (!next.mContext || !next.mContext->key_context_data())
        {
            return false;
        }

        if (next.mContext->key_context_data()->parms().coeff_modulus().size() != params.mCoeffModulusBits.size())
        {
            return false;
        }

        ctx = std::move(next);
        return true;
    }

    bool logVoleCanonicalizePoly(LogVoleRnsPoly& poly, const LogVoleRingNttContext& ctx)
    {
        if (!logVoleValidateShapeAgainstContext(poly, ctx))
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
                poly.mCoeffs[offset + i] %= mod;
            }
        }

        return true;
    }

    bool logVoleForwardNtt(LogVoleRnsPoly& poly, const LogVoleRingNttContext& ctx)
    {
        if (!logVoleCanonicalizePoly(poly, ctx) || !ctx.mContext || !ctx.mContext->key_context_data())
        {
            return false;
        }

        const auto& tables = ctx.mContext->key_context_data()->small_ntt_tables();
        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        for (std::size_t modIdx = 0; modIdx < ctx.mModuli.size(); ++modIdx)
        {
            seal::util::ntt_negacyclic_harvey(poly.mCoeffs.data() + (modIdx * n), tables[modIdx]);
        }

        return true;
    }

    bool logVoleInverseNtt(LogVoleRnsPoly& poly, const LogVoleRingNttContext& ctx)
    {
        if (!logVoleValidateShapeAgainstContext(poly, ctx) || !ctx.mContext || !ctx.mContext->key_context_data())
        {
            return false;
        }

        const auto& tables = ctx.mContext->key_context_data()->small_ntt_tables();
        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        for (std::size_t modIdx = 0; modIdx < ctx.mModuli.size(); ++modIdx)
        {
            seal::util::inverse_ntt_negacyclic_harvey(poly.mCoeffs.data() + (modIdx * n), tables[modIdx]);
        }

        return logVoleCanonicalizePoly(poly, ctx);
    }

    bool logVoleDyadicMultiplyAddNtt(
        const LogVoleRnsPoly& aNtt,
        const LogVoleRnsPoly& bNtt,
        const LogVoleRnsPoly& cNtt,
        const LogVoleRingNttContext& ctx,
        LogVoleRnsPoly& out)
    {
        if (!logVoleValidateShapeAgainstContext(aNtt, ctx) ||
            !logVoleValidateShapeAgainstContext(bNtt, ctx) ||
            !logVoleValidateShapeAgainstContext(cNtt, ctx))
        {
            return false;
        }

        LogVoleRnsPoly next{};
        next.mCoeffs.resize(aNtt.mCoeffs.size(), 0u);

        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        for (std::size_t modIdx = 0; modIdx < ctx.mModuli.size(); ++modIdx)
        {
            const auto& modulus = ctx.mModuli[modIdx];
            const u64 mod = modulus.value();
            const std::size_t offset = modIdx * n;
            for (std::size_t i = 0; i < n; ++i)
            {
                const std::size_t index = offset + i;
                const u64 mulMod =
                    seal::util::multiply_uint_mod(aNtt.mCoeffs[index] % mod, bNtt.mCoeffs[index] % mod, modulus);
                next.mCoeffs[index] = logVoleAddMod(mulMod, cNtt.mCoeffs[index], mod);
            }
        }

        out = std::move(next);
        return true;
    }

    bool logVoleRingAdd(
        const LogVoleRnsPoly& a,
        const LogVoleRnsPoly& b,
        const LogVoleRingNttContext& ctx,
        LogVoleRnsPoly& out)
    {
        if (!logVoleValidateShapeAgainstContext(a, ctx) || !logVoleValidateShapeAgainstContext(b, ctx))
        {
            return false;
        }

        LogVoleRnsPoly next{};
        next.mCoeffs.resize(a.mCoeffs.size(), 0u);

        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        for (std::size_t modIdx = 0; modIdx < ctx.mModuli.size(); ++modIdx)
        {
            const u64 mod = ctx.mModuli[modIdx].value();
            const std::size_t offset = modIdx * n;
            for (std::size_t i = 0; i < n; ++i)
            {
                const std::size_t idx = offset + i;
                next.mCoeffs[idx] = logVoleAddMod(a.mCoeffs[idx], b.mCoeffs[idx], mod);
            }
        }

        out = std::move(next);
        return true;
    }

    bool logVoleRingSub(
        const LogVoleRnsPoly& a,
        const LogVoleRnsPoly& b,
        const LogVoleRingNttContext& ctx,
        LogVoleRnsPoly& out)
    {
        if (!logVoleValidateShapeAgainstContext(a, ctx) || !logVoleValidateShapeAgainstContext(b, ctx))
        {
            return false;
        }

        LogVoleRnsPoly next{};
        next.mCoeffs.resize(a.mCoeffs.size(), 0u);

        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        for (std::size_t modIdx = 0; modIdx < ctx.mModuli.size(); ++modIdx)
        {
            const u64 mod = ctx.mModuli[modIdx].value();
            const std::size_t offset = modIdx * n;
            for (std::size_t i = 0; i < n; ++i)
            {
                const std::size_t idx = offset + i;
                const u64 av = a.mCoeffs[idx] % mod;
                const u64 bv = b.mCoeffs[idx] % mod;
                next.mCoeffs[idx] = (av >= bv) ? (av - bv) : static_cast<u64>(mod - (bv - av));
            }
        }

        out = std::move(next);
        return true;
    }

    bool logVoleRingMultiply(
        const LogVoleRnsPoly& a,
        const LogVoleRnsPoly& b,
        const LogVoleRingNttContext& ctx,
        LogVoleRnsPoly& out)
    {
        if (!logVoleValidateShapeAgainstContext(a, ctx) || !logVoleValidateShapeAgainstContext(b, ctx))
        {
            return false;
        }

        LogVoleRnsPoly aNtt = a;
        LogVoleRnsPoly bNtt = b;
        if (!logVoleForwardNtt(aNtt, ctx) || !logVoleForwardNtt(bNtt, ctx))
        {
            return false;
        }

        LogVoleRnsPoly zero{};
        zero.mCoeffs.assign(aNtt.mCoeffs.size(), 0u);

        LogVoleRnsPoly productNtt{};
        if (!logVoleDyadicMultiplyAddNtt(aNtt, bNtt, zero, ctx, productNtt) ||
            !logVoleInverseNtt(productNtt, ctx))
        {
            return false;
        }

        out = std::move(productNtt);
        return true;
    }

    bool logVoleRingMultiplyScalar(
        const LogVoleRnsPoly& a,
        u64 scalar,
        const LogVoleRingNttContext& ctx,
        LogVoleRnsPoly& out)
    {
        if (!logVoleValidateShapeAgainstContext(a, ctx))
        {
            return false;
        }

        LogVoleRnsPoly next = a;
        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        for (std::size_t modIdx = 0; modIdx < ctx.mModuli.size(); ++modIdx)
        {
            const auto& modulus = ctx.mModuli[modIdx];
            const u64 mod = modulus.value();
            const u64 scalarMod = scalar % mod;
            const std::size_t offset = modIdx * n;
            for (std::size_t i = 0; i < n; ++i)
            {
                const std::size_t idx = offset + i;
                next.mCoeffs[idx] = seal::util::multiply_uint_mod(next.mCoeffs[idx] % mod, scalarMod, modulus);
            }
        }

        out = std::move(next);
        return true;
    }

    bool logVoleGadgetDecompose(
        const LogVoleRnsPoly& poly,
        u32 base,
        u32 tau,
        const LogVoleRingNttContext& ctx,
        std::vector<LogVoleRnsPoly>& out)
    {
        if (base < 2u || tau == 0u || !logVoleValidateShapeAgainstContext(poly, ctx))
        {
            return false;
        }

        LogVoleRnsPoly canonical = poly;
        if (!logVoleCanonicalizePoly(canonical, ctx))
        {
            return false;
        }

        std::vector<LogVoleRnsPoly> next(tau);
        for (auto& digit : next)
        {
            digit.mCoeffs.assign(canonical.mCoeffs.size(), 0u);
        }

        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        const u64 baseU64 = static_cast<u64>(base);
        for (std::size_t modIdx = 0; modIdx < ctx.mModuli.size(); ++modIdx)
        {
            const u64 mod = ctx.mModuli[modIdx].value();
            const std::size_t offset = modIdx * n;
            for (std::size_t i = 0; i < n; ++i)
            {
                u64 value = canonical.mCoeffs[offset + i] % mod;
                for (u32 j = 0; j < tau; ++j)
                {
                    next[j].mCoeffs[offset + i] = value % baseU64;
                    value /= baseU64;
                }
            }
        }

        out = std::move(next);
        return true;
    }

    bool logVoleGadgetRecompose(
        const std::vector<LogVoleRnsPoly>& digits,
        u32 base,
        const LogVoleRingNttContext& ctx,
        LogVoleRnsPoly& out)
    {
        if (digits.empty() || base < 2u)
        {
            return false;
        }

        for (const auto& digit : digits)
        {
            if (!logVoleValidateShapeAgainstContext(digit, ctx))
            {
                return false;
            }
        }

        LogVoleRnsPoly next{};
        next.mCoeffs.assign(digits[0].mCoeffs.size(), 0u);

        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        for (std::size_t modIdx = 0; modIdx < ctx.mModuli.size(); ++modIdx)
        {
            const u64 mod = ctx.mModuli[modIdx].value();
            const std::size_t offset = modIdx * n;

            std::vector<u64> basePows(digits.size(), 1u);
            for (std::size_t j = 0; j < digits.size(); ++j)
            {
                basePows[j] = logVoleBasePowMod(static_cast<u64>(base), static_cast<u32>(j), mod);
            }

            for (std::size_t i = 0; i < n; ++i)
            {
                u64 acc = 0u;
                for (std::size_t j = 0; j < digits.size(); ++j)
                {
                    const u64 term = seal::util::multiply_uint_mod(
                        digits[j].mCoeffs[offset + i] % mod, basePows[j], ctx.mModuli[modIdx]);
                    acc = logVoleAddMod(acc, term, mod);
                }
                next.mCoeffs[offset + i] = acc;
            }
        }

        out = std::move(next);
        return true;
    }

    bool logVoleGadgetDecomposeBits(
        const LogVoleRnsPoly& poly,
        u32 digitBits,
        u32 levels,
        const LogVoleRingNttContext& ctx,
        std::vector<LogVoleRnsPoly>& out)
    {
        if (digitBits == 0u || levels == 0u || !logVoleValidateShapeAgainstContext(poly, ctx))
        {
            return false;
        }

        LogVoleRnsPoly canonical = poly;
        if (!logVoleCanonicalizePoly(canonical, ctx))
        {
            return false;
        }

        auto contextData = ctx.mContext ? ctx.mContext->key_context_data() : nullptr;
        if (!contextData)
        {
            return false;
        }

        std::vector<LogVoleRnsPoly> next(levels);
        for (auto& digit : next)
        {
            digit.mCoeffs.assign(canonical.mCoeffs.size(), 0u);
        }

        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        const std::size_t coeffModCount = ctx.mModuli.size();
        seal::util::Pointer<u64> composedPoly =
            seal::util::allocate_poly(n, coeffModCount, seal::MemoryManager::GetPool());
        std::copy(canonical.mCoeffs.begin(), canonical.mCoeffs.end(), composedPoly.get());
        contextData->rns_tool()->base_q()->compose_array(composedPoly.get(), n, seal::MemoryManager::GetPool());

        auto tempMpi = seal::util::allocate_uint(coeffModCount, seal::MemoryManager::GetPool());
        for (std::size_t i = 0; i < n; ++i)
        {
            u64* valuePtr = composedPoly.get() + i * coeffModCount;
            for (u32 level = 0; level < levels; ++level)
            {
                seal::util::set_uint(valuePtr, coeffModCount, tempMpi.get());

                for (std::size_t w = 0; w < coeffModCount; ++w)
                {
                    const u32 bitOffset = static_cast<u32>(w * 64u);
                    if (bitOffset >= digitBits)
                    {
                        tempMpi[w] = 0;
                    }
                    else if (bitOffset + 64u > digitBits)
                    {
                        const u32 remainingBits = digitBits - bitOffset;
                        const u64 mask = (static_cast<u64>(1u) << remainingBits) - 1u;
                        tempMpi[w] &= mask;
                    }
                }

                for (std::size_t modIdx = 0; modIdx < coeffModCount; ++modIdx)
                {
                    next[level].mCoeffs[modIdx * n + i] =
                        seal::util::modulo_uint(tempMpi.get(), coeffModCount, ctx.mModuli[modIdx]);
                }

                seal::util::right_shift_uint(valuePtr, digitBits, coeffModCount, valuePtr);
            }
        }

        out = std::move(next);
        return true;
    }

    bool logVoleGadgetRecomposeBits(
        const std::vector<LogVoleRnsPoly>& digits,
        u32 digitBits,
        const LogVoleRingNttContext& ctx,
        LogVoleRnsPoly& out)
    {
        if (digits.empty() || digitBits == 0u)
        {
            return false;
        }

        for (const auto& digit : digits)
        {
            if (!logVoleValidateShapeAgainstContext(digit, ctx))
            {
                return false;
            }
        }

        LogVoleRnsPoly next{};
        next.mCoeffs.assign(digits[0].mCoeffs.size(), 0u);

        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        for (std::size_t modIdx = 0; modIdx < ctx.mModuli.size(); ++modIdx)
        {
            const u64 mod = ctx.mModuli[modIdx].value();
            const std::size_t offset = modIdx * n;

            std::vector<u64> pow2Shifts(digits.size(), 0u);
            for (std::size_t level = 0; level < digits.size(); ++level)
            {
                const u64 shiftU64 = static_cast<u64>(level) * static_cast<u64>(digitBits);
                if (shiftU64 > static_cast<u64>(std::numeric_limits<u32>::max()))
                {
                    return false;
                }
                pow2Shifts[level] = logVoleBasePowMod(2u, static_cast<u32>(shiftU64), mod);
            }

            for (std::size_t i = 0; i < n; ++i)
            {
                u64 acc = 0u;
                for (std::size_t level = 0; level < digits.size(); ++level)
                {
                    const u64 term = seal::util::multiply_uint_mod(
                        digits[level].mCoeffs[offset + i] % mod, pow2Shifts[level], ctx.mModuli[modIdx]);
                    acc = logVoleAddMod(acc, term, mod);
                }
                next.mCoeffs[offset + i] = acc;
            }
        }

        out = std::move(next);
        return true;
    }

    std::vector<u64> logVolePackRingBatch(const std::vector<LogVoleRnsPoly>& polys)
    {
        std::size_t total = 0;
        for (const auto& poly : polys)
        {
            total += poly.mCoeffs.size();
        }

        std::vector<u64> out;
        out.reserve(total);
        for (const auto& poly : polys)
        {
            out.insert(out.end(), poly.mCoeffs.begin(), poly.mCoeffs.end());
        }

        return out;
    }

    bool logVoleUnpackRingBatch(
        u32 count,
        u32 polyModulusDegree,
        u32 coeffModulusCount,
        const std::vector<u64>& flat,
        std::vector<LogVoleRnsPoly>& out)
    {
        if (count == 0u || polyModulusDegree == 0u || coeffModulusCount == 0u)
        {
            return false;
        }

        const std::size_t perPoly = static_cast<std::size_t>(polyModulusDegree) * coeffModulusCount;
        if (perPoly == 0u || count > std::numeric_limits<std::size_t>::max() / perPoly)
        {
            return false;
        }

        const std::size_t expected = static_cast<std::size_t>(count) * perPoly;
        if (flat.size() != expected)
        {
            return false;
        }

        std::vector<LogVoleRnsPoly> next;
        next.reserve(count);
        for (std::size_t i = 0; i < count; ++i)
        {
            const auto begin = flat.begin() + static_cast<std::ptrdiff_t>(i * perPoly);
            const auto end = begin + static_cast<std::ptrdiff_t>(perPoly);
            next.push_back(LogVoleRnsPoly{ std::vector<u64>(begin, end) });
        }

        out = std::move(next);
        return true;
    }

    std::vector<u64> logVolePackRingTensor(const LogVoleRingTensor& tensor)
    {
        return logVolePackRingBatch(tensor.mPolys);
    }

    bool logVoleUnpackRingTensor(
        u32 rows,
        u32 cols,
        u32 polyModulusDegree,
        u32 coeffModulusCount,
        const std::vector<u64>& flat,
        LogVoleRingTensor& out)
    {
        if (rows == 0u || cols == 0u || rows > std::numeric_limits<u32>::max() / cols)
        {
            return false;
        }

        std::vector<LogVoleRnsPoly> polys;
        if (!logVoleUnpackRingBatch(rows * cols, polyModulusDegree, coeffModulusCount, flat, polys))
        {
            return false;
        }

        LogVoleRingTensor next{};
        next.mRows = rows;
        next.mCols = cols;
        next.mPolys = std::move(polys);
        out = std::move(next);
        return true;
    }

    LogVoleRnsPoly logVoleDeriveUniformPolyFromNonce(
        const LogVoleRingNttContext& ctx,
        u64 nonce,
        u64 domainTag,
        u32 index)
    {
        const u64 rawSeed = logVoleCombineSeed(nonce) ^ logVoleCombineSeed(domainTag) ^
                            logVoleCombineSeed(index) ^ logVoleCombineSeed(ctx.mParams.mPolyModulusDegree) ^
                            logVoleCombineSeed(static_cast<u64>(ctx.mParams.mCoeffModulusBits.size()));

        std::mt19937_64 rng(rawSeed);
        LogVoleRnsPoly out{};
        out.mCoeffs.resize(logVolePolyCoeffCount(ctx.mParams), 0u);

        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        for (std::size_t modIdx = 0; modIdx < ctx.mModuli.size(); ++modIdx)
        {
            const u64 mod = ctx.mModuli[modIdx].value();
            std::uniform_int_distribution<u64> dist(0u, mod - 1u);
            const std::size_t offset = modIdx * n;
            for (std::size_t i = 0; i < n; ++i)
            {
                out.mCoeffs[offset + i] = dist(rng);
            }
        }

        return out;
    }

    bool logVoleAddGaussianNoise(
        LogVoleRnsPoly& poly,
        double noiseStandardDeviation,
        double noiseMaxDeviation,
        u64 seed,
        u64 streamId,
        const LogVoleRingNttContext& ctx)
    {
        if (noiseStandardDeviation < 0 || !logVoleCanonicalizePoly(poly, ctx))
        {
            return false;
        }

        const u64 rawSeed = logVoleCombineSeed(seed) ^ logVoleCombineSeed(streamId);
        auto prng = seal::UniformRandomGeneratorFactory::DefaultFactory()->create({ rawSeed, 0 });
        seal::RandomToStandardAdapter engine(prng);
        seal::util::ClippedNormalDistribution dist(0, noiseStandardDeviation, noiseMaxDeviation);

        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        for (std::size_t modIdx = 0; modIdx < ctx.mModuli.size(); ++modIdx)
        {
            const u64 mod = ctx.mModuli[modIdx].value();
            const std::size_t offset = modIdx * n;
            for (std::size_t i = 0; i < n; ++i)
            {
                const std::size_t idx = offset + i;
                const i64 noise = static_cast<i64>(dist(engine));
                const u64 value = poly.mCoeffs[idx] % mod;
                if (noise >= 0)
                {
                    poly.mCoeffs[idx] = logVoleAddMod(value, static_cast<u64>(noise), mod);
                }
                else
                {
                    const u64 absNoise = static_cast<u64>(-noise) % mod;
                    poly.mCoeffs[idx] = (value >= absNoise) ? static_cast<u64>(value - absNoise)
                                                            : static_cast<u64>(mod - (absNoise - value));
                }
            }
        }

        return true;
    }

    bool logVoleAddPolyError(
        LogVoleRnsPoly& poly,
        double noiseStandardDeviation,
        double noiseMaxDeviation,
        u64 seed,
        u64 streamId,
        const LogVoleRingNttContext& ctx)
    {
        if (noiseStandardDeviation < 0 || !logVoleCanonicalizePoly(poly, ctx))
        {
            return false;
        }

        auto contextDataPtr = ctx.mContext ? ctx.mContext->key_context_data() : nullptr;
        if (!contextDataPtr)
        {
            return false;
        }

        const u64 rawSeed = logVoleCombineSeed(seed) ^ logVoleCombineSeed(streamId);
        auto prng = seal::UniformRandomGeneratorFactory::DefaultFactory()->create({ rawSeed, 0 });

        auto& contextData = *contextDataPtr;
        auto& parms = contextData.parms();
        auto& coeffModulus = parms.coeff_modulus();
        const std::size_t coeffModulusSize = coeffModulus.size();
        const std::size_t coeffCount = parms.poly_modulus_degree();

        seal::util::Pointer<u64> temp =
            seal::util::allocate_poly(coeffCount, coeffModulusSize, seal::MemoryManager::GetPool());
        seal::util::RNSIter tempIter(temp.get(), coeffCount);

        logVoleSamplePolyNormal(prng, parms, temp.get(), noiseStandardDeviation, noiseMaxDeviation);

        seal::util::PolyIter destinationIter(poly.mCoeffs.data(), coeffCount, coeffModulusSize);
        seal::util::add_poly_coeffmod(
            destinationIter[0], tempIter, coeffModulusSize, coeffModulus, destinationIter[0]);

        return true;
    }
}

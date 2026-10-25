#include "libOTe/Vole/LogVole/LogVoleCpuArithmetic.h"
#include "libOTe/Vole/LogVole/LogVoleArithmetic.h"
#include <algorithm>
#include <cstdlib>

#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
#include <immintrin.h>
#define LV_CPU_IFMA 1
#endif

namespace osuCrypto::LogVole::detail
{
    namespace
    {
#if defined(__SIZEOF_INT128__)
        template<std::size_t Limbs>
        void composeRns(const u64* source, u64* destination,
            std::size_t count, const seal::util::RNSBase& base, std::size_t start = 0)
        {
            const auto* moduli = base.base();
            const auto* inverse = base.inv_punctured_prod_mod_base_array();
            const auto* punctured = base.punctured_prod_array();
            const auto* q = base.base_prod();
            for (std::size_t coeff = start; coeff < count; ++coeff)
            {
                u64 sum[Limbs]{};
                for (std::size_t j = 0; j < Limbs; ++j)
                {
                    const u64 scalar = seal::util::multiply_uint_mod(
                        source[j * count + coeff], inverse[j], moduli[j]);
                    u64 carry = 0;
                    for (std::size_t w = 0; w < Limbs; ++w)
                    {
                        const __uint128_t acc = static_cast<__uint128_t>(punctured[j * Limbs + w]) *
                            scalar + sum[w] + carry;
                        sum[w] = static_cast<u64>(acc);
                        carry = static_cast<u64>(acc >> 64);
                    }
                }
                // Each term is <Q. With <=61-bit moduli, Limbs*Q fits in
                // 64*Limbs bits for both 4 and 8 limbs, so accumulating before
                // reduction is exact and needs at most Limbs-1 subtractions.
                while (true)
                {
                    bool atLeastQ = true;
                    for (std::size_t w = Limbs; w-- > 0;)
                        if (sum[w] != q[w]) { atLeastQ = sum[w] > q[w]; break; }
                    if (!atLeastQ) break;
                    unsigned char borrow = 0;
                    for (std::size_t w = 0; w < Limbs; ++w)
                    {
                        unsigned long long word;
                        borrow = seal::util::sub_uint64(sum[w], q[w], borrow, &word);
                        sum[w] = word;
                    }
                }
                std::copy_n(sum, Limbs, destination + coeff * Limbs);
            }
        }
#endif
#if defined(LV_CPU_IFMA)
        template<unsigned Bits>
        __attribute__((target("avx512f,avx512dq"), always_inline))
        inline __m512i reduceInput(__m512i value, __m512i q, __m512i gap)
        {
            // For Bits>=52 and gap<2^24, one fold of an arbitrary u64 is <2q.
            value = _mm512_add_epi64(_mm512_and_si512(value,
                _mm512_set1_epi64((u64{1} << Bits) - 1)),
                _mm512_mullo_epi64(_mm512_srli_epi64(value, Bits), gap));
            return _mm512_mask_sub_epi64(value,
                _mm512_cmp_epu64_mask(value, q, _MM_CMPINT_NLT), value, q);
        }

        __attribute__((target("avx512f")))
        bool containsRejected(const u64* source, std::size_t count, u64 limit)
        {
            const auto bound = _mm512_set1_epi64(limit);
            std::size_t i = 0;
            for (; i + 8 <= count; i += 8)
                if (_mm512_cmp_epu64_mask(_mm512_loadu_si512(source + i), bound, _MM_CMPINT_NLT))
                    return true;
            for (; i < count; ++i) if (source[i] >= limit) return true;
            return false;
        }

        template<unsigned Bits>
        __attribute__((target("avx512f,avx512dq")))
        void reduceMod(const u64* source, u64* destination, std::size_t count, u64 modulus)
        {
            const auto q = _mm512_set1_epi64(modulus);
            const auto gap = _mm512_set1_epi64((u64{1} << Bits) - modulus);
            for (std::size_t i = 0; i < count; i += 8)
            {
                const auto lanes = static_cast<__mmask8>((1u << std::min<std::size_t>(8, count - i)) - 1);
                const auto value = _mm512_maskz_loadu_epi64(lanes, source + i);
                _mm512_mask_storeu_epi64(destination + i, lanes, reduceInput<Bits>(value, q, gap));
            }
        }

        // Exact high half of a 64x64-bit product. The middle sum is <3*2^32;
        // each partial product fits in u64, including all carry boundaries.
        __attribute__((target("avx512f,avx512dq"), always_inline))
        inline __m512i multiplyHigh64(__m512i x, __m512i y)
        {
            const auto mask = _mm512_set1_epi64(0xffffffffULL);
            const auto xl = _mm512_and_si512(x, mask), xh = _mm512_srli_epi64(x, 32);
            const auto yl = _mm512_and_si512(y, mask), yh = _mm512_srli_epi64(y, 32);
            const auto low = _mm512_mullo_epi64(xl, yl);
            const auto a = _mm512_mullo_epi64(xh, yl), b = _mm512_mullo_epi64(xl, yh);
            const auto middle = _mm512_add_epi64(_mm512_srli_epi64(low, 32),
                _mm512_add_epi64(_mm512_and_si512(a, mask), _mm512_and_si512(b, mask)));
            return _mm512_add_epi64(_mm512_mullo_epi64(xh, yh),
                _mm512_add_epi64(_mm512_srli_epi64(middle, 32),
                    _mm512_add_epi64(_mm512_srli_epi64(a, 32), _mm512_srli_epi64(b, 32))));
        }

        template<unsigned Bits>
        __attribute__((target("avx512f,avx512dq,avx512ifma"), always_inline))
        inline __m512i estimateQuotient(__m512i x, __m512i shoup)
        {
            auto high = _mm512_madd52hi_epu64(_mm512_setzero_si512(), x, shoup);
            if constexpr (Bits == 52)
                high = _mm512_add_epi64(high, _mm512_mullo_epi64(x, _mm512_srli_epi64(shoup, 52)));
            else
            {
                const auto mask = _mm512_set1_epi64((u64{1} << 52) - 1);
                const auto xh = _mm512_srli_epi64(x, 52), sh = _mm512_srli_epi64(shoup, 52);
                high = _mm512_add_epi64(high, _mm512_mullo_epi64(xh, _mm512_and_si512(shoup, mask)));
                high = _mm512_add_epi64(high, _mm512_mullo_epi64(_mm512_and_si512(x, mask), sh));
                high = _mm512_add_epi64(high, _mm512_slli_epi64(_mm512_mullo_epi64(xh, sh), 52));
            }
            return _mm512_srli_epi64(high, Bits == 52 ? 11 : 8);
        }

        template<std::size_t Limbs, unsigned Bits>
        __attribute__((target("avx512f,avx512dq,avx512ifma")))
        void scaleAndRoundRns(const u64* source, u64* destination,
            std::size_t count, const seal::util::RNSBase& base, u64 plaintextModulus)
        {
            constexpr unsigned ShoupBits = Bits == 52 ? 63 : 60;
            const auto zero = _mm512_setzero_si512(), one = _mm512_set1_epi64(1);
            const auto p = _mm512_set1_epi64(plaintextModulus);
            __m512i q[Limbs], gap[Limbs], inverse[Limbs], inverseShoup[Limbs],
                plainShoup[Limbs], reciprocalLow[Limbs], reciprocalHigh[Limbs];
            for (std::size_t j = 0; j < Limbs; ++j)
            {
                const u64 modulus = base.base()[j].value();
                const u64 inv = base.inv_punctured_prod_mod_base_array()[j].operand;
                q[j] = _mm512_set1_epi64(modulus);
                gap[j] = _mm512_set1_epi64((u64{1} << Bits) - modulus);
                inverse[j] = _mm512_set1_epi64(inv);
                inverseShoup[j] = _mm512_set1_epi64(static_cast<u64>(
                    (static_cast<__uint128_t>(inv) << ShoupBits) / modulus));
                plainShoup[j] = _mm512_set1_epi64(static_cast<u64>(
                    (static_cast<__uint128_t>(plaintextModulus) << ShoupBits) / modulus));
                const auto reciprocal = reciprocal2Pow128Wide(modulus);
                reciprocalLow[j] = _mm512_set1_epi64(reciprocal.mLo);
                reciprocalHigh[j] = _mm512_set1_epi64(reciprocal.mHi);
            }
            for (std::size_t i = 0; i < count; i += 8)
            {
                const auto lanes = static_cast<__mmask8>((1u << std::min<std::size_t>(8, count - i)) - 1);
                auto scaled = zero, fracLo = zero, fracHi = _mm512_set1_epi64(u64{1} << 63);
                for (std::size_t j = 0; j < Limbs; ++j)
                {
                    auto x = reduceInput<Bits>(
                        _mm512_maskz_loadu_epi64(lanes, source + j * count + i), q[j], gap[j]);
                    auto quotient = estimateQuotient<Bits>(x, inverseShoup[j]);
                    x = _mm512_sub_epi64(_mm512_mullo_epi64(x, inverse[j]),
                        _mm512_mullo_epi64(quotient, q[j]));
                    x = _mm512_mask_sub_epi64(x, _mm512_cmp_epu64_mask(x, q[j], _MM_CMPINT_NLT), x, q[j]);

                    if (plaintextModulus == base.base()[j].value())
                    {
                        // Denoise target: x*p/q_j is exactly x with no
                        // fractional contribution. This branch is public.
                        scaled = _mm512_add_epi64(scaled, x);
                        scaled = _mm512_mask_sub_epi64(scaled,
                            _mm512_cmp_epu64_mask(scaled, p, _MM_CMPINT_NLT), scaled, p);
                        continue;
                    }

                    // Shoup gives floor(x*p/q) or one less. The corresponding
                    // remainder is in [0,2q), so the low u64 subtraction is
                    // exact even though each unreduced product is wider.
                    quotient = estimateQuotient<Bits>(x, plainShoup[j]);
                    auto rem = _mm512_sub_epi64(_mm512_mullo_epi64(x, p),
                        _mm512_mullo_epi64(quotient, q[j]));
                    const auto correction = _mm512_cmp_epu64_mask(rem, q[j], _MM_CMPINT_NLT);
                    rem = _mm512_mask_sub_epi64(rem, correction, rem, q[j]);
                    quotient = _mm512_mask_add_epi64(quotient, correction, quotient, one);
                    scaled = _mm512_add_epi64(scaled, quotient);

                    // Preserve the original floor(2^128/q) fixed-point sum,
                    // including both u64 carries and the 128-bit overflow.
                    const auto termLo = _mm512_mullo_epi64(rem, reciprocalLow[j]);
                    const auto termHi = _mm512_add_epi64(multiplyHigh64(rem, reciprocalLow[j]),
                        _mm512_mullo_epi64(rem, reciprocalHigh[j]));
                    const auto nextLo = _mm512_add_epi64(fracLo, termLo);
                    const auto carryLo = _mm512_cmp_epu64_mask(nextLo, fracLo, _MM_CMPINT_LT);
                    const auto nextHi = _mm512_add_epi64(fracHi, termHi);
                    auto carryHi = _mm512_cmp_epu64_mask(nextHi, fracHi, _MM_CMPINT_LT);
                    fracHi = _mm512_mask_add_epi64(nextHi, carryLo, nextHi, one);
                    carryHi |= _mm512_cmp_epu64_mask(fracHi, nextHi, _MM_CMPINT_LT);
                    fracLo = nextLo;
                    scaled = _mm512_mask_add_epi64(scaled, carryHi, scaled, one);
                    scaled = _mm512_mask_sub_epi64(scaled,
                        _mm512_cmp_epu64_mask(scaled, p, _MM_CMPINT_NLT), scaled, p);
                }
                _mm512_mask_storeu_epi64(destination + i, lanes, scaled);
            }
        }

        template<unsigned Bits>
        __attribute__((target("avx512f,avx512dq,avx512ifma")))
        bool checkRoundingMargin(const u64* source, std::size_t count,
            std::span<const seal::Modulus> moduli, std::span<const std::size_t> sourceLimbs,
            std::span<const seal::util::MultiplyUIntModOperand> inverse,
            std::span<const wideU64> reciprocal, wideU64 margin)
        {
            const auto zero = _mm512_setzero_si512(), one = _mm512_set1_epi64(1);
            const auto marginLo = _mm512_set1_epi64(margin.mLo);
            const auto marginHi = _mm512_set1_epi64(margin.mHi);
            __m512i q[8], gap[8], inv[8], shoup[8], reciprocalLo[8], reciprocalHi[8];
            for (std::size_t j = 0; j < sourceLimbs.size(); ++j)
            {
                const u64 modulus = moduli[sourceLimbs[j]].value();
                q[j] = _mm512_set1_epi64(modulus);
                gap[j] = _mm512_set1_epi64((u64{1} << Bits) - modulus);
                inv[j] = _mm512_set1_epi64(inverse[j].operand);
                shoup[j] = _mm512_set1_epi64(inverse[j].quotient >> (Bits == 52 ? 1 : 4));
                reciprocalLo[j] = _mm512_set1_epi64(reciprocal[j].mLo);
                reciprocalHi[j] = _mm512_set1_epi64(reciprocal[j].mHi);
            }
            for (std::size_t i = 0; i < count; i += 8)
            {
                const auto lanes = static_cast<__mmask8>((1u << std::min<std::size_t>(8, count - i)) - 1);
                auto lo = zero, hi = _mm512_set1_epi64(u64{1} << 63);
                for (std::size_t j = 0; j < sourceLimbs.size(); ++j)
                {
                    auto x = reduceInput<Bits>(_mm512_maskz_loadu_epi64(
                        lanes, source + sourceLimbs[j] * count + i), q[j], gap[j]);
                    const auto quotient = estimateQuotient<Bits>(x, shoup[j]);
                    x = _mm512_sub_epi64(_mm512_mullo_epi64(x, inv[j]),
                        _mm512_mullo_epi64(quotient, q[j]));
                    x = _mm512_mask_sub_epi64(x, _mm512_cmp_epu64_mask(x, q[j], _MM_CMPINT_NLT), x, q[j]);
                    const auto termLo = _mm512_mullo_epi64(x, reciprocalLo[j]);
                    const auto termHi = _mm512_add_epi64(multiplyHigh64(x, reciprocalLo[j]),
                        _mm512_mullo_epi64(x, reciprocalHi[j]));
                    const auto nextLo = _mm512_add_epi64(lo, termLo);
                    hi = _mm512_add_epi64(hi, termHi);
                    hi = _mm512_mask_add_epi64(hi,
                        _mm512_cmp_epu64_mask(nextLo, lo, _MM_CMPINT_LT), hi, one);
                    lo = nextLo;
                }
                // Test both sides of the original 128-bit rounding boundary.
                // The subtraction's low-word borrow also handles sum == 0.
                const auto distanceLo = _mm512_sub_epi64(zero, lo);
                auto distanceHi = _mm512_sub_epi64(zero, hi);
                distanceHi = _mm512_mask_sub_epi64(distanceHi,
                    _mm512_cmp_epu64_mask(lo, zero, _MM_CMPINT_NE), distanceHi, one);
                const auto lowSide = _mm512_cmp_epu64_mask(hi, marginHi, _MM_CMPINT_LT) |
                    (_mm512_cmp_epu64_mask(hi, marginHi, _MM_CMPINT_EQ) &
                     _mm512_cmp_epu64_mask(lo, marginLo, _MM_CMPINT_LT));
                const auto highSide = _mm512_cmp_epu64_mask(distanceHi, marginHi, _MM_CMPINT_LT) |
                    (_mm512_cmp_epu64_mask(distanceHi, marginHi, _MM_CMPINT_EQ) &
                     _mm512_cmp_epu64_mask(distanceLo, marginLo, _MM_CMPINT_LT));
                if (lanes & (lowSide | highSide)) return false;
            }
            return true;
        }

        u64 radix52Word(const u64* value, std::size_t words, std::size_t index)
        {
            const std::size_t bit = index * 52, word = bit / 64, shift = bit % 64;
            if (word >= words) return 0;
            u64 result = value[word] >> shift;
            if (shift && word + 1 < words) result |= value[word + 1] << (64 - shift);
            return result & ((u64{1} << 52) - 1);
        }

        // Shoup multiplication for x < 2^52, with a 63-bit reciprocal. The
        // middle radix digit fits in u64; the quotient is at most one low, so
        // the subtraction produces a value in [0,2q) without any approximation.
        __attribute__((target("avx512f,avx512dq,avx512ifma"), always_inline))
        inline __m512i multiplyConstant52(__m512i x, __m512i operand, __m512i shoup, __m512i q)
        {
            auto high = _mm512_madd52hi_epu64(_mm512_setzero_si512(), x, shoup);
            high = _mm512_add_epi64(high, _mm512_mullo_epi64(x, _mm512_srli_epi64(shoup, 52)));
            const auto quotient = _mm512_srli_epi64(high, 11);
            auto result = _mm512_sub_epi64(_mm512_mullo_epi64(x, operand),
                _mm512_mullo_epi64(quotient, q));
            return _mm512_mask_sub_epi64(result,
                _mm512_cmp_epu64_mask(result, q, _MM_CMPINT_NLT), result, q);
        }

        __attribute__((target("avx512f,avx512dq,avx512ifma"), always_inline))
        inline __m512i multiplyConstant55(__m512i x, __m512i operand, __m512i shoup, __m512i q)
        {
            // 60-bit Shoup reciprocal, x < 2^55. Include every high-input
            // cross product before shifting: the radix-52 middle fits in
            // 63 bits because the complete product has fewer than 115 bits.
            const auto mask = _mm512_set1_epi64((u64{1} << 52) - 1);
            const auto xh = _mm512_srli_epi64(x, 52), sh = _mm512_srli_epi64(shoup, 52);
            auto high = _mm512_madd52hi_epu64(_mm512_setzero_si512(), x, shoup);
            high = _mm512_add_epi64(high, _mm512_mullo_epi64(xh, _mm512_and_si512(shoup, mask)));
            high = _mm512_add_epi64(high, _mm512_mullo_epi64(_mm512_and_si512(x, mask), sh));
            high = _mm512_add_epi64(high, _mm512_slli_epi64(_mm512_mullo_epi64(xh, sh), 52));
            const auto quotient = _mm512_srli_epi64(high, 8);
            auto result = _mm512_sub_epi64(_mm512_mullo_epi64(x, operand), _mm512_mullo_epi64(quotient, q));
            return _mm512_mask_sub_epi64(result,
                _mm512_cmp_epu64_mask(result, q, _MM_CMPINT_NLT), result, q);
        }

        template<bool Wide>
        __attribute__((target("avx512f,avx512dq,avx512ifma")))
        void unliftCenteredRns(const u64* source, u64* destination, std::size_t count,
            u64 modulus, u64 inverseLift, std::span<const seal::Modulus> destinationModuli)
        {
            const auto q = _mm512_set1_epi64(modulus);
            const auto half = _mm512_set1_epi64(modulus >> 1);
            const auto operand = _mm512_set1_epi64(inverseLift);
            const auto shoup = _mm512_set1_epi64(static_cast<u64>(
                (static_cast<__uint128_t>(inverseLift) << (Wide ? 60 : 63)) / modulus));
            for (std::size_t i = 0; i < count; i += 8)
            {
                const auto lanes = static_cast<__mmask8>((1u << std::min<std::size_t>(8, count-i)) - 1);
                const auto input = _mm512_maskz_loadu_epi64(lanes, source+i);
                const auto residue = Wide ? multiplyConstant55(input, operand, shoup, q)
                                          : multiplyConstant52(input, operand, shoup, q);
                const auto negative = _mm512_cmp_epu64_mask(residue, half, _MM_CMPINT_GT);
                const auto centered = _mm512_mask_sub_epi64(residue, negative, residue, q);
                for (std::size_t j = 0; j < destinationModuli.size(); ++j)
                {
                    const auto value = _mm512_mask_add_epi64(centered, negative, centered,
                        _mm512_set1_epi64(destinationModuli[j].value()));
                    _mm512_mask_storeu_epi64(destination+j*count+i, lanes, value);
                }
            }
        }

        template<std::size_t Limbs, bool Wide, unsigned DigitBits = 0, bool LowDigit = false>
        __attribute__((target("avx512f,avx512dq,avx512ifma")))
        void composeRnsVector(const u64* source, u64* destination,
            std::size_t count, const seal::util::RNSBase& base)
        {
            // Eight independent CRT reconstructions in radix 2^52. Delaying
            // carries across all CRT terms makes IFMA useful for the full wide
            // integer, including 55-bit residue moduli. The cross term from
            // scalar >> 52 is exact; IFMA alone would silently lose those bits.
            constexpr std::size_t Words = (Limbs * 55 + 3 + 51) / 52;
            // Q/q_j contains only Limbs-1 moduli. Its higher radix-52
            // words are identically zero, including for mixed-width bases.
            // Do not multiply those zero words for every coefficient.
            constexpr std::size_t PuncturedWords = ((Limbs-1) * (Wide ? 55 : 52) + 51) / 52;
            constexpr u64 maskValue = (u64{1} << 52) - 1;
            const auto zero = _mm512_setzero_si512();
            const auto mask = _mm512_set1_epi64(maskValue);
            const auto one = _mm512_set1_epi64(1);
            static const bool quotientEnabled = [] {
                const char* value = std::getenv("LV_CPU_CRT_QUOTIENT");
                return !value || value[0] != '0';
            }();
            __m512i punctured[Limbs][PuncturedWords], q[Words], inv[Limbs], invShoup[Limbs],
                reciprocal[Limbs], moduli[Limbs];
            for (std::size_t j = 0; j < Limbs; ++j)
            {
                const u64 operand = base.inv_punctured_prod_mod_base_array()[j].operand;
                const u64 mod = base.base()[j].value();
                moduli[j] = _mm512_set1_epi64(mod);
                inv[j] = _mm512_set1_epi64(operand);
                invShoup[j] = _mm512_set1_epi64(static_cast<u64>(
                    (static_cast<__uint128_t>(operand) << (Wide ? 60 : 63)) / mod));
                reciprocal[j] = _mm512_set1_epi64(static_cast<u64>((__uint128_t{1} << 64) / mod));
            }
            for (std::size_t w = 0; w < Words; ++w)
            {
                q[w] = _mm512_set1_epi64(radix52Word(base.base_prod(), Limbs, w));
                for (std::size_t j = 0; w < PuncturedWords && j < Limbs; ++j)
                    punctured[j][w] = _mm512_set1_epi64(
                        radix52Word(base.punctured_prod_array() + j * Limbs, Limbs, w));
            }
            constexpr std::size_t Digits = (DigitBits + 51) / 52;
            __m512i qHalf[Words], powers[Limbs][Digits + 1],
                powersShoup[Limbs][Digits + 1], digitBase[Limbs];
            if constexpr (DigitBits != 0)
            {
                if constexpr (!LowDigit)
                    for (std::size_t w = 0; w < Words; ++w)
                        qHalf[w] = _mm512_or_si512(_mm512_srli_epi64(q[w], 1),
                            w + 1 < Words ? _mm512_slli_epi64(_mm512_and_si512(q[w + 1], one), 51) : zero);
                for (std::size_t j = 0; j < Limbs; ++j)
                {
                    const u64 mod = base.base()[j].value();
                    u64 power = 1;
                    for (std::size_t w = 0; w < Digits; ++w)
                    {
                        powers[j][w] = _mm512_set1_epi64(power);
                        powersShoup[j][w] = _mm512_set1_epi64(
                            static_cast<u64>((static_cast<__uint128_t>(power) << 63) / mod));
                        power = static_cast<u64>((static_cast<__uint128_t>(power) << 52) % mod);
                    }
                    if constexpr (!LowDigit)
                    {
                        power = 1;
                        for (unsigned bit = 0; bit < DigitBits; ++bit) power = (2 * power) % mod;
                        digitBase[j] = _mm512_set1_epi64(power);
                    }
                }
            }
            const auto indices = _mm512_set_epi64(7*Limbs, 6*Limbs, 5*Limbs,
                4*Limbs, 3*Limbs, 2*Limbs, Limbs, 0);
            std::size_t coeff = 0;
            for (; coeff + 8 <= count; coeff += 8)
            {
                __m512i sum[Words + 1];
                for (auto& word : sum) word = zero;
                auto fraction = zero, alpha = zero;
                for (std::size_t j = 0; j < Limbs; ++j)
                {
                    const auto input = _mm512_loadu_si512(source + j * count + coeff);
                    const auto scalar = Wide ? multiplyConstant55(input, inv[j], invShoup[j], moduli[j])
                        : multiplyConstant52(input, inv[j], invShoup[j], moduli[j]);
                    if (quotientEnabled)
                    {
                        const auto next = _mm512_add_epi64(fraction, _mm512_mullo_epi64(scalar, reciprocal[j]));
                        alpha = _mm512_mask_add_epi64(alpha,
                            _mm512_cmp_epu64_mask(next, fraction, _MM_CMPINT_LT), alpha, one);
                        fraction = next;
                    }
                    const auto high = _mm512_srli_epi64(scalar, 52);
                    for (std::size_t w = 0; w < PuncturedWords; ++w)
                    {
                        sum[w] = _mm512_madd52lo_epu64(sum[w], punctured[j][w], scalar);
                        sum[w + 1] = _mm512_madd52hi_epu64(sum[w + 1], punctured[j][w], scalar);
                        if constexpr (Wide)
                            sum[w + 1] = _mm512_add_epi64(sum[w + 1],
                                _mm512_mullo_epi64(punctured[j][w], high));
                    }
                }
                // Each accumulator is < 8*9*2^52, so no u64 carry was lost.
                // The complete sum is < Limbs*Q and fits in Words radix digits.
                for (std::size_t w = 0; w < Words; ++w)
                {
                    sum[w + 1] = _mm512_add_epi64(sum[w + 1], _mm512_srli_epi64(sum[w], 52));
                    sum[w] = _mm512_and_si512(sum[w], mask);
                }
                if (quotientEnabled)
                {
                    // alpha = floor(sum(x_j*floor(2^64/q_j))/2^64).
                    // This underestimates floor(sum(x_j/q_j)) by at most one:
                    // Limbs<=8 and q_j<2^55 give total error <8/512<1.
                    // Subtract alpha*Q exactly in radix 2^52; the remaining
                    // integer is nonnegative and below 2Q.
                    auto carry = zero;
                    __mmask8 borrow = 0;
                    for (std::size_t w = 0; w < Words; ++w)
                    {
                        const auto product = _mm512_add_epi64(_mm512_mullo_epi64(q[w], alpha), carry);
                        carry = _mm512_srli_epi64(product, 52);
                        const auto sub = _mm512_mask_add_epi64(_mm512_and_si512(product, mask),
                            borrow, _mm512_and_si512(product, mask), one);
                        borrow = _mm512_cmp_epu64_mask(sum[w], sub, _MM_CMPINT_LT);
                        sum[w] = _mm512_and_si512(_mm512_sub_epi64(sum[w], sub), mask);
                    }
                }
                for (;;)
                {
                    __mmask8 equal = 0xff, greater = 0;
                    for (std::size_t w = Words; w-- > 0;)
                    {
                        greater |= equal & _mm512_cmp_epu64_mask(sum[w], q[w], _MM_CMPINT_GT);
                        equal &= _mm512_cmpeq_epi64_mask(sum[w], q[w]);
                    }
                    const __mmask8 reduce = greater | equal;
                    if (!reduce) break;
                    __mmask8 borrow = 0;
                    for (std::size_t w = 0; w < Words; ++w)
                    {
                        const auto sub = _mm512_mask_add_epi64(q[w], borrow, q[w], one);
                        borrow = _mm512_cmp_epu64_mask(sum[w], sub, _MM_CMPINT_LT);
                        const auto difference = _mm512_and_si512(_mm512_sub_epi64(sum[w], sub), mask);
                        sum[w] = _mm512_mask_mov_epi64(sum[w], reduce, difference);
                    }
                    if (quotientEnabled) break; // The proven bound needs at most one correction.
                }
                if constexpr (DigitBits != 0)
                {
                    __mmask8 equal = 0xff, negative = 0;
                    if constexpr (!LowDigit)
                    {
                        for (std::size_t w = Words; w-- > 0;)
                        {
                            negative |= equal & _mm512_cmp_epu64_mask(sum[w], qHalf[w], _MM_CMPINT_GT);
                            equal &= _mm512_cmpeq_epi64_mask(sum[w], qHalf[w]);
                        }
                        __mmask8 borrow = 0;
                        for (std::size_t w = 0; w < Words; ++w)
                        {
                            const auto sub = _mm512_mask_add_epi64(q[w], borrow, q[w], one);
                            borrow = _mm512_cmp_epu64_mask(sum[w], sub, _MM_CMPINT_LT);
                            sum[w] = _mm512_mask_mov_epi64(sum[w], negative,
                                _mm512_and_si512(_mm512_sub_epi64(sum[w], sub), mask));
                        }
                    }
                    // Dropping balanced digit zero rounds upward exactly when
                    // its sign bit is set. Extract only the requested digit;
                    // no wide shifts, coefficient transpose, or scratch copy.
                    auto carry = LowDigit ? zero : _mm512_and_si512(one,
                        _mm512_srli_epi64(sum[(DigitBits - 1) / 52], (DigitBits - 1) % 52));
                    __m512i digits[Digits];
                    for (std::size_t w = 0; w < Digits; ++w)
                    {
                        constexpr unsigned Shift = LowDigit ? 0 : DigitBits % 52;
                        const std::size_t bit = (LowDigit ? 0 : DigitBits) + w * 52, word = bit / 52;
                        auto digit = _mm512_srli_epi64(sum[word], Shift);
                        if (word + 1 < Words)
                            digit = _mm512_or_si512(digit,
                                _mm512_slli_epi64(sum[word + 1], 52 - Shift));
                        digit = _mm512_add_epi64(_mm512_and_si512(digit, mask), carry);
                        carry = _mm512_srli_epi64(digit, 52);
                        digits[w] = _mm512_and_si512(digit, mask);
                    }
                    constexpr unsigned LastBits = (DigitBits - 1) % 52 + 1;
                    digits[Digits - 1] = _mm512_and_si512(digits[Digits - 1],
                        _mm512_set1_epi64((u64{1} << LastBits) - 1));
                    if constexpr (!LowDigit)
                        negative = _mm512_test_epi64_mask(digits[Digits - 1],
                            _mm512_set1_epi64(u64{1} << (LastBits - 1)));
                    for (std::size_t j = 0; j < Limbs; ++j)
                    {
                        auto result = zero;
                        for (std::size_t w = 0; w < Digits; ++w)
                        {
                            result = _mm512_add_epi64(result,
                                multiplyConstant52(digits[w], powers[j][w], powersShoup[j][w], moduli[j]));
                            result = _mm512_mask_sub_epi64(result,
                                _mm512_cmp_epu64_mask(result, moduli[j], _MM_CMPINT_NLT), result, moduli[j]);
                        }
                        if constexpr (!LowDigit)
                        {
                            auto balanced = _mm512_sub_epi64(result, digitBase[j]);
                            balanced = _mm512_mask_add_epi64(balanced,
                                _mm512_cmp_epu64_mask(result, digitBase[j], _MM_CMPINT_LT), balanced, moduli[j]);
                            result = _mm512_mask_mov_epi64(result, negative, balanced);
                        }
                        _mm512_storeu_si512(destination + j * count + coeff, result);
                    }
                }
                else
                    for (std::size_t w = 0; w < Limbs; ++w)
                    {
                        const std::size_t bit = w * 64, digit = bit / 52, shift = bit % 52;
                        auto word = _mm512_srlv_epi64(sum[digit], _mm512_set1_epi64(shift));
                        if (digit + 1 < Words)
                            word = _mm512_or_si512(word, _mm512_sllv_epi64(sum[digit + 1],
                                _mm512_set1_epi64(52 - shift)));
                        if (shift > 40 && digit + 2 < Words)
                            word = _mm512_or_si512(word, _mm512_sllv_epi64(sum[digit + 2],
                                _mm512_set1_epi64(104 - shift)));
                        _mm512_i64scatter_epi64(destination + coeff * Limbs + w, indices, word, 8);
                    }
            }
            if constexpr (DigitBits == 0) composeRns<Limbs>(source, destination, count, base, coeff);
        }

        template<unsigned Bits>
        __attribute__((target("avx512f,avx512dq,avx512ifma")))
        void dyadicInnerProduct(const u64* const* a, const u64* const* b,
            std::size_t terms, u64* c, std::size_t count, u64 modulus)
        {
            const auto q = _mm512_set1_epi64(modulus);
            const auto gap = _mm512_set1_epi64((u64{1} << Bits) - modulus);
            const auto mask = _mm512_set1_epi64((u64{1} << Bits) - 1);
            const auto mask52 = _mm512_set1_epi64((u64{1} << 52) - 1);
            const auto zero = _mm512_setzero_si512();
            for (std::size_t i = 0; i < count; i += 8)
            {
                const auto lanes = static_cast<__mmask8>((1u << std::min<std::size_t>(8, count - i)) - 1);
                auto lo52 = zero, hi52 = zero;
                for (std::size_t t = 0; t < terms; ++t)
                {
                    auto x = _mm512_maskz_loadu_epi64(lanes, a[t] + i);
                    auto y = _mm512_maskz_loadu_epi64(lanes, b[t] + i);
                    x = reduceInput<Bits>(x, q, gap);
                    y = reduceInput<Bits>(y, q, gap);
                    lo52 = _mm512_madd52lo_epu64(lo52, x, y);
                    hi52 = _mm512_madd52hi_epu64(hi52, x, y);
                    if constexpr (Bits > 52)
                    {
                        const auto xh = _mm512_srli_epi64(x, 52), yh = _mm512_srli_epi64(y, 52);
                        hi52 = _mm512_add_epi64(hi52, _mm512_mullo_epi64(xh, _mm512_and_si512(y, mask52)));
                        hi52 = _mm512_add_epi64(hi52, _mm512_mullo_epi64(yh, _mm512_and_si512(x, mask52)));
                        hi52 = _mm512_add_epi64(hi52, _mm512_slli_epi64(_mm512_mullo_epi64(xh, yh), 52));
                    }
                }
                // At most 32 products of <55-bit operands: the exact sum is
                // <2^115. The low accumulator is <2^57 and the high <2^63;
                // delayed carries cannot overflow either u64 accumulator.
                hi52 = _mm512_add_epi64(hi52, _mm512_srli_epi64(lo52, 52));
                lo52 = _mm512_and_si512(lo52, mask52);
                const auto low = _mm512_or_si512(lo52,
                    _mm512_and_si512(_mm512_slli_epi64(hi52, 52), mask));
                const auto high = _mm512_srli_epi64(hi52, Bits - 52);
                auto fLow = _mm512_madd52lo_epu64(_mm512_and_si512(low, mask52), high, gap);
                auto fHigh = _mm512_madd52hi_epu64(zero, high, gap);
                fHigh = _mm512_add_epi64(fHigh, _mm512_srli_epi64(fLow, 52));
                fHigh = _mm512_add_epi64(fHigh, _mm512_srli_epi64(low, 52));
                fHigh = _mm512_add_epi64(fHigh,
                    _mm512_mullo_epi64(_mm512_srli_epi64(high, 52), gap));
                fLow = _mm512_or_si512(_mm512_and_si512(fLow, mask52),
                    _mm512_and_si512(_mm512_slli_epi64(fHigh, 52), mask));
                auto result = _mm512_add_epi64(fLow,
                    _mm512_mullo_epi64(_mm512_srli_epi64(fHigh, Bits - 52), gap));
                // With 32 terms, the second fold can exceed 2q for a 52-bit
                // modulus at the largest supported gap. A third fold handles
                // that bound exactly; the intermediate is still <2^56.
                result = reduceInput<Bits>(result, q, gap);
                const auto z = reduceInput<Bits>(_mm512_maskz_loadu_epi64(lanes, c + i), q, gap);
                result = _mm512_add_epi64(result, z);
                result = _mm512_mask_sub_epi64(result,
                    _mm512_cmp_epu64_mask(result, q, _MM_CMPINT_NLT), result, q);
                _mm512_mask_storeu_epi64(c + i, lanes, result);
            }
        }

        template<unsigned Bits, bool Subtract>
        __attribute__((target("avx512f,avx512dq,avx512ifma")))
        void dyadic(const u64* a, const u64* b, u64* c, std::size_t count, const seal::Modulus& modulus)
        {
            constexpr u64 radix = u64{1} << Bits;
            const auto q = _mm512_set1_epi64(modulus.value());
            const auto gap = _mm512_set1_epi64(radix - modulus.value());
            const auto mask = _mm512_set1_epi64(radix - 1);
            const auto mask52 = _mm512_set1_epi64((u64{1} << 52) - 1);
            const auto zero = _mm512_setzero_si512();
            std::size_t i = 0;
            for (; i + 8 <= count; i += 8)
            {
                __m512i x = _mm512_loadu_si512(a + i);
                __m512i y = _mm512_loadu_si512(b + i);
                __m512i z = _mm512_loadu_si512(c + i);
                // Any u64 folds to below 2q for Bits>=52 and gap<2^24.
#define LV_CPU_REDUCE_INPUT(v) \
                v = _mm512_add_epi64(_mm512_and_si512(v, mask), \
                    _mm512_mullo_epi64(_mm512_srli_epi64(v, Bits), gap)); \
                v = _mm512_mask_sub_epi64(v, _mm512_cmp_epu64_mask(v, q, _MM_CMPINT_NLT), v, q)
                LV_CPU_REDUCE_INPUT(x);
                LV_CPU_REDUCE_INPUT(y);
                LV_CPU_REDUCE_INPUT(z);
#undef LV_CPU_REDUCE_INPUT
                // Exact product in radix 2^52. IFMA ignores the top 12 input
                // bits, so wider moduli require the cross products explicitly.
                const auto xl = _mm512_and_si512(x, mask52);
                const auto yl = _mm512_and_si512(y, mask52);
                const auto lo52 = _mm512_madd52lo_epu64(zero, xl, yl);
                auto hi52 = _mm512_madd52hi_epu64(zero, xl, yl);
                if constexpr (Bits > 52)
                {
                    const auto xh = _mm512_srli_epi64(x, 52);
                    const auto yh = _mm512_srli_epi64(y, 52);
                    hi52 = _mm512_add_epi64(hi52, _mm512_mullo_epi64(xh, yl));
                    hi52 = _mm512_add_epi64(hi52, _mm512_mullo_epi64(yh, xl));
                    hi52 = _mm512_add_epi64(hi52,
                        _mm512_slli_epi64(_mm512_mullo_epi64(xh, yh), 52));
                }
                const auto low = _mm512_or_si512(lo52,
                    _mm512_and_si512(_mm512_slli_epi64(hi52, 52), mask));
                const auto high = _mm512_srli_epi64(hi52, Bits - 52);
                // Fold high*2^Bits to high*gap, retaining the carry at bit 52.
                auto fLow = _mm512_madd52lo_epu64(_mm512_and_si512(low, mask52), high, gap);
                auto fHigh = _mm512_madd52hi_epu64(zero, high, gap);
                fHigh = _mm512_add_epi64(fHigh, _mm512_srli_epi64(fLow, 52));
                fHigh = _mm512_add_epi64(fHigh, _mm512_srli_epi64(low, 52));
                if constexpr (Bits > 52)
                    fHigh = _mm512_add_epi64(fHigh,
                        _mm512_mullo_epi64(_mm512_srli_epi64(high, 52), gap));
                fLow = _mm512_or_si512(_mm512_and_si512(fLow, mask52),
                    _mm512_and_si512(_mm512_slli_epi64(fHigh, 52), mask));
                // The next high radix digit is <=gap, so this fold is
                // <2^Bits+gap^2<2q, and a single subtraction is sufficient.
                auto result = _mm512_add_epi64(fLow,
                    _mm512_mullo_epi64(_mm512_srli_epi64(fHigh, Bits - 52), gap));
                result = _mm512_mask_sub_epi64(result,
                    _mm512_cmp_epu64_mask(result, q, _MM_CMPINT_NLT), result, q);
                if constexpr (Subtract)
                {
                    const auto borrow = _mm512_cmp_epu64_mask(z, result, _MM_CMPINT_LT);
                    result = _mm512_sub_epi64(z, result);
                    result = _mm512_mask_add_epi64(result, borrow, result, q);
                }
                else
                {
                    result = _mm512_add_epi64(result, z);
                    result = _mm512_mask_sub_epi64(result,
                        _mm512_cmp_epu64_mask(result, q, _MM_CMPINT_NLT), result, q);
                }
                _mm512_storeu_si512(c + i, result);
            }
            for (; i < count; ++i)
            {
                const u64 product = mulMod(a[i] % modulus.value(), b[i] % modulus.value(), modulus);
                if constexpr (Subtract)
                    c[i] = seal::util::sub_uint_mod(c[i] % modulus.value(), product, modulus);
                else c[i] = addMod(c[i] % modulus.value(), product, modulus);
            }
        }
#endif
    }

    bool cpuReduceMod(const u64* source, u64* destination,
        std::size_t count, const seal::Modulus& modulus, const u64* rejectionLimit)
    {
#if defined(LV_CPU_IFMA)
        static const bool enabled = [] {
            const char* value = std::getenv("LV_CPU_VECTOR_REDUCE");
            return (!value || value[0] != '0') && __builtin_cpu_supports("avx512f") &&
                __builtin_cpu_supports("avx512dq");
        }();
        const u64 q = modulus.value();
        const int bits = modulus.bit_count();
        if (!enabled || (bits != 52 && bits != 55) || (u64{1} << bits) - q >= (u64{1} << 24))
            return false;
        if (rejectionLimit && containsRejected(source, count, *rejectionLimit)) return false;
        if (bits == 52) reduceMod<52>(source, destination, count, q);
        else reduceMod<55>(source, destination, count, q);
        return true;
#else
        return false;
#endif
    }

    bool cpuScaleAndRoundRns(const u64* source, u64* destination,
        std::size_t count, const seal::util::RNSBase& base, u64 plaintextModulus)
    {
#if defined(LV_CPU_IFMA)
        static const bool enabled = [] {
            const char* value = std::getenv("LV_CPU_VECTOR_ROUND");
            return (!value || value[0] != '0') && __builtin_cpu_supports("avx512f") &&
                __builtin_cpu_supports("avx512dq") && __builtin_cpu_supports("avx512ifma");
        }();
        if (!enabled || (base.size() != 4 && base.size() != 8) || plaintextModulus < 2) return false;
        const int bits = base.base()[0].bit_count();
        if ((bits != 52 && bits != 55) || plaintextModulus >= (u64{1} << bits)) return false;
        for (std::size_t j = 0; j < base.size(); ++j)
            if (base.base()[j].bit_count() != bits ||
                (u64{1} << bits) - base.base()[j].value() >= (u64{1} << 24)) return false;
        if (base.size() == 4)
        {
            if (bits == 52) scaleAndRoundRns<4, 52>(source, destination, count, base, plaintextModulus);
            else scaleAndRoundRns<4, 55>(source, destination, count, base, plaintextModulus);
        }
        else
        {
            if (bits == 52) scaleAndRoundRns<8, 52>(source, destination, count, base, plaintextModulus);
            else scaleAndRoundRns<8, 55>(source, destination, count, base, plaintextModulus);
        }
        return true;
#else
        return false;
#endif
    }

    bool cpuDenoiseRns(const u64* source, u64* destination,
        std::size_t count, const seal::util::RNSBase& base, std::size_t target)
    {
        static const bool enabled = [] {
            const char* value = std::getenv("LV_CPU_VECTOR_DENOISE");
            return !value || value[0] != '0';
        }();
        return enabled && target < base.size() && cpuScaleAndRoundRns(
            source, destination, count, base, base.base()[target].value());
    }

    bool cpuCheckRoundingMargin(const u64* source, std::size_t count,
        std::span<const seal::Modulus> moduli, std::span<const std::size_t> sourceLimbs,
        std::span<const seal::util::MultiplyUIntModOperand> inverse,
        std::span<const wideU64> reciprocal, wideU64 margin, bool& accepted)
    {
#if defined(LV_CPU_IFMA)
        static const bool enabled = [] {
            const char* value = std::getenv("LV_CPU_VECTOR_GOLDEN_CHECK");
            return (!value || value[0] != '0') && __builtin_cpu_supports("avx512f") &&
                __builtin_cpu_supports("avx512dq") && __builtin_cpu_supports("avx512ifma");
        }();
        if (!enabled || sourceLimbs.empty() || sourceLimbs.size() > 8 ||
            inverse.size() != sourceLimbs.size() || reciprocal.size() != sourceLimbs.size() ||
            sourceLimbs[0] >= moduli.size()) return false;
        const int bits = moduli[sourceLimbs[0]].bit_count();
        if (bits != 52 && bits != 55) return false;
        for (std::size_t j = 0; j < sourceLimbs.size(); ++j)
        {
            if (sourceLimbs[j] >= moduli.size()) return false;
            const auto& modulus = moduli[sourceLimbs[j]];
            if (modulus.bit_count() != bits || (u64{1} << bits) - modulus.value() >= (u64{1} << 24) ||
                inverse[j].operand >= modulus.value()) return false;
        }
        accepted = bits == 52
            ? checkRoundingMargin<52>(source, count, moduli, sourceLimbs, inverse, reciprocal, margin)
            : checkRoundingMargin<55>(source, count, moduli, sourceLimbs, inverse, reciprocal, margin);
        return true;
#else
        return false;
#endif
    }

    bool cpuComposeRns(const u64* source, u64* destination,
        std::size_t count, const seal::util::RNSBase& base)
    {
#if defined(__SIZEOF_INT128__)
        static const bool enabled = [] {
            const char* value = std::getenv("LV_CPU_FAST_CRT");
            return !value || value[0] != '0';
        }();
        if (!enabled || (base.size() != 4 && base.size() != 8)) return false;
        for (std::size_t i = 0; i < base.size(); ++i)
            if (base.base()[i].bit_count() > 61) return false;
#if defined(LV_CPU_IFMA)
        static const bool vectorEnabled = [] {
            const char* value = std::getenv("LV_CPU_VECTOR_CRT");
            return (!value || value[0] != '0') && __builtin_cpu_supports("avx512f") &&
                __builtin_cpu_supports("avx512dq") && __builtin_cpu_supports("avx512ifma");
        }();
        int maxBits = 0;
        for (std::size_t i = 0; i < base.size(); ++i)
            maxBits = std::max(maxBits, base.base()[i].bit_count());
        if (vectorEnabled && count >= 8 && maxBits >= 52 && maxBits <= 55)
        {
            if (base.size() == 4)
            {
                if (maxBits <= 52) composeRnsVector<4, false>(source, destination, count, base);
                else composeRnsVector<4, true>(source, destination, count, base);
            }
            else
            {
                if (maxBits <= 52) composeRnsVector<8, false>(source, destination, count, base);
                else composeRnsVector<8, true>(source, destination, count, base);
            }
            return true;
        }
#endif
        if (base.size() == 4) composeRns<4>(source, destination, count, base);
        else composeRns<8>(source, destination, count, base);
        return true;
#else
        return false;
#endif
    }

    bool cpuCenteredHighDigit(const u64* source, u64* destination,
        std::size_t count, unsigned digitBits, const seal::util::RNSBase& base)
    {
#if defined(LV_CPU_IFMA)
        static const bool enabled = [] {
            const char* value = std::getenv("LV_CPU_FUSED_GADGET");
            const char* vector = std::getenv("LV_CPU_VECTOR_CRT");
            const char* fast = std::getenv("LV_CPU_FAST_CRT");
            return (!value || value[0] != '0') && (!vector || vector[0] != '0') &&
                (!fast || fast[0] != '0') && __builtin_cpu_supports("avx512f") &&
                __builtin_cpu_supports("avx512dq") && __builtin_cpu_supports("avx512ifma");
        }();
        if (!enabled || count == 0 || count % 8) return false;
        const bool gold = base.size() == 4 && digitBits == 110;
        const bool noGold = base.size() == 8 && digitBits == 208;
        if (!gold && !noGold) return false;
        for (std::size_t j = 0; j < base.size(); ++j)
            if (base.base()[j].bit_count() != (gold ? 55 : 52)) return false;
        if (gold) composeRnsVector<4, true, 110>(source, destination, count, base);
        else composeRnsVector<8, false, 208>(source, destination, count, base);
        return true;
#else
        return false;
#endif
    }

    bool cpuLowDigitRns(const u64* source, u64* destination,
        std::size_t count, unsigned digitBits, const seal::util::RNSBase& base)
    {
#if defined(LV_CPU_IFMA)
        static const bool enabled = [] {
            const char* value = std::getenv("LV_CPU_FUSED_LOW_DIGIT");
            const char* vector = std::getenv("LV_CPU_VECTOR_CRT");
            const char* fast = std::getenv("LV_CPU_FAST_CRT");
            return (!value || value[0] != '0') && (!vector || vector[0] != '0') &&
                (!fast || fast[0] != '0') && __builtin_cpu_supports("avx512f") &&
                __builtin_cpu_supports("avx512dq") && __builtin_cpu_supports("avx512ifma");
        }();
        if (!enabled || count == 0 || count % 8) return false;
        const bool gold = base.size() == 4 && digitBits == 110;
        const bool noGold = base.size() == 8 && digitBits == 208;
        if (!gold && !noGold) return false;
        for (std::size_t j = 0; j < base.size(); ++j)
            if (base.base()[j].bit_count() != (gold ? 55 : 52)) return false;
        if (gold) composeRnsVector<4, true, 110, true>(source, destination, count, base);
        else composeRnsVector<8, false, 208, true>(source, destination, count, base);
        return true;
#else
        return false;
#endif
    }

    bool cpuUnliftCenteredRns(const u64* source, u64* destination,
        std::size_t count, const seal::Modulus& sourceModulus, u64 inverseLift,
        std::span<const seal::Modulus> destinationModuli)
    {
#if defined(LV_CPU_IFMA)
        static const bool enabled = [] {
            const char* value = std::getenv("LV_CPU_VECTOR_RECURSIVE_LEAF");
            return (!value || value[0] != '0') && __builtin_cpu_supports("avx512f") &&
                __builtin_cpu_supports("avx512dq") && __builtin_cpu_supports("avx512ifma");
        }();
        const auto bits = sourceModulus.bit_count();
        if (!enabled || count == 0 || destinationModuli.empty() ||
            (bits != 52 && bits != 55) || inverseLift >= sourceModulus.value()) return false;
        // The centered magnitude must fit in every destination modulus.
        for (const auto& modulus : destinationModuli)
            if (modulus.value() <= (sourceModulus.value() >> 1)) return false;
        // Public ring callers can supply noncanonical representatives. The
        // scalar caller normalizes them through SEAL's full-width multiplier.
        if (containsRejected(source, count, sourceModulus.value())) return false;
        if (bits == 52) unliftCenteredRns<false>(source, destination, count,
            sourceModulus.value(), inverseLift, destinationModuli);
        else unliftCenteredRns<true>(source, destination, count,
            sourceModulus.value(), inverseLift, destinationModuli);
        return true;
#else
        return false;
#endif
    }

    bool cpuDyadicInnerProduct(const u64* const* a, const u64* const* b,
        std::size_t terms, u64* c, std::size_t count, const seal::Modulus& modulus)
    {
#if defined(LV_CPU_IFMA)
        static const bool enabled = [] {
            const char* value = std::getenv("LV_CPU_FUSED_DOT");
            const char* vector = std::getenv("LV_CPU_VECTOR_DYADIC");
            return (!value || value[0] != '0') && (!vector || vector[0] != '0') &&
                __builtin_cpu_supports("avx512f") && __builtin_cpu_supports("avx512dq") &&
                __builtin_cpu_supports("avx512ifma");
        }();
        const int bits = modulus.bit_count();
        // Two-term measurements showed no benefit over the existing dyadic
        // kernel, and a small 52-bit regression. Fuse only longer products.
        if (!enabled || terms < 3 || terms > 32 || (bits != 52 && bits != 55) ||
            (u64{1} << bits) - modulus.value() >= (u64{1} << 24)) return false;
        if (bits == 52) dyadicInnerProduct<52>(a, b, terms, c, count, modulus.value());
        else dyadicInnerProduct<55>(a, b, terms, c, count, modulus.value());
        return true;
#else
        return false;
#endif
    }

    template<bool Subtract>
    bool cpuDyadicProduct(const u64* a, const u64* b, u64* c,
        std::size_t count, const seal::Modulus& modulus)
    {
#if defined(LV_CPU_IFMA)
        static const bool enabled = [] {
            const char* value = std::getenv("LV_CPU_VECTOR_DYADIC");
            return (!value || value[0] != '0') && __builtin_cpu_supports("avx512f") &&
                __builtin_cpu_supports("avx512dq") && __builtin_cpu_supports("avx512ifma");
        }();
        const u64 q = modulus.value();
        if (!enabled || count < 8) return false;
        if (q < (u64{1} << 52) && (u64{1} << 52) - q < (u64{1} << 24))
        {
            dyadic<52, Subtract>(a, b, c, count, modulus);
            return true;
        }
        if (q < (u64{1} << 55) && (u64{1} << 55) - q < (u64{1} << 24))
        {
            dyadic<55, Subtract>(a, b, c, count, modulus);
            return true;
        }
#endif
        return false;
    }

    bool cpuDyadicMultiplyAdd(const u64* a, const u64* b, u64* c,
        std::size_t count, const seal::Modulus& modulus)
    {
        return cpuDyadicProduct<false>(a, b, c, count, modulus);
    }

    bool cpuDyadicMultiplySubtract(const u64* a, const u64* b, u64* c,
        std::size_t count, const seal::Modulus& modulus)
    {
        return cpuDyadicProduct<true>(a, b, c, count, modulus);
    }
}

#include "libOTe/Vole/LogVole/LogVoleCpuZk.h"
#include "libOTe/Vole/LogVole/LogVoleArithmetic.h"
#include <algorithm>
#include <cstdlib>
#include <limits>

#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
#include <immintrin.h>
#define LV_ZK_VECTOR 1
#define LV_ZK_TARGET __attribute__((target("avx512f,avx512dq,avx512ifma")))
#define LV_ZK_INLINE LV_ZK_TARGET __attribute__((always_inline)) inline
#endif

namespace osuCrypto::LogVole::detail
{
    namespace
    {
#if defined(LV_ZK_VECTOR)
        template<unsigned Bits>
        struct VectorField
        {
            static_assert(Bits == 51 || Bits == 54);
            __m512i q, gap, mask, mask52, zero;

            LV_ZK_INLINE explicit VectorField(u64 modulus)
                : q(_mm512_set1_epi64(modulus)), gap(_mm512_set1_epi64((u64{1} << Bits) - modulus)),
                  mask(_mm512_set1_epi64((u64{1} << Bits) - 1)),
                  mask52(_mm512_set1_epi64((u64{1} << 52) - 1)), zero(_mm512_setzero_si512()) {}

            LV_ZK_INLINE __m512i canonical(__m512i x) const
            {
                x = _mm512_add_epi64(_mm512_and_si512(x, mask),
                    _mm512_mullo_epi64(_mm512_srli_epi64(x, Bits), gap));
                return subtractQ(x);
            }

            LV_ZK_INLINE __m512i subtractQ(__m512i x) const
            {
                return _mm512_mask_sub_epi64(x, _mm512_cmp_epu64_mask(x, q, _MM_CMPINT_NLT), x, q);
            }

            LV_ZK_INLINE __m512i add(__m512i x, __m512i y) const
            {
                return subtractQ(_mm512_add_epi64(x, y));
            }

            LV_ZK_INLINE __m512i subtract(__m512i x, __m512i y) const
            {
                const auto difference = _mm512_sub_epi64(x, y);
                return _mm512_mask_add_epi64(difference,
                    _mm512_cmp_epu64_mask(x, y, _MM_CMPINT_LT), difference, q);
            }

            LV_ZK_INLINE void product(__m512i x, __m512i y, __m512i& lo52, __m512i& hi52) const
            {
                lo52 = _mm512_madd52lo_epu64(zero, x, y);
                hi52 = _mm512_madd52hi_epu64(zero, x, y);
                if constexpr (Bits > 52)
                {
                    const auto xh = _mm512_srli_epi64(x, 52), yh = _mm512_srli_epi64(y, 52);
                    hi52 = _mm512_add_epi64(hi52, _mm512_mullo_epi64(xh, _mm512_and_si512(y, mask52)));
                    hi52 = _mm512_add_epi64(hi52, _mm512_mullo_epi64(yh, _mm512_and_si512(x, mask52)));
                    hi52 = _mm512_add_epi64(hi52, _mm512_slli_epi64(_mm512_mullo_epi64(xh, yh), 52));
                }
            }

            LV_ZK_INLINE __m512i reduceProduct(__m512i lo52, __m512i hi52) const
            {
                __m512i low, high;
                if constexpr (Bits < 52)
                {
                    low = _mm512_and_si512(lo52, mask);
                    high = _mm512_or_si512(_mm512_slli_epi64(hi52, 52 - Bits),
                        _mm512_srli_epi64(lo52, Bits));
                }
                else
                {
                    low = _mm512_and_si512(_mm512_or_si512(lo52, _mm512_slli_epi64(hi52, 52)), mask);
                    high = _mm512_srli_epi64(hi52, Bits - 52);
                }
                auto foldedLo = _mm512_madd52lo_epu64(_mm512_and_si512(low, mask52), high, gap);
                auto foldedHi = _mm512_madd52hi_epu64(zero, high, gap);
                foldedHi = _mm512_add_epi64(foldedHi, _mm512_srli_epi64(foldedLo, 52));
                if constexpr (Bits > 52)
                {
                    foldedHi = _mm512_add_epi64(foldedHi, _mm512_srli_epi64(low, 52));
                    foldedHi = _mm512_add_epi64(foldedHi,
                        _mm512_mullo_epi64(_mm512_srli_epi64(high, 52), gap));
                }
                foldedLo = _mm512_and_si512(foldedLo, mask52);
                if constexpr (Bits < 52)
                {
                    low = _mm512_and_si512(foldedLo, mask);
                    high = _mm512_or_si512(_mm512_slli_epi64(foldedHi, 52 - Bits),
                        _mm512_srli_epi64(foldedLo, Bits));
                }
                else
                {
                    low = _mm512_and_si512(_mm512_or_si512(foldedLo,
                        _mm512_slli_epi64(foldedHi, 52)), mask);
                    high = _mm512_srli_epi64(foldedHi, Bits - 52);
                }
                // At most two products, gap<2^24, Bits>=51: after the
                // second fold the value is <2^Bits+2*gap^2<2q.
                return subtractQ(_mm512_add_epi64(low, _mm512_mullo_epi64(high, gap)));
            }

            LV_ZK_INLINE __m512i multiply(__m512i x, __m512i y) const
            {
                __m512i lo, hi;
                product(x, y, lo, hi);
                return reduceProduct(lo, hi);
            }

            LV_ZK_INLINE __m512i multiplyPair(__m512i x, __m512i y, __m512i z, __m512i w) const
            {
                __m512i lo, hi, otherLo, otherHi;
                product(x, y, lo, hi);
                product(z, w, otherLo, otherHi);
                lo = _mm512_add_epi64(lo, otherLo);
                hi = _mm512_add_epi64(_mm512_add_epi64(hi, otherHi), _mm512_srli_epi64(lo, 52));
                return reduceProduct(_mm512_and_si512(lo, mask52), hi);
            }

            LV_ZK_INLINE __m512i constant(__m512i x, __m512i operand, __m512i shoup) const
            {
                auto high = _mm512_madd52hi_epu64(zero, x, shoup);
                if constexpr (Bits < 52)
                    high = _mm512_add_epi64(high, _mm512_mullo_epi64(x, _mm512_srli_epi64(shoup, 52)));
                else
                {
                    const auto xh = _mm512_srli_epi64(x, 52), sh = _mm512_srli_epi64(shoup, 52);
                    high = _mm512_add_epi64(high, _mm512_mullo_epi64(xh, _mm512_and_si512(shoup, mask52)));
                    high = _mm512_add_epi64(high, _mm512_mullo_epi64(_mm512_and_si512(x, mask52), sh));
                    high = _mm512_add_epi64(high, _mm512_slli_epi64(_mm512_mullo_epi64(xh, sh), 52));
                }
                const auto quotient = _mm512_srli_epi64(high, Bits < 52 ? 11 : 8);
                return subtractQ(_mm512_sub_epi64(_mm512_mullo_epi64(x, operand),
                    _mm512_mullo_epi64(quotient, q)));
            }
        };

        template<unsigned Bits>
        LV_ZK_TARGET void witnessRange(const u32* operands, const u64* wires,
            u64* outputs, std::size_t count, const seal::Modulus& modulus)
        {
            const VectorField<Bits> field(modulus.value());
            const auto even = _mm512_setr_epi32(0,2,4,6,8,10,12,14,0,0,0,0,0,0,0,0);
            const auto odd = _mm512_setr_epi32(1,3,5,7,9,11,13,15,0,0,0,0,0,0,0,0);
            for (std::size_t i = 0; i < count; i += 8)
            {
                const auto active = std::min<std::size_t>(8, count-i);
                const auto lanes = static_cast<__mmask8>((1u << active)-1);
                const auto raw = _mm512_maskz_loadu_epi32(static_cast<__mmask16>((1u << (2*active))-1), operands+2*i);
                const auto ix = _mm512_cvtepu32_epi64(_mm512_castsi512_si256(_mm512_permutexvar_epi32(even, raw)));
                const auto iy = _mm512_cvtepu32_epi64(_mm512_castsi512_si256(_mm512_permutexvar_epi32(odd, raw)));
                const auto x = field.canonical(_mm512_mask_i64gather_epi64(field.zero, lanes, ix, wires, 8));
                const auto y = field.canonical(_mm512_mask_i64gather_epi64(field.zero, lanes, iy, wires, 8));
                _mm512_mask_storeu_epi64(outputs+i, lanes, field.multiply(x,y));
            }
        }

        template<unsigned Bits, bool Prover>
        LV_ZK_TARGET void gateRange(const u32* operands, const u64* wires, const u64* labels,
            const u64* outputs, std::size_t count, u64 firstPower, u64 chi, u64 delta,
            const seal::Modulus& modulus, u64* result)
        {
            const u64 q = modulus.value();
            const VectorField<Bits> field(q);
            seal::util::MultiplyUIntModOperand chiOperand;
            chiOperand.set(chi % q, modulus);
            u64 weights[8];
            weights[0] = firstPower % q;
            for (unsigned lane = 1; lane < 8; ++lane)
                weights[lane] = seal::util::multiply_uint_mod(weights[lane-1], chiOperand, modulus);
            u64 stride = chi % q;
            for (unsigned i = 0; i < 3; ++i) stride = mulMod(stride, stride, modulus);
            constexpr unsigned ShoupBits = Bits < 52 ? 63 : 60;
            const auto strideVector = _mm512_set1_epi64(stride);
            const auto strideShoup = _mm512_set1_epi64(static_cast<u64>(
                (static_cast<__uint128_t>(stride) << ShoupBits) / q));
            delta %= q;
            const auto deltaVector = _mm512_set1_epi64(delta);
            const auto deltaShoup = _mm512_set1_epi64(static_cast<u64>(
                (static_cast<__uint128_t>(delta) << ShoupBits) / q));
            const auto even = _mm512_setr_epi32(0,2,4,6,8,10,12,14,0,0,0,0,0,0,0,0);
            const auto odd = _mm512_setr_epi32(1,3,5,7,9,11,13,15,0,0,0,0,0,0,0,0);
            auto powers = _mm512_loadu_si512(weights), sumU = field.zero, sumV = field.zero;
            for (std::size_t i = 0; i < count; i += 8)
            {
                const auto active = std::min<std::size_t>(8, count - i);
                const auto lanes = static_cast<__mmask8>((1u << active) - 1);
                const auto raw = _mm512_maskz_loadu_epi32(static_cast<__mmask16>((1u << (2*active)) - 1), operands + 2*i);
                // Zero-extend the public u32 indices before gathering. Signed
                // i32 gathers would misaddress circuits with indices >=2^31.
                const auto ix = _mm512_cvtepu32_epi64(_mm512_castsi512_si256(_mm512_permutexvar_epi32(even, raw)));
                const auto iy = _mm512_cvtepu32_epi64(_mm512_castsi512_si256(_mm512_permutexvar_epi32(odd, raw)));
                const auto mx = field.canonical(_mm512_mask_i64gather_epi64(field.zero, lanes, ix, labels, 8));
                const auto my = field.canonical(_mm512_mask_i64gather_epi64(field.zero, lanes, iy, labels, 8));
                const auto mz = field.canonical(_mm512_maskz_loadu_epi64(lanes, outputs + i));
                if constexpr (Prover)
                {
                    const auto wx = field.canonical(_mm512_mask_i64gather_epi64(field.zero, lanes, ix, wires, 8));
                    const auto wy = field.canonical(_mm512_mask_i64gather_epi64(field.zero, lanes, iy, wires, 8));
                    const auto a0 = field.multiply(mx, my);
                    const auto a1 = field.subtract(mz, field.multiplyPair(wx, my, wy, mx));
                    sumU = field.add(sumU, field.multiply(powers, a0));
                    sumV = field.add(sumV, field.multiply(powers, a1));
                }
                else
                {
                    const auto b = field.add(field.multiply(mx, my), field.constant(mz, deltaVector, deltaShoup));
                    sumU = field.add(sumU, field.multiply(powers, b));
                }
                powers = field.constant(powers, strideVector, strideShoup);
            }
            u64 partialU[8], partialV[8];
            _mm512_storeu_si512(partialU, sumU);
            _mm512_storeu_si512(partialV, sumV);
            result[0] = result[1] = 0;
            for (unsigned lane = 0; lane < 8; ++lane)
            {
                result[0] = addMod(result[0], partialU[lane], modulus);
                if constexpr (Prover) result[1] = addMod(result[1], partialV[lane], modulus);
            }
        }

        int vectorBits(const seal::Modulus& modulus, std::size_t count)
        {
            static const bool enabled = [] {
                const char* value = std::getenv("LV_CPU_VECTOR_ZK");
                const char* pseudo = std::getenv("LV_CPU_ZK_PSEUDO_REDUCE");
                return (!value || value[0] != '0') && (!pseudo || pseudo[0] != '0') &&
                    __builtin_cpu_supports("avx512f") && __builtin_cpu_supports("avx512dq") &&
                    __builtin_cpu_supports("avx512ifma");
            }();
            const int bits = modulus.bit_count();
            if (!enabled || count < 8 || (bits != 51 && bits != 54) ||
                (u64{1} << bits) - modulus.value() >= (u64{1} << 24)) return 0;
            return bits;
        }

#if defined(__SIZEOF_INT128__)
        // Each product is kept as lo52 + 2^52*hi52 without modular reduction.
        // A 512-term block gives at most 64 products per lane, or 128 for the
        // prover's cross sum. At 54 bits, hi52 < 2^56, so its cross accumulator
        // stays below 2^63; lo52 stays below 2^59. Horizontal reconstruction
        // sums fewer than 2^118 in uint128. Neither vector lane can overflow.
        template<unsigned Bits>
        LV_ZK_INLINE void accumulateRawProduct(const VectorField<Bits>& field,
            __m512i a, __m512i b, __m512i& low, __m512i& high)
        {
            __m512i productLow, productHigh;
            field.product(a, b, productLow, productHigh);
            low = _mm512_add_epi64(low, productLow);
            high = _mm512_add_epi64(high, productHigh);
        }

        LV_ZK_INLINE u64 reduceRawLanes(__m512i low, __m512i high, u64 modulus)
        {
            u64 lows[8], highs[8];
            _mm512_storeu_si512(lows, low);
            _mm512_storeu_si512(highs, high);
            __uint128_t sum = 0;
            for (unsigned lane = 0; lane != 8; ++lane)
                sum += (static_cast<__uint128_t>(highs[lane]) << 52) + lows[lane];
            return static_cast<u64>(sum % modulus);
        }

        template<unsigned Bits>
        LV_ZK_TARGET void matrixProverTermsVector(
            const u64* a, const u64* ma, const u64* bt, const u64* mbt,
            u64* a0, u64* cross, std::size_t n, std::size_t beginRow,
            std::size_t endRow, const seal::Modulus& modulus)
        {
            const VectorField<Bits> field(modulus.value());
            for (std::size_t i = beginRow; i < endRow; ++i)
                for (std::size_t j = 0; j < n; ++j)
                {
                    const u64* ar = a + i * n;
                    const u64* mar = ma + i * n;
                    const u64* br = bt + j * n;
                    const u64* mbr = mbt + j * n;
                    u64 sum0 = 0, sumCross = 0;
                    for (std::size_t start = 0; start < n; start += 512)
                    {
                        const std::size_t end = std::min(n, start + 512);
                        auto low0 = field.zero, high0 = field.zero;
                        auto lowCross = field.zero, highCross = field.zero;
                        std::size_t k = start;
                        for (; k + 8 <= end; k += 8)
                        {
                            const auto av = _mm512_loadu_si512(ar + k);
                            const auto mav = _mm512_loadu_si512(mar + k);
                            const auto bv = _mm512_loadu_si512(br + k);
                            const auto mbv = _mm512_loadu_si512(mbr + k);
                            accumulateRawProduct(field, mav, mbv, low0, high0);
                            accumulateRawProduct(field, av, mbv, lowCross, highCross);
                            accumulateRawProduct(field, bv, mav, lowCross, highCross);
                        }
                        if (k != end)
                        {
                            const auto lanes = static_cast<__mmask8>((1u << (end - k)) - 1);
                            const auto av = _mm512_maskz_loadu_epi64(lanes, ar + k);
                            const auto mav = _mm512_maskz_loadu_epi64(lanes, mar + k);
                            const auto bv = _mm512_maskz_loadu_epi64(lanes, br + k);
                            const auto mbv = _mm512_maskz_loadu_epi64(lanes, mbr + k);
                            accumulateRawProduct(field, mav, mbv, low0, high0);
                            accumulateRawProduct(field, av, mbv, lowCross, highCross);
                            accumulateRawProduct(field, bv, mav, lowCross, highCross);
                        }
                        sum0 = addMod(sum0, reduceRawLanes(low0, high0, modulus.value()), modulus);
                        sumCross = addMod(sumCross,
                            reduceRawLanes(lowCross, highCross, modulus.value()), modulus);
                    }
                    a0[i * n + j] = sum0;
                    cross[i * n + j] = sumCross;
                }
        }

        template<unsigned Bits>
        LV_ZK_TARGET void matrixVerifierTermsVector(
            const u64* a, const u64* bt, u64* products, std::size_t n,
            std::size_t beginRow, std::size_t endRow, const seal::Modulus& modulus)
        {
            const VectorField<Bits> field(modulus.value());
            for (std::size_t i = beginRow; i < endRow; ++i)
                for (std::size_t j = 0; j < n; ++j)
                {
                    const u64* ar = a + i * n;
                    const u64* br = bt + j * n;
                    u64 sum = 0;
                    for (std::size_t start = 0; start < n; start += 512)
                    {
                        const std::size_t end = std::min(n, start + 512);
                        auto low = field.zero, high = field.zero;
                        std::size_t k = start;
                        for (; k + 8 <= end; k += 8)
                            accumulateRawProduct(field, _mm512_loadu_si512(ar + k),
                                _mm512_loadu_si512(br + k), low, high);
                        if (k != end)
                        {
                            const auto lanes = static_cast<__mmask8>((1u << (end - k)) - 1);
                            accumulateRawProduct(field, _mm512_maskz_loadu_epi64(lanes, ar + k),
                                _mm512_maskz_loadu_epi64(lanes, br + k), low, high);
                        }
                        sum = addMod(sum, reduceRawLanes(low, high, modulus.value()), modulus);
                    }
                    products[i * n + j] = sum;
                }
        }

        int matrixVectorBits(const seal::Modulus& modulus)
        {
            static const bool enabled = [] {
                const char* value = std::getenv("LV_CPU_VECTOR_MATMUL");
                return (!value || value[0] != '0') &&
                    __builtin_cpu_supports("avx512f") && __builtin_cpu_supports("avx512dq") &&
                    __builtin_cpu_supports("avx512ifma");
            }();
            const int bits = modulus.bit_count();
            return enabled && (bits == 51 || bits == 54) ? bits : 0;
        }
#endif
#endif

        bool validMatrixRange(std::size_t n, std::size_t beginRow,
            std::size_t endRow, const seal::Modulus& modulus)
        {
            const auto maxWords = std::numeric_limits<std::size_t>::max() / sizeof(u64);
            return n != 0 && n <= maxWords / n && beginRow <= endRow && endRow <= n &&
                modulus.value() >= 2 && modulus.value() < (u64{1} << 61);
        }

#if defined(__SIZEOF_INT128__)
        std::size_t scalarMatrixBlockSize(const seal::Modulus& modulus)
        {
            // Each product is <2^(2*bits). Limit each raw accumulator to
            // <2^126, leaving space to combine the two cross-product sums.
            // Avoid shifting by an unrepresentable amount for small moduli.
            const unsigned exponent = 126u - 2u * static_cast<unsigned>(modulus.bit_count());
            return exponent >= 12 ? 4096 : std::size_t{1} << exponent;
        }

        void matrixProverTermsScalar(
            const u64* a, const u64* ma, const u64* bt, const u64* mbt,
            u64* a0, u64* cross, std::size_t n, std::size_t beginRow,
            std::size_t endRow, const seal::Modulus& modulus)
        {
            const std::size_t block = scalarMatrixBlockSize(modulus);
            for (std::size_t i = beginRow; i < endRow; ++i)
                for (std::size_t j = 0; j < n; ++j)
                {
                    const u64* ar = a + i * n;
                    const u64* mar = ma + i * n;
                    const u64* br = bt + j * n;
                    const u64* mbr = mbt + j * n;
                    u64 sum0 = 0, sumCross = 0;
                    for (std::size_t start = 0; start < n; start += block)
                    {
                        const std::size_t end = std::min(n, start + block);
                        __uint128_t raw0 = 0, raw1 = 0, raw2 = 0;
                        for (std::size_t k = start; k < end; ++k)
                        {
                            raw0 += static_cast<__uint128_t>(mar[k]) * mbr[k];
                            raw1 += static_cast<__uint128_t>(ar[k]) * mbr[k];
                            raw2 += static_cast<__uint128_t>(br[k]) * mar[k];
                        }
                        sum0 = addMod(sum0, static_cast<u64>(raw0 % modulus.value()), modulus);
                        sumCross = addMod(sumCross,
                            static_cast<u64>((raw1 + raw2) % modulus.value()), modulus);
                    }
                    a0[i * n + j] = sum0;
                    cross[i * n + j] = sumCross;
                }
        }

        void matrixVerifierTermsScalar(
            const u64* a, const u64* bt, u64* products, std::size_t n,
            std::size_t beginRow, std::size_t endRow, const seal::Modulus& modulus)
        {
            const std::size_t block = scalarMatrixBlockSize(modulus);
            for (std::size_t i = beginRow; i < endRow; ++i)
                for (std::size_t j = 0; j < n; ++j)
                {
                    const u64* ar = a + i * n;
                    const u64* br = bt + j * n;
                    u64 sum = 0;
                    for (std::size_t start = 0; start < n; start += block)
                    {
                        const std::size_t end = std::min(n, start + block);
                        __uint128_t raw = 0;
                        for (std::size_t k = start; k < end; ++k)
                            raw += static_cast<__uint128_t>(ar[k]) * br[k];
                        sum = addMod(sum, static_cast<u64>(raw % modulus.value()), modulus);
                    }
                    products[i * n + j] = sum;
                }
        }
#endif
    }

    bool cpuZkWitnessRange(const u32* operands, const u64* wires, u64* outputs,
        std::size_t count, const seal::Modulus& modulus)
    {
#if defined(LV_ZK_VECTOR)
        static const bool enabled = [] {
            const char* value = std::getenv("LV_CPU_VECTOR_WITNESS");
            return !value || value[0] != '0';
        }();
        if (!enabled) return false;
        const int bits = vectorBits(modulus, count);
        if (bits == 51) witnessRange<51>(operands, wires, outputs, count, modulus);
        else if (bits == 54) witnessRange<54>(operands, wires, outputs, count, modulus);
        else return false;
        return true;
#else
        return false;
#endif
    }

    bool cpuZkProverRange(const u32* operands, const u64* wires, const u64* macs,
        const u64* outputs, std::size_t count, u64 firstPower, u64 chi,
        const seal::Modulus& modulus, std::array<u64, 2>& result)
    {
#if defined(LV_ZK_VECTOR)
        const int bits = vectorBits(modulus, count);
        if (bits == 51) gateRange<51, true>(operands, wires, macs, outputs, count, firstPower, chi, 0, modulus, result.data());
        else if (bits == 54) gateRange<54, true>(operands, wires, macs, outputs, count, firstPower, chi, 0, modulus, result.data());
        else return false;
        return true;
#else
        return false;
#endif
    }

    bool cpuZkVerifierRange(const u32* operands, const u64* keys, const u64* outputs,
        std::size_t count, u64 firstPower, u64 chi, u64 delta,
        const seal::Modulus& modulus, u64& result)
    {
#if defined(LV_ZK_VECTOR)
        const int bits = vectorBits(modulus, count);
        u64 sums[2];
        if (bits == 51) gateRange<51, false>(operands, nullptr, keys, outputs, count, firstPower, chi, delta, modulus, sums);
        else if (bits == 54) gateRange<54, false>(operands, nullptr, keys, outputs, count, firstPower, chi, delta, modulus, sums);
        else return false;
        result = sums[0];
        return true;
#else
        return false;
#endif
    }

    bool cpuZkMatMulProverTerms(
        const u64* a, const u64* ma, const u64* bt, const u64* mbt,
        u64* a0, u64* cross, std::size_t n, std::size_t beginRow,
        std::size_t endRow, const seal::Modulus& modulus)
    {
        if (!validMatrixRange(n, beginRow, endRow, modulus)) return false;
        if (beginRow == endRow) return true;
        if (!a || !ma || !bt || !mbt || !a0 || !cross) return false;
#if defined(__SIZEOF_INT128__)
#if defined(LV_ZK_VECTOR)
        const int bits = matrixVectorBits(modulus);
        if (bits == 51) matrixProverTermsVector<51>(a, ma, bt, mbt, a0, cross,
            n, beginRow, endRow, modulus);
        else if (bits == 54) matrixProverTermsVector<54>(a, ma, bt, mbt, a0, cross,
            n, beginRow, endRow, modulus);
        else
#endif
            matrixProverTermsScalar(a, ma, bt, mbt, a0, cross, n, beginRow, endRow, modulus);
        return true;
#else
        return false;
#endif
    }

    bool cpuZkMatMulVerifierTerms(
        const u64* a, const u64* bt, u64* products, std::size_t n,
        std::size_t beginRow, std::size_t endRow, const seal::Modulus& modulus)
    {
        if (!validMatrixRange(n, beginRow, endRow, modulus)) return false;
        if (beginRow == endRow) return true;
        if (!a || !bt || !products) return false;
#if defined(__SIZEOF_INT128__)
#if defined(LV_ZK_VECTOR)
        const int bits = matrixVectorBits(modulus);
        if (bits == 51) matrixVerifierTermsVector<51>(a, bt, products, n, beginRow, endRow, modulus);
        else if (bits == 54) matrixVerifierTermsVector<54>(a, bt, products, n, beginRow, endRow, modulus);
        else
#endif
            matrixVerifierTermsScalar(a, bt, products, n, beginRow, endRow, modulus);
        return true;
#else
        return false;
#endif
    }
}

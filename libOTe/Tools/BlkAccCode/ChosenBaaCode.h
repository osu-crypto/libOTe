#pragma once

#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Aligned.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "libOTe/Tools/CompilerHints.h"
#include "ChosenBaaField.h"

#include <array>
#include <limits>

namespace osuCrypto
{
    // Field-generic transpose encoder for chosen-block BAA, RS[16,K,17-K].
    // Ported from ladnir/libOTe chosen-block-baa, fa7bfc3c8a0178fc99b0b666d5f31fc2a9277579.
    // Both interleavers are Fisher--Yates shuffles, including at power-of-two
    // lengths. Each accumulator output has an independent nonzero field weight.
    // Randomness is expanded by AES; see README.md for the proof boundary.
    template<u64 K, typename F = block, typename Field = ChosenBaaField<F>>
    class ChosenBaaCode
    {
        static_assert(K == 4 || K == 8);
        static_assert(std::is_same_v<F, typename Field::Element>);
        using Matrix = std::array<F, K * (16 - K)>;
        u64 mN = 0;
        std::array<AlignedUnVector<u32>, 2> mPerm;
        std::array<block, 2> mWeightSeeds;
        const Matrix* mMatrix = nullptr;

        static u32 sampleBelow(PRNG& prng, u32 bound)
        {
            u64 product = u64(prng.get<u32>()) * bound;
            if (u32(product) < bound)
            {
                const u32 threshold = (u32(0) - bound) % bound;
                while (u32(product) < threshold)
                    product = u64(prng.get<u32>()) * bound;
            }
            return u32(product >> 32);
        }

        // Fixed, unrolled prefix and scatter kernels expose independent products.
        template<bool Pair, u64 Count = 8, u64 J = 0>
        static OC_FORCEINLINE void prefix(const F* a, const F* b, F* va, F* vb, F& sa, F& sb)
        {
            if constexpr (J < Count)
            {
                va[J] = sa = Field::add(sa, a[J]);
                if constexpr (Pair) vb[J] = sb = Field::add(sb, b[J]);
                prefix<Pair, Count, J + 1>(a, b, va, vb, sa, sb);
            }
        }
        template<bool Pair, u64 Count = 8, u64 J = 0>
        static OC_FORCEINLINE void scatter(const u32* indices, const F* a, const F* b, F* oa, F* ob)
        {
            if constexpr (J < Count)
            {
                const auto dest = indices[J];
                oa[dest] = a[J];
                if constexpr (Pair) ob[dest] = b[J];
                scatter<Pair, Count, J + 1>(indices, a, b, oa, ob);
            }
        }
        template<bool Pair, u64 J = 0>
        static OC_FORCEINLINE void prefetchDestinations(const u32* indices, F* a, F* b)
        {
#ifdef OC_ENABLE_SSE2
            if constexpr (J < 8)
            {
                const auto dest = indices[J];
                _mm_prefetch(reinterpret_cast<const char*>(a + dest), _MM_HINT_T2);
                if constexpr (Pair)
                    _mm_prefetch(reinterpret_cast<const char*>(b + dest), _MM_HINT_T2);
                prefetchDestinations<Pair, J + 1>(indices, a, b);
            }
#endif
        }
        template<bool Pair, bool Prefetch>
        void stageImpl(const F* a, const F* b, F* outA, F* outB, u64 which) const
        {
            PRNG weights(mWeightSeeds[which]);
            F sumA = Field::zero(), sumB = Field::zero();
            for (u64 i = 0; i < mN; i += 8)
            {
                // Schedule future random destination lines before their stores.
                // Bound the metadata reads as well as the prefetch addresses;
                // the final eight batches use the same arithmetic without hints.
                if constexpr (Prefetch)
                    if (i + 64 + 8 <= mN)
                        prefetchDestinations<Pair>(mPerm[which].data() + i + 64, outA, outB);
                std::array<F, 8> coeffs, valuesA, valuesB;
                Field::sample8(weights, coeffs.data());
#if defined(OC_ENABLE_VPCLMUL) && defined(ENABLE_AVX512)
                if constexpr (std::is_same_v<Field, ChosenBaaField<block>>)
                {
                    const F* bi = nullptr;
                    if constexpr (Pair) bi = b + i;
                    prefix<Pair>(a + i, bi, valuesA.data(), valuesB.data(), sumA, sumB);
                    Field::mul8(valuesA.data(), coeffs.data());
                    if constexpr (Pair) Field::mul8(valuesB.data(), coeffs.data());
                    scatter<Pair>(mPerm[which].data() + i, valuesA.data(), valuesB.data(), outA, outB);
                }
                else
#endif
                {
                    // Preserve the interleaved prefix/product schedule for
                    // 128-bit PCLMUL, PMULL, and generic field arithmetic.
                    for (u64 j = 0; j < 8; ++j)
                    {
                        sumA = Field::add(sumA, a[i + j]);
                        valuesA[j] = Field::mul(sumA, coeffs[j]);
                        if constexpr (Pair)
                        {
                            sumB = Field::add(sumB, b[i + j]);
                            valuesB[j] = Field::mul(sumB, coeffs[j]);
                        }
                    }
                    for (u64 j = 0; j < 8; ++j)
                    {
                        const auto dest = mPerm[which][i + j];
                        outA[dest] = valuesA[j];
                        if constexpr (Pair) outB[dest] = valuesB[j];
                    }
                }
            }
        }
        template<bool Pair>
        void stage(const F* a, const F* b, F* outA, F* outB, u64 which) const
        {
#ifdef OC_ENABLE_SSE2
            if constexpr (std::is_same_v<Field, ChosenBaaField<block>>)
            {
                // Small inputs already fit in cache; avoid issuing extra hints.
                // Select the loop once rather than testing size in every batch.
                if (mN >= (u64{1} << 18))
                    return stageImpl<Pair, true>(a, b, outA, outB, which);
            }
#endif
            stageImpl<Pair, false>(a, b, outA, outB, which);
        }
        static const Matrix& matrixData()
        {
            // One immutable RS matrix per field/profile, independent of the seed.
            // Thread-safe initialization does field inversion only on first use.
            static const Matrix matrix = [] {
                Matrix result;
                for (u64 i = 0; i < 16; ++i)
                    for (u64 j = 0; j < i; ++j)
                        if (Field::point(i) == Field::point(j))
                            throw std::invalid_argument("Chosen BAA requires sixteen distinct evaluation points.");
                for (u64 row = 0; row < K; ++row)
                {
                    const F x = Field::point(row);
                    F denominator = Field::one();
                    for (u64 h = 0; h < K; ++h)
                        if (h != row) denominator = Field::mul(denominator, Field::sub(x, Field::point(h)));
                    const F inv = Field::inverse(denominator);
                    for (u64 col = 0; col < 16 - K; ++col)
                    {
                        F numerator = Field::one();
                        for (u64 h = 0; h < K; ++h)
                            if (h != row) numerator = Field::mul(numerator, Field::sub(Field::point(K + col), Field::point(h)));
                        // Consecutive output rows form consecutive SIMD lanes.
                        result[col * K + row] = Field::mul(numerator, inv);
                    }
                }
                return result;
            }();
            return matrix;
        }

        template<bool Pair>
        void encode(span<F> a, span<F> b) const
        {
            if (!mN || a.size() != mN || (Pair && b.size() != mN))
                throw std::invalid_argument("Chosen BAA input size does not match configuration.");
            AlignedUnVector<F> scratchA(mN), scratchB;
            if constexpr (Pair)
                scratchB.resize(mN);
            stage<Pair>(a.data(), b.data(), scratchA.data(), scratchB.data(), 1);
            stage<Pair>(scratchA.data(), scratchB.data(), a.data(), b.data(), 0);
            for (u64 i = 0; i < mN / 16; ++i)
            {
                // The output prefix cannot overwrite a future constituent.
                Field::template local<K>(a.data() + 16 * i, a.data() + K * i, mMatrix->data());
                if constexpr (Pair)
                    Field::template local<K>(b.data() + 16 * i, b.data() + K * i, mMatrix->data());
            }
        }

    public:
        void config(u64 n, block seed)
        {
            if (!n || n % 16 || n > std::numeric_limits<u32>::max())
                throw std::invalid_argument("Chosen BAA length must be a positive multiple of 16 fitting u32.");
            mMatrix = &matrixData();
            PRNG master(seed);
            const std::array<block, 2> permutationSeeds{ master.get<block>(), master.get<block>() };
            mWeightSeeds = { master.get<block>(), master.get<block>() };
            for (u64 stage = 0; stage < 2; ++stage)
            {
                auto& perm = mPerm[stage];
                perm.resize(n);
                for (u64 i = 0; i < n; ++i)
                    perm[i] = u32(i);
                PRNG random(permutationSeeds[stage]);
                for (u64 remaining = n; remaining > 1; --remaining)
                    std::swap(perm[remaining - 1], perm[sampleBelow(random, u32(remaining))]);
            }
            mN = n;
        }

        u64 outputSize() const { return mN / 16 * K; }
        u32 permutationIndex(u64 stage, u64 i) const
        {
            if (i >= mN) throw std::out_of_range("Chosen BAA permutation index.");
            return mPerm.at(stage)[i];
        }
        block weightSeed(u64 stage) const { return mWeightSeeds.at(stage); }
        F matrix(u64 row, u64 col) const
        {
            if (!mMatrix || row >= K || col >= 16 - K) throw std::out_of_range("Chosen BAA matrix index.");
            return (*mMatrix)[col * K + row];
        }
        void dualEncode(span<F> a) const { encode<false>(a, {}); }
        void dualEncode2(span<F> a, span<F> b) const { encode<true>(a, b); }
    };

}

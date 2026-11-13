#pragma once

#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Aligned.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "libOTe/Tools/CompilerHints.h"
#include "libOTe/Tools/Coproto.h"
#include "libOTe/TwoChooseOne/ConfigureCode.h"
#include <array>

namespace osuCrypto
{
    // GF(2^128) transpose encoder for chosen-block BAA, RS[16,K,17-K].
    // Ported from ladnir/libOTe chosen-block-baa, fa7bfc3c8a0178fc99b0b666d5f31fc2a9277579.
    // Both interleavers are Fisher--Yates shuffles, including at power-of-two
    // lengths. Each accumulator output has an independent nonzero field weight.
    // Randomness is expanded by AES; see README.md for the proof boundary.
    template<u64 K>
    class ChosenBaaCode
    {
        static_assert(K == 4 || K == 8);
        u64 mN = 0;
        std::array<AlignedUnVector<u32>, 2> mPerm;
        std::array<block, 2> mWeightSeeds;
        std::array<block, K * (16 - K)> mMatrix;

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

        static block inverse(block x)
        {
            block result = x;
            for (u64 i = 1; i < 127; ++i)
                result = result.gf128Mul(result).gf128Mul(x);
            return result.gf128Mul(result);
        }

        // Fixed-size kernels keep independent field products visible to the
        // compiler. No permutation dispatch or allocation in the scan loop.
        template<bool Pair>
        void stage(block* a, block* b, block* outA, block* outB, u64 which) const
        {
            PRNG weights(mWeightSeeds[which]);
            block sumA = ZeroBlock, sumB = ZeroBlock;
            for (u64 i = 0; i < mN; i += 8)
            {
                std::array<block, 8> coeffs, valuesA, valuesB;
                weights.get(coeffs.data(), coeffs.size());
                for (u64 j = 0; j < 8; ++j)
                {
                    while (coeffs[j] == ZeroBlock)
                        coeffs[j] = weights.get<block>();
                    sumA ^= a[i + j];
                    valuesA[j] = sumA.gf128Mul(coeffs[j]);
                    if constexpr (Pair)
                    {
                        sumB ^= b[i + j];
                        valuesB[j] = sumB.gf128Mul(coeffs[j]);
                    }
                }
                for (u64 j = 0; j < 8; ++j)
                {
                    const auto dest = mPerm[which][i + j];
                    outA[dest] = valuesA[j];
                    if constexpr (Pair)
                        outB[dest] = valuesB[j];
                }
            }
        }

        template<u64 Row = 0>
        OC_FORCEINLINE void local(const block* in, block* out) const
        {
            if constexpr (Row < K)
            {
                block low = ZeroBlock, high = ZeroBlock;
                for (u64 col = 0; col < 16 - K; ++col)
                {
                    block lo, hi;
                    in[K + col].gf128Mul(mMatrix[Row * (16 - K) + col], lo, hi);
                    low ^= lo;
                    high ^= hi;
                }
                // Reduction is linear: reduce once per output, rather than
                // once per constituent coefficient.
                out[Row] = in[Row] ^ low.gf128Reduce(high);
                local<Row + 1>(in, out);
            }
        }

        template<bool Pair>
        void encode(span<block> a, span<block> b) const
        {
            if (!mN || a.size() != mN || (Pair && b.size() != mN))
                throw std::invalid_argument("Chosen BAA input size does not match configuration.");
            AlignedUnVector<block> scratchA(mN), scratchB;
            if constexpr (Pair)
                scratchB.resize(mN);
            stage<Pair>(a.data(), b.data(), scratchA.data(), scratchB.data(), 1);
            stage<Pair>(scratchA.data(), scratchB.data(), a.data(), b.data(), 0);
            for (u64 i = 0; i < mN / 16; ++i)
            {
                // The output prefix cannot overwrite a future constituent.
                local(a.data() + 16 * i, a.data() + K * i);
                if constexpr (Pair)
                    local(b.data() + 16 * i, b.data() + K * i);
            }
        }

    public:
        void config(u64 n, block seed)
        {
            if (!n || n % 16 || n > std::numeric_limits<u32>::max())
                throw std::invalid_argument("Chosen BAA length must be a positive multiple of 16 fitting u32.");
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
            for (u64 row = 0; row < K; ++row)
            {
                const block x(0, row + 1);
                block denominator = OneBlock;
                for (u64 h = 0; h < K; ++h)
                    if (h != row)
                        denominator = denominator.gf128Mul(x ^ block(0, h + 1));
                const block inv = inverse(denominator);
                for (u64 col = 0; col < 16 - K; ++col)
                {
                    const block point(0, K + col + 1);
                    block numerator = OneBlock;
                    for (u64 h = 0; h < K; ++h)
                        if (h != row)
                            numerator = numerator.gf128Mul(point ^ block(0, h + 1));
                    mMatrix[row * (16 - K) + col] = numerator.gf128Mul(inv);
                }
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
        block matrix(u64 row, u64 col) const { return mMatrix.at(row * (16 - K) + col); }
        void dualEncode(span<block> a) const { encode<false>(a, {}); }
        void dualEncode2(span<block> a, span<block> b) const { encode<true>(a, b); }
    };

    // Keep aligned encoder state and scratch out of the caller's coroutine frame.
    OC_NOINLINE void chosenBaaCompress(MultType type, block seed, span<block> a, span<block> b = {});
    task<> chosenBaaSeed(bool sender, PRNG& prng, Socket& chl, block& seed);
}

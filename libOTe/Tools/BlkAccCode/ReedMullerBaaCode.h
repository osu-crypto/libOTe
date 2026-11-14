#pragma once
#include "ChosenBaaField.h"
#include "cryptoTools/Common/Aligned.h"
#include "libOTe/Tools/CompilerHints.h"
#include <array>
#include <algorithm>
#include <limits>

namespace osuCrypto
{
    // RM(2,5)[32,16,8], followed by two independently permuted plain
    // accumulators. Valid over characteristic-two fields. Extension of the
    // binary generator preserves its minimum Hamming distance exactly.
    // The finite binary certificate is length-specific; see the benchmark note.
    template<typename F = block, typename Field = ChosenBaaField<F>>
    class ReedMullerBaaCode
    {
        u64 mN = 0;
        std::array<AlignedUnVector<u32>, 2> mPerm;
        AlignedUnVector<u32> mInverseFirst;
#if defined(__aarch64__) || defined(_M_ARM64)
        // Native M3 measurements favor the direct scatter/compression path.
        static constexpr bool fusedTranspose = false;
#else
        static constexpr bool fusedTranspose = true;
#endif
        static constexpr std::array<unsigned, 16> monomials{
            0,1,2,3,4,5,6,8,9,10,12,16,17,18,20,24 };

        static u32 below(PRNG& random, u32 bound)
        {
            u64 p = u64(random.get<u32>()) * bound;
            if (u32(p) < bound)
            {
                const auto threshold = (u32(0) - bound) % bound;
                while (u32(p) < threshold) p = u64(random.get<u32>()) * bound;
            }
            return u32(p >> 32);
        }
        template<bool Transpose, unsigned Bit, unsigned I = 0>
        static OC_FORCEINLINE void butterfly(F* v)
        {
            if constexpr (I < 32)
            {
                if constexpr (I & (1u << Bit))
                {
                    if constexpr (Transpose) v[I ^ (1u << Bit)] = Field::add(v[I ^ (1u << Bit)], v[I]);
                    else v[I] = Field::add(v[I], v[I ^ (1u << Bit)]);
                }
                butterfly<Transpose, Bit, I + 1>(v);
            }
        }
        template<bool Transpose, unsigned Bit = 0>
        static OC_FORCEINLINE void transform(F* v)
        {
            // The five tensor factors commute, including after transposition.
            if constexpr (Bit < 5)
            {
                butterfly<Transpose, Bit>(v);
                transform<Transpose, Bit + 1>(v);
            }
        }
        template<unsigned I = 0>
        static OC_FORCEINLINE void loadMessage(const F* in, F* v)
        {
            if constexpr (I < 16) { v[monomials[I]] = in[I]; loadMessage<I + 1>(in, v); }
        }
        template<unsigned I = 0>
        static OC_FORCEINLINE void storeMessage(const F* v, F* out)
        {
            if constexpr (I < 16) { out[I] = v[monomials[I]]; storeMessage<I + 1>(v, out); }
        }
        template<bool Transpose, unsigned J = 0>
        static OC_FORCEINLINE void prefetch(const F* in, F* out, const u32* p)
        {
            if constexpr (J < 16)
            {
#ifdef OC_ENABLE_SSE2
                const F* address = Transpose ? out + p[J] : in + p[J];
                _mm_prefetch(reinterpret_cast<const char*>(address), _MM_HINT_T2);
#endif
                prefetch<Transpose, J + 1>(in, out, p);
            }
        }
        template<unsigned J = 0>
        static OC_FORCEINLINE void gather(const F* in, const u32* p, F* v)
        {
            if constexpr (J < 16) { v[J] = in[p[J]]; gather<J + 1>(in, p, v); }
        }
        template<bool Transpose, unsigned J = 0>
        static OC_FORCEINLINE void accumulate(const F* in, F* out, const u32* p, F& sum)
        {
            if constexpr (J < 16)
            {
                constexpr auto pos = Transpose ? 15 - J : J;
                sum = Field::add(sum, in[pos]);
                if constexpr (Transpose) out[p[pos]] = sum;
                else out[pos] = sum;
                accumulate<Transpose, J + 1>(in, out, p, sum);
            }
        }
        template<bool Transpose>
        void stage(const F* in, F* out, unsigned which) const
        {
            F sum = Field::zero();
            const auto* p = mPerm[which].data();
            for (u64 j = 0; j < mN; j += 16)
            {
                const u64 i = Transpose ? mN - j - 16 : j;
                constexpr u64 lead = 256;
                if (j + lead + 16 <= mN)
                {
                    const u64 ahead = Transpose ? i - lead : i + lead;
                    prefetch<Transpose>(in, out, p + ahead);
                }
                if constexpr (Transpose) accumulate<true>(in + i, out, p + i, sum);
                else
                {
                    std::array<F, 16> v;
                    gather(in, p + i, v.data());
                    accumulate<false>(v.data(), out + i, p + i, sum);
                }
            }
        }
        template<unsigned J = 0>
        static OC_FORCEINLINE void suffixBatch(F* in, F& sum)
        {
            if constexpr (J < 16)
            {
                constexpr unsigned pos = 15 - J;
                in[pos] = sum = Field::add(sum, in[pos]);
                suffixBatch<J + 1>(in, sum);
            }
        }
        void finishTranspose(F* in, F* out) const
        {
            // Separate the contiguous suffix scan from the permutation, then
            // fuse its inverse gather with local compression. This avoids a
            // full random-write pass and an additional read of the codeword.
            F sum = Field::zero();
            for (u64 end = mN; end; end -= 16) suffixBatch(in + end - 16, sum);
            const auto* p = mInverseFirst.data();
            for (u64 i = 0; i < mN; i += 32)
            {
                if (i + 256 + 32 <= mN)
                {
                    prefetch<false>(in, out, p + i + 256);
                    prefetch<false>(in, out, p + i + 272);
                }
                std::array<F, 32> v;
                gather(in, p + i, v.data());
                gather(in, p + i + 16, v.data() + 16);
                localTranspose(v.data(), out + i / 2);
            }
        }
    public:
        void config(u64 n, block seed)
        {
            if (!n || n % 32 || n > std::numeric_limits<u32>::max())
                throw std::invalid_argument("RM BAA length must be a positive multiple of 32 fitting u32.");
            if (Field::add(Field::one(), Field::one()) != Field::zero())
                throw std::invalid_argument("RM BAA requires characteristic two.");
            PRNG master(seed);
            const std::array<block, 2> seeds{master.get<block>(), master.get<block>()};
            for (unsigned s = 0; s < 2; ++s)
            {
                auto& p = mPerm[s]; p.resize(n);
                for (u64 i = 0; i < n; ++i) p[i] = u32(i);
                PRNG random(seeds[s]);
                for (u64 i = n; i > 1; --i) std::swap(p[i - 1], p[below(random, u32(i))]);
            }
            if constexpr (fusedTranspose)
            {
                mInverseFirst.resize(n);
                for (u64 i = 0; i < n; ++i) mInverseFirst[mPerm[0][i]] = u32(i);
            }
            mN = n;
        }
        u64 messageSize() const { return mN / 2; }
        u64 codewordSize() const { return mN; }
        u32 permutationIndex(unsigned stage, u64 i) const
        {
            if (i >= mN) throw std::out_of_range("RM BAA permutation index.");
            return mPerm.at(stage)[i];
        }
        static void localEncode(const F* in, F* out)
        {
            std::array<F, 32> v;
            v.fill(Field::zero()); loadMessage(in, v.data()); transform<false>(v.data());
            std::copy(v.begin(), v.end(), out);
        }
        static void localTranspose(const F* in, F* out)
        {
            std::array<F, 32> v;
            std::copy_n(in, 32, v.data()); transform<true>(v.data()); storeMessage(v.data(), out);
        }
        // Caller-owned, disjoint buffers; no allocation during encoding.
        void encode(span<const F> input, span<F> output, span<F> scratch) const
        {
            if (!mN || input.size() != messageSize() || output.size() != mN || scratch.size() != mN)
                throw std::invalid_argument("RM BAA forward buffer size.");
            for (u64 i = 0; i < mN / 32; ++i) localEncode(input.data() + 16 * i, output.data() + 32 * i);
            stage<false>(output.data(), scratch.data(), 0);
            stage<false>(scratch.data(), output.data(), 1);
        }
        // In place, producing the message-size prefix. Scratch is disjoint.
        void dualEncode(span<F> inOut, span<F> scratch) const
        {
            if (!mN || inOut.size() != mN || scratch.size() != mN)
                throw std::invalid_argument("RM BAA transpose buffer size.");
            stage<true>(inOut.data(), scratch.data(), 1);
            if constexpr (fusedTranspose) finishTranspose(scratch.data(), inOut.data());
            else
            {
                stage<true>(scratch.data(), inOut.data(), 0);
                for (u64 i = 0; i < mN / 32; ++i)
                    localTranspose(inOut.data() + 32 * i, inOut.data() + 16 * i);
            }
        }
    };
}

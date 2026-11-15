#pragma once
#include "ChosenBaaCode.h"
#include <algorithm>
#include "AdditiveRs8.h"
#include "SmallBaaGfni.h"

namespace osuCrypto
{
    template<typename F, typename Field = ChosenBaaField<F>>
    struct SmallBaaArithmetic
    {
        static F madd(F state, u32 coefficient, F input)
        { return Field::add(input, Field::mul(state, Field::point(coefficient - 1))); }
    };
    template<>
    struct SmallBaaArithmetic<block, ChosenBaaField<block>>
    {
        // Polynomial coefficient 1..256 in the canonical GF(2^128) basis.
        // Two independent 64x9 carryless products; the overflow has at most
        // eight bits, so multiplication by x^7+x^2+x+1 cannot overflow again.
        static OC_FORCEINLINE block madd(block state, u32 coefficient, block input)
        {
#if defined(OC_ENABLE_SSE2) && defined(__GFNI__)
            return chosen_baa_detail::smallGfniMadd(state, coefficient, input);
#else
            const block c(0, coefficient);
            const auto lo = state.clmulepi64_si128<0x00>(c);
            const auto hi = state.clmulepi64_si128<0x01>(c);
            const auto overflow = hi.srli_si128<8>();
            return input ^ lo ^ hi.slli_si128<8>() ^ overflow ^
                overflow.slli_epi64(1) ^ overflow.slli_epi64(2) ^ overflow.slli_epi64(7);
#endif
        }
    };

    // [16,8,9] RS followed by two permuted recursive scans. Independent
    // coefficients use 256 distinct nonzero field elements. This is a
    // different map from ChosenBaaCode's full-field weighted accumulators.
    // Packed metadata supports n <= 2^24, with eight coefficient bits.
    template<typename F = block, typename Field = ChosenBaaField<F>,
             typename Arithmetic = SmallBaaArithmetic<F, Field>>
    class SmallAlphabetBaaCode
    {
        static constexpr u32 indexMask = (1u << 24) - 1;
        u64 mN = 0;
        std::array<AlignedUnVector<u32>, 2> mMeta;
        std::array<F, 64> mMatrix, mForward;
        static constexpr bool additiveLocal = std::is_same_v<Field, ChosenBaaField<block>>;
#if defined(OC_ENABLE_SSE2) && defined(OC_ENABLE_VPCLMUL)
        // A short, fully unrolled GF128 recurrence schedules better than sixteen
        // live steps on the measured x86 backends. Other field/backends retain
        // the existing sixteen-element schedule.
        static constexpr unsigned scanBatch = additiveLocal ? 4 : 16;
#else
        static constexpr unsigned scanBatch = 16;
#endif
        chosen_baa_detail::AdditiveRs8 mAdditive;
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
        static void shuffle(AlignedUnVector<u32>& p, PRNG& random)
        {
            constexpr u64 batch = 64;
            std::array<u32, batch> indices;
            u64 i = p.size();
            for (; i > batch; i -= batch)
            {
                // Draw in exactly the scalar Fisher--Yates order, including
                // rejection draws. Only the memory accesses are scheduled ahead.
                for (u64 j = 0; j < batch; ++j)
                {
                    indices[j] = below(random, u32(i - j));
#if defined(__GNUC__) || defined(__clang__)
                    __builtin_prefetch(p.data() + indices[j], 1, 3);
#elif defined(OC_ENABLE_SSE2)
                    _mm_prefetch(reinterpret_cast<const char*>(p.data() + indices[j]), _MM_HINT_T0);
#endif
                }
                // Swaps must stay ordered: sampled indices can coincide or
                // refer to another position in this batch.
                for (u64 j = 0; j < batch; ++j)
                    std::swap(p[i - j - 1], p[indices[j]]);
            }
            for (; i > 1; --i) std::swap(p[i - 1], p[below(random, u32(i))]);
        }
        template<bool Transpose, unsigned J = 0>
        static OC_FORCEINLINE void prefetch(const F* in, F* out, const u32* p)
        {
            if constexpr (J < scanBatch)
            {
#ifdef OC_ENABLE_SSE2
                const F* address = Transpose ? out + (p[J] & indexMask) : in + (p[J] & indexMask);
                _mm_prefetch(reinterpret_cast<const char*>(address), _MM_HINT_T2);
#endif
                prefetch<Transpose, J + 1>(in, out, p);
            }
        }
        template<unsigned J = 0>
        static OC_FORCEINLINE void gather(const F* in, const u32* p, F* values)
        {
            if constexpr (J < scanBatch) { values[J] = in[p[J] & indexMask]; gather<J + 1>(in, p, values); }
        }
        template<unsigned J = 0>
        static OC_FORCEINLINE void forwardBatch(const F* values, F* out, const u32* p, F& sum)
        {
            if constexpr (J < scanBatch)
            {
                out[J] = sum = Arithmetic::madd(sum, (p[J] >> 24) + 1, values[J]);
                forwardBatch<J + 1>(values, out, p, sum);
            }
        }
        template<unsigned J = 0>
        static OC_FORCEINLINE void transposeBatch(const F* in, F* out, const u32* p, F& sum, u32& coefficient)
        {
            if constexpr (J < scanBatch)
            {
                constexpr auto pos = scanBatch - 1 - J;
                sum = Arithmetic::madd(sum, coefficient, in[pos]);
                coefficient = (p[pos] >> 24) + 1;
                out[p[pos] & indexMask] = sum;
                transposeBatch<J + 1>(in, out, p, sum, coefficient);
            }
        }
        template<bool Transpose>
        void stage(const F* in, F* out, unsigned which) const
        {
            const auto* p = mMeta[which].data();
            F sum = Field::zero();
            u32 coefficient = 1;
            for (u64 j = 0; j < mN; j += scanBatch)
            {
                const u64 i = Transpose ? mN - j - scanBatch : j;
                constexpr u64 lead = 256;
                if (j + lead + scanBatch <= mN)
                    prefetch<Transpose>(in, out, p + (Transpose ? i - lead : i + lead));
                if constexpr (Transpose) transposeBatch(in + i, out, p + i, sum, coefficient);
                else
                {
                    std::array<F, scanBatch> values;
                    gather(in, p + i, values.data());
                    forwardBatch(values.data(), out + i, p + i, sum);
                }
            }
        }
    public:
        void config(u64 n, block seed)
        {
            if (!n || n % 16 || n > (1u << 24)) throw std::invalid_argument("Small-alphabet BAA length.");
            // The proof requires distinct nonzero alphabet elements, not
            // integer scalar multiples of one in positive characteristic.
            for (u64 i = 0; i < 256; ++i)
            {
                const F c = Field::point(i);
                if (c == Field::zero()) throw std::invalid_argument("BAA coefficient alphabet contains zero.");
                for (u64 j = 0; j < i; ++j)
                    if (c == Field::point(j)) throw std::invalid_argument("BAA coefficient alphabet repeats.");
            }
            using LocalField = std::conditional_t<additiveLocal, chosen_baa_detail::AdditivePoints, Field>;
            ChosenBaaCode<8, F, LocalField> local;
            local.config(16, seed);
            for (u64 row = 0; row < 8; ++row) for (u64 col = 0; col < 8; ++col)
                mMatrix[col * 8 + row] = mForward[row * 8 + col] = local.matrix(row, col);
            if constexpr (additiveLocal)
            {
                for (u64 i = 0; i < 8; ++i) for (u64 j = 0; j < 8; ++j)
                    if (mMatrix[i * 8 + j] != mMatrix[i ^ j]) throw std::logic_error("Additive RS symmetry.");
                mAdditive.init(mMatrix.data());
            }
            PRNG master(seed);
            const std::array<block, 2> permutationSeeds{master.get<block>(), master.get<block>()};
            const std::array<block, 2> coefficientSeeds{master.get<block>(), master.get<block>()};
            for (unsigned s = 0; s < 2; ++s)
            {
                auto& p = mMeta[s]; p.resize(n);
                for (u64 i = 0; i < n; ++i) p[i] = u32(i);
                PRNG random(permutationSeeds[s]), coefficients(coefficientSeeds[s]);
                shuffle(p, random);
                for (u64 i = 0; i < n; )
                {
                    // Consume the same byte stream in contiguous chunks, so
                    // packing coefficients can vectorize without per-byte PRNG
                    // calls. Consume the view before the next PRNG operation.
                    const auto bytes = coefficients.getBufferSpan(n - i);
                    for (u64 j = 0; j < bytes.size(); ++j)
                        p[i + j] |= u32(bytes[j]) << 24;
                    i += bytes.size();
                }
            }
            mN = n;
        }
        u64 messageSize() const { return mN / 2; }
        u64 codewordSize() const { return mN; }
        u32 metadata(unsigned stage, u64 i) const
        {
            if (i >= mN) throw std::out_of_range("Small-alphabet BAA metadata index.");
            return mMeta.at(stage)[i];
        }
        F matrix(u64 row, u64 col) const
        {
            if (row >= 8 || col >= 8 || !mN) throw std::out_of_range("Small-alphabet BAA matrix index.");
            return mMatrix[col * 8 + row];
        }
        // Caller-owned disjoint buffers. No allocation inside either encoder.
        void encode(span<const F> input, span<F> output, span<F> scratch) const
        {
            if (!mN || input.size() != mN / 2 || output.size() != mN || scratch.size() != mN)
                throw std::invalid_argument("Small-alphabet BAA forward buffer size.");
            for (u64 i = 0; i < mN / 16; ++i)
            {
                const auto* src = input.data() + 8 * i; auto* dst = output.data() + 16 * i;
                std::copy_n(src, 8, dst);
                if constexpr (additiveLocal) mAdditive.apply(src, dst + 8);
                else Field::template localForward<8>(src, dst, mForward.data());
            }
            stage<false>(output.data(), scratch.data(), 0);
            stage<false>(scratch.data(), output.data(), 1);
        }
        void dualEncode(span<F> inOut, span<F> scratch) const
        {
            if (!mN || inOut.size() != mN || scratch.size() != mN)
                throw std::invalid_argument("Small-alphabet BAA transpose buffer size.");
            stage<true>(inOut.data(), scratch.data(), 1);
            stage<true>(scratch.data(), inOut.data(), 0);
            for (u64 i = 0; i < mN / 16; ++i)
            {
                if constexpr (additiveLocal)
                {
                    std::array<block, 8> values;
                    mAdditive.apply(inOut.data() + 16 * i + 8, values.data());
                    for (u64 j = 0; j < 8; ++j) inOut[8 * i + j] = inOut[16 * i + j] ^ values[j];
                }
                else Field::template local<8>(inOut.data() + 16 * i, inOut.data() + 8 * i, mMatrix.data());
            }
        }
    };
}

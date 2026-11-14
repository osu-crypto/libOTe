#pragma once
#include "ChosenBaaField.h"
#include "cryptoTools/Common/Aligned.h"
#include <array>
#include <algorithm>
#include <limits>

namespace osuCrypto::chosen_baa_detail
{
    // Extended Newton [16,8]: y[t]=sum_j binom(t,j)x[j] for t<15,
    // y[15]=x[7], followed by two independently permuted plain scans.
    // This generic arithmetic backend shares the Fp reference's linear map.
    // The optimized AVX-512 Fp128 reference remains a separate benchmark.
    template<typename F, typename Field>
    class NewtonBaaCode
    {
        u64 mN = 0;
        std::array<AlignedUnVector<u32>, 2> mPerm;

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
        template<unsigned T = 0>
        static OC_FORCEINLINE void forwardLocal(F* v, F* out)
        {
            if constexpr (T < 15)
            {
                out[T] = v[0];
                if constexpr (T < 14)
                {
                    // Increasing order consumes the previous difference level.
                    updateForward<0, (14 - T < 7 ? 14 - T : 7)>(v);
                    forwardLocal<T + 1>(v, out);
                }
            }
        }
        template<unsigned J, unsigned Count>
        static OC_FORCEINLINE void updateForward(F* v)
        {
            if constexpr (J < Count)
            {
                v[J] = Field::add(v[J], v[J + 1]);
                updateForward<J + 1, Count>(v);
            }
        }
        template<unsigned Count>
        static OC_FORCEINLINE void updateTranspose(F* v)
        {
            if constexpr (Count)
            {
                v[Count] = Field::add(v[Count], v[Count - 1]);
                updateTranspose<Count - 1>(v);
            }
        }
        template<unsigned T = 14>
        static OC_FORCEINLINE void transposeLocal(const F* in, F* v)
        {
            v[0] = Field::add(v[0], in[T]);
            if constexpr (T)
            {
                updateTranspose<(15 - T < 7 ? 15 - T : 7)>(v);
                transposeLocal<T - 1>(in, v);
            }
        }
        template<bool Transpose, unsigned J = 0>
        static OC_FORCEINLINE void batch(const F* in, F* out, const u32* p, F& sum)
        {
            if constexpr (J < 16)
            {
                constexpr unsigned pos = Transpose ? 15 - J : J;
                if constexpr (Transpose)
                    out[p[pos]] = sum = Field::add(sum, in[pos]);
                else out[pos] = sum = Field::add(sum, in[p[pos]]);
                batch<Transpose, J + 1>(in, out, p, sum);
            }
        }
        template<bool Transpose>
        void stage(const F* in, F* out, unsigned which) const
        {
            F sum = Field::zero();
            for (u64 j = 0; j < mN; j += 16)
            {
                const u64 i = Transpose ? mN - j - 16 : j;
                if constexpr (Transpose) batch<true>(in + i, out, mPerm[which].data() + i, sum);
                else batch<false>(in, out + i, mPerm[which].data() + i, sum);
            }
        }
    public:
        void config(u64 n, block seed)
        {
            if (!n || n % 16 || n > std::numeric_limits<u32>::max())
                throw std::invalid_argument("ChosenBaa10 prime-field length.");
            // The extended Newton constituent needs characteristic >14.
            F value = Field::zero();
            for (unsigned i = 1; i <= 14; ++i)
            {
                value = Field::add(value, Field::one());
                if (value == Field::zero())
                    throw std::invalid_argument("ChosenBaa10 Newton backend requires characteristic >14.");
            }
            PRNG master(seed);
            const std::array<block, 2> seeds{master.get<block>(), master.get<block>()};
            for (unsigned s = 0; s < 2; ++s)
            {
                auto& p = mPerm[s]; p.resize(n);
                for (u64 i = 0; i < n; ++i) p[i] = u32(i);
                PRNG random(seeds[s]);
                for (u64 i = n; i > 1; --i) std::swap(p[i - 1], p[below(random, u32(i))]);
            }
            mN = n;
        }
        u64 messageSize() const { return mN / 2; }
        u64 codewordSize() const { return mN; }
        u32 permutationIndex(unsigned stage, u64 i) const
        {
            if (i >= mN) throw std::out_of_range("ChosenBaa10 permutation index.");
            return mPerm.at(stage)[i];
        }
        static void localEncode(const F* in, F* out)
        {
            std::array<F, 8> v;
            std::copy_n(in, 8, v.data());
            out[15] = v[7]; forwardLocal(v.data(), out);
        }
        static void localTranspose(const F* in, F* out)
        {
            std::array<F, 8> v; v.fill(Field::zero()); v[7] = in[15];
            transposeLocal(in, v.data()); std::copy(v.begin(), v.end(), out);
        }
        void encode(span<const F> input, span<F> output, span<F> scratch) const
        {
            if (!mN || input.size() != mN / 2 || output.size() != mN || scratch.size() != mN)
                throw std::invalid_argument("ChosenBaa10 forward buffer size.");
            for (u64 i = 0; i < mN; i += 16) localEncode(input.data() + i / 2, output.data() + i);
            stage<false>(output.data(), scratch.data(), 0);
            stage<false>(scratch.data(), output.data(), 1);
        }
        void dualEncode(span<F> inOut, span<F> scratch) const
        {
            if (!mN || inOut.size() != mN || scratch.size() != mN)
                throw std::invalid_argument("ChosenBaa10 transpose buffer size.");
            stage<true>(inOut.data(), scratch.data(), 1);
            stage<true>(scratch.data(), inOut.data(), 0);
            for (u64 i = 0; i < mN; i += 16) localTranspose(inOut.data() + i, inOut.data() + i / 2);
        }
    };
}

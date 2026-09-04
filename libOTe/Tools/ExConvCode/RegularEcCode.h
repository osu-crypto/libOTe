// © 2026 Peter Rindal.
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

#pragma once

#include "cryptoTools/Common/Aligned.h"
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Crypto/PRNG.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <type_traits>
#include <utility>
#include <vector>

namespace osuCrypto
{
    // The transpose encoder for the two-sided-regular expand-convolute code.
    //
    // The row encoder is x -> x B C, where B has LeftDegree nonzero entries
    // per row and RightDegree nonzero entries per column. The n columns of B
    // are divided into LeftDegree equal regions. An independent permutation of
    // the k rows assigns one entry per row in each region.
    //
    // The wrapped convolution has all-zero initial state and recurrence
    //
    //   y[t] = u[t] + y[t - Memory]
    //        + sum_{j=1}^{Memory-1} b[t,j] y[t-j].
    //
    // Out-of-range terms are omitted. "Wrapped" refers to fixing the oldest
    // tap to one; the time index does not wrap around. dualEncode computes
    // (B C) e and therefore applies C in a reverse sweep before applying B.
    template<u64 LeftDegree, u64 Memory>
    class RegularEcCode
    {
        static_assert(LeftDegree > 0, "the left degree must be positive");
        static_assert(Memory > 0, "the convolution memory must be positive");

        static constexpr u64 CoefficientBytes = (Memory - 1 + 7) / 8;

    public:
        u64 mMessageSize = 0;
        u64 mCodeSize = 0;
        u64 mRegionSize = 0;
        u64 mRightDegree = 0;
        block mSeed = ZeroBlock;

        void config(
            u64 messageSize,
            u64 codeSize,
            block seed = block(33333, 33333))
        {
            if (messageSize == 0 || codeSize == 0)
                throw std::invalid_argument(
                    "Regular EC dimensions must be nonzero. " LOCATION);
            if (messageSize >= codeSize)
                throw std::invalid_argument(
                    "Regular EC message size must be smaller than its code size. " LOCATION);
            if (codeSize % LeftDegree)
                throw std::invalid_argument(
                    "Regular EC code size must be divisible by its left degree. " LOCATION);

            const u64 regionSize = codeSize / LeftDegree;
            if (messageSize % regionSize)
                throw std::invalid_argument(
                    "Regular EC dimensions do not give an integral right degree. " LOCATION);
            const u64 rightDegree = messageSize / regionSize;
            if (rightDegree == 0)
                throw std::invalid_argument(
                    "Regular EC right degree must be positive. " LOCATION);
            if ((rightDegree & 1) == 0)
                throw std::invalid_argument(
                    "Binary regular EC requires an odd right degree. " LOCATION);
            if (messageSize > std::numeric_limits<u32>::max() ||
                codeSize > std::numeric_limits<u32>::max())
                throw std::invalid_argument(
                    "Regular EC currently uses 32-bit expander indices. " LOCATION);
            if (Memory >= codeSize)
                throw std::invalid_argument(
                    "Regular EC convolution memory must be smaller than the code size. " LOCATION);
            if (messageSize > std::numeric_limits<u64>::max() / LeftDegree)
                throw std::length_error(
                    "Regular EC neighbor table size overflows. " LOCATION);
            if constexpr (CoefficientBytes != 0)
            {
                if (codeSize > std::numeric_limits<u64>::max() / CoefficientBytes)
                    throw std::length_error(
                        "Regular EC coefficient table size overflows. " LOCATION);
            }

            AlignedUnVector<u32> regionNeighbors(
                messageSize * (LeftDegree - 1));
            AlignedUnVector<u32> assignment(messageSize);
            u64 position = 0;
            for (u64 right = 0; right != regionSize; ++right)
            {
                for (u64 edge = 0; edge != rightDegree; ++edge)
                    assignment[position++] = static_cast<u32>(right);
            }

            PRNG expanderPrng(seed ^ block(0x3f2a910d8b27c465ull,
                                           0x91e07c56a43db82full));
            // A global permutation of the left vertices only reorders the
            // generator rows. Fix the first region to the canonical grouping
            // and sample the remaining relative permutations independently.
            for (u64 region = 1; region != LeftDegree; ++region)
            {
                // Shuffling the repeated right indices directly samples the
                // same balanced assignment as shuffling all left positions
                // and then discarding order within each right-degree group.
                shuffle(assignment, expanderPrng);
                std::copy(
                    assignment.begin(),
                    assignment.end(),
                    regionNeighbors.begin() + (region - 1) * messageSize);
            }

            AlignedUnVector<u8> coefficients;
            if constexpr (CoefficientBytes != 0)
            {
                coefficients.resize(codeSize * CoefficientBytes);
                PRNG coefficientPrng(seed ^ block(0xc682f7615d49a03bull,
                                                  0x27bd149e60f35ca8ull));
                coefficientPrng.get(coefficients.data(), coefficients.size());

            }

            mMessageSize = messageSize;
            mCodeSize = codeSize;
            mRegionSize = regionSize;
            mRightDegree = rightDegree;
            mSeed = seed;
            mRegionNeighbors = std::move(regionNeighbors);
            mCoefficients = std::move(coefficients);
        }

        static constexpr u64 leftDegree() { return LeftDegree; }
        static constexpr u64 memory() { return Memory; }
        u64 rightDegree() const { return mRightDegree; }

        u64 rightAt(u64 region, u64 left) const
        {
            if (region >= LeftDegree || left >= mMessageSize)
                throw std::out_of_range(
                    "Regular EC neighbor index is out of range. " LOCATION);
            if (region == 0)
                return left / mRightDegree;
            return region * mRegionSize +
                mRegionNeighbors[(region - 1) * mMessageSize + left];
        }

        bool randomCoefficient(u64 time, u64 lag) const
        {
            if (time >= mCodeSize || lag == 0 || lag >= Memory)
                throw std::out_of_range(
                    "Regular EC convolution coefficient is out of range. " LOCATION);
            return randomCoefficientUnchecked(time, lag);
        }

        template<typename F, typename Ctx>
        void dualConvolve(span<F> e, Ctx ctx) const
        {
            if (mCodeSize == 0 || e.size() != mCodeSize)
                throw std::invalid_argument(
                    "Regular EC convolution buffer has the wrong size. " LOCATION);
            convolveTranspose<F>(e.data(), ctx);
        }

        template<typename F, typename Ctx>
        void dualExpand(span<F> e, span<F> w, Ctx ctx) const
        {
            checkEncodeSizes(e.size(), w.size());
            expandTranspose<F>(e.data(), w.data(), ctx);
        }

        template<typename F, typename Ctx>
        void dualEncode(span<F> e, span<F> w, Ctx ctx) const
        {
            checkEncodeSizes(e.size(), w.size());
            convolveTranspose<F>(e.data(), ctx);
            expandTranspose<F>(e.data(), w.data(), ctx);
        }

        template<typename F, typename Ctx, typename Iter>
        void dualEncode(Iter e, Ctx ctx) const
        {
            if (mCodeSize == 0)
                throw std::runtime_error("Regular EC is not configured. " LOCATION);

            span<F> input(e, e + mCodeSize);
            typename Ctx::template Vec<F> output;
            ctx.resize(output, mMessageSize);
            dualEncode<F>(input, span<F>(output.data(), output.size()), ctx);
            ctx.copy(output.begin(), output.end(), e);
        }

        template<typename F0, typename F1, typename Ctx>
        void dualEncode2(
            span<F0> e0,
            span<F0> w0,
            span<F1> e1,
            span<F1> w1,
            Ctx ctx) const
        {
            checkEncodeSizes(e0.size(), w0.size());
            checkEncodeSizes(e1.size(), w1.size());
            convolveTranspose<F0>(e0.data(), ctx);
            convolveTranspose<F1>(e1.data(), ctx);
            expandTranspose<F0>(e0.data(), w0.data(), ctx);
            expandTranspose<F1>(e1.data(), w1.data(), ctx);
        }

        template<
            typename F0,
            typename F1,
            typename Ctx,
            typename Iter0,
            typename Iter1>
        void dualEncode2(Iter0 e0, Iter1 e1, Ctx ctx) const
        {
            if (mCodeSize == 0)
                throw std::runtime_error("Regular EC is not configured. " LOCATION);

            typename Ctx::template Vec<F0> output0;
            typename Ctx::template Vec<F1> output1;
            ctx.resize(output0, mMessageSize);
            ctx.resize(output1, mMessageSize);

            dualEncode2<F0, F1>(
                span<F0>(e0, e0 + mCodeSize),
                span<F0>(output0.data(), output0.size()),
                span<F1>(e1, e1 + mCodeSize),
                span<F1>(output1.data(), output1.size()),
                ctx);
            ctx.copy(output0.begin(), output0.end(), e0);
            ctx.copy(output1.begin(), output1.end(), e1);
        }

    private:
        AlignedUnVector<u32> mRegionNeighbors;
        AlignedUnVector<u8> mCoefficients;

        static OC_FORCEINLINE u64 multiplyHigh(u64 lhs, u64 rhs)
        {
#if defined(__SIZEOF_INT128__) || (defined(_MSC_VER) && defined(_WIN64))
            return mod64(lhs, rhs);
#else
            const u64 lhsLow = static_cast<u32>(lhs);
            const u64 lhsHigh = lhs >> 32;
            const u64 rhsLow = static_cast<u32>(rhs);
            const u64 rhsHigh = rhs >> 32;
            const u64 lowLow = lhsLow * rhsLow;
            const u64 highLow = lhsHigh * rhsLow;
            const u64 lowHigh = lhsLow * rhsHigh;
            const u64 highHigh = lhsHigh * rhsHigh;
            const u64 middle = (lowLow >> 32) +
                static_cast<u32>(highLow) + static_cast<u32>(lowHigh);
            return highHigh + (highLow >> 32) + (lowHigh >> 32) +
                (middle >> 32);
#endif
        }

        static OC_FORCEINLINE u64 sampleBelow(PRNG& prng, u64 bound)
        {
            u64 sample = prng.get<u64>();
            u64 low = sample * bound;
            if (low < bound)
            {
                const u64 threshold = (u64{ 0 } - bound) % bound;
                while (low < threshold)
                {
                    sample = prng.get<u64>();
                    low = sample * bound;
                }
            }
            return multiplyHigh(sample, bound);
        }

        static void shuffle(AlignedUnVector<u32>& permutation, PRNG& prng)
        {
            // Spell out Fisher--Yates instead of using std::shuffle. The
            // standard library does not specify how a random engine is mapped
            // to permutations, but sender and receiver must derive the same B.
            u64 remaining = permutation.size();
            while (remaining > 1)
            {
                const u64 requested = (remaining - 1) * sizeof(u64);
                const auto randomBytes = prng.getBufferSpan(requested);
                const u64 samples = randomBytes.size() / sizeof(u64);
                bool discardedTail = false;
                for (u64 index = 0; index != samples && remaining > 1; ++index)
                {
                    u64 sample;
                    std::memcpy(
                        &sample,
                        randomBytes.data() + index * sizeof(u64),
                        sizeof(sample));

                    const u64 low = sample * remaining;
                    u64 selected;
                    if (low < remaining &&
                        low < (u64{ 0 } - remaining) % remaining)
                    {
                        selected = sampleBelow(prng, remaining);
                        discardedTail = true;
                    }
                    else
                    {
                        selected = multiplyHigh(sample, remaining);
                    }

                    std::swap(permutation[remaining - 1], permutation[selected]);
                    --remaining;
                    if (discardedTail)
                        break;
                }
            }
        }

        void checkEncodeSizes(u64 inputSize, u64 outputSize) const
        {
            if (mCodeSize == 0)
                throw std::runtime_error("Regular EC is not configured. " LOCATION);
            if (inputSize != mCodeSize || outputSize != mMessageSize)
                throw std::invalid_argument(
                    "Regular EC encode buffer has the wrong size. " LOCATION);
        }

        OC_FORCEINLINE bool randomCoefficientUnchecked(u64 time, u64 lag) const
        {
            const u64 bit = lag - 1;
            return (mCoefficients[time * CoefficientBytes + bit / 8] >>
                    (bit & 7)) & 1;
        }

        template<u64 Lag = 1, bool CheckRange = true, typename F, typename Ctx>
        OC_FORCEINLINE void addRandomTaps(F* __restrict x, u64 time, Ctx& ctx) const
        {
            if constexpr (Lag < Memory)
            {
                if constexpr (!CheckRange)
                {
                    const bool coefficient = randomCoefficientUnchecked(time, Lag);
                    if constexpr (std::is_same_v<std::remove_cv_t<F>, block>)
                    {
                        // A block carries 128 independent binary encodings.
                        // Avoid an unpredictable branch for every random tap.
                        x[time - Lag] ^= x[time] & block::allSame<bool>(coefficient);
                    }
                    else if (coefficient)
                    {
                        ctx.plus(x[time - Lag], x[time - Lag], x[time]);
                    }
                }
                else if (time >= Lag)
                {
                    const bool coefficient = randomCoefficientUnchecked(time, Lag);
                    if constexpr (std::is_same_v<std::remove_cv_t<F>, block>)
                    {
                        x[time - Lag] ^= x[time] & block::allSame<bool>(coefficient);
                    }
                    else if (coefficient)
                    {
                        ctx.plus(x[time - Lag], x[time - Lag], x[time]);
                    }
                }
                addRandomTaps<Lag + 1, CheckRange>(x, time, ctx);
            }
        }

        template<u64 Lag = 1, bool CheckRange = true>
        OC_FORCEINLINE void addPackedBlockTaps(
            block* __restrict x,
            u64 time,
            block value,
            u64 coefficients) const
        {
            if constexpr (Lag < Memory)
            {
                if constexpr (!CheckRange)
                {
                    x[time - Lag] ^=
                        value & block::allSame<bool>(coefficients & 1);
                }
                else if (time >= Lag)
                {
                    x[time - Lag] ^=
                        value & block::allSame<bool>(coefficients & 1);
                }
                addPackedBlockTaps<Lag + 1, CheckRange>(
                    x, time, value, coefficients >> 1);
            }
        }

        template<u64 Lag = 1, bool CheckRange = true>
        OC_FORCEINLINE void addPackedByteTaps(
            u8* __restrict x,
            u64 time,
            u8 value,
            u64 coefficients) const
        {
            if constexpr (Lag < Memory)
            {
                if constexpr (!CheckRange)
                {
                    const u8 mask =
                        u8{ 0 } - static_cast<u8>(coefficients & 1);
                    x[time - Lag] ^= value & mask;
                }
                else if (time >= Lag)
                {
                    const u8 mask =
                        u8{ 0 } - static_cast<u8>(coefficients & 1);
                    x[time - Lag] ^= value & mask;
                }
                addPackedByteTaps<Lag + 1, CheckRange>(
                    x, time, value, coefficients >> 1);
            }
        }

        OC_FORCEINLINE u64 packedCoefficients(u64 time) const
        {
            static_assert(CoefficientBytes <= sizeof(u64));
            u64 coefficients = 0;
            if constexpr (CoefficientBytes != 0)
            {
                std::memcpy(
                    &coefficients,
                    mCoefficients.data() + time * CoefficientBytes,
                    CoefficientBytes);
            }
            return coefficients;
        }

        template<typename F, typename Ctx>
        void convolveTranspose(F* __restrict x, Ctx ctx) const
        {
            u64 time = mCodeSize;
            while (time > Memory)
            {
                --time;
                if constexpr (
                    std::is_same_v<std::remove_cv_t<F>, block> &&
                    CoefficientBytes <= sizeof(u64))
                {
                    addPackedBlockTaps<1, false>(
                        x, time, x[time], packedCoefficients(time));
                }
                else if constexpr (
                    std::is_same_v<std::remove_cv_t<F>, u8> &&
                    CoefficientBytes <= sizeof(u64))
                {
                    addPackedByteTaps<1, false>(
                        x, time, x[time], packedCoefficients(time));
                }
                else
                {
                    addRandomTaps<1, false>(x, time, ctx);
                }
                ctx.plus(x[time - Memory], x[time - Memory], x[time]);
            }
            while (time-- > 0)
            {
                if constexpr (
                    std::is_same_v<std::remove_cv_t<F>, block> &&
                    CoefficientBytes <= sizeof(u64))
                {
                    addPackedBlockTaps<1, true>(
                        x, time, x[time], packedCoefficients(time));
                }
                else if constexpr (
                    std::is_same_v<std::remove_cv_t<F>, u8> &&
                    CoefficientBytes <= sizeof(u64))
                {
                    addPackedByteTaps<1, true>(
                        x, time, x[time], packedCoefficients(time));
                }
                else
                {
                    addRandomTaps<1, true>(x, time, ctx);
                }
            }
        }

        template<typename F, typename Ctx>
        void expandTranspose(
            const F* __restrict input,
            F* __restrict output,
            Ctx ctx) const
        {
            const F* __restrict firstRegion = input;
            F* __restrict firstOutput = output;
            if constexpr (std::is_same_v<std::remove_cv_t<F>, block>)
            {
                if (mRightDegree == 5)
                {
                    for (u64 right = 0; right != mRegionSize; ++right)
                    {
                        const block value = firstRegion[right];
                        firstOutput[0] = value;
                        firstOutput[1] = value;
                        firstOutput[2] = value;
                        firstOutput[3] = value;
                        firstOutput[4] = value;
                        firstOutput += 5;
                    }
                }
                else
                {
                    for (u64 right = 0; right != mRegionSize; ++right)
                    {
                        const F& value = firstRegion[right];
                        for (u64 edge = 0; edge != mRightDegree; ++edge)
                            ctx.copy(*firstOutput++, value);
                    }
                }
            }
            else
            {
                for (u64 right = 0; right != mRegionSize; ++right)
                {
                    const F& value = firstRegion[right];
                    for (u64 edge = 0; edge != mRightDegree; ++edge)
                        ctx.copy(*firstOutput++, value);
                }
            }

            const u32* __restrict neighbor = mRegionNeighbors.data();
            for (u64 region = 1; region != LeftDegree; ++region)
            {
                const F* __restrict regionInput = input + region * mRegionSize;
                for (u64 left = 0; left != mMessageSize; ++left)
                {
                    const F& value = regionInput[*neighbor++];
                    if constexpr (std::is_same_v<std::remove_cv_t<F>, block>)
                        output[left] ^= value;
                    else
                        ctx.plus(output[left], output[left], value);
                }
            }
        }
    };
}

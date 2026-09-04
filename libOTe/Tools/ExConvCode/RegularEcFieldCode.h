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
#include "libOTe/Tools/CoeffCtx.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <utility>

namespace osuCrypto
{
    // Direct implementation of the finite-field two-sided-regular EC
    // ensemble. Each region is a uniform balanced
    // assignment of the left vertices, every edge has an independent
    // nonzero field label, and every convolution tap is sampled from the full
    // field. A public seed expands these choices pseudorandomly.
    //
    // This implementation materializes the balanced regional assignments,
    // edge labels, and convolution taps. It is the structurally faithful
    // reference, not the low-memory path.
    template<u64 LeftDegree, u64 Memory, typename Scalar>
    class RegularEcFieldCode
    {
        static_assert(LeftDegree > 0, "the left degree must be positive");
        static_assert(Memory > 0, "the convolution memory must be positive");

        static constexpr u64 ExpanderDomain = 0x3f2a910d8b27c465ull;
        static constexpr u64 LabelDomain = 0x2ed29b1684cc73a5ull;
        static constexpr u64 CoefficientDomain = 0xb8a9471653d04ea3ull;

    public:
        u64 mMessageSize = 0;
        u64 mCodeSize = 0;
        u64 mRegionSize = 0;
        u64 mRightDegree = 0;
        block mSeed = ZeroBlock;

        template<typename Ctx>
        void config(u64 messageSize, u64 codeSize, block seed, const Ctx& ctx)
        {
            if (messageSize == 0 || codeSize == 0)
                throw std::invalid_argument(
                    "Regular EC field dimensions must be nonzero. " LOCATION);
            if (messageSize >= codeSize)
                throw std::invalid_argument(
                    "Regular EC field message size must be smaller than its code size. " LOCATION);
            if (codeSize % LeftDegree)
                throw std::invalid_argument(
                    "Regular EC field code size must be divisible by its left degree. " LOCATION);

            const u64 regionSize = codeSize / LeftDegree;
            if (messageSize % regionSize)
                throw std::invalid_argument(
                    "Regular EC field dimensions do not give an integral right degree. " LOCATION);
            const u64 rightDegree = messageSize / regionSize;
            if (rightDegree == 0)
                throw std::invalid_argument(
                    "Regular EC field right degree must be positive. " LOCATION);
            if (messageSize > std::numeric_limits<u32>::max() ||
                codeSize > std::numeric_limits<u32>::max())
                throw std::invalid_argument(
                    "Regular EC field code currently uses 32-bit expander indices. " LOCATION);
            if (Memory >= codeSize)
                throw std::invalid_argument(
                    "Regular EC field convolution memory must be smaller than the code size. " LOCATION);
            if (!ctx.template isField<Scalar>())
                throw std::invalid_argument(
                    "Regular EC field code requires a field-valued scalar context. " LOCATION);
            if (LeftDegree > 1 &&
                messageSize > std::numeric_limits<u64>::max() / (LeftDegree - 1))
                throw std::length_error(
                    "Regular EC field neighbor table size overflows. " LOCATION);
            if (messageSize > std::numeric_limits<u64>::max() / LeftDegree)
                throw std::length_error(
                    "Regular EC field edge-label table size overflows. " LOCATION);
            if (codeSize > std::numeric_limits<u64>::max() / Memory)
                throw std::length_error(
                    "Regular EC field coefficient table size overflows. " LOCATION);

            AlignedUnVector<u32> regionNeighbors(
                messageSize * (LeftDegree - 1));
            AlignedUnVector<u32> assignment(messageSize);
            u64 position = 0;
            for (u64 right = 0; right != regionSize; ++right)
            {
                for (u64 slot = 0; slot != rightDegree; ++slot)
                    assignment[position++] = static_cast<u32>(right);
            }

            PRNG expanderPrng(seed ^ block(
                ExpanderDomain, 0x91e07c56a43db82full));
            // A common permutation of the left vertices only reorders the
            // generator rows. Fix the first region and sample the remaining
            // relative balanced assignments independently.
            for (u64 region = 1; region != LeftDegree; ++region)
            {
                shuffle(assignment, expanderPrng);
                std::copy(
                    assignment.begin(), assignment.end(),
                    regionNeighbors.begin() + (region - 1) * messageSize);
            }

            AlignedUnVector<Scalar> edgeLabels(messageSize * LeftDegree);
            PRNG labelPrng(seed ^ block(
                LabelDomain, 0xa4aba1c3d0921f6bull));
            Scalar zero;
            ctx.zero(zero);
            for (auto& label : edgeLabels)
            {
                do
                    ctx.fromBlock(label, labelPrng.get<block>());
                while (ctx.eq(label, zero));
            }

            AlignedUnVector<Scalar> coefficients(codeSize * Memory);
            PRNG coefficientPrng(seed ^ block(
                CoefficientDomain, 0xc682f7615d49a03bull));
            for (auto& coefficient : coefficients)
                ctx.fromBlock(coefficient, coefficientPrng.get<block>());

            mMessageSize = messageSize;
            mCodeSize = codeSize;
            mRegionSize = regionSize;
            mRightDegree = rightDegree;
            mSeed = seed;
            mRegionNeighbors = std::move(regionNeighbors);
            mEdgeLabels = std::move(edgeLabels);
            mCoefficients = std::move(coefficients);
        }

        static constexpr u64 leftDegree() { return LeftDegree; }
        static constexpr u64 memory() { return Memory; }
        u64 rightDegree() const { return mRightDegree; }
        u64 scheduleBytes() const
        {
            return sizeof(*this) +
                mRegionNeighbors.capacity() * sizeof(u32) +
                mEdgeLabels.capacity() * sizeof(Scalar) +
                mCoefficients.capacity() * sizeof(Scalar);
        }

        u64 rightAt(u64 region, u64 left) const
        {
            checkEdgeIndex(region, left);
            if (region == 0)
                return left / mRightDegree;
            return region * mRegionSize +
                mRegionNeighbors[(region - 1) * mMessageSize + left];
        }

        template<typename Ctx>
        Scalar edgeLabel(u64 region, u64 left, const Ctx&) const
        {
            checkEdgeIndex(region, left);
            return edgeLabelUnchecked(region, left);
        }

        template<typename Ctx>
        Scalar feedbackCoefficient(u64 time, u64 lag, const Ctx&) const
        {
            if (time >= mCodeSize || lag == 0 || lag > Memory)
                throw std::out_of_range(
                    "Regular EC field convolution coefficient is out of range. " LOCATION);
            return mCoefficients[time * Memory + lag - 1];
        }

        template<typename F, typename Ctx>
        void dualConvolve(span<F> input, Ctx ctx) const
        {
            if (mCodeSize == 0 || input.size() != mCodeSize)
                throw std::invalid_argument(
                    "Regular EC field convolution buffer has the wrong size. " LOCATION);
            convolveTranspose(input.data(), ctx);
        }

        template<typename F, typename Ctx>
        void dualExpand(span<const F> input, span<F> output, Ctx ctx) const
        {
            checkEncodeSizes(input.size(), output.size());
            expandTranspose(input.data(), output.data(), ctx);
        }

        template<typename F, typename Ctx>
        void dualEncode(span<F> input, span<F> output, Ctx ctx) const
        {
            checkEncodeSizes(input.size(), output.size());
            convolveTranspose(input.data(), ctx);
            expandTranspose(input.data(), output.data(), ctx);
        }

        template<typename F, typename Ctx, typename Iter>
        void dualEncode(Iter input, Ctx ctx) const
        {
            if (mCodeSize == 0)
                throw std::runtime_error(
                    "Regular EC field code is not configured. " LOCATION);
            typename Ctx::template Vec<F> output;
            ctx.resize(output, mMessageSize);
            dualEncode<F>(
                span<F>(&*input, mCodeSize),
                span<F>(output.data(), output.size()), ctx);
            ctx.copy(output.begin(), output.end(), input);
        }

        template<typename F0, typename F1, typename Ctx, typename Iter0, typename Iter1>
        void dualEncode2(Iter0 input0, Iter1 input1, Ctx ctx) const
        {
            if (mCodeSize == 0)
                throw std::runtime_error(
                    "Regular EC field code is not configured. " LOCATION);
            typename Ctx::template Vec<F0> output0;
            typename Ctx::template Vec<F1> output1;
            ctx.resize(output0, mMessageSize);
            ctx.resize(output1, mMessageSize);
            convolveTranspose2(&*input0, &*input1, ctx);
            expandTranspose2(
                &*input0, output0.data(), &*input1, output1.data(), ctx);
            ctx.copy(output0.begin(), output0.end(), input0);
            ctx.copy(output1.begin(), output1.end(), input1);
        }

    private:
        AlignedUnVector<u32> mRegionNeighbors;
        AlignedUnVector<Scalar> mEdgeLabels;
        AlignedUnVector<Scalar> mCoefficients;

        OC_FORCEINLINE const Scalar& edgeLabelUnchecked(
            u64 region, u64 left) const
        {
            return mEdgeLabels[region * mMessageSize + left];
        }

        void checkEdgeIndex(u64 region, u64 left) const
        {
            if (region >= LeftDegree || left >= mMessageSize)
                throw std::out_of_range(
                    "Regular EC field neighbor index is out of range. " LOCATION);
        }

        void checkEncodeSizes(u64 inputSize, u64 outputSize) const
        {
            if (mCodeSize == 0)
                throw std::runtime_error(
                    "Regular EC field code is not configured. " LOCATION);
            if (inputSize != mCodeSize || outputSize != mMessageSize)
                throw std::invalid_argument(
                    "Regular EC field encode buffer has the wrong size. " LOCATION);
        }

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

        static void shuffle(AlignedUnVector<u32>& assignment, PRNG& prng)
        {
            u64 remaining = assignment.size();
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
                    std::swap(assignment[remaining - 1], assignment[selected]);
                    --remaining;
                    if (discardedTail)
                        break;
                }
            }
        }

        template<typename Ctx>
        OC_FORCEINLINE void coefficientsAtTime(
            u64 time,
            std::array<Scalar, Memory>& coefficients,
            const Ctx& ctx) const
        {
            const Scalar* __restrict source =
                mCoefficients.data() + time * Memory;
            for (u64 offset = 0; offset != Memory; ++offset)
                ctx.copy(coefficients[offset], source[offset]);
        }

        template<u64 Lag = 1, bool CheckRange = true, typename F, typename Ctx>
        OC_FORCEINLINE void addRandomTaps(
            F* __restrict input,
            u64 time,
            const std::array<Scalar, Memory>& coefficients,
            Ctx& ctx) const
        {
            if constexpr (Lag <= Memory)
            {
                if constexpr (!CheckRange)
                {
                    F product;
                    ctx.mul(product, input[time], coefficients[Lag - 1]);
                    ctx.plus(input[time - Lag], input[time - Lag], product);
                }
                else if (time >= Lag)
                {
                    F product;
                    ctx.mul(product, input[time], coefficients[Lag - 1]);
                    ctx.plus(input[time - Lag], input[time - Lag], product);
                }
                addRandomTaps<Lag + 1, CheckRange>(
                    input, time, coefficients, ctx);
            }
        }

        template<u64 Lag = 1, bool CheckRange = true,
            typename F0, typename F1, typename Ctx>
        OC_FORCEINLINE void addRandomTaps2(
            F0* __restrict input0,
            F1* __restrict input1,
            u64 time,
            const std::array<Scalar, Memory>& coefficients,
            Ctx& ctx) const
        {
            if constexpr (Lag <= Memory)
            {
                if constexpr (!CheckRange)
                {
                    F0 product0;
                    F1 product1;
                    ctx.mul(product0, input0[time], coefficients[Lag - 1]);
                    ctx.mul(product1, input1[time], coefficients[Lag - 1]);
                    ctx.plus(input0[time - Lag], input0[time - Lag], product0);
                    ctx.plus(input1[time - Lag], input1[time - Lag], product1);
                }
                else if (time >= Lag)
                {
                    F0 product0;
                    F1 product1;
                    ctx.mul(product0, input0[time], coefficients[Lag - 1]);
                    ctx.mul(product1, input1[time], coefficients[Lag - 1]);
                    ctx.plus(input0[time - Lag], input0[time - Lag], product0);
                    ctx.plus(input1[time - Lag], input1[time - Lag], product1);
                }
                addRandomTaps2<Lag + 1, CheckRange>(
                    input0, input1, time, coefficients, ctx);
            }
        }

        template<typename F, typename Ctx>
        void convolveTranspose(F* __restrict input, Ctx ctx) const
        {
            std::array<Scalar, Memory> coefficients;
            u64 time = mCodeSize;
            while (time > Memory)
            {
                --time;
                coefficientsAtTime(time, coefficients, ctx);
                addRandomTaps<1, false>(input, time, coefficients, ctx);
            }
            while (time-- > 0)
            {
                coefficientsAtTime(time, coefficients, ctx);
                addRandomTaps<1, true>(input, time, coefficients, ctx);
            }
        }

        template<typename F0, typename F1, typename Ctx>
        void convolveTranspose2(
            F0* __restrict input0, F1* __restrict input1, Ctx ctx) const
        {
            std::array<Scalar, Memory> coefficients;
            u64 time = mCodeSize;
            while (time > Memory)
            {
                --time;
                coefficientsAtTime(time, coefficients, ctx);
                addRandomTaps2<1, false>(
                    input0, input1, time, coefficients, ctx);
            }
            while (time-- > 0)
            {
                coefficientsAtTime(time, coefficients, ctx);
                addRandomTaps2<1, true>(
                    input0, input1, time, coefficients, ctx);
            }
        }

        template<typename F, typename Ctx>
        void expandTranspose(
            const F* __restrict input,
            F* __restrict output,
            Ctx ctx) const
        {
            for (u64 right = 0; right != mRegionSize; ++right)
            {
                const u64 leftBase = right * mRightDegree;
                for (u64 slot = 0; slot != mRightDegree; ++slot)
                {
                    const u64 left = leftBase + slot;
                    const Scalar& label = edgeLabelUnchecked(0, left);
                    ctx.mul(output[left], input[right], label);
                }
            }

            const u32* __restrict neighbor = mRegionNeighbors.data();
            for (u64 region = 1; region != LeftDegree; ++region)
            {
                const F* __restrict regionInput = input + region * mRegionSize;
                for (u64 left = 0; left != mMessageSize; ++left)
                {
                    const Scalar& label = edgeLabelUnchecked(region, left);
                    F product;
                    ctx.mul(product, regionInput[*neighbor++], label);
                    ctx.plus(output[left], output[left], product);
                }
            }
        }

        template<typename F0, typename F1, typename Ctx>
        void expandTranspose2(
            const F0* __restrict input0,
            F0* __restrict output0,
            const F1* __restrict input1,
            F1* __restrict output1,
            Ctx ctx) const
        {
            for (u64 right = 0; right != mRegionSize; ++right)
            {
                const u64 leftBase = right * mRightDegree;
                for (u64 slot = 0; slot != mRightDegree; ++slot)
                {
                    const u64 left = leftBase + slot;
                    const Scalar& label = edgeLabelUnchecked(0, left);
                    ctx.mul(output0[left], input0[right], label);
                    ctx.mul(output1[left], input1[right], label);
                }
            }

            const u32* __restrict neighbor = mRegionNeighbors.data();
            for (u64 region = 1; region != LeftDegree; ++region)
            {
                const F0* __restrict regionInput0 =
                    input0 + region * mRegionSize;
                const F1* __restrict regionInput1 =
                    input1 + region * mRegionSize;
                for (u64 left = 0; left != mMessageSize; ++left)
                {
                    const u32 right = *neighbor++;
                    const Scalar& label = edgeLabelUnchecked(region, left);
                    F0 product0;
                    F1 product1;
                    ctx.mul(product0, regionInput0[right], label);
                    ctx.mul(product1, regionInput1[right], label);
                    ctx.plus(output0[left], output0[left], product0);
                    ctx.plus(output1[left], output1[left], product1);
                }
            }
        }
    };
}

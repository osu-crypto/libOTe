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
#include "libOTe/Tools/CoeffCtx.h"
#include "libOTe/Tools/ExConvCode/RegularEcFastSchedule.h"
#if defined(ENABLE_AVX) && !defined(LIBDIVIDE_AVX2)
#define LIBDIVIDE_AVX2
#elif defined(ENABLE_SSE) && !defined(LIBDIVIDE_SSE2)
#define LIBDIVIDE_SSE2
#endif
#include "libdivide.h"

#include <array>
#include <limits>
#include <stdexcept>

namespace osuCrypto
{
    template<typename F, typename Scalar, typename Ctx>
    concept RegularEcStreamingFieldCompatible =
        requires(Ctx ctx, F f, Scalar scalar, block seed)
        {
            ctx.plus(f, f, f);
            ctx.minus(f, f, f);
            ctx.mul(f, f, scalar);
            ctx.plus(scalar, scalar, scalar);
            ctx.minus(scalar, scalar, scalar);
            ctx.mul(scalar, scalar, scalar);
            ctx.fromBlock(scalar, seed);
            ctx.zero(f);
            ctx.zero(scalar);
            ctx.one(scalar);
        };

    // Streaming heuristic inspired by the finite-field two-sided-regular EC
    // ensemble. Unlike the proved ensemble, one pseudorandom sign is derived per
    // code coordinate rather than one full-field multiplier per edge. Each
    // coordinate is signed once before an exact-regular scatter. Convolution
    // taps are regenerated from the public seed at every position. In odd
    // characteristic, each edge slot uses a shifted right-hand cycle and a
    // cheap signed incidence pattern. The sign vectors span the slot space and
    // remove the constant-slot kernel of an unsigned striped scatter; this is
    // not a proof that every finite sampled expander has full row rank.
    // Characteristic two instead uses compact full-index permutations because
    // +1 and -1 coincide. Its full-field convolution coefficients require
    // ambient-field multiplications and mix the binary components of the
    // scalar representation. The unit expander labels still differ from the
    // independently labeled proved ensemble. Both paths avoid a schedule
    // proportional to n.
    template<u64 LeftDegree, u64 Memory, typename Scalar>
    class RegularEcStreamingFieldCode
    {
        static_assert(LeftDegree > 0, "the left degree must be positive");
        static_assert(Memory > 0, "the convolution memory must be positive");

        static constexpr u64 PermutationDomain = 0x177dee2d21ea3bc5ull;
        static constexpr u64 ColumnSignDomain = 0x2ed29b1684cc73a5ull;
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
                    "Finite-field regular EC dimensions must be nonzero. " LOCATION);
            if (messageSize >= codeSize)
                throw std::invalid_argument(
                    "Finite-field regular EC message size must be smaller than its code size. " LOCATION);
            if (codeSize % LeftDegree)
                throw std::invalid_argument(
                    "Finite-field regular EC code size must be divisible by its left degree. " LOCATION);

            const u64 regionSize = codeSize / LeftDegree;
            if (messageSize % regionSize)
                throw std::invalid_argument(
                    "Finite-field regular EC dimensions do not give an integral right degree. " LOCATION);
            const u64 rightDegree = messageSize / regionSize;
            if (rightDegree == 0)
                throw std::invalid_argument(
                    "Finite-field regular EC right degree must be positive. " LOCATION);
            if (messageSize > std::numeric_limits<u32>::max() ||
                codeSize > std::numeric_limits<u32>::max())
                throw std::invalid_argument(
                    "Finite-field regular EC currently uses 32-bit expander indices. " LOCATION);
            if (Memory >= codeSize)
                throw std::invalid_argument(
                    "Finite-field regular EC convolution memory must be smaller than the code size. " LOCATION);
            if (!ctx.template isField<Scalar>())
                throw std::invalid_argument(
                    "Finite-field regular EC requires a field-valued scalar context. " LOCATION);
            if (regionSize == 1 &&
                ctx.template characteristicTwo<Scalar>())
                throw std::invalid_argument(
                    "Characteristic-two streaming regular EC requires a region size of at least two. " LOCATION);

            mMessageSize = messageSize;
            mCodeSize = codeSize;
            mRegionSize = regionSize;
            mRightDegree = rightDegree;
            mSeed = seed;
            mRightDegreeDivider =
                libdivide::libdivide_u32_gen(static_cast<u32>(rightDegree));
            mUseFullPermutations =
                ctx.template characteristicTwo<Scalar>();
            if (mUseFullPermutations)
            {
                for (u64 region = 1; region != LeftDegree; ++region)
                    mRegionPermutations[region - 1].init(
                        messageSize,
                        seed,
                        PermutationDomain + region * 0x9e3779b97f4a7c15ull);
            }
            else
            {
                mRegionOffsets.resize((LeftDegree - 1) * rightDegree);
                mRegionSigns.resize((LeftDegree - 1) * rightDegree);
                const u64 seedMaterial = seed.get<u64>(0) ^
                    std::rotl(seed.get<u64>(1), 23);
                const long double collisionBudget =
                    static_cast<long double>(rightDegree) *
                    static_cast<long double>(rightDegree - 1) / 2 *
                    static_cast<long double>(LeftDegree) *
                    static_cast<long double>(LeftDegree - 1) / 2;
                const bool requireDistinctDifferences =
                    static_cast<long double>(regionSize) >=
                    2 * collisionBudget;
                constexpr u64 MaxOffsetAttempts = 128;
                u64 attempt = 0;
                for (;;)
                {
                    for (u64 region = 1; region != LeftDegree; ++region)
                    {
                        for (u64 slot = 0; slot != rightDegree; ++slot)
                        {
                            const u64 index =
                                (region - 1) * rightDegree + slot;
                            const u64 sample = detail::regularEcMix64(
                                seedMaterial + PermutationDomain +
                                attempt * 0xd1b54a32d192ed03ull +
                                index * 0x9e3779b97f4a7c15ull);
                            mRegionOffsets[index] =
                                static_cast<u32>(sample % regionSize);
                            // Together with the all-positive first region,
                            // these sign vectors span the slot space.
                            mRegionSigns[index] = region < rightDegree ?
                                static_cast<u8>(slot == region) :
                                static_cast<u8>(sample >> 63);
                        }
                    }
                    if (!requireDistinctDifferences ||
                        hasDistinctOffsetDifferences())
                        break;
                    if (++attempt == MaxOffsetAttempts)
                        throw std::runtime_error(
                            "Finite-field regular EC could not sample collision-free striped offsets. " LOCATION);
                }
            }
            mColumnSignCounter.init(seed, ColumnSignDomain);
            mCoefficientCounter.init(seed, CoefficientDomain);
        }

        static constexpr u64 leftDegree() { return LeftDegree; }
        static constexpr u64 memory() { return Memory; }
        u64 rightDegree() const { return mRightDegree; }
        u64 scheduleBytes() const
        {
            return sizeof(*this) +
                mRegionOffsets.capacity() * sizeof(u32) +
                mRegionSigns.capacity() * sizeof(u8);
        }

        u64 rightAt(u64 region, u64 left) const
        {
            checkEdgeIndex(region, left);
            return rightAtUnchecked(region, static_cast<u32>(left));
        }

        template<typename Ctx>
        Scalar edgeLabel(u64 region, u64 left, const Ctx& ctx) const
        {
            checkEdgeIndex(region, left);
            Scalar label = columnSignAtUnchecked(rightAtUnchecked(
                region, static_cast<u32>(left)), ctx);
            if (!mUseFullPermutations && negativeEdgeUnchecked(
                    region, static_cast<u32>(left)))
            {
                Scalar zero;
                ctx.zero(zero);
                ctx.minus(label, zero, label);
            }
            return label;
        }

        template<typename Ctx>
        Scalar feedbackCoefficient(u64 time, u64 lag, const Ctx& ctx) const
        {
            if (time >= mCodeSize || lag == 0 || lag > Memory)
                throw std::out_of_range(
                    "Finite-field regular EC convolution coefficient is out of range. " LOCATION);
            return sampleAt(
                mCoefficientCounter, time * Memory + lag - 1, ctx);
        }

        template<typename F, typename Ctx>
        void dualConvolve(span<F> input, Ctx ctx) const
        {
            if (mCodeSize == 0 || input.size() != mCodeSize)
                throw std::invalid_argument(
                    "Finite-field regular EC convolution buffer has the wrong size. " LOCATION);
            convolveTranspose(input.data(), ctx);
        }

        template<typename F, typename Ctx>
        void dualExpand(span<F> input, span<F> output, Ctx ctx) const
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
                    "Finite-field regular EC is not configured. " LOCATION);
            typename Ctx::template Vec<F> output;
            ctx.resize(output, mMessageSize);
            dualEncode<F>(
                span<F>(&*input, mCodeSize),
                span<F>(output.data(), output.size()),
                ctx);
            ctx.copy(output.begin(), output.end(), input);
        }

        template<typename F0, typename F1, typename Ctx, typename Iter0, typename Iter1>
        void dualEncode2(Iter0 input0, Iter1 input1, Ctx ctx) const
        {
            if (mCodeSize == 0)
                throw std::runtime_error(
                    "Finite-field regular EC is not configured. " LOCATION);
            typename Ctx::template Vec<F0> output0;
            typename Ctx::template Vec<F1> output1;
            ctx.resize(output0, mMessageSize);
            ctx.resize(output1, mMessageSize);
            convolveTranspose2<true>(&*input0, &*input1, ctx);
            expandTranspose2(
                &*input0, output0.data(), &*input1, output1.data(), ctx);
            ctx.copy(output0.begin(), output0.end(), input0);
            ctx.copy(output1.begin(), output1.end(), input1);
        }

    private:
        AlignedUnVector<u32> mRegionOffsets;
        AlignedUnVector<u8> mRegionSigns;
        std::array<detail::RegularEcFeistel, LeftDegree - 1> mRegionPermutations;
        detail::RegularEcCounter mColumnSignCounter;
        detail::RegularEcCounter mCoefficientCounter;
        libdivide::libdivide_u32_t mRightDegreeDivider{};
        bool mUseFullPermutations = false;

        template<typename Ctx>
        OC_FORCEINLINE Scalar sampleAt(
            const detail::RegularEcCounter& counter,
            u64 index,
            const Ctx& ctx) const
        {
            Scalar value;
            if constexpr (sizeof(Scalar) <= sizeof(u64))
                ctx.fromBlock(value, block(counter.word(index), 0));
            else
                ctx.fromBlock(value, counter.sample(index));
            return value;
        }

        template<typename Ctx>
        OC_FORCEINLINE Scalar columnSignAtUnchecked(
            u64 index, const Ctx& ctx) const
        {
            Scalar value;
            ctx.one(value);
            const u64 signWord = mColumnSignCounter.word(index >> 6);
            if ((signWord >> (index & 63)) & 1)
            {
                Scalar zero;
                ctx.zero(zero);
                ctx.minus(value, zero, value);
            }
            return value;
        }

        template<typename Fn>
        OC_FORCEINLINE void forEachNegativeColumn(Fn&& fn) const
        {
            u64 firstColumn = 0;
            u64 firstWord = 0;
            std::array<u64, 4> words;
            while (firstColumn != mCodeSize)
            {
                mColumnSignCounter.fourWords(firstWord, words);
                for (u64 lane = 0; lane != words.size(); ++lane)
                {
                    const u64 count = std::min<u64>(
                        64, mCodeSize - firstColumn);
                    u64 negative = words[lane];
                    if (count != 64)
                        negative &= (u64{ 1 } << count) - 1;
                    while (negative)
                    {
                        const u64 bit = std::countr_zero(negative);
                        fn(firstColumn + bit);
                        negative &= negative - 1;
                    }
                    firstColumn += count;
                    if (firstColumn == mCodeSize)
                        return;
                }
                firstWord += words.size();
            }
        }

        template<typename F, typename Ctx>
        OC_FORCEINLINE void negateColumn(
            F& value, const F& zero, const Ctx& ctx) const
        {
            ctx.minus(value, zero, value);
        }

        template<typename Ctx>
        OC_FORCEINLINE void coefficientsAtTime(
            u64 time,
            std::array<Scalar, Memory>& coefficients,
            const Ctx& ctx) const
        {
            const u64 first = time * Memory;
            if constexpr (sizeof(Scalar) <= sizeof(u64) && Memory == 4)
            {
                std::array<u64, 4> words;
                mCoefficientCounter.fourWords(first, words);
                for (u64 offset = 0; offset != Memory; ++offset)
                    ctx.fromBlock(coefficients[offset], block(words[offset], 0));
            }
            else
            {
                for (u64 offset = 0; offset != Memory; ++offset)
                    coefficients[offset] = sampleAt(
                        mCoefficientCounter, first + offset, ctx);
            }
        }

        void checkEdgeIndex(u64 region, u64 left) const
        {
            if (region >= LeftDegree || left >= mMessageSize)
                throw std::out_of_range(
                    "Finite-field regular EC neighbor index is out of range. " LOCATION);
        }

        OC_FORCEINLINE u32 bucket(u32 permuted) const
        {
            return libdivide::libdivide_u32_do(permuted, &mRightDegreeDivider);
        }

        OC_FORCEINLINE u64 rightAtUnchecked(u64 region, u32 left) const
        {
            if (region == 0)
                return bucket(left);
            if (mUseFullPermutations)
            {
                const u32 permuted = mRegionPermutations[region - 1](left);
                return region * mRegionSize + bucket(permuted);
            }
            const u32 base = bucket(left);
            const u32 slot = left - base * static_cast<u32>(mRightDegree);
            u64 right = base + mRegionOffsets[
                (region - 1) * mRightDegree + slot];
            if (right >= mRegionSize)
                right -= mRegionSize;
            return region * mRegionSize + right;
        }

        OC_FORCEINLINE bool negativeEdgeUnchecked(u64 region, u32 left) const
        {
            if (region == 0)
                return false;
            const u32 base = bucket(left);
            const u32 slot = left - base * static_cast<u32>(mRightDegree);
            return mRegionSigns[(region - 1) * mRightDegree + slot] != 0;
        }

        bool hasDistinctOffsetDifferences() const
        {
            auto offset = [&](u64 region, u64 slot) -> u32 {
                return region == 0 ? 0 :
                    mRegionOffsets[(region - 1) * mRightDegree + slot];
            };
            auto difference = [&](u64 region, u64 first, u64 second) -> u32 {
                const u32 lhs = offset(region, first);
                const u32 rhs = offset(region, second);
                return lhs >= rhs ? lhs - rhs :
                    static_cast<u32>(lhs + mRegionSize - rhs);
            };

            for (u64 first = 0; first != mRightDegree; ++first)
            {
                for (u64 second = first + 1; second != mRightDegree; ++second)
                {
                    for (u64 region0 = 0; region0 != LeftDegree; ++region0)
                    {
                        const u32 value = difference(
                            region0, first, second);
                        for (u64 region1 = region0 + 1;
                            region1 != LeftDegree; ++region1)
                        {
                            if (value == difference(
                                    region1, first, second))
                                return false;
                        }
                    }
                }
            }
            return true;
        }

        void checkEncodeSizes(u64 inputSize, u64 outputSize) const
        {
            if (mCodeSize == 0)
                throw std::runtime_error(
                    "Finite-field regular EC is not configured. " LOCATION);
            if (inputSize != mCodeSize || outputSize != mMessageSize)
                throw std::invalid_argument(
                    "Finite-field regular EC encode buffer has the wrong size. " LOCATION);
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

        template<bool ApplyColumnSigns = false,
            typename F0, typename F1, typename Ctx>
        void convolveTranspose2(
            F0* __restrict input0, F1* __restrict input1, Ctx ctx) const
        {
            std::array<Scalar, Memory> coefficients;
            F0 zero0;
            F1 zero1;
            u64 signWordIndex = 0;
            u64 signWord = 0;
            if constexpr (ApplyColumnSigns)
            {
                ctx.zero(zero0);
                ctx.zero(zero1);
                signWordIndex = (mCodeSize - 1) >> 6;
                signWord = mColumnSignCounter.word(signWordIndex);
            }
            u64 time = mCodeSize;
            while (time > Memory)
            {
                --time;
                coefficientsAtTime(time, coefficients, ctx);
                addRandomTaps2<1, false>(
                    input0, input1, time, coefficients, ctx);
                if constexpr (ApplyColumnSigns)
                {
                    if (!mUseFullPermutations &&
                        ((signWord >> (time & 63)) & 1))
                    {
                        negateColumn(input0[time], zero0, ctx);
                        negateColumn(input1[time], zero1, ctx);
                    }
                    if (time && ((time - 1) >> 6) != signWordIndex)
                    {
                        signWordIndex = (time - 1) >> 6;
                        signWord = mColumnSignCounter.word(signWordIndex);
                    }
                }
            }
            while (time-- > 0)
            {
                coefficientsAtTime(time, coefficients, ctx);
                addRandomTaps2<1, true>(
                    input0, input1, time, coefficients, ctx);
                if constexpr (ApplyColumnSigns)
                {
                    if (!mUseFullPermutations &&
                        ((signWord >> (time & 63)) & 1))
                    {
                        negateColumn(input0[time], zero0, ctx);
                        negateColumn(input1[time], zero1, ctx);
                    }
                    if (time && ((time - 1) >> 6) != signWordIndex)
                    {
                        signWordIndex = (time - 1) >> 6;
                        signWord = mColumnSignCounter.word(signWordIndex);
                    }
                }
            }
        }

        template<typename F, typename Ctx>
        void scaleColumns(F* __restrict input, Ctx& ctx) const
        {
            if (mUseFullPermutations)
                return;
            F zero;
            ctx.zero(zero);
            forEachNegativeColumn([&](u64 index) {
                negateColumn(input[index], zero, ctx);
            });
        }

        template<typename F, typename Ctx>
        void expandTranspose(
            F* __restrict input, F* __restrict output, Ctx ctx) const
        {
            scaleColumns(input, ctx);
            for (u32 right = 0; right != mRegionSize; ++right)
            {
                const u32 leftBase = right * static_cast<u32>(mRightDegree);
                for (u32 slot = 0; slot != mRightDegree; ++slot)
                    ctx.copy(output[leftBase + slot], input[right]);
            }

            for (u64 region = 1; region != LeftDegree; ++region)
            {
                const F* __restrict regionInput = input + region * mRegionSize;
                if (mUseFullPermutations)
                {
                    const auto& permutation = mRegionPermutations[region - 1];
                    u32 left = 0;
                    std::array<u32, 4> permuted;
                    for (; left + 4 <= mMessageSize; left += 4)
                    {
                        permutation.four(left, permuted);
                        for (u32 lane = 0; lane != permuted.size(); ++lane)
                            ctx.plus(output[left + lane], output[left + lane],
                                regionInput[bucket(permuted[lane])]);
                    }
                    for (; left != mMessageSize; ++left)
                        ctx.plus(output[left], output[left],
                            regionInput[bucket(permutation(left))]);
                }
                else
                {
                    const u32* __restrict offsets = mRegionOffsets.data() +
                        (region - 1) * mRightDegree;
                    const u8* __restrict signs = mRegionSigns.data() +
                        (region - 1) * mRightDegree;
                    for (u32 base = 0; base != mRegionSize; ++base)
                    {
                        const u32 leftBase =
                            base * static_cast<u32>(mRightDegree);
                        for (u32 slot = 0; slot != mRightDegree; ++slot)
                        {
                            u32 right = base + offsets[slot];
                            if (right >= mRegionSize)
                                right -= static_cast<u32>(mRegionSize);
                            if (signs[slot])
                                ctx.minus(output[leftBase + slot],
                                    output[leftBase + slot], regionInput[right]);
                            else
                                ctx.plus(output[leftBase + slot],
                                    output[leftBase + slot], regionInput[right]);
                        }
                    }
                }
            }
        }

        template<typename F0, typename F1, typename Ctx>
        void expandTranspose2(
            F0* __restrict input0, F0* __restrict output0,
            F1* __restrict input1, F1* __restrict output1, Ctx ctx) const
        {
            for (u32 right = 0; right != mRegionSize; ++right)
            {
                const u32 leftBase = right * static_cast<u32>(mRightDegree);
                for (u32 slot = 0; slot != mRightDegree; ++slot)
                {
                    ctx.copy(output0[leftBase + slot], input0[right]);
                    ctx.copy(output1[leftBase + slot], input1[right]);
                }
            }

            for (u64 region = 1; region != LeftDegree; ++region)
            {
                const F0* __restrict regionInput0 = input0 + region * mRegionSize;
                const F1* __restrict regionInput1 = input1 + region * mRegionSize;
                if (mUseFullPermutations)
                {
                    const auto& permutation = mRegionPermutations[region - 1];
                    u32 left = 0;
                    std::array<u32, 4> permuted;
                    for (; left + 4 <= mMessageSize; left += 4)
                    {
                        permutation.four(left, permuted);
                        for (u32 lane = 0; lane != permuted.size(); ++lane)
                        {
                            const u32 right = bucket(permuted[lane]);
                            ctx.plus(output0[left + lane], output0[left + lane],
                                regionInput0[right]);
                            ctx.plus(output1[left + lane], output1[left + lane],
                                regionInput1[right]);
                        }
                    }
                    for (; left != mMessageSize; ++left)
                    {
                        const u32 right = bucket(permutation(left));
                        ctx.plus(output0[left], output0[left], regionInput0[right]);
                        ctx.plus(output1[left], output1[left], regionInput1[right]);
                    }
                }
                else
                {
                    const u32* __restrict offsets = mRegionOffsets.data() +
                        (region - 1) * mRightDegree;
                    const u8* __restrict signs = mRegionSigns.data() +
                        (region - 1) * mRightDegree;
                    for (u32 base = 0; base != mRegionSize; ++base)
                    {
                        const u32 leftBase =
                            base * static_cast<u32>(mRightDegree);
                        for (u32 slot = 0; slot != mRightDegree; ++slot)
                        {
                            u32 right = base + offsets[slot];
                            if (right >= mRegionSize)
                                right -= static_cast<u32>(mRegionSize);
                            if (signs[slot])
                            {
                                ctx.minus(output0[leftBase + slot],
                                    output0[leftBase + slot], regionInput0[right]);
                                ctx.minus(output1[leftBase + slot],
                                    output1[leftBase + slot], regionInput1[right]);
                            }
                            else
                            {
                                ctx.plus(output0[leftBase + slot],
                                    output0[leftBase + slot], regionInput0[right]);
                                ctx.plus(output1[leftBase + slot],
                                    output1[leftBase + slot], regionInput1[right]);
                            }
                        }
                    }
                }
            }
        }
    };

}

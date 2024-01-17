// � 2023 Peter Rindal.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#pragma once

#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Range.h"
#include "libOTe/Tools/LDPC/Mtx.h"
#include "libOTe/Tools/EACode/Util.h"

namespace osuCrypto
{

    template<class Iter>
    auto getRestrictPtr(Iter& c)
    {
        //if constexpr (coproto::has_data_member_func<Container>::value)
        //{
        //    return (decltype(c.data())__restrict) c.data();
        //}
        //else
        {
            return c;
        }
    }

    // The encoder for the expander matrix B.
    // B has mMessageSize rows and mCodeSize columns. It is sampled uniformly
    // with fixed row weight mExpanderWeight.
    class ExpanderCode2
    {
    public:

        void config(
            u64 messageSize,
            u64 codeSize,
            u64 expanderWeight,
            block seed = block(33333, 33333))
        {
            mMessageSize = messageSize;
            mCodeSize = codeSize;
            mExpanderWeight = expanderWeight;
            mSeed = seed;
        }

        // the seed that generates the code.
        block mSeed = block(0, 0);

        // The message size of the code. K.
        u64 mMessageSize = 0;

        // The codeword size of the code. n.
        u64 mCodeSize = 0;

        // The row weight of the B matrix.
        u64 mExpanderWeight = 0;

        u64 parityRows() const { return mCodeSize - mMessageSize; }
        u64 parityCols() const { return mCodeSize; }

        u64 generatorRows() const { return mMessageSize; }
        u64 generatorCols() const { return mCodeSize; }

        // compute a eight output.
        // the result is written to the dst iterator/ptr.
        // 
        template<
            typename CoeffCtx,
            typename DstIter,
            typename SrcIter
        >
        void expandEight(
            DstIter&& dst,
            SrcIter&& ee,
            detail::ExpanderModd& prng,
            CoeffCtx ctx) const;


        template<
            typename F,
            typename CoeffCtx,
            bool add,
            typename SrcIter,
            typename DstIter
        >
        void expand(
            SrcIter&& input,
            DstIter&& output,
            CoeffCtx ctx = {}
        ) const;


        template<
            typename F,
            typename CoeffCtx
        >
        typename CoeffCtx::template Vec<F> getB(CoeffCtx ctx = {}) const;

    };

    template<
        typename CoeffCtx,
        typename DstIter,
        typename SrcIter
    >
    OC_FORCEINLINE void
        ExpanderCode2::expandEight(
            DstIter&& dst,
            SrcIter&& ee,
            detail::ExpanderModd& prng,
            CoeffCtx ctx) const
    {
        u64 rr[8];
        rr[0] = prng.get();
        rr[1] = prng.get();
        rr[2] = prng.get();
        rr[3] = prng.get();
        rr[4] = prng.get();
        rr[5] = prng.get();
        rr[6] = prng.get();
        rr[7] = prng.get();

        ctx.plus(*(dst + 0), *(dst + 0), *(ee + rr[0]));
        ctx.plus(*(dst + 1), *(dst + 1), *(ee + rr[1]));
        ctx.plus(*(dst + 2), *(dst + 2), *(ee + rr[2]));
        ctx.plus(*(dst + 3), *(dst + 3), *(ee + rr[3]));
        ctx.plus(*(dst + 4), *(dst + 4), *(ee + rr[4]));
        ctx.plus(*(dst + 5), *(dst + 5), *(ee + rr[5]));
        ctx.plus(*(dst + 6), *(dst + 6), *(ee + rr[6]));
        ctx.plus(*(dst + 7), *(dst + 7), *(ee + rr[7]));

    }


    template<
        typename F,
        typename CoeffCtx,
        bool Add,
        typename SrcIter,
        typename DstIter
    >
    void ExpanderCode2::expand(
        SrcIter&& input,
        DstIter&& output,
        CoeffCtx ctx) const
    {
        (void)*(input + (mCodeSize - 1));
        (void)*(output + (mMessageSize - 1));

        detail::ExpanderModd prng(mSeed, mCodeSize);

        auto main = mMessageSize / 8 * 8;
        u64 i = 0;

        for (; i < main; i += 8, output += 8)
        {
            if constexpr (Add == false)
            {
                ctx.zero(output, output + 8);
            }

            for (auto j = 0ull; j < mExpanderWeight; ++j)
            {
                // temp[0...7] = expand(input)
                expandEight<CoeffCtx>(
                    output, input, 
                    prng, ctx);
            }
        }

        if constexpr (Add == false)
        {
            ctx.zero(output, output + (mMessageSize-i));
        }

        for (; i < mMessageSize; ++i, ++output)
        {
            for (auto j = 0ull; j < mExpanderWeight; ++j)
            {
                ctx.plus(*output, *output, *(input + prng.get()));
            }
        }
    }


    template<
        typename F,
        typename CoeffCtx
    >
    inline typename CoeffCtx::template Vec<F> ExpanderCode2::getB(CoeffCtx ctx) const
    {

        typename CoeffCtx::template Vec<F> e, x;
        ctx.resize(e, mCodeSize);
        ctx.resize(x, mMessageSize * mCodeSize);

        for (u64 i = 0; i < e.size(); ++i)
        {
            // construct the i'th unit vector as input.
            ctx.zero(e.begin(), e.end());
            ctx.one(e.begin() + i, e.begin() + i + 1);

            // expand it to geth the i'th row of the matrix
            expand<F, CoeffCtx, false>(e.begin(), x.begin() + i * mCodeSize);
        }

        return x;
    }


    //    //detail::ExpanderModd prng(mSeed, mCodeSize);
    //    //PointList points(mMessageSize, mCodeSize);

    //    //u64 i = 0;
    //    //auto main = mMessageSize / 8 * 8;

    //    //// for the main phase we process 8 expands in parallel.
    //    //Matrix<u64> rows(8, mExpanderWeight);
    //    //for (; i < main; i += 8)
    //    //{
    //    //    for (auto j = 0ull; j < mExpanderWeight; ++j)
    //    //    {
    //    //        for (u64 k = 0; k < 8; ++k)
    //    //            rows(k, j) = prng.get();
    //    //    }

    //    //    for (auto j = 0ull; j < mExpanderWeight; ++j)
    //    //    {
    //    //        for (u64 k = 0; k < 8; ++k)
    //    //        {
    //    //            auto rk = rows[k];
    //    //            // we could have duplicates that cancel.
    //    //            auto count = std::count(rk.begin(), rk.end(), rk[j]);
    //    //            if (count == 1 || (count > 1 && std::find(rk.begin(), rk.end(), rk[j]) == rk.begin() + j))
    //    //                points.push_back(i + k, rk[j]);
    //    //        }
    //    //    }
    //    //}

    //    //for (; i < mMessageSize; ++i)
    //    //{
    //    //    auto rk = rows[0];
    //    //    for (auto j = 0ull; j < mExpanderWeight; ++j)
    //    //        rk[j] = prng.get();

    //    //    for (auto j = 0ull; j < mExpanderWeight; ++j)
    //    //    {
    //    //        // we could have duplicates that cancel.
    //    //        auto count = std::count(rk.begin(), rk.end(), rk[j]);
    //    //        if (count == 1 || (count > 1 && std::find(rk.begin(), rk.end(), rk[j]) == rk.begin() + j))
    //    //            points.push_back(i, rk[j]);
    //    //    }
    //    //}

    //    //return points;
    //}

}

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




        //template<
        //    bool Add,
        //    typename CoeffCtx,
        //    typename... F,
        //    typename... SrcDstIterPair
        //>
        //void expandMany(
        //    std::tuple<SrcDstIterPair...>  out,
        //    CoeffCtx ctx = {})const;

    };



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

        auto rInput = ctx.restrictPtr<const F>(input);
        auto rOutput = ctx.restrictPtr<F>(output);

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
                u64 rr[8];
                rr[0] = prng.get();
                rr[1] = prng.get();
                rr[2] = prng.get();
                rr[3] = prng.get();
                rr[4] = prng.get();
                rr[5] = prng.get();
                rr[6] = prng.get();
                rr[7] = prng.get();

                ctx.plus(*(rOutput + 0), *(rOutput + 0), *(rInput + rr[0]));
                ctx.plus(*(rOutput + 1), *(rOutput + 1), *(rInput + rr[1]));
                ctx.plus(*(rOutput + 2), *(rOutput + 2), *(rInput + rr[2]));
                ctx.plus(*(rOutput + 3), *(rOutput + 3), *(rInput + rr[3]));
                ctx.plus(*(rOutput + 4), *(rOutput + 4), *(rInput + rr[4]));
                ctx.plus(*(rOutput + 5), *(rOutput + 5), *(rInput + rr[5]));
                ctx.plus(*(rOutput + 6), *(rOutput + 6), *(rInput + rr[6]));
                ctx.plus(*(rOutput + 7), *(rOutput + 7), *(rInput + rr[7]));
            }
        }

        if constexpr (Add == false)
        {
            ctx.zero(output, output + (mMessageSize - i));
        }

        for (; i < mMessageSize; ++i, ++output)
        {
            for (auto j = 0ull; j < mExpanderWeight; ++j)
            {
                ctx.plus(*output, *output, *(input + prng.get()));
            }
        }
    }

    //template<
    //    bool Add,
    //    typename CoeffCtx,
    //    typename... F,
    //    typename... SrcDstIterPair
    //>
    //void ExpanderCode2::expandMany(
    //    std::tuple<SrcDstIterPair...>  inOuts,
    //    CoeffCtx ctx)const
    //{

    //    std::apply([&](auto&&... inOut) {(
    //        [&] {
    //            (void)*(std::get<0>(inOut) + (mCodeSize - 1));
    //            (void)*(std::get<1>(inOut) + (mMessageSize - 1));
    //        }(), ...); }, inOuts);


    //    detail::ExpanderModd prng(mSeed, mCodeSize);

    //    auto main = mMessageSize / 8 * 8;
    //    u64 i = 0;

    //    std::vector<u64> rr(8 * mExpanderWeight);

    //    for (; i < main; i += 8)
    //    {
    //        for (auto j = 0ull; j < mExpanderWeight; ++j)
    //        {
    //            rr[j * 8 + 0] = prng.get();
    //            rr[j * 8 + 1] = prng.get();
    //            rr[j * 8 + 2] = prng.get();
    //            rr[j * 8 + 3] = prng.get();
    //            rr[j * 8 + 4] = prng.get();
    //            rr[j * 8 + 5] = prng.get();
    //            rr[j * 8 + 6] = prng.get();
    //            rr[j * 8 + 7] = prng.get();
    //        }

    //        std::apply([&](auto&&... inOut) {([&] {

    //            auto& input = std::get<0>(inOut);
    //            auto& output = std::get<1>(inOut);

    //            if constexpr (Add == false)
    //            {
    //                ctx.zero(output, output + 8);
    //            }

    //            for (auto j = 0ull; j < mExpanderWeight; ++j)
    //            {
    //                ctx.plus(*(output + 0), *(output + 0), *(input + rr[j * 8 + 0]));
    //                ctx.plus(*(output + 1), *(output + 1), *(input + rr[j * 8 + 1]));
    //                ctx.plus(*(output + 2), *(output + 2), *(input + rr[j * 8 + 2]));
    //                ctx.plus(*(output + 3), *(output + 3), *(input + rr[j * 8 + 3]));
    //                ctx.plus(*(output + 4), *(output + 4), *(input + rr[j * 8 + 4]));
    //                ctx.plus(*(output + 5), *(output + 5), *(input + rr[j * 8 + 5]));
    //                ctx.plus(*(output + 6), *(output + 6), *(input + rr[j * 8 + 6]));
    //                ctx.plus(*(output + 7), *(output + 7), *(input + rr[j * 8 + 7]));
    //            }

    //            output += 8;
    //            }(), ...); }, inOuts);

    //    }

    //    for (auto j = 0ull; j < mExpanderWeight; ++j)
    //    {
    //        rr[j * 8 + 0] = prng.get();
    //        rr[j * 8 + 1] = prng.get();
    //        rr[j * 8 + 2] = prng.get();
    //        rr[j * 8 + 3] = prng.get();
    //        rr[j * 8 + 4] = prng.get();
    //        rr[j * 8 + 5] = prng.get();
    //        rr[j * 8 + 6] = prng.get();
    //        rr[j * 8 + 7] = prng.get();
    //    }

    //    std::apply([&](auto&&... inOut) {([&] {

    //        auto& input = std::get<0>(inOut);
    //        auto& output = std::get<1>(inOut);
    //        if constexpr (Add == false)
    //        {
    //            ctx.zero(output, output + (mMessageSize - i));
    //        }

    //        for (u64 k = 0; i < mMessageSize; ++i, ++output, ++k)
    //        {
    //            for (auto j = 0ull; j < mExpanderWeight; ++j)
    //            {
    //                ctx.plus(*output, *output, *(input + rr[j*8 + k]));
    //            }
    //        }
    //        }(), ...); }, inOuts);
    //}



}

#pragma once
// © 2023 Peter Rindal.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Timer.h"
#include "libOTe/Tools/ExConvCode/Expander.h"
#include "Util.h"
namespace osuCrypto
{

    // The encoder for the generator matrix G = B * A.
    // B is the expander while A is the accumulator.
    // 
    // B has mMessageSize rows and mCodeSize columns. It is sampled uniformly
    // with fixed row weight mExpanderWeight.
    //
    // A is a solid upper triangular n by n matrix
    // https://eprint.iacr.org/2022/1014
    class EACode : public ExpanderCode, public TimerAdapter
    {
    public:


        void config(
            u64 messageSize,
            u64 codeSize,
            u64 expanderWeight,
            block seed = block(33333, 33333))
        {
            ExpanderCode::config(messageSize, codeSize, expanderWeight, false, seed);
        }
        // Compute w = G * e.
        template<typename T, typename Ctx>
        void dualEncode(span<T> e, span<T> w, Ctx ctx);


        template<typename T, typename Ctx, typename Iter>
        void dualEncode(Iter iter, Ctx ctx)
        {
            span<T> e(iter, iter + mCodeSize);
            AlignedUnVector<T> w(mMessageSize);
            dualEncode<T>(e, w, ctx);
            std::copy(w.begin(), w.end(), iter);
        }

        template<typename T, typename T2, typename Ctx>
        void dualEncode2(
            span<T> e0,
            span<T> w0,
            span<T2> e1,
            span<T2> w1, Ctx ctx
        );


        template<typename T, typename Ctx>
        void accumulate(span<T> x, Ctx ctx);
        template<typename T, typename T2, typename Ctx>
        void accumulate(span<T> x, span<T2> x2, Ctx ctx);

        // Get the parity check version of the accumulator
        SparseMtx getAPar() const;

        SparseMtx getA() const;
    };

    // Compute w = G * e.
    template<typename T, typename Ctx>
    void EACode::dualEncode(span<T> e, span<T> w, Ctx ctx)
    {
        if (mCodeSize == 0)
            throw RTE_LOC;
        if (e.size() != mCodeSize)
            throw RTE_LOC;
        if (w.size() != mMessageSize)
            throw RTE_LOC;


        setTimePoint("EACode.encode.begin");

        accumulate<T>(e, ctx);

        setTimePoint("EACode.encode.accumulate");

        expand<T, Ctx, false>(e.begin(), w.begin(), ctx);
        setTimePoint("EACode.encode.expand");
    }




    template<typename T, typename T2, typename Ctx>
    void EACode::dualEncode2(
        span<T> e0,
        span<T> w0,
        span<T2> e1,
        span<T2> w1, Ctx ctx
    )
    {
        if (mCodeSize == 0)
            throw RTE_LOC;
        if (e0.size() != mCodeSize)
            throw RTE_LOC;
        if (e1.size() != mCodeSize)
            throw RTE_LOC;
        if (w0.size() != mMessageSize)
            throw RTE_LOC;
        if (w1.size() != mMessageSize)
            throw RTE_LOC;

        setTimePoint("EACode.encode.begin");

        accumulate<T, T2>(e0, e1, ctx);
        //accumulate<T2>(e1);

        setTimePoint("EACode.encode.accumulate");

        expand<T, Ctx, false>(e0.begin(), w0.begin(), ctx);
        expand<T2, Ctx, false>(e1.begin(), w1.begin(), ctx);
        setTimePoint("EACode.encode.expand");
    }



    template<typename T, typename Ctx>
    void EACode::accumulate(span<T> x, Ctx ctx)
    {
        if (x.size() != mCodeSize)
            throw RTE_LOC;
        auto main = (u64)std::max<i64>(0, mCodeSize - 1);
        T* __restrict xx = x.data();

        for (u64 i = 0; i < main; ++i)
        {
            ctx.plus(xx[i + 1], xx[i + 1], xx[i]);
            ctx.mulConst(xx[i + 1], xx[i + 1]);
        }
    }

    template<typename T, typename T2, typename Ctx>
    void EACode::accumulate(span<T> x, span<T2> x2, Ctx ctx)
    {
        if (x.size() != mCodeSize)
            throw RTE_LOC;
        if (x2.size() != mCodeSize)
            throw RTE_LOC;

        auto main = (u64)std::max<i64>(0, mCodeSize - 1);
        T* __restrict xx1 = x.data();
        T2* __restrict xx2 = x2.data();

        for (u64 i = 0; i < main; ++i)
        {
            ctx.plus(xx1[i + 1], xx1[i + 1], xx1[i]);
            ctx.plus(xx2[i + 1], xx2[i + 1], xx2[i]);
            ctx.mulConst(xx1[i + 1], xx1[i + 1]);
            ctx.mulConst(xx2[i + 1], xx2[i + 1]);

        }
    }


    inline SparseMtx EACode::getAPar() const
    {
        PointList AP(mCodeSize, mCodeSize);;
        for (u64 i = 0; i < mCodeSize; ++i)
        {
            AP.push_back(i, i);
            if (i + 1 < mCodeSize)
                AP.push_back(i + 1, i);
        }
        return AP;
    }

    inline SparseMtx EACode::getA() const
    {
        auto APar = getAPar();

        auto A = DenseMtx::Identity(mCodeSize);

        for (u64 i = 0; i < mCodeSize; ++i)
        {
            for (auto y : APar.col(i))
            {
                //std::cout << y << " ";
                if (y != i)
                {
                    auto ay = A.row(y);
                    auto ai = A.row(i);
                    ay ^= ai;

                }
            }

            //std::cout << "\n" << A << std::endl;
        }

        return A.sparse();
    }
}

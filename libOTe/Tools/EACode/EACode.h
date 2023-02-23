#pragma once

#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Timer.h"
#include "Expander.h"
#include "Util.h"

namespace osuCrypto
{

    // THe encoder for the generator matrix G = B * A.
    // B is the expander while A is the accumulator.
    // 
    // B has mMessageSize rows and mCodeSize columns. It is sampled uniformly
    // with fixed row weight mExpanderWeight.
    //
    // A is a solid upper triangular n by n matrix
    class EACode : public ExpanderCode, public TimerAdapter
    {
    public:
        using ExpanderCode::config;
        using ExpanderCode::getB;


        // Compute w = G * e.
        template<typename T>
        void dualEncode(span<T> e, span<T> w)
        {
            if (mCodeSize == 0)
                throw RTE_LOC;
            if (e.size() != mCodeSize)
                throw RTE_LOC;
            if (w.size() != mMessageSize)
                throw RTE_LOC;


            setTimePoint("ExConv.encode.begin");

            accumulate<T>(e);

            setTimePoint("ExConv.encode.accumulate");

            expand<T>(e, w);
            setTimePoint("ExConv.encode.expand");
        }


        template<typename T, typename T2>
        void dualEncode2(
            span<T> e0,
            span<T> w0,
            span<T2> e1,
            span<T2> w1
        )
        {
            if (mCodeSize == 0)
                throw RTE_LOC;
            if (e0.size() != mCodeSize) 
                throw RTE_LOC;
            if(e1.size() != mCodeSize)
                throw RTE_LOC;
            if(w0.size() != mMessageSize)
                throw RTE_LOC;
            if(w1.size() != mMessageSize)
                throw RTE_LOC;

            setTimePoint("ExConv.encode.begin");

            accumulate<T, T2>(e0, e1);
            //accumulate<T2>(e1);

            setTimePoint("ExConv.encode.accumulate");

            expand<T>(e0, w0);
            expand<T2>(e1, w1);
            setTimePoint("ExConv.encode.expand");
        }

        OC_FORCEINLINE void accOne(
            PointList& pl,
            u64 i) const
        {
        }

        template<typename T>
        void accumulate(span<T> x)
        {
            if (x.size() != mCodeSize)
                throw RTE_LOC;
            auto main = (u64)std::max<i64>(0, mCodeSize - 1);
            T* __restrict xx = x.data();

            for (u64 i = 0; i < main; ++i)
            {
                auto xj = xx[i + 1] ^ xx[i];
                xx[i + 1] = xj;
            }
        }

        template<typename T, typename T2>
        void accumulate(span<T> x, span<T2> x2)
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
                auto x1j = xx1[i + 1] ^ xx1[i];
                auto x2j = xx2[i + 1] ^ xx2[i];
                xx1[i + 1] = x1j;
                xx2[i + 1] = x2j;
            }
        }


        // Get the parity check version of the accumulator
        SparseMtx getAPar() const
        {
            PointList AP(mCodeSize, mCodeSize);;
            for (i64 i = 0; i < mCodeSize; ++i)
            {
                AP.push_back(i, i);
                if (i + 1 < mCodeSize)
                    AP.push_back(i + 1, i);
            }
            return AP;
        }

        SparseMtx getA() const
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
    };
}

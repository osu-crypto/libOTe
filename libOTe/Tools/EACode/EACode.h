#pragma once

#include "cryptoTools/Common/Defines.h"
#include "libOTe/Tools/LDPC/Mtx.h"
#include "cryptoTools/Common/Range.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "libOTe/Tools/LDPC/LdpcEncoder.h"

#include "Util.h"

namespace osuCrypto
{
#if __cplusplus >= 201703L
#define EA_CONSTEXPR constexpr
#else
#define EA_CONSTEXPR
#endif
    // THe encoder for the generator matrix G = B * A.
    // B is the expander while A is the accumulator.
    // 
    // B has mMessageSize rows and mCodeSize columns. It is sampled uniformly
    // with fixed row weight mExpanderWeight.
    //
    // A is a solid upper triangular n by n matrix
    class EACode : public TimerAdapter
    {
    public:

        void config(
            u64 messageSize,
            u64 codeSize,
            u64 expanderWeight,
            block seed = block(0, 0))
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


        template<typename T, u64 count>
        OC_FORCEINLINE typename std::enable_if<(count > 1), T>::type
            expandOne(const T* __restrict ee, detail::ExpanderModd& prng)const
        {
            if EA_CONSTEXPR (count >= 8)
            {
                u64 rr[8];
                T w[8];
                rr[0] = prng.get();
                rr[1] = prng.get();
                rr[2] = prng.get();
                rr[3] = prng.get();
                rr[4] = prng.get();
                rr[5] = prng.get();
                rr[6] = prng.get();
                rr[7] = prng.get();

                w[0] = ee[rr[0]];
                w[1] = ee[rr[1]];
                w[2] = ee[rr[2]];
                w[3] = ee[rr[3]];
                w[4] = ee[rr[4]];
                w[5] = ee[rr[5]];
                w[6] = ee[rr[6]];
                w[7] = ee[rr[7]];

                auto ww =
                    w[0] ^
                    w[1] ^
                    w[2] ^
                    w[3] ^
                    w[4] ^
                    w[5] ^
                    w[6] ^
                    w[7];

                if EA_CONSTEXPR(count > 8)
                {

                    ww = ww ^ expandOne<T, (count < 8 ? 0 : count - 8)>(ee, prng);
                }
                return ww;
            }
            else
            {

                auto r = prng.get();
                auto ww = expandOne<T, count - 1>(ee, prng);
                return ww ^ ee[r];
            }
        }


        template<typename T, typename T2, u64 count>
        OC_FORCEINLINE typename std::enable_if<(count > 1), T>::type
            expandOne(
                const T* __restrict ee1, 
                const T2* __restrict ee2,
                T* __restrict y1,
                T2* __restrict y2,
                detail::ExpanderModd& prng)const
        {
            if EA_CONSTEXPR (count >= 8)
            {
                u64 rr[8];
                T w1[8];
                T2 w2[8];
                rr[0] = prng.get();
                rr[1] = prng.get();
                rr[2] = prng.get();
                rr[3] = prng.get();
                rr[4] = prng.get();
                rr[5] = prng.get();
                rr[6] = prng.get();
                rr[7] = prng.get();

                w1[0] = ee1[rr[0]];
                w1[1] = ee1[rr[1]];
                w1[2] = ee1[rr[2]];
                w1[3] = ee1[rr[3]];
                w1[4] = ee1[rr[4]];
                w1[5] = ee1[rr[5]];
                w1[6] = ee1[rr[6]];
                w1[7] = ee1[rr[7]];

                w2[0] = ee2[rr[0]];
                w2[1] = ee2[rr[1]];
                w2[2] = ee2[rr[2]];
                w2[3] = ee2[rr[3]];
                w2[4] = ee2[rr[4]];
                w2[5] = ee2[rr[5]];
                w2[6] = ee2[rr[6]];
                w2[7] = ee2[rr[7]];

                auto ww1 =
                    w1[0] ^
                    w1[1] ^
                    w1[2] ^
                    w1[3] ^
                    w1[4] ^
                    w1[5] ^
                    w1[6] ^
                    w1[7];
                auto ww2 =
                    w2[0] ^
                    w2[1] ^
                    w2[2] ^
                    w2[3] ^
                    w2[4] ^
                    w2[5] ^
                    w2[6] ^
                    w2[7];

                if EA_CONSTEXPR (count > 8)
                {
                    T yy1;
                    T2 yy2;
                    expandOne<T, (count < 8 ? 0 : count - 8)>(ee1, ee2, yy1,yy2, prng);
                    ww1 = ww1 ^ yy1;
                    ww2 = ww2 ^ yy2;
                }

                y1 = ww1;
                y2 = ww2;

            }
            else
            {

                auto r = prng.get();
                T yy1;
                T2 yy2;
                expandOne<T, count - 1>(ee1, ee2, yy1, yy2, prng);
                y1 = ee1[r] ^ yy1;
                y2 = ee2[r] ^ yy2;
            }
        }



        template<typename T, u64 count>
        OC_FORCEINLINE typename std::enable_if<count == 1, T>::type
            expandOne(const T* __restrict ee, detail::ExpanderModd& prng) const
        {
            auto r = prng.get();
            return ee[r];
        }


        template<typename T, typename T2, u64 count>
        OC_FORCEINLINE typename std::enable_if<count == 1, T>::type
            expandOne(
                const T* __restrict ee1,
                const T2* __restrict ee2,
                T* __restrict y1,
                T2* __restrict y2,
                detail::ExpanderModd& prng) const
        {
            auto r = prng.get();
            *y1 = ee1[r];
            *y2 = ee2[r];
        }


        template<typename T, u64 count>
        OC_FORCEINLINE typename std::enable_if<count == 0, T>::type
            expandOne(const T* __restrict ee, detail::ExpanderModd& prng) const
        {
            return {};
        }


        template<typename T, typename T2, u64 count>
        OC_FORCEINLINE typename std::enable_if<count == 0, T>::type
            expandOne(
                const T* __restrict ee1,
                const T2* __restrict ee2,
                T* __restrict y1,
                T2* __restrict y2,
                detail::ExpanderModd& prng) const
        {
        }


        template<typename T>
        void expand(
            span<const T> e,
            span<T> w) const
        {
            assert(w.size() == mMessageSize);
            assert(e.size() == mCodeSize);
            detail::ExpanderModd prng(mSeed, mCodeSize);

            const T* __restrict  ee = e.data();
            T* __restrict  ww = w.data();

            auto main = mMessageSize / 8 * 8;
            u64 i = 0;

            for (; i < main; i += 8)
            {
#define CASE(I) \
                case I:\
                ww[i + 0] = expandOne<T, I>(ee, prng);\
                ww[i + 1] = expandOne<T, I>(ee, prng);\
                ww[i + 2] = expandOne<T, I>(ee, prng);\
                ww[i + 3] = expandOne<T, I>(ee, prng);\
                ww[i + 4] = expandOne<T, I>(ee, prng);\
                ww[i + 5] = expandOne<T, I>(ee, prng);\
                ww[i + 6] = expandOne<T, I>(ee, prng);\
                ww[i + 7] = expandOne<T, I>(ee, prng);\
                break

                switch (mExpanderWeight)
                {
                    CASE(7);
                    CASE(11);
                    CASE(21);
                default:
                    for (u64 jj = 0; jj < 8; ++jj)
                    {
                        auto r = prng.get();
                        auto wv = ee[r];

                        for (auto j = 1ull; j < mExpanderWeight; ++j)
                        {
                            r = prng.get();
                            wv = wv ^ ee[r];
                        }
                        ww[i + jj] = wv;
                    }
                }
#undef CASE
            }

            for (; i < mMessageSize; ++i)
            {
                auto wv = ee[prng.get()];
                for (auto j = 1ull; j < mExpanderWeight; ++j)
                    wv = wv ^ ee[prng.get()];
                ww[i] = wv;
            }
        }



        template<typename T, typename T2>
        void expand(
            span<const T> e1,
            span<const T2> e2,
            span<T> w1,
            span<T2> w2
        ) const
        {
            assert(w1.size() == mMessageSize);
            assert(w2.size() == mMessageSize);
            assert(e1.size() == mCodeSize);
            assert(e2.size() == mCodeSize);
            detail::ExpanderModd prng(mSeed, mCodeSize);

            const T* __restrict  ee1 = e1.data();
            const T2* __restrict  ee2 = e2.data();
            T* __restrict  ww1 = w1.data();
            T2* __restrict  ww2 = w2.data();

            auto main = mMessageSize / 8 * 8;
            u64 i = 0;

            for (; i < main; i += 8)
            {
#define CASE(I) \
                case I:\
                expandOne<T, T2, I>(ee1, ee2, ww1[i + 0],ww2[i + 0], prng);\
                expandOne<T, T2, I>(ee1, ee2, ww1[i + 1],ww2[i + 1], prng);\
                expandOne<T, T2, I>(ee1, ee2, ww1[i + 2],ww2[i + 2], prng);\
                expandOne<T, T2, I>(ee1, ee2, ww1[i + 3],ww2[i + 3], prng);\
                expandOne<T, T2, I>(ee1, ee2, ww1[i + 4],ww2[i + 4], prng);\
                expandOne<T, T2, I>(ee1, ee2, ww1[i + 5],ww2[i + 5], prng);\
                expandOne<T, T2, I>(ee1, ee2, ww1[i + 6],ww2[i + 6], prng);\
                expandOne<T, T2, I>(ee1, ee2, ww1[i + 7],ww2[i + 7], prng);\
                break

                switch (mExpanderWeight)
                {
                    CASE(5);
                    CASE(7);
                    CASE(9);
                    CASE(11);
                    CASE(21);
                    CASE(40);
                default:
                    for (u64 jj = 0; jj < 8; ++jj)
                    {
                        auto r = prng.get();
                        auto wv1 = ee1[r];
                        auto wv2 = ee2[r];

                        for (auto j = 1ull; j < mExpanderWeight; ++j)
                        {
                            r = prng.get();
                            wv1 = wv1 ^ ee1[r];
                            wv2 = wv2 ^ ee2[r];
                        }
                        ww1[i + jj] = wv1;
                        ww2[i + jj] = wv2;
                    }
                }
#undef CASE
            }

            for (; i < mMessageSize; ++i)
            {
                auto r = prng.get();
                auto wv1 = ee1[r];
                auto wv2 = ee2[r];
                for (auto j = 1ull; j < mExpanderWeight; ++j)
                {
                    r = prng.get();
                    wv1 = wv1 ^ ee1[r];
                    wv2 = wv2 ^ ee2[r];

                }
                ww1[i] = wv1;
                ww2[i] = wv2;
            }
        }

        SparseMtx getB() const
        {
            //PRNG prng(mSeed);
            detail::ExpanderModd prng(mSeed, mCodeSize);
            PointList points(mMessageSize, mCodeSize);

            std::vector<u64> row(mExpanderWeight);

            {

                for (auto i : rng(mMessageSize))
                {
                    row[0] = prng.get();
                    //points.push_back(i, row[0]);
                    for (auto j : rng(1, mExpanderWeight))
                    {
                        //do {
                        row[j] = prng.get();
                        //} while
                        auto iter = std::find(row.data(), row.data() + j, row[j]);
                        if (iter != row.data() + j)
                        {
                            row[j] = ~0ull;
                            *iter =  ~0ull;
                        }
                        //throw RTE_LOC;

                    }
                    for (auto j : rng(mExpanderWeight))
                    {

                        if (row[j] != ~0ull)
                        {
                            //std::cout << row[j] << " ";
                            points.push_back(i, row[j]);
                        }
                        else
                        {
                            //std::cout << "* ";
                        }
                    }
                    //std::cout << std::endl;
                }
            }

            return points;
        }

        // Get the parity check version of the accumulator
        SparseMtx getAPar() const
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

#undef EA_CONSTEXPR
}

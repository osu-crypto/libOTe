#pragma once

#include "cryptoTools/Common/Defines.h"
#include "libOTe/Tools/LDPC/Mtx.h"
#include "cryptoTools/Common/Range.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "libOTe/Tools/LDPC/LdpcEncoder.h"
#ifdef ENABLE_AVX
#define LIBDIVIDE_AVX2
#elif ENABLE_SSE
#define LIBDIVIDE_SSE2
#endif
#include "SqrtPerm.h"
#include "libdivide.h"
#include "TungstenData.h"

namespace osuCrypto
{


    template<
        typename Table>
        OC_FORCEINLINE SparseMtx getAccPar(u64 n, bool transposed)
    {

        PointList AP(n, n);;

        for (i64 i = 0; i < n; ++i)
        {
            //std::cout << "x[" << i << "] += ";
            AP.push_back(i, i);

            //if (i + 1 < n)
            //    AP.push_back(i + 1, i);


            if (transposed)
            {
                auto row = Table::data[i % Table::data.size()];
                auto xi = i;
                i64 xs = xi - Table::data.size() + 1;
                if (xs >= 0)
                {
                    //std::cout << " " << i64(xs);
                    AP.push_back(i, xs);
                }

                for (auto x : row)
                {
                    i64 xx = x + xs;
                    if (xx >= 0)
                    {
                        //std::cout << " " << i64(xx);
                        AP.push_back(i, xx);
                    }
                }
            }
            else
            {

                auto col = Table::data[i % Table::data.size()];
                for (auto x : col)
                {
                    //std::cout << " " << x + i;
                    if (x + i < n)
                        AP.push_back(x + i, i);
                }
                if (i + Table::data.size() - 1 < n)
                    AP.push_back(i + Table::data.size() - 1, i);
            }

            //std::cout << std::endl;
        }

        return AP;
    }

    template<typename Table>
    DenseMtx getAcc(u64 n, bool transposed)
    {
        auto APar = getAccPar<Table>(n, transposed);
        auto A = DenseMtx::Identity(n);

        //std::cout << A << std::endl << std::endl;

        //if (transposed)
        //{

        //    for (u64 i = 0; i < n; ++i)
        //    {
        //        for (auto y : APar.row(i))
        //        {
        //            if (y != i)
        //            {
        //                auto ay = A.row(y);
        //                auto ai = A.row(i);

        //                //for (auto j = 0; j < ay.size(); ++j)
        //                //{
        //                //    ai[j] = ai[j] ^ ay[j];
        //                //}
        //                ai ^= ay;
        //            }
        //        }
        //        //std::cout << i << "\n";
        //        //std::cout << A << std::endl << std::endl;
        //    }
        //}
        //else
        {

            for (u64 i = 0; i < n; ++i)
            {
                for (auto y : APar.col(i))
                {
                    if (y != i)
                    {
                        auto ay = A.row(y);
                        auto ai = A.row(i);
                        ay ^= ai;
                    }


                }
                //std::cout << i << "\n";
                //std::cout << A << std::endl << std::endl;
            }
        }

        return A;
    }


    template<
        typename Table,
        typename Perm,
        typename T,
        bool rangeCheck,
        bool verbose = false>
        OC_FORCEINLINE void accumulateBlock(T* xx, T* end, Perm& perm)
    {
        //auto& perm = mPerm;
        static constexpr int chunkSize = Perm::chunkSize;

        static_assert(Table::data.size() % chunkSize == 0, "");
        auto tIter = Table::data.data();
        for (u64 j = 0; j < Table::data.size();)
        {

            //_mm_prefetch((char*)(xx + j + Table::data.size()), _MM_HINT_T0);
            for (u64 k = 0; k < chunkSize; ++k, ++j)
            {

                T* __restrict xi = xx + j;
                T* __restrict xs = xi + Table::data.size() - 1;

                if constexpr (Table::data[0].size() == 4)
                {
                    T* __restrict x0 = xi + tIter[j].data()[0];
                    T* __restrict x1 = xi + tIter[j].data()[1];
                    T* __restrict x2 = xi + tIter[j].data()[2];
                    T* __restrict x3 = xi + tIter[j].data()[3];

                    //std::cout << "xs[" << j << "] += " << (Table::data.size() + 2) << std::endl;
                    //std::cout << "x0[" << j << "] += " << tIter[j][0] << std::endl;
                    //std::cout << "x1[" << j << "] += " << tIter[j][1] << std::endl;
                    //std::cout << "x2[" << j << "] += " << tIter[j][2] << std::endl;
                    //std::cout << "x3[" << j << "] += " << tIter[j][3] << std::endl;

                    if constexpr (rangeCheck)
                    {
                        if (xs < end) *xs = *xs ^ *xi;
                        if (x0 < end) *x0 = *x0 ^ *xi;
                        if (x1 < end) *x1 = *x1 ^ *xi;
                        if (x2 < end) *x2 = *x2 ^ *xi;
                        if (x3 < end) *x3 = *x3 ^ *xi;
                    }
                    else
                    {

                        auto xxs = *xs ^ *xi;
                        auto xx0 = *x0 ^ *xi;
                        auto xx1 = *x1 ^ *xi;
                        auto xx2 = *x2 ^ *xi;
                        auto xx3 = *x3 ^ *xi;

                        assert(x3 < end);
                        assert(xs < end);
                        *xs = xxs;
                        *x0 = xx0;
                        *x1 = xx1;
                        *x2 = xx2;
                        *x3 = xx3;

                    }
                }
                else if constexpr (Table::data[0].size() == 7)
                {
                    T* __restrict x0 = xi + Table::data[j][0];
                    T* __restrict x1 = xi + Table::data[j][1];
                    T* __restrict x2 = xi + Table::data[j][2];
                    T* __restrict x3 = xi + Table::data[j][3];
                    T* __restrict x4 = xi + Table::data[j][4];
                    T* __restrict x5 = xi + Table::data[j][5];
                    T* __restrict x6 = xi + Table::data[j][6];

                    if constexpr (rangeCheck)
                    {
                        if (xs < end) *xs = *xs ^ *xi;
                        if (x0 < end) *x0 = *x0 ^ *xi;
                        if (x1 < end) *x1 = *x1 ^ *xi;
                        if (x2 < end) *x2 = *x2 ^ *xi;
                        if (x3 < end) *x3 = *x3 ^ *xi;
                        if (x4 < end) *x4 = *x3 ^ *xi;
                        if (x5 < end) *x5 = *x5 ^ *xi;
                        if (x6 < end) *x6 = *x6 ^ *xi;
                    }
                    else
                    {
                        auto xxs = *xs ^ *xi;
                        auto xx0 = *x0 ^ *xi;
                        auto xx1 = *x1 ^ *xi;
                        auto xx2 = *x2 ^ *xi;
                        auto xx3 = *x3 ^ *xi;
                        auto xx4 = *x4 ^ *xi;
                        auto xx5 = *x5 ^ *xi;
                        auto xx6 = *x6 ^ *xi;

                        *xs = xxs;
                        *x0 = xx0;
                        *x1 = xx1;
                        *x2 = xx2;
                        *x3 = xx3;
                        *x4 = xx4;
                        *x5 = xx5;
                        *x6 = xx6;
                    }
                }
                else
                {
                    throw RTE_LOC;
                }

                perm.apply(xi, k);

                if constexpr (verbose)
                {
                    BitVector state;
                    state.reserve(Table::data.size());
                    auto base = (int)*(u8*)&xx[j] & 1;
                    for (u64 i : rng(Table::data.size()))
                    {
                        auto bit = (int)*(u8*)&xx[j + i] & 1;
                        if (i == 1 || std::find(Table::data[j].begin(), Table::data[j].end(), i) != Table::data[j].end())
                        {
                            std::cout << state << (base ? Color::Green : Color::Red) << bit << Color::Default;
                            state.resize(0);
                        }
                        else
                            state.pushBack(bit);
                    }
                    if (state.size())
                        std::cout << state;
                    std::cout << std::endl;
                }
            }

            perm.applyChunk(xx + j - chunkSize);
        }
    }


    template<
        typename Table,
        typename Perm,
        typename T,
        bool rangeCheck,
        bool verbose = false>
        OC_FORCEINLINE void accumulateBlock2(T* xx, T* b, T* e, Perm& perm)
    {
        //auto& perm = mPerm;
        static constexpr int chunkSize = Perm::chunkSize;
        //auto e = xx - Table::data.size();
        static_assert(Table::data.size() % chunkSize == 0, "");
        auto tIter = Table::data.data();

        for (u64 j = 0; j < Table::data.size();)
        {

            _mm_prefetch((char*)(xx + j + Table::data.size() * 2), _MM_HINT_T0);
            for (u64 k = 0; k < chunkSize; ++k, ++j)
            {

                auto i = xx - b;

                T* const  __restrict xi = xx + j;
                T* __restrict xs = xi - Table::data.size() + 1;
                //T* __restrict xs = xi - 1;

                if constexpr (Table::data[0].size() == 4)
                {
                    T* const  __restrict x0 = xs + tIter[j].data()[0];
                    T* const  __restrict x1 = xs + tIter[j].data()[1];
                    T* const  __restrict x2 = xs + tIter[j].data()[2];
                    T* const  __restrict x3 = xs + tIter[j].data()[3];

                    if (x0 >= b)
                    {
                        //assert(A(i, (x0 - b)) == 1);
                    }

                    assert(x3 < e);
                    assert(xi < e);

                    if constexpr (rangeCheck)
                    {
                        if (xs >= b) *xi = *xs ^ *xi;
                        if (x0 >= b) *xi = *x0 ^ *xi;
                        if (x1 >= b) *xi = *x1 ^ *xi;
                        if (x2 >= b) *xi = *x2 ^ *xi;
                        if (x3 >= b) *xi = *x3 ^ *xi;
                    }
                    else
                    {
                        //std::cout << (xs - b)
                        //    << " + " << (x0 - b)
                        //    << " + " << (x1 - b)
                        //    << " + " << (x2 - b)
                        //    << " + " << (x3 - b);


                        assert(xs >= b);

                        *xi = *xi
                            ^ *xs
                            ^ *x0
                            ^ *x1
                            ^ *x2
                            ^ *x3;
                    }
                    //std::cout << "\n";
                }
                //else if constexpr (Table::data[0].size() == 7)
                //{

                //    T* __restrict x0 = xb + Table::data[j][0];
                //    T* __restrict x1 = xb + Table::data[j][1];
                //    T* __restrict x2 = xb + Table::data[j][2];
                //    T* __restrict x3 = xb + Table::data[j][3];
                //    T* __restrict x4 = xb + Table::data[j][4];
                //    T* __restrict x5 = xb + Table::data[j][5];
                //    T* __restrict x6 = xb + Table::data[j][6];

                //    if constexpr (rangeCheck)
                //    {
                //        if (xs >= e) *xi = *xs ^ *xi;
                //        if (x0 >= e) *xi = *x0 ^ *xi;
                //        if (x1 >= e) *xi = *x1 ^ *xi;
                //        if (x2 >= e) *xi = *x2 ^ *xi;
                //        if (x3 >= e) *xi = *x3 ^ *xi;
                //        if (x4 >= e) *xi = *x3 ^ *xi;
                //        if (x5 >= e) *xi = *x5 ^ *xi;
                //        if (x6 >= e) *xi = *x6 ^ *xi;
                //    }
                //    else
                //    {
                //        *xi = *xi
                //            ^ *xs
                //            ^ *x0
                //            ^ *x1
                //            ^ *x2
                //            ^ *x3
                //            ^ *x4
                //            ^ *x5
                //            ^ *x6;
                //    }
                //}
                else
                {
                    throw RTE_LOC;
                }

                perm.apply(xi, k);
            }

            perm.applyChunk(xx + j - chunkSize);
        }
    }

    template<typename T, typename Table_ /*= TableTungsten1024x4*/>
    struct TableAcc
    {
        using Table = Table_;
        static constexpr int blockSize = Table::data.size();

        std::array<T, blockSize * 2> mBuffer;
        bool mFirst = true;

        void reset()
        {
            mFirst = true;
        }

        template<bool rangeCheck, typename Perm>
        OC_FORCEINLINE void processBlock(T* xx, T* end, Perm& perm)
        {
            accumulateBlock<Table, Perm, T, rangeCheck>(xx, end, perm);
        }

        void run(span<T> x)
        {

            T* __restrict xx = x.data();
            auto end = x.data() + x.size();
            NoopPerm noop;

            update(x, noop);
            processBlock<true>(end - blockSize, end, noop);

        }

        template<typename Perm>
        void update(span<T> x, Perm& perm)
        {
            if (x.size() == 0 || (x.size() % blockSize))
                throw RTE_LOC;
            auto xx_ = x.data();
            auto rem = x.size() - blockSize;

            if (mFirst)
            {
                if (rem)
                {
                    for (u64 i = 0; i < rem; )
                    {
                        processBlock<false>(xx_ + i, x.data() + x.size(), perm);
                        i += blockSize;
                    }
                }

                memcpy(mBuffer.data(), x.data() + rem, blockSize * sizeof(T));
            }
            else
            {
                memcpy(mBuffer.data() + blockSize, xx_, blockSize * sizeof(T));
                processBlock<false>(mBuffer.data(), mBuffer.data() + mBuffer.size(), perm);
                memcpy(xx_, mBuffer.data() + blockSize, blockSize * sizeof(T));

                T* src;
                if (rem)
                {
                    for (u64 i = 0; i < rem; )
                    {
                        processBlock<false>(xx_ + i, x.data() + x.size(), perm);
                        i += blockSize;
                    }

                    src = x.data() + rem;
                }
                else
                    src = mBuffer.data() + blockSize;

                memcpy(mBuffer.data(), src, blockSize * sizeof(T));
            }

            mFirst = false;
        }


        template<typename Perm>
        void finalize(Perm& perm)
        {
            processBlock<true>(mBuffer.data(), mBuffer.data() + mBuffer.size(), perm);
            perm.finalize();
        }



        SparseMtx getAPar(u64 n)const
        {
            return getAccPar<Table>(n, false);
        }
        DenseMtx getA(u64 n) const
        {
            return getAcc<Table>(n, false);
        }

    };

    template<typename T, typename Table_ >
    struct TableAccTrans
    {

        using Table = Table_;
        static constexpr int blockSize = Table::data.size();

        std::array<T, blockSize * 2> mBuffer;
        bool mFirst = true;

        void reset()
        {
            mFirst = true;
        }

        template<bool rangeCheck, typename Perm>
        OC_FORCEINLINE void processBlock(T* xx, T* begin, T* end, Perm& perm)
        {
            accumulateBlock2<Table, Perm, T, rangeCheck>(xx, begin, end, perm);
        }


        void run(span<T> x)
        {
            NoopPerm noop;
            update(x, noop);
        }

        template<typename Perm>
        void update(span<T> x, Perm& perm)
        {
            if (x.size() == 0 || (x.size() % blockSize))
                throw RTE_LOC;
            auto xx_ = x.data();
            auto rem = x.size();

            if (mFirst)
            {
                auto e = x.data() + x.size();
                if (rem)
                {
                    processBlock<true>(xx_, xx_, e, perm);
                    for (u64 i = blockSize; i < rem; )
                    {
                        processBlock<false>(xx_ + i, xx_, e, perm);
                        i += blockSize;
                    }
                }

                memcpy(mBuffer.data(), x.data() + rem - blockSize, blockSize * sizeof(T));
                mFirst = false;
            }
            else
            {
                auto buffMid = mBuffer.data() + blockSize;
                memcpy(buffMid, xx_, blockSize * sizeof(T));
                processBlock<false>(buffMid, mBuffer.data(), mBuffer.data() + mBuffer.size(), perm);
                memcpy(xx_, buffMid, blockSize * sizeof(T));

                T* src;
                if (rem)
                {
                    for (u64 i = blockSize; i < rem; )
                    {
                        processBlock<false>(xx_ + i, xx_, x.data() + x.size(), perm);
                        i += blockSize;
                    }

                    src = x.data() + rem - blockSize;
                }
                else
                    src = buffMid;

                memcpy(mBuffer.data(), src, blockSize * sizeof(T));
            }

        }


        template<typename Perm>
        void finalize(Perm& perm)
        {
            perm.finalize();



        }



        SparseMtx getAPar(u64 n)const
        {
            return getAccPar<Table>(n, true);
        }
        DenseMtx getA(u64 n) const
        {
            return getAcc<Table>(n, true);
        }

    };

}
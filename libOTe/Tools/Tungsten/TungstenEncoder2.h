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
#include "TungstenPerm.h"
#include "TungstenAccumulator.h"
namespace osuCrypto
{

    template<
        typename T_ = block, 
        typename Expander_ = TungstenPerm<T_, 8>, 
        typename Acc_ = TableAcc<T_, TableTungsten1024x4>,
        typename Acc2_ = Acc_
    >
    struct Tungsten2 : public TimerAdapter
    {
        using T = T_;
        using Expander = Expander_;
        using Acc = Acc_;
        using Acc2 = Acc2_;

        bool accTwice = true;
        static constexpr int chunkSize = Expander::chunkSize;
        static constexpr int blockSize = Acc::blockSize;

        //using Expander = TungstenBinExpander<T, chunkSize>;
        //using Expander = TungstenExpander<T, chunkSize>;
        //using Table = TableTungsten128x4;
        //using Table = TableTungsten8x4;

        bool mFirst = true;
        u64 mExpanderWeight = 0;
        Expander mExpander;
        Acc mAcc;


        Tungsten2(u64 size, u64 expanderWeight)
            : mExpander(size)
            , mExpanderWeight(expanderWeight)
        {
            reset();
        }

        void reset()
        {
            mFirst = true;
            mAcc.reset();
            mExpander.reset();
        }

        void update(span<T> x)
        {
            mAcc.update(x, mExpander);
        }

        //template<bool rangeCheck = false>
        //OC_FORCEINLINE void processBlock2(T* x, T* xb, T* xe)
        //{
        //    accumulateBlock2<Table, Expander, T, rangeCheck>(x, xb, xe, mExpander);
        //}


        //void update2(span<T> x)
        //{
        //    assert(x.size() && (x.size() % Table::data.size() == 0));

        //    auto xx_ = x.data();
        //    auto rem = x.size() - Table::data.size();
        //    auto e = x.data() + x.size();

        //    if (mFirst)
        //    {
        //        processBlock2<true>(xx_, xx_, e);

        //        for (u64 i = Table::data.size(); i < rem; i += Table::data.size())
        //        {
        //            processBlock2(xx_ + i, xx_, e);
        //        }

        //        memcpy(mBuffer.data(), x.data() + rem, Table::data.size() * sizeof(T));
        //    }
        //    else
        //    {
        //        memcpy(mBuffer.data() + Table::data.size(), x.data(), Table::data.size() * sizeof(T));
        //        processBlock2(mBuffer.data(), mBuffer.data(), mBuffer.data() + mBuffer.size());

        //        T* src;
        //        if (rem)
        //        {
        //            memcpy(
        //                x.data(),
        //                mBuffer.data() + Table::data.size(),
        //                Table::data.size() * sizeof(T));

        //            for (u64 i = Table::data.size(); i < rem; i += Table::data.size())
        //            {
        //                processBlock2(xx_ + i, xx_, e);
        //            }

        //            src = x.data() + rem;
        //        }
        //        else
        //            src = mBuffer.data() + Table::data.size();

        //        memcpy(mBuffer.data(), src, Table::data.size() * sizeof(T));
        //    }

        //    mFirst = false;
        //}



        void finalize(span<T> w)
        {
            mAcc.finalize(mExpander);


            if (accTwice)
            {

                Acc2 acc;
                acc.run(mExpander.mBuffer);
                setTimePoint("acc2");
            }


            linearSums<T>(mExpander.mBuffer, w, mExpanderWeight);

        }


        SparseMtx getAPar()
        {
            return mAcc.getAPar(mExpander.mBuffer.size());
        }
        DenseMtx getA()
        {
            return mAcc.getA(mExpander.mBuffer.size());
        }

        SparseMtx getP()
        {
            return mExpander.getMatrix();
        }

        SparseMtx getS()
        {
            return getLinearSums(mExpander.mBuffer.size(), mExpanderWeight);
        }
    };


    template<
        typename T_ = block,
        typename Expander_ = TungstenPerm<T_, 8>,
        typename Acc_ = TableAcc<T_, TableTungsten1024x4>,
        typename Acc2_ = Acc_
    >
        struct Tungsten3 : public TimerAdapter
    {
        using T = T_;
        using Expander = Expander_;
        using Acc = Acc_;
        using Acc2 = Acc2_;

        bool accTwice = true;
        static constexpr int chunkSize = Expander::chunkSize;
        static constexpr int blockSize = Acc::blockSize;

        bool mFirst = true;
        Expander mExpander;
        Acc mAcc;


        Tungsten3(u64 size)
            : mExpander(size)
        {
            reset();
        }

        void reset()
        {
            mFirst = true;
            mAcc.reset();
            mExpander.reset();
        }

        void update(span<T> x)
        {
            mAcc.update(x, mExpander);
        }

        void finalize(span<T> w)
        {
            mAcc.finalize(mExpander);
            //EveryOther<T,8> eo(w);
            //RepTwo<T,8> eo(w);
            Acc2 acc;
            {
                SMemcpy<T,8> eo(w);
                acc.run(span<T>(mExpander.mBuffer.data(), w.size()), eo);
            }
            {
                SXor<T, 8> eo(w);
                acc.run(span<T>(mExpander.mBuffer.data()+ w.size(), w.size()), eo);
            }
            setTimePoint("acc2");
        }

        SparseMtx getAPar()
        {
            return mAcc.getAPar(mExpander.mBuffer.size());
        }
        DenseMtx getA()
        {
            return mAcc.getA(mExpander.mBuffer.size());
        }

        SparseMtx getP()
        {
            return mExpander.getMatrix();
        }

        SparseMtx getS()
        {
            //return EveryOther<T, 8>::getMatrix(mExpander.mBuffer.size());
            return RepTwo<T, 8>::getMatrix(mExpander.mBuffer.size());
        }
    };


}
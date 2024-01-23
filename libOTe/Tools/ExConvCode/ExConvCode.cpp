#include "ExConvCode.h"

namespace osuCrypto
{


    // configure the code. The default parameters are choses to balance security and performance.
    // For additional parameter choices see the paper.


    //// get the expander matrix
    //SparseMtx ExConvCode::getB() const
    //{
    //    throw RTE_LOC;
    //    //if (mSystematic)
    //    //{
    //    //    PointList R(mMessageSize, mCodeSize);
    //    //    auto B = mExpander.getB().points();

    //    //    for (auto p : B)
    //    //    {
    //    //        R.push_back(p.mRow, mMessageSize + p.mCol);
    //    //    }
    //    //    for (u64 i = 0; i < mMessageSize; ++i)
    //    //        R.push_back(i, i);

    //    //    return R;
    //    //}
    //    //else
    //    //{
    //    //    return mExpander.getB();
    //    //}
    //}


    // Get the parity check version of the accumulator
    //SparseMtx  ExConvCode::getAPar() const
    //{
    //    throw RTE_LOC;
    //    //PRNG prng(mSeed ^ OneBlock);

    //    //auto n = mCodeSize - mSystematic * mMessageSize;

    //    //PointList AP(n, n);;
    //    //DenseMtx A = DenseMtx::Identity(n);

    //    //block rnd;
    //    //u8* __restrict ptr = (u8*)prng.mBuffer.data();
    //    //auto qe = prng.mBuffer.size() * 128;
    //    //u64 q = 0;

    //    //for (u64 i = 0; i < n; ++i)
    //    //{
    //    //    accOne(AP, i, ptr, prng, rnd, q, qe, n);
    //    //}
    //    //return AP;
    //}

    //// get the accumulator matrix
    //SparseMtx  ExConvCode::getA() const
    //{
    //    auto APar = getAPar();

    //    auto A = DenseMtx::Identity(mCodeSize);

    //    u64 offset = mSystematic ? mMessageSize : 0ull;

    //    for (u64 i = 0; i < APar.rows(); ++i)
    //    {
    //        for (auto y : APar.col(i))
    //        {
    //            if (y != i)
    //            {
    //                auto ay = A.row(y + offset);
    //                auto ai = A.row(i + offset);
    //                ay ^= ai;
    //            }
    //        }
    //    }

    //    return A.sparse();
    //}


}
#include "ExConvCode2.h"
//#include "ExConvCode2Impl.h"
#include "libOTe/Tools/Subfield/Subfield.h"

namespace osuCrypto
{


    //template void ExConvCode2::dualEncode<block, CoeffCtxGF>(span<block> e);
    //template void ExConvCode2::dualEncode<block, CoeffCtxGF>(span<block> e, span<block> w);
    //
    //template void ExConvCode2::dualEncode<u8, CoeffCtxGF>(span<u8> e);
    //template void ExConvCode2::dualEncode<u8, CoeffCtxGF>(span<u8> e, span<u8> w);

    //template void ExConvCode2::dualEncode2<block, u8, CoeffCtxGF>(span<block>, span<u8> e);
    //template void ExConvCode2::accumulate<block, u8, CoeffCtxGF>(span<block>, span<u8> e);

    //template void ExConvCode2::dualEncode2<block, block>(span<block>, span<block> e);
    //template void ExConvCode2::accumulate<block, block, CoeffCtxGF>(span<block>, span<block> e);


    // configure the code. The default parameters are choses to balance security and performance.
    // For additional parameter choices see the paper.
    void ExConvCode2::config(
        u64 messageSize,
        u64 codeSize,
        u64 expanderWeight,
        u64 accumulatorSize,
        bool systematic,
        block seed)
    {
        if (codeSize == 0)
            codeSize = 2 * messageSize;

        mSeed = seed;
        mMessageSize = messageSize;
        mCodeSize = codeSize;
        mAccumulatorSize = accumulatorSize;
        mSystematic = systematic;
        mExpander.config(messageSize, codeSize - messageSize * systematic, expanderWeight, seed ^ CCBlock);
    }

    //// get the expander matrix
    //SparseMtx ExConvCode2::getB() const
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
    //SparseMtx  ExConvCode2::getAPar() const
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
    //SparseMtx  ExConvCode2::getA() const
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
#include "Base/naor-pinkas.h"
#include "KkrtNcoOtReceiver.h"
#include "Tools/Tools.h"
#include "Common/Log.h"
#include  <mmintrin.h>
#include "KkrtDefines.h"
using namespace std;

namespace osuCrypto
{
    void KkrtNcoOtReceiver::setBaseOts(
        ArrayView<std::array<block, 2>> baseRecvOts)
    {


        if (baseRecvOts.size() % 128 != 0)
            throw std::runtime_error("rt error at " LOCATION);

        mGens.resize(baseRecvOts.size());

        for (u64 i = 0; i < mGens.size(); i++)
        {
            mGens[i][0].SetSeed(baseRecvOts[i][0]);
            mGens[i][1].SetSeed(baseRecvOts[i][1]);
        }
        mHasBase = true;
    }


    void KkrtNcoOtReceiver::init(u64 numOtExt)
    {

        if (mHasBase == false)
            throw std::runtime_error("rt error at " LOCATION);

        static const u64 superBlkSize(8);

        // this will be used as temporary buffers of 128 columns, 
        // each containing 1024 bits. Once transposed, they will be copied
        // into the T1, T0 buffers for long term storage.
        std::array<std::array<block, superBlkSize>, 128> t0;
        std::array<std::array<block, superBlkSize>, 128> t1;

        // we are going to process OTs in blocks of 128 * superblkSize messages.
        u64 numSuperBlocks = ((numOtExt + 127) / 128 + superBlkSize - 1) / superBlkSize;
        u64 numCols = mGens.size();

        // We need two matrices, T0 and T1. These will hold the expanded and transposed
        // rows that we got the using the base OTs as PRNG seed.
        mT0 = std::move(MatrixView<block>(numOtExt, numCols / 128));
        mT1 = std::move(MatrixView<block>(numOtExt, numCols / 128));

        // The is the index of the last correction value u = T0 ^ T1 ^ c(w)
        // that was sent to the sender.
        mCorrectionIdx = 0;

        // the index of the OT that has been completed.
        u64 doneIdx = 0;

        // NOTE: We do not transpose a bit-matrix of size numCol * numCol.
        //   Instead we break it down into smaller chunks. We do 128 columns 
        //   times 8 * 128 rows at a time, where 8 = superBlkSize. This is done for  
        //   performance reasons. The reason for 8 is that most CPUs have 8 AES vector  
        //   lanes, and so its more efficient to encrypt (aka prng) 8 blocks at a time.
        //   So that's what we do. 
        for (u64 superBlkIdx = 0; superBlkIdx < numSuperBlocks; ++superBlkIdx)
        {
            // compute at what row does the user want us to stop.
            // The code will still compute the transpose for these
            // extra rows, but it is thrown away.
            u64 stopIdx
                = doneIdx
                + std::min(u64(128) * superBlkSize, numOtExt - doneIdx);


            for (u64 i = 0; i < numCols / 128; ++i)
            {

                for (u64 tIdx = 0, colIdx = i * 128; tIdx < 128; ++tIdx, ++colIdx)
                {
                    // generate the column indexed by colIdx. This is done with
                    // AES in counter mode acting as a PRNG. We don't use the normal
                    // PRNG interface because that would result in a data copy when 
                    // we move it into the T0,T1 matrices. Instead we do it directly.
                    mGens[colIdx][0].mAes.ecbEncCounterMode(mGens[colIdx][0].mBlockIdx, superBlkSize, ((block*)t0.data() + superBlkSize * tIdx));
                    mGens[colIdx][1].mAes.ecbEncCounterMode(mGens[colIdx][1].mBlockIdx, superBlkSize, ((block*)t1.data() + superBlkSize * tIdx));

                    // increment the counter mode idx.
                    mGens[colIdx][0].mBlockIdx += superBlkSize;
                    mGens[colIdx][1].mBlockIdx += superBlkSize;
                }

                // transpose our 128 columns of 1024 bits. We will have 1024 rows, 
                // each 128 bits wide.
                sse_transpose128x1024(t0);
                sse_transpose128x1024(t1);

                // This is the index of where we will store the matrix long term.
                // doneIdx is the starting row. i is the offset into the blocks of 128 bits.
                // __restrict isn't crucial, it just tells the compiler that this pointer
                // is unique and it shouldn't worry about pointer aliasing. 
                block* __restrict mT0Iter = mT0.data() + mT0.size()[1] * doneIdx + i;
                block* __restrict mT1Iter = mT1.data() + mT1.size()[1] * doneIdx + i;

                for (u64 rowIdx = doneIdx, j = 0; rowIdx < stopIdx; ++j)
                {
                    // because we transposed 1024 rows, the indexing gets a bit weird. But this
                    // is the location of the next row that we want. Keep in mind that we had long
                    // **contiguous** columns. 
                    block* __restrict t0Iter = ((block*)t0.data()) + j;
                    block* __restrict t1Iter = ((block*)t1.data()) + j;

                    // do the copy!
                    for (u64 k = 0; rowIdx < stopIdx && k < 128; ++rowIdx, ++k)
                    {
                        *mT0Iter = *(t0Iter);
                        *mT1Iter = *(t1Iter);

                        t0Iter += superBlkSize;
                        t1Iter += superBlkSize;

                        mT0Iter += mT0.size()[1];
                        mT1Iter += mT0.size()[1];
                    }
                }
            }

            doneIdx = stopIdx;
        }

    }


    std::unique_ptr<NcoOtExtReceiver> KkrtNcoOtReceiver::split()
    {
        auto* raw = new KkrtNcoOtReceiver();

        std::vector<std::array<block, 2>> base(mGens.size());

        for (u64 i = 0; i < base.size(); ++i)
        {
            base[i][0] = mGens[i][0].get<block>();
            base[i][1] = mGens[i][1].get<block>();
        }
        raw->setBaseOts(base);

        return std::unique_ptr<NcoOtExtReceiver>(raw);
    }

    void KkrtNcoOtReceiver::encode(
        u64 otIdx,
        const ArrayView<block> choice, 
        block & val)
    {
#ifndef NDEBUG
        if (choice.size() != mT0.size()[1])
            throw std::invalid_argument("");

        if (eq(mT0[otIdx][0], ZeroBlock))
            throw std::runtime_error("uninitialized OT extension");

        if (eq(mT0[otIdx][0], AllOneBlock))
            throw std::runtime_error("This otIdx has already been encoded");
#endif // !NDEBUG

        block* t0Val = mT0.data() + mT0.size()[1] * otIdx;
        block* t1Val = mT1.data() + mT0.size()[1] * otIdx;

        // encode the correction value as u = T0 + T1 + c(w), there c(w) is a pseudo-random codeword.
        for (u64 i = 0; i < mT0.size()[1]; ++i)
        {
            // reuse mT1 as the place we store the correlated value. 
            // this will later get sent to the sender.
            t1Val[i]
                = choice[i]
                ^ t0Val[i]
                ^ t1Val[i];
        }

#ifdef KKRT_SHA_HASH

        // now hash it to remove the correlation.
        SHA1  sha1;
        u8 hashBuff[SHA1::HashSize];

        sha1.Update((u8*)mT0[otIdx].data(), mT0[otIdx].size() * sizeof(block));
        sha1.Final(hashBuff);

        val = toBlock(hashBuff);
#else
        std::array<block, 10> aesBuff;
        mAesFixedKey.ecbEncBlocks(t0Val, mT0.size()[1], aesBuff.data());

        val = ZeroBlock;
        for (u64 i = 0; i < mT0.size()[1]; ++i)
            val = val ^ aesBuff[i] ^ t0Val[i];
#endif
#ifndef NDEBUG
        // a debug check to mark this OT as used and ready to send.
        mT0[otIdx][0] = AllOneBlock;
#endif

    }

    void KkrtNcoOtReceiver::zeroEncode(u64 otIdx)
    {
#ifndef NDEBUG
        if (eq(mT0[otIdx][0], ZeroBlock))
            throw std::runtime_error("uninitialized OT extension");

        if (eq(mT0[otIdx][0], AllOneBlock))
            throw std::runtime_error("This otIdx has already been encoded");
#endif // !NDEBUG

        block* t0Val = mT0.data() + mT0.size()[1] * otIdx;
        block* t1Val = mT1.data() + mT0.size()[1] * otIdx;

        // This is here in the case that you done want to encode a message.
        // It s more efficient since we don't call SHA.
        for (u64 i = 0; i < mT0.size()[1]; ++i)
        {
            // reuse mT1 as the place we store the correlated value. 
            // this will later get sent to the sender.
            t1Val[i]
                = t0Val[i]
                ^ t1Val[i];
        }

#ifndef NDEBUG
        // a debug check to mark this OT as used and ready to send.
        mT0[otIdx][0] = AllOneBlock;
#endif
    }

    void KkrtNcoOtReceiver::getParams(
        bool maliciousSecure,
        u64 compSecParm,
        u64 statSecParam,
        u64 inputBitCount,
        u64 inputCount,
        u64 & inputBlkSize,
        u64 & baseOtCount)
    {
        //if (maliciousSecure) throw std::runtime_error("");

        baseOtCount = roundUpTo(compSecParm * (maliciousSecure? 7 : 4), 128);
        inputBlkSize = baseOtCount / 128;
    }

    void KkrtNcoOtReceiver::sendCorrection(Channel & chl, u64 sendCount)
    {
#ifndef NDEBUG
        // make sure these OTs all contain valid correction values, aka encode has been called.
        for (u64 i = mCorrectionIdx; i < mCorrectionIdx + sendCount; ++i)
            if (neq(mT0[i][0], AllOneBlock))
                throw std::runtime_error("This send request contains uninitialized OT. Call encode first...");
#endif

        // this is potentially dangerous. We dont have a guarantee that mT1 will still exist when 
        // the network gets around to sending this. Oh well.
        TODO("Make this memory safe");
        chl.asyncSend(mT1.data() + (mCorrectionIdx * mT1.size()[1]), mT1.size()[1] * sendCount * sizeof(block));

        mCorrectionIdx += sendCount;
    }

}

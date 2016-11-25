#include "KosDotExtReceiver.h"
#include "Tools/Tools.h"
#include "Common/Log.h"
#include "Common/ByteStream.h"
#include "Common/BitVector.h"
#include "Crypto/PRNG.h"
#include "Crypto/Commit.h"
#include "TcoOtDefines.h"
#include <queue>

using namespace std;

namespace osuCrypto
{
    void KosDotExtReceiver::setBaseOts(ArrayView<std::array<block, 2>> baseOTs)
    {

        PRNG prng(ZeroBlock);
        mCode.random(prng, baseOTs.size(), 128);

        mGens.resize(baseOTs.size());
        for (u64 i = 0; i < baseOTs.size(); i++)
        {
            mGens[i][0].SetSeed(baseOTs[i][0]);
            mGens[i][1].SetSeed(baseOTs[i][1]);
        }


        mHasBase = true;
    }
    std::unique_ptr<OtExtReceiver> KosDotExtReceiver::split()
    {
        std::vector<std::array<block, 2>>baseRecvOts(mGens.size());

        for (u64 i = 0; i < mGens.size(); ++i)
        {
            baseRecvOts[i][0] = mGens[i][0].get<block>();
            baseRecvOts[i][1] = mGens[i][1].get<block>();
        }

        auto dot = new KosDotExtReceiver();
        dot->mCode = mCode;

        std::unique_ptr<OtExtReceiver> ret(dot);

        ret->setBaseOts(baseRecvOts);

        return std::move(ret);
    } 


    void KosDotExtReceiver::receive(
        const BitVector& choices,
        ArrayView<block> messages,
        PRNG& prng,
        Channel& chl)
    {

        if (mHasBase == false)
            throw std::runtime_error("rt error at " LOCATION);



        // we are going to process OTs in blocks of 128 * superBlkSize messages.
        u64 numOtExt = roundUpTo(choices.size(), 128);
        u64 numSuperBlocks = (numOtExt / 128 + superBlkSize) / superBlkSize;
        u64 numBlocks = numSuperBlocks * superBlkSize;

        // commit to as seed which will be used to 
        block seed = prng.get<block>();
        Commit myComm(seed);
        chl.asyncSend(myComm.data(), myComm.size());

        PRNG zPrng(ZeroBlock);
        // turn the choice vbitVector into an array of blocks. 
        BitVector choices2(numBlocks * 128);
        //choices2.randomize(zPrng);
        choices2 = choices;
        choices2.resize(numBlocks * 128);
        for (u64 i = 0; i < 128; ++i)
        { 
            choices2[choices.size() + i] = prng.getBit();

            //std::cout << "extra " << i << "  " << choices2[choices.size() + i] << std::endl;
        }

        auto choiceBlocks = choices2.getArrayView<block>();
        // this will be used as temporary buffers of 128 columns, 
        // each containing 1024 bits. Once transposed, they will be copied
        // into the T1, T0 buffers for long term storage.
        std::array<std::array<block, superBlkSize>, 128> t0;

        // the index of the OT that has been completed.
        //u64 doneIdx = 0;

        std::array<std::array<block,2>, 128> extraBlocks;
        auto xIter = extraBlocks.data();
        auto xIterMaster = xIter;
        //u64 extraIdx = 0;

        std::vector<block> messages1(messages.size());

        block* mEnd0 = messages.data() + messages.size();
        block* mEnd1 = messages1.data() + messages1.size();
        block* mIter0 = messages.data();
        block* mIter1 = messages1.data();

        u64 step = std::min(numSuperBlocks, (u64)commStepSize);
        std::unique_ptr<ByteStream> uBuff(new ByteStream(step * mGens.size() * superBlkSize * sizeof(block)));

        // get an array of blocks that we will fill. 
        auto uIter = (block*)uBuff->data();
        auto uEnd = uIter + step * mGens.size() * superBlkSize;


        u64 colStepCount = (mGens.size() + 127) / 128;

        // we assume we have the number of columns of between 129 and 256...
        if (colStepCount != 2)
            throw std::runtime_error(LOCATION);



        // NOTE: We do not transpose a bit-matrix of size numCol * numCol.
        //   Instead we break it down into smaller chunks. We do 128 columns 
        //   times 8 * 128 rows at a time, where 8 = superBlkSize. This is done for  
        //   performance reasons. The reason for 8 is that most CPUs have 8 AES vector  
        //   lanes, and so its more efficient to encrypt (aka prng) 8 blocks at a time.
        //   So that's what we do. 
        for (u64 superBlkIdx = 0; superBlkIdx < numSuperBlocks; ++superBlkIdx)
        {

            // the users next 128 choice bits. This will select what message is receiver.
            block* cIter = choiceBlocks.data() + superBlkSize * superBlkIdx;

            // this will store the next 128 rows of the matrix u
            for (u64 colStepIdx = 0; colStepIdx < 2; ++colStepIdx)
            {

                block* tIter = (block*)t0.data();
                memset(t0.data(), 0, superBlkSize * 128 * sizeof(block));


                u64 colStop = std::min((colStepIdx + 1)* 128, mGens.size());

                // transpose 128 columns at at time. Each column will be 128 * superBlkSize = 1024 bits long.
                for (u64 colIdx = colStepIdx * 128; colIdx < colStop; ++colIdx)
                {
                    // generate the column indexed by colIdx. This is done with
                    // AES in counter mode acting as a PRNG. We don't use the normal
                    // PRNG interface because that would result in a data copy when 
                    // we move it into the T0,T1 matrices. Instead we do it directly.
                    mGens[colIdx][0].mAes.ecbEncCounterMode(mGens[colIdx][0].mBlockIdx, superBlkSize, tIter);
                    mGens[colIdx][1].mAes.ecbEncCounterMode(mGens[colIdx][1].mBlockIdx, superBlkSize, uIter);


                    // increment the counter mode idx.
                    mGens[colIdx][0].mBlockIdx += superBlkSize;
                    mGens[colIdx][1].mBlockIdx += superBlkSize;

                    uIter[0] = uIter[0] ^ cIter[0];
                    uIter[1] = uIter[1] ^ cIter[1];
                    uIter[2] = uIter[2] ^ cIter[2];
                    uIter[3] = uIter[3] ^ cIter[3];
                    uIter[4] = uIter[4] ^ cIter[4];
                    uIter[5] = uIter[5] ^ cIter[5];
                    uIter[6] = uIter[6] ^ cIter[6];
                    uIter[7] = uIter[7] ^ cIter[7];

                    uIter[0] = uIter[0] ^ tIter[0];
                    uIter[1] = uIter[1] ^ tIter[1];
                    uIter[2] = uIter[2] ^ tIter[2];
                    uIter[3] = uIter[3] ^ tIter[3];
                    uIter[4] = uIter[4] ^ tIter[4];
                    uIter[5] = uIter[5] ^ tIter[5];
                    uIter[6] = uIter[6] ^ tIter[6];
                    uIter[7] = uIter[7] ^ tIter[7];

                    uIter += 8;
                    tIter += 8;
                }


                if (uIter == uEnd)
                {
                    // send over u buffer
                    chl.asyncSend(std::move(uBuff));

                    u64 step = std::min(numSuperBlocks - superBlkIdx - 1, (u64)commStepSize);

                    if (step)
                    {
                        uBuff.reset(new ByteStream(step * mGens.size() * superBlkSize * sizeof(block)));
                        uIter = (block*)uBuff->data();
                        uEnd = uIter + step * mGens.size() * superBlkSize;
                    }
                }


                // transpose our 128 columns of 1024 bits. We will have 1024 rows, 
                // each 128 bits wide.
                sse_transpose128x1024(t0);


                block* mIter = colStepIdx? mIter1: mIter0;
                block* mEnd = std::min(mIter + 128 * superBlkSize, (colStepIdx? mEnd1 : mEnd0));

                // compute how many rows are unused.
                u64 unusedCount = (mIter + 128 * superBlkSize) - mEnd;

                // compute the begin and end index of the extra rows that 
                // we will compute in this iters. These are taken from the 
                // unused rows what we computed above.
                xIter = xIterMaster;
                auto xEnd = std::min(xIter + unusedCount, extraBlocks.data() + 128);

                tIter = (block*)t0.data();
                block* tEnd = (block*)t0.data() + 128 * superBlkSize;

                while (mIter != mEnd)
                {
                    while (mIter != mEnd && tIter < tEnd)
                    {
                        (*mIter) = *tIter;

                        tIter += superBlkSize;
                        mIter += 1;
                    }

                    tIter = tIter - 128 * superBlkSize + 1;
                }


                if (tIter < (block*)t0.data())
                {
                    tIter = tIter + 128 * superBlkSize - 1;
                }

                while (xIter != xEnd)
                {
                    while (xIter != xEnd && tIter < tEnd)
                    {
                        (*xIter)[colStepIdx] = *tIter;

                        tIter += superBlkSize;
                        xIter += 1;
                    }

                    tIter = tIter - 128 * superBlkSize + 1;
                }

                if (colStepIdx) mIter1 = mIter;
                else mIter0 = mIter;
            }
            xIterMaster = xIter;
        }


        gTimer.setTimePoint("recv.transposeDone");

        // do correlation check and hashing
        // For the malicious secure OTs, we need a random PRNG that is chosen random 
        // for both parties. So that is what this is. 
        PRNG commonPrng;
        block theirSeed;
        chl.recv(&theirSeed, sizeof(block));
        chl.asyncSendCopy(&seed, sizeof(block));
        commonPrng.SetSeed(seed ^ theirSeed);
        gTimer.setTimePoint("recv.cncSeed");


        // this buffer will be sent to the other party to prove we used the 
        // same value of r in all of the column vectors...
        std::unique_ptr<ByteStream> correlationData(new ByteStream( 2 * 3 * sizeof(block)));
        correlationData->setp(correlationData->capacity());
        auto& x = correlationData->getArrayView<std::array<block,2>>()[0];
        auto& t = correlationData->getArrayView<std::array<block, 2>>()[1];
        auto& t2 = correlationData->getArrayView<std::array<block, 2>>()[2];


        x = t = t2 = { ZeroBlock,ZeroBlock };
        block ti, ti2;

        u64 doneIdx = (0);

        std::array<block, 2> zeroOneBlk{ ZeroBlock, AllOneBlock };
        std::array<block, 128> challenges;

        std::array<block, 8> expendedChoiceBlk;
        std::array<std::array<u8, 16>, 8>& expendedChoice = *reinterpret_cast<std::array<std::array<u8, 16>, 8>*>(&expendedChoiceBlk);

        block mask = _mm_set_epi8(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1);



        u64 bb = (messages.size() + 127) / 128;
        for (u64 blockIdx = 0; blockIdx < bb; ++blockIdx)
        {
            commonPrng.mAes.ecbEncCounterMode(doneIdx, 128, challenges.data());

            u64 stop = std::min(messages.size(), doneIdx + 128);

            expendedChoiceBlk[0] = mask & _mm_srai_epi16(choiceBlocks[blockIdx], 0);
            expendedChoiceBlk[1] = mask & _mm_srai_epi16(choiceBlocks[blockIdx], 1);
            expendedChoiceBlk[2] = mask & _mm_srai_epi16(choiceBlocks[blockIdx], 2);
            expendedChoiceBlk[3] = mask & _mm_srai_epi16(choiceBlocks[blockIdx], 3);
            expendedChoiceBlk[4] = mask & _mm_srai_epi16(choiceBlocks[blockIdx], 4);
            expendedChoiceBlk[5] = mask & _mm_srai_epi16(choiceBlocks[blockIdx], 5);
            expendedChoiceBlk[6] = mask & _mm_srai_epi16(choiceBlocks[blockIdx], 6);
            expendedChoiceBlk[7] = mask & _mm_srai_epi16(choiceBlocks[blockIdx], 7);
             
            for (u64 i = 0, dd = doneIdx; dd < stop; ++dd, ++i)
            {


                x[0] = x[0] ^ (challenges[i] & zeroOneBlk[expendedChoice[i % 8][i / 8]]);
                x[1] = x[1] ^ (challenges[i] & zeroOneBlk[expendedChoice[i % 8][i / 8]]);

                // multiply over polynomial ring to avoid reduction
                mul128(messages[dd], challenges[i], ti, ti2);
                t[0] = t[0] ^ ti;
                t2[0] = t2[0] ^ ti2;

                mul128(messages1[dd], challenges[i], ti, ti2);
                t[1] = t[1] ^ ti;
                t2[1] = t2[1] ^ ti2;

                //std::cout << "r m[" << dd << "] " << messages[dd] << " " << messages1[dd] << " " << choices2[dd] << std::endl;

                std::array<block, 2> msg{ messages[dd], messages1[dd] };
                mCode.encode(msg, ArrayView<block>(&messages[dd], 1));
            }


            doneIdx = stop;
        }



        for (auto& blk : extraBlocks)
        {
            // and check for correlation
            block chij = commonPrng.get<block>();


            if (choices2[doneIdx++])
            {
                x[0] = x[0] ^ chij;
                x[1] = x[1] ^ chij;
            }
            // multiply over polynomial ring to avoid reduction
            mul128(blk[0], chij, ti, ti2);
            t[0] = t[0] ^ ti;
            t2[0] = t2[0] ^ ti2;

            mul128(blk[1], chij, ti, ti2);
            t[1] = t[1] ^ ti;
            t2[1] = t2[1] ^ ti2;
        }

        gTimer.setTimePoint("recv.checkSummed");

        chl.asyncSend(std::move(correlationData));
        gTimer.setTimePoint("recv.done");

        static_assert(gOtExtBaseOtCount == 128, "expecting 128");
    }

}

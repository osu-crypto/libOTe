#include "LzKosOtExtReceiver.h"
#include "Tools/Tools.h"
#include "Common/Log.h"
#include "Common/ByteStream.h"
#include "Common/BitVector.h"
#include "Crypto/PRNG.h"
#include "Crypto/Commit.h"

using namespace std;

namespace osuCrypto
{
    void LzKosOtExtReceiver::setBaseOts(ArrayView<std::array<block, 2>> baseOTs)
    {
        if (baseOTs.size() != gOtExtBaseOtCount)
            throw std::runtime_error(LOCATION);

        for (u64 i = 0; i < gOtExtBaseOtCount; i++)
        {
            mGens[i][0].SetSeed(baseOTs[i][0]);
            mGens[i][1].SetSeed(baseOTs[i][1]);
        }


        mHasBase = true;
    }
    std::unique_ptr<OtExtReceiver> LzKosOtExtReceiver::split()
    {
        std::array<std::array<block, 2>, gOtExtBaseOtCount>baseRecvOts;

        for (u64 i = 0; i < mGens.size(); ++i)
        {
            baseRecvOts[i][0] = mGens[i][0].get<block>();
            baseRecvOts[i][1] = mGens[i][1].get<block>();
        }

        std::unique_ptr<OtExtReceiver> ret(new LzKosOtExtReceiver());

        ret->setBaseOts(baseRecvOts);

        return std::move(ret);
    }


    void LzKosOtExtReceiver::receive(
        const BitVector& choices,
        ArrayView<block> messages,
        PRNG& prng,
        Channel& chl)
    {

        if (mHasBase == false)
            throw std::runtime_error("rt error at " LOCATION);


        static const u64 superBlkSize(8);

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

        std::array<block, 128> extraBlocks;
        block* xIter = extraBlocks.data();
        //u64 extraIdx = 0;

        block* mIter = messages.data();

        // NOTE: We do not transpose a bit-matrix of size numCol * numCol.
        //   Instead we break it down into smaller chunks. We do 128 columns 
        //   times 8 * 128 rows at a time, where 8 = superBlkSize. This is done for  
        //   performance reasons. The reason for 8 is that most CPUs have 8 AES vector  
        //   lanes, and so its more efficient to encrypt (aka prng) 8 blocks at a time.
        //   So that's what we do. 
        for (u64 superBlkIdx = 0; superBlkIdx < numSuperBlocks; ++superBlkIdx)
        {

            // this will store the next 128 rows of the matrix u
            std::unique_ptr<ByteStream> uBuff(new ByteStream(128 * superBlkSize * sizeof(block)));

            // get an array of blocks that we will fill. 
            auto uIter = (block*)uBuff->data();


            block* tIter = (block*)t0.data();
            block* cIter = choiceBlocks.data() + superBlkSize * superBlkIdx;


            for (u64 colIdx = 0; colIdx < 128; ++colIdx)
            {
                // generate the column indexed by colIdx. This is done with
                // AES in counter mode acting as a PRNG. We don'tIter use the normal
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


            // send over u buffer
            chl.asyncSend(std::move(uBuff));

            // transpose our 128 columns of 1024 bits. We will have 1024 rows, 
            // each 128 bits wide.
            sse_transpose128x1024(t0);



            //block* mStart = mIter;
            block* mEnd = std::min(mIter + 128 * superBlkSize, (block*)messages.end());

            // compute how many rows are unused.
            u64 unusedCount = (mIter + 128 * superBlkSize) - mEnd;

            // compute the begin and end index of the extra rows that 
            // we will compute in this iters. These are taken from the 
            // unused rows what we computed above.
            block* xEnd = std::min(xIter + unusedCount, extraBlocks.data() + 128);

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
                    *xIter = *tIter;

                    tIter += superBlkSize;
                    xIter += 1;
                }

                tIter = tIter - 128 * superBlkSize + 1;
            }


#ifdef KOS_DEBUG

            u64 doneIdx = mStart - messages.data();
            block* msgIter = messages.data() + doneIdx;
            chl.send(msgIter, sizeof(block) * 128 * superBlkSize);
            cIter = choiceBlocks.data() + superBlkSize * superBlkIdx;
            chl.send(cIter, sizeof(block) * superBlkSize);
#endif
            //doneIdx = stopIdx;
        }

#ifdef KOS_DEBUG
        chl.send(extraBlocks.data(), sizeof(block) * 128);
        BitVector cc;
        cc.copy(choices2, choices.size(), 128);
        chl.send(cc);
#endif


        // do correlation check and hashing
        // For the malicious secure OTs, we need a random PRNG that is chosen random 
        // for both parties. So that is what this is. 
        PRNG commonPrng;
        //random_seed_commit(ByteArray(seed), chl, SEED_SIZE, prng.get<block>());
        block theirSeed;
        chl.recv(&theirSeed, sizeof(block));
        chl.asyncSendCopy(&seed, sizeof(block));
        commonPrng.SetSeed(seed ^ theirSeed);

        // this buffer will be sent to the other party to prove we used the 
        // same value of r in all of the column vectors...
        std::unique_ptr<ByteStream> correlationData(new ByteStream(3 * sizeof(block)));
        correlationData->setp(correlationData->capacity());
        block& x = correlationData->getArrayView<block>()[0];
        block& t = correlationData->getArrayView<block>()[1];
        block& t2 = correlationData->getArrayView<block>()[2];
        x = t = t2 = ZeroBlock;
        block ti, ti2;

        SHA1 sha;
        u8 hashBuff[20];
        u64 doneIdx = (0);
        //std::cout << IoStream::lock;

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

            for (u64 i = 0; doneIdx < stop; ++doneIdx, ++i)
            {
                u8 choiceBit = expendedChoice[i % 8][i / 8];

                x = x ^ (challenges[i] & zeroOneBlk[choiceBit]);

                // multiply over polynomial ring to avoid reduction
                mul128(messages[doneIdx], challenges[i], ti, ti2);

                t = t ^ ti;
                t2 = t2 ^ ti2;

                if (choiceBit)
                {
                    // hash it
                    sha.Reset();
                    sha.Update((u8*)&messages[doneIdx], sizeof(block));
                    sha.Final(hashBuff);
                    messages[doneIdx] = *(block*)hashBuff;
                }
            }
        }



        //u64 xtra = 0;;
        for (block& blk : extraBlocks)
        {
            // and check for correlation
            block chij = commonPrng.get<block>();

            //std::cout << "recvIdx' " << xtra++ << "   " << blk << "   " << chij << "  " << (u32)choices2[doneIdx] << std::endl;

            if (choices2[doneIdx++]) x = x ^ chij;

            // multiply over polynomial ring to avoid reduction
            mul128(blk, chij, ti, ti2);

            t = t ^ ti;
            t2 = t2 ^ ti2;
        }
        //std::cout << IoStream::unlock;

        chl.asyncSend(std::move(correlationData));

        static_assert(gOtExtBaseOtCount == 128, "expecting 128");
    }

}

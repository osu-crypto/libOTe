#include "IknpOtExtReceiver.h"
#ifdef ENABLE_IKNP

#include "libOTe/Tools/Tools.h"
#include <cryptoTools/Common/Log.h>

#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/Commit.h>
#include "TcoOtDefines.h"

using namespace std;

namespace osuCrypto
{
    void IknpOtExtReceiver::setBaseOts(span<std::array<block, 2>> baseOTs)
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


    IknpOtExtReceiver IknpOtExtReceiver::splitBase()
    {
        std::array<std::array<block, 2>, gOtExtBaseOtCount>baseRecvOts;

        for (u64 i = 0; i < mGens.size(); ++i)
        {
            baseRecvOts[i][0] = mGens[i][0].get<block>();
            baseRecvOts[i][1] = mGens[i][1].get<block>();
        }

        return IknpOtExtReceiver(baseRecvOts);
    }


    std::unique_ptr<OtExtReceiver> IknpOtExtReceiver::split()
    {
        std::array<std::array<block, 2>, gOtExtBaseOtCount>baseRecvOts;

        for (u64 i = 0; i < mGens.size(); ++i)
        {
            baseRecvOts[i][0] = mGens[i][0].get<block>();
            baseRecvOts[i][1] = mGens[i][1].get<block>();
        }

        return std::make_unique<IknpOtExtReceiver>(baseRecvOts);
    }


    void IknpOtExtReceiver::receive(
        const BitVector& choices,
        span<block> messages,
        PRNG& prng,
        Channel& chl)
    {
        if (hasBaseOts() == false)
            genBaseOts(prng, chl);

        // we are going to process OTs in blocks of 128 * superBlkSize messages.
        u64 numOtExt = roundUpTo(choices.size(), 128);
        u64 numSuperBlocks = (numOtExt / 128 + superBlkSize - 1) / superBlkSize;
        u64 numBlocks = numSuperBlocks * superBlkSize;

        BitVector choices2(numBlocks * 128);
        choices2 = choices;
        choices2.resize(numBlocks * 128);

        auto choiceBlocks = choices2.getSpan<block>();
        // this will be used as temporary buffers of 128 columns, 
        // each containing 1024 bits. Once transposed, they will be copied
        // into the T1, T0 buffers for long term storage.
        std::array<std::array<block, superBlkSize>, 128> t0;

        // the index of the OT that has been completed.
        //u64 doneIdx = 0;

        auto mIter = messages.begin();

        u64 step = std::min<u64>(numSuperBlocks, (u64)commStepSize);
        std::vector<block> uBuff(step * 128 * superBlkSize);

        // get an array of blocks that we will fill. 
        auto uIter = (block*)uBuff.data();
        auto uEnd = uIter + uBuff.size();

        // NOTE: We do not transpose a bit-matrix of size numCol * numCol.
        //   Instead we break it down into smaller chunks. We do 128 columns 
        //   times 8 * 128 rows at a time, where 8 = superBlkSize. This is done for  
        //   performance reasons. The reason for 8 is that most CPUs have 8 AES vector  
        //   lanes, and so its more efficient to encrypt (aka prng) 8 blocks at a time.
        //   So that's what we do. 
        for (u64 superBlkIdx = 0; superBlkIdx < numSuperBlocks; ++superBlkIdx)
        {

            // this will store the next 128 rows of the matrix u

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

            if (uIter == uEnd)
            {
                // send over u buffer
                chl.asyncSend(std::move(uBuff));

                u64 step = std::min<u64>(numSuperBlocks - superBlkIdx - 1, (u64)commStepSize);

                if (step)
                {
                    uBuff.resize(step * 128 * superBlkSize);
                    uIter = (block*)uBuff.data();
                    uEnd = uIter + uBuff.size();
                }
            }

            // transpose our 128 columns of 1024 bits. We will have 1024 rows, 
            // each 128 bits wide.
            sse_transpose128x1024(t0);


            //block* mStart = mIter;
            //block* mEnd = std::min<block*>(mIter + 128 * superBlkSize, &*messages.end());
            auto mEnd = mIter + std::min<u64>(128 * superBlkSize, messages.end() - mIter);


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

#ifdef IKNP_DEBUG
            u64 doneIdx = mStart - messages.data();
            block* msgIter = messages.data() + doneIdx;
            chl.send(msgIter, sizeof(block) * 128 * superBlkSize);
            cIter = choiceBlocks.data() + superBlkSize * superBlkIdx;
            chl.send(cIter, sizeof(block) * superBlkSize);
#endif
            //doneIdx = stopIdx;
        }


#ifdef IKNP_SHA_HASH
        RandomOracle sha;
        u8 hashBuff[20];
#else
        std::array<block, 8> aesHashTemp;
#endif

        u64 doneIdx = (0);

        u64 bb = (messages.size() + 127) / 128;
        for (u64 blockIdx = 0; blockIdx < bb; ++blockIdx)
        {
            u64 stop = std::min<u64>(messages.size(), doneIdx + 128);

#ifdef IKNP_SHA_HASH
            for (u64 i = 0; doneIdx < stop; ++doneIdx, ++i)
            {
                // hash it
                sha.Reset();
                sha.Update((u8*)&messages[doneIdx], sizeof(block));
                sha.Final(hashBuff);
                messages[doneIdx] = *(block*)hashBuff;
            }
#else
            auto length = stop - doneIdx;
            auto steps = length / 8;
            block* mIter = messages.data() + doneIdx;
            for (u64 i = 0; i < steps; ++i)
            {
                mAesFixedKey.ecbEncBlocks(mIter, 8, aesHashTemp.data());
                mIter[0] = mIter[0] ^ aesHashTemp[0];
                mIter[1] = mIter[1] ^ aesHashTemp[1];
                mIter[2] = mIter[2] ^ aesHashTemp[2];
                mIter[3] = mIter[3] ^ aesHashTemp[3];
                mIter[4] = mIter[4] ^ aesHashTemp[4];
                mIter[5] = mIter[5] ^ aesHashTemp[5];
                mIter[6] = mIter[6] ^ aesHashTemp[6];
                mIter[7] = mIter[7] ^ aesHashTemp[7];

                mIter += 8;
            }

            auto rem = length - steps * 8;
            mAesFixedKey.ecbEncBlocks(mIter, rem, aesHashTemp.data());
            for (u64 i = 0; i < rem; ++i)
            {
                mIter[i] = mIter[i] ^ aesHashTemp[i];
            }

            doneIdx = stop;
#endif

        }

        static_assert(gOtExtBaseOtCount == 128, "expecting 128");
    }

}
#endif
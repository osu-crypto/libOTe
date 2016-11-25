#include "LzKosOtExtSender.h"

#include "Tools/Tools.h"
#include "Common/Log.h"
#include "Common/ByteStream.h"
#include "Crypto/Commit.h"

namespace osuCrypto
{
    //#define KOS_DEBUG

    using namespace std;




    std::unique_ptr<OtExtSender> LzKosOtExtSender::split()
    {

        std::unique_ptr<OtExtSender> ret(new LzKosOtExtSender());

        std::array<block, gOtExtBaseOtCount> baseRecvOts;

        for (u64 i = 0; i < mGens.size(); ++i)
        {
            baseRecvOts[i] = mGens[i].get<block>();
        }

        ret->setBaseOts(baseRecvOts, mBaseChoiceBits);

        return std::move(ret);
    }

    void LzKosOtExtSender::setBaseOts(ArrayView<block> baseRecvOts, const BitVector & choices)
    {
        if (baseRecvOts.size() != gOtExtBaseOtCount || choices.size() != gOtExtBaseOtCount)
            throw std::runtime_error("not supported/implemented");


        mBaseChoiceBits = choices;
        for (u64 i = 0; i < gOtExtBaseOtCount; i++)
        {
            mGens[i].SetSeed(baseRecvOts[i]);
        }
    }

    void LzKosOtExtSender::send(
        ArrayView<std::array<block, 2>> messages,
        PRNG& prng,
        Channel& chl)
    {

        const u8 superBlkSize(8);


        // round up
        u64 numOtExt = roundUpTo(messages.size(), 128);
        u64 numSuperBlocks = (numOtExt / 128 + superBlkSize) / superBlkSize;

        // a temp that will be used to transpose the sender's matrix
        std::array<std::array<block, superBlkSize>, 128> t, u;
        std::array<block, 128> choiceMask;
        block delta = *(block*)mBaseChoiceBits.data();

        for (u64 i = 0; i < 128; ++i)
        {
            if (mBaseChoiceBits[i]) choiceMask[i] = AllOneBlock;
            else choiceMask[i] = ZeroBlock;
        }

        std::array<block, 128> extraBlocks;
        block* xIter = extraBlocks.data();


        Commit theirSeedComm;
        chl.recv(theirSeedComm.data(), theirSeedComm.size());

        std::array<block, 2>* mIter = messages.data();


        for (u64 superBlkIdx = 0; superBlkIdx < numSuperBlocks; ++superBlkIdx)
        {

            block * tIter = (block*)t.data();
            block * uIter = (block*)u.data();
            block * cIter = choiceMask.data();

            chl.recv(u.data(), superBlkSize * 128 * sizeof(block));

            // transpose 128 columns at at time. Each column will be 128 * superBlkSize = 1024 bits long.
            for (u64 colIdx = 0; colIdx < 128; ++colIdx)
            {
                // generate the columns using AES-NI in counter mode.
                mGens[colIdx].mAes.ecbEncCounterMode(mGens[colIdx].mBlockIdx, superBlkSize, tIter);
                mGens[colIdx].mBlockIdx += superBlkSize;

                uIter[0] = uIter[0] & *cIter;
                uIter[1] = uIter[1] & *cIter;
                uIter[2] = uIter[2] & *cIter;
                uIter[3] = uIter[3] & *cIter;
                uIter[4] = uIter[4] & *cIter;
                uIter[5] = uIter[5] & *cIter;
                uIter[6] = uIter[6] & *cIter;
                uIter[7] = uIter[7] & *cIter;

                tIter[0] = tIter[0] ^ uIter[0];
                tIter[1] = tIter[1] ^ uIter[1];
                tIter[2] = tIter[2] ^ uIter[2];
                tIter[3] = tIter[3] ^ uIter[3];
                tIter[4] = tIter[4] ^ uIter[4];
                tIter[5] = tIter[5] ^ uIter[5];
                tIter[6] = tIter[6] ^ uIter[6];
                tIter[7] = tIter[7] ^ uIter[7];

                ++cIter;
                uIter += 8;
                tIter += 8;
            }

            // transpose our 128 columns of 1024 bits. We will have 1024 rows, 
            // each 128 bits wide.
            sse_transpose128x1024(t);


            //std::array<block, 2>* mStart = mIter;
            std::array<block, 2>* mEnd = std::min(mIter + 128 * superBlkSize, (std::array<block, 2>*)messages.end());

            // compute how many rows are unused.
            u64 unusedCount = (mIter + 128 * superBlkSize) - mEnd;

            // compute the begin and end index of the extra rows that 
            // we will compute in this iters. These are taken from the 
            // unused rows what we computed above.
            block* xEnd = std::min(xIter + unusedCount, extraBlocks.data() + 128);

            tIter = (block*)t.data();
            block* tEnd = (block*)t.data() + 128 * superBlkSize;

            while (mIter != mEnd)
            {
                while (mIter != mEnd && tIter < tEnd)
                {
                    (*mIter)[0] = *tIter;
                    (*mIter)[1] = *tIter ^ delta;

                    //u64 tV = tIter - (block*)t.data();
                    //u64 tIdx = tV / 8 + (tV % 8) * 128;
                    //std::cout << "midx " << (mIter - messages.data()) << "   tIdx " << tIdx << std::endl;

                    tIter += superBlkSize;
                    mIter += 1;
                }

                tIter = tIter - 128 * superBlkSize + 1;
            }


            if (tIter < (block*)t.data())
            {
                tIter = tIter + 128 * superBlkSize - 1;
            }

            while (xIter != xEnd)
            {
                while (xIter != xEnd && tIter < tEnd)
                {
                    *xIter = *tIter;

                    //u64 tV = tIter - (block*)t.data();
                    //u64 tIdx = tV / 8 + (tV % 8) * 128;
                    //std::cout << "xidx " << (xIter - extraBlocks.data()) << "   tIdx " << tIdx << std::endl;

                    tIter += superBlkSize;
                    xIter += 1;
                }

                tIter = tIter - 128 * superBlkSize + 1;
            }

            //std::cout << "blk end " << std::endl;

#ifdef KOS_DEBUG
            BitVector choice(128 * superBlkSize);
            chl.recv(u.data(), superBlkSize * 128 * sizeof(block));
            chl.recv(choice.data(), sizeof(block) * superBlkSize);

            u64 doneIdx = mStart - messages.data();
            u64 xx = std::min(i64(128 * superBlkSize), (messages.data() + messages.size()) - mEnd);
            for (u64 rowIdx = doneIdx,
                j = 0; j < xx; ++rowIdx, ++j)
            {
                if (neq(((block*)u.data())[j], messages[rowIdx][choice[j]]))
                {
                    std::cout << rowIdx << std::endl;
                    throw std::runtime_error("");
                }
            }
#endif
            //doneIdx = (mEnd - messages.data());
        }


#ifdef KOS_DEBUG
        BitVector choices(128);
        std::vector<block> xtraBlk(128);

        chl.recv(xtraBlk.data(), 128 * sizeof(block));
        choices.resize(128);
        chl.recv(choices);

        for (u64 i = 0; i < 128; ++i)
        {
            if (neq(xtraBlk[i], choices[i] ? extraBlocks[i] ^ delta : extraBlocks[i]))
            {
                std::cout << "extra " << i << std::endl;
                std::cout << xtraBlk[i] << "  " << (u32)choices[i] << std::endl;
                std::cout << extraBlocks[i] << "  " << (extraBlocks[i] ^ delta) << std::endl;

                throw std::runtime_error("");
            }
        }
#endif


        block seed = prng.get<block>();
        chl.asyncSend(&seed, sizeof(block));
        block theirSeed;
        chl.recv(&theirSeed, sizeof(block));

        if (Commit(theirSeed) != theirSeedComm)
            throw std::runtime_error("bad commit " LOCATION);


        PRNG commonPrng(seed ^ theirSeed);

        block  qi, qi2;
        block q2 = ZeroBlock;
        block q1 = ZeroBlock;

        SHA1 sha;
        u8 hashBuff[20];
        u64 doneIdx = 0;
        std::array<block, 128> challenges;

        u64 bb = (messages.size() + 127) / 128;
        for (u64 blockIdx = 0; blockIdx < bb; ++blockIdx)
        {
            commonPrng.mAes.ecbEncCounterMode(doneIdx, 128, challenges.data());
            u64 stop = std::min(messages.size(), doneIdx + 128);

            for (u64 i = 0; doneIdx < stop; ++doneIdx, ++i)
            {

                mul128(messages[doneIdx][0], challenges[i], qi, qi2);
                q1 = q1  ^ qi;
                q2 = q2 ^ qi2;


                // hash the message with delta
                sha.Reset();
                sha.Update((u8*)&messages[doneIdx][1], sizeof(block));
                sha.Final(hashBuff);
                messages[doneIdx][1] = *(block*)hashBuff;
            }
        }


        //u64 xtra = 0;
        for (auto& blk : extraBlocks)
        {
            block chii = commonPrng.get<block>();


            mul128(blk, chii, qi, qi2);
            q1 = q1  ^ qi;
            q2 = q2 ^ qi2;
        }

        //std::cout << IoStream::unlock;

        block t1, t2;
        std::vector<char> data(sizeof(block) * 3);

        chl.recv(data.data(), data.size());

        block& received_x = ((block*)data.data())[0];
        block& received_t = ((block*)data.data())[1];
        block& received_t2 = ((block*)data.data())[2];

        // check t = x * Delta + q 
        mul128(received_x, delta, t1, t2);
        t1 = t1 ^ q1;
        t2 = t2 ^ q2;

        if (eq(t1, received_t) && eq(t2, received_t2))
        {
            //std::cout << "\tCheck passed\n";
        }
        else
        {
            std::cout << "OT Ext Failed Correlation check failed" << std::endl;
            std::cout << "rec t = " << received_t << std::endl;
            std::cout << "tmp1  = " << t1 << std::endl;
            std::cout << "q  = " << q1 << std::endl;
            throw std::runtime_error("Exit");;
        }

        static_assert(gOtExtBaseOtCount == 128, "expecting 128");
    }


}

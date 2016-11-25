#include "KosDotExtSender.h"

#include "Tools/Tools.h"
#include "Common/Log.h"
#include "Common/ByteStream.h"
#include "Crypto/Commit.h"
#include "TcoOtDefines.h"


namespace osuCrypto
{
    //#define KOS_DEBUG

    using namespace std;


    std::unique_ptr<OtExtSender> KosDotExtSender::split()
    {
        auto dot = new KosDotExtSender();
        dot->mCode = mCode;
        std::unique_ptr<OtExtSender> ret(dot);

        std::vector<block> baseRecvOts(mGens.size());

        for (u64 i = 0; i < mGens.size(); ++i)
        {
            baseRecvOts[i] = mGens[i].get<block>();
        }

        ret->setBaseOts(baseRecvOts, mBaseChoiceBits);

        return std::move(ret);
    }

    void KosDotExtSender::setBaseOts(ArrayView<block> baseRecvOts, const BitVector & choices)
    {


        PRNG prng(ZeroBlock);
        mCode.random(prng, choices.size(), 128);

        mBaseChoiceBits = choices;
        mGens.resize(choices.size());

        mBaseChoiceBits.resize(roundUpTo(mBaseChoiceBits.size(), 8));

        for (u64 i = mBaseChoiceBits.size() - 1; i >= choices.size(); --i)
        {
            mBaseChoiceBits[i] = 0;
        }
        mBaseChoiceBits.resize(choices.size());

        for (u64 i = 0; i < mGens.size(); i++)
        {
            mGens[i].SetSeed(baseRecvOts[i]);
        }
    }

    void KosDotExtSender::send(
        ArrayView<std::array<block, 2>> messages,
        PRNG& prng,
        Channel& chl)
    {
        // round up 
        u64 numOtExt = roundUpTo(messages.size(), 128);
        u64 numSuperBlocks = (numOtExt / 128 + superBlkSize) / superBlkSize;
        //u64 numBlocks = numSuperBlocks * superBlkSize;

        // a temp that will be used to transpose the sender's matrix
        std::array<std::array<block, superBlkSize>, 128> t;
        std::vector<std::array<block, superBlkSize>> u(mGens.size()  * commStepSize);


        std::vector<block> choiceMask(mBaseChoiceBits.size());
        std::array<block, 2> delta{ ZeroBlock, ZeroBlock };

        memcpy(delta.data(), mBaseChoiceBits.data(), mBaseChoiceBits.sizeBytes());
        


        for (u64 i = 0; i < choiceMask.size(); ++i)
        {
            if (mBaseChoiceBits[i]) choiceMask[i] = AllOneBlock;
            else choiceMask[i] = ZeroBlock;
        }


        std::array<std::array<block,2>, 128> extraBlocks;
        std::array<block,2>* xIter = extraBlocks.data();
        auto xIterMaster = xIter;

        Commit theirSeedComm;
        chl.recv(theirSeedComm.data(), theirSeedComm.size());


        std::array<block, 2>* mIterMaster = messages.data();
        std::array<block, 2>* mIter = nullptr;


        // set uIter = to the end so that it gets loaded on the first loop.
        block * uIter = (block*)u.data() + superBlkSize * mGens.size()  * commStepSize;
        block * uEnd = uIter;

        u64 colStepCount = (mGens.size() + 127) / 128;

        // we assume we have the number of columns of between 129 and 256...
        if (colStepCount > 2)
            throw std::runtime_error(LOCATION);



        for (u64 superBlkIdx = 0; superBlkIdx < numSuperBlocks; ++superBlkIdx)
        {


            if (uIter == uEnd)
            {
                u64 step = std::min(numSuperBlocks - superBlkIdx,(u64) commStepSize);
                chl.recv(u.data(), step * superBlkSize * mGens.size() * sizeof(block));
                uIter = (block*)u.data();
            }


            block * cIter = choiceMask.data();

            for (u64 colStepIdx = 0; colStepIdx < 2; ++colStepIdx)
            {
                block * tIter = (block*)t.data();
                memset(t.data(), 0, superBlkSize * 128 * sizeof(block));



                u64 colStop = std::min((colStepIdx + 1) * 128, mGens.size());

                // transpose 128 columns at at time. Each column will be 128 * superBlkSize = 1024 bits long.
                for (u64 colIdx = colStepIdx * 128; colIdx < colStop; ++colIdx)
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


                mIter = mIterMaster;
                //std::array<block, 2>* mStart = mIter;
                std::array<block, 2>* mEnd = std::min(mIter + 128 * superBlkSize, (std::array<block, 2>*)messages.end());

                // compute how many rows are unused.
                u64 unusedCount = (mIter + 128 * superBlkSize) - mEnd;


                // compute the begin and end index of the extra rows that 
                // we will compute in this iters. These are taken from the 
                // unused rows what we computed above.
                xIter = xIterMaster;
                std::array<block,2>* xEnd = std::min(xIter + unusedCount, extraBlocks.data() + 128);

                tIter = (block*)t.data();
                block* tEnd = (block*)t.data() + 128 * superBlkSize;


                while (mIter != mEnd)
                {
                    while (mIter != mEnd && tIter < tEnd)
                    {
                        (*mIter)[colStepIdx] = *tIter;
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
                        (*xIter)[colStepIdx] = *tIter;

                        tIter += superBlkSize;
                        xIter += 1;
                    }
                    tIter = tIter - 128 * superBlkSize + 1;
                }
            }
            xIterMaster = xIter;
            mIterMaster = mIter;
        }


#ifdef KOS_DEBUG
        BitVector choices(128);
        std::vector<block> xtraBlk(128);

        chl.recv(xtraBlk.data(), 128 * sizeof(block));
        choices.resize(128);
        chl.recv(choices);

        for (u64 i = 0; i < 128; ++i)
        {
            if (neq(xtraBlk[i] , choices[i] ? extraBlocks[i] ^ delta : extraBlocks[i] ))
            {
                std::cout << "extra " << i << std::endl;
                std::cout << xtraBlk[i] << "  " << (u32)choices[i] << std::endl;
                std::cout << extraBlocks[i] << "  " << (extraBlocks[i] ^ delta) << std::endl;

                throw std::runtime_error("");
            }
        }
#endif
        gTimer.setTimePoint("send.transposeDone");

        block seed = prng.get<block>();
        chl.asyncSend(&seed, sizeof(block));
        block theirSeed;
        chl.recv(&theirSeed, sizeof(block));
        gTimer.setTimePoint("send.cncSeed");

        if (Commit(theirSeed) != theirSeedComm)
            throw std::runtime_error("bad commit " LOCATION);


        PRNG commonPrng(seed ^ theirSeed);

        block  qi, qi2;
        std::array<block ,2>q2{ZeroBlock,ZeroBlock};
        std::array<block, 2>q1{ZeroBlock,ZeroBlock};

        u64 doneIdx = 0;

        std::array<block, 128> challenges;

        gTimer.setTimePoint("send.checkStart");



        u64 bb = (messages.size() + 127) / 128;
        for (u64 blockIdx = 0; blockIdx < bb; ++blockIdx)
        {
            commonPrng.mAes.ecbEncCounterMode(doneIdx, 128, challenges.data());
            u64 stop = std::min(messages.size(), doneIdx + 128);

            for (u64 i = 0, dd = doneIdx; dd < stop; ++dd, ++i)
            {

                mul128(messages[dd][0], challenges[i], qi, qi2);
                q1[0] = q1[0]  ^ qi;
                q2[0] = q2[0] ^ qi2;
                mul128(messages[dd][1], challenges[i], qi, qi2);
                q1[1] = q1[1]  ^ qi;
                q2[1] = q2[1] ^ qi2;

                std::array<block, 2> messages1
                {
                    messages[dd][0] ^ delta[0],
                    messages[dd][1] ^ delta[1],
                };

                mCode.encode(messages[dd], ArrayView<block>(&messages[dd][0], 1));
                mCode.encode(messages1, ArrayView<block>(&messages[dd][1], 1));
            }

            doneIdx = stop;
        }

        for (auto& blk : extraBlocks)
        {
            block chii = commonPrng.get<block>();

            mul128(blk[0], chii, qi, qi2);
            q1[0] = q1[0] ^ qi;
            q2[0] = q2[0] ^ qi2;
            mul128(blk[1], chii, qi, qi2);
            q1[1] = q1[1] ^ qi;
            q2[1] = q2[1] ^ qi2;
        }

        gTimer.setTimePoint("send.checkSummed");

        std::array<block, 2> t1, t2;
        std::vector<char> data(sizeof(block) * 6);

        chl.recv(data.data(), data.size());
        gTimer.setTimePoint("send.proofReceived");

        auto& received_x =  ((std::array<block,2>*)data.data())[0];
        auto& received_t =  ((std::array<block,2>*)data.data())[1];
        auto& received_t2 = ((std::array<block,2>*)data.data())[2];

        // check t = x * Delta + q 
        mul128(received_x[0], delta[0], t1[0], t2[0]);
        t1[0] = t1[0] ^ q1[0];
        t2[0] = t2[0] ^ q2[0];

        mul128(received_x[1], delta[1], t1[1], t2[1]);
        t1[1] = t1[1] ^ q1[1];
        t2[1] = t2[1] ^ q2[1];


        if (eq(t1[0], received_t[0]) && eq(t2[0], received_t2[0]))
        {
            //std::cout << "\tCheck passed\n";
        }
        else
        {
            std::cout << "OT Ext Failed Correlation check failed" << std::endl;
            std::cout << "rec t = " << received_t[0] << std::endl;
            std::cout << "tmp1  = " << t1[0] << std::endl;
            std::cout << "q  = " << q1[0] << std::endl;
            throw std::runtime_error("Exit");;
        }


        if (eq(t1[1], received_t[1]) && eq(t2[1], received_t2[1]))
        {
            //std::cout << "\tCheck passed\n";
        }
        else
        {
            std::cout << "2 OT Ext Failed Correlation check failed" << std::endl;

            throw std::runtime_error("Exit");;
        }
        gTimer.setTimePoint("send.done");

        static_assert(gOtExtBaseOtCount == 128, "expecting 128");
    }


}

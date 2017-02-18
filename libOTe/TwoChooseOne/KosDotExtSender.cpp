#include "KosDotExtSender.h"

#include "libOTe/Tools/Tools.h"
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/ByteStream.h>
#include <cryptoTools/Crypto/Commit.h>
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

        // a temp that will be used to transpose the sender's matrix
        MatrixView<u8> t(mGens.size(), superBlkSize * sizeof(block));
        std::vector<std::array<block, superBlkSize>> u(mGens.size()  * commStepSize);

        std::vector<block> choiceMask(mBaseChoiceBits.size());
        std::array<block, 2> delta{ ZeroBlock, ZeroBlock };

        memcpy(delta.data(), mBaseChoiceBits.data(), mBaseChoiceBits.sizeBytes());


        for (u64 i = 0; i < choiceMask.size(); ++i)
        {
            if (mBaseChoiceBits[i]) choiceMask[i] = AllOneBlock;
            else choiceMask[i] = ZeroBlock;
        }


        std::array<std::array<block, 2>, 128> extraBlocks;
        std::array<block, 2>* xIter = extraBlocks.data();

        Commit theirSeedComm;
        chl.recv(theirSeedComm.data(), theirSeedComm.size());

        std::array<block, 2>* mIter = messages.data();
        auto mIterPartial = mIter + messages.size() - 128 * superBlkSize;


        // set uIter = to the end so that it gets loaded on the first loop.
        block * uIter = (block*)u.data() + superBlkSize * mGens.size()  * commStepSize;
        block * uEnd = uIter;

        for (u64 superBlkIdx = 0; superBlkIdx < numSuperBlocks; ++superBlkIdx)
        {

            if (uIter == uEnd)
            {
                u64 step = std::min<u64>(numSuperBlocks - superBlkIdx, (u64)commStepSize);
                chl.recv(u.data(), step * superBlkSize * mGens.size() * sizeof(block));
                uIter = (block*)u.data();
            }

            block * cIter = choiceMask.data();
            block * tIter = (block*)t.data();

            // transpose 128 columns at at time. Each column will be 128 * superBlkSize = 1024 bits long.
            for (u64 colIdx = 0; colIdx < mGens.size(); ++colIdx)
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



            if (mIter > mIterPartial)
            {
                MatrixView<u8> tOut(128 * superBlkSize, sizeof(block) * 2);

                // transpose our 128 columns of 1024 bits. We will have 1024 rows, 
                // each 128 bits wide.
                sse_transpose(t, tOut);

                auto mCount = std::min<u64>(128 * superBlkSize, messages.end() - mIter);
                auto xCount = std::min<u64>(128 * superBlkSize - mCount, extraBlocks.data() + extraBlocks.size() - xIter);

                memcpy(mIter, tOut.data(), mCount * sizeof(block) * 2);
                mIter += mCount;


                memcpy(xIter, tOut.data() + mCount * sizeof(block) * 2, xCount * sizeof(block) * 2);
                xIter += xCount;
            }
            else
            {
                MatrixView<u8> tOut(
                    (u8*)mIter,
                    128 * superBlkSize,
                    sizeof(block) * 2,
                    false);

                mIter += 128 * superBlkSize;

                // transpose our 128 columns of 1024 bits. We will have 1024 rows, 
                // each 128 bits wide.
                sse_transpose(t, tOut);
            }

        }

        gTimer.setTimePoint("send.transposeDone");

        block seed = prng.get<block>();
        chl.asyncSend(&seed, sizeof(block));
        block theirSeed;
        chl.recv(&theirSeed, sizeof(block));
        gTimer.setTimePoint("send.cncSeed");

        if (Commit(theirSeed) != theirSeedComm)
            throw std::runtime_error("bad commit " LOCATION);


        PRNG commonPrng(seed ^ theirSeed);

        block  qi1, qi2, qi3, qi4,
            q1(ZeroBlock), q2(ZeroBlock), q3(ZeroBlock), q4(ZeroBlock);

        u64 doneIdx = 0;

        std::array<block, 128> challenges, challenges2;

        gTimer.setTimePoint("send.checkStart");

        //std::cout << IoStream::lock;

        u64 xx = 0;
        u64 bb = (messages.size() + 127 + 128) / 128;
        for (u64 blockIdx = 0; blockIdx < bb; ++blockIdx)
        {
            commonPrng.mAes.ecbEncCounterMode(doneIdx, 128, challenges.data());
            commonPrng.mAes.ecbEncCounterMode(doneIdx, 128, challenges2.data());

            u64 stop0 = std::min<u64>(messages.size(), doneIdx + 128);
            u64 stop1 = std::min<u64>(messages.size() + 128, doneIdx + 128);

            u64 i = 0, dd = doneIdx;
            for (; dd < stop0; ++dd, ++i)
            {
                mul256(messages[dd][0], messages[dd][1], challenges[i], challenges2[i], qi1, qi2, qi3, qi4);

                q1 = q1 ^ qi1;
                q2 = q2 ^ qi2;
                q3 = q3 ^ qi3;
                q4 = q4 ^ qi4;

                std::array<block, 2> messages1 { messages[dd][0] ^ delta[0], messages[dd][1] ^ delta[1]};

                mCode.encode((u8*)messages[dd].data(), (u8*)&messages[dd][0]);
                mCode.encode((u8*)messages1.data(), (u8*)&messages[dd][1]);
            }


            for (; dd < stop1; ++dd, ++i, ++xx)
            {
                mul256(extraBlocks[xx][0], extraBlocks[xx][1], challenges[i], challenges2[i], qi1, qi2, qi3, qi4);
                q1 = q1 ^ qi1;
                q2 = q2 ^ qi2;
                q3 = q3 ^ qi3;
                q4 = q4 ^ qi4;
            }

            doneIdx = stop1;
        }


        gTimer.setTimePoint("send.checkSummed");

        block t1, t2, t3, t4;
        std::vector<char> data(sizeof(block) * 8);

        chl.recv(data.data(), data.size());


        //std::cout << IoStream::unlock;
        
        gTimer.setTimePoint("send.proofReceived");

        auto& received_x = ((std::array<block, 4>*)data.data())[0];
        auto& received_t = ((std::array<block, 4>*)data.data())[1];


        // check t = x * Delta + q 
        mul256(received_x[0], received_x[1], delta[0], delta[1], t1, t2, t3, t4);
        t1 = t1 ^ q1;
        t2 = t2 ^ q2;
        t3 = t3 ^ q3;
        t4 = t4 ^ q4;


        if (eq(t1, received_t[0]) && eq(t2, received_t[1]) &&
            eq(t3, received_t[2]) && eq(t4, received_t[3]))
        {
            //std::cout << "\tCheck passed\n";
        }
        else
        {
            std::cout << "OT Ext Failed Correlation check failed" << std::endl;
            std::cout << "rec t[0] = " << received_t[0] << std::endl;
            std::cout << "rec t[1] = " << received_t[1] << std::endl;
            std::cout << "rec t[2] = " << received_t[2] << std::endl;
            std::cout << "rec t[3] = " << received_t[3] << std::endl << std::endl;
            std::cout << "exp t[0] = " << t1 << std::endl;
            std::cout << "exp t[1] = " << t2 << std::endl;
            std::cout << "exp t[2] = " << t3 << std::endl;
            std::cout << "exp t[3] = " << t4 << std::endl << std::endl;
            std::cout << "q  = " << q1 << std::endl;
             throw std::runtime_error("Exit");;
        }

        gTimer.setTimePoint("send.done");

        static_assert(gOtExtBaseOtCount == 128, "expecting 128");
    }


}

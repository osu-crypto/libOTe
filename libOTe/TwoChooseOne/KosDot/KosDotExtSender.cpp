#include "KosDotExtSender.h"
#ifdef ENABLE_DELTA_KOS

#include "libOTe/Tools/Tools.h"
#include <cryptoTools/Common/Matrix.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Crypto/Commit.h>
#include <cryptoTools/Network/Channel.h>
#include "libOTe/TwoChooseOne/TcoOtDefines.h"


namespace osuCrypto
{
    //#define KOS_DEBUG

    using namespace std;

    KosDotExtSender KosDotExtSender::splitBase()
    {
        std::vector<block> baseRecvOts(mGens.size());
        for (u64 i = 0; i < mGens.size(); ++i)
            baseRecvOts[i] = mGens[i].get<block>();

        return KosDotExtSender(baseRecvOts, mBaseChoiceBits);
    }

    std::unique_ptr<OtExtSender> KosDotExtSender::split()
    {
        std::vector<block> baseRecvOts(mGens.size());
        for (u64 i = 0; i < mGens.size(); ++i)
            baseRecvOts[i] = mGens[i].get<block>();

        return std::make_unique<KosDotExtSender>(baseRecvOts, mBaseChoiceBits);
    }

    void KosDotExtSender::setBaseOts(span<block> baseRecvOts, const BitVector& choices)
    {
        mBaseChoiceBits = choices;
        mGens.resize(choices.size());
        mBaseChoiceBits.resize(roundUpTo(mBaseChoiceBits.size(), 8));
        for (u64 i = mBaseChoiceBits.size() - 1; i >= choices.size(); --i)
            mBaseChoiceBits[i] = 0;

        mBaseChoiceBits.resize(choices.size());
        for (u64 i = 0; i < mGens.size(); i++)
            mGens[i].SetSeed(baseRecvOts[i]);
    }

    void KosDotExtSender::setDelta(const block& delta)
    {
        mDelta = delta;
    }

    void KosWarning();
    
    task<> KosDotExtSender::send(
        span<std::array<block, 2>> messages,
        PRNG& prng,
        Socket& chl)
    {
        KosWarning();

        MC_BEGIN(task<>,this, messages, &prng, &chl,
            numOtExt = u64{}, numSuperBlocks = u64{},
            t = Matrix<u8>{},
            u = std::vector<std::array<block, superBlkSize>>{},
            choiceMask = std::vector<block>{},
            delta = std::array<block, 2>{},
            extraBlocks = std::array<std::array<block, 2>, 128>{},
            xIter = (std::array<block, 2>*)nullptr,
            theirSeedComm = Commit{},
            mIter = span<std::array<block, 2>>::iterator{},
            mIterPartial = span<std::array<block, 2>>::iterator{},
            uIter = (block*)nullptr,
            uEnd = (block*)nullptr,
            superBlkIdx = u64{},
            step = u64{},
            seed = block{},
            offset = block{},
            theirSeed = block{},
            code = LinearCode{},
            q = std::array<block, 4>{},
            recv = std::array<block, 8>{}
        );

        if (hasBaseOts() == false)
            MC_AWAIT(genBaseOts(prng, chl));

        setTimePoint("KosDot.send.start");

        // round up
        numOtExt = roundUpTo(messages.size(), 128);
        numSuperBlocks = (numOtExt / 128 + superBlkSize) / superBlkSize;

        // a temp that will be used to transpose the sender's matrix
        t.resize(mGens.size(), superBlkSize * sizeof(block));
        u.resize(mGens.size() * commStepSize);

        choiceMask.resize(mBaseChoiceBits.size());
        delta = { ZeroBlock, ZeroBlock };

        memcpy(delta.data(), mBaseChoiceBits.data(), mBaseChoiceBits.sizeBytes());


        for (u64 i = 0; i < choiceMask.size(); ++i)
        {
            if (mBaseChoiceBits[i]) choiceMask[i] = AllOneBlock;
            else choiceMask[i] = ZeroBlock;
        }


        xIter = extraBlocks.data();

        MC_AWAIT(chl.recv(theirSeedComm));

        mIter = messages.begin();
        mIterPartial = messages.end() - std::min<u64>(128 * superBlkSize, messages.size());

        // set uIter = to the end so that it gets loaded on the first loop.
        uIter = (block*)u.data() + superBlkSize * mGens.size() * commStepSize;
        uEnd = uIter;

        for (superBlkIdx = 0; superBlkIdx < numSuperBlocks; ++superBlkIdx)
        {

            if (uIter == uEnd)
            {
                step = std::min<u64>(numSuperBlocks - superBlkIdx, (u64)commStepSize);
                MC_AWAIT(chl.recv(span<block>((block*)u.data(), step * superBlkSize * mGens.size())));
                uIter = (block*)u.data();
            }

            block* cIter = choiceMask.data();
            block* tIter = (block*)t.data();

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



            if (mIter >= mIterPartial)
            {
                Matrix<u8> tOut(128 * superBlkSize, sizeof(block) * 2);

                // transpose our 128 columns of 1024 bits. We will have 1024 rows,
                // each 128 bits wide.
                transpose(t, tOut);

                auto mCount = std::min<u64>(128 * superBlkSize, messages.end() - mIter);
                auto xCount = std::min<u64>(128 * superBlkSize - mCount, extraBlocks.data() + extraBlocks.size() - xIter);


                //std::copy(mIter, mIter + mCount, tOut.begin());
                if (mCount)
                    memcpy(&*mIter, tOut.data(), mCount * sizeof(block) * 2);
                mIter += mCount;


                memcpy(xIter, tOut.data() + mCount * sizeof(block) * 2, xCount * sizeof(block) * 2);
                xIter += xCount;
            }
            else
            {
                MatrixView<u8> tOut(
                    (u8*)&*mIter,
                    128 * superBlkSize,
                    sizeof(block) * 2);

                mIter += std::min<u64>(128 * superBlkSize, messages.end() - mIter);

                // transpose our 128 columns of 1024 bits. We will have 1024 rows,
                // each 128 bits wide.
                transpose(t, tOut);
            }

        }

        setTimePoint("KosDot.send.transposeDone");

        seed = prng.get<block>();
        MC_AWAIT(chl.send(std::move(seed)));

        {

            PRNG codePrng(seed);
            code.random(codePrng, mBaseChoiceBits.size(), 128);
            block curDelta;
            code.encode((u8*)delta.data(), (u8*)&curDelta);

            if (eq(mDelta, ZeroBlock))
                mDelta = prng.get<block>();
            offset = curDelta ^ mDelta;
        }

        MC_AWAIT(chl.send(std::move(offset)));

        MC_AWAIT(chl.recv(theirSeed));

        setTimePoint("KosDot.send.cncSeed");

        if (Commit(theirSeed) != theirSeedComm)
            throw std::runtime_error("bad commit " LOCATION);


        {

            PRNG commonPrng(seed ^ theirSeed);

            block  qi1, qi2, qi3, qi4;
            memset(q.data(), 0, 4 * sizeof(block));

            u64 doneIdx = 0;

            std::array<block, 128> challenges, challenges2;

            setTimePoint("KosDot.send.checkStart");

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

                    q[0] = q[0] ^ qi1;
                    q[1] = q[1] ^ qi2;
                    q[2] = q[2] ^ qi3;
                    q[3] = q[3] ^ qi4;

                    code.encode((u8*)messages[dd].data(), (u8*)&messages[dd][0]);
                    messages[dd][1] = messages[dd][0] ^ mDelta;
                }

                for (; dd < stop1; ++dd, ++i, ++xx)
                {
                    mul256(extraBlocks[xx][0], extraBlocks[xx][1], challenges[i], challenges2[i], qi1, qi2, qi3, qi4);
                    q[0] = q[0] ^ qi1;
                    q[1] = q[1] ^ qi2;
                    q[2] = q[2] ^ qi3;
                    q[3] = q[3] ^ qi4;
                }

                doneIdx = stop1;
            }
        }

        setTimePoint("KosDot.send.checkSummed");

        MC_AWAIT(chl.recv(recv));

        {
            block t1, t2, t3, t4;
            setTimePoint("KosDot.send.proofReceived");

            auto& received_x = ((std::array<block, 4>*)recv.data())[0];
            auto& received_t = ((std::array<block, 4>*)recv.data())[1];

            // check t = x * Delta + q
            mul256(received_x[0], received_x[1], delta[0], delta[1], t1, t2, t3, t4);
            t1 = t1 ^ q[0];
            t2 = t2 ^ q[1];
            t3 = t3 ^ q[2];
            t4 = t4 ^ q[3];

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
                std::cout << "q  = " << q[0] << std::endl;
                throw std::runtime_error("Exit");;
            }

            setTimePoint("KosDot.send.done");

            static_assert(gOtExtBaseOtCount == 128, "expecting 128");
        }

        MC_END();
    }

}
#endif
#include "KosDotExtReceiver.h"
#ifdef ENABLE_DELTA_KOS

#include "libOTe/Tools/Tools.h"

#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Matrix.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/Commit.h>
#include <cryptoTools/Network/Channel.h>

#include "libOTe/TwoChooseOne/TcoOtDefines.h"
#include <queue>

using namespace std;

namespace osuCrypto
{
    void KosDotExtReceiver::setBaseOts(span<std::array<block, 2>> baseOTs)
    {
        mGens.resize(baseOTs.size());
        for (u64 i = 0; i < u64(baseOTs.size()); i++)
        {
            mGens[i][0].SetSeed(baseOTs[i][0]);
            mGens[i][1].SetSeed(baseOTs[i][1]);
        }

        mHasBase = true;
    }

    KosDotExtReceiver KosDotExtReceiver::splitBase()
    {
        std::vector<std::array<block, 2>>baseRecvOts(mGens.size());

        for (u64 i = 0; i < mGens.size(); ++i)
        {
            baseRecvOts[i][0] = mGens[i][0].get<block>();
            baseRecvOts[i][1] = mGens[i][1].get<block>();
        }

        return KosDotExtReceiver(baseRecvOts);
    }

    std::unique_ptr<OtExtReceiver> KosDotExtReceiver::split()
    {
        std::vector<std::array<block, 2>>baseRecvOts(mGens.size());

        for (u64 i = 0; i < mGens.size(); ++i)
        {
            baseRecvOts[i][0] = mGens[i][0].get<block>();
            baseRecvOts[i][1] = mGens[i][1].get<block>();
        }

        return std::make_unique<KosDotExtReceiver>(baseRecvOts);
    }


    task<> KosDotExtReceiver::receive(
        const BitVector& choices,
        span<block> messages,
        PRNG& prng,
        Socket& chl)
    {
        MC_BEGIN(task<>,this, choices, messages, &prng, &chl,
            numOtExt = u64{},
            numSuperBlocks = u64{},
            numBlocks = u64{},
            seed = block{},
            myComm = Commit{},
            choices2 = BitVector{},
            choiceBlocks = span<block>{},
            t0 = Matrix<u8>{},
            messageTemp = Matrix<u8>{},
            mIter = Matrix<u8>::iterator{},
            step = u64{},
            uBuff = std::vector<block>{},
            uIter = (block*)nullptr,
            tIter = (block*)nullptr,
            cIter = (block*)nullptr,
            uEnd = (block*)nullptr,
            superBlkIdx = u64{},
            theirSeed = block{},
            offset = block{},
            correlationData = std::vector<std::array<block, 4>>(2)
        );
        if (hasBaseOts() == false) 
            MC_AWAIT(genBaseOts(prng, chl));

        setTimePoint("KosDot.recv.start");

        // we are going to process OTs in blocks of 128 * superBlkSize messages.
        numOtExt = roundUpTo(choices.size(), 128);
        numSuperBlocks = (numOtExt / 128 + superBlkSize) / superBlkSize;
        numBlocks = numSuperBlocks * superBlkSize;

        // commit to as seed which will be used to
        seed = prng.get<block>();
        myComm = Commit(seed);
        MC_AWAIT(chl.send(std::move(myComm)));

        // turn the choice vbitVector into an array of blocks.
        choices2.resize(numBlocks * 128);
        choices2 = choices;
        choices2.resize(numBlocks * 128);
        for (u64 i = 0; i < 128; ++i)
        {
            choices2[choices.size() + i] = prng.getBit();
        }

        choiceBlocks = choices2.getSpan<block>();
        // this will be used as temporary buffers of 128 columns,
        // each containing 1024 bits. Once transposed, they will be copied
        // into the T1, T0 buffers for long term storage.
        t0.resize(mGens.size(), superBlkSize * sizeof(block));

        messageTemp.resize(messages.size() + 128, sizeof(block) * 2);
        mIter = messageTemp.begin();


        step = std::min<u64>(numSuperBlocks, (u64)commStepSize);
        uBuff.resize(step * mGens.size() * superBlkSize);

        // get an array of blocks that we will fill.
        uIter = (block*)uBuff.data();
        uEnd = uIter + uBuff.size();



        // NOTE: We do not transpose a bit-matrix of size numCol * numCol.
        //   Instead we break it down into smaller chunks. We do 128 columns
        //   times 8 * 128 rows at a time, where 8 = superBlkSize. This is done for
        //   performance reasons. The reason for 8 is that most CPUs have 8 AES vector
        //   lanes, and so its more efficient to encrypt (aka prng) 8 blocks at a time.
        //   So that's what we do.
        for (superBlkIdx = 0; superBlkIdx < numSuperBlocks; ++superBlkIdx)
        {

            // the users next 128 choice bits. This will select what message is receiver.
            cIter = choiceBlocks.data() + superBlkSize * superBlkIdx;

            tIter = (block*)t0.data();
            memset(t0.data(), 0, superBlkSize * 128 * sizeof(block));

            // transpose 128 columns at at time. Each column will be 128 * superBlkSize = 1024 bits long.
            for (u64 colIdx = 0; colIdx < mGens.size(); ++colIdx)
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
                MC_AWAIT(chl.send(std::move(uBuff)));

                u64 step = std::min<u64>(numSuperBlocks - superBlkIdx - 1, (u64)commStepSize);

                if (step)
                {
                    uBuff.resize(step * mGens.size() * superBlkSize);
                    uIter = (block*)uBuff.data();
                    uEnd = uIter + uBuff.size();
                }
            }



            auto mCount = std::min<u64>((messageTemp.end() - mIter) / messageTemp.stride(), 128 * superBlkSize);

            MatrixView<u8> tOut(
                (u8*)&*mIter,
                mCount,
                messageTemp.stride());

            mIter += mCount * messageTemp.stride();

            // transpose our 128 columns of 1024 bits. We will have 1024 rows,
            // each 128 bits wide.
            transpose(t0, tOut);
        }


        setTimePoint("KosDot.recv.transposeDone");

        // do correlation check and hashing
        // For the malicious secure OTs, we need a random PRNG that is chosen random
        // for both parties. So that is what this is.
        MC_AWAIT(chl.recv(theirSeed));
        MC_AWAIT(chl.send(std::move(seed)));
        MC_AWAIT(chl.recv(offset));

        {

            setTimePoint("KosDot.recv.cncSeed");

            PRNG commonPrng(seed ^ theirSeed);
            PRNG codePrng(theirSeed);
            LinearCode code;
            code.random(codePrng, mGens.size(), 128);

            // this buffer will be sent to the other party to prove we used the
            // same value of r in all of the column vectors...
            auto& x = correlationData[0];
            auto& t = correlationData[1];

            x = t = { ZeroBlock,ZeroBlock, ZeroBlock, ZeroBlock };
            block ti1, ti2, ti3, ti4;

            u64 doneIdx = (0);

            std::array<block, 2> zeroOneBlk{ ZeroBlock, AllOneBlock };
            std::array<block, 128> challenges, challenges2;

            std::array<block, 8> expendedChoiceBlk;
            std::array<std::array<u8, 16>, 8>& expendedChoice = *reinterpret_cast<std::array<std::array<u8, 16>, 8>*>(&expendedChoiceBlk);

            block mask = block(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1);

            //std::cout << IoStream::lock;

            auto msg = (std::array<block, 2>*)messageTemp.data();

            u64 bb = (messageTemp.bounds()[0] + 127) / 128;
            for (u64 blockIdx = 0; blockIdx < bb; ++blockIdx)
            {
                commonPrng.mAes.ecbEncCounterMode(doneIdx, 128, challenges.data());
                commonPrng.mAes.ecbEncCounterMode(doneIdx, 128, challenges2.data());

                u64 stop0 = std::min<u64>(messages.size(), doneIdx + 128);
                u64 stop1 = std::min<u64>(messageTemp.bounds()[0], doneIdx + 128);

                expendedChoiceBlk[0] = mask & choiceBlocks[blockIdx].srai_epi16(0);
                expendedChoiceBlk[1] = mask & choiceBlocks[blockIdx].srai_epi16(1);
                expendedChoiceBlk[2] = mask & choiceBlocks[blockIdx].srai_epi16(2);
                expendedChoiceBlk[3] = mask & choiceBlocks[blockIdx].srai_epi16(3);
                expendedChoiceBlk[4] = mask & choiceBlocks[blockIdx].srai_epi16(4);
                expendedChoiceBlk[5] = mask & choiceBlocks[blockIdx].srai_epi16(5);
                expendedChoiceBlk[6] = mask & choiceBlocks[blockIdx].srai_epi16(6);
                expendedChoiceBlk[7] = mask & choiceBlocks[blockIdx].srai_epi16(7);

                u64 i = 0, dd = doneIdx;
                for (; dd < stop0; ++dd, ++i)
                {
                    auto maskBlock = zeroOneBlk[expendedChoice[i % 8][i / 8]];
                    x[0] = x[0] ^ (challenges[i] & maskBlock);
                    x[1] = x[1] ^ (challenges2[i] & maskBlock);

                    mul256(msg[dd][0], msg[dd][1], challenges[i], challenges2[i], ti1, ti2, ti3, ti4);
                    t[0] = t[0] ^ ti1;
                    t[1] = t[1] ^ ti2;
                    t[2] = t[2] ^ ti3;
                    t[3] = t[3] ^ ti4;

                    code.encode((u8*)msg[dd].data(), (u8*)&messages[dd]);

                    messages[dd] = messages[dd] ^ (maskBlock & offset);
                }

                for (; dd < stop1; ++dd, ++i)
                {

                    x[0] = x[0] ^ (challenges[i] & zeroOneBlk[expendedChoice[i % 8][i / 8]]);
                    x[1] = x[1] ^ (challenges2[i] & zeroOneBlk[expendedChoice[i % 8][i / 8]]);

                    mul256(msg[dd][0], msg[dd][1], challenges[i], challenges2[i], ti1, ti2, ti3, ti4);
                    t[0] = t[0] ^ ti1;
                    t[1] = t[1] ^ ti2;
                    t[2] = t[2] ^ ti3;
                    t[3] = t[3] ^ ti4;
                }


                doneIdx = stop1;
            }
        }

        MC_AWAIT(chl.send(std::move(correlationData)));

        setTimePoint("KosDot.recv.done");

        static_assert(gOtExtBaseOtCount == 128, "expecting 128");

        MC_END();
    }

}
#endif
#include "IknpDotExtReceiver.h"
#ifdef ENABLE_DELTA_IKNP
#include "libOTe/Tools/Tools.h"

#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Matrix.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/Commit.h>
#include <cryptoTools/Network/Channel.h>

#include "TcoOtDefines.h"
#include <queue>


namespace osuCrypto
{
    void IknpDotExtReceiver::setBaseOts(gsl::span<std::array<block, 2>> baseOTs)
    {
        mGens.resize(baseOTs.size());
        for (u64 i = 0; i <u64(baseOTs.size()); i++)
        {
            mGens[i][0].SetSeed(baseOTs[i][0]);
            mGens[i][1].SetSeed(baseOTs[i][1]);
        }

        mHasBase = true;
    }

    IknpDotExtReceiver IknpDotExtReceiver::splitBase()
    {
        std::vector<std::array<block, 2>>baseRecvOts(mGens.size());

        for (u64 i = 0; i < mGens.size(); ++i)
        {
            baseRecvOts[i][0] = mGens[i][0].get<block>();
            baseRecvOts[i][1] = mGens[i][1].get<block>();
        }

        return IknpDotExtReceiver(baseRecvOts);
    }

    std::unique_ptr<OtExtReceiver> IknpDotExtReceiver::split()
    {
        std::vector<std::array<block, 2>>baseRecvOts(mGens.size());

        for (u64 i = 0; i < mGens.size(); ++i)
        {
            baseRecvOts[i][0] = mGens[i][0].get<block>();
            baseRecvOts[i][1] = mGens[i][1].get<block>();
        }

        return std::make_unique<IknpDotExtReceiver>(baseRecvOts);
    }


    void IknpDotExtReceiver::receive(
        const BitVector& choices,
        gsl::span<block> messages,
        PRNG& prng,
        Channel& chl)
    {
        if (hasBaseOts() == false)
            genBaseOts(prng, chl);

        setTimePoint("IknpDot.recv.transposeDone");

        // we are going to process OTs in blocks of 128 * superBlkSize messages.
        u64 numOtExt = roundUpTo(choices.size(), 128 * superBlkSize);
        u64 numSuperBlocks = numOtExt / 128 / superBlkSize;
        u64 numBlocks = numSuperBlocks * superBlkSize;

        // turn the choice vbitVector into an array of blocks.
        BitVector choices2(numBlocks * 128);
        choices2 = choices;
		choices2.resize(numBlocks * 128);

        auto choiceBlocks = choices2.getSpan<block>();
        // this will be used as temporary buffers of 128 columns,
        // each containing 1024 bits. Once transposed, they will be copied
        // into the T1, T0 buffers for long term storage.
        Matrix<u8> t0(mGens.size(), superBlkSize * sizeof(block));

        Matrix<u8> messageTemp(messages.size(), sizeof(block) * 2);
        auto mIter = messageTemp.begin();


        u64 step = std::min<u64>(numSuperBlocks, (u64)commStepSize);
        std::vector<block> uBuff(step * mGens.size() * superBlkSize);

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

            // the users next 128 choice bits. This will select what message is receiver.
            block* cIter = choiceBlocks.data() + superBlkSize * superBlkIdx;



            block* tIter = (block*)t0.data();
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
                chl.asyncSend(std::move(uBuff));

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
            sse_transpose(t0, tOut);
        }


        setTimePoint("IknpDot.recv.transposeDone");

        // do correlation check and hashing
        // For the malicious secure OTs, we need a random PRNG that is chosen random
        // for both parties. So that is what this is.
        PRNG commonPrng;
        block theirSeed;
        chl.recv((u8*)&theirSeed, sizeof(block));

		block offset;
		chl.recv(offset);


        setTimePoint("IknpDot.recv.cncSeed");

        PRNG codePrng(theirSeed);
        LinearCode code;
        code.random(codePrng, mGens.size(), 128);

        u64 doneIdx = (0);

        std::array<block, 2> zeroOneBlk{ ZeroBlock, AllOneBlock };

        std::array<block, 8> expendedChoiceBlk;
        std::array<std::array<u8, 16>, 8>& expendedChoice = *reinterpret_cast<std::array<std::array<u8, 16>, 8>*>(&expendedChoiceBlk);

        block mask = _mm_set_epi8(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1);

        //std::cout << IoStream::lock;

        auto msg = (std::array<block, 2>*)messageTemp.data();

        u64 bb = (messageTemp.bounds()[0] + 127) / 128;
        for (u64 blockIdx = 0; blockIdx < bb; ++blockIdx)
        {
            u64 stop0 = std::min<u64>(messages.size(), doneIdx + 128);

            expendedChoiceBlk[0] = mask & _mm_srai_epi16(choiceBlocks[blockIdx], 0);
            expendedChoiceBlk[1] = mask & _mm_srai_epi16(choiceBlocks[blockIdx], 1);
            expendedChoiceBlk[2] = mask & _mm_srai_epi16(choiceBlocks[blockIdx], 2);
            expendedChoiceBlk[3] = mask & _mm_srai_epi16(choiceBlocks[blockIdx], 3);
            expendedChoiceBlk[4] = mask & _mm_srai_epi16(choiceBlocks[blockIdx], 4);
            expendedChoiceBlk[5] = mask & _mm_srai_epi16(choiceBlocks[blockIdx], 5);
            expendedChoiceBlk[6] = mask & _mm_srai_epi16(choiceBlocks[blockIdx], 6);
            expendedChoiceBlk[7] = mask & _mm_srai_epi16(choiceBlocks[blockIdx], 7);

            u64 i = 0, dd = doneIdx;
            for (; dd < stop0; ++dd, ++i)
            {
				auto maskBlock = zeroOneBlk[expendedChoice[i % 8][i / 8]];

                code.encode((u8*)msg[dd].data(),(u8*)&messages[dd]);

				messages[dd] = messages[dd] ^ (maskBlock & offset);
            }

            doneIdx = stop0;
        }

        setTimePoint("IknpDot.recv.done");

        static_assert(gOtExtBaseOtCount == 128, "expecting 128");
    }

}
#endif
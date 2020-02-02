#include "IknpDotExtSender.h"
#ifdef ENABLE_DELTA_IKNP
#include "libOTe/Tools/Tools.h"
#include <cryptoTools/Common/Matrix.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Crypto/Commit.h>
#include <cryptoTools/Network/Channel.h>
#include "TcoOtDefines.h"


namespace osuCrypto
{


    IknpDotExtSender IknpDotExtSender::splitBase()
    {
        std::vector<block> baseRecvOts(mGens.size());
        for (u64 i = 0; i < mGens.size(); ++i)
            baseRecvOts[i] = mGens[i].get<block>();

        return IknpDotExtSender(baseRecvOts, mBaseChoiceBits);
    }

    std::unique_ptr<OtExtSender> IknpDotExtSender::split()
    {
        std::vector<block> baseRecvOts(mGens.size());
        for (u64 i = 0; i < mGens.size(); ++i)
            baseRecvOts[i] = mGens[i].get<block>();

        return std::make_unique<IknpDotExtSender>(baseRecvOts, mBaseChoiceBits);
    }

    void IknpDotExtSender::setBaseOts(span<block> baseRecvOts, const BitVector & choices)
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

	void IknpDotExtSender::setDelta(const block & delta)
	{
		mDelta = delta;
	}

    void IknpDotExtSender::send(
        span<std::array<block, 2>> messages,
        PRNG& prng,
        Channel& chl)
    {
        setTimePoint("IknpDot.send.transposeDone");

        // round up
        u64 numOtExt = roundUpTo(messages.size(), 128 * superBlkSize);
        u64 numSuperBlocks = numOtExt / 128 / superBlkSize;

        // a temp that will be used to transpose the sender's matrix
        Matrix<u8> t(mGens.size(), superBlkSize * sizeof(block));
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

        auto mIter = messages.begin();
        auto mIterPartial = messages.end() - std::min<u64>(128 * superBlkSize, messages.size());


        // set uIter = to the end so that it gets loaded on the first loop.
        block * uIter = (block*)u.data() + superBlkSize * mGens.size()  * commStepSize;
        block * uEnd = uIter;

        for (u64 superBlkIdx = 0; superBlkIdx < numSuperBlocks; ++superBlkIdx)
        {

            if (uIter == uEnd)
            {
                u64 step = std::min<u64>(numSuperBlocks - superBlkIdx, (u64)commStepSize);
                chl.recv((u8*)u.data(), step * superBlkSize * mGens.size() * sizeof(block));
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



            if (mIter >= mIterPartial)
            {
                Matrix<u8> tOut(128 * superBlkSize, sizeof(block) * 2);

                // transpose our 128 columns of 1024 bits. We will have 1024 rows,
                // each 128 bits wide.
                sse_transpose(t, tOut);

                auto mCount = std::min<u64>(128 * superBlkSize, messages.end() - mIter);
                auto xCount = std::min<u64>(128 * superBlkSize - mCount, extraBlocks.data() + extraBlocks.size() - xIter);


                //std::copy(mIter, mIter + mCount, tOut.begin());
                if(mCount) memcpy(&*mIter, tOut.data(), mCount * sizeof(block) * 2);
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
                sse_transpose(t, tOut);
            }

        }

        setTimePoint("IknpDot.send.transposeDone");

        block seed = prng.get<block>();
        chl.asyncSend((u8*)&seed, sizeof(block));

		PRNG codePrng(seed);
        LinearCode code;
        code.random(codePrng, mBaseChoiceBits.size(), 128);
		block curDelta;
		code.encode((u8*)delta.data(), (u8*)&curDelta);

		if (eq(mDelta, ZeroBlock))
			mDelta = prng.get<block>();

		block offset = curDelta ^ mDelta;
		chl.asyncSend(offset);

        u64 doneIdx = 0;

        setTimePoint("IknpDot.send.checkStart");



        u64 bb = (messages.size() + 127) / 128;
        for (u64 blockIdx = 0; blockIdx < bb; ++blockIdx)
        {

            u64 stop0 = std::min<u64>(messages.size(), doneIdx + 128);

            u64 i = 0, dd = doneIdx;
            for (; dd < stop0; ++dd, ++i)
            {
                code.encode((u8*)messages[dd].data(), (u8*)&messages[dd][0]);
				messages[dd][1] = messages[dd][0] ^ mDelta;
            }

            doneIdx = stop0;
        }

        setTimePoint("IknpDot.send.done");

        static_assert(gOtExtBaseOtCount == 128, "expecting 128");
    }


}
#endif
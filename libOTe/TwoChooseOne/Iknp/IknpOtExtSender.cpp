#include "IknpOtExtSender.h"
#ifdef ENABLE_IKNP
#include "libOTe/Tools/Tools.h"
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Crypto/Commit.h>

#include "libOTe/TwoChooseOne/TcoOtDefines.h"

namespace osuCrypto
{


	IknpOtExtSender IknpOtExtSender::splitBase()
	{
		std::array<block, gOtExtBaseOtCount> baseRecvOts;

		if (!hasBaseOts())
			throw std::runtime_error("base OTs have not been set. " LOCATION);

		mGens.ecbEncCounterMode(mPrngIdx++, baseRecvOts.data());
		return IknpOtExtSender(baseRecvOts, mBaseChoiceBits);
	}

	std::unique_ptr<OtExtSender> IknpOtExtSender::split()
	{
		return std::make_unique<IknpOtExtSender>(splitBase());
	}

	void IknpOtExtSender::setBaseOts(span<block> baseRecvOts, const BitVector& choices)
	{
		if (baseRecvOts.size() != gOtExtBaseOtCount || choices.size() != gOtExtBaseOtCount)
			throw std::runtime_error("not supported/implemented");

		mBaseChoiceBits = choices;
		mGens.setKeys(baseRecvOts);
	}

	task<> IknpOtExtSender::send(
		span<std::array<block, 2>> messages,
		PRNG& prng,
		Socket& chl)
	{
		MC_BEGIN(task<>, this, messages, &prng, &chl,
			numOtExt = u64{},
			numSuperBlocks = u64{},
			step = u64{},
			superBlkIdx = u64{},
			// a temp that will be used to transpose the sender's matrix
			t = AlignedUnVector<block>{ 128 },
			u = AlignedUnVector<block>(128 * commStepSize),
			choiceMask = AlignedArray<block, 128>{},
			delta = block{},
			recvView = span<u8>{},
			mIter = span<std::array<block, 2>>::iterator{},
			uIter = (block*)nullptr,
			tIter = (block*)nullptr,
			cIter = (block*)nullptr,
			uEnd = (block*)nullptr
		);

		if (hasBaseOts() == false)
			MC_AWAIT(genBaseOts(prng, chl));

		// round up 
		numOtExt = roundUpTo(messages.size(), 128);
		numSuperBlocks = (numOtExt / 128);
		//u64 numBlocks = numSuperBlocks * superBlkSize;


		delta = *(block*)mBaseChoiceBits.data();

		for (u64 i = 0; i < 128; ++i)
		{
			if (mBaseChoiceBits[i]) choiceMask[i] = AllOneBlock;
			else choiceMask[i] = ZeroBlock;
		}

		mIter = messages.begin();
		uEnd = u.data() + u.size();
		uIter = uEnd;

		for (superBlkIdx = 0; superBlkIdx < numSuperBlocks; ++superBlkIdx)
		{
			tIter = (block*)t.data();
			cIter = choiceMask.data();

			if (uIter == uEnd)
			{
				step = std::min<u64>(numSuperBlocks - superBlkIdx, (u64)commStepSize);
				step *= 128 * sizeof(block);
				recvView = span<u8>((u8*)u.data(), step);
				uIter = u.data();

				MC_AWAIT(chl.recv(recvView));
			}

			mGens.ecbEncCounterMode(mPrngIdx, tIter);
			++mPrngIdx;

			// transpose 128 columns at at time. Each column will be 128 * superBlkSize = 1024 bits long.
			for (u64 colIdx = 0; colIdx < 128 / 8; ++colIdx)
			{
				uIter[0] = uIter[0] & cIter[0];
				uIter[1] = uIter[1] & cIter[1];
				uIter[2] = uIter[2] & cIter[2];
				uIter[3] = uIter[3] & cIter[3];
				uIter[4] = uIter[4] & cIter[4];
				uIter[5] = uIter[5] & cIter[5];
				uIter[6] = uIter[6] & cIter[6];
				uIter[7] = uIter[7] & cIter[7];

				tIter[0] = tIter[0] ^ uIter[0];
				tIter[1] = tIter[1] ^ uIter[1];
				tIter[2] = tIter[2] ^ uIter[2];
				tIter[3] = tIter[3] ^ uIter[3];
				tIter[4] = tIter[4] ^ uIter[4];
				tIter[5] = tIter[5] ^ uIter[5];
				tIter[6] = tIter[6] ^ uIter[6];
				tIter[7] = tIter[7] ^ uIter[7];

				cIter += 8;
				uIter += 8;
				tIter += 8;
			}

			// transpose our 128 columns of 1024 bits. We will have 1024 rows,
			// each 128 bits wide.
			transpose128(t.data());


			auto mEnd = mIter + std::min<u64>(128, messages.end() - mIter);

			tIter = t.data();
			if (mEnd - mIter == 128)
			{
				for (u64 i = 0; i < 128; i += 8)
				{
					mIter[i + 0][0] = tIter[i + 0];
					mIter[i + 1][0] = tIter[i + 1];
					mIter[i + 2][0] = tIter[i + 2];
					mIter[i + 3][0] = tIter[i + 3];
					mIter[i + 4][0] = tIter[i + 4];
					mIter[i + 5][0] = tIter[i + 5];
					mIter[i + 6][0] = tIter[i + 6];
					mIter[i + 7][0] = tIter[i + 7];
					mIter[i + 0][1] = tIter[i + 0] ^ delta;
					mIter[i + 1][1] = tIter[i + 1] ^ delta;
					mIter[i + 2][1] = tIter[i + 2] ^ delta;
					mIter[i + 3][1] = tIter[i + 3] ^ delta;
					mIter[i + 4][1] = tIter[i + 4] ^ delta;
					mIter[i + 5][1] = tIter[i + 5] ^ delta;
					mIter[i + 6][1] = tIter[i + 6] ^ delta;
					mIter[i + 7][1] = tIter[i + 7] ^ delta;

				}

				mIter += 128;

			}
			else
			{
				while (mIter != mEnd)
				{
					(*mIter)[0] = *tIter;
					(*mIter)[1] = *tIter ^ delta;

					tIter += 1;
					mIter += 1;
				}
			}

#ifdef IKNP_DEBUG
			fix this...
			BitVector choice(128 * superBlkSize);
			chl.recv(u.data(), superBlkSize * 128 * sizeof(block));
			chl.recv(choice.data(), sizeof(block) * superBlkSize);

			u64 doneIdx = mStart - messages.data();
			u64 xx = std::min<u64>(i64(128 * superBlkSize), (messages.data() + messages.size()) - mEnd);
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
		}


		if (mHash)
		{

#ifdef IKNP_SHA_HASH
			RandomOracle sha;
			u8 hashBuff[20];
			u64 doneIdx = 0;


			u64 bb = (messages.size() + 127) / 128;
			for (u64 blockIdx = 0; blockIdx < bb; ++blockIdx)
			{
				u64 stop = std::min<u64>(messages.size(), doneIdx + 128);

				for (u64 i = 0; doneIdx < stop; ++doneIdx, ++i)
				{
					// hash the message without delta
					sha.Reset();
					sha.Update((u8*)&messages[doneIdx][0], sizeof(block));
					sha.Final(hashBuff);
					messages[doneIdx][0] = *(block*)hashBuff;

					// hash the message with delta
					sha.Reset();
					sha.Update((u8*)&messages[doneIdx][1], sizeof(block));
					sha.Final(hashBuff);
					messages[doneIdx][1] = *(block*)hashBuff;
				}
			}
#else

			mAesFixedKey.hashBlocks((block*)messages.data(), messages.size() * 2, (block*)messages.data());
		}
#endif
		MC_END();
		static_assert(gOtExtBaseOtCount == 128, "expecting 128");
	}


}


#endif

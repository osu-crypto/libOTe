#include "IknpOtExtSender.h"
#ifdef ENABLE_IKNP
#include "libOTe/Tools/Tools.h"
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Crypto/Commit.h>
#include <cryptoTools/Network/Channel.h>

#include "TcoOtDefines.h"
#include <iomanip>

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

	void IknpOtExtSender::send(
		span<std::array<block, 2>> messages,
		PRNG& prng,
		Channel& chl)
	{

		if (hasBaseOts() == false)
			genBaseOts(prng, chl);

		// round up
		static const auto commStepSize = 512 * 8;
		static const auto superBlkSize = 1;

		u64 numOtExt = roundUpTo(messages.size(), 128);
		u64 numSuperBlocks = (numOtExt / 128 + superBlkSize - 1) / superBlkSize;
		//u64 numBlocks = numSuperBlocks * superBlkSize;

		// a temp that will be used to transpose the sender's matrix
		AlignedArray<block, 128> t;
		AlignedUnVector<block> u(128 * commStepSize);

		AlignedArray<block, 128> choiceMask;
		block delta = *(block*)mBaseChoiceBits.data();

		for (u64 i = 0; i < 128; ++i)
		{
			if (mBaseChoiceBits[i]) choiceMask[i] = AllOneBlock;
			else choiceMask[i] = ZeroBlock;
		}

		auto mIter = messages.begin();

		block* uIter = (block*)u.data() + superBlkSize * 128 * commStepSize;
		block* uEnd = uIter;

		for (u64 superBlkIdx = 0; superBlkIdx < numSuperBlocks; ++superBlkIdx)
		{


			block* tIter = (block*)t.data();
			block* cIter = choiceMask.data();

			if (uIter == uEnd)
			{
				u64 step = std::min<u64>(numSuperBlocks - superBlkIdx, (u64)commStepSize);

				chl.recv((u8*)u.data(), step * superBlkSize * 128 * sizeof(block));
				uIter = (block*)u.data();
			}

			mGens.ecbEncCounterMode(mPrngIdx, tIter);
			++mPrngIdx;

			// transpose 128 columns at at time. Each column will be 128 * superBlkSize = 1024 bits long.
			for (u64 colIdx = 0; colIdx < 128 / 8; ++colIdx)
			{
				//// generate the columns using AES-NI in counter mode.
				//mGens[colIdx].mAes.ecbEncCounterMode(mGens[colIdx].mBlockIdx, superBlkSize, tIter);
				//mGens[colIdx].mBlockIdx += superBlkSize;

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


			auto mEnd = mIter + std::min<u64>(128 * superBlkSize, messages.end() - mIter);

			tIter = (block*)t.data();
			block* tEnd = (block*)t.data() + 128 * superBlkSize;
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
					while (mIter != mEnd && tIter < tEnd)
					{
						(*mIter)[0] = *tIter;
						(*mIter)[1] = *tIter ^ delta;

						tIter += superBlkSize;
						mIter += 1;
					}

					tIter = tIter - 128 * superBlkSize + 1;
				}
			}

#ifdef IKNP_DEBUG
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
			//std::array<block, 8> aesHashTemp;

			//u64 doneIdx = 0;
			//u64 bb = (messages.size() + 127) / 128;
			//for (u64 blockIdx = 0; blockIdx < bb; ++blockIdx)
			//{
			//	u64 stop = std::min<u64>(messages.size(), doneIdx + 128);
			//	//auto length = 2 * (stop - doneIdx);
			//	//auto steps = length / 8;
			//	//block* mIter = messages[doneIdx].data();
			//	//for (u64 i = 0; i < steps; ++i)
			//	//{
			//	//	mAesFixedKey.ecbEncBlocks(mIter, 8, aesHashTemp.data());
			//	//	mIter[0] = mIter[0] ^ aesHashTemp[0];
			//	//	mIter[1] = mIter[1] ^ aesHashTemp[1];
			//	//	mIter[2] = mIter[2] ^ aesHashTemp[2];
			//	//	mIter[3] = mIter[3] ^ aesHashTemp[3];
			//	//	mIter[4] = mIter[4] ^ aesHashTemp[4];
			//	//	mIter[5] = mIter[5] ^ aesHashTemp[5];
			//	//	mIter[6] = mIter[6] ^ aesHashTemp[6];
			//	//	mIter[7] = mIter[7] ^ aesHashTemp[7];

			//	//	mIter += 8;
			//	//}

			//	//auto rem = length - steps * 8;
			//	//mAesFixedKey.ecbEncBlocks(mIter, rem, aesHashTemp.data());
			//	//for (u64 i = 0; i < rem; ++i)
			//	//{
			//	//	mIter[i] = mIter[i] ^ aesHashTemp[i];
			//	//}

			//	doneIdx = stop;
			//}
		}
#endif

		static_assert(gOtExtBaseOtCount == 128, "expecting 128");
	}


}
#endif
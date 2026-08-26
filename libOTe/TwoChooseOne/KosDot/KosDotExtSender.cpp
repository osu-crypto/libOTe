#include "KosDotExtSender.h"
#ifdef ENABLE_DELTA_KOS

#include "libOTe/Tools/Tools.h"
#include <cryptoTools/Common/Matrix.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Crypto/Commit.h>
#include <cryptoTools/Network/Channel.h>
#include "libOTe/TwoChooseOne/KosDot/KosDotExtCheck.h"
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

		auto child = KosDotExtSender(baseRecvOts, mBaseChoiceBits);
		child.mDelta = mDelta;
		child.mHasDelta = mHasDelta || neq(mDelta, ZeroBlock);
		child.mCodeState = mCodeState;
		return child;
	}

	std::unique_ptr<OtExtSender> KosDotExtSender::split()
	{
		std::vector<block> baseRecvOts(mGens.size());
		for (u64 i = 0; i < mGens.size(); ++i)
			baseRecvOts[i] = mGens[i].get<block>();

		auto child = std::make_unique<KosDotExtSender>(baseRecvOts, mBaseChoiceBits);
		child->mDelta = mDelta;
		child->mHasDelta = mHasDelta || neq(mDelta, ZeroBlock);
		child->mCodeState = mCodeState;
		return child;
	}

	void KosDotExtSender::setBaseOts(span<block> baseRecvOts, const BitVector& choices)
	{
		if (baseRecvOts.size() != baseOtCount() || choices.size() != baseOtCount())
			throw std::runtime_error("KosDot base OT count mismatch. " LOCATION);

		mBaseChoiceBits = choices;
		mGens.resize(choices.size());
		mCodeState = std::make_shared<details::KosDotCodeState>();
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
		mHasDelta = true;
	}


	task<> KosDotExtSender::send(
		span<std::array<block, 2>> messages,
		PRNG& prng,
		Socket& chl)
	{
		MACORO_TRY{

		auto numOtExt = u64{};
		auto numSuperBlocks = u64{};
		auto t = Matrix<u8>{};
		auto u = std::vector<std::array<block, superBlkSize>>{};
		auto choiceMask = std::vector<block>{};
		auto delta = std::array<block, 2>{};
		auto extraBlocks = std::array<std::array<block, 2>, 128>{};
		auto xIter = (std::array<block, 2>*)nullptr;
		auto theirSeedComm = Commit{};
		auto mIter = span<std::array<block, 2>>::iterator{};
		auto mIterPartial = span<std::array<block, 2>>::iterator{};
		auto uIter = (block*)nullptr;
		auto uEnd = (block*)nullptr;
		auto superBlkIdx = u64{};
		auto step = u64{};
		auto codeSeed = block{};
		auto checkSeed = block{};
		auto offset = block{};
		auto theirSeed = block{};
		auto recv = details::KosDotProof{};

		if (hasBaseOts() == false)
			co_await genBaseOts(prng, chl);

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

		co_await chl.recv(theirSeedComm);

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
				co_await(chl.recv(span<block>((block*)u.data(), step * superBlkSize * mGens.size())));
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

		mCodeState->initSender(prng);
		codeSeed = mCodeState->seed();
		checkSeed = prng.get<block>();
		co_await chl.send(std::array<block, 2>{ codeSeed, checkSeed });

		{
			const auto& code = mCodeState->code();
			block curDelta;
			code.encode((u8*)delta.data(), (u8*)&curDelta);

			if (!mHasDelta && neq(mDelta, ZeroBlock))
				mHasDelta = true;
			if (!mHasDelta)
			{
				mDelta = prng.get<block>();
				mHasDelta = true;
			}
			offset = curDelta ^ mDelta;
		}

		co_await chl.send(std::move(offset));
		co_await chl.recv(theirSeed);

		setTimePoint("KosDot.send.cncSeed");

		if (Commit(theirSeed) != theirSeedComm)
			throw std::runtime_error("bad commit " LOCATION);


		setTimePoint("KosDot.send.checkStart");
		auto q = details::kosDotColumnCheck(
			span<const details::KosDotCheckRow>(messages.data(), messages.size()),
			span<const details::KosDotCheckRow>(extraBlocks.data(), extraBlocks.size()),
			checkSeed ^ theirSeed);

		setTimePoint("KosDot.send.checkSummed");

		co_await chl.recv(recv);

		{
			setTimePoint("KosDot.send.proofReceived");

			auto received_x = recv.back();
			for (u64 i = 0; i < details::KosDotCheckColumns; ++i)
			{
				auto expected = q[i] ^
					(received_x & zeroAndAllOne[mBaseChoiceBits[i]]);
				if (expected != recv[i])
					throw std::runtime_error("KOS-Dot, bad malicious check. " LOCATION);
			}

			const auto& code = mCodeState->code();
			for (auto& row : messages)
			{
				block output;
				code.encode(reinterpret_cast<u8*>(row.data()),
					reinterpret_cast<u8*>(&output));
				row[0] = output;
				row[1] = output ^ mDelta;
			}
		}

		setTimePoint("KosDot.send.done");
		static_assert(gOtExtBaseOtCount == 128, "expecting 128");

		} MACORO_CATCH(eptr) {
			if (!chl.closed()) co_await chl.close();
			std::rethrow_exception(eptr);
		}
	}

}
#endif

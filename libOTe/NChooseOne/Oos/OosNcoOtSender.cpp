#include "OosNcoOtSender.h"
#ifdef ENABLE_OOS
#include "libOTe/Tools/Tools.h"
#include "libOTe/Tools/bch511.h"
#include <cryptoTools/Crypto/RandomOracle.h>
#include <cryptoTools/Network/Channel.h>
#include "OosDefines.h"

namespace osuCrypto
{

	u64 OosNcoOtSender::getBaseOTCount() const
	{
		if (mGens.size())
			return mGens.size();
		else
			throw std::runtime_error("must call configure(...) before getBaseOTCount() " LOCATION);
	}

	task<> OosNcoOtSender::setBaseOts(
		span<block> baseRecvOts,
		const BitVector& choices, Socket& chl)
	{
		MC_BEGIN(task<>, this, baseRecvOts, &choices, &chl,
			delta = BitVector{});

		delta.resize(choices.size());

		MC_AWAIT(chl.recv(delta));

		setUniformBaseOts(baseRecvOts, choices ^ delta);

		MC_END();
	}

	void OosNcoOtSender::setUniformBaseOts(span<block> baseRecvOts, const BitVector& uniformChoices)
	{
		if (uniformChoices.size() != u64(baseRecvOts.size()))
			throw std::runtime_error("size mismatch");

		if (uniformChoices.size() % (sizeof(block) * 8) != 0)
			throw std::runtime_error("only multiples of 128 are supported");

		mBaseChoiceBits = uniformChoices;
		mGens.resize(uniformChoices.size());

		for (u64 i = 0; i < u64(baseRecvOts.size()); i++)
		{
			mGens[i].SetSeed(baseRecvOts[i]);
		}

		mChoiceBlks.resize(uniformChoices.size() / (sizeof(block) * 8));
		for (u64 i = 0; i < mChoiceBlks.size(); ++i)
		{
			mChoiceBlks[i] = toBlock(mBaseChoiceBits.data() + (i * sizeof(block)));
		}
	}

	OosNcoOtSender OosNcoOtSender::splitBase()
	{
		OosNcoOtSender raw;
		raw.mCode = mCode;
		raw.mInputByteCount = mInputByteCount;
		raw.mStatSecParam = mStatSecParam;
		raw.mGens.resize(mGens.size());
		raw.mMalicious = mMalicious;
		//raw->mChoiceBlks = mChoiceBlks;

		if (hasBaseOts())
		{
			std::vector<block> base(mGens.size());
			// use some of the OT extension PRNG to new base OTs
			for (u64 i = 0; i < base.size(); ++i)
			{
				base[i] = mGens[i].get<block>();
			}
			raw.setUniformBaseOts(base, mBaseChoiceBits);
		}
#ifdef OC_NO_MOVE_ELISION
		return std::move(raw);
#else
		return raw;
#endif
	}


	std::unique_ptr<NcoOtExtSender> OosNcoOtSender::split()
	{
		return std::make_unique<OosNcoOtSender>((splitBase()));
	}


	task<> OosNcoOtSender::init(
		u64 numOTExt, PRNG& prng, Socket& chl)
	{
		MC_BEGIN(task<>, this, numOTExt, &prng, &chl);

		if (mInputByteCount == 0)
			throw std::runtime_error("configure must be called first" LOCATION);

		if (hasBaseOts() == false)
			MC_AWAIT(genBaseOts(prng, chl));

		{
			const u8 superBlkSize(8);
			// round up
			numOTExt = ((numOTExt + 127 + mStatSecParam) / 128) * 128;

			// We need two matrices, one for the senders matrix T^i_{b_i} and
			// one to hold the the correction values. This is sometimes called
			// the u = T0 + T1 + C matrix in the papers.
			mCorrectionVals = Matrix<block>();
			mCorrectionVals.resize(numOTExt, mGens.size() / 128);
			mT = Matrix<block>();
			mT.resize(numOTExt, mGens.size() / 128);

			// The receiver will send us correction values, this is the index of
			// the next one they will send.
			mCorrectionIdx = 0;

			// we are going to process OTs in blocks of 128 * superblkSize messages.
			u64 numSuperBlocks = (numOTExt / 128 + superBlkSize - 1) / superBlkSize;

			// the index of the last OT that we have completed.
			u64 doneIdx = 0;

        // a temp that will be used to transpose the sender's matrix
        AlignedArray<std::array<block, superBlkSize>, 128> t;

			u64 numCols = mGens.size();


			for (u64 superBlkIdx = 0; superBlkIdx < numSuperBlocks; ++superBlkIdx)
			{
				// compute at what row does the user want use to stop.
				// the code will still compute the transpose for these
				// extra rows, but it is thrown away.
				u64 stopIdx
					= doneIdx
					+ std::min<u64>(u64(128) * superBlkSize, mT.bounds()[0] - doneIdx);

				for (u64 i = 0; i < numCols / 128; ++i)
				{

					// transpose 128 columns at at time. Each column will be 128 * superBlkSize = 1024 bits long.
					for (u64 tIdx = 0, colIdx = i * 128; tIdx < 128; ++tIdx, ++colIdx)
					{
						// generate the columns using AES-NI in counter mode.
						mGens[colIdx].mAes.ecbEncCounterMode(mGens[colIdx].mBlockIdx, superBlkSize, ((block*)t.data() + superBlkSize * tIdx));
						mGens[colIdx].mBlockIdx += superBlkSize;
					}

					// transpose our 128 columns of 1024 bits. We will have 1024 rows,
					// each 128 bits wide.
					transpose128x1024(t);

					// This is the index of where we will store the matrix long term.
					// doneIdx is the starting row. l is the offset into the blocks of 128 bits.
					// __restrict isn't crucial, it just tells the compiler that this pointer
					// is unique and it shouldn't worry about pointer aliasing.
					block* __restrict mTIter = mT.data() + doneIdx * mT.stride() + i;

					for (u64 rowIdx = doneIdx, j = 0; rowIdx < stopIdx; ++j)
					{
						// because we transposed 1024 rows, the indexing gets a bit weird. But this
						// is the location of the next row that we want. Keep in mind that we had long
						// **contiguous** columns.
						block* __restrict tIter = (((block*)t.data()) + j);

						// do the copy!
						for (u64 k = 0; rowIdx < stopIdx && k < 128; ++rowIdx, ++k)
						{
							*mTIter = *tIter;

							tIter += superBlkSize;
							mTIter += mT.stride();
						}
					}

				}

				doneIdx = stopIdx;
			}
		}
		MC_END();
	}


	void OosNcoOtSender::encode(
		u64 otIdx,
		const void* plaintext,
		void* dest,
		u64 destSize)
	{

#ifndef NDEBUG
		if (mInputByteCount == 0)
			throw std::runtime_error("configure must be called first" LOCATION);
#endif // !NDEBUG

		// compute the codeword. We assume the
		// the codeword is less that 10 block = 1280 bits.
		std::array<block, 10> codeword = { ZeroBlock, ZeroBlock, ZeroBlock, ZeroBlock, ZeroBlock, ZeroBlock, ZeroBlock, ZeroBlock, ZeroBlock, ZeroBlock };
		memcpy(codeword.data(), plaintext, mInputByteCount);
		mCode.encode((u8*)codeword.data(), (u8*)codeword.data());

#ifdef OOS_SHA_HASH
		//RandomOracle  sha1(destSize);
#else
#error "NOT ALLOWED"
		std::array<block, 10> aesBuff;
#endif
		// the index of the otIdx'th correction value u = t1 + t0 + c(w)
		// and the associated T value held by the sender.
		auto* corVal = mCorrectionVals.data() + otIdx * mCorrectionVals.stride();
		auto* tVal = mT.data() + otIdx * mT.stride();


		// This is the hashing phase. Here we are using
		//  codewords that we computed above.
		if (mT.stride() == 4)
		{
			// use vector instructions if we can. You can optimize this
			// for your use case too.
			block t0 = corVal[0] ^ codeword[0];
			block t1 = corVal[1] ^ codeword[1];
			block t2 = corVal[2] ^ codeword[2];
			block t3 = corVal[3] ^ codeword[3];

			t0 = t0 & mChoiceBlks[0];
			t1 = t1 & mChoiceBlks[1];
			t2 = t2 & mChoiceBlks[2];
			t3 = t3 & mChoiceBlks[3];

			codeword[0] = tVal[0] ^ t0;
			codeword[1] = tVal[1] ^ t1;
			codeword[2] = tVal[2] ^ t2;
			codeword[3] = tVal[3] ^ t3;

#ifdef OOS_SHA_HASH
			// hash it all to get rid of the correlation.
			RandomOracle  sha1(destSize);
			sha1.Update(otIdx);
			sha1.Update((u8*)codeword.data(), sizeof(block) * mT.stride());
			sha1.Final((u8*)dest);

			//std::array<u32, 5> out{ 0,0,0,0,0 };
			//sha1_compress(out.data(), (u8*)&codeword[0]);
			//memcpy(dest, out.data(), destSize);

#else
			//H(x) = AES_f(H'(x)) + H'(x),     where  H'(x) = AES_f(x_0) + x_0 + ... +  AES_f(x_n) + x_n.
			mAesFixedKey.ecbEncFourBlocks(codeword.data(), aesBuff.data());
			codeword[0] = codeword[0] ^ aesBuff[0];
			codeword[1] = codeword[1] ^ aesBuff[1];
			codeword[2] = codeword[2] ^ aesBuff[2];
			codeword[3] = codeword[3] ^ aesBuff[3];

			block val = codeword[0] ^ codeword[1];
			codeword[2] = codeword[2] ^ codeword[3];

			val = val ^ codeword[2];

			mAesFixedKey.ecbEncBlock(val, codeword[0]);
			val = val ^ codeword[0];
			memcpy(dest, &val, std::min<u64>(RandomOracle::HashSize, destSize));
#endif
		}
		else
		{
			// this is the general case. slightly slower...
			for (u64 i = 0; i < mT.stride(); ++i)
			{
				block t0 = corVal[i] ^ codeword[i];
				block t1 = t0 & mChoiceBlks[i];

				codeword[i]
					= tVal[i]
					^ t1;
			}
#ifdef OOS_SHA_HASH
			// hash it all to get rid of the correlation.
			RandomOracle  sha1(destSize);
			sha1.Update((u8*)codeword.data(), sizeof(block) * mT.stride());
			sha1.Final((u8*)dest);
#else
			//H(x) = AES_f(H'(x)) + H'(x),     where  H'(x) = AES_f(x_0) + x_0 + ... +  AES_f(x_n) + x_n.
			mAesFixedKey.ecbEncBlocks(codeword.data(), mT.stride(), aesBuff.data());

			block val = ZeroBlock;
			for (u64 i = 0; i < mT.stride(); ++i)
				val = val ^ codeword[i] ^ aesBuff[i];


			mAesFixedKey.ecbEncBlock(val, codeword[0]);
			val = val ^ codeword[0];
			memcpy(dest, &val, std::min<u64>(RandomOracle::HashSize, destSize));
#endif
		}
	}

	void OosNcoOtSender::configure(
		bool maliciousSecure,
		u64 statSecParam,
		u64 inputBitCount)
	{
		if (inputBitCount <= 76)
		{
			mCode.load(bch511_binary, sizeof(bch511_binary));
			//mCode.loadTxtFile("C:/Users/peter/repo/libOTe/libOTe/Tools/bch511.txt");
		}
		else
			throw std::runtime_error(LOCATION);



		mInputByteCount = (inputBitCount + 7) / 8;
		mStatSecParam = statSecParam;
		mMalicious = maliciousSecure;
		mGens.resize(roundUpTo(mCode.codewordBitSize(), 128));
	}

	//std::future<void> OosNcoOtSender::asyncRecvCorrection(Channel & chl, u64 recvCount)
	//{
	//    // receive the next OT correction values. This will be several rows of the form u = T0 + T1 + C(w)
	//    // there c(w) is a pseudo-random code.
	//    auto dest = &mCorrectionVals(mCorrectionIdx,0);

	//    // update the index of there we should store the next set of correction values.
	//    mCorrectionIdx += recvCount;

	//    return chl.asyncRecv(dest, recvCount * mCorrectionVals.stride());
	//}

	task<> OosNcoOtSender::recvCorrection(Socket& chl, u64 recvCount)
	{

		MC_BEGIN(task<>, this, recvCount, &chl
			, dest = (block*)nullptr
		);
#ifndef NDEBUG
		if (recvCount > mCorrectionVals.bounds()[0] - mCorrectionIdx)
			throw std::runtime_error("bad receiver, will overwrite the end of our buffer" LOCATION);

#endif // !NDEBUG

		// receive the next OT correction values. This will be several rows of the form u = T0 + T1 + C(w)
		// there c(w) is a pseudo-random code.
		dest = mCorrectionVals.data() + i32(mCorrectionIdx * mCorrectionVals.stride());

		// update the index of there we should store the next set of correction values.
		mCorrectionIdx += recvCount;

		MC_AWAIT(chl.recv(span<block>(dest, recvCount * mCorrectionVals.stride())));
		MC_END();
	}

	//u64 OosNcoOtSender::recvCorrection(Channel & chl)
	//{

	//    // receive the next OT correction values. This will be several rows of the form u = T0 + T1 + C(w)
	//    // there c(w) is a pseudo-random code.
	//    auto dest = mCorrectionVals.data() + i32(mCorrectionIdx * mCorrectionVals.stride());
	//    auto maxReceiveCount = (mCorrectionVals.rows() - mCorrectionIdx) * mCorrectionVals.stride();

	//    ReceiveAtMost<block> reciever(dest, maxReceiveCount);
	//    chl.recv(reciever);

	//    // check that the number of blocks received is ok.
	//    if (reciever.receivedSize() % mCorrectionVals.stride())
	//        throw std::runtime_error("An even number of correction blocks were not sent. " LOCATION);

	//    // compute how many corrections were received.
	//    auto numCorrections = reciever.receivedSize() / mCorrectionVals.stride();

	//    // update the index of there we should store the next set of correction values.
	//    mCorrectionIdx += numCorrections;

	//    return numCorrections;
	//}

	task<> OosNcoOtSender::check(Socket& chl, block seed)
	{
		MC_BEGIN(task<>, this, &chl, seed);
		if (mMalicious)
		{

			if (mStatSecParam % 8)
				throw std::runtime_error("Must be a multiple of 8. " LOCATION);

			// first we need to receive the extra mStatSecParam number of correction
			// values. This will just be for random inputs and are used to mask
			// their true choices that were used in the remaining correction values.
			MC_AWAIT(recvFinalization(chl));

			// now send them out challenge seed.
			MC_AWAIT(sendChallenge(chl, seed));
			computeProof();
			MC_AWAIT(recvProof(chl));
			//std::cout << "pass" << std::endl;
		}
		MC_END();
	}

	task<> OosNcoOtSender::recvFinalization(Socket& chl)
	{
		// first we need to receive the extra mStatSecParam number of correction
		// values. This will just be for random inputs and are used to mask
		// their true choices that were used in the remaining correction values.
		return recvCorrection(chl, mStatSecParam);
	}


	task<> OosNcoOtSender::sendChallenge(Socket& chl, block seed)
	{
		mChallengeSeed = seed;
		return macoro::make_task(chl.send(std::move(mChallengeSeed)));
	}

	void OosNcoOtSender::computeProof()
	{

		if (eq(mChallengeSeed, ZeroBlock))
			throw RTE_LOC;

		// This AES will work as a PRNG, using AES-NI in counter mode.
		AES aes(mChallengeSeed);
		// the index of the AES counter.
		u64 aesIdx(0);

		// the index of the row that we are doing.
		u64 k = 0;

		// qSum will hold the summation over all the rows. We need
		// mStatSecParam number of them. First initialize them, each
		// with one of the dummy values that were just send.
		qSum.resize(mStatSecParam * mT.stride());
		for (u64 i = 0; i < mStatSecParam; ++i)
		{
			// The rows are most likely several blocks wide.
			for (u64 j = 0; j < mT.stride(); ++j)
			{
				qSum[i * mT.stride() + j]
					= (mCorrectionVals[mCorrectionIdx - mStatSecParam + i][j]
						& mChoiceBlks[j])
					^ mT[mCorrectionIdx - mStatSecParam + i][j];
			}
		}

		// This will make the receiver send all of their input words
		// and the complete T0 matrix. For DEBUG only
#ifdef OOS_CHECK_DEBUG
		Buff mT0Buff, mWBuff;
		std::vector<std::array<block, 2>> baseOTs;
		std::vector<u64> mBlockIdxs(mGens.size());
		chl.recv(mT0Buff);
		chl.recv(mWBuff);

		chl.recv(baseOTs);
		chl.recv(mBlockIdxs);
		for (u64 i = 0; i < mGens.size(); ++i)
		{
			if (neq(mGens[i].getSeed(), baseOTs[i][mBaseChoiceBits[i]]))
			{
				throw std::runtime_error(LOCATION);
			}

			if (mGens[i].mBlockIdx != mBlockIdxs[i])
			{
				throw std::runtime_error(LOCATION);
			}
		}

		// the matrix generated by the zero messages
		auto mT0_DEBUG = mT0Buff.getMatrixView<block>(mCode.codewordBlkSize());

		// the input words used by the receiver
		auto mW_DEBUG = mWBuff.getMatrixView<block>(mCode.plaintextBlkSize());
#endif

		u64 codeSize = mT.stride();

		// This is an optimization trick. When iterating over the rows,
		// we want to multiply the x^(l)_i bit with the l'th row. To
		// do this we will index using zeroAndQ and & instead of of multiplication.
		// To make this work, the zeroAndQ[0] will always be 00000.....00000,
		// and  zeroAndQ[1] will hold the q_i row. This is so much faster than
		// if(x^(l)_i) qSum[l] = qSum[l] ^ q_i.
		std::array<std::array<block, 8>, 2> zeroAndQ;

		// set it all to zero initially.
		memset(zeroAndQ.data(), 0, zeroAndQ.size() * 2 * sizeof(block));

		// make sure that having this allocated on the stack is ok.
		if (codeSize < zeroAndQ.size()) throw std::runtime_error("Make this bigger. " LOCATION);


		// this will hold out random x^(l)_i values that we compute from the seed.
		std::vector<block> challengeBuff(mStatSecParam);

		// since we don't want to do bit shifting, this larger array
		// will be used to hold each bit of challengeBuff as a whole
		// byte. See below for how we do this efficiently.
		std::vector<block> expandedBuff(mStatSecParam * 8);
		u8* byteView = (u8*)expandedBuff.data();

		// This will be used to compute expandedBuff
		block mask = block(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1);

		// get raw pointer to this data. faster than normal indexing.
		auto corIter = mCorrectionVals.data();
		auto tIter = mT.data();

		// compute the index that we should stop at. We process 128 rows at a time.
		u64 blkStopIdx = (mCorrectionIdx - mStatSecParam + 127) / 128;
		for (u64 blkIdx = 0; blkIdx < blkStopIdx; ++blkIdx)
		{
			// generate mStatSecParam * 128 bits using AES-NI in counter mode.
			aes.ecbEncCounterMode(aesIdx, mStatSecParam, challengeBuff.data());
			aesIdx += mStatSecParam;

			// now expand each of these bits into its own byte. This is done with the
			// right shift instruction _mm_srai_epi16. and then we mask to get only
			// the bottom bit. Doing the 8 times gets us each bit in its own byte.
			for (u64 i = 0; i < mStatSecParam; ++i)
			{
				expandedBuff[i * 8 + 0] = mask & challengeBuff[i].srai_epi16(0);
				expandedBuff[i * 8 + 1] = mask & challengeBuff[i].srai_epi16(1);
				expandedBuff[i * 8 + 2] = mask & challengeBuff[i].srai_epi16(2);
				expandedBuff[i * 8 + 3] = mask & challengeBuff[i].srai_epi16(3);
				expandedBuff[i * 8 + 4] = mask & challengeBuff[i].srai_epi16(4);
				expandedBuff[i * 8 + 5] = mask & challengeBuff[i].srai_epi16(5);
				expandedBuff[i * 8 + 6] = mask & challengeBuff[i].srai_epi16(6);
				expandedBuff[i * 8 + 7] = mask & challengeBuff[i].srai_epi16(7);
			}

			// compute when we should stop of this set.
			u64 stopIdx = std::min<u64>(mCorrectionIdx - mStatSecParam - k, u64(128));
			k += 128;

			// get an integrator to the challenge bit
			u8* xIter = byteView;

			if (mT.stride() == 4)
			{
				//  vvvvvvvvvvvv   OPTIMIZED for codeword size 4   vvvvvvvvvvvv

				for (u64 i = 0; i < stopIdx; ++i, corIter += 4, tIter += 4)
				{

					// compute q_i = (u_i & choice) ^ T_i
					auto q0 = (corIter[0] & mChoiceBlks[0]);
					auto q1 = (corIter[1] & mChoiceBlks[1]);
					auto q2 = (corIter[2] & mChoiceBlks[2]);
					auto q3 = (corIter[3] & mChoiceBlks[3]);

					// place it in the one location of zeroAndQ. This will
					// be used for efficient multiplication of q_i by the bit x^(l)_i
					zeroAndQ[1][0] = q0 ^ tIter[0];
					zeroAndQ[1][1] = q1 ^ tIter[1];
					zeroAndQ[1][2] = q2 ^ tIter[2];
					zeroAndQ[1][3] = q3 ^ tIter[3];

					// This is meant to debug the check. If turned on,
					// the receiver will have sent it's T0 and W matrix.
					// This will let us identify the row that things go wrong...
#ifdef OOS_CHECK_DEBUG
					u64 kk = k - 128 + i;
					std::vector<block> cw(mCode.codewordBlkSize());
					mCode.encode(mW_DEBUG[kk], cw);

					for (u64 j = 0; j < 4; ++j)
					{
						//block t = tIter[j];
						auto cor = corIter[j];
						//block tc = cor & mChoiceBlks[j];

						block tq = mT0_DEBUG[kk][j] ^ zeroAndQ[1][j];
						block cb = cw[j] & mChoiceBlks[j];

						if (neq(tq, cb))
						{
							std::cout << "row " << (kk) << " " << j << std::endl;
							std::cout <<
								"tq " << tq << " = " << mT0_DEBUG[kk][j] << " ^ " << zeroAndQ[1][j] << "\n" <<
								"cb " << cb << " = (" << cw[j] << "} & " << mChoiceBlks[j] << "\n" <<
								"w = " << mW_DEBUG[kk][0] << " ->  " << cw[0] << std::endl <<
								"diff " << (tq ^ cb) << std::endl;

							throw std::runtime_error(LOCATION);
						}
						//std::cout << "tq " << tq << " cb " << cb << " = c(" << mW_DEBUG[kk][0] << "} & " << mChoiceBlks[j] << " diff " << (tq ^ cb) << std::endl;
					}
#endif

					// get a raw pointer into the first summation
					auto qSumIter = qSum.data();

					// iterate over the mStatSecParam of challenges. Process
					// two of the value per loop.
					for (u64 j = 0; j < mStatSecParam / 2; ++j, qSumIter += 8)
					{
						u8 x0 = *xIter++;
						u8 x1 = *xIter++;

						// This is where the bit multiplication of
						// x^(l)_i * q_i happens. Its done with a single
						// array index instruction. If x is zero, then mask
						// will hold the all zero string. Otherwise it holds
						// the row q_i.
						block* mask0 = zeroAndQ[x0].data();
						block* mask1 = zeroAndQ[x1].data();

						// Xor it in.
						qSumIter[0] = qSumIter[0] ^ mask0[0];
						qSumIter[1] = qSumIter[1] ^ mask0[1];
						qSumIter[2] = qSumIter[2] ^ mask0[2];
						qSumIter[3] = qSumIter[3] ^ mask0[3];
						qSumIter[4] = qSumIter[4] ^ mask1[0];
						qSumIter[5] = qSumIter[5] ^ mask1[1];
						qSumIter[6] = qSumIter[6] ^ mask1[2];
						qSumIter[7] = qSumIter[7] ^ mask1[3];
					}
				}

				//  ^^^^^^^^^^^^^   OPTIMIZED for codeword size 4   ^^^^^^^^^^^^^
			}
			else
			{
				//  vvvvvvvvvvvv       general codeword size        vvvvvvvvvvvv

				for (u64 i = 0; i < stopIdx; ++i, corIter += codeSize, tIter += codeSize)
				{
					for (u64 m = 0; m < codeSize; ++m)
					{
						// compute q_i = (u_i & choice) ^ T_i
						// place it in the one location of zeroAndQ. This will
						// be used for efficient multiplication of q_i by the bit x^(l)_i
						zeroAndQ[1][m] = (corIter[m] & mChoiceBlks[m]) ^ tIter[m];
					}

					// This is meant to debug the check. If turned on,
					// the receiver will have sent it's T0 and W matrix.
					// This will let us identify the row that things go wrong...
#ifdef OOS_CHECK_DEBUG
					u64 kk = k - 128;
					std::vector<block> cw(mCode.codewordBlkSize());
					mCode.encode(mW_DEBUG[kk], cw);

					for (u64 j = 0; j < codeSize; ++j)
					{
						block tq = mT0_DEBUG[kk][j] ^ zeroAndQ[1][j];
						block cb = cw[j] & mChoiceBlks[j];

						if (neq(tq, cb))
						{
							throw std::runtime_error(LOCATION);
						}
					}
#endif
					// get a raw pointer into the first summation
					auto qSumIter = qSum.data();

					// iterate over the mStatSecParam of challenges. Process
					// two of the value per loop.
					for (u64 j = 0; j < mStatSecParam; ++j, qSumIter += codeSize)
					{

						// This is where the bit multiplication of
						// x^(l)_i * q_i happens. Its done with a single
						// array index instruction. If x is zero, then mask
						// will hold the all zero string. Otherwise it holds
						// the row q_i.
						block* mask0 = zeroAndQ[*xIter++].data();

						for (u64 m = 0; m < codeSize; ++m)
						{
							// Xor it in.
							qSumIter[m] = qSumIter[m] ^ mask0[m];
						}
					}
				}

				//  ^^^^^^^^^^^^^      general codeword size        ^^^^^^^^^^^^^
			}
		}
	}

	task<> OosNcoOtSender::recvProof(Socket& chl)
	{
		MC_BEGIN(task<>, this, &chl,
			tSum = std::vector<block>{},
			wSum = std::vector<block>{}
		);

		tSum.resize(mStatSecParam * mT.stride());
		wSum.resize(mStatSecParam * mCode.plaintextBlkSize());

		// now wait for the receiver's challenge answer.
		MC_AWAIT(chl.recv(tSum));
		MC_AWAIT(chl.recv(wSum));

		{
			// a buffer to store codewords
			std::vector<block> cw(mCode.codewordBlkSize());

			// check each of the mStatSecParam number of challenges
			for (u64 l = 0; l < mStatSecParam; ++l)
			{

				span<block> word(
					wSum.data() + l * mCode.plaintextBlkSize(),
					mCode.plaintextBlkSize());

				// encode their l'th linear combination of choice words.
				mCode.encode(word, cw);

				// check that the linear relation holds.
				for (u64 j = 0; j < cw.size(); ++j)
				{
					block tq = tSum[l * cw.size() + j] ^ qSum[l * cw.size() + j];
					block cb = cw[j] & mChoiceBlks[j];

					if (neq(tq, cb))
					{
						//std::cout << "bad OOS16 OT check. " << l << "m " << j << std::endl;
						//return;
						throw std::runtime_error("bad OOS16 OT check. " LOCATION);
					}
				}

			}
		}

		MC_END();
	}

}

#endif
#include "KosOtExtSender.h"
#ifdef ENABLE_KOS

#include "libOTe/Tools/Tools.h"
#include "libOTe/TwoChooseOne/TcoOtDefines.h"
#include "cryptoTools/Crypto/Commit.h"
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Common/Log.h"


namespace osuCrypto
{
	KosOtExtSender::KosOtExtSender(SetUniformOts, span<block> baseRecvOts, const BitVector& choices)
	{
		setBaseOts(baseRecvOts, choices);
	}

	void KosOtExtSender::setUniformBaseOts(span<block> baseRecvOts, const BitVector& choices)
	{
		setBaseOts(baseRecvOts, choices);
	}

	KosOtExtSender KosOtExtSender::splitBase()
	{
		if (!hasBaseOts())
			throw std::runtime_error("base OTs have not been set. " LOCATION);

		std::array<block, gOtExtBaseOtCount> baseRecvOts;
		for (u64 i = 0; i < mGens.mAESs.size(); ++i)
			baseRecvOts[i] = mGens.mAESs[i].ecbEncBlock(block(mPrngIdx));

		++mPrngIdx;
		return KosOtExtSender(SetUniformOts{}, baseRecvOts, mBaseChoiceBits);
	}

	std::unique_ptr<OtExtSender> KosOtExtSender::split()
	{
		return std::make_unique<KosOtExtSender>(splitBase());
	}

	void KosOtExtSender::setBaseOts(span<block> baseRecvOts, const BitVector& choices)
	{
		if (baseRecvOts.size() != gOtExtBaseOtCount || choices.size() != gOtExtBaseOtCount)
			throw std::runtime_error("not supported/implemented");

		mBaseChoiceBits = choices;
		mGens.setKeys(baseRecvOts);

		mPrngIdx = 0;
	}

	task<> KosOtExtSender::send(
		span<std::array<block, 2>> messages,
		PRNG& prng,
		Socket& chl)
	{
		MACORO_TRY{


		if (mIsMalicious && mHashType == HashType::NoHash)
			throw std::runtime_error("malicious no hash is not supported, use DotKos. " LOCATION);


		if (hasBaseOts() == false)
			co_await genBaseOts(prng, chl);

		// The other party either need to commit
		// to a random value or we will generate 
		// it via Fiat Shamir.
		auto fs = RandomOracle(sizeof(block));

		// used to hash messages
		RandomOracle sha(sizeof(block));
		
		u64 numExtra = 0;
		auto hashType = mHashType;
		auto mal = mIsMalicious;
		if (mIsMalicious)
			numExtra = 128;

		setTimePoint("Kos.send.start");

		auto delta = *mBaseChoiceBits.blocks();
		auto choiceMask = AlignedUnVector<block>{ 128 };
		for (u64 i = 0; i < 128; ++i)
		{
			if (mBaseChoiceBits[i]) choiceMask[i] = AllOneBlock;
			else choiceMask[i] = ZeroBlock;
		}

		// get an array of blocks that we will fill.
		u64 numBlocks = divCeil(messages.size() + numExtra, 128);
		auto tSize = mIsMalicious ? numBlocks * 128ull : 128ull;
		auto t = AlignedUnVector<block>{ tSize };
		auto u = AlignedUnVector<block>{};
		auto transBuff = AlignedUnVector<block>{ 128ull * mIsMalicious };

		block* uIter = 0;
		block* uEnd = 0;

		auto mIter = messages.data();
		auto tIter = t.data();
		auto remaining = numBlocks;

		for (u64 i = 0; i < numBlocks; ++i)
		{

			if (uIter == uEnd)
			{
				auto step = std::min<u64>(remaining, (u64)commStepSize);
				remaining -= step;
				u.resize(step * 128);
				uIter = u.data();
				uEnd = uIter + u.size();

				co_await(chl.recv(u));

				if (mFiatShamir)
					fs.Update(u.data(), u.size());
			}

			mGens.ecbEncCounterMode(mPrngIdx, tIter);
			++mPrngIdx;

			auto cIter = choiceMask.data();
			// transpose 128 columns at at time.
			for (u64 colIdx = 0; colIdx < 16; ++colIdx)
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

			assert(cIter == choiceMask.data() + choiceMask.size());
			tIter -= 128;

			// transpose our 128 columns of 1024 bits. We will have 1024 rows,
			// each 128 bits wide.
			block* trans = nullptr;
			if (mal)
			{
				memcpy(transBuff.data(), tIter, 128 * sizeof(block));
				transpose128(transBuff.data());
				trans = transBuff.data();
				tIter += 128;
			}
			else
			{
				transpose128(tIter);
				trans = tIter;
			}

			auto size = std::min<u64>(128, messages.data() + messages.size() - mIter);

			if (size == 128)
			{
				for (u64 j = 0; j < 128; j += 8)
				{
					mIter[0][0] = trans[0];
					mIter[1][0] = trans[1];
					mIter[2][0] = trans[2];
					mIter[3][0] = trans[3];
					mIter[4][0] = trans[4];
					mIter[5][0] = trans[5];
					mIter[6][0] = trans[6];
					mIter[7][0] = trans[7];
					mIter[0][1] = trans[0] ^ delta;
					mIter[1][1] = trans[1] ^ delta;
					mIter[2][1] = trans[2] ^ delta;
					mIter[3][1] = trans[3] ^ delta;
					mIter[4][1] = trans[4] ^ delta;
					mIter[5][1] = trans[5] ^ delta;
					mIter[6][1] = trans[6] ^ delta;
					mIter[7][1] = trans[7] ^ delta;

					trans += 8;
					mIter += 8;
				}
			}
			else
			{
				auto mEnd = mIter + size;
				while (mIter != mEnd)
				{
					(*mIter)[0] = *trans;
					(*mIter)[1] = *trans ^ delta;

					trans += 1;
					mIter += 1;
				}
			}
			mIter -= size;

			if (hashType == HashType::AesHash)
			{
				auto hh = span<block>(mIter->data(), size * 2);
				mIter += size;
				if (mIsMalicious)
				{
					mAesFixedKey.TmmoHashBlocks(hh, hh, [mTweak = i * 256]() mutable {
						return block(mTweak++ >> 1);
						});
				}
				else
				{
					mAesFixedKey.hashBlocks(hh, hh);
				}
			}
			else if (hashType == HashType::RandomOracle)
			{
				for (u64 j = 0; j < size; ++j)
				{
					auto idx = i * 128 + j;

					// hash the message without delta
					sha.Reset();
					sha.Update(idx);
					sha.Update((*mIter)[0]);
					sha.Final((*mIter)[0]);

					// hash the message with delta
					sha.Reset();
					sha.Update(idx);
					sha.Update((*mIter)[1]);
					sha.Final((*mIter)[1]);

					++mIter;
				}
			}

			if (tIter > t.data() + t.size())
			{
				std::cout << "logic error " << LOCATION << std::endl;
				std::terminate();
			}
		}

		setTimePoint("Kos.send.transposeDone");


		block seed = ZeroBlock;
		if (mIsMalicious)
		{

			if (mFiatShamir)
			{
				fs.Final(seed);
			}
			else
			{
				seed = prng.get<block>();
				co_await chl.send(std::move(seed));
			}

			co_await check(seed, t, chl);
		}

		setTimePoint("Kos.send.done");

		} MACORO_CATCH(eptr) {
			if (!chl.closed()) co_await chl.close();
			std::rethrow_exception(eptr);
		}
	}

	task<> KosOtExtSender::check(
		block seed,
		span<block> t,
		coproto::Socket& sock)
	{

		block qi, qi2;
		std::vector<block> q1(t.end()-128, t.end());
		std::vector<block> q2(128);

		setTimePoint("Kos.send.checkStart");
	
		if (t.size() % 128)
			throw RTE_LOC;
		PRNG commonPrng(seed, 128);

		u64 n = (t.size() - 128) / 128;
		auto cIter = commonPrng.mBuffer.data();
		auto cEnd = commonPrng.mBuffer.data() + commonPrng.mBuffer.size();
		auto tIter = t.data();
		for (u64 j = 0; j < n; ++j)
		{
			for (u64 i = 0; i < 128; ++i)
			{
				tIter[i].gf128Mul(*cIter, qi, qi2);
				q1[i] = q1[i] ^ qi;
				q2[i] = q2[i] ^ qi2;
			}

			++cIter;
			tIter += 128;

			if (cIter == cEnd)
			{
				commonPrng.refillBuffer();
				cIter = commonPrng.mBuffer.data();
			}
		}

		for (u64 r = 0; r < 128; ++r)
			q1[r] = q1[r].cc_gf128Reduce(q2[r]);

		setTimePoint("Kos.send.checkSummed");

		std::vector<block>u(129);
		co_await sock.recv(u);
		setTimePoint("Kos.send.proofReceived");

		for (u64 i = 0; i < 128; ++i)
		{
			block& received_x = u.back();
			block& received_t = u[i];
			auto tt = (received_x & zeroAndAllOne[mBaseChoiceBits[i]]) ^ q1[i];

			if (tt != received_t)
			{
				//std::cout << "OT Ext Failed Correlation check failed" << std::endl;
				throw std::runtime_error("KOS, bad mal check " LOCATION);
			}
		}
		setTimePoint("Kos.send.proofDone");

		static_assert(gOtExtBaseOtCount == 128, "expecting 128");
	}


}

#endif

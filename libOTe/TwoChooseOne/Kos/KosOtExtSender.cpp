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
		setUniformBaseOts(baseRecvOts, choices);
	}

	void KosOtExtSender::setUniformBaseOts(span<block> baseRecvOts, const BitVector& choices)
	{
		if (baseRecvOts.size() != gOtExtBaseOtCount || choices.size() != gOtExtBaseOtCount)
			throw std::runtime_error("not supported/implemented");

		mBaseChoiceBits = choices;
		mGens.setKeys(baseRecvOts);
		
		mPrngIdx = 0;
		mUniformBase = true;
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
		setUniformBaseOts(baseRecvOts, choices);
		mUniformBase = false;
	}

	task<> KosOtExtSender::send(
		span<std::array<block, 2>> messages,
		PRNG& prng,
		Socket& chl)
	try {
		if (hasBaseOts() == false)
			co_await genBaseOts(prng, chl);

		// The other party either need to commit
		// to a random value or we will generate 
		// it via Fiat Shamir.
		auto fs = RandomOracle(sizeof(block));
		auto theirSeedComm = Commit{};
		if (mIsMalicious)
		{

			if (mUniformBase == false)
			{
				auto diff = BitVector{};
				diff.resize(mBaseChoiceBits.size());
				co_await chl.recv(diff.getSpan<u8>());
				mBaseChoiceBits ^= diff;
				mUniformBase = true;
			}

			if (mFiatShamir == false)
				co_await(chl.recv(theirSeedComm));
		}

		setTimePoint("Kos.send.start");


		// extra OTs used in the KOS check.
		// We do 4 sets of malicious checks instead of 1
		// to mitigate the uncertainty surrounding the KOS security.
		u64 numExtra = gKosChallengeRepititions * mIsMalicious;
		auto extraMessages = AlignedUnVector<std::array<block, 2>>{ numExtra * 128 };

		auto delta = *mBaseChoiceBits.blocks();
		auto choiceMask = AlignedUnVector<block>{ 128 };
		for (u64 i = 0; i < 128; ++i)
		{
			if (mBaseChoiceBits[i]) choiceMask[i] = AllOneBlock;
			else choiceMask[i] = ZeroBlock;
		}

		// get an array of blocks that we will fill.
		auto t = AlignedUnVector<block>{ 128 };
		auto u = AlignedUnVector<block>{};
		block* uIter = 0;
		block* uEnd = 0;
		u64 remaining = divCeil(messages.size(), 128) + numExtra;


		for (auto extra : { false, true })
		{
			// The next OT message to be computed
			auto msgs = extra ?
				span<std::array<block, 2>>(extraMessages) :
				span<std::array<block, 2>>(messages);

			auto mIter = msgs.data();

			u64 numBlocks = divCeil(msgs.size(), 128);

			for (u64 i = 0; i < numBlocks; ++i)
			{
				auto tIter = t.data();
				auto cIter = choiceMask.data();

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
				assert(tIter == t.data() + t.size());

				// transpose our 128 columns of 1024 bits. We will have 1024 rows,
				// each 128 bits wide.
				assert(t.size() == 128);
				transpose128(t.data());

				auto size = std::min<u64>(128, messages.data() + messages.size() - mIter);
				tIter = t.data();

				if (size == 128)
				{
					for (u64 j = 0; j < 128; j += 8)
					{
						mIter[0][0] = tIter[0];
						mIter[1][0] = tIter[1];
						mIter[2][0] = tIter[2];
						mIter[3][0] = tIter[3];
						mIter[4][0] = tIter[4];
						mIter[5][0] = tIter[5];
						mIter[6][0] = tIter[6];
						mIter[7][0] = tIter[7];
						mIter[0][1] = tIter[0] ^ delta;
						mIter[1][1] = tIter[1] ^ delta;
						mIter[2][1] = tIter[2] ^ delta;
						mIter[3][1] = tIter[3] ^ delta;
						mIter[4][1] = tIter[4] ^ delta;
						mIter[5][1] = tIter[5] ^ delta;
						mIter[6][1] = tIter[6] ^ delta;
						mIter[7][1] = tIter[7] ^ delta;

						tIter += 8;
						mIter += 8;
					}
				}
				else
				{
					auto mEnd = mIter + size;
					while (mIter != mEnd)
					{
						(*mIter)[0] = *tIter;
						(*mIter)[1] = *tIter ^ delta;

						tIter += 1;
						mIter += 1;
					}
				}

				//auto m = mIter - size;
				//for (u64 j = 0; j < size; ++j)
				//	std::cout << "s[" << i + j << "] " << m[j][0] << " " << m[j][1] << std::endl;

				assert(tIter == t.data() + size);
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
				block theirSeed;
				co_await chl.recv(theirSeed);
				setTimePoint("Kos.send.cncSeed");
				if (Commit(theirSeed) != theirSeedComm)
					throw std::runtime_error("KOS, bad commit " LOCATION);
				seed = seed ^ theirSeed;
			}
		}

		auto q = hash(messages, seed, extraMessages);

		if (mIsMalicious)
		{
			u.resize(2 * q.size());
			co_await chl.recv(u);
			setTimePoint("Kos.send.proofReceived");

			for (u64 i = 0; i < q.size(); ++i)
			{
				block& received_x = u[i * 2 + 0];
				block& received_t = u[i * 2 + 1];
				auto tt = received_x.gf128Mul(delta) ^ q[i];

				if (tt != received_t)
				{
					//std::cout << "OT Ext Failed Correlation check failed" << std::endl;
					throw std::runtime_error("KOS, bad mal check " LOCATION);
				}
			}
		}

		setTimePoint("Kos.send.done");
	}
	catch (...)
	{
		chl.close();
		throw;
	}


	std::vector<block> KosOtExtSender::hash(
		span<std::array<block, 2>> message,
		block seed,
		span<std::array<block, 2>> extraMessages)
	{
		if (mIsMalicious && mHashType == HashType::NoHash)
			throw std::runtime_error("malicious no hash is not supported, use DotKos. " LOCATION);

		if (mHashType == HashType::NoHash)
			return {};


		assert(extraMessages.size() % 128 == 0);
		auto numExtra = extraMessages.size() / 128;

		PRNG commonPrng(seed, 128);

		block  qi, qi2;
		std::vector<block> q2(numExtra);
		std::vector<block> q1(numExtra);

		RandomOracle sha(sizeof(block));

		setTimePoint("Kos.send.checkStart");

		for (auto extra : { false, true })
		{

			auto msgs = extra ?
				extraMessages :
				message;

			u64 n = msgs.size();

			for (u64 i = 0; i < n; )
			{
				auto size = std::min<u64>(msgs.size() - i, 128);
				for (u64 r = 0; r < numExtra; ++r)
				{
					auto& challenges = commonPrng.mBuffer;
					for (u64 j = 0; j < size; ++j)
					{
						mul128(msgs[i + j][0], challenges[j], qi, qi2);
						q1[r] = q1[r] ^ qi;
						q2[r] = q2[r] ^ qi2;
					}
					commonPrng.refillBuffer();
				}

				if (mHashType == HashType::RandomOracle)
				{
					for (u64 j = 0; j < size; ++j)
					{
						auto idx = i + j;

						// hash the message without delta
						sha.Reset();
						sha.Update(idx);
						sha.Update(msgs[idx][0]);
						sha.Final(msgs[idx][0]);

						// hash the message with delta
						sha.Reset();
						sha.Update(idx);
						sha.Update(msgs[idx][1]);
						sha.Final(msgs[idx][1]);
					}
				}
				else
				{
					assert(mHashType == HashType::AesHash);

					auto hh = span<block>(msgs[i].data(), size * 2);
					if (mIsMalicious)
					{
						mAesFixedKey.TmmoHashBlocks(hh, hh, [mTweak = i * 2]() mutable {
							return block(mTweak++ >> 1);
							});
					}
					else
					{
						mAesFixedKey.hashBlocks(hh, hh);
					}
				}

				i += size;
			}
		}

		setTimePoint("Kos.send.checkSummed");

		for (u64 i = 0; i < q1.size(); ++i)
			q1[i] = q1[i].gf128Reduce(q2[i]);
		return q1;

		static_assert(gOtExtBaseOtCount == 128, "expecting 128");
	}


}

#endif

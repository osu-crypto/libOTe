#include "KosOtExtReceiver.h"
#ifdef ENABLE_KOS

#include "libOTe/Tools/Tools.h"
#include "libOTe/config.h"

#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/Commit.h>
#include <cryptoTools/Network/Channel.h>

#include "libOTe/TwoChooseOne/TcoOtDefines.h"

using namespace std;
//#define KOS_DEBUG

namespace osuCrypto
{
	KosOtExtReceiver::KosOtExtReceiver(SetUniformOts, span<std::array<block, 2>> baseOTs)
	{
		setUniformBaseOts(baseOTs);
	}

	void KosOtExtReceiver::setUniformBaseOts(span<std::array<block, 2>> baseOTs)
	{
		if (baseOTs.size() != gOtExtBaseOtCount)
			throw std::runtime_error(LOCATION);

		std::array<std::vector<block>, 2> keys;
		keys[0].resize(gOtExtBaseOtCount);
		keys[1].resize(gOtExtBaseOtCount);
		for (u64 i = 0; i < gOtExtBaseOtCount; i++)
		{
			keys[0][i] = baseOTs[i][0];
			keys[1][i] = baseOTs[i][1];
		}
		mGens.resize(2);
		mGens[0].setKeys(keys[0]);
		mGens[1].setKeys(keys[1]);

		mHasBase = true;
		mUniformBase = true;
	}

	void KosOtExtReceiver::setBaseOts(span<std::array<block, 2>> baseOTs)
	{
		setUniformBaseOts(baseOTs);
		mPrngIdx = 0;
		mUniformBase = false;
	}

	KosOtExtReceiver KosOtExtReceiver::splitBase()
	{
		std::array<std::array<block, 2>, gOtExtBaseOtCount>baseRecvOts;

		if (!hasBaseOts())
			throw std::runtime_error("base OTs have not been set. " LOCATION);

		for (u64 i = 0; i < mGens.size(); ++i)
		{
			baseRecvOts[i][0] = mGens[0].mAESs[i].ecbEncBlock(block(mPrngIdx));
			baseRecvOts[i][1] = mGens[1].mAESs[i].ecbEncBlock(block(mPrngIdx));
		}
		++mPrngIdx;

		return KosOtExtReceiver(SetUniformOts{}, baseRecvOts);
	}

	std::unique_ptr<OtExtReceiver> KosOtExtReceiver::split()
	{
		return std::make_unique<KosOtExtReceiver>(splitBase());
	}

	task<> KosOtExtReceiver::receive(
		const BitVector& choices,
		span<block> messages,
		PRNG& prng,
		Socket& chl)
	{
		MACORO_TRY{

		// we are going to process OTs in blocks of 128 * superBlkSize messages.
		if (hasBaseOts() == false)
			co_await genBaseOts(prng, chl);

		setTimePoint("Kos.recv.start");

		// used for the malicious check.
		auto fs = RandomOracle(sizeof(block));
		auto myComm = Commit{};
		auto seed = block{};

		if (mIsMalicious)
		{
			// in the malicious case its best to use that the
			// sender used random choice bits to ensure that
			// they did not force both OT strings to be the same.
			if (mUniformBase == false)
			{
				block diff = prng.get();
				co_await chl.send(std::move(diff));

				auto iter = BitIterator((u8*)&diff, 0);
				for (u64 i = 0; i < gOtExtBaseOtCount; i++)
				{
					if (*iter)
						std::swap(mGens[0].mAESs[i], mGens[1].mAESs[i]);
					++iter;
				}
				mUniformBase = true;
			}

			// set up the hasher used for the malcious check.
			if (mFiatShamir == false)
			{
				seed = prng.get<block>();
				myComm = Commit(seed);
				co_await chl.send(std::move(myComm));
			}
		}

		// extra OTs used in the KOS check.
		// We do 4 sets of malicious checks instead of 1
		// to mitigate the uncertainty surrounding the KOS security.
		u64 numExtra = gKosChallengeRepititions * mIsMalicious;
		auto extraChoice = AlignedUnVector<block>{ numExtra };
		auto extraMessages = AlignedUnVector<block>{ 128 * numExtra };
		auto t0 = AlignedUnVector<block>{ 128 };
		for (auto& c : extraChoice)
			c = prng.get();

		// get an array of blocks that we will fill.
		auto uBuff = AlignedUnVector<block>{};
		block* uIter = 0;
		block* uEnd = 0;
		u64 remaining = choices.sizeBlocks() + extraChoice.size();

		// we handle the main OTs and the extra in two seperate
		// iterations.
		for (auto extra : { false, true })
		{
			span<block> choice = extra ?
				span<block>(extraChoice) :
				span<block>(choices.blocks(), choices.sizeBlocks());
			auto cIter = choice.data();

			auto msgs = extra ?
				span<block>(extraMessages) :
				span<block>(messages);
			auto mIter = msgs.data();

			// each iteration produces 128 OTs
			for (auto i = 0ull; i < choice.size(); ++i)
			{
				if (uIter == uEnd)
				{
					u64 step = std::min<u64>(remaining, (u64)commStepSize);
					remaining -= step;
					uBuff.resize(step * 128);
					uIter = uBuff.data();
					uEnd = uIter + uBuff.size();
				}

				// expand the base OTs strings
				auto tIter = t0.data();
				mGens[0].ecbEncCounterMode(mPrngIdx, tIter);
				mGens[1].ecbEncCounterMode(mPrngIdx, uIter);
				++mPrngIdx;

				for (u64 colIdx = 0; colIdx < 16; ++colIdx)
				{
					uIter[0] = uIter[0] ^ *cIter;
					uIter[1] = uIter[1] ^ *cIter;
					uIter[2] = uIter[2] ^ *cIter;
					uIter[3] = uIter[3] ^ *cIter;
					uIter[4] = uIter[4] ^ *cIter;
					uIter[5] = uIter[5] ^ *cIter;
					uIter[6] = uIter[6] ^ *cIter;
					uIter[7] = uIter[7] ^ *cIter;

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
				++cIter;

				// send the buffer if we are our of room
				if (uIter == uEnd)
				{
					// hash the message to get the malicious check.
					if (mFiatShamir)
						fs.Update(uBuff.data(), uBuff.size());

					// send over u buffer
					co_await chl.send(std::move(uBuff));
				}

				// transpose our 128 columns of 1024 bits. We will have 1024 rows,
				// each 128 bits wide.
				transpose128(t0.data());

				auto size = std::min<u64>(128, msgs.data() + msgs.size() - mIter);
				memcpy(mIter, t0.data(), size * sizeof(block));
				mIter += size;

				//auto m = mIter - size;
				//for (u64 j = 0; j < size; ++j)
				//	std::cout << "r[" << i + j << "] " << m[j]  << " " << *oc::BitIterator(choice.data(), i+j) << std::endl;
			}
		}

		setTimePoint("Kos.recv.transposeDone");

		if (mIsMalicious)
		{
			if (mFiatShamir)
			{
				fs.Final(seed);
			}
			else
			{
				block theirSeed;
				co_await chl.recv(theirSeed);
				co_await chl.send(std::move(seed));
				seed = seed ^ theirSeed;
				setTimePoint("Kos.recv.cncSeed");
			}
		}

		// hash the messages and do the malicious check
		uBuff = hash(messages, choices, seed, extraChoice, extraMessages);
		setTimePoint("Kos.recv.hash");

		if(mIsMalicious)
			co_await(chl.send(std::move(uBuff)));

			} MACORO_CATCH(eptr) {
				if (!chl.closed()) co_await chl.close();
				std::rethrow_exception(eptr);
			}
	}

	AlignedUnVector<block> KosOtExtReceiver::hash(
		span<block> message,
		BitVector const& choices,
		block seed,
		span<block> extraChoices,
		span<block> extraMessage)
	{
		if (mIsMalicious && mHashType == HashType::NoHash)
			throw std::runtime_error("malicious no hash is not supported, use DotKos. " LOCATION);

		if (mHashType == HashType::NoHash)
			return {};

		// this buffer will be sent to the other party to prove we used the
		// same value of r in all of the column vectors...
		AlignedUnVector<block> correlationData(2 * extraChoices.size());
		auto x = correlationData.subspan(0, extraChoices.size());
		auto t = correlationData.subspan(extraChoices.size());;
		AlignedUnVector<block> t2(extraChoices.size());

		for (u64 i = 0; i < extraChoices.size(); ++i)
		{
			x[i] = ZeroBlock;
			t[i] = ZeroBlock;
			t2[i] = ZeroBlock;
		}
		block ti, ti2;

		RandomOracle sha(sizeof(block));
		std::array<block, 2> zeroOneBlk{ ZeroBlock, AllOneBlock };
		block mask = block(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1);
		PRNG commonPrng(seed, 128);

		for (auto extra : { false, true })
		{
			auto msgs = extra ?
				extraMessage :
				message;

			auto choice = extra ?
				extraChoices :
				span<block>(choices.blocks(), choices.sizeBlocks());

			u64 n = msgs.size();
			for (u64 i = 0; i < n;)
			{
				u64 size = std::min<u64>(msgs.size() - i, 128);

				if (mIsMalicious)
				{
					auto ci = choice[i / 128];
					for (u64 r = 0; r < extraChoices.size(); ++r)
					{
						std::array<block, 8> expendedChoiceBlk;
						expendedChoiceBlk[0] = mask & ci.srai_epi16(0);
						expendedChoiceBlk[1] = mask & ci.srai_epi16(1);
						expendedChoiceBlk[2] = mask & ci.srai_epi16(2);
						expendedChoiceBlk[3] = mask & ci.srai_epi16(3);
						expendedChoiceBlk[4] = mask & ci.srai_epi16(4);
						expendedChoiceBlk[5] = mask & ci.srai_epi16(5);
						expendedChoiceBlk[6] = mask & ci.srai_epi16(6);
						expendedChoiceBlk[7] = mask & ci.srai_epi16(7);

						auto expendedChoice = (u8*)expendedChoiceBlk.data();
						auto& challenges = commonPrng.mBuffer;
						assert(size <= challenges.size());
						for (u64 j = 0; j < size; ++j)
						{
							// we expand the noise bits in an interlaced manner. this
							// indexes the choice bits in logical order.
							auto idx = (j % 8) * 16 + j / 8;

							x[r] = x[r] ^ (challenges[j] & zeroOneBlk[expendedChoice[idx]]);

							// multiply over polynomial ring to avoid reduction
							mul128(msgs[i + j], challenges[j], ti, ti2);
							t[r] = t[r] ^ ti;
							t2[r] = t2[r] ^ ti2;
						}

						commonPrng.refillBuffer();
					}
				}

				if (mHashType == HashType::RandomOracle)
				{
					for (u64 j = 0; j < size; ++j)
					{
						auto idx = i + j;
						// hash it
						sha.Reset();
						sha.Update(idx);
						sha.Update(msgs[idx]);
						sha.Final(msgs[idx]);
					}
				}
				else 
				{
					assert(mHashType == HashType::AesHash);

					auto hh = msgs.subspan(i, size);
					if (mIsMalicious)
					{
						mAesFixedKey.TmmoHashBlocks(hh, hh, [mTweak = i]() mutable {
							return block(mTweak++);
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

		for (u64 i = 0; i < extraChoices.size(); ++i)
		{
			t[i] = t[i].gf128Reduce(t2[i]);
		}

		setTimePoint("Kos.recv.done");
		return correlationData;
		static_assert(gOtExtBaseOtCount == 128, "expecting 128");
	}

}
#endif
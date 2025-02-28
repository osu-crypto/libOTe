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
		setBaseOts(baseOTs);
	}

	void KosOtExtReceiver::setBaseOts(span<std::array<block, 2>> baseOTs)
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
		mPrngIdx = 0;
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

		if (mIsMalicious && mHashType == HashType::NoHash)
			throw std::runtime_error("malicious no hash is not supported, use DotKos. " LOCATION);

		// we are going to process OTs in blocks of 128 * superBlkSize messages.
		if (hasBaseOts() == false)
			co_await genBaseOts(prng, chl);

		setTimePoint("Kos.recv.start");

		// used for the malicious check.
		auto fs = RandomOracle(sizeof(block));

		// used to hash messages
		RandomOracle sha(sizeof(block));

		u64 numExtra = 0;
		auto hashType = mHashType;
		auto mal = mIsMalicious;

		if (mIsMalicious)
			numExtra = 128;

		// extra OTs used in the KOS check.
		// We do 4 sets of malicious checks instead of 1
		// to mitigate the uncertainty surrounding the KOS security.
		auto extraMessages = AlignedUnVector<block>{ numExtra };
		auto extraChoice = BitVector{ numExtra };
		extraChoice.randomize(prng);

		u64 numBlocks = divCeil(messages.size() + numExtra, 128);
		auto tSize = mIsMalicious ? numBlocks * 128ull : 128ull;
		auto t0 = AlignedUnVector<block>{ tSize };
		auto transBuff = AlignedUnVector<block>{ 128ull * mIsMalicious };

		// get an array of blocks that we will fill.
		auto uBuff = AlignedUnVector<block>{};
		block* uIter = 0;
		block* uEnd = 0;
		u64 remaining = choices.sizeBlocks() + extraChoice.sizeBlocks();
		auto tIter = t0.data();

		// we handle the main OTs and the extra in two seperate
		// iterations.
		for (auto extra : { false, true })
		{
			span<block> choice = extra ?
				span<block>(extraChoice.blocks(), extraChoice.sizeBlocks()) :
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
				block* trans = nullptr;
				tIter -= 128;

				if (mal)
				{
					memcpy(transBuff.data(), tIter, 128 * sizeof(block));
					transpose128(transBuff.data());
					trans = transBuff.data();
					tIter += 128;
				}
				else
				{
					transpose128(t0.data());
					trans = t0.data();
					tIter = t0.data();
				}

				auto size = std::min<u64>(128, msgs.data() + msgs.size() - mIter);
				auto src = span<block>(trans, size);
				auto dst = span<block>(mIter, size);
				if (hashType == HashType::AesHash)
				{
					if (mIsMalicious)
					{
						mAesFixedKey.TmmoHashBlocks(src, dst, [mTweak = i * 128]() mutable {
							return block(mTweak++);
							});
					}
					else
					{
						mAesFixedKey.hashBlocks(src, dst);
					}
				}
				else if (mHashType == HashType::RandomOracle)
				{
					for (u64 j = 0; j < size; ++j)
					{
						auto idx = i * 128 + j;
						assert(&msgs[idx] == &dst[j]);
						// hash it
						sha.Reset();
						sha.Update(idx);
						sha.Update(src[j]);
						sha.Final(dst[j]);
					}
				}
				else
				{
					memcpy(dst.data(), src.data(), size * sizeof(block));
				}

				mIter += size;
			}
		}

		setTimePoint("Kos.recv.transposeDone");

		if (mIsMalicious)
		{
			block seed;
			if (mFiatShamir)
			{
				fs.Final(seed);
			}
			else
			{
				co_await chl.recv(seed);
				setTimePoint("Kos.recv.cncSeed");
			}

			// hash the messages and do the malicious check
				co_await check(t0, choices, extraChoice, seed, chl);

			setTimePoint("Kos.recv.hash");
		}

		} MACORO_CATCH(eptr) {
			if (!chl.closed()) co_await chl.close();
			std::rethrow_exception(eptr);
		}
	}

	task<> KosOtExtReceiver::check(
		span<block> T,
		BitVector const& choices,
		BitVector const& xChoices,
		block seed,
		coproto::Socket& sock)
	{

		std::vector<block> t1(T.end() - 128, T.end());
		std::vector<block> t2(128);
		block x1 = xChoices.blocks()[0], x2 = ZeroBlock;

		block ti, ti2;
		block xi, xi2;
		PRNG commonPrng(seed, 128);

		u64 n = choices.sizeBlocks();
		auto X = choices.blocks();
		auto cIter = commonPrng.mBuffer.data();
		auto cEnd = commonPrng.mBuffer.data() + commonPrng.mBuffer.size();
		auto tIter = T.data();
		for (u64 j = 0; j < n; ++j)
		{

			X[j].gf128Mul(*cIter, xi, xi2);
			x1 ^= xi;
			x2 ^= xi2;

			for (u64 i = 0; i < 128; ++i)
			{
				tIter[i].gf128Mul(*cIter, ti, ti2);
				t1[i] ^= ti;
				t2[i] ^= ti2;
			}

			++cIter;
			tIter += 128;

			if (cIter == cEnd)
			{
				commonPrng.refillBuffer();
				cIter = commonPrng.mBuffer.data();
			}
		}

		for (u64 i = 0; i < 128; ++i)
			t1[i] = t1[i].gf128Reduce(t2[i]);
		t1.push_back(x1.gf128Reduce(x2));
		co_await sock.send(std::move(t1));

		setTimePoint("Kos.recv.done");
		static_assert(gOtExtBaseOtCount == 128, "expecting 128");
	}

}
#endif
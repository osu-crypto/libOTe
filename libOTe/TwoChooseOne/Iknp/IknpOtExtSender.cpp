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

		// a temp that will be used to transpose the sender's matrix
		auto t = AlignedUnVector<block>{ 128 };
		{
			auto u = AlignedUnVector<block>(128 * commStepSize);
			{
				auto choiceMask = AlignedUnVector<block>{ 128 };
				{

					if (hasBaseOts() == false)
						co_await genBaseOts(prng, chl);

					// round up 
					auto numBlocks = divCeil(messages.size(), 128);

					assert(mBaseChoiceBits.size() == 128);
					auto delta = *(block*)mBaseChoiceBits.data();

					for (u64 i = 0; i < 128; ++i)
					{
						if (mBaseChoiceBits[i]) choiceMask[i] = AllOneBlock;
						else choiceMask[i] = ZeroBlock;
					}

					auto mIter = messages.data();
					block* uEnd = 0;
					block* uIter = 0;

					for (auto i = 0ull; i < numBlocks; ++i)
					{
						auto tIter = t.data();
						auto cIter = choiceMask.data();

						if (uIter == uEnd)
						{
							auto step = std::min<u64>(numBlocks - i, (u64)commStepSize) * 128;
							u.resize(step);
							uIter = u.data();
							uEnd = uIter + u.size();

							co_await(chl.recv(u));
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
							for (u64 i = 0; i < 128; i += 8)
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

						assert(tIter == t.data() + size);


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

					assert(uIter == uEnd);
					assert(mIter == messages.data() + messages.size());

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

					static_assert(gOtExtBaseOtCount == 128, "expecting 128");
				}
			}
		}
	}
}


#endif

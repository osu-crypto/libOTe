#include "SoftSpokenMalLeakyDotExt.h"
#ifdef ENABLE_SOFTSPOKEN_OT

#include "SoftSpokenMalLeakyDotExt.h"
#include "SoftSpokenMalOtExt.h"

namespace osuCrypto
{
	template<typename Hasher1>
	void SoftSpokenMalLeakyDotSender::sendImpl(
		span<std::array<block, 2>> messages, PRNG& prng, Channel& chl, Hasher1& hasher)
	{
		if (!hasBaseOts())
			genBaseOts(prng, chl);

		size_t nChunks = divCeil(messages.size() + 64, 128);
		size_t messagesFullChunks = messages.size() / 128;
		size_t numExtra = nChunks - messagesFullChunks; // Always 1 or 2

		block* scratch = (block*)messages.data();
		AlignedUnVector<block> scratchBacking;
		if (wSize() > 2 * 128)
		{
			scratchBacking.resize(messagesFullChunks * chunkSize() + paddingSize());
			scratch = scratchBacking.data();
		}
		ChunkerBase::runBatch(chl, span<block>(scratch, messagesFullChunks * chunkSize()));

		// Extra blocks
		ChunkerBase::runBatch(chl, mExtraW.subspan(0, numExtra * chunkSize()));

		mVole->sendChallenge(prng, chl);
		hasher.send(prng, chl);

		hasher.setGlobalParams(this, scratch);
		hasher.runBatch(chl, messages.subspan(0, messagesFullChunks * 128));
		//hasher.runBatch(chl, messages.subspan(messagesFullChunks * 128), this, mExtraW.data());
		hasher.setGlobalParams(this, mExtraW.data());
		hasher.runBatch(chl, messages.subspan(messagesFullChunks * 128));

		// Hash the last extra block if there was one with no used mMessages in it at all.
		if (numExtra == 2 || messages.size() % 128 == 0)
			mVole->hash(mExtraW.subspan(chunkSize() * (numExtra - 1), wPadded()));

		mVole->checkResponse(chl);
	}

	void SoftSpokenMalLeakyDotSender::processChunk(size_t nChunk, size_t numUsed, span<block> messages)
	{
		size_t blockIdx = mFieldBitsThenBlockIdx++;
		mVole->generateChosen(blockIdx, useAES(mVole->mVole.mNumVoles), messages.subspan(0, wPadded()));
	}

	void SoftSpokenMalLeakyDotSender::Hasher::processChunk(
		size_t nChunk, size_t numUsed,
		span<std::array<block, 2>> messages)
	{
		auto inputW = mInputW + nChunk * mParent->chunkSize();
		mParent->mVole->hash(span<const block>(inputW, mParent->wPadded()));

		transpose128(inputW);
		mParent->xorMessages(numUsed, (block*)messages.data(), inputW);
	}

	template<typename Hasher1>
	void SoftSpokenMalLeakyDotReceiver::receiveImpl(
		const BitVector& choices, span<block> messages, PRNG& prng, Channel& chl, Hasher1& hasher)
	{
		if (!hasBaseOts())
			genBaseOts(prng, chl);

		size_t nChunks = divCeil(messages.size() + 64, 128);
		size_t messagesFullChunks = messages.size() / 128;

		block* scratch = (block*)messages.data();
		AlignedUnVector<block> scratchBacking;
		if (vSize() > 128)
		{
			scratchBacking.resize(messagesFullChunks * chunkSize() + paddingSize());
			scratch = scratchBacking.data();
		}

		ChunkerBase::runBatch<block>(
			chl, span<block>(scratch, messagesFullChunks * chunkSize()),
			span<block>(choices.blocks(), messagesFullChunks));

		// Extra blocks
		size_t numExtra = nChunks - messagesFullChunks; // Always 1 or 2
		u64 extraChoicesU64[4] = { 0 };
		u64 sacrificialChoices = prng.get<u64>();
		int bit = messages.size() % 128;
		if (bit)
			memcpy(extraChoicesU64, choices.blocks() + messagesFullChunks, sizeof(block));

		int bit64 = bit % 64;
		int word = bit / 64;
		u64 mask = ((u64)1 << bit64) - 1;
		extraChoicesU64[word] &= mask;
		extraChoicesU64[word] |= sacrificialChoices << bit64;
		// Shift twice so that it becomes zero if bit64 = 0 (shift by 64 is undefined).
		extraChoicesU64[word + 1] = sacrificialChoices >> (63 - bit64) >> 1;

		block extraChoices[2] = { toBlock(0,0), toBlock(0,0) };
		memcpy(extraChoices, extraChoicesU64, 2 * sizeof(block));

		ChunkerBase::runBatch<block>(
			chl, mExtraV.subspan(0, numExtra * chunkSize()),
			span<block>(extraChoices, numExtra));

		mVole->recvChallenge(chl);
		hasher.recv(chl);

		hasher.setGlobalParams(this, scratch);
		hasher.template runBatch<block>(
			chl, messages.subspan(0, messagesFullChunks * 128),
			span<block>(choices.blocks(), messagesFullChunks));

		hasher.setGlobalParams(this, mExtraV.data());
		hasher.template runBatch<block>(
			chl, messages.subspan(messagesFullChunks * 128),
			span<block>(extraChoices, messages.size() % 128 != 0));

		// Hash the last extra block if there was one with no used mMessages in it at all.
		if (numExtra == 2 || messages.size() % 128 == 0)
			mVole->hash(
				span<block>(&extraChoices[numExtra - 1], 1),
				mExtraV.subspan(chunkSize() * (numExtra - 1), vPadded()));

		mVole->sendResponse(chl);
	}

	void SoftSpokenMalLeakyDotReceiver::processChunk(
		size_t nChunk, size_t numUsed, span<block> messages, block choices)
	{
		size_t blockIdx = mFieldBitsThenBlockIdx++;
		mVole->generateChosen(
			blockIdx, useAES(mVole->mVole.mNumVoles),
			span<block>(&choices, 1), messages.subspan(0, vPadded()));
	}

	template void SoftSpokenMalLeakyDotSender::sendImpl(
		span<std::array<block, 2>> messages, PRNG& prng, Channel& chl,
		SoftSpokenMalLeakyDotSender::Hasher& hasher);
	template void SoftSpokenMalLeakyDotReceiver::receiveImpl(
		const BitVector& choices, span<block> messages, PRNG& prng, Channel& chl,
		SoftSpokenMalLeakyDotReceiver::Hasher& hasher);
	template void SoftSpokenMalLeakyDotSender::sendImpl(
		span<std::array<block, 2>> messages, PRNG& prng, Channel& chl,
		SoftSpokenMalOtSender::Hasher& hasher);
	template void SoftSpokenMalLeakyDotReceiver::receiveImpl(
		const BitVector& choices, span<block> messages, PRNG& prng, Channel& chl,
		SoftSpokenMalOtReceiver::Hasher& hasher);

}

#endif

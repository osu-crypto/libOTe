#include "SoftSpokenShOtExt.h"
#ifdef ENABLE_SOFTSPOKEN_OT

namespace osuCrypto
{

	void SoftSpokenShOtSender::send(span<std::array<block, 2>> messages, PRNG& prng, Channel& chl)
	{
		if (!hasBaseOts())
			genBaseOts(prng, chl);

		ChunkerBase::runBatch(chl, messages);
	}

	void SoftSpokenShOtSender::processChunk(
		size_t nChunk, size_t numUsed, span<std::array<block, 2>> messages)
	{
		size_t blockIdx = mFieldBitsThenBlockIdx++;
		// secret usages = 1 per VOLE and 1 per message. However, only 1 or the other is secret, so only
		// need to increment by max(mNumVoles, 128) = 128.
		generateChosen(blockIdx, useAES(128), numUsed, messages);
	}

	void SoftSpokenShOtReceiver::receive(
		const BitVector& choices, span<block> messages, PRNG& prng, Channel& chl)
	{
		if (!hasBaseOts())
			genBaseOts(prng, chl);

		const size_t numBlocks = divCeil(choices.size(), 128);
		ChunkerBase::runBatch<block>(chl, messages, span<block>(choices.blocks(), numBlocks));
	}

	void SoftSpokenShOtReceiver::processChunk(
		size_t nChunk, size_t numUsed, span<block> messages, block chioces)
	{
		size_t blockIdx = mFieldBitsThenBlockIdx++;
		generateChosen(blockIdx, useAES(128), numUsed, chioces, messages);
	}
}

#endif

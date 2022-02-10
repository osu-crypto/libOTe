#include "TwoOneSemiHonest.h"
#ifdef ENABLE_SOFTSPOKEN_OT

namespace osuCrypto
{
namespace SoftSpokenOT
{

void TwoOneSemiHonestSender::send(span<std::array<block, 2>> messages, PRNG& prng, Channel& chl)
{
	if (!hasBaseOts())
		genBaseOts(prng, chl);

	ChunkerBase::runBatch(chl, messages);
}

void TwoOneSemiHonestSender::processChunk(
	size_t nChunk, size_t numUsed, span<std::array<block, 2>> messages)
{
	size_t blockIdx = fieldBitsThenBlockIdx++;
	// secret usages = 1 per VOLE and 1 per message. However, only 1 or the other is secret, so only
	// need to increment by max(numVoles, 128) = 128.
	generateChosen(blockIdx, useAES(128), numUsed, messages);
}

void TwoOneSemiHonestReceiver::receive(
	const BitVector& choices, span<block> messages, PRNG& prng, Channel& chl)
{
	if (!hasBaseOts())
		genBaseOts(prng, chl);

	const size_t numBlocks = divCeil(choices.size(), 128);
	ChunkerBase::runBatch<block>(chl, messages, span<block>(choices.blocks(), numBlocks));
}

void TwoOneSemiHonestReceiver::processChunk(
	size_t nChunk, size_t numUsed, span<block> messages, block chioces)
{
	size_t blockIdx = fieldBitsThenBlockIdx++;
	generateChosen(blockIdx, useAES(128), numUsed, chioces, messages);
}

}
}

#endif

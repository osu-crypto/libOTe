#include "TwoOneSemiHonest.h"
#ifdef ENABLE_SOFTSPOKEN_OT

namespace osuCrypto
{
namespace SoftSpokenOT
{

void TwoOneSemiHonestSender::xorAndHashMessages(size_t numUsed, block* messages) const
{
	block deltaBlock = delta();

	// Loop backwards, similarly to DotSemiHonest.
	size_t i = numUsed;
	while (i >= superBlkSize / 2)
	{
		i -= superBlkSize / 2;

		// Temporary array, so I (and the compiler) don't have to worry so much about aliasing.
		block superBlk[superBlkSize];
		for (size_t j = 0; j < superBlkSize / 2; ++j)
		{
			superBlk[2*j] = messages[i + j];
			superBlk[2*j + 1] = messages[i + j] ^ deltaBlock;
		}

		mAesFixedKey.hashBlocks<superBlkSize>(superBlk, messages + 2*i);
	}

	// Finish up. The more straightforward while (i--) unfortunately gives a (spurious AFAICT)
	// compiler warning about undefined behavior at iteration 0xfffffffffffffff, so use a for loop.
	size_t remainingIters = i;
	for (size_t j = 0; j < remainingIters; ++j)
	{
		i = remainingIters - j - 1;

		block msgs[2];
		msgs[0] = messages[i];
		msgs[1] = msgs[0] ^ deltaBlock;
		mAesFixedKey.hashBlocks<2>(msgs, messages + 2*i);
	}

	// Note: probably need a stronger hash for malicious secure version.
}

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
	generateChosen(blockIdx, numUsed, messages);
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
	generateChosen(blockIdx, numUsed, chioces, messages);
}

}
}

#endif

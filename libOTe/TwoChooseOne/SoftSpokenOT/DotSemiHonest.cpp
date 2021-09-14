#include "DotSemiHonest.h"
#ifdef ENABLE_SOFTSPOKEN_OT

namespace osuCrypto
{
namespace SoftSpokenOT
{

const size_t DotSemiHonestSender::chunkSize;
const size_t DotSemiHonestSender::commSize;
const size_t DotSemiHonestReceiver::chunkSize;
const size_t DotSemiHonestReceiver::commSize;

// TODO: Maybe do something with the timer.

void DotSemiHonestSender::setBaseOts(
	span<block> baseRecvOts,
	const BitVector& choices,
	PRNG& prng,
	Channel& chl)
{
	const size_t numVoles = divCeil(gOtExtBaseOtCount, fieldBits());
	vole.emplace(
		SmallFieldVoleReceiver(fieldBits(), numVoles, chl, prng, baseRecvOts, choices, numThreads),
		ReplicationCode(numVoles)
	);

	fieldBitsThenBlockIdx = 0;
	initTemporaryStorage();
}

void DotSemiHonestReceiver::setBaseOts(
	span<std::array<block, 2>> baseSendOts,
	PRNG& prng, Channel& chl)
{
	const size_t numVoles = divCeil(gOtExtBaseOtCount, fieldBits());
	vole.emplace(
		SmallFieldVoleSender(fieldBits(), numVoles, chl, prng, baseSendOts, numThreads),
		ReplicationCode(numVoles)
	);

	fieldBitsThenBlockIdx = 0;
	initTemporaryStorage();
}

void DotSemiHonestSender::send(span<std::array<block, 2>> messages, PRNG& prng, Channel& chl)
{
	if (!hasBaseOts())
		genBaseOts(prng, chl);

	runBatch(chl, messages);
}

void DotSemiHonestSender::processChunk(size_t numUsed, span<std::array<block, 2>> messages)
{
	size_t blockIdx = fieldBitsThenBlockIdx++;

	block* messagesPtr = (block*) messages.data();
	generateChosen(blockIdx, span<block>(messagesPtr, wPadded()));

	block deltaBlock = delta();

	// Loop backwards to avoid tripping over other iterations, as the loop is essentially mapping
	// index i to index 2*i.
	size_t i = numUsed;
	while (i >= superBlkSize / 2)
	{
		i -= superBlkSize / 2;

		// Temporary array, so I (and the compiler) don't have to worry so much about aliasing.
		block superBlk[superBlkSize];
		for (size_t j = 0; j < superBlkSize / 2; ++j)
		{
			superBlk[2*j] = messagesPtr[i + j];
			superBlk[2*j + 1] = messagesPtr[i + j] ^ deltaBlock;
		}
		std::copy_n(superBlk, superBlkSize, messagesPtr + 2*i);
	}

	// Finish up
	while (i-- > 0)
	{
		block v = messagesPtr[i];
		messagesPtr[2*i] = v;
		messagesPtr[2*i + 1] = v ^ deltaBlock;
	}
}


void DotSemiHonestReceiver::receive(
	const BitVector& choices, span<block> messages, PRNG& prng, Channel& chl)
{
	if (!hasBaseOts())
		genBaseOts(prng, chl);

	const size_t numBlocks = divCeil(choices.size(), 128);
	runBatch<block>(chl, messages, span<block>(choices.blocks(), numBlocks));
}

void DotSemiHonestReceiver::processChunk(size_t numUsed, span<block> messages, block choices)
{
	size_t blockIdx = fieldBitsThenBlockIdx++;
	generateChosen(blockIdx, choices, messages);
}

}
}

#endif

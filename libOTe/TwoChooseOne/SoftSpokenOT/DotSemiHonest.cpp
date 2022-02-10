#include "DotSemiHonest.h"
#ifdef ENABLE_SOFTSPOKEN_OT

#include "libOTe/Vole/SoftSpokenOT/SubspaceVoleMaliciousLeaky.h"

namespace osuCrypto
{
namespace SoftSpokenOT
{

template<typename T> const size_t DotSemiHonestSenderWithVole<T>::commSize;
template<typename T> const size_t DotSemiHonestReceiverWithVole<T>::commSize;

// TODO: Maybe do something with the timer.

template<typename SubspaceVole>
void DotSemiHonestSenderWithVole<SubspaceVole>::setBaseOts(
	span<block> baseRecvOts,
	const BitVector& choices,
	PRNG& prng,
	Channel& chl,
	bool malicious)
{
	block seed;
	chl.recv(&seed, 1);
	mAESs.setSeed(seed);

	const size_t numVoles = divCeil(gOtExtBaseOtCount, fieldBits());
	vole.emplace(
		SmallFieldVoleReceiver(
			fieldBits(), numVoles, chl, prng, baseRecvOts, choices, numThreads, malicious),
		RepetitionCode(numVoles)
	);

	fieldBitsThenBlockIdx = 0;
	initTemporaryStorage();
}

template<typename SubspaceVole>
void DotSemiHonestReceiverWithVole<SubspaceVole>::setBaseOts(
	span<std::array<block, 2>> baseSendOts,
	PRNG& prng, Channel& chl, bool malicious)
{
	block seed = prng.get<block>();
	chl.asyncSendCopy(&seed, 1);
	mAESs.setSeed(seed);

	const size_t numVoles = divCeil(gOtExtBaseOtCount, fieldBits());
	vole.emplace(
		SmallFieldVoleSender(fieldBits(), numVoles, chl, prng, baseSendOts, numThreads, malicious),
		RepetitionCode(numVoles)
	);

	fieldBitsThenBlockIdx = 0;
	initTemporaryStorage();
}

template<typename SubspaceVole>
void DotSemiHonestSenderWithVole<SubspaceVole>::send(
	span<std::array<block, 2>> messages, PRNG& prng, Channel& chl)
{
	if (!hasBaseOts())
		genBaseOts(prng, chl);

	ChunkerBase::runBatch(chl, messages);
}

template<typename SubspaceVole>
void DotSemiHonestSenderWithVole<SubspaceVole>::processChunk(
	size_t nChunk, size_t numUsed, span<std::array<block, 2>> messages)
{
	size_t blockIdx = fieldBitsThenBlockIdx++;

	block* messagesPtr = (block*) messages.data();

	// Only 1 AES evaluation per VOLE is on a secret seed.
	generateChosen(blockIdx, useAES(vole->vole.numVoles), span<block>(messagesPtr, wPadded()));
	xorMessages(numUsed, messagesPtr, messagesPtr);
}

// messagesOut and messagesIn must either be equal or non-overlapping.
template<typename SubspaceVole>
void DotSemiHonestSenderWithVole<SubspaceVole>::xorMessages(
	size_t numUsed, block* messagesOut, const block* messagesIn) const
{
	block deltaBlock = delta();

	// Loop backwards to avoid tripping over other iterations, as the loop is essentially mapping
	// index i to index 2*i and messagesOut might be messagesIn.
	size_t i = numUsed;
	while (i >= superBlkSize / 2)
	{
		i -= superBlkSize / 2;

		// Temporary array, so I (and the compiler) don't have to worry so much about aliasing.
		block superBlk[superBlkSize];
		for (size_t j = 0; j < superBlkSize / 2; ++j)
		{
			superBlk[2*j] = messagesIn[i + j];
			superBlk[2*j + 1] = messagesIn[i + j] ^ deltaBlock;
		}
		std::copy_n(superBlk, superBlkSize, messagesOut + 2*i);
	}

	// Finish up. The more straightforward while (i--) unfortunately gives a (spurious AFAICT)
	// compiler warning about undefined behavior at iteration 0xfffffffffffffff, so use a for loop.
	size_t remainingIters = i;
	for (size_t j = 0; j < remainingIters; ++j)
	{
		i = remainingIters - j - 1;

		block v = messagesIn[i];
		messagesOut[2*i] = v;
		messagesOut[2*i + 1] = v ^ deltaBlock;
	}
}


template<typename SubspaceVole>
void DotSemiHonestReceiverWithVole<SubspaceVole>::receive(
	const BitVector& choices, span<block> messages, PRNG& prng, Channel& chl)
{
	if (!hasBaseOts())
		genBaseOts(prng, chl);

	const size_t numBlocks = divCeil(choices.size(), 128);
	ChunkerBase::template runBatch<block>(chl, messages, span<block>(choices.blocks(), numBlocks));
}

template<typename SubspaceVole>
void DotSemiHonestReceiverWithVole<SubspaceVole>::processChunk(
	size_t nChunk, size_t numUsed, span<block> messages, block choices)
{
	size_t blockIdx = fieldBitsThenBlockIdx++;

	// Only 1 AES evaluation per VOLE is on a secret seed.
	generateChosen(blockIdx, useAES(vole->vole.numVoles), choices, messages);
}

template class DotSemiHonestSenderWithVole<SubspaceVoleReceiver<RepetitionCode>>;
template class DotSemiHonestReceiverWithVole<SubspaceVoleSender<RepetitionCode>>;
template class DotSemiHonestSenderWithVole<SubspaceVoleMaliciousReceiver<RepetitionCode>>;
template class DotSemiHonestReceiverWithVole<SubspaceVoleMaliciousSender<RepetitionCode>>;

}
}

#endif

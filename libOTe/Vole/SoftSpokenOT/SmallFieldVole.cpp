#include "SmallFieldVole.h"
#ifdef ENABLE_SOFTSPOKEN_OT

#include <cryptoTools/Crypto/AES.h>

#include <boost/log/core.hpp> // For BOOST_LOG_UNREACHABLE()

#ifdef BOOST_LOG_UNREACHABLE
#define UNREACHABLE() BOOST_LOG_UNREACHABLE()
#else
#define UNREACHABLE()
#endif

namespace osuCrypto
{

// Output: V (or W) in inOut[1 ...], and U in inOut[0]. If blocks > 2**depth, this pattern repeats
// once every 2**depth blocks.
template<size_t depth, size_t blocks = superBlkSize>
static TRY_FORCEINLINE void xorReduce(block* BOOST_RESTRICT inOut, size_t maxDepth)
{
	assert((blocks & ((1 << depth) - 1)) == 0); // Can't reduce partial trees.

	// Force unroll outer loop using template recursion.
	xorReduce<depth - 1, (depth > 1 ? blocks : 0)>(inOut, maxDepth);

	if (depth <= maxDepth)
	{
		size_t stride = 1 << (depth - 1);
		for (size_t i = 0; i < blocks; i += 2 * stride)
		{
			for (size_t j = 0; j < depth; ++j)
				inOut[i + j] ^= inOut[i + stride + j];
			inOut[i + depth] = inOut[i + stride + depth - 1];
		}
	}
}

// Base case
template<> TRY_FORCEINLINE void xorReduce<0, 0>(block* BOOST_RESTRICT inOut, size_t maxDepth) {}

// outU is unused when this is called by the receiver, and a few operations might be saved by not
// computing it. However, it's just a few XORs, and the compiler will likely optimize it out anyway.
static TRY_FORCEINLINE void xorReducePath(
	size_t fieldBits, size_t fieldSize, size_t superBlk, block (*BOOST_RESTRICT path)[superBlkSize],
	block* BOOST_RESTRICT outVW, block* BOOST_RESTRICT outU, bool isReceiver)
{
	// Reduce up the combining tree, continuing for as many nodes just got completed.
	// However, the root is skipped, in case it might have a different size.
	size_t treeDepth = 0;
	for (size_t blkInTree = superBlk; treeDepth < (fieldBits - 1) / superBlkShift
	     && blkInTree % superBlkSize == 0; ++treeDepth)
	{
		blkInTree /= superBlkSize;

		xorReduce<superBlkShift>(path[treeDepth], superBlkShift);

		for (size_t depth = 0; depth < superBlkShift; ++depth)
			outVW[treeDepth * superBlkShift + depth] ^= path[treeDepth][depth + 1];
		path[treeDepth + 1][(blkInTree - 1) % superBlkSize] = path[treeDepth][0];
	}

	// Reduce the root of the combining tree.
	if ((superBlk & (fieldSize - 1)) == 0)
	{
		size_t depthRemaining = 1 + (fieldBits - 1) % superBlkShift;
		xorReduce<superBlkShift>(path[treeDepth], depthRemaining);

		for (size_t j = 0; j < depthRemaining; ++j)
			outVW[treeDepth * superBlkShift + j] = path[treeDepth][j + 1];
		if (!isReceiver)
			*outU = path[treeDepth][0];
	}
}

template<size_t fieldBitsConst>
//__attribute__((optimize("unroll-loops")))
void SubspaceVoleSender::generateNthBlockImpl(
	size_t blockIdx, block* BOOST_RESTRICT outV, block* BOOST_RESTRICT outU) const
{
	// Allow the compiler to hardcode fieldBits based on the template parameter.
	const size_t fieldBits = fieldBitsConst > 0 ? fieldBitsConst : this->fieldBits;
	constexpr size_t fieldBitsMax =
		fieldBitsConst > 0 ? fieldBitsConst : SubspaceVoleSender::fieldBitsMax;
	const size_t fieldSize = 1 << fieldBits;

	block* BOOST_RESTRICT seeds = this->seeds.get();
	block blockIdxBlock = toBlock(blockIdx);

	if (fieldBits <= superBlkShift) // >= 1 VOLEs per superblock.
	{
		if (fieldBitsConst == 0)
			UNREACHABLE();

		const size_t volePerSuperBlk = superBlkSize / fieldSize;
		for (size_t nVole = 0; nVole < numVoles; nVole += volePerSuperBlk, outV += superBlkSize)
		{
			// TODO: Try combining the block index into the AES key. It gives the same PRG, but
			// might be faster.
			block input[superBlkSize], hashes[superBlkSize];
			for (size_t i = 0; i < superBlkSize; ++i, ++seeds)
				input[i] = blockIdxBlock ^ *seeds;
			mAesFixedKey.hashBlocks<superBlkSize>(input, hashes);

			xorReduce<superBlkShift>(hashes, superBlkShift);
			for (size_t i = 0; i < volePerSuperBlk; ++i, ++outU)
			{
				for (size_t j = 0; j < fieldBits; ++j)
					outV[i * fieldBits + j] = hashes[i * fieldSize + j + 1];
				*outU = hashes[i * fieldSize];
			}
		}
	}
	else // > 1 super block per VOLE.
	{
		for (size_t nVole = 0; nVole < numVoles; ++nVole, outV += fieldBits, ++outU)
		{
			block path[divCeil(fieldBitsMax, superBlkShift)][superBlkSize];
			for (size_t i = 0; i < fieldBits; ++i)
				// GCC seems to generate better code with an open coded memset.
				outV[i] = toBlock(0UL);

			#ifdef __GNUC__
			#pragma GCC unroll 4
			#endif
			for (size_t superBlk = 0; superBlk < fieldSize;)
			{
				block input[superBlkSize];
				for (size_t i = 0; i < superBlkSize; ++i, ++superBlk, ++seeds)
					input[i] = blockIdxBlock ^ *seeds;
				mAesFixedKey.hashBlocks<superBlkSize>(input, path[0]);
				xorReducePath(fieldBits, fieldSize, superBlk, path, outV, outU, false);
			}
		}
	}
}

template<size_t fieldBitsConst>
//__attribute__((optimize("unroll-loops")))
void SubspaceVoleReceiver::generateNthBlockImpl(size_t blockIdx, block* BOOST_RESTRICT outW) const
{
	// Allow the compiler to hardcode fieldBits based on the template parameter.
	const size_t fieldBits = fieldBitsConst > 0 ? fieldBitsConst : this->fieldBits;
	constexpr size_t fieldBitsMax =
		fieldBitsConst > 0 ? fieldBitsConst : SubspaceVoleSender::fieldBitsMax;
	const size_t fieldSize = 1 << fieldBits;

	block* BOOST_RESTRICT seeds = this->seeds.get();
	block blockIdxBlock = toBlock(blockIdx);

	if (fieldBits <= superBlkShift)
	{
		// >= 1 VOLEs per superblock. This case can only occur for small fieldSize, small enough
		// that this cannot be the variable size implementation (fieldBitsConst != 0).
		if (fieldBitsConst == 0)
			UNREACHABLE();

		// Avoid compilation trouble when this if branch is unreachable.
		constexpr size_t fieldBits_ = std::min(fieldBitsMax, (size_t) superBlkShift);

		// This is a trickier case, as we need to decide how many VOLES will fit
		// per super block, and how many AES calls to use. Try to get as close to 8 AES invocations
		// per superblock as possible.
		constexpr size_t aesPerVole = (1 << fieldBits_) - 1;
		constexpr size_t volePerSuperBlk = divNearest(superBlkSize, aesPerVole);
		constexpr size_t aesPerSuperBlk = aesPerVole * volePerSuperBlk;
		constexpr size_t fieldsPerSuperBlk = volePerSuperBlk << fieldBits_;

		for (size_t nVole = 0; nVole < numVoles; nVole += volePerSuperBlk, outW += aesPerSuperBlk)
		{
			block input[aesPerSuperBlk], hashes[aesPerSuperBlk], xorHashes[fieldsPerSuperBlk];
			for (size_t i = 0; i < aesPerSuperBlk; ++i, ++seeds)
				input[i] = blockIdxBlock ^ *seeds;
			mAesFixedKey.hashBlocks<aesPerSuperBlk>(input, hashes);

			// Intersperse the hashes with zeros, because the zeroth seed for each VOLE is unknown.
			for (size_t i = 0; i < volePerSuperBlk; ++i)
			{
				xorHashes[i * fieldSize] = toBlock(0UL);
				for (size_t j = 0; j < aesPerVole; ++j)
					xorHashes[i * fieldSize + j + 1] = hashes[i * aesPerVole + j];
			}

			xorReduce<fieldBits_>(xorHashes, fieldBits);
			for (size_t i = 0; i < volePerSuperBlk; ++i)
				for (size_t j = 0; j < fieldBits; ++j)
					outW[i * fieldBits + j] = xorHashes[i * fieldSize + j + 1];
		}
	}
	else
	{
		// > 1 super block per VOLE. Do blocks of 8, or 7 at the start because the zeroth seed in a
		// VOLE is unknown.
		for (size_t nVole = 0; nVole < numVoles; ++nVole, outW += fieldBits)
		{
			block path[divCeil(fieldBitsMax, superBlkShift)][superBlkSize];
			memset(outW, 0, fieldBits * sizeof(block));
			//for (size_t i = 0; i < fieldBits; ++i)
			//	// GCC seems to generate better code with an open coded memset.
			//	outW[i] = toBlock(0UL);

			block input0[superBlkSize -  1];
			for (size_t i = 0; i < superBlkSize - 1; ++i, ++seeds)
				input0[i] = blockIdxBlock ^ *seeds;
			mAesFixedKey.hashBlocks<superBlkSize - 1>(input0, &path[0][1]);

			// The zeroth seed is unknown, so set the corresponding path element to zero.
			path[0][0] = toBlock(0UL);

			size_t superBlk = superBlkSize;
			xorReducePath(fieldBits, fieldSize, superBlk, path, outW, nullptr, true);

			#ifdef __GNUC__
			#pragma GCC unroll 3
			#endif
			while (superBlk < fieldSize)
			{
				block input[superBlkSize];
				for (size_t i = 0; i < superBlkSize; ++i, ++superBlk, ++seeds)
					input[i] = blockIdxBlock ^ *seeds;
				mAesFixedKey.hashBlocks<superBlkSize>(input, path[0]);

				xorReducePath(fieldBits, fieldSize, superBlk, path, outW, nullptr, true);
			}
		}
	}
}

// TODO: try both PprfOutputFormat::Plain and PprfOutputFormat::Interleaved.

#define VOLE_FIELD_CASE(party, n) \
	case n: \
		generateNthBlockPtr = &SubspaceVole##party::generateNthBlockImpl<n>; \
		break;

SubspaceVoleSender::SubspaceVoleSender(size_t fieldBits_, size_t numVoles_) :
	SubspaceVoleBase(fieldBits_, numVoles_)
{
	seeds.reset(new block[numVolesPadded() * fieldSize()]);
	memset(seeds.get() + numVoles * fieldSize(), 0,
	       (numVolesPadded() - numVoles) * fieldSize() * sizeof(block));

	// Need this somewhere
	// MatrixView<block>(seeds.get(), numVoles, fieldSize() - isReceiver);

	// Select specialized implementation of generateNthBlock.
	switch (fieldBits)
	{
		VOLE_FIELD_CASE(Sender, 1)
		VOLE_FIELD_CASE(Sender, 2)
		VOLE_FIELD_CASE(Sender, 3)
		VOLE_FIELD_CASE(Sender, 4)
		VOLE_FIELD_CASE(Sender, 5)
		VOLE_FIELD_CASE(Sender, 6)
		VOLE_FIELD_CASE(Sender, 7)
		VOLE_FIELD_CASE(Sender, 8)
		VOLE_FIELD_CASE(Sender, 9)
		VOLE_FIELD_CASE(Sender, 10)
	default:
		generateNthBlockPtr = &SubspaceVoleSender::generateNthBlockImpl<0>;
	}
}

SubspaceVoleReceiver::SubspaceVoleReceiver(size_t fieldBits_, size_t numVoles_) :
	SubspaceVoleBase(fieldBits_, numVoles_)
{
	seeds.reset(new block[numVolesPadded() * fieldSize()]);
	memset(seeds.get() + numVoles * fieldSize(), 0,
	       (numVolesPadded() - numVoles) * fieldSize() * sizeof(block));

	// TODO: Reorder random bits to handle the (Delta ^) part.

	// Select specialized implementation of generateNthBlock.
	switch (fieldBits)
	{
		VOLE_FIELD_CASE(Receiver, 1)
		VOLE_FIELD_CASE(Receiver, 2)
		VOLE_FIELD_CASE(Receiver, 3)
		VOLE_FIELD_CASE(Receiver, 4)
		VOLE_FIELD_CASE(Receiver, 5)
		VOLE_FIELD_CASE(Receiver, 6)
		VOLE_FIELD_CASE(Receiver, 7)
		VOLE_FIELD_CASE(Receiver, 8)
		VOLE_FIELD_CASE(Receiver, 9)
		VOLE_FIELD_CASE(Receiver, 10)
	default:
		generateNthBlockPtr = &SubspaceVoleReceiver::generateNthBlockImpl<0>;
	}
}

#undef VOLE_FIELD_CASE

}

#endif

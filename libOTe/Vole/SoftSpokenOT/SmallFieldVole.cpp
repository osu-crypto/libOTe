#include "SmallFieldVole.h"
#ifdef ENABLE_SOFTSPOKEN_OT

#include <cryptoTools/Common/Matrix.h>
#include <cryptoTools/Common/TestCollection.h>
#include <cryptoTools/Crypto/AES.h>
#include <cryptoTools/Crypto/Blake2.h>
#include "libOTe/Tools/SilentPprf.h"

#include <boost/log/core.hpp> // For BOOST_LOG_UNREACHABLE()

#ifdef BOOST_LOG_UNREACHABLE
#define UNREACHABLE() BOOST_LOG_UNREACHABLE()
#else
#define UNREACHABLE()
#endif

namespace osuCrypto
{
namespace SoftSpokenOT
{

// Output: v (or w) in inOut[1 ...], and u in inOut[0]. If blocks > 2**depth, this pattern repeats
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
			inOut[i + depth] = inOut[i + stride];
		}
	}
}

// Base case
template<> TRY_FORCEINLINE void xorReduce<0, 0>(block* BOOST_RESTRICT inOut, size_t maxDepth) {}

// outU is unused when this is called by the receiver, and a few operations might be saved by not
// computing it. However, it's just a few XORs, and the compiler will likely optimize it out anyway.
static TRY_FORCEINLINE void xorReducePath(
	size_t fieldBits, size_t fieldSize, size_t superBlk, block (*BOOST_RESTRICT path)[superBlkSize],
	block* BOOST_RESTRICT outU, block* BOOST_RESTRICT outVW, bool isReceiver,
	bool correctionPresent = false)
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

		if (correctionPresent)
			for (size_t j = 0; j < depthRemaining; ++j)
				outVW[treeDepth * superBlkShift + j] ^= path[treeDepth][j + 1];
		else
			for (size_t j = 0; j < depthRemaining; ++j)
				outVW[treeDepth * superBlkShift + j] = path[treeDepth][j + 1];
		if (!isReceiver)
			*outU = path[treeDepth][0];
	}
}

template<size_t fieldBitsConst>
TRY_FORCEINLINE void SmallFieldVoleSender::generateImpl(
	size_t blockIdx, block* BOOST_RESTRICT outU, block* BOOST_RESTRICT outV) const
{
	// Allow the compiler to hardcode fieldBits based on the template parameter.
	const size_t fieldBits = fieldBitsConst > 0 ? fieldBitsConst : this->fieldBits;
	constexpr size_t fieldBitsMax =
		fieldBitsConst > 0 ? fieldBitsConst : SmallFieldVoleSender::fieldBitsMax;
	const size_t fieldSize = 1 << fieldBits;

	block* BOOST_RESTRICT seeds = this->seeds.get();
	block blockIdxBlock = toBlock(blockIdx);

	if (fieldBits <= superBlkShift) // >= 1 VOLEs per superblock.
	{
		if (fieldBitsConst == 0)
			UNREACHABLE();

		const size_t volePerSuperBlk = superBlkSize / fieldSize;
		for (size_t nVole = 0; nVole < numVoles; nVole += volePerSuperBlk)
		{
			// TODO: Try combining the block index into the AES key. It gives the same PRG, but
			// might be faster.
			block input[superBlkSize], hashes[superBlkSize];
			for (size_t i = 0; i < superBlkSize; ++i, ++seeds)
				input[i] = blockIdxBlock ^ *seeds;
			mAesFixedKey.hashBlocks<superBlkSize>(input, hashes);

			xorReduce<superBlkShift>(hashes, fieldBits);
			for (size_t i = 0; i < volePerSuperBlk; ++i, ++outU)
			{
				for (size_t j = 0; j < fieldBits; ++j, ++outV)
					*outV = hashes[i * fieldSize + j + 1];
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
				xorReducePath(fieldBits, fieldSize, superBlk, path, outU, outV, false);
			}
		}
	}
}

template<size_t fieldBitsConst>
TRY_FORCEINLINE void SmallFieldVoleReceiver::generateImpl(
	size_t blockIdx, block* BOOST_RESTRICT outW, const block* BOOST_RESTRICT correction) const
{
	// Allow the compiler to hardcode fieldBits based on the template parameter.
	const size_t fieldBits = fieldBitsConst > 0 ? fieldBitsConst : this->fieldBits;
	constexpr size_t fieldBitsMax =
		fieldBitsConst > 0 ? fieldBitsConst : SmallFieldVoleSender::fieldBitsMax;
	const size_t fieldSize = 1 << fieldBits;

	block* BOOST_RESTRICT seeds = this->seeds.get();
	block blockIdxBlock = toBlock(blockIdx);

	bool correctionPresent = (correction != nullptr);
	const u8* BOOST_RESTRICT deltaPtr = deltaUnpacked.get();

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

		for (size_t nVole = 0; nVole < numVoles; nVole += volePerSuperBlk,
		     correction += volePerSuperBlk, deltaPtr += fieldBits * volePerSuperBlk)
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

			xorReduce<fieldBits_, fieldsPerSuperBlk>(xorHashes, fieldBits);
			if (correctionPresent)
			{
				if (numVoles - nVole >= volePerSuperBlk)
					for (size_t i = 0; i < volePerSuperBlk; ++i)
						for (size_t j = 0; j < fieldBits; ++j, ++outW)
							*outW = xorHashes[i * fieldSize + j + 1] ^
								correction[i] & block::allSame(deltaPtr[i * fieldBits + j]);
				else
					for (size_t i = 0; i < numVoles - nVole; ++i)
						for (size_t j = 0; j < fieldBits; ++j, ++outW)
							*outW = xorHashes[i * fieldSize + j + 1] ^
								correction[i] & block::allSame(deltaPtr[i * fieldBits + j]);
			}
			else
				for (size_t i = 0; i < volePerSuperBlk; ++i)
					for (size_t j = 0; j < fieldBits; ++j, ++outW)
						*outW = xorHashes[i * fieldSize + j + 1];
		}
	}
	else
	{
		// > 1 super block per VOLE. Do blocks of 8, or 7 at the start because the zeroth seed in a
		// VOLE is unknown.
		for (size_t nVole = 0; nVole < numVoles; ++nVole, outW += fieldBits, deltaPtr += fieldBits)
		{
			block path[divCeil(fieldBitsMax, superBlkShift)][superBlkSize];
			if (correctionPresent)
				for (size_t i = 0; i < fieldBits; ++i)
					outW[i] = correction[nVole] & block::allSame(deltaPtr[i]);
			else
				for (size_t i = 0; i < fieldBits; ++i)
					outW[i] = toBlock(0UL);

			block input0[superBlkSize -  1];
			for (size_t i = 0; i < superBlkSize - 1; ++i, ++seeds)
				input0[i] = blockIdxBlock ^ *seeds;
			mAesFixedKey.hashBlocks<superBlkSize - 1>(input0, &path[0][1]);

			// The zeroth seed is unknown, so set the corresponding path element to zero.
			path[0][0] = toBlock(0UL);

			size_t superBlk = superBlkSize;
			xorReducePath(fieldBits, fieldSize, superBlk, path, nullptr, outW, true);

			#ifdef __GNUC__
			#pragma GCC unroll 3
			#endif
			while (superBlk < fieldSize)
			{
				block input[superBlkSize];
				for (size_t i = 0; i < superBlkSize; ++i, ++superBlk, ++seeds)
					input[i] = blockIdxBlock ^ *seeds;
				mAesFixedKey.hashBlocks<superBlkSize>(input, path[0]);

				xorReducePath(fieldBits, fieldSize, superBlk, path, nullptr, outW,
				              true, correctionPresent);
			}
		}
	}
}

template<size_t fieldBitsConst, typename T, T Func>
struct SmallFieldVoleBase::call_member_func {};

template<size_t fieldBitsConst, typename Class, typename Return, typename... Params, Return (Class::*Func)(Params...) const>
struct SmallFieldVoleBase::call_member_func<fieldBitsConst, Return (Class::*)(Params...) const, Func>
{
	static Return call(const Class& this_, Params... params)
	{
		this_.template generateImpl<fieldBitsConst>(std::forward<Params>(params)...);
	}
};

SmallFieldVoleSender::SmallFieldVoleSender(size_t fieldBits_, size_t numVoles_) :
	SmallFieldVoleBase(fieldBits_, numVoles_),
	numVolesPadded(computeNumVolesPadded(fieldBits_, numVoles_)),
	generatePtr(selectGenerateImpl(fieldBits))
{
	seeds.reset(new block[numVolesPadded * fieldSize()]);
	std::fill_n(seeds.get(), numVolesPadded * fieldSize(), toBlock(0UL));
}

SmallFieldVoleReceiver::SmallFieldVoleReceiver(size_t fieldBits_, size_t numVoles_) :
	SmallFieldVoleBase(fieldBits_, numVoles_),
	numVolesPadded(computeNumVolesPadded(fieldBits_, numVoles_)),
	generatePtr(selectGenerateImpl(fieldBits))
{
	seeds.reset(new block[numVolesPadded * (fieldSize() - 1)]);
	std::fill_n(seeds.get(), numVolesPadded * (fieldSize() - 1), toBlock(0UL));
}

SmallFieldVoleSender::SmallFieldVoleSender(size_t fieldBits_, size_t numVoles_, span<const block> seeds_) :
	SmallFieldVoleSender(fieldBits_, numVoles_)
{
	size_t numSeeds = numVoles * fieldSize();
	if ((size_t) seeds_.size() != numSeeds)
		throw RTE_LOC;
	gsl::copy(seeds_, span<block>(seeds.get(), numSeeds));
}

SmallFieldVoleReceiver::SmallFieldVoleReceiver(size_t fieldBits_, size_t numVoles_, BitVector delta_) :
	SmallFieldVoleReceiver(fieldBits_, numVoles_)
{
	if ((size_t) delta_.size() != numBaseOTs())
		throw RTE_LOC;
	delta = std::move(delta_);
	deltaUnpacked.reset(new u8[delta.size()]);
	for (size_t i = 0; i < delta.size(); ++i)
		deltaUnpacked[i] = -(u8) delta[i];
}

SmallFieldVoleReceiver::SmallFieldVoleReceiver(size_t fieldBits_, size_t numVoles_,
	span<const block> seeds_, BitVector delta_) :
	SmallFieldVoleReceiver(fieldBits_, numVoles_, delta_)
{
	size_t numSeeds = numVoles * (fieldSize() - 1);
	if ((size_t) seeds_.size() != numSeeds)
		throw RTE_LOC;
	gsl::copy(seeds_, span<block>(seeds.get(), numSeeds));
}

SmallFieldVoleSender::SmallFieldVoleSender(size_t fieldBits_, size_t numVoles_, Channel& chl,
	PRNG& prng, span<const std::array<block, 2>> baseMessages, size_t numThreads, bool malicious) :
	SmallFieldVoleSender(fieldBits_, numVoles_)
{
	SilentMultiPprfSender pprf(fieldSize(), numVoles);
	pprf.setBase(baseMessages);

	MatrixView<block> seedView(seeds.get(), numVoles, fieldSize());
	pprf.expand(chl, span<const block>(), prng, seedView, PprfOutputFormat::BlockTransposed, numThreads);

	// Prove consistency
	if (malicious)
	{
		std::vector<std::array<block, 2>> corrections(numVoles, {block::allSame(0)});
		std::vector<std::array<block, 2>> hashes(numVoles, {block::allSame(0)});
		for (size_t row = 0; row < numVoles; ++row)
		{
			Blake2 hasher(2 * sizeof(block));

			for (size_t col = 0; col < fieldSize(); ++col)
			{
				Blake2 prg(3 * sizeof(block));
				std::array<block, 3> prgOut;
				prg.Update(seeds[row * fieldSize() + col]);
				prg.Final(prgOut);

				for (int i = 0; i < 2; ++i)
					corrections[row][i] ^= prgOut[i];
				hasher.Update(&prgOut[0], 2);
				seeds[row * fieldSize() + col] = prgOut[2];
			}

			// TODO: probably fine to hash together, not separately.
			hasher.Final(hashes[row]);
		}

		chl.asyncSend(std::move(corrections));
		chl.asyncSend(std::move(hashes));
	}
}

// The choice bits (as expected by SilentMultiPprfReceiver) store the locations of the complements
// of the active paths (because they tell which messages were transferred, not which ones weren't),
// in big endian. We want delta, which is the locations of the active paths, in little endian.
static BitVector choicesToDelta(const BitVector& choices, size_t fieldBits, size_t numVoles)
{
	if ((size_t) choices.size() != numVoles * fieldBits)
		throw RTE_LOC;

	BitVector delta(choices.size());
	for (size_t i = 0; i < numVoles; ++i)
		for (size_t j = 0; j < fieldBits; ++j)
			delta[i * fieldBits + j] = 1 ^ choices[(i + 1) * fieldBits - j - 1];
	return delta;
}

SmallFieldVoleReceiver::SmallFieldVoleReceiver(size_t fieldBits_, size_t numVoles_, Channel& chl,
	PRNG& prng, span<const block> baseMessages, BitVector choices, size_t numThreads,
	bool malicious) :
	SmallFieldVoleReceiver(fieldBits_, numVoles_, choicesToDelta(choices, fieldBits_, numVoles_))
{
	SilentMultiPprfReceiver pprf;
	pprf.configure(fieldSize(), numVoles);

	if (pprf.mDepth != fieldBits) // Sanity check: log2ceil.
		throw RTE_LOC;
	if (pprf.baseOtCount() != numBaseOTs()) // Sanity check
		throw RTE_LOC;

	pprf.setBase(baseMessages);
	pprf.setChoiceBits(PprfOutputFormat::BlockTransposed, choices);

	Matrix<block> seedsFull(numVoles, fieldSize());
	pprf.expand(chl, prng, seedsFull, PprfOutputFormat::BlockTransposed, false, numThreads);

	// Check consistency
	if (malicious)
	{
		std::vector<std::array<block, 2>> totals(numVoles, {block::allSame(0)});
		std::vector<std::array<block, 2>> entryHashes(numVoles * fieldSize(), {block::allSame(0)});
		block* seedMatrix = seedsFull.data();
		for (size_t row = 0; row < numVoles; ++row)
		{

			for (size_t col = 0; col < fieldSize(); ++col)
			{
				Blake2 prg(3 * sizeof(block));
				std::array<block, 3> prgOut;
				prg.Update(seedMatrix[row * fieldSize() + col]);
				prg.Final(prgOut);

				for (int i = 0; i < 2; ++i)
				{
					totals[row][i] ^= prgOut[i];
					entryHashes[row * fieldSize() + col][i] = prgOut[i];
				}
				seedMatrix[row * fieldSize() + col] = prgOut[2];
			}
		}

		std::vector<std::array<block, 2>> corrections(numVoles, {block::allSame(0)});
		std::vector<std::array<block, 2>> hashes(numVoles, {block::allSame(0)});
		chl.recv(&corrections[0], corrections.size());
		chl.recv(&hashes[0], hashes.size());

		int eq = 1;
		for (size_t row = 0; row < numVoles; ++row)
		{
			for (int i = 0; i < 2; ++i)
				corrections[row][i] ^= totals[row][i];

			size_t rowDelta = 0;
			for (size_t bit = 0; bit < fieldBits; ++bit)
				rowDelta |= (size_t) delta[row * fieldBits + bit] << bit;

			for (size_t col = 0; col < fieldSize(); ++col)
			{
				block isUnknownSeed = block::allSame(col == rowDelta);
				for (int i = 0; i < 2; ++i)
					entryHashes[row * fieldSize() + col][i] ^= isUnknownSeed & corrections[row][i];
			}

			Blake2 hasher(2 * sizeof(block));
			std::array<block, 2> hash;
			for (size_t col = 0; col < fieldSize(); ++col)
				hasher.Update(entryHashes[row * fieldSize() + col]);
			hasher.Final(hash);

			for (int i = 0; i < 2; ++i)
				eq &= (hash[i] == hashes[row][i]);
		}
		if (!eq)
			throw std::runtime_error("PPRF failed consistency check.");
	}

	// Reorder seeds to handle the (Delta ^) part, moving the unknown seeds to column 0. This
	// effectively makes it compute w = sum_x (Delta ^ x) * r_x instead of v = sum_x x * r_x.
	// TODO: Might be best to do this as part of going down the pprf tree. There, it would cost
	// O(numVoles * fieldSize) time, rather than O(numVoles * fieldSize * fieldBits).
	for (size_t i = 0; i < fieldBits; ++i)
	{
		size_t dMask = (size_t) 1 << i;
		block* matrix = seedsFull.data();
		// Bit hack to iterate over all values that are have a 0 in position i (from Hacker's
		// Delight).
		for (size_t col = 0; col < fieldSize(); col = (col + dMask + 1) & ~dMask)
			for (size_t row = 0; row < numVoles; ++row)
				cswapBytes(
					matrix[row * fieldSize() + col],
					matrix[row * fieldSize() + col + dMask],
					deltaUnpacked[row * fieldBits + i]);
	}

	// Remove the unknown seeds so that generate doesn't have to skip over them.
	MatrixView<block> seedView(seeds.get(), numVoles, fieldSize() - 1);
	for (size_t row = 0; row < numVoles; ++row)
		gsl::copy(seedsFull[row].subspan(1), seedView[row]);
}

// TODO: Malicious version. Should use an actual hash function for bottom layer of tree.

#define VOLE_GEN_FUNC(party, n) &SmallFieldVole##party::generateImpl<n>
#define VOLE_FIELD_BITS_TABLE(party, n) \
	&call_member_func<n, decltype(VOLE_GEN_FUNC(party, n)), VOLE_GEN_FUNC(party, n)>::call

decltype(SmallFieldVoleSender::generatePtr)
SmallFieldVoleSender::selectGenerateImpl(size_t fieldBits)
{
	static const decltype(generatePtr) table[] = {
		VOLE_FIELD_BITS_TABLE(Sender, 1),
		VOLE_FIELD_BITS_TABLE(Sender, 2),
		VOLE_FIELD_BITS_TABLE(Sender, 3),
		VOLE_FIELD_BITS_TABLE(Sender, 4),
		VOLE_FIELD_BITS_TABLE(Sender, 5),
		VOLE_FIELD_BITS_TABLE(Sender, 6),
		VOLE_FIELD_BITS_TABLE(Sender, 7),
		VOLE_FIELD_BITS_TABLE(Sender, 8),
		VOLE_FIELD_BITS_TABLE(Sender, 9),
		VOLE_FIELD_BITS_TABLE(Sender, 10)
	};
	if (fieldBits <= sizeof(table) / sizeof(table[0]))
		return table[fieldBits - 1];
	else
		return VOLE_FIELD_BITS_TABLE(Sender, 0);
}

decltype(SmallFieldVoleReceiver::generatePtr)
SmallFieldVoleReceiver::selectGenerateImpl(size_t fieldBits)
{
	static const decltype(generatePtr) table[] = {
		VOLE_FIELD_BITS_TABLE(Receiver, 1),
		VOLE_FIELD_BITS_TABLE(Receiver, 2),
		VOLE_FIELD_BITS_TABLE(Receiver, 3),
		VOLE_FIELD_BITS_TABLE(Receiver, 4),
		VOLE_FIELD_BITS_TABLE(Receiver, 5),
		VOLE_FIELD_BITS_TABLE(Receiver, 6),
		VOLE_FIELD_BITS_TABLE(Receiver, 7),
		VOLE_FIELD_BITS_TABLE(Receiver, 8),
		VOLE_FIELD_BITS_TABLE(Receiver, 9),
		VOLE_FIELD_BITS_TABLE(Receiver, 10)
	};
	if (fieldBits <= sizeof(table) / sizeof(table[0]))
		return table[fieldBits - 1];
	else
		return VOLE_FIELD_BITS_TABLE(Receiver, 0);
}

#undef VOLE_FIELD_BITS_CASE

void tests::xorReduction()
{
	const bool print = false;

	auto arrayAssertEq = [=](auto x, auto y) {
		if (print)
		{
			std::copy(x.begin(), x.end(), std::ostream_iterator<block>(std::cout, ", "));
			std::cout << '\n';
			std::copy(y.begin(), y.end(), std::ostream_iterator<block>(std::cout, ", "));
			std::cout << '\n';
		}

		if (x != y)
			throw UnitTestFail(LOCATION);
	};

	if (print)
		std::cout << '\n';
	const std::array<block, 8> testSuperBlock = {
		block::allSame(0x20), block::allSame(0x03), block::allSame(0xf9), block::allSame(0x2d),
		block::allSame(0x3a), block::allSame(0xb9), block::allSame(0xa3), block::allSame(0xbb)
	};

	std::array<block, 8> depth1 = testSuperBlock;
	const std::array<block, 8> desiredDepth1 = {
		block::allSame(0x23), block::allSame(0x03), block::allSame(0xd4), block::allSame(0x2d),
		block::allSame(0x83), block::allSame(0xb9), block::allSame(0x18), block::allSame(0xbb)
	};
	xorReduce<3>(depth1.data(), 1);
	arrayAssertEq(depth1, desiredDepth1);

	std::array<block, 8> depth2 = testSuperBlock;
	const std::array<block, 8> desiredDepth2 = {
		block::allSame(0xf7), block::allSame(0x2e), block::allSame(0xd4), block::allSame(0x2d),
		block::allSame(0x9b), block::allSame(0x02), block::allSame(0x18), block::allSame(0xbb)
	};
	xorReduce<3>(depth2.data(), 2);
	arrayAssertEq(depth2, desiredDepth2);

	std::array<block, 8> depth3 = testSuperBlock;
	const std::array<block, 8> desiredDepth3 = {
		block::allSame(0x6c), block::allSame(0x2c), block::allSame(0xcc), block::allSame(0x9b),
		block::allSame(0x9b), block::allSame(0x02), block::allSame(0x18), block::allSame(0xbb)
	};
	xorReduce<3>(depth3.data(), 3);
	arrayAssertEq(depth3, desiredDepth3);
}

}
}

#endif

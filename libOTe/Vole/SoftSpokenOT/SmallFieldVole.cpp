#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif

#include "SmallFieldVole.h"
#ifdef ENABLE_SOFTSPOKEN_OT

#include <cryptoTools/Common/Matrix.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/Range.h>
#include <cryptoTools/Common/TestCollection.h>
#include <cryptoTools/Crypto/AES.h>
#include <cryptoTools/Crypto/Blake2.h>

//#include <boost/log/core.hpp> // For BOOST_LOG_UNREACHABLE()
//
//#ifdef BOOST_LOG_UNREACHABLE
//#define UNREACHABLE() BOOST_LOG_UNREACHABLE()
//#else
//#define UNREACHABLE()
//#endif

#if defined(__GNUC__) || defined(__clang__)
#       define UNREACHABLE() __builtin_unreachable()
#elif defined(_MSC_VER)
#   define UNREACHABLE() __assume(0)
#else
#	define UNREACHABLE()
#endif



namespace osuCrypto
{

	// Output: v (or w) in inOut[1 ...], and u in inOut[0]. If blocks > 2**depth, this pattern repeats
	// once every 2**depth blocks.
	template<u64 depth, u64 blocks = superBlkSize>
	static OC_FORCEINLINE void xorReduce(block* __restrict inOut, u64 maxDepth)
	{
		assert((blocks & ((1 << depth) - 1)) == 0); // Can't reduce partial trees.

		// Force unroll outer loop using template recursion.
		xorReduce<depth - 1, (depth > 1 ? blocks : 0)>(inOut, maxDepth);

		if (depth <= maxDepth)
		{
			u64 stride = 1 << (depth - 1);
			for (u64 i = 0; i < blocks; i += 2 * stride)
			{
				for (u64 j = 0; j < depth; ++j)
					inOut[i + j] ^= inOut[i + stride + j];
				inOut[i + depth] = inOut[i + stride];
			}
		}
	}

	// Base case
	template<> OC_FORCEINLINE void xorReduce<0, 0>(block* __restrict inOut, u64 maxDepth) {}

	// outU is unused when this is called by the receiver, and a few operations might be saved by not
	// computing it. However, it's just a few XORs, and the compiler will likely optimize it out anyway.
	static OC_FORCEINLINE void xorReducePath(
		u64 fieldBits, u64 fieldSize, u64 superBlk, block(*__restrict path)[superBlkSize],
		block* __restrict outU, block* __restrict outVW, bool isReceiver,
		bool correctionPresent = false)
	{
		// Reduce up the combining tree, continuing for as many nodes just got completed.
		// However, the root is skipped, in case it might have a different size.
		u64 treeDepth = 0;
		for (u64 blkInTree = superBlk; treeDepth < (fieldBits - 1) / superBlkShift
			&& blkInTree % superBlkSize == 0; ++treeDepth)
		{
			blkInTree /= superBlkSize;

			xorReduce<superBlkShift>(path[treeDepth], superBlkShift);

			for (u64 depth = 0; depth < superBlkShift; ++depth)
				outVW[treeDepth * superBlkShift + depth] ^= path[treeDepth][depth + 1];
			path[treeDepth + 1][(blkInTree - 1) % superBlkSize] = path[treeDepth][0];
		}

		// Reduce the root of the combining tree.
		if ((superBlk & (fieldSize - 1)) == 0)
		{
			u64 depthRemaining = 1 + (fieldBits - 1) % superBlkShift;
			xorReduce<superBlkShift>(path[treeDepth], depthRemaining);

			if (correctionPresent)
				for (u64 j = 0; j < depthRemaining; ++j)
					outVW[treeDepth * superBlkShift + j] ^= path[treeDepth][j + 1];
			else
				for (u64 j = 0; j < depthRemaining; ++j)
					outVW[treeDepth * superBlkShift + j] = path[treeDepth][j + 1];
			if (!isReceiver)
				*outU = path[treeDepth][0];
		}

	}

	template<u64 fieldBitsConst>
	OC_FORCEINLINE void generateSenderImpl(
		const SmallFieldVoleSender& This,
		u64 blockIdx, const AES& aes, block* __restrict outU, block* __restrict outV)
	{
		// Allow the compiler to hardcode mFieldBits based on the template parameter.
		const u64 fieldBits = fieldBitsConst > 0 ? fieldBitsConst : This.mFieldBits;
		constexpr u64 fieldBitsMax =
			fieldBitsConst > 0 ? fieldBitsConst : SmallFieldVoleSender::fieldBitsMax;
		const u64 fieldSize = 1 << fieldBits;

		assert(This.mSeeds.size());

		block* __restrict seeds = This.mSeeds.data();
		block blockIdxBlock = toBlock(blockIdx);

		if (fieldBits <= superBlkShift) // >= 1 VOLEs per superblock.
		{
			if (fieldBitsConst == 0)
				UNREACHABLE();

			const u64 volePerSuperBlk = superBlkSize / fieldSize;
			for (u64 nVole = 0; nVole < This.mNumVoles; nVole += volePerSuperBlk)
			{
				// TODO: Try combining the block index into the AES key. It gives the same PRG, but
				// might be faster.
				block input[superBlkSize], hashes[superBlkSize];
				for (u64 i = 0; i < superBlkSize; ++i, ++seeds)
					input[i] = blockIdxBlock ^ *seeds;
				aes.hashBlocks<superBlkSize>(input, hashes);

				xorReduce<superBlkShift>(hashes, fieldBits);
				for (u64 i = 0; i < volePerSuperBlk; ++i, ++outU)
				{
					for (u64 j = 0; j < fieldBits; ++j, ++outV)
					{
						*outV = hashes[i * fieldSize + j + 1];
					}
					*outU = hashes[i * fieldSize];
				}
			}
		}
		else // > 1 super block per VOLE.
		{
			for (u64 nVole = 0; nVole < This.mNumVoles; ++nVole, outV += fieldBits, ++outU)
			{
				block path[divCeil(fieldBitsMax, superBlkShift)][superBlkSize];
				for (u64 i = 0; i < fieldBits; ++i)
					// GCC seems to generate better code with an open coded memset.
					outV[i] = toBlock(0, 0);

#ifdef __GNUC__
#pragma GCC unroll 4
#endif
				for (u64 superBlk = 0; superBlk < fieldSize;)
				{
					block input[superBlkSize];
					for (u64 i = 0; i < superBlkSize; ++i, ++superBlk, ++seeds)
						input[i] = blockIdxBlock ^ *seeds;
					aes.hashBlocks<superBlkSize>(input, path[0]);
					xorReducePath(fieldBits, fieldSize, superBlk, path, outU, outV, false);
				}
			}
		}
	}

	template<u64 fieldBitsConst>
	OC_FORCEINLINE void generateReceiverImpl(
		const SmallFieldVoleReceiver& This,
		u64 blockIdx, const AES& aes,
		block* __restrict outW, const block* __restrict correction) 
	{
		// Allow the compiler to hardcode mFieldBits based on the template parameter.
		const u64 fieldBits = fieldBitsConst > 0 ? fieldBitsConst : This.mFieldBits;
		constexpr u64 fieldBitsMax =
			fieldBitsConst > 0 ? fieldBitsConst : SmallFieldVoleSender::fieldBitsMax;
		const u64 fieldSize = 1 << fieldBits;

		assert(This.mSeeds.size());
		block* __restrict seeds = This.mSeeds.data();
		block blockIdxBlock = toBlock(blockIdx);

		bool correctionPresent = (correction != nullptr);
		const u8* __restrict deltaPtr = This.mDeltaUnpacked.data();

		if (fieldBits <= superBlkShift)
		{
			// >= 1 VOLEs per superblock. This case can only occur for small fieldSize, small enough
			// that this cannot be the variable size implementation (fieldBitsConst != 0).
			if (fieldBitsConst == 0)
				UNREACHABLE();

			// Avoid compilation trouble when this if branch is unreachable.
			constexpr u64 fieldBits_ = std::min(fieldBitsMax, (u64)superBlkShift);

			// This is a trickier case, as we need to decide how many VOLES will fit
			// per super block, and how many AES calls to use. Try to get as close to 8 AES invocations
			// per superblock as possible.
			constexpr u64 aesPerVole = (1 << fieldBits_) - 1;
			constexpr u64 volePerSuperBlk = divNearest(superBlkSize, aesPerVole);
			constexpr u64 aesPerSuperBlk = aesPerVole * volePerSuperBlk;
			constexpr u64 fieldsPerSuperBlk = volePerSuperBlk << fieldBits_;

			for (u64 nVole = 0; nVole < This.mNumVoles; nVole += volePerSuperBlk,
				correction += volePerSuperBlk, deltaPtr += fieldBits * volePerSuperBlk)
			{
				block input[aesPerSuperBlk], hashes[aesPerSuperBlk], xorHashes[fieldsPerSuperBlk];
				for (u64 i = 0; i < aesPerSuperBlk; ++i, ++seeds)
					input[i] = blockIdxBlock ^ *seeds;
				aes.hashBlocks<aesPerSuperBlk>(input, hashes);

				// Intersperse the hashes with zeros, because the zeroth seed for each VOLE is unknown.
				for (u64 i = 0; i < volePerSuperBlk; ++i)
				{
					xorHashes[i * fieldSize] = toBlock(0, 0);
					for (u64 j = 0; j < aesPerVole; ++j)
						xorHashes[i * fieldSize + j + 1] = hashes[i * aesPerVole + j];
				}

				xorReduce<fieldBits_, fieldsPerSuperBlk>(xorHashes, fieldBits);
				if (correctionPresent)
					for (u64 i = 0; i < volePerSuperBlk; ++i)
						for (u64 j = 0; j < fieldBits; ++j, ++outW)
							*outW = xorHashes[i * fieldSize + j + 1] ^
								correction[i] & block::allSame(deltaPtr[i * fieldBits + j]);
				else
					for (u64 i = 0; i < volePerSuperBlk; ++i)
						for (u64 j = 0; j < fieldBits; ++j, ++outW)
							*outW = xorHashes[i * fieldSize + j + 1];
			}
		}
		else
		{
			// > 1 super block per VOLE. Do blocks of 8, or 7 at the start because the zeroth seed in a
			// VOLE is unknown.
			for (u64 nVole = 0; nVole < This.mNumVoles; ++nVole, outW += fieldBits, deltaPtr += fieldBits)
			{
				block path[divCeil(fieldBitsMax, superBlkShift)][superBlkSize];
				if (correctionPresent)
					for (u64 i = 0; i < fieldBits; ++i)
						outW[i] = correction[nVole] & block::allSame(deltaPtr[i]);
				else
					for (u64 i = 0; i < fieldBits; ++i)
						outW[i] = toBlock(0, 0);

				block input0[superBlkSize - 1];
				for (u64 i = 0; i < superBlkSize - 1; ++i, ++seeds)
					input0[i] = blockIdxBlock ^ *seeds;
				aes.hashBlocks<superBlkSize - 1>(input0, &path[0][1]);

				// The zeroth seed is unknown, so set the corresponding path element to zero.
				path[0][0] = toBlock(0, 0);

				u64 superBlk = superBlkSize;
				xorReducePath(fieldBits, fieldSize, superBlk, path, nullptr, outW, true);

#ifdef __GNUC__
#pragma GCC unroll 3
#endif
				while (superBlk < fieldSize)
				{
					block input[superBlkSize];
					for (u64 i = 0; i < superBlkSize; ++i, ++superBlk, ++seeds)
						input[i] = blockIdxBlock ^ *seeds;
					aes.hashBlocks<superBlkSize>(input, path[0]);

					xorReducePath(fieldBits, fieldSize, superBlk, path, nullptr, outW,
						true, correctionPresent);
				}
			}
		}
	}


	// mSeeds must be the OT messages from mNumVoles instances of 2**mFieldBits - 1 of 2**mFieldBits OT,
	// with each OT occupying a contiguous memory range.

	void SmallFieldVoleSender::setSeed(span<const block> seeds_) {
		u64 numSeeds = mNumVoles * fieldSize();
		if ((u64)seeds_.size() != numSeeds)
			throw RTE_LOC;

		assert(mNumVolesPadded >= numSeeds);
		mSeeds.resize(mNumVolesPadded * fieldSize());
		std::copy(seeds_.begin(), seeds_.end(), mSeeds.data());
	}

	u64 computeNumVolesPadded(u64 fieldBits, u64 numVoles)
	{
		u64 volesPadded;
		if (fieldBits <= superBlkShift) // >= 1 VOLEs per superblock.
			volesPadded = roundUpTo(numVoles, divNearest(superBlkSize, (1 << fieldBits) - 1));
		else // > 1 super block per VOLE.
			volesPadded = numVoles;

		// Padding for sharedFunctionXor.
		return std::max<u64>(volesPadded, roundUpTo(numVoles, 4));
	}

	void SmallFieldVoleBase::init(u64 fieldBits_, u64 numVoles_, bool malicious)
	{
		mFieldBits = fieldBits_;
		mNumVoles = numVoles_;
		mMalicious = malicious;
		mInit = true;
		if (mFieldBits < 1 || mFieldBits > fieldBitsMax)
			throw RTE_LOC;
		mNumVolesPadded = (computeNumVolesPadded(fieldBits_, numVoles_));
		mSeeds.resize(0);
	}

	void SmallFieldVoleSender::init(u64 fieldBits_, u64 numVoles_, bool malicious)
	{
		SmallFieldVoleBase::init(fieldBits_, numVoles_, malicious);
		//mNumVolesPadded = (computeNumVolesPadded(fieldBits_, numVoles_));
		mGenerateFn = (selectGenerateImpl(mFieldBits));
		if (!mPprf)
			mPprf.reset(new PprfSender);
	}

	void SmallFieldVoleReceiver::init(u64 fieldBits_, u64 numVoles_, bool malicious)
	{
		SmallFieldVoleBase::init(fieldBits_, numVoles_, malicious);
		mGenerateFn = (selectGenerateImpl(mFieldBits));
		if (!mPprf)
			mPprf.reset(new PprfReceiver);
	}

	void SmallFieldVoleReceiver::setDelta(BitVector delta_)
	{
		if ((u64)delta_.size() != baseOtCount())
			throw RTE_LOC;
		mDelta = std::move(delta_);
		mDeltaUnpacked.resize(wPadded());
		for (u64 i = 0; i < mDelta.size(); ++i)
			mDeltaUnpacked[i] = -(u8)mDelta[i];
	}

	void SmallFieldVoleReceiver::setSeeds(span<const block> seeds_) 
	{
		u64 numSeeds = mNumVoles * (fieldSize() - 1);
		if ((u64)seeds_.size() != numSeeds)
			throw RTE_LOC;

		assert(mNumVolesPadded >= numSeeds);
		mSeeds.resize(mNumVolesPadded * (fieldSize() - 1));
		std::copy(seeds_.begin(), seeds_.end(), mSeeds.data());
	}

	void SmallFieldVoleReceiver::setBaseOts(span<const block> baseMessages, const BitVector& choices)
	{
		setDelta(choices);

		if (!mPprf)
			throw RTE_LOC;

		mPprf->configure(fieldSize(), mNumVoles);

		if (mPprf->mDepth != mFieldBits) // Sanity check: log2ceil.
			throw RTE_LOC;
		if (mPprf->baseOtCount() != baseOtCount()) // Sanity check
			throw RTE_LOC;

		mPprf->setBase(baseMessages);
		mPprf->setChoiceBits(choices);
	}

	void SmallFieldVoleSender::setBaseOts(span<std::array<block, 2>> msgs)
	{

		if (!mPprf)
			throw RTE_LOC;

		mPprf->configure(fieldSize(), mNumVoles);

		if (mPprf->mDepth != mFieldBits) // Sanity check: log2ceil.
			throw RTE_LOC;
		if (mPprf->baseOtCount() != baseOtCount()) // Sanity check
			throw RTE_LOC;


		mPprf->setBase(msgs);
	}

	task<> SmallFieldVoleSender::expand(Socket& chl,PRNG& prng, u64 numThreads)
	{
		MC_BEGIN(task<>, this, &chl, &prng, numThreads,
			corrections = std::vector<std::array<block, 2>>{},
			hashes = std::vector<std::array<block, 2>>{},
			seedView = MatrixView<block>{},
			_ = AlignedUnVector<block>{}
		);

		
		assert(mSeeds.size() == 0  && mNumVoles && mNumVoles <= mNumVolesPadded);
		mSeeds.resize(mNumVolesPadded * fieldSize());
		std::fill(mSeeds.begin(), mSeeds.end(), block(0, 0));
		mSeeds.resize(mNumVoles * fieldSize());

		MC_AWAIT(mPprf->expand(chl, _, prng.get(), mSeeds, PprfOutputFormat::ByTreeIndex, false, 1));
		mSeeds.resize(mNumVolesPadded * fieldSize());
		seedView = MatrixView<block>(mSeeds.data(), mNumVoles, fieldSize());

		// Prove consistency
		if (mMalicious)
		{
			corrections.resize(mNumVoles, { block::allSame(0) });
			hashes.resize(mNumVoles, { block::allSame(0) });
			for (u64 row = 0; row < mNumVoles; ++row)
			{
				Blake2 hasher(2 * sizeof(block));

				for (u64 col = 0; col < fieldSize(); ++col)
				{
					Blake2 prg(3 * sizeof(block));
					std::array<block, 3> prgOut;
					prg.Update(mSeeds[row * fieldSize() + col]);
					prg.Final(prgOut);

					for (int i = 0; i < 2; ++i)
						corrections[row][i] ^= prgOut[i];
					hasher.Update(&prgOut[0], 2);
					mSeeds[row * fieldSize() + col] = prgOut[2];
				}

				// TODO: probably fine to hash together, not separately.
				hasher.Final(hashes[row]);
			}

			MC_AWAIT(chl.send(std::move(corrections)));
			MC_AWAIT(chl.send(std::move(hashes)));
		}

		MC_END();
	}


	task<> SmallFieldVoleReceiver::expand(Socket& chl, PRNG& prng, u64 numThreads)
	{
		MC_BEGIN(task<>, this, &chl, &prng, numThreads, 
			seeds = AlignedUnVector<block>{},
			seedsFull = MatrixView<block>{},
			totals = std::vector<std::array<block, 2>>{},
			entryHashes = std::vector<std::array<block, 2>>{},
			corrections = std::vector<std::array<block, 2>>{},
			hashes = std::vector<std::array<block, 2>>{},
			seedMatrix = (block*)nullptr
		);

		assert(mSeeds.size() == 0 && mNumVoles && mNumVoles <= mNumVolesPadded);
		mSeeds.resize(mNumVolesPadded * (fieldSize() - 1));
		std::fill(mSeeds.begin(), mSeeds.end(), block(0, 0));

		seeds.resize(mNumVoles * fieldSize());
		MC_AWAIT(mPprf->expand(chl, seeds, PprfOutputFormat::ByTreeIndex, false, 1));
		seedsFull = MatrixView<block>(seeds.data(), mNumVoles, fieldSize());

		// Check consistency
		if (mMalicious)
		{
			totals.resize(mNumVoles, { block::allSame(0) });
			entryHashes.resize(mNumVoles * fieldSize(), { block::allSame(0) });
			seedMatrix = seedsFull.data();
			for (u64 row = 0; row < mNumVoles; ++row)
			{

				for (u64 col = 0; col < fieldSize(); ++col)
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

			corrections.resize(mNumVoles, { block::allSame(0) });
			hashes.resize(mNumVoles, { block::allSame(0) });
			MC_AWAIT(chl.recv(corrections));
			MC_AWAIT(chl.recv(hashes));

			{
				bool eq = true;
				for (u64 row = 0; row < mNumVoles; ++row)
				{
					for (int i = 0; i < 2; ++i)
						corrections[row][i] ^= totals[row][i];

					u64 rowDelta = 0;
					for (u64 bit = 0; bit < mFieldBits; ++bit)
						rowDelta |= (u64)mDelta[row * mFieldBits + bit] << bit;

					for (u64 col = 0; col < fieldSize(); ++col)
					{
						block isUnknownSeed = block::allSame(col == rowDelta);
						for (int i = 0; i < 2; ++i)
							entryHashes[row * fieldSize() + col][i] ^= isUnknownSeed & corrections[row][i];
					}

					Blake2 hasher(2 * sizeof(block));
					std::array<block, 2> hash;
					for (u64 col = 0; col < fieldSize(); ++col)
						hasher.Update(entryHashes[row * fieldSize() + col]);
					hasher.Final(hash);

					for (int i = 0; i < 2; ++i)
						eq &= (hash[i] == hashes[row][i]);
				}

				// TODO: Should delay abort until the VOLE consistency check, to stop the two events from
				// being distinguished.
				if (!eq)
					throw std::runtime_error("PPRF failed consistency check.");
			}
		}
		{

			// Reorder mSeeds to handle the (Delta ^) part, moving the unknown mSeeds to column 0. This
			// effectively makes it compute w = sum_x (Delta ^ x) * r_x instead of v = sum_x x * r_x.
			// TODO: Might be best to do this as part of going down the pprf tree. There, it would cost
			// O(mNumVoles * fieldSize) time, rather than O(mNumVoles * fieldSize * mFieldBits).
			for (u64 i = 0; i < mFieldBits; ++i)
			{
				u64 dMask = (u64)1 << i;
				block* matrix = seedsFull.data();
				// Bit hack to iterate over all values that are have a 0 in position i (from Hacker's
				// Delight).
				for (u64 col = 0; col < fieldSize(); col = (col + dMask + 1) & ~dMask)
					for (u64 row = 0; row < mNumVoles; ++row)
						cswapBytes(
							matrix[row * fieldSize() + col],
							matrix[row * fieldSize() + col + dMask],
							mDeltaUnpacked[row * mFieldBits + i]);
			}

			// Remove the unknown mSeeds so that generate doesn't have to skip over them.
			MatrixView<block> seedView(mSeeds.data(), mNumVoles, fieldSize() - 1);
			for (u64 row = 0; row < mNumVoles; ++row)
			{
				auto src = seedsFull[row].subspan(1);
				std::copy(src.begin(), src.end(), seedView[row].begin());
			}
		}

		MC_END();
	}

	// TODO: Malicious version. Should use an actual hash function for bottom layer of tree.

	SmallFieldVoleSender::GenerateFn
		SmallFieldVoleSender::selectGenerateImpl(u64 fieldBits)
	{
		static const GenerateFn table[] = {
			generateSenderImpl<1>,
			generateSenderImpl<2>,
			generateSenderImpl<3>,
			generateSenderImpl<4>,
			generateSenderImpl<5>,
			generateSenderImpl<6>,
			generateSenderImpl<7>,
			generateSenderImpl<8>,
			generateSenderImpl<9>,
			generateSenderImpl<10>
		};
		if (fieldBits <= sizeof(table) / sizeof(table[0]))
			return table[fieldBits - 1];
		else
			return generateSenderImpl<0>;
	}

	SmallFieldVoleReceiver::GenerateFn
		SmallFieldVoleReceiver::selectGenerateImpl(u64 fieldBits)
	{
		static const GenerateFn table[] = {
			generateReceiverImpl<1>,
			generateReceiverImpl<2>,
			generateReceiverImpl<3>,
			generateReceiverImpl<4>,
			generateReceiverImpl<5>,
			generateReceiverImpl<6>,
			generateReceiverImpl<7>,
			generateReceiverImpl<8>,
			generateReceiverImpl<9>,
			generateReceiverImpl<10>
		};
		if (fieldBits <= sizeof(table) / sizeof(table[0]))
			return table[fieldBits - 1];
		else
			return generateReceiverImpl<0>;
	}


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

#endif

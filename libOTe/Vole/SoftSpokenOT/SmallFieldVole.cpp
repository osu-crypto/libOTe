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


#if defined(OC_ENABLE_VAES) && defined(__AVX512F__) && defined(__VAES__)
	// Each ZMM holds the four 128-bit hashes for one two-bit VOLE.
	static OC_FORCEINLINE __m512i storeTwoBitV(const __m512i a, const __m512i b, block* outV)
	{
		// For each VOLE, v[0] = h1 ^ h3 and v[1] = h2 ^ h3.
		const auto middle = _mm512_shuffle_i32x4(a, b, _MM_SHUFFLE(2, 1, 2, 1));
		const auto last = _mm512_shuffle_i32x4(a, b, _MM_SHUFFLE(3, 3, 3, 3));
		_mm512_storeu_si512(outV, _mm512_xor_si512(middle, last));

		// Keep h0 ^ h1 and h2 ^ h3 for the final reduction to u.
		const auto even = _mm512_shuffle_i32x4(a, b, _MM_SHUFFLE(2, 0, 2, 0));
		const auto odd = _mm512_shuffle_i32x4(a, b, _MM_SHUFFLE(3, 1, 3, 1));
		return _mm512_xor_si512(even, odd);
	}

	// All two-bit outputs XOR an even number of Davies-Meyer hashes. The
	// common final-round key and index cancel. AESENCLAST folds in each seed.
	template<unsigned stride, unsigned lanes>
	static OC_FORCEINLINE void hashTwoBitSeeds(const block* seeds, block index,
		const AES& aes, __m512i (&state)[lanes])
	{
		static_assert(stride == 3 || stride == 4);
		const auto tweak = _mm512_broadcast_i32x4(index.mData);
		const auto first = _mm512_xor_si512(tweak, _mm512_broadcast_i32x4(aes.mRoundKey[0].mData));
		__m512i raw[lanes];
#pragma GCC unroll 9
		for (unsigned i = 0; i < lanes; ++i)
		{
			if constexpr (stride == 4)
				raw[i] = _mm512_loadu_si512(seeds + 4 * i);
			else
				raw[i] = _mm512_maskz_loadu_epi64(0x3f, seeds + 3 * i);
			state[i] = _mm512_xor_si512(raw[i], first);
		}
#pragma GCC unroll 9
		for (unsigned round = 1; round < 10; ++round)
		{
			const auto key = _mm512_broadcast_i32x4(aes.mRoundKey[round].mData);
#pragma GCC unroll 9
			for (unsigned i = 0; i < lanes; ++i)
				state[i] = _mm512_aesenc_epi128(state[i], key);
		}
#pragma GCC unroll 9
		for (unsigned i = 0; i < lanes; ++i)
			state[i] = _mm512_aesenclast_epi128(state[i], raw[i]);
	}

	static OC_FORCEINLINE void generateEightTwoBitSenders(
		const block* seeds, block index, const AES& aes, block* outU, block* outV)
	{
		__m512i state[8];
		hashTwoBitSeeds<4>(seeds, index, aes, state);
#pragma GCC unroll 2
		for (unsigned i = 0; i < 8; i += 4)
		{
			const auto ab = storeTwoBitV(state[i], state[i + 1], outV + 2 * i);
			const auto cd = storeTwoBitV(state[i + 2], state[i + 3], outV + 2 * i + 4);
			const auto even = _mm512_shuffle_i32x4(ab, cd, _MM_SHUFFLE(2, 0, 2, 0));
			const auto odd = _mm512_shuffle_i32x4(ab, cd, _MM_SHUFFLE(3, 1, 3, 1));
			_mm512_storeu_si512(outU + i, _mm512_xor_si512(even, odd));
		}
	}
#elif defined(OC_ENABLE_VAES) && defined(__AVX2__) && defined(__VAES__)
	// Two seeds per YMM. The common last-round key and index cancel in
	// the even-weight reductions, just as they do in the 512-bit kernel.
	template<unsigned lanes>
	static OC_FORCEINLINE void hashTwoBitSeeds256(const block* seeds, block index,
		const AES& aes, __m256i (&state)[lanes])
	{
		const auto first = _mm256_broadcastsi128_si256((index ^ aes.mRoundKey[0]).mData);
		__m256i raw[lanes];
		for (unsigned i = 0; i < lanes; ++i)
		{
			raw[i] = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(seeds + 2 * i));
			state[i] = _mm256_xor_si256(raw[i], first);
		}
#pragma GCC unroll 9
		for (unsigned round = 1; round < 10; ++round)
		{
			const auto key = _mm256_broadcastsi128_si256(aes.mRoundKey[round].mData);
			for (auto& v : state)
				v = _mm256_aesenc_epi128(v, key);
		}
		for (unsigned i = 0; i < lanes; ++i)
			state[i] = _mm256_aesenclast_epi128(state[i], raw[i]);
	}

	static OC_FORCEINLINE void generateFourTwoBitSenders(
		const block* seeds, block index, const AES& aes, block* outU, block* outV)
	{
		__m256i state[8];
		hashTwoBitSeeds256(seeds, index, aes, state);
		for (unsigned i = 0; i < 4; i += 2)
		{
			__m256i partial[2];
			for (unsigned j = 0; j < 2; ++j)
			{
				const auto a = state[2 * (i + j)], b = state[2 * (i + j) + 1];
				const auto middle = _mm256_permute2x128_si256(a, b, 0x21);
				const auto last = _mm256_permute2x128_si256(b, b, 0x11);
				_mm256_storeu_si256(reinterpret_cast<__m256i*>(outV + 2 * (i + j)), _mm256_xor_si256(middle, last));
				partial[j] = _mm256_xor_si256(a, b);
			}
			const auto even = _mm256_permute2x128_si256(partial[0], partial[1], 0x20);
			const auto odd = _mm256_permute2x128_si256(partial[0], partial[1], 0x31);
			_mm256_storeu_si256(reinterpret_cast<__m256i*>(outU + i), _mm256_xor_si256(even, odd));
		}
	}
#endif

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
			u64 nVole = 0;
#if defined(OC_ENABLE_VAES) && defined(__AVX512F__) && defined(__VAES__)
			if constexpr (fieldBitsConst == 2)
			{
				for (; nVole + 8 <= This.mNumVoles; nVole += 8, seeds += 32, outU += 8, outV += 16)
					generateEightTwoBitSenders(seeds, blockIdxBlock, aes, outU, outV);
			}
#elif defined(OC_ENABLE_VAES) && defined(__AVX2__) && defined(__VAES__)
			if constexpr (fieldBitsConst == 2)
			{
				for (; This.mNumVoles - nVole >= 4; nVole += 4, seeds += 16, outU += 4, outV += 8)
					generateFourTwoBitSenders(seeds, blockIdxBlock, aes, outU, outV);
			}
#endif
			for (; nVole < This.mNumVoles; nVole += volePerSuperBlk)
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

#if defined(OC_ENABLE_VAES) && defined(__AVX512F__) && defined(__VAES__)
	// Three registers hold the seed triples of four consecutive VOLEs:
	// [a0 a1 a2 b0], [b1 b2 c0 c1], [c2 d0 d1 d2].
	template<bool corrected>
	static OC_FORCEINLINE void storeFourTwoBitW(__m512i x, __m512i y, __m512i z,
		const u8* delta, const block* correction, block* out)
	{
		const auto ab = _mm512_permutex2var_epi64(x, _mm512_setr_epi64(0, 1, 2, 3, 6, 7, 8, 9), y);
		const auto cd = _mm512_shuffle_i32x4(y, z, _MM_SHUFFLE(2, 1, 3, 2));
		auto wAB = _mm512_xor_si512(ab, _mm512_shuffle_i32x4(x, y, _MM_SHUFFLE(1, 1, 2, 2)));
		auto wCD = _mm512_xor_si512(cd, _mm512_shuffle_i32x4(z, z, _MM_SHUFFLE(3, 3, 0, 0)));
		if constexpr (corrected)
		{
			// Each delta bit selects both 64-bit halves of one output block.
			const auto bytes = _mm_loadl_epi64(reinterpret_cast<const __m128i*>(delta));
			const unsigned mask = _mm_movemask_epi8(_mm_unpacklo_epi8(bytes, bytes));
			const auto c = _mm512_loadu_si512(correction);
			wAB = _mm512_mask_xor_epi64(wAB, __mmask8(mask), wAB,
				_mm512_shuffle_i32x4(c, c, _MM_SHUFFLE(1, 1, 0, 0)));
			wCD = _mm512_mask_xor_epi64(wCD, __mmask8(mask >> 8), wCD,
				_mm512_shuffle_i32x4(c, c, _MM_SHUFFLE(3, 3, 2, 2)));
		}
		_mm512_storeu_si512(out, wAB);
		_mm512_storeu_si512(out + 4, wCD);
	}

	template<bool corrected>
	static OC_FORCEINLINE void generateTwelveTwoBitReceivers(const block* seeds, block index,
		const AES& aes, const u8* delta, const block* correction, block* out)
	{
		__m512i state[9];
		hashTwoBitSeeds<4>(seeds, index, aes, state);
#pragma GCC unroll 3
		for (unsigned i = 0; i < 3; ++i)
			storeFourTwoBitW<corrected>(state[3 * i], state[3 * i + 1], state[3 * i + 2],
				corrected ? delta + 8 * i : nullptr, corrected ? correction + 4 * i : nullptr, out + 8 * i);
	}

	// The existing receiver generates complete groups of three, including its
	// final padded outputs. Load exactly three seeds per VOLE in the remainder.
	static OC_FORCEINLINE void generateThreeTwoBitReceivers(const block* seeds, block index,
		const AES& aes, const u8* delta, const block* correction, block* out)
	{
		__m512i state[3];
		hashTwoBitSeeds<3>(seeds, index, aes, state);
#pragma GCC unroll 3
		for (unsigned i = 0; i < 3; ++i)
		{
			const auto h2 = _mm512_shuffle_i32x4(state[i], state[i], _MM_SHUFFLE(2, 2, 2, 2));
			auto w = _mm512_castsi512_si256(_mm512_xor_si512(state[i], h2));
			if (correction)
			{
				const auto masks = _mm256_set_m128i(_mm_set1_epi8(delta[2 * i + 1]), _mm_set1_epi8(delta[2 * i]));
				const auto c = _mm256_broadcastsi128_si256(correction[i].mData);
				w = _mm256_xor_si256(w, _mm256_and_si256(masks, c));
			}
			_mm256_storeu_si256(reinterpret_cast<__m256i*>(out + 2 * i), w);
		}
	}
#endif

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

			u64 nVole = 0;
#if defined(OC_ENABLE_VAES) && defined(__AVX512F__) && defined(__VAES__)
			if constexpr (fieldBitsConst == 2)
			{
				for (; nVole + 12 <= This.mNumVoles; nVole += 12, seeds += 36, outW += 24)
				{
					if (correctionPresent)
					{
						generateTwelveTwoBitReceivers<true>(seeds, blockIdxBlock, aes, deltaPtr, correction, outW);
						correction += 12;
						deltaPtr += 24;
					}
					else
						generateTwelveTwoBitReceivers<false>(seeds, blockIdxBlock, aes, deltaPtr, nullptr, outW);
				}
				for (; nVole < This.mNumVoles; nVole += 3, seeds += 9, outW += 6)
				{
					generateThreeTwoBitReceivers(seeds, blockIdxBlock, aes, deltaPtr, correction, outW);
					if (correctionPresent)
					{
						correction += 3;
						deltaPtr += 6;
					}
				}
				return;
			}
#endif
			for (; nVole < This.mNumVoles; nVole += volePerSuperBlk)
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

				if (correctionPresent)
				{
					correction += volePerSuperBlk;
					deltaPtr += fieldBits * volePerSuperBlk;
				}
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

		assert(mNumVoles <= mNumVolesPadded);
		mSeeds.resize(mNumVolesPadded * fieldSize());
		std::copy(seeds_.begin(), seeds_.end(), mSeeds.data());
	}

	u64 computeNumVolesPadded(u64 fieldBits, u64 numVoles)
	{
		u64 volesPadded;
		if (fieldBits <= superBlkShift) // >= 1 VOLEs per superblock.
			volesPadded = roundUpTo(numVoles, divNearest(superBlkSize, (1ull << fieldBits) - 1));
		else // > 1 super block per VOLE.
			volesPadded = numVoles;

		// Padding for sharedFunctionXor.
		return std::max<u64>(volesPadded, roundUpTo(numVoles, 4));
	}

	void SmallFieldVoleBase::init(u64 fieldBits_, u64 numVoles_, bool malicious)
	{
		baseOtCount(fieldBits_, numVoles_);
		const auto fieldSize = 1ull << fieldBits_;
		const auto numVolesPadded = computeNumVolesPadded(fieldBits_, numVoles_);
		if (numVolesPadded > seedCountMax / fieldSize)
			throw std::invalid_argument("SmallField VOLE seed count exceeds the supported range. " LOCATION);

		mFieldBits = fieldBits_;
		mNumVoles = numVoles_;
		mNumVolesPadded = numVolesPadded;
		mMalicious = malicious;
		mSeeds.clear();
		mInit = true;
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
		mConsistencyFailed = false;
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
		std::fill(mDeltaUnpacked.begin() + mDelta.size(), mDeltaUnpacked.end(), u8{0});
	}

	void SmallFieldVoleReceiver::setSeeds(span<const block> seeds_) 
	{
		u64 numSeeds = mNumVoles * (fieldSize() - 1);
		if ((u64)seeds_.size() != numSeeds)
			throw RTE_LOC;

		assert(mNumVoles <= mNumVolesPadded);
		mSeeds.resize(mNumVolesPadded * (fieldSize() - 1));
		std::copy(seeds_.begin(), seeds_.end(), mSeeds.data());
		// Packed generation reads complete seed groups, including a partial final group.
		if (mFieldBits <= superBlkShift)
			std::fill(mSeeds.begin() + numSeeds, mSeeds.end(), ZeroBlock);
		mConsistencyFailed = false;
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
		if (!mInit || !mPprf || !mNumVoles || mNumVoles > mNumVolesPadded ||
			!mSeeds.empty() || !mPprf->hasBaseOts())
			throw std::logic_error("SmallField VOLE sender is not ready to expand. " LOCATION);

		MACORO_TRY{
		auto corrections = std::vector<std::array<block, 2>>{};
			auto hashes = std::vector<std::array<block, 2>>{};
			auto seedView = MatrixView<block>{};
			auto _ = AlignedUnVector<block>{};

		
		assert(mSeeds.size() == 0  && mNumVoles && mNumVoles <= mNumVolesPadded);
		mSeeds.resize(mNumVolesPadded * fieldSize());
		std::fill(mSeeds.begin(), mSeeds.end(), block(0, 0));
		mSeeds.resize(mNumVoles * fieldSize());

		co_await (mPprf->expand(chl, _, prng.get(), mSeeds, PprfOutputFormat::ByTreeIndex, false, 1));
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

			co_await (chl.send(std::move(corrections)));
			co_await (chl.send(std::move(hashes)));
		}

	} MACORO_CATCH(eptr) {
		clearSeed();
		if (!chl.closed()) co_await chl.close();
		std::rethrow_exception(eptr);
	}
	}


	task<> SmallFieldVoleReceiver::expand(
		Socket& chl, PRNG& prng, u64 numThreads, bool deferConsistencyFailure)
	{
		if (!mInit || !mPprf || !mNumVoles || mNumVoles > mNumVolesPadded ||
			!mSeeds.empty() || !mPprf->hasBaseOts())
			throw std::logic_error("SmallField VOLE receiver is not ready to expand. " LOCATION);

		MACORO_TRY{
		auto seeds = AlignedUnVector<block>{};
			auto seedsFull = MatrixView<block>{};
			auto totals = std::vector<std::array<block, 2>>{};
			auto entryHashes = std::vector<std::array<block, 2>>{};
			auto corrections = std::vector<std::array<block, 2>>{};
			auto hashes = std::vector<std::array<block, 2>>{};
			auto seedMatrix = (block*)nullptr;

		assert(mSeeds.size() == 0 && mNumVoles && mNumVoles <= mNumVolesPadded);
		mConsistencyFailed = false;
		mSeeds.resize(mNumVolesPadded * (fieldSize() - 1));
		std::fill(mSeeds.begin(), mSeeds.end(), block(0, 0));

		seeds.resize(mNumVoles * fieldSize());
		co_await (mPprf->expand(chl, seeds, PprfOutputFormat::ByTreeIndex, false, 1));
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
			co_await (chl.recv(corrections));
			co_await (chl.recv(hashes));

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

				mConsistencyFailed = !eq;
				if (mConsistencyFailed && !deferConsistencyFailure)
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

		} MACORO_CATCH(eptr) {
			clearSeed();
			if (!chl.closed()) co_await chl.close();
			std::rethrow_exception(eptr);
		}
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

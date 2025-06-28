#pragma once
#include "BaseCode.h"
#include "BlkAccCode.h"
#include "Permutation.h"
#include "Accumulator.h"
#include "BlockDiagonal.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Common/Aligned.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "libOTe/Tools/CoeffCtx.h"

namespace osuCrypto
{

	/**
	 * @brief Block Accumulator Code implementation with high minimum distance.
	 * see "Block-Diagonal Codes: Accelerated Linear Codes for Pseudorandom Correlation Generators"
	 *
	 * This class implements a block accumulator code that performs:
	 * 1. Accumulate
	 * 2. Permute
	 * 3. (repeated depth-1 times)
	 * 4. Systematic block diagonal compression
	 *
	 * The code maps from a codeword of size codeSize to a message of size messageSize .
	 * The systematic block diagonal step compresses while the other operations map
	 * codeSize vector to codeSize vector.
	 */
	struct BlkAccCode// : BaseCode<T>
	{

		u64 mK = 0;  // Size of output (message size)
		u64 mN = 0;  // Size of input (code size)

		// Seeds for randomness
		block mSeed = ZeroBlock;

		// Depth parameter for accumulation-permutation steps
		u64 mDepth = 0;

		// blockSize Size of processing blocks (default 8)
		u64 mBlockSize = 0;

		/**
		 * @brief Initialize the block accumulator code
		 *
		 * @param msgSize Size of the output message
		 * @param codeSize Size of the input codeword
		 * @param blockSize Size of processing blocks (default 8)
		 * @param depth Depth parameter for accumulation (default 3)
		 */
		void init(
			u64 msgSize,
			u64 codeSize,
			u64 blockSize = 8,
			u64 depth = 3,
			block seed = block(239478123692759237ull, 256237497312390762ull))
		{
			if (codeSize < msgSize)
				throw RTE_LOC;

			if (depth < 3)
				throw RTE_LOC; // Depth must be at least 3 for linear distance.

			mN = codeSize;
			mK = msgSize;
			mBlockSize = blockSize;
			mDepth = depth;
			mSeed = seed;
		}

		/**
		 * @brief Apply the block accumulator code to the input data
		 *
		 * Performs the sequence: accumulate, permute, accumulate, permute, ...
		 * (repeated depth-1 times), then applies systematic block diagonal compression.
		 *
		 * @param input Input message
		 * @param output Output codeword
		 */
		template<typename F, typename CoeffCtx>
		void dualEncode(auto iter, CoeffCtx ctx) 
		{

			// Initialize the output with the input data (systematic part) and zero-pad
			typename CoeffCtx::template Vec<F> temp;
			ctx.resize(temp, mN);

			//auto print = [&](auto iter, auto end) {
			//	std::stringstream ss;
			//	while(iter != end)
			//		ss << ctx.str(*iter++) << " ";
			//	return ss.str();
			//	};
			//std::cout << print(iter, iter + mN) << std::endl;;

			auto round = [&](auto inputIter, auto outputIter, auto seed){
				// Create the appropriate permutation type based on whether codeSize is power of 2
				if (isPowerOfTwo(mN)) {
					// For power of 2 sizes, use Feistel2KPerm
					Accumulator<Feistel2KPerm> accumPerm(mN, Feistel2KPerm(mN, seed));

					// Apply the accumulate-permute operation
					accumPerm.template dualEncode<F>(
						ctx.template restrictPtr<F>(inputIter), 
						ctx.template restrictPtr<F>(outputIter), 
						ctx);
				}
				else {
					// For non-power of 2 sizes, use FeistelPerm
					Accumulator<FeistelPerm> accumPerm(mN, FeistelPerm(mN, seed));

					// Apply the accumulate-permute operation
					accumPerm.template dualEncode<F>(inputIter, outputIter, ctx);
				}

				//std::cout << print(outputIter, outputIter + mN) << std::endl;;
				};

			// Apply the accumulate-permute pattern (mDepth - 1) times
			for (u64 i = 0; i < mDepth - 1; ++i) {
				block seed = subseed(i);
				if ((i & 1) == 0)
					round(ctx.template restrictPtr<F>(iter), ctx.template restrictPtr<F>(temp.data()), seed);
				else
					round(ctx.template restrictPtr<F>(temp.data()), ctx.template restrictPtr<F>(iter), seed);
			}


			block seed = subseed(mDepth-1);
			BlockDiagonal bd(mK, mN, mBlockSize, seed);

			if (mDepth & 1)
				bd.template dualEncode<F>(ctx.template restrictPtr<F>(iter), ctx);
			else
			{
				bd.template dualEncode<F>(ctx.template restrictPtr<F>(temp.data()), ctx);
				ctx.copy(ctx.template restrictPtr<F>(temp.data()), ctx.template restrictPtr<F>(temp.data() + mK), ctx.template restrictPtr<F>(iter));
			}

			//std::cout<<print(iter, iter + mK) << std::endl;

		}
		


		//void dualEncodeBlk(block* iter)
		//{

		//	// Initialize the output with the input data (systematic part) and zero-pad
		//	AlignedUnVector<block> temp(mN);
		//	auto ctx = CoeffCtxGF2{};
		//	//auto print = [&](auto iter, auto end) {
		//	//	std::stringstream ss;
		//	//	while(iter != end)
		//	//		ss << ctx.str(*iter++) << " ";
		//	//	return ss.str();
		//	//	};
		//	//std::cout << print(iter, iter + mN) << std::endl;;

		//	auto round = [&](auto inputIter, auto outputIter, auto seed) {
		//		// Create the appropriate permutation type based on whether codeSize is power of 2
		//		if (isPowerOfTwo(mN)) {
		//			// For power of 2 sizes, use Feistel2KPerm
		//			Accumulator<Feistel2KPerm> accumPerm(mN, Feistel2KPerm(mN, seed));

		//			// Apply the accumulate-permute operation
		//			accumPerm.dualEncodeBlk(
		//				(block*__restrict)inputIter,
		//				(block*__restrict)outputIter);
		//		}
		//		else {
		//			// For non-power of 2 sizes, use FeistelPerm
		//			Accumulator<FeistelPerm> accumPerm(mN, FeistelPerm(mN, seed));

		//			// Apply the accumulate-permute operation
		//			accumPerm.dualEncodeBlk(inputIter, outputIter);
		//		}

		//		//std::cout << print(outputIter, outputIter + mN) << std::endl;;
		//		};

		//	// Apply the accumulate-permute pattern (mDepth - 1) times
		//	for (u64 i = 0; i < mDepth - 1; ++i) {
		//		block seed = subseed(i);
		//		if ((i & 1) == 0)
		//			round(iter, temp.data(), seed);
		//		else
		//			round(temp.data(), iter, seed);
		//	}


		//	block seed = subseed(mDepth - 1);
		//	BlockDiagonal bd(mK, mN, mBlockSize, seed);

		//	if (mDepth & 1)
		//		bd.dualEncode<block>(iter, ctx);
		//	else
		//	{
		//		bd.dualEncode<block>(temp.data(), ctx);
		//		ctx.copy(temp.data(), temp.data() + mK, iter);
		//	}

		//	//std::cout<<print(iter, iter + mK) << std::endl;

		//}

		//void dualEncodeSqrt(block* iter)
		//{

		//	// Initialize the output with the input data (systematic part) and zero-pad
		//	AlignedUnVector<block> temp(mN);
		//	auto ctx = CoeffCtxGF2{};
		//	//auto print = [&](auto iter, auto end) {
		//	//	std::stringstream ss;
		//	//	while(iter != end)
		//	//		ss << ctx.str(*iter++) << " ";
		//	//	return ss.str();
		//	//	};
		//	//std::cout << print(iter, iter + mN) << std::endl;;

		//	auto round = [&](auto inputIter, auto outputIter, auto seed) {
		//		// Create the appropriate permutation type based on whether codeSize is power of 2
		//		if (isPowerOfTwo(mN)) {
		//			// For power of 2 sizes, use Feistel2KPerm
		//			Accumulator<Feistel2KPerm> accumPerm(mN, Feistel2KPerm(mN, seed));

		//			// Apply the accumulate-permute operation
		//			accumPerm.dualEncodeBlk(
		//				(block * __restrict)inputIter,
		//				(block * __restrict)outputIter);
		//		}
		//		else {
		//			// For non-power of 2 sizes, use FeistelPerm
		//			Accumulator<FeistelPerm> accumPerm(mN, FeistelPerm(mN, seed));

		//			// Apply the accumulate-permute operation
		//			accumPerm.dualEncodeBlk(inputIter, outputIter);
		//		}

		//		//std::cout << print(outputIter, outputIter + mN) << std::endl;;
		//		};

		//	// Apply the accumulate-permute pattern (mDepth - 1) times
		//	for (u64 i = 0; i < mDepth - 1; ++i) {
		//		block seed = subseed(i);
		//		if ((i & 1) == 0)
		//			round(iter, temp.data(), seed);
		//		else
		//			round(temp.data(), iter, seed);
		//	}


		//	block seed = subseed(mDepth - 1);
		//	BlockDiagonal bd(mK, mN, mBlockSize, seed);

		//	if (mDepth & 1)
		//		bd.dualEncode<block>(iter, ctx);
		//	else
		//	{
		//		bd.dualEncode<block>(temp.data(), ctx);
		//		ctx.copy(temp.data(), temp.data() + mK, iter);
		//	}

		//	//std::cout<<print(iter, iter + mK) << std::endl;

		//}




		/**
		 * @brief Apply the block accumulator code to the input data
		 *
		 * Performs the sequence: accumulate, permute, accumulate, permute, ...
		 * (repeated depth-1 times), then applies systematic block diagonal compression.
		 *
		 * @param input Input message
		 * @param output Output codeword
		 */
		template<typename F, typename G, typename CoeffCtx>
		void dualEncode2(auto iter0, auto iter1, CoeffCtx ctx)
		{
			dualEncode<F>(iter0, ctx);
			dualEncode<G>(iter1, ctx);
		}

		bool isPowerOfTwo(u64 n)
		{
			return (n != 0) && ((n & (n - 1)) == 0);
		}


		block subseed(u64 i)
		{
			return mAesFixedKey.hashBlock(mSeed ^ block(i, 0));
		}
	};

}
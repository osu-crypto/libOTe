#pragma once
#include <numeric>
#include "BaseCode.h"
#include <algorithm>
#include "cryptoTools/Common/Aligned.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "Permutation.h"
#include "libOTe/Tools/LDPC/Mtx.h"

namespace osuCrypto
{

	/**
	 * @brief Checks if a type has a chunkSize static member
	 *
	 * This type trait is used to determine if the permutation type supports
	 * chunk-based processing for better performance.
	 */
	template<typename T, typename = void>
	struct HasChunkSize : std::false_type {};

	template<typename T>
	struct HasChunkSize<T, std::void_t<decltype(T::chunkSize)>> : std::true_type {};

	/**
	 * @brief A class that combines accumulation and permutation operations
	 *
	 * The Accumulator class implements a linear code component that performs two operations:
	 * 1. Accumulation: compute the prefix sum of input elements using the provided context operations
	 * 2. Permutation: Elements are reordered according to the permutation
	 *
	 * This combined operation has good mixing properties and helps create codes with
	 * high minimum distance. It's used as a building block in the BlkAccCode.
	 *
	 * @tparam Perm The permutation type to use (e.g., Feistel2KPerm or FeistelPerm)
	 */
	template<typename Perm>
	struct Accumulator
	{
		u64 mN = 0; // Size of input (also size of output in this case)

		/**
		 * @brief The permutation instance used to reorder elements
		 *
		 * After accumulation, elements are permuted using this instance.
		 * For exmaple, Feistel2KPerm or FeistelPerm.
		 */
		Perm mPerm;

		/**
		 * @brief Constructs an Accumulator with the given size and permutation
		 *
		 * @param n Size of both input and output vectors
		 * @param perm Permutation instance (default constructs if not provided)
		 */
		explicit Accumulator(u64 n, Perm perm = {})
			: mN(n)
			, mPerm(std::move(perm))
		{
		}


		/**
		 * @brief Apply the accumulate-permute operation to input data
		 *
		 * This performs two steps:
		 * 1. Progressive accumulation: each element i is XORed into elements i+1, i+2, etc.
		 * 2. Permutation: the accumulated values are permuted using the specified permutation
		 *
		 * The function has two implementations based on whether the permutation supports
		 * chunk-based processing for better performance.
		 *
		 * @param in Input data
		 * @param out Output data (must be distinct from input)
		 */
		template<typename F, typename InIter, typename OutIter, typename CoeffCtx>
		void dualEncode(InIter inIter, OutIter outIter, CoeffCtx ctx)
		{
			mPerm.init(mN);

			if constexpr (HasChunkSize<Perm>::value == false)
			{

				auto n = mN;
				//const T* __restrict inIter = in.data();
				auto permIter = mPerm.begin(outIter);
				typename CoeffCtx::template Vec<F> sum;
				ctx.resize(sum, 1);
				ctx.zero(sum[0]);
				for (std::size_t i = 0; i < n; ++i)
				{
					ctx.plus(sum[0], sum[0], *inIter);
					ctx.copy(*permIter, sum[0]);
					++permIter;
					++inIter;
				}
			}
			else
			{
				constexpr u32 chunkSize = Perm::chunkSize;

				typename CoeffCtx::template Vec<F> chunk;
				ctx.resize(chunk, chunkSize + 1);
				auto&& sum = chunk[chunkSize];
				ctx.zero(chunk.begin(), chunk.end());

				auto n = mN;
				auto permIter = mPerm.begin(outIter);
				if (n % chunkSize)
					throw RTE_LOC;
				auto main = n / chunkSize;

				for (std::size_t i = 0; i < main; ++i)
				{
					for (u64 j = 0; j < chunkSize; ++j)
					{
						//sum ^= *inIter;
						//chunk[j] = sum;
						ctx.plus(sum, sum, *inIter);
						ctx.copy(chunk[j], sum);
						++inIter;
					}
					mPerm.chunk(permIter, chunk.data());
				}
			}
		}


		//void dualEncodeBlk(block* __restrict inIter, block* __restrict outIter)
		//{
		//	mPerm.init(mN);

		//	if constexpr (HasChunkSize<Perm>::value == false)
		//	{

		//		auto n = mN;
		//		//const T* __restrict inIter = in.data();
		//		auto permIter = mPerm.begin(outIter);
		//		block sum = ZeroBlock;
		//		for (std::size_t i = 0; i < n; ++i)
		//		{
		//			sum ^= *inIter;
		//			*permIter = sum[0];
		//			++permIter;
		//			++inIter;
		//		}
		//	}
		//	else
		//	{
		//		if constexpr (std::is_same<Perm, Feistel2KPerm>::value)
		//		{

		//			constexpr u32 chunkSize = 8;

		//			block chunk[chunkSize];
		//			block sum = ZeroBlock;

		//			auto n = mN;
		//			auto main = n / chunkSize;
		//			u64 idx = 0;
		//			for (std::size_t i = 0; i < main; ++i)
		//			{
		//				{
		//					std::array<block, 2> idxs;
		//					//__m128i increment = _mm_set_epi32(3, 2, 1, 0);
		//					block increment(3, 2, 1, 0);
		//					idxs[0] = block::allSame<u32>(idx).add_epi32(increment);
		//					idxs[1] = block::allSame<u32>(idx + 4).add_epi32(increment);

		//					idxs[0] = mPerm.feistelBijection(idxs[0]);
		//					idxs[1] = mPerm.feistelBijection(idxs[1]);

		//					for (u64 i = 0; i < 2; ++i)
		//					{
		//						for (u64 j = 0; j < 4; ++j)
		//						{
		//							auto d = idxs[i].get<u32>(j);

		//							sum ^= *inIter;
		//							outIter[d] = sum;
		//						}
		//					}

		//					idx += chunkSize;
		//				}

		//				//for (u64 j = 0; j < chunkSize; ++j)
		//				//{
		//				//    ++inIter;
		//				//}
		//				//mPerm.chunkBlk(permIter, chunk);
		//			}
		//		}
		//		else
		//		{
		//			throw RTE_LOC;
		//		}
		//	}
		//}

		SparseMtx getMtx()
		{
			mPerm.init(mN);
			PointList pl(mN, mN);
			auto iter = mPerm.begin();
			for (u64 i = 0; i < mN; ++i)
			{
				auto pi = *iter; ++iter;
				for (u64 j = 0; j <= i; ++j)
				{
					pl.push_back(pi, j);
				}
			}
			return pl;
		}
	};



	///**
	// * @brief This class is perform a fused permute accumulate operation.
	// *
	// * given an input vec x of size n, it computes the following:
	// *
	// * 1. Partition x is into blocks of size ~sqrt(n)
	// * 2. For each block, uniformly permute the elements within that block
	// * 3. perform a progressive accumulation across the whole (permuted) vector.
	// * 2. For each block, uniformly permute the elements within that block
	// * 4. Partition the state into small chunks.
	// * 5. Globally and uniformly permute the chunks and write them to the output.
	// */
	//struct SqrtPermAccumulator
	//{
	//	u64 mN = 0; // Size of input (also size of output in this case)


	//	u64 mBlockSize = 0; // Size of the blocks for small permutation

	//	constexpr static u32 mChunkSize = 8; // Size of the chunks

	//	bool mPermuteInput = true; // Whether to permute the input

	//	block mSeed = ZeroBlock; // Seed for the permutation

	//	/**
	//	 * @brief Constructs an Accumulator with the given size and permutation
	//	 *
	//	 * @param n Size of both input and output vectors
	//	 * @param perm Permutation instance (default constructs if not provided)
	//	 */
	//	SqrtPermAccumulator(u64 n, bool permuteInput, block seed)
	//		: mN(n)
	//	{
	//		if (n % mChunkSize)
	//			throw RTE_LOC;
	//		if (n != 1ull << log2ceil(n))
	//			throw RTE_LOC;

	//		// next power of 2 size after sqrt(n)
	//		mBlockSize = 1ull << log2ceil(sqrt(n));
	//		mSeed = seed;
	//	}


	//	///**
	//	// * @brief Apply the accumulate-permute operation to input data
	//	// *
	//	// * This performs two steps:
	//	// * 1. Progressive accumulation: each element i is XORed into elements i+1, i+2, etc.
	//	// * 2. Permutation: the accumulated values are permuted using the specified permutation
	//	// *
	//	// * The function has two implementations based on whether the permutation supports
	//	// * chunk-based processing for better performance.
	//	// *
	//	// * @param in Input data
	//	// * @param out Output data (must be distinct from input)
	//	// */
	//	//template<typename F, typename InIter, typename OutIter, typename CoeffCtx>
	//	//void dualEncode(InIter inIter, OutIter outIter, CoeffCtx ctx)
	//	//{
	//	//    mPerm.init(mN);

	//	//    if constexpr (HasChunkSize<Perm>::value == false)
	//	//    {

	//	//        auto n = mN;
	//	//        //const T* __restrict inIter = in.data();
	//	//        auto permIter = mPerm.begin(outIter);
	//	//        typename CoeffCtx::template Vec<F> sum;
	//	//        ctx.resize(sum, 1);
	//	//        ctx.zero(sum[0]);
	//	//        for (std::size_t i = 0; i < n; ++i)
	//	//        {
	//	//            ctx.plus(sum[0], sum[0], *inIter);
	//	//            ctx.copy(*permIter, sum[0]);
	//	//            ++permIter;
	//	//            ++inIter;
	//	//        }
	//	//    }
	//	//    else
	//	//    {
	//	//        constexpr u32 chunkSize = Perm::chunkSize;

	//	//        typename CoeffCtx::template Vec<F> chunk;
	//	//        ctx.resize(chunk, chunkSize + 1);
	//	//        auto&& sum = chunk[chunkSize];
	//	//        ctx.zero(chunk.begin(), chunk.end());

	//	//        auto n = mN;
	//	//        auto permIter = mPerm.begin(outIter);
	//	//        if (n % chunkSize)
	//	//            throw RTE_LOC;
	//	//        auto main = n / chunkSize;

	//	//        for (std::size_t i = 0; i < main; ++i)
	//	//        {
	//	//            for (u64 j = 0; j < chunkSize; ++j)
	//	//            {
	//	//                //sum ^= *inIter;
	//	//                //chunk[j] = sum;
	//	//                ctx.plus(sum, sum, *inIter);
	//	//                ctx.copy(chunk[j], sum);
	//	//                ++inIter;
	//	//            }
	//	//            mPerm.chunk(permIter, chunk.data());
	//	//        }
	//	//    }
	//	//}


	//	void dualEncode(block* __restrict inIter, block* __restrict outIter)
	//	{
	//		u64 numBlock = divCeil(mN, mBlockSize);
	//		if (mN % numBlock)
	//			throw RTE_LOC;

	//		Feistel2KPerm smallPerm;
	//		smallPerm.init(mBlockSize, mSeed);
	//		auto iter = inIter;
	//		Feistel2KPerm largePerm;
	//		largePerm.init(mN / mChunkSize, mSeed);

	//		block sum = ZeroBlock;
	//		for(u64 i = 0, c = 0; i < numBlock; ++i)
	//		{
	//			auto src = iter + i * mBlockSize;
	//			// permute the small block
	//			if (mPermuteInput)
	//			{
	//				for (u64 j = 0; j < mBlockSize; )
	//				{
	//					block buffer[mChunkSize];
	//					for(u64 k = 0; k < mChunkSize; ++k, ++j)
	//					{
	//						auto idx = smallPerm.feistelBijection(j);
	//						sum ^= src[idx];
	//						buffer[k] = sum;
	//					}

	//					auto idx = largePerm.feistelBijection(c++) * mChunkSize;
	//					for (u64 k = 0; k < mChunkSize; ++k)
	//					{
	//						outIter[idx + k] = buffer[k];
	//					}
	//				}
	//			}
	//			else
	//			{
	//				for (u64 j = 0; j < mBlockSize; )
	//				{
	//					block buffer[mChunkSize];
	//					for (u64 k = 0; k < mChunkSize; ++k, ++j)
	//					{
	//						auto idx = j;
	//						sum ^= src[idx];
	//						buffer[k] = sum;
	//					}

	//					auto idx = largePerm.feistelBijection(c++) * mChunkSize;
	//					for (u64 k = 0; k < mChunkSize; ++k)
	//					{
	//						outIter[idx + k] = buffer[k];
	//					}
	//				}
	//			}
	//		}
	//	}

	//	SparseMtx getMtx()
	//	{
	//		throw RTE_LOC; // Not implemented yet
	//		//mPerm.init(mN);
	//		//PointList pl(mN, mN);
	//		//auto iter = mPerm.begin();
	//		//for (u64 i = 0; i < mN; ++i)
	//		//{
	//		//	auto pi = *iter; ++iter;
	//		//	for (u64 j = 0; j <= i; ++j)
	//		//	{
	//		//		pl.push_back(pi, j);
	//		//	}
	//		//}
	//		//return pl;
	//	}
	//};

}
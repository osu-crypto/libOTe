#pragma once
#include <numeric>
#include "BaseCode.h"
#include <algorithm>
#include "cryptoTools/Common/Aligned.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "Permutation.h"

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
            mPerm.init(n);
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
                    mPerm.chunk(permIter, chunk.begin());
				}
            }
        }
    };

}
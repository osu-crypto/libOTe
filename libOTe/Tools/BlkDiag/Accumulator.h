#pragma once
#include <numeric>
#include "BaseCode.h"
#include <algorithm>
#include "cryptoTools/Common/Aligned.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "Permutation.h"

namespace osuCrypto
{

    template<typename T, typename Perm>
    struct Accumulator : public BaseCode<T>
    {
		using BaseCode<T>::mK;
		using BaseCode<T>::mN;
        Perm mPerm;

        explicit Accumulator(u64 n, Perm perm = {})
            : BaseCode<T>(n,n)
            , mPerm(std::move(perm))
        {
            mPerm.init(n);
        }

		bool inplace() const override
		{
			return false;
		}


        void invoke(span<const T> in, span<T> out)
        {
            if (in.size() != mN || out.size() != mN)
                throw RTE_LOC;


            if constexpr (HasChunkSize<Perm> == false)
            {

                auto n = mN;
                const T* __restrict inIter = in.data();
                auto outIter = mPerm.begin(out.data());
                T sum;
                setBytes(sum, 0);
                for (std::size_t i = 0; i < n; ++i)
                {
                    sum ^= *inIter;
                    *outIter = sum;
                    ++outIter;
                    ++inIter;
                }
            }
            else
            {
                constexpr u32 chunkSize = Perm::chunkSize;
				std::array<T, chunkSize> chunk;
				auto n = mN;
				const T* __restrict inIter = in.data();
				auto outIter = mPerm.begin(out.data());
				T sum;
				setBytes(sum, 0);
				if (n % chunkSize)
					throw RTE_LOC;
				auto main = n / chunkSize;

				for (std::size_t i = 0; i < main; ++i)
				{
					for (u64 j = 0; j < chunkSize; ++j)
					{
						sum ^= *inIter;
                        chunk[j] = sum;
						++inIter;
					}
                    mPerm.chunk<T>(outIter, chunk.data());
				}
            }
        }
    };

}
#pragma once

#include "EnumeratorTools.h"
#include "Enumerator.h"

#include <iostream>

namespace osuCrypto {



	template<typename I, typename R>
	struct ComposeEnumerator : Enumerator<R>
	{


		std::vector<Enumerator<R>*> mSubcodes;
		ChooseCache<I> mChoose;

		void enumerate(
			span<const R> inDist,
			span<R> outDist) override
		{
			enumerateImpl(inDist, outDist);
		}

		void enumerate(
			span<const R> inDist,
			span<R> outDist,
			MatrixView<R> fullEnum) override
		{
			enumerateImpl(inDist, outDist, fullEnum);
		}


		template<typename Full = int>
		void enumerateImpl(
			span<const R> inDist,
			span<R> outDist,
			Full&& fullEnum = {})
		{

			u64 k = mSubcodes[0].mK;
			u64 n = mSubcodes.back().mN;

			if (inDist.size() != k + 1)
				throw RTE_LOC;
			if (outDist.size() != n + 1)
				throw RTE_LOC;

			std::array<std::vector<R>, 2> distributions;
			distributions[0].resize(k + 1);

			R expectedSum = 0;
			if (inDist.size())
			{
				for (size_t w = 0; w <= k; w++)
				{
					distributions[0][w] = inDist[w];
					expectedSum += inDist[w];
				}
			}
			else
			{
				for (size_t w = 0; w <= k; w++)
				{
					distributions[0][w] = mChoose(k, w);
					expectedSum += distributions[0][w];
				}
			}

			Matrix<R> curEnum;

			// Compute distributions for iterations
			for (size_t iter = 0; iter < mSubcodes.size(); iter++)
			{
				distributions[1].resize(mSubcodes[iter].mN + 1);
				std::fill(distributions[1].begin(), distributions[1].end(), R(0));


				if constexpr (std::is_same_v<Full, int>)
				{
					mSubcodes[iter].enumerate(
						distributions[0],
						distributions[1]);
				}
				else
				{
					Matrix<R> enumI(
						distributions[0].size() + 1,
						distributions[1].size() + 1);

					mSubcodes[iter].enumerate(
						distributions[0],
						distributions[1],
						enumI);

					if (curEnum.size())
						curEnum = composeEnums<R>(curEnum, enumI, mChoose);
					else
						curEnum = std::move(enumI);
				}

				// expand_and_interpolate(distributions[(iter + 1) % 2]);

				// Check the sum of the final distribution is equal to the sum of the initial distribution
				R sum = std::reduce(distributions[1].begin(), distributions[1].end()); // distribution_sum<R>(distributions[num_iters % 2]);
				if constexpr (std::is_same_v<R, Float>)
				{
					if (boost::multiprecision::isinf(sum) ||
						boost::multiprecision::isnan(sum))
					{
						throw std::runtime_error("NAN final sum. " LOCATION);
					}
				}

				if (std::is_same_v<I, Int>)
				{
					if (sum != expectedSum)
					{
						std::cout << Color::Red
							<< "Initial distribution sum: " << expectedSum << std::endl
							<< "Final distribution sum  : " << sum << std::endl << Color::Default;
					}
				}
				else
				{
					auto ratio = expectedSum / sum;
					if (ratio > 1.0001 || ratio < 0.9999)
					{
						std::cout << Color::Red << "Initial distribution sum: " << expectedSum << std::endl;
						std::cout << "Final distribution sum: " << sum << std::endl << Color::Default;
					}
				}

				std::swap(distributions[0], distributions[1]);
			}

			// Copy the final distribution to the output
			std::copy(distributions[0].begin(),
				distributions[0].end(),
				outDist.begin());

			if constexpr (std::is_same_v<Full, int> == false)
			{
				if (curEnum.rows() != k + 1)
					throw RTE_LOC;
				if (curEnum.cols() != n + 1)
					throw RTE_LOC;
				std::copy(curEnum.begin(), curEnum.end(), fullEnum.begin());
			}
		}

	};

	void composeEnum_exhaustive_Test(const CLP& cmd);

}


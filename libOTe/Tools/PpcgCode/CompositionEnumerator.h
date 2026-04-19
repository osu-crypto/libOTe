#pragma once

#include "EnumeratorTools.h"
#include "Enumerator.h"

#include <iostream>

namespace osuCrypto {



	template<typename I, typename R>
	struct ComposeEnumerator : Enumerator<R>
	{

		using Enumerator<R>::mK;
		using Enumerator<R>::mN;
		using Enumerator<R>::mLoadBar;

		bool mSystematic = false;
		u64 mNumThreads = 0;
		const Choose<I>& mChoose;
		std::vector<Enumerator<R>*> mSubcodes;

		u64 mTrim = 0;

		ComposeEnumerator() = default;
		ComposeEnumerator(
			std::vector<Enumerator<R>*> subcodes,
			bool systematic,
			const Choose<I>& choose,
			u64 numThreads = 0)
			: mSubcodes(std::move(subcodes))
			, mSystematic(systematic)
			, mNumThreads(numThreads ? numThreads : std::thread::hardware_concurrency())
			, mChoose(choose)
		{
			if (mSubcodes.size() == 0)
				throw RTE_LOC;

			mK = mSubcodes[0]->mK;
			mN = mSubcodes.back()->mN + mSystematic * mK;

			for (u64 i = 1; i < mSubcodes.size(); ++i)
			{
				if (mSubcodes[i - 1]->mN != mSubcodes[i]->mK)
					throw RTE_LOC;
			}
		}


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

		u64 numTicks() const override
		{
			u64 ticks = 0;
			for (u64 i =0; i < mSubcodes.size(); ++i)
			{
				ticks += mSubcodes[i]->numTicks();
				if (i && mSystematic)
				{
					// compose enumerator
					ticks += mSubcodes[i]->mK * mSubcodes[i]->mK;
				}

				if (mSystematic)
					ticks += mSubcodes[i]->mK;
			}
			return ticks;
		}


		template<typename Full = int>
		void enumerateImpl(
			span<const R> inDist,
			span<R> outDist,
			Full&& fullEnum = {})
		{


			if (inDist.size() != mK + 1)
				throw RTE_LOC;
			if (outDist.size() != mN + 1)
				throw RTE_LOC;

			if constexpr (std::is_same_v<Full, int> == false)
			{
				if (fullEnum.rows() != mK + 1)
					throw RTE_LOC;
				if (fullEnum.cols() != mN + 1)
					throw RTE_LOC;
			}


			std::array<std::vector<R>, 2> distributions;
			distributions[0].resize(mK + 1);

			R expectedSum = 0;
			for (size_t w = 0; w <= mK; w++)
			{
				distributions[0][w] = inDist[w];
				expectedSum += inDist[w];
			}

			Matrix<R> curEnum;

			// Compute distributions for iterations
			for (size_t iter = 0; iter < mSubcodes.size(); iter++)
			{
				distributions[1].resize(mSubcodes[iter]->mN + 1);
				std::fill(distributions[1].begin(), distributions[1].end(), R(0));


				if (std::is_same_v<Full, int> && mSystematic == false)
				{
					mSubcodes[iter]->enumerate(
						distributions[0],
						distributions[1]);
				}
				else
				{
					Matrix<R> enumI(
						distributions[0].size(),
						distributions[1].size());

					mSubcodes[iter]->enumerate(
						distributions[0],
						distributions[1],
						enumI);

					if (curEnum.size())
						curEnum = composeEnums<R>(curEnum, enumI, mChoose, mNumThreads, mSystematic? mLoadBar: nullptr);
					else
						curEnum = std::move(enumI);
				}

				if (iter == 0 && mTrim)
				{
					for(u64 i = 0; i< mTrim; ++i)
					{
                        distributions[1][mTrim] += distributions[1][i];
                        distributions[1][i] = R(0);
                    }
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
					if constexpr (std::is_same_v<R, Rat>)
					{
						auto sumN = sum;
						auto expectedSumN = expectedSum;
						sumN.backend().normalize();
						expectedSumN.backend().normalize();
						if (sumN != expectedSumN)
						{
							std::cout << Color::Red
								<< "Initial distribution sum: " << expectedSumN << std::endl
								<< "Final distribution sum  : " << sumN << std::endl << Color::Default;
						}
					}
					else if (sum != expectedSum)
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

			if (mSystematic)
			{
				curEnum = makeSystematic<R>(curEnum);
				osuCrypto::enumerate<R>(curEnum, inDist, outDist, mChoose, mLoadBar);
			}
			else
			{
				// Copy the final distribution to the output
				std::copy(distributions[0].begin(),
					distributions[0].end(),
					outDist.begin());
			}

			if constexpr (std::is_same_v<Full, int> == false)
			{
				std::copy(curEnum.begin(), curEnum.end(), fullEnum.begin());
			}
		}

	};

	void composeEnum_exhaustive_Test(const CLP& cmd);
	void composeEnum_sysExhaustive_Test(const CLP& cmd);

}


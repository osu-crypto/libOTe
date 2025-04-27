#pragma once
#include "Enumerator.h"
#include "cryptoTools/Common/CLP.h"
#include "EnumeratorTools.h"
namespace osuCrypto
{


	template<typename I, typename R>
	struct ExpandEnumerator : Enumerator<R>
	{

		using Enumerator<R>::mK;
		using Enumerator<R>::mN;
		using Enumerator<R>::mLoadBar;

		// the weight of the expander.
		u64 mSigma = 0;

		const Choose<I>& mChoose;


		ExpandEnumerator() = default;
		ExpandEnumerator(u64 k, u64 n, u64 sigma, const Choose<I>& choose)
			: Enumerator<R>(k, n)
			, mSigma(sigma)
			, mChoose(choose)
		{
		}



		void enumerate(
			span<const R> inDist,
			span<R> outDist) override
		{
			enumerate(inDist, outDist,
				mK, mN, mSigma, 1, mChoose, {}, mLoadBar);
		}

		void enumerate(
			span<const R> inDist,
			span<R> outDist,
			MatrixView<R> fullEnum) override
		{
			enumerate(inDist, outDist,
				mK, mN, mSigma, 1, mChoose, fullEnum, mLoadBar);
		}


		u64 numTicks() const override
		{
			return mN + 1;
		}

		template<typename Full = int>
		static void enumerate(
			span<const R> inDist,
			span<R> outDist,
			u64 k,
			u64 n,
			u64 sigma,
			u64 numThreads,
			const Choose<I>& choose,
			Full&& full = {},
			LoadingBar* loadingBar = nullptr)
		{


			if (inDist.size() != k + 1)
				throw RTE_LOC;
			if (outDist.size() != n + 1)
				throw RTE_LOC;

			if (loadingBar)
				loadingBar->name("ExpandEnumerator");

			// given that there are w ones in the inputs,
			// how many ways are there to pick sigma of them
			// such that the result is a 1 (or 0).
			std::vector<std::array<I, 2>>  sums(k + 1);

			for (u64 w = 1; w <= k; ++w)
			{

				for (u64 i = 0; i <= sigma; ++i)
				{
					// we are going to pick i of the ones
					// and (sigma - i) of the zeros.
					sums[w][i & 1] += choose(w, i) * choose(k - w, sigma - i);
				}

				//std::cout << "sum[" << w << "]=" << sums[w][0] << " " << sums[w][1] << std::endl;
			}

			R numMtx = boost::multiprecision::pow(choose(k, sigma), n);
			//std::cout << "numMtx " << numMtx << " = " << choose(k, sigma) << "^" << n << std::endl;
			if constexpr (std::is_same_v<Full, int> == false)
				full(0, 0) = 1;

			for (u64 h = 0; h <= n; ++h)
			{
				R dh = 0;

				for (u64 w = 1; w <= k; ++w)
				{
					// there are n choose h ways to have h ones
					// For each one, there are sums[w][1] to get such a one and
					// we have to pick h of them. so we have
					// sums[w][1]^h options. 
					// For each zero, there are sums[w][0] to get such a zero
					// and we have to pick (n - h) of them. so we have
					// sums[w][0]^(n - h) options.
					auto pOnes = boost::multiprecision::pow(sums[w][1], h);
					auto pZeros = boost::multiprecision::pow(sums[w][0], n - h);

					//std::cout << "E(" << w << "," << h << ") = "
					//	<< choose(n, h) << " * " << choose(k, w) << " * "
					//	<< pOnes << " * " << pZeros << " / " << numMtx << std::endl;

					auto enumWH =
						choose(n, h) *
						choose(k, w) *
						pOnes * pZeros / numMtx;


					if constexpr (std::is_same_v<R, Float>)
					{
						if (boost::multiprecision::isinf(enumWH) ||
							boost::multiprecision::isnan(enumWH))
						{
							std::cout << "NAN E(" << w << "," << h << ") = "
								<< choose(n, h) << " * " << choose(k, w) << " * "
								<< pOnes << " * " << pZeros << " / " << numMtx <<
								" = " << enumWH << std::endl;

							std::cout << "pZeros = " << pZeros <<" = " << sums[w][0] <<"^"<<(n-h) << std::endl;

							throw std::runtime_error("NAN final sum. " LOCATION);
						}
					}
					if (inDist.size())
					{
						dh += (inDist[w] / choose(k, w)) *
							enumWH;
					}
					else
						dh += enumWH;

					if constexpr (std::is_same_v<Full, int> == false)
					{
						full(w, h) = enumWH;
					}


				}

				if (loadingBar)
					loadingBar->tick();

				if constexpr (std::is_same_v<R, Rat>)
					dh.backend().normalize();
				outDist[h] = dh;

			}
			outDist[0] += inDist[0];

		}

	};
	void expandEnum_exhaustive_Test(const CLP& cmd);






}
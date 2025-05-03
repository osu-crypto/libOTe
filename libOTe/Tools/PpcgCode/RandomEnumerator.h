#pragma once
#include "cryptoTools/Common/Defines.h"
#include "EnumeratorTools.h"
#include "Enumerator.h"
#include "libOTe/Tools/LDPC/Mtx.h"

namespace osuCrypto
{

	template<typename I, typename R>
	struct RandomEnumerator : Enumerator<R>
	{
		using Enumerator<R>::mK;
		using Enumerator<R>::mN;
		using Enumerator<R>::mLoadBar;

		bool mSystematic = false;
		const Choose<I>& mChoose;

		RandomEnumerator() = default;
		RandomEnumerator(u64 k, u64 n, bool sys, const Choose<I>& choose)
			: Enumerator<R>(k, n)
			, mSystematic(sys)
			, mChoose(choose)
		{
		}


		void enumerate(
			span<const R> inDist,
			span<R> outDist) override
		{
			enumerate(inDist, outDist, mSystematic,
				mK, mN, 1, mChoose, {}, mLoadBar);
		}

		void enumerate(
			span<const R> inDist,
			span<R> outDist,
			MatrixView<R> fullEnum) override
		{
			enumerate(inDist, outDist, mSystematic,
				mK, mN, 1, mChoose, fullEnum, mLoadBar);
		}


		u64 numTicks() const override
		{
			return mN;
		}


		static R enumerate(
			u64 w,
			u64 h,
			u64 k,
			u64 n,
			const Choose<I>& choose)
		{
			if (w == 0 && h == 0)
				return 1;

			if (w == 0 || w > k)
				return 0;
			return R(choose(k, w) * choose(n, h)) / pow2_<I>(n);
		}

		template<typename Full = int>
		static void enumerate(
			span<const R> inDist,
			span<R> outDist,
			bool systematic,
			u64 k,
			u64 n,
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
				loadingBar->name("RandomEnumerator");

			outDist[0] = inDist[0];

			if constexpr (std::is_same_v<Full, int> == false)
			{
				if (full.rows() != inDist.size())
					throw RTE_LOC;
				if (full.cols() != outDist.size())
					throw RTE_LOC;
				full(0, 0) = 1;
			}

			//if(systematic)
			//	n -= k;

			auto nn = n - systematic * k;

			for (u64 h = 0; h <= n; ++h)
			{
				//out[h] = sum_w (in[w] / (k choose w) ) * enum_{w,h}
				//         sum_w (in[w] / (k choose w) ) * (n - h choose w/2) (h-1 choose ceil(w/2)-1)

				auto dh = R(0);

				u64 wb = systematic ? std::max<i64>(1, h - nn) : 1;
				u64 we = systematic ? std::min<i64>(k, h) : k;
				for (u64 w = wb; w <= we; ++w)
				{
					auto hh = h - systematic * w;
					R enumWH = enumerate(w, hh, k, nn, choose);

					//std::cout << "(w,h,k) = " << w << ", " << i64(hh) << ", "<<k<<" -> " << enumWH << std::endl;

					if (inDist.size())
					{
						//std::cout << w << " " << h << " ~ " << inDist[w] << " " << enumWH << " / " << choose_pascal<I>(k, w, choose) << std::endl;
						dh += (inDist[w] / choose(k, w)) *
							enumWH;
					}
					else
						dh += enumWH;

					if constexpr (std::is_same_v<Full, int> == false)
						full(w, h) = enumWH;
				}

				if constexpr (std::is_same_v<R, Rat>)
					dh.backend().normalize();

				if(h)
					outDist[h] = dh;
				else
					outDist[h] += dh;

				if (loadingBar)
					loadingBar->tick();
			}
		}

	};





	void RandomEnum_exhaustive_Test(const CLP& cmd);
}
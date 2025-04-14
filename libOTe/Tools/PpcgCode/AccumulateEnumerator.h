#pragma once
#include "cryptoTools/Common/Defines.h"
#include "EnumeratorTools.h"

namespace osuCrypto
{



	template<typename I, typename R, typename Full = int>
	void accumulateEnumerator(
		span<const R> inDist,
		span<R> outDist,
		bool systematic,
		u64 k,
		u64 n,
		u64 numThreads,
		const ChooseCache<I>& pascal_triangle,
		Full&& full = {})
	{

		for (u64 h = 1; h <= n; ++h)
		{
			//out[h] = sum_w (in[w] / (k choose w) ) * enum_{w,h}
			//         sum_w (in[w] / (k choose w) ) * (n - h choose w/2) (h-1 choose ceil(w/2)-1)

			auto dh = R(0);
			for (u64 w = 1; w <= k; ++w)
			{
				auto hh = systematic ? h - w : h;
				if (hh > n || hh == 0)
					continue;
				auto enumWH = choose_pascal<I>(n - hh, w / 2, pascal_triangle) *
					choose_pascal<I>(hh - 1, (w + 1) / 2 - 1, pascal_triangle);

				if (inDist.size())
				{
					dh += (inDist[w] / choose_pascal<I>(k, w, pascal_triangle)) *
						enumWH;
				}
				else
					dh += enumWH;

				if constexpr (std::is_same_v<Full, int> == false)
					full(w, h) = enumWH;
			}

			outDist[h] = dh;
		}
	}



	inline void accumulateEnum_exhaustive_Test(const CLP& cmd)
	{
		u64 n = cmd.getOr("n", 10);
		u64 numThreads = cmd.getOr("nt", std::thread::hardware_concurrency());
		//std::cout << "n: " << n << std::endl;
		std::vector<Rat> actIn(n + 1);
		std::vector<Rat> actOut(n + 1);
		Matrix<Rat> actEnum(n + 1, n + 1);
		Matrix<Rat> expEnum(n + 1, n + 1);

		ChooseCache<Int> pas(n);

		accumulateEnumerator<Int, Rat>(actIn, actOut, false, n, n, numThreads, pas, actEnum);

		for (u64 v = 1; v < (1ull << n); ++v)
		{
			auto w = popcount(v);
			
			auto t = v;
			for (u64 i = 0; i < n-1; ++i)
			{
				auto b = t & (1ull << i);
				t = t ^ (b << 1);
			}
			auto h = popcount(t);
			expEnum(w, h) += 1;
		}

		if (expEnum != actEnum)
			throw RTE_LOC;
	}
}
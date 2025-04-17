#pragma once
#include "cryptoTools/Common/Defines.h"
#include "EnumeratorTools.h"

namespace osuCrypto
{




	template<typename I>
	I accumulateEnumerator(
		u64 w,
		u64 h,
		u64 k,
		u64 n,
		const ChooseCache<I>& pascal_triangle)
	{
		if (n != k)
			throw RTE_LOC;
		if (w == 0 && h == 0)
			return 1;

		if (w == 0 || w > k)
			return 0;

		if (h == 0 || h > n)
			return 0;

		return choose_pascal<I>(n - h, w / 2, pascal_triangle) *
			choose_pascal<I>(h - 1, (w + 1) / 2 - 1, pascal_triangle);
	}

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

		if (systematic == false && k != n)
			throw RTE_LOC;
		if (systematic == true && 2 * k != n)
			throw RTE_LOC;

		outDist[0] = inDist[0];

		if constexpr (std::is_same_v<Full, int> == false)
			full(0, 0) = 1;

		//if(systematic)
		//	n -= k;

		auto nn = n - systematic * k;

		for (u64 h = 1; h <= n; ++h)
		{
			//out[h] = sum_w (in[w] / (k choose w) ) * enum_{w,h}
			//         sum_w (in[w] / (k choose w) ) * (n - h choose w/2) (h-1 choose ceil(w/2)-1)

			auto dh = R(0);

			u64 wb = systematic ? std::max<i64>(1, h - nn) : 1;
			u64 we = systematic ? std::min<i64>(k, h) : k;
			for (u64 w = wb; w <= we; ++w)
			{
				auto hh = h - systematic * w;
				I enumWH = accumulateEnumerator(w, hh, k, nn, pascal_triangle);

				//std::cout << "(w,h,k) = " << w << ", " << i64(hh) << ", "<<k<<" -> " << enumWH << std::endl;

				if (inDist.size())
				{
					//std::cout << w << " " << h << " ~ " << inDist[w] << " " << enumWH << " / " << choose_pascal<I>(k, w, pascal_triangle) << std::endl;
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
		auto Ks = cmd.getManyOr<u64>("k", { 2, 5, 10 });
		bool verbose = cmd.isSet("v");
		u64 numThreads = cmd.getOr("nt", std::thread::hardware_concurrency());
		//std::cout << "n: " << n << std::endl;


		for (auto k : Ks)
		{
			//for (auto sys : { false, true })
			{
				std::cout << std::endl;
				auto nSys = k + k;

				std::vector<Rat> actIn(k + 1);
				std::vector<Rat> actOut(k + 1);
				std::vector<Rat> expOut(k + 1);
				std::vector<Rat> sysOut(nSys + 1);
				std::vector<Rat> expSysOut(nSys + 1);
				Matrix<Rat> actEnum(k + 1, k + 1);
				Matrix<Rat> sysEnum(k + 1, nSys + 1);
				Matrix<Rat> expEnum(k + 1, k + 1);

				ChooseCache<Int> pas(k);
				for (u64 i = 0; i < actIn.size(); ++i)
				{
					actIn[i] = pas(k, i);
				}



				accumulateEnumerator<Int, Rat>(actIn, actOut, false, k, k, numThreads, pas, actEnum);
				accumulateEnumerator<Int, Rat>(actIn, sysOut, true, k, nSys, numThreads, pas, sysEnum);

				for (u64 v = 0; v < (1ull << k); ++v)
				{
					auto w = popcount(v);

					auto t = v;
					for (u64 i = 0; i < k - 1; ++i)
					{
						auto b = t & (1ull << i);
						t = t ^ (b << 1);
					}
					auto h = popcount(t);
					expEnum(w, h) += 1;
				}

				if (verbose)
				{

					for (u64 i = 0; i < expEnum.rows(); ++i)
					{
						for (u64 j = 0; j < expEnum.cols(); ++j)
						{
							std::cout << expEnum(i, j) << " ";
						}
						std::cout << std::endl;
					}
					std::cout << std::endl;

					for (u64 i = 0; i < expEnum.rows(); ++i)
					{
						for (u64 j = 0; j < expEnum.cols(); ++j)
						{
							std::cout << actEnum(i, j) << " ";
						}
						std::cout << std::endl;
					}
					std::cout << std::endl;

					for (u64 i = 0; i < sysEnum.rows(); ++i)
					{
						for (u64 j = 0; j < sysEnum.cols(); ++j)
						{
							std::cout << sysEnum(i, j) << " ";
						}
						std::cout << std::endl;
					}
					std::cout << std::endl;

				}

				if (expEnum != actEnum)
					throw RTE_LOC;

				for (u64 i = 0; i < k; ++i)
				{
					for (u64 j = 0; j < nSys; ++j)
					{
						if (j < i)
						{
							if (sysEnum(i, j))
								throw RTE_LOC;
						}
						else if (j <= i + k)
						{
							if (sysEnum(i, j) != expEnum(i, j - i))
								throw RTE_LOC;
						}
						else
						{
							if (sysEnum(i, j))
								throw RTE_LOC;
						}
					}
				}

				enumerate<Rat>(actEnum, actIn, expOut, pas);

				if (expOut != actOut)
				{
					for (u64 i = 0; i < expOut.size(); ++i)
					{
						std::cout << i << " " << expOut[i] << " " << actOut[i] << std::endl;
					}
					throw RTE_LOC;
				}

				enumerate<Rat>(sysEnum, actIn, expSysOut, pas);

				if (expSysOut != sysOut)
				{
					for (u64 i = 0; i < sysOut.size(); ++i)
					{
						std::cout << i << " " << expSysOut[i] << " " << sysOut[i] << std::endl;
					}
					throw RTE_LOC;
				}
			}
		}
	}


	inline void accumulateEnum_exhaustive_Test_(const CLP& cmd)
	{
		auto Ks = cmd.getManyOr<u64>("k", { 2, 5, 10 });
		bool verbose = cmd.isSet("v");
		u64 numThreads = cmd.getOr("nt", std::thread::hardware_concurrency());
		//std::cout << "n: " << n << std::endl;


		for (auto k : Ks)
		{
			for (auto sys : { false, true })
			{
				std::cout << std::endl;
				auto n = k + sys * k;

				std::vector<Rat> actIn(k + 1);
				std::vector<Rat> actOut(n + 1);
				Matrix<Rat> actEnum(k + 1, n + 1);
				Matrix<Rat> expEnum(k + 1, n + 1);

				ChooseCache<Int> pas(n);

				accumulateEnumerator<Int, Rat>(actIn, actOut, sys, k, n, numThreads, pas, actEnum);

				for (u64 v = 0; v < (1ull << k); ++v)
				{
					auto w = popcount(v);

					auto t = v;
					for (u64 i = 0; i < k - 1; ++i)
					{
						auto b = t & (1ull << i);
						t = t ^ (b << 1);
					}
					auto h = popcount(t) + w * sys;
					expEnum(w, h) += 1;

					if (sys)
					{
						t <<= k;
						t |= v;
					}

					if (verbose)
					{
						std::cout << BitVector((u8*)&v, k) << std::endl;
						std::cout << BitVector((u8*)&t, n) << std::endl;
					}
				}

				for (u64 i = 0; i < expEnum.rows(); ++i)
				{
					for (u64 j = 0; j < expEnum.cols(); ++j)
					{
						std::cout << expEnum(i, j) << " ";
					}
					std::cout << std::endl;
				}
				std::cout << std::endl;

				for (u64 i = 0; i < expEnum.rows(); ++i)
				{
					for (u64 j = 0; j < expEnum.cols(); ++j)
					{
						std::cout << actEnum(i, j) << " ";
					}
					std::cout << std::endl;
				}
				std::cout << std::endl;


				if (expEnum != actEnum)
				{


					throw RTE_LOC;
				}
			}
		}
	}
}
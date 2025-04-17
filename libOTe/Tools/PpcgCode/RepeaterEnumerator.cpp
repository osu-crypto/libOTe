#include "RepeaterEnumerator.h"

namespace osuCrypto {


	void RepeaterEnum_exhaustive_Test(const CLP& cmd)
	{
		auto Ks = cmd.getManyOr<u64>("k", { 2, 5, 7 });
		auto Es = cmd.getManyOr<u64>("e", { 2, 3, 2 });
		bool verbose = cmd.isSet("v");
		u64 numThreads = cmd.getOr("nt", std::thread::hardware_concurrency());
		//std::cout << "n: " << n << std::endl;


		for (u64 i = 0; i < Ks.size(); ++i)
		{
			auto k = Ks[i];
			auto e = Es[i];
			auto n = k * e;

			std::vector<Rat> actIn(k + 1);
			std::vector<Rat> actOut(n + 1);
			std::vector<Rat> expOut(n + 1);
			Matrix<Rat> actEnum(k + 1, n + 1);
			Matrix<Rat> expEnum(k + 1, n + 1);

			ChooseCache<Int> pas(k);
			for (u64 i = 0; i < actIn.size(); ++i)
			{
				actIn[i] = pas(k, i);
			}


			RepeaterEnumerator<Int, Rat>{k, n, pas}.enumerate(actIn, actOut, actEnum);

			for (u64 w = 0; w <= k; ++w)
			{
				expEnum(w, e * w) = pas(k, w);
			}

			if (e == 2)
			{
				Matrix<Rat> expEnum2(k + 1, n + 1);
				auto mtx = RepeaterEnumerator<Int, Rat>{ k, n, pas }.getMtx();
				//std::cout << "R \n" << mtx << std::endl;

				for (u64 v = 0; v < (1ull << k); ++v)
				{
					auto w = popcount(v);
					auto t = v | (v << k);
					auto h = popcount(t);
					++expEnum2(w, h);
					{
						std::vector<u8> vv(k);
						std::vector<u8> tt(n);
						for (u64 i = 0; i < k; ++i)
						{
							vv[i] = (v >> i) & 1;
						}
						mtx.leftMultAdd(vv, tt);
						for (u64 i = 0; i < n; ++i)
						{
							if (tt[i] != ((t >> i) & 1))
							{
								std::cout << "error" << std::endl;
								throw RTE_LOC;
							}
						}

					}
				}

				if (expEnum != expEnum2)
					throw RTE_LOC;
			}

			if (verbose)
			{
				std::cout << enumToString(actEnum) << std::endl;
				std::cout << enumToString(expEnum) << std::endl;
			}

			if (expEnum != actEnum)
				throw RTE_LOC;

			enumerate<Rat>(actEnum, actIn, expOut, pas);

			if (expOut != actOut)
			{
				for (u64 i = 0; i < expOut.size(); ++i)
				{
					std::cout << i << " " << expOut[i] << " " << actOut[i] << std::endl;
				}
				throw RTE_LOC;
			}
		}
	}

}

#include "AccumulateEnumerator.h"

namespace osuCrypto
{

	void accumulateEnum_exhaustive_Test(const CLP& cmd)
	{
		auto Ks = cmd.getManyOr<u64>("k", { 2, 5, 10 });
		bool verbose = cmd.isSet("v");
		u64 numThreads = cmd.getOr("nt", std::thread::hardware_concurrency());
		//std::cout << "n: " << n << std::endl;


		for (auto k : Ks)
		{
			auto nSys = k + k;

			std::vector<Rat> actIn(k + 1);
			std::vector<Rat> actOut(k + 1);
			std::vector<Rat> expOut(k + 1);
			std::vector<Rat> sysOut(nSys + 1);
			std::vector<Rat> expSysOut(nSys + 1);
			Matrix<Rat> actEnum(k + 1, k + 1);
			Matrix<Rat> sysEnum(k + 1, nSys + 1);
			Matrix<Rat> expEnum(k + 1, k + 1);

			Choose<Int> pas(k);
			for (u64 i = 0; i < actIn.size(); ++i)
			{
				actIn[i] = pas(k, i);
			}



			AccumulatorEnumerator<Int, Rat> acc(k, k, pas);
			AccumulatorEnumerator<Int, Rat> sys(k, nSys, pas);
			acc.enumerate(actIn, actOut, actEnum);
			sys.enumerate(actIn, sysOut, sysEnum);

			auto mtx = acc.getMtx();
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

				{
					std::vector<u8> vv(k);
					std::vector<u8> tt(k);
					for (u64 i = 0; i < k; ++i)
					{
						vv[i] = (v >> i) & 1;
					}
					mtx.leftMultAdd(vv, tt);
					for (u64 i = 0; i < k; ++i)
					{
						if (tt[i] != ((t >> i) & 1))
						{
							std::cout << "error" << std::endl;
							throw RTE_LOC;
						}
					}

					//if (v == 2)
					//{
					//	std::cout << mtx << std::endl;
					//	for (u64 i = 0; i < k; ++i)
					//		std::cout << vv[i] << " ";
					//	std::cout << std::endl;
					//	for (u64 i = 0; i < k; ++i)
					//		std::cout << tt[i] << " ";
					//	std::cout << std::endl;
					//}
				}

				expEnum(w, h) += 1;
			}


			if (verbose)
			{
				std::cout << enumToString(actEnum) << std::endl;
				std::cout << enumToString(expEnum) << std::endl;
				std::cout << enumToString(sysEnum) << std::endl;
			}

			if (expEnum != actEnum)
				throw RTE_LOC;
			auto expSysEnum = makeSystematic<Rat>(expEnum);
			if (expSysEnum != sysEnum)
			{
				std::cout << enumToString(expSysEnum) << std::endl << std::endl;
				std::cout << enumToString(sysEnum) << std::endl;

				throw RTE_LOC;
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
#include "ExpandEnumerator.h"
#include "EnumeratorTools.h"
#include "libOTe/Tools/LDPC/Util.h"
#include "cryptoTools/Common/BitVector.h"
namespace osuCrypto
{
	void expandEnum_exhaustive_Test(const CLP& cmd)
	{

		auto Ks = cmd.getManyOr<u64>("k", { 2, 3/*, 6 */ });
		auto sigmas = cmd.getManyOr<u64>("sigma", { 1, 2/*, 3*/ });
		bool verbose = cmd.isSet("v");
		u64 numThreads = cmd.getOr("nt", std::thread::hardware_concurrency());
		//std::cout << "n: " << n << std::endl;




		for (auto k : Ks)
		{
			auto n = k * 2;

			for (auto sigma : sigmas)
			{

				//auto nSys = k + k;

				std::vector<Rat> actIn(k + 1);
				std::vector<Rat> actOut(n + 1);
				std::vector<Rat> expOut(n + 1);
				//std::vector<Rat> sysOut(nSys + 1);
				//std::vector<Rat> expSysOut(nSys + 1);
				Matrix<Rat> actEnum(k + 1, n + 1);
				//Matrix<Rat> sysEnum(k + 1, nSys + 1);
				Matrix<Rat> expEnum(k + 1, n + 1);

				Choose<Int> pas(n);
				for (u64 i = 0; i < actIn.size(); ++i)
				{
					actIn[i] = pas(k, i);
				}



				ExpandEnumerator<Int, Rat> acc(k, n, sigma, pas);
				//ExpandEnumerator<Int, Rat> sys(k, nSys, sigma, pas);
				acc.enumerate(actIn, actOut, actEnum);
				//sys.enumerate(actIn, sysOut, sysEnum);

				//auto mtx = acc.getMtx();

				//std::vector<std::vector<u64>> combos(static_cast<u64>(pas(k, sigma)));
				//for (u64 i = 0; i < combos.size(); ++i)
				//	combos[i] = ithCombination(i, k, sigma);

				u64 numCombos = static_cast<u64>(pas(k, sigma));
				std::vector<u64> combIdxs(n);
				std::vector<u64> mtx(n);
				for (u64 i = 0; i < n; ++i)
					mtx[i] = (1ull << sigma) - 1; // 000000111

				std::vector<u64> set(sigma);
				auto next = [&]() {
					for (u64 i = 0; i < mtx.size(); ++i)
					{
						combIdxs[i] = (combIdxs[i] + 1) % numCombos;
						ithCombination(combIdxs[i], k, set);

						mtx[i] = 0;
						for (u64 j = 0; j < sigma; ++j)
							mtx[i] ^= (1ull << set[j]);

						if (combIdxs[i])
							return;
					}
					};

				auto total = static_cast<u64>(boost::multiprecision::pow(Int(numCombos), n));
				//std::cout << "total: " << total << " = " << numCombos <<"^"<<n << std::endl;
				for (u64 m = 0; m < total; ++m)
				{
					PointList points(k, n);
					for (u64 i = 0; i < n; ++i)
					{
						for (u64 j = 0; j < k; ++j)
						{
							if ((mtx[i] >> j) & 1)
								points.push_back(j, i);
						}
					}
					//SparseMtx sm(points);
					//std::cout << sm << std::endl;

					//std::vector<u8>X(k), Y(n);
					for (u64 x = 0; x < (1ull << k); ++x)
					{
						auto w = popcount(x);
						//for (u64 j = 0; j < k; ++j)
						//	X[j] = (x >> j) & 1;
						u64 h = 0;
						u64 y = 0;
						for (u64 j = 0; j < n; ++j)
						{
							y ^= u64(popcount(mtx[j] & x) & 1) << j;
							h += popcount(x & mtx[j]) & 1;

						}
						//std::fill(Y.begin(), Y.end(), 0);
						//sm.leftMultAdd(X, Y);
						//for (u64 j = 0; j < n; ++j)
						//{
						//	if (Y[j] != ((y >> j) & 1))
						//	{
						//		std::cout << "error" << std::endl;
						//		throw RTE_LOC;
						//	}
						//}

						expEnum(w, h) += 1;
					}
					next();
				}

				for (auto& e : expEnum)
					e /= total;


				if (verbose)
				{
					std::cout << "formulaic" << std::endl;
					std::cout << enumToString(actEnum) << std::endl;
					std::cout << "exhaustive" << std::endl;
					std::cout << enumToString(expEnum) << std::endl;
				}

				if (expEnum != actEnum)
					throw RTE_LOC;
				//auto expSysEnum = makeSystematic<Rat>(expEnum);
				//if (expSysEnum != sysEnum)
				//{
				//	std::cout << enumToString(expSysEnum) << std::endl << std::endl;
				//	std::cout << enumToString(sysEnum) << std::endl;

				//	throw RTE_LOC;
				//}

				enumerate<Rat>(actEnum, actIn, expOut, pas);

				if (expOut != actOut)
				{
					for (u64 i = 0; i < expOut.size(); ++i)
					{
						std::cout << i << " " << expOut[i] << " " << actOut[i] << std::endl;
					}
					throw RTE_LOC;
				}

				//enumerate<Rat>(sysEnum, actIn, expSysOut, pas);

				//if (expSysOut != sysOut)
				//{
				//	for (u64 i = 0; i < sysOut.size(); ++i)
				//	{
				//		std::cout << i << " " << expSysOut[i] << " " << sysOut[i] << std::endl;
				//	}
				//	throw RTE_LOC;
				//}
			}
		}
	}


}
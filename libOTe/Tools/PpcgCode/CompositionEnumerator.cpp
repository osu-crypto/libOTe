#include "CompositionEnumerator.h"
#include "EnumeratorTools.h"
#include "AccumulateEnumerator.h"
#include "RepeaterEnumerator.h"

#include "cryptoTools/Crypto/RandomOracle.h"
namespace osuCrypto
{

	u64 permute(u64 x, const std::vector<u64>& perm)
	{
		u64 y = 0;
		for (u64 i = 0; i < perm.size(); ++i)
		{
			y |= ((x >> perm[i]) & 1) << i;
		}
		return y;
	}
	std::vector<u8> permute(const std::vector<u8>& x, const std::vector<u64>& perm)
	{
		std::vector<u8> y(perm.size());
		for (u64 i = 0; i < perm.size(); ++i)
		{
			y[i] = x[perm[i]];// |= ((x >> perm[i]) & 1) << i;
		}
		return y;
	}


	void composeEnum_exhaustive_Test(const CLP& cmd)
	{
		// testing G = repeat pi accumulate code
		// we will enumerator all pi.

		auto Ks = cmd.getManyOr<u64>("k", { 2, 4 });
		bool verbose = cmd.isSet("v");
		u64 numThreads = cmd.getOr("nt", std::thread::hardware_concurrency());
		//std::cout << "n: " << n << std::endl;

		for (auto k : Ks)
		{
			auto n = k + k;

			std::vector<Rat> actIn(k + 1);
			std::vector<Rat> actMid(n + 1);
			std::vector<Rat> actOut(n + 1);
			std::vector<Rat> expOut(n + 1);
			std::vector<Rat> expOut2(n + 1);
			Matrix<Rat> repEnum(k + 1, n + 1);
			Matrix<Rat> accEnum(n + 1, n + 1);
			Matrix<Rat> expEnum(k + 1, n + 1);

			ChooseCache<Int> pas(n);
			for (u64 i = 0; i < actIn.size(); ++i)
			{
				actIn[i] = pas(k, i);
			}

			RepeaterEnumerator<Int, Rat>(k, n, pas).enumerate(actIn, actMid, repEnum);
			AccumulatorEnumerator<Int, Rat>(n, n, pas).enumerate(actMid, actOut, accEnum);


//			auto R = RepeaterEnumerator<Int, Rat>(k, n, pas).getMtx();
//			auto A = AccumulatorEnumerator<Int, Rat>(n, n, pas).getMtx();

			auto actEnum = composeEnums<Rat>(repEnum, accEnum, pas);

			auto numPerms = fact<Int>(n);
			std::set<block> hashs;
			std::vector<u64> pi(n);
			std::iota(pi.begin(), pi.end(), 0);
			for (u64 i = 0; i < numPerms; ++i)
			{
				RandomOracle  ro(16);
				ro.Update(pi.data(), pi.size());
				block hash;
				ro.Final(hash);
				if(hashs.insert(hash).second == false)
					throw RTE_LOC;
				for (u64 x = 0; x < (1ull << k); ++x)
				{
					//std::vector<u8> xx(k);
					//for (u64 i = 0; i < k; ++i)
					//	xx[i] = (x >> i) & 1;
					//std::vector<u8> tt(n);
					//R.leftMultAdd(xx, tt);

					auto w = popcount(x);
					auto t = x | (x << k);

					//for (u64 i = 0; i < n; ++i)
					//	if (tt[i] != ((t >> i) & 1))
					//	{
					//		std::cout << "error" << std::endl;
					//		throw RTE_LOC;
					//	}

					auto y = permute(t, pi);
					//auto yy = permute(tt, pi);
					auto f = y;
					for (u64 i = 0; i < n - 1; ++i)
					{
						auto b = f & (1ull << i);
						f = f ^ (b << 1);
					}

					//std::vector<u8> ff(n);
					//A.leftMultAdd(yy, ff);
					auto h = popcount(f);
					//auto h2 = std::accumulate(ff.begin(), ff.end(), 0);
					//if (h != h2)
					//{
					//	std::cout << A << std::endl;
					//	for (u64 i = 0; i < n; ++i)
					//		std::cout << int(yy[i]) << " ";
					//	std::cout << std::endl;
					//	for (u64 i = 0; i < n; ++i)
					//		std::cout << int(ff[i]) << " ";
					//	std::cout << std::endl;

					//	for (u64 i = 0; i < n; ++i)
					//		std::cout << ((y >> i) &1) << " ";
					//	std::cout << std::endl;
					//	for (u64 i = 0; i < n; ++i)
					//		std::cout << ((f>>i)&1) << " ";
					//	std::cout << std::endl;

					//	std::cout << "error" << std::endl;
					//	throw RTE_LOC;
					//}

					++expEnum(w, h);
					++expOut[h];
				}

				std::next_permutation(pi.begin(), pi.end());
			}
			for (u64 i = 0; i < expEnum.size(); ++i)
			{
				expEnum(i) = expEnum(i) / numPerms;
				expEnum(i).backend().normalize();
			}
			for (u64 i = 0; i < expOut.size(); ++i)
			{
				expOut[i] = expOut[i] / numPerms;
				expOut[i].backend().normalize();
			}

			if (verbose)
			{
				std::cout << "rep" << std::endl;
				std::cout << enumToString(repEnum) << std::endl;
				std::cout << "acc" << std::endl;
				std::cout << enumToString(accEnum) << std::endl;
				std::cout << "composed" << std::endl;
				std::cout << enumToString(actEnum) << std::endl;

				std::cout << "brute force" << std::endl;
				std::cout << enumToString(expEnum) << std::endl;
			}

			enumerate<Rat>(actEnum, actIn, expOut2, pas);
			if (expOut != actOut || expOut != expOut2)
			{
				for (u64 i = 0; i < expOut.size(); ++i)
				{
					std::cout << i << " " << expOut[i] << " " << actOut[i] <<"  " << expOut2[i] << std::endl;
				}
				throw RTE_LOC;
			}


			if (expEnum != actEnum)
				throw RTE_LOC;



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
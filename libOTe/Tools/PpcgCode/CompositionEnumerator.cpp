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
			std::vector<Rat> comOut(n + 1);
			std::vector<Rat> expOut(n + 1);
			std::vector<Rat> expOut2(n + 1);
			Matrix<Rat> repEnum(k + 1, n + 1);
			Matrix<Rat> accEnum(n + 1, n + 1);
			Matrix<Rat> expEnum(k + 1, n + 1);
			Matrix<Rat> comEnum(k + 1, n + 1);

			ChooseCache<Int> pas(n);
			for (u64 i = 0; i < actIn.size(); ++i)
			{
				actIn[i] = pas(k, i);
			}

			RepeaterEnumerator<Int, Rat> rep(k, n, pas);
			AccumulatorEnumerator<Int, Rat> acc(n, n, pas);
			rep.enumerate(actIn, actMid, repEnum);
			acc.enumerate(actMid, actOut, accEnum);

			ComposeEnumerator<Int, Rat> compose({
				& rep,
				& acc
				}, false, pas);

//			auto R = RepeaterEnumerator<Int, Rat>(k, n, pas).getMtx();
//			auto A = AccumulatorEnumerator<Int, Rat>(n, n, pas).getMtx();

			auto actEnum = composeEnums<Rat>(repEnum, accEnum, pas);

			compose.enumerate(actIn, comOut, comEnum);

			if (comEnum != actEnum)
			{
				std::cout << enumToString(comEnum) << std::endl;
				std::cout << enumToString(actEnum) << std::endl;
				throw RTE_LOC;
			}

			if (actOut != comOut)
			{
				for (u64 i = 0; i < actOut.size(); ++i)
				{
					std::cout << i << " " << actOut[i] << " " << comOut[i] << std::endl;
				}
				throw RTE_LOC;
			}

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




	void composeEnum_sysExhaustive_Test(const CLP& cmd)
	{
		// testing G = repeat pi accumulate code
		// we will enumerator all pi.

		auto Ks = cmd.getManyOr<u64>("k", { 2, 3 });
		bool verbose = cmd.isSet("v");
		u64 numThreads = cmd.getOr("nt", std::thread::hardware_concurrency());
		//std::cout << "n: " << n << std::endl;

		for (auto k : Ks)
		{
			auto n = k + k;

			std::vector<Rat> actIn(k + 1);
			std::vector<Rat> actMid(k + 1);
			//std::vector<Rat> actOut(k + 1);
			std::vector<Rat> comOut(n + 1);
			std::vector<Rat> expOut(n + 1);
			std::vector<Rat> expOut2(n + 1);
			Matrix<Rat> acc0Enum(k + 1, k + 1);
			Matrix<Rat> acc1Enum(k + 1, k + 1);
			Matrix<Rat> expEnum(k + 1, n + 1);
			Matrix<Rat> comEnum(k + 1, n + 1);

			ChooseCache<Int> pas(n);
			for (u64 i = 0; i < actIn.size(); ++i)
			{
				actIn[i] = pas(k, i);
			}

			AccumulatorEnumerator<Int, Rat> acc0(k, k, pas);
			AccumulatorEnumerator<Int, Rat> acc1(k, k, pas);
			acc0.enumerate(actIn, actMid, acc0Enum);
			//acc1.enumerate(actMid, actOut, acc1Enum);

			ComposeEnumerator<Int, Rat> compose({
				&acc0,
				&acc0
				},true, pas);

			auto manualEnum = makeSystematic<Rat>(composeEnums<Rat>(acc0Enum, acc0Enum, pas));
			compose.enumerate(actIn, comOut, comEnum);

			auto A0 = acc0.getMtx();

			auto numPerms = fact<Int>(n);
			std::set<block> hashs;
			std::vector<u64> pi(k);
			std::iota(pi.begin(), pi.end(), 0);

			for (u64 i = 0; i < numPerms; ++i)
			{
				PointList pl(k, k);
				for (u64 j = 0; j < k; ++j)
					pl.push_back(pi[j], j);
				SparseMtx Pi(pl);
				SparseMtx G = A0 * Pi * A0;
				auto p = G.points();
				PointList pl2(k, n);
				for (u64 j = 0; j < k; ++j)
					pl2.push_back(j, j+k);
				for (auto pp : p)
					pl2.push_back(pp.mRow, pp.mCol);
				SparseMtx GG(pl2);

				for (u64 x = 0; x < (1ull << k); ++x)
				{

					auto w = popcount(x);
					//auto t = x | (x << k);
					//auto y = permute(t, pi);
					//auto f = y;
					//for (u64 i = 0; i < n - 1; ++i)
					//{
					//	auto b = f & (1ull << i);
					//	f = f ^ (b << 1);
					//}
					//auto h = popcount(f);

					std::vector<u8> xx(k);
					for (u64 i = 0; i < k; ++i)
						xx[i] = (x >> i) & 1;
					std::vector<u8> tt(k);
					A0.leftMultAdd(xx, tt);
		
					//for (u64 i = 0; i < n; ++i)
					//	if (tt[i] != ((t >> i) & 1))
					//	{
					//		std::cout << "error" << std::endl;
					//		throw RTE_LOC;
					//	}
					auto yy = permute(tt, pi);
					std::vector<u8> yy2(k);
					Pi.leftMultAdd(tt, yy2);
					if (yy != yy2)
						throw RTE_LOC;


					std::vector<u8> ff(k);
					A0.leftMultAdd(yy, ff);
					ff.insert(ff.end(), xx.begin(), xx.end());
					std::vector<u8> gg(n);
					GG.leftMultAdd(xx, gg);
					if (ff != gg)
						throw RTE_LOC;

					auto h = std::accumulate(ff.begin(), ff.end(), 0);
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
				std::cout << enumToString(acc0Enum) << std::endl;
				std::cout << "acc" << std::endl;
				std::cout << enumToString(acc1Enum) << std::endl;
				std::cout << "composed" << std::endl;
				std::cout << enumToString(manualEnum) << std::endl;

				std::cout << "brute force" << std::endl;
				std::cout << enumToString(expEnum) << std::endl;
			}

			if (expEnum != manualEnum)
			{
				throw RTE_LOC;
			}

			if (comEnum != manualEnum)
			{
				std::cout << enumToString(comEnum) << std::endl;
				std::cout << enumToString(manualEnum) << std::endl;
				throw RTE_LOC;
			}

			//if (actOut != comOut)
			//{
			//	for (u64 i = 0; i < actOut.size(); ++i)
			//	{
			//		std::cout << i << " " << actOut[i] << " " << comOut[i] << std::endl;
			//	}
			//	throw RTE_LOC;
			//}

			enumerate<Rat>(manualEnum, actIn, expOut2, pas);
			if (expOut != comOut || expOut != expOut2)
			{
				for (u64 i = 0; i < expOut.size(); ++i)
				{
					std::cout << i << " " << expOut[i] << " " << comOut[i] << "  " << expOut2[i] << std::endl;
				}
				throw RTE_LOC;
			}
		}
	}
}
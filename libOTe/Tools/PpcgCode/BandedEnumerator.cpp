#include "BandedEnumerator.h"
#include "cryptoTools/Common/BitVector.h"

namespace osuCrypto {

	namespace
	{
		bool increment(span<BitVector> bv)
		{
			for (u64 i = 0; i < bv.size(); ++i)
			{
				for (u64 j = 0; j < bv[i].size(); ++j)
				{
					if (bv[i][j] == 0)
					{
						bv[i][j] = 1;
						return true;
					}
					bv[i][j] = 0;
				}
			}
			return false;
		}

		void bandedMtxMultBit(
			span<BitVector> G,
			u64 x,
			span<u8> y,
			u64 k,
			u64 n,
			u64 sigma)
		{
			if (G.size() != k || y.size() != n)
				throw RTE_LOC;

			std::fill(y.begin(), y.end(), 0);
			for (u64 i = 0; i < k; ++i)
			{
				if (((x >> i) & 1) == 0)
					continue;

				auto rowWidth = std::min<u64>(sigma, n - i);
				if (G[i].size() != rowWidth)
					throw RTE_LOC;

				for (u64 j = 0; j < rowWidth; ++j)
					y[i + j] ^= u8(G[i][j]);
			}
		}
	}

	void BandedEnum_exhaustive_Test(const CLP& cmd)
	{
		u64 v = cmd.isSet("v");
		auto Ns = cmd.getManyOr<u64>("n", { 4, 5, 6 });
		auto Ks = cmd.getManyOr<u64>("k", { 3, 4, 4 });
		auto sigmas = cmd.getManyOr<u64>("sigma", { 2, 2, 3 });
		u64 numThreads = cmd.getOr("nt", std::thread::hardware_concurrency());

		if (Ns.size() != Ks.size() || Ns.size() != sigmas.size())
			throw RTE_LOC;

		for (u64 p = 0; p < Ns.size(); ++p)
		{
			auto n = Ns[p];
			auto k = Ks[p];
			auto sigma = sigmas[p];

			if (k > n || k >= 63 || sigma == 0)
				throw RTE_LOC;

			if (v)
			{
				std::cout << "n: " << n << std::endl;
				std::cout << "k: " << k << std::endl;
				std::cout << "sigma: " << sigma << std::endl;
			}

			std::vector<Rat> actIn(k + 1), actOut(n + 1), expOut(n + 1);
			Matrix<Rat> actEnum(k + 1, n + 1), expEnum(k + 1, n + 1);

			Choose<Int> pas(n + k + sigma + 2);
			BallsBinsCap<Int> bbc(n, k, sigma > 1 ? sigma - 2 : 0, pas);
			for (u64 i = 0; i <= k; ++i)
				actIn[i] = pas(k, i);

			BandedEnumerator<Int, Rat> band(k, n, sigma, pas, bbc, numThreads);
			band.enumerate(actIn, actOut, actEnum);

			std::vector<BitVector> Gbv(k);
			u64 size = 0;
			for (u64 i = 0; i < k; ++i)
			{
				Gbv[i].resize(std::min<u64>(sigma, n - i));
				size += Gbv[i].size();
			}

			std::vector<u8> y(n);
			do
			{
				for (u64 x = 0; x < (1ull << k); ++x)
				{
					bandedMtxMultBit(Gbv, x, y, k, n, sigma);
					auto w = popcount<u64>(x);
					u64 h = 0;
					for (auto yy : y)
						h += yy;
					expEnum(w, h) += 1;
				}
			} while (increment(Gbv));

			for (auto& e : expEnum)
			{
				e /= (Int(1) << size);
				e.backend().normalize();
			}

			if (expEnum != actEnum)
			{
				std::cout << "exhaustive" << std::endl;
				std::cout << enumToString(expEnum) << std::endl;
				std::cout << "formula" << std::endl;
				std::cout << enumToString(actEnum) << std::endl;
				throw RTE_LOC;
			}

			enumerate<Rat>(actEnum, actIn, expOut, pas);
			if (expOut != actOut)
			{
				for (u64 i = 0; i < expOut.size(); ++i)
					std::cout << i << " " << expOut[i] << " " << actOut[i] << std::endl;
				throw RTE_LOC;
			}
		}
	}

}

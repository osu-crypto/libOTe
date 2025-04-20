#include "BlockEnumerator.h"

namespace osuCrypto {




	std::string toString(span<const u8> x)
	{
		std::stringstream ss;
		for (auto xx : x)
			ss << int(xx) << ' ';
		return ss.str();
	}




	// Given a bit-packed representation of the block matrix G,
	// compute y = x * G.
	//
	// G should be in column major order with only sigmaK bits per column.
	// We do not express G as the full k by n matrix.
	template<typename T>
	void blockMtxMultBit(
		span<const T> G,
		span<const T> x,
		span<T> y,
		u64 k, u64 n, u64 sigmaK, u64 sigmaN)
	{
		if (G.size() != n)
			throw RTE_LOC;
		if (x.size() != k / sigmaK)
			throw RTE_LOC;
		if (y.size() != n)
			throw RTE_LOC;
		if (sigmaK > sizeof(T) * 8)
			throw RTE_LOC;

		u64 blocks = n / sigmaN;
		auto Giter = G.data();
		auto yIter = y.data();
		for (u64 i = 0; i < blocks; i++)
		{
			auto xi = x[i];
			for (u64 j = 0; j < sigmaN; j++)
			{
				*yIter++ = popcount(*Giter++ & xi) % 2;
			}
		}
	}


	// Given a compact representation of the block matrix G,
	// return a printable string of it 
	//
	// G should be in column major order with only sigmaK elements per column.
	// We do not express G as the full k by n matrix.
	template<typename T>
	std::string blockMtxToString(std::vector<T>& G, u64 k, u64 n)
	{
		std::stringstream ss;
		if (G.size() % k)
			throw RTE_LOC;
		if (n % k)
			throw RTE_LOC;

		auto e = n / k;
		auto sigma = G.size() / k;

		if (G.size() != n * sigma)
			throw RTE_LOC;

		MatrixView<T> GG(G.data(), n, sigma);
		auto iter = G.begin();
		for (u64 i = 0; i < k; ++i)
		{
			auto b = i / sigma;
			auto jb = b * sigma * e;
			auto je = (b + 1) * sigma * e;

			for (u64 j = 0; j < jb; ++j)
				ss << '0' << ' ';
			for (u64 j = jb; j < je; ++j)
				ss << int(GG(j, i % sigma)) << ' ';
			for (u64 j = je; j < n; ++j)
				ss << '0' << ' ';
			ss << std::endl;
		}
		ss << std::endl;
		return ss.str();
	}





	bool increment(span<u8> bv) {
		for (size_t i = 0; i < bv.size(); ++i) {
			if (bv[i] == 0) {
				bv[i] = 1;
				return 1;
			}
			else {
				bv[i] = 0;
			}
		}

		return 0;
	}

	// print a row major represetnation of the block matrix in 
	// compact form.
	template<typename T>
	std::string printStans(std::vector<T>& G, u64 k, u64 n)
	{
		std::stringstream ss;
		if (G.size() % k)
			throw RTE_LOC;
		if (n % k)
			throw RTE_LOC;

		auto e = n / k;
		auto sigma = G.size() / k;

		if (G.size() != n * sigma)
			throw RTE_LOC;

		auto iter = G.begin();
		for (u64 i = 0; i < k; ++i)
		{
			auto b = i / sigma;
			auto jb = b * sigma * e;
			auto je = (b + 1) * sigma * e;

			for (u64 j = 0; j < jb; ++j)
				ss << '0' << ' ';
			for (u64 j = jb; j < je; ++j)
				ss << int(*iter++) << ' ';
			for (u64 j = je; j < n; ++j)
				ss << '0' << ' ';
			ss << std::endl;
		}
		ss << std::endl;
		return ss.str();
	}


	// we will generate all G <- D and exhaustively
	// encode all c = x G and construct the enumerator.
	// We then compare this with the formula based enumerator.
	void blockEnum_exhaustive_Test(const CLP& cmd)
	{
		u64 v = cmd.isSet("v");
		auto Ns = cmd.getManyOr<u64>("n", { 8, 6 });
		auto Ks = cmd.getManyOr<u64>("k", { 4, 6 });
		auto sigmaKs = cmd.getManyOr<u64>("sigma", { 2,2 }); // window size
		//auto systematics = cmd.getManyOr<u64>("sys", { false, true }); // window size
		u64 numThreads = cmd.getOr("nt", std::thread::hardware_concurrency());

		if (Ns.size() != Ks.size() ||
			Ns.size() != sigmaKs.size())
			throw RTE_LOC;

		for (u64 p = 0; p < Ns.size(); ++p)
		{
			auto n = Ns[p];
			auto k = Ks[p];
			auto sigmaK = sigmaKs[p];

			if (v)
			{
				std::cout << "n: " << n << std::endl;
				std::cout << "k: " << k << std::endl;
				std::cout << "sigmaK: " << sigmaK << std::endl;
			}
			std::vector<Rat> actIn(k + 1);
			std::vector<Rat> actOut(n + 1);
			std::vector<Rat> sysOut(n + 1 + k);
			std::vector<Rat> expOut(n + 1);
			std::vector<Rat> expSysOut(n + k + 1);

			Matrix<Rat> actEnum(actIn.size(), actOut.size());
			Matrix<Rat> sysEnum(actIn.size(), sysOut.size());
			Matrix<Rat> expEnum(actIn.size(), actOut.size());

			auto sigmaN = n / k * sigmaK;
			auto q = n / sigmaK;

			if (k % sigmaK)
				throw RTE_LOC;
			if (n % sigmaN)
				throw RTE_LOC;

			ChooseCache<Int> pas(n);
			for (u64 i = 0; i < actIn.size(); ++i)
			{
				actIn[i] = pas(k, i);
			}

			BlockEnumerator<Int, Rat> blk(k, n, sigmaK, false, pas, pas);
			BlockEnumerator<Int, Rat>sys(k, n + k, sigmaK, true, pas, pas);

			blk.enumerate(actIn, actOut, actEnum);
			sys.enumerate(actIn, sysOut, sysEnum);

			std::vector<u8> Gbv(n * sigmaK);
			using T = u8;
			if (sigmaK > 8)
				throw std::runtime_error("we assume sigmaK bits it inside a T");
			std::vector<T> Gm(n);
			Matrix<T> Xs(1ull << k, k / sigmaK);
			T mask = (1ull << sigmaK) - 1;
			for (u64 i = 0; i < Xs.rows(); ++i)
			{
				for (u64 j = 0; j < Xs.cols(); ++j)
					Xs(i, j) = (i >> (j * sigmaK)) & mask;
			}

			auto z = std::vector<u8>(n);
			do
			{
				for (u64 i = 0; i < n; ++i)
				{
					Gm[i] = 0;
					for (u64 j = 0; j < sigmaK; ++j)
						Gm[i] |= Gbv[i * sigmaK + j] << j;
				}

				for (u64 x = 0; x < (1ull << k); ++x)
				{
					blockMtxMultBit<u8>(Gm, Xs[x], z, k, n, sigmaK, sigmaN);
					auto w = popcount(x);
					u64 h = 0;
					for (u64 j = 0; j < n; ++j)
						h += z[j];
					expEnum(w, h) += 1;
				}
			} while (increment(Gbv));

			for (u64 i = 0; i < expEnum.size(); ++i)
			{
				expEnum(i) = expEnum(i) / (Int(1) << Gbv.size());
				expEnum(i).backend().normalize();
			}

			if (expEnum != actEnum)
			{
				for (u64 i = 0; i < expEnum.rows(); ++i)
				{
					for (u64 j = 0; j < expEnum.cols(); ++j)
					{
						if (expEnum(i, j) != actEnum(i, j))
						{
							std::cout << Color::Red;
						}
						std::cout << "------------" << std::endl;
						std::cout << "exp " << expEnum(i, j) << ", act " << actEnum(i, j) << std::endl;

						if (expEnum(i, j) != actEnum(i, j))
						{
							std::cout << Color::Default;
						}
					}
				}

				throw RTE_LOC;
			}

			if (v)
			{
				std::cout << enumToString(expEnum) << std::endl;;
				std::cout << enumToString(sysEnum) << std::endl;;
			}

			auto expSysEnum = makeSystematic<Rat>(expEnum);
			if (expSysEnum != sysEnum)
			{
				std::cout << enumToString(expSysEnum) << std::endl;
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



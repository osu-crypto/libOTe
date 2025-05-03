#include "RandomEnumerator.h"

namespace osuCrypto {




	std::string toString(span<const u8> x);


	// Given a bit-packed representation of the block matrix G,
	// compute y = x * G.
	//
	// G should be in column major order with only sigmaK bits per column.
	// y will be one bit per byte. n bytes...
	void RandomMtxMultBit(
		Matrix<u8> G,
		span<u8> x,
		span<u8> y,
		u64 k, u64 n)
	{
		if (G.rows() != n)
			throw RTE_LOC;
		if (x.size() != divCeil(k, sizeof(u8) * 8))
			throw RTE_LOC;
		if (G.cols() != x.size())
			throw RTE_LOC;
		if (y.size() != n)
			throw RTE_LOC;

		auto Giter = G.data();
		auto yIter = y.data();
		for (u64 i = 0; i < n; i++)
		{
			for (u64 j = 0; j < x.size(); j++)
			{
				*yIter++ = popcount(*Giter++ & x[j]) % 2;
			}
		}
	}

	namespace
	{

		bool increment(Matrix<u8>& G, u64 k) {

			for (size_t i = 0; i < G.rows(); ++i) 
			{
				BitIterator bv(G.data(i));
				for (u64 j = 0; j < k; ++j)
				{

					if (*bv == 0) {
						*bv = 1;
						return 1;
					}
					else {
						*bv = 0;
					}

					++bv;
				}
			}
			return 0;
		}

	}


	// we will generate all G <- D and exhaustively
	// encode all c = x G and construct the enumerator.
	// We then compare this with the formula based enumerator.
	void RandomEnum_exhaustive_Test(const CLP& cmd)
	{
		u64 v = cmd.isSet("v");
		auto Ns = cmd.getManyOr<u64>("n", { 2, 4, 4 });
		auto Ks = cmd.getManyOr<u64>("k", { 2, 4, 2 });
		u64 numThreads = cmd.getOr("nt", std::thread::hardware_concurrency());

		if (Ns.size() != Ks.size())
			throw RTE_LOC;

		for (u64 p = 0; p < Ns.size(); ++p)
		{
			auto n = Ns[p];
			auto k = Ks[p];

			if (v)
			{
				std::cout << "n: " << n << std::endl;
				std::cout << "k: " << k << std::endl;
			}
			std::vector<Rat> actIn(k + 1);
			std::vector<Rat> actOut(n + 1);
			std::vector<Rat> sysOut(n + 1 + k);
			std::vector<Rat> expOut(n + 1);
			std::vector<Rat> expSysOut(n + k + 1);

			Matrix<Rat> actEnum(actIn.size(), actOut.size());
			Matrix<Rat> sysEnum(actIn.size(), sysOut.size());
			Matrix<Rat> expEnum(actIn.size(), actOut.size());

			Choose<Int> pas(n);
			for (u64 i = 0; i < actIn.size(); ++i)
			{
				actIn[i] = pas(k, i);
			}

			RandomEnumerator<Int, Rat> blk(k, n, false, pas);
			RandomEnumerator<Int, Rat> sys(k, n + k, true, pas);

			blk.enumerate(actIn, actOut, actEnum);
			sys.enumerate(actIn, sysOut, sysEnum);

			Matrix<u8> Gbv(n, divCeil(k, 8));
			Matrix<u8> Xs(1ull << k, divCeil(k, 8));
			u64 mask = (1ull << k) - 1;
			for (u64 i = 0; i < Xs.rows(); ++i)
			{
				for (u64 j = 0; j < Xs.cols(); ++j)
					Xs(i, j) = (i & mask) >> (j * 8);
			}

			u64 size = 0;
			auto y = std::vector<u8>(n);
			do
			{
				for (u64 x = 0; x < (1ull << k); ++x)
				{
					RandomMtxMultBit(Gbv, Xs[x], y, k, n);
					auto w = popcount(x);
					u64 h = 0;
					for (u64 j = 0; j < n; ++j)
						h += y[j];
					expEnum(w, h) += 1;
				}
				++size;
			} while (increment(Gbv, k));

			if (size != 1ull << (n * k))
				throw RTE_LOC;

			for (u64 i = 0; i < expEnum.size(); ++i)
			{
				expEnum(i) = expEnum(i) / (Int(1) << (n * k));
				expEnum(i).backend().normalize();
			}

			if (expEnum != actEnum)
			{
				std::cout << "exhaustive" << std::endl;
				std::cout << enumToString(expEnum) << std::endl;
				std::cout << "formula" << std::endl;
				std::cout << enumToString(actEnum) << std::endl;

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



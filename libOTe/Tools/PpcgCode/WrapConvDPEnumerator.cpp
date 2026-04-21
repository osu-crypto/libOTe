#include "WrapConvDPEnumerator.h"

#include "WrapConvEnumerator.h"

#include "cryptoTools/Common/BitVector.h"

namespace osuCrypto
{
	// shared simulator from RandConvEnumerator.cpp
	void randConvMultBit(span<u8> C, span<u8> x, span<u8> y, u64 k, u64 n, u64 sigma, bool v);

	namespace
	{
		bool incrementWrap(span<BitVector> bv, u64 sigma)
		{
			for (size_t i = 0; i < bv.size(); ++i)
			{
				if (bv[i].size())
				{
					for (u64 j = 0; j < std::min<u64>(bv[i].size(), sigma - 1); ++j)
					{
						if (bv[i][j] == 0)
						{
							bv[i][j] = 1;
							return true;
						}
						bv[i][j] = 0;
					}
				}
			}
			return false;
		}

		void compareMatrices(MatrixView<Rat> lhs, MatrixView<Rat> rhs)
		{
			if (lhs.rows() != rhs.rows() || lhs.cols() != rhs.cols())
				throw RTE_LOC;

			for (u64 i = 0; i < lhs.rows(); ++i)
			{
				for (u64 j = 0; j < lhs.cols(); ++j)
				{
					auto a = lhs(i, j);
					auto b = rhs(i, j);
					a.backend().normalize();
					b.backend().normalize();
					if (a != b)
					{
						std::cout << "matrix mismatch at (" << i << ", " << j << "): "
							<< a << " != " << b << std::endl;
						throw RTE_LOC;
					}
				}
			}
		}

		void compareVectors(span<Rat> lhs, span<Rat> rhs)
		{
			if (lhs.size() != rhs.size())
				throw RTE_LOC;

			for (u64 i = 0; i < lhs.size(); ++i)
			{
				auto a = lhs[i];
				auto b = rhs[i];
				a.backend().normalize();
				b.backend().normalize();
				if (a != b)
				{
					std::cout << "vector mismatch at " << i << ": "
						<< a << " != " << b << std::endl;
					throw RTE_LOC;
				}
			}
		}

		Matrix<Rat> bruteWrapEnum(u64 k, u64 n, u64 sigma)
		{
			if (k > n)
				throw RTE_LOC;

			Matrix<Rat> expEnum(k + 1, n + 1);
			for (auto& v : expEnum)
				v = Rat(0);

			Choose<Int> choose(2 * n + 8);

			u64 size = 0;
			std::vector<BitVector> Gbv(n);
			for (u64 i = 0; i < n; ++i)
			{
				Gbv[i].resize(std::min(i, sigma));
				size += std::max<i64>(0, std::min<i64>(Gbv[i].size(), sigma - 1));
				if (Gbv[i].size() == sigma)
					Gbv[i].back() = 1;
			}

			std::vector<u8> Gm(n, 0);
			std::vector<u8> xBytes(divCeil(k, 8), 0);
			std::vector<u8> y(n, 0);
			do
			{
				for (u64 i = 0; i < n; ++i)
				{
					Gm[i] = 0;
					for (u64 j = 0; j < Gbv[i].size(); ++j)
						Gm[i] |= u8(Gbv[i][j]) << j;
				}

				for (u64 x = 0; x < (u64(1) << k); ++x)
				{
					std::fill(xBytes.begin(), xBytes.end(), 0);
					for (u64 i = 0; i < k; ++i)
						xBytes[i / 8] |= u8((x >> i) & 1) << (i % 8);

					randConvMultBit(Gm, xBytes, y, k, n, sigma, false);

					auto w = popcount(x);
					u64 h = 0;
					for (auto yi : y)
						h += yi;
					expEnum(w, h) += 1;
				}
			} while (incrementWrap(Gbv, sigma));

			auto denom = Int(1) << size;
			for (auto& v : expEnum)
			{
				v /= denom;
				v.backend().normalize();
			}

			return expEnum;
		}
	}

	void WrapConvDP_compare_Test(const CLP& cmd)
	{
		auto Ns = cmd.getManyOr<u64>("n", { 8, 12, 16 });
		auto Ks = cmd.getManyOr<u64>("k", { 8, 12, 16 });
		auto sigmas = cmd.getManyOr<u64>("sigma", { 2, 3, 4 });

		if (Ns.size() != Ks.size() || Ns.size() != sigmas.size())
			throw RTE_LOC;

		for (u64 p = 0; p < Ns.size(); ++p)
		{
			auto n = Ns[p];
			auto k = Ks[p];
			auto sigma = sigmas[p];

			Choose<Int> choose(2 * n + 8);
			BallsBinsCap<Int> bbc(n, n, sigma - 2, choose);

			std::vector<Rat> inDist(k + 1), outOld(n + 1), outDp(n + 1);
			for (u64 w = 0; w <= k; ++w)
				inDist[w] = choose(k, w);

			Matrix<Rat> fullOld(k + 1, n + 1), fullDp(k + 1, n + 1);

			WrapConvEnumerator<Int, Rat> oldEnum(k, n, sigma, choose, bbc);
			WrapConvDPEnumerator<Int, Rat> dpEnum(k, n, sigma, choose);

			oldEnum.enumerate(inDist, outOld, fullOld);
			dpEnum.enumerate(inDist, outDp, fullDp);

			compareMatrices(fullOld, fullDp);
			compareVectors(outOld, outDp);
		}
	}

	void WrapConvDP_exhaustive_Test(const CLP& cmd)
	{
		auto Ns = cmd.getManyOr<u64>("n", { 5, 6, 7 });
		auto Ks = cmd.getManyOr<u64>("k", { 4, 4, 5 });
		auto sigmas = cmd.getManyOr<u64>("sigma", { 2, 3, 2 });

		if (Ns.size() != Ks.size() || Ns.size() != sigmas.size())
			throw RTE_LOC;

		for (u64 p = 0; p < Ns.size(); ++p)
		{
			auto n = Ns[p];
			auto k = Ks[p];
			auto sigma = sigmas[p];

			Choose<Int> choose(2 * n + 8);
			std::vector<Rat> inDist(k + 1), outDp(n + 1), outExp(n + 1);
			for (u64 w = 0; w <= k; ++w)
				inDist[w] = choose(k, w);

			Matrix<Rat> fullDp(k + 1, n + 1);
			WrapConvDPEnumerator<Int, Rat> dpEnum(k, n, sigma, choose);
			dpEnum.enumerate(inDist, outDp, fullDp);

			auto fullExp = bruteWrapEnum(k, n, sigma);
			for (u64 h = 0; h <= n; ++h)
			{
				Rat sum = 0;
				for (u64 w = 0; w <= k; ++w)
					sum += fullExp(w, h);
				outExp[h] = sum;
			}

			compareMatrices(fullDp, fullExp);
			compareVectors(outDp, outExp);
		}
	}
}

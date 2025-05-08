#include "RandConvEnumerator.h"
#include "BallsBins.h"

namespace osuCrypto {



	// each C[i] is the i-th convolution vector.
	// i.e. y[i] = C[i] * y[i - [sigma]] + x[i].
	void randConvMultBit(span<u8> C, span<u8> x, span<u8> y, u64 k, u64 n, u64 sigma, bool v = false)
	{
		if (k != n)
			throw RTE_LOC;
		if (sigma > 8)
			throw RTE_LOC;
		u8 yPrev = 0;
		for (u64 i = 0; i < n; ++i)
		{
			u8 xi = (x[i / 8] >> (i % 8)) & 1;

			if (v)
			{
				std::cout << "x" << i << " " << int(xi) << std::endl;;
				std::cout << "p" << i << " ";
				for (u64 j = 0; j < sigma; ++j)
					std::cout << (int(yPrev >> j) & 1) << " ";
				std::cout << std::endl;

				std::cout << "c" << i << " ";
				for (u64 j = 0; j < sigma; ++j)
					std::cout << (int(C[i] >> j) & 1) << " ";
				std::cout << std::endl;
			}

			y[i] = xi ^ (popcount<u8>(yPrev & C[i]) & 1);
			yPrev <<= 1;
			yPrev |= y[i];


			if (v)
			{
				std::cout << "y" << i << " " << int(y[i]) << std::endl << std::endl;;
			}
		}
	}


	bool increment(span<BitVector> bv) {
		for (size_t i = 0; i < bv.size(); ++i) {
			for (u64 j = 0; j < bv[i].size(); ++j)
			{
				if (bv[i][j] == 0) {
					bv[i][j] = 1;
					return 1;
				}
				else {
					bv[i][j] = 0;
				}
			}
		}

		return 0;
	}


	//void computeRT(span<u8> y, u64 sigma, u64& r, u64& t, bool v = false)
	//{
	//	//u64 qi = 0;
	//	//u64 termCount = 0;
	//	//r = 0;
	//	//t = 0;
	//	//for (u64 i = 0; i < y.size(); ++i)
	//	//{
	//	//	assert(y[i] < 2);
	//	//	if (qi == 0 && y[i])
	//	//	{
	//	//		qi = 1;
	//	//		++r;
	//	//	}

	//	//	if (qi)
	//	//	{
	//	//		if (y[i] == 0)
	//	//		{
	//	//			++t;
	//	//			++termCount;
	//	//		}
	//	//		else
	//	//		{
	//	//			termCount = 0;
	//	//		}
	//	//	}

	//	//	if (termCount == sigma+1)
	//	//	{
	//	//		t -= sigma;
	//	//		qi = 0;
	//	//		termCount = 0;
	//	//	}
	//	//}

	//	std::vector<u8> q(y.size());
	//	std::vector<u8> term(y.size());
	//	//std::vector<u8> start(y.size());

	//	t = 0;
	//	r = 0;
	//	for (u64 i = 0; i < y.size(); ++i)
	//	{
	//		// the previous sigma outputs
	//		auto b = std::max<i64>(i - sigma, 0);
	//		auto e = i;
	//		span<u8> prev = y.subspan(b, e - b);


	//		auto pSum = std::accumulate(prev.begin(), prev.end(), 0);
	//		q[i] = pSum ? 1 : 0;

	//		// the current sigma outputs
	//		auto b_ = std::max<i64>(i - sigma + 1, 0);
	//		auto e_ = i + 1;
	//		span<u8> cur = y.subspan(b_, e_ - b_);

	//		// is the current range terminating.
	//		auto cSum = std::accumulate(cur.begin(), cur.end(), 0);
	//		if (i && cSum == 0 && q[i])
	//		{
	//			for (u64 j = b_; j < e_; ++j)
	//			{
	//				term[j] = 1;
	//				--t;
	//			}
	//		}

	//		r += y[i] == 1 && q[i] == 0;
	//		t += y[i] == 0 && q[i] == 1;
	//	}
	//}

	void getRT(span<u8>y, u64 sigma,
		u64& r, u64& t, bool v = false, span<u8> x = {})

	{
		std::vector<u8> q(y.size());
		std::vector<u8> term(y.size());
		std::vector<u8> start(y.size());
		r = 0;
		t = 0;


		for (u64 i = 0; i < y.size(); ++i)
		{
			// the previous sigma outputs
			auto b = std::max<i64>(i - sigma, 0);
			auto e = i;
			span<u8> prev = y.subspan(b, e - b);


			auto pSum = std::accumulate(prev.begin(), prev.end(), 0);
			q[i] = pSum ? 1 : 0;

			// the current sigma outputs
			auto b_ = std::max<i64>(i - sigma + 1, 0);
			auto e_ = i + 1;
			span<u8> cur = y.subspan(b_, e_ - b_);

			// is the current range terminating.
			auto cSum = std::accumulate(cur.begin(), cur.end(), 0);
			if (i && cSum == 0 && q[i])
			{
				for (u64 j = b_; j < e_; ++j)
				{
					term[j] = 1;
					--t;
				}
			}

			start[i] = y[i] == 1 && q[i] == 0;

			r +=
				(y[i] == 1 && q[i] == 0) ||
				(q[i] == 1 && cSum == 0);
			t += y[i] == 0 && q[i] == 1;
		}

		if (v)
		{

			std::cout << "x: ";
			for (u64 i = 0; i < x.size(); ++i)
			{
				if (start[i])
					std::cout << Color::Blue;
				if (q[i])
					std::cout << Color::Red;
				std::cout << int(x[i]);
				std::cout << Color::Default;
			}

			std::cout << "\ny: ";
			for (u64 i = 0; i < x.size(); ++i)
			{
				if (start[i])
					std::cout << Color::Blue;
				if (q[i])
					std::cout << Color::Red;
				if (term[i])
					std::cout << Color::Green;
				std::cout << int(y[i]);
				std::cout << Color::Default;
			}

			std::cout << "\nq: ";
			for (u64 i = 0; i < x.size(); ++i)
			{
				std::cout << int(q[i]);
			}

			std::cout << "\nt: ";
			for (u64 i = 0; i < x.size(); ++i)
			{
				std::cout << int(term[i]);
			}
			std::cout << "\ns: ";
			for (u64 i = 0; i < x.size(); ++i)
			{
				std::cout << int(start[i]);
			}
			std::cout << std::endl;
			auto w = std::accumulate(x.begin(), x.end(), 0);
			auto h = std::accumulate(y.begin(), y.end(), 0);
			std::cout << "w " << w << " h " << h << " r " << r << " t " << t << std::endl;

			std::cout << std::endl;
		}
	}

	// we will generate all G <- D and exhaustively
	// encode all c = x G and construct the enumerator.
	// We then compare this with the formula based enumerator.
	void RandConvEnum_single_Test(const CLP& cmd)
	{
		u64 v = cmd.isSet("v");
		auto Ns = cmd.getManyOr<u64>("n", { 4, 4 });
		auto Ks = cmd.getManyOr<u64>("k", { 4, 4 });
		auto sigmas = cmd.getManyOr<u64>("sigma", { 1,2 }); // window size
		//auto systematics = cmd.getManyOr<u64>("sys", { false, true }); // window size
		u64 numThreads = cmd.getOr("nt", std::thread::hardware_concurrency());

		if (Ns.size() != Ks.size() ||
			Ns.size() != sigmas.size())
			throw RTE_LOC;

		for (u64 p = 0; p < Ns.size(); ++p)
		{
			auto n = Ns[p];
			auto k = Ks[p];
			auto sigma = sigmas[p];

			if (v)
			{
				std::cout << "n: " << n << std::endl;
				std::cout << "k: " << k << std::endl;
				std::cout << "sigma: " << sigma << std::endl;
			}

			// k by n by r by t0
			Matrix<Matrix<Rat>> expEnum(k + 1, n + 1);
			u64 rMax = n;// / sigma;
			for (auto& expEnumRT : expEnum)
				expEnumRT.resize(rMax + 1, n);

			Choose<Int> pas(n + n);
			BallsBinsCap<Int> bbc(n, n, sigma - 1, pas);

			u64 size = 0;
			std::vector<BitVector> Gbv(n);
			for (u64 i = 0; i < n; ++i)
			{
				Gbv[i].resize(std::min(i, sigma));
				size += Gbv[i].size();
			}
			using T = u8;
			if (sigma > 8)
				throw std::runtime_error("we assume sigma bits it inside a T");
			std::vector<T> Gm(n);
			Matrix<T> Xs(1ull << k, divCeil(sigma, 8));
			T mask = (1ull << sigma) - 1;
			for (u64 i = 0; i < Xs.rows(); ++i)
			{
				copyBytesMin(Xs[i], i);
			}

			auto z = std::vector<u8>(n);
			do
			{
				PointList pl(k, n);
				auto G = DenseMtx::Identity(n);

				for (u64 i = 0; i < n; ++i)
				{
					pl.push_back(i, i);
					PointList pli(k, n);
					for (u64 j = 0; j < n; ++j)
						pli.push_back(j, j);
					Gm[i] = 0;
					for (u64 j = 0; j < Gbv[i].size(); ++j)
					{
						Gm[i] |= T(Gbv[i][j]) << j;
						if (Gbv[i][j])
						{
							pl.push_back(i - j - 1, i);
							pli.push_back(i - j - 1, i);
						}
					}

					SparseMtx Gi(pli);
					G = G * Gi.dense();
				}
				auto GG = G.sparse();

				std::vector<u8> xx(k), yy(n);
				for (u64 x = 0; x < (1ull << k); ++x)
				{

					randConvMultBit(Gm, Xs[x], z, k, n, sigma);
					auto w = popcount<u8>(x);
					u64 h = 0;
					for (u64 j = 0; j < n; ++j)
						h += z[j];

					u64 r, t0;
					getRT(z, sigma, r, t0);

					if (0)
					{
						for (u64 w = 0; w < k; ++w)
						{
							xx[w] = (x >> w) & 1;
						}


						std::fill(yy.begin(), yy.end(), 0);
						GG.leftMultAdd(xx, yy);
						getRT(yy, sigma, r, t0, 1, xx);

						if (yy != z)
						{

							SparseMtx sp(pl);
							std::cout << "-------" << std::endl;
							std::cout << sp << std::endl << std::endl;
							std::cout << G << std::endl << std::endl;

							std::cout << "x ";
							for (u64 j = 0; j < k; ++j)
								std::cout << int(xx[j]) << " ";
							std::cout << std::endl;
							std::cout << "y ";
							for (u64 j = 0; j < n; ++j)
								std::cout << int(yy[j]) << " ";
							std::cout << std::endl;
							randConvMultBit(Gm, Xs[x], z, k, n, sigma, true);

							throw RTE_LOC;
						}
					}

					expEnum(w, h)(r, t0) += 1;

				}
			} while (increment(Gbv));


			for (auto& E : expEnum)
			{
				for (auto& ERT : E)
				{
					ERT = ERT / (Int(1) << size);
					ERT.backend().normalize();
				}
			}

			for (u64 w = 0; w < k; ++w)
			{
				for (u64 h = 0; h < n; ++h)
				{
					for (u64 r = 0; r < rMax; ++r)
					{
						for (u64 t0 = 0; t0 < n; ++t0)
						{
							auto Ewhrt = RandConvEnumerator<Int, Rat>::enumerate(w, h, r, t0, k, n, sigma, pas, bbc);
							Ewhrt.backend().normalize();

							if (Ewhrt != expEnum(w, h)(r, t0))
							{
								std::cout << "w " << w << " h " << h << " r " << r << " t " << t0 << std::endl;

								std::cout << "exhaustive " << expEnum(w, h)(r, t0) << std::endl;
								std::cout << "formula    " << Ewhrt << std::endl;



								auto r1 = divCeil(r, 2);
								auto r0 = r - r1;

								i64 v = n - h - t0 - r0 * sigma;
								i64 s = n - r1 - v;

								auto E1 = pas(h - 1, r1 - 1);
								auto E2 = ballsBinsCap(t0, h - r0, sigma - 1, pas);
								auto E3 = ballsBins(v, r0 + 1, pas);
								auto E4 = pas(n - r1 - v, w - r1);
								std::cout << "E1 " << E1 << " = " << i64(h - 1) << " choose " << i64(r1 - 1) << " ways to start runs" << std::endl;
								std::cout << "E2 " << E2 << " = Cap(" << t0 << ", " << i64(h - r0) << ", " << sigma - 1 << ") ways to assign t0 freezone output 0s." << std::endl;
								std::cout << "E3 " << E3 << " = B(" << v << ", " << r0 + 1 << ") ways to assign deazones" << std::endl;
								std::cout << "E4 " << E4 << " = " << i64(n - r1 - v) << " choose " << i64(w - r1) << " ways to assign input freezones" << std::endl;
								std::cout << "Sc " << pow2_<Int>(s) << " = 2^" << s << " scaling" << std::endl;


								throw RTE_LOC;
							}
						}
					}
				}
			}
		}
	}


	// we will generate all G <- D and exhaustively
	// encode all c = x G and construct the enumerator.
	// We then compare this with the formula based enumerator.
	void RandConvEnum_exhaustive_Test(const CLP& cmd)
	{
		u64 v = cmd.isSet("v");
		auto Ns = cmd.getManyOr<u64>("n", { 4, 6, 6 });
		auto Ks = cmd.getManyOr<u64>("k", { 4, 6, 6 });
		auto sigmas = cmd.getManyOr<u64>("sigma", { 1,2, 3 }); // window size
		//auto systematics = cmd.getManyOr<u64>("sys", { false, true }); // window size
		u64 numThreads = cmd.getOr("nt", std::thread::hardware_concurrency());

		if (Ns.size() != Ks.size() ||
			Ns.size() != sigmas.size())
			throw RTE_LOC;

		for (u64 p = 0; p < Ns.size(); ++p)
		{
			auto n = Ns[p];
			auto k = Ks[p];
			auto sigma = sigmas[p];

			if (v)
			{
				std::cout << "n: " << n << std::endl;
				std::cout << "k: " << k << std::endl;
				std::cout << "sigma: " << sigma << std::endl;
			}
			std::vector<Rat> actIn(k + 1);
			std::vector<Rat> actOut(n + 1);
			//std::vector<Rat> sysOut(n + 1 + k);
			std::vector<Rat> expOut(n + 1);
			//std::vector<Rat> expSysOut(n + k + 1);

			Matrix<Rat> actEnum(actIn.size(), actOut.size());
			//Matrix<Rat> sysEnum(actIn.size(), sysOut.size());
			Matrix<Rat> expEnum(actIn.size(), actOut.size());

			Choose<Int> pas(2*n);
			BallsBinsCap<Int> bbc(n, n, sigma - 1, pas);

			RandConvEnumerator<Int, Rat> blk(k, n, sigma, pas, bbc);
			//RandConvEnumerator<Int, Rat>sys(k, n + k, sigma, pas, pas);

			blk.enumerate(actIn, actOut, actEnum);
			//sys.enumerate(actIn, sysOut, sysEnum);

			// 0
			// 00
			// xss
			// 0xss
			// 00xss
			// 000xs
			// 0000x


			// s + s-1 +s -2 +...+s-(s-1)
			// s^2 0 
			u64 size = 0;// n* sigma - sigma * (sigma - 1) / 2;
			std::vector<BitVector> Gbv(n);
			for (u64 i = 0; i < n; ++i)
			{
				Gbv[i].resize(std::min(i, sigma));
				size += Gbv[i].size();
			}
			using T = u8;
			if (sigma > 8)
				throw std::runtime_error("we assume sigma bits it inside a T");
			std::vector<T> Gm(n);
			Matrix<T> Xs(1ull << k, divCeil(sigma, 8));
			T mask = (1ull << sigma) - 1;
			for (u64 i = 0; i < Xs.rows(); ++i)
			{
				copyBytesMin(Xs[i], i);
			}

			auto y = std::vector<u8>(n);
			do
			{
				for (u64 i = 0; i < n; ++i)
				{
					Gm[i] = 0;
					for (u64 j = 0; j < Gbv[i].size(); ++j)
					{
						Gm[i] |= T(Gbv[i][j]) << j;
					}
				}
				//PointList pl(k, n);
				//auto G = DenseMtx::Identity(n);
				//for (u64 i = 0; i < n; ++i)
				//{
				//	pl.push_back(i, i);
				//	PointList pli(k, n);
				//	for (u64 j = 0; j < n; ++j)
				//		pli.push_back(j, j);
				//	for (u64 j = 0; j < Gbv[i].size(); ++j)
				//	{
				//		if (Gbv[i][j])
				//		{
				//			pl.push_back(i - j - 1, i);
				//			pli.push_back(i - j - 1, i);
				//		}
				//	}
				//	SparseMtx Gi(pli);
				//	G = G * Gi.dense();
				//}
				//auto GG = G.sparse();

				std::vector<u8> xx(k), yy(n);
				for (u64 x = 0; x < (1ull << k); ++x)
				{

					randConvMultBit(Gm, Xs[x], y, k, n, sigma);
					auto w = popcount(x);
					u64 h = 0;
					for (u64 j = 0; j < n; ++j)
						h += y[j];
					expEnum(w, h) += 1;

					//{
					//	for (u64 w = 0; w < k; ++w)
					//	{
					//		xx[w] = (x >> w) & 1;
					//	}

					//	std::fill(yy.begin(), yy.end(), 0);
					//	GG.leftMultAdd(xx, yy);

					//	if (yy != y)
					//	{

					//		SparseMtx sp(pl);
					//		std::cout << "-------" << std::endl;
					//		std::cout << sp << std::endl << std::endl;
					//		std::cout << G << std::endl << std::endl;

					//		std::cout << "x ";
					//		for (u64 j = 0; j < k; ++j)
					//			std::cout << int(xx[j]) << " ";
					//		std::cout << std::endl;
					//		std::cout << "y ";
					//		for (u64 j = 0; j < n; ++j)
					//			std::cout << int(yy[j]) << " ";
					//		std::cout << std::endl;
					//		randConvMultBit(Gm, Xs[x], y, k, n, sigma, true);

					//		throw RTE_LOC;
					//	}
					//}
				}
			} while (increment(Gbv));

			for (u64 i = 0; i < expEnum.size(); ++i)
			{
				expEnum(i) = expEnum(i) / (Int(1) << size);
				expEnum(i).backend().normalize();
			}

			if (expEnum != actEnum)
			{
				std::cout << "exp " << std::endl;
				std::cout << enumToString(expEnum) << std::endl;;
				std::cout << "formula " << std::endl;
				std::cout << enumToString(actEnum) << std::endl;;

				throw RTE_LOC;
			}

			if (v)
			{

				std::cout << "exp " << std::endl;
				std::cout << enumToString(expEnum) << std::endl;;
				std::cout << "formula " << std::endl;
				std::cout << enumToString(actEnum) << std::endl;;
				//std::cout << enumToString(expEnum) << std::endl;;
				//std::cout << enumToString(sysEnum) << std::endl;;
			}

			//auto expSysEnum = makeSystematic<Rat>(expEnum);
			//if (expSysEnum != sysEnum)
			//{
			//	std::cout << enumToString(expSysEnum) << std::endl;
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



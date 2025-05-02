#include "WrapConvEnumerator.h"
#include "BallsBins.h"

namespace osuCrypto {



	// each C[i] is the i-th convolution vector.
	// i.e. y[i] = C[i] * y[i - [sigma]] + x[i].
	void randConvMultBit(span<u8> C, span<u8> x, span<u8> y, u64 k, u64 n, u64 sigma, bool v = false);

	namespace
	{

		bool increment(span<BitVector> bv, u64 sigma) {
			for (size_t i = 0; i < bv.size(); ++i) {
				if (bv[i].size())
				{
					//bv[i][bv[i].size() - 1] = 1;
					for (u64 j = 0; j < std::min<u64>(bv[i].size(), sigma - 1); ++j)
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
			}

			return 0;
		}

	}

	//void computeRT(span<u8> y, u64 sigma, u64& r, u64& t, bool verbose = false)
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

	// r = number of runs transitions
	// t = number of terminations
	// v = number of almost terminations
	// d = is there trailing zone
	void getRTVD(span<u8>y, u64 sigma,
		u64& r, u64& t0, u64& v, u64& d, bool verbose = false, span<u8> x = {})

	{
		//std::vector<u8> q(y.size() * verbose);
		//std::vector<u8> term(y.size() * verbose);
		//std::vector<u8> start(y.size() * verbose);


		auto isOn = [&](i64 i)
			{
				auto onB = std::max<i64>(i - sigma, 0);
				auto onE = i;
				span<u8> onRange = y.subspan(onB, std::max<i64>(0, onE - onB));
				return std::accumulate(onRange.begin(), onRange.end(), 0) != 0;
			};

		// x ****1
		// y 10000
		auto isTerm = [&](i64 i) {

			if (i < sigma)
				return false;


			auto b = i - sigma;
			if (y[b] != 1)
				return false;
			for (u64 j = b + 1; j < i; ++j)
				if (y[j] != 0)
					return false;
			if (y[i] != 0)
				return false;
			if (x.size() && x[i] == 0)
				throw RTE_LOC;

			return true;
			};

		// x ****0
		// y 10001
		auto isNearTerm = [&](i64 i) {

			if (i < sigma)
				return false;

			auto b = i - sigma;
			if (y[b] != 1)
				return false;
			for (u64 j = b + 1; j < i; ++j)
				if (y[j] != 0)
					return false;
			if (y[i] != 1)
				return false;
			if (x.size() && x[i] == 1)
				throw RTE_LOC;

			return true;
			};

		// x ****|
		// y 1000|
		auto isTrailing = [&](i64 i) {

			if (i != y.size() - 1)
				return false;
			if (i < sigma - 1)
				return false;

			auto b = i - sigma + 1;
			if (y[b] != 1)
				return false;
			for (u64 j = b + 1; j <= i; ++j)
				if (y[j] != 0)
					return false;

			return true;
			};


		// y = 1*****100
		// y = 1010000000
		// T = 00^^^^^000
		// t = 0000001000
		//         ^
		// f =   11111
		//     10000
		//        10000


		// the the next sigma positions contain pred
		auto scan = [&](u64 i, auto&& pred, u64 size = 0) {
			if (size == 0)
				size = sigma + 1;
			for (u64 j = i;
				j < std::min<i64>(i + size, y.size());
				++j)
			{
				if (pred(j))
					return true;
			}
			return false;
			};

		auto isT0 = [&](u64 i) {

			return isOn(i) == 1 &&
				y[i] == 0 &&
				!scan(i, isTerm) &&
				!scan(i, isNearTerm) &&
				!scan(i, isTrailing, sigma);
			};

		r = isTerm(y.size() - 1) ||
			isOn(y.size() - 1) == false && y.back() == 1;
		t0 = 0;
		v = 0;

		auto dB = std::max<i64>(y.size() - sigma, 0);
		auto dE = y.size();
		auto dRange = y.subspan(dB, dE - dB);
		d = isTrailing(y.size() - 1);

		bool prevOn = 0;
		//std::cout << "x y o p r t v " << std::endl;

		for (i64 i = 0; i < y.size(); ++i)
		{
			// the previous sigma outputs
			//auto prevOn = isOn(i - 1);
			auto on = isOn(i);
			auto term = isTerm(i);
			auto nearTerm = isNearTerm(i);
			auto rr = on ^ prevOn;
			auto t0i = isT0(i);
			//if (x.size())
			//	std::cout << int(x[i]) << " ";
			//else
			//	std::cout << "  ";
			//std::cout << int(y[i]) << " ";
			//std::cout << int(on) << " ";
			//std::cout << int(prevOn) << " ";
			//std::cout << int(rr) << " ";
			//std::cout << int(term) << " ";
			//std::cout << int(nearTerm) << std::endl;;

			r += rr;
			t0 += t0i;
			//t += term;
			v += nearTerm;

			prevOn = on;
		}

		if (verbose)
		{

			auto w = std::accumulate(x.begin(), x.end(), 0);
			auto h = std::accumulate(y.begin(), y.end(), 0);
			std::cout << "w " << w << " h " << h << " r " << r << " t0 " << t0 << " v " << v << " d " << d << std::endl;
			std::cout << "x:  ";
			for (u64 i = 0; i < x.size(); ++i)
			{
				auto on = isOn(i);
				auto start = x[i] && on == false;
				auto end = isTerm(i);
				auto nearTerm = isNearTerm(i);
				if (start || end)
					std::cout << Color::Blue;
				else if (nearTerm)
					std::cout << Color::Green;
				else if (on)
					std::cout << Color::Red;

				std::cout << int(x[i]);
				std::cout << Color::Default;
			}

			std::cout << "\ny:  ";
			for (u64 i = 0; i < x.size(); ++i)
			{

				auto term = scan(i, isTerm);
				auto nearTerm = scan(i, isNearTerm) && !isNearTerm(i);

				auto on = isOn(i);

				if (d && i >= x.size() - sigma)
					std::cout << Color::Pink;
				else if (term)
					std::cout << Color::Blue;
				else if (nearTerm)
					std::cout << Color::Green;
				else if (on || y[i])
					std::cout << Color::Red;

				std::cout << int(y[i]);
				std::cout << Color::Default;
			}
			std::cout << "\nb:  ";
			for (u64 i = 0; i < x.size(); ++i)
			{
				std::cout << int(isOn(i - 1) == 0 && isOn(i));
			}
			std::cout << "\ne:  ";
			for (u64 i = 0; i < x.size(); ++i)
			{
				std::cout << int(isTerm(i));
			}

			std::cout << "\nq:  ";
			for (u64 i = 0; i < x.size(); ++i)
			{
				std::cout << int(isOn(i));
			}

			std::cout << "\nt0: ";
			for (u64 i = 0; i < x.size(); ++i)
			{
				std::cout << int(isT0(i));
			}

			std::cout << "\nn:  ";
			for (u64 i = 0; i < x.size(); ++i)
			{
				std::cout << int(isNearTerm(i));
			}
			std::cout << "\ns:  ";
			for (u64 i = 0; i < x.size(); ++i)
			{
				std::cout << int(isOn(i) && !isTerm(i) && !isNearTerm(i));
			}
			std::cout << std::endl;

		}
	}

	// we will generate all G <- D and exhaustively
	// encode all c = x G and construct the enumerator.
	// We then compare this with the formula based enumerator.
	void WrapConvEnum_single_Test(const CLP& cmd)
	{
		u64 verbose = cmd.isSet("v");
		auto Ns = cmd.getManyOr<u64>("n", { 4, 6, 8 });
		auto Ks = cmd.getManyOr<u64>("k", { 4, 6, 8 });
		auto Ss = cmd.getManyOr<u64>("sigma", { 2, 3, 2 }); // window size
		//auto systematics = cmd.getManyOr<u64>("sys", { false, true }); // window size
		u64 numThreads = cmd.getOr("nt", std::thread::hardware_concurrency());
		auto pp = cmd.getOr<u64>("pp", 0);

		if (Ns.size() != Ks.size() ||
			Ns.size() != Ss.size())
			throw RTE_LOC;

		for (u64 p = pp; p < Ns.size(); ++p)
		{
			auto n = Ns[p];
			auto k = Ks[p];
			auto sigma = Ss[p];

			if (verbose)
			{
				std::cout << "n: " << n << std::endl;
				std::cout << "k: " << k << std::endl;
				std::cout << "sigma: " << sigma << std::endl;
			}

			// k by n by r by t0
			Matrix<Matrix<Matrix<Rat>>> expEnum(k + 1, n + 1);
			u64 rMax = n;// / sigma;
			u64 vMax = n;
			for (auto& expEnumRT : expEnum)
			{
				expEnumRT.resize(rMax + 1, n+1);
				for (auto& expEnumRTT : expEnumRT)
					expEnumRTT.resize(vMax+1, 2);
			}

			// in general its not needed but we will be evaluating outside the correct
			// range which can result in bigger values.
			Choose<Int> choose(n * n);
			BallsBinsCap<Int> bbc(n, n, sigma - 2, choose);

			u64 size = 0;
			std::vector<BitVector> Gbv(n);
			for (u64 i = 0; i < n; ++i)
			{
				Gbv[i].resize(std::min(i, sigma));
				size += std::max<i64>(0, std::min<i64>(Gbv[i].size(), sigma - 1));
				if (Gbv[i].size() == sigma)
				{
					//Gbv[i][0] = 1;
					Gbv[i].back() = 1;
				}
			}
			using T = u8;
			if (sigma > 8)
				throw std::runtime_error("we assume sigma bits it inside a T");
			std::vector<T> Gm(n);
			Matrix<T> Xs(1ull << k, divCeil(sigma, 8));
			T mask = (1ull << (sigma)) - 1;
			for (u64 i = 0; i < Xs.rows(); ++i)
			{
				copyBytesMin(Xs[i], i);
			}

			std::set<std::string> ss;

			auto z = std::vector<u8>(n);
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
				//if (verbose)
				//{
				//	std::cout << "H: \n" << SparseMtx(pl) << std::endl;
				//	std::cout << "G: \n" << G << std::endl;
				//}

				std::vector<u8> xx(k), yy(n);
				for (u64 x = 0; x < (1ull << k); ++x)
				{

					randConvMultBit(Gm, Xs[x], z, k, n, sigma);
					auto w = popcount(x);
					u64 h = 0;
					for (u64 j = 0; j < n; ++j)
						h += z[j];

					for (u64 w = 0; w < k; ++w)
					{
						xx[w] = (x >> w) & 1;
					}

					u64 r, t0, v, d;
					getRTVD(z, sigma, r, t0, v, d, verbose, xx);

					if (verbose)
					{
						auto Ewhrt = WrapConvEnumerator<Int, Rat>::enumerate<true>(
							w, h,
							r, t0,
							v, d,
							k, n, sigma, choose, bbc);
						std::cout << "E " << Ewhrt << std::endl;
						std::cout << std::endl;

						if (Ewhrt == 0)
						{
							throw RTE_LOC;
						}
					}

					//if (0)
					//{
					//	for (u64 w = 0; w < k; ++w)
					//	{
					//		xx[w] = (x >> w) & 1;
					//	}


					//	std::fill(yy.begin(), yy.end(), 0);
					//	GG.leftMultAdd(xx, yy);
					//	getRTVD(yy, sigma, r, t0, v, d, 1, xx);

					//	if (yy != z)
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
					//		randConvMultBit(Gm, Xs[x], z, k, n, sigma, true);

					//		throw RTE_LOC;
					//	}
					//}

					//if (w == 1 && h == 2 && r == 1 && t0 == 1 && v == 1 && d == 0)
					//{
					//	std::stringstream str;
					//	for (auto x : xx)
					//		str << int(x);
					//	for (auto x : z)
					//		str << int(x);
					//	auto b  = ss.insert(str.str());
					//	if (b.second)
					//	{
					//		getRTVD(z, sigma, r, t0, v, d, true, xx);
					//	}
					//}

					expEnum(w, h)(r, t0)(v, d) += 1;

				}
			} while (increment(Gbv, sigma));

			Rat sum = 0, expSum = 0;

			for (auto& E : expEnum)
			{
				for (auto& ERT : E)
				{
					for (auto& ERTT : ERT)
					{
						ERTT = ERTT / (Int(1) << size);
						ERTT.backend().normalize();
						expSum += ERTT;
					}
				}
			}

			bool shortCircuit = true;

			// input weight
			for (u64 w = 0; w <= k; ++w) {
				// output weight
				for (u64 h = 0; h <= n; ++h) {
					// number of runs
					for (u64 r = 0; r <= rMax; ++r) {
						auto r0 = r / 2;
						if (shortCircuit)
						{
							i64 t1 = h - r0;
							if (t1 < 0)
								break;
							i64 f1 = w - r;
							if (f1 < 0)
								break;

							i64 z = n - h - r0 * sigma;
							if (z < 0)
								break;
							//i64 f0 = n - w - z;
							//if (f0 < 0)
							//	break;
						}

						// number of zeros in the output freezone
						for (u64 t0 = 0; t0 <= n; ++t0) {
							if (shortCircuit)
							{

								i64 z = n - h - t0 - r0 * sigma;
								if (z < 0)
									break;
								//i64 f0 = n - w - z;
								//if (f0 < 0)
								//	break;
							}
							// number of almost terminations
							for (u64 v = 0; v <= vMax; ++v)
							{
								if (shortCircuit)
								{
									i64 t1 = h - v - r0;
									if (t1 < 0)
										break;
									i64 z = n - h - v * (sigma - 1) - t0 - r0 * sigma;
									if (z < 0)
										break;
									//i64 f0 = n - w - z - v;
									//if (f0 < 0)
									//	break;
								}

								// number of trailing zones
								for (u64 d = 0; d < 2; ++d)
								{
									if (shortCircuit)
									{
										i64 t1 = h - v - r0 - d;
										if (t1 < 0)
											break;

										i64 z = n - h - (v + d) * (sigma - 1) - t0 - r0 * sigma;
										if (z < 0)
											break;
									}

									auto Ewhrt = WrapConvEnumerator<Int, Rat>::enumerate(
										w, h,
										r, t0,
										v, d,
										k, n, sigma, choose, bbc);

									sum += Ewhrt;
									Ewhrt.backend().normalize();

									if (Ewhrt != expEnum(w, h)(r, t0)(v, d))
									{
										std::cout
											<< "w " << w << " h " << h
											<< " r " << r << " t0 " << t0
											<< " v " << v << " d " << d
											<< std::endl;

										std::cout << "exhaustive " << expEnum(w, h)(r, t0)(v, d)
											<< " = " << expEnum(w, h)(r, t0)(v, d) * (Int(1) << size) << " / " << (Int(1) << size) << std::endl;
										std::cout << "formula    " << Ewhrt << std::endl;

										auto Ewhrt = WrapConvEnumerator<Int, Rat>::enumerate<true>(
											w, h,
											r, t0,
											v, d,
											k, n, sigma, choose, bbc);
										throw RTE_LOC;
									}

								}
							}
						}
					}
				}
			}

			sum.backend().normalize();
			expSum.backend().normalize();
			if (sum != expSum)
			{
				std::cout << "sum " << sum << std::endl;
				std::cout << "expSum " << expSum << std::endl;
				throw RTE_LOC;
			}
		}

	}


	// we will generate all G <- D and exhaustively
	// encode all c = x G and construct the enumerator.
	// We then compare this with the formula based enumerator.
	void WrapConvEnum_exhaustive_Test(const CLP& cmd)
	{
		u64 verbose = cmd.isSet("v");
		auto Ns = cmd.getManyOr<u64>("n", { 4, 6, 6, 8 });
		auto Ks = cmd.getManyOr<u64>("k", { 4, 6, 6, 8 });
		auto sigmas = cmd.getManyOr<u64>("sigma", { 2,2,3, 3 }); // window size
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

			if (verbose)
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

			Choose<Int> pas(2 * n);
			BallsBinsCap<Int> bbc(n, n, sigma - 2, pas);

			WrapConvEnumerator<Int, Rat> blk(k, n, sigma, pas, bbc);
			//RandConvEnumerator<Int, Rat>sys(k, n + k, sigma, choose, choose);

			blk.enumerate(actIn, actOut, actEnum);
			//sys.enumerate(actIn, sysOut, sysEnum);

			u64 size = 0;
			std::vector<BitVector> Gbv(n);
			for (u64 i = 0; i < n; ++i)
			{
				Gbv[i].resize(std::min(i, sigma));
				size += std::max<i64>(0, std::min<i64>(Gbv[i].size(), sigma - 1));
				if (Gbv[i].size() == sigma)
				{
					//Gbv[i][0] = 1;
					Gbv[i].back() = 1;
				}
			}
			using T = u8;
			if (sigma > 8)
				throw std::runtime_error("we assume sigma bits it inside a T");
			std::vector<T> Gm(n);
			Matrix<T> Xs(1ull << k, divCeil(sigma, 8));
			T mask = (1ull << (sigma)) - 1;
			for (u64 i = 0; i < Xs.rows(); ++i)
			{
				copyBytesMin(Xs[i], i);
			}

			std::set<std::string> ss;

			auto z = std::vector<u8>(n);
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

				std::vector<u8> xx(k), yy(n);
				for (u64 x = 0; x < (1ull << k); ++x)
				{

					randConvMultBit(Gm, Xs[x], z, k, n, sigma);
					auto w = popcount(x);
					u64 h = 0;
					for (u64 j = 0; j < n; ++j)
						h += z[j];

					expEnum(w, h) += 1;

				}
			} while (increment(Gbv, sigma));


			for (auto& E : expEnum)
			{
				E = E / (Int(1) << size);
				E.backend().normalize();
			}



			if (expEnum != actEnum)
			{
				std::cout << "exp " << std::endl;
				std::cout << enumToString(expEnum) << std::endl;;
				std::cout << "formula " << std::endl;
				std::cout << enumToString(actEnum) << std::endl;;

				throw RTE_LOC;
			}

			if (verbose)
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

			//enumerate<Rat>(sysEnum, actIn, expSysOut, choose);

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



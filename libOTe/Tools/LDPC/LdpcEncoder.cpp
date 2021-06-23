#include "LdpcEncoder.h"
//#include <eigen/dense>
#include <set>
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/Timer.h"
#include "LdpcSampler.h"
#include "libOTe/Tools/Tools.h"
namespace osuCrypto
{
	namespace details
	{
		constexpr  std::array<std::array<u8, 4>, 16> SilverRightEncoder::diagMtx_g16_w5_seed1_t36;
		constexpr  std::array<std::array<u8, 10>, 32> SilverRightEncoder::diagMtx_g32_w11_seed2_t36;
		constexpr  std::array<u8, 2> SilverRightEncoder::mOffsets;
	}

	bool LdpcEncoder::init(SparseMtx H, u64 gap)
	{

#ifndef NDEBUG
		for (u64 i = H.cols() - H.rows() + gap, j = 0; i < H.cols(); ++i, ++j)
		{
			auto row = H.row(j);
			assert(row[row.size() - 1] == i);
		}
#endif
		auto c0 = H.cols() - H.rows();
		auto c1 = c0 + gap;
		auto r0 = H.rows() - gap;

		mN = H.cols();
		mM = H.rows();
		mGap = gap;


		mA = H.subMatrix(0, 0, r0, c0);
		mB = H.subMatrix(0, c0, r0, gap);
		mC = H.subMatrix(0, c1, r0, H.rows() - gap);
		mD = H.subMatrix(r0, 0, gap, c0);
		mE = H.subMatrix(r0, c0, gap, gap);
		mF = H.subMatrix(r0, c1, gap, H.rows() - gap);
		mH = std::move(H);

		mCInv.init(mC);

		if (mGap)
		{
			SparseMtx CB;

			// CB = C^-1 B
			mCInv.mult(mB, CB);

			//assert(mC.invert().mult(mB) == CB);
			// Ep = F C^-1 B
			mEp = mF.mult(CB);
			//// Ep = F C^-1 B + E
			mEp += mE;
			mEp = mEp.invert();

			return (mEp.rows() != 0);
		}

		return true;
	}

	void LdpcEncoder::encode(span<u8> c, span<const u8> mm)
	{
		assert(mm.size() == mM);
		assert(c.size() == mN);

		auto s = mM - mGap;
		auto iter = c.begin() + mM;
		span<u8> m(c.begin(), iter);
		span<u8> p(iter, iter + mGap); iter += mGap;
		span<u8> pp(iter, c.end());


		// m = mm
		std::copy(mm.begin(), mm.end(), m.begin());
		std::fill(c.begin() + mM, c.end(), 0);

		// pp = A * m
		mA.multAdd(m, pp);

		if (mGap)
		{
			std::vector<u8> t(s);

			// t = C^-1 pp      = C^-1 A m
			mCInv.mult(pp, t);

			// p = - F t + D m  = -F C^-1 A m + D m
			mF.multAdd(t, p);
			mD.multAdd(m, p);

			// p = - Ep p       = -Ep (-F C^-1 A m + D m)
			t = mEp.mult(p);
			std::copy(t.begin(), t.end(), p.begin());

			// pp = pp + B p    
			mB.multAdd(p, pp);
		}

		// pp = C^-1 pp 
		mCInv.mult(pp, pp);
	}

	namespace details
	{

		void DiagInverter::init(const SparseMtx& c)
		{
			mC = (&c);
			assert(mC->rows() == mC->cols());

#ifndef NDEBUG
			for (u64 i = 0; i < mC->rows(); ++i)
			{
				auto row = mC->row(i);
				assert(row.size() && row[row.size() - 1] == i);

				for (u64 j = 0; j < row.size() - 1; ++j)
				{
					assert(row[j] < row[j + 1]);
				}
			}
#endif
		}


		std::vector<SparseMtx> DiagInverter::getSteps()
		{
			std::vector<SparseMtx> steps;

			u64 n = mC->cols();
			u64 nn = mC->cols() * 2;

			for (u64 i = 0; i < mC->rows(); ++i)
			{
				auto row = mC->row(i);
				PointList points(nn, nn);

				points.push_back({ i, n + i });
				assert(row[row.size() - 1] == i);
				for (u64 j = 0; j < (u64)row.size() - 1; ++j)
				{
					points.push_back({ i,row[j] });
				}

				for (u64 j = 0; j < i; ++j)
				{
					points.push_back({ j,j });
				}

				for (u64 j = 0; j < n; ++j)
				{
					points.push_back({ n + j, n + j });
				}
				steps.emplace_back(nn, nn, points);

			}

			return steps;
		}

		// computes x = mC^-1 * y
		void DiagInverter::mult(span<const u8> y, span<u8> x)
		{
			// solves for x such that y = M x, ie x := H^-1 y 
			assert(mC);
			assert(mC->rows() == y.size());
			assert(mC->cols() == x.size());

			for (u64 i = 0; i < mC->rows(); ++i)
			{
				auto row = mC->row(i);
				x[i] = y[i];

				assert(row[row.size() - 1] == i);
				for (u64 j = 0; j < (u64)row.size() - 1; ++j)
				{
					x[i] ^= x[row[j]];
				}
			}
		}
		void DiagInverter::mult(const SparseMtx& y, SparseMtx& x)
		{
			auto n = mC->rows();
			assert(n == y.rows());
			//assert(n == x.rows());
			//assert(y.cols() == x.cols());

			auto xNumRows = n;
			auto xNumCols = y.cols();

			std::vector<u64>& xCol = x.mDataCol; xCol.reserve(y.mDataCol.size());
			std::vector<u64>
				colSizes(xNumCols),
				rowSizes(xNumRows);

			for (u64 c = 0; c < y.cols(); ++c)
			{
				auto cc = y.col(c);
				auto yIter = cc.begin();
				auto yEnd = cc.end();

				auto xColBegin = xCol.size();
				for (u64 i = 0; i < n; ++i)
				{
					u8 bit = 0;
					if (yIter != yEnd && *yIter == i)
					{
						bit = 1;
						++yIter;
					}

					auto rr = mC->row(i);
					auto mIter = rr.begin();
					auto mEnd = rr.end() - 1;

					auto xIter = xCol.begin() + xColBegin;
					auto xEnd = xCol.end();

					while (mIter != mEnd && xIter != xEnd)
					{
						if (*mIter < *xIter)
							++mIter;
						else if (*xIter < *mIter)
							++xIter;
						else
						{
							bit ^= 1;
							++xIter;
							++mIter;
						}
					}

					if (bit)
					{
						xCol.push_back(i);
						++rowSizes[i];
					}
				}
				colSizes[c] = xCol.size();
			}

			x.mCols.resize(colSizes.size());
			auto iter = xCol.begin();
			for (u64 i = 0; i < colSizes.size(); ++i)
			{
				auto end = xCol.begin() + colSizes[i];
				x.mCols[i] = SparseMtx::Col(span<u64>(iter, end));
				iter = end;
			}

			x.mRows.resize(rowSizes.size());
			x.mDataRow.resize(x.mDataCol.size());
			iter = x.mDataRow.begin();
			//auto prevSize = 0ull;
			for (u64 i = 0; i < rowSizes.size(); ++i)
			{
				auto end = iter + rowSizes[i];

				rowSizes[i] = 0;
				//auto ss = rowSizes[i];
				//rowSizes[i] = rowSizes[i] - prevSize;
				//prevSize = ss;

				x.mRows[i] = SparseMtx::Row(span<u64>(iter, end));
				iter = end;
			}

			iter = xCol.begin();
			for (u64 i = 0; i < x.cols(); ++i)
			{
				for (u64 j : x.col(i))
				{
					x.mRows[j][rowSizes[j]++] = i;
				}
			}

		}



		void SilverLeftEncoder::init(u64 rows, std::vector<double> rs)
		{
			mRows = rows;
			mWeight = rs.size();
			assert(mWeight > 4);

			mRs = rs;
			mYs.resize(rs.size());
			std::set<u64> s;

			u64 trials = 0;
			for (u64 i = 0; i < mWeight; ++i)
			{
				mYs[i] = u64(rows * rs[i]) % rows;
				while (s.insert(mYs[i]).second == false)
				{
					++mYs[i];

					if (++trials > 1000)
					{
						std::cout << "these ratios resulted in too many collitions. " LOCATION << std::endl;
						throw std::runtime_error("these ratios resulted in too many collitions. " LOCATION);
					}
				}
			}
		}

		void SilverLeftEncoder::init(u64 rows, SilverCode code)
		{
			auto weight = code.weight();
			switch (weight)
			{
			case 5:
				init(rows, { { 0, 0.372071, 0.576568, 0.608917, 0.854475} });

				// 0 0.0494143 0.437702 0.603978 0.731941

				// yset 3,785
				// 0 0.372071 0.576568 0.608917 0.854475
				break;
			case 11:
				init(rows, { { 0, 0.00278835, 0.0883852, 0.238023, 0.240532, 0.274624, 0.390639, 0.531551, 0.637619, 0.945265, 0.965874} });
				// 0 0.00278835 0.0883852 0.238023 0.240532 0.274624 0.390639 0.531551 0.637619 0.945265 0.965874
				break;
			default:
				// no preset parameters
				throw RTE_LOC;
			}
		}

		void SilverLeftEncoder::encode(span<u8> pp, span<const u8> m)
		{
			auto cols = mRows;
			assert(pp.size() == mRows);
			assert(m.size() == cols);

			// pp = pp + A * m
			auto v = mYs;
			for (u64 i = 0; i < cols; ++i)
			{
				for (u64 j = 0; j < mWeight; ++j)
				{
					auto row = v[j];
					pp[row] ^= m[i];

					++v[j];
					if (v[j] == mRows)
						v[j] = 0;
				}
			}
		}


		void SilverLeftEncoder::getPoints(PointList& points)
		{
			auto cols = mRows;
			auto v = mYs;

			for (u64 i = 0; i < cols; ++i)
			{
				for (u64 j = 0; j < mWeight; ++j)
				{
					auto row = v[j];

					points.push_back({ row, i });

					++v[j];
					if (v[j] == mRows)
						v[j] = 0;
				}
			}
		}

		SparseMtx SilverLeftEncoder::getMatrix()
		{
			PointList points(mRows, mRows);
			getPoints(points);
			return SparseMtx(mRows, mRows, points);
		}

		void SilverRightEncoder::init(u64 rows, SilverCode c, bool extend)
		{
			mGap = c.gap();
			assert(mGap < rows);
			mCode = c;
			mRows = rows;
			mExtend = extend;
			mCols = extend ? rows : rows - mGap;
		}

		void SilverRightEncoder::encode(span<u8> x, span<const u8> y)
		{
			assert(mExtend);
			for (u64 i = 0; i < mRows; ++i)
			{
				x[i] = y[i];
				if (mCode == SilverCode::Weight5)
				{
					for (u64 j = 0; j < 4; ++j)
					{
						auto col = i - 16 + diagMtx_g16_w5_seed1_t36[i & 15][j];
						if (col < mRows)
							x[i] = x[i] ^ x[col];
					}
				}

				if (mCode == SilverCode::Weight11)
				{
					for (u64 j = 0; j < 10; ++j)
					{
						auto col = i - 32 + diagMtx_g32_w11_seed2_t36[i & 31][j];
						if (col < mRows)
							x[i] = x[i] ^ x[col];
					}
				}

				for (u64 j = 0; j < mOffsets.size(); ++j)
				{
					auto p = i - mOffsets[j] - mGap;
					if (p >= mRows)
						break;
					x[i] = x[i] ^ x[p];
				}
			}
		}

		void SilverRightEncoder::getPoints(PointList& points, u64 colOffset)
		{
			auto rr = mRows;

			for (u64 i = 0; i < rr; ++i)
			{
				if (i < mCols)
					points.push_back({ i, i + colOffset });

				switch (mCode)
				{
				case SilverCode::Weight5:

					for (u64 j = 0; j < 4; ++j)
					{
						auto col = i - 16 + diagMtx_g16_w5_seed1_t36[i & 15][j];
						if (col < mCols)
							points.push_back({ i, col + colOffset });
					}

					break;
				case SilverCode::Weight11:
					for (u64 j = 0; j < 10; ++j)
					{
						auto col = i - 32 + diagMtx_g32_w11_seed2_t36[i & 31][j];
						if (col < mCols)
							points.push_back({ i, col + colOffset });
					}

					break;
				default:
					break;
				}

				for (u64 j = 0; j < mOffsets.size(); ++j)
				{
					auto col = i - mOffsets[j] - mGap;
					if (col < mRows)
						points.push_back({ i, col + colOffset });
				}
			}

			if (mExtend)
			{
				for (u64 i = rr; i < mRows; ++i)
					points.push_back({ i, i + colOffset });
			}
		}

		SparseMtx SilverRightEncoder::getMatrix()
		{
			PointList points(mRows, cols());
			getPoints(points, 0);
			return SparseMtx(mRows, cols(), points);
		}
	}


	void tests::LdpcEncoder_diagonalSolver_test()
	{
		u64 n = 10;
		u64 w = 4;
		u64 t = 10;

		oc::PRNG prng(block(0, 0));
		std::vector<u8> x(n), y(n);
		for (u64 tt = 0; tt < t; ++tt)
		{
			SparseMtx H = sampleTriangular(n, 0.5, prng);

			//std::cout << H << std::endl;

			for (auto& yy : y)
				yy = prng.getBit();

			details::DiagInverter HInv(H);

			HInv.mult(y, x);

			auto z = H.mult(x);

			assert(z == y);

			auto Y = sampleFixedColWeight(n, w, 3, prng, false);

			SparseMtx X;

			HInv.mult(Y, X);

			auto Z = H * X;

			assert(Z == Y);

		}




		return;
	}

	void tests::LdpcEncoder_encode_test()
	{

		u64 rows = 16;
		u64 cols = rows * 2;
		u64 colWeight = 4;
		u64 dWeight = 3;
		u64 gap = 6;

		auto k = cols - rows;

		assert(gap >= dWeight);

		oc::PRNG prng(block(0, 2));


		SparseMtx H;
		LdpcEncoder E;


		//while (b)
		for (u64 i = 0; i < 40; ++i)
		{
			bool b = true;
			//std::cout << " +====================" << std::endl;
			while (b)
			{
				H = sampleTriangularBand(
					rows, cols,
					colWeight, gap,
					dWeight, false, prng);
				//H = sampleTriangular(rows, cols, colWeight, gap, prng);
				b = !E.init(H, gap);
			}

			//std::cout << H << std::endl;

			std::vector<u8> m(k), c(cols);

			for (auto& mm : m)
				mm = prng.getBit();


			E.encode(c, m);

			auto ss = H.mult(c);

			//for (auto sss : ss)
			//    std::cout << int(sss) << " ";
			//std::cout << std::endl;
			assert(ss == std::vector<u8>(H.rows(), 0));

		}
		return;

	}

	void tests::LdpcEncoder_encode_g0_test()
	{

		u64 rows = 17;
		u64 cols = rows * 2;
		u64 colWeight = 4;

		auto k = cols - rows;

		oc::PRNG prng(block(0, 2));


		SparseMtx H;
		LdpcEncoder E;


		//while (b)
		for (u64 i = 0; i < 40; ++i)
		{
			bool b = true;
			//std::cout << " +====================" << std::endl;
			while (b)
			{
				//H = sampleTriangularBand(
				//    rows, cols,
				//    colWeight, 0,
				//    1, false, prng);
				// 
				// 


				H = sampleTriangularBand(
					rows, cols,
					colWeight, 8,
					colWeight, colWeight, 0, 0, { 5,31 }, true, true, true, prng, prng);
				//H = sampleTriangular(rows, cols, colWeight, gap, prng);
				b = !E.init(H, 0);
			}

			//std::cout << H << std::endl;

			std::vector<u8> m(k), c(cols);

			for (auto& mm : m)
				mm = prng.getBit();


			E.encode(c, m);

			auto ss = H.mult(c);

			assert(ss == std::vector<u8>(H.rows(), 0));

		}
		return;
	}


	void tests::LdpcS1Encoder_encode_test()
	{
		u64 rows = 100;
		SilverCode weight = SilverCode::Weight5;

		details::SilverLeftEncoder zz;
		zz.init(rows, weight);

		std::vector<u8> m(rows), pp(rows);

		PRNG prng(ZeroBlock);

		for (u64 i = 0; i < rows; ++i)
			m[i] = prng.getBit();

		zz.encode(pp, m);

		auto p2 = zz.getMatrix().mult(m);

		if (p2 != pp)
		{
			throw RTE_LOC;
		}

	}



	void tests::LdpcS1Encoder_encode_Trans_test()
	{
		u64 rows = 100;
		SilverCode weight = SilverCode::Weight5;
		

		details::SilverLeftEncoder zz;
		zz.init(rows, weight);

		std::vector<u8> m(rows), pp(rows);

		PRNG prng(ZeroBlock);

		for (u64 i = 0; i < rows; ++i)
			m[i] = prng.getBit();

		zz.cirTransEncode<u8>(pp, m);

		auto p2 = zz.getMatrix().dense().transpose().sparse().mult(m);

		if (p2 != pp)
		{
			throw RTE_LOC;
		}
	}


	void tests::LdpcComposit_RegRepDiagBand_encode_test()
	{
		u64 rows = 500;
		

		PRNG prng(ZeroBlock);
		using namespace details;
		using Encoder = SilverEncoder;

		for (auto code : { SilverCode::Weight5 , SilverCode::Weight11 })
		{

			Encoder enc;
			enc.mL.init(rows, code);
			enc.mR.init(rows, code, true);

			auto H = enc.getMatrix();

			LdpcEncoder enc2;
			enc2.init(H, 0);

			auto cols = enc.cols();
			auto k = cols - rows;
			std::vector<u8> m(k), c(cols), c2(cols);

			for (auto& mm : m)
				mm = prng.getBit();

			enc.encode<u8>(c, m);
			enc2.encode(c2, m);

			auto ss = H.mult(c);

			if (ss != std::vector<u8>(H.rows(), 0))
				throw RTE_LOC;
			if (c2 != c)
				throw RTE_LOC;


			auto R = enc.mR.getMatrix();
			auto g = SilverCode::gap(code);
			auto d1 = enc.mR.mOffsets[0] + g;
			auto d2 = enc.mR.mOffsets[1] + g;


			for (u64 i = 0; i < R.cols() - g; ++i)
			{
				std::set<u64> ss;

				auto col = R.col(i);
				for (auto cc : col)
				{
					ss.insert(cc);
				}

				auto expSize = SilverCode::weight(code);

				if (d1 < R.rows())
				{
					++expSize;
					if (ss.find(d1) == ss.end())
						throw RTE_LOC;
				}

				if (d2 < R.rows())
				{
					++expSize;
					if (ss.find(d2) == ss.end())
						throw RTE_LOC;
				}

				if (col.usize() != expSize)
					throw RTE_LOC;

				++d1;
				++d2;


			}
		}
	}


	void tests::LdpcComposit_RegRepDiagBand_Trans_test()
	{

		u64 rows = 234;

		using namespace details;
		SilverCode code = SilverCode::Weight5;


		using Encoder = LdpcCompositEncoder<SilverLeftEncoder, SilverRightEncoder>;
		PRNG prng(ZeroBlock);

		Encoder enc;
		enc.mL.init(rows, code);
		enc.mR.init(rows, code, true);

		auto H = enc.getMatrix();
		auto HD = H.dense();
		auto Gt = computeGen(HD).transpose();


		LdpcEncoder enc2;
		enc2.init(H, 0);


		auto cols = enc.cols();
		auto k = cols - rows;

		std::vector<u8> c(cols);

		for (auto& cc : c)
			cc = prng.getBit();
		//std::cout << "\n";

		auto mOld = c;
		enc2.cirTransEncode<u8>(mOld);
		mOld.resize(k);


		auto mCur = c;
		enc.cirTransEncode<u8>(mCur);
		mCur.resize(k);
	}


}
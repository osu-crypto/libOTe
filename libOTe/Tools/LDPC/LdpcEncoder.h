#pragma once
// © 2022 Visa.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// This code implements features described in [Silver: Silent VOLE and Oblivious Transfer from Hardness of Decoding Structured LDPC Codes, https://eprint.iacr.org/2021/1150]; the paper is licensed under Creative Commons Attribution 4.0 International Public License (https://creativecommons.org/licenses/by/4.0/legalcode).
#include "libOTe/config.h"
#ifdef  ENABLE_INSECURE_SILVER

#include "Mtx.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/Timer.h"
#include <numeric>

namespace osuCrypto
{
	namespace details
	{
		class DiagInverter
		{
		public:

			const SparseMtx* mC = nullptr;

			DiagInverter() = default;
			DiagInverter(const DiagInverter&) = default;
			DiagInverter& operator=(const DiagInverter&) = default;

			DiagInverter(const SparseMtx& c) { init(c); }

			void init(const SparseMtx& c);

			// returns a list of matrices to multiply with to encode.
			std::vector<SparseMtx> getSteps();

			// computes x = mC^-1 * y
			void mult(span<const u8> y, span<u8> x);

			// computes x = mC^-1 * y
			void mult(const SparseMtx& y, SparseMtx& x);

			template<typename T>
			void cirTransMult(span<T> x, span<T> y)
			{
				// solves for x such that y = M x, ie x := H^-1 y 
				assert(mC);
				assert(mC->cols() == x.size());

				for (u64 i = mC->rows() - 1; i != ~u64(0); --i)
				{
					auto row = mC->row(i);
					assert(row[row.size() - 1] == i);
					for (u64 j = 0; j < (u64)row.size() - 1; ++j)
					{
						auto col = row[j];
						assert(col < i);
						x[col] = x[col] ^ x[i];
					}
				}
			}
		};
	}

	// a generic encoder for any g-ALT LDPC code 
	class LdpcEncoder
	{
	public:

		LdpcEncoder() = default;
		LdpcEncoder(const LdpcEncoder&) = default;
		LdpcEncoder(LdpcEncoder&&) = default;


		u64 mN, mM, mGap;
		SparseMtx mA, mH;
		SparseMtx mB;
		SparseMtx mC;
		SparseMtx mD;
		SparseMtx mE, mEp;
		SparseMtx mF;
		details::DiagInverter mCInv;

		// initialize the encoder with the given matrix which is 
		// in gap-ALT form.
		bool init(SparseMtx mtx, u64 gap);

		// encode the given message m and populate c with
		// the resulting codeword.
		void encode(span<u8> c, span<const u8> m);

		// perform the circuit transpose of the encoding algorithm.
		// the inputs and output is c.
		template<typename T>
		void dualEncode(span<T> c)
		{
			if (mGap)
				throw std::runtime_error(LOCATION);
			assert(c.size() == mN);

			auto k = mN - mM;
			span<T> pp(c.subspan(k, mM));
			span<T> mm(c.subspan(0, k));

			mCInv.cirTransMult(pp, mm);

			for (u64 i = 0; i < k; ++i)
			{
				for (auto row : mA.col(i))
				{
					c[i] = c[i] ^ pp[row];
				}
			}
		}
	};

	// INSECURE
	// enum struct to specify which silver code variant to use.
	// https://eprint.iacr.org/2021/1150
	// see also https://eprint.iacr.org/2023/882
	struct SilverCode
	{
		enum code
		{
			Weight5 = 5,
			Weight11 = 11,
		};
		code mCode;

		SilverCode() = default;
		SilverCode(const SilverCode&) = default;
		SilverCode& operator=(const SilverCode&) = default;
		SilverCode(const code& c) : mCode(c) {}

		bool operator==(code c) { return mCode == c; }
		bool operator!=(code c) { return mCode != c; }
		operator code()
		{
			return mCode;
		}

		u64 weight() { return weight(mCode); }
		u64 gap() { 
			return gap(mCode);
		}
		static u64 weight(code c)
		{
			return (u64)c;
		}
		static u64 gap(code c)
		{
			switch (c)
			{
			case Weight5:
				return 16;
				break;
			case Weight11:
				return 32;
				break;
			default:
				throw RTE_LOC;
				break;
			}
		}
	};

	namespace details
	{

		// the silver encoder for the left half of the matrix.
		// This part of the code constists of mWeight diagonals.
		// The positions of these diagonals is determined by 
		class SilverLeftEncoder
		{
		public:

			u64 mRows, mWeight;
			std::vector<u64> mYs;
			std::vector<double> mRs;

			// a custom initialization which the specifed diagonal 
			// factional positions.
			void init(u64 rows, std::vector<double> rs, u64 rep = 0);

			// initialize the left half with the given silver presets.
			void init(u64 rows, SilverCode code, u64 rep = 0);

			// encode the given message m and populate c with
			// the resulting codeword.
			void encode(span<u8> pp, span<const u8> m);

			u64 cols() { return mRows; }

			u64 rows() { return mRows; }

			// populates points with the matrix representation of this
			// encoder.
			void getPoints(PointList& points);

			// return parity check matrix representation of this encoder.
			SparseMtx getMatrix();


			// return generator matrix representation of this encoder.
			void getTransPoints(PointList& points);

			// return generator matrix representation of this encoder.
			SparseMtx getTransMatrix();

			// perform the circuit transpose of the encoding algorithm.
			// the output it written to ppp.
			template<typename T>
			void dualEncode(span<T> ppp, span<const T> mm);

			// perform the circuit transpose of the encoding algorithm twice.
			// the output it written to ppp0 and ppp1.
			template<typename T0, typename T1>
			void dualEncode2(
				span<T0> ppp0, span<T1> ppp1,
				span<const T0> mm0, span<const T1> mm1);
		};


		class SilverRightEncoder
		{
		public:

			static constexpr  std::array<std::array<u8, 4>, 16> diagMtx_g16_w5_seed1_t36
			{ {
				{ {0,  4, 11, 15 }},
				{ {0,  8,  9, 10 } },
				{ {1,  2, 10, 14 } },
				{ {0,  5,  8, 15 } },
				{ {3, 13, 14, 15 } },
				{ {2,  4,  7,  8 } },
				{ {0,  9, 12, 15 } },
				{ {1,  6,  8, 14 } },
				{ {4,  5,  6, 14 } },
				{ {1,  3,  8, 13 } },
				{ {3,  4,  7,  8 } },
				{ {3,  5,  9, 13 } },
				{ {8, 11, 12, 14 } },
				{ {6, 10, 12, 13 } },
				{ {2,  7,  8, 13 } },
				{ {0,  6, 10, 15 } }
			} };


			static constexpr  std::array<std::array<u8, 10>, 32> diagMtx_g32_w11_seed2_t36
			{ {
				{ { 6,  7,  8, 12, 16, 17, 20, 22, 24, 25 } },
				{ { 0,  1,  6, 10, 12, 13, 17, 19, 30, 31 } },
				{ { 1,  4,  7, 10, 12, 16, 21, 22, 30, 31 } },
				{ { 3,  5,  9, 13, 15, 21, 23, 25, 26, 27 } },
				{ { 3,  8,  9, 14, 17, 19, 24, 25, 26, 28 } },
				{ { 3, 11, 12, 13, 14, 16, 17, 21, 22, 30 } },
				{ { 2,  4,  5, 11, 12, 17, 22, 24, 30, 31 } },
				{ { 5,  8, 11, 12, 13, 17, 18, 20, 27, 29 } },
				{ {13, 16, 17, 18, 19, 20, 21, 22, 26, 30 } },
				{ { 3,  8, 13, 15, 16, 17, 19, 20, 21, 27 } },
				{ { 0,  2,  4,  5,  6, 21, 23, 26, 28, 30 } },
				{ { 2,  4,  6,  8, 10, 11, 22, 26, 28, 30 } },
				{ { 7,  9, 11, 14, 15, 16, 17, 18, 24, 30 } },
				{ { 0,  3,  7, 12, 13, 18, 20, 24, 25, 28 } },
				{ { 1,  5,  7,  8, 12, 13, 21, 24, 26, 27 } },
				{ { 0, 16, 17, 19, 22, 24, 25, 27, 28, 31 } },
				{ { 0,  6,  7, 15, 16, 18, 22, 24, 29, 30 } },
				{ { 2,  3,  4,  7, 15, 17, 18, 20, 22, 26 } },
				{ { 2,  3,  9, 16, 17, 19, 24, 27, 29, 31 } },
				{ { 1,  3,  5,  7, 13, 14, 20, 23, 24, 27 } },
				{ { 0,  2,  3,  9, 10, 14, 19, 20, 21, 25 } },
				{ { 4, 13, 16, 20, 21, 23, 25, 27, 28, 31 } },
				{ { 1,  2,  5,  6,  9, 13, 15, 17, 20, 24 } },
				{ { 0,  4,  7,  8, 12, 13, 20, 23, 28, 30 } },
				{ { 0,  3,  4,  5,  8,  9, 23, 25, 26, 28 } },
				{ { 0,  3,  4,  7,  8, 10, 11, 15, 21, 26 } },
				{ { 5,  6,  7,  8, 10, 11, 15, 21, 22, 25 } },
				{ { 0,  1,  2,  3,  8,  9, 22, 24, 27, 28 } },
				{ { 1,  2, 13, 14, 15, 16, 19, 22, 29, 30 } },
				{ { 2, 14, 15, 16, 19, 20, 25, 26, 28, 29 } },
				{ { 8,  9, 11, 12, 13, 15, 17, 18, 23, 27 } },
				{ { 0,  2,  4,  5,  6,  7, 10, 12, 14, 19 } }
			} };

			static constexpr std::array<u8, 2> mOffsets{ {5,31} };

			u64 mGap;

			u64 mRows, mCols;
			SilverCode mCode;
			bool mExtend;

			// initialize the right half of the silver encoder
			// with the given preset. extend should be true if
			// this is used to encode and false to determine the 
			// effective minimum distance.
			void init(u64 rows, SilverCode c, bool extend);

			u64 cols() { return mCols; }

			u64 rows() { return mRows; }

			// encode the given message m and populate c with
			// the resulting codeword.
			void encode(span<u8> x, span<const u8> y);

			// populates points with the matrix representation of this
			// encoder. 
			void getPoints(PointList& points, u64 colOffset);

			// return matrix representation of this encoder.
			SparseMtx getMatrix();


			// return generator matrix representation of this encoder.
			std::vector<SparseMtx> getTransMatrices();
			SparseMtx getTransMatrix();


			// perform the circuit transpose of the encoding algorithm.
			// the inputs and output is x.
			template<typename T>
			void dualEncode(span<T> x);

			// perform the circuit transpose of the encoding algorithm twice.
			// the inputs and output is x0 and x1.
			template<typename T0, typename T1>
			void dualEncode2(span<T0> x0, span<T1> x1);
		};

		// a full encoder expressed and the left and right encoder.
		template<typename LEncoder, typename REncoder>
		class LdpcCompositEncoder : public TimerAdapter
		{
		public:

			LEncoder mL;
			REncoder mR;

			template<typename T>
			void encode(span<T>c, span<const T> mm)
			{
				assert(mm.size() == cols() - rows());
				assert(c.size() == cols());

				auto s = rows();
				auto iter = c.begin() + s;
				span<T> m(c.begin(), iter);
				span<T> pp(iter, c.end());

				// m = mm
				std::copy(mm.begin(), mm.end(), m.begin());
				std::fill(c.begin() + s, c.end(), 0);

				// pp = A * m
				mL.encode(pp, mm);

				// pp = C^-1 pp 
				mR.encode(pp, pp);
			}

			template<typename T>
			void dualEncode(span<T> c)
			{
				auto k = cols() - rows();
				assert(c.size() == cols());
				setTimePoint("encode_begin");
				span<T> pp(c.subspan(k, rows()));

				mR.template dualEncode<T>(pp);
				setTimePoint("diag");
				mL.template dualEncode<T>(c.subspan(0, k), pp);
				setTimePoint("L");

			}


			template<typename T0, typename T1>
			void dualEncode2(span<T0> c0, span<T1> c1)
			{
				auto k = cols() - rows();
				assert(c0.size() == cols());

				setTimePoint("encode_begin");
				span<T0> pp0(c0.subspan(k, rows()));
				span<T1> pp1(c1.subspan(k, rows()));

				mR.template dualEncode2<T0, T1>(pp0, pp1);

				setTimePoint("diag");
				mL.template dualEncode2<T0, T1>(c0.subspan(0, k), c1.subspan(0, k), pp0, pp1);
				setTimePoint("L");
			}


			u64 cols() { return mL.cols() + mR.cols(); }

			u64 rows() { return mR.rows(); }

			void getPoints(PointList& points)
			{
				mL.getPoints(points);
				mR.getPoints(points, mL.cols());
			}

			SparseMtx getMatrix()
			{
				PointList points(rows(), cols());
				getPoints(points);
				return SparseMtx(rows(), cols(), points);
			}

		};

	}

	// the full silver encoder which is composed
	// of the left and right sub-encoders.
	struct SilverEncoder : public details::LdpcCompositEncoder<details::SilverLeftEncoder, details::SilverRightEncoder>
	{
		void init(u64 rows, SilverCode code)
		{
			mL.init(rows, code);
			mR.init(rows, code, true);
		}
	};


	namespace tests
	{

		void LdpcEncoder_diagonalSolver_test();
		void LdpcEncoder_encode_test();
		void LdpcEncoder_encode_g0_test();

		void LdpcS1Encoder_encode_test();
		void LdpcS1Encoder_encode_Trans_test();

		void LdpcComposit_RegRepDiagBand_encode_test();
		void LdpcComposit_RegRepDiagBand_Trans_test();

	}























	// perform the circuit transpose of the encoding algorithm.
	// the output it written to ppp.
	template<typename T>
	void details::SilverLeftEncoder::dualEncode(span<T> ppp, span<const T> mm)
	{
		auto cols = mRows;
		assert(ppp.size() == mRows);
		assert(mm.size() == cols);

		auto v = mYs;
		T* __restrict pp = ppp.data();
		const T* __restrict m = mm.data();

		for (u64 i = 0; i < cols; )
		{
			auto end = cols;
			for (u64 j = 0; j < mWeight; ++j)
			{
				if (v[j] == mRows)
					v[j] = 0;

				auto jEnd = cols - v[j] + i;
				end = std::min<u64>(end, jEnd);
			}
			T* __restrict P = &pp[i];
			T* __restrict PE = &pp[end];

			switch (mWeight)
			{
			case 5:
			{
				const T* __restrict M0 = &m[v[0]];
				const T* __restrict M1 = &m[v[1]];
				const T* __restrict M2 = &m[v[2]];
				const T* __restrict M3 = &m[v[3]];
				const T* __restrict M4 = &m[v[4]];

				v[0] += end - i;
				v[1] += end - i;
				v[2] += end - i;
				v[3] += end - i;
				v[4] += end - i;
				i = end;

				while (P != PE)
				{
					*P = *P
						^ *M0
						^ *M1
						^ *M2
						^ *M3
						^ *M4
						;

					++M0;
					++M1;
					++M2;
					++M3;
					++M4;
					++P;
				}


				break;
			}
			case 11:
			{

				const T* __restrict M0 = &m[v[0]];
				const T* __restrict M1 = &m[v[1]];
				const T* __restrict M2 = &m[v[2]];
				const T* __restrict M3 = &m[v[3]];
				const T* __restrict M4 = &m[v[4]];
				const T* __restrict M5 = &m[v[5]];
				const T* __restrict M6 = &m[v[6]];
				const T* __restrict M7 = &m[v[7]];
				const T* __restrict M8 = &m[v[8]];
				const T* __restrict M9 = &m[v[9]];
				const T* __restrict M10 = &m[v[10]];

				v[0] += end - i;
				v[1] += end - i;
				v[2] += end - i;
				v[3] += end - i;
				v[4] += end - i;
				v[5] += end - i;
				v[6] += end - i;
				v[7] += end - i;
				v[8] += end - i;
				v[9] += end - i;
				v[10] += end - i;
				i = end;

				while (P != PE)
				{
					*P = *P
						^ *M0
						^ *M1
						^ *M2
						^ *M3
						^ *M4
						^ *M5
						^ *M6
						^ *M7
						^ *M8
						^ *M9
						^ *M10
						;

					++M0;
					++M1;
					++M2;
					++M3;
					++M4;
					++M5;
					++M6;
					++M7;
					++M8;
					++M9;
					++M10;
					++P;
				}

				break;
			}
			default:
				while (i != end)
				{
					for (u64 j = 0; j < mWeight; ++j)
					{
						auto row = v[j];
						pp[i] = pp[i] ^ m[row];
						++v[j];
					}
					++i;
				}
				break;
			}

		}
	}

	// perform the circuit transpose of the encoding algorithm twice.
	// the output it written to ppp0 and ppp1.
	template<typename T0, typename T1>
	void details::SilverLeftEncoder::dualEncode2(
		span<T0> ppp0, span<T1> ppp1,
		span<const T0> mm0, span<const T1> mm1)
	{
		auto cols = mRows;
		// pp = pp + m * A
		auto v = mYs;
		T0* __restrict pp0 = ppp0.data();
		T1* __restrict pp1 = ppp1.data();
		const T0* __restrict m0 = mm0.data();
		const T1* __restrict m1 = mm1.data();

		for (u64 i = 0; i < cols; )
		{
			auto end = cols;
			for (u64 j = 0; j < mWeight; ++j)
			{
				if (v[j] == mRows)
					v[j] = 0;

				auto jEnd = cols - v[j] + i;
				end = std::min<u64>(end, jEnd);
			}
			switch (mWeight)
			{
			case 5:
				while (i != end)
				{
					auto& r0 = v[0];
					auto& r1 = v[1];
					auto& r2 = v[2];
					auto& r3 = v[3];
					auto& r4 = v[4];

					pp0[i] = pp0[i]
						^ m0[r0]
						^ m0[r1]
						^ m0[r2]
						^ m0[r3]
						^ m0[r4];

					pp1[i] = pp1[i]
						^ m1[r0]
						^ m1[r1]
						^ m1[r2]
						^ m1[r3]
						^ m1[r4];

					++r0;
					++r1;
					++r2;
					++r3;
					++r4;
					++i;
				}
				break;
			case 11:
				while (i != end)
				{
					auto& r0 = v[0];
					auto& r1 = v[1];
					auto& r2 = v[2];
					auto& r3 = v[3];
					auto& r4 = v[4];
					auto& r5 = v[5];
					auto& r6 = v[6];
					auto& r7 = v[7];
					auto& r8 = v[8];
					auto& r9 = v[9];
					auto& r10 = v[10];

					pp0[i] = pp0[i]
						^ m0[r0]
						^ m0[r1]
						^ m0[r2]
						^ m0[r3]
						^ m0[r4]
						^ m0[r5]
						^ m0[r6]
						^ m0[r7]
						^ m0[r8]
						^ m0[r9]
						^ m0[r10]
						;

					pp1[i] = pp1[i]
						^ m1[r0]
						^ m1[r1]
						^ m1[r2]
						^ m1[r3]
						^ m1[r4]
						^ m1[r5]
						^ m1[r6]
						^ m1[r7]
						^ m1[r8]
						^ m1[r9]
						^ m1[r10]
						;

					++r0;
					++r1;
					++r2;
					++r3;
					++r4;
					++r5;
					++r6;
					++r7;
					++r8;
					++r9;
					++r10;
					++i;
				}

				break;
			default:
				while (i != end)
				{
					for (u64 j = 0; j < mWeight; ++j)
					{
						auto row = v[j];
						pp0[i] = pp0[i] ^ m0[row];
						pp1[i] = pp1[i] ^ m1[row];
						++v[j];
					}
					++i;
				}
				break;
			}
		}
	}


	template<typename T>
	void details::SilverRightEncoder::dualEncode(span<T> x)
	{
		// solves for x such that y = M x, ie x := H^-1 y 
		assert(mExtend);
		assert(cols() == x.size());

		constexpr int FIXED_OFFSET_SIZE = 2;
		if (mOffsets.size() != FIXED_OFFSET_SIZE)
			throw RTE_LOC;

		std::vector<u64> offsets(mOffsets.size());
		for (u64 j = 0; j < offsets.size(); ++j)
		{
			offsets[j] = mRows - 1 - mOffsets[j] - mGap;
		}

		u64 i = mRows - 1;
		T* __restrict ofCol0 = &x[offsets[0]];
		T* __restrict ofCol1 = &x[offsets[1]];
		T* __restrict xi = &x[i];

		switch (mCode)
		{
		case osuCrypto::SilverCode::Weight5:
		{
			auto mainEnd =
				roundUpTo(
					*std::max_element(mOffsets.begin(), mOffsets.end())
					+ mGap,
					16);

			T* __restrict xx = xi - 16;

			for (; i > mainEnd;)
			{
				for (u64 jj = 0; jj < 16; ++jj)
				{

					auto col0 = diagMtx_g16_w5_seed1_t36[i & 15][0];
					auto col1 = diagMtx_g16_w5_seed1_t36[i & 15][1];
					auto col2 = diagMtx_g16_w5_seed1_t36[i & 15][2];
					auto col3 = diagMtx_g16_w5_seed1_t36[i & 15][3];

					T* __restrict xc0 = xx + col0;
					T* __restrict xc1 = xx + col1;
					T* __restrict xc2 = xx + col2;
					T* __restrict xc3 = xx + col3;

					*xc0 = *xc0 ^ *xi;
					*xc1 = *xc1 ^ *xi;
					*xc2 = *xc2 ^ *xi;
					*xc3 = *xc3 ^ *xi;

					*ofCol0 = *ofCol0 ^ *xi;
					*ofCol1 = *ofCol1 ^ *xi;


					--ofCol0;
					--ofCol1;

					--xx;
					--xi;
					--i;
				}
			}

			break;
		}
		case osuCrypto::SilverCode::Weight11:
		{


			auto mainEnd =
				roundUpTo(
					*std::max_element(mOffsets.begin(), mOffsets.end())
					+ mGap,
					32);

			T* __restrict xx = xi - 32;

			for (; i > mainEnd;)
			{
				for (u64 jj = 0; jj < 32; ++jj)
				{

					auto col0 = diagMtx_g32_w11_seed2_t36[i & 31][0];
					auto col1 = diagMtx_g32_w11_seed2_t36[i & 31][1];
					auto col2 = diagMtx_g32_w11_seed2_t36[i & 31][2];
					auto col3 = diagMtx_g32_w11_seed2_t36[i & 31][3];
					auto col4 = diagMtx_g32_w11_seed2_t36[i & 31][4];
					auto col5 = diagMtx_g32_w11_seed2_t36[i & 31][5];
					auto col6 = diagMtx_g32_w11_seed2_t36[i & 31][6];
					auto col7 = diagMtx_g32_w11_seed2_t36[i & 31][7];
					auto col8 = diagMtx_g32_w11_seed2_t36[i & 31][8];
					auto col9 = diagMtx_g32_w11_seed2_t36[i & 31][9];

					T* __restrict xc0 = xx + col0;
					T* __restrict xc1 = xx + col1;
					T* __restrict xc2 = xx + col2;
					T* __restrict xc3 = xx + col3;
					T* __restrict xc4 = xx + col4;
					T* __restrict xc5 = xx + col5;
					T* __restrict xc6 = xx + col6;
					T* __restrict xc7 = xx + col7;
					T* __restrict xc8 = xx + col8;
					T* __restrict xc9 = xx + col9;

					*xc0 = *xc0 ^ *xi;
					*xc1 = *xc1 ^ *xi;
					*xc2 = *xc2 ^ *xi;
					*xc3 = *xc3 ^ *xi;
					*xc4 = *xc4 ^ *xi;
					*xc5 = *xc5 ^ *xi;
					*xc6 = *xc6 ^ *xi;
					*xc7 = *xc7 ^ *xi;
					*xc8 = *xc8 ^ *xi;
					*xc9 = *xc9 ^ *xi;

					*ofCol0 = *ofCol0 ^ *xi;
					*ofCol1 = *ofCol1 ^ *xi;


					--ofCol0;
					--ofCol1;

					--xx;
					--xi;
					--i;
				}
			}

			break;
		}
		default:
			throw RTE_LOC;
			break;
		}

		offsets[0] = ofCol0 - x.data();
		offsets[1] = ofCol1 - x.data();

		for (; i != ~u64(0); --i)
		{

			switch (mCode)
			{
			case osuCrypto::SilverCode::Weight5:

				for (u64 j = 0; j < 4; ++j)
				{
					auto col = diagMtx_g16_w5_seed1_t36[i & 15][j] + i - 16;
					if (col < mRows)
						x[col] = x[col] ^ x[i];
				}
				break;
			case osuCrypto::SilverCode::Weight11:

				for (u64 j = 0; j < 10; ++j)
				{
					auto col = diagMtx_g32_w11_seed2_t36[i & 31][j] + i - 32;
					if (col < mRows)
						x[col] = x[col] ^ x[i];
				}
				break;
			default:
				break;
			}

			for (u64 j = 0; j < FIXED_OFFSET_SIZE; ++j)
			{
				auto& col = offsets[j];

				if (col >= mRows)
					break;
				assert(i - mOffsets[j] - mGap == col);

				x[col] = x[col] ^ x[i];
				--col;
			}
		}
	}

	template<typename T0, typename T1>
	void details::SilverRightEncoder::dualEncode2(span<T0> x0, span<T1> x1)
	{
		// solves for x such that y = M x, ie x := H^-1 y 
		assert(mExtend);
		assert(cols() == x0.size());
		assert(cols() == x1.size());

		constexpr int FIXED_OFFSET_SIZE = 2;
		if (mOffsets.size() != FIXED_OFFSET_SIZE)
			throw RTE_LOC;

		std::vector<u64> offsets(mOffsets.size());
		for (u64 j = 0; j < offsets.size(); ++j)
		{
			offsets[j] = mRows - 1 - mOffsets[j] - mGap;
		}

		u64 i = mRows - 1;
		T0* __restrict ofCol00 = &x0[offsets[0]];
		T0* __restrict ofCol10 = &x0[offsets[1]];
		T1* __restrict ofCol01 = &x1[offsets[0]];
		T1* __restrict ofCol11 = &x1[offsets[1]];
		T0* __restrict xi0 = &x0[i];
		T1* __restrict xi1 = &x1[i];

		switch (mCode)
		{
		case osuCrypto::SilverCode::Weight5:
		{

			auto mainEnd =
				roundUpTo(
					*std::max_element(mOffsets.begin(), mOffsets.end())
					+ mGap,
					16);

			T0* __restrict xx0 = xi0 - 16;
			T1* __restrict xx1 = xi1 - 16;

			for (; i > mainEnd;)
			{
				for (u64 jj = 0; jj < 16; ++jj)
				{

					auto col0 = diagMtx_g16_w5_seed1_t36[i & 15][0];
					auto col1 = diagMtx_g16_w5_seed1_t36[i & 15][1];
					auto col2 = diagMtx_g16_w5_seed1_t36[i & 15][2];
					auto col3 = diagMtx_g16_w5_seed1_t36[i & 15][3];

					T0* __restrict xc00 = xx0 + col0;
					T0* __restrict xc10 = xx0 + col1;
					T0* __restrict xc20 = xx0 + col2;
					T0* __restrict xc30 = xx0 + col3;
					T1* __restrict xc01 = xx1 + col0;
					T1* __restrict xc11 = xx1 + col1;
					T1* __restrict xc21 = xx1 + col2;
					T1* __restrict xc31 = xx1 + col3;

					*xc00 = *xc00 ^ *xi0;
					*xc10 = *xc10 ^ *xi0;
					*xc20 = *xc20 ^ *xi0;
					*xc30 = *xc30 ^ *xi0;

					*xc01 = *xc01 ^ *xi1;
					*xc11 = *xc11 ^ *xi1;
					*xc21 = *xc21 ^ *xi1;
					*xc31 = *xc31 ^ *xi1;

					*ofCol00 = *ofCol00 ^ *xi0;
					*ofCol10 = *ofCol10 ^ *xi0;
					*ofCol01 = *ofCol01 ^ *xi1;
					*ofCol11 = *ofCol11 ^ *xi1;


					--ofCol00;
					--ofCol10;
					--ofCol01;
					--ofCol11;

					--xx0;
					--xx1;
					--xi0;
					--xi1;
					--i;
				}
			}

			break;
		}
		case osuCrypto::SilverCode::Weight11:
		{


			auto mainEnd =
				roundUpTo(
					*std::max_element(mOffsets.begin(), mOffsets.end())
					+ mGap,
					32);

			T0* __restrict xx0 = xi0 - 32;
			T1* __restrict xx1 = xi1 - 32;

			for (; i > mainEnd;)
			{
				for (u64 jj = 0; jj < 32; ++jj)
				{

					auto col0 = diagMtx_g32_w11_seed2_t36[i & 31][0];
					auto col1 = diagMtx_g32_w11_seed2_t36[i & 31][1];
					auto col2 = diagMtx_g32_w11_seed2_t36[i & 31][2];
					auto col3 = diagMtx_g32_w11_seed2_t36[i & 31][3];
					auto col4 = diagMtx_g32_w11_seed2_t36[i & 31][4];
					auto col5 = diagMtx_g32_w11_seed2_t36[i & 31][5];
					auto col6 = diagMtx_g32_w11_seed2_t36[i & 31][6];
					auto col7 = diagMtx_g32_w11_seed2_t36[i & 31][7];
					auto col8 = diagMtx_g32_w11_seed2_t36[i & 31][8];
					auto col9 = diagMtx_g32_w11_seed2_t36[i & 31][9];

					T0* __restrict xc00 = xx0 + col0;
					T0* __restrict xc10 = xx0 + col1;
					T0* __restrict xc20 = xx0 + col2;
					T0* __restrict xc30 = xx0 + col3;
					T0* __restrict xc40 = xx0 + col4;
					T0* __restrict xc50 = xx0 + col5;
					T0* __restrict xc60 = xx0 + col6;
					T0* __restrict xc70 = xx0 + col7;
					T0* __restrict xc80 = xx0 + col8;
					T0* __restrict xc90 = xx0 + col9;

					T1* __restrict xc01 = xx1 + col0;
					T1* __restrict xc11 = xx1 + col1;
					T1* __restrict xc21 = xx1 + col2;
					T1* __restrict xc31 = xx1 + col3;
					T1* __restrict xc41 = xx1 + col4;
					T1* __restrict xc51 = xx1 + col5;
					T1* __restrict xc61 = xx1 + col6;
					T1* __restrict xc71 = xx1 + col7;
					T1* __restrict xc81 = xx1 + col8;
					T1* __restrict xc91 = xx1 + col9;

					*xc00 = *xc00 ^ *xi0;
					*xc10 = *xc10 ^ *xi0;
					*xc20 = *xc20 ^ *xi0;
					*xc30 = *xc30 ^ *xi0;
					*xc40 = *xc40 ^ *xi0;
					*xc50 = *xc50 ^ *xi0;
					*xc60 = *xc60 ^ *xi0;
					*xc70 = *xc70 ^ *xi0;
					*xc80 = *xc80 ^ *xi0;
					*xc90 = *xc90 ^ *xi0;

					*xc01 = *xc01 ^ *xi1;
					*xc11 = *xc11 ^ *xi1;
					*xc21 = *xc21 ^ *xi1;
					*xc31 = *xc31 ^ *xi1;
					*xc41 = *xc41 ^ *xi1;
					*xc51 = *xc51 ^ *xi1;
					*xc61 = *xc61 ^ *xi1;
					*xc71 = *xc71 ^ *xi1;
					*xc81 = *xc81 ^ *xi1;
					*xc91 = *xc91 ^ *xi1;

					*ofCol00 = *ofCol00 ^ *xi0;
					*ofCol10 = *ofCol10 ^ *xi0;

					*ofCol01 = *ofCol01 ^ *xi1;
					*ofCol11 = *ofCol11 ^ *xi1;


					--ofCol00;
					--ofCol10;
					--ofCol01;
					--ofCol11;

					--xx0;
					--xx1;

					--xi0;
					--xi1;
					--i;
				}
			}

			break;
		}
		default:
			throw RTE_LOC;
			break;
		}

		offsets[0] = ofCol00 - x0.data();
		offsets[1] = ofCol10 - x0.data();

		for (; i != ~u64(0); --i)
		{

			switch (mCode)
			{
			case osuCrypto::SilverCode::Weight5:

				for (u64 j = 0; j < 4; ++j)
				{
					auto col = diagMtx_g16_w5_seed1_t36[i & 15][j] + i - 16;
					if (col < mRows)
					{
						x0[col] = x0[col] ^ x0[i];
						x1[col] = x1[col] ^ x1[i];
					}
				}
				break;
			case osuCrypto::SilverCode::Weight11:

				for (u64 j = 0; j < 10; ++j)
				{
					auto col = diagMtx_g32_w11_seed2_t36[i & 31][j] + i - 32;
					if (col < mRows)
					{
						x0[col] = x0[col] ^ x0[i];
						x1[col] = x1[col] ^ x1[i];
					}
				}
				break;
			default:
				break;
			}

			for (u64 j = 0; j < FIXED_OFFSET_SIZE; ++j)
			{
				auto& col = offsets[j];

				if (col >= mRows)
					break;
				assert(i - mOffsets[j] - mGap == col);

				x0[col] = x0[col] ^ x0[i];
				x1[col] = x1[col] ^ x1[i];
				--col;
			}
		}
	}




}
#endif //  ENABLE_INSECURE_SILVER


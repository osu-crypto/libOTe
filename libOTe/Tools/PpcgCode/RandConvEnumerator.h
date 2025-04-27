#pragma once

#include "EnumeratorTools.h"
#include "Enumerator.h"
#include "cryptoTools/Common/Matrix.h"
#include <iostream>
#include "cryptoTools/Common/ThreadBarrier.h"
#include "Print.h"
#include "LoadingBar.h"
#include "libOTe/Tools/LDPC/Mtx.h"
//#include "oldMinDistTest.h"
#include "cryptoTools/Common/BitVector.h"
#include <thread>
#include "BallsBins.h"

namespace osuCrypto {

	template<typename I, typename R>
	struct RandConvEnumerator : Enumerator<R>
	{
		RandConvEnumerator(
			u64 k,
			u64 n,
			u64 sigma,
			const Choose<I>& choose,
			const BallsBinsCap<I>& bbc,
			u64 numThreads = 0)
			: Enumerator<R>(k, n)
			, mSigma(sigma)
			//, mSystematic(sys)
			, mNumThreads(numThreads ? numThreads : std::thread::hardware_concurrency())
			, mChoose(choose)
			, mBallsBinsCap(bbc)
		{
			if (k != n)
				throw RTE_LOC;
		}

		// the number of rows
		using Enumerator<R>::mK;
		// the number of columns
		using Enumerator<R>::mN;
		using Enumerator<R>::mLoadBar;

		// the state size of the convolution
		u64 mSigma = 0;

		// the number threads for the enumerator computation.
		u64 mNumThreads = 0;

		// should the matrix be of the form G=(I||G') where G' contains the blocks.
		//bool mSystematic = false;

		// The n choose k cache for the integer type I (might be Float)
		const Choose<I>& mChoose;
		
		// balls bin cap for cap=sigma-1.
		const BallsBinsCap<I>& mBallsBinsCap;

		u64 numTicks() const override
		{
			return mK;
		}

		// map the input dist to the output dist.
		void enumerate(
			span<const R> inDist,
			span<R> outDist) override
		{
			enumerate(inDist, outDist,
				mK, mN, mSigma, mNumThreads, mChoose, mBallsBinsCap, {}, mLoadBar);
		}

		// map the input dist to the output dist.
		// also outputs the full enumerator matrix.
		void enumerate(
			span<const R> inDist,
			span<R> outDist,
			MatrixView<R> full) override
		{
			enumerate(inDist, outDist,
				mK, mN, mSigma, mNumThreads, mChoose, mBallsBinsCap, full, mLoadBar);
		}


		// a helper function that computes the E_wh term in isolation.
		static R enumerate(
			u64 w, u64 h,
			u64 r, u64 t0,
			u64 k, u64 n, u64 sigma,
			const Choose<I>& choose,
			const BallsBinsCap<I>& bbc)
		{
			if (bbc.mCap != sigma - 1)
				throw RTE_LOC;

			if (w == 0 && h == 0 && r == 0 && t0 == 0)
				return 1;

			auto r1 = divCeil(r, 2);
			auto r0 = r - r1;
			i64 v = n - h - t0 - r0 * sigma;
			i64 s = n - r1 - v;
			if (s < 0)
				return 0;
			if (v < 0)
				return 0;
			auto E1 = choose(h - 1, r1 - 1);
			auto E2 = bbc(t0, h - r0);
			auto E3 = ballsBins(v, r0 + 1, choose);
			auto E4 = choose(s, w - r1);

			return R(E1 * E2 * E3 * E4) / pow2_<I>(s);
		}

		// a helper function that computes the E_wh term in isolation.
		static R enumerate(
			u64 w, u64 h,
			u64 k, u64 n, u64 sigma,
			const Choose<I>& choose,
			const BallsBinsCap<I>& bbc)
		{
			if (!(w <= k && h <= n && sigma <= k))
				throw RTE_LOC;
			if (k % sigma)
				throw RTE_LOC;
			if (n % k)
				throw RTE_LOC;
			if (w == 0 && h == 0)
				return 1;
			if (w == 0 || h == 0)
				return 0;

			R enumerator = 0;

			// each run requires
			// * one 1 in the input
			// * one 1 in the output
			// * sigma zeros in the output
			auto rMax = n;// std::min<i64>(std::min<i64>(w, h), 2 * ((n - h) / sigma) + 1);
			for (i64 r = 1; r <= rMax; ++r)
			{

				// the number of zeros in the runs is limited by
				// * having at most n-h 0s in the output
				// * out of these n-h 0s, r0 * sigma  are used for terminations.
				// * every 1 in the output that is not followed by a termination 
				//   can have at most sigma-1 0s. Therefore there can be at most
				//   (h-r0)(sigma-1) free zeros.
				auto t0Max = n - h;// std::min<i64>(n - h - r0 * sigma, (h - r0) * (sigma - 1));
				for (i64 t0 = 0; t0 <= t0Max; ++t0)
				{
					//i64 v = n - h - t0 - r0 * sigma;
					//if (v < 0)
					//	continue;

					//auto E1 = choose(h - 1, r1 - 1);
					//auto E2 = bbc(t0, h - r0, sigma - 1);
					//auto E3 = ballsBins(v, r0 + 1, choose);
					//auto E4 = choose(n - r1 - v, w - r1);

					R Ewhrt = enumerate(w, h, r, t0, k, n, sigma, choose, bbc);
					//R(E1 * E2 * E3 * E4) / pow2_<I>(v);

					enumerator += Ewhrt;
				}
			}

			if constexpr(std::is_same_v<R,Rat>)
				enumerator.backend().normalize();

			return enumerator;
		}




		// optimized block enumerator
		// 
		// inputDist: input the input weight distribution, if empty, we assume (w choose k)
		// outputDist: output distribution.
		// systematic: replace E_{w,h} with E_{w,h-w}. This should be true
		//    for the last subcode, e.g. G = (I ||(G1 G2 G3)), then G3 is systematic...
		// k = input length (inputDist.size() - 1)
		// n = output length (outputDist.size() - 1)
		// sigma = the subblock size
		// numThreads = number of threads to use
		// choose = pascal triangle cache for the integer/floating point type
		// choose2 = pascal triangle cache for the integer type (required for the labeledBallsBinsCap)
		// full = either void and then not used, or a matrix of R and the full 
		//    enumerator is written to it.
		template<typename Full = int>
		static void enumerate(
			span<const R> inputDist,
			span<R> outputDist,
			u64 k,
			u64 n,
			u64 sigma,
			u64 numThreads,
			const Choose<I>& choose,
			const BallsBinsCap<I>& bbc,
			Full&& full = {},
			LoadingBar* laodingBar = nullptr)
		{
			if (laodingBar)
				laodingBar->name("BlockEnumerator");

			if (inputDist.size() != 0 && inputDist.size() != k + 1)
				throw RTE_LOC;
			if (outputDist.size() != n + 1)
				throw RTE_LOC;
			if (!sigma || !k)
				throw RTE_LOC;
			if (k % sigma)
				throw RTE_LOC;
			if (n % k)
				throw RTE_LOC;
			if (numThreads < 1)
				throw RTE_LOC;

			//auto nn = systematic ? n - k : n;
			//if (nn % k)
			//	throw RTE_LOC;

			//auto e = nn / k;
			//auto qMax = k / sigma;

			// v[q] = 2^{-e sigma q} * C(k/sigma, q)
			//std::vector<R> v(qMax + 1);
			//Matrix<R> D(numThreads - 1, outputDist.size());
			//std::vector<std::vector<R>> D(numThreads - 1); for (auto& d : D)d.resize(outputDist.size());;
			//ThreadBarrier vBarrier(numThreads);
			//ThreadBarrier cBarrier(numThreads);

			std::vector<R> inputFrac(inputDist.size());
			auto start = std::chrono::system_clock::now();

			// special case the zero weight input.
			if constexpr (std::is_same_v<Full, int> == false)
			{
				if (full.rows() != k + 1)
					throw RTE_LOC;
				if (full.cols() != n + 1)
					throw RTE_LOC;
				full(0, 0) = 1;
			}
			outputDist[0] = inputDist.size() ? inputDist[0] : 1;


			//for (u64 w = 0; w < k; ++w)
			//{
			//	inputFrac[w] = inputDist[w] / choose(k, w);
			//}


			for (u64 h = 1; h <= n; ++h)
			{
				for (u64 w = 1; w <= k; ++w)
				{
					auto Ewh = enumerate(w, h, k, n, sigma, choose, bbc);
					outputDist[h] += inputDist[w] * Ewh / choose(k,w);

					if constexpr (std::is_same_v<Full, int> == false)
					{
						full(w, h) = Ewh;
					}

					if constexpr (std::is_same_v<Rat, Float>)
					{
						if (isnan(outputDist[h]))
						{
							std::lock_guard l(gIoStreamMtx);
							std::cout << "outputDist[" << h << "] NAN " << std::endl;
							int i = 0;
							std::cin >> i;

						}
					}
				}


				if constexpr (std::is_same_v<std::remove_cvref_t<R>, Rat>)
				{
					outputDist[h].backend().normalize();
				}
			}


		}

	};


	// we will generate all G <- D and exhaustively
	// encode all c = x G and construct the enumerator.
	// We then compare this with the formula based enumerator.
	void RandConvEnum_exhaustive_Test(const CLP& cmd);

	void RandConvEnum_single_Test(const CLP& cmd);


}



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
			const BallsBinsCap<Int>& bbc,
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
		const BallsBinsCap<Int>& mBallsBinsCap;

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
			i64 w, i64 h,
			i64 r, i64 t0,
			i64 k, i64 n, i64 sigma,
			const Choose<I>& choose,
			const BallsBinsCap<Int>& bbc)
		{
			if (bbc.mCap != sigma - 1)
				throw RTE_LOC;
			if (w < 0 || h < 0 || r < 0 || t0 < 0 || k < 0 || n < 0 || sigma <= 0)
				return 0;

			if (w == 0 && h == 0 && r == 0 && t0 == 0)
				return 1;

			auto r1 = divCeil(r, 2);
			auto r0 = r - r1;
			auto v = n - h - t0 - r0 * sigma;
			auto s = n - r1 - v;
			if (v < 0 || s < 0)
				return 0;

			auto E1 = choose_<I>(h - 1, r1 - 1);
			auto E2 = bbc(t0, h - r0);
			auto E3 = ballsBins<I>(v, r0 + 1, choose);
			auto E4 = choose_<I>(s, w - r1);

			return R(E1 * E2 * E3 * E4) / pow2_<I>(s);
		}

		// a helper function that computes the E_wh term in isolation.
		static R enumerate(
			i64 w, i64 h,
			i64 k, i64 n, i64 sigma,
			const Choose<I>& choose,
			const BallsBinsCap<Int>& bbc)
		{
			if (w < 0 || h < 0 || k < 0 || n < 0 || sigma <= 0)
				throw RTE_LOC;
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

			// each on run must at with a 1 in the input and output.
			// each on run must (except the last) must terminate with sigma zeros.
			// we have (n-h) zeros, therefore we can have at most 2(n-h)/sigma runs.
			auto rMax = std::min<i64>(
				2 * std::min(w, h) + 1,
				2 * ((n - h) / sigma) + 1);
			for (i64 r = 1; r <= rMax; ++r)
			{
				auto r1 = divCeil(r, 2);
				auto r0 = r - r1;

				// just looking at the number of output zeros available,
				// we know there are (n-h) zeros, and (r1 - 1) * sigma
				// are used for terminations. 
				// We also have h-r1 bins, each with capacity sigma - 1.
				i64 t0Max = std::min<i64>(
					n - h - (r1 - 1) * sigma,
					(h - r0) * (sigma - 1));
				if (t0Max < 0)
					continue;

				for (i64 t0 = 0; t0 <= t0Max; ++t0)
				{
					R Ewhrt = enumerate(w, h, r, t0, k, n, sigma, choose, bbc);
					enumerator += Ewhrt;
				}
			}

			if constexpr (std::is_same_v<R, Rat>)
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
			const BallsBinsCap<Int>& bbc,
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


			std::vector<R> inputFrac(inputDist.size());
			for (u64 w = 0; w <= k; ++w)
			{
				inputFrac[w] = inputDist[w] / choose(k, w);
			}

			std::vector<std::jthread> thrds(numThreads);
			for (u64 i = 0; i < numThreads; ++i)
			{
				thrds[i] = std::jthread([&, i] {
					for (u64 h = 1 + i; h <= n; h += numThreads)
					{
						R dh = 0;
						for (u64 w = 1; w <= k; ++w)
						{
							auto Ewh = enumerate(w, h, k, n, sigma, choose, bbc);
							dh += inputFrac[w] * Ewh;// / choose(k, w);

							if constexpr (std::is_same_v<Full, int> == false)
							{
								full(w, h) = Ewh;
							}

							if constexpr (std::is_same_v<Rat, Float>)
							{
								if (isnan(dh))
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
							dh.backend().normalize();
						}

						outputDist[h] = dh;
					}

					});
			}

		}

	};


	// we will generate all G <- D and exhaustively
	// encode all c = x G and construct the enumerator.
	// We then compare this with the formula based enumerator.
	void RandConvEnum_exhaustive_Test(const CLP& cmd);

	void RandConvEnum_single_Test(const CLP& cmd);


}



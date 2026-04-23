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
	struct WrapConvEnumerator : Enumerator<R>
	{
		struct Stats
		{
			u64 mHVisited = 0;
			u64 mWHCalls = 0;
			u64 mRVisited = 0;
			u64 mT0Visited = 0;
			u64 mVVisited = 0;
			u64 mDVisited = 0;
			u64 mNonZeroTerms = 0;
			u64 mSkipNegZ = 0;
			u64 mSkipNegF0 = 0;
			u64 mSkipNegF1 = 0;
			u64 mSkipNegT0 = 0;
			u64 mSkipNegT1 = 0;
			u64 mSkipHr = 0;
			u64 mSkipK = 0;
			u64 mSkipD = 0;
		};

		WrapConvEnumerator(
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
			if (k > n)
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
		u64 mHMax = 0;
		Stats mStats;

		u64 numTicks() const override
		{
			return mK;
		}

		// map the input dist to the output dist.
		void enumerate(
			span<const R> inDist,
			span<R> outDist) override
		{
			enumerateImpl(inDist, outDist,
				mK, mN, mSigma, mNumThreads, mChoose, mBallsBinsCap,
				mHMax ? mHMax : mN,
				&mStats, {}, mLoadBar);
		}

		// map the input dist to the output dist.
		// also outputs the full enumerator matrix.
		void enumerate(
			span<const R> inDist,
			span<R> outDist,
			MatrixView<R> full) override
		{
			enumerateImpl(inDist, outDist,
				mK, mN, mSigma, mNumThreads, mChoose, mBallsBinsCap,
				mHMax ? mHMax : mN,
				&mStats, full, mLoadBar);
		}


		// a helper function that computes the E_wh term in isolation.
		template<
			bool verbose = false>
		static R enumerate(
			i64 w, i64 h,
			i64 r, i64 t0,
			i64 v, i64 d,
			i64 k, i64 n,
			i64 sigma,
			const Choose<I>& choose,
			const BallsBinsCap<Int>& bbc,
			Stats* stats = nullptr)
		{
			if (bbc.mCap != sigma - 2)
				throw RTE_LOC;
			if (sigma == 1)
				throw RTE_LOC;

			if (w == 0 && h == 0 && r == 0 && t0 == 0 && v == 0 && d == 0)
				return 1;

			// number of on runs
			i64 r1 = divCeil(r, 2);
			// number of off runs not the first. number of terminations.
			i64 r0 = r - r1;
			// number of deadzone/off runs
			i64 z = n - h - (v + d) * (sigma - 1) - t0 - r0 * sigma;
			// number of free zeros in the input
			i64 f0 = n - w - z - v;
			// number of free ones in the input
			i64 f1 = w - r;
			// number of free ones in the output
			i64 t1 = h - v - r0 - d;
			// number of times the convolutions values matters, the scaling factor.
			i64 s = f1 + f0;

			auto negZ = z < 0;
			auto negF0 = f0 < 0;
			auto negF1 = f1 < 0;
			auto negT0 = t0 < 0;
			auto negT1 = t1 < 0;
			auto hrCheck = h - r0 - d < 0;
			auto kCheck = k - r - v - f0 - f1 < 0;
			auto dCheck = d > (r1 - r0);

			// there is a special case when sigma=1, we can have it where there 
			// is no trailing zone but we have free output ones. These two cases 
			// look the same. The fix is to skip if we have t1 for sigma=1
			//auto special = sigma == 1 && t1;

			// For the special case of sigma = 1, we have a problem that
			// free output 1s look like trailing zones. In this case we disallow
			//auto smallSigmaD = sigma <= 1 && d == 0 && t1;

			bool skip =
				(negZ || negF0 || negF1 || negT0 || negT1 || hrCheck || kCheck || dCheck);
			if (skip && stats)
			{
				stats->mSkipNegZ += negZ;
				stats->mSkipNegF0 += negF0;
				stats->mSkipNegF1 += negF1;
				stats->mSkipNegT0 += negT0;
				stats->mSkipNegT1 += negT1;
				stats->mSkipHr += hrCheck;
				stats->mSkipK += kCheck;
				stats->mSkipD += dCheck;
			}
			if (skip)
				return 0;

			// near terminations can come before or after any output freezone 1.
			auto E1 = ballsBins<I>(v, t1 + d + (r0 == r1), choose);

			// terminations can come before or after any of the free output ones
			// or terminations. There are t1 + v+1 places to put the terminations.
			// we have r1-1 terminations to place (not counting the last if its mandatory).
			auto E2 = ballsBins<I>(r1 - 1, t1 + v + d + (r0 == r1), choose);

			// there are z zeros in the deadzones, and r0+1 bins to put them in.
			auto E3 = ballsBins<I>(z, r0 + 1, choose);
			auto E4 = bbc(t0, t1);
			auto E5 = choose(f0 + f1, f0);
			auto P = E1 * E2 * E3 * E4 * E5;

			if (verbose)
			{


				std::cout << "r1 " << r1 << std::endl;
				std::cout << "r0 " << r0 << std::endl;
				std::cout << "z  " << z << std::endl;
				std::cout << "f0 " << f0 << std::endl;
				std::cout << "f1 " << f1 << std::endl;
				std::cout << "t0 " << t0 << std::endl;
				std::cout << "t1 " << t1 << std::endl;
				std::cout << "s  " << s << std::endl;

				std::cout << "E1 " << E1 << " = B(" << v << ", " << t1 + d + (r0 == r1) << ") ways for near terminations" << std::endl;
				std::cout << "E2 " << E2 << " = B(" << r1 - 1 << ", " << t1 + v + d << ") ways for terminations" << std::endl;
				std::cout << "E3 " << E3 << " = B(" << z << ", " << r0 + 1 << ") ways deadzone 0s." << std::endl;
				std::cout << "E4 " << E4 << " = C(" << t0 << ", " << t1 << ", " << i64(sigma - 2) << ") output freezone zeros" << std::endl;
				std::cout << "E5 " << E5 << " = " << f0 + f1 << " choose " << i64(f0) << " ways for freezones" << std::endl;
				std::cout << "sk " << skip << " = " << negZ << " " << negF0 << " " << negF1 << " "
					<< negT0 << " " << negT1 << " " << hrCheck << " " << kCheck << " "
					<< dCheck << std::endl;

				std::cout << "Sc " << (s < 0 ? -1 : pow2_<Int>(s)) << " = 2^" << s << " scaling" << std::endl;


			}

			return R(P) / to<R>(pow2_<I>(s));
		}

		// a helper function that computes the E_wh term in isolation.
		static R enumerate(
			u64 w, u64 h,
			u64 k, u64 n, u64 sigma,
			const Choose<I>& choose,
			const BallsBinsCap<Int>& bbc,
			Stats* stats = nullptr)
		{
			auto floorDiv = [](i64 numer, i64 denom) -> i64
			{
				if (denom <= 0)
					throw RTE_LOC;
				if (numer >= 0)
					return numer / denom;
				return -(((-numer) + denom - 1) / denom);
			};

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
			auto rMax = std::min<u64>(n, h*2);
			rMax = std::min<u64>(rMax, w);
			rMax = std::min<u64>(rMax, 2 * (n - h) / sigma + 1);

			for (i64 r = 1; r <= rMax; ++r)
			{
				if (stats)
					++stats->mRVisited;
				auto r1 = divCeil(r, 2);
				auto r0 = r - r1;

				// n - h - t0 - r0 * sigma >= 0
				// t0 <= n - h - r0 * sigma 
				i64 t0Max = n - h - r0 * sigma;
				for (i64 t0 = 0; t0 <= t0Max; ++t0)
				{
					if (stats)
						++stats->mT0Visited;
					//i64 z = n - h - t0 - r0 * sigma;
					//if (z < 0)
					//	break;
					//i64 f0 = n - w - z;
					//if (f0 < 0)
					//	break;

					// 0 <= t1
					// 0 <= h - v - r0 
					// v <= h - r0 
					auto vMax = h - r0;

					// 0 <= f0
					// 0 <= n - h - v * (sigma - 1) - t0 - r0 * sigma;
					// v * (sigma - 1) <= n - h - t0 - r0 * sigma
					// v <= (n - h - t0 - r0 * sigma) / (sigma - 1)
					vMax = std::min<i64>(vMax, (n - h - t0 - r0 * sigma) / (sigma - 1));
					for (i64 v = 0; v <= vMax; ++v)
					{
						if (stats)
							++stats->mVVisited;

						//i64 t1 = h - v - r0;
						//if (t1 < 0)
						//	break;
						//i64 z = n - h - v * (sigma - 1) - t0 - r0 * sigma;
						//if (z < 0)
						//	break;
						//i64 f0 = n - w - z - v;
						//if (f0 < 0)
						//	break;
						

						// 0 <= k - r - v - f0 - f1
						// 0 <= k - r - v - (n - w - z - v) - ( w - r)
						// 0 <= k - r - v - n + w + z + v -  w + r
						// 0 <= k - n + z 
						// 0 <= k - n + n - h - (v + d) * (sigma - 1) - t0 - r0 * sigma;
						// 0 <= k - h - (v + d) * (sigma - 1) - t0 - r0 * sigma;
						// (v + d) * (sigma - 1) <= k - h - t0 - r0 * sigma;
						// d <= (k - h - t0 - r0 * sigma) / (sigma - 1) - v;


						// 0 <= t1 = h - v - r0 - d;
						// d <= h-v-r0
						auto dMax = std::min<i64>((r % 2), h - v - r0);
						auto zBase = n - h - v * (sigma - 1) - t0 - r0 * sigma;
						auto kBase = k - n + zBase;
						auto f0Base = h - w + t0 + r0 * sigma + v * (sigma - 2);

						dMax = std::min<i64>(dMax, floorDiv(zBase, i64(sigma - 1)));
						dMax = std::min<i64>(dMax, floorDiv(kBase, i64(sigma - 1)));

						i64 dMin = 0;
						if (f0Base < 0)
							dMin = 1;
						if (dMin && f0Base + i64(sigma - 1) < 0)
							continue;
						if (dMin > dMax)
							continue;

						for (i64 d = dMin; d <= dMax; ++d) // 
						{
							if (stats)
								++stats->mDVisited;
							auto z = n - h - (v + d) * (sigma - 1) - t0 - r0 * sigma;
							if (z < 0)
							{
								if (stats)
								{
									++stats->mSkipNegZ;
									if (k - n + z < 0)
										++stats->mSkipK;
								}
								continue;
							}

							if (k - n + z < 0)
							{
								if (stats)
									++stats->mSkipK;
								continue;
							}

							auto f0 = n - w - z - v;
							if (f0 < 0)
							{
								if (stats)
									++stats->mSkipNegF0;
								continue;
							}

							auto Ewhrt = enumerate(w, h, r, t0, v, d, k, n, sigma, choose, bbc, stats);
							enumerator += Ewhrt;
							if (stats && Ewhrt != R(0))
								++stats->mNonZeroTerms;
							if constexpr (std::is_same_v<Rat, Float>)
							{
								if (isnan(enumerator))
								{
									std::lock_guard l(gIoStreamMtx);
									std::cout << "outputDist[" << h << "] NAN " << std::endl;
									int i = 0;
									std::cin >> i;
								}
							}
						}

					}
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
			enumerateImpl(
				inputDist, outputDist,
				k, n, sigma, numThreads,
				choose, bbc,
				n, nullptr,
				std::forward<Full>(full),
				laodingBar);
		}

		template<typename Full = int>
		static void enumerateImpl(
			span<const R> inputDist,
			span<R> outputDist,
			u64 k,
			u64 n,
			u64 sigma,
			u64 numThreads,
			const Choose<I>& choose,
			const BallsBinsCap<Int>& bbc,
			u64 hLimit,
			Stats* statsOut,
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
			for (auto& v : outputDist)
				v = R(0);
			outputDist[0] = inputDist.size() ? inputDist[0] : 1;
			if (statsOut)
				*statsOut = Stats{};


			std::vector<R> inputFrac(k + 1);
			for (u64 w = 0; w <= k; ++w)
			{
				auto numer = inputDist.size() ? inputDist[w] : to<R>(choose(k, w));
				inputFrac[w] = numer / to<R>(choose(k, w));
			}

			auto hMax = std::min<u64>(hLimit, n);
			std::vector<Stats> threadStats(numThreads);
			std::vector<std::jthread> thrds(numThreads);
			for (u64 i = 0; i < numThreads; ++i)
			{
				thrds[i] = std::jthread([&, i] {
					auto& stats = threadStats[i];
					for (u64 h = 1 + i; h <= hMax; h += numThreads)
					{
						++stats.mHVisited;
						R dh = 0;
						for (u64 w = 1; w <= k; ++w)
						{
							++stats.mWHCalls;
							auto Ewh = enumerate(w, h, k, n, sigma, choose, bbc, &stats);
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

			for (auto& thrd : thrds)
				if (thrd.joinable())
					thrd.join();

			for (auto& stats : threadStats)
			{
				if (statsOut)
				{
					statsOut->mHVisited += stats.mHVisited;
					statsOut->mWHCalls += stats.mWHCalls;
					statsOut->mRVisited += stats.mRVisited;
					statsOut->mT0Visited += stats.mT0Visited;
					statsOut->mVVisited += stats.mVVisited;
					statsOut->mDVisited += stats.mDVisited;
					statsOut->mNonZeroTerms += stats.mNonZeroTerms;
					statsOut->mSkipNegZ += stats.mSkipNegZ;
					statsOut->mSkipNegF0 += stats.mSkipNegF0;
					statsOut->mSkipNegF1 += stats.mSkipNegF1;
					statsOut->mSkipNegT0 += stats.mSkipNegT0;
					statsOut->mSkipNegT1 += stats.mSkipNegT1;
					statsOut->mSkipHr += stats.mSkipHr;
					statsOut->mSkipK += stats.mSkipK;
					statsOut->mSkipD += stats.mSkipD;
				}
			}

		}

	};


	// we will generate all G <- D and exhaustively
	// encode all c = x G and construct the enumerator.
	// We then compare this with the formula based enumerator.
	void WrapConvEnum_exhaustive_Test(const CLP& cmd);

	void WrapConvEnum_single_Test(const CLP& cmd);


}



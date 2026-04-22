#pragma once

#include "Enumerator.h"
#include "EnumeratorTools.h"
#include "BallsBins.h"

namespace osuCrypto {

	template<typename I, typename R>
	struct BandedEnumerator : Enumerator<R>
	{
		BandedEnumerator(
			u64 k,
			u64 n,
			u64 sigma,
			const Choose<I>& choose,
			const BallsBinsCap<Int>& bbc,
			u64 numThreads = 0)
			: Enumerator<R>(k, n)
			, mSigma(sigma)
			, mNumThreads(numThreads ? numThreads : std::thread::hardware_concurrency())
			, mChoose(choose)
			, mBallsBinsCap(bbc)
		{
		}

		using Enumerator<R>::mK;
		using Enumerator<R>::mN;
		using Enumerator<R>::mLoadBar;

		u64 mSigma = 0;
		u64 mNumThreads = 0;
		const Choose<I>& mChoose;
		const BallsBinsCap<Int>& mBallsBinsCap;

		u64 numTicks() const override
		{
			return mN;
		}

		void enumerate(
			span<const R> inDist,
			span<R> outDist) override
		{
			enumerate(inDist, outDist,
				mK, mN, mSigma, mNumThreads, mChoose, mBallsBinsCap, {}, mLoadBar);
		}

		void enumerate(
			span<const R> inDist,
			span<R> outDist,
			MatrixView<R> full) override
		{
			enumerate(inDist, outDist,
				mK, mN, mSigma, mNumThreads, mChoose, mBallsBinsCap, full, mLoadBar);
		}

		static I countInputs(
			i64 w, i64 q, i64 runs,
			i64 k, i64 n, i64 sigma,
			const Choose<I>& choose,
			const BallsBinsCap<Int>& bbc)
		{
			if (w == 0 && q == 0 && runs == 0)
				return 1;
			if (w <= 0 || q <= 0 || runs <= 0)
				return 0;
			if (runs > w)
				return 0;
			if (sigma <= 0)
				return 0;
			if (q < w)
				return 0;
			if (q > n || q > w * sigma)
				return 0;

			auto miniRuns = w - runs;
			auto assignMiniRuns = choose_<I>(w - 1, runs - 1);
			if (assignMiniRuns == 0)
				return 0;

			I total = 0;
			for (i64 c = 0; c < sigma; ++c)
			{
				auto tailTrim = std::min<i64>(sigma - 1 - c, n - k);
				auto qTilde = q - tailTrim;
				auto zerosInsideRuns = qTilde - w - (runs - 1) * (sigma - 1) - c;
				auto waysMiniRunShapes = bbc(zerosInsideRuns, miniRuns);
				if (waysMiniRunShapes == 0)
					continue;

				auto outsideZeros = k - qTilde;
				auto boundaryBins = c == sigma - 1 ? runs + 1 : runs;
				auto waysOutside = ballsBins<I>(outsideZeros, boundaryBins, choose);
				if (waysOutside == 0)
					continue;

				total += assignMiniRuns * waysMiniRunShapes * waysOutside;
			}

			return total;
		}

		static R enumerate(
			u64 w, u64 h,
			u64 k, u64 n, u64 sigma,
			const Choose<I>& choose,
			const BallsBinsCap<Int>& bbc)
		{
			if (w == 0 && h == 0)
				return 1;
			if (w == 0 || h > n || sigma == 0)
				return 0;
			if (sigma == 1)
				return to<R>(choose(k, w) * choose_<I>(w, h)) * invPow2<R>(w);

			R enumerator = 0;
			auto qMax = std::min<u64>(n, w * sigma);
			for (u64 q = w; q <= qMax; ++q)
			{
				auto chooseQH = choose_<I>(q, h);
				if (chooseQH == 0)
					continue;

				I countWQ = 0;
				for (u64 runs = 1; runs <= w; ++runs)
					countWQ += countInputs(w, q, runs, k, n, sigma, choose, bbc);

				if (countWQ == 0)
					continue;

				enumerator += to<R>(countWQ * chooseQH) * invPow2<R>(q);
			}

			normalizeIfNeeded(enumerator);

			return enumerator;
		}

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
			LoadingBar* loadingBar = nullptr)
		{
			if (inputDist.size() != 0 && inputDist.size() != k + 1)
				throw RTE_LOC;
			if (outputDist.size() != n + 1)
				throw RTE_LOC;
			if (sigma == 0 || k == 0 || n < k || numThreads < 1)
				throw RTE_LOC;

			if constexpr (std::is_same_v<Full, int> == false)
			{
				if (full.rows() != k + 1 || full.cols() != n + 1)
					throw RTE_LOC;
				full(0, 0) = 1;
			}

			if (loadingBar)
				loadingBar->name("BandedEnumerator");

			std::fill(outputDist.begin(), outputDist.end(), R(0));
			outputDist[0] = inputDist.size() ? inputDist[0] : 1;
			if constexpr (std::is_same_v<Full, int> == false)
			{
				for (u64 w = 1; w <= k; ++w)
					full(w, 0) = enumerate(w, 0, k, n, sigma, choose, bbc);
			}

			std::vector<R> inputFrac(inputDist.size());
			for (u64 w = 0; w <= k; ++w)
				inputFrac[w] = inputDist.size() ? inputDist[w] / to<R>(choose(k, w)) : R(1);

			for (u64 w = 1; w <= k; ++w)
				outputDist[0] += inputFrac[w] * enumerate(w, 0, k, n, sigma, choose, bbc);

			std::vector<std::jthread> threads(numThreads);
			for (u64 i = 0; i < numThreads; ++i)
			{
				threads[i] = std::jthread([&, i] {
					for (u64 h = 1 + i; h <= n; h += numThreads)
					{
						R dh = 0;
						for (u64 w = 1; w <= k; ++w)
						{
							auto Ewh = enumerate(w, h, k, n, sigma, choose, bbc);
							dh += inputFrac[w] * Ewh;
							if constexpr (std::is_same_v<Full, int> == false)
								full(w, h) = Ewh;
						}
						outputDist[h] = dh;
						if (loadingBar && i == 0)
							loadingBar->tick();
					}
				});
			}
		}
	};

	void BandedEnum_exhaustive_Test(const CLP& cmd);

}

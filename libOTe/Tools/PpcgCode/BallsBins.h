
#pragma once
#include "Choose.h"

namespace osuCrypto
{


	// the number of ways to assign n balls into k bins.
	// this can be thought of as having n+k-1 elements and we have
	// to choose k-1 of them. The remaining n elements are the balls
	// with the elements we chose being the dividers.
	template<typename T>
	inline T ballsBins(i64 n, i64 k, const Choose<T>& choose)
	{
		if (n < 0 || k < 0)
			return 0;
		if (n == 0 && k == 0)
			return 1;

		return choose(n + k - 1, k - 1);
	}


	// we have a matrix with `bins` rows and `cap` columns.
	// we count the number of ways to fill the matrix with `balls` ones
	// each row has weight at least 1.
	// This function returns the number of such configurations.
	template<typename T>
	inline T labeledBallsBinsCap(i64 balls, i64 bins, i64 cap, const Choose<T>& choose) {
		if (balls < 0 || bins < 0 || cap < 0)
			return 0;

		if (balls < bins)
			return 0;
		if (balls == bins * cap)
			return 1;

		T d = 0;
		for (u64 i = 0; i <= bins; ++i) {
			auto mt = choose(bins, i);

			i64 bb = cap * (bins - i64(i));
			if (bb < balls || bb < 0) {
				break;
			}

			auto r = choose(bb, balls);

			if (i & 1)
				d -= mt * r;
			else
				d += mt * r;

			//T v = (w & 1) ? -1 : 1;
			//d += v * mt * r;

		}
		//std::cout << "labeledBallsBinsCap( " << balls << ", " << bins << ", " << cap << ") = " << d << std::endl;

		//if (balls < cap)
		//{
		//	auto d2 = ballsBins<T>(balls, bins, choose);
		//	if (d != d2)
		//		throw RTE_LOC;
		//}
		if (d < 0)
			return 0;
		//if (d < 0)
		//{
		//	std::lock_guard l(gIoStreamMtx);
		//	std::cout << "ballsBinsCap(" << balls << ", " << bins << ", " << cap << ") = " << d << std::endl;
		//	int w = 0;
		//	std::cin >> w;
		//}
		return d;
	}



	// TODO note this function is likely buggy
	template<typename T>
	inline T ballsBinsCap(i64 balls, i64 bins, i64 cap, const Choose<T>& choose)
	{
		// TODO the special cases eg balls=0 are probably buggy, or at least they were in labeledballbincap
		//std::cout << "debug before using" << std::endl;
		//assert(false);
		if (balls < 0 || bins < 0)
			return 0;
		if (balls == 0)
			return 1;
		if (cap < 0 || bins == 0)
			return 0;

		if (balls * 2 > bins * cap)
			balls = bins * cap - balls;

		if (balls < bins * cap)
		{

			T d = 0;
			for (u64 i = 0; i < bins; ++i)
			{
				T v = (i & 1) ? -1 : 1;
				auto mt = choose(bins, i);

				//std::cout << w << " mt " << mt << " = C("<< bins<<", " << w << ")" << std::endl;

				i64 bb = bins + balls - i64(i) * (cap + 1) - 1;
				if (bb < bins - 1 || bb < 0)
					break;

				auto r = choose(bb, bins - 1);
				//std::cout << w << " r " << r << " = C(" << bb << ", " << bins-1 << ")" << std::endl;

				if (mt != mt)
					throw RTE_LOC;
				if (r != r)
					throw RTE_LOC;
				d += v * mt * r;
				//std::cout << w << " d " << d << std::endl;
			}
			return d;
		}
		else if (balls == bins * cap)
			return 1;
		else
			return 0;
	}


	// this caches many different choices for number of balls
	// and bins, for a **fixed** cap.
	template<typename I>
	struct BallsBinsCap
	{

		i64 mBalls = 0;
		i64 mBins = 0;
		i64 mCap = 0;
		I mZero = 0;
		I mOne = 1;

		std::vector<std::vector<I>> mCache;


		BallsBinsCap() = default;
		BallsBinsCap(const BallsBinsCap&) = default;
		BallsBinsCap(BallsBinsCap&&) = default;
		BallsBinsCap& operator=(const BallsBinsCap&) = default;
		BallsBinsCap& operator=(BallsBinsCap&&) = default;

		BallsBinsCap(u64 balls, u64 bins, u64 cap, const Choose<Int>& choose)
		{
			preprocess(balls, bins, cap, choose);
		}

		void preprocess(u64 balls, u64 bins, u64 cap, const Choose<Int>& choose)
		{
			mBalls = balls;
			mBins = bins;
			mCap = cap;
			if (mCap <= 0)
				return;

			if (choose.mN < mBalls + mBins - 1)
				throw RTE_LOC;

			mCache.resize(mBins + 1);
			for (u64 bins = 1; bins <= mBins; ++bins)
			{
				// maxBalls = bins * cap
				// we are symmetric on balls and (bins * cap - balls)
				// therefore we only need to compute the first half.

				// operator() folds values with balls > bins*cap/2 back by symmetry,
				// but the exact midpoint remains in-range and must be cached.
				u64 maxBalls = std::min<u64>(mBalls, (bins * mCap) / 2);
				mCache[bins].resize(maxBalls + 1);
				for (u64 balls = 0; balls < mCache[bins].size(); ++balls)
				{
					mCache[bins][balls] = ballsBinsCap(balls, bins, mCap, choose);
				}
			}
		}

		const I& operator()(i64 balls, i64 bins) const
		{
			auto& r = [=]() mutable -> const I& {

				if (balls < 0 || bins < 0)
					return mZero;
				if (balls == 0)
					return mOne;
				if (mCap <= 0 || bins == 0)
					return mZero;
				if (balls * 2 > bins * mCap)
					return (*this)(bins * mCap - balls, bins);
				if (bins >= mCache.size())
					throw RTE_LOC;
				if (balls >= mCache[bins].size())
					throw RTE_LOC;


				return mCache[bins][balls];
				}();

				//{
				//	Choose<Int> choose(10 + bins + mCap);
				//	auto r2 = ballsBinsCap<Int>(balls, bins, mCap, choose);
				//	if (r != r2)
				//	{
				//		std::cout << r << std::endl;
				//		std::cout << r2 << std::endl;
				//		throw RTE_LOC;
				//	}
				//}
				return r;
				//assert(r == ballsBinsCap(balls, bins, mCap, choose));
		}

	};


}

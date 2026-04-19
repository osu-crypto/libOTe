
#include <bitset>
#include <cassert>
#include <random>

#include "EnumeratorTools.h"
#include "MinimumDistance.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "RepeaterEnumerator.h"
#include "CompositionEnumerator.h"
#include "libOTe/Tools/LDPC/Util.h"
#include "AccumulateEnumerator.h"
#include "BlockEnumerator.h"
#include "BandedEnumerator.h"
#include "ExpandEnumerator.h"
#include "RandConvEnumerator.h"
#include "BallsBins.h"
#include "WrapConvEnumerator.h"
#include "RandomEnumerator.h"

#define BITSET_SIZE 128

namespace osuCrypto {

	u64 labeledBallsBinsCapExhaustive(i64 balls, i64 bins, i64 cap)
	{
		if (balls < 0)
			return 0;
		if (bins < 0)
			return 0;
		if (cap < 0)
			return 0;
		i64 n = bins * cap;
		auto nck = choose_<Int>(n, balls);

		Matrix<u8> M(bins, cap);
		u64 count = 0;
		std::vector<u64> idx(balls);
		for (u64 i = 0; i < nck; ++i)
		{
			ithCombination(i, n, idx);
			std::fill(M.begin(), M.end(), 0);
			for (auto j : idx)
			{
				M(j) = 1;
			}

			bool bad = false;
			for (u64 j = 0; j < bins; ++j)
			{
				if (std::accumulate(M[j].begin(), M[j].end(), 0) == 0)
				{
					bad = true;
					break;
				}
			}

			if (!bad)
			{
				//for (u64 i = 0; i < M.rows(); ++i)
				//{
				//	for (u64 j = 0; j < M.cols(); ++j)
				//	{
				//		std::cout << int(M(i, j)) << " ";
				//	}
				//	std::cout << std::endl;
				//}
				//std::cout << std::endl;

				++count;
			}
		}

		return count;
	}

	void labeledBallsBinsCap_Test(const CLP& cmd)
	{
		u64 binsMax = cmd.getOr("bins", 5);
		u64 capMax = cmd.getOr("cap", 5);

		Choose<Int> pas(binsMax * capMax);

		for (u64 bins = -1; bins < binsMax; ++bins)
		{
			for (u64 cap = -1; cap < capMax; ++cap)
			{

				for (u64 balls = -1; balls < bins * cap; ++balls)
				{
					auto count1 = labeledBallsBinsCapExhaustive(balls, bins, cap);
					auto count2 = labeledBallsBinsCap(balls, bins, cap, pas);
					//std::cout << "balls: " << balls << " bins: " << bins << " cap: " << cap << " count: " << count << std::endl;
					if (count1 != count2)
					{
						std::cout << "balls: " << balls << " bins: " << bins << " cap: " << cap << " count: " << count1 << " != " << count2 << std::endl;
						throw RTE_LOC;
					}
				}
			}
		}
	}



	u64 ballsBinsCapExhaustive(i64 balls, i64 bins, i64 cap)
	{

		if (balls < 0)
			return 0;
		if (bins < 0)
			return 0;
		if (cap < 0)
			return 0;

		// we have a position for each ball and (bins-1) dividers.
		// balls into bins is the same as choosing (bins-1) dividers.
		auto n = balls + bins - 1;
		auto nck = choose(n, bins - 1);;
		if(balls <= cap)
			return nck;
		u64 count = 0;
		std::vector<u64> idx(bins-1);
		//std::cout << "bbc " << balls << " " << bins << " " << cap << std::endl;

		for (u64 i = 0; i < nck; ++i)
		{
			ithCombination(i, n, idx);

			// count this combination if there are no bins it more than cap balls.
			auto b = [&] {
				if(idx[0] > cap || n-idx.back()-1 > cap)
					return 0;
				for (u64 j = 1; j < idx.size(); ++j)
					if(idx[j] - idx[j - 1] - 1 > cap)
						return 0;
				return 1;
				}();

			//if (b)
			//{
			//	std::cout << int(b) << " [ " << idx[0] << ", ";
			//	for (u64 j = 1; j < idx.size(); ++j)
			//		std::cout << (idx[j] - idx[j - 1]) << ", ";
			//	std::cout << (n - idx.back()-1) << " ] ~ ( ";
			//	for (u64 j = 0; j < idx.size(); ++j)
			//		std::cout << idx[j] << " ";
			//	std::cout << " )" << std::endl;


			//}
			count += b;
		}

		return count;
	}

	void ballsBinsCap_Test(const CLP& cmd)
	{
		u64 binsMax = cmd.getOr("bins", 5);
		u64 capMax = cmd.getOr("cap", 5);

		Choose<Int> pas(binsMax * capMax);
		std::vector<BallsBinsCap<Int>> cache(capMax);
		Choose<Int> choose(binsMax * capMax);

		for (i64 cap = 0; cap < capMax; ++cap)
		{
			cache[cap] = BallsBinsCap<Int>(capMax, binsMax, cap, choose);
		}
		for (i64 bins = -1; bins < binsMax; ++bins)
		{
			for (i64 cap = -1; cap < capMax; ++cap)
			{

				for (u64 balls = -1; balls < bins * cap; ++balls)
				{
					auto count1 = ballsBinsCapExhaustive(balls, bins, cap);
					auto count2 = ballsBinsCap(balls, bins, cap, pas);

					//std::cout << "balls: " << balls << " bins: " << bins << " cap: " << cap << " count: " << count << std::endl;
					if (count1 != count2)
					{
						std::cout << "balls: " << balls << " bins: " << bins << " cap: " << cap << " count: " << count1 << " != " << count2 << std::endl;
						throw RTE_LOC;
					}

					if (cap >= 0)
					{
						auto count3 = cache[cap](balls, bins);
						if (count1 != count3)
						{
							std::cout << "cache balls: " << balls << " bins: " << bins << " cap: " << cap << " count: " << count1 << " != " << count3 << std::endl;
							throw RTE_LOC;
						}
					}
				}
			}
		}

		// Regression check: when bins*cap is even, the cache must include the midpoint.
		{
			Choose<Int> choose(64);
			BallsBinsCap<Int> cache(16, 6, 3, choose);
			auto cached = cache(9, 6);
			auto direct = ballsBinsCap<Int>(9, 6, 3, choose);
			if (cached != direct)
			{
				std::cout << "midpoint cache mismatch: " << cached << " != " << direct << std::endl;
				throw RTE_LOC;
			}
		}
	}

	void minimumDistanceTestMain(oc::CLP& cmd) {
		TestCollection tests;

		tests.add("RepeaterEnum_exhaustive_Test        ", RepeaterEnum_exhaustive_Test);
		tests.add("ballsBinsCap_Test                   ", ballsBinsCap_Test);
		tests.add("labeledBallsBinsCap_Test            ", labeledBallsBinsCap_Test);
		tests.add("accumulateEnum_exhaustive_Test      ", accumulateEnum_exhaustive_Test);
		tests.add("blockEnum_exhaustive_Test           ", blockEnum_exhaustive_Test);
		tests.add("BandedEnum_exhaustive_Test          ", BandedEnum_exhaustive_Test);
		tests.add("expandEnum_exhaustive_Test          ", expandEnum_exhaustive_Test);
		tests.add("RandomEnum_exhaustive_Test          ", RandomEnum_exhaustive_Test);
		
		tests.add("RandConvEnum_single_Test            ", RandConvEnum_single_Test);;
		tests.add("RandConvEnum_exhaustive_Test        ", RandConvEnum_exhaustive_Test);
		tests.add("WrapConvEnum_single_Test            ", WrapConvEnum_single_Test);;
		tests.add("WrapConvEnum_exhaustive_Test        ", WrapConvEnum_exhaustive_Test);
		
		tests.add("composeEnum_exhaustive_Test         ", composeEnum_exhaustive_Test);
		tests.add("composeEnum_sysExhaustive_Test      ", composeEnum_sysExhaustive_Test);
		

		//tests.add("chooseTest                          ", chooseTest);
		//tests.add("expanding_distribution_opt_test     ", expanding_distribution_opt_test);
		//tests.add("minimum_distance_tests              ", minimum_distance_tests);
		tests.runIf(cmd);
	}


}


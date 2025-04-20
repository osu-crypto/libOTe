
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

#define BITSET_SIZE 128

namespace osuCrypto {

	u64 ballsBinsCapExhaustive(u64 balls, u64 bins, u64 cap)
	{
		u64 n = bins * cap;
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

	void ballsBinsCap_Test(const CLP& cmd)
	{
		u64 binsMax = cmd.getOr("bins", 5);
		u64 capMax = cmd.getOr("cap", 5);

		ChooseCache<Int> pas(binsMax * capMax);

		for (u64 bins = 2; bins < binsMax; ++bins)
		{
			for (u64 cap = 2; cap < capMax; ++cap)
			{

				for (u64 balls = bins; balls < bins * cap; ++balls)
				{
					auto count1 = ballsBinsCapExhaustive(balls, bins, cap);
					auto count2 = labeledBallBinCap(balls, bins, cap, pas);
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

	void minimumDistanceTestMain(oc::CLP& cmd) {
		TestCollection tests;

		tests.add("RepeaterEnum_exhaustive_Test        ", RepeaterEnum_exhaustive_Test);
		tests.add("ballsBinsCap_Test                   ", ballsBinsCap_Test);
		tests.add("accumulateEnum_exhaustive_Test      ", accumulateEnum_exhaustive_Test);
		tests.add("blockEnum_exhaustive_Test           ", blockEnum_exhaustive_Test);
		tests.add("composeEnum_exhaustive_Test         ", composeEnum_exhaustive_Test);
		tests.add("composeEnum_sysExhaustive_Test      ", composeEnum_sysExhaustive_Test);
		

		tests.add("chooseTest                          ", chooseTest);
		//tests.add("expanding_distribution_opt_test     ", expanding_distribution_opt_test);
		//tests.add("minimum_distance_tests              ", minimum_distance_tests);
		tests.runIf(cmd);
	}


}


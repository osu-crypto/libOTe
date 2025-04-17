
#include <bitset>
#include <cassert>
#include <random>

#include "EnumeratorTools.h"
#include "MinimumDistance.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "oldMinDistTest.h"
#include "RepeaterEnumerator.h"
#include "CompositionEnumerator.h"

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
					auto count3 = old_::labeledBallBinCap_old<Int>(balls, bins, cap);
					//std::cout << "balls: " << balls << " bins: " << bins << " cap: " << cap << " count: " << count << std::endl;
					if (count1 != count2)
					{
						std::cout << "balls: " << balls << " bins: " << bins << " cap: " << cap << " count: " << count1 << " != " << count2 
							<< " " << count3 << std::endl;
						throw RTE_LOC;
					}
				}
			}
		}
	}

	u64 hamming_weight(const std::vector<short>& array) {
		u64 sum = 0;
		for (const auto& a : array) {
			sum += a;
		}
		return sum;
	}

	std::vector<short> decimalToBinary(uint64_t n, uint64_t bitsize) {
		assert(bitsize < 64);
		assert(n < (uint64_t(1) << bitsize));
		std::vector<short> binary(bitsize);
		if (n == 0) {
			return binary; // 0
		}

		// NOTE put in the same order as in bitset
		uint64_t i = 0; // bitsize-1;
		while (n > 0) {
			binary[i++] = static_cast<short>(n % 2);
			//binary[i--] = static_cast<short>(n % 2);
			n /= uint64_t(2);
		}
		return binary;
	}

	std::vector<short> generate_uniform_bits(size_t size, std::mt19937& gen) {
		std::vector<short> bits(size);
		std::uniform_int_distribution<> dis(0, 1); // Distribution to produce 0 or 1

		for (size_t i = 0; i < size; ++i) {
			bits[i] = static_cast<short>(dis(gen));
		}

		return bits;
	}

	std::vector<std::bitset<BITSET_SIZE>> generate_all_gis(u64 k, u64 n, u64 sigma) {
		u64 num_gis_in_g = k / sigma;
		u64 e = n / k;
		u64 num_elements_in_one_gi = sigma * e * sigma;
		// all G_is but in the same G
		const u64 num_elements_in_all_gis = num_gis_in_g * num_elements_in_one_gi;
		// std::cout << "Bitset size: " << num_elements_in_all_gis << std::endl;
		assert(BITSET_SIZE >= num_elements_in_all_gis);
		// 2^{k/sigma * sigma * e * sigma}
		assert(num_elements_in_all_gis < 64);
		u64 num_possibilities = u64(1) << num_elements_in_all_gis;
		std::vector<std::bitset<BITSET_SIZE>> all_possibilities(num_possibilities);
		for (size_t idx = 0; idx < num_possibilities; idx++) {
			all_possibilities[idx] = idx;
			// std::cout << all_possibilities[idx] << std::endl;
		}
		return all_possibilities;
	}

	std::vector<std::vector<short>> generate_all_gis_bool(u64 k, u64 n, u64 sigma) {
		u64 num_gis_in_g = k / sigma;
		u64 e = n / k;
		u64 num_elements_in_one_gi = sigma * e * sigma;
		// all G_is but in the same G
		const u64 num_elements_in_all_gis = num_gis_in_g * num_elements_in_one_gi;
		// 2^{k/sigma * sigma * e * sigma}
		assert(num_elements_in_all_gis < 64);
		u64 num_possibilities = u64(1) << num_elements_in_all_gis;
		std::vector<std::vector<short>> all_possibilities;
		for (size_t idx = 0; idx < num_possibilities; idx++) {
			all_possibilities.push_back(decimalToBinary(idx, num_elements_in_all_gis));
			// std::cout << all_possibilities[idx] << std::endl;
		}
		return all_possibilities;
	}

	std::vector<std::vector<short>> generate_random_gis_bool(u64 k, u64 n, u64 sigma,
		size_t num_random,
		std::mt19937& gen) {
		u64 num_gis_in_g = k / sigma;
		u64 e = n / k;
		u64 num_elements_in_one_gi = sigma * e * sigma;
		// all G_is but in the same G
		const u64 num_elements_in_all_gis = num_gis_in_g * num_elements_in_one_gi;
		std::vector<std::vector<short>> random_gis;
		for (size_t idx = 0; idx < num_random; idx++) {
			random_gis.push_back(generate_uniform_bits(num_elements_in_all_gis, gen));
		}
		return random_gis;
	}

	std::vector<std::bitset<BITSET_SIZE>> generate_all_x_of_weight_w(u64 k, u64 w) {
		assert(BITSET_SIZE >= k);
		std::vector<std::bitset<BITSET_SIZE>> all_xs;
		assert(k <= 63);
		u64 num_possibilities = 1 << k; // 2^{k}
		for (size_t idx = 0; idx < num_possibilities; idx++) {
			std::bitset<BITSET_SIZE> possibility = idx;
			if (possibility.count() == w) {
				all_xs.push_back(possibility);
				// std::cout << possibility << std::endl;
			}
		}
		return all_xs;
	}

	std::vector<std::vector<short>> generate_all_x_of_weight_w_bool(u64 k, u64 w) {
		std::vector<std::vector<short>> all_xs;
		assert(k < 64);
		u64 num_possibilities = 1 << k; // 2^{k}
		for (size_t idx = 0; idx < num_possibilities; idx++) {
			std::vector<short> possibility = decimalToBinary(idx, k);
			u64 sum = hamming_weight(possibility);
			if (sum == w) {
				all_xs.push_back(possibility);
				// std::cout << possibility << std::endl;
			}
		}
		return all_xs;
	}

	std::vector<std::bitset<BITSET_SIZE>> generate_all_x(u64 k) {
		assert(BITSET_SIZE >= k);
		assert(k < 64);
		u64 num_possibilities = u64(1) << k; // 2^{k}
		std::vector<std::bitset<BITSET_SIZE>> all_xs(num_possibilities);
		for (size_t idx = 0; idx < num_possibilities; idx++) {
			all_xs[idx] = idx;
		}
		return all_xs;
	}

	std::vector<std::vector<short>> generate_all_x_bool(u64 k) {
		assert(k < 64);
		u64 num_possibilities = (u64(1) << k) - 1; // 2^{k} - 1 (as we skip all 0 x)
		std::vector<std::vector<short>> all_xs;
		for (size_t idx = 0; idx < num_possibilities; idx++) {
			all_xs.push_back(decimalToBinary(idx + 1, k));
		}
		return all_xs;
	}

	std::bitset<BITSET_SIZE> multiply_x_g(const std::bitset<BITSET_SIZE>& x,
		const std::bitset<BITSET_SIZE>& g,
		u64 sigma, u64 k, u64 n) {
		assert(BITSET_SIZE >= n);
		std::bitset<BITSET_SIZE> res;
		size_t e = n / k;
		assert(k % sigma == 0 && n % sigma == 0);
		size_t num_gis = k / sigma; // number of G_i's in a single G
		for (size_t gi = 0; gi < num_gis; gi++) {
			size_t x_offset = gi * sigma;
			size_t res_offset = gi * e * sigma;
			size_t g_offset = gi * sigma * e * sigma;
			for (size_t si = 0; si < (e * sigma); si++) {
				for (size_t sj = 0; sj < sigma; sj++) {
					res[res_offset + si] = res[res_offset + si] ^
						(x[x_offset + sj] && g[g_offset + sj * e * sigma + si]);
				}
			}
		}
		return res;
	}

	std::vector<short> multiply_x_g_bool(const std::vector<short>& x,
		const std::vector<short>& g,
		u64 sigma, u64 k, u64 n) {
		std::vector<short> res(n);
		size_t e = n / k;
		assert(k % sigma == 0 && n % sigma == 0);
		size_t num_gis = k / sigma; // number of G_i's in a single G
		for (size_t gi = 0; gi < num_gis; gi++) {
			size_t x_offset = gi * sigma;
			size_t res_offset = gi * e * sigma;
			size_t g_offset = gi * sigma * e * sigma;
			for (size_t si = 0; si < (e * sigma); si++) {
				for (size_t sj = 0; sj < sigma; sj++) {
					res[res_offset + si] = res[res_offset + si] ^
						(x[x_offset + sj] && g[g_offset + sj * e * sigma + si]);
				}
			}
		}
		return res;
	}

	template<typename I, typename R>
	void iterate_and_count(std::vector<short>& expanded_x,
		const std::vector<short>& g,
		std::vector<R>& count_weight_h_outputs,
		u64 n, u64 sigma,
		size_t num_expanding_gis) {
		// Iterate over all permutations
		// 1. first sort expanded_x
		std::sort(expanded_x.begin(), expanded_x.end());
		// 2. compute number of permutations
		u64 hw = hamming_weight(expanded_x);
		I num_perms = fact<I>(n) / (fact<I>(hw) * fact<I>(n - hw));
		I num_perms_check = 0;
		// 2. use std::next_permutation to get all perms
		do {
			num_perms_check++;
			// multiply x and g at each iteration
			// TODO different G at each iteration?
			std::vector<short> xg = multiply_x_g_bool(expanded_x, g, sigma, n, n);
			count_weight_h_outputs[hamming_weight(xg)] += R(1) / num_perms / R(num_expanding_gis);
		} while (std::next_permutation(expanded_x.begin(),
			expanded_x.end()));
		assert(num_perms_check == num_perms);
	}

	//
	template<typename I, typename R>
	std::vector<R> brute_force_block_minimum_distance(
		SubcodeType expander,
		u64 multiplier,
		u64 num_iters,
		u64 k, u64 n,
		u64 sigma, u64 sigma_expander,
		size_t num_random,
		std::mt19937& gen,
		bool exact,
		bool verbose) {
		assert(multiplier == 0 && num_iters == 1); // now only supports these
		size_t e = n / k;
		// Generate num_random possible G_i's (the blocks in matrix G)
		// TODO Generate different G for all iterations
		std::vector<std::vector<short>> expanding_gis;
		std::vector<std::vector<short>> gis;
		if (exact) {
			gis = generate_all_gis_bool(n, n, sigma);
			if (expander == SubcodeType::Block) {
				assert(false); // TODO function does not yet exist
			}
		}
		else { // approximate
			gis = generate_random_gis_bool(n, n, sigma, num_random, gen);
			if (expander == SubcodeType::Block) {
				// Remember this is missing the identity, which is handled later
				expanding_gis = generate_random_gis_bool(k, n - k, sigma_expander, num_random, gen);
			}
		}
		if (verbose)
			std::cout << "All " << gis.size() << " Gi's generated..." << std::endl;
		// Generate all possible input x's
		std::vector<std::vector<short>> xs = generate_all_x_bool(k);
		if (verbose)
			std::cout << "All " << xs.size() << " x's generated..." << std::endl;
		std::vector<R> count_weight_h_outputs(n + 1);
		// iterate over all G's
		for (const auto& g : gis) {
			// for each G, iterate over all x's
			for (const auto& x : xs) {
				// expander
				if (expander == SubcodeType::Repeater) {
					// repeater
					std::vector<short> expanded_x;
					for (size_t i = 0; i < k; i++) {
						for (size_t j = 0; j < e; j++) {
							expanded_x.push_back(x[i]);
						}
					}
					// Iterate over all permutations and count weights
					iterate_and_count<I, R>(expanded_x, g, count_weight_h_outputs,
						n, sigma, 1);
				}
				else if (expander == SubcodeType::Block) {
					size_t num_expanding_gis = expanding_gis.size();
					// expanding block
					for (const auto& expanding_g : expanding_gis) {
						std::vector<short> expanded_x;
						// insert identity of size k
						expanded_x.insert(expanded_x.end(), x.begin(), x.end());
						assert(expanded_x.size() == k);
						// insert the multiplied part of size n-k
						std::vector<short> expansion = multiply_x_g_bool(x, expanding_g,
							sigma_expander, k, n - k);
						expanded_x.insert(expanded_x.end(), expansion.begin(), expansion.end());
						assert(expanded_x.size() == n);
						// Iterate over all permutations and count weights
						iterate_and_count<I, R>(expanded_x, g, count_weight_h_outputs,
							n, sigma, num_expanding_gis);
					}
				}
				else
					throw RTE_LOC;
			}
		}
		// Divide each count by the number of G's
		for (auto& count : count_weight_h_outputs) {
			count /= gis.size();
		}
		// Compute the minimum distance
		// Find at which index the sum >= 1. That is the minimum distance
		// u64 minimum_distance = minimum_distance_from_distribution<R>(n, count_weight_h_outputs);
		return count_weight_h_outputs;
	}



	//void expanding_distribution_opt_test(const CLP& cmd)
	//{

	//	using INT = Int;
	//	using RAT = Rat;
	//	//using INT = Float;
	//	//using RAT = Float;
	//	bool systematic = true;
	//	u64 k = 1 << cmd.getOr("kk", 6);
	//	u64 n = k + k * systematic;
	//	u64 sigma = cmd.getOr("s", 16);
	//	u64 numThreads = cmd.getOr("threads", 4);
	//	ChooseCache<INT> pas(n);
	//	u64 trials = cmd.getOr("trials", 1);
	//	Timer timer;
	//	print_timings = cmd.isSet("print_timings");

	//	for (u64 tt = 0; tt < trials; ++tt)
	//	{

	//		std::vector<RAT>/* inputDist(k + 1), */outputDist0(n + 1), outputDist1(n + 1);
	//		//for (u64 i = 1; i < inputDist.size(); ++i)
	//		//	inputDist[i] = choose_pascal(k, i, pas);

	//		timer.setTimePoint("start");

	//		BlockEnumerator<INT, RAT>::enumerate(
	//			{}, outputDist0,
	//			systematic, k, n, sigma,
	//			numThreads, pas, pas);
	//		timer.setTimePoint("opt");

	//		compute_expanding_block_distribution<INT, RAT>(outputDist1, k, n, sigma, pas);
	//		timer.setTimePoint("old");

	//		if (std::is_same_v<INT, Float>)
	//		{
	//			for (u64 i = 0; i < outputDist0.size(); ++i)
	//			{
	//				auto f = (outputDist0[i] / outputDist1[i]);
	//				if (f > 1.001 || f < 0.999)
	//				{
	//					std::cout << Color::Red;
	//					std::cout << i << "  " << outputDist0[i] << "  " << outputDist1[i] << std::endl << Color::Default;
	//					throw RTE_LOC;
	//				}
	//			}
	//		}
	//		else
	//		{

	//			if (outputDist0 != outputDist1)
	//			{
	//				std::cout << "opt vs old" << std::endl;
	//				for (u64 i = 0; i < outputDist0.size(); ++i)
	//				{
	//					if (outputDist0[i] != outputDist1[i])
	//						std::cout << Color::Red;
	//					std::cout << i << "  " << outputDist0[i] << "  " << outputDist1[i] << std::endl << Color::Default;
	//				}
	//				throw RTE_LOC;
	//			}
	//		}
	//	}
	//	if (cmd.isSet("timing"))
	//		std::cout << timer << std::endl;
	//}

	//void minimum_distance_tests(const CLP& cmd) {

	//	u64 numThreads = 16;
	//	// expander, multiplier, num_iters, k, n, sigma, sigma_expander (0 if repeater), approximate (1 means compute all 
	//	// elements in the distribution exactly)
	//	std::vector<std::vector<u64>> params = {
	//			{0, 1, 3, 6, 3, 0, 1}, // repeater and block enumerator
	//			{0, 1, 4, 8, 2, 0, 1}, // repeater and block enumerator
	//			{0, 1, 6, 12, 3, 0, 1}, // repeater and block enumerator
	//			//{0, 1, 4, 8, 4, 2, 1}, // expanding block and block enumerator
	//			//{0, 1, 3, 9, 3, 3, 1}, // expanding block and block enumerator
	//			//{0, 1, 4, 8, 8, 2} // expanding block and block enumerator
	//			// TODO add test with >1 iteration {0, 0, 1, 6, 12, 2},
	//			//  TODO add more tests with different expander multiplier
	//			//{4,12,2},
	//			//{6,6,3}
	//	};
	//	auto et = SubcodeType::Repeater;

	//	for (const auto& param : params) {
	//		// TODO remove when ready
	//		//if (param[1] != 0) assert(false);
	//		std::vector<Rat> expected_distribution =
	//			minimum_distance<Int, Rat>(et,
	//				param[0],// multipler
	//				param[1],// num_iters
	//				param[2],// k
	//				param[3],// n
	//				param[4],// sigma
	//				param[5],// sigma_expander
	//				param[6],// approximate
	//				numThreads,
	//				0, 0, 0);// verbose, numpoints, normalize
	//		double expected_md =
	//			minimum_distance_from_distribution<Rat>(expected_distribution).mExpectMD;

	//		u64 seed = 24523452345234523;
	//		std::mt19937 gen(seed); // Mersenne Twister engine
	//		size_t num_random = cmd.getOr("trials", 1000);
	//		std::vector<Rat> approximate_true_distribution = brute_force_block_minimum_distance<Int, Rat>(
	//			et,
	//			param[0],
	//			param[1],
	//			param[2],
	//			param[3],
	//			param[4],
	//			param[5],
	//			num_random,
	//			gen,
	//			false,
	//			cmd.isSet("v"));
	//		double approximate_true_md = minimum_distance_from_distribution<Rat>(approximate_true_distribution).mExpectMD;


	//		// Compare the full distributions
	//		bool similar = compareDistributions<Rat>(expected_distribution, approximate_true_distribution, param[4] + 1, 0.1); // last param is error tolerance
	//		if (!similar) {
	//			print_distribution<Rat>(expected_distribution, approximate_true_distribution);

	//			throw RTE_LOC;
	//		}

	//		if (expected_md != approximate_true_md) {
	//			std::cout << "Expected minimum distance: " << expected_md << std::endl;
	//			// std::cout << "True minimum distance: " << true_md << std::endl;
	//			std::cout << "Approximate true minimum distance: " << approximate_true_md << std::endl;

	//			print_distribution<Rat>(expected_distribution, approximate_true_distribution);

	//			throw RTE_LOC;
	//		}

	//	}
	//}

	void minimumDistanceTestMain(oc::CLP& cmd) {
		TestCollection tests;

		tests.add("RepeaterEnum_exhaustive_Test        ", RepeaterEnum_exhaustive_Test);
		tests.add("ballsBinsCap_Test                   ", ballsBinsCap_Test);
		tests.add("minimumDistanceTestMain_old         ", minimumDistanceTestMain_old);
		tests.add("accumulateEnum_exhaustive_Test      ", accumulateEnum_exhaustive_Test);
		tests.add("blockEnum_exhaustive_Test           ", blockEnum_exhaustive_Test);
		tests.add("composeEnum_exhaustive_Test         ", composeEnum_exhaustive_Test);
		

		tests.add("chooseTest                          ", chooseTest);
		//tests.add("expanding_distribution_opt_test     ", expanding_distribution_opt_test);
		//tests.add("minimum_distance_tests              ", minimum_distance_tests);
		tests.runIf(cmd);
	}


}


#ifndef LIBOTE_MINIMUMDISTANCE_H
#define LIBOTE_MINIMUMDISTANCE_H

#include <chrono>
#include <numeric>
#include <stdexcept>
#include <vector>

#include "BlockEnumerator.h"
#include "ExpandingBlockEnumerator.h"
//#include "NonrecConvEnumerator.h"
#include "EnumeratorTools.h"
#include "RepeaterEnumerator.h"
#include "cryptoTools/Common/Matrix.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/ThreadBarrier.h"

#include <boost/multiprecision/cpp_dec_float.hpp>
#include <future>
#include <fstream>
#include "libOTe/Tools/LDPC/Mtx.h"
#include "libOTe/Tools/LDPC/Util.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "LoadingBar.h"
#include "AccumulateEnumerator.h"
#include "Print.h"
#include "Subcode.h"

namespace osuCrypto
{

	struct MD
	{
		// the expected minimum distance
		double mExpectMD = 0;

		// The relative minimum distance h/k
		// such that we would expect 1 codework with weight h
		double mZeroRelDist = 0;

		double mZeroValue = 0;
	};

	// given a weight distribution, return the minimum distance.
	template<typename R>
	MD minimumDistance(span<R> distribution) {
		assert(distribution.size() > 0);
		auto n = distribution.size() - 1;
		R sum = 0;
		R weighted = 0;
		//u64 minimum_distance = 0;
		MD ret;
		for (size_t h = 0; h < n; h++) {
			;
			sum += distribution[h];
			weighted += distribution[h] * h;

			if (ret.mZeroRelDist == 0 && distribution[h] >= 1)
			{
				std::cout << "zero " << h << " " << distribution[h] << std::endl;
				ret.mZeroRelDist = double(h) / n;
				ret.mZeroValue = ((double)(weighted / n));
			}

			if (ret.mExpectMD == 0 && sum >= 1) {
				std::cout << "expected " << h << " " << distribution[h] << std::endl;
				ret.mExpectMD = (double)(weighted / n);
			}

			if (ret.mExpectMD && ret.mZeroRelDist)
				break;
		}
		return ret;
	}




	struct OnExit
	{
		std::function<void()> mFunc;
		~OnExit() { mFunc(); }
	};

	template<typename I, typename R>
	std::vector<R> minimum_distance(
		SubcodeType et, u64 multiplier, u64 num_iters,
		u64 k, u64 n, u64 sigma, u64 sigma_expander,
		u64 approximate,
		u64 num_threads,
		bool verbose, // print the distribution
		u64 numPoints,  // number of locations to print
		bool normalizes // normalize the distribution to be a probability distribution when printing
	) {
		// TODO Assumes G's sigma is the same for all iterations (except expanding step)

		if (!sigma || !k || (!sigma_expander && et == SubcodeType::Block))
			throw RTE_LOC;
		if (num_threads < 1)
			throw RTE_LOC;

		if (n == k) throw RTE_LOC;
		if (k % sigma)
		{
			auto kk = k;
			k = ((k + sigma / 2) / sigma) * sigma;
			std::cout << Color::Red << "Rounding k to the nearest multiple of sigma. k = " << kk << " -> " << k << std::endl << Color::Default;
		}
		if (n % k)
		{
			auto nn = n;
			n = ((n + k / 2) / k) * k;
			std::cout << Color::Red << "rounding n to the nearest multiple of k. n = " << nn << " -> " << n << std::endl << Color::Default;
		}

		std::cout << "pascal I ";
		auto start = std::chrono::steady_clock::now();
		ChooseCache<I> pascal_triangle(n);
		auto end = std::chrono::steady_clock::now();
		auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
		std::cout << elapsed.count() << " ms" << std::endl;
		start = std::chrono::steady_clock::now();
		std::cout << "pascal Int ";
		ChooseCache<Int> pascal_triangle2(n);
		//auto& pascal_triangle2 = pascal_triangle;
		end = std::chrono::steady_clock::now();
		elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
		std::cout << elapsed.count() << " ms" << std::endl;


		// NOTE no longer used as k^2 space too big
		// Compute all k^2 possible block enumerators
		// k^2 space... but it is reused at each iteration
		/*
		std::vector<std::vector<R>> block_enumerators(k, std::vector<R>(k));
		for (size_t w = 0; w < k; w++) {
			for (size_t h = 0; h < k; h++) {
				block_enumerators[w][h] = block_enum<I, R>(w, h, k, sigma);
			}
		}
		 */

		 // 2 * (n + 1) space
		Matrix<R> distributions(2, n + 1);

		loadBar.start((n + 1) * num_iters + (n + 1) / 2, "Computing distribution");
		std::jthread printer([] {loadBar.print(); });
		OnExit oe([&]() {loadBar.cancel(); });

		if (et == SubcodeType::Repeater)
		{
			throw RTE_LOC;
			// Compute distribution for the expansion step
			// Expansion step is slightly different from the iterations
			// At the beginning there are c_w = k choose w inputs of weight w<=k
			// After expansion, c_w (for w<=n) depends on what expander we use
			//compute_expanding_distribution<I, R>(
			//	distributions[0],
			//	et, k, n,
			//	sigma_expander, pascal_triangle);
		}
		else
		{
			BlockEnumerator<I, R>::enumerate(
				{}, distributions[0], 1,
				k, n, sigma_expander, num_threads,
				pascal_triangle,
				pascal_triangle2);

		}

		//print_distribution(distributions[0]);

		// Compute distributions for iterations
		for (size_t iter = 0; iter < num_iters; iter++) {


			if (iter)
				std::fill(distributions[(iter + 1) % 2].begin(), distributions[(iter + 1) % 2].end(), R(0));

			BlockEnumerator<I, R>::enumerate(
				distributions[iter % 2],
				distributions[(iter + 1) % 2],
				false,
				n,
				n,
				sigma,
				num_threads,
				pascal_triangle,
				pascal_triangle2);
			// expand_and_interpolate(distributions[(iter + 1) % 2]);

		}

		// Now return the distribution associated with the last iteration

		// Check the sum of the final distribution is equal to the sum of the initial distribution
		R final_distribution_sum = std::reduce(distributions[num_iters % 2].begin(),
			distributions[num_iters % 2].end()); // distribution_sum<R>(distributions[num_iters % 2]);

		if constexpr (std::is_same_v<R, Float>)
		{
			if (boost::multiprecision::isinf(final_distribution_sum) ||
				boost::multiprecision::isnan(final_distribution_sum))
			{
				throw std::runtime_error("NAN final sum. " LOCATION);
			}
		}
		// Sum initial distribution
		R initial_distribution_sum = 0;
		for (size_t w = 1; w <= k; w++) {
			initial_distribution_sum += R(choose_pascal<I>(k, w, pascal_triangle));
		}

		if (std::is_same_v<I, Int>)
		{

			if (initial_distribution_sum != final_distribution_sum)
			{
				std::cout << Color::Red
					<< "Initial distribution sum: " << initial_distribution_sum << std::endl
					<< "Final distribution sum  : " << final_distribution_sum << std::endl << Color::Default;
			}
		}
		else
		{
			auto ratio = initial_distribution_sum / final_distribution_sum;
			if (ratio > 1.0001 || ratio < 0.9999)
			{
				std::cout << Color::Red << "Initial distribution sum: " << initial_distribution_sum << std::endl;
				std::cout << "Final distribution sum: " << final_distribution_sum << std::endl << Color::Default;
			}
		}
		//assert(final_distribution_sum == initial_distribution_sum);
		//if (approximate == 1 && final_distribution_sum != initial_distribution_sum) throw RTE_LOC;

		auto ret = distributions[num_iters % 2];

		return { ret.begin(), ret.end() };

	}





	template<typename I, typename R>
	std::vector<R> composeEnumerator(
		span<Subcode> subcodes,
		u64 num_threads,
		bool verbose, // print the distribution
		u64 numPoints,  // number of locations to print
		bool normalizes // normalize the distribution to be a probability distribution when printing
	) {
		// TODO Assumes G's sigma is the same for all iterations (except expanding step)

		u64 k = subcodes[0].mK;
		u64 n = subcodes.back().mN;

		if (num_threads < 1)
			throw RTE_LOC;

		if (n == k) throw RTE_LOC;

		std::cout << "pascal I ";
		auto start = std::chrono::steady_clock::now();
		ChooseCache<I> pascal_triangle(n);
		auto end = std::chrono::steady_clock::now();
		auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
		std::cout << elapsed.count() << " ms" << std::endl;
		start = std::chrono::steady_clock::now();
		std::cout << "pascal Int ";
		ChooseCache<Int> pascal_triangle2(n);
		//auto& pascal_triangle2 = pascal_triangle;
		end = std::chrono::steady_clock::now();
		elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
		std::cout << elapsed.count() << " ms" << std::endl;


		// 2 * (n + 1) space
		std::array<std::vector<R>, 2> distributions;// (n + 1);

		loadBar.start((n + 1) * subcodes.size() + (n + 1) / 2, "Computing distribution");
		std::jthread printer([] {loadBar.print(); });
		OnExit oe([&]() {loadBar.cancel(); });

		//subcodes[0].enumerator({}, distributions[0], pascal_triangle, pascal_triangle2);

		//print_distribution(distributions[0]);

		// Sum initial distribution
		R expectedSum = 0;
		for (size_t w = 1; w <= k; w++) {
			expectedSum += R(choose_pascal<I>(k, w, pascal_triangle));
		}

		// Compute distributions for iterations
		for (size_t iter = 0; iter < subcodes.size(); iter++) {
			subcodes[iter].enumerate<I, R>(
				distributions[0],
				distributions[1],
				num_threads,
				pascal_triangle,
				pascal_triangle2);

			// expand_and_interpolate(distributions[(iter + 1) % 2]);

			// Check the sum of the final distribution is equal to the sum of the initial distribution
			R sum = std::reduce(distributions[1].begin(), distributions[1].end()); // distribution_sum<R>(distributions[num_iters % 2]);

			if constexpr (std::is_same_v<R, Float>)
			{
				if (boost::multiprecision::isinf(sum) ||
					boost::multiprecision::isnan(sum))
				{
					throw std::runtime_error("NAN final sum. " LOCATION);
				}
			}

			if (std::is_same_v<I, Int>)
			{
				if (sum != expectedSum)
				{
					std::cout << Color::Red
						<< "Initial distribution sum: " << expectedSum << std::endl
						<< "Final distribution sum  : " << sum << std::endl << Color::Default;
				}
			}
			else
			{
				auto ratio = expectedSum / sum;
				if (ratio > 1.0001 || ratio < 0.9999)
				{
					std::cout << Color::Red << "Initial distribution sum: " << expectedSum << std::endl;
					std::cout << "Final distribution sum: " << sum << std::endl << Color::Default;
				}
			}

			std::swap(distributions[0], distributions[1]);
		}

		return std::move(distributions[0]);
	}


	// the new enumerator code, this one is more modular
	// in that you can specify the subcode type for each subcode
	inline void enumerateCode(const oc::CLP& cmd) try {

		// expander (0: firstSubcode, 1: block expander), 
		// multiplier (0: block, 1: non recursive convolution), 
		// num_iters, k, n, sigma, sigma_expander (0 if firstSubcode),
		// approximate - 1 if exact ie compute exactly all elements in the distribution, 2 means compute every other
		//               element in the distribution and approximate the remaining, 4 means compute every 4th element
		//               and approximate the rest

		//
		// varying iterations, everything else fixed
		//
		if (cmd.isSet("help"))
		{
			std::cout << "This function benchmarks the minimum distance computation for various parameters." << std::endl;
			std::cout << "The parameters are: " << std::endl;
			std::cout << "-subcode block block block, " << std::endl;
			std::cout << "-subcode repeat acc acc, " << std::endl;
			std::cout << "-systematic, " << std::endl;
			std::cout << "-k [list int], " << std::endl;
			std::cout << "-rate double " << std::endl;
			std::cout << "-sigma [list int] " << std::endl;
			return;
		}

		auto subCodeTags = cmd.getManyOr("subcode", std::vector<std::string>{""});
		if (subCodeTags.size() == 0)
			throw std::runtime_error("subcodes must be specified {repeat, acc, block, ... }. " LOCATION);

		// the input size
		auto Ks = cmd.getManyOr("k", std::vector<u64>{512});

		// n = k / rate
		auto rate = cmd.getOr("rate", 0.5);

		// block size
		auto sigmas = cmd.getManyOr("sigma", std::vector<u64>{64});
		bool verbose = cmd.isSet("verbose");
		bool systematic = cmd.isSet("systematic");

		// when printing the curve, how many points to show. 0=all n points.
		u64 numPoints = cmd.getOr("numPoints", 0);

		// when printing the distribution, should we normalize it so the area under the
		// curve is 1.
		bool normalizes = cmd.getOr("normalize", 0);

		// the number of "threshold distances". For `threshold in {1,2,4,...}`, we 
		// print the weight just that `threshold` codewords are expected to exist.
		u64 numMD = cmd.getOr("numMD", 1);

		u64 num_threads = cmd.getOr("threads", std::thread::hardware_concurrency());
		print_timings = verbose;
		bool print_dist = cmd.isSet("printDist") || cmd.isSet("numPoints");

		std::vector<Subcode> subcodes(subCodeTags.size());

		for (size_t i = 0; i < subCodeTags.size(); ++i)
		{
			if (subCodeTags[i] == "repeat")
				subcodes[i] = Subcode(SubcodeType::Repeater);
			else if (subCodeTags[i] == "acc")
				subcodes[i] = Subcode(SubcodeType::Accumulate);
			else if (subCodeTags[i] == "block")
				subcodes[i] = Subcode(SubcodeType::Block);
			else
				throw std::runtime_error("subcodes must be {repeat, accumulate, block, ... }. " LOCATION);

		}


		for (auto k : Ks)
		{
			for (auto sigma : sigmas)
			{
#if 1
				using INT = Float;
				using RAT = Float;
#else
				using INT = Int;
				using RAT = Rat;
#endif

				u64 n = k / rate;
				if (k % sigma)
				{
					auto kk = k;
					k = ((k + sigma / 2) / sigma) * sigma;
					std::cout << Color::Red << "Rounding k to the nearest "
						<< "multiple of sigma. k = " << kk << " -> " << k
						<< std::endl << Color::Default;
				}
				if (n % k)
				{
					auto nn = n;
					n = ((n + k / 2) / k) * k;
					std::cout << Color::Red << "rounding n to the nearest "
						<< "multiple of k. n = " << nn << " -> " << n
						<< std::endl << Color::Default;
				}

				for (u64 j = 0; j < subcodes.size(); ++j)
				{
					if (subcodes[j].mType == SubcodeType::Block)
						subcodes[j].mSigma = sigma;

					subcodes[j].mK = j ? subcodes[j - 1].mN : k;
					subcodes[j].mN = n - k * (systematic && j != subcodes.size() - 1);

					if (systematic && j == subcodes.size() - 1)
						subcodes.back().mSystematic = systematic;

					//std::cout << subcodes[j].mK << " -> " << subcodes[j].mN << std::endl;
				}

				auto start = std::chrono::high_resolution_clock::now();
				auto dist = composeEnumerator<INT, RAT>(
					subcodes, num_threads, verbose, numPoints, normalizes);

				auto expected_md = minimumDistance<RAT>(dist);
				auto end = std::chrono::high_resolution_clock::now();

				if (print_dist)
				{
					print_distribution<RAT>(dist, numPoints, normalizes);
				}

				std::ofstream out(
					"dist_k" + std::to_string(k) + "_n" + std::to_string(n)
					+ "_s" + std::to_string(sigma) + "_i" + std::to_string(subcodes.size()) + ".txt", std::ios::trunc);

				out << "k:" << k << "_n:" << n << "_sigma:" << sigma << "_iters:"
					<< subcodes.size() << std::endl;
				print_distribution<RAT>(dist, 0, normalizes, out);

				std::cout << "k: " << k << " n: " << n << " sigma: " << sigma
					<< " iters: " << subcodes.size() << " rate: " << rate << " time: "
					<< std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count() << "ms" << std::endl;

				std::cout << "MD: " << expected_md.mExpectMD << " zero: " << expected_md.mZeroRelDist
					<< " zeroVal: " << expected_md.mZeroValue << std::endl;


				//if (cmd.isSet("exact"))
				//{
				//	PRNG prng(block(421354523452343423ull, 2332453245234123421ull));
				//	auto md = exactMD(subcodes, k, n, sigma, prng);
				//	std::cout << "Exact MD: " << md << std::endl;
				//}
			}
		}
	}
	catch (std::exception& e) {
		std::cout << e.what() << std::endl;
	}

	inline void fullEnumerate(const oc::CLP& cmd)
		try {

		auto subcode = [&]() {
			if (cmd.isSet("acc"))
				return SubcodeType::Accumulate;
			if (cmd.isSet("block"))
				return SubcodeType::Block;
			if (cmd.isSet("repeat"))
				return SubcodeType::Repeater;
			throw RTE_LOC;
			}();

		u64 k = cmd.getOr("k", 100);
		u64 e = cmd.getOr("e", 2);
		u64 n = k * e;
		u64 sigma = cmd.getOr("sigma", 10);
		bool systematic = cmd.isSet("systematic");
		u64 numThreads = cmd.getOr("nt", std::thread::hardware_concurrency());

		u64 numPoints = cmd.getOr("numPoints", 20);

		Matrix<Float> E(k + 1, n + 1);
		std::vector<Float> dist(n + 1);

		ChooseCache<Float> pascal_triangle(n);
		ChooseCache<Int> pascal_triangle2(n);

		switch (subcode)
		{
		case osuCrypto::SubcodeType::Repeater:
			throw RTE_LOC;
			break;
		case osuCrypto::SubcodeType::Block:
			BlockEnumerator<Float, Float>::enumerate({}, dist,
				systematic,
				k,
				n,
				sigma,
				numThreads,
				pascal_triangle,
				pascal_triangle2,
				E);
			break;
		case osuCrypto::SubcodeType::Accumulate:

			AccumulatorEnumerator<Float, Float>::enumerate(
				{},
				dist,
				systematic,
				k, n, numThreads, pascal_triangle,
				E);

			break;
		default:
			throw RTE_LOC;
		}

		print_enumerator(E, numPoints);

	}
	catch (std::exception& e) {
		std::cout << e.what() << std::endl;
	}


	//inline void fullEnumerate2(const oc::CLP& cmd)
	//	try {

	//	//
	//	//		auto subCodeTags = cmd.getManyOr("subcode", std::vector<std::string>{""});
	//	//		if (subCodeTags.size() == 0)
	//	//			throw std::runtime_error("subcodes must be specified {repeat, acc, block, ... }. " LOCATION);
	//	//
	//	//		// the input size
	//	//		auto Ks = cmd.getManyOr("k", std::vector<u64>{512});
	//	//
	//	//		// n = k / rate
	//	//		auto rate = cmd.getOr("rate", 0.5);
	//	//
	//	//		// block size
	//	//		auto sigmas = cmd.getManyOr("sigma", std::vector<u64>{64});
	//	//		bool verbose = cmd.isSet("verbose");
	//	//		bool systematic = cmd.isSet("systematic");
	//	//
	//	//		// when printing the curve, how many points to show. 0=all n points.
	//	//		u64 numPoints = cmd.getOr("numPoints", 0);
	//	//
	//	//		u64 num_threads = cmd.getOr("threads", std::thread::hardware_concurrency());
	//	//		print_timings = verbose;
	//	//
	//	//		std::vector<Subcode> subcodes(subCodeTags.size());
	//	//
	//	//		for (size_t i = 0; i < subCodeTags.size(); ++i)
	//	//		{
	//	//			if (subCodeTags[i] == "repeat")
	//	//				subcodes[i] = Subcode(SubcodeType::Repeater);
	//	//			else if (subCodeTags[i] == "acc")
	//	//				subcodes[i] = Subcode(SubcodeType::Accumulate);
	//	//			else if (subCodeTags[i] == "block")
	//	//				subcodes[i] = Subcode(SubcodeType::Block);
	//	//			else
	//	//				throw std::runtime_error("subcodes must be {repeat, acc, block, ... }. " LOCATION);
	//	//
	//	//
	//	//			switch (subcodes[i])
	//	//			{
	//	//			case osuCrypto::SubcodeType::Repeater:
	//	//				throw RTE_LOC;
	//	//				break;
	//	//			case osuCrypto::SubcodeType::Block:
	//	//				blockEnumerator<Float, Float>({}, dist,
	//	//					systematic,
	//	//					k,
	//	//					n,
	//	//					sigma,
	//	//					numThreads,
	//	//					pascal_triangle,
	//	//					pascal_triangle2,
	//	//					E);
	//	//				break;
	//	//			case osuCrypto::SubcodeType::Accumulate:
	//	//
	//	//				accumulateEnumerator<Float, Float>(
	//	//					{},
	//	//					dist,
	//	//					systematic,
	//	//					k, n, numThreads, pascal_triangle,
	//	//					E);
	//	//
	//	//				break;
	//	//			default:
	//	//				throw RTE_LOC;
	//	//			}
	//	//
	//	//
	//	//		}
	//	//
	//	//
	//	//		for (auto k : Ks)
	//	//		{
	//	//			for (auto sigma : sigmas)
	//	//			{
	//	//#if 1
	//	//				using INT = Float;
	//	//				using RAT = Float;
	//	//#else
	//	//				using INT = Int;
	//	//				using RAT = Rat;
	//	//#endif
	//	//
	//	//				u64 n = k / rate;
	//	//				if (k % sigma)
	//	//				{
	//	//					auto kk = k;
	//	//					k = ((k + sigma / 2) / sigma) * sigma;
	//	//					std::cout << Color::Red << "Rounding k to the nearest "
	//	//						<< "multiple of sigma. k = " << kk << " -> " << k
	//	//						<< std::endl << Color::Default;
	//	//				}
	//	//				if (n % k)
	//	//				{
	//	//					auto nn = n;
	//	//					n = ((n + k / 2) / k) * k;
	//	//					std::cout << Color::Red << "rounding n to the nearest "
	//	//						<< "multiple of k. n = " << nn << " -> " << n
	//	//						<< std::endl << Color::Default;
	//	//				}
	//	//
	//	//				for (u64 j = 0; j < subcodes.size(); ++j)
	//	//				{
	//	//					if (subcodes[j].mType == SubcodeType::Block)
	//	//						subcodes[j].mSigma = sigma;
	//	//
	//	//					subcodes[j].mK = j ? subcodes[j - 1].mN : k;
	//	//					subcodes[j].mN = n - k * (systematic && j != subcodes.size() - 1);
	//	//
	//	//					if (systematic && j == subcodes.size() - 1)
	//	//						subcodes.back().mSystematic = systematic;
	//	//
	//	//					//std::cout << subcodes[j].mK << " -> " << subcodes[j].mN << std::endl;
	//	//				}
	//	//
	//	//			}
	//	//			print_enumerator(E, numPoints);

	//}
	//catch (std::exception& e) {
	//	std::cout << e.what() << std::endl;
	//}


	inline void benchmarks(const oc::CLP& cmd) try {

		// expander (0: firstSubcode, 1: block expander), 
		// multiplier (0: block, 1: non recursive convolution), 
		// num_iters, k, n, sigma, sigma_expander (0 if firstSubcode),
		// approximate - 1 if exact ie compute exactly all elements in the distribution, 2 means compute every other
		//               element in the distribution and approximate the remaining, 4 means compute every 4th element
		//               and approximate the rest

		//
		// varying iterations, everything else fixed
		//
		if (cmd.isSet("help"))
		{
			std::cout << "This function benchmarks the minimum distance computation for various parameters." << std::endl;
			std::cout << "The parameters are: " << std::endl;
			std::cout << "-repeater, " << std::endl;
			std::cout << "-iters [list int] " << std::endl;
			std::cout << "-k [list int], " << std::endl;
			std::cout << "-rate double " << std::endl;
			std::cout << "-sigmas [list int] " << std::endl;
			//std::cout << "-sigma_expander [list int] " << std::endl;
			return;
		}

		auto firstSubcode = cmd.isSet("repeater") ? SubcodeType::Repeater : SubcodeType::Block;
		auto conv = cmd.isSet("conv");
		auto num_iters = cmd.getManyOr("iters", std::vector<u64>{1});

		// the input size
		auto Ks = cmd.getManyOr("k", std::vector<u64>{512});

		// n = k / rate
		auto rate = cmd.getOr("rate", 0.5);

		// block size
		auto sigmas = cmd.getManyOr("sigma", std::vector<u64>{64});
		bool verbose = cmd.isSet("verbose");

		// when printing the curve, how many points to show. 0=all n points.
		u64 numPoints = cmd.getOr("numPoints", 0);

		// when printing the distribution, should we normalize it so the area under the
		// curve is 1.
		bool normalizes = cmd.getOr("normalize", 0);

		// the number of "threshold distances". For `threshold in {1,2,4,...}`, we 
		// print the weight just that `threshold` codewords are expected to exist.
		u64 numMD = cmd.getOr("numMD", 1);

		u64 num_threads = cmd.getOr("threads", std::thread::hardware_concurrency());
		print_timings = verbose;
		bool print_dist = cmd.isSet("printDist") || cmd.isSet("numPoints");

		//Int;
		//boost::multiprecision::cpp_int
		std::vector<std::vector<u64>> params;
		for (auto i : num_iters)
		{
			for (auto k : Ks)
			{
				for (auto sigma : sigmas)
				{
					//for (auto sigma_exp : sigma_expander)
					{
#if 1
						using INT = Float;
						using RAT = Float;
#else
						using INT = Int;
						using RAT = Rat;
#endif
						u64 n = k / rate;
						if (k % sigma)
						{
							auto kk = k;
							k = ((k + sigma / 2) / sigma) * sigma;
							std::cout << Color::Red << "Rounding k to the nearest multiple of sigma. k = " << kk << " -> " << k << std::endl << Color::Default;
						}
						if (n % k)
						{
							auto nn = n;
							n = ((n + k / 2) / k) * k;
							std::cout << Color::Red << "rounding n to the nearest multiple of k. n = " << nn << " -> " << n << std::endl << Color::Default;
						}


						auto start = std::chrono::high_resolution_clock::now();
						auto dist = minimum_distance<INT, RAT>(
							firstSubcode, conv, i, k, n, sigma, sigma, 1,
							num_threads, verbose, numPoints, normalizes);
						auto expected_md = minimumDistance<RAT>(dist);
						auto end = std::chrono::high_resolution_clock::now();

						if (print_dist)
						{
							print_distribution<RAT>(dist, numPoints, normalizes);
						}
						std::ofstream out(
							"dist_k" + std::to_string(k) + "_n" + std::to_string(n) + "_s" + std::to_string(sigma) + "_i" + std::to_string(i) + ".txt", std::ios::trunc);
						out << "k:" << k << "_n:" << n << "_sigma:" << sigma << "_iters:" << i << std::endl;
						print_distribution<RAT>(dist, 0, normalizes, out);

						std::cout << "k: " << k << " n: " << n << " sigma: " << sigma << " iters: " << i << " rate: " << rate << " time: " << std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count() << "ms" << std::endl;

						std::cout << "MD: " << expected_md.mExpectMD << " zero: " << expected_md.mZeroRelDist << " zeroVal: " << expected_md.mZeroValue << std::endl;
					}
				}
			}
		}

	}
	catch (std::exception& e) {
		std::cout << e.what() << std::endl;
	}

	inline void minimumDistanceMain(oc::CLP& cmd)
	{
		if (cmd.isSet("benchmarks"))
		{
			benchmarks(cmd);
			return;
		}
		else if (cmd.isSet("full"))
		{
			fullEnumerate(cmd);
		}
		else
		{
			enumerateCode(cmd);
			return;
		}
	}
}

#endif //LIBOTE_MINIMUMDISTANCE_H

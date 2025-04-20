#include "MinimumDistance.h"

#include <chrono>
#include <numeric>
#include <stdexcept>
#include <vector>

#include "BlockEnumerator.h"
#include "EnumeratorTools.h"
#include "RepeaterEnumerator.h"
#include "CompositionEnumerator.h"

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

	enum Subcode
	{
		Repeater,
		Block,
		Accumulator
	};

	// the new enumerator code, this one is more modular
	// in that you can specify the subcode type for each subcode
	void enumerateCode(const oc::CLP& cmd) try {

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
		bool full = cmd.isSet("full");
		bool skipH0 = cmd.isSet("skipH0");
		//std::vector<Subcode> subcodes(subCodeTags.size());

		//for (size_t i = 0; i < subCodeTags.size(); ++i)
		//{
		//	if (subCodeTags[i] == "repeat")
		//		subcodes[i] = Subcode(Subcode::Repeater);
		//	else if (subCodeTags[i] == "acc")
		//		subcodes[i] = Subcode(Subcode::Accumulator);
		//	else if (subCodeTags[i] == "block")
		//		subcodes[i] = Subcode(Subcode::Block);
		//	else
		//		throw std::runtime_error("subcodes must be {repeat, accumulate, block, ... }. " LOCATION);

		//}

#if 1
		using I = Float;
		using R = Float;
#else
		using I = Int;
		using R = Rat;
#endif

		for (auto k : Ks)
		{
			for (auto sigma : sigmas)
			{

				u64 n = k / rate - k * systematic;
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

				std::stringstream ss, sh;
				if (systematic)
				{
					sh << "S";
					ss << "S" << k << "." << k / rate;
				}

				ChooseCache<I> choose;// (n, lb);
				ChooseCache<Int> chooseInt;// (n);
				LoadingBar lb;
				u64 kk = k;
				std::vector<std::unique_ptr<Enumerator<R>>> subcodes;
				std::vector<Enumerator<R>*> subcodesParam;
				for (u64 i = 0; i < subCodeTags.size(); ++i)
				{
					if (subCodeTags[i] == "repeat")
					{
						sh << "R";
						ss << "r" << kk << "." << n;
						subcodes.emplace_back(new RepeaterEnumerator<I, R>(kk, n, choose));
					}
					else if (subCodeTags[i] == "acc")
					{
						sh << "A";
						ss << "A" << kk << "." << n;
						subcodes.emplace_back(new AccumulatorEnumerator<I, R>(kk, n, choose));
					}
					else if (subCodeTags[i] == "block")
					{
						sh << "B";
						ss << "B" << kk << "." << n << "." << sigma;
						if (skipH0) ss << "h1";
						subcodes.emplace_back(new BlockEnumerator<I, R>(kk, n, sigma, false, choose, chooseInt, skipH0));
					}
					else if (subCodeTags[i] == "sysBlock")
					{
						sh << "sB";
						ss << "sB" << kk << "." << n << "." << sigma;
						if (skipH0) ss << "h1";
						subcodes.emplace_back(new BlockEnumerator<I, R>(kk, n, sigma, true, choose, chooseInt, skipH0));
					}
					else
						throw std::runtime_error("subcodes must be {repeat, accumulate, block, ... }. " LOCATION);
					subcodesParam.push_back(subcodes.back().get());
					subcodes.back()->mLoadBar = &lb;

					kk = n;
				}



				auto start = std::chrono::high_resolution_clock::now();
				ComposeEnumerator<I, R> comp(
					subcodesParam,
					systematic, choose);
				comp.mLoadBar = &lb;


				std::vector<R> inDist(comp.mK + 1), outDist(comp.mN + 1);


				lb.start(comp.numTicks() + choose.numTicks(n), sh.str());

				choose.precompute(n, &lb);
				chooseInt.precompute(n, &lb);

				if (cmd.hasValue("w"))
				{
					u64 w = cmd.get<u64>("w");
					inDist[w] = choose(k, w);
				}
				else
				{
					for (u64 w = 0; w < inDist.size(); ++w)
						inDist[w] = choose(k, w);
				}


				Matrix<R> fullEnum;
				if (full)
				{
					fullEnum.resize(inDist.size(), outDist.size());
					comp.enumerate(inDist, outDist, fullEnum);
				}
				else
					comp.enumerate(inDist, outDist);

				lb.cancel();

				auto expected_md = minimumDistance<R>(outDist);
				auto end = std::chrono::high_resolution_clock::now();

				sh << "_";
				if (print_dist)
				{
					print_distribution<R>(outDist, numPoints, normalizes, std::cout, ". " + sh.str() + ss.str());
				}

				std::ofstream out(
					"dist_" + sh.str() + ss.str() + ".txt", std::ios::trunc);

				print_distribution<R>(outDist, 0, normalizes, out, ". " + sh.str() + ss.str());

				std::cout << sh.str() << ss.str() << " time: "
					<< std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count() << "ms" << std::endl;

				std::cout << "MD: " << expected_md.mExpectMD << " zero: " << expected_md.mZeroRelDist
					<< " zeroVal: " << expected_md.mZeroValue << std::endl;

				if (fullEnum.size())
				{
					std::cout << "log2(E)" << std::endl;
					std::cout << logEnumToString(fullEnum) << std::endl;
				}
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

	void fullEnumerate(const oc::CLP& cmd)
		try {
		throw RTE_LOC;
		//auto subcode = [&]() {
		//	if (cmd.isSet("acc"))
		//		return Subcode::Accumulate;
		//	if (cmd.isSet("block"))
		//		return Subcode::Block;
		//	if (cmd.isSet("repeat"))
		//		return Subcode::Repeater;
		//	throw RTE_LOC;
		//	}();

		//u64 k = cmd.getOr("k", 100);
		//u64 e = cmd.getOr("e", 2);
		//u64 n = k * e;
		//u64 sigma = cmd.getOr("sigma", 10);
		//bool systematic = cmd.isSet("systematic");
		//u64 numThreads = cmd.getOr("nt", std::thread::hardware_concurrency());

		//u64 numPoints = cmd.getOr("numPoints", 20);

		//Matrix<Float> E(k + 1, n + 1);
		//std::vector<Float> dist(n + 1);

		//ChooseCache<Float> pascal_triangle(n);
		//ChooseCache<Int> pascal_triangle2(n);

		//switch (subcode)
		//{
		//case osuCrypto::Subcode::Repeater:
		//	throw RTE_LOC;
		//	break;
		//case osuCrypto::Subcode::Block:
		//	BlockEnumerator<Float, Float>::enumerate({}, dist,
		//		systematic,
		//		k,
		//		n,
		//		sigma,
		//		numThreads,
		//		pascal_triangle,
		//		pascal_triangle2,
		//		E);
		//	break;
		//case osuCrypto::Subcode::Accumulate:

		//	AccumulatorEnumerator<Float, Float>::enumerate(
		//		{},
		//		dist,
		//		systematic,
		//		k, n, numThreads, pascal_triangle,
		//		E);

		//	break;
		//default:
		//	throw RTE_LOC;
		//}

		//print_enumerator(E, numPoints);

	}
	catch (std::exception& e) {
		std::cout << e.what() << std::endl;
	}

	void minimumDistanceMain(const oc::CLP& cmd)
	{
		//if (cmd.isSet("full"))
		//{
		//	fullEnumerate(cmd);
		//}
		//else
		{
			enumerateCode(cmd);
			return;
		}
	}
}


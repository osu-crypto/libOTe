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
#include "ExpandEnumerator.h"
#include "RandomEnumerator.h"
#include "BandedEnumerator.h"
#include "RandConvEnumerator.h"
#include "WrapConvEnumerator.h"
#include "WrapConvDPEnumerator.h"
#include "SystematicEnumerator.h"

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

		auto broadcastOrIndex = [&](auto const& values, u64 idx, u64 count, const char* name)
		{
			using T = std::decay_t<decltype(values[0])>;
			if (values.size() == 1)
				return values[0];
			if (values.size() == count)
				return values[idx];
			throw std::runtime_error(std::string(name) + " must have size 1 or match -subcode count. " LOCATION);
		};

		// expander (0: firstSubcode, 1: block expander), 
		// multiplier (0: block, 1: non recursive convolution), 
		// num_iters, k, n, sigma, sigma_expander (0 if firstSubcode),
		// approximate - 1 if exact ie compute exactly all elements in the distribution, 2 means compute every other
		//               element in the distribution and approximate the remaining, 4 means compute every 4th element
		//               and approximate the rest

		//
		// varying iterations, everything else fixed
		//
		if (cmd.isSet("help") || !cmd.isSet("subcode"))
		{
			std::cout << "This function benchmarks the minimum distance computation for various parameters." << std::endl;
			std::cout << "The parameters are: " << std::endl;
			std::cout << "-subcode [repeat, block, sysBlock, band, sysBand, acc, exp, rand, sysRand, randConv, wrapConv, wrapConvDp]+ " << std::endl;
			std::cout << "   e.g. -subcode repeat acc acc " << std::endl;
			std::cout << "-systematic " << std::endl;
			std::cout << "-k [list int] " << std::endl;
			std::cout << "-rate double " << std::endl;
			std::cout << "-stageRate [list double]  # optional, broadcast or one per subcode" << std::endl;
			std::cout << "-sigma [list int] " << std::endl;
			std::cout << "-stageSigma [list int]   # optional, broadcast or one per subcode" << std::endl;
			std::cout << "-exp [list int] " << std::endl;
			std::cout << "-stageExp [list int]     # optional, broadcast or one per subcode" << std::endl;
			return;
		}

		auto subCodeTags = cmd.getManyOr("subcode", std::vector<std::string>{""});
		if (subCodeTags.size() == 0)
			throw std::runtime_error("subcodes must be specified {repeat, acc, block, band, sysBand, randConv, wrapConv, wrapConvDp, ... }. " LOCATION);

		// the input size
		auto Ks = cmd.getManyOr("k", std::vector<u64>{512});

		// n = k / rate
		auto rate = cmd.getOr("rate", 0.5);
		auto stageRates = cmd.getMany<double>("stageRate");

		// block size
		auto sigmas = cmd.getManyOr("sigma", std::vector<u64>{64});
		auto stageSigmas = cmd.getMany<u64>("stageSigma");
		auto exps = cmd.getManyOr("exp", std::vector<u64>{64});
		auto stageExps = cmd.getMany<u64>("stageExp");
		bool verbose = cmd.isSet("verbose");
		bool systematic = cmd.isSet("systematic");
		bool doPlot = !cmd.isSet("noPlot");

		// when printing the curve, how many points to show. 0=all n points.
		u64 numPoints = cmd.getOr("numPoints", 0);

		// when printing the distribution, should we normalize it so the area under the
		// curve is 1.
		bool percent = cmd.getOr("percent", 1);

		// the number of "threshold distances". For `threshold in {1,2,4,...}`, we 
		// print the weight just that `threshold` codewords are expected to exist.
		u64 numMD = cmd.getOr("numMD", 1);

		u64 num_threads = cmd.getOr("threads", std::thread::hardware_concurrency());
		print_timings = verbose;
		bool print_dist = cmd.isSet("printDist") || cmd.isSet("numPoints");
		bool full = cmd.isSet("full");

        u64 trim = cmd.getOr("trim", 0);

		constexpr std::string_view path = __FILE__;
		auto folder = path.substr(0, path.find_last_of("/\\"));
		std::string scriptPath = std::string(folder) + "/plot.py";

		using I = Int;
		using R = Rat;

		auto sigmaSweep = stageSigmas.size() ? std::vector<u64>{ stageSigmas[0] } : sigmas;
		auto expSweep = stageExps.size() ? std::vector<u64>{ stageExps[0] } : exps;

		std::vector<std::string> filenames;
		for (auto k : Ks)
		{
			for (auto sigma : sigmaSweep)
			{
				for (auto exp : expSweep)
				{
					auto initialK = k;
					auto sigma0 = stageSigmas.size() ? broadcastOrIndex(stageSigmas, 0, subCodeTags.size(), "stageSigma") : sigma;
					if (initialK % sigma0)
					{
						auto kk = initialK;
						initialK = ((initialK + sigma0 / 2) / sigma0) * sigma0;
						std::cout << Color::Red << "Rounding k to the nearest "
							<< "multiple of sigma. k = " << kk << " -> " << initialK
							<< std::endl << Color::Default;
					}

					std::stringstream ss, sh;
					if (systematic)
					{
						sh << "S";
						ss << "S" << initialK << "." << initialK / rate;
					}

					std::vector<u64> stageNs(subCodeTags.size());
					std::vector<u64> stageSigmasResolved(subCodeTags.size());
					std::vector<u64> stageExpsResolved(subCodeTags.size());
					u64 kk = initialK;
					u64 maxN = initialK;
					u64 maxLocal = 0;
					for (u64 i = 0; i < subCodeTags.size(); ++i)
					{
						auto sigmaI = stageSigmas.size() ? broadcastOrIndex(stageSigmas, i, subCodeTags.size(), "stageSigma") : sigma;
						auto expI = stageExps.size() ? broadcastOrIndex(stageExps, i, subCodeTags.size(), "stageExp") : exp;
						auto rateI = stageRates.size() ? broadcastOrIndex(stageRates, i, subCodeTags.size(), "stageRate") : rate;
						if (rateI <= 0)
							throw std::runtime_error("stageRate values must be positive. " LOCATION);

						stageSigmasResolved[i] = sigmaI;
						stageExpsResolved[i] = expI;

						u64 n = kk / rateI;
						if (i + 1 == subCodeTags.size())
							n -= kk * systematic;

						if (n % kk)
						{
							auto nn = n;
							n = ((n + kk / 2) / kk) * kk;
							std::cout << Color::Red << "rounding n to the nearest "
								<< "multiple of k. n = " << nn << " -> " << n
								<< std::endl << Color::Default;
						}

						stageNs[i] = n;
						maxN = std::max(maxN, n);
						maxLocal = std::max(maxLocal, std::max(sigmaI, expI));
						kk = n;
					}

					Choose<I> choose;// (n, lb);
					Choose<Int> chooseInt;// (n);
					LoadingBar lb;
					auto chooseBound = 2 * maxN + maxLocal + 8;
					choose.precompute(chooseBound);
					chooseInt.precompute(chooseBound);

					kk = initialK;
					std::vector<std::unique_ptr<Enumerator<R>>> subcodes;
					std::vector<std::unique_ptr<BallsBinsCap<Int>>> ballsBinsCaps;
					std::vector<Enumerator<R>*> subcodesParam;
					for (u64 i = 0; i < subCodeTags.size(); ++i)
					{
						auto n = stageNs[i];
						auto sigmaI = stageSigmasResolved[i];
						auto expI = stageExpsResolved[i];
						if (subCodeTags[i] == "repeat")
						{
							sh << "R";
							ss << "R" << kk << "." << n;
							subcodes.emplace_back(new RepeaterEnumerator<I, R>(kk, n, choose));
						}
						else if (subCodeTags[i] == "band")
						{
							sh << "Band" << sigmaI;
							ss << "Band" << kk << "." << n << "." << sigmaI;
							ballsBinsCaps.emplace_back(
								new BallsBinsCap<Int>(n, kk, sigmaI > 1 ? sigmaI - 2 : 0, chooseInt));
							subcodes.emplace_back(
								new BandedEnumerator<I, R>(kk, n, sigmaI, choose, *ballsBinsCaps.back(), num_threads));
						}
						else if (subCodeTags[i] == "sysBand")
						{
							if (n < 2 * kk)
								throw std::runtime_error("sysBand currently requires stage output length n >= 2k so the parity branch has length at least k. " LOCATION);
							auto parityN = n - kk;
							sh << "sBand" << sigmaI;
							ss << "sBand" << kk << "." << n << "." << sigmaI;
							ballsBinsCaps.emplace_back(
								new BallsBinsCap<Int>(parityN, kk, sigmaI > 1 ? sigmaI - 2 : 0, chooseInt));
							auto parity = std::make_unique<BandedEnumerator<I, R>>(
								kk, parityN, sigmaI, choose, *ballsBinsCaps.back(), num_threads);
							subcodes.emplace_back(
								new SystematicEnumerator<I, R>(std::move(parity), choose));
						}
						else if (subCodeTags[i] == "acc")
						{
							sh << "A";
							ss << "A" << kk << "." << n;
							subcodes.emplace_back(new AccumulatorEnumerator<I, R>(kk, n, choose));
						}
						else if (subCodeTags[i] == "block")
						{
							sh << "B"<< sigmaI;
							ss << "B" << kk << "." << n << "." << sigmaI;
							subcodes.emplace_back(new BlockEnumerator<I, R>(kk, n, sigmaI, false, choose, chooseInt, false));
						}
						else if (subCodeTags[i] == "sysBlock")
						{
							sh << "sB"<< sigmaI;
							ss << "sB" << kk << "." << n << "." << sigmaI;
							subcodes.emplace_back(new BlockEnumerator<I, R>(kk, n, sigmaI, true, choose, chooseInt, false));
						}
						else if (subCodeTags[i] == "exp")
						{
							sh << "E"<< expI;
							ss << "E" << kk << "." << n << "." << expI;
							subcodes.emplace_back(new ExpandEnumerator<I, R>(kk, n, expI, choose));
						}
						else if (subCodeTags[i] == "rand")
						{
							sh << "Rnd";
							ss << "Rnd" << kk << "." << n;
							subcodes.emplace_back(new RandomEnumerator<I, R>(kk, n, false, choose));
						}
						else if (subCodeTags[i] == "sysRand")
						{
							sh << "sRnd";
							ss << "sRnd" << kk << "." << n;
							subcodes.emplace_back(new RandomEnumerator<I, R>(kk, n, true, choose));
						}
						else if (subCodeTags[i] == "randConv")
						{
							sh << "RC" << sigmaI;
							ss << "RC" << kk << "." << n << "." << sigmaI;
							ballsBinsCaps.emplace_back(
								new BallsBinsCap<Int>(n, n, sigmaI > 0 ? sigmaI - 1 : 0, chooseInt));
							subcodes.emplace_back(
								new RandConvEnumerator<I, R>(kk, n, sigmaI, choose, *ballsBinsCaps.back(), num_threads));
						}
						else if (subCodeTags[i] == "wrapConv")
						{
							sh << "WC" << sigmaI;
							ss << "WC" << kk << "." << n << "." << sigmaI;
							ballsBinsCaps.emplace_back(
								new BallsBinsCap<Int>(n, n, sigmaI > 1 ? sigmaI - 2 : 0, chooseInt));
							subcodes.emplace_back(
								new WrapConvEnumerator<I, R>(kk, n, sigmaI, choose, *ballsBinsCaps.back(), num_threads));
						}
						else if (subCodeTags[i] == "wrapConvDp")
						{
							sh << "WCDP" << sigmaI;
							ss << "WCDP" << kk << "." << n << "." << sigmaI;
							subcodes.emplace_back(
								new WrapConvDPEnumerator<I, R>(kk, n, sigmaI, choose));
						}
						else
							throw std::runtime_error("subcodes must be {repeat, accumulate, block, band, sysBand, randConv, wrapConv, wrapConvDp, ... }. " LOCATION);
						subcodesParam.push_back(subcodes.back().get());

						kk = n;
					}



					auto start = std::chrono::high_resolution_clock::now();
					ComposeEnumerator<I, R> comp(
						subcodesParam,
						systematic, choose);

					comp.mTrim = trim;

					std::vector<R> inDist(comp.mK + 1), outDist(comp.mN + 1);


					if (cmd.hasValue("w"))
					{
						u64 w = cmd.get<u64>("w");
						inDist[w] = choose(k, w);
					}
					else
					{
						auto wBegin = cmd.getOr("wBegin", 0);
						for (u64 w = wBegin; w < inDist.size(); ++w)
							inDist[w] = choose(initialK, w);
					}


					Matrix<R> fullEnum;
					if (full)
					{
						fullEnum.resize(inDist.size(), outDist.size());
						comp.enumerate(inDist, outDist, fullEnum);
					}
					else
						comp.enumerate(inDist, outDist);

					auto expected_md = minimumDistance<R>(outDist);
					auto end = std::chrono::high_resolution_clock::now();



					sh << "_";
					if (print_dist)
					{
						print_distribution<R>(outDist, numPoints, percent, std::cout, ". " + sh.str() + ss.str());
						std::cout << "----------" << std::endl;
					}

					{
						auto filename = "dist_" + sh.str() + ss.str() + ".txt";
						std::ofstream out(filename, std::ios::trunc);
						print_distribution<R>(outDist, 0, false, out, sh.str() + ss.str());// 
						filenames.push_back(filename);
					}

					std::cout << sh.str() << ss.str() << " time: "
						<< std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count() << "ms" << std::endl;

					std::cout << "MD: " << expected_md.mExpectMD << " zero: " << expected_md.mZeroRelDist
						<< " zeroVal: " << expected_md.mZeroValue << std::endl;

					if (fullEnum.size())
					{
						if (print_dist)
						{
							std::cout << "log2(E)" << std::endl;
							std::cout << logEnumToString(fullEnum) << std::endl;
						}

						auto filename = "enum_" + sh.str() + ss.str() + ".txt";
						std::ofstream enumFile(
							filename, std::ios::trunc);
						print_enumerator<R>(fullEnum, outDist, 0, enumFile);

						if (doPlot)
						{
							std::string command = "py " + scriptPath + " --enum " + filename;
							if (percent)
								command += " --percent ";
							std::cout << command << std::endl;
							int result = std::system(command.c_str());
						}

					}
				}
			}
		}

		if (doPlot)
		{
			std::string command = "py " + scriptPath + " --dist ";
			for (auto filename : filenames)
				command += filename + " ";
			if (percent)
				command += " --percent --both ";
			std::cout << command << std::endl;
			int result = std::system(command.c_str());
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

		//Choose<Float> choose(n);
		//Choose<Int> choose2(n);

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
		//		choose,
		//		choose2,
		//		E);
		//	break;
		//case osuCrypto::Subcode::Accumulate:

		//	AccumulatorEnumerator<Float, Float>::enumerate(
		//		{},
		//		dist,
		//		systematic,
		//		k, n, numThreads, choose,
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


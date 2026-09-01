#include "RevCuckoo_Tests.h"
#include "libOTe/Dpf/RevCuckooDmpf.h"

namespace osuCrypto
{

	void RevCuckoo_baseOtSlicing_Test(const oc::CLP&)
	{
		RevCuckooDmpf<block> dpf;
		dpf.init(0, 4, 2, 32, 2, 2, 10, false);
		if (dpf.mLinearSecParam != 10 ||
			dpf.hashWidth() != dpf.mPartitionSize + 10 + 8 ||
			dpf.mBinarySolver.mC != dpf.hashWidth())
			throw std::runtime_error("RevCuckoo hash-width slack regression. " LOCATION);

		auto count = dpf.baseOtCount();
		std::vector<std::array<block, 2>> baseSend(count.mSendCount);
		std::vector<block> baseRecv(count.mRecvCount);
		BitVector baseChoice(count.mRecvCount);

		for (u64 i = 0; i < baseSend.size(); ++i)
		{
			baseSend[i][0] = block(i, 0x1111111111111111ull);
			baseSend[i][1] = block(i, 0x2222222222222222ull);
		}
		for (u64 i = 0; i < baseRecv.size(); ++i)
			baseRecv[i] = block(i, 0x3333333333333333ull);

		dpf.setBaseOts(baseSend, baseRecv, baseChoice);

		u64 sendIdx = 0;
		u64 recvIdx = 0;
		auto check = [&](const DpfMult& mult, u64 expectedSend, u64 expectedRecv)
		{
			if (mult.baseOtCount() == 0)
				return;
			if (mult.mSendOts[0][0] != baseSend[expectedSend][0] ||
				mult.mRecvOts[0] != baseRecv[expectedRecv])
				throw std::runtime_error("RevCuckoo base OTs overlap. " LOCATION);
		};

		for (auto& dedup : dpf.mDedup)
		{
			auto eqCount = dedup.mEq.baseOtCount();
			check(dedup.mMult, sendIdx + eqCount.mSendCount, recvIdx + eqCount.mRecvCount);
			auto subCount = dedup.baseOtCount();
			sendIdx += subCount.mSendCount;
			recvIdx += subCount.mRecvCount;
		}

		for (auto& hash : dpf.mGoldreichHash)
		{
			check(hash.mMult, sendIdx, recvIdx);
			auto subCount = hash.baseOtCount();
			sendIdx += subCount.mSendCount;
			recvIdx += subCount.mRecvCount;
		}

		check(dpf.mWaksmanPermute.mMult, sendIdx, recvIdx);
		auto permCount = dpf.mWaksmanPermute.baseOtCount();
		sendIdx += permCount.mSendCount;
		recvIdx += permCount.mRecvCount;

		check(dpf.mBinarySolver.mMult, sendIdx, recvIdx);
		auto solverCount = dpf.mBinarySolver.baseOtCount();
		sendIdx += solverCount;
		recvIdx += solverCount;

		auto denseCount = dpf.mSparseDpf.mRegDpf.baseOtCount();
		check(dpf.mSparseDpf.mRegDpf.mMultiplier, sendIdx, recvIdx);
		check(dpf.mSparseDpf.mMultiplier, sendIdx + denseCount, recvIdx + denseCount);
		auto sparseCount = dpf.mSparseDpf.baseOtCount();
		sendIdx += sparseCount;
		recvIdx += sparseCount;

		check(dpf.mMultiplier, sendIdx, recvIdx);
		auto multCount = dpf.mMultiplier.baseOtCount();
		sendIdx += multCount;
		recvIdx += multCount;

		if (sendIdx != baseSend.size() || recvIdx != baseRecv.size())
			throw std::runtime_error("RevCuckoo base OT regression miscount. " LOCATION);
	}


	template<typename F, typename CoeffCtx>
	void RevCuckoo_iterative_impl(const oc::CLP& cmd)
	{
		// Initialize parameters
		PRNG prng(block(231234, 321312));
		u64 domain = cmd.getOr("domain", 32); // Domain size
		u64 numPoints = cmd.getOr("numPoints", 4); // Number of points
		u64 numSets = cmd.getOr("numSets", 6); // Number of sets
		u64 numPartitions = cmd.getOr("numPartitions", 2); // Number of partitions
		u64 linearSecParam = cmd.getOr("linearSecParam", 40); // Security parameter
		u64 cuckooSecParam = cmd.getOr("cuckooSecParam", 2); // Cuckoo security parameter
		u64 numValueSets = cmd.getOr("numValueSets", 3); // Number of different value sets to test
		bool print = cmd.isSet("print"); // Print flag
		bool printTimer = cmd.isSet("printTimer"); // Print timer flag

		Timer timer[2];

		// Generate input points (fixed for all iterations)
		Matrix<u64> points0(numSets, numPoints);
		Matrix<u64> points1(numSets, numPoints);
		Matrix<u64> actualPoints(numSets, numPoints);
		for (u64 i = 0; i < points1.size(); ++i)
		{
			points1(i) = prng.get<u64>();
			points0(i) = (prng.get<u64>() % domain) ^ points1(i);
			actualPoints(i) = points0(i) ^ points1(i);
		}

		auto ctx = CoeffCtx{};

		// Initialize RevCuckooDmpf instances
		std::array<RevCuckooDmpf<F>, 2> dpf;
		dpf[0].init(0, numPoints, numSets, domain, numPartitions, cuckooSecParam, linearSecParam);
		dpf[1].init(1, numPoints, numSets, domain, numPartitions, cuckooSecParam, linearSecParam);
		dpf[0].mPrint = print;
		dpf[1].mPrint = print;
		dpf[0].setTimer(timer[0]);
		dpf[1].setTimer(timer[1]);

		if (cmd.hasValue("print"))
		{
			dpf[0].mPrintIndex = cmd.getOr("print", 0);
			dpf[1].mPrintIndex = cmd.getOr("print", 0);
		}

		// Setup base OTs
		auto baseCount0 = dpf[0].baseOtCount();
		auto baseCount1 = dpf[1].baseOtCount();
		std::array<std::vector<block>, 2> baseRecv;
		std::array<std::vector<std::array<block, 2>>, 2> baseSend;
		std::array<BitVector, 2> baseChoice;
		baseRecv[0].resize(baseCount0.mRecvCount);
		baseRecv[1].resize(baseCount1.mRecvCount);
		baseSend[0].resize(baseCount0.mSendCount);
		baseSend[1].resize(baseCount1.mSendCount);
		baseChoice[0].resize(baseCount0.mRecvCount);
		baseChoice[1].resize(baseCount1.mRecvCount);
		baseChoice[0].randomize(prng);
		baseChoice[1].randomize(prng);
		for (u64 i = 0; i < baseCount0.mRecvCount; ++i)
		{
			baseSend[1][i] = prng.get();
			baseRecv[0][i] = baseSend[1][i][baseChoice[0][i]];
		}
		for (u64 i = 0; i < baseCount1.mRecvCount; ++i)
		{
			baseSend[0][i] = prng.get();
			baseRecv[1][i] = baseSend[0][i][baseChoice[1][i]];
		}
		dpf[0].setBaseOts(baseSend[0], baseRecv[0], baseChoice[0]);
		dpf[1].setBaseOts(baseSend[1], baseRecv[1], baseChoice[1]);

		// Create sockets for communication
		auto sock = coproto::LocalAsyncSocket::makePair();
		//sock[0].enableLogging();
		//sock[1].enableLogging();

		// Phase 1: Setup points (called once)
		if (print)
		{
			std::cout << "Setting up points..." << std::endl;
		}
		auto r = macoro::sync_wait(macoro::when_all_ready(
			dpf[0].setPoints(points0, prng, sock[0]),
			dpf[1].setPoints(points1, prng, sock[1])
		));
		std::get<0>(r).result();
		std::get<1>(r).result();

		if (dpf[0].mPublicHashSeed != dpf[1].mPublicHashSeed ||
			dpf[0].mGoldreichHashSeeds != dpf[1].mGoldreichHashSeeds)
			throw std::runtime_error("RevCuckoo public hash seeds disagree. " LOCATION);
		if (dpf[0].mGoldreichHashSeeds.size() != numPartitions)
			throw std::runtime_error("RevCuckoo public hash seed count mismatch. " LOCATION);
		for (u64 i = 0; i < dpf[0].mGoldreichHashSeeds.size(); ++i)
			for (u64 j = 0; j < i; ++j)
				if (dpf[0].mGoldreichHashSeeds[i] == dpf[0].mGoldreichHashSeeds[j])
					throw std::runtime_error("RevCuckoo public hash seeds overlap. " LOCATION);

		// verify that the internal shares are correct.
		for (u64 s = 0, k = 0; s < numSets; ++s)
		{
			u64 f = dpf[0].mLeafShares.size() / numSets;
			std::set<u64> active;
			// Verify the output for this iteration
			for (u64 i = 0; i < f; ++i, ++k)
			{
				u64 unit = 0;
				for (u64 j = 0; j < dpf[0].mLeafShares[k].size(); ++j)
				{
					auto val = dpf[0].mLeafShares[k][j] ^ dpf[1].mLeafShares[k][j];
					bool tag = dpf[0].mLeafTags[k][j] ^ dpf[1].mLeafTags[k][j];

					if (val != ZeroBlock)
					{
						active.insert(dpf[0].mSparseSets[k][j]);
						++unit;
					}

					if ((val != ZeroBlock) != bool(tag))
						throw RTE_LOC;
				}

				if (unit > 1)
					throw RTE_LOC;
			}

			//if (active.size() < numPoints)
			//	throw RTE_LOC;

			for (auto p : actualPoints[s])
			{
				if (active.find(p) == active.end())
				{
					std::cout << "Point " << p << " not found in leaf shares." << std::endl;
					throw RTE_LOC;
				}
			}
		}

		// Phase 2: Multiple value expansions (called multiple times)
		for (u64 iteration = 0; iteration < numValueSets; ++iteration)
		{
			if (print)
			{
				std::cout << "Iteration " << iteration + 1 << " of " << numValueSets << std::endl;
			}

			// Generate different values for each iteration
			std::vector<F> values0(numPoints * numSets);
			std::vector<F> values1(numPoints * numSets);
			for (u64 i = 0; i < values1.size(); ++i)
			{
				values0[i] = prng.get();
				values1[i] = prng.get();
			}

			// Prepare output matrices for this iteration
			std::array<Matrix<F>, 2> output;
			output[0].resize(numSets, domain);
			output[1].resize(numSets, domain);

			// Expand values using the cached point setup
			auto r = macoro::sync_wait(macoro::when_all_ready(
				dpf[0].expand(values0, prng, sock[0], [&](auto j, auto i, auto v) { output[0](j, i) = v; }),
				dpf[1].expand(values1, prng, sock[1], [&](auto j, auto i, auto v) { output[1](j, i) = v; })
			));
			std::get<0>(r).result();
			std::get<1>(r).result();
			F zero;
			ctx.zero(zero);

			for (u64 s = 0; s < numSets; ++s)
			{
				std::unordered_map<u64, F> expectedMap;

				for (u64 i = 0; i < numPoints; ++i)
				{
					auto p = actualPoints[s][i];
					F v;
					ctx.plus(v, values0[s * numPoints + i], values1[s * numPoints + i]);
					ctx.plus(expectedMap[p], expectedMap[p], v);
				}


				// Verify the output for this iteration
				bool allCorrect = true;
				for (u64 i = 0; i < domain && allCorrect; ++i)
				{
					auto iter = expectedMap.find(i);
					F actual;
					ctx.plus(actual, output[0](s, i), output[1](s, i));

					auto expected = iter == expectedMap.end()
						? zero : iter->second;

					if (actual != expected)
					{
						allCorrect = false;
						//std::cout << "Iteration " << iteration << " failed at set "<<s<<", domain point " << i << std::endl;
						//std::cout << "Expected: " << expected << std::endl;
						//std::cout << "Actual: " << actual << std::endl;

						//// Show which input points map to this domain position
						//for (u64 j = 0; j < numPoints; ++j)
						//{
						//	if (actualPoints[s][j] == i)
						//	{
						//		std::cout << "Input point " << j << " maps to domain position " << i
						//			<< " with value " << (values0[j] ^ values1[j]) << std::endl;
						//	}
						//}
						//throw RTE_LOC;
					}
				}
				if (!allCorrect)
				{
					std::cout << "Iteration " << iteration + 1 << " failed verification for set " << s << std::endl;
					for (u64 i = 0; i < domain; ++i)
					{
						auto iter = expectedMap.find(i);
						F actual, neg;
						ctx.plus(actual, output[0](s, i), output[1](s, i));
						auto expected = iter == expectedMap.end() ? zero : iter->second;
						ctx.minus(neg, zero, expected);

						if (actual != expected)
							std::cout << Color::Red;
						std::cout << i << ": Exp " << expected << ", Act " << actual
							<< " = " << output[0](s, i) << " + " << output[1](s, i)
							<< ", negExp " << neg
							<< std::endl << Color::Default;
					}
					throw RTE_LOC;
				}
			}

		}


		if (printTimer)
		{
			for (u64 i = 0; i < 2; ++i)
			{
				std::cout << "Dpf " << i << " time: \n" << timer[i] << std::endl;
			}
		}

	}
	void RevCuckoo_iterative_Test(const oc::CLP& cmd)
	{
		RevCuckoo_iterative_impl<block, CoeffCtxGF128>(cmd);
		RevCuckoo_iterative_impl<u64, CoeffCtxInteger>(cmd);
	}

	void RevCuckoo_singlePoint_Test(const oc::CLP&)
	{
		CLP cmd;
		cmd.setDefault("domain", 32);
		cmd.setDefault("numPoints", 1);
		cmd.setDefault("numSets", 1);
		cmd.setDefault("numValueSets", 1);
		RevCuckoo_iterative_impl<block, CoeffCtxGF128>(cmd);
		RevCuckoo_iterative_impl<u64, CoeffCtxInteger>(cmd);
	}

	void RevCuckoo_robustness_Test(const oc::CLP&)
	{
		struct Params
		{
			u64 mDomain;
			u64 mPoints;
			u64 mSets;
			u64 mPartitions;
			u64 mExpansions;
		};

		// These remain intentionally bounded. They cover the former empty-bucket
		// failure, non-power-of-two domains, three partitions, and repeated expansion
		// without selecting parameters outside the paper hash's quadratic feature bound.
		for (auto p : {
			Params{ 32, 8, 16, 2, 3 },
			Params{ 257, 17, 5, 3, 2 }
			})
		{
			CLP cmd;
			cmd.setDefault("domain", p.mDomain);
			cmd.setDefault("numPoints", p.mPoints);
			cmd.setDefault("numSets", p.mSets);
			cmd.setDefault("numPartitions", p.mPartitions);
			cmd.setDefault("linearSecParam", 40);
			cmd.setDefault("numValueSets", p.mExpansions);
			RevCuckoo_iterative_impl<block, CoeffCtxGF128>(cmd);
		}
	}

	void RevCuckoo_failurePropagation_Test(const oc::CLP&)
	{
		constexpr u64 points = 4;
		constexpr u64 sets = 2;
		constexpr u64 domain = 32;
		PRNG prng(block(0x1234, 0x5678));
		std::array<RevCuckooDmpf<block>, 2> dpf;
		for (u64 p = 0; p < 2; ++p)
			dpf[p].init(p, points, sets, domain);

		auto count0 = dpf[0].baseOtCount();
		auto count1 = dpf[1].baseOtCount();
		std::array<std::vector<block>, 2> recv{
			std::vector<block>(count0.mRecvCount),
			std::vector<block>(count1.mRecvCount) };
		std::array<std::vector<std::array<block, 2>>, 2> send{
			std::vector<std::array<block, 2>>(count0.mSendCount),
			std::vector<std::array<block, 2>>(count1.mSendCount) };
		std::array<BitVector, 2> choices{
			BitVector(count0.mRecvCount), BitVector(count1.mRecvCount) };
		choices[0].randomize(prng);
		choices[1].randomize(prng);
		for (u64 i = 0; i < recv[0].size(); ++i)
		{
			send[1][i] = prng.get();
			recv[0][i] = send[1][i][choices[0][i]];
		}
		for (u64 i = 0; i < recv[1].size(); ++i)
		{
			send[0][i] = prng.get();
			recv[1][i] = send[0][i][choices[1][i]];
		}
		dpf[0].setBaseOts(send[0], recv[0], choices[0]);
		dpf[1].setBaseOts(send[1], recv[1], choices[1]);

		Matrix<u64> invalid(sets - 1, points);
		Matrix<u64> valid(sets, points);
		prng.get(invalid.data(), invalid.size());
		prng.get(valid.data(), valid.size());
		auto sockets = coproto::LocalAsyncSocket::makePair();
		auto results = macoro::sync_wait(macoro::when_all_ready(
			dpf[0].setPoints(invalid, prng, sockets[0]),
			dpf[1].setPoints(valid, prng, sockets[1])));

		bool failed[2]{};
		try { std::get<0>(results).result(); }
		catch (...) { failed[0] = true; }
		try { std::get<1>(results).result(); }
		catch (...) { failed[1] = true; }
		if (!failed[0] || !failed[1])
			throw std::runtime_error("RevCuckoo did not propagate a one-sided setup failure. " LOCATION);
	}



	void Goldreich_Proto_Test(const oc::CLP& cmd)
	{

		std::array<GoldreichHash, 2> hash;
		u64 n = 100; // Increased sample size for better statistical analysis
		u64 in = 8;  // Increased input size
		u64 out = 16; // Increased output size for better testing
		//bool v = cmd.isSet("v");
		//auto inBits = in * 8;
		//auto outBits = out * 8;

		hash[0].init(0, n, in, out);
		hash[1].init(1, n, in, out);

		auto count0 = hash[0].baseOtCount();
		auto count1 = hash[1].baseOtCount();
		if (count0.mRecvCount != count1.mSendCount)
			throw RTE_LOC;
		if (count0.mSendCount != count1.mRecvCount)
			throw RTE_LOC;

		PRNG prng(block(231234, 321312));
		std::array<std::vector<block>, 2> baseRecv;
		std::array<std::vector<std::array<block, 2>>, 2> baseSend;
		std::array<BitVector, 2> baseChoice;
		baseRecv[0].resize(count0.mRecvCount);
		baseRecv[1].resize(count1.mRecvCount);
		baseSend[0].resize(count0.mSendCount);
		baseSend[1].resize(count1.mSendCount);
		baseChoice[0].resize(count0.mRecvCount);
		baseChoice[1].resize(count1.mRecvCount);
		for (u64 i = 0; i < 2; ++i)
		{
			baseChoice[i].randomize(prng);
			prng.get(baseSend[i ^ 1].data(), baseSend[i ^ 1].size());
			for (u64 j = 0; j < baseChoice[i].size(); ++j)
				baseRecv[i][j] = baseSend[i ^ 1][j][baseChoice[i][j]];
		}

		hash[0].setBaseOts(baseSend[0], baseRecv[0], baseChoice[0]);
		hash[1].setBaseOts(baseSend[1], baseRecv[1], baseChoice[1]);

		auto seed = prng.get<block>();

		std::array<Matrix<u8>, 2> input, output;
		input[0].resize(n, in);
		input[1].resize(n, in);
		prng.get(input[0].data(), input[0].size());
		prng.get(input[1].data(), input[1].size());
		output[0].resize(n, out);
		output[1].resize(n, out);

		auto sock = coproto::LocalAsyncSocket::makePair();
		macoro::sync_wait(macoro::when_all_ready(
			hash[0].hash(input[0], output[0], sock[0], seed),
			hash[1].hash(input[1], output[1], sock[1], seed)
		));

		Matrix<u8> rIn(n, in), rOut(n, out);
		for (u64 j = 0; j < n; ++j)
		{
			for (u64 k = 0; k < in; ++k)
			{
				rIn(j, k) = input[0](j, k) ^ input[1](j, k);
			}
		}

		hash[0].hash(rIn, rOut, seed);
		for (u64 j = 0; j < n; ++j)
		{
			std::vector<u8> act(out);
			for (u64 k = 0; k < out; ++k)
				act[k] = output[0](j, k) ^ output[1](j, k);
			for (u64 k = 0; k < out; ++k)
			{
				if (act[k] != rOut[j][k])
				{
					std::cout << "j " << j << std::endl;
					std::cout << "act " << toHex(act) << std::endl;
					std::cout << "exp " << toHex(rOut[j]) << std::endl;
					throw RTE_LOC;
				}
			}
		}

	}

	void Goldreich_stat_Test(const oc::CLP& cmd)
	{

		GoldreichHash hash;
		u64 n = 100000; // Increased sample size for better statistical analysis
		u64 in = 8;  // Increased input size
		u64 out = 16; // Increased output size for better testing
		bool v = cmd.isSet("v");
		//auto inBits = in * 8;
		auto outBits = out * 8;

		hash.init(0, n, in, out);
		block seed = block(2342143213662143, 4352452314532765);

		Matrix<u8> rIn(n, in), rOut(n, out);
		for (u64 j = 0; j < n; ++j)
		{
			copyBytesMin(rIn[j], j);
		}

		hash.hash(rIn, rOut, seed);
		if (v)
		{
			// Print a sample of the output for inspection
			std::cout << "\nSample of hash output (first 10 rows):" << std::endl;
			for (u64 j = 0; j < std::min<u64>(n, 10ull); ++j)
			{
				std::cout << "Row " << j << ": ";
				for (u64 k = 0; k < divCeil(outBits, 8); ++k)
				{
					auto act = rOut(j, k);
					std::cout << std::hex << std::setw(2) << std::setfill('0') << int(act);
				}
				std::cout << std::endl;
			}
			std::cout << std::dec; // Reset output to decimal
		}

		// Let's now test the uniformity of the output
		if (v)
		{
			std::cout << "\n==============================================" << std::endl;
			std::cout << "Testing uniformity of GoldreichHash output" << std::endl;
			std::cout << "==============================================" << std::endl;
		}

		// 1. Chi-Square Test for byte distribution
		// We'll count occurrences of each byte value in the output and check if they're uniform
		std::array<u64, 256> byteFrequencies{};
		u64 totalBytes = 0;

		// Count frequency of each byte value
		for (u64 i = 0; i < n; ++i)
		{
			for (u64 j = 0; j < divCeil(outBits, 8); ++j)
			{
				u8 xorByte = rOut(i, j);
				byteFrequencies[xorByte]++;
				totalBytes++;
			}
		}

		// Chi-square statistic for byte distribution
		double expectedFreq = static_cast<double>(totalBytes) / 256.0;
		double chiSquare = 0.0;

		for (u64 i = 0; i < 256; ++i)
		{
			double diff = byteFrequencies[i] - expectedFreq;
			chiSquare += (diff * diff) / expectedFreq;
		}

		// For 255 degrees of freedom at 0.05 significance level, critical value is around 293
		const double chiSquareCritical = 293.25;
		bool chiSquaredPassed = chiSquare < chiSquareCritical;

		if (v)
		{
			std::cout << "Chi-Square Test for Byte Distribution:" << std::endl;
			std::cout << "Chi-Square Value: " << chiSquare << std::endl;
			std::cout << "Critical Value (a=0.05): " << chiSquareCritical << std::endl;
			std::cout << "Result: " << (chiSquaredPassed ? "PASSED" : "FAILED") << std::endl;
			std::cout << "Interpretation: " << (chiSquaredPassed ?
				"Output bytes are uniformly distributed" :
				"Output bytes are NOT uniformly distributed") << std::endl;
			std::cout << std::endl;
		}

		// 2. Bit Distribution Test
		// We'll check if each bit position is roughly 50% 0's and 50% 1's
		std::vector<u64> bitOnes(outBits, 0);

		for (u64 i = 0; i < n; ++i)
		{
			for (u64 j = 0; j < outBits; ++j)
			{
				u64 bytePos = j / 8;
				u64 bitPos = j % 8;
				u8 xorByte = rOut(i, bytePos);
				bool bitValue = (xorByte >> bitPos) & 1;

				if (bitValue)
					bitOnes[j]++;
			}
		}

		if (v)
		{
			std::cout << "Bit Distribution Test:" << std::endl;
			std::cout << "Checking if each bit position is approximately 50% ones" << std::endl;
		}

		// Expected number of ones for a uniform distribution is n/2
		double expectedOnes = static_cast<double>(n) / 2.0;

		// Chi-square statistic for bit distribution (1 degree of freedom per bit)
		//double bitChiSquare = 0.0;
		u64 failedBits = 0;

		for (u64 j = 0; j < outBits; ++j)
		{
			double diff = bitOnes[j] - expectedOnes;
			double bitChi = (diff * diff) / expectedOnes + (diff * diff) / (n - expectedOnes);

			// Critical value for 1 degree of freedom at 0.05 significance is 3.84
			bool bitPassed = bitChi < 3.84;

			if (!bitPassed)
				failedBits++;

			if (v)
			{
				// Detailed bit analysis if verbose mode is on
				std::cout << "Bit " << j << ": " << (bitOnes[j] * 100.0 / n) << "% ones, chi-square = "
					<< bitChi << " - " << (bitPassed ? "PASSED" : "FAILED") << std::endl;
			}
		}

		// We expect about 5% of bits to fail by random chance (at a=0.05)
		double expectedFailRate = 0.05;
		double actualFailRate = static_cast<double>(failedBits) / outBits;
		bool bitDistributionPassed = actualFailRate <= expectedFailRate * 2;

		if (v)
		{
			std::cout << "Failed Bits: " << failedBits << " out of " << outBits << " ("
				<< (actualFailRate * 100.0) << "%)" << std::endl;
			std::cout << "Expected Fail Rate: " << (expectedFailRate * 100.0) << "%" << std::endl;
			std::cout << "Result: " << (bitDistributionPassed ? "PASSED" : "FAILED") << std::endl;
			std::cout << "Interpretation: " << (bitDistributionPassed ?
				"Bit positions show expected randomness" :
				"Some bit positions show non-random distribution") << std::endl;

			std::cout << "==============================================" << std::endl;
		}

		// 4. Overall result summary
		if (v)
		{
			std::cout << "\nSummary of GoldreichHash Uniformity Tests:" << std::endl;
			std::cout << "1. Chi-Square Test: " << (chiSquaredPassed ? "PASSED" : "FAILED") << std::endl;
			std::cout << "2. Bit Distribution Test: " << (bitDistributionPassed ? "PASSED" : "FAILED") << std::endl;
			std::cout << "Overall: " << ((chiSquaredPassed && bitDistributionPassed) ?
				"PASSED - Output appears uniform" :
				"FAILED - Output may not be uniform") << std::endl;
		}

		// Throw exception if any test fails
		if (!chiSquaredPassed || !bitDistributionPassed)
			throw RTE_LOC;

	}
}

#include "Permute_Tests.h"

#include "libOTe/Dpf/RevCuckoo/WaksmanPermute.h"
#include "cryptoTools/Common/Matrix.h"
#include "cryptoTools/Common/CLP.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <set>
#include <algorithm>
#include <iostream>
#include <unordered_set>
#include <numeric>

namespace osuCrypto
{

	void WaksmanPermute_plain_Test(const CLP& cmd)
	{
		//// Test parameters
		//auto N = cmd.getManyOr<u64>("n", { 16, 17, 32, 33 });
		//u64 inputBytes = cmd.getOr("inputBytes", 8);
		//u64 numTests = cmd.getOr("numTests", 5);
		//bool verbose = cmd.isSet("v");

		//PRNG prng(block(243573546521, 4532165));

		//// Create a  instance
		//WaksmanPermute permuter;

		//for (u64 n : N)
		//{
		//	for (u64 testIdx = 0; testIdx < numTests; ++testIdx)
		//	{
		//		if (verbose)
		//			std::cout << "Running test " << testIdx + 1 << "/" << numTests << std::endl;

		//		// Create input data with unique patterns
		//		Matrix<u8> input(n, inputBytes);
		//		std::unordered_map<u64, u64> set;
		//		prng.get(input.data(), input.size());
		//		for (u64 i = 0; i < n; ++i)
		//		{
		//			u64 vv = 0;
		//			copyBytesMin(vv, input[i]);
		//			set[vv]++;
		//		}

		//		// Generate random seeds for permutation
		//		//block seed0 = prng.get<block>();
		//		//block seed1 = prng.get<block>();

		//		permuter.applyPlain(input, [&] {return prng.getBit(); });

		//		std::unordered_map<u64, u64> outSet;
		//		for (u64 i = 0; i < n; ++i)
		//		{
		//			u64 vv = 0;
		//			copyBytesMin(vv, input[i]);
		//			outSet[vv]++;
		//		}

		//		if (outSet != set)
		//			throw RTE_LOC;

		//	}

		//}
	}

	// Generic test function that works with different field types and coefficient contexts
	template<typename F, typename CoeffCtx>
	void WaksmanPermute_Generic_Test_impl(const CLP& cmd, CoeffCtx ctx)
	{
		// Test parameters
		auto N = cmd.getManyOr<u64>("n", { 16, 17, 32, 33 });
		u64 numTests = cmd.getOr("numTests", 5);
		bool verbose = cmd.isSet("v");

		PRNG prng(block(243573546521, 4532165));

		for (u64 n : N)
		{
			for (u64 testIdx = 0; testIdx < numTests; ++testIdx)
			{
				if (verbose)
					std::cout << "Running generic test with type " << typeid(F).name()
					<< " - " << testIdx + 1 << "/" << numTests << std::endl;

				// Create permuter instances
				std::array<WaksmanPermute, 2> permuters;
				permuters[0].init(0, n);
				permuters[1].init(1, n);

				// Create input data using coefficient context
				auto input = ctx.template makeVec<F>(n);

				std::array<decltype(input), 2> inputs;
				for (u64 p = 0; p < 2; ++p)
				{
					inputs[p] = ctx.template makeVec<F>(n);
				}

				auto sock = coproto::LocalAsyncSocket::makePair();

				// Store expected values for verification
				auto expectedValues = ctx.template makeVec<F>(n);
				ctx.resize(expectedValues, n);

				for (u64 i = 0; i < n; ++i)
				{
					// Generate random field elements
					ctx.fromBlock(inputs[0][i], prng.get());
					ctx.fromBlock(inputs[1][i], prng.get());

					// Store the expected combined value
					ctx.plus(expectedValues[i], inputs[0][i], inputs[1][i]);
				}

				// Set up base OTs
				auto count = std::array{ permuters[0].baseOtCount(), permuters[1].baseOtCount() };
				std::array<std::vector<block>, 2> baseRecvOts;
				std::array<std::vector<std::array<block, 2>>, 2> baseSendOts;
				std::array<BitVector, 2> baseRecvBits;

				for (u64 p = 0; p < 2; ++p)
				{
					if (count[p].mRecvCount != count[p ^ 1].mSendCount)
						throw RTE_LOC;

					baseRecvOts[p].resize(count[p].mRecvCount);
					baseSendOts[p ^ 1].resize(count[p].mRecvCount);
					baseRecvBits[p].resize(count[p].mRecvCount);
					baseRecvBits[p].randomize(prng);
					for (u64 i = 0; i < count[p].mRecvCount; ++i) {
						baseSendOts[p ^ 1][i] = prng.get();
						baseRecvOts[p][i] = baseSendOts[p ^ 1][i][baseRecvBits[p][i]];
					}
				}

				permuters[0].setBaseOts(baseSendOts[0], baseRecvOts[0], baseRecvBits[0]);
				permuters[1].setBaseOts(baseSendOts[1], baseRecvOts[1], baseRecvBits[1]);

				// Apply the permutation protocol
				auto r = macoro::sync_wait(macoro::when_all_ready(
					permuters[0].apply<F, CoeffCtx>(inputs[0], sock[0], ctx),
					permuters[1].apply<F, CoeffCtx>(inputs[1], sock[1], ctx)
				));

				// Verify that the result is a permutation of the input
				std::multiset<std::string> inputSet, outputSet;

				for (u64 i = 0; i < n; ++i)
				{
					// Reconstruct the original value
					auto originalValue = ctx.template make<F>();
					ctx.copy(originalValue, expectedValues[i]);
					inputSet.insert(ctx.str(originalValue));

					// Reconstruct the output value
					auto outputValue = ctx.template make<F>();
					ctx.plus(outputValue, inputs[0][i], inputs[1][i]);
					outputSet.insert(ctx.str(outputValue));
				}

				// Verify that output is a permutation of input
				if (inputSet != outputSet)
				{
					std::cout << "Permutation test failed for type " << typeid(F).name()
						<< " at test " << testIdx << std::endl;
					std::cout << "Input and output sets differ!" << std::endl;
					throw RTE_LOC;
				}
			}
		}
	}
	void WaksmanPermute_Proto_Test(const CLP& cmd)
	{
		// Test with different coefficient contexts and field types
		WaksmanPermute_Generic_Test_impl<block, CoeffCtxGF2>(cmd, CoeffCtxGF2{});
		WaksmanPermute_Generic_Test_impl<u64, CoeffCtxInteger>(cmd, CoeffCtxInteger{});
	}


	// Generic test function that works with different field types and coefficient contexts
	template<typename F, typename CoeffCtx>
	void WaksmanPermute_Many_Test_impl(const CLP& cmd, CoeffCtx ctx)
	{
		// Test parameters
		auto N = cmd.getManyOr<u64>("n", { 16, 17, 32, 33 });
		u64 batches = cmd.getOr("batches", 10);
		u64 numTests = cmd.getOr("numTests", 5);
		bool verbose = cmd.isSet("v");

		PRNG prng(block(243573546521, 4532165));

		for (u64 n : N)
		{
			for (u64 testIdx = 0; testIdx < numTests; ++testIdx)
			{
				if (verbose)
					std::cout << "Running generic test with type " << typeid(F).name()
					<< " - " << testIdx + 1 << "/" << numTests << std::endl;

				// Create permuter instances
				std::array<WaksmanPermute, 2> permuters;
				permuters[0].init(0, n, batches);
				permuters[1].init(1, n, batches);

				// Create input data using coefficient context
				using VecF = typename CoeffCtx::template Vec<F>;
				VecF input = ctx.template makeVec<F>(n);

				std::array<std::vector<VecF>, 2> inputs;
				for (u64 p = 0; p < 2; ++p)
				{
					inputs[p].resize(batches);

					for (u64 b = 0; b < batches; ++b)
						inputs[p][b] = ctx.template makeVec<F>(n);
				}

				auto sock = coproto::LocalAsyncSocket::makePair();

				// Store expected values for verification
				std::vector<decltype(input)> expectedValues(batches);
				for (u64 b = 0; b < batches; ++b)
				{
					ctx.resize(expectedValues[b], n);
					for (u64 i = 0; i < n; ++i)
					{
						// Generate random field elements
						ctx.fromBlock(inputs[0][b][i], prng.get());
						ctx.fromBlock(inputs[1][b][i], prng.get());

						// Store the expected combined value
						ctx.plus(expectedValues[b][i], inputs[0][b][i], inputs[1][b][i]);
					}
				}

				// Set up base OTs
				auto count = std::array{ permuters[0].baseOtCount(), permuters[1].baseOtCount() };
				std::array<std::vector<block>, 2> baseRecvOts;
				std::array<std::vector<std::array<block, 2>>, 2> baseSendOts;
				std::array<BitVector, 2> baseRecvBits;

				for (u64 p = 0; p < 2; ++p)
				{
					if (count[p].mRecvCount != count[p ^ 1].mSendCount)
						throw RTE_LOC;

					baseRecvOts[p].resize(count[p].mRecvCount);
					baseSendOts[p ^ 1].resize(count[p].mRecvCount);
					baseRecvBits[p].resize(count[p].mRecvCount);
					baseRecvBits[p].randomize(prng);
					for (u64 i = 0; i < count[p].mRecvCount; ++i) {
						baseSendOts[p ^ 1][i] = prng.get();
						baseRecvOts[p][i] = baseSendOts[p ^ 1][i][baseRecvBits[p][i]];
					}
				}

				permuters[0].setBaseOts(baseSendOts[0], baseRecvOts[0], baseRecvBits[0]);
				permuters[1].setBaseOts(baseSendOts[1], baseRecvOts[1], baseRecvBits[1]);

				// Apply the permutation protocol
				auto r = macoro::sync_wait(macoro::when_all_ready(
					permuters[0].applyMany<F, VecF>(inputs[0], sock[0], ctx),
					permuters[1].applyMany<F, VecF>(inputs[1], sock[1], ctx)
				));

				// Verify that the result is a permutation of the input
				for (u64 b = 0; b < batches; ++b)
				{
					// Create sets to compare input and output
					std::multiset<std::string> inputSet, outputSet;

					for (u64 i = 0; i < n; ++i)
					{
						// Reconstruct the original value
						auto originalValue = ctx.template make<F>();
						ctx.copy(originalValue, expectedValues[b][i]);
						inputSet.insert(ctx.str(originalValue));

						// Reconstruct the output value
						auto outputValue = ctx.template make<F>();
						ctx.plus(outputValue, inputs[0][b][i], inputs[1][b][i]);
						outputSet.insert(ctx.str(outputValue));
					}

					// Verify that output is a permutation of input
					if (inputSet != outputSet)
					{
						std::cout << "Permutation test failed for type " << typeid(F).name()
							<< " at test " << testIdx << std::endl;
						std::cout << "Input and output sets differ!" << std::endl;
						throw RTE_LOC;
					}
				}
			}
		}
	}
	void WaksmanPermute_Many_Test(const CLP& cmd)
	{
		// Test with different coefficient contexts and field types
		WaksmanPermute_Many_Test_impl<block, CoeffCtxGF2>(cmd, CoeffCtxGF2{});
		WaksmanPermute_Many_Test_impl<u64, CoeffCtxInteger>(cmd, CoeffCtxInteger{});
	}

}
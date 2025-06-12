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
		// Test parameters
		auto N = cmd.getManyOr<u64>("n", { 16, 17, 32, 33 });
		u64 inputBytes = cmd.getOr("inputBytes", 8);
		u64 numTests = cmd.getOr("numTests", 5);
		bool verbose = cmd.isSet("v");

		PRNG prng(block(243573546521, 4532165));

		// Create a  instance
		WaksmanPermute permuter;

		for (u64 n : N)
		{
			for (u64 testIdx = 0; testIdx < numTests; ++testIdx)
			{
				if (verbose)
					std::cout << "Running test " << testIdx + 1 << "/" << numTests << std::endl;

				// Create input data with unique patterns
				Matrix<u8> input(n, inputBytes);
				std::unordered_map<u64, u64> set;
				prng.get(input.data(), input.size());
				for (u64 i = 0; i < n; ++i)
				{
					u64 vv = 0;
					copyBytesMin(vv, input[i]);
					set[vv]++;
				}

				// Generate random seeds for permutation
				block seed0 = prng.get<block>();
				block seed1 = prng.get<block>();

				permuter.apply(input, [&] {return prng.getBit(); });

				std::unordered_map<u64, u64> outSet;
				for (u64 i = 0; i < n; ++i)
				{
					u64 vv = 0;
					copyBytesMin(vv, input[i]);
					outSet[vv]++;
				}

				if (outSet != set)
					throw RTE_LOC;

			}

		}
	}

	void WaksmanPermute_Proto_Test(const CLP& cmd)
	{

		// Test parameters
		auto N = cmd.getManyOr<u64>("n", { 16, 17, 32, 33 });
		u64 inputBytes = cmd.getOr("inputBytes", 8);
		u64 numTests = cmd.getOr("numTests", 5);
		bool verbose = cmd.isSet("v");

		PRNG prng(block(243573546521, 4532165));


		for (u64 n : N)
		{
			for (u64 testIdx = 0; testIdx < numTests; ++testIdx)
			{
				if (verbose)
					std::cout << "Running test " << testIdx + 1 << "/" << numTests << std::endl;

				// Create a  instance
				std::array<WaksmanPermute, 2> permuters;

				permuters[0].init(0, n);
				permuters[1].init(1, n);

				// Create input data with unique patterns
				Matrix<u8> input(n, inputBytes);
				std::array<Matrix<u8>, 2> inputs;
				inputs[0].resize(n, inputBytes);
				inputs[1].resize(n, inputBytes);

				auto sock = coproto::LocalAsyncSocket::makePair();
				std::unordered_map<u64, u64> set;
				//prng.get(input.data(), input.size());
				for (u64 i = 0; i < n; ++i)
				{
					u64 vv = i;
					copyBytesMin(input[i], vv);
					//copyBytesMin(vv, input[i]);
					set[vv]++;

					copyBytes(inputs[0][i], input[i]);
					for(u64 j = 0; j < inputBytes; ++j)
					{
						inputs[1][i][j] = prng.get<u8>();
						inputs[0][i][j] ^= inputs[1][i][j]; 
					}
				}

				// Generate random seeds for permutation
				block seed0 = prng.get<block>();
				block seed1 = prng.get<block>();

				std::array count{ permuters[0].baseOtCount(), permuters[1].baseOtCount() };
				std::array<std::vector<block>, 2> baseRecvOts;
				std::array<std::vector<std::array<block,2>>, 2> baseSendOts;
				std::array<BitVector, 2> baseRecvBits;
				for(u64 p = 0; p < 2; ++p)
				{
					if (count[p].mRecvCount != count[p^1].mSendCount)
						throw RTE_LOC;

					baseRecvOts[p].resize(count[p].mRecvCount);
					baseSendOts[p^1].resize(count[p].mRecvCount);
					baseRecvBits[p].resize(count[p].mRecvCount);
					baseRecvBits[p].randomize(prng);
					for (u64 i = 0; i < count[p].mRecvCount; ++i) {
						baseSendOts[p^1][i] = prng.get();
						baseRecvOts[p][i] = baseSendOts[p ^ 1][i][baseRecvBits[p][i]];
					}
				}

				permuters[0].setBaseOts(baseSendOts[0], baseRecvOts[0], baseRecvBits[0]);
				permuters[1].setBaseOts(baseSendOts[1], baseRecvOts[1], baseRecvBits[1]);

				auto r = macoro::sync_wait(macoro::when_all_ready(
					permuters[0].apply(inputs[0], seed0, sock[0]),
					permuters[1].apply(inputs[1], seed1, sock[1])
				));

				std::unordered_map<u64, u64> outSet;
				std::vector<u8> outBuf(inputBytes);
				for (u64 i = 0; i < n; ++i)
				{
					copyBytes(outBuf, inputs[0][i]);
					for (u64 j = 0; j < inputBytes; ++j)
					{
						outBuf[j] ^= inputs[1][i][j];
					}

					u64 vv = 0;
					copyBytesMin(vv, outBuf);
					outSet[vv]++;
				}

				if (outSet != set)
					throw RTE_LOC;

			}

		}
	}

}
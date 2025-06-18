#include "BlkAccCode_Tests.h"
#include "Common.h"
#include <cryptoTools/Common/TestCollection.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Crypto/PRNG.h>
#include "libOTe/Tools/BlkAccCode/BlkAccCode.h"
#include "libOTe/Tools/CoeffCtx.h"
using namespace osuCrypto;

namespace tests_libOTe
{


	template<typename F, typename Ctx>
	void BlkAccCode_paramSweep_impl()
	{
		//using Ctx = CoeffCtxGF2;
		//using F = block; // Using block type for the code

		// Test BlkAccCode with power-of-2 and non-power-of-2 sizes,
		// verifying linearity for each case
		struct TestParams {
			u64 messageSize;
			u64 codeSize;
			u64 blockSize;
			u64 depth;
			bool isPowerOfTwo;
			const char* description;
		};

		std::vector<TestParams> testParams = {
			{64, 128, 8, 3, true, "n 64"},
			{128, 256, 8, 3, true, "n 128"},
			{128, 1024, 16, 3, true, "10x compress"},
			{120, 240, 8, 3, false, "Non-power-of-2 sized"},
			{120, 240, 8, 4, false, "d 4"},
			{128, 256, 8, 5, false, "d 5"}
		};

		for (const auto& params : testParams)
		{
			BlkAccCode code;
			code.init(params.messageSize, params.codeSize, params.blockSize, params.depth);

			// Test linearity for each case
			PRNG prng(ZeroBlock);

			// Create two random inputs x and y
			std::vector<F> inputX(params.codeSize);
			std::vector<F> inputY(params.codeSize);
			std::vector<F> inputXplusY(params.codeSize); // x + y

			prng.get(inputX.data(), inputX.size());
			prng.get(inputY.data(), inputY.size());

			// Compute x + y
			for (u64 i = 0; i < params.codeSize; i++) {
				Ctx{}.plus(inputXplusY[i], inputX[i], inputY[i]);
			}
			code.dualEncode<F>(inputX.begin(), Ctx{});
			code.dualEncode<F>(inputY.begin(), Ctx{});
			code.dualEncode<F>(inputXplusY.begin(), Ctx{});


			// Verify linearity: encode(x) + encode(y) = encode(x+y)
			for (u64 i = 0; i < params.messageSize; i++) {
				F exp;
				Ctx{}.plus(exp, inputX[i], inputY[i]); // exp = encode(x) + encode(y)
				if (exp != inputXplusY[i]) {
					throw UnitTestFail(std::string(params.description) +
						" linearity test failed: encode(x) + encode(y) != encode(x+y)" LOCATION);
				}
			}
		}
	}



	void BlkAccCode_paramSweep_test()
	{
		BlkAccCode_paramSweep_impl<block, CoeffCtxGF2>();
		BlkAccCode_paramSweep_impl<u64, CoeffCtxInteger>();
	}


	void BlkAccCode_mtx_test()
	{
		u64 n = 32;
		u64 k = 16;
		u64 sigma = 8;
		u64 depth = 3;
		BlkAccCode code;
		code.init(k, n, sigma, depth);

		PRNG prng(CCBlock);
		std::vector<u8> x(n);
		prng.get(x.data(), x.size());
		auto input = x;


		auto print = [](span<u8> v) {
			std::stringstream ss;
			for (auto vv : v)
				ss << int(vv) <<" ";
			return ss.str();
			};
		//std::cout << "\n";
		//std::cout << print(input) << std::endl;

		for (u64 d = 0; d < depth - 1; ++d)
		{
			auto seed = code.subseed(d);
			Accumulator<FeistelPerm> acc(n, FeistelPerm(n, seed));

			auto AccMtx = acc.getMtx();
			//std::cout << AccMtx << std::endl;

			std::vector<u8> y(n);
			acc.dualEncode<u8>(x.begin(), y.begin(), CoeffCtxGF2{});

			//std::cout << print(y) << std::endl;
			std::vector<u8> yy(n);
			AccMtx.multAdd(x, yy);
			 
			for (u64 i = 0; i < k; ++i)
				if (y[i] != yy[i])
				{
					std::cout << "x   " << print(x) << std::endl;
					std::cout << "act " << print(y) << std::endl;
					std::cout << "exp " << print(yy) << std::endl;


					throw RTE_LOC;
				}

			x = y;
		}



		{
			BlockDiagonal bd(k, n, sigma, code.subseed(depth - 1));
			auto bdMtx = bd.getMtx();
			auto xx = x;
			bd.dualEncode<u8>(xx.begin(), CoeffCtxGF2{});
			xx.resize(k);
			//std::cout << print(xx) << std::endl;

			std::vector<u8> y(k);
			bdMtx.multAdd(x, y);

			for (u64 i = 0; i < k; ++i)
				if (xx[i] != y[i])
				{
					std::cout << "x   " << print(x) << std::endl;
					std::cout << "act " << print(xx) << std::endl;
					std::cout << "exp " << print(y) << std::endl;


					throw RTE_LOC;
				}

			x = xx;
		}


		code.dualEncode<u8>(input.begin(), CoeffCtxGF2{});
		input.resize(k);
		if (input != x)
		{

			std::cout << "act " << print(input) << std::endl;
			std::cout << "exp " << print(x) << std::endl;
			throw RTE_LOC;
		}
		//code.init(params.messageSize, params.codeSize, params.blockSize, params.depth);


	}
}

#include "RingLpn_Tests.h"
//#include "libOTe/Triple/RingLpn/fft/RingLpnFft.h"
#include "cryptoTools/Common/Matrix.h"
#include "libOTe/Triple/RingLpn/RingLpnTriple.h"
#include "coproto/Socket/LocalAsyncSock.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Common/TestCollection.h"
#include "libOTe/Tools/Field/FP.h"


namespace osuCrypto
{

	void RingLpn_basic_test(const CLP& cmd)
	{

		//using F = Fp<0xFFFFFFFB, u32, u64>;
		using F = F12289;

		auto logn = 6;
		u64 n = 1ull << logn;
		bool verbose = cmd.isSet("v");
		std::vector<u64> cs{ 1 };
		u64 t = cmd.getOr("t", 8);
		u64 c = cmd.getOr("c", 1);
		auto blockSize = n / t;

		Poly<F> xnPlus1;
		xnPlus1[n] = 1;
		xnPlus1[0] = 1;

		std::vector<Poly<F>> as(c);
		std::vector<Poly<F>> bs(c);
		std::vector<Poly<F>> rs(c);

		PRNG prng(block(12345, 67890));

		// Generate random coefficients rs[i]
		for (u64 i = 0; i < c; ++i) {
			//rs[i][0] = 1; 
			for (u64 j = 0; j < n; ++j)
				rs[i][j] = prng.get();
		}

		// Generate sparse polynomials a[i] and b[i] with weight t
		for (u64 i = 0; i < c; ++i) {

			// Generate t random positions for non-zero coefficients
			for (u64 j = 0; j < t; ++j)
			{
				as[i][j * blockSize + prng.get<u64>() % blockSize] = prng.get();
				bs[i][j * blockSize + prng.get<u64>() % blockSize] = prng.get();
			}
		}
		// this test checks the following:
		//
		// a' = a[0] * r[0] + a[1] * r[1] + ... + a[c-1] * r[c-1]  mod xnPlus1
		// b' = b[0] * r[0] + b[1] * r[1] + ... + b[c-1] * r[c-1]  mod xnPlus1
		// c' = a' * b' mod xnPlus1
		//    = (a[0] * r[0] + a[1] * r[1] + ... + a[c-1] * r[c-1]) *
		//      (b[0] * r[0] + b[1] * r[1] + ... + b[c-1] * r[c-1]) mod xnPlus1
		//    = a[0] * b[0] * r[0] * r[0] +
		//      a[0] * b[1] * r[0] * r[1] + 
		//      ... +
		//      a[c-1] * b[c-1] * r[c-1] * r[c-1] mod xnPlus1


		// to match the protocol, we will have each a[i], b[i] be a polynomial
		// of max degree n-1 and weight t.
		// this does is just a sanity check that the RingLpnTriple
		// and only works with Poly<F>. It does not use the RingLpnTriple

		// Compute a' = sum(a[i] * r[i]) mod x^n + 1
		Poly<F> aPrime(n);
		for (u64 i = 0; i < c; ++i) {
			auto scaled = as[i] * rs[i];
			aPrime = aPrime + scaled;
		}
		aPrime = aPrime % xnPlus1;

		// Compute b' = sum(b[i] * r[i]) mod x^n + 1
		Poly<F> bPrime(n);
		for (u64 i = 0; i < c; ++i) {
			auto scaled = bs[i] * rs[i];
			bPrime = bPrime + scaled;
		}
		bPrime = bPrime % xnPlus1;

		// Compute c' = a' * b' mod x^n + 1
		Poly<F> cPrime = (aPrime * bPrime) % xnPlus1;

		// Compute the expected result using the expanded form
		Poly<F> expected(n);
		for (u64 i = 0; i < c; ++i) {
			for (u64 j = 0; j < c; ++j) {
				auto term = (as[i] * bs[j]) * (rs[i] * rs[j]);
				expected = expected + term;
			}
		}
		expected = expected % xnPlus1;

		// Verify that c' equals the expected result
		if (cPrime != expected) {
			if (verbose) {
				std::cout << "Test failed!" << std::endl;
				std::cout << "c' = " << cPrime << std::endl;
				std::cout << "expected = " << expected << std::endl;
			}
			throw RTE_LOC;
		}

		// ============ FFT/Evaluation Domain Testing ============

		// Find a primitive root of unity for NTT of size 2*n
		auto psi = primRootOfUnity<F>(2 * n);
		std::vector<F> w(2 * n);
		for (u64 i = 0; i < 2 * n; ++i) {
			w[i] = psi.pow(i);
		}

		// Convert polynomials to evaluation form using NTT
		std::vector<F> aPrime_eval(n), bPrime_eval(n), cPrime_eval(n);

		// Copy coefficients to evaluation vectors (ensure they're the right size)
		for (u64 i = 0; i < n; ++i) {
			aPrime_eval[i] = aPrime.getCoeff(i);
			bPrime_eval[i] = bPrime.getCoeff(i);
			cPrime_eval[i] = cPrime.getCoeff(i);
		}

		// Apply NTT (negative wrapped to handle x^n + 1 modulus)
		nttNegWrapCt<F>(aPrime_eval, w);
		nttNegWrapCt<F>(bPrime_eval, w);
		nttNegWrapCt<F>(cPrime_eval, w);

		// Compute componentwise product in evaluation domain
		std::vector<F> expected_eval(n);
		for (u64 i = 0; i < n; ++i) {
			expected_eval[i] = aPrime_eval[i] * bPrime_eval[i];
		}

		// Verify that eval(c') = eval(a') * eval(b')
		bool evalTest = true;
		for (u64 i = 0; i < n; ++i) {
			if (cPrime_eval[i] != expected_eval[i]) {
				evalTest = false;
				if (verbose) {
					std::cout << "FFT domain test failed at position " << i << std::endl;
					std::cout << "eval(c')[" << i << "] = " << cPrime_eval[i] << std::endl;
					std::cout << "eval(a')[" << i << "] * eval(b')[" << i << "] = "
						<< expected_eval[i] << std::endl;
				}
				break;
			}
		}

		if (!evalTest) {
			throw RTE_LOC;
		}

		// Additional verification: transform back and compare with polynomial result
		//std::vector<F> cPrime_reconstructed = cPrime_eval;

		// Inverse NTT to get back to coefficient form
		// Note: We need the inverse NTT function - this might require implementing
		// the inverse transformation or using a different approach

		if (verbose) {
			std::cout << "FFT domain test passed!" << std::endl;
			std::cout << "RingLpn_basic_test completed successfully with c=" << c
				<< ", t=" << t << ", n=" << n << std::endl;
		}

	}


	// This test evaluates the full PCG.Expand for both parties and
	// checks correctness of the resulting OLE correlation.
	void RingLpn_ole_test(const CLP& cmd)
	{
#ifdef ENABLE_RINGLPN

		//using F = Fp<0xFFFFFFFB, u32, u64>;
		using F = F12289;

		auto logn = 6;
		u64 n = 1ull << logn;
		bool verbose = cmd.isSet("v");
		std::vector<u64> cs{ cmd.getManyOr<u64>("c", {4}) };

		for (auto c : cs)
			for (auto base : { RingLpnTriple<F>::BaseCorType::Precomputed, RingLpnTriple<F>::BaseCorType::OtBased })
			{

				std::array<RingLpnTriple<F>, 2> oles;
				if (cmd.hasValue("t"))
					oles[0].mPolyWeight = oles[1].mPolyWeight = cmd.get<u64>("t");

				oles[0].mNumPolys = oles[1].mNumPolys = c;

				oles[0].mDebug = cmd.isSet("debug");
				oles[1].mDebug = oles[0].mDebug;

				PRNG prng0(block(2424523452345, 111124521521455324));
				PRNG prng1(block(6474567454546, 567546754674345444));
				Timer timer;

				oles[0].init(0, n, base);
				oles[1].init(1, n, base);



				{
					auto otCount0 = oles[0].baseCorCount();
					auto otCount1 = oles[1].baseCorCount();
					if (otCount0.mRecvOtCount != otCount1.mSendOtCount ||
						otCount0.mSendOtCount != otCount1.mRecvOtCount)
						throw RTE_LOC;
					std::array<std::vector<std::array<block, 2>>, 2> baseSend;
					baseSend[0].resize(otCount0.mSendOtCount);
					baseSend[1].resize(otCount1.mSendOtCount);
					std::array<std::vector<block>, 2> baseRecv, oleMult, oleAdd;
					std::array<BitVector, 2> baseChoice;

					for (u64 i = 0; i < 2; ++i)
					{
						prng0.get(baseSend[i].data(), baseSend[i].size());
						baseRecv[1 ^ i].resize(baseSend[i].size());
						baseChoice[1 ^ i].resize(baseSend[i].size());
						baseChoice[1 ^ i].randomize(prng0);
						for (u64 j = 0; j < baseSend[i].size(); ++j)
						{
							baseRecv[1 ^ i][j] = baseSend[i][j][baseChoice[1 ^ i][j]];
						}
					}

					std::array<std::vector<F>, 2> coeffs, tensor;
					coeffs[0].resize(otCount0.mCoeffCount);
					coeffs[1].resize(otCount1.mCoeffCount);
					tensor[0].resize(otCount0.mCoeffCount * otCount0.mCoeffCount);
					tensor[1].resize(otCount1.mCoeffCount * otCount1.mCoeffCount);
					for (u64 i = 0; i < coeffs[0].size(); ++i)
					{
						coeffs[0][i] = prng0.get();
						coeffs[1][i] = prng1.get();
					}
					for (u64 i = 0; i < coeffs[0].size(); ++i)
					{
						for (u64 j = 0; j < coeffs[0].size(); ++j)
						{
							auto idx = i * coeffs[0].size() + j;
							tensor[0][idx] = prng0.get();
							tensor[1][idx] = coeffs[0][i] * coeffs[1][j] - tensor[0][idx];

							//std::cout
							//	<< coeffs[0][i] << " * " << coeffs[1][j] << " = "
							//	<< tensor[0][idx] << " + " << tensor[1][idx]
							//	<< std::endl;

							if ((tensor[0][idx] + tensor[1][idx]) != (coeffs[0][i] * coeffs[1][j]))
								throw RTE_LOC;
						}
					}

					oleMult[0].resize(otCount0.mOleCount / 128);
					oleMult[1].resize(otCount0.mOleCount / 128);
					oleAdd[0].resize(otCount0.mOleCount / 128);
					oleAdd[1].resize(otCount0.mOleCount / 128);
					prng0.get(oleMult[0].data(), oleMult[0].size());
					prng0.get(oleMult[1].data(), oleMult[1].size());
					prng0.get(oleAdd[0].data(), oleAdd[0].size());
					for (u64 i = 0; i < oleAdd[1].size(); ++i)
						oleAdd[1][i] = (oleMult[1][i] & oleMult[0][i]) ^ oleAdd[0][i];

					oles[0].setBaseCors(baseSend[0], baseRecv[0], baseChoice[0], oleMult[0], oleAdd[0], coeffs[0], tensor[0]);
					oles[1].setBaseCors(baseSend[1], baseRecv[1], baseChoice[1], oleMult[1], oleAdd[1], coeffs[1], tensor[1]);
				}

				auto sock = coproto::LocalAsyncSocket::makePair();
				std::vector<F>
					A(n), B(n),
					C0(n), C1(n);

				if (verbose)
					oles[0].setTimer(timer);

				auto r = macoro::sync_wait(macoro::when_all_ready(
					oles[0].expand(A, C0, prng0, sock[0]),
					oles[1].expand(B, C1, prng1, sock[1])));
				std::get<0>(r).result();
				std::get<1>(r).result();

				//Now we check that we got the correct OLE correlations and fail
				//the test otherwise.
				for (size_t i = 0; i < n; i++)
				{
					auto act = C0[i] + C1[i];
					auto exp = A[i] * B[i];

					if (exp != act)
						throw RTE_LOC;
				}

				if (verbose)
					std::cout << "Time taken: \n" << timer << std::endl;
			}

#else
		throw UnitTestSkipped("ENABLE_RINGLPN not defined.");
#endif

	}

	void RingLpn_Triple_test(const CLP& cmd)
	{
#ifdef ENABLE_RINGLPN

		using F = Fp<0xFFFFFFFB, u32, u64>;
		std::array<RingLpnTriple<F>, 2> oles;

		auto logn = 5;
		u64 n = 1ull << logn;
		auto blocks = divCeil(n, 128);
		bool verbose = cmd.isSet("v");

		if (cmd.hasValue("t"))
			oles[0].mPolyWeight = oles[1].mPolyWeight = cmd.get<u64>("t");

		PRNG prng0(block(2424523452345, 111124521521455324));
		PRNG prng1(block(6474567454546, 567546754674345444));
		Timer timer;

		oles[0].init(0, n);
		oles[1].init(1, n);

		throw RTE_LOC;
		//{
		//	auto otCount0 = oles[0].baseOtCount();
		//	auto otCount1 = oles[1].baseOtCount();
		//	if (otCount0.mRecvCount != otCount1.mSendCount ||
		//		otCount0.mSendCount != otCount1.mRecvCount)
		//		throw RTE_LOC;
		//	std::array<std::vector<std::array<block, 2>>, 2> baseSend;
		//	baseSend[0].resize(otCount0.mSendCount);
		//	baseSend[1].resize(otCount1.mSendCount);
		//	std::array<std::vector<block>, 2> baseRecv;
		//	std::array<BitVector, 2> baseChoice;

		//	for (u64 i = 0; i < 2; ++i)
		//	{
		//		prng0.get(baseSend[i].data(), baseSend[i].size());
		//		baseRecv[1 ^ i].resize(baseSend[i].size());
		//		baseChoice[1 ^ i].resize(baseSend[i].size());
		//		baseChoice[1 ^ i].randomize(prng0);
		//		for (u64 j = 0; j < baseSend[i].size(); ++j)
		//		{
		//			baseRecv[1 ^ i][j] = baseSend[i][j][baseChoice[1 ^ i][j]];
		//		}
		//	}

		//	oles[0].setBaseOts(baseSend[0], baseRecv[0], baseChoice[0]);
		//	oles[1].setBaseOts(baseSend[1], baseRecv[1], baseChoice[1]);
		//}

		auto sock = coproto::LocalAsyncSocket::makePair();
		std::array<std::vector<block>, 2>
			A, B, C;
		for (u64 i = 0; i < 2; ++i)
		{
			A[i].resize(blocks);
			B[i].resize(blocks);
			C[i].resize(blocks);
		}

		if (verbose)
			oles[0].setTimer(timer);

		throw RTE_LOC;
		//auto r = macoro::sync_wait(macoro::when_all_ready(
		//	oles[0].expand(A[0], B[0], C[0], prng0, sock[0]),
		//	oles[1].expand(A[1], B[1], C[1], prng1, sock[1])));
		//std::get<0>(r).result();
		//std::get<1>(r).result();

		// Now we check that we got the correct OLE correlations and fail
		// the test otherwise.
		for (size_t i = 0; i < blocks; i++)
		{
			auto a = A[0][i] ^ A[1][i];
			auto b = B[0][i] ^ B[1][i];
			auto c = C[0][i] ^ C[1][i];
			if ((a & b) != c)
				throw RTE_LOC;
		}

		if (verbose)
			std::cout << "Time taken: \n" << timer << std::endl;
#else
		throw UnitTestSkipped("ENABLE_RINGLPN not defined.");
#endif
	}

	void RingLpn_GenBase_test(const CLP& cmd)
	{
#ifdef ENABLE_RINGLPN
		// This test checks the base OTs are generated correctly.
		using F = Fp<0xFFFFFFFB, u32, u64>;

		for (auto type : { SilentBaseType::Base, SilentBaseType::BaseExtend })
		{

			std::array<RingLpnTriple<F>, 2> oles;
			PRNG prng0(block(2424523452345, 111124521521455324));
			PRNG prng1(block(6474567454546, 567546754674345444));

			// insecure but makes the but makes the test run faster.
			oles[0].mPolyWeight = 3;
			oles[1].mPolyWeight = 3;

			u64 n = 1000;
			oles[0].init(0, n);
			oles[1].init(1, n);

			auto blocks = divCeil(n, 128);

			auto sock = coproto::LocalAsyncSocket::makePair();
			std::vector<block>
				ALsb(blocks),
				AMsb(blocks),
				BLsb(blocks),
				BMsb(blocks),
				C0Lsb(blocks),
				C0Msb(blocks),
				C1Lsb(blocks),
				C1Msb(blocks);

			// baseExtend is the default and will be called by expand.
			if (type == SilentBaseType::Base)
			{
				auto r = macoro::sync_wait(macoro::when_all_ready(
					oles[0].genBaseCors(prng0, sock[0]),
					oles[1].genBaseCors(prng1, sock[1])));
				std::get<0>(r).result();
				std::get<1>(r).result();
			}


			throw RTE_LOC;
			//auto r = macoro::sync_wait(macoro::when_all_ready(
			//	oles[0].expand(ALsb, AMsb, C0Lsb, C0Msb, prng0, sock[0]),
			//	oles[1].expand(BLsb, BMsb, C1Lsb, C1Msb, prng1, sock[1])));
			//std::exception_ptr ep;
			//try{
			//	std::get<0>(r).result();
			//}
			//catch (std::exception& e)
			//{
			//	std::cout << e.what() << std::endl;
			//	ep = std::current_exception();
			//}

			//std::get<1>(r).result();

			//if (ep)
			//	std::rethrow_exception(ep);

			// Now we check that we got the correct OLE correlations and fail
			// the test otherwise.
			for (size_t i = 0; i < blocks; i++)
			{
				auto Lsb = C0Lsb[i] ^ C1Lsb[i];
				auto Msb = C0Msb[i] ^ C1Msb[i];
				block mLsb, mMsb;
				throw RTE_LOC;
				//F4Multiply(
				//	ALsb[i], AMsb[i],
				//	BLsb[i], BMsb[i],
				//	mLsb, mMsb);

				if (Lsb != mLsb)
					throw RTE_LOC;
				if (Msb != mMsb)
					throw RTE_LOC;
			}
		}
#else
		throw UnitTestSkipped("ENABLE_RINGLPN not defined.");
#endif
	}

	void RingLpn_tensor_test(const CLP& cmd)
	{
#ifdef ENABLE_RINGLPN
		//using F = Fp<0xFFFFFFFB, u32, u64>;
		using F = Fp<17, u32, u32>;
		using Ctx = DefaultCoeffCtx_t<F>::type;
		Ctx ctx;

		std::array<RingLpnTriple<F>, 2> oles;

		PRNG prng(block(2424523452345, 111124521521455324));

		oles[0].init(0, 1000);
		oles[1].init(1, 1000);

		u64 n = oles[0].mNumPolys * oles[0].mPolyWeight;
		u64 n2 = n * n;
		auto sock = coproto::LocalAsyncSocket::makePair();
		std::array<std::vector<F>, 2> coeff, prod;
		coeff[0].resize(n);
		coeff[1].resize(n);
		prod[0].resize(n2);
		prod[1].resize(n2);

		{
			std::vector<F> c(n), a(n), b(n);

			F d = prng.get();
			for (auto& cc : c)
				cc = prng.get();

			DefaultBaseOT ot;
			auto recv = NoisyVoleReceiver<F, F, Ctx>::receive(c, a, prng, ot, sock[0], ctx);
			auto send = NoisyVoleSender<F, F, Ctx>::send(d, b, prng, ot, sock[1], ctx);
			auto r = macoro::sync_wait(macoro::when_all_ready(std::move(recv), std::move(send)));

			for (u64 i = 0; i < n; ++i)
			{
				//a = b + c * delta
				if (b[i] + c[i] * d != a[i])
				{
					std::cout << "c[" << i << "] = " << c[i] << std::endl;
					std::cout << "a[" << i << "] = " << a[i] << std::endl;
					std::cout << "b[" << i << "] = " << b[i] << std::endl;
					std::cout << "d = " << d << std::endl;
					throw RTE_LOC;
				}
			}
		}


		std::vector<std::array<block, 2>> sendOts(n * ctx.bitSize<F>());
		std::vector<block> recvOts(n * ctx.bitSize<F>());
		BitVector choice(n * ctx.bitSize<F>());
		for (u64 i = 0; i < sendOts.size(); ++i)
		{
			sendOts[i] = prng.get();
			choice[i] = prng.getBit();
			recvOts[i] = sendOts[i][choice[i]];
		}

		//auto r = macoro::sync_wait(macoro::when_all_ready(
		//	oles[0].tensorSend(coeff[0], prod[0], sock[0], prng, sendOts),
		//	oles[1].tensorRecv(coeff[1], prod[1], sock[1], prng, recvOts, choice)));

		auto r = macoro::sync_wait(macoro::when_all_ready(
			oles[0].tensorRecv(coeff[0], prod[0], sock[0], prng, recvOts, choice),
			oles[1].tensorSend(coeff[1], prod[1], sock[1], prng, sendOts)));
		std::get<0>(r).result();
		std::get<1>(r).result();

		// Now we check that we got the correct OLE correlations and fail
		// the test otherwise.
		for (size_t i = 0; i < n; i++)
		{
			for (size_t j = 0; j < n; j++)
			{
				auto p = j * n + i;
				auto ci = coeff[0][i];
				auto cj = coeff[1][j];
				auto exp = ci * cj;
				auto act = prod[0][p] + prod[1][p];
				if (exp != act)
				{
					std::cout << "i: " << i << ", j: " << j << std::endl;
					std::cout << "coeff[0][" << i << "] = " << ci << std::endl;
					std::cout << "coeff[1][" << j << "] = " << cj << std::endl;
					std::cout << "prod[0][" << p << "] = " << prod[0][p] << std::endl;
					std::cout << "prod[1][" << p << "] = " << prod[1][p] << std::endl;
					std::cout << "exp = " << exp << std::endl;
					std::cout << "act = " << act << std::endl;

					throw RTE_LOC;
				}
			}
		}
#else
		throw UnitTestSkipped("ENABLE_RINGLPN not defined.");
#endif
	}
}
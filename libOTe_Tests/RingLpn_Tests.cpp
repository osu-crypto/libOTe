
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
		{

			std::array<RingLpnTriple<F>, 2> oles;
			if (cmd.hasValue("t"))
				oles[0].mT = oles[1].mT = cmd.get<u64>("t");

			oles[0].mC = oles[1].mC = c;

			PRNG prng0(block(2424523452345, 111124521521455324));
			PRNG prng1(block(6474567454546, 567546754674345444));
			Timer timer;

			oles[0].init(0, n);
			oles[1].init(1, n);

			{
				auto otCount0 = oles[0].baseOtCount();
				auto otCount1 = oles[1].baseOtCount();
				if (otCount0.mRecvCount != otCount1.mSendCount ||
					otCount0.mSendCount != otCount1.mRecvCount)
					throw RTE_LOC;
				std::array<std::vector<std::array<block, 2>>, 2> baseSend;
				baseSend[0].resize(otCount0.mSendCount);
				baseSend[1].resize(otCount1.mSendCount);
				std::array<std::vector<block>, 2> baseRecv;
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

				oles[0].setBaseOts(baseSend[0], baseRecv[0], baseChoice[0]);
				oles[1].setBaseOts(baseSend[1], baseRecv[1], baseChoice[1]);
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
			oles[0].mT = oles[1].mT = cmd.get<u64>("t");

		PRNG prng0(block(2424523452345, 111124521521455324));
		PRNG prng1(block(6474567454546, 567546754674345444));
		Timer timer;

		oles[0].init(0, n);
		oles[1].init(1, n);

		{
			auto otCount0 = oles[0].baseOtCount();
			auto otCount1 = oles[1].baseOtCount();
			if (otCount0.mRecvCount != otCount1.mSendCount ||
				otCount0.mSendCount != otCount1.mRecvCount)
				throw RTE_LOC;
			std::array<std::vector<std::array<block, 2>>, 2> baseSend;
			baseSend[0].resize(otCount0.mSendCount);
			baseSend[1].resize(otCount1.mSendCount);
			std::array<std::vector<block>, 2> baseRecv;
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

			oles[0].setBaseOts(baseSend[0], baseRecv[0], baseChoice[0]);
			oles[1].setBaseOts(baseSend[1], baseRecv[1], baseChoice[1]);
		}

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
			oles[0].mT = 3;
			oles[1].mT = 3;

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
					oles[0].genBaseOts(prng0, sock[0], type),
					oles[1].genBaseOts(prng1, sock[1], type)));
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
		using F = Fp<0xFFFFFFFB, u32, u64>;

		std::array<RingLpnTriple<F>, 2> oles;

		PRNG prng0(block(2424523452345, 111124521521455324));
		PRNG prng1(block(6474567454546, 567546754674345444));

		oles[0].init(0, 1000);
		oles[1].init(1, 1000);

		u64 n = oles[0].mC * oles[0].mT;
		u64 n2 = n * n;
		auto sock = coproto::LocalAsyncSocket::makePair();
		std::array<std::vector<F>, 2> coeff, prod;
		coeff[0].resize(n);
		coeff[1].resize(n);
		prod[0].resize(n2);
		prod[1].resize(n2);

		oles[1].mSendOts.resize(2 * n);
		oles[0].mRecvOts.resize(2 * n);
		oles[0].mChoiceOts.resize(2 * n);
		for (u64 i = 0; i < 2 * n; ++i)
		{
			oles[1].mSendOts[i] = prng0.get();;
			oles[0].mChoiceOts[i] = prng0.getBit();
			oles[0].mRecvOts[i] = oles[1].mSendOts[i][oles[0].mChoiceOts[i]];
		}
		auto r = macoro::sync_wait(macoro::when_all_ready(
			oles[0].tensor(coeff[0], prod[0], sock[0]),
			oles[1].tensor(coeff[1], prod[1], sock[1])));
		std::get<0>(r).result();
		std::get<1>(r).result();

		// Now we check that we got the correct OLE correlations and fail
		// the test otherwise.
		for (size_t i = 0; i < n; i++)
		{
			for (size_t j = 0; j < n; j++)
			{
				auto p = i * n + j;

				auto ci = coeff[0][i];
				auto cj = coeff[1][j];
				auto exp = ci * cj;
				auto act = prod[0][p] + prod[1][p];
				if (exp != act)
					throw RTE_LOC;
			}
		}
#else
		throw UnitTestSkipped("ENABLE_RINGLPN not defined.");
#endif
	}
}

#include "Ntt_Tests.h"
#include "libOTe/Tools/Ntt/NttNegWrapMatrix.h"
#include "libOTe/Tools/Ntt/NttNegWrap.h"
#include "libOTe/Tools/Field/Fp.h"
#include "libOTe/Tools/Field/Goldilocks.h"
#include "libOTe/Tools/Ntt/Poly.h"
#include "cryptoTools/Common/TestCollection.h"

using namespace oc;

namespace tests_libOTe
{

	void Ntt_nttNegWrapMatrix_normal_Test()
	{
		//using F = F12289;
		//u64 n = 1024;
		//F psi = 12282;
		using F = F7681;
		//u64 n = 4;
		//F psi = 1925;
		u64 n = 8;
		bool verbose = false;
		PRNG prng(CCBlock);
		auto g = findGenerator<F>(prng);
		auto psi = primRootOfUnity(2 * n, g);

		if (isPrimRootOfUnity<F>(2 * n, psi) == false)
		{
			std::cout << "psi is not a primitive (2n)-root of unity for n = " << n << std::endl;
			throw RTE_LOC;
		}

		for (NttOrder order : {NttOrder::NormalOrder, NttOrder::BitReversedOrder})
		{


			// the modulus polynomial is x^n + 1
			Poly<F> mod(n, F(1));
			mod[n] = F(1);
			mod[0] = F(1);

			// x^{n-1}
			Poly<F> a(n - 1, F(1)), aHat(n - 1, F(1));
			Poly<F> b(n - 1, F(1)), bHat(n - 1, F(1));
			Poly<F> c(n - 1, F(1)), cHat(n - 1, F(1));

			nttNegWrapMatrix<F>(aHat, a, psi, order, verbose);
			nttNegWrapMatrix<F>(bHat, a, psi, order);
			hadamarProd<F>(cHat, aHat, bHat);
			inttNegWrapMatrix<F>(c, cHat, psi, order);
			c.compact();

			auto exp = (a * b) % mod;

			if (c != exp)
			{
				std::cout << "exp " << exp << std::endl;
				std::cout << "act " << c << std::endl;
				//for (u64 i = 0; i < c.size(); ++i)
				//{
				//    std::cout << i << " " << c[i] << " " << exp.getCoeff(i) << (c[i] != exp.getCoeff(i) ? " <<<<<<" : "") << std::endl;
				//}
				throw RTE_LOC;
			}
		}
	}

	template<typename F>
	void Ntt_nttNegWrapMatrix_Test_impl()
	{

		u64 n = 128;
		PRNG prng(CCBlock);
		auto psi = primRootOfUnity<F>(2 * n);
		//std::cout << "phi " << psi << std::endl;

		if (isPrimRootOfUnity<F>(2 * n, psi) == false)
		{
			std::cout << "psi is not a primitive (2n)-root of unity for n = " << n << std::endl;
			throw RTE_LOC;
		}

		for (NttOrder order : { NttOrder::NormalOrder, NttOrder::BitReversedOrder})
		{

			// the modulus polynomial is x^n + 1
			Poly<F> mod(n, F(1));
			mod[n] = F(1);
			mod[0] = F(1);

			// x^{n-1}
			Poly<F> a(n - 1, F(1)), a2(n - 1, F(1)), aHat(n - 1, F(1)), aHat2(n - 1, F(1));
			Poly<F> b(n - 1, F(1)), bHat(n - 1, F(1)), bHat2(n - 1, F(1));
			Poly<F> c1(n - 1, F(1)), c1Hat(n - 1, F(1));
			Poly<F> c2(n - 1, F(1)), c2Hat(n - 1, F(1));
			
			std::vector<F> psiPowers(2 * n);
			nttPrecomputeRootsOfUnity<F>(psi, psiPowers);
			std::vector<F> negWRapPowers = getNegWrapRoots<F>(psiPowers, n);
			//for (u64 i = 0; i < psiPowers.size(); ++i)
			//{
			//	psiPowers[i] = psi.pow(i);
			//}
			for (u64 i = 0; i < a.size(); ++i)
				a[i] = F(i);

			b = prng.get();

			c1 = (a * b) % mod;

			//std::cout << "\n matrix:\n";
			nttNegWrapMatrix<F>(aHat, a, psi, order);
			//std::cout << "\n recurive:\n";
			nttNegWrapCt<F>(aHat2, a, psi, order);
			//ntt_negacyclic_recursive_bitrev<F>(aHat2, a, psi);
			// check that the niave and efficent methods give the 
			// same result.
			if (aHat != aHat2)
			{
				for (u64 i = 0; i < aHat.size(); ++i)
				{
					std::cout << i << " " << aHat[i] << " " << aHat2[i] << (aHat[i] != aHat2[i] ? " <<<<<<" : "") << std::endl;
				}
				throw RTE_LOC;
			}

			//std::cout << "\n inplace:\n";

			auto aa = a;
			nttNegWrapCt<F>(aa, negWRapPowers, order);
			if (aa != aHat)
			{
				std::cout << "aHat " << aHat << std::endl;
				std::cout << "aa   " << aa << std::endl;
				throw RTE_LOC;
			}
			continue;

			//nttNegWrapMatrix<F>(bHat, b, psi, order);
			//nttNegWrapCt<F>(bHat2, b, psi, order);
			//if (bHat != bHat2)
			//	throw RTE_LOC;

			//// apply the NTT to c1.
			//nttNegWrapMatrix<F>(c1Hat, c1, psi, order);
			//c1Hat.compact();

			//// compute the componetwise multplication of aHat and bHat
			//hadamarProd<F>(c2Hat, aHat, bHat);

			//c1Hat.compact();
			//c2Hat.compact();
			//// check that we get the same evaluations.
			//if (c1Hat != c2Hat)
			//{
			//	std::cout << c1Hat << std::endl;
			//	std::cout << c2Hat << std::endl;

			//	throw RTE_LOC;
			//}

			//// convert back
			//inttNegWrapMatrix<F>(a2, aHat, psi, order);

			//if (a != a2)
			//	throw RTE_LOC;
		}
		//inttNegWrapGs<F>(a2, aHat, psi, order);
	}

	void Ntt_nttNegWrapMatrix_Test()
	{
		//using F = F12289;
		//u64 n = 1024;
		//F psi = 12282;
		//using F = F7681;
		//u64 n = 4;
		//F psi = 1925;
		Ntt_nttNegWrapMatrix_Test_impl<F7681>();
		Ntt_nttNegWrapMatrix_Test_impl<F12289>();
		Ntt_nttNegWrapMatrix_Test_impl<Goldilocks>();
	}




	void Ntt_bitReverse_SIMD_Test()
	{
#if !defined(OC_ENABLE_SSE2)
		throw UnitTestSkipped("OC_ENABLE_SSE2 not defined.");
#else
		// Validate SIMD bit-reversal (bitrev_k_4_ssse3) against scalar bitReversal
		// for multiple bit-widths and a representative set of inputs.
		for (int k = 1; k <= 32; ++k)
		{
			// Keep runtime small: exhaustive for small k, sample for larger k.
			uint64_t maxCount;
			if (k <= 12)
				maxCount = 1ull << k;          // full coverage
			else
				maxCount = 1ull << 12;         // sample 4096 values

			// Drive j through a sequence to get coverage without PRNG deps.
			uint32_t j = 0;
			for (uint64_t i = 0; i < maxCount; i += 4)
			{
				// Pack 4 consecutive ints
				__m128i j4 = _mm_set_epi32(j + 3, j + 2, j + 1, j);
				__m128i r4 = oc::bitrev_k_4_ssse3(j4, k);

				alignas(16) uint32_t got[4];
				_mm_store_si128((__m128i*)got, r4);

				for (int lane = 0; lane < 4; ++lane)
				{
					uint32_t x = j + lane;
					// For k <= 31, limit x to [0, 2^k) for exhaustive passes
					if (k <= 12 && x >= (1u << k))
						continue;

					auto exp = oc::bitReversal(k, x);
					if (got[lane] != exp)
					{
						std::cout << "bitrev mismatch: k=" << k
							<< " x=" << x
							<< " simd=" << got[lane]
							<< " scalar=" << exp << std::endl;
						throw RTE_LOC;
					}
				}
				j += 4;
			}
		}
#endif
	}
}
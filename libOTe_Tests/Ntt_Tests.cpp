
#include "Ntt_Tests.h"
#include "libOTe/Tools/NTT/NttNegWrapMatrix.h"
#include "libOTe/Tools/NTT/NttNegWrap.h"
#include "libOTe/Tools/Field/FP.h"
#include "libOTe/Tools/NTT/Poly.h"

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
			Poly<F> mod(n, 1);
			mod[n] = 1;
			mod[0] = 1;

			// x^{n-1}
			Poly<F> a(n - 1, 1), aHat(n - 1, 1);
			Poly<F> b(n - 1, 1), bHat(n - 1, 1);
			Poly<F> c(n - 1, 1), cHat(n - 1, 1);

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


	void Ntt_nttNegWrapMatrix_Test()
	{
		//using F = F12289;
		//u64 n = 1024;
		//F psi = 12282;
		using F = F7681;
		//u64 n = 4;
		//F psi = 1925;
		u64 n = 8;
		PRNG prng(CCBlock);
		auto g = findGenerator<F>(prng);
		auto psi = primRootOfUnity(2 * n, g);
		std::cout << "phi " << psi << std::endl;

		if (isPrimRootOfUnity<F>(2 * n, psi) == false)
		{
			std::cout << "psi is not a primitive (2n)-root of unity for n = " << n << std::endl;
			throw RTE_LOC;
		}

		for (NttOrder order : { /*NttOrder::NormalOrder,*/ NttOrder::BitReversedOrder})
		{

			// the modulus polynomial is x^n + 1
			Poly<F> mod(n, 1);
			mod[n] = 1;
			mod[0] = 1;

			// x^{n-1}
			Poly<F> a(n - 1, 1), a2(n - 1, 1), aHat(n - 1, 1), aHat2(n - 1, 1);
			Poly<F> b(n - 1, 1), bHat(n - 1, 1), bHat2(n - 1, 1);
			Poly<F> c1(n - 1, 1), c1Hat(n - 1, 1);
			Poly<F> c2(n - 1, 1), c2Hat(n - 1, 1);

			a[0] = 1;
			a[1] = 2;
			a[2] = 3;
			a[3] = 4;
			b = prng.get();

			c1 = (a * b) % mod;

			std::cout << "\n matrix:\n";
			nttNegWrapMatrix<F>(aHat, a, psi, order);
			std::cout << "\n recurive:\n";
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


			nttNegWrapMatrix<F>(bHat, b, psi, order);
			nttNegWrapCt<F>(bHat2, b, psi, order);
			if (bHat != bHat2)
				throw RTE_LOC;

			// apply the NTT to c1.
			nttNegWrapMatrix<F>(c1Hat, c1, psi, order);
			c1Hat.compact();

			// compute the componetwise multplication of aHat and bHat
			hadamarProd<F>(c2Hat, aHat, bHat);

			c1Hat.compact();
			c2Hat.compact();
			// check that we get the same evaluations.
			if (c1Hat != c2Hat)
			{
				std::cout << c1Hat << std::endl;
				std::cout << c2Hat << std::endl;

				throw RTE_LOC;
			}

			// convert back
			inttNegWrapMatrix<F>(a2, aHat, psi, order);

			if (a != a2)
				throw RTE_LOC;
		}
		//inttNegWrapGs<F>(a2, aHat, psi, order);
	}

}
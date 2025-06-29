

#include "libOTe/Tools/Field/FP.h"
#include "libOTe/Tools/Field/GF128.h"
#include "libOTe/Tools/NTT/Poly.h"
#include "Field_Tests.h"
using namespace osuCrypto;
#include <vector>

namespace tests_libOTe
{

    template<typename F>
    void Field_Test()
    {
        PRNG prng(AllOneBlock);

        // Test basic field properties
        F a(prng.get()), b(prng.get());

        a = 1467;
        b = 2489;

        auto c = a + b;
        auto d = b + a;
        if (c != d)
            throw RTE_LOC;

        c = a - b;
        d = a + (-b);
        if (c != d)
            throw RTE_LOC;

        c = a * b;
        d = b * a;
        if (c != d)
            throw RTE_LOC;

        if (a != 0)
        {
            auto aInv = a.inverse();
            c = a * aInv;
            if (c != 1)
                throw RTE_LOC;
        }

        auto g = findGenerator<F>(prng);
		//std::cout << "Generator: " << g << std::endl;

        auto factors = uniqueFactor(F::order() - 1);

		// compute some valid n of the form  n = p1^e1 * p2^e2 * ... * pk^ek
		// where p1, p2, ..., pk are the prime factors of (p-1).
        std::vector<u64> ns;
        for (u64 i = 0; i < 10; ++i)
        {
            u64 n = 1;
            for (auto fe : factors)
            {
                auto e = (prng.get<u64>() % fe.mExp) + 1;
                u64 f = 1;
                for (u64 j = 0; j < e; ++j)
                    f *= fe.mFactor;
				//std::cout << fe.mFactor << "^" << e << " " << std::endl;
                n *=  f;
            }
            ns.push_back(n);
            //std::cout << "  " << n << std::endl;
        }

        for (auto n : ns)
        {
            auto unity = primRootOfUnity<F>(n, g);

            // Check that it is an n-th root of unity
            if (unity.pow(n) != 1)
                throw RTE_LOC;

            // Check that it is a primitive n-th root of unity
            if (!isPrimRootOfUnity(n, unity))
            {
				std::cout << unity << " is not a primitive root of unity for n = " << n << std::endl;
				std::cout << " (p-1) = " << (F::mMod-1) / n << " n + " << (F::mMod - 1) % n << std::endl;
                for(u64 i = 1; i < n; ++i)
                {
                    if (unity.pow(i) == 1)
                    {
                        std::cout << "It is a " << i << "-th root of unity." << std::endl;
                        break;
                    }
				}
                throw RTE_LOC;
            }
        }
    }

    
    void Field_F7681_Test()
    {
        Field_Test<F7681>();


        {
            using F32769 = Fp<32769, u16, u32>;
		    F32769 a(12345), b(67890);
            auto c = F32769::barrettMul(a, b);
            if(c.mVal != (12345 * 67890) % 32769)
            {
                std::cout << "p=32769 berrett multiplication failed: "
                    << c.mVal << " != " << (12345 * 67890 % 32769) << std::endl;
                throw RTE_LOC;
			}
        }
    }

    void Field_F12289_Test()
    {
		Field_Test<F12289>();
    }


    void Field_GF128_Test()
    {
        GF128 g;
    }

}
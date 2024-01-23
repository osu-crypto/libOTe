
#include "Ntt_Tests.h"
#include "libOTe/Tools/NTT/NttNegWrapMatrix.h"
#include "libOTe/Tools/NTT/NttNegWrap.h"
#include "libOTe/Tools/Field/FP.h"
#include "libOTe/Tools/NTT/Poly.h"

using namespace oc;

namespace tests_libOTe
{
    void Ntt_nttNegWrapMatrix_Test()
    {
        //using F = F12289;
        //u64 n = 1024;
        //F psi = 12282;
        using F = F7681;
        u64 n = 4;
        F psi = 1925;

        NttOrder order = NttOrder::BitReversedOrder;

        Poly<F> mod(n + 1);
        mod[n] = 1;
        mod[0] = 1;

        Poly<F> a(n), a2(n), aHat(n), aHat2(n);
        Poly<F> b(n), bHat(n), bHat2(n);
        Poly<F> c1(n), c1Hat(n);
        Poly<F> c2(n), c2Hat(n);

        PRNG prng(CCBlock);
        a[0] = 1;
        a[1] = 2;
        a[2] = 3;
        a[3] = 4;
        //a = prng.get();
        b = prng.get();

        c1 = (a * b) % mod;

        nttNegWrapMatrix<F>(aHat, a, psi, order);
        nttNegWrapMatrix<F>(bHat, b, psi, order);

        nttNegWrapCt<F>(aHat2, a, psi, order);
        nttNegWrapCt<F>(bHat2, b, psi, order);

        if (aHat != aHat2)
        {
            for (u64 i = 0; i < aHat.size(); ++i)
            {
                std::cout << i << " " << aHat[i] << " " << aHat2[i] << (aHat[i] != aHat2[i] ? " <<<<<<" : "") << std::endl;
            }
            throw RTE_LOC;
        }
        if (bHat != bHat2)
            throw RTE_LOC;

        //std::cout << "ahat " << aHat << std::endl;

        nttNegWrapMatrix<F>(c1Hat, c1, psi, order);

        hadamarProd<F>(c2Hat, aHat, bHat);


        if (c1Hat != c2Hat)
        {
            for (u64 i = 0; i < c1Hat.size(); ++i)
            {
                std::cout << i << " " << c1Hat[i] << " " << c2Hat[i] << (c1Hat[i] != c2Hat[i] ? " <<<<<<" : "") << std::endl;
            }
            throw RTE_LOC;
        }

        inttNegWrapMatrix<F>(a2, aHat, psi, order);

        if (a != a2)
            throw RTE_LOC;

        inttNegWrapGs<F>(a2, aHat, psi, order);
    }

}
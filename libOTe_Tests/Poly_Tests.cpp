#include "Poly_Tests.h"
#include "libOTe/Tools/NTT/Poly.h"
#include "libOTe/Tools/Field/FP.h"
#include "cryptoTools/Crypto/PRNG.h"

using namespace oc;

void tests_libOTe::Poly_basics_Tests()
{
    F12289 x;

    u64 n = 16;
    Poly<F12289> a, b, c, d;

    PRNG prng(CCBlock);
    a.setCoeff(n - 1, 1);
    b.setCoeff(n - 1, 1);
    c.setCoeff(n - 1, 1);
    d.setCoeff(n - 1, 1);
    for (u64 i = 0; i < n; ++i)
    {
        a[i] = prng.get();
        b[i] = prng.get();
        c[i] = prng.get();
        d[i] = prng.get();
    }

    auto ab = a + b;
    auto cd = c + d;
    auto ac = a * c;
    auto ad = a * d;
    auto bc = b * c;
    auto bd = b * d;

    auto abcd1 = ab * cd;
    auto abcd2 = ac + ad + bc + bd;

    if (abcd1 != abcd2)
        throw RTE_LOC;


    std::cout << "a " << a << std::endl;
    std::cout << "b " << b << std::endl;
    std::cout << "c " << c << std::endl;
    std::cout << "d " << d << std::endl;
    std::cout << "abcd " << abcd1 << std::endl;


    auto abcd_ar = abcd1 % a;
    auto abcd_ad = abcd1 / a;
    abcd2 = a * abcd_ad + abcd_ar;
    if (abcd1 != abcd2)
        throw RTE_LOC;
}

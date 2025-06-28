#include "Poly_Tests.h"
#include "libOTe/Tools/NTT/Poly.h"
#include "libOTe/Tools/Field/FP.h"
#include "cryptoTools/Crypto/PRNG.h"

using namespace oc;

namespace tests_libOTe
{
    void Poly_basics_Tests()
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


        //std::cout << "a " << a << std::endl;
        //std::cout << "b " << b << std::endl;
        //std::cout << "c " << c << std::endl;
        //std::cout << "d " << d << std::endl;
        //std::cout << "abcd " << abcd1 << std::endl;


        auto abcd_ar = abcd1 % a;
        auto abcd_ad = abcd1 / a;
        abcd2 = a * abcd_ad + abcd_ar;
        if (abcd1 != abcd2)
            throw RTE_LOC;


    }




    // Helper function to evaluate a polynomial at a point using Horner's method.
    template<typename Field>
    Field eval(const Poly<Field>& p, const Field& x)
    {
        if (p.isZero())
            return Field(0);

        Field y = p[0];
        for (u64 i = 1; i < p.size(); ++i)
            y += p[i] * x.pow(i);
        //for (i64 i = p.degree(); i >= 0; --i)
        //{
        //    y = y * x + p[i];
        //}
        return y;
    }

    // Test polynomial evaluation and roots.
    void Poly_eval_root_test()
    {
        using Field = F12289;
        PRNG prng(CCBlock);

        // We construct a polynomial p(x) with a known root r, as in p(x) = q(x) * (x-r).
        // We then check that p(r) == 0 and p(x) % (x-r) == 0.
        Poly<Field> q;
        while (q.isZero())
            q.setCoeff(5, prng.get());
        for (u64 i = 0; i < q.degree(); ++i)
            q[i] = prng.get();

        Field r = prng.get();
        Poly<Field> xr;
        xr.setCoeff(1, 1);
        xr.setCoeff(0, -r);

        auto negR = -r;
        if (r + negR != 0)
            throw RTE_LOC;

        auto xr_at_r = eval(xr, r);
        if (xr_at_r != 0)
            throw RTE_LOC;

        auto p = q * xr;
        auto p_at_r = eval(p, r);

        if (p_at_r != 0)
            throw RTE_LOC;

        auto rem = p % xr;
        if (!rem.isZero())
            throw RTE_LOC;

        // Now, test with a non-zero remainder.
        // p(x) = q(x) * (x-r) + rem, so p(r) should equal the remainder.
        Field remConst = prng.get();
        p = p + remConst;

        p_at_r = eval(p, r);
        if (p_at_r != remConst)
            throw RTE_LOC;

        rem = p % xr;
        if (rem.degree() != 0 || rem[0] != remConst)
            throw RTE_LOC;
    }

    // Test scalar multiplication and division.
    void Poly_scalar_test()
    {
        using Field = F12289;
        PRNG prng(CCBlock);

        Poly<Field> p;
        while (p == 0)
            p.setCoeff(4, prng.get());

        for (u64 i = 0; i < p.degree(); ++i)
            p[i] = prng.get();

        Field s = prng.get();
        while (s == 0)
            s = prng.get();

        // Test p * s
        Poly<Field> ps = p * s;
        if (ps.degree() != p.degree())
            throw RTE_LOC;

        for (u64 i = 0; i <= p.degree(); ++i)
        {
            if (ps[i] != p[i] * s)
                throw RTE_LOC;
        }

        // Test ps / s
        Poly<Field> p_div_s = ps / s;
        if (p_div_s != p)
            throw RTE_LOC;

        // Test p * 0
        Poly<Field> zero_p = p * Field(0);
        if (!zero_p.isZero())
            throw RTE_LOC;
    }
}
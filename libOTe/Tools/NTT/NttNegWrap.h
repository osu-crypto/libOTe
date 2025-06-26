#pragma once
#include "cryptoTools/Common/Defines.h"
#include <vector>
#include "NttOrder.h"

namespace osuCrypto
{


    // ntt negative-wrapping using the fast COOLEY-TUKEY NTT algo.
    // This will perform an ntt with respect to modulus
    // (x^n +1)
    // 
    // O(n log n) time.
    // a are the coeffs,
    // aHat are the evaluations
    // psi is the 2n-th root of unity.
    template<typename F>
    void nttNegWrapCt(
        span<F> aHat,
        span<const F> a,
        const F& psi,
        NttOrder order)
    {
        auto n = a.size();
        auto ln = log2ceil(n);
        auto qq = F::order() - 1;

        if (n != 1ull << ln)
            throw RTE_LOC;
        if (n > qq)
            throw RTE_LOC;
        if (qq % n != 0)
            throw RTE_LOC;
        if (psi.pow(2 * n) != 1)
            throw RTE_LOC;

        if (n == 1)
        {
            aHat[0] = a[0];
            return;
        }

        std::vector<F> A(n / 2), B(n / 2);

        for (u64 i = 0; i < A.size(); ++i)
        {
            A[i] = a[2 * i + 0];
            B[i] = a[2 * i + 1];
        }

        std::vector<F> AHat(n / 2), BHat(n / 2);
        auto psi2 = psi * psi;
        nttNegWrapCt<F>(AHat, A, psi2, NttOrder::BitReversedOrder);
        nttNegWrapCt<F>(BHat, B, psi2, NttOrder::BitReversedOrder);

        if (order == NttOrder::BitReversedOrder)
        {
            for (u64 i = 0; i < A.size(); ++i)
            {
                auto psiB = psi.pow(2 * i + 1) * BHat[i];
                aHat[2 * i + 0] = AHat[i] + psiB;
                aHat[2 * i + 1] = AHat[i] - psiB;
            }
        }
        else
        {
            for (u64 i = 0; i < A.size(); ++i)
            {
                auto psiB = psi.pow(2 * i + 1) * BHat[i];

                auto d = 2 * i;
                u64 idx0 = bitReveral(ln, d);
                u64 idx1 = bitReveral(ln, d + 1);


                aHat[idx0] = AHat[i] + psiB;
                aHat[idx1] = AHat[i] - psiB;
            }
        }
    }



    // inverse ntt negative-wrapping using the fast GENTLEMAN-SANDE  NTT algo.
    // This will perform an ntt with respect to modulus
    // (x^n +1)
    // 
    // O(n log n) time.
    // a are the coeffs,
    // aHat are the evaluations
    // psi is the 2n-th root of unity.
    template<typename F>
    void inttNegWrapGs(
        span<F> a,
        span<const F> aHat,
        const F& psi,
        NttOrder order)
    {
        auto n = a.size();
        auto ln = log2ceil(n);
        auto qq = F::order() - 1;

        if (n != 1ull << ln)
            throw RTE_LOC;
        if (n > qq)
            throw RTE_LOC;
        if (qq % n != 0)
            throw RTE_LOC;
        if (psi.pow(2 * n) != 1)
            throw RTE_LOC;

        if (order != NttOrder::BitReversedOrder)
            throw RTE_LOC;

        if (n == 1)
        {
            a[0] = aHat[0];
            return;
        }

        span<const F>
            AHat = aHat.subspan(0, n / 2),
            BHat = aHat.subspan(n / 2);

        std::vector<F> A(n / 2), B(n / 2);
        auto psi2 = psi * psi;
        inttNegWrapGs<F>(A, AHat, psi2, NttOrder::BitReversedOrder);
        inttNegWrapGs<F>(B, BHat, psi2, NttOrder::BitReversedOrder);

        for (u64 i = 0; i < A.size(); ++i)
        {
            auto psi2i = psi.pow(2 * n - 2 * i);

            a[2 * i + 0] = (A[i] + B[i]) * psi2i;
            a[2 * i + 1] = (A[i] - B[i]) * psi2i;
        }
    }


}
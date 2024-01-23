#pragma once
#include "cryptoTools/Common/Defines.h"
#include <vector>
#include "NttOrder.h"

namespace osuCrypto
{


    // ntt negative-wrapping using the full matrix.
    // This will perform an ntt with respect to modulus
    // (x^n +1)
    // 
    // O(n^2) time.
    // a are the coeffs,
    // aHat are the evaluations
    // psi is the 2n-th root of unity.
    // order is the desired output order
    template<typename F>
    void nttNegWrapMatrix(
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

        std::vector<F> powers(2 * n);

        for (u64 i = 0; i < powers.size(); ++i)
        {
            powers[i] = psi.pow(i);
            //std::cout << "psi^" << i << " " << powers[i] << std::endl;
            if (i && powers[i] == 1)
                throw RTE_LOC;
        }


        for (u64 i = 0; i < n; ++i)
        {

            u64 idx = (order == NttOrder::NormalOrder) ?
                i : bitReveral(ln, i);

            auto& ai = aHat[idx];
            ai = 0;
            //std::cout << "aHat[" << i << "] = ";
            for (u64 j = 0; j < n; ++j)
            {
                auto idx = (2 * i * j + j) % powers.size();
                //std::cout << "psi^" << idx << " ";
                ai += powers[idx] * a[j];
            }
            //std::cout << std::endl;
        }
    }

    // inverse ntt negative-wrapping using the full matrix.
    // This will perform an ntt with respect to modulus
    // (x^n +1)
    // 
    // O(n^2) time.
    // a are the coeffs,
    // aHat are the evaluations
    // psi is the 2n-th root of unity.
    // order is the input order
    template<typename F>
    void inttNegWrapMatrix(
        span<F> a,
        span<const F> aHat_,
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


        span<const F> aHat;
        std::vector<F> temp;

        if (order == NttOrder::NormalOrder)
        {
            aHat = aHat_;
        }
        else
        {
            temp.resize(aHat_.size());
            for (u64 i = 0; i < aHat_.size(); ++i)
                temp[i] = aHat_[bitReveral(ln, i)];
            aHat = temp;
        }
        
        auto psiInv = psi.inverse();
        std::vector<F> powers(2 * n);
        for (u64 i = 0; i < powers.size(); ++i)
        {
            powers[i] = psiInv.pow(i);
            if (i && powers[i] == 1)
                throw RTE_LOC;
        }

        for (u64 i = 0; i < n; ++i)
        {
            auto& ai = a[i];
            ai = 0;
            for (u64 j = 0; j < n; ++j)
            {
                auto idx = (2 * j * i + i) % powers.size();
                //std::cout << "psi^" << idx << " ";
                ai += powers[idx] * aHat[j];
            }
            //std::cout << std::endl;
        }

        auto nInv = F(a.size()).inverse();
        for (u64 i = 0; i < a.size(); ++i)
        {
            a[i] *= nInv;
        }
    }
}
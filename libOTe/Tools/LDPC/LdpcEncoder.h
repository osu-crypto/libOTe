#pragma once
#include "Mtx.h"

namespace osuCrypto
{

    class DiagInverter
    {
    public:

        const SparseMtx* mC = nullptr;

        DiagInverter() = default;
        DiagInverter(const DiagInverter&) = default;
        DiagInverter& operator=(const DiagInverter&) = default;

        DiagInverter(const SparseMtx& c)
        {
            init(c);
        }
        void init(const SparseMtx& c)
        {
            mC = (&c);
            assert(mC->rows() == mC->cols());

#ifndef NDEBUG
            for (u64 i = 0; i < mC->rows(); ++i)
            {
                auto row = mC->row(i);
                assert(row.size() && row[row.size() - 1] == i);

                for (u64 j = 0; j < row.size() - 1; ++j)
                {
                    assert(row[j] < row[j + 1]);
                }
            }
#endif
        }


        // computes x = mC^-1 * y
        void mult(span<const u8> y, span<u8> x);


        template<typename T>
        void cirTransMult(span<T> x)
        {
            // solves for x such that y = M x, ie x := H^-1 y 
            assert(mC);
            assert(mC->cols() == x.size());
            for (u64 i = mC->rows() - 1; i != ~u64(0); --i)
            {
                auto row = mC->row(i);
                for (u64 j = 0; j < row.size() - 1; ++j)
                {
                    auto col = row[j];
                    x[col] ^= x[i];
                }
            }
        }


        // computes x = mC^-1 * y
        void mult(const SparseMtx& y, SparseMtx& x);

    };

    class LdpcEncoder
    {
    public:

        //using SparseMtx = std::vector<std::array<u64, 2>>;

        LdpcEncoder() = default;
        LdpcEncoder(const LdpcEncoder&) = default;
        LdpcEncoder(LdpcEncoder&&) = default;


        u64 mN, mM, mGap;
        SparseMtx mA, mH;
        SparseMtx mB;
        SparseMtx mC;
        SparseMtx mD;
        SparseMtx mE, mEp;
        SparseMtx mF;
        DiagInverter mCInv;


        bool init(SparseMtx mtx, u64 gap);


        void encode(span<u8> c, span<const u8> m);

        template<typename T>
        void cirTransEncode(span<T> c)
        {
            if (mGap)
                throw std::runtime_error(LOCATION);
            auto k = mN - mM;
            span<u8> pp(c.subspan(k, mM));

            mCInv.cirTransMult(pp);

            for (u64 i = 0; i < k; ++i)
            {
                for (auto row : mA.col(i))
                {
                    c[i] ^= pp[row];
                }
            }
        }

    };


    namespace tests
    {

        void LdpcEncoder_diagonalSolver_test();
        void LdpcEncoder_encode_test();
        void LdpcEncoder_encode_g0_test();
        void LdpcEncoder_encode_Trans_g0_test();

    }

}
#pragma once
#include "Mtx.h"
#include "cryptoTools/Crypto/PRNG.h"

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


        std::vector<SparseMtx> getSteps()
        {
            std::vector<SparseMtx> steps;

            u64 n = mC->cols();
            u64 nn = mC->cols() * 2;

            for (u64 i = 0; i < mC->rows(); ++i)
            {
                auto row = mC->row(i);
                std::vector<Point> points;

                points.push_back({ i, n + i });
                assert(row[row.size() - 1] == i);
                for (u64 j = 0; j < row.size() - 1; ++j)
                {
                    points.push_back({ i,row[j] });
                }


                for (u64 j = 0; j < i; ++j)
                {
                    points.push_back({ j,j });
                }

                for (u64 j = 0; j < n; ++j)
                {
                    points.push_back({ n + j, n + j });
                }
                steps.emplace_back(nn, nn, points);

            }

            return steps;
        }

        // computes x = mC^-1 * y
        void mult(span<const u8> y, span<u8> x)
        {
            // solves for x such that y = M x, ie x := H^-1 y 
            assert(mC);
            assert(mC->rows() == y.size());
            assert(mC->cols() == x.size());

            //u64 n = mC->cols();
            //u64 nn = mC->cols() * 2;

            //std::vector<u8> xx(n);

            //std::vector<u8> combined;
            //combined.insert(combined.end(), xx.begin(), xx.end());
            //combined.insert(combined.end(), y.begin(), y.end());

            //auto steps = getSteps();

            for (u64 i = 0; i < mC->rows(); ++i)
            {
                auto row = mC->row(i);
                x[i] = y[i];

                assert(row[row.size() - 1] == i);
                for (u64 j = 0; j < row.size() - 1; ++j)
                {
                    x[i] ^= x[row[j]];
                }


                //combined = steps[i] * combined;
                //std::cout << "x  ";
                //for (u64 j = 0; j < n; ++j)
                //    std::cout << int(xx[j]) << " ";

                //std::cout << "\nx' ";
                //for (u64 j = 0; j < n; ++j)
                //    std::cout << int(combined[j]) << " ";
                //std::cout << "\ny  ";
                //for (u64 j = 0; j < n; ++j)
                //    std::cout << int(y[j]) << " ";

                //std::cout << "\ny' ";
                //for (u64 j = 0; j < n; ++j)
                //    std::cout << int(combined[j+n]) << " ";
                //std::cout << std::endl;

                //for (u64 j = 0; j < n; ++j)
                //{
                //    assert(xx[j] == combined[j]);
                //    assert(y[j] == combined[j+n]);
                //}
            }

            //std::copy(xx.begin(), xx.end(), x.begin());
        }


        //void cirTransMult(span<u8> x, span<u8> y)
        //{
        //    // solves for x such that y = M x, ie x := H^-1 y 
        //    assert(mC);
        //    assert(mC->cols() == x.size());


        //    for (u64 i = mC->rows() - 1; i != ~u64(0); --i)
        //    {
        //        auto row = mC->row(i);
        //        assert(row[row.size() - 1] == i);
        //        for (u64 j = 0; j < row.size() - 1; ++j)
        //        {
        //            auto col = row[j];
        //            assert(col < i);

        //            x[col] = x[col] ^ x[i];
        //        }

        //    }
        //}


        template<typename T>
        void cirTransMult(span<T> x, span<T> y)
        {
            // solves for x such that y = M x, ie x := H^-1 y 
            assert(mC);
            assert(mC->cols() == x.size());

            for (u64 i = mC->rows() - 1; i != ~u64(0); --i)
            {
                auto row = mC->row(i);
                assert(row[row.size() - 1] == i);
                for (u64 j = 0; j < row.size() - 1; ++j)
                {
                    auto col = row[j];
                    assert(col < i);

                    x[col] = x[col] ^ x[i];
                }
            }
        }


        // computes x = mC^-1 * y
        void mult(const SparseMtx& y, SparseMtx& x);

    };

    //inline int fff(u8 x)
    //{
    //    return x;
    //}

    //inline int fff(block x)
    //{
    //    return 0;
    //}

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
            assert(c.size() == mN);

            auto k = mN - mM;
            span<T> pp(c.subspan(k, mM));
            span<T> mm(c.subspan(0, k));

            //std::cout << "P  ";
            //for (u64 i = 0; i < pp.size(); ++i)
            //    std::cout << fff(pp[i]) << " ";
            //std::cout << std::endl;

            mCInv.cirTransMult(pp, mm);

            //std::cout << "P' ";
            //for (u64 i = 0; i < pp.size(); ++i)
            //    std::cout << fff(pp[i]) << " ";
            //std::cout << std::endl;

            for (u64 i = 0; i < k; ++i)
            {
                for (auto row : mA.col(i))
                {
                    c[i] = c[i] ^ pp[row];
                }


            }

            //std::cout << "m  ";
            //for (u64 i = 0; i < k; ++i)
            //    std::cout << fff(c[i]) << " ";
            //std::cout << std::endl;
        }

    };
    bool isPrime(u64 n);
    inline u64 mod(u64 x, u64 p)
    {
        if (x >= p)
        {
            x -= p;

            if (x >= p)
            {
                auto y = x / p;
                x -= y * p;
            }
        }

        return x;

    }

    class LdpcZpStarEncoder
    {
    public:
        u64 mRows, mWeight;
        u64 mP, mY;
        void init(u64 rows, u64 weight);

        u64 mod(u64 x)
        {
            return ::oc::mod(x, mP);
        }

        std::vector<u64> getVals();

        void encode(span<u8> pp, span<const u8> m);


        template<typename T>
        void cirTransEncode(span<T> pp, span<const T> m)
        {
            auto cols = mRows;
            assert(pp.size() == mRows);
            assert(m.size() == cols);

            // pp = m * A

            auto v = getVals();

            for (u64 i = 0; i < cols; ++i)
            {
                for (u64 j = 0; j < mWeight; ++j)
                {
                    auto row = v[j];

                    assert(row != mY);
                    assert(row < mP);

                    if (row > mY)
                        --row;

                    pp[i] ^= m[row];

                    v[j] = mod(v[j] + j + 1);
                }
            }
        }


        u64 cols() {
            return mRows;
        }

        void getPoints(std::vector<Point>& points)
        {
            auto cols = mRows;
            auto v = getVals();

            for (u64 i = 0; i < cols; ++i)
            {
                for (u64 j = 0; j < mWeight; ++j)
                {
                    auto row = v[j];

                    assert(row != mY);
                    assert(row < mP);

                    if (row > mY)
                        --row;

                    points.push_back({ row, i });

                    v[j] = mod(v[j] + j + 1);
                }
            }
        }

        SparseMtx getMatrix()
        {
            std::vector<Point> points;
            getPoints(points);
            return SparseMtx(mRows, mRows, points);
        }
    };

    class LdpcDiagBandEncoder
    {
    public:
        u64 mGap, mCols, mRows;
        u64 mGapWeight;
        std::vector<u64> mOffsets;
        Matrix<u8> mRandColumns;
        Matrix<u8> mRandRows;
        bool mExtend;

        void init(
            u64 rows,
            u64 gap,
            u64 gapWeight,
            std::vector<u64> lowerBandOffsets,
            bool extend,
            PRNG& prng)
        {
            assert(gap < rows);
            assert(gapWeight >= 1);
            assert(gapWeight - 1 <= gap);

            assert(gap < 255);

            mRows = rows;
            mGap = gap;
            mGapWeight = gapWeight;
            mOffsets = lowerBandOffsets;
            mExtend = extend;

            if (extend)
                mCols = rows;
            else
                mCols = rows - mGap;

            mRandColumns.resize(mRows - mGap, mGapWeight - 1, AllocType::Uninitialized);
            mRandRows.resize(rows, gap + 1);

            auto rr = mRandColumns.rows();
            auto ww = mRandColumns.cols();
            for (u64 i = 0; i < rr; ++i)
            {
                for (i64 j = 0; j < ww; ++j)
                {
                restart:

                    auto r = prng.get<u8>() % mGap;// +(i + 1);
                    for (u64 k = 0; k < j; ++k)
                    {
                        if (r == mRandColumns(i, k))
                        {
                            goto restart;
                        }
                    }
                    mRandColumns(i, j) = r;

                    u64 rr = r + i + 1;
                    auto& rowSize = mRandRows(rr, gap);

                    assert(rowSize != gap);

                    mRandRows(rr, rowSize) = r;
                    ++rowSize;
                }
            }


        }

        u64 cols() {
            return mCols;
        }

        void encode(span<u8> x, span<const u8> y)
        {
            assert(mExtend);
            // solves for x such that y = M x, ie x := H^-1 y 

            auto H = getMatrix();

            auto assertFind = [&](u64 i, u64 x)
            {
                auto row = H.row(i);
                assert(std::find(row.begin(), row.end(), x) != row.end());
            };

            for (u64 i = 0; i < mRows; ++i)
            {
                auto rowSize = mRandRows(i, mGap);
                auto row = &mRandRows(i, 0);
                x[i] = y[i];
                assertFind(i, i);

                for (u64 j = 0; j < rowSize; ++j)
                {
                    auto col = i - row[j] - 1;
                    assert(col < i);
                    assertFind(i, col);
                    x[i] = x[i] ^ x[col];

                }

                for (u64 j = 0; j < mOffsets.size(); ++j)
                {
                    auto p = i - mOffsets[j] - mGap;
                    if (p >= mRows)
                        break;
                    assertFind(i, p);

                    x[i] = x[i] ^ x[p];
                }
            }
        }

        template<typename T>
        void cirTransEncode(span<T> x)
        {
            assert(mExtend);

            // solves for x such that y = M x, ie x := H^-1 y 
            assert(cols() == x.size());
            auto H = getMatrix();

            auto assertFind = [&](u64 i, u64 x)
            {
                auto row = H.row(i);
                assert(std::find(row.begin(), row.end(), x) != row.end());
            };

            for (u64 i = mRows - 1; i != ~u64(0); --i)
            {

                auto rowSize = mRandRows(i, mGap);
                auto row = &mRandRows(i, 0);
                assertFind(i, i);
                std::set<u64> rrr;
                assert(rrr.insert(i).second);


                for (u64 j = 0; j < rowSize; ++j)
                {
                    auto col = i - row[j] - 1;
                    assert(col < i);
                    assertFind(i, col);
                    x[col] = x[col] ^ x[i];

                    assert(rrr.insert(col).second);
                }

                for (u64 j = 0; j < mOffsets.size(); ++j)
                {
                    auto p = i - mOffsets[j] - mGap;
                    if (p >= mRows)
                        break;
                    assertFind(i, p);

                    x[p] = x[p] ^ x[i];
                    assert(rrr.insert(p).second);
                }

                auto row2 = H.row(i);
                for (auto c : row2)
                {
                    assert(rrr.find(c) != rrr.end());
                }
                //assert(rrr.size() == row.size() - 1);
            }

            //assert(mC);
            //assert(mC->cols() == x.size());
            //for (u64 i = mC->rows() - 1; i != ~u64(0); --i)
            //{
            //    auto row = mC->row(i);
            //    assert(row[row.size() - 1] == i);
            //    for (u64 j = 0; j < row.size() - 1; ++j)
            //    {
            //        auto col = row[j];
            //        x[col] = x[col] ^ x[i];
            //    }
            //}
        }

        template<typename T>
        void cirTransEncode(span<T> x, span<const T> y)
        {
            std::memcpy(x.data(), y.data(), y.size() * sizeof(T));
            cirTransEncode(x);
        }


        void getPoints(std::vector<Point>& points, u64 colOffset)
        {
            auto rr = mRandColumns.rows();
            auto ww = mRandColumns.cols();
            std::set<std::pair<u64, u64>> set;
            for (u64 i = 0; i < rr; ++i)
            {
                points.push_back({ i, i + colOffset });

                assert(set.insert({ i, i + colOffset }).second);

                for (u64 j = 0; j < ww; ++j)
                {
                    points.push_back({ mRandColumns(i,j) + i + 1 , i + colOffset });
                    assert(set.insert({ mRandColumns(i,j) + i + 1, i + colOffset }).second);
                }


                for (u64 j = 0; j < mOffsets.size(); ++j)
                {

                    auto p = mOffsets[j] + mGap + i;
                    if (p >= mRows)
                        break;

                    points.push_back({ p, i + colOffset });

                    assert(set.insert({ p, i + colOffset }).second);

                }
            }

            if (mExtend)
            {
                for (u64 i = rr; i < cols(); ++i)
                {
                    points.push_back({ i, i + colOffset });
                    assert(set.insert({ i, i + colOffset }).second);
                }
            }
        }

        SparseMtx getMatrix()
        {
            std::vector<Point> points;
            getPoints(points, 0);
            return SparseMtx(mRows, cols(), points);
        }

    };
    //LdpcDiagBandEncoder;
    //    LdpcZpStarEncoder;
    template<typename LEncoder, typename REncoder>
    class LdpcCompositEncoder
    {
    public:

        LEncoder mL;
        REncoder mR;



        template<typename T>
        void encode(span<T>c, span<const T> mm)
        {
            assert(mm.size() == cols() - rows());
            assert(c.size() == cols());

            auto s = rows();
            auto iter = c.begin() + s;
            span<T> m(c.begin(), iter);
            span<T> pp(iter, c.end());


            // m = mm
            std::copy(mm.begin(), mm.end(), m.begin());
            std::fill(c.begin() + s, c.end(), 0);

            // pp = A * m
            mL.encode(pp, mm);

            // pp = C^-1 pp 
            mR.encode(pp, pp);
        }

        template<typename T>
        void cirTransEncode(span<T> c)
        {
            auto k = cols() - rows();
            assert(c.size() == cols());
            //assert(m.size() == k);

            span<T> pp(c.subspan(k, rows()));

            //std::cout << "P  ";
            //for (u64 i = 0; i < pp.size(); ++i)
            //    std::cout << int(pp[i]) << " ";
            //std::cout << std::endl;

            mR.cirTransEncode(pp);

            //std::cout << "P' ";
            //for (u64 i = 0; i < pp.size(); ++i)
            //    std::cout << int(pp[i]) << " ";
            //std::cout << std::endl;

            mL.cirTransEncode<T>(c.subspan(0,k), pp);

            //std::cout << "m  ";
            //for (u64 i = 0; i < m.size(); ++i)
            //    std::cout << int(m[i]) << " ";
            //std::cout << std::endl;

        }

        u64 cols() {
            return mL.cols() + mR.cols();
        }

        u64 rows() {
            return mR.cols();
        }
        void getPoints(std::vector<Point>& points)
        {
            mL.getPoints(points);
            mR.getPoints(points, mL.cols());
        }

        SparseMtx getMatrix()
        {
            std::vector<Point> points;
            getPoints(points);
            return SparseMtx(rows(), cols(), points);
        }
    };

    namespace tests
    {

        void LdpcEncoder_diagonalSolver_test();
        void LdpcEncoder_encode_test();
        void LdpcEncoder_encode_g0_test();
        void LdpcEncoder_encode_Trans_g0_test();
        void LdpcZpStarEncoder_encode_test();
        void LdpcZpStarEncoder_encode_Trans_test();

        void LdpcDiagBandEncoder_encode_test();
        void LdpcComposit_ZpDiagBand_encode_test();
        void LdpcComposit_ZpDiagBand_Trans_test();
    }

}
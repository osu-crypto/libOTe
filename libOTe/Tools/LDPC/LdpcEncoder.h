#pragma once
#include "Mtx.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <numeric>

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



    class LdpcS1Encoder
    {
    public:

        u64 mRows, mWeight;
        std::vector<u64> mYs;
        std::vector<double> mRs;
        void init(u64 rows, std::vector<double> rs);
        void init(u64 rows, u64 weight)
        {
            switch (weight)
            {
            case 5:
                init(rows, { {0, 0.231511, 0.289389, 0.4919, 0.877814} });
                break;
            case 11:
                init(rows, { {0, 0.12214352, 0.231511, 0.25483572, 0.319389, 0.41342, 0.4919,0.53252, 0.734232, 0.877814, 0.9412} });
                break;
            default:
                // no preset parameters
                throw RTE_LOC;
            }
        }



        void encode(span<u8> pp, span<const u8> m)
        {
            auto cols = mRows;
            assert(pp.size() == mRows);
            assert(m.size() == cols);

            // pp = pp + A * m

            auto v = mYs;

            for (u64 i = 0; i < cols; ++i)
            {
                for (u64 j = 0; j < mWeight; ++j)
                {
                    auto row = v[j];

                    pp[row] ^= m[i];

                    ++v[j];
                    if (v[j] == mRows)
                        v[j] = 0;
                }
            }
        }

        template<typename T>
        void cirTransEncode(span<T> ppp, span<const T> mm)
        {
            auto cols = mRows;
            assert(pp.size() == mRows);
            assert(m.size() == cols);

            // pp = pp + m * A

            auto v = mYs;

            T* __restrict pp = ppp.data();
            const T* __restrict m = mm.data();


            for (u64 i = 0; i < cols; )
            {
                auto end = cols;
                for (u64 j = 0; j < mWeight; ++j)
                {
                    if (v[j] == mRows)
                        v[j] = 0;

                    auto jEnd = cols - v[j] + i;
                    end = std::min<u64>(end, jEnd);
                }
                switch (mWeight)
                {
                case 5:
                    while (i != end)
                    {
                        auto& r0 = v[0];
                        auto& r1 = v[1];
                        auto& r2 = v[2];
                        auto& r3 = v[3];
                        auto& r4 = v[4];

                        pp[i] = pp[i]
                            ^ m[r0]
                            ^ m[r1]
                            ^ m[r2]
                            ^ m[r3]
                            ^ m[r4];

                        ++r0;
                        ++r1;
                        ++r2;
                        ++r3;
                        ++r4;
                        ++i;
                    }
                    break;
                case 11:
                    while (i != end)
                    {
                        auto& r0 = v[0];
                        auto& r1 = v[1];
                        auto& r2 = v[2];
                        auto& r3 = v[3];
                        auto& r4 = v[4];
                        auto& r5 = v[5];
                        auto& r6 = v[6];
                        auto& r7 = v[7];
                        auto& r8 = v[8];
                        auto& r9 = v[9];
                        auto& r10 = v[10];

                        pp[i] = pp[i]
                            ^ m[r0]
                            ^ m[r1]
                            ^ m[r2]
                            ^ m[r3]
                            ^ m[r4]
                            ^ m[r5]
                            ^ m[r6]
                            ^ m[r7]
                            ^ m[r8]
                            ^ m[r9]
                            ^ m[r10]
                            ;


                        ++r0;
                        ++r1;
                        ++r2;
                        ++r3;
                        ++r4;
                        ++r5;
                        ++r6;
                        ++r7;
                        ++r8;
                        ++r9;
                        ++r10;
                        ++i;
                    }

                    break;
                default:
                    while (i != end)
                    {
                        for (u64 j = 0; j < mWeight; ++j)
                        {
                            auto row = v[j];

                            pp[i] = pp[i] ^ m[row];


                            ++v[j];
                        }

                        ++i;
                    }
                    break;
                }

            }
        }


        template<typename T>
        void cirTransEncode2(span<T> ppp0, span<T> ppp1, span<const T> mm0, span<const T> mm1)
        {
            auto cols = mRows;
            //assert(pp.size() == mRows);
            //assert(m.size() == cols);

            // pp = pp + m * A

            auto v = mYs;


            T* __restrict pp0 = ppp0.data();
            T* __restrict pp1 = ppp1.data();
            const T* __restrict m0 = mm0.data();
            const T* __restrict m1 = mm1.data();

            for (u64 i = 0; i < cols; )
            {
                auto end = cols;
                for (u64 j = 0; j < mWeight; ++j)
                {
                    if (v[j] == mRows)
                        v[j] = 0;

                    auto jEnd = cols - v[j] + i;
                    end = std::min<u64>(end, jEnd);
                }
                switch (mWeight)
                {
                case 5:
                    while (i != end)
                    {
                        auto& r0 = v[0];
                        auto& r1 = v[1];
                        auto& r2 = v[2];
                        auto& r3 = v[3];
                        auto& r4 = v[4];

                        pp0[i] = pp0[i]
                            ^ m0[r0]
                            ^ m0[r1]
                            ^ m0[r2]
                            ^ m0[r3]
                            ^ m0[r4];

                        pp1[i] = pp1[i]
                            ^ m1[r0]
                            ^ m1[r1]
                            ^ m1[r2]
                            ^ m1[r3]
                            ^ m1[r4];

                        ++r0;
                        ++r1;
                        ++r2;
                        ++r3;
                        ++r4;
                        ++i;
                    }
                    break;
                case 11:
                    while (i != end)
                    {
                        auto& r0 = v[0];
                        auto& r1 = v[1];
                        auto& r2 = v[2];
                        auto& r3 = v[3];
                        auto& r4 = v[4];
                        auto& r5 = v[5];
                        auto& r6 = v[6];
                        auto& r7 = v[7];
                        auto& r8 = v[8];
                        auto& r9 = v[9];
                        auto& r10 = v[10];

                        pp0[i] = pp0[i]
                            ^ m0[r0]
                            ^ m0[r1]
                            ^ m0[r2]
                            ^ m0[r3]
                            ^ m0[r4]
                            ^ m0[r5]
                            ^ m0[r6]
                            ^ m0[r7]
                            ^ m0[r8]
                            ^ m0[r9]
                            ^ m0[r10]
                            ;

                        pp1[i] = pp1[i]
                            ^ m1[r0]
                            ^ m1[r1]
                            ^ m1[r2]
                            ^ m1[r3]
                            ^ m1[r4]
                            ^ m1[r5]
                            ^ m1[r6]
                            ^ m1[r7]
                            ^ m1[r8]
                            ^ m1[r9]
                            ^ m1[r10]
                            ;

                        ++r0;
                        ++r1;
                        ++r2;
                        ++r3;
                        ++r4;
                        ++r5;
                        ++r6;
                        ++r7;
                        ++r8;
                        ++r9;
                        ++r10;
                        ++i;
                    }

                    break;
                default:
                    while (i != end)
                    {
                        for (u64 j = 0; j < mWeight; ++j)
                        {
                            auto row = v[j];

                            pp0[i] = pp0[i] ^ m0[row];
                            pp1[i] = pp1[i] ^ m1[row];


                            ++v[j];
                        }

                        ++i;
                    }
                    break;
                }

            }
        }


        u64 cols() {
            return mRows;
        }

        u64 rows() {
            return mRows;
        }

        void getPoints(std::vector<Point>& points)
        {
            auto cols = mRows;
            auto v = mYs;

            for (u64 i = 0; i < cols; ++i)
            {
                for (u64 j = 0; j < mWeight; ++j)
                {
                    auto row = v[j];

                    points.push_back({ row, i });

                    ++v[j];
                    if (v[j] == mRows)
                        v[j] = 0;
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

    class LdpcZpStarEncoder
    {
    public:
        u64 mRows, mWeight;
        u64 mP, mY, mIdx0;
        std::vector<u64> mRandStarts;
        void init(u64 rows, u64 weight);
        //void init(u64 rows, u64 weight, PRNG& randStartPrng);


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

                    pp[i] = pp[i] ^ m[row];

                    v[j] = mod(v[j] + j + 1);
                }
            }
        }

        u64 ZpToIdx(u64 x)
        {
            assert(x != 0 && x < mP);
            if (x >= mP - mY)
                x = x - (mP - mY);
            else
                x = x + mY - 1;

            assert(x < mRows);
            return x;
        }


        u64 idxToZp(u64 x)
        {
            auto z = x + (mP - mY);
            if (z >= mP)
                z -= mP - 1;
            assert(z != 0 && z < mP);
            return z;
        };

        struct Rec
        {
            u64 end;
            u64 pos = 0;
            bool isY = false;
        };
        Rec getNextEnd(u64 idx, u64 j, u64 slope)
        {
            bool yy;
            u64 diff, z = idxToZp(idx);
            //auto idx = vv[j];

            //auto slope = (j + 1);
            u64 e2;

            if (z < mIdx0)
            {
                diff = (mIdx0 - z);
                yy = true;
            }
            else
            {
                assert(z < mP);
                assert(z >= mIdx0);
                diff = mP - z;
                yy = false;
            }
            e2 = (diff + slope - 1) / slope;

            assert(z + e2 * slope >= (yy ? mIdx0 : mP));
            assert(z + (e2 - 1) * slope < (yy ? mIdx0 : mP));
            return { e2, j, yy };
        };

        template<typename T>
        void optCirTransEncode(span<T> pp, span<const T> m, span<u64> weights)
        {

            std::vector<Rec> recs; recs.reserve(weights.size());
            assert(isPrime(mP));

            std::vector<u64> vv(weights.size());

            for (u64 i = weights.size() - 1; i != ~u64(0); --i)
            {
                auto slope = weights[i] + 1;
                vv[i] = ZpToIdx(slope);

                auto rec = getNextEnd(vv[i], i, slope);
                recs.push_back(rec);

                auto s = recs.size();
                if (s > 1)
                    assert(recs[s - 2].end < recs[s - 1].end);
            }

            auto e = recs.front().end;
            auto vPtr = vv.data();
            auto pPtr = pp.data();
            for (u64 i = 0; i < mRows;)
            {

                switch (vv.size())
                {
                case 1:
                {
                    auto slope = weights[0] + 1;
                    while (i != e)
                    {
                        auto v0 = m[vPtr[0]];

                        *pPtr = *pPtr ^ v0;
                        ++pPtr;

                        vPtr[0] += slope;

                        ++i;
                    }

                    break;
                }
                case 5:

                    for (u64 j = 0; j < weights.size(); ++j)
                        assert(weights[j] = j);

                    while (i != e)
                    {
                        auto v0 = m[vPtr[0]];
                        auto v1 = m[vPtr[1]];
                        auto v2 = m[vPtr[2]];
                        auto v3 = m[vPtr[3]];
                        auto v4 = m[vPtr[4]];

                        *pPtr = *pPtr ^ v0 ^ v1 ^ v2 ^ v3 ^ v4;;
                        ++pPtr;

                        vPtr[0] += 1;
                        vPtr[1] += 2;
                        vPtr[2] += 3;
                        vPtr[3] += 4;
                        vPtr[4] += 5;

                        ++i;
                    }
                    break;
                default:
                    throw RTE_LOC;
                    break;
                }

                if (i < mRows)
                {
                    assert(recs[0].end == e);

                    while (recs[0].end == e)
                    {

                        auto rec = recs[0];
                        recs.erase(recs.begin());
                        auto j = rec.pos;
                        auto slope = weights[j] + 1;

                        auto z = idxToZp(vv[j]);

                        if (rec.isY)
                        {
                            assert(z >= mIdx0);
                            assert(vv[j] >= mRows);
                            vv[j] -= mRows;
                            assert(vv[j] < mRows);
                        }
                        else
                        {
                            --vv[j];
                        }

                        rec = getNextEnd(vv[j], j, slope);
                        auto next = vv[j] + slope * rec.end;
                        rec.end += i;

                        auto iter = recs.begin();
                        while (iter != recs.end() && iter->end < rec.end)
                            ++iter;

                        recs.insert(iter, rec);
                    }

                    e = recs[0].end;
                }
            }
        }

        template<typename T>
        void optCirTransEncode(span<T> pp, span<const T> m)
        {
            if (1)
            {
                std::vector<u64> weight(mWeight);
                std::iota(weight.begin(), weight.end(), 0);
                optCirTransEncode(pp, m, weight);
            }
            else
            {
                for (u64 w = 0; w < mWeight; ++w)
                {
                    optCirTransEncode(pp, m, span<u64>(&w, 1));
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
                    mRandColumns(i, j) = static_cast<u8>(r);

                    u64 row = r + i + 1;
                    auto& rowSize = mRandRows(row, gap);

                    assert(rowSize != gap);

                    mRandRows(row, rowSize) = static_cast<u8>(r);
                    ++rowSize;
                }
            }


        }

        u64 cols() {
            return mCols;
        }


        u64 rows() {
            return mRows;
        }

        void encode(span<u8> x, span<const u8> y)
        {
            assert(mExtend);
            // solves for x such that y = M x, ie x := H^-1 y 

            //auto H = getMatrix();

            //auto assertFind = [&](u64 i, u64 x)
            //{
            //    auto row = H.row(i);
            //    assert(std::find(row.begin(), row.end(), x) != row.end());
            //};

            for (u64 i = 0; i < mRows; ++i)
            {
                auto rowSize = mRandRows(i, mGap);
                auto row = &mRandRows(i, 0);
                x[i] = y[i];
                //assertFind(i, i);

                for (u64 j = 0; j < rowSize; ++j)
                {
                    auto col = i - row[j] - 1;
                    assert(col < i);
                    //assertFind(i, col);
                    x[i] = x[i] ^ x[col];

                }

                for (u64 j = 0; j < mOffsets.size(); ++j)
                {
                    auto p = i - mOffsets[j] - mGap;
                    if (p >= mRows)
                        break;
                    //assertFind(i, p);

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
            //auto H = getMatrix();

            //auto assertFind = [&](u64 i, u64 x)
            //{
            //    auto row = H.row(i);
            //    assert(std::find(row.begin(), row.end(), x) != row.end());
            //};

            for (u64 i = mRows - 1; i != ~u64(0); --i)
            {

                auto rowSize = mRandRows(i, mGap);
                auto row = &mRandRows(i, 0);
                //assertFind(i, i);
                //std::set<u64> rrr;
                //assert(rrr.insert(i).second);


                for (u64 j = 0; j < rowSize; ++j)
                {
                    auto col = i - row[j] - 1;
                    assert(col < i);
                    //assertFind(i, col);
                    x[col] = x[col] ^ x[i];

                    //assert(rrr.insert(col).second);
                }

                for (u64 j = 0; j < mOffsets.size(); ++j)
                {
                    auto p = i - mOffsets[j] - mGap;
                    if (p >= mRows)
                        break;

                    x[p] = x[p] ^ x[i];
                    //assert(rrr.insert(p).second);
                }
            }
        }


        template<typename T>
        void cirTransEncode2(span<T> x0, span<T> x1)
        {
            assert(mExtend);

            // solves for x such that y = M x, ie x := H^-1 y 
            assert(cols() == x0.size());
            assert(cols() == x1.size());
            //auto H = getMatrix();

            //auto assertFind = [&](u64 i, u64 x)
            //{
            //    auto row = H.row(i);
            //    assert(std::find(row.begin(), row.end(), x) != row.end());
            //};

            for (u64 i = mRows - 1; i != ~u64(0); --i)
            {

                auto rowSize = mRandRows(i, mGap);
                auto row = &mRandRows(i, 0);
                //assertFind(i, i);
                //std::set<u64> rrr;
                //assert(rrr.insert(i).second);


                for (u64 j = 0; j < rowSize; ++j)
                {
                    auto col = i - row[j] - 1;
                    assert(col < i);
                    //assertFind(i, col);
                    x0[col] = x0[col] ^ x0[i];
                    x1[col] = x1[col] ^ x1[i];

                    //assert(rrr.insert(col).second);
                }

                for (u64 j = 0; j < mOffsets.size(); ++j)
                {
                    auto p = i - mOffsets[j] - mGap;
                    if (p >= mRows)
                        break;

                    x0[p] = x0[p] ^ x0[i];
                    x0[p] = x0[p] ^ x0[i];
                    //assert(rrr.insert(p).second);
                }
            }
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

            for (u64 i = 0; i < rr; ++i)
            {
                points.push_back({ i, i + colOffset });

                //assert(set.insert({ i, i + colOffset }).second);

                for (u64 j = 0; j < ww; ++j)
                {
                    points.push_back({ mRandColumns(i,j) + i + 1 , i + colOffset });
                    //assert(set.insert({ mRandColumns(i,j) + i + 1, i + colOffset }).second);
                }


                for (u64 j = 0; j < mOffsets.size(); ++j)
                {

                    auto p = mOffsets[j] + mGap + i;
                    if (p >= mRows)
                        break;

                    points.push_back({ p, i + colOffset });

                    //assert(set.insert({ p, i + colOffset }).second);

                }
            }

            if (mExtend)
            {
                for (u64 i = rr; i < cols(); ++i)
                {
                    points.push_back({ i, i + colOffset });
                    //assert(set.insert({ i, i + colOffset }).second);
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



    class LdpcDiagRepeaterEncoder
    {
    public:
        u64 mGap, mCols, mRows;
        u64 mGapWeight, mPeriod;
        std::vector<u64> mOffsets;
        Matrix<u8> mRandColumns;
        Matrix<u64> mRandRows;
        bool mExtend;

        void init(
            u64 rows,
            u64 gap,
            u64 gapWeight,
            u64 period,
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
            mPeriod = std::min(period, rows);

            if (extend)
                mCols = rows;
            else
                mCols = rows - mGap;

            mRandColumns.resize(period, mGapWeight - 1, AllocType::Uninitialized);
            mRandRows.resize(period, gap + 1);

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
                    mRandColumns(i, j) = static_cast<u8>(r);

                    u64 row = (r + i + 1) % rr;
                    auto& rowSize = mRandRows(row, gap);

                    assert(rowSize != gap);

                    mRandRows(row, rowSize) = static_cast<u8>(r);
                    ++rowSize;
                }
            }
        }

        u64 cols() {
            return mCols;
        }

        u64 rows()
        {
            return mRows;
        }

        void encode(span<u8> x, span<const u8> y)
        {
            assert(mExtend);
            // solves for x such that y = M x, ie x := H^-1 y 

            //auto H = getMatrix();

            //auto assertFind = [&](u64 i, u64 x)
            //{
            //    auto row = H.row(i);
            //    assert(std::find(row.begin(), row.end(), x) != row.end());
            //};

            for (u64 i = 0; i < mRows; ++i)
            {
                auto rowSize = mRandRows(i % mPeriod, mGap);
                auto row = &mRandRows(i % mPeriod, 0);

                std::set<std::pair<u64, u64>> rrow;

                x[i] = y[i];
                //assertFind(i, i);
                //assert(rrow.insert({ i,i }).second);

                for (u64 j = 0; j < rowSize; ++j)
                {
                    auto col = i - row[j] - 1;

                    if (col >= mRows)
                        break;

                    x[i] = x[i] ^ x[col];

                    //assertFind(i, col);
                    //assert(rrow.insert({ i,col }).second);

                }

                for (u64 j = 0; j < mOffsets.size(); ++j)
                {
                    auto p = i - mOffsets[j] - mGap;
                    if (p >= mRows)
                        break;

                    x[i] = x[i] ^ x[p];
                    //assertFind(i, p);
                    //assert(rrow.insert({ i,p }).second);
                }


                //assert(rrow.size() == H.mRows[i].size());
                //for (u64 j = 0; j < H.mRows[i].size(); ++j)
                //    assert(rrow.find({ i,H.mRows[i][j] }) != rrow.end());
            }
        }

        template<typename T>
        void cirTransEncode(span<T> x)
        {
            assert(mExtend);

            // solves for x such that y = M x, ie x := H^-1 y 
            assert(cols() == x.size());


            constexpr int FIXED_OFFSET_SIZE = 2;
            if (mOffsets.size() != FIXED_OFFSET_SIZE)
                throw RTE_LOC;

            auto offsets = mOffsets;
            auto randRows = mRandRows;

            auto randRowSize = mRandRows.rows();
            u64 randRowIdx = (mRows - 1) % mPeriod;

            for (u64 i = mRows - 1, k = 0; k < randRows.rows(); ++k, --i)
            {
                auto r = i % mPeriod;
                auto rowSize = mRandRows(r, mGap);
                for (u64 j = 0; j < rowSize; ++j)
                {
                    randRows(r, j) = i - randRows(r, j) - 1;
                }

            }

            for (u64 j = 0; j < offsets.size(); ++j)
            {
                offsets[j] = mRows - 1 - offsets[j] - mGap;
            }


            auto mainEnd =
                *std::max_element(mOffsets.begin(), mOffsets.end())
                + mGap + 10;

            u64 i = mRows - 1;
            T* __restrict  osCol0 = &x[offsets[0]];
            T* __restrict  osCol1 = &x[offsets[1]];

            T* __restrict  xi = &x[i];
            T* __restrict  xPtr = x.data();
            for (; i != mainEnd; --i)
            {

                auto rowSize = randRows(randRowIdx, mGap);
                auto row2 = &randRows(randRowIdx, 0);

                if (randRowIdx == 0)
                    randRowIdx = randRowSize - 1;
                else
                    --randRowIdx;

                for (u64 j = 0; j < rowSize; ++j)
                {
                    auto& col = row2[j];
                    auto& cx = xPtr[col];

                    cx = cx ^ *xi;
                    col -= mPeriod;
                }
                *osCol0 = *osCol0 ^ *xi;
                *osCol1 = *osCol1 ^ *xi;


                --osCol0;
                --osCol1;
                --xi;
            }
            offsets[0] = osCol0 - x.data();
            offsets[1] = osCol1 - x.data();

            //for (u64 j = 0; j < FIXED_OFFSET_SIZE; ++j)


            for (; i != ~u64(0); --i)
            {

                auto rowSize = randRows(randRowIdx, mGap);
                auto row2 = &randRows(randRowIdx, 0);

                if (randRowIdx == 0)
                    randRowIdx = randRowSize - 1;
                else
                    --randRowIdx;

                for (u64 j = 0; j < rowSize; ++j)
                {
                    auto& col = row2[j];
                    if (col >= mRows)
                        break;

                    x[col] = x[col] ^ x[i];

                    col -= mPeriod;
                }

                for (u64 j = 0; j < FIXED_OFFSET_SIZE; ++j)
                {
                    auto& col = offsets[j];

                    if (col >= mRows)
                        break;
                    assert(i - mOffsets[j] - mGap == col);

                    x[col] = x[col] ^ x[i];
                    --col;
                }
            }
        }



        template<typename T>
        void cirTransEncode2(span<T> x0, span<T> x1)
        {

            assert(mExtend);

            // solves for x such that y = M x, ie x := H^-1 y 
            assert(cols() == x0.size());
            assert(cols() == x1.size());


            constexpr int FIXED_OFFSET_SIZE = 2;
            if (mOffsets.size() != FIXED_OFFSET_SIZE)
                throw RTE_LOC;

            auto offsets = mOffsets;
            auto randRows = mRandRows;

            auto randRowSize = mRandRows.rows();
            u64 randRowIdx = (mRows - 1) % mPeriod;

            for (u64 i = mRows - 1, k = 0; k < randRows.rows(); ++k, --i)
            {
                auto r = i % mPeriod;
                auto rowSize = mRandRows(r, mGap);
                for (u64 j = 0; j < rowSize; ++j)
                {
                    randRows(r, j) = i - randRows(r, j) - 1;
                }

            }

            for (u64 j = 0; j < offsets.size(); ++j)
            {
                offsets[j] = mRows - 1 - offsets[j] - mGap;
            }


            auto mainEnd =
                *std::max_element(mOffsets.begin(), mOffsets.end())
                + mGap + 10;

            u64 i = mRows - 1;
            T* __restrict osCol00 = &x0[offsets[0]];
            T* __restrict osCol10 = &x0[offsets[1]];
            T* __restrict osCol01 = &x1[offsets[0]];
            T* __restrict osCol11 = &x1[offsets[1]];

            T* __restrict xi0 = &x0[i];
            T* __restrict xi1 = &x1[i];
            T* __restrict xPtr0 = x0.data();
            T* __restrict xPtr1 = x1.data();
            for (; i != mainEnd; --i)
            {

                auto rowSize = randRows(randRowIdx, mGap);
                auto row2 = &randRows(randRowIdx, 0);

                if (randRowIdx == 0)
                    randRowIdx = randRowSize - 1;
                else
                    --randRowIdx;

                for (u64 j = 0; j < rowSize; ++j)
                {
                    auto& col = row2[j];
                    auto& cx0 = xPtr0[col];
                    auto& cx1 = xPtr1[col];

                    cx0 = cx0 ^ *xi0;
                    cx1 = cx1 ^ *xi1;
                    col -= mPeriod;
                }
                *osCol00 = *osCol00 ^ *xi0;
                *osCol10 = *osCol10 ^ *xi0;
                *osCol01 = *osCol01 ^ *xi1;
                *osCol11 = *osCol11 ^ *xi1;


                --osCol00;
                --osCol10;
                --xi0;
                --osCol01;
                --osCol11;
                --xi1;
            }
            offsets[0] = osCol00 - x0.data();
            offsets[1] = osCol10 - x0.data();

            //for (u64 j = 0; j < FIXED_OFFSET_SIZE; ++j)


            for (; i != ~u64(0); --i)
            {

                auto rowSize = randRows(randRowIdx, mGap);
                auto row2 = &randRows(randRowIdx, 0);

                if (randRowIdx == 0)
                    randRowIdx = randRowSize - 1;
                else
                    --randRowIdx;

                for (u64 j = 0; j < rowSize; ++j)
                {
                    auto& col = row2[j];
                    if (col >= mRows)
                        break;

                    x0[col] = x0[col] ^ x0[i];
                    x1[col] = x1[col] ^ x1[i];

                    col -= mPeriod;
                }

                for (u64 j = 0; j < FIXED_OFFSET_SIZE; ++j)
                {
                    auto& col = offsets[j];

                    if (col >= mRows)
                        break;
                    assert(i - mOffsets[j] - mGap == col);

                    x0[col] = x0[col] ^ x0[i];
                    x1[col] = x1[col] ^ x1[i];
                    --col;
                }
            }
        }


        template<typename T>
        void cirTransEncode(span<T> x, span<const T> y)
        {
            std::memcpy(x.data(), y.data(), y.size() * sizeof(T));
            cirTransEncode(x);
        }

        void getPoints(std::vector<Point>& points, u64 colOffset)
        {
            auto rr = mCols;
            auto ww = mRandColumns.cols();

            for (u64 i = 0; i < rr; ++i)
            {
                points.push_back({ i, i + colOffset });

                //assert(set.insert({ i, i + colOffset }).second);

                for (u64 j = 0; j < ww; ++j)
                {

                    auto row = mRandColumns(i % mPeriod, j) + i + 1;
                    if (row < mRows)
                        points.push_back({ row, i + colOffset });
                    //assert(set.insert({ mRandColumns(i,j) + i + 1, i + colOffset }).second);
                }


                for (u64 j = 0; j < mOffsets.size(); ++j)
                {

                    auto p = mOffsets[j] + mGap + i;
                    if (p >= mRows)
                        break;

                    points.push_back({ p, i + colOffset });

                    //assert(set.insert({ p, i + colOffset }).second);

                }
            }

            if (mExtend)
            {
                for (u64 i = rr; i < mRows; ++i)
                {
                    points.push_back({ i, i + colOffset });
                    //assert(set.insert({ i, i + colOffset }).second);
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
    class LdpcCompositEncoder : public TimerAdapter
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
            setTimePoint("encode_begin");
            span<T> pp(c.subspan(k, rows()));

            //std::cout << "P  ";
            //for (u64 i = 0; i < pp.size(); ++i)
            //    std::cout << int(pp[i]) << " ";
            //std::cout << std::endl;

            mR.cirTransEncode(pp);

            setTimePoint("diag");
            //std::cout << "P' ";
            //for (u64 i = 0; i < pp.size(); ++i)
            //    std::cout << int(pp[i]) << " ";
            //std::cout << std::endl;

            mL.template cirTransEncode<T>(c.subspan(0, k), pp);
            setTimePoint("zp");
            //if(0)

            //std::cout << "m  ";
            //for (u64 i = 0; i < m.size(); ++i)
            //    std::cout << int(m[i]) << " ";
            //std::cout << std::endl;

        }


        template<typename T>
        void cirTransEncode2(span<T> c0, span<T> c1)
        {
            auto k = cols() - rows();
            assert(c0.size() == cols());
            //assert(m.size() == k);
            setTimePoint("encode_begin");
            span<T> pp0(c0.subspan(k, rows()));
            span<T> pp1(c1.subspan(k, rows()));

            //std::cout << "P  ";
            //for (u64 i = 0; i < pp.size(); ++i)
            //    std::cout << int(pp[i]) << " ";
            //std::cout << std::endl;

            mR.cirTransEncode2(pp0, pp1);

            setTimePoint("diag");
            //std::cout << "P' ";
            //for (u64 i = 0; i < pp.size(); ++i)
            //    std::cout << int(pp[i]) << " ";
            //std::cout << std::endl;

            mL.template cirTransEncode2<T>(c0.subspan(0, k), c1.subspan(0, k), pp0, pp1);
            setTimePoint("zp");
            //if(0)

            //std::cout << "m  ";
            //for (u64 i = 0; i < m.size(); ++i)
            //    std::cout << int(m[i]) << " ";
            //std::cout << std::endl;

        }


        u64 cols() {
            return mL.cols() + mR.cols();
        }

        u64 rows() {
            return mR.rows();
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
    using ZpDiagEncoder = LdpcCompositEncoder<LdpcZpStarEncoder, LdpcDiagBandEncoder>;
    using ZpDiagRepEncoder = LdpcCompositEncoder<LdpcZpStarEncoder, LdpcDiagRepeaterEncoder>;
    using S1DiagRepEncoder = LdpcCompositEncoder<LdpcS1Encoder, LdpcDiagRepeaterEncoder>;

    namespace tests
    {

        void LdpcEncoder_diagonalSolver_test();
        void LdpcEncoder_encode_test();
        void LdpcEncoder_encode_g0_test();
        void LdpcEncoder_encode_Trans_g0_test();
        void LdpcZpStarEncoder_encode_test();
        void LdpcZpStarEncoder_encode_Trans_test();

        void LdpcS1Encoder_encode_test();
        void LdpcS1Encoder_encode_Trans_test();

        void LdpcDiagBandEncoder_encode_test();
        void LdpcComposit_ZpDiagBand_encode_test();
        void LdpcComposit_ZpDiagBand_Trans_test();


        void LdpcComposit_ZpDiagRep_encode_test();
        void LdpcComposit_ZpDiagRep_Trans_test();
    }

}
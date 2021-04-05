#pragma once
#include "Mtx.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/Timer.h"
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
                PointList points(nn,nn);

                points.push_back({ i, n + i });
                assert(row[row.size() - 1] == i);
                for (u64 j = 0; j < (u64)row.size() - 1; ++j)
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
                for (u64 j = 0; j < (u64)row.size() - 1; ++j)
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
                for (u64 j = 0; j < (u64)row.size() - 1; ++j)
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
                //init(rows, { {0, 0.231511, 0.289389, 0.4919, 0.877814} });
                init(rows, { { 0, 0.372071, 0.576568, 0.608917, 0.854475} });

                // 0 0.0494143 0.437702 0.603978 0.731941

                // yset 3,785
                // 0 0.372071 0.576568 0.608917 0.854475
                break;
            case 11:
                //init(rows, { {0, 0.12214352, 0.231511, 0.25483572, 0.319389, 0.41342, 0.4919,0.53252, 0.734232, 0.877814, 0.9412} });
                init(rows, { { 0, 0.00278835, 0.0883852, 0.238023, 0.240532, 0.274624, 0.390639, 0.531551, 0.637619, 0.945265, 0.965874} });
                // 0 0.00278835 0.0883852 0.238023 0.240532 0.274624 0.390639 0.531551 0.637619 0.945265 0.965874
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
            assert(ppp.size() == mRows);
            assert(mm.size() == cols);

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

                T* __restrict P = &pp[i];
                T* __restrict PE = &pp[end];


                switch (mWeight)
                {
                case 5:
                {

                    //while (i != end)
                    //{
                    //    auto& r0 = v[0];
                    //    auto& r1 = v[1];
                    //    auto& r2 = v[2];
                    //    auto& r3 = v[3];
                    //    auto& r4 = v[4];

                    //    pp[i] = pp[i]
                    //        ^ m[r0]
                    //        ^ m[r1]
                    //        ^ m[r2]
                    //        ^ m[r3]
                    //        ^ m[r4];

                    //    ++r0;
                    //    ++r1;
                    //    ++r2;
                    //    ++r3;
                    //    ++r4;
                    //    ++i;
                    //}


                    const T* __restrict M0 = &m[v[0]];
                    const T* __restrict M1 = &m[v[1]];
                    const T* __restrict M2 = &m[v[2]];
                    const T* __restrict M3 = &m[v[3]];
                    const T* __restrict M4 = &m[v[4]];

                    v[0] += end - i;
                    v[1] += end - i;
                    v[2] += end - i;
                    v[3] += end - i;
                    v[4] += end - i;
                    i = end;

                    while (P != PE)
                    {
                        *P = *P
                            ^ *M0
                            ^ *M1
                            ^ *M2
                            ^ *M3
                            ^ *M4
                            ;

                        ++M0;
                        ++M1;
                        ++M2;
                        ++M3;
                        ++M4;
                        ++P;
                    }


                    break;
                }
                case 11:
                {

                    //while (i != end)
                    //{
                    //    auto& r0 = v[0];
                    //    auto& r1 = v[1];
                    //    auto& r2 = v[2];
                    //    auto& r3 = v[3];
                    //    auto& r4 = v[4];
                    //    auto& r5 = v[5];
                    //    auto& r6 = v[6];
                    //    auto& r7 = v[7];
                    //    auto& r8 = v[8];
                    //    auto& r9 = v[9];
                    //    auto& r10 = v[10];

                    //    pp[i] = pp[i]
                    //        ^ m[r0]
                    //        ^ m[r1]
                    //        ^ m[r2]
                    //        ^ m[r3]
                    //        ^ m[r4]
                    //        ^ m[r5]
                    //        ^ m[r6]
                    //        ^ m[r7]
                    //        ^ m[r8]
                    //        ^ m[r9]
                    //        ^ m[r10]
                    //        ;


                    //    ++r0;
                    //    ++r1;
                    //    ++r2;
                    //    ++r3;
                    //    ++r4;
                    //    ++r5;
                    //    ++r6;
                    //    ++r7;
                    //    ++r8;
                    //    ++r9;
                    //    ++r10;
                    //    ++i;
                    //}

                    const T* __restrict M0 = &m[v[0]];
                    const T* __restrict M1 = &m[v[1]];
                    const T* __restrict M2 = &m[v[2]];
                    const T* __restrict M3 = &m[v[3]];
                    const T* __restrict M4 = &m[v[4]];
                    const T* __restrict M5 = &m[v[5]];
                    const T* __restrict M6 = &m[v[6]];
                    const T* __restrict M7 = &m[v[7]];
                    const T* __restrict M8 = &m[v[8]];
                    const T* __restrict M9 = &m[v[9]];
                    const T* __restrict M10 = &m[v[10]];

                    v[0] += end - i;
                    v[1] += end - i;
                    v[2] += end - i;
                    v[3] += end - i;
                    v[4] += end - i;
                    v[5] += end - i;
                    v[6] += end - i;
                    v[7] += end - i;
                    v[8] += end - i;
                    v[9] += end - i;
                    v[10] += end - i;
                    i = end;


                    while (P != PE)
                    {
                        *P = *P
                            ^ *M0
                            ^ *M1
                            ^ *M2
                            ^ *M3
                            ^ *M4
                            ^ *M5
                            ^ *M6
                            ^ *M7
                            ^ *M8
                            ^ *M9
                            ^ *M10
                            ;

                        ++M0;
                        ++M1;
                        ++M2;
                        ++M3;
                        ++M4;
                        ++M5;
                        ++M6;
                        ++M7;
                        ++M8;
                        ++M9;
                        ++M10;
                        ++P;
                    }

                    break;
                }
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


        template<typename T0, typename T1>
        void cirTransEncode2(
            span<T0> ppp0, span<T1> ppp1,
            span<const T0> mm0, span<const T1> mm1)
        {
            auto cols = mRows;
            //assert(pp.size() == mRows);
            //assert(m.size() == cols);

            // pp = pp + m * A

            auto v = mYs;


            T0* __restrict pp0 = ppp0.data();
            T1* __restrict pp1 = ppp1.data();
            const T0* __restrict m0 = mm0.data();
            const T1* __restrict m1 = mm1.data();

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

        void getPoints(PointList& points)
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
            PointList points(mRows, mRows);
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

                        if (rec.isY)
                        {
                            assert(idxToZp(vv[j]) >= mIdx0);
                            assert(vv[j] >= mRows);
                            vv[j] -= mRows;
                            assert(vv[j] < mRows);
                        }
                        else
                        {
                            --vv[j];
                        }

                        rec = getNextEnd(vv[j], j, slope);
                        //auto next = vv[j] + slope * rec.end;
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

        void getPoints(PointList& points)
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
            PointList points(mRows, mRows);
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
                for (u64 j = 0; j < (u64)ww; ++j)
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

        void getPoints(PointList& points, u64 colOffset)
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
            PointList points(mRows, cols());
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
                for (u64 j = 0; j < ww; ++j)
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

        void getPoints(PointList& points, u64 colOffset)
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
            PointList points(mRows, cols());
            getPoints(points, 0);
            return SparseMtx(mRows, cols(), points);
        }

    };










    class LdpcDiagRegRepeaterEncoder
    {
    public:

        enum Code
        {
            Weight5 = 5,
            Weight11 = 11,
        };

        static u64 gap(Code c)
        {
            switch (c)
            {
            case osuCrypto::LdpcDiagRegRepeaterEncoder::Weight5:
                return 16;
                break;
            case osuCrypto::LdpcDiagRegRepeaterEncoder::Weight11:
                return 32;
                break;
            default:
                throw RTE_LOC;
                break;
            }
        }

        static u64 weight(Code c)
        {
            return (u64)c;
        }




        static constexpr  std::array<std::array<u8, 4>, 16> diagMtx_g16_w5_seed1_t36
        { {
            {{ 0, 1, 5, 12}},
            {{ 2, 10, 11, 12}},
            {{ 1, 4, 5, 13}},
            {{ 3, 4, 9, 12}},
            {{ 2, 3, 4, 8}},
            {{ 8, 10, 13, 14}},
            {{ 0, 3, 6, 7}},
            {{ 0, 6, 9, 14}},
            {{ 7, 13, 14, 15}},
            {{ 2, 7, 11, 13}},
            {{ 2, 3, 14, 15}},
            {{ 1, 5, 9, 15}},
            {{ 5, 8, 9, 11}},
            {{ 4, 8, 10, 11}},
            {{ 1, 6, 7, 12}},
            {{ 0, 6, 10, 15}},
        } };


        static constexpr  std::array<std::array<u8, 10>, 32> diagMtx_g32_w11_seed2_t36
        { {
            { { 7, 8, 9, 13, 17, 18, 21, 23, 25, 26}},
            { { 0, 1, 2, 3, 8, 12, 14, 15, 19, 21} },
            { { 1, 2, 4, 7, 10, 13, 15, 19, 24, 25} },
            { { 7, 9, 13, 17, 19, 25, 27, 29, 30, 31} },
            { { 1, 8, 13, 14, 19, 22, 24, 29, 30, 31} },
            { { 4, 9, 17, 18, 19, 20, 22, 23, 27, 28} },
            { { 5, 6, 9, 11, 12, 18, 19, 24, 29, 31} },
            { { 3, 5, 13, 16, 19, 20, 21, 25, 26, 28} },
            { { 3, 7, 22, 25, 26, 27, 28, 29, 30, 31} },
            { { 5, 13, 18, 23, 25, 26, 27, 29, 30, 31} },
            { { 0, 2, 5, 7, 9, 11, 13, 15, 16, 17} },
            { { 2, 6, 8, 10, 14, 16, 18, 20, 22, 23} },
            { { 5, 11, 20, 22, 24, 27, 28, 29, 30, 31} },
            { { 0, 2, 6, 7, 10, 14, 17, 21, 26, 27} },
            { { 4, 7, 9, 10, 16, 20, 22, 23, 27, 28} },
            { { 0, 1, 3, 6, 8, 9, 11, 12, 15, 16} },
            { { 0, 1, 3, 7, 9, 14, 15, 17, 23, 24} },
            { { 1, 3, 4, 6, 8, 12, 20, 21, 22, 25} },
            { { 3, 4, 6, 11, 14, 16, 18, 21, 22, 28} },
            { { 1, 2, 8, 11, 12, 15, 21, 23, 25, 27} },
            { { 3, 8, 9, 10, 14, 21, 23, 24, 30, 31} },
            { { 3, 6, 10, 11, 13, 15, 17, 18, 21, 26} },
            { { 0, 4, 6, 8, 11, 15, 24, 25, 28, 29} },
            { { 0, 4, 5, 12, 15, 20, 22, 24, 28, 31} },
            { { 1, 2, 16, 18, 19, 21, 25, 28, 29, 30} },
            { { 1, 2, 4, 5, 9, 15, 20, 26, 29, 30} },
            { { 0, 1, 2, 3, 5, 6, 10, 16, 17, 20} },
            { { 4, 5, 18, 20, 23, 24, 28, 29, 30, 31} },
            { { 10, 11, 12, 13, 16, 19, 26, 27, 30, 31} },
            { { 0, 12, 13, 14, 17, 18, 23, 24, 26, 27} },
            { { 7, 8, 10, 11, 12, 14, 16, 17, 22, 26} },
            { { 0, 2, 4, 5, 6, 7, 10, 12, 14, 19} },
        } };

        static constexpr std::array<u8, 2> mOffsets{ {5,31} };

        u64 mGap;

        u64 mRows, mCols;
        Code mCode;
        //std::vector<u64> mOffsets;
        bool mExtend;

        void init(
            u64 rows,
            Code c,
            bool extend)
        {
            mGap = gap(c);

            assert(mGap < rows);

            mCode = c;

            mRows = rows;
            mExtend = extend;

            if (extend)
                mCols = rows;
            else
                mCols = rows - mGap;
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

            for (u64 i = 0; i < mRows; ++i)
            {
                //auto rowSize = mRandRows(i % mPeriod, mGap);


                x[i] = y[i];
                if (mCode == Code::Weight5)
                {
                    for (u64 j = 0; j < 4; ++j)
                    {
                        auto col = i - 16 + diagMtx_g16_w5_seed1_t36[i & 15][j];

                        if (col < mRows)
                            x[i] = x[i] ^ x[col];
                    }
                }

                if (mCode == Code::Weight11)
                {
                    for (u64 j = 0; j < 10; ++j)
                    {
                        auto col = i - 32 + diagMtx_g32_w11_seed2_t36[i & 31][j];

                        if (col < mRows)
                            x[i] = x[i] ^ x[col];
                    }
                }

                for (u64 j = 0; j < mOffsets.size(); ++j)
                {
                    auto p = i - mOffsets[j] - mGap;
                    if (p >= mRows)
                        break;

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


            constexpr int FIXED_OFFSET_SIZE = 2;
            if (mOffsets.size() != FIXED_OFFSET_SIZE)
                throw RTE_LOC;

            std::vector<u64> offsets(mOffsets.size());
            for (u64 j = 0; j < offsets.size(); ++j)
            {
                offsets[j] = mRows - 1 - mOffsets[j] - mGap;
            }

            u64 i = mRows - 1;
            T* __restrict ofCol0 = &x[offsets[0]];
            T* __restrict ofCol1 = &x[offsets[1]];
            T* __restrict xi = &x[i];

            switch (mCode)
            {
            case osuCrypto::LdpcDiagRegRepeaterEncoder::Weight5:
            {

                auto mainEnd =
                    roundUpTo(
                        *std::max_element(mOffsets.begin(), mOffsets.end())
                        + mGap,
                        16);

                T* __restrict xx = xi - 16;

                for (; i > mainEnd;)
                {
                    for (u64 jj = 0; jj < 16; ++jj)
                    {

                        auto col0 = diagMtx_g16_w5_seed1_t36[i & 15][0];
                        auto col1 = diagMtx_g16_w5_seed1_t36[i & 15][1];
                        auto col2 = diagMtx_g16_w5_seed1_t36[i & 15][2];
                        auto col3 = diagMtx_g16_w5_seed1_t36[i & 15][3];

                        T* __restrict xc0 = xx + col0;
                        T* __restrict xc1 = xx + col1;
                        T* __restrict xc2 = xx + col2;
                        T* __restrict xc3 = xx + col3;

                        *xc0 = *xc0 ^ *xi;
                        *xc1 = *xc1 ^ *xi;
                        *xc2 = *xc2 ^ *xi;
                        *xc3 = *xc3 ^ *xi;

                        *ofCol0 = *ofCol0 ^ *xi;
                        *ofCol1 = *ofCol1 ^ *xi;


                        --ofCol0;
                        --ofCol1;

                        --xx;
                        --xi;
                        --i;
                    }
                }

                break;
            }
            case osuCrypto::LdpcDiagRegRepeaterEncoder::Weight11:
            {


                auto mainEnd =
                    roundUpTo(
                        *std::max_element(mOffsets.begin(), mOffsets.end())
                        + mGap,
                        32);

                T* __restrict xx = xi - 32;

                for (; i > mainEnd;)
                {
                    for (u64 jj = 0; jj < 32; ++jj)
                    {

                        auto col0 = diagMtx_g32_w11_seed2_t36[i & 31][0];
                        auto col1 = diagMtx_g32_w11_seed2_t36[i & 31][1];
                        auto col2 = diagMtx_g32_w11_seed2_t36[i & 31][2];
                        auto col3 = diagMtx_g32_w11_seed2_t36[i & 31][3];
                        auto col4 = diagMtx_g32_w11_seed2_t36[i & 31][4];
                        auto col5 = diagMtx_g32_w11_seed2_t36[i & 31][5];
                        auto col6 = diagMtx_g32_w11_seed2_t36[i & 31][6];
                        auto col7 = diagMtx_g32_w11_seed2_t36[i & 31][7];
                        auto col8 = diagMtx_g32_w11_seed2_t36[i & 31][8];
                        auto col9 = diagMtx_g32_w11_seed2_t36[i & 31][9];

                        T* __restrict xc0 = xx + col0;
                        T* __restrict xc1 = xx + col1;
                        T* __restrict xc2 = xx + col2;
                        T* __restrict xc3 = xx + col3;
                        T* __restrict xc4 = xx + col4;
                        T* __restrict xc5 = xx + col5;
                        T* __restrict xc6 = xx + col6;
                        T* __restrict xc7 = xx + col7;
                        T* __restrict xc8 = xx + col8;
                        T* __restrict xc9 = xx + col9;

                        *xc0 = *xc0 ^ *xi;
                        *xc1 = *xc1 ^ *xi;
                        *xc2 = *xc2 ^ *xi;
                        *xc3 = *xc3 ^ *xi;
                        *xc4 = *xc4 ^ *xi;
                        *xc5 = *xc5 ^ *xi;
                        *xc6 = *xc6 ^ *xi;
                        *xc7 = *xc7 ^ *xi;
                        *xc8 = *xc8 ^ *xi;
                        *xc9 = *xc9 ^ *xi;

                        *ofCol0 = *ofCol0 ^ *xi;
                        *ofCol1 = *ofCol1 ^ *xi;


                        --ofCol0;
                        --ofCol1;

                        --xx;
                        --xi;
                        --i;
                    }
                }

                break;
            }
            default:
                throw RTE_LOC;
                break;
            }

            offsets[0] = ofCol0 - x.data();
            offsets[1] = ofCol1 - x.data();

            for (; i != ~u64(0); --i)
            {

                switch (mCode)
                {
                case osuCrypto::LdpcDiagRegRepeaterEncoder::Weight5:

                    for (u64 j = 0; j < 4; ++j)
                    {
                        auto col = diagMtx_g16_w5_seed1_t36[i & 15][j] + i - 16;
                        if (col < mRows)
                            x[col] = x[col] ^ x[i];
                    }
                    break;
                case osuCrypto::LdpcDiagRegRepeaterEncoder::Weight11:

                    for (u64 j = 0; j < 10; ++j)
                    {
                        auto col = diagMtx_g32_w11_seed2_t36[i & 31][j] + i - 32;
                        if (col < mRows)
                            x[col] = x[col] ^ x[i];
                    }
                    break;
                default:
                    break;
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



        template<typename T0,typename T1>
        void cirTransEncode2(span<T0> x0, span<T1> x1)
        {
            assert(mExtend);

            // solves for x such that y = M x, ie x := H^-1 y 
            assert(cols() == x0.size());
            assert(cols() == x1.size());


            constexpr int FIXED_OFFSET_SIZE = 2;
            if (mOffsets.size() != FIXED_OFFSET_SIZE)
                throw RTE_LOC;

            std::vector<u64> offsets(mOffsets.size());
            for (u64 j = 0; j < offsets.size(); ++j)
            {
                offsets[j] = mRows - 1 - mOffsets[j] - mGap;
            }

            u64 i = mRows - 1;
            T0* __restrict ofCol00 = &x0[offsets[0]];
            T0* __restrict ofCol10 = &x0[offsets[1]];
            T1* __restrict ofCol01 = &x1[offsets[0]];
            T1* __restrict ofCol11 = &x1[offsets[1]];
            T0* __restrict xi0 = &x0[i];
            T1* __restrict xi1 = &x1[i];

            switch (mCode)
            {
            case osuCrypto::LdpcDiagRegRepeaterEncoder::Weight5:
            {

                auto mainEnd =
                    roundUpTo(
                        *std::max_element(mOffsets.begin(), mOffsets.end())
                        + mGap,
                        16);

                T0* __restrict xx0 = xi0 - 16;
                T1* __restrict xx1 = xi1 - 16;

                for (; i > mainEnd;)
                {
                    for (u64 jj = 0; jj < 16; ++jj)
                    {

                        auto col0 = diagMtx_g16_w5_seed1_t36[i & 15][0];
                        auto col1 = diagMtx_g16_w5_seed1_t36[i & 15][1];
                        auto col2 = diagMtx_g16_w5_seed1_t36[i & 15][2];
                        auto col3 = diagMtx_g16_w5_seed1_t36[i & 15][3];

                        T0* __restrict xc00 = xx0 + col0;
                        T0* __restrict xc10 = xx0 + col1;
                        T0* __restrict xc20 = xx0 + col2;
                        T0* __restrict xc30 = xx0 + col3;
                        T1* __restrict xc01 = xx1 + col0;
                        T1* __restrict xc11 = xx1 + col1;
                        T1* __restrict xc21 = xx1 + col2;
                        T1* __restrict xc31 = xx1 + col3;

                        *xc00 = *xc00 ^ *xi0;
                        *xc10 = *xc10 ^ *xi0;
                        *xc20 = *xc20 ^ *xi0;
                        *xc30 = *xc30 ^ *xi0;

                        *xc01 = *xc01 ^ *xi1;
                        *xc11 = *xc11 ^ *xi1;
                        *xc21 = *xc21 ^ *xi1;
                        *xc31 = *xc31 ^ *xi1;

                        *ofCol00 = *ofCol00 ^ *xi0;
                        *ofCol10 = *ofCol10 ^ *xi0;
                        *ofCol01 = *ofCol01 ^ *xi1;
                        *ofCol11 = *ofCol11 ^ *xi1;


                        --ofCol00;
                        --ofCol10;
                        --ofCol01;
                        --ofCol11;

                        --xx0;
                        --xx1;
                        --xi0;
                        --xi1;
                        --i;
                    }
                }

                break;
            }
            case osuCrypto::LdpcDiagRegRepeaterEncoder::Weight11:
            {


                auto mainEnd =
                    roundUpTo(
                        *std::max_element(mOffsets.begin(), mOffsets.end())
                        + mGap,
                        32);

                T0* __restrict xx0 = xi0 - 32;
                T1* __restrict xx1 = xi1 - 32;

                for (; i > mainEnd;)
                {
                    for (u64 jj = 0; jj < 32; ++jj)
                    {

                        auto col0 = diagMtx_g32_w11_seed2_t36[i & 31][0];
                        auto col1 = diagMtx_g32_w11_seed2_t36[i & 31][1];
                        auto col2 = diagMtx_g32_w11_seed2_t36[i & 31][2];
                        auto col3 = diagMtx_g32_w11_seed2_t36[i & 31][3];
                        auto col4 = diagMtx_g32_w11_seed2_t36[i & 31][4];
                        auto col5 = diagMtx_g32_w11_seed2_t36[i & 31][5];
                        auto col6 = diagMtx_g32_w11_seed2_t36[i & 31][6];
                        auto col7 = diagMtx_g32_w11_seed2_t36[i & 31][7];
                        auto col8 = diagMtx_g32_w11_seed2_t36[i & 31][8];
                        auto col9 = diagMtx_g32_w11_seed2_t36[i & 31][9];

                        T0* __restrict xc00 = xx0 + col0;
                        T0* __restrict xc10 = xx0 + col1;
                        T0* __restrict xc20 = xx0 + col2;
                        T0* __restrict xc30 = xx0 + col3;
                        T0* __restrict xc40 = xx0 + col4;
                        T0* __restrict xc50 = xx0 + col5;
                        T0* __restrict xc60 = xx0 + col6;
                        T0* __restrict xc70 = xx0 + col7;
                        T0* __restrict xc80 = xx0 + col8;
                        T0* __restrict xc90 = xx0 + col9;

                        T1* __restrict xc01 = xx1 + col0;
                        T1* __restrict xc11 = xx1 + col1;
                        T1* __restrict xc21 = xx1 + col2;
                        T1* __restrict xc31 = xx1 + col3;
                        T1* __restrict xc41 = xx1 + col4;
                        T1* __restrict xc51 = xx1 + col5;
                        T1* __restrict xc61 = xx1 + col6;
                        T1* __restrict xc71 = xx1 + col7;
                        T1* __restrict xc81 = xx1 + col8;
                        T1* __restrict xc91 = xx1 + col9;

                        *xc00 = *xc00 ^ *xi0;
                        *xc10 = *xc10 ^ *xi0;
                        *xc20 = *xc20 ^ *xi0;
                        *xc30 = *xc30 ^ *xi0;
                        *xc40 = *xc40 ^ *xi0;
                        *xc50 = *xc50 ^ *xi0;
                        *xc60 = *xc60 ^ *xi0;
                        *xc70 = *xc70 ^ *xi0;
                        *xc80 = *xc80 ^ *xi0;
                        *xc90 = *xc90 ^ *xi0;

                        *xc01 = *xc01 ^ *xi1;
                        *xc11 = *xc11 ^ *xi1;
                        *xc21 = *xc21 ^ *xi1;
                        *xc31 = *xc31 ^ *xi1;
                        *xc41 = *xc41 ^ *xi1;
                        *xc51 = *xc51 ^ *xi1;
                        *xc61 = *xc61 ^ *xi1;
                        *xc71 = *xc71 ^ *xi1;
                        *xc81 = *xc81 ^ *xi1;
                        *xc91 = *xc91 ^ *xi1;

                        *ofCol00 = *ofCol00 ^ *xi0;
                        *ofCol10 = *ofCol10 ^ *xi0;

                        *ofCol01 = *ofCol01 ^ *xi1;
                        *ofCol11 = *ofCol11 ^ *xi1;


                        --ofCol00;
                        --ofCol10;
                        --ofCol01;
                        --ofCol11;

                        --xx0;
                        --xx1;

                        --xi0;
                        --xi1;
                        --i;
                    }
                }

                break;
            }
            default:
                throw RTE_LOC;
                break;
            }

            offsets[0] = ofCol00 - x0.data();
            offsets[1] = ofCol10 - x0.data();

            for (; i != ~u64(0); --i)
            {

                switch (mCode)
                {
                case osuCrypto::LdpcDiagRegRepeaterEncoder::Weight5:

                    for (u64 j = 0; j < 4; ++j)
                    {
                        auto col = diagMtx_g16_w5_seed1_t36[i & 15][j] + i - 16;
                        if (col < mRows)
                        {
                            x0[col] = x0[col] ^ x0[i];
                            x1[col] = x1[col] ^ x1[i];
                        }
                    }
                    break;
                case osuCrypto::LdpcDiagRegRepeaterEncoder::Weight11:

                    for (u64 j = 0; j < 10; ++j)
                    {
                        auto col = diagMtx_g32_w11_seed2_t36[i & 31][j] + i - 32;
                        if (col < mRows)
                        {
                            x0[col] = x0[col] ^ x0[i];
                            x1[col] = x1[col] ^ x1[i];
                        }
                    }
                    break;
                default:
                    break;
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





        void getPoints(PointList& points, u64 colOffset)
        {
            auto rr = mRows;

            for (u64 i = 0; i < rr; ++i)
            {
                points.push_back({ i, i + colOffset });

                //assert(set.insert({ i, i + colOffset }).second);

                switch (mCode)
                {
                case osuCrypto::LdpcDiagRegRepeaterEncoder::Weight5:

                    for (u64 j = 0; j < 4; ++j)
                    {
                        //auto row = diagMtx_g16_w5_seed1_t36[i & 15].data();

                        auto col = i - 16 + diagMtx_g16_w5_seed1_t36[i & 15][j];
                        //throw RTE_LOC;
                        if (col < mRows)
                            points.push_back({ i, col + colOffset });

                        //assert(set.insert({ mRandColumns(i,j) + i + 1, i + colOffset }).second);
                    }

                    break;
                case osuCrypto::LdpcDiagRegRepeaterEncoder::Weight11:
                    for (u64 j = 0; j < 10; ++j)
                    {
                        //auto row = diagMtx_g16_w5_seed1_t36[i & 15].data();

                        auto col = i - 32 + diagMtx_g32_w11_seed2_t36[i & 31][j];
                        //throw RTE_LOC;
                        if (col < mRows)
                            points.push_back({ i, col + colOffset });

                        //assert(set.insert({ mRandColumns(i,j) + i + 1, i + colOffset }).second);
                    }

                    break;
                default:
                    break;
                }


                for (u64 j = 0; j < mOffsets.size(); ++j)
                {

                    auto col = i - mOffsets[j] - mGap;
                    if (col < mRows)
                        points.push_back({ i, col + colOffset });

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
            PointList points(mRows, cols());
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

            mR.template cirTransEncode<T>(pp);

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


        template<typename T0, typename T1>
        void cirTransEncode2(span<T0> c0, span<T1> c1)
        {
            auto k = cols() - rows();
            assert(c0.size() == cols());
            //assert(m.size() == k);
            setTimePoint("encode_begin");
            span<T0> pp0(c0.subspan(k, rows()));
            span<T1> pp1(c1.subspan(k, rows()));

            //std::cout << "P  ";
            //for (u64 i = 0; i < pp.size(); ++i)
            //    std::cout << int(pp[i]) << " ";
            //std::cout << std::endl;

            mR.template cirTransEncode2<T0,T1>(pp0, pp1);

            setTimePoint("diag");
            //std::cout << "P' ";
            //for (u64 i = 0; i < pp.size(); ++i)
            //    std::cout << int(pp[i]) << " ";
            //std::cout << std::endl;

            mL.template cirTransEncode2<T0,T1>(c0.subspan(0, k), c1.subspan(0, k), pp0, pp1);
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
        void getPoints(PointList& points)
        {
            mL.getPoints(points);
            mR.getPoints(points, mL.cols());
        }

        SparseMtx getMatrix()
        {
            PointList points(rows(), cols());
            getPoints(points);
            return SparseMtx(rows(), cols(), points);
        }
    };
    using ZpDiagEncoder = LdpcCompositEncoder<LdpcZpStarEncoder, LdpcDiagBandEncoder>;
    //using ZpDiagRepEncoder = LdpcCompositEncoder<LdpcZpStarEncoder, LdpcDiagRepeaterEncoder>;
    using S1DiagRepEncoder = LdpcCompositEncoder<LdpcS1Encoder, LdpcDiagRepeaterEncoder>;
    using S1DiagRegRepEncoder = LdpcCompositEncoder<LdpcS1Encoder, LdpcDiagRegRepeaterEncoder>;

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


        void LdpcComposit_RegRepDiagBand_encode_test();
        void LdpcComposit_RegRepDiagBand_Trans_test();


        //void LdpcComposit_ZpDiagRep_encode_test();
        //void LdpcComposit_ZpDiagRep_Trans_test();
    }

}
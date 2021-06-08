#include "LdpcEncoder.h"
//#include <eigen/dense>
#include <set>
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/Timer.h"
#include "LdpcSampler.h"
#include "libOTe/Tools/Tools.h"
namespace osuCrypto
{



    constexpr  std::array<std::array<u8, 4>, 16> LdpcDiagRegRepeaterEncoder::diagMtx_g16_w5_seed1_t36;
    constexpr  std::array<std::array<u8, 10>, 32> LdpcDiagRegRepeaterEncoder::diagMtx_g32_w11_seed2_t36;
    constexpr  std::array<u8, 2> LdpcDiagRegRepeaterEncoder::mOffsets;

    bool LdpcEncoder::init(SparseMtx H, u64 gap)
    {

#ifndef NDEBUG
        for (u64 i = H.cols() - H.rows() + gap, j = 0; i < H.cols(); ++i, ++j)
        {
            auto row = H.row(j);
            assert(row[row.size() - 1] == i);
        }
#endif
        auto c0 = H.cols() - H.rows();
        auto c1 = c0 + gap;
        auto r0 = H.rows() - gap;

        mN = H.cols();
        mM = H.rows();
        mGap = gap;


        mA = H.subMatrix(0, 0, r0, c0);
        mB = H.subMatrix(0, c0, r0, gap);
        mC = H.subMatrix(0, c1, r0, H.rows() - gap);
        mD = H.subMatrix(r0, 0, gap, c0);
        mE = H.subMatrix(r0, c0, gap, gap);
        mF = H.subMatrix(r0, c1, gap, H.rows() - gap);
        mH = std::move(H);

        mCInv.init(mC);

        if (mGap)
        {
            SparseMtx CB;

            // CB = C^-1 B
            mCInv.mult(mB, CB);

            //assert(mC.invert().mult(mB) == CB);
            // Ep = F C^-1 B
            mEp = mF.mult(CB);
            //// Ep = F C^-1 B + E
            mEp += mE;
            mEp = mEp.invert();

            return (mEp.rows() != 0);
        }

        return true;
    }

    void LdpcEncoder::encode(span<u8> c, span<const u8> mm)
    {
        assert(mm.size() == mM);
        assert(c.size() == mN);

        auto s = mM - mGap;
        auto iter = c.begin() + mM;
        span<u8> m(c.begin(), iter);
        span<u8> p(iter, iter + mGap); iter += mGap;
        span<u8> pp(iter, c.end());


        // m = mm
        std::copy(mm.begin(), mm.end(), m.begin());
        std::fill(c.begin() + mM, c.end(), 0);

        // pp = A * m
        mA.multAdd(m, pp);

        if (mGap)
        {
            std::vector<u8> t(s);

            // t = C^-1 pp      = C^-1 A m
            mCInv.mult(pp, t);

            // p = - F t + D m  = -F C^-1 A m + D m
            mF.multAdd(t, p);
            mD.multAdd(m, p);

            // p = - Ep p       = -Ep (-F C^-1 A m + D m)
            t = mEp.mult(p);
            std::copy(t.begin(), t.end(), p.begin());

            // pp = pp + B p    
            mB.multAdd(p, pp);
        }

        // pp = C^-1 pp 
        mCInv.mult(pp, pp);
    }

    void DiagInverter::mult(const SparseMtx& y, SparseMtx& x)
    {
        auto n = mC->rows();
        assert(n == y.rows());
        //assert(n == x.rows());
        //assert(y.cols() == x.cols());

        auto xNumRows = n;
        auto xNumCols = y.cols();

        std::vector<u64>& xCol = x.mDataCol; xCol.reserve(y.mDataCol.size());
        std::vector<u64>
            colSizes(xNumCols),
            rowSizes(xNumRows);

        for (u64 c = 0; c < y.cols(); ++c)
        {
            auto cc = y.col(c);
            auto yIter = cc.begin();
            auto yEnd = cc.end();

            auto xColBegin = xCol.size();
            for (u64 i = 0; i < n; ++i)
            {
                u8 bit = 0;
                if (yIter != yEnd && *yIter == i)
                {
                    bit = 1;
                    ++yIter;
                }

                auto rr = mC->row(i);
                auto mIter = rr.begin();
                auto mEnd = rr.end() - 1;

                auto xIter = xCol.begin() + xColBegin;
                auto xEnd = xCol.end();

                while (mIter != mEnd && xIter != xEnd)
                {
                    if (*mIter < *xIter)
                        ++mIter;
                    else if (*xIter < *mIter)
                        ++xIter;
                    else
                    {
                        bit ^= 1;
                        ++xIter;
                        ++mIter;
                    }
                }

                if (bit)
                {
                    xCol.push_back(i);
                    ++rowSizes[i];
                }
            }
            colSizes[c] = xCol.size();
        }

        x.mCols.resize(colSizes.size());
        auto iter = xCol.begin();
        for (u64 i = 0; i < colSizes.size(); ++i)
        {
            auto end = xCol.begin() + colSizes[i];
            x.mCols[i] = SparseMtx::Col(span<u64>(iter, end));
            iter = end;
        }

        x.mRows.resize(rowSizes.size());
        x.mDataRow.resize(x.mDataCol.size());
        iter = x.mDataRow.begin();
        //auto prevSize = 0ull;
        for (u64 i = 0; i < rowSizes.size(); ++i)
        {
            auto end = iter + rowSizes[i];

            rowSizes[i] = 0;
            //auto ss = rowSizes[i];
            //rowSizes[i] = rowSizes[i] - prevSize;
            //prevSize = ss;

            x.mRows[i] = SparseMtx::Row(span<u64>(iter, end));
            iter = end;
        }

        iter = xCol.begin();
        for (u64 i = 0; i < x.cols(); ++i)
        {
            for (u64 j : x.col(i))
            {
                x.mRows[j][rowSizes[j]++] = i;
            }
        }

    }



    void LdpcZpStarEncoder::init(u64 rows, u64 weight)
    {
        assert(isPrime(rows + 1));
        assert(weight);
        assert(weight <= rows);

        mRows = rows;
        mWeight = weight;

        mP = mRows + 1;
        mY = mP / 2;
        mIdx0 = idxToZp(0);

    }

    //void LdpcZpStarEncoder::init(u64 rows, u64 weight, PRNG& prng)
    //{
    //    init(rows, weight);
    //    struct Collision
    //    {
    //        u64 j0, j1;
    //        u64 alt;
    //    };

    //    std::vector<Collision> collisions;
    //    mRandStarts.reserve(mWeight);
    //    std::set<u64> set;
    //    while (set.size() != mWeight)
    //    {
    //        auto v = prng.get<u64>() % rows + 1;
    //        if (set.insert(v).second)
    //        {
    //            mRandStarts.push_back(v);

    //            for (u64 i = 0; i < mRandStarts.size() - 1; ++i)
    //            {
    //                auto a = i + 1;
    //                //auto
    //            }
    //        }
    //    }
    //}

    std::vector<u64> LdpcZpStarEncoder::getVals()
    {

        std::vector<u64> v(mWeight);
        for (u64 i = 0; i < mWeight; ++i)
            v[i] = mod(i + 1 + mY);
        return v;
    }

    void LdpcZpStarEncoder::encode(span<u8> pp, span<const u8> m)
    {
        auto cols = mRows;
        assert(pp.size() == mRows);
        assert(m.size() == cols);

        // pp = A * m

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

                pp[row] ^= m[i];

                v[j] = mod(v[j] + j + 1);
            }
        }
    }



    void tests::LdpcEncoder_diagonalSolver_test()
    {
        u64 n = 10;
        //u64 m = n;
        u64 w = 4;
        u64 t = 10;

        oc::PRNG prng(block(0, 0));
        std::vector<u8> x(n), y(n);
        for (u64 tt = 0; tt < t; ++tt)
        {
            SparseMtx H = sampleTriangular(n, 0.5, prng);

            //std::cout << H << std::endl;

            for (auto& yy : y)
                yy = prng.getBit();

            DiagInverter HInv(H);

            HInv.mult(y, x);

            auto z = H.mult(x);

            assert(z == y);

            auto Y = sampleFixedColWeight(n, w, 3, prng, false);

            SparseMtx X;

            HInv.mult(Y, X);

            auto Z = H * X;

            assert(Z == Y);

        }




        return;
    }

    void tests::LdpcEncoder_encode_test()
    {

        u64 rows = 16;
        u64 cols = rows * 2;
        u64 colWeight = 4;
        u64 dWeight = 3;
        u64 gap = 6;

        auto k = cols - rows;

        assert(gap >= dWeight);

        oc::PRNG prng(block(0, 2));


        SparseMtx H;
        LdpcEncoder E;


        //while (b)
        for (u64 i = 0; i < 40; ++i)
        {
            bool b = true;
            //std::cout << " +====================" << std::endl;
            while (b)
            {
                H = sampleTriangularBand(
                    rows, cols,
                    colWeight, gap,
                    dWeight, false, prng);
                //H = sampleTriangular(rows, cols, colWeight, gap, prng);
                b = !E.init(H, gap);
            }

            //std::cout << H << std::endl;

            std::vector<u8> m(k), c(cols);

            for (auto& mm : m)
                mm = prng.getBit();


            E.encode(c, m);

            auto ss = H.mult(c);

            //for (auto sss : ss)
            //    std::cout << int(sss) << " ";
            //std::cout << std::endl;
            assert(ss == std::vector<u8>(H.rows(), 0));

        }
        return;

    }

    void tests::LdpcEncoder_encode_g0_test()
    {

        u64 rows = 17;
        u64 cols = rows * 2;
        u64 colWeight = 4;

        auto k = cols - rows;

        oc::PRNG prng(block(0, 2));


        SparseMtx H;
        LdpcEncoder E;


        //while (b)
        for (u64 i = 0; i < 40; ++i)
        {
            bool b = true;
            //std::cout << " +====================" << std::endl;
            while (b)
            {
                //H = sampleTriangularBand(
                //    rows, cols,
                //    colWeight, 0,
                //    1, false, prng);
                // 
                // 


                H = sampleTriangularBand(
                    rows, cols,
                    colWeight, 8,
                    colWeight, colWeight, 0,0, { 5,31 }, true, true,true, prng, prng);
                //H = sampleTriangular(rows, cols, colWeight, gap, prng);
                b = !E.init(H, 0);
            }

            //std::cout << H << std::endl;

            std::vector<u8> m(k), c(cols);

            for (auto& mm : m)
                mm = prng.getBit();


            E.encode(c, m);

            auto ss = H.mult(c);

            //for (auto sss : ss)
            //    std::cout << int(sss) << " ";
            //std::cout << std::endl;
            assert(ss == std::vector<u8>(H.rows(), 0));

        }
        return;

    }

    void tests::LdpcEncoder_encode_Trans_g0_test()
    {
        //u64 rows = 70;
        //u64 colWeight = 4;

        u64 rows = nextPrime(100) - 1;
        u64 colWeight = 5;
        u64 gap = 8;
        u64 gapWeight = 5;
        std::vector<u64> lowerDiags{ 5, 31 };

        u64 cols = rows * 2;
        auto k = cols - rows;

        oc::PRNG prng(ZeroBlock);

        SparseMtx H;
        LdpcEncoder E;

        for (u64 i = 0; i < 1; ++i)
        {
            bool b = true;
            //std::cout << " +====================" << std::endl;
            while (b)
            {
                //H = sampleTriangularBand(
                //    rows, cols,
                //    colWeight, 0,
                //    1, false, prng);


                //H = sampleTriangularBand(
                //    rows, cols,
                //    colWeight, 8,
                //    colWeight, colWeight, 0, { 5,31 }, true, true, prng);
                // 



                ZpDiagEncoder enc;
                enc.mL.init(rows, colWeight);
                enc.mR.init(rows, gap, gapWeight, lowerDiags, true, prng);

                H = enc.getMatrix();
                
                //H = sampleTriangular(rows, cols, colWeight, gap, prng);
                b = !E.init(H, 0);
            }

            std::vector<u8> c(cols), m(k);

            for (auto& cc : c)
                cc = prng.getBit();

            auto m2 = c;
            E.cirTransEncode<u8>(m2);
            m2.resize(k);

            auto HD = H.dense();
            auto Gt = computeGen(HD).transpose();
            //std::cout << H << std::endl;

            //auto m = c * Gt;
            assert(Gt.cols() == k);
            assert(Gt.rows() == cols);
            for (u64 i = 0; i < k; ++i)
            {
                for (u64 j = 0; j < cols; ++j)
                {
                    if (Gt(j, i))
                        m[i] ^= c[j];
                }
            }
            //m = computeGen(H.dense()).sparse() * c;

            if (m != m2)
            {
                throw std::runtime_error(LOCATION);
            }

        }

    }

    void tests::LdpcZpStarEncoder_encode_test()
    {
        u64 rows = nextPrime(100) - 1;
        u64 weight = 5;

        LdpcZpStarEncoder zz;
        zz.init(rows, weight);

        std::vector<u8> m(rows), pp(rows);

        PRNG prng(ZeroBlock);

        for (u64 i = 0; i < rows; ++i)
            m[i] = prng.getBit();

        zz.encode(pp, m);

        auto p2 = zz.getMatrix().mult(m);

        if (p2 != pp)
        {
            throw RTE_LOC;
        }

    }



    void tests::LdpcZpStarEncoder_encode_Trans_test()
    {
        u64 rows = nextPrime(100) - 1;
        u64 weight = 5;

        LdpcZpStarEncoder zz;
        zz.init(rows, weight);

        std::vector<u8> m(rows), pp(rows);

        PRNG prng(ZeroBlock);

        for (u64 i = 0; i < rows; ++i)
            m[i] = prng.getBit();

        zz.cirTransEncode<u8>(pp, m);

        auto p2 = zz.getMatrix().dense().transpose().sparse().mult(m);

        if (p2 != pp)
        {
            throw RTE_LOC;
        }

    }


    void tests::LdpcS1Encoder_encode_test()
    {
        u64 rows = 100;
        u64 weight = 5;

        LdpcS1Encoder zz;
        zz.init(rows, weight);

        std::vector<u8> m(rows), pp(rows);

        PRNG prng(ZeroBlock);

        for (u64 i = 0; i < rows; ++i)
            m[i] = prng.getBit();

        zz.encode(pp, m);

        auto p2 = zz.getMatrix().mult(m);

        if (p2 != pp)
        {
            throw RTE_LOC;
        }

    }



    void tests::LdpcS1Encoder_encode_Trans_test()
    {
        u64 rows = 100;
        u64 weight = 5;

        LdpcS1Encoder zz;
        zz.init(rows, weight);

        std::vector<u8> m(rows), pp(rows);

        PRNG prng(ZeroBlock);

        for (u64 i = 0; i < rows; ++i)
            m[i] = prng.getBit();

        zz.cirTransEncode<u8>(pp, m);

        auto p2 = zz.getMatrix().dense().transpose().sparse().mult(m);

        if (p2 != pp)
        {
            throw RTE_LOC;
        }

    }

    void tests::LdpcDiagBandEncoder_encode_test()
    {

        u64 rows = nextPrime(100) - 1;
        u64 weight = 5;
        u64 gap = 16;
        std::vector<u64> lowerDiags{ 5, 31 };
        PRNG prng(ZeroBlock);

        LdpcDiagBandEncoder zz;
        zz.init(rows, gap, weight, lowerDiags, true, prng);

        std::vector<u8> m(rows), pp(rows);


        //std::cout << zz.getMatrix() << std::endl;

        for (u64 i = 0; i < rows; ++i)
            m[i] = prng.getBit();

        zz.encode(pp, m);

        auto m2 = zz.getMatrix().mult(pp);

        if (m2 != m)
        {
            throw RTE_LOC;
        }

    }

    void tests::LdpcComposit_ZpDiagBand_encode_test()
    {

        u64 rows = nextPrime(100) - 1;
        u64 colWeight = 5;
        u64 gap = 16;
        u64 gapWeight = 5;
        std::vector<u64> lowerDiags{ 5, 31 };

        using ZpDiagEncoder = LdpcCompositEncoder<LdpcZpStarEncoder, LdpcDiagBandEncoder>;
        PRNG prng(ZeroBlock);

        ZpDiagEncoder enc;
        enc.mL.init(rows, colWeight);
        enc.mR.init(rows, gap, gapWeight, lowerDiags, true, prng);

        auto H = enc.getMatrix();
        auto HD = H.dense();
        auto G = computeGen(HD).transpose();


        LdpcEncoder enc2;
        enc2.init(H, 0);


        auto cols = enc.cols();
        auto k=  cols - rows;
        std::vector<u8> m(k), c(cols), c2(cols);

        for (auto& mm : m)
            mm = prng.getBit();


        enc.encode<u8>(c, m);

        enc2.encode(c2, m);

        auto ss = H.mult(c);

        //for (auto sss : ss)
        //    std::cout << int(sss) << " ";
        //std::cout << std::endl;
        if (ss != std::vector<u8>(H.rows(), 0))
            throw RTE_LOC;
        if (c2 != c)
            throw RTE_LOC;

    }

    void tests::LdpcComposit_ZpDiagBand_Trans_test()
    {

        u64 rows = nextPrime(100) - 1;
        u64 colWeight = 5;
        u64 gap = 8;
        u64 gapWeight = 5;
        std::vector<u64> lowerDiags{ 5, 31 };

        using ZpDiagEncoder = LdpcCompositEncoder<LdpcZpStarEncoder, LdpcDiagBandEncoder>;
        PRNG prng(ZeroBlock);

        ZpDiagEncoder enc;
        enc.mL.init(rows, colWeight);
        enc.mR.init(rows, gap, gapWeight, lowerDiags, true, prng);

        auto H = enc.getMatrix();
        auto HD = H.dense();
        auto Gt = computeGen(HD).transpose();


        LdpcEncoder enc2;
        enc2.init(H, 0);


        auto cols = enc.cols();
        auto k = cols - rows;

        std::vector<u8> c(cols);

        for (auto& cc : c)
            cc = prng.getBit();
        //std::cout << "\n";

        auto mOld = c;
        enc2.cirTransEncode<u8>(mOld);
        mOld.resize(k);


        auto mCur = c;
        enc.cirTransEncode<u8>(mCur);
        mCur.resize(k);



        //std::cout << H << std::endl;
        std::vector<u8> mMan(k);

        //auto m = c * Gt;
        assert(Gt.cols() == k);
        assert(Gt.rows() == cols);
        for (u64 i = 0; i < k; ++i)
        {
            for (u64 j = 0; j < cols; ++j)
            {
                if (Gt(j, i))
                    mMan[i] ^= c[j];
            }
        }

        if (mMan != mCur || mOld != mCur)
        {

            std::cout << "mCur ";
            for (u64 i = 0; i < mCur.size(); ++i)
                std::cout << int(mCur[i]) << " ";
            std::cout << std::endl;

            std::cout << "mOld ";
            for (u64 i = 0; i < mOld.size(); ++i)
                std::cout << int(mOld[i]) << " ";
            std::cout << std::endl;

            std::cout << "mMan ";
            for (u64 i = 0; i < mMan.size(); ++i)
                std::cout << int(mMan[i]) << " ";
            std::cout << std::endl;

            throw std::runtime_error(LOCATION);
        }


    }


    //void tests::LdpcComposit_ZpDiagRep_encode_test()
    //{

    //    u64 rows = nextPrime(100) - 1;
    //    u64 colWeight = 11;
    //    u64 gap = 32;
    //    u64 gapWeight = 11;
    //    std::vector<u64> lowerDiags{ 5, 31 };
    //    u64 period = 23;

    //    PRNG prng(ZeroBlock);

    //    ZpDiagRepEncoder enc;
    //    enc.mL.init(rows, colWeight);
    //    enc.mR.init(rows, gap, gapWeight, period, lowerDiags, true, prng);

    //    auto H = enc.getMatrix();
    //    //std::cout << H << std::endl;


    //    LdpcEncoder enc2;
    //    enc2.init(H, 0);


    //    auto cols = enc.cols();
    //    auto k = cols - rows;
    //    std::vector<u8> m(k), c(cols), c2(cols);

    //    for (auto& mm : m)
    //        mm = prng.getBit();


    //    enc.encode<u8>(c, m);

    //    enc2.encode(c2, m);

    //    auto ss = H.mult(c);

    //    //for (auto sss : ss)
    //    //    std::cout << int(sss) << " ";
    //    //std::cout << std::endl;
    //    if (ss != std::vector<u8>(H.rows(), 0))
    //        throw RTE_LOC;
    //    if (c2 != c)
    //        throw RTE_LOC;

    //}



    void tests::LdpcComposit_RegRepDiagBand_encode_test()
    {

        u64 rows = nextPrime(100) - 1;
        u64 colWeight = 5;
        LdpcDiagRegRepeaterEncoder::Code code = LdpcDiagRegRepeaterEncoder::Weight11;

        PRNG prng(ZeroBlock);
        using Encoder = LdpcCompositEncoder<LdpcS1Encoder, LdpcDiagRegRepeaterEncoder>;

        Encoder enc;
        enc.mL.init(rows, colWeight);
        enc.mR.init(rows, code, true);

        auto H = enc.getMatrix();
        //std::cout << H << std::endl;


        LdpcEncoder enc2;
        enc2.init(H, 0);


        auto cols = enc.cols();
        auto k = cols - rows;
        std::vector<u8> m(k), c(cols), c2(cols);

        for (auto& mm : m)
            mm = prng.getBit();


        enc.encode<u8>(c, m);

        enc2.encode(c2, m);

        auto ss = H.mult(c);

        //for (auto sss : ss)
        //    std::cout << int(sss) << " ";
        //std::cout << std::endl;
        if (ss != std::vector<u8>(H.rows(), 0))
            throw RTE_LOC;
        if (c2 != c)
            throw RTE_LOC;

    }


    void tests::LdpcComposit_RegRepDiagBand_Trans_test()
    {

        u64 rows = 234;
        u64 colWeight = 5;
        LdpcDiagRegRepeaterEncoder::Code code = LdpcDiagRegRepeaterEncoder::Weight11;
        

        using Encoder = LdpcCompositEncoder<LdpcS1Encoder, LdpcDiagRegRepeaterEncoder>;
        PRNG prng(ZeroBlock);

        Encoder enc;
        enc.mL.init(rows, colWeight);
        enc.mR.init(rows, code, true);

        auto H = enc.getMatrix();
        auto HD = H.dense();
        auto Gt = computeGen(HD).transpose();


        LdpcEncoder enc2;
        enc2.init(H, 0);


        auto cols = enc.cols();
        auto k = cols - rows;

        std::vector<u8> c(cols);

        for (auto& cc : c)
            cc = prng.getBit();
        //std::cout << "\n";

        auto mOld = c;
        enc2.cirTransEncode<u8>(mOld);
        mOld.resize(k);


        auto mCur = c;
        enc.cirTransEncode<u8>(mCur);
        mCur.resize(k);



        ////std::cout << H << std::endl;
        //std::vector<u8> mMan(k);

        ////auto m = c * Gt;
        //assert(Gt.cols() == k);
        //assert(Gt.rows() == cols);
        //for (u64 i = 0; i < k; ++i)
        //{
        //    for (u64 j = 0; j < cols; ++j)
        //    {
        //        if (Gt(j, i))
        //            mMan[i] ^= c[j];
        //    }
        //}

        //if (mMan != mCur || mOld != mCur)
        //{

        //    std::cout << "mCur ";
        //    for (u64 i = 0; i < mCur.size(); ++i)
        //        std::cout << int(mCur[i]) << " ";
        //    std::cout << std::endl;

        //    std::cout << "mOld ";
        //    for (u64 i = 0; i < mOld.size(); ++i)
        //        std::cout << int(mOld[i]) << " ";
        //    std::cout << std::endl;

        //    std::cout << "mMan ";
        //    for (u64 i = 0; i < mMan.size(); ++i)
        //        std::cout << int(mMan[i]) << " ";
        //    std::cout << std::endl;

        //    throw std::runtime_error(LOCATION);
        //}


    }


    //void tests::LdpcComposit_ZpDiagRep_Trans_test()
    //{
    //    Timer tt;
    //    tt.setTimePoint("");
    //    u64 rows = nextPrime(100) - 1;
    //    tt.setTimePoint("prime");
    //    u64 colWeight = 5;
    //    u64 gap = 8;
    //    u64 gapWeight = 5;
    //    u64 period = 23;
    //    std::vector<u64> lowerDiags{ 5, 31 };

    //    PRNG prng(ZeroBlock);

    //    ZpDiagRepEncoder enc;
    //    enc.mL.init(rows, colWeight);
    //    enc.mR.init(rows, gap, gapWeight, period, lowerDiags, true, prng);
    //    tt.setTimePoint("init");

    //    auto H = enc.getMatrix();
    //    tt.setTimePoint("getMatrix");

    //    auto HD = H.dense();
    //    auto Gt = computeGen(HD).transpose();
    //    tt.setTimePoint("computeGen");


    //    auto cols = enc.cols();
    //    auto k = cols - rows;

    //    {
    //        std::vector<u8> pp1(rows), pp2, m1(k), m2;

    //        for (auto& p : pp1)
    //            p = prng.getBit();
    //        for (auto& mm : m1)
    //            mm = prng.getBit();

    //        pp2 = pp1;
    //        m2 = m1;

    //        enc.mL.cirTransEncode<u8>(pp1, m1);
    //        enc.mL.optCirTransEncode<u8>(pp2, m2);

    //        if (pp1 != pp2)
    //            throw RTE_LOC;
    //        if (m1 != m2)
    //            throw RTE_LOC;
    //    }


    //    LdpcEncoder enc2;
    //    enc2.init(H, 0);



    //    std::vector<u8> c(cols);

    //    for (auto& cc : c)
    //        cc = prng.getBit();
    //    //std::cout << "\n";
    //    tt.setTimePoint("init2");

    //    auto mOld = c;
    //    enc2.cirTransEncode<u8>(mOld);
    //    mOld.resize(k);
    //    tt.setTimePoint("encode1");


    //    auto mCur = c;
    //    enc.cirTransEncode<u8>(mCur);
    //    mCur.resize(k);

    //    tt.setTimePoint("encode2");


    //    //std::cout << H << std::endl;
    //    std::vector<u8> mMan(k);

    //    //auto m = c * Gt;
    //    assert(Gt.cols() == k);
    //    assert(Gt.rows() == cols);
    //    for (u64 i = 0; i < k; ++i)
    //    {
    //        for (u64 j = 0; j < cols; ++j)
    //        {
    //            if (Gt(j, i))
    //                mMan[i] ^= c[j];
    //        }
    //    }
    //    tt.setTimePoint("Gt");
    //    //std::cout << tt << std::endl;

    //    if (mMan != mCur || mOld != mCur)
    //    {

    //        std::cout << "mCur ";
    //        for (u64 i = 0; i < mCur.size(); ++i)
    //            std::cout << int(mCur[i]) << " ";
    //        std::cout << std::endl;

    //        std::cout << "mOld ";
    //        for (u64 i = 0; i < mOld.size(); ++i)
    //            std::cout << int(mOld[i]) << " ";
    //        std::cout << std::endl;

    //        std::cout << "mMan ";
    //        for (u64 i = 0; i < mMan.size(); ++i)
    //            std::cout << int(mMan[i]) << " ";
    //        std::cout << std::endl;

    //        throw std::runtime_error(LOCATION);
    //    }


    //}
    void LdpcS1Encoder::init(u64 rows, std::vector<double> rs)
    {
        mRows = rows;
        mWeight = rs.size();
        assert(mWeight > 4);

        mRs = rs;
        mYs.resize(rs.size());
        std::set<u64> s;
        for (u64 i = 0; i < mWeight; ++i)
        {
            mYs[i] = u64(rows * rs[i]) % rows;
            if (s.insert(mYs[i]).second == false)
            {
                throw std::runtime_error("these ratios resulted in a collitions. " LOCATION);
            }
        }
    }
}
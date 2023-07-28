#pragma once
// © 2022 Visa.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// This code implements features described in [Silver: Silent VOLE and Oblivious Transfer from Hardness of Decoding Structured LDPC Codes, https://eprint.iacr.org/2021/1150]; the paper is licensed under Creative Commons Attribution 4.0 International Public License (https://creativecommons.org/licenses/by/4.0/legalcode).
#include "libOTe/config.h"
#ifdef ENABLE_LDPC
#include "Mtx.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <vector>
#include <numeric>
#include "cryptoTools/Common/CLP.h"
#include "cryptoTools/Common/BitVector.h"
#include "Util.h"
#include "libOTe/Tools/Tools.h"
#include <random>

namespace osuCrypto
{

    //inline void push(PointList& p, Point x)
    //{
    //    //for (u64 i = 0; i < p.size(); ++i)
    //    //{
    //    //    if (p[i].mCol == x.mCol && p[i].mRow == x.mRow)
    //    //    {
    //    //        assert(0);
    //    //    }
    //    //}

    //    //std::cout << "{" << x.mRow << ", " << x.mCol << " } " << std::endl;
    //    p.push_back(x);
    //}


    extern std::vector<i64> slopes_, ys_, lastYs_;
    extern std::vector<double> yr_;
    extern bool printDiag;
    // samples a uniform partiy check matrix with
    // each column having weight w.
    inline std::vector<i64> sampleFixedColWeight(
        u64 rows, u64 cols,
        u64 w, u64 diag, bool randY,
        oc::PRNG& prng, PointList& points)
    {
        std::vector<i64>& diagOffsets = lastYs_;
        diagOffsets.clear();

        diag = std::min(diag, w);

        if (slopes_.size() == 0)
            slopes_ = { {1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1} };

        if (slopes_.size() < diag)
            throw RTE_LOC;

        if (diag)
        {
            if (randY)
            {
                yr_.clear();
                std::uniform_real_distribution<> dist(0, 1);
                yr_.push_back(0);
                //s.insert(0);

                while (yr_.size() != diag)
                {
                    auto v = dist(prng);
                    yr_.push_back(v);
                }

                std::sort(yr_.begin(), yr_.end());
                //diagOffsets.insert(diagOffsets.end(), s.begin(), s.end());
            }

            if (yr_.size())
            {
                if (yr_.size() < diag)
                {
                    std::cout << "yr.size() < diag" << std::endl;
                    throw RTE_LOC;
                }
                std::set<u64> ss;
                //ss.insert(0);
                //diagOffsets.resize(diag);

                for (u64 i = 0; ss.size() < diag; ++i)
                {
                    auto p = u64(rows * yr_[i]) % rows;
                    while (ss.insert(p).second == false)
                        p = u64(p + 1) % rows;
                }

                //for (u64 i = 0; i < diag; ++i)
                //{
                //}
                diagOffsets.clear();
                for (auto s : ss)
                    diagOffsets.push_back(s);
            }
            else if (ys_.size())
            {

                if (ys_.size() < diag)
                    throw RTE_LOC;

                diagOffsets = ys_;
                diagOffsets.resize(diag);

            }
            else
            {
                diagOffsets.resize(diag);

                for (u64 i = 0; i < diag; ++i)
                    diagOffsets[i] = rows / 2;
            }

        }
        std::set<u64> set;
        for (u64 i = 0; i < cols; ++i)
        {
            set.clear();
            if (diag && i < rows)
            {
                //assert(diag <= minWeight);
                for (u64 j = 0; j < diag; ++j)
                {
                    i64& r = diagOffsets[j];



                    r = (slopes_[j] + r);

                    if (r >= i64(rows))
                        r -= rows;

                    if (r < 0)
                        r += rows;

                    if (r >= i64(rows) || r < 0)
                    {
                        //std::cout << i << " " << r << " " << rows << std::endl;
                        throw RTE_LOC;
                    }


                    set.insert(r);
                    //auto& pat = patterns[i % patterns.size()];
                    //for (u64 k = 0; k < pat.size(); ++k)
                    //{

                    //    auto nn = set.insert((r + pat[k]) % rows);
                    //    if (!nn.second)
                    //        set.erase(nn.first);
                    //}

                    //auto r2 = (r + 1 + (i & 15)) % rows;
                    //nn = set.insert(r2).second;
                    //if (nn)
                    //    points.push_back({ r2, i });
                }
            }

            for (auto ss : set)
            {
                points.push_back({ ss, i });
            }

            while (set.size() < w)
            {
                auto j = prng.get<u64>() % rows;
                if (set.insert(j).second)
                    points.push_back({ j, i });
            }
        }

        return diagOffsets;
    }

    DenseMtx computeGen(DenseMtx& H);

    // samples a uniform partiy check matrix with
    // each column having weight w.
    inline SparseMtx sampleFixedColWeight(u64 rows, u64 cols, u64 w, oc::PRNG& prng, bool checked)
    {
        PointList points(rows, cols);
        sampleFixedColWeight(rows, cols, w, false, false, prng, points);

        if (checked)
        {
            u64 i = 1;
            SparseMtx H(rows, cols, points);

            auto D = H.dense();
            auto g = computeGen(D);

            while(g.rows() == 0)
            {
                ++i;
                points.mPoints.clear();
                sampleFixedColWeight(rows, cols, w, false, false, prng, points);

                H = SparseMtx(rows, cols, points);
                D = H.dense();
                g = computeGen(D);
            }

            //std::cout << "("<<i<<") " ;


            return H;
        }
        else
            return SparseMtx(rows, cols, points);
    }

    template<typename Iter>
    inline void shuffle(Iter begin, Iter end, oc::PRNG& prng)
    {
        u64 n = u64(end - begin);

        for (u64 i = 0; i < n; ++i)
        {
            auto j = prng.get<u64>() % (n - i);

            std::swap(*begin, *(begin + j));

            ++begin;
        }
    }

    // samples a uniform set of size weight in the 
    // inteveral [begin, end). If diag, then begin 
    // will always be in the set.
    inline std::set<u64> sampleCol(u64 begin, u64 end, u64 mod, u64 weight, bool diag, oc::PRNG& prng)
    {
        //std::cout << "sample " << prng.get<block>() << std::endl;

        std::set<u64> idxs;

        auto n = end - begin;
        if (n < weight)
        {
            std::cout << "n < weight " << LOCATION << std::endl;
            abort();
        }

        if (diag)
        {
            idxs.insert(begin % mod);
            ++begin;
            --n;
            --weight;
        }

        if (n < 3 * weight)
        {
            auto nn = std::min(3 * weight, n);
            std::vector<u64> set(nn);
            std::iota(set.begin(), set.end(), begin);

            shuffle(set.begin(), set.end(), prng);

            //for (u64 i = 0; i < weight; ++i)
            //{
            //    std::cout << set[i] << std::endl;
            //}
            //for(auto s : set)
            //auto iter = set.beg
            for (u64 i = 0; i < weight; ++i)
                idxs.insert((set[i]) % mod);
        }
        else
        {
            while (idxs.size() < weight)
            {
                auto x = prng.get<u64>() % n;
                //std::cout << x << std::endl;
                idxs.insert((x + begin) % mod);
            }
        }

        return idxs;
    }


    inline std::set<u64> sampleCol(u64 begin, u64 end, u64 weight, bool diag, oc::PRNG& prng)
    {
        std::set<u64> idxs;

        auto n = end - begin;
        if (n < weight)
        {
            std::cout << "n < weight " << LOCATION << std::endl;
            abort();
        }

        if (diag)
        {
            idxs.insert(begin);
            ++begin;
            --n;
            --weight;
        }

        if (n < 3 * weight)
        {
            auto nn = std::min(3 * weight, n);
            std::vector<u64> set(nn);
            std::iota(set.begin(), set.end(), begin);

            shuffle(set.begin(), set.end(), prng);

            //for (u64 i = 0; i < weight; ++i)
            //{
            //    std::cout << set[i] << std::endl;
            //}

            idxs.insert(set.begin(), set.begin() + weight);
        }
        else
        {
            while (idxs.size() < weight)
            {
                auto x = prng.get<u64>() % n;
                //std::cout << x << std::endl;
                idxs.insert(x + begin);
            }
        }
        return idxs;
    }



    // sample a parity check which is approx triangular with. 
    // The diagonal will have fixed weight = dWeight.
    // The other columns will have weight = weight.
    inline void sampleTriangular(u64 rows, u64 cols, u64 weight, u64 gap, oc::PRNG& prng, PointList& points)
    {
        auto b = cols - rows + gap;
        sampleFixedColWeight(rows, b, weight, 0, false, prng, points);

        for (u64 i = 0; i < rows - gap; ++i)
        {
            auto w = std::min<u64>(weight - 1, (rows - i) / 2);
            auto s = sampleCol(i + 1, rows, w, false, prng);

            points.push_back({ i, b + i });
            for (auto ss : s)
                points.push_back({ ss, b + i });

        }
    }


    inline void sampleUniformSystematic(u64 rows, u64 cols, oc::PRNG& prng, PointList& points)
    {

        for (u64 i = 0; i < rows; ++i)
        {
            points.push_back({ i, cols - rows + i });

            for (u64 j = 0; j < cols - rows; ++j)
            {
                if (prng.get<bool>())
                {
                    points.push_back({ i,j });
                }
            }
        }


    }

    inline SparseMtx sampleUniformSystematic(u64 rows, u64 cols, oc::PRNG& prng)
    {
        PointList points(rows, cols);
        sampleUniformSystematic(rows, cols, prng, points);
        return SparseMtx(rows, cols, points);
    }

    void sampleRegDiag(
        u64 rows, u64 gap, u64 weight,
        oc::PRNG& prng, PointList& points
    );


    // sample a parity check which is approx triangular with. 
    // The diagonal will have fixed weight = dWeight.
    // The other columns will have weight = weight.
    void sampleRegTriangularBand(
        u64 rows, u64 cols,
        u64 weight, u64 gap,
        u64 dWeight, u64 diag, u64 dDiag, u64 period,
        std::vector<u64> doubleBand,
        bool trim, bool extend, bool randY,
        oc::PRNG& prng, PointList& points);


    // sample a parity check which is approx triangular with. 
    // The diagonal will have fixed weight = dWeight.
    // The other columns will have weight = weight.
    inline void sampleTriangularBand(
        u64 rows, u64 cols,
        u64 weight, u64 gap,
        u64 dWeight, u64 diag, u64 dDiag, u64 period,
        std::vector<u64> doubleBand,
        bool trim, bool extend, bool randY,
        oc::PRNG& lPrng, PRNG& rPrng, PointList& points)
    {
        auto dHeight = gap + 1;

        assert(extend == false || trim == true);
        assert(gap < rows);
        assert(dWeight > 0);
        assert(dWeight <= dHeight);

        if (extend)
        {
            for (u64 i = 0; i < gap; ++i)
            {
                points.push_back({ rows - gap + i, cols - gap + i });
            }
        }

        //auto b = trim ? cols - rows + gap : cols - rows;
        auto b = cols - rows;

        auto diagOffset = sampleFixedColWeight(rows, b, weight, diag, randY, lPrng, points);

        u64 ii = trim ? 0 : rows - gap;
        u64 e = trim ? rows - gap : rows;


        //if (doubleBand.size())
        //{
        //    if (dDiag || !trim)
        //    {
        //        std::cout << "assumed no dDiag and assumed trim" << std::endl;
        //        abort();
        //    }

        //    //for (auto db : doubleBand)
        //    //{
        //    //    assert(db >= 1);

        //    //    for (u64 j = db + gap, c = b; j < rows; ++j, ++c)
        //    //    {
        //    //        points.push_back({ j, c });
        //    //    }
        //    //}
        //}

        if (period && dDiag)
            throw RTE_LOC;

        if (period)
        {
            if (trim == false)
                throw RTE_LOC;

            for (u64 p = 0; p < period; ++p)
            {
                std::set<u64> s;

                auto ww = dWeight - 1;
  
                assert(ww < dHeight);

                s = sampleCol(1, dHeight, ww, false, rPrng);

                for (auto db : doubleBand)
                {
                    assert(db >= 1);
                    u64 j = db + gap;
                    s.insert(j);

                }

                for (u64 i = p; i < e; i += period)
                {

                    points.push_back({ i % rows, b + i });
                    for (auto ss : s)
                    {
                        if(i + ss < rows)
                            points.push_back({ (i+ss), b + i });
                    }
                }

            }
        }
        else
        {

            for (u64 i = 0; i < e; ++i, ++ii)
            {
                auto ww = dWeight - 1;
                for (auto db : doubleBand)
                {
                    assert(db >= 1);
                    u64 j = db + gap + ii;

                    if (j >= rows)
                    {
                        if (dDiag)
                            ++ww;
                    }
                    else
                        points.push_back({ j, b + i });

                }
                assert(ww < dHeight);

                auto s = sampleCol(ii + 1, ii + dHeight, ww, false, rPrng);

                points.push_back({ ii % rows, b + i });
                for (auto ss : s)
                    points.push_back({ ss % rows, b + i });

            }
        }
    }



    // sample a parity check which is approx triangular with. 
    // The diagonal will have fixed weight = dWeight.
    // The other columns will have weight = weight.
    inline SparseMtx sampleTriangularBand(
        u64 rows, u64 cols,
        u64 weight, u64 gap,
        u64 dWeight, u64 diag, oc::PRNG& prng)
    {
        PointList points(rows, cols);
        sampleTriangularBand(rows, cols, weight,
            gap, dWeight, diag, 0, 0,
            {}, false, false, false, prng, prng, points);

        return SparseMtx(rows, cols, points);
    }


    // sample a parity check which is approx triangular with. 
    // The diagonal will have fixed weight = dWeight.
    // The other columns will have weight = weight.
    inline SparseMtx sampleTriangularBand(
        u64 rows, u64 cols,
        u64 weight, u64 gap,
        u64 dWeight, u64 diag, u64 dDiag, u64 period, std::vector<u64> doubleBand,
        bool trim, bool extend, bool randY,
        oc::PRNG& lPrng,
        oc::PRNG& rPrng)
    {
        PointList points(rows, cols);
        sampleTriangularBand(
            rows, cols,
            weight, gap,
            dWeight, diag, dDiag, period, doubleBand, trim, extend, randY,
            lPrng, rPrng, points);

        auto cc = (trim && !extend) ? cols - gap : cols;

        return SparseMtx(rows, cc, points);
    }



    // sample a parity check which is approx triangular with. 
    // The diagonal will have fixed weight = dWeight.
    // The other columns will have weight = weight.
    inline SparseMtx sampleRegTriangularBand(
        u64 rows, u64 cols,
        u64 weight, u64 gap,
        u64 dWeight, u64 diag, u64 dDiag, u64 period, std::vector<u64> doubleBand,
        bool trim, bool extend, bool randY,
        oc::PRNG& prng)
    {
        auto cc = (trim && !extend) ? cols - gap : cols;
        PointList points(rows, cc);
        sampleRegTriangularBand(
            rows, cols,
            weight, gap,
            dWeight, diag, dDiag, period, doubleBand, trim, extend, randY,
            prng, points);


        return SparseMtx(rows, cc, points);
    }


    // sample a parity check which is approx triangular with. 
    // The diagonal will have fixed weight = dWeight.
    // The other columns will have weight = weight.
    inline void sampleTriangularLongBand(
        u64 rows, u64 cols,
        u64 weight, u64 gap,
        u64 dWeight, u64 diag, bool doubleBand,
        oc::PRNG& prng, PointList& points)
    {
        auto dHeight = gap + 1;
        assert(gap < rows);
        assert(dWeight < weight);
        assert(dWeight <= dHeight);

        //sampleFixedColWeight(rows, cols - rows, weight, diag, prng, points);

        std::set<u64> s;
        for (u64 i = 0, ii = rows - gap; i < cols; ++i, ++ii)
        {
            if (doubleBand)
            {
                assert(dWeight >= 2);
                s = sampleCol(ii + 1, ii + dHeight - 1, rows, dWeight - 2, false, prng);
                s.insert((ii + dHeight) % rows);
                //points.push_back({ () % rows, i });
            }
            else
                s = sampleCol(ii + 1, ii + dHeight, rows, dWeight - 1, false, prng);


            s.insert(ii % rows);

            if (i < rows)
            {
                while (s.size() != weight)
                {
                    auto j = prng.get<u64>() % rows;
                    s.insert(j);
                }
            }

            //points.push_back({ ii % rows, i });
            for (auto ss : s)
                points.push_back({ ss % rows, i });



        }
    }

    // sample a parity check which is approx triangular with. 
    // The diagonal will have fixed weight = dWeight.
    // The other columns will have weight = weight.
    inline SparseMtx sampleTriangularLongBand(
        u64 rows, u64 cols,
        u64 weight, u64 gap,
        u64 dWeight, u64 diag, bool doubleBand,
        oc::PRNG& prng)
    {
        PointList points(rows, cols);
        sampleTriangularLongBand(
            rows, cols,
            weight, gap,
            dWeight, diag, doubleBand,
            prng, points);

        return SparseMtx(rows, cols, points);
    }

    //// sample a parity check which is approx triangular with. 
    //// The diagonal will have fixed weight = dWeight.
    //// The other columns will have weight = weight.
    //inline void sampleTriangularBand2(u64 rows, u64 cols, u64 weight, u64 gap, u64 dWeight, oc::PRNG& prng, PointList& points)
    //{
    //    auto dHeight = gap + 1;
    //    assert(dWeight > 0);
    //    assert(dWeight <= dHeight);

    //    sampleFixedColWeight(rows, cols - rows, weight, false, prng, points);

    //    auto b = cols - rows;
    //    for (u64 i = 0, ii = rows - gap; i < rows; ++i, ++ii)
    //    {
    //        if (ii >= rows)
    //        {
    //            auto s = sampleCol(ii + 1, ii + dHeight, dWeight - 1, false, prng);
    //            points.push_back({ ii % rows, b + i });
    //            for (auto ss : s)
    //                points.push_back({ ss % rows, b + i });
    //        }
    //        else
    //        {
    //            auto s = sampleCol(ii, ii + dHeight, dWeight, false, prng);
    //            for (auto ss : s)
    //                points.push_back({ ss % rows, b + i });
    //        }

    //    }
    //}

    //// sample a parity check which is approx triangular with. 
    //// The diagonal will have fixed weight = dWeight.
    //// The other columns will have weight = weight.
    //inline SparseMtx sampleTriangularBand2(u64 rows, u64 cols, u64 weight, u64 gap, u64 dWeight, oc::PRNG& prng)
    //{
    //    PointList points;
    //    sampleTriangularBand2(rows, cols, weight, gap, dWeight, prng, points);
    //    return SparseMtx(rows, cols, points);
    //}


    // sample a parity check which is approx triangular with. 
    // The other columns will have weight = weight.
    inline void sampleTriangular(u64 rows, double density, oc::PRNG& prng, PointList& points)
    {
        assert(density > 0);

        u64 t = static_cast<u64>(~u64{ 0 } *density);

        for (u64 i = 0; i < rows; ++i)
        {
            points.push_back({ i, i });

            for (u64 j = 0; j < i; ++j)
            {
                if (prng.get<u64>() < t)
                {
                    points.push_back({ i, j });
                }
            }
        }
    }

    // sample a parity check which is approx triangular with. 
    // The diagonal will have fixed weight = dWeight.
    // The other columns will have weight = weight.
    inline SparseMtx sampleTriangular(u64 rows, double density, oc::PRNG& prng)
    {
        PointList points(rows, rows);
        sampleTriangular(rows, density, prng, points);
        return SparseMtx(rows, rows, points);
    }


    inline SparseMtx sampleTriangular(u64 rows, u64 cols, u64 weight, u64 gap, oc::PRNG& prng)
    {
        PointList points(rows, cols);
        sampleTriangular(rows, cols, weight, gap, prng, points);
        return SparseMtx(rows, cols, points);
    }



}
#endif
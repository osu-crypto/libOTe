#pragma once
#include "Mtx.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <vector>
#include <numeric>
#include "cryptoTools/Common/CLP.h"
#include "cryptoTools/Common/BitVector.h"

namespace osuCrypto
{

    inline void push(std::vector<Point>& p, Point x)
    {
        //for (u64 i = 0; i < p.size(); ++i)
        //{
        //    if (p[i].mCol == x.mCol && p[i].mRow == x.mRow)
        //    {
        //        assert(0);
        //    }
        //}

        //std::cout << "{" << x.mRow << ", " << x.mCol << " } " << std::endl;
        p.push_back(x);
    }




    // samples a uniform partiy check matrix with
    // each column having weight w.
    inline std::vector<u64> sampleFixedColWeight(
        u64 rows, u64 cols, 
        u64 w, u64 diag, 
        oc::PRNG& prng, std::vector<Point>& points)
    {
        std::vector<u64> diagOffsets;

        std::array<u64, 7> slopes{ {1,2,3,4, 5, 23} };

        if (diag)
        {

            diagOffsets.resize(diag);
            //std::set<u64> s;

            for (u64 i = 0; i < diag; ++i)
                diagOffsets[i]= rows / 2;

            //while (s.size() != diag)
            //    s.insert(prng.get<u64>() % rows);
            //
            //diagOffsets.insert(diagOffsets.end(), s.begin(), s.end());
            //for (u64 j = 0; j < diag; ++j)
                //diagOffsets[j] = prng.get<u64>() % rows;
                //diagOffsets[j] = j * rows / diag;
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
                    u64& r = diagOffsets[j];

                    //if (j & 1)
                    //{
                    //    r -= (slopes[j]);
                    //    if (r > rows)
                    //        r += rows;
                    //}
                    //else
                        r = (slopes[j] + r) % rows;
                    bool nn = set.insert(r).second;

                    if(nn)
                        push(points, { r, i });
                }
            }

            while (set.size() < w)
            {
                //if(i != rows -1)
                //    std::cout << "collide " << i << std::endl;

                auto j = prng.get<u64>() % rows;
                if (set.insert(j).second)
                    push(points, { j, i });
            }
        }

        return diagOffsets;
    }
    DenseMtx computeGen(DenseMtx& H);

    // samples a uniform partiy check matrix with
    // each column having weight w.
    inline SparseMtx sampleFixedColWeight(u64 rows, u64 cols, u64 w, oc::PRNG& prng, bool checked)
    {
        std::vector<Point> points;
        sampleFixedColWeight(rows, cols, w, false, prng, points);

        if (checked)
        {
            SparseMtx H(rows, cols, points);

            auto D = H.dense();
            auto g = computeGen(D);

            if (g.rows() == 0)
            {
                return sampleFixedColWeight(rows, cols, w, prng, checked);
            }
            else
                return H;
        }
        else
            return SparseMtx(rows, cols, points);
    }

    template<typename Iter>
    inline void shuffle(Iter begin, Iter end, oc::PRNG& prng)
    {
        auto n = end - begin;

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
            for(u64 i = 0; i < weight; ++i)
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


    // samples a uniform partiy check matrix with
    // each column having weight w.
    inline void sampleColGroup(
        u64 rows, u64 cols,
        u64 rowWidth, u64 colWidth,
        u64 w,
        u64 numGroups, oc::PRNG& prng, std::vector<Point>& points)
    {
        if(rows < rowWidth * numGroups)
        {
            std::cout << "rows < rowWidth * numGroups " << LOCATION << std::endl;
            abort();
        }
        if (cols < colWidth * numGroups)
        {
            std::cout << "rows < rowWidth * numGroups " << LOCATION << std::endl;
            abort();
        }
        std::set<u64> ss;

        std::set<u64> group;
        std::vector<u64> vec;
        oc::BitVector bv(rowWidth * numGroups);
        for (u64 i = 0; i < cols; i += colWidth)
        {
            group.clear();
            for (u64 j = 0; j < numGroups; ++j)
            {
                auto r = prng.get<u64>() % (rows);

                auto s = group.size();
                //for (u64 k = 0; k < rowWidth; ++k)
                while(group.size() != s +rowWidth)
                {
                    group.insert(r);
                    r = (r + 1) % rows;
                }
            }

            auto e = std::min(cols, i + colWidth);
            vec.clear();
            vec.insert(vec.begin(), group.begin(), group.end());
            if (w)
            {

                for (u64 j = i; j < e; ++j)
                {
                    auto set = sampleCol(0, vec.size(), w, false, prng);
                    for (auto s : set)
                    {
                        assert(ss.insert((vec[s] << 32) + j).second);
                        points.push_back({ vec[s], j });
                    }
                }
            }
            else
            {
                bv.resize(vec.size());
                for (u64 j = i; j < e; ++j)
                {
                    bv.randomize(prng);

                    //auto set = sampleCol(0, rowWidth * numGroups, w, false, prng);
                    for (u64 k = 0; k < bv.size(); ++k)
                        //for (auto s : set)
                    {
                        if (bv[k])
                        {
                            assert(ss.insert((vec[k] << 32) + j).second);
                            points.push_back({ vec[k], j });
                        }
                    }
                }

            }
        }

    }




    // sample a parity check which is approx triangular with. 
    // The diagonal will have fixed weight = dWeight.
    // The other columns will have weight = weight.
    inline void sampleTriangular(u64 rows, u64 cols, u64 weight, u64 gap, oc::PRNG& prng, std::vector<Point>& points)
    {
        auto b = cols - rows + gap;
        sampleFixedColWeight(rows, b, weight, false, prng, points);

        for (u64 i = 0; i < rows - gap; ++i)
        {
            auto w = std::min<u64>(weight - 1, (rows - i) / 2);
            auto s = sampleCol(i + 1, rows, w, false, prng);

            push(points, { i, b + i });
            for (auto ss : s)
                push(points, { ss, b + i });

        }
    }


    inline void sampleUniformSystematic(u64 rows, u64 cols, oc::PRNG& prng, std::vector<Point>& points)
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
        std::vector<Point> points;
        sampleUniformSystematic(rows, cols, prng, points);
        return SparseMtx(rows, cols, points);
    }

    // sample a parity check which is approx triangular with. 
    // The diagonal will have fixed weight = dWeight.
    // The other columns will have weight = weight.
    inline void sampleTriangularBand(
        u64 rows, u64 cols, 
        u64 weight, u64 gap,
        u64 dWeight, u64 diag, u64 dDiag, std::vector<double> doubleBand, bool trim, bool extend,
        oc::PRNG& prng, std::vector<Point>& points)
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

        auto diagOffset = sampleFixedColWeight(rows, b, weight, diag, prng, points);

        u64 ii = trim ? 0 : rows - gap;
        u64 e = trim ? rows - gap : rows;

        std::set<u64> s;
        bool dd = std::find(doubleBand.begin(), doubleBand.end(), 0.0) != doubleBand.end();

        for (u64 i = 0; i < e; ++i, ++ii)
        {
            if (dd)
            {
                assert(dWeight >= 2);
                s = sampleCol(ii + 1, ii + dHeight - 1, dWeight - 2, false, prng);
                push(points, { (ii + dHeight-1) % rows, b + i });
            }
            else
                s = sampleCol(ii + 1, ii + dHeight, dWeight - 1, false, prng);

            push(points, { ii % rows, b + i });
            for (auto ss : s)
                push(points, { ss % rows, b + i });

        }

        if (dDiag)
        {
            //std::set<u64> diagOffset;
            //for(u64 i =0; i < dDiag; ++i)
            //for(u64 j = 1; j <= dDiag; ++j)
            //    diagOffset.insert(j * (rows - gap - 1)/ dDiag);

            //while (diagOffset.size() != dDiag)
            //{
            //    diagOffset.insert(prng.get<u64>() % (rows-gap));
            //}

            //std::vector<u64> diags(diagOffset.begin(), diagOffset.end());

            //std::set<std::pair<u64, u64>> ex;
            //for (auto p : points)
            //{
            //    assert(ex.insert(std::pair<u64, u64>{ p.mRow, p.mCol }).second);
            //}
            //
            //e = trim ? rows -1 - gap : rows- 1;
            for (u64 j = trim? gap : 0, c = b; j < rows-1; ++j, ++c)
            {
                //bool bb = false;
                std::set<u64> s;
                for (u64 i  =0 ; i < diagOffset.size(); ++i)
                {

                    if (i & 1)
                    {
                        --diagOffset[i];
                        if (diagOffset[i] <= j)
                        {
                            diagOffset[i] = rows-1;
                        }
                    }
                    else
                    {
                        ++diagOffset[i];
                    }

                    if (diagOffset[i] < rows && diagOffset[i] > j)
                        s.insert(diagOffset[i]);
                }


                for(auto ss : s)
                    points.push_back({ ss, c });
            }
        }

        if (doubleBand.size())
        {
            if (dDiag || !trim)
            {
                std::cout << "assumed no dDiag and assumed trim" << std::endl;
                abort();
            }

            for (auto db : doubleBand)
            {
                if (db == 0.0)
                    continue;

                assert(db >= 1);

                for (u64 j = db + gap, c = b; j < rows; ++j, ++c)
                {
                    points.push_back({ j, c });
                }
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
        std::vector<Point> points;
        sampleTriangularBand(rows, cols, weight, gap, dWeight, diag, 0, {}, false, false, prng, points);
        return SparseMtx(rows, cols, points);
    }


    // sample a parity check which is approx triangular with. 
    // The diagonal will have fixed weight = dWeight.
    // The other columns will have weight = weight.
    inline SparseMtx sampleTriangularBand(
        u64 rows, u64 cols,
        u64 weight, u64 gap,
        u64 dWeight, u64 diag, u64 dDiag, std::vector<double> doubleBand,
        bool trim, bool extend,
        oc::PRNG& prng)
    {
        std::vector<Point> points;
        sampleTriangularBand(
            rows, cols, 
            weight, gap, 
            dWeight, diag, dDiag, doubleBand, trim, extend,
            prng, points);

        auto cc = (trim && !extend) ? cols - gap : cols;

        return SparseMtx(rows, cc, points);
    }


    // sample a parity check which is approx triangular with. 
    // The diagonal will have fixed weight = dWeight.
    // The other columns will have weight = weight.
    inline void sampleTriangularLongBand(
        u64 rows, u64 cols,
        u64 weight, u64 gap,
        u64 dWeight, u64 diag, bool doubleBand,
        oc::PRNG& prng, std::vector<Point>& points)
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
                s = sampleCol(ii + 1, ii + dHeight - 1,rows, dWeight - 2, false, prng);
                s.insert((ii + dHeight) % rows);
                //push(points, { () % rows, i });
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

            //push(points, { ii % rows, i });
            for (auto ss : s)
                push(points, { ss % rows, i  });



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
        std::vector<Point> points;
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
    //inline void sampleTriangularBand2(u64 rows, u64 cols, u64 weight, u64 gap, u64 dWeight, oc::PRNG& prng, std::vector<Point>& points)
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
    //            push(points, { ii % rows, b + i });
    //            for (auto ss : s)
    //                push(points, { ss % rows, b + i });
    //        }
    //        else
    //        {
    //            auto s = sampleCol(ii, ii + dHeight, dWeight, false, prng);
    //            for (auto ss : s)
    //                push(points, { ss % rows, b + i });
    //        }

    //    }
    //}

    //// sample a parity check which is approx triangular with. 
    //// The diagonal will have fixed weight = dWeight.
    //// The other columns will have weight = weight.
    //inline SparseMtx sampleTriangularBand2(u64 rows, u64 cols, u64 weight, u64 gap, u64 dWeight, oc::PRNG& prng)
    //{
    //    std::vector<Point> points;
    //    sampleTriangularBand2(rows, cols, weight, gap, dWeight, prng, points);
    //    return SparseMtx(rows, cols, points);
    //}


    // sample a parity check which is approx triangular with. 
    // The other columns will have weight = weight.
    inline void sampleTriangular(u64 rows, double density, oc::PRNG& prng, std::vector<Point>& points)
    {
        assert(density > 0);

        u64 t = ~u64{ 0 } *density;

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
        std::vector<Point> points;
        sampleTriangular(rows, density, prng, points);
        return SparseMtx(rows, rows, points);
    }


    inline SparseMtx sampleTriangular(u64 rows, u64 cols, u64 weight, u64 gap, oc::PRNG& prng)
    {
        std::vector<Point> points;
        sampleTriangular(rows, cols, weight, gap, prng, points);
        return SparseMtx(rows, cols, points);
    }



    void sampleExp(oc::CLP& cmd);
}
#include "libOTe/Tools/LDPC/LdpcSampler.h"
#include "libOTe/Tools/LDPC/LdpcEncoder.h"
#include <fstream>
#include "libOTe/Tools/LDPC/Util.h"
#include <thread>

#ifdef ENABLE_ALGO994
extern "C" {
#include "libOTe/Tools/LDPC/Algo994/data_defs.h"
}
#endif

namespace osuCrypto
{

    std::vector<i64> slopes_, ys_, lastYs_;
    std::vector<double> yr_;
    bool printDiag = false;


    void sampleRegDiag(u64 rows, u64 gap, u64 weight, oc::PRNG& prng, PointList& points)
    {

        if (rows < gap * 2)
            throw RTE_LOC;

        auto cols = rows - gap;
        std::vector<u64> rowWeights(cols);
        std::vector<std::set<u64>> rowSets(rows - gap);


        for (u64 c = 0; c < cols; ++c)
        {
            std::set<u64> s;
            //auto remCols = cols - c;

            for (u64 j = 0; j < gap; ++j)
            {
                auto rowIdx = c + j;

                // how many remaining slots are there to the left (speial case at the start)
                u64 remA = std::max<i64>(gap - rowIdx, 0);

                // how many remaining slots there are to the right.
                u64 remB = std::min<u64>(j, cols - c);
                
                u64 rem = remA + remB;


                auto& w = rowWeights[rowIdx % cols];
                auto needed = (weight - w);

                if (needed > rem)
                    throw RTE_LOC;

                if (needed && needed == rem)
                {
                    s.insert(rowIdx);
                    points.push_back({ rowIdx, c });
                    ++w;
                }
            }

            if (s.size() > weight)
                throw RTE_LOC;

            while (s.size() != weight)
            {
                auto j = (prng.get<u8>() % gap);
                auto r = c + j;

                auto& w = rowWeights[r % cols];

                if (w != weight && s.insert(r).second)
                {
                    ++w;
                    points.push_back({ r, c });
                }
            }

            for (auto ss : s)
            {
                rowSets[ss% cols].insert(c);
                if (rowSets[ss % cols].size() > weight)
                    throw RTE_LOC;
            }

            if (c > gap && rowSets[c].size() != weight)
            {
                SparseMtx H(c + gap + 1, c + 1, points);
                std::cout << H << std::endl << std::endl;
                throw RTE_LOC;
            }


        }

        if (printDiag)
        {

            //std::vector<std::vector<u64>> hh;
            SparseMtx H(rows, cols, points);
            std::cout << H << std::endl << std::endl;

            std::cout << "{{\n";


            for (u64 i = 0; i < cols; ++i)
            {
                std::cout << "{{ ";
                bool first = true;
                //hh.emplace_back();

                for (u64 j = 0; j < (u64)H.row(i).size(); ++j)
                {
                    auto c = H.row(i)[j];
                    c = (c + cols - 1 - i) % cols;

                    if (!first)
                        std::cout << ", ";
                    std::cout << c;

                    //hh[i].push_back(H.row(i)[j]);
                    first = false;
                }

                for (u64 j = 0; j < (u64)H.row(i + cols).size(); ++j)
                {

                    auto c = H.row(i+cols)[j];
                    c = (c + cols - 1 - i) % cols;

                    if (!first)
                        std::cout << ", ";
                    std::cout << c;
                    //hh[i].push_back(H.row(i+cols)[j]);
                    first = false;
                }



                std::cout << "}},\n";
            }
            std::cout << "}}"<< std::endl;


            //{
            //    u64 rowIdx = 0;
            //    for (auto row : hh)
            //    {
            //        std::set<u64> s;
            //        std::cout << "(";
            //        for (auto c : row)
            //        {
            //            std::cout << int(c) << " ";
            //            s.insert();
            //        }
            //        std::cout << std::endl << "{";

            //        for (auto c : s)
            //            std::cout << c << " ";
            //        std::cout << std::endl;
            //        ++rowIdx;
            //    }
            //}
        }
    }

    // sample a parity check which is approx triangular with. 
    // The diagonal will have fixed weight = dWeight.
    // The other columns will have weight = weight.
    void sampleRegTriangularBand(u64 rows, u64 cols,
        u64 weight, u64 gap, u64 dWeight,
        u64 diag, u64 dDiag,u64 period,
        std::vector<u64> doubleBand,
        bool trim, bool extend, bool randY,
        oc::PRNG& prng, PointList& points)
    {
        //auto dHeight =;

        assert(extend == false || trim == true);
        assert(gap < rows);
        assert(dWeight > 0);
        assert(dWeight <= gap + 1);

        if (trim == false)
            throw RTE_LOC;


        if (period == 0 || period > rows)
            period = rows;

        if (extend)
        {
            for (u64 i = 0; i < gap; ++i)
            {
                points.push_back({ rows - gap + i, cols - gap + i });
            }
        }

        //auto b = trim ? cols - rows + gap : cols - rows;
        auto b = cols - rows;
        auto diagOffset = sampleFixedColWeight(rows, b, weight, diag, randY, prng, points);
        u64 e = rows - gap;
        auto e2 = cols - gap;


        PointList diagPoints(period + gap, period);
        sampleRegDiag(period + gap, gap, dWeight - 1, prng, diagPoints);
        //std::cout << "cols " << cols << std::endl;
            
        std::set<std::pair<u64, u64>> ss;
        for (u64 i = 0; i < e; ++i)
        {

            points.push_back({ i, b + i });
            if (b + i >= cols)
                throw RTE_LOC;

            //if (ss.insert({ i, b + i }));
            for (auto db : doubleBand)
            {
                assert(db >= 1);
                u64 j = db + gap + i;

                if (j < rows)
                    points.push_back({ j, b + i });
            }
        }

        auto blks = (e + period - 1) / (period);
        for (u64 i = 0; i < blks; ++i)
        {
            auto ii = i * period;
            for (auto p : diagPoints)
            {
                auto r = ii + p.mRow + 1;
                auto c = ii + p.mCol + b;
                if(r < rows && c < e2)
                    points.push_back({ r, c });
            }
        }

    }
}

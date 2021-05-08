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

            SparseMtx H(rows, cols, points);
            std::cout << H << std::endl << std::endl;

            std::cout << "{{\n";


            for (u64 i = 0; i < cols; ++i)
            {
                std::cout << "{{ ";
                bool first = true;

                for (u64 j = 0; j < (u64)H.row(i).size(); ++j)
                {
                    if (!first)
                        std::cout << ", ";
                    std::cout << H.row(i)[j];
                    first = false;
                }

                for (u64 j = 0; j < (u64)H.row(i + cols).size(); ++j)
                {
                    if (!first)
                        std::cout << ", ";
                    std::cout << H.row(i + cols)[j];
                    first = false;
                }



                std::cout << "}},\n";
            }
            std::cout << "}}"<< std::endl;

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


        //for (auto c : colCounts)
        //    std::cout << c << std::endl;
    }


    void sampleExp(oc::CLP& cmd)
    {


        auto rowVec = cmd.getManyOr<u64>("r", { 1000 });

        for (u64 rows : rowVec)
        {


            u64 cols = static_cast<u64>(rows * cmd.getOr("e", 2.0));
            u64 colWeight = cmd.getOr("cw", 5);
            //u64 colGroups = cmd.getOr("cg", colWeight);
            u64 dWeight = cmd.getOr("dw", 3);
            u64 gap = cmd.getOr("g", 12);
            u64 tt = cmd.getOr("t", 1);
            auto ss = oc::sysRandomSeed().as<u64>()[0];
            u64 s = cmd.getOr("s", ss);
            u64 nt = cmd.getOr("nt", std::thread::hardware_concurrency());

            u64 tStart = cmd.getOr("tStart", 0);

            bool uniform = cmd.isSet("u");

#ifdef ENABLE_ALGO994
            alg994 = cmd.getOr("algo", ALG_SAVED);
            num_saved_generators = cmd.getOr("numGen", 5);
            num_cores = (int)nt;
            num_permutations = cmd.getOr("numPerm", 10);
            print_matrices = 0;
#endif


            std::string outPath = cmd.getOr<std::string>("o", "temp.txt");
            bool noEncode = cmd.isSet("ne");

            //auto k = cols - rows;
            //assert(gap >= dWeight);

            SparseMtx H;
            LdpcEncoder E;


            std::vector<u64> dd;
            //double min = 9999999999999, max = 0, avg = 0;
            for (u64 i = tStart; i < tt; ++i)
            {
                //std::cout << "================" << i << "==================\n\n\n" << std::endl;

                oc::PRNG prng(block(i, s));

                if (uniform)
                {
                    if (cmd.isSet("cw"))
                        H = sampleFixedColWeight(rows, cols, colWeight, prng, true);
                    else
                        H = sampleUniformSystematic(rows, cols, prng);
                }
                else
                {
                    bool b = true;
                    u64 tries = 0;
                    while (b)
                    {
                        //if (cmd.isSet("cg"))
                        //    H = sampleTriangularBandGrouped(rows, cols, colWeight, gap, colGroups, dWeight, prng);
                        //else
                        H = sampleTriangularBand(
                            rows, cols,
                            colWeight, gap,
                            dWeight, false, prng);
                        // H = sampleTriangular(rows, cols, colWeight, gap, prng);
                        if (noEncode)
                            break;

                        b = !E.init(H, gap);

                        ++tries;

                        if (tries % 1000)
                            std::cout << "\r" << i << " ... " << tries << std::flush;
                    }
                    if (!noEncode)
                        std::cout << "\rsamples " << tries << "          " << std::endl;
                }







                //if (outPath.size())
                //{

                std::fstream out(outPath, std::fstream::trunc | std::fstream::out);

                if (out.is_open() == false)
                {
                    std::cout << "failed to open: " << outPath << std::endl;
                    return;
                }

                std::vector<std::pair<u64, u64>> swaps;
                auto G = computeGen(H.dense(), swaps);


                if (cmd.isSet("v"))
                {
                    std::cout << "H\n" << H << std::endl;
                    std::cout << "G\n" << G << std::endl;
                }

                out << G.rows() << " " << G.cols() << " matrix dimensions\n"
                    << G << std::endl;

                out.close();

                u64 d;

                if (cmd.isSet("ex"))
                    d = (u64)minDist(H.dense(), true).first;
                else
                    d = minDist(outPath, nt, false);
                dd.push_back(d);
                std::cout << d << " " << std::flush;

                //if (d == 1)
                //{

                //    abort();
                //    auto x = minDist(H.dense(), true);

                //}
                //min = std::min<double>(min, d);
                //max = std::max<double>(max, d);
                //avg += d;

                //}

            }

            auto min = *std::min_element(dd.begin(), dd.end());
            auto max = *std::max_element(dd.begin(), dd.end());
            auto avg = std::accumulate(dd.begin(), dd.end(), 0ull) / double(tt);
            //avg = avg / tt;

            std::cout << "\r";
            if (rowVec.size() > 1)
                std::cout << rows << ": ";

            if (tt == 1)
                std::cout << "d=" << avg << "                    " << std::endl;
            else
            {
                std::cout << min << " " << avg << " " << max << " ~ ";
                for (auto d : dd)
                    std::cout << d << " ";
                std::cout << std::endl;
            }


        }

        return;

    }
}

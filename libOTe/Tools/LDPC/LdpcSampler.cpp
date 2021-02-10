#include "libOTe/Tools/LDPC/LdpcSampler.h"
#include "libOTe/Tools/LDPC/LdpcEncoder.h"
#include <fstream>
#include "libOTe/Tools/LDPC/Util.h"
#include <thread>

extern "C" {
#include "libOTe/Tools/LDPC/Algo994/data_defs.h"
}


namespace osuCrypto
{



    void sampleExp(oc::CLP& cmd)
    {


        auto rowVec = cmd.getManyOr<u64>("r", { 1000 });

        for (u64 rows : rowVec)
        {


            u64 cols = static_cast<u64>(rows * cmd.getOr("e", 2.0));
            u64 colWeight = cmd.getOr("cw", 5);
            u64 colGroups = cmd.getOr("cg", colWeight);
            u64 dWeight = cmd.getOr("dw", 3);
            u64 gap = cmd.getOr("g", 12);
            u64 tt = cmd.getOr("t", 1);
            auto ss = oc::sysRandomSeed().as<u64>()[0];
            u64 s = cmd.getOr("s", ss);
            u64 nt = cmd.getOr("nt", std::thread::hardware_concurrency());

            u64 tStart = cmd.getOr("tStart", 0);

            bool uniform = cmd.isSet("u");

            alg994 = cmd.getOr("algo", ALG_SAVED);
            num_saved_generators = cmd.getOr("numGen", 5);
            num_cores = (int)nt;
            num_permutations = cmd.getOr("numPerm", 10);
            print_matrices = 0;


            std::string outPath = cmd.getOr<std::string>("o", "temp.txt");
            bool noEncode = cmd.isSet("ne");

            auto k = cols - rows;
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
                    if(cmd.isSet("cw"))
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
                    d = (u64) minDist(H.dense(), true).first;
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

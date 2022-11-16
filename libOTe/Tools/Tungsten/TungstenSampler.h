
#include "libOTe/Tools/LDPC/LdpcSampler.h"
#include "cryptoTools/Common/CLP.h"
#include "cryptoTools/Common/Range.h"
#include <iostream>
#include <iomanip>

namespace osuCrypto
{



    inline void sampleTungstenDiag(const CLP& cmd)
    {
        auto row = cmd.getOr("row", 20);
        auto size = cmd.getOr("size", row);
        auto weight = cmd.getOr("w", 5);
        auto shift = cmd.getOr("shift", 2);
        PRNG prng(block(0, cmd.getOr("seed", 0)));

        //PointList points(row, row);
        //printDiag = true;
        ////sampleRegDiag(row, size, weight, prng, points);
        //SparseMtx M(points);
        DenseMtx M(row, row);



        if (size == row)
        {

            Matrix<u64> perms(weight, row);
            for (u64 i : rng(weight))
            {
                auto p = perms[i];
                std::iota(p.begin(), p.end(), 0ull);
            }
            for (u64 i : rng(row))
            {
                std::set<u64> col;
                u64 j = 0;
                while (col.size() < weight)
                {
                    auto p = perms[j];
                    auto d = (prng.get<u64>() % (row - i)) + i;
                    std::swap(p[i], p[d]);

                    auto b = col.insert(p[i]);
                    if (b.second)
                    {
                        M(i, p[i]) = 1;
                        ++j;
                    }
                }
            }
        }
        else
        {

            throw RTE_LOC;
            //Matrix<u64> perms(weight, row);
            //for (u64 i : rng(weight))
            //{
            //    auto p = perms[i];
            //    std::iota(p.begin(), p.end(), 0ull);
            //}

            std::vector<std::set<u64>> rem(weight);
            for (u64 i : rng(weight))
            {
                for (u64 j : rng(row))
                    rem[i].insert(j);
            }
            u64 ww = row * weight;
            for (u64 i : rng(row))
            {
                std::set<u64> col;
                u64 j = 0;

                while (j < weight)
                {
                    std::vector<u64> remj;

                    for (u64 k : rng(i, i + size))
                    {
                        auto q = std::min<u64>(k, k - row);
                        if (rem[j].find(q) != rem[j].end() &&
                            col.find(q) == col.end())
                        {
                            remj.push_back(q);
                        }
                    }

                    if (remj.size())
                    {
                        auto q = remj[prng.get<u64>() % remj.size()];
                        rem[j].erase(q);
                        col.insert(q);
                        M(i, q) = 1;
                        --ww;
                        //bad = true;
                        //break;
                    }
                    else
                        std::cout << "**\n";
                    ++j;
                    //auto p = perms[j];
                    //auto d = (prng.get<u64>() % (row - i)) + i;
                    //std::swap(p[i], p[d]);

                    //auto pi = p[i];
                    //auto q = pi - i;
                    //if (q > row)
                    //    q += row;

                    //if (q < size)
                    //{

                    //    auto b = col.insert(pi);
                    //    if (b.second)
                    //    {
                    //        M(i, pi) = 1;
                    //        ++j;
                    //    }
                    //}
                }
                std::cout << M << std::endl;

            }

            std::cout << "\n---------------" << std::endl;

            while (ww)
            {

            }

            //std::vector<std::set<u64>> rem(weight);
            //for (u64 i : rng(weight))
            //{
            //    for (u64 j : rng(row))
            //        rem[i].insert(j);
            //}

            //for (u64 i : rng(row))
            //{
            //    std::set<u64> col;
            //    u64 j = 0;
            //    while (col.size() < weight)
            //    {


            //    }
            //}
        }

        //auto M = sampleRegTriangularBand(row, col, weight, size, dWeight,0, 0, period, {}, trim, ext, 0, prng);

        if(cmd.isSet("v"))
            std::cout << M << std::endl;


        std::cout << "static constexpr  std::array<std::array<u8, "
            << weight <<
            ">, "
            << row <<
            "> tunsten_diagMtx_" << row << "x" << weight << " = \n{{\n";
        for (u64 i : rng(row))
        {
            std::cout << "\t{{ ";
            bool first = true;
            for (auto j : rng(i, row))
            {
                if (M(i, j))
                {
                    if (!std::exchange(first, false))
                        std::cout << ", ";
                    std::cout << std::setw(3) << std::setfill(' ') << j - i + shift;
                }
            }
            //std::cout << "  ";
            for (auto j : rng(i))
            {
                if (M(i, j))
                {
                    if (!std::exchange(first, false))
                        std::cout << ", ";
                    std::cout << std::setw(3) << std::setfill(' ') << j + (row - i) + shift;
                }
            }
            std::cout << " }},\n";

        }
        std::cout << "}};\n";

    }

}


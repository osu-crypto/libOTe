
#include "libOTe/Tools/LDPC/LdpcSampler.h"
#include "cryptoTools/Common/CLP.h"
#include "cryptoTools/Common/Range.h"
#include <iostream>
#include <iomanip>

namespace osuCrypto
{




    inline Matrix<u64> sampleTungstenDiag(u64 row, u64 weight, u64 shift, PRNG& prng)
    {

        DenseMtx M(row, row);
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
                u64 tries = 0;
                while (col.size() < weight)
                {
                    ++tries;
                    if (tries > 10000)
                        return sampleTungstenDiag(row, weight, shift, prng);

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

        Matrix<u64> ret(row, weight);
        for (u64 i : rng(row))
        {
            bool first = true;
            u64 k = 0;
            for (auto j : rng(i, row))
            {
                if (M(i, j))
                {
                    ret(i, k++) = j - i + shift;
                }
            }
            for (auto j : rng(i))
            {
                if (M(i, j))
                {
                    ret(i, k++) = j + (row - i) + shift;
                }
            }

            if (k != weight)
                throw RTE_LOC;
        }
        return ret;
    }


    inline void sampleTungstenDiag(const CLP& cmd)
    {
        auto row = cmd.getOr("row", 20);
        auto weight = cmd.getOr("w", 5);
        auto shift = cmd.getOr("shift", 2);
        PRNG prng(block(0, cmd.getOr("seed", 0)));

        auto M = sampleTungstenDiag(row, weight, shift, prng);

        //auto max = *std::max_element(M.begin(), M.end());
        //auto bit = roundUpTo(max, 8);


        std::cout << "struct TableTungsten" << row << "x" << weight << "{\n"
            << "static constexpr  std::array<std::array<u8, "
            << weight <<
            ">, "
            << row <<
            "> data = \n{{\n";
        for (u64 i : rng(row))
        {
            std::cout << "\t{{ ";
            std::cout << std::setw(3) << std::setfill(' ') << M(i, 0);
            for (auto j : rng(1, weight))
                std::cout << ", " << std::setw(3) << std::setfill(' ') << M(i, j);
            std::cout << " }},\n";
        }
        std::cout << "}};\n};\n";
    }

}


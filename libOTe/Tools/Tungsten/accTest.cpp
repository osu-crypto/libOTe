#include "accTest.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Timer.h"
#include <cmath>
#include <numeric>
#include "TungstenData.h"
#include "TungstenSampler.h"

namespace osuCrypto
{
    //double choose(u64 n, u64 k)
    //{
    //    double v = 1;

    //    while (k)
    //    {

    //        v *= double(n) / k;
    //        --n;
    //        --k;
    //    }

    //    return v;
    //}

    struct Acc
    {
        u64 i = 0;
        u64 state = 1;

        u64 stateSize;
        u64 stateMask;

        u64 accSize;
        u64 accMask;

        u64 sticky;

        Matrix<u64> Table;

        void init(u64 stateSize_, u64 sticky_, u64 weight, PRNG& prng)
        {
            i = 0;
            state = 234;
            stateSize = stateSize_;
            sticky = sticky_;
            if (stateSize > 64)
                throw RTE_LOC;

            if (sticky_ >= stateSize)
                throw RTE_LOC;

            accSize = stateSize - sticky;
            stateMask = (1ull << stateSize) - 1;
            accMask = (1ull << accSize) - 1;

            Table = sampleTungstenDiag(accSize, weight, 0, prng);
        }

        u64 step()
        {
            auto c = 0;// prng.get<u64>() < pct;

            u64 mask = 0;
            if (accSize != Table.rows())
                throw RTE_LOC;

            auto r = i++ % Table.rows();
            auto row = Table[r];
            for (auto j : row)
            {
                assert((j) < accSize);
                mask |= 1ull << (j);
            }

            if (sticky)
                mask |= 1ull << (stateSize - 1);

            state = state << 1 | (c ^ (popcount(mask & state) & 1));
            state &= stateMask;
            return state;
        }

        void print()
        {

            DenseMtx M(Table.rows() * 2, Table.rows());
            for (u64 i = 0; i < Table.rows(); ++i)
            {
                for (u64 k = 0; k < Table.cols(); ++k)
                {
                    auto t = Table(i, k);
                    M(i + t, i) = 1;
                }
            }

            std::cout << M << std::endl;
        }
    };

    void periodTest(const oc::CLP& cmd)
    {
        PRNG prng(block(0, cmd.getOr("seed", 0)));
        auto t = cmd.getOr("t", 1);

        Timer timer;
        timer.setTimePoint("");
        double navg=0;
        for (u64 tt : rng(t))
        {

            Acc acc0, acc1;
            acc0.init(
                cmd.getOr("ss", 9),
                cmd.getOr("sticky", 0),
                cmd.getOr("w", 4),
                prng
            );

            acc1 = acc0;
            auto verbose = cmd.isSet("v");

            if (cmd.isSet("print"))
            {
                acc0.print();
            }

            while (true)
            {
                auto c = 0;// prng.get<u64>() < pct;
                acc0.step();
                acc0.step();
                acc1.step();

                if (acc0.state == acc1.state && (acc0.i % acc0.accSize) == (acc1.i % acc0.accSize))
                {
                    if(verbose)
                        std::cout << "collide " << acc1.i << std::endl;
                    break;
                }
            }

            u64 p = 0;
            auto s = acc0.step();
            if (verbose)
                std::cout << p << " " << s << " " << popcount(s) << std::endl;
            ++p;
            while ((acc0.state != acc1.state) || ((acc0.i % 8) != (acc1.i % 8)))
            {
                auto s = acc0.step();
                if (verbose)
                    std::cout << p << " " << s << " " << popcount(s) << std::endl;
                ++p;
            }

            auto norm = (double(p) / std::pow(2, acc0.accSize));
            auto norm2 = (double(p) / std::pow(2, acc0.stateSize));
            navg += norm;
            std::cout<< tt << " period " 
                << std::setw(10) << std::setfill(' ') << p  << " " 
                << std::setw(8) << std::setfill(' ') << norm << " " 
                << std::setw(8) << std::setfill(' ') << norm2 << std::endl;
            if (verbose)
                std::cout << p++ << " " << acc0.step() << std::endl;

        }

        std::cout << "avg " << navg / t << std::endl;
        timer.setTimePoint("end");
        std::cout << timer << std::endl;
    }

    void accTest(const oc::CLP& cmd)
    {
        // log size of the codeword
        u64 nn = cmd.getOr("nn", 20);

        // size of the accumulator
        u64 stateSize = cmd.getOr("ss", nn);

        // weight of the input word
        u64 w = cmd.getOr("w", 1);

        // weight of the accumulator
        u64 a = cmd.getOr("a", 7);

        // weight of the expander
        u64 c = cmd.getOr("c", 7);


        auto rep = cmd.isSet("rep");
        // 
        u64 n = 1ull << nn;

        u64 tt = cmd.getOr("t", 1);

        u64 numStates = cmd.getOr("ns", 128);

        auto verbose = cmd.isSet("v");

        double pc = 1 - std::pow(1 - w / double(n), c);
        assert(pc < 1);
        u64 pct = ~0ull * pc;
        std::cout << "pc " << pc << std::endl;
        std::cout << "ns " << numStates << std::endl;

        assert(stateSize < 64);
        u64 sticky = cmd.getOr("sticky", 0);
        u64 stateMask = (1ull << stateSize) - 1;

        u64 accSize = stateSize - sticky;
        if (accSize > stateSize)
            throw RTE_LOC;
        u64 accMask = (1ull << accSize) - 1;
        std::vector<u64> counts(stateSize + 1),
            totals;
        Timer timer;
        timer.setTimePoint("");
        for (u64 t = 0; t < tt; ++t)
        {

            PRNG prng(block(t, cmd.getOr("seed", 0)));


            u64 i = 0;
            std::vector<u64> states(numStates), stateStartIdx(numStates);
            std::iota(states.begin(), states.end(), 1);
            for (; i < n; ++i)
            {
                auto c = 0;// prng.get<u64>() < pct;

                u64 mask = 0;
                if (rep)
                {
                    if (accSize != 8)
                        throw RTE_LOC;

                    TableTungsten8x4 table;
                    auto r = i % table.data.size();
                    auto row = table.data[r];
                    for (auto j : row)
                    {
                        assert((j - 2) < accSize);
                        mask |= 1ull << (j - 2);
                    }
                }
                else
                {
                    if (a)
                    {
                        for (u64 j = 0; j < a; ++j)
                            mask |= 1ull << (prng.get<u16>() % (accSize));
                        while (popcount(mask) != a)
                            mask |= 1ull << (prng.get<u16>() % (accSize));
                    }
                    else
                    {
                        mask |= prng.get<u64>() & accMask;
                    }
                }
                if (sticky)
                    mask |= 1ull << (stateSize - 1);

                if (verbose)
                    std::cout << "\t" << BitVector((u8*)&mask, stateSize) << std::endl;
                for (u64 j = 0; j < numStates; ++j)
                {
                    auto& state = states[j];
                    state = state << 1 | (c ^ (popcount(mask & state) & 1));
                    state &= stateMask;

                    ++counts[popcount(state)];

                    if (state == j + 1 && (i % 8) == 0)
                    {
                        std::cout << "period " << j << " " << i << std::endl;
                    }

                    if (state == 0 || ((a & 1) && state == stateMask))
                    {
                        std::cout << "reset " << j << " " << state << " @ i " << i << std::endl;;
                        state = j + 1;
                    }

                    if (verbose)
                        std::cout << i << " " << oc::BitVector((u8*)&state, stateSize) << " " << c << " "
                        << double(popcount(state)) / stateSize << std::endl;
                }

            }

            auto m = oc::log2floor(i);
            totals.resize(std::max<u64>(totals.size(), m + 1));
            ++totals[m];

            //std::cout << "total " << i << std::endl;
        }

        timer.setTimePoint("end");
        std::cout << timer << std::endl;

        for (u64 j = 0; j < counts.size(); ++j)
        {
            std::cout << "c" << j << " " << counts[j] << " = 2^" << std::log2(counts[j]) << std::endl;
        }

        std::cout << "\n";
        for (u64 j = 0; j < totals.size(); ++j)
        {
            if (totals[j])
                std::cout << "t" << j << " " << totals[j] << std::endl;
        }
    }

    double xorPr(double A, double B)
    {
        return A + B - 2 * A * B;
    }

    void accPr(const oc::CLP& cmd)
    {

        // log size of the codeword
        u64 nn = cmd.getOr("nn", 20);

        // size of the accumulator
        u64 stateSize = cmd.getOr("ss", nn);

        // weight of the input word
        u64 w = cmd.getOr("w", 1);

        // weight of the accumulator
        u64 a = cmd.getOr("a", 7);

        // weight of the expander
        u64 c = cmd.getOr("c", 7);

        // 
        u64 n = 1ull << nn;

        u64 tt = cmd.getOr("t", 1);

        u64 steps = cmd.getOr("steps", n);
        double pa = double(a) / stateSize;
        double pc = 1 - std::pow(1 - w / double(n), c);
        assert(pc < 1);
        u64 pct = ~0ull * pc;
        std::cout << "pa " << pa << std::endl;
        std::cout << "pc " << pc << std::endl;

        assert(stateSize < 64);
        u64 stateMask = (1ull << stateSize) - 1;

        const bool sticky = cmd.isSet("sticky");

        PRNG prng(block(0, cmd.getOr("seed", 0)));


        u64 i = 0;
        std::vector<double> state(stateSize);
        state.back() = 1;
        for (; i < steps; ++i)
        {
            double p = 0;// pc;
            for (u64 j = 0; j < stateSize; ++j)
                p = xorPr(p, state[state.size() - 1 - j] * pa);

            state.push_back(p);

            //std::cout << i << " " << p << std::endl;
        }

        std::vector<u64> counts(steps);
        for (u64 t = 0; t < tt; ++t)
        {

            PRNG prng(block(t, cmd.getOr("seed", 0)));


            u64 i = 0;
            u64 state = 1;
            for (; i < steps; ++i)
            {
                auto c = 0;// prng.get<u64>() < pct;

                //u64 mask = prng.get<u64>() & prng.get<u64>();
                u64 mask = 0;
                for (u64 j = 0; j < stateSize; ++j)
                {
                    mask = mask << 1 | (1ull * (prng.get<u64>() < (~0ull * pa)));
                }

                state = state << 1 | (c ^ (popcount(mask & state) & 1));
                state &= stateMask;


                if (state & 1)
                    ++counts[i];
                //std::cout << i << " " << oc::BitVector((u8*)&state, stateSize) << " " << c << " " 
                //    << double(popcount(state)) / stateSize << std::endl;
            }

            //std::cout << "total " << i << std::endl;
        }

        for (u64 i = 0; i < steps; ++i)
            std::cout << i << " " << state[i + stateSize] << " " << double(counts[i]) / tt << std::endl;


        //    for (u64 j = 0; j < stateSize; ++j)
    //            std::cout << "s" << j << " " << cc[j] / double(steps) / tt << std::endl;

            //    auto m = oc::log2floor(i);
            //    totals.resize(std::max<u64>(totals.size(), m + 1));
            //    ++totals[m];

            //for (u64 j = 0; j < stateSize; ++j)
            //{
            //    std::cout << "p" << j << " " << state[state.size() - 1 - j] << std::endl;
            //}

            //std::cout << "\n";
            //for (u64 j = 0; j < totals.size(); ++j)
            //{
            //    if (totals[j])
            //        std::cout << "t" << j << " " << totals[j] << std::endl;
            //}
    }
}
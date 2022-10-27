#include "accTest.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/BitVector.h"

namespace osuCrypto
{
    double choose(u64 n, u64 k)
    {
        double v = 1;
        
        while (k)
        {

            v *= double(n) / k;
            --n;
            --k;
        }

        return v;
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

        // 
        u64 n = 1ull << nn;

        u64 tt = cmd.getOr("t", 1);


        double pc = 1- std::pow(1-w / double(n), c);
        assert(pc < 1);
        u64 pct = ~0ull * pc;
        std::cout << "pc " << pc << std::endl;

        assert(stateSize < 64);
        u64 stateMask = (1ull << stateSize) - 1;

        const bool sticky = cmd.isSet("sticky");
        std::vector<u64> counts(stateSize + 1),
            totals;

        for (u64 t = 0; t < tt; ++t)
        {

            PRNG prng(block(t, cmd.getOr("seed", 0)));


            u64 i = 0;
            u64 state = 1;
            for (; i < n && state; ++i)
            {
                auto c = prng.get<u64>() < pct;

                u64 mask = 0;
                for (u64 j = 0; j < a; ++j)
                    mask |= 1ull << (prng.get<u16>() % (stateSize-sticky));
                while (popcount(mask) != a)
                    mask |= 1ull << (prng.get<u16>() % (stateSize - sticky));
                if (sticky)
                    mask |= 1ull << (stateSize-1);

                state = state << 1 | (c ^ (popcount(mask & state) & 1));
                state &= stateMask;

                ++counts[popcount(state)];

                //std::cout << i << " " << oc::BitVector((u8*)&state, stateSize) << " " << c << " " 
                //    << double(popcount(state)) / stateSize << std::endl;
            }

            auto m = oc::log2floor(i);
            totals.resize(std::max<u64>(totals.size(), m + 1));
            ++totals[m];

            //std::cout << "total " << i << std::endl;
        }


        for (u64 j = 0; j < counts.size(); ++j)
        {
            std::cout <<"c" << j << " " << counts[j] << std::endl;
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
        double pc = 1-std::pow(1- w / double(n), c);
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
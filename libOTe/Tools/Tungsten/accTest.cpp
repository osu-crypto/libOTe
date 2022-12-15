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

    struct color
    {
        BitVector mBv;
        Color cc;
        color(BitVector bv, Color c = Color::Green)
            :mBv(std::move(bv))
            , cc(c)
        {
        }
    };

    inline std::ostream& operator<<(std::ostream& o, const color& c)
    {

        Color cur = Color::Default;
        Color alt = c.cc;
        for (u64 i = 0; i < c.mBv.size(); ++i)
        {
            if (c.mBv[i] != (cur == c.cc))
            {
                o << alt;
                std::swap(alt, cur);
            }

            o << c.mBv[i];
        }

        //if (cur != Color::Default)
        o << Color::White;

        return o;
    }

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
        double navg = 0;
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
                    if (verbose)
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
            std::cout << tt << " period "
                << std::setw(10) << std::setfill(' ') << p << " "
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
        auto ts = cmd.getOr("ts", 0);

        u64 numStates = cmd.getOr("ns", 128);

        auto cc = cmd.getManyOr<u64>("cc", { 0 });
        auto verbose = cmd.isSet("v");

        double pc = 1 - std::pow(1 - w / double(n), c);
        assert(pc < 1);
        u64 pct = ~0ull * pc;
        std::cout << "pc " << pc << std::endl;
        std::cout << "ns " << numStates << std::endl;

        assert(stateSize < 64);
        u64 sticky = cmd.getOr("sticky", 0);
        auto accShift = cmd.getManyOr<u64>("shift", { 0 });
        u64 stateMask = (1ull << stateSize) - 1;

        u64 accSize = stateSize - sticky;
        if (accSize > stateSize)
            throw RTE_LOC;
        u64 accMask = (1ull << accSize) - 1;
        std::vector<u64> counts(stateSize + 1),
            totals;
        Timer timer;

        u64 pattern = 0, patternSize = 0;
        for (auto ss : accShift)
        {
            pattern <<= ss;
            pattern |= 1;
        }


        auto steps = cmd.getManyOr<u64>("steps", {});
        auto stepSize = cmd.getOr<u64>("stepSize", 0);
        u64 jj = 0;
        for (auto s : steps)
        {
            u64 p = 0;
            for (auto i = 0; i < stepSize; i += s)
            {
                p |= 1;
                p <<= s;

            }
                {
                    std::cout << "s " << s << " ex " << jj << std::endl;
                    p <<= jj++;
                    //++jj;
                }
            pattern ^= p;
        }

        timer.setTimePoint("");
        for (u64 t = ts; t < tt; ++t)
        {

            PRNG prng(block(t, cmd.getOr("seed", 0)));


            u64 i = 0;
            std::vector<u64> states(numStates), stateStartIdx(numStates);
            std::iota(states.begin(), states.end(), 1);
            for (; i < n; ++i)
            {
                auto c = prng.get<u64>() < pct;

                //if (i < 10 && !(i & 1))
                //    c = 1;


                //if (i == 10||i==19||i==20)
                //    c = 1;
                if (std::find(cc.begin(), cc.end(), i) != cc.end())
                    c = 1;

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
                        //mask |= prng.get<u64>() & accMask;
                    }
                }

                //if (accShift)
                //{
                //    mask <<= 1;
                //    mask |= 1;
                //    mask <<= 1;

                //    auto ss = accShift -1;
                //    while (ss > 0)
                //    {
                //        mask <<= 1;
                //        mask |= 1;
                //        ss -= 1;
                //    }

                //}
                if (pattern)
                {
                    mask <<= patternSize;
                    mask |= pattern;
                }

                //auto ss = accShift;
                //while (ss > 0)
                //{
                //    mask <<= 2;
                //    mask |= 1;
                //    ss -= 2;
                //}
                //if (accShift)
                //{
                //    mask <<= 1;
                //    mask |= 1;
                //}

                if (sticky)
                    mask |= (1ull << (stateSize - 1)) | 1;

                if (verbose)
                {
                    std::cout << "\t" << color(BitVector((u8*)&mask, stateSize), Color::Red) << std::endl;
                    std::cout << i << "\t" << color(BitVector((u8*)&states[0], stateSize)) << " " << (c ^ (popcount(mask & states[0]) & 1)) << " c " << (int)c << std::endl;

                }
                for (u64 j = 0; j < numStates; ++j)
                {
                    //std::cout << (states[0] >> (stateSize - 1));

                    auto& state = states[j];
                    state = state << 1 | (c ^ (popcount(mask & state) & 1));
                    state &= stateMask;

                    ++counts[popcount(state)];

                    if (state == 0 || ((a & 1) && state == stateMask))
                    {
                        std::cout << "reset t " << t << " j " << j << " st " << state << " @ i " << i << std::endl;;
                        state = j + 1;
                        std::terminate();
                    }

                    //if (verbose)
                    //    std::cout << i << " " << oc::BitVector((u8*)&state, stateSize) << " " << c << " "
                    //    << double(popcount(state)) / stateSize << std::endl;
                }

            }


            //std::terminate();

            auto m = oc::log2floor(i);
            totals.resize(std::max<u64>(totals.size(), m + 1));
            ++totals[m];

            //std::cout << "total " << i << std::endl;
        }

        timer.setTimePoint("end");
        //std::cout << timer << std::endl;


        if (!cmd.isSet("noHist"))
        {

            for (u64 j = 0; j < counts.size(); ++j)
            {
                std::cout << "c " << j << " " << counts[j] << " = 2^" << std::log2(counts[j]) << std::endl;
            }

            std::cout << "\n";
            for (u64 j = 0; j < totals.size(); ++j)
            {
                if (totals[j])
                    std::cout << "t" << j << " " << totals[j] << std::endl;
            }
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
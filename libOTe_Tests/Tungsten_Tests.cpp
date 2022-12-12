
#include "Tungsten_Tests.h"
#include "libOTe/Tools/Tungsten/TungstenEncoder.h"
#include <iomanip>
#include "cryptoTools/Common/Timer.h"
#include "libOTe/Tools/QuasiCyclicCode.h"
using namespace oc;

namespace tests_libOTe
{
    void Tungsten_encode_basic_test(const oc::CLP& cmd)
    {
        auto k = cmd.getOr("k", 16);
        auto n = cmd.getOr("n", k * 2);
        auto bw = cmd.getOr("bw", 5);
        auto aw = cmd.getOr("aw", 8);
        auto sticky = cmd.getOr("ns", 1);
        auto skip = cmd.isSet("skip");
        auto reuse = (Tungsten::RNG)cmd.getOr("rng", 3);
        bool permute = cmd.isSet("permute");

        bool v = cmd.isSet("v");

        if (reuse != Tungsten::RNG::gf128mul &&
            reuse != Tungsten::RNG::prng &&
            reuse != Tungsten::RNG::xoshiro256Plus &&
            reuse != Tungsten::RNG::aeslite
            )
            throw RTE_LOC;

        Tungsten code;
        code.config(k, n, bw, aw, reuse, permute, sticky);
        code.mExtraDiag = cmd.getOr("extra", 0);

        auto A = code.getA();
        auto B = code.getB();
        auto G = B * A;
        std::vector<block> m0(k), m1(k), c0(n), a1(n);

        if (v)
        {
            std::cout << "B\n" << B << std::endl << std::endl;
            std::cout << "A'\n" << code.getAPar() << std::endl << std::endl;
            std::cout << "A\n" << A << std::endl << std::endl;
            std::cout << "G\n" << G << std::endl;
        }

        PRNG prng(ZeroBlock);
        prng.get(c0.data(), c0.size());

        auto a0 = c0;
        code.uniformAccumulate<block>(a0);
        A.multAdd(c0, a1);
        //A.leftMultAdd(c0, a1);
        if (a0 != a1)
        {
            if (v)
            {

                for (u64 i = 0; i < k; ++i)
                    std::cout << std::hex << std::setw(2) << std::setfill('0') << (a0[i]) << " ";
                std::cout << "\n";
                for (u64 i = 0; i < k; ++i)
                    std::cout << std::hex << std::setw(2) << std::setfill('0') << (a1[i]) << " ";
                std::cout << "\n";
            }

            throw RTE_LOC;
        }

        auto cc = c0;
        B.multAdd(cc, m0);
        code.expand<block>(cc, m1);

        if (m0 != m1)
            throw RTE_LOC;

        m0.resize(0);
        m0.resize(k);

        G.multAdd(c0, m0);

        code.cirTransEncode<block>(c0, m1);

        if (m0 != m1)
            throw RTE_LOC;

    }

    struct Perm__
    {
        static constexpr int chunkSize = 8;

        Perm__() = default;
        Perm__(u64 n) : buff(n) {}


        std::vector<block> buff;
        std::vector<block>::iterator mIter;
        void reset()
        {
            mIter = buff.begin();
        }


        void finalize()
        {
        }

        template<typename T>
        OC_FORCEINLINE void apply(T* __restrict x, u64 k)
        {}

        template<bool, typename T>
        OC_FORCEINLINE void applyChunk(T* __restrict x)
        {
            std::copy(x, x + chunkSize, mIter);
            mIter += chunkSize;
        }
    };


    void Tungsten2_encode_basic_test(const oc::CLP& cmd)
    {
        auto k = cmd.getOr("k", 16);
        auto n = cmd.getOr("n", k * 2);
        auto bw = cmd.getOr("bw", 5);
        auto aw = cmd.getOr("aw", 10);
        auto sticky = cmd.getOr("ns", 1);
        auto skip = cmd.isSet("skip");
        auto reuse = (Tungsten::RNG)cmd.getOr("rng", 2);
        bool permute = cmd.isSet("permute");

        bool v = cmd.isSet("v");

        if (reuse != Tungsten::RNG::gf128mul &&
            reuse != Tungsten::RNG::prng &&
            reuse != Tungsten::RNG::xoshiro256Plus
            )
            throw RTE_LOC;
        using Tung = Tungsten2<block, TungstenPerm<block, 8>, TableTungsten8x4>;

        Tung code(n, bw);


        //code.config(k, n, bw, aw, reuse, permute, sticky);

        auto A = code.getA();
        auto P = code.getP().dense();
        auto S = code.getS().dense();
        auto PA = P * A;
        auto APA = A * PA;
        //auto G = S.dense() * PA;
        auto SAPA = S * APA; 
        
        if (v)
        {
            //std::cout << "P\n" << P << std::endl << std::endl;
            std::cout << "A'\n" << code.getAPar() << std::endl << std::endl;
            //std::cout << "S\n" << S << std::endl << std::endl;
            //std::cout << "AP\n" << A * P << std::endl << std::endl;

            std::cout << "A\n" << A << std::endl << std::endl;
            //std::cout << "PA\n" << PA << std::endl << std::endl;
            //std::cout << "APA\n" << A * PA << std::endl;
            std::cout << "SAPA\n" << SAPA << std::endl;
        }

        std::cout << S << std::endl;

        const std::vector<block> c0 = [n]() {
             std::vector<block> c0(n);
            c0[0] = AllOneBlock;
            return c0;
        }();

        PRNG prng(ZeroBlock);


        {
            std::vector<block> a1(n);
            auto tt = c0;
            Tung code(n, bw);
            auto iter = tt.data();
            if (tt.size() % Tung::Table::data.size())
                throw RTE_LOC;
            while (iter != tt.data() + n)
            {
                code.processBlock<true>(iter, tt.data() + tt.size());
                iter += Tung::Table::data.size();
            }
            A.sparse().multAdd(c0, a1);

            if (memcmp(tt.data(), a1.data(), n * sizeof(block)))
            {
                //if (v)
                {

                    for (u64 i = 0; i <n; ++i)
                        std::cout << std::hex   << (tt[i].get<int>(0)&1) << (tt[i] != a1[i] ? "<" : " ");
                    std::cout << "\n";            
                    for (u64 i = 0; i < n; ++i)   
                        std::cout << std::hex   << (a1[i].get<int>(0) & 1) << " ";
                    std::cout << "\n";
                }

                throw RTE_LOC;
            }
        }


        {

            auto tt = c0;
            Tungsten2<block, Perm__, TableTungsten8x4> code(n, bw);
            code.update(tt);
            code.processBlock<true>(code.mBuffer.data(), code.mBuffer.data() + code.mBuffer.size());


            std::vector<block> a1(n);
            A.sparse().multAdd(c0, a1);

            if (memcmp(code.mPerm.buff.data(), a1.data(), n * sizeof(block)))
            {
                //if (v)
                {

                    for (u64 i = 0; i < n; ++i)
                        std::cout << std::hex << (tt[i].get<int>(0) & 1) << (tt[i] != a1[i] ? "<" : " ");
                    std::cout << "\n";
                    for (u64 i = 0; i < n; ++i)
                        std::cout << std::hex << (a1[i].get<int>(0) & 1) << " ";
                    std::cout << "\n";
                }

                throw RTE_LOC;
            }
        }

        {

            auto tt = c0;
            Tung code(n, bw);
            code.update(tt);
            code.processBlock<true>(code.mBuffer.data(), code.mBuffer.data() + code.mBuffer.size());


            std::vector<block> a1(n);
            PA.sparse().multAdd(c0, a1);

            if (memcmp(code.mPerm.mBuffer.data(), a1.data(), n * sizeof(block)))
            {
                //if (v)
                {

                    for (u64 i = 0; i < n; ++i)
                        std::cout << std::hex << (tt[i].get<int>(0) & 1) << (tt[i] != a1[i] ? "<" : " ");
                    std::cout << "\n";
                    for (u64 i = 0; i < n; ++i)
                        std::cout << std::hex << (a1[i].get<int>(0) & 1) << " ";
                    std::cout << "\n";
                }

                throw RTE_LOC;
            }
        }

        {

            auto tt = c0;
            Tung code(n, bw);
            code.update(tt);
            tt.resize(k);
            code.finalize(tt);


            std::vector<block> a0(n);
            APA.sparse().multAdd(c0, a0);

            if (memcmp(code.mPerm.mBuffer.data(), a0.data(), n * sizeof(block)))
            {
                //if (v)
                {

                    for (u64 i = 0; i < k; ++i)
                        std::cout << std::hex << (code.mPerm.mBuffer[i].get<int>(0) & 1) << (code.mPerm.mBuffer[i] != a0[i] ? "<" : " ");
                    std::cout << "\n";
                    for (u64 i = 0; i < k; ++i)
                        std::cout << std::hex << (a0[i].get<int>(0) & 1) << " ";
                    std::cout << "\n";
                }

                throw RTE_LOC;
            }

            std::vector<block> a1(k);
            SAPA.sparse().multAdd(c0, a1);

            if (memcmp(tt.data(), a1.data(), k * sizeof(block)))
            {
                //if (v)
                {

                    for (u64 i = 0; i < k; ++i)
                        std::cout << std::hex << (tt[i].get<int>(0) & 1) << (tt[i] != a1[i] ? "<" : " ");
                    std::cout << "\n";
                    for (u64 i = 0; i < k; ++i)
                        std::cout << std::hex << (a1[i].get<int>(0) & 1) << " ";
                    std::cout << "\n";
                }

                throw RTE_LOC;
            }
        }
    }

    void perm_bench(const oc::CLP& cmd)
    {
        auto n = cmd.getOr("n", 1 << cmd.getOr("nn", 20));
        auto binSize = 1 << cmd.getOr("mm", 10);
        auto tt = cmd.getOr("t", 10);
        PRNG prng(ZeroBlock);
        SqrtPerm sp;
        Perm p;
        static constexpr int step = 8;

        AlignedUnVector<block> x(n);
        sp.init(n, binSize, prng);
        p.init(n / step, prng);
        Timer t, t2;
        sp.setTimer(t2);
        std::cout << n / binSize << " bins of size " << binSize << std::endl;
        t.setTimePoint("b");



        for (u64 i = 0; i < tt; ++i)
            sp.apply<block>(x);
        auto b = t.setTimePoint("sp");
        std::vector<u64> diffs;
        for (u64 i = 0; i < tt; ++i)
        {
            span<std::array<block, step>> x8((std::array<block, step>*)x.data(), x.size() / step);
            p.apply<std::array<block, step>>(x8);
            //p.apply<block>(x);
            auto e = t2.setTimePoint("p");
            diffs.push_back(std::chrono::duration_cast<std::chrono::nanoseconds>(e - b).count());
            b = e;

        }
        t.setTimePoint("p");
        std::cout << t << std::endl;
        std::cout << t2 << std::endl;
        for (u64 i = 0; i < tt; ++i)
            std::cout << diffs[i] / double(n) << " " << diffs[i] << std::endl;


    }


    void Tungsten_encode_basic_bench(const oc::CLP& cmd)
    {
        auto k = cmd.getOr("k", 1 << cmd.getOr("kk", 10));
        auto n = cmd.getOr("n", k * 2);
        auto bw = cmd.getOr("bw", 5);
        auto aw = cmd.getOr("aw", log2ceil(k));
        auto sticky = cmd.getOr("ns", 1);
        auto reuse = (Tungsten::RNG)cmd.getOr("rng", 3);
        auto skip = cmd.isSet("skip");
        auto permute = cmd.getOr("permute", 0);
        auto tt = cmd.getOr("trials", 1);

        bool v = cmd.isSet("v");

        if (reuse != Tungsten::RNG::gf128mul &&
            reuse != Tungsten::RNG::prng &&
            reuse != Tungsten::RNG::xoshiro256Plus &&
            reuse != Tungsten::RNG::aeslite
            )
            throw RTE_LOC;

        u64 step = 1 << cmd.getOr("step", 14);

        if (n % step)
            throw RTE_LOC;
        if (cmd.isSet("or"))
        {
            Tungsten code;
            code.config(k, n, bw, aw, reuse, permute, sticky);
            code.mAccumulatorWeight = cmd.getOr("aaw", 0);
            code.mExtraDiag = cmd.getOr("extra", 0);
            AlignedUnVector<block> m1(k), c0(n);

            oc::Timer timer;
            code.setTimer(timer);
            for (auto t : rng(tt))
            {
                code.cirTransEncode<block>(c0, m1);
            }
            std::cout << timer << std::endl;
        }
        else if (cmd.isSet("reg"))
        {
            TungstanClassic code(n, bw);

            //TungstenAccumulator code(TungstenBinPermuter{ (u64)n, (u64)bw });
            oc::Timer timer;
            code.setTimer(timer);
            //code.setTimer(timer);
            std::vector<block> c0(step, ZeroBlock);
            c0[0] = OneBlock;
            for (auto t : rng(tt))
            {
                code.reset();
                timer.setTimePoint("reset");
                for (u64 j = 0; j < n; j += step)
                {
                    span<block> buff(c0.data(), step);
                    code.update(buff);
                }

                timer.setTimePoint("acc");

                //code.finalize(m1);

                timer.setTimePoint("expand");
                //code.cirTransEncode<block>(c0, m1);
            }


            if (!cmd.isSet("quiet"))
                std::cout << timer << std::endl;

        }
        else if (cmd.isSet("bpm"))
        {
#ifdef ENABLE_BITPOLYMUL
            oc::Timer timer;
            QuasiCyclicCode code;
            auto p = nextPrime(n);
            code.init(p);
            std::vector<block> c0(code.size(), ZeroBlock);
            for (auto t : rng(tt))
            {

                timer.setTimePoint("reset");
                code.encode(c0);
                timer.setTimePoint("encode");
            }



            if (!cmd.isSet("quiet"))
                std::cout << timer << std::endl;
#endif
        }
        else
        {

            //Tungsten code;
            //code.config(k, n, bw, aw, reuse, permute, sticky);
            //code.mAccumulatorWeight = cmd.getOr("aaw", 4);
            AlignedUnVector<block> m1(k)/*, c0(n)*/;

            Tungsten2<> code(n, bw);
            //TungstenAccumulator code(TungstenBinPermuter{ (u64)n, (u64)bw });
            oc::Timer timer;
            code.setTimer(timer);
            //code.setTimer(timer);
            std::vector<block> c0(step, ZeroBlock);
            c0[0] = OneBlock;
            for (auto t : rng(tt))
            {
                code.reset();
                timer.setTimePoint("reset");
                for (u64 j = 0; j < n; j += step)
                {
                    span<block> buff(c0.data(), step);
                    code.update(buff);
                }

                timer.setTimePoint("acc");

                code.finalize(m1);

                timer.setTimePoint("expand");
                //code.cirTransEncode<block>(c0, m1);
            }


            if (!cmd.isSet("quiet"))
                std::cout << timer << std::endl;
        }
    }


}
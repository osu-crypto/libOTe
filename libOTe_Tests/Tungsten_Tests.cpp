
#include "Tungsten_Tests.h"
#include "libOTe/Tools/Tungsten/TungstenEncoder.h"
#include "libOTe/Tools/Tungsten/TungstenEncoder2.h"
#include <iomanip>
#include "cryptoTools/Common/Timer.h"
#include "libOTe/Tools/QuasiCyclicCode.h"
#include "libOTe/Tools/Tungsten/accTest.h"
#include "libOTe/Tools/LDPC/Util.h"

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

            auto H = B * code.getAPar();
            std::cout << "H\n" << H << std::endl;
             
            std::vector<std::pair<u64, u64>> colSwaps;
            auto G2 = computeGen(H.dense(), colSwaps);
            std::cout << "G2\n" << G2 << std::endl;
            for (auto swap : colSwaps)
                std::cout << swap.first << "  " << swap.second << std::endl;

            auto GG = G.dense();// colSwap(G.dense(), colSwaps);
            GG = computeSysGen(GG);
            std::cout << "GG\n" << GG << std::endl;


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

        code.dualEncode<block>(c0, m1);

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

        template<typename T>
        OC_FORCEINLINE void applyChunk(T* __restrict x)
        {
            std::copy(x, x + chunkSize, mIter);
            mIter += chunkSize;
        }
    };


    void Tungsten2_encode_basic_test(const oc::CLP& cmd)
    {
        auto k = cmd.getOr("k", 64);
        auto n = cmd.getOr("n", k * 2);
        auto bw = cmd.getOr("bw", 5);
        auto aw = cmd.getOr("aw", 10);
        auto sticky = cmd.getOr("ns", 1);
        auto skip = cmd.isSet("skip");
        bool permute = cmd.isSet("permute");

        bool v = cmd.isSet("v");

        using Tung = Tungsten2<block, TungstenPerm<block, 8>, TableAcc<block, TableTungsten8x4>>;

        Tung code(n, bw);

        //code.config(k, n, bw, aw, reuse, permute, sticky);

        auto A = code.getA();
        auto P = code.getP().dense();
        auto S = code.getS().dense();
        auto PA = P * A;
        auto APA = A * PA;
        //auto G = S.dense() * PA;
        auto SAPA = S * APA;
        auto SPA = S * PA;

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

        using Table = Tung::Acc::Table;
        {
            std::vector<block> a1(n);
            auto tt = c0;
            Tung code(n, bw);
            auto iter = tt.data();
            if (tt.size() % Table::data.size())
                throw RTE_LOC;
            while (iter != tt.data() + n)
            {
                code.mAcc.processBlock<true>(iter, tt.data() + tt.size(), code.mExpander);
                iter += Table::data.size();
            }
            A.sparse().multAdd(c0, a1);

            if (memcmp(tt.data(), a1.data(), n * sizeof(block)))
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
            Tungsten2<block, Perm__, TableAcc<block, TableTungsten8x4>> code(n, bw);
            code.update(tt);

            code.mAcc.finalize(code.mExpander);
            //code.mAcc.processBlock<true>(code.mBuffer.data(), code.mBuffer.data() + code.mBuffer.size(), code.mExpander);

            //code.processBlock<true>(code.mBuffer.data(), code.mBuffer.data() + code.mBuffer.size());


            std::vector<block> a1(n);
            A.sparse().multAdd(c0, a1);

            if (memcmp(code.mExpander.buff.data(), a1.data(), n * sizeof(block)))
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
            code.mAcc.finalize(code.mExpander);


            std::vector<block> a1(n);
            PA.sparse().multAdd(c0, a1);

            if (memcmp(code.mExpander.mBuffer.data(), a1.data(), n * sizeof(block)))
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


            //span<block> ss = tt;
            //while (ss.size())
            //{
            //    auto step = std::min<u64>(ss.size(), Tung::Acc::blockSize * 4);
            //    code.update(ss.subspan(0, step));
            //    ss = ss.subspan(step);
            //}
            code.update(tt);

            tt.resize(k);
            code.finalize(tt);


            std::vector<block> a0(k);
            SAPA.sparse().multAdd(c0, a0);

            if (memcmp(tt.data(), a0.data(), k * sizeof(block)))
            {
                //if (v)
                {

                    for (u64 i = 0; i < k; ++i)
                        std::cout << std::hex << (code.mExpander.mBuffer[i].get<int>(0) & 1) << (code.mExpander.mBuffer[i] != a0[i] ? "<" : " ");
                    std::cout << "\n";
                    for (u64 i = 0; i < k; ++i)
                        std::cout << std::hex << (a0[i].get<int>(0) & 1) << " ";
                    std::cout << "\n";
                }

                throw RTE_LOC;
            }

            //std::vector<block> a1(k);
            //SAPA.sparse().multAdd(c0, a1);

            //if (memcmp(tt.data(), a1.data(), k * sizeof(block)))
            //{
            //    //if (v)
            //    {

            //        for (u64 i = 0; i < k; ++i)
            //            std::cout << std::hex << (tt[i].get<int>(0) & 1) << (tt[i] != a1[i] ? "<" : " ");
            //        std::cout << "\n";
            //        for (u64 i = 0; i < k; ++i)
            //            std::cout << std::hex << (a1[i].get<int>(0) & 1) << " ";
            //        std::cout << "\n";
            //    }

            //    throw RTE_LOC;
            //}
        }
    }


    void Tungsten2_encode_trans_test(const oc::CLP& cmd)
    {
        auto k = cmd.getOr("k", 64);
        auto n = cmd.getOr("n", k * 2);
        auto bw = cmd.getOr("bw", 5);
        auto aw = cmd.getOr("aw", 10);
        auto sticky = cmd.getOr("ns", 1);
        auto skip = cmd.isSet("skip");
        bool permute = cmd.isSet("permute");

        bool v = cmd.isSet("v");
        PRNG prng(ZeroBlock);

        using Table = TableTungsten16x4;
        using Tung = Tungsten2<block, TungstenPerm<block, 1>, TableAccTrans<block, Table>>;

        Tung code(n, bw);

        //code.config(k, n, bw, aw, reuse, permute, sticky);

        auto A = code.getA();
        auto APar = code.getAPar().dense();
        auto P = code.getP().dense();
        auto S = code.getS().dense();

        //DenseMtx APar(n,n), E(k,n), A(n,n);
        //for (u64 i = 0; i < n; ++i)
        //{
        //    APar(i, i) = 1;
        //    if (i)
        //        APar(i, i - 1) = 1;
        //    for (u64 j = 0; j <= i; ++j)
        //        A(i, j) = 1;

        //}
        //for (u64 i = 0; i < k; ++i)
        //    for (u64 j = 0; j < bw; ++j)
        //        E(i, prng.get<u64>() % n) = 1;

        //auto PAPar = (P * APar);
        //auto AParPAPar = APar * PAPar;
        //auto SAParPAPar = S*AParPAPar;
        ////std::cout << "P\n" << P << std::endl << std::endl;
        //std::cout << "A'\n" << APar << std::endl << std::endl;

        //auto EA = A * P * A;
        //auto EAp = APar * PAPar;
        //for (u64 i = 0; i < n; ++i)
        //{
        //    BitVector a(n), ap(n), pap(n);
        //    for (u64 j = 0; j < n; ++j)
        //    {
        //        a[j] = EA(i, j);
        //        ap[j] = EAp(i, j);
        //        pap[j] = PAPar(i, j);
        //    }
        //    std::cout << color(a, Color::Green, ' ') << std::endl;
        //    std::cout << color(ap, Color::Red, ' ') << std::endl;
        //    //std::cout << color(pap, Color::Blue, ' ') << std::endl;
        //}
        //std::cout << "EA'\n" << E*APar << std::endl << std::endl;
        //std::cout << "PA'\n" << PAPar << std::endl << std::endl;
        //std::cout << "APA'\n" << AParPAPar << std::endl << std::endl;
        //std::cout << "SAPA'\n" << SAParPAPar << std::endl << std::endl;
        //std::cout << "SA'\n" << S * APar << std::endl << std::endl;
        //[i = 43, j = i](){}

        //return;
        auto PA = P * A;
        auto APA = A * PA;
        //auto G = S.dense() * PA;
        auto SAPA = S * APA;
        auto SPA = S * PA;

        if (v)
        {
            auto APar = code.getAPar().dense();
            //std::cout << "P\n" << P << std::endl << std::endl;
            std::cout << "A'\n" << APar << std::endl << std::endl;
            std::cout << "PA'\n" << (P * APar) << std::endl << std::endl;
            std::cout << "APA'\n" << APar * P * APar << std::endl << std::endl;
            std::cout << "SAPA'\n" << S * APar * P * APar << std::endl << std::endl;
            std::cout << "SA'\n" << S * APar << std::endl << std::endl;
            //std::cout << "S\n" << S << std::endl << std::endl;
            //std::cout << "AP\n" << A * P << std::endl << std::endl;

            //std::cout << "A\n" << A << std::endl << std::endl;
            //std::cout << "PA\n" << PA << std::endl << std::endl;
            //std::cout << "APA\n" << A * PA << std::endl;
            //std::cout << "SAPA\n" << SAPA << std::endl;
        }


        const std::vector<block> c0 = [n]() {
            std::vector<block> c0(n);
            c0[0] = AllOneBlock;
            return c0;
        }();


        {
            std::vector<block> a1(n);
            auto tt = c0;
            Tung code(n, bw);
            auto iter = tt.data();
            if (tt.size() % Table::data.size())
                throw RTE_LOC;

            u64 jj = 0;
            while (iter != tt.data() + n)
            {
                code.mAcc.processBlock<true>(iter, tt.data(), tt.data() + tt.size(), code.mExpander);
                iter += Table::data.size();
                ++jj;
            }
            A.sparse().multAdd(c0, a1);

            if (memcmp(tt.data(), a1.data(), n * sizeof(block)))
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
            Tungsten2<block, Perm__, TableAccTrans<block, Table>> code(n, bw);
            code.update(tt);

            code.mAcc.finalize(code.mExpander);
            //code.mAcc.processBlock<true>(code.mBuffer.data(), code.mBuffer.data() + code.mBuffer.size(), code.mExpander);

            //code.processBlock<true>(code.mBuffer.data(), code.mBuffer.data() + code.mBuffer.size());


            std::vector<block> a1(n);
            A.sparse().multAdd(c0, a1);

            if (memcmp(code.mExpander.buff.data(), a1.data(), n * sizeof(block)))
            {
                //if (v)
                {
                    BitVector act(n);
                    BitVector exp(n);

                    for (u64 i = 0; i < n; ++i)
                        act[i] = tt[i].get<u8>(0) & 1;
                    for (u64 i = 0; i < n; ++i)
                        exp[i] = a1[i].get<u8>(0) & 1;

                    std::cout << "act " << color(act) << "\n";
                    std::cout << "exp " << color(exp) << "\n";
                    std::cout << "    " << color(exp ^ act, Color::Red) << "\n";
                }

                throw RTE_LOC;
            }
        }

        {

            auto tt = c0;
            Tung code(n, bw);
            code.update(tt);
            code.mAcc.finalize(code.mExpander);


            std::vector<block> a1(n);
            PA.sparse().multAdd(c0, a1);

            if (memcmp(code.mExpander.mBuffer.data(), a1.data(), n * sizeof(block)))
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
            std::vector<block> w(k);
            Tung code(n, bw);
            code.update(tt);
            code.finalize(w);


            std::vector<block> a1(k);
            SAPA.sparse().multAdd(c0, a1);

            if (memcmp(w.data(), a1.data(), k * sizeof(block)))
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

    void Tungsten2_encode_sum_test(const oc::CLP& cmd)
    {
        auto k = cmd.getOr("k", 1024);
        auto n = cmd.getOr("n", k * 2);
        auto bw = cmd.getOr("bw", 5);
        auto aw = cmd.getOr("aw", 10);
        auto sticky = cmd.getOr("ns", 1);
        auto skip = cmd.isSet("skip");
        bool permute = cmd.isSet("permute");

        bool v = cmd.isSet("v");
        PRNG prng(ZeroBlock);

        using Acc = SumAcc<block>;
        using Perm = TungstenPerm<block, 8>;
        using Tung = Tungsten2<block, Perm, Acc>;

        Tung code(n, bw);


        auto A = code.getA();
        auto APar = code.getAPar().dense();
        auto P = code.getP().dense();
        auto S = code.getS().dense();

        auto PA = P * A;
        auto APA = A * PA;
        //auto G = S.dense() * PA;
        auto SAPA = S * APA;
        auto SPA = S * PA;

        if (v)
        {
            //auto APar = code.getAPar().dense();
            //std::cout << "P\n" << P << std::endl << std::endl;
            std::cout << "A'\n" << APar << std::endl << std::endl;
            //std::cout << "PA'\n" << (P * APar) << std::endl << std::endl;
            //std::cout << "APA'\n" << APar * P * APar << std::endl << std::endl;
            //std::cout << "SAPA'\n" << S * APar * P * APar << std::endl << std::endl;
            //std::cout << "SA'\n" << S * APar << std::endl << std::endl;

            //std::cout << "S\n" << S << std::endl << std::endl;
            //std::cout << "AP\n" << A * P << std::endl << std::endl;

            std::cout << "A\n" << A << std::endl << std::endl;
            std::cout << "PA\n" << PA << std::endl << std::endl;
            std::cout << "APA\n" << A * PA << std::endl;
            std::cout << "SAPA\n" << SAPA << std::endl;
        }


        const std::vector<block> c0 = [n]() {
            std::vector<block> c0(n);
            c0[0] = AllOneBlock;
            return c0;
        }();


        {
            std::vector<block> a1(n);
            auto tt = c0;
            Tung code(n, bw);
            auto iter = tt.data();
            if (tt.size() % Acc::blockSize)
                throw RTE_LOC;

            u64 jj = 0;
            while (iter != tt.data() + n)
            {
                if (iter == tt.data())
                    code.mAcc.processBlock<true>(iter, tt.data(), tt.data() + tt.size(), code.mExpander);
                else
                    code.mAcc.processBlock<false>(iter, tt.data(), tt.data() + tt.size(), code.mExpander);

                iter += Acc::blockSize;
                ++jj;
            }
            A.sparse().multAdd(c0, a1);

            if (memcmp(tt.data(), a1.data(), n * sizeof(block)))
            {
                std::cout << APar << std::endl;
                {
                    BitVector act(n);
                    BitVector exp(n);

                    for (u64 i = 0; i < n; ++i)
                        act[i] = tt[i].get<u8>(0) & 1;
                    for (u64 i = 0; i < n; ++i)
                        exp[i] = a1[i].get<u8>(0) & 1;

                    std::cout << "act " << color(act) << "\n";
                    std::cout << "exp " << color(exp) << "\n";
                    std::cout << "    " << color(exp ^ act, Color::Red) << "\n";
                }

                throw RTE_LOC;
            }
        }

        {

            auto tt = c0;
            std::vector<block> w(k);
            Tung code(n, bw);
            code.update(tt);
            code.finalize(w);


            std::vector<block> a1(k);
            SAPA.sparse().multAdd(c0, a1);

            if (memcmp(w.data(), a1.data(), k * sizeof(block)))
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


    void Tungsten2_encode_APA_test(const oc::CLP& cmd)
    {
        auto k = cmd.getOr("k", 64);
        auto n = cmd.getOr("n", k * 2);
        auto aw = cmd.getOr("aw", 10);
        auto sticky = cmd.getOr("ns", 1);
        auto skip = cmd.isSet("skip");
        bool permute = cmd.isSet("permute");

        bool v = cmd.isSet("v");
        PRNG prng(ZeroBlock);

        using Acc = SumAcc<block>;
        using Acc2 = TableAccTrans<block, TableTungsten128x4>;
        using Perm = TungstenPerm<block, 8>;
        using Tung = Tungsten3<block, Perm, Acc, Acc2>;

        Tung code(n);


        auto A = code.getA();
        auto A2 = Acc2::getA(n);
        //auto APar = code.getAPar().dense();
        auto P = code.getP().dense();
        auto S = code.getS().dense();

        auto PA = P * A;
        auto APA = A2 * PA;
        //auto G = S.dense() * PA;
        auto SAPA = S * APA;
        //auto SPA = S * PA;

        if (v)
        {
            //auto APar = code.getAPar().dense();
            //std::cout << "P\n" << P << std::endl << std::endl;
            //std::cout << "A'\n" << APar << std::endl << std::endl;
            //std::cout << "PA'\n" << (P * APar) << std::endl << std::endl;
            //std::cout << "APA'\n" << APar * P * APar << std::endl << std::endl;
            //std::cout << "SAPA'\n" << S * APar * P * APar << std::endl << std::endl;
            //std::cout << "SA'\n" << S * APar << std::endl << std::endl;

            std::cout << "S\n" << S << std::endl << std::endl;
            //std::cout << "AP\n" << A * P << std::endl << std::endl;

            std::cout << "A\n" << A << std::endl << std::endl;
            std::cout << "PA\n" << PA << std::endl << std::endl;
            std::cout << "APA\n" << A2 * PA << std::endl;
            std::cout << "SAPA\n" << SAPA << std::endl;
        }


        const std::vector<block> c0 = [n]() {
            std::vector<block> c0(n);
            c0[0] = AllOneBlock;
            return c0;
        }();


        {
            std::vector<block> a1(n);
            auto tt = c0;
            Tung code(n);
            auto iter = tt.data();
            if (tt.size() % Acc::blockSize)
                throw RTE_LOC;

            u64 jj = 0;
            while (iter != tt.data() + n)
            {
                if (iter == tt.data())
                    code.mAcc.processBlock<true>(iter, tt.data(), tt.data() + tt.size(), code.mExpander);
                else
                    code.mAcc.processBlock<false>(iter, tt.data(), tt.data() + tt.size(), code.mExpander);

                iter += Acc::blockSize;
                ++jj;
            }
            A.sparse().multAdd(c0, a1);

            if (memcmp(tt.data(), a1.data(), n * sizeof(block)))
            {
                //std::cout << APar << std::endl;
                {
                    BitVector act(n);
                    BitVector exp(n);

                    for (u64 i = 0; i < n; ++i)
                        act[i] = tt[i].get<u8>(0) & 1;
                    for (u64 i = 0; i < n; ++i)
                        exp[i] = a1[i].get<u8>(0) & 1;

                    std::cout << "act " << color(act) << "\n";
                    std::cout << "exp " << color(exp) << "\n";
                    std::cout << "    " << color(exp ^ act, Color::Red) << "\n";
                }

                throw RTE_LOC;
            }
        }

        {

            auto tt = c0;
            std::vector<block> w(k);
            Tung code(n);
            code.update(tt);
            code.finalize(w);


            std::vector<block> a1(k);
            SAPA.sparse().multAdd(c0, a1);

            if (memcmp(w.data(), a1.data(), k * sizeof(block)))
            {
                //if (v)

                BitVector act(k);
                BitVector exp(k);

                for (u64 i = 0; i < k; ++i)
                    act[i] = w[i].get<u8>(0) & 1;
                for (u64 i = 0; i < k; ++i)
                    exp[i] = a1[i].get<u8>(0) & 1;

                std::cout << "\nact " << color(act) << "\n";
                std::cout << "exp " << color(exp) << "\n";
                std::cout << "    " << color(exp ^ act, Color::Red) << "\n";
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
                code.dualEncode<block>(c0, m1);
            }
            std::cout << timer << std::endl;
        }
        else if (cmd.isSet("reg"))
        {
            //TungstanClassic code(n, bw);

            ////TungstenAccumulator code(TungstenBinPermuter{ (u64)n, (u64)bw });
            //oc::Timer timer;
            //code.setTimer(timer);
            ////code.setTimer(timer);
            //std::vector<block> c0(step, ZeroBlock);
            //c0[0] = OneBlock;
            //for (auto t : rng(tt))
            //{
            //    code.reset();
            //    timer.setTimePoint("reset");
            //    for (u64 j = 0; j < n; j += step)
            //    {
            //        span<block> buff(c0.data(), step);
            //        code.update(buff);
            //    }

            //    timer.setTimePoint("acc");

            //    //code.finalize(m1);

            //    timer.setTimePoint("expand");
            //    //code.dualEncode<block>(c0, m1);
            //}


            //if (!cmd.isSet("quiet"))
            //    std::cout << timer << std::endl;

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
                code.dualEncode(c0);
                timer.setTimePoint("encode");
            }



            if (!cmd.isSet("quiet"))
                std::cout << timer << std::endl;
#endif
        }
        else if (cmd.isSet("trans"))
        {
            //Tungsten code;
            //code.config(k, n, bw, aw, reuse, permute, sticky);
            //code.mAccumulatorWeight = cmd.getOr("aaw", 4);
            AlignedUnVector<block> m1(k)/*, c0(n)*/;

            //Tungsten2<block, NoopPerm, TableTungsten1024x4> code(n, bw);
            Tungsten2<block, TungstenPerm<block, 8>, TableAccTrans<block, TableTungsten1024x4>>
                code(n, bw);
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
                //code.dualEncode<block>(c0, m1);
            }


            if (!cmd.isSet("quiet"))
                std::cout << timer << std::endl;
        }
        else if (cmd.isSet("sum"))
        {
            //Tungsten code;
            //code.config(k, n, bw, aw, reuse, permute, sticky);
            //code.mAccumulatorWeight = cmd.getOr("aaw", 4);
            AlignedUnVector<block> m1(k)/*, c0(n)*/;

            //Tungsten2<block, NoopPerm, TableTungsten1024x4> code(n, bw);
            Tungsten2<block, TungstenPerm<block, 8>, SumAcc<block>, TableAccTrans<block, TableTungsten1024x4>>
                code(n, bw);
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
                //code.dualEncode<block>(c0, m1);
            }


            if (!cmd.isSet("quiet"))
                std::cout << timer << std::endl;
        }
        else if (cmd.isSet("APA"))
        {
            //Tungsten code;
            //code.config(k, n, bw, aw, reuse, permute, sticky);
            //code.mAccumulatorWeight = cmd.getOr("aaw", 4);
            AlignedUnVector<block> m1(k)/*, c0(n)*/;


            using Acc = SumAcc<block>;
            using Acc2 = TableAccTrans<block, TableTungsten128x4>; // SumAcc<block>; // TableAccTrans<block, TableTungsten128x4>;
            using Perm = TungstenPerm<block, 8>;
            using Tung = Tungsten3<block, Perm, Acc, Acc2>;
            Tung code(n);
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
                //code.dualEncode<block>(c0, m1);
            }


            if (!cmd.isSet("quiet"))
                std::cout << timer << std::endl;
        }
        else
        {

            //Tungsten code;
            //code.config(k, n, bw, aw, reuse, permute, sticky);
            //code.mAccumulatorWeight = cmd.getOr("aaw", 4);
            AlignedUnVector<block> m1(k)/*, c0(n)*/;

            //Tungsten2<block, NoopPerm, TableTungsten1024x4> code(n, bw);
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
                //code.dualEncode<block>(c0, m1);
            }


            if (!cmd.isSet("quiet"))
                std::cout << timer << std::endl;
        }
    }


}
#include "EACode_Tests.h"
#include "libOTe/Tools/EACode/EACode.h"
#include <iomanip>

namespace osuCrypto
{
    void EACode_encode_basic_test(const oc::CLP& cmd)
    {

        auto k = cmd.getOr("k", 16ull);
        auto R = cmd.getOr("R", 5.0);
        auto n = cmd.getOr("n", k * R);
        auto bw = cmd.getOr("bw", 7);

        bool v = cmd.isSet("v");


        EACode code;
        code.config(k, n, bw);

        auto A = code.getA();
        auto B = code.getB();
        auto G = B * A;
        std::vector<block> m0(k), m1(k), c(n), c0(n), c1(n), a1(n);
        std::vector<u8> c2(n), m2(k);

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
        code.accumulate<block>(a0);
        A.multAdd(c0, a1);
        //A.leftMultAdd(c0, c1);
        if (a0 != a1)
        {
            if (v)
            {

                for (u64 i = 0; i < k; ++i)
                    std::cout << std::hex << std::setw(2) << std::setfill('0') << (a0[i]) << " ";
                std::cout << "\n";
                for (u64 i = 0; i < k; ++i)
                    std::cout << std::hex << std::setw(2) << std::setfill('0') << (c1[i]) << " ";
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


        cc = c0;
        code.dualEncode<block>(cc, m1);

        if (m0 != m1)
            throw RTE_LOC;

        cc = c0;
        for (u64 i = 0; i < code.mCodeSize; ++i)
            c2[i] = c0[i].get<u8>(0);

        code.dualEncode2<block,u8>(cc, m1, c2, m2);

        if (m0 != m1)
            throw RTE_LOC;

        for (u64 i = 0; i < code.mMessageSize; ++i)
            m2[i] = m0[i].get<u8>(0);

    }

}
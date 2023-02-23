#include "ExConvCode_Tests.h"
#include "libOTe/Tools/ExConvCode/ExConvCode.h"
#include <iomanip>

namespace osuCrypto
{
    void ExConvCode_encode_basic_test(const oc::CLP& cmd)
    {

        auto k = cmd.getOr("k", 16);
        auto R = cmd.getOr("R", 2.0);
        auto n = cmd.getOr("n", k * R);
        auto bw = cmd.getOr("bw", 7);
        auto aw = cmd.getOr("aw", 8);
        auto wrap = cmd.getOr("wrap", 1);

        bool v = cmd.isSet("v");


        ExConvCode code;
        code.config(k, n, bw, aw, wrap);

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
        code.accumulate<block>(a0);
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
        code.mExpander.expand<block>(cc, m1);

        if (m0 != m1)
            throw RTE_LOC;

        m0.resize(0);
        m0.resize(k);

        G.multAdd(c0, m0);

        code.dualEncode<block>(c0, m1);

        if (m0 != m1)
            throw RTE_LOC;
    }

}
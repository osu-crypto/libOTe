#include "ExConvCode_Tests.h"
#include "libOTe/Tools/ExConvCode/ExConvCode.h"
#include "libOTe/Tools/ExConvCode/ExConvCode.h"
#include <iomanip>

namespace osuCrypto
{
    void ExConvCode_encode_basic_test(const oc::CLP& cmd)
    {

        auto k = cmd.getOr("k", 16ul);
        auto R = cmd.getOr("R", 2.0);
        auto n = cmd.getOr<u64>("n", k * R);
        auto bw = cmd.getOr("bw", 7);
        auto aw = cmd.getOr("aw", 8);

        bool v = cmd.isSet("v");

        for (auto sys : {/* false,*/ true })
        {



            ExConvCode code;
            code.config(k, n, bw, aw, sys);

            auto A = code.getA();
            auto B = code.getB();
            auto G = B * A;

            std::vector<block> m0(k), m1(k), a1(n);

            if (v)
            {
                std::cout << "B\n" << B << std::endl << std::endl;
                std::cout << "A'\n" << code.getAPar() << std::endl << std::endl;
                std::cout << "A\n" << A << std::endl << std::endl;
                std::cout << "G\n" << G << std::endl;

            }

            const auto c0 = [&]() {
                std::vector<block> c0(n);
                PRNG prng(ZeroBlock);
                prng.get(c0.data(), c0.size());
                return c0;
            }();

            auto a0 = c0;
            auto aa0 = a0;
            std::vector<u8> aa1(n);
            for (u64 i = 0; i < n; ++i)
            {
                aa1[i] = aa0[i].get<u8>(0);
            }
            if (code.mSystematic)
            {
                code.accumulate<block>(span<block>(a0.begin() + k, a0.begin() + n));
                code.accumulate<block, u8>(
                    span<block>(aa0.begin() + k, aa0.begin() + n),
                    span<u8>(aa1.begin() + k, aa1.begin() + n)
                    );

                for (u64 i = 0; i < n; ++i)
                {
                    if (aa0[i] != a0[i])
                        throw RTE_LOC;
                    if (aa1[i] != a0[i].get<u8>(0))
                        throw RTE_LOC;
                }
            }
            else
            {
                code.accumulate<block>(a0);
            }
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



            for (u64 q = 0; q < n; ++q)
            {
                std::vector<block> c0(n);
                c0[q] = AllOneBlock;

                //auto q = 0;
                auto cc = c0;
                auto cc1 = c0;
                auto mm1 = m1;
                
                std::vector<u8> cc2(cc1.size()), mm2(mm1.size());
                for (u64 i = 0; i < n; ++i)
                    cc2[i] = cc1[i].get<u8>(0);
                for (u64 i = 0; i < k; ++i)
                    mm2[i] = mm1[i].get<u8>(0);
                //std::vector<block> cc(n);
                //cc[q] = AllOneBlock;
                std::fill(m0.begin(), m0.end(), ZeroBlock);
                B.multAdd(cc, m0);


                if (code.mSystematic)
                {
                    std::copy(cc.begin(), cc.begin() + k, m1.begin());
                    code.mExpander.expand<block, true>(
                        span<block>(cc.begin() + k, cc.end()),
                        m1);
                    //for (u64 i = 0; i < k; ++i)
                    //    m1[i] ^= cc[i];
                    std::copy(cc1.begin(), cc1.begin() + k, mm1.begin());
                    std::copy(cc2.begin(), cc2.begin() + k, mm2.begin());

                    code.mExpander.expand<block, u8, true>(
                        span<block>(cc1.begin() + k, cc1.end()),
                        span<u8>(cc2.begin() + k, cc2.end()),
                        mm1, mm2);
                }
                else
                {
                    code.mExpander.expand<block>(cc, m1);
                }
                if (m0 != m1)
                {

                    std::cout << "B\n" << B << std::endl << std::endl;
                    for (u64 i = 0; i < n; ++i)
                        std::cout << (c0[i].get<u8>(0) & 1) << " ";
                    std::cout << std::endl;

                    std::cout << "exp act " << q << "\n";
                    for (u64 i = 0; i < k; ++i)
                    {
                        std::cout << (m0[i].get<u8>(0) & 1) << " " << (m1[i].get<u8>(0) & 1) << std::endl;
                    }
                    throw RTE_LOC;
                }

                if (code.mSystematic)
                {
                    if (mm1 != m1)
                        throw RTE_LOC;

                    for (u64 i = 0; i < k; ++i)
                        if (mm2[i] != m1[i].get<u8>(0))
                            throw RTE_LOC;
                }
            }

            //for (u64 q = 0; q < n; ++q)
            {
                auto q = 0;

                //std::fill(c0.begin(), c0.end(), ZeroBlock);
                //c0[q] = AllOneBlock;
                auto cc = c0;
                auto cc1 = c0;
                std::vector<u8> cc2(cc1.size());
                for (u64 i = 0; i < n; ++i)
                    cc2[i] = cc1[i].get<u8>(0);


                std::fill(m0.begin(), m0.end(), ZeroBlock);
                G.multAdd(c0, m0);

                if (code.mSystematic)
                {
                    code.dualEncode<block>(cc);
                    std::copy(cc.begin(), cc.begin() + k, m1.begin());
                }
                else
                {
                    code.dualEncode<block>(cc, m1);
                }

                if (m0 != m1)
                {
                    std::cout << "G\n" << G << std::endl << std::endl;
                    for (u64 i = 0; i < n; ++i)
                        std::cout << (c0[i].get<u8>(0) & 1) << " ";
                    std::cout << std::endl;

                    std::cout << "exp act " << q << "\n";
                    for (u64 i = 0; i < k; ++i)
                    {
                        std::cout << (m0[i].get<u8>(0) & 1) << " " << (m1[i].get<u8>(0) & 1) << std::endl;
                    }
                    throw RTE_LOC;
                }


                if (code.mSystematic)
                {
                    code.dualEncode2<block, u8>(cc1, cc2);

                    for (u64 i = 0; i < k; ++i)
                    {
                        if (cc1[i] != cc[i])
                            throw RTE_LOC;
                        if (cc2[i] != cc[i].get<u8>(0))
                            throw RTE_LOC;
                    }
                }
            }
        }
    }

}
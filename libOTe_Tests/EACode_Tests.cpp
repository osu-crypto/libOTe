#include "EACode_Tests.h"
#include "libOTe/Tools/EACode/EACode.h"
#include <iomanip>
#include "libOTe/Tools/CoeffCtx.h"
#include "libOTe_Tests/ExConvCode_Tests.h"
#include "libOTe/Tools/ExConvCode/ExConvChecker.h"

namespace osuCrypto
{
    void EACode_encode_basic_test(const oc::CLP& cmd)
    {

        auto k = cmd.getOr("k", 16ull);
        auto R = cmd.getOr("R", 5.0);
        auto n = cmd.getOr("n", k * R);
        auto bw = cmd.getOr("bw", 7);



        EACode code;
        code.config(k, n, bw);

        //auto A = code.getA();
        //auto B = code.getB();
        //auto G = B * A;
        std::vector<block> m0(k), m1(k), c(n), c0(n), c1(n), a1(n);
        std::vector<u8> c2(n), m2(k);

        //if (v)
        //{
        //    std::cout << "B\n" << B << std::endl << std::endl;
        //    std::cout << "A'\n" << code.getAPar() << std::endl << std::endl;
        //    std::cout << "A\n" << A << std::endl << std::endl;
        //    std::cout << "G\n" << G << std::endl;

        //}


        PRNG prng(ZeroBlock);
        prng.get(c0.data(), c0.size());

        auto a0 = c0;
        code.accumulate<block, CoeffCtxGF128>(a0, {});
        CoeffCtxGF128 ctx;
        block sum = c0[0];
        for (u64 i = 0; i < a0.size(); ++i)
        {
            if (a0[i] != sum)
                throw RTE_LOC;

            if (i + 1 < a0.size())
            {
                sum ^= c0[i + 1];
                ctx.mulConst(sum, sum);
            }
        }

        u64 i = 0;
        detail::ExpanderModd expanderCoeff(code.mSeed, code.mCodeSize);
        auto main = k / 8 * 8;
        for (; i < main; i += 8)
        {
            for (u64 j = 0; j < code.mExpanderWeight; ++j)
            {
                for (u64 p = 0; p < 8; ++p)
                {
                    auto idx = expanderCoeff.get();
                    m0[i + p] = m0[i + p] ^ a0[idx];
                }
            }
        }

        for (; i < k; ++i)
        {
            for (u64 j = 0; j < code.mExpanderWeight; ++j)
            {
                auto idx = expanderCoeff.get();
                m0[i] = m0[i] ^ a0[idx];
            }
        }

        code.dualEncode<block, CoeffCtxGF128>(c0, m1, {});

        if (m0 != m1)
            throw RTE_LOC;

    }


    void EACode_weight_test(const oc::CLP& cmd)
    {
        u64  k = cmd.getOr("k", 1ull << cmd.getOr("kk", 6));
        u64 n = k * 2;
        u64 bw = cmd.getOr("bw", 21);
        bool verbose = cmd.isSet("v");

        EACode encoder;
        encoder.config(k, n, bw);
        auto threshold = n / 4 - 2 * std::sqrt(n);
        u64 min = 0;
        //if (cmd.isSet("x2"))
        //    min = getGeneratorWeightx2(encoder, verbose);
        //else
        min = getGeneratorWeight(encoder, verbose);

        if(verbose)
            std::cout << min << " / " << n << " = " << double(min) / n << std::endl;

        if (min < threshold)
        {
            throw RTE_LOC;
        }
    }

}
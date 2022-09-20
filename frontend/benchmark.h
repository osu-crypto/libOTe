#pragma once
#include "cryptoTools/Common/CLP.h"
#include "cryptoTools/Common/Aligned.h"
#include <chrono>
#include "libOTe/Tools/Tools.h"

#include "libOTe/Tools/LDPC/LdpcEncoder.h"
namespace osuCrypto
{

    inline void encodeBench(CLP& cmd)
    {
        u64 trials = cmd.getOr("t", 10);

        // the message length of the code. 
        // The noise vector will have size n=2*m.
        // the user can use 
        //   -m X 
        // to state that exactly X rows should be used or
        //   -mm X
        // to state that 2^X rows should be used.
        u64 m = cmd.getOr("m", 1ull << cmd.getOr("mm", 10));

        // the weight of the code, must be 5 or 11.
        u64 w = cmd.getOr("w", 5);

        // verbose flag.
        bool v = cmd.isSet("v");


        SilverCode code;
        if (w == 11)
            code = SilverCode::Weight11;
        else if (w == 5)
            code = SilverCode::Weight5;
        else
        {
            std::cout << "invalid weight" << std::endl;
            throw RTE_LOC;
        }

        PRNG prng(ZeroBlock);
        SilverEncoder encoder;
        encoder.init(m,code);


        std::vector<block> x(encoder.cols());
        Timer timer, verbose;

        if (v)
            encoder.setTimer(verbose);

        timer.setTimePoint("_____________________");
        for (u64 i = 0; i < trials; ++i)
        {
            encoder.cirTransEncode<block>(x);
            timer.setTimePoint("encode");
        }

        std::cout << timer << std::endl;

        if (v)
            std::cout << verbose << std::endl;
    }



    inline void transpose(const CLP& cmd)
    {
        u64 trials = cmd.getOr("trials", 1ull << 18);
#ifdef ENABLE_AVX
        {


            AlignedArray<block, 128> data;

            Timer timer;
            auto start0 = timer.setTimePoint("b");

            for (u64 i = 0; i < trials; ++i)
            {
                avx_transpose128(data.data());
            }

            auto end0 = timer.setTimePoint("b");


            for (u64 i = 0; i < trials; ++i)
            {
                sse_transpose128(data.data());
            }

            auto end1 = timer.setTimePoint("b");

            std::cout << "avx " << std::chrono::duration_cast<std::chrono::milliseconds>(end0 - start0).count() << std::endl;
            std::cout << "sse " << std::chrono::duration_cast<std::chrono::milliseconds>(end1 - end0).count() << std::endl;
        }

        {
            AlignedArray<block, 1024> data;

            Timer timer;
            auto start1 = timer.setTimePoint("b");

            for (u64 i = 0; i < trials * 8; ++i)
            {
                avx_transpose128(data.data());
            }


            auto start0 = timer.setTimePoint("b");

            for (u64 i = 0; i < trials; ++i)
            {
                avx_transpose128x1024(data.data());
            }

            auto end0 = timer.setTimePoint("b");


            for (u64 i = 0; i < trials; ++i)
            {
                sse_transpose128x1024(*(std::array<std::array<block, 8>, 128>*)data.data());
            }

            auto end1 = timer.setTimePoint("b");

            std::cout << "avx " << std::chrono::duration_cast<std::chrono::milliseconds>(start0 - start1).count() << std::endl;
            std::cout << "avx " << std::chrono::duration_cast<std::chrono::milliseconds>(end0 - start0).count() << std::endl;
            std::cout << "sse " << std::chrono::duration_cast<std::chrono::milliseconds>(end1 - end0).count() << std::endl;
        }
#endif
    }
}
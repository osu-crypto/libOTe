#include "ExConvChecker.h"
#include "libOTe/Tools/ExConvCode/ExConvCode.h"
#include <iomanip>
#include "libOTe/Tools/CoeffCtx.h"

namespace osuCrypto
{


    Matrix<u8> getAccumulator_(ExConvCode& encoder)
    {
        auto k = encoder.mMessageSize;;
        auto n = encoder.mCodeSize;;
        if (encoder.mSystematic == false)
            throw RTE_LOC;//not impl

        auto d = n - k;
        Matrix<u8> g(d, d);
        for (u64 i = 0; i < d; ++i)
        {
            std::vector<u8> x(d);
            x[i] = 1;
            CoeffCtxGF2 ctx;
            encoder.accumulate<u8, CoeffCtxGF2>(x.data(), ctx);

            for (u64 j = 0; j < d; ++j)
            {
                g(j, i) = x[j];
            }
        }
        return g;
    }


    u64 getAccWeight(ExConvCode& encoder, u64 trials)
    {
        auto n = encoder.mCodeSize;
        //auto g = getGenerator(encoder);
        auto g = getAccumulator_(encoder);
        auto G = compress(g);

        auto N = G.cols();

        u64 min = n;


        u64 step, exSize;
        if (encoder.mExpander.mRegular)
            exSize = step = encoder.mExpander.mCodeSize / encoder.mExpander.mExpanderWeight;
        else
        {
            step = 0;
            exSize = n;
        }
        detail::ExpanderModd prng(encoder.mExpander.mSeed, exSize);


        for (u64 i = 0; i < trials; ++i)
        {
            u64 weight = 0;
            for (u64 j = 0; j < N; ++j)
            {
                block sum = ZeroBlock;
                for (u64 k = 0; k < encoder.mExpander.mExpanderWeight; ++k)
                {
                    auto idx = prng.get() + step * k;
                    sum = sum ^ G(j, idx);
                }

                weight +=
                    popcount(sum.get<u64>(0)) +
                    popcount(sum.get<u64>(1));
                //weight += g(i, j);
            }

            min = std::min<u64>(min, weight);
        }

        return min;
    }


    //u64 getGeneratorWeight(ExConvCode& encoder)
    //{
    //    auto k = encoder.mMessageSize;
    //    auto n = encoder.mCodeSize;
    //    auto g = getGenerator(encoder);
    //    bool failed = false;
    //    u64 min = n;
    //    u64 iMin = 0;;
    //    for (u64 i = 0; i < k; ++i)
    //    {
    //        u64 weight = 0;
    //        for (u64 j = 0; j < n; ++j)
    //        {
    //            //if (verbose)
    //            //{
    //            //    if (g(i, j))
    //            //        std::cout << Color::Green << "1" << Color::Default;
    //            //    else
    //            //        std::cout << "0";
    //            //}
    //            assert(g(i, j) < 2);
    //            weight += g(i, j);
    //        }
    //        //if (verbose)
    //        //    std::cout << std::endl;

    //        if (weight < min)
    //            iMin = i;
    //        min = std::min<u64>(min, weight);
    //    }
    //}

    void ExConvChecker(const oc::CLP& cmd)
    {
        u64  k = cmd.getOr("k", 1ull << cmd.getOr("kk", 6));
        u64 n = k * 2;
        bool verbose = cmd.isSet("v");
        bool accTwice = cmd.getOr("accTwice", 1);
        bool sys = cmd.getOr("sys", 1);
        bool reg = cmd.getOr("reg", 1);
        u64 nt = cmd.getOr("nt", 1);

        u64 trials = cmd.getOr("trials", 1);
        u64 awBeing = cmd.getOr("aw", 0);
        u64 awEnd = cmd.getOr("awEnd", 20);
        u64 bwBeing = cmd.getOr("bw", 3);
        u64 bwEnd = cmd.getOr("bwEnd", 11);

        for (u64 aw = awBeing; aw < awEnd; aw += 2)
        {
            for (u64 bw = bwBeing; bw < bwEnd; bw += 2)
            {


                u64 avg = 0;
                u64 gMin = n;
                std::mutex mtx;
                u64 ticks = n * trials;
               std::atomic<u64> done = 0;
                auto routine = [&](u64 i) {
                    for (u64 j = i; j < trials; j += nt)
                    {

                        ExConvCode encoder;
                        encoder.config(k, n, bw, aw, sys, reg, block(21341234, j));
                        encoder.mAccTwice = accTwice;

                        u64 min = 0;
                        if (cmd.isSet("x2"))
                            min = getGeneratorWeightx2(encoder, verbose);
                        else
                            min = getGeneratorWeight<ExConvCode, std::atomic<u64>&>(encoder, verbose, done);

                        std::lock_guard<std::mutex> lock(mtx);
                        gMin = std::min(gMin, min);
                        avg += min;
                    }
                    };

                std::vector<std::thread> thrds(nt);
                for (u64 i = 0; i < thrds.size(); ++i)
                {
                    thrds[i] = std::thread(routine, i);
                }
                //routine(nt - 1);
                u64 sleep = 1;
                while (done != ticks)
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds(sleep));
                    sleep = std::min<u64>(1000, sleep * 2);

                    u64 d = double(done) * 40 / ticks;

                    std::cout << "[" << std::string(d, '|') << std::string(40 - d, ' ') << "] " << double(done) * 100 / ticks << "%\r" << std::flush;
                }
                std::cout <<std::string(50, ' ') << "\r" << std::flush;

                for (u64 i = 0; i < thrds.size(); ++i)
                {
                    thrds[i].join();
                }
                std::cout << "aw " << aw << " bw " << bw << 
                    ": min " << double(gMin) / n <<
                    ", avg " << double(avg) / n / trials << std::endl;
            }
        }

    }

}

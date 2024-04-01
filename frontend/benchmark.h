#pragma once
#include "cryptoTools/Common/CLP.h"
#include "cryptoTools/Common/Aligned.h"
#include <chrono>
#include "libOTe/Tools/Tools.h"

#include "libOTe/Tools/EACode/EACode.h"
#include "libOTe/Tools/ExConvCode/ExConvCode.h"
#include "libOTe/Tools/QuasiCyclicCode.h"

#include "libOTe/TwoChooseOne/Silent/SilentOtExtReceiver.h"
#include "libOTe/TwoChooseOne/Silent/SilentOtExtSender.h"
#include "libOTe/Vole/Silent/SilentVoleSender.h"
#include "libOTe/Vole/Silent/SilentVoleReceiver.h"
#include "libOTe/Tools/CoeffCtx.h"
#include "libOTe/Tools/TungstenCode/TungstenCode.h"
#include "libOTe/Tools/ExConvCodeOld/ExConvCodeOld.h"

namespace osuCrypto
{

    inline void QCCodeBench(CLP& cmd)
    {

#ifdef ENABLE_BITPOLYMUL
        u64 trials = cmd.getOr("t", 10);

        // the message length of the code. 
        // The noise vector will have size n=2*k.
        // the user can use 
        //   -k X 
        // to state that exactly X rows should be used or
        //   -kk X
        // to state that 2^X rows should be used.
        u64 k = cmd.getOr("k", 1ull << cmd.getOr("kk", 10));

        u64 n = k * 2;

        // verbose flag.


        oc::Timer timer;
        QuasiCyclicCode code;
        code.init2(k, n);
        std::vector<block> c0(code.size(), ZeroBlock);
        for (auto t = 0ull; t < trials; ++t)
        {

            timer.setTimePoint("reset");
            code.dualEncode(c0);
            timer.setTimePoint("encode");
        }



        if (!cmd.isSet("quiet"))
            std::cout << timer << std::endl;
#endif
    }

    inline void EACodeBench(CLP& cmd)
    {
        u64 trials = cmd.getOr("t", 10);

        // the message length of the code. 
        // The noise vector will have size n=2*k.
        // the user can use 
        //   -k X 
        // to state that exactly X rows should be used or
        //   -kk X
        // to state that 2^X rows should be used.
        u64 k = cmd.getOr("k", 1ull << cmd.getOr("kk", 10));

        u64 n = cmd.getOr<u64>("n", k * cmd.getOr("R", 5.0));

        // the weight of the code
        u64 w = cmd.getOr("w", 7);

        // size for the accumulator (# random transitions)

        // verbose flag.
        bool v = cmd.isSet("v");


        EACode code;
        code.config(k, n, w);

        if (v)
        {
            std::cout << "n: " << code.mCodeSize << std::endl;
            std::cout << "k: " << code.mMessageSize << std::endl;
            std::cout << "w: " << code.mExpanderWeight << std::endl;
        }

        std::vector<block> x(code.mCodeSize), y(code.mMessageSize);
        Timer timer, verbose;

        if (v)
            code.setTimer(verbose);

        timer.setTimePoint("_____________________");
        for (u64 i = 0; i < trials; ++i)
        {
            code.dualEncode<block, CoeffCtxGF128>(x, y, {});
            timer.setTimePoint("encode");
        }

        std::cout << "EA " << std::endl;
        std::cout << timer << std::endl;

        if (v)
            std::cout << verbose << std::endl;
    }

    inline void ExConvCodeBench(CLP& cmd)
    {
        u64 trials = cmd.getOr("t", 10);

        // the message length of the code. 
        // The noise vector will have size n=2*k.
        // the user can use 
        //   -k X 
        // to state that exactly X rows should be used or
        //   -kk X
        // to state that 2^X rows should be used.
        u64 k = cmd.getOr("k", 1ull << cmd.getOr("kk", 10));

        u64 n = cmd.getOr<u64>("n", k * cmd.getOr("R", 2.0));

        // the weight of the code
        u64 w = cmd.getOr("w", 7);

        // size for the accumulator (# random transitions)
        u64 a = cmd.getOr("a", roundUpTo(log2ceil(n), 8));

        bool gf128 = cmd.isSet("gf128");

        // verbose flag.
        bool v = cmd.isSet("v");
        bool sys = cmd.isSet("sys");

        ExConvCode code;
        code.config(k, n, w, a, sys);

        if (v)
        {
            std::cout << "n: " << code.mCodeSize << std::endl;
            std::cout << "k: " << code.mMessageSize << std::endl;
            //std::cout << "w: " << code.mExpanderWeight << std::endl;
        }

        std::vector<block> x(code.mCodeSize), y(code.mMessageSize * !sys);
        Timer timer, verbose;

        if (v)
            code.setTimer(verbose);

        timer.setTimePoint("_____________________");
        for (u64 i = 0; i < trials; ++i)
        {
            if (gf128)
                code.dualEncode<block, CoeffCtxGF128>(x.begin(), {});
            else
                code.dualEncode<block, CoeffCtxGF2>(x.begin(), {});

            timer.setTimePoint("encode");
        }

        std::cout << "EC " << std::endl;
        std::cout << timer << std::endl;

        if (v)
            std::cout << verbose << std::endl;
    }

    inline void ExConvCodeOldBench(CLP& cmd)
    {
#ifdef LIBOTE_ENABLE_OLD_EXCONV

        u64 trials = cmd.getOr("t", 10);

        // the message length of the code. 
        // The noise vector will have size n=2*k.
        // the user can use 
        //   -k X 
        // to state that exactly X rows should be used or
        //   -kk X
        // to state that 2^X rows should be used.
        u64 k = cmd.getOr("k", 1ull << cmd.getOr("kk", 10));

        u64 n = cmd.getOr<u64>("n", k * cmd.getOr("R", 2.0));

        // the weight of the code
        u64 w = cmd.getOr("w", 7);

        // size for the accumulator (# random transitions)
        u64 a = cmd.getOr("a", roundUpTo(log2ceil(n), 8));

        bool gf128 = cmd.isSet("gf128");

        // verbose flag.
        bool v = cmd.isSet("v");
        bool sys = cmd.isSet("sys");

        ExConvCodeOld code;
        code.config(k, n, w, a, sys);

        if (v)
        {
            std::cout << "n: " << code.mCodeSize << std::endl;
            std::cout << "k: " << code.mMessageSize << std::endl;
            //std::cout << "w: " << code.mExpanderWeight << std::endl;
        }

        std::vector<block> x(code.mCodeSize), y(code.mMessageSize * !sys);
        Timer timer, verbose;

        if (v)
            code.setTimer(verbose);

        timer.setTimePoint("_____________________");
        for (u64 i = 0; i < trials; ++i)
        {
            code.dualEncode<block>(x);

            timer.setTimePoint("encode");
        }

        if (cmd.isSet("quiet") == false)
        {
            std::cout << "EC " << std::endl;
            std::cout << timer << std::endl;
        }
        if (v)
            std::cout << verbose << std::endl;
#else
        std::cout << "LIBOTE_ENABLE_OLD_EXCONV = false" << std::endl;
#endif
    }


    inline void PprfBench(CLP& cmd)
    {

#ifdef ENABLE_SILENTOT

        try
        {
            using Ctx = CoeffCtxGF2;
            RegularPprfReceiver<block, block, Ctx> recver;
            RegularPprfSender<block, block, Ctx> sender;

            u64 trials = cmd.getOr("t", 10);

            u64 w = cmd.getOr("w", 32);
            u64 n = cmd.getOr("n", 1ull << cmd.getOr("nn", 14));

            PRNG prng0(ZeroBlock), prng1(ZeroBlock);
            block delta = prng0.get();

            auto sock = coproto::LocalAsyncSocket::makePair();

            Timer rTimer;
            auto s = rTimer.setTimePoint("start");
            auto ctx = Ctx{};
            auto vals = Ctx::Vec<block>(w);
            auto out0 = Ctx::Vec<block>(n / w * w);
            auto out1 = Ctx::Vec<block>(n / w * w);



            for (u64 t = 0; t < trials; ++t)
            {
                sender.configure(n / w, w);
                recver.configure(n / w, w);

                std::vector<std::array<block, 2>> baseSend(sender.baseOtCount());
                std::vector<block> baseRecv(sender.baseOtCount());
                BitVector baseChoice(sender.baseOtCount());
                sender.setBase(baseSend);
                recver.setBase(baseRecv);
                recver.setChoiceBits(baseChoice);

                auto p0 = sender.expand(sock[0], vals, prng0.get(), out0, PprfOutputFormat::Interleaved, true, 1, ctx);
                auto p1 = recver.expand(sock[1], out1, PprfOutputFormat::Interleaved, true, 1, ctx);

                rTimer.setTimePoint("r start");
                coproto::sync_wait(macoro::when_all_ready(
                    std::move(p0), std::move(p1)));
                rTimer.setTimePoint("r done");

            }
            auto e = rTimer.setTimePoint("end");

            auto time = std::chrono::duration_cast<std::chrono::milliseconds>(e - s).count();
            auto avgTime = time / double(trials);
            auto timePer512 = avgTime / n * 512;
            std::cout << "OT n:" << n << ", " <<
                avgTime << "ms/batch, " << timePer512 << "ms/512ot" << std::endl;

            std::cout << rTimer << std::endl;

            std::cout << sock[0].bytesReceived() / trials << " " << sock[1].bytesReceived() / trials << " bytes per " << std::endl;
        }
        catch (std::exception& e)
        {
            std::cout << e.what() << std::endl;
        }
#else
        std::cout << "ENABLE_SILENTOT = false" << std::endl;
#endif
    }

    inline void TungstenCodeBench(CLP& cmd)
    {
        u64 trials = cmd.getOr("t", 10);

        // the message length of the code. 
        // The noise vector will have size n=2*k.
        // the user can use 
        //   -k X 
        // to state that exactly X rows should be used or
        //   -kk X
        // to state that 2^X rows should be used.
        u64 k = cmd.getOr("k", 1ull << cmd.getOr("kk", 10));

        u64 n = cmd.getOr<u64>("n", k * cmd.getOr("R", 2.0));

        // verbose flag.
        bool v = cmd.isSet("v");

        experimental::TungstenCode code;
        code.config(k, n);
        code.mNumIter = cmd.getOr("iter", 2);

        if (v)
        {
            std::cout << "n: " << code.mCodeSize << std::endl;
            std::cout << "k: " << code.mMessageSize << std::endl;
        }

        AlignedUnVector<block> x(code.mCodeSize);
        Timer timer, verbose;
        

        timer.setTimePoint("_____________________");
        for (u64 i = 0; i < trials; ++i)
        {
            code.dualEncode<block, CoeffCtxGF2>(x.data(), {});

            timer.setTimePoint("encode");
        }

        if (cmd.isSet("quiet") == false)
        {
            std::cout << "tungsten " << std::endl;
            std::cout << timer << std::endl;
        }
        if (v)
            std::cout << verbose << std::endl;
    }


    inline void transpose(const CLP& cmd)
    {
#ifdef ENABLE_AVX
        u64 trials = cmd.getOr("trials", 1ull << 18);
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


    inline void SilentOtBench(const CLP& cmd)
    {
#ifdef ENABLE_SILENTOT

        try
        {

            SilentOtExtSender sender;
            SilentOtExtReceiver recver;

            u64 trials = cmd.getOr("t", 10);

            u64 n = cmd.getOr("n", 1ull << cmd.getOr("nn", 20));
            MultType multType = (MultType)cmd.getOr("m", (int)MultType::ExConv7x24);
            std::cout << multType << std::endl;

            recver.mMultType = multType;
            sender.mMultType = multType;

            PRNG prng0(ZeroBlock), prng1(ZeroBlock);
            block delta = prng0.get();

            auto sock = coproto::LocalAsyncSocket::makePair();

            Timer sTimer;
            Timer rTimer;
            recver.setTimer(rTimer);
            sender.setTimer(rTimer);
            sTimer.setTimePoint("start");
            auto s = sTimer.setTimePoint("start");

            for (u64 t = 0; t < trials; ++t)
            {
                sender.configure(n);
                recver.configure(n);

                auto choice = recver.sampleBaseChoiceBits(prng0);
                std::vector<std::array<block, 2>> sendBase(sender.silentBaseOtCount());
                std::vector<block> recvBase(recver.silentBaseOtCount());
                sender.setSilentBaseOts(sendBase);
                recver.setSilentBaseOts(recvBase);

                auto p0 = sender.silentSendInplace(delta, n, prng0, sock[0]);
                auto p1 = recver.silentReceiveInplace(n, prng1, sock[1], ChoiceBitPacking::True);

                rTimer.setTimePoint("r start");
                coproto::sync_wait(macoro::when_all_ready(
                    std::move(p0), std::move(p1)));
                rTimer.setTimePoint("r done");

            }
            auto e = rTimer.setTimePoint("end");

            if (cmd.isSet("quiet") == false)
            {

                auto time = std::chrono::duration_cast<std::chrono::milliseconds>(e - s).count();
                auto avgTime = time / double(trials);
                auto timePer512 = avgTime / n * 512;
                std::cout << "OT n:" << n << ", " <<
                    avgTime << "ms/batch, " << timePer512 << "ms/512ot" << std::endl;

                std::cout << sTimer << std::endl;
                std::cout << rTimer << std::endl;

                std::cout << sock[0].bytesReceived() / trials << " " << sock[1].bytesReceived() / trials << " bytes per " << std::endl;
            }
        }
        catch (std::exception& e)
        {
            std::cout << e.what() << std::endl;
        }
#else
        std::cout << "ENABLE_SILENTOT = false" << std::endl;
#endif
    }

    inline void VoleBench2(const CLP& cmd)
    {
#ifdef ENABLE_SILENT_VOLE
        try
        {

            SilentVoleSender<block, block, CoeffCtxGF128> sender;
            SilentVoleReceiver<block, block, CoeffCtxGF128> recver;

            u64 trials = cmd.getOr("t", 10);

            u64 n = cmd.getOr("n", 1ull << cmd.getOr("nn", 20));
            MultType multType = (MultType)cmd.getOr("m", (int)MultType::ExConv7x24);
            std::cout << multType << std::endl;

            recver.mMultType = multType;
            sender.mMultType = multType;

            std::vector<std::array<block, 2>> baseSend(128);
            std::vector<block> baseRecv(128);
            BitVector baseChoice(128);
            PRNG prng(CCBlock);
            baseChoice.randomize(prng);
            for (u64 i = 0; i < 128; ++i)
            {
                baseSend[i] = prng.get();
                baseRecv[i] = baseSend[i][baseChoice[i]];
            }

#ifdef ENABLE_SOFTSPOKEN_OT
            sender.mOtExtRecver.emplace();
            sender.mOtExtSender.emplace();
            recver.mOtExtRecver.emplace();
            recver.mOtExtSender.emplace();
            sender.mOtExtRecver->setBaseOts(baseSend);
            recver.mOtExtRecver->setBaseOts(baseSend);
            sender.mOtExtSender->setBaseOts(baseRecv, baseChoice);
            recver.mOtExtSender->setBaseOts(baseRecv, baseChoice);
#endif // ENABLE_SOFTSPOKEN_OT

            PRNG prng0(ZeroBlock), prng1(ZeroBlock);
            block delta = prng0.get();

            auto sock = coproto::LocalAsyncSocket::makePair();

            Timer sTimer;
            Timer rTimer;
            sTimer.setTimePoint("start");
            rTimer.setTimePoint("start");

            auto t0 = std::thread([&] {
                for (u64 t = 0; t < trials; ++t)
                {
                    auto p0 = sender.silentSendInplace(delta, n, prng0, sock[0]);

                    char c;

                    coproto::sync_wait(sock[0].send(std::move(c)));
                    coproto::sync_wait(sock[0].recv(c));
                    sTimer.setTimePoint("__");
                    coproto::sync_wait(sock[0].send(std::move(c)));
                    coproto::sync_wait(sock[0].recv(c));
                    sTimer.setTimePoint("s start");
                    coproto::sync_wait(p0);
                    sTimer.setTimePoint("s done");
                }
                });


            for (u64 t = 0; t < trials; ++t)
            {
                auto p1 = recver.silentReceiveInplace(n, prng1, sock[1]);
                char c;
                coproto::sync_wait(sock[1].send(std::move(c)));
                coproto::sync_wait(sock[1].recv(c));

                rTimer.setTimePoint("__");
                coproto::sync_wait(sock[1].send(std::move(c)));
                coproto::sync_wait(sock[1].recv(c));

                rTimer.setTimePoint("r start");
                coproto::sync_wait(p1);
                rTimer.setTimePoint("r done");

            }


            t0.join();
            std::cout << sTimer << std::endl;
            std::cout << rTimer << std::endl;

            std::cout << sock[0].bytesReceived() / trials << " " << sock[1].bytesReceived() / trials << " bytes per " << std::endl;
        }
        catch (std::exception& e)
        {
            std::cout << e.what() << std::endl;
        }
#else
        std::cout << "ENABLE_Silent_VOLE = false" << std::endl;
#endif
    }
}
#include "Vole_Tests.h"
#include "libOTe/Vole/NoisyVoleSender.h"
#include "libOTe/Vole/NoisyVoleReceiver.h"
#include "libOTe/Vole/SilentVoleSender.h"
#include "libOTe/Vole/SilentVoleReceiver.h"
#include "cryptoTools/Network/Session.h"
#include "cryptoTools/Network/IOService.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Common/TestCollection.h"

using namespace oc;

#include <libOTe/config.h>


#if defined(ENABLE_SILENT_VOLE) || defined(ENABLE_SILENTOT)

void Vole_Noisy_test(const oc::CLP& cmd)
{
    Timer timer;
    timer.setTimePoint("start");
    u64 n = cmd.getOr("n", 123);
    block seed = block(0, cmd.getOr("seed", 0));
    PRNG prng(seed);

    block x = prng.get();
    std::vector<block> y(n), z0(n), z1(n);
    prng.get<block>(y);

    NoisyVoleReceiver recv;
    NoisyVoleSender send;

    recv.setTimer(timer);
    send.setTimer(timer);

    IOService ios;
    auto chl1 = Session(ios, "localhost:1212", SessionMode::Server).addChannel();
    auto chl0 = Session(ios, "localhost:1212", SessionMode::Client).addChannel();
    timer.setTimePoint("net");


    BitVector recvChoice((u8*)&x, 128);
    std::vector<block> otRecvMsg(128);
    std::vector<std::array<block, 2>> otSendMsg(128);
    prng.get<std::array<block, 2>>(otSendMsg);
    for (u64 i = 0; i < 128; ++i)
        otRecvMsg[i] = otSendMsg[i][recvChoice[i]];
    timer.setTimePoint("ot");

    recv.receive(y, z0, prng, otSendMsg, chl0);
    timer.setTimePoint("recv");
    send.send(x, z1, prng, otRecvMsg, chl1);
    timer.setTimePoint("send");

    for (u64 i = 0; i < n; ++i)
    {
        if (y[i].gf128Mul(x) != (z0[i] ^ z1[i]))
        {
            throw RTE_LOC;
        }
    }
    timer.setTimePoint("done");

    //std::cout << timer << std::endl;

}

#else 
void Vole_Noisy_test(const oc::CLP& cmd)
    {
        throw UnitTestSkipped(
            "ENABLE_SILENT_VOLE not defined. "
        );
    }
#endif

#ifdef ENABLE_SILENT_VOLE

namespace {
    void fakeBase(u64 n,
        u64 threads,
        PRNG& prng,
        SilentVoleReceiver& recver, SilentVoleSender& sender)
    {
        sender.configure(n, 128);
        auto count = sender.silentBaseOtCount();
        std::vector<std::array<block, 2>> msg2(count);
        for (u64 i = 0; i < msg2.size(); ++i)
        {
            msg2[i][0] = prng.get();
            msg2[i][1] = prng.get();
        }
        sender.setSilentBaseOts(msg2);

        // fake base OTs.
        {
            recver.configure(n,128);
            BitVector choices = recver.sampleBaseChoiceBits(prng);
            std::vector<block> msg(choices.size());
            for (u64 i = 0; i < msg.size(); ++i)
                msg[i] = msg2[i][choices[i]];
            recver.setSilentBaseOts(msg);
        }
    }

}

void Vole_Silent_test(const oc::CLP& cmd)
{
    Timer timer;
    timer.setTimePoint("start");
    u64 n = cmd.getOr("n", 102043);
    block seed = block(0, cmd.getOr("seed", 0));
    PRNG prng(seed);
    u64 threads = 1;

    block x = prng.get();
    std::vector<block> c(n), z0(n), z1(n);

    SilentVoleReceiver recv;
    SilentVoleSender send;

    recv.setTimer(timer);
    send.setTimer(timer);

    //recv.mDebug = true;
    //send.mDebug = true;

    IOService ios;
    auto chl1 = Session(ios, "localhost:1212", SessionMode::Server).addChannel();
    auto chl0 = Session(ios, "localhost:1212", SessionMode::Client).addChannel();
    timer.setTimePoint("net");

    timer.setTimePoint("ot");
    fakeBase(n, threads, prng, recv, send);

    // c * x = z + m

    std::thread thrd = std::thread([&]() {
        recv.silentReceive(c, z0, prng, chl0);
        timer.setTimePoint("recv");
        });
    send.silentSend(x, z1, prng, chl1);
    timer.setTimePoint("send");
    thrd.join();
    for (u64 i = 0; i < n; ++i)
    {
        if (c[i].gf128Mul(x) != (z0[i] ^ z1[i]))
        {
            throw RTE_LOC;
        }
    }
    timer.setTimePoint("done");


}

void Vole_Silent_paramSweep_test(const oc::CLP& cmd)
{

    Timer timer;
    timer.setTimePoint("start");
    block seed = block(0, cmd.getOr("seed", 0));
    PRNG prng(seed);

    block x = prng.get();
    u64 threads = 0;

    IOService ios;
    auto chl1 = Session(ios, "localhost:1212", SessionMode::Server).addChannel();
    auto chl0 = Session(ios, "localhost:1212", SessionMode::Client).addChannel();
    timer.setTimePoint("net");

    timer.setTimePoint("ot");

    //recv.mDebug = true;
    //send.mDebug = true;

    SilentVoleReceiver recv;
    SilentVoleSender send;
    // c * x = z + m

    //for (u64 n = 5000; n < 10000; ++n)
    for(u64 n : {12,/* 123,465,*/1642,/*4356,34254,*/93425})
    {
        std::vector<block> c(n), z0(n), z1(n);

        fakeBase(n, threads, prng, recv, send);

        recv.setTimer(timer);
        send.setTimer(timer);
        std::thread thrd = std::thread([&]() {
            recv.silentReceive(c, z0, prng, chl0);
            timer.setTimePoint("recv");
            });
        send.silentSend(x, z1, prng, chl1);
        timer.setTimePoint("send");
        thrd.join();
        for (u64 i = 0; i < n; ++i)
        {
            if (c[i].gf128Mul(x) != (z0[i] ^ z1[i]))
            {
                throw RTE_LOC;
            }
        }
        timer.setTimePoint("done");
    }
}



void Vole_Silent_baseOT_test(const oc::CLP& cmd)
{

    Timer timer;
    timer.setTimePoint("start");
    u64 n = 123;
    block seed = block(0, cmd.getOr("seed", 0));
    PRNG prng(seed);

    block x = prng.get();


    IOService ios;
    auto chl1 = Session(ios, "localhost:1212", SessionMode::Server).addChannel();
    auto chl0 = Session(ios, "localhost:1212", SessionMode::Client).addChannel();
    timer.setTimePoint("net");

    timer.setTimePoint("ot");

    //recv.mDebug = true;
    //send.mDebug = true;

    SilentVoleReceiver recv;
    SilentVoleSender send;
    // c * x = z + m

    //for (u64 n = 5000; n < 10000; ++n)
    {
        std::vector<block> c(n), z0(n), z1(n);


        recv.setTimer(timer);
        send.setTimer(timer);
        std::thread thrd = std::thread([&]() {
            recv.silentReceive(c, z0, prng, chl0);
            timer.setTimePoint("recv");
            });
        send.silentSend(x, z1, prng, chl1);
        timer.setTimePoint("send");
        thrd.join();
        for (u64 i = 0; i < n; ++i)
        {
            if (c[i].gf128Mul(x) != (z0[i] ^ z1[i]))
            {
                throw RTE_LOC;
            }
        }
        timer.setTimePoint("done");
    }
}



void Vole_Silent_mal_test(const oc::CLP& cmd)
{

    Timer timer;
    timer.setTimePoint("start");
    u64 n = 12343;
    block seed = block(0, cmd.getOr("seed", 0));
    PRNG prng(seed);

    block x = prng.get();


    IOService ios;
    auto chl1 = Session(ios, "localhost:1212", SessionMode::Server).addChannel();
    auto chl0 = Session(ios, "localhost:1212", SessionMode::Client).addChannel();
    timer.setTimePoint("net");

    timer.setTimePoint("ot");

    //recv.mDebug = true;
    //send.mDebug = true;

    SilentVoleReceiver recv;
    SilentVoleSender send;

    send.mMalType = SilentSecType::Malicious;
    recv.mMalType = SilentSecType::Malicious;
    // c * x = z + m

    //for (u64 n = 5000; n < 10000; ++n)
    {
        std::vector<block> c(n), z0(n), z1(n);


        recv.setTimer(timer);
        send.setTimer(timer);
        std::thread thrd = std::thread([&]() {
            recv.silentReceive(c, z0, prng, chl0);
            timer.setTimePoint("recv");
            });
        send.silentSend(x, z1, prng, chl1);
        timer.setTimePoint("send");
        thrd.join();
        for (u64 i = 0; i < n; ++i)
        {
            if (c[i].gf128Mul(x) != (z0[i] ^ z1[i]))
            {
                throw RTE_LOC;
            }
        }
        timer.setTimePoint("done");
    }
}

#else

namespace {
    void throwDisabled()
    {
        throw UnitTestSkipped(
            "ENABLE_SILENT_VOLE not defined. "
        );
    }
}


void Vole_Silent_test(const oc::CLP& cmd){throwDisabled();}
void Vole_Silent_paramSweep_test(const oc::CLP& cmd){throwDisabled();}
void Vole_Silent_baseOT_test(const oc::CLP& cmd){throwDisabled();}
void Vole_Silent_mal_test(const oc::CLP& cmd){throwDisabled();}

#endif

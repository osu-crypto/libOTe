#include "Vole_Tests.h"
#include "libOTe/Vole/NoisyVoleSender.h"
#include "libOTe/Vole/NoisyVoleReceiver.h"
#include "libOTe/Vole/SilentVoleSender.h"
#include "libOTe/Vole/SilentVoleReceiver.h"
#include "cryptoTools/Network/Session.h"
#include "cryptoTools/Network/IOService.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Timer.h"

using namespace oc;

void NoisyVole_test(const oc::CLP& cmd)
{
    Timer timer;
    timer.setTimePoint("start");
    u64 n = cmd.getOr("n", 100);
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
    std::vector<std::array<block,2>> otSendMsg(128);
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

void SilentVole_test(const oc::CLP& cmd)
{
    Timer timer;
    timer.setTimePoint("start");
    u64 n = cmd.getOr("n", 1000);
    block seed = block(0, cmd.getOr("seed", 0));
    PRNG prng(seed);

    block x = prng.get();
    std::vector<block> c(n), z0(n), z1(n);

    SilentVoleReceiver recv;
    SilentVoleSender send;

    recv.setTimer(timer);
    send.setTimer(timer);

    IOService ios;
    auto chl1 = Session(ios, "localhost:1212", SessionMode::Server).addChannel();
    auto chl0 = Session(ios, "localhost:1212", SessionMode::Client).addChannel();
    timer.setTimePoint("net");

    timer.setTimePoint("ot");

    // c * x = z + m

    std::thread thrd = std::thread([&]() {
        recv.silentReceive(c, z0, prng, { &chl0,1 });
        timer.setTimePoint("recv");
        });
    send.silentSend(x, z1, prng, { &chl1,1 });
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


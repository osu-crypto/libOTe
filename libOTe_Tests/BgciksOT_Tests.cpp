#include "BgciksOT_Tests.h"
#include "libOTe/TwoChooseOne/BgciksOtExtSender.h"
#include "libOTe/TwoChooseOne/BgciksOtExtReceiver.h"
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Network/IOService.h>
using namespace oc;


void bitShift_test(const CLP& cmd)
{

    u64 n = cmd.getOr("n", 100);
    u64 t = cmd.getOr("t", 10);

    PRNG prng(ZeroBlock);

    std::vector<block> dest(n), in(n + 1);
    prng.get(dest.data(), dest.size());
    prng.get(in.data(), in.size());

    for (u64 i = 0; i < dest.size(); ++i)
    {
        u8 bitShift = prng.get<u8>() % 128;
        BitVector dv((u8*)dest.data(), dest.size() * 128);
        BitVector iv;
        iv.append((u8*)in.data(), dest.size() * 128, bitShift);

        dv ^= iv;

        bitShiftXor(dest, in, bitShift);


        BitVector dv2((u8*)dest.data(), dest.size() * 128);

        if (dv != dv2)
        {
            std::cout << "d2 " << dv2 << std::endl;
            std::cout << "d  " << dv << std::endl;
            std::cout << "f  " << (dv2 ^ dv) << std::endl;
            throw RTE_LOC;
        }

    }


}

void BgciksOT_Test(const CLP& cmd)
{
    
    IOService ios;
    Session s0(ios, "localhost:1212", SessionMode::Server);
    Session s1(ios, "localhost:1212", SessionMode::Client);

    BgciksOtExtSender sender;
    BgciksOtExtReceiver recver;
    u64 n = cmd.getOr("n",100);
    Channel chl0 = s0.addChannel();
    Channel chl1 = s1.addChannel();

    Timer timer;
    sender.setTimer(timer);
    recver.setTimer(timer);

    sender.genBase(n, chl0);
    recver.genBase(n, chl1);

    std::vector<block> messages2(n);
    BitVector choice;
    std::vector<std::array<block, 2>> messages(n);
    PRNG prng(ZeroBlock);

    sender.send(messages, prng, chl0);
    recver.receive(messages2, choice, prng, chl1);
    bool passed = true;
    for (u64 i = 0; i < n; ++i)
    {
        if (neq(messages2[i], messages[i][0]) && neq(messages2[i], messages[i][1]))
        {
            passed = false;
            std::cout << Color::Red;
            std::cout << i << " " << messages2[i] << " " << messages[i][0] << " " << messages[i][1] << std::endl << Color::Default;
        }
    }

    if (cmd.isSet("v"))
        std::cout << timer << std::endl;

    if (passed == false)
        throw RTE_LOC;
}

//void BgciksOT_mul_Test(const CLP& cmd)
//{
//    gf2x_mod_mul()
//}
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

    PRNG prng(toBlock(cmd.getOr("seed", 0)));

    std::vector<block> dest(n), in(n + 1);
    prng.get(dest.data(), dest.size());
    prng.get(in.data(), in.size());



    //std::cout << "a " << (_mm_slli_epi64(AllOneBlock, 20)) << std::endl;
    //std::cout << "b " << (_mm_srli_epi64(AllOneBlock, 20)) << std::endl;

    for (u64 i = 0; i < dest.size(); ++i)
    {
        u8 bitShift = prng.get<u8>() % 64;


        memset(dest.data(), 0, dest.size() * 16);

        BitVector dv((u8*)dest.data(), dest.size() * 128);
        BitVector iv;
        iv.append((u8*)in.data(), dest.size() * 128, bitShift);

        dv ^= iv;

        bitShiftXor(dest, in, bitShift);


        BitVector dv2((u8*)dest.data(), dest.size() * 128);

        if (dv != dv2)
        {
            auto b = (bitShift > 64) ? 128 - bitShift : 64 - bitShift;

            std::cout << "\n"<< bitShift<< "\n";
            std::cout << "   "
                << std::string(b, ' ')
                << std::string(bitShift, 'x') <<'\n';
            std::cout << "d2 " << dv2 << std::endl;
            std::cout << "d  " << dv << std::endl;
            std::cout << "f  " << (dv2 ^ dv) << std::endl;
            throw RTE_LOC;
        }

    }


}

void clearBits(span<block> in, u64 idx)
{
    auto p = (u8*)in.data() + idx / 8;
    auto e = (u8*)in.data() + in.size() * 16;

    if (idx & 7) 
    {
        *p++ &= (1 << (idx & 7)) - 1;
    }

    while (p != e)
        *p++ = 0;


    BitVector test((u8*)in.data(), in.size() * 128);
    for (u64 i = idx; i < test.size(); ++i)
        if (test[i])
            throw RTE_LOC;
}


void modp_test(const CLP& cmd)
{
    u64 n = cmd.getOr("n", 100);
    u64 c = cmd.getOr("c", 2);
    u64 t = cmd.getOr("t", 10);


    PRNG prng(toBlock(cmd.getOr("seed", 0)));

    auto iBits = n * c * 128  - prng.get<u64>() % 128;
    auto nBits = n * 128;

    std::vector<block> dest(n), in((iBits + 127) / 128);

    for (u64 i = 0; i < dest.size(); ++i)
    {
        u64 p = nBits;// -(prng.get<u64>() % 128);

        prng.get(in.data(), in.size());
        clearBits(in, iBits);

        memset(dest.data(), 0, dest.size() * 16);

        BitVector dv((u8*)in.data(), p);
        BitVector iv;

        for (u64 j = 1; j < c; ++j)
        {
            auto rem = std::min<u64>(p, iBits - j * p);
            iv.resize(0);
            iv.append((u8*)in.data(), rem, j * p);
            iv.resize(p, 0);

            dv ^= iv;
        }

        modp(dest, in, p);


        BitVector dv2((u8*)dest.data(), p);

        if (dv != dv2)
        {
            //auto b = (bitShift > 64) ? 128 - bitShift : 64 - bitShift;

            std::cout << "\n" << p << "\n";
            //std::cout << "   "
            //    << std::string(b, ' ')
            //    << std::string(bitShift, 'x') << '\n';
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
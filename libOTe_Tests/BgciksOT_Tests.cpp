#include "BgciksOT_Tests.h"
#include "libOTe/TwoChooseOne/BgciksOtExtSender.h"
#include "libOTe/TwoChooseOne/BgciksOtExtReceiver.h"
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Network/IOService.h>
using namespace oc;

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
            std::cout << Color::Red << i<< " "<< messages2[i] << " " << messages[i][0] << " " << messages[i][1] << std::endl << Color::Default;
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
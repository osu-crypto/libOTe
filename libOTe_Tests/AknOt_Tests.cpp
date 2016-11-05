#include "AknOt_Tests.h"
#include "Common/Defines.h"
#include "Network/BtIOService.h"
#include "Network/BtEndpoint.h"
#include "Common/Log.h"
#include "OT/NChooseK/AknOtReceiver.h"
#include "OT/NChooseK/AknOtSender.h"
#include "OT/TwoChooseOne/KosOtExtReceiver.h"
#include "OT/TwoChooseOne/KosOtExtSender.h"
#include "Common.h"
#include "OTOracleReceiver.h"
#include "OTOracleSender.h"
using namespace osuCrypto;

void AknOt_sendRecv1000_Test()
{

    u64 totalOts (149501);
    u64 minOnes    (4028);
    u64 avgOnes    (5028);
    u64 maxOnes    (9363);
    u64 cncThreshold(724);
    double cncProb (0.0999);

    //u64 totalOts  (10);
    //u64 minOnes    (0);
    //u64 avgOnes    (5);
    //u64 maxOnes    (999999999);
    //u64 cncThreshold(9999999);
    //double cncProb (0.1);


    Log::setThreadName("Recvr");

    BtIOService ios(0);
    BtEndpoint  ep0(ios, "127.0.0.1", 1212, true, "ep");
    BtEndpoint  ep1(ios, "127.0.0.1", 1212, false, "ep");
    
    u64 numTHreads(4);

    std::vector<Channel*> sendChls(numTHreads), recvChls(numTHreads);
    for (u64 i = 0; i < numTHreads; ++i)
    {
        sendChls[i] = &ep1.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));
        recvChls[i] = &ep0.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));
    }
    //Channel& sChl  = ep1.addChannel("chl0", "chl0");
    //Channel& rChl  = ep0.addChannel("chl0", "chl0");
    //Channel& sChl1 = ep1.addChannel("chl1", "chl1");
    //Channel& rChl1 = ep0.addChannel("chl1", "chl1");

    AknOtReceiver recv;
    AknOtSender send;

    OTOracleReceiver otExtRecv(ZeroBlock);
    OTOracleSender otExtSend(ZeroBlock);

    PRNG
        sPrng(ZeroBlock),
        rPrng(OneBlock);


    //BitVector bv(128);
    //bv.randomize(sPrng);
    //std::vector<block> r(128);
    //std::vector<std::array<block, 2>> s(128);

    //std::atomic<u64>__(0),___(0);
    //otExtRecv.Extend(bv, r, rPrng, *(Channel*)nullptr, __);
    //otExtSend.Extend(s, rPrng, *(Channel*)nullptr, ___);

    //if (neq(r[0], s[0][bv[0]]))
    //    throw UnitTestFail();

    std::thread thrd([&]() {

        Log::setThreadName("Sender");

        send.init(totalOts, cncThreshold, cncProb,otExtSend, sendChls, sPrng);
    });

    recv.init(totalOts, avgOnes, cncProb, otExtRecv, recvChls, rPrng);


    thrd.join();

    
    for (u64 i = 0; i < recv.mMessages.size(); ++i)
    {

        if (neq(send.mMessages[i][recv.mChoices[i]], recv.mMessages[i]))
            throw UnitTestFail();
    }

    if (recv.mOnes.size() < minOnes)
        throw UnitTestFail();



    if (recv.mOnes.size() > maxOnes)
        throw UnitTestFail();

    for (u64 i = 0; i < numTHreads; ++i)
    {
        sendChls[i]->close();// = &ep1.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));
        recvChls[i]->close();// = &ep0.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));
    }
    //sChl.close();
    //rChl.close();
    //sChl1.close();
    //rChl1.close();

    ep0.stop();
    ep1.stop();

    ios.stop();

}

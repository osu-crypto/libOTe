#include "AknOt_Tests.h"
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Network/Endpoint.h>
#include <cryptoTools/Common/Log.h>
#include "libOTe/NChooseK/AknOtReceiver.h"
#include "libOTe/NChooseK/AknOtSender.h"
#include "libOTe/TwoChooseOne/KosOtExtReceiver.h"
#include "libOTe/TwoChooseOne/KosOtExtSender.h"
#include "Common.h"
#include "OTOracleReceiver.h"
#include "OTOracleSender.h"
using namespace osuCrypto;

namespace tests_libOTe
{
    void AknOt_sendRecv1000_Test()
    {

        u64 totalOts(149501);
        u64 minOnes(4028);
        u64 avgOnes(5028);
        u64 maxOnes(9363);
        u64 cncThreshold(724);
        double cncProb(0.0999);

        //u64 totalOts  (10);
        //u64 minOnes    (0);
        //u64 avgOnes    (5);
        //u64 maxOnes    (999999999);
        //u64 cncThreshold(9999999);
        //double cncProb (0.1);


        setThreadName("Recvr");

        IOService ios(0);
        Endpoint  ep0(ios, "127.0.0.1", 1212, EpMode::Server, "ep");
        Endpoint  ep1(ios, "127.0.0.1", 1212, EpMode::Client, "ep");

        u64 numTHreads(4);

        std::vector<Channel> sendChls(numTHreads), recvChls(numTHreads);
        for (u64 i = 0; i < numTHreads; ++i)
        {
            sendChls[i] = std::move(ep1.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i)));
            recvChls[i] = std::move(ep0.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i)));
        }


        AknOtReceiver recv;
        AknOtSender send;

        OTOracleReceiver otExtRecv(ZeroBlock);
        OTOracleSender otExtSend(ZeroBlock);

        PRNG
            sPrng(ZeroBlock),
            rPrng(OneBlock);

        std::thread thrd([&]() {

            setThreadName("Sender");

            send.init(totalOts, cncThreshold, cncProb, otExtSend, sendChls, sPrng);
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

        //for (u64 i = 0; i < numTHreads; ++i)
        //{
        //    sendChls[i].close();
        //    recvChls[i].close();
        //}

        //ep0.stop();
        //ep1.stop();

        //ios.stop();

    }
}
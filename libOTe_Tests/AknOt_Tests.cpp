#include "AknOt_Tests.h"
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Common/Log.h>
#include "libOTe/NChooseK/AknOtReceiver.h"
#include "libOTe/NChooseK/AknOtSender.h"
#include "libOTe/TwoChooseOne/KosOtExtReceiver.h"
#include "libOTe/TwoChooseOne/KosOtExtSender.h"
#include "Common.h"
#include <cryptoTools/Common/TestCollection.h>
using namespace osuCrypto;
#include "libOTe/Base/BaseOT.h"

namespace tests_libOTe
{
    void AknOt_sendRecv1000_Test()
    {
#if defined(ENABLE_AKN)
#ifndef LIBOTE_HAS_BASE_OT
#pragma error("ENABLE_AKN requires libOTe to have base OTs");
#endif


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
        Session  ep0(ios, "127.0.0.1", 1212, SessionMode::Server, "ep");
        Session  ep1(ios, "127.0.0.1", 1212, SessionMode::Client, "ep");

        u64 numTHreads(4);

        std::vector<Channel> sendChls(numTHreads), recvChls(numTHreads);
        for (u64 i = 0; i < numTHreads; ++i)
        {
            sendChls[i] = std::move(ep1.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i)));
            recvChls[i] = std::move(ep0.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i)));
        }


        AknOtReceiver recv;
        AknOtSender send;

        KosOtExtReceiver otExtRecv;
        KosOtExtSender otExtSend;

        PRNG
            sPrng(ZeroBlock),
            rPrng(OneBlock);

        bool failed = false;
        std::thread thrd([&]() {

            setThreadName("Sender");
            try {

                send.init(totalOts, cncThreshold, cncProb, otExtSend, sendChls, sPrng);
            }
            catch (...)
            {
                failed = true;
            }
        });

        try {

            recv.init(totalOts, avgOnes, cncProb, otExtRecv, recvChls, rPrng);
        }
        catch (...)
        {
            failed = true;
        }
        thrd.join();

        if (failed)
            throw RTE_LOC;

        for (u64 i = 0; i < recv.mMessages.size(); ++i)
        {
            if (neq(send.mMessages[i][recv.mChoices[i]], recv.mMessages[i]))
                throw UnitTestFail();
        }

        if (recv.mOnes.size() < minOnes)
            throw UnitTestFail();
        if (recv.mOnes.size() > maxOnes)
            throw UnitTestFail();

#else
        throw UnitTestSkipped("no base OTs are enabled or ENABLE_AKN not defined.");
#endif
    }
}
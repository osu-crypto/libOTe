#include "OT_Tests.h"

#include "libOTe/TwoChooseOne/OTExtInterface.h"

#include "libOTe/Tools/Tools.h"
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/IOService.h>

#include "libOTe/Base/naor-pinkas.h"
#include <cryptoTools/Common/Log.h>

#include "Common.h"
#include <thread>
#include <vector>
#include <cryptoTools/Common/BitVector.h>

#ifdef GetMessage
#undef GetMessage
#endif

using namespace osuCrypto;


namespace tests_libOTe
{

    void NaorPinkasOt_Test_Impl()
    {
        setThreadName("Sender");

        IOService ios(0);
        Session ep0(ios, "127.0.0.1", 1212, SessionMode::Server);
        Session ep1(ios, "127.0.0.1", 1212, SessionMode::Client);
        Channel senderChannel = ep1.addChannel();
        Channel recvChannel = ep0.addChannel();

        PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
        PRNG prng1(_mm_set_epi32(4253233465, 334565, 0, 235));

        u64 numOTs = 1;
        std::atomic<u64> sendedDoneIdx(0), recvDoneIdx(0);
        std::vector<block> recvMsg(numOTs);
        std::vector<std::array<block, 2>> sendMsg(numOTs);
        BitVector choices(numOTs);
        choices.randomize(prng0);



        std::thread thrd = std::thread([&]() {
            setThreadName("receiver");


            //crypto crpt(128, prng1.getSeed());


            NaorPinkas baseOTs;// (&crpt);

            //baseOTs(recvChannel, OTRole::Sender);

            baseOTs.send(sendMsg, prng1, recvChannel, 1);
            //baseOTs.exec_base(prng0);


            //{
            //    std::lock_guard<std::mutex> lock(Log::mMtx);
            //    for (u64 i = 0; i < baseOTs.receiver_outputs.size(); ++i)
            //    {
            //        std::cout << "i  " << baseOTs.sender_inputs[i][0] << " " << baseOTs.sender_inputs[i][1] << std::endl;
            //    }

        });

        //crypto crpt(128, prng0.get<block>());
        NaorPinkas baseOTs;

        baseOTs.receive(choices, recvMsg, prng0, senderChannel, 1);

        thrd.join();

        senderChannel.close();
        recvChannel.close();

        ep1.stop();
        ep0.stop();

        ios.stop();


        for (u64 i = 0; i < numOTs; ++i)
        {
            if (neq(recvMsg[i], sendMsg[i][choices[i]]))
            {
                std::cout << "failed " << i << std::endl;
                throw UnitTestFail();
            }
        }

    }

}
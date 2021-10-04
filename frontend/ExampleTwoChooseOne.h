#pragma once

#include "libOTe/Base/BaseOT.h"
#include "libOTe/TwoChooseOne/KosOtExtReceiver.h"
#include "libOTe/TwoChooseOne/KosOtExtSender.h"
#include "libOTe/TwoChooseOne/KosDotExtReceiver.h"
#include "libOTe/TwoChooseOne/KosDotExtSender.h"
#include "libOTe/TwoChooseOne/IknpOtExtReceiver.h"
#include "libOTe/TwoChooseOne/IknpOtExtSender.h"


#include "libOTe/TwoChooseOne/SilentOtExtReceiver.h"
#include "libOTe/TwoChooseOne/SilentOtExtSender.h"

namespace osuCrypto
{

#ifdef ENABLE_IKNP
    void noHash(IknpOtExtSender& s, IknpOtExtReceiver& r)
    {
        s.mHash = false;
        r.mHash = false;
    }
#endif

    template<typename Sender, typename Receiver>
    void noHash(Sender&, Receiver&)
    {
        throw std::runtime_error("This protocol does not support noHash");
    }

    template<typename OtExtSender, typename OtExtRecver>
    void TwoChooseOne_example(Role role, int totalOTs, int numThreads, std::string ip, std::string tag, CLP& cmd)
    {
        if (totalOTs == 0)
            totalOTs = 1 << 20;

        bool randomOT = true;

        auto numOTs = totalOTs / numThreads;
        u64 trials = cmd.getOr("trials", 1);

        // get up the networking
        auto rr = role == Role::Sender ? SessionMode::Server : SessionMode::Client;
        IOService ios;
        Session  ep0(ios, ip, rr);
        PRNG prng(sysRandomSeed());

        // for each thread we need to construct a channel (socket) for it to communicate on.
        std::vector<Channel> chls(numThreads);
        for (int i = 0; i < numThreads; ++i)
            chls[i] = ep0.addChannel();



        std::vector<OtExtSender> senders(numThreads);
        std::vector<OtExtRecver> receivers(numThreads);

#ifdef LIBOTE_HAS_BASE_OT
        // Now compute the base OTs, we need to set them on the first pair of extenders.
        // In real code you would only have a sender or reciever, not both. But we do
        // here just showing the example.
        if (role == Role::Receiver)
        {
            DefaultBaseOT base;
            std::array<std::array<block, 2>, 128> baseMsg;
            base.send(baseMsg, prng, chls[0], numThreads);
            receivers[0].setBaseOts(baseMsg, prng, chls[0]);

            //receivers[0].genBaseOts(prng, chls[0]);
        }
        else
        {

            DefaultBaseOT base;
            BitVector bv(128);
            std::array<block, 128> baseMsg;
            bv.randomize(prng);
            base.receive(bv, baseMsg, prng, chls[0], numThreads);
            senders[0].setBaseOts(baseMsg, bv, chls[0]);
        }
#else
        if (!cmd.isSet("fakeBase"))
            std::cout << "warning, base ots are not enabled. Fake base OTs will be used. " << std::endl;
        PRNG commonPRNG(oc::ZeroBlock);
        std::array<std::array<block, 2>, 128> sendMsgs;
        commonPRNG.get(sendMsgs.data(), sendMsgs.size());
        if (role == Role::Receiver)
        {
            receivers[0].setBaseOts(sendMsgs, prng, chls[0]);
        }
        else
        {
            BitVector bv(128);
            bv.randomize(commonPRNG);
            std::array<block, 128> recvMsgs;
            for (u64 i = 0; i < 128; ++i)
                recvMsgs[i] = sendMsgs[i][bv[i]];
            senders[0].setBaseOts(recvMsgs, bv, chls[0]);
        }
#endif

        // for the rest of the extenders, call split. This securely
        // creates two sets of extenders that can be used in parallel.
        for (auto i = 1; i < numThreads; ++i)
        {
            if (role == Role::Receiver)
                receivers[i] = receivers[0].splitBase();
            else
                senders[i] = senders[0].splitBase();
        }

        if (cmd.isSet("noHash"))
            for (auto i = 0; i < numThreads; ++i)
                noHash(senders[i], receivers[i]);

        Timer timer, sendTimer, recvTimer;
        sendTimer.setTimePoint("start");
        recvTimer.setTimePoint("start");
        auto routine = [&](int i)
        {
            // get a random number generator seeded from the system
            PRNG prng(sysRandomSeed());

            // construct a vector to stored the random send messages.
            std::vector<std::array<block, 2>> sMsgs(numOTs * (role == Role::Sender));

            // construct the choices that we want.
            BitVector choice(numOTs);
            // in this case pick random messages.
            choice.randomize(prng);

            // construct a vector to stored the received messages.
            std::vector<block> rMsgs(numOTs * (role != Role::Sender));

            for (u64 tt = 0; tt < trials; ++tt)
            {

                timer.reset();
                auto s = timer.setTimePoint("start");

                if (role == Role::Receiver)
                {

                    if (randomOT)
                    {
                        // perform  numOTs random OTs, the results will be written to msgs.
                        receivers[i].receive(choice, rMsgs, prng, chls[i]);
                    }
                    else
                    {
                        // perform  numOTs chosen message OTs, the results will be written to msgs.
                        receivers[i].receiveChosen(choice, rMsgs, prng, chls[i]);
                    }
                }
                else
                {

                    // if delta OT is used, then the user can call the following
                    // to set the desired XOR difference between the zero messages
                    // and the one messages.
                    //
                    //     senders[i].setDelta(some 128 bit delta);
                    //

                    if (randomOT)
                    {
                        // perform the OTs and write the random OTs to msgs.
                        senders[i].send(sMsgs, prng, chls[i]);
                    }
                    else
                    {
                        // Populate msgs with something useful...
                        prng.get(sMsgs.data(), sMsgs.size());

                        // perform the OTs. The receiver will learn one
                        // of the messages stored in msgs.
                        senders[i].sendChosen(sMsgs, prng, chls[i]);
                    }
                }

                auto e = timer.setTimePoint("finish");
                auto milli = std::chrono::duration_cast<std::chrono::milliseconds>(e - s).count();

                auto com = (chls[0].getTotalDataRecv() + chls[0].getTotalDataSent()) * numThreads;

                if (role == Role::Sender && i == 0)
                    lout << tag << " n=" << Color::Green << totalOTs << " " << milli << " ms  " << com << " bytes" << std::endl << Color::Default;

            }

            if (cmd.isSet("v") && role == Role::Sender && i == 0)
            {
                if (role == Role::Sender)
                    lout << " **** sender ****\n" << sendTimer << std::endl;

                if (role == Role::Receiver)
                    lout << " **** receiver ****\n" << recvTimer << std::endl;
            }

        };

        senders[0].setTimer(sendTimer);
        receivers[0].setTimer(recvTimer);

        std::vector<std::thread> thrds(numThreads);
        for (int i = 0; i < numThreads; ++i)
            thrds[i] = std::thread(routine, i);

        for (int i = 0; i < numThreads; ++i)
            thrds[i].join();


    }


}

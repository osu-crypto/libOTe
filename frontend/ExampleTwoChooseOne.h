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

#include "libOTe/TwoChooseOne/SoftSpokenOT/DotSemiHonest.h"
#include "libOTe/TwoChooseOne/SoftSpokenOT/DotMaliciousLeaky.h"
#include "libOTe/TwoChooseOne/SoftSpokenOT/DotMalicious.h"
#include "libOTe/TwoChooseOne/SoftSpokenOT/TwoOneSemiHonest.h"
#include "libOTe/TwoChooseOne/SoftSpokenOT/TwoOneMalicious.h"

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

    template<typename OtExtSender, typename OtExtRecver, typename ...Params>
    void TwoChooseOne_example(Role role, int totalOTs, int numThreads, std::string ip, std::string tag, CLP& cmd, Params&&... params)
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



        std::vector<OtExtSender> senders;
        std::vector<OtExtRecver> receivers;
        senders.reserve(numThreads);
        receivers.reserve(numThreads);

        size_t nBaseOTs;
        if (role == Role::Receiver)
        {
            receivers.emplace_back(std::forward<Params>(params)...);
            nBaseOTs = receivers[0].baseOtCount();
        }
        else
        {
            senders.emplace_back(std::forward<Params>(params)...);
            nBaseOTs = senders[0].baseOtCount();
        }

#ifndef LIBOTE_HAS_BASE_OT
        if (!cmd.isSet("fakeBase"))
            std::cout << "warning, base ots are not enabled. Fake base OTs will be used. " << std::endl;
#else
        if (cmd.isSet("fakeBase"))
#endif
        {

            PRNG commonPRNG(oc::ZeroBlock);
            std::vector<std::array<block, 2>> sendMsgs(nBaseOTs);
            commonPRNG.get(sendMsgs.data(), sendMsgs.size());
            if (role == Role::Receiver)
            {
                receivers[0].setBaseOts(sendMsgs, prng, chls[0]);
            }
            else
            {
                BitVector bv(nBaseOTs);
                bv.randomize(commonPRNG);
                std::vector<block> recvMsgs(nBaseOTs);
                for (u64 i = 0; i < nBaseOTs; ++i)
                    recvMsgs[i] = sendMsgs[i][bv[i]];
                senders[0].setBaseOts(recvMsgs, bv, prng, chls[0]);
            }
        }

        // for the rest of the extenders, call split. This securely
        // creates two sets of extenders that can be used in parallel.
        for (auto i = 1; i < numThreads; ++i)
        {
            if (role == Role::Receiver)
                receivers.push_back(receivers[0].splitBase());
            else
                senders.push_back(senders[0].splitBase());
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
            auto sMsgs = allocAlignedBlockArray<std::array<block, 2>>(numOTs * (role == Role::Sender));

            // construct the choices that we want.
            BitVector choice(numOTs);
            // in this case pick random messages.
            choice.randomize(prng);

            // construct a vector to stored the received messages.
            auto rMsgs = allocAlignedBlockArray(numOTs * (role != Role::Sender));

            const char* roleStr = (role == Role::Sender) ? "Sender" : "Receiver";

            u64 totalMilli = 0;
            u64 totalCom = 0;
            u64 totalStartupMilli = 0;
            u64 totalStartupCom = 0;
            for (u64 tt = 0; tt < trials; ++tt)
            {
                sync(chls[i], role);
                chls[0].resetStats();

                timer.reset();
                auto s = timer.setTimePoint("start");

#ifdef LIBOTE_HAS_BASE_OT
                if (!cmd.isSet("fakeBase"))
                {
                    // Now compute the base OTs, we need to set them on the first pair of extenders.
                    // In real code you would only have a sender or reciever, not both. But we do
                    // here just showing the example.
                    if (role == Role::Receiver)
                    {
                        receivers.emplace_back(std::forward<Params>(params)...);
                        DefaultBaseOT base;
                        std::vector<std::array<block, 2>, AlignedBlockAllocator2> baseMsg(nBaseOTs);
                        base.send(baseMsg, prng, chls[i], numThreads);
                        receivers[i].setBaseOts(baseMsg, prng, chls[i]);
                    }
                    else
                    {

                        DefaultBaseOT base;
                        BitVector bv(nBaseOTs);
                        std::vector<block, AlignedBlockAllocator> baseMsg(nBaseOTs);
                        bv.randomize(prng);
                        base.receive(bv, baseMsg, prng, chls[i], numThreads);
                        senders[i].setBaseOts(baseMsg, bv, prng, chls[i]);
                    }
                }
#endif

                auto Startup = timer.setTimePoint("Startup");
                auto milli = std::chrono::duration_cast<std::chrono::milliseconds>(Startup - s).count();
                totalStartupMilli += milli;

                auto com = chls[0].getTotalDataRecv() * numThreads;
                totalStartupCom += com;

                if (role == Role::Receiver)
                {

                    if (randomOT)
                    {
                        // perform  numOTs random OTs, the results will be written to msgs.
                        receivers[i].receive(choice, span(rMsgs.get(), numOTs), prng, chls[i]);
                    }
                    else
                    {
                        // perform  numOTs chosen message OTs, the results will be written to msgs.
                        receivers[i].receiveChosen(choice, span(rMsgs.get(), numOTs), prng, chls[i]);
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
                        senders[i].send(span(sMsgs.get(), numOTs), prng, chls[i]);
                    }
                    else
                    {
                        // Populate msgs with something useful...
                        prng.get(sMsgs.get(), numOTs);

                        // perform the OTs. The receiver will learn one
                        // of the messages stored in msgs.
                        senders[i].sendChosen(span(sMsgs.get(), numOTs), prng, chls[i]);
                    }
                }

                auto e = timer.setTimePoint("finish");
                milli = std::chrono::duration_cast<std::chrono::milliseconds>(e - s).count();
                totalMilli += milli;

                com = chls[0].getTotalDataRecv() * numThreads;
                totalCom += com;
                chls[0].resetStats();

                if (i == 0)
                {
                    lout << tag << " (" << roleStr << ") n=" << Color::Green << totalOTs << " " << milli << " ms  " << com << " bytes" << std::endl << Color::Default;
                }

            }

            if (i == 0)
            {
                i64 avgMilli = lround((double) totalMilli / trials);
                i64 avgCom = lround((double) totalCom / trials);
                i64 avgStartupMilli = lround((double) totalStartupMilli / trials);
                i64 avgStartupCom = lround((double) totalStartupCom / trials);
                lout << tag << " (" << roleStr << ") average: n=" << Color::Green << totalOTs << " " << avgMilli << " ms  " << avgCom << " bytes, Startup " << avgStartupMilli << " ms  " << avgStartupCom << " bytes" << std::endl << Color::Default;
            }

            if (cmd.isSet("v") && role == Role::Sender && i == 0)
            {
                if (role == Role::Sender)
                    lout << " **** sender ****\n" << sendTimer << std::endl;

                if (role == Role::Receiver)
                    lout << " **** receiver ****\n" << recvTimer << std::endl;
            }

        };

        if (role == Role::Receiver)
            receivers[0].setTimer(recvTimer);
        else
            senders[0].setTimer(sendTimer);

        std::vector<std::thread> thrds(numThreads);
        for (int i = 0; i < numThreads; ++i)
            thrds[i] = std::thread(routine, i);

        for (int i = 0; i < numThreads; ++i)
            thrds[i].join();


    }


}

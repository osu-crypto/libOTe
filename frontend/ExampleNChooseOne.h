#pragma once


#include "cryptoTools/Common/Matrix.h"
#include "libOTe/NChooseOne/Oos/OosNcoOtReceiver.h"
#include "libOTe/NChooseOne/Oos/OosNcoOtSender.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h"
#include "cryptoTools/Common/Matrix.h"

namespace osuCrypto
{





    template<typename NcoOtSender, typename  NcoOtReceiver>
    void NChooseOne_example(Role role, int totalOTs, int numThreads, std::string ip, std::string tag, CLP&)
    {
        const u64 step = 1024;

        if (totalOTs == 0)
            totalOTs = 1 << 20;

        bool randomOT = true;
        auto numOTs = totalOTs / numThreads;
        auto numChosenMsgs = 256;

        // get up the networking
        auto rr = role == Role::Sender ? SessionMode::Server : SessionMode::Client;
        IOService ios;
        Session  ep0(ios, ip, rr);
        PRNG prng(sysRandomSeed());

        // for each thread we need to construct a channel (socket) for it to communicate on.
        std::vector<Channel> chls(numThreads);
        for (int i = 0; i < numThreads; ++i)
            chls[i] = ep0.addChannel();

        std::vector<NcoOtReceiver> recvers(numThreads);
        std::vector<NcoOtSender> senders(numThreads);

        // all Nco Ot extenders must have configure called first. This determines
        // a variety of parameters such as how many base OTs are required.
        bool maliciousSecure = false;
        u64 statSecParam = 40;
        u64 inputBitCount = 76; // the kkrt protocol default to 128 but oos can only do 76.
        recvers[0].configure(maliciousSecure, statSecParam, inputBitCount);
        senders[0].configure(maliciousSecure, statSecParam, inputBitCount);

        // Generate new base OTs for the first extender. This will use
        // the default BaseOT protocol. You can also manually set the
        // base OTs with setBaseOts(...);
        if (role == Role::Sender)
            senders[0].genBaseOts(prng, chls[0]);
        else
            recvers[0].genBaseOts(prng, chls[0]);

        // now that we have one valid pair of extenders, we can call split on
        // them to get more copies which can be used concurrently.
        for (int i = 1; i < numThreads; ++i)
        {
            recvers[i] = recvers[0].splitBase();
            senders[i] = senders[0].splitBase();
        }

        // create a lambda function that performs the computation of a single receiver thread.
        auto recvRoutine = [&](int k)
        {
            auto& chl = chls[k];
            PRNG prng(sysRandomSeed());

            if (randomOT)
            {
                // once configure(...) and setBaseOts(...) are called,
                // we can compute many batches of OTs. First we need to tell
                // the instance how mant OTs we want in this batch. This is done here.
                recvers[k].init(numOTs, prng, chl);

                // now we can iterate over the OTs and actaully retreive the desired
                // messages. However, for efficieny we will do this in steps where
                // we do some computation followed by sending off data. This is more
                // efficient since data will be sent in the background :).
                for (int i = 0; i < numOTs; )
                {
                    // figure out how many OTs we want to do in this step.
                    auto min = std::min<u64>(numOTs - i, step);

                    // iterate over this step.
                    for (u64 j = 0; j < min; ++j, ++i)
                    {
                        // For the OT index by i, we need to pick which
                        // one of the N OT messages that we want. For this
                        // example we simply pick a random one. Note only the
                        // first log2(N) bits of choice is considered.
                        block choice = prng.get<block>();

                        // this will hold the (random) OT message of our choice
                        block otMessage;

                        // retreive the desired message.
                        recvers[k].encode(i, &choice, &otMessage);

                        // do something cool with otMessage
                        //otMessage;
                    }

                    // Note that all OTs in this region must be encode. If there are some
                    // that you don't actually care about, then you can skip them by calling
                    //
                    //    recvers[k].zeroEncode(i);
                    //

                    // Now that we have gotten out the OT messages for this step,
                    // we are ready to send over network some information that
                    // allows the sender to also compute the OT messages. Since we just
                    // encoded "min" OT messages, we will tell the class to send the
                    // next min "correction" values.
                    recvers[k].sendCorrection(chl, min);
                }

                // once all numOTs have been encoded and had their correction values sent
                // we must call check. This allows to sender to make sure we did not cheat.
                // For semi-honest protocols, this can and will be skipped.
                recvers[k].check(chl, ZeroBlock);

            }
            else
            {
                std::vector<block>recvMsgs(numOTs);
                std::vector<u64> choices(numOTs);

                // define which messages the receiver should learn.
                for (int i = 0; i < numOTs; ++i)
                    choices[i] = prng.get<u8>();

                // the messages that were learned are written to recvMsgs.
                recvers[k].receiveChosen(numChosenMsgs, recvMsgs, choices, prng, chl);
            }
        };

        // create a lambda function that performs the computation of a single sender thread.
        auto sendRoutine = [&](int k)
        {
            auto& chl = chls[k];
            PRNG prng(sysRandomSeed());

            if (randomOT)
            {
                // Same explanation as above.
                senders[k].init(numOTs, prng, chl);

                // Same explanation as above.
                for (int i = 0; i < numOTs; )
                {
                    // Same explanation as above.
                    auto min = std::min<u64>(numOTs - i, step);

                    // unlike for the receiver, before we call encode to get
                    // some desired OT message, we must call recvCorrection(...).
                    // This receivers some information that the receiver had sent
                    // and allows the sender to compute any OT message that they desired.
                    // Note that the step size must match what the receiver used.
                    // If this is unknown you can use recvCorrection(chl) -> u64
                    // which will tell you how many were sent.
                    senders[k].recvCorrection(chl, min);
                    i += min;
                    //// we now encode any OT message with index less that i + min.
                    //for (u64 j = 0; j < min; ++j, ++i)
                    //{
                    //    // in particular, the sender can retreive many OT messages
                    //    // at a single index, in this case we chose to retreive 3
                    //    // but that is arbitrary.
                    //    auto choice0 = prng.get<block>();
                    //    auto choice1 = prng.get<block>();
                    //    auto choice2 = prng.get<block>();

                    //    // these we hold the actual OT messages.
                    //    block
                    //        otMessage0,
                    //        otMessage1,
                    //        otMessage2;

                    //    // now retreive the messages
                    //    senders[k].encode(i, &choice0, &otMessage0);
                    //    senders[k].encode(i, &choice1, &otMessage1);
                    //    senders[k].encode(i, &choice2, &otMessage2);
                    //}
                }

                // This call is required to make sure the receiver did not cheat.
                // All corrections must be recieved before this is called.
                senders[k].check(chl, ZeroBlock);
            }
            else
            {
                // populate this with the messages that you want to send.
                Matrix<block> sendMessages(numOTs, numChosenMsgs);
                prng.get(sendMessages.data(), sendMessages.size());

                // perform the OTs with the given messages.
                senders[k].sendChosen(sendMessages, prng, chl);
            }
        };


        std::vector<std::thread> thds(numThreads);
        std::function<void(int)> routine;

        if (role == Role::Sender)
            routine = sendRoutine;
        else
            routine = recvRoutine;


        Timer time;
        auto s = time.setTimePoint("start");

        for (int k = 0; k < numThreads; ++k)
            thds[k] = std::thread(routine, k);


        for (int k = 0; k < numThreads; ++k)
            thds[k].join();

        auto e = time.setTimePoint("finish");
        auto milli = std::chrono::duration_cast<std::chrono::milliseconds>(e - s).count();

        if (role == Role::Sender)
            std::cout << tag << " n=" << totalOTs << " " << milli << " ms  " << (chls[0].getTotalDataRecv() + chls[0].getTotalDataSent()) * chls.size() << std::endl;
    }

}

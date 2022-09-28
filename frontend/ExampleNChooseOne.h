#pragma once


#include "cryptoTools/Common/Matrix.h"
#include "libOTe/NChooseOne/Oos/OosNcoOtReceiver.h"
#include "libOTe/NChooseOne/Oos/OosNcoOtSender.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h"
#include "cryptoTools/Common/Matrix.h"
#include "libOTe/Tools/Coproto.h"

namespace osuCrypto
{



    auto chls = cp::LocalAsyncSocket::makePair();

    template<typename NcoOtSender, typename  NcoOtReceiver>
    void NChooseOne_example(Role role, int totalOTs, int numThreads, std::string ip, std::string tag, CLP&)
    {
#ifdef COPROTO_ENABLE_BOOST
        const u64 step = 1024;

        if (totalOTs == 0)
            totalOTs = 1 << 20;

        bool randomOT = true;
        u64 numOTs = (u64)totalOTs;
        auto numChosenMsgs = 256;

        // get up the networking        
        auto chl = cp::asioConnect(ip, role == Role::Sender);
        //auto chl = role == Role::Sender ? chls[0] : chls[1];

        PRNG prng(ZeroBlock);// sysRandomSeed());

        NcoOtSender sender;
        NcoOtReceiver recver;

        // all Nco Ot extenders must have configure called first. This determines
        // a variety of parameters such as how many base OTs are required.
        bool maliciousSecure = false;
        u64 statSecParam = 40;
        u64 inputBitCount = 76; // the kkrt protocol default to 128 but oos can only do 76.

        // create a lambda function that performs the computation of a single receiver thread.
        auto recvRoutine = [&]() -> task<>
        {
            MC_BEGIN(task<>,&,
                i = u64{}, min = u64{},
                recvMsgs = std::vector<block>{},
                choices = std::vector<u64>{}
                );

            recver.configure(maliciousSecure, statSecParam, inputBitCount);
            //MC_AWAIT(sync(chl, Role::Receiver));

            if (randomOT)
            {
                // once configure(...) and setBaseOts(...) are called,
                // we can compute many batches of OTs. First we need to tell
                // the instance how many OTs we want in this batch. This is done here.
                MC_AWAIT(recver.init(numOTs, prng, chl));

                // now we can iterate over the OTs and actually retrieve the desired
                // messages. However, for efficiency we will do this in steps where
                // we do some computation followed by sending off data. This is more
                // efficient since data will be sent in the background :).
                for (i = 0; i < numOTs; )
                {
                    // figure out how many OTs we want to do in this step.
                    min = std::min<u64>(numOTs - i, step);

                    //// iterate over this step.
                    for (u64 j = 0; j < min; ++j, ++i)
                    {
                        // For the OT index by i, we need to pick which
                        // one of the N OT messages that we want. For this
                        // example we simply pick a random one. Note only the
                        // first log2(N) bits of choice is considered.
                        block choice = prng.get<block>();

                        // this will hold the (random) OT message of our choice
                        block otMessage;

                        // retrieve the desired message.
                        recver.encode(i, &choice, &otMessage);

                        // do something cool with otMessage
                        //otMessage;
                    }

                    // Note that all OTs in this region must be encode. If there are some
                    // that you don't actually care about, then you can skip them by calling
                    //
                    //    recver.zeroEncode(i);
                    //

                    // Now that we have gotten out the OT mMessages for this step,
                    // we are ready to send over network some information that
                    // allows the sender to also compute the OT mMessages. Since we just
                    // encoded "min" OT mMessages, we will tell the class to send the
                    // next min "correction" values.
                    MC_AWAIT(recver.sendCorrection(chl, min));
                }

                // once all numOTs have been encoded and had their correction values sent
                // we must call check. This allows to sender to make sure we did not cheat.
                // For semi-honest protocols, this can and will be skipped.
                MC_AWAIT(recver.check(chl, prng.get()));
            }
            else
            {
                recvMsgs.resize(numOTs);
                choices.resize(numOTs);

                // define which messages the receiver should learn.
                for (i = 0; i < numOTs; ++i)
                    choices[i] = prng.get<u8>();

                // the messages that were learned are written to recvMsgs.
                MC_AWAIT(recver.receiveChosen(numChosenMsgs, recvMsgs, choices, prng, chl));
            }

            MC_AWAIT(chl.flush());
            MC_END();
        };

        // create a lambda function that performs the computation of a single sender thread.
        auto sendRoutine = [&]()
        {
            MC_BEGIN(task<>,&,
                sendMessages = Matrix<block>{},
                i = u64{}, min = u64{}
                );

            sender.configure(maliciousSecure, statSecParam, inputBitCount);
            //MC_AWAIT(sync(chl, Role::Sender));

            if (randomOT)
            {
                // Same explanation as above.
                MC_AWAIT(sender.init(numOTs, prng, chl));

                // Same explanation as above.
                for (i = 0; i < numOTs; )
                {
                    // Same explanation as above.
                    min = std::min<u64>(numOTs - i, step);

                    // unlike for the receiver, before we call encode to get
                    // some desired OT message, we must call recvCorrection(...).
                    // This receivers some information that the receiver had sent
                    // and allows the sender to compute any OT message that they desired.
                    // Note that the step size must match what the receiver used.
                    // If this is unknown you can use recvCorrection(chl) -> u64
                    // which will tell you how many were sent.
                    MC_AWAIT(sender.recvCorrection(chl, min));

                    // we now encode any OT message with index less that i + min.
                    for (u64 j = 0; j < min; ++j, ++i)
                    {
                        // in particular, the sender can retrieve many OT messages
                        // at a single index, in this case we chose to retrieve 3
                        // but that is arbitrary.
                        auto choice0 = prng.get<block>();
                        auto choice1 = prng.get<block>();
                        auto choice2 = prng.get<block>();

                        // these we hold the actual OT messages.
                        block
                            otMessage0,
                            otMessage1,
                            otMessage2;

                        // now retrieve the messages
                        sender.encode(i, &choice0, &otMessage0);
                        sender.encode(i, &choice1, &otMessage1);
                        sender.encode(i, &choice2, &otMessage2);
                    }
                }

                // This call is required to make sure the receiver did not cheat.
                // All corrections must be received before this is called.
                MC_AWAIT(sender.check(chl, ZeroBlock));
            }
            else
            {
                // populate this with the messages that you want to send.
                sendMessages.resize(numOTs, numChosenMsgs);
                prng.get(sendMessages.data(), sendMessages.size());

                // perform the OTs with the given messages.
                MC_AWAIT(sender.sendChosen(sendMessages, prng, chl));

            }

            MC_AWAIT(chl.flush());
            MC_END();
        };


        Timer time;
        auto s = time.setTimePoint("start");


        task<> proto;
        if (role == Role::Sender)
            proto = sendRoutine();
        else
            proto = recvRoutine();
        try
        {
            cp::sync_wait(proto);
        }
        catch (std::exception& e)
        {
            std::cout << e.what() << std::endl;
        }

        auto e = time.setTimePoint("finish");
        auto milli = std::chrono::duration_cast<std::chrono::milliseconds>(e - s).count();

        if (role == Role::Sender)
            std::cout << tag << " n=" << totalOTs << " " << milli << " ms  " << std::endl;
#endif
    }

}

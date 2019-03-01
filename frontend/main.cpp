#include <iostream>

//using namespace std;
#include "tests_cryptoTools/UnitTests.h"
#include "libOTe_Tests/UnitTests.h"

#include <cryptoTools/Common/Defines.h>
using namespace osuCrypto;


#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/IOService.h>
#include <numeric>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Common/Log.h>
int miraclTestMain();


#include "libOTe/TwoChooseOne/KosOtExtReceiver.h"
#include "libOTe/TwoChooseOne/KosOtExtSender.h"
#include "libOTe/TwoChooseOne/KosDotExtReceiver.h"
#include "libOTe/TwoChooseOne/KosDotExtSender.h"
#include "libOTe/TwoChooseOne/IknpOtExtReceiver.h"
#include "libOTe/TwoChooseOne/IknpOtExtSender.h"
#include "libOTe/TwoChooseOne/IknpDotExtReceiver.h"
#include "libOTe/TwoChooseOne/IknpDotExtSender.h"

#include "libOTe/NChooseOne/Oos/OosNcoOtReceiver.h"
#include "libOTe/NChooseOne/Oos/OosNcoOtSender.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h"

#include "libOTe/NChooseK/AknOtReceiver.h"
#include "libOTe/NChooseK/AknOtSender.h"

#include <cryptoTools/Common/CLP.h>

enum class Role
{
    Sender,
    Receiver
};


template<typename NcoOtSender, typename  NcoOtReceiver>
void NChooseOne_example(Role role, int totalOTs, int numThreads, std::string ip, std::string tag)
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
    bool statSecParam = 40;
    bool inputBitCount = 76; // the kkrt protocol default to 128 but oos can only do 76.
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
            for (u64 i = 0; i < numOTs; ++i)
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

                // we now encode any OT message with index less that i + min.
                for (u64 j = 0; j < min; ++j, ++i)
                {
                    // in particular, the sender can retreive many OT messages
                    // at a single index, in this case we chose to retreive 3
                    // but that is arbitrary. 
                    auto choice0 = prng.get<block>();
                    auto choice1 = prng.get<block>();
                    auto choice2 = prng.get<block>();

                    // these we hold the actual OT messages. 
                    block
                        otMessage0,
                        otMessage1,
                        otMessage2;

                    // now retreive the messages
                    senders[k].encode(i, &choice0, &otMessage0);
                    senders[k].encode(i, &choice1, &otMessage1);
                    senders[k].encode(i, &choice2, &otMessage2);
                }
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
        std::cout << tag << " n=" << totalOTs << " " << milli << " ms" << std::endl;
}


template<typename OtExtSender, typename OtExtRecver>
void TwoChooseOne_example(Role role, int totalOTs, int numThreads, std::string ip, std::string tag)
{
    if (totalOTs == 0)
        totalOTs = 1 << 20;

    bool randomOT = true;

    auto numOTs = totalOTs / numThreads;

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

    // Now compute the base OTs, we need to set them on the first pair of extenders.
    // In real code you would only have a sender or reciever, not both. But we do 
    // here just showing the example. 
    if (role == Role::Receiver)
        receivers[0].genBaseOts(prng, chls[0]);
    else
        senders[0].genBaseOts(prng, chls[0]);

    // for the rest of the extenders, call split. This securely 
    // creates two sets of extenders that can be used in parallel.
    for (auto i = 1; i < numThreads; ++i)
    {
        senders[i] = senders[0].splitBase();
        receivers[i] = receivers[0].splitBase();
    }


    auto routine = [&](int i)
    {
        // get a random number generator seeded from the system
        PRNG prng(sysRandomSeed());

        if (role == Role::Receiver)
        {
            // construct the choices that we want.
            BitVector choice(numOTs);
            // in this case pick random messages.
            choice.randomize(prng);

            // construct a vector to stored the received messages. 
            std::vector<block> msgs(numOTs);

            if (randomOT)
            {
                // perform  numOTs random OTs, the results will be written to msgs.
                receivers[i].receive(choice, msgs, prng, chls[i]);
            }
            else
            {
                // perform  numOTs chosen message OTs, the results will be written to msgs.
                receivers[i].receiveChosen(choice, msgs, prng, chls[i]);
            }
        }
        else
        {
            // construct a vector to stored the random send messages. 
            std::vector<std::array<block, 2>> msgs(numOTs);

            // if delta OT is used, then the user can call the following 
            // to set the desired XOR difference between the zero messages
            // and the one messages.
            //
            //     senders[i].setDelta(some 128 bit delta);
            //

            if (randomOT)
            {
                // perform the OTs and write the random OTs to msgs.
                senders[i].send(msgs, prng, chls[i]);
            }
            else
            {
                // Populate msgs with something useful...
                prng.get(msgs.data(), msgs.size());

                // perform the OTs. The receiver will learn one
                // of the messages stored in msgs.
                senders[i].sendChosen(msgs, prng, chls[i]);
            }
        }
    };


    Timer timer;
    timer.reset();
    auto s = timer.setTimePoint("start");

    std::vector<std::thread> thrds(numThreads);
    for (int i = 0; i < numThreads; ++i)
        thrds[i] = std::thread(routine, i);

    for (int i = 0; i < numThreads; ++i)
        thrds[i].join();

    auto e = timer.setTimePoint("finish");
    auto milli = std::chrono::duration_cast<std::chrono::milliseconds>(e - s).count();

    if (role == Role::Sender)
        std::cout << tag << " n=" << totalOTs << " " << milli << " ms" << std::endl;
}



template<typename BaseOT>
void baseOT_example(Role role, int totalOTs, int numThreads, std::string ip, std::string tag)
{
    IOService ios;
    PRNG prng(sysRandomSeed());

    if (totalOTs == 0)
        totalOTs = 128;

    if (numThreads > 1)
        std::cout << "multi threading for the base OT example is not implemented.\n" << std::flush;

    if (role == Role::Receiver)
    {
        auto chl0 = Session(ios, ip, SessionMode::Server).addChannel();
        BaseOT recv;

        std::vector<block> msg(totalOTs);
        BitVector choice(totalOTs);
        choice.randomize(prng);


        Timer t;
        auto s = t.setTimePoint("base OT start");

        recv.receive(choice, msg, prng, chl0);

        auto e = t.setTimePoint("base OT end");
        auto milli = std::chrono::duration_cast<std::chrono::milliseconds>(e - s).count();

        std::cout << tag << " n=" << totalOTs << " " << milli << " ms" << std::endl;
    }
    else
    {

        auto chl1 = Session(ios, ip, SessionMode::Client).addChannel();

        BaseOT send;

        std::vector<std::array<block, 2>> msg(totalOTs);

        send.send(msg, prng, chl1);
    }
}



static const std::vector<std::string>
unitTestTag{ "u", "unitTest" },
kos{ "k", "kos" },
dkos{ "d", "dkos" },
kkrt{ "kk", "kkrt" },
iknp{ "i", "iknp" },
diknp{ "d", "diknp" },
oos{ "o", "oos" },
akn{ "a", "akn" },
np{ "np" },
simple{ "simplest" };

using ProtocolFunc = std::function<void(Role, int, int, std::string, std::string)>;

bool runIf(ProtocolFunc protocol, CLP& cmd, std::vector<std::string> tag)
{
    auto n = cmd.isSet("nn")
        ? (1 << cmd.get<int>("nn"))
        : cmd.getOr("n", 0);

    auto t = cmd.getOr("t", 1);
    auto ip = cmd.getOr<std::string>("ip", "localhost:1212");

    if (cmd.isSet(tag))
    {
        if (cmd.hasValue("r"))
        {
            auto role = cmd.get<int>("r") ? Role::Sender : Role::Receiver;
            protocol(role, n, t, ip, tag.back());
        }
        else
        {
            auto thrd = std::thread([&] {
                try { protocol(Role::Sender, n, t, ip, tag.back()); }
                catch (std::exception& e)
                {
                    lout << e.what() << std::endl;
                }
            });

            try { protocol(Role::Receiver, n, t, ip, tag.back()); }
            catch (std::exception& e)
            {
                lout << e.what() << std::endl;
            }
            thrd.join();
        }

        return true;
    }

    return false;
}

int main(int argc, char** argv)
{

    CLP cmd;
    cmd.parse(argc, argv);
    bool flagSet = false;

    if (cmd.isSet(unitTestTag))
    {
        flagSet = true;
        auto tests = tests_cryptoTools::Tests;
        tests += tests_libOTe::Tests;

        if (cmd.isSet("list"))
        {
            tests.list();
            return 0;
        }
        else
        {
            cmd.setDefault("loop", 1);
            auto loop = cmd.get<u64>("loop");

            TestCollection::Result result;
            if (cmd.hasValue(unitTestTag))
                result = tests.run(cmd.getMany<u64>(unitTestTag), loop);
            else
                result = tests.runAll(loop);

            if (result == TestCollection::Result::passed)
                return 0;
            else
                return 1;
        }
    }

#ifdef ENABLE_SIMPLESTOT
    flagSet |= runIf(baseOT_example<SimplestOT>, cmd, simple);
#endif
#ifdef NAOR_PINKAS
    flagSet |= runIf(baseOT_example<NaorPinkas>, cmd, np);
#endif
    flagSet |= runIf(TwoChooseOne_example<IknpOtExtSender, IknpOtExtReceiver>, cmd, iknp);
    flagSet |= runIf(TwoChooseOne_example<IknpDotExtSender, IknpDotExtReceiver>, cmd, diknp);
    flagSet |= runIf(TwoChooseOne_example<KosOtExtSender, KosOtExtReceiver>, cmd, kos);
    flagSet |= runIf(TwoChooseOne_example<KosDotExtSender, KosDotExtReceiver>, cmd, dkos);

    flagSet |= runIf(NChooseOne_example<KkrtNcoOtSender, KkrtNcoOtReceiver>, cmd, kkrt);
    flagSet |= runIf(NChooseOne_example<OosNcoOtSender, OosNcoOtReceiver>, cmd, oos);


    if (flagSet == false)
    {

        std::cout
            << "#######################################################\n"
            << "#                      - libOTe -                     #\n"
            << "#               A library for performing              #\n"
            << "#                  oblivious transfer.                #\n"
            << "#                     Peter Rindal                    #\n"
            << "#######################################################\n" << std::endl;

        bool spEnabled, npEnabled;
#ifdef ENABLE_SIMPLESTOT
        spEnabled = true;
#else 
        spEnabled = false;
#endif
#ifdef NAOR_PINKAS
        npEnabled = true;
#else 
        npEnabled = false;
#endif

        std::cout
            << "Protocols:\n"
            << Color::Green << "  -simplest" << Color::Default << "  : to run the SimplestOT active secure 1-out-of-2 base OT" << (spEnabled ? "" : "(disabled)") << "\n"
            << Color::Green << "  -np      " << Color::Default << "  : to run the NaorPinkas active secure 1-out-of-2 base OT" << (npEnabled ? "" : "(disabled)") << "\n"
            << Color::Green << "  -iknp    " << Color::Default << "  : to run the IKNP passive secure 1-out-of-2       OT\n"
            << Color::Green << "  -diknp   " << Color::Default << "  : to run the IKNP passive secure 1-out-of-2 Delta-OT\n"
            << Color::Green << "  -kos     " << Color::Default << "  : to run the KOS  active secure  1-out-of-2       OT\n"
            << Color::Green << "  -dkos    " << Color::Default << "  : to run the KOS  active secure  1-out-of-2 Delta-OT\n"
            << Color::Green << "  -oos     " << Color::Default << "  : to run the OOS  active secure  1-out-of-N OT for N=2^76\n"
            << Color::Green << "  -kkrt    " << Color::Default << "  : to run the KKRT passive secure 1-out-of-N OT for N=2^128\n\n"

            << "Other Options:\n"
            << Color::Green << "  -n         " << Color::Default << ": the number of OTs to perform\n"
            << Color::Green << "  -r 0/1     " << Color::Default << ": Do not play both OT roles. r 1 -> OT sender and network server. r 0 -> OT receiver and network cleint.\n"
            << Color::Green << "  -ip        " << Color::Default << ": the IP and port of the netowrk server, default = localhost:1212\n"
            << Color::Green << "  -t         " << Color::Default << ": the number of threads that should be used\n"
            << Color::Green << "  -u         " << Color::Default << ": to run the unit tests\n"
            << Color::Green << "  -u -list   " << Color::Default << ": to list the unit tests\n"
            << Color::Green << "  -u 1 2 15  " << Color::Default << ": to run the unit tests indexed by {1, 2, 15}.\n"
            << std::endl;
    }

    return 0;
}

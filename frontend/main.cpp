#include <iostream>

//using namespace std;
#include "tests_cryptoTools/UnitTests.h"
#include "libOTe_Tests/UnitTests.h"
#include <cryptoTools/Common/Defines.h>

using namespace osuCrypto;

#include <string.h>
#include <stdio.h>

#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/IOService.h>
#include <numeric>
#include <cryptoTools/Common/Timer.h>

#include <iomanip>
#include "util.h"

#include "ExampleBase.h"
#include "ExampleTwoChooseOne.h"
#include "ExampleNChooseOne.h"
#include "ExampleSilent.h"
#include "ExampleVole.h"


static const std::vector<std::string>
unitTestTag{ "u", "unitTest" },
kos{ "k", "kos" },
dkos{ "d", "dkos" },
kkrt{ "kk", "kkrt" },
iknp{ "i", "iknp" },
diknp{ "diknp" },
oos{ "o", "oos" },
Silent{ "s", "Silent" },
vole{ "vole" },
akn{ "a", "akn" },
np{ "np" },
simple{ "simplest" },
simpleasm{ "simplest-asm" };

#ifdef ENABLE_IKNP
void minimal()
{
    // Setup networking. See cryptoTools\frontend_cryptoTools\Tutorials\Network.cpp
    IOService ios;
    Channel senderChl = Session(ios, "localhost:1212", SessionMode::Server).addChannel();
    Channel recverChl = Session(ios, "localhost:1212", SessionMode::Client).addChannel();

    // The number of OTs.
    int n = 100;

    // The code to be run by the OT receiver.
    auto recverThread = std::thread([&]() {
        PRNG prng(sysRandomSeed());
        IknpOtExtReceiver recver;

        // Choose which messages should be received.
        BitVector choices(n);
        choices[0] = 1;
        //...

        // Receive the messages
        std::vector<block> messages(n);
        recver.receiveChosen(choices, messages, prng, recverChl);

        // messages[i] = sendMessages[i][choices[i]];
        });

    PRNG prng(sysRandomSeed());
    IknpOtExtSender sender;

    // Choose which messages should be sent.
    std::vector<std::array<block, 2>> sendMessages(n);
    sendMessages[0] = { toBlock(54), toBlock(33) };
    //...

    // Send the messages.
    sender.sendChosen(sendMessages, prng, senderChl);
    recverThread.join();
}
#endif



#include "cryptoTools/Crypto/RandomOracle.h"
int main(int argc, char** argv)
{

    CLP cmd;
    cmd.parse(argc, argv);
    bool flagSet = false;

    //if (cmd.isSet("triang"))
    //{
    //    ldpc(cmd);
    //    return 0;
    //}


    //if (cmd.isSet("encode"))
    //{
    //    encodeBench(cmd);
    //    return 0;
    //}

    //if (cmd.isSet("ldpc"))
    //{
    //    ldpcMain(cmd);
    //    return 0;
    //}

    if (cmd.isSet(unitTestTag))
    {
        flagSet = true;
        auto tests = tests_cryptoTools::Tests;
        tests += tests_libOTe::Tests;

        auto r = tests.runIf(cmd);
        return r == TestCollection::Result::passed ? 0 : -1;
    }

    if (cmd.isSet("latency"))
    {
        getLatency(cmd);
        flagSet = true;
    }

#ifdef ENABLE_SIMPLESTOT
    flagSet |= runIf(baseOT_example<SimplestOT>, cmd, simple);
#endif
#ifdef ENABLE_SIMPLESTOT_ASM
    flagSet |= runIf(baseOT_example<AsmSimplestOT>, cmd, simpleasm);
#endif
#ifdef ENABLE_NP
    flagSet |= runIf(baseOT_example<NaorPinkas>, cmd, np);
#endif
#ifdef ENABLE_IKNP
    flagSet |= runIf(TwoChooseOne_example<IknpOtExtSender, IknpOtExtReceiver>, cmd, iknp);
#endif
#ifdef ENABLE_KOS
    flagSet |= runIf(TwoChooseOne_example<KosOtExtSender, KosOtExtReceiver>, cmd, kos);
#endif
#ifdef ENABLE_DELTA_KOS
    flagSet |= runIf(TwoChooseOne_example<KosDotExtSender, KosDotExtReceiver>, cmd, dkos);
#endif
#ifdef ENABLE_KKRT
    flagSet |= runIf(NChooseOne_example<KkrtNcoOtSender, KkrtNcoOtReceiver>, cmd, kkrt);
#endif
#ifdef ENABLE_OOS
    flagSet |= runIf(NChooseOne_example<OosNcoOtSender, OosNcoOtReceiver>, cmd, oos);
#endif

    flagSet |= runIf(Silent_example, cmd, Silent);
    flagSet |= runIf(Vole_example, cmd, vole);



    if (flagSet == false)
    {

        std::cout
            << "#######################################################\n"
            << "#                      - libOTe -                     #\n"
            << "#               A library for performing              #\n"
            << "#                  oblivious transfer.                #\n"
            << "#                     Peter Rindal                    #\n"
            << "#######################################################\n" << std::endl;


        std::cout
            << "Protocols:\n"
            << Color::Green << "  -simplest-asm" << Color::Default << "  : to run the ASM-SimplestOT active secure  1-out-of-2  base OT      " << Color::Red << (spaEnabled ? "" : "(disabled)") << "\n" << Color::Default
            << Color::Green << "  -simplest    " << Color::Default << "  : to run the SimplestOT     active secure  1-out-of-2  base OT      " << Color::Red << (spEnabled ? "" : "(disabled)") << "\n" << Color::Default
            << Color::Green << "  -np          " << Color::Default << "  : to run the NaorPinkas     active secure  1-out-of-2  base OT      " << Color::Red << (npEnabled ? "" : "(disabled)") << "\n" << Color::Default
            << Color::Green << "  -iknp        " << Color::Default << "  : to run the IKNP           passive secure 1-out-of-2       OT      " << Color::Red << (iknpEnabled ? "" : "(disabled)") << "\n" << Color::Default
            << Color::Green << "  -diknp       " << Color::Default << "  : to run the IKNP           passive secure 1-out-of-2 Delta-OT      " << Color::Red << (diknpEnabled ? "" : "(disabled)") << "\n" << Color::Default
            << Color::Green << "  -Silent      " << Color::Default << "  : to run the Silent         passive secure 1-out-of-2       OT      " << Color::Red << (silentEnabled ? "" : "(disabled)") << "\n" << Color::Default
            << Color::Green << "  -kos         " << Color::Default << "  : to run the KOS            active secure  1-out-of-2       OT      " << Color::Red << (kosEnabled ? "" : "(disabled)") << "\n" << Color::Default
            << Color::Green << "  -dkos        " << Color::Default << "  : to run the KOS            active secure  1-out-of-2 Delta-OT      " << Color::Red << (dkosEnabled ? "" : "(disabled)") << "\n" << Color::Default
            << Color::Green << "  -oos         " << Color::Default << "  : to run the OOS            active secure  1-out-of-N OT for N=2^76 " << Color::Red << (oosEnabled ? "" : "(disabled)") << "\n" << Color::Default
            << Color::Green << "  -kkrt        " << Color::Default << "  : to run the KKRT           passive secure 1-out-of-N OT for N=2^128" << Color::Red << (kkrtEnabled ? "" : "(disabled)") << "\n\n" << Color::Default

            << "Other Options:\n"
            << Color::Green << "  -n           " << Color::Default << ": the number of OTs to perform\n"
            << Color::Green << "  -r 0/1       " << Color::Default << ": Do not play both OT roles. r 1 -> OT sender and network server. r 0 -> OT receiver and network client.\n"
            << Color::Green << "  -ip          " << Color::Default << ": the IP and port of the netowrk server, default = localhost:1212\n"
            << Color::Green << "  -t           " << Color::Default << ": the number of threads that should be used\n"
            << Color::Green << "  -u           " << Color::Default << ": to run the unit tests\n"
            << Color::Green << "  -u -list     " << Color::Default << ": to list the unit tests\n"
            << Color::Green << "  -u 1 2 15    " << Color::Default << ": to run the unit tests indexed by {1, 2, 15}.\n"
            << std::endl;
    }

    return 0;
}

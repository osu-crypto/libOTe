#include <iostream>
#include "tests_cryptoTools/UnitTests.h"
#include "libOTe_Tests/UnitTests.h"
#include <cryptoTools/Common/Defines.h>
#include "cryptoTools/Crypto/RandomOracle.h"


#include <string.h>
#include <stdio.h>

#include <numeric>
#include <cryptoTools/Common/Timer.h>

#include <iomanip>
#include "util.h"
#include "benchmark.h"

#include "ExampleBase.h"
#include "benchmark.h"
#include "ExampleTwoChooseOne.h"
#include "ExampleNChooseOne.h"
#include "ExampleSilent.h"
#include "ExampleVole.h"
#include "ExampleMessagePassing.h"
#include "libOTe/Tools/LDPC/Util.h"
#include "cryptoTools/Crypto/RandomOracle.h"
#include "libOTe/Tools/EACode/EAChecker.h"
#include "libOTe/Tools/ExConvCode/ExConvChecker.h"

#include "libOTe/TwoChooseOne/Iknp/IknpOtExtSender.h"
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtReceiver.h"

using namespace osuCrypto;
#ifdef ENABLE_IKNP
void minimal()
{
	// Setup networking. See cryptoTools\frontend_cryptoTools\Tutorials\Network.cpp
	auto sockets = coproto::LocalAsyncSocket::makePair();

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
		auto proto = recver.receiveChosen(choices, messages, prng, sockets[0]);

		coproto::sync_wait(proto);

		// messages[i] = sendMessages[i][choices[i]];
		});

	PRNG prng(sysRandomSeed());
	IknpOtExtSender sender;

	// Choose which messages should be sent.
	std::vector<std::array<block, 2>> sendMessages(n);
	sendMessages[0] = { toBlock(54), toBlock(33) };
	//...

	// Send the messages.
	auto proto = sender.sendChosen(sendMessages, prng, sockets[1]);

	auto r = coproto::sync_wait(macoro::wrap(proto));

	recverThread.join();

	r.value();
}
#endif


int main(int argc, char** argv)
{
	CLP cmd;
	cmd.parse(argc, argv);

	bool flagSet = false;

	if (cmd.isSet("EAChecker"))
	{
		EAChecker(cmd);
		return 0;
	}
	if (cmd.isSet("ExConvChecker"))
	{
		ExConvChecker(cmd);
		return 0;
	}
	

	// various benchmarks
	if (cmd.isSet("bench"))
	{
		if (cmd.isSet("QC"))
			QCCodeBench(cmd);
		else if (cmd.isSet("silent"))
			SilentOtBench(cmd);
		else if (cmd.isSet("pprf"))
			PprfBench(cmd);
		else if (cmd.isSet("vole2"))
			VoleBench2(cmd);
		else if (cmd.isSet("ea"))
			EACodeBench(cmd);
		else if (cmd.isSet("ec"))
			ExConvCodeBench(cmd);
		else if (cmd.isSet("ecold"))
			ExConvCodeOldBench(cmd);
		else if (cmd.isSet("tungsten"))
			TungstenCodeBench(cmd);

		return 0;
	}

	// unit tests.
	if (cmd.isSet(unitTestTag))
	{
		flagSet = true;
		auto tests = tests_cryptoTools::Tests;
		tests += tests_libOTe::Tests;

		auto r = tests.runIf(cmd);
		return r == TestCollection::Result::passed ? 0 : -1;
	}

#ifdef ENABE_BOOST
	// compute the network latency.
	if (cmd.isSet("latency"))
	{
		getLatency(cmd);
		flagSet = true;
	}
#endif


	// run various examples.
	flagSet |= baseOT_examples(cmd);
	flagSet |= TwoChooseOne_Examples(cmd);
	flagSet |= NChooseOne_Examples(cmd);
	flagSet |= Silent_Examples(cmd);
	flagSet |= Vole_Examples(cmd);

	if (cmd.isSet("messagePassing"))
	{
		messagePassingExample(cmd);
		flagSet = 1;
	}


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
            << Color::Green << "  -simplest-asm   " << Color::Default << "  : to run the ASM-SimplestOT  active secure       1-out-of-2  base OT      " << Color::Red << (spaEnabled ? "" : "(disabled)")             << "\n"   << Color::Default
            << Color::Green << "  -simplest       " << Color::Default << "  : to run the SimplestOT      active secure       1-out-of-2  base OT      " << Color::Red << (spEnabled ? "" : "(disabled)")              << "\n"   << Color::Default
            << Color::Green << "  -moellerpopf    " << Color::Default << "  : to run the McRosRoyTwist   active secure       1-out-of-2  base OT      " << Color::Red << (popfotMoellerEnabled ? "" : "(disabled)")   << "\n"   << Color::Default
            << Color::Green << "  -ristrettopopf  " << Color::Default << "  : to run the McRosRoy        active secure       1-out-of-2  base OT      " << Color::Red << (popfotRistrettoEnabled ? "" : "(disabled)") << "\n"   << Color::Default
            << Color::Green << "  -mr             " << Color::Default << "  : to run the MasnyRindal     active secure       1-out-of-2  base OT      " << Color::Red << (mrEnabled ? "" : "(disabled)")              << "\n"   << Color::Default
            << Color::Green << "  -np             " << Color::Default << "  : to run the NaorPinkas      active secure       1-out-of-2  base OT      " << Color::Red << (npEnabled ? "" : "(disabled)")              << "\n"   << Color::Default
            << Color::Green << "  -iknp           " << Color::Default << "  : to run the IKNP            passive secure      1-out-of-2       OT      " << Color::Red << (iknpEnabled ? "" : "(disabled)")            << "\n"   << Color::Default
            << Color::Green << "  -diknp          " << Color::Default << "  : to run the IKNP            passive secure      1-out-of-2 Delta-OT      " << Color::Red << (diknpEnabled ? "" : "(disabled)")           << "\n"   << Color::Default
            << Color::Green << "  -Silent         " << Color::Default << "  : to run the Silent          passive secure      1-out-of-2       OT      " << Color::Red << (silentEnabled ? "" : "(disabled)")          << "\n"   << Color::Default
            << Color::Green << "  -kos            " << Color::Default << "  : to run the KOS             active secure       1-out-of-2       OT      " << Color::Red << (kosEnabled ? "" : "(disabled)")             << "\n"   << Color::Default
            << Color::Green << "  -dkos           " << Color::Default << "  : to run the KOS             active secure       1-out-of-2 Delta-OT      " << Color::Red << (dkosEnabled ? "" : "(disabled)")            << "\n"   << Color::Default
            << Color::Green << "  -ssdelta        " << Color::Default << "  : to run the SoftSpoken      passive secure      1-out-of-2 Delta-OT      " << Color::Red << (softSpokenEnabled ? "" : "(disabled)")            << "\n"   << Color::Default
            << Color::Green << "  -sshonest       " << Color::Default << "  : to run the SoftSpoken      passive secure      1-out-of-2       OT      " << Color::Red << (softSpokenEnabled ? "" : "(disabled)")            << "\n"   << Color::Default
            << Color::Green << "  -smleakydelta   " << Color::Default << "  : to run the SoftSpoken      active secure leaky 1-out-of-2 Delta-OT      " << Color::Red << (softSpokenEnabled ? "" : "(disabled)")            << "\n"   << Color::Default
            << Color::Green << "  -smalicious     " << Color::Default << "  : to run the SoftSpoken      active secure       1-out-of-2       OT      " << Color::Red << (softSpokenEnabled ? "" : "(disabled)")            << "\n"   << Color::Default
            << Color::Green << "  -oos            " << Color::Default << "  : to run the OOS             active secure       1-out-of-N OT for N=2^76 " << Color::Red << (oosEnabled ? "" : "(disabled)")             << "\n"   << Color::Default
			<< Color::Green << "  -kkrt           " << Color::Default << "  : to run the KKRT            passive secure      1-out-of-N OT for N=2^128" << Color::Red << (kkrtEnabled ? "" : "(disabled)") << "\n" << Color::Default
			<< Color::Green << "  -messagePassing " << Color::Default << "  : to run the message passing example                                      " << Color::Red << (silentEnabled ? "" : "(disabled)")            << "\n\n" << Color::Default

			<< "POPF Options:\n"
			<< Color::Green << "  -eke            " << Color::Default << "  : to run the EKE POPF (Moeller only)                                  " << "\n" << Color::Default
			<< Color::Green << "  -mrPopf         " << Color::Default << "  : to run the MasnyRindal POPF (Moeller only)                          " << "\n" << Color::Default
			<< Color::Green << "  -feistel        " << Color::Default << "  : to run the Feistel POPF                                             " << "\n" << Color::Default
			<< Color::Green << "  -feistelMul     " << Color::Default << "  : to run the Feistel With Multiplication POPF                         " << "\n\n" << Color::Default
												  
            << "SoftSpokenOT options:\n"		  
            << Color::Green << "  -f              " << Color::Default << "  : the number of bits in the finite field (aka the depth of the PPRF). " << "\n\n"<< Color::Default
												  
            << "Other Options:\n"				  
            << Color::Green << "  -n              " << Color::Default << ": the number of OTs to perform\n"
            << Color::Green << "  -r 0/1          " << Color::Default << ": Do not play both OT roles. r 1 -> OT sender and network server. r 0 -> OT receiver and network client.\n"
            << Color::Green << "  -ip             " << Color::Default << ": the IP and port of the netowrk server, default = localhost:1212\n"
            << Color::Green << "  -t              " << Color::Default << ": the number of threads that should be used\n"
            << Color::Green << "  -u              " << Color::Default << ": to run the unit tests\n"
            << Color::Green << "  -u -list        " << Color::Default << ": to list the unit tests\n"
            << Color::Green << "  -u 1 2 15       " << Color::Default << ": to run the unit tests indexed by {1, 2, 15}.\n"
            << std::endl;
    }

	return 0;
}

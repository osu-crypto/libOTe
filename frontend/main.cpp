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
#include <cryptoTools/Common/Matrix.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Log.h>
int miraclTestMain();
#include <cryptoTools/Crypto/PRNG.h>

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

#include "libOTe/TwoChooseOne/SilentOtExtReceiver.h"
#include "libOTe/TwoChooseOne/SilentOtExtSender.h"

#include "libOTe/NChooseK/AknOtReceiver.h"
#include "libOTe/NChooseK/AknOtSender.h"

#include <cryptoTools/Common/CLP.h>
#include "util.h"
#include <iomanip>
#include <boost/preprocessor/variadic/size.hpp>

#include "libOTe/Base/SimplestOT.h"
#include "libOTe/Base/MasnyRindal.h"
#include "libOTe/Base/MasnyRindalKyber.h"
#include "libOTe/Base/naor-pinkas.h"



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
void TwoChooseOne_example(Role role, int totalOTs, int numThreads, std::string ip, std::string tag, CLP & cmd)
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

	Timer timer, sendTimer, recvTimer;
	timer.reset();
	auto s = timer.setTimePoint("start");
	sendTimer.setTimePoint("start");
	recvTimer.setTimePoint("start");


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
		senders[0].setBaseOts(baseMsg, bv,chls[0]);
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

	senders[0].setTimer(sendTimer);
	receivers[0].setTimer(recvTimer);

	std::vector<std::thread> thrds(numThreads);
	for (int i = 0; i < numThreads; ++i)
		thrds[i] = std::thread(routine, i);

	for (int i = 0; i < numThreads; ++i)
		thrds[i].join();

	auto e = timer.setTimePoint("finish");
	auto milli = std::chrono::duration_cast<std::chrono::milliseconds>(e - s).count();

	auto com = (chls[0].getTotalDataRecv() + chls[0].getTotalDataSent()) * numThreads;

	if (role == Role::Sender)
		lout << tag << " n=" << Color::Green << totalOTs << " " << milli << " ms  " << com << " bytes" << std::endl << Color::Default;


	if (cmd.isSet("v"))
	{
		if (role == Role::Sender)
			lout << " **** sender ****\n" << sendTimer << std::endl;

		if (role == Role::Receiver)
			lout << " **** receiver ****\n" << recvTimer << std::endl;
	}
}


//template<typename OtExtSender, typename OtExtRecver>
void TwoChooseOneG_example(Role role, int numOTs, int numThreads, std::string ip, std::string tag, CLP & cmd)
{
#ifdef ENABLE_SILENTOT

	if (numOTs == 0)
		numOTs = 1 << 20;
	using OtExtSender = SilentOtExtSender;
	using OtExtRecver = SilentOtExtReceiver;

	// get up the networking
	auto rr = role == Role::Sender ? SessionMode::Server : SessionMode::Client;
	IOService ios;
	Session  ep0(ios, ip, rr);
	PRNG prng(sysRandomSeed());

	// for each thread we need to construct a channel (socket) for it to communicate on.
	std::vector<Channel> chls(numThreads);
	for (int i = 0; i < numThreads; ++i)
		chls[i] = ep0.addChannel();

	//bool mal = cmd.isSet("mal");
	OtExtSender sender;
	OtExtRecver receiver;


	auto routine = [&](int s, int sec, SilentBaseType type)
	{
		// get a random number generator seeded from the system
		PRNG prng(sysRandomSeed());

		sync(chls[0], role);

		if (role == Role::Receiver)
		{
			// construct the choices that we want.
			BitVector choice(numOTs);
			// in this case pick random messages.
			choice.randomize(prng);

			// construct a vector to stored the received messages. 
			std::vector<block> msgs(numOTs);

			receiver.genBase(numOTs, chls[0], prng, s, sec, type, chls.size());
			// perform  numOTs random OTs, the results will be written to msgs.
			receiver.silentReceive(choice, msgs, prng, chls);
		}
		else
		{
			std::vector<std::array<block, 2>> msgs(numOTs);

			sender.genBase(numOTs, chls[0], prng, s, sec, type, chls.size());
			// construct a vector to stored the random send messages. 

			// if delta OT is used, then the user can call the following 
			// to set the desired XOR difference between the zero messages
			// and the one messages.
			//
			//     senders[i].setDelta(some 128 bit delta);
			//

			// perform the OTs and write the random OTs to msgs.
			sender.silentSend(msgs, prng, chls);
		}
	};

	cmd.setDefault("s", "4");
	cmd.setDefault("sec", "80");
	std::vector<int> ss = cmd.getMany<int>("s");
	std::vector<int> secs = cmd.getMany<int>("sec");
	std::vector< SilentBaseType> types;

	if (cmd.isSet("base"))
		types.push_back(SilentBaseType::Base);
	if (cmd.isSet("baseExtend"))
		types.push_back(SilentBaseType::BaseExtend);
	//if (cmd.isSet("extend"))
	//	types.push_back(SilentBaseType::Extend);
	//if (types.size() == 0 || cmd.isSet("none"))
	//	types.push_back(SilentBaseType::None);


	for (auto s : ss)
		for (auto sec : secs)
			for (auto type : types)
			{

				chls[0].resetStats();

				Timer timer, sendTimer, recvTimer;
				timer.reset();
				auto b = timer.setTimePoint("start");
				sendTimer.setTimePoint("start");
				recvTimer.setTimePoint("start");

				sender.setTimer(sendTimer);
				receiver.setTimer(recvTimer);

				routine(s, sec, type);


				auto e = timer.setTimePoint("finish");
				auto milli = std::chrono::duration_cast<std::chrono::milliseconds>(e - b).count();

				u64 com = 0;
				for(auto &c : chls)
					com += (c.getTotalDataRecv() + c.getTotalDataSent());

				std::string typeStr = "n ";
				switch (type)
				{
				case SilentBaseType::Base:
					typeStr = "b ";
					break;
				//case SilentBaseType::Extend:
				//	typeStr = "e ";
				//	break;
				case SilentBaseType::BaseExtend:
					typeStr = "be";
					break;
				default:
					break;
				}


				if (role == Role::Sender)
					lout << tag <<
					" n:" << Color::Green << std::setw(6) << std::setfill(' ')<<numOTs << Color::Default <<
					" type: " << Color::Green << typeStr << Color::Default <<
					" sec: " << Color::Green << std::setw(3) << std::setfill(' ') << sec << Color::Default <<
					" s: " << Color::Green << s << Color::Default <<
					"   ||   " << Color::Green << 
					std::setw(6) << std::setfill(' ') << milli << " ms   " <<
					std::setw(6) << std::setfill(' ') << com << " bytes" << std::endl << Color::Default;

				if (cmd.isSet("v"))
				{
					if (role == Role::Sender)
						lout << " **** sender ****\n" << sendTimer << std::endl;

					if (role == Role::Receiver)
						lout << " **** receiver ****\n" << recvTimer << std::endl;
				}
			}

#endif
}





template<typename BaseOT>
void baseOT_example(Role role, int totalOTs, int numThreads, std::string ip, std::string tag, CLP&)
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
diknp{ "diknp" },
oos{ "o", "oos" },
Silent{ "s", "Silent" },
akn{ "a", "akn" },
np{ "np" },
simple{ "simplest" },
simpleasm{ "simplest-asm" };

using ProtocolFunc = std::function<void(Role, int, int, std::string, std::string, CLP&)>;

bool runIf(ProtocolFunc protocol, CLP & cmd, std::vector<std::string> tag)
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
			protocol(role, n, t, ip, tag.back(), cmd);
		}
		else
		{
			auto thrd = std::thread([&] {
				try { protocol(Role::Sender, n, t, ip, tag.back(), cmd); }
				catch (std::exception & e)
				{
					lout << e.what() << std::endl;
				}
				});

			try { protocol(Role::Receiver, n, t, ip, tag.back(), cmd); }
			catch (std::exception & e)
			{
				lout << e.what() << std::endl;
			}
			thrd.join();
		}

		return true;
	}

	return false;
}
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


//
// Created by Erik Buchholz on 27.02.20.
//
#include <string.h>
#include <stdio.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <libOTe/NChooseOne/Oos/OosNcoOtReceiver.h>
#include <libOTe/NChooseOne/Oos/OosNcoOtSender.h>

#define LINE "------------------------------------------------------"
#define TOTALOTS 10
#define SETSIZE 2<<10

#ifdef ENABLE_SIMPLESTOT
const bool spEnabled = true;
#else 
const bool spEnabled = false;
#endif
#ifdef ENABLE_SIMPLESTOT_ASM
const bool spaEnabled = true;
#else 
const bool spaEnabled = false;
#endif
#ifdef ENABLE_IKNP
const bool iknpEnabled = true;
#else 
const bool iknpEnabled = false;
#endif
#ifdef ENABLE_DELTA_IKNP
const bool diknpEnabled = true;
#else 
const bool diknpEnabled = false;
#endif
#ifdef ENABLE_KOS
const bool kosEnabled = true;
#else 
const bool kosEnabled = false;
#endif
#ifdef ENABLE_DELTA_KOS
const bool dkosEnabled = true;
#else 
const bool dkosEnabled = false;
#endif
#ifdef ENABLE_NP
const bool npEnabled = true;
#else 
const bool npEnabled = false;
#endif

#ifdef ENABLE_OOS
const bool oosEnabled = true;
#else 
const bool oosEnabled = false;
#endif
#ifdef ENABLE_KKRT
const bool kkrtEnabled = true;
#else 
const bool kkrtEnabled = false;
#endif

#ifdef ENABLE_SILENTOT
const bool silentEnabled = true;
#else 
const bool silentEnabled = false;
#endif

#include "cryptoTools/Crypto/RandomOracle.h"
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

		tests.runIf(cmd);
		return 0;
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
#ifdef ENABLE_DELTA_IKNP
	flagSet |= runIf(TwoChooseOne_example<IknpDotExtSender, IknpDotExtReceiver>, cmd, diknp);
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

	flagSet |= runIf(TwoChooseOneG_example, cmd, Silent);



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
			<< Color::Green << "  -simplest-asm" << Color::Default << "  : to run the ASM-SimplestOT active secure  1-out-of-2  base OT      "  <<Color::Red<< (spaEnabled ? "" : "(disabled)") << "\n"	  << Color::Default
			<< Color::Green << "  -simplest    " << Color::Default << "  : to run the SimplestOT     active secure  1-out-of-2  base OT      "  <<Color::Red<< (spEnabled ? "" : "(disabled)") << "\n"	  << Color::Default
			<< Color::Green << "  -np          " << Color::Default << "  : to run the NaorPinkas     active secure  1-out-of-2  base OT      "  <<Color::Red<< (npEnabled ? "" : "(disabled)") << "\n"	  << Color::Default
			<< Color::Green << "  -iknp        " << Color::Default << "  : to run the IKNP           passive secure 1-out-of-2       OT      "  <<Color::Red<< (iknpEnabled ? "" : "(disabled)") << "\n"	  << Color::Default
			<< Color::Green << "  -diknp       " << Color::Default << "  : to run the IKNP           passive secure 1-out-of-2 Delta-OT      "  <<Color::Red<< (diknpEnabled ? "" : "(disabled)") << "\n"  << Color::Default
			<< Color::Green << "  -Silent      " << Color::Default << "  : to run the Silent         passive secure 1-out-of-2       OT      "  <<Color::Red<< (silentEnabled ? "" : "(disabled)") <<"\n"  << Color::Default
			<< Color::Green << "  -kos         " << Color::Default << "  : to run the KOS            active secure  1-out-of-2       OT      "  <<Color::Red<< (kosEnabled ? "" : "(disabled)") << "\n"	  << Color::Default
			<< Color::Green << "  -dkos        " << Color::Default << "  : to run the KOS            active secure  1-out-of-2 Delta-OT      "  <<Color::Red<< (dkosEnabled ? "" : "(disabled)") << "\n"	  << Color::Default
			<< Color::Green << "  -oos         " << Color::Default << "  : to run the OOS            active secure  1-out-of-N OT for N=2^76 "  <<Color::Red<< (oosEnabled ? "" : "(disabled)") << "\n"	  << Color::Default
			<< Color::Green << "  -kkrt        " << Color::Default << "  : to run the KKRT           passive secure 1-out-of-N OT for N=2^128" <<Color::Red<< (kkrtEnabled ? "" : "(disabled)") << "\n\n" << Color::Default

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

#pragma once

#include "libOTe/Base/BaseOT.h"
#include "libOTe/TwoChooseOne/Kos/KosOtExtReceiver.h"
#include "libOTe/TwoChooseOne/Kos/KosOtExtSender.h"
#include "libOTe/TwoChooseOne/KosDot/KosDotExtReceiver.h"
#include "libOTe/TwoChooseOne/KosDot/KosDotExtSender.h"
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtReceiver.h"
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtSender.h"


#include "libOTe/TwoChooseOne/Silent/SilentOtExtReceiver.h"
#include "libOTe/TwoChooseOne/Silent/SilentOtExtSender.h"

//#include "libOTe/TwoChooseOne/SoftSpokenOT/SoftSpokenMalLeakyDotExt.h"
//#include "libOTe/TwoChooseOne/SoftSpokenOT/SoftSpokenMalOtExt.h"
//#include "libOTe/TwoChooseOne/SoftSpokenOT/SoftSpokenShOtExt.h"
//#include "libOTe/TwoChooseOne/SoftSpokenOT/SoftSpokenShDotExt.h"

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

#ifdef ENABLE_SOFTSPOKEN_OT
    // soft spoken takes an extra parameter as input what determines
    // the computation/communication trade-off.
    template<typename T>
    using is_SoftSpoken = typename std::conditional<
        //std::is_same<T, SoftSpokenShOtSender>::value ||
        //std::is_same<T, SoftSpokenShOtReceiver>::value ||
        //std::is_same<T, SoftSpokenShOtSender>::value ||
        //std::is_same<T, SoftSpokenShOtReceiver>::value ||
        //std::is_same<T, SoftSpokenMalOtSender>::value ||
        //std::is_same<T, SoftSpokenMalOtReceiver>::value ||
        //std::is_same<T, SoftSpokenMalLeakyDotSender>::value ||
        //std::is_same<T, SoftSpokenMalOtReceiver>::value
		false
		,
        std::true_type, std::false_type>::type;
#else
    template<typename T>
    using is_SoftSpoken = std::false_type;
#endif

    template<typename T>
    typename std::enable_if<is_SoftSpoken<T>::value,T>::type
        construct(CLP& cmd)
    {
        return T( cmd.getOr("f", 2) );
    }

    template<typename T>
    typename std::enable_if<!is_SoftSpoken<T>::value, T>::type
         construct(CLP& cmd)
    {
        return T{};
    }

    template<typename OtExtSender, typename OtExtRecver>
    void TwoChooseOne_example(Role role, int totalOTs, int numThreads, std::string ip, std::string tag, CLP& cmd)
    {

#ifdef COPROTO_ENABLE_BOOST
        if (totalOTs == 0)
            totalOTs = 1 << 20;

		bool randomOT = true;

		// get up the networking
		auto chl = cp::asioConnect(ip, role == Role::Sender);

		PRNG prng(sysRandomSeed());


		OtExtSender  sender;
		OtExtRecver  receiver;


#ifdef LIBOTE_HAS_BASE_OT
		// Now compute the base OTs, we need to set them on the first pair of extenders.
		// In real code you would only have a sender or reciever, not both. But we do
		// here just showing the example.
		if (role == Role::Receiver)
		{
			DefaultBaseOT base;
			std::array<std::array<block, 2>, 128> baseMsg;

			// perform the base To, call sync_wait to block until they have completed.
			cp::sync_wait(base.send(baseMsg, prng, chl));
			cp::sync_wait(receiver.setBaseOts(baseMsg, prng, chl));
		}
		else
		{

			DefaultBaseOT base;
			BitVector bv(128);
			std::array<block, 128> baseMsg;
			bv.randomize(prng);

			// perform the base To, call sync_wait to block until they have completed.
			cp::sync_wait(base.receive(bv, baseMsg, prng, chl));
			cp::sync_wait(sender.setBaseOts(baseMsg, bv, chl));
		}

#else
		if (!cmd.isSet("fakeBase"))
			std::cout << "warning, base ots are not enabled. Fake base OTs will be used. " << std::endl;
		PRNG commonPRNG(oc::ZeroBlock);
		std::array<std::array<block, 2>, 128> sendMsgs;
		commonPRNG.get(sendMsgs.data(), sendMsgs.size());
		if (role == Role::Receiver)
		{
			cp::sync_wait(receiver.setBaseOts(sendMsgs, prng, chl));
		}
		else
		{
			BitVector bv(128);
			bv.randomize(commonPRNG);
			std::array<block, 128> recvMsgs;
			for (u64 i = 0; i < 128; ++i)
				recvMsgs[i] = sendMsgs[i][bv[i]];
			cp::sync_wait(sender.setBaseOts(recvMsgs, bv, chl));
		}
#endif

		if (cmd.isSet("noHash"))
			noHash(sender, receiver);

		Timer timer, sendTimer, recvTimer;
		sendTimer.setTimePoint("start");
		recvTimer.setTimePoint("start");
		auto s = timer.setTimePoint("start");

		if (numThreads == 1)
		{
			if (role == Role::Receiver)
			{
				// construct the choices that we want.
				BitVector choice(totalOTs);
				// in this case pick random messages.
				choice.randomize(prng);

				// construct a vector to stored the received messages.
				std::vector<block> rMsgs(totalOTs);

				if (randomOT)
				{
					// perform  totalOTs random OTs, the results will be written to msgs.
					cp::sync_wait(receiver.receive(choice, rMsgs, prng, chl));
				}
				else
				{
					// perform  totalOTs chosen message OTs, the results will be written to msgs.
					cp::sync_wait(receiver.receiveChosen(choice, rMsgs, prng, chl));
				}
			}
			else
			{
				// construct a vector to stored the random send messages.
				std::vector<std::array<block, 2>> sMsgs(totalOTs);


				// if delta OT is used, then the user can call the following
				// to set the desired XOR difference between the zero messages
				// and the one messages.
				//
				//     senders[i].setDelta(some 128 bit delta);
				//

				if (randomOT)
				{
					// perform the OTs and write the random OTs to msgs.
					cp::sync_wait(sender.send(sMsgs, prng, chl));
				}
				else
				{
					// Populate msgs with something useful...
					prng.get(sMsgs.data(), sMsgs.size());

					// perform the OTs. The receiver will learn one
					// of the messages stored in msgs.
					cp::sync_wait(sender.sendChosen(sMsgs, prng, chl));
				}
			}

		}
		else
		{	
			
			// for multi threading, we only show example for random OTs.
			// We first need to construct the inputs
			// that each thread will use. Note that the actual protocol 
			// is not thread safe so everything needs to be independent.
			std::vector<macoro::eager_task<>> tasks(numThreads);
			std::vector<PRNG> threadPrngs(numThreads);
			std::vector<cp::Socket> threadChls(numThreads);

			macoro::thread_pool::work work;
			macoro::thread_pool threadPool(numThreads, work);

			if (role == Role::Receiver)
			{
				std::vector<OtExtRecver> receivers(numThreads);
				std::vector<BitVector> threadChoices(numThreads);
				std::vector<std::vector<block>> threadMsgs(numThreads);

				for (u64 threadIndex = 0; threadIndex < (u64)numThreads; ++threadIndex)
				{
					u64 beginIndex = oc::roundUpTo(totalOTs * threadIndex / numThreads, 128);
					u64 endIndex = oc::roundUpTo((totalOTs + 1) * threadIndex / numThreads, 128);

					threadChoices[threadIndex].resize(endIndex - beginIndex);
					threadChoices[threadIndex].randomize(prng);

					threadMsgs[threadIndex].resize(endIndex - beginIndex);

					// create a copy of the receiver so that each can run 
					// independently. A single receiver is not thread safe.
					receivers[threadIndex] = receiver.splitBase();

					// create a PRNG for this thread.
					threadPrngs[threadIndex].SetSeed(prng.get<block>());

					// create a socket for this thread. This is done by calling fork().
					threadChls[threadIndex] = chl.fork();

					// start the receive protocol on the thread pool
					tasks[threadIndex] =
						receivers[threadIndex].receive(
							threadChoices[threadIndex],
							threadMsgs[threadIndex],
							threadPrngs[threadIndex],
							threadChls[threadIndex])
						| macoro::start_on(threadPool);
				}

				// block this thread until the receive operations
				// have completed. 
				for (u64 threadIndex = 0; threadIndex < (u64)numThreads; ++threadIndex)
					cp::sync_wait(tasks[threadIndex]);
			}
			else
			{
				std::vector<OtExtSender> senders(numThreads);
				std::vector<std::vector<std::array<block, 2>>> threadMsgs(numThreads);

				for (u64 threadIndex = 0; threadIndex < (u64)numThreads; ++threadIndex)
				{
					u64 beginIndex = oc::roundUpTo(totalOTs * threadIndex / numThreads, 128);
					u64 endIndex = oc::roundUpTo((totalOTs + 1) * threadIndex / numThreads, 128);

					threadMsgs[threadIndex].resize(endIndex - beginIndex);

					// create a copy of the receiver so that each can run 
					// independently. A single receiver is not thread safe.
					senders[threadIndex] = sender.splitBase();

					// create a PRNG for this thread.
					threadPrngs[threadIndex].SetSeed(prng.get<block>());

					// create a socket for this thread. This is done by calling fork().
					threadChls[threadIndex] = chl.fork();

					// start the send protocol on the thread pool
					tasks[threadIndex] =
						senders[threadIndex].send(
							threadMsgs[threadIndex],
							threadPrngs[threadIndex],
							threadChls[threadIndex])
						| macoro::start_on(threadPool);
				}

				// block this thread until the receive operations
				// have completed. 
				for (u64 threadIndex = 0; threadIndex < (u64)numThreads; ++threadIndex)
					cp::sync_wait(tasks[threadIndex]);
			}

			work.reset();
		}

		auto e = timer.setTimePoint("finish");
		auto milli = std::chrono::duration_cast<std::chrono::milliseconds>(e - s).count();

		auto com = 0;// (chls[0].getTotalDataRecv() + chls[0].getTotalDataSent())* numThreads;

		if (role == Role::Sender)
			lout << tag << " n=" << Color::Green << totalOTs << " " << milli << " ms  " << com << " bytes" << std::endl << Color::Default;


		if (cmd.isSet("v") && role == Role::Sender)
		{
			if (role == Role::Sender)
				lout << " **** sender ****\n" << sendTimer << std::endl;

			if (role == Role::Receiver)
				lout << " **** receiver ****\n" << recvTimer << std::endl;
		}

#else
	throw std::runtime_error("This example requires coproto to enable boost support. Please build libOTe with `-DCOPROTO_ENABLE_BOOST=ON`. " LOCATION);
#endif
	}
}

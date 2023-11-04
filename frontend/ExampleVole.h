#pragma once


#include "libOTe/Vole/Silent/SilentVoleReceiver.h"
#include "libOTe/Vole/Silent/SilentVoleSender.h"

namespace osuCrypto
{


	//template<typename OtExtSender, typename OtExtRecver>
	void Vole_example(Role role, int numOTs, int numThreads, std::string ip, std::string tag, CLP& cmd)
	{
#if defined(ENABLE_SILENT_VOLE) && defined(COPROTO_ENABLE_BOOST)

		if (numOTs == 0)
			numOTs = 1 << 20;
		using OtExtSender = SilentVoleSender;
		using OtExtRecver = SilentVoleReceiver;

		// get up the networking
		auto chl = cp::asioConnect(ip, role == Role::Sender);

		// get a random number generator seeded from the system
		PRNG prng(sysRandomSeed());

		auto mulType = (MultType)cmd.getOr("multType", (int)DefaultMultType);
		bool fakeBase = cmd.isSet("fakeBase");

		u64 milli;
		Timer timer;

		gTimer.setTimePoint("begin");
		if (role == Role::Receiver)
		{
			// construct a vector to stored the received messages.
			std::unique_ptr<block[]> backing0(new block[numOTs]);
			std::unique_ptr<block[]> backing1(new block[numOTs]);
			span<block> choice(backing0.get(), numOTs);
			span<block> msgs(backing1.get(), numOTs);
			gTimer.setTimePoint("recver.msg.alloc");

			OtExtRecver receiver;
			receiver.mMultType = mulType;
			receiver.configure(numOTs);
			gTimer.setTimePoint("recver.config");

			// generate base OTs
			if (fakeBase)
			{
				auto nn = receiver.baseOtCount();
				std::vector<std::array<block, 2>> baseSendMsgs(nn);
				PRNG pp(oc::ZeroBlock);
				pp.get(baseSendMsgs.data(), baseSendMsgs.size());
				receiver.setBaseOts(baseSendMsgs);
			}
			else
			{
				cp::sync_wait(receiver.genSilentBaseOts(prng, chl));
			}

			// block until both parties are ready (optional).
			cp::sync_wait(sync(chl, role));
			auto b = timer.setTimePoint("start");
			receiver.setTimePoint("start");
			gTimer.setTimePoint("recver.genBase");

			// perform  numOTs random OTs, the results will be written to msgs.
			cp::sync_wait(receiver.silentReceive(choice, msgs, prng, chl));

			// record the time.
			receiver.setTimePoint("finish");
			auto e = timer.setTimePoint("finish");
			milli = std::chrono::duration_cast<std::chrono::milliseconds>(e - b).count();
		}
		else
		{
			gTimer.setTimePoint("sender.thrd.begin");


			std::unique_ptr<block[]> backing(new block[numOTs]);
			span<block> msgs(backing.get(), numOTs);

			gTimer.setTimePoint("sender.msg.alloc");

			OtExtSender sender;
			sender.mMultType = mulType;
			sender.configure(numOTs);
			gTimer.setTimePoint("sender.config");
			timer.setTimePoint("start");

			// generate base OTs
			if (fakeBase)
			{
				auto nn = sender.baseOtCount();
				BitVector bits(nn); bits.randomize(prng);
				std::vector<std::array<block, 2>> baseSendMsgs(nn);
				std::vector<block> baseRecvMsgs(nn);
				PRNG pp(oc::ZeroBlock);
				pp.get(baseSendMsgs.data(), baseSendMsgs.size());
				for (u64 i = 0; i < nn; ++i)
					baseRecvMsgs[i] = baseSendMsgs[i][bits[i]];
				sender.setBaseOts(baseRecvMsgs, bits);
			}
			else
			{
				cp::sync_wait(sender.genSilentBaseOts(prng, chl));
			}

			// block until both parties are ready (optional).
			cp::sync_wait(sync(chl, role));
			auto b = sender.setTimePoint("start");
			gTimer.setTimePoint("sender.genBase");

			// perform the OTs and write the random OTs to msgs.
			block delta = prng.get();
			cp::sync_wait(sender.silentSend(delta, msgs, prng, chl));

			sender.setTimePoint("finish");
			auto e = timer.setTimePoint("finish");
			milli = std::chrono::duration_cast<std::chrono::milliseconds>(e - b).count();
		}
		if (role == Role::Sender)
		{

			lout << tag <<
				" n:" << Color::Green << std::setw(6) << std::setfill(' ') << numOTs << Color::Default <<
				"   ||   " << Color::Green <<
				std::setw(6) << std::setfill(' ') << milli << " ms   " <<
				//std::setw(6) << std::setfill(' ') << com << " bytes" <<
				std::endl << Color::Default;

			if (cmd.getOr("v", 0) > 1)
				lout << gTimer << std::endl;

		}

		cp::sync_wait(chl.flush());
#endif
	}

}

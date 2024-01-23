
#include "libOTe/Vole/Silent/SilentVoleReceiver.h"
#include "libOTe/Vole/Silent/SilentVoleSender.h"
#include "util.h"
#include "coproto/Socket/AsioSocket.h"

namespace osuCrypto
{


	template<typename F, typename G>
	void Vole_example(Role role, int numVole, int numThreads, std::string ip, std::string tag, const CLP& cmd)
	{
#if defined(ENABLE_SILENT_VOLE) && defined(COPROTO_ENABLE_BOOST)

		if (numVole == 0)
			numVole = 1 << 20;

		// get up the networking
		auto chl = cp::asioConnect(ip, role == Role::Sender);

		// get a random number generator seeded from the system
		PRNG prng(sysRandomSeed());

		auto mulType = (MultType)cmd.getOr("multType", (int)DefaultMultType);

		u64 milli;
		Timer timer;

		gTimer.setTimePoint("begin");
		if (role == Role::Receiver)
		{
			// construct a vector to stored the received messages.
			// A = B + C * delta
			AlignedUnVector<G> C(numVole);
			AlignedUnVector<F> A(numVole);
			gTimer.setTimePoint("recver.msg.alloc");

			SilentVoleReceiver<F, G> receiver;
			receiver.mMultType = mulType;
			receiver.configure(numVole);
			gTimer.setTimePoint("recver.config");

			// block until both parties are ready (optional).
			cp::sync_wait(sync(chl, role));
			auto b = timer.setTimePoint("start");
			receiver.setTimePoint("start");
			gTimer.setTimePoint("recver.genBase");

			// perform  numVole random OTs, the results will be written to msgs.
			cp::sync_wait(receiver.silentReceive(C, A, prng, chl));

			// record the time.
			receiver.setTimePoint("finish");
			auto e = timer.setTimePoint("finish");
			milli = std::chrono::duration_cast<std::chrono::milliseconds>(e - b).count();
		}
		else
		{
			gTimer.setTimePoint("sender.thrd.begin");

			// A = B + C * delta
			AlignedUnVector<F> B(numVole);
			block delta = prng.get();

			gTimer.setTimePoint("sender.msg.alloc");

			SilentVoleSender<F, G> sender;
			sender.mMultType = mulType;
			sender.configure(numVole);
			gTimer.setTimePoint("sender.config");
			timer.setTimePoint("start");

			// block until both parties are ready (optional).
			cp::sync_wait(sync(chl, role));
			auto b = sender.setTimePoint("start");
			gTimer.setTimePoint("sender.genBase");

			// perform the OTs and write the random OTs to msgs.
			cp::sync_wait(sender.silentSend(delta, B, prng, chl));

			sender.setTimePoint("finish");
			auto e = timer.setTimePoint("finish");
			milli = std::chrono::duration_cast<std::chrono::milliseconds>(e - b).count();
		}
		if (role == Role::Sender)
		{

			lout << tag <<
				" n:" << Color::Green << std::setw(6) << std::setfill(' ') << numVole << Color::Default <<
				"   ||   " << Color::Green <<
				std::setw(6) << std::setfill(' ') << milli << " ms   " <<
				//std::setw(6) << std::setfill(' ') << com << " bytes" <<
				std::endl << Color::Default;

			if (cmd.getOr("v", 0) > 1)
				lout << gTimer << std::endl;

		}

		// make sure all messages are sent.
		cp::sync_wait(chl.flush());
#endif
	}
	bool Vole_Examples(const CLP& cmd)
	{
		return
			runIf(Vole_example<block, block>, cmd, vole);
	}

}

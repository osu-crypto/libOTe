
#include "libOTe/TwoChooseOne/Silent/SilentOtExtReceiver.h"
#include "libOTe/TwoChooseOne/Silent/SilentOtExtSender.h"
#include "util.h"
#include <iomanip>

#include "cryptoTools/Network/IOService.h"
#include "coproto/Socket/AsioSocket.h"

namespace osuCrypto
{

	void Silent_example(Role role, u64 numOTs, u64 numThreads, std::string ip, std::string tag, const CLP& cmd)
	{
#if defined(ENABLE_SILENTOT) && defined(COPROTO_ENABLE_BOOST)

		if (numOTs == 0)
			numOTs = 1 << 20;

		// get up the networking
		auto chl = cp::asioConnect(ip, role == Role::Sender);


		PRNG prng(sysRandomSeed());

		bool fakeBase = cmd.isSet("fakeBase");
		u64 trials = cmd.getOr("trials", 1);

		auto multType = (MultType)cmd.getOr("multType", (int)DefaultMultType);

		// malicious or semi-honest security.
		auto malicious = cmd.isSet("mal") ?
			SilentSecType::Malicious :
			SilentSecType::SemiHonest;

		// how should we generate the base ots? 
		// base = use the base OTs directly.
		// baseExtend = use 128 base OTs and then extend those.
		SilentBaseType baseType = cmd.isSet("base") ?
			SilentBaseType::Base :
			SilentBaseType::BaseExtend;

		// how should we generate the noise distribution?
		// regular = use the regular noise distribution. First base OTs
		//    must be generate for each expansion.
		// stationary = use the stationary noise distribution. First base OTs
		//    must be generated once, and then the same base OTs can be used
		//    for each expansion. This is more efficient if many expansions are 
		//    performed but also requires base VOLE correlations.
		auto noiseDist = cmd.isSet("stationary") ?
			SdNoiseDistribution::Stationary :
			SdNoiseDistribution::Regular;

		// do we want random or correlated OTs (aka VOLE)?
		auto otType = cmd.isSet("correlated") ?
			OTType::Correlated :
			OTType::Random;

		// optionally use a thread pool to run the protocol.
		macoro::thread_pool threadPool;
		auto work = threadPool.make_work();
		if (numThreads > 1)
			threadPool.create_threads(numThreads);


		for (u64 tt = 0; tt < trials; ++tt)
		{
			Timer timer;
			auto start = timer.setTimePoint("start");
			if (role == Role::Sender)
			{
				SilentOtExtSender sender;

				// optionally configure the sender. default is semi honest security and 
				// regular noise distribution.
				sender.configure(numOTs, 2, numThreads, malicious, noiseDist, multType);

				// it is possible to generate the base OTs and VOLES externally and then
				// set them here. If this is not called then the base OTs will be generated
				// using the DefaultBaseOT protocol and then extended into ~1000 base OTs
				if (fakeBase)
				{
					// we must generate base OTs and if stationary base VOLE correlations.
					SilentBaseCount baseCorCount = sender.baseCount();

					// generate random OTs using a common PRNG. This is insecure but gets the
					// point across.
					auto commonPrng = PRNG(CCBlock);
					std::vector<std::array<block, 2>> baseSendMsgs(baseCorCount.mBaseOtCount);
					commonPrng.get(baseSendMsgs.data(), baseSendMsgs.size());

					// if stationary  noise is used we must also generate the 
					// base VOLE correlations: baseA = baseB + baseC * delta
					std::vector<block> baseB(baseCorCount.mBaseVoleCount);
					block delta = commonPrng.get<block>();
					commonPrng.get(baseB.data(), baseB.size());

					sender.setBaseCors(baseSendMsgs, baseB, delta);
				}
				else
				{
					// optional. You can request that the base ot are generated either
					// using just base OTs (few rounds, more computation) or 128 base OTs 
					// and then extend those. The default is the latter, base + extension.
					cp::sync_wait(sender.genBaseCors({}, prng, chl, baseType == SilentBaseType::BaseExtend));
				}

				if (otType == OTType::Random)
				{

					std::vector<std::array<block, 2>> messages(numOTs);

					// create the protocol object.
					task<> protocol = sender.silentSend(messages, prng, chl);

					// run the protocol
					if (numThreads <= 1)
						cp::sync_wait(protocol);
					else
					{
						// launch the protocol on the thread pool. This requires two steps:

						// 1. tell the socket to resume the protocol on the thread pool.
						chl.setExecutor(threadPool);

						// 2. start the protocol on the thread pool.
						cp::sync_wait(std::move(protocol) | macoro::start_on(threadPool));
					}

					// messages has been populated with random OT messages.
					// See the header for other options.
				}
				else
				{
					// it is also possible to send correlated OTs (aka a vole),
					// where the receiver gets a, c and the sender gets b, delta such that
					// 
					//    a[i] = b[i] + c[i] * delta.
					//
					std::vector<block> B(numOTs);
					// delta is optional, if not set then it is random.
					// for stationary noise, it must be the same value
					// as was used to generate the base VOLE correlations.
					// we will leave it empty for now, but it can be set later.
					// the value that was used it sender.mDelta.
					std::optional<block> delta; 

					cp::sync_wait(sender.silentSend(delta, B, prng, chl));

					// a = B + C * sender.mDelta

					// if stationary, then the protocol can be invoked again and the 
					// base OTs that had specific values will be reused. However, new base
					// vole correlations will still be required. If malicious security is 
					// used then there additional random base OTs will be required for that.
					
				}
			}
			else
			{

				SilentOtExtReceiver recver;

				// configure the sender. optional for semi honest security...
				recver.configure(numOTs, 2, numThreads, malicious, noiseDist, multType);

				// it is possible to generate the OTs and VOLES externally and then
				// set them here. If this is not called then the base OTs will be generated
				// using the DefaultBaseOT protocol and then extended into ~1000 base OTs
				// and the base VOLE correlations will be generated if stationary noise is used.
				if (fakeBase)
				{
					// we must generate base OTs and if stationary base VOLE correlations.
					SilentBaseCount counts = recver.baseCount();

					// the first set of choice bits must have specific values
					// as they encode the noise locations for which not all bit strings
					// are valid. To get these bits we must call sampleBaseChoiceBits().
					auto specialBits = recver.sampleBaseChoiceBits(prng);

					// for the rest, we use random bits.
					BitVector choices(counts.mBaseOtCount);
					std::copy(specialBits.begin(), specialBits.end(), choices.begin());
					for (u64 i = specialBits.size(); i < choices.size(); ++i)
						choices[i] = prng.getBit();

					std::vector<std::array<block, 2>> baseSendMsgs(choices.size());
					std::vector<block> baseRecvMsgs(choices.size());

					auto commonPrng = PRNG(CCBlock);
					commonPrng.get(baseSendMsgs.data(), baseSendMsgs.size());
					for (u64 i = 0; i < choices.size(); ++i)
						baseRecvMsgs[i] = baseSendMsgs[i][choices[i]];

					// if stationary  noise is used we must also generate the
					// base VOLE correlations: baseA = baseB + baseC * delta
					std::vector<block> baseA(counts.mBaseVoleCount), baseB(counts.mBaseVoleCount);
					BitVector baseC(counts.mBaseVoleCount);
					baseC.randomize(prng);
					block delta = commonPrng.get<block>();
					commonPrng.get(baseB.data(), baseB.size());
					for (u64 i = 0; i < baseA.size(); ++i)
					{
						// baseA[i] = baseB[i] + baseC[i] * delta 
						baseA[i] = baseB[i] ^ (baseC[i] ? delta : ZeroBlock);
					}

					recver.setBaseCors(baseRecvMsgs, choices, baseA, baseC);
				}
				else
				{
					// optional. You can request that the base ot are generated either
					// using just base OTs (few rounds, more computation) or 128 base OTs and then extend those.
					// The default is the latter, base + extension.
					cp::sync_wait(recver.genBaseCors(prng, chl, baseType == SilentBaseType::BaseExtend));
				}

				if (otType == OTType::Random)
				{
					std::vector<block> messages(numOTs);
					BitVector choices(numOTs);

					// create the protocol object.
					auto protocol = recver.silentReceive(choices, messages, prng, chl);

					// run the protocol
					if (numThreads <= 1)
						cp::sync_wait(protocol);
					else
						// launch the protocol on the thread pool.
						cp::sync_wait(std::move(protocol) | macoro::start_on(threadPool));

					// choices, messages has been populated with random OT messages.
					// messages[i] = sender.message[i][choices[i]]
					// See the header for other options.
				}
				else
				{
					// it is also possible to receive correlated OTs (aka a vole),
					// where the receiver gets a, c and the sender gets b, delta such that
					// 
					//    a[i] = b[i] + c[i] * delta.
					//
					std::vector<block> A(numOTs);
					BitVector C(numOTs);

					cp::sync_wait(recver.silentReceive(C, A, prng, chl, OTType::Correlated));


					// if stationary, then the protocol can be invoked again and the 
					// base OTs that had specific values will be reused. However, new base
					// vole correlations will still be required. If malicious security is 
					// used then there additional random base OTs will be required for that.

				}
			}

			auto end = timer.setTimePoint("end");
			auto milli = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

			u64 com = chl.bytesReceived() + chl.bytesSent();

			if (role == Role::Sender)
			{
				std::string typeStr = baseType == SilentBaseType::Base ? "b " : "be ";
				lout << tag <<
					" n:" << Color::Green << std::setw(6) << std::setfill(' ') << numOTs << Color::Default <<
					" type: " << Color::Green << typeStr << Color::Default <<
					"   ||   " << Color::Green <<
					std::setw(6) << std::setfill(' ') << milli << " ms   " <<
					std::setw(6) << std::setfill(' ') << com << " bytes" << std::endl << Color::Default;

				if (cmd.getOr("v", 0) > 1)
					lout << gTimer << std::endl;
			}

			if (cmd.isSet("v"))
			{
				if (role == Role::Sender)
					lout << " **** sender ****\n" << timer << std::endl;

				if (role == Role::Receiver)
					lout << " **** receiver ****\n" << timer << std::endl;
			}
		}

		cp::sync_wait(chl.flush());

#else
		std::cout << "This example requires coproto to enable boost support. Please build libOTe with `-DCOPROTO_ENABLE_BOOST=ON`. \n" << LOCATION << std::endl;
#endif
	}
	bool Silent_Examples(const CLP& cmd)
	{
		return runIf(Silent_example, cmd, Silent);
	}


}

#include "Vole_Tests.h"
#include "libOTe/Vole/Noisy/NoisyVoleSender.h"
#include "libOTe/Vole/Noisy/NoisyVoleReceiver.h"
#include "libOTe/Vole/Silent/SilentVoleSender.h"
#include "libOTe/Vole/Silent/SilentVoleReceiver.h"
#include "cryptoTools/Network/Session.h"
#include "cryptoTools/Network/IOService.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Common/Range.h"
#include "cryptoTools/Common/TestCollection.h"
#include "Common.h"
#include "coproto/Socket/BufferingSocket.h"

using namespace oc;

#include <libOTe/config.h>
#include "libOTe/Tools/CoeffCtx.h"

using namespace tests_libOTe;
#ifdef ENABLE_SILENT_VOLE
template<typename F, typename G, typename Ctx>
void Vole_Noisy_test_impl(u64 n)
{
	PRNG prng(CCBlock);

	F delta = prng.get();
	std::vector<G> c(n);
	std::vector<F> a(n), b(n);
	prng.get(c.data(), c.size());

	NoisyVoleReceiver<F, G, Ctx> recv;
	NoisyVoleSender<F, G, Ctx> send;

	auto chls = cp::LocalAsyncSocket::makePair();

	Ctx ctx;
	BitVector recvChoice = ctx.binaryDecomposition(delta);
	std::vector<block> otRecvMsg(recvChoice.size());
	std::vector<std::array<block, 2>> otSendMsg(recvChoice.size());
	prng.get<std::array<block, 2>>(otSendMsg);
	for (u64 i = 0; i < recvChoice.size(); ++i)
		otRecvMsg[i] = otSendMsg[i][recvChoice[i]];

	// compute a,b such that
	// 
	//   a = b + c * delta
	//
	auto p0 = recv.receive(c, a, prng, otSendMsg, chls[0], ctx);
	auto p1 = send.send(delta, b, prng, otRecvMsg, chls[1], ctx);

	eval(p0, p1);

	for (u64 i = 0; i < n; ++i)
	{
		F prod, sum;

		ctx.mul(prod, delta, c[i]);
		ctx.minus(sum, a[i], b[i]);

		if (prod != sum)
		{
			throw RTE_LOC;
		}
	}
}

void Vole_Noisy_test(const oc::CLP& cmd)
{
	for (u64 n : {1, 8, 433})
	{
		Vole_Noisy_test_impl<u8, u8, CoeffCtxInteger>(n);
		Vole_Noisy_test_impl<u64, u32, CoeffCtxInteger>(n);
		Vole_Noisy_test_impl<block, block, CoeffCtxGF128>(n);
		Vole_Noisy_test_impl<std::array<u32, 11>, u32, CoeffCtxArray<u32, 11>>(n);
	}
}

namespace
{

	template<typename G, typename R, typename S, typename F, typename Ctx>
	void fakeBase(
		u64 n,
		PRNG& prng,
		F delta,
		R& recver,
		S& sender,
		Ctx ctx)
	{

		auto count = sender.baseCount();

		std::vector<std::array<block, 2>> msg2(count.mBaseOtCount);
		BitVector choices = recver.sampleBaseChoiceBits(prng);
		std::vector<block> msg(choices.size());

		if (choices.size() != msg2.size())
			throw RTE_LOC;

		for (auto& m : msg2)
		{
			m[0] = prng.get();
			m[1] = prng.get();
		}

		for (auto i : rng(msg.size()))
			msg[i] = msg2[i][choices[i]];

		// a = b + c * d
		// the sender gets b, d
		// the recver gets a, c
		//auto c = recver.sampleBaseVoleVals(prng);
		typename Ctx::template Vec<F>
			a(count.mBaseVoleCount),
			b(count.mBaseVoleCount);
		typename Ctx::template Vec<G>
			c(count.mBaseVoleCount);

		if constexpr (std::is_same_v<G, bool>)
		{
			for (u64 i = 0; i < c.size(); ++i)
				c[i] = prng.getBit();
		}
		else
			prng.get(c.data(), c.size());
		prng.get(b.data(), b.size());
		for (auto i : rng(c.size()))
		{
			ctx.mul(a[i], delta, c[i]);
			ctx.plus(a[i], b[i], a[i]);
		}
		sender.setBaseCors(msg2, b);
		recver.setBaseCors(choices, msg, a, c);
	}

}


template<typename F, typename G, typename Ctx>
void Vole_Silent_test_impl(u64 n, MultType type, bool debug, bool doFakeBase, bool mal, SdNoiseDistribution noise)
{
	using VecF = typename Ctx::template Vec<F>;
	using VecG = typename Ctx::template Vec<G>;
	Ctx ctx;

	block seed = CCBlock;
	PRNG prng(seed);

	auto chls = cp::LocalAsyncSocket::makePair();

	SilentVoleReceiver<F, G, Ctx> recv;
	SilentVoleSender<F, G, Ctx> send;
	recv.mDebug = debug;
	send.mDebug = debug;
	auto mt = mal ? SilentSecType::Malicious : SilentSecType::SemiHonest;

	VecF a(n), b(n);
	VecG c(n);
	F d = prng.get();

	send.configure(n, mt, type, SilentBaseType::BaseExtend, noise);
	recv.configure(n, mt, type, SilentBaseType::BaseExtend, noise);

	if (doFakeBase)
		fakeBase<G>(n, prng, d, recv, send, ctx);

	u64 l = noise == SdNoiseDistribution::Regular ? 1 : 3;
	for (u64 t = 0; t < l; ++t)
	{
		if (t)
		{
			auto count = send.baseCount();
			if (count.mBaseOtCount)
				throw RTE_LOC;

			if (doFakeBase)
				fakeBase<G>(n, prng, d, recv, send, ctx);
		}

		auto p0 = recv.silentReceive(c, a, prng, chls[0]);
		auto p1 = send.silentSend(d, b, prng, chls[1]);

		eval(p0, p1);

		for (u64 i = 0; i < n; ++i)
		{
			// a = b + c * d
			F exp;
			ctx.mul(exp, d, c[i]);
			ctx.plus(exp, exp, b[i]);

			if (a[i] != exp)
			{
				throw RTE_LOC;
			}
		}
	}

}


void Vole_Silent_paramSweep_test(const oc::CLP& cmd)
{
	auto debug = cmd.isSet("debug");
	auto noise = (SdNoiseDistribution)cmd.getOr("noise", 0);
	for (u64 n : {128, 45364})
	{
		Vole_Silent_test_impl<u64, u64, CoeffCtxInteger>(n, DefaultMultType, debug, false, false, noise);
		Vole_Silent_test_impl<block, block, CoeffCtxGF128>(n, DefaultMultType, debug, false, false, noise);
		Vole_Silent_test_impl<block, bool, CoeffCtxGF2>(n, DefaultMultType, debug, false, false, noise);
		Vole_Silent_test_impl<std::array<u32, 8>, u32, CoeffCtxArray<u32, 8>>(n, DefaultMultType, debug, false, false, noise);
	}
}


void Vole_Silent_stationary_test(const oc::CLP& cmd)
{
	auto debug = cmd.isSet("debug");
	auto noise = (SdNoiseDistribution)cmd.getOr("noise", 1);
	for (u64 n : {128, 45364})
	{
		Vole_Silent_test_impl<u64, u64, CoeffCtxInteger>(n, DefaultMultType, debug, false, false, noise);
		Vole_Silent_test_impl<block, block, CoeffCtxGF128>(n, DefaultMultType, debug, false, false, noise);
	}
}


void Vole_Silent_QuasiCyclic_test(const oc::CLP& cmd)
{
#if defined(ENABLE_BITPOLYMUL)
	auto debug = cmd.isSet("debug");
	auto noise = (SdNoiseDistribution)cmd.getOr("noise", 0);
	for (u64 n : {128, 333})
		Vole_Silent_test_impl<block, block, CoeffCtxGF128>(n, MultType::QuasiCyclic, debug, false, false, noise);
#else
	throw UnitTestSkipped("ENABLE_BITPOLYMUL not defined." LOCATION);
#endif
}

void Vole_Silent_BlkAcc_test(const oc::CLP& cmd)
{
	auto noise = (SdNoiseDistribution)cmd.getOr("noise", 0);
	auto debug = cmd.isSet("debug");
	for (u64 n : {128, 33341})
		Vole_Silent_test_impl<block, block, CoeffCtxGF128>(n, MultType::BlkAcc3x8, debug, false, false, noise);
}

void Vole_Silent_Tungsten_test(const oc::CLP& cmd)
{
	auto noise = (SdNoiseDistribution)cmd.getOr("noise", 0);
	auto debug = cmd.isSet("debug");
	for (u64 n : {128, 33341})
		Vole_Silent_test_impl<block, block, CoeffCtxGF128>(n, MultType::Tungsten, debug, false, false, noise);
}


void Vole_Silent_baseOT_test(const oc::CLP& cmd)
{
	auto debug = cmd.isSet("debug");
	u64 n = 128;
	for (auto noise : { SdNoiseDistribution::Regular, SdNoiseDistribution::Stationary })
	{
		Vole_Silent_test_impl<u64, u64, CoeffCtxInteger>(n, DefaultMultType, debug, true, false, noise);
		Vole_Silent_test_impl<block, block, CoeffCtxGF128>(n, DefaultMultType, debug, true, false, noise);
		Vole_Silent_test_impl<std::array<u32, 8>, u32, CoeffCtxArray<u32, 8>>(n, DefaultMultType, debug, true, false, noise);
	}
}



void Vole_Silent_mal_test(const oc::CLP& cmd)
{
	auto debug = cmd.isSet("debug");
	for (auto noise : { SdNoiseDistribution::Regular, SdNoiseDistribution::Stationary })
	{

		for (u64 n : {4364})
		{
			Vole_Silent_test_impl<block, block, CoeffCtxGF128>(n, DefaultMultType, debug, false, true, noise);
		}
	}
}


inline u64 eval(
	macoro::task<>& t1, macoro::task<>& t0,
	cp::BufferingSocket& s1, cp::BufferingSocket& s0)
{
	auto e = macoro::make_eager(macoro::when_all_ready(std::move(t0), std::move(t1)));

	u64 rounds = 0;
	{
		auto b1 = s1.getOutbound();
		if (b1)
		{
			s0.processInbound(*b1);
			++rounds;
		}
	}

	u64 idx = 0;
	while (e.is_ready() == false)
	{
		if (idx % 2 == 0)
		{
			auto b0 = s0.getOutbound();
			if (!b0)
				throw RTE_LOC;
			s1.processInbound(*b0);

		}
		else
		{
			auto b1 = s1.getOutbound();
			if (!b1)
				throw RTE_LOC;
			s0.processInbound(*b1);
		}

		++rounds;
		++idx;

	}

	auto r = macoro::sync_wait(std::move(e));
	std::get<0>(r).result();
	std::get<1>(r).result();
	return rounds;
}


void Vole_Silent_Rounds_test(const oc::CLP& cmd)
{

	Timer timer;
	timer.setTimePoint("start");
	u64 n = 1233;
	block seed = block(0, cmd.getOr("seed", 0));
	PRNG prng(seed);

	block x = prng.get();


	cp::BufferingSocket chls[2];

	SilentVoleReceiver<block, block, CoeffCtxGF128> recv;
	SilentVoleSender<block, block, CoeffCtxGF128> send;

	for (u64 jj : {0, 1})
	{

		send.configure(n,SilentSecType::SemiHonest, DefaultMultType, SilentBaseType::Base);
		recv.configure(n,SilentSecType::SemiHonest, DefaultMultType, SilentBaseType::Base);
		// c * x = z + m

		//for (u64 n = 5000; n < 10000; ++n)
		{

			recv.setTimer(timer);
			send.setTimer(timer);
			if (jj)
			{
				AlignedUnVector<block> c(n), z0(n), z1(n);
				auto p0 = recv.silentReceive(c, z0, prng, chls[0]);
				auto p1 = send.silentSend(x, z1, prng, chls[1]);
				std::string baseName;
				//
//#if defined ENABLE_MRR_TWIST && defined ENABLE_SSE
//                using BaseOT = McRosRoyTwist;
//#elif defined ENABLE_MR
//                using BaseOT = MasnyRindal;
//#elif defined ENABLE_MRR
//                using BaseOT = McRosRoy;
//#elif defined ENABLE_MR_KYBER

#if defined ENABLE_MRR_TWIST && defined ENABLE_SSE
				u64 expRound = 3;
				baseName = "using DefaultBaseOT = McRosRoyTwist;";
#elif defined ENABLE_MR
				u64 expRound = 3;
				baseName = "using DefaultBaseOT = MasnyRindal;";
#elif defined ENABLE_MRR
				u64 expRound = 3;
				baseName = "using DefaultBaseOT = McRosRoy;";
#elif defined ENABLE_MR_KYBER
				u64 expRound = 3;
				baseName = "using DefaultBaseOT = MasnyRindalKyber;";
#elif defined ENABLE_SIMPLESTOT_ASM
				u64 expRound = 5;
				baseName = "using DefaultBaseOT = AsmSimplestOT;";
#elif defined ENABLE_SIMPLESTOT
				u64 expRound = 5;
				baseName = "using DefaultBaseOT = SimplestOT;";
#elif defined ENABLE_MOCK_OT
				u64 expRound = 3;
				baseName = "using DefaultBaseOT = INSECURE_MOCK_OT;";
#else
				baseName = "????";
				u64 expRound = 0;
#endif

				auto rounds = eval(p0, p1, chls[1], chls[0]);
				if (rounds != expRound)
				{
					std::cout << baseName << std::endl;
					throw std::runtime_error("act " + std::to_string(rounds) + "!= exp " + std::to_string(expRound) + " " + COPROTO_LOCATION);
				}


				for (u64 i = 0; i < n; ++i)
				{
					if (c[i].gf128Mul(x) != (z0[i] ^ z1[i]))
					{
						throw RTE_LOC;
					}
				}
			}
			else
			{


				auto p0 = send.genBaseCors(prng, chls[0], x);
				auto p1 = recv.genBaseCors(prng, chls[1]);

				auto rounds = eval(p0, p1, chls[1], chls[0]);
				if (rounds != 3)
					throw RTE_LOC;

				p0 = send.silentSendInplace(x, n, prng, chls[0]);
				p1 = recv.silentReceiveInplace(n, prng, chls[1]);
				rounds = eval(p0, p1, chls[1], chls[0]);



				for (u64 i = 0; i < n; ++i)
				{
					if (recv.mC[i].gf128Mul(x) != (send.mB[i] ^ recv.mA[i]))
					{
						throw RTE_LOC;
					}
				}
			}

		}

		timer.setTimePoint("done");
	}
}
#else


namespace {
	void throwDisabled()
	{
		throw UnitTestSkipped(
			"ENABLE_SILENT_VOLE not defined. "
		);
	}
}
void Vole_Silent_Tungsten_test(const oc::CLP& cmd) { throwDisabled(); }
void Vole_Silent_BlkAcc_test(const oc::CLP& cmd) { throwDisabled(); }
void Vole_Silent_stationary_test(const oc::CLP& cmd) { throwDisabled(); }

void Vole_Noisy_test(const oc::CLP& cmd) { throwDisabled(); }
void Vole_Silent_QuasiCyclic_test(const oc::CLP& cmd) { throwDisabled(); }
void Vole_Silent_paramSweep_test(const oc::CLP& cmd) { throwDisabled(); }
void Vole_Silent_baseOT_test(const oc::CLP& cmd) { throwDisabled(); }
void Vole_Silent_mal_test(const oc::CLP& cmd) { throwDisabled(); }
void Vole_Silent_Rounds_test(const oc::CLP& cmd) { throwDisabled(); }


#endif
//
//
//void Vole_Silent_QuasiCyclic_test(const oc::CLP& cmd) { throwDisabled(); }
//void Vole_Silent_Silver_test(const oc::CLP& cmd) { throwDisabled(); }
//void Vole_Silent_paramSweep_test(const oc::CLP& cmd) { throwDisabled(); }
//void Vole_Silent_baseOT_test(const oc::CLP& cmd) { throwDisabled(); }
//void Vole_Silent_mal_test(const oc::CLP& cmd) { throwDisabled(); }
//void Vole_Silent_Rounds_test(const oc::CLP& cmd) { throwDisabled(); }

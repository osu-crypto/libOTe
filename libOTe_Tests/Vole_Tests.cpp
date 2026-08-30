#include "Vole_Tests.h"
#include "libOTe/Vole/Noisy/NoisyVoleSender.h"
#include "libOTe/Vole/Noisy/NoisyVoleReceiver.h"
#include "libOTe/Vole/Silent/SilentVoleSender.h"
#include "libOTe/Vole/Silent/SilentVoleReceiver.h"
#include "libOTe/TwoChooseOne/ConfigureCode.h"
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
#include "libOTe/Tools/Field/Fp.h"
#include "libOTe/Tools/Field/FVec.h"
#include "libOTe/Tools/Field/Goldilocks.h"

using namespace tests_libOTe;
#ifdef ENABLE_SILENT_VOLE
template<typename F, typename G, typename Ctx>
void Vole_Noisy_test_impl(u64 n)
{
	PRNG prng(CCBlock);

	F delta = prng.get();
	std::vector<G> c(n);
	std::vector<F> a(n), b(n);
	for (auto& value : c)
		value = prng.get();

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
		Vole_Noisy_test_impl<F12289, F12289, DefaultCoeffCtx<F12289>>(n);
		using VF = FVec<Fp31, 2>;
		Vole_Noisy_test_impl<VF, VF, DefaultCoeffCtx<VF>>(n);
	}
}

namespace
{
	unsigned binaryRank(span<const block> values)
	{
		std::array<block, 128> basis{};
		std::array<bool, 128> occupied{};
		unsigned rank = 0;

		for (block value : values)
		{
			for (int pivot = 127; pivot >= 0; --pivot)
			{
				const auto words = value.get<u64>();
				if (((words[pivot / 64] >> (pivot % 64)) & 1) == 0)
					continue;

				if (occupied[pivot])
					value ^= basis[pivot];
				else
				{
					basis[pivot] = value;
					occupied[pivot] = true;
					++rank;
					break;
				}
			}
		}

		return rank;
	}

	template<typename G, typename R, typename S, typename F, typename Ctx>
	void fakeBase(
		u64 n,
		PRNG& prng,
		F delta,
		R& recver,
		S& sender,
		Ctx ctx,
		SdNoiseDistribution noise)
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

		for (u64 i = 0; i < c.size(); ++i)
		{
			if (noise == SdNoiseDistribution::Regular &&
				i < recver.mNumPartitions)
				sampleRegularNoiseUnit(c[i], prng, ctx);
			else
				ctx.fromBlock(c[i], prng.get<block>());
		}
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
void Vole_Silent_test_impl(
	u64 n,
	MultType type,
	bool debug,
	bool doFakeBase,
	bool mal,
	SdNoiseDistribution noise,
	bool requireFullBinaryRank = false,
	block seed = CCBlock)
{
	using VecF = typename Ctx::template Vec<F>;
	using VecG = typename Ctx::template Vec<G>;
	Ctx ctx;

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
		fakeBase<G>(n, prng, d, recv, send, ctx, noise);

	u64 l = noise == SdNoiseDistribution::Regular ? 1 : 3;
	for (u64 t = 0; t < l; ++t)
	{
		if (t)
		{
			auto count = send.baseCount();
			if (count.mBaseOtCount)
				throw RTE_LOC;

			if (doFakeBase)
				fakeBase<G>(n, prng, d, recv, send, ctx, noise);
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

		if (requireFullBinaryRank)
		{
			if constexpr (std::is_same_v<G, block>)
			{
				const auto rank = binaryRank(c);
				if (rank != 128)
					throw UnitTestFail(
						"Silent VOLE default matrix output has binary rank " +
						std::to_string(rank));
			}
			else
			{
				throw RTE_LOC;
			}
		}
	}

}

namespace
{
	struct CountingOtReceiver final : OtReceiver
	{
		u64 mCalls = 0;

		task<> receive(const BitVector&, span<block>, PRNG&, Socket&) override
		{
			++mCalls;
			throw std::runtime_error("unexpected OT receive");
			co_return;
		}
	};

	struct CountingOtSender final : OtSender
	{
		u64 mCalls = 0;

		task<> send(span<std::array<block, 2>>, PRNG&, Socket&) override
		{
			++mCalls;
			throw std::runtime_error("unexpected OT send");
			co_return;
		}
	};

	template<typename T>
	struct OversizedVector
	{
		T mValue{};

		u64 size() const { return static_cast<u64>(std::numeric_limits<u32>::max()) + 1; }
		void resize(u64) {}
		T* begin() { return &mValue; }
		T* end() { return &mValue; }
		const T* begin() const { return &mValue; }
		const T* end() const { return &mValue; }
		T& operator[](std::size_t) { return mValue; }
		const T& operator[](std::size_t) const { return mValue; }
	};

	void expectTaskFailure(task<>&& operation)
	{
		bool threw = false;
		try
		{
			macoro::sync_wait(std::move(operation));
		}
		catch (const std::exception&)
		{
			threw = true;
		}
		if (!threw)
			throw RTE_LOC;
	}

	void expectTaskInvalidArgument(task<>&& operation)
	{
		bool threw = false;
		try
		{
			macoro::sync_wait(std::move(operation));
		}
		catch (const std::invalid_argument&)
		{
			threw = true;
		}
		if (!threw)
			throw RTE_LOC;
	}

	template<typename Fn>
	void expectInvalidArgument(Fn&& fn)
	{
		bool threw = false;
		try
		{
			fn();
		}
		catch (const std::invalid_argument&)
		{
			threw = true;
		}
		if (!threw)
			throw RTE_LOC;
	}
}

void Vole_Noisy_Audit_Test(const oc::CLP&)
{
	PRNG prng(CCBlock);
	CoeffCtxInteger ctx;
	u8 delta = 0;

	expectInvalidArgument([] {
		SilentVoleSender<block, block, CoeffCtxGF128> sender;
		sender.configure(0);
	});
	expectInvalidArgument([] {
		SilentVoleReceiver<block, block, CoeffCtxGF128> receiver;
		receiver.configure(0);
	});

	expectInvalidArgument([] {
		SilentVoleSender<block, block, CoeffCtxGF128> sender;
		sender.configure(128, static_cast<SilentSecType>(255));
	});
	expectInvalidArgument([] {
		SilentVoleReceiver<block, block, CoeffCtxGF128> receiver;
		receiver.configure(128, static_cast<SilentSecType>(255));
	});
	expectInvalidArgument([] {
		SilentVoleSender<block, block, CoeffCtxGF128> sender;
		sender.configure(128, SilentSecType::SemiHonest, DefaultMultType,
			static_cast<SilentBaseType>(255));
	});
	expectInvalidArgument([] {
		SilentVoleReceiver<block, block, CoeffCtxGF128> receiver;
		receiver.configure(128, SilentSecType::SemiHonest, DefaultMultType,
			static_cast<SilentBaseType>(255));
	});

	using SilentSender = SilentVoleSender<block, block, CoeffCtxGF128>;
	using SilentReceiver = SilentVoleReceiver<block, block, CoeffCtxGF128>;
	{
		SilentReceiver receiver;
		receiver.configure(128);
		auto count = receiver.baseCount();
		std::vector<block> recvBaseOts(count.mBaseOtCount);
		SilentReceiver::VecF baseA(count.mBaseVoleCount);
		SilentReceiver::VecG baseC(count.mBaseVoleCount);
		expectInvalidArgument([&] {
			receiver.setBaseCors({}, recvBaseOts, baseA, baseC);
		});
		if (receiver.mState != SilentReceiver::State::Configured ||
			!receiver.mBaseA.empty() || !receiver.mBaseC.empty() ||
			receiver.hasBaseCors())
			throw UnitTestFail(
				"Silent VOLE accepted missing base-OT choices");
	}

	{
		SilentSender sender;
		sender.configure(128);
		auto sockets = cp::LocalAsyncSocket::makePair();
		macoro::sync_wait(sockets[1].close());
		expectTaskInvalidArgument(sender.silentSendInplace(
			ZeroBlock, 0, prng, sockets[0]));
		if (sender.mState != SilentSender::State::Configured ||
			sender.mRequestSize != 128)
			throw UnitTestFail(
				"zero-length Silent VOLE sender call changed configured state");
	}

	{
		SilentReceiver receiver;
		receiver.configure(128);
		auto sockets = cp::LocalAsyncSocket::makePair();
		macoro::sync_wait(sockets[1].close());
		expectTaskInvalidArgument(receiver.silentReceiveInplace(
			0, prng, sockets[0]));
		if (receiver.mState != SilentReceiver::State::Configured ||
			receiver.mRequestSize != 128)
			throw UnitTestFail(
				"zero-length Silent VOLE receiver call changed configured state");
	}

	{
		CountingOtReceiver ot;
		std::vector<u8> output;
		cp::BufferingSocket socket;
		expectTaskFailure(NoisyVoleSender<u8, u8, CoeffCtxInteger>::send(
			delta, output, prng, ot, socket, ctx));
		if (ot.mCalls != 0)
			throw RTE_LOC;
	}

	{
		CountingOtSender ot;
		std::vector<u8> input(2), output(1);
		cp::BufferingSocket socket;
		expectTaskFailure(NoisyVoleReceiver<u8, u8, CoeffCtxInteger>::receive(
			input, output, prng, ot, socket, ctx));
		if (ot.mCalls != 0)
			throw RTE_LOC;
	}

	{
		CountingOtSender ot;
		std::vector<u8> input, output;
		cp::BufferingSocket socket;
		expectTaskFailure(NoisyVoleReceiver<u8, u8, CoeffCtxInteger>::receive(
			input, output, prng, ot, socket, ctx));
		if (ot.mCalls != 0)
			throw RTE_LOC;
	}

	{
		CountingOtReceiver ot;
		OversizedVector<u8> output;
		cp::BufferingSocket socket;
		expectTaskFailure(NoisyVoleSender<u8, u8, CoeffCtxInteger>::send(
			delta, output, prng, ot, socket, ctx));
		if (ot.mCalls != 0)
			throw RTE_LOC;
	}

	{
		CountingOtSender ot;
		OversizedVector<u8> input, output;
		cp::BufferingSocket socket;
		expectTaskFailure(NoisyVoleReceiver<u8, u8, CoeffCtxInteger>::receive(
			input, output, prng, ot, socket, ctx));
		if (ot.mCalls != 0)
			throw RTE_LOC;
	}

	expectInvalidArgument([] {
		syndromeDecodingConfigure(1025, 1, DefaultMultType,
			SdNoiseDistribution::Regular, SdNoiseSecurityModel::binary());
	});
	expectInvalidArgument([] {
		syndromeDecodingConfigure(128,
			static_cast<u64>(std::numeric_limits<u32>::max()) + 1,
			DefaultMultType, SdNoiseDistribution::Regular,
			SdNoiseSecurityModel::binary());
	});
	expectInvalidArgument([] {
		syndromeDecodingConfigure(128, 1, DefaultMultType,
			SdNoiseDistribution::Regular, SdNoiseSecurityModel{ 0.5 });
	});
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

void Vole_Silent_defaultMatrixRank_test(const oc::CLP& cmd)
{
	// Test only the default encoder. Trial one of the original reproducer had
	// rank 127 before extension-field component mixing was added.
	Vole_Silent_test_impl<block, block, CoeffCtxGF128>(
		45364,
		DefaultMultType,
		cmd.isSet("debug"),
		true,
		false,
		SdNoiseDistribution::Regular,
		true,
		block(0x72616e6b2d706f63ULL, 1));
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


void Vole_Silent_QuasiCyclic_test(const oc::CLP&)
{
	using Sender = SilentVoleSender<block, block, CoeffCtxGF128>;
	using Receiver = SilentVoleReceiver<block, block, CoeffCtxGF128>;
	Sender sender;
	Receiver receiver;
	bool senderRejected = false;
	bool receiverRejected = false;
	try
	{
		sender.configure(128, SilentSecType::SemiHonest, MultType::QuasiCyclic,
			SilentBaseType::Base, SdNoiseDistribution::Regular);
	}
	catch (const std::invalid_argument&)
	{
		senderRejected = true;
	}
	try
	{
		receiver.configure(128, SilentSecType::SemiHonest, MultType::QuasiCyclic,
			SilentBaseType::Base, SdNoiseDistribution::Regular);
	}
	catch (const std::invalid_argument&)
	{
		receiverRejected = true;
	}
	if (!senderRejected || !receiverRejected || sender.isConfigured() ||
		receiver.isConfigured())
		throw UnitTestFail("Silent VOLE accepted the binary-only QuasiCyclic code");
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

void Vole_Silent_malBase_test(const oc::CLP& cmd)
{
	auto debug = cmd.isSet("debug");
	for (auto noise : { SdNoiseDistribution::Regular, SdNoiseDistribution::Stationary })
	{
		Vole_Silent_test_impl<block, block, CoeffCtxGF128>(
			4364, DefaultMultType, debug, true, true, noise);
	}
}

void Vole_Silent_Clear_test(const oc::CLP&)
{
	using Sender = SilentVoleSender<block, block, CoeffCtxGF128>;
	using Receiver = SilentVoleReceiver<block, block, CoeffCtxGF128>;

	Sender sender;
	Receiver receiver;
	sender.configure(128, SilentSecType::Malicious, DefaultMultType,
		SilentBaseType::BaseExtend, SdNoiseDistribution::Stationary);
	receiver.configure(128, SilentSecType::Malicious, DefaultMultType,
		SilentBaseType::BaseExtend, SdNoiseDistribution::Stationary);
	sender.mB.resize(1);
	sender.mBaseB.resize(1);
	sender.mDerandomizeMalCheck = true;
	receiver.mA.resize(1);
	receiver.mC.resize(1);
	receiver.mBaseA.resize(1);
	receiver.mBaseC.resize(1);
	receiver.mMalCheckSeed = OneBlock;
	receiver.mDerandomizeMalCheck = true;

	auto invalidMult = static_cast<MultType>(255);
	bool senderConfigThrew = false;
	bool receiverConfigThrew = false;
	try
	{
		sender.configure(256, SilentSecType::SemiHonest, invalidMult,
			SilentBaseType::Base, SdNoiseDistribution::Regular);
	}
	catch (const std::exception&)
	{
		senderConfigThrew = true;
	}
	try
	{
		receiver.configure(256, SilentSecType::SemiHonest, invalidMult,
			SilentBaseType::Base, SdNoiseDistribution::Regular);
	}
	catch (const std::exception&)
	{
		receiverConfigThrew = true;
	}

	if (!senderConfigThrew || !receiverConfigThrew ||
		sender.mState != Sender::State::Configured ||
		receiver.mState != Receiver::State::Configured ||
		sender.mNoiseType != SdNoiseDistribution::Stationary ||
		receiver.mNoiseType != SdNoiseDistribution::Stationary ||
		sender.mRequestSize != 128 || receiver.mRequestSize != 128 ||
		sender.mSecurityType != SilentSecType::Malicious ||
		receiver.mSecurityType != SilentSecType::Malicious ||
		sender.mLpnMultType != DefaultMultType ||
		receiver.mLpnMultType != DefaultMultType ||
		sender.mB.size() != 1 || sender.mBaseB.size() != 1 ||
		receiver.mA.size() != 1 || receiver.mC.size() != 1 ||
		receiver.mBaseA.size() != 1 || receiver.mBaseC.size() != 1 ||
		!receiver.mMalCheckSeed.has_value())
		throw RTE_LOC;

	sender.clear();
	receiver.clear();

	if (sender.mState != Sender::State::Default || sender.isConfigured() ||
		sender.mNoiseType != SdNoiseDistribution::Regular ||
		sender.mRequestSize || sender.mNoiseVecSize || sender.mNumPartitions ||
		sender.mSizePer || sender.mSecParam || sender.mCodeSeed != ZeroBlock ||
		!sender.mB.empty() || !sender.mBaseB.empty() || sender.mDerandomizeMalCheck)
		throw RTE_LOC;

	if (receiver.mState != Receiver::State::Default || receiver.isConfigured() ||
		receiver.mNoiseType != SdNoiseDistribution::Regular ||
		receiver.mRequestSize || receiver.mNoiseVecSize || receiver.mNumPartitions ||
		receiver.mSizePer || receiver.mSecParam || receiver.mCodeSeed != ZeroBlock ||
		!receiver.mA.empty() || !receiver.mC.empty() || !receiver.mBaseA.empty() ||
		!receiver.mBaseC.empty() || receiver.mMalCheckSeed.has_value() ||
		receiver.mDerandomizeMalCheck)
		throw RTE_LOC;

	PRNG failurePrng(CCBlock);
	Sender failedSender;
	failedSender.configure(128, SilentSecType::Malicious, DefaultMultType,
		SilentBaseType::BaseExtend, SdNoiseDistribution::Stationary);
	auto failedSenderCount = failedSender.baseCount();
	std::vector<std::array<block, 2>> failedSendBase(
		failedSenderCount.mBaseOtCount);
	Sender::VecF failedBaseB(failedSenderCount.mBaseVoleCount);
	failurePrng.get(failedSendBase.data(), failedSendBase.size());
	failurePrng.get(failedBaseB.data(), failedBaseB.size());
	failedSender.setBaseCors(failedSendBase, failedBaseB);
	auto failedSenderSockets = cp::LocalAsyncSocket::makePair();
	macoro::sync_wait(failedSenderSockets[1].close());
	bool failedSenderThrew = false;
	try
	{
		macoro::sync_wait(failedSender.silentSendInplace(
			failurePrng.get<block>(), 128, failurePrng, failedSenderSockets[0]));
	}
	catch (const std::exception&)
	{
		failedSenderThrew = true;
	}
	if (!failedSenderThrew || failedSender.isConfigured() ||
		failedSender.hasBaseCors() || !failedSender.mBaseB.empty())
		throw UnitTestFail("failed Silent VOLE sender retained correlations");

	Receiver failedReceiver;
	failedReceiver.configure(128, SilentSecType::Malicious, DefaultMultType,
		SilentBaseType::BaseExtend, SdNoiseDistribution::Stationary);
	auto failedReceiverCount = failedReceiver.baseCount();
	auto failedChoices = failedReceiver.sampleBaseChoiceBits(failurePrng);
	std::vector<block> failedRecvBase(failedReceiverCount.mBaseOtCount);
	Receiver::VecF failedBaseA(failedReceiverCount.mBaseVoleCount);
	Receiver::VecG failedBaseC(failedReceiverCount.mBaseVoleCount);
	failurePrng.get(failedRecvBase.data(), failedRecvBase.size());
	failurePrng.get(failedBaseA.data(), failedBaseA.size());
	failurePrng.get(failedBaseC.data(), failedBaseC.size());
	failedReceiver.setBaseCors(
		failedChoices, failedRecvBase, failedBaseA, failedBaseC);
	auto failedReceiverSockets = cp::LocalAsyncSocket::makePair();
	macoro::sync_wait(failedReceiverSockets[1].close());
	bool failedReceiverThrew = false;
	try
	{
		macoro::sync_wait(failedReceiver.silentReceiveInplace(
			128, failurePrng, failedReceiverSockets[0]));
	}
	catch (const std::exception&)
	{
		failedReceiverThrew = true;
	}
	if (!failedReceiverThrew || failedReceiver.isConfigured() ||
		failedReceiver.hasBaseCors() || !failedReceiver.mBaseA.empty() ||
		!failedReceiver.mBaseC.empty())
		throw UnitTestFail("failed Silent VOLE receiver retained correlations");

	using Product = FVec<Fp31, 2>;
	SilentVoleSender<Product> productSender;
	SilentVoleReceiver<Product> productReceiver;
	productSender.configure(128, SilentSecType::SemiHonest, DefaultMultType,
		SilentBaseType::Base, SdNoiseDistribution::Stationary);
	productReceiver.configure(128, SilentSecType::SemiHonest, DefaultMultType,
		SilentBaseType::Base, SdNoiseDistribution::Stationary);
	const auto productConfig = syndromeDecodingConfigure(
		128, 128, DefaultMultType, SdNoiseDistribution::Stationary,
		SdNoiseSecurityModel{
			coefficientRegularNoiseFactor<Product>(CoeffCtxFVec<Fp31, 2>{}) });
	if (productSender.mNumPartitions != productConfig.mNumPartitions ||
		productSender.mSizePer != productConfig.mSizePer ||
		productSender.mNoiseVecSize != productConfig.mNoiseVectorSize ||
		productReceiver.mNumPartitions != productConfig.mNumPartitions ||
		productReceiver.mSizePer != productConfig.mSizePer ||
		productReceiver.mNoiseVecSize != productConfig.mNoiseVectorSize)
		throw UnitTestFail(
			"Silent VOLE used binary-group parameters for an odd-characteristic product group");

	SilentVoleSender<Goldilocks> goldSender;
	goldSender.configure(128, SilentSecType::SemiHonest, DefaultMultType,
		SilentBaseType::Base, SdNoiseDistribution::Stationary);
	const auto goldConfig = syndromeDecodingConfigure(
		128, 128, DefaultMultType, SdNoiseDistribution::Stationary,
		SdNoiseSecurityModel{ coefficientRegularNoiseFactor<Goldilocks>(
			CoeffCtxGoldilocks{}) });
	if (goldSender.mNumPartitions != goldConfig.mNumPartitions ||
		goldSender.mSizePer != goldConfig.mSizePer ||
		goldSender.mNoiseVecSize != goldConfig.mNoiseVectorSize)
		throw UnitTestFail("Silent VOLE misclassified the Goldilocks additive group");
}

void Vole_Silent_NoiseSampling_test(const oc::CLP&)
{
	const auto binaryLarge = getRegNoiseWeight(
		0.25, 4096, 128, SdNoiseDistribution::Regular,
		SdNoiseSecurityModel::binary());
	const auto binarySmall = getRegNoiseWeight(
		0.25, 2048, 128, SdNoiseDistribution::Regular,
		SdNoiseSecurityModel::binary());
	const auto f9Regular = getRegNoiseWeight(
		0.25, 4096, 128, SdNoiseDistribution::Regular,
		SdNoiseSecurityModel{ 9.0 / 8.0 });
	const auto largeFieldRegular = getRegNoiseWeight(
		0.25, 4096, 128, SdNoiseDistribution::Regular,
		SdNoiseSecurityModel{ 1.0 });
	const auto stationaryWeight = getRegNoiseWeight(
		0.25, 4096, 128, SdNoiseDistribution::Stationary,
		SdNoiseSecurityModel::binary());
	if (binaryLarge != 128 || binarySmall != 144 || f9Regular != 136 ||
		largeFieldRegular != 160 || stationaryWeight != 160)
		throw UnitTestFail("Silent-noise security floors selected an unexpected weight");

	PRNG prng(CCBlock);
	CoeffCtxInteger integerCtx;
	for (u64 i = 0; i < 256; ++i)
	{
		u64 value;
		sampleRegularNoiseUnit(value, prng, integerCtx);
		if ((value & 1) == 0 || !isRegularNoiseUnit(value, integerCtx))
			throw UnitTestFail("Regular integer noise was not sampled from the units");
	}

	using Product = FVec<Fp31, 2>;
	CoeffCtxFVec<Fp31, 2> productCtx;
	for (u64 i = 0; i < 64; ++i)
	{
		Product value;
		sampleRegularNoiseUnit(value, prng, productCtx);
		if (value.v[0] == Fp31::zero() || value.v[1] == Fp31::zero() ||
			!isRegularNoiseUnit(value, productCtx))
			throw UnitTestFail("Regular product-ring noise contained a nonunit lane");
	}

	SilentVoleReceiver<u64> regular;
	SilentVoleReceiver<u64> stationary;
	regular.configure(1024, SilentSecType::SemiHonest, DefaultMultType,
		SilentBaseType::Base, SdNoiseDistribution::Regular);
	stationary.configure(1024, SilentSecType::SemiHonest, DefaultMultType,
		SilentBaseType::Base, SdNoiseDistribution::Stationary);
	if (regular.mNoiseType != SdNoiseDistribution::Regular ||
		stationary.mNoiseType != SdNoiseDistribution::Stationary ||
		stationary.mNumPartitions <= regular.mNumPartitions)
		throw UnitTestFail("Stationary integer noise did not receive the larger weight");

	const auto count = regular.baseCount();
	auto choices = regular.sampleBaseChoiceBits(prng);
	std::vector<block> recvBaseOts(count.mBaseOtCount);
	SilentVoleReceiver<u64>::VecF baseA(count.mBaseVoleCount);
	SilentVoleReceiver<u64>::VecG baseC(count.mBaseVoleCount);
	prng.get(recvBaseOts.data(), recvBaseOts.size());
	prng.get(baseA.data(), baseA.size());
	for (u64 i = 0; i < regular.mNumPartitions; ++i)
		sampleRegularNoiseUnit(baseC[i], prng, integerCtx);
	baseC[0] = 2;

	bool rejected = false;
	try
	{
		regular.setBaseCors(choices, recvBaseOts, baseA, baseC);
	}
	catch (const std::invalid_argument&)
	{
		rejected = true;
	}
	if (!rejected || regular.mState != SilentVoleReceiver<u64>::State::Configured)
		throw UnitTestFail("Regular silent VOLE accepted a nonunit base coefficient");

	baseC[0] = 3;
	regular.setBaseCors(choices, recvBaseOts, baseA, baseC);
	if (!regular.hasBaseCors())
		throw UnitTestFail("Regular silent VOLE rejected valid unit coefficients");
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

#if defined ENABLE_SIMPLESTOT
				u64 expRound = 3;
				baseName = "using DefaultBaseOT = SimplestOT;";
#elif defined ENABLE_MRR_TWIST && defined ENABLE_SSE
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
void Vole_Noisy_Audit_Test(const oc::CLP& cmd) { throwDisabled(); }
void Vole_Silent_QuasiCyclic_test(const oc::CLP& cmd) { throwDisabled(); }
void Vole_Silent_paramSweep_test(const oc::CLP& cmd) { throwDisabled(); }
void Vole_Silent_defaultMatrixRank_test(const oc::CLP& cmd) { throwDisabled(); }
void Vole_Silent_baseOT_test(const oc::CLP& cmd) { throwDisabled(); }
void Vole_Silent_mal_test(const oc::CLP& cmd) { throwDisabled(); }
void Vole_Silent_malBase_test(const oc::CLP& cmd) { throwDisabled(); }
void Vole_Silent_Clear_test(const oc::CLP& cmd) { throwDisabled(); }
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

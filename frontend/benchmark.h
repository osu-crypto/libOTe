#pragma once
#include "cryptoTools/Common/CLP.h"
#include "cryptoTools/Common/Aligned.h"
#include <chrono>
#include "libOTe/Tools/Tools.h"

#include "libOTe/Tools/EACode/EACode.h"
#include "libOTe/Tools/ExConvCode/ExConvCode.h"
#include "libOTe/Tools/QuasiCyclicCode.h"

#include "libOTe/TwoChooseOne/Silent/SilentOtExtReceiver.h"
#include "libOTe/TwoChooseOne/Silent/SilentOtExtSender.h"
#include "libOTe/Vole/Silent/SilentVoleSender.h"
#include "libOTe/Vole/Silent/SilentVoleReceiver.h"
#include "libOTe/Tools/CoeffCtx.h"
#include "libOTe/Tools/TungstenCode/TungstenCode.h"
#include "libOTe/Tools/ExConvCodeOld/ExConvCodeOld.h"
#include "libOTe/Dpf/RegularDpf.h"
#include "libOTe/Dpf/TernaryDpf.h"
#include "libOTe/Triple/Foleage/FoleageTriple.h"
#include "libOTe/Triple/SilentOtTriple/SilentOtTriple.h"
#include "libOTe/Dpf/RevCuckooDmpf.h"
#include "libOTe/Dpf/SumDmpf.h"
#include "libOTe/Tools/Ntt/NttNegWrap.h"
#include "libOTe/Triple/RingLpn/RingLpnTriple.h"
#include "libOTe/Tools/Field/Fp.h"
#include "libOTe/Dpf/RevCuckoo/WaksmanPermute.h"
#include "libOTe/Tools/Field/Goldilocks.h"

namespace osuCrypto
{


	inline void QCCodeBench(CLP& cmd)
	{

#ifdef ENABLE_BITPOLYMUL
		u64 trials = cmd.getOr("t", 10);

		// the message length of the code. 
		// The noise vector will have size n=2*k.
		// the user can use 
		//   -k X 
		// to state that exactly X rows should be used or
		//   -kk X
		// to state that 2^X rows should be used.
		u64 k = cmd.getOr("k", 1ull << cmd.getOr("kk", 10));

		u64 n = k * 2;

		// verbose flag.


		oc::Timer timer;
		QuasiCyclicCode code;
		code.init2(k, n);
		std::vector<block> c0(code.size(), ZeroBlock);
		for (auto t = 0ull; t < trials; ++t)
		{

			timer.setTimePoint("reset");
			code.dualEncode(c0);
			timer.setTimePoint("encode");
		}



		if (!cmd.isSet("quiet"))
			std::cout << timer << std::endl;
#endif
	}

	inline void EACodeBench(CLP& cmd)
	{
		u64 trials = cmd.getOr("t", 10);

		// the message length of the code. 
		// The noise vector will have size n=2*k.
		// the user can use 
		//   -k X 
		// to state that exactly X rows should be used or
		//   -kk X
		// to state that 2^X rows should be used.
		u64 k = cmd.getOr("k", 1ull << cmd.getOr("kk", 10));

		u64 n = cmd.getOr<u64>("n", k * cmd.getOr("R", 5.0));

		// the weight of the code
		u64 w = cmd.getOr("w", 7);

		// size for the accumulator (# random transitions)

		// verbose flag.
		bool v = cmd.isSet("v");


		EACode code;
		code.config(k, n, w);

		if (v)
		{
			std::cout << "n: " << code.mCodeSize << std::endl;
			std::cout << "k: " << code.mMessageSize << std::endl;
			std::cout << "w: " << code.mExpanderWeight << std::endl;
		}

		std::vector<block> x(code.mCodeSize), y(code.mMessageSize);
		Timer timer, verbose;

		if (v)
			code.setTimer(verbose);

		timer.setTimePoint("_____________________");
		for (u64 i = 0; i < trials; ++i)
		{
			code.dualEncode<block, CoeffCtxGF128>(x, y, {});
			timer.setTimePoint("encode");
		}

		std::cout << "EA " << std::endl;
		std::cout << timer << std::endl;

		if (v)
			std::cout << verbose << std::endl;
	}

	inline void ExConvCodeBench(CLP& cmd)
	{
		u64 trials = cmd.getOr("t", 10);

		// the message length of the code. 
		// The noise vector will have size n=2*k.
		// the user can use 
		//   -k X 
		// to state that exactly X rows should be used or
		//   -kk X
		// to state that 2^X rows should be used.
		u64 k = cmd.getOr("k", 1ull << cmd.getOr("kk", 10));

		u64 n = cmd.getOr<u64>("n", k * cmd.getOr("R", 2.0));

		// the weight of the code
		u64 w = cmd.getOr("w", 7);

		// size for the accumulator (# random transitions)
		u64 a = cmd.getOr("a", roundUpTo(log2ceil(n), 8));

		bool gf128 = cmd.isSet("gf128");

		// verbose flag.
		bool v = cmd.isSet("v");
		bool sys = cmd.isSet("sys");

		ExConvCode code;
		code.config(k, n, w, a, sys);

		if (v)
		{
			std::cout << "n: " << code.mCodeSize << std::endl;
			std::cout << "k: " << code.mMessageSize << std::endl;
			//std::cout << "w: " << code.mExpanderWeight << std::endl;
		}

		std::vector<block> x(code.mCodeSize), y(code.mMessageSize * !sys);
		Timer timer, verbose;

		if (v)
			code.setTimer(verbose);

		timer.setTimePoint("_____________________");
		for (u64 i = 0; i < trials; ++i)
		{
			if (gf128)
				code.dualEncode<block, CoeffCtxGF128>(x.begin(), {});
			else
				code.dualEncode<block, CoeffCtxGF2>(x.begin(), {});

			timer.setTimePoint("encode");
		}

		std::cout << "EC " << std::endl;
		std::cout << timer << std::endl;

		if (v)
			std::cout << verbose << std::endl;
	}

	inline void ExConvCodeOldBench(CLP& cmd)
	{
#ifdef LIBOTE_ENABLE_OLD_EXCONV

		u64 trials = cmd.getOr("t", 10);

		// the message length of the code. 
		// The noise vector will have size n=2*k.
		// the user can use 
		//   -k X 
		// to state that exactly X rows should be used or
		//   -kk X
		// to state that 2^X rows should be used.
		u64 k = cmd.getOr("k", 1ull << cmd.getOr("kk", 10));

		u64 n = cmd.getOr<u64>("n", k * cmd.getOr("R", 2.0));

		// the weight of the code
		u64 w = cmd.getOr("w", 7);

		// size for the accumulator (# random transitions)
		u64 a = cmd.getOr("a", roundUpTo(log2ceil(n), 8));

		bool gf128 = cmd.isSet("gf128");

		// verbose flag.
		bool v = cmd.isSet("v");
		bool sys = cmd.isSet("sys");

		ExConvCodeOld code;
		code.config(k, n, w, a, sys);

		if (v)
		{
			std::cout << "n: " << code.mCodeSize << std::endl;
			std::cout << "k: " << code.mMessageSize << std::endl;
			//std::cout << "w: " << code.mExpanderWeight << std::endl;
		}

		std::vector<block> x(code.mCodeSize), y(code.mMessageSize * !sys);
		Timer timer, verbose;

		if (v)
			code.setTimer(verbose);

		timer.setTimePoint("_____________________");
		for (u64 i = 0; i < trials; ++i)
		{
			code.dualEncode<block>(x);

			timer.setTimePoint("encode");
		}

		if (cmd.isSet("quiet") == false)
		{
			std::cout << "EC " << std::endl;
			std::cout << timer << std::endl;
		}
		if (v)
			std::cout << verbose << std::endl;
#else
		std::cout << "LIBOTE_ENABLE_OLD_EXCONV = false" << std::endl;
#endif
	}


	inline void PprfBench(CLP& cmd)
	{

#ifdef ENABLE_SILENTOT

		try
		{
			using Ctx = CoeffCtxGF2;
			RegularPprfReceiver<block, block, Ctx> recver;
			RegularPprfSender<block, block, Ctx> sender;

			u64 trials = cmd.getOr("t", 10);

			u64 w = cmd.getOr("w", 32);
			u64 n = cmd.getOr("n", 1ull << cmd.getOr("nn", 14));

			PRNG prng0(ZeroBlock), prng1(ZeroBlock);
			//block delta = prng0.get();

			auto sock = coproto::LocalAsyncSocket::makePair();

			Timer rTimer;
			auto s = rTimer.setTimePoint("start");
			auto ctx = Ctx{};
			auto vals = Ctx::Vec<block>(w);
			auto out0 = Ctx::Vec<block>(n / w * w);
			auto out1 = Ctx::Vec<block>(n / w * w);



			for (u64 t = 0; t < trials; ++t)
			{
				sender.configure(n / w, w);
				recver.configure(n / w, w);

				std::vector<std::array<block, 2>> baseSend(sender.baseOtCount());
				std::vector<block> baseRecv(sender.baseOtCount());
				BitVector baseChoice(sender.baseOtCount());
				sender.setBase(baseSend);
				recver.setBase(baseRecv);
				recver.setChoiceBits(baseChoice);

				auto p0 = sender.expand(sock[0], vals, prng0.get(), out0, PprfOutputFormat::Interleaved, true, 1, ctx);
				auto p1 = recver.expand(sock[1], out1, PprfOutputFormat::Interleaved, true, 1, ctx);

				rTimer.setTimePoint("r start");
				coproto::sync_wait(macoro::when_all_ready(
					std::move(p0), std::move(p1)));
				rTimer.setTimePoint("r done");

			}
			auto e = rTimer.setTimePoint("end");

			auto time = std::chrono::duration_cast<std::chrono::milliseconds>(e - s).count();
			auto avgTime = time / double(trials);
			auto timePer512 = avgTime / n * 512;
			std::cout << "OT n:" << n << ", " <<
				avgTime << "ms/batch, " << timePer512 << "ms/512ot" << std::endl;

			std::cout << rTimer << std::endl;

			std::cout << sock[0].bytesReceived() / trials << " " << sock[1].bytesReceived() / trials << " bytes per " << std::endl;
		}
		catch (std::exception& e)
		{
			std::cout << e.what() << std::endl;
		}
#else
		std::cout << "ENABLE_SILENTOT = false" << std::endl;
#endif
	}

	inline void TungstenCodeBench(CLP& cmd)
	{
		u64 trials = cmd.getOr("t", 10);

		// the message length of the code. 
		// The noise vector will have size n=2*k.
		// the user can use 
		//   -k X 
		// to state that exactly X rows should be used or
		//   -kk X
		// to state that 2^X rows should be used.
		u64 k = cmd.getOr("k", 1ull << cmd.getOr("kk", 10));

		u64 n = cmd.getOr<u64>("n", k * cmd.getOr("R", 2.0));

		// verbose flag.
		bool v = cmd.isSet("v");

		experimental::TungstenCode code;
		code.config(k, n);
		code.mNumIter = cmd.getOr("iter", 2);

		if (v)
		{
			std::cout << "n: " << code.mCodeSize << std::endl;
			std::cout << "k: " << code.mMessageSize << std::endl;
		}

		AlignedUnVector<block> x(code.mCodeSize);
		Timer timer, verbose;


		timer.setTimePoint("_____________________");
		for (u64 i = 0; i < trials; ++i)
		{
			code.dualEncode<block, CoeffCtxGF2>(x.data(), {});

			timer.setTimePoint("encode");
		}

		if (cmd.isSet("quiet") == false)
		{
			std::cout << "tungsten " << std::endl;
			std::cout << timer << std::endl;
		}
		if (v)
			std::cout << verbose << std::endl;
	}


	inline void transpose(const CLP& cmd)
	{
#ifdef ENABLE_AVX
		u64 trials = cmd.getOr("trials", 1ull << 18);
		{

			AlignedArray<block, 128> data;

			Timer timer;
			auto start0 = timer.setTimePoint("b");

			for (u64 i = 0; i < trials; ++i)
			{
				avx_transpose128(data.data());
			}

			auto end0 = timer.setTimePoint("b");


			for (u64 i = 0; i < trials; ++i)
			{
				sse_transpose128(data.data());
			}

			auto end1 = timer.setTimePoint("b");

			std::cout << "avx " << std::chrono::duration_cast<std::chrono::milliseconds>(end0 - start0).count() << std::endl;
			std::cout << "sse " << std::chrono::duration_cast<std::chrono::milliseconds>(end1 - end0).count() << std::endl;
		}

		{
			AlignedArray<block, 1024> data;

			Timer timer;
			auto start1 = timer.setTimePoint("b");

			for (u64 i = 0; i < trials * 8; ++i)
			{
				avx_transpose128(data.data());
			}


			auto start0 = timer.setTimePoint("b");

			for (u64 i = 0; i < trials; ++i)
			{
				avx_transpose128x1024(data.data());
			}

			auto end0 = timer.setTimePoint("b");


			for (u64 i = 0; i < trials; ++i)
			{
				sse_transpose128x1024(*(std::array<std::array<block, 8>, 128>*)data.data());
			}

			auto end1 = timer.setTimePoint("b");

			std::cout << "avx " << std::chrono::duration_cast<std::chrono::milliseconds>(start0 - start1).count() << std::endl;
			std::cout << "avx " << std::chrono::duration_cast<std::chrono::milliseconds>(end0 - start0).count() << std::endl;
			std::cout << "sse " << std::chrono::duration_cast<std::chrono::milliseconds>(end1 - end0).count() << std::endl;
		}
#endif
	}


	inline void SilentOtBench(const CLP& cmd)
	{
#ifdef ENABLE_SILENTOT

		try
		{

			SilentOtExtSender sender;
			SilentOtExtReceiver recver;

			u64 trials = cmd.getOr("t", 10);

			u64 n = cmd.getOr("n", 1ull << cmd.getOr("nn", 20));
			MultType multType = (MultType)cmd.getOr("m", (int)MultType::ExConv7x24);
			std::cout << multType << std::endl;

			recver.mMultType = multType;
			sender.mMultType = multType;

			PRNG prng0(ZeroBlock), prng1(ZeroBlock);
			block delta = prng0.get();

			auto sock = coproto::LocalAsyncSocket::makePair();

			Timer sTimer;
			Timer rTimer;
			recver.setTimer(rTimer);
			sender.setTimer(rTimer);
			sTimer.setTimePoint("start");
			auto s = sTimer.setTimePoint("start");

			macoro::thread_pool pool0, pool1;
			auto w0 = pool0.make_work();
			auto w1 = pool1.make_work();
			pool0.create_thread();
			pool1.create_thread();

			for (u64 t = 0; t < trials; ++t)
			{
				sender.configure(n);
				recver.configure(n);

				auto choice = recver.sampleBaseChoiceBits(prng0);
				std::vector<std::array<block, 2>> sendBase(sender.silentBaseOtCount());
				std::vector<block> recvBase(recver.silentBaseOtCount());
				sender.setSilentBaseOts(sendBase);
				recver.setSilentBaseOts(recvBase);

				auto p0 = sender.silentSendInplace(delta, n, prng0, sock[0]);
				auto p1 = recver.silentReceiveInplace(n, prng1, sock[1], ChoiceBitPacking::True);

				rTimer.setTimePoint("r start");
				if (cmd.isSet("mt"))
				{
					sock[0].setExecutor(pool0);
					sock[1].setExecutor(pool1);
					coproto::sync_wait(macoro::when_all_ready(
						std::move(p0) | macoro::start_on(pool0),
						std::move(p1) | macoro::start_on(pool1)));
				}
				else
				{
					coproto::sync_wait(macoro::when_all_ready(
						std::move(p0),
						std::move(p1)));

				}
				rTimer.setTimePoint("r done");

			}
			auto e = rTimer.setTimePoint("end");

			if (cmd.isSet("quiet") == false)
			{

				auto time = std::chrono::duration_cast<std::chrono::milliseconds>(e - s).count();
				auto avgTime = time / double(trials);
				auto timePer512 = avgTime / n * 512;
				std::cout << "OT n:" << n << ", " <<
					avgTime << "ms/batch, " << timePer512 << "ms/512ot" << std::endl;

				std::cout << sTimer << std::endl;
				std::cout << rTimer << std::endl;

				std::cout << sock[0].bytesReceived() / trials << " " << sock[1].bytesReceived() / trials << " bytes per " << std::endl;
			}
		}
		catch (std::exception& e)
		{
			std::cout << e.what() << std::endl;
		}
#else
		std::cout << "ENABLE_SILENTOT = false" << std::endl;
#endif
	}

	inline void VoleBench2(const CLP& cmd)
	{
#ifdef ENABLE_SILENT_VOLE
		try
		{

			SilentVoleSender<block, block, CoeffCtxGF128> sender;
			SilentVoleReceiver<block, block, CoeffCtxGF128> recver;

			u64 trials = cmd.getOr("t", 10);

			u64 n = cmd.getOr("n", 1ull << cmd.getOr("nn", 20));
			MultType multType = (MultType)cmd.getOr("m", (int)MultType::ExConv7x24);
			std::cout << multType << std::endl;

			recver.mMultType = multType;
			sender.mMultType = multType;

			std::vector<std::array<block, 2>> baseSend(128);
			std::vector<block> baseRecv(128);
			BitVector baseChoice(128);
			PRNG prng(CCBlock);
			baseChoice.randomize(prng);
			for (u64 i = 0; i < 128; ++i)
			{
				baseSend[i] = prng.get();
				baseRecv[i] = baseSend[i][baseChoice[i]];
			}

#ifdef ENABLE_SOFTSPOKEN_OT
			sender.mOtExtRecver.emplace();
			sender.mOtExtSender.emplace();
			recver.mOtExtRecver.emplace();
			recver.mOtExtSender.emplace();
			sender.mOtExtRecver->setBaseOts(baseSend);
			recver.mOtExtRecver->setBaseOts(baseSend);
			sender.mOtExtSender->setBaseOts(baseRecv, baseChoice);
			recver.mOtExtSender->setBaseOts(baseRecv, baseChoice);
#endif // ENABLE_SOFTSPOKEN_OT

			PRNG prng0(ZeroBlock), prng1(ZeroBlock);
			block delta = prng0.get();

			auto sock = coproto::LocalAsyncSocket::makePair();

			Timer sTimer;
			Timer rTimer;
			sTimer.setTimePoint("start");
			rTimer.setTimePoint("start");

			auto t0 = std::thread([&] {
				for (u64 t = 0; t < trials; ++t)
				{
					auto p0 = sender.silentSendInplace(delta, n, prng0, sock[0]);

					char c = 0;

					coproto::sync_wait(sock[0].send(std::move(c)));
					coproto::sync_wait(sock[0].recv(c));
					sTimer.setTimePoint("__");
					coproto::sync_wait(sock[0].send(std::move(c)));
					coproto::sync_wait(sock[0].recv(c));
					sTimer.setTimePoint("s start");
					coproto::sync_wait(p0);
					sTimer.setTimePoint("s done");
				}
				});


			for (u64 t = 0; t < trials; ++t)
			{
				auto p1 = recver.silentReceiveInplace(n, prng1, sock[1]);
				char c = 0;
				coproto::sync_wait(sock[1].send(std::move(c)));
				coproto::sync_wait(sock[1].recv(c));

				rTimer.setTimePoint("__");
				coproto::sync_wait(sock[1].send(std::move(c)));
				coproto::sync_wait(sock[1].recv(c));

				rTimer.setTimePoint("r start");
				coproto::sync_wait(p1);
				rTimer.setTimePoint("r done");

			}


			t0.join();
			std::cout << sTimer << std::endl;
			std::cout << rTimer << std::endl;

			std::cout << sock[0].bytesReceived() / trials << " " << sock[1].bytesReceived() / trials << " bytes per " << std::endl;
		}
		catch (std::exception& e)
		{
			std::cout << e.what() << std::endl;
		}
#else
		std::cout << "ENABLE_Silent_VOLE = false" << std::endl;
#endif
	}


	void AESBenchmark(const oc::CLP& cmd)
	{
		u64 n = roundUpTo(cmd.getOr("n", 1ull << cmd.getOr("nn", 20)), 8);
		u64 t = cmd.getOr("t", 10);
		using AES_ = AES;// details::AES<details::AESTypes::Portable>;

		auto unroll8 = [](AES_& aes, block* __restrict s)
			{
				block b[8];
				b[0] = AES_::firstFn(s[0], aes.mRoundKey[0]);
				b[1] = AES_::firstFn(s[1], aes.mRoundKey[0]);
				b[2] = AES_::firstFn(s[2], aes.mRoundKey[0]);
				b[3] = AES_::firstFn(s[3], aes.mRoundKey[0]);
				b[4] = AES_::firstFn(s[4], aes.mRoundKey[0]);
				b[5] = AES_::firstFn(s[5], aes.mRoundKey[0]);
				b[6] = AES_::firstFn(s[6], aes.mRoundKey[0]);
				b[7] = AES_::firstFn(s[7], aes.mRoundKey[0]);

				for (u64 i = 1; i < 9; ++i)
				{
					b[0] = AES_::roundFn(b[0], aes.mRoundKey[i]);
					b[1] = AES_::roundFn(b[1], aes.mRoundKey[i]);
					b[2] = AES_::roundFn(b[2], aes.mRoundKey[i]);
					b[3] = AES_::roundFn(b[3], aes.mRoundKey[i]);
					b[4] = AES_::roundFn(b[4], aes.mRoundKey[i]);
					b[5] = AES_::roundFn(b[5], aes.mRoundKey[i]);
					b[6] = AES_::roundFn(b[6], aes.mRoundKey[i]);
					b[7] = AES_::roundFn(b[7], aes.mRoundKey[i]);
				}


				b[0] = AES_::penultimateFn(b[0], aes.mRoundKey[9]);
				b[1] = AES_::penultimateFn(b[1], aes.mRoundKey[9]);
				b[2] = AES_::penultimateFn(b[2], aes.mRoundKey[9]);
				b[3] = AES_::penultimateFn(b[3], aes.mRoundKey[9]);
				b[4] = AES_::penultimateFn(b[4], aes.mRoundKey[9]);
				b[5] = AES_::penultimateFn(b[5], aes.mRoundKey[9]);
				b[6] = AES_::penultimateFn(b[6], aes.mRoundKey[9]);
				b[7] = AES_::penultimateFn(b[7], aes.mRoundKey[9]);
				s[0] = AES_::finalFn(b[0], aes.mRoundKey[10]);
				s[1] = AES_::finalFn(b[1], aes.mRoundKey[10]);
				s[2] = AES_::finalFn(b[2], aes.mRoundKey[10]);
				s[3] = AES_::finalFn(b[3], aes.mRoundKey[10]);
				s[4] = AES_::finalFn(b[4], aes.mRoundKey[10]);
				s[5] = AES_::finalFn(b[5], aes.mRoundKey[10]);
				s[6] = AES_::finalFn(b[6], aes.mRoundKey[10]);
				s[7] = AES_::finalFn(b[7], aes.mRoundKey[10]);

			};

		oc::AlignedUnVector<block> x(n);
		AES_ aes(block(42352345, 3245345234676534));
		Timer timer;
		timer.setTimePoint("begin");
		for (u64 tt = 0; tt < t; ++tt)
		{
			for (u64 i = 0; i < n; i += 8)
			{
				unroll8(aes, x.data() + i);
			}
			timer.setTimePoint("unroll");
		}

		for (u64 tt = 0; tt < t; ++tt)
		{
			for (u64 i = 0; i < n; i += 8)
			{
				aes.ecbEncBlocks<8>(x.data() + i, x.data() + i);
			}
			timer.setTimePoint("aes <>");
		}

		for (u64 tt = 0; tt < t; ++tt)
		{
			aes.ecbEncBlocks(x, x);
			timer.setTimePoint("aes ");
		}

		std::cout << timer << std::endl;

	}

	void RegularDpfBenchmark(const oc::CLP& cmd)
	{
#ifdef ENABLE_REGULAR_DPF
		PRNG prng(block(231234, 321312));
		u64 trials = cmd.getOr("t", 100);
		u64 domain = 1ull << cmd.getOr("d", 10);
		u64 numPoints = cmd.getOr("p", 64);
		std::vector<u64> points0(numPoints);
		std::vector<u64> points1(numPoints);
		std::vector<block> values0(numPoints);
		std::vector<block> values1(numPoints);
		for (u64 i = 0; i < numPoints; ++i)
		{
			points1[i] = prng.get<u64>();
			points0[i] = (prng.get<u64>() % domain) ^ points1[i];
			values0[i] = prng.get();
			values1[i] = prng.get();
		}


		auto sock = coproto::LocalAsyncSocket::makePair();

		Timer timer;

		std::array<oc::RegularDpf<block>, 2> dpf;
		dpf[0].init(0, domain, numPoints);
		dpf[1].init(1, domain, numPoints);

		auto baseCount = dpf[0].baseOtCount();

		std::array<std::vector<block>, 2> baseRecv;
		std::array<std::vector<std::array<block, 2>>, 2> baseSend;
		std::array<BitVector, 2> baseChoice;
		baseRecv[0].resize(baseCount);
		baseRecv[1].resize(baseCount);
		baseSend[0].resize(baseCount);
		baseSend[1].resize(baseCount);
		baseChoice[0].resize(baseCount);
		baseChoice[1].resize(baseCount);
		baseChoice[0].randomize(prng);
		baseChoice[1].randomize(prng);
		for (u64 i = 0; i < baseCount; ++i)
		{
			baseSend[0][i] = prng.get();
			baseSend[1][i] = prng.get();
			baseRecv[0][i] = baseSend[1][i][baseChoice[0][i]];
			baseRecv[1][i] = baseSend[0][i][baseChoice[1][i]];
		}
		dpf[0].setBaseOts(baseSend[0], baseRecv[0], baseChoice[0]);
		dpf[1].setBaseOts(baseSend[1], baseRecv[1], baseChoice[1]);

		std::array<Matrix<block>, 2> output;
		output[0].resize(numPoints, domain);
		output[1].resize(numPoints, domain);

		for (u64 tt = 0; tt < trials; ++tt)
		{

			timer.setTimePoint("start");
			macoro::sync_wait(macoro::when_all_ready(
				dpf[0].expand(points0, values0, prng, sock[0], [&](auto k, auto i, auto v, auto t) { output[0](k, i) = v; }),
				dpf[1].expand(points1, values1, prng, sock[1], [&](auto k, auto i, auto v, auto t) { output[1](k, i) = v; })
			));
			timer.setTimePoint("finish");

			dpf[0].init(0, domain, numPoints);
			dpf[1].init(1, domain, numPoints);
			dpf[0].setBaseOts(baseSend[0], baseRecv[0], baseChoice[0]);
			dpf[1].setBaseOts(baseSend[1], baseRecv[1], baseChoice[1]);
		}

		if (cmd.isSet("v"))
			std::cout << timer << std::endl;
#else
		std::cout << "ENABLE_REGULAR_DPF = false" << std::endl;
#endif
	}


	void TernaryDpfBenchmark(const oc::CLP& cmd)
	{
#ifdef ENABLE_TERNARY_DPF
		using F = block;
		using Ctx = CoeffCtxGF2;
		Timer timer;

		PRNG prng(block(231234, 321312));
		u64 depth = cmd.getOr("depth", 3);
		u64 domain = ipow(3, depth) - 3;
		u64 numPoints = cmd.getOr("numPoints", 1000);
		u64 trials = cmd.getOr("trials", 1);

		std::vector<F3x32> points0(numPoints);
		std::vector<F3x32> points1(numPoints);
		std::vector<F3x32> points(numPoints);
		std::vector<F> values0(numPoints);
		std::vector<F> values1(numPoints);
		//Ctx ctx;
		for (u64 i = 0; i < numPoints; ++i)
		{
			points[i] = F3x32(prng.get<u64>() % domain);
			points1[i] = F3x32(prng.get<u64>() % domain);
			points0[i] = points[i] - points1[i];
			//std::cout << points[i] << " = " << points0[i] <<" + "<< points1[i] << std::endl;
			values0[i] = prng.get();
			values1[i] = prng.get();
			//ctx.minus(points0[i], points[i], points1[i];)
		}


		for (u64 i = 0; i < trials; ++i)
		{

			std::array<oc::TernaryDpf<F, Ctx>, 2> dpf;
			dpf[0].init(0, domain, numPoints);
			dpf[1].init(1, domain, numPoints);

			auto baseCount = dpf[0].baseOtCount();

			std::array<std::vector<block>, 2> baseRecv;
			std::array<std::vector<std::array<block, 2>>, 2> baseSend;
			std::array<BitVector, 2> baseChoice;
			baseRecv[0].resize(baseCount);
			baseRecv[1].resize(baseCount);
			baseSend[0].resize(baseCount);
			baseSend[1].resize(baseCount);
			baseChoice[0].resize(baseCount);
			baseChoice[1].resize(baseCount);
			baseChoice[0].randomize(prng);
			baseChoice[1].randomize(prng);
			for (u64 i = 0; i < baseCount; ++i)
			{
				baseSend[0][i] = prng.get();
				baseSend[1][i] = prng.get();
				baseRecv[0][i] = baseSend[1][i][baseChoice[0][i]];
				baseRecv[1][i] = baseSend[0][i][baseChoice[1][i]];
			}
			dpf[0].setBaseOts(baseSend[0], baseRecv[0], baseChoice[0]);
			dpf[1].setBaseOts(baseSend[1], baseRecv[1], baseChoice[1]);

			std::array<Matrix<F>, 2> output;
			//std::array<Matrix<u8>, 2> tags;
			output[0].resize(domain, numPoints, AllocType::Uninitialized);
			output[1].resize(domain, numPoints, AllocType::Uninitialized);
			//		tags[0].resize(numPoints, domain, AllocType::Uninitialized);
			//		tags[1].resize(numPoints, domain, AllocType::Uninitialized);

			auto sock = coproto::LocalAsyncSocket::makePair();

			timer.setTimePoint("beign");
			auto out0 = output[0].data();
			auto out1 = output[1].data();

			macoro::sync_wait(macoro::when_all_ready(
				dpf[0].expand(points0, values0, [&](auto k, auto i, auto v) { *out0++ = v; }, prng, sock[0]),
				dpf[1].expand(points1, values1, [&](auto k, auto i, auto v) { *out1++ = v; }, prng, sock[1])
			));
			timer.setTimePoint("end");
		}

		std::cout << timer << std::endl;
#else
		std::cout << "ENABLE_TERNARY_DPF = false" << std::endl;
#endif

	}




	// This test evaluates the full PCG.Expand for both parties and
	// checks correctness of the resulting OLE correlation.
	void FoleageBenchmark(const CLP& cmd)
	{
#ifdef ENABLE_FOLEAGE

		auto logn = cmd.getOr("nn", 10);
		u64 n = ipow(3, logn);
		auto blocks = divCeil(n, 128);
		//bool verbose = cmd.isSet("v");


		u64 trials = cmd.getOr("trials", 1);

		//PRNG prng(block(342342));
		PRNG prng0(block(2424523452345, 111124521521455324));
		PRNG prng1(block(6474567454546, 567546754674345444));
		Timer timer;

		macoro::thread_pool::work work;
		macoro::thread_pool pool(2, work);
		auto sock = coproto::LocalAsyncSocket::makePair();
		sock[0].setExecutor(pool);
		sock[1].setExecutor(pool);
		double tps = 0;

		for (u64 ii = 0; ii < trials; ++ii)
		{

			std::array<FoleageTriple, 2> oles;
			if (cmd.hasValue("t"))
				oles[0].mT = oles[1].mT = cmd.get<u64>("t");
			if (cmd.hasValue("c"))
				oles[0].mC = oles[1].mC = cmd.get<u64>("c");

			oles[0].init(0, n);
			oles[1].init(1, n);

			if (cmd.isSet("mockBase"))
			{
				auto otCount0 = oles[0].baseOtCount();
				auto otCount1 = oles[1].baseOtCount();
				if (otCount0.mRecvCount != otCount1.mSendCount ||
					otCount0.mSendCount != otCount1.mRecvCount)
					throw RTE_LOC;
				std::array<std::vector<std::array<block, 2>>, 2> baseSend;
				baseSend[0].resize(otCount0.mSendCount);
				baseSend[1].resize(otCount1.mSendCount);
				std::array<std::vector<block>, 2> baseRecv;
				std::array<BitVector, 2> baseChoice;

				for (u64 i = 0; i < 2; ++i)
				{
					prng0.get(baseSend[i].data(), baseSend[i].size());
					baseRecv[1 ^ i].resize(baseSend[i].size());
					baseChoice[1 ^ i].resize(baseSend[i].size());
					baseChoice[1 ^ i].randomize(prng0);
					for (u64 j = 0; j < baseSend[i].size(); ++j)
					{
						baseRecv[1 ^ i][j] = baseSend[i][j][baseChoice[1 ^ i][j]];
					}
				}

				oles[0].setBaseOts(baseSend[0], baseRecv[0], baseChoice[0]);
				oles[1].setBaseOts(baseSend[1], baseRecv[1], baseChoice[1]);
			}

			std::vector<block>
				Av0(blocks),
				Av1(blocks),
				Bv0(blocks),
				Bv1(blocks),
				Cv0(blocks),
				Cv1(blocks);

			oles[0].setTimer(timer);
			auto b = timer.setTimePoint("start");

			auto r = macoro::sync_wait(macoro::when_all_ready(
				oles[0].expand(Av0, Bv0, Cv0, prng0, sock[0]) | macoro::start_on(pool),
				oles[1].expand(Av1, Bv1, Cv1, prng1, sock[1]) | macoro::start_on(pool)));
			auto e = timer.setTimePoint("end");
			tps = double(n) / (std::chrono::duration_cast<std::chrono::milliseconds>(e - b).count() / 1000.0);
			std::get<0>(r).result();
			std::get<1>(r).result();

		}
		work = {};
		std::cout << "foleage triple n=" << n << ", log2=" << log2ceil(n)
			<< " triples/sec = " << u64(tps)
			<< "\n Time taken: \n" << timer << std::endl;
#else
		std::cout << "ENABLE_FOLEAGE = false" << std::endl;
#endif
	}



	void SilentOtTripleBenchmark(const CLP& cmd)
	{
#ifdef ENABLE_SILENTOT

		auto logn = cmd.getOr("nn", 10);
		u64 n = 1ull << logn;
		auto blocks = divCeil(n, 128);


		u64 trials = cmd.getOr("trials", 1);

		//PRNG prng(block(342342));
		PRNG prng0(block(2424523452345, 111124521521455324));
		PRNG prng1(block(6474567454546, 567546754674345444));
		Timer timer;

		macoro::thread_pool::work work;
		macoro::thread_pool pool(2, work);
		auto sock = coproto::LocalAsyncSocket::makePair();
		sock[0].setExecutor(pool);
		sock[1].setExecutor(pool);

		double tps = 0;
		for (u64 ii = 0; ii < trials; ++ii)
		{

			std::array<SilentOtTriple, 2> oles;

			oles[0].init(0, n);
			oles[1].init(1, n);

			if (cmd.hasValue("mult"))
				oles[0].mMultType = oles[1].mMultType = (MultType)cmd.get<u64>("mult");

			if (cmd.isSet("mockBase"))
			{
				auto otCount0 = oles[0].baseOtCount(prng0);
				auto otCount1 = oles[1].baseOtCount(prng0);
				std::array<std::vector<std::array<block, 2>>, 2> baseSend;
				baseSend[0].resize(otCount0.mSendCount);
				baseSend[1].resize(otCount1.mSendCount);
				std::array<std::vector<block>, 2> baseRecv;
				std::array<BitVector, 2> baseChoice
				{
					otCount0.mRecvChoice,
					otCount1.mRecvChoice
				};

				for (u64 i = 0; i < 2; ++i)
				{
					prng0.get(baseSend[i].data(), baseSend[i].size());
					baseRecv[1 ^ i].resize(baseSend[i].size());
					for (u64 j = 0; j < baseSend[i].size(); ++j)
					{
						baseRecv[1 ^ i][j] = baseSend[i][j][baseChoice[1 ^ i][j]];
					}
				}

				oles[0].setBaseOts(baseSend[0], baseRecv[0]);
				oles[1].setBaseOts(baseSend[1], baseRecv[1]);
			}

			std::vector<block>
				Av0(blocks),
				Av1(blocks),
				Bv0(blocks),
				Bv1(blocks),
				Cv0(blocks),
				Cv1(blocks);

			oles[0].setTimer(timer);

			auto b = timer.setTimePoint("start");
			auto r = macoro::sync_wait(macoro::when_all_ready(
				oles[0].expand(Av0, Bv0, Cv0, prng0, sock[0]) | macoro::start_on(pool),
				oles[1].expand(Av1, Bv1, Cv1, prng1, sock[1]) | macoro::start_on(pool)));
			auto e = timer.setTimePoint("end");
			tps = double(n) / (std::chrono::duration_cast<std::chrono::milliseconds>(e - b).count() / 1000.0);
			std::get<0>(r).result();
			std::get<1>(r).result();

		}
		work = {};
		std::cout << "SilentOTTriple n=" << n << ", log2=" << log2ceil(n)
			<< " triples/sec = " << u64(tps)
			<< "\n Time taken: \n" << timer << std::endl;
#else
		std::cout << "ENABLE_FOLEAGE = false" << std::endl;
#endif
	}


	template<typename F, typename CoeffCtx>
	void RevCuckoo_bench_impl(const oc::CLP& cmd)
	{
		// Initialize parameters
		PRNG prng(block(231234, 321312));
		u64 domain = cmd.getOr("domain", 1ull << cmd.getOr("dd", 12)); // Domain size
		u64 numPoints = cmd.getOr("numPoints", 16); // Number of points
		u64 numSets = cmd.getOr("numSets", 16 * 4); // Number of sets
		u64 numPartitions = cmd.getOr("numPartitions", 2); // Number of partitions
		u64 linearSecParam = cmd.getOr("linearSecParam", 40); // Security parameter
		u64 cuckooSecParam = cmd.getOr("cuckooSecParam", 2); // Cuckoo security parameter
		u64 iterations = cmd.getOr("iters", 3); // Number of different value sets to test
		bool print = cmd.isSet("print"); // Print flag

		Timer timer[2];

		// Generate input points (fixed for all iterations)
		Matrix<u64> points0(numSets, numPoints);
		Matrix<u64> points1(numSets, numPoints);
		Matrix<u64> actualPoints(numSets, numPoints);
		for (u64 i = 0; i < points1.size(); ++i)
		{
			points1(i) = prng.get<u64>();
			points0(i) = (prng.get<u64>() % domain) ^ points1(i);
			actualPoints(i) = points0(i) ^ points1(i);
		}

		//auto ctx = CoeffCtx{};

		// Initialize RevCuckooDmpf instances
		std::array<RevCuckooDmpf<F>, 2> dpf;
		dpf[0].init(0, numPoints, numSets, domain, numPartitions, cuckooSecParam, linearSecParam);
		dpf[1].init(1, numPoints, numSets, domain, numPartitions, cuckooSecParam, linearSecParam);
		dpf[0].mPrint = print;
		dpf[1].mPrint = print;
		dpf[0].setTimer(timer[0]);
		dpf[1].setTimer(timer[1]);

		if (cmd.hasValue("print"))
		{
			dpf[0].mPrintIndex = cmd.getOr("print", 0);
			dpf[1].mPrintIndex = cmd.getOr("print", 0);
		}

		// Setup base OTs
		auto baseCount0 = dpf[0].baseOtCount();
		auto baseCount1 = dpf[1].baseOtCount();
		if (baseCount0.mSendCount != baseCount1.mRecvCount)
			throw RTE_LOC;
		if (baseCount1.mSendCount != baseCount0.mRecvCount)
			throw RTE_LOC;
		std::array<std::vector<block>, 2> baseRecv;
		std::array<std::vector<std::array<block, 2>>, 2> baseSend;
		std::array<BitVector, 2> baseChoice;
		baseRecv[0].resize(baseCount0.mRecvCount);
		baseRecv[1].resize(baseCount1.mRecvCount);
		baseSend[0].resize(baseCount0.mSendCount);
		baseSend[1].resize(baseCount1.mSendCount);
		baseChoice[0].resize(baseCount0.mRecvCount);
		baseChoice[1].resize(baseCount1.mRecvCount);
		baseChoice[0].randomize(prng);
		baseChoice[1].randomize(prng);
		for (u64 i = 0; i < baseCount0.mRecvCount; ++i)
		{
			baseSend[1][i] = prng.get();
			baseRecv[0][i] = baseSend[1][i][baseChoice[0][i]];
		}
		for (u64 i = 0; i < baseCount1.mRecvCount; ++i)
		{
			baseSend[0][i] = prng.get();
			baseRecv[1][i] = baseSend[0][i][baseChoice[1][i]];
		}
		dpf[0].setBaseOts(baseSend[0], baseRecv[0], baseChoice[0]);
		dpf[1].setBaseOts(baseSend[1], baseRecv[1], baseChoice[1]);

		// Create sockets for communication
		auto sock = coproto::LocalAsyncSocket::makePair();

		std::array<macoro::thread_pool, 2> threadPools;
		sock[0].setExecutor(threadPools[0]);
		sock[1].setExecutor(threadPools[1]);
		auto work0 = threadPools[0].make_work();
		auto work1 = threadPools[1].make_work();
		threadPools[0].create_thread();
		threadPools[1].create_thread();

		auto r = macoro::sync_wait(macoro::when_all_ready(
			dpf[0].setPoints(points0, prng, sock[0]) | macoro::start_on(threadPools[0]),
			dpf[1].setPoints(points1, prng, sock[1]) | macoro::start_on(threadPools[1])
		));
		std::get<0>(r).result();
		std::get<1>(r).result();

		// Phase 2: Multiple value expansions (called multiple times)
		for (u64 iteration = 0; iteration < iterations; ++iteration)
		{
			if (print)
			{
				std::cout << "Iteration " << iteration << " of " << iterations << std::endl;
			}

			// Generate different values for each iteration
			std::vector<F> values0(numPoints * numSets);
			std::vector<F> values1(numPoints * numSets);
			for (u64 i = 0; i < values1.size(); ++i)
			{
				values0[i] = prng.get();
				values1[i] = prng.get();
			}

			// Prepare output matrices for this iteration
			std::array<Matrix<F>, 2> output;
			output[0].resize(numSets, domain);
			output[1].resize(numSets, domain);

			// Expand values using the cached point setup
			auto r = macoro::sync_wait(macoro::when_all_ready(
				dpf[0].expand(values0, prng, sock[0], [&](auto j, auto i, auto v) { output[0](j, i) = v; }) | macoro::start_on(threadPools[0]),
				dpf[1].expand(values1, prng, sock[1], [&](auto j, auto i, auto v) { output[1](j, i) = v; }) | macoro::start_on(threadPools[1])
			));
			std::get<0>(r).result();
			std::get<1>(r).result();
		}


		for (u64 i = 0; i < 2; ++i)
		{
			std::cout << "Dpf " << i << " time: \n" << timer[i] << std::endl;
		}
	}

	void RevCuckooBench(const oc::CLP& cmd)
	{
		if (cmd.isSet("block"))
			RevCuckoo_bench_impl<block, CoeffCtxGF128>(cmd);
		else
			RevCuckoo_bench_impl<u64, CoeffCtxInteger>(cmd);
	}





	template<typename F, typename CoeffCtx>
	void SumDmpf_bench_impl(const oc::CLP& cmd)
	{
		// Initialize parameters
		PRNG prng(block(231234, 321312));
		u64 domain = cmd.getOr("domain", 1ull << cmd.getOr("dd", 12)); // Domain size
		u64 numPoints = cmd.getOr("numPoints", 16); // Number of points
		u64 numSets = cmd.getOr("numSets", 16 * 4); // Number of sets
		u64 iterations = cmd.getOr("iters", 3); // Number of different value sets to test
		bool print = cmd.isSet("print"); // Print flag

		Timer timer[2];

		// Generate input points (fixed for all iterations)
		Matrix<u64> points0(numSets, numPoints);
		Matrix<u64> points1(numSets, numPoints);
		Matrix<u64> actualPoints(numSets, numPoints);
		for (u64 i = 0; i < points1.size(); ++i)
		{
			points1(i) = prng.get<u64>();
			points0(i) = (prng.get<u64>() % domain) ^ points1(i);
			actualPoints(i) = points0(i) ^ points1(i);
		}

		//auto ctx = CoeffCtx{};

		// Initialize RevCuckooDmpf instances
		std::array<SumDmpf<F>, 2> dpf;
		dpf[0].init(0, domain, numPoints, numSets);
		dpf[1].init(1, domain, numPoints, numSets);
		//dpf[0].mPrint = print;
		//dpf[1].mPrint = print;
		//dpf[0].setTimer(timer[0]);
		//dpf[1].setTimer(timer[1]);


		dpf[0].init(0, domain, numPoints, numSets);
		dpf[1].init(1, domain, numPoints, numSets);

		auto baseCount0 = dpf[0].baseOtCount();
		auto baseCount1 = dpf[1].baseOtCount();

		std::array<std::vector<block>, 2> baseRecv;
		std::array<std::vector<std::array<block, 2>>, 2> baseSend;
		std::array<BitVector, 2> baseChoice;
		baseRecv[0].resize(baseCount0.mRecvCount);
		baseRecv[1].resize(baseCount1.mRecvCount);
		baseSend[0].resize(baseCount0.mSendCount);
		baseSend[1].resize(baseCount1.mSendCount);
		baseChoice[0].resize(baseCount0.mRecvCount);
		baseChoice[1].resize(baseCount1.mRecvCount);
		baseChoice[0].randomize(prng);
		baseChoice[1].randomize(prng);
		if (baseCount0.mRecvCount != baseCount1.mRecvCount)
			throw RTE_LOC;
		for (u64 i = 0; i < baseCount0.mRecvCount; ++i)
		{
			baseSend[0][i] = prng.get();
			baseSend[1][i] = prng.get();
			baseRecv[0][i] = baseSend[1][i][baseChoice[0][i]];
			baseRecv[1][i] = baseSend[0][i][baseChoice[1][i]];
		}
		dpf[0].setBaseOts(baseSend[0], baseRecv[0], baseChoice[0]);
		dpf[1].setBaseOts(baseSend[1], baseRecv[1], baseChoice[1]);

		// Create sockets for communication
		auto sock = coproto::LocalAsyncSocket::makePair();

		std::array<macoro::thread_pool, 2> threadPools;
		sock[0].setExecutor(threadPools[0]);
		sock[1].setExecutor(threadPools[1]);
		auto work0 = threadPools[0].make_work();
		auto work1 = threadPools[1].make_work();
		threadPools[0].create_thread();
		threadPools[1].create_thread();

		// Generate different values for each iteration
		std::vector<F> values0(numPoints * numSets);
		std::vector<F> values1(numPoints * numSets);
		for (u64 i = 0; i < values1.size(); ++i)
		{
			values0[i] = prng.get();
			values1[i] = prng.get();
		}

		// Prepare output matrices for this iteration
		std::array<Matrix<F>, 2> output;
		output[0].resize(numSets, domain);
		output[1].resize(numSets, domain);

		timer->setTimePoint("begin");

		// Phase 2: Multiple value expansions (called multiple times)
		for (u64 iteration = 0; iteration < iterations; ++iteration)
		{
			if (print)
			{
				std::cout << "Iteration " << iteration << " of " << iterations << std::endl;
			}

			dpf[0].setBaseOts(baseSend[0], baseRecv[0], baseChoice[0]);
			dpf[1].setBaseOts(baseSend[1], baseRecv[1], baseChoice[1]);

			macoro::sync_wait(macoro::when_all_ready(
				dpf[0].setPoints(points0, prng, sock[0]) | macoro::start_on(threadPools[0]),
				dpf[1].setPoints(points1, prng, sock[1]) | macoro::start_on(threadPools[1])
			));

			// Expand values using the cached point setup
			auto r = macoro::sync_wait(macoro::when_all_ready(
				dpf[0].expand(values0, prng, sock[0], [&](auto j, auto i, auto v) { output[0](j, i) = v; }) | macoro::start_on(threadPools[0]),
				dpf[1].expand(values1, prng, sock[1], [&](auto j, auto i, auto v) { output[1](j, i) = v; }) | macoro::start_on(threadPools[1])
			));
			std::get<0>(r).result();
			std::get<1>(r).result();

			timer->setTimePoint("done");
		}


		for (u64 i = 0; i < 2; ++i)
		{
			std::cout << "Dpf " << i << " time: \n" << timer[i] << std::endl;
		}
	}

	void SumDmpfBench(const oc::CLP& cmd)
	{
		if (cmd.isSet("block"))
			SumDmpf_bench_impl<block, CoeffCtxGF128>(cmd);
		else
			SumDmpf_bench_impl<u64, CoeffCtxInteger>(cmd);
	}


	void FftBench(const oc::CLP& cmd)
	{
		using F = Goldilocks;
		u64 n = cmd.getOr("n", 1ull << cmd.getOr("nn", 16));
		u64 t = cmd.getOr("t", 10);
		AlignedUnVector<F> a(n), w(n * 2);

		Timer timer;
		timer.setTimePoint("begin");
		auto psi = primRootOfUnity<F>(n * 2);
		timer.setTimePoint("primRootOfUnity");

		nttPrecomputeRootsOfUnity<F>(psi, w);
		timer.setTimePoint("nttPrecomputeRootsOfUnity");
		auto nw = getNegWrapRoots<F>(w, n);
		timer.setTimePoint("getNegWrapRoots");


		timer.setTimePoint("begin");
		for (u64 tt = 0; tt < t; ++tt)
		{
			nttNegWrapCt<F>(a, nw);
			timer.setTimePoint("done");

		}

		if (!cmd.isSet("quiet"))
			std::cout << timer << std::endl;

	}

#ifdef ENABLE_RINGLPN
	template<typename F>
	void ringSetBase(std::array<RingLpnTriple<F>, 2>& oles);
#endif

	void RingLpnBench(const CLP& cmd)
		try {

#ifdef ENABLE_RINGLPN

		//using F = Fp<0xFFFFFFFB, u32, u64>;
		//using F = F12289;
		using F = Goldilocks;

		auto logn = cmd.getOr("nn", 16);
		u64 n = 1ull << logn;
		bool quiet = cmd.isSet("quiet");
		auto mode = RingLpnTriple<F>::Mode::Ole;
		auto dpf = RingLpnTriple<F>::DpfType::RevCuckooDmpf;
		auto tensor = RingLpnTriple<F>::TensorBaseCorType::Precomputed;
		u64 trials = cmd.getOr("trials", 1);
		u64 exp = cmd.getOr("exp", 10);


		auto sock = coproto::LocalAsyncSocket::makePair();
		std::vector<F>
			A(n), B(n),
			C0(n), C1(n);

		PRNG prng0(block(2424523452345, 111124521521455324));
		PRNG prng1(block(6474567454546, 567546754674345444));
		Timer timer;

		std::array<macoro::thread_pool, 2> threadPools;
		sock[0].setExecutor(threadPools[0]);
		sock[1].setExecutor(threadPools[1]);
		auto work0 = threadPools[0].make_work();
		auto work1 = threadPools[1].make_work();
		threadPools[0].create_thread();
		threadPools[1].create_thread();

		std::array<u64, 2> first{}, second{};
		for (u64 tt = 0; tt < trials; ++tt)
		{
			std::array<RingLpnTriple<F>, 2> oles;
			oles[0].mDebug = cmd.isSet("debug");
			oles[1].mDebug = oles[0].mDebug;
			oles[0].mNumPolys = oles[1].mNumPolys = cmd.getOr("c", 2);
			oles[0].mPolyWeight = oles[1].mPolyWeight = cmd.getOr("t", 64);
			oles[0].init(0, n, mode, dpf, tensor);
			oles[1].init(1, n, mode, dpf, tensor);

			ringSetBase(oles);
			timer.setTimePoint("setBase");

			oles[0].setTimer(timer);


			for (u64 ee = 0; ee < exp; ++ee)
			{
				if (ee)
				{
					auto count0 = oles[0].baseCorCount();
					//auto count1 = oles[1].baseCorCount();
					auto coeffs = count0.mCoeffCount;
					std::vector<F> coeff0(coeffs), coeff1(coeffs);
					for (auto& c : coeff0)
						c = prng0.get();
					for (auto& c : coeff1)
						c = prng1.get();
					std::vector<F> tensor0(coeffs * coeffs), tensor1(coeffs * coeffs);
					for (u64 i = 0; i < coeffs; ++i)
					{
						for (u64 j = 0; j < coeffs; ++j)
						{
							auto idx = i * coeffs + j;
							tensor0[idx] = prng0.get();
							tensor1[idx] = coeff0[i] * coeff1[j] - tensor0[idx];
						}
					}

					oles[0].setBaseCors({}, {}, {}, {}, {}, coeff0, tensor0);
					oles[1].setBaseCors({}, {}, {}, {}, {}, coeff1, tensor1);
					timer.setTimePoint("setBase**");
				}

				auto before0 = sock[0].bytesReceived();
				auto before1 = sock[1].bytesReceived();

				auto r = macoro::sync_wait(macoro::when_all_ready(
					oles[0].expand(A, C0, prng0, sock[0]) | macoro::start_on(threadPools[0]),
					oles[1].expand(B, C1, prng1, sock[1]) | macoro::start_on(threadPools[1])));
				std::get<0>(r).result();
				std::get<1>(r).result();

				timer.setTimePoint("done______");

				auto after0 = sock[0].bytesReceived();
				auto after1 = sock[1].bytesReceived();

				if (ee)
				{
					first[0] += after0;
					first[1] += after1;
				}
				else
				{

					second[0] += after0 - before0;
					second[1] += after1 - before1;
				}

			}
		}

		if (!quiet)
		{
			std::cout << "Time taken: \n" << timer << std::endl;

			std::cout << "setup  " << first[0] / trials << " " << first[1] / trials << std::endl;
			std::cout << "expand " << second[0]/exp / trials << " " << second[1] / exp / trials << std::endl;
		}
#else
		throw UnitTestSkipped("ENABLE_RINGLPN not defined.");
#endif

	}
	catch (const std::exception& e)
	{
		std::cout << "RingLpnBench exception: " << e.what() << std::endl;
	}


	inline void WaksmanPermuteBench(const CLP& cmd)
	{
		using coproto::LocalAsyncSocket;

		u64 trials = cmd.getOr("t", 10);
		u64 n = cmd.getOr<u64>("n", 1ull << cmd.getOr("nn", 16));
		bool verbose = cmd.isSet("v");

		// Two-party protocol benchmark.
		const bool useU64 = cmd.isSet("u64");
		Timer timer, protoTimer;

		macoro::thread_pool pool0, pool1;
		auto w0 = pool0.make_work();
		auto w1 = pool1.make_work();

		auto sock = LocalAsyncSocket::makePair();
		PRNG prng0(block(2424523452345, 111124521521455324));
		PRNG prng1(block(5232345632, 5232345632));

		pool0.create_thread();
		pool1.create_thread();
		sock[0].setExecutor(pool0);
		sock[1].setExecutor(pool1);

		if (!useU64)
		{
			// F = block with GF(2) semantics
			using F = block;
			CoeffCtxGF2 ctx;

			std::array<WaksmanPermute, 2> perm;
			perm[0].init(0, n);
			perm[1].init(1, n);

			// Base OTs
			auto bc0 = perm[0].baseOtCount();
			auto bc1 = perm[1].baseOtCount();

			std::array<std::vector<block>, 2> baseRecv;
			std::array<std::vector<std::array<block, 2>>, 2> baseSend;
			std::array<BitVector, 2> baseChoice;

			baseRecv[0].resize(bc0.mRecvCount);
			baseRecv[1].resize(bc1.mRecvCount);
			baseSend[0].resize(bc0.mSendCount);
			baseSend[1].resize(bc1.mSendCount);
			baseChoice[0].resize(bc0.mRecvCount);
			baseChoice[1].resize(bc1.mRecvCount);
			baseChoice[0].randomize(prng0);
			baseChoice[1].randomize(prng0);

			for (u64 i = 0; i < bc0.mRecvCount; ++i)
			{
				baseSend[1][i] = prng0.get();
				baseRecv[0][i] = baseSend[1][i][baseChoice[0][i]];
			}
			for (u64 i = 0; i < bc1.mRecvCount; ++i)
			{
				baseSend[0][i] = prng0.get();
				baseRecv[1][i] = baseSend[0][i][baseChoice[1][i]];
			}

			perm[0].setBaseOts(baseSend[0], baseRecv[0], baseChoice[0]);
			perm[1].setBaseOts(baseSend[1], baseRecv[1], baseChoice[1]);

			auto in0 = ctx.makeVec<F>(n);
			auto in1 = ctx.makeVec<F>(n);
			for (u64 i = 0; i < n; ++i)
			{
				ctx.fromBlock(in0[i], prng0.get());
				ctx.fromBlock(in1[i], prng1.get());
			}

			if (verbose)
				std::cout << "Waksman apply (GF2/block): n=" << n << " trials=" << trials << (cmd.isSet("mt") ? " [mt]" : "") << std::endl;

			timer.setTimePoint("begin");
			for (u64 t = 0; t < trials; ++t)
			{
				timer.setTimePoint("b");
				auto r = macoro::sync_wait(macoro::when_all_ready(
					perm[0].apply<F, CoeffCtxGF2>(in0, sock[0], ctx) | macoro::start_on(pool0),
					perm[1].apply<F, CoeffCtxGF2>(in1, sock[1], ctx) | macoro::start_on(pool1)));
				std::get<0>(r).result();
				std::get<1>(r).result();
				timer.setTimePoint("apply");
			}

			if (!cmd.isSet("quiet"))
			{
				// Print timer and basic throughput
				std::cout << "WaksmanPermute (proto, GF2/block) n=" << n << std::endl;
				std::cout << timer << std::endl;
				std::cout << sock[0].bytesReceived() / trials << " " << sock[1].bytesReceived() / trials << " bytes per trial" << std::endl;
			}
		}
		else
		{
			// F = u64 with integer arithmetic
			using F = u64;
			CoeffCtxInteger ctx;

			std::array<WaksmanPermute, 2> perm;
			perm[0].init(0, n);
			perm[1].init(1, n);

			// Base OTs
			auto bc0 = perm[0].baseOtCount();
			auto bc1 = perm[1].baseOtCount();

			std::array<std::vector<block>, 2> baseRecv;
			std::array<std::vector<std::array<block, 2>>, 2> baseSend;
			std::array<BitVector, 2> baseChoice;

			baseRecv[0].resize(bc0.mRecvCount);
			baseRecv[1].resize(bc1.mRecvCount);
			baseSend[0].resize(bc0.mSendCount);
			baseSend[1].resize(bc1.mSendCount);
			baseChoice[0].resize(bc0.mRecvCount);
			baseChoice[1].resize(bc1.mRecvCount);
			baseChoice[0].randomize(prng0);
			baseChoice[1].randomize(prng0);

			for (u64 i = 0; i < bc0.mRecvCount; ++i)
			{
				baseSend[1][i] = prng0.get();
				baseRecv[0][i] = baseSend[1][i][baseChoice[0][i]];
			}
			for (u64 i = 0; i < bc1.mRecvCount; ++i)
			{
				baseSend[0][i] = prng0.get();
				baseRecv[1][i] = baseSend[0][i][baseChoice[1][i]];
			}

			perm[0].setBaseOts(baseSend[0], baseRecv[0], baseChoice[0]);
			perm[1].setBaseOts(baseSend[1], baseRecv[1], baseChoice[1]);

			auto in0 = ctx.makeVec<F>(n);
			auto in1 = ctx.makeVec<F>(n);
			for (u64 i = 0; i < n; ++i)
			{
				ctx.fromBlock(in0[i], prng0.get());
				ctx.fromBlock(in1[i], prng1.get());
			}

			if (verbose)
				std::cout << "Waksman apply (u64/integer): n=" << n << " trials=" << trials << (cmd.isSet("mt") ? " [mt]" : "") << std::endl;

			timer.setTimePoint("begin");
			for (u64 t = 0; t < trials; ++t)
			{
				auto r = macoro::sync_wait(macoro::when_all_ready(
					perm[0].apply<F, CoeffCtxInteger>(in0, sock[0], ctx) | macoro::start_on(pool0),
					perm[1].apply<F, CoeffCtxInteger>(in1, sock[1], ctx) | macoro::start_on(pool1)));
				std::get<0>(r).result();
				std::get<1>(r).result();
				timer.setTimePoint("apply");
			}

			if (!cmd.isSet("quiet"))
			{
				std::cout << "WaksmanPermute (proto, u64) n=" << n << std::endl;
				std::cout << timer << std::endl;
				std::cout << sock[0].bytesReceived() / trials << " " << sock[1].bytesReceived() / trials << " bytes per trial" << std::endl;
			}
		}
	}

	inline void BinarySolverBench(const CLP& cmd)
	{
		using coproto::LocalAsyncSocket;

		// Problem size and options
		u64 rows = cmd.getOr<u64>("rows", 32);
		u64 cols = cmd.getOr<u64>("cols", 64);
		u64 gbits = cmd.getOr<u64>("g", 16);
		u64 trials = cmd.getOr("t", 5);
		u64 batch = cmd.getOr<u64>("batch", 64);
		bool doPrint = cmd.isSet("print");

		auto c8 = divCeil(cols, 8);
		auto g8 = divCeil(gbits, 8);

		// Sockets and executors
		macoro::thread_pool pool0, pool1;
		auto w0 = pool0.make_work();
		auto w1 = pool1.make_work();
		pool0.create_thread();
		pool1.create_thread();

		auto sock = LocalAsyncSocket::makePair();
		sock[0].setExecutor(pool0);
		sock[1].setExecutor(pool1);

		// RNGs
		PRNG prng0(block(2424523452345, 111124521521455324));
		PRNG prng1(block(6474567454546, 567546754674345444));

		// Prepare solvers and base OTs (batched)
		std::array<BinarySolver, 2> solver;
		solver[0].init(0, rows, cols, gbits, batch);
		solver[1].init(1, rows, cols, gbits, batch);
		solver[0].mPrint = doPrint;
		solver[1].mPrint = doPrint;

		u64 bc0 = solver[0].baseOtCount();
		u64 bc1 = solver[1].baseOtCount();
		if (bc0 != bc1) throw RTE_LOC;

		std::array<std::vector<std::array<block, 2>>, 2> baseSend;
		std::array<std::vector<block>, 2> baseRecv;
		std::array<BitVector, 2> baseChoice;

		for (u64 p = 0; p < 2; ++p)
		{
			baseSend[p].resize(bc0);
			baseRecv[p].resize(bc0);
			baseChoice[p].resize(bc0);
			baseChoice[p].randomize(prng0);
		}

		for (u64 i = 0; i < bc0; ++i)
		{
			baseSend[1][i] = prng0.get();
			baseRecv[0][i] = baseSend[1][i][baseChoice[0][i]];
			baseSend[0][i] = prng0.get();
			baseRecv[1][i] = baseSend[0][i][baseChoice[1][i]];
		}

		solver[0].setBaseOts(baseSend[0], baseRecv[0], baseChoice[0]);
		solver[1].setBaseOts(baseSend[1], baseRecv[1], baseChoice[1]);

		// Allocate batched inputs/outputs once
		std::vector<Matrix<u8>> M0(batch), M1(batch), Y0(batch), Y1(batch), X0(batch), X1(batch);
		for (u64 b = 0; b < batch; ++b)
		{
			M0[b].resize(rows, c8);
			M1[b].resize(rows, c8);
			Y0[b].resize(rows, g8);
			Y1[b].resize(rows, g8);
			X0[b].resize(cols, g8);
			X1[b].resize(cols, g8);
		}

		// Build MatrixView spans for batched call (reused across trials)
		std::vector<MatrixView<const u8>> M0v, M1v, Y0v, Y1v;
		std::vector<MatrixView<u8>> X0v, X1v;
		M0v.reserve(batch); M1v.reserve(batch);
		Y0v.reserve(batch); Y1v.reserve(batch);
		X0v.reserve(batch); X1v.reserve(batch);
		for (u64 b = 0; b < batch; ++b)
		{
			M0v.emplace_back(M0[b]); M1v.emplace_back(M1[b]);
			Y0v.emplace_back(Y0[b]); Y1v.emplace_back(Y1[b]);
			X0v.emplace_back(X0[b]); X1v.emplace_back(X1[b]);
		}

		Timer timer;
		timer.setTimePoint("begin");

		for (u64 t = 0; t < trials; ++t)
		{
			// Re-init to reset internal multiplier state each trial
			solver[0].init(0, rows, cols, gbits, batch);
			solver[1].init(1, rows, cols, gbits, batch);
			solver[0].mPrint = doPrint;
			solver[1].mPrint = doPrint;
			solver[0].setBaseOts(baseSend[0], baseRecv[0], baseChoice[0]);
			solver[1].setBaseOts(baseSend[1], baseRecv[1], baseChoice[1]);

			// Directly sample shares as random; no clear values, no checking.
			for (u64 b = 0; b < batch; ++b)
			{
				prng0.get(M0[b].data(), M0[b].size());
				prng1.get(M1[b].data(), M1[b].size());
				prng0.get(Y0[b].data(), Y0[b].size());
				prng1.get(Y1[b].data(), Y1[b].size());
				setBytes(X0[b], 0);
				setBytes(X1[b], 0);
			}

			auto r = macoro::sync_wait(macoro::when_all_ready(
				solver[0].solve(M0v, Y0v, X0v, prng0, sock[0]) | macoro::start_on(pool0),
				solver[1].solve(M1v, Y1v, X1v, prng1, sock[1]) | macoro::start_on(pool1)
			));
			std::get<0>(r).result();
			std::get<1>(r).result();

			timer.setTimePoint("solve");
		}

		if (!cmd.isSet("quiet"))
		{
			std::cout << "BinarySolver batched (no-check) m=" << rows << " c=" << cols << " g=" << gbits
				<< " batch=" << batch << std::endl;
			std::cout << timer << std::endl;
			std::cout << sock[0].bytesReceived() / trials << " " << sock[1].bytesReceived() / trials << " bytes per trial" << std::endl;
		}
	}

	void Goldilocks_Mul_Bench(const CLP& cmd)
	{
		using clock = std::chrono::steady_clock;


		// Pre-generate inputs to avoid timing RNG/pack
		const size_t V = 1ull << cmd.getOr("nn", 16);         // number of vectors
		auto trials = cmd.getOr("t", 10ull);
		const size_t R = cmd.getOr("r", 64ull);              // repeats
		auto quiet = cmd.isSet("q");

		auto benchScalar = [&](const char* name)
			{
				// Pre-generate scalar inputs (same magnitude as 4 lanes per vector)
				const size_t S = V * 4;
				std::vector<Goldilocks> a(S), b(S);
				{
					PRNG prng(CCBlock);
					for (size_t i = 0; i < S; ++i)
					{
						a.data()[i] = prng.get<Goldilocks>();
						b.data()[i] = prng.get<Goldilocks>();
					}
				}

				double total = 0;
				for (u64 jj = 0; jj < trials; ++jj)
				{
					volatile u64 sink = 0;

					// warmup
					for (size_t i = 0; i < std::min<size_t>(S, 1024); ++i)
					{
						osuCrypto::Goldilocks z;
						osuCrypto::Goldilocks::mul(z, a.data()[i], b.data()[i]);
						sink += z.mVal;
					}

					auto t0 = clock::now();
					for (size_t r = 0; r < R; ++r)
					{
						for (size_t i = 0; i < S; ++i)
						{
							osuCrypto::Goldilocks z;
							osuCrypto::Goldilocks::mul(z, a.data()[i], b.data()[i]);
							sink += z.mVal;
						}
					}
					auto t1 = clock::now();

					double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
					const double ops = double(S) * double(R);
					total += ms;

					// giga multiplies per second
					auto Gms = ops / (ms * 1e6);

					if (!quiet)
					{

						std::cout << "[Goldilocks scalar mul bench] " << name
							<< "  time: " << ms << " ms"
							<< "  G muls/s: " << Gms
							<< "  ops: " << ops
							<< "  checksum: " << sink
							<< std::endl;
					}
				}

				if (!quiet)
					std::cout << "avg " << total / trials << std::endl;
			};


		//auto benchBatch = [&](const char* name)
		//	{
		//		// Pre-generate scalar inputs (same magnitude as 4 lanes per vector)
		//		constexpr int w = 2;
		//		const size_t S = V * w;
		//		std::vector<u64> a(S), b(S);
		//		{
		//			PRNG prng(CCBlock);
		//			for (size_t i = 0; i < S; ++i)
		//			{
		//				a.data()[i] = prng.get<u64>();
		//				b.data()[i] = prng.get<u64>();
		//			}
		//		}

		//		double total = 0;
		//		for (u64 jj = 0; jj < trials; ++jj)
		//		{
		//			u64 sink[w];
		//			for (u64 jj = 0; jj < w; ++jj)
		//				sink[jj] = 0;

		//			// warmup
		//			for (size_t i = 0; i < std::min<size_t>(S, 1024); i += w)
		//			{
		//				u64 z[w];
		//				mulPzt22x4<w>(z, a.data() +i, b.data() + i);
		//				for (u64 jj = 0; jj < w; ++jj)
		//					sink[jj] += z[jj];
		//				//sink[2] += z[2].mVal;
		//				//sink[3] += z[3].mVal;
		//			}

		//			auto t0 = clock::now();
		//			for (size_t r = 0; r < R; ++r)
		//			{
		//				for (size_t i = 0; i < S; i += w)
		//				{
		//					u64 z[w];
		//					mulPzt22x4<w>(z, a.data() + i, b.data() + i);
		//					for (u64 jj = 0; jj < w; ++jj)
		//						sink[jj] += z[jj];
		//				}
		//			}
		//			auto t1 = clock::now();

		//			double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
		//			const double ops = double(S) * double(R);
		//			total += ms;

		//			// giga multiplies per second
		//			auto Gms = ops / (ms * 1e6);

		//			if (!quiet)
		//			{

		//				std::cout << "[Goldilocks batch mul bench] " << name
		//					<< "  time: " << ms << " ms"
		//					<< "  G muls/s: " << Gms
		//					<< "  ops: " << ops
		//					<< "  checksum: " << sink
		//					<< std::endl;
		//			}
		//		}

		//		if (!quiet)
		//			std::cout << "avg " << total / trials << std::endl;
		//	};

		benchScalar("Scalar");
		//benchBatch("batch");
	}

	inline void MulxThroughputBench(const CLP& cmd)
	{
#if !(defined(__BMI2__) || (defined(_MSC_VER) && defined(_M_X64)))
		std::cout << "_mulx_u64 (BMI2) not enabled for this target." << std::endl;
		return;
#else
		using clock = std::chrono::steady_clock;

		const size_t V = 1ull << cmd.getOr("nn", 16); // number of operand pairs (must be >= 4 for K=4)
		const size_t R = cmd.getOr("r", 64);          // repeats to amortize overhead
		const u64 trials = cmd.getOr("t", 10);
		const bool quiet = cmd.isSet("q");

		std::vector<u64> A(V), B(V);
		{
			PRNG prng(CCBlock);
			for (size_t i = 0; i < V; ++i) {
				A[i] = prng.get<u64>();
				B[i] = prng.get<u64>();
			}
		}

		auto benchK = [&](int K)
			{
				double total_ms = 0.0;
				for (u64 tt = 0; tt < trials; ++tt)
				{
					volatile u64 sink = 0;

					// Warmup (1024 pairs or as many as we have)
					{
						size_t i = 0, W = std::min<size_t>(V, 1024);
						if (K == 1) {
							for (; i < W; ++i) {
								unsigned long long hi0;
								auto lo0 = _mulx_u64(A[i], B[i], &hi0);
								sink += lo0 + hi0;
							}
						}
						else if (K == 2) {
							for (; i + 1 < W; i += 2) {
								unsigned long long hi0, hi1;
								auto lo0 = _mulx_u64(A[i + 0], B[i + 0], &hi0);
								auto lo1 = _mulx_u64(A[i + 1], B[i + 1], &hi1);
								sink += lo0 + hi0 + lo1 + hi1;
							}
							for (; i < W; ++i) {
								unsigned long long hi0;
								auto lo0 = _mulx_u64(A[i], B[i], &hi0);
								sink += lo0 + hi0;
							}
						}
						else { // K == 4
							for (; i + 3 < W; i += 4) {
								unsigned long long hi0, hi1, hi2, hi3;
								auto lo0 = _mulx_u64(A[i + 0], B[i + 0], &hi0);
								auto lo1 = _mulx_u64(A[i + 1], B[i + 1], &hi1);
								auto lo2 = _mulx_u64(A[i + 2], B[i + 2], &hi2);
								auto lo3 = _mulx_u64(A[i + 3], B[i + 3], &hi3);
								sink += lo0 + hi0 + lo1 + hi1 + lo2 + hi2 + lo3 + hi3;
							}
							for (; i < W; ++i) {
								unsigned long long hi0;
								auto lo0 = _mulx_u64(A[i], B[i], &hi0);
								sink += lo0 + hi0;
							}
						}
					}

					auto t0 = clock::now();
					for (size_t r = 0; r < R; ++r)
					{
						size_t i = 0;
						if (K == 1) {
							for (; i < V; ++i) {
								unsigned long long hi0;
								auto lo0 = _mulx_u64(A[i], B[i], &hi0);
								sink += lo0 + hi0;
							}
						}
						else if (K == 2) {
							for (; i + 1 < V; i += 2) {
								unsigned long long hi0, hi1;
								auto lo0 = _mulx_u64(A[i + 0], B[i + 0], &hi0);
								auto lo1 = _mulx_u64(A[i + 1], B[i + 1], &hi1);
								sink += lo0 + hi0 + lo1 + hi1;
							}
							for (; i < V; ++i) {
								unsigned long long hi0;
								auto lo0 = _mulx_u64(A[i], B[i], &hi0);
								sink += lo0 + hi0;
							}
						}
						else { // K == 4
							for (; i + 3 < V; i += 4) {
								unsigned long long hi0, hi1, hi2, hi3;
								auto lo0 = _mulx_u64(A[i + 0], B[i + 0], &hi0);
								auto lo1 = _mulx_u64(A[i + 1], B[i + 1], &hi1);
								auto lo2 = _mulx_u64(A[i + 2], B[i + 2], &hi2);
								auto lo3 = _mulx_u64(A[i + 3], B[i + 3], &hi3);
								sink += lo0 + hi0 + lo1 + hi1 + lo2 + hi2 + lo3 + hi3;
							}
							for (; i < V; ++i) {
								unsigned long long hi0;
								auto lo0 = _mulx_u64(A[i], B[i], &hi0);
								sink += lo0 + hi0;
							}
						}
					}
					auto t1 = clock::now();

					double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
					const double muls = double(V) * double(R);     // total mulx ops
					const double Gmuls_per_s = muls / (ms * 1e6);   // giga mulx per second

					total_ms += ms;
					if (!quiet) {
						std::cout << "[_mulx_u64 throughput] K=" << K
							<< "  time: " << ms << " ms"
							<< "  G mulx/s: " << Gmuls_per_s
							<< "  ops: " << muls
							<< std::endl;
					}
				}
				if (!quiet) {
					std::cout << "avg(K=" << K << "): " << (total_ms / trials) << " ms" << std::endl;
				}
			};

		benchK(1);
		benchK(2);
		benchK(4);
#endif
	}

	inline void benchmark(CLP& cmd)
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
		else if (cmd.isSet("aes"))
			AESBenchmark(cmd);
		else if (cmd.isSet("dpf"))
			RegularDpfBenchmark(cmd);
		else if (cmd.isSet("triDpf"))
			TernaryDpfBenchmark(cmd);
		else if (cmd.isSet("foleage"))
			FoleageBenchmark(cmd);
		else if (cmd.isSet("silentTriple"))
			SilentOtTripleBenchmark(cmd);
		else if (cmd.isSet("revCuckoo"))
			RevCuckooBench(cmd);
		else if (cmd.isSet("sum"))
			SumDmpfBench(cmd);
		else if (cmd.isSet("fft"))
			FftBench(cmd);
		else if (cmd.isSet("ring"))
			RingLpnBench(cmd);
		else if (cmd.isSet("waksman"))
			WaksmanPermuteBench(cmd);
		else if (cmd.isSet("binSolve"))
			BinarySolverBench(cmd);
		else if (cmd.isSet("goldilocks"))
			Goldilocks_Mul_Bench(cmd);
		else if (cmd.isSet("mulx"))
			MulxThroughputBench(cmd);
		else
		{
			std::cout << "unknown benchmark, opts:" << std::endl;
			std::cout << "  -QC" << std::endl;
			std::cout << "  -silent" << std::endl;
			std::cout << "  -pprf" << std::endl;
			std::cout << "  -vole2" << std::endl;
			std::cout << "  -ea" << std::endl;
			std::cout << "  -ec" << std::endl;
			std::cout << "  -ecold" << std::endl;
			std::cout << "  -tungsten" << std::endl;
			std::cout << "  -aes" << std::endl;
			std::cout << "  -dpf" << std::endl;
			std::cout << "  -triDpf" << std::endl;
			std::cout << "  -foleage" << std::endl;
			std::cout << "  -silentTriple" << std::endl;
			std::cout << "  -revCuckoo" << std::endl;
			std::cout << "  -fft" << std::endl;
			std::cout << "  -sum" << std::endl;
			std::cout << "  -ring" << std::endl;
			std::cout << "  -waksman" << std::endl;
			std::cout << "  -binSolve" << std::endl;
		}
	}
}
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
				coproto::sync_wait(macoro::when_all_ready(
					std::move(p0), std::move(p1)));
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

		std::array<oc::RegularDpf, 2> dpf;
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
				dpf[0].expand(points0, values0, prng.get(), [&](auto k, auto i, auto v, auto t) { output[0](k, i) = v; }, sock[0]),
				dpf[1].expand(points1, values1, prng.get(), [&](auto k, auto i, auto v, auto t) { output[1](k, i) = v; }, sock[1])
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

		for (u64 ii = 0; ii < trials; ++ii)
		{

			std::array<FoleageTriple, 2> oles;
			if (cmd.hasValue("t"))
				oles[0].mT = oles[1].mT = cmd.get<u64>("t");
			if (cmd.hasValue("c"))
				oles[0].mC = oles[1].mC = cmd.get<u64>("c");

			oles[0].init(0, n);
			oles[1].init(1, n);

			std::cout << "leaf " << oles[0].mDpfLeafDepth << " main " << oles[0].mDpfTreeDepth << std::endl;

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
				ALsb(blocks),
				AMsb(blocks),
				BLsb(blocks),
				BMsb(blocks),
				C0Lsb(blocks),
				C0Msb(blocks),
				C1Lsb(blocks),
				C1Msb(blocks);


			oles[0].setTimer(timer);
			timer.setTimePoint("start");
			auto r = macoro::sync_wait(macoro::when_all_ready(
				oles[0].expand(ALsb, AMsb, C0Lsb, C0Msb, prng0, sock[0]) | macoro::start_on(pool),
				oles[1].expand(BLsb, BMsb, C1Lsb, C1Msb, prng1, sock[1]) | macoro::start_on(pool)));
			timer.setTimePoint("end");
			std::get<0>(r).result();
			std::get<1>(r).result();

		}
		work = {};
		std::cout << "n="<<n<<", log2="<<log2ceil(n)<<"\n Time taken: \n" << timer << std::endl;
#else
		std::cout << "ENABLE_FOLEAGE = false" << std::endl;
#endif
	}
}
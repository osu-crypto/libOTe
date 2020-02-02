#include "OT_Tests.h"

#include "libOTe/TwoChooseOne/OTExtInterface.h"

#include "libOTe/Tools/Tools.h"
#include "libOTe/Tools/LinearCode.h"
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Common/Log.h>

#include "libOTe/TwoChooseOne/IknpOtExtReceiver.h"
#include "libOTe/TwoChooseOne/IknpOtExtSender.h"

#include "libOTe/TwoChooseOne/KosOtExtReceiver.h"
#include "libOTe/TwoChooseOne/KosOtExtSender.h"


#include "libOTe/TwoChooseOne/KosDotExtReceiver.h"
#include "libOTe/TwoChooseOne/KosDotExtSender.h"

#include "libOTe/TwoChooseOne/IknpDotExtReceiver.h"
#include "libOTe/TwoChooseOne/IknpDotExtSender.h"

#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h"

#include "Common.h"
#include <thread>
#include <vector>
#include <random>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Matrix.h>

#ifdef GetMessage
#undef GetMessage
#endif

#ifdef  _MSC_VER
#pragma warning(disable: 4800)
#endif //  _MSC_VER


using namespace osuCrypto;

namespace tests_libOTe
{
	void OT_100Receive_Test(BitVector& choiceBits, span<block> recv, span<std::array<block, 2>>  sender)
	{

		for (u64 i = 0; i < choiceBits.size(); ++i)
		{

			u8 choice = choiceBits[i];
			const block & revcBlock = recv[i];
			//(i, choice, revcBlock);
			const block& senderBlock = sender[i][choice];

			//if (i%512==0) {
			//    std::cout << "[" << i << ",0]--" << sender[i][0] << std::endl;
			//    std::cout << "[" << i << ",1]--" << sender[i][1] << std::endl;
			//    std::cout << (int)choice << "-- " << recv[i] << std::endl;
			//}
			if (neq(revcBlock, senderBlock))
				throw UnitTestFail();

			if (eq(revcBlock, sender[i][1 ^ choice]))
				throw UnitTestFail();
		}

	}


	void printMtx(std::array<block, 128>& data)
	{
		for (auto& d : data)
		{
			std::cout << d << std::endl;
		}
	}

	void Tools_Transpose_Test()
	{
		{

			std::array<block, 128> data;
			memset((u8*)data.data(), 0, sizeof(data));

			data[0] = _mm_set_epi64x(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
			data[1] = _mm_set_epi64x(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
			data[2] = _mm_set_epi64x(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
			data[3] = _mm_set_epi64x(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
			data[4] = _mm_set_epi64x(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
			data[5] = _mm_set_epi64x(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
			data[6] = _mm_set_epi64x(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
			data[7] = _mm_set_epi64x(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);

			//printMtx(data);
			eklundh_transpose128(data);


			for (auto& d : data)
			{
				if (neq(d, _mm_set_epi64x(0, 0xFF)))
				{
					std::cout << "expected" << std::endl;
					std::cout << _mm_set_epi64x(0xF, 0) << std::endl << std::endl;

					printMtx(data);

					throw UnitTestFail();
				}
			}
		}
		{


			std::array<block, 128> data;
			memset((u8*)data.data(), 0, sizeof(data));

			data[0] = _mm_set_epi64x(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
			data[1] = _mm_set_epi64x(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
			data[2] = _mm_set_epi64x(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
			data[3] = _mm_set_epi64x(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
			data[4] = _mm_set_epi64x(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
			data[5] = _mm_set_epi64x(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
			data[6] = _mm_set_epi64x(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
			data[7] = _mm_set_epi64x(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);

			sse_transpose128(data);


			for (auto& d : data)
			{
				if (neq(d, _mm_set_epi64x(0, 0xFF)))
				{
					std::cout << "expected" << std::endl;
					std::cout << _mm_set_epi64x(0xF, 0) << std::endl << std::endl;

					printMtx(data);

					throw UnitTestFail();
				}
			}
		}

		{
			PRNG prng(ZeroBlock);

			std::array<std::array<block, 8>, 128> data;

			prng.get((u8*)data.data(), sizeof(block) * 8 * 128);


			std::array<std::array<block, 8>, 128> data2 = data;

			sse_transpose128x1024(data);


			for (u64 i = 0; i < 8; ++i)
			{

				std::array<block, 128> sub;

				for (u64 j = 0; j < 128; ++j)
				{
					sub[j] = data2[j][i];
				}

				sse_transpose128(sub);

				for (u64 j = 0; j < 128; ++j)
				{
					if (neq(sub[j], data[j][i]))
						throw UnitTestFail();
				}
			}

		}
	}

	void Tools_Transpose_View_Test()
	{




		{

			PRNG prng(ZeroBlock);

			std::array<block, 128> data;
			prng.get(data.data(), data.size());
			std::array<block, 128> data2;

			MatrixView<block> dataView(data.begin(), data.end(), 1);
			MatrixView<block> data2View(data2.begin(), data2.end(), 1);

			sse_transpose(dataView, data2View);

			sse_transpose128(data);




			for (u64 i = 0; i < 128; ++i)
			{
				if (neq(data[i], data2[i]))
				{
					std::cout << i << "\n";
					printMtx(data);
					std::cout << "\n";
					printMtx(data2);

					throw UnitTestFail();
				}
			}
		}


		{
			PRNG prng(ZeroBlock);

			std::array<std::array<block, 8>, 128> data;

			prng.get((u8*)data.data(), sizeof(block) * 8 * 128);


			std::array<std::array<block, 8>, 128> data2;

			MatrixView<block> dataView((block*)data.data(), 128, 8);
			MatrixView<block> data2View((block*)data2.data(), 128 * 8, 1);
			sse_transpose(dataView, data2View);


			for (u64 i = 0; i < 8; ++i)
			{
				std::array<block, 128> data128;

				for (u64 j = 0; j < 128; ++j)
				{
					data128[j] = data[j][i];
				}

				sse_transpose128(data128);


				for (u64 j = 0; j < 128; ++j)
				{
					if (neq(data128[j], data2View[i * 128 + j][0]))
						throw UnitTestFail();
				}
			}

		}


		{
			PRNG prng(ZeroBlock);

			//std::array<std::array<std::array<block, 8>, 128>, 2> data;

			Matrix<block> dataView(208, 8);
			prng.get((u8*)dataView.data(), sizeof(block) *dataView.bounds()[0] * dataView.stride());

			Matrix<block> data2View(1024, 2);
			memset(data2View.data(), 0, data2View.bounds()[0] * data2View.stride() * sizeof(block));
			sse_transpose(dataView, data2View);

			for (u64 b = 0; b < 2; ++b)
			{

				for (u64 i = 0; i < 8; ++i)
				{
					std::array<block, 128> data128;

					for (u64 j = 0; j < 128; ++j)
					{
						if (dataView.bounds()[0] > 128 * b + j)
							data128[j] = dataView[128 * b + j][i];
						else
							data128[j] = ZeroBlock;
					}

					sse_transpose128(data128);

					for (u64 j = 0; j < 128; ++j)
					{
						if (neq(data128[j], data2View[i * 128 + j][b]))
						{
							std::cout << "failed " << i << "  " << j << "  " << b << std::endl;
							std::cout << "exp: " << data128[j] << "\nact: " << data2View[i * 128 + j][b] << std::endl;
							throw UnitTestFail();
						}
					}
				}
			}
		}

		{
			PRNG prng(ZeroBlock);

			Matrix<u8> in(16, 8);
			prng.get((u8*)in.data(), sizeof(u8) *in.bounds()[0] * in.stride());

			Matrix<u8> out(63, 2);
			sse_transpose(in, out);


			Matrix<u8> out2(64, 2);
			sse_transpose(in, out2);

			for (u64 i = 0; i < out.bounds()[0]; ++i)
			{
				if (memcmp(out[i].data(), out2[i].data(), out[i].size()))
				{
					std::cout << "bad " << i << std::endl;
					throw UnitTestFail();
				}
			}
		}

		{
			PRNG prng(ZeroBlock);

			//std::array<std::array<std::array<block, 8>, 128>, 2> data;

			Matrix<u8> in(25, 9);
			Matrix<u8> in2(32, 9);

			prng.get((u8*)in.data(), sizeof(u8) *in.bounds()[0] * in.stride());
			memset(in2.data(), 0, in2.bounds()[0] * in2.stride());

			for (u64 i = 0; i < in.bounds()[0]; ++i)
			{
				for (u64 j = 0; j < in.stride(); ++j)
				{
					in2[i][j] = in[i][j];
				}
			}

			Matrix<u8> out(72, 4);
			Matrix<u8> out2(72, 4);

			sse_transpose(in, out);
			sse_transpose(in2, out2);

			for (u64 i = 0; i < out.bounds()[0]; ++i)
			{
				for (u64 j = 0; j < out.stride(); ++j)
				{
					if (out[i][j] != out2[i][j])
					{
						std::cout << (u32)out[i][j] << " != " << (u32)out2[i][j] << std::endl;
						throw UnitTestFail();
					}
				}
			}
		}
	}

    void OtExt_genBaseOts_Test()
    {
#if defined(LIBOTE_HAS_BASE_OT) && defined(ENABLE_KOS)
        IOService ios(0);
        Session ep0(ios, "127.0.0.1", 1212, SessionMode::Server);
        Session ep1(ios, "127.0.0.1", 1212, SessionMode::Client);
        Channel senderChannel = ep1.addChannel();
        Channel recvChannel = ep0.addChannel();

        KosOtExtSender sender;
        KosOtExtReceiver recv;

        auto thrd = std::thread([&]() {
            PRNG prng(ZeroBlock);
            recv.genBaseOts(prng, recvChannel);
        });

        PRNG prng(OneBlock);
        sender.genBaseOts(prng, senderChannel);
        thrd.join();

        for (u64 i = 0; i < sender.mGens.size(); ++i)
        {
            auto b = sender.mBaseChoiceBits[i];
            if (neq(sender.mGens[i].getSeed(), recv.mGens[i][b].getSeed()))
                throw RTE_LOC;

            if (eq(sender.mGens[i].getSeed(), recv.mGens[i][b^1].getSeed()))
                throw RTE_LOC;
        }
#else
        throw UnitTestSkipped("LibOTe has no BaseOTs or ENABLE_KOS not define  ");
#endif
    }


	void OtExt_Kos_Test()
	{
#if defined(ENABLE_KOS)
		setThreadName("Sender");

		IOService ios;
		Session ep0(ios, "127.0.0.1", 1212, SessionMode::Server);
		Session ep1(ios, "127.0.0.1", 1212, SessionMode::Client);
		Channel senderChannel = ep1.addChannel();
		Channel recvChannel   = ep0.addChannel();

		PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
		PRNG prng1(_mm_set_epi32(4253233465, 334565, 0, 235));

		u64 numOTs = 20000;

		std::vector<block> recvMsg(numOTs), baseRecv(128);
		std::vector<std::array<block, 2>> sendMsg(numOTs), baseSend(128);
		BitVector choices(numOTs), baseChoice(128);
		choices.randomize(prng0);
		baseChoice.randomize(prng0);

		for (u64 i = 0; i < 128; ++i)
		{
			baseSend[i][0] = prng0.get<block>();
			baseSend[i][1] = prng0.get<block>();
			baseRecv[i] = baseSend[i][baseChoice[i]];
		}

		KosOtExtSender sender;
		KosOtExtReceiver recv;

		std::thread thrd = std::thread([&]() {
			setThreadName("receiver");

			recv.setBaseOts(baseSend, prng0, recvChannel);
			recv.receive(choices, recvMsg, prng0, recvChannel);
		});

		sender.setBaseOts(baseRecv, baseChoice, senderChannel);
		sender.send(sendMsg, prng1, senderChannel);
		thrd.join();

		OT_100Receive_Test(choices, recvMsg, sendMsg);
#else
		throw UnitTestSkipped("ENALBE_KOS is not defined.");
#endif
	}

    void OtExt_Chosen_Test()
    {
#if defined(ENABLE_KOS)

        IOService ios;
        Session ep0(ios, "127.0.0.1:1212", SessionMode::Server);
        Session ep1(ios, "127.0.0.1:1212", SessionMode::Client);
        Channel senderChannel = ep1.addChannel();
        Channel recvChannel	  = ep0.addChannel();

        u64 numOTs = 200;

        std::vector<block> recvMsg(numOTs), baseRecv(128);
        std::vector<std::array<block, 2>> sendMsg(numOTs), baseSend(128);
        BitVector choices(numOTs), baseChoice(128);
        PRNG prng0(ZeroBlock);
        choices.randomize(prng0);
        baseChoice.randomize(prng0);
		
        for (u64 i = 0; i < 128; ++i)
        {
            baseSend[i][0] = prng0.get<block>();
            baseSend[i][1] = prng0.get<block>();
            baseRecv[i] = baseSend[i][baseChoice[i]];
        }
		
        prng0.get(sendMsg.data(), sendMsg.size());

        KosOtExtSender sender;
        KosOtExtReceiver recv;

        auto thrd = std::thread([&]() { 
            PRNG prng1(OneBlock); 
            recv.setBaseOts(baseSend, prng1, recvChannel);
            recv.receiveChosen(choices, recvMsg, prng1, recvChannel); 
        });

        sender.setBaseOts(baseRecv, baseChoice, senderChannel);
        sender.sendChosen(sendMsg, prng0, senderChannel);

        thrd.join();
		
        for (u64 i = 0; i < numOTs; ++i)
        {
            if (neq(recvMsg[i], sendMsg[i][choices[i]]))
                throw UnitTestFail("bad message " LOCATION);
        }
#else
	throw UnitTestSkipped("ENALBE_KOS is not defined.");
#endif
    }


	void mul128b(__m128i b, __m128i a, __m128i &c0, __m128i &c1)
	{
		__m128i t1, t2;
		c0 = _mm_clmulepi64_si128(a, b, 0x00);
		c1 = _mm_clmulepi64_si128(a, b, 0x11);
		t1 = _mm_shuffle_epi32(a, 0xEE);
		t1 = _mm_xor_si128(a, t1);
		t2 = _mm_shuffle_epi32(b, 0xEE);
		t2 = _mm_xor_si128(b, t2);
		t1 = _mm_clmulepi64_si128(t1, t2, 0x00);
		t1 = _mm_xor_si128(c0, t1);
		t1 = _mm_xor_si128(c1, t1);
		t2 = t1;
		t1 = _mm_slli_si128(t1, 8);
		t2 = _mm_srli_si128(t2, 8);
		c0 = _mm_xor_si128(c0, t1);
		c1 = _mm_xor_si128(c1, t2);
	}

	void DotExt_Kos_Test()
	{
#if defined(ENABLE_KOS)

		setThreadName("Sender");

		IOService ios;
		Session ep0(ios, "127.0.0.1", 1212, SessionMode::Server);
		Session ep1(ios, "127.0.0.1", 1212, SessionMode::Client);
		Channel senderChannel = ep1.addChannel();
		Channel recvChannel   = ep0.addChannel();

		PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
		PRNG prng1(_mm_set_epi32(4253233465, 334565, 0, 235));

		u64 numOTs = 952;
		u64 s = 40;

		std::vector<block> recvMsg(numOTs), baseRecv(128 + s);
		std::vector<std::array<block, 2>> sendMsg(numOTs), baseSend(128 + s);
		BitVector choices(numOTs);
		choices.randomize(prng0);

		BitVector baseChoice(128 + s);
		baseChoice.randomize(prng0);

		for (u64 i = 0; i < 128 + s; ++i)
		{
			baseSend[i][0] = prng0.get<block>();
			baseSend[i][1] = prng0.get<block>();
			baseRecv[i] = baseSend[i][baseChoice[i]];
		}
		KosDotExtSender sender;
		KosDotExtReceiver recv;

		std::thread thrd = std::thread([&]() {
			setThreadName("receiver");
			recv.setBaseOts(baseSend);
			recv.receive(choices, recvMsg, prng0, recvChannel);
		});

		block delta = prng1.get<block>();
		sender.setDelta(delta);
		sender.setBaseOts(baseRecv, baseChoice);
		sender.send(sendMsg, prng1, senderChannel);
		thrd.join();


		OT_100Receive_Test(choices, recvMsg, sendMsg);

		for (auto& s : sendMsg)
		{
			if (neq(s[0] ^ delta, s[1]))
				throw UnitTestFail();
		}

		senderChannel.close();
		recvChannel.close();

#else
		throw UnitTestSkipped("ENALBE_KOS is not defined.");
#endif
	}

	void DotExt_Iknp_Test()
	{
#ifdef ENABLE_IKNP

		setThreadName("Sender");

		IOService ios;
		Session ep0(ios, "127.0.0.1", 1212, SessionMode::Server);
		Session ep1(ios, "127.0.0.1", 1212, SessionMode::Client);
		Channel senderChannel = ep1.addChannel();
		Channel recvChannel   = ep0.addChannel();

		PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
		PRNG prng1(_mm_set_epi32(4253233465, 334565, 0, 235));

		u64 numTrials = 4;
		for (u64 t = 0; t < numTrials; ++t)
		{
			u64 numOTs = 4234;
			u64 s = 40;

			std::vector<block> recvMsg(numOTs), baseRecv(128 + s);
			std::vector<std::array<block, 2>> sendMsg(numOTs), baseSend(128 + s);
			BitVector choices(numOTs);
			choices.randomize(prng0);

			BitVector baseChoice(128 + s);
			baseChoice.randomize(prng0);

			for (u64 i = 0; i < 128 + s; ++i)
			{
				baseSend[i][0] = prng0.get<block>();
				baseSend[i][1] = prng0.get<block>();
				baseRecv[i] = baseSend[i][baseChoice[i]];
			}

			IknpDotExtSender sender;
			IknpDotExtReceiver recv;

			std::thread thrd = std::thread([&]() {
				setThreadName("receiver");
				recv.setBaseOts(baseSend);
				recv.receive(choices, recvMsg, prng0, recvChannel);
			});

			block delta = prng1.get<block>();
			sender.setDelta(delta);
			sender.setBaseOts(baseRecv, baseChoice);
			sender.send(sendMsg, prng1, senderChannel);
			thrd.join();

			OT_100Receive_Test(choices, recvMsg, sendMsg);

			for (auto& s : sendMsg)
			{
				if (neq(s[0] ^ delta, s[1]))
					throw UnitTestFail();
			}
		}

		senderChannel.close();
		recvChannel.close();
#else
		throw UnitTestSkipped("ENABLE_IKNP is not defined.");
#endif
	}


	void OtExt_Iknp_Test()
	{
#ifdef ENABLE_IKNP

		setThreadName("Sender");

		IOService ios;
		Session ep0(ios, "127.0.0.1", 1212, SessionMode::Server);
		Session ep1(ios, "127.0.0.1", 1212, SessionMode::Client);
		Channel senderChannel = ep1.addChannel();
		Channel recvChannel   = ep0.addChannel();

		PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
		PRNG prng1(_mm_set_epi32(4253233465, 334565, 0, 235));

		u64 numOTs = 200;

		std::vector<block> recvMsg(numOTs), baseRecv(128);
		std::vector<std::array<block, 2>> sendMsg(numOTs), baseSend(128);
		BitVector choices(numOTs), baseChoice(128);
		choices.randomize(prng0);
		baseChoice.randomize(prng0);

		prng0.get((u8*)baseSend.data()->data(), sizeof(block) * 2 * baseSend.size());
		for (u64 i = 0; i < 128; ++i)
		{
			baseRecv[i] = baseSend[i][baseChoice[i]];
		}

		IknpOtExtSender sender;
		IknpOtExtReceiver recv;

		std::thread thrd = std::thread([&]() {
			recv.setBaseOts(baseSend);
			recv.receive(choices, recvMsg, prng0, recvChannel);
		});

		sender.setBaseOts(baseRecv, baseChoice);
		sender.send(sendMsg, prng1, senderChannel);
		thrd.join();

		OT_100Receive_Test(choices, recvMsg, sendMsg);

#else
		throw UnitTestSkipped("ENABLE_IKNP is not defined.");
#endif
	}







}
#include "OT_Tests.h"

#include "libOTe/TwoChooseOne/OTExtInterface.h"
#include "libOTe/Base/BaseOT.h"
#include "libOTe/Tools/Tools.h"
#include "libOTe/Tools/LinearCode.h"
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Common/Log.h>

#include "libOTe/TwoChooseOne/Iknp/IknpOtExtReceiver.h"
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtSender.h"

#include "libOTe/TwoChooseOne/Kos/KosOtExtReceiver.h"
#include "libOTe/TwoChooseOne/Kos/KosOtExtSender.h"


#include "libOTe/TwoChooseOne/KosDot/KosDotExtReceiver.h"
#include "libOTe/TwoChooseOne/KosDot/KosDotExtSender.h"



//#include "libOTe/TwoChooseOne/SoftSpokenOT/SoftSpokenMalLeakyDotExt.h"
//#include "libOTe/TwoChooseOne/SoftSpokenOT/SoftSpokenMalOtExt.h"
//#include "libOTe/TwoChooseOne/SoftSpokenOT/SoftSpokenShDotExt.h"
//#include "libOTe/TwoChooseOne/SoftSpokenOT/SoftSpokenShOtExt.h"


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
            const block& revcBlock = recv[i];
            //(i, choice, revcBlock);
            const block& senderBlock = sender[i][choice];

            //if (i%512==0) {
            //    std::cout << "[" << i << ",0]--" << sender[i][0] << std::endl;
            //    std::cout << "[" << i << ",1]--" << sender[i][1] << std::endl;
            //    std::cout << (int)choice << "-- " << recv[i] << std::endl;
            //}
            if (revcBlock == ZeroBlock)
                throw RTE_LOC;

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

            data[0] = block(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
            data[1] = block(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
            data[2] = block(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
            data[3] = block(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
            data[4] = block(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
            data[5] = block(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
            data[6] = block(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
            data[7] = block(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);

            //printMtx(data);
            eklundh_transpose128(data);


			for (auto& d : data)
			{
				if (neq(d, block(0, 0xFF)))
				{
					std::cout << "expected" << std::endl;
					std::cout << block(0, 0xFF) << std::endl << std::endl;

                    printMtx(data);

					throw UnitTestFail();
				}
			}
		}

#ifdef OC_ENABLE_SSE2
		{


            std::array<block, 128> data;
            memset((u8*)data.data(), 0, sizeof(data));

            data[0] = block(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
            data[1] = block(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
            data[2] = block(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
            data[3] = block(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
            data[4] = block(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
            data[5] = block(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
            data[6] = block(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
            data[7] = block(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);

			sse_transpose128(data.data());


			for (auto& d : data)
			{
				if (neq(d, block(0, 0xFF)))
				{
					std::cout << "expected" << std::endl;
					std::cout << block(0, 0xFF) << std::endl << std::endl;

                    printMtx(data);

					throw UnitTestFail();
				}
			}
		}
#endif

#ifdef OC_ENABLE_AVX2
		{


			AlignedArray<block, 128> data;
			memset((u8*)data.data(), 0, sizeof(data));

			data[0] = block(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
			data[1] = block(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
			data[2] = block(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
			data[3] = block(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
			data[4] = block(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
			data[5] = block(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
			data[6] = block(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
			data[7] = block(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);

			avx_transpose128(data.data());


			for (auto& d : data)
			{
				if (neq(d, block(0, 0xFF)))
				{
					std::cout << "expected" << std::endl;
					std::cout << block(0, 0xFF) << std::endl << std::endl;

					printMtx(data);

					throw UnitTestFail();
				}
			}
		}
#endif

		{
			PRNG prng(ZeroBlock);

            AlignedArray<std::array<block, 8>, 128> data;
            assert((u64)data.data() % 32 == 0);
            prng.get((u8*)data.data(), sizeof(block) * 8 * 128);


            AlignedArray<std::array<block, 8>, 128> data2 = data;

            transpose128x1024(data);


            for (u64 i = 0; i < 8; ++i)
            {

				AlignedArray<block, 128> sub;

                for (u64 j = 0; j < 128; ++j)
                {
                    sub[j] = data2[j][i];
                }

				transpose128(sub.data());

				for (u64 j = 0; j < 128; ++j)
				{
					if (neq(sub[j], data[j][i]))
					{
						std::cout << "chunk " << j << " row " << i << std::endl;
						std::cout << "exp " << data[j][i] << std::endl;
						std::cout << "act " << sub[j] << std::endl;
						throw UnitTestFail();
					}
				}
			}

        }
    }

	void Tools_Transpose_Bench()
	{
		PRNG prng(ZeroBlock);
		AlignedArray<block, 128> data;
		prng.get(data.data(), data.size());

		u64 highAtEnd = data[127].get<u64>()[1];

		for (u64 i = 0; i < 10000; ++i)
		{
			transpose128(data.data());
			data[0] += block::allSame((u64)1);
		}

		// Add a check just to make sure this doesn't get compiled out.
		if (data[127].get<u64>()[1] != highAtEnd)
			throw UnitTestFail();
	}

	void Tools_Transpose_View_Test()
	{




        {

            PRNG prng(ZeroBlock);

			AlignedArray<block, 128> data;
			prng.get(data.data(), data.size());
			std::array<block, 128> data2;

            MatrixView<block> dataView(data.begin(), data.end(), 1);
            MatrixView<block> data2View(data2.begin(), data2.end(), 1);

            transpose(dataView, data2View);

			transpose128(data.data());




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
            transpose(dataView, data2View);


			for (u64 i = 0; i < 8; ++i)
			{
				AlignedArray<block, 128> data128;

                for (u64 j = 0; j < 128; ++j)
                {
                    data128[j] = data[j][i];
                }

				transpose128(data128.data());


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
            prng.get((u8*)dataView.data(), sizeof(block) * dataView.bounds()[0] * dataView.stride());

            Matrix<block> data2View(1024, 2);
            memset(data2View.data(), 0, data2View.bounds()[0] * data2View.stride() * sizeof(block));
            transpose(dataView, data2View);

            for (u64 b = 0; b < 2; ++b)
            {

				for (u64 i = 0; i < 8; ++i)
				{
					AlignedArray<block, 128> data128;

                    for (u64 j = 0; j < 128; ++j)
                    {
                        if (dataView.bounds()[0] > 128 * b + j)
                            data128[j] = dataView[128 * b + j][i];
                        else
                            data128[j] = ZeroBlock;
                    }

					transpose128(data128.data());

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
            prng.get((u8*)in.data(), sizeof(u8) * in.bounds()[0] * in.stride());

            Matrix<u8> out(63, 2);
            transpose(in, out);


            Matrix<u8> out2(64, 2);
            transpose(in, out2);

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

            prng.get((u8*)in.data(), sizeof(u8) * in.bounds()[0] * in.stride());
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

            transpose(in, out);
            transpose(in2, out2);

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
        gKosWarning = false;
        //IOService ios(0);
        //Session ep0(ios, "127.0.0.1", 1212, SessionMode::Server);
        //Session ep1(ios, "127.0.0.1", 1212, SessionMode::Client);
        //Channel senderChannel = ep1.addChannel();
        //Channel recvChannel = ep0.addChannel();
        
        auto sockets = cp::LocalAsyncSocket::makePair();

		KosOtExtSender sender;
		KosOtExtReceiver recv;

        PRNG prng0(ZeroBlock);
        PRNG prng2(OneBlock);

        auto proto0 = recv.genBaseOts(prng0, sockets[0]);
        auto proto1 = sender.genBaseOts(prng2, sockets[1]);

        eval(proto0, proto1);

		for (u64 i = 0; i < sender.mGens.size(); ++i)
		{
			auto b = sender.mBaseChoiceBits[i];
			if (neq(sender.mGens[i].getSeed(), recv.mGens[i][b].getSeed()))
				throw RTE_LOC;

            if (eq(sender.mGens[i].getSeed(), recv.mGens[i][b ^ 1].getSeed()))
                throw RTE_LOC;
        }
#else
		throw UnitTestSkipped("LibOTe has no BaseOTs or ENABLE_KOS not define  ");
#endif
	}


    void OtExt_Kos_Test()
    {
#if defined(ENABLE_KOS)
        gKosWarning = false;
        setThreadName("Sender");

        //IOService ios;
        //Session ep0(ios, "127.0.0.1", 1212, SessionMode::Server);
        //Session ep1(ios, "127.0.0.1", 1212, SessionMode::Client);
        //Channel senderChannel = ep1.addChannel();
        //Channel recvChannel = ep0.addChannel();
        
        auto sockets = cp::LocalAsyncSocket::makePair();

        PRNG prng0(block(4253465, 3434565));
        PRNG prng1(block(42532335, 334565));

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


        recv.setBaseOts(baseSend);
        sender.setBaseOts(baseRecv, baseChoice);

        auto main0 = recv.receive(choices, recvMsg, prng0, sockets[0]);
        auto main1 = sender.send(sendMsg, prng1, sockets[1]);

        eval(main0, main1);

        OT_100Receive_Test(choices, recvMsg, sendMsg);
#else
        throw UnitTestSkipped("ENABLE_KOS is not defined.");
#endif
    }



    void OtExt_Kos_fs_Test()
    {
#if defined(ENABLE_KOS)
        gKosWarning = false;
        setThreadName("Sender");


        
        auto sockets = cp::LocalAsyncSocket::makePair();

        PRNG prng0(block(4253465, 3434565));
        PRNG prng1(block(42532335, 334565));

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

        sender.mFiatShamir = true;
        recv.mFiatShamir = true;

        recv.setBaseOts(baseSend);
        sender.setBaseOts(baseRecv, baseChoice);

        auto main0 = recv.receive(choices, recvMsg, prng1, sockets[0]);
        auto main1 = sender.send(sendMsg, prng1, sockets[1]);

        eval(main0, main1);

        //    recv.setBaseOts(baseSend, prng0, recvChannel);
        //    recv.receive(choices, recvMsg, prng0, recvChannel);

        //sender.setBaseOts(baseRecv, baseChoice, senderChannel);
        //sender.send(sendMsg, prng1, senderChannel);

        OT_100Receive_Test(choices, recvMsg, sendMsg);
#else
        throw UnitTestSkipped("ENABLE_KOS is not defined.");
#endif
    }

    void OtExt_Kos_ro_Test()
    {
#if defined(ENABLE_KOS)
        gKosWarning = false;
        setThreadName("Sender");

        //IOService ios;
        //Session ep0(ios, "127.0.0.1", 1212, SessionMode::Server);
        //Session ep1(ios, "127.0.0.1", 1212, SessionMode::Client);
        //Channel senderChannel = ep1.addChannel();
        //Channel recvChannel = ep0.addChannel();

        
        auto sockets = cp::LocalAsyncSocket::makePair();

        PRNG prng0(block(4253465, 3434565));
        PRNG prng1(block(42532335, 334565));

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

        sender.mHashType = KosOtExtSender::HashType::RandomOracle;
        recv.mHashType = KosOtExtReceiver::HashType::RandomOracle;

        //std::thread thrd = std::thread([&]() {
        //    setThreadName("receiver");

        //    recv.setBaseOts(baseSend, prng0, recvChannel);
        //    recv.receive(choices, recvMsg, prng0, recvChannel);
        //    });

        //sender.setBaseOts(baseRecv, baseChoice, senderChannel);
        //sender.send(sendMsg, prng1, senderChannel);
        //thrd.join();

        recv.setBaseOts(baseSend);
        sender.setBaseOts(baseRecv, baseChoice);

        auto main0 = recv.receive(choices, recvMsg, prng1, sockets[0]);
        auto main1 = sender.send(sendMsg, prng1, sockets[1]);

        eval(main0, main1);


        OT_100Receive_Test(choices, recvMsg, sendMsg);
#else
        throw UnitTestSkipped("ENABLE_KOS is not defined.");
#endif
    }

	void OtExt_Chosen_Test()
	{
#if defined(ENABLE_KOS)
        gKosWarning = false;

        //IOService ios;
        //Session ep0(ios, "127.0.0.1:1212", SessionMode::Server);
        //Session ep1(ios, "127.0.0.1:1212", SessionMode::Client);
        //Channel senderChannel = ep1.addChannel();
        //Channel recvChannel = ep0.addChannel();

        
        auto sockets = cp::LocalAsyncSocket::makePair();

        u64 numOTs = 200;

        std::vector<block> recvMsg(numOTs), baseRecv(128);
        std::vector<std::array<block, 2>> sendMsg(numOTs), baseSend(128);
        BitVector choices(numOTs), baseChoice(128);
        PRNG prng0(ZeroBlock);
        PRNG prng1(block(42532335, 334565));
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

        //auto thrd = std::thread([&]() {
        //    PRNG prng1(OneBlock);
        //    recv.setBaseOts(baseSend, prng1, recvChannel);
        //    recv.receiveChosen(choices, recvMsg, prng1, recvChannel);
        //    });

        //sender.setBaseOts(baseRecv, baseChoice, senderChannel);
        //sender.sendChosen(sendMsg, prng0, senderChannel);

        //thrd.join();

        recv.setBaseOts(baseSend);
        sender.setBaseOts(baseRecv, baseChoice);

        auto main0 = recv.receive(choices, recvMsg, prng1, sockets[0]);
        auto main1 = sender.send(sendMsg, prng1, sockets[1]);

        eval(main0, main1);

		for (u64 i = 0; i < numOTs; ++i)
		{
			if (neq(recvMsg[i], sendMsg[i][choices[i]]))
				throw UnitTestFail("bad message " LOCATION);
		}
#else
        throw UnitTestSkipped("ENABLE_KOS is not defined.");
#endif
	}


    //void mul128b(__m128i b, __m128i a, __m128i &c0, __m128i &c1)
    //{
    //	__m128i t1, t2;
    //	c0 = _mm_clmulepi64_si128(a, b, 0x00);
    //	c1 = _mm_clmulepi64_si128(a, b, 0x11);
    //	t1 = _mm_shuffle_epi32(a, 0xEE);
    //	t1 = _mm_xor_si128(a, t1);
    //	t2 = _mm_shuffle_epi32(b, 0xEE);
    //	t2 = _mm_xor_si128(b, t2);
    //	t1 = _mm_clmulepi64_si128(t1, t2, 0x00);
    //	t1 = _mm_xor_si128(c0, t1);
    //	t1 = _mm_xor_si128(c1, t1);
    //	t2 = t1;
    //	t1 = _mm_slli_si128(t1, 8);
    //	t2 = _mm_srli_si128(t2, 8);
    //	c0 = _mm_xor_si128(c0, t1);
    //	c1 = _mm_xor_si128(c1, t2);
    //}

    void DotExt_Kos_Test()
    {
#if defined(ENABLE_DELTA_KOS)
        gKosWarning = false;

        setThreadName("Sender");

        auto sock = cp::LocalAsyncSocket::makePair();

        PRNG prng0(block(4253465, 3434565));
        PRNG prng1(block(42532335, 334565));

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

        setThreadName("receiver");
        recv.setBaseOts(baseSend);

        block delta = prng1.get<block>();
        sender.setDelta(delta);
        sender.setBaseOts(baseRecv, baseChoice);

        auto p1 = recv.receive(choices, recvMsg, prng0, sock[1]);
        auto p0 = sender.send(sendMsg, prng1, sock[0]);

        eval(p0, p1);

        OT_100Receive_Test(choices, recvMsg, sendMsg);

        for (auto& s : sendMsg)
        {
            if (neq(s[0] ^ delta, s[1]))
                throw UnitTestFail();
        }

#else
        throw UnitTestSkipped("ENABLE_DELTA_KOS is not defined.");
#endif
    }

    void DotExt_Iknp_Test()
    {
#ifdef ENABLE_IKNP

        setThreadName("Sender");


        
        auto sockets = cp::LocalAsyncSocket::makePair();

        PRNG prng0(block(4253465, 3434565));
        PRNG prng1(block(42532335, 334565));

        u64 numTrials = 4;
        for (u64 t = 0; t < numTrials; ++t)
        {
            u64 numOTs = 4234;

            AlignedUnVector<block> recvMsg(numOTs), baseRecv(128);
            AlignedUnVector<std::array<block, 2>> sendMsg(numOTs), baseSend(128);
            BitVector choices(numOTs);
            choices.randomize(prng0);

            BitVector baseChoice(128);
            baseChoice.randomize(prng0);

            for (u64 i = 0; i < 128; ++i)
            {
                baseSend[i][0] = prng0.get<block>();
                baseSend[i][1] = prng0.get<block>();
                baseRecv[i] = baseSend[i][baseChoice[i]];
            }

            IknpOtExtSender sender;
            IknpOtExtReceiver recv;

            sender.mHash = false;
            recv.mHash = false;
            ;
            recv.setBaseOts(baseSend);
            auto proto0 = recv.receive(choices, recvMsg, prng0, sockets[0]);
            block delta = baseChoice.getArrayView<block>()[0];

            sender.setBaseOts(baseRecv, baseChoice);
            auto proto1 = sender.send(sendMsg, prng1, sockets[1]);

            eval(proto0, proto1);

            OT_100Receive_Test(choices, recvMsg, sendMsg);

            for (auto& s : sendMsg)
            {
                if (neq(s[0] ^ delta, s[1]))
                    throw UnitTestFail(LOCATION);
            }
        }

#else
        throw UnitTestSkipped("ENABLE_IKNP is not defined.");
#endif
}


    void OtExt_Iknp_Test()
    {
#ifdef ENABLE_IKNP

        setThreadName("Sender");


        
        auto sockets = cp::LocalAsyncSocket::makePair();

        PRNG prng0(block(4253465, 3434565));
        PRNG prng1(block(42532335, 334565));

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

        recv.setBaseOts(baseSend);
        auto proto0 = recv.receive(choices, recvMsg, prng0, sockets[0]);

        sender.setBaseOts(baseRecv, baseChoice);
        auto proto1 = sender.send(sendMsg, prng1, sockets[1]);
        eval(proto0, proto1);

        OT_100Receive_Test(choices, recvMsg, sendMsg);

#else
        throw UnitTestSkipped("ENABLE_IKNP is not defined.");
#endif
	}
}

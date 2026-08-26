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
#include "libOTe/TwoChooseOne/KosDot/KosDotExtCheck.h"



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

            auto print = [&] {
                    std::cout << "[" << i << ",0]  " << sender[i][0] << std::endl;
                    std::cout << "[" << i << ",1]  " << sender[i][1] << std::endl;
                    std::cout <<"[  " <<(int)choice << "]  " << recv[i] << std::endl;
                };

            //if (i%512==0) {
            //    std::cout << "[" << i << ",0]--" << sender[i][0] << std::endl;
            //    std::cout << "[" << i << ",1]--" << sender[i][1] << std::endl;
            //    std::cout << (int)choice << "-- " << recv[i] << std::endl;
            //}
            if (revcBlock == ZeroBlock)
            {
                print();
                throw RTE_LOC;
            }

            if (neq(revcBlock, senderBlock))
            {
                print();
                throw UnitTestFail();
            }
            if (eq(revcBlock, sender[i][1 ^ choice]))
            {
                print();
                throw UnitTestFail();
            }
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
            data[0] = data[0].add_epi64(block::allSame((u64)1));
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
#ifdef ENABLE_AVX
        u64 L = 128 * 3;
        for(u64 b = 1; b < L-1; ++b)
        {
            PRNG prng(ZeroBlock);

            //std::array<std::array<std::array<block, 8>, 128>, 2> data;

            u64 rows = L - b;
            u64 cols = b;

            Matrix<u8> in(rows, divCeil(cols, 8));
            Matrix<u8> in2(rows, divCeil(cols, 8));

            prng.get((u8*)in.data(), sizeof(u8) * in.bounds()[0] * in.stride());
            memset(in2.data(), 0, in2.bounds()[0] * in2.stride());

            for (u64 i = 0; i < in.bounds()[0]; ++i)
            {
                for (u64 j = 0; j < in.stride(); ++j)
                {
                    in2[i][j] = in[i][j];
                }
            }

            Matrix<u8> out(cols, divCeil(rows,8));
            Matrix<u8> out2(cols, divCeil(rows, 8));

            avx_transpose(in, out);
            sse_transpose(in2, out2);

            for (u64 i = 0; i < out.bounds()[0]; ++i)
            {
                for (u64 j = 0; j < out.stride(); ++j)
                {
                    if (out[i][j] != out2[i][j])
                    {
                        std::cout << i <<" " <<j << " : " << (u32)out[i][j] << " != " << (u32)out2[i][j] << std::endl;
                        throw UnitTestFail();
                    }
                }
            }
        }
#endif
    }

    void OtExt_genBaseOts_Test()
    {
        
        //IOService ios(0);
        //Session ep0(ios, "127.0.0.1", 1212, SessionMode::Server);
        //Session ep1(ios, "127.0.0.1", 1212, SessionMode::Client);
        //Channel senderChannel = ep1.addChannel();
        //Channel recvChannel = ep0.addChannel();
#if defined(LIBOTE_HAS_BASE_OT) && defined(ENABLE_KOS)

        auto sockets = cp::LocalAsyncSocket::makePair();

		KosOtExtSender sender;
		KosOtExtReceiver recv;

        PRNG prng0(ZeroBlock);
        PRNG prng2(OneBlock);

        auto proto0 = recv.genBaseOts(prng0, sockets[0]);
        auto proto1 = sender.genBaseOts(prng2, sockets[1]);

        eval(proto0, proto1);

		for (u64 i = 0; i < gOtExtBaseOtCount; ++i)
		{
			auto b = sender.mBaseChoiceBits[i];
			if (neq(sender.mGens.mAESs[i].getKey(), recv.mGens[b].mAESs[i].getKey()))
				throw RTE_LOC;

            if (eq(sender.mGens.mAESs[i].getKey(), recv.mGens[b ^ 1].mAESs[i].getKey()))
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

        //IOService ios;
        //Session ep0(ios, "127.0.0.1", 1212, SessionMode::Server);
        //Session ep1(ios, "127.0.0.1", 1212, SessionMode::Client);
        //Channel senderChannel = ep1.addChannel();
        //Channel recvChannel = ep0.addChannel();
        
        auto sockets = cp::LocalAsyncSocket::makePair();

        PRNG prng0(block(4253465, 3434565));
        PRNG prng1(block(42532335, 334565));

        u64 numOTs = 128;

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

        sender.mHashType = HashType::RandomOracle;
        recv.mHashType = HashType::RandomOracle;

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
            u64 numOTs = 128;

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

            sender.mHashType = HashType::NoHash;
            recv.mHashType = HashType::NoHash;
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


    void OtExt_Kos_Split_Test()
    {
#if defined(ENABLE_KOS)
        auto runKos = [](bool iknp) {
            auto sockets = cp::LocalAsyncSocket::makePair();
            PRNG prng0(block(0x6b6f7353706c6974, iknp));
            PRNG prng1(block(0x53656e6465724f54, iknp));

            constexpr u64 numOTs = 257;
            AlignedUnVector<block> recvMsg(numOTs), baseRecv(gOtExtBaseOtCount);
            AlignedUnVector<std::array<block, 2>> sendMsg(numOTs), baseSend(gOtExtBaseOtCount);
            BitVector choices(numOTs), baseChoice(gOtExtBaseOtCount);
            choices.randomize(prng0);
            baseChoice.randomize(prng0);

            for (u64 i = 0; i < gOtExtBaseOtCount; ++i)
            {
                baseSend[i][0] = prng0.get<block>();
                baseSend[i][1] = prng0.get<block>();
                baseRecv[i] = baseSend[i][baseChoice[i]];
            }

            if (iknp)
            {
#ifdef ENABLE_IKNP
                IknpOtExtSender sender;
                IknpOtExtReceiver receiver;
                receiver.setBaseOts(baseSend);
                sender.setBaseOts(baseRecv, baseChoice);

                auto splitReceiver = receiver.splitBase();
                auto splitSender = sender.splitBase();
                auto p0 = splitReceiver.receive(choices, recvMsg, prng0, sockets[0]);
                auto p1 = splitSender.send(sendMsg, prng1, sockets[1]);
                eval(p0, p1);
#else
                throw UnitTestSkipped("ENABLE_IKNP is not defined.");
#endif
            }
            else
            {
                KosOtExtSender sender;
                KosOtExtReceiver receiver;
                receiver.setBaseOts(baseSend);
                sender.setBaseOts(baseRecv, baseChoice);

                auto splitReceiver = receiver.splitBase();
                auto splitSender = sender.splitBase();
                auto p0 = splitReceiver.receive(choices, recvMsg, prng0, sockets[0]);
                auto p1 = splitSender.send(sendMsg, prng1, sockets[1]);
                eval(p0, p1);
            }

            OT_100Receive_Test(choices, recvMsg, sendMsg);
        };

        runKos(false);
#ifdef ENABLE_IKNP
        runKos(true);
#endif
#else
        throw UnitTestSkipped("ENABLE_KOS is not defined.");
#endif
    }


    void OtExt_Kos_BlockBoundary_Test()
    {
#if defined(ENABLE_KOS)
        for (auto numOTs : { 0ull, 128ull, 256ull })
        {
            auto sockets = cp::LocalAsyncSocket::makePair();
            PRNG prng0(block(0x426f756e64617279, numOTs));
            PRNG prng1(block(0x4b4f53426c6f636b, numOTs));

            AlignedUnVector<block> recvMsg(numOTs), baseRecv(gOtExtBaseOtCount);
            AlignedUnVector<std::array<block, 2>> sendMsg(numOTs), baseSend(gOtExtBaseOtCount);
            BitVector choices(numOTs), baseChoice(gOtExtBaseOtCount);
            choices.randomize(prng0);
            baseChoice.randomize(prng0);

            for (u64 i = 0; i < gOtExtBaseOtCount; ++i)
            {
                baseSend[i][0] = prng0.get<block>();
                baseSend[i][1] = prng0.get<block>();
                baseRecv[i] = baseSend[i][baseChoice[i]];
            }

            KosOtExtSender sender;
            KosOtExtReceiver receiver;
            receiver.setBaseOts(baseSend);
            sender.setBaseOts(baseRecv, baseChoice);

            auto p0 = receiver.receive(choices, recvMsg, prng0, sockets[0]);
            auto p1 = sender.send(sendMsg, prng1, sockets[1]);
            eval(p0, p1);
            OT_100Receive_Test(choices, recvMsg, sendMsg);
        }
#else
        throw UnitTestSkipped("ENABLE_KOS is not defined.");
#endif
    }


    void OtExt_InputValidation_Test()
    {
        auto expectThrow = [](auto&& fn) {
            bool threw = false;
            try
            {
                fn();
            }
            catch (const std::exception&)
            {
                threw = true;
            }

            if (!threw)
                throw UnitTestFail(LOCATION);
        };

#if defined(ENABLE_KOS)
        {
            auto sockets = cp::LocalAsyncSocket::makePair();
            PRNG prng(ZeroBlock);
            KosOtExtReceiver receiver;
            BitVector choices(129);
            AlignedUnVector<block> messages(128);

            expectThrow([&] {
                macoro::sync_wait(receiver.receive(choices, messages, prng, sockets[0]));
            });
        }
        {
            auto sockets = cp::LocalAsyncSocket::makePair();
            PRNG prng(ZeroBlock);
            KosOtExtReceiver receiver;
            BitVector choices(127);
            AlignedUnVector<block> messages(128);

            expectThrow([&] {
                macoro::sync_wait(receiver.receiveChosen(choices, messages, prng, sockets[0]));
            });
        }
#endif

        {
            struct DeterministicOtSender final : OtSender
            {
                task<> send(
                    span<std::array<block, 2>> messages,
                    PRNG&,
                    Socket&) override
                {
                    for (u64 i = 0; i < messages.size(); ++i)
                        messages[i] = { block(i, 0), block(i, 1) };
                    co_return;
                }
            } sender;

            auto sockets = cp::LocalAsyncSocket::makePair();
            PRNG prng(ZeroBlock);
            AlignedUnVector<block> messages(2);
            AlignedUnVector<block> peerCorrection(2);
            auto results = macoro::sync_wait(macoro::when_all_ready(
                sender.sendCorrelated(
                    messages,
                    [](block, u64) -> block {
                        throw std::runtime_error(
                            "intentional correlation callback failure");
                    },
                    prng,
                    sockets[0]),
                sockets[1].recv(peerCorrection)));
            bool senderRejected = false;
            bool peerReleased = false;
            try { std::get<0>(results).result(); }
            catch (const std::exception&) { senderRejected = true; }
            try { std::get<1>(results).result(); }
            catch (const std::exception&) { peerReleased = true; }
            if (!senderRejected || !peerReleased || !sockets[0].closed())
                throw UnitTestFail(
                    "Correlated OT callback failure left its peer waiting");
        }

#if defined(ENABLE_DELTA_KOS)
        {
            auto sockets = cp::LocalAsyncSocket::makePair();
            PRNG prng(ZeroBlock);
            KosDotExtReceiver receiver;
            BitVector choices(129);
            AlignedUnVector<block> messages(128);

            expectThrow([&] {
                macoro::sync_wait(receiver.receive(choices, messages, prng, sockets[0]));
            });
        }
#endif
    }


    void DotExt_Kos_BaseValidation_Test()
    {
#if defined(ENABLE_DELTA_KOS)
        auto expectThrow = [](auto&& fn) {
            bool threw = false;
            try
            {
                fn();
            }
            catch (const std::exception&)
            {
                threw = true;
            }

            if (!threw)
                throw UnitTestFail(LOCATION);
        };

        for (auto count : { 0ull, 167ull, 169ull })
        {
            AlignedUnVector<block> baseRecv(count);
            AlignedUnVector<std::array<block, 2>> baseSend(count);
            BitVector baseChoice(count);

            expectThrow([&] {
                KosDotExtSender sender;
                sender.setBaseOts(baseRecv, baseChoice);
            });
            expectThrow([&] {
                KosDotExtReceiver receiver;
                receiver.setBaseOts(baseSend);
            });
        }

        {
            AlignedUnVector<block> baseRecv(167);
            BitVector baseChoice(168);
            expectThrow([&] {
                KosDotExtSender sender;
                sender.setBaseOts(baseRecv, baseChoice);
            });
        }
#else
        throw UnitTestSkipped("ENABLE_DELTA_KOS is not defined.");
#endif
    }


    void OtExt_NoHashMultiBlock_Test()
    {
#ifdef ENABLE_IKNP
        auto sockets = cp::LocalAsyncSocket::makePair();
        PRNG receiverPrng(block(0x4e6f486173685265, 1));
        PRNG senderPrng(block(0x4e6f486173685365, 2));
        constexpr u64 numOTs = 257;

        AlignedUnVector<block> recvMsg(numOTs), baseRecv(gOtExtBaseOtCount);
        AlignedUnVector<std::array<block, 2>> sendMsg(numOTs), baseSend(gOtExtBaseOtCount);
        BitVector choices(numOTs), baseChoice(gOtExtBaseOtCount);
        choices.randomize(receiverPrng);
        baseChoice.randomize(receiverPrng);
        for (u64 i = 0; i < gOtExtBaseOtCount; ++i)
        {
            baseSend[i][0] = receiverPrng.get<block>();
            baseSend[i][1] = receiverPrng.get<block>();
            baseRecv[i] = baseSend[i][baseChoice[i]];
        }

        IknpOtExtSender sender;
        IknpOtExtReceiver receiver;
        sender.mHashType = HashType::NoHash;
        receiver.mHashType = HashType::NoHash;
        sender.setBaseOts(baseRecv, baseChoice);
        receiver.setBaseOts(baseSend);

        auto p0 = receiver.receive(choices, recvMsg, receiverPrng, sockets[0]);
        auto p1 = sender.send(sendMsg, senderPrng, sockets[1]);
        eval(p0, p1);
        OT_100Receive_Test(choices, recvMsg, sendMsg);

        auto delta = baseChoice.blocks()[0];
        for (const auto& pair : sendMsg)
            if ((pair[0] ^ pair[1]) != delta)
                throw UnitTestFail(LOCATION);
#else
        throw UnitTestSkipped("ENABLE_IKNP is not defined.");
#endif
    }


    void OtExt_SplitConfig_Test()
    {
#if defined(ENABLE_KOS)
        PRNG prng(block(0x53706c6974436667, 1));
        AlignedUnVector<block> baseRecv(gOtExtBaseOtCount);
        AlignedUnVector<std::array<block, 2>> baseSend(gOtExtBaseOtCount);
        BitVector baseChoice(gOtExtBaseOtCount);
        baseChoice.randomize(prng);
        for (u64 i = 0; i < gOtExtBaseOtCount; ++i)
        {
            baseSend[i][0] = prng.get<block>();
            baseSend[i][1] = prng.get<block>();
            baseRecv[i] = baseSend[i][baseChoice[i]];
        }

        KosOtExtSender kosSender;
        kosSender.mHashType = HashType::RandomOracle;
        kosSender.mFiatShamir = true;
        kosSender.mIsMalicious = false;
        kosSender.setBaseOts(baseRecv, baseChoice);
        auto kosSenderChild = kosSender.splitBase();
        if (kosSenderChild.mHashType != HashType::RandomOracle ||
            !kosSenderChild.mFiatShamir || kosSenderChild.mIsMalicious)
            throw UnitTestFail(LOCATION);

        KosOtExtReceiver kosReceiver;
        kosReceiver.mHashType = HashType::RandomOracle;
        kosReceiver.mFiatShamir = true;
        kosReceiver.mIsMalicious = false;
        kosReceiver.setBaseOts(baseSend);
        auto kosReceiverChild = kosReceiver.splitBase();
        if (kosReceiverChild.mHashType != HashType::RandomOracle ||
            !kosReceiverChild.mFiatShamir || kosReceiverChild.mIsMalicious)
            throw UnitTestFail(LOCATION);

#ifdef ENABLE_IKNP
        auto sockets = cp::LocalAsyncSocket::makePair();
        constexpr u64 numOTs = 257;
        AlignedUnVector<block> recvMsg(numOTs);
        AlignedUnVector<std::array<block, 2>> sendMsg(numOTs);
        BitVector choices(numOTs);
        choices.randomize(prng);

        IknpOtExtSender iknpSender;
        IknpOtExtReceiver iknpReceiver;
        iknpSender.mHashType = HashType::NoHash;
        iknpReceiver.mHashType = HashType::NoHash;
        iknpSender.setBaseOts(baseRecv, baseChoice);
        iknpReceiver.setBaseOts(baseSend);

        auto senderChild = iknpSender.split();
        auto receiverChild = iknpReceiver.split();
        auto typedSender = dynamic_cast<IknpOtExtSender*>(senderChild.get());
        auto typedReceiver = dynamic_cast<IknpOtExtReceiver*>(receiverChild.get());
        if (!typedSender || !typedReceiver ||
            typedSender->mHashType != HashType::NoHash ||
            typedReceiver->mHashType != HashType::NoHash)
            throw UnitTestFail(LOCATION);

        PRNG receiverPrng(block(0x53706c6974526563, 2));
        PRNG senderPrng(block(0x53706c697453656e, 3));
        auto p0 = receiverChild->receive(choices, recvMsg, receiverPrng, sockets[0]);
        auto p1 = senderChild->send(sendMsg, senderPrng, sockets[1]);
        eval(p0, p1);
        OT_100Receive_Test(choices, recvMsg, sendMsg);
#endif
#else
        throw UnitTestSkipped("ENABLE_KOS is not defined.");
#endif
    }


    void OtExt_MoveState_Test()
    {
#if defined(ENABLE_KOS) || defined(ENABLE_DELTA_KOS)
#ifdef ENABLE_KOS
#ifdef ENABLE_IKNP
		{
			std::array<block, gOtExtBaseOtCount> senderBase{};
			std::array<std::array<block, 2>, gOtExtBaseOtCount> receiverBase{};
			BitVector senderChoices(gOtExtBaseOtCount);

			IknpOtExtSender sender(senderBase, senderChoices);
			IknpOtExtReceiver receiver(receiverBase);
			if (sender.mIsMalicious || receiver.mIsMalicious)
				throw UnitTestFail("IKNP base-OT constructor enabled malicious KOS mode");

			IknpOtExtSender movedSender(std::move(sender));
			IknpOtExtReceiver movedReceiver;
			movedReceiver = std::move(receiver);
			if (movedSender.mIsMalicious || sender.mIsMalicious ||
				movedReceiver.mIsMalicious || receiver.mIsMalicious)
				throw UnitTestFail("IKNP move changed the semi-honest mode");

			sender.setBaseOts(senderBase, senderChoices);
			receiver.setBaseOts(receiverBase);
			if (sender.mIsMalicious || receiver.mIsMalicious)
				throw UnitTestFail("Moved-from IKNP object changed wire mode after reuse");
		}
#endif
        {
            KosOtExtSender source;
            source.mPrngIdx = 9;
            source.mBaseChoiceBits.resize(1);
            source.mHashType = HashType::RandomOracle;
            source.mFiatShamir = true;
            source.mIsMalicious = false;

            KosOtExtSender destination(std::move(source));
            if (destination.mPrngIdx != 9 || destination.mBaseChoiceBits.size() != 1 ||
                destination.mHashType != HashType::RandomOracle ||
                !destination.mFiatShamir || destination.mIsMalicious)
                throw UnitTestFail(LOCATION);
            if (source.mPrngIdx || source.mBaseChoiceBits.size() ||
                source.mHashType != HashType::AesHash || source.mFiatShamir ||
                !source.mIsMalicious || source.hasBaseOts())
                throw UnitTestFail(LOCATION);
        }
        {
            KosOtExtReceiver source;
            source.mHasBase = true;
            source.mGens.resize(1);
            source.mPrngIdx = 9;
            source.mHashType = HashType::RandomOracle;
            source.mFiatShamir = true;
            source.mIsMalicious = false;

            KosOtExtReceiver destination(std::move(source));
            if (!destination.mHasBase || destination.mGens.size() != 1 ||
                destination.mPrngIdx != 9 || destination.mHashType != HashType::RandomOracle ||
                !destination.mFiatShamir || destination.mIsMalicious)
                throw UnitTestFail(LOCATION);
            if (source.mHasBase || !source.mGens.empty() || source.mPrngIdx ||
                source.mHashType != HashType::AesHash || source.mFiatShamir ||
                !source.mIsMalicious || source.hasBaseOts())
                throw UnitTestFail(LOCATION);
        }
#endif
#ifdef ENABLE_DELTA_KOS
        {
            KosDotExtSender source;
            source.mDelta = block(3, 4);
            source.mHasDelta = true;
            source.mGens.resize(1);
            source.mBaseChoiceBits.resize(1);

            KosDotExtSender destination(std::move(source));
            if (destination.mDelta != block(3, 4) || !destination.mHasDelta ||
                destination.mGens.size() != 1 || destination.mBaseChoiceBits.size() != 1)
                throw UnitTestFail(LOCATION);
            if (source.mDelta != ZeroBlock || source.mHasDelta || !source.mGens.empty() ||
                source.mBaseChoiceBits.size() || source.hasBaseOts())
                throw UnitTestFail(LOCATION);
        }
        {
            KosDotExtReceiver source;
            source.mHasBase = true;
            source.mGens.resize(1);

            KosDotExtReceiver destination(std::move(source));
            if (!destination.mHasBase || destination.mGens.size() != 1)
                throw UnitTestFail(LOCATION);
            if (source.mHasBase || !source.mGens.empty() || source.hasBaseOts())
                throw UnitTestFail(LOCATION);
        }
#endif
#else
        throw UnitTestSkipped("ENABLE_KOS or ENABLE_DELTA_KOS is required.");
#endif
    }


    void Tools_Arithmetic_Audit_Test()
    {
        const block a0(0x0123456789abcdef, 0xfedcba9876543210);
        const block a1(0x0000000000000003, 0x456789abcdef0123);
        const block b0(0x0f1e2d3c4b5a6978, 0x8877665544332211);
        const block b1(0x0000000000000002, 0x13579bdf2468ace0);
        block c0 = AllOneBlock, c1 = AllOneBlock, c2 = AllOneBlock;
        block d0, d1, d2, d3;

        mul190(a0, a1, b0, b1, c0, c1, c2);
        mul256(a0, a1, b0, b1, d0, d1, d2, d3);
        if (c0 != d0 || c1 != d1 || c2 != d2)
            throw UnitTestFail(LOCATION);
    }


    void DotExt_Kos_Check_Test()
    {
#if defined(ENABLE_DELTA_KOS)
        PRNG prng(block(0x4b6f73446f744368, 1));
        constexpr u64 numRows = 257;
        std::vector<details::KosDotCheckRow> tRows(numRows), qRows(numRows);
        std::array<details::KosDotCheckRow, 128> tExtra, qExtra;
        BitVector choices(numRows), extraChoices(128), deltaBits(details::KosDotCheckColumns);
        choices.randomize(prng);
        extraChoices.randomize(prng);
        deltaBits.randomize(prng);

        std::array<block, 2> delta{ ZeroBlock, ZeroBlock };
        std::memcpy(delta.data(), deltaBits.data(), deltaBits.sizeBytes());
        for (u64 i = 0; i < numRows; ++i)
        {
            tRows[i] = { prng.get<block>(), prng.get<block>() };
            auto mask = zeroAndAllOne[choices[i]];
            qRows[i] = { tRows[i][0] ^ (delta[0] & mask),
                tRows[i][1] ^ (delta[1] & mask) };
        }
        for (u64 i = 0; i < tExtra.size(); ++i)
        {
            tExtra[i] = { prng.get<block>(), prng.get<block>() };
            auto mask = zeroAndAllOne[extraChoices[i]];
            qExtra[i] = { tExtra[i][0] ^ (delta[0] & mask),
                tExtra[i][1] ^ (delta[1] & mask) };
        }

        auto seed = prng.get<block>();
        auto tCheck = details::kosDotColumnCheck(tRows, tExtra, seed);
        auto qCheck = details::kosDotColumnCheck(qRows, qExtra, seed);
        auto xCheck = details::kosDotChoiceCheck(
            choices, extraChoices.blocks()[0], seed);
        for (u64 i = 0; i < details::KosDotCheckColumns; ++i)
        {
            auto expected = qCheck[i] ^
                (xCheck & zeroAndAllOne[deltaBits[i]]);
            if (tCheck[i] != expected)
                throw UnitTestFail(LOCATION);
        }

        qRows[128][0] ^= OneBlock;
        auto tamperedQCheck = details::kosDotColumnCheck(qRows, qExtra, seed);
        bool rejected = false;
        for (u64 i = 0; i < details::KosDotCheckColumns; ++i)
        {
            auto expected = tamperedQCheck[i] ^
                (xCheck & zeroAndAllOne[deltaBits[i]]);
            rejected |= tCheck[i] != expected;
        }
        if (!rejected)
            throw UnitTestFail(LOCATION);
#else
        throw UnitTestSkipped("ENABLE_DELTA_KOS is not defined.");
#endif
    }


    void DotExt_Kos_SplitDelta_Test()
    {
#if defined(ENABLE_DELTA_KOS)
        PRNG prng(block(0x4b6f73446f745370, 1));
        constexpr u64 baseCount = gOtExtBaseOtCount + 40;
        constexpr u64 numOTs = 129;
        AlignedUnVector<block> baseRecv(baseCount), recvMsg(numOTs);
        AlignedUnVector<std::array<block, 2>> baseSend(baseCount), sendMsg(numOTs);
        BitVector baseChoice(baseCount), choices(numOTs);
        baseChoice.randomize(prng);
        choices.randomize(prng);
        for (u64 i = 0; i < baseCount; ++i)
        {
            baseSend[i][0] = prng.get<block>();
            baseSend[i][1] = prng.get<block>();
            baseRecv[i] = baseSend[i][baseChoice[i]];
        }

        KosDotExtSender sender;
        KosDotExtReceiver receiver;
        sender.setDelta(ZeroBlock);
        sender.setBaseOts(baseRecv, baseChoice);
        receiver.setBaseOts(baseSend);
        auto senderChild = sender.splitBase();
        auto receiverChild = receiver.splitBase();
        if (!senderChild.mHasDelta || senderChild.mDelta != ZeroBlock)
            throw UnitTestFail(LOCATION);

        auto sockets = cp::LocalAsyncSocket::makePair();
        PRNG receiverPrng(block(0x4b6f73446f745265, 2));
        PRNG senderPrng(block(0x4b6f73446f745365, 3));
        auto p0 = receiverChild.receive(choices, recvMsg, receiverPrng, sockets[0]);
        auto p1 = senderChild.send(sendMsg, senderPrng, sockets[1]);
        eval(p0, p1);
        for (u64 i = 0; i < numOTs; ++i)
            if (recvMsg[i] != sendMsg[i][choices[i]] ||
                sendMsg[i][0] != sendMsg[i][1])
                throw UnitTestFail(LOCATION);
#else
        throw UnitTestSkipped("ENABLE_DELTA_KOS is not defined.");
#endif
    }

    void DotExt_Kos_MapReuse_Test()
    {
#if defined(ENABLE_DELTA_KOS)
        PRNG setupPrng(block(0x4b6f73446f744d61, 1));
        constexpr u64 baseCount = gOtExtBaseOtCount + 40;
        constexpr u64 numOTs = 257;
        AlignedUnVector<block> baseRecv(baseCount);
        AlignedUnVector<std::array<block, 2>> baseSend(baseCount);
        BitVector baseChoice(baseCount);
        baseChoice.randomize(setupPrng);
        for (u64 i = 0; i < baseCount; ++i)
        {
            baseSend[i][0] = setupPrng.get<block>();
            baseSend[i][1] = setupPrng.get<block>();
            baseRecv[i] = baseSend[i][baseChoice[i]];
        }

        KosDotExtSender sender;
        KosDotExtReceiver receiver;
        sender.setDelta(setupPrng.get<block>());
        sender.setBaseOts(baseRecv, baseChoice);
        receiver.setBaseOts(baseSend);

        block mapSeed = ZeroBlock;
        for (u64 round = 0; round < 3; ++round)
        {
            auto sockets = cp::LocalAsyncSocket::makePair();
            PRNG receiverPrng(block(0x4b6f73446f744d72, round));
            PRNG senderPrng(block(0x4b6f73446f744d73, round));
            BitVector choices(numOTs);
            choices.randomize(receiverPrng);
            AlignedUnVector<block> recvMsg(numOTs);
            AlignedUnVector<std::array<block, 2>> sendMsg(numOTs);

            auto p0 = receiver.receive(choices, recvMsg, receiverPrng, sockets[0]);
            auto p1 = sender.send(sendMsg, senderPrng, sockets[1]);
            eval(p0, p1);
            OT_100Receive_Test(choices, recvMsg, sendMsg);

            const auto senderSeed = sender.mCodeState->seed();
            const auto receiverSeed = receiver.mCodeState->seed();
            if (senderSeed != receiverSeed || (round && senderSeed != mapSeed))
                throw UnitTestFail("KOS-Dot changed its compression map across calls");
            mapSeed = senderSeed;
        }

        auto senderChild = sender.splitBase();
        auto receiverChild = receiver.splitBase();
        if (senderChild.mCodeState != sender.mCodeState ||
            receiverChild.mCodeState != receiver.mCodeState ||
            senderChild.mCodeState->seed() != mapSeed ||
            receiverChild.mCodeState->seed() != mapSeed)
            throw UnitTestFail("KOS-Dot split did not retain its compression map");

        details::KosDotCodeState mismatch;
        if (!mismatch.initReceiver(block(1, 2)) ||
            mismatch.initReceiver(block(3, 4)))
            throw UnitTestFail("KOS-Dot accepted a changed compression map");
#else
        throw UnitTestSkipped("ENABLE_DELTA_KOS is not defined.");
#endif
    }
}

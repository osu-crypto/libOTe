#include "Subfield_Test.h"
#include "libOTe/Tools/Subfield/Subfield.h"
#include "libOTe/Tools/Subfield/ExConvCode.h"
#include "libOTe/Vole/Subfield/NoisyVoleSender.h"
#include "libOTe/Vole/Subfield/NoisyVoleReceiver.h"
#include "libOTe/Vole/Subfield/SilentVoleSender.h"
#include "libOTe/Vole/Subfield/SilentVoleReceiver.h"

#include "Common.h"

namespace osuCrypto::Subfield
{

    using tests_libOTe::eval;

    void Subfield_ExConvCode_encode_test(const oc::CLP& cmd)
    {
        {
            u64 n = 1024;
            ExConvCode<TypeTraitF128> code;
            code.config(n / 2, n, 7, 24, true);

            PRNG prng(ZeroBlock);
            block delta = prng.get<block>();
            std::vector<block> y(n), z0(n), z1(n);
            prng.get(y.data(), y.size());
            prng.get(z0.data(), z0.size());
            for (u64 i = 0; i < n; ++i)
            {
                z1[i] = z0[i] ^ delta.gf128Mul(y[i]);
            }

            code.dualEncode<block>(z1);
//            code.dualEncode<block>(z0);
//            code.dualEncode<block>(y);
            code.dualEncode2<block, block>(z0, y);

            for (u64 i = 0; i < n; ++i)
            {
                block left = delta.gf128Mul(y[i]);
                block right = z1[i] ^ z0[i];
                if (left != right)
                    throw RTE_LOC;
            }
        }

        {
            u64 n = 1024;
            ExConvCode<TypeTraitPrimitive<u8>> code;
            code.config(n / 2, n, 7, 24, true);

            PRNG prng(ZeroBlock);
            u8 delta = 111;
            std::vector<u8> y(n), z0(n), z1(n);
            prng.get(y.data(), y.size());
            prng.get(z0.data(), z0.size());
            for (u64 i = 0; i < n; ++i)
            {
                z1[i] = z0[i] + delta * y[i];
            }

            code.dualEncode<u8>(z1);
            code.dualEncode2<u8, u8>(z0, y);

            for (u64 i = 0; i < n; ++i)
            {
                u8 left = delta * y[i];
                u8 right = z1[i] - z0[i];
                if (left != right)
                    throw RTE_LOC;
            }
        }

        {
            u64 n = 1024;
            ExConvCode<TypeTrait64> code;
            code.config(n / 2, n, 7, 24, true);

            PRNG prng(ZeroBlock);
            u64 delta = 111;
            std::vector<u64> y(n), z0(n), z1(n);
            prng.get(y.data(), y.size());
            prng.get(z0.data(), z0.size());
            for (u64 i = 0; i < n; ++i)
            {
                z1[i] = z0[i] + delta * y[i];
            }

            code.dualEncode<u64>(z1);
            code.dualEncode2<u64, u64>(z0, y);

            for (u64 i = 0; i < n; ++i)
            {
                u64 left = delta * y[i];
                u64 right = z1[i] - z0[i];
                if (left != right)
                    throw RTE_LOC;
            }
        }
    }

    void Subfield_Tools_Pprf_test(const oc::CLP& cmd) {
#if defined(ENABLE_SILENTOT) || defined(ENABLE_SILENT_VOLE)

        //{
        //    u64 domain = cmd.getOr("d", 16);
        //    auto threads = cmd.getOr("t", 1);
        //    u64 numPoints = cmd.getOr("s", 1) * 8;

        //    PRNG prng(ZeroBlock);

        //    auto sockets = cp::LocalAsyncSocket::makePair();

        //    auto format = PprfOutputFormat::Interleaved;
        //    SilentSubfieldPprfSender<TypeTrait128> sender;
        //    SilentSubfieldPprfReceiver<TypeTrait128> recver;

        //    sender.configure(domain, numPoints);
        //    recver.configure(domain, numPoints);

        //    auto numOTs = sender.baseOtCount();
        //    std::vector<std::array<block, 2>> sendOTs(numOTs);
        //    std::vector<block> recvOTs(numOTs);
        //    BitVector recvBits = recver.sampleChoiceBits(domain * numPoints, format, prng);
        //    //recvBits.randomize(prng);

        //    //recvBits[16] = 1;
        //    prng.get(sendOTs.data(), sendOTs.size());
        //    for (u64 i = 0; i < numOTs; ++i) {
        //        //recvBits[i] = 0;
        //        recvOTs[i] = sendOTs[i][recvBits[i]];
        //    }
        //    sender.setBase(sendOTs);
        //    recver.setBase(recvOTs);

        //    //auto cols = (numPoints * domain + 127) / 128;
        //    Matrix<u128> sOut2(numPoints * domain, 1);
        //    Matrix<u128> rOut2(numPoints * domain, 1);
        //    std::vector<u64> points(numPoints);
        //    recver.getPoints(points, format);

        //    std::vector<u128> arr(numPoints);
        //    prng.get(arr.data(), arr.size());
        //    auto p0 = sender.expand(sockets[0], arr, prng, sOut2, format, true, threads);
        //    auto p1 = recver.expand(sockets[1], prng, rOut2, format, true, threads);

        //    eval(p0, p1);
        //    for (u64 i = 0; i < numPoints; i++) {
        //        u64 point = points[i];
        //        auto exp = sOut2(point) + arr[i];
        //        if (exp != rOut2(point)) {
        //            throw RTE_LOC;
        //        }
        //    }
        //}

#else
        throw UnitTestSkipped("ENABLE_SILENTOT not defined.");
#endif
    }

    void Subfield_Noisy_Vole_test(const oc::CLP& cmd) {

        {
            Timer timer;
            timer.setTimePoint("start");
            u64 n = cmd.getOr("n", 400);
            block seed = block(0, cmd.getOr("seed", 0));
            PRNG prng(seed);

            u64 x = prng.get();
            std::vector<u64> y(n);
            std::vector<u64> z0(n), z1(n);
            prng.get(y.data(), y.size());

            NoisySubfieldVoleReceiver<TypeTrait64> recv;
            NoisySubfieldVoleSender<TypeTrait64> send;

            recv.setTimer(timer);
            send.setTimer(timer);

            auto chls = cp::LocalAsyncSocket::makePair();
            timer.setTimePoint("net");

            BitVector recvChoice((u8*)&x, 64);
            std::vector<block> otRecvMsg(64);
            std::vector<std::array<block, 2>> otSendMsg(64);
            prng.get<std::array<block, 2>>(otSendMsg);
            for (u64 i = 0; i < 64; ++i)
                otRecvMsg[i] = otSendMsg[i][recvChoice[i]];
            timer.setTimePoint("ot");

            auto p0 = recv.receive(y, z0, prng, otSendMsg, chls[0]);
            auto p1 = send.send(x, z1, prng, otRecvMsg, chls[1]);

            eval(p0, p1);

            for (u64 i = 0; i < n; ++i)
            {
                if (x * y[i] != (z1[i] - z0[i]))
                {
                    throw RTE_LOC;
                }
            }
            timer.setTimePoint("done");

            //std::cout << timer << std::endl;
        }

        {
            Timer timer;
            timer.setTimePoint("start");
            u64 n = cmd.getOr("n", 400);
            block seed = block(0, cmd.getOr("seed", 0));
            PRNG prng(seed);

            constexpr size_t N = 3;
            using TypeTrait = TypeTraitVec<u32, N>;
            u64 bitsF = TypeTrait::bitsF;
            using F = TypeTrait::F;
            using G = TypeTrait::G;

            F x = TypeTrait::fromBlock(prng.get<block>());
            std::vector<G> y(n);
            std::vector<F> z0(n), z1(n);
            prng.get(y.data(), y.size());

            NoisySubfieldVoleReceiver<TypeTrait> recv;
            NoisySubfieldVoleSender<TypeTrait> send;

            recv.setTimer(timer);
            send.setTimer(timer);

            auto chls = cp::LocalAsyncSocket::makePair();
            timer.setTimePoint("net");

            BitVector recvChoice((u8*)&x, bitsF);
            std::vector<block> otRecvMsg(bitsF);
            std::vector<std::array<block, 2>> otSendMsg(bitsF);
            prng.get<std::array<block, 2>>(otSendMsg);
            for (u64 i = 0; i < bitsF; ++i)
                otRecvMsg[i] = otSendMsg[i][recvChoice[i]];
            timer.setTimePoint("ot");

            auto p0 = recv.receive(y, z0, prng, otSendMsg, chls[0]);
            auto p1 = send.send(x, z1, prng, otRecvMsg, chls[1]);

            eval(p0, p1);
            //      std::cout << "transferred " << (chls[0].bytesSent() + chls[0].bytesReceived()) << std::endl;
            timer.setTimePoint("verify");

            for (u64 i = 0; i < n; ++i)
            {
                for (u64 j = 0; j < N; j++) {
                    G left = x[j] * y[i];
                    G right = z1[i][j] - z0[i][j];
                    if (left != right)
                    {
                        throw RTE_LOC;
                    }
                }
            }
            timer.setTimePoint("done");

            //      std::cout << timer << std::endl;
        }

        {
            Timer timer;
            timer.setTimePoint("start");
            u64 n = cmd.getOr("n", 400);
            block seed = block(0, cmd.getOr("seed", 0));
            PRNG prng(seed);

            block x = prng.get();
            std::vector<block> y(n);
            std::vector<block> z0(n), z1(n);
            prng.get(y.data(), y.size());

            NoisySubfieldVoleReceiver<TypeTraitF128> recv;
            NoisySubfieldVoleSender<TypeTraitF128> send;

            recv.setTimer(timer);
            send.setTimer(timer);

            auto chls = cp::LocalAsyncSocket::makePair();
            timer.setTimePoint("net");

            size_t k = 128;
            BitVector recvChoice((u8*)&x, k);
            std::vector<block> otRecvMsg(k);
            std::vector<std::array<block, 2>> otSendMsg(k);
            prng.get<std::array<block, 2>>(otSendMsg);
            for (u64 i = 0; i < k; ++i)
                otRecvMsg[i] = otSendMsg[i][recvChoice[i]];
            timer.setTimePoint("ot");

            auto p0 = recv.receive(y, z0, prng, otSendMsg, chls[0]);
            auto p1 = send.send(x, z1, prng, otRecvMsg, chls[1]);

            eval(p0, p1);

            for (u64 i = 0; i < n; ++i)
            {
                if (x.gf128Mul(y[i]) != (z1[i] ^ z0[i]))
                {
                    throw RTE_LOC;
                }
            }
            timer.setTimePoint("done");

            //std::cout << timer << std::endl;
        }
    }

    void Subfield_Silent_Vole_test(const oc::CLP& cmd) {
        using namespace oc::Subfield;
#if defined(ENABLE_SILENTOT)
        Timer timer;
        timer.setTimePoint("start");
        u64 n = cmd.getOr("n", 102043);
        u64 nt = cmd.getOr("nt", std::thread::hardware_concurrency());
        block seed = block(0, cmd.getOr("seed", 0));

        {
            PRNG prng(seed);
            u64 x = TypeTrait64::fromBlock(prng.get<block>());
            std::vector<u64> c(n), z0(n), z1(n);

            SilentSubfieldVoleReceiver<TypeTrait64> recv;
            SilentSubfieldVoleSender<TypeTrait64> send;

            recv.mMultType = MultType::ExConv7x24;
            send.mMultType = MultType::ExConv7x24;

            recv.setTimer(timer);
            send.setTimer(timer);

//            recv.mDebug = true;
//            send.mDebug = true;

            auto chls = cp::LocalAsyncSocket::makePair();

            timer.setTimePoint("net");

            timer.setTimePoint("ot");
            //  fakeBase(n, nt, prng, x, recv, send);

            auto p0 = send.silentSend(x, span<u64>(z0), prng, chls[0]);
            auto p1 = recv.silentReceive(span<u64>(c), span<u64>(z1), prng, chls[1]);

            eval(p0, p1);
            timer.setTimePoint("send");
            for (u64 i = 0; i < n; ++i) {
                u64 left = c[i] * x;
                u64 right = z1[i] - z0[i];
                if (left != right) {
                    std::cout << "bad " << i << "\n  c[i] " << c[i] << " * x " << x << " = " << left << std::endl;
                    std::cout << "z0[i] " << z0[i] << " - z1 " << z1[i] << " = " << right << std::endl;
                    throw RTE_LOC;
                }
            }
        }

        {
            PRNG prng(seed);
            constexpr size_t N = 10;
            using TypeTrait = TypeTraitVec<u32, N>;
            using F = TypeTrait::F;
            using G = TypeTrait::G;
            F x = TypeTrait::fromBlock(prng.get<block>());
            std::vector<G> c(n);
            std::vector<F> z0(n), z1(n);

            SilentSubfieldVoleReceiver<TypeTrait> recv;
            SilentSubfieldVoleSender<TypeTrait> send;

            recv.mMultType = MultType::ExConv7x24;
            send.mMultType = MultType::ExConv7x24;

            recv.setTimer(timer);
            send.setTimer(timer);

            //    recv.mDebug = true;
            //    send.mDebug = true;

            auto chls = cp::LocalAsyncSocket::makePair();

            timer.setTimePoint("net");

            timer.setTimePoint("ot");
            //  fakeBase(n, nt, prng, x, recv, send);

            auto p0 = send.silentSend(x, span<F>(z0), prng, chls[0]);
            auto p1 = recv.silentReceive(span<G>(c), span<F>(z1), prng, chls[1]);

            eval(p0, p1);
            //    std::cout << "transferred " << (chls[0].bytesSent() + chls[0].bytesReceived()) << std::endl;
            timer.setTimePoint("verify");

            timer.setTimePoint("send");
            for (u64 i = 0; i < n; i++) {
                for (u64 j = 0; j < N; j++) {
                    G left = c[i] * x[j];
                    G right = z1[i][j] - z0[i][j];
                    if (left != right) {
                        std::cout << "bad " << i << "\n  c[i] " << c[i] << " * x[j] " << x[j] << " = " << left << std::endl;
                        std::cout << "z0[i][j] " << z0[i][j] << " - z1 " << z1[i][j] << " = " << right << std::endl;
                        throw RTE_LOC;
                    }
                }
            }
        }

        {
            PRNG prng(seed);
            block x = prng.get();
            std::vector<block> c(n), z0(n), z1(n);

            SilentSubfieldVoleReceiver<TypeTraitF128> recv;
            SilentSubfieldVoleSender<TypeTraitF128> send;

            recv.mMultType = MultType::ExConv7x24;
            send.mMultType = MultType::ExConv7x24;

            recv.setTimer(timer);
            send.setTimer(timer);

//            recv.mDebug = true;
//            send.mDebug = true;

            auto chls = cp::LocalAsyncSocket::makePair();

            timer.setTimePoint("net");

            timer.setTimePoint("ot");
            //  fakeBase(n, nt, prng, x, recv, send);

            auto p0 = send.silentSend(x, span<block>(z0), prng, chls[0]);
            auto p1 = recv.silentReceive(span<block>(c), span<block>(z1), prng, chls[1]);

            eval(p0, p1);
            timer.setTimePoint("send");
            for (u64 i = 0; i < n; ++i) {
                block left = x.gf128Mul(c[i]);
                block right = z1[i] ^ z0[i];
                if (left != right) {
                    std::cout << "bad " << i << "\n  c[i] " << c[i] << " * x " << x << " = " << left << std::endl;
                    std::cout << "z0[i] " << z0[i] << " - z1 " << z1[i] << " = " << right << std::endl;
                    throw RTE_LOC;
                }
            }
        }

        timer.setTimePoint("done");
        //  std::cout << timer << std::endl;
#else
        throw UnitTestSkipped("not defined." LOCATION);
#endif
    }

}
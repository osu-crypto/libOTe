#include "Subfield_Test.h"
#include "libOTe/Tools/Subfield/Subfield.h"
#include "libOTe/Tools/ExConvCode/ExConvCode2.h"
#include "libOTe/Vole/Subfield/NoisyVoleSender.h"
#include "libOTe/Vole/Subfield/NoisyVoleReceiver.h"
#include "libOTe/Vole/Subfield/SilentVoleSender.h"
#include "libOTe/Vole/Subfield/SilentVoleReceiver.h"

#include "Common.h"

namespace osuCrypto
{
    static_assert(std::is_trivially_copyable_v<std::array<u32, 10>>);
    static_assert(std::is_trivially_copyable_v<block>);

    using tests_libOTe::eval;

    template<typename F, typename G, typename Trait>
    void subfield_vole_test(u64 n)
    {
        PRNG prng(CCBlock);

        F delta = prng.get();
        std::vector<G> c(n);
        std::vector<F> a(n), b(n);
        prng.get(c.data(), c.size());

        NoisySubfieldVoleReceiver<F, G, Trait> recv;
        NoisySubfieldVoleSender<F, G, Trait> send;

        auto chls = cp::LocalAsyncSocket::makePair();

        BitVector recvChoice = Trait::binaryDecomposition(delta);
        std::vector<block> otRecvMsg(recvChoice.size());
        std::vector<std::array<block, 2>> otSendMsg(recvChoice.size());
        prng.get<std::array<block, 2>>(otSendMsg);
        for (u64 i = 0; i < recvChoice.size(); ++i)
            otRecvMsg[i] = otSendMsg[i][recvChoice[i]];

        // compute a,b such that
        // 
        //   a = b + c * delta
        //
        auto p0 = recv.receive(c, a, prng, otSendMsg, chls[0]);
        auto p1 = send.send(delta, b, prng, otRecvMsg, chls[1]);

        eval(p0, p1);

        for (u64 i = 0; i < n; ++i)
        {
            F prod, sum;

            Trait::mul(prod, delta, c[i]);
            Trait::minus(sum, a[i], b[i]);

            if (prod != sum)
            {
                throw RTE_LOC;
            }
        }
    }

    void Subfield_Noisy_Vole_test(const oc::CLP& cmd) 
    {

        for (u64 n : {1, 8, 433})
        {
            subfield_vole_test<u8, u8, CoeffCtxInteger>(n);
            subfield_vole_test<u64, u32, CoeffCtxInteger>(n);
            subfield_vole_test<block, block, CoeffCtxGFBlock>(n);
            subfield_vole_test<std::array<u32, 11>, u32, CoeffCtxArray<u32, 11>>(n);
        }
    }

    void Subfield_Silent_Vole_test(const oc::CLP& cmd) {
        using namespace oc;
#if defined(ENABLE_SILENTOT)
        Timer timer;
        timer.setTimePoint("start");
        u64 n = cmd.getOr("n", 102043);
        u64 nt = cmd.getOr("nt", std::thread::hardware_concurrency());
        block seed = block(0, cmd.getOr("seed", 0));

        //{
        //    PRNG prng(seed);
        //    u64 x = prng.get<u64>();
        //    std::vector<u64> c(n), z0(n), z1(n);

        //    SilentSubfieldVoleReceiver<u64> recv;
        //    SilentSubfieldVoleSender<u64> send;

        //    recv.mMultType = MultType::ExConv7x24;
        //    send.mMultType = MultType::ExConv7x24;

        //    recv.setTimer(timer);
        //    send.setTimer(timer);

        //    //            recv.mDebug = true;
        //    //            send.mDebug = true;

        //    auto chls = cp::LocalAsyncSocket::makePair();

        //    timer.setTimePoint("net");

        //    timer.setTimePoint("ot");
        //    //  fakeBase(n, nt, prng, delta, recv, send);

        //    auto p0 = send.silentSend(x, span<u64>(z0), prng, chls[0]);
        //    auto p1 = recv.silentReceive(span<u64>(c), span<u64>(z1), prng, chls[1]);

        //    eval(p0, p1);
        //    timer.setTimePoint("send");
        //    for (u64 i = 0; i < n; ++i) {
        //        u64 left = c[i] * x;
        //        u64 right = z1[i] - z0[i];
        //        if (left != right) {
        //            std::cout << "bad " << i << "\n  c[i] " << c[i] << " * x " << x << " = " << left << std::endl;
        //            std::cout << "z0[i] " << z0[i] << " - z1 " << z1[i] << " = " << right << std::endl;
        //            throw RTE_LOC;
        //        }
        //    }
        //}

        //{
        //    PRNG prng(seed);
        //    constexpr size_t N = 10;
        //    using G = u32;
        //    using F = std::array<G, N>;
        //    using CoeffCtx = CoeffCtxArray<G, N>;
        //    F x;
        //    CoeffCtx::fromBlock<F>(x, prng.get<block>());
        //    std::vector<G> c(n);
        //    std::vector<F> a(n), b(n);

        //    SilentSubfieldVoleReceiver<F, G, CoeffCtx> recv;
        //    SilentSubfieldVoleSender<F, G, CoeffCtx> send;

        //    recv.mMultType = MultType::ExConv7x24;
        //    send.mMultType = MultType::ExConv7x24;

        //    recv.setTimer(timer);
        //    send.setTimer(timer);

        //    //    recv.mDebug = true;
        //    //    send.mDebug = true;

        //    auto chls = cp::LocalAsyncSocket::makePair();

        //    timer.setTimePoint("net");

        //    timer.setTimePoint("ot");
        //    //  fakeBase(n, nt, prng, delta, recv, send);

        //    auto p0 = send.silentSend(x, span<F>(b), prng, chls[0]);
        //    auto p1 = recv.silentReceive(span<G>(c), span<F>(a), prng, chls[1]);

        //    eval(p0, p1);
        //    //    std::cout << "transferred " << (chls[0].bytesSent() + chls[0].bytesReceived()) << std::endl;
        //    timer.setTimePoint("verify");

        //    timer.setTimePoint("send");
        //    for (u64 i = 0; i < n; i++) {
        //        for (u64 j = 0; j < N; j++) {
        //            throw RTE_LOC;// fix this
        //            // c = a delta + b
        //            // c - b = a delta
        //            //G left = a[i] * delta[j];
        //            //G right = c[i][j] - b[i][j];
        //            //if (left != right) {
        //            //    std::cout << "bad " << i << "\n  a[i] " << a[i] << " * delta[j] " << delta[j] << " = " << left << std::endl;
        //            //    std::cout << "c[i][j] " << c[i][j] << " - b " << b[i][j] << " = " << right << std::endl;
        //            //    throw RTE_LOC;
        //            //}
        //        }
        //    }
        //}

        //{
        //    PRNG prng(seed);
        //    block x = prng.get();
        //    std::vector<block> c(n), z0(n), z1(n);

        //    SilentSubfieldVoleReceiver<block> recv;
        //    SilentSubfieldVoleSender<block> send;

        //    recv.mMultType = MultType::ExConv7x24;
        //    send.mMultType = MultType::ExConv7x24;

        //    recv.setTimer(timer);
        //    send.setTimer(timer);

        //    //            recv.mDebug = true;
        //    //            send.mDebug = true;

        //    auto chls = cp::LocalAsyncSocket::makePair();

        //    timer.setTimePoint("net");

        //    timer.setTimePoint("ot");
        //    //  fakeBase(n, nt, prng, delta, recv, send);

        //    auto p0 = send.silentSend(x, span<block>(z0), prng, chls[0]);
        //    auto p1 = recv.silentReceive(span<block>(c), span<block>(z1), prng, chls[1]);

        //    eval(p0, p1);
        //    timer.setTimePoint("send");
        //    for (u64 i = 0; i < n; ++i) {
        //        block left = x.gf128Mul(c[i]);
        //        block right = z1[i] ^ z0[i];
        //        if (left != right) {
        //            std::cout << "bad " << i << "\n  c[i] " << c[i] << " * x " << x << " = " << left << std::endl;
        //            std::cout << "z0[i] " << z0[i] << " - z1 " << z1[i] << " = " << right << std::endl;
        //            throw RTE_LOC;
        //        }
        //    }
        //}
        //timer.setTimePoint("done");
        //  std::cout << timer << std::endl;
#else
        throw UnitTestSkipped("not defined." LOCATION);
#endif
    }

}
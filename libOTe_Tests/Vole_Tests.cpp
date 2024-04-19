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

    template<typename R, typename S, typename F, typename Ctx>
    void fakeBase(
        u64 n,
        PRNG& prng,
        F delta,
        R& recver,
        S& sender,
        Ctx ctx)
    {
        sender.configure(n, SilentBaseType::Base, 128);
        recver.configure(n, SilentBaseType::Base, 128);


        std::vector<std::array<block, 2>> msg2(sender.silentBaseOtCount());
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
        auto c = recver.sampleBaseVoleVals(prng);
        typename Ctx::template Vec<F> a(c.size()), b(c.size());

        prng.get(b.data(), b.size());
        for (auto i : rng(c.size()))
        {
            ctx.mul(a[i], delta, c[i]);
            ctx.plus(a[i], b[i], a[i]);
        }
        sender.setSilentBaseOts(msg2, b);
        recver.setSilentBaseOts(msg, a);
    }

}


template<typename F, typename G, typename Ctx>
void Vole_Silent_test_impl(u64 n, MultType type, bool debug, bool doFakeBase, bool mal)
{
    using VecF = typename Ctx::template Vec<F>;
    using VecG = typename Ctx::template Vec<G>;
    Ctx ctx;

    block seed = CCBlock;
    PRNG prng(seed);

    auto chls = cp::LocalAsyncSocket::makePair();

    SilentVoleReceiver<F, G, Ctx> recv;
    SilentVoleSender<F, G, Ctx> send;
    recv.mMultType = type;
    send.mMultType = type;
    recv.mDebug = debug;
    send.mDebug = debug;
    if (mal)
    {
        recv.mMalType = SilentSecType::Malicious;
        send.mMalType = SilentSecType::Malicious;
    }

    VecF a(n), b(n);
    VecG c(n);
    F d = prng.get();

    if (doFakeBase)
        fakeBase(n, prng, d, recv, send, ctx);

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


void Vole_Silent_paramSweep_test(const oc::CLP& cmd)
{
    auto debug = cmd.isSet("debug");
    for (u64 n : {128, 45364})
    {
        Vole_Silent_test_impl<u64, u64, CoeffCtxInteger>(n, DefaultMultType, debug, false, false);
        Vole_Silent_test_impl<block, block, CoeffCtxGF128>(n, DefaultMultType, debug, false, false);
        Vole_Silent_test_impl<block, bool, CoeffCtxGF2>(n, DefaultMultType, debug, false, false);
        Vole_Silent_test_impl<std::array<u32, 8>, u32, CoeffCtxArray<u32, 8>>(n, DefaultMultType, debug, false, false);
    }
}

void Vole_Silent_QuasiCyclic_test(const oc::CLP& cmd)
{
#if defined(ENABLE_BITPOLYMUL)
    auto debug = cmd.isSet("debug");
    for (u64 n : {128, 333})
        Vole_Silent_test_impl<block, block, CoeffCtxGF128>(n, MultType::QuasiCyclic, debug, false, false);
#else
    throw UnitTestSkipped("ENABLE_BITPOLYMUL not defined." LOCATION);
#endif
}
void Vole_Silent_Tungsten_test(const oc::CLP& cmd)
{
    auto debug = cmd.isSet("debug");
    for (u64 n : {128, 33341})
        Vole_Silent_test_impl<block, block, CoeffCtxGF128>(n, MultType::Tungsten, debug, false, false);
}


void Vole_Silent_baseOT_test(const oc::CLP& cmd)
{
    auto debug = cmd.isSet("debug");
    u64 n = 128;
    Vole_Silent_test_impl<u64, u64, CoeffCtxInteger>(n, DefaultMultType, debug, true, false);
    Vole_Silent_test_impl<block, block, CoeffCtxGF128>(n, DefaultMultType, debug, true, false);
    Vole_Silent_test_impl<std::array<u32, 8>, u32, CoeffCtxArray<u32, 8>>(n, DefaultMultType, debug, true, false);
}



void Vole_Silent_mal_test(const oc::CLP& cmd)
{
    auto debug = cmd.isSet("debug");
    for (u64 n : {45364})
    {
        Vole_Silent_test_impl<block, block, CoeffCtxGF128>(n, DefaultMultType, debug, false, true);
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

    send.mMalType = SilentSecType::SemiHonest;
    recv.mMalType = SilentSecType::SemiHonest;
    for (u64 jj : {0, 1})
    {

        send.configure(n, SilentBaseType::Base);
        recv.configure(n, SilentBaseType::Base);
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
#if (defined ENABLE_MRR_TWIST && defined ENABLE_SSE) || \
                defined ENABLE_MR || defined ENABLE_MRR
                u64 expRound = 3;
#else
                u64 expRound = 5;
#endif

                auto rounds = eval(p0, p1, chls[1], chls[0]);
                if (rounds != expRound)
                    throw std::runtime_error(std::to_string(rounds) + "!=" + std::to_string(expRound) + ". " + COPROTO_LOCATION);


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


                auto p0 = send.genSilentBaseOts(prng, chls[0], x);
                auto p1 = recv.genSilentBaseOts(prng, chls[1]);

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
void Vole_Noisy_test(const oc::CLP& cmd) { throwDisabled(); }
void Vole_Silent_QuasiCyclic_test(const oc::CLP& cmd) { throwDisabled(); }
void Vole_Silent_paramSweep_test(const oc::CLP& cmd) { throwDisabled(); }
void Vole_Silent_baseOT_test(const oc::CLP& cmd) { throwDisabled(); }
void Vole_Silent_mal_test(const oc::CLP& cmd) { throwDisabled(); }
void Vole_Silent_Rounds_test(const oc::CLP& cmd) { throwDisabled(); }
void Vole_Silent_Tungsten_test(const oc::CLP& cmd) { throwDisabled(); }


#endif
//
//
//void Vole_Silent_QuasiCyclic_test(const oc::CLP& cmd) { throwDisabled(); }
//void Vole_Silent_Silver_test(const oc::CLP& cmd) { throwDisabled(); }
//void Vole_Silent_paramSweep_test(const oc::CLP& cmd) { throwDisabled(); }
//void Vole_Silent_baseOT_test(const oc::CLP& cmd) { throwDisabled(); }
//void Vole_Silent_mal_test(const oc::CLP& cmd) { throwDisabled(); }
//void Vole_Silent_Rounds_test(const oc::CLP& cmd) { throwDisabled(); }

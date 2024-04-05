#include "SilentOT_Tests.h"

#include "libOTe/TwoChooseOne/Silent/SilentOtExtSender.h"
#include "libOTe/TwoChooseOne/Silent/SilentOtExtReceiver.h"
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Range.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Common/TestCollection.h>
#include "libOTe/Tools/Tools.h"
#include "libOTe/Tools/QuasiCyclicCode.h"
#include "Common.h"
using namespace oc;

void Tools_bitShift_test(const CLP& cmd)
{
#ifdef ENABLE_BITPOLYMUL
    //u64 nBits = ;
    u64 n = cmd.getOr("n", 10);// (nBits + 127) / 128;
    u64 t = cmd.getOr("t", 10);

    PRNG prng(toBlock(cmd.getOr("seed", 0)));

    std::vector<block> dest(n), in;
    prng.get(dest.data(), dest.size());



    //std::cout << "a " << (_mm_slli_epi64(AllOneBlock, 20)) << std::endl;
    //std::cout << "b " << (_mm_srli_epi64(AllOneBlock, 20)) << std::endl;

    for (u64 i = 0; i < t; ++i)
    {
        u8 bitShift = prng.get<u8>() % 128;

        u64 inSize = std::max<u64>(1, n + (i & 1 ? 1 : -1));
        u64 inBits = std::min<u64>(n * 128, inSize * 128 - bitShift);

        in.resize(inSize);
        prng.get(in.data(), in.size());


        memset(dest.data(), 0, dest.size() * 16);

        BitVector dv((u8*)dest.data(), n * 128);
        BitVector iv, ivt((u8*)in.data(), in.size() * 128);
        iv.append((u8*)in.data(), inBits, bitShift);
        iv.resize(n * 128, 0);
        auto dv1 = dv;

        dv ^= iv;

        QuasiCyclicCode::bitShiftXor(dest, in, bitShift);


        BitVector dv2((u8*)dest.data(), n * 128);

        if (dv != dv2)
        {
            auto b = (bitShift > 64) ? 128 - bitShift : 64 - bitShift;

            std::cout << "\n" << int(bitShift) << "\n";
            std::cout << " i* " << ivt << std::endl;
            std::cout << " i  " << iv << std::endl;
            std::cout << " d  " << dv1 << std::endl;

            std::cout << "   " << std::string(b, ' ') << std::string(bitShift, 'x') << '\n';
            std::cout << "act " << dv2 << std::endl;
            std::cout << "exp " << dv << std::endl;
            std::cout << "    " << (dv2 ^ dv) << std::endl;
            throw RTE_LOC;
        }

    }
#else
    throw UnitTestSkipped("ENABLE_BITPOLYMUL not defined.");
#endif
}

void clearBits(span<block> in, u64 idx)
{
    auto p = (u8*)in.data() + idx / 8;
    auto e = (u8*)in.data() + in.size() * 16;

    if (idx & 7)
    {
        *p++ &= (1 << (idx & 7)) - 1;
    }

    while (p != e)
        *p++ = 0;


    BitVector test((u8*)in.data(), in.size() * 128);
    for (u64 i = idx; i < test.size(); ++i)
        if (test[i])
            throw RTE_LOC;
}


void Tools_modp_test(const CLP& cmd)
{
#ifdef ENABLE_BITPOLYMUL

    PRNG prng(toBlock(cmd.getOr("seed", 0)));

    auto iBits = cmd.getOr("c", 1026ull);
    auto nBits = cmd.getOr("n", 223ull);

    auto n = (nBits + 127) / 128;
    auto c = (iBits + nBits - 1) / nBits;

    std::vector<block> dest(n), in((iBits + 127) / 128);

    for (u64 i = 0; i < dest.size(); ++i)
    {
        u64 p = nBits;// -(prng.get<u64>() % 128);

        prng.get(in.data(), in.size());
        memset(in.data(), -1, in.size() * 16);
        clearBits(in, iBits);

        memset(dest.data(), 0, dest.size() * 16);

        BitVector dv((u8*)in.data(), p);
        BitVector iv;

        //std::cout << "\nin[0] = " << dv << std::endl;

        for (u64 j = 1; j < c; ++j)
        {
            auto rem = std::min<u64>(p, iBits - j * p);
            iv.resize(0);
            iv.append((u8*)in.data(), rem, j * p);

            //std::cout << "in["<<j<<"] = " << iv << std::endl;

            iv.resize(p, 0);
            dv ^= iv;
        }
        //std::cout << "out   = " << dv << std::endl;



        QuasiCyclicCode::modp(dest, in, p);


        BitVector dv2((u8*)dest.data(), p);

        if (dv != dv2)
        {
            //auto b = (bitShift > 64) ? 128 - bitShift : 64 - bitShift;
            auto diff = (dv2 ^ dv);
            std::cout << "\n" << p << "\n";
            //std::cout << "   "
            //    << std::string(b, ' ')
            //    << std::string(bitShift, 'x') << '\n';
            std::cout << "act     " << dv2 << std::endl;
            std::cout << "exp     " << dv << std::endl;
            std::cout << "f       " << diff << std::endl;

            for (u64 i = 0; i < diff.size(); ++i)
                if (diff[i])
                    std::cout << " " << i;
            std::cout << std::endl;

            throw RTE_LOC;
        }

        //std::cout << dv2 << std::endl;

    }

#else
    throw UnitTestSkipped("ENABLE_BITPOLYMUL not defined.");
#endif
}

void Tools_quasiCyclic_test(const oc::CLP& cmd)
{

#ifdef ENABLE_BITPOLYMUL


    QuasiCyclicCode code;
    u64 k = 1 << 10;
    u64 t = 1;
    auto scaler = 2;
    auto n = k * scaler;

    AlignedUnVector<block> A(n), B(n), C(n);

    PRNG prng(oc::ZeroBlock);
    code.init2(k, n);

    for (auto tt : rng(t))
    {
        (void)tt;

        prng.get(A.data(), n);
        prng.get(B.data(), n);

        for (auto i : rng(n))
        {
            C[i] = A[i] ^ B[i];
        }

        code.dualEncode(A);
        code.dualEncode(B);
        code.dualEncode(C);

        for (u64 i : rng(k))
        {
            if (C[i] != (A[i] ^ B[i]))
                throw RTE_LOC;
        }


    }


    for (auto tt : rng(t))
    {
        (void)tt;

        for (u64 i = 0; i < n; ++i)
        {
            A[i] = oc::zeroAndAllOne[prng.getBit()];
        }

        code.dualEncode(A);

        for (u64 i : rng(k))
        {

            if (A[i] != oc::AllOneBlock && A[i] != oc::ZeroBlock)
            {
                std::cout << i << " " << A[i] << std::endl;
                throw RTE_LOC;
            }
        }
    }


    if(cmd.isSet("getMatrix"))
    {
        k = 256;
        n = k * scaler;

        code.init2(k,n);
        auto mtx = code.getMatrix();
        A.resize(n);
        auto bb = 10;

        prng.get(A.data(), n);
        DenseMtx AA(bb, n);

        for (auto i : rng(n))
        {
            for (u64 j : rng(bb))
                AA(j, i) = *BitIterator((u8*)&A[i], j);
        }

        code.dualEncode(A);
        auto A2 = AA * mtx;

        for (auto i : rng(k))
        {
            for (u64 j : rng(bb))
                if (A2(j, i) != *BitIterator((u8*)&A[i], j))
                    throw RTE_LOC;
        }

    }
#else
    throw UnitTestSkipped("ENABLE_BITPOLYMUL not defined.");
#endif
}


#ifdef ENABLE_SILENTOT
namespace {

#ifdef ENABLE_SILENTOT

    void fakeBase(u64 n,
        u64 s,
        u64 threads,
        PRNG& prng,
        SilentOtExtReceiver& recver, SilentOtExtSender& sender)
    {
        sender.configure(n, s, threads);
        auto count = sender.silentBaseOtCount();
        std::vector<std::array<block, 2>> msg2(count);
        for (u64 i = 0; i < msg2.size(); ++i)
        {
            msg2[i][0] = prng.get();
            msg2[i][1] = prng.get();
        }
        sender.setSilentBaseOts(msg2);

        // fake base OTs.
        {
            recver.configure(n, s, threads);
            BitVector choices = recver.sampleBaseChoiceBits(prng);
            std::vector<block> msg(choices.size());
            for (u64 i = 0; i < msg.size(); ++i)
                msg[i] = msg2[i][choices[i]];
            recver.setSilentBaseOts(msg);
        }
    }

    void checkRandom(
        span<block> messages, span<std::array<block, 2>>messages2,
        BitVector& choice, u64 n,
        bool verbose)
    {

        if (messages.size() != n)
            throw RTE_LOC;
        if (messages2.size() != n)
            throw RTE_LOC;
        if (choice.size() != n)
            throw RTE_LOC;
        bool passed = true;

        auto hamming = choice.hammingWeight();
        if(hamming < n / 2 - std::sqrt(n))
            throw RTE_LOC;
        for (u64 i = 0; i < n; ++i)
        {
            block m1 = messages[i];
            block m2a = messages2[i][0];
            block m2b = (messages2[i][1]);
            u8 c = choice[i];


            std::array<bool, 2> eqq{
                eq(m1, m2a),
                eq(m1, m2b)
            };
            if (eqq[c ^ 1] == true)
            {
                passed = false;
                if (verbose)
                    std::cout << Color::Pink;
            }
            if (eqq[0] == false && eqq[1] == false)
            {
                passed = false;
                if (verbose)
                    std::cout << Color::Red;
            }

            if (eqq[c] == false && verbose)
                std::cout << "m" << i << " " << m1 << " != (" << m2a << " " << m2b << ")_" << (int)c << "\n";

        }

        if (passed == false)
            throw RTE_LOC;
    }


    template<typename Choice>
    void checkCorrelated(
        span<block> Ar, span<block> Bs,
        Choice& choice, block delta, u64 n,
        bool verbose,
        ChoiceBitPacking packing)
    {

        if (Ar.size() != n)
            throw RTE_LOC;
        if (Bs.size() != n)
            throw RTE_LOC;
        if (packing == ChoiceBitPacking::False &&
            (u64)choice.size() != n)
            throw RTE_LOC;
        bool passed = true;
        //bool first = true;
        block mask = AllOneBlock ^ OneBlock;

        u64 hamming = 0;

        for (u64 i = 0; i < n; ++i)
        {
            block m1 = Ar[i];
            block m2a = Bs[i];
            block m2b = (Bs[i] ^ delta);
            u8 c, c2;

            if (packing == ChoiceBitPacking::True)
            {
                c = u8((m1 & OneBlock) == OneBlock) & 1;
                m1 = m1 & mask;
                m2a = m2a & mask;
                m2b = m2b & mask;

                if (choice.size())
                {
                    c2 = choice[i];

                    if (c2 != c)
                        throw RTE_LOC;
                }
            }
            else
            {
                c = choice[i];
            }

            hamming += c;

            std::array<bool, 2> eqq{
                eq(m1, m2a),
                eq(m1, m2b)
            };

            bool good = true;
            if (eqq[c] == false || eqq[c ^ 1] == true)
            {
                good = passed = false;
                //if (verbose)
                std::cout << Color::Pink;
            }
            if (eqq[0] == false && eqq[1] == false)
            {
                good = passed = false;
                //if (verbose)
                std::cout << Color::Red;
            }

            if (!good /*&& first*/)
            {
                //first = false;
                std::cout << i << " m " << mask << std::endl;
                std::cout << "r " << m1 << " " << int(c) << std::endl;
                std::cout << "s " << m2a << " " << m2b << std::endl;
                std::cout << "d " << (m1 ^ m2a) << " " << (m1 ^ m2b) << std::endl;
            }

            std::cout << Color::Default;
        }

        if (passed == false)
            throw RTE_LOC;

        if (n > 100 && hamming < n / 2 - std::sqrt(n))
            throw RTE_LOC;
    }

#endif
}
#endif
using namespace tests_libOTe;

void OtExt_Silent_random_Test(const CLP& cmd)
{
#ifdef ENABLE_SILENTOT


    auto sockets = cp::LocalAsyncSocket::makePair();

    u64 n = cmd.getOr("n", 10000);
    bool verbose = cmd.getOr("v", 0) > 1;
    u64 threads = cmd.getOr("t", 4);
    u64 s = cmd.getOr("s", 2);

    PRNG prng(toBlock(cmd.getOr("seed", 0)));
    PRNG prng1(toBlock(cmd.getOr("seed1", 1)));


    SilentOtExtSender sender;
    SilentOtExtReceiver recver;
    fakeBase(n, s, threads, prng, recver, sender);
    auto type = OTType::Random;

    std::vector<block> messages2(n);
    BitVector choice(n);
    std::vector<std::array<block, 2>> messages(n);

    auto p0 = sender.silentSend(messages, prng, sockets[0]);
    auto p1 = recver.silentReceive(choice, messages2, prng, sockets[1], type);

    eval(p0, p1);

    checkRandom(messages2, messages, choice, n, verbose);

#else
    throw UnitTestSkipped("ENABLE_SILENTOT not defined.");
#endif
}


void OtExt_Silent_correlated_Test(const CLP& cmd)
{
#ifdef ENABLE_SILENTOT


    auto sockets = cp::LocalAsyncSocket::makePair();

    u64 n = cmd.getOr("n", 10000);
    bool verbose = cmd.getOr("v", 0) > 1;
    u64 threads = cmd.getOr("t", 4);
    u64 s = cmd.getOr("s", 2);

    PRNG prng(toBlock(cmd.getOr("seed", 0)));
    PRNG prng1(toBlock(cmd.getOr("seed1", 1)));


    SilentOtExtSender sender;
    SilentOtExtReceiver recver;
    fakeBase(n, s, threads, prng, recver, sender);

    block delta = prng.get();

    std::vector<block> messages2(n);
    BitVector choice(n);
    std::vector<block> messages(n);
    auto type = OTType::Correlated;

    auto p0 = sender.silentSend(delta, messages, prng, sockets[0]);
    auto p1 = recver.silentReceive(choice, messages2, prng, sockets[1], type);

    eval(p0, p1);

    checkCorrelated(
        messages, messages2, choice, delta,
        n, verbose, ChoiceBitPacking::False);
#else
    throw UnitTestSkipped("ENABLE_SILENTOT not defined.");
#endif
}



void OtExt_Silent_inplace_Test(const CLP& cmd)
{
#ifdef ENABLE_SILENTOT



    auto sockets = cp::LocalAsyncSocket::makePair();

    u64 n = cmd.getOr("n", 10000);
    bool verbose = cmd.getOr("v", 0) > 1;
    u64 threads = cmd.getOr("t", 4);
    u64 s = cmd.getOr("s", 2);

    PRNG prng(toBlock(cmd.getOr("seed", 0)));
    PRNG prng1(toBlock(cmd.getOr("seed1", 1)));


    SilentOtExtSender sender;
    SilentOtExtReceiver recver;

    block delta = prng.get();

    //auto type = OTType::Correlated;

    {
        fakeBase(n, s, threads, prng, recver, sender);
        auto p0 = sender.silentSendInplace(delta, n, prng, sockets[0]);
        auto p1 = recver.silentReceiveInplace(n, prng, sockets[1]);

        eval(p0, p1);


        auto& messages = recver.mA;
        auto& messages2 = sender.mB;
        auto& choice = recver.mC;
        checkCorrelated(messages, messages2, choice, delta,
            n, verbose, ChoiceBitPacking::False);
    }

    {
        fakeBase(n, s, threads, prng, recver, sender);
        auto p0 = sender.silentSendInplace(delta, n, prng, sockets[0]);
        auto p1 = recver.silentReceiveInplace(n, prng, sockets[1], ChoiceBitPacking::True);

        eval(p0, p1);

        auto& messages = recver.mA;
        auto& messages2 = sender.mB;
        auto& choice = recver.mC;
        checkCorrelated(messages, messages2, choice, delta,
            n, verbose, ChoiceBitPacking::True);

    }
#else
    throw UnitTestSkipped("ENABLE_SILENTOT not defined.");
#endif
}

void OtExt_Silent_paramSweep_Test(const oc::CLP& cmd)
{
#ifdef ENABLE_SILENTOT


    auto sockets = cp::LocalAsyncSocket::makePair();

    std::vector<u64> nn = cmd.getManyOr<u64>("n",
        { 12, /*134,*/433 , /*4234,*/5466 });

    bool verbose = cmd.getOr("v", 0) > 1;
    u64 threads = cmd.getOr("t", 4);
    u64 s = cmd.getOr("s", 2);

    PRNG prng(toBlock(cmd.getOr("seed", 0)));
    PRNG prng1(toBlock(cmd.getOr("seed1", 1)));

    SilentOtExtSender sender;
    SilentOtExtReceiver recver;

    block delta = prng.get();
    //auto type = OTType::Correlated;

    for (auto n : nn)
    {
        fakeBase(n, s, threads, prng, recver, sender);

        auto p0 = sender.silentSendInplace(delta, n, prng, sockets[0]);
        auto p1 = recver.silentReceiveInplace(n, prng, sockets[1]);

        eval(p0, p1);

        checkCorrelated(sender.mB, recver.mA, recver.mC, delta,
            n, verbose, ChoiceBitPacking::False);
    }

#else
    throw UnitTestSkipped("ENABLE_SILENTOT not defined.");
#endif
}


void OtExt_Silent_QuasiCyclic_Test(const oc::CLP& cmd)
{
#if defined(ENABLE_SILENTOT) && defined(ENABLE_BITPOLYMUL)



    auto sockets = cp::LocalAsyncSocket::makePair();

    std::vector<u64> nn = cmd.getManyOr<u64>("n",
        { /*12, 134, 600,*/ 4234/*, 14366 */ });//

    bool verbose = cmd.getOr("v", 0) > 1;
    u64 threads = cmd.getOr("t", 4);
    u64 s = cmd.getOr("s", 2);


    PRNG prng(toBlock(cmd.getOr("seed", 0)));
    PRNG prng1(toBlock(cmd.getOr("seed1", 1)));

    SilentOtExtSender sender;
    SilentOtExtReceiver recver;

    sender.mMultType = MultType::QuasiCyclic;
    recver.mMultType = MultType::QuasiCyclic;

    //sender.mDebug = true;
    //recver.mDebug = true;

    block delta = prng.get();
    //auto type = OTType::Correlated;

    for (auto n : nn)
    {
        //block delta
        std::vector<std::array<block, 2>> msg2(n);
        std::vector<block> msg1(n);
        BitVector choice(n);

        fakeBase(n, s, threads, prng, recver, sender);
        auto p0 = sender.silentSend(msg2, prng, sockets[0]);
        auto p1 = recver.silentReceive(choice, msg1, prng, sockets[1]);

        eval(p0, p1);


        checkRandom(msg1, msg2, choice, n, verbose);

        auto type = ChoiceBitPacking::False;
        fakeBase(n, s, threads, prng, recver, sender);
        p0 = sender.silentSendInplace(delta, n, prng, sockets[0]);
        p1 = recver.silentReceiveInplace(n, prng, sockets[1], type);


        eval(p0, p1);

        checkCorrelated(recver.mA, sender.mB, recver.mC, delta, n, verbose, type);

    }

#else
    throw UnitTestSkipped("ENABLE_SILENTOT or ENABLE_BITPOLYMUL are not defined.");
#endif
}

void OtExt_Silent_Tungsten_Test(const oc::CLP& cmd)
{

#if defined(ENABLE_SILENTOT) 

    auto sockets = cp::LocalAsyncSocket::makePair();

    std::vector<u64> nn = cmd.getManyOr<u64>("n",
        { /*12, 134, 600,*/ 1234/*, 14366 */ });//

    bool verbose = cmd.getOr("v", 0) > 1;
    u64 threads = cmd.getOr("t", 4);
    u64 s = cmd.getOr("s", 2);


    PRNG prng(toBlock(cmd.getOr("seed", 0)));
    PRNG prng1(toBlock(cmd.getOr("seed1", 1)));

    SilentOtExtSender sender;
    SilentOtExtReceiver recver;

    sender.mMultType = MultType::Tungsten;
    recver.mMultType = MultType::Tungsten;


    block delta = prng.get();

    for (auto n : nn)
    {
        std::vector<std::array<block, 2>> msg2(n);
        std::vector<block> msg1(n);
        BitVector choice(n);

        fakeBase(n, s, threads, prng, recver, sender);
        auto p0 = sender.silentSend(msg2, prng, sockets[0]);
        auto p1 = recver.silentReceive(choice, msg1, prng, sockets[1]);

        eval(p0, p1);


        checkRandom(msg1, msg2, choice, n, verbose);

        auto type = ChoiceBitPacking::False;
        fakeBase(n, s, threads, prng, recver, sender);
        p0 = sender.silentSendInplace(delta, n, prng, sockets[0]);
        p1 = recver.silentReceiveInplace(n, prng, sockets[1], type);


        eval(p0, p1);

        checkCorrelated(recver.mA, sender.mB, recver.mC, delta, n, verbose, type);

    }

#else
    throw UnitTestSkipped("ENABLE_SILENTOT or ENABLE_INSECURE_SILVER are not defined.");
#endif
}

void OtExt_Silent_baseOT_Test(const oc::CLP& cmd)
{

#ifdef ENABLE_SILENTOT



    auto sockets = cp::LocalAsyncSocket::makePair();

    u64 n = 123;//

    bool verbose = cmd.getOr("v", 0) > 1;

    PRNG prng(toBlock(cmd.getOr("seed", 0)));
    PRNG prng1(toBlock(cmd.getOr("seed1", 1)));

    SilentOtExtSender sender;
    SilentOtExtReceiver recver;

    //block delta = prng.get();
    //auto type = OTType::Correlated;

    std::vector<std::array<block, 2>> msg2(n);
    std::vector<block> msg1(n);
    BitVector choice(n);

    auto p0 = sender.silentSend(msg2, prng, sockets[0]);
    auto p1 = recver.silentReceive(choice, msg1, prng, sockets[1]);


    eval(p0, p1);

    checkRandom(msg1, msg2, choice, n, verbose);
#else
    throw UnitTestSkipped("ENABLE_SILENTOT not defined.");
#endif
}



void OtExt_Silent_mal_Test(const oc::CLP& cmd)
{

#ifdef ENABLE_SILENTOT



    auto sockets = cp::LocalAsyncSocket::makePair();

    u64 n = 12093;//

    bool verbose = cmd.getOr("v", 0) > 1;

    PRNG prng(toBlock(cmd.getOr("seed", 0)));
    PRNG prng1(toBlock(cmd.getOr("seed1", 1)));

    SilentOtExtSender sender;
    SilentOtExtReceiver recver;

    sender.mMalType = SilentSecType::Malicious;
    recver.mMalType = SilentSecType::Malicious;

    std::vector<std::array<block, 2>> msg2(n);
    std::vector<block> msg1(n);
    BitVector choice(n);

    auto p0 = sender.silentSend(msg2, prng, sockets[0]);
    auto p1 = recver.silentReceive(choice, msg1, prng, sockets[1]);


    eval(p0, p1);

    checkRandom(msg1, msg2, choice, n, verbose);
#else
    throw UnitTestSkipped("ENABLE_SILENTOT not defined.");
#endif
}

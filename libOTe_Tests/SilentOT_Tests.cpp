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
#include "libOTe/Triple/SilentOtTriple/SilentOtTriple.h"

using namespace oc;
using namespace tests_libOTe;

//=================================================================================================
// Utility tests for the underlying encoding components
//=================================================================================================

void Tools_bitShift_test(const CLP& cmd)
{
#ifdef ENABLE_BITPOLYMUL
    // Test parameters
    u64 n = cmd.getOr("n", 10);
    u64 t = cmd.getOr("t", 10);
    PRNG prng(toBlock(cmd.getOr("seed", 0)));

    std::vector<block> dest(n), in;
    prng.get(dest.data(), dest.size());

    // Test bitShiftXor with various shift values
    for (u64 i = 0; i < t; ++i)
    {
        u8 bitShift = prng.get<u8>() % 128;

        u64 inSize = std::max<u64>(1, n + (i & 1 ? 1 : -1));
        u64 inBits = std::min<u64>(n * 128, inSize * 128 - bitShift);

        in.resize(inSize);
        prng.get(in.data(), in.size());
        memset(dest.data(), 0, dest.size() * 16);

        // Create reference bit vectors to compare against
        BitVector dv((u8*)dest.data(), n * 128);
        BitVector iv, ivt((u8*)in.data(), in.size() * 128);
        iv.append((u8*)in.data(), inBits, bitShift);
        iv.resize(n * 128, 0);
        auto dv1 = dv;
        dv ^= iv;

        // Apply bitShiftXor operation
        QuasiCyclicCode::bitShiftXor(dest, in, bitShift);
        BitVector dv2((u8*)dest.data(), n * 128);

        // Verify results
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

// Helper function to clear bits after a specified index
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

    // Verify that bits were properly cleared
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
        u64 p = nBits;

        prng.get(in.data(), in.size());
        memset(in.data(), -1, in.size() * 16);
        clearBits(in, iBits);
        memset(dest.data(), 0, dest.size() * 16);

        // Create reference bit vectors for verification
        BitVector dv((u8*)in.data(), p);
        BitVector iv;

        for (u64 j = 1; j < c; ++j)
        {
            auto rem = std::min<u64>(p, iBits - j * p);
            iv.resize(0);
            iv.append((u8*)in.data(), rem, j * p);
            iv.resize(p, 0);
            dv ^= iv;
        }

        // Apply modp operation
        QuasiCyclicCode::modp(dest, in, p);
        BitVector dv2((u8*)dest.data(), p);

        // Verify results
        if (dv != dv2)
        {
            auto diff = (dv2 ^ dv);
            std::cout << "\n" << p << "\n";
            std::cout << "act     " << dv2 << std::endl;
            std::cout << "exp     " << dv << std::endl;
            std::cout << "f       " << diff << std::endl;

            for (u64 i = 0; i < diff.size(); ++i)
                if (diff[i])
                    std::cout << " " << i;
            std::cout << std::endl;

            throw RTE_LOC;
        }
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

    // Test 1: Linear property - encoding(A ⊕ B) = encoding(A) ⊕ encoding(B)
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

    // Test 2: Binary field property - output consists only of 0/1 blocks
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

    // Test 3: Matrix representation if requested
    if (cmd.isSet("getMatrix"))
    {
        k = 256;
        n = k * scaler;

        code.init2(k, n);
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

//=================================================================================================
// Silent OT Triple tests
//=================================================================================================

void SilentOtTriple_ole_test(const oc::CLP& cmd)
{
#ifdef ENABLE_SILENTOT
    std::array<SilentOtTriple, 2> oles;

    u64 n = 4232;
    auto blocks = divCeil(n, 128);
    bool verbose = cmd.isSet("v");

    PRNG prng0(block(2424523452345, 111124521521455324));
    PRNG prng1(block(6474567454546, 567546754674345444));
    Timer timer;

    // Initialize both parties
    oles[0].init(0, n, SilentSecType::SemiHonest, SilentOtTriple::Type::OLE);
    oles[1].init(1, n, SilentSecType::SemiHonest, SilentOtTriple::Type::OLE);

    // Set up base OTs
    {
        auto otCount0 = oles[0].baseCount(prng0);
        auto otCount1 = oles[1].baseCount(prng1);
        if (otCount0.mRecvChoice.size() != otCount1.mSendCount ||
            otCount0.mSendCount != otCount1.mRecvChoice.size())
            throw RTE_LOC;
        
        std::array<std::vector<std::array<block, 2>>, 2> baseSend;
        baseSend[0].resize(otCount0.mSendCount);
        baseSend[1].resize(otCount1.mSendCount);
        std::array<std::vector<block>, 2> baseRecv;
        std::array<BitVector, 2> baseChoice{
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

        oles[0].setBaseOts(baseSend[1], baseRecv[0]);
        oles[1].setBaseOts(baseSend[1], baseRecv[1]);
    }

    // Create local socket pair for communication
    auto sock = coproto::LocalAsyncSocket::makePair();
    std::vector<block>
        A(blocks),
        B(blocks),
        C0(blocks),
        C1(blocks);

    // Run protocol
    auto r = macoro::sync_wait(macoro::when_all_ready(
        oles[0].expand(A, C0, prng0, sock[0]),
        oles[1].expand(B, C1, prng1, sock[1])));
    std::get<0>(r).result();
    std::get<1>(r).result();

    // Verify OLE correlation: C0 ⊕ C1 = A & B
    for (size_t i = 0; i < blocks; i++)
    {
        auto act = C0[i] ^ C1[i];
        auto exp = A[i] & B[i];

        if (act != exp)
        {
            std::cout << "i " << i << std::endl;
            std::cout << "act " << act << std::endl;
            std::cout << "exp " << exp << std::endl;
            throw RTE_LOC;
        }

        // Additional check for first block to verify triple correlation
        if (i == 0)
        {
            // OLE triple computation:
            // a0 * b0 + a0 * b1 + a1 * b0 + a1 * b1 = c0 + c1
            auto a0 = A[0];
            auto b0 = A[1];
            auto a1 = B[1];
            auto b1 = B[0];

            auto c0 = (a0 & b0) ^ C0[0] ^ C0[1];
            auto c1 = (a1 & b1) ^ C1[0] ^ C1[1];

            if (((a0 ^ a1) & (b0 ^ b1)) != (c0 ^ c1))
                throw RTE_LOC;
        }
    }

    if (verbose)
        std::cout << "Time taken: \n" << timer << std::endl;
#else
    throw UnitTestSkipped("ENABLE_SILENTOT not defined.");
#endif
}

void SilentOtTriple_triple_test(const oc::CLP& cmd)
{
#ifdef ENABLE_SILENTOT
    std::array<SilentOtTriple, 2> oles;

    u64 n = 4232;
    auto blocks = divCeil(n, 128);
    bool verbose = cmd.isSet("v");

    PRNG prng0(block(2424523452345, 111124521521455324));
    PRNG prng1(block(6474567454546, 567546754674345444));
    Timer timer;

    // Initialize both parties
    oles[0].init(0, n, SilentSecType::SemiHonest, SilentOtTriple::Type::Triple);
    oles[1].init(1, n, SilentSecType::SemiHonest, SilentOtTriple::Type::Triple);

    // Set up base OTs
    {
        auto otCount0 = oles[0].baseCount(prng0);
        auto otCount1 = oles[1].baseCount(prng1);
        if (otCount0.mRecvChoice.size() != otCount1.mSendCount ||
            otCount0.mSendCount != otCount1.mRecvChoice.size())
            throw RTE_LOC;
        
        std::array<std::vector<std::array<block, 2>>, 2> baseSend;
        baseSend[0].resize(otCount0.mSendCount);
        baseSend[1].resize(otCount1.mSendCount);
        std::array<std::vector<block>, 2> baseRecv;
        std::array<BitVector, 2> baseChoice{
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

        oles[0].setBaseOts(baseSend[1], baseRecv[0]);
        oles[1].setBaseOts(baseSend[1], baseRecv[1]);
    }

    // Create local socket pair for communication
    auto sock = coproto::LocalAsyncSocket::makePair();
    std::vector<block>
        Av0(blocks),
        Av1(blocks),
        Bv0(blocks),
        Bv1(blocks),
        Cv0(blocks),
        Cv1(blocks);

    // Run protocol
    auto r = macoro::sync_wait(macoro::when_all_ready(
        oles[0].expand(Av0, Bv0, Cv0, prng0, sock[0]),
        oles[1].expand(Av1, Bv1, Cv1, prng1, sock[1])));
    std::get<0>(r).result();
    std::get<1>(r).result();

    // Verify triple correlation: C0 ⊕ C1 = (A0 ⊕ A1) & (B0 ⊕ B1)
    for (size_t i = 0; i < blocks; i++)
    {
        auto act = Cv0[i] ^ Cv1[i];
        auto exp = (Av0[i] ^ Av1[i]) & (Bv0[i] ^ Bv1[i]);

        if (act != exp)
        {
            std::cout << "i " << i << std::endl;
            std::cout << "act " << act << std::endl;
            std::cout << "exp " << exp << std::endl;
            throw RTE_LOC;
        }
    }

    if (verbose)
        std::cout << "Time taken: \n" << timer << std::endl;
#else
    throw UnitTestSkipped("ENABLE_SILENTOT not defined.");
#endif
}

//=================================================================================================
// Silent OT Extension tests - Helper functions
//=================================================================================================

#ifdef ENABLE_SILENTOT
namespace {
    /**
     * @brief Sets up fake base OTs and VOLEs for testing.
     *
     * This function creates base OTs and VOLEs without network communication
     * for efficient testing.
     * 
     * @param n Number of OTs
     * @param s Scaling factor
     * @param threads Number of threads
     * @param prng Source of randomness
     * @param recver Receiver instance
     * @param sender Sender instance
     * @param delta Optional delta value for VOLE correlation
     */
    void fakeBase(
        u64 n,
        u64 s,
        u64 threads,
        PRNG& prng,
        SilentOtExtReceiver& recver, 
        SilentOtExtSender& sender,
        std::optional<block> delta = {})
    {
        auto count = sender.baseCount();
        auto D = delta.value_or(prng.get<block>());

        std::vector<std::array<block, 2>> msg2(count.mBaseOtCount);
        std::vector<block> baseA(count.mBaseVoleCount), baseB(count.mBaseVoleCount);
        BitVector baseC(count.mBaseVoleCount);
        baseC.randomize(prng);

        // Generate random base OT messages
        for (u64 i = 0; i < msg2.size(); ++i)
        {
            msg2[i][0] = prng.get();
            msg2[i][1] = prng.get();
        }

        // Generate base VOLE correlation
        prng.get(baseB.data(), baseB.size());
        for (u64 i = 0; i < baseA.size(); ++i)
        {
            // A = B + C * delta
            baseA[i] = baseB[i] ^ (baseC[i] ? D : ZeroBlock);
        }

        // Set the base correlations
        sender.setBaseCors(msg2, baseB, D);

        // Set receiver's base OTs and VOLEs
        {
            BitVector choices = recver.sampleBaseChoiceBits(prng);
            std::vector<block> msg(choices.size());
            for (u64 i = 0; i < msg.size(); ++i)
                msg[i] = msg2[i][choices[i]];
            recver.setBaseCors(msg, choices, baseA, baseC);
        }
    }

    /**
     * @brief Validates random OT output.
     * 
     * Verifies that the receiver gets exactly one of the sender's messages
     * according to the choice bit, and that the distribution of choice bits
     * is sufficiently random.
     *
     * @param messages Receiver's OT messages
     * @param messages2 Sender's OT message pairs
     * @param choice Receiver's choice bits
     * @param n Number of OTs
     * @param verbose Enable detailed output
     */
    void checkRandom(
        span<block> messages, 
        span<std::array<block, 2>> messages2,
        BitVector& choice, 
        u64 n,
        bool verbose)
    {
        if (messages.size() != n)
            throw RTE_LOC;
        if (messages2.size() != n)
            throw RTE_LOC;
        if (choice.size() != n)
            throw RTE_LOC;
            
        bool passed = true;

        // Check that choice bits are well-distributed
        auto hamming = choice.hammingWeight();
        auto threshold = n / 2 - 2 * std::sqrt(n);
        if (hamming < threshold)
            throw RTE_LOC;
            
        // Verify each OT message
        for (u64 i = 0; i < n; ++i)
        {
            block m1 = messages[i];
            block m2a = messages2[i][0];
            block m2b = messages2[i][1];
            u8 c = choice[i];

            std::array<bool, 2> eqq{
                eq(m1, m2a),
                eq(m1, m2b)
            };
            
            // Received wrong message
            if (eqq[c ^ 1] == true)
            {
                passed = false;
                if (verbose)
                    std::cout << Color::Pink;
            }
            
            // Didn't receive either message
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

    /**
     * @brief Validates correlated OT output.
     * 
     * Verifies that the receiver's messages and sender's messages satisfy the
     * correlation Ar = Bs ⊕ (choice * delta) for each OT.
     *
     * @param Ar Receiver's OT messages
     * @param Bs Sender's OT messages
     * @param choice Receiver's choice bits
     * @param delta Correlation value
     * @param n Number of OTs
     * @param verbose Enable detailed output
     * @param packing Choice bit packing method
     */
    template<typename Choice>
    void checkCorrelated(
        span<block> Ar, 
        span<block> Bs,
        Choice& choice, 
        block delta, 
        u64 n,
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
        block mask = AllOneBlock ^ OneBlock;
        u64 hamming = 0;

        for (u64 i = 0; i < n; ++i)
        {
            block m1 = Ar[i];
            block m2a = Bs[i];
            block m2b = (Bs[i] ^ delta);
            u8 c, c2;

            // For packed choice bits, extract from LSB
            if (packing == ChoiceBitPacking::True)
            {
                c = u8((m1 & OneBlock) == OneBlock) & 1;
                m1 = m1 & mask;
                m2a = m2a & mask;
                m2b = m2b & mask;

                // Verify against explicit choice bits if provided
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

            // Check correlation: Ar = Bs ⊕ (c * delta)
            std::array<bool, 2> eqq{
                eq(m1, m2a),  // c=0: Ar = Bs
                eq(m1, m2b)   // c=1: Ar = Bs ⊕ delta
            };

            bool good = true;
            if (eqq[c] == false || eqq[c ^ 1] == true)
            {
                good = passed = false;
                std::cout << Color::Pink;
            }
            if (eqq[0] == false && eqq[1] == false)
            {
                good = passed = false;
                std::cout << Color::Red;
            }

            if (!good)
            {
                std::cout << i << " m " << mask << std::endl;
                std::cout << "r " << m1 << " " << int(c) << std::endl;
                std::cout << "s " << m2a << " " << m2b << std::endl;
                std::cout << "d " << (m1 ^ m2a) << " " << (m1 ^ m2b) << std::endl;
            }

            std::cout << Color::Default;
        }

        if (passed == false)
            throw RTE_LOC;

        // Check if choice bits are well-distributed
        if (n > 100 && hamming < n / 2 - std::sqrt(n))
            throw RTE_LOC;
    }
}
#endif

//=================================================================================================
// Silent OT Extension tests
//=================================================================================================

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

    // Initialize Silent OT
    SilentOtExtSender sender;
    SilentOtExtReceiver recver;
    sender.configure(n);
    recver.configure(n);
    fakeBase(n, s, threads, prng, recver, sender);
    
    auto type = OTType::Random;
    sender.mDebug = cmd.isSet("debug");
    recver.mDebug = cmd.isSet("debug");

    // Run protocol
    std::vector<block> messages2(n);
    BitVector choice(n);
    std::vector<std::array<block, 2>> messages(n);

    auto p0 = sender.silentSend(messages, prng, sockets[0]);
    auto p1 = recver.silentReceive(choice, messages2, prng, sockets[1], type);

    eval(p0, p1);

    // Verify results
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

    // Initialize Silent OT
    SilentOtExtSender sender;
    SilentOtExtReceiver recver;
    sender.configure(n);
    recver.configure(n);
    fakeBase(n, s, threads, prng, recver, sender);

    // Run protocol (correlated OT)
    std::vector<block> messages2(n);
    BitVector choice(n);
    std::vector<block> messages(n);
    auto type = OTType::Correlated;

    auto delta = *sender.mDelta;
    auto p0 = sender.silentSend({}, messages, prng, sockets[0]);
    auto p1 = recver.silentReceive(choice, messages2, prng, sockets[1], type);

    eval(p0, p1);

    // Verify results
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
    sender.configure(n);
    recver.configure(n);

    // Test 1: Regular correlated OT with separate choice bits
    {
        fakeBase(n, s, threads, prng, recver, sender);
        auto delta = *sender.mDelta;
        
        auto p0 = sender.silentSendInplace(delta, n, prng, sockets[0]);
        auto p1 = recver.silentReceiveInplace(n, prng, sockets[1]);

        eval(p0, p1);

        auto& messages = recver.mA;
        auto& messages2 = sender.mB;
        auto& choice = recver.mC;
        
        checkCorrelated(messages, messages2, choice, delta,
            n, verbose, ChoiceBitPacking::False);
    }

    // Test 2: Correlated OT with packed choice bits
    {
        fakeBase(n, s, threads, prng, recver, sender);
        auto delta = *sender.mDelta;
        
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

    // Test different sizes of OTs
    std::vector<u64> nn = cmd.getManyOr<u64>("n",
        { 12, 433, 5466 });

    bool verbose = cmd.getOr("v", 0) > 1;
    u64 threads = cmd.getOr("t", 4);
    u64 s = cmd.getOr("s", 2);

    PRNG prng(toBlock(cmd.getOr("seed", 0)));
    PRNG prng1(toBlock(cmd.getOr("seed1", 1)));

    SilentOtExtSender sender;
    SilentOtExtReceiver recver;

    // Run tests with different OT counts
    for (auto n : nn)
    {
        sender.configure(n);
        recver.configure(n);
        fakeBase(n, s, threads, prng, recver, sender);
        auto delta = *sender.mDelta;

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
        { 134 });

    bool verbose = cmd.getOr("v", 0) > 1;
    u64 threads = cmd.getOr("t", 4);
    u64 s = cmd.getOr("s", 2);

    PRNG prng(toBlock(cmd.getOr("seed", 0)));
    PRNG prng1(toBlock(cmd.getOr("seed1", 1)));

    SilentOtExtSender sender;
    SilentOtExtReceiver recver;

    Timer timer;
    sender.setTimer(timer);
    
    for (auto n : nn)
    {
        // Test with QuasiCyclic encoding
        std::vector<std::array<block, 2>> msg2(n);
        std::vector<block> msg1(n);
        BitVector choice(n);
        
        sender.configure(n, 2, 1, SilentSecType::SemiHonest, SdNoiseDistribution::Regular, MultType::QuasiCyclic);
        recver.configure(n, 2, 1, SilentSecType::SemiHonest, SdNoiseDistribution::Regular, MultType::QuasiCyclic);
        
        fakeBase(n, s, threads, prng, recver, sender);
        auto delta = *sender.mDelta;
        
        auto p0 = sender.silentSend(msg2, prng, sockets[0]);
        auto p1 = recver.silentReceive(choice, msg1, prng, sockets[1]);

        eval(p0, p1);

        checkRandom(msg1, msg2, choice, n, verbose);
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
        { 1234 });

    bool verbose = cmd.getOr("v", 0) > 1;
    u64 threads = cmd.getOr("t", 4);
    u64 s = cmd.getOr("s", 2);

    PRNG prng(toBlock(cmd.getOr("seed", 0)));
    PRNG prng1(toBlock(cmd.getOr("seed1", 1)));

    SilentOtExtSender sender;
    SilentOtExtReceiver recver;

    for (auto n : nn)
    {
        // Test 1: Random OT with Tungsten encoding
        {
            std::vector<std::array<block, 2>> msg2(n);
            std::vector<block> msg1(n);
            BitVector choice(n);
            
            sender.configure(n, 2, 1, SilentSecType::SemiHonest, SdNoiseDistribution::Regular, MultType::Tungsten);
            recver.configure(n, 2, 1, SilentSecType::SemiHonest, SdNoiseDistribution::Regular, MultType::Tungsten);

            fakeBase(n, s, threads, prng, recver, sender);
            
            auto p0 = sender.silentSend(msg2, prng, sockets[0]);
            auto p1 = recver.silentReceive(choice, msg1, prng, sockets[1]);

            eval(p0, p1);

            checkRandom(msg1, msg2, choice, n, verbose);
        }

        // Test 2: Correlated OT with Tungsten encoding
        {
            sender.configure(n);
            recver.configure(n);
            auto type = ChoiceBitPacking::False;
            
            fakeBase(n, s, threads, prng, recver, sender);
            auto delta = *sender.mDelta;

            auto p0 = sender.silentSendInplace(delta, n, prng, sockets[0]);
            auto p1 = recver.silentReceiveInplace(n, prng, sockets[1], type);

            eval(p0, p1);

            checkCorrelated(recver.mA, sender.mB, recver.mC, delta, n, verbose, type);
        }
    }
#else
    throw UnitTestSkipped("ENABLE_SILENTOT or ENABLE_INSECURE_SILVER are not defined.");
#endif
}

void OtExt_Silent_baseOT_Test(const oc::CLP& cmd)
{
#ifdef ENABLE_SILENTOT
    auto sockets = cp::LocalAsyncSocket::makePair();

    u64 n = 1230;
    bool verbose = cmd.getOr("v", 0) > 1;

    PRNG prng(toBlock(cmd.getOr("seed", 0)));
    PRNG prng1(toBlock(cmd.getOr("seed1", 1)));

    // Test with different noise models
    for (auto noise : { SdNoiseDistribution::Stationary })
    {
        // Test with and without OT extension
        for (auto ext : { false, true })
        {
            SilentOtExtSender sender;
            SilentOtExtReceiver recver;

            std::vector<std::array<block, 2>> msg2(n);
            std::vector<block> msg1(n);
            BitVector choice(n);

            sender.configure(n, 2, 1, SilentSecType::SemiHonest, noise);
            recver.configure(n, 2, 1, SilentSecType::SemiHonest, noise);

            // For stationary noise, reuse the base OTs multiple times
            u64 c = noise == SdNoiseDistribution::Stationary ? 3 : 1;

            for (u64 j = 0; j < c; ++j)
            {
                // Generate base correlations
                auto g0 = sender.genBaseCors({}, prng, sockets[0], ext);
                auto g1 = recver.genBaseCors(prng, sockets[1], ext);
                eval(g0, g1);

                // Run random OT
                auto p0 = sender.silentSend(msg2, prng, sockets[0]);
                auto p1 = recver.silentReceive(choice, msg1, prng, sockets[1]);
                eval(p0, p1);

                checkRandom(msg1, msg2, choice, n, verbose);
            }
        }
    }
#else
    throw UnitTestSkipped("ENABLE_SILENTOT not defined.");
#endif
}

void OtExt_Silent_stationary_Test(const oc::CLP& cmd)
{
#ifdef ENABLE_SILENTOT
    auto sockets = cp::LocalAsyncSocket::makePair();

    u64 n = 1230;
    bool verbose = cmd.getOr("v", 0) > 1;

    PRNG prng(toBlock(cmd.getOr("seed", 0)));
    PRNG prng1(toBlock(cmd.getOr("seed1", 1)));

    // Focus on stationary noise distribution
    auto noise = SdNoiseDistribution::Stationary;

    SilentOtExtSender sender;
    SilentOtExtReceiver recver;
    sender.mDebug = cmd.isSet("debug");
    recver.mDebug = cmd.isSet("debug");

    std::vector<std::array<block, 2>> msg2(n);
    std::vector<block> msg1(n);
    BitVector choice(n);

    sender.configure(n, 2, 1, SilentSecType::SemiHonest, noise);
    recver.configure(n, 2, 1, SilentSecType::SemiHonest, noise);

    // Use same delta across multiple executions (important for stationary noise)
    u64 c = 4;
    block delta = prng.get();

    // Run protocol multiple times with the same base correlations
    for (u64 j = 0; j < c; ++j)
    {
        fakeBase(n, 2, 1, prng, recver, sender, delta);
        
        auto p0 = sender.silentSend(msg2, prng, sockets[0]);
        auto p1 = recver.silentReceive(choice, msg1, prng, sockets[1]);
        eval(p0, p1);

        checkRandom(msg1, msg2, choice, n, verbose);
    }
#else
    throw UnitTestSkipped("ENABLE_SILENTOT not defined.");
#endif
}

void OtExt_Silent_mal_Test(const oc::CLP& cmd)
{
#ifdef ENABLE_SILENTOT
    auto sockets = cp::LocalAsyncSocket::makePair();

    u64 n = 1293;
    bool verbose = cmd.getOr("v", 0) > 1;

    PRNG prng(toBlock(cmd.getOr("seed", 0)));
    PRNG prng1(toBlock(cmd.getOr("seed1", 1)));

    for (auto noise : { SdNoiseDistribution::Regular, SdNoiseDistribution::Stationary })
    {
        // Test with malicious security
        SilentOtExtSender sender;
        SilentOtExtReceiver recver;

        std::vector<std::array<block, 2>> msg2(n);
        std::vector<block> msg1(n);
        BitVector choice(n);
        sender.configure(n, 2, 1, SilentSecType::Malicious, noise);
        recver.configure(n, 2, 1, SilentSecType::Malicious, noise);

		u64 iters = noise == SdNoiseDistribution::Stationary ? 3 : 1;

        for (u64 j = 0; j < iters; ++j)
        {
            // Run random OT protocol
            auto p0 = sender.silentSend(msg2, prng, sockets[0]);
            auto p1 = recver.silentReceive(choice, msg1, prng, sockets[1]);
            eval(p0, p1);
            checkRandom(msg1, msg2, choice, n, verbose);
		}
    }
#else
    throw UnitTestSkipped("ENABLE_SILENTOT not defined.");
#endif
}

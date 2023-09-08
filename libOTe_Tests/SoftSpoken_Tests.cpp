#include "OT_Tests.h"
#include "SoftSpoken_Tests.h"

#include "libOTe/TwoChooseOne/OTExtInterface.h"
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/CLP.h>


#include "libOTe/Vole/SoftSpokenOT/SmallFieldVole.h"
//#include "libOTe/TwoChooseOne/SoftSpokenOT/SoftSpokenMalLeakyDotExt.h"
#include "libOTe/TwoChooseOne/SoftSpokenOT/SoftSpokenMalOtExt.h"
#include "libOTe/TwoChooseOne/SoftSpokenOT/SoftSpokenShOtExt.h"
//#include "libOTe/TwoChooseOne/SoftSpokenOT/SoftSpokenShOtExt.h"

#include "Common.h"
#include <thread>
#include <vector>
#include <random>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Matrix.h>


using namespace osuCrypto;

namespace tests_libOTe
{



    void Vole_SoftSpokenSmall_Test(const oc::CLP& cmd)
    {
#ifdef ENABLE_SOFTSPOKEN_OT
        //throw RTE_LOC;
        tests::xorReduction();

        const bool print = cmd.isSet("v");

        setThreadName("Receiver");

        PRNG prng0(block(4234385, 3445235));
        PRNG prng1(block(42348395, 989835));

        u64 numVoles = cmd.getOr("n", 128);
        auto sockets = cp::LocalAsyncSocket::makePair();

        for (size_t fieldBits = 1; fieldBits <= 10; fieldBits += 3)
        {
            for (int malicious = 0; malicious < 2; ++malicious)
            {
                const size_t nBaseOTs = SmallFieldVoleBase::baseOtCount(fieldBits, numVoles);

                std::vector<std::array<block, 2>> baseSend(nBaseOTs);
                std::vector<block> baseRecv(nBaseOTs);
                BitVector baseChoice(nBaseOTs);
                baseChoice.randomize(prng0);

                prng0.get(baseSend.data(), baseSend.size());
                for (u64 i = 0; i < nBaseOTs; ++i)
                    baseRecv[i] = baseSend[i][baseChoice[i]];

                SmallFieldVoleSender sender;
                SmallFieldVoleReceiver recver;

                recver.init(fieldBits, numVoles, malicious);
                sender.init(fieldBits, numVoles, malicious);

                std::vector<block>
                    u(sender.uPadded()),
                    v(sender.vPadded()),
                    w(recver.wPadded());

                sender.setBaseOts(baseSend);
                recver.setBaseOts(baseRecv, baseChoice);

                cp::sync_wait(
                    cp::when_all_ready(
                        sender.expand(sockets[0], prng1, 1),
                        recver.expand(sockets[1], prng0, 1)
                    ));

                sender.generate(0, mAesFixedKey, u, v);
                recver.generate(0, mAesFixedKey, w);

                if (sender.vSize() != recver.wSize())
                    throw UnitTestFail(LOCATION);
                if (sender.uSize() > u.size())
                    throw UnitTestFail(LOCATION);
                if (sender.vSize() > v.size() || recver.wSize() > w.size())
                    throw UnitTestFail(LOCATION);
                u.resize(numVoles);

                BitVector delta = recver.mDelta;
                if (print)
                {
                    std::cout << "Delta:\n";
                    for (size_t i = 0; i < delta.sizeBlocks(); ++i)
                        std::cout << delta.blocks()[i] << ", ";

                    std::cout << "\nSeeds:\n";
                }

                size_t fieldSize = recver.fieldSize();
                for (size_t i = 0; i < numVoles; ++i)
                {
                    size_t deltaI = 0;
                    for (size_t j = 0; j < fieldBits; ++j)
                        deltaI += (size_t)delta[i * fieldBits + j] << j;

                    if (print)
                    {
                        for (size_t j = 0; j < fieldSize; ++j)
                            std::cout << j << ": " << sender.mSeeds[i * fieldSize + j] << '\n';
                        for (size_t j = 1; j < fieldSize; ++j)
                            std::cout << j << ": " << recver.mSeeds[i * (fieldSize - 1) + j - 1] << '\n';
                    }

                    for (size_t j = 0; j < fieldSize; ++j)
                    {
                        if (j == deltaI)
                            // Punctured point.
                            continue;

                        block senderSeed = sender.mSeeds[i * fieldSize + j];
                        block recvSeed = recver.mSeeds[i * (fieldSize - 1) + (j ^ deltaI) - 1];
                        if (senderSeed != recvSeed)
                            throw UnitTestFail(LOCATION);
                    }
                }

                if (print)
                    std::cout << "\nOutputs:\n";

                std::vector<block> shouldEqualV = w;
                recver.sharedFunctionXor(span<const block>(u), span<block>(shouldEqualV));
                for (size_t i = 0; i < recver.wSize(); ++i)
                {
                    if (print)
                    {
                        std::cout << u[i / fieldBits] << '\n';
                        std::cout << v[i] << '\n';
                        std::cout << shouldEqualV[i] << '\n';
                        std::cout << w[i] << '\n';
                    }
                    if (v[i] != shouldEqualV[i])
                        throw UnitTestFail(LOCATION);

                    if (v[i] != (w[i] ^ (block::allSame((bool)delta[i]) & u[i / fieldBits])))
                        throw UnitTestFail(LOCATION);
                }
            }
        }

#else
        throw UnitTestSkipped("ENABLE_SOFTSPOKEN_OT is not defined.");
#endif
    }

    void OtExt_SoftSpokenSemiHonest_Test(const oc::CLP& cmd)
    {
#ifdef ENABLE_SOFTSPOKEN_OT
        setThreadName("Sender");

        auto sockets = cp::LocalAsyncSocket::makePair();

        PRNG prng0(block(4234335, 3445235));
        PRNG prng1(block(42348345, 989835));

        auto nnumOTs = cmd.getManyOr<u64>("n", { { 10, 100, 9733 } });

        for (auto random : { false, true })
        {
            for (auto numOTs : nnumOTs)
            {

                for (size_t fieldBits = 1; fieldBits <= 11; fieldBits += 3)
                {

                    SoftSpokenShOtSender<> sender;
                    SoftSpokenShOtReceiver<> recver;

                    sender.init(fieldBits, random);
                    recver.init(fieldBits, random);

                    const size_t nBaseOTs = sender.baseOtCount();
                    if (nBaseOTs != recver.baseOtCount())
                        throw UnitTestFail(LOCATION);

                    AlignedVector<block> recvMsg(numOTs), baseRecv(nBaseOTs);
                    AlignedVector<std::array<block, 2>> sendMsg(numOTs), baseSend(nBaseOTs);
                    BitVector choices(numOTs), baseChoice(nBaseOTs);

                    choices.randomize(prng0);
                    baseChoice.randomize(prng0);

                    prng0.get(baseSend.data(), baseSend.size());
                    for (u64 i = 0; i < nBaseOTs; ++i)
                        baseRecv[i] = baseSend[i][baseChoice[i]];

                    recver.setBaseOts(baseSend);
                    sender.setBaseOts(baseRecv, baseChoice);

                    cp::sync_wait(cp::when_all_ready(
                        recver.receive(choices, recvMsg, prng0, sockets[0]),
                        sender.send(sendMsg, prng1, sockets[1])
                    ));


                    //for (u64 i = 0; i < numOTs; ++i)
                    //{
                    //    std::cout << sendMsg[i][0] << ", " << sendMsg[i][1] << ", " << recvMsg[i] << "," << std::endl;
                    //}
                    //std::cout << std::endl;

                    OT_100Receive_Test(choices, recvMsg, sendMsg);

                    if (random == false)
                    {


                        const block delta = sender.delta();
                        for (auto& s : sendMsg)
                            if (neq(s[0] ^ delta, s[1]))
                                throw UnitTestFail(LOCATION);
                    }
                }
            }
        }
#else
        throw UnitTestSkipped("ENABLE_SOFTSPOKEN_OT is not defined.");
#endif
    }


    void OtExt_SoftSpokenSemiHonest_Split_Test(const oc::CLP& cmd)
    {
#ifdef ENABLE_SOFTSPOKEN_OT
        setThreadName("Sender");

        auto sockets = cp::LocalAsyncSocket::makePair();

        PRNG prng0(block(4234335, 3445235));
        PRNG prng1(block(42348345, 989835));

        auto numOTs = 1231;

        SoftSpokenShOtSender<> sender;
        SoftSpokenShOtReceiver<> recver;

        const size_t nBaseOTs = sender.baseOtCount();
        if (nBaseOTs != recver.baseOtCount())
            throw UnitTestFail(LOCATION);

        AlignedVector<block> recvMsg(numOTs), baseRecv(nBaseOTs);
        AlignedVector<std::array<block, 2>> sendMsg(numOTs), baseSend(nBaseOTs);
        BitVector choices(numOTs), baseChoice(nBaseOTs);

        choices.randomize(prng0);
        baseChoice.randomize(prng0);

        prng0.get(baseSend.data(), baseSend.size());
        for (u64 i = 0; i < nBaseOTs; ++i)
            baseRecv[i] = baseSend[i][baseChoice[i]];

        recver.setBaseOts(baseSend);
        sender.setBaseOts(baseRecv, baseChoice);

        cp::sync_wait(cp::when_all_ready(
            recver.receive(choices, recvMsg, prng0, sockets[0]),
            sender.send(sendMsg, prng1, sockets[1])
        ));

        OT_100Receive_Test(choices, recvMsg, sendMsg);


        auto recver2 = recver.splitBase();
        auto sender2 = sender.splitBase();
        cp::sync_wait(cp::when_all_ready(
            recver2.receive(choices, recvMsg, prng0, sockets[0]),
            sender2.send(sendMsg, prng1, sockets[1])
        ));


        OT_100Receive_Test(choices, recvMsg, sendMsg);
#else
        throw UnitTestSkipped("ENABLE_SOFTSPOKEN_OT is not defined.");
#endif
    }

    void DotExt_SoftSpokenMaliciousLeaky_Test(const oc::CLP& cmd)
    {
#ifdef ENABLE_SOFTSPOKEN_OT
        setThreadName("Sender");

        auto sockets = cp::LocalAsyncSocket::makePair();

        PRNG prng0(block(4234335, 3445235));
        PRNG prng1(block(42348345, 989835));

        auto nnumOTs = cmd.getManyOr<u64>("n", { 9733 });
        for (auto numOTs : nnumOTs)
        {

            for (size_t fieldBits = 1; fieldBits <= 11; fieldBits += 3)
            {


                SoftSpokenMalOtSender sender;
                SoftSpokenMalOtReceiver recver;


                sender.init(fieldBits, false);
                recver.init(fieldBits, false);

                const size_t nBaseOTs = sender.baseOtCount();
                if (nBaseOTs != recver.baseOtCount())
                    throw UnitTestFail(LOCATION);

                std::vector<block> baseRecv(nBaseOTs);
                std::vector<std::array<block, 2>> baseSend(nBaseOTs);
                BitVector choices(numOTs), baseChoice(nBaseOTs);
                choices.randomize(prng0);
                baseChoice.randomize(prng0);

                prng0.get((u8*)baseSend.data()->data(), sizeof(block) * 2 * baseSend.size());
                for (u64 i = 0; i < nBaseOTs; ++i)
                {
                    baseRecv[i] = baseSend[i][baseChoice[i]];
                }

                AlignedVector<block> recvMsg(numOTs);
                AlignedVector<std::array<block, 2>> sendMsg(numOTs);

                memset(recvMsg.data(), 0xcc, numOTs * sizeof(block));
                block bb0, bb1;
                memset(bb0.data(), 0xc1, sizeof(block));
                memset(bb1.data(), 0xc2, sizeof(block));
                for (u64 i = 0; i < numOTs; ++i)
                {
                    sendMsg[i][0] = bb0;
                    sendMsg[i][1] = bb1;
                }


                recver.setBaseOts(baseSend);
                sender.setBaseOts(baseRecv, baseChoice);


                cp::sync_wait(
                    cp::when_all_ready(
                        recver.receive(choices, recvMsg, prng0, sockets[0]),
                        sender.send(sendMsg, prng1, sockets[1])
                    )
                );

                OT_100Receive_Test(choices, recvMsg, sendMsg);

                const block delta = sender.delta();
                for (auto& s : sendMsg)
                {
                    if (s[0] == bb0 || s[1] == bb1)
                        throw RTE_LOC;

                    if (neq(s[0] ^ delta, s[1]))
                        throw UnitTestFail(LOCATION);
                }
            }
        }
#else
        throw UnitTestSkipped("ENABLE_SOFTSPOKEN_OT is not defined.");
#endif
    }

    void OtExt_SoftSpokenMalicious21_Test(const oc::CLP& cmd)
    {
#ifdef ENABLE_SOFTSPOKEN_OT

        setThreadName("Sender");

        auto sockets = cp::LocalAsyncSocket::makePair();

        PRNG prng0(block(4234335, 3445235));
        PRNG prng1(block(42348345, 989835));

        auto nnumOTs = cmd.getManyOr<u64>("n", { 9733 });
        for (auto numOTs : nnumOTs)
        {

            for (size_t fieldBits = 1; fieldBits <= 11; fieldBits += 3)
            {

                //SoftSpokenMalOtSender sender;
                //SoftSpokenMalOtReceiver recver;
                //sender.init(fieldBits);
                //recver.init(fieldBits);


                SoftSpokenMalOtSender sender;
                SoftSpokenMalOtReceiver recver;
                sender.init(fieldBits, true);
                recver.init(fieldBits, true);

                size_t nBaseOTs = sender.baseOtCount();
                if (nBaseOTs != recver.baseOtCount())
                    throw UnitTestFail(LOCATION);

                std::vector<block> baseRecv(nBaseOTs);
                std::vector<std::array<block, 2>> baseSend(nBaseOTs);
                BitVector choices(numOTs), baseChoice(nBaseOTs);
                choices.randomize(prng0);
                baseChoice.randomize(prng0);

                prng0.get((u8*)baseSend.data()->data(), sizeof(block) * 2 * baseSend.size());
                for (u64 i = 0; i < nBaseOTs; ++i)
                {
                    baseRecv[i] = baseSend[i][baseChoice[i]];
                }

                AlignedVector<block> recvMsg(numOTs);
                AlignedVector<std::array<block, 2>> sendMsg(numOTs);

                recver.setBaseOts(baseSend);
                sender.setBaseOts(baseRecv, baseChoice);

                cp::sync_wait(
                    cp::when_all_ready(
                        recver.receive(choices, recvMsg, prng0, sockets[0]),
                        sender.send(sendMsg, prng1, sockets[1])
                    )
                );



                OT_100Receive_Test(choices, recvMsg, sendMsg);
            }
        }
#else
        throw UnitTestSkipped("ENABLE_SOFTSPOKEN_OT is not defined.");
#endif
    }




    void OtExt_SoftSpokenMalicious21_Split_Test(const oc::CLP& cmd)
    {
#ifdef ENABLE_SOFTSPOKEN_OT

        setThreadName("Sender");

        auto sockets = cp::LocalAsyncSocket::makePair();

        PRNG prng0(block(4234335, 3445235));
        PRNG prng1(block(42348345, 989835));

        auto numOTs = 9733;

                SoftSpokenMalOtSender sender;
                SoftSpokenMalOtReceiver recver;

                size_t nBaseOTs = sender.baseOtCount();
                if (nBaseOTs != recver.baseOtCount())
                    throw UnitTestFail(LOCATION);

                std::vector<block> baseRecv(nBaseOTs);
                std::vector<std::array<block, 2>> baseSend(nBaseOTs);
                BitVector choices(numOTs), baseChoice(nBaseOTs);
                choices.randomize(prng0);
                baseChoice.randomize(prng0);

                prng0.get((u8*)baseSend.data()->data(), sizeof(block) * 2 * baseSend.size());
                for (u64 i = 0; i < nBaseOTs; ++i)
                {
                    baseRecv[i] = baseSend[i][baseChoice[i]];
                }

                AlignedVector<block> recvMsg(numOTs);
                AlignedVector<std::array<block, 2>> sendMsg(numOTs);

                recver.setBaseOts(baseSend);
                sender.setBaseOts(baseRecv, baseChoice);

                cp::sync_wait(
                    cp::when_all_ready(
                        recver.receive(choices, recvMsg, prng0, sockets[0]),
                        sender.send(sendMsg, prng1, sockets[1])
                    )
                );

                OT_100Receive_Test(choices, recvMsg, sendMsg);

                auto recver2 = recver.splitBase();
                auto sender2 = sender.splitBase();


                cp::sync_wait(
                    cp::when_all_ready(
                        recver2.receive(choices, recvMsg, prng0, sockets[0]),
                        sender2.send(sendMsg, prng1, sockets[1])
                    )
                );

                OT_100Receive_Test(choices, recvMsg, sendMsg);

#else
        throw UnitTestSkipped("ENABLE_SOFTSPOKEN_OT is not defined.");
#endif
    }




}

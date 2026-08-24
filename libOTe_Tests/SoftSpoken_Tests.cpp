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

    void Vole_SoftSpokenSmall_Audit_Test(const oc::CLP&)
    {
#ifdef ENABLE_SOFTSPOKEN_OT
        SmallFieldVoleSender sender;
        SmallFieldVoleReceiver receiver;
        sender.init((u64)1, (u64)1, false);
        receiver.init((u64)1, (u64)1, false);

        std::vector<block> u(sender.uPadded());
        std::vector<block> v(sender.vPadded());
        std::vector<block> w(receiver.wPadded());
        std::vector<block> correction(receiver.uPadded());

        auto expectRejected = [](auto&& fn, const char* message) {
            bool rejected = false;
            try { fn(); }
            catch (const std::runtime_error&) { rejected = true; }
            if (!rejected)
                throw UnitTestFail(message);
        };

        expectRejected([&] {
            sender.generate(0, mAesFixedKey,
                span<block>(u.data(), u.size() - 1), span<block>(v));
        }, "SmallField VOLE sender accepted an undersized u span");
        expectRejected([&] {
            sender.generate(0, mAesFixedKey,
                span<block>(u), span<block>(v.data(), v.size() - 1));
        }, "SmallField VOLE sender accepted an undersized v span");
        expectRejected([&] {
            receiver.generate(0, mAesFixedKey,
                span<block>(w.data(), w.size() - 1));
        }, "SmallField VOLE receiver accepted an undersized w span");
        expectRejected([&] {
            receiver.generate(0, mAesFixedKey, span<block>(w),
                span<const block>(correction.data(), correction.size() - 1));
        }, "SmallField VOLE receiver accepted an undersized correction span");
        expectRejected([&] {
            receiver.sharedFunctionXor(
                span<const block>(u.data(), 0), span<block>(w));
        }, "SmallField VOLE receiver accepted an undersized input span");
        expectRejected([&] {
            receiver.sharedFunctionXor(span<const block>(u.data(), 1),
                span<block>(w.data(), w.size() - 1));
        }, "SmallField VOLE receiver accepted an undersized product span");

        // Keep readable nonzero values after the declared one-element input.
        // The old four-at-a-time implementation consumed all four values and
        // changed the padded output even though only the first value was valid.
        std::array<block, 4> tailInput{
            OneBlock, block::allSame(0x11), block::allSame(0x22), block::allSame(0x44) };
        std::fill(w.begin(), w.end(), ZeroBlock);
        receiver.mDeltaUnpacked.resize(receiver.wPadded());
        std::fill(receiver.mDeltaUnpacked.begin(),
            receiver.mDeltaUnpacked.end(), 0xff);
        receiver.sharedFunctionXor(
            span<const block>(tailInput.data(), 1), span<block>(w));

        if (w[0] != OneBlock)
            throw UnitTestFail("SmallField VOLE tail omitted the valid input");
        for (u64 i = 1; i < w.size(); ++i)
            if (w[i] != ZeroBlock)
                throw UnitTestFail("SmallField VOLE tail consumed padded input");
#else
        throw UnitTestSkipped("ENABLE_SOFTSPOKEN_OT is not defined.");
#endif
    }

    void OtExt_SoftSpoken_AesState_Audit_Test(const oc::CLP&)
    {
#ifdef ENABLE_SOFTSPOKEN_OT
        const auto expectRejected = [](auto&& fn, const char* message) {
            bool rejected = false;
            try { fn(); }
            catch (const std::exception&) { rejected = true; }
            if (!rejected)
                throw UnitTestFail(message);
        };

        // Splitting before the protocol seed is installed must preserve the
        // unseeded state. The old path evaluated an uninitialized AES object
        // and treated the resulting child as seeded.
        AESStream unseededStream;
        expectRejected([&] { (void)unseededStream.split(); },
            "SoftSpoken split an unseeded AES stream");

        AESRekeyManager unseededManager;
        auto unseededChild = unseededManager.split();
        expectRejected([&] { (void)unseededManager.useAES(1); },
            "SoftSpoken seeded the parent during an unseeded split");
        expectRejected([&] { (void)unseededChild.useAES(1); },
            "SoftSpoken seeded the child during an unseeded split");

        const block seed(0x4155442d303433ull, 0x53504c49542d4145ull);
        AES expectedPrng(seed);
        std::array<block, AESStream::chunkSize + 1> expectedKeys;
        expectedPrng.ecbEncCounterMode(0, expectedKeys);

        AESStream stream(seed);
        for (u64 i = 0; i != AESStream::chunkSize; ++i)
        {
            if (stream.get().getKey() != expectedKeys[i])
                throw UnitTestFail(
                    "SoftSpoken AES stream selected the wrong cached key");
            if (i + 1 != AESStream::chunkSize)
                stream.next();
        }
        auto childStream = stream.split();
        if (stream.get().getKey() != expectedKeys[AESStream::chunkSize])
            throw UnitTestFail(
                "SoftSpoken AES split reused a stale cache entry");
        if (!childStream.hasSeed())
            throw UnitTestFail("SoftSpoken AES split returned an unseeded child");

        // A batch that triggers a rekey is the first use of the new key and
        // must count against that key's limit.
        AESRekeyManager manager;
        manager.setSeed(seed);
        const auto key0 = manager.useAES(
            AESRekeyManager::maxAESKeyUsage).getKey();
        const auto key1 = manager.useAES(1).getKey();
        const auto key2 = manager.useAES(
            AESRekeyManager::maxAESKeyUsage).getKey();
        if (key0 == key1 || key1 == key2)
            throw UnitTestFail(
                "SoftSpoken AES rekey accounting omitted a triggering batch");

        // A seeded split advances the parent to a fresh key. Its usage count
        // therefore starts at zero, independently of the previous key.
        manager.setSeed(seed);
        (void)manager.useAES(AESRekeyManager::maxAESKeyUsage / 2);
        auto childManager = manager.split();
        const auto parentAfterSplit = manager.useAES(
            AESRekeyManager::maxAESKeyUsage).getKey();
        const auto parentAfterLimit = manager.useAES(1).getKey();
        if (parentAfterSplit == parentAfterLimit)
            throw UnitTestFail(
                "SoftSpoken AES split retained the previous key's usage count");
        (void)childManager.useAES(1);

        // Some callers submit an indivisible batch larger than the nominal
        // limit. It gets a key to itself and forces a rekey before later use.
        manager.setSeed(seed);
        const auto oversizedKey = manager.useAES(
            AESRekeyManager::maxAESKeyUsage + 128).getKey();
        const auto afterOversizedKey = manager.useAES(1).getKey();
        if (oversizedKey == afterOversizedKey)
            throw UnitTestFail(
                "SoftSpoken accumulated use after an oversized AES batch");
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

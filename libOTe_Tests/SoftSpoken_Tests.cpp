#include "OT_Tests.h"
#include "SoftSpoken_Tests.h"

#include "libOTe/TwoChooseOne/OTExtInterface.h"
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/CLP.h>


#include "libOTe/Vole/SoftSpokenOT/SmallFieldVole.h"
#include "libOTe/Vole/SoftSpokenOT/SubspaceVole.h"
#include "libOTe/Vole/SoftSpokenOT/SubspaceVoleMaliciousLeaky.h"
#include "libOTe/Tools/RepetitionCode.h"
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
            catch (const std::exception&) { rejected = true; }
            if (!rejected)
                throw UnitTestFail(message);
		};
		PRNG auditPrng(block::allSame(0x129));

		SmallFieldVoleSender defaultSender;
		auto defaultSenderSockets = cp::LocalAsyncSocket::makePair();
		expectRejected([&] {
			cp::sync_wait(defaultSender.expand(defaultSenderSockets[0], auditPrng, 1));
		}, "Default SmallField VOLE sender expansion was not rejected");
		SmallFieldVoleReceiver defaultReceiver;
		auto defaultReceiverSockets = cp::LocalAsyncSocket::makePair();
		expectRejected([&] {
			cp::sync_wait(defaultReceiver.expand(defaultReceiverSockets[0], auditPrng, 1));
		}, "Default SmallField VOLE receiver expansion was not rejected");

		expectRejected([&] {
			sender.generate(0, mAesFixedKey, span<block>(u), span<block>(v));
		}, "SmallField VOLE sender generated without expanded seeds");
		expectRejected([&] {
			receiver.generate(0, mAesFixedKey, span<block>(w));
		}, "SmallField VOLE receiver generated without expanded seeds");
		std::vector<block> directSenderSeeds(2);
		std::vector<block> directReceiverSeeds(1);
		sender.setSeed(directSenderSeeds);
		receiver.setSeeds(directReceiverSeeds);

		SmallFieldVoleSender seededSender;
		SmallFieldVoleReceiver seededReceiver;
		seededSender.init(2, 4, false);
		seededReceiver.init(2, 4, false);
		std::vector<block> senderSeeds(4 * 4);
		std::vector<block> receiverSeeds(4 * 3);
		seededSender.setSeed(senderSeeds);
		seededReceiver.setSeeds(receiverSeeds);
		const auto seededSenderCount = seededSender.mSeeds.size();
		const auto seededReceiverCount = seededReceiver.mSeeds.size();
		auto seededSenderSockets = cp::LocalAsyncSocket::makePair();
		expectRejected([&] {
			cp::sync_wait(seededSender.expand(seededSenderSockets[0], auditPrng, 1));
		}, "Seeded SmallField VOLE sender expansion was not rejected");
		auto seededReceiverSockets = cp::LocalAsyncSocket::makePair();
		expectRejected([&] {
			cp::sync_wait(seededReceiver.expand(seededReceiverSockets[0], auditPrng, 1));
		}, "Seeded SmallField VOLE receiver expansion was not rejected");
		if (seededSender.mSeeds.size() != seededSenderCount ||
			seededReceiver.mSeeds.size() != seededReceiverCount)
			throw UnitTestFail("Rejected SmallField VOLE expansion changed seed state");

		SmallFieldVoleSender moveSenderSource;
		moveSenderSource.init(2, 4, false);
		moveSenderSource.setSeed(senderSeeds);
		SmallFieldVoleSender moveSenderDestination(std::move(moveSenderSource));
		if (moveSenderSource.mInit || moveSenderSource.mFieldBits ||
			moveSenderSource.mNumVoles || moveSenderSource.mNumVolesPadded ||
			moveSenderSource.hasSeed() || moveSenderSource.hasBaseOts() ||
			moveSenderSource.mPprf)
			throw UnitTestFail("SmallField VOLE sender move left active source state");
		expectRejected([&] {
			std::vector<block> empty;
			moveSenderSource.generate(
				0, mAesFixedKey, span<block>(empty), span<block>(empty));
		}, "Moved-from SmallField VOLE sender remained usable");

		SmallFieldVoleReceiver moveReceiverSource;
		moveReceiverSource.init(2, 4, false);
		moveReceiverSource.setSeeds(receiverSeeds);
		SmallFieldVoleReceiver moveReceiverDestination;
		moveReceiverDestination = std::move(moveReceiverSource);
		if (moveReceiverSource.mInit || moveReceiverSource.mFieldBits ||
			moveReceiverSource.mNumVoles || moveReceiverSource.mNumVolesPadded ||
			moveReceiverSource.hasSeed() || moveReceiverSource.hasBaseOts() ||
			moveReceiverSource.mPprf || moveReceiverSource.mDelta.size() ||
			!moveReceiverSource.mDeltaUnpacked.empty())
			throw UnitTestFail("SmallField VOLE receiver move left active source state");
		expectRejected([&] {
			std::vector<block> empty;
			moveReceiverSource.generate(0, mAesFixedKey, span<block>(empty));
		}, "Moved-from SmallField VOLE receiver remained usable");

		expectRejected([&] { seededSender.init(0, 1, false); },
			"SmallField VOLE accepted a zero field width");
		if (!seededSender.mInit || seededSender.mFieldBits != 2 ||
			seededSender.mNumVoles != 4)
			throw UnitTestFail("SmallField VOLE failed initialization changed existing state");

		SmallFieldVoleSender zeroVoles;
		expectRejected([&] { zeroVoles.init(1, 0, false); },
			"SmallField VOLE accepted zero VOLEs");
		expectRejected([&] {
			zeroVoles.init(1, SmallFieldVoleBase::seedCountMax, false);
		}, "SmallField VOLE accepted an oversized padded seed count");
		expectRejected([&] { zeroVoles.init(31, 1, false); },
			"SmallField VOLE accepted an oversized 31-bit seed table");

		SubspaceVoleSender<RepetitionCode> subspaceSender;
		SubspaceVoleReceiver<RepetitionCode> subspaceReceiver;
		SubspaceVoleMaliciousSender<RepetitionCode> maliciousSender;
		SubspaceVoleMaliciousReceiver<RepetitionCode> maliciousReceiver;
		expectRejected([&] { subspaceSender.init(0, 1); },
			"Subspace VOLE sender divided by a zero field width");
		expectRejected([&] { subspaceReceiver.init(0, 1); },
			"Subspace VOLE receiver divided by a zero field width");
		expectRejected([&] { maliciousSender.init(0, 1); },
			"Malicious subspace VOLE sender divided by a zero field width");
		expectRejected([&] { maliciousReceiver.init(0, 1); },
			"Malicious subspace VOLE receiver divided by a zero field width");

		constexpr u64 maliciousFieldBits = 1;
		const u64 maliciousNumVoles =
			divCeil(gOtExtBaseOtCount, maliciousFieldBits);
		maliciousSender.init(maliciousFieldBits, maliciousNumVoles);
		maliciousReceiver.init(maliciousFieldBits, maliciousNumVoles);
		std::vector<block> maliciousU(maliciousSender.code().dimension());
		std::vector<block> maliciousV(maliciousSender.vPadded());
		std::vector<block> maliciousW(maliciousReceiver.wPadded());

		expectRejected([&] {
			maliciousSender.generateRandom(
				0, mAesFixedKey, span<block>(maliciousU), span<block>(maliciousV));
		}, "Malicious subspace VOLE sender generated without seeds");
		expectRejected([&] {
			maliciousSender.generateRandom(0, mAesFixedKey,
				span<block>(maliciousU),
				span<block>(maliciousV.data(), maliciousV.size() - 1));
		}, "Malicious subspace VOLE sender accepted an undersized v span");
		expectRejected([&] {
			maliciousSender.generateChosen(0, mAesFixedKey,
				span<const block>(maliciousU.data(), maliciousU.size() - 1),
				span<block>(maliciousV));
		}, "Malicious subspace VOLE sender accepted an undersized u span");
		expectRejected([&] {
			maliciousReceiver.generateRandom(0, mAesFixedKey,
				span<block>(maliciousW.data(), maliciousW.size() - 1));
		}, "Malicious subspace VOLE receiver accepted an undersized w span");

		expectRejected([&] {
			maliciousSender.hash(
				span<const block>(maliciousU), span<const block>(maliciousV));
		}, "Malicious subspace VOLE sender hashed without a challenge");
		expectRejected([&] {
			maliciousReceiver.hash(span<const block>(maliciousW));
		}, "Malicious subspace VOLE receiver hashed without a challenge");
		maliciousSender.setChallenge(block::allSame(0x124));
		expectRejected([&] {
			maliciousSender.hash(span<const block>(maliciousU),
				span<const block>(maliciousV.data(), maliciousV.size() - 1));
		}, "Malicious subspace VOLE hash accepted an undersized v span");

		SubspaceVoleMaliciousSender<RepetitionCode> maliciousMoveDestination(
			std::move(maliciousSender));
		if (maliciousSender.hasChallenge() || maliciousSender.hasSeed() ||
			!maliciousSender.hashU.empty() || !maliciousSender.subtotalU.empty() ||
			!maliciousSender.hashV.empty() || !maliciousSender.subtotalV.empty())
			throw UnitTestFail(
				"Malicious subspace VOLE move left active source state");
		expectRejected([&] {
			maliciousSender.hash(
				span<const block>(maliciousU), span<const block>(maliciousV));
		}, "Moved-from malicious subspace VOLE sender retained its challenge");

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

		SmallFieldVoleSender failedSender;
		failedSender.init(1, 1, false);
		auto failedSenderSockets = cp::LocalAsyncSocket::makePair();
		expectRejected([&] {
			cp::sync_wait(failedSender.expand(failedSenderSockets[0], auditPrng, 1));
		}, "Failed SmallField VOLE sender expansion did not throw");
		if (failedSender.hasSeed())
			throw UnitTestFail("Failed SmallField VOLE sender expansion retained seed state");

		SmallFieldVoleReceiver failedReceiver;
		failedReceiver.init(1, 1, false);
		auto failedReceiverSockets = cp::LocalAsyncSocket::makePair();
		expectRejected([&] {
			cp::sync_wait(failedReceiver.expand(failedReceiverSockets[0], auditPrng, 1));
		}, "Failed SmallField VOLE receiver expansion did not throw");
		if (failedReceiver.hasSeed() || failedReceiver.mConsistencyFailed)
			throw UnitTestFail("Failed SmallField VOLE receiver expansion retained seed state");

		SubspaceVoleMaliciousSender<RepetitionCode> deferredSender;
		SubspaceVoleMaliciousReceiver<RepetitionCode> deferredReceiver;
		deferredSender.init(maliciousFieldBits, maliciousNumVoles);
		deferredReceiver.init(maliciousFieldBits, maliciousNumVoles);
		const auto deferredBaseCount = deferredReceiver.mVole.baseOtCount();
		std::vector<block> deferredBase(deferredBaseCount, ZeroBlock);
		BitVector deferredChoices(deferredBaseCount);
		deferredReceiver.mVole.setBaseOts(deferredBase, deferredChoices);
		std::vector<block> deferredSeeds(
			maliciousNumVoles * (deferredReceiver.mVole.fieldSize() - 1), ZeroBlock);
		deferredReceiver.mVole.setSeeds(deferredSeeds);
		deferredReceiver.mVole.mConsistencyFailed = true;

		auto deferredSockets = cp::LocalAsyncSocket::makePair();
		block deferredChallenge;
		cp::sync_wait(cp::when_all_ready(
			deferredReceiver.sendChallenge(auditPrng, deferredSockets[0]),
			deferredSockets[1].recv(deferredChallenge)));
		deferredSender.setChallenge(deferredChallenge);
		auto deferredResults = cp::sync_wait(cp::when_all_ready(
			deferredSender.sendResponse(deferredSockets[1]),
			deferredReceiver.checkResponse(deferredSockets[0])));
		std::get<0>(deferredResults).result();
		bool deferredRejected = false;
		try { std::get<1>(deferredResults).result(); }
		catch (const std::exception&) { deferredRejected = true; }
		if (!deferredRejected)
			throw UnitTestFail(
				"Deferred SmallField VOLE failure was not folded into the final check");
		if (deferredReceiver.hasSeed() ||
			deferredReceiver.hasDeferredConsistencyFailure() ||
			deferredReceiver.hasChallenge())
			throw UnitTestFail("Final malicious VOLE failure retained seed state");
		expectRejected([&] {
			cp::sync_wait(deferredReceiver.checkResponse(deferredSockets[0]));
		}, "Failed malicious VOLE response check allowed a retry");

		SubspaceVoleMaliciousSender<RepetitionCode> failedResponseSender;
		failedResponseSender.init(maliciousFieldBits, maliciousNumVoles);
		failedResponseSender.setChallenge(block::allSame(0x437));
		auto failedResponseSockets = cp::LocalAsyncSocket::makePair();
		failedResponseSockets[0].mSock->mImpl->mDebugErrorInjector = [] {
			return cp::make_error_code(cp::code::ioError);
		};
		expectRejected([&] {
			cp::sync_wait(failedResponseSender.sendResponse(failedResponseSockets[0]));
		}, "Failed malicious VOLE response send did not throw");
		if (failedResponseSender.hasChallenge())
			throw UnitTestFail("Failed malicious VOLE response send retained its challenge");
		expectRejected([&] {
			cp::sync_wait(failedResponseSender.sendResponse(failedResponseSockets[0]));
		}, "Failed malicious VOLE response send allowed a retry");
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

    void OtExt_SoftSpoken_BufferState_Audit_Test(const oc::CLP&)
    {
#ifdef ENABLE_SOFTSPOKEN_OT
        const auto expectRejected = [](auto&& fn, const char* message) {
            bool rejected = false;
            try { fn(); }
            catch (const std::exception&) { rejected = true; }
            if (!rejected)
                throw UnitTestFail(message);
        };

        using Sender = SubspaceVoleSender<RepetitionCode>;
        using Receiver = SubspaceVoleReceiver<RepetitionCode>;
        constexpr u64 fieldBits = 1;
        const u64 numVoles = divCeil(gOtExtBaseOtCount, fieldBits);

        Sender moveSource;
        moveSource.init(fieldBits, numVoles);
        moveSource.mMessages.resize(2);
        moveSource.mMessages[0] = block::allSame(0x44);
        moveSource.mMessages[1] = block::allSame(0x45);
        Sender moveDestination(std::move(moveSource));
        if (!moveSource.mMessages.empty() || moveDestination.mMessages.size() != 2 ||
            moveDestination.mMessages[0] != block::allSame(0x44) ||
            moveDestination.mMessages[1] != block::allSame(0x45))
            throw UnitTestFail(
                "Subspace VOLE move construction lost its send buffer");

        Sender assignmentSource;
        assignmentSource.init(fieldBits, numVoles);
        assignmentSource.mMessages.resize(1);
        assignmentSource.mMessages[0] = block::allSame(0x46);
        Sender assignmentDestination;
        assignmentDestination.init(fieldBits, numVoles);
        assignmentDestination.mMessages.resize(1);
        assignmentDestination.mMessages[0] = block::allSame(0x99);
        assignmentDestination = std::move(assignmentSource);
        if (!assignmentSource.mMessages.empty() ||
            assignmentDestination.mMessages.size() != 1 ||
            assignmentDestination.mMessages[0] != block::allSame(0x46))
            throw UnitTestFail(
                "Subspace VOLE move assignment retained a stale send buffer");

        Sender reservationSender;
        reservationSender.init(fieldBits, numVoles);
        constexpr u64 chosen = 2;
        const u64 reservationPadding = reservationSender.mVole.uPadded() -
            reservationSender.code().codimension();
        const u64 expectedCapacity = reservationSender.code().length() * chosen +
            reservationPadding;
        reservationSender.reserveMessages(0, chosen);
        if (reservationSender.mMessages.capacity() != expectedCapacity)
            throw UnitTestFail(
                "Subspace VOLE multiplied its message reservation twice");
        expectRejected([&] { reservationSender.reserveMessages(~0ull, 1); },
            "Subspace VOLE accepted a wrapped message reservation");

        Receiver receiver;
        receiver.init(fieldBits, numVoles);
        auto sockets = cp::LocalAsyncSocket::makePair();
        receiver.mMessages.resize(1);
        receiver.mReadIndex = 0;
        expectRejected([&] { (void)receiver.recv(sockets[0], 1); },
            "Subspace VOLE discarded an unread receive buffer");

        receiver.mMessages.resize(2);
        receiver.mReadIndex = 1;
        expectRejected([&] { (void)receiver.getMessage(2, 2); },
            "Subspace VOLE read beyond its receive buffer");
        receiver.mReadIndex = 0;
        expectRejected([&] { (void)receiver.getMessage(2, 1); },
            "Subspace VOLE advanced beyond its padded message");
        receiver.clear();
        expectRejected([&] { (void)receiver.recv(sockets[0], ~0ull, 1); },
            "Subspace VOLE accepted a wrapped receive size");

        const block hashKey(0x4155442d303435ull, 0x525443522d4d4f56ull);
        const block aesSeed(0x53544154452d4d4full, 0x56452d4145530000ull);
        TwoOneRTCR<1> rtcrSource(hashKey, aesSeed);
        const block movedKey = rtcrSource.useAES(1).getKey();
        TwoOneRTCR<1> rtcrDestination(std::move(rtcrSource));
        if (rtcrDestination.useAES(1).getKey() != movedKey)
            throw UnitTestFail("TwoOneRTCR move construction lost its AES key");
        expectRejected([&] { (void)rtcrSource.useAES(1); },
            "TwoOneRTCR move construction left the source seeded");

        TwoOneRTCR<1> rtcrAssignmentSource(hashKey, aesSeed);
        const block assignedKey = rtcrAssignmentSource.useAES(1).getKey();
        TwoOneRTCR<1> rtcrAssignmentDestination(
            block::allSame(0x77), block::allSame(0x88));
        (void)rtcrAssignmentDestination.useAES(1);
        rtcrAssignmentDestination = std::move(rtcrAssignmentSource);
        if (rtcrAssignmentDestination.useAES(1).getKey() != assignedKey)
            throw UnitTestFail("TwoOneRTCR move assignment retained a stale AES key");
        expectRejected([&] { (void)rtcrAssignmentSource.useAES(1); },
            "TwoOneRTCR move assignment left the source seeded");

        SoftSpokenShOtSender<> shSenderSource;
        SoftSpokenShOtSender<> shSenderDestination(std::move(shSenderSource));
        if (shSenderSource.fieldBits() || shSenderSource.hasBaseOts())
            throw UnitTestFail(
                "SoftSpoken sender move left active source state");
        expectRejected([&] { (void)shSenderSource.baseOtCount(); },
            "Moved-from SoftSpoken sender accepted base-OT counting");
        expectRejected([&] { (void)shSenderSource.delta(); },
            "Moved-from SoftSpoken sender exposed an empty delta");
        expectRejected([&] { (void)shSenderSource.split(); },
            "Moved-from SoftSpoken sender allowed splitting");
        shSenderSource.init();
        if (shSenderSource.baseOtCount() != gOtExtBaseOtCount)
            throw UnitTestFail(
                "Moved-from SoftSpoken sender could not be reinitialized");

        SoftSpokenShOtReceiver<> shReceiverSource;
        SoftSpokenShOtReceiver<> shReceiverDestination;
        shReceiverDestination = std::move(shReceiverSource);
        if (shReceiverSource.fieldBits() || shReceiverSource.hasBaseOts())
            throw UnitTestFail(
                "SoftSpoken receiver move left active source state");
        expectRejected([&] { (void)shReceiverSource.baseOtCount(); },
            "Moved-from SoftSpoken receiver accepted base-OT counting");
        expectRejected([&] { (void)shReceiverSource.split(); },
            "Moved-from SoftSpoken receiver allowed splitting");
        shReceiverSource.init();
        if (shReceiverSource.baseOtCount() != gOtExtBaseOtCount)
            throw UnitTestFail(
                "Moved-from SoftSpoken receiver could not be reinitialized");

        SoftSpokenMalOtSender malSenderSource;
        SoftSpokenMalOtSender malSenderDestination(std::move(malSenderSource));
        expectRejected([&] { (void)malSenderSource.baseOtCount(); },
            "Moved-from malicious SoftSpoken sender accepted base-OT counting");
        expectRejected([&] { (void)malSenderSource.delta(); },
            "Moved-from malicious SoftSpoken sender exposed an empty delta");
        expectRejected([&] { (void)malSenderSource.split(); },
            "Moved-from malicious SoftSpoken sender allowed splitting");
        malSenderSource.init();

        SoftSpokenMalOtReceiver malReceiverSource;
        SoftSpokenMalOtReceiver malReceiverDestination;
        malReceiverDestination = std::move(malReceiverSource);
        expectRejected([&] { (void)malReceiverSource.baseOtCount(); },
            "Moved-from malicious SoftSpoken receiver accepted base-OT counting");
        expectRejected([&] { (void)malReceiverSource.split(); },
            "Moved-from malicious SoftSpoken receiver allowed splitting");
        malReceiverSource.init();

        SoftSpokenMalOtReceiver emptyReceiver;
        BitVector emptyChoices;
        AlignedUnVector<block> emptyMessages;
        PRNG prng(block::allSame(0x50));
        auto emptySockets = cp::LocalAsyncSocket::makePair();
        expectRejected([&] {
            cp::sync_wait(emptyReceiver.receive(
                emptyChoices, emptyMessages, prng, emptySockets[0]));
        }, "SoftSpoken malicious receiver accepted an empty request");
        if (emptyReceiver.hasBaseOts() ||
            emptyReceiver.mBase.mSubVole.hasSeed() ||
            emptyReceiver.mBase.mBlockIdx != 0)
            throw UnitTestFail(
                "SoftSpoken mutated receiver state for an empty request");
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

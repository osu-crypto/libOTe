#include "libOTe/Vole/LogVole/LogVole.h"
#include "libOTe/Vole/LogVole/LogVoleArithmetic.h"
#include "libOTe/Vole/LogVole/LogVoleParallel.h"
#include "libOTe/Vole/LogVole/LogVoleLenc.h"
#include "libOTe/Vole/LogVole/LogVoleLhe.h"
#include "libOTe_Tests/LogVole_TestUtil.h"
#include "cryptoTools/Common/CLP.h"
#include "coproto/Socket/LocalAsyncSock.h"
#include "macoro/sync_wait.h"
#include "macoro/when_all.h"

#include <array>
#include <barrier>
#include <future>
#include <tuple>
#include <vector>

using namespace osuCrypto;
using namespace osuCrypto::LogVole;

namespace
{
    struct SessionResult
    {
        std::vector<u64> mKeys, mMacs;
        std::array<u64, 4> mSenderRandom{}, mReceiverRandom{};
    };

    SessionResult runSession(u64 seed, u32 threads, bool useGpu, std::barrier<>* start = nullptr)
    {
        constexpr u64 count = 1u << 16, delta = 19;
        LogVoleSender sender;
        LogVoleReceiver receiver;
        sender.mUseGpu = useGpu;
        receiver.mUseGpu = useGpu;
        sender.configure(count, 55, threads);
        receiver.configure(count, 55, threads);
        PRNG senderPrng(toBlock(0x53454e44, seed));
        PRNG receiverPrng(toBlock(0x52454356, seed));
        if (start) start->arrive_and_wait();
        auto offline = coproto::LocalAsyncSocket::makePair();
        auto setup = macoro::sync_wait(macoro::when_all_ready(
            sender.offline(delta, senderPrng, offline[0]), receiver.offline(offline[1])));
        std::get<0>(setup).result();
        std::get<1>(setup).result();
        SessionResult result;
        result.mKeys.resize(2 * count);
        result.mMacs.resize(2 * count);
        std::vector<u64> x(count);
        const seal::Modulus modulus(sender.modulus());
        for (u64 query = 0; query != 2; ++query)
        {
            for (u64 i = 0; i != count; ++i) x[i] = (i * 7 + query) % modulus.value();
            auto online = coproto::LocalAsyncSocket::makePair();
            auto keys = span<u64>(result.mKeys).subspan(query * count, count);
            auto macs = span<u64>(result.mMacs).subspan(query * count, count);
            auto outputs = macoro::sync_wait(macoro::when_all_ready(
                sender.send(keys, senderPrng, online[0]),
                receiver.receive(x, macs, receiverPrng, online[1])));
            std::get<0>(outputs).result();
            std::get<1>(outputs).result();
            for (u64 i = 0; i != count; ++i)
                LOGVOLE_REQUIRE_EQ(macs[i], mulAddMod(x[i], delta, keys[i], modulus));
        }
        senderPrng.get(result.mSenderRandom.data(), result.mSenderRandom.size());
        receiverPrng.get(result.mReceiverRandom.data(), result.mReceiverRandom.size());
        return result;
    }

    void sameResult(const SessionResult& first, const SessionResult& second, const char* stage)
    {
        LOGVOLE_REQUIRE_TRUE(first.mKeys == second.mKeys) << stage;
        LOGVOLE_REQUIRE_TRUE(first.mMacs == second.mMacs) << stage;
        LOGVOLE_REQUIRE_TRUE(first.mSenderRandom == second.mSenderRandom) << stage;
        LOGVOLE_REQUIRE_TRUE(first.mReceiverRandom == second.mReceiverRandom) << stage;
    }
}

void LogVole_Core_IndependentExecutionContexts(const CLP&)
{
    std::weak_ptr<ExecutionContext> lifetime;
    {
        RingParams params;
        params.mPolyModulusDegree = 1024;
        assignValues(params.mCoeffModulusBits, {30, 30});
        RingParams other = params;
        other.mExecutionContext = std::make_shared<ExecutionContext>();
        RingNttContext first, repeated, independent;
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, first));
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, repeated));
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(other, independent));
        LOGVOLE_REQUIRE_TRUE(first.mContext == repeated.mContext);
        LOGVOLE_REQUIRE_TRUE(first.mContext != independent.mContext);
        ZpCrtContext firstZp, repeatedZp, independentZp;
        LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(params, 20, firstZp));
        LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(params, 20, repeatedZp));
        LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(other, 20, independentZp));
        LOGVOLE_REQUIRE_TRUE(firstZp.mBatchEncoder == repeatedZp.mBatchEncoder);
        LOGVOLE_REQUIRE_TRUE(firstZp.mBatchEncoder != independentZp.mBatchEncoder);
        const auto firstA = sharedLhePublicANtt(first, 2);
        const auto firstB = sharedLencPublicBNtt(first, 2);
        LOGVOLE_REQUIRE_TRUE(firstA == sharedLhePublicANtt(repeated, 2));
        LOGVOLE_REQUIRE_TRUE(firstA != sharedLhePublicANtt(independent, 2));
        LOGVOLE_REQUIRE_TRUE(firstB == sharedLencPublicBNtt(repeated, 2));
        LOGVOLE_REQUIRE_TRUE(firstB != sharedLencPublicBNtt(independent, 2));
        lifetime = params.mExecutionContext;
        executionContext(params).mRingOps.reset();
        RnsPoly zero, output;
        resizeZero(zero.mCoeffs, ringPolyCoeffCount(params));
        LOGVOLE_REQUIRE_TRUE(ringAdd(zero, zero, first, output));
        LOGVOLE_REQUIRE_EQ(executionContext(params).mRingOps.mAddCount.load(), 1u);
        LOGVOLE_REQUIRE_EQ(executionContext(other).mRingOps.mAddCount.load(), 0u);
        const auto quota = osuCrypto::LogVole::detail::hardwareWorkerSlots();
        osuCrypto::LogVole::detail::ParallelWorkerSlotGuard one(
            quota, nullptr, params.mExecutionContext.get());
        osuCrypto::LogVole::detail::ParallelWorkerSlotGuard two(
            quota, nullptr, other.mExecutionContext.get());
        LOGVOLE_REQUIRE_EQ(one.grantedWorkers(), quota);
        LOGVOLE_REQUIRE_EQ(two.grantedWorkers(), quota);
    }
    LOGVOLE_REQUIRE_TRUE(lifetime.expired());
}

void LogVole_Core_SeededSessionIsolation(const CLP& cmd)
{
    const auto serial = runSession(91, 1, false);
    sameResult(serial, runSession(91, 1, false), "repeat with one worker");
    const auto expected = runSession(91, 2, false);
    (void)runSession(92, 1, false);
    sameResult(expected, runSession(91, 2, false), "repeat with two workers");
    std::barrier start(2);
    auto unrelated = std::async(std::launch::async, [&] {
        return runSession(93, 1, cmd.getOr("gpu", 0) != 0, &start);
    });
    sameResult(expected, runSession(91, 2, false, &start), "concurrent independent session");
    (void)unrelated.get();
}

#include "libOTe_Tests/LogVole_SenderResources.h"
#include "libOTe/Vole/LogVole/LogVoleRingReceiver.h"
#include "libOTe/Vole/LogVole/LogVoleRingSender.h"

#include "libOTe_Tests/LogVole_TestUtil.h"

#include "coproto/Socket/LocalAsyncSock.h"
#include "macoro/sync_wait.h"
#include "macoro/thread_pool.h"
#include "macoro/when_all.h"

#include "seal/util/rns.h"
#include "seal/util/uintarith.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <tuple>
#include <vector>

using namespace osuCrypto::LogVole;

namespace
{
    ShrinkExpandParams make_params(bool trunc = false)
    {
        ShrinkExpandParams params{};
        params.mRing.mPolyModulusDegree = 1024;
        assignValues<int>(params.mRing.mCoeffModulusBits, { 30, 30 });
        params.mPlaintextModulusBits = 20;
        params.mAlpha = 2;
        params.mMu = trunc ? 4u : 3u;
        params.mTau = trunc ? 2u : 3u;
        params.mGadgetLogBase = 20;
        params.mMode = ShrinkExpandMode::FullNoise;
        params.mNoiseBound = 2;
        params.mTruncateOneGadgetDigit = trunc;
        return params;
    }

    ShrinkExpandParams make_full_noise_params()
    {
        auto params = make_params();
        assignValues<int>(params.mRing.mCoeffModulusBits, { 54, 54, 54, 54, 54, 54, 54 });
        params.mPlaintextModulusBits = 54;
        params.mGadgetLogBase = 126;
        params.mMode = ShrinkExpandMode::FullNoise;
        params.mNoiseBound = 2;
        return params;
    }

    std::vector<RnsPoly> sample_batch(const RingNttContext& ctx, std::uint32_t count, std::uint64_t seed)
    {
        std::vector<RnsPoly> out;
        out.reserve(count);
        for (std::uint32_t i = 0; i < count; ++i)
        {
            out.push_back(deriveUniformPolyFromNonce(ctx, seed, 0x1E2C0005u, i));
        }
        return out;
    }

    RnsPoly sample_poly(const RingNttContext& ctx, std::uint64_t seed)
    {
        return deriveUniformPolyFromNonce(ctx, seed, 0x1E2C0006u, 0);
    }

    void expect_poly_equal(const RnsPoly& a, const RnsPoly& b)
    {
        LOGVOLE_REQUIRE_EQ(a.mCoeffs.size(), b.mCoeffs.size());
        for (std::size_t i = 0; i < a.mCoeffs.size(); ++i)
        {
            LOGVOLE_EXPECT_EQ(a.mCoeffs[i], b.mCoeffs[i]) << "coeff idx " << i;
        }
    }

    void expect_batch_equal(const std::vector<RnsPoly>& a, const std::vector<RnsPoly>& b)
    {
        LOGVOLE_REQUIRE_EQ(a.size(), b.size());
        for (std::size_t i = 0; i < a.size(); ++i)
        {
            expect_poly_equal(a[i], b[i]);
        }
    }

    std::vector<RnsPoly> multiply_batches(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& a,
        const std::vector<RnsPoly>& b)
    {
        std::vector<RnsPoly> out;
        out.reserve(a.size());
        for (std::size_t i = 0; i < a.size(); ++i)
        {
            RnsPoly product{};
            LOGVOLE_REQUIRE_TRUE(ringMultiply(a[i], b[i], ctx, product));
            out.push_back(std::move(product));
        }
        return out;
    }

    std::vector<RnsPoly> subtract_batches(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& a,
        const std::vector<RnsPoly>& b)
    {
        std::vector<RnsPoly> out;
        out.reserve(a.size());
        for (std::size_t i = 0; i < a.size(); ++i)
        {
            RnsPoly diff{};
            LOGVOLE_REQUIRE_TRUE(ringSub(a[i], b[i], ctx, diff));
            out.push_back(std::move(diff));
        }
        return out;
    }

    std::uint32_t log_q_bits(const ShrinkExpandParams& params)
    {
        std::uint32_t out = 0;
        for (const auto bits : params.mRing.mCoeffModulusBits)
        {
            out += static_cast<std::uint32_t>(bits);
        }
        return out;
    }

    long double centered_max_log2(const RingNttContext& ctx, const std::vector<RnsPoly>& batch)
    {
        std::uint64_t maxAbs = 0;
        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        for (const auto& poly : batch)
        {
            for (std::size_t modIdx = 0; modIdx < ringModulusCount(ctx); ++modIdx)
            {
                const std::uint64_t mod = ringModulusValue(ctx, modIdx);
                const std::size_t offset = modIdx * n;
                for (std::size_t i = 0; i < n; ++i)
                {
                    const std::uint64_t reduced = poly.mCoeffs[offset + i] % mod;
                    const std::uint64_t centered = (reduced <= (mod / 2u)) ? reduced : (mod - reduced);
                    maxAbs = std::max(maxAbs, centered);
                }
            }
        }

        return maxAbs == 0 ? 0.0L : std::log2(static_cast<long double>(maxAbs));
    }

    long double max_centered_log2(const RingNttContext& ctx, const std::vector<RnsPoly>& polys)
    {
        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        const std::size_t rho = ctx.mParams.mCoeffModulusBits.size();
        const auto hostContext = getRingHostContext(ctx);
        LOGVOLE_REQUIRE_TRUE(hostContext != nullptr);
        auto contextData = hostContext->key_context_data();
        seal::util::RNSBase fullBase(contextData->parms().coeff_modulus(), seal::MemoryManager::GetPool());

        auto composedPoly = seal::util::allocate_poly(n, rho, seal::MemoryManager::GetPool());
        auto coeffMpi = seal::util::allocate_uint(rho, seal::MemoryManager::GetPool());

        long double maxLog2 = 0.0L;
        for (const auto& poly : polys)
        {
            std::copy(poly.mCoeffs.begin(), poly.mCoeffs.end(), composedPoly.get());
            fullBase.compose_array(composedPoly.get(), n, seal::MemoryManager::GetPool());

            for (std::size_t i = 0; i < n; ++i)
            {
                const std::uint64_t* valPtr = composedPoly.get() + i * rho;
                const int bitCountPos = seal::util::get_significant_bit_count_uint(valPtr, rho);

                seal::util::sub_uint(fullBase.base_prod(), valPtr, rho, coeffMpi.get());
                const int bitCountNeg = seal::util::get_significant_bit_count_uint(coeffMpi.get(), rho);

                const int bitCount = std::min(bitCountPos, bitCountNeg);
                if (bitCount > maxLog2)
                {
                    maxLog2 = bitCount;
                }
            }
        }
        return maxLog2;
    }

    void run_offline(
        const ShrinkExpandParams& params,
        const std::vector<RnsPoly>& s,
        LogVoleRingSender& sender,
        LogVoleRingReceiver& receiver,
        ShrinkExpandSenderState& senderState,
        ShrinkExpandReceiverState& receiverState,
        osuCrypto::LogVoleExecutionOptions execution = {})
    {
    tests_libOTe::logvole_test::SetupResources setupResources;
        RingNttContext ctx;
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, ctx,
            std::make_shared<RingContextFactory>(execution)));
        ShrinkExpandSenderOfflineInput senderOfflineInput{};
        senderOfflineInput.mRingFactoryOwner = ctx.mFactoryOwner;
        senderOfflineInput.mParams = params;
        senderOfflineInput.mS = s;

        ShrinkExpandReceiverOfflineInput receiverOfflineInput{};
        receiverOfflineInput.mRingFactoryOwner = ctx.mFactoryOwner;
        receiverOfflineInput.mParams = params;

        auto offlineSockets = coproto::LocalAsyncSocket::makePair();
        oc::PRNG offlinePrng(oc::block(0x515EEDu, 0));
        auto offlineResult = macoro::sync_wait(macoro::when_all_ready(
            sender.offline(setupResources.executor, setupResources.results, senderOfflineInput, senderState, offlinePrng, offlineSockets[0]),
            receiver.offline(receiverOfflineInput, receiverState, offlineSockets[1])));
        std::get<0>(offlineResult).result();
        std::get<1>(offlineResult).result();
    }

    void run_expand(
        macoro::thread_pool& executor, std::span<LheDecryptBuffer> buffers,
        std::span<LheDecryptBuffer> receiverBuffers, std::span<LencEvalBuffer> lencBuffers,
        LogVoleRingSender& sender,
        LogVoleRingReceiver& receiver,
        const ShrinkExpandSenderState& senderState,
        const ShrinkExpandReceiverState& receiverState,
        std::uint64_t nonce,
        const RnsPoly& tbkPrime,
        const std::vector<RnsPoly>& x,
        ShrinkExpandSenderExpandOutput& senderOutput,
        ShrinkExpandReceiverExpandOutput& receiverOutput)
    {
        ShrinkExpandExpandSenderInput senderExpandInput{};
        senderExpandInput.mSid = nonce;
        resizeFill<std::uint8_t>(senderExpandInput.mSeed, 16, static_cast<std::uint8_t>(0x5Du));
        senderExpandInput.mNonce = nonce;
        senderExpandInput.mTbkPrime = tbkPrime;

        ReceiverExpandInput receiverExpandInput{};
        receiverExpandInput.mSid = senderExpandInput.mSid;
        receiverExpandInput.mSeed = senderExpandInput.mSeed;
        receiverExpandInput.mNonce = nonce;
        receiverExpandInput.mX = x;

        std::vector<const std::uint64_t*> maskAllocations;
        {
            auto lease = detail::ShrinkExpandScratch::acquire(receiverState.mCpuScratch);
            auto& masks = lease.ct2();
            masks.resize(receiverState.mParams.mMu);
            for (auto& mask : masks)
            {
                mask.mCoeffs.resize(ringPolyCoeffCount(receiverState.mParams.mRing));
                maskAllocations.push_back(mask.mCoeffs.data());
            }
        }
        auto checkMaskReuse = [&] {
            auto lease = detail::ShrinkExpandScratch::acquire(receiverState.mCpuScratch);
            LOGVOLE_REQUIRE_EQ(lease.ct2().size(), maskAllocations.size());
            for (std::size_t i = 0; i < maskAllocations.size(); ++i)
                LOGVOLE_REQUIRE_TRUE(lease.ct2()[i].mCoeffs.data() == maskAllocations[i]);
        };
        std::vector<const std::uint64_t*> productAllocations;
        for (const auto& buffer : buffers) productAllocations.push_back(buffer.mProduct.mCoeffs.data());
        std::vector<const std::uint64_t*> receiverAllocations;
        for (const auto& buffer : receiverBuffers) receiverAllocations.push_back(buffer.mProduct.mCoeffs.data());
        std::vector<const RnsPoly* const*> ciphertextAllocations, nodeAllocations;
        for (const auto& buffer : lencBuffers)
        {
            ciphertextAllocations.push_back(buffer.mCiphertexts.data());
            nodeAllocations.push_back(buffer.mNodes.data());
        }
        auto onWorker = [](macoro::thread_pool& pool, macoro::task<> operation) -> macoro::task<> {
            co_await pool.schedule();
            co_await std::move(operation);
        };
        // Count the sender key derivation separately from its dyadic expansion.
        // Repeat with a null selection on the same prepared resources.
        RingOpsStats senderStats;
        auto countedSender = senderState;
        auto countedContext = std::make_shared<RingNttContext>(*senderState.mRingFactoryOwner);
        countedContext->mExecutionOptions.mRingOpsStats = &senderStats;
        countedSender.mRingFactoryOwner = countedContext;
        for (bool collect : {true, false})
        {
            countedContext->mExecutionOptions.mRingOpsStats = collect ? &senderStats : nullptr;
            auto onlineSockets = coproto::LocalAsyncSocket::makePair();
            auto onlineResult = macoro::sync_wait(macoro::when_all_ready(
                sender.expand(executor, buffers, countedSender, senderExpandInput, senderOutput, onlineSockets[0]),
                onWorker(executor, receiver.expand(executor, receiverBuffers, lencBuffers,
                    receiverState, receiverExpandInput, receiverOutput, onlineSockets[1]))));
            std::get<0>(onlineResult).result();
            std::get<1>(onlineResult).result();
            LOGVOLE_REQUIRE_EQ(senderStats.mMulCount.load(), senderState.mParams.mTau);
        }
        checkMaskReuse();
        for (std::size_t i = 0; i < buffers.size(); ++i)
            LOGVOLE_REQUIRE_TRUE(buffers[i].mProduct.mCoeffs.data() == productAllocations[i]);
        for (std::size_t i = 0; i < receiverBuffers.size(); ++i)
            LOGVOLE_REQUIRE_TRUE(receiverBuffers[i].mProduct.mCoeffs.data() == receiverAllocations[i]);
        for (std::size_t i = 0; i < lencBuffers.size(); ++i)
        {
            LOGVOLE_REQUIRE_TRUE(lencBuffers[i].mCiphertexts.data() == ciphertextAllocations[i]);
            LOGVOLE_REQUIRE_TRUE(lencBuffers[i].mNodes.data() == nodeAllocations[i]);
            LOGVOLE_REQUIRE_TRUE(lencBuffers[i].mCiphertexts.empty() && lencBuffers[i].mNodes.empty());
        }
        // Socket and direct async expansion must preserve the same arithmetic result.
        ShrinkExpandShrinkOutput shrink;
        LOGVOLE_REQUIRE_TRUE(shrinkExpandShrink(receiverState, x, shrink));
        senderExpandInput.mDigest = std::move(shrink.mDigest);
        ShrinkExpandSenderExpandOutput reference;
        LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(shrinkExpandExpandSender(executor, std::span(buffers).first(1),
            senderState, senderExpandInput, reference)));
        expect_batch_equal(senderOutput.mTbk, reference.mTbk);

        ShrinkExpandExpandReceiverInput coreInput;
        coreInput.mSeed = receiverExpandInput.mSeed;
        coreInput.mSid = receiverExpandInput.mSid;
        coreInput.mNonce = receiverExpandInput.mNonce;
        coreInput.mDigest = senderExpandInput.mDigest;
        coreInput.mTree = shrink.mTree;
        RingNttContext ctx;
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(senderState.mParams.mRing, ctx, senderState.mRingFactoryOwner));
        const auto& params = senderState.mParams;
        LOGVOLE_REQUIRE_TRUE(params.mTruncateOneGadgetDigit
            ? deriveSkxTrunc(ctx, senderState.hostSk1(), coreInput.mDigest, tbkPrime,
                params.mGadgetLogBase, params.mTau, coreInput.mSkX)
            : deriveSkx(ctx, senderState.hostSk1(), coreInput.mDigest, tbkPrime,
                params.mGadgetLogBase, params.mTau, coreInput.mSkX));
        ShrinkExpandReceiverExpandOutput receiverReference;
        LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(shrinkExpandExpandReceiver(executor, std::span(receiverBuffers).first(1),
            std::span(lencBuffers).first(1), receiverState, coreInput, receiverReference)));
        expect_batch_equal(receiverOutput.mTbm, receiverReference.mTbm);
        if (params.mTruncateOneGadgetDigit)
        {
            // Failure after LHE must not publish partial receiver output.
            auto preserved = receiverOutput;
            LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(shrinkExpandExpandReceiver(executor,
                receiverBuffers, {}, receiverState, coreInput, preserved)));
            expect_batch_equal(preserved.mTbm, receiverOutput.mTbm);
            checkMaskReuse();
        }
    }

    void expect_relation(
        const RingNttContext& ctx,
        const ShrinkExpandParams& params,
        const std::vector<RnsPoly>& s,
        const std::vector<RnsPoly>& x,
        const ShrinkExpandSenderExpandOutput& senderOutput,
        const ShrinkExpandReceiverExpandOutput& receiverOutput)
    {
        const auto tbmMinusTbk = subtract_batches(ctx, receiverOutput.mTbm, senderOutput.mTbk);
        const auto expected = multiply_batches(ctx, s, x);

        if (!params.mTruncateOneGadgetDigit && params.mMode != ShrinkExpandMode::FullNoise)
        {
            expect_batch_equal(tbmMinusTbk, expected);
            return;
        }

        const auto residual = subtract_batches(ctx, tbmMinusTbk, expected);
        if (params.mMode == ShrinkExpandMode::FullNoise)
        {
            const auto maxLog2 = max_centered_log2(ctx, residual);
            LOGVOLE_EXPECT_GT(maxLog2, 0);
            LOGVOLE_EXPECT_LT(maxLog2, static_cast<double>(log_q_bits(params)));
            return;
        }

        const long double pathLen = 1.0L + std::log2(static_cast<long double>(params.mMu));
        const long double truncationBoundLog2 = static_cast<long double>(params.mGadgetLogBase) +
                                               std::log2(static_cast<long double>(params.mRing.mPolyModulusDegree)) +
                                               std::log2(pathLen);
        LOGVOLE_EXPECT_LT(centered_max_log2(ctx, residual), truncationBoundLog2 + 2.0L);
    }
}

void LogVole_ShrinkExpandCoproto_OfflineAndExpandDeterministicRelation(const oc::CLP&)
{
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, ctx));

    const auto s = sample_batch(ctx, params.mMu, 0x2001u);

    // The application owns one executor and prepared buffers across queries.
    macoro::thread_pool executor;
    auto work = executor.make_work();
    executor.create_threads(1);
    std::array<LheDecryptBuffer, 3> buffers;
    for (auto& buffer : buffers) buffer.mProduct.mCoeffs.resize(ringPolyCoeffCount(params.mRing));
    LogVoleRingSender sender{};
    LogVoleRingReceiver receiver{};
    ShrinkExpandSenderState senderState{};
    ShrinkExpandReceiverState receiverState{};
    run_offline(params, s, sender, receiver, senderState, receiverState);
    std::array<LheDecryptBuffer, 3> receiverBuffers;
    for (auto& buffer : receiverBuffers) buffer.mProduct.mCoeffs.resize(ringPolyCoeffCount(params.mRing));
    std::array<LencEvalBuffer, 3> lencBuffers;
    const auto terms = std::size_t{2} * receiverState.hostLacct().mLevels * (params.mTau + 1);
    for (auto& buffer : lencBuffers)
    {
        buffer.mCiphertexts.reserve(terms);
        buffer.mNodes.reserve(terms);
    }

    auto x = sample_batch(ctx, params.mMu, 0x3001u);
    const auto tbkPrime = sample_poly(ctx, 0x4001u);

    ShrinkExpandSenderExpandOutput senderOutput{};
    ShrinkExpandReceiverExpandOutput receiverOutput{};
    run_expand(executor, buffers, receiverBuffers, lencBuffers, sender, receiver, senderState, receiverState, 0x999u, tbkPrime, x, senderOutput, receiverOutput);

    expect_relation(ctx, params, s, x, senderOutput, receiverOutput);
}

void LogVole_ShrinkExpandCoproto_TruncOfflineAndExpandBoundedRelation(const oc::CLP&)
{
    const auto params = make_params(true);
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, ctx));

    const auto s = sample_batch(ctx, params.mMu, 0x2101u);

    // The application owns one executor and prepared buffers across queries.
    macoro::thread_pool executor;
    auto work = executor.make_work();
    executor.create_threads(1);
    std::array<LheDecryptBuffer, 3> buffers;
    for (auto& buffer : buffers) buffer.mProduct.mCoeffs.resize(ringPolyCoeffCount(params.mRing));
    LogVoleRingSender sender{};
    LogVoleRingReceiver receiver{};
    ShrinkExpandSenderState senderState{};
    ShrinkExpandReceiverState receiverState{};
    osuCrypto::LogVoleExecutionOptions execution;
    run_offline(params, s, sender, receiver, senderState, receiverState, execution);
    std::array<LheDecryptBuffer, 3> receiverBuffers;
    for (auto& buffer : receiverBuffers) buffer.mProduct.mCoeffs.resize(ringPolyCoeffCount(params.mRing));
    std::array<LencEvalBuffer, 3> lencBuffers;
    const auto terms = std::size_t{2} * receiverState.hostLacct().mLevels * (params.mTau + 1);
    for (auto& buffer : lencBuffers)
    {
        buffer.mCiphertexts.reserve(terms);
        buffer.mNodes.reserve(terms);
    }

    auto x = sample_batch(ctx, params.mMu, 0x3101u);
    const auto tbkPrime = sample_poly(ctx, 0x4101u);

    ShrinkExpandSenderExpandOutput senderOutput{};
    ShrinkExpandReceiverExpandOutput receiverOutput{};
    run_expand(executor, buffers, receiverBuffers, lencBuffers, sender, receiver, senderState, receiverState, 0xA99u, tbkPrime, x, senderOutput, receiverOutput);

    expect_relation(ctx, params, s, x, senderOutput, receiverOutput);
}

void LogVole_ShrinkExpandCoproto_FullNoiseTolerance(const oc::CLP&)
{
    const auto params = make_full_noise_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, ctx));

    const auto s = sample_batch(ctx, params.mMu, 0x5001u);

    // The application owns one executor and prepared buffers across queries.
    macoro::thread_pool executor;
    auto work = executor.make_work();
    executor.create_threads(1);
    std::array<LheDecryptBuffer, 3> buffers;
    for (auto& buffer : buffers) buffer.mProduct.mCoeffs.resize(ringPolyCoeffCount(params.mRing));
    LogVoleRingSender sender{};
    LogVoleRingReceiver receiver{};
    ShrinkExpandSenderState senderState{};
    ShrinkExpandReceiverState receiverState{};
    run_offline(params, s, sender, receiver, senderState, receiverState);
    std::array<LheDecryptBuffer, 3> receiverBuffers;
    for (auto& buffer : receiverBuffers) buffer.mProduct.mCoeffs.resize(ringPolyCoeffCount(params.mRing));
    std::array<LencEvalBuffer, 3> lencBuffers;
    const auto terms = std::size_t{2} * receiverState.hostLacct().mLevels * (params.mTau + 1);
    for (auto& buffer : lencBuffers)
    {
        buffer.mCiphertexts.reserve(terms);
        buffer.mNodes.reserve(terms);
    }

    auto x = sample_batch(ctx, params.mMu, 0x6001u);
    const auto tbkPrime = sample_poly(ctx, 0x7001u);

    ShrinkExpandSenderExpandOutput senderOutput{};
    ShrinkExpandReceiverExpandOutput receiverOutput{};
    run_expand(executor, buffers, receiverBuffers, lencBuffers, sender, receiver, senderState, receiverState, 0xAAA1u, tbkPrime, x, senderOutput, receiverOutput);

    expect_relation(ctx, params, s, x, senderOutput, receiverOutput);
}

void LogVole_ShrinkExpandCoproto_OfflineStateReuseAcrossQueries(const oc::CLP&)
{
    for (bool truncated : {false, true})
    {
        const auto params = make_params(truncated);
        RingNttContext ctx{};
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, ctx));

        const auto s = sample_batch(ctx, params.mMu, 0xA001u);

        // The application owns one executor and prepared buffers across queries.
        macoro::thread_pool executor;
        auto work = executor.make_work();
        executor.create_threads(1);
        std::array<LheDecryptBuffer, 3> buffers;
        for (auto& buffer : buffers) buffer.mProduct.mCoeffs.resize(ringPolyCoeffCount(params.mRing));
        LogVoleRingSender sender{};
        LogVoleRingReceiver receiver{};
        ShrinkExpandSenderState senderState{};
        ShrinkExpandReceiverState receiverState{};
        run_offline(params, s, sender, receiver, senderState, receiverState);
        std::array<LheDecryptBuffer, 3> receiverBuffers;
        for (auto& buffer : receiverBuffers) buffer.mProduct.mCoeffs.resize(ringPolyCoeffCount(params.mRing));
        std::array<LencEvalBuffer, 3> lencBuffers;
        const auto terms = std::size_t{2} * receiverState.hostLacct().mLevels * (params.mTau + 1);
        for (auto& buffer : lencBuffers)
        {
            buffer.mCiphertexts.reserve(terms);
            buffer.mNodes.reserve(terms);
        }

        for (std::uint64_t iter = 0; iter < 3; ++iter)
        {
            const auto x = sample_batch(ctx, params.mMu, 0xB000u + iter);
            const auto tbkPrime = sample_poly(ctx, 0xC000u + iter);

            ShrinkExpandSenderExpandOutput senderOutput{};
            ShrinkExpandReceiverExpandOutput receiverOutput{};
            run_expand(
                executor, buffers, std::span(receiverBuffers).first(iter == 1 ? 3 : 1),
                std::span(lencBuffers).first(iter == 1 ? 3 : 1),
                sender,
                receiver,
                senderState,
                receiverState,
                0xD000u + iter,
                tbkPrime,
                x,
                senderOutput,
                receiverOutput);

            expect_relation(ctx, params, s, x, senderOutput, receiverOutput);
        }
    }
}

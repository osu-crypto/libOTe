#include "libOTe_Tests/LogVole_SenderResources.h"
#include "libOTe/Vole/LogVole/LogVoleShrinkExpand.h"
#include "libOTe/Vole/LogVole/LogVoleEncoding.h"

#include "libOTe_Tests/LogVole_TestUtil.h"

#include "seal/util/rns.h"
#include "seal/util/uintarith.h"

#include "macoro/thread_pool.h"
#include "macoro/sync_wait.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <random>
#include <vector>

using namespace osuCrypto::LogVole;

namespace
{
    bool finalize_receiver_from_sender_wire(
        const ShrinkExpandReceiverOfflineInput& input,
        const ShrinkExpandSenderState& sender,
        ShrinkExpandReceiverState& receiver)
    {
        const auto workers = input.mParams.mNumWorkerThreads;
        auto bytes = encodeShrinkExpandOfflineState(sender, workers);
        ShrinkExpandOfflineMessage message;
        return decode(bytes, message, workers) &&
            finalizeShrinkExpandReceiverOffline(input, std::move(message), receiver);
    }

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
            out.push_back(deriveUniformPolyFromNonce(ctx, seed, 0x1E2C0003u, i));
        }
        return out;
    }

    RnsPoly sample_scalar(const RingNttContext& ctx, std::uint64_t seed)
    {
        return deriveUniformPolyFromNonce(ctx, seed, 0x1E2C0004u, 0);
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

    bool compute_expected_s_mul_x(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& s,
        const std::vector<RnsPoly>& x,
        std::vector<RnsPoly>& out)
    {
        if (s.size() != x.size())
        {
            return false;
        }

        out.clear();
        out.reserve(s.size());
        for (std::size_t i = 0; i < s.size(); ++i)
        {
            RnsPoly prod{};
            if (!ringMultiply(s[i], x[i], ctx, prod))
            {
                return false;
            }
            out.push_back(std::move(prod));
        }
        return true;
    }

    bool subtract_batches(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& a,
        const std::vector<RnsPoly>& b,
        std::vector<RnsPoly>& out)
    {
        if (a.size() != b.size())
        {
            return false;
        }

        out.clear();
        out.reserve(a.size());
        for (std::size_t i = 0; i < a.size(); ++i)
        {
            RnsPoly diff{};
            if (!ringSub(a[i], b[i], ctx, diff))
            {
                return false;
            }
            out.push_back(std::move(diff));
        }
        return true;
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
                    if (centered > maxAbs)
                    {
                        maxAbs = centered;
                    }
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

    std::uint32_t log_q_bits(const ShrinkExpandParams& params)
    {
        std::uint32_t out = 0;
        for (const auto bits : params.mRing.mCoeffModulusBits)
        {
            out += static_cast<std::uint32_t>(bits);
        }
        return out;
    }

    bool run_relation(bool trunc)
    {
    tests_libOTe::logvole_test::SetupResources setupResources;
        const auto params = make_params(trunc);
        CpuBenchmarkContext benchmark;
        benchmark.mCpus = {0, 1, 2};
        benchmark.mWorkerLimit = 3;
        RingNttContext ctx{};
        if (!makeRingNttContext(params.mRing, ctx))
        {
            return false;
        }

        const auto s = sample_batch(ctx, params.mMu, trunc ? 0x1101u : 0x1100u);
        const auto x = sample_batch(ctx, params.mMu, trunc ? 0x2201u : 0x2200u);
        const auto sk1 = sample_batch(ctx, params.mTau, trunc ? 0x3301u : 0x3300u);
        const auto tbkPrime = sample_scalar(ctx, trunc ? 0x4401u : 0x4400u);

        ShrinkExpandSenderOfflineInput senderInput{};
        senderInput.mParams = params;
        senderInput.mS = s;
        senderInput.mFixedSk1 = sk1;

        ShrinkExpandSenderState senderState{};
        oc::PRNG offlinePrng(oc::block(trunc ? 0xA101u : 0xA100u, 0));
        if (!macoro::sync_wait(prepareShrinkExpandSenderOffline(setupResources.executor, setupResources.results, senderInput, offlinePrng, senderState)))
        {
            return false;
        }

        ShrinkExpandReceiverOfflineInput receiverInput{};
        receiverInput.mParams = params;

        ShrinkExpandReceiverState receiverState{};
        if (!finalize_receiver_from_sender_wire(receiverInput, senderState, receiverState))
        {
            return false;
        }

        ShrinkExpandShrinkOutput shrink{};
        if (!shrinkExpandShrink(receiverState, x, shrink))
        {
            return false;
        }

        RnsPoly skX{};
        bool skxOk = false;
        if (trunc)
        {
            skxOk = deriveSkxTrunc(ctx, senderState.mSk1, shrink.mDigest, tbkPrime, params.mGadgetLogBase, params.mTau, skX);
        }
        else
        {
            skxOk = deriveSkx(ctx, senderState.mSk1, shrink.mDigest, tbkPrime, params.mGadgetLogBase, params.mTau, skX);
        }
        if (!skxOk)
        {
            return false;
        }

        ShrinkExpandExpandSenderInput senderExpandInput{};
        resizeFill<std::uint8_t>(
        senderExpandInput.mSeed,
            16,
            static_cast<std::uint8_t>(trunc ? 0x51u : 0x50u));
        senderExpandInput.mDigest = shrink.mDigest;
        senderExpandInput.mNonce = 0;
        senderExpandInput.mTbkPrime = tbkPrime;

        tests_libOTe::logvole_test::SenderResources senderResources(params.mRing, false, 3);
        tests_libOTe::logvole_test::ReceiverBuffers receiverBuffers(params, false, 3);
        ShrinkExpandSenderExpandOutput senderExpand{};
        if (!macoro::sync_wait(shrinkExpandExpandSender(senderResources.executor,
            std::span(senderResources.buffers).first(1), senderState, senderExpandInput, senderExpand)))
        {
            return false;
        }
        {
            auto lease = detail::ShrinkExpandScratch::acquire(senderState.mCpuScratch);
            LOGVOLE_REQUIRE_TRUE(lease.cpuRows().executor() == nullptr);
        }
        const auto* senderProduct = senderResources.buffers[0].mProduct.mCoeffs.data();
        for (oc::u32 workers : {3u, 3u, 1u})
        {
            benchmark.reset();
            ShrinkExpandSenderExpandOutput repeated;
            LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(shrinkExpandExpandSender(senderResources.executor,
                std::span(senderResources.buffers).first(workers), senderState, senderExpandInput,
                repeated, {&benchmark})));
            LOGVOLE_REQUIRE_EQ(benchmark.mActiveTaskThreads.load(), 0u);
            LOGVOLE_REQUIRE_TRUE(benchmark.mPeakTaskThreads.load() <= workers);
            LOGVOLE_REQUIRE_EQ(repeated.mTbk.size(), senderExpand.mTbk.size());
            for (std::size_t row = 0; row < repeated.mTbk.size(); ++row)
                LOGVOLE_REQUIRE_TRUE(rangesEqual(repeated.mTbk[row].mCoeffs, senderExpand.mTbk[row].mCoeffs));
            auto lease = detail::ShrinkExpandScratch::acquire(senderState.mCpuScratch);
            LOGVOLE_REQUIRE_TRUE(lease.cpuRows().executor() == nullptr);
            LOGVOLE_REQUIRE_TRUE(senderResources.buffers[0].mProduct.mCoeffs.data() == senderProduct);
        }

        ShrinkExpandExpandReceiverInput receiverExpandInput{};
        receiverExpandInput.mSid = senderExpandInput.mSid;
        receiverExpandInput.mSeed = senderExpandInput.mSeed;
        receiverExpandInput.mNonce = senderExpandInput.mNonce;
        receiverExpandInput.mX = x;
        receiverExpandInput.mDigest = shrink.mDigest;
        receiverExpandInput.mSkX = skX;
        receiverExpandInput.mTree = shrink.mTree;

        ShrinkExpandReceiverExpandOutput receiverExpand{};
        if (!macoro::sync_wait(shrinkExpandExpandReceiver(senderResources.executor,
            std::span(receiverBuffers.lhe).first(1), std::span(receiverBuffers.lenc).first(1),
            receiverState, receiverExpandInput, receiverExpand)))
        {
            return false;
        }
        {
            auto lease = detail::ShrinkExpandScratch::acquire(receiverState.mCpuScratch);
            LOGVOLE_REQUIRE_TRUE(lease.cpuRows().executor() == nullptr);
        }
        // Reuse the same operation storage across parallel and serial calls.
        // A serial allowance must remain serial even with a prepared pool.
        const auto* receiverProduct = receiverBuffers.lhe[0].mProduct.mCoeffs.data();
        const auto* receiverCiphertexts = receiverBuffers.lenc[0].mCiphertexts.data();
        const auto* receiverNodes = receiverBuffers.lenc[0].mNodes.data();
        for (oc::u32 workers : {3u, 3u, 1u})
        {
            benchmark.reset();
            ShrinkExpandReceiverExpandOutput repeated;
            LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(shrinkExpandExpandReceiver(senderResources.executor,
                std::span(receiverBuffers.lhe).first(workers), std::span(receiverBuffers.lenc).first(workers),
                receiverState, receiverExpandInput, repeated, {&benchmark})));
            LOGVOLE_REQUIRE_EQ(benchmark.mActiveTaskThreads.load(), 0u);
            LOGVOLE_REQUIRE_TRUE(benchmark.mPeakTaskThreads.load() <= workers);
            LOGVOLE_REQUIRE_EQ(repeated.mTbm.size(), receiverExpand.mTbm.size());
            for (std::size_t row = 0; row < repeated.mTbm.size(); ++row)
                LOGVOLE_REQUIRE_TRUE(rangesEqual(repeated.mTbm[row].mCoeffs, receiverExpand.mTbm[row].mCoeffs));
            auto lease = detail::ShrinkExpandScratch::acquire(receiverState.mCpuScratch);
            LOGVOLE_REQUIRE_TRUE(lease.cpuRows().executor() == nullptr);
            LOGVOLE_REQUIRE_TRUE(receiverBuffers.lhe[0].mProduct.mCoeffs.data() == receiverProduct);
            LOGVOLE_REQUIRE_TRUE(receiverBuffers.lenc[0].mCiphertexts.data() == receiverCiphertexts);
            LOGVOLE_REQUIRE_TRUE(receiverBuffers.lenc[0].mNodes.data() == receiverNodes);
            LOGVOLE_REQUIRE_TRUE(receiverBuffers.lenc[0].mCiphertexts.empty());
            LOGVOLE_REQUIRE_TRUE(receiverBuffers.lenc[0].mNodes.empty());
        }

        std::vector<RnsPoly> diff;
        std::vector<RnsPoly> expected;
        if (!subtract_batches(ctx, receiverExpand.mTbm, senderExpand.mTbk, diff) ||
            !compute_expected_s_mul_x(ctx, s, x, expected) ||
            diff.size() != expected.size())
        {
            return false;
        }

        if (!trunc && params.mMode != ShrinkExpandMode::FullNoise)
        {
            for (std::size_t i = 0; i < diff.size(); ++i)
            {
                if (!rangesEqual(diff[i].mCoeffs, expected[i].mCoeffs))
                {
                    return false;
                }
            }
            return true;
        }

        std::vector<RnsPoly> residual;
        if (!subtract_batches(ctx, diff, expected, residual))
        {
            return false;
        }

        if (params.mMode == ShrinkExpandMode::FullNoise)
        {
            const auto maxLog2 = max_centered_log2(ctx, residual);
            return maxLog2 > 0 && maxLog2 < static_cast<long double>(log_q_bits(params));
        }

        const long double pathLen = 1.0L + std::log2(static_cast<long double>(params.mMu));
        const long double truncationBoundLog2 = static_cast<long double>(params.mGadgetLogBase) +
                                               std::log2(static_cast<long double>(params.mRing.mPolyModulusDegree)) +
                                               std::log2(pathLen);
        return centered_max_log2(ctx, residual) < truncationBoundLog2 + 2.0L;
    }
}

void LogVole_ShrinkExpandCore_ParamsValidation(const oc::CLP&)
{
    using Scratch = detail::ShrinkExpandScratch;
    {
        ShrinkExpandSenderState sender;
        LOGVOLE_REQUIRE_FALSE(sender.mCpuScratch);
        sender.mCpuScratch = std::make_shared<Scratch>();
        const auto copy = sender;
        ShrinkExpandReceiverState receiver;
        LOGVOLE_REQUIRE_FALSE(receiver.mCpuScratch);
        receiver.mCpuScratch = std::make_shared<Scratch>();
        LOGVOLE_REQUIRE_TRUE(sender.mCpuScratch == copy.mCpuScratch);
        LOGVOLE_REQUIRE_TRUE(sender.mCpuScratch != receiver.mCpuScratch);
    }
    std::weak_ptr<Scratch> lifetime;
    {
        auto owner = std::make_shared<Scratch>();
        lifetime = owner;
        const std::uint64_t* firstData = nullptr;
        const std::uint64_t* secondData = nullptr;
        {
            auto first = Scratch::acquire(owner);
            first.ct2().resize(1);
            resizeFill<std::uint64_t>(first.ct2()[0].mCoeffs, 32, 17);
            firstData = first.ct2()[0].mCoeffs.data();

            // A nested borrow also covers overlapping state-copy operations:
            // neither operation may overwrite the other's live coefficients.
            auto second = Scratch::acquire(owner);
            second.ct2().resize(1);
            resizeFill<std::uint64_t>(second.ct2()[0].mCoeffs, 32, 29);
            secondData = second.ct2()[0].mCoeffs.data();
            auto moved = std::move(first);
            LOGVOLE_REQUIRE_TRUE(firstData != secondData);
            LOGVOLE_REQUIRE_EQ(moved.ct2()[0].mCoeffs[0], 17u);
            LOGVOLE_REQUIRE_EQ(moved.ct2()[0].mCoeffs[31], 17u);
        }
        struct Cancelled {};
        try
        {
            auto lease = Scratch::acquire(owner);
            throw Cancelled{};
        }
        catch (const Cancelled&) {}
        {
            // Return and exception unwinding retain reusable capacity. A lease
            // keeps its pool alive even after the caller releases its owner.
            auto lease = Scratch::acquire(owner);
            LOGVOLE_REQUIRE_EQ(lease.ct2().size(), 1u);
            const auto data = lease.ct2()[0].mCoeffs.data();
            LOGVOLE_REQUIRE_TRUE(data == firstData || data == secondData);
            owner.reset();
            LOGVOLE_REQUIRE_FALSE(lifetime.expired());
        }
    }
    LOGVOLE_REQUIRE_TRUE(lifetime.expired());

    auto params = make_params();
    LOGVOLE_REQUIRE_TRUE(validateShrinkExpandParams(params));

    params.mPlaintextModulusBits = 0;
    LOGVOLE_REQUIRE_FALSE(validateShrinkExpandParams(params));
}

void LogVole_ShrinkExpandCore_OfflineStateShapes(const oc::CLP&)
{
    tests_libOTe::logvole_test::SetupResources setupResources;
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, ctx));

    ShrinkExpandSenderOfflineInput senderInput{};
    senderInput.mParams = params;
    senderInput.mS = sample_batch(ctx, params.mMu, 0x6600u);
    senderInput.mFixedSk1 = sample_batch(ctx, params.mTau, 0x7700u);

    ShrinkExpandSenderState senderState{};
    oc::PRNG prng(oc::block(0x7701u, 0));
    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(prepareShrinkExpandSenderOffline(setupResources.executor, setupResources.results, senderInput, prng, senderState)));

    LOGVOLE_EXPECT_EQ(senderState.mS.size(), params.mMu);
    LOGVOLE_EXPECT_EQ(senderState.mR.size(), params.mMu);
    LOGVOLE_EXPECT_EQ(senderState.mSk1.size(), params.mTau);
    LOGVOLE_EXPECT_EQ(senderState.mCt1.mRows, params.mMu);
    LOGVOLE_EXPECT_EQ(senderState.mCt1.mCols, params.mTau);
    LOGVOLE_EXPECT_EQ(senderState.mLacct.mWidthPadded, 4u);

    ShrinkExpandReceiverOfflineInput receiverInput{};
    receiverInput.mParams = params;

    ShrinkExpandReceiverState receiverState{};
    LOGVOLE_REQUIRE_TRUE(finalize_receiver_from_sender_wire(receiverInput, senderState, receiverState));
    LOGVOLE_REQUIRE_TRUE(senderState.mCpuScratch && receiverState.mCpuScratch);
    LOGVOLE_REQUIRE_TRUE(senderState.mCpuScratch != receiverState.mCpuScratch);
    LOGVOLE_EXPECT_EQ(receiverState.mCt1.mRows, params.mMu);
    LOGVOLE_EXPECT_EQ(receiverState.mLacct.mCt.mRows, senderState.mLacct.mCt.mRows);
}

void LogVole_ShrinkExpandCore_DeterministicRelationExact(const oc::CLP&)
{
    LOGVOLE_REQUIRE_TRUE(run_relation(false));
}

void LogVole_ShrinkExpandCore_TruncDeterministicRelationBounded(const oc::CLP&)
{
    LOGVOLE_REQUIRE_TRUE(run_relation(true));
}

void LogVole_ShrinkExpandCore_OfflineMetadataMismatchRejected(const oc::CLP&)
{
    tests_libOTe::logvole_test::SetupResources setupResources;
    auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, ctx));

    ShrinkExpandSenderOfflineInput senderInput{};
    senderInput.mParams = params;
    senderInput.mS = sample_batch(ctx, params.mMu, 0x8800u);
    senderInput.mFixedSk1 = sample_batch(ctx, params.mTau, 0x9900u);

    ShrinkExpandSenderState senderState{};
    oc::PRNG prng(oc::block(0x9901u, 0));
    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(prepareShrinkExpandSenderOffline(setupResources.executor, setupResources.results, senderInput, prng, senderState)));

    ShrinkExpandReceiverOfflineInput receiverInput{};
    receiverInput.mParams = params;
    receiverInput.mParams.mTau += 1;

    ShrinkExpandReceiverState receiverState{};
    LOGVOLE_REQUIRE_FALSE(finalize_receiver_from_sender_wire(receiverInput, senderState, receiverState));
}

void LogVole_ShrinkExpandCore_DenoiseCombExactness(const oc::CLP&)
{
    constexpr std::uint64_t seedX = 0x8888;
    constexpr std::uint64_t seedNoise = 0x9999;

    const auto params = make_full_noise_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, ctx));

    const std::size_t n = params.mRing.mPolyModulusDegree;
    const std::size_t rho = params.mRing.mCoeffModulusBits.size();
    const std::size_t wPrime = 2;

    const auto xBatch = sample_batch(ctx, static_cast<std::uint32_t>(wPrime), seedX);

    std::vector<RnsPoly> tbaPrime;
    tbaPrime.reserve(wPrime * rho);

    const auto hostContext = getRingHostContext(ctx);
    LOGVOLE_REQUIRE_TRUE(hostContext != nullptr);
    auto keyContextData = hostContext->key_context_data();
    seal::util::RNSBase fullBase(keyContextData->parms().coeff_modulus(), seal::MemoryManager::GetPool());
    auto pool = seal::MemoryManager::GetPool();

    auto pJMpi = seal::util::allocate_uint(rho, pool);
    auto pJHalfMpi = seal::util::allocate_uint(rho, pool);
    auto modJMpi = seal::util::allocate_uint(rho, pool);
    auto remainderMpi = seal::util::allocate_uint(rho, pool);
    auto valMpi = seal::util::allocate_uint(rho, pool);
    auto noiseMpi = seal::util::allocate_uint(rho, pool);

    oc::PRNG prng(oc::block(seedNoise, 0));

    for (std::size_t i = 0; i < wPrime; ++i)
    {
        for (std::size_t j = 0; j < rho; ++j)
        {
            RnsPoly polyJ{};
            resizeZero(polyJ.mCoeffs, n * rho);

            const auto modulusJ = fullBase.base()[j];
            seal::util::set_uint(modulusJ.value(), rho, modJMpi.get());
            seal::util::divide_uint(fullBase.base_prod(), modJMpi.get(), rho, pJMpi.get(), remainderMpi.get(), pool);
            seal::util::right_shift_uint(pJMpi.get(), 1, rho, pJHalfMpi.get());

            for (std::size_t k = 0; k < n; ++k)
            {
                const std::uint64_t xKJ = xBatch[i].mCoeffs[j * n + k];
                seal::util::set_uint(xKJ, rho, valMpi.get());
                seal::util::multiply_uint(valMpi.get(), pJMpi.get(), rho, valMpi.get());

                const std::uint64_t noiseVal = (prng.get<std::uint64_t>() % 1000) + 1;
                const bool negative = (prng.get<std::uint64_t>() % 2) == 1;
                seal::util::set_uint(noiseVal, rho, noiseMpi.get());
                if (negative)
                {
                    seal::util::sub_uint(valMpi.get(), noiseMpi.get(), rho, valMpi.get());
                }
                else
                {
                    seal::util::add_uint(valMpi.get(), noiseMpi.get(), rho, valMpi.get());
                }

                seal::util::divide_uint(valMpi.get(), fullBase.base_prod(), rho, pJHalfMpi.get(), remainderMpi.get(), pool);
                for (std::size_t modIdx = 0; modIdx < rho; ++modIdx)
                {
                    polyJ.mCoeffs[modIdx * n + k] =
                        seal::util::modulo_uint(remainderMpi.get(), rho, fullBase.base()[modIdx]);
                }
            }
            tbaPrime.push_back(std::move(polyJ));
        }
    }

    std::vector<RnsPoly> outBatch;
    macoro::thread_pool executor;
    auto work = executor.make_work();
    executor.create_threads(1);
    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(shrinkExpandDenoiseComb(executor, 1, ctx, tbaPrime, outBatch)));
    expect_batch_equal(outBatch, xBatch);
    auto onPool = [](macoro::thread_pool& pool, macoro::task<bool> operation) -> macoro::task<bool> {
        co_await pool.schedule();
        co_return co_await std::move(operation);
    };
    for (const auto allowance : {std::size_t{1}, std::size_t{3}})
    {
        // Exact expected values, serial and parallel, with the controller on
        // the only executor thread. The same public API also supports aliasing.
        auto alias = tbaPrime;
        auto operation = shrinkExpandDenoiseComb(executor, allowance, ctx, alias, alias);
        LOGVOLE_REQUIRE_EQ(alias.size(), tbaPrime.size()); // Still lazy.
        LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(onPool(executor, std::move(operation))));
        expect_batch_equal(alias, xBatch);
    }
    LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(shrinkExpandDenoiseComb(executor, 0, ctx, tbaPrime, outBatch)));
    expect_batch_equal(outBatch, xBatch);
    auto malformed = tbaPrime;
    malformed[0].mCoeffs.resize(malformed[0].mCoeffs.size() - 1);
    LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(shrinkExpandDenoiseComb(executor, 3, ctx, malformed, outBatch)));
    expect_batch_equal(outBatch, xBatch);

}

void LogVole_ShrinkExpandCore_FullNoiseTolerance(const oc::CLP&)
{
    tests_libOTe::logvole_test::SetupResources setupResources;
    auto params = make_full_noise_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, ctx));

    ShrinkExpandSenderOfflineInput senderInput{};
    senderInput.mParams = params;
    senderInput.mS = sample_batch(ctx, params.mMu, 0x5001u);

    ShrinkExpandSenderState senderState{};
    oc::PRNG offlinePrng(oc::block(0x5002u, 0));
    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(prepareShrinkExpandSenderOffline(setupResources.executor, setupResources.results, senderInput, offlinePrng, senderState)));

    ShrinkExpandReceiverOfflineInput receiverInput{};
    receiverInput.mParams = params;
    ShrinkExpandReceiverState receiverState{};
    LOGVOLE_REQUIRE_TRUE(finalize_receiver_from_sender_wire(receiverInput, senderState, receiverState));

    auto x = sample_batch(ctx, params.mMu, 0x6001u);
    ShrinkExpandShrinkOutput shrink{};
    LOGVOLE_REQUIRE_TRUE(shrinkExpandShrink(receiverState, x, shrink));

    const auto tbkPrime = sample_scalar(ctx, 0x7001u);
    RnsPoly skX{};
    LOGVOLE_REQUIRE_TRUE(deriveSkx(
        ctx,
        senderState.mSk1,
        shrink.mDigest,
        tbkPrime,
        params.mGadgetLogBase,
        params.mTau,
        skX));

    ShrinkExpandExpandSenderInput senderExpandInput{};
    resizeFill<std::uint8_t>(senderExpandInput.mSeed, 16, static_cast<std::uint8_t>(0xA1u));
    senderExpandInput.mDigest = shrink.mDigest;
    senderExpandInput.mNonce = 0;
    senderExpandInput.mTbkPrime = tbkPrime;

    const auto tasks = std::max(1u, senderState.mParams.mNumWorkerThreads);
    tests_libOTe::logvole_test::SenderResources senderResources(params.mRing, false, tasks);
    tests_libOTe::logvole_test::ReceiverBuffers receiverBuffers(params, false, tasks);
    ShrinkExpandSenderExpandOutput senderExpand{};
    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(shrinkExpandExpandSender(senderResources.executor,
        senderResources.buffers, senderState, senderExpandInput, senderExpand)));

    ShrinkExpandExpandReceiverInput receiverExpandInput{};
    receiverExpandInput.mSid = senderExpandInput.mSid;
    receiverExpandInput.mSeed = senderExpandInput.mSeed;
    receiverExpandInput.mNonce = senderExpandInput.mNonce;
    receiverExpandInput.mX = x;
    receiverExpandInput.mDigest = shrink.mDigest;
    receiverExpandInput.mSkX = skX;
    receiverExpandInput.mTree = shrink.mTree;

    ShrinkExpandReceiverExpandOutput receiverExpand{};
    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(shrinkExpandExpandReceiver(senderResources.executor,
        receiverBuffers.lhe, receiverBuffers.lenc, receiverState, receiverExpandInput, receiverExpand)));

    std::vector<RnsPoly> tbmMinusTbk;
    LOGVOLE_REQUIRE_TRUE(subtract_batches(ctx, receiverExpand.mTbm, senderExpand.mTbk, tbmMinusTbk));

    std::vector<RnsPoly> expected;
    LOGVOLE_REQUIRE_TRUE(compute_expected_s_mul_x(ctx, senderInput.mS, x, expected));

    std::vector<RnsPoly> residual;
    LOGVOLE_REQUIRE_TRUE(subtract_batches(ctx, tbmMinusTbk, expected, residual));

    const auto maxLog2 = max_centered_log2(ctx, residual);
    const double maxNoiseAllowed = static_cast<double>(log_q_bits(params) - params.mRing.mCoeffModulusBits.back());
    LOGVOLE_EXPECT_GT(maxLog2, 0);
    LOGVOLE_EXPECT_LT(maxLog2, maxNoiseAllowed);
}

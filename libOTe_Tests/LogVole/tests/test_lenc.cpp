#include "libOTe_Tests/LogVole_SenderResources.h"
#include "cryptoTools/Common/CLP.h"
#include "libOTe_Tests/LogVole_TestOptions.h"
#include "libOTe/Vole/LogVole/LogVoleLenc.h"
#include "libOTe/Vole/LogVole/LogVoleLhe.h"
#include "libOTe/Vole/LogVole/LogVoleCore.h"
#include "libOTe/config.h"
#if defined(ENABLE_LOGVOLE_CUDA)
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuProtocol.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuGaussian.h"
#endif

#include "libOTe_Tests/LogVole_TestUtil.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cmath>
#include <limits>
#include <span>
#include <string>
#include <vector>

using namespace osuCrypto::LogVole;

namespace
{


    struct LencParams
    {
        RingParams mRing{};
        std::uint32_t mMu = 3;
        std::uint32_t mTau = 3;
        std::uint32_t mTauHi = 2;
        std::uint32_t mGadgetLogBase = 20;
        std::uint32_t mPlaintextModulusBits = 20;
    };

    LencParams make_params()
    {
        LencParams p{};
        p.mRing.mPolyModulusDegree = 1024;
        assignValues<int>(p.mRing.mCoeffModulusBits, { 30, 30 });
        return p;
    }

    std::vector<RnsPoly> sample_batch(const RingNttContext& ctx, std::uint32_t count, std::uint64_t seed)
    {
        std::vector<RnsPoly> out;
        out.reserve(count);
        for (std::uint32_t i = 0; i < count; ++i)
        {
            out.push_back(deriveUniformPolyFromNonce(ctx, seed, 0x1E2C0001u, i));
        }
        return out;
    }

    void expect_poly_equal(const RnsPoly& a, const RnsPoly& b)
    {
        LOGVOLE_REQUIRE_EQ(a.mCoeffs.size(), b.mCoeffs.size());
        for (std::size_t i = 0; i < a.mCoeffs.size(); ++i)
        {
            LOGVOLE_EXPECT_EQ(a.mCoeffs[i], b.mCoeffs[i]) << " coeff idx " << i;
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

    void expect_tensor_equal(const RingTensor& a, const RingTensor& b)
    {
        LOGVOLE_EXPECT_EQ(a.mRows, b.mRows);
        LOGVOLE_EXPECT_EQ(a.mCols, b.mCols);
        expect_batch_equal(a.mPolys, b.mPolys);
    }

    void expect_encoding_equal(const LencEncodeOutput& expected, const LencEncodeOutput& actual,
                               bool emitRCoeffDomain = true)
    {
        auto compareBatch = [](const std::vector<RnsPoly>& left, const std::vector<RnsPoly>& right) {
            LOGVOLE_REQUIRE_EQ(left.size(), right.size());
            for (std::size_t i = 0; i < left.size(); ++i)
                LOGVOLE_REQUIRE_TRUE(rangesEqual(left[i].mCoeffs, right[i].mCoeffs)) << " polynomial " << i;
        };
        LOGVOLE_EXPECT_EQ(expected.mLacct.mWidthPadded, actual.mLacct.mWidthPadded);
        LOGVOLE_EXPECT_EQ(expected.mLacct.mLevels, actual.mLacct.mLevels);
        LOGVOLE_EXPECT_EQ(expected.mLacct.mCt.mRows, actual.mLacct.mCt.mRows);
        LOGVOLE_EXPECT_EQ(expected.mLacct.mCt.mCols, actual.mLacct.mCt.mCols);
        if (emitRCoeffDomain) compareBatch(expected.mR, actual.mR);
        else LOGVOLE_REQUIRE_TRUE(actual.mR.empty());
        compareBatch(expected.mRNtt, actual.mRNtt);
        compareBatch(expected.mLacct.mCt.mPolys, actual.mLacct.mCt.mPolys);
    }

    void expect_deferred_tensor_equal(const std::shared_ptr<const LazyRingTensorHostState>& owner,
                                      const RingTensor& shape, const RingTensor& expected)
    {
        LOGVOLE_REQUIRE_TRUE(owner);
        LOGVOLE_REQUIRE_TRUE(shape.mPolys.empty());
        LOGVOLE_REQUIRE_EQ(shape.mRows, expected.mRows);
        LOGVOLE_REQUIRE_EQ(shape.mCols, expected.mCols);
        std::vector<std::uint8_t> expectedBytes;
        expectedBytes.reserve(expected.mPolys.size() * expected.mPolys.front().mCoeffs.size() * sizeof(std::uint64_t));
        for (const auto& poly : expected.mPolys)
            for (auto word : poly.mCoeffs)
                for (unsigned byte = 0; byte < sizeof(word); ++byte)
                    expectedBytes.push_back(static_cast<std::uint8_t>(word >> (8u * byte)));
        std::vector<std::uint8_t> actualBytes(expectedBytes.size(), 0xA5u);
        LOGVOLE_REQUIRE_FALSE(owner->copyCoefficientsTo(std::span(actualBytes).first(actualBytes.size() - 1)));
        LOGVOLE_REQUIRE_TRUE(std::all_of(actualBytes.begin(), actualBytes.end(),
            [](std::uint8_t byte) { return byte == 0xA5u; }));
        // Export before requesting get(): transport must not depend on a host
        // tensor having already been materialized.
        LOGVOLE_REQUIRE_TRUE(owner->copyCoefficientsTo(std::span(actualBytes)));
        LOGVOLE_REQUIRE_TRUE(rangesEqual(expectedBytes, actualBytes));
        const auto& host = owner->get();
        expect_tensor_equal(expected, host);
        LOGVOLE_REQUIRE_TRUE(&owner->get() == &host);
        auto mutableCopy = host;
        mutableCopy.mPolys.front().mCoeffs.front() ^= 1;
        LOGVOLE_REQUIRE_EQ(owner->get().mPolys.front().mCoeffs.front(),
            expected.mPolys.front().mCoeffs.front());
        LOGVOLE_REQUIRE_TRUE(owner->copyCoefficientsTo(std::span(actualBytes)));
        LOGVOLE_REQUIRE_TRUE(rangesEqual(expectedBytes, actualBytes));
    }

    void check_compact_noise_parity(const RingNttContext& ctx)
    {
        LOGVOLE_REQUIRE_TRUE(ringModulusCount(ctx) > 0);
        const std::uint64_t q0 = ringModulusValue(ctx, 0);
        LOGVOLE_REQUIRE_TRUE(q0 > 1);
        seal::prng_seed_type seed{};
        oc::PRNG seedPrng(oc::block(0x434F4D50414354ull, 1), 3);
        seedPrng.get(seed.data(), seed.size());
        const auto n = ctx.mParams.mPolyModulusDegree;
        for (double sigma : { 0.0, 3.2 })
        {
            LOGVOLE_REQUIRE_TRUE(canSamplePolyErrorCompact(ctx, sigma, 6 * sigma));
            std::vector<std::uint64_t> compact(n);
            LOGVOLE_REQUIRE_TRUE(samplePolyErrorCompactFromSeed(compact, sigma, 6 * sigma, seed, ctx));
            RnsPoly expected;
            resizeZero(expected.mCoeffs, ringPolyCoeffCount(ctx.mParams));
            LOGVOLE_REQUIRE_TRUE(addPolyErrorFromSeed(expected, sigma, 6 * sigma, seed, ctx));
            RnsPoly actual;
            LOGVOLE_REQUIRE_TRUE(expandPolyErrorCompact(compact, actual, ctx));
            LOGVOLE_REQUIRE_TRUE(rangesEqual(actual.mCoeffs, expected.mCoeffs));
            if (sigma > 0)
            {
                const std::uint64_t halfQ = q0 >> 1u;
                bool positive = false, negative = false;
                for (std::uint64_t value : compact)
                {
                    positive |= value > 0 && value <= halfQ;
                    negative |= value > halfQ;
                }
                LOGVOLE_REQUIRE_TRUE(positive && negative);
            }
            // Rejected shapes/coefficients must not partially overwrite output.
            const auto preserved = actual;
            compact[0] = q0;
            LOGVOLE_EXPECT_FALSE(expandPolyErrorCompact(compact, actual, ctx));
            LOGVOLE_REQUIRE_TRUE(rangesEqual(actual.mCoeffs, preserved.mCoeffs));
            LOGVOLE_EXPECT_FALSE(expandPolyErrorCompact(std::span<const std::uint64_t>(compact).first(n - 1), actual, ctx));
            LOGVOLE_REQUIRE_TRUE(rangesEqual(actual.mCoeffs, preserved.mCoeffs));
        }
        const double infinity = std::numeric_limits<double>::infinity();
        const double nan = std::numeric_limits<double>::quiet_NaN();
        const double halfBoundary = std::nextafter(static_cast<double>(q0 >> 1u), infinity);
        for (double sigma : { -1.0, infinity, nan })
            LOGVOLE_EXPECT_FALSE(canSamplePolyErrorCompact(ctx, sigma, 19.2));
        for (double clip : { -1.0, infinity, nan, halfBoundary })
        {
            LOGVOLE_EXPECT_FALSE(canSamplePolyErrorCompact(ctx, 3.2, clip));
            std::vector<std::uint64_t> untouched(n, 0x76543210u);
            const auto before = untouched;
            LOGVOLE_EXPECT_FALSE(samplePolyErrorCompactFromSeed(untouched, 3.2, clip, seed, ctx));
            LOGVOLE_REQUIRE_TRUE(rangesEqual(untouched, before));
        }
        std::vector<std::uint64_t> shortOutput(n - 1, 0x12345678u);
        const auto before = shortOutput;
        LOGVOLE_EXPECT_FALSE(samplePolyErrorCompactFromSeed(shortOutput, 3.2, 19.2, seed, ctx));
        LOGVOLE_REQUIRE_TRUE(rangesEqual(shortOutput, before));
    }

    void check_trunc_setup_parity(const LencParams& params, bool useGpu, std::uint32_t width = 0)
    {
    tests_libOTe::logvole_test::SetupResources setupResources;
        osuCrypto::LogVoleGpuSetupOptions setupOptions;
        osuCrypto::LogVoleExecutionOptions advanced;
        advanced.mUseGpu = useGpu;
        advanced.mAdvanced.mStreams.mIndexScratchKiB = 256;
        advanced.mAdvanced.mStreams.mReuseDownloadStaging = false;
        advanced.mAdvanced.mProtocol.mGaussianResident = false;
#if defined(ENABLE_LOGVOLE_CUDA)
        const bool haveGpu = gpu::enabled(advanced);
        gpu::GaussianHostCompatibility gaussianCompatibility;
        const bool haveGaussian = haveGpu && gaussianCompatibility.compatible();
#else
        const bool haveGpu = false;
        const bool haveGaussian = false;
#endif
        RingNttContext ctx{};
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, ctx,
            std::make_shared<RingContextFactory>(advanced)));
        RingNttContext cpuCtx;
        auto cpuOptions = advanced;
        cpuOptions.mUseGpu = false;
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, cpuCtx,
            std::make_shared<RingContextFactory>(cpuOptions)));
        check_compact_noise_parity(ctx);
        auto s = sample_batch(ctx, params.mMu, 0x1E2CB47Cu);
        const auto publicB = buildLencPublicBNtt(ctx, params.mTauHi + 1);
        const auto sharedB = sharedLencPublicBNtt(ctx, params.mTauHi + 1);
        LOGVOLE_REQUIRE_TRUE(sharedB && sharedB == sharedLencPublicBNtt(ctx, params.mTauHi + 1));
        auto mutableB = buildLencPublicBNtt(ctx, params.mTauHi + 1);
        mutableB.front().mCoeffs.front() ^= 1;
        LOGVOLE_REQUIRE_TRUE(rangesEqual(sharedB->front().mCoeffs, publicB.front().mCoeffs));
        for (bool gadgetLeaves : { false, true })
        for (double sigma : { 0.0, 3.2 })
        {
            // Three AES blocks force the 64-byte SEAL seeds across refills.
            // Even sigma=0 consumes seeds for rLayers, but no ciphertext noise.
            oc::PRNG referencePrng(oc::block(0x1E2C5EEDu, 0), 3);
            LencEncodeOutput expected{};
            {
                tests_libOTe::logvole_test::ScopedOptionValue option(setupOptions.mParallelLenc, (false) ? osuCrypto::LogVoleChoice::Enabled : osuCrypto::LogVoleChoice::Disabled);
                tests_libOTe::logvole_test::ScopedOptionValue deviceOption(setupOptions.mLencDevice, false);
                // Keep every transform in the reference on the CPU.
                const auto& ctx = cpuCtx;
                LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(lencEncTrunc(setupResources.executor, setupResources.results, ctx, s, params.mTauHi,
                    params.mGadgetLogBase, params.mPlaintextModulusBits, referencePrng,
                    expected, sigma, 6 * sigma, width, true, gadgetLeaves, &publicB, 1, false, false, nullptr, nullptr, setupOptions)));
            }
            const auto nextReference = referencePrng.get<oc::block>();
            if (haveGpu)
            {
                tests_libOTe::logvole_test::ScopedOptionValue resident(ctx.mExecutionOptions.mAdvanced.mProtocol.mGaussianResident, true);
                // Unknown host arithmetic must exercise exact host replay; strict rejection is checked separately.
                tests_libOTe::logvole_test::ScopedOptionValue residentStrict(ctx.mExecutionOptions.mAdvanced.mProtocol.mGaussianResidentStrict, (haveGaussian));
                tests_libOTe::logvole_test::ScopedOptionValue residentDecline(ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mGaussianResident, false);
                tests_libOTe::logvole_test::ScopedOptionValue transform(ctx.mExecutionOptions.mAdvanced.mProtocol.mGaussianTransform, true);
                tests_libOTe::logvole_test::ScopedOptionValue transformStrict(ctx.mExecutionOptions.mAdvanced.mProtocol.mGaussianTransformStrict, (haveGaussian));
                tests_libOTe::logvole_test::ScopedOptionValue transformDecline(ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mGaussianTransform, false);
                tests_libOTe::logvole_test::ScopedOptionValue device(setupOptions.mLencDevice, true);
                tests_libOTe::logvole_test::ScopedOptionValue deviceStrict(setupOptions.mLencDeviceStrict, true);
                tests_libOTe::logvole_test::ScopedOptionValue deviceDecline(ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mLencDevice, false);
                tests_libOTe::logvole_test::ScopedOptionValue compact(setupOptions.mCompactNoise, true);
                tests_libOTe::logvole_test::ScopedOptionValue compactStrict(setupOptions.mCompactNoiseStrict, true);
                tests_libOTe::logvole_test::ScopedOptionValue padding(setupOptions.mLencDevicePadding, true);
                tests_libOTe::logvole_test::ScopedOptionValue randomizer(setupOptions.mLencRandomizerOutput, true);
                tests_libOTe::logvole_test::ScopedOptionValue randomizerStrict(setupOptions.mLencRandomizerOutputStrict, true);
                tests_libOTe::logvole_test::ScopedOptionValue randomizerDecline(ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mLencRandomizerOutput, false);
                auto invoke = [&](oc::PRNG& prng, LencEncodeOutput& out, bool emitR) {
                    return macoro::sync_wait(lencEncTrunc(setupResources.executor, setupResources.results, ctx, s, params.mTauHi, params.mGadgetLogBase,
                        params.mPlaintextModulusBits, prng, out, sigma, 6 * sigma,
                        width, emitR, gadgetLeaves, &publicB, 4, false, false, nullptr, nullptr, setupOptions));
                };
                // Focus on resident R/ciphertext sampling and finite-prefix
                // repair without multiplying the complete option matrix below.
                for (const char* blocks : {"0", "1"})
                for (bool emitR : {false, true})
                {
                    tests_libOTe::logvole_test::ScopedOptionValue prefix(ctx.mExecutionOptions.mAdvanced.mProtocol.mGaussianTransformPrefixBlocks, static_cast<std::uint64_t>(std::strtoull(blocks, nullptr, 10)));
                    oc::PRNG actualPrng(oc::block(0x1E2C5EEDu, 0), 3);
                    LencEncodeOutput actual;
                    LOGVOLE_REQUIRE_TRUE(invoke(actualPrng, actual, emitR));
                    expect_encoding_equal(expected, actual, emitR);
                    LOGVOLE_EXPECT_EQ(actualPrng.get<oc::block>(), nextReference);
                }
                {
                    oc::PRNG retainedPrng(oc::block(0x1E2C5EEDu, 0), 3);
                    LencEncodeOutput retained;
                    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(lencEncTrunc(setupResources.executor, setupResources.results, ctx, s, params.mTauHi,
                        params.mGadgetLogBase, params.mPlaintextModulusBits, retainedPrng,
                        retained, sigma, 6 * sigma, width, true, gadgetLeaves, &publicB, 4, true, true, nullptr, nullptr, setupOptions)));
                    LOGVOLE_REQUIRE_TRUE(retained.mLazyRandomizers != nullptr);
                    LOGVOLE_REQUIRE_EQ(retained.mLazyRandomizers->count(), s.size());
                    LOGVOLE_REQUIRE_TRUE(retained.mR.empty() && retained.mRNtt.empty());
                    LOGVOLE_EXPECT_EQ(retainedPrng.get<oc::block>(), nextReference);
                    expect_deferred_tensor_equal(retained.mLazyCt, retained.mLacct.mCt, expected.mLacct.mCt);

                    const auto owner = retained.mLazyRandomizers;
                    auto sk = sample_batch(ctx, params.mTauHi, 0xC710u);
                    const auto publicA = sharedLhePublicANtt(ctx, params.mMu);
                    RingTensor referenceLhe, referenceRoot;
                    std::vector<RnsPoly> rootB(publicB.begin(), publicB.begin() + params.mTauHi);
                    std::vector<RnsPoly> starB{publicB.back()};
                    oc::PRNG lheReferencePrng(oc::block(0xC7, 1), 3), rootReferencePrng(oc::block(0xC7, 2), 3);
                    {
                        const auto& ctx = cpuCtx;
                        LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(lheEnc1Trunc(setupResources.executor, setupResources.results, ctx, expected.mRNtt, sk,
                            params.mGadgetLogBase, referenceLhe, sigma, 6 * sigma, &lheReferencePrng,
                            true, publicA.get(), 1, nullptr,  {}, nullptr, nullptr, nullptr, nullptr, 0, false, setupOptions)));
                        LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(buildRootTopCt(setupResources.executor, setupResources.results, ctx, expected.mR, expected.mRNtt,
                            rootB, starB, params.mGadgetLogBase, 1, rootReferencePrng, sigma,
                            6 * sigma, referenceRoot, 1,  {}, nullptr, nullptr, nullptr, nullptr, nullptr, setupOptions)));
                    }
                    const auto nextLhe = lheReferencePrng.get<oc::block>();
                    const auto nextRoot = rootReferencePrng.get<oc::block>();
                    // Exercise resident consumers before requesting either host
                    // snapshot. Decline replays existing seeds, never resamples.
                    for (const char* decline : {"0", "1"})
                    {
                        tests_libOTe::logvole_test::ScopedOptionValue lheDevice(setupOptions.mLheDevice, true);
                        tests_libOTe::logvole_test::ScopedOptionValue lheDecline(ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mLheDevice, (decline)[0] == '1');
                        tests_libOTe::logvole_test::ScopedOptionValue lheStrict(setupOptions.mLheDeviceStrict, (decline[0] == '0' ? "1" : "0")[0] != '0');
                        tests_libOTe::logvole_test::ScopedOptionValue rootDevice(setupOptions.mRootDevice, true);
                        tests_libOTe::logvole_test::ScopedOptionValue rootDecline(ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mRootDevice, (decline)[0] == '1');
                        tests_libOTe::logvole_test::ScopedOptionValue rootStrict(setupOptions.mRootDeviceStrict, (decline[0] == '0' ? "1" : "0")[0] != '0');
                        tests_libOTe::logvole_test::ScopedOptionValue allowFallback(setupOptions.mCompactNoiseStrict, false);
                        tests_libOTe::logvole_test::ScopedOptionValue rootCompact(setupOptions.mRootCompactNoise, true);
                        tests_libOTe::logvole_test::ScopedOptionValue rootCompactStrict(setupOptions.mRootCompactNoiseStrict, false);
                        RingTensor actualLhe, actualRoot;
                        oc::PRNG lhePrng(oc::block(0xC7, 1), 3), rootPrng(oc::block(0xC7, 2), 3);
                        LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(lheEnc1Trunc(setupResources.executor, setupResources.results, ctx, {}, sk, params.mGadgetLogBase,
                            actualLhe, sigma, 6 * sigma, &lhePrng, true, publicA.get(), 4, nullptr, owner, nullptr, nullptr, nullptr, nullptr, 0, false, setupOptions)));
                        LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(buildRootTopCt(setupResources.executor, setupResources.results, ctx, expected.mR, {}, rootB, starB,
                            params.mGadgetLogBase, 1, rootPrng, sigma, 6 * sigma, actualRoot, 4, owner, nullptr, nullptr, nullptr, nullptr, nullptr, setupOptions)));
                        expect_tensor_equal(referenceLhe, actualLhe);
                        expect_tensor_equal(referenceRoot, actualRoot);
                        LOGVOLE_EXPECT_EQ(lhePrng.get<oc::block>(), nextLhe);
                        LOGVOLE_EXPECT_EQ(rootPrng.get<oc::block>(), nextRoot);
                    }
                    expect_batch_equal(expected.mRNtt, owner->hostNtt());
                    expect_batch_equal(expected.mR, owner->hostCoefficients());
                    LOGVOLE_REQUIRE_TRUE(&owner->hostNtt() == &owner->hostNtt());
                    ShrinkExpandSenderState state;
                    state.mParams.mRing = params.mRing;
                    state.mLazyRandomizers = owner;
                    auto independent = state;
                    materializeShrinkExpandHostState(independent);
                    LOGVOLE_REQUIRE_FALSE(independent.mLazyRandomizers);
                    expect_batch_equal(expected.mR, independent.mR);
                    independent.mR.front().mCoeffs.front() ^= 1;
                    expect_batch_equal(expected.mR, state.hostR());

                    RingTensor rejected = referenceLhe;
                    const auto* rejectedData = rejected.mPolys.data();
                    oc::PRNG invalidPrng(oc::block(0xC7, 1), 3), untouchedPrng(oc::block(0xC7, 1), 3);
                    LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(lheEnc1Trunc(setupResources.executor, setupResources.results, ctx, expected.mRNtt, sk, params.mGadgetLogBase,
                        rejected, sigma, 6 * sigma, &invalidPrng, true, publicA.get(), 4, nullptr, owner, nullptr, nullptr, nullptr, nullptr, 0, false, setupOptions)));
                    LOGVOLE_REQUIRE_TRUE(rejected.mPolys.data() == rejectedData);
                    LOGVOLE_EXPECT_EQ(invalidPrng.get<oc::block>(), untouchedPrng.get<oc::block>());
                    {
                        auto eagerOptions = ctx.mExecutionOptions;
                        eagerOptions.mAdvanced.mProtocol.mLencRandomizerResidency = false;
                        RingNttContext eagerCtx;
                        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, eagerCtx,
                            std::make_shared<RingContextFactory>(eagerOptions)));
                        oc::PRNG eagerPrng(oc::block(0x1E2C5EEDu, 0), 3);
                        LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(lencEncTrunc(setupResources.executor, setupResources.results, eagerCtx, s, params.mTauHi,
                            params.mGadgetLogBase, params.mPlaintextModulusBits, eagerPrng,
                            retained, sigma, 6 * sigma, width, true, gadgetLeaves, &publicB, 4, false, true, nullptr, nullptr, setupOptions)));
                        LOGVOLE_REQUIRE_FALSE(retained.mLazyRandomizers);
                        expect_encoding_equal(expected, retained);
                        LOGVOLE_EXPECT_EQ(eagerPrng.get<oc::block>(), nextReference);
                    }
                }
                {
                    oc::PRNG deferredPrng(oc::block(0x1E2C5EEDu, 0), 3);
                    LencEncodeOutput deferred;
                    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(lencEncTrunc(setupResources.executor, setupResources.results, ctx, s, params.mTauHi,
                        params.mGadgetLogBase, params.mPlaintextModulusBits, deferredPrng,
                        deferred, sigma, 6 * sigma, width, true, gadgetLeaves, &publicB, 4, true, false, nullptr, nullptr, setupOptions)));
                    expect_deferred_tensor_equal(deferred.mLazyCt, deferred.mLacct.mCt, expected.mLacct.mCt);
                    LOGVOLE_EXPECT_EQ(deferredPrng.get<oc::block>(), nextReference);
                    auto materialized = deferred;
                    materialized.mLacct.mCt = deferred.mLazyCt->get();
                    expect_encoding_equal(expected, materialized);

                    if (!gadgetLeaves && sigma > 0 && params.mRing.mPolyModulusDegree == 1024 &&
                        width == 0 && params.mTauHi + 1u == params.mTau)
                    {
                        const auto retained = deferred.mLazyCt;
                        LencEncodeOutput rejected = expected;
                        rejected.mLazyCt = retained;
                        const auto* storage = rejected.mLacct.mCt.mPolys.data();
                        oc::PRNG rejectedPrng(oc::block(0x1E2C5EEDu, 0), 3);
                        oc::PRNG untouchedPrng(oc::block(0x1E2C5EEDu, 0), 3);
                        LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(lencEncTrunc(setupResources.executor, setupResources.results, ctx, s, 0,
                            params.mGadgetLogBase, params.mPlaintextModulusBits, rejectedPrng,
                            rejected, sigma, 6 * sigma, width, true, gadgetLeaves, &publicB, 4, true, false, nullptr, nullptr, setupOptions)));
                        LOGVOLE_REQUIRE_TRUE(rejected.mLazyCt == retained);
                        LOGVOLE_REQUIRE_TRUE(rejected.mLacct.mCt.mPolys.data() == storage);
                        expect_encoding_equal(expected, rejected);
                        LOGVOLE_EXPECT_EQ(rejectedPrng.get<oc::block>(), untouchedPrng.get<oc::block>());

                        // Full LENC has no deferred producer. An explicit
                        // request still returns an independent eager result and
                        // removes an owner left in the reused output object.
                        oc::PRNG fullReferencePrng(oc::block(0x1E2C5EEDu, 0), 3);
                        oc::PRNG fullActualPrng(oc::block(0x1E2C5EEDu, 0), 3);
                        LencEncodeOutput fullReference;
                        LOGVOLE_REQUIRE_TRUE(lencEnc(ctx, s, params.mTau, params.mGadgetLogBase,
                            fullReferencePrng, fullReference, sigma, 6 * sigma, width, true, &publicB, 4));
                        LOGVOLE_REQUIRE_TRUE(lencEnc(ctx, s, params.mTau, params.mGadgetLogBase,
                            fullActualPrng, deferred, sigma, 6 * sigma, width, true, &publicB, 4, true));
                        LOGVOLE_REQUIRE_FALSE(deferred.mLazyCt);
                        expect_encoding_equal(fullReference, deferred);
                        LOGVOLE_EXPECT_EQ(fullActualPrng.get<oc::block>(), fullReferencePrng.get<oc::block>());
                        deferred.mLacct.mCt.mPolys.front().mCoeffs.front() ^= 1;
                        expect_tensor_equal(expected.mLacct.mCt, retained->get());
                    }
                }
                if (sigma > 0.0)
                {
                    tests_libOTe::logvole_test::ScopedOptionValue decline(ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mGaussianResident, true);
                    {
                        tests_libOTe::logvole_test::ScopedOptionValue replay(ctx.mExecutionOptions.mAdvanced.mProtocol.mGaussianResidentStrict, false);
                        oc::PRNG replayPrng(oc::block(0x1E2C5EEDu, 0), 3);
                        LencEncodeOutput actual;
                        LOGVOLE_REQUIRE_TRUE(invoke(replayPrng, actual, true));
                        expect_encoding_equal(expected, actual);
                        LOGVOLE_EXPECT_EQ(replayPrng.get<oc::block>(), nextReference);
                    }
                    tests_libOTe::logvole_test::ScopedOptionValue requireResident(ctx.mExecutionOptions.mAdvanced.mProtocol.mGaussianResidentStrict, true);
                    oc::PRNG rejectedPrng(oc::block(0x1E2C5EEDu, 0), 3);
                    oc::PRNG seedPrefix(oc::block(0x1E2C5EEDu, 0), 3);
                    for (std::size_t i = 0; i < static_cast<std::size_t>(expected.mLacct.mLevels) *
                            expected.mLacct.mWidthPadded; ++i)
                    {
                        seal::prng_seed_type seed;
                        seedPrefix.get(seed.data(), seed.size());
                    }
                    LencEncodeOutput rejected = expected;
                    const auto* storage = rejected.mR.data();
                    LOGVOLE_REQUIRE_FALSE(invoke(rejectedPrng, rejected, true));
                    LOGVOLE_REQUIRE_TRUE(rejected.mR.data() == storage);
                    expect_encoding_equal(expected, rejected);
                    LOGVOLE_EXPECT_EQ(rejectedPrng.get<oc::block>(), seedPrefix.get<oc::block>());
                }
            }
            for (std::uint32_t workers : { 1u, 4u })
            for (bool deviceAssembly : { false, true })
            for (bool compactNoise : { false, true })
            for (bool emitRCoeffDomain : { true, false })
            for (bool directDownload : { false, true })
            for (bool deviceRandomizerOutput : { false, true })
            for (bool devicePadding : { false, true })
            {
                if (deviceAssembly && !haveGpu) continue;
                if (directDownload && !deviceAssembly) continue;
                if (compactNoise && !deviceAssembly) continue;
                if (!emitRCoeffDomain && !compactNoise) continue;
                if (deviceRandomizerOutput && !compactNoise) continue;
                if (devicePadding && (!deviceAssembly || directDownload || workers != 4u || deviceRandomizerOutput)) continue;
                tests_libOTe::logvole_test::ScopedOptionValue option(setupOptions.mParallelLenc, (true) ? osuCrypto::LogVoleChoice::Enabled : osuCrypto::LogVoleChoice::Disabled);
                tests_libOTe::logvole_test::ScopedOptionValue deviceOption(setupOptions.mLencDevice, (deviceAssembly ? "1" : "0")[0] != '0');
                // Strict mode makes the device-selected branch fail instead
                // of silently satisfying this equality test with CPU fallback.
                tests_libOTe::logvole_test::ScopedOptionValue strictOption(setupOptions.mLencDeviceStrict, true);
                tests_libOTe::logvole_test::ScopedOptionValue compactOption(setupOptions.mCompactNoise, (compactNoise ? "1" : "0")[0] != '0');
                tests_libOTe::logvole_test::ScopedOptionValue compactStrict(setupOptions.mCompactNoiseStrict, true);
                tests_libOTe::logvole_test::ScopedOptionValue forceOption(ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mLencDevice, false);
                auto advanced = ctx.mExecutionOptions;
                advanced.mAdvanced.mProtocol.mPipelinedDownload = false;
                advanced.mAdvanced.mProtocol.mDirectDownload = directDownload;
                RingNttContext selected;
                LOGVOLE_REQUIRE_TRUE(makeRingNttContext(ctx.mParams, selected,
                    std::make_shared<RingContextFactory>(advanced)));
                tests_libOTe::logvole_test::ScopedOptionValue randomizerOutput(setupOptions.mLencRandomizerOutput, (deviceRandomizerOutput ? "1" : "0")[0] != '0');
                tests_libOTe::logvole_test::ScopedOptionValue randomizerStrict(setupOptions.mLencRandomizerOutputStrict, true);
                tests_libOTe::logvole_test::ScopedOptionValue randomizerDecline(ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mLencRandomizerOutput, false);
                // Generic expansion must not inherit the unrelated root hook.
                tests_libOTe::logvole_test::ScopedOptionValue rootDecline(selected.mExecutionOptions.mAdvanced.mProtocol.mFailures.mRootCompactNoise, true);
                tests_libOTe::logvole_test::ScopedOptionValue paddingOption(setupOptions.mLencDevicePadding, (devicePadding ? "1" : "0")[0] != '0');
#if defined(ENABLE_LOGVOLE_CUDA)
                if (deviceAssembly) LOGVOLE_REQUIRE_TRUE(gpu::enabled(ctx));
#endif
                oc::PRNG actualPrng(oc::block(0x1E2C5EEDu, 0), 3);
                LencEncodeOutput actual{};
                LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(lencEncTrunc(setupResources.executor, setupResources.results, selected, s, params.mTauHi,
                    params.mGadgetLogBase, params.mPlaintextModulusBits, actualPrng,
                    actual, sigma, 6 * sigma, width, emitRCoeffDomain, gadgetLeaves, &publicB, workers, false, false, nullptr, nullptr, setupOptions)));
                expect_encoding_equal(expected, actual, emitRCoeffDomain);
                LOGVOLE_EXPECT_EQ(actualPrng.get<oc::block>(), nextReference);
            }
            if (haveGpu)
            {
                tests_libOTe::logvole_test::ScopedOptionValue option(setupOptions.mParallelLenc, (true) ? osuCrypto::LogVoleChoice::Enabled : osuCrypto::LogVoleChoice::Disabled);
                tests_libOTe::logvole_test::ScopedOptionValue deviceOption(setupOptions.mLencDevice, true);
                tests_libOTe::logvole_test::ScopedOptionValue compactOption(setupOptions.mCompactNoise, true);
                tests_libOTe::logvole_test::ScopedOptionValue forceOption(ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mLencDevice, true);
                tests_libOTe::logvole_test::ScopedOptionValue deviceStrict(setupOptions.mLencDeviceStrict, false);
                tests_libOTe::logvole_test::ScopedOptionValue compactStrict(setupOptions.mCompactNoiseStrict, false);
                tests_libOTe::logvole_test::ScopedOptionValue paddingOption(setupOptions.mLencDevicePadding, true);
                for (bool emitRCoeffDomain : { true, false })
                {
                    oc::PRNG fallbackPrng(oc::block(0x1E2C5EEDu, 0), 3);
                    LencEncodeOutput actual;
                    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(lencEncTrunc(setupResources.executor, setupResources.results, ctx, s, params.mTauHi,
                        params.mGadgetLogBase, params.mPlaintextModulusBits, fallbackPrng,
                        actual, sigma, 6 * sigma, width, emitRCoeffDomain, gadgetLeaves, &publicB, 4, false, false, nullptr, nullptr, setupOptions)));
                    expect_encoding_equal(expected, actual, emitRCoeffDomain);
                    LOGVOLE_EXPECT_EQ(fallbackPrng.get<oc::block>(), nextReference);
                }
                // Prove that forced decline cannot silently satisfy strict GPU
                // parity; the non-strict calls above must replay compact R/noise.
                tests_libOTe::logvole_test::ScopedOptionValue strictOption(setupOptions.mLencDeviceStrict, true);
                oc::PRNG failedPrng(oc::block(0x1E2C5EEDu, 0), 3);
                LencEncodeOutput failed;
                failed.mLacct.mWidthPadded = 0xBADu;
                LOGVOLE_EXPECT_FALSE(macoro::sync_wait(lencEncTrunc(setupResources.executor, setupResources.results, ctx, s, params.mTauHi,
                    params.mGadgetLogBase, params.mPlaintextModulusBits, failedPrng,
                    failed, sigma, 6 * sigma, width, true, gadgetLeaves, &publicB, 4, false, false, nullptr, nullptr, setupOptions)));
                LOGVOLE_EXPECT_EQ(failed.mLacct.mWidthPadded, 0xBADu);
            }
            if (haveGpu)
            {
                tests_libOTe::logvole_test::ScopedOptionValue option(setupOptions.mParallelLenc, (true) ? osuCrypto::LogVoleChoice::Enabled : osuCrypto::LogVoleChoice::Disabled);
                tests_libOTe::logvole_test::ScopedOptionValue deviceOption(setupOptions.mLencDevice, true);
                tests_libOTe::logvole_test::ScopedOptionValue compactOption(setupOptions.mCompactNoise, true);
                tests_libOTe::logvole_test::ScopedOptionValue forceOption(ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mLencDevice, false);
                tests_libOTe::logvole_test::ScopedOptionValue deviceStrict(setupOptions.mLencDeviceStrict, true);
                tests_libOTe::logvole_test::ScopedOptionValue randomizerOutput(setupOptions.mLencRandomizerOutput, true);
                tests_libOTe::logvole_test::ScopedOptionValue randomizerDecline(ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mLencRandomizerOutput, true);
                {
                    tests_libOTe::logvole_test::ScopedOptionValue allowReplay(setupOptions.mLencRandomizerOutputStrict, false);
                    oc::PRNG fallbackPrng(oc::block(0x1E2C5EEDu, 0), 3);
                    LencEncodeOutput actual;
                    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(lencEncTrunc(setupResources.executor, setupResources.results, ctx, s, params.mTauHi,
                        params.mGadgetLogBase, params.mPlaintextModulusBits, fallbackPrng,
                        actual, sigma, 6 * sigma, width, true, gadgetLeaves, &publicB, 4, false, false, nullptr, nullptr, setupOptions)));
                    expect_encoding_equal(expected, actual);
                    LOGVOLE_EXPECT_EQ(fallbackPrng.get<oc::block>(), nextReference);
                }
                tests_libOTe::logvole_test::ScopedOptionValue requireOutput(setupOptions.mLencRandomizerOutputStrict, true);
                oc::PRNG rejectedPrng(oc::block(0x1E2C5EEDu, 0), 3);
                LencEncodeOutput rejected = expected;
                const auto* storage = rejected.mR.data();
                LOGVOLE_REQUIRE_TRUE(!macoro::sync_wait(lencEncTrunc(setupResources.executor, setupResources.results, ctx, s, params.mTauHi,
                    params.mGadgetLogBase, params.mPlaintextModulusBits, rejectedPrng,
                    rejected, sigma, 6 * sigma, width, true, gadgetLeaves, &publicB, 4, false, false, nullptr, nullptr, setupOptions)));
                LOGVOLE_REQUIRE_TRUE(rejected.mR.data() == storage);
                expect_encoding_equal(expected, rejected);
                LOGVOLE_EXPECT_EQ(rejectedPrng.get<oc::block>(), nextReference);
                // With no coefficient output requested, the output-only hook
                // and strict requirement do not introduce work or a failure.
                oc::PRNG nttOnlyPrng(oc::block(0x1E2C5EEDu, 0), 3);
                LencEncodeOutput nttOnly;
                LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(lencEncTrunc(setupResources.executor, setupResources.results, ctx, s, params.mTauHi,
                    params.mGadgetLogBase, params.mPlaintextModulusBits, nttOnlyPrng,
                    nttOnly, sigma, 6 * sigma, width, false, gadgetLeaves, &publicB, 4, false, false, nullptr, nullptr, setupOptions)));
                expect_encoding_equal(expected, nttOnly, false);
                LOGVOLE_EXPECT_EQ(nttOnlyPrng.get<oc::block>(), nextReference);
            }
        }
        if (haveGpu)
        {
            tests_libOTe::logvole_test::ScopedOptionValue option(setupOptions.mParallelLenc, (true) ? osuCrypto::LogVoleChoice::Enabled : osuCrypto::LogVoleChoice::Disabled);
            tests_libOTe::logvole_test::ScopedOptionValue deviceOption(setupOptions.mLencDevice, true);
            tests_libOTe::logvole_test::ScopedOptionValue deviceStrict(setupOptions.mLencDeviceStrict, true);
            tests_libOTe::logvole_test::ScopedOptionValue decline(ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mLencDevice, false);
            tests_libOTe::logvole_test::ScopedOptionValue compactOption(setupOptions.mCompactNoise, true);
            tests_libOTe::logvole_test::ScopedOptionValue paddingOption(setupOptions.mLencDevicePadding, true);
            // A power-of-two input needs neither a host copy nor a device tail.
            auto exactWidthInput = s;
            while ((exactWidthInput.size() & (exactWidthInput.size() - 1u)) != 0)
                exactWidthInput.push_back(s.front());
            const auto unchangedInput = exactWidthInput;
            oc::PRNG referencePrng(oc::block(0x1E2C4ADu, 0), 3);
            LencEncodeOutput expected;
            {
                const auto& ctx = cpuCtx;
                LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(lencEncTrunc(setupResources.executor, setupResources.results, ctx, exactWidthInput, params.mTauHi,
                    params.mGadgetLogBase, params.mPlaintextModulusBits, referencePrng,
                    expected, 3.2, 19.2, 0, true, true, &publicB, 1, false, false, nullptr, nullptr, setupOptions)));
            }
            oc::PRNG actualPrng(oc::block(0x1E2C4ADu, 0), 3);
            LencEncodeOutput actual;
            LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(lencEncTrunc(setupResources.executor, setupResources.results, ctx, exactWidthInput, params.mTauHi,
                params.mGadgetLogBase, params.mPlaintextModulusBits, actualPrng,
                actual, 3.2, 19.2, 0, true, true, &publicB, 4, false, false, nullptr, nullptr, setupOptions)));
            expect_encoding_equal(expected, actual);
            expect_batch_equal(exactWidthInput, unchangedInput);
            LOGVOLE_EXPECT_EQ(actualPrng.get<oc::block>(), referencePrng.get<oc::block>());

            auto invalidInput = s;
            invalidInput.front().mCoeffs.resize(invalidInput.front().mCoeffs.size() - 1u);
            oc::PRNG invalidPrng(oc::block(0x1E2CBADu, 0), 3);
            oc::PRNG untouchedPrng(oc::block(0x1E2CBADu, 0), 3);
            const auto* storage = actual.mR.data();
            LOGVOLE_REQUIRE_TRUE(!macoro::sync_wait(lencEncTrunc(setupResources.executor, setupResources.results, ctx, invalidInput, params.mTauHi,
                params.mGadgetLogBase, params.mPlaintextModulusBits, invalidPrng,
                actual, 3.2, 19.2, 0, true, true, &publicB, 4, false, false, nullptr, nullptr, setupOptions)));
            LOGVOLE_REQUIRE_TRUE(actual.mR.data() == storage);
            expect_encoding_equal(expected, actual);
            LOGVOLE_EXPECT_EQ(invalidPrng.get<oc::block>(), untouchedPrng.get<oc::block>());
        }
    }
}

void LogVole_LencOps_SingletonPaddingAndRelation(const oc::CLP&)
{
    tests_libOTe::logvole_test::SetupResources setupResources;
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, ctx));
    auto s = sample_batch(ctx, 1, 0x53494e474c4553ull);
    std::vector<RnsPoly> x(1);
    resizeZero(x[0].mCoeffs, ringPolyCoeffCount(ctx.mParams));
    // A small constant is represented exactly by both leaf decompositions.
    for (std::size_t j = 0; j < ringModulusCount(ctx); ++j)
        x[0].mCoeffs[j * ctx.mParams.mPolyModulusDegree] = 7;

    for (bool truncated : {false, true})
    {
        LencEncodeOutput enc;
        oc::PRNG prng(oc::block(0x53494e474c4553ull, truncated));
        LOGVOLE_REQUIRE_TRUE(truncated
            ? macoro::sync_wait(lencEncTrunc(setupResources.executor, setupResources.results, ctx, s, params.mTauHi, params.mGadgetLogBase,
                params.mPlaintextModulusBits, prng, enc))
            : lencEnc(ctx, s, params.mTau, params.mGadgetLogBase, prng, enc));
        LOGVOLE_REQUIRE_EQ(enc.mLacct.mWidthPadded, 2u);
        LOGVOLE_REQUIRE_EQ(enc.mLacct.mLevels, 1u);
        LOGVOLE_REQUIRE_EQ(enc.mR.size(), 1u);
        LOGVOLE_REQUIRE_TRUE(validateRingPolyShape(enc.mR[0], ctx.mParams));

        RnsPoly digest;
        LOGVOLE_REQUIRE_TRUE(truncated
            ? lencDigestTrunc(ctx, x, params.mTauHi, params.mGadgetLogBase,
                params.mPlaintextModulusBits, digest)
            : lencDigest(ctx, x, params.mTau, params.mGadgetLogBase, digest));
        LOGVOLE_REQUIRE_TRUE(validateRingPolyShape(digest, ctx.mParams));
        std::vector<RnsPoly> eval(1);
        eval[0].mCoeffs.resize(ringPolyCoeffCount(ctx.mParams));
        DigestTree evalTree;
        if (truncated)
            LOGVOLE_REQUIRE_TRUE(buildDigestTreeTrunc(ctx, x, params.mTauHi,
                params.mGadgetLogBase, params.mPlaintextModulusBits, evalTree,
                enc.mLacct.mWidthPadded));
        std::array<LencEvalBuffer, 3> evalBuffers;
        for (auto& buffer : evalBuffers)
        {
            buffer.mCiphertexts.reserve(2u * enc.mLacct.mLevels * (params.mTauHi + 1u));
            buffer.mNodes.reserve(2u * enc.mLacct.mLevels * (params.mTauHi + 1u));
        }
        LOGVOLE_REQUIRE_TRUE(truncated
            ? macoro::sync_wait(lencEvalTrunc(setupResources.executor, evalBuffers,
                ctx, enc.mLacct, evalTree, 1, params.mTauHi,
                params.mGadgetLogBase, params.mPlaintextModulusBits, eval, LencEvalMode::Coefficient))
            : lencEval(ctx, enc.mLacct, x, 1, params.mTau,
                params.mGadgetLogBase, eval));
        LOGVOLE_REQUIRE_EQ(eval.size(), 1u);
        RnsPoly rDigest, sx, expected;
        LOGVOLE_REQUIRE_TRUE(ringMultiply(enc.mR[0], digest, ctx, rDigest));
        LOGVOLE_REQUIRE_TRUE(ringMultiply(s[0], x[0], ctx, sx));
        LOGVOLE_REQUIRE_TRUE(ringSub(rDigest, sx, ctx, expected));
        expect_poly_equal(expected, eval[0]);

        DigestTree tree;
        LOGVOLE_REQUIRE_FALSE(truncated
            ? buildDigestTreeTrunc(ctx, x, params.mTauHi, params.mGadgetLogBase,
                params.mPlaintextModulusBits, tree, 1)
            : buildDigestTree(ctx, x, params.mTau, params.mGadgetLogBase, tree, 1));
        LencEncodeOutput rejected;
        LOGVOLE_REQUIRE_FALSE(truncated
            ? macoro::sync_wait(lencEncTrunc(setupResources.executor, setupResources.results, ctx, s, params.mTauHi, params.mGadgetLogBase,
                params.mPlaintextModulusBits, prng, rejected, 0, 0, 1))
            : lencEnc(ctx, s, params.mTau, params.mGadgetLogBase,
                prng, rejected, 0, 0, 1));
    }
}

void LogVole_LencOps_EncShapeAndDeterminism(const oc::CLP&)
{
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, ctx));

    auto s = sample_batch(ctx, params.mMu, 0x1111u);
    LencEncodeOutput enc1{};
    oc::PRNG prng1(oc::block(0xABCDEF01u, 0));
    LOGVOLE_REQUIRE_TRUE(lencEnc(ctx, s, params.mTau, params.mGadgetLogBase, prng1, enc1));

    LencEncodeOutput enc2{};
    oc::PRNG prng2(oc::block(0xABCDEF01u, 0));
    LOGVOLE_REQUIRE_TRUE(lencEnc(ctx, s, params.mTau, params.mGadgetLogBase, prng2, enc2));

    LOGVOLE_EXPECT_EQ(enc1.mR.size(), params.mMu);
    LOGVOLE_EXPECT_EQ(enc1.mRNtt.size(), params.mMu);
    LOGVOLE_EXPECT_EQ(enc1.mLacct.mWidthPadded, 4u);
    LOGVOLE_EXPECT_EQ(enc1.mLacct.mLevels, 2u);
    LOGVOLE_EXPECT_EQ(enc1.mLacct.mCt.mRows, enc1.mLacct.mLevels * enc1.mLacct.mWidthPadded);
    LOGVOLE_EXPECT_EQ(enc1.mLacct.mCt.mCols, 2u * params.mTau);

    expect_batch_equal(enc1.mR, enc2.mR);
    expect_batch_equal(enc1.mRNtt, enc2.mRNtt);
    expect_tensor_equal(enc1.mLacct.mCt, enc2.mLacct.mCt);
}

void LogVole_LencOps_DigestTreeDeterministic(const oc::CLP&)
{
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, ctx));

    auto x = sample_batch(ctx, params.mMu, 0x2222u);

    DigestTree tree1{};
    LOGVOLE_REQUIRE_TRUE(buildDigestTree(ctx, x, params.mTau, params.mGadgetLogBase, tree1));

    DigestTree tree2{};
    LOGVOLE_REQUIRE_TRUE(buildDigestTree(ctx, x, params.mTau, params.mGadgetLogBase, tree2));

    LOGVOLE_EXPECT_EQ(tree1.mWidthPadded, 4u);
    LOGVOLE_EXPECT_EQ(tree1.mLevels, 2u);
    expect_poly_equal(tree1.mDigest, tree2.mDigest);
    LOGVOLE_REQUIRE_EQ(tree1.mNodeDecompNtt.size(), tree2.mNodeDecompNtt.size());
    for (std::size_t i = 1; i < tree1.mNodeDecompNtt.size(); ++i)
    {
        expect_batch_equal(tree1.mNodeDecompNtt[i], tree2.mNodeDecompNtt[i]);
    }

    RnsPoly digest{};
    LOGVOLE_REQUIRE_TRUE(lencDigest(ctx, x, params.mTau, params.mGadgetLogBase, digest));
    expect_poly_equal(digest, tree1.mDigest);
}

void LogVole_LencOps_EvalMatchesRmulDigestMinusSmulX(const oc::CLP&)
{
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, ctx));

    auto s = sample_batch(ctx, params.mMu, 0x3333u);
    auto x = sample_batch(ctx, params.mMu, 0x4444u);

    LencEncodeOutput enc{};
    oc::PRNG prng(oc::block(0x5555u, 0));
    LOGVOLE_REQUIRE_TRUE(lencEnc(ctx, s, params.mTau, params.mGadgetLogBase, prng, enc));

    RnsPoly digest{};
    LOGVOLE_REQUIRE_TRUE(lencDigest(ctx, x, params.mTau, params.mGadgetLogBase, digest, enc.mLacct.mWidthPadded));

    std::vector<RnsPoly> eval;
    LOGVOLE_REQUIRE_TRUE(lencEval(ctx, enc.mLacct, x, params.mMu, params.mTau, params.mGadgetLogBase, eval));

    LOGVOLE_REQUIRE_EQ(eval.size(), params.mMu);
    for (std::size_t i = 0; i < params.mMu; ++i)
    {
        RnsPoly rMulDigest{};
        LOGVOLE_REQUIRE_TRUE(ringMultiply(enc.mR[i], digest, ctx, rMulDigest));

        RnsPoly sMulX{};
        LOGVOLE_REQUIRE_TRUE(ringMultiply(s[i], x[i], ctx, sMulX));

        RnsPoly expected{};
        LOGVOLE_REQUIRE_TRUE(ringSub(rMulDigest, sMulX, ctx, expected));

        expect_poly_equal(eval[i], expected);
    }
}

void LogVole_LencOps_EvalFromPrebuiltTreeMatchesEvalFromX(const oc::CLP&)
{
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, ctx));

    auto s = sample_batch(ctx, params.mMu, 0x6666u);
    auto x = sample_batch(ctx, params.mMu, 0x7777u);

    LencEncodeOutput enc{};
    oc::PRNG prng(oc::block(0x8888u, 0));
    LOGVOLE_REQUIRE_TRUE(lencEnc(ctx, s, params.mTau, params.mGadgetLogBase, prng, enc));

    std::vector<RnsPoly> evalFromX;
    LOGVOLE_REQUIRE_TRUE(lencEval(ctx, enc.mLacct, x, params.mMu, params.mTau, params.mGadgetLogBase, evalFromX));

    DigestTree tree{};
    LOGVOLE_REQUIRE_TRUE(buildDigestTree(ctx, x, params.mTau, params.mGadgetLogBase, tree, enc.mLacct.mWidthPadded));

    std::vector<RnsPoly> evalFromTree;
    LOGVOLE_REQUIRE_TRUE(lencEval(ctx, enc.mLacct, tree, params.mMu, params.mTau, params.mGadgetLogBase, evalFromTree));

    expect_batch_equal(evalFromX, evalFromTree);
}

void LogVole_LencOps_EvalRejectsMuMismatch(const oc::CLP&)
{
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, ctx));

    auto s = sample_batch(ctx, params.mMu, 0x9999u);
    auto x = sample_batch(ctx, params.mMu, 0xAAAAu);

    LencEncodeOutput enc{};
    oc::PRNG prng(oc::block(0xBBBBu, 0));
    LOGVOLE_REQUIRE_TRUE(lencEnc(ctx, s, params.mTau, params.mGadgetLogBase, prng, enc));

    std::vector<RnsPoly> eval;
    LOGVOLE_REQUIRE_FALSE(lencEval(
        ctx,
        enc.mLacct,
        x,
        params.mMu + 1u,
        params.mTau,
        params.mGadgetLogBase,
        eval));
}

void LogVole_LencOps_TruncEncShapeAndDeterminism(const oc::CLP& cmd)
{
    tests_libOTe::logvole_test::SetupResources setupResources;
    osuCrypto::LogVoleGpuSetupOptions setupOptions;
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, ctx));

    auto s = sample_batch(ctx, params.mMu, 0x110011u);
    LencEncodeOutput enc1{};
    oc::PRNG prng1(oc::block(0x221122u, 0));
    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(lencEncTrunc(setupResources.executor, setupResources.results,
        ctx,
        s,
        params.mTauHi,
        params.mGadgetLogBase,
        params.mPlaintextModulusBits,
        prng1,
        enc1)));

    LencEncodeOutput enc2{};
    oc::PRNG prng2(oc::block(0x221122u, 0));
    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(lencEncTrunc(setupResources.executor, setupResources.results,
        ctx,
        s,
        params.mTauHi,
        params.mGadgetLogBase,
        params.mPlaintextModulusBits,
        prng2,
        enc2)));

    LOGVOLE_EXPECT_EQ(enc1.mR.size(), params.mMu);
    LOGVOLE_EXPECT_EQ(enc1.mRNtt.size(), params.mMu);
    LOGVOLE_EXPECT_EQ(enc1.mLacct.mWidthPadded, 4u);
    LOGVOLE_EXPECT_EQ(enc1.mLacct.mLevels, 2u);
    LOGVOLE_EXPECT_EQ(enc1.mLacct.mCt.mRows, enc1.mLacct.mLevels * enc1.mLacct.mWidthPadded);
    LOGVOLE_EXPECT_EQ(enc1.mLacct.mCt.mCols, 2u * params.mTauHi);

    expect_batch_equal(enc1.mR, enc2.mR);
    expect_batch_equal(enc1.mRNtt, enc2.mRNtt);
    expect_tensor_equal(enc1.mLacct.mCt, enc2.mLacct.mCt);

    const bool useGpu = cmd.getOr("gpu", 0) != 0;
#if defined(ENABLE_LOGVOLE_CUDA)
    if (useGpu) LOGVOLE_REQUIRE_TRUE(gpu::available());
#endif
    // Cover leaf activeTau smaller than, larger than, and equal to the
    // internal activeTau, including explicit padding beyond the input width.
    check_trunc_setup_parity(params, useGpu);
    auto varied = params;
    varied.mTauHi = 1;
    varied.mPlaintextModulusBits = 40;
    check_trunc_setup_parity(varied, useGpu);
    varied.mTauHi = 2;
    check_trunc_setup_parity(varied, useGpu, 8);

    if (cmd.getOr("lvFactoryFast", 0)) return;

    auto production = params;
    production.mTauHi = 1;
    production.mGadgetLogBase = 110;
    production.mPlaintextModulusBits = 55;
    production.mRing.mPolyModulusDegree = 8192;
    assignValues<int>(production.mRing.mCoeffModulusBits, { 55, 55, 55, 55 });
    check_trunc_setup_parity(production, useGpu);
    production.mGadgetLogBase = 208;
    production.mRing.mPolyModulusDegree = 16384;
    assignValues<int>(production.mRing.mCoeffModulusBits, { 52, 52, 52, 52, 52, 52, 52, 52 });
    check_trunc_setup_parity(production, useGpu);
}

void LogVole_LencOps_TruncDigestTreeDeterministic(const oc::CLP&)
{
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, ctx));

    auto x = sample_batch(ctx, params.mMu, 0x330033u);

    DigestTree tree1{};
    LOGVOLE_REQUIRE_TRUE(buildDigestTreeTrunc(
        ctx,
        x,
        params.mTauHi,
        params.mGadgetLogBase,
        params.mPlaintextModulusBits,
        tree1));

    DigestTree tree2{};
    LOGVOLE_REQUIRE_TRUE(buildDigestTreeTrunc(
        ctx,
        x,
        params.mTauHi,
        params.mGadgetLogBase,
        params.mPlaintextModulusBits,
        tree2));

    LOGVOLE_EXPECT_EQ(tree1.mWidthPadded, 4u);
    LOGVOLE_EXPECT_EQ(tree1.mLevels, 2u);
    expect_poly_equal(tree1.mDigest, tree2.mDigest);
    LOGVOLE_REQUIRE_EQ(tree1.mNodeDecompNtt.size(), tree2.mNodeDecompNtt.size());
    for (std::size_t i = 1; i < tree1.mNodeDecompNtt.size(); ++i)
    {
        expect_batch_equal(tree1.mNodeDecompNtt[i], tree2.mNodeDecompNtt[i]);
    }

    RnsPoly digest{};
    LOGVOLE_REQUIRE_TRUE(lencDigestTrunc(
        ctx,
        x,
        params.mTauHi,
        params.mGadgetLogBase,
        params.mPlaintextModulusBits,
        digest));
    expect_poly_equal(digest, tree1.mDigest);
}

void LogVole_LencOps_TruncEvalPrebuiltTreeDomainsAndReuse(const oc::CLP&)
{
    tests_libOTe::logvole_test::SetupResources setupResources;
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, ctx));

    auto s = sample_batch(ctx, params.mMu, 0x440044u);
    auto x = sample_batch(ctx, params.mMu, 0x550055u);

    LencEncodeOutput enc{};
    oc::PRNG prng(oc::block(0x660066u, 0));
    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(lencEncTrunc(setupResources.executor, setupResources.results,
        ctx,
        s,
        params.mTauHi,
        params.mGadgetLogBase,
        params.mPlaintextModulusBits,
        prng,
        enc)));

    DigestTree tree;
    LOGVOLE_REQUIRE_TRUE(buildDigestTreeTrunc(ctx, x, params.mTauHi,
        params.mGadgetLogBase, params.mPlaintextModulusBits, tree,
        enc.mLacct.mWidthPadded));
    std::array<LencEvalBuffer, 3> evalBuffers;
    for (auto& buffer : evalBuffers)
    {
        buffer.mCiphertexts.reserve(2u * enc.mLacct.mLevels * (params.mTauHi + 1u));
        buffer.mNodes.reserve(2u * enc.mLacct.mLevels * (params.mTauHi + 1u));
    }
    std::vector<RnsPoly> evalCoefficient(params.mMu);
    for (auto& poly : evalCoefficient) poly.mCoeffs.resize(ringPolyCoeffCount(ctx.mParams));
    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(lencEvalTrunc(
        setupResources.executor, evalBuffers, ctx,
        enc.mLacct,
        tree,
        params.mMu,
        params.mTauHi,
        params.mGadgetLogBase,
        params.mPlaintextModulusBits,
        evalCoefficient, LencEvalMode::Coefficient)));

    std::array<const RnsPoly* const*, 3> ciphertextAllocations{}, nodeAllocations{};
    for (std::size_t i = 0; i < evalBuffers.size(); ++i)
    {
        ciphertextAllocations[i] = evalBuffers[i].mCiphertexts.data();
        nodeAllocations[i] = evalBuffers[i].mNodes.data();
    }
    const auto* treeAllocation = tree.mNodeDecompNtt.data();
    const auto* ciphertextAllocation = enc.mLacct.mCt.mPolys.data();
    std::vector<RnsPoly> evalNtt(params.mMu);
    for (auto& poly : evalNtt) poly.mCoeffs.resize(ringPolyCoeffCount(ctx.mParams));
    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(lencEvalTrunc(
        setupResources.executor, evalBuffers, ctx,
        enc.mLacct,
        tree,
        params.mMu,
        params.mTauHi,
        params.mGadgetLogBase,
        params.mPlaintextModulusBits,
        evalNtt, LencEvalMode::Ntt)));
    LOGVOLE_REQUIRE_TRUE(inverseNttBatch(evalNtt, ctx));
    LOGVOLE_REQUIRE_TRUE(tree.mNodeDecompNtt.data() == treeAllocation);
    LOGVOLE_REQUIRE_TRUE(enc.mLacct.mCt.mPolys.data() == ciphertextAllocation);
    for (std::size_t i = 0; i < evalBuffers.size(); ++i)
    {
        LOGVOLE_REQUIRE_TRUE(evalBuffers[i].mCiphertexts.data() == ciphertextAllocations[i]);
        LOGVOLE_REQUIRE_TRUE(evalBuffers[i].mNodes.data() == nodeAllocations[i]);
        LOGVOLE_REQUIRE_TRUE(evalBuffers[i].mCiphertexts.empty() && evalBuffers[i].mNodes.empty());
    }

    expect_batch_equal(evalCoefficient, evalNtt);
}

void LogVole_LencOps_TruncEvalRejectsMuMismatch(const oc::CLP&)
{
    tests_libOTe::logvole_test::SetupResources setupResources;
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, ctx));

    auto s = sample_batch(ctx, params.mMu, 0x770077u);
    auto x = sample_batch(ctx, params.mMu, 0x880088u);

    LencEncodeOutput enc{};
    oc::PRNG prng(oc::block(0x990099u, 0));
    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(lencEncTrunc(setupResources.executor, setupResources.results,
        ctx,
        s,
        params.mTauHi,
        params.mGadgetLogBase,
        params.mPlaintextModulusBits,
        prng,
        enc)));

    std::array<LencEvalBuffer, 3> evalBuffers;
    for (auto& buffer : evalBuffers)
    {
        buffer.mCiphertexts.reserve(2u * enc.mLacct.mLevels * (params.mTauHi + 1u));
        buffer.mNodes.reserve(2u * enc.mLacct.mLevels * (params.mTauHi + 1u));
    }
    // The explicit-tree API rejects a leaf count beyond the padded tree.
    const auto invalidMu = enc.mLacct.mWidthPadded + 1u;
    std::vector<RnsPoly> eval(invalidMu);
    for (auto& poly : eval) poly.mCoeffs.resize(ringPolyCoeffCount(ctx.mParams));
    DigestTree tree;
    LOGVOLE_REQUIRE_TRUE(buildDigestTreeTrunc(ctx, x, params.mTauHi,
        params.mGadgetLogBase, params.mPlaintextModulusBits, tree,
        enc.mLacct.mWidthPadded));
    LOGVOLE_REQUIRE_FALSE(macoro::sync_wait(lencEvalTrunc(
        setupResources.executor, evalBuffers, ctx,
        enc.mLacct,
        tree,
        invalidMu,
        params.mTauHi,
        params.mGadgetLogBase,
        params.mPlaintextModulusBits,
        eval, LencEvalMode::Coefficient)));
}

void LogVole_LencOps_TruncLeafInputsAreGadgetPath(const oc::CLP&)
{
    tests_libOTe::logvole_test::SetupResources setupResources;
    auto params = make_params();
    params.mMu = 4;
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, ctx));

    auto s = sample_batch(ctx, params.mMu, 0xAA00AAu);
    auto x = sample_batch(ctx, params.mMu, 0xBB00BBu);

    LencEncodeOutput enc{};
    oc::PRNG prng(oc::block(0xCC00CCu, 0));
    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(lencEncTrunc(setupResources.executor, setupResources.results,
        ctx,
        s,
        params.mTauHi,
        params.mGadgetLogBase,
        params.mPlaintextModulusBits,
        prng,
        enc,
        0.0,
        0.0,
        0,
        true,
        true)));

    DigestTree tree{};
    LOGVOLE_REQUIRE_TRUE(buildDigestTreeTrunc(
        ctx,
        x,
        params.mTauHi,
        params.mGadgetLogBase,
        params.mPlaintextModulusBits,
        tree,
        enc.mLacct.mWidthPadded,
        true));

    const std::uint32_t firstLeaf = tree.mWidthPadded - 1u;
    LOGVOLE_REQUIRE_EQ(tree.mNodeDecompNtt[firstLeaf].size(), 1u);

    std::array<LencEvalBuffer, 3> evalBuffers;
    for (auto& buffer : evalBuffers)
    {
        buffer.mCiphertexts.reserve(2u * enc.mLacct.mLevels * (params.mTauHi + 1u));
        buffer.mNodes.reserve(2u * enc.mLacct.mLevels * (params.mTauHi + 1u));
    }
    std::vector<RnsPoly> eval(params.mMu);
    for (auto& poly : eval) poly.mCoeffs.resize(ringPolyCoeffCount(ctx.mParams));
    LOGVOLE_REQUIRE_TRUE(macoro::sync_wait(lencEvalTrunc(
        setupResources.executor, evalBuffers, ctx,
        enc.mLacct,
        tree,
        params.mMu,
        params.mTauHi,
        params.mGadgetLogBase,
        params.mPlaintextModulusBits,
        eval, LencEvalMode::Coefficient,
        true)));
    LOGVOLE_EXPECT_EQ(eval.size(), params.mMu);
    LOGVOLE_EXPECT_EQ(enc.mLacct.mCt.mCols, 2u * params.mTauHi);
}

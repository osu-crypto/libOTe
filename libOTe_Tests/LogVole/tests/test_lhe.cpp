#include "cryptoTools/Common/CLP.h"
#include "libOTe_Tests/LogVole_TestOptions.h"
#include "libOTe/Vole/LogVole/LogVoleLhe.h"
#include "libOTe/config.h"
#if defined(ENABLE_LOGVOLE_CUDA)
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuProtocol.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuGaussian.h"
#endif

#include "libOTe_Tests/LogVole_TestUtil.h"

#include <algorithm>
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


    struct LheParams
    {
        RingParams mRing{};
        std::uint32_t mMu = 3;
        std::uint32_t mTau = 3;
        std::uint32_t mTauHi = 2;
        std::uint32_t mGadgetLogBase = 20;
    };

    LheParams make_params()
    {
        LheParams p{};
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
            out.push_back(deriveUniformPolyFromNonce(ctx, seed, 0x1E2C0002u, i));
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

    bool batches_equal(const std::vector<RnsPoly>& a, const std::vector<RnsPoly>& b)
    {
        if (a.size() != b.size())
        {
            return false;
        }

        for (std::size_t i = 0; i < a.size(); ++i)
        {
            if (!rangesEqual(a[i].mCoeffs, b[i].mCoeffs))
            {
                return false;
            }
        }

        return true;
    }

    void expect_tensor_equal(const RingTensor& a, const RingTensor& b)
    {
        LOGVOLE_EXPECT_EQ(a.mRows, b.mRows);
        LOGVOLE_EXPECT_EQ(a.mCols, b.mCols);
        expect_batch_equal(a.mPolys, b.mPolys);
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

    bool forward_tensor(RingTensor& tensor, const RingNttContext& ctx)
    {
        for (auto& poly : tensor.mPolys)
        {
            if (!forwardNtt(poly, ctx))
            {
                return false;
            }
        }
        return true;
    }

    bool zero_poly(const RingNttContext& ctx, RnsPoly& out)
    {
        resizeZero(out.mCoeffs, ringPolyCoeffCount(ctx.mParams));
        return true;
    }

    bool recompute_trunc_high_part(
        const RingNttContext& ctx,
        const RnsPoly& digest,
        std::uint32_t gadgetLogBase,
        std::uint32_t tauHi,
        RnsPoly& out)
    {
        std::vector<RnsPoly> hiDigits;
        if (!gadgetDecomposeBitsRangeCentered(digest, gadgetLogBase, 1, tauHi, ctx, hiDigits) ||
            !zero_poly(ctx, out))
        {
            return false;
        }

        for (std::uint32_t i = 0; i < tauHi; ++i)
        {
            RnsPoly shifted{};
            if (!multiplyByGPower(ctx, hiDigits[i], gadgetLogBase, i + 1u, shifted) ||
                !ringAddInplace(out, shifted, ctx))
            {
                return false;
            }
        }
        return true;
    }

    void check_enc1_serial_reference(const RingParams& ring, bool useGpu, std::uint32_t cols, std::uint32_t gadgetBits = 20)
    {
        osuCrypto::LogVoleGpuSetupOptions setupOptions;
        osuCrypto::LogVoleExecutionOptions advanced;
        advanced.mUseGpu = useGpu;
        advanced.mAdvanced.mProtocol.mGaussianResident = false;
#if defined(ENABLE_LOGVOLE_CUDA)
        const bool haveGpu = gpu::enabled(advanced);
        const bool haveGaussian = haveGpu && gpu::gaussianTransformHostCompatible();
#else
        const bool haveGpu = false;
        const bool haveGaussian = false;
#endif
        RingNttContext ctx{};
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(ring, ctx,
            std::make_shared<RingContextFactory>(advanced)));
        RingNttContext cpuCtx;
        auto cpuOptions = advanced;
        cpuOptions.mUseGpu = false;
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(ring, cpuCtx,
            std::make_shared<RingContextFactory>(cpuOptions)));
        constexpr std::uint32_t rows = 5;
        auto r = sample_batch(ctx, rows, 0x123456u);
        auto sk = sample_batch(ctx, cols, 0x234567u);
        std::vector<RnsPoly> publicA;
        LOGVOLE_REQUIRE_TRUE(buildLhePublicANtt(ctx, rows, publicA));
        // Exercise the normalization contract for coefficient and NTT inputs.
        for (auto* batch : { &r, &sk, &publicA })
            for (auto& poly : *batch)
                for (std::size_t limb = 0; limb < ringModulusCount(ctx); ++limb)
                {
                    const auto offset = limb * ring.mPolyModulusDegree;
                    poly.mCoeffs[offset] = std::numeric_limits<std::uint64_t>::max();
                    poly.mCoeffs[offset + ring.mPolyModulusDegree - 1] = ringModulusValue(ctx, limb) + 3;
                }
        const auto originalR = r, originalSk = sk, originalA = publicA;

        for (bool inputNtt : { false, true })
        for (bool truncate : { false, true })
        for (double sigma : { 0.0, 3.2 })
        {
            // The reference retains the original serial transform/noise order.
            // A short PRNG buffer makes each 64-byte SEAL seed cross a refill.
            oc::PRNG referencePrng(oc::block(0x345678u, 0), 3);
            RingTensor expected{};
            expected.mRows = rows;
            expected.mCols = cols;
            expected.mPolys.resize(ringTensorSize(expected));
            {
                const auto& ctx = cpuCtx;
                auto rNtt = r, skNtt = sk;
                for (auto& poly : skNtt) LOGVOLE_REQUIRE_TRUE(forwardNtt(poly, ctx));
                if (!inputNtt)
                    for (auto& poly : rNtt) LOGVOLE_REQUIRE_TRUE(forwardNtt(poly, ctx));
                for (std::uint32_t row = 0; row < rows; ++row)
                for (std::uint32_t col = 0; col < cols; ++col)
                {
                    auto& poly = expected.mPolys[ringTensorIndex(expected, row, col)];
                    LOGVOLE_REQUIRE_TRUE(multiplyByGPower(ctx, rNtt[row], gadgetBits,
                        col + static_cast<std::uint32_t>(truncate), poly));
                    LOGVOLE_REQUIRE_TRUE(dyadicMultiplyAddNttInplace(publicA[row], skNtt[col], poly, ctx));
                    LOGVOLE_REQUIRE_TRUE(inverseNtt(poly, ctx));
                    if (sigma > 0)
                        LOGVOLE_REQUIRE_TRUE(addPolyError(poly, sigma, 19.2, referencePrng, ctx));
                }
            }
            const auto nextReference = referencePrng.get<oc::block>();
#if defined(ENABLE_LOGVOLE_CUDA)
            if (haveGpu && !inputNtt && !truncate && sigma == 0.0)
            {
                auto aliasedR = r;
                {
                    tests_libOTe::logvole_test::ScopedOptionValue forced(ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mLheDevice, true);
                    const auto* storage = aliasedR.data();
                    LOGVOLE_REQUIRE_FALSE(gpu::assembleLheCiphertextDevice(ctx,
                        aliasedR, sk, publicA, gadgetBits, false, 0u, aliasedR));
                    LOGVOLE_REQUIRE_TRUE(aliasedR.data() == storage);
                    LOGVOLE_REQUIRE_TRUE(batches_equal(aliasedR, r));
                }
                tests_libOTe::logvole_test::ScopedOptionValue enabled(ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mLheDevice, false);
                LOGVOLE_REQUIRE_TRUE(gpu::assembleLheCiphertextDevice(ctx,
                    aliasedR, sk, publicA, gadgetBits, false, 0u, aliasedR));
                LOGVOLE_REQUIRE_TRUE(batches_equal(aliasedR, expected.mPolys));
            }
#endif
            if (haveGpu)
            {
                tests_libOTe::logvole_test::ScopedOptionValue resident(ctx.mExecutionOptions.mAdvanced.mProtocol.mGaussianResident, true);
                // Unknown host arithmetic must exercise exact host replay; strict rejection is checked separately.
                tests_libOTe::logvole_test::ScopedOptionValue residentStrict(ctx.mExecutionOptions.mAdvanced.mProtocol.mGaussianResidentStrict, (haveGaussian));
                tests_libOTe::logvole_test::ScopedOptionValue residentDecline(ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mGaussianResident, false);
                tests_libOTe::logvole_test::ScopedOptionValue transform(ctx.mExecutionOptions.mAdvanced.mProtocol.mGaussianTransform, true);
                tests_libOTe::logvole_test::ScopedOptionValue transformStrict(ctx.mExecutionOptions.mAdvanced.mProtocol.mGaussianTransformStrict, (haveGaussian));
                tests_libOTe::logvole_test::ScopedOptionValue transformDecline(ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mGaussianTransform, false);
                tests_libOTe::logvole_test::ScopedOptionValue device(setupOptions.mLheDevice, true);
                tests_libOTe::logvole_test::ScopedOptionValue deviceStrict(setupOptions.mLheDeviceStrict, true);
                tests_libOTe::logvole_test::ScopedOptionValue deviceDecline(ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mLheDevice, false);
                tests_libOTe::logvole_test::ScopedOptionValue compact(setupOptions.mCompactNoise, true);
                tests_libOTe::logvole_test::ScopedOptionValue compactStrict(setupOptions.mCompactNoiseStrict, true);
                auto invoke = [&](oc::PRNG& prng, RingTensor& out,
                                  std::shared_ptr<const LazyRingTensorHostState>* deferred = nullptr) {
                    return truncate
                        ? lheEnc1Trunc(ctx, r, sk, gadgetBits, out, sigma, 19.2, &prng, inputNtt, &publicA, 4, deferred,  {}, nullptr, nullptr, nullptr, nullptr, 0, false, setupOptions)
                        : lheEnc1(ctx, r, sk, gadgetBits, out, sigma, 19.2, &prng, inputNtt, &publicA, 4, deferred,  {}, setupOptions);
                };
                for (const char* blocks : {"0", "1"})
                {
                    tests_libOTe::logvole_test::ScopedOptionValue prefix(ctx.mExecutionOptions.mAdvanced.mProtocol.mGaussianTransformPrefixBlocks, static_cast<std::uint64_t>(std::strtoull(blocks, nullptr, 10)));
                    oc::PRNG actualPrng(oc::block(0x345678u, 0), 3);
                    RingTensor actual;
                    LOGVOLE_REQUIRE_TRUE(invoke(actualPrng, actual));
                    expect_tensor_equal(expected, actual);
                    LOGVOLE_EXPECT_EQ(actualPrng.get<oc::block>(), nextReference);
                }
                {
                    oc::PRNG deferredPrng(oc::block(0x345678u, 0), 3);
                    RingTensor deferred;
                    std::shared_ptr<const LazyRingTensorHostState> owner;
                    LOGVOLE_REQUIRE_TRUE(invoke(deferredPrng, deferred, &owner));
                    expect_deferred_tensor_equal(owner, deferred, expected);
                    LOGVOLE_EXPECT_EQ(deferredPrng.get<oc::block>(), nextReference);

                    if (!inputNtt && truncate && sigma > 0 && ring.mPolyModulusDegree == 1024)
                    {
                        const auto retained = owner;
                        RingTensor rejected = expected;
                        const auto* storage = rejected.mPolys.data();
                        oc::PRNG rejectedPrng(oc::block(0x345678u, 0), 3);
                        oc::PRNG untouchedPrng(oc::block(0x345678u, 0), 3);
                        LOGVOLE_REQUIRE_FALSE(lheEnc1Trunc(ctx, r, sk, gadgetBits, rejected,
                            -1.0, 19.2, &rejectedPrng, inputNtt, &publicA, 4, &owner,  {}, nullptr, nullptr, nullptr, nullptr, 0, false, setupOptions));
                        LOGVOLE_REQUIRE_TRUE(owner == retained);
                        LOGVOLE_REQUIRE_TRUE(rejected.mPolys.data() == storage);
                        expect_tensor_equal(expected, rejected);
                        LOGVOLE_EXPECT_EQ(rejectedPrng.get<oc::block>(), untouchedPrng.get<oc::block>());

                        // With compact noise disabled, the device result needs
                        // host noise addition before it is a complete ciphertext.
                        // The explicit deferred request must therefore publish
                        // eager data and reset a previous owner.
                        {
                            tests_libOTe::logvole_test::ScopedOptionValue eagerNoise(setupOptions.mCompactNoise, false);
                            oc::PRNG eagerPrng(oc::block(0x345678u, 0), 3);
                            LOGVOLE_REQUIRE_TRUE(invoke(eagerPrng, deferred, &owner));
                            LOGVOLE_REQUIRE_FALSE(owner);
                            expect_tensor_equal(expected, deferred);
                            LOGVOLE_EXPECT_EQ(eagerPrng.get<oc::block>(), nextReference);
                        }
                        deferred.mPolys.front().mCoeffs.front() ^= 1;
                        expect_tensor_equal(expected, retained->get());
                        {
                            tests_libOTe::logvole_test::ScopedOptionValue eagerDevice(setupOptions.mLheDevice, false);
                            oc::PRNG eagerPrng(oc::block(0x345678u, 0), 3);
                            owner = retained;
                            LOGVOLE_REQUIRE_TRUE(invoke(eagerPrng, deferred, &owner));
                            LOGVOLE_REQUIRE_FALSE(owner);
                            expect_tensor_equal(expected, deferred);
                            LOGVOLE_EXPECT_EQ(eagerPrng.get<oc::block>(), nextReference);
                        }
                    }
                }
                tests_libOTe::logvole_test::ScopedOptionValue decline(ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mGaussianResident, true);
                {
                    tests_libOTe::logvole_test::ScopedOptionValue replay(ctx.mExecutionOptions.mAdvanced.mProtocol.mGaussianResidentStrict, false);
                    oc::PRNG replayPrng(oc::block(0x345678u, 0), 3);
                    RingTensor actual;
                    LOGVOLE_REQUIRE_TRUE(invoke(replayPrng, actual));
                    expect_tensor_equal(expected, actual);
                    LOGVOLE_EXPECT_EQ(replayPrng.get<oc::block>(), nextReference);
                }
                if (sigma > 0.0)
                {
                    tests_libOTe::logvole_test::ScopedOptionValue requireResident(ctx.mExecutionOptions.mAdvanced.mProtocol.mGaussianResidentStrict, true);
                    oc::PRNG rejectedPrng(oc::block(0x345678u, 0), 3);
                    RingTensor rejected = expected;
                    const auto* storage = rejected.mPolys.data();
                    LOGVOLE_REQUIRE_FALSE(invoke(rejectedPrng, rejected));
                    LOGVOLE_REQUIRE_TRUE(rejected.mPolys.data() == storage);
                    expect_tensor_equal(expected, rejected);
                    LOGVOLE_EXPECT_EQ(rejectedPrng.get<oc::block>(), nextReference);
                }
                LOGVOLE_REQUIRE_TRUE(batches_equal(r, originalR));
                LOGVOLE_REQUIRE_TRUE(batches_equal(sk, originalSk));
                LOGVOLE_REQUIRE_TRUE(batches_equal(publicA, originalA));
            }
            for (std::uint32_t workers : { 1u, 4u })
            for (bool deviceAssembly : { false, true })
            for (bool compactNoise : { false, true })
            {
                if (deviceAssembly && !haveGpu) continue;
                if (compactNoise && !deviceAssembly) continue;
                tests_libOTe::logvole_test::ScopedOptionValue parallelOption(setupOptions.mParallelLhe, (true) ? osuCrypto::LogVoleChoice::Enabled : osuCrypto::LogVoleChoice::Disabled);
                tests_libOTe::logvole_test::ScopedOptionValue deviceOption(setupOptions.mLheDevice, (deviceAssembly ? "1" : "0")[0] != '0');
                tests_libOTe::logvole_test::ScopedOptionValue strictOption(setupOptions.mLheDeviceStrict, true);
                tests_libOTe::logvole_test::ScopedOptionValue compactOption(setupOptions.mCompactNoise, (compactNoise ? "1" : "0")[0] != '0');
                tests_libOTe::logvole_test::ScopedOptionValue compactStrict(setupOptions.mCompactNoiseStrict, true);
                tests_libOTe::logvole_test::ScopedOptionValue forceOption(ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mLheDevice, false);
#if defined(ENABLE_LOGVOLE_CUDA)
                if (deviceAssembly) LOGVOLE_REQUIRE_TRUE(gpu::enabled(ctx));
#endif
                oc::PRNG actualPrng(oc::block(0x345678u, 0), 3);
                RingTensor actual{};
                const bool ok = truncate
                    ? lheEnc1Trunc(ctx, r, sk, gadgetBits, actual, sigma, 19.2,
                        &actualPrng, inputNtt, &publicA, workers, nullptr,  {}, nullptr, nullptr, nullptr, nullptr, 0, false, setupOptions)
                    : lheEnc1(ctx, r, sk, gadgetBits, actual, sigma, 19.2,
                        &actualPrng, inputNtt, &publicA, workers, nullptr,  {}, setupOptions);
                LOGVOLE_REQUIRE_TRUE(ok);
                expect_tensor_equal(expected, actual);
                LOGVOLE_EXPECT_EQ(actualPrng.get<oc::block>(), nextReference);
                LOGVOLE_REQUIRE_TRUE(batches_equal(r, originalR));
                LOGVOLE_REQUIRE_TRUE(batches_equal(sk, originalSk));
                LOGVOLE_REQUIRE_TRUE(batches_equal(publicA, originalA));
            }
            if (haveGpu)
            {
                tests_libOTe::logvole_test::ScopedOptionValue deviceOption(setupOptions.mLheDevice, true);
                tests_libOTe::logvole_test::ScopedOptionValue compactOption(setupOptions.mCompactNoise, true);
                tests_libOTe::logvole_test::ScopedOptionValue deviceStrict(setupOptions.mLheDeviceStrict, false);
                tests_libOTe::logvole_test::ScopedOptionValue compactStrict(setupOptions.mCompactNoiseStrict, false);
                tests_libOTe::logvole_test::ScopedOptionValue forceOption(ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mLheDevice, true);
                auto invoke = [&](oc::PRNG& prng, RingTensor& output, double clip) {
                    return truncate
                        ? lheEnc1Trunc(ctx, r, sk, gadgetBits, output, sigma, clip,
                            &prng, inputNtt, &publicA, 4, nullptr,  {}, nullptr, nullptr, nullptr, nullptr, 0, false, setupOptions)
                        : lheEnc1(ctx, r, sk, gadgetBits, output, sigma, clip,
                            &prng, inputNtt, &publicA, 4, nullptr,  {}, setupOptions);
                };
                for (const char* parallel : { "0", "1" })
                {
                    tests_libOTe::logvole_test::ScopedOptionValue parallelOption(setupOptions.mParallelLhe, ((parallel)[0] != '0') ? osuCrypto::LogVoleChoice::Enabled : osuCrypto::LogVoleChoice::Disabled);
                    oc::PRNG fallbackPrng(oc::block(0x345678u, 0), 3);
                    RingTensor actual;
                    LOGVOLE_REQUIRE_TRUE(invoke(fallbackPrng, actual, 19.2));
                    expect_tensor_equal(expected, actual);
                    LOGVOLE_EXPECT_EQ(fallbackPrng.get<oc::block>(), nextReference);
                }
                {
                    tests_libOTe::logvole_test::ScopedOptionValue strictOption(setupOptions.mLheDeviceStrict, true);
                    oc::PRNG failedPrng(oc::block(0x345678u, 0), 3);
                    RingTensor failed;
                    failed.mRows = 0xBADu;
                    LOGVOLE_EXPECT_FALSE(invoke(failedPrng, failed, 19.2));
                    LOGVOLE_EXPECT_EQ(failed.mRows, 0xBADu);
                }
                if (sigma == 0.0)
                {
                    tests_libOTe::logvole_test::ScopedOptionValue allowDevice(ctx.mExecutionOptions.mAdvanced.mProtocol.mFailures.mLheDevice, false);
                    const double ineligibleClip = std::nextafter(
                        static_cast<double>(ringModulusValue(ctx, 0) >> 1u),
                        std::numeric_limits<double>::infinity());
                    // Eligibility failure is checked before drawing seeds.
                    oc::PRNG rejectedPrng(oc::block(0x345678u, 0), 3);
                    RingTensor rejected;
                    rejected.mRows = 0xBADu;
                    {
                        tests_libOTe::logvole_test::ScopedOptionValue strictCompact(setupOptions.mCompactNoiseStrict, true);
                        LOGVOLE_EXPECT_FALSE(invoke(rejectedPrng, rejected, ineligibleClip));
                    }
                    LOGVOLE_EXPECT_EQ(rejected.mRows, 0xBADu);
                    LOGVOLE_EXPECT_EQ(rejectedPrng.get<oc::block>(), nextReference);
                    // Without strict compact mode, sigma=0 keeps the ordinary
                    // noiseless result even when compact representation declines.
                    oc::PRNG fallbackPrng(oc::block(0x345678u, 0), 3);
                    RingTensor actual;
                    LOGVOLE_REQUIRE_TRUE(invoke(fallbackPrng, actual, ineligibleClip));
                    expect_tensor_equal(expected, actual);
                    LOGVOLE_EXPECT_EQ(fallbackPrng.get<oc::block>(), nextReference);
                }
                LOGVOLE_REQUIRE_TRUE(batches_equal(r, originalR));
                LOGVOLE_REQUIRE_TRUE(batches_equal(sk, originalSk));
                LOGVOLE_REQUIRE_TRUE(batches_equal(publicA, originalA));
            }
        }
    }
}

void LogVole_LheOps_PublicADeterministic(const oc::CLP&)
{
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, ctx));

    std::vector<RnsPoly> a1;
    LOGVOLE_REQUIRE_TRUE(buildLhePublicANtt(ctx, params.mMu, a1));

    std::vector<RnsPoly> a2;
    LOGVOLE_REQUIRE_TRUE(buildLhePublicANtt(ctx, params.mMu, a2));

    LOGVOLE_EXPECT_EQ(a1.size(), params.mMu);
    expect_batch_equal(a1, a2);

    const auto shared = sharedLhePublicANtt(ctx, params.mMu);
    LOGVOLE_REQUIRE_TRUE(shared && shared == sharedLhePublicANtt(ctx, params.mMu));
    expect_batch_equal(*shared, a2);
    a1.front().mCoeffs.front() ^= 1;
    expect_batch_equal(*shared, a2);
    LOGVOLE_EXPECT_FALSE(sharedLhePublicANtt(ctx, 0));
}

void LogVole_LheOps_Enc1ShapeDeterminismAndColumnDecrypt(const oc::CLP& cmd)
{
    osuCrypto::LogVoleGpuSetupOptions setupOptions;
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, ctx));

    auto r = sample_batch(ctx, params.mMu, 0x1010u);
    auto sk1 = sample_batch(ctx, params.mTau, 0x2020u);

    std::vector<RnsPoly> publicA;
    LOGVOLE_REQUIRE_TRUE(buildLhePublicANtt(ctx, params.mMu, publicA));

    RingTensor ct1{};
    LOGVOLE_REQUIRE_TRUE(lheEnc1(ctx, r, sk1, params.mGadgetLogBase, ct1, 0.0, 0.0, nullptr, false, &publicA));

    RingTensor ct2{};
    LOGVOLE_REQUIRE_TRUE(lheEnc1(ctx, r, sk1, params.mGadgetLogBase, ct2, 0.0, 0.0, nullptr, false, &publicA));

    LOGVOLE_EXPECT_EQ(ct1.mRows, params.mMu);
    LOGVOLE_EXPECT_EQ(ct1.mCols, params.mTau);
    expect_tensor_equal(ct1, ct2);

    for (std::uint32_t col = 0; col < params.mTau; ++col)
    {
        std::vector<RnsPoly> column;
        column.reserve(params.mMu);
        for (std::uint32_t row = 0; row < params.mMu; ++row)
        {
            column.push_back(ct1.mPolys[ringTensorIndex(ct1, row, col)]);
        }

        std::vector<RnsPoly> dec;
        LOGVOLE_REQUIRE_TRUE(lheDec(ctx, column, sk1[col], dec, &publicA));

        for (std::uint32_t row = 0; row < params.mMu; ++row)
        {
            RnsPoly expected{};
            LOGVOLE_REQUIRE_TRUE(multiplyByGPower(ctx, r[row], params.mGadgetLogBase, col, expected));
            expect_poly_equal(dec[row], expected);
        }
    }

    // Exercise parallel assembly with an explicit backend selection.
    const bool useGpu = cmd.getOr("gpu", 0) != 0;
#if defined(ENABLE_LOGVOLE_CUDA)
    if (useGpu) LOGVOLE_REQUIRE_TRUE(gpu::available());
#endif
    check_enc1_serial_reference(params.mRing, useGpu, params.mTau);
    if (cmd.getOr("lvFactoryFast", 0)) return;
    RingParams productionRing{};
    productionRing.mPolyModulusDegree = 8192;
    assignValues<int>(productionRing.mCoeffModulusBits, { 55, 55, 55, 55 });
    check_enc1_serial_reference(productionRing, useGpu, 2, 110);
    productionRing.mPolyModulusDegree = 16384;
    assignValues<int>(productionRing.mCoeffModulusBits, { 52, 52, 52, 52, 52, 52, 52, 52 });
    check_enc1_serial_reference(productionRing, useGpu, 2, 208);
}

void LogVole_LheOps_ApplyCt1AndDeriveSkxRelation(const oc::CLP&)
{
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, ctx));

    auto r = sample_batch(ctx, params.mMu, 0x4040u);
    auto sk1 = sample_batch(ctx, params.mTau, 0x5050u);
    auto digest = deriveUniformPolyFromNonce(ctx, 0x6060u, 0x7070u, 0);

    std::vector<RnsPoly> publicA;
    LOGVOLE_REQUIRE_TRUE(buildLhePublicANtt(ctx, params.mMu, publicA));

    RingTensor ct1{};
    LOGVOLE_REQUIRE_TRUE(lheEnc1(ctx, r, sk1, params.mGadgetLogBase, ct1, 0.0, 0.0, nullptr, false, &publicA));
    LOGVOLE_REQUIRE_TRUE(forward_tensor(ct1, ctx));

    std::vector<RnsPoly> applied;
    LOGVOLE_REQUIRE_TRUE(lheApplyCt1(ctx, ct1, digest, params.mGadgetLogBase, params.mTau, applied, true));

    RnsPoly tbkPrime{};
    LOGVOLE_REQUIRE_TRUE(zero_poly(ctx, tbkPrime));

    RnsPoly skx{};
    LOGVOLE_REQUIRE_TRUE(deriveSkx(ctx, sk1, digest, tbkPrime, params.mGadgetLogBase, params.mTau, skx));

    std::vector<RnsPoly> dec;
    LOGVOLE_REQUIRE_TRUE(lheDec(ctx, applied, skx, dec, &publicA, true));

    for (std::uint32_t row = 0; row < params.mMu; ++row)
    {
        RnsPoly expected{};
        LOGVOLE_REQUIRE_TRUE(ringMultiply(r[row], digest, ctx, expected));
        expect_poly_equal(dec[row], expected);
    }
}

void LogVole_LheOps_TruncApplyCt1AndDeriveSkxRelation(const oc::CLP&)
{
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, ctx));

    auto r = sample_batch(ctx, params.mMu, 0x8080u);
    auto sk1 = sample_batch(ctx, params.mTauHi, 0x9090u);
    auto digest = deriveUniformPolyFromNonce(ctx, 0xA0A0u, 0xB0B0u, 0);

    std::vector<RnsPoly> publicA;
    LOGVOLE_REQUIRE_TRUE(buildLhePublicANtt(ctx, params.mMu, publicA));

    RingTensor ct1{};
    LOGVOLE_REQUIRE_TRUE(lheEnc1Trunc(ctx, r, sk1, params.mGadgetLogBase, ct1, 0.0, 0.0, nullptr, false, &publicA));
    LOGVOLE_REQUIRE_TRUE(forward_tensor(ct1, ctx));

    std::vector<RnsPoly> applied;
    LOGVOLE_REQUIRE_TRUE(lheApplyCt1Trunc(ctx, ct1, digest, params.mGadgetLogBase, params.mTauHi, applied, true));

    RnsPoly tbkPrime{};
    LOGVOLE_REQUIRE_TRUE(zero_poly(ctx, tbkPrime));

    RnsPoly skx{};
    LOGVOLE_REQUIRE_TRUE(deriveSkxTrunc(ctx, sk1, digest, tbkPrime, params.mGadgetLogBase, params.mTauHi, skx));

    std::vector<RnsPoly> dec;
    LOGVOLE_REQUIRE_TRUE(lheDec(ctx, applied, skx, dec, &publicA, true));

    RnsPoly highPart{};
    LOGVOLE_REQUIRE_TRUE(recompute_trunc_high_part(ctx, digest, params.mGadgetLogBase, params.mTauHi, highPart));

    for (std::uint32_t row = 0; row < params.mMu; ++row)
    {
        RnsPoly expected{};
        LOGVOLE_REQUIRE_TRUE(ringMultiply(r[row], highPart, ctx, expected));
        expect_poly_equal(dec[row], expected);
    }
}

void LogVole_LheOps_ApplyCt1AndDeriveSkxRelations(const oc::CLP& cmd)
{
    LogVole_LheOps_ApplyCt1AndDeriveSkxRelation(cmd);
    LogVole_LheOps_TruncApplyCt1AndDeriveSkxRelation(cmd);
}

void LogVole_LheOps_HashedCt2Deterministic(const oc::CLP&)
{
    const auto params = make_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params.mRing, ctx));

    AlignedUnVec<std::uint8_t> seed(16);
    for (std::size_t idx = 0; idx < seed.size(); ++idx)
    {
        seed[idx] = static_cast<std::uint8_t>(idx + 1);
    }
    const auto digest = deriveUniformPolyFromNonce(ctx, 0xD1CEu, 0xC720u, 0);

    std::vector<RnsPoly> ct2A;
    LOGVOLE_REQUIRE_TRUE(buildHashedCt2(ctx, params.mMu, seed, 17, digest, 2, ct2A));

    std::vector<RnsPoly> ct2B;
    LOGVOLE_REQUIRE_TRUE(buildHashedCt2(ctx, params.mMu, seed, 17, digest, 2, ct2B));

    expect_batch_equal(ct2A, ct2B);

    std::vector<RnsPoly> ct2Sid;
    LOGVOLE_REQUIRE_TRUE(buildHashedCt2(ctx, params.mMu, seed, 18, digest, 2, ct2Sid));
    LOGVOLE_EXPECT_FALSE(batches_equal(ct2A, ct2Sid));

    const auto otherDigest = deriveUniformPolyFromNonce(ctx, 0xD1CEu, 0xC720u, 1);
    std::vector<RnsPoly> ct2Digest;
    LOGVOLE_REQUIRE_TRUE(buildHashedCt2(ctx, params.mMu, seed, 17, otherDigest, 2, ct2Digest));
    LOGVOLE_EXPECT_FALSE(batches_equal(ct2A, ct2Digest));

    std::vector<RnsPoly> ct2Instance;
    LOGVOLE_REQUIRE_TRUE(buildHashedCt2(ctx, params.mMu, seed, 17, digest, 3, ct2Instance));
    LOGVOLE_EXPECT_FALSE(batches_equal(ct2A, ct2Instance));

    AlignedUnVec<std::uint8_t> otherSeed = seed;
    otherSeed[0] ^= 0x80;
    std::vector<RnsPoly> ct2Seed;
    LOGVOLE_REQUIRE_TRUE(buildHashedCt2(ctx, params.mMu, otherSeed, 17, digest, 2, ct2Seed));
    LOGVOLE_EXPECT_FALSE(batches_equal(ct2A, ct2Seed));

    const auto seedBlock = deriveSeedInstanceBlock(seed, 17, digest, 2, params.mMu);
    const auto otherMuSeedBlock = deriveSeedInstanceBlock(seed, 17, digest, 2, params.mMu + 1);
    LOGVOLE_EXPECT_FALSE(seedBlock == otherMuSeedBlock);
}

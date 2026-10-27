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
    class ScopedEnvironmentValue
    {
    public:
        ScopedEnvironmentValue(const char* name, const char* value) : mName(name)
        {
            if (const char* old = std::getenv(name)) { mHadOld = true; mOld = old; }
            if (value) ::tests_libOTe::logvole_test::setEnvironment(name, value, 1);
            else ::tests_libOTe::logvole_test::unsetEnvironment(name);
        }
        ~ScopedEnvironmentValue()
        {
            if (mHadOld) ::tests_libOTe::logvole_test::setEnvironment(mName.c_str(), mOld.c_str(), 1);
            else ::tests_libOTe::logvole_test::unsetEnvironment(mName.c_str());
        }
        ScopedEnvironmentValue(const ScopedEnvironmentValue&) = delete;
        ScopedEnvironmentValue& operator=(const ScopedEnvironmentValue&) = delete;
    private:
        std::string mName, mOld;
        bool mHadOld = false;
    };

#if defined(ENABLE_LOGVOLE_CUDA)
    class ScopedGpuEnabled
    {
    public:
        explicit ScopedGpuEnabled(bool enabled) : mWasEnabled(gpu::enabled()) { gpu::setEnabled(enabled); }
        ~ScopedGpuEnabled() { gpu::setEnabled(mWasEnabled); }
        ScopedGpuEnabled(const ScopedGpuEnabled&) = delete;
        ScopedGpuEnabled& operator=(const ScopedGpuEnabled&) = delete;
    private:
        bool mWasEnabled;
    };
#endif

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
        LOGVOLE_REQUIRE_TRUE(owner->copyCoefficientsTo(actualBytes));
        LOGVOLE_REQUIRE_TRUE(rangesEqual(expectedBytes, actualBytes));
        const auto& host = owner->get();
        expect_tensor_equal(expected, host);
        LOGVOLE_REQUIRE_TRUE(&owner->get() == &host);
        auto mutableCopy = host;
        mutableCopy.mPolys.front().mCoeffs.front() ^= 1;
        LOGVOLE_REQUIRE_EQ(owner->get().mPolys.front().mCoeffs.front(),
            expected.mPolys.front().mCoeffs.front());
        LOGVOLE_REQUIRE_TRUE(owner->copyCoefficientsTo(actualBytes));
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

    void check_enc1_serial_reference(const RingParams& ring, std::uint32_t cols, std::uint32_t gadgetBits = 20)
    {
        ScopedEnvironmentValue residentDefault("LV_GPU_SETUP_GAUSSIAN_RESIDENT", "0");
        ScopedEnvironmentValue extraDownload("LV_GPU_SETUP_EXTRA_PIPELINED_DOWNLOAD", "1");
        ScopedEnvironmentValue reuseDownloadWorkers("LV_GPU_SETUP_DOWNLOAD_REUSE_WORKERS", "1");
#if defined(ENABLE_LOGVOLE_CUDA)
        const bool haveGpu = gpu::enabled();
        const bool haveGaussian = haveGpu && gpu::gaussianTransformHostCompatible();
#else
        const bool haveGpu = false;
        const bool haveGaussian = false;
#endif
        RingNttContext ctx{};
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(ring, ctx));
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
#if defined(ENABLE_LOGVOLE_CUDA)
                ScopedGpuEnabled cpuReference(false);
#endif
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
                    ScopedEnvironmentValue forced("LV_GPU_SETUP_LHE_DEVICE_FORCE_DECLINE", "1");
                    const auto* storage = aliasedR.data();
                    LOGVOLE_REQUIRE_FALSE(gpu::assembleLheCiphertextDevice(ctx,
                        aliasedR, sk, publicA, gadgetBits, false, 0u, aliasedR));
                    LOGVOLE_REQUIRE_TRUE(aliasedR.data() == storage);
                    LOGVOLE_REQUIRE_TRUE(batches_equal(aliasedR, r));
                }
                ScopedEnvironmentValue enabled("LV_GPU_SETUP_LHE_DEVICE_FORCE_DECLINE", "0");
                LOGVOLE_REQUIRE_TRUE(gpu::assembleLheCiphertextDevice(ctx,
                    aliasedR, sk, publicA, gadgetBits, false, 0u, aliasedR));
                LOGVOLE_REQUIRE_TRUE(batches_equal(aliasedR, expected.mPolys));
            }
#endif
            if (haveGpu)
            {
                ScopedEnvironmentValue resident("LV_GPU_SETUP_GAUSSIAN_RESIDENT", "1");
                // Unknown host arithmetic must exercise exact host replay; strict rejection is checked separately.
                ScopedEnvironmentValue residentStrict("LV_GPU_SETUP_GAUSSIAN_RESIDENT_STRICT", haveGaussian ? "1" : "0");
                ScopedEnvironmentValue residentDecline("LV_GPU_SETUP_GAUSSIAN_RESIDENT_FORCE_DECLINE", "0");
                ScopedEnvironmentValue transform("LV_GPU_SETUP_GAUSSIAN_TRANSFORM", "1");
                ScopedEnvironmentValue transformStrict("LV_GPU_SETUP_GAUSSIAN_TRANSFORM_STRICT", haveGaussian ? "1" : "0");
                ScopedEnvironmentValue transformDecline("LV_GPU_SETUP_GAUSSIAN_TRANSFORM_FORCE_DECLINE", "0");
                ScopedEnvironmentValue device("LV_GPU_SETUP_LHE_DEVICE", "1");
                ScopedEnvironmentValue deviceStrict("LV_GPU_SETUP_LHE_DEVICE_STRICT", "1");
                ScopedEnvironmentValue deviceDecline("LV_GPU_SETUP_LHE_DEVICE_FORCE_DECLINE", "0");
                ScopedEnvironmentValue compact("LV_GPU_SETUP_COMPACT_NOISE", "1");
                ScopedEnvironmentValue compactStrict("LV_GPU_SETUP_COMPACT_NOISE_STRICT", "1");
                auto invoke = [&](oc::PRNG& prng, RingTensor& out,
                                  std::shared_ptr<const LazyRingTensorHostState>* deferred = nullptr) {
                    return truncate
                        ? lheEnc1Trunc(ctx, r, sk, gadgetBits, out, sigma, 19.2, &prng, inputNtt, &publicA, 4, deferred)
                        : lheEnc1(ctx, r, sk, gadgetBits, out, sigma, 19.2, &prng, inputNtt, &publicA, 4, deferred);
                };
                for (const char* blocks : {"0", "1"})
                {
                    ScopedEnvironmentValue prefix("LV_GPU_SETUP_GAUSSIAN_TRANSFORM_PREFIX_BLOCKS", blocks);
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
                            -1.0, 19.2, &rejectedPrng, inputNtt, &publicA, 4, &owner));
                        LOGVOLE_REQUIRE_TRUE(owner == retained);
                        LOGVOLE_REQUIRE_TRUE(rejected.mPolys.data() == storage);
                        expect_tensor_equal(expected, rejected);
                        LOGVOLE_EXPECT_EQ(rejectedPrng.get<oc::block>(), untouchedPrng.get<oc::block>());

                        // With compact noise disabled, the device result needs
                        // host noise addition before it is a complete ciphertext.
                        // The explicit deferred request must therefore publish
                        // eager data and reset a previous owner.
                        {
                            ScopedEnvironmentValue eagerNoise("LV_GPU_SETUP_COMPACT_NOISE", "0");
                            oc::PRNG eagerPrng(oc::block(0x345678u, 0), 3);
                            LOGVOLE_REQUIRE_TRUE(invoke(eagerPrng, deferred, &owner));
                            LOGVOLE_REQUIRE_FALSE(owner);
                            expect_tensor_equal(expected, deferred);
                            LOGVOLE_EXPECT_EQ(eagerPrng.get<oc::block>(), nextReference);
                        }
                        deferred.mPolys.front().mCoeffs.front() ^= 1;
                        expect_tensor_equal(expected, retained->get());
                        {
                            ScopedEnvironmentValue eagerDevice("LV_GPU_SETUP_LHE_DEVICE", "0");
                            oc::PRNG eagerPrng(oc::block(0x345678u, 0), 3);
                            owner = retained;
                            LOGVOLE_REQUIRE_TRUE(invoke(eagerPrng, deferred, &owner));
                            LOGVOLE_REQUIRE_FALSE(owner);
                            expect_tensor_equal(expected, deferred);
                            LOGVOLE_EXPECT_EQ(eagerPrng.get<oc::block>(), nextReference);
                        }
                    }
                }
                ScopedEnvironmentValue decline("LV_GPU_SETUP_GAUSSIAN_RESIDENT_FORCE_DECLINE", "1");
                {
                    ScopedEnvironmentValue replay("LV_GPU_SETUP_GAUSSIAN_RESIDENT_STRICT", "0");
                    oc::PRNG replayPrng(oc::block(0x345678u, 0), 3);
                    RingTensor actual;
                    LOGVOLE_REQUIRE_TRUE(invoke(replayPrng, actual));
                    expect_tensor_equal(expected, actual);
                    LOGVOLE_EXPECT_EQ(replayPrng.get<oc::block>(), nextReference);
                }
                if (sigma > 0.0)
                {
                    ScopedEnvironmentValue requireResident("LV_GPU_SETUP_GAUSSIAN_RESIDENT_STRICT", "1");
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
                ScopedEnvironmentValue parallelOption("LV_GPU_SETUP_LHE", "1");
                ScopedEnvironmentValue deviceOption("LV_GPU_SETUP_LHE_DEVICE", deviceAssembly ? "1" : "0");
                ScopedEnvironmentValue strictOption("LV_GPU_SETUP_LHE_DEVICE_STRICT", "1");
                ScopedEnvironmentValue compactOption("LV_GPU_SETUP_COMPACT_NOISE", compactNoise ? "1" : "0");
                ScopedEnvironmentValue compactStrict("LV_GPU_SETUP_COMPACT_NOISE_STRICT", "1");
                ScopedEnvironmentValue forceOption("LV_GPU_SETUP_LHE_DEVICE_FORCE_DECLINE", "0");
#if defined(ENABLE_LOGVOLE_CUDA)
                if (deviceAssembly) LOGVOLE_REQUIRE_TRUE(gpu::enabled());
#endif
                oc::PRNG actualPrng(oc::block(0x345678u, 0), 3);
                RingTensor actual{};
                const bool ok = truncate
                    ? lheEnc1Trunc(ctx, r, sk, gadgetBits, actual, sigma, 19.2,
                        &actualPrng, inputNtt, &publicA, workers)
                    : lheEnc1(ctx, r, sk, gadgetBits, actual, sigma, 19.2,
                        &actualPrng, inputNtt, &publicA, workers);
                LOGVOLE_REQUIRE_TRUE(ok);
                expect_tensor_equal(expected, actual);
                LOGVOLE_EXPECT_EQ(actualPrng.get<oc::block>(), nextReference);
                LOGVOLE_REQUIRE_TRUE(batches_equal(r, originalR));
                LOGVOLE_REQUIRE_TRUE(batches_equal(sk, originalSk));
                LOGVOLE_REQUIRE_TRUE(batches_equal(publicA, originalA));
            }
            if (haveGpu)
            {
                ScopedEnvironmentValue deviceOption("LV_GPU_SETUP_LHE_DEVICE", "1");
                ScopedEnvironmentValue compactOption("LV_GPU_SETUP_COMPACT_NOISE", "1");
                ScopedEnvironmentValue deviceStrict("LV_GPU_SETUP_LHE_DEVICE_STRICT", "0");
                ScopedEnvironmentValue compactStrict("LV_GPU_SETUP_COMPACT_NOISE_STRICT", "0");
                ScopedEnvironmentValue forceOption("LV_GPU_SETUP_LHE_DEVICE_FORCE_DECLINE", "1");
                auto invoke = [&](oc::PRNG& prng, RingTensor& output, double clip) {
                    return truncate
                        ? lheEnc1Trunc(ctx, r, sk, gadgetBits, output, sigma, clip,
                            &prng, inputNtt, &publicA, 4)
                        : lheEnc1(ctx, r, sk, gadgetBits, output, sigma, clip,
                            &prng, inputNtt, &publicA, 4);
                };
                for (const char* parallel : { "0", "1" })
                {
                    ScopedEnvironmentValue parallelOption("LV_GPU_SETUP_LHE", parallel);
                    oc::PRNG fallbackPrng(oc::block(0x345678u, 0), 3);
                    RingTensor actual;
                    LOGVOLE_REQUIRE_TRUE(invoke(fallbackPrng, actual, 19.2));
                    expect_tensor_equal(expected, actual);
                    LOGVOLE_EXPECT_EQ(fallbackPrng.get<oc::block>(), nextReference);
                }
                {
                    ScopedEnvironmentValue strictOption("LV_GPU_SETUP_LHE_DEVICE_STRICT", "1");
                    oc::PRNG failedPrng(oc::block(0x345678u, 0), 3);
                    RingTensor failed;
                    failed.mRows = 0xBADu;
                    LOGVOLE_EXPECT_FALSE(invoke(failedPrng, failed, 19.2));
                    LOGVOLE_EXPECT_EQ(failed.mRows, 0xBADu);
                }
                if (sigma == 0.0)
                {
                    ScopedEnvironmentValue allowDevice("LV_GPU_SETUP_LHE_DEVICE_FORCE_DECLINE", "0");
                    const double ineligibleClip = std::nextafter(
                        static_cast<double>(ringModulusValue(ctx, 0) >> 1u),
                        std::numeric_limits<double>::infinity());
                    // Eligibility failure is checked before drawing seeds.
                    oc::PRNG rejectedPrng(oc::block(0x345678u, 0), 3);
                    RingTensor rejected;
                    rejected.mRows = 0xBADu;
                    {
                        ScopedEnvironmentValue strictCompact("LV_GPU_SETUP_COMPACT_NOISE_STRICT", "1");
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

void LogVole_LheOps_Enc1ShapeDeterminismAndColumnDecrypt(const oc::CLP&)
{
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

    // With LV_GPU_SETUP_LHE=1 these also exercise the parallel implementation
    // in CPU-only builds. GPU test runs exercise the batched device inverse.
#if defined(ENABLE_LOGVOLE_CUDA)
    ScopedGpuEnabled useGpu(true);
    if (const char* strict = std::getenv("LV_GPU_SETUP_LHE_DEVICE_STRICT"))
        if (strict[0] == '1') LOGVOLE_REQUIRE_TRUE(gpu::enabled());
#endif
    check_enc1_serial_reference(params.mRing, params.mTau);
    RingParams productionRing{};
    productionRing.mPolyModulusDegree = 8192;
    assignValues<int>(productionRing.mCoeffModulusBits, { 55, 55, 55, 55 });
    check_enc1_serial_reference(productionRing, 2, 110);
    productionRing.mPolyModulusDegree = 16384;
    assignValues<int>(productionRing.mCoeffModulusBits, { 52, 52, 52, 52, 52, 52, 52, 52 });
    check_enc1_serial_reference(productionRing, 2, 208);
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

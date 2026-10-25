#include "libOTe/Vole/LogVole/LogVoleRing.h"
#include "libOTe/Vole/LogVole/LogVoleLenc.h"
#include "libOTe/Vole/LogVole/LogVoleLhe.h"
#include "libOTe/Vole/LogVole/LogVoleRuntime.h"
#include "libOTe/Vole/LogVole/LogVoleParallel.h"
#include "libOTe/Vole/LogVole/LogVole.h"
#include "libOTe/config.h"
#if defined(ENABLE_LOGVOLE_CUDA)
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuGaussian.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuBackend.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuKernels.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuProtocol.h"
#endif

#include "libOTe_Tests/LogVole_TestUtil.h"
#include "cryptoTools/Common/CLP.h"
#include "seal/util/ntt.h"
#include "seal/util/rns.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cfenv>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <future>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
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

    void swap_moduli_for_test(RingNttContext& ctx, std::size_t first, std::size_t second)
    {
        if (ctx.mGpuLightweight)
        {
            auto changed = std::make_shared<RingModulusMetadata>(*ctx.mRawModuli);
            std::swap(changed->mValues[first], changed->mValues[second]);
            std::swap(changed->mBitCounts[first], changed->mBitCounts[second]);
            ctx.mRawModuli = std::move(changed);
        }
        else std::swap(ctx.mModuli[first], ctx.mModuli[second]);
    }

    RingParams make_small_params()
    {
        RingParams params{};
        params.mPolyModulusDegree = 1024;
        assignValues<int>(params.mCoeffModulusBits, { 30, 30 });
        return params;
    }

    RingParams make_four_limb_params()
    {
        RingParams params{};
        params.mPolyModulusDegree = 1024;
        assignValues<int>(params.mCoeffModulusBits, { 30, 30, 30, 30 });
        return params;
    }

    void expect_poly_equal(const RnsPoly& a, const RnsPoly& b)
    {
        LOGVOLE_REQUIRE_EQ(a.mCoeffs.size(), b.mCoeffs.size());
        for (std::size_t i = 0; i < a.mCoeffs.size(); ++i)
        {
            LOGVOLE_EXPECT_EQ(a.mCoeffs[i], b.mCoeffs[i]) << " coeff index " << i;
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

#if defined(ENABLE_LOGVOLE_CUDA)
    void expect_single_limb_batching_parity(const RingParams& ring, std::uint32_t plaintextBits)
    {
        ScopedEnvironmentValue minimalChain("LV_GPU_SETUP_FULL_MOD_CHAIN", "0");
        // This fixture deliberately compares two eager SEAL representations.
        ScopedEnvironmentValue eagerRing("LV_GPU_SETUP_LIGHTWEIGHT_RING", "0");
        ScopedEnvironmentValue eagerCrt("LV_GPU_SETUP_LIGHTWEIGHT_CRT", "0");
        ZpCrtContext reference, candidate;
        {
            ScopedEnvironmentValue originalBatching("LV_GPU_SETUP_BATCHING_SINGLE_LIMB", "0");
            LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(ring, plaintextBits, reference));
        }
        {
            ScopedEnvironmentValue compactBatching("LV_GPU_SETUP_BATCHING_SINGLE_LIMB", "1");
            LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(ring, plaintextBits, candidate));
            ZpCrtContext again;
            LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(ring, plaintextBits, again));
            LOGVOLE_EXPECT_TRUE(again.mBatchingContext == candidate.mBatchingContext);
        }
        // Only the encoding helper changes. The cryptographic ring and full-Q
        // plaintext lift retain exactly the same cached objects and values.
        LOGVOLE_EXPECT_TRUE(reference.mRing.mContext == candidate.mRing.mContext);
        LOGVOLE_EXPECT_TRUE(reference.mBatchingContext != candidate.mBatchingContext);
        LOGVOLE_REQUIRE_EQ(ringModulusCount(candidate.mRing), ring.mCoeffModulusBits.size());
        LOGVOLE_REQUIRE_EQ(candidate.mBatchingContext->key_context_data()->parms().coeff_modulus().size(), 1u);
        LOGVOLE_REQUIRE_TRUE(candidate.mBatchingContext->parameters_set());
        LOGVOLE_REQUIRE_TRUE(candidate.mBatchingContext->first_context_data()->qualifiers().using_batching);
        LOGVOLE_EXPECT_EQ(reference.mPlaintextModulus, candidate.mPlaintextModulus);
        LOGVOLE_EXPECT_EQ(reference.mPlaintextModulusBits, candidate.mPlaintextModulusBits);
        LOGVOLE_REQUIRE_TRUE(rangesEqual(reference.mPlaintextLiftModQj, candidate.mPlaintextLiftModQj));
        const auto* fullTables = reference.mBatchingContext->first_context_data()->plain_ntt_tables();
        const auto* singleTables = candidate.mBatchingContext->first_context_data()->plain_ntt_tables();
        LOGVOLE_REQUIRE_TRUE(fullTables && singleTables);
        LOGVOLE_REQUIRE_EQ(fullTables->get_root(), singleTables->get_root());
        LOGVOLE_REQUIRE_EQ(fullTables->inv_degree_modulo().operand, singleTables->inv_degree_modulo().operand);
        LOGVOLE_REQUIRE_EQ(fullTables->inv_degree_modulo().quotient, singleTables->inv_degree_modulo().quotient);
        for (std::size_t i = 0; i < ring.mPolyModulusDegree; ++i)
        {
            const auto fullRoot = fullTables->get_from_root_powers(i);
            const auto singleRoot = singleTables->get_from_root_powers(i);
            const auto fullInverse = fullTables->get_from_inv_root_powers(i);
            const auto singleInverse = singleTables->get_from_inv_root_powers(i);
            LOGVOLE_REQUIRE_TRUE(fullRoot.operand == singleRoot.operand && fullRoot.quotient == singleRoot.quotient);
            LOGVOLE_REQUIRE_TRUE(fullInverse.operand == singleInverse.operand && fullInverse.quotient == singleInverse.quotient);
        }
        std::vector<std::uint64_t> labels(ring.mPolyModulusDegree - 3u);
        for (std::size_t i = 0; i < labels.size(); ++i)
            labels[i] = i % 3u ? i % reference.mPlaintextModulus : reference.mPlaintextModulus - 1u;
        seal::Plaintext fullPlain, singlePlain;
        reference.mBatchEncoder->encode(labels, fullPlain);
        candidate.mBatchEncoder->encode(labels, singlePlain);
        LOGVOLE_REQUIRE_EQ(fullPlain.coeff_count(), singlePlain.coeff_count());
        LOGVOLE_REQUIRE_TRUE(std::equal(fullPlain.data(), fullPlain.data() + fullPlain.coeff_count(), singlePlain.data()));
        std::vector<std::uint64_t> fullDecoded, singleDecoded;
        reference.mBatchEncoder->decode(fullPlain, fullDecoded);
        candidate.mBatchEncoder->decode(singlePlain, singleDecoded);
        LOGVOLE_REQUIRE_TRUE(fullDecoded == singleDecoded);
        auto expectedLabels = labels;
        expectedLabels.resize(ring.mPolyModulusDegree, 0u);
        LOGVOLE_REQUIRE_TRUE(singleDecoded == expectedLabels);
        for (bool scaleAndRound : {false, true})
        {
            RnsPoly fullEncoded, singleEncoded;
            LOGVOLE_REQUIRE_TRUE(wrapZpBatchCrt(reference, labels, scaleAndRound, 7u, 1u, fullEncoded));
            LOGVOLE_REQUIRE_TRUE(wrapZpBatchCrt(candidate, labels, scaleAndRound, 7u, 1u, singleEncoded));
            expect_poly_equal(fullEncoded, singleEncoded);
            AlignedUnVec<std::uint64_t> fullUnwrapped, singleUnwrapped;
            // Force the CPU CRT/decode path here. GPU plaintext tables have
            // already been checked word for word, without its shared cache.
            ScopedGpuEnabled cpuDecode(false);
            LOGVOLE_REQUIRE_TRUE(unwrapRingLabelsCrt(reference, {fullEncoded}, labels.size(), scaleAndRound, 1u, fullUnwrapped));
            LOGVOLE_REQUIRE_TRUE(unwrapRingLabelsCrt(candidate, {singleEncoded}, labels.size(), scaleAndRound, 1u, singleUnwrapped));
            LOGVOLE_REQUIRE_TRUE(rangesEqual(fullUnwrapped, singleUnwrapped));
            // A toy one-limb ring can have Q/p too small for exact rounded
            // recovery, independently of the batching helper. Production
            // multi-limb rings retain the original exact round trip.
            if (!scaleAndRound || ring.mCoeffModulusBits.size() > 1u)
                LOGVOLE_REQUIRE_TRUE(rangesEqual(singleUnwrapped, labels));
        }
    }
#endif
}

void LogVole_RingOps_ScalarUploadLifetimeAndRoleSwitch(const oc::CLP& cmd)
{
#if defined(ENABLE_LOGVOLE_CUDA)
    const bool requested = cmd.getOr("gpu", 0) != 0;
    ScopedGpuEnabled gpuScope(requested);
    if (requested) LOGVOLE_REQUIRE_TRUE(gpu::enabled());
    if (!gpu::enabled()) { LOGVOLE_SKIP() << "requires -gpu 1"; return; }
    const std::vector<std::uint64_t> input{1, 2, 3, 0xffffffffffffffffull};
    // The future joins its worker before the token is consumed. A completed
    // upload must remain usable after that thread's CUDA stream is destroyed.
    auto worker = std::async(std::launch::async, [&] { return gpu::uploadScalars(input); });
    auto uploaded = worker.get();
    LOGVOLE_REQUIRE_TRUE(uploaded);
    LOGVOLE_REQUIRE_TRUE(uploaded->producerStream() == nullptr);
    std::vector<std::uint64_t> fetched(input.size());
    LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(*uploaded, fetched));
    LOGVOLE_REQUIRE_TRUE(fetched == input);

    const auto runId = allocateProtocolCacheRunId();
    // Warm both role streams, then hand cached storage from one role to the
    // next while its last device write may still be pending.
    for (auto role : {ProtocolCacheRole::Sender, ProtocolCacheRole::Receiver})
    {
        ScopedProtocolCacheScope scope(role, runId);
        (void)gpu::threadStream();
    }
    std::vector<std::uint64_t> expected(1u << 18, 0x9e3779b97f4a7c15ull);
    for (unsigned iteration = 0; iteration < 8; ++iteration)
    {
        void* previous = nullptr;
        {
            ScopedProtocolCacheScope scope(ProtocolCacheRole::Sender, runId);
            auto& stream = gpu::threadStream();
            previous = stream.raw();
            gpu::DeviceScalars retired;
            LOGVOLE_REQUIRE_TRUE(retired.resize(expected.size()));
            LOGVOLE_REQUIRE_TRUE(gpu::gpuMemsetZero(retired.data(),
                expected.size() * sizeof(std::uint64_t), stream.raw()));
        }
        {
            ScopedProtocolCacheScope scope(ProtocolCacheRole::Receiver, runId);
            uploaded = gpu::uploadScalars(expected);
            LOGVOLE_REQUIRE_TRUE(uploaded);
            LOGVOLE_REQUIRE_TRUE(gpu::gpuCurrentStream() == gpu::threadStream().raw());
            LOGVOLE_REQUIRE_TRUE(gpu::gpuStreamSync(previous));
            fetched.resize(expected.size());
            LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(*uploaded, fetched));
            LOGVOLE_REQUIRE_TRUE(fetched == expected);
        }
    }
#else
    (void)cmd;
    LOGVOLE_SKIP() << "requires ENABLE_LOGVOLE_CUDA";
#endif
}

void LogVole_RingOps_PartyCachesDoNotAlias(const oc::CLP&)
{
    RingNttContext senderCtx{}, receiverCtx{};
    constexpr std::uint32_t count = 4;
    const std::uint64_t runId = allocateProtocolCacheRunId();

    std::shared_ptr<const std::vector<RnsPoly>> senderA, senderB;
    std::shared_ptr<const std::vector<RnsPoly>> receiverA, receiverB;
#if defined(ENABLE_LOGVOLE_CUDA)
    std::shared_ptr<gpu::GpuRing> senderRing, receiverRing;
#endif
    {
        ScopedProtocolCacheScope scope(ProtocolCacheRole::Sender, runId);
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(make_small_params(), senderCtx));
        senderA = sharedLhePublicANtt(senderCtx, count);
        senderB = sharedLencPublicBNtt(senderCtx, count / 2);
#if defined(ENABLE_LOGVOLE_CUDA)
        if (gpu::enabled()) senderRing = gpu::GpuRing::get(senderCtx);
#endif
    }
    {
        ScopedProtocolCacheScope scope(ProtocolCacheRole::Receiver, runId);
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(make_small_params(), receiverCtx));
        receiverA = sharedLhePublicANtt(receiverCtx, count);
        receiverB = sharedLencPublicBNtt(receiverCtx, count / 2);
#if defined(ENABLE_LOGVOLE_CUDA)
        if (gpu::enabled()) receiverRing = gpu::GpuRing::get(receiverCtx);
#endif
    }

    LOGVOLE_REQUIRE_TRUE(senderA && senderB && receiverA && receiverB);
    LOGVOLE_EXPECT_TRUE(senderCtx.mContext != receiverCtx.mContext);
    LOGVOLE_EXPECT_TRUE(senderA != receiverA);
    LOGVOLE_EXPECT_TRUE(senderB != receiverB);
    expect_batch_equal(*senderA, *receiverA);
    expect_batch_equal(*senderB, *receiverB);
#if defined(ENABLE_LOGVOLE_CUDA)
    if (gpu::enabled())
    {
        LOGVOLE_REQUIRE_TRUE(senderRing && receiverRing);
        LOGVOLE_EXPECT_TRUE(senderRing != receiverRing);
    }
#endif
}

void LogVole_RingOps_LightweightProductionContexts(const oc::CLP& cmd)
{
    const bool requestGpu = cmd.getOr("gpu", 0) != 0;
#if defined(ENABLE_LOGVOLE_CUDA)
    ScopedGpuEnabled gpuScope(requestGpu);
    if (requestGpu) LOGVOLE_REQUIRE_TRUE(gpu::enabled());
#else
    (void)requestGpu;
#endif
    ScopedEnvironmentValue lightweightRing("LV_GPU_SETUP_LIGHTWEIGHT_RING", "1");
    ScopedEnvironmentValue lightweightCrt("LV_GPU_SETUP_LIGHTWEIGHT_CRT", "1");
    ScopedEnvironmentValue minimalChain("LV_GPU_SETUP_FULL_MOD_CHAIN", "0");
    ScopedEnvironmentValue singleBatchLimb("LV_GPU_SETUP_BATCHING_SINGLE_LIMB", "1");
    struct Preset
    {
        std::uint32_t degree, bits;
        std::uint64_t plaintext;
        std::vector<std::uint64_t> primes, roots, lift;
    };
    // Independently extracted with the installed SEAL 4.1.1 CoeffModulus,
    // PlainModulus, NTTTables and RNSBase; preserve their exact limb order.
    const std::array<Preset, 2> presets{{
        {8192u, 55u, 18014398508400641ULL,
            {36028797017276417ULL, 36028797017456641ULL, 36028797017571329ULL, 36028797018652673ULL},
            {2122358902623ULL, 4991203289951ULL, 3055459936772ULL, 15372713853695ULL},
            {31167066492716324ULL, 21694619169948978ULL, 65560066590007ULL, 11186266514113866ULL}},
        {16384u, 52u, 2251799813554177ULL,
            {4503599623864321ULL, 4503599624716289ULL, 4503599624847361ULL, 4503599625404417ULL,
             4503599625535489ULL, 4503599625830401ULL, 4503599626321921ULL, 4503599626682369ULL},
            {62875005116ULL, 628540673523ULL, 20953053066ULL, 77888184398ULL,
             373971078837ULL, 439212745275ULL, 92204214445ULL, 186470750825ULL},
            {4387753181945957ULL, 2958736519422233ULL, 4311407244373363ULL, 2043635392656052ULL,
             3613420940470256ULL, 2606009313598ULL, 2340510748877534ULL, 2511146381739566ULL}}
    }};
    for (const auto& preset : presets)
    {
        RingParams params{};
        params.mPolyModulusDegree = preset.degree;
        params.mCoeffModulusBits.resize(preset.primes.size());
        std::fill(params.mCoeffModulusBits.begin(), params.mCoeffModulusBits.end(), preset.bits);
        const auto run = allocateProtocolCacheRunId();
        std::array<RingNttContext, 2> lightweight;
        std::array<ZpCrtContext, 2> crt;
        std::array<bool, 2> roleGpu{};
#if defined(ENABLE_LOGVOLE_CUDA)
        std::array<std::shared_ptr<gpu::GpuRing>, 2> deviceRings;
#endif
        for (std::size_t party = 0; party < 2; ++party)
        {
            ScopedProtocolCacheScope roleScope(
                party ? ProtocolCacheRole::Receiver : ProtocolCacheRole::Sender, run);
#if defined(ENABLE_LOGVOLE_CUDA)
            roleGpu[party] = gpu::enabled();
#endif
            auto& context = lightweight[party];
            LOGVOLE_REQUIRE_TRUE(makeGpuRingNttContext(params, context));
            LOGVOLE_REQUIRE_TRUE(context.mGpuLightweight && context.mHostContextCache && !context.mContext);
            LOGVOLE_REQUIRE_TRUE(context.mModuli.empty() && context.mRawModuli);
            LOGVOLE_REQUIRE_TRUE(validateRingContextMetadata(context));
            RingNttContext again;
            LOGVOLE_REQUIRE_TRUE(makeGpuRingNttContext(params, again));
            LOGVOLE_EXPECT_TRUE(again.mHostContextCache == context.mHostContextCache);
            LOGVOLE_EXPECT_TRUE(again.mRawModuli == context.mRawModuli);
            LOGVOLE_REQUIRE_EQ(ringModulusCount(context), preset.primes.size());
            for (std::size_t limb = 0; limb < preset.primes.size(); ++limb)
            {
                LOGVOLE_EXPECT_EQ(ringModulusValue(context, limb), preset.primes[limb]);
                LOGVOLE_EXPECT_EQ(ringModulusBitCount(context, limb), static_cast<int>(preset.bits));
            }

            RingNttContext selected;
            LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, selected));
            LOGVOLE_EXPECT_EQ(selected.mGpuLightweight, roleGpu[party]);
            LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(params, preset.bits, crt[party]));
            LOGVOLE_EXPECT_EQ(crt[party].mGpuLightweight, roleGpu[party]);
            LOGVOLE_EXPECT_EQ(crt[party].mPlaintextModulus, preset.plaintext);
            LOGVOLE_EXPECT_EQ(crt[party].mPlaintextModulusBits, preset.bits - 1u);
            LOGVOLE_REQUIRE_TRUE(rangesEqual(crt[party].mPlaintextLiftModQj, preset.lift));
            if (roleGpu[party])
            {
                LOGVOLE_REQUIRE_TRUE(!crt[party].mBatchingContext && !crt[party].mBatchEncoder);
                LOGVOLE_REQUIRE_TRUE(crt[party].mHostContextCache != nullptr);
#if defined(ENABLE_LOGVOLE_CUDA)
                deviceRings[party] = gpu::GpuRing::get(context);
                LOGVOLE_REQUIRE_TRUE(deviceRings[party] != nullptr);
                LOGVOLE_REQUIRE_TRUE(deviceRings[party]->hostModuli() == preset.primes);
                LOGVOLE_REQUIRE_TRUE(deviceRings[party]->view().mRoots != nullptr);
                LOGVOLE_REQUIRE_TRUE(deviceRings[party]->view().mInvRoots != nullptr);
#endif
                for (const char* option : {"LV_GPU_SETUP_LIGHTWEIGHT_RING", "LV_GPU_SETUP_LIGHTWEIGHT_CRT"})
                {
                    ScopedEnvironmentValue optOut(option, "0");
                    ZpCrtContext eager;
                    LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(params, preset.bits, eager));
                    LOGVOLE_REQUIRE_TRUE(!eager.mGpuLightweight && eager.mBatchingContext && eager.mBatchEncoder);
                    LOGVOLE_EXPECT_EQ(eager.mPlaintextModulus, preset.plaintext);
                    LOGVOLE_REQUIRE_TRUE(rangesEqual(eager.mPlaintextLiftModQj, preset.lift));
                    if (std::strcmp(option, "LV_GPU_SETUP_LIGHTWEIGHT_RING") == 0)
                    {
                        RingNttContext eagerRing;
                        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, eagerRing));
                        LOGVOLE_REQUIRE_TRUE(!eagerRing.mGpuLightweight && eagerRing.mContext);
                    }
                }
                ZpCrtContext restored;
                LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(params, preset.bits, restored));
                LOGVOLE_REQUIRE_TRUE(restored.mGpuLightweight);
                LOGVOLE_EXPECT_TRUE(restored.mHostContextCache == crt[party].mHostContextCache);
            }
        }
        LOGVOLE_EXPECT_TRUE(lightweight[0].mHostContextCache != lightweight[1].mHostContextCache);
        LOGVOLE_EXPECT_TRUE(lightweight[0].mRawModuli != lightweight[1].mRawModuli);
        if (roleGpu[0] && roleGpu[1])
        {
            LOGVOLE_EXPECT_TRUE(crt[0].mHostContextCache != crt[1].mHostContextCache);
#if defined(ENABLE_LOGVOLE_CUDA)
            LOGVOLE_EXPECT_TRUE(deviceRings[0] != deviceRings[1]);
            LOGVOLE_EXPECT_TRUE(deviceRings[0]->view().mRoots != deviceRings[1]->view().mRoots);
#endif
        }

        // A declined metadata factory must not consume or replace the caller's owner.
        auto unsupported = params;
        unsupported.mPolyModulusDegree = 262144u;
        auto unchanged = lightweight[0];
        LOGVOLE_REQUIRE_FALSE(makeGpuRingNttContext(unsupported, unchanged));
        LOGVOLE_EXPECT_TRUE(unchanged.mHostContextCache == lightweight[0].mHostContextCache);
        LOGVOLE_EXPECT_TRUE(unchanged.mParams == params && unchanged.mGpuLightweight && !unchanged.mContext);
        for (std::size_t limb = 0; limb < preset.primes.size(); ++limb)
            LOGVOLE_EXPECT_EQ(ringModulusValue(unchanged, limb), preset.primes[limb]);

        // Explicit CPU oracles stay on the host even in the GPU test invocation.
#if defined(ENABLE_LOGVOLE_CUDA)
        ScopedGpuEnabled cpuOracle(false);
#endif
        RingNttContext eager;
        ZpCrtContext eagerCrt;
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, eager));
        LOGVOLE_REQUIRE_TRUE(!eager.mGpuLightweight && eager.mContext);
        LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(params, preset.bits, eagerCrt));
        LOGVOLE_EXPECT_EQ(eagerCrt.mPlaintextModulus, preset.plaintext);
        LOGVOLE_REQUIRE_TRUE(rangesEqual(eagerCrt.mPlaintextLiftModQj, preset.lift));
        // Concurrent copies resolve to a single immutable host fallback owner.
        std::array<std::future<std::shared_ptr<seal::SEALContext>>, 4> readers;
        for (auto& reader : readers)
            reader = std::async(std::launch::async, [context = lightweight[0]] {
                return getRingHostContext(context);
            });
        const auto senderHost = readers[0].get();
        for (std::size_t reader = 1; reader < readers.size(); ++reader)
            LOGVOLE_REQUIRE_TRUE(readers[reader].get() == senderHost);
        const auto receiverHost = getRingHostContext(lightweight[1]);
        LOGVOLE_REQUIRE_TRUE(senderHost && receiverHost && senderHost != receiverHost);
        const auto copied = lightweight[0];
        LOGVOLE_EXPECT_TRUE(getRingHostContext(copied) == senderHost);
        LOGVOLE_EXPECT_TRUE(!lightweight[0].mContext && !lightweight[1].mContext);
        LOGVOLE_EXPECT_TRUE(lightweight[0].mModuli.empty() && lightweight[1].mModuli.empty());
        const auto& hostModuli = getRingHostModuli(lightweight[0]);
        LOGVOLE_REQUIRE_TRUE(hostModuli == eager.mModuli);
        LOGVOLE_EXPECT_TRUE(&getRingHostModuli(copied) == &hostModuli);
        LOGVOLE_REQUIRE_TRUE(senderHost->key_parms_id() == eager.mContext->key_parms_id());
        const auto* tables = senderHost->key_context_data()->small_ntt_tables();
        for (std::size_t limb = 0; limb < preset.roots.size(); ++limb)
            LOGVOLE_EXPECT_EQ(tables[limb].get_root(), preset.roots[limb]);

        if (preset.degree == 8192u)
        {
            CivoleParams production;
            LOGVOLE_REQUIRE_TRUE(makeCivoleParams(CivoleSetting::GoldenSeed, production, 4u));
            LOGVOLE_REQUIRE_TRUE(production.mLogVole.mShrinkExpand.mRing == params);
            production.mLogVole.mW = (std::uint64_t{1} << 25) / params.mPolyModulusDegree;
            production.mLogVole.mTotalLabelCount = std::uint64_t{1} << 25;
            std::vector<std::uint64_t> expectedLo, expectedHi, lightweightLo, lightweightHi;
            LOGVOLE_REQUIRE_TRUE(goldenSeedRoundingMargins(
                production.mLogVole, eager, expectedLo, expectedHi));
            LOGVOLE_REQUIRE_TRUE(goldenSeedRoundingMargins(
                production.mLogVole, lightweight[0], lightweightLo, lightweightHi));
            LOGVOLE_REQUIRE_TRUE(expectedLo == lightweightLo);
            LOGVOLE_REQUIRE_TRUE(expectedHi == lightweightHi);
        }

        osuCrypto::PRNG expectedPrng(osuCrypto::block(0x5345414cu, preset.degree));
        osuCrypto::PRNG actualPrng(osuCrypto::block(0x5345414cu, preset.degree));
        auto expected = sampleUniformPoly(eager, expectedPrng);
        auto actual = sampleUniformPoly(lightweight[0], actualPrng);
        expect_poly_equal(actual, expected);
        LOGVOLE_EXPECT_EQ(actualPrng.get<std::uint64_t>(), expectedPrng.get<std::uint64_t>());
        LOGVOLE_REQUIRE_TRUE(addPolyError(expected, 3.2, 36.0, expectedPrng, eager));
        LOGVOLE_REQUIRE_TRUE(addPolyError(actual, 3.2, 36.0, actualPrng, lightweight[0]));
        expect_poly_equal(actual, expected);
        LOGVOLE_EXPECT_EQ(actualPrng.get<std::uint64_t>(), expectedPrng.get<std::uint64_t>());
        LOGVOLE_REQUIRE_TRUE(forwardNtt(expected, eager));
        LOGVOLE_REQUIRE_TRUE(forwardNtt(actual, lightweight[0]));
        expect_poly_equal(actual, expected);
        LOGVOLE_REQUIRE_TRUE(inverseNtt(expected, eager));
        LOGVOLE_REQUIRE_TRUE(inverseNtt(actual, lightweight[0]));
        expect_poly_equal(actual, expected);

        for (unsigned corruption = 0; corruption < 5; ++corruption)
        {
            auto malformed = lightweight[0];
            if (corruption == 0) malformed.mHostContextCache.reset();
            if (corruption == 1)
            {
                auto changed = std::make_shared<RingModulusMetadata>(*malformed.mRawModuli);
                changed->mValues[0] = changed->mValues[1];
                malformed.mRawModuli = std::move(changed);
            }
            if (corruption == 2) --malformed.mParams.mCoeffModulusBits[0];
            if (corruption == 3) malformed.mRawModuli.reset();
            if (corruption == 4)
            {
                auto changed = std::make_shared<RingModulusMetadata>(*malformed.mRawModuli);
                --changed->mBitCounts[0];
                malformed.mRawModuli = std::move(changed);
            }
            LOGVOLE_REQUIRE_TRUE(getRingHostContext(malformed) == nullptr);
            LOGVOLE_REQUIRE_TRUE(getRingHostModuli(malformed).empty());
            std::vector<RnsPoly> batch{actual};
            LOGVOLE_REQUIRE_FALSE(forwardNttBatch(batch, malformed));
            LOGVOLE_REQUIRE_FALSE(inverseNttBatch(batch, malformed));
            expect_poly_equal(batch[0], actual);
        }

        if (preset.degree == 8192u)
        {
            CivoleParams production;
            LOGVOLE_REQUIRE_TRUE(makeCivoleParams(CivoleSetting::GoldenSeed, production, 4u));
            production.mLogVole.mW = (std::uint64_t{1} << 25) / params.mPolyModulusDegree;
            production.mLogVole.mTotalLabelCount = std::uint64_t{1} << 25;
            auto malformed = lightweight[0];
            auto changed = std::make_shared<RingModulusMetadata>(*malformed.mRawModuli);
            changed->mValues[0] = changed->mValues[1];
            malformed.mRawModuli = std::move(changed);
            std::vector<std::uint64_t> lo{17}, hi{23};
            LOGVOLE_REQUIRE_FALSE(goldenSeedRoundingMargins(production.mLogVole, malformed, lo, hi));
            LOGVOLE_REQUIRE_TRUE(lo == std::vector<std::uint64_t>{17});
            LOGVOLE_REQUIRE_TRUE(hi == std::vector<std::uint64_t>{23});
        }

        const std::vector<std::uint64_t> labels{0u, 1u, preset.plaintext - 1u, 7u};
        for (bool scaled : {false, true})
        {
            RnsPoly reference;
            LOGVOLE_REQUIRE_TRUE(wrapZpBatchCrt(eagerCrt, labels, scaled, 0u, 1u, reference));
            AlignedUnVec<std::uint64_t> expectedDecoded;
#if defined(ENABLE_LOGVOLE_CUDA)
            {
                ScopedGpuEnabled cpuOracle(false);
                LOGVOLE_REQUIRE_TRUE(unwrapRingLabelsCrt(
                    eagerCrt, {reference}, labels.size(), scaled, 1u,
                    expectedDecoded));
            }
#else
            LOGVOLE_REQUIRE_TRUE(unwrapRingLabelsCrt(
                eagerCrt, {reference}, labels.size(), scaled, 1u,
                expectedDecoded));
#endif
            for (const auto& candidate : crt)
            {
                RnsPoly encoded;
                LOGVOLE_REQUIRE_TRUE(wrapZpBatchCrt(candidate, labels, scaled, 0u, 1u, encoded));
                expect_poly_equal(encoded, reference);
                AlignedUnVec<std::uint64_t> decoded;
                LOGVOLE_REQUIRE_TRUE(unwrapRingLabelsCrt(candidate, {encoded}, labels.size(), scaled, 1u, decoded));
                LOGVOLE_REQUIRE_TRUE(rangesEqual(decoded, labels));
                LOGVOLE_REQUIRE_TRUE(rangesEqual(decoded, expectedDecoded));
                if (candidate.mGpuLightweight)
                    LOGVOLE_EXPECT_TRUE(!candidate.mBatchingContext && !candidate.mBatchEncoder && !candidate.mRing.mContext);
            }
        }
        {
            // Public input may be a shape-valid polynomial whose residues
            // were not canonicalized yet. SEAL reduces each q limb before
            // CRT compose; the device path must do the same without changing
            // its caller's host polynomial.
            RnsPoly raw;
            LOGVOLE_REQUIRE_TRUE(wrapZpBatchCrt(
                eagerCrt, labels, false, 0u, 1u, raw));
            for (std::size_t limb = 0; limb < preset.primes.size(); ++limb)
            {
                const auto offset = limb * static_cast<std::size_t>(preset.degree);
                raw.mCoeffs[offset] += preset.primes[limb];
            }
            AlignedUnVec<std::uint64_t> expected;
            LOGVOLE_REQUIRE_TRUE(unwrapRingLabelsCrt(
                eagerCrt, {raw}, labels.size(), false, 1u, expected));
            for (const auto& candidate : crt)
            {
                AlignedUnVec<std::uint64_t> actual;
                LOGVOLE_REQUIRE_TRUE(unwrapRingLabelsCrt(
                    candidate, {raw}, labels.size(), false, 1u, actual));
                LOGVOLE_REQUIRE_TRUE(rangesEqual(actual, expected));
            }
        }
        if (crt[0].mGpuLightweight)
        {
            // A copied lightweight context must not bypass metadata or owner
            // validation through the warm device table cache.
            RnsPoly validEncoded;
            LOGVOLE_REQUIRE_TRUE(wrapZpBatchCrt(
                eagerCrt, labels, false, 0u, 1u, validEncoded));
            for (unsigned corruption = 0; corruption < 5; ++corruption)
            {
                auto malformed = crt[0];
                if (corruption == 0) --malformed.mPlaintextModulus;
                if (corruption == 1) ++malformed.mPlaintextLiftModQj[0];
                if (corruption == 2) swap_moduli_for_test(malformed.mRing, 0, 1);
                if (corruption == 3) malformed.mRing.mHostContextCache = crt[1].mRing.mHostContextCache;
                if (corruption == 4) --malformed.mPlaintextModulusBits;
                RnsPoly encoded;
                encoded.mCoeffs = {0xdecafbadULL};
                LOGVOLE_REQUIRE_FALSE(wrapZpBatchCrt(
                    malformed, labels, false, 0u, 1u, encoded))
                    << " corruption " << corruption;
                AlignedUnVec<std::uint64_t> unchanged;
                assignValues<std::uint64_t>(unchanged,
                    {0xdecafbadULL, 0x12345678ULL});
                LOGVOLE_REQUIRE_FALSE(unwrapRingLabelsCrt(
                    malformed, {validEncoded}, labels.size(), false, 1u,
                    unchanged)) << " corruption " << corruption;
                LOGVOLE_REQUIRE_TRUE(rangesEqual(unchanged,
                    std::vector<std::uint64_t>{0xdecafbadULL, 0x12345678ULL}));
            }
        }
    }

#if defined(ENABLE_LOGVOLE_CUDA)
    if (gpu::enabled())
    {
        // The production constants above remain the fast path. These tuples
        // force exact dynamic prime selection, mixed-width ordering, device
        // CRT/plaintext setup and a separate role-local raw-ring certificate.
        const std::array<std::pair<std::uint32_t, std::vector<int>>, 3> dynamicCases{{
            {1024u, {30, 30}}, {2048u, {30, 31, 30}},
            {65536u, {30, 31, 30, 31, 30, 31, 30, 31, 30}}
        }};
        for (const auto& [degree, widths] : dynamicCases)
        {
            RingParams params{};
            params.mPolyModulusDegree = degree;
            params.mCoeffModulusBits.resize(widths.size());
            std::copy(widths.begin(), widths.end(), params.mCoeffModulusBits.begin());
            const auto expectedPrimes = seal::CoeffModulus::Create(degree, widths);
            const auto run = allocateProtocolCacheRunId();
            std::array<RingNttContext, 2> dynamicRing;
            std::array<ZpCrtContext, 2> dynamicCrt;
            std::array<std::shared_ptr<gpu::GpuPlainNtt>, 2> plainOwners;
            for (std::size_t party = 0; party < 2; ++party)
            {
                ScopedProtocolCacheScope roleScope(
                    party ? ProtocolCacheRole::Receiver : ProtocolCacheRole::Sender, run);
                LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, dynamicRing[party]));
                const auto& selected = dynamicRing[party];
                LOGVOLE_REQUIRE_TRUE(selected.mGpuLightweight && selected.mRawModuli &&
                    selected.mRawModuli->mDynamicGpuCertificate && !selected.mContext);
                LOGVOLE_REQUIRE_TRUE(validateRingContextMetadata(selected));
                LOGVOLE_REQUIRE_EQ(ringModulusCount(selected), widths.size());
                for (std::size_t limb = 0; limb < widths.size(); ++limb)
                    LOGVOLE_EXPECT_EQ(ringModulusValue(selected, limb), expectedPrimes[limb].value());
                LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(params, 30u, dynamicCrt[party]));
                LOGVOLE_REQUIRE_TRUE(dynamicCrt[party].mGpuLightweight &&
                    !dynamicCrt[party].mBatchingContext && !dynamicCrt[party].mBatchEncoder);
                const auto certificate = selected.mRawModuli->mDynamicGpuCertificate;
                LOGVOLE_REQUIRE_TRUE(gpu::GpuRing::get(selected) == certificate);

                ZpCrtContext eager;
                {
                    ScopedEnvironmentValue eagerRing("LV_GPU_SETUP_LIGHTWEIGHT_RING", "0");
                    ScopedEnvironmentValue eagerCrt("LV_GPU_SETUP_LIGHTWEIGHT_CRT", "0");
                    LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(params, 30u, eager));
                }
                LOGVOLE_REQUIRE_TRUE(!eager.mGpuLightweight && eager.mBatchEncoder);
                LOGVOLE_EXPECT_EQ(dynamicCrt[party].mPlaintextModulus, eager.mPlaintextModulus);
                LOGVOLE_EXPECT_EQ(dynamicCrt[party].mPlaintextModulusBits, eager.mPlaintextModulusBits);
                LOGVOLE_REQUIRE_TRUE(rangesEqual(
                    dynamicCrt[party].mPlaintextLiftModQj, eager.mPlaintextLiftModQj));
                plainOwners[party] = gpu::GpuPlainNtt::getRaw(degree, eager.mPlaintextModulus);
                LOGVOLE_REQUIRE_TRUE(plainOwners[party] && plainOwners[party]->slotCount() == degree);
                const auto lazyHost = getRingHostContext(selected);
                LOGVOLE_REQUIRE_TRUE(lazyHost &&
                    lazyHost->key_context_data()->parms().coeff_modulus() == expectedPrimes);

                const auto* sealTables = lazyHost->key_context_data()->small_ntt_tables();
                std::vector<gpu::HostShoupOperand> roots(static_cast<std::size_t>(degree) * widths.size());
                std::vector<gpu::HostShoupOperand> inverse(roots.size());
                auto& stream = gpu::threadStream();
                LOGVOLE_REQUIRE_TRUE(gpu::downloadToHost(roots.data(), certificate->view().mRoots,
                    roots.size() * sizeof(roots[0]), stream));
                LOGVOLE_REQUIRE_TRUE(gpu::downloadToHost(inverse.data(), certificate->view().mInvRoots,
                    inverse.size() * sizeof(inverse[0]), stream));
                for (std::size_t limb = 0; limb < widths.size(); ++limb)
                for (std::size_t i = 0; i < degree; ++i)
                {
                    const auto forward = sealTables[limb].get_from_root_powers(i);
                    const auto backward = sealTables[limb].get_from_inv_root_powers(i);
                    const auto offset = limb * degree + i;
                    LOGVOLE_EXPECT_EQ(roots[offset].mOperand, forward.operand);
                    LOGVOLE_EXPECT_EQ(roots[offset].mQuotient, forward.quotient);
                    LOGVOLE_EXPECT_EQ(inverse[offset].mOperand, backward.operand);
                    LOGVOLE_EXPECT_EQ(inverse[offset].mQuotient, backward.quotient);
                }

                // Compare the GPU's multiword CRT constants with SEAL's RNSBase,
                // including the ninth limb that formerly exceeded setup bounds.
                seal::util::RNSBase sealBase(expectedPrimes, seal::MemoryManager::GetPool());
                std::vector<std::uint64_t> baseProduct(widths.size());
                std::vector<std::uint64_t> punctured(widths.size() * widths.size());
                std::vector<gpu::HostShoupOperand> inversePunctured(widths.size());
                LOGVOLE_REQUIRE_TRUE(gpu::downloadToHost(baseProduct.data(),
                    certificate->view().mBaseProd, baseProduct.size() * sizeof(baseProduct[0]), stream));
                LOGVOLE_REQUIRE_TRUE(gpu::downloadToHost(punctured.data(),
                    certificate->view().mPuncturedProd, punctured.size() * sizeof(punctured[0]), stream));
                LOGVOLE_REQUIRE_TRUE(gpu::downloadToHost(inversePunctured.data(),
                    certificate->view().mInvPuncturedProd,
                    inversePunctured.size() * sizeof(inversePunctured[0]), stream));
                for (std::size_t i = 0; i < widths.size(); ++i)
                {
                    LOGVOLE_EXPECT_EQ(baseProduct[i], sealBase.base_prod()[i]);
                    const auto inverseOp = sealBase.inv_punctured_prod_mod_base_array()[i];
                    LOGVOLE_EXPECT_EQ(inversePunctured[i].mOperand, inverseOp.operand);
                    LOGVOLE_EXPECT_EQ(inversePunctured[i].mQuotient, inverseOp.quotient);
                }
                for (std::size_t i = 0; i < punctured.size(); ++i)
                    LOGVOLE_EXPECT_EQ(punctured[i], sealBase.punctured_prod_array()[i]);

                const auto batchData = eager.mBatchingContext->first_context_data();
                LOGVOLE_REQUIRE_TRUE(batchData && batchData->plain_ntt_tables());
                const auto& plainTables = *batchData->plain_ntt_tables();
                const auto& plainView = plainOwners[party]->view();
                std::vector<gpu::HostShoupOperand> plainRoots(degree), plainInverse(degree);
                std::vector<std::uint32_t> slotMap(degree), inverseSlotMap(degree);
                LOGVOLE_REQUIRE_TRUE(gpu::downloadToHost(plainRoots.data(), plainView.mRoots,
                    plainRoots.size() * sizeof(plainRoots[0]), stream));
                LOGVOLE_REQUIRE_TRUE(gpu::downloadToHost(plainInverse.data(), plainView.mInvRoots,
                    plainInverse.size() * sizeof(plainInverse[0]), stream));
                LOGVOLE_REQUIRE_TRUE(gpu::downloadToHost(slotMap.data(), plainOwners[party]->slotMap(),
                    slotMap.size() * sizeof(slotMap[0]), stream));
                LOGVOLE_REQUIRE_TRUE(gpu::downloadToHost(inverseSlotMap.data(),
                    plainOwners[party]->inverseSlotMap(),
                    inverseSlotMap.size() * sizeof(inverseSlotMap[0]), stream));
                for (std::size_t i = 0; i < degree; ++i)
                {
                    const auto forward = plainTables.get_from_root_powers(i);
                    const auto backward = plainTables.get_from_inv_root_powers(i);
                    LOGVOLE_EXPECT_EQ(plainRoots[i].mOperand, forward.operand);
                    LOGVOLE_EXPECT_EQ(plainRoots[i].mQuotient, forward.quotient);
                    LOGVOLE_EXPECT_EQ(plainInverse[i].mOperand, backward.operand);
                    LOGVOLE_EXPECT_EQ(plainInverse[i].mQuotient, backward.quotient);
                }
                // A SEAL-encoded sequence has a unique NTT-domain value in
                // every slot. This checks the entire device map independently
                // of the device map-generation formula.
                std::vector<std::uint64_t> distinctSlots(degree);
                for (std::size_t i = 0; i < degree; ++i) distinctSlots[i] = i + 1u;
                seal::Plaintext encoded;
                eager.mBatchEncoder->encode(distinctSlots, encoded);
                LOGVOLE_REQUIRE_EQ(encoded.coeff_count(), degree);
                std::vector<std::uint64_t> eval(encoded.data(), encoded.data() + degree);
                seal::util::ntt_negacyclic_harvey(eval.data(), plainTables);
                for (std::size_t i = 0; i < degree; ++i)
                {
                    LOGVOLE_REQUIRE_TRUE(slotMap[i] < degree);
                    LOGVOLE_EXPECT_EQ(inverseSlotMap[slotMap[i]], i);
                    LOGVOLE_EXPECT_EQ(eval[slotMap[i]] % eager.mPlaintextModulus,
                        distinctSlots[i]);
                }

                if (degree == 65536u)
                {
                    RnsPoly input;
                    input.mCoeffs.resize(static_cast<std::size_t>(degree) * widths.size());
                    for (std::size_t limb = 0; limb < widths.size(); ++limb)
                    for (std::size_t i = 0; i < degree; ++i)
                        input.mCoeffs[limb * degree + i] =
                            (static_cast<std::uint64_t>(i) * 17u + limb * 23u + 1u) %
                            expectedPrimes[limb].value();
                    auto expectedNtt = input;
                    for (std::size_t limb = 0; limb < widths.size(); ++limb)
                        seal::util::ntt_negacyclic_harvey(
                            expectedNtt.mCoeffs.data() + limb * degree, sealTables[limb]);
                    gpu::GpuPolyBuffer device(*certificate, 1u);
                    LOGVOLE_REQUIRE_TRUE(device.data() && device.upload(input, 0u, stream));
                    LOGVOLE_REQUIRE_TRUE(gpu::nttForward(*certificate, device.data(), 1u, stream));
                    std::vector<RnsPoly> transformed;
                    LOGVOLE_REQUIRE_TRUE(device.download(transformed, stream));
                    LOGVOLE_REQUIRE_EQ(transformed.size(), 1u);
                    expect_poly_equal(transformed[0], expectedNtt);
                    LOGVOLE_REQUIRE_TRUE(gpu::nttInverse(*certificate, device.data(), 1u, stream));
                    std::vector<RnsPoly> roundTrip;
                    LOGVOLE_REQUIRE_TRUE(device.download(roundTrip, stream));
                    LOGVOLE_REQUIRE_EQ(roundTrip.size(), 1u);
                    expect_poly_equal(roundTrip[0], input);
                }

                const std::vector<std::uint64_t> labels{
                    0u, 1u, eager.mPlaintextModulus - 1u, 7u, 11u};
                for (bool scaled : {false, true})
                {
                    RnsPoly reference, actual;
                    LOGVOLE_REQUIRE_TRUE(wrapZpBatchCrt(eager, labels, scaled, 0u, 1u, reference));
                    LOGVOLE_REQUIRE_TRUE(wrapZpBatchCrt(
                        dynamicCrt[party], labels, scaled, 0u, 1u, actual));
                    expect_poly_equal(actual, reference);
                    AlignedUnVec<std::uint64_t> decoded;
                    LOGVOLE_REQUIRE_TRUE(unwrapRingLabelsCrt(
                        dynamicCrt[party], {actual}, labels.size(), scaled, 1u, decoded));
                    LOGVOLE_REQUIRE_TRUE(rangesEqual(decoded, labels));
                    if (!scaled)
                    {
                        AlignedUnVec<std::uint64_t> expectedDecoded;
                        LOGVOLE_REQUIRE_TRUE(unwrapRingLabelsCrt(
                            eager, {actual}, labels.size(), false, 1u,
                            expectedDecoded));
                        LOGVOLE_REQUIRE_TRUE(rangesEqual(decoded, expectedDecoded));

                        // Force the path that reduces a full 64-bit host
                        // residue before the dynamic rho=2/3/9 CRT compose.
                        auto raw = actual;
                        for (std::size_t limb = 0; limb < widths.size(); ++limb)
                            raw.mCoeffs[limb * static_cast<std::size_t>(degree)] +=
                                expectedPrimes[limb].value();
                        AlignedUnVec<std::uint64_t> expectedRaw, actualRaw;
                        LOGVOLE_REQUIRE_TRUE(unwrapRingLabelsCrt(
                            eager, {raw}, labels.size(), false, 1u,
                            expectedRaw));
                        LOGVOLE_REQUIRE_TRUE(unwrapRingLabelsCrt(
                            dynamicCrt[party], {raw}, labels.size(), false,
                            1u, actualRaw));
                        LOGVOLE_REQUIRE_TRUE(rangesEqual(actualRaw, expectedRaw));
                    }
                }
                if (degree <= 2048u)
                {
                    std::vector<std::uint64_t> twoRings(degree + 5u);
                    for (std::size_t i = 0; i < twoRings.size(); ++i)
                        twoRings[i] = (i * 17u + 3u) % eager.mPlaintextModulus;
                    for (bool scaled : {false, true})
                    {
                        RnsPoly expectedConstant, actualConstant;
                        LOGVOLE_REQUIRE_TRUE(wrapZpConstantCrt(
                            eager, 7u, scaled, 2u, expectedConstant));
                        LOGVOLE_REQUIRE_TRUE(wrapZpConstantCrt(
                            dynamicCrt[party], 7u, scaled, 2u, actualConstant));
                        expect_poly_equal(actualConstant, expectedConstant);

                        RnsPoly expectedEmpty, actualEmpty;
                        LOGVOLE_REQUIRE_TRUE(wrapZpBatchCrt(
                            eager, {}, scaled, 7u, 1u, expectedEmpty));
                        LOGVOLE_REQUIRE_TRUE(wrapZpBatchCrt(
                            dynamicCrt[party], {}, scaled, 7u, 1u, actualEmpty));
                        expect_poly_equal(actualEmpty, expectedEmpty);

                        std::vector<RnsPoly> expectedLabels, actualLabels;
                        LOGVOLE_REQUIRE_TRUE(wrapZpLabelsCrt(
                            eager, twoRings, scaled, 7u, 2u, expectedLabels));
                        LOGVOLE_REQUIRE_TRUE(wrapZpLabelsCrt(
                            dynamicCrt[party], twoRings, scaled, 7u, 2u, actualLabels));
                        LOGVOLE_REQUIRE_EQ(actualLabels.size(), 2u);
                        for (std::size_t i = 0; i < actualLabels.size(); ++i)
                            expect_poly_equal(actualLabels[i], expectedLabels[i]);
                    }
                }
                auto malformed = selected;
                auto changed = std::make_shared<RingModulusMetadata>(*malformed.mRawModuli);
                changed->mValues[0] = changed->mValues[1];
                malformed.mRawModuli = std::move(changed);
                LOGVOLE_REQUIRE_FALSE(validateRingContextMetadata(malformed));
                LOGVOLE_REQUIRE_TRUE(getRingHostContext(malformed) == nullptr);
                {
                    auto invalidCrt = dynamicCrt[party];
                    ++invalidCrt.mPlaintextLiftModQj[0];
                    RnsPoly valid;
                    LOGVOLE_REQUIRE_TRUE(wrapZpBatchCrt(
                        eager, labels, false, 0u, 1u, valid));
                    AlignedUnVec<std::uint64_t> unchanged;
                    assignValues<std::uint64_t>(unchanged, {23u, 47u});
                    LOGVOLE_REQUIRE_FALSE(unwrapRingLabelsCrt(
                        invalidCrt, {valid}, labels.size(), false,
                        1u, unchanged));
                    LOGVOLE_REQUIRE_TRUE(rangesEqual(unchanged,
                        std::vector<std::uint64_t>{23u, 47u}));
                    RnsPoly invalidShape;
                    invalidShape.mCoeffs = {17u};
                    LOGVOLE_REQUIRE_FALSE(unwrapRingLabelsCrt(
                        dynamicCrt[party], {invalidShape}, labels.size(),
                        false, 1u, unchanged));
                    LOGVOLE_REQUIRE_TRUE(rangesEqual(unchanged,
                        std::vector<std::uint64_t>{23u, 47u}));
                }

                if (degree == 65536u)
                {
                    // Native prime-selection failures return status in the
                    // consolidated metadata record. Every rejected setup
                    // must leave the caller's prior host results untouched.
                    auto noCoefficientPrime = params;
                    noCoefficientPrime.mCoeffModulusBits[0] = 2;
                    std::vector<std::uint64_t> unchangedPrimes{0xdecafbadULL};
                    LOGVOLE_REQUIRE_FALSE(gpu::selectSealCoeffModuliDevice(
                        noCoefficientPrime, unchangedPrimes));
                    LOGVOLE_REQUIRE_TRUE(rangesEqual(unchangedPrimes,
                        std::vector<std::uint64_t>{0xdecafbadULL}));
                    std::uint64_t unchangedPlain = 0xdecafbadULL;
                    std::uint32_t unchangedBits = 31u;
                    LOGVOLE_REQUIRE_FALSE(gpu::selectSealPlainModulusDevice(
                        degree, 2u, certificate->view().mMinModulus,
                        unchangedPlain, unchangedBits));
                    LOGVOLE_EXPECT_EQ(unchangedPlain, 0xdecafbadULL);
                    LOGVOLE_EXPECT_EQ(unchangedBits, 31u);
                    AlignedUnVec<std::uint64_t> unchangedLift;
                    unchangedLift.resize(1);
                    unchangedLift[0] = 0xdecafbadULL;
                    LOGVOLE_REQUIRE_FALSE(gpu::preparePlaintextLiftDevice(
                        *certificate, certificate->view().mMinModulus, unchangedLift));
                    LOGVOLE_REQUIRE_EQ(unchangedLift.size(), 1u);
                    LOGVOLE_EXPECT_EQ(unchangedLift[0], 0xdecafbadULL);

                    const std::uint64_t oneModFactor = 2u * static_cast<std::uint64_t>(degree) + 1u;
                    const std::uint64_t composite = oneModFactor * oneModFactor;
                    int compositeBits = 0;
                    for (auto q = composite; q; q >>= 1) ++compositeBits;
                    RingParams compositeParams{};
                    compositeParams.mPolyModulusDegree = degree;
                    compositeParams.mCoeffModulusBits.resize(1u);
                    compositeParams.mCoeffModulusBits[0] = compositeBits;
                    LOGVOLE_REQUIRE_TRUE(gpu::GpuRing::getRaw(compositeParams,
                        std::span<const std::uint64_t>(&composite, 1u)) == nullptr);
                    LOGVOLE_REQUIRE_TRUE(gpu::GpuRing::get(selected) == certificate);
                }
            }
            LOGVOLE_EXPECT_TRUE(dynamicRing[0].mRawModuli->mDynamicGpuCertificate !=
                dynamicRing[1].mRawModuli->mDynamicGpuCertificate);
            LOGVOLE_EXPECT_TRUE(dynamicCrt[0].mHostContextCache != dynamicCrt[1].mHostContextCache);
            LOGVOLE_EXPECT_TRUE(plainOwners[0] != plainOwners[1]);
            LOGVOLE_EXPECT_TRUE(plainOwners[0]->slotMap() != plainOwners[1]->slotMap());
        }
    }
#endif
}

void LogVole_RingOps_NttRoundTrip(const oc::CLP& cmd)
{
    const auto params = make_small_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));

    RnsPoly poly = deriveUniformPolyFromNonce(ctx, 0x1234u, 0x5678u, 0);
    RnsPoly expected = poly;
    LOGVOLE_REQUIRE_TRUE(canonicalizePoly(expected, ctx));

    LOGVOLE_REQUIRE_TRUE(forwardNtt(poly, ctx));
    LOGVOLE_REQUIRE_TRUE(inverseNtt(poly, ctx));

    expect_poly_equal(poly, expected);

#if defined(ENABLE_LOGVOLE_CUDA)
    const bool gpuWasEnabled = gpu::enabled();
    struct RestoreGpu
    {
        bool mEnabled;
        ~RestoreGpu() { gpu::setEnabled(mEnabled); }
    } restoreGpu{ gpuWasEnabled };
    gpu::setEnabled(cmd.getOr("gpu", 0) != 0);
    if (!gpu::enabled()) return;
    // Keep the existing full/minimal-chain comparison independent of the
    // separate opt-in batching-context representation below.
    ScopedEnvironmentValue originalBatching("LV_GPU_SETUP_BATCHING_SINGLE_LIMB", "0");
    for (std::uint32_t limbs : {1u, 2u, 4u})
    {
        RingParams varied = make_small_params();
        varied.mCoeffModulusBits.resize(limbs);
        std::fill(varied.mCoeffModulusBits.begin(), varied.mCoeffModulusBits.end(), 30);
        for (std::uint32_t plaintextBits : {14u, 20u, 30u})
            expect_single_limb_batching_parity(varied, plaintextBits);
    }
    const char* reuseOption = std::getenv("LV_GPU_NTT_REUSE_HOST");
    const bool expectReuse = !reuseOption || reuseOption[0] != '0';

    for (bool eightLimbs : { false, true })
    {
        RingParams batchParams{};
        batchParams.mPolyModulusDegree = eightLimbs ? 16384 : 8192;
        batchParams.mCoeffModulusBits.resize(eightLimbs ? 8 : 4);
        std::fill(batchParams.mCoeffModulusBits.begin(), batchParams.mCoeffModulusBits.end(),
            eightLimbs ? 52 : 55);
        RingNttContext batchCtx{};
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(batchParams, batchCtx));
        expect_single_limb_batching_parity(batchParams, eightLimbs ? 52u : 55u);
        {
            ScopedEnvironmentValue eagerRing("LV_GPU_SETUP_LIGHTWEIGHT_RING", "0");
            ScopedEnvironmentValue eagerCrt("LV_GPU_SETUP_LIGHTWEIGHT_CRT", "0");
            RingNttContext fullRing, minimalRing;
            ZpCrtContext fullCrt, minimalCrt;
            const auto plaintextBits = eightLimbs ? 52u : 55u;
            {
                ScopedEnvironmentValue fullChain("LV_GPU_SETUP_FULL_MOD_CHAIN", "1");
                LOGVOLE_REQUIRE_TRUE(makeRingNttContext(batchParams, fullRing));
                LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(batchParams, plaintextBits, fullCrt));
            }
            {
                ScopedEnvironmentValue minimalChain("LV_GPU_SETUP_FULL_MOD_CHAIN", "0");
                LOGVOLE_REQUIRE_TRUE(makeRingNttContext(batchParams, minimalRing));
                LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(batchParams, plaintextBits, minimalCrt));
                RingNttContext again;
                LOGVOLE_REQUIRE_TRUE(makeRingNttContext(batchParams, again));
                LOGVOLE_EXPECT_TRUE(again.mContext == minimalRing.mContext);
            }
            auto expectSameUsableContexts = [](const auto& full, const auto& minimal) {
                LOGVOLE_REQUIRE_TRUE(full != minimal);
                LOGVOLE_REQUIRE_TRUE(full->key_parms_id() == minimal->key_parms_id());
                LOGVOLE_REQUIRE_TRUE(full->first_parms_id() == minimal->first_parms_id());
                for (const auto& pair : { std::pair{full->key_context_data(), minimal->key_context_data()},
                                         std::pair{full->first_context_data(), minimal->first_context_data()} })
                {
                    LOGVOLE_REQUIRE_TRUE(pair.first && pair.second);
                    const auto expected = pair.first->qualifiers();
                    const auto actual = pair.second->qualifiers();
                    LOGVOLE_REQUIRE_TRUE(expected.parameters_set() && actual.parameters_set());
                    LOGVOLE_EXPECT_TRUE(expected.sec_level == actual.sec_level);
                    LOGVOLE_EXPECT_EQ(expected.using_ntt, actual.using_ntt);
                    LOGVOLE_EXPECT_EQ(expected.using_batching, actual.using_batching);
                    LOGVOLE_EXPECT_EQ(expected.using_fast_plain_lift, actual.using_fast_plain_lift);
                }
                LOGVOLE_EXPECT_TRUE(full->first_context_data()->next_context_data() != nullptr);
                LOGVOLE_EXPECT_TRUE(minimal->first_context_data()->next_context_data() == nullptr);
            };
            expectSameUsableContexts(fullRing.mContext, minimalRing.mContext);
            expectSameUsableContexts(fullCrt.mBatchingContext, minimalCrt.mBatchingContext);
            LOGVOLE_EXPECT_EQ(fullCrt.mPlaintextModulus, minimalCrt.mPlaintextModulus);
            LOGVOLE_EXPECT_EQ(fullCrt.mPlaintextModulusBits, minimalCrt.mPlaintextModulusBits);
            LOGVOLE_REQUIRE_TRUE(rangesEqual(fullCrt.mPlaintextLiftModQj, minimalCrt.mPlaintextLiftModQj));

            // Exercise the actual host samplers and NTT tables, independently
            // of any GPU ring cache shared by these identical parameter sets.
            ScopedEnvironmentValue hostUniform("LV_GPU_SETUP_UNIFORM_DEVICE", "0");
            auto fullPoly = deriveUniformPolyFromNonce(fullRing, 0x43484149u, 0x4e504152u, 1u);
            auto minimalPoly = deriveUniformPolyFromNonce(minimalRing, 0x43484149u, 0x4e504152u, 1u);
            expect_poly_equal(fullPoly, minimalPoly);
            osuCrypto::PRNG fullPrng(osuCrypto::block(0x43484149u, 0x4e4e4f49u));
            osuCrypto::PRNG minimalPrng(osuCrypto::block(0x43484149u, 0x4e4e4f49u));
            LOGVOLE_REQUIRE_TRUE(addPolyError(fullPoly, 3.2, 36.0, fullPrng, fullRing));
            LOGVOLE_REQUIRE_TRUE(addPolyError(minimalPoly, 3.2, 36.0, minimalPrng, minimalRing));
            expect_poly_equal(fullPoly, minimalPoly);
            LOGVOLE_REQUIRE_TRUE(forwardNtt(fullPoly, fullRing));
            LOGVOLE_REQUIRE_TRUE(forwardNtt(minimalPoly, minimalRing));
            expect_poly_equal(fullPoly, minimalPoly);
            LOGVOLE_REQUIRE_TRUE(inverseNtt(fullPoly, fullRing));
            LOGVOLE_REQUIRE_TRUE(inverseNtt(minimalPoly, minimalRing));
            expect_poly_equal(fullPoly, minimalPoly);

            std::vector<std::uint64_t> labels(batchParams.mPolyModulusDegree - 3u);
            for (std::size_t i = 0; i < labels.size(); ++i)
                labels[i] = i % 3u ? i : fullCrt.mPlaintextModulus - 1u;
            for (bool multiplyByDelta : {false, true})
            {
                RnsPoly fullEncoded, minimalEncoded;
                LOGVOLE_REQUIRE_TRUE(wrapZpBatchCrt(fullCrt, labels, multiplyByDelta, 7u, 1u, fullEncoded));
                LOGVOLE_REQUIRE_TRUE(wrapZpBatchCrt(minimalCrt, labels, multiplyByDelta, 7u, 1u, minimalEncoded));
                expect_poly_equal(fullEncoded, minimalEncoded);
            }
        }
        // The 65 MiB case exceeds the old 64 MiB transfer chunk. The smaller
        // cases exercise both NTT kernels without relying on batch dispatch.
        for (std::size_t count : { std::size_t(1), std::size_t(5), std::size_t(65) })
        {
            if (!eightLimbs && count == 65) continue;
            std::vector<RnsPoly> actual(count + 2);
            for (std::size_t i = 0; i < actual.size(); ++i)
                actual[i] = deriveUniformPolyFromNonce(batchCtx, 0x4E545452u, 0x45555345u, i);
            auto reference = actual;
            for (std::size_t i = 1; i <= count; ++i)
                LOGVOLE_REQUIRE_TRUE(forwardNtt(reference[i], batchCtx));
            std::vector<const std::uint64_t*> allocations;
            for (const auto& item : actual) allocations.push_back(item.mCoeffs.data());
            auto window = std::span<RnsPoly>(actual).subspan(1, count);
            LOGVOLE_REQUIRE_TRUE(gpu::nttHostBatch(batchCtx, window, false));
            for (std::size_t i = 0; i < actual.size(); ++i)
            {
                LOGVOLE_REQUIRE_TRUE(rangesEqual(actual[i].mCoeffs, reference[i].mCoeffs));
                if (expectReuse) LOGVOLE_REQUIRE_TRUE(actual[i].mCoeffs.data() == allocations[i]);
            }
            for (std::size_t i = 1; i <= count; ++i)
                LOGVOLE_REQUIRE_TRUE(inverseNtt(reference[i], batchCtx));
            LOGVOLE_REQUIRE_TRUE(gpu::nttHostBatch(batchCtx, window, true));
            for (std::size_t i = 0; i < actual.size(); ++i)
            {
                LOGVOLE_REQUIRE_TRUE(rangesEqual(actual[i].mCoeffs, reference[i].mCoeffs));
                if (expectReuse) LOGVOLE_REQUIRE_TRUE(actual[i].mCoeffs.data() == allocations[i]);
            }

            // The 65-polynomial NoGolden case wraps both 32 MiB staging
            // slots and leaves a partial final chunk. Test a nonzero device
            // offset, cache reuse and exact output with one/four CPU workers.
            if (count == 5 || count == 65)
            {
                auto ring = gpu::GpuRing::get(batchCtx);
                LOGVOLE_REQUIRE_TRUE(ring != nullptr);
                auto& stream = gpu::threadStream();
                gpu::GpuPolyBuffer device;
                LOGVOLE_REQUIRE_TRUE(device.resize(*ring, actual.size()));
                LOGVOLE_REQUIRE_TRUE(device.upload(actual, stream));
                gpu::GpuStream emptyStream;
                LOGVOLE_REQUIRE_EQ(emptyStream.stagingCapacity(), 0u);
                for (const char* slotSize : {"1", "32"})
                {
                    ScopedEnvironmentValue slotSetting("LV_GPU_SETUP_DOWNLOAD_SLOT_MIB", slotSize);
                    const std::size_t slotBytes = std::size_t(slotSize[0] == '1' ? 1 : 32) << 20;
                    const std::size_t run = std::min(count, std::max<std::size_t>(1, slotBytes / ring->polyBytes()));
                    const std::size_t requiredBytes = 2u * run * ring->polyBytes();
                    auto* existing = stream.staging(requiredBytes);
                    LOGVOLE_REQUIRE_TRUE(existing != nullptr);
                    const auto capacity = stream.stagingCapacity();
                    LOGVOLE_REQUIRE_TRUE(stream.existingStaging(requiredBytes) == existing);
                    LOGVOLE_REQUIRE_TRUE(stream.existingStaging(capacity + 1u) == nullptr);
                    LOGVOLE_REQUIRE_EQ(stream.stagingCapacity(), capacity);
                    for (const char* reuse : {"0", "1"})
                    {
                        ScopedEnvironmentValue reuseSetting("LV_GPU_SETUP_REUSE_DOWNLOAD_STAGING", reuse);
                        for (std::uint32_t workers : {1u, 4u})
                        {
                            if (reuse[0] == '1')
                            {
                                // The borrowed buffer still feeds an earlier
                                // H2D. Same-stream ordering must protect its
                                // bytes until that upload has consumed them.
                                std::memcpy(existing, actual.back().mCoeffs.data(), ring->polyBytes());
                                LOGVOLE_REQUIRE_TRUE(gpu::gpuMemcpyH2D(device.poly(0), existing,
                                    ring->polyBytes(), stream.raw()));
                            }
                            std::vector<RnsPoly> downloaded{actual[0]};
                            LOGVOLE_REQUIRE_TRUE(device.downloadPipelined(downloaded, stream, workers, 1u, count));
                            LOGVOLE_REQUIRE_EQ(downloaded.size(), count);
                            for (std::size_t i = 0; i < count; ++i)
                                LOGVOLE_REQUIRE_TRUE(rangesEqual(downloaded[i].mCoeffs, actual[i + 1u].mCoeffs));
                            LOGVOLE_REQUIRE_TRUE(stream.existingStaging(requiredBytes) == existing);
                            LOGVOLE_REQUIRE_EQ(stream.stagingCapacity(), capacity);
                            if (reuse[0] == '1')
                            {
                                RnsPoly priorUpload;
                                LOGVOLE_REQUIRE_TRUE(device.downloadAsync(priorUpload, 0, stream));
                                LOGVOLE_REQUIRE_TRUE(stream.sync());
                                expect_poly_equal(priorUpload, actual.back());
                                // A different stream with no pinned capacity
                                // takes the private fallback without growing
                                // or borrowing this stream's staging.
                                std::vector<RnsPoly> privateDownload;
                                LOGVOLE_REQUIRE_TRUE(device.downloadPipelined(privateDownload, emptyStream, workers, 1u, count));
                                expect_batch_equal(privateDownload, downloaded);
                                LOGVOLE_REQUIRE_EQ(emptyStream.stagingCapacity(), 0u);
                            }
                            const auto expectedDownload = downloaded;
                            LOGVOLE_REQUIRE_FALSE(device.downloadPipelined(downloaded, stream, workers, actual.size() + 1u));
                            expect_batch_equal(downloaded, expectedDownload);
                            LOGVOLE_REQUIRE_FALSE(device.downloadPipelined(downloaded, stream, workers, 1u, actual.size()));
                            expect_batch_equal(downloaded, expectedDownload);
                        }
                    }
                }
                if (count == 65)
                {
                    // Reuse one bounded worker pool across eight full chunks
                    // and a one-polynomial tail, then release all worker state.
                    ScopedEnvironmentValue slots("LV_GPU_SETUP_DOWNLOAD_SLOT_MIB", "8");
                    ScopedEnvironmentValue borrow("LV_GPU_SETUP_REUSE_DOWNLOAD_STAGING", "1");
                    LOGVOLE_REQUIRE_TRUE(stream.staging(std::size_t(16) << 20) != nullptr);
                    for (const char* reuseWorkers : {"0", "1"})
                    for (std::uint32_t workers : {1u, 4u})
                    {
                        ScopedEnvironmentValue reuse("LV_GPU_SETUP_DOWNLOAD_REUSE_WORKERS", reuseWorkers);
                        CpuBenchmarkContext context;
#if defined(__linux__)
                        cpu_set_t mask;
                        CPU_ZERO(&mask);
                        LOGVOLE_REQUIRE_EQ(sched_getaffinity(0, sizeof(mask), &mask), 0);
                        for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu)
                            if (CPU_ISSET(cpu, &mask)) context.mCpus.push_back(cpu);
#else
                        context.mCpus.resize(workers);
#endif
                        context.mWorkerLimit = workers;
                        struct RestoreContext
                        {
                            CpuBenchmarkContext* previous = tCpuBenchmarkContext;
                            ~RestoreContext() { tCpuBenchmarkContext = previous; }
                        } restoreContext;
                        tCpuBenchmarkContext = &context;
                        const auto originalScope = currentProtocolCacheScope();
                        const auto originalSlots = detail::gParallelWorkerSlotsInUse.load();
                        std::vector<RnsPoly> downloaded;
                        LOGVOLE_REQUIRE_TRUE(device.downloadPipelined(downloaded, stream, workers, 1u, count));
                        LOGVOLE_REQUIRE_EQ(downloaded.size(), count);
                        for (std::size_t i = 0; i < count; ++i)
                            LOGVOLE_REQUIRE_TRUE(rangesEqual(downloaded[i].mCoeffs, actual[i + 1u].mCoeffs));
                        LOGVOLE_REQUIRE_EQ(context.mWorkerSlots.load(), 0u);
                        LOGVOLE_REQUIRE_EQ(context.mActiveTaskThreads.load(), 0u);
                        LOGVOLE_REQUIRE_TRUE(context.mPeakTaskThreads.load() <= workers);
                        LOGVOLE_REQUIRE_TRUE(context.mPeakTaskThreads.load() > 0u);
                        LOGVOLE_REQUIRE_EQ(context.mAffinityFailures.load(), 0u);
#if defined(__linux__)
                        if (workers > 1u && context.mCpus.size() > 1u)
                            LOGVOLE_REQUIRE_TRUE(context.mWorkersChecked.load() > 0u);
#endif
                        LOGVOLE_REQUIRE_EQ(detail::gParallelWorkerSlotsInUse.load(), originalSlots);
                        LOGVOLE_REQUIRE_EQ(currentProtocolCacheScope().mRunId, originalScope.mRunId);
                        LOGVOLE_REQUIRE_TRUE(currentProtocolCacheScope().mRole == originalScope.mRole);
                    }
                }
            }

            if (count == 5)
            {
                // Failure must not transform any prefix: callers retry the
                // complete batch with the CPU implementation on false.
                actual[count].mCoeffs.resize(actual[count].mCoeffs.size() - 1);
                reference = actual;
                LOGVOLE_EXPECT_FALSE(gpu::nttHostBatch(batchCtx, window, false));
                for (std::size_t i = 0; i < actual.size(); ++i)
                    LOGVOLE_REQUIRE_TRUE(rangesEqual(actual[i].mCoeffs, reference[i].mCoeffs));
            }
        }
    }
#endif
}

void LogVole_RingOps_NttTwoTileInPlaceParity(const oc::CLP& cmd)
{
#if defined(ENABLE_LOGVOLE_CUDA)
    const bool gpuWasEnabled = gpu::enabled();
    struct RestoreGpu
    {
        bool mEnabled;
        ~RestoreGpu() { gpu::setEnabled(mEnabled); }
    } restoreGpu{gpuWasEnabled};
    gpu::setEnabled(cmd.getOr("gpu", 0) != 0);
    if (!gpu::enabled()) return;

    RingParams params{};
    params.mPolyModulusDegree = 16384u;
    params.mCoeffModulusBits.resize(8u);
    std::fill(params.mCoeffModulusBits.begin(), params.mCoeffModulusBits.end(), 52);
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));
    auto ring = gpu::GpuRing::get(ctx);
    LOGVOLE_REQUIRE_TRUE(ring && ring->n() == params.mPolyModulusDegree &&
        ring->rho() == params.mCoeffModulusBits.size());
    auto& stream = gpu::threadStream();
    for (std::size_t count : {std::size_t{1}, std::size_t{8}, std::size_t{16}})
    {
        std::vector<RnsPoly> original(count), expected(count);
        for (std::size_t i = 0; i < count; ++i)
        {
            original[i] = deriveUniformPolyFromNonce(
                ctx, 0x54574f54u, 0x494c454eu, static_cast<std::uint64_t>(i));
            expected[i] = original[i];
            LOGVOLE_REQUIRE_TRUE(forwardNtt(expected[i], ctx));
        }

        gpu::GpuPolyBuffer inPlace(*ring, count);
        gpu::GpuPolyBuffer outOfPlaceInput(*ring, count);
        gpu::GpuPolyBuffer outOfPlace(*ring, count);
        LOGVOLE_REQUIRE_TRUE(
            inPlace.data() && outOfPlaceInput.data() && outOfPlace.data());
        for (unsigned iteration = 0; iteration < 4u; ++iteration)
        {
            LOGVOLE_REQUIRE_TRUE(inPlace.upload(original, stream));
            LOGVOLE_REQUIRE_TRUE(outOfPlaceInput.upload(original, stream));
            LOGVOLE_REQUIRE_TRUE(gpu::nttForward(
                *ring, inPlace.data(), static_cast<std::uint32_t>(count), stream));
            LOGVOLE_REQUIRE_TRUE(gpu::launchNttForwardFrom(
                ring->view(), outOfPlaceInput.data(), nullptr,
                outOfPlace.data(), nullptr, static_cast<std::uint32_t>(count),
                stream.raw()));
            std::vector<RnsPoly> actualInPlace, actualOutOfPlace;
            LOGVOLE_REQUIRE_TRUE(inPlace.download(actualInPlace, stream));
            LOGVOLE_REQUIRE_TRUE(outOfPlace.download(actualOutOfPlace, stream));
            expect_batch_equal(actualInPlace, expected);
            expect_batch_equal(actualOutOfPlace, expected);
        }
    }
#else
    (void)cmd;
    LOGVOLE_SKIP() << "requires ENABLE_LOGVOLE_CUDA";
#endif
}

void LogVole_RingOps_NttBatchDeviceCanonicalization(const oc::CLP& cmd)
{
#if defined(ENABLE_LOGVOLE_CUDA)
    const bool requestGpu = cmd.getOr("gpu", 0) != 0;
    ScopedGpuEnabled gpuScope(requestGpu);
    if (requestGpu) LOGVOLE_REQUIRE_TRUE(gpu::enabled());
#else
    (void)cmd;
#endif
    ScopedEnvironmentValue strict("LV_GPU_SETUP_NTT_CANONICALIZE_STRICT", "1");
    ScopedEnvironmentValue noDecline("LV_GPU_SETUP_NTT_CANONICALIZE_FORCE_DECLINE", nullptr);
    osuCrypto::PRNG random(osuCrypto::block(0x4e545443u, 0x414e4f4eu));
    for (std::uint32_t degree : {1024u, 8192u, 16384u})
    {
        RingParams params{};
        params.mPolyModulusDegree = degree;
        params.mCoeffModulusBits.resize(degree == 16384u ? 8u : degree == 8192u ? 4u : 2u);
        std::fill(params.mCoeffModulusBits.begin(), params.mCoeffModulusBits.end(),
            degree == 16384u ? 52 : degree == 8192u ? 55 : 30);
        RingNttContext ctx{};
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));
        const auto hostContext = getRingHostContext(ctx);
        LOGVOLE_REQUIRE_TRUE(hostContext != nullptr);
        const auto* tables = hostContext->key_context_data()->small_ntt_tables();
        for (std::size_t count : {std::size_t(4), std::size_t(9)})
        {
            std::vector<RnsPoly> original(count);
            for (auto& poly : original)
            {
                poly.mCoeffs.resize(ringPolyCoeffCount(params));
                for (std::size_t limb = 0; limb < ringModulusCount(ctx); ++limb)
                for (std::size_t i = 0; i < degree; ++i)
                {
                    const auto q = ringModulusValue(ctx, limb);
                    const std::array<std::uint64_t, 8> values{
                        0u, q - 1u, q, 2u * q - 1u,
                        std::numeric_limits<std::uint64_t>::max(), std::uint64_t(1) << 63u,
                        random.get<std::uint64_t>(), random.get<std::uint64_t>()};
                    poly.mCoeffs[limb * degree + i] = values[i % values.size()];
                }
            }
            // The oracle uses scalar integer remainder and SEAL directly,
            // independently of both batch dispatch and CPU reduction helpers.
            auto canonical = original;
            auto transformed = original;
            for (std::size_t row = 0; row < count; ++row)
            for (std::size_t limb = 0; limb < ringModulusCount(ctx); ++limb)
            {
                const auto q = ringModulusValue(ctx, limb);
                for (std::size_t i = 0; i < degree; ++i)
                {
                    const auto index = limb * degree + i;
                    canonical[row].mCoeffs[index] %= q;
                    transformed[row].mCoeffs[index] %= q;
                }
                seal::util::ntt_negacyclic_harvey(
                    transformed[row].mCoeffs.data() + limb * degree, tables[limb]);
            }
            auto inverseReference = transformed;
            for (auto& poly : inverseReference)
                for (std::size_t limb = 0; limb < ringModulusCount(ctx); ++limb)
                    seal::util::inverse_ntt_negacyclic_harvey(
                        poly.mCoeffs.data() + limb * degree, tables[limb]);
            expect_batch_equal(inverseReference, canonical);

            for (const char* option : {"0", "1"})
            {
                ScopedEnvironmentValue reduction("LV_GPU_SETUP_NTT_CANONICALIZE", option);
                auto actual = original;
                LOGVOLE_REQUIRE_TRUE(forwardNttBatch(actual, ctx));
                expect_batch_equal(actual, transformed);
                LOGVOLE_REQUIRE_TRUE(inverseNttBatch(actual, ctx));
                expect_batch_equal(actual, inverseReference);
                for (const auto& poly : actual)
                    for (std::size_t limb = 0; limb < ringModulusCount(ctx); ++limb)
                        for (std::size_t i = 0; i < degree; ++i)
                            LOGVOLE_REQUIRE_TRUE(poly.mCoeffs[limb * degree + i] < ringModulusValue(ctx, limb));

                // A malformed final member must leave every preceding member
                // untouched, in either direction and with either dispatch.
                for (bool inverse : {false, true})
                {
                    auto invalid = inverse ? transformed : original;
                    invalid.back().mCoeffs.resize(invalid.back().mCoeffs.size() - 1u);
                    const auto before = invalid;
                    LOGVOLE_REQUIRE_FALSE(inverse ? inverseNttBatch(invalid, ctx) : forwardNttBatch(invalid, ctx));
                    expect_batch_equal(invalid, before);
                }
            }

            ScopedEnvironmentValue reduction("LV_GPU_SETUP_NTT_CANONICALIZE", "1");
#if defined(ENABLE_LOGVOLE_CUDA)
            if (gpu::enabled() && count == 4u)
            {
                for (const char* declineAt : {"1", "2"})
                {
                    ScopedEnvironmentValue decline("LV_GPU_SETUP_NTT_CANONICALIZE_FORCE_DECLINE", declineAt);
                    for (bool inverse : {false, true})
                    {
                        auto rejected = inverse ? transformed : original;
                        const auto before = rejected;
                        LOGVOLE_REQUIRE_FALSE(inverse ? inverseNttBatch(rejected, ctx) : forwardNttBatch(rejected, ctx));
                        expect_batch_equal(rejected, before);
                        // Direct helper rejection also retains host data after
                        // the forced post-kernel failure and stream cleanup.
                        LOGVOLE_REQUIRE_FALSE(gpu::nttHostBatch(ctx, rejected, inverse, true));
                        expect_batch_equal(rejected, before);
                        {
                            ScopedEnvironmentValue allowFallback("LV_GPU_SETUP_NTT_CANONICALIZE_STRICT", "0");
                            LOGVOLE_REQUIRE_TRUE(inverse ? inverseNttBatch(rejected, ctx) : forwardNttBatch(rejected, ctx));
                            expect_batch_equal(rejected, inverse ? inverseReference : transformed);
                        }
                        {
                            // An explicit rollback ignores this option's
                            // strict/debug controls and keeps the old path.
                            ScopedEnvironmentValue disabled("LV_GPU_SETUP_NTT_CANONICALIZE", "0");
                            auto rollback = before;
                            LOGVOLE_REQUIRE_TRUE(inverse ? inverseNttBatch(rollback, ctx) : forwardNttBatch(rollback, ctx));
                            expect_batch_equal(rollback, inverse ? inverseReference : transformed);
                        }
                    }
                }
            }
#endif
            if (count == 4u)
            {
                // Strict selection never lowers the established four-poly
                // GPU threshold, even if a device attempt would be declined.
                ScopedEnvironmentValue decline("LV_GPU_SETUP_NTT_CANONICALIZE_FORCE_DECLINE", "2");
                for (std::size_t smallCount : {std::size_t(1), std::size_t(3)})
                {
                    std::vector<RnsPoly> actual(original.begin(), original.begin() + smallCount);
                    const std::vector<RnsPoly> expectedNtt(transformed.begin(), transformed.begin() + smallCount);
                    const std::vector<RnsPoly> expectedCoeff(canonical.begin(), canonical.begin() + smallCount);
                    if (ctx.mGpuLightweight)
                    {
                        // Lightweight contexts deliberately select the GPU at
                        // every batch size. Strict forced decline must leave
                        // the host inputs untouched instead of materializing
                        // SEAL as an implicit fallback.
                        const auto before = actual;
                        LOGVOLE_REQUIRE_FALSE(forwardNttBatch(actual, ctx));
                        expect_batch_equal(actual, before);
                        continue;
                    }
                    LOGVOLE_REQUIRE_TRUE(forwardNttBatch(actual, ctx));
                    expect_batch_equal(actual, expectedNtt);
                    LOGVOLE_REQUIRE_TRUE(inverseNttBatch(actual, ctx));
                    expect_batch_equal(actual, expectedCoeff);
                }
            }
            auto invalidContext = ctx;
            invalidContext.mContext.reset();
            invalidContext.mGpuLightweight = false;
            invalidContext.mHostContextCache.reset();
            auto unchanged = original;
            LOGVOLE_REQUIRE_FALSE(forwardNttBatch(unchanged, invalidContext));
            LOGVOLE_REQUIRE_FALSE(inverseNttBatch(unchanged, invalidContext));
            expect_batch_equal(unchanged, original);
            LOGVOLE_REQUIRE_TRUE(forwardNttBatch({}, invalidContext));
            LOGVOLE_REQUIRE_TRUE(inverseNttBatch({}, invalidContext));
        }
    }
}

void LogVole_RingOps_GadgetDecomposeRecompose(const oc::CLP&)
{
    const auto params = make_small_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));

    RnsPoly poly = deriveUniformPolyFromNonce(ctx, 0x55AAu, 0xCCDDu, 0);

    std::vector<RnsPoly> digits;
    LOGVOLE_REQUIRE_TRUE(gadgetDecompose(poly, 1u << 10u, 4u, ctx, digits));
    LOGVOLE_REQUIRE_EQ(digits.size(), 4u);

    RnsPoly recomposed{};
    LOGVOLE_REQUIRE_TRUE(gadgetRecompose(digits, 1u << 10u, ctx, recomposed));

    LOGVOLE_REQUIRE_TRUE(canonicalizePoly(poly, ctx));
    LOGVOLE_REQUIRE_TRUE(canonicalizePoly(recomposed, ctx));
    expect_poly_equal(poly, recomposed);
}

void LogVole_RingOps_GadgetDecomposeRecomposeBits(const oc::CLP&)
{
    const auto params = make_small_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));

    RnsPoly poly = deriveUniformPolyFromNonce(ctx, 0xAA55u, 0x11EEu, 0);

    std::vector<RnsPoly> digits;
    LOGVOLE_REQUIRE_TRUE(gadgetDecomposeBits(poly, 20u, 4u, ctx, digits));
    LOGVOLE_REQUIRE_EQ(digits.size(), 4u);

    RnsPoly recomposed{};
    LOGVOLE_REQUIRE_TRUE(gadgetRecomposeBits(digits, 20u, ctx, recomposed));

    LOGVOLE_REQUIRE_TRUE(canonicalizePoly(poly, ctx));
    LOGVOLE_REQUIRE_TRUE(canonicalizePoly(recomposed, ctx));
    expect_poly_equal(poly, recomposed);
}

void LogVole_RingOps_GadgetDecomposeBitsRangeMatchesSlice(const oc::CLP&)
{
    const auto params = make_small_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));

    RnsPoly poly = deriveUniformPolyFromNonce(ctx, 0xBEEFu, 0xCAFEu, 1);

    std::vector<RnsPoly> full;
    std::vector<RnsPoly> range;
    LOGVOLE_REQUIRE_TRUE(gadgetDecomposeBits(poly, 10u, 6u, ctx, full));
    LOGVOLE_REQUIRE_TRUE(gadgetDecomposeBitsRange(poly, 10u, 2u, 3u, ctx, range));
    LOGVOLE_REQUIRE_EQ(range.size(), 3u);

    for (std::size_t i = 0; i < range.size(); ++i)
    {
        expect_poly_equal(range[i], full[i + 2]);
    }
}

void LogVole_RingOps_CenteredGadgetDecomposeRecomposeBits(const oc::CLP&)
{
    const auto params = make_four_limb_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));

    RnsPoly poly = deriveUniformPolyFromNonce(ctx, 0xA11CEu, 0xB0Bu, 2);

    std::vector<RnsPoly> digits;
    LOGVOLE_REQUIRE_TRUE(gadgetDecomposeBitsRangeCentered(poly, 20u, 0u, 7u, ctx, digits));
    LOGVOLE_REQUIRE_EQ(digits.size(), 7u);

    RnsPoly recomposed{};
    LOGVOLE_REQUIRE_TRUE(gadgetRecomposeBits(digits, 20u, ctx, recomposed));

    LOGVOLE_REQUIRE_TRUE(canonicalizePoly(poly, ctx));
    LOGVOLE_REQUIRE_TRUE(canonicalizePoly(recomposed, ctx));
    expect_poly_equal(poly, recomposed);
}

void LogVole_RingOps_TensorPackUnpack(const oc::CLP&)
{
    const auto params = make_small_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));

    RingTensor tensor{};
    tensor.mRows = 2;
    tensor.mCols = 3;
    for (std::uint32_t i = 0; i < tensor.mRows * tensor.mCols; ++i)
    {
        tensor.mPolys.push_back(deriveUniformPolyFromNonce(ctx, 0x77u, 0x99u, i));
    }

    auto packed = packRingTensor(tensor);
    RingTensor unpacked{};
    LOGVOLE_REQUIRE_TRUE(unpackRingTensor(
        tensor.mRows,
        tensor.mCols,
        params.mPolyModulusDegree,
        static_cast<std::uint32_t>(params.mCoeffModulusBits.size()),
        packed,
        unpacked));
    LOGVOLE_REQUIRE_EQ(unpacked.mRows, tensor.mRows);
    LOGVOLE_REQUIRE_EQ(unpacked.mCols, tensor.mCols);
    LOGVOLE_REQUIRE_EQ(unpacked.mPolys.size(), tensor.mPolys.size());

    for (std::size_t i = 0; i < tensor.mPolys.size(); ++i)
    {
        expect_poly_equal(tensor.mPolys[i], unpacked.mPolys[i]);
    }
}

void LogVole_RingOps_NonceBatchDeterminism(const oc::CLP&)
{
    ScopedEnvironmentValue originalCpuOption("LV_GPU_SETUP_UNIFORM_DEVICE", "0");
    const auto params = make_small_params();
    RingNttContext ctx{};
    LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));

    const std::vector<std::uint64_t> nonces{ 1, 2, 3, 4 };
    auto a = deriveUniformPolyBatchFromNonceList(ctx, nonces, 0xF00Du, 3u, 1u);
    auto b = deriveUniformPolyBatchFromNonceList(ctx, nonces, 0xF00Du, 3u, 1u);
    expect_batch_equal(a, b);

    std::vector<RnsPoly> c;
    LOGVOLE_REQUIRE_TRUE(deriveUniformPolyBatchFromNonceListInplace(ctx, nonces, 0xF00Du, 3u, c, 1u));
    expect_batch_equal(a, c);

#if defined(ENABLE_LOGVOLE_CUDA)
    ScopedGpuEnabled useGpu(true);
    const bool haveGpu = gpu::enabled();
    if (const char* strict = std::getenv("LV_GPU_SETUP_UNIFORM_DEVICE_STRICT"))
        if (strict[0] == '1') LOGVOLE_REQUIRE_TRUE(haveGpu);
#else
    const bool haveGpu = false;
#endif
    auto compareExact = [](const std::vector<RnsPoly>& expected, const std::vector<RnsPoly>& actual) {
        LOGVOLE_REQUIRE_EQ(actual.size(), expected.size());
        for (std::size_t i = 0; i < actual.size(); ++i)
            LOGVOLE_REQUIRE_TRUE(rangesEqual(actual[i].mCoeffs, expected[i].mCoeffs))
                << " sampled polynomial " << i;
    };
    auto checkSetupSampling = [&](const RingParams& ring) {
        RingNttContext sampleContext{};
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(ring, sampleContext));
        constexpr std::uint64_t nonce = 0x534554555053414Dull, domain = 0x554E49464F524Dull;
        for (std::uint32_t count : { 1u, 4u, 32u })
        {
            std::vector<RnsPoly> expectedNonce, expectedNtt, expectedPrivate, expectedPublicB;
            oc::PRNG referencePrng(oc::block(0x53414D504C45ull, 7), 3);
            {
                ScopedEnvironmentValue cpuOption("LV_GPU_SETUP_UNIFORM_DEVICE", "0");
#if defined(ENABLE_LOGVOLE_CUDA)
                ScopedGpuEnabled cpuReference(false);
#endif
                for (std::uint32_t i = 0; i < count; ++i)
                {
                    expectedNonce.push_back(deriveUniformPolyFromNonce(sampleContext, nonce, domain, i));
                    expectedPrivate.push_back(sampleUniformPoly(sampleContext, referencePrng));
                }
                expectedNtt = expectedNonce;
                for (auto& poly : expectedNtt) LOGVOLE_REQUIRE_TRUE(forwardNtt(poly, sampleContext));
                for (std::uint32_t i = 0; i < 4; ++i)
                    expectedPublicB.push_back(deriveUniformPolyFromNonceNtt(
                        sampleContext, 0xC0DEC0DEull, 0x1EEC0DEu, i));
            }
            const auto nextReference = referencePrng.get<oc::block>();
            for (bool device : { false, true })
            {
                if (device && !haveGpu) continue;
                ScopedEnvironmentValue deviceOption("LV_GPU_SETUP_UNIFORM_DEVICE", device ? "1" : "0");
                ScopedEnvironmentValue strictOption("LV_GPU_SETUP_UNIFORM_DEVICE_STRICT", "1");
                ScopedEnvironmentValue declineOption("LV_GPU_SETUP_UNIFORM_FORCE_DECLINE", "0");
#if defined(ENABLE_LOGVOLE_CUDA)
                if (device) LOGVOLE_REQUIRE_TRUE(gpu::enabled());
#endif
                compareExact(expectedNonce, deriveUniformPolyBatchFromNonce(sampleContext, nonce, domain, count));
                // This established API's name is historical: its values are
                // coefficient-domain samples, not transformed polynomials.
                compareExact(expectedNonce, deriveUniformPolyBatchFromNonceNtt(sampleContext, nonce, domain, count));
                compareExact(expectedNonce, deriveUniformPolyBatchFromNonce(sampleContext, nonce, domain, count, false));
                compareExact(expectedNtt, deriveUniformPolyBatchFromNonce(sampleContext, nonce, domain, count, true));
                oc::PRNG actualPrng(oc::block(0x53414D504C45ull, 7), 3);
                compareExact(expectedPrivate, sampleUniformPolyBatch(sampleContext, count, actualPrng));
                LOGVOLE_EXPECT_EQ(actualPrng.get<oc::block>(), nextReference);
                // Public B has actual NTT values, unlike the historical raw
                // BatchFromNonceNtt API. The direct explicit-transform call
                // above verifies device execution independently of this cache.
                compareExact(expectedPublicB, buildLencPublicBNtt(sampleContext, 2));
            }
            if (haveGpu && count == 4)
            {
                ScopedEnvironmentValue deviceOption("LV_GPU_SETUP_UNIFORM_DEVICE", "1");
                ScopedEnvironmentValue declineOption("LV_GPU_SETUP_UNIFORM_FORCE_DECLINE", "1");
                ScopedEnvironmentValue fallbackOption("LV_GPU_SETUP_UNIFORM_DEVICE_STRICT", "0");
                oc::PRNG fallbackPrng(oc::block(0x53414D504C45ull, 7), 3);
                compareExact(expectedPrivate, sampleUniformPolyBatch(sampleContext, count, fallbackPrng));
                LOGVOLE_EXPECT_EQ(fallbackPrng.get<oc::block>(), nextReference);
                compareExact(expectedNtt, deriveUniformPolyBatchFromNonce(sampleContext, nonce, domain, count, true));
                ScopedEnvironmentValue strictOption("LV_GPU_SETUP_UNIFORM_DEVICE_STRICT", "1");
                bool rejected = false;
                try { (void)deriveUniformPolyBatchFromNonce(sampleContext, nonce, domain, count, true); }
                catch (const std::runtime_error&) { rejected = true; }
                LOGVOLE_REQUIRE_TRUE(rejected);
            }
        }
        oc::PRNG emptyPrng(oc::block(0x454D505459ull, 1), 3), emptyReference(oc::block(0x454D505459ull, 1), 3);
        LOGVOLE_REQUIRE_TRUE(sampleUniformPolyBatch(sampleContext, 0, emptyPrng).empty());
        LOGVOLE_EXPECT_EQ(emptyPrng.get<oc::block>(), emptyReference.get<oc::block>());
    };
    checkSetupSampling(params);
    RingParams production{};
    production.mPolyModulusDegree = 8192;
    assignValues<int>(production.mCoeffModulusBits, { 55, 55, 55, 55 });
    checkSetupSampling(production);
    production.mPolyModulusDegree = 16384;
    assignValues<int>(production.mCoeffModulusBits, { 52, 52, 52, 52, 52, 52, 52, 52 });
    checkSetupSampling(production);
}

void LogVole_RingOps_PublicUniformRetentionParity(const oc::CLP& cmd)
{
#if defined(ENABLE_LOGVOLE_CUDA)
    const bool requested = cmd.getOr("gpu", 0) != 0;
    ScopedGpuEnabled gpuScope(requested);
    if (requested) LOGVOLE_REQUIRE_TRUE(gpu::enabled());
    if (!gpu::enabled()) { LOGVOLE_SKIP() << "requires -gpu 1"; return; }
    ScopedEnvironmentValue retain("LV_GPU_SETUP_PUBLIC_RETAIN", "1");
    ScopedEnvironmentValue retainDecline("LV_GPU_SETUP_PUBLIC_RETAIN_FORCE_DECLINE", "0");
    ScopedEnvironmentValue uniform("LV_GPU_SETUP_UNIFORM_DEVICE", "1");
    ScopedEnvironmentValue uniformStrict("LV_GPU_SETUP_UNIFORM_DEVICE_STRICT", "1");
    ScopedEnvironmentValue uniformDecline("LV_GPU_SETUP_UNIFORM_FORCE_DECLINE", "0");
    ScopedEnvironmentValue lheDevice("LV_GPU_SETUP_LHE_DEVICE", "1");
    ScopedEnvironmentValue lheStrict("LV_GPU_SETUP_LHE_DEVICE_STRICT", "1");
    ScopedEnvironmentValue lheDecline("LV_GPU_SETUP_LHE_DEVICE_FORCE_DECLINE", "0");
    ScopedEnvironmentValue compact("LV_GPU_SETUP_COMPACT_NOISE", "0");
    LOGVOLE_REQUIRE_TRUE(gpu::publicUniformRetentionEnabled());
    auto exact = [](const auto& a, const auto& b) {
        LOGVOLE_REQUIRE_EQ(a.size(), b.size());
        for (std::size_t i = 0; i < a.size(); ++i)
            LOGVOLE_REQUIRE_TRUE(rangesEqual(a[i].mCoeffs, b[i].mCoeffs)) << " polynomial " << i;
    };

    for (const auto& shape : { std::pair{1024u, 2u}, {8192u, 4u}, {16384u, 8u} })
    {
        RingParams params;
        params.mPolyModulusDegree = shape.first;
        params.mCoeffModulusBits.resize(shape.second);
        std::fill(params.mCoeffModulusBits.begin(), params.mCoeffModulusBits.end(),
            shape.first == 1024u ? 30 : shape.first == 8192u ? 55 : 52);
        RingNttContext ctx;
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));
        const auto run = allocateProtocolCacheRunId();
        ScopedProtocolCacheScope cacheScope(ProtocolCacheRole::Sender, run);
        constexpr std::uint32_t count = 4;
        constexpr std::uint64_t nonce = 0x52455441494e4544ULL, domain = 0x5055424c4943ULL;

        for (bool actualNtt : {false, true})
        {
            std::vector<RnsPoly> expected;
            {
                ScopedGpuEnabled cpuReference(false);
                expected = deriveUniformPolyBatchFromNonce(ctx, nonce, domain, count, actualNtt);
            }
            const auto before = gpu::publicUniformRetentionStats();
            gpu::RetainedPublicUniformPtr token;
            auto sampled = deriveUniformPolyBatchFromNonce(ctx, nonce, domain, count, actualNtt, &token);
            exact(expected, sampled);
            LOGVOLE_REQUIRE_TRUE(token && token->count() == count);
            LOGVOLE_REQUIRE_TRUE(gpu::publicUniformRetentionStats().mCaptures > before.mCaptures);
            auto owner = std::make_shared<const std::vector<RnsPoly>>(std::move(sampled));
            const std::span<const RnsPoly> span(*owner);
            LOGVOLE_REQUIRE_TRUE(gpu::registerPublicUniformRetention(ctx, owner, token));
            LOGVOLE_REQUIRE_TRUE(gpu::registerPublicUniformRetention(ctx, owner, token));
            LOGVOLE_REQUIRE_TRUE(gpu::findPublicUniformRetention(ctx, span) == token);
            std::vector<RnsPoly> fetched;
            LOGVOLE_REQUIRE_TRUE(gpu::fetchRetainedPublicUniform(*token, fetched));
            exact(expected, fetched);

            // Const ownership must originate from the captured allocations.
            // Merely copying the exact values never registers a mutable clone.
            auto copied = std::make_shared<const std::vector<RnsPoly>>(*owner);
            LOGVOLE_REQUIRE_FALSE(gpu::registerPublicUniformRetention(ctx, copied, token));
            LOGVOLE_REQUIRE_TRUE(gpu::findPublicUniformRetention(ctx, *copied) == nullptr);
            LOGVOLE_REQUIRE_TRUE(gpu::findPublicUniformRetention(ctx, span.first(count - 1)) == nullptr);
            LOGVOLE_REQUIRE_TRUE(gpu::findPublicUniformRetention(ctx, span.subspan(1)) == nullptr);
            LOGVOLE_REQUIRE_TRUE(gpu::findPublicUniformRetention(ctx, {}) == nullptr);
            RingNttContext changed = ctx;
            swap_moduli_for_test(changed, 0, 1);
            LOGVOLE_REQUIRE_TRUE(gpu::findPublicUniformRetention(changed, span) == nullptr);
            LOGVOLE_REQUIRE_FALSE(gpu::registerPublicUniformRetention(changed, owner, token));
            changed = ctx;
            changed.mParams.mPolyModulusDegree *= 2;
            LOGVOLE_REQUIRE_TRUE(gpu::findPublicUniformRetention(changed, span) == nullptr);
            {
                ScopedProtocolCacheScope peer(ProtocolCacheRole::Receiver, run);
                // Party-local GPU caches and retained allocations must not be
                // visible through a peer role, even in this single-process test.
                LOGVOLE_REQUIRE_TRUE(gpu::findPublicUniformRetention(ctx, span) == nullptr);
                LOGVOLE_REQUIRE_FALSE(gpu::registerPublicUniformRetention(ctx, owner, token));
            }
            {
                ScopedProtocolCacheScope anotherRun(ProtocolCacheRole::Sender, allocateProtocolCacheRunId());
                LOGVOLE_REQUIRE_TRUE(gpu::findPublicUniformRetention(ctx, span) == nullptr);
                LOGVOLE_REQUIRE_FALSE(gpu::registerPublicUniformRetention(ctx, owner, token));
            }
            {
                ScopedGpuEnabled cpuOnly(false);
                LOGVOLE_REQUIRE_TRUE(gpu::findPublicUniformRetention(ctx, span) == nullptr);
                auto capture = token;
                exact(expected, deriveUniformPolyBatchFromNonce(ctx, nonce, domain, count, actualNtt, &capture));
                LOGVOLE_REQUIRE_TRUE(capture == nullptr);
            }
            for (const char* flag : {"LV_GPU_SETUP_PUBLIC_RETAIN", "LV_GPU_SETUP_PUBLIC_RETAIN_FORCE_DECLINE"})
            {
                ScopedEnvironmentValue rollback(flag,
                    std::string(flag) == "LV_GPU_SETUP_PUBLIC_RETAIN" ? "0" : "1");
                LOGVOLE_REQUIRE_TRUE(gpu::findPublicUniformRetention(ctx, span) == nullptr);
                auto capture = token;
                exact(expected, deriveUniformPolyBatchFromNonce(ctx, nonce, domain, count, actualNtt, &capture));
                LOGVOLE_REQUIRE_TRUE(capture == nullptr);
            }
            LOGVOLE_REQUIRE_TRUE(gpu::findPublicUniformRetention(ctx, span) == token);
            {
                auto capture = token;
                LOGVOLE_REQUIRE_TRUE(deriveUniformPolyBatchFromNonce(
                    ctx, nonce, domain, 0, actualNtt, &capture).empty());
                LOGVOLE_REQUIRE_TRUE(capture == nullptr);
                std::vector<std::array<std::uint64_t, 8>> seeds(1);
                std::vector<RnsPoly> unchanged = expected;
                capture = token;
                ScopedEnvironmentValue decline("LV_GPU_SETUP_UNIFORM_FORCE_DECLINE", "1");
                LOGVOLE_REQUIRE_FALSE(gpu::sampleUniformBatchFromSeedsDevice(
                    ctx, seeds, actualNtt, unchanged, &capture));
                exact(expected, unchanged);
                LOGVOLE_REQUIRE_TRUE(capture == token);
            }

            // Lookup must reject the saved span before touching freed host
            // storage; retaining the completed device owner remains safe.
            owner.reset();
            LOGVOLE_REQUIRE_TRUE(gpu::findPublicUniformRetention(ctx, span) == nullptr);
            LOGVOLE_REQUIRE_TRUE(gpu::fetchRetainedPublicUniform(*token, fetched));
            exact(expected, fetched);
        }

        // Production cache A is a legacy raw sample despite its Ntt name;
        // public B is actually transformed. Check both independent oracles.
        std::vector<RnsPoly> expectedA, expectedB;
        {
            ScopedGpuEnabled cpuReference(false);
            expectedA = deriveUniformPolyBatchFromNonce(ctx, 0xA11ACE5Eull, 0xA110CA7Aull, count);
            expectedB = deriveUniformPolyBatchFromNonce(ctx, 0xC0DEC0DEull, 0x1EEC0DEu, count, true);
        }
        const auto beforeRetainOnly = gpu::publicUniformRetentionStats();
        const auto deviceA = retainedLhePublicANtt(ctx, count);
        const auto deviceB = retainedLencPublicBNtt(ctx, count / 2);
        const auto afterRetainOnly = gpu::publicUniformRetentionStats();
        LOGVOLE_REQUIRE_TRUE(deviceA && deviceB && deviceA != deviceB);
        LOGVOLE_REQUIRE_TRUE(gpu::retainedPublicUniformMatches(ctx, *deviceA, count, false));
        LOGVOLE_REQUIRE_TRUE(gpu::retainedPublicUniformMatches(ctx, *deviceB, count, true));
        LOGVOLE_REQUIRE_EQ(afterRetainOnly.mHostMaterializations,
            beforeRetainOnly.mHostMaterializations);
        std::shared_ptr<const std::vector<RnsPoly>> materializedA, materializedB;
        LOGVOLE_REQUIRE_TRUE(gpu::materializeRetainedPublicUniform(ctx, deviceA, materializedA));
        LOGVOLE_REQUIRE_TRUE(gpu::materializeRetainedPublicUniform(ctx, deviceB, materializedB));
        exact(expectedA, *materializedA);
        exact(expectedB, *materializedB);
        const auto afterMaterialize = gpu::publicUniformRetentionStats();
        LOGVOLE_REQUIRE_EQ(afterMaterialize.mHostMaterializations,
            afterRetainOnly.mHostMaterializations + 2u);
        auto sameA = materializedB;
        LOGVOLE_REQUIRE_TRUE(gpu::materializeRetainedPublicUniform(ctx, deviceA, sameA));
        LOGVOLE_REQUIRE_TRUE(sameA == materializedA);
        LOGVOLE_REQUIRE_EQ(gpu::publicUniformRetentionStats().mHostMaterializations,
            afterMaterialize.mHostMaterializations);
        {
            ScopedProtocolCacheScope peer(ProtocolCacheRole::Receiver, run);
            auto unchanged = materializedB;
            LOGVOLE_REQUIRE_FALSE(gpu::materializeRetainedPublicUniform(ctx, deviceA, unchanged));
            LOGVOLE_REQUIRE_TRUE(unchanged == materializedB);
        }
        const auto publicA = sharedLhePublicANtt(ctx, count);
        const auto publicB = sharedLencPublicBNtt(ctx, count / 2);
        LOGVOLE_REQUIRE_TRUE(publicA && publicB);
        exact(expectedA, *publicA);
        exact(expectedB, *publicB);
        const auto retainedA = gpu::findPublicUniformRetention(ctx, *publicA);
        const auto retainedB = gpu::findPublicUniformRetention(ctx, *publicB);
        LOGVOLE_REQUIRE_TRUE(retainedA && retainedB && retainedA != retainedB);
        std::vector<RnsPoly> downloaded;
        LOGVOLE_REQUIRE_TRUE(gpu::fetchRetainedPublicUniform(*retainedA, downloaded));
        exact(expectedA, downloaded);
        LOGVOLE_REQUIRE_TRUE(gpu::fetchRetainedPublicUniform(*retainedB, downloaded));
        exact(expectedB, downloaded);
        LOGVOLE_REQUIRE_TRUE(sharedLhePublicANtt(ctx, count) == publicA);
        LOGVOLE_REQUIRE_TRUE(sharedLencPublicBNtt(ctx, count / 2) == publicB);

        auto mutableA = *publicA;
        mutableA[0].mCoeffs[0] = (mutableA[0].mCoeffs[0] + 1) % ringModulusValue(ctx, 0);
        LOGVOLE_REQUIRE_TRUE(gpu::findPublicUniformRetention(ctx, mutableA) == nullptr);
        auto r = expectedA;
        const std::vector<RnsPoly> sk{expectedA.front()};
        for (const auto* a : {publicA.get(), static_cast<const std::vector<RnsPoly>*>(&mutableA)})
        {
            const oc::block seed(0x5055424c4845ULL, shape.first);
            oc::PRNG referencePrng(seed, 3), actualPrng(seed, 3);
            RingTensor expected, actual;
            {
                ScopedGpuEnabled cpuReference(false);
                LOGVOLE_REQUIRE_TRUE(lheEnc1(ctx, r, sk, 8, expected, 3.2, 19.2,
                    &referencePrng, false, a, 4));
            }
            const auto before = gpu::publicUniformRetentionStats();
            LOGVOLE_REQUIRE_TRUE(lheEnc1(ctx, r, sk, 8, actual, 3.2, 19.2,
                &actualPrng, false, a, 4));
            const auto after = gpu::publicUniformRetentionStats();
            LOGVOLE_REQUIRE_EQ(expected.mRows, actual.mRows);
            LOGVOLE_REQUIRE_EQ(expected.mCols, actual.mCols);
            exact(expected.mPolys, actual.mPolys);
            LOGVOLE_REQUIRE_EQ(referencePrng.get<oc::block>(), actualPrng.get<oc::block>());
            if (a == publicA.get())
            {
                LOGVOLE_REQUIRE_TRUE(after.mCopies > before.mCopies);
                LOGVOLE_REQUIRE_TRUE(after.mCopiedBytes >= before.mCopiedBytes + count * ringPolyCoeffCount(params) * sizeof(std::uint64_t));
            }
            else LOGVOLE_REQUIRE_EQ(after.mCopies, before.mCopies);
        }
        LOGVOLE_REQUIRE_TRUE(gpu::fetchRetainedPublicUniform(*retainedA, downloaded));
        exact(expectedA, downloaded);
        exact(expectedA, *publicA);
        exact(expectedB, *publicB);
        if (shape.first == 1024u)
        {
            std::weak_ptr<const std::vector<RnsPoly>> oldA, oldB;
            {
                ScopedProtocolCacheScope secondRun(ProtocolCacheRole::Sender, allocateProtocolCacheRunId());
                const auto temporaryA = sharedLhePublicANtt(ctx, count);
                const auto temporaryB = sharedLencPublicBNtt(ctx, count / 2);
                oldA = temporaryA;
                oldB = temporaryB;
                LOGVOLE_REQUIRE_TRUE(temporaryA != publicA && temporaryB != publicB);
                exact(expectedA, *temporaryA);
                exact(expectedB, *temporaryB);
            }
            LOGVOLE_REQUIRE_TRUE(gpu::findPublicUniformRetention(ctx, *publicA) == retainedA);
            LOGVOLE_REQUIRE_TRUE(gpu::findPublicUniformRetention(ctx, *publicB) == retainedB);
            {
                ScopedProtocolCacheScope thirdRun(ProtocolCacheRole::Sender, allocateProtocolCacheRunId());
                LOGVOLE_REQUIRE_TRUE(sharedLhePublicANtt(ctx, count) != nullptr);
                LOGVOLE_REQUIRE_TRUE(sharedLencPublicBNtt(ctx, count / 2) != nullptr);
            }
            LOGVOLE_REQUIRE_TRUE(oldA.expired() && oldB.expired());
            LOGVOLE_REQUIRE_TRUE(gpu::findPublicUniformRetention(ctx, *publicA) == retainedA);
            LOGVOLE_REQUIRE_TRUE(gpu::findPublicUniformRetention(ctx, *publicB) == retainedB);
        }
    }
#else
    (void)cmd;
    LOGVOLE_SKIP() << "requires ENABLE_LOGVOLE_CUDA";
#endif
}

void LogVole_RingOps_GaussianPrefixBatchParity(const oc::CLP&)
{
    ScopedEnvironmentValue originalTransform("LV_GPU_SETUP_GAUSSIAN_TRANSFORM", "0");
#if defined(ENABLE_LOGVOLE_CUDA)
    ScopedGpuEnabled useGpu(true);
    const bool haveGpu = gpu::enabled();
    if (const char* strict = std::getenv("LV_GPU_SETUP_GAUSSIAN_PRG_STRICT"))
        if (strict[0] == '1') LOGVOLE_REQUIRE_TRUE(haveGpu);
    if (haveGpu)
    {
        ScopedEnvironmentValue decline("LV_GPU_SETUP_GAUSSIAN_PRG_FORCE_DECLINE", "0");
        std::array<seal::prng_seed_type, 1> seeds{};
        seeds[0][0] = 0x50494E4E45445052ull;
        gpu::GaussianPrngPrefixBuffer first, second;
        LOGVOLE_REQUIRE_TRUE(gpu::sampleGaussianPrngPrefixesDevice(seeds, 512, first));
        LOGVOLE_REQUIRE_TRUE(first.mData != nullptr);
        LOGVOLE_REQUIRE_EQ(first.mWords, std::size_t(512));
        const std::vector<std::uint64_t> saved(first.mData.get(), first.mData.get() + first.mWords);
        seeds[0][1] = 0x5345434F4E44ull;
        LOGVOLE_REQUIRE_TRUE(gpu::sampleGaussianPrngPrefixesDevice(seeds, 512, second));
        LOGVOLE_REQUIRE_TRUE(second.mData != nullptr);
        LOGVOLE_REQUIRE_TRUE(first.mData.get() != second.mData.get());
        LOGVOLE_REQUIRE_TRUE(std::equal(saved.begin(), saved.end(), first.mData.get()));
        const auto previous = second.mData;
        const auto previousWords = second.mWords;
        ScopedEnvironmentValue forceDecline("LV_GPU_SETUP_GAUSSIAN_PRG_FORCE_DECLINE", "1");
        LOGVOLE_REQUIRE_TRUE(!gpu::sampleGaussianPrngPrefixesDevice(seeds, 512, second));
        LOGVOLE_REQUIRE_TRUE(second.mData == previous);
        LOGVOLE_REQUIRE_EQ(second.mWords, previousWords);
        LOGVOLE_REQUIRE_TRUE(std::equal(saved.begin(), saved.end(), first.mData.get()));
    }
#else
    const bool haveGpu = false;
#endif
    constexpr std::uint64_t sentinel = 0xBADC0FFEE0DDF00Dull;
    auto checkCase = [&](const RingNttContext& ctx, std::uint32_t count,
                         double sigma, double clip, const std::vector<std::uint8_t>& active) {
        const std::size_t n = ctx.mParams.mPolyModulusDegree;
        std::vector<std::uint64_t> expected(count * n + 2, sentinel);
        std::vector<seal::prng_seed_type> seeds(count), referenceSeeds(count);
        oc::PRNG referenceParent(oc::block(0x4741555353505247ull, 19), 3);
        oc::PRNG batchParent(oc::block(0x4741555353505247ull, 19), 3);
        // The caller draws parent seeds only for active rows. Scalar sampling
        // between these draws must agree with preparing the complete seed list.
        for (std::size_t i = 0; i < count; ++i)
        {
            if (!active.empty() && !active[i]) continue;
            referenceParent.get(referenceSeeds[i].data(), referenceSeeds[i].size());
            LOGVOLE_REQUIRE_TRUE(samplePolyErrorCompactFromSeed(
                std::span<std::uint64_t>(expected).subspan(1 + i * n, n),
                sigma, clip, referenceSeeds[i], ctx));
        }
        for (std::size_t i = 0; i < count; ++i)
            if (active.empty() || active[i]) batchParent.get(seeds[i].data(), seeds[i].size());
        LOGVOLE_REQUIRE_TRUE(seeds == referenceSeeds);
        const auto nextParent = referenceParent.get<oc::block>();

        for (bool device : { false, true })
        {
            if (device && !haveGpu) continue;
            ScopedEnvironmentValue enabled("LV_GPU_SETUP_GAUSSIAN_PRG", device ? "1" : "0");
            ScopedEnvironmentValue strict("LV_GPU_SETUP_GAUSSIAN_PRG_STRICT", "1");
            ScopedEnvironmentValue decline("LV_GPU_SETUP_GAUSSIAN_PRG_FORCE_DECLINE", "0");
            // One prefix block cannot supply even N=1024 normal samples; this
            // checks exact continuation after the GPU-generated prefix ends.
            for (const char* prefix : { "0", "1" })
            {
                if (!device && prefix[0] == '1') continue;
                ScopedEnvironmentValue blocks("LV_GPU_SETUP_GAUSSIAN_PRG_PREFIX_BLOCKS", prefix);
                std::vector<std::uint64_t> actual(expected.size(), sentinel);
                LOGVOLE_REQUIRE_TRUE(samplePolyErrorCompactBatchFromSeeds(
                    std::span<std::uint64_t>(actual).subspan(1, count * n),
                    sigma, clip, seeds, ctx, 3, active));
                LOGVOLE_REQUIRE_TRUE(actual == expected)
                    << " N=" << n << " count=" << count << " sigma=" << sigma
                    << " GPU=" << device << " prefix=" << prefix;
                LOGVOLE_REQUIRE_TRUE(seeds == referenceSeeds);
            }
        }
        LOGVOLE_EXPECT_EQ(batchParent.get<oc::block>(), nextParent);

        if (haveGpu && count == 4 && sigma > 0)
        {
            ScopedEnvironmentValue enabled("LV_GPU_SETUP_GAUSSIAN_PRG", "1");
            ScopedEnvironmentValue decline("LV_GPU_SETUP_GAUSSIAN_PRG_FORCE_DECLINE", "1");
            ScopedEnvironmentValue strict("LV_GPU_SETUP_GAUSSIAN_PRG_STRICT", "0");
            std::vector<std::uint64_t> replay(expected.size(), sentinel);
            LOGVOLE_REQUIRE_TRUE(samplePolyErrorCompactBatchFromSeeds(
                std::span<std::uint64_t>(replay).subspan(1, count * n),
                sigma, clip, seeds, ctx, 3, active));
            LOGVOLE_REQUIRE_TRUE(replay == expected);
            ScopedEnvironmentValue reject("LV_GPU_SETUP_GAUSSIAN_PRG_STRICT", "1");
            std::vector<std::uint64_t> rejected(expected.size(), sentinel);
            LOGVOLE_REQUIRE_TRUE(!samplePolyErrorCompactBatchFromSeeds(
                std::span<std::uint64_t>(rejected).subspan(1, count * n),
                sigma, clip, seeds, ctx, 3, active));
            LOGVOLE_REQUIRE_TRUE(std::all_of(rejected.begin(), rejected.end(),
                [&](std::uint64_t value) { return value == sentinel; }));
        }
    };

    for (std::uint32_t n : { 1024u, 8192u, 16384u })
    {
        RingParams params{};
        params.mPolyModulusDegree = n;
        params.mCoeffModulusBits.resize(n == 1024 ? 2 : n == 8192 ? 4 : 8);
        std::fill(params.mCoeffModulusBits.begin(), params.mCoeffModulusBits.end(),
            n == 1024 ? 30 : n == 8192 ? 55 : 52);
        RingNttContext ctx{};
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));
        for (std::uint32_t count : { 1u, 4u, 32u }) checkCase(ctx, count, 3.2, 19.2, {});
        checkCase(ctx, 4, 0.0, 19.2, {});
        checkCase(ctx, 4, 3.2, 19.2, { 1, 0, 2, 0 });
        if (n == 1024)
        {
            // Tight rejection clipping consumes substantially more randomness
            // than the prefix heuristic; the scalar stream must still match.
            checkCase(ctx, 1, 3.2, 0.125, {});
#if defined(ENABLE_LOGVOLE_CUDA)
            ScopedGpuEnabled cpuOnly(false);
#endif
            ScopedEnvironmentValue enabled("LV_GPU_SETUP_GAUSSIAN_PRG", "1");
            ScopedEnvironmentValue strict("LV_GPU_SETUP_GAUSSIAN_PRG_STRICT", "1");
            ScopedEnvironmentValue decline("LV_GPU_SETUP_GAUSSIAN_PRG_FORCE_DECLINE", "1");
            const std::vector<seal::prng_seed_type> seeds(2);
            std::vector<std::uint64_t> actual(2 * n, sentinel), expected(2 * n, sentinel);
            for (std::size_t i = 0; i < seeds.size(); ++i)
                LOGVOLE_REQUIRE_TRUE(samplePolyErrorCompactFromSeed(
                    std::span<std::uint64_t>(expected).subspan(i * n, n), 3.2, 19.2, seeds[i], ctx));
            LOGVOLE_REQUIRE_TRUE(samplePolyErrorCompactBatchFromSeeds(actual, 3.2, 19.2, seeds, ctx, 2));
            LOGVOLE_REQUIRE_TRUE(actual == expected);
        }

        const std::vector<seal::prng_seed_type> seeds(4);
        std::vector<std::uint64_t> untouched(4 * n, sentinel);
        const auto initial = untouched;
        const std::array<std::uint8_t, 4> inactive{ 0, 0, 0, 0 };
        LOGVOLE_REQUIRE_TRUE(samplePolyErrorCompactBatchFromSeeds(untouched, 3.2, 19.2, seeds, ctx, 3, inactive));
        LOGVOLE_REQUIRE_TRUE(untouched == initial);
        LOGVOLE_REQUIRE_TRUE(samplePolyErrorCompactBatchFromSeeds({}, 3.2, 19.2, {}, ctx));
        LOGVOLE_REQUIRE_TRUE(!samplePolyErrorCompactBatchFromSeeds(
            std::span<std::uint64_t>(untouched).subspan(1), 3.2, 19.2, seeds, ctx));
        LOGVOLE_REQUIRE_TRUE(!samplePolyErrorCompactBatchFromSeeds(
            untouched, 3.2, 19.2, seeds, ctx, 3, std::span<const std::uint8_t>(inactive).first(3)));
        LOGVOLE_REQUIRE_TRUE(!samplePolyErrorCompactBatchFromSeeds(
            untouched, 3.2, std::numeric_limits<double>::infinity(), seeds, ctx));
        LOGVOLE_REQUIRE_TRUE(untouched == initial);
    }
}

void LogVole_RingOps_GaussianTransformBatchParity(const oc::CLP& cmd)
{
#if defined(ENABLE_LOGVOLE_CUDA)
    const bool requested = cmd.getOr("gpu", 0) != 0;
    ScopedGpuEnabled gpuScope(requested);
    if (requested) LOGVOLE_REQUIRE_TRUE(gpu::enabled());
    if (!gpu::enabled()) { LOGVOLE_SKIP() << "requires -gpu 1"; return; }
    if (!gpu::gaussianTransformHostCompatible())
    {
        if (const char* strict = std::getenv("LV_GPU_SETUP_GAUSSIAN_TRANSFORM_STRICT"))
            LOGVOLE_REQUIRE_TRUE(strict[0] != '1') << "unrecognized host Gaussian arithmetic";
        LOGVOLE_SKIP() << "requires recognized CPU compiler/libm arithmetic";
        return;
    }
    ScopedEnvironmentValue transform("LV_GPU_SETUP_GAUSSIAN_TRANSFORM", "1");
    ScopedEnvironmentValue strict("LV_GPU_SETUP_GAUSSIAN_TRANSFORM_STRICT", "1");
    ScopedEnvironmentValue decline("LV_GPU_SETUP_GAUSSIAN_TRANSFORM_FORCE_DECLINE", "0");
    ScopedEnvironmentValue prefix("LV_GPU_SETUP_GAUSSIAN_TRANSFORM_PREFIX_BLOCKS", "0");
    ScopedEnvironmentValue originalPrg("LV_GPU_SETUP_GAUSSIAN_PRG", "0");
    ScopedEnvironmentValue originalPrgStrict("LV_GPU_SETUP_GAUSSIAN_PRG_STRICT", "0");
    constexpr std::uint64_t marker = 0xdeadbadc0ffef00dULL;

    for (const auto shape : {0, 1, 2})
    {
        RingParams params = make_small_params();
        if (shape == 1)
        {
            params.mPolyModulusDegree = 8192;
            assignValues<int>(params.mCoeffModulusBits, {55, 55, 55, 55});
        }
        if (shape == 2)
        {
            params.mPolyModulusDegree = 16384;
            assignValues<int>(params.mCoeffModulusBits, {52, 52, 52, 52, 52, 52, 52, 52});
        }
        RingNttContext ctx;
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));
        const std::size_t n = params.mPolyModulusDegree;
        for (std::uint32_t count : {1, 4, 32})
        for (double sigma : {0.0, 3.2})
        {
            const std::vector<std::uint8_t> active = count == 4
                ? std::vector<std::uint8_t>{1, 0, 2, 0} : std::vector<std::uint8_t>{};
            std::vector<seal::prng_seed_type> seeds(count), referenceSeeds(count);
            std::vector<std::uint64_t> expected(count * n + 2, marker);
            oc::PRNG parent(oc::block(0x4558414354474155ULL, count), 3);
            oc::PRNG referenceParent(oc::block(0x4558414354474155ULL, count), 3);
            for (std::size_t row = 0; row < count; ++row)
            {
                if (!active.empty() && !active[row]) continue;
                referenceParent.get(referenceSeeds[row].data(), referenceSeeds[row].size());
                LOGVOLE_REQUIRE_TRUE(samplePolyErrorCompactFromSeed(
                    std::span<std::uint64_t>(expected).subspan(1 + row * n, n),
                    sigma, 19.2, referenceSeeds[row], ctx));
                parent.get(seeds[row].data(), seeds[row].size());
            }
            LOGVOLE_REQUIRE_TRUE(seeds == referenceSeeds);
            for (const char* blocks : {"0", "1"})
            {
                ScopedEnvironmentValue finitePrefix("LV_GPU_SETUP_GAUSSIAN_TRANSFORM_PREFIX_BLOCKS", blocks);
                std::vector<std::uint64_t> actual(expected.size(), marker);
                LOGVOLE_REQUIRE_TRUE(samplePolyErrorCompactBatchFromSeeds(
                    std::span<std::uint64_t>(actual).subspan(1, count * n),
                    sigma, 19.2, seeds, ctx, 4, active));
                LOGVOLE_REQUIRE_TRUE(actual == expected)
                    << "N=" << n << " count=" << count << " sigma=" << sigma << " prefix=" << blocks;
            }
            LOGVOLE_EXPECT_EQ(parent.get<oc::block>(), referenceParent.get<oc::block>());
            LOGVOLE_REQUIRE_TRUE(seeds == referenceSeeds);

            gpu::GaussianSampleBuffer direct;
            LOGVOLE_REQUIRE_TRUE(gpu::sampleGaussianCompactDevice(
                seeds, static_cast<std::uint32_t>(n), sigma, 19.2, ringModulusValue(ctx, 0), direct));
            LOGVOLE_REQUIRE_EQ(direct.mValues.mWords, count * n);
            for (std::size_t row = 0; row < count; ++row)
            {
                LOGVOLE_REQUIRE_TRUE(direct.mComplete[row]);
                if (!active.empty() && !active[row]) continue;
                LOGVOLE_REQUIRE_TRUE(std::equal(expected.begin() + 1 + row * n,
                    expected.begin() + 1 + (row + 1) * n, direct.mValues.mData.get() + row * n));
            }
            if (count == 4 && sigma > 0)
            {
                const auto retained = direct.mValues.mData;
                const std::vector<std::uint64_t> snapshot(retained.get(), retained.get() + count * n);
                const auto flags = direct.mComplete;
                gpu::GaussianSampleBuffer incomplete;
                LOGVOLE_REQUIRE_TRUE(gpu::sampleGaussianCompactDevice(seeds, static_cast<std::uint32_t>(n),
                    sigma, 19.2, ringModulusValue(ctx, 0), incomplete, 512));
                LOGVOLE_REQUIRE_TRUE(incomplete.mValues.mData != retained);
                LOGVOLE_REQUIRE_TRUE(std::all_of(incomplete.mComplete.begin(), incomplete.mComplete.end(),
                    [](auto complete) { return complete == 0; }));
                LOGVOLE_REQUIRE_TRUE(std::equal(snapshot.begin(), snapshot.end(), retained.get()));
                ScopedEnvironmentValue forced("LV_GPU_SETUP_GAUSSIAN_TRANSFORM_FORCE_DECLINE", "1");
                LOGVOLE_REQUIRE_TRUE(!gpu::sampleGaussianCompactDevice(seeds, static_cast<std::uint32_t>(n),
                    sigma, 19.2, ringModulusValue(ctx, 0), direct));
                LOGVOLE_REQUIRE_TRUE(direct.mValues.mData == retained && direct.mComplete == flags);
                std::vector<std::uint64_t> fallback(expected.size(), marker);
                LOGVOLE_REQUIRE_TRUE(!samplePolyErrorCompactBatchFromSeeds(
                    std::span<std::uint64_t>(fallback).subspan(1, count * n), sigma, 19.2, seeds, ctx, 4, active));
                LOGVOLE_REQUIRE_TRUE(std::all_of(fallback.begin(), fallback.end(), [](auto x) { return x == marker; }));
                ScopedEnvironmentValue allowReplay("LV_GPU_SETUP_GAUSSIAN_TRANSFORM_STRICT", "0");
                LOGVOLE_REQUIRE_TRUE(samplePolyErrorCompactBatchFromSeeds(
                    std::span<std::uint64_t>(fallback).subspan(1, count * n), sigma, 19.2, seeds, ctx, 4, active));
                LOGVOLE_REQUIRE_TRUE(fallback == expected);
            }
        }
    }
    {
        struct RestoreRounding { int mode = std::fegetround(); ~RestoreRounding() { std::fesetround(mode); } } rounding;
        LOGVOLE_REQUIRE_EQ(std::fesetround(FE_UPWARD), 0);
        LOGVOLE_REQUIRE_TRUE(!gpu::gaussianTransformHostCompatible());
    }
#else
    LOGVOLE_SKIP() << "requires CUDA build";
#endif
}

void LogVole_RingOps_GaussianResidentBatchParity(const oc::CLP& cmd)
{
#if defined(ENABLE_LOGVOLE_CUDA)
    const bool requested = cmd.getOr("gpu", 0) != 0;
    ScopedGpuEnabled gpuScope(requested);
    if (requested) LOGVOLE_REQUIRE_TRUE(gpu::enabled());
    if (!gpu::enabled()) { LOGVOLE_SKIP() << "requires -gpu 1"; return; }
    if (!gpu::gaussianTransformHostCompatible())
    {
        if (const char* strict = std::getenv("LV_GPU_SETUP_GAUSSIAN_RESIDENT_STRICT"))
            LOGVOLE_REQUIRE_TRUE(strict[0] != '1') << "unrecognized host Gaussian arithmetic";
        LOGVOLE_SKIP() << "requires recognized CPU compiler/libm arithmetic";
        return;
    }
    ScopedEnvironmentValue resident("LV_GPU_SETUP_GAUSSIAN_RESIDENT", "1");
    ScopedEnvironmentValue residentStrict("LV_GPU_SETUP_GAUSSIAN_RESIDENT_STRICT", "1");
    ScopedEnvironmentValue residentDecline("LV_GPU_SETUP_GAUSSIAN_RESIDENT_FORCE_DECLINE", "0");
    ScopedEnvironmentValue transform("LV_GPU_SETUP_GAUSSIAN_TRANSFORM", "1");
    ScopedEnvironmentValue transformStrict("LV_GPU_SETUP_GAUSSIAN_TRANSFORM_STRICT", "1");
    ScopedEnvironmentValue transformDecline("LV_GPU_SETUP_GAUSSIAN_TRANSFORM_FORCE_DECLINE", "0");
    ScopedEnvironmentValue prefix("LV_GPU_SETUP_GAUSSIAN_TRANSFORM_PREFIX_BLOCKS", "0");
    constexpr std::uint64_t marker = 0x5a5afedcba987654ULL;

    for (std::uint32_t degree : {1024u, 8192u, 16384u})
    {
        RingParams params = make_small_params();
        params.mPolyModulusDegree = degree;
        params.mCoeffModulusBits.resize(degree == 16384u ? 8u : degree == 8192u ? 4u : 2u);
        std::fill(params.mCoeffModulusBits.begin(), params.mCoeffModulusBits.end(),
            degree == 16384u ? 52 : degree == 8192u ? 55 : 30);
        RingNttContext ctx;
        LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, ctx));
        if (degree != 8192u)
        {
            // Check the expansion independently of the Gaussian generator,
            // including the centered sign boundary and a resident prefix.
            const std::uint32_t count = degree == 1024u ? 3u : 17u;
            const std::uint64_t q0 = ringModulusValue(ctx, 0);
            const std::array<std::uint64_t, 5> values{0u, 1u, q0 / 2u, q0 / 2u + 1u, q0 - 1u};
            for (std::size_t limb = 0; limb < ringModulusCount(ctx); ++limb)
                LOGVOLE_REQUIRE_TRUE(q0 / 2u < ringModulusValue(ctx, limb));
            std::vector<std::uint64_t> compactValues(std::size_t(count + 2u) * degree);
            for (std::size_t i = 0; i < compactValues.size(); ++i)
                compactValues[i] = values[(i + i / degree) % values.size()];
            const auto originalCompact = compactValues;
            auto device = gpu::uploadScalars(compactValues);
            LOGVOLE_REQUIRE_TRUE(device != nullptr && gpu::waitScalars(*device));
            std::vector<RnsPoly> coefficients(count);
            for (std::size_t row = 0; row < count; ++row)
            {
                coefficients[row].mCoeffs.resize(ringPolyCoeffCount(params));
                for (std::size_t limb = 0; limb < ringModulusCount(ctx); ++limb)
                for (std::size_t column = 0; column < degree; ++column)
                {
                    const auto value = compactValues[row * degree + column];
                    coefficients[row].mCoeffs[limb * degree + column] = value <= q0 / 2u
                        ? value : ringModulusValue(ctx, limb) - (q0 - value);
                }
            }
            for (bool outputNtt : {false, true})
            {
                auto expected = coefficients;
                if (outputNtt)
                {
                    ScopedGpuEnabled cpuReference(false);
                    for (auto& poly : expected) LOGVOLE_REQUIRE_TRUE(forwardNttCanonical(poly, ctx));
                }
                const auto checkExpansion = [&](std::uint32_t workers) {
                    std::vector<RnsPoly> hostOutput, residentOutput;
                    LOGVOLE_REQUIRE_TRUE(gpu::expandErrorCompactDevice(ctx,
                        std::span<const std::uint64_t>(compactValues).first(std::size_t(count) * degree),
                        outputNtt, hostOutput, workers));
                    LOGVOLE_REQUIRE_TRUE(gpu::expandErrorCompactDevice(ctx,
                        *device, outputNtt, residentOutput, count, workers));
                    LOGVOLE_REQUIRE_EQ(hostOutput.size(), expected.size());
                    LOGVOLE_REQUIRE_EQ(residentOutput.size(), expected.size());
                    for (std::size_t row = 0; row < expected.size(); ++row)
                    {
                        LOGVOLE_REQUIRE_TRUE(rangesEqual(hostOutput[row].mCoeffs, expected[row].mCoeffs));
                        LOGVOLE_REQUIRE_TRUE(rangesEqual(residentOutput[row].mCoeffs, expected[row].mCoeffs));
                    }
                };
                for (const char* direct : {"0", "1"})
                {
                    ScopedEnvironmentValue expand("LV_GPU_SETUP_COMPACT_EXPAND_DIRECT", direct);
                    ScopedEnvironmentValue pipeline("LV_GPU_SETUP_COMPACT_PIPELINED_DOWNLOAD", "0");
                    checkExpansion(1u);
                }
                if (degree == 16384u && outputNtt)
                {
                    ScopedEnvironmentValue expand("LV_GPU_SETUP_COMPACT_EXPAND_DIRECT", "1");
                    ScopedEnvironmentValue slots("LV_GPU_SETUP_DOWNLOAD_SLOT_MIB", "1");
                    for (const char* pipelineValue : {"0", "1"})
                    for (std::uint32_t workers : {1u, 4u})
                    {
                        ScopedEnvironmentValue pipeline("LV_GPU_SETUP_COMPACT_PIPELINED_DOWNLOAD", pipelineValue);
                        checkExpansion(workers);
                    }
                }
            }
            LOGVOLE_REQUIRE_TRUE(compactValues == originalCompact);
            std::vector<std::uint64_t> fetched(compactValues.size());
            LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(*device, fetched));
            LOGVOLE_REQUIRE_TRUE(fetched == originalCompact);
            std::vector<RnsPoly> rejected = coefficients;
            const auto* storage = rejected.data();
            LOGVOLE_REQUIRE_FALSE(gpu::expandErrorCompactDevice(ctx, *device, false, rejected, count + 3u, 4u));
            LOGVOLE_REQUIRE_TRUE(rejected.data() == storage);
            for (std::size_t row = 0; row < coefficients.size(); ++row)
                LOGVOLE_REQUIRE_TRUE(rangesEqual(rejected[row].mCoeffs, coefficients[row].mCoeffs));
        }
        for (std::uint32_t count : {1u, 4u, 32u})
        for (double sigma : {0.0, 3.2})
        {
            const std::size_t words = static_cast<std::size_t>(count) * degree;
            const std::vector<std::uint8_t> active = count == 4u
                ? std::vector<std::uint8_t>{1u, 0u, 2u, 0u} : std::vector<std::uint8_t>{};
            oc::PRNG parent(oc::block(0x5245534944454e54ULL, count), 3);
            oc::PRNG referenceParent(oc::block(0x5245534944454e54ULL, count), 3);
            std::vector<seal::prng_seed_type> seeds(count), expectedSeeds(count);
            std::vector<std::uint64_t> expected(words, 0);
            for (std::size_t row = 0; row < count; ++row)
            {
                if (!active.empty() && !active[row]) continue;
                parent.get(seeds[row].data(), seeds[row].size());
                referenceParent.get(expectedSeeds[row].data(), expectedSeeds[row].size());
                LOGVOLE_REQUIRE_TRUE(samplePolyErrorCompactFromSeed(
                    std::span<std::uint64_t>(expected).subspan(row * degree, degree),
                    sigma, 19.2, expectedSeeds[row], ctx));
            }
            const auto unchangedSeeds = seeds;
            LOGVOLE_REQUIRE_TRUE(seeds == expectedSeeds);
            gpu::GaussianDeviceSampleBuffer direct;
            LOGVOLE_REQUIRE_TRUE(gpu::sampleGaussianCompactResidentDevice(
                seeds, degree, sigma, 19.2, ringModulusValue(ctx, 0), direct, 0, active));
            LOGVOLE_REQUIRE_TRUE(direct.mValues != nullptr);
            LOGVOLE_REQUIRE_EQ(direct.mValues->count(), words);
            LOGVOLE_REQUIRE_EQ(direct.mComplete.size(), count);
            LOGVOLE_REQUIRE_TRUE(std::all_of(direct.mComplete.begin(), direct.mComplete.end(),
                [](auto complete) { return complete == 1u; }));
            std::vector<std::uint64_t> fetched(words, marker);
            LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(*direct.mValues, fetched));
            LOGVOLE_REQUIRE_TRUE(fetched == expected);
            const auto retained = direct.mValues;
            const auto retainedFlags = direct.mComplete;

            for (const char* blocks : {"0", "1"})
            {
                // Prefix1 must repair active positive-noise rows from their
                // original seeds and publish a completed device result.
                ScopedEnvironmentValue finitePrefix("LV_GPU_SETUP_GAUSSIAN_TRANSFORM_PREFIX_BLOCKS", blocks);
                std::vector<std::uint64_t> host{marker};
                gpu::DeviceScalarsPtr device;
                LOGVOLE_REQUIRE_TRUE(samplePolyErrorCompactBatchForSetup(
                    host, device, sigma, 19.2, seeds, ctx, 4, active));
                LOGVOLE_REQUIRE_TRUE(host.empty() && device != nullptr);
                LOGVOLE_REQUIRE_EQ(device->count(), words);
                LOGVOLE_REQUIRE_TRUE(device != retained);
                LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(*device, fetched));
                LOGVOLE_REQUIRE_TRUE(fetched == expected);
                const auto materializedOwner = device;
                LOGVOLE_REQUIRE_TRUE(materializePolyErrorCompactBatchForSetup(
                    host, device, sigma, 19.2, seeds, ctx, 4, active));
                LOGVOLE_REQUIRE_TRUE(host == expected && device == materializedOwner);
            }
            LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(*retained, fetched));
            LOGVOLE_REQUIRE_TRUE(fetched == expected);
            LOGVOLE_REQUIRE_TRUE(seeds == unchangedSeeds);
            for (unsigned i = 0; i < 8u; ++i)
                LOGVOLE_EXPECT_EQ(parent.get<std::uint64_t>(), referenceParent.get<std::uint64_t>());

            if (count != 4u || sigma == 0.0) continue;
            gpu::GaussianDeviceSampleBuffer incomplete;
            LOGVOLE_REQUIRE_TRUE(gpu::sampleGaussianCompactResidentDevice(
                seeds, degree, sigma, 19.2, ringModulusValue(ctx, 0), incomplete, 512, active));
            LOGVOLE_REQUIRE_TRUE(incomplete.mValues != retained);
            LOGVOLE_REQUIRE_EQ(incomplete.mComplete.size(), active.size());
            for (std::size_t row = 0; row < active.size(); ++row)
                LOGVOLE_EXPECT_EQ(incomplete.mComplete[row], active[row] ? 0u : 1u);

            std::vector<std::uint64_t> host{marker};
            gpu::DeviceScalarsPtr device = retained;
            {
                ScopedEnvironmentValue decline("LV_GPU_SETUP_GAUSSIAN_RESIDENT_FORCE_DECLINE", "1");
                LOGVOLE_REQUIRE_FALSE(gpu::sampleGaussianCompactResidentDevice(
                    seeds, degree, sigma, 19.2, ringModulusValue(ctx, 0), direct, 0, active));
                LOGVOLE_REQUIRE_TRUE(direct.mValues == retained && direct.mComplete == retainedFlags);
                LOGVOLE_REQUIRE_FALSE(samplePolyErrorCompactBatchForSetup(
                    host, device, sigma, 19.2, seeds, ctx, 4, active));
                LOGVOLE_REQUIRE_TRUE(host == std::vector<std::uint64_t>{marker} && device == retained);
                ScopedEnvironmentValue allowReplay("LV_GPU_SETUP_GAUSSIAN_RESIDENT_STRICT", "0");
                LOGVOLE_REQUIRE_TRUE(samplePolyErrorCompactBatchForSetup(
                    host, device, sigma, 19.2, seeds, ctx, 4, active));
                LOGVOLE_REQUIRE_TRUE(host == expected && device == nullptr);
            }
            {
                // Explicit rollback and disabled GPU selection both retain
                // exact host output despite resident strict mode.
                ScopedEnvironmentValue rollback("LV_GPU_SETUP_GAUSSIAN_RESIDENT", "0");
                host.assign(1, marker);
                device = retained;
                LOGVOLE_REQUIRE_TRUE(samplePolyErrorCompactBatchForSetup(
                    host, device, sigma, 19.2, seeds, ctx, 1, active));
                LOGVOLE_REQUIRE_TRUE(host == expected && device == nullptr);
            }
            {
                ScopedGpuEnabled cpuOnly(false);
                host.assign(1, marker);
                device = retained;
                LOGVOLE_REQUIRE_TRUE(samplePolyErrorCompactBatchForSetup(
                    host, device, sigma, 19.2, seeds, ctx, 1, active));
                LOGVOLE_REQUIRE_TRUE(host == expected && device == nullptr);
            }
            host.assign(1, marker);
            device = retained;
            LOGVOLE_REQUIRE_FALSE(samplePolyErrorCompactBatchForSetup(host, device, sigma, 19.2,
                seeds, ctx, 4, std::span<const std::uint8_t>(active).first(3)));
            LOGVOLE_REQUIRE_TRUE(host == std::vector<std::uint64_t>{marker} && device == retained);
            LOGVOLE_REQUIRE_FALSE(samplePolyErrorCompactBatchForSetup(
                host, device, sigma, std::numeric_limits<double>::infinity(), seeds, ctx, 4, active));
            LOGVOLE_REQUIRE_TRUE(host == std::vector<std::uint64_t>{marker} && device == retained);
            {
                ScopedEnvironmentValue incompatibleSelection("LV_GPU_SETUP_GAUSSIAN_TRANSFORM", "0");
                LOGVOLE_REQUIRE_FALSE(samplePolyErrorCompactBatchForSetup(
                    host, device, sigma, 19.2, seeds, ctx, 4, active));
                LOGVOLE_REQUIRE_TRUE(host == std::vector<std::uint64_t>{marker} && device == retained);
            }
            LOGVOLE_REQUIRE_FALSE(materializePolyErrorCompactBatchForSetup(host, device,
                sigma, 19.2, std::span<const seal::prng_seed_type>(seeds).first(3), ctx));
            LOGVOLE_REQUIRE_TRUE(host == std::vector<std::uint64_t>{marker} && device == retained);
            {
                // An absent device result can be materialized by exact seeded
                // CPU replay without changing any retained device owner.
                gpu::DeviceScalarsPtr absent;
                std::vector<std::uint64_t> replayHost{marker};
                LOGVOLE_REQUIRE_TRUE(materializePolyErrorCompactBatchForSetup(
                    replayHost, absent, sigma, 19.2, seeds, ctx, 4, active));
                LOGVOLE_REQUIRE_TRUE(replayHost == expected && absent == nullptr);
            }
            {
                // A completed device owner remains valid across a CPU-only
                // consumer; materialization replays its original seeds without
                // fetching, replacing, or releasing that retained owner.
                ScopedGpuEnabled cpuOnly(false);
                const auto retainedOwner = device;
                std::vector<std::uint64_t> replayHost{marker};
                LOGVOLE_REQUIRE_TRUE(materializePolyErrorCompactBatchForSetup(
                    replayHost, device, sigma, 19.2, seeds, ctx, 4, active));
                LOGVOLE_REQUIRE_TRUE(replayHost == expected && device == retainedOwner);
            }
            LOGVOLE_REQUIRE_FALSE(gpu::sampleGaussianCompactResidentDevice(
                seeds, 0u, sigma, 19.2, ringModulusValue(ctx, 0), direct));
            LOGVOLE_REQUIRE_TRUE(direct.mValues == retained && direct.mComplete == retainedFlags);
            LOGVOLE_REQUIRE_FALSE(gpu::sampleGaussianCompactResidentDevice(
                seeds, degree, sigma, 19.2, ringModulusValue(ctx, 0), direct, 0,
                std::span<const std::uint8_t>(active).first(3)));
            LOGVOLE_REQUIRE_TRUE(direct.mValues == retained && direct.mComplete == retainedFlags);
            LOGVOLE_REQUIRE_FALSE(gpu::sampleGaussianCompactResidentDevice(
                {}, degree, sigma, 19.2, ringModulusValue(ctx, 0), direct));
            LOGVOLE_REQUIRE_TRUE(direct.mValues == retained && direct.mComplete == retainedFlags);
            {
                struct RestoreRounding
                {
                    int mode = std::fegetround();
                    ~RestoreRounding() { std::fesetround(mode); }
                } rounding;
                LOGVOLE_REQUIRE_EQ(std::fesetround(FE_UPWARD), 0);
                LOGVOLE_REQUIRE_FALSE(gpu::sampleGaussianCompactResidentDevice(
                    seeds, degree, sigma, 19.2, ringModulusValue(ctx, 0), direct, 0, active));
                LOGVOLE_REQUIRE_TRUE(direct.mValues == retained && direct.mComplete == retainedFlags);
                LOGVOLE_REQUIRE_FALSE(samplePolyErrorCompactBatchForSetup(
                    host, device, sigma, 19.2, seeds, ctx, 4, active));
                LOGVOLE_REQUIRE_TRUE(host == std::vector<std::uint64_t>{marker} && device == retained);
            }

            const std::vector<std::uint8_t> inactive(count, 0);
            LOGVOLE_REQUIRE_TRUE(samplePolyErrorCompactBatchForSetup(
                host, device, sigma, 19.2, seeds, ctx, 4, inactive));
            LOGVOLE_REQUIRE_TRUE(host.empty() && device != nullptr && device->count() == words);
            LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(*device, fetched));
            LOGVOLE_REQUIRE_TRUE(std::all_of(fetched.begin(), fetched.end(), [](auto x) { return x == 0u; }));
            LOGVOLE_REQUIRE_TRUE(samplePolyErrorCompactBatchForSetup(host, device, sigma, 19.2, {}, ctx));
            LOGVOLE_REQUIRE_TRUE(host.empty() && device == nullptr);
            LOGVOLE_REQUIRE_TRUE(gpu::fetchScalars(*retained, fetched));
            LOGVOLE_REQUIRE_TRUE(fetched == expected);
        }
    }
#else
    (void)cmd;
    LOGVOLE_SKIP() << "requires ENABLE_LOGVOLE_CUDA";
#endif
}

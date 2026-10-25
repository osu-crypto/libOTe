#include "libOTe/Vole/LogVole/LogVole.h"
#include "libOTe/Vole/LogVole/LogVoleGarbled.h"
#include "libOTe/Vole/LogVole/LogVoleRuntime.h"
#include "libOTe/config.h"
#if defined(ENABLE_LOGVOLE_CUDA)
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuBackend.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuProtocol.h"
#endif
#include "libOTe_Tests/LogVole_TestUtil.h"

#include <algorithm>
#include <array>
#include <cstdlib>
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
            if (const char* old = std::getenv(name))
            {
                mHadOld = true;
                mOld = old;
            }
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

    RingParams makeParams(std::uint32_t degree, const std::vector<int>& widths)
    {
        RingParams params{};
        params.mPolyModulusDegree = degree;
        params.mCoeffModulusBits.resize(widths.size());
        std::copy(widths.begin(), widths.end(),
            params.mCoeffModulusBits.begin());
        return params;
    }

    void expectSameMetadata(const RingNttContext& ring,
        const ZpCrtContext& zp, const RingNttContext& eagerRing,
        const ZpCrtContext& eagerZp)
    {
        LOGVOLE_REQUIRE_EQ(ringModulusCount(ring),
            ringModulusCount(eagerRing));
        for (std::size_t j = 0; j < ringModulusCount(ring); ++j)
            LOGVOLE_EXPECT_EQ(ringModulusValue(ring, j),
                ringModulusValue(eagerRing, j));
        LOGVOLE_EXPECT_EQ(zp.mPlaintextModulus,
            eagerZp.mPlaintextModulus);
        LOGVOLE_EXPECT_EQ(zp.mPlaintextModulusBits,
            eagerZp.mPlaintextModulusBits);
        LOGVOLE_REQUIRE_EQ(zp.mPlaintextLiftModQj.size(),
            eagerZp.mPlaintextLiftModQj.size());
        for (std::size_t j = 0; j < zp.mPlaintextLiftModQj.size(); ++j)
            LOGVOLE_EXPECT_EQ(zp.mPlaintextLiftModQj[j],
                eagerZp.mPlaintextLiftModQj[j]);
    }
}

void LogVole_NativeSealBundle_ExactParityAndRollback(const oc::CLP&)
{
#if defined(ENABLE_LOGVOLE_CUDA)
    if (!gpu::available()) return;
    const bool wasEnabled = gpu::enabled();
    gpu::setEnabled(true);
    struct RestoreGpu
    {
        bool old;
        ~RestoreGpu() { gpu::setEnabled(old); }
    } restore{wasEnabled};
    ScopedEnvironmentValue fullChain("LV_GPU_SETUP_FULL_MOD_CHAIN", "0");
    ScopedEnvironmentValue ringMode("LV_GPU_SETUP_LIGHTWEIGHT_RING", "1");
    ScopedEnvironmentValue crtMode("LV_GPU_SETUP_LIGHTWEIGHT_CRT", "1");
    ScopedEnvironmentValue singleLimb("LV_GPU_SETUP_BATCHING_SINGLE_LIMB", "1");
    ScopedEnvironmentValue bundleMode("LV_GPU_NATIVE_SEAL_BUNDLE", "1");
    struct Case
    {
        std::uint32_t degree;
        std::vector<int> widths;
        std::uint32_t plaintextBits;
        bool production;
    };
    const std::array<Case, 5> cases{{
        {1024u, {30, 30}, 30u, false},
        {2048u, {30, 31, 30}, 30u, false},
        {65536u, {30, 31, 30, 31, 30, 31, 30, 31, 30}, 30u, false},
        {8192u, {55, 55, 55, 55}, 55u, true},
        {16384u, {52, 52, 52, 52, 52, 52, 52, 52}, 52u, true}
    }};
    for (const auto& [degree, widths, plaintextBits, production] : cases)
    {
        const auto params = makeParams(degree, widths);
        const auto run = allocateProtocolCacheRunId();
        std::array<RingNttContext, 2> bundledRing{};
        std::array<ZpCrtContext, 2> bundledZp{};
        for (std::size_t party = 0; party < 2; ++party)
        {
            const auto role = party ? ProtocolCacheRole::Receiver :
                ProtocolCacheRole::Sender;
            ScopedProtocolCacheScope owner(role, run);
            std::shared_ptr<gpu::GpuPlainNtt> priorPlain;
            std::shared_ptr<gpu::GpuRing> priorDeviceRing;
            bool priorPlainAlreadyNative = false;
            if (production)
            {
                {
                    ScopedProtocolCacheScope noRun(role, 0u);
                    RingNttContext earlyRing{};
                    ZpCrtContext earlyZp{};
                    LOGVOLE_REQUIRE_TRUE(makeNativeSealSetupContexts(
                        params, plaintextBits, earlyRing, earlyZp));
                    LOGVOLE_REQUIRE_FALSE(earlyZp.mNativeSealBundleCommitted);
                }
                // The native publication must supersede a same-role table
                // created by an explicit sequential opt-out.
                ScopedEnvironmentValue optOut(
                    "LV_GPU_NATIVE_SEAL_BUNDLE", "0");
                RingNttContext priorRing{};
                ZpCrtContext priorZp{};
                LOGVOLE_REQUIRE_TRUE(makeNativeSealSetupContexts(
                    params, plaintextBits, priorRing, priorZp));
                LOGVOLE_REQUIRE_FALSE(priorZp.mNativeSealBundleCommitted);
                priorDeviceRing = gpu::GpuRing::get(priorRing);
                LOGVOLE_REQUIRE_TRUE(priorDeviceRing != nullptr);
                priorPlain = gpu::GpuPlainNtt::getRaw(
                    degree, priorZp.mPlaintextModulus);
                LOGVOLE_REQUIRE_TRUE(priorPlain != nullptr);
                priorPlainAlreadyNative =
                    priorPlain->nativeBundleOwnerRole() == role;
            }
            LOGVOLE_REQUIRE_TRUE(makeNativeSealSetupContexts(
                params, plaintextBits, bundledRing[party], bundledZp[party]));
            LOGVOLE_REQUIRE_TRUE(bundledZp[party].mNativeSealBundleCommitted);
            LOGVOLE_REQUIRE_TRUE(bundledRing[party].mGpuLightweight &&
                bundledZp[party].mGpuLightweight &&
                bundledRing[party].mRawModuli &&
                bundledRing[party].mRawModuli->mDynamicGpuCertificate &&
                bundledZp[party].mNativePlainNtt);
            const auto& certificate =
                bundledRing[party].mRawModuli->mDynamicGpuCertificate;
            LOGVOLE_REQUIRE_TRUE(gpu::GpuRing::get(bundledRing[party]) ==
                certificate);
            LOGVOLE_EXPECT_EQ(certificate->rawOwnerRole(), role);
            LOGVOLE_EXPECT_EQ(
                bundledZp[party].mNativePlainNtt->nativeBundleOwnerRole(),
                role);
            LOGVOLE_REQUIRE_TRUE(gpu::GpuPlainNtt::getRaw(
                degree, bundledZp[party].mPlaintextModulus) ==
                bundledZp[party].mNativePlainNtt);
            RingNttContext standaloneRing{};
            LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, standaloneRing));
            LOGVOLE_REQUIRE_TRUE(standaloneRing.mRawModuli &&
                standaloneRing.mRawModuli->mDynamicGpuCertificate ==
                    certificate);
            LOGVOLE_REQUIRE_TRUE(gpu::GpuRing::get(standaloneRing) ==
                certificate);
            LOGVOLE_REQUIRE_TRUE(gpu::GpuRing::getRaw(params,
                standaloneRing.mRawModuli->mValues) == certificate);
            if (production)
            {
                // A preceding test can already have published the native
                // same-role owner. In that case this call reuses it; only a
                // genuinely sequential prior table must be superseded.
                LOGVOLE_REQUIRE_TRUE(priorPlainAlreadyNative
                    ? priorPlain == bundledZp[party].mNativePlainNtt
                    : priorPlain != bundledZp[party].mNativePlainNtt);
                ScopedEnvironmentValue explicitFallback(
                    "LV_GPU_NATIVE_SEAL_BUNDLE", "0");
                RingNttContext fallbackRing{};
                LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, fallbackRing));
                LOGVOLE_REQUIRE_TRUE(fallbackRing.mRawModuli &&
                    !fallbackRing.mRawModuli->mDynamicGpuCertificate);
                LOGVOLE_REQUIRE_TRUE(gpu::GpuRing::get(fallbackRing) ==
                    priorDeviceRing);
                LOGVOLE_REQUIRE_TRUE(gpu::GpuRing::getRaw(params,
                    fallbackRing.mRawModuli->mValues) == priorDeviceRing);
                LOGVOLE_REQUIRE_TRUE(gpu::GpuPlainNtt::getRaw(degree,
                    bundledZp[party].mPlaintextModulus) == priorPlain);
            }
            const auto expectedQ = seal::CoeffModulus::Create(degree, widths);
            for (std::size_t j = 0; j < widths.size(); ++j)
                LOGVOLE_EXPECT_EQ(ringModulusValue(bundledRing[party], j),
                    expectedQ[j].value());
            RingNttContext eagerRing{};
            ZpCrtContext eagerZp{};
            {
                ScopedEnvironmentValue eagerRingMode(
                    "LV_GPU_SETUP_LIGHTWEIGHT_RING", "0");
                ScopedEnvironmentValue eagerCrtMode(
                    "LV_GPU_SETUP_LIGHTWEIGHT_CRT", "0");
                LOGVOLE_REQUIRE_TRUE(makeNativeSealSetupContexts(
                    params, plaintextBits, eagerRing, eagerZp));
            }
            LOGVOLE_REQUIRE_FALSE(eagerZp.mNativeSealBundleCommitted);
            expectSameMetadata(bundledRing[party], bundledZp[party],
                eagerRing, eagerZp);
            RingNttContext optOutRing{};
            ZpCrtContext optOutZp{};
            {
                ScopedEnvironmentValue optOut(
                    "LV_GPU_NATIVE_SEAL_BUNDLE", "0");
                LOGVOLE_REQUIRE_TRUE(makeNativeSealSetupContexts(
                    params, plaintextBits, optOutRing, optOutZp));
            }
            LOGVOLE_REQUIRE_FALSE(optOutZp.mNativeSealBundleCommitted);
            expectSameMetadata(bundledRing[party], bundledZp[party],
                optOutRing, optOutZp);
            const auto laterRun = allocateProtocolCacheRunId();
            {
                ScopedProtocolCacheScope sameRole(role, laterRun);
                RingNttContext reusedRing{};
                ZpCrtContext reusedZp{};
                LOGVOLE_REQUIRE_TRUE(makeNativeSealSetupContexts(
                    params, plaintextBits, reusedRing, reusedZp));
                LOGVOLE_REQUIRE_TRUE(reusedZp.mNativeSealBundleCommitted);
                LOGVOLE_REQUIRE_TRUE(
                    reusedRing.mRawModuli->mDynamicGpuCertificate ==
                    certificate);
                LOGVOLE_REQUIRE_TRUE(reusedZp.mNativePlainNtt ==
                    bundledZp[party].mNativePlainNtt);
                RingNttContext standaloneReused{};
                LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params,
                    standaloneReused));
                LOGVOLE_REQUIRE_TRUE(standaloneReused.mRawModuli &&
                    standaloneReused.mRawModuli->mDynamicGpuCertificate ==
                        certificate);
            }
        }
        LOGVOLE_REQUIRE_TRUE(
            bundledRing[0].mRawModuli->mDynamicGpuCertificate !=
            bundledRing[1].mRawModuli->mDynamicGpuCertificate);
        LOGVOLE_REQUIRE_TRUE(bundledZp[0].mNativePlainNtt !=
            bundledZp[1].mNativePlainNtt);
        {
            ScopedProtocolCacheScope receiver(
                ProtocolCacheRole::Receiver, allocateProtocolCacheRunId());
            LOGVOLE_REQUIRE_TRUE(
                gpu::GpuRing::get(bundledRing[0]) == nullptr);
        }
        {
            ScopedProtocolCacheScope sender(
                ProtocolCacheRole::Sender, allocateProtocolCacheRunId());
            auto failedQ = params;
            failedQ.mCoeffModulusBits[0] = 2;
            gpu::NativeSealSetupBundle untouched{};
            untouched.mPlaintextPrime = 0xdecafbadULL;
            untouched.mOwnerRunId = 91u;
            LOGVOLE_REQUIRE_FALSE(
                gpu::buildNativeSealSetupBundleDevice(
                    failedQ, plaintextBits, untouched));
            LOGVOLE_EXPECT_EQ(untouched.mPlaintextPrime,
                0xdecafbadULL);
            LOGVOLE_EXPECT_EQ(untouched.mOwnerRunId, 91u);
            LOGVOLE_REQUIRE_FALSE(
                gpu::buildNativeSealSetupBundleDevice(
                    params, 2u, untouched));
            LOGVOLE_EXPECT_EQ(untouched.mPlaintextPrime,
                0xdecafbadULL);
            LOGVOLE_EXPECT_EQ(untouched.mOwnerRunId, 91u);
        }
    }
#endif
}

void LogVole_NativeSealBundle_ProductionConfigureUsesDeviceAndFreshRuns(
    const oc::CLP&)
{
#if defined(ENABLE_LOGVOLE_CUDA)
    if (!gpu::available()) return;
    const bool wasEnabled = gpu::enabled();
    gpu::setEnabled(true);
    struct RestoreGpu
    {
        bool old;
        ~RestoreGpu() { gpu::setEnabled(old); }
    } restore{wasEnabled};
    ScopedEnvironmentValue fullChain("LV_GPU_SETUP_FULL_MOD_CHAIN", "0");
    ScopedEnvironmentValue ringMode("LV_GPU_SETUP_LIGHTWEIGHT_RING", "1");
    ScopedEnvironmentValue crtMode("LV_GPU_SETUP_LIGHTWEIGHT_CRT", "1");
    ScopedEnvironmentValue singleLimb("LV_GPU_SETUP_BATCHING_SINGLE_LIMB", "1");
    ScopedEnvironmentValue bundleMode("LV_GPU_NATIVE_SEAL_BUNDLE", "1");
    ScopedProtocolCacheScope noIncomingRun(
        ProtocolCacheRole::Unspecified, 0u);
    const auto previousScope = currentProtocolCacheScope();
    struct ProductionSetting
    {
        CivoleSetting setting;
        std::uint32_t requestedBits;
        std::uint64_t exactPrime;
    };
    const std::array<ProductionSetting, 2> cases{{
        {CivoleSetting::GoldenSeed, 55u, 18014398508400641ULL},
        {CivoleSetting::NoGoldenSeed, 52u, 2251799813554177ULL}
    }};
    for (const auto& [setting, requestedBits, exactPrime] : cases)
    {
        osuCrypto::LogVoleSender senderA, senderB;
        osuCrypto::LogVoleReceiver receiverA, receiverB;
        senderA.configure(8u, requestedBits, 1u, setting);
        senderB.configure(8u, requestedBits, 1u, setting);
        receiverA.configure(8u, requestedBits, 1u, setting);
        receiverB.configure(8u, requestedBits, 1u, setting);
        const std::array<std::uint64_t, 4> runs{{
            senderA.configureCacheRunId(), senderB.configureCacheRunId(),
            receiverA.configureCacheRunId(), receiverB.configureCacheRunId()
        }};
        for (std::size_t i = 0; i < runs.size(); ++i)
        {
            LOGVOLE_REQUIRE_TRUE(runs[i] != 0u);
            for (std::size_t j = 0; j < i; ++j)
                LOGVOLE_REQUIRE_TRUE(runs[i] != runs[j]);
        }
        LOGVOLE_REQUIRE_TRUE(senderA.nativeSealBundleAtConfigure());
        LOGVOLE_REQUIRE_TRUE(senderB.nativeSealBundleAtConfigure());
        LOGVOLE_REQUIRE_TRUE(receiverA.nativeSealBundleAtConfigure());
        LOGVOLE_REQUIRE_TRUE(receiverB.nativeSealBundleAtConfigure());
        for (auto modulus : {senderA.modulus(), senderB.modulus(),
                 receiverA.modulus(), receiverB.modulus()})
            LOGVOLE_EXPECT_EQ(modulus, exactPrime);
        LOGVOLE_EXPECT_EQ(currentProtocolCacheScope().mRole,
            previousScope.mRole);
        LOGVOLE_EXPECT_EQ(currentProtocolCacheScope().mRunId,
            previousScope.mRunId);

        CivoleParams params{};
        LOGVOLE_REQUIRE_TRUE(makeCivoleParams(setting, params, 1u));
        std::array<ZpCrtContext, 2> selected{};
        for (std::size_t party = 0; party < selected.size(); ++party)
        {
            const auto role = party ? ProtocolCacheRole::Receiver :
                ProtocolCacheRole::Sender;
            ScopedProtocolCacheScope owner(role, runs[party ? 2u : 0u]);
            LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(
                params.mLogVole.mShrinkExpand.mRing,
                params.mLogVole.mShrinkExpand.mPlaintextModulusBits,
                selected[party]));
            LOGVOLE_REQUIRE_TRUE(selected[party].mNativeSealBundleCommitted);
            LOGVOLE_REQUIRE_TRUE(selected[party].mNativePlainNtt &&
                selected[party].mRing.mRawModuli &&
                selected[party].mRing.mRawModuli->mDynamicGpuCertificate);
            LOGVOLE_EXPECT_EQ(
                selected[party].mNativePlainNtt->nativeBundleOwnerRole(), role);
            LOGVOLE_EXPECT_EQ(
                selected[party].mRing.mRawModuli->mDynamicGpuCertificate->rawOwnerRole(),
                role);
            RingNttContext standalone{};
            LOGVOLE_REQUIRE_TRUE(makeRingNttContext(
                params.mLogVole.mShrinkExpand.mRing, standalone));
            LOGVOLE_REQUIRE_TRUE(standalone.mRawModuli &&
                standalone.mRawModuli->mDynamicGpuCertificate ==
                    selected[party].mRing.mRawModuli->mDynamicGpuCertificate);
            LOGVOLE_REQUIRE_TRUE(gpu::GpuRing::get(standalone) ==
                standalone.mRawModuli->mDynamicGpuCertificate);
            LOGVOLE_REQUIRE_TRUE(gpu::GpuRing::getRaw(
                params.mLogVole.mShrinkExpand.mRing,
                standalone.mRawModuli->mValues) ==
                standalone.mRawModuli->mDynamicGpuCertificate);
            LOGVOLE_REQUIRE_TRUE(gpu::GpuPlainNtt::getRaw(
                standalone.mParams.mPolyModulusDegree,
                selected[party].mPlaintextModulus) ==
                selected[party].mNativePlainNtt);
            {
                // Runtime callbacks use the party role with run ID zero after
                // configure has published the native owners under a fresh run.
                // That sequential scope must select the same native cache lane.
                ScopedProtocolCacheScope sequentialRole(role, 0u);
                ZpCrtContext sequential{};
                LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(
                    params.mLogVole.mShrinkExpand.mRing,
                    params.mLogVole.mShrinkExpand.mPlaintextModulusBits,
                    sequential));
                LOGVOLE_REQUIRE_TRUE(sequential.mNativeSealBundleCommitted);
                LOGVOLE_REQUIRE_TRUE(sequential.mNativePlainNtt ==
                    selected[party].mNativePlainNtt);
                LOGVOLE_REQUIRE_TRUE(sequential.mRing.mRawModuli &&
                    sequential.mRing.mRawModuli->mDynamicGpuCertificate ==
                        selected[party].mRing.mRawModuli->mDynamicGpuCertificate);

                RingNttContext sequentialStandalone{};
                LOGVOLE_REQUIRE_TRUE(makeRingNttContext(
                    params.mLogVole.mShrinkExpand.mRing,
                    sequentialStandalone));
                LOGVOLE_REQUIRE_TRUE(sequentialStandalone.mRawModuli &&
                    sequentialStandalone.mRawModuli->mDynamicGpuCertificate ==
                        selected[party].mRing.mRawModuli->mDynamicGpuCertificate);
                LOGVOLE_REQUIRE_TRUE(gpu::GpuRing::get(
                    sequentialStandalone) ==
                        selected[party].mRing.mRawModuli->mDynamicGpuCertificate);
                LOGVOLE_REQUIRE_TRUE(gpu::GpuRing::getRaw(
                    params.mLogVole.mShrinkExpand.mRing,
                    sequentialStandalone.mRawModuli->mValues) ==
                        selected[party].mRing.mRawModuli->mDynamicGpuCertificate);
                LOGVOLE_REQUIRE_TRUE(gpu::GpuPlainNtt::getRaw(
                    sequentialStandalone.mParams.mPolyModulusDegree,
                    sequential.mPlaintextModulus) ==
                        selected[party].mNativePlainNtt);
            }
            {
                ScopedEnvironmentValue explicitFallback(
                    "LV_GPU_NATIVE_SEAL_BUNDLE", "0");
                RingNttContext fallback{};
                LOGVOLE_REQUIRE_TRUE(makeRingNttContext(
                    params.mLogVole.mShrinkExpand.mRing, fallback));
                LOGVOLE_REQUIRE_TRUE(fallback.mRawModuli &&
                    !fallback.mRawModuli->mDynamicGpuCertificate);
                LOGVOLE_REQUIRE_TRUE(gpu::GpuRing::get(fallback) !=
                    standalone.mRawModuli->mDynamicGpuCertificate);
                LOGVOLE_REQUIRE_TRUE(gpu::GpuPlainNtt::getRaw(
                    fallback.mParams.mPolyModulusDegree,
                    selected[party].mPlaintextModulus) !=
                    selected[party].mNativePlainNtt);
            }
        }
        LOGVOLE_REQUIRE_TRUE(selected[0].mNativePlainNtt !=
            selected[1].mNativePlainNtt);
        LOGVOLE_REQUIRE_TRUE(
            selected[0].mRing.mRawModuli->mDynamicGpuCertificate !=
            selected[1].mRing.mRawModuli->mDynamicGpuCertificate);

        osuCrypto::LogVoleGarbledSender garbledSenderA, garbledSenderB;
        osuCrypto::LogVoleGarbledReceiver garbledReceiverA, garbledReceiverB;
        garbledSenderA.configure(1u, 1u, setting);
        garbledSenderB.configure(1u, 1u, setting);
        garbledReceiverA.configure(1u, 1u, setting);
        garbledReceiverB.configure(1u, 1u, setting);
        const std::array<std::uint64_t, 4> garbledRuns{{
            garbledSenderA.configureCacheRunId(),
            garbledSenderB.configureCacheRunId(),
            garbledReceiverA.configureCacheRunId(),
            garbledReceiverB.configureCacheRunId()
        }};
        for (std::size_t i = 0; i < garbledRuns.size(); ++i)
        {
            LOGVOLE_REQUIRE_TRUE(garbledRuns[i] != 0u);
            for (std::size_t j = 0; j < i; ++j)
                LOGVOLE_REQUIRE_TRUE(garbledRuns[i] != garbledRuns[j]);
            for (auto civoleRun : runs)
                LOGVOLE_REQUIRE_TRUE(garbledRuns[i] != civoleRun);
        }
        LOGVOLE_REQUIRE_TRUE(garbledSenderA.nativeSealBundleAtConfigure());
        LOGVOLE_REQUIRE_TRUE(garbledSenderB.nativeSealBundleAtConfigure());
        LOGVOLE_REQUIRE_TRUE(garbledReceiverA.nativeSealBundleAtConfigure());
        LOGVOLE_REQUIRE_TRUE(garbledReceiverB.nativeSealBundleAtConfigure());
        for (auto modulus : {garbledSenderA.modulus(),
                 garbledSenderB.modulus(), garbledReceiverA.modulus(),
                 garbledReceiverB.modulus()})
            LOGVOLE_EXPECT_EQ(modulus, exactPrime);

        const auto suppliedRun = allocateProtocolCacheRunId();
        {
            ScopedProtocolCacheScope explicitOwner(
                ProtocolCacheRole::Unspecified, suppliedRun);
            osuCrypto::LogVoleSender explicitlyScoped{};
            osuCrypto::LogVoleGarbledSender garbledScopedSender{};
            osuCrypto::LogVoleGarbledReceiver garbledScopedReceiver{};
            explicitlyScoped.configure(8u, requestedBits, 1u, setting);
            garbledScopedSender.configure(1u, 1u, setting);
            garbledScopedReceiver.configure(1u, 1u, setting);
            LOGVOLE_EXPECT_EQ(explicitlyScoped.configureCacheRunId(),
                suppliedRun);
            LOGVOLE_EXPECT_EQ(garbledScopedSender.configureCacheRunId(),
                suppliedRun);
            LOGVOLE_EXPECT_EQ(garbledScopedReceiver.configureCacheRunId(),
                suppliedRun);
            LOGVOLE_REQUIRE_TRUE(
                explicitlyScoped.nativeSealBundleAtConfigure());
            LOGVOLE_REQUIRE_TRUE(
                garbledScopedSender.nativeSealBundleAtConfigure());
            LOGVOLE_REQUIRE_TRUE(
                garbledScopedReceiver.nativeSealBundleAtConfigure());
        }
        {
            ScopedEnvironmentValue optOut("LV_GPU_NATIVE_SEAL_BUNDLE", "0");
            osuCrypto::LogVoleSender sequentialSender{};
            osuCrypto::LogVoleReceiver sequentialReceiver{};
            osuCrypto::LogVoleGarbledSender sequentialGarbledSender{};
            osuCrypto::LogVoleGarbledReceiver sequentialGarbledReceiver{};
            sequentialSender.configure(8u, requestedBits, 1u, setting);
            sequentialReceiver.configure(8u, requestedBits, 1u, setting);
            sequentialGarbledSender.configure(1u, 1u, setting);
            sequentialGarbledReceiver.configure(1u, 1u, setting);
            LOGVOLE_REQUIRE_FALSE(
                sequentialSender.nativeSealBundleAtConfigure());
            LOGVOLE_REQUIRE_FALSE(
                sequentialReceiver.nativeSealBundleAtConfigure());
            LOGVOLE_REQUIRE_FALSE(
                sequentialGarbledSender.nativeSealBundleAtConfigure());
            LOGVOLE_REQUIRE_FALSE(
                sequentialGarbledReceiver.nativeSealBundleAtConfigure());
            LOGVOLE_EXPECT_EQ(sequentialSender.modulus(), exactPrime);
            LOGVOLE_EXPECT_EQ(sequentialReceiver.modulus(), exactPrime);
            LOGVOLE_EXPECT_EQ(sequentialGarbledSender.modulus(), exactPrime);
            LOGVOLE_EXPECT_EQ(sequentialGarbledReceiver.modulus(), exactPrime);
            LOGVOLE_REQUIRE_TRUE(sequentialSender.configureCacheRunId() !=
                sequentialReceiver.configureCacheRunId());
        }
        senderA.clear();
        receiverA.clear();
        LOGVOLE_EXPECT_EQ(senderA.configureCacheRunId(), 0u);
        LOGVOLE_EXPECT_EQ(receiverA.configureCacheRunId(), 0u);
        LOGVOLE_REQUIRE_FALSE(senderA.nativeSealBundleAtConfigure());
        LOGVOLE_REQUIRE_FALSE(receiverA.nativeSealBundleAtConfigure());
    }
#endif
}

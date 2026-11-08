#include "libOTe/Vole/LogVole/LogVole.h"
#include "libOTe/Vole/LogVole/LogVoleGarbled.h"
#include "libOTe/Vole/LogVole/LogVoleRuntime.h"
#include "libOTe/config.h"
#include "cryptoTools/Common/CLP.h"
#if defined(ENABLE_LOGVOLE_CUDA)
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuBackend.h"
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuProtocol.h"
#endif
#include "libOTe_Tests/LogVole_TestUtil.h"

#include <algorithm>
#include <array>
#include <utility>
#include <vector>

using namespace osuCrypto::LogVole;

namespace
{
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

void LogVole_NativeSealBundle_ExactParityAndRollback(const oc::CLP& cmd)
{
    const auto identityService = ProtocolCacheService::create();
#if defined(ENABLE_LOGVOLE_CUDA)
    if (!gpu::available()) return;
    osuCrypto::LogVoleOptions options;
    options.mUseGpu = true;
    options.mAdvanced.mContexts.mNativeSealBundle = true;
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
        if (cmd.getOr("lvFactoryFast", 0) && degree == 65536u) continue;
        const auto params = makeParams(degree, widths);
        const auto run = identityService->allocate();
        std::array<RingNttContext, 2> bundledRing{};
        std::array<ZpCrtContext, 2> bundledZp{};
        for (std::size_t party = 0; party < 2; ++party)
        {
            const auto role = party ? ProtocolCacheRole::Receiver :
                ProtocolCacheRole::Sender;
            const ProtocolCacheScope owner(run, role);
            auto factory = std::make_shared<ZpContextFactory>(
                std::make_shared<RingContextFactory>(options, identityService));
            auto sequentialOptions = options;
            sequentialOptions.mAdvanced.mContexts.mNativeSealBundle = false;
            auto sequentialFactory = std::make_shared<ZpContextFactory>(
                std::make_shared<RingContextFactory>(sequentialOptions, identityService));
            std::shared_ptr<gpu::GpuPlainNtt> priorPlain;
            std::shared_ptr<gpu::GpuRing> priorDeviceRing;
            RingNttContext priorRing{};
            ZpCrtContext priorZp{};
            bool priorPlainAlreadyNative = false;
            if (production)
            {
                {
                    const ProtocolCacheScopeView noRun{{}, role};
                    RingNttContext earlyRing{};
                    ZpCrtContext earlyZp{};
                    LOGVOLE_REQUIRE_TRUE(makeNativeSealSetupContexts(
                        params, plaintextBits, earlyRing, earlyZp, factory, noRun));
                    LOGVOLE_REQUIRE_FALSE(earlyZp.mNativeSealBundleCommitted);
                }
                // Keep a separate sequential owner alive while native setup is published.
                LOGVOLE_REQUIRE_TRUE(makeNativeSealSetupContexts(
                    params, plaintextBits, priorRing, priorZp, sequentialFactory, owner));
                LOGVOLE_REQUIRE_FALSE(priorZp.mNativeSealBundleCommitted);
                priorDeviceRing = gpu::GpuRing::get(priorRing);
                LOGVOLE_REQUIRE_TRUE(priorDeviceRing != nullptr);
                priorPlain = gpu::GpuPlainNtt::getRaw(
                    degree, priorZp.mPlaintextModulus, priorRing.mResourceScope, {}, owner);
                LOGVOLE_REQUIRE_TRUE(priorPlain != nullptr);
                priorPlainAlreadyNative =
                    priorPlain->nativeBundleOwnerRole() == role;
            }
            LOGVOLE_REQUIRE_TRUE(makeNativeSealSetupContexts(
                params, plaintextBits, bundledRing[party], bundledZp[party], factory, owner));
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
                degree, bundledZp[party].mPlaintextModulus, bundledRing[party].mResourceScope, {}, owner) ==
                bundledZp[party].mNativePlainNtt);
            RingNttContext standaloneRing{};
            LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, standaloneRing, factory->ringFactory(), owner));
            LOGVOLE_REQUIRE_TRUE(standaloneRing.mRawModuli &&
                standaloneRing.mRawModuli->mDynamicGpuCertificate ==
                    certificate);
            LOGVOLE_REQUIRE_TRUE(gpu::GpuRing::get(standaloneRing) ==
                certificate);
            LOGVOLE_REQUIRE_TRUE(gpu::GpuRing::getRaw(params,
                standaloneRing.mRawModuli->mValues, standaloneRing.mResourceScope) == certificate);
            if (production)
            {
                // The native owner cannot replace the sequential owner's tables.
                LOGVOLE_REQUIRE_TRUE(priorPlainAlreadyNative
                    ? priorPlain == bundledZp[party].mNativePlainNtt
                    : priorPlain != bundledZp[party].mNativePlainNtt);
                RingNttContext fallbackRing{};
                LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params, fallbackRing, sequentialFactory->ringFactory(), owner));
                LOGVOLE_REQUIRE_TRUE(fallbackRing.mRawModuli &&
                    !fallbackRing.mRawModuli->mDynamicGpuCertificate);
                LOGVOLE_REQUIRE_TRUE(gpu::GpuRing::get(fallbackRing) ==
                    priorDeviceRing);
                LOGVOLE_REQUIRE_TRUE(gpu::GpuRing::getRaw(params,
                    fallbackRing.mRawModuli->mValues, fallbackRing.mResourceScope) == priorDeviceRing);
                LOGVOLE_REQUIRE_TRUE(gpu::GpuPlainNtt::getRaw(degree,
                    bundledZp[party].mPlaintextModulus, fallbackRing.mResourceScope, {}, owner) == priorPlain);
            }
            const auto expectedQ = seal::CoeffModulus::Create(degree, widths);
            for (std::size_t j = 0; j < widths.size(); ++j)
                LOGVOLE_EXPECT_EQ(ringModulusValue(bundledRing[party], j),
                    expectedQ[j].value());
            RingNttContext eagerRing{};
            ZpCrtContext eagerZp{};
            {
                auto eagerOptions = options;
                eagerOptions.mAdvanced.mContexts.mLightweightRing = false;
                eagerOptions.mAdvanced.mContexts.mLightweightCrt = false;
                auto eagerFactory = std::make_shared<ZpContextFactory>(
                    std::make_shared<RingContextFactory>(eagerOptions, identityService));
                LOGVOLE_REQUIRE_TRUE(makeNativeSealSetupContexts(
                    params, plaintextBits, eagerRing, eagerZp, eagerFactory, owner));
            }
            LOGVOLE_REQUIRE_FALSE(eagerZp.mNativeSealBundleCommitted);
            expectSameMetadata(bundledRing[party], bundledZp[party],
                eagerRing, eagerZp);
            RingNttContext optOutRing{};
            ZpCrtContext optOutZp{};
            {
                LOGVOLE_REQUIRE_TRUE(makeNativeSealSetupContexts(
                    params, plaintextBits, optOutRing, optOutZp, sequentialFactory, owner));
            }
            LOGVOLE_REQUIRE_FALSE(optOutZp.mNativeSealBundleCommitted);
            expectSameMetadata(bundledRing[party], bundledZp[party],
                optOutRing, optOutZp);
            const auto laterRun = identityService->allocate();
            {
                const ProtocolCacheScope sameRole(laterRun, role);
                RingNttContext reusedRing{};
                ZpCrtContext reusedZp{};
                LOGVOLE_REQUIRE_TRUE(makeNativeSealSetupContexts(
                    params, plaintextBits, reusedRing, reusedZp, factory, sameRole));
                LOGVOLE_REQUIRE_TRUE(reusedZp.mNativeSealBundleCommitted);
                LOGVOLE_REQUIRE_TRUE(
                    reusedRing.mRawModuli->mDynamicGpuCertificate ==
                    certificate);
                LOGVOLE_REQUIRE_TRUE(reusedZp.mNativePlainNtt ==
                    bundledZp[party].mNativePlainNtt);
                RingNttContext standaloneReused{};
                LOGVOLE_REQUIRE_TRUE(makeRingNttContext(params,
                    standaloneReused, factory->ringFactory(), sameRole));
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
            // Retained context ownership remains authoritative; contradictory
            // stored provenance is rejected.
            LOGVOLE_REQUIRE_TRUE(
                gpu::GpuRing::get(bundledRing[0]) ==
                    bundledRing[0].mRawModuli->mDynamicGpuCertificate);
            auto wrongOwner = bundledRing[0];
            wrongOwner.mResourceScope.mRole = ProtocolCacheRole::Receiver;
            LOGVOLE_REQUIRE_TRUE(gpu::GpuRing::get(wrongOwner) == nullptr);
        }
        {
            const ProtocolCacheScope sender(identityService->allocate(), ProtocolCacheRole::Sender);
            auto failedQ = params;
            failedQ.mCoeffModulusBits[0] = 2;
            gpu::NativeSealSetupBundle untouched{};
            untouched.mPlaintextPrime = 0xdecafbadULL;
            untouched.mOwnerRunId = identityService->qualify(91u);
            LOGVOLE_REQUIRE_FALSE(
                gpu::buildNativeSealSetupBundleDevice(
                    failedQ, plaintextBits, untouched, std::make_shared<gpu::GpuSetupContext>(options, nullptr, identityService), sender));
            LOGVOLE_EXPECT_EQ(untouched.mPlaintextPrime,
                0xdecafbadULL);
            LOGVOLE_EXPECT_EQ(untouched.mOwnerRunId, identityService->qualify(91u));
            LOGVOLE_REQUIRE_FALSE(
                gpu::buildNativeSealSetupBundleDevice(
                    params, 2u, untouched, std::make_shared<gpu::GpuSetupContext>(options, nullptr, identityService), sender));
            LOGVOLE_EXPECT_EQ(untouched.mPlaintextPrime,
                0xdecafbadULL);
            LOGVOLE_EXPECT_EQ(untouched.mOwnerRunId, identityService->qualify(91u));
        }
    }
#endif
}

void LogVole_NativeSealBundle_ProductionConfigureUsesDeviceAndFreshRuns(
    const oc::CLP&)
{
    const auto identityService = ProtocolCacheService::create();
#if defined(ENABLE_LOGVOLE_CUDA)
    if (!gpu::available()) return;
    osuCrypto::LogVoleOptions options;
    options.mUseGpu = true;
    options.mAdvanced.mContexts.mNativeSealBundle = true;
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

        auto factory = std::make_shared<ZpContextFactory>(
                std::make_shared<RingContextFactory>(options, identityService));
        osuCrypto::LogVoleOptions sessionOptions = options;
        sessionOptions.mRequestSize = 8u;
        sessionOptions.mPlaintextModulusBits = requestedBits;
        sessionOptions.mNumThreads = 1u;
        sessionOptions.mSetting = setting;
        sessionOptions.mMode = OnlineMode::Interactive;
        osuCrypto::LogVoleSender senderA(sessionOptions, factory);
        osuCrypto::LogVoleSender senderB(sessionOptions, factory);

        osuCrypto::LogVoleReceiver receiverA(sessionOptions, factory);
        osuCrypto::LogVoleReceiver receiverB(sessionOptions, factory);
        const std::array<ProtocolCacheRunId, 4> runs{{
            senderA.configureCacheIdentity(), senderB.configureCacheIdentity(),
            receiverA.configureCacheIdentity(), receiverB.configureCacheIdentity()
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

        CivoleParams params{};
        LOGVOLE_REQUIRE_TRUE(makeCivoleParams(setting, params, 1u));
        std::array<ZpCrtContext, 2> selected{};
        for (std::size_t party = 0; party < selected.size(); ++party)
        {
            const auto role = party ? ProtocolCacheRole::Receiver :
                ProtocolCacheRole::Sender;
            const ProtocolCacheScope owner(runs[party ? 2u : 0u], role);
            LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(
                params.mLogVole.mShrinkExpand.mRing,
                params.mLogVole.mShrinkExpand.mPlaintextModulusBits,
                selected[party], factory, owner));
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
                params.mLogVole.mShrinkExpand.mRing, standalone, factory->ringFactory(), owner));
            LOGVOLE_REQUIRE_TRUE(standalone.mRawModuli &&
                standalone.mRawModuli->mDynamicGpuCertificate ==
                    selected[party].mRing.mRawModuli->mDynamicGpuCertificate);
            LOGVOLE_REQUIRE_TRUE(gpu::GpuRing::get(standalone) ==
                standalone.mRawModuli->mDynamicGpuCertificate);
            LOGVOLE_REQUIRE_TRUE(gpu::GpuRing::getRaw(
                params.mLogVole.mShrinkExpand.mRing,
                standalone.mRawModuli->mValues, standalone.mResourceScope) ==
                standalone.mRawModuli->mDynamicGpuCertificate);
            LOGVOLE_REQUIRE_TRUE(gpu::GpuPlainNtt::getRaw(
                standalone.mParams.mPolyModulusDegree,
                selected[party].mPlaintextModulus, selected[party].mRing.mResourceScope, {}, owner) ==
                selected[party].mNativePlainNtt);
            {
                const ProtocolCacheScopeView otherRole{{}, party ? ProtocolCacheRole::Sender :
                    ProtocolCacheRole::Receiver};
                RingNttContext retained;
                LOGVOLE_REQUIRE_TRUE(makeRingNttContext(standalone.mParams, retained,
                    selected[party].mRing.mFactoryOwner, otherRole));
                LOGVOLE_REQUIRE_TRUE(retained.mFactoryOwner == selected[party].mRing.mFactoryOwner);
                LOGVOLE_REQUIRE_TRUE(retained.mGpuExecution == selected[party].mRing.mGpuExecution);
                LOGVOLE_REQUIRE_TRUE(gpu::GpuRing::get(retained) ==
                    selected[party].mRing.mRawModuli->mDynamicGpuCertificate);
                LOGVOLE_REQUIRE_TRUE(gpu::GpuPlainNtt::getRaw(retained.mParams.mPolyModulusDegree,
                    selected[party].mPlaintextModulus, retained.mResourceScope, {}, otherRole) ==
                    selected[party].mNativePlainNtt);
            }
            {
                // Runtime callbacks use the party role with run ID zero after
                // configure has published the native owners under a fresh run.
                // That sequential scope must select the same native cache lane.
                const ProtocolCacheScopeView sequentialRole{{}, role};
                ZpCrtContext sequential{};
                LOGVOLE_REQUIRE_TRUE(makeZpCrtContext(
                    params.mLogVole.mShrinkExpand.mRing,
                    params.mLogVole.mShrinkExpand.mPlaintextModulusBits,
                    sequential, factory, sequentialRole));
                LOGVOLE_REQUIRE_TRUE(sequential.mNativeSealBundleCommitted);
                LOGVOLE_REQUIRE_TRUE(sequential.mNativePlainNtt ==
                    selected[party].mNativePlainNtt);
                LOGVOLE_REQUIRE_TRUE(sequential.mRing.mRawModuli &&
                    sequential.mRing.mRawModuli->mDynamicGpuCertificate ==
                        selected[party].mRing.mRawModuli->mDynamicGpuCertificate);

                RingNttContext sequentialStandalone{};
                LOGVOLE_REQUIRE_TRUE(makeRingNttContext(
                    params.mLogVole.mShrinkExpand.mRing,
                    sequentialStandalone, factory->ringFactory(), sequentialRole));
                LOGVOLE_REQUIRE_TRUE(sequentialStandalone.mRawModuli &&
                    sequentialStandalone.mRawModuli->mDynamicGpuCertificate ==
                        selected[party].mRing.mRawModuli->mDynamicGpuCertificate);
                LOGVOLE_REQUIRE_TRUE(gpu::GpuRing::get(
                    sequentialStandalone) ==
                        selected[party].mRing.mRawModuli->mDynamicGpuCertificate);
                LOGVOLE_REQUIRE_TRUE(gpu::GpuRing::getRaw(
                    params.mLogVole.mShrinkExpand.mRing,
                    sequentialStandalone.mRawModuli->mValues, sequentialStandalone.mResourceScope) ==
                        selected[party].mRing.mRawModuli->mDynamicGpuCertificate);
                LOGVOLE_REQUIRE_TRUE(gpu::GpuPlainNtt::getRaw(
                    sequentialStandalone.mParams.mPolyModulusDegree,
                    sequential.mPlaintextModulus, sequential.mRing.mResourceScope, {}, sequentialRole) ==
                        selected[party].mNativePlainNtt);
            }
            {
                RingNttContext fallback{};
                auto fallbackOptions = options;
                fallbackOptions.mAdvanced.mContexts.mNativeSealBundle = false;
                LOGVOLE_REQUIRE_TRUE(makeRingNttContext(
                    params.mLogVole.mShrinkExpand.mRing, fallback,
                    std::make_shared<RingContextFactory>(fallbackOptions, factory->ringFactory()->protocolService()), owner));
                LOGVOLE_REQUIRE_TRUE(fallback.mRawModuli &&
                    !fallback.mRawModuli->mDynamicGpuCertificate);
                LOGVOLE_REQUIRE_TRUE(gpu::GpuRing::get(fallback) !=
                    standalone.mRawModuli->mDynamicGpuCertificate);
                LOGVOLE_REQUIRE_TRUE(gpu::GpuPlainNtt::getRaw(
                    fallback.mParams.mPolyModulusDegree,
                    selected[party].mPlaintextModulus, fallback.mResourceScope, {}, owner) !=
                    selected[party].mNativePlainNtt);
            }
        }
        LOGVOLE_REQUIRE_TRUE(selected[0].mNativePlainNtt !=
            selected[1].mNativePlainNtt);
        LOGVOLE_REQUIRE_TRUE(
            selected[0].mRing.mRawModuli->mDynamicGpuCertificate !=
            selected[1].mRing.mRawModuli->mDynamicGpuCertificate);

        osuCrypto::LogVoleOptions garbledOptions = options;
        garbledOptions.mRequestSize = 1u;
        garbledOptions.mNumThreads = 1u;
        garbledOptions.mSetting = setting;
        osuCrypto::LogVoleGarbledSender garbledSenderA(garbledOptions);
        osuCrypto::LogVoleGarbledSender garbledSenderB(garbledOptions);

        osuCrypto::LogVoleGarbledReceiver garbledReceiverA(garbledOptions);
        osuCrypto::LogVoleGarbledReceiver garbledReceiverB(garbledOptions);
        const std::array<ProtocolCacheRunId, 4> garbledRuns{{
            garbledSenderA.configureCacheIdentity(),
            garbledSenderB.configureCacheIdentity(),
            garbledReceiverA.configureCacheIdentity(),
            garbledReceiverB.configureCacheIdentity()
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

        const auto suppliedRun = identityService->allocate();
        {
            const ProtocolCacheScope explicitOwner(suppliedRun, ProtocolCacheRole::Unspecified);

            osuCrypto::LogVoleSender explicitlyScoped(sessionOptions, {}, explicitOwner);

            osuCrypto::LogVoleGarbledSender garbledScopedSender(garbledOptions, explicitOwner);
            osuCrypto::LogVoleGarbledReceiver garbledScopedReceiver(garbledOptions, explicitOwner);
            LOGVOLE_EXPECT_EQ(explicitlyScoped.configureCacheIdentity(),
                suppliedRun);
            LOGVOLE_EXPECT_EQ(garbledScopedSender.configureCacheIdentity(),
                suppliedRun);
            LOGVOLE_EXPECT_EQ(garbledScopedReceiver.configureCacheIdentity(),
                suppliedRun);
            LOGVOLE_REQUIRE_TRUE(
                explicitlyScoped.nativeSealBundleAtConfigure());
            LOGVOLE_REQUIRE_TRUE(
                garbledScopedSender.nativeSealBundleAtConfigure());
            LOGVOLE_REQUIRE_TRUE(
                garbledScopedReceiver.nativeSealBundleAtConfigure());
        }
        {

            osuCrypto::LogVoleOptions sequentialSenderOptions;
            sequentialSenderOptions.mRequestSize = 8u;
            sequentialSenderOptions.mPlaintextModulusBits = requestedBits;
            sequentialSenderOptions.mNumThreads = 1u;
            sequentialSenderOptions.mSetting = setting;
            osuCrypto::LogVoleSender sequentialSender(sequentialSenderOptions);
            osuCrypto::LogVoleReceiver sequentialReceiver(sequentialSenderOptions);
            osuCrypto::LogVoleOptions sequentialGarbledSenderOptions;
            sequentialGarbledSenderOptions.mRequestSize = 1u;
            sequentialGarbledSenderOptions.mNumThreads = 1u;
            sequentialGarbledSenderOptions.mSetting = setting;
            osuCrypto::LogVoleGarbledSender sequentialGarbledSender(sequentialGarbledSenderOptions);
            osuCrypto::LogVoleGarbledReceiver sequentialGarbledReceiver(sequentialGarbledSenderOptions);
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
            LOGVOLE_REQUIRE_TRUE(sequentialSender.configureCacheIdentity() !=
                sequentialReceiver.configureCacheIdentity());
        }
        senderA.clear();
        receiverA.clear();
        LOGVOLE_EXPECT_EQ(senderA.configureCacheIdentity(), ProtocolCacheRunId{});
        LOGVOLE_EXPECT_EQ(receiverA.configureCacheIdentity(), ProtocolCacheRunId{});
        LOGVOLE_REQUIRE_FALSE(senderA.nativeSealBundleAtConfigure());
        LOGVOLE_REQUIRE_FALSE(receiverA.nativeSealBundleAtConfigure());
    }
#endif
}

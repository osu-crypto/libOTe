#pragma once

#include "libOTe/Vole/LogVole/LogVoleRing.h"

#include "cryptoTools/Crypto/PRNG.h"

#include <memory>
#include <vector>

namespace osuCrypto::LogVole
{
    bool buildLhePublicANtt(const RingNttContext& ctx, u32 mu, std::vector<RnsPoly>& out);

    // Setup states borrow immutable cached public data. The mutable builder
    // above continues to return an independent copy for existing callers.
    std::shared_ptr<const std::vector<RnsPoly>> sharedLhePublicANtt(
        const RingNttContext& ctx, u32 mu);

    std::shared_ptr<const gpu::RetainedPublicUniform> retainedLhePublicANtt(
        const RingNttContext& ctx, u32 mu);

    bool multiplyByGPower(
        const RingNttContext& ctx,
        const RnsPoly& poly,
        u32 gadgetLogBase,
        u32 power,
        RnsPoly& out);

    // Internal setup can request a lazy owner for a completed GPU ciphertext.
    // Then out retains rows/columns with no host polynomials; eager fallback
    // instead returns the ordinary tensor and resets the owner. Failure leaves
    // both caller outputs unchanged. Default/public calls remain eager.
    bool lheEnc1(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& r,
        const std::vector<RnsPoly>& sk1,
        u32 gadgetLogBase,
        RingTensor& out,
        double noiseStandardDeviation = 0.0,
        double noiseMaxDeviation = 0.0,
        PRNG* prng = nullptr,
        bool rInputIsNtt = false,
        const std::vector<RnsPoly>* publicANtt = nullptr,
        u32 requestedWorkers = 1,
        std::shared_ptr<const LazyRingTensorHostState>* deferredCiphertext = nullptr,
        std::shared_ptr<const LazyLencRandomizerState> randomizers = {});

    bool lheEnc1Trunc(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& r,
        const std::vector<RnsPoly>& sk1,
        u32 gadgetLogBase,
        RingTensor& out,
        double noiseStandardDeviation = 0.0,
        double noiseMaxDeviation = 0.0,
        PRNG* prng = nullptr,
        bool rInputIsNtt = false,
        const std::vector<RnsPoly>* publicANtt = nullptr,
        u32 requestedWorkers = 1,
        std::shared_ptr<const LazyRingTensorHostState>* deferredCiphertext = nullptr,
        std::shared_ptr<const LazyLencRandomizerState> randomizers = {},
        const gpu::DeviceBatch* rootR1Device = nullptr,
        const LazyRootErrorHostState* rootR1Host = nullptr,
        const gpu::DeviceBatch* rootSecretDevice = nullptr,
        const LazyRootSecretHostState* rootSecretHost = nullptr,
        u64 rootSecretOwnerRunId = 0,
        bool topSecretDomain = false);

    bool lheApplyCt1(
        const RingNttContext& ctx,
        const RingTensor& ct1,
        const RnsPoly& digest,
        u32 gadgetLogBase,
        u32 tau,
        std::vector<RnsPoly>& out,
        bool outputNtt = false,
        u32 requestedWorkers = 1);

    bool lheApplyCt1Trunc(
        const RingNttContext& ctx,
        const RingTensor& ct1,
        const RnsPoly& digest,
        u32 gadgetLogBase,
        u32 tauHi,
        std::vector<RnsPoly>& out,
        bool outputNtt = false,
        u32 requestedWorkers = 1);

    bool buildHashedCt2(
        const RingNttContext& ctx,
        u32 mu,
        std::span<const u8> seed,
        u64 sid,
        const RnsPoly& digest,
        u64 instanceIdx,
        std::vector<RnsPoly>& out);

    bool lheDec(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& cipher,
        const RnsPoly& sk,
        std::vector<RnsPoly>& out,
        const std::vector<RnsPoly>* publicANtt = nullptr,
        bool cipherInputIsNtt = false,
        bool outputNtt = false,
        u32 requestedWorkers = 1);

    // Consuming overload: reuses the ciphertext allocation for NTT-domain
    // decryption. The coefficient-domain special case keeps its existing path.
    bool lheDec(
        const RingNttContext& ctx,
        std::vector<RnsPoly>&& cipher,
        const RnsPoly& sk,
        std::vector<RnsPoly>& out,
        const std::vector<RnsPoly>* publicANtt = nullptr,
        bool cipherInputIsNtt = false,
        bool outputNtt = false,
        u32 requestedWorkers = 1);

    bool deriveSkx(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& sk1,
        const RnsPoly& digest,
        const RnsPoly& tbkPrime,
        u32 gadgetLogBase,
        u32 tau,
        RnsPoly& out);

    bool deriveSkxTrunc(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& sk1,
        const RnsPoly& digest,
        const RnsPoly& tbkPrime,
        u32 gadgetLogBase,
        u32 tauHi,
        RnsPoly& out);
}

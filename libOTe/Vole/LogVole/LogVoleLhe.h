#pragma once
#include "libOTe/Vole/LogVole/LogVoleIdentity.h"
#include "libOTe/Vole/LogVole/LogVoleCpuRows.h"
#include "libOTe/Vole/LogVole/LogVoleCpuBenchmark.h"

#include "libOTe/Vole/LogVole/LogVoleRing.h"

#include "cryptoTools/Crypto/PRNG.h"

#include "macoro/task.h"

#include <memory>
#include <vector>

namespace macoro { class thread_pool; }

namespace osuCrypto::LogVole
{
    bool buildLhePublicANtt(const RingNttContext& ctx, u32 mu, std::vector<RnsPoly>& out, ProtocolCacheScopeView scope = {}, PendingRingOpsStats* stats = legacyRingOpsThreadLocalStats());

    // Setup states borrow immutable cached public data. The mutable builder
    // above continues to return an independent copy for existing callers.
    std::shared_ptr<const std::vector<RnsPoly>> sharedLhePublicANtt(
        const RingNttContext& ctx, u32 mu, ProtocolCacheScopeView scope = {}, PendingRingOpsStats* stats = legacyRingOpsThreadLocalStats());

    std::shared_ptr<const gpu::RetainedPublicUniform> retainedLhePublicANtt(
        const RingNttContext& ctx, u32 mu, ProtocolCacheScopeView scope = {}, PendingRingOpsStats* stats = legacyRingOpsThreadLocalStats());

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
    // Independent CPU setup phases use requestedWorkers logical tasks (zero
    // selects one), bounded by useful work; setupResults must hold every task.
    // Shared-PRNG sequential phases and GPU compatibility policy are unchanged.
    macoro::task<bool> lheEnc1(
        macoro::thread_pool& executor, std::span<u8> setupResults,
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
        LogVoleGpuSetupOptions options = {}, CpuBenchmarkState cpuBenchmark = {}, ProtocolCacheScope setupScope = {});

    macoro::task<bool> lheEnc1Trunc(
        macoro::thread_pool& executor, std::span<u8> setupResults,
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
        ProtocolCacheRunId rootSecretOwnerRunId = 0,
        bool topSecretDomain = false,
        LogVoleGpuSetupOptions options = {}, CpuBenchmarkState cpuBenchmark = {}, ProtocolCacheScope setupScope = {});

    bool lheApplyCt1(
        const RingNttContext& ctx,
        const RingTensor& ct1,
        const RnsPoly& digest,
        u32 gadgetLogBase,
        u32 tau,
        std::vector<RnsPoly>& out,
        bool outputNtt = false,
        u32 requestedWorkers = 1, PendingRingOpsStats* stats = legacyRingOpsThreadLocalStats());

    bool lheApplyCt1Trunc(
        const RingNttContext& ctx,
        const RingTensor& ct1,
        const RnsPoly& digest,
        u32 gadgetLogBase,
        u32 tauHi,
        std::vector<RnsPoly>& out,
        bool outputNtt = false,
        u32 requestedWorkers = 1, PendingRingOpsStats* stats = legacyRingOpsThreadLocalStats());

    bool buildHashedCt2(
        const RingNttContext& ctx,
        u32 mu,
        std::span<const u8> seed,
        u64 sid,
        const RnsPoly& digest,
        u64 instanceIdx,
        std::vector<RnsPoly>& out, PendingRingOpsStats* stats = legacyRingOpsThreadLocalStats());

    // Caller-owned storage for one CPU decryption chunk. No executor or
    // scheduling policy is retained here. Reused exclusively until lheDec joins.
    struct LheDecryptBuffer
    {
        RnsPoly mProduct;
        bool mOk = true;
    };

    enum class LheDomain { Coefficient, Ntt };

    // CPU-only, lazy, in-place decryption. Ciphertext and output use the same
    // domain; sk is coefficient-domain and public A is always NTT-domain.
    // NTT ciphertext coefficients must be canonical: [0, q) for each modulus q.
    // Coefficient-domain ciphertext may contain arbitrary u64 values.
    // All arguments are borrowed from creation through completion: keep them
    // alive and unchanged, with exclusive access to ciphertext and buffers.
    // Await every started operation before destroying it or reusing resources.
    // One chunk runs inline; parallel chunks require a running executor.
    // The awaiting caller may resume on an executor worker. Destroy/join that
    // executor from outside its worker threads, not from that continuation.
    // Each active product needs ringPolyCoeffCount words for coefficient-domain
    // or non-fused NTT arithmetic. Batch/coefficient allocations are retained.
    // Validation failure leaves ciphertext unchanged; execution failure may
    // leave partially decrypted rows. No work occurs before the task is awaited.
    macoro::task<bool> lheDec(
        macoro::thread_pool& executor, std::span<LheDecryptBuffer> buffers,
        const RingNttContext& ctx, std::vector<RnsPoly>& ciphertextAndOutput,
        const RnsPoly& sk, const std::vector<RnsPoly>& publicANtt,
        LheDomain domain, CpuBenchmarkState cpuBenchmark = {});

    // cpuScratch supplies exclusive reusable resources for CPU row phases.
    // Other phases/backends retain their existing execution path.
    [[deprecated("Use async in-place lheDec with explicit executor and buffers")]]
    bool lheDec(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& cipher,
        const RnsPoly& sk,
        std::vector<RnsPoly>& out,
        const std::vector<RnsPoly>* publicANtt = nullptr,
        bool cipherInputIsNtt = false,
        bool outputNtt = false,
        u32 requestedWorkers = 1, CpuBenchmarkState cpuBenchmark = {},
        detail::CpuRowScratch* cpuScratch = nullptr, ProtocolCacheScopeView scope = {});

    // Consuming overload: reuses the ciphertext allocation for NTT-domain
    // decryption. The coefficient-domain special case keeps its existing path.
    [[deprecated("Use async in-place lheDec with explicit executor and buffers")]]
    bool lheDec(
        const RingNttContext& ctx,
        std::vector<RnsPoly>&& cipher,
        const RnsPoly& sk,
        std::vector<RnsPoly>& out,
        const std::vector<RnsPoly>* publicANtt = nullptr,
        bool cipherInputIsNtt = false,
        bool outputNtt = false,
        u32 requestedWorkers = 1, CpuBenchmarkState cpuBenchmark = {},
        detail::CpuRowScratch* cpuScratch = nullptr, ProtocolCacheScopeView scope = {});

    bool deriveSkx(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& sk1,
        const RnsPoly& digest,
        const RnsPoly& tbkPrime,
        u32 gadgetLogBase,
        u32 tau,
        RnsPoly& out, PendingRingOpsStats* stats = legacyRingOpsThreadLocalStats());

    bool deriveSkxTrunc(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& sk1,
        const RnsPoly& digest,
        const RnsPoly& tbkPrime,
        u32 gadgetLogBase,
        u32 tauHi,
        RnsPoly& out, PendingRingOpsStats* stats = legacyRingOpsThreadLocalStats());
}

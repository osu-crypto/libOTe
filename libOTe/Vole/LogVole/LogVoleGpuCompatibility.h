#pragma once

// Existing synchronous GPU session paths and host fallbacks. CPU callers use
// the explicit-executor APIs in the normal headers.
#include "libOTe/Vole/LogVole/LogVoleCore.h"
#include "libOTe/Vole/LogVole/LogVoleZk.h"

namespace osuCrypto::LogVole::detail
{
    // Legacy synchronous sampling retained for GPU paths and the explicit serial
    // CPU seed-only fallback. The latter uses requestedWorkers = 1 without a pool.
    // requestedWorkers > 1 splits the coefficients across the worker pool, each
    // range drawing from its own PRNG keyed from `prng`. zeta is the receiver's
    // local randomizer, so only its distribution matters; requestedWorkers = 1
    // keeps the original single-stream draw order.
    bool gpuLegacySampleRootZeta(
        const RingNttContext& ctx,
        u32 randomizerWidth,
        u32 gadgetLogBase,
        PRNG& prng,
        std::vector<RnsPoly>& out,
        u32 requestedWorkers = 1, CpuBenchmarkState cpuBenchmark = {}, detail::CpuRowScratch* cpuSetupScratch = nullptr);

    // Exact replay of sampleRootZeta's parallel path. `taskSeeds` is ordered as
    // [poly][range], with one independent cryptoTools AES-CTR PRNG per range.
    // Keeping this boundary explicit lets the GPU consume the already-drawn
    // seeds while any allocation/launch fallback reconstructs the same zeta
    // without advancing the parent PRNG a second time. `forceFirstReject` is a
    // deterministic test hook: it treats task zero's first candidate as rejected
    // in both the CPU and GPU implementations.
    bool gpuLegacySampleRootZetaFromTaskSeeds(
        const RingNttContext& ctx,
        u32 randomizerWidth,
        u32 gadgetLogBase,
        std::span<const block> taskSeeds,
        u32 rangesPerPoly,
        std::vector<RnsPoly>& out,
        u32 requestedWorkers = 1,
        bool forceFirstReject = false, CpuBenchmarkState cpuBenchmark = {}, detail::CpuRowScratch* cpuSetupScratch = nullptr);


    bool gpuLegacyWrapZpLabelsCrt(
        const ZpCrtContext& ctx,
        std::span<const u64> labels,
        bool multiplyByDelta,
        u64 padValue,
        u32 requestedWorkers,
        std::vector<RnsPoly>& out, CpuBenchmarkState cpuBenchmark = {}, ProtocolCacheScopeView scope = {});

    bool gpuLegacyUnwrapRingLabelsCrt(
        const ZpCrtContext& ctx,
        const std::vector<RnsPoly>& labels,
        u64 zpLabelCount,
        bool scaleAndRound,
        u32 requestedWorkers,
        AlignedUnVec<u64>& out, CpuBenchmarkState cpuBenchmark = {}, ProtocolCacheScopeView scope = {});

    bool gpuLegacyLheDec(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& cipher,
        const RnsPoly& sk,
        std::vector<RnsPoly>& out,
        const std::vector<RnsPoly>* publicANtt = nullptr,
        bool cipherInputIsNtt = false,
        bool outputNtt = false,
        u32 requestedWorkers = 1, CpuBenchmarkState cpuBenchmark = {},
        detail::CpuRowScratch* cpuScratch = nullptr, ProtocolCacheScopeView scope = {});

    bool gpuLegacyLheDec(
        const RingNttContext& ctx,
        std::vector<RnsPoly>&& cipher,
        const RnsPoly& sk,
        std::vector<RnsPoly>& out,
        const std::vector<RnsPoly>* publicANtt = nullptr,
        bool cipherInputIsNtt = false,
        bool outputNtt = false,
        u32 requestedWorkers = 1, CpuBenchmarkState cpuBenchmark = {},
        detail::CpuRowScratch* cpuScratch = nullptr, ProtocolCacheScopeView scope = {});

    bool gpuLegacyLencEvalTrunc(
        const RingNttContext& ctx,
        const LencLacct& lacct,
        const std::vector<RnsPoly>& x,
        u32 mu,
        u32 tauHi,
        u32 gadgetLogBase,
        u32 plaintextModulusBits,
        std::vector<RnsPoly>& out,
        bool outputNtt = false,
        u32 requestedWorkers = 1,
        bool leafInputsAreGadget = false, CpuBenchmarkState cpuBenchmark = {},
        detail::CpuRowScratch* cpuScratch = nullptr, ProtocolCacheScopeView scope = {});

    bool gpuLegacyLencEvalTrunc(
        const RingNttContext& ctx,
        const LencLacct& lacct,
        const DigestTree& tree,
        u32 mu,
        u32 tauHi,
        u32 gadgetLogBase,
        u32 plaintextModulusBits,
        std::vector<RnsPoly>& out,
        bool outputNtt = false,
        u32 requestedWorkers = 1,
        bool leafInputsAreGadget = false, CpuBenchmarkState cpuBenchmark = {},
        detail::CpuRowScratch* cpuScratch = nullptr);

    bool gpuLegacyLencSubtractEvalTruncNttInplace(
        const RingNttContext& ctx,
        const LencLacct& lacct,
        const DigestTree& tree,
        u32 mu,
        u32 tauHi,
        u32 gadgetLogBase,
        u32 plaintextModulusBits,
        std::vector<RnsPoly>& out,
        u32 requestedWorkers = 1,
        bool leafInputsAreGadget = false, CpuBenchmarkState cpuBenchmark = {},
        detail::CpuRowScratch* cpuScratch = nullptr);

    bool gpuLegacyExpandSender(
        const ShrinkExpandSenderState& state,
        const ShrinkExpandExpandSenderInput& input,
        ShrinkExpandSenderExpandOutput& out,
        // CPU LHE allowance: outer chunk workers pass 1 to avoid nested pools.
        u32 cpuLheWorkers, CpuBenchmarkState cpuBenchmark = {}, ProtocolCacheScopeView scope = {});

    bool gpuLegacyExpandReceiver(
        const ShrinkExpandReceiverState& state,
        const ShrinkExpandExpandReceiverInput& input,
        ShrinkExpandReceiverExpandOutput& out,
        // CPU row allowance: outer chunk workers pass 1 to avoid nested pools.
        u32 cpuRowWorkers, CpuBenchmarkState cpuBenchmark = {}, ProtocolCacheScopeView scope = {});

    bool gpuLegacyDenoiseComb(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& tbaPrime,
        std::vector<RnsPoly>& out,
        u32 requestedWorkers = 1, CpuBenchmarkState cpuBenchmark = {});

    bool gpuLegacyFinalizeRootResponseReceiver(
        ReceiverState& state,
        const RootDigestState& digestState,
        const RootResponseMessage& response,
        RnsPoly& rootKey,
        std::shared_ptr<void>* rootKeyDevice = nullptr, CpuBenchmarkState cpuBenchmark = {}, ProtocolCacheScopeView cacheScope = {});

    bool gpuLegacyFinalizeRootResponseReceiver(
        ReceiverState& state,
        const RootDigestState& digestState,
        RootResponseMessage&& response,
        RnsPoly& rootKey,
        std::shared_ptr<void>* rootKeyDevice = nullptr, CpuBenchmarkState cpuBenchmark = {}, ProtocolCacheScopeView cacheScope = {});

    bool gpuLegacyComputeRootSenderKey(
        const SenderState& state,
        std::span<const u8> seed,
        RnsPoly& rootKey, CpuBenchmarkState cpuBenchmark = {}, ProtocolCacheScopeView cacheScope = {});

    bool gpuLegacySeedLabelDenoiseTbm(
        const std::vector<RnsPoly>& tbmPrime,
        u32 wPrime,
        u32 tau,
        const RingParams& ring,
        std::vector<RnsPoly>& out,
        u32 requestedWorkers = 1, CpuBenchmarkState cpuBenchmark = {});

    // Existing ZK GPU-session host fallback; CPU proofs await their executor.
    bool gpuLegacyZkMulProverResponse(
        const ZkMulCircuit& circuit,
        std::span<const u64> wires,
        std::span<const u64> macs,
        u64 chi,
        u64 modulus,
        ZkMulCpuWorkspace& workspace,
        ZkProof& out);

    bool gpuLegacyZkMulVerifierValue(
        const ZkMulCircuit& circuit,
        std::span<const u64> keys,
        u64 chi,
        u64 delta,
        u64 modulus,
        ZkMulCpuWorkspace& workspace,
        u64& out);

    bool gpuLegacyZkMatMulProverResponse(
        const ZkMatMulStatement& st,
        std::span<const u64> wires,
        std::span<const u64> macs,
        const ZkMatMulChallenge& ch,
        u64 modulus,
        u32 threads,
        std::vector<ZkProof>& out, const LogVoleZkOptions& settings = {}, CpuBenchmarkState cpuBenchmark = {});

    bool gpuLegacyZkMatMulVerifierValue(
        const ZkMatMulStatement& st,
        std::span<const u64> keys,
        std::span<const u64> publicProduct,
        const ZkMatMulChallenge& ch,
        u64 delta,
        u64 modulus,
        u32 threads,
        std::vector<u64>& out, const LogVoleZkOptions& settings = {}, CpuBenchmarkState cpuBenchmark = {});
    // Existing GPU-session candidate validation and its scheduling.
    bool gpuLegacyValidateGoldenSeedCandidate(
        const Params& params,
        const std::vector<RnsPoly>& tbkPerSampledPoly,
        bool& out, HostStepProfiler* profile = nullptr, CpuBenchmarkState cpuBenchmark = {});

    bool gpuLegacyValidateLeafGoldenSeedCandidate(
        const Params& params,
        const std::vector<RnsPoly>& tbk,
        bool& out, HostStepProfiler* profile = nullptr, CpuBenchmarkState cpuBenchmark = {});
}

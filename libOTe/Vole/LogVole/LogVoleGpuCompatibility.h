#pragma once

// Existing synchronous GPU session paths and host fallbacks. CPU callers use
// the explicit-executor APIs in the normal headers.
#include "libOTe/Vole/LogVole/LogVoleCore.h"

namespace osuCrypto::LogVole::detail
{
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

}

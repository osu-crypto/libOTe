#pragma once
#include "libOTe/Vole/LogVole/LogVoleCpuBenchmark.h"

#include "libOTe/Tools/Coproto.h"
#include "libOTe/Vole/LogVole/LogVoleCore.h"
#include "libOTe/Vole/LogVole/LogVoleShrinkExpand.h"

namespace osuCrypto::LogVole
{
    struct ProtocolCacheScope;

    struct ReceiverExpandInput
    {
        u64 mNonce = 0;
        u64 mSid = 0;
        AlignedUnVec<u8> mSeed;
        std::vector<RnsPoly> mX;
    };

    class LogVoleRingReceiver
    {
        struct OnlinePrefetchPlan;

        task<> onlineStart(
            macoro::thread_pool& executor, std::span<LheDecryptBuffer> lheBuffers,
            std::span<LencEvalBuffer> lencBuffers, std::span<RootZetaBuffer> zetaBuffers,
            ReceiverState& state, const ReceiverOnlineInput& input,
            ReceiverOnlineOutput& output, PRNG& prng, Socket& sock,
            std::shared_ptr<void> firstQueryGpuAllocations, const void* firstQueryOwner,
            ProtocolCacheScope cacheScope);

        task<> onlineImpl(
            ReceiverState& state,
            const ReceiverOnlineInput& input,
            ReceiverOnlineOutput& output,
            PRNG& prng,
            Socket& sock,
            OnlinePrefetchPlan& prefetchPlan,
            u32 recursionDepth, CpuBenchmarkState cpuBenchmark,
            macoro::thread_pool& executor, std::span<LheDecryptBuffer> lheBuffers,
            std::span<LencEvalBuffer> lencBuffers, std::span<RootZetaBuffer> zetaBuffers, ProtocolCacheScope cacheScope);

    public:
        task<> offline(
            const ShrinkExpandReceiverOfflineInput& input,
            ShrinkExpandReceiverState& state,
            Socket& sock, ProtocolCacheScope setupScope = {});

        task<> offline(
            const ReceiverOfflineInput& input,
            ReceiverState& state,
            Socket& sock,
            std::shared_ptr<void>* firstQueryGpuAllocations = nullptr,
            ProtocolCacheScope setupScope = {});

        // CPU diagnostics are borrowed through completion; null disables collection.
        // GPU execution retains the legacy diagnostic selection.
        task<> keyDerive(
            const KeyDeriveReceiverInput& input,
            KeyDeriveReceiverOutput& output,
            Socket& sock, LogVoleEncodingOptions encoding = {}, bool useGpu = false, HostStepProfiler* profile = nullptr,
            ProtocolCacheScope scope = {}, TimingStats* timing = nullptr, RingOpsStats* totals = nullptr);

        // CPU expansion resources are borrowed exclusively until completion and
        // may be reused across queries. Recursive levels share one ring shape;
        // prepare LHE products for it and LENC capacity for the largest level
        // (including root-left). Buffers bound concurrency, further capped by
        // each level's nonzero worker limit. Zeta buffers are reused at the root;
        // see RootZetaBuffer for preparation sizes. Other CPU phases remain legacy.
        // Started operations must finish before destruction. Join the executor
        // outside its workers. The GPU allocation handle is retained by value.
        task<> online(
            macoro::thread_pool& executor, std::span<LheDecryptBuffer> lheBuffers,
            std::span<LencEvalBuffer> lencBuffers, std::span<RootZetaBuffer> zetaBuffers,
            ReceiverState& state, const ReceiverOnlineInput& input,
            ReceiverOnlineOutput& output, PRNG& prng, Socket& sock,
            std::shared_ptr<void> firstQueryGpuAllocations = {},
            const void* firstQueryOwner = nullptr, ProtocolCacheScope cacheScope = {});

        // Borrow executor and exclusive prepared buffers until completion.
        // The continuation may run on an executor worker; join it externally.
        task<> expand(
            macoro::thread_pool& executor, std::span<LheDecryptBuffer> lheBuffers,
            std::span<LencEvalBuffer> lencBuffers,
            const ShrinkExpandReceiverState& state,
            const ReceiverExpandInput& input,
            ShrinkExpandReceiverExpandOutput& output,
            Socket& sock, ProtocolCacheScope cacheScope = {});
    };
}

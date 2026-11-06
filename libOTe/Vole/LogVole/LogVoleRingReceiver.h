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
            macoro::thread_pool* executor, std::span<LheDecryptBuffer> lheBuffers,
            std::span<LencEvalBuffer> lencBuffers,
            ReceiverState& state, const ReceiverOnlineInput& input,
            ReceiverOnlineOutput& output, PRNG& prng, Socket& sock,
            std::shared_ptr<void> firstQueryGpuAllocations, const void* firstQueryOwner);

        task<> onlineImpl(
            ReceiverState& state,
            const ReceiverOnlineInput& input,
            ReceiverOnlineOutput& output,
            PRNG& prng,
            Socket& sock,
            OnlinePrefetchPlan& prefetchPlan,
            u32 recursionDepth, CpuBenchmarkState cpuBenchmark,
            macoro::thread_pool* executor, std::span<LheDecryptBuffer> lheBuffers,
            std::span<LencEvalBuffer> lencBuffers, ProtocolCacheScope cacheScope);

    public:
        task<> offline(
            const ShrinkExpandReceiverOfflineInput& input,
            ShrinkExpandReceiverState& state,
            Socket& sock);

        task<> offline(
            const ReceiverOfflineInput& input,
            ReceiverState& state,
            Socket& sock,
            std::shared_ptr<void>* firstQueryGpuAllocations = nullptr);

        task<> keyDerive(
            const KeyDeriveReceiverInput& input,
            KeyDeriveReceiverOutput& output,
            Socket& sock, LogVoleEncodingOptions encoding = {}, bool useGpu = false, HostStepProfiler* profile = nullptr);

        // Root CPU resources are borrowed exclusively until completion and may
        // be reused across queries. Prepare buffers for the root level's ring
        // and both root-left/final-expansion LENC dimensions. Intermediate CPU
        // loops retain their legacy path.
        // Started operations must finish before destruction. Join the executor
        // outside its workers. The GPU allocation handle is retained by value.
        task<> online(
            macoro::thread_pool& executor, std::span<LheDecryptBuffer> lheBuffers,
            std::span<LencEvalBuffer> lencBuffers,
            ReceiverState& state, const ReceiverOnlineInput& input,
            ReceiverOnlineOutput& output, PRNG& prng, Socket& sock,
            std::shared_ptr<void> firstQueryGpuAllocations = {},
            const void* firstQueryOwner = nullptr);

        [[deprecated("Use online with explicit executor and root CPU buffers")]]
        task<> online(
            ReceiverState& state,
            const ReceiverOnlineInput& input,
            ReceiverOnlineOutput& output,
            PRNG& prng,
            Socket& sock,
            const std::shared_ptr<void>& firstQueryGpuAllocations = {},
            const void* firstQueryOwner = nullptr);

        // Borrow executor and exclusive prepared buffers until completion.
        // The continuation may run on an executor worker; join it externally.
        task<> expand(
            macoro::thread_pool& executor, std::span<LheDecryptBuffer> lheBuffers,
            std::span<LencEvalBuffer> lencBuffers,
            const ShrinkExpandReceiverState& state,
            const ReceiverExpandInput& input,
            ShrinkExpandReceiverExpandOutput& output,
            Socket& sock);
    };
}

#pragma once
#include "libOTe/Vole/LogVole/LogVoleIdentity.h"
#include "libOTe/Vole/LogVole/LogVoleCpuBenchmark.h"

#include "libOTe/Vole/LogVole/LogVoleLenc.h"
#include "libOTe/Vole/LogVole/LogVoleLhe.h"

#include "cryptoTools/Crypto/PRNG.h"

#include <memory>
#include <span>
#include <vector>

namespace osuCrypto::LogVole
{
    struct ShrinkExpandSenderOfflineInput
    {
        ShrinkExpandParams mParams;
        std::shared_ptr<gpu::GpuExecutionContext> mGpuExecution;
        std::shared_ptr<detail::ShrinkExpandScratch> mCpuScratch;
        std::shared_ptr<const RingNttContext> mRingFactoryOwner;
        std::vector<RnsPoly> mS;
        // Internal sender setup only. The exact coefficient batch is borrowed
        // by LENC before its hostS() view is requested on decline/inspection.
        std::shared_ptr<const gpu::DeviceBatch> mSDevice;
        std::shared_ptr<const LazySeedLabelHostState> mLazyS;
        std::vector<RnsPoly> mFixedSk1;
        std::shared_ptr<const gpu::DeviceBatch> mFixedSk1Device;
        std::shared_ptr<const LazyRootSecretHostState> mLazyFixedSk1;
        ProtocolCacheRunId mFixedSk1OwnerRunId = 0;
        // Only selected internal transport may defer its private top key.
        bool mDeferTopSk1Host = false;
        // Explicit internal transport opt-in; ordinary public setup stays eager.
        bool mDeferHostCiphertexts = false;
    };

    struct ShrinkExpandReceiverOfflineInput
    {
        ShrinkExpandParams mParams;
        std::shared_ptr<gpu::GpuExecutionContext> mGpuExecution;
        std::shared_ptr<detail::ShrinkExpandScratch> mCpuScratch;
        std::shared_ptr<const RingNttContext> mRingFactoryOwner;
        bool mDeferHostSnapshot = false;
    };

    struct ShrinkExpandOfflineMessage
    {
        ShrinkExpandParams mParams;
        RingTensor mCt1;
        ShrinkExpandLacct mLacct;
        std::shared_ptr<const LazyRingTensorHostState> mLazyCt1;
        std::shared_ptr<const LazyLacctHostState> mLazyLacct;
    };

    namespace detail
    {
        std::shared_ptr<const LazyLacctHostState> makeLazyLacctHostState(
            const ShrinkExpandLacct& metadata,
            std::shared_ptr<const LazyRingTensorHostState> tensor);
    }

    struct ShrinkExpandShrinkOutput
    {
        RnsPoly mDigest;
        std::shared_ptr<DigestTree> mTree;
    };

    struct ShrinkExpandExpandSenderInput
    {
        u64 mNonce = 0;
        u64 mSid = 0;
        AlignedUnVec<u8> mSeed;
        RnsPoly mDigest;
        RnsPoly mMaskDigest;
        RnsPoly mTbkPrime;
    };

    struct ShrinkExpandExpandReceiverInput
    {
        u64 mNonce = 0;
        u64 mSid = 0;
        AlignedUnVec<u8> mSeed;
        std::vector<RnsPoly> mX;
        RnsPoly mDigest;
        RnsPoly mMaskDigest;
        RnsPoly mSkX;
        std::shared_ptr<DigestTree> mTree;
    };

    struct ShrinkExpandSenderExpandOutput
    {
        std::vector<RnsPoly> mTbk;
    };

    struct ShrinkExpandReceiverExpandOutput
    {
        std::vector<RnsPoly> mTbm;
    };

    bool validateShrinkExpandParams(const ShrinkExpandParams& params);
    bool validateShrinkExpandSenderOfflineInput(const ShrinkExpandSenderOfflineInput& input);
    bool validateShrinkExpandReceiverOfflineInput(const ShrinkExpandReceiverOfflineInput& input);

    // Restore independent mutable bulk host storage for an explicit internal
    // GPU view. Also invalidate its device mirror before caller mutation. For
    // an ordinary state only the mirror is invalidated; allocation failures
    // leave an existing view unchanged.
    void materializeShrinkExpandHostState(ShrinkExpandSenderState& state);
    void materializeShrinkExpandHostState(ShrinkExpandReceiverState& state);

    std::vector<RnsPoly> sampleUniformBatch(
        const RingNttContext& ctx,
        u32 count,
        PRNG& prng);

    macoro::task<bool> prepareShrinkExpandSenderOffline(
        macoro::thread_pool& executor, std::span<u8> setupResults,
        const ShrinkExpandSenderOfflineInput& input,
        PRNG& prng,
        ShrinkExpandOfflineMessage& message,
        ShrinkExpandSenderState& senderState, CpuBenchmarkState cpuBenchmark = {}, ProtocolCacheScope setupScope = currentProtocolCacheScope());

    // State-only preparation keeps one tensor package and avoids a discarded
    // message copy. Explicit internal opt-in can defer its host ciphertexts.
    macoro::task<bool> prepareShrinkExpandSenderOffline(
        macoro::thread_pool& executor, std::span<u8> setupResults,
        const ShrinkExpandSenderOfflineInput& input,
        PRNG& prng,
        ShrinkExpandSenderState& senderState, CpuBenchmarkState cpuBenchmark = {}, ProtocolCacheScope setupScope = currentProtocolCacheScope());

    bool finalizeShrinkExpandReceiverOffline(
        const ShrinkExpandReceiverOfflineInput& input,
        const ShrinkExpandOfflineMessage& message,
        ShrinkExpandReceiverState& receiverState,
        ProtocolCacheScopeView scope = currentProtocolCacheScope());

    // Consumes ciphertext storage after validation; state is unchanged on failure.
    bool finalizeShrinkExpandReceiverOffline(
        const ShrinkExpandReceiverOfflineInput& input,
        ShrinkExpandOfflineMessage&& message,
        ShrinkExpandReceiverState& receiverState,
        ProtocolCacheScopeView scope = currentProtocolCacheScope());

    bool shrinkExpandShrink(
        const ShrinkExpandReceiverState& state,
        const std::vector<RnsPoly>& x,
        ShrinkExpandShrinkOutput& out);

    bool shrinkExpandShrink(
        const ShrinkExpandReceiverState& state,
        std::span<const RnsPoly> x,
        ShrinkExpandShrinkOutput& out);

    // CPU expansion: executor and exclusive prepared buffers are borrowed
    // until completion. Output is published only after decryption succeeds.
    macoro::task<bool> shrinkExpandExpandSender(
        macoro::thread_pool& executor, std::span<LheDecryptBuffer> buffers,
        const ShrinkExpandSenderState& state,
        const ShrinkExpandExpandSenderInput& input,
        ShrinkExpandSenderExpandOutput& out, CpuBenchmarkState cpuBenchmark = {});

    [[deprecated("Use async sender expansion with explicit executor and buffers")]]
    bool shrinkExpandExpandSender(
        const ShrinkExpandSenderState& state,
        const ShrinkExpandExpandSenderInput& input,
        ShrinkExpandSenderExpandOutput& out,
        // CPU LHE allowance: outer chunk workers pass 1 to avoid nested pools.
        u32 cpuLheWorkers, CpuBenchmarkState cpuBenchmark = {});

    // CPU expansion. All referenced objects must survive completion; buffers
    // are exclusive to this operation (not shared with a concurrent sender).
    // Prepare LHE product storage and LENC pointer capacity as their APIs require.
    // Output is published only on success. Started tasks must finish before reuse.
    macoro::task<bool> shrinkExpandExpandReceiver(
        macoro::thread_pool& executor, std::span<LheDecryptBuffer> lheBuffers,
        std::span<LencEvalBuffer> lencBuffers,
        const ShrinkExpandReceiverState& state, const ShrinkExpandExpandReceiverInput& input,
        ShrinkExpandReceiverExpandOutput& out, CpuBenchmarkState cpuBenchmark = {});

    [[deprecated("Use async receiver expansion with explicit executor and buffers")]]
    bool shrinkExpandExpandReceiver(
        const ShrinkExpandReceiverState& state,
        const ShrinkExpandExpandReceiverInput& input,
        ShrinkExpandReceiverExpandOutput& out,
        // CPU row allowance: outer chunk workers pass 1 to avoid nested pools.
        u32 cpuRowWorkers, CpuBenchmarkState cpuBenchmark = {});

    // Borrow context/input and exclusive output until completion; input may
    // alias output. Immutable recovery data is prepared once for all chunks.
    // workerAllowance bounds concurrency; one worker runs inline.
    macoro::task<bool> shrinkExpandDenoiseComb(
        macoro::thread_pool& executor, std::size_t workerAllowance,
        const RingNttContext& ctx, const std::vector<RnsPoly>& tbaPrime,
        std::vector<RnsPoly>& out, CpuBenchmarkState cpuBenchmark = {});

    [[deprecated("Use async denoise with an explicit executor and worker allowance")]]
    bool shrinkExpandDenoiseComb(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& tbaPrime,
        std::vector<RnsPoly>& out,
        u32 requestedWorkers = 1, CpuBenchmarkState cpuBenchmark = {});
}

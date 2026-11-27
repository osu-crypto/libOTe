#pragma once

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
        std::vector<RnsPoly> mS;
        // Internal sender setup only. The exact coefficient batch is borrowed
        // by LENC before its hostS() view is requested on decline/inspection.
        std::shared_ptr<const gpu::DeviceBatch> mSDevice;
        std::shared_ptr<const LazySeedLabelHostState> mLazyS;
        std::vector<RnsPoly> mFixedSk1;
        std::shared_ptr<const gpu::DeviceBatch> mFixedSk1Device;
        std::shared_ptr<const LazyRootSecretHostState> mLazyFixedSk1;
        u64 mFixedSk1OwnerRunId = 0;
        // Only selected internal transport may defer its private top key.
        bool mDeferTopSk1Host = false;
        // Explicit internal transport opt-in; ordinary public setup stays eager.
        bool mDeferHostCiphertexts = false;
    };

    struct ShrinkExpandReceiverOfflineInput
    {
        ShrinkExpandParams mParams;
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

    bool prepareShrinkExpandSenderOffline(
        const ShrinkExpandSenderOfflineInput& input,
        PRNG& prng,
        ShrinkExpandOfflineMessage& message,
        ShrinkExpandSenderState& senderState);

    // State-only preparation keeps one tensor package and avoids a discarded
    // message copy. Explicit internal opt-in can defer its host ciphertexts.
    bool prepareShrinkExpandSenderOffline(
        const ShrinkExpandSenderOfflineInput& input,
        PRNG& prng,
        ShrinkExpandSenderState& senderState);

    bool finalizeShrinkExpandReceiverOffline(
        const ShrinkExpandReceiverOfflineInput& input,
        const ShrinkExpandOfflineMessage& message,
        ShrinkExpandReceiverState& receiverState);

    // Consumes ciphertext storage after validation; state is unchanged on failure.
    bool finalizeShrinkExpandReceiverOffline(
        const ShrinkExpandReceiverOfflineInput& input,
        ShrinkExpandOfflineMessage&& message,
        ShrinkExpandReceiverState& receiverState);

    bool shrinkExpandShrink(
        const ShrinkExpandReceiverState& state,
        const std::vector<RnsPoly>& x,
        ShrinkExpandShrinkOutput& out);

    bool shrinkExpandShrink(
        const ShrinkExpandReceiverState& state,
        std::span<const RnsPoly> x,
        ShrinkExpandShrinkOutput& out);

    bool shrinkExpandExpandSender(
        const ShrinkExpandSenderState& state,
        const ShrinkExpandExpandSenderInput& input,
        ShrinkExpandSenderExpandOutput& out);

    bool shrinkExpandExpandReceiver(
        const ShrinkExpandReceiverState& state,
        const ShrinkExpandExpandReceiverInput& input,
        ShrinkExpandReceiverExpandOutput& out);

    bool shrinkExpandDenoiseComb(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& tbaPrime,
        std::vector<RnsPoly>& out,
        u32 requestedWorkers = 1);
}

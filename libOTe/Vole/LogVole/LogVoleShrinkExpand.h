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
        std::vector<RnsPoly> mFixedSk1;
    };

    struct ShrinkExpandReceiverOfflineInput
    {
        ShrinkExpandParams mParams;
    };

    struct ShrinkExpandOfflineMessage
    {
        ShrinkExpandParams mParams;
        RingTensor mCt1;
        ShrinkExpandLacct mLacct;
    };

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

    std::vector<RnsPoly> sampleUniformBatch(
        const RingNttContext& ctx,
        u32 count,
        PRNG& prng);

    bool prepareShrinkExpandSenderOffline(
        const ShrinkExpandSenderOfflineInput& input,
        PRNG& prng,
        ShrinkExpandOfflineMessage& message,
        ShrinkExpandSenderState& senderState);

    bool prepareShrinkExpandSenderOffline(
        const ShrinkExpandSenderOfflineInput& input,
        PRNG& prng,
        ShrinkExpandSenderState& senderState);

    bool finalizeShrinkExpandReceiverOffline(
        const ShrinkExpandReceiverOfflineInput& input,
        const ShrinkExpandOfflineMessage& message,
        ShrinkExpandReceiverState& receiverState);

    bool finalizeShrinkExpandReceiverOffline(
        const ShrinkExpandReceiverOfflineInput& input,
        const ShrinkExpandSenderState& senderState,
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
        std::vector<RnsPoly>& out);
}

#pragma once

#include "libOTe/Vole/LogVole2/LogVole2Lenc.h"
#include "libOTe/Vole/LogVole2/LogVole2Lhe.h"

#include <memory>
#include <vector>

namespace osuCrypto::LogVole2
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
        RnsPoly mTbkPrime;
    };

    struct ShrinkExpandExpandReceiverInput
    {
        u64 mNonce = 0;
        std::vector<RnsPoly> mX;
        RnsPoly mDigest;
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
    bool resolveShrinkExpandEffectiveNoiseBound(const ShrinkExpandParams& params, i64& out);

    std::vector<RnsPoly> sampleUniformBatch(
        const RingNttContext& ctx,
        u32 count,
        u64 seed,
        u64 domainTag);

    bool prepareShrinkExpandSenderOffline(
        const ShrinkExpandSenderOfflineInput& input,
        ShrinkExpandOfflineMessage& message,
        ShrinkExpandSenderState& senderState);

    bool prepareShrinkExpandSenderOffline(
        const ShrinkExpandSenderOfflineInput& input,
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

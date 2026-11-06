#pragma once

#include "libOTe/Tools/Coproto.h"
#include "libOTe/Vole/LogVole/LogVoleCore.h"
#include "libOTe/Vole/LogVole/LogVoleShrinkExpand.h"

namespace osuCrypto::LogVole
{
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

        task<> onlineImpl(
            ReceiverState& state,
            const ReceiverOnlineInput& input,
            ReceiverOnlineOutput& output,
            PRNG& prng,
            Socket& sock,
            OnlinePrefetchPlan& prefetchPlan,
            u32 recursionDepth);

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
            Socket& sock);

        task<> online(
            ReceiverState& state,
            const ReceiverOnlineInput& input,
            ReceiverOnlineOutput& output,
            PRNG& prng,
            Socket& sock,
            const std::shared_ptr<void>& firstQueryGpuAllocations = {},
            const void* firstQueryOwner = nullptr);

        task<> expand(
            const ShrinkExpandReceiverState& state,
            const ReceiverExpandInput& input,
            ShrinkExpandReceiverExpandOutput& output,
            Socket& sock);
    };
}

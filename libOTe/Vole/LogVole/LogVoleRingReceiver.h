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
    public:
        task<> offline(
            const ShrinkExpandReceiverOfflineInput& input,
            ShrinkExpandReceiverState& state,
            Socket& sock);

        task<> offline(
            const ReceiverOfflineInput& input,
            ReceiverState& state,
            Socket& sock);

        task<> keyDerive(
            const KeyDeriveReceiverInput& input,
            KeyDeriveReceiverOutput& output,
            Socket& sock);

        task<> online(
            ReceiverState& state,
            const ReceiverOnlineInput& input,
            ReceiverOnlineOutput& output,
            PRNG& prng,
            Socket& sock);

        task<> expand(
            const ShrinkExpandReceiverState& state,
            const ReceiverExpandInput& input,
            ShrinkExpandReceiverExpandOutput& output,
            Socket& sock);
    };
}

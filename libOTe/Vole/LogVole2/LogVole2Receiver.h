#pragma once

#include "libOTe/Tools/Coproto.h"
#include "libOTe/Vole/LogVole2/LogVole2Core.h"
#include "libOTe/Vole/LogVole2/LogVole2ShrinkExpand.h"

namespace osuCrypto::LogVole2
{
    struct ReceiverExpandInput
    {
        u64 mNonce = 0;
        std::vector<RnsPoly> mX;
    };

    class Receiver
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
            Socket& sock);

        task<> expand(
            const ShrinkExpandReceiverState& state,
            const ReceiverExpandInput& input,
            ShrinkExpandReceiverExpandOutput& output,
            Socket& sock);
    };
}

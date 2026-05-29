#pragma once

#include "libOTe/Tools/Coproto.h"
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

        task<> expand(
            const ShrinkExpandReceiverState& state,
            const ReceiverExpandInput& input,
            ShrinkExpandReceiverExpandOutput& output,
            Socket& sock);
    };
}

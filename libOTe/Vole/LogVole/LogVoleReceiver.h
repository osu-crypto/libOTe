#pragma once

#include "libOTe/Tools/Coproto.h"
#include "libOTe/Vole/LogVole/LogVoleLenc.h"

namespace osuCrypto::LogVole
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

        task<> keyDerive(
            const KeyDeriveReceiverInput& input,
            KeyDeriveReceiverOutput& output,
            Socket& sock);

        task<> expand(
            const ShrinkExpandReceiverState& state,
            const ReceiverExpandInput& input,
            ShrinkExpandReceiverExpandOutput& output,
            Socket& sock);
    };
}

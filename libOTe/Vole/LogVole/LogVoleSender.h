#pragma once

#include "libOTe/Tools/Coproto.h"
#include "libOTe/Vole/LogVole/LogVoleLenc.h"

namespace osuCrypto::LogVole
{
    class Sender
    {
    public:
        task<> offline(
            const ShrinkExpandSenderOfflineInput& input,
            ShrinkExpandSenderState& state,
            Socket& sock);

        task<> keyDerive(
            const KeyDeriveSenderInput& input,
            KeyDeriveSenderOutput& output,
            Socket& sock);

        task<> expand(
            const ShrinkExpandSenderState& state,
            const ShrinkExpandSenderExpandInput& input,
            ShrinkExpandSenderExpandOutput& output,
            Socket& sock);
    };
}

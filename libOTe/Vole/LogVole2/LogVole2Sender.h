#pragma once

#include "libOTe/Tools/Coproto.h"
#include "libOTe/Vole/LogVole2/LogVole2Core.h"
#include "libOTe/Vole/LogVole2/LogVole2ShrinkExpand.h"

namespace osuCrypto::LogVole2
{
    class Sender
    {
    public:
        task<> offline(
            const ShrinkExpandSenderOfflineInput& input,
            ShrinkExpandSenderState& state,
            Socket& sock);

        task<> offline(
            const SenderOfflineInput& input,
            SenderState& state,
            Socket& sock);

        task<> keyDerive(
            const KeyDeriveSenderInput& input,
            KeyDeriveSenderOutput& output,
            Socket& sock);

        task<> online(
            const SenderState& state,
            SenderOnlineOutput& output,
            Socket& sock);

        task<> online(
            const SenderState& state,
            const SenderOnlineOptions& options,
            SenderOnlineOutput& output,
            Socket& sock);

        task<> expand(
            const ShrinkExpandSenderState& state,
            const ShrinkExpandExpandSenderInput& input,
            ShrinkExpandSenderExpandOutput& output,
            Socket& sock);
    };
}

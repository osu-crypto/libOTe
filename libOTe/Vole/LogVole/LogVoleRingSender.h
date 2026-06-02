#pragma once

#include "libOTe/Tools/Coproto.h"
#include "libOTe/Vole/LogVole/LogVoleCore.h"
#include "libOTe/Vole/LogVole/LogVoleShrinkExpand.h"

namespace osuCrypto::LogVole
{
    class LogVoleRingSender
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

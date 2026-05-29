#pragma once

#include "libOTe/Tools/Coproto.h"
#include "libOTe/Vole/LogVole/LogVoleLenc.h"

namespace osuCrypto::LogVole
{
    class Receiver
    {
    public:
        task<> keyDerive(
            const KeyDeriveReceiverInput& input,
            KeyDeriveReceiverOutput& output,
            Socket& sock);
    };
}

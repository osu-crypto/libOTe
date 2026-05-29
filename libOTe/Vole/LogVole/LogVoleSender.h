#pragma once

#include "libOTe/Tools/Coproto.h"
#include "libOTe/Vole/LogVole/LogVoleLenc.h"

namespace osuCrypto::LogVole
{
    class Sender
    {
    public:
        task<> keyDerive(
            const KeyDeriveSenderInput& input,
            KeyDeriveSenderOutput& output,
            Socket& sock);
    };
}

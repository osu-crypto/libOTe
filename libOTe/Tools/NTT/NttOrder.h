#pragma once

#include "cryptoTools/Common/Defines.h"

namespace osuCrypto
{
    enum class NttOrder
    {
        NormalOrder, // NO order
        BitReversedOrder, // BO order
    };

    // reverse the first bitCount bits of x
    inline u64 bitReveral(u64 bitCount, u64 x)
    {
        u64 r = 0;
        for (u64 i = 0; i < bitCount; ++i)
        {
            r <<= 1;
            r |= x & 1;
            x >>= 1;
        }
        return r;
    }
}
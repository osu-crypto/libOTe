#pragma once
#include "ReedMullerBaaCode.h"
#include <type_traits>

namespace osuCrypto
{
    // Each bit lane is an independent binary codeword, not a field symbol.
    template<typename Word>
    struct BinaryBAAArithmetic
    {
        static_assert(std::is_same_v<Word, block> || std::is_unsigned_v<Word>);
        static Word zero() { return Word{}; }
        static Word one() { return Word(1); }
        static OC_FORCEINLINE Word add(Word a, Word b) { return a ^ b; }
    };
    template<> inline block BinaryBAAArithmetic<block>::one() { return OneBlock; }

    // Binary RM BAA, 10% distance tier. block stores 128 independent bit lanes.
    template<typename Word = block>
    using BinaryBAA = ReedMullerBaaCode<Word, BinaryBAAArithmetic<Word>>;
}

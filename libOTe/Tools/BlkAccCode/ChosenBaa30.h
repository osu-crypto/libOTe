#pragma once
#include "SmallAlphabetBaaCode.h"

namespace osuCrypto
{
    // Public distance tier. The >30.524% certificate is for n=2^21 with
    // ideal uniform setup, not a guarantee for every supported length/field.
    template<typename F = block, typename Field = ChosenBaaField<F>>
    using ChosenBaa30 = SmallAlphabetBaaCode<F, Field>;
}

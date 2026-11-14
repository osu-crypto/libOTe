#pragma once
#include "ReedMullerBaaCode.h"
#include "NewtonBaaCode.h"
#include <type_traits>

namespace osuCrypto
{
    // Specialize for another characteristic-two representation. Keeping this
    // selection in a trait permits optimized field backends without changing
    // callers or adding runtime dispatch inside the encoder.
    template<typename F, typename Field = ChosenBaaField<F>>
    struct ChosenBaa10Backend
    {
        using type = chosen_baa_detail::NewtonBaaCode<F, Field>;
    };

    template<typename Field>
    struct ChosenBaa10Backend<block, Field>
    {
        using type = ReedMullerBaaCode<block, Field>;
    };

    // The low-distance tier uses a field-appropriate constituent: lifted RM
    // in characteristic two, extended Newton over sufficiently large primes.
    // Exact distance evidence is field- and length-specific; see README.md.
    template<typename F = block, typename Field = ChosenBaaField<F>>
    using ChosenBaa10 = typename ChosenBaa10Backend<F, Field>::type;
}

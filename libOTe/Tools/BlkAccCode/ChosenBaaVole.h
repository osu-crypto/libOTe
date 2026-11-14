#pragma once
#include "ChosenBaaCode.h"
#include "ChosenBaa10.h"
#include "ChosenBaa30.h"
#include "libOTe/Tools/Coproto.h"
#include "libOTe/TwoChooseOne/ConfigureCode.h"

namespace osuCrypto
{
    // Keep aligned encoder state and scratch out of the caller's coroutine frame.
    // The standalone encoder is field-generic; these protocol adapters use GF128.
    OC_NOINLINE void chosenBaaCompress(MultType type, block seed, span<block> a, span<block> b = {});
    task<> chosenBaaSeed(bool sender, PRNG& prng, Socket& chl, block& seed);
}

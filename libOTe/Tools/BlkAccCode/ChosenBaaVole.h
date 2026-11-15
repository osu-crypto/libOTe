#pragma once
#include "ChosenBaaCode.h"
#include "BinaryBAA.h"
#include "ChosenBAA30.h"
#include "libOTe/Tools/Coproto.h"
#include "libOTe/TwoChooseOne/ConfigureCode.h"

namespace osuCrypto
{
    struct ChosenBaaWorkspace
    {
        ChosenBAA30<> code;
        AlignedUnVector<block> scratch;
    };

    // Keep aligned encoder state and scratch out of the caller's coroutine frame.
    // The standalone encoder is field-generic; these protocol adapters use GF128.
    OC_NOINLINE void chosenBaaCompress(MultType type, block seed, span<block> a, span<block> b = {});
    // The workspace must be heap-owned: the encoder contains over-aligned SIMD
    // state. Capacity is reused, but config regenerates the code for every seed.
    OC_NOINLINE void chosenBaaCompress(MultType type, block seed,
        std::unique_ptr<ChosenBaaWorkspace>& workspace, span<block> a, span<block> b = {});
    OC_NOINLINE void binaryBaaCompress(block seed, span<block> values, span<u8> choices = {});
    task<> chosenBaaSeed(bool sender, PRNG& prng, Socket& chl, block& seed);
}

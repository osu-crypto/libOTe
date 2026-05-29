#pragma once

#include "libOTe/Vole/LogVole2/LogVole2ShrinkExpand.h"

#include <vector>

namespace osuCrypto::LogVole2
{
    enum class SeedLabelMode : u8
    {
        Leaf = 0,
        Internal = 1
    };

    enum class RecursiveMode : u8
    {
        Root = 0,
        Internal = 1
    };

    SeedLabelMode evalSeedLabelMode(u32 w, u32 alpha, u32 tau, u32 rho);
    RecursiveMode evalRecursiveMode(u32 w, u32 alpha, u32 tau, u32 rho);

    bool seedLabelAgg(
        const std::vector<RnsPoly>& inputHat,
        u32 outCount,
        u32 tau,
        const RingParams& ring,
        std::vector<RnsPoly>& out);

    bool seedLabelGadgetDecomposeAndUnbundle(
        const RnsPoly& digest,
        u32 gadgetLogBase,
        u32 tau,
        const RingParams& ring,
        std::vector<RnsPoly>& out);

    bool seedLabelGadgetDecomposeHiAndUnbundle(
        const RnsPoly& digest,
        u32 gadgetLogBase,
        u32 tauHi,
        const RingParams& ring,
        std::vector<RnsPoly>& out);

    bool seedLabelDenoiseTbm(
        const std::vector<RnsPoly>& tbmPrime,
        u32 wPrime,
        u32 tau,
        const RingParams& ring,
        std::vector<RnsPoly>& out);

    bool seedLabelRepOfflineSenderInput(
        const std::vector<RnsPoly>& s,
        u32 gamma,
        u32 alpha,
        u32 tau,
        const RingParams& ring,
        std::vector<RnsPoly>& out);

    bool seedLabelSampleCt2FromSeed(
        const SamplingSeedConfig& samplingSeeds,
        const std::vector<u8>& seed,
        u32 instanceIdx,
        u32 coeffCount,
        const RingParams& ring,
        std::vector<RnsPoly>& out);
}

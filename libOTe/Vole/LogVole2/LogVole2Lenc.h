#pragma once

#include "libOTe/Vole/LogVole2/LogVole2Ring.h"

#include <memory>
#include <vector>

namespace osuCrypto::LogVole2
{
    struct LencLacct
    {
        u32 mWidthPadded = 0;
        u32 mLevels = 0;
        RingTensor mCt;
    };

    struct LencEncodeOutput
    {
        std::vector<RnsPoly> mR;
        std::vector<RnsPoly> mRNtt;
        LencLacct mLacct;
    };

    struct DigestTree
    {
        u32 mWidthPadded = 0;
        u32 mLevels = 0;
        RnsPoly mDigest;
        std::vector<std::vector<RnsPoly>> mNodeDecompNtt;
    };

    std::vector<RnsPoly> buildLencPublicBNtt(const RingNttContext& ctx, u32 tau);

    bool buildDigestTree(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& x,
        u32 tau,
        u32 gadgetLogBase,
        DigestTree& out,
        u32 requestedWidthPadded = 0,
        const std::vector<RnsPoly>* publicBNtt = nullptr,
        u32 requestedWorkers = 1);

    bool lencEnc(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& s,
        u32 tau,
        u32 gadgetLogBase,
        const SamplingSeedConfig& samplingSeeds,
        LencEncodeOutput& out,
        double noiseStandardDeviation = 0.0,
        double noiseMaxDeviation = 0.0,
        u32 requestedWidthPadded = 0,
        bool emitRCoeffDomain = true,
        const std::vector<RnsPoly>* publicBNtt = nullptr,
        u32 requestedWorkers = 1);

    bool lencDigest(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& x,
        u32 tau,
        u32 gadgetLogBase,
        RnsPoly& out,
        u32 widthPadded = 0);

    bool lencEval(
        const RingNttContext& ctx,
        const LencLacct& lacct,
        const std::vector<RnsPoly>& x,
        u32 mu,
        u32 tau,
        u32 gadgetLogBase,
        std::vector<RnsPoly>& out,
        bool outputNtt = false,
        u32 requestedWorkers = 1);

    bool lencEval(
        const RingNttContext& ctx,
        const LencLacct& lacct,
        const DigestTree& tree,
        u32 mu,
        u32 tau,
        u32 gadgetLogBase,
        std::vector<RnsPoly>& out,
        bool outputNtt = false,
        u32 requestedWorkers = 1);
}

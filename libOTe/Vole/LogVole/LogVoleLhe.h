#pragma once

#include "libOTe/Vole/LogVole/LogVoleRing.h"

#include "cryptoTools/Crypto/PRNG.h"

#include <vector>

namespace osuCrypto::LogVole
{
    bool buildLhePublicANtt(const RingNttContext& ctx, u32 mu, std::vector<RnsPoly>& out);

    bool multiplyByGPower(
        const RingNttContext& ctx,
        const RnsPoly& poly,
        u32 gadgetLogBase,
        u32 power,
        RnsPoly& out);

    bool lheEnc1(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& r,
        const std::vector<RnsPoly>& sk1,
        u32 gadgetLogBase,
        RingTensor& out,
        double noiseStandardDeviation = 0.0,
        double noiseMaxDeviation = 0.0,
        PRNG* prng = nullptr,
        bool rInputIsNtt = false,
        const std::vector<RnsPoly>* publicANtt = nullptr,
        u32 requestedWorkers = 1);

    bool lheEnc1Trunc(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& r,
        const std::vector<RnsPoly>& sk1,
        u32 gadgetLogBase,
        RingTensor& out,
        double noiseStandardDeviation = 0.0,
        double noiseMaxDeviation = 0.0,
        PRNG* prng = nullptr,
        bool rInputIsNtt = false,
        const std::vector<RnsPoly>* publicANtt = nullptr,
        u32 requestedWorkers = 1);

    bool lheApplyCt1(
        const RingNttContext& ctx,
        const RingTensor& ct1,
        const RnsPoly& digest,
        u32 gadgetLogBase,
        u32 tau,
        std::vector<RnsPoly>& out,
        bool outputNtt = false,
        u32 requestedWorkers = 1);

    bool lheApplyCt1Trunc(
        const RingNttContext& ctx,
        const RingTensor& ct1,
        const RnsPoly& digest,
        u32 gadgetLogBase,
        u32 tauHi,
        std::vector<RnsPoly>& out,
        bool outputNtt = false,
        u32 requestedWorkers = 1);

    bool buildHashedCt2(
        const RingNttContext& ctx,
        u32 mu,
        std::span<const u8> seed,
        u64 sid,
        const RnsPoly& digest,
        u64 instanceIdx,
        std::vector<RnsPoly>& out);

    bool lheDec(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& cipher,
        const RnsPoly& sk,
        std::vector<RnsPoly>& out,
        const std::vector<RnsPoly>* publicANtt = nullptr,
        bool cipherInputIsNtt = false,
        bool outputNtt = false,
        u32 requestedWorkers = 1);

    bool deriveSkx(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& sk1,
        const RnsPoly& digest,
        const RnsPoly& tbkPrime,
        u32 gadgetLogBase,
        u32 tau,
        RnsPoly& out);

    bool deriveSkxTrunc(
        const RingNttContext& ctx,
        const std::vector<RnsPoly>& sk1,
        const RnsPoly& digest,
        const RnsPoly& tbkPrime,
        u32 gadgetLogBase,
        u32 tauHi,
        RnsPoly& out);
}

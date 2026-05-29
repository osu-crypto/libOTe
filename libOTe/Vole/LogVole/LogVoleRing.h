#pragma once

#include <cryptoTools/Common/Defines.h>

#include "seal/seal.h"

#include <memory>
#include <vector>

namespace osuCrypto::LogVole
{
    struct RingParams
    {
        u32 mPolyModulusDegree = 0;
        std::vector<int> mCoeffModulusBits;
    };

    struct RnsPoly
    {
        std::vector<u64> mCoeffs;
    };

    struct RingTensor
    {
        u32 mRows = 0;
        u32 mCols = 0;
        std::vector<RnsPoly> mPolys;
    };

    struct RingNttContext
    {
        RingParams mParams;
        std::vector<seal::Modulus> mModuli;
        std::shared_ptr<seal::SEALContext> mContext;
    };

    inline u64 polyCoeffCount(const RingParams& params)
    {
        return static_cast<u64>(params.mPolyModulusDegree) * params.mCoeffModulusBits.size();
    }

    inline u64 tensorSize(const RingTensor& tensor)
    {
        return static_cast<u64>(tensor.mRows) * tensor.mCols;
    }

    inline u64 tensorIndex(const RingTensor& tensor, u32 row, u32 col)
    {
        return static_cast<u64>(row) * tensor.mCols + col;
    }

    bool validateRingParams(const RingParams& params);
    bool validateRingPolyShape(const RnsPoly& poly, const RingParams& params);
    bool validateRingBatchShape(const std::vector<RnsPoly>& polys, const RingParams& params);
    bool makeRingNttContext(const RingParams& params, RingNttContext& ctx);

    bool canonicalizePoly(RnsPoly& poly, const RingNttContext& ctx);
    bool forwardNtt(RnsPoly& poly, const RingNttContext& ctx);
    bool inverseNtt(RnsPoly& poly, const RingNttContext& ctx);

    bool dyadicMultiplyAddNtt(
        const RnsPoly& aNtt,
        const RnsPoly& bNtt,
        const RnsPoly& cNtt,
        const RingNttContext& ctx,
        RnsPoly& out);

    bool ringAdd(
        const RnsPoly& a,
        const RnsPoly& b,
        const RingNttContext& ctx,
        RnsPoly& out);

    bool ringSub(
        const RnsPoly& a,
        const RnsPoly& b,
        const RingNttContext& ctx,
        RnsPoly& out);

    bool ringMultiply(
        const RnsPoly& a,
        const RnsPoly& b,
        const RingNttContext& ctx,
        RnsPoly& out);

    bool ringMultiplyScalar(
        const RnsPoly& a,
        u64 scalar,
        const RingNttContext& ctx,
        RnsPoly& out);

    bool gadgetDecompose(
        const RnsPoly& poly,
        u32 base,
        u32 tau,
        const RingNttContext& ctx,
        std::vector<RnsPoly>& out);

    bool gadgetRecompose(
        const std::vector<RnsPoly>& digits,
        u32 base,
        const RingNttContext& ctx,
        RnsPoly& out);

    bool gadgetDecomposeBits(
        const RnsPoly& poly,
        u32 digitBits,
        u32 levels,
        const RingNttContext& ctx,
        std::vector<RnsPoly>& out);

    bool gadgetRecomposeBits(
        const std::vector<RnsPoly>& digits,
        u32 digitBits,
        const RingNttContext& ctx,
        RnsPoly& out);

    std::vector<u64> packRingBatch(const std::vector<RnsPoly>& polys);
    bool unpackRingBatch(
        u32 count,
        u32 polyModulusDegree,
        u32 coeffModulusCount,
        const std::vector<u64>& flat,
        std::vector<RnsPoly>& out);

    std::vector<u64> packRingTensor(const RingTensor& tensor);
    bool unpackRingTensor(
        u32 rows,
        u32 cols,
        u32 polyModulusDegree,
        u32 coeffModulusCount,
        const std::vector<u64>& flat,
        RingTensor& out);

    RnsPoly deriveUniformPolyFromNonce(
        const RingNttContext& ctx,
        u64 nonce,
        u64 domainTag,
        u32 index);

    bool addGaussianNoise(
        RnsPoly& poly,
        double noiseStandardDeviation,
        double noiseMaxDeviation,
        u64 seed,
        u64 streamId,
        const RingNttContext& ctx);

    bool addPolyError(
        RnsPoly& poly,
        double noiseStandardDeviation,
        double noiseMaxDeviation,
        u64 seed,
        u64 streamId,
        const RingNttContext& ctx);
}

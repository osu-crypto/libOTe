#pragma once

#include <cryptoTools/Common/Defines.h>

#include "seal/seal.h"

#include <memory>
#include <vector>

namespace osuCrypto
{
    struct LogVoleRingParams
    {
        u32 mPolyModulusDegree = 0;
        std::vector<int> mCoeffModulusBits;
    };

    struct LogVoleRnsPoly
    {
        std::vector<u64> mCoeffs;
    };

    struct LogVoleRingTensor
    {
        u32 mRows = 0;
        u32 mCols = 0;
        std::vector<LogVoleRnsPoly> mPolys;
    };

    struct LogVoleRingNttContext
    {
        LogVoleRingParams mParams;
        std::vector<seal::Modulus> mModuli;
        std::shared_ptr<seal::SEALContext> mContext;
    };

    inline u64 logVolePolyCoeffCount(const LogVoleRingParams& params)
    {
        return static_cast<u64>(params.mPolyModulusDegree) * params.mCoeffModulusBits.size();
    }

    inline u64 logVoleTensorSize(const LogVoleRingTensor& tensor)
    {
        return static_cast<u64>(tensor.mRows) * tensor.mCols;
    }

    inline u64 logVoleTensorIndex(const LogVoleRingTensor& tensor, u32 row, u32 col)
    {
        return static_cast<u64>(row) * tensor.mCols + col;
    }

    bool logVoleValidateRingParams(const LogVoleRingParams& params);
    bool logVoleValidateRingPolyShape(const LogVoleRnsPoly& poly, const LogVoleRingParams& params);
    bool logVoleValidateRingBatchShape(const std::vector<LogVoleRnsPoly>& polys, const LogVoleRingParams& params);
    bool logVoleMakeRingNttContext(const LogVoleRingParams& params, LogVoleRingNttContext& ctx);

    bool logVoleCanonicalizePoly(LogVoleRnsPoly& poly, const LogVoleRingNttContext& ctx);
    bool logVoleForwardNtt(LogVoleRnsPoly& poly, const LogVoleRingNttContext& ctx);
    bool logVoleInverseNtt(LogVoleRnsPoly& poly, const LogVoleRingNttContext& ctx);

    bool logVoleDyadicMultiplyAddNtt(
        const LogVoleRnsPoly& aNtt,
        const LogVoleRnsPoly& bNtt,
        const LogVoleRnsPoly& cNtt,
        const LogVoleRingNttContext& ctx,
        LogVoleRnsPoly& out);

    bool logVoleRingAdd(
        const LogVoleRnsPoly& a,
        const LogVoleRnsPoly& b,
        const LogVoleRingNttContext& ctx,
        LogVoleRnsPoly& out);

    bool logVoleRingSub(
        const LogVoleRnsPoly& a,
        const LogVoleRnsPoly& b,
        const LogVoleRingNttContext& ctx,
        LogVoleRnsPoly& out);

    bool logVoleRingMultiply(
        const LogVoleRnsPoly& a,
        const LogVoleRnsPoly& b,
        const LogVoleRingNttContext& ctx,
        LogVoleRnsPoly& out);

    bool logVoleRingMultiplyScalar(
        const LogVoleRnsPoly& a,
        u64 scalar,
        const LogVoleRingNttContext& ctx,
        LogVoleRnsPoly& out);

    bool logVoleGadgetDecompose(
        const LogVoleRnsPoly& poly,
        u32 base,
        u32 tau,
        const LogVoleRingNttContext& ctx,
        std::vector<LogVoleRnsPoly>& out);

    bool logVoleGadgetRecompose(
        const std::vector<LogVoleRnsPoly>& digits,
        u32 base,
        const LogVoleRingNttContext& ctx,
        LogVoleRnsPoly& out);

    bool logVoleGadgetDecomposeBits(
        const LogVoleRnsPoly& poly,
        u32 digitBits,
        u32 levels,
        const LogVoleRingNttContext& ctx,
        std::vector<LogVoleRnsPoly>& out);

    bool logVoleGadgetRecomposeBits(
        const std::vector<LogVoleRnsPoly>& digits,
        u32 digitBits,
        const LogVoleRingNttContext& ctx,
        LogVoleRnsPoly& out);

    std::vector<u64> logVolePackRingBatch(const std::vector<LogVoleRnsPoly>& polys);
    bool logVoleUnpackRingBatch(
        u32 count,
        u32 polyModulusDegree,
        u32 coeffModulusCount,
        const std::vector<u64>& flat,
        std::vector<LogVoleRnsPoly>& out);

    std::vector<u64> logVolePackRingTensor(const LogVoleRingTensor& tensor);
    bool logVoleUnpackRingTensor(
        u32 rows,
        u32 cols,
        u32 polyModulusDegree,
        u32 coeffModulusCount,
        const std::vector<u64>& flat,
        LogVoleRingTensor& out);

    LogVoleRnsPoly logVoleDeriveUniformPolyFromNonce(
        const LogVoleRingNttContext& ctx,
        u64 nonce,
        u64 domainTag,
        u32 index);

    bool logVoleAddGaussianNoise(
        LogVoleRnsPoly& poly,
        double noiseStandardDeviation,
        double noiseMaxDeviation,
        u64 seed,
        u64 streamId,
        const LogVoleRingNttContext& ctx);

    bool logVoleAddPolyError(
        LogVoleRnsPoly& poly,
        double noiseStandardDeviation,
        double noiseMaxDeviation,
        u64 seed,
        u64 streamId,
        const LogVoleRingNttContext& ctx);
}

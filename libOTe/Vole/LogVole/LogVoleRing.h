#pragma once

#include <cryptoTools/Common/Defines.h>

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
}

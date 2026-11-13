#pragma once
#include "libOTe/Vole/LogVole/LogVoleRing.h"
#include <array>

namespace tests_libOTe::logvole_test
{
    inline auto ringStatsSnapshot(const osuCrypto::LogVole::RingOpsStats& stats)
    {
        return std::array<osuCrypto::u64, 11>{
            stats.mNttCount.load(), stats.mInttCount.load(), stats.mAddCount.load(),
            stats.mSubCount.load(), stats.mMulCount.load(), stats.mMulScalarCount.load(),
            stats.mDyadicMulAddCount.load(), stats.mGadgetDecomposeCount.load(),
            stats.mGadgetRecomposeCount.load(), stats.mPrngPolyCount.load(),
            stats.mErrorAddCount.load()};
    }
}

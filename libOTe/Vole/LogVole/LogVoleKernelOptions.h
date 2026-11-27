#pragma once
#include <cstdint>

namespace osuCrypto
{
    enum class LogVoleChoice { Automatic, Disabled, Enabled };

    // Host dispatch choices. Captured by the table owner at construction;
    // never passed to device kernels. Defaults retain the existing schedules.
    struct LogVoleGpuKernelOptions
    {
        bool mNoGoldH200InverseOpTrace = false;
        bool mFixedIpMuRowReuse = true;
        bool mFixedIpWideMuRowReuse = true;
        bool mPointwisePseudo55Reduce = true;
        std::uint32_t mNoGoldH200RootL2Mode = 3u;
        bool mFusedIp = false;
        bool mNoGoldH200InversePackedRoots = true;
        std::uint32_t mRootL2MiB = 8;
        std::uint32_t mRootL2HitPercent = 100;

        bool valid() const noexcept
        {
            return mNoGoldH200RootL2Mode <= 3u &&
                (mRootL2MiB == 1u || mRootL2MiB == 2u || mRootL2MiB == 4u || mRootL2MiB == 8u || mRootL2MiB == 12u || mRootL2MiB == 16u) &&
                (mRootL2HitPercent == 25u || mRootL2HitPercent == 50u || mRootL2HitPercent == 75u || mRootL2HitPercent == 100u);
        }
        bool operator==(const LogVoleGpuKernelOptions& other) const noexcept
        {
            return mNoGoldH200InverseOpTrace == other.mNoGoldH200InverseOpTrace &&
                mFixedIpMuRowReuse == other.mFixedIpMuRowReuse &&
                mFixedIpWideMuRowReuse == other.mFixedIpWideMuRowReuse &&
                mPointwisePseudo55Reduce == other.mPointwisePseudo55Reduce &&
                mNoGoldH200RootL2Mode == other.mNoGoldH200RootL2Mode &&
                mFusedIp == other.mFusedIp &&
                mNoGoldH200InversePackedRoots == other.mNoGoldH200InversePackedRoots &&
                mRootL2MiB == other.mRootL2MiB &&
                mRootL2HitPercent == other.mRootL2HitPercent;
        }
    };
}

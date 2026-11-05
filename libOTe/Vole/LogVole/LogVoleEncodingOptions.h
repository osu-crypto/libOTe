#pragma once

namespace osuCrypto
{
    // Passed explicitly to wire allocation and transfer operations.
    struct LogVoleWireOptions
    {
        bool mPinned = true;
        bool mDirectDownload = true;
        bool mHugePages = true;
        bool operator==(const LogVoleWireOptions&) const = default;
    };

    struct LogVoleEncodingOptions
    {
        LogVoleWireOptions mWire;
        bool mRootU64Memcpy = true;
        bool mSetupMemcpy = true;
        bool mParallel = true;
        bool mEncodedReceive = true;
        bool mRootEncodedReceive = true;
        bool mRootCtREncodedReceive = true;
        bool mRootLacctEncodedReceive = true;
        bool mRootBStarEncodedReceive = true;
        bool mRootWirePinOverlap = false;
        bool mRootWireCudaAlloc = false;
        bool mRootWireCudaAllocEarly = false;
        bool operator==(const LogVoleEncodingOptions&) const = default;
    };
}

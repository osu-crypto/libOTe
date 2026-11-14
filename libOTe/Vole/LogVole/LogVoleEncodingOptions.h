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
        bool operator==(const LogVoleEncodingOptions&) const = default;
    };
}

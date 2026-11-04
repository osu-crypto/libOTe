#pragma once

#include "libOTe/Vole/LogVole/LogVoleTypes.h"
#include <functional>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace osuCrypto::LogVole
{
    namespace gpu { class RetainedPublicUniform; }
    enum class ProtocolCacheRole : u8;

    // Public operands belong to the retained ring context. Entries may retain
    // immutable device tables and native streams, never this cache or a context.
    struct PublicPolynomialCache
    {
        struct Key
        {
            RingParams mRing;
            u32 mCount = 0;
            u64 mRunId = 0;
            ProtocolCacheRole mRole{};
            int mDevice = -1;

            bool operator==(const Key& other) const
            {
                return mRing == other.mRing && mCount == other.mCount &&
                    mRunId == other.mRunId && mRole == other.mRole &&
                    mDevice == other.mDevice;
            }
        };
        struct Hash
        {
            std::size_t operator()(const Key& key) const
            {
                std::size_t h = std::hash<u32>{}(key.mRing.mPolyModulusDegree);
                h ^= std::hash<u32>{}(key.mCount) + 0x9e3779b9u + (h << 6u) + (h >> 2u);
                h ^= std::hash<u64>{}(key.mRunId) + 0x9e3779b9u + (h << 6u) + (h >> 2u);
                h ^= std::hash<u8>{}(static_cast<u8>(key.mRole)) +
                    0x9e3779b9u + (h << 6u) + (h >> 2u);
                h ^= std::hash<int>{}(key.mDevice) + 0x9e3779b9u + (h << 6u) + (h >> 2u);
                for (int bits : key.mRing.mCoeffModulusBits)
                    h ^= std::hash<int>{}(bits) + 0x9e3779b9u + (h << 6u) + (h >> 2u);
                return h;
            }
        };
        struct Entry
        {
            std::mutex mMutex;
            std::shared_ptr<const std::vector<RnsPoly>> mHost;
            std::shared_ptr<const gpu::RetainedPublicUniform> mDevice;
        };
        struct Lane
        {
            std::mutex mMutex;
            std::unordered_map<Key, std::shared_ptr<Entry>, Hash> mEntries;
        };
        Lane mLhe, mLenc;
    };
}

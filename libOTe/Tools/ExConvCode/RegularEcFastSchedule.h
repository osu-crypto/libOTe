#pragma once

#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/block.h"
#include "cryptoTools/Crypto/AES.h"

#include <algorithm>
#include <array>
#include <bit>
#include <limits>
#include <stdexcept>

namespace osuCrypto::detail
{
    // A small public-seed generator for code schedules. This is deliberately
    // not a cryptographic PRG. It uses the same xorshift Feistel shape as Block
    // Accumulate and the one-AES-round expansion pattern used by ExConv.
    // Distinct domains must be used for permutations, labels, and taps.
    OC_FORCEINLINE u64 regularEcMix64(u64 value)
    {
        value ^= value >> 30;
        value *= 0xbf58476d1ce4e5b9ull;
        value ^= value >> 27;
        value *= 0x94d049bb133111ebull;
        value ^= value >> 31;
        return value;
    }

    OC_FORCEINLINE u32 regularEcMix32(u32 value)
    {
        value |= 1;
        value ^= value << 13;
        value ^= value >> 17;
        value ^= value << 5;
        return value;
    }

    OC_FORCEINLINE block regularEcMix32(block value)
    {
        value = value | block::allSame<u32>(1);
        value ^= value.slli_epi32<13>();
        value ^= value.srli_epi32(17);
        value ^= value.slli_epi32<5>();
        return value;
    }

    class RegularEcFeistel
    {
    public:
        void init(u64 size, block seed, u64 domain)
        {
            if (size == 0 || size > std::numeric_limits<u32>::max())
                throw std::invalid_argument(
                    "Regular EC permutation domain must fit in a nonzero u32 range. " LOCATION);

            mSize = static_cast<u32>(size);
            const u32 bits = static_cast<u32>(log2ceil(size));
            mMask = static_cast<u32>((u64{ 1 } << bits) - 1);
            const u64 material = regularEcMix64(
                seed.get<u64>(0) + domain + seed.get<u64>(1));
            mMultiplier = static_cast<u32>(material) | 1;
            mAddend = static_cast<u32>(material >> 32) & mMask;
            mShift0 = std::max<u32>(1, bits / 2);
            mShift1 = std::max<u32>(1, bits / 3);
            mMaskBlock = block::allSame<u32>(mMask);
            mMultiplierBlock = block::allSame<u32>(mMultiplier);
            mAddendBlock = block::allSame<u32>(mAddend);
        }

        OC_FORCEINLINE u32 operator()(u32 value) const
        {
            do
                value = permutePow2(value);
            while (value >= mSize);
            return value;
        }

        OC_FORCEINLINE void four(u32 first, std::array<u32, 4>& output) const
        {
            const block increment(3, 2, 1, 0);
            block values = block::allSame<u32>(first).add_epi32(increment);
            values = permutePow2(values);
            for (u64 lane = 0; lane != output.size(); ++lane)
            {
                u32 value = values.get<u32>(lane);
                while (value >= mSize)
                    value = permutePow2(value);
                output[lane] = value;
            }
        }

    private:
        u32 mSize = 0;
        u32 mMask = 0;
        u32 mMultiplier = 1;
        u32 mAddend = 0;
        u32 mShift0 = 1;
        u32 mShift1 = 1;
        block mMaskBlock = ZeroBlock;
        block mMultiplierBlock = ZeroBlock;
        block mAddendBlock = ZeroBlock;

        OC_FORCEINLINE u32 permutePow2(u32 value) const
        {
            value ^= value >> mShift0;
            value = (value * mMultiplier + mAddend) & mMask;
            value ^= value >> mShift1;
            return value;
        }

        OC_FORCEINLINE block permutePow2(block values) const
        {
            values ^= values.srli_epi32(static_cast<u8>(mShift0));
#ifdef OC_ENABLE_SSE2
            values = block(_mm_mullo_epi32(values, mMultiplierBlock));
#else
            std::array<u32, 4> lanes;
            for (u64 lane = 0; lane != 4; ++lane)
                lanes[lane] = values.get<u32>(lane) * mMultiplier;
            values = block(lanes);
#endif
            values = values.add_epi32(mAddendBlock) & mMaskBlock;
            values ^= values.srli_epi32(static_cast<u8>(mShift1));
            return values;
        }
    };

    class RegularEcCounter
    {
    public:
        RegularEcCounter() = default;

        RegularEcCounter(block seed, u64 domain)
        {
            init(seed, domain);
        }

        void init(block seed, u64 domain)
        {
            const u64 key0 = regularEcMix64(seed.get<u64>(0) + domain);
            const u64 key1 = regularEcMix64(seed.get<u64>(1) +
                std::rotl(domain, 29) + 0x9e3779b97f4a7c15ull);
            mKey = block(key0, key1);
        }

        OC_FORCEINLINE u64 word(u64 index) const
        {
            const u64 first = index & ~u64{ 1 };
            const block output = AES::roundEnc(block(first, first + 1), mKey);
            return output.get<u64>(index & 1);
        }

        OC_FORCEINLINE void fourWords(
            u64 first,
            std::array<u64, 4>& output) const
        {
            if (first & 1)
            {
                for (u64 lane = 0; lane != output.size(); ++lane)
                    output[lane] = word(first + lane);
                return;
            }
            const block output01 = AES::roundEnc(block(first, first + 1), mKey);
            const block output23 = AES::roundEnc(block(first + 2, first + 3), mKey);
            output[0] = output01.get<u64>(0);
            output[1] = output01.get<u64>(1);
            output[2] = output23.get<u64>(0);
            output[3] = output23.get<u64>(1);
        }

        OC_FORCEINLINE block sample(u64 index) const
        {
            const u64 low = word(index);
            const u64 high = word(index ^ 0xd1b54a32d192ed03ull);
            return block(low, high);
        }

    private:
        block mKey = ZeroBlock;
    };
}

#pragma once

#include <cstdint> // For uint32_t, uint64_t if needed

namespace osuCrypto
{

    // Xorshift-based hash function
    inline unsigned int xorshifthash(unsigned int x)
    {
        // Force x to be non-zero using a bitwise OR with 1
        x |= 1;

        // Xorshift operations
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        return x;
    }

    inline block xorshifthash(block x)
    {
        // Force x to be non-zero using a bitwise OR with 1
        x = x | block::allSame<i32>(1);

        // Xorshift operations
        x = x ^ x.slli_epi32<13>();
        x = x ^ x.srai_epi32<17>();
        x = x ^ x.slli_epi32<5>();
        return x;
    }

    // Functor for generating random binary values
    struct RandomBinaryFunctor
    {
        unsigned int seed;

        explicit RandomBinaryFunctor(unsigned int seed) : seed(seed) {}

        int operator()(const int& index) const
        {
            unsigned int value = xorshifthash(seed ^ index);
            return value & 1; // Return the least significant bit
        }
    };

}
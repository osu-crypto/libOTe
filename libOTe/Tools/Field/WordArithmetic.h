#pragma once

#include <cstdint>

namespace osuCrypto::wordArithmetic
{
    using Word = std::uint64_t;

    // Four half-word products, usable by either host compiler and in constexpr.
    constexpr void multiply(Word a, Word b, Word& low, Word& high) noexcept
    {
        constexpr Word mask = 0xffffffff;
        const Word p00 = (a & mask) * (b & mask);
        const Word p01 = (a & mask) * (b >> 32);
        const Word p10 = (a >> 32) * (b & mask);
        const Word middle = (p00 >> 32) + (p01 & mask) + (p10 & mask);
        low = (p00 & mask) | (middle << 32);
        high = (a >> 32) * (b >> 32) + (p01 >> 32) + (p10 >> 32) + (middle >> 32);
    }

    constexpr unsigned leadingZeros(Word x) noexcept
    {
        unsigned n = 0;
        if (!(x >> 32)) { n += 32; x <<= 32; }
        if (!(x >> 48)) { n += 16; x <<= 16; }
        if (!(x >> 56)) { n += 8; x <<= 8; }
        if (!(x >> 60)) { n += 4; x <<= 4; }
        if (!(x >> 62)) { n += 2; x <<= 2; }
        return n + !(x >> 63); // precondition: x != 0
    }

    // Two normalized base-2^32 quotient digits. Preconditions: divisor != 0,
    // high < divisor. Each estimate needs at most two corrections. All
    // wraparound below is unsigned and intentional; no bit-at-a-time division.
    constexpr Word divide(Word low, Word high, Word divisor, Word& remainder) noexcept
    {
        constexpr Word base = Word{1} << 32;
        constexpr Word mask = base - 1;
        const unsigned shift = leadingZeros(divisor);
        const Word v = divisor << shift;
        const Word v1 = v >> 32, v0 = v & mask;
        const Word upper = (high << shift) | (shift ? low >> (64 - shift) : 0);
        const Word lower = low << shift;
        const Word u1 = lower >> 32, u0 = lower & mask;
        Word q1 = upper / v1, r = upper % v1;
        while (q1 >= base || q1 * v0 > base * r + u1)
        {
            --q1;
            r += v1;
            if (r >= base) break;
        }
        const Word middle = upper * base + u1 - q1 * v;
        Word q0 = middle / v1;
        r = middle % v1;
        while (q0 >= base || q0 * v0 > base * r + u0)
        {
            --q0;
            r += v1;
            if (r >= base) break;
        }
        remainder = (middle * base + u0 - q0 * v) >> shift;
        return q1 * base + q0;
    }

    // Full two-word quotient; unlike divide(), accepts any high word.
    constexpr void divideFull(Word low, Word high, Word divisor,
        Word& quotientLow, Word& quotientHigh, Word& remainder) noexcept
    {
        quotientHigh = high / divisor;
        const Word reducedHigh = high % divisor;
        if (!reducedHigh)
        {
            quotientLow = low / divisor;
            remainder = low % divisor;
        }
        else quotientLow = divide(low, reducedHigh, divisor, remainder);
    }
}

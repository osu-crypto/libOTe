#pragma once

// Independent test oracle: base-2^16 multiplication and bit-at-a-time division.
// Never call production word arithmetic or the GPU implementation here.
#include <cstdint>
#include <stdexcept>

namespace host_oracle
{
    using u64 = std::uint64_t;
    struct Uint128
    {
        u64 lo, hi;
        constexpr Uint128(u64 low = 0, u64 high = 0) : lo(low), hi(high) {}
        explicit constexpr operator u64() const { return lo; }
        friend constexpr bool operator==(Uint128 a, Uint128 b) { return a.lo == b.lo && a.hi == b.hi; }
        friend constexpr bool operator!=(Uint128 a, Uint128 b) { return !(a == b); }
        friend constexpr bool operator<(Uint128 a, Uint128 b) { return a.hi != b.hi ? a.hi < b.hi : a.lo < b.lo; }
        friend constexpr bool operator>(Uint128 a, Uint128 b) { return b < a; }
        friend constexpr bool operator<=(Uint128 a, Uint128 b) { return !(b < a); }
        friend constexpr bool operator>=(Uint128 a, Uint128 b) { return !(a < b); }
        friend constexpr Uint128 operator~(Uint128 a) { return {~a.lo, ~a.hi}; }
        friend constexpr Uint128 operator|(Uint128 a, Uint128 b) { return {a.lo | b.lo, a.hi | b.hi}; }
        friend constexpr Uint128 operator&(Uint128 a, Uint128 b) { return {a.lo & b.lo, a.hi & b.hi}; }
        friend constexpr Uint128 operator<<(Uint128 a, unsigned shift)
        {
            if (!shift) return a;
            if (shift >= 128) return {};
            if (shift >= 64) return {0, a.lo << (shift - 64)};
            return {a.lo << shift, (a.hi << shift) | (a.lo >> (64 - shift))};
        }
        friend constexpr Uint128 operator>>(Uint128 a, unsigned shift)
        {
            if (!shift) return a;
            if (shift >= 128) return {};
            if (shift >= 64) return {a.hi >> (shift - 64), 0};
            return {(a.lo >> shift) | (a.hi << (64 - shift)), a.hi >> shift};
        }
        friend constexpr Uint128 operator+(Uint128 a, Uint128 b)
        {
            const u64 low = a.lo + b.lo;
            return {low, a.hi + b.hi + (low < a.lo)};
        }
        friend constexpr Uint128 operator-(Uint128 a, Uint128 b)
        {
            return {a.lo - b.lo, a.hi - b.hi - (a.lo < b.lo)};
        }
        constexpr Uint128& operator+=(Uint128 b) { return *this = *this + b; }
    };

    constexpr Uint128 multiply(u64 a, u64 b)
    {
        u64 digits[8]{};
        for (unsigned i = 0; i != 4; ++i)
        {
            u64 carry = 0;
            for (unsigned j = 0; j != 4; ++j)
            {
                const u64 sum = digits[i + j] + carry +
                    ((a >> (16 * i)) & 0xffff) * ((b >> (16 * j)) & 0xffff);
                digits[i + j] = sum & 0xffff;
                carry = sum >> 16;
            }
            digits[i + 4] = carry;
        }
        return {digits[0] | (digits[1] << 16) | (digits[2] << 32) | (digits[3] << 48),
                digits[4] | (digits[5] << 16) | (digits[6] << 32) | (digits[7] << 48)};
    }
    constexpr Uint128 operator*(Uint128 a, Uint128 b)
    {
        auto product = multiply(a.lo, b.lo);
        product.hi += a.lo * b.hi + a.hi * b.lo;
        return product;
    }
    constexpr Uint128 add(Uint128 a, Uint128 b) { return a + b; }
    constexpr Uint128 subtract(Uint128 a, Uint128 b) { return a - b; }
    constexpr Uint128 scale(Uint128 a, u64 b) { return a * Uint128{b}; }

    constexpr Uint128 divide(Uint128 a, u64 divisor, u64& remainder)
    {
        if (!divisor) throw std::domain_error("oracle division by zero");
        Uint128 quotient;
        remainder = 0;
        for (unsigned bit = 128; bit-- != 0;)
        {
            const bool carry = (remainder >> 63) != 0;
            remainder = (remainder << 1) | ((bit < 64 ? a.lo >> bit : a.hi >> (bit - 64)) & 1);
            if (carry || remainder >= divisor)
            {
                remainder -= divisor;
                if (bit < 64) quotient.lo |= u64{1} << bit;
                else quotient.hi |= u64{1} << (bit - 64);
            }
        }
        return quotient;
    }
    constexpr Uint128 operator/(Uint128 a, u64 divisor) { u64 r = 0; return divide(a, divisor, r); }
    constexpr u64 remainder(Uint128 a, u64 divisor) { u64 r = 0; divide(a, divisor, r); return r; }
    constexpr u64 operator%(Uint128 a, u64 divisor) { return remainder(a, divisor); }
}

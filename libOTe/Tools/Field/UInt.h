#pragma once
#include <array>
#include <cstdint>
#include <cstring>
#include <compare>
#include <ostream>
#include <limits>
#include <type_traits>
#include <stdexcept>
#include "util.h"

namespace osuCrypto 
{

    // Unsigned fixed-width integer: width = bit count.
    // Behaves like a builtin unsigned integer with modulo 2^W wrap-around.
    template <std::size_t W>
    class UInt {
        static_assert(W > 0, "UInt<W>: W must be > 0");
        static_assert(W % 64 == 0, "UInt<W>: W must be multiple of 64");

    public:
        using limb_t = u64;
        static constexpr std::size_t limbs = W / 64;
        static constexpr std::size_t bits = W;

        std::array<limb_t, limbs> v{}; // little-endian: v[0] is least significant

        // ---- ctors ----
        constexpr UInt() = default;               // zero
        constexpr UInt(int x) { v.fill(0); v[0] = x; }
        constexpr UInt(u64 x) { v.fill(0); v[0] = x; }
        constexpr explicit UInt(bool b) : UInt(static_cast<u64>(b)) {}

        // ---- inspectors ----
        static constexpr UInt zero() { return UInt{}; }
        static constexpr UInt one() { return UInt{ u64{1} }; }

        constexpr bool is_zero() const {
            for (auto x : v) if (x) return false;
            return true;
        }

        // ---- conversions ----
        explicit constexpr operator bool() const { return !is_zero(); }
        explicit constexpr operator u64()  const { return v[0]; }

        // ---- comparisons ----
        friend constexpr bool operator==(const UInt& a, const UInt& b) {
            for (std::size_t i = 0; i < limbs; ++i)
                if (a.v[i] != b.v[i]) return false;
            return true;
        }

        static constexpr int ucmp(const UInt& a, const UInt& b) {
            for (std::size_t i = limbs; i-- > 0;) {
                if (a.v[i] < b.v[i]) return -1;
                if (a.v[i] > b.v[i]) return 1;
            }
            return 0;
        }

        friend constexpr std::strong_ordering operator<=>(const UInt& a, const UInt& b) {
            int c = ucmp(a, b);
            if (c < 0) return std::strong_ordering::less;
            if (c > 0) return std::strong_ordering::greater;
            return std::strong_ordering::equal;
        }

        // ---- bitwise ----
        constexpr UInt& operator&=(const UInt& r) { for (std::size_t i = 0; i < limbs; ++i) v[i] &= r.v[i]; return *this; }
        constexpr UInt& operator|=(const UInt& r) { for (std::size_t i = 0; i < limbs; ++i) v[i] |= r.v[i]; return *this; }
        constexpr UInt& operator^=(const UInt& r) { for (std::size_t i = 0; i < limbs; ++i) v[i] ^= r.v[i]; return *this; }

        friend constexpr UInt operator&(UInt a, const UInt& b) { a &= b; return a; }
        friend constexpr UInt operator|(UInt a, const UInt& b) { a |= b; return a; }
        friend constexpr UInt operator^(UInt a, const UInt& b) { a ^= b; return a; }

        constexpr UInt operator~() const {
            UInt r;
            for (std::size_t i = 0; i < limbs; ++i) r.v[i] = ~v[i];
            return r;
        }

        // ---- shifts ----
        constexpr UInt& operator<<=(std::size_t k) {
            if (k == 0) return *this;
            const std::size_t limb = k / 64;
            const std::size_t sh = k % 64;
            if (limb >= limbs) { v.fill(0); return *this; }

            if (sh == 0) {
                for (std::size_t i = limbs; i-- > limb;)
                    v[i] = v[i - limb];
            }
            else {
                for (std::size_t i = limbs; i-- > limb;) {
                    u64 hi = v[i - limb] << sh;
                    u64 car = (i >= limb + 1) ? (v[i - limb - 1] >> (64 - sh)) : 0;
                    v[i] = hi | car;
                }
            }
            for (std::size_t i = 0; i < limb; ++i) v[i] = 0;
            return *this;
        }
        friend constexpr UInt operator<<(UInt a, std::size_t k) { a <<= k; return a; }

        constexpr UInt& operator>>=(std::size_t k) {
            if (k == 0) return *this;
            const std::size_t limb = k / 64;
            const std::size_t sh = k % 64;
            if (limb >= limbs) { v.fill(0); return *this; }

            if (sh == 0) {
                for (std::size_t i = 0; i + limb < limbs; ++i)
                    v[i] = v[i + limb];
            }
            else {
                for (std::size_t i = 0; i + limb < limbs; ++i) {
                    u64 lo = v[i + limb] >> sh;
                    u64 car = (i + limb + 1 < limbs) ? (v[i + limb + 1] << (64 - sh)) : 0;
                    v[i] = lo | car;
                }
            }
            for (std::size_t i = limbs - limb; i < limbs; ++i) v[i] = 0;
            return *this;
        }
        friend constexpr UInt operator>>(UInt a, std::size_t k) { a >>= k; return a; }

        // ---- arithmetic ----
        constexpr UInt& operator+=(const UInt& r) {
            u8 c = 0;
            for (std::size_t i = 0; i < limbs; ++i)
                v[i] = addc64(v[i], r.v[i], c, c);
            return *this;
        }
        friend constexpr UInt operator+(UInt a, const UInt& b) { a += b; return a; }

        constexpr UInt& operator-=(const UInt& r) {
            u8 b = 0;
            for (std::size_t i = 0; i < limbs; ++i)
                v[i] = subc64(v[i], r.v[i], b, b);
            return *this;
        }
        friend constexpr UInt operator-(UInt a, const UInt& b) { a -= b; return a; }

        constexpr UInt& operator*=(const UInt& r) {
            UInt out;
            for (std::size_t i = 0; i < limbs; ++i) {
                u64 carry = 0; // full 64-bit accumulator
                for (std::size_t j = 0; j + i < limbs; ++j) {
                    u64 lo, hi; mul128(v[i], r.v[j], lo, hi);

                    u8 c1 = 0;
                    u64 s = addc64(out.v[i + j], lo, c1, c1);

                    u8 c2 = 0;
                    s = addc64(s, carry, c2, c2);

                    out.v[i + j] = s;
                    carry = hi + c1 + c2;
                }
                // modulo 2^W: any remaining carry is discarded
            }
            *this = out;
            return *this;
        }
        friend constexpr UInt operator*(UInt a, const UInt& b) { a *= b; return a; }

        constexpr UInt& operator+=(u64 r) {
            u8 c = 0;
            v[0] = addc64(v[0], r, c, c);
            for (std::size_t i = 1; c && i < limbs; ++i)
                v[i] = addc64(v[i], u64{ 0 }, c, c);
            return *this;
        }
        constexpr UInt& operator-=(u64 r) {
            u8 b = 0;
            v[0] = subc64(v[0], r, b);
            for (std::size_t i = 1; b && i < limbs; ++i)
                v[i] = subc64(v[i], u64{ 0 }, b);
            return *this;
        }
        constexpr UInt& operator*=(u64 r) {
            UInt out;
            u64 carry = 0;
            for (std::size_t i = 0; i < limbs; ++i) {
                u64 lo, hi; mul128(v[i], r, lo, hi);

                u8 c1 = 0;
                u64 s = addc64(out.v[i], lo, c1, c1);

                u8 c2 = 0;
                s = addc64(s, carry, c2, c2);

                out.v[i] = s;
                carry = hi + c1 + c2;
            }
            *this = out; // modulo 2^W drops final carry
            return *this;
        }

        friend constexpr UInt operator+(UInt a, u64 b) { a += b; return a; }
        friend constexpr UInt operator-(UInt a, u64 b) { a -= b; return a; }
        friend constexpr UInt operator*(UInt a, u64 b) { a *= b; return a; }

        // ---- division: restoring long division (no __int128) ----
        inline static constexpr void div(const UInt& numerator,
            const UInt& denominator,
            UInt& quo,
            UInt& rem)
        {
            if (denominator.is_zero())
                throw std::domain_error("division by zero");

            quo = zero();
            rem = zero();

            if (ucmp(numerator, denominator) < 0) {
                rem = numerator;
                return;
            }

            for (std::size_t bi = bits; bi-- > 0;) {
                rem <<= 1;
                const u64 bit = (numerator.v[bi / 64] >> (bi % 64)) & 1ull;
                rem.v[0] |= bit;
                if (ucmp(rem, denominator) >= 0) {
                    rem -= denominator;
                    quo.v[bi / 64] |= (1ull << (bi % 64));
                }
            }
        }

		friend constexpr UInt operator/(UInt a, const UInt& b) { UInt q, r; div(a, b, q, r); return q; }
		friend constexpr UInt operator%(UInt a, const UInt& b) { UInt q, r; div(a, b, q, r); return r; }

		constexpr UInt& operator/=(const UInt& r) { UInt q, rem; div(*this, r, q, rem); *this = q; return *this; }
		constexpr UInt& operator%=(const UInt& r) { UInt q, rem; div(*this, r, q, rem); *this = rem; return *this; }



        // ---- I/O (hex) ----
        friend std::ostream& operator<<(std::ostream& os, const UInt& x) {
            os << "0x";
            bool started = false;
            for (std::size_t i = limbs; i-- > 0;) {
                if (!started) {
                    if (x.v[i] == 0) { if (i == 0) os << '0'; continue; }
                    os << std::hex << x.v[i];
                    started = true;
                }
                else {
                    os.width(16); os.fill('0'); os << std::hex << x.v[i];
                }
            }
            os << std::dec;
            return os;
        }
    };

    // Aliases
    using u128 = UInt<128>;

} 

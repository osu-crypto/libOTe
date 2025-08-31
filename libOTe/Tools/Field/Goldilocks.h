#pragma once

#include "cryptoTools/Common/Defines.h"
#include <array>
#include <iostream>
#include <assert.h>
#include <utility>
#include "util.h"
#include "UInt.h"

namespace osuCrypto
{


	// Goldilocks: Finite field F_p with p = 2^64 - 2^32 + 1.
	//
	// Overview
	// --------
	// - This type models arithmetic in the "Goldilocks" prime field F_p frequently used
	//   in NTT/FFT-based polynomial arithmetic and zk protocols.
	// - Elements are stored in an "unreduced" representative mVal in [0, 2^64),
	//   where values in [p, 2^64) are also allowed. The canonical() method maps an
	//   element back to [0, p-1].
	// - The add/sub implementations use a field-specific trick that adds/subtracts a fixed
	//   "reducer" (= 2^32 - 1) after carry/borrow, avoiding branches on the critical path.
	// - Multiplication uses an optimized reduction that leverages the Goldilocks congruences:
	//     2^64 ≡ 2^32 - 1 (mod p), 2^96 ≡ -1 (mod p).
	//
	// API notes
	// ---------
	// - All operators (+, -, *, /) and helpers (add, sub, mul, inv, pow, increment, decrement, negate)
	//   produce a valid unreduced representative (canonicality is not guaranteed unless stated).
	// - operator u64() returns canonical().mVal.
	// - inv(0) is defined to be 0 for convenience in some algorithms; consumers should treat 0 as non-invertible.
	// - pow(result, x, e) computes x^e using square-and-multiply over the field.
	//
	// Roots of unity
	// --------------
	// - GoldilocksRootsOfUnity holds a table of primitive 2^k-th roots for k = 0..32.
	// - primRootOfUnity<Goldilocks>(n) returns the primitive n-th root for n a power of two.
	//
	// Performance tips
	// ----------------
	// - This implementation is constexpr-friendly where practical, enabling compile-time folding in some cases.
	// - The fast reduction paths in mulPzt22 rely on 64x64->128 multiplication via mul128 defined in util.h.
	// 
	// see 
	// * EcGFp5: a Specialized Elliptic Curve
	// * https://github.com/mir-protocol/plonky2/blob/main/plonky2/plonky2.pdf
	// * https://cp4space.hatsya.com/2021/09/01/an-efficient-prime-for-number-theoretic-transforms
	// * https://xn--2-umb.com/22/goldilocks/
	// * https://github.com/ingonyama-zk/papers/blob/main/goldilocks_ntt_trick.pdf
	// * https://xn--2-umb.com/23/gold-reduce/
	struct Goldilocks
	{
		// Field modulus p = 2^64 - 2^32 + 1.
		// Using a two's-complement identity to keep it constexpr and obvious.
		// the 2^64 is implicit in u64 arithmetic.
		static constexpr u64 mModulus = -(1ull << 32) + 1;

		// Alias for the modulus, useful for generic code treating "order" as the field size.
		static constexpr u128 order() { return (u128(1) << 64) + u128(mModulus); }

		// Internal value (unreduced). Any u64 is accepted; interpreted modulo mModulus.
		// Invariant: all arithmetic maintains a correct representative modulo p.
		u64 mVal;

		// Returns the canonical representative in [0, p-1].
		constexpr Goldilocks canonical() const noexcept
		{
			return { (mVal < mModulus) ? mVal : mVal - mModulus };
		}

		// Returns the canonical representative in [0, p-1].
		constexpr OC_FORCEINLINE u64 integer() const noexcept
		{
			return canonical().mVal;
		}

		// Implicit cast to the canonical u64 value in [0, p-1].
		constexpr OC_FORCEINLINE operator u64() const noexcept
		{
			return canonical().mVal;
		}

		// Field addition (this + rhs).
		constexpr OC_FORCEINLINE Goldilocks operator+(const Goldilocks& rhs) const noexcept
		{
			Goldilocks result;
			add(result, *this, rhs);
			return result;
		}

		// In-place addition.
		constexpr OC_FORCEINLINE Goldilocks& operator+=(const Goldilocks& rhs) noexcept
		{
			add(*this, *this, rhs);
			return *this;
		}

		// Field subtraction (this - rhs).
		constexpr OC_FORCEINLINE Goldilocks operator-(const Goldilocks& rhs) const noexcept
		{
			Goldilocks result;
			sub(result, *this, rhs);
			return result;
		}

		// In-place subtraction.
		constexpr OC_FORCEINLINE Goldilocks& operator-=(const Goldilocks& rhs) noexcept
		{
			sub(*this, *this, rhs);
			return *this;
		}

		// Field negation (-this).
		constexpr OC_FORCEINLINE Goldilocks operator-() const noexcept
		{
			Goldilocks result;
			negate(result, *this);
			return result;
		}

		// Field multiplication (this * rhs).
		constexpr OC_FORCEINLINE Goldilocks operator*(const Goldilocks& rhs) const noexcept
		{
			Goldilocks result;
			mul(result, *this, rhs);
			return result;
		}

		// In-place multiplication.
		constexpr OC_FORCEINLINE Goldilocks& operator*=(const Goldilocks& rhs) noexcept
		{
			mul(*this, *this, rhs);
			return *this;
		}

		// Field division (this / rhs) = this * inv(rhs). inv(0) := 0 by convention here.
		constexpr OC_FORCEINLINE Goldilocks operator/(const Goldilocks& rhs) const noexcept
		{
			Goldilocks result;
			inv(result, rhs);
			mul(result, *this, result);
			return result;
		}

		// In-place division.
		constexpr  OC_FORCEINLINE Goldilocks& operator/=(const Goldilocks& rhs) noexcept
		{
			Goldilocks inv_rhs;
			inv(inv_rhs, rhs);
			mul(*this, *this, inv_rhs);
			return *this;
		}

		// Equality comparison uses canonical representatives.
		constexpr OC_FORCEINLINE bool operator==(const Goldilocks& rhs) const noexcept
		{
			return canonical().mVal == rhs.canonical().mVal;
		}

		// Equality comparison uses canonical representatives.
		constexpr OC_FORCEINLINE bool operator!=(const Goldilocks& rhs) const noexcept
		{
			return !(*this == rhs);
		}

		constexpr  OC_FORCEINLINE bool operator<(const Goldilocks& rhs) const noexcept
		{
			return canonical().mVal < rhs.canonical().mVal;
		}
		constexpr OC_FORCEINLINE bool operator<=(const Goldilocks& rhs) const noexcept
		{
			return canonical().mVal <= rhs.canonical().mVal;
		}
		constexpr OC_FORCEINLINE bool operator>(const Goldilocks& rhs) const noexcept
		{
			return canonical().mVal > rhs.canonical().mVal;
		}
		constexpr OC_FORCEINLINE bool operator>=(const Goldilocks& rhs) const noexcept
		{
			return canonical().mVal >= rhs.canonical().mVal;
		}

		constexpr OC_FORCEINLINE Goldilocks& operator=(const Goldilocks& other) noexcept = default;

		// Bitwise AND on unreduced representatives. This is not a field operation.
		// Only used in select internal idioms; do not rely on it as a field operation.
		constexpr OC_FORCEINLINE Goldilocks operator&(const Goldilocks& rhs) const noexcept
		{
			return { mVal & rhs.mVal };
		}

		// Pre-increment: ++x  => x = x + 1 (mod p), returns reference to updated x.
		constexpr OC_FORCEINLINE Goldilocks& operator++() noexcept
		{
			increment(*this, *this);
			return *this;
		}

		// Post-increment: x++  => returns old value, then x = x + 1 (mod p).
		constexpr OC_FORCEINLINE Goldilocks operator++(int) noexcept
		{
			Goldilocks tmp = *this;
			increment(*this, *this);
			return tmp;
		}

		// Pre-decrement: --x  => x = x - 1 (mod p), returns reference to updated x.
		constexpr OC_FORCEINLINE Goldilocks& operator--() noexcept
		{
			decrement(*this, *this);
			return *this;
		}

		// Post-decrement: x--  => returns old value, then x = x - 1 (mod p).
		constexpr OC_FORCEINLINE Goldilocks operator--(int) noexcept
		{
			Goldilocks tmp = *this;
			decrement(*this, *this);
			return tmp;
		}

		// Returns x^exp in the field using square-and-multiply.
		constexpr OC_FORCEINLINE Goldilocks pow(u64 exp) const noexcept
		{
			Goldilocks result;
			pow(result, *this, exp);
			return result;
		}

		// pow(result, x, exps):
		//   Compute x^exps via square-and-multiply with field multiplication.
		static constexpr OC_FORCEINLINE void pow(
			Goldilocks& result,
			Goldilocks x,
			u64 exps) noexcept
		{
			result = (exps & 1) ? x : Goldilocks{ 1 };
			exps >>= 1;

			auto base = x;
			while (exps)
			{
				mul(base, base, base);
				if (exps & 1)
					mul(result, result, base);
				exps >>= 1;
			}
		}


		// inv(result, in):
		//   Compute the multiplicative inverse of in modulo p via an extended Euclidean algorithm.
		//   Convention: inv(0) = 0. Callers should treat 0 as non-invertible in strict math contexts.
		static constexpr OC_FORCEINLINE void inv(
			Goldilocks& result,
			Goldilocks in);


		// mul(result, in1, in2):
		//   Field multiplication. Currently forwards to mulPzt22.
		static constexpr OC_FORCEINLINE void mul(
			Goldilocks& result,
			Goldilocks in1,
			Goldilocks in2);

		static constexpr OC_FORCEINLINE void redPzt22(Goldilocks& result, u64 lo, u64 hi);

		// mulPzt22(result, in1, in2):
		//   Fast modular multiplication specialized for Goldilocks:
		//     Let x = in1 * in2 = x_hi * 2^64 + x_lo.
		//     Using congruences 2^64 ≡ 2^32 - 1 and 2^96 ≡ -1 (mod p),
		//     reduce with:
		//       x ≡ x0 - x2 + x1*(2^32 - 1)  (mod p),
		//     where x1 = low32(x_hi), x2 = high32(x_hi), x0 = x_lo.
		static constexpr OC_FORCEINLINE void mulPzt22(
			Goldilocks& result,
			Goldilocks in1,
			Goldilocks in2);

		// Alternative multiplication variants (commented out). Kept as references for experimentation.
		//static constexpr void mulBerrettV2(
		//	Goldilocks& result,
		//	Goldilocks in1,
		//	Goldilocks in2);
		//static constexpr void mulBerrettV1(
		//	Goldilocks& result,
		//	Goldilocks in1,
		//	Goldilocks in2);

		// add(result, in1, in2):
		//   Field addition with branchless correction. If the 64-bit addition overflows, add (2^32 - 1),
		//   and if that overflows, add (2^32 - 1) again. This leverages the Goldilocks modulus structure.
		static constexpr OC_FORCEINLINE void add(
			Goldilocks& result,
			Goldilocks in1,
			Goldilocks in2);

		// sub(result, in1, in2):
		//   Field subtraction with branchless correction. If the subtraction borrows, subtract (2^32 - 1),
		//   and if that borrows, subtract (2^32 - 1) again.
		static constexpr OC_FORCEINLINE void sub(
			Goldilocks& result,
			Goldilocks in1,
			Goldilocks in2);

		// increment(result, in1):
		//   result = in1 + 1 (mod p).
		static constexpr OC_FORCEINLINE void increment(
			Goldilocks& result,
			Goldilocks in1)
		{
			auto v = in1.mVal + 1;
			result.mVal = v < mModulus ? v : v - mModulus;
		}

		// decrement(result, in1):
		//   result = in1 - 1 (mod p).
		static constexpr OC_FORCEINLINE void decrement(
			Goldilocks& result,
			Goldilocks in1)
		{

			auto v = in1.mVal - 1;
			result.mVal = in1.mVal == 0 ? mModulus - 1 : v;
		}

		// negate(result, in1):
		//   result = -in1 (mod p). Note that -0 = 0.
		static constexpr OC_FORCEINLINE void negate(
			Goldilocks& result,
			Goldilocks in1)
		{
			auto v = in1.canonical().mVal;
			result.mVal = v == 0 ? 0 : mModulus - v;
		}

	};


	static_assert(std::is_trivially_copyable<Goldilocks>::value, "Trivially copyable");
	static_assert(std::is_trivially_constructible_v<Goldilocks>, "Trivially constructible");
	static_assert(sizeof(Goldilocks) == 8, "Expected size");
	static_assert(std::is_constructible_v<Goldilocks, u64>, "Constructible from u64");
	static_assert(std::is_constructible_v<Goldilocks, decltype(1)>, "Constructible from int");



	// Function to prevent branch from being inlined/optimized away
#if defined(__GNUC__) || defined(__clang__)
	[[gnu::noinline]] inline void branch_hint() noexcept {
		asm volatile("" ::: "memory");
	}
#elif defined(_MSC_VER)
	__declspec(noinline) inline void branch_hint() noexcept {
		_ReadWriteBarrier(); // Memory barrier to prevent reordering
	}
#else
	inline void branch_hint() noexcept {
		// Generic fallback - might not work on all compilers
		volatile int dummy = 0;
		(void)dummy;
	}
#endif


	constexpr  OC_FORCEINLINE void Goldilocks::inv(
		Goldilocks& result,
		Goldilocks in)
	{
		// Extended Euclidean algorithm to find modular inverse
		if (in.mVal == 0)
		{
			result.mVal = 0; // Handle zero case gracefully
			return;
		}

		Goldilocks t{ 0 };
		Goldilocks r{ mModulus };
		Goldilocks tt{ 1 };
		Goldilocks rr{ in.mVal };
		while (rr.mVal != 0) {
			auto q = Goldilocks{ r.mVal / rr.mVal };

			// Update t and tt
			t = std::exchange(tt, t - q * tt);

			// Update r and rr
			r = std::exchange(rr, r - q * rr);
		}
		result.mVal = t.mVal;
	}


	// [x]p=[x'''⋅2^96 +x'' 2^64+x']p
//     =[x2(−1)+x1(2^32−1)+x0]p
//     =[x1(2^32−1)+x0-x2]p
//
// due to 2^96 ≡ -1 (mod p) and 2^64 ≡ 2^32 - 1 (mod p)
	constexpr OC_FORCEINLINE void Goldilocks::redPzt22(
		Goldilocks& result,
		u64 lo,
		u64 hi)
	{
		constexpr u64 EPSILON = (1ull << 32) - 1;

		u64 x2 = hi >> 32;
		u64 x1 = hi & EPSILON;

		// t0 = x0 - x2
		u8 borrow;
		auto t0 = subc64(lo, x2, borrow);

		if (1)
		{
			if (borrow) /*[[unlikely]]*/ {
				branch_hint();
				t0 -= EPSILON;
			}
		}
		else
		{
			t0 -= -u32(borrow);
		}

		// t1 = x1 * (2^32 - 1)
		//auto t1 = x1 * EPSILON;
		auto t1 = (x1 << 32) - x1;

		// result = t0 + t1
		//        = x0 - x2 + x1 * (2^32 - 1)
		u8 carry;
		u64 res_wrapped = addc64(t0, t1, carry);
		u64 res = res_wrapped + (u64(carry) << 32) - carry;

		result.mVal = res;
	}

	// [x]p=[x'''⋅2^96 +x'' 2^64+x']p
	//     =[x2(−1)+x1(2^32−1)+x0]p
	//     =[x1(2^32−1)+x0-x2]p
	//
	// due to 2^96 ≡ -1 (mod p) and 2^64 ≡ 2^32 - 1 (mod p)
	constexpr OC_FORCEINLINE void Goldilocks::mulPzt22(
		Goldilocks& result,
		Goldilocks in1,
		Goldilocks in2)
	{

		// 2^32 - 1

		u64 x0, x_hi;
		mul128(in1.mVal, in2.mVal, x0, x_hi);
		redPzt22(result, x0, x_hi);

#if !defined(NDEBUG) 
		{
			saf
			auto prod = (u128(in1.mVal) * u128(in2.mVal)) % u128(mModulus);
			auto vv = Goldilocks{ result.mVal }.canonical();
			assert(vv.mVal == prod);
		}
#endif
	}

#if 0

#define SIMD(j, X) if constexpr(w==2)\
{\
	{ constexpr int j = 0; X; }\
	{ constexpr int j = 1; X; }\
}\
	else for (u64 j = 0; j < w; j++) { X; }\
 do {} while (0)

	// [x]p=[x'''⋅2^96 +x'' 2^64+x']p
//     =[x2(−1)+x1(2^32−1)+x0]p
//     =[x1(2^32−1)+x0-x2]p
//
// due to 2^96 ≡ -1 (mod p) and 2^64 ≡ 2^32 - 1 (mod p)
	template<int w>
	inline void redPzt22x4(
		u64* __restrict result,
		u64* __restrict lo,
		u64* __restrict hi)
	{
		constexpr u64 EPSILON = (1ull << 32) - 1;

		u64 x2[w], x1[w];
		u8 borrow[w];
		u64 t0[w], t1[w];
		u8 carry[w];
		u64 res_wrapped[w];

		SIMD(j, x2[j] = hi[j] >> 32);
		SIMD(j, x1[j] = hi[j] & EPSILON);

		// t0 = x0 - x2
		SIMD(j, borrow[j] = _subborrow_u64(0, lo[j], x2[j], t0 + j));

		SIMD(j, if (borrow[j]) { branch_hint(); t0[j] -= EPSILON; });

		// t1 = x1 * (2^32 - 1)
		//auto t1 = x1 * EPSILON;
		SIMD(j, t1[j] = (x1[j] << 32) - x1[j]);
		// result = t0 + t1
		//        = x0 - x2 + x1 * (2^32 - 1)
		SIMD(j, carry[j] = _addcarry_u64(0, t0[j], t1[j], res_wrapped + j));

		SIMD(j, result[j] = res_wrapped[j] + (u64(carry[j]) << 32) - carry[j]);
	}

	// [x]p=[x'''⋅2^96 +x'' 2^64+x']p
	//     =[x2(−1)+x1(2^32−1)+x0]p
	//     =[x1(2^32−1)+x0-x2]p
	//
	// due to 2^96 ≡ -1 (mod p) and 2^64 ≡ 2^32 - 1 (mod p)
	template<int w>
	inline void mulPzt22x4(
		u64* __restrict result,
		const u64* __restrict in1,
		const u64* __restrict in2)
	{

		// 2^32 - 1
		u64 low[w], high[w];
		SIMD(j, low[j] = _mulx_u64(in1[j], in2[j], (long long unsigned int* )high + j)); // high = a*b/2^64
		redPzt22x4<w>(result, low, high);

		//#if !defined(NDEBUG) 
		//		{
		//			auto prod = (u128(in1.mVal) * u128(in2.mVal)) % u128(mModulus);
		//			auto vv = Goldilocks{ result.mVal }.canonical();
		//			assert(vv.mVal == prod);
		//		}
		//#endif
	}
#undef SIMD
#endif

	//	constexpr void Goldilocks::mulBerrettV1(
	//		Goldilocks& result,
	//		Goldilocks in1,
	//		Goldilocks in2)
	//	{
	//		// p = 2^64 - 2^32 + 1, b = 2^32, EPSILON = b - 1
	//		//constexpr u64 EPSILON = (1ull << 32) - 1; // 0x00000000FFFFFFFF
	//
	//		// 128-bit product x = a*b = (x1 << 64) | x0
	//		u64 xL, xH;
	//		mul128(in1.mVal, in2.mVal, xL, xH);
	//
	//
	//
	//		u32 x0 = u32(xL);
	//		u32 x1 = u32(xL >> 32);
	//		u32 x2 = u32(xH);
	//		u32 x3 = u32(xH >> 32);
	//
	//		constexpr u64 b = 1ull << 32;
	//		constexpr u64 EPS = b - 1;                   // 2^32 - 1
	//		constexpr u64 p = mModulus;                // b^2 - b + 1
	//
	//		// s = x1 + x2; carry = floor(s / b); low = s mod b
	//		const u64 s = u64(x1) + u64(x2);         // <= 2^33 - 2
	//		const u64 carry = s >> 32;                   // 0 or 1
	//		const u64 low = u64(u32(s));               // (x1 + x2) mod b
	//
	//		// A = x0 + x1 + low * (b-1)  (fits in 65 bits; capture final carryA)
	//		u8 sum0, c0;
	//		sum0 = addc64(u64(x0), u64(x1), c0);         // c0 == 0 (since <= 2^33-2)
	//
	//		const u64 term = low * EPS;                  // fits in 64 bits
	//		u64 A;
	//		u8 c1;
	//		A = addc64(sum0, term, c1);                  // c1 ∈ {0,1}
	//		const u64 carryA = c1;                       // whether A overflowed 64 bits
	//
	//		// B = x3 + carry  (<= 2^32)
	//		u64 B;
	//		u8 cB;
	//		B = addc64(u64(x3), carry, cB);              // cB == 0
	//
	//		// r = A - B (mod 2^64), capture borrow
	//		u64 r_mod;
	//		u8 borrowAB;
	//		r_mod = subc64(A, B, borrowAB);
	//
	//		// If carryA==0 and we borrowed, then r < 0.
	//		// Produce r += p safely as (p - B) + A  (no overflow since A < B here).
	//		if (!carryA && borrowAB) {
	//			u64 t;
	//			u8 b1;
	//			t = subc64(p, B, b1);                    // b1 == 0 (since p > B)
	//			u64 r_pos;
	//			u8 c2;
	//			r_pos = addc64(t, A, c2);                // c2 == 0 (A < B ⇒ sum < p)
	//			result.mVal = r_pos;
	//			return;
	//		}
	//
	//		// Otherwise r >= 0. Possibly subtract p once (at most one needed).
	//		u64 r1;
	//		u8 bP;
	//		r1 = subc64(r_mod, p, bP);                   // if no borrow, r_mod >= p
	//		auto r = (bP ? r_mod : r1);
	//
	//#if !defined(NDEBUG) && defined(__SIZEOF_INT128__)
	//		{
	//			// Verify correctness modulo p (debug only).
	//			__uint128_t prod = ((__uint128_t)in1.mVal * (__uint128_t)in2.mVal)
	//				% (__uint128_t)mModulus;
	//			auto check = Goldilocks{ (u64)r }.canonical();
	//			assert(check.mVal == prod);
	//		}
	//#endif
	//
	//		result.mVal = r;
	//	}

		//	constexpr void Goldilocks::mulBerrettV2(
		//		Goldilocks& result,
		//		Goldilocks in1,
		//		Goldilocks in2)
		//	{
		//		// p = 2^64 - 2^32 + 1, b = 2^32, EPSILON = b - 1
		//		constexpr u64 EPSILON = (1ull << 32) - 1; // 0x00000000FFFFFFFF
		//
		//		// 128-bit product x = a*b = (x1 << 64) | x0
		//		u64 x0, x1;
		//		mul128(in1.mVal, in2.mVal, x0, x1);
		//
		//		// Notation matches the blog:
		//		// x0 = low 64 bits, x1 = high 64 bits
		//
		//		// Compute the carry of: x0 + ((x1<<32) - (x1>>32))
		//		// (This equals floor((x1_low32 + x1_high32) / 2^32).)
		//		const u64 t = (x1 << 32) - (x1 >> 32);   // wraps mod 2^64, by design
		//		u64 carry0;
		//		(void)addc64(x0, t, carry0);            // carry0 ∈ {0,1}
		//
		//		// q = (x1 >> 32) + x1 + carry0, tracking overflow of q itself
		//		u64 q, c1, c2;
		//		q = addc64(x1 >> 32, x1, c1);
		//		q = addc64(q, carry0, c2);
		//		const u64 q_overflow = c1 | c2;          // 1 iff q overflowed 64 bits
		//
		//		// r = x0 + (q<<32) - q   (all wrapping 64-bit ops)
		//		u64 r = x0 + (q << 32);
		//		r -= q;
		//
		//		// Variant B fix-up: if q overflowed, add (2^32 - 1)
		//		constexpr u64 EPS = (1ull << 32) - 1;
		//		r += (EPS & (0 - q_overflow));           // branchless
		//
		//
		//#ifndef NDEBUG
		//		{
		//			// Verify correctness modulo p (debug only).
		//			__uint128_t prod = ((__uint128_t)in1.mVal * (__uint128_t)in2.mVal)
		//				% (__uint128_t)mModulus;
		//			auto check = Goldilocks{ r }.canonical();
		//			assert(check.mVal == prod);
		//		}
		//#endif
		//
		//		result.mVal = r;
		//	}



	constexpr OC_FORCEINLINE void Goldilocks::mul(
		Goldilocks& result,
		Goldilocks in1,
		Goldilocks in2)
	{
		mulPzt22(result, in1, in2);
	}


	constexpr OC_FORCEINLINE void Goldilocks::add(
		Goldilocks& result,
		Goldilocks in1,
		Goldilocks in2)
	{
		constexpr u64 reducer = 0x00000000FFFFFFFFull;

		// First add with carry
		u8 carry1 = 0;
		u64 sum = addc64(in1.mVal, in2.mVal, carry1);

		// If carry, add reducer
		u64 correction = reducer & (0 - carry1); // 0 if no carry, reducer if carry

		//sum += correction;

		// Add correction and check for second carry
		// might overflow because we allow non-reduced values.
		// eg in1 = -1, in2 = -1;
		u8 carry2 = 0;
		sum = addc64(sum, correction, carry2);

		// If second carry, add reducer again
		if (0)
		{
			sum += reducer & (0 - carry2);
		}
		else
		{
			if (carry2)
			{
				branch_hint();
				sum += reducer;
			}
		}

		result.mVal = sum;
	}

	constexpr  OC_FORCEINLINE void Goldilocks::sub(
		Goldilocks& result,
		Goldilocks in1,
		Goldilocks in2)
	{
			constexpr u64 reducer = 0x00000000FFFFFFFFull;
			//constexpr u64 masks[2]{ 0, reducer };

			// Subtract with borrow detection
			u8 borrow1 = 0;
			u64 diff = subc64(in1.mVal, in2.mVal, borrow1);


			// If borrow, subtract reducer
			u64 correction = reducer & (0 - borrow1);
			//u64 correction = masks[borrow1];
			//diff -= correction;

			// Subtract correction and check for second borrow
			u8 borrow2 = 0;
			diff = subc64(diff, correction, borrow2);


			// If second borrow, subtract reducer again
			if (0)
			{
				diff -= reducer & (0 - borrow2);
			}
			else
			{
				if (borrow2)
				{
					branch_hint();
					diff -= reducer;
				}
			}

			result.mVal = diff;
	}

	// Table of primitive 2^k-th roots of unity for k=0..32, suitable for NTTs over F_p.
	// Entry i is a primitive 2^i-th root. Consumers should ensure sizes are powers of two.
	static constexpr std::array<Goldilocks, 33> GoldilocksRootsOfUnity =
	{
		Goldilocks{1ull},
		Goldilocks{18446744069414584320ull},
		Goldilocks{281474976710656ull},
		Goldilocks{16777216ull},
		Goldilocks{4096ull},
		Goldilocks{64ull},
		Goldilocks{8ull},
		Goldilocks{2198989700608ull},
		Goldilocks{4404853092538523347ull},
		Goldilocks{6434636298004421797ull},
		Goldilocks{4255134452441852017ull},
		Goldilocks{9113133275150391358ull},
		Goldilocks{4355325209153869931ull},
		Goldilocks{4308460244895131701ull},
		Goldilocks{7126024226993609386ull},
		Goldilocks{1873558160482552414ull},
		Goldilocks{8167150655112846419ull},
		Goldilocks{5718075921287398682ull},
		Goldilocks{3411401055030829696ull},
		Goldilocks{8982441859486529725ull},
		Goldilocks{1971462654193939361ull},
		Goldilocks{6553637399136210105ull},
		Goldilocks{8124823329697072476ull},
		Goldilocks{5936499541590631774ull},
		Goldilocks{2709866199236980323ull},
		Goldilocks{8877499657461974390ull},
		Goldilocks{3757607247483852735ull},
		Goldilocks{4969973714567017225ull},
		Goldilocks{2147253751702802259ull},
		Goldilocks{2530564950562219707ull},
		Goldilocks{1905180297017055339ull},
		Goldilocks{3524815499551269279ull},
		Goldilocks{7277203076849721926ull}
	};


	// primRootOfUnity<F>(n):
	//   Return a primitive n-th root of unity for the field type F.
	//   For Goldilocks, n must be a power of two and is served from GoldilocksRootsOfUnity.
	//   This primary template is declared for specialization by other fields.
	template<typename F>
	inline F primRootOfUnity(u64 n);

	// Goldilocks specialization:
	// - n must be a power of two (n = 2^k).
	// - Returns the precomputed primitive n-th root from the table above.
	template<>
	inline Goldilocks primRootOfUnity<Goldilocks>(u64 n)
	{
		auto ln = log2ceil(n);
		if (1ull << ln != n)
			throw RTE_LOC;
		return GoldilocksRootsOfUnity[ln];
	}


}
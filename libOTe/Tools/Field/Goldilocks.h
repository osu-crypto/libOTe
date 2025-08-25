#pragma once

#include "cryptoTools/Common/Defines.h"
#include <array>
#include <iostream>
#include <assert.h>
#include <utility>
#include <immintrin.h>
#include "util.h"

namespace osuCrypto
{


	// Finite field Fp with p = 2^64 - 2^32 + 1. 
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
		static constexpr u64 mModulus = 0xffffffff00000001ull;

		// we store the value in unreduced form.
		// eg, mVal = mModulus is a valid representation of 0.
		u64 mVal;

		constexpr Goldilocks canonical() const noexcept
		{
			auto res = mVal;
			if (res >= mModulus)
				res -= mModulus;
			return { res };
		}

		constexpr operator u64() const noexcept
		{
			return canonical().mVal;
		}

		constexpr Goldilocks operator+(const Goldilocks& rhs) const noexcept
		{
			Goldilocks result;
			add(result, *this, rhs);
			return result;
		}
		constexpr Goldilocks& operator+=(const Goldilocks& rhs) noexcept
		{
			add(*this, *this, rhs);
			return *this;
		}
		constexpr Goldilocks operator-(const Goldilocks& rhs) const noexcept
		{
			Goldilocks result;
			sub(result, *this, rhs);
			return result;
		}
		constexpr Goldilocks& operator-=(const Goldilocks& rhs) noexcept
		{
			sub(*this, *this, rhs);
			return *this;
		}
		constexpr Goldilocks operator*(const Goldilocks& rhs) const noexcept
		{
			Goldilocks result;
			mul(result, *this, rhs);
			return result;
		}
		constexpr Goldilocks& operator*=(const Goldilocks& rhs) noexcept
		{
			mul(*this, *this, rhs);
			return *this;
		}

		constexpr Goldilocks operator/(const Goldilocks& rhs) const noexcept
		{
			Goldilocks result;
			inv(result, rhs);
			mul(result, *this, result);
			return result;
		}
		constexpr Goldilocks& operator/=(const Goldilocks& rhs) noexcept
		{
			Goldilocks inv_rhs;
			inv(inv_rhs, rhs);
			mul(*this, *this, inv_rhs);
			return *this;
		}

		constexpr bool operator==(const Goldilocks& rhs) const noexcept
		{
			return canonical().mVal == rhs.canonical().mVal;
		}
		constexpr bool operator!=(const Goldilocks& rhs) const noexcept
		{
			return !(*this == rhs);
		}
		constexpr bool operator<(const Goldilocks& rhs) const noexcept
		{
			return canonical().mVal < rhs.canonical().mVal;
		}
		constexpr bool operator<=(const Goldilocks& rhs) const noexcept
		{
			return canonical().mVal <= rhs.canonical().mVal;
		}
		constexpr bool operator>(const Goldilocks& rhs) const noexcept
		{
			return canonical().mVal > rhs.canonical().mVal;
		}
		constexpr bool operator>=(const Goldilocks& rhs) const noexcept
		{
			return canonical().mVal >= rhs.canonical().mVal;
		}

		constexpr Goldilocks& operator=(const Goldilocks& other) noexcept = default;

		//// increment operators
		//constexpr Goldilocks& operator++()
		//{
		//	add(*this, *this, { 1 });
		//	return *this;
		//}

		static constexpr void exp(
			Goldilocks& result,
			const Goldilocks& x,
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

		static constexpr void inv(
			Goldilocks& result,
			const Goldilocks& in);


		static constexpr void mul(
			Goldilocks& result,
			const Goldilocks& in1,
			const Goldilocks& in2);


		static constexpr void mulPzt22(
			Goldilocks& result,
			const Goldilocks& in1,
			const Goldilocks& in2);

		//static constexpr void mulBerrettV2(
		//	Goldilocks& result,
		//	const Goldilocks& in1,
		//	const Goldilocks& in2);


		//static constexpr void mulBerrettV1(
		//	Goldilocks& result,
		//	const Goldilocks& in1,
		//	const Goldilocks& in2);

		static constexpr void add(
			Goldilocks& result,
			const Goldilocks& in1,
			const Goldilocks& in2);

		static constexpr void sub(
			Goldilocks& result,
			const Goldilocks& in1,
			const Goldilocks& in2);

		static constexpr void increment(
			Goldilocks& result,
			const Goldilocks& in1)
		{
			auto v = in1.mVal + 1;
			result.mVal = v < mModulus ? v : v - mModulus;
		}

		static constexpr void decrement(
			Goldilocks& result,
			const Goldilocks& in1)
		{

			auto v = in1.mVal - 1;
			result.mVal = in1.mVal == 0 ? mModulus - 1 : v;
		}



	};



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


	constexpr void Goldilocks::inv(
		Goldilocks& result,
		const Goldilocks& in)
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
	constexpr void Goldilocks::mulPzt22(
		Goldilocks& result,
		const Goldilocks& in1,
		const Goldilocks& in2)
	{

		// 2^32 - 1
		constexpr u64 EPSILON = (1ull << 32) - 1;

		u64 x0, x_hi;
		mul128(in1.mVal, in2.mVal, x0, x_hi);

		u64 x2 = x_hi >> 32;
		u64 x1 = x_hi & EPSILON;


		// t0 = x0 - x2
		u8 borrow;
		auto t0 = subc64(x0, x2, borrow);
		if (borrow) {
			branch_hint();
			t0 -= EPSILON;
		}

		// t1 = x1 * (2^32 - 1)
		//auto t1 = x1 * EPSILON;
		auto t1 = (x1 << 32) - x1;

		// result = t0 + t1
		//        = x0 - x2 + x1 * (2^32 - 1)
		u8 carry;
		u64 res_wrapped = addc64(t0, t1, carry);
		u64 res = res_wrapped + (u64(carry) << 32) - carry;

#if !defined(NDEBUG) && defined(__SIZEOF_INT128__)
		{
			auto prod = (__uint128_t(in1.mVal) * in2.mVal) % __uint128_t(mModulus);
			auto vv = Goldilocks{ res }.canonical();
			assert(vv.mVal == prod);
		}
#endif

		result.mVal = res;
	}


//	constexpr void Goldilocks::mulBerrettV1(
//		Goldilocks& result,
//		const Goldilocks& in1,
//		const Goldilocks& in2)
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
	//		const Goldilocks& in1,
	//		const Goldilocks& in2)
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



	constexpr void Goldilocks::mul(
		Goldilocks& result,
		const Goldilocks& in1,
		const Goldilocks& in2)
	{
		mulPzt22(result, in1, in2);
	}


	constexpr void Goldilocks::add(
		Goldilocks& result,
		const Goldilocks& in1,
		const Goldilocks& in2)
	{
		constexpr u64 reducer = 0x00000000FFFFFFFFull;

		// First add with carry
		u8 carry1 = 0;
		u64 sum = addc64(in1.mVal, in2.mVal, carry1);

		// If carry, add reducer
		u64 correction = reducer & (0 - carry1); // 0 if no carry, reducer if carry

		// Add correction and check for second carry
		u8 carry2 = 0;
		sum = addc64(sum, correction, carry2);

		// If second carry, add reducer again
		sum += reducer & (0 - carry2);

		result.mVal = sum;
	}

	constexpr void Goldilocks::sub(
		Goldilocks& result,
		const Goldilocks& in1,
		const Goldilocks& in2)
	{
		constexpr u64 reducer = 0x00000000FFFFFFFFull;

		// Subtract with borrow detection
		u8 borrow1 = 0;
		u64 diff = subc64(in1.mVal, in2.mVal, borrow1);

		// If borrow, subtract reducer
		u64 correction = reducer & (0 - borrow1);

		// Subtract correction and check for second borrow
		u8 borrow2 = 0;
		diff = subc64(diff, correction, borrow2);

		// If second borrow, subtract reducer again
		diff -= reducer & (0 - borrow2);

		result.mVal = diff;
	}

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





}
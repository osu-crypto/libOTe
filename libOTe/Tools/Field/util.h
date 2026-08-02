#pragma once

#include "cryptoTools/Common/Defines.h"
#if (defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86))
	#if defined(_MSC_VER)
		#include <immintrin.h>
	#else
		#include <x86intrin.h>
	#endif
	#define OSUCRYPTO_HAS_X86_ADDCARRY 1
#endif

#if defined(__BMI2__) || (defined(_MSC_VER) && defined(__AVX2__)) // VS usually ties BMI2 to /arch:AVX2
#define OSUCRYPTO_HAVE_MULX 1
#else
#define OSUCRYPTO_HAVE_MULX 0
#endif

namespace osuCrypto
{


	// (a + b + cin) mod 2^64; sets cout to 0/1
	constexpr OC_FORCEINLINE u64 addc64(u64 a, u64 b, u8 cin, u8& cout) noexcept {
		if (std::is_constant_evaluated()) {
			u64 t = a + b;        
			u64 c1 = (t < a);
			u64 s = t + cin;      
			u64 c2 = (s < t);
			cout = (c1 | c2);
			return s;
		}
		else {
#if defined(OSUCRYPTO_HAS_X86_ADDCARRY)
			unsigned long long s;
			cout = _addcarry_u64(cin, a, b, &s);
			return static_cast<u64>(s);
#else
			u64 t = a + b;        
			u64 c1 = (t < a);
			u64 s = t + cin;      
			u64 c2 = (s < t);
			cout = (c1 | c2);
			return s;
#endif
		}
	}

	// convenience wrapper: carry-in = 0
	constexpr OC_FORCEINLINE u64 addc64(u64 a, u64 b, u8& cout) noexcept {
		return addc64(a, b, 0, cout);
	}

	// (a - b - bin) mod 2^64; sets bout to 0/1 (1 = borrow)
	constexpr OC_FORCEINLINE u64 subc64(u64 a, u64 b, u8 bin, u8& bout) noexcept {
		if (std::is_constant_evaluated()) {
			u64 t = a - b;        
			u64 b1 = (a < b);
			u64 d = t - bin;      
			u64 b2 = (t < bin);
			bout = (b1 | b2);
			return d;
		}
		else {
#if defined(OSUCRYPTO_HAS_X86_ADDCARRY)
			unsigned long long d;
			bout = _subborrow_u64(bin, a, b, &d);
			return static_cast<u64>(d);
#else
			u64 t = a - b;        u64 b1 = (a < b);
			u64 d = t - bin;      u64 b2 = (t < bin);
			bout = (b1 | b2);
			return d;
#endif
		}
	}

	// convenience wrapper: borrow-in = 0
	constexpr OC_FORCEINLINE u64 subc64(u64 a, u64 b, u8& bout) noexcept {
		return subc64(a, b, 0, bout);
	}

	// Generic helper function for 64×64→128-bit multiplication
	// Returns a 128-bit product of two 64-bit unsigned integers
	constexpr OC_FORCEINLINE void mul128(u64 a, u64 b, u64& low, u64& high) noexcept
	{
		auto portable = [&]() {
			// Portable implementation for constexpr evaluation
			// Use grade-school multiplication algorithm

			// Split into 32-bit chunks
			u64 a_lo = a & 0xFFFFFFFF;
			u64 a_hi = a >> 32;
			u64 b_lo = b & 0xFFFFFFFF;
			u64 b_hi = b >> 32;

			// Compute partial products
			u64 lo_lo = a_lo * b_lo;
			u64 hi_lo = a_hi * b_lo;
			u64 lo_hi = a_lo * b_hi;
			u64 hi_hi = a_hi * b_hi;

			// Combine partial products with proper carries
			u64 mid = (lo_lo >> 32) + (hi_lo & 0xFFFFFFFF) + (lo_hi & 0xFFFFFFFF);

			low = (lo_lo & 0xFFFFFFFF) | (mid << 32);
			high = (mid >> 32) + (hi_lo >> 32) + (lo_hi >> 32) + hi_hi;
			};
		if (std::is_constant_evaluated())
		{
			portable();
		}
		else
		{
#ifdef ENABLE_BMI2
			low = _mulx_u64(a, b, (long long unsigned int*) &high); // high = a*b/2^64
#elif defined(__SIZEOF_INT128__)
			// GCC/Clang with native __int128 support
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#endif

			unsigned __int128 result = static_cast<unsigned __int128>(a) * b;

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
			low = static_cast<u64>(result);
			high = static_cast<u64>(result >> 64);

#elif defined(_MSC_VER) && defined(_M_X64)
			// MSVC on x64 - use intrinsics
			//low = _mulx_u64(a, b, &high); // high = a*b/2^64
			low = _umul128(a, b, &high);
#elif (defined(__GNUC__) || defined(__clang__)) && (defined(__x86_64__) || defined(__aarch64__))
			// Use GCC/Clang inline assembly for x86_64 or ARM64
#if defined(__x86_64__)
			asm("mulq %3" : "=a"(low), "=d"(high) : "a"(a), "rm"(b));
#elif defined(__aarch64__)
			asm("mul %0, %2, %3\n\t"
				"umulh %1, %2, %3"
				: "=r"(low), "=r"(high)
				: "r"(a), "r"(b));
#endif
#else
			portable();
#endif
		}
	}
}
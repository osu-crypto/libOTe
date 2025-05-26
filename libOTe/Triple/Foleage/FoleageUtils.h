#pragma once
// © 2025 Peter Rindal.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

// Code partially authored by:
// Maxime Bombar, Dung Bui, Geoffroy Couteau, Alain Couvreur, Clément Ducros, and Sacha Servan - Schreiber


#include "libOTe/config.h"
#if defined(ENABLE_FOLEAGE) || defined(ENABLE_TERNARY_DPF)

#include "cryptoTools/Crypto/AES.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Crypto/RandomOracle.h"
#include <cmath>
#include <sstream>
#include <iomanip>

namespace osuCrypto
{


	// a value representing (Z_3)^32.
	// The value is stored in 2 bits per Z_3 element.
	struct F3x32
	{
		u64 mVal;

		F3x32() = default;
		F3x32(const F3x32&) = default;

		F3x32(u64 v)
		{
			fromInt(v);
		}

		F3x32& operator=(const F3x32&) = default;

		F3x32 operator+(const F3x32& t) const
		{
			F3x32 r;
			r.mVal = 0;
			for (u64 i = 0; i < 32; ++i)
			{
				auto a = t[i];
				auto b = (*this)[i];
				auto c = (a + b) % 3;

				r.mVal |= u64(c) << (i * 2);
			}
			return r;
		}


		F3x32 operator-(const F3x32& t) const
		{
			F3x32 r;
			r.mVal = 0;
			for (u64 i = 0; i < 32; ++i)
			{
				auto a = t[i];
				auto b = (*this)[i];
				auto c = (b + 3 - a) % 3;

				r.mVal |= u64(c) << (i * 2);
			}
			return r;
		}


		bool operator==(const F3x32& t) const
		{
			return mVal == t.mVal;
		}


		u64 toInt() const
		{
			u64 r = 0;
			for (u64 i = 31; i < 32; --i)
			{
				r *= 3;
				r += (mVal >> (i * 2)) & 3;
			}

			return r;
		}

		void fromInt(u64 v)
		{
			mVal = 0;
			for (u64 i = 0; i < 32; ++i)
			{
				mVal |= (v % 3) << (i * 2);
				v /= 3;
			}
		}

		F3x32 lower(u64 digits)
		{
			F3x32 r;
			r.mVal = mVal & ((1ull << (2 * digits)) - 1);
			return r;
		}
		F3x32 upper(u64 digits)
		{
			F3x32 r;
			r.mVal = mVal >> (2 * digits);
			return r;
		}

		// returns the i'th Z_3 element.
		u8 operator[](u64 i) const
		{
			return (mVal >> (i * 2)) & 3;
		}
	};

	inline std::ostream& operator<<(std::ostream& o, const F3x32& t)
	{
		u64 m = 0;
		u64 v = t.mVal;
		while (v)
		{
			++m;
			v >>= 2;
		}
		if (!m)
			o << "0";
		else
		{
			for (u64 i = m - 1; i < m; --i)
			{
				o << int(t[i]);
			}
		}
		return o;
	}


	// Multiplies two elements of F4
	// and returns the result.
	inline uint8_t F4Multiply(uint8_t a, uint8_t b)
	{
		u8 tmp = ((a & 0b10) & (b & 0b10));
		uint8_t res = tmp ^ (((a & 0b10) & ((b & 0b01) << 1)) ^ (((a & 0b01) << 1) & (b & 0b10)));
		res |= ((a & 0b01) & (b & 0b01)) ^ (tmp >> 1);
		return res;
	}


	// component-wise Multiplies two elements of F4^64 
	// and returns the result.
	inline void F4Multiply(
		block aLsb, block aMsb,
		block bLsb, block bMsb,
		block& cLsb, block& cMsb)
	{
		auto tmp = aMsb & bMsb;// msb only
		cMsb = tmp ^ (aMsb & bLsb) ^ (aLsb & bMsb);// msb only
		cLsb = (aLsb & bLsb) ^ tmp;
	}


	// Multiplies two packed matrices of F4 elements column-by-column.
	// Note that here the "columns" are packed into an element of uint8_t
	// resulting in a matrix with 4 columns.
	inline void F4Multiply(
		span<uint8_t> a_poly,
		span<uint8_t> b_poly,
		span<uint8_t> res_poly,
		size_t poly_size)
	{
		const uint8_t pattern = 0xaa;
		uint8_t mask_h = pattern;     // 0b10101010
		uint8_t mask_l = mask_h >> 1; // 0b01010101

		uint8_t tmp;
		uint8_t a_h, a_l, b_h, b_l;

		for (size_t i = 0; i < poly_size; i++)
		{
			// multiplication over F4
			a_h = (a_poly[i] & mask_h);
			a_l = (a_poly[i] & mask_l);
			b_h = (b_poly[i] & mask_h);
			b_l = (b_poly[i] & mask_l);

			tmp = (a_h & b_h);
			res_poly[i] = tmp ^ (a_h & (b_l << 1));
			res_poly[i] ^= ((a_l << 1) & b_h);
			res_poly[i] |= (a_l & b_l) ^ (tmp >> 1);
		}
	}

	// Multiplies two packed matrices of F4 elements column-by-column.
	// Note that here the "columns" are packed into an element of uint16_t
	// resulting in a matrix with 8 columns.
	inline void F4Multiply(
		span<uint16_t> a_poly,
		span<uint16_t> b_poly,
		span<uint16_t> res_poly,
		size_t poly_size)
	{
		const uint16_t pattern = 0xaaaa;
		uint16_t mask_h = pattern;     // 0b101010101010101001010
		uint16_t mask_l = mask_h >> 1; // 0b010101010101010100101

		uint16_t tmp;
		uint16_t a_h, a_l, b_h, b_l;

		for (size_t i = 0; i < poly_size; i++)
		{
			// multiplication over F4
			a_h = (a_poly[i] & mask_h);
			a_l = (a_poly[i] & mask_l);
			b_h = (b_poly[i] & mask_h);
			b_l = (b_poly[i] & mask_l);

			tmp = (a_h & b_h);
			res_poly[i] = tmp ^ (a_h & (b_l << 1));
			res_poly[i] ^= ((a_l << 1) & b_h);
			res_poly[i] |= (a_l & b_l) ^ (tmp >> 1);
		}
	}

	// Multiplies two packed matrices of F4 elements column-by-column.
	// Note that here the "columns" are packed into an element of uint32_t
	// resulting in a matrix with 16 columns.
	inline void F4Multiply(
		span<uint32_t> a_poly,
		span<uint32_t> b_poly,
		span<uint32_t> res_poly,
		size_t poly_size)
	{
		const uint32_t pattern = 0xaaaaaaaa;
		uint32_t mask_h = pattern;     // 0b101010101010101001010
		uint32_t mask_l = mask_h >> 1; // 0b010101010101010100101

		uint32_t tmp;
		uint32_t a_h, a_l, b_h, b_l;

		for (size_t i = 0; i < poly_size; i++)
		{
			// multiplication over F4
			a_h = (a_poly[i] & mask_h);
			a_l = (a_poly[i] & mask_l);
			b_h = (b_poly[i] & mask_h);
			b_l = (b_poly[i] & mask_l);

			tmp = (a_h & b_h);
			res_poly[i] = tmp ^ (a_h & (b_l << 1));
			res_poly[i] ^= ((a_l << 1) & b_h);
			res_poly[i] |= (a_l & b_l) ^ (tmp >> 1);
		}
	}

	// Multiplies two packed matrices of F4 elements column-by-column.
	// Note that here the "columns" are packed into an element of uint64_t
	// resulting in a matrix with 32 columns.
	inline void F4Multiply(
		span<uint64_t> a_poly,
		span<uint64_t> b_poly,
		span<uint64_t> res_poly,
		size_t poly_size)
	{
		const uint64_t pattern = 0xaaaaaaaaaaaaaaaa;
		uint64_t mask_h = pattern;     // 0b101010101010101001010
		uint64_t mask_l = mask_h >> 1; // 0b010101010101010100101

		uint64_t tmp;
		uint64_t a_h, a_l, b_h, b_l;

		for (size_t i = 0; i < poly_size; i++)
		{
			// multiplication over F4
			a_h = (a_poly[i] & mask_h);
			a_l = (a_poly[i] & mask_l);
			b_h = (b_poly[i] & mask_h);
			b_l = (b_poly[i] & mask_l);

			tmp = (a_h & b_h);
			res_poly[i] = tmp ^ (a_h & (b_l << 1));
			res_poly[i] ^= ((a_l << 1) & b_h);
			res_poly[i] |= (a_l & b_l) ^ (tmp >> 1);
		}
	}

	inline u64 log3ceil(u64 x)
	{
		if (x == 0) return 0;
		u64 i = 0;
		u64 v = 1;
		while (v < x)
		{
			v *= 3;
			i++;
		}
		//assert(i == ceil(log_base(x, 3)));

		return i;
	}

	// Compute base^exp without the floating-point precision
	// errors of the built-in pow function.
	inline constexpr size_t ipow(size_t base, size_t exp)
	{
		if (exp == 1)
			return base;

		if (exp == 0)
			return 1;

		size_t result = 1;
		while (1)
		{
			if (exp & 1)
				result *= base;
			exp >>= 1;
			if (!exp)
				break;
			base *= base;
		}

		return result;
	}

	inline int popcount(block x)
	{
		return popcount(x.get<u64>(0)) + popcount(x.get<u64>(1));
	}

	inline std::array<u8, 64> extractF4(const block& val)
	{
		std::array<u8, 64> ret;
		const char* ptr = (const char*)&val;
		for (u8 i = 0; i < 16; ++i)
		{
			ret[i * 4 + 0] = (ptr[i] >> 0) & 3;
			ret[i * 4 + 1] = (ptr[i] >> 2) & 3;
			ret[i * 4 + 2] = (ptr[i] >> 4) & 3;
			ret[i * 4 + 3] = (ptr[i] >> 6) & 3;;
		}
		return ret;
	}

	// A 512 bit value that is used to represent a vector of 3^5=243 F4 elements.
	// We use this value because its greater than 128 bits and almost a power of 2.
	// the last 26 bits are unused.
	struct FoleageF4x243
	{
		std::array<block, 4> mVal;

		FoleageF4x243 operator^(const FoleageF4x243& o) const
		{
			FoleageF4x243 r;
			r.mVal[0] = mVal[0] ^ o.mVal[0];
			r.mVal[1] = mVal[1] ^ o.mVal[1];
			r.mVal[2] = mVal[2] ^ o.mVal[2];
			r.mVal[3] = mVal[3] ^ o.mVal[3];
			return r;
		}
		FoleageF4x243& operator^=(const FoleageF4x243& o)
		{
			mVal[0] = mVal[0] ^ o.mVal[0];
			mVal[1] = mVal[1] ^ o.mVal[1];
			mVal[2] = mVal[2] ^ o.mVal[2];
			mVal[3] = mVal[3] ^ o.mVal[3];
			return *this;
		}

		bool operator==(const FoleageF4x243& o) const
		{
			return
				mVal[0] == o.mVal[0] &&
				mVal[1] == o.mVal[1] &&
				mVal[2] == o.mVal[2] &&
				mVal[3] == o.mVal[3];
		}
	};

	inline std::array<u8, 256> extractF4(const FoleageF4x243& val)
	{
		std::array<u8, 256> ret;
		const char* ptr = (const char*)&val;
		for (u8 i = 0; i < 64; ++i)
		{
			ret[i * 4 + 0] = (ptr[i] >> 0) & 3;
			ret[i * 4 + 1] = (ptr[i] >> 2) & 3;
			ret[i * 4 + 2] = (ptr[i] >> 4) & 3;
			ret[i * 4 + 3] = (ptr[i] >> 6) & 3;;
		}
		return ret;
	}
}
#endif
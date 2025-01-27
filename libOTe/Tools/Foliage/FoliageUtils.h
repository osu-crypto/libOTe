#pragma once
#include "cryptoTools/Crypto/AES.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <cmath>
#include "uint128.h"
namespace osuCrypto
{
	using uint128_t = absl::uint128_t;
	//using int128_t = block;
	//using uint128_t = block;
	//using uint128_t = __uint128_t;
	//struct uint128_t
	//{
	//	std::array<u64, 2> mVals;

	//	uint128_t() = default;
	//	uint128_t(const uint128_t&) = default;
	//	uint128_t& operator=(const uint128_t&) = default;

	//	uint128_t(const u64& v) : mVals({ v,0 }) {};

	//	bool operator==(const uint128_t& o) const { return mVals[0] == o.mVals[0] && mVals[1] == o.mVals[1]; }
	//	bool operator!=(const uint128_t& o) const { return !(*this == o); }

	//	bool operator==(const u64& o) const { return *this == uint128_t{ o }; }
	//	bool operator!=(const u64& o) const { return *this != uint128_t{ o }; }
	//	bool operator==(const int& o) const { return *this == uint128_t{ u64(o) }; }
	//	bool operator!=(const int& o) const { return *this != uint128_t{ u64(o) }; }


	//	uint128_t operator^(const uint128_t&o) const {
	//		uint128_t r = *this;
	//		r ^= o;
	//		return r;
	//	}
	//	uint128_t& operator^=(const uint128_t& o) 
	//	{
	//		mVals[0] ^= o.mVals[0];
	//		mVals[1] ^= o.mVals[1];
	//		return *this;
	//	}

	//	uint128_t operator&(const uint128_t&o) const {
	//		uint128_t r = *this;
	//		r &= o;
	//		return r;
	//	}
	//	uint128_t& operator&=(const uint128_t&o)
	//	{
	//		mVals[0] &= o.mVals[0];
	//		mVals[1] &= o.mVals[1];
	//		return *this;
	//	}


	//	uint128_t operator+(const uint128_t&o) const
	//	{
	//		uint128_t r = *this;
	//		r += o;
	//		return r;
	//	}
	//	uint128_t& operator+=(const uint128_t&o) 
	//	{
	//		u64 v;
	//		char cout = _addcarry_u64(0, mVals[0], o.mVals[0], &mVals[0]);
	//		_addcarry_u64(cout, mVals[1], o.mVals[1], &mVals[1]);
	//		return *this;
	//	}


	//	uint128_t operator-(const uint128_t&o) const
	//	{
	//		uint128_t r = *this;
	//		r -= o;
	//		return r;
	//	}
	//	uint128_t& operator-=(const uint128_t&o) 
	//	{
	//		auto borrow = _subborrow_u64(0, mVals[0], o.mVals[0], &mVals[0]);
	//		_subborrow_u64(borrow, mVals[1], o.mVals[1], &mVals[1]);
	//		return *this;
	//	}


	//	uint128_t operator>>(u64 s) const
	//	{
	//		auto r = *this;
	//		r >>= s;
	//		return r;
	//	}
	//	uint128_t& operator>>=(u64 s) 
	//	{
	//		assert(s <= 128);
	//		if (s < 64)
	//		{
	//			mVals[0] = (mVals[0] >> s) | (mVals[1] << (64-s));
	//			mVals[1] >>= s;
	//		}
	//		else
	//		{
	//			s = s - 64;
	//			mVals[0] = mVals[1] >> s;
	//			mVals[1] = 0;
	//		}
	//		return *this;
	//	}

	//	uint128_t operator<<(u64 s) const
	//	{
	//		auto r = *this;
	//		r <<= s;
	//		return r;
	//	}
	//	uint128_t& operator<<=(u64 s) 
	//	{
	//		assert(s <= 128);
	//		if (s < 64)
	//		{
	//			mVals[1] = (mVals[1] << s) | (mVals[0] >> (64 - s));
	//			mVals[0] <<= s;
	//		}
	//		else
	//		{
	//			s = s - 64;
	//			mVals[1] = mVals[0] << s;
	//			mVals[0] = 0;
	//		}
	//		return *this;
	//	}

	//	uint128_t operator>>(int s) const { return *this >> u64(s); }
	//	uint128_t& operator>>=(int s) { return *this >>= u64(s); }

	//	uint128_t operator<<(int s) const { return *this << u64(s); }
	//	uint128_t& operator<<=(int s) { return *this >>= u64(s); }

	//	operator u64 () const
	//	{
	//		return mVals[0];
	//	}


	//};



	inline  void printBytes(void* p, int num)
	{
		unsigned char* c = (unsigned char*)p;
		for (int i = 0; i < num; i++)
		{
			printf("%02x", c[i]);
		}
		printf("\n");
	}

	// Samples a uniformly random value between 0 and max via rejection sampling.
	inline uint64_t random_index(uint64_t max, PRNG& prng)
	{
		if (max == 0)
			return 0;

		return prng.get<u64>() % (max + 1);
		//while (1)
		//{

		//	// Use rejection sampling to ensure uniformity
		//	if (rand_value <= (UINT64_MAX - (UINT64_MAX % (max + 1))))
		//		return rand_value % (max + 1);
		//}
	}

	// Samples a random trit (0,1,2) via rejection sampling
	inline  uint8_t rand_trit(PRNG& prng)
	{
		uint8_t t;

		while (1)
		{
			//RAND_bytes(&rand_byte, 1);
			t = prng.get();
			if (t <= 170) // Rejecting values greater than 170
				return t % 3;
		}
	}

	// Reverses the order of elements in an array of uint8_t values
	inline  void reverse_uint8_array(span<uint8_t> trits, size_t size)
	{
		size_t i = 0;
		size_t j = size - 1;

		while (i < j)
		{
			// Swap elements at positions i and j
			uint8_t temp = trits[i];
			trits[i] = trits[j];
			trits[j] = temp;

			// Move towards the center of the array
			i++;
			j--;
		}
	}

	// Converts an array of trits (not packed) into their integer representation.
	inline  size_t trits_to_int(span<uint8_t> trits, size_t size)
	{
		reverse_uint8_array(trits, size);
		size_t result = 0;
		for (size_t i = 0; i < size; i++)
			result = result * 3 + (size_t)trits[i];

		return result;
	}

	// Converts an integer into ternary representation (each trit = 0,1,2)
	inline  void int_to_trits(size_t n, span<uint8_t> trits, size_t size)
	{
		for (size_t i = 0; i < size; i++)
			trits[i] = 0;

		size_t index = 0;
		while (n > 0 && index < size)
		{
			trits[index] = (uint8_t)(n % 3);
			n = n / 3;
			index++;
		}
	}

	// Computes the log of `a` base `base`
	inline  double log_base(double a, double base)
	{
		return std::log2(a) / std::log2(base);
	}

	// Compute base^exp without the floating-point precision
	// errors of the built-in pow function.
	inline size_t ipow(size_t base, size_t exp)
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


}
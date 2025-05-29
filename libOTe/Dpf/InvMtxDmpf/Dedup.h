
#pragma once
#include "cryptoTools/Common/Defines.h"
#include "macoro/task.h"
#include "Equality.h"

namespace osuCrypto
{
	// This class is used to deduplicate the input data for the DMPF protocol.
	//
	// the output will consist of the first occurrence of each key, and the sum of the values for each key.
	// if key k[i] is a duplicate and not the first occurrence, in the output it will be replaced
	// by the alternate key a[i] and the associated value will be zero.
	// 
	// for example, if the input is:
	//	k1, k2, k1, k3, k2
	//  v1, v2, v3, v4, v5
	//  a1, a2, a3, a4, a5
	// 
	// the output will be:
	//  k1,      k2,      a3, k3, a4
	//  v1 + v3, v2 + v5, 0,  v4, 0
	// 
	class Dedup
	{
	public:
		u64 mN = 0; // The number of input elements.
		u64 mKeyBitCount = 0; // The bit count of the keys.
		u64 mValueBitCount = 0; // The bit count of the values.

		// Deduplicate the input data.
		void init(u64 n, u64 keyBitCount, u64 valueBitCount)
		{
			mN = n;
			mKeyBitCount = keyBitCount;
			mValueBitCount = valueBitCount;
		}

		macoro::task<void> dedup(
			Matrix<u8> keys, // The input keys to deduplicate.
			Matrix<u8> values, // The input values to deduplicate.
			Matrix<u8> altKeys // The output indices of the deduplicated keys
		);
		

		
	};
}
#pragma once
#include "cryptoTools/Crypto/AES.h"
#include <array>

#ifdef OC_ENABLE_VAES
namespace osuCrypto::details
{
	// Each YMM lane holds one sender message. Keep both messages in registers
	// through the Davies-Meyer feed-forward and store directly to the output.
	struct OtPairHashVaes
	{
		__m256i key[11];
		__m256i dpair;

		OC_FORCEINLINE OtPairHashVaes(const osuCrypto::AES& aes, block delta)
			: dpair(_mm256_set_m128i(delta.mData, _mm_setzero_si128()))
		{
			for (u64 k = 0; k < 11; ++k)
				key[k] = _mm256_broadcastsi128_si256(aes.mRoundKey[k].mData);
		}

		template<bool clearChoiceBit, bool streaming = false, bool aligned32 = false>
		OC_FORCEINLINE void hashEight(const block* r, std::array<block, 2>* m) const
		{
			const auto mask = _mm256_set_epi64x(-1, -2, -1, -2);
			__m256i x0, x1, x2, x3, x4, x5, x6, x7;
			__m256i a0, a1, a2, a3, a4, a5, a6, a7;
#define OC_HASH_LANES(OP) OP(0); OP(1); OP(2); OP(3); OP(4); OP(5); OP(6); OP(7)
#define OC_HASH_LOAD(j) \
			x##j = _mm256_xor_si256(_mm256_broadcastsi128_si256(_mm_loadu_si128(&r[j].mData)), dpair); \
			if constexpr (clearChoiceBit) x##j = _mm256_and_si256(x##j, mask); \
			a##j = _mm256_xor_si256(x##j, key[0])
#define OC_HASH_ROUND(j) a##j = _mm256_aesenc_epi128(a##j, key[k])
#define OC_HASH_STORE(j) \
			a##j = _mm256_xor_si256(_mm256_aesenclast_epi128(a##j, key[10]), x##j); \
			if constexpr (streaming && aligned32) \
				_mm256_stream_si256(reinterpret_cast<__m256i*>(&m[j]), a##j); \
			else if constexpr (streaming) { \
				_mm_stream_si128(&m[j][0].mData, _mm256_castsi256_si128(a##j)); \
				_mm_stream_si128(&m[j][1].mData, _mm256_extracti128_si256(a##j, 1)); \
			} else \
				_mm256_storeu_si256(reinterpret_cast<__m256i*>(&m[j]), a##j)
			OC_HASH_LANES(OC_HASH_LOAD);
			for (u64 k = 1; k < 10; ++k)
			{
				OC_HASH_LANES(OC_HASH_ROUND);
			}
			OC_HASH_LANES(OC_HASH_STORE);
#undef OC_HASH_STORE
#undef OC_HASH_ROUND
#undef OC_HASH_LOAD
#undef OC_HASH_LANES
		}
	};
}
#endif

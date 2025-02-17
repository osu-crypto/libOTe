#include <stdlib.h>
#include <stdio.h>
#include "libOTe/Tools/Foleage/fft/FoleageFft.h"
#include "libOTe/Tools/Foleage/PerfectShuffle.h"
namespace osuCrypto {

	void fft_recursive_uint64(
		span<uint64_t> coeffs,
		const size_t num_vars,
		const size_t num_coeffs)
	{
		// coeffs (coeffs_h, coeffs_l) are parsed as L(left)|M(middle)|R(right)

		if (num_vars > 1)
		{
			// apply FFT on all left coefficients
			fft_recursive_uint64(
				coeffs,
				num_vars - 1,
				num_coeffs / 3);

			// apply FFT on all middle coefficients
			fft_recursive_uint64(
				coeffs.subspan(num_coeffs),
				num_vars - 1,
				num_coeffs / 3);

			// apply FFT on all right coefficients
			fft_recursive_uint64(
				coeffs.subspan(2 * num_coeffs),
				num_vars - 1,
				num_coeffs / 3);
		}

		// temp variables to store intermediate values
		uint64_t tL, tM;
		uint64_t mult, xor_h, xor_l;

		uint64_t* coeffsL = coeffs.data() + 0;
		uint64_t* coeffsM = coeffs.data() + num_coeffs;
		uint64_t* coeffsR = coeffs.data() + 2 * num_coeffs;

		const uint64_t pattern = 0xaaaaaaaaaaaaaaaa;
		const uint64_t mask_h = pattern;     // 0b101010101010101001010
		const uint64_t mask_l = mask_h >> 1; // 0b010101010101010100101

		for (size_t j = 0; j < num_coeffs; j++)
		{
			xor_h = (coeffsM[j] ^ coeffsR[j]) & mask_h;
			xor_l = (coeffsM[j] ^ coeffsR[j]) & mask_l;

			// pre compute: \alpha * (cM[j] ^ cR[j])
			// computed as: mult_l = (h ^ l) and mult_h = l
			// mult_l = (xor&mask_h>>1) ^ (xor & mask_l) [align h and l then xor]
			// mult_h = (xor&mask_l) shifted left by 1 to put in h place [shift and OR into place]
			mult = (xor_h >> 1) ^ (xor_l) | (xor_l << 1);

			// tL coefficient obtained by evaluating on X_i=1
			tL = coeffsL[j] ^ coeffsM[j] ^ coeffsR[j];

			// tM coefficient obtained by evaluating on X_i=\alpha
			tM = coeffsL[j] ^ coeffsR[j] ^ mult;

			// Explanation:
			// cL + cM*\alpha + cR*\alpha^2
			// = cL + cM*\alpha + cR*\alpha + cR
			// = cL + cR + \alpha*(cM + cR)

			// tR: coefficient obtained by evaluating on X_i=\alpha^2=\alpha + 1
			coeffsR[j] = coeffsL[j] ^ coeffsM[j] ^ mult;

			// Explanation:
			// cL + cM*(\alpha+1) + cR(\alpha+1)^2
			// = cL + cM + cM*\alpha + cR*(3\alpha + 2)
			// = cL + cM + \alpha*(cM + cR)
			// Note: we're in the F_2 field extension so 3\alpha+2 = \alpha+0.

			coeffsL[j] = tL;
			coeffsM[j] = tM;
		}
	}

	void fft_recursive_uint32(
		span<uint32_t> coeffs,
		const size_t num_vars,
		const size_t num_coeffs)
	{
		// coeffs (coeffs_h, coeffs_l) are parsed as L(left)|M(middle)|R(right)

		if (num_vars > 1)
		{
			// apply FFT on all left coefficients
			fft_recursive_uint32(
				coeffs,
				num_vars - 1,
				num_coeffs / 3);

			// apply FFT on all middle coefficients
			fft_recursive_uint32(
				coeffs.subspan(num_coeffs),
				num_vars - 1,
				num_coeffs / 3);

			// apply FFT on all right coefficients
			fft_recursive_uint32(
				coeffs.subspan(2 * num_coeffs),
				num_vars - 1,
				num_coeffs / 3);
		}

		// temp variables to store intermediate values
		uint32_t tL, tM;
		uint32_t mult, xor_h, xor_l;

		uint32_t* coeffsL = coeffs.data() + 0;
		uint32_t* coeffsM = coeffs.data() + num_coeffs;
		uint32_t* coeffsR = coeffs.data() + 2 * num_coeffs;

		const uint32_t pattern = 0xaaaaaaaa;
		const uint32_t mask_h = pattern;     // 0b101010101010101001010
		const uint32_t mask_l = mask_h >> 1; // 0b010101010101010100101

		for (size_t j = 0; j < num_coeffs; j++)
		{
			xor_h = (coeffsM[j] ^ coeffsR[j]) & mask_h;
			xor_l = (coeffsM[j] ^ coeffsR[j]) & mask_l;

			// pre compute: \alpha * (cM[j] ^ cR[j])
			// computed as: mult_l = (h ^ l) and mult_h = l
			// mult_l = (xor&mask_h>>1) ^ (xor & mask_l) [align h and l then xor]
			// mult_h = (xor&mask_l) shifted left by 1 to put in h place [shift and OR into place]
			mult = (xor_h >> 1) ^ (xor_l) | (xor_l << 1);

			// tL coefficient obtained by evaluating on X_i=1
			tL = coeffsL[j] ^ coeffsM[j] ^ coeffsR[j];

			// tM coefficient obtained by evaluating on X_i=\alpha
			tM = coeffsL[j] ^ coeffsR[j] ^ mult;

			// Explanation:
			// cL + cM*\alpha + cR*\alpha^2
			// = cL + cM*\alpha + cR*\alpha + cR
			// = cL + cR + \alpha*(cM + cR)

			// tR: coefficient obtained by evaluating on X_i=\alpha^2=\alpha + 1
			coeffsR[j] = coeffsL[j] ^ coeffsM[j] ^ mult;

			// Explanation:
			// cL + cM*(\alpha+1) + cR(\alpha+1)^2
			// = cL + cM + cM*\alpha + cR*(3\alpha + 2)
			// = cL + cM + \alpha*(cM + cR)
			// Note: we're in the F_2 field extension so 3\alpha+2 = \alpha+0.

			coeffsL[j] = tL;
			coeffsM[j] = tM;
		}
	}

	void fft_recursive_uint16(
		span<uint16_t> coeffs,
		const size_t num_vars,
		const size_t num_coeffs)
	{
		// coeffs (coeffs_h, coeffs_l) are parsed as L(left)|M(middle)|R(right)

		if (num_vars > 1)
		{
			// apply FFT on all left coefficients
			fft_recursive_uint16(
				coeffs,
				num_vars - 1,
				num_coeffs / 3);

			// apply FFT on all middle coefficients
			fft_recursive_uint16(
				coeffs.subspan(num_coeffs),
				num_vars - 1,
				num_coeffs / 3);

			// apply FFT on all right coefficients
			fft_recursive_uint16(
				coeffs.subspan(2 * num_coeffs),
				num_vars - 1,
				num_coeffs / 3);
		}

		// temp variables to store intermediate values
		uint16_t tL, tM;
		uint16_t mult, xor_h, xor_l;

		uint16_t* coeffsL = coeffs.data() + 0;
		uint16_t* coeffsM = coeffs.data() + num_coeffs;
		uint16_t* coeffsR = coeffs.data() + 2 * num_coeffs;

		const uint16_t pattern = 0xaaaa;
		const uint16_t mask_h = pattern;     // 0b101010101010101001010
		const uint16_t mask_l = mask_h >> 1; // 0b010101010101010100101

		for (size_t j = 0; j < num_coeffs; j++)
		{
			xor_h = (coeffsM[j] ^ coeffsR[j]) & mask_h;
			xor_l = (coeffsM[j] ^ coeffsR[j]) & mask_l;

			// pre compute: \alpha * (cM[j] ^ cR[j])
			// computed as: mult_l = (h ^ l) and mult_h = l
			// mult_l = (xor&mask_h>>1) ^ (xor & mask_l) [align h and l then xor]
			// mult_h = (xor&mask_l) shifted left by 1 to put in h place [shift and OR into place]
			mult = (xor_h >> 1) ^ (xor_l) | (xor_l << 1);

			// tL coefficient obtained by evaluating on X_i=1
			tL = coeffsL[j] ^ coeffsM[j] ^ coeffsR[j];

			// tM coefficient obtained by evaluating on X_i=\alpha
			tM = coeffsL[j] ^ coeffsR[j] ^ mult;

			// Explanation:
			// cL + cM*\alpha + cR*\alpha^2
			// = cL + cM*\alpha + cR*\alpha + cR
			// = cL + cR + \alpha*(cM + cR)

			// tR: coefficient obtained by evaluating on X_i=\alpha^2=\alpha + 1
			coeffsR[j] = coeffsL[j] ^ coeffsM[j] ^ mult;

			// Explanation:
			// cL + cM*(\alpha+1) + cR(\alpha+1)^2
			// = cL + cM + cM*\alpha + cR*(3\alpha + 2)
			// = cL + cM + \alpha*(cM + cR)
			// Note: we're in the F_2 field extension so 3\alpha+2 = \alpha+0.

			coeffsL[j] = tL;
			coeffsM[j] = tM;
		}
	}

	void foliageFftUint8(
		span<uint8_t> coeffs,
		const size_t num_vars,
		const size_t num_coeffs)
	{
		// coeffs (coeffs_h, coeffs_l) are parsed as L(left)|M(middle)|R(right)

		if (num_vars > 1)
		{
			// apply FFT on all left coefficients
			foliageFftUint8(
				coeffs,
				num_vars - 1,
				num_coeffs / 3);

			// apply FFT on all middle coefficients
			foliageFftUint8(
				coeffs.subspan(num_coeffs),
				num_vars - 1,
				num_coeffs / 3);

			// apply FFT on all right coefficients
			foliageFftUint8(
				coeffs.subspan(2 * num_coeffs),
				num_vars - 1,
				num_coeffs / 3);
		}

		// temp variables to store intermediate values
		uint8_t tL, tM;
		uint8_t mult, xor_h, xor_l;

		uint8_t* coeffsL = coeffs.data() + 0;
		uint8_t* coeffsM = coeffs.data() + num_coeffs;
		uint8_t* coeffsR = coeffs.data() + 2 * num_coeffs;

		const uint8_t pattern = 0xaa;
		const uint8_t mask_h = pattern;     // 0b101010101010101001010
		const uint8_t mask_l = mask_h >> 1; // 0b010101010101010100101

		for (size_t j = 0; j < num_coeffs; j++)
		{
			xor_h = (coeffsM[j] ^ coeffsR[j]) & mask_h;
			xor_l = (coeffsM[j] ^ coeffsR[j]) & mask_l;

			// pre compute: \alpha * (cM[j] ^ cR[j])
			// computed as: mult_l = (h ^ l) and mult_h = l
			// mult_l = (xor&mask_h>>1) ^ (xor & mask_l) [align h and l then xor]
			// mult_h = (xor&mask_l) shifted left by 1 to put in h place [shift and OR into place]
			mult = (xor_h >> 1) ^ (xor_l) | (xor_l << 1);

			// tL coefficient obtained by evaluating on X_i=1
			tL = coeffsL[j] ^ coeffsM[j] ^ coeffsR[j];

			// tM coefficient obtained by evaluating on X_i=\alpha
			tM = coeffsL[j] ^ coeffsR[j] ^ mult;

			// Explanation:
			// cL + cM*\alpha + cR*\alpha^2
			// = cL + cM*\alpha + cR*\alpha + cR
			// = cL + cR + \alpha*(cM + cR)

			// tR: coefficient obtained by evaluating on X_i=\alpha^2=\alpha + 1
			coeffsR[j] = coeffsL[j] ^ coeffsM[j] ^ mult;

			// Explanation:
			// cL + cM*(\alpha+1) + cR(\alpha+1)^2
			// = cL + cM + cM*\alpha + cR*(3\alpha + 2)
			// = cL + cM + \alpha*(cM + cR)
			// Note: we're in the F_2 field extension so 3\alpha+2 = \alpha+0.

			coeffsL[j] = tL;
			coeffsM[j] = tM;
		}
	}


	void foleageFFT2(
		uint8_t* lsb,
		uint8_t* msb,
		const size_t num_vars,
		const size_t num_coeffs)
	{
		if (num_vars > 1)
		{
			// apply FFT on all left coefficients
			foleageFFT2(
				lsb, msb,
				num_vars - 1,
				num_coeffs / 3);

			// apply FFT on all middle coefficients
			foleageFFT2(
				lsb + num_coeffs,
				msb + num_coeffs,
				num_vars - 1,
				num_coeffs / 3);

			// apply FFT on all right coefficients
			foleageFFT2(
				lsb + 2 * num_coeffs,
				msb + 2 * num_coeffs,
				num_vars - 1,
				num_coeffs / 3);
		}

		uint8_t* __restrict ptrL0 = lsb + 0;
		uint8_t* __restrict ptrL1 = msb + 0;
		uint8_t* __restrict ptrM0 = lsb + num_coeffs;
		uint8_t* __restrict ptrM1 = msb + num_coeffs;
		uint8_t* __restrict ptrR0 = lsb + 2 * num_coeffs;
		uint8_t* __restrict ptrR1 = msb + 2 * num_coeffs;

		for (size_t j = 0; j < num_coeffs; j++)
		{

			auto coeffsL0 = *ptrL0;
			auto coeffsL1 = *ptrL1;
			auto coeffsM0 = *ptrM0;
			auto coeffsM1 = *ptrM1;
			auto coeffsR0 = *ptrR0;
			auto coeffsR1 = *ptrR1;

			auto xor_h = coeffsM1 ^ coeffsR1;
			auto xor_l = coeffsM0 ^ coeffsR0;

			// pre compute: \alpha * (cM[j] ^ cR[j])
			// computed as: mult_l = (h ^ l) and mult_h = l
			// mult_l = (xor&mask_h>>1) ^ (xor & mask_l) [align h and l then xor]
			// mult_h = (xor&mask_l) shifted left by 1 to put in h place [shift and OR into place]
			auto mult0 = xor_h ^ xor_l;
			auto mult1 = xor_l;

			// tL coefficient obtained by evaluating on X_i=1
			auto tL0 = coeffsL0 ^ coeffsM0 ^ coeffsR0;
			auto tL1 = coeffsL1 ^ coeffsM1 ^ coeffsR1;

			// tM coefficient obtained by evaluating on X_i=\alpha
			auto tM0 = coeffsL0 ^ coeffsR0 ^ mult0;
			auto tM1 = coeffsL1 ^ coeffsR1 ^ mult1;

			// Explanation:
			// cL + cM*\alpha + cR*\alpha^2
			// = cL + cM*\alpha + cR*\alpha + cR
			// = cL + cR + \alpha*(cM + cR)

			// tR: coefficient obtained by evaluating on X_i=\alpha^2=\alpha + 1
			*ptrR0 = coeffsL0 ^ coeffsM0 ^ mult0;
			*ptrR1 = coeffsL1 ^ coeffsM1 ^ mult1;

			// Explanation:
			// cL + cM*(\alpha+1) + cR(\alpha+1)^2
			// = cL + cM + cM*\alpha + cR*(3\alpha + 2)
			// = cL + cM + \alpha*(cM + cR)
			// Note: we're in the F_2 field extension so 3\alpha+2 = \alpha+0.

			*ptrL0 = tL0;
			*ptrL1 = tL1;
			*ptrM0 = tM0;
			*ptrM1 = tM1;

			++ptrL0;
			++ptrL1;
			++ptrM0;
			++ptrM1;
			++ptrR0;
			++ptrR1;
		}
	}

	template<typename BlockSize>
	void foleageFFTLevel(
		u8* lsb,
		u8* msb,
		BlockSize blockSize,
		u64 regions
	)
	{
		//static_assert(depth);
		//u64 blockSize = ipow(3, depth - 1);

		for (u64 r = 0; r < regions; ++r)
		{

			uint8_t* __restrict ptrL0 = lsb + r * 3 * blockSize + 0;
			uint8_t* __restrict ptrL1 = msb + r * 3 * blockSize + 0;
			uint8_t* __restrict ptrM0 = lsb + r * 3 * blockSize + blockSize;
			uint8_t* __restrict ptrM1 = msb + r * 3 * blockSize + blockSize;
			uint8_t* __restrict ptrR0 = lsb + r * 3 * blockSize + 2 * blockSize;
			uint8_t* __restrict ptrR1 = msb + r * 3 * blockSize + 2 * blockSize;

			constexpr u64 width = 1;
			auto main = blockSize / (width * 16);
			for (u64 k = 0; k < main; ++k)
			{

				block coeffsL0[width];
				block coeffsL1[width];
				block coeffsM0[width];
				block coeffsM1[width];
				block coeffsR0[width];
				block coeffsR1[width];

				//{ constexpr u64 VAR = 1; STATEMENT; }\
				//{ constexpr u64 VAR = 2; STATEMENT; }\
				//{ constexpr u64 VAR = 3; STATEMENT; }\
				//{ constexpr u64 VAR = 4; STATEMENT; }\
				//{ constexpr u64 VAR = 5; STATEMENT; }\
				//{ constexpr u64 VAR = 6; STATEMENT; }\
				//{ constexpr u64 VAR = 7; STATEMENT; }\

#define SIMD8(VAR, STATEMENT) \
	{ constexpr u64 VAR = 0; STATEMENT; }\
	do{}while(0)


				SIMD8(q, coeffsL0[q] = _mm_loadu_epi8(ptrL0 + q * 16));
				SIMD8(q, coeffsL1[q] = _mm_loadu_epi8(ptrL1 + q * 16));
				SIMD8(q, coeffsM0[q] = _mm_loadu_epi8(ptrM0 + q * 16));
				SIMD8(q, coeffsM1[q] = _mm_loadu_epi8(ptrM1 + q * 16));
				SIMD8(q, coeffsR0[q] = _mm_loadu_epi8(ptrR0 + q * 16));
				SIMD8(q, coeffsR1[q] = _mm_loadu_epi8(ptrR1 + q * 16));



				block xor_h[width], xor_l[width];
				SIMD8(j, xor_h[j] = coeffsM1[j] ^ coeffsR1[j]);
				SIMD8(j, xor_l[j] = coeffsM0[j] ^ coeffsR0[j]);

				// pre compute: \alpha * (cM[j] ^ cR[j])
				// computed as: mult_l = (h ^ l) and mult_h = l
				// mult_l = (xor&mask_h>>1) ^ (xor & mask_l) [align h and l then xor]
				// mult_h = (xor&mask_l) shifted left by 1 to put in h place [shift and OR into place]
				block mult0[width];// , mult1[width];
				SIMD8(j, mult0[j] = xor_h[j] ^ xor_l[j]);
				//SIMD8(j, mult1[j] = xor_l[j]);

				// tL coefficient obtained by evaluating on X_i=1
				block tL0[width], tL1[width];
				SIMD8(j, tL0[j] = coeffsL0[j] ^ coeffsM0[j] ^ coeffsR0[j]);
				SIMD8(j, tL1[j] = coeffsL1[j] ^ coeffsM1[j] ^ coeffsR1[j]);

				// tM coefficient obtained by evaluating on X_i=\alpha
				block tM0[width], tM1[width];
				SIMD8(j, tM0[j] = coeffsL0[j] ^ coeffsR0[j] ^ mult0[j]);
				SIMD8(j, tM1[j] = coeffsL1[j] ^ coeffsR1[j] ^ xor_l[j]);

				// Explanation:
				// cL + cM*\alpha + cR*\alpha^2
				// = cL + cM*\alpha + cR*\alpha + cR
				// = cL + cR + \alpha*(cM + cR)

				// tR: coefficient obtained by evaluating on X_i=\alpha^2=\alpha + 1
				SIMD8(j, coeffsR0[j] = coeffsL0[j] ^ coeffsM0[j] ^ mult0[j]);
				SIMD8(j, coeffsR1[j] = coeffsL1[j] ^ coeffsM1[j] ^ xor_l[j]);

				SIMD8(j, _mm_storeu_epi8(ptrR0 + j * 16, coeffsR0[j]));
				SIMD8(j, _mm_storeu_epi8(ptrR1 + j * 16, coeffsR1[j]));
				// Explanation:
				// cL + cM*(\alpha+1) + cR(\alpha+1)^2
				// = cL + cM + cM*\alpha + cR*(3\alpha + 2)
				// = cL + cM + \alpha*(cM + cR)
				// Note: we're in the F_2 field extension so 3\alpha+2 = \alpha+0.

				SIMD8(j, _mm_storeu_epi8(ptrL0 + j * 16, tL0[j]));
				SIMD8(j, _mm_storeu_epi8(ptrL1 + j * 16, tL1[j]));

				SIMD8(j, _mm_storeu_epi8(ptrM0 + j * 16, tM0[j]));
				SIMD8(j, _mm_storeu_epi8(ptrM1 + j * 16, tM1[j]));


				ptrL0 += width * 16;
				ptrL1 += width * 16;
				ptrM0 += width * 16;
				ptrM1 += width * 16;
				ptrR0 += width * 16;
				ptrR1 += width * 16;
			}

#undef SIMD8

			for (size_t j = main * width * 16; j < blockSize; j++)
			{

				auto coeffsL0 = *ptrL0;
				auto coeffsL1 = *ptrL1;
				auto coeffsM0 = *ptrM0;
				auto coeffsM1 = *ptrM1;
				auto coeffsR0 = *ptrR0;
				auto coeffsR1 = *ptrR1;

				auto xor_h = coeffsM1 ^ coeffsR1;
				auto xor_l = coeffsM0 ^ coeffsR0;

				// pre compute: \alpha * (cM[j] ^ cR[j])
				// computed as: mult_l = (h ^ l) and mult_h = l
				// mult_l = (xor&mask_h>>1) ^ (xor & mask_l) [align h and l then xor]
				// mult_h = (xor&mask_l) shifted left by 1 to put in h place [shift and OR into place]
				auto mult0 = xor_h ^ xor_l;
				auto mult1 = xor_l;

				// tL coefficient obtained by evaluating on X_i=1
				auto tL0 = coeffsL0 ^ coeffsM0 ^ coeffsR0;
				auto tL1 = coeffsL1 ^ coeffsM1 ^ coeffsR1;

				// tM coefficient obtained by evaluating on X_i=\alpha
				auto tM0 = coeffsL0 ^ coeffsR0 ^ mult0;
				auto tM1 = coeffsL1 ^ coeffsR1 ^ mult1;

				// Explanation:
				// cL + cM*\alpha + cR*\alpha^2
				// = cL + cM*\alpha + cR*\alpha + cR
				// = cL + cR + \alpha*(cM + cR)

				// tR: coefficient obtained by evaluating on X_i=\alpha^2=\alpha + 1
				*ptrR0 = coeffsL0 ^ coeffsM0 ^ mult0;
				*ptrR1 = coeffsL1 ^ coeffsM1 ^ mult1;

				// Explanation:
				// cL + cM*(\alpha+1) + cR(\alpha+1)^2
				// = cL + cM + cM*\alpha + cR*(3\alpha + 2)
				// = cL + cM + \alpha*(cM + cR)
				// Note: we're in the F_2 field extension so 3\alpha+2 = \alpha+0.

				*ptrL0 = tL0;
				*ptrL1 = tL1;
				*ptrM0 = tM0;
				*ptrM1 = tM1;

				++ptrL0;
				++ptrL1;
				++ptrM0;
				++ptrM1;
				++ptrR0;
				++ptrR1;
			}
		}
	}

	template<u8 stride>
	void foleageFFTL1L2(
		u8* lsb,
		u8* msb,
		u64 regions
	)
	{
		//static_assert(depth);
		//u64 blockSize = ipow(3, depth - 1);
		u64 r = 0;
		if constexpr (0 && stride == 2)
		{
			constexpr auto stepSize = 24;
			auto main = regions / stepSize;
			block tempLsb[9];
			block tempMsb[9];

			for (u64 i = 0; i < main; ++i, r += stepSize)
			{
				auto lsb0 = lsb + r * stride;
				auto lsb1 = lsb + r * stride + 16;
				auto lsb2 = lsb + r * stride + 32;

				auto msb0 = msb + r * stride;
				auto msb1 = msb + r * stride + 16;
				auto msb2 = msb + r * stride + 32;

				//  0  1  2  3  4  5  6  7
				//  8  9 10 11 12 13 14 15
				// 16 17 18 19 20 21 22 23
				foleageTransposeLeaf<stepSize>(lsb0, (__m128i*) & tempLsb[0]);
				foleageTransposeLeaf<stepSize>(lsb1, (__m128i*) & tempLsb[1]);
				foleageTransposeLeaf<stepSize>(lsb2, (__m128i*) & tempLsb[2]);

				foleageTransposeLeaf<stepSize>(msb0, (__m128i*) & tempMsb[0]);
				foleageTransposeLeaf<stepSize>(msb1, (__m128i*) & tempMsb[1]);
				foleageTransposeLeaf<stepSize>(msb2, (__m128i*) & tempMsb[2]);


				foleageFFTOne<1>(
					&tempLsb[0], &tempMsb[0],
					&tempLsb[1], &tempMsb[1],
					&tempLsb[2], &tempMsb[2]
				);

				foleageFFTOne<1>(
					&tempLsb[3], &tempMsb[3],
					&tempLsb[4], &tempMsb[4],
					&tempLsb[5], &tempMsb[5]
				);

				foleageFFTOne<1>(
					&tempLsb[6], &tempMsb[6],
					&tempLsb[7], &tempMsb[7],
					&tempLsb[8], &tempMsb[8]
				);

				foleageTranspose<stride>((u8*)&tempLsb[0], (__m128i*)lsb0);

				foleageTranspose<stride>((u8*)&tempMsb[0], (__m128i*)msb0);

				foleageFFTOne<3>(
					(block*)lsb0, (block*)msb0,
					(block*)lsb1, (block*)msb1,
					(block*)lsb2, (block*)msb2
				);
			}
		}

		for (; r < regions; ++r)
		{
			constexpr u8 blockSize = 3 * stride;
			uint8_t* __restrict ptrL0 = lsb + r * 3 * blockSize + 0;
			uint8_t* __restrict ptrL1 = msb + r * 3 * blockSize + 0;
			uint8_t* __restrict ptrM0 = lsb + r * 3 * blockSize + blockSize;
			uint8_t* __restrict ptrM1 = msb + r * 3 * blockSize + blockSize;
			uint8_t* __restrict ptrR0 = lsb + r * 3 * blockSize + 2 * blockSize;
			uint8_t* __restrict ptrR1 = msb + r * 3 * blockSize + 2 * blockSize;


			for (u64 j = 0; j < 9; j += 3)
			{

				foleageFFTOne<stride>(
					ptrL0 + (j + 0) * stride, ptrL1 + (j + 0) * stride,
					ptrL0 + (j + 1) * stride, ptrL1 + (j + 1) * stride,
					ptrL0 + (j + 2) * stride, ptrL1 + (j + 2) * stride
				);
			}

			//foleageFFTOne<stride>(
			//	ptrL0 + 0 * stride, ptrL1 + 0 * stride,
			//	ptrL0 + 1 * stride, ptrL1 + 1 * stride,
			//	ptrL0 + 2 * stride, ptrL1 + 2 * stride
			//);
			//foleageFFTOne<stride>(
			//	ptrM0 + 0 * stride, ptrM1 + 0 * stride,
			//	ptrM0 + 1 * stride, ptrM1 + 1 * stride,
			//	ptrM0 + 2 * stride, ptrM1 + 2 * stride
			//);

			//foleageFFTOne<stride>(
			//	ptrR0 + 0 * stride, ptrR1 + 0 * stride,
			//	ptrR0 + 1 * stride, ptrR1 + 1 * stride,
			//	ptrR0 + 2 * stride, ptrR1 + 2 * stride
			//);


				foleageFFTOne<stride * 3>(
					ptrL0, ptrL1,
					ptrM0, ptrM1,
					ptrR0, ptrR1
				);
			//foleageFFTOne<stride>(
			//	ptrL0 + 1 * stride, ptrL1 + 1 * stride,
			//	ptrM0 + 1 * stride, ptrM1 + 1 * stride,
			//	ptrR0 + 1 * stride, ptrR1 + 1 * stride
			//);
			//foleageFFTOne<stride>(
			//	ptrL0 + 2 * stride, ptrL1 + 2 * stride,
			//	ptrM0 + 2 * stride, ptrM1 + 2 * stride,
			//	ptrR0 + 2 * stride, ptrR1 + 2 * stride
			//);
		}
	}

	template<u8 stride>
	void foleageFFTL1L2L3(
		u8* lsb,
		u8* msb,
		u64 regions
	)
	{

		for (u64 r = 0; r < regions; ++r)
		{
			constexpr u8 L4blockSize = 27 * stride;

			// L3 has 3 blocks of size L3blockSize
			constexpr u8 L3blockSize = 9 * stride;
			constexpr u8 L2blockSize = 3 * stride;
			constexpr u8 L1blockSize = 1 * stride;

			uint8_t* baseLsb = lsb + r * L4blockSize;
			uint8_t* baseMsb = msb + r * L4blockSize;


			for (u64 k = 0; k < 3; ++k)
			{
				// left 1/3
				uint8_t* __restrict ptrL0 = baseLsb + k * L3blockSize + 0 * L2blockSize;
				uint8_t* __restrict ptrL1 = baseMsb + k * L3blockSize + 0 * L2blockSize;
				// middle 1/3
				uint8_t* __restrict ptrM0 = baseLsb + k * L3blockSize + 1 * L2blockSize;
				uint8_t* __restrict ptrM1 = baseMsb + k * L3blockSize + 1 * L2blockSize;
				// right 1/3
				uint8_t* __restrict ptrR0 = baseLsb + k * L3blockSize + 2 * L2blockSize;
				uint8_t* __restrict ptrR1 = baseMsb + k * L3blockSize + 2 * L2blockSize;


				for (u64 j = 0; j < 9; j += 3)
				{
					foleageFFTOne<stride>(
						ptrL0 + (j + 0) * stride, ptrL1 + (j + 0) * stride,
						ptrL0 + (j + 1) * stride, ptrL1 + (j + 1) * stride,
						ptrL0 + (j + 2) * stride, ptrL1 + (j + 2) * stride
					);
				}

				foleageFFTOne<stride * 3>(
					ptrL0, ptrL1,
					ptrM0, ptrM1,
					ptrR0, ptrR1
				);
			}


			foleageFFTOne<stride * 9>(
				baseLsb + 0 * L3blockSize, baseMsb +  0 * L3blockSize,
				baseLsb + 1 * L3blockSize, baseMsb +  1 * L3blockSize,
				baseLsb + 2 * L3blockSize, baseMsb +  2 * L3blockSize
			);

		}
	}

	void foleageFFT(
		uint8_t* lsb,
		uint8_t* msb,
		const size_t num_vars,
		const size_t num_coeffs)
	{
		//assert(lsb.size() == msb.size());
		//assert(lsb.size() % stride == 0);
		//assert(blockSize  == 1 || blockSize % 3 == 0);
		//assert(blockSize < lsb.size() / stride);

		// coeffs (coeffs_h, coeffs_l) are parsed as L(left)|M(middle)|R(right)
		//u64 stepSize = blockSize * stride;


		if (num_vars > 1)
		{
			// apply FFT on all left coefficients
			foleageFFT(
				lsb, msb,
				num_vars - 1,
				num_coeffs / 3);

			// apply FFT on all middle coefficients
			foleageFFT(
				lsb + num_coeffs,
				msb + num_coeffs,
				num_vars - 1,
				num_coeffs / 3);

			// apply FFT on all right coefficients
			foleageFFT(
				lsb + 2 * num_coeffs,
				msb + 2 * num_coeffs,
				num_vars - 1,
				num_coeffs / 3);
		}


		foleageFFTLevel(lsb, msb, num_coeffs, 1);
	}

	template<u64 stride>
	void foleageFFT2(
		span<uint8_t> lsb,
		span<uint8_t> msb)
	{
		auto n = lsb.size() / stride;

		auto log3N = log3ceil(n);
		if (n != ipow(3, log3N))
			throw RTE_LOC;
		if (lsb.size() != n * stride)
			throw RTE_LOC;
		if (lsb.size() != msb.size())
			throw RTE_LOC;
		for (u64 i = 1; i <= log3N; ++i)
		{
			auto regionSize = ipow(3, i);
			auto regions = n / regionSize;

				switch (i)
				{
					case 1:
					if(log3N == 1)
						foleageFFTLevel(lsb.data(), msb.data(), std::integral_constant<u8, 1 * stride>{}, regions);
					break;
				case 2:
					//	foleageFFTLevel(lsb.data(), msb.data(), std::integral_constant<u8, 3 * stride>{}, regions);
					//if (log3N == 2)
					foleageFFTL1L2<stride>(lsb.data(), msb.data(), regions);
					break;
				case 3:
					foleageFFTLevel(lsb.data(), msb.data(), std::integral_constant<u8, 9 * stride>{}, regions);
					//foleageFFTL1L2L3<stride>(lsb.data(), msb.data(), regions);
					break;
				case 4:
					foleageFFTLevel(lsb.data(), msb.data(), std::integral_constant<u8, 27 * stride>{}, regions);
					break;
				default:
					u64 blockSize = regionSize / 3 * stride;
					foleageFFTLevel(lsb.data(), msb.data(), blockSize, regions);
					break;
				}
		}
		 
	}

	template
		void foleageFFT2<2>(
			span<uint8_t> lsb,
			span<uint8_t> msb);
	template
		void foleageFFT2<1>(
			span<uint8_t> lsb,
			span<uint8_t> msb);
}
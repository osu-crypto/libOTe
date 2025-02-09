#pragma once

#include <string.h>
#include <stdint.h>
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/MatrixView.h"
#include "libOTe/Tools/Foleage/FoleageUtils.h"

//#include "libOTe/Tools/Foleage/utils.h"
namespace osuCrypto {

	//typedef __int128 int128_t;
	//typedef unsigned __int128 uint128_t;

	// FFT for (up to) 32 polynomials over F4
	void fft_recursive_uint64(
		span<uint64_t> coeffs,
		const size_t num_vars,
		const size_t num_coeffs);

	// FFT for (up to) 16 polynomials over F4
	void fft_recursive_uint32(
		span<uint32_t> coeffs,
		const size_t num_vars,
		const size_t num_coeffs);

	// FFT for (up to) 8 polynomials over F4
	void fft_recursive_uint16(
		span<uint16_t> coeffs,
		const size_t num_vars,
		const size_t num_coeffs);

	// FFT for (up to) 4 polynomials over F4
	void fft_recursive_uint8(
		span<uint8_t> coeffs,
		const size_t num_vars,
		const size_t num_coeffs);



	void foleageFFT(
		uint8_t* lsb,
		uint8_t* msb,
		const size_t num_vars,
		const size_t num_coeffs);

	inline void printShuffle1(const u16* ptr)
	{

		for (u64 j = 0; j < 8; ++j)
		{
			auto v = ptr[j];
			std::cout << std::setw(2) << std::setfill(' ') << v << " ";
		}
	}
	inline void printShuffle3(const u16* ptr)
	{
		for (u64 i = 0; i < 3; ++i)
		{
			printShuffle1(ptr + i * 8);
			std::cout << std::endl;
		}
	}

	inline void printShuffle9(const u16* ptr)
	{
		for (u64 i = 0; i < 3; ++i)
		{
			printShuffle1(ptr + i * 24);
			printShuffle1(ptr + i * 24 + 8);
			printShuffle1(ptr + i * 24 + 16);
			std::cout << std::endl;
		}
	}
	// shuffles 3 blocks or 48 bytes
	template<u64 stride>
	void foleageTransposeLeaf(u8* src, __m128i* dst)
	{

		if constexpr (stride == 2)
		{
			// input:
			//  0  1  2  3  4  5  6  7
			//  8  9 10 11 12 13 14 15
			// 16 17 18 19 20 21 22 23
			//
			// output:
			//  0  3  6  9 12 15 18 21
			//  1  4  7 10 13 16 19 22
			//  2  5  8 11 14 17 20 23

			if (1)
			{
				//  0     6    12    18
				auto a0 = _mm_i32gather_epi32((int*)src, _mm_set_epi32(18, 12, 6, 0), 2);
				//     3     9    15    21
				auto a1 = _mm_i32gather_epi32((int*)src, _mm_set_epi32(20, 14, 8, 2), 2);
				//  0  3  6  9 12 15 18 21
				dst[0] = _mm_blendv_epi8(a0, a1, _mm_set_epi16(-1, 0, -1, 0, -1, 0, -1, 0));

				// 1     7    13    19
				auto b0 = _mm_i32gather_epi32((int*)src, _mm_set_epi32(19, 13, 7, 1), 2);
				//    4    10    16    22
				auto b1 = _mm_i32gather_epi32((int*)src, _mm_set_epi32(21, 15, 9, 3), 2);
				//  1  4  7 10 13 16 19 22
				dst[1] = _mm_blendv_epi8(b0, b1, _mm_set_epi16(-1, 0, -1, 0, -1, 0, -1, 0));

				// 2     8    14    20
				auto c0 = _mm_i32gather_epi32((int*)src, _mm_set_epi32(20, 14, 8, 2), 2);
				//    5    11    17    23
				auto c1 = _mm_i32gather_epi32((int*)src, _mm_set_epi32(22, 16, 10, 4), 2);
				//  2  5  8 11 14 17 20 23
				dst[2] = _mm_blendv_epi8(c0, c1, _mm_set_epi16(-1, 0, -1, 0, -1, 0, -1, 0));

			}
			else
			{


				//  0  1  2  3  4  5  6  7
				auto v0 = _mm_loadu_si128((__m128i*)src);

				//  8  9 10 11 12 13 14 15
				auto v1 = _mm_loadu_si128((__m128i*)(src + 16));

				// 16 17 18 19 20 21 22 23
				auto v2 = _mm_loadu_si128((__m128i*)(src + 32));

				// 0    3  6      1      4    7      2     5
				// 0 0c 0d 0e 0f, 1a 1b 1c 1d 1e 1f, 2a 2b 2c 2d
				v0 = _mm_shuffle_epi8(v0, _mm_set_epi8(11, 10, 5, 4, 15, 14, 9, 8, 3, 2, 13, 12, 7, 6, 1, 0));

				// 8    11 14      9      12   15     10    13
				// 2e ef 2g 2h 2i ej, 0g 0h 0i 0j 0k 0l, 1g 1h 1i 1j
				v1 = _mm_shuffle_epi8(v1, _mm_set_epi8(11, 10, 5, 4, 15, 14, 9, 8, 3, 2, 13, 12, 7, 6, 1, 0));

				// 16   19 22      17     20   23     18    21
				// 1k 1l 1m 1n 1o 1p, 2k 2l 2m 2n 2o 2p, 0m 0n 0o 0p
				v2 = _mm_shuffle_epi8(v2, _mm_set_epi8(11, 10, 5, 4, 15, 14, 9, 8, 3, 2, 13, 12, 7, 6, 1, 0));

				// 0  3  6 9 12 15 18 21
				// 0 0c 0d 0e 0f, 0g 0h 0i 0j 0k 0l, 1g 1h 1i 1j
				auto u0 = _mm_blendv_epi8(v0, v1, _mm_set_epi16(-1, -1, -1, -1, -1, 0, 0, 0));

				// 0  3  6 17     20   23     18    21
				// 0 0c 0d 0e 0f, 0g 0h 0i 0j 0k 0l, 0m 0n 0o 0p
				u0 = _mm_blendv_epi8(u0, v2, _mm_set_epi16(-1, -1, 0, 0, 0, 0, 0, 0));

				// 16   19 22    1      4    7      2     5
				// 1k 1l 1m 1n 1o 1p, 1a 1b 1c 1d 1e 1f, 2a 2b 2c 2d
				auto u1 = _mm_blendv_epi8(v2, v0, _mm_set_epi16(-1, -1, -1, -1, -1, 0, 0, 0));

				// 16   19 22    1      4    7       10    13
				// 1k 1l 1m 1n 1o 1p, 1a 1b 1c 1d 1e 1f, 1g 1h 1i 1j
				u1 = _mm_blendv_epi8(u1, v1, _mm_set_epi16(-1, -1, 0, 0, 0, 0, 0, 0));

				//  1  4  7 10 13 16 19 22
				// 1a 1b 1c 1d 1e 1f 1g 1h 1i 1j 1k 1l 1m 1n 1o 1p
				u1 = _mm_shuffle_epi8(u1, _mm_set_epi8(5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6));


				//  8    11 14  17     20   23     18    21
				// 2e ef 2g 2h 2i ej, 2k 2l 2m 2n 2o 2p, 0m 0n 0o 0p
				auto u2 = _mm_blendv_epi8(v1, v2, _mm_set_epi16(-1, -1, -1, -1, -1, 0, 0, 0));

				//  8    11 14  17     20   23      2     5
				// 2e ef 2g 2h 2i ej, 2k 2l 2m 2n 2o 2p, 2a 2b 2c 2d
				u2 = _mm_blendv_epi8(u2, v0, _mm_set_epi16(-1, -1, 0, 0, 0, 0, 0, 0));

				//  2  5  8 11 14 17 20 23
				// 2a 2b 2c 2d 2e ef 2g 2h 2i ej 2k 2l 2m 2n 2o 2p, 
				u2 = _mm_shuffle_epi8(u2, _mm_set_epi8(11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12));


				_mm_store_si128(dst, u0);
				_mm_store_si128(dst + 1, u1);
				_mm_store_si128(dst + 2, u2);
			}
		}
		else
		{
			throw RTE_LOC;
		}
	}

	// src points at the input data. Logically, there are 3 rows and 24 columns.
	// each element is of stride bytes. The output is 3 rows and 8 columns. Each
	// element is of stride * 3 bytes. The i'th element in the output are the 
	// three elements in the i'th column of the input.
	//
	// the input has 8 columns of row 0, then 8 columns row 1, 8 columns row 2, then repeates.
	template<u64 stride>
	void foleageTranspose(u8* __restrict src, __m128i* __restrict dst)
	{
		if constexpr (stride == 2)
		{
			// input data:
			//  0  1  2  3  4  5  6  7
			//  8  9 10 11 12 13 14 15
			// 16 17 18 19 20 21 22 23
			//
			// 24 25 26 27 28 29 30 31
			// 32 33 34 35 36 37 38 39
			// 40 41 42 43 44 45 46 47
			//
			// 48 49 50 51 52 53 54 55
			// 56 57 58 59 60 61 62 63
			// 64 65 66 67 68 69 70 71
			// 

			// the input comes in 16 byte chunks. chunks {0,3,6},{1,4,7},{2,5,8} each belong to the same FFT position {0,1,2}. If we lay out the data
			// logically we get:
			//         |        |        |        |        |        |        |
			//  0  1  2  3  4  5  6  7 24 25 26 27 28 29 30 31 48 49 50 51 52 53 54 55
			//  8  9 10 11 12 13 14 15 32 33 34 35 36 37 38 39 56 57 58 59 60 61 62 63
			// 16 17 18 19 20 21 22 23 40 41 42 43 44 45 46 47 64 65 66 67 68 69 70 71
			//         |        |        |        |        |        |        |
			// 
			// at the previous FFT level, each column corresponds to a FFT instance, e.g. sub blocks {0,8,16}, {1,9,17}, ...
			// 
			// We now want to merge these sub blocks into a single block. This corresponds 
			// to doing a 3x3 sub block transpose.
			//  
			//  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 
			//         |        |        |        |        |        |        |
			//  0  8 16  3 11 19  6 14 22 25 33 41 28 36 44 31 39 47 50 58 66 53 61 69
			//  1  9 17  4 12 20  7 15 23 26 34 42 29 37 45 48 56 64 51 59 67 54 62 70
			//  2 10 18  5 13 21 24 32 40 27 35 43 30 38 46 49 57 65 52 60 68 55 63 71
			//         |        |        |        |        |        |        |
			// 
			// We are going to transpose using the i32gather instruction. We want the output to be stored with
			// each row being contiguous, e.g. "0  8 ... 69" should all be next to eachother.
			// Each position takes up stride=2 bytes. But the i32gather instruction works on 4 byte chunks.
			// So we will split the 8 gathered values across two instructions. One to gather the even 
			// positions and one the odd. We will then blend these two together to get the final output. eg:

			//0  8 16  3 11 19  6 14 | 22 25 33 41 28 36 44 31 |39 47 50 58 66 53 61 69
			//0    16    11     6    | 22    33    28    44    |39    50    66    61  
			//   8     3    19    14 |    25    41    36    31 |   47    58    53    69
			// 
			// For row 0 we want to select					   
			//  * blend(gather(0,16,11,6),gatherHigh(8,3,19,14))
			//  * blend(gather(22,33,28,44),gatherHigh(35,41,36,31))
			//  * blend(gather(39,50,66,61),gatherHigh(47,58,53,69))
			//  
			// where gatherHigh(a,b,c,d) = gather(a-1,b-1,c-1,d-1), 
			// and blend(...) takes every other 16 bits.
			// 
			// The other rows follow the same logic.
			//
			// the final set of indices are (each 4 are in reverse order to match _mm_set_epi32):
			//
			//  6,11,16, 0 | 44,28,33,22 | 61,66,50,39
			// 13,18, 2, 7 | 30,35,40,34 | 68,52,57,46
			//							 
			//*  7,12,17,1 | 45,29,34,23 | 62,67,51,56
			//* 14,19, 3,8 | 47,36,41,25 | 69,53,58,63
			// 
			//* 24,13,18,2 | 46,30,35,40 | 63,68,52,57
			//* 31,20, 4,9 | 48,37,42,26 | 70,54,59,64

			// 0 0 
			auto a00 = _mm_i32gather_epi32((int*)src, _mm_set_epi32(6, 11, 16, 0), 2);
			auto a01 = _mm_i32gather_epi32((int*)src, _mm_set_epi32(13, 18, 2, 7), 2);
			dst[0] = _mm_blendv_epi8(a00, a01, _mm_set_epi16(-1, 0, -1, 0, -1, 0, -1, 0));
			auto a10 = _mm_i32gather_epi32((int*)src, _mm_set_epi32(44, 28, 33, 22), 2);
			auto a11 = _mm_i32gather_epi32((int*)src, _mm_set_epi32(30, 35, 40, 24), 2);
			dst[1] = _mm_blendv_epi8(a10, a11, _mm_set_epi16(-1, 0, -1, 0, -1, 0, -1, 0));
			auto a20 = _mm_i32gather_epi32((int*)src, _mm_set_epi32(61, 66, 50, 39), 2);
			auto a21 = _mm_i32gather_epi32((int*)src, _mm_set_epi32(68, 52, 57, 46), 2);
			dst[2] = _mm_blendv_epi8(a20, a21, _mm_set_epi16(-1, 0, -1, 0, -1, 0, -1, 0));


			auto b00 = _mm_i32gather_epi32((int*)src, _mm_set_epi32(7, 12, 17, 1), 2);
			auto b01 = _mm_i32gather_epi32((int*)src, _mm_set_epi32(14, 19, 3, 8), 2);
			dst[3] = _mm_blendv_epi8(b00, b01, _mm_set_epi16(-1, 0, -1, 0, -1, 0, -1, 0));
			auto b10 = _mm_i32gather_epi32((int*)src, _mm_set_epi32(45, 29, 34, 23), 2);
			auto b11 = _mm_i32gather_epi32((int*)src, _mm_set_epi32(47, 36, 41, 25), 2);
			dst[4] = _mm_blendv_epi8(b10, b11, _mm_set_epi16(-1, 0, -1, 0, -1, 0, -1, 0));
			auto b20 = _mm_i32gather_epi32((int*)src, _mm_set_epi32(62, 67, 51, 56), 2);
			auto b21 = _mm_i32gather_epi32((int*)src, _mm_set_epi32(69, 53, 58, 63), 2);
			dst[5] = _mm_blendv_epi8(b20, b21, _mm_set_epi16(-1, 0, -1, 0, -1, 0, -1, 0));


			auto c00 = _mm_i32gather_epi32((int*)src, _mm_set_epi32(24, 13, 18, 2), 2);
			auto c01 = _mm_i32gather_epi32((int*)src, _mm_set_epi32(31, 20, 4, 9), 2);
			dst[6] = _mm_blendv_epi8(c00, c01, _mm_set_epi16(-1, 0, -1, 0, -1, 0, -1, 0));
			auto c10 = _mm_i32gather_epi32((int*)src, _mm_set_epi32(46, 30, 35, 40), 2);
			auto c11 = _mm_i32gather_epi32((int*)src, _mm_set_epi32(48, 37, 42, 26), 2);
			dst[7] = _mm_blendv_epi8(c10, c11, _mm_set_epi16(-1, 0, -1, 0, -1, 0, -1, 0));
			auto c20 = _mm_i32gather_epi32((int*)src, _mm_set_epi32(63, 68, 52, 57), 2);
			auto c21 = _mm_i32gather_epi32((int*)src, _mm_set_epi32(70, 54, 59, 64), 2);
			dst[8] = _mm_blendv_epi8(c20, c21, _mm_set_epi16(-1, 0, -1, 0, -1, 0, -1, 0));

		}
		else
		{
			throw RTE_LOC;
		}
	}

	template<u64 stride>
	void foliageUnTranspose(u8* src, __m128i* dst)
	{
		constexpr std::array<u8, 24 * 3> inv{
			   0,  1,  2, 24, 25, 26, 48, 49, 50,
			   3,  4,  5, 27, 28, 29, 51, 52, 53,  
			   6,  7,  8, 30, 31, 32, 54, 55, 56, 
			   9, 10, 11, 33, 34, 35, 57, 58, 59, 
			  12, 13, 14, 36, 37, 38, 60, 61, 62,
			  15, 16, 17, 39, 40, 41, 63, 64, 65, 
			  18, 19, 20, 42, 43, 44, 66, 67, 68, 
			  21, 22, 23, 45, 46, 47, 69, 70, 71
		};

		auto dstPtr = (u8*)dst;
		for (u64 i = 0; i < inv.size(); ++i)
		{
			memcpy(dstPtr, src + inv[i] * stride, stride);
			dstPtr += stride;
		}


		//  0  1  2 24 25 26 48 49 50  3  4  5 27 28 29 51 52 53  6  7  8 30 31 32
		// 54 55 56  9 10 11 33 34 35 57 58 59 12 13 14 36 37 38 60 61 62 15 16 17
		// 39 40 41 63 64 65 18 19 20 42 43 44 66 67 68 21 22 23 45 46 47 69 70 71
	}



	template<typename u64 stride, typename T>
	OC_FORCEINLINE void foleageFFTOne(
		T* __restrict coeffsL0,
		T* __restrict coeffsL1,
		T* __restrict coeffsM0,
		T* __restrict coeffsM1,
		T* __restrict coeffsR0,
		T* __restrict coeffsR1)
	{

#pragma unroll(stride)
		for (u64 i = 0; i < stride; ++i)
		{

			auto xor_h = coeffsM1[i] ^ coeffsR1[i];
			auto xor_l = coeffsM0[i] ^ coeffsR0[i];

			auto mult0 = xor_h ^ xor_l;
			auto mult1 = xor_l;

			// tL coefficient obtained by evaluating on X_i=1
			auto tL0 = coeffsL0[i] ^ xor_l;
			auto tL1 = coeffsL1[i] ^ xor_h;
			auto tM0 = coeffsL0[i] ^ coeffsR0[i] ^ mult0;
			auto tM1 = coeffsL1[i] ^ coeffsR1[i] ^ mult1;
			coeffsR0[i] = coeffsL0[i] ^ coeffsM0[i] ^ mult0;
			coeffsR1[i] = coeffsL1[i] ^ coeffsM1[i] ^ mult1;
			coeffsL0[i] = tL0;
			coeffsL1[i] = tL1;
			coeffsM0[i] = tM0;
			coeffsM1[i] = tM1;
		}
	}



	inline void foleageFFT(
		MatrixView<uint8_t> lsb,
		MatrixView<uint8_t> msb)
	{
		if (lsb.rows() != msb.rows())
			throw RTE_LOC;
		if (lsb.cols() != msb.cols())
			throw RTE_LOC;
		auto numCoeffs = lsb.rows();
		if (numCoeffs % 3)
			throw RTE_LOC;
		auto numVars = log3ceil(numCoeffs);
		foleageFFT(lsb.data(), msb.data(), numVars, lsb.size() / 3);
	}


	template<u64 stride>
	void foleageFFT2(
		span<uint8_t> lsb,
		span<uint8_t> msb);

}

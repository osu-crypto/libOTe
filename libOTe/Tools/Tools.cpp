#include "Tools.h"
#include <type_traits>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/MatrixView.h>

#ifdef OC_ENABLE_SSE2
#ifndef _MSC_VER
#include <x86intrin.h>
#endif
#include <wmmintrin.h>
#endif
#ifdef OC_ENABLE_AVX2
#include <immintrin.h>
#endif

#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Log.h>
#include "libOTe/Tools/Tools.h"
#include "cryptoTools/Common/Aligned.h"
#include <limits>
#include <stdexcept>
using std::array;

namespace osuCrypto {

	namespace
	{
		u64 addMod(u64 x, u64 y, u64 modulus)
		{
			return x >= modulus - y ? x - (modulus - y) : x + y;
		}

		u64 mulMod(u64 x, u64 y, u64 modulus)
		{
			if (x == 0 || y <= std::numeric_limits<u64>::max() / x)
				return (x * y) % modulus;

			u64 result = 0;
			while (y)
			{
				if (y & 1)
					result = addMod(result, x, modulus);
				y >>= 1;
				if (y)
					x = addMod(x, x, modulus);
			}
			return result;
		}
	}

	// Utility function to do modular exponentiation.
	// It returns (x^y) % p
	u64 power(u64 x, u64 y, u64 p)
	{
		if (p == 0)
			throw std::invalid_argument("Modular exponentiation requires a nonzero modulus. " LOCATION);

		u64 res = 1;      // Initialize result
		x = x % p;  // Update x if it is more than or
		// equal to p
		while (y > 0)
		{
			// If y is odd, multiply x with result
			if (y & 1)
				res = mulMod(res, x, p);

			// y must be even now
			y = y >> 1; // y = y/2
			x = mulMod(x, x, p);
		}
		return res;
	}

	namespace
	{
		bool isPrime64(u64 n)
		{
			constexpr u64 smallPrimes[] = { 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37 };
			for (auto prime : smallPrimes)
			{
				if (n % prime == 0)
					return n == prime;
			}
			if (n < 2)
				return false;

			u64 d = n - 1;
			u64 shifts = 0;
			while ((d & 1) == 0)
			{
				d >>= 1;
				++shifts;
			}

			// This witness set is deterministic for every 64-bit integer.
			constexpr u64 witnesses[] =
				{ 2, 325, 9375, 28178, 450775, 9780504, 1795265022 };
			for (auto witness : witnesses)
			{
				witness %= n;
				if (witness == 0)
					continue;

				auto x = power(witness, d, n);
				if (x == 1 || x == n - 1)
					continue;

				bool composite = true;
				for (u64 r = 1; r < shifts; ++r)
				{
					x = mulMod(x, x, n);
					if (x == n - 1)
					{
						composite = false;
						break;
					}
				}
				if (composite)
					return false;
			}
			return true;
		}
	}

	bool isPrime(u64 n, PRNG& prng, u64 k)
	{
		(void)prng;
		(void)k;
		return isPrime64(n);
	}

	bool isPrime(u64 n)
	{
		return isPrime64(n);
	}


	u64 nextPrime(u64 n)
	{
		if (n <= 2)
			return 2;
		if ((n & 1) == 0)
			++n;

		while (!isPrime64(n))
		{
			if (n > std::numeric_limits<u64>::max() - 2)
				throw std::overflow_error("No 64-bit prime is at least the requested value. " LOCATION);
			n += 2;
		}
		return n;
	}

	namespace
	{
		bool isPrimitiveRootTwo(u64 prime)
		{
			if (prime <= 2)
				return false;

			const auto phi = prime - 1;
			auto remaining = phi;

			auto checkFactor = [&](u64 factor)
			{
				return power(2, phi / factor, prime) != 1;
			};

			if ((remaining & 1) == 0)
			{
				if (!checkFactor(2))
					return false;
				do
				{
					remaining >>= 1;
				} while ((remaining & 1) == 0);
			}

			for (u64 factor = 3; factor <= remaining / factor; factor += 2)
			{
				if (remaining % factor)
					continue;
				if (!checkFactor(factor))
					return false;
				do
				{
					remaining /= factor;
				} while (remaining % factor == 0);
			}

			return remaining == 1 || checkFactor(remaining);
		}
	}

	u64 nextPrimeWithPrimitiveRootTwo(u64 n)
	{
		auto prime = nextPrime(std::max<u64>(n, 3));
		while (!isPrimitiveRootTwo(prime))
		{
			if (prime == std::numeric_limits<u64>::max())
				throw std::overflow_error(
					"No 64-bit prime with primitive root two is at least the requested value. " LOCATION);
			prime = nextPrime(prime + 1);
		}
		return prime;
	}

	void print(array<block, 128>& inOut)
	{
		BitVector temp(128);

		for (u64 i = 0; i < 128; ++i)
		{

			temp.assign(inOut[i]);
			std::cout << temp << std::endl;
		}
		std::cout << std::endl;
	}

	u8 getBit(array<block, 128>& inOut, u64 i, u64 j)
	{
		BitVector temp(128);
		temp.assign(inOut[i]);

		return temp[j];

	}


	void eklundh_transpose128(block* inOut)
	{
		const static u64 TRANSPOSE_MASKS128[7][2] = {
			{ 0x0000000000000000, 0xFFFFFFFFFFFFFFFF },
			{ 0x00000000FFFFFFFF, 0x00000000FFFFFFFF },
			{ 0x0000FFFF0000FFFF, 0x0000FFFF0000FFFF },
			{ 0x00FF00FF00FF00FF, 0x00FF00FF00FF00FF },
			{ 0x0F0F0F0F0F0F0F0F, 0x0F0F0F0F0F0F0F0F },
			{ 0x3333333333333333, 0x3333333333333333 },
			{ 0x5555555555555555, 0x5555555555555555 }
		};

		u32 width = 64;
		u32 logn = 7, nswaps = 1;

#ifdef TRANSPOSE_DEBUG
		stringstream input_ss[128];
		stringstream output_ss[128];
#endif

		// now transpose output a-place
		for (u32 i = 0; i < logn; i++)
		{
			u64 mask1 = TRANSPOSE_MASKS128[i][1], mask2 = TRANSPOSE_MASKS128[i][0];
			u64 inv_mask1 = ~mask1, inv_mask2 = ~mask2;

			// for width >= 64, shift is undefined so treat as h special case
			// (and avoid branching a inner loop)
			if (width < 64)
			{
				for (u32 j = 0; j < nswaps; j++)
				{
					for (u32 k = 0; k < width; k++)
					{
						u32 i1 = k + 2 * width * j;
						u32 i2 = k + width + 2 * width * j;

						// t1 is lower 64 bits, t2 is upper 64 bits
						// (remember we're transposing a little-endian format)
						auto d = inOut[i1].get<u64>();
						auto dd = inOut[i2].get<u64>();

						u64 t1 = d[0];
						u64 t2 = d[1];

						u64 tt1 = dd[0];
						u64 tt2 = dd[1];

						// swap operations due to little endian-ness
						d[0] = (t1 & mask1) ^ ((tt1 & mask1) << width);

						d[1] = (t2 & mask2) ^
							((tt2 & mask2) << width) ^
							((tt1 & mask1) >> (64 - width));

						dd[0] = (tt1 & inv_mask1) ^
							((t1 & inv_mask1) >> width) ^
							((t2 & inv_mask2)) << (64 - width);

						dd[1] = (tt2 & inv_mask2) ^
							((t2 & inv_mask2) >> width);

						inOut[i1] = d;
						inOut[i2] = dd;
					}
				}
			}
			else
			{
				for (u32 j = 0; j < nswaps; j++)
				{
					for (u32 k = 0; k < width; k++)
					{
						u32 i1 = k + 2 * width * j;
						u32 i2 = k + width + 2 * width * j;

						// t1 is lower 64 bits, t2 is upper 64 bits
						// (remember we're transposing a little-endian format)
						auto d = inOut[i1].get<u64>();
						auto dd = inOut[i2].get<u64>();

						//u64 t1 = d[0];
						u64 t2 = d[1];

						//u64 tt1 = dd[0];
						//u64 tt2 = dd[1];

						d[0] &= mask1;
						d[1] = (t2 & mask2) ^
							((dd[0] & mask1) >> (64 - width));

						dd[0] = (dd[0] & inv_mask1) ^
							((t2 & inv_mask2)) << (64 - width);

						dd[1] &= inv_mask2;

						inOut[i1] = d;
						inOut[i2] = dd;
					}
				}
			}
			nswaps *= 2;
			width /= 2;
		}
#ifdef TRANSPOSE_DEBUG
		for (u32 k = 0; k < 128; k++)
		{
			for (u32 blkIdx = 0; blkIdx < 128; blkIdx++)
			{
				output_ss[blkIdx] << inOut[offset + blkIdx].get_bit(k);
			}
		}
		for (u32 k = 0; k < 128; k++)
		{
			if (output_ss[k].str().compare(input_ss[k].str()) != 0)
			{
				cerr << "String " << k << " failed. offset = " << offset << endl;
				exit(1);
			}
		}
		std::cout << "\ttranspose with offset " << offset << " ok\n";
#endif
	}



	void eklundh_transpose128x1024(block* inOut)
	{


		for (u64 i = 0; i < 8; ++i)
		{
			std::array<block, 128> sub;
			for (u64 j = 0; j < 128; ++j)
				sub[j] = inOut[j * 8 + i];

			eklundh_transpose128(sub.data());

			for (u64 j = 0; j < 128; ++j)
				inOut[j * 8 + i] = sub[j];
		}

	}



	//  load          column  w,w+1          (byte index)
	//                   __________________
	//                  |                  |
	//                  |                  |
	//                  |                  |
	//                  |                  |
	//  row  16*h,      |     #.#          |
	//       ...,       |     ...          |
	//  row  16*(h+1)   |     #.#          |     into  u16OutView  column wise
	//                  |                  |
	//                  |                  |
	//                   ------------------
	//
	// note: u16OutView is a 16x16 bit matrix = 16 rows of 2 bytes each.
	//       u16OutView[0] stores the first column of 16 bytes,
	//       u16OutView[1] stores the second column of 16 bytes.
	void sse_loadSubSquare(block* in, array<block, 2>& out, u64 x, u64 y)
	{
		auto* outBytes = reinterpret_cast<u8*>(out.data());
		auto* inBytes = reinterpret_cast<const u8*>(in);

		for (int l = 0; l < 16; l++)
		{
			auto row = static_cast<u64>(16 * x + l) * sizeof(block);
			outBytes[l] = inBytes[row + 2 * y];
			outBytes[sizeof(block) + l] = inBytes[row + 2 * y + 1];
		}
	}



	// given a 16x16 sub square, place its transpose into two-byte lanes at
	// rows  16*h, ..., 16 *(h+1)  a byte  columns w, w+1.
	void sse_transposeSubSquare(block* out, array<block, 2>& in, u64 x, u64 y)
	{
		for (int j = 0; j < 8; j++)
		{
			auto lo = static_cast<u16>(in[0].movemask_epi8());
			auto hi = static_cast<u16>(in[1].movemask_epi8());
			memcpy(out[16 * x + 7 - j].data() + y * sizeof(u16), &lo, sizeof(lo));
			memcpy(out[16 * x + 15 - j].data() + y * sizeof(u16), &hi, sizeof(hi));

			in[0] = in[0].slli_epi64(1);
			in[1] = in[1].slli_epi64(1);
		}
	}


	void transpose(const MatrixView<block>& in, const MatrixView<block>& out)
	{
		MatrixView<u8> inn((u8*)in.data(), in.bounds()[0], in.stride() * sizeof(block));
		MatrixView<u8> outt((u8*)out.data(), out.bounds()[0], out.stride() * sizeof(block));

		transpose(inn, outt);
	}

	void sse_transpose(MatrixView<const u8> in, MatrixView<u8> out)
	{
		// the amount of work that we use to vectorize (hard code do not change)
		static const u64 chunkSize = 8;

		// the number of input columns
		int bitWidth = static_cast<int>(in.bounds()[0]);

		// In the main loop, we tranpose things in subBlocks. This is how many we have.
		// a subblock is 16 (bits) columns wide and 64 bits tall
		int subBlockWidth = bitWidth / 16;
		int subBlockHight = static_cast<int>(out.bounds()[0]) / (8 * chunkSize);

		// since we allows arbitrary sized inputs, we have to deal with the left overs
		int leftOverHeight = static_cast<int>(out.bounds()[0]) % (chunkSize * 8);
		int leftOverWidth = static_cast<int>(in.bounds()[0]) % 16;


		// make sure that the output can hold the input.
		if (static_cast<int>(out.stride()) < (bitWidth + 7) / 8)
			throw std::runtime_error(LOCATION);

		// we can handle the case that the output should be truncated, but
		// not the case that the input is too small. (simple call this function
		// with a smaller out.bounds()[0], since thats "free" to do.)
		if (out.bounds()[0] > in.stride() * 8)
			throw std::runtime_error(LOCATION);

		union TempObj
		{
			//array<block, chunkSize> blks;
			block blks[chunkSize];
			//array < array<u8, 16>, chunkSize> bytes;
			u8 bytes[chunkSize][16];
		};

		TempObj t;


		// some useful constants that we will use
		auto wStep = 16 * in.stride();
		auto eightOutSize1 = 8 * out.stride();
		auto outStart = out.data() + (7) * out.stride();
		auto step = in.stride();
		auto
			step01 = step * 1,
			step02 = step * 2,
			step03 = step * 3,
			step04 = step * 4,
			step05 = step * 5,
			step06 = step * 6,
			step07 = step * 7,
			step08 = step * 8,
			step09 = step * 9,
			step10 = step * 10,
			step11 = step * 11,
			step12 = step * 12,
			step13 = step * 13,
			step14 = step * 14,
			step15 = step * 15;


		// this is the main loop that gets the best performance (highly vectorized).
		for (int h = 0; h < subBlockHight; ++h)
		{
			// we are concerned with the output rows a range [16 * h, 16 * h + 15]

			for (int w = 0; w < subBlockWidth; ++w)
			{
				// we are concerned with the w'th section of 16 bits for the 16 output rows above.

				auto start = in.data() + h * chunkSize + w * wStep;

				auto src00 = start;
				auto src01 = start + step01;
				auto src02 = start + step02;
				auto src03 = start + step03;
				auto src04 = start + step04;
				auto src05 = start + step05;
				auto src06 = start + step06;
				auto src07 = start + step07;
				auto src08 = start + step08;
				auto src09 = start + step09;
				auto src10 = start + step10;
				auto src11 = start + step11;
				auto src12 = start + step12;
				auto src13 = start + step13;
				auto src14 = start + step14;
				auto src15 = start + step15;

				// perform the transpose on the byte level. We will then use
				// sse instrucitions to get it on the bit level. t.bytes is the
				// same as a but in a 2D byte view.
				t.bytes[0][0] = src00[0]; t.bytes[1][0] = src00[1];  t.bytes[2][0] = src00[2]; t.bytes[3][0] = src00[3];   t.bytes[4][0] = src00[4];  t.bytes[5][0] = src00[5];  t.bytes[6][0] = src00[6]; t.bytes[7][0] = src00[7];
				t.bytes[0][1] = src01[0]; t.bytes[1][1] = src01[1];  t.bytes[2][1] = src01[2]; t.bytes[3][1] = src01[3];   t.bytes[4][1] = src01[4];  t.bytes[5][1] = src01[5];  t.bytes[6][1] = src01[6]; t.bytes[7][1] = src01[7];
				t.bytes[0][2] = src02[0]; t.bytes[1][2] = src02[1];  t.bytes[2][2] = src02[2]; t.bytes[3][2] = src02[3];   t.bytes[4][2] = src02[4];  t.bytes[5][2] = src02[5];  t.bytes[6][2] = src02[6]; t.bytes[7][2] = src02[7];
				t.bytes[0][3] = src03[0]; t.bytes[1][3] = src03[1];  t.bytes[2][3] = src03[2]; t.bytes[3][3] = src03[3];   t.bytes[4][3] = src03[4];  t.bytes[5][3] = src03[5];  t.bytes[6][3] = src03[6]; t.bytes[7][3] = src03[7];
				t.bytes[0][4] = src04[0]; t.bytes[1][4] = src04[1];  t.bytes[2][4] = src04[2]; t.bytes[3][4] = src04[3];   t.bytes[4][4] = src04[4];  t.bytes[5][4] = src04[5];  t.bytes[6][4] = src04[6]; t.bytes[7][4] = src04[7];
				t.bytes[0][5] = src05[0]; t.bytes[1][5] = src05[1];  t.bytes[2][5] = src05[2]; t.bytes[3][5] = src05[3];   t.bytes[4][5] = src05[4];  t.bytes[5][5] = src05[5];  t.bytes[6][5] = src05[6]; t.bytes[7][5] = src05[7];
				t.bytes[0][6] = src06[0]; t.bytes[1][6] = src06[1];  t.bytes[2][6] = src06[2]; t.bytes[3][6] = src06[3];   t.bytes[4][6] = src06[4];  t.bytes[5][6] = src06[5];  t.bytes[6][6] = src06[6]; t.bytes[7][6] = src06[7];
				t.bytes[0][7] = src07[0]; t.bytes[1][7] = src07[1];  t.bytes[2][7] = src07[2]; t.bytes[3][7] = src07[3];   t.bytes[4][7] = src07[4];  t.bytes[5][7] = src07[5];  t.bytes[6][7] = src07[6]; t.bytes[7][7] = src07[7];
				t.bytes[0][8] = src08[0]; t.bytes[1][8] = src08[1];  t.bytes[2][8] = src08[2]; t.bytes[3][8] = src08[3];   t.bytes[4][8] = src08[4];  t.bytes[5][8] = src08[5];  t.bytes[6][8] = src08[6]; t.bytes[7][8] = src08[7];
				t.bytes[0][9] = src09[0]; t.bytes[1][9] = src09[1];  t.bytes[2][9] = src09[2]; t.bytes[3][9] = src09[3];   t.bytes[4][9] = src09[4];  t.bytes[5][9] = src09[5];  t.bytes[6][9] = src09[6]; t.bytes[7][9] = src09[7];
				t.bytes[0][10] = src10[0]; t.bytes[1][10] = src10[1];  t.bytes[2][10] = src10[2]; t.bytes[3][10] = src10[3];   t.bytes[4][10] = src10[4];  t.bytes[5][10] = src10[5];  t.bytes[6][10] = src10[6]; t.bytes[7][10] = src10[7];
				t.bytes[0][11] = src11[0]; t.bytes[1][11] = src11[1];  t.bytes[2][11] = src11[2]; t.bytes[3][11] = src11[3];   t.bytes[4][11] = src11[4];  t.bytes[5][11] = src11[5];  t.bytes[6][11] = src11[6]; t.bytes[7][11] = src11[7];
				t.bytes[0][12] = src12[0]; t.bytes[1][12] = src12[1];  t.bytes[2][12] = src12[2]; t.bytes[3][12] = src12[3];   t.bytes[4][12] = src12[4];  t.bytes[5][12] = src12[5];  t.bytes[6][12] = src12[6]; t.bytes[7][12] = src12[7];
				t.bytes[0][13] = src13[0]; t.bytes[1][13] = src13[1];  t.bytes[2][13] = src13[2]; t.bytes[3][13] = src13[3];   t.bytes[4][13] = src13[4];  t.bytes[5][13] = src13[5];  t.bytes[6][13] = src13[6]; t.bytes[7][13] = src13[7];
				t.bytes[0][14] = src14[0]; t.bytes[1][14] = src14[1];  t.bytes[2][14] = src14[2]; t.bytes[3][14] = src14[3];   t.bytes[4][14] = src14[4];  t.bytes[5][14] = src14[5];  t.bytes[6][14] = src14[6]; t.bytes[7][14] = src14[7];
				t.bytes[0][15] = src15[0]; t.bytes[1][15] = src15[1];  t.bytes[2][15] = src15[2]; t.bytes[3][15] = src15[3];   t.bytes[4][15] = src15[4];  t.bytes[5][15] = src15[5];  t.bytes[6][15] = src15[6]; t.bytes[7][15] = src15[7];

				// get pointers to the output.
				auto out0 = outStart + (chunkSize * h + 0) * eightOutSize1 + w * 2;
				auto out1 = outStart + (chunkSize * h + 1) * eightOutSize1 + w * 2;
				auto out2 = outStart + (chunkSize * h + 2) * eightOutSize1 + w * 2;
				auto out3 = outStart + (chunkSize * h + 3) * eightOutSize1 + w * 2;
				auto out4 = outStart + (chunkSize * h + 4) * eightOutSize1 + w * 2;
				auto out5 = outStart + (chunkSize * h + 5) * eightOutSize1 + w * 2;
				auto out6 = outStart + (chunkSize * h + 6) * eightOutSize1 + w * 2;
				auto out7 = outStart + (chunkSize * h + 7) * eightOutSize1 + w * 2;

				for (int j = 0; j < 8; j++)
				{
					// use the special movemask_epi8 to perform the final step of that bit-wise tranpose.
					// this instruction takes ever 8'th bit (start at idx 7) and moves them into a single
					// 16 bit output. Its like shaving off the top bit of each of the 16 bytes.
					auto mask = static_cast<u16>(t.blks[0].movemask_epi8());
					memcpy(out0, &mask, sizeof(mask));
					mask = static_cast<u16>(t.blks[1].movemask_epi8());
					memcpy(out1, &mask, sizeof(mask));
					mask = static_cast<u16>(t.blks[2].movemask_epi8());
					memcpy(out2, &mask, sizeof(mask));
					mask = static_cast<u16>(t.blks[3].movemask_epi8());
					memcpy(out3, &mask, sizeof(mask));
					mask = static_cast<u16>(t.blks[4].movemask_epi8());
					memcpy(out4, &mask, sizeof(mask));
					mask = static_cast<u16>(t.blks[5].movemask_epi8());
					memcpy(out5, &mask, sizeof(mask));
					mask = static_cast<u16>(t.blks[6].movemask_epi8());
					memcpy(out6, &mask, sizeof(mask));
					mask = static_cast<u16>(t.blks[7].movemask_epi8());
					memcpy(out7, &mask, sizeof(mask));

					// step each of out 8 pointer over to the next output row.
					out0 -= out.stride();
					out1 -= out.stride();
					out2 -= out.stride();
					out3 -= out.stride();
					out4 -= out.stride();
					out5 -= out.stride();
					out6 -= out.stride();
					out7 -= out.stride();

					// shift the 128 values so that the top bit is now the next one.
					t.blks[0] = t.blks[0].slli_epi64(1);
					t.blks[1] = t.blks[1].slli_epi64(1);
					t.blks[2] = t.blks[2].slli_epi64(1);
					t.blks[3] = t.blks[3].slli_epi64(1);
					t.blks[4] = t.blks[4].slli_epi64(1);
					t.blks[5] = t.blks[5].slli_epi64(1);
					t.blks[6] = t.blks[6].slli_epi64(1);
					t.blks[7] = t.blks[7].slli_epi64(1);
				}
			}
		}

		// this is a special case there we dont have chunkSize bytes of input column left.
		// because of this, the vectorized code above does not work and we instead so thing
		// one byte as a time.

		// hhEnd denotes how many bytes are left [0,8).
		auto hhEnd = (leftOverHeight + 7) / 8;

		// the last byte might be only part of a byte, so we also account for this
		auto lastSkip = (8 - leftOverHeight % 8) % 8;

		for (int hh = 0; hh < hhEnd; ++hh)
		{
			// compute those parameters that determine if this is the last byte
			// and that its a partial byte meaning that the last so mant output
			// rows  should not be written to.
			auto skip = hh == (hhEnd - 1) ? lastSkip : 0;
			auto rem = 8 - skip;

			for (int w = 0; w < subBlockWidth; ++w)
			{

				auto start = in.data() + subBlockHight * chunkSize + hh + w * wStep;

				t.bytes[0][0] = *(start);
				t.bytes[0][1] = *(start + step01);
				t.bytes[0][2] = *(start + step02);
				t.bytes[0][3] = *(start + step03);
				t.bytes[0][4] = *(start + step04);
				t.bytes[0][5] = *(start + step05);
				t.bytes[0][6] = *(start + step06);
				t.bytes[0][7] = *(start + step07);
				t.bytes[0][8] = *(start + step08);
				t.bytes[0][9] = *(start + step09);
				t.bytes[0][10] = *(start + step10);
				t.bytes[0][11] = *(start + step11);
				t.bytes[0][12] = *(start + step12);
				t.bytes[0][13] = *(start + step13);
				t.bytes[0][14] = *(start + step14);
				t.bytes[0][15] = *(start + step15);


				auto out0 = outStart + (chunkSize * subBlockHight + hh) * 8 * out.stride() + w * 2;

				out0 -= out.stride() * skip;
				t.blks[0] = t.blks[0].slli_epi64(skip);

				for (int j = 0; j < rem; j++)
				{
					auto mask = static_cast<u16>(t.blks[0].movemask_epi8());
					memcpy(out0, &mask, sizeof(mask));

					out0 -= out.stride();

					t.blks[0] = t.blks[0].slli_epi64(1);
				}
			}
		}

		// this is a special case where the input column count was not a multiple of 16.
		// For this case, we use
		if (leftOverWidth)
		{
			for (int h = 0; h < subBlockHight; ++h)
			{
				// we are concerned with the output rows a range [16 * h, 16 * h + 15]

				auto start = in.data() + h * chunkSize + subBlockWidth * wStep;

				std::array<const u8*, 16> src{
					start, start + step01, start + step02, start + step03, start + step04, start + step05,
					start + step06, start + step07, start + step08, start + step09, start + step10,
					start + step11, start + step12, start + step13, start + step14, start + step15
				};

				memset(t.blks, 0, sizeof(t));
				for (int i = 0; i < leftOverWidth; ++i)
				{
					t.bytes[0][i] = src[i][0];
					t.bytes[1][i] = src[i][1];
					t.bytes[2][i] = src[i][2];
					t.bytes[3][i] = src[i][3];
					t.bytes[4][i] = src[i][4];
					t.bytes[5][i] = src[i][5];
					t.bytes[6][i] = src[i][6];
					t.bytes[7][i] = src[i][7];
				}

				auto out0 = outStart + (chunkSize * h + 0) * eightOutSize1 + subBlockWidth * 2;
				auto out1 = outStart + (chunkSize * h + 1) * eightOutSize1 + subBlockWidth * 2;
				auto out2 = outStart + (chunkSize * h + 2) * eightOutSize1 + subBlockWidth * 2;
				auto out3 = outStart + (chunkSize * h + 3) * eightOutSize1 + subBlockWidth * 2;
				auto out4 = outStart + (chunkSize * h + 4) * eightOutSize1 + subBlockWidth * 2;
				auto out5 = outStart + (chunkSize * h + 5) * eightOutSize1 + subBlockWidth * 2;
				auto out6 = outStart + (chunkSize * h + 6) * eightOutSize1 + subBlockWidth * 2;
				auto out7 = outStart + (chunkSize * h + 7) * eightOutSize1 + subBlockWidth * 2;

				if (leftOverWidth <= 8)
				{
					for (int j = 0; j < 8; j++)
					{
						*out0 = t.blks[0].movemask_epi8();
						*out1 = t.blks[1].movemask_epi8();
						*out2 = t.blks[2].movemask_epi8();
						*out3 = t.blks[3].movemask_epi8();
						*out4 = t.blks[4].movemask_epi8();
						*out5 = t.blks[5].movemask_epi8();
						*out6 = t.blks[6].movemask_epi8();
						*out7 = t.blks[7].movemask_epi8();

						out0 -= out.stride();
						out1 -= out.stride();
						out2 -= out.stride();
						out3 -= out.stride();
						out4 -= out.stride();
						out5 -= out.stride();
						out6 -= out.stride();
						out7 -= out.stride();

						t.blks[0] = t.blks[0].slli_epi64(1);
						t.blks[1] = t.blks[1].slli_epi64(1);
						t.blks[2] = t.blks[2].slli_epi64(1);
						t.blks[3] = t.blks[3].slli_epi64(1);
						t.blks[4] = t.blks[4].slli_epi64(1);
						t.blks[5] = t.blks[5].slli_epi64(1);
						t.blks[6] = t.blks[6].slli_epi64(1);
						t.blks[7] = t.blks[7].slli_epi64(1);
					}
				}
				else
				{
					for (int j = 0; j < 8; j++)
					{
						auto mask = static_cast<u16>(t.blks[0].movemask_epi8());
						memcpy(out0, &mask, sizeof(mask));
						mask = static_cast<u16>(t.blks[1].movemask_epi8());
						memcpy(out1, &mask, sizeof(mask));
						mask = static_cast<u16>(t.blks[2].movemask_epi8());
						memcpy(out2, &mask, sizeof(mask));
						mask = static_cast<u16>(t.blks[3].movemask_epi8());
						memcpy(out3, &mask, sizeof(mask));
						mask = static_cast<u16>(t.blks[4].movemask_epi8());
						memcpy(out4, &mask, sizeof(mask));
						mask = static_cast<u16>(t.blks[5].movemask_epi8());
						memcpy(out5, &mask, sizeof(mask));
						mask = static_cast<u16>(t.blks[6].movemask_epi8());
						memcpy(out6, &mask, sizeof(mask));
						mask = static_cast<u16>(t.blks[7].movemask_epi8());
						memcpy(out7, &mask, sizeof(mask));

						out0 -= out.stride();
						out1 -= out.stride();
						out2 -= out.stride();
						out3 -= out.stride();
						out4 -= out.stride();
						out5 -= out.stride();
						out6 -= out.stride();
						out7 -= out.stride();

						t.blks[0] = t.blks[0].slli_epi64(1);
						t.blks[1] = t.blks[1].slli_epi64(1);
						t.blks[2] = t.blks[2].slli_epi64(1);
						t.blks[3] = t.blks[3].slli_epi64(1);
						t.blks[4] = t.blks[4].slli_epi64(1);
						t.blks[5] = t.blks[5].slli_epi64(1);
						t.blks[6] = t.blks[6].slli_epi64(1);
						t.blks[7] = t.blks[7].slli_epi64(1);
					}
				}
			}

			//auto hhEnd = (leftOverHeight + 7) / 8;
			//auto lastSkip = (8 - leftOverHeight % 8) % 8;
			for (int hh = 0; hh < hhEnd; ++hh)
			{
				auto skip = hh == (hhEnd - 1) ? lastSkip : 0;
				auto rem = 8 - skip;

				// we are concerned with the output rows a range [16 * h, 16 * h + 15]
				auto w = subBlockWidth;

				auto start = in.data() + subBlockHight * chunkSize + hh + w * wStep;

				std::array<const u8*, 16> src{
					start, start + step01, start + step02, start + step03, start + step04, start + step05,
					start + step06, start + step07, start + step08, start + step09, start + step10,
					start + step11, start + step12, start + step13, start + step14, start + step15
				};


				t.blks[0] = ZeroBlock;
				for (int i = 0; i < leftOverWidth; ++i)
				{
					t.bytes[0][i] = src[i][0];
				}

				auto out0 = outStart + (chunkSize * subBlockHight + hh) * 8 * out.stride() + w * 2;

				out0 -= out.stride() * skip;
				t.blks[0] = t.blks[0].slli_epi64(skip);

				for (int j = 0; j < rem; j++)
				{
					if (leftOverWidth > 8)
					{
						auto mask = static_cast<u16>(t.blks[0].movemask_epi8());
						memcpy(out0, &mask, sizeof(mask));
					}
					else
					{
						*out0 = t.blks[0].movemask_epi8();
					}

					out0 -= out.stride();

					t.blks[0] = t.blks[0].slli_epi64(1);
				}
			}
		}
	}

#ifdef ENABLE_AVX

	void avx_transpose(MatrixView<const u8> in, MatrixView<u8> out)
	{
		AlignedArray<block, 128> buff;
		auto rBits = std::min<u64>(in.rows(), out.cols() * 8);
		auto cBits = std::min<u64>(in.cols() * 8, out.rows());

		// the number of full 128x128 bit squares.
		u64 rMain = rBits / 128;
		u64 cMain = cBits / 128;
		auto inStride = in.cols();
		auto outStride = out.cols();

		auto rRemBits = rBits - rMain * 128;
		auto cRemBits = cBits - cMain * 128;

		auto rRemBytes = divCeil(rRemBits, 8);
		auto cRemBytes = divCeil(cRemBits, 8);


		for (u64 i = 0; i < rMain; ++i)
		{
			// full 128x128 bit squares
			for (u64 j = 0; j < cMain; ++j)
			{
				auto src = in.data(i * 128) + j * sizeof(block);
				for (u64 k = 0; k < 128; ++k)
				{
					assert((u8*)src + sizeof(block) <= in.data() + in.size());
					memcpy(buff.data() + k, src, sizeof(block));
					src += inStride;
				}

				avx_transpose128(buff.data());

				auto dst = out.data(j * 128) + i * sizeof(block);
				for (u64 k = 0; k < 128; ++k)
				{
					assert((u8*)dst + sizeof(block) <= out.data() + out.size());
					memcpy(dst, buff.data() + k, sizeof(block));
					dst += outStride;
				}
			}

			// partial columns but full set of rows
			if (cRemBits)
			{
				memset(buff.data(), 0, sizeof(buff));
				auto src = in.data(i * 128) + cMain * sizeof(block);
				for (u64 k = 0; k < 128; ++k)
				{
					assert((u8*)src + cRemBytes <= in.data() + in.size());
					memcpy(buff.data() + k, src, cRemBytes);
					src += inStride;
				}

				avx_transpose128(buff.data());

				auto dst = out.data(cMain * 128) + i * sizeof(block);
				for (u64 k = 0; k < cRemBits; ++k)
				{
					assert((u8*)dst + sizeof(block) <= out.data() + out.size());
					memcpy(dst, buff.data() + k, sizeof(block));
					dst += outStride;
				}
			}
		}

		// partial rows
		if (rRemBits)
		{
			for (u64 j = 0; j < cMain; ++j)
			{
				auto src = in.data(rMain * 128) + j * sizeof(block);
				for (u64 k = 0; k < rRemBits; ++k)
				{
					assert((u8*)src + sizeof(block) <= in.data() + in.size());
					memcpy(buff.data() + k, src, sizeof(block));
					src += inStride;
				}

				memset(buff.data() + rRemBits, 0, (128 - rRemBits) * sizeof(block));

				avx_transpose128(buff.data());

				auto dst = out.data(j * 128) + rMain * sizeof(block);
				for (u64 k = 0; k < 128; ++k)
				{
					assert((u8*)dst + rRemBytes <= out.data() + out.size());
					memcpy(dst, buff.data() + k, rRemBytes);
					dst += outStride;
				}
			}

			if (cRemBits)
			{
				memset(buff.data(), 0, sizeof(buff));
				auto src = in.data(rMain * 128) + cMain * sizeof(block);
				for (u64 k = 0; k < rRemBits; ++k)
				{
					assert((u8*)src + cRemBytes <= in.data() + in.size());
					memcpy(buff.data() + k, src, cRemBytes);
					src += inStride;
				}
				memset(buff.data() + rRemBits, 0, (128 - rRemBits) * sizeof(block));

				avx_transpose128(buff.data());

				auto dst = out.data(cMain * 128) + rMain * sizeof(block);
				for (u64 k = 0; k < cRemBits; ++k)
				{
					assert((u8*)dst + rRemBytes <= out.data() + out.size());
					memcpy(dst, buff.data() + k, rRemBytes);
					dst += outStride;
				}
			}
		}

	}
#endif


	void transpose(MatrixView<const u8> in, MatrixView<u8> out)
	{
#if defined(ENABLE_AVX)
		avx_transpose(in, out);
#else
		sse_transpose(in, out);
#endif
	}



	void sse_transpose128(block* inOut)
	{
		array<block, 2> a, b;

		for (int j = 0; j < 8; j++)
		{
			sse_loadSubSquare(inOut, a, j, j);
			sse_transposeSubSquare(inOut, a, j, j);

			for (int k = 0; k < j; k++)
			{
				sse_loadSubSquare(inOut, a, k, j);
				sse_loadSubSquare(inOut, b, j, k);
				sse_transposeSubSquare(inOut, a, j, k);
				sse_transposeSubSquare(inOut, b, k, j);
			}
		}
	}




	inline void sse_loadSubSquarex(block* in, array<block, 2>& out, u64 x, u64 y, u64 i)
	{
		auto* outBytes = reinterpret_cast<u8*>(out.data());
		auto* inBytes = reinterpret_cast<const u8*>(in);

		auto x16 = (x * 16);

		auto i16y2 = (i * 16) + 2 * y;
		auto i16y21 = (i * 16) + 2 * y + 1;


		outBytes[0] = inBytes[(x16 + 0) * 128 + i16y2];
		outBytes[16] = inBytes[(x16 + 0) * 128 + i16y21];
		outBytes[1] = inBytes[(x16 + 1) * 128 + i16y2];
		outBytes[17] = inBytes[(x16 + 1) * 128 + i16y21];
		outBytes[2] = inBytes[(x16 + 2) * 128 + i16y2];
		outBytes[18] = inBytes[(x16 + 2) * 128 + i16y21];
		outBytes[3] = inBytes[(x16 + 3) * 128 + i16y2];
		outBytes[19] = inBytes[(x16 + 3) * 128 + i16y21];
		outBytes[4] = inBytes[(x16 + 4) * 128 + i16y2];
		outBytes[20] = inBytes[(x16 + 4) * 128 + i16y21];
		outBytes[5] = inBytes[(x16 + 5) * 128 + i16y2];
		outBytes[21] = inBytes[(x16 + 5) * 128 + i16y21];
		outBytes[6] = inBytes[(x16 + 6) * 128 + i16y2];
		outBytes[22] = inBytes[(x16 + 6) * 128 + i16y21];
		outBytes[7] = inBytes[(x16 + 7) * 128 + i16y2];
		outBytes[23] = inBytes[(x16 + 7) * 128 + i16y21];
		outBytes[8] = inBytes[(x16 + 8) * 128 + i16y2];
		outBytes[24] = inBytes[(x16 + 8) * 128 + i16y21];
		outBytes[9] = inBytes[(x16 + 9) * 128 + i16y2];
		outBytes[25] = inBytes[(x16 + 9) * 128 + i16y21];
		outBytes[10] = inBytes[(x16 + 10) * 128 + i16y2];
		outBytes[26] = inBytes[(x16 + 10) * 128 + i16y21];
		outBytes[11] = inBytes[(x16 + 11) * 128 + i16y2];
		outBytes[27] = inBytes[(x16 + 11) * 128 + i16y21];
		outBytes[12] = inBytes[(x16 + 12) * 128 + i16y2];
		outBytes[28] = inBytes[(x16 + 12) * 128 + i16y21];
		outBytes[13] = inBytes[(x16 + 13) * 128 + i16y2];
		outBytes[29] = inBytes[(x16 + 13) * 128 + i16y21];
		outBytes[14] = inBytes[(x16 + 14) * 128 + i16y2];
		outBytes[30] = inBytes[(x16 + 14) * 128 + i16y21];
		outBytes[15] = inBytes[(x16 + 15) * 128 + i16y2];
		outBytes[31] = inBytes[(x16 + 15) * 128 + i16y21];

	}



	inline void sse_transposeSubSquarex(block* out, array<block, 2>& in, u64 x, u64 y, u64 i)
	{
		auto i8y = i * 8 + y;
		auto x16_7 = x * 16 + 7;
		auto x16_15 = x * 16 + 15;

		block b0 = in[0].slli_epi64(0);
		block b1 = in[0].slli_epi64(1);
		block b2 = in[0].slli_epi64(2);
		block b3 = in[0].slli_epi64(3);
		block b4 = in[0].slli_epi64(4);
		block b5 = in[0].slli_epi64(5);
		block b6 = in[0].slli_epi64(6);
		block b7 = in[0].slli_epi64(7);

		auto mask = static_cast<u16>(b0.movemask_epi8());
		memcpy(out[(x16_7 - 0) * 8].data() + i8y * sizeof(mask), &mask, sizeof(mask));
		mask = static_cast<u16>(b1.movemask_epi8());
		memcpy(out[(x16_7 - 1) * 8].data() + i8y * sizeof(mask), &mask, sizeof(mask));
		mask = static_cast<u16>(b2.movemask_epi8());
		memcpy(out[(x16_7 - 2) * 8].data() + i8y * sizeof(mask), &mask, sizeof(mask));
		mask = static_cast<u16>(b3.movemask_epi8());
		memcpy(out[(x16_7 - 3) * 8].data() + i8y * sizeof(mask), &mask, sizeof(mask));
		mask = static_cast<u16>(b4.movemask_epi8());
		memcpy(out[(x16_7 - 4) * 8].data() + i8y * sizeof(mask), &mask, sizeof(mask));
		mask = static_cast<u16>(b5.movemask_epi8());
		memcpy(out[(x16_7 - 5) * 8].data() + i8y * sizeof(mask), &mask, sizeof(mask));
		mask = static_cast<u16>(b6.movemask_epi8());
		memcpy(out[(x16_7 - 6) * 8].data() + i8y * sizeof(mask), &mask, sizeof(mask));
		mask = static_cast<u16>(b7.movemask_epi8());
		memcpy(out[(x16_7 - 7) * 8].data() + i8y * sizeof(mask), &mask, sizeof(mask));

		b0 = in[1].slli_epi64(0);
		b1 = in[1].slli_epi64(1);
		b2 = in[1].slli_epi64(2);
		b3 = in[1].slli_epi64(3);
		b4 = in[1].slli_epi64(4);
		b5 = in[1].slli_epi64(5);
		b6 = in[1].slli_epi64(6);
		b7 = in[1].slli_epi64(7);

		mask = static_cast<u16>(b0.movemask_epi8());
		memcpy(out[(x16_15 - 0) * 8].data() + i8y * sizeof(mask), &mask, sizeof(mask));
		mask = static_cast<u16>(b1.movemask_epi8());
		memcpy(out[(x16_15 - 1) * 8].data() + i8y * sizeof(mask), &mask, sizeof(mask));
		mask = static_cast<u16>(b2.movemask_epi8());
		memcpy(out[(x16_15 - 2) * 8].data() + i8y * sizeof(mask), &mask, sizeof(mask));
		mask = static_cast<u16>(b3.movemask_epi8());
		memcpy(out[(x16_15 - 3) * 8].data() + i8y * sizeof(mask), &mask, sizeof(mask));
		mask = static_cast<u16>(b4.movemask_epi8());
		memcpy(out[(x16_15 - 4) * 8].data() + i8y * sizeof(mask), &mask, sizeof(mask));
		mask = static_cast<u16>(b5.movemask_epi8());
		memcpy(out[(x16_15 - 5) * 8].data() + i8y * sizeof(mask), &mask, sizeof(mask));
		mask = static_cast<u16>(b6.movemask_epi8());
		memcpy(out[(x16_15 - 6) * 8].data() + i8y * sizeof(mask), &mask, sizeof(mask));
		mask = static_cast<u16>(b7.movemask_epi8());
		memcpy(out[(x16_15 - 7) * 8].data() + i8y * sizeof(mask), &mask, sizeof(mask));

	}


	// we have long rows of contiguous data data, 128 columns
	void sse_transpose128x1024(block* inOut)
	{
		array<block, 2> a, b;

		for (int i = 0; i < 8; ++i)
		{
			for (int j = 0; j < 8; j++)
			{
				sse_loadSubSquarex(inOut, a, j, j, i);
				sse_transposeSubSquarex(inOut, a, j, j, i);

				for (int k = 0; k < j; k++)
				{
					sse_loadSubSquarex(inOut, a, k, j, i);
					sse_loadSubSquarex(inOut, b, j, k, i);
					sse_transposeSubSquarex(inOut, a, j, k, i);
					sse_transposeSubSquarex(inOut, b, k, j, i);
				}
			}

		}


	}

#ifdef OC_ENABLE_AVX2
	// Templates are used for loop unrolling.

	// Base case for the following function.
	template<size_t blockSizeShift, size_t blockRowsShift, size_t j = 0>
	static OC_FORCEINLINE typename std::enable_if<j == (1 << blockSizeShift)>::type
		avx_transpose_block_iter1(__m256i* inOut) {}

	// Transpose the order of the 2^blockSizeShift by 2^blockSizeShift blocks (but not within each
	// block) within each 2^(blockSizeShift+1) by 2^(blockSizeShift+1) matrix in a nRows by 2^7
	// matrix. Only handles the first two rows out of every 2^blockRowsShift rows in each block,
	// starting j * 2^blockRowsShift rows into the block. When blockRowsShift == 1 this does the
	// transposes within the 2 by 2 blocks as well.
	template<size_t blockSizeShift, size_t blockRowsShift, size_t j = 0>
	static OC_FORCEINLINE typename std::enable_if<
		(j < (1 << blockSizeShift)) && (blockSizeShift > 0) && (blockSizeShift < 6) &&
		(blockRowsShift >= 1)
		>::type avx_transpose_block_iter1(__m256i* inOut)
	{
		avx_transpose_block_iter1<blockSizeShift, blockRowsShift, j + (1 << blockRowsShift)>(inOut);

		// Mask consisting of alternating 2^blockSizeShift 0s and 2^blockSizeShift 1s. Least
		// significant bit is 0.
		u64 mask = ((u64)-1) << 32;
		for (int k = 4; k >= (int)blockSizeShift; --k)
			mask = mask ^ (mask >> (1 << k));

		__m256i& x = inOut[j / 2];
		__m256i& y = inOut[j / 2 + (1 << (blockSizeShift - 1))];

		// Handle the 2x2 blocks as well. Each block is within a single 256-bit vector, so it works
		// differently from the other cases.
		if (blockSizeShift == 1)
		{
			// transpose 256 bit blocks so that two can be done in parallel.
			__m256i u = _mm256_permute2x128_si256(x, y, 0x20);
			__m256i v = _mm256_permute2x128_si256(x, y, 0x31);

			__m256i diff = _mm256_xor_si256(u, _mm256_slli_epi16(v, 1));
			diff = _mm256_and_si256(diff, _mm256_set1_epi16(0xaaaa));
			u = _mm256_xor_si256(u, diff);
			v = _mm256_xor_si256(v, _mm256_srli_epi16(diff, 1));

			// Transpose again to switch back.
			x = _mm256_permute2x128_si256(u, v, 0x20);
			y = _mm256_permute2x128_si256(u, v, 0x31);
		}

		__m256i diff = _mm256_xor_si256(x, _mm256_slli_epi64(y, (u64)1 << blockSizeShift));
		diff = _mm256_and_si256(diff, _mm256_set1_epi64x(mask));
		x = _mm256_xor_si256(x, diff);
		y = _mm256_xor_si256(y, _mm256_srli_epi64(diff, (u64)1 << blockSizeShift));
	}

	// Special case to use the unpack* instructions.
	template<size_t blockSizeShift, size_t blockRowsShift, size_t j = 0>
	static OC_FORCEINLINE typename std::enable_if<
		(j < (1 << blockSizeShift)) && (blockSizeShift == 6)
		>::type avx_transpose_block_iter1(__m256i* inOut)
	{
		avx_transpose_block_iter1<blockSizeShift, blockRowsShift, j + (1 << blockRowsShift)>(inOut);

		__m256i& x = inOut[j / 2];
		__m256i& y = inOut[j / 2 + (1 << (blockSizeShift - 1))];
		__m256i outX = _mm256_unpacklo_epi64(x, y);
		__m256i outY = _mm256_unpackhi_epi64(x, y);
		x = outX;
		y = outY;
	}

	// Base case for the following function.
	template<size_t blockSizeShift, size_t blockRowsShift, size_t nRows>
	static OC_FORCEINLINE typename std::enable_if<nRows == 0>::type
		avx_transpose_block_iter2(__m256i* inOut) {}

	// Transpose the order of the 2^blockSizeShift by 2^blockSizeShift blocks (but not within each
	// block) within each 2^(blockSizeShift+1) by 2^(blockSizeShift+1) matrix in a nRows by 2^7
	// matrix. Only handles the first two rows out of every 2^blockRowsShift rows in each block.
	// When blockRowsShift == 1 this does the transposes within the 2 by 2 blocks as well.
	template<size_t blockSizeShift, size_t blockRowsShift, size_t nRows>
	static OC_FORCEINLINE typename std::enable_if<(nRows > 0)>::type
		avx_transpose_block_iter2(__m256i* inOut)
	{
		constexpr size_t matSize = 1 << (blockSizeShift + 1);
		static_assert(nRows % matSize == 0, "Can't transpose a fractional number of matrices");

		constexpr size_t i = nRows - matSize;
		avx_transpose_block_iter2<blockSizeShift, blockRowsShift, i>(inOut);
		avx_transpose_block_iter1<blockSizeShift, blockRowsShift>(inOut + i / 2);
	}

	// Base case for the following function.
	template<size_t blockSizeShift, size_t matSizeShift, size_t blockRowsShift, size_t matRowsShift>
	static OC_FORCEINLINE typename std::enable_if<blockSizeShift == matSizeShift>::type
		avx_transpose_block(__m256i* inOut) {}

	// Transpose the order of the 2^blockSizeShift by 2^blockSizeShift blocks (but not within each
	// block) within each 2^matSizeShift by 2^matSizeShift matrix in a 2^(matSizeShift +
	// matRowsShift) by 2^7 matrix. Only handles the first two rows out of every 2^blockRowsShift
	// rows in each block. When blockRowsShift == 1 this does the transposes within the 2 by 2
	// blocks as well.
	template<size_t blockSizeShift, size_t matSizeShift, size_t blockRowsShift, size_t matRowsShift>
	static OC_FORCEINLINE typename std::enable_if<(blockSizeShift < matSizeShift)>::type
		avx_transpose_block(__m256i* inOut)
	{
		avx_transpose_block_iter2<
			blockSizeShift, blockRowsShift, (1 << (matRowsShift + matSizeShift))>(inOut);
		avx_transpose_block<blockSizeShift + 1, matSizeShift, blockRowsShift, matRowsShift>(inOut);
	}

	static constexpr size_t avxBlockShift = 4;
	static constexpr size_t avxBlockSize = 1 << avxBlockShift;

	// Base case for the following function.
	template<size_t iter = 7>
	static OC_FORCEINLINE typename std::enable_if<iter <= avxBlockShift + 1>::type
		avx_transpose(__m256i* inOut)
	{
		for (size_t i = 0; i < 64; i += avxBlockSize)
			avx_transpose_block<1, iter, 1, avxBlockShift + 1 - iter>(inOut + i);
	}

	// Algorithm roughly from "Extension of Eklundh's matrix transposition algorithm and its
	// application in digital image processing". Transpose each block of size 2^iter by 2^iter
	// inside a 2^7 by 2^7 matrix.
	template<size_t iter = 7>
	static OC_FORCEINLINE typename std::enable_if<(iter > avxBlockShift + 1)>::type
		avx_transpose(__m256i* inOut)
	{
		assert((u64)inOut % 32 == 0);
		avx_transpose<iter - avxBlockShift>(inOut);

		constexpr size_t blockSizeShift = iter - avxBlockShift;
		size_t mask = (1 << (iter - 1)) - (1 << (blockSizeShift - 1));
		if (iter == 7)
			// Simpler (but equivalent) iteration for when iter == 7, which means that it doesn't
			// need to count on both sides of the range of bits specified in mask.
			for (size_t i = 0; i < (1 << (blockSizeShift - 1)); ++i)
				avx_transpose_block<blockSizeShift, iter, blockSizeShift, 0>(inOut + i);
		else
			// Iteration trick adapted from "Hacker's Delight".
			for (size_t i = 0; i < 64; i = (i + mask + 1) & ~mask)
				avx_transpose_block<blockSizeShift, iter, blockSizeShift, 0>(inOut + i);
	}

	void avx_transpose128(block* inOut)
	{
		avx_transpose((__m256i*) inOut);
	}

	// input is 128 rows off 8 blocks each.
	void avx_transpose128x1024(block* inOut)
	{
		assert((u64)inOut % 32 == 0);
		AlignedArray<block, 128 * 8> buff;
		for (u64 i = 0; i < 8; ++i)
		{


			//AlignedArray<block, 128> sub;
			auto sub = &buff[128 * i];
			for (u64 j = 0; j < 128; ++j)
			{
				sub[j] = inOut[j * 8 + i];
			}

			//for (u64 j = 0; j < 128; ++j)
			//{
			//    buff[128 * i + j] = inOut[i + j * 8];
			//}

			avx_transpose128(&buff[128 * i]);
		}

		for (u64 i = 0; i < 8; ++i)
		{
			//AlignedArray<block, 128> sub;
			auto sub = &buff[128 * i];
			for (u64 j = 0; j < 128; ++j)
			{
				inOut[j * 8 + i] = sub[j];
			}
		}

	}
#endif
}




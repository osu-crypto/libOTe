#pragma once

#include "libOTe/Tools/Foliage/FoliageUtils.h"

namespace osuCrypto
{
    //typedef __int128 int128_t;
    //typedef unsigned __int128 uint128_t;

    // Samples a non-zero element of F4
    inline uint8_t rand_f4x(PRNG& prng)
    {
        uint8_t t = 0;
        while (t == 0)
        {
            t = prng.get<u8>() & 3;
        }
        return t;
    }

    // Multiplies two elements of F4 (optionally: 4 elements packed into uint8_t)
    // and returns the result.
    inline uint8_t mult_f4(uint8_t a, uint8_t b)
    {
        u8 tmp = ((a & 0b10) & (b & 0b10));
        uint8_t res = tmp ^ (((a & 0b10) & ((b & 0b01) << 1)) ^ (((a & 0b01) << 1) & (b & 0b10)));
        res |= ((a & 0b01) & (b & 0b01)) ^ (tmp >> 1);
        return res;
    }

    inline void f4Mult(
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
    inline void multiply_fft_8(
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
    inline void multiply_fft_16(
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
    inline void multiply_fft_32(
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
    inline void multiply_fft_64(
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



    // samples the a polynomials and axa polynomials
    inline void sample_a_and_a2(span<uint8_t> fft_a, span<uint32_t> fft_a2, size_t poly_size, size_t c, PRNG& prng)
    {
        if (c > 16)
            throw RTE_LOC;

        prng.get(fft_a.data(), poly_size);

        // make a_0 the identity polynomial (in FFT space) i.e., all 1s
        for (size_t i = 0; i < poly_size; i++)
        {
            fft_a[i] = (fft_a[i] & ~3ull) | 1;
        }

        //std::cout << "sampleA " << int(fft_a[0]) << int(fft_a[1]) << int(fft_a[2]) << int(fft_a[3]) << std::endl;

        // FOR DEBUGGING: set fft_a to the identity
        // for (size_t i = 0; i < poly_size; i++)
        // {
        //     fft_a[i] = (0xaaaa >> 1);
        // }

        uint32_t prod;
        for (size_t j = 0; j < c; j++)
        {
            for (size_t k = 0; k < c; k++)
            {
                for (size_t i = 0; i < poly_size; i++)
                {
                    auto a = (fft_a[i] >> (2 * j)) & 0b11;
                    auto b = (fft_a[i] >> (2 * k)) & 0b11;
                    auto a1 = a & 1;
                    auto a2 = a & 2;
					auto b1 = b & 1;
					auto b2 = b & 2;

                    {
                        u8 tmp = (a2 & b2);
                        prod = tmp ^ ((a2 & (b1 << 1)) ^ ((a1 << 1) & b2));
                        prod |= (a1 & b1) ^ (tmp >> 1);
                        //return res;
                    }
                    //prod = mult_f4(, );
                    size_t slot = j * c + k;
                    fft_a2[i] |= prod << (2 * slot);
                }
            }
        }
    }

}
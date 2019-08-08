/*
Copyright (C) 2017 Ming-Shing Chen

This file is part of BitPolyMul.

BitPolyMul is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

BitPolyMul is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with BitPolyMul.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "libOTe/config.h"
#ifdef ENABLE_BITPOLYMUL


#include <stdint.h>

#include "gfext_aesni.h"

#include "bitmat_prod.h"

#include "byte_inline_func.h"

#include "string.h"





/////////////////////////////////////////////////
///
/// truncated FFT,  7 layers
///
//////////////////////////////////////////////////////

#include "trunc_btfy_tab.h"
#include "trunc_btfy_tab_64.h"

#include "transpose.h"

namespace bpm {

    static inline
        void bit_bc_64x2_div(__m256i* x)
    {
        for (unsigned i = 0; i < 64; i++) x[64 + i] = _mm256_srli_si256(x[i], 8);
        for (int i = 64 - 1; i >= 0; i--) {
            x[1 + i] = xor256(x[1 + i], x[64 + i]);
            x[4 + i] = xor256(x[4 + i], x[64 + i]);
            x[16 + i] = xor256(x[16 + i], x[64 + i]);
        }
        for (unsigned i = 0; i < 64; i++) x[i] = _mm256_unpacklo_epi64(x[i], x[64 + i]);

        for (unsigned i = 0; i < 64; i += 64) {
            __m256i* pi = x + i;
            for (int j = 32 - 1; j >= 0; j--) {
                pi[1 + j] = xor256(pi[1 + j], pi[32 + j]);
                pi[2 + j] = xor256(pi[2 + j], pi[32 + j]);
                pi[16 + j] = xor256(pi[16 + j], pi[32 + j]);
            }
        }
        for (unsigned i = 0; i < 64; i += 32) {
            __m256i* pi = x + i;
            for (int j = 16 - 1; j >= 0; j--) {
                pi[1 + j] = xor256(pi[1 + j], pi[16 + j]);
            }
        }
        for (unsigned i = 0; i < 64; i += 16) {
            __m256i* pi = x + i;
            for (int j = 8 - 1; j >= 0; j--) {
                pi[1 + j] = xor256(pi[1 + j], pi[8 + j]);
                pi[2 + j] = xor256(pi[2 + j], pi[8 + j]);
                pi[4 + j] = xor256(pi[4 + j], pi[8 + j]);
            }
        }
        for (unsigned i = 0; i < 64; i += 8) {
            __m256i* pi = x + i;
            pi[4] = xor256(pi[4], pi[7]);
            pi[3] = xor256(pi[3], pi[6]);
            pi[2] = xor256(pi[2], pi[5]);
            pi[1] = xor256(pi[1], pi[4]);
        }

        for (unsigned i = 0; i < 64; i += 4) {
            __m256i* pi = x + i;
            pi[2] = xor256(pi[2], pi[3]);
            pi[1] = xor256(pi[1], pi[2]);
        }

    }



    void encode_128_half_input_zero(uint64_t* rfx, const uint64_t* fx, unsigned n_fx_128b)
    {
        if (128 * 2 > n_fx_128b) { printf("unsupported number of terms.\n"); exit(-1); }

        __m256i temp[128];
        __m128i* temp128 = (__m128i*) temp;
        uint64_t* temp64 = (uint64_t*)temp;
        const __m256i* fx_256 = (const __m256i*) fx;
        __m128i* rfx_128 = (__m128i*) rfx;
        unsigned n_fx_256b = n_fx_128b / 2;
        unsigned num = n_fx_256b / 128;
        __m256i t2[128];
        __m128i* t2_128 = (__m128i*) t2;

        for (unsigned i = 0; i < num; i++) {
            for (unsigned j = 0; j < 64; j++) {
                temp[j] = fx_256[i + j * num];
                temp[j] = div_s7(temp[j]);
            }

            tr_bit_64x64_b4_avx2((uint8_t*)(temp128), (const uint8_t*)temp);
            bit_bc_64x2_div(temp);
            // truncated FFT
            for (unsigned j = 0; j < 8; j++) {
                bitmatrix_prod_64x128_4R_b32_opt_avx2((uint8_t*)(&t2_128[32 * j]), beta_mul_64_bm4r_ext_8, (const uint8_t*)(&temp64[32 * j]));
            }
            for (unsigned k = 0; k < 8; k++) for (unsigned j = 0; j < 8; j++) rfx_128[i * 256 + k * 8 + j] = t2_128[k * 32 + j * 2];
            for (unsigned k = 0; k < 8; k++) for (unsigned j = 0; j < 8; j++) rfx_128[i * 256 + 64 + k * 8 + j] = t2_128[k * 32 + 16 + j * 2];
            for (unsigned k = 0; k < 8; k++) for (unsigned j = 0; j < 8; j++) rfx_128[i * 256 + 128 + k * 8 + j] = t2_128[k * 32 + j * 2 + 1];
            for (unsigned k = 0; k < 8; k++) for (unsigned j = 0; j < 8; j++) rfx_128[i * 256 + 128 + 64 + k * 8 + j] = t2_128[k * 32 + 16 + j * 2 + 1];
        }
    }

#if 1
    static inline
        void bit_bc_div(__m256i * x)
    {
        /// div s6 = x^64 + x^16 + x^4 + x
        for (int i = 64 - 1; i >= 0; i--) {
            x[1 + i] = xor256(x[1 + i], x[64 + i]);
            x[4 + i] = xor256(x[4 + i], x[64 + i]);
            x[16 + i] = xor256(x[16 + i], x[64 + i]);
        }
        /// div s5 = s^32 + x^16 + x^2 + x
        for (unsigned i = 0; i < 128; i += 64) {
            __m256i* pi = x + i;
            for (int j = 32 - 1; j >= 0; j--) {
                pi[1 + j] = xor256(pi[1 + j], pi[32 + j]);
                pi[2 + j] = xor256(pi[2 + j], pi[32 + j]);
                pi[16 + j] = xor256(pi[16 + j], pi[32 + j]);
            }
        }
        /// div s4 = x^16 + x
        for (unsigned i = 0; i < 128; i += 32) {
            __m256i* pi = x + i;
            for (int j = 16 - 1; j >= 0; j--) {
                pi[1 + j] = xor256(pi[1 + j], pi[16 + j]);
            }
        }
        /// div s3 = x^8 + x^4 + x^2 + x
        for (unsigned i = 0; i < 128; i += 16) {
            __m256i* pi = x + i;
            for (int j = 8 - 1; j >= 0; j--) {
                pi[1 + j] = xor256(pi[1 + j], pi[8 + j]);
                pi[2 + j] = xor256(pi[2 + j], pi[8 + j]);
                pi[4 + j] = xor256(pi[4 + j], pi[8 + j]);
            }
        }
        /// div s2 = x^4 + x
        for (unsigned i = 0; i < 128; i += 8) {
            __m256i* pi = x + i;
            pi[4] = xor256(pi[4], pi[7]);
            pi[3] = xor256(pi[3], pi[6]);
            pi[2] = xor256(pi[2], pi[5]);
            pi[1] = xor256(pi[1], pi[4]);
        }
        /// div s1 = x^2 + x
        for (unsigned i = 0; i < 128; i += 4) {
            __m256i* pi = x + i;
            pi[2] = xor256(pi[2], pi[3]);
            pi[1] = xor256(pi[1], pi[2]);
        }
    }
#else
    static inline
        void bit_bc_div(__m256i* x)
    {
        /// var substitue s4^4 = x^64 + x^4
        for (int i = 64; i--;) x[4 + i] ^= x[64 + i];
        /// var substitue s4^2 = x32 + x^2
        for (int i = 32; i--;) x[2 + i] ^= x[32 + i];
        /// var substitue s4 = x16 + x
        for (int i = 16; i--;) x[1 + i] ^= x[16 + i];
        for (int i = 16; i--;) x[1 + 32 + i] ^= x[16 + 32 + i];

        for (int i = 32; i--;) x[2 + 64 + i] ^= x[32 + 64 + i];
        /// var substitue s4 = x16 + x
        for (int i = 16; i--;) x[1 + 64 + i] ^= x[16 + 64 + i];
        for (int i = 16; i--;) x[1 + 96 + i] ^= x[16 + 96 + i];

        /// 8 blocks, 16 elements per block
        for (unsigned i = 0; i < 16; i++) {
            /// div s6 = x^64 + x^16 + x^4 + x = s4^4 + s4
            x[4 * 16 + i] ^= x[7 * 16 + i];
            x[3 * 16 + i] ^= x[6 * 16 + i];
            x[2 * 16 + i] ^= x[5 * 16 + i];
            x[1 * 16 + i] ^= x[4 * 16 + i];
            /// div s5 = x^32 + x^16 + x^2 + x = s4^2 + s4
            x[6 * 16 + i] ^= x[7 * 16 + i];
            x[2 * 16 + i] ^= x[3 * 16 + i];
            x[5 * 16 + i] ^= x[6 * 16 + i];
            x[1 * 16 + i] ^= x[2 * 16 + i];
        }
        for (unsigned k = 0; k < 16; k++) {
            __m256i* f = &x[k * 16];
            f[9] ^= f[15];
            f[8] ^= f[14];
            f[7] ^= f[13];
            f[6] ^= f[12];
            f[5] ^= f[11];
            f[4] ^= f[10];
            f[3] ^= f[9];
            f[2] ^= f[8];

            f[12] ^= f[15];
            f[11] ^= f[14];
            f[4] ^= f[7];
            f[3] ^= f[6];

            f[10] ^= f[13];
            f[9] ^= f[12];
            f[2] ^= f[5];
            f[1] ^= f[4];

            f[11] ^= f[15];
            f[10] ^= f[14];
            f[9] ^= f[13];
            f[8] ^= f[12];
            f[7] ^= f[11];
            f[6] ^= f[10];
            f[5] ^= f[9];
            f[4] ^= f[8];

            f[14] ^= f[15];
            f[10] ^= f[11];
            f[6] ^= f[7];
            f[2] ^= f[3];

            f[13] ^= f[14];
            f[9] ^= f[10];
            f[5] ^= f[6];
            f[1] ^= f[2];
        }
    }
#endif

    void encode_128(uint64_t* rfx, const uint64_t* fx, unsigned n_fx_128b)
    {
        if (128 * 2 > n_fx_128b) { printf("unsupported number of terms.\n"); exit(-1); }

        __m256i temp[128];
        __m128i* temp128 = (__m128i*) temp;
        const __m256i* fx_256 = (const __m256i*) fx;
        __m128i* rfx_128 = (__m128i*) rfx;
        unsigned n_fx_256b = n_fx_128b / 2;
        unsigned num = n_fx_256b / 128;

        for (unsigned i = 0; i < num; i++) {
            for (unsigned j = 0; j < 128; j++) {
                temp[j] = fx_256[i + j * num];
                temp[j] = div_s7(temp[j]);
            }

            tr_bit_128x128_b2_avx2((uint8_t*)(temp128), (const uint8_t*)temp);
            bit_bc_div(temp);
            // truncated FFT
            for (unsigned j = 0; j < 8; j++) {
                bitmatrix_prod_128x128_4R_b32_opt_avx2((uint8_t*)(temp + 16 * j), beta_mul_64_bm4r_ext_8, (const uint8_t*)(temp + 16 * j));
            }
            for (unsigned j = 0; j < 128; j++) rfx_128[i * 256 + j] = temp128[j * 2];
            for (unsigned j = 0; j < 128; j++) rfx_128[i * 256 + 128 + j] = temp128[j * 2 + 1];
        }
    }



    static inline
        void bit_bc_exp(__m256i* x)
    {
        for (unsigned i = 0; i < 128; i += 4) {
            __m256i* pi = x + i;
            pi[1] = xor256(pi[1], pi[2]);
            pi[2] = xor256(pi[2], pi[3]);
        }
        for (unsigned i = 0; i < 128; i += 8) {
            __m256i* pi = x + i;
            pi[1] = xor256(pi[1], pi[4]);
            pi[2] = xor256(pi[2], pi[5]);
            pi[3] = xor256(pi[3], pi[6]);
            pi[4] = xor256(pi[4], pi[7]);
        }
        for (unsigned i = 0; i < 128; i += 16) {
            __m256i* pi = x + i;
            for (unsigned j = 0; j < 8; j++) {
                pi[1 + j] = xor256(pi[1 + j], pi[8 + j]);
                pi[2 + j] = xor256(pi[2 + j], pi[8 + j]);
                pi[4 + j] = xor256(pi[4 + j], pi[8 + j]);
            }
        }
        for (unsigned i = 0; i < 128; i += 32) {
            __m256i* pi = x + i;
            for (unsigned j = 0; j < 16; j++) {
                pi[1 + j] = xor256(pi[1 + j], pi[16 + j]);
            }
        }
        for (unsigned i = 0; i < 128; i += 64) {
            __m256i* pi = x + i;
            for (unsigned j = 0; j < 32; j++) {
                pi[1 + j] = xor256(pi[1 + j], pi[32 + j]);
                pi[2 + j] = xor256(pi[2 + j], pi[32 + j]);
                pi[16 + j] = xor256(pi[16 + j], pi[32 + j]);
            }
        }
        for (unsigned i = 0; i < 64; i++) {
            x[1 + i] = xor256(x[1 + i], x[64 + i]);
            x[4 + i] = xor256(x[4 + i], x[64 + i]);
            x[16 + i] = xor256(x[16 + i], x[64 + i]);
        }
    }


    void decode_128(uint64_t* rfx, const uint64_t* fx, unsigned n_fx_128b)
    {
        if (128 * 2 > n_fx_128b) { printf("unsupported number of terms.\n"); exit(-1); }

        const __m128i* fx_128 = (__m128i*) fx;
        __m256i* rfx_256 = (__m256i*) rfx;
        if (uint64_t(rfx_256) % 32)
        {
            std::cout << "Error (Bitpolymul) pointer need to be 32 bit aligned. " LOCATION << std::endl;
            throw RTE_LOC;
        }

        unsigned n_fx_256b = n_fx_128b / 2;
        unsigned num = n_fx_256b / 128;
        __m256i temp[128];
        __m128i* temp128 = (__m128i*) temp;

        for (unsigned i = 0; i < num; i++) {
            /// truncated iFFT here.
            for (unsigned j = 0; j < 128; j++) {
                temp128[j * 2] = fx_128[i * 256 + j];
                temp128[j * 2 + 1] = fx_128[i * 256 + 128 + j];
            }

            for (unsigned j = 0; j < 8; j++) {
                bitmatrix_prod_128x128_4R_b32_opt_avx2((uint8_t*)(temp + 16 * j), i_beta_mul_64_bm4r_ext_8, (const uint8_t*)(temp + 16 * j));
            }

            bit_bc_exp(temp);

            tr_bit_128x128_b2_avx2((uint8_t*)temp, (const uint8_t*)temp128);

            for (unsigned j = 0; j < 128; j++) {
                temp[j] = exp_s7(temp[j]);
                rfx_256[i + j * num] = temp[j];
            }
        }
    }



    ///////////////////////////////////////




    static inline
        void bit_bc_64x2_exp(__m256i* x)
    {
        for (unsigned i = 0; i < 64; i += 4) {
            __m256i* pi = x + i;
            pi[1] = xor256(pi[1], pi[2]);
            pi[2] = xor256(pi[2], pi[3]);
        }
        for (unsigned i = 0; i < 64; i += 8) {
            __m256i* pi = x + i;
            pi[1] = xor256(pi[1], pi[4]);
            pi[2] = xor256(pi[2], pi[5]);
            pi[3] = xor256(pi[3], pi[6]);
            pi[4] = xor256(pi[4], pi[7]);
        }
        for (unsigned i = 0; i < 64; i += 16) {
            __m256i* pi = x + i;
            for (unsigned j = 0; j < 8; j++) {
                pi[1 + j] = xor256(pi[1 + j], pi[8 + j]);
                pi[2 + j] = xor256(pi[2 + j], pi[8 + j]);
                pi[4 + j] = xor256(pi[4 + j], pi[8 + j]);
            }
        }
        for (unsigned i = 0; i < 64; i += 32) {
            __m256i* pi = x + i;
            for (unsigned j = 0; j < 16; j++) {
                pi[1 + j] = xor256(pi[1 + j], pi[16 + j]);
            }
        }
        for (unsigned i = 0; i < 64; i += 64) {
            __m256i* pi = x + i;
            for (unsigned j = 0; j < 32; j++) {
                pi[1 + j] = xor256(pi[1 + j], pi[32 + j]);
                pi[2 + j] = xor256(pi[2 + j], pi[32 + j]);
                pi[16 + j] = xor256(pi[16 + j], pi[32 + j]);
            }
        }

        for (unsigned i = 0; i < 64; i++) x[64 + i] = _mm256_srli_si256(x[i], 8);
        for (unsigned i = 0; i < 64; i++) {
            x[1 + i] = xor256(x[1 + i], x[64 + i]);
            x[4 + i] = xor256(x[4 + i], x[64 + i]);
            x[16 + i] = xor256(x[16 + i], x[64 + i]);
        }
        for (unsigned i = 0; i < 64; i++) x[i] = _mm256_unpacklo_epi64(x[i], x[64 + i]);

    }






    void encode_64_half_input_zero(uint64_t* rfx, const uint64_t* fx, unsigned n_fx) /// XXX: further optimization.
    {
        if (64 * 4 > n_fx) { printf("unsupported number of terms.\n"); exit(-1); }

        __m256i temp[128];
        uint64_t* temp64 = (uint64_t*)temp;
        const __m256i* fx_256 = (const __m256i*) fx;
        unsigned n_fx_256b = n_fx >> 2;
        unsigned num = n_fx_256b / 64;

        for (unsigned i = 0; i < num; i++) {
            for (unsigned j = 0; j < 32; j++) {
                temp[j] = fx_256[i + j * num];
                temp[j] = div_s7(temp[j]);
            }
            for (unsigned j = 32; j < 64; j++) temp[j] = _mm256_setzero_si256();

            tr_bit_64x64_b4_avx2((uint8_t*)(temp), (const uint8_t*)temp);

            bit_bc_64x2_div(temp);

            // truncated FFT
            //for(unsigned j=0;j<256;j++) temp64[j] = bitmatrix_prod_64x64_M4R( beta_mul_32_m4r , temp64[j] );
#if 0
            for (unsigned j = 0; j < (64 * 4 / 32); j++) bitmatrix_prod_64x64_h32zero_4R_b32_avx2((uint8_t*)(&temp64[32 * j]), beta_mul_32_bm4r, (uint8_t*)(&temp64[32 * j]));
#else
            for (unsigned j = 0; j < (64 * 4 / 64); j++) bitmatrix_prod_64x64_h32zero_4R_b64_avx2((uint8_t*)(&temp64[64 * j]), beta_mul_32_bm4r, (uint8_t*)(&temp64[64 * j]));
#endif

            for (unsigned j = 0; j < 64; j++) rfx[i * 256 + j] = temp64[j * 4];
            for (unsigned j = 0; j < 64; j++) rfx[i * 256 + 64 + j] = temp64[j * 4 + 1];
            for (unsigned j = 0; j < 64; j++) rfx[i * 256 + 128 + j] = temp64[j * 4 + 2];
            for (unsigned j = 0; j < 64; j++) rfx[i * 256 + 192 + j] = temp64[j * 4 + 3];

        }
    }




    void encode_64(uint64_t* rfx, const uint64_t* fx, unsigned n_fx)
    {
        if (64 * 4 > n_fx) { printf("unsupported number of terms.\n"); exit(-1); }

        __m256i temp[128];
        uint64_t* temp64 = (uint64_t*)temp;
        const __m256i* fx_256 = (const __m256i*) fx;
        unsigned n_fx_256b = n_fx >> 2;
        unsigned num = n_fx_256b / 64;

        for (unsigned i = 0; i < num; i++) {
            for (unsigned j = 0; j < 64; j++) {
                temp[j] = fx_256[i + j * num];
                temp[j] = div_s7(temp[j]);
            }

            tr_bit_64x64_b4_avx2((uint8_t*)(temp), (const uint8_t*)temp);

            bit_bc_64x2_div(temp);

            // truncated FFT
            //for(unsigned j=0;j<256;j++) temp64[j] = bitmatrix_prod_64x64_M4R( beta_mul_32_m4r , temp64[j] );
            for (unsigned j = 0; j < (64 * 4 / 32); j++) bitmatrix_prod_64x64_4R_b32_avx2((uint8_t*)(&temp64[32 * j]), beta_mul_32_bm4r, (uint8_t*)(&temp64[32 * j]));
            for (unsigned j = 0; j < 64; j++) rfx[i * 256 + j] = temp64[j * 4];
            for (unsigned j = 0; j < 64; j++) rfx[i * 256 + 64 + j] = temp64[j * 4 + 1];
            for (unsigned j = 0; j < 64; j++) rfx[i * 256 + 128 + j] = temp64[j * 4 + 2];
            for (unsigned j = 0; j < 64; j++) rfx[i * 256 + 192 + j] = temp64[j * 4 + 3];
        }
    }



    void decode_64(uint64_t* rfx, const uint64_t* fx, unsigned n_fx)
    {
        if (64 * 4 > n_fx) { printf("unsupported number of terms.\n"); exit(-1); }

        __m256i temp[128];
        uint64_t* temp64 = (uint64_t*)temp;

        __m256i* rfx_256 = (__m256i*) rfx;
        unsigned n_fx_256b = n_fx >> 2;
        unsigned num = n_fx_256b / 64;

        for (unsigned i = 0; i < num; i++) {
            /// truncated iFFT here.
            for (unsigned j = 0; j < 64; j++) {
                temp64[j * 4] = fx[i * 256 + j];
                temp64[j * 4 + 1] = fx[i * 256 + 64 + j];
                temp64[j * 4 + 2] = fx[i * 256 + 128 + j];
                temp64[j * 4 + 3] = fx[i * 256 + 192 + j];
            }
            // truncated iFFT
            //for(unsigned j=0;j<64*4;j++) temp64[j] = bitmatrix_prod_64x64_M4R( i_beta_mul_32_m4r , temp64[j] );
#if 0
            for (unsigned j = 0; j < (64 * 4 / 32); j++) bitmatrix_prod_64x64_4R_b32_avx2((uint8_t*)(&temp64[32 * j]), i_beta_mul_32_bm4r, (uint8_t*)(&temp64[32 * j]));
#else
            for (unsigned j = 0; j < (64 * 4 / 64); j++) bitmatrix_prod_64x64_4R_b64_avx2((uint8_t*)(&temp64[64 * j]), i_beta_mul_32_bm4r, (uint8_t*)(&temp64[64 * j]));
#endif
            bit_bc_64x2_exp(temp);

            tr_bit_64x64_b4_avx2((uint8_t*)(temp), (const uint8_t*)temp);

            for (unsigned j = 0; j < 64; j++) {
                temp[j] = exp_s7(temp[j]);
#if 0
                _mm256_stream_si256(&rfx_256[i + j * num], temp[j]);
#elif 1
                _mm256_store_si256(&rfx_256[i + j * num], temp[j]);
#else
                rfx_256[i + j * num] = temp[j];
#endif
            }
        }
    }
}
#endif


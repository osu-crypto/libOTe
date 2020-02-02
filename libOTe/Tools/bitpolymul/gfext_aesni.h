#pragma once
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
#ifdef ENABLE_SILENTOT


#include <stdint.h>
#include <immintrin.h>
#include "bpmDefines.h"

namespace bpm {
//
//    /// X^64 + X^4 + X^3 + X + 1
//    /// 0x1b
    alignas(32) const uint64_t _gf2ext64_reducer[4] = { 0x415A776C2D361B00ULL,0x1bULL,0x415A776C2D361B00ULL,0x1bULL };

     inline
        __m128i _gf2ext64_reduce_sse(__m128i x0)
    {
        __m128i reducer = _mm_load_si128((__m128i const*)_gf2ext64_reducer);
        //__m128i *reducer = (__m128i *)_gf2ext128_reducer;
        __m128i r0 = _mm_clmulepi64_si128(x0, reducer, 0x11);
        __m128i r1 = _mm_shuffle_epi8(reducer, r0);
        __m128i r2 = _mm_xor_si128(x0, r0);
        r1 = _mm_xor_si128(r1, _mm_slli_si128(r2, 8));
        return _mm_srli_si128(r1, 8);
    }


     inline
        __m128i _gf2ext64_reduce_x2_sse(__m128i x0, __m128i y0)
    {
        __m128i reducer = _mm_load_si128((__m128i const*)_gf2ext64_reducer);
        //__m128i *reducer = (__m128i *)_gf2ext128_reducer;
        __m128i r0 = _mm_clmulepi64_si128(x0, reducer, 0x11);
        __m128i s0 = _mm_clmulepi64_si128(y0, reducer, 0x11);
        __m128i r2 = _mm_xor_si128(x0, r0);
        __m128i s2 = _mm_xor_si128(y0, s0);
        __m128i pr = _mm_unpacklo_epi64(r2, s2);

        __m128i rr = _mm_unpackhi_epi64(r0, s0);
        __m128i rr2 = _mm_shuffle_epi8(reducer, rr);

        return _mm_xor_si128(pr, rr2);
    }
//
     inline
        __m256i _gf2ext64_reduce_x4_avx2(__m128i w0, __m128i x0, __m128i y0, __m128i z0)
    {
        __m256i reducer2 = _mm256_load_si256((__m256i const*)_gf2ext64_reducer);
        //__m128i *reducer = (__m128i *)_gf2ext128_reducer;
        __m128i reducer = _mm256_castsi256_si128(reducer2);
        __m128i r0 = _mm_clmulepi64_si128(w0, reducer, 0x11);
        __m128i s0 = _mm_clmulepi64_si128(x0, reducer, 0x11);
        __m128i t0 = _mm_clmulepi64_si128(y0, reducer, 0x11);
        __m128i u0 = _mm_clmulepi64_si128(z0, reducer, 0x11);
        __m128i r2 = _mm_xor_si128(w0, r0);
        __m128i s2 = _mm_xor_si128(x0, s0);
        __m128i t2 = _mm_xor_si128(y0, t0);
        __m128i u2 = _mm_xor_si128(z0, u0);
        __m256i pr1 = _mm256_castsi128_si256(_mm_unpacklo_epi64(r2, s2));
        __m256i pr2 = _mm256_inserti128_si256(pr1, _mm_unpacklo_epi64(t2, u2), 1);

        __m256i rr1 = _mm256_castsi128_si256(_mm_unpackhi_epi64(r0, s0));
        __m256i rr2 = _mm256_inserti128_si256(rr1, _mm_unpackhi_epi64(t0, u0), 1);
        return _mm256_xor_si256(pr2, _mm256_shuffle_epi8(reducer2, rr2));
    }

//
     inline
        __m128i _gf2ext64_mul_hi_sse(__m128i a0, __m128i b0)
    {
        __m128i c0 = _mm_clmulepi64_si128(a0, b0, 1);
        __m128i c3 = _gf2ext64_reduce_sse(c0);
        return c3;
    }

     inline
        __m128i _gf2ext64_mul_2x1_sse(__m128i a0a1, __m128i b0)
    {
        __m128i c0 = _mm_clmulepi64_si128(a0a1, b0, 0);
        __m128i c1 = _mm_clmulepi64_si128(a0a1, b0, 1);
        __m128i c3 = _gf2ext64_reduce_x2_sse(c0, c1);
        return c3;
    }

     inline
        __m256i _gf2ext64_mul_4x1_avx2(__m256i a, __m128i b0)
    {
        __m128i al = _mm256_castsi256_si128(a);
        __m128i c0 = _mm_clmulepi64_si128(al, b0, 0);
        __m128i c1 = _mm_clmulepi64_si128(al, b0, 1);
        __m128i ah = _mm256_extracti128_si256(a, 1);
        __m128i c2 = _mm_clmulepi64_si128(ah, b0, 0);
        __m128i c3 = _mm_clmulepi64_si128(ah, b0, 1);

        return _gf2ext64_reduce_x4_avx2(c0, c1, c2, c3);
    }


     inline
        __m256i _gf2ext64_mul_4x4_avx2(__m256i a, __m256i b)
    {
        __m128i al = _mm256_castsi256_si128(a);
        __m128i bl = _mm256_castsi256_si128(b);
        __m128i c0 = _mm_clmulepi64_si128(al, bl, 0);
        __m128i c1 = _mm_clmulepi64_si128(al, bl, 0x11);
        __m128i ah = _mm256_extracti128_si256(a, 1);
        __m128i bh = _mm256_extracti128_si256(b, 1);
        __m128i c2 = _mm_clmulepi64_si128(ah, bh, 0);
        __m128i c3 = _mm_clmulepi64_si128(ah, bh, 0x11);

        return _gf2ext64_reduce_x4_avx2(c0, c1, c2, c3);
    }


     inline
        void gf2ext64_mul_4x4_avx2(uint8_t* c, const uint8_t* a, const uint8_t* b)
    {
        __m256i as = _mm256_load_si256((__m256i const*)a);
        __m256i bs = _mm256_load_si256((__m256i const*)b);
        __m256i cs = _gf2ext64_mul_4x4_avx2(as, bs);

        _mm256_store_si256((__m256i*) c, cs);
    }



//

    /////////////////////////////////////////////


    /// X^128 + X^7 + X^2 + X + 1
    /// 0x       8       7
    alignas(32) const uint64_t _gf2ext128_reducer[2] = { 0x87ULL,0x0ULL };

    //USED;
     inline
        __m128i _gf2ext128_reduce_sse(__m128i x0, __m128i x128)
    {
        __m128i reducer = _mm_load_si128((__m128i const*)_gf2ext128_reducer);
        //__m128i *reducer = (__m128i *)_gf2ext128_reducer;
        __m128i x64 = _mm_clmulepi64_si128(x128, reducer, 1);  /// 0_32 , xx2_32 , xx1 , xx0
        x128 = _mm_xor_si128(x128, _mm_shuffle_epi32(x64, 0xfe)); // 0,0,0,xx2 ; 0xfe --> 3,3,3,2
        x0 = _mm_xor_si128(x0, _mm_shuffle_epi32(x64, 0x4f)); // xx1 , xx0 , 0 , 0   ;  0x4f -->  1,0,3,3  --> xx1,xx0,0,0
        x0 = _mm_xor_si128(x0, _mm_clmulepi64_si128(x128, reducer, 0));
        return x0;
    }


#define _MUL_128_KARATSUBA( c0,c1,a0,b0 ) \
do {\
  c0 = _mm_clmulepi64_si128( a0,b0 , 0x00 ); \
  c1 = _mm_clmulepi64_si128( a0,b0 , 0x11 ); \
  __m128i _tt0 = _mm_xor_si128(a0, _mm_srli_si128(a0,8)); \
  __m128i _tt1 = _mm_xor_si128(b0,_mm_srli_si128(b0,8)); \
  __m128i _tt2 = _mm_xor_si128(_mm_xor_si128(_mm_clmulepi64_si128( _tt0, _tt1 , 0 ),c0),c1); \
  c0 = _mm_xor_si128(c0, _mm_slli_si128( _tt2 , 8 )); \
  c1 = _mm_xor_si128(c1,_mm_srli_si128( _tt2 , 8 )); \
} while(0)


    //USED;
     inline
        void gf2ext128_mul_sse(uint8_t* c, const uint8_t* a, const uint8_t* b)
    {
        __m128i a0 = _mm_load_si128((__m128i const*)a);
        __m128i b0 = _mm_load_si128((__m128i const*)b);
        __m128i c0, c128;
        _MUL_128_KARATSUBA(c0, c128, a0, b0);

        __m128i c3 = _gf2ext128_reduce_sse(c0, c128);
        //__m128i c3 = _gf_aesgcm_reduce_sse( c0 , c128 );
        _mm_store_si128((__m128i*) c, c3);
    }


     inline
        __m128i _gf2ext128_mul_sse(__m128i a0, __m128i b0)
    {
        __m128i c0, c128;
        _MUL_128_KARATSUBA(c0, c128, a0, b0);
        __m128i c3 = _gf2ext128_reduce_sse(c0, c128);
        return c3;
    }


     inline
        __m256i _gf2ext128_mul_2x1_avx2(__m256i a0a1, __m128i b0)
    {
        __m128i a0 = _mm256_castsi256_si128(a0a1);
        __m128i a1 = _mm256_extracti128_si256(a0a1, 1);

        __m128i c0, c128;
        __m128i d0, d128;
        _MUL_128_KARATSUBA(c0, c128, a0, b0);
        _MUL_128_KARATSUBA(d0, d128, a1, b0);
        __m128i c3 = _gf2ext128_reduce_sse(c0, c128);
        __m128i d3 = _gf2ext128_reduce_sse(d0, d128);

        __m256i r = _mm256_castsi128_si256(c3);

        return _mm256_inserti128_si256(r, d3, 1);
    }



    //////////////////////////////////////////////////////////////////////////////////////


    //// s7 = x^64 + x^32 + x16 + x8 + x4 + x2 + x


    alignas(32) const uint64_t _s7[2] = { 0x100010116ULL,0x1ULL };

     inline
        __m256i div_s7(__m256i a)
    {
        __m128i r_s7 = _mm_load_si128((__m128i const*)_s7);
        __m128i a1 = _mm256_extracti128_si256(a, 1);
        __m128i a0 = _mm256_castsi256_si128(a);

        __m128i a1h_s7 = _mm_clmulepi64_si128(a1, r_s7, 1);
        a1 = _mm_xor_si128(a1, _mm_srli_si128(_mm_xor_si128(a1, a1h_s7), 8));
        a0 = _mm_xor_si128(a0, _mm_slli_si128(a1h_s7, 8));

        a0 = _mm_xor_si128(a0, _mm_slli_si128(a1, 8));
        a0 = _mm_xor_si128(a0, _mm_clmulepi64_si128(a1, r_s7, 0));

        __m256i r = _mm256_castsi128_si256(a0);
        return _mm256_inserti128_si256(r, a1, 1);
    }


    //USED;
     inline
        __m256i exp_s7(__m256i a)
    {
        __m128i r_s7 = _mm_load_si128((__m128i const*)_s7);
        __m128i a1 = _mm256_extracti128_si256(a, 1);
        __m128i a0 = _mm256_castsi256_si128(a);

        a0 = _mm_xor_si128(a0, _mm_clmulepi64_si128(a1, r_s7, 0));
        a0 = _mm_xor_si128(a0, _mm_slli_si128(a1, 8));
        __m128i a1h_s7 = _mm_clmulepi64_si128(a1, r_s7, 1);
        a0 = _mm_xor_si128(a0, _mm_slli_si128(a1h_s7, 8));
        a1 = _mm_xor_si128(a1, _mm_srli_si128(_mm_xor_si128(a1, a1h_s7), 8));

        __m256i r = _mm256_castsi128_si256(a0);
        return _mm256_inserti128_si256(r, a1, 1);
    }

}
#endif


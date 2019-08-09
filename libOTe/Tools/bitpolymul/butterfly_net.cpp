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

#include "bpmDefines.h"

/////////////////////////////////////////////////
///
/// pclmulqdq version
///
//////////////////////////////////////////////////////

#include "gf2128_cantor_iso.h"

#include "ska.h"

namespace bpm {

    //static
    //    void butterfly_0(__m128i* poly, unsigned unit)
    //{
    //    unsigned unit_2 = unit / 2;
    //    for (unsigned i = 0; i < unit_2; i++) {
    //        poly[unit_2 + i] = xor128(poly[unit_2 + i], poly[i]);
    //    }
    //}


    //static
    //    void butterfly(__m128i* poly, unsigned unit, unsigned ska)
    //{
    //    uint8_t ska_iso[16] BIT_POLY_ALIGN(32);
    //    bitmatrix_prod_64x128_8R_sse(ska_iso, gfCantorto2128_8R, ska);
    //    //__m128i a = _mm_load_si128( (__m128i*) ska_iso );

    //    unsigned unit_2 = unit / 2;
    //    for (unsigned i = 0; i < unit_2; i++) {
    //        __m128i r;
    //        gf2ext128_mul_sse((uint8_t*)& r, (uint8_t*)& poly[unit_2 + i], ska_iso);
    //        poly[i] = xor128(poly[i], r);
    //        poly[unit_2 + i] = xor128(poly[unit_2 + i], poly[i]);
    //    }

    //}


    //static
    //    void i_butterfly(__m128i* poly, unsigned unit, unsigned ska)
    //{
    //    uint8_t ska_iso[16] BIT_POLY_ALIGN(32);
    //    bitmatrix_prod_64x128_8R_sse(ska_iso, gfCantorto2128_8R, ska);
    //    //__m128i a = _mm_load_si128( (__m128i*) ska_iso );

    //    unsigned unit_2 = unit / 2;
    //    for (unsigned i = 0; i < unit_2; i++) {
    //        poly[unit_2 + i] = xor128(poly[unit_2 + i], poly[i]);
    //        __m128i r;
    //        gf2ext128_mul_sse((uint8_t*)& r, (uint8_t*)& poly[unit_2 + i], ska_iso);
    //        poly[i] = xor128(poly[i], r);
    //    }

    //}


    ///////////////////////////////////////////////////////



    //void butterfly_net_half_inp_clmul(uint64_t* fx, unsigned n_fx)
    //{
    //    if (1 >= n_fx) return;

    //    unsigned log_n = __builtin_ctz(n_fx);

    //    unsigned n_terms = n_fx;

    //    __m128i* poly = (__m128i*) & fx[0];

    //    /// first layer
    //    memcpy(poly + (n_terms / 2), poly, 8 * n_terms);

    //    for (unsigned i = log_n - 1; i > 0; i--) {
    //        unsigned unit = (1 << i);
    //        unsigned num = n_terms / unit;

    //        butterfly_0(poly, unit);
    //        for (unsigned j = 1; j < num; j++) {
    //            butterfly(poly + j * unit, unit, get_s_k_a_cantor(i - 1, j * unit));
    //        }
    //    }
    //}



    //void i_butterfly_net_clmul(uint64_t* fx, unsigned n_fx)
    //{
    //    if (1 >= n_fx) return;

    //    unsigned log_n = __builtin_ctz(n_fx);

    //    __m128i* poly = (__m128i*) & fx[0];
    //    unsigned n_terms = n_fx;

    //    for (unsigned i = 1; i <= log_n; i++) {
    //        unsigned unit = (1 << i);
    //        unsigned num = n_terms / unit;

    //        butterfly_0(poly, unit);
    //        for (unsigned j = 1; j < num; j++) {
    //            i_butterfly(poly + j * unit, unit, get_s_k_a_cantor(i - 1, j * unit));
    //        }
    //    }
    //}



}
#endif
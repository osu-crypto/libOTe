/*

   MinDistance.
   Software package with several fast scalar, vector, and parallel
   implementations for computing the minimum distance of a random linear code.

   Copyright (C) 2017  Fernando Hernando (carrillf@mat.uji.es)
   Copyright (C) 2017  Francisco Igual (figual@ucm.es)
   Copyright (C) 2017  Gregorio Quintana (gquintan@uji.es)

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA

*/

// Vector sizes.

#include <stdint.h>

#include "config.h"

#ifdef USE_VECTORIZATION
#include <immintrin.h>

#define VECT_SIZE_AVX512 16
#define VECT_SIZE_AVX2 8
#define VECT_SIZE_SSE 4

#ifdef USE_AVX512
 #define VECT_SIZE VECT_SIZE_AVX512
#endif
#ifdef USE_AVX2
 #define VECT_SIZE VECT_SIZE_AVX2
#endif
#ifdef USE_SSE
 #define VECT_SIZE VECT_SIZE_SSE
#endif

int compute_distance_of_uint32_vector_with_precomputing_vect(
    uint32_t * vec, int n );

void add_uint32_vector_to_vector_vect( int n, uint32_t * targetVec,
    uint32_t * sourceVec );

void allocateVecAdditionArray_AVX512( __m512i ** vecAdditionVec, 
    int chunks );

void loadVecAdditionArray_AVX512( __m512i * vecAdditionVec, 
    uint32_t * vecAddition, int chunks );

void loadVecAdditionArray_AVX2( __m256i * vecAdditionVec, 
    uint32_t * vecAddition, int chunks );

void allocateVecAdditionArray_AVX2( __m256i ** vecAdditionVec, 
    int chunks );

void loadVecAdditionArray_SSE( __m128i * vecAdditionVec, 
    uint32_t * vecAddition, int chunks );

void allocateVecAdditionArray_SSE( __m128i ** vecAdditionVec, 
    int chunks );

int popcount_vect_SSE( __m128i * vecAdditionVec, 
    uint32_t * ptr, int chunks );

int popcount_vect_AVX2( __m256i * vecAdditionVec, 
    uint32_t * ptr, int chunks );

int popcount_vect_AVX512( __m512i * vecAdditionVec, 
    uint32_t * ptr, int chunks );

#endif // USE_VECTORIZATION.

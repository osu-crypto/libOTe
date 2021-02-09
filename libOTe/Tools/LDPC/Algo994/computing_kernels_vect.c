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

#include <stdio.h>
#include <stdlib.h>
#include "libOTe/Tools/LDPC/Algo994/utils.h"
#include "libOTe/Tools/LDPC/Algo994/count_combinations.h"
#include "libOTe/Tools/LDPC/Algo994/check_combinations.h"
#include "libOTe/Tools/LDPC/Algo994/computing_kernels.h"
#include "libOTe/Tools/LDPC/Algo994/computing_kernels_vect.h"

#ifdef USE_VECTORIZATION
// ============================================================================
// Support vectorized functions.


#ifdef _MSC_VER
#  include <intrin.h>
//#  define popcount_32l __popcnt64
#endif
int popcount_32(int32_t x);
int popcount_64(int64_t x)
{
#ifdef _MSC_VER
    return __popcnt64(x);
#else
    return __builtin_popcountl(x);
#endif
}


//
//#ifdef _MSC_VER
//#  include <intrin.h>
//#  define popcount_32 __popcnt
//#endif


#if defined(USE_SSE) || defined(USE_AVX2) || defined(USE_AVX512)
static inline int popcount_128(__m128i n) {
  volatile const __m128i n_hi = _mm_unpackhi_epi64(n, n);
  return popcount_64(_mm_cvtsi128_si64(n)) + popcount_64(_mm_cvtsi128_si64(n_hi));
}

#ifdef USE_SSSE3
__m128i popcount_mask; 
__m128i popcount_table; 

static inline __m128i popcnt8_128(__m128i n ) {
  popcount_mask  = _mm_set1_epi8( 0x0F );
  popcount_table = _mm_setr_epi8( 0, 1, 1, 2, 1, 2, 2, 3, 
                                  1, 2, 2, 3, 2, 3, 3, 4 );
  
  const __m128i pcnt0 = _mm_shuffle_epi8( popcount_table, 
                                          _mm_and_si128( n, popcount_mask ) );
  const __m128i pcnt1 = _mm_shuffle_epi8( popcount_table, 
                                         _mm_and_si128( _mm_srli_epi16( n, 4 ), 
                                                        popcount_mask ) );
  return _mm_add_epi8( pcnt0, pcnt1 );
}

static inline __m128i popcnt64_128( __m128i n ) {
  const __m128i cnt8 = popcnt8_128( n );
  return _mm_sad_epu8(cnt8, _mm_setzero_si128( ) );
}

static inline int popcnt128b_128( __m128i n ) {
  const __m128i cnt64 = popcnt64_128( n );
  const __m128i cnt64_hi = _mm_unpackhi_epi64( cnt64, cnt64 );
  const __m128i cnt128 = _mm_add_epi32( cnt64, cnt64_hi );
  return _mm_cvtsi128_si32( cnt128 );
}
#endif

#endif

#if defined(USE_AVX2) || defined(USE_AVX512)
static inline int popcount_256( __m256i n ) {
  return popcount_64( _mm256_extract_epi64( n, 0 ) ) +
         popcount_64( _mm256_extract_epi64( n, 1 ) ) +
         popcount_64( _mm256_extract_epi64( n, 2 ) ) +
         popcount_64( _mm256_extract_epi64( n, 3 ) );
}

// Perform 4 population counts. Needs to be summed.
__m256i popcnt64_256 ( __m256i v ) {
  __m256i lookup = _mm256_setr_epi8 ( 0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 
                                      3, 3, 4, 0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 
                                      2, 3, 2, 3, 3, 4 );
  __m256i low_mask = _mm256_set1_epi8 ( 0x0f );
  __m256i lo = _mm256_and_si256 ( v , low_mask );
  __m256i hi = _mm256_and_si256 ( _mm256_srli_epi32 ( v , 4 ), low_mask );
  __m256i popcnt1 = _mm256_shuffle_epi8 ( lookup , lo );
  __m256i popcnt2 = _mm256_shuffle_epi8 ( lookup , hi );
  __m256i total = _mm256_add_epi8 ( popcnt1 , popcnt2 );
  return _mm256_sad_epu8 ( total , _mm256_setzero_si256 ( ) );
}

static inline int popcnt256_256( __m256i n ) {
  const __m256i cnt64 = popcnt64_256( n );

  const __m256i cnt64_hi = _mm256_unpackhi_epi64( cnt64, cnt64 );
  const __m256i cnt64_lo = _mm256_unpacklo_epi64( cnt64, cnt64 );
  const __m256i cnt256 = _mm256_add_epi64( cnt64_hi, cnt64_lo );
  const __m256i result256 = _mm256_unpackhi_epi64( cnt256, cnt256 );
  return _mm256_extract_epi64( result256, 0 ) + 
         _mm256_extract_epi64( result256, 2 );
}
#endif

#if defined(USE_AVX512)
static inline int popcount_512( __m512i n ) {
  __m256i upper = _mm512_extracti64x4_epi64( n, 0 );
  __m256i lower = _mm512_extracti64x4_epi64( n, 1 );

  return popcount_64(_mm256_extract_epi64( upper, 0 ) ) +
         popcount_64(_mm256_extract_epi64( lower, 0 ) ) +
         popcount_64(_mm256_extract_epi64( upper, 1 ) ) +
         popcount_64(_mm256_extract_epi64( lower, 1 ) ) +
         popcount_64(_mm256_extract_epi64( upper, 2 ) ) +
         popcount_64(_mm256_extract_epi64( lower, 2 ) ) +
         popcount_64(_mm256_extract_epi64( upper, 3 ) ) +
         popcount_64(_mm256_extract_epi64( lower, 3 ) );
}

static inline __m512i popcount2_512(__m512i n) {
  __m256i upper = _mm512_extracti64x4_epi64( n, 0 );
  __m256i lower = _mm512_extracti64x4_epi64( n, 1 );

  return _mm512_set_epi64(popcount_64(_mm256_extract_epi64( upper, 0 ) ),
         popcount_64(_mm256_extract_epi64( upper, 1 ) ),
         popcount_64(_mm256_extract_epi64( upper, 2 ) ),
         popcount_64(_mm256_extract_epi64( upper, 3 ) ),
         popcount_64(_mm256_extract_epi64( lower, 0 ) ),
         popcount_64(_mm256_extract_epi64( lower, 1 ) ),
         popcount_64(_mm256_extract_epi64( lower, 2 ) ),
         popcount_64(_mm256_extract_epi64( lower, 3 ) ) );
}

#endif

// ============================================================================
int compute_distance_of_uint32_vector_with_precomputing_vect(
    uint32_t * vec, int n ) {

  int dist = 0, i;

#ifdef USE_SSE
  __m128i  _cVec;

  int chunks = n / VECT_SIZE;

  for( i = 0; i < chunks; i++ ) {
    _cVec = _mm_loadu_si128( (__m128i*)((uint32_t*)(vec + VECT_SIZE * i)) );

    dist += popcount_128( _cVec );
  }

  for( i = VECT_SIZE * chunks; i < n; i++ ) {
    dist += popcount_32( vec[ i ] );
  }
#endif // USE_SSE

#ifdef USE_AVX2
  __m256i  _cVec;
  __m128i  _cVec128;

  int chunks = n / VECT_SIZE_AVX2;
  int chunks_128 = ( n % VECT_SIZE_AVX2 ) / ( VECT_SIZE_SSE );

  for( i = 0; i < chunks; i++ ) {
    _cVec = _mm256_loadu_si256( (__m256i*)((uint32_t*)(vec + VECT_SIZE_AVX2 * i)) );

    dist += popcount_256( _cVec );
  }

  for( i = 0; i < chunks_128; i++ ) {
    _cVec128 = _mm_loadu_si128( (__m128i*)((uint32_t*)(vec + ( chunks * VECT_SIZE_AVX2 ) + ( VECT_SIZE_SSE ) * i)) );

    dist += popcount_128( _cVec128 );
  }

  for( i = VECT_SIZE * chunks + VECT_SIZE_SSE * chunks_128; i < n; i++ ) {
    dist += popcount_32( vec[ i ] );
  }
#endif // USE_AVX2

#ifdef USE_AVX512
  __m512i  _cVec;
  __m256i  _cVec256;
  __m128i  _cVec128;

  int chunks_512 = n / VECT_SIZE_AVX512;
  int chunks_256 = ( n % VECT_SIZE_AVX512 ) / ( VECT_SIZE_AVX2 );
  int chunks_128 = ( n - chunks_512 * VECT_SIZE_AVX512 - 
                   (     chunks_256 * VECT_SIZE_AVX2 ) ) / ( VECT_SIZE_SSE );

  for( i = 0; i < chunks_512; i++ ) {
    _cVec = _mm512_loadu_si512( (__m512i*)((uint32_t*)(vec + VECT_SIZE * i)) );

    dist += popcount_512( _cVec );
  }

  for( i = 0; i < chunks_256; i++ ) {
    _cVec256 = _mm256_loadu_si256( (__m256i*)((uint32_t*)( vec + 
                                                         ( chunks_512 * VECT_SIZE_AVX512 ) + 
                                                         (              VECT_SIZE_AVX2 ) * i ) ) );

    dist += popcount_256( _cVec256 );
  }

  for( i = 0; i < chunks_128; i++ ) {
    _cVec128 = _mm_loadu_si128( (__m128i*)((uint32_t*)( vec + 
                                                      ( chunks_512 * VECT_SIZE_AVX512 ) + 
                                                      ( chunks_256 * VECT_SIZE_AVX2 ) + 
                                                      (              VECT_SIZE_SSE ) * i ) ) );

    dist += popcount_128( _cVec128 );
  }

  for( i = VECT_SIZE * chunks_512 + ( VECT_SIZE_AVX2 ) * chunks_256 + ( VECT_SIZE_SSE ) * chunks_128; i < n; i++ ) {
    dist += popcount_32( vec[ i ] );
  }
#endif // USE_AVX512
  return dist;
}

// ============================================================================
void add_uint32_vector_to_vector_vect( int n, uint32_t * targetVec,
    uint32_t * sourceVec ) {
  int  i;

#ifdef USE_SSE
  __m128i _targetVec;
  __m128i _sourceVec;

  int chunks = n / VECT_SIZE;

  for( i = 0; i < chunks; i++ ) {
    _targetVec = _mm_loadu_si128( (__m128i*)((uint32_t*)(targetVec + VECT_SIZE * i)) );
    _sourceVec = _mm_loadu_si128( (__m128i*)((uint32_t*)(sourceVec + VECT_SIZE * i)) );

    _targetVec = _mm_xor_si128( _targetVec, _sourceVec );

    _mm_storeu_si128( (__m128i*)((uint32_t*)(targetVec + VECT_SIZE * i)), _targetVec );
  }

  for( i = VECT_SIZE * chunks; i < n; i++ ) {
        targetVec[ i ] ^= sourceVec[ i ];
  }
#endif // USE_SSE2

#ifdef USE_AVX2
  __m256i _targetVec;
  __m256i _sourceVec;

  __m128i _targetVec128;
  __m128i _sourceVec128;

  int chunks = n / VECT_SIZE;
  int chunks_128 = ( n % VECT_SIZE ) / ( VECT_SIZE / 2 );

  for( i = 0; i < chunks; i++ ) {
    _targetVec = _mm256_loadu_si256( (__m256i*)((uint32_t*)(targetVec + VECT_SIZE * i)) );
    _sourceVec = _mm256_loadu_si256( (__m256i*)((uint32_t*)(sourceVec + VECT_SIZE * i)) );

    _targetVec = _mm256_xor_si256( _targetVec, _sourceVec );

    _mm256_storeu_si256( (__m256i*)((uint32_t*)(targetVec + VECT_SIZE * i)), _targetVec );
  }

  for( i = 0; i < chunks_128; i++ ) {
    _targetVec128 = _mm_loadu_si128( (__m128i*)((uint32_t*)(targetVec + ( chunks * VECT_SIZE ) + ( VECT_SIZE / 2 ) * i)) );
    _sourceVec128 = _mm_loadu_si128( (__m128i*)((uint32_t*)(sourceVec + ( chunks * VECT_SIZE ) + ( VECT_SIZE / 2 ) * i)) );

    _targetVec128 = _mm_xor_si128( _targetVec128, _sourceVec128 );

    _mm_storeu_si128( (__m128i*)((int32_t*)(targetVec + ( chunks * VECT_SIZE ) + ( VECT_SIZE / 2 ) * i)), _targetVec128 );
  }

  for( i = VECT_SIZE * chunks + ( VECT_SIZE / 2 ) * chunks_128; i < n; i++ ) {
        targetVec[ i ] ^= sourceVec[ i ];
  }
#endif // USE_AVX2

#ifdef USE_AVX512
  __m512i _targetVec;
  __m512i _sourceVec;

  __m256i _targetVec256;
  __m256i _sourceVec256;

  __m128i _targetVec128;
  __m128i _sourceVec128;

  int chunks = n / VECT_SIZE;
  int chunks_256 = ( n % VECT_SIZE ) / ( VECT_SIZE / 2 );
  int chunks_128 =  ( n - chunks * VECT_SIZE - ( chunks_256 * VECT_SIZE/2 ) ) / ( VECT_SIZE / 4 );

  for( i = 0; i < chunks; i++ ) {
    _targetVec = _mm512_loadu_si512( (__m512i*)((uint32_t*)(targetVec + VECT_SIZE * i)) );
    _sourceVec = _mm512_loadu_si512( (__m512i*)((uint32_t*)(sourceVec + VECT_SIZE * i)) );

    _targetVec = _mm512_xor_si512( _targetVec, _sourceVec );

    _mm512_storeu_si512( (__m512i*)((uint32_t*)(targetVec + VECT_SIZE * i)), _targetVec );

  }

  for( i = 0; i < chunks_256; i++ ) {
    _targetVec256 = _mm256_loadu_si256( (__m256i*)((uint32_t*)(targetVec + ( chunks * VECT_SIZE ) + ( VECT_SIZE / 2 ) * i)) );
    _sourceVec256 = _mm256_loadu_si256( (__m256i*)((uint32_t*)(sourceVec + ( chunks * VECT_SIZE ) + ( VECT_SIZE / 2 ) * i)) );

    _targetVec256 = _mm256_xor_si256( _targetVec256, _sourceVec256 );

    _mm256_storeu_si256( (__m256i*)((uint32_t*)(targetVec + chunks * VECT_SIZE + ( VECT_SIZE / 2 ) * i)), _targetVec256 );
  }

  for( i = 0; i < chunks_128; i++ ) {
    _targetVec128 = _mm_loadu_si128( (__m128i*)((uint32_t*)(targetVec + ( chunks * VECT_SIZE ) + chunks_256 * ( VECT_SIZE / 2 ) + ( VECT_SIZE / 4 ) * i)) );
    _sourceVec128 = _mm_loadu_si128( (__m128i*)((uint32_t*)(sourceVec + ( chunks * VECT_SIZE ) + chunks_256 * ( VECT_SIZE / 2 ) + ( VECT_SIZE / 4 ) * i)) );

    _targetVec128 = _mm_xor_si128( _targetVec128, _sourceVec128 );

    _mm_storeu_si128( (__m128i*)((uint32_t*)(targetVec + ( chunks * VECT_SIZE ) + chunks_256 * ( VECT_SIZE / 2 ) + ( VECT_SIZE / 4 )  * i)), _targetVec128 );
  }

  for( i = VECT_SIZE * chunks + ( VECT_SIZE / 2 ) * chunks_256 + ( VECT_SIZE / 4 ) * chunks_128; i < n; i++ ) {
        targetVec[ i ] ^= sourceVec[ i ];
  }
#endif // USE_AVX512

}





#if defined(USE_SSE) || defined(USE_AVX2) || defined(USE_AVX512)
void allocateVecAdditionArray_SSE( __m128i ** vecAdditionVec, int chunks ) {
  int retAlign;

  retAlign = posix_memalign( ( void ** ) vecAdditionVec, 16, chunks * sizeof( __m256i ) );

  if( retAlign != 0 ) {
    fprintf( stderr, "\n\nERROR: posix_memalign failed.\n\n\n" );
    exit( -1 );
  }
}

void loadVecAdditionArray_SSE( __m128i * vecAdditionVec, uint32_t * vecAddition, int chunks ) {
  int i;

  for( i = 0; i < chunks; i++ ) {
    vecAdditionVec[i] = _mm_loadu_si128( ( __m128i const * )( ( int* )( vecAddition + VECT_SIZE_SSE * i ) ) );
  }

}
#endif

#if defined(USE_AVX2) || defined(USE_AVX512)
void allocateVecAdditionArray_AVX2( __m256i ** vecAdditionVec, int chunks ) {
  int i, retAlign;

  retAlign = posix_memalign( ( void ** ) vecAdditionVec, 32, chunks * sizeof( __m256i ) );

  if( retAlign != 0 ) {
    fprintf( stderr, "\n\nERROR: posix_memalign failed.\n\n\n" );
    exit( -1 );
  }
}

void loadVecAdditionArray_AVX2( __m256i * vecAdditionVec, uint32_t * vecAddition, int chunks ) {
  int i;

  for( i = 0; i < chunks; i++ ) {
    vecAdditionVec[i] = _mm256_loadu_si256( ( __m256i const * )( ( int* )( vecAddition + VECT_SIZE_AVX2 * i ) ) );
    }
}
#endif

#if defined(USE_AVX512)
void allocateVecAdditionArray_AVX512( __m512i ** vecAdditionVec, int chunks ) {
    int i, retAlign;

    retAlign = posix_memalign( ( void ** ) vecAdditionVec, 64, chunks * sizeof( __m512i ) );

    if( retAlign != 0 ) {
        fprintf( stderr, "\n\nERROR: posix_memalign failed.\n\n\n" );
        exit( -1 );
    }
}

void loadVecAdditionArray_AVX512( __m512i * vecAdditionVec, uint32_t * vecAddition, int chunks ) {
  int i;

  for( i = 0; i < chunks; i++ ) {
    vecAdditionVec[i] = _mm512_loadu_si512( (__m512i const *)((int*)(vecAddition + VECT_SIZE_AVX512 * i)) );
  }
}
#endif

#if defined(USE_AVX512)
int popcount_vect_AVX512( __m512i * vecAdditionVec, uint32_t * ptr, int chunks ) {
  int j, dist = 0;
  __m512i ptrVec, cVec;

  #pragma omp simd //aligned(ptr)
  for( j = 0; j < chunks; j++ )
  {
    ptrVec = _mm512_loadu_si512( (__m512i const *)ptr );
    cVec = _mm512_xor_si512( vecAdditionVec[ j ], ptrVec );
    dist += popcount_512( cVec );
  }
  
  return dist;
}
#endif

#if defined(USE_AVX2) || defined(USE_AVX512)
int popcount_vect_AVX2( __m256i * vecAdditionVec, uint32_t * ptr, int chunks ) {
  int j, dist = 0;
  __m256i ptrVec, cVec;

  #pragma omp simd //aligned(ptr)
  for( j = 0; j < chunks; j++ )
  {
    ptrVec = _mm256_loadu_si256( (__m256i const *)ptr );
    cVec = _mm256_xor_si256( vecAdditionVec[ j ], ptrVec );
    dist += popcount_256( cVec );
  }

  return dist;
}
#endif

#if defined(USE_SSE) || defined(USE_AVX2) || defined(USE_AVX512)
int popcount_vect_SSE( __m128i * vecAdditionVec, uint32_t * ptr, int chunks ) {
  int j, dist = 0;
  __m128i ptrVec, cVec;

  //#pragma omp simd //aligned(ptr)
  for( j = 0; j < chunks; j++ )
  {
    ptrVec = _mm_loadu_si128( (__m128i const *)ptr );
    cVec = _mm_xor_si128( vecAdditionVec[ j ], ptrVec );
    dist += popcount_128( cVec );
  }

  return dist;
}
#endif

#endif

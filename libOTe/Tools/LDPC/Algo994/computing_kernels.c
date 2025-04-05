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

#ifdef _MSC_VER
#  include <intrin.h>
#endif

//#  define popcount_32 __popcnt
int popcount_32(int32_t x)
{
#ifdef _MSC_VER
    int v = __popcnt(x);
#else
    int v = __builtin_popcount(x);
#endif

    //int c = 0;
    //for (int i = 0; i < 32; ++i)
    //{
    //    if (x & 1)
    //        ++c;

    //    x = x >> 1;
    //}

    //if (c != v)
    //    printf("bad-----------------\n");
    //else
    //    printf("x %d\n", x);
    return v;

}


// ============================================================================
// Declaration of local variables.

static int vecNumOnes[ 256 ];

// ============================================================================
// Declaration of local prototypes.

static int count_ones_in_uint8( uint8_t a );

static int count_ones_in_uint32_with_precomputing( uint32_t a );

// ============================================================================
void init_computing_kernels_module() {
  int  i;

  for( i = 0; i < 256; i++ ) {
    vecNumOnes[ i ] = count_ones_in_uint8( ( uint8_t ) i );
  }
}

// ============================================================================
static int count_ones_in_uint8( uint8_t a ) {
//
// Count ones in an "uint8_t" number.
//
  int      i, num;
  uint8_t  aa;

  aa  = a;
  num = 0;
  for( i = 0; i < 8; i++ ) {
    num += ( aa & 1 );
    aa = aa >> 1 ;
  }
  return( num );
}

// ============================================================================
static int count_ones_in_uint32_with_precomputing( uint32_t a ) {
//
// Count ones in an "uint32_t" number.
// This routine uses precomputing to accelerate the computations.
//
  int  dist;

  dist = vecNumOnes[ ( int ) ( ( uint8_t ) ( ( a >> 24 ) & 0xFF ) ) ] +
         vecNumOnes[ ( int ) ( ( uint8_t ) ( ( a >> 16 ) & 0xFF ) ) ] +
         vecNumOnes[ ( int ) ( ( uint8_t ) ( ( a >>  8 ) & 0xFF ) ) ] +
         vecNumOnes[ ( int ) ( ( uint8_t ) ( ( a       ) & 0xFF ) ) ];

  return( dist );
}


// ============================================================================
int compute_distance_of_uint32_vector_with_precomputing(
    uint32_t * vec, int n ) {
  int  dist;

  dist = 0;

#ifdef USE_VECTORIZATION
  dist = compute_distance_of_uint32_vector_with_precomputing_vect( vec, n );
#else // USE_VECTORIZATION
  for(int i = 0; i < n; i++ ) {
    dist += count_ones_in_uint32_with_precomputing( vec[ i ] );
  }
#endif // USE_VECTORIZATION
  return( dist );
}

// ============================================================================
void copy_uint32_vector( int n, uint32_t * targetVec, uint32_t * sourceVec ) {
  int  i;

  for( i = 0; i < n; i++ ) {
    targetVec[ i ] = sourceVec[ i ];
  }
}

// ============================================================================
void add_uint32_vector_to_vector( int n, uint32_t * targetVec,
    uint32_t * sourceVec ) {

#ifdef USE_VECTORIZATION
  add_uint32_vector_to_vector_vect( n, targetVec, sourceVec );
#else // USE_VECTORIZATION
  for(int i = 0; i < n; i++ ) {
    targetVec[ i ] ^= sourceVec[ i ];
  }

#endif // USE_VECTORIZATION
}

// ============================================================================
void add_two_uint32_vectors( int n, uint32_t * targetVec,
    uint32_t * sourceVec1, uint32_t * sourceVec2 ) {
//
// Add two int vectors sourceVec1 and sourceVec2 into targetVec.
// Original contents of targetVec is overwritten.
//
  int  i;

  for( i = 0; i < n; i++ ) {
    targetVec[ i ] = sourceVec1[ i ] ^ sourceVec2[ i ];
  }
}

// ============================================================================
void copy_uint32_matrix( int numRows, int numCols, int rowStride,
    uint32_t * targetMat, uint32_t * sourceMat ) {
  int  i, j;

  for( i = 0; i < numRows; i++ ) {
    for( j = 0; j < numCols; j++ ) {
      targetMat[ rowStride * i + j ] = sourceMat[ rowStride * i + j ];
    }
  }
}

// ============================================================================
int compute_distance_of_uint32_rows( int k, int n,
    uint32_t * gammaMatrices, int rowStride ) {
//
// It performs the following for every row:
// 1. The distance of the row is computed,
// 2. and the minimum distance is updated.
// "gammaMatrices" is of dimension k x n.
//
  uint32_t  c, * ptr2;
  int       i, j, minDist, dist;

  // Quick return.
  if( ( k <= 0 )||( n <= 0 ) ) return 0;

  // Usual algorithm.
  minDist = 0;
  for( i = 0; i < k; i++ ) {
    dist = 0;
    ptr2 = & gammaMatrices[ rowStride * i + 0 ];
    for( j = 0; j < n; j++ ) {
      c = * ptr2;
      dist += count_ones_in_uint32_with_precomputing( c );
      ptr2++;
    }
    if( ( dist != 0 )&&( ( minDist <= 0 )||( dist < minDist ) ) ) {
      minDist = dist;
    }
  }

  return( minDist );
}

// ============================================================================
void add_selected_rows( int k, int n, int numRows,
    uint32_t * gammaMatrices, int rowStride,
    uint32_t * vecAddition, int * vecIndices ) {
//
// It adds all the selected rows (rows with indices appearing inside the first
// "numRows" elements of vector "vecIndices") of "gammaMatrices",
// and save the result into "vecAddition".
// "gammaMatrices" is of dimension k x n.
// "vecAddition"   is of dimension n.
// "vecIndices"    is of dimension numRows.
// This routine is employed when computing combinations based on
// combinations with fewer elements.
//
  uint32_t  * ptr2;
  int       i, j, rowIndex;

  // Initialize vector.
  for( j = 0; j < n; j++ ) {
    vecAddition[ j ] = ( uint32_t ) 0;
  }

  // Quick return.
  if( ( k <= 0 )||( n <= 0 ) ) return;

  // Usual algorithm:
  // Accumulate the "numRows" selected rows into "vecAddition".
  for( i = 0; i < numRows; i++ ) {
    rowIndex = vecIndices[ i ];
    ptr2 = & gammaMatrices[ rowStride * rowIndex + 0 ];
    for( j = 0; j < n; j++ ) {
      vecAddition[ j ] ^= ( * ptr2 );
      ptr2++;
    }
  }
}

// ============================================================================
void accumulate_uint32_vector_and_selected_rows( int k, int n, int numRows,
    uint32_t * gammaMatrices, int rowStride,
    uint32_t * vecAddition, int * vecIndices ) {
//
// It accumulates the vector "vecAddition" and all the selected rows (rows
// with indices appearing inside the first "numRows" elements of vector
// "vecIndices") of "gammaMatrices".
// "gammaMatrices" is of dimension k x n.
// "vecAddition"   is of dimension n.
// "vecIndices"    is of dimension numRows.
// This routine is employed when computing combinations based on
// combinations with fewer elements.
//
  uint32_t  * ptr2;
  int       i, j, rowIndex;

  // Quick return.
  if( ( k <= 0 )||( n <= 0 ) ) return;

  // Usual algorithm:
  // Accumulate the "numRows" selected rows into "vecAddition".
  for( i = 0; i < numRows; i++ ) {
    rowIndex = vecIndices[ i ];
    ptr2 = & gammaMatrices[ rowStride * rowIndex + 0 ];
    for( j = 0; j < n; j++ ) {
      vecAddition[ j ] ^= ( * ptr2 );
      ptr2++;
    }
  }
}

// ============================================================================
int add_every_row_to_uint32_vector_and_compute_distance( int k, int n,
    uint32_t * gammaMatrices, int rowStride, uint32_t * vecAddition ) {
//
// It performs the following for every row:
// 1. The row is added to "vecAddition",
// 2. the distance of that addition of the row and "vecAddition" is computed,
// 3. and the minimum distance is updated.
// "gammaMatrices" is of dimension k x n.
// "vecAddition"   is of dimension n.
// This routine is employed when computing combinations based on
// combinations with fewer elements.
//
  uint32_t  * ptr2, c;
  int       i, j, minDist, dist;
#ifdef CHECK_COMBINATIONS
  uint32_t  * vecAdditionAux;
#endif

  // Quick return.
  if( k <= 0 ) return 0;

  // Update the number of combinations evaluated.
#ifdef COUNT_COMBINATIONS
  add_num_combinations_in_count_combinations( k );
#endif

#ifdef CHECK_COMBINATIONS
  //// print_uint32_matrix_as_bin( "gamma matrix", gammaMatrices, k, rowStride );
  //// print_uint32_vector_as_bin( "vecAddition", vecAddition, rowStride );
  create_aligned_uint32_vector(
      "add_every_row_to_uint32_vector_and_compute_distance",
      & vecAdditionAux, rowStride );
#endif

#ifdef USE_VECTORIZATION

#ifdef USE_SSE
  __m128i * vecAdditionVec_128 = NULL;

  int chunks_128 = n / VECT_SIZE;

  minDist = 0;

  // SSE2
  if( chunks_128 != 0 ) {
    allocateVecAdditionArray_SSE( &vecAdditionVec_128, chunks_128 );
    loadVecAdditionArray_SSE( vecAdditionVec_128, vecAddition, chunks_128 );
  }

  for( i = 0; i < k; i++ ) {
    dist = 0;
    ptr2 = & gammaMatrices[ rowStride * i + 0 ];

    dist += popcount_vect_SSE( vecAdditionVec_128, ptr2, chunks_128 );
    ptr2 = ptr2 + chunks_128 * VECT_SIZE_SSE;

    //#pragma omp simd aligned(ptr2)
    for( j = VECT_SIZE_SSE * chunks_128; j < n; j++ ) {
        c = vecAddition[ j ] ^ ( * ptr2 );
        ptr2++;
        dist += popcount_32( c );
      }

    if( ( i == 0 )||( ( dist != 0 )&&( dist < minDist ) ) ) {
      minDist = dist;
    }

  }
  if( chunks_128 ) {
    free( vecAdditionVec_128 );
  }
#endif

#ifdef USE_AVX2
  __m256i * vecAdditionVec_256;
  __m128i * vecAdditionVec_128;

  int chunks_256 = n / VECT_SIZE;
  int chunks_128 = ( n % VECT_SIZE ) / ( VECT_SIZE / 2 );
  int retAlign;

  minDist = 0;

  // AVX2
  if( chunks_256 != 0 ) {
    allocateVecAdditionArray_AVX2( &vecAdditionVec_256, chunks_256 );
    loadVecAdditionArray_AVX2( vecAdditionVec_256, vecAddition, chunks_256 );
  }

  // SSE2
  if( chunks_128 != 0 ) {
    allocateVecAdditionArray_SSE( &vecAdditionVec_128, chunks_128 );
    loadVecAdditionArray_SSE( vecAdditionVec_128, vecAddition + 
                              chunks_256 * VECT_SIZE_AVX2, chunks_128 );
  }

  for( i = 0; i < k; i++ ) {
    dist = 0;
    ptr2 = & gammaMatrices[ rowStride * i + 0 ];

    dist += popcount_vect_AVX2( vecAdditionVec_256, ptr2, chunks_256 );
    ptr2 = ptr2 + chunks_256 * VECT_SIZE_AVX2;

    dist += popcount_vect_SSE( vecAdditionVec_128, ptr2, chunks_128 );
    ptr2 = ptr2 + chunks_128 * VECT_SIZE_SSE;

    #pragma omp simd aligned(ptr2)
    for( j = VECT_SIZE_AVX2 * chunks_256 + 
             VECT_SIZE_SSE * chunks_128; j < n; j++ ) {
        c = vecAddition[ j ] ^ ( * ptr2 );
        ptr2++;
        dist += popcount_32( c );
      }

    if( ( i == 0 )||( ( dist != 0 )&&( dist < minDist ) ) ) {
      minDist = dist;
    }

  }

  if( chunks_256 ) {
    free( vecAdditionVec_256 );
  }

  if( chunks_128 ) {
    free( vecAdditionVec_128 );
  }
#endif // AVX2.

#ifdef USE_AVX512
  __m512i * vecAdditionVec_512;
  __m256i * vecAdditionVec_256;
  __m128i * vecAdditionVec_128;

  int chunks_512 = n / VECT_SIZE;
  int chunks_256 = ( n % VECT_SIZE ) / ( VECT_SIZE / 2 );
  int chunks_128 = ( n - chunks_512 * VECT_SIZE - ( chunks_256 * VECT_SIZE/2 ) ) / ( VECT_SIZE / 4 );
  int retAlign;

  minDist = 0;

  // AVX512
  if( chunks_512 != 0 ) {
    allocateVecAdditionArray_AVX512( &vecAdditionVec_512, chunks_512 );
    loadVecAdditionArray_AVX512( vecAdditionVec_512, vecAddition, chunks_512 );
  }

  // AVX2
  if( chunks_256 != 0 ) {
    allocateVecAdditionArray_AVX2( &vecAdditionVec_256, chunks_256 );
    loadVecAdditionArray_AVX2( vecAdditionVec_256, vecAddition + 
                             ( chunks_512 * VECT_SIZE_AVX512 ), chunks_256 );
  }

  // SSE2
  if( chunks_128 != 0 ) {
    allocateVecAdditionArray_SSE( &vecAdditionVec_128, chunks_128 );
    loadVecAdditionArray_SSE( vecAdditionVec_128, vecAddition + 
                            ( chunks_512 * VECT_SIZE_AVX512 ) + 
                            ( chunks_256 * VECT_SIZE_AVX2), chunks_128 );
  }

  for( i = 0; i < k; i++ ) {
    dist = 0;
    ptr2 = & gammaMatrices[ rowStride * i + 0 ];

    dist += popcount_vect_AVX512( vecAdditionVec_512, ptr2, chunks_512 );
    ptr2 = ptr2 + chunks_512 * VECT_SIZE_AVX512;

    dist += popcount_vect_AVX2( vecAdditionVec_256, ptr2, chunks_256 );
    ptr2 = ptr2 + chunks_256 * VECT_SIZE_AVX2;

    dist += popcount_vect_SSE( vecAdditionVec_128, ptr2, chunks_128 );
    ptr2 = ptr2 + chunks_128 * VECT_SIZE_SSE;

    #pragma omp simd aligned(ptr2)
    for( j = VECT_SIZE_AVX512 * chunks_512 + 
             VECT_SIZE_AVX2 * chunks_256 +  
             VECT_SIZE_SSE * chunks_128; j < n; j++ ) {
        c = vecAddition[ j ] ^ ( * ptr2 );
        ptr2++;
        dist += popcount_32( c );
      }

    if( ( i == 0 )||( ( dist != 0 )&&( dist < minDist ) ) ) {
      minDist = dist;
    }
  }

  if( chunks_512 ) {
    free( vecAdditionVec_512 );
  }
  if( chunks_256 ) {
    free( vecAdditionVec_256 );
  }
  if( chunks_128 ) {
    free( vecAdditionVec_128 );
  }
#endif

#else // USE_VECTORIZATION

  // Usual algorithm.
  minDist = 0;
  for( i = 0; i < k; i++ ) {
    dist = 0;
    ptr2 = & gammaMatrices[ rowStride * i + 0 ];
    for( j = 0; j < n; j++ ) {
      c = vecAddition[ j ] ^ ( * ptr2 );
      ptr2++;
      dist += count_ones_in_uint32_with_precomputing( c );
#ifdef CHECK_COMBINATIONS
      vecAdditionAux[ j ] = c;
#endif
    }
    if( ( dist != 0 )&&( ( minDist <= 0 )||( dist < minDist ) ) ) {
      minDist = dist;
    }
#ifdef CHECK_COMBINATIONS
    //// printf( "i: %d \n", i );
    check_current_addition_in_check_combinations( vecAdditionAux, rowStride );
#endif
  }

#ifdef CHECK_COMBINATIONS
  free( vecAdditionAux );
#endif

#endif

  return( minDist );
}

// ============================================================================
int add_every_row_to_two_int_vectors_and_compute_distance( int k, int n,
    uint32_t * gammaMatrices, int rowStride,
    uint32_t * vecAddition1, uint32_t * vecAddition2 ) {
//
// It performs the following for every row:
// 1. The row is added to both "vecAddition1" and "vecAddition2",
// 2. the distance of those additions are computed,
// 3. and the minimum distance is updated.
// "gammaMatrices" is of dimension k x n.
// "vecAddition1"  is of dimension n.
// "vecAddition2"  is of dimension n.
// This routine is employed when computing combinations based on combinations
// with fewer elements.
//
  uint32_t  c1, c2;
  int       i, j, minDist, dist, dist1, dist2;

  //// printf( "add_every_row_to_two_int_vectors_and_compute_.... k: %d\n",
  ////         k );

  // Quick return.
  if( k <= 0 ) return 0;

  // Update the number of combinations evaluated.
#ifdef COUNT_COMBINATIONS
  add_num_combinations_in_count_combinations( 2 * k );
#endif

#ifdef USE_VECTORIZATION

#ifdef USE_SSE
  __m128i * vecAddition1Vec_128 = NULL, * vecAddition2Vec_128 = NULL;

  int chunks_128 = n / VECT_SIZE;
  int * ptr2;

  minDist = 0;

  // SSE2
  if ( chunks_128 != 0 ) {
    allocateVecAdditionArray_SSE( &vecAddition1Vec_128, chunks_128 );
    allocateVecAdditionArray_SSE( &vecAddition2Vec_128, chunks_128 );

    loadVecAdditionArray_SSE( vecAddition1Vec_128, vecAddition1, chunks_128 );
    loadVecAdditionArray_SSE( vecAddition2Vec_128, vecAddition2, chunks_128 );
  }

  for( i = 0; i < k; i++ ) {
    dist = 0;
    dist1 = 0;
    dist2 = 0;
    ptr2 = & gammaMatrices[ rowStride * i + 0 ];

    dist += popcount_vect_SSE( vecAddition1Vec_128, ptr2, chunks_128 );
    dist += popcount_vect_SSE( vecAddition2Vec_128, ptr2, chunks_128 );
    ptr2 = ptr2 + chunks_128 * VECT_SIZE_SSE;

    //#pragma omp simd aligned(ptr2)
    for( j = VECT_SIZE_SSE * chunks_128; j < n; j++ ) {
        c1 = vecAddition1[ j ] ^ ( * ptr2 );
        c2 = vecAddition2[ j ] ^ ( * ptr2 );
        ptr2++;
        dist1 += popcount_32( c1 );
        dist2 += popcount_32( c2 );
      }

    dist = ( dist1 <= dist2 ? dist1 : dist2 );
    if( ( i == 0 )||( ( dist != 0 )&&( dist < minDist ) ) ) {
      minDist = dist;
    }

  }

  if ( chunks_128 ) {
    free( vecAddition1Vec_128 );
    free( vecAddition2Vec_128 );
  }
#endif

#ifdef USE_AVX2
  __m256i * vecAddition1Vec_256, * vecAddition2Vec_256;
  __m128i * vecAddition1Vec_128, * vecAddition2Vec_128;

  int chunks_256 = n / VECT_SIZE;
  int chunks_128 = ( n % VECT_SIZE ) / ( VECT_SIZE / 2 );
  int * ptr2;
  int retAlign;

  minDist = 0;

  // AVX2
  if ( chunks_256 != 0 ) {
    allocateVecAdditionArray_AVX2( &vecAddition1Vec_256, chunks_256 );
    allocateVecAdditionArray_AVX2( &vecAddition2Vec_256, chunks_256 );

    loadVecAdditionArray_AVX2( vecAddition1Vec_256, vecAddition1, chunks_256 );
    loadVecAdditionArray_AVX2( vecAddition2Vec_256, vecAddition2, chunks_256 );
  }

  // SSE2
  if ( chunks_128 != 0 ) {
    allocateVecAdditionArray_SSE( &vecAddition1Vec_128, chunks_128 );
    allocateVecAdditionArray_SSE( &vecAddition2Vec_128, chunks_128 );

    loadVecAdditionArray_SSE( vecAddition1Vec_128, vecAddition1 + 
                              chunks_256 * VECT_SIZE_AVX2, chunks_128 );
    loadVecAdditionArray_SSE( vecAddition2Vec_128, vecAddition2 + 
                              chunks_256 * VECT_SIZE_AVX2, chunks_128 );
  }

  for( i = 0; i < k; i++ ) {
    dist = 0;
    dist1 = 0;
    dist2 = 0;
    ptr2 = & gammaMatrices[ rowStride * i + 0 ];

    dist += popcount_vect_AVX2( vecAddition1Vec_256, ptr2, chunks_256 );
    dist += popcount_vect_AVX2( vecAddition2Vec_256, ptr2, chunks_256 );
    ptr2 = ptr2 + chunks_256 * VECT_SIZE_AVX2;

    dist += popcount_vect_SSE( vecAddition1Vec_128, ptr2, chunks_128 );
    dist += popcount_vect_SSE( vecAddition2Vec_128, ptr2, chunks_128 );
    ptr2 = ptr2 + chunks_128 * VECT_SIZE_SSE;

    #pragma omp simd aligned(ptr2)
    for( j = VECT_SIZE_AVX2 * chunks_256 + 
             VECT_SIZE_SSE * chunks_128; j < n; j++ ) {
      c1 = vecAddition1[ j ] ^ ( * ptr2 );
      c2 = vecAddition2[ j ] ^ ( * ptr2 );
      ptr2++;
      dist1 += popcount_32( c1 );
      dist2 += popcount_32( c2 );
    }

    dist = ( dist1 <= dist2 ? dist1 : dist2 );
    if( ( i == 0 )||( ( dist != 0 )&&( dist < minDist ) ) ) {
      minDist = dist;
    }

  }

  if ( chunks_256 ) {
    free( vecAddition1Vec_256 );
    free( vecAddition2Vec_256 );
  }

  if ( chunks_128 ) {
    free( vecAddition1Vec_128 );
    free( vecAddition2Vec_128 );
  }

#endif

#ifdef USE_AVX512
  __m512i * vecAddition1Vec_512, * vecAddition2Vec_512;
  __m256i * vecAddition1Vec_256, * vecAddition2Vec_256;
  __m128i * vecAddition1Vec_128, * vecAddition2Vec_128;

  int chunks_512 = n / VECT_SIZE;
  int chunks_256 = ( n % VECT_SIZE ) / ( VECT_SIZE / 2 );
  int chunks_128 = ( n - chunks_512 * VECT_SIZE - ( chunks_256 * VECT_SIZE/2 ) ) / ( VECT_SIZE / 4 );
  int * ptr2;
  int retAlign;

  minDist = 0;

  // AVX512
  if( chunks_512 != 0 ) {
    allocateVecAdditionArray_AVX512( &vecAddition1Vec_512, chunks_512 );
    allocateVecAdditionArray_AVX512( &vecAddition2Vec_512, chunks_512 );

    loadVecAdditionArray_AVX512( vecAddition1Vec_512, vecAddition1, chunks_512 );
    loadVecAdditionArray_AVX512( vecAddition1Vec_512, vecAddition2, chunks_512 );
  }

  // AVX2
  if ( chunks_256 != 0 ) {
    allocateVecAdditionArray_AVX2( &vecAddition1Vec_256, chunks_256 );
    allocateVecAdditionArray_AVX2( &vecAddition2Vec_256, chunks_256 );

    loadVecAdditionArray_AVX2( vecAddition1Vec_256, vecAddition1 + 
                             ( chunks_512 * VECT_SIZE_AVX512 ), chunks_256 );
    loadVecAdditionArray_AVX2( vecAddition2Vec_256, vecAddition2 + 
                             ( chunks_512 * VECT_SIZE_AVX512 ), chunks_256 );
  }

  // SSE2
  if ( chunks_128 != 0 ) {
      allocateVecAdditionArray_SSE(&vecAddition1Vec_128, chunks_128);
      allocateVecAdditionArray_SSE( &vecAddition2Vec_128, chunks_128 );

    loadVecAdditionArray_SSE( vecAddition1Vec_128, vecAddition1 + 
                            ( chunks_512 * VECT_SIZE_AVX512 ) + 
                            ( chunks_256 * VECT_SIZE_AVX2), chunks_128 );
    loadVecAdditionArray_SSE( vecAddition2Vec_128, vecAddition2 + 
                            ( chunks_512 * VECT_SIZE_AVX512 ) + 
                            ( chunks_256 * VECT_SIZE_AVX2), chunks_128 );
  }

  for( i = 0; i < k; i++ ) {
    dist = 0;
    dist1 = 0;
    dist2 = 0;
    ptr2 = & gammaMatrices[ rowStride * i + 0 ];

    dist += popcount_vect_AVX512( vecAddition1Vec_512, ptr2, chunks_512 );
    dist += popcount_vect_AVX512( vecAddition2Vec_512, ptr2, chunks_512 );
    ptr2 = ptr2 + chunks_512 * VECT_SIZE_AVX512;

    dist += popcount_vect_AVX2( vecAddition1Vec_256, ptr2, chunks_256 );
    dist += popcount_vect_AVX2( vecAddition2Vec_256, ptr2, chunks_256 );
    ptr2 = ptr2 + chunks_256 * VECT_SIZE_AVX2;

    dist += popcount_vect_SSE( vecAddition1Vec_128, ptr2, chunks_128 );
    dist += popcount_vect_SSE( vecAddition2Vec_128, ptr2, chunks_128 );
    ptr2 = ptr2 + chunks_128 * VECT_SIZE_SSE;

    #pragma omp simd aligned(ptr2)
    for( j = VECT_SIZE_AVX512 * chunks_512 + 
             VECT_SIZE_AVX2 * chunks_256 + 
             VECT_SIZE_SSE * chunks_128; j < n; j++ ) {
        c1 = vecAddition1[ j ] ^ ( * ptr2 );
        c2 = vecAddition2[ j ] ^ ( * ptr2 );
        ptr2++;
        dist1 += popcount_32( c1 );
        dist2 += popcount_32( c2 );
      }

    dist = ( dist1 <= dist2 ? dist1 : dist2 );
    if( ( i == 0 )||( ( dist != 0 )&&( dist < minDist ) ) ) {
      minDist = dist;
    }

  }

  if( chunks_512 ) {
    free( vecAddition1Vec_512 );
    free( vecAddition2Vec_512 );
  }
  if( chunks_256 ) {
    free( vecAddition1Vec_256 );
    free( vecAddition2Vec_256 );
  }
  if( chunks_128 ) {
    free( vecAddition1Vec_128 );
    free( vecAddition2Vec_128 );
  }

#endif

#else // VECT

  // Usual algorithm.
  minDist = 0;
  for( i = 0; i < k; i++ ) {
    dist1 = 0;
    dist2 = 0;
    uint32_t* ptrGamma = & gammaMatrices[ rowStride * i + 0 ];
    for( j = 0; j < n; j++ ) {
      int ge = * ptrGamma;
      c1 = vecAddition1[ j ] ^ ge;
      dist1 += count_ones_in_uint32_with_precomputing( c1 );
      c2 = vecAddition2[ j ] ^ ge;
      dist2 += count_ones_in_uint32_with_precomputing( c2 );
      ptrGamma++;
    }
    if( ( dist1 != 0 )&&( ( minDist <= 0 )||( dist1 < minDist ) ) ) {
      minDist = dist1;
    }
    if( ( dist2 != 0 )&&( ( minDist <= 0 )||( dist2 < minDist ) ) ) {
      minDist = dist2;
    }
  }

#endif

  return( minDist );
}



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
#include "libOTe/Tools/LDPC/Algo994/constant_defs.h"
#include "libOTe/Tools/LDPC/Algo994/count_combinations.h"
#include "libOTe/Tools/LDPC/Algo994/utils.h"
#include "libOTe/Tools/LDPC/Algo994/computing_kernels.h"
#include "libOTe/Tools/LDPC/Algo994/alg_stack.h"


// ============================================================================
// Declaration of local prototypes.

static int get_next_combination_and_update_stack_by_using_prefix(
    int * vecCombi, int numTotalElems, int numElemsToTake,
    uint32_t * matAddCombis, uint32_t * aGammaMatrix, int rowStride,
    uint32_t * vecAdditionPrefix );



// ============================================================================
int generate_with_stack_alg(
    GammaMatrix g,
    int numTotalElems, int numElemsToTake,
    int printMethod ) {
//
// Stack-based algorithm with some optimizations.
// Combinations of numTotalElems taken numElemsToTake-1 at a time are employed
// instead of combinations taken numElemsToTake at a time.
//
  uint32_t  * vecAddition;
  int       minDist;

  if( printMethod == 1 ) {
    printf( "    generate_with_stack_alg\n" );
  }

  // Quick return.
  if( ( numTotalElems <= 0 )||( numElemsToTake <= 0 ) ) {
    return 0;
  }

  // Create the vector for storing the addition of combinations.
  create_aligned_uint32_vector( "generate_with_stack_alg",
      & vecAddition, g.rowStride );

  // Initialize the vector for storing the addition of combinations to zero.
  set_uint32_vector_to_zero( vecAddition, g.rowStride );

  // Generate and process combinations.
  minDist = process_prefix_with_stack_alg(
                g,
                numTotalElems, numElemsToTake,
                -1, vecAddition, printMethod );

  // Remove the vector with the addition of combinations.
  free( vecAddition );

  // Return minimum distance.
  return( minDist );
}

// ============================================================================
int process_prefix_with_stack_alg(
    GammaMatrix g,
    int numTotalElems, int numElemsToTake,
    int lastValueInPrefix, uint32_t * vecAdditionPrefix,
    int printMethod ) {
//
// Process a prefix (a combination with fewer elements) with stack
// algorithm.
// It generates every combination starting with "lastValueInPrefix" + 1,
// and "vecAdditionPrefix" is added to the addition of every combination.
//
// If lastValueInPrefix is 5, all combinations starting with 6 will be
// generated. Vector vecAdditionPrefix will be added to the addition of
// all those combinations.
//
  uint32_t  * vecAdditionAux, * matAddCombis;
  int       * vecCombi,
            i, iStart, iMatStart, done, minDist, dist, numElemsToTakeMinusOne;

  if( printMethod == 1 ) {
    printf( "    process_prefix_with_stack_alg\n" );
  }

  // Check input arguments.
  check_condition_is_true( numTotalElems == g.numRows,
      "process_prefix_with_basic_alg",
      "dimensions in input arguments do not match" );

  // Quick return.
  if( ( numTotalElems <= 0 )||( numElemsToTake <= 0 ) ) {
    return 0;
  }

  // Create the auxiliary vector for storing the addition of combinations.
  create_aligned_uint32_vector( "process_prefix_with_stack_alg",
      & vecAdditionAux, g.rowStride );

  // Some initializations.
  minDist = -1;

  if( numElemsToTake == 1 ) {
    //
    // Simple case: Only one element in combinations.
    //
    //// printf( "    Alg_stack. then: Simple case\n" );

    // Copy vecAdditionPrefix into vecAdditionAux.
    copy_uint32_vector( g.rowStride, vecAdditionAux, vecAdditionPrefix );

    // Add the rows of combination.
    iStart      = lastValueInPrefix + 1;
    iMatStart = ( iStart < g.numRows ? iStart : g.numRows - 1 );
    dist = add_every_row_to_uint32_vector_and_compute_distance(
               g.numRows - iStart, g.actualNumCols,
               & g.buffer[ g.rowStride * iMatStart ], g.rowStride,
               vecAdditionAux );

    // Update minimum distance.
    if( ( dist > 0 )&&( ( minDist == -1 )||( dist < minDist ) ) ) {
      minDist = dist;
    }

  } else {
    //
    // Usual case: More than one element in combinations.
    //
    //// printf( "    Alg_stack. else: Usual case\n" );

    // Some initialization.
    numElemsToTakeMinusOne = numElemsToTake - 1;

    // Create the vector for storing combinations.
    create_int_vector( "process_prefix_with_stack_alg",
        & vecCombi, numElemsToTakeMinusOne );

    // Initialize the vector with combinations.
    init_vector_with_combinations( lastValueInPrefix, vecCombi,
        numElemsToTakeMinusOne );

    // Create matrix for storing the addition of combinations.
    create_aligned_uint32_vector( "process_prefix_with_stack_alg",
        & matAddCombis, numElemsToTakeMinusOne * g.rowStride );

    //
    // Generate and process all combinations taking one fewer element.
    //

    // Initialize matrix with additions of combinations.
    // Use vecAdditionPrefix.
    add_two_uint32_vectors( g.rowStride,
        & matAddCombis[ g.rowStride * 0 ],
        & g.buffer[ g.rowStride * vecCombi[ 0 ] ],
        vecAdditionPrefix );
    for( i = 1; i < numElemsToTakeMinusOne; i++ ) {
      add_two_uint32_vectors( g.rowStride,
          & matAddCombis[ g.rowStride * i ],
          & matAddCombis[ g.rowStride * ( i - 1 ) ],
          & g.buffer[ g.rowStride * vecCombi[ i ] ] );
    }

    // Main loop.
    done = 0;
    while( ! done ) {
#ifdef PRINT_COMBINATIONS
      print_int_vector( "  i_combi", vecCombi, numElemsToTakeMinusOne );
#endif

      // New processing: Employ combinations with one fewer element.

      // Evaluate all the combinations of numElemsToTake elements derived
      // from the combination with one fewer element.
      iStart = vecCombi[ numElemsToTakeMinusOne - 1 ] + 1;
      dist = add_every_row_to_uint32_vector_and_compute_distance(
                 numTotalElems - iStart, g.actualNumCols,
                 & g.buffer[ g.rowStride * iStart ], g.rowStride,
                 & matAddCombis[ g.rowStride *
                                 ( numElemsToTakeMinusOne - 1 ) ] );

      // Update minimum distance.
      if( ( dist > 0 )&&( ( minDist == -1 )||( dist < minDist ) ) ) {
        minDist = dist;
      }

      // Get new combination.
      done = get_next_combination_and_update_stack_by_using_prefix(
                 vecCombi, numTotalElems - 1, numElemsToTakeMinusOne,
                 matAddCombis, g.buffer, g.rowStride,
                 vecAdditionPrefix );
    }

    // Remove the matrix with the addition of combinations.
    free( matAddCombis );

    // Remove the vector for storing combinations.
    free( vecCombi );
  }

  // Remove the auxiliary vector with the addition of combinations.
  free( vecAdditionAux );

  // Return minimum distance.
  return( minDist );
}

// ============================================================================
static int get_next_combination_and_update_stack_by_using_prefix(
    int * vecCombi, int numTotalElems, int numElemsToTake,
    uint32_t * matAddCombis, uint32_t * aGammaMatrix, int rowStride,
    uint32_t * vecAdditionPrefix ) {
// Get new combination.
  int  diff, i, j, jStart, processedAll;

  //// printf( "get_next_combination_and_update_stack_by_using_prefix\n" );
  diff = numTotalElems - numElemsToTake;
  i = numElemsToTake;
  do {
    i--;
    vecCombi[ i ]++;
  } while( ( i > 0 )&&( vecCombi[ i ] > ( i + diff ) ) );
  for( j = i + 1; j < numElemsToTake; j++ ) {
    vecCombi[ j ] = vecCombi[ j - 1 ] + 1;
  }
  processedAll = ( vecCombi[ 0 ] > numTotalElems - numElemsToTake );

  // Rebuild matAddCombis from position "i".
  if( i <= 0 ) {
    add_two_uint32_vectors( rowStride,
        & matAddCombis[ rowStride * 0 ],
        & aGammaMatrix[ rowStride * vecCombi[ 0 ] ],
        vecAdditionPrefix );
  }
  jStart = ( i > 1 ? i : 1 );
  for( j = jStart; j < numElemsToTake; j++ ) {
    add_two_uint32_vectors( rowStride, & matAddCombis[ rowStride * j ],
        & matAddCombis[ rowStride * ( j - 1 ) ],
        & aGammaMatrix[ rowStride * vecCombi[ j ] ] );
  }

  return( processedAll );
}

#if 0
// ============================================================================
static int get_next_combination_and_update_stack(
    int * vecCombi, int numTotalElems, int numElemsToTake,
    int * matAddCombis, int * aGammaMatrix, int rowStride ) {
// Get new combination.
  int  diff, i, j, jStart, processedAll;

  //// printf( "get_next_combination_and_update_stack\n" );
  diff = numTotalElems - numElemsToTake;
  i = numElemsToTake;
  do {
    i--;
    vecCombi[ i ]++;
  } while( ( i > 0 )&&( vecCombi[ i ] > ( i + diff ) ) );
  for( j = i + 1; j < numElemsToTake; j++ ) {
    vecCombi[ j ] = vecCombi[ j - 1 ] + 1;
  }
  processedAll = ( vecCombi[ 0 ] > numTotalElems - numElemsToTake );

  // Rebuild matAddCombis from position "i".
  copy_uint32_vector( rowStride,
      & matAddCombis[ rowStride * 0 ],
      & aGammaMatrix[ rowStride * vecCombi[ 0 ] ] );
  jStart = ( i > 1 ? i : 1 );
  for( j = jStart; j < numElemsToTake; j++ ) {
    add_two_uint32_vectors( rowStride, & matAddCombis[ rowStride * j ],
        & matAddCombis[ rowStride * ( j - 1 ) ],
        & aGammaMatrix[ rowStride * vecCombi[ j ] ] );
  }

  return( processedAll );
}
#endif


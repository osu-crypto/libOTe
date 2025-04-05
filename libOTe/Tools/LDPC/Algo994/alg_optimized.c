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
#include "libOTe/Tools/LDPC/Algo994/computing_kernels.h"
#include "libOTe/Tools/LDPC/Algo994/utils.h"
#include "libOTe/Tools/LDPC/Algo994/count_combinations.h"
#include "libOTe/Tools/LDPC/Algo994/alg_common.h"
#include "libOTe/Tools/LDPC/Algo994/alg_optimized.h"


// ============================================================================
int generate_with_optimized_alg(
    GammaMatrix g,
    int numTotalElems, int numElemsToTake,
    int printMethod ) {
//
// Optimized algorithm.
// Combinations of numTotalElems taken numElemsToTake-1 at a time are employed
// instead of combinations taken numElemsToTake at a time.
//
  uint32_t  * vecAddition;
  int       minDist;

  if( printMethod == 1 ) {
    printf( "    generate_with_optimized_alg\n" );
  }

  // Quick return.
  if( ( numTotalElems <= 0 )||( numElemsToTake <= 0 ) ) {
    return 0;
  }

  // Create the vector for storing the addition of combinations.
  create_aligned_uint32_vector( "generate_with_optimized_alg",
      & vecAddition, g.rowStride );

  // Initialize the vector for storing the addition of combinations to zero.
  set_uint32_vector_to_zero( vecAddition, g.rowStride );

  // Generate and process combinations.
  minDist = process_prefix_with_optimized_alg(
                g,
                numTotalElems, numElemsToTake,
                -1, vecAddition, printMethod );

  // Remove the vector with the addition of combinations.
  free( vecAddition );

  // Return minimum distance.
  return( minDist );
}

// ============================================================================
int process_prefix_with_optimized_alg(
    GammaMatrix g,
    int numTotalElems, int numElemsToTake,
    int lastValueInPrefix, uint32_t * vecAdditionPrefix,
    int printMethod ) {
//
// Process a prefix (a combination with fewer elements) with optimized
// algorithm.
// It generates every combination starting with "lastValueInPrefix" + 1,
// and "vecAdditionPrefix" is added to the addition of every combination.
//
// If lastValueInPrefix is 5, all combinations starting with 6 will be
// generated. Vector vecAdditionPrefix will be added to the addition of
// all those combinations.
//
  uint32_t  * vecAdditionAux;
  int       * vecCombi,
            iStart, iMatStart, done, minDist, dist, numElemsToTakeMinusOne;

  if( printMethod == 1 ) {
    printf( "    process_prefix_with_optimized_alg\n" );
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
  create_aligned_uint32_vector( "process_prefix_with_optimized_alg",
      & vecAdditionAux, g.rowStride );

  // Some initializations.
  minDist = -1;

  if( numElemsToTake == 1 ) {
    //
    // Simple case: Only one element in combinations.
    //
    //// printf( "    Alg_optimized. then: Simple case\n" );

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
    // Optimized processing: Employ combinations with one fewer element.
    //
    //// printf( "    Alg_optimized. else: Usual case\n" );

    // Some initialization.
    numElemsToTakeMinusOne = numElemsToTake - 1;

    // Create the vector for storing combinations.
    create_int_vector( "process_prefix_with_optimized_alg",
        & vecCombi, numElemsToTakeMinusOne );

    // Initialize the vector with combinations.
    init_vector_with_combinations( lastValueInPrefix, vecCombi,
        numElemsToTakeMinusOne );

    // Main loop to generate and process all combinations.
    done = 0;
    while( ! done ) {
#ifdef PRINT_COMBINATIONS
      print_int_vector( "  i_combi", vecCombi, numElemsToTakeMinusOne );
#endif

      // Copy vecAdditionPrefix into vecAdditionAux.
      copy_uint32_vector( g.rowStride, vecAdditionAux, vecAdditionPrefix );

      // Add the rows of combination.
      accumulate_uint32_vector_and_selected_rows( g.numRows, g.actualNumCols,
          numElemsToTakeMinusOne, g.buffer, g.rowStride,
          vecAdditionAux, vecCombi );

      // Evaluate all the combinations of numElemsToTake elements
      // from the combinations with one fewer element.
      iStart      = vecCombi[ numElemsToTakeMinusOne - 1 ] + 1;
      iMatStart = ( iStart < g.numRows ? iStart : g.numRows - 1 );
      dist = add_every_row_to_uint32_vector_and_compute_distance(
                 numTotalElems - iStart, g.actualNumCols,
                 & g.buffer[ g.rowStride * iMatStart ], g.rowStride,
                 vecAdditionAux );

      // Update minimum distance.
      if( ( dist > 0 )&&( ( minDist == -1 )||( dist < minDist ) ) ) {
        minDist = dist;
      }

      // Get new combination.
      done = get_next_combination( vecCombi, numTotalElems - 1,
                 numElemsToTakeMinusOne );
    }

    // Remove the vector for storing combinations.
    free( vecCombi );
  }

  // Remove the auxiliary vector with the addition of combinations.
  free( vecAdditionAux );

  // Return minimum distance.
  return( minDist );
}



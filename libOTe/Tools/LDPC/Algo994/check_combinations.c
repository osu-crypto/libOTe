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
#include <inttypes.h>
#include <omp.h>
#include "libOTe/Tools/LDPC/Algo994/utils.h"
#include "libOTe/Tools/LDPC/Algo994/alg_common.h"
#include "libOTe/Tools/LDPC/Algo994/computing_kernels.h"
#include "libOTe/Tools/LDPC/Algo994/check_combinations.h"


// ============================================================================
// Declaration of local variables.

static int       _numTotalElems, _numElemsToTake;
static uint32_t  * _aGammaMatrix;
static int       _numRows, _actualNumCols, _rowStride;
static int       _vecCombi[ 2048 ];
static int       _done;
static uint64_t  _numCheckedCombinations;


// ============================================================================
// Declaration of local prototypes.

static void next_combination_in_check_combinations();


// ============================================================================
void init_check_combinations( int numTotalElems, int numElemsToTake,
    uint32_t * aGammaMatrix, int numRows, int actualNumCols, int rowStride ) {
//
// Initialize the module to check combinations.
//

  // Save arguments.
  _numTotalElems  = numTotalElems;
  _numElemsToTake = numElemsToTake;
  _aGammaMatrix   = aGammaMatrix;
  _numRows        = numRows;
  _actualNumCols  = actualNumCols;
  _rowStride      = rowStride;

  // Some initializations.
  _done = 0;

  // Initialize vector with combinations.
  init_vector_with_combinations( -1, _vecCombi, _numElemsToTake );

  // Print initial message.
  printf( "init_check_combinations: %d %d %d %d %d \n",
          _numTotalElems, _numElemsToTake, _numRows, _actualNumCols,
          _rowStride );
}

// ============================================================================
void init_num_checked_combinations_in_check_combinations() {
//
// Initialize the number of checked combinations.
//
  _numCheckedCombinations = 0;
}

// ============================================================================
void print_num_checked_combinations_in_check_combinations() {
//
// Print the number of checked combinations.
//
  printf( "Number of total combinations checked:   %" PRId64 "\n\n",
          _numCheckedCombinations );
}

// ============================================================================
void check_current_addition_in_check_combinations(
    uint32_t * vecAddCurrentCombi, int numElems ) {
//
// Check current combination.
//
  uint32_t  * vecAddition;
  int       equal;

  check_condition_is_true( ! omp_in_parallel(),
      "check_current_addition_in_check_combinations",
      "Checking combinations in OpenMP parallel mode" );

  create_aligned_uint32_vector( "check_current_addition_in_check_combinations",
      & vecAddition, _rowStride );

  add_selected_rows( _numRows, _actualNumCols, _numElemsToTake,
      _aGammaMatrix, _rowStride,
      vecAddition, _vecCombi );

/*
  print_uint32_vector_as_bin( "addition of current combi             ",
      vecAddCurrentCombi, numElems );
  print_uint32_vector_as_bin( "stored current addition of combination",
      vecAddition, _actualNumCols );
  print_int_vector( "stored current combination", _vecCombi, _numElemsToTake );

  printf( "Equal: %d\n", are_equal_uint32_vectors( numElems, vecAddCurrentCombi,
                                                   vecAddition ) );
*/
  equal = are_equal_uint32_vectors( numElems, vecAddCurrentCombi, vecAddition );
  //// printf( "Equal: %d\n", equal );
  check_condition_is_true( equal,
      "check_current_addition_in_check_combinations",
      "Found different additions" );

  next_combination_in_check_combinations();

  _numCheckedCombinations++;

  free( vecAddition );
}

// ============================================================================
static void next_combination_in_check_combinations() {
//
// Update the vector with combinations to store the next combination, and
// return a pointer to the vector storing the next combination.
//
  check_condition_is_true( ! _done,
      "next_combination_in_check_combinations",
      "Attempt to go beyond the last combination." );

  _done = get_next_combination( _vecCombi, _numTotalElems, _numElemsToTake );
/*
  if( _done ) {
    printf( "WARNING in next_combination_in_check_combinations: Found last combination\n" );
  }
*/
}

#if 0
// ============================================================================
int * get_current_combination_in_check_combinations() {
//
// Update the vector with combinations to store the next combination, and
// return a pointer to the vector storing the next combination.
//
  check_condition_is_true( ! _done,
      "get_current_combination_in_check_combinations",
      "Attempt to go beyond the last combination." );

  return( _vecCombi );
}
#endif



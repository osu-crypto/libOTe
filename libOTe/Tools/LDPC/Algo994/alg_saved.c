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
#include <omp.h>
#include "libOTe/Tools/LDPC/Algo994/constant_defs.h"
#include "libOTe/Tools/LDPC/Algo994/count_combinations.h"
#include "libOTe/Tools/LDPC/Algo994/computing_kernels.h"
#include "libOTe/Tools/LDPC/Algo994/utils.h"
#include "libOTe/Tools/LDPC/Algo994/data_defs.h"
#include "libOTe/Tools/LDPC/Algo994/alg_saved.h"


#undef EXPAND_RECURSION


// ============================================================================
// Declaration of local prototypes.

static int starting_index_of( int numTotalElems, int numElemsToTake,
    int lastDigit );

static int generate_with_saved_recursive(
    int cfg_num_saved_generators, int cfg_num_cores,
    SavedCombi * vecSavedCombi,
    int numTotalElems, int numElemsToTake,
    int lastValueInPrefix, uint32_t * vecAdditionPrefix,
    int printMethod,
    int level );

static int generate_with_saved_1_s(
    int cfg_num_saved_generators, int cfg_num_cores,
    SavedCombi * vecSavedCombi,
    int numTotalElems, int numElemsToTake,
    int lastValueInPrefix, uint32_t * vecAdditionPrefix,
    int printMethod );

#ifdef EXPAND_RECURSION
static int generate_with_saved_sp1_2s(
    int cfg_num_saved_generators, int cfg_num_cores,
    SavedCombi * vecSavedCombi,
    int numTotalElems, int numElemsToTake,
    int lastValueInPrefix, uint32_t * vecAdditionPrefix,
    int printMethod,
    int level );

static int generate_with_saved_2sp1_3s(
    int cfg_num_saved_generators, int cfg_num_cores,
    SavedCombi * vecSavedCombi,
    int numTotalElems, int numElemsToTake,
    int lastValueInPrefix, uint32_t * vecAdditionPrefix,
    int printMethod,
    int level );
#endif


// ============================================================================
int generate_with_saved_alg(
    int cfg_num_saved_generators, int cfg_num_cores,
    GammaMatrix g, SavedCombi * vecSavedCombi,
    int numTotalElems, int numElemsToTake,
    int printMethod ) {
//
// Saved algorithm.
//
  uint32_t  * vecAddition;
  int       minDist;

  if( printMethod == 1 ) {
    printf( "    generate_with_saved_alg\n" );
  }

  // Quick return.
  if( ( numTotalElems <= 0 )||( numElemsToTake <= 0 ) ) {
    return 0;
  }

  // Create the vector for storing the addition of combinations.
  create_aligned_uint32_vector( "generate_with_saved_alg",
      & vecAddition, g.rowStride );

  // Initialize the vector for storing the addition of combinations to zero.
  set_uint32_vector_to_zero( vecAddition, g.rowStride );

  // Generate and process combinations.
  minDist = process_prefix_with_saved_alg( cfg_num_saved_generators,
                cfg_num_cores,
                g, vecSavedCombi,
                numTotalElems, numElemsToTake,
                -1, vecAddition, printMethod );

  // Remove the vector with the addition of combinations.
  free( vecAddition );

  // Return minimum distance.
  return( minDist );
}

// ============================================================================
int process_prefix_with_saved_alg(
    int cfg_num_saved_generators, int cfg_num_cores,
    GammaMatrix g, SavedCombi * vecSavedCombi,
    int numTotalElems, int numElemsToTake,
    int lastValueInPrefix, uint32_t * vecAdditionPrefix,
    int printMethod ) {
//
// Process a prefix (a combination with fewer elements) with saved algorithm.
// It generates every combination starting with "lastValueInPrefix" + 1,
// and "vecAdditionPrefix" is added to the addition of every combination.
//
// If lastValueInPrefix is 5, all combinations starting with 6 will be
// generated. Vector vecAdditionPrefix will be added to the addition of
// all those combinations.
//
  int  minDist;

  if( printMethod == 1 ) {
    printf( "    process_prefix_with_saved_alg\n" );
  }

  // Check input arguments.
  check_condition_is_true( numTotalElems == g.numRows,
      "process_prefix_with_saved_alg",
      "dimensions in input arguments do not match" );

  // Quick return.
  if( ( numTotalElems <= 0 )||( numElemsToTake <= 0 ) ) {
    return 0;
  }

  // Choose the adequate method according to the number of current
  // elements to take.
  if( numElemsToTake <= cfg_num_saved_generators ) {
    // Data savings must be taken advantage of,
    // with one addition of two saved cases.

    // First, fill saved structures, if needed.
    fill_structures_for_saved_data_for_1_s(
        cfg_num_saved_generators,
        g, vecSavedCombi,
        numTotalElems, numElemsToTake,
        printMethod );
  }

  minDist = generate_with_saved_recursive(
                cfg_num_saved_generators, cfg_num_cores,
                vecSavedCombi,
                numTotalElems, numElemsToTake,
                lastValueInPrefix, vecAdditionPrefix,
                printMethod,
                0 ); // level

  // Return minimum distance.
  return( minDist );
}

// ============================================================================
void fill_structures_for_saved_data_for_1_s(
    int cfg_num_saved_generators,
    GammaMatrix g, SavedCombi * vecSavedCombi,
    int numTotalElems, int numElemsToTake,
    int printMethod ) {
//
// Algorithm to fill saved data structures for cases 1..s.
//
  uint32_t    * ptrRowA, * ptrRowB, * ptrRowC;
  int         a, b, i, j, iStart, iEnd, jStart, jEnd, idxInAdd;
  SavedCombi  * ptrSavedA, * ptrSavedB, * ptrSavedC;

  if( printMethod == 1 ) {
    printf( "    fill_structures_for_saved_data_for_1_s\n" );
  }

  // Check input arguments.
  check_condition_is_true( ( 0 < numElemsToTake )&&
                           ( numElemsToTake <= cfg_num_saved_generators ),
      "fill_structures_for_saved_data_for_1_s",
      "Invalid numElemsToTake" );

  // Check whether the data structure has already been filled.
  ptrSavedC = & vecSavedCombi[ numElemsToTake - 1 ];
  if( ptrSavedC->filled == 0 ) {

    // Set filled field.
    ptrSavedC->filled++;

    // Set actualNumColsMat field.
    ptrSavedC->actualNumColsMat = g.actualNumCols;

    if( numElemsToTake == 1 ) {
      // Simple case: Only one element.

      // Save Gamma matrix inside data structure.
      copy_uint32_matrix( g.numRows, g.actualNumCols, g.rowStride,
          ptrSavedC->matAdditions, g.buffer );
      // Set the vector with last digits.
      init_vector_with_combinations( -1, ptrSavedC->vecLastDigits,
          g.numRows );

    } else {
      // Advanced case: More than one element.

      // Compute the two previous cases to use to build this one.
      a = numElemsToTake - 1;
      b = 1;

      // Check values of a and b.
      check_condition_is_true( ( 0 < a )&&( a <= cfg_num_saved_generators )&&
                               ( 0 < b )&&( b <= cfg_num_saved_generators ),
          "fill_structures_for_saved_data_for_1_s",
          "Invalid values of a or b or both" );
      // Check that data structures for a and b are already filled.
      check_condition_is_true( ( vecSavedCombi[ a-1 ].filled > 0 )&&
                               ( vecSavedCombi[ b-1 ].filled > 0 ),
          "fill_structures_for_saved_data_for_1_s",
          "Data structure not filled for a, for b or for both" );

      // Compute and save contents of matAdditions and vecLastDigits.
      ptrSavedA = & vecSavedCombi[ a - 1 ];
      ptrSavedB = & vecSavedCombi[ b - 1 ];
      iStart    = 0;
      iEnd      = ptrSavedA->numCombinations;
      idxInAdd  = 0;
      for( i = iStart; i < iEnd; i++ ) {

        // Process element only if there is enough "room".
        if( ( ptrSavedA->vecLastDigits[ i ] + b ) < numTotalElems ) {

          ptrRowA = & ptrSavedA->matAdditions[ g.rowStride * i ];
          jStart = starting_index_of( g.numRows, b,
                                      ptrSavedA->vecLastDigits[ i ] );
          jEnd   = ptrSavedB->numCombinations;
          for( j = jStart; j < jEnd; j++ ) {

            // Compute addition of ptrRowA and ptrRowB and save it into
            // matAdditions.
            ptrRowB = & ptrSavedB->matAdditions[ g.rowStride * j ];
            ptrRowC = & ptrSavedC->matAdditions[ g.rowStride * idxInAdd ];
            add_two_uint32_vectors( g.actualNumCols, ptrRowC, ptrRowA, ptrRowB );

            // Save last digit and addition into vecLastDigits.
            ptrSavedC->vecLastDigits[ idxInAdd ] =
                ptrSavedB->vecLastDigits[ j ];

            idxInAdd++;
          }
        }
      }
    }
  }
}

// ============================================================================
static int starting_index_of( int numTotalElems, int numElemsToTake,
    int lastDigit ) {
// Compute the row index inside the matrix that stores combinations where the
// combinations starting with "lastDigit + 1" are stored.
//   numTotalElems:  Number of total elements.
//   numElemsToTake: Number of elements to take.
//   lastDigit:      Last digit.
  int  result;

  if( lastDigit < 0 ) {
    result = 0;
  } else if( lastDigit >= ( numTotalElems - numElemsToTake ) ) {
    result = get_num_combinations( numTotalElems, numElemsToTake );
  } else {
    result = get_num_combinations( numTotalElems, numElemsToTake ) -
             get_num_combinations( numTotalElems - lastDigit - 1,
                                   numElemsToTake );
  }
  //// printf( "starting_index_of. numTotalEl: %d numElToTake: %d lDigit: %d\n",
  ////         numTotalElems, numElemsToTake, lastDigit );
  //// printf( "    result: %d \n", result );
  return( result );
}

// ============================================================================
static int generate_with_saved_recursive(
    int cfg_num_saved_generators, int cfg_num_cores,
    SavedCombi * vecSavedCombi,
    int numTotalElems, int numElemsToTake,
    int lastValueInPrefix, uint32_t * vecAdditionPrefix,
    int printMethod,
    int level ) {
//
// Algorithm with saved data by using a recursive method.
//
  uint32_t    * vecAddition, * ptrRowA;
  int         rowStride, actualNumCols,
              a, b, i, iStart, iEnd,
              minDist, dist, minDistThread, lastDigit;
  SavedCombi  * ptrSavedA;

  if( printMethod == 1 ) {
    for( i = 0; i < level; i++ ) {
      printf( "  " );
    }
    printf( "    generate_with_saved_recursive with cores: %d  %d %d\n",
            cfg_num_cores, level, numElemsToTake );
  }

  // Check input arguments.
  check_condition_is_true( numElemsToTake > 0,
      "generate_with_saved_recursive",
      "numElemsToTake is not > 1" );

  //
  // Check if only one call is enough.
  //
  if( numElemsToTake <= cfg_num_saved_generators ) {
    //
    // Only one call to 1..s method is enough.
    //
    minDist = generate_with_saved_1_s(
                  cfg_num_saved_generators, cfg_num_cores,
                  vecSavedCombi,
                  numTotalElems, numElemsToTake,
                  lastValueInPrefix, vecAdditionPrefix,
                  printMethod );

#ifdef EXPAND_RECURSION
  } else if( numElemsToTake <= 2 * cfg_num_saved_generators ) {
    //
    // Only one call to s+1..2s method is enough.
    //
    // This branch and routine "generate_with_saved_sp1_2s" could be removed,
    // and the code would work correctly and efficiently.
    // They have been added to make easier migrating to GPUs.
    minDist = generate_with_saved_sp1_2s(
                  cfg_num_saved_generators, cfg_num_cores,
                  vecSavedCombi,
                  numTotalElems, numElemsToTake,
                  lastValueInPrefix, vecAdditionPrefix,
                  printMethod,
                  level );

  } else if( numElemsToTake <= 3 * cfg_num_saved_generators ) {
    //
    // Only one call to 2s+1..3s method is enough.
    //
    // This branch and routine "generate_with_saved_2sp1_3s" could be removed,
    // and the code would work correctly and efficiently.
    // They have been added to make easier migrating to GPUs.
    minDist = generate_with_saved_2sp1_3s(
                  cfg_num_saved_generators, cfg_num_cores,
                  vecSavedCombi,
                  numTotalElems, numElemsToTake,
                  lastValueInPrefix, vecAdditionPrefix,
                  printMethod,
                  level );
#endif

  } else {
    //
    // One call is not enough: Recursive calls are required.
    //

    // Compute value a.
    if( numElemsToTake <= 2 * cfg_num_saved_generators ) {
      a = numElemsToTake - cfg_num_saved_generators;
    } else {
      a = cfg_num_saved_generators;
    }
    b = numElemsToTake - a;
    //// printf( "numElemsToTake: %d  a: %d  b: %d\n", numElemsToTake, a, b );

    // Check value a.
    check_condition_is_true( ( 0 < a )&&( a <= cfg_num_saved_generators ),
        "generate_with_saved_recursive",
        "Invalid a" );
    // Check that data structures for a are already filled.
    check_condition_is_true( vecSavedCombi[ a-1 ].filled > 0,
        "generate_with_saved_recursive",
        "Data structure not filled for a" );

    // Some initializations.
    minDist       = -1;

    ptrSavedA     = & vecSavedCombi[ a - 1 ];

    rowStride     = ptrSavedA->rowStrideMat;
    actualNumCols = ptrSavedA->actualNumColsMat;

    iStart        = starting_index_of( numTotalElems, a, lastValueInPrefix );
    iEnd          = ptrSavedA->numCombinations;

    // Parallel region.
    #pragma omp parallel \
        private( vecAddition, ptrRowA, dist, minDistThread, lastDigit ) \
        num_threads( cfg_num_cores ) \
        if( ( level == 0 )&&( cfg_num_cores > 1 ) )
    {
      // Set thread variable with global data.
      minDistThread = minDist;

      // Create the vector for storing the addition of combinations.
      create_aligned_uint32_vector( "generate_with_saved_recursive",
           & vecAddition, rowStride );

      #pragma omp for schedule( dynamic )
      for( i = iStart; i < iEnd; i++ ) {

        // Process element only if there are enough "room".
        lastDigit = ptrSavedA->vecLastDigits[ i ];
        if( ( lastDigit + b ) < numTotalElems ) {

          ptrRowA = & ptrSavedA->matAdditions[ rowStride * i ];

          // Compute the addition of prefix and current row.
          add_two_uint32_vectors( actualNumCols, vecAddition,
              vecAdditionPrefix, ptrRowA );

          // Recursive call.
          dist = generate_with_saved_recursive(
                     cfg_num_saved_generators, cfg_num_cores,
                     vecSavedCombi,
                     numTotalElems, b,
                     lastDigit, vecAddition,
                     0,
                     level + 1 );

          // Update minimum distance.
          if( ( dist > 0 )&&
              ( ( minDistThread == -1 )||( dist < minDistThread ) ) ) {
            minDistThread = dist;
          }
        }
      }

      // Update minimum distance.
      #pragma omp critical
      if( ( minDistThread > 0 )&&
          ( ( minDist == -1 )||( minDistThread < minDist ) ) ) {
        minDist = minDistThread;
      }

      // Remove the vector with the addition of combinations.
      free( vecAddition );
    }
  }

  // Return minimum distance.
  return( minDist );
}

// ============================================================================
static int generate_with_saved_1_s(
    int cfg_num_saved_generators, int cfg_num_cores,
    SavedCombi * vecSavedCombi,
    int numTotalElems, int numElemsToTake,
    int lastValueInPrefix, uint32_t * vecAdditionPrefix,
    int printMethod ) {
//
// Algorithm with saved data for cases 1..s.
// Simple case: Use the data structure just filled.
//
  uint32_t    * vecAddition;
  int         rowStride, actualNumCols,
              jStart, jEnd, jMatStart, minDist, dist;
  SavedCombi  * ptrSaved;

  if( printMethod == 1 ) {
    printf( "    generate_with_saved_1_s\n" );
  }

  // Check input arguments.
  check_condition_is_true( numElemsToTake <= cfg_num_saved_generators,
      "generate_with_saved_1_s",
      "Invalid numElemsToTake and cfg_num_saved_generators" );

  // Some initializations.
  minDist       = -1;

  ptrSaved      = & vecSavedCombi[ numElemsToTake - 1 ];
  rowStride     = ptrSaved->rowStrideMat;
  actualNumCols = ptrSaved->actualNumColsMat;

  // Create the vector for storing the addition of combinations.
  create_aligned_uint32_vector( "generate_with_saved_1_s",
       & vecAddition, rowStride );

  // Generate and test all combinations for one element.
  jStart    = starting_index_of( numTotalElems, numElemsToTake,
                                 lastValueInPrefix );
  jEnd      = ptrSaved->numCombinations;
  jMatStart = ( jStart < jEnd ? jStart : jEnd - 1 );
  copy_uint32_vector( actualNumCols, vecAddition, vecAdditionPrefix );
  dist = add_every_row_to_uint32_vector_and_compute_distance(
             jEnd - jStart, actualNumCols,
             & ptrSaved->matAdditions[ rowStride * jMatStart ], rowStride,
             vecAddition );

  // Update minimum distance.
  if( ( dist > 0 )&&( ( minDist == -1 )||( dist < minDist ) ) ) {
    minDist = dist;
  }

  // Remove the vector with the addition of combinations.
  free( vecAddition );

  // Return minimum distance.
  return( minDist );
}

#ifdef EXPAND_RECURSION
// ============================================================================
static int generate_with_saved_sp1_2s(
    int cfg_num_saved_generators, int cfg_num_cores,
    SavedCombi * vecSavedCombi,
    int numTotalElems, int numElemsToTake,
    int lastValueInPrefix, uint32_t * vecAdditionPrefix,
    int printMethod,
    int level ) {
//
// Algorithm with saved data for cases s+1..2*s.
//
  uint32_t    * vecAddition, * ptrRowA, * ptrRowB;
  int         rowStride, actualNumCols,
              a, b, i, iStart, iEnd, jStart, jEnd, jMatStart,
              minDist, dist, minDistThread, lastDigit;
  SavedCombi  * ptrSavedA, * ptrSavedB;

  if( printMethod == 1 ) {
    printf( "    generate_with_saved_sp1_2s with cores: %d\n",
            cfg_num_cores );
  }

  // Check input arguments.
  check_condition_is_true( ( cfg_num_saved_generators < numElemsToTake )&&
                           ( numElemsToTake <= 2 * cfg_num_saved_generators ),
      "generate_with_saved_sp1_2s",
      "Invalid numElemsToTake and cfg_num_saved_generators" );
  check_condition_is_true( numElemsToTake > 1,
      "generate_with_saved_sp1_2s",
      "numElemsToTake is not > 1" );

  // Compute values a and b: the two previous cases used to compute this one.
  b = ( numElemsToTake + 1 ) / 2;
  a = numElemsToTake - b;
  //// printf( "numElemsToTake: %d a: %d b: %d\n", numElemsToTake, a, b );

  // Check values of a and b.
  check_condition_is_true( ( 0 < a )&&( a <= cfg_num_saved_generators )&&
                           ( 0 < b )&&( b <= cfg_num_saved_generators ),
      "generate_with_saved_sp1_2s",
      "Invalid values for a or b or both" );
  // Check that data structures for a and b are already filled.
  check_condition_is_true( ( vecSavedCombi[ a-1 ].filled > 0 )&&
                           ( vecSavedCombi[ b-1 ].filled > 0 ),
      "generate_with_saved_sp1_2s",
      "Data structure not filled for a or b or both" );

  // Check that double parallelization is not applied.
  check_condition_is_true( ( ! omp_in_parallel() )||( level != 0 ),
      "generate_with_saved_sp1_2s",
      "Already inside an OpenMP parallel area" );

  // Some initializations.
  minDist       = -1;

  ptrSavedA     = & vecSavedCombi[ a - 1 ];
  ptrSavedB     = & vecSavedCombi[ b - 1 ];

  rowStride     = ptrSavedA->rowStrideMat;
  actualNumCols = ptrSavedA->actualNumColsMat;

  iStart        = starting_index_of( numTotalElems, a, lastValueInPrefix );
  iEnd          = ptrSavedA->numCombinations;

  // Parallel region.
  #pragma omp parallel \
      private( vecAddition, ptrRowA, ptrRowB, dist, minDistThread, \
               lastDigit, jStart, jEnd, jMatStart ) \
      num_threads( cfg_num_cores ) \
      if( ( level == 0 )&&( cfg_num_cores > 1 ) )
  {
    // Set thread variable with global data.
    minDistThread = minDist;

    // Create the vector for storing the addition of combinations.
    create_aligned_uint32_vector( "generate_with_saved_sp1_2s",
         & vecAddition, rowStride );

    #pragma omp for schedule( dynamic )
    for( i = iStart; i < iEnd; i++ ) {

      // Process element only if there are enough "room".
      lastDigit = ptrSavedA->vecLastDigits[ i ];
      if( ( lastDigit + b ) < numTotalElems ) {

        ptrRowA = & ptrSavedA->matAdditions[ rowStride * i ];

        // Compute the addition of two cases and save it into vecAddition.
        add_two_uint32_vectors( actualNumCols, vecAddition,
            vecAdditionPrefix, ptrRowA );

        // Evaluate all the combinations of numElemsToTake elements derived
        // from the combination with one fewer element.
        jStart    = starting_index_of( numTotalElems, b, lastDigit );
        jEnd      = ptrSavedB->numCombinations;
        jMatStart = ( jStart < jEnd ? jStart : jEnd - 1 );
        ptrRowB   = & ptrSavedB->matAdditions[ rowStride * jMatStart ];
        dist = add_every_row_to_uint32_vector_and_compute_distance(
                   jEnd - jStart, actualNumCols,
                   ptrRowB, rowStride,
                   vecAddition );

        // Update minimum distance.
        if( ( dist > 0 )&&
            ( ( minDistThread == -1 )||( dist < minDistThread ) ) ) {
          minDistThread = dist;
        }
      }
    }

    // Update minimum distance.
    #pragma omp critical
    if( ( minDistThread > 0 )&&
        ( ( minDist == -1 )||( minDistThread < minDist ) ) ) {
      minDist = minDistThread;
    }

    // Remove the vector with the addition of combinations.
    free( vecAddition );
  }

  // Return minimum distance.
  return( minDist );
}

// ============================================================================
static int generate_with_saved_2sp1_3s(
    int cfg_num_saved_generators, int cfg_num_cores,
    SavedCombi * vecSavedCombi,
    int numTotalElems, int numElemsToTake,
    int lastValueInPrefix, uint32_t * vecAdditionPrefix,
    int printMethod,
    int level ) {
//
// Algorithm with saved data for cases 2*s+1..3*s.
//
  uint32_t    * vecAdditionI, * vecAdditionJ,
              * ptrRowA, * ptrRowB, * ptrRowC;
  int         rowStride, actualNumCols,
              a, b, c,
              i, iStart, iEnd, iLastDigit,
              j, jStart, jEnd, jLastDigit,
              kStart, kEnd, kMatStart,
              minDist, dist, minDistThread;
  SavedCombi  * ptrSavedA, * ptrSavedB, * ptrSavedC;

  if( printMethod == 1 ) {
    printf( "    generate_with_saved_2sp1_3s with cores: %d\n",
            cfg_num_cores );
  }

  // Check input arguments.
  check_condition_is_true( ( 2 * cfg_num_saved_generators < numElemsToTake )&&
                           ( numElemsToTake <= 3 * cfg_num_saved_generators ),
      "generate_with_saved_2sp1_3s",
      "Invalid numElemsToTake and cfg_num_saved_generators" );
  check_condition_is_true( numElemsToTake > 1,
      "generate_with_saved_2sp1_3s",
      "numElemsToTake is not > 1" );

  // Compute values a, b, and c: the previous cases used to compute this one.
  a = cfg_num_saved_generators;
  c = cfg_num_saved_generators;
  b = numElemsToTake - a - c;
  //// printf( "numElemsToTake: %d a: %d b: %d c: %d\n",numElemsToTake,a,b,c);

  // Check values of a, b, and c.
  check_condition_is_true( ( 0 < a )&&( a <= cfg_num_saved_generators )&&
                           ( 0 < b )&&( b <= cfg_num_saved_generators )&&
                           ( 0 < c )&&( c <= cfg_num_saved_generators ),
      "generate_with_saved_2sp1_3s",
      "Invalid values for a or b or c or both" );
  // Check that data structures for a and b are already filled.
  check_condition_is_true( ( vecSavedCombi[ a - 1 ].filled > 0 )&&
                           ( vecSavedCombi[ b - 1 ].filled > 0 )&&
                           ( vecSavedCombi[ c - 1 ].filled > 0 ),
      "generate_with_saved_2sp1_3s",
      "Data structure not filled for a or b or c or both" );

  // Check that double parallelization is not applied.
  check_condition_is_true( ( ! omp_in_parallel() )||( level != 0 ),
      "generate_with_saved_2sp1_3s",
      "Already inside an OpenMP parallel area" );

  // Some initializations.
  minDist       = -1;

  ptrSavedA     = & vecSavedCombi[ a - 1 ];
  ptrSavedB     = & vecSavedCombi[ b - 1 ];
  ptrSavedC     = & vecSavedCombi[ c - 1 ];

  rowStride     = ptrSavedA->rowStrideMat;
  actualNumCols = ptrSavedA->actualNumColsMat;

  iStart        = starting_index_of( numTotalElems, a, lastValueInPrefix );
  iEnd          = ptrSavedA->numCombinations;

  // Parallel region.
  #pragma omp parallel \
      private( vecAdditionI, vecAdditionJ, ptrRowA, ptrRowB, ptrRowC, \
               iLastDigit, j, jLastDigit, jStart, jEnd, \
               kStart, kEnd, kMatStart, \
               dist, minDistThread ) \
      num_threads( cfg_num_cores ) \
      if( ( level == 0 )&&( cfg_num_cores > 1 ) )
  {
    // Set thread variable with global data.
    minDistThread = minDist;

    // Create the vectors for storing the addition of combinations.
    create_aligned_uint32_vector( "generate_with_saved_2sp1_3s",
         & vecAdditionI, rowStride );
    create_aligned_uint32_vector( "generate_with_saved_2sp1_3s",
         & vecAdditionJ, rowStride );

    #pragma omp for schedule( dynamic )
    for( i = iStart; i < iEnd; i++ ) {

      // Process element only if there are enough "room".
      iLastDigit = ptrSavedA->vecLastDigits[ i ];
      if( ( iLastDigit + b + c ) < numTotalElems ) {

        ptrRowA = & ptrSavedA->matAdditions[ rowStride * i ];

        // Compute the addition of two cases and save it into vecAddition.
        add_two_uint32_vectors( actualNumCols, vecAdditionI,
            vecAdditionPrefix, ptrRowA );

        jStart = starting_index_of( numTotalElems, b, iLastDigit );
        jEnd   = ptrSavedB->numCombinations;
        for( j = jStart; j < jEnd; j++ ) {

          ptrRowB = & ptrSavedB->matAdditions[ rowStride * j ];

          // Process element only if there are enough "room".
          jLastDigit = ptrSavedB->vecLastDigits[ j ];
          if( ( jLastDigit + c ) < numTotalElems ) {

            // Compute the addition of two cases and save it into vecAddition.
            add_two_uint32_vectors( actualNumCols, vecAdditionJ,
                vecAdditionI, ptrRowB );

            // Evaluate all the combinations of numElemsToTake elements derived
            // from the combination with one fewer element.
            kStart    = starting_index_of( numTotalElems, c, jLastDigit );
            kEnd      = ptrSavedC->numCombinations;
            kMatStart = ( kStart < kEnd ? kStart : kEnd - 1 );
            ptrRowC   = & ptrSavedC->matAdditions[ rowStride * kMatStart ];
            dist = add_every_row_to_uint32_vector_and_compute_distance(
                       kEnd - kStart, actualNumCols,
                       ptrRowC, rowStride,
                       vecAdditionJ );

            // Update minimum distance.
            if( ( dist > 0 )&&
                ( ( minDistThread == -1 )||( dist < minDistThread ) ) ) {
              minDistThread = dist;
            }
          }
        }
      }
    }

    // Update minimum distance.
    #pragma omp critical
    if( ( minDistThread > 0 )&&
        ( ( minDist == -1 )||( minDistThread < minDist ) ) ) {
      minDist = minDistThread;
    }

    // Remove the vectors with the addition of combinations.
    free( vecAdditionI );
    free( vecAdditionJ );
  }

  // Return minimum distance.
  return( minDist );
}
#endif


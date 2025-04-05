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
#include "libOTe/Tools/LDPC/Algo994/alg_saved_unrolled.h"


// ============================================================================
// Declaration of local prototypes.

static int starting_index_of( int numTotalElems, int numElemsToTake,
    int lastDigit );

static int generate_with_saved_recursive_level0(
    int cfg_num_saved_generators, int cfg_num_cores,
    SavedCombi * vecSavedCombi,
    int numTotalElems, int numElemsToTake,
    int lastValueInPrefix, uint32_t * vecAdditionPrefix,
    int printMethod );

static void generate_with_saved_recursive_level0_single_iteration(
    int cfg_num_saved_generators, int cfg_num_cores,
    SavedCombi * vecSavedCombi,
    int numTotalElems, int numElemsToTake,
    int lastValueInPrefix, uint32_t * vecAdditionPrefix,
    int printMethod,
    uint32_t * vecAddition,
    int a, int b,
    int idx,
    int * minDistThread );

static int generate_with_saved_recursive_on_two_vectors(
    int cfg_num_saved_generators, int cfg_num_cores,
    SavedCombi * vecSavedCombi,
    int numTotalElems, int numElemsToTake,
    int lastValueInPrefix,
    uint32_t * vecAdditionPrefix1, uint32_t * vecAdditionPrefix2,
    int printMethod,
    int level );

static int generate_with_saved_1_s_on_two_vectors(
    int cfg_num_saved_generators, int cfg_num_cores,
    SavedCombi * vecSavedCombi,
    int numTotalElems, int numElemsToTake,
    int lastValueInPrefix,
    uint32_t * vecAdditionPrefix1, uint32_t * vecAdditionPrefix2,
    int printMethod,
    int level );


// ============================================================================
int generate_with_saved_unrolled_alg(
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
    printf( "    generate_with_saved_unrolled_alg\n" );
  }

  // Quick return.
  if( ( numTotalElems <= 0 )||( numElemsToTake <= 0 ) ) {
    return 0;
  }

  // Create the vector for storing the addition of combinations.
  create_aligned_uint32_vector( "generate_with_saved_unrolled_alg",
      & vecAddition, g.rowStride );

  // Initialize the vector for storing the addition of combinations to zero.
  set_uint32_vector_to_zero( vecAddition, g.rowStride );

  // Generate and process combinations.
  minDist = process_prefix_with_saved_unrolled_alg( cfg_num_saved_generators,
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
int process_prefix_with_saved_unrolled_alg(
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
    printf( "    process_prefix_with_saved_unrolled_alg\n" );
  }

  // Check input arguments.
  check_condition_is_true( numTotalElems == g.numRows,
      "process_prefix_with_saved_unrolled_alg",
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
    fill_structures_for_saved_unrolled_data_for_1_s(
        cfg_num_saved_generators,
        g, vecSavedCombi,
        numTotalElems, numElemsToTake,
        printMethod );
  }

  minDist = generate_with_saved_recursive_level0(
                cfg_num_saved_generators, cfg_num_cores,
                vecSavedCombi,
                numTotalElems, numElemsToTake,
                lastValueInPrefix, vecAdditionPrefix,
                printMethod );

  // Return minimum distance.
  return( minDist );
}

// ============================================================================
void fill_structures_for_saved_unrolled_data_for_1_s(
    int cfg_num_saved_generators,
    GammaMatrix g, SavedCombi * vecSavedCombi,
    int numTotalElems, int numElemsToTake,
    int printMethod ) {
//
// Algorithm to fill saved data structures for cases 1..s.
//
  uint32_t    * ptrRowA, * ptrRowB, * ptrRowC;
  int         a, b, i, j, k, iStart, iEnd, jStart, jEnd, kStart, kEnd,
              idxInAdd;
  SavedCombi  * ptrSavedA, * ptrSavedB, * ptrSavedC;

  if( printMethod == 1 ) {
    printf( "    fill_structures_for_saved_unrolled_data_for_1_s\n" );
  }

  // Check input arguments.
  check_condition_is_true( ( 0 < numElemsToTake )&&
                           ( numElemsToTake <= cfg_num_saved_generators ),
      "fill_structures_for_saved_unrolled_data_for_1_s",
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
          "fill_structures_for_saved_unrolled_data_for_1_s",
          "Invalid values of a or b or both" );
      // Check that data structures for a and b are already filled.
      check_condition_is_true( ( vecSavedCombi[ a-1 ].filled > 0 )&&
                               ( vecSavedCombi[ b-1 ].filled > 0 ),
          "fill_structures_for_saved_unrolled_data_for_1_s",
          "Data structure not filled for a, for b or for both" );

/*
    #
    # Fill current SavedCombi with previous SavedCombi objects.
    #
    if( g == 1 ) :
      # Easy case: Assign contiguous elements.
      for i in range( 0, sc.numCombinations ) :
        sc.combi[ i ] = chr( ord( '0' ) + i )
    else :
      # Compose combinations in current object sc with previous objects.
      a = g - 1
      b = 1

      scA    = listSavedCombi[ a - 1 ]
      scB    = listSavedCombi[ b - 1 ]
      scC    = sc
      idxInC = 0
      for i in range( 0, numTotalElems - a ) :

        kStart = get_num_combinations( numTotalElems, a ) - \
                 get_num_combinations( numTotalElems - i, a )

        for j in range( a + i, numTotalElems ) :

          kEnd = kStart + get_num_combinations( j - i - 1, a - 1 )

          for k in range( kStart, kEnd ) :
            scC.combi[ idxInC ] = scA.combi[ k ] + scB.combi[ j ]
            idxInC = idxInC + 1

      if( idxInC != scC.numCombinations ) :
        print
        print 'ERROR in generate_lex_order: idxinC: ', idxInC, \
              ' scC.numCombinations:', scC.numCombinations
        print

    # Print current contents.
    sc.print_saved_combi()
*/

      // Compute and save contents of matAdditions and vecLastDigits.
      ptrSavedA = & vecSavedCombi[ a - 1 ];
      ptrSavedB = & vecSavedCombi[ b - 1 ];
      idxInAdd  = 0;
      iStart    = 0;
      iEnd      = numTotalElems - a;
      for( i = iStart; i < iEnd; i++ ) {

        kStart = get_num_combinations( numTotalElems, a ) -
                 get_num_combinations( numTotalElems - i, a );
        jStart = a + i;
        jEnd   = numTotalElems;

        for( j = jStart; j < jEnd; j++ ) {

          ptrRowB = & ptrSavedB->matAdditions[ g.rowStride * j ];
          kEnd = kStart + get_num_combinations( j - i - 1, a - 1 );

          for( k = kStart; k < kEnd; k++ ) {
            //// scC.combi[ idxInC ] = scA.combi[ k ] + scB.combi[ j ]

            // Compute addition of ptrRowA and ptrRowB and save it into
            // matAdditions.
            ptrRowA = & ptrSavedA->matAdditions[ g.rowStride * k ];
            ptrRowC = & ptrSavedC->matAdditions[ g.rowStride * idxInAdd ];
            add_two_uint32_vectors( g.actualNumCols, ptrRowC, ptrRowA, ptrRowB );

            // Save last digit and addition into vecLastDigits.
            ptrSavedC->vecLastDigits[ idxInAdd ] =
                ptrSavedB->vecLastDigits[ j ];

            idxInAdd++;
          }
        }
      }

      // Check values of a and b.
      check_condition_is_true( idxInAdd == ptrSavedC->numCombinations,
          "fill_structures_for_saved_unrolled_data_for_1_s",
          "Invalid number of processed combinations" );
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
static int generate_with_saved_recursive_level0(
    int cfg_num_saved_generators, int cfg_num_cores,
    SavedCombi * vecSavedCombi,
    int numTotalElems, int numElemsToTake,
    int lastValueInPrefix, uint32_t * vecAdditionPrefix,
    int printMethod ) {
//
// Algorithm with saved data by using a recursive method.
//
  uint32_t    * vecAdditionI, * vecAdditionIp1,
              * ptrRowAI, * ptrRowAIp1;
  int         rowStride, actualNumCols,
              a, b, i, iStart, iEnd, iNumIter, iRem,
              idxI, idxIp1, lastDigitI, lastDigitIp1,
              threadId, dist, minDist, minDistThread;
  SavedCombi  * ptrSavedA;
  //// double      t1, t2;

  if( printMethod == 1 ) {
    printf( "    generate_with_saved_recursive_level0 with cores: %d  %d\n",
            cfg_num_cores, numElemsToTake );
  }

  // Check input arguments.
  check_condition_is_true( numElemsToTake > 0,
      "generate_with_saved_recursive_level0",
      "numElemsToTake is not > 1" );

  //
  // Check if only one call is enough.
  //
  if( numElemsToTake <= cfg_num_saved_generators ) {
    //
    // Only one call to 1..s method is enough.
    //
    minDist = generate_with_saved_1_s_on_two_vectors(
                  cfg_num_saved_generators, cfg_num_cores,
                  vecSavedCombi,
                  numTotalElems, numElemsToTake,
                  lastValueInPrefix, vecAdditionPrefix, NULL,
                  printMethod,
                  1 ); // level

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
        "generate_with_saved_recursive_level0",
        "Invalid a" );
    // Check that data structures for a are already filled.
    check_condition_is_true( vecSavedCombi[ a-1 ].filled > 0,
        "generate_with_saved_recursive_level0",
        "Data structure not filled for a" );

    // Some initializations.
    minDist       = -1;

    ptrSavedA     = & vecSavedCombi[ a - 1 ];

    rowStride     = ptrSavedA->rowStrideMat;
    actualNumCols = ptrSavedA->actualNumColsMat;

    iStart        = starting_index_of( numTotalElems, a, lastValueInPrefix );
    iEnd          = ptrSavedA->numCombinations;
    iNumIter      = iEnd - iStart;
    iRem          = iNumIter % 2;

    // Parallel region.
    #pragma omp parallel \
        private( threadId, dist, minDistThread, \
                 idxI, idxIp1, \
                 lastDigitI, lastDigitIp1, \
                 vecAdditionI, vecAdditionIp1, \
                 ptrRowAI, ptrRowAIp1 ) \
        num_threads( cfg_num_cores ) \
        if( cfg_num_cores > 1 )
    {
      // Set thread id.
      threadId = omp_get_thread_num();

      // Set thread variable with global data.
      minDistThread = minDist;

      // Create the vectors for storing the addition of combinations.
      create_aligned_uint32_vector( "generate_with_saved_recursive_level0",
           & vecAdditionI, rowStride );
      create_aligned_uint32_vector( "generate_with_saved_recursive_level0",
           & vecAdditionIp1, rowStride );

      // Thread 0 processes remaining iteration, if needed.
      if( ( threadId == 0 )&&( iRem != 0 ) ) {
        idxI = iStart;
        generate_with_saved_recursive_level0_single_iteration(
            cfg_num_saved_generators, cfg_num_cores,
            vecSavedCombi,
            numTotalElems, numElemsToTake,
            lastValueInPrefix, vecAdditionPrefix,
            printMethod,
            vecAdditionI,
            a, b,
            idxI,
            & minDistThread );
      }

      #pragma omp for schedule( dynamic )
      for( i = iStart + iRem; i < iEnd; i += 2 ) {
        // Process two iterations of the old loop in each iteration.

        idxI   = i;
        idxIp1 = i + 1;

        lastDigitI   = ptrSavedA->vecLastDigits[ idxI   ];
        lastDigitIp1 = ptrSavedA->vecLastDigits[ idxIp1 ];

/*
        printf( "idxI: %4d  idxIp1: %4d  ", idxI, idxIp1 );
        printf( "lastDigitI: %3d lastDigitIp1: %3d  ",lastDigitI,lastDigitIp1);
        printf( "  %c\n", ( lastDigitI == lastDigitIp1 ? '*' : ' ' ) );
*/

        if( lastDigitI != lastDigitIp1 ) {
          // Last digit is different in the two iterations.
          generate_with_saved_recursive_level0_single_iteration(
              cfg_num_saved_generators, cfg_num_cores,
              vecSavedCombi,
              numTotalElems, numElemsToTake,
              lastValueInPrefix, vecAdditionPrefix,
              0, //// printMethod
              vecAdditionI,
              a, b,
              idxI,
              & minDistThread );

          generate_with_saved_recursive_level0_single_iteration(
              cfg_num_saved_generators, cfg_num_cores,
              vecSavedCombi,
              numTotalElems, numElemsToTake,
              lastValueInPrefix, vecAdditionPrefix,
              0, //// printMethod
              vecAdditionIp1,
              a, b,
              idxIp1,
              & minDistThread );

        } else {
          // Last digit is the same in the two iterations.
          // Process both iterations at the same time.

          ptrRowAI   = & ptrSavedA->matAdditions[ rowStride * idxI   ];
          ptrRowAIp1 = & ptrSavedA->matAdditions[ rowStride * idxIp1 ];

          // Process element only if there are enough "room".
          if( ( lastDigitI + b ) < numTotalElems ) {

            // Compute the addition of prefix and current row.
            add_two_uint32_vectors( actualNumCols, vecAdditionI,
                vecAdditionPrefix, ptrRowAI );
            add_two_uint32_vectors( actualNumCols, vecAdditionIp1,
                vecAdditionPrefix, ptrRowAIp1 );

            dist = generate_with_saved_recursive_on_two_vectors(
                       cfg_num_saved_generators, cfg_num_cores,
                       vecSavedCombi,
                       numTotalElems, b,
                       lastDigitI, vecAdditionI, vecAdditionIp1,
                       0, //// printMethod
                       1 ); // level

            // Update minimum distance.
            if( ( dist > 0 )&&
                ( ( minDistThread == -1 )||( dist < minDistThread ) ) ) {
              minDistThread = dist;
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
      free( vecAdditionIp1 );
    }
  }

  // Return minimum distance.
  return( minDist );
}

// ============================================================================
static void generate_with_saved_recursive_level0_single_iteration(
    int cfg_num_saved_generators, int cfg_num_cores,
    SavedCombi * vecSavedCombi,
    int numTotalElems, int numElemsToTake,
    int lastValueInPrefix, uint32_t * vecAdditionPrefix,
    int printMethod,
    uint32_t * vecAddition,
    int a, int b,
    int idx,
    int * minDistThread ) {
//
  uint32_t    * ptrRowA;
  int         lastDigit, rowStride, actualNumCols, dist;
  SavedCombi  * ptrSavedA;

  // Some initializations.
  ptrSavedA     = & vecSavedCombi[ a - 1 ];

  rowStride     = ptrSavedA->rowStrideMat;
  actualNumCols = ptrSavedA->actualNumColsMat;

  // Process element only if there are enough "room".
  lastDigit = ptrSavedA->vecLastDigits[ idx ];
  if( ( lastDigit + b ) < numTotalElems ) {

    ptrRowA = & ptrSavedA->matAdditions[ rowStride * idx ];

    // Compute the addition of prefix and current row.
    add_two_uint32_vectors( actualNumCols, vecAddition,
        vecAdditionPrefix, ptrRowA );

    // Recursive call.
    dist = generate_with_saved_recursive_on_two_vectors(
               cfg_num_saved_generators, cfg_num_cores,
               vecSavedCombi,
               numTotalElems, numElemsToTake - a,
               lastDigit, vecAddition, NULL,
               0, // printMethod
               1 ); // level

    // Update minimum distance.
    if( ( dist > 0 )&&
        ( ( * minDistThread == -1 )||( dist < * minDistThread ) ) ) {
      * minDistThread = dist;
    }
  }
}

// ============================================================================
static int generate_with_saved_recursive_on_two_vectors(
    int cfg_num_saved_generators, int cfg_num_cores,
    SavedCombi * vecSavedCombi,
    int numTotalElems, int numElemsToTake,
    int lastValueInPrefix,
    uint32_t * vecAdditionPrefix1, uint32_t * vecAdditionPrefix2,
    int printMethod,
    int level ) {
//
// Algorithm with saved data by using a recursive method.
// If vecAdditionPrefix2 != NULL, both vectors are processed.
// Otherwise, only vector vecAdditionPrefix1 is processed.
//
  uint32_t    * vecAddition1, * vecAddition2,
              * ptrRowA;
  int         rowStride, actualNumCols,
              a, b, i, iStart, iEnd,
              minDist, dist, lastDigit;
  SavedCombi  * ptrSavedA;

  if( printMethod == 1 ) {
    for( i = 0; i < level; i++ ) {
      printf( "  " );
    }
    printf( "    generate_with_saved_recursive_on_two_vectors with cores: %d  %d %d\n",
            cfg_num_cores, level, numElemsToTake );
  }

  // Check input arguments.
  check_condition_is_true( numElemsToTake > 0,
      "generate_with_saved_recursive_on_two_vectors",
      "numElemsToTake is not > 1" );

  //
  // Check if only one call is enough.
  //
  if( numElemsToTake <= cfg_num_saved_generators ) {
    //
    // Only one call to 1..s method is enough.
    //
    minDist = generate_with_saved_1_s_on_two_vectors(
                  cfg_num_saved_generators, cfg_num_cores,
                  vecSavedCombi,
                  numTotalElems, numElemsToTake,
                  lastValueInPrefix, vecAdditionPrefix1, vecAdditionPrefix2,
                  printMethod,
                  level + 1 );

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
        "generate_with_saved_recursive_on_two_vectors",
        "Invalid a" );
    // Check that data structures for a are already filled.
    check_condition_is_true( vecSavedCombi[ a-1 ].filled > 0,
        "generate_with_saved_recursive_on_two_vectors",
        "Data structure not filled for a" );

    // Some initializations.
    minDist       = -1;

    ptrSavedA     = & vecSavedCombi[ a - 1 ];

    rowStride     = ptrSavedA->rowStrideMat;
    actualNumCols = ptrSavedA->actualNumColsMat;

    iStart        = starting_index_of( numTotalElems, a, lastValueInPrefix );
    iEnd          = ptrSavedA->numCombinations;

    // Create the vectors for storing the addition of combinations.
    create_aligned_uint32_vector(
         "generate_with_saved_recursive_on_two_vectors",
         & vecAddition1, rowStride );
    if( vecAdditionPrefix2 != NULL ) {
      create_aligned_uint32_vector(
           "generate_with_saved_recursive_on_two_vectors",
           & vecAddition2, rowStride );
    } else {
      vecAddition2 = NULL;
    }

    // Main loop.
    for( i = iStart; i < iEnd; i++ ) {

      // Process element only if there are enough "room".
      lastDigit = ptrSavedA->vecLastDigits[ i ];
      if( ( lastDigit + b ) < numTotalElems ) {

        ptrRowA = & ptrSavedA->matAdditions[ rowStride * i ];

        // Compute the addition of prefix and current row.
        add_two_uint32_vectors( actualNumCols, vecAddition1,
            vecAdditionPrefix1, ptrRowA );
        if( vecAdditionPrefix2 != NULL ) {
          add_two_uint32_vectors( actualNumCols, vecAddition2,
              vecAdditionPrefix2, ptrRowA );
        }

        // Recursive call.
        dist = generate_with_saved_recursive_on_two_vectors(
                   cfg_num_saved_generators, cfg_num_cores,
                   vecSavedCombi,
                   numTotalElems, b,
                   lastDigit, vecAddition1, vecAddition2,
                   0, // printMethod
                   level + 1 );

        // Update minimum distance.
        if( ( dist > 0 )&&( ( minDist == -1 )||( dist < minDist ) ) ) {
          minDist = dist;
        }
      }
    }

    // Remove the vectors with the addition of combinations.
    free( vecAddition1 );
    if( vecAdditionPrefix2 != NULL ) {
      free( vecAddition2 );
    }
  }

  // Return minimum distance.
  return( minDist );
}

// ============================================================================
static int generate_with_saved_1_s_on_two_vectors(
    int cfg_num_saved_generators, int cfg_num_cores,
    SavedCombi * vecSavedCombi,
    int numTotalElems, int numElemsToTake,
    int lastValueInPrefix,
    uint32_t * vecAdditionPrefix1, uint32_t * vecAdditionPrefix2,
    int printMethod,
    int level ) {
//
// Algorithm with saved data for cases 1..s.
// Simple case: Use the data structure just filled.
// If vecAdditionPrefix2 != NULL, both vectors are processed.
// Otherwise, only vector vecAdditionPrefix1 is processed.
//
  uint32_t    * vecAddition1, * vecAddition2;
  int         rowStride, actualNumCols,
              i, jStart, jEnd, jMatStart, minDist, dist;
  SavedCombi  * ptrSaved;

  if( printMethod == 1 ) {
    for( i = 0; i < level; i++ ) {
      printf( "  " );
    }
    printf( "    generate_with_saved_1_s_on_two_vectors\n" );
  }

  // Check input arguments.
  check_condition_is_true( numElemsToTake <= cfg_num_saved_generators,
      "generate_with_saved_1_s_on_two_vectors",
      "Invalid numElemsToTake and cfg_num_saved_generators" );

  // Some initializations.
  minDist       = -1;

  ptrSaved      = & vecSavedCombi[ numElemsToTake - 1 ];
  rowStride     = ptrSaved->rowStrideMat;
  actualNumCols = ptrSaved->actualNumColsMat;

  // Create the vectors for storing the addition of combinations.
  create_aligned_uint32_vector( "generate_with_saved_1_s_on_two_vectors",
       & vecAddition1, rowStride );
  if( vecAdditionPrefix2 != NULL ) {
    create_aligned_uint32_vector( "generate_with_saved_1_s_on_two_vectors",
         & vecAddition2, rowStride );
  }

  // Generate and test all combinations for two elements.
  jStart    = starting_index_of( numTotalElems, numElemsToTake,
                                 lastValueInPrefix );
  jEnd      = ptrSaved->numCombinations;
  jMatStart = ( jStart < jEnd ? jStart : jEnd - 1 );

  copy_uint32_vector( actualNumCols, vecAddition1, vecAdditionPrefix1 );
  if( vecAdditionPrefix2 != NULL ) {
    copy_uint32_vector( actualNumCols, vecAddition2, vecAdditionPrefix2 );
  }

  if( vecAdditionPrefix2 != NULL ) {
    dist = add_every_row_to_two_int_vectors_and_compute_distance(
               jEnd - jStart, actualNumCols,
               & ptrSaved->matAdditions[ rowStride * jMatStart ], rowStride,
               vecAddition1, vecAddition2 );
  } else {
    dist = add_every_row_to_uint32_vector_and_compute_distance(
               jEnd - jStart, actualNumCols,
               & ptrSaved->matAdditions[ rowStride * jMatStart ], rowStride,
               vecAddition1 );
  }

  // Update minimum distance.
  if( ( dist > 0 )&&( ( minDist == -1 )||( dist < minDist ) ) ) {
    minDist = dist;
  }

  // Remove the vectors with the addition of combinations.
  free( vecAddition1 );
  if( vecAdditionPrefix2 != NULL ) {
    free( vecAddition2 );
  }

  // Return minimum distance.
  return( minDist );
}


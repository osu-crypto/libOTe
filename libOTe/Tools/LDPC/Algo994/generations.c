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
#include "libOTe/Tools/LDPC/Algo994/luf2.h"
#include "libOTe/Tools/LDPC/Algo994/count_combinations.h"
#include "libOTe/Tools/LDPC/Algo994/check_combinations.h"
#include "libOTe/Tools/LDPC/Algo994/utils.h"
#include "libOTe/Tools/LDPC/Algo994/read_config.h"
#include "libOTe/Tools/LDPC/Algo994/computing_kernels.h"
#include "libOTe/Tools/LDPC/Algo994/constant_defs.h"
#include "libOTe/Tools/LDPC/Algo994/data_defs.h"
#include "libOTe/Tools/LDPC/Algo994/alg_basic.h"
#include "libOTe/Tools/LDPC/Algo994/alg_optimized.h"
#include "libOTe/Tools/LDPC/Algo994/alg_stack.h"
#include "libOTe/Tools/LDPC/Algo994/alg_saved.h"
#include "libOTe/Tools/LDPC/Algo994/alg_saved_unrolled.h"
#include "libOTe/Tools/LDPC/Algo994/alg_gray.h"
#include "libOTe/Tools/LDPC/Algo994/alg_common.h"
#include "libOTe/Tools/LDPC/Algo994/generations.h"


// ============================================================================
// Declaration of local prototypes.

static void create_vector_of_gamma_matrices(
    int numGammaMatrices, GammaMatrix ** vecGammaMatrices,
    int numRows, int rowStride );

static void remove_vector_of_gamma_matrices(
    int numGammaMatrices, GammaMatrix * vecGammaMatrices );

static void create_data_structures_for_saving_combinations(
    int cfg_alg, int cfg_num_saved_generators, int numGammaMatrices,
    int k, int nGamma, SavedCombi *** vecSavedCombisForAGamma );

static void remove_data_structures_for_saving_combinations(
    int cfg_alg, int cfg_num_saved_generators, int numGammaMatrices,
    SavedCombi ** vecSavedCombisForAGamma );

static int enumerate_generators_to_compute_distances(
    int cfg_alg, int cfg_num_saved_generators, int cfg_num_cores,
    double t1,
    int kInput, int nInput,
    int numGammaMatrices, GammaMatrix * vecGammaMatrices,
    SavedCombi ** vecSavedCombisForAGamma );

static int generate_combinations(
    int cfg_alg, int cfg_num_saved_generators, int cfg_num_cores,
    GammaMatrix g,
    SavedCombi * vecSavedCombi,
    int  numTotalElems, int numElemsToTake );

static void compact_matrix( char * sourceMat, uint32_t * targetMat,
    int kSourceMat, int nSourceMat, int nTargetMat );

static void diagonalize_several_permuted_matrices(
    int cfg_num_permutations,
    int cfg_print_matrices,
    int kInput, int nInput, char * inputMatrix,
    int numGammaMatrices, GammaMatrix * vecGammaMatrices, int nGamma );

static void diagonalize_input_matrix(
    int cfg_print_matrices,
    int kInput, int nInput, char * inputMatrix,
    int numGammaMatrices, GammaMatrix * vecGammaMatrices );

static void generate_permutation( int n, int * vecPermut );

static void init_permutation_vector( int n, int * vecPermut );

static void permut_matrix( int kInput, int nInput, char * inputMatrix,
    int * vecPermut );

static void copy_vector_of_gamma_matrices(
    int numGammaMatrices,
    GammaMatrix * vecGammaMatricesDst,
    GammaMatrix * vecGammaMatricesSrc );

static int compare_ranks( int numGammaMatrices,
    GammaMatrix * vecGammaMatrices1, GammaMatrix * vecGammaMatrices2 );

#if 0
static int sum_ranks( int numGammaMatrices, GammaMatrix * vecGammaMatrices );
#endif

#if 0
int get_next_combination_in_new_order( int * vecCombi,
    int numTotalElems, int numElemsToTake );
#endif

#if 0
static void print_contents_of_data_structures(
    SavedCombi ** vecSavedCombisForAGamma,
    int numGammaMatrices, int nGamma, int numCombis );
#endif

#if 0
static void print_filled_field_of_data_structures(
    SavedCombi ** vecSavedCombisForAGamma,
    int numGammaMatrices, int cfg_num_saved_generators );
#endif


// ============================================================================
int compute_distance_of_matrix(char* inputMatrix, int kInput, int nInput) {
    int          cfg_alg, cfg_num_saved_generators,
        cfg_num_cores, cfg_num_permutations, cfg_print_matrices,
        info;


    // Initialize module for counting ones.
    init_computing_kernels_module();

    // Read the configuration file.
    info = read_config(&cfg_alg,
        &cfg_num_saved_generators,
        &cfg_num_cores,
        &cfg_num_permutations,
        &cfg_print_matrices);
    if (info != 0) {
        fprintf(stderr, "\n");
        fprintf(stderr, "ERROR in compute_distance_of_matrix: ");
        fprintf(stderr, "Error reading file 'config.in'.\n\n\n");
        exit(-1);
    }
    return info;

}

int compute_distance_of_matrix_impl(char* inputMatrix, int kInput, int nInput,
    
    int cfg_alg, 
    int cfg_num_saved_generators, 
    int cfg_num_cores,
    int cfg_num_permutations,
    int cfg_print_matrices)
{

    int kGamma, nGamma, numGammaMatrices,
        minDist;

    double       t1, t2;
    GammaMatrix* vecGammaMatrices;
    SavedCombi** vecSavedCombisForAGamma;
    uint32_t* compactInputMatrix;

    // Set initial timer.
    t1 = omp_get_wtime();

  // Print input matrix.
  if( cfg_print_matrices == 1 ) {
    print_char_matrix( "Input matrix", inputMatrix, kInput, nInput );
  }

  // Check if input matrix is null matrix.
  if( count_non_zero_elements_in_char_matrix( inputMatrix,
          kInput, nInput ) == 0 ) {
    // Matrix is nulll. Quick return.
    return( 0 );
  }

  // Some initializations.
  numGammaMatrices = ( nInput + kInput - 1 ) / kInput;
  kGamma           = numGammaMatrices * kInput;
  nGamma           = ( nInput + 8 * ( int ) sizeof( uint32_t ) - 1 ) /
                     ( 8 * ( int ) sizeof( uint32_t ) );

  // Determine the algorithm to apply.
  if( cfg_alg == ALG_GRAY ) {
    //
    // Algorithm based on brute force: Gray codes.
    //
    if (print_logs())
    {
        printf("Dims of input matrix:         %d x %d\n", kInput, nInput);
        printf("Dims of compact input matrix: %d x %d\n", kInput, nGamma);
    }
    // Create a compacted input matrix.
    create_aligned_uint32_vector( "compute_distance_of_matrix",
        & compactInputMatrix, kInput * nGamma );

    // Compact input matrix.
    compact_matrix( inputMatrix, compactInputMatrix, kInput, nInput, nGamma );

    // Compute distance.
    minDist = generate_with_gray_alg( cfg_num_cores,
                  kInput, nGamma, compactInputMatrix, 1 );

    // Remove the compacted input matrix.
    free( compactInputMatrix );

  } else {
    //
    // Algorithms based on Brower-Zimmermann.
    //

    // Create and initialize the vector of Gamma matrices.
    create_vector_of_gamma_matrices( numGammaMatrices, & vecGammaMatrices,
        kInput, nGamma );

    // Create and initialize data structures for saving addition of
    // combinations.
    create_data_structures_for_saving_combinations(
        cfg_alg, cfg_num_saved_generators, numGammaMatrices,
        kInput, nGamma, & vecSavedCombisForAGamma );

    //
    // Diagonalize matrices.
    // =====================
    //
    if (print_logs())
        printf( "Performing several matrix diagonalizations...\n" );

    diagonalize_several_permuted_matrices(
        cfg_num_permutations, cfg_print_matrices,
        kInput, nInput, inputMatrix,
        numGammaMatrices, vecGammaMatrices, nGamma );

    t2 = omp_get_wtime();

    if (print_logs())
    {
        printf("Finished matrix diagonalizations. Elapsed time (s.): %.2lf\n",
            t2 - t1);
        fflush(stdout);

        // Print some info.
        printf("\n\n");
        printf("MEMORY_ALIGNMENT:                   %d\n", MEMORY_ALIGNMENT);
        printf("Dimensions of input matrix:         %d x %d \n", kInput, nInput);
        printf("Dimensions of compacted Gamma mats: %d x %d \n", kGamma, nGamma);
    }
    //
    // Compute distances.
    // ==================
    //
    minDist = enumerate_generators_to_compute_distances(
                  cfg_alg, cfg_num_saved_generators, cfg_num_cores,
                  t1,
                  kInput, nInput,
                  numGammaMatrices, vecGammaMatrices,
                  vecSavedCombisForAGamma );

    // Remove the vector of Gamma matrices.
    remove_vector_of_gamma_matrices( numGammaMatrices, vecGammaMatrices );

    // Remove data structures for saving addition of combinations.
    remove_data_structures_for_saving_combinations(
        cfg_alg, cfg_num_saved_generators, numGammaMatrices,
        vecSavedCombisForAGamma );
  }

  // Get and print final timing.
  t2 = omp_get_wtime();
  if (print_logs())
  {
      printf("Computed distance: %d ", minDist);
      printf("    Elapsed time (s.): %.2lf\n\n", t2 - t1);
      fflush(stdout);
  }
  // Return results.
  return( minDist );
}

// ============================================================================
static void create_vector_of_gamma_matrices(
    int numGammaMatrices, GammaMatrix ** vecGammaMatrices,
    int numRows, int rowStride ) {
//
// Create and initialize with empty values a vector with numGammaMatrices
// Gamma matrices.
//
  int       i;
  uint32_t  * ptrAux;

  if (print_logs())
      printf( "Creating vector of Gamma matrices.\n" );

  // Create the vector.
  * vecGammaMatrices = ( GammaMatrix * ) malloc( ( size_t )
                           numGammaMatrices * sizeof( GammaMatrix ) );
  if( * vecGammaMatrices == NULL ) {
    fprintf( stderr, "ERROR in create_vector_of_gamma_matrices: " );
    fprintf( stderr, "Allocation of vecGammaMatrices failed.\n" );
    exit( -1 );
  }

  // Initialize every element in vector.
  for( i = 0; i < numGammaMatrices; i++ ) {
    // Allocate memory for the matrix, and initialize it.
    create_aligned_uint32_vector( "create_vector_of_gamma_matrices",
        & ptrAux, numRows * rowStride );

    // Initialize most of the fields of the struct.
    ( * vecGammaMatrices )[ i ].buffer        = ptrAux;
    ( * vecGammaMatrices )[ i ].numRows       = numRows;
    ( * vecGammaMatrices )[ i ].rowStride     = rowStride;
    ( * vecGammaMatrices )[ i ].actualNumCols = -1;
    ( * vecGammaMatrices )[ i ].rank          = -1;
  }
  if (print_logs())
      printf( "End of creating vector of Gamma matrices.\n" );
}

// ============================================================================
static void remove_vector_of_gamma_matrices(
    int numGammaMatrices, GammaMatrix * vecGammaMatrices ) {
//
// Remove the vector of Gamma matrices.
//
  int  i;

  if (print_logs())
      printf( "Erasing vector of Gamma matrices.\n" );

  for( i = 0; i < numGammaMatrices; i++ ) {
    // Remove the memory assigned for every Gamma matrix.
    if( vecGammaMatrices[ i ].buffer != NULL ) {
      free( vecGammaMatrices[ i ].buffer );
    }
  }
  // Remove the vector of GammaMatrix objects.
  free( vecGammaMatrices );
}

// ============================================================================
static void create_data_structures_for_saving_combinations(
    int cfg_alg, int cfg_num_saved_generators, int numGammaMatrices,
    int k, int nGamma, SavedCombi *** vecSavedCombisForAGamma ) {
//
// Create and initialize the data structures needed for saving all
// combinations.
//
  uint32_t    * ptrAdds;
  int         i, j, numCombis, * ptrLastDigits;
  double      accumMemoryInMB;
  SavedCombi  * ptrSavedCombi;

  if (print_logs())
      printf( "Creating data structures for saving combinations.\n" );

  if( ( cfg_alg != ALG_SAVED )&&
      ( cfg_alg != ALG_SAVED_UNROLLED ) ) {
    // No data structures must be built.
    * vecSavedCombisForAGamma = NULL;

  } else {
    // Data structures must be built.

    // Initializations.
    accumMemoryInMB = 0.0;

    // Create and initialize data structures for saving additions.
    * vecSavedCombisForAGamma = ( SavedCombi ** ) malloc( ( size_t )
                                    numGammaMatrices * sizeof( SavedCombi * ) );
    if( * vecSavedCombisForAGamma == NULL ) {
      fprintf( stderr, "ERROR in create_data_structures_for...: " );
      fprintf( stderr, "Allocation of vecSavedCombisForAGamma failed.\n" );
      exit( -1 );
    }

    for( i = 0; i < numGammaMatrices; i++ ) {
      ptrSavedCombi = ( SavedCombi * ) malloc( ( size_t )
                          cfg_num_saved_generators * sizeof( SavedCombi ) );
      if( ptrSavedCombi == NULL ) {
        fprintf( stderr, "ERROR in create_data_structures_for...: " );
        fprintf( stderr, "Allocation of ptrSavedCombi failed.\n" );
        exit( -1 );
      }
      ( * vecSavedCombisForAGamma )[ i ] = ptrSavedCombi;
    }

    for( j = 0; j < cfg_num_saved_generators; j++ ) {
      numCombis = get_num_combinations( k, j + 1 );

      accumMemoryInMB +=
          ( ( double ) ( numCombis * ( ( int ) sizeof( int ) ) +
                         numCombis * nGamma * ( ( int ) sizeof( int ) ) ) ) /
          1048576.0;

      if (print_logs())
      {
          printf("Generators: %2d  ", j + 1);
          printf("Combinations: %10d  ", numCombis);
          printf("Required accum.mem.(MB): %.1lf\n", accumMemoryInMB);
      }
      //// if( numCombis > 20000000 ) {
      ////   fprintf( stderr, "ERROR in create_data_structures_for...: " );
      ////   fprintf( stderr, "number of combinations too large.\n" );
      ////   exit( -1 );
      //// }
      for( i = 0; i < numGammaMatrices; i++ ) {

        // Create and initialize the vector of ints to store the last digits.
        create_int_vector( "create_data_structures_for_saving_...",
            & ptrLastDigits, numCombis );
        set_int_vector_to_zero( ptrLastDigits, numCombis );

        // Create and initialize the vector of uint32_t to store the additions.
        create_aligned_uint32_vector( "create_data_structures_for_saving_...",
            & ptrAdds, numCombis * nGamma );

        (* vecSavedCombisForAGamma)[ i ][ j ].filled            = 0;
        (* vecSavedCombisForAGamma)[ i ][ j ].numCombinations   = numCombis;
        (* vecSavedCombisForAGamma)[ i ][ j ].rowStrideMat      = nGamma;
        (* vecSavedCombisForAGamma)[ i ][ j ].actualNumColsMat  = -1;
        (* vecSavedCombisForAGamma)[ i ][ j ].matAdditions      = ptrAdds;
        (* vecSavedCombisForAGamma)[ i ][ j ].vecLastDigits     = ptrLastDigits;
      }
    }
  }
  if (print_logs())
      printf( "End of creating data structures for saving combinations.\n\n" );
}

// ============================================================================
static void remove_data_structures_for_saving_combinations(
    int cfg_alg, int cfg_num_saved_generators, int numGammaMatrices,
    SavedCombi ** vecSavedCombisForAGamma ) {
//
// Remove the data structures needed for saving all combinations.
//
  int  i, j;

  if(print_logs())
    printf( "Erasing data structures for saving addition of combinations.\n" );

  if( ( cfg_alg != ALG_SAVED )&&
      ( cfg_alg != ALG_SAVED_UNROLLED ) ) {
    // No data structures must be erased.

  } else {
    // Data structures must be erased.
    for( i = 0; i < numGammaMatrices; i++ ) {
      for( j = 0; j < cfg_num_saved_generators; j++ ) {
        free( vecSavedCombisForAGamma[ i ][ j ].vecLastDigits );
        free( vecSavedCombisForAGamma[ i ][ j ].matAdditions );
      }
    }
    for( i = 0; i < numGammaMatrices; i++ ) {
      free( vecSavedCombisForAGamma[ i ] );
    }
    free( vecSavedCombisForAGamma );
  }
}

// ============================================================================
static int enumerate_generators_to_compute_distances(
    int cfg_alg, int cfg_num_saved_generators, int cfg_num_cores,
    double t1,
    int kInput, int nInput,
    int numGammaMatrices, GammaMatrix * vecGammaMatrices,
    SavedCombi ** vecSavedCombisForAGamma ) {
//
// It computes the distance by enumerating generators until the convergence
// condition is found.
//
  int         lowerDist, upperDist, done, i, j,
              numGammaMatricesProcessed, numGammaMatricesContributing,
              minDist;
  double      t2;
  SavedCombi  * vecSavedCombisJm1;

  // Some initializations.
  // Initialize lowerDist to the number of full-rank matrices.
  //// lowerDist = nInput / kInput;
  lowerDist = 0;
  for( j = 1; j <= numGammaMatrices; j++ ) {
    if( vecGammaMatrices[ j - 1 ].rank == kInput ) {
      lowerDist++;
    }
  }
  // Initialize upperDist to the number of columns.
  upperDist = nInput;
  if (print_logs())
      printf( "Distance Loop. lowerDist: %d  upperDist: %d \n",
              lowerDist, upperDist );
  done = ( lowerDist >= upperDist ? 1 : 0 );

#ifdef COUNT_COMBINATIONS
  // Initialize the number of combinations.
  init_num_combinations_in_count_combinations();
#endif
#ifdef CHECK_COMBINATIONS
  // Initialize the number of checked combinations.
  init_num_checked_combinations_in_check_combinations();
#endif

  //
  // For every combination size.
  //
  if (print_logs())
  {
      printf("kInput:            %d\n", kInput);
      printf("numGammaMatrices:  %d\n", numGammaMatrices);
  }
  for( i = 1; ( i <= kInput )&&( ! done ); i++ ) {
      if (print_logs())
          printf( "  Generators: %d\n", i );

    // Compute the number of contributiong Gamma matrices.
    numGammaMatricesProcessed = 0;
    for( j = 1; j <= numGammaMatrices; j++ ) {
      if( vecGammaMatrices[ j - 1 ].rank + i - kInput >= 0 ) {
        numGammaMatricesProcessed++;
      }
    }
    if( numGammaMatricesProcessed == 0 ) {
      numGammaMatricesProcessed = 1;
    }
    if (print_logs())
        printf( "  numGMatProcessed: %d\n", numGammaMatricesProcessed );

    numGammaMatricesContributing = 0;
    for( j = 1; j <= numGammaMatrices; j++ ) {
      //// printf( "    j: %d  \n",  j );
      //// printf( "    upperDist: %d \n",  upperDist );
      //// printf( "    numGMatProcessed: %d \n",  numGammaMatricesProcessed );
      //// printf( "    kInput: %d \n",  kInput );
      //// printf( "    vecGammaMatrices[ j - 1 ].rank: %d \n",
      ////         vecGammaMatrices[ j - 1 ].rank );
      if( ( ( upperDist / numGammaMatricesProcessed ) - 1 ) >=
          ( kInput - vecGammaMatrices[ j - 1 ].rank ) ) {
        numGammaMatricesContributing++;
      }
    }
    if (print_logs())
        printf( "  numGMatContrib:   %d\n", numGammaMatricesContributing );

    //
    // Process gamma matrix "j".
    //
    for( j = 1; ( j <= numGammaMatricesContributing )&&( ! done ); j++ ) {
        if (print_logs())
            printf( "    Gamma Matrix: %d of %d \n", j, numGammaMatrices );

      // Set vecSavedCombisJm1.
      if( ( cfg_alg == ALG_SAVED )||
          ( cfg_alg == ALG_SAVED_UNROLLED ) ) {
        vecSavedCombisJm1 = vecSavedCombisForAGamma[ j - 1 ];
      } else {
        vecSavedCombisJm1 = NULL;
      }

      // Compute upperDist:
      // Generate combinations of "k" elements taken by "i" elements.
      minDist = generate_combinations( cfg_alg, cfg_num_saved_generators,
                    cfg_num_cores,
                    vecGammaMatrices[ j - 1 ],
                    vecSavedCombisJm1,
                    kInput, i );
      //// printf( "  minDist: %d \n", minDist );

      // Update the minimum distance for those matrices where the diagonalized
      // block has been removed.
      if( vecGammaMatrices[ j - 1 ].rank == kInput ) {
        minDist += i;
      }

      // Update upperDist with current distance.
      if( ( minDist != 0 )&&( minDist < upperDist ) ) {
          if (minDist == 1 && upperDist > lowerDist + 1)
          {
              printf("\n\n\n\n\n\n\n---------------------------------\n upper %d, lower %d\n\n\n\n", upperDist, lowerDist);
          }

        upperDist = minDist;
      }

      // Compute lowerDist.
      if( ( kInput - vecGammaMatrices[ j - 1 ].rank ) <= i ) {
        lowerDist++;
      }

      // Check if break right now.
      done = ( lowerDist >= upperDist ? 1 : 0 );

      // Print message.
      t2 = omp_get_wtime();
      if (print_logs())
          printf( "    End Gamma. lower: %2d  upper: %2d ", lowerDist, upperDist);
      if (print_logs())
          printf( "       Elapsed time (s.): %.2lf\n\n", t2-t1 );
      fflush( stdout );
    }

    // Check if break right now.
    done = ( lowerDist >= upperDist ? 1 : 0 );

    // Print message.
    t2 = omp_get_wtime();
    if (print_logs())
    {
        printf("  End Combin.  lower: %2d  upper: %2d ", lowerDist, upperDist);
        printf("       Elapsed time (s.): %.2lf\n\n", t2 - t1);
        fflush(stdout);
    }
  }

  // Print message.
  t2 = omp_get_wtime();
  if (print_logs())
  {
      printf("End Distance.  lower: %2d  upper: %2d ", lowerDist, upperDist);
      printf("       Elapsed time (s.): %.2lf\n\n", t2 - t1);
  }
#ifdef COUNT_COMBINATIONS
  // Print the number of combinations.
  print_num_combinations_in_count_combinations();
  fflush( stdout );
#endif
#ifdef CHECK_COMBINATIONS
  // Print the number of checked combinations.
  print_num_checked_combinations_in_check_combinations();
#endif
  fflush( stdout );

#if 0
  print_filled_field_of_data_structures( vecSavedCombisForAGamma,
      numGammaMatrices, cfg_num_saved_generators );
#endif

  return(lowerDist);
}

// ============================================================================
static int generate_combinations(
    int cfg_alg, int cfg_num_saved_generators, int cfg_num_cores,
    GammaMatrix g,
    SavedCombi * vecSavedCombi,
    int  numTotalElems, int numElemsToTake ) {
//
// Apply the different algorithms according to cfg_alg.
//
  int  dist;

#ifdef CHECK_COMBINATIONS
  // Initialize the module to check combinations.
  init_check_combinations( numTotalElems, numElemsToTake,
      g.buffer, g.numRows, g.actualNumCols, g.rowStride );
#endif

  // Some initializations.
  dist = -1;

  if( cfg_alg == ALG_BASIC ) {
    // Basic algorithm.
    dist = generate_with_basic_alg( g, numTotalElems, numElemsToTake, print_logs());

  } else if( cfg_alg == ALG_OPTIMIZED ) {
    // Optimized algorithm.
    dist = generate_with_optimized_alg( g, numTotalElems, numElemsToTake, print_logs());

  } else if( cfg_alg == ALG_STACK ) {
    // Stack-based algorithm.
    dist = generate_with_stack_alg( g, numTotalElems, numElemsToTake, print_logs());

  } else if( cfg_alg == ALG_SAVED ) {
    // Algorithm with data savings.
    dist = generate_with_saved_alg( cfg_num_saved_generators, cfg_num_cores,
               g, vecSavedCombi, numTotalElems, numElemsToTake, print_logs());

  } else if( cfg_alg == ALG_SAVED_UNROLLED ) {
    // Algorithm with data savings and unrolling.
    dist = generate_with_saved_unrolled_alg(
               cfg_num_saved_generators, cfg_num_cores,
               g, vecSavedCombi, numTotalElems, numElemsToTake, print_logs() );

  } else {
    fprintf( stderr, "\nERROR in generate_combinations: Unknown alg: %d \n\n",
             cfg_alg );
    exit( -1 );
  }

  // Return minimum distance.
  return( dist );
}

// ============================================================================
static void compact_matrix( char * sourceMat, uint32_t * targetMat,
    int kSourceMat, int nSourceMat, int nTargetMat ) {
  int       i, j, kk, kkLimit, nbits;
  uint32_t  c;

  nbits = 8 * sizeof( uint32_t );
  for( i = 0; i < kSourceMat; i++ ) {
    for( j = 0; j < nTargetMat; j++ ) {
      c = 0;
      kkLimit = ( nbits < nSourceMat - j * nbits ) ?
                  nbits : ( nSourceMat - j * nbits );
      for( kk = 0; kk < kkLimit; kk++ ) {
        c = c << 1;
        c = c | ( sourceMat[ nSourceMat * i + ( j * nbits + kk ) ] & 0xFF );
      }
      c = c << ( nbits - kkLimit );

      targetMat[ nTargetMat * i + j ] = c;
    }
  }
}

// ============================================================================
static void diagonalize_several_permuted_matrices(
    int cfg_num_permutations,
    int cfg_print_matrices,
    int kInput, int nInput, char * inputMatrix,
    int numGammaMatrices, GammaMatrix * vecGammaMatrices, int nGamma ) {
//
// It process input matrix with several permutations.
// It returns the gamma matrices for the best permutation found.
// It generates a gammaMatrix for every block diagonalized.
//
  char         * inputMatrixCopy;
  GammaMatrix  * vecGammaMatricesCopy;
  int          * vecPermut;
  int          iter, i, comparison;

  // Create a matrix for storing a copy of inputMatrix.
  create_uninitialized_char_vector( "diagonalize_several_permuted_matrices",
         & inputMatrixCopy, kInput * nInput );

  // Create a new data structure for storing Gamma matrices.
  create_vector_of_gamma_matrices( numGammaMatrices, & vecGammaMatricesCopy,
      kInput, nGamma );

  // Create the vector for storing a permutation.
  create_uninitialized_int_vector( "diagonalize_several_permuted_matrices",
         & vecPermut, nInput );

  // Initialize the seed for generating the permutations.
  srand( 11 );

  // Test several permutations.
  if (print_logs())
    printf( "\n" );

  for( iter = 0; iter < cfg_num_permutations; iter++ ) {

    // Copy inputMatrix into inputMatrixCopy.
    copy_char_matrix( kInput, nInput, inputMatrixCopy, inputMatrix );

    // Permut matrix except for the first case.
    if( iter == 0 ) {
      // Do not permutate the first case.
      init_permutation_vector( nInput, vecPermut );
    } else {
      // Generate a permutation.
      generate_permutation( nInput, vecPermut );

      // Permut matrix with previous permutation.
      permut_matrix( kInput, nInput, inputMatrixCopy, vecPermut );
    }

    //// printf( "Permutation: \n" );
    //// for( j = 0; j < nInput; j++ ) {
    ////   printf( " %d", vecPermut[ j ] );
    //// }
    //// printf( "\n" );
    //// printf( "End of permutation.\n" );

    // Diagonalize permuted matrix.
    if (print_logs())
        printf( "Diagonalizing permuted matrix %d\n", iter );
    diagonalize_input_matrix( cfg_print_matrices,
        kInput, nInput, inputMatrixCopy,
        numGammaMatrices, vecGammaMatricesCopy );

    if (print_logs())
        printf( "Matrix diagonalized.\n" );
    fflush( stdout );

    // Print the ranks.
    if (print_logs())
    {
        printf("Rank vector: ");
        for (i = 0; i < numGammaMatrices; i++) {
            printf("%d ", vecGammaMatricesCopy[i].rank);
        }
        printf("\n\n");
    }
    // Update the maximum rank of the last gamma matrix.
    if( iter == 0 ) {
      comparison = 1;
    } else {
      comparison = compare_ranks( numGammaMatrices,
                       vecGammaMatrices, vecGammaMatricesCopy );
    }
    //// printf( "comparison: %d\n", comparison );
    if( comparison == 1 ) {
      // Detected new best matrix.
      // Copy the gamma matrices from vecGammaMatricesCopy to vecGammaMatrices.
      copy_vector_of_gamma_matrices(
          numGammaMatrices,
          vecGammaMatrices,
          vecGammaMatricesCopy );
    }
  }

  //// // Print matrices.
  //// if( cfg_print_matrices == 1 ) {
  ////   print_uint32_matrix_as_bin( "Compacted Gammas",
  ////       gammaMatrices, kGamma, nGamma );
  //// }

  // Print the final (best) ranks.
  if (print_logs())
  {
      printf("Best rank vector: ");
      for (i = 0; i < numGammaMatrices; i++) {
          printf("%d ", vecGammaMatrices[i].rank);
      }
      printf("\n\n");
  }
  // Remove the permutation vector.
  free( vecPermut );

  // Remove the new data structure for storing Gamma matrices.
  remove_vector_of_gamma_matrices( numGammaMatrices, vecGammaMatricesCopy );

  // Remove the copy of inputMatrix.
  free( inputMatrixCopy );
}

// ============================================================================
static void diagonalize_input_matrix(
    int cfg_print_matrices,
    int kInput, int nInput, char * inputMatrix,
    int numGammaMatrices, GammaMatrix * vecGammaMatrices ) {
//
// It diagonalizes input submatrices inside inputMatrix.
// It generates one result: a gammaMatrix for every block diagonalized.
//
  int     i, jStart, rank, ii, jj, nbits;
  char    * inputMatrixCopy;

  // Create and initialize a matrix to store a copy the input matrix.
  create_uninitialized_char_vector( "diagonalize_input_matrix",
         & inputMatrixCopy, kInput * nInput );

  // Diagonalize matrix.
  jStart =  0;
  rank   = -1;
  for( i = 0; i < numGammaMatrices; i++ ) {
    //// printf( "  Diagonalization loop. Stage i: %d \n", i );

    // Diagonalize matrix.
    diagonalize_block( inputMatrix, kInput, nInput, jStart, & rank );

    // Remove the diagonalized part, if needed.
    if( rank == kInput ) {
      // Full rank matrix: Remove the diagonalized part.
      // Make a copy of inputMatrix into inputMatrixCopy removing the
      // identity out of it.
      set_char_matrix_to_zero( inputMatrixCopy, kInput, nInput );
      for( ii = 0; ii < kInput; ii++ ) {
        for( jj = 0; jj < jStart; jj++ ) {
          inputMatrixCopy[ ii * nInput + jj ] =
              inputMatrix[ ii * nInput + jj ];
        }
        for( jj = jStart + rank; jj < nInput; jj++ ) {
          inputMatrixCopy[ ii * nInput + ( jj - rank ) ] =
              inputMatrix[ ii * nInput + jj ];
        }
      }
      //// print_char_matrix( "copy", inputMatrixCopy, kInput, nInput );
    } else {
      // Rank-defficient matrix: No changes to input matrix.
      copy_char_matrix( kInput, nInput, inputMatrixCopy, inputMatrix );
    }

    // Print matrices.
    if( cfg_print_matrices == 1 ) {
      printf( "Rank: %d \n", rank );
      print_char_matrix( "Final matrix", inputMatrix, kInput, nInput );
      print_char_matrix( "Copy matrix ", inputMatrixCopy, kInput, nInput );
      printf( "\n" );
    }

    // Store diagonalized matrix into gamma matrix.
    compact_matrix( inputMatrixCopy,
        vecGammaMatrices[ i ].buffer, kInput, nInput,
        vecGammaMatrices[ i ].rowStride );

    // Print matrices.
    if( cfg_print_matrices == 1 ) {
      print_uint32_matrix_as_bin(
          "Compacted i-th Gamma after a diagonalization",
          vecGammaMatrices[ i ].buffer,
          vecGammaMatrices[ i ].numRows,
          vecGammaMatrices[ i ].rowStride );
    }

    // Store the rank.
    vecGammaMatrices[ i ].rank = rank;

    // Store the actualNumCols: The actual number of columns to be processed.
    nbits = 8 * sizeof( uint32_t );
    if( rank == kInput ) {
      vecGammaMatrices[ i ].actualNumCols = ( nInput - kInput + nbits - 1 ) /
                                            nbits;
    } else {
      vecGammaMatrices[ i ].actualNumCols = ( nInput + nbits - 1 ) / nbits;
    }

    // Update jStart.
    jStart += rank;
  }

  //// // Print matrices.
  //// if( cfg_print_matrices == 1 ) {
  ////   print_uint32_matrix_as_bin( "Compacted Gammas",
  ////       gammaMatrices, kGamma, nGamma );
  //// }

  // Remove copy of input matrix.
  free( inputMatrixCopy );
}

// ============================================================================
static void generate_permutation( int n, int * vecPermut ) {
// It generates a permutation of n elements into vec.
  int  j, p, aux;

  // Create an initial permutation.
  for( j = 0; j < n; j++ ) {
    vecPermut[ j ] = j;
  }
  for( j = 0; j < n; j++ ) {
    p = get_random_int() % n;
    aux = vecPermut[ j ];
    vecPermut[ j ] = vecPermut[ p ];
    vecPermut[ p ] = aux;
  }
}

// ============================================================================
static void init_permutation_vector( int n, int * vecPermut ) {
// It generates a permutation of n elements into vec.
  int  j;

  // Create an initial permutation.
  for( j = 0; j < n; j++ ) {
    vecPermut[ j ] = j;
  }
}

// ============================================================================
static void permut_matrix( int kInput, int nInput, char * inputMatrix,
    int * vecPermut ) {
// It permutes kInput x nInput inputMatrix with permutation in vecPermut.
  char  * vecRow;
  int   k, j;

  // Create the vector for storing a row.
  create_uninitialized_char_vector( "permut_matrix", & vecRow, nInput );

  // Permut inputMatrix according to vecPermut.
  for( k = 0; k < kInput; k++ ) {
    // Process row k-th.
    for( j = 0; j < nInput; j++ ) {
      vecRow[ j ] = inputMatrix[ k * nInput + j ];
    }
    for( j = 0; j < nInput; j++ ) {
      inputMatrix[ k * nInput + vecPermut[ j ] ] = vecRow[ j ];
    }
  }
  //// print_char_matrix( "Permuted matrix", inputMatrix, kInput, nInput );

  // Remove the vector for storing a row.
  free( vecRow );
}

// ============================================================================
static void copy_vector_of_gamma_matrices(
    int numGammaMatrices,
    GammaMatrix * vecGammaMatricesDst,
    GammaMatrix * vecGammaMatricesSrc ) {
//
// Copy the contents of vecGammaMatricesSrc into vecGammaMatricesDst.
//
  int  i;

  //// printf( "Copying vector of Gamma matrices.\n" );

  // Initialize every element in vector.
  for( i = 0; i < numGammaMatrices; i++ ) {
    // Copy the fields of the struct.
    vecGammaMatricesDst[ i ].numRows       = vecGammaMatricesSrc[ i ].numRows;
    vecGammaMatricesDst[ i ].rowStride     = vecGammaMatricesSrc[ i ].rowStride;
    vecGammaMatricesDst[ i ].actualNumCols =
        vecGammaMatricesSrc[ i ].actualNumCols;
    vecGammaMatricesDst[ i ].rank          = vecGammaMatricesSrc[ i ].rank;

    // Copy the data.
    copy_uint32_vector(
        vecGammaMatricesSrc[ i ].numRows * vecGammaMatricesSrc[ i ].rowStride,
        vecGammaMatricesDst[ i ].buffer,
        vecGammaMatricesSrc[ i ].buffer );
  }
  //// printf( "End of copying vector of Gamma matrices.\n\n" );
}

// ============================================================================
static int compare_ranks( int numGammaMatrices,
    GammaMatrix * vecGammaMatrices1, GammaMatrix * vecGammaMatrices2 ) {
//
// It compares the ranks of the two gamma matrices:
// It returns -1 if vecGammaMatrices1 is better,
// it returns  1 if vecGammaMatrices2 is better, and
// it returns  0 if both are equivalent.
//
  int  i, sum1, sum2, rank1, rank2, comparison;

  //// printf( "Comparing ranks...\n" );

  // Compare every element in vector.
  sum1 = 0;
  sum2 = 0;
  for( i = 0; i < numGammaMatrices; i++ ) {
    sum1 += vecGammaMatrices1[ i ].rank;
    sum2 += vecGammaMatrices2[ i ].rank;
  }

  if( sum1 > sum2 ) {
    return -1;
  } else if( sum1 < sum2 ) {
    return 1;
  } else {
    // Look for most full-rank submatrices.
    comparison = 0;
    for( i = 0; ( i < numGammaMatrices )&&( comparison == 0 ); i++ ) {
      rank1 = vecGammaMatrices1[ i ].rank;
      rank2 = vecGammaMatrices2[ i ].rank;
      if( rank1 > rank2 ) {
        comparison = -1;
      } else if( rank1 < rank2 ) {
        comparison = 1;
      }
    }
    return comparison;
  }
}

#if 0
// ============================================================================
static int sum_ranks( int numGammaMatrices, GammaMatrix * vecGammaMatrices ) {
//
// It adds up the ranks of the gamma matrices.
//
  int  i, sum;

  printf( "Adding ranks...\n" );

  // Compare every element in vector.
  sum = 0;
  for( i = 0; i < numGammaMatrices; i++ ) {
    sum += vecGammaMatrices[ i ].rank;
  }
  return sum;
}
#endif

#if 0
// ============================================================================
int get_next_combination_in_new_order( int * vecCombi,
    int numTotalElems, int numElemsToTake ) {
// Get new combination.
  int  i, j, done;

  //// printf( "Starting get_next_combination_in_new_order\n" );
  i = 0;
  while( ( i < ( numElemsToTake - 1 ) )&&
         ( vecCombi[ i + 1 ] == vecCombi[ i ] + 1 ) ) {
    i++;
  }
  vecCombi[ i ]++;
  for( j = 0; j < i; j++ ) {
    vecCombi[ j ] = j;
  }
  done = ( vecCombi[ numElemsToTake - 1 ] == numTotalElems );
  //// printf( "done: %d    ", done );
  //// print_int_vector( " current combi", vecCombi, numElemsToTake );
  return( done );
}
#endif

#if 0
// ============================================================================
static void print_contents_of_data_structures(
    SavedCombi ** vecSavedCombisForAGamma,
    int numGammaMatrices, int nGamma, int numCombis ) {
// Print contents of data structures for saving addition of combinations.

  int  i, j, jj, nev;

  for( i = 0; i < numGammaMatrices; i++ ) {
    printf( "\n" );
    printf( "Gamma matrix: %d \n", i );

    for( j = 1; j <= numCombis; j++ ) {
      nev = vecSavedCombisForAGamma[ i ][ j - 1 ].numElemsInVectors;
      printf( "Saved combis: %d \n", nev );

      for( jj = 0; jj < nev; jj++ ) {
        printf( "Last digit: %d  ",
                vecSavedCombisForAGamma[ i ][ j - 1 ].vecLastDigits[ jj ] );
        print_uint32_vector_as_bin( " addition: ",
          & vecSavedCombisForAGamma[ i ][ j - 1 ].matAdditions[ nGamma * jj ],
          nGamma );
      }
    }
  }
}
#endif

#if 0
// ============================================================================
static void print_filled_field_of_data_structures(
    SavedCombi ** vecSavedCombisForAGamma,
    int numGammaMatrices, int cfg_num_saved_generators ) {
//
// Print field filled of data structures.
//
  int  i, j;

  for( i = 0; i < numGammaMatrices; i++ ) {
    printf( "\n" );
    printf( "Gamma matrix: %d \n", i );

    for( j = 1; j <= cfg_num_saved_generators; j++ ) {
      printf( "  Generator:      %2d  ", j );
      printf( "  Saved combis: %5d  ",
              vecSavedCombisForAGamma[ i ][ j - 1 ].numElemsInVectors );
      printf( "  filled:       %2d\n",
              vecSavedCombisForAGamma[ i ][ j - 1 ].filled );
    }
  }
  printf( "\n" );
}
#endif



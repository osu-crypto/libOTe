
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

#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include "libOTe/Tools/LDPC/Algo994/data_defs.h"
#include "libOTe/Tools/LDPC/Algo994/read_config.h"


// ============================================================================
int read_config( int * alg,
                 int * num_saved_generators,
                 int * num_cores,
                 int * num_permutations,
                 int * print_matrices ) {

  int       iretval;
  char      * pcretval;
  enum { MAX_LINE_LENGTH = 10240 };
  char      myLine[ MAX_LINE_LENGTH ];
  FILE      * fp;

  // Open the configuration file.
  if ( ( fp = fopen( "config.in", "r" ) ) == NULL ) {
    //return -1;
      *alg = ALG_SAVED_UNROLLED;
      *num_saved_generators = 5;
      *num_cores = 8;
      *num_permutations = 4;
      *print_matrices = 0;
      return 0;
  }

  // Read the algorithm to apply.
  iretval = fscanf( fp, "%d", alg );
  if( iretval != 1 ) {
    fprintf( stderr, "\n\nERROR in read_config: fscanf failed.\n\n\n" );
    fclose( fp );
    return -1;
  }
  pcretval = fgets( myLine, MAX_LINE_LENGTH, fp );
  if( pcretval == NULL ) {
    fprintf( stderr, "\n\nERROR in read_config: fgets failed.\n\n\n" );
    return -1;
  }
  printf( "%% Algorithm to apply:              %d\n", * alg );
  // Check the algorithm to apply.
  if( ( * alg != ALG_BASIC )&&
      ( * alg != ALG_OPTIMIZED )&&
      ( * alg != ALG_STACK )&&
      ( * alg != ALG_SAVED )&&
      ( * alg != ALG_SAVED_UNROLLED )&&
      ( * alg != ALG_GRAY ) ) {
    fprintf( stderr, "ERROR in read_config: alg id is not right.\n\n" );
    fclose( fp );
    return -1;
  }

  // Read the number of saved generators.
  iretval = fscanf( fp, "%d", num_saved_generators );
  pcretval = fgets( myLine, MAX_LINE_LENGTH, fp );
  printf( "%% Number of saved generators:      %d\n", * num_saved_generators );
  // Check number of saved generators.
  if( * num_saved_generators < 1 ) {
    fprintf( stderr, "\n\nERROR in read_config: num_saved_generators must be >= 1\n\n\n" );
    fclose( fp );
    return -1;
  }

  // Read the number of cores.
  iretval = fscanf( fp, "%d", num_cores );
  pcretval = fgets( myLine, MAX_LINE_LENGTH, fp );
  printf( "%% Number of cores:                 %d\n", * num_cores );
  // Check number of cores.
  if( * num_cores < 1 ) {
    fprintf( stderr, "\n\nERROR in read_config: num_cores must be >= 1\n\n\n" );
    fclose( fp );
    return -1;
  }

  // Read the number of permutations.
  iretval = fscanf( fp, "%d", num_permutations );
  pcretval = fgets( myLine, MAX_LINE_LENGTH, fp );
  printf( "%% Number of permutations:          %d\n", * num_permutations );
  // Check number of num_permutations.
  if( * num_permutations < 1 ) {
    fprintf( stderr, "\n\nERROR in read_config: num_permutations must be >= 1\n\n\n" );
    fclose( fp );
    return -1;
  }

  // Read whether print matrices.
  iretval = fscanf( fp, "%d", print_matrices );
  if( iretval != 1 ) {
    fprintf( stderr, "\n\nERROR in read_config: fscanf failed.\n\n\n" );
    fclose( fp );
    return -1;
  }
  pcretval = fgets( myLine, MAX_LINE_LENGTH, fp );
  if( pcretval == NULL ) {
    fprintf( stderr, "\n\nERROR in read_config: fgets failed.\n\n\n" );
    fclose( fp );
    return -1;
  }
  printf( "%% Print matrices:                  %d\n", * print_matrices );

  // Close file, and return.
  fclose( fp );
  printf( "\n" );

  return 0;
}


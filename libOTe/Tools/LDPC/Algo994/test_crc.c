///*
//
//   MinDistance.
//   Software package with several fast scalar, vector, and parallel
//   implementations for computing the minimum distance of a random linear code.
//
//   Copyright (C) 2017  Fernando Hernando (carrillf@mat.uji.es)
//   Copyright (C) 2017  Francisco Igual (figual@ucm.es)
//   Copyright (C) 2017  Gregorio Quintana (gquintan@uji.es)
//
//   This program is free software; you can redistribute it and/or modify
//   it under the terms of the GNU General Public License as published by
//   the Free Software Foundation; either version 3 of the License, or
//   (at your option) any later version.
//
//   This program is distributed in the hope that it will be useful,
//   but WITHOUT ANY WARRANTY; without even the implied warranty of
//   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//   GNU General Public License for more details.
//
//   You should have received a copy of the GNU General Public License
//   along with this program; if not, write to the Free Software Foundation,
//   Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
//
//*/
//
//
//#include <stdio.h>
//#include <stdlib.h>
//#include "libOTe/Tools/LDPC/Algo994/utils.h"
//#include "libOTe/Tools/LDPC/Algo994/generations.h"
//
//#include <config.h>
//
//#ifdef USE_VECTORIZATION
//#include <x86intrin.h>
//
//// Check the best vectorization option.
//
//#ifdef USE_AVX512
// #define VECT_VERSION "AVX512"
//#endif
//
//#ifdef USE_AVX2
// #define VECT_VERSION "AVX2"
//#endif
//
//#ifdef USE_SSE
// #define VECT_VERSION "SSE"
//#endif
//
//#else
// #define VECT_VERSION "No vectorization"
//
//#endif // USE_VECTORIZATION.
//
//// ============================================================================
//int main( int argc, char *argv[] ) {
//  char  * inputMatrix;
//  int   info, k, n, dist;
//
//  // Checking the number of arguments.
//  if ( argc != 2 ) {
//    printf( "Usage:  %s  file_to_process\n\n", argv[ 0 ] );
//    exit( -1 );
//  }
//
//  // Report vectorization information.
//  printf( "Vectorization scheme: %s\n", VECT_VERSION );
//
//  // Read input matrix.
//  info = read_char_matrix( argv[ 1 ], & inputMatrix, & k, & n );
//  if( info != 0 ) {
//    fprintf( stderr, "\n" );
//    fprintf( stderr, "ERROR in read_char_matrix: " );
//    fprintf( stderr, "Error while reading input file with matrix.\n\n\n" );
//    return -1;
//  }
//
//  // Compute distance of input matrix.
//  dist = compute_distance_of_matrix( inputMatrix, k, n );
//  printf( "\n\n" );
//  printf( "Distance of input matrix:  %d \n", dist );
//  fprintf(stderr, "%d", dist);
//
//  // Remove matrices.
//  free( inputMatrix );
//
//  printf( "%% End of Program\n" );
//  return 0;
//}
//

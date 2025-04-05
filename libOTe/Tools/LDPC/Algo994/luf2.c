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
#include "libOTe/Tools/LDPC/Algo994/luf2.h"


// ============================================================================
// Declaration of local prototypes.

static void nullify_lower_and_upper_triangular_parts( char * mat, int k, int n,
    int jStart );

static void look_for_non_zero_element( char * mat, int k, int n,
    int iStart, int jStart, int * foundPivot, int * iPivot, int * jPivot );

static void swap_rows( char * mat, int k, int n, int i1, int i2 );

static void swap_columns( char * mat, int k, int n, int j1, int j2 );

static void add_row_to_row( char * mat, int k, int n,
    int idxTargetRow, int idxRowToAdd );

#if 0
static void print_char_matrix_2( char * name, char * mat, int rowStride,
    int k, int n );
#endif


// ============================================================================
void diagonalize_block( char * mat, int k, int n, int jStart,
    int * rank ) {
  int  nDelta, kn, jEnd, r, j;

  nullify_lower_and_upper_triangular_parts( mat, k, n, jStart );
  //// print_matrix( "Mat. after nullifying matrix", mat, m, n );

  // Compute and return rank.
  nDelta = n - jStart;
  kn     = ( k < nDelta ? k : nDelta );
  jEnd   = jStart + kn;
  r      = 0;
  for( j = jStart; j < jEnd; j++ ) {
    if( mat[ n * ( j - jStart ) + j ] != 0 ) {
      r++;
    }
  }
  * rank = r;
  //// print_char_matrix_2( "local", & mat[ n * 0 + jStart ], n, k, ( k < n ? k : n ) );
}

// ============================================================================
int count_non_zero_elements_in_char_matrix( char * mat, int k, int n ) {
  int  nz, i, j;

  nz = 0;
  for( i = 0; i < k; i++ ) {
    for( j = 0; j < n; j++ ) {
      if( mat[ n * i + j ] != 0 ) {
        nz++;
      }
    }
  }
  return( nz );
}

// ============================================================================
static void nullify_lower_and_upper_triangular_parts( char * mat, int k, int n,
    int jStart ) {
  int  j, ii, kk, nDelta, kn, jEnd, iPivot, jPivot, foundPivot;

  nDelta = n - jStart;
  kn     = ( k < nDelta ? k : nDelta );
  jEnd   = jStart + kn;

  for( j = jStart; j < jEnd; j++ ) {
    ii = j - jStart;
    // Check if diagonal element is zero.
    if( mat[ n * ii + j ] == 0 ) {
      // Look for a non-zero element.
      look_for_non_zero_element( mat, k, n, ii, j,
                                 & foundPivot, & iPivot, & jPivot );
      if( foundPivot != 0 ) {
        // Pivot non-zero element into position (ii,j).
        swap_rows( mat, k, n, ii, iPivot );
        swap_columns( mat, k, n, j, jPivot );
      }
    }
    if( mat[ n * ii + j ] != 0 ) {
      // Nullify elements above the diagonal in column j-th.
      for( kk = 0; kk < ii; kk++ ) {
        if( mat[ n * kk + j ] != 0 ) {
          add_row_to_row( mat, k, n, kk, ii );
        }
      }
      // Nullify elements below the diagonal in column j-th.
      for( kk = ii + 1; kk < k; kk++ ) {
        if( mat[ n * kk + j ] != 0 ) {
          add_row_to_row( mat, k, n, kk, ii );
        }
      }
    }
    //// print_matrix( "Intermediate matrix", mat, m, n );
  }
}

// ============================================================================
static void look_for_non_zero_element( char * mat, int k, int n,
    int iStart, int jStart, int * foundPivot, int * iPivot, int * jPivot ) {
  int  i, j;

  * foundPivot = 0;
  * iPivot     = iStart;
  * jPivot     = jStart;
  for( i = iStart; ( i < k )&&( * foundPivot == 0 ); i++ ) {
    for( j = jStart; ( j < n )&&( * foundPivot == 0 ); j++ ) {
      //// printf( "    i,j: %d %d \n", i, j );
      if( mat[ n * i + j ] != 0 ) {
        //// printf( "    found at i,j: %d %d \n", i, j );
        * foundPivot = 1;
        * iPivot     = i;
        * jPivot     = j;
      }
    }
  }
}

// ============================================================================
static void swap_rows( char * mat, int k, int n, int i1, int i2 ) {
  int   j;
  char  tmp;

  if( i1 != i2 ) {
    for( j = 0; j < n; j++ ) {
      tmp = mat[ n * i1 + j ];
      mat[ n * i1 + j ] = mat[ n * i2 + j ];
      mat[ n * i2 + j ] = tmp;
    }
  }
}

// ============================================================================
static void swap_columns( char * mat, int k, int n, int j1, int j2 ) {
  int   i;
  char  tmp;

  if( j1 != j2 ) {
    for( i = 0; i < k; i++ ) {
      tmp = mat[ n * i + j1 ];
      mat[ n * i + j1 ] = mat[ n * i + j2 ];
      mat[ n * i + j2 ] = tmp;
    }
  }
}

// ============================================================================
static void add_row_to_row( char * mat, int k, int n,
    int idxTargetRow, int idxRowToAdd ) {
  int  j;

  if( idxTargetRow != idxRowToAdd ) {
    for( j = 0; j < n; j++ ) {
      mat[ n * idxTargetRow + j ] ^= mat[ n * idxRowToAdd + j ];
    }
  }
}

#if 0
// ============================================================================
static void print_char_matrix_2( char * name, char * mat, int rowStride,
    int k, int n ) {
  int  i, j;

  printf( "%s:\n", name );
  for( i = 0; i < k; i++ ) {
    for( j = 0; j < n; j++ ) {
      printf( "%c", '0' + mat[ rowStride * i + j ] );
    }
    printf( "\n" );
  }
  printf( "\n" );
}
#endif


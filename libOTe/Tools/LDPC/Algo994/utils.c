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
#include <stdint.h>
#include <omp.h>
#include "libOTe/Tools/LDPC/Algo994/constant_defs.h"
#include "libOTe/Tools/LDPC/Algo994/utils.h"


// ============================================================================
// Declaration of local prototypes.

static void print_uint8_in_binary( uint8_t a );

static void print_uint32_in_binary( uint32_t a );

static uint64_t compute_product_range( uint64_t iStart, uint64_t iEnd );

unsigned long long
hash(void* data, int n)
{
    unsigned long long hash = 5381;
    int c;
    char* str = (char*)data;
    for (int i = 0; i < n; ++i)
    {
        c = *str++;
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }

    return hash;
}


unsigned long long random_int_seed = 11;
void set_random_int_seed(unsigned long long seed)
{
    random_int_seed = seed;
}
int get_random_int()
{
    random_int_seed = hash(&random_int_seed, sizeof(unsigned long long));

    return ((unsigned int)random_int_seed) >> 1;
}


int print_logs_var = 0;
void set_print_logs(int b)
{
    print_logs_var = b;
}
int print_logs()
{
    return print_logs_var;
}

// ============================================================================
void check_condition_is_true( int condition, char * routineName,
    char * message ) {
//
// Check if condition is met. Otherwise, the execution is aborted.
//
  if( ! condition ) {
    fprintf( stderr, "\n\nERROR in %s: %s.\n\n\n", routineName, message );
    exit( -1 );
  }
}

// ============================================================================
void create_uninitialized_char_vector( char * routineName,
    char ** vector, int numElements ) {
//
// Create an uninitialized vector with numElements elements of type char.
//
  // Allocate vector.
  * vector = ( char * ) malloc( ( size_t ) numElements * sizeof( char ) );
  if( * vector == NULL ) {
    fprintf( stderr, "\n\nERROR in %s: malloc failed.\n", routineName );
    fprintf( stderr, "This call might have failed because " );
    fprintf( stderr, "there is not enough memory.\n\n\n" );
    exit( -1 );
  }
}

// ============================================================================
void create_uint8_vector( char * routineName,
    uint8_t ** vector, int numElements ) {
//
// Create an initialized vector with numElements elements of type uint8_t.
//
  int  i;

  // Allocate vector.
  * vector = ( uint8_t * ) malloc( ( size_t )
                 numElements * sizeof( uint8_t ) );
  if( * vector == NULL ) {
    fprintf( stderr, "\n\nERROR in %s: malloc failed.\n", routineName );
    fprintf( stderr, "This call might have failed because " );
    fprintf( stderr, "there is not enough memory.\n\n\n" );
    exit( -1 );
  }
  // Initialize contents of vector.
  for( i = 0; i < numElements; i++ ) {
    ( * vector )[ i ] = 0;
  }
}

// ============================================================================
void create_uint16_vector( char * routineName,
    uint16_t ** vector, int numElements ) {
//
// Create an initialized vector with numElements elements of type uint16_t.
//
  int  i;

  // Allocate vector.
  * vector = ( uint16_t * ) malloc( ( size_t )
                 numElements * sizeof( uint16_t ) );
  if( * vector == NULL ) {
    fprintf( stderr, "\n\nERROR in %s: malloc failed.\n", routineName );
    fprintf( stderr, "This call might have failed because " );
    fprintf( stderr, "there is not enough memory.\n\n\n" );
    exit( -1 );
  }
  // Initialize contents of vector.
  for( i = 0; i < numElements; i++ ) {
    ( * vector )[ i ] = 0;
  }
}

// ============================================================================
void create_int_vector( char * routineName,
    int ** vector, int numElements ) {
//
// Create and initialize a vector with numElements elements of type int.
//
  int  i;

  // Allocate vector.
  * vector = ( int * ) malloc( ( size_t ) numElements * sizeof( int ) );
  if( * vector == NULL ) {
    fprintf( stderr, "\n\nERROR in %s: malloc failed.\n", routineName );
    fprintf( stderr, "This call might have failed because " );
    fprintf( stderr, "there is not enough memory.\n\n\n" );
    exit( -1 );
  }
  // Initialize contents of vector.
  for( i = 0; i < numElements; i++ ) {
    ( * vector )[ i ] = 0;
  }
}

// ============================================================================
void create_uninitialized_int_vector( char * routineName,
    int ** vector, int numElements ) {
//
// Create an uninitialized vector with numElements elements of type int.
//
  // Allocate vector.
  * vector = ( int * ) malloc( ( size_t ) numElements * sizeof( int ) );
  if( * vector == NULL ) {
    fprintf( stderr, "\n\nERROR in %s: malloc failed.\n", routineName );
    fprintf( stderr, "This call might have failed because " );
    fprintf( stderr, "there is not enough memory.\n\n\n" );
    exit( -1 );
  }
}

// ============================================================================
void create_aligned_uint32_vector( char * routineName,
    uint32_t ** vector, int numElements ) {
//
// Create and initialize an aligned vector with numElements elements of type
// int.
//
  int  retAlign, i;

  // Allocate vector.
  if( MEMORY_ALIGNMENT == 0 ) {
    // Allocate with no memory alignment.
    * vector = ( uint32_t * ) malloc(
                   ( size_t ) numElements * sizeof( uint32_t ) );
    if( * vector == NULL ) {
      fprintf( stderr, "\n\nERROR in %s: malloc failed.\n", routineName );
      fprintf( stderr, "This call might have failed because " );
      fprintf( stderr, "there is not enough memory.\n\n\n" );
      exit( -1 );
    }
  } else {
    // Allocate with memory alignment.
    retAlign = posix_memalign( ( void ** ) vector, MEMORY_ALIGNMENT,
                   ( size_t ) numElements * sizeof( uint32_t ) );
    if( retAlign != 0 ) {
      fprintf( stderr, "\n\nERROR in %s: posix_memalign failed.\n",
               routineName );
      fprintf( stderr, "This call might have failed because " );
      fprintf( stderr, "there is not enough memory.\n\n\n" );
      exit( -1 );
    }
  }
  // Initialize contents of vector.
  for( i = 0; i < numElements; i++ ) {
    ( * vector )[ i ] = 0;
  }
}

// ============================================================================
void init_vector_with_combinations( int lastValueInPrefix,
    int * vecCombi, int numElements ) {
//
// It initializes vector with combinations vecCombi with numElements with
// increasing values starting at lastValueInPrefix + 1.
//
  int i;

  for( i = 0; i < numElements; i++ ) {
    vecCombi[ i ] = lastValueInPrefix + i + 1;
  }
}
char nextChar(FILE* fp)
{
    return (char)fgetc(fp);
}

char nextCharNoSpace(FILE* fp)
{
    char c = nextChar(fp);
    while (c == ' ')
        c = nextChar(fp);

    return c;
}
 
// ============================================================================
int read_char_matrix( char * fileName, char ** mat, int * k, int * n ) {
  FILE       * fp;
  int        filledMatrix, iretval;
  char       c, * pcretval;
  enum { MAX_LINE_LENGTH = 10240 };
  char       myLine[ MAX_LINE_LENGTH ];
  double     t1, t2;

  // Set timer.
  t1 = omp_get_wtime();

  // Open file.
  if ( ( fp = fopen( fileName, "r" ) ) == NULL ) {
    return -1;
  }

  // Read dimensions of matrix.
  iretval = fscanf( fp, "%d %d", k, n );
  if( iretval != 2 ) {
    fprintf( stderr, "\n\nERROR in read_char_matrix: fscanf failed.\n\n\n" );
    return -1;
  }

  if (print_logs())
    printf( "Matrix dimensions:  %d x %d \n", * k, * n );
  pcretval = fgets( myLine, MAX_LINE_LENGTH, fp );
  if( pcretval == NULL ) {
    fprintf( stderr, "\n\nERROR in read_char_matrix: fgets failed.\n\n\n" );
    return -1;
  }

  // Check that k <= n.
  if( * k > * n ) {
    fprintf( stderr, "\n\nERROR in read_char_matrix: k > n. k: %d  n: %d\n\n\n",
             * k, * n );
    return -1;
  }

  // Create the matrix.
  * mat = ( char * ) malloc( ( ( size_t ) ( * k ) ) *
                             ( ( size_t ) ( * n ) ) * sizeof( char ) );
  if( * mat == NULL ) {
    fprintf( stderr, "\n\nERROR in read_char_matrix: malloc failed.\n\n\n" );
    exit( -1 );
  }

  // Read contents of matrix.
  filledMatrix = 0;

  c = ' ';

  int checksum = 0;

  for (int i = 0; i < *k; ++i)
  {
      for (int j = 0; j < *n; ++j)
      {
          if (c != '0' && c != '1')
              c = nextCharNoSpace(fp);

          if (c == '0')
          {
              (*mat)[*n * i + j] = 0;
          }
          else if (c == '1')
          {
              (*mat)[*n * i + j] = 1;

              checksum += (i + 1) * (j + 1);
          }
          else
          {
              printf("invalid char '%c' at %d,%d\n", c, i, j);
              return -1;
          }

          //if (verbose)
          //{
          //    printf(" %c", c);
          //}

          c = ' ';
      }

      if (i != *k - 1)
      {
          c = nextCharNoSpace(fp);
          if (c == '\n')
          {
              c = nextCharNoSpace(fp);
              if (c == '\r')
                  c = nextCharNoSpace(fp);
          }

          if (c != '0' && c != '1')
          {
              printf("invalid char '%c' at %d,0\n", c, i);
              return -1;
          }
      }

      //if (verbose)
      //{
      //    printf("\n");
      //}

  }

  filledMatrix = 1;

  if (print_logs())
      printf("checksum %d\n", checksum);

  // Check whether matrix was fully filled.
  //// printf( "i,j after main loop: %d %d \n", i, j );
  if (filledMatrix != 1) {
      fprintf(stderr,
          "\n\nERROR in read_char_matrix: Matrix could not be filled\n\n\n");
      exit(-1);
  }

  // Read and print trailing chars after filling matrix.
  c = nextCharNoSpace(fp);
  while (c != EOF)
  {
      if (c != '\n' && c != '\r')
      {
          printf("invalid char '%c' after matrix\n", c);
      }
      c = nextCharNoSpace(fp);
  }

  // Get timer.
  t2 = omp_get_wtime();
  if (print_logs())
  {
      printf("Read input matrix. Elapsed time (s.): %lf\n", t2 - t1);
      printf("\n");
  }
  // Close file.
  fclose( fp );

  return 0;
}

// ============================================================================
void read_char_matrix_2( char * fileName, char ** mat, int * k, int * n ) {
  FILE       * fp;
  int        i, j, tmp, iretval;
  char       * pcretval;
  enum { MAX_LINE_LENGTH = 10240 };
  char       myLine[ MAX_LINE_LENGTH ];
  double     t1, t2;

  // Set timer.
  t1 = omp_get_wtime();

  // Open file.
  if ( ( fp = fopen( fileName, "r" ) ) == NULL ) {
    return;
  }

  // Read dimensions of matrix.
  iretval = fscanf( fp, "%d %d", k, n );
  if( iretval != 2 ) {
    fprintf( stderr, "\n\nERROR in read_char_matrix_2: fscanf failed.\n\n\n" );
    exit( -1 );
  }
  printf( "Matrix dimensions:  %d x %d \n", * k, * n );
  pcretval = fgets( myLine, MAX_LINE_LENGTH, fp );
  if( pcretval == NULL ) {
    fprintf( stderr, "\n\nERROR in read_char_matrix_2: fgets failed.\n\n\n" );
    exit( -1 );
  }

  // Create the matrix.
  * mat = ( char * ) malloc( ( ( size_t ) ( * k ) ) *
                             ( ( size_t ) ( * n ) ) * sizeof( char ) );
  if( * mat == NULL ) {
    fprintf( stderr, "\n\nERROR in read_char_matrix_2: malloc failed.\n\n\n" );
    exit( -1 );
  }

  // Read contents of matrix.
  for( i = 0; i < * k; i++ ) {
    for( j = 0; j < * n; j++ ) {
      iretval = fscanf( fp, "%d", & tmp );
      //// printf( "  i,j,tmp: %d %d %d\n", i, j, tmp );
      ( * mat )[ ( * n ) * i + j ] = ( char ) tmp;
      //// printf( "mat[ %d, %d ] = %d \n", i, j, ( * mat)[ ( * n ) * i + j ] );
    }
    pcretval = fgets( myLine, MAX_LINE_LENGTH, fp );
  }

  // Get timer.
  t2 = omp_get_wtime();
  printf( "Read input matrix. Elapsed time (s.): %lf\n", t2-t1 );
}

// ============================================================================
void print_char_matrix( char * name, char * mat, int k, int n ) {
  int  i, j;

  printf( "%s:\n", name );
  for( i = 0; i < k; i++ ) {
    for( j = 0; j < n; j++ ) {
      printf( "%c ", '0' + mat[ n * i + j ] );
    }
    printf( "\n" );
  }
  printf( "\n" );
  fflush( stdout );
}

// ============================================================================
void print_uint32_matrix_as_bin( char * name, uint32_t * mat, int k, int n ) {
  int   i, j;
  //// char  c;

  printf( "%s:\n", name );
  for( i = 0; i < k; i++ ) {
    for( j = 0; j < n; j++ ) {
      print_uint32_in_binary( mat[ n * i + j ] );
    }
    printf( "\n" );
  }
  printf( "\n" );
  fflush( stdout );
}

// ============================================================================
void print_uint8_vector_as_bin_in_reverse( char * name, uint8_t vec[],
    int n ) {
  int   i;

  printf( "%s: ", name );
  for( i = n - 1; i >= 0; i-- ) {
    print_uint8_in_binary( vec[ i ] );
    if( i > 0 ) {
      printf( "- " );
    }
  }
  printf( "\n" );
  fflush( stdout );
}

// ============================================================================
void print_uint16_vector_as_bin_in_reverse( char * name, uint16_t vec[],
    int n ) {
  int   i;

  printf( "%s: ", name );
  for( i = n - 1; i >= 0; i-- ) {
    print_uint8_in_binary( ( uint8_t ) ( ( vec[ i ] >> 8 ) & 0xFF ) );
    print_uint8_in_binary( ( uint8_t ) ( ( vec[ i ]      ) & 0xFF ) );
    if( i > 0 ) {
      printf( "- " );
    }
  }
  printf( "\n" );
  fflush( stdout );
}

// ============================================================================
void print_int_vector( char * name, int vec[], int n ) {
  int  i;

  printf( "%s: ", name );
  for( i = 0; i < n; i++ ) {
    printf( "%d ", vec[ i ] );
  }
  printf( "\n" );
  fflush( stdout );
}

// ============================================================================
void print_uint32_vector_as_bin( char * name, uint32_t vec[], int n ) {
  int   i;

  printf( "%s: ", name );
  for( i = 0; i < n; i++ ) {
    print_uint32_in_binary( vec[ i ] );
  }
  printf( "\n" );
  fflush( stdout );
}

// ============================================================================
void print_uint32_matrix( char * name, uint32_t * mat, int m, int n ) {
  int  i, j;

  printf( "%s: \n", name );
  for( i = 0; i < m; i++ ) {
    for( j = 0; j < n; j++ ) {
      printf( "%2d ", mat[ n * i + j ] );
    }
    printf( "\n" );
  }
  printf( "\n" );
  fflush( stdout );
}

// ============================================================================
void set_char_matrix_to_zero( char * mat, int k, int n ) {
  int  i, j;

  for( i = 0; i < k; i++ ) {
    for( j = 0; j < n; j++ ) {
      mat[ n * i + j ] = '\0';
    }
  }
}

// ============================================================================
void set_int_vector_to_zero( int * vec, int n ) {
  int  i;

  for( i = 0; i < n; i++ ) {
    vec[ i ] = 0;
  }
}

// ============================================================================
void set_uint32_vector_to_zero( uint32_t * vec, int n ) {
  int  i;

  for( i = 0; i < n; i++ ) {
    vec[ i ] = 0;
  }
}

// ============================================================================
void copy_uint8_vector( int n, uint8_t * targetVec, uint8_t * sourceVec ) {
  int  i;

  for( i = 0; i < n; i++ ) {
    targetVec[ i ] = sourceVec[ i ];
  }
}

// ============================================================================
void copy_uint16_vector( int n, uint16_t * targetVec, uint16_t * sourceVec ) {
  int  i;

  for( i = 0; i < n; i++ ) {
    targetVec[ i ] = sourceVec[ i ];
  }
}

// ============================================================================
void copy_char_matrix( int k, int n, char * targetMat, char * sourceMat ) {
  int  i, j;

  for( i = 0; i < k; i++ ) {
    for( j = 0; j < n; j++ ) {
      targetMat[ n * i + j ] = sourceMat[ n * i + j ];
    }
  }
}

// ============================================================================
static void print_uint8_in_binary( uint8_t a ) {
  int  i;

  for( i = 7; i >= 0; i-- ) {
    printf( "%1d ", ( a >> i ) & 1 );
  }
}

// ============================================================================
static void print_uint32_in_binary( uint32_t a ) {
  print_uint8_in_binary( ( uint8_t )( ( a >> 24 ) & 0xFF ) );
  print_uint8_in_binary( ( uint8_t )( ( a >> 16 ) & 0xFF ) );
  print_uint8_in_binary( ( uint8_t )( ( a >>  8 ) & 0xFF ) );
  print_uint8_in_binary( ( uint8_t )( ( a       ) & 0xFF ) );
}

// ============================================================================
int are_equal_uint32_vectors( int numElems,
    uint32_t * vec1, uint32_t * vec2 ) {
// Return 1 if contents of vectors are the same. Othersize, return 0.
  int  i, equal;

  equal = 1;
  for( i = 0; i < numElems; i++ ) {
    if( vec1[ i ] != vec2[ i ] ) {
      equal = 0;
      break;
    }
  }
  return( equal );
}

// ============================================================================
int get_num_combinations( int m, int n ) {
  uint64_t  numer, denom, quotient;

  //// printf( "m n:  %d %d\n", m, n );
  if( n == 1 ) {
    quotient = ( uint64_t ) m;
  } else {
    numer = compute_product_range( ( uint64_t ) ( m - n + 1 ), ( uint64_t ) m );
    denom = compute_product_range( ( uint64_t ) 2, ( uint64_t ) n );
    quotient = numer / denom;
    //// printf( "numer:  %lld\n", numer );
    //// printf( "denom:  %lld\n", denom );
    //// printf( "m n: %d %d  numer: %lld denom: %lld  num: %lld\n",
    ////         m, n, numer, denom, numer / denom );

    // Check for large values of quotient before truncating to int.
    if( quotient > ( uint64_t ) 2000000000 ) {
      fprintf( stderr, "\n" );
      fprintf( stderr, "ERROR in get_num_combinations: " );
      fprintf( stderr, "Number of combinations too large.\n\n\n" );
      exit( -1 );
    }
  }
  //// printf( "quotient: %d \n", ( int ) quotient );
  return( ( int ) quotient );
}

// ============================================================================
static uint64_t compute_product_range( uint64_t iStart, uint64_t iEnd ) {
  uint64_t  f, i;

  f = 1;
  for( i = iStart; i <= iEnd; i++ ) {
    f *= i;
  }
  return( f );
}



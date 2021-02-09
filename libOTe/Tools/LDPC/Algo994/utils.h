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


#include <stdint.h>

// ============================================================================
// Declaration of macros.

//#define min( a, b ) ( (a) < (b) ? (a) : (b) )
//#define max( a, b ) ( (a) > (b) ? (a) : (b) )
void set_random_int_seed(unsigned long long seed);
int get_random_int();

void set_print_logs(int b);
int print_logs();


#ifdef _MSC_VER

inline int posix_memalign(void** ptr, size_t align, size_t size)
{
    int saved_errno = errno;
    void* p = malloc(size);
    if (p == NULL)
    {
        errno = saved_errno;
        return -1;
    }

    *ptr = p;
    return 0;
}
#endif

// ============================================================================
// Declaration of function prototypes.

void check_condition_is_true( int condition, char * routineName,
    char * message );

void create_uninitialized_char_vector( char * routineName,
    char ** vector, int numElements );

void create_uint8_vector( char * routineName,
    uint8_t ** vector, int numElements );

void create_uint16_vector( char * routineName,
    uint16_t ** vector, int numElements );

void create_int_vector( char * routineName,
    int ** vector, int numElements );

void create_uninitialized_int_vector( char * routineName,
    int ** vector, int numElements );

void create_aligned_uint32_vector( char * routineName,
    uint32_t ** vector, int numElements );

void init_vector_with_combinations( int lastValueInPrefix,
    int * vecCombi, int numElements );

int read_char_matrix( char * fileName, char ** mat, int * m, int * n );

void read_char_matrix_2( char * fileName, char ** mat, int * m, int * n );

void print_char_matrix( char * name, char * mat, int m, int n );

void print_uint32_matrix_as_bin( char * name, uint32_t * mat, int m, int n );

void print_uint8_vector_as_bin_in_reverse( char * name, uint8_t vec[],
    int n );

void print_uint16_vector_as_bin_in_reverse( char * name, uint16_t vec[],
    int n );

void print_int_vector( char * name, int vec[], int n );

void print_uint32_vector_as_bin( char * name, uint32_t vec[], int n );

void print_uint32_matrix( char * name, uint32_t * mat, int m, int n );

void set_char_matrix_to_zero( char * mat, int m, int n );

void set_int_vector_to_zero( int * vec, int n );

void set_uint32_vector_to_zero( uint32_t * vec, int n );

void copy_char_matrix( int m, int n, char * targetMat, char * sourceMat );

void copy_uint8_vector( int n, uint8_t * targetVec, uint8_t * sourceVec );

void copy_uint16_vector( int n, uint16_t * targetVec, uint16_t * sourceVec );

int are_equal_uint32_vectors( int numElems,
    uint32_t * vec1, uint32_t * vec2 );

int get_num_combinations( int m, int n );



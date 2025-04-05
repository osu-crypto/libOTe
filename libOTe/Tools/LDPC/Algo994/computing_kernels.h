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


void init_computing_kernels_module();

int compute_distance_of_uint32_vector_with_precomputing(
    uint32_t * vec, int n );

void copy_uint32_vector( int n, uint32_t * targetVec, uint32_t * sourceVec );

void add_uint32_vector_to_vector( int n, uint32_t * targetVec,
    uint32_t * sourceVec );

void add_two_uint32_vectors( int n, uint32_t * targetVec,
    uint32_t * sourceVec1, uint32_t * sourceVec2 );

void copy_uint32_matrix( int numRows, int numCols, int rowStride,
    uint32_t * targetMat, uint32_t * sourceMat );

int compute_distance_of_uint32_rows( int k, int n,
    uint32_t * gammaMatrices, int rowStride );

void add_selected_rows( int k, int n, int numRows,
    uint32_t * gammaMatrices, int rowStride,
    uint32_t * vecAddition, int * vecIndices );

void accumulate_uint32_vector_and_selected_rows( int k, int n, int numRows,
    uint32_t * gammaMatrices, int rowStride,
    uint32_t * vecAddition, int * vecIndices );

int add_every_row_to_uint32_vector_and_compute_distance( int k, int n,
    uint32_t * gammaMatrices, int rowStride, uint32_t * vecAddition );

int add_every_row_to_two_int_vectors_and_compute_distance( int k, int n,
    uint32_t * gammaMatrices, int rowStride,
    uint32_t * vecAddition1, uint32_t * vecAddition2 );


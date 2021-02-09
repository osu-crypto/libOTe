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


#ifndef DATA_DEFS_H_
#define DATA_DEFS_H_
#include <stdint.h>


// ============================================================================
// Declaration of constants.
//
#define ALG_BASIC           1
#define ALG_OPTIMIZED       2
#define ALG_STACK           3
#define ALG_SAVED           4
#define ALG_SAVED_UNROLLED  5
#define ALG_GRAY            10


// ============================================================================
// Declaration of types.

typedef struct GammaMatrix GammaMatrix;
struct GammaMatrix {
  uint32_t  * buffer;       // buffer is kGamma x rowStride.
  int       numRows;        // Old name: kGamma.
  int       rowStride;      // Old name: rowStride.
  int       actualNumCols;  // Old name: actualRowSize.
  int       rank;
};

typedef struct SavedCombi SavedCombi;
struct SavedCombi {
  int       filled;
  int       numCombinations;  // Number of rows in matAdditions, and number of
                              // elements in vecLastDigits.
  int       rowStrideMat;     // Number of total columns in matAdditions.
  int       actualNumColsMat; // Number of columns with useful info in
                              // matAdditions.
  uint32_t  * matAdditions;   // matAdditions is numCombinations x rowStrideMat.
  int       * vecLastDigits;
};

#endif


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
#include <stdint.h>
#include <assert.h>
#include <omp.h>
#include "libOTe/Tools/LDPC/Algo994/utils.h"
#include "libOTe/Tools/LDPC/Algo994/computing_kernels.h"
#include "libOTe/Tools/LDPC/Algo994/alg_gray.h"



#undef PRINT_MESSAGES



// ============================================================================
// Declaration of local prototypes.

static int compute_distance_of_range_of_combinations(int numCompactElems,
    uint16_t* vecLowerBound, uint16_t* vecUpperBound,
    int kInput, int rowStride, uint32_t* compactInputMatrix);

static int compare_binary_codes(int numCompactElems,
    uint16_t* vecBinaryCode1, uint16_t* vecBinaryCode2);

static void set_right_most_part(int numCompactElems,
    uint16_t* vecBinaryCode, uint32_t value);

static uint32_t extract_right_most_part(int numCompactElems,
    uint16_t* vecBinaryCode);

static void set_bit_to_one(int numCompactElems,
    uint16_t* vecBinaryCode, int bitNumber);

static void increment_binary_vector(int numCompactElems,
    uint16_t* vecBinaryCode);

static void compute_addition_of_rows_in_code(int numCompactElems,
    uint16_t* vecCode,
    int kInput, int rowStride, uint32_t* compactInputMatrix,
    uint32_t* vecAddition);

static int find_the_only_difference(int numCompactElems,
    uint16_t* vecCode1, uint16_t* vecCode2);

static void obtain_gray_code_from_binary_code(int numCompactElems,
    uint16_t* vecGrayCode, uint16_t* vecBinaryCode);

#ifndef min
#define min(a,b) (((a) < (b)) ? (a) : (b))
#endif // !min


// ============================================================================
int generate_with_gray_alg(int cfg_num_cores,
    int kInput, int rowStride, uint32_t* compactInputMatrix,
    int printMethod) {
    //
    // Gray algorithm.
    //
    int       minDist, minDistThread, threadId,
        sizeInBitsOfElem, numCompactElems;
    uint16_t* vecLowerBound, * vecUpperBound, * vecTotal;
    uint32_t  rmpNumCombinations, rmpNumCombinationsPerCore,
        rmpLowerBound, rmpUpperBound;

    if (printMethod == 1) {
        printf("    generate_with_gray_alg with cores: %d\n", cfg_num_cores);
    }

    // Quick return.
    if (kInput <= 0) {
        return 0;
    }

    // Compute the number of compacted elements in vectors.
    sizeInBitsOfElem = 8 * sizeof(uint16_t);
    numCompactElems = (kInput + sizeInBitsOfElem) / sizeInBitsOfElem;

#ifdef PRINT_MESSAGES
    printf("  cfg_num_cores:    %d\n", cfg_num_cores);
    printf("  kInput:           %d\n", kInput);
    printf("  numCompactElems:  %d\n", numCompactElems);
#endif

    // Create and initialize a vector for storing the total number of
    // combinations.
    create_uint16_vector("generate_with_gray_alg",
        &vecTotal, numCompactElems);

    set_bit_to_one(numCompactElems, vecTotal, kInput);

#ifdef PRINT_MESSAGES
    print_uint16_vector_as_bin_in_reverse("vecTotal", vecTotal,
        numCompactElems);
    printf("\n");
#endif

    //
    // To avoid arithmetic with k-bits (where k might be large),
    // the right-most part (two elements) of the number of total combinations
    // and the right-most part (two elements) of the number of total
    // combinations per core are computed. The resulting work partitioning
    // among the threads is not exact, but it avoids complex arithmetic.
    //
    /*
    digitsShifted = kInput -
                    sizeInBitsOfElem *
                    max( 0,
                         ( kInput + sizeInBitsOfElem - 1 ) /
                             sizeInBitsOfElem - 2 );
    rmpNumCombinations = 1 << digitsShifted;
    printf( "  digitsShifted:          %d\n", digitsShifted );
    printf( "  rmpNumCombinations 2:     %d\n", rmpNumCombinations );
    */
    rmpNumCombinations = extract_right_most_part(numCompactElems, vecTotal);
    rmpNumCombinationsPerCore =
        (rmpNumCombinations + ((uint32_t)cfg_num_cores) - 1) /
        ((uint32_t)cfg_num_cores);
    assert(rmpNumCombinationsPerCore > 0);
#ifdef PRINT_MESSAGES
    printf("  rmpNumCombinations:        %d\n", rmpNumCombinations);
    printf("  rmpNumCombinationsPerCore: %d\n", rmpNumCombinationsPerCore);
#endif

    // Initialize global minDist.
    minDist = -1;

#pragma omp parallel \
      private( threadId, \
               minDistThread, \
               rmpLowerBound, rmpUpperBound, \
               vecLowerBound, vecUpperBound ) \
      num_threads( cfg_num_cores )
    {
        threadId = omp_get_thread_num();
        rmpLowerBound = rmpNumCombinationsPerCore * ((uint32_t)threadId);
        rmpUpperBound = min(rmpNumCombinationsPerCore *
            (((uint32_t)threadId) + 1),
            rmpNumCombinations);

#ifdef PRINT_MESSAGES
#pragma omp critical
        {
            printf("threadId: %d   rmpLowerBound: %d   rmpUpperBound: %d\n",
                threadId, rmpLowerBound, rmpUpperBound);
        }
#endif

        // Create a vector for storing the lower bound.
        create_uint16_vector("generate_with_gray_alg",
            &vecLowerBound, numCompactElems);

        // Create a vector for storing the upper bound.
        create_uint16_vector("generate_with_gray_alg",
            &vecUpperBound, numCompactElems);

        // Initialize the vector for storing the lower bound.
        if (threadId == 0) {
            // First thread: Set vecLowerBound to 0...01.
            set_bit_to_one(numCompactElems, vecLowerBound, 0);
        }
        else {
            // Non-first thread.
            set_right_most_part(numCompactElems, vecLowerBound, rmpLowerBound);
        }

        // Initialize the vector for storing the upper bound.
        if (threadId == cfg_num_cores - 1) {
            // Last thread: Set vecUpperBound to the total number of combinations.
            copy_uint16_vector(numCompactElems, vecUpperBound, vecTotal);
        }
        else {
            // Non-last thread.
            set_right_most_part(numCompactElems, vecUpperBound, rmpUpperBound);
        }

#ifdef PRINT_MESSAGES
#pragma omp critical
        {
            print_uint16_vector_as_bin_in_reverse("lowerb  ", vecLowerBound,
                numCompactElems);
            print_uint16_vector_as_bin_in_reverse("upperb  ", vecUpperBound,
                numCompactElems);
        }
#endif

        // Compute the minimum distance of the range of combinations between
        // vecLowerBound (included) and vecUpperBound (not included).
        minDistThread = compute_distance_of_range_of_combinations(
            numCompactElems,
            vecLowerBound, vecUpperBound,
            kInput, rowStride, compactInputMatrix);

        // Update minimum distance.
#pragma omp critical
        if ((minDistThread > 0) &&
            ((minDist == -1) || (minDistThread < minDist))) {
            minDist = minDistThread;
        }

        // Remove the vectors with the lower and upper bounds.
        free(vecLowerBound);
        free(vecUpperBound);
    }

    // Remove the vector for storing the total number of combinations.
    free(vecTotal);

    // Return minimum distance.
    return(minDist);
}

// ============================================================================
static int compute_distance_of_range_of_combinations(int numCompactElems,
    uint16_t* vecLowerBound, uint16_t* vecUpperBound,
    int kInput, int rowStride, uint32_t* compactInputMatrix) {
    //
    // It computes the distance of the range of combinations between
    // vecLowerBound (included) and vecUpperBound (not included).
    //
    uint32_t* vecAddition;
    uint16_t* vecBinaryCode, * vecGrayCode, * vecPreviousGrayCode;
    int       minDist, dist, idxDiff, firstTime, compare;

    // Create the vector for storing the addition of combinations.
    create_aligned_uint32_vector("generate_with_gray_alg",
        &vecAddition, rowStride);

    // Initialize the vector for storing the addition of combinations to zero.
    set_uint32_vector_to_zero(vecAddition, rowStride);

    // Create and initialize a vector for storing the Gray code.
    create_uint16_vector("generate_with_gray_alg",
        &vecGrayCode, numCompactElems);

    // Create and initialize a vector for storing the previous Gray code.
    create_uint16_vector("generate_with_gray_alg",
        &vecPreviousGrayCode, numCompactElems);

    // Create a vector for storing the current combination.
    create_uint16_vector("generate_with_gray_alg",
        &vecBinaryCode, numCompactElems);

    // Copy vecLowerBound to vecBinaryCode.
    copy_uint16_vector(numCompactElems, vecBinaryCode, vecLowerBound);

    // Initialize the vector for storing the current Gray code.
    obtain_gray_code_from_binary_code(numCompactElems, vecGrayCode,
        vecBinaryCode);

    // Main loop for traversing all the combinations assigned.
    minDist = -1;
    firstTime = 1;
    // Check if current code is smaller than the upper bound.
    compare = compare_binary_codes(numCompactElems,
        vecBinaryCode, vecUpperBound);
    while (compare == 1) {

        //// print_uint16_vector_as_bin_in_reverse( "  i", vecBinaryCode,
        ////     numCompactElems );
        //// print_uint16_vector_as_bin_in_reverse( "  g", vecGrayCode,
        ////     numCompactElems );
        //// printf( "\n" );

        if (firstTime == 1) {
            // The first time there is no previous saved addition in vecAddition.
            firstTime = 0;

            // Compute the addition of the rows of compactInputMatrix whose
            // index is set to one in vecGrayCode.
            compute_addition_of_rows_in_code(numCompactElems, vecGrayCode,
                kInput, rowStride, compactInputMatrix, vecAddition);

        }
        else {
            // The rest of times there is a previous addition in vecAddition that
            // can be reused to save work.

            // Find out the difference of the current Gray code and the previous
            // one.
            idxDiff = find_the_only_difference(numCompactElems,
                vecGrayCode, vecPreviousGrayCode);
            assert(idxDiff < kInput);

            // Add the new different row to the current addition.
            add_uint32_vector_to_vector(rowStride,
                vecAddition, &compactInputMatrix[idxDiff * rowStride + 0]);
        }

        // Compute the distance of the addition.
        dist = compute_distance_of_uint32_vector_with_precomputing(
            vecAddition, rowStride);

        // Update minimum distance.
        if ((dist > 0) &&
            ((minDist == -1) || (dist < minDist))) {
            minDist = dist;
        }
        //// printf( "  dist: %d   minDist: %d\n", dist, minDist );

        // Get next combination.
        increment_binary_vector(numCompactElems, vecBinaryCode);

        // Save current gray code.
        copy_uint16_vector(numCompactElems, vecPreviousGrayCode, vecGrayCode);

        // Obtain new gray code from current binary code.
        obtain_gray_code_from_binary_code(numCompactElems, vecGrayCode,
            vecBinaryCode);

        // Check if current code is smaller than the upper bound.
        compare = compare_binary_codes(numCompactElems,
            vecBinaryCode, vecUpperBound);
    }

    // Remove the vector with combinations.
    free(vecBinaryCode);

    // Remove the vectors with the Gray codes.
    free(vecGrayCode);
    free(vecPreviousGrayCode);

    // Remove the vector with the addition of combinations.
    free(vecAddition);

    // Return minimum distance.
    return(minDist);
}

// ============================================================================
static int compare_binary_codes(int numCompactElems,
    uint16_t* vecBinaryCode1, uint16_t* vecBinaryCode2) {
    // It returns -1,0,1 depending on the result of the comparison between
    // vecBinaryCode1 and vecBinaryCode2.
    int  i, compare;

    // Main loop to compare: Start comparing the right-most elements.
    compare = 0;
    i = numCompactElems - 1;
    while ((i > 0) && (vecBinaryCode1[i] == vecBinaryCode2[i])) {
        i--;
    }
    // The loop is done.
    if (vecBinaryCode1[i] < vecBinaryCode2[i]) {
        compare = 1;
    }
    else if (vecBinaryCode1[i] > vecBinaryCode2[i]) {
        compare = -1;
    }
    else {
        compare = 0;
    }
    return compare;
}

// ============================================================================
static void set_right_most_part(int numCompactElems,
    uint16_t* vecBinaryCode, uint32_t value) {
    // It sets the two right-most elements in the vector to the contents of value.
    int  sizeInBitsOfElem;

    if (numCompactElems == 1) {
        vecBinaryCode[0] = (uint16_t)value;
    }
    else if (numCompactElems > 1) {
        sizeInBitsOfElem = 8 * sizeof(uint16_t);
        vecBinaryCode[numCompactElems - 1] =
            (uint16_t)(value >> sizeInBitsOfElem);
        vecBinaryCode[numCompactElems - 2] = (uint16_t)value;
    }
}

// ============================================================================
static uint32_t extract_right_most_part(int numCompactElems,
    uint16_t* vecBinaryCode) {
    // It extracts and returns the two right-most elements in the vector.
    int       sizeInBitsOfElem;
    uint32_t  result, rightPart, leftPart;

    if (numCompactElems == 0) {
        result = 0;
    }
    else if (numCompactElems == 1) {
        result = vecBinaryCode[0];
    }
    else {
        sizeInBitsOfElem = 8 * sizeof(uint16_t);
        rightPart = (uint32_t)
            (((uint32_t)vecBinaryCode[numCompactElems - 1])
                << sizeInBitsOfElem);
        leftPart = (uint32_t)vecBinaryCode[numCompactElems - 2];
        result = rightPart | leftPart;
    }
    return result;
}

// ============================================================================
static void set_bit_to_one(int numCompactElems,
    uint16_t* vecBinaryCode, int bitNumber) {
    // It sets the left-most bitNumber-th bit in vector to one.
    int  sizeInBitsOfElem, quotient, remainder;

    sizeInBitsOfElem = 8 * sizeof(uint16_t);
    quotient = bitNumber / sizeInBitsOfElem;
    assert(quotient < numCompactElems);
    remainder = bitNumber % sizeInBitsOfElem;
    //// printf( "bitNumber: %d \n", bitNumber );
    //// printf( "quotient:  %d \n", quotient );
    //// printf( "remainder: %d \n", remainder );
    vecBinaryCode[quotient] = (uint16_t)
        (vecBinaryCode[quotient] | (1 << remainder));
}

// ============================================================================
static void increment_binary_vector(int numCompactElems,
    uint16_t* vecBinaryCode) {
    // It increments the vector with a binary code in one unit.
    int       i, sizeInBitsOfElem;
    uint32_t  top, carry;

    sizeInBitsOfElem = 8 * sizeof(uint16_t);
    top = (uint32_t)((1 << sizeInBitsOfElem) - 1);
    carry = 1;
    i = 0;
    do {
        if (vecBinaryCode[i] < top) {
            vecBinaryCode[i] = (uint16_t)(vecBinaryCode[i] + 1);
            carry = 0;
        }
        else {
            vecBinaryCode[i] = 0;
            carry = 1;
        }
        i++;
    } while ((i < numCompactElems) && (carry == 1));
}

// ============================================================================
static void compute_addition_of_rows_in_code(int numCompactElems,
    uint16_t* vecCode,
    int kInput, int rowStride, uint32_t* compactInputMatrix,
    uint32_t* vecAddition) {
    // It computes and returns into vecAddition the addition of the rows in
    // compactInputMatrix whose indices are set to one inside vecCode.
    int       i, j, rowIdx, sizeInBitsOfElem;
    uint16_t  elem;

    // Initialize the vector for storing the addition of combinations to zero.
    set_uint32_vector_to_zero(vecAddition, rowStride);

    sizeInBitsOfElem = 8 * sizeof(uint16_t);
    rowIdx = 0;
    for (i = 0; i < numCompactElems; i++) {
        elem = vecCode[i];
        for (j = 0; j < sizeInBitsOfElem; j++) {
            if ((elem & 1) == 1) {
                add_uint32_vector_to_vector(rowStride,
                    vecAddition, &compactInputMatrix[rowIdx * rowStride + 0]);
            }
            elem = (uint16_t)(elem >> 1);
            rowIdx++;
        }
    }
}

// ============================================================================
static int find_the_only_difference(int numCompactElems,
    uint16_t* vecCode1, uint16_t* vecCode2) {
    // It returns the index of the only difference between two codes. There must
    // be one and only one different bit.
    int       i, j, sizeInBitsOfElem;
    uint16_t  diff;

    // Search for the element in the vector that is different.
    i = 0;
    while ((i < numCompactElems) &&
        (vecCode1[i] == vecCode2[i])) {
        i++;
    }
    assert(i < numCompactElems);

    // Search for the bit that is different inside the element.
    sizeInBitsOfElem = 8 * sizeof(uint16_t);
    diff = (uint16_t)(vecCode1[i] ^ vecCode2[i]);
    j = 0;
    while ((j < sizeInBitsOfElem) && ((diff & 1) == 0)) {
        diff = (uint16_t)(diff >> 1);
        j++;
    }
    assert(j < sizeInBitsOfElem);

    return(i * sizeInBitsOfElem + j);
}

// ============================================================================
static void obtain_gray_code_from_binary_code(int numCompactElems,
    uint16_t* vecGrayCode, uint16_t* vecBinaryCode) {
    // It converts a binary code into a gray code.
    int       i, sizeInBitsOfElemMinusOne;
    uint16_t  shifted, rightMostBitToZero;

    //// rightMostBitToZero = 0x7FFF;
    sizeInBitsOfElemMinusOne = 8 * sizeof(uint16_t) - 1;
    rightMostBitToZero = (uint16_t)~(1 << sizeInBitsOfElemMinusOne);
    for (i = 0; i < numCompactElems; i++) {
        shifted = (uint16_t)(vecBinaryCode[i] >> 1);
        shifted &= rightMostBitToZero;
        if (i < numCompactElems - 1) {
            shifted = (uint16_t)
                (shifted |
                ((vecBinaryCode[i + 1] & 1) << sizeInBitsOfElemMinusOne));
        }
        vecGrayCode[i] = (uint16_t)(vecBinaryCode[i] ^ shifted);
    }
}



#ifndef LIBOTE_BINOMIALCOEFFICIENTTEST_H
#define LIBOTE_BINOMIALCOEFFICIENTTEST_H

#include <cassert>
#include <chrono>
#include <iostream>
#include <vector>
#include "cryptoTools/Common/CLP.h"

namespace osuCrypto {

    ///*
    //NEW BINOMIAL COEFFICIENT FUNCTION BASED ON PASCAL'S TRIANGLE WITH CACHING ACROSS CALLS

    //Static Cache: The function uses a static cache, which is a std::vector of std::vector<T>, 
    //to store previously computed values of the binomial coefficient "n choose k." The cache 
    //allows the function to avoid recomputation by storing results of binomial coefficient 
    //calculations, which can be reused in future calls. The value -1 is used to denote 
    //uncomputed values within the cache.

    //Dynamic Resizing: To handle any input values of "n" and "k," the function dynamically 
    //resizes the cache. If the cache has fewer rows than needed for the requested "n," it resizes 
    //to accommodate up to row "n." Similarly, if row "n" has fewer columns than required for "k," 
    //it resizes that row up to column "k." This dynamic resizing ensures that the cache can store 
    //values up to the requested "n" and "k," allowing the function to retain previously computed 
    //results.

    //Symmetry Optimization: The function takes advantage of the symmetry of binomial coefficients, 
    //where "n choose k" is the same as "n choose (n - k)." By setting "k" to min(k, n - k), the 
    //function minimizes the number of multiplications needed, reducing computation time.

    //Checking Cache: After resizing, the function first checks whether the required value "n choose k"
    //is already in the cache. If the cache contains a previously computed value, the function simply 
    //returns it immediately, saving time and resources.

    //1D Row Calculation: The function calculates Pascal’s Triangle values up to the "n-th" row using 
    //a single row vector of size "k + 1." Each element row[j] represents the binomial coefficient for
    //the current row "i choose j." For each row "i," it updates row[j] from right to left (starting 
    //from min(i, k) down to 1). This update pattern ensures that each row[j] value is based on the 
    //values from the previous row of Pascal’s Triangle, but only one row is stored at a time, making 
    //the calculation efficient in terms of memory.

    //Cache Storage: After calculating the desired binomial coefficient, the function stores this
    //value in cache[n][k] before returning it. Storing the value allows any future requests for 
    //"n choose k" to retrieve the result directly from the cache, avoiding recomputation.

    //This function is optimized for efficiency by using caching, symmetry reduction, and a dynamic
    //programming approach with a 1D row calculation based on Pascal’s Triangle. It is suitable for 
    //computing binomial coefficients with moderate values of "n" and "k" and can handle repeated calls 
    //efficiently due to caching.
    //*/
    //template <typename T>
    //T choose_new(int64_t n, int64_t k, std::vector<std::vector<T>>& cache) {
    //    if (k < 0 || k > n)
    //        return 0;
    //    if (k == 0 || k == n)
    //        return 1;

    //    // Reduce the number of calculations by using symmetry: C(n, k) = C(n, n - k)
    //    if (k > n - k)
    //        k = n - k;

    //    // Resize the cache if necessary
    //    if (cache.size() <= n) {
    //        cache.resize(n + 1);
    //    }

    //    // Resize the specific row if necessary
    //    if (cache[n].size() <= k) {
    //        cache[n].resize(k + 1, -1); // Use -1 to denote uncomputed values
    //    }

    //    // Return cached value if it exists
    //    if (cache[n][k] != -1) return cache[n][k];

    //    // Option 1
    //    // computes unnecessary values in a row even if just one k for n is needed
    //    // does not cache intermediate rows
    //    /*
    //    // Use a 1D vector to store the current row of Pascal's Triangle
    //    std::vector<T> row(k + 1, 0);
    //    row[0] = 1; // C(n, 0) is always 1

    //    // Build up Pascal's Triangle up to the nth row
    //    for (int64_t i = 1; i <= n; ++i) {
    //        // Update row from the end to the beginning to use only one array
    //        for (int64_t j = std::min(i, k); j > 0; --j) {
    //            row[j] += row[j - 1];
    //        }
    //    }

    //    // Store the result in the cache before returning
    //    cache[n][k] = row[k];
    //    return row[k];
    //    */
    //    // Option 2: avoids the issues in the first option
    //    // Recursive computation: C(n, k) = C(n-1, k-1) + C(n-1, k)
    //    cache[n][k] = choose_new<T>(n - 1, k - 1, cache) +
    //        choose_new<T>(n - 1, k, cache);
    //    return cache[n][k];
    //}

    //template <typename T>
    //inline T choose_old(int64_t n, int64_t k)
    //{
    //    if (k < 0 || k > n)
    //        return 0;
    //    if (k == 0 || k == n)
    //        return 1;

    //    k = std::min<int64_t>(k, n - k);
    //    T c = 1;
    //    for (uint64_t i = 0; i < k; ++i)
    //        c = c * (n - i) / (i + 1);
    //    return c;
    //}

    //inline void binomialCoefficientTestMain(const oc::CLP& cmd) {
    //    int64_t n = 1000;

    //    std::vector<std::vector<Int>> pascal_triangle;

    //    // Verify correctness
    //    for (int64_t k = -2; k < (n + 2); k++) {
    //        Int new_choose = choose_new<Int>(n, k, pascal_triangle);
    //        Int old_choose = choose_old<Int>(n, k);
    //        std::cout << "New: C(" << n << ", " << k << ") = " << new_choose << std::endl;
    //        std::cout << "Old: C(" << n << ", " << k << ") = " << old_choose << std::endl;
    //        assert(new_choose == old_choose);
    //    }

    //    // Check performance

    //    std::cout << "Running new..." << std::endl;
    //    auto start = std::chrono::high_resolution_clock::now();
    //    for (int64_t k = -2; k < (n + 2); k++) {
    //        // NOTE not completely fair as pascal_triangle already built
    //        Int new_choose = choose_new<Int>(n, k, pascal_triangle);
    //    }
    //    auto end = std::chrono::high_resolution_clock::now();
    //    // Calculate elapsed time in milliseconds
    //    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    //    std::cout << "Execution time: " << duration.count() << " microseconds" << std::endl;

    //    std::cout << "Running old..." << std::endl;
    //    start = std::chrono::high_resolution_clock::now();
    //    for (int64_t k = -2; k < (n + 2); k++) {
    //        Int old_choose = choose_old<Int>(n, k);
    //    }
    //    end = std::chrono::high_resolution_clock::now();
    //    // Calculate elapsed time in milliseconds
    //    duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    //    std::cout << "Execution time: " << duration.count() << " microseconds" << std::endl;
    //}
}

#endif // LIBOTE_BINOMIALCOEFFICIENTTEST_H
#ifndef PPCG_TOOLS_H
#define PPCG_TOOLS_H

#include <cstddef>

// factorial
template <typename I>
I factorial(size_t n) {
    if (n == 0) {
        return 1;
    }
    I res = 1;
    for (size_t i = 2; i <= n; i++) {
        res = res * i;
    }
    return res;
}

// n choose k
template<typename I>
I n_choose_k(int64_t n, int64_t k) {
    if (k > n) {
        return 0;
    }
    I sum = factorial<I>(n) / (factorial<I>(k) * factorial<I>(n - k));
    return sum;
}

// balls in bins
// TODO


// Balls in bins with capacity
template<typename I>
I balls_bins_capacity(size_t n, size_t k, size_t c) {
    I sum = 0;
    for (size_t i = 0; i <= k; i++) {
        int part_0 = (i % 2 == 0) ? 1 : -1;
        std::cout << part_0 << std::endl;
        I part_1 = n_choose_k<I>(k, i);
        I part_2 = n_choose_k<I>(n + k - i * (c + 1) - 1, k - 1);
        sum += (part_0 * part_1 * part_2);
    }
    return sum;
}

#endif //PPCG_TOOLS_H

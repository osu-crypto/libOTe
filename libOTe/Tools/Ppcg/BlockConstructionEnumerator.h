#ifndef PPCG_BLOCKCONSTRUCTIONENUMERATOR_H
#define PPCG_BLOCKCONSTRUCTIONENUMERATOR_H

#include <cstddef>
#include <iostream>

template<typename I, typename F>
I block_construction_enumerator(size_t w, size_t h,
                                size_t n, size_t sigma) {
    I enumerator = 0;
    size_t n_over_sigma = n / sigma;
    for (size_t q = 0; q <= n_over_sigma; q++) {
        // Part 1: 2^{-\sigma q}
        F part_one = 1.0 / (1 << (sigma * q));
        std::cerr << part_one << std::endl;

        // Part 2: E_{w,q}


        // Part 3: E_{q,h}


        // Put it all together

    }
    std::cout << "Computing enumerator for the block construction..." << std::endl;
    return enumerator;
}

#endif //PPCG_BLOCKCONSTRUCTIONENUMERATOR_H

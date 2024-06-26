#ifndef PPCG_BLOCKCONSTRUCTIONENUMERATOR_H
#define PPCG_BLOCKCONSTRUCTIONENUMERATOR_H

#include <cstddef>
#include <iostream>

#include "Tools.h"

template<typename I, typename F>
I block_construction_enumerator(size_t w, size_t h,
                                size_t n, size_t sigma) {
    std::cout << "Computing enumerator for the block construction..." << std::endl;
    I enumerator = 0;
    size_t n_over_sigma = n / sigma;
    for (size_t q = 0; q <= n_over_sigma; q++) {
        // Part 1: 2^{-\sigma q}
        F scale = 1.0 / (1 << (sigma * q));
        std::cerr << "scale " << scale << std::endl;

        // Part 2: E_{w,q}
        I E_wq = balls_bins_capacity<I>(w - q, q, sigma - 1);
        std::cerr << "E_wq " << E_wq << std::endl;

        // Part 3: E_{q,h} = sigma * q choose h
        I E_qh = n_choose_k<I>(sigma * q, h);
        std::cerr << "E_qh " << E_qh << std::endl;

        // Putting it all together
        enumerator += scale * E_wq * E_qh;
        std::cerr << "Enumerator " << enumerator << std::endl;
    }
    return enumerator;
}

#endif //PPCG_BLOCKCONSTRUCTIONENUMERATOR_H

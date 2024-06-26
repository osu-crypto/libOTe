#include <cassert>
#include <iostream>

#include "BlockConstructionEnumerator.h"
#include "Tools.h"

int main() {
    size_t w = 1; // input weight
    size_t h = 1; // output weight
    size_t n = 4; // x,y bit length
    size_t sigma = 2; // block length

    assert(n % sigma == 0);

    //
    // Tests for building blocks for the enumerators
    //
    assert(factorial<int>(3) == 6);
    assert(factorial<int>(9) == 362880);
    assert(n_choose_k<int>(3,3) == 1);
    assert(n_choose_k<int>(5,4) == 5);
    assert(n_choose_k<int>(2,3) == 0);
    assert(balls_bins_capacity<int>(8,3,4) == 15);

    // TODO


    //
    // Compute Enumerators
    //

    // 1. block construction
    int enumerator_block_construction = block_construction_enumerator<int, double>(w, h, n, sigma);
    std::cout << "Enumerator: " << enumerator_block_construction << std::endl;

    // 2. convolution construction
    // TODO enumerator other construction


    //
    // Compute minimum distance
    //

    // 1. block construction

    // 2. convolution construction

    return 0;
}

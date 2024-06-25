#include <cassert>
#include <iostream>

#include "BlockConstructionEnumerator.h"

int main() {
    size_t w = 1; // input weight
    size_t h = 1; // output weight
    size_t n = 4; // x,y bit length
    size_t sigma = 2; // block length

    assert(n % sigma == 0);

    //
    // Tests for building blocks for the enumerators
    //

    // TODO


    //
    // Compute Enumerators
    //
    int enumerator_block_construction = block_construction_enumerator<int, double>(w, h, n, sigma);
    std::cout << "Enumerator: " << enumerator_block_construction << std::endl;

    // TODO enumerator other construction

    return 0;
}

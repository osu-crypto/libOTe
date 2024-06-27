#ifndef LIBOTE_MINIMUMDISTANCE_H
#define LIBOTE_MINIMUMDISTANCE_H

#include "BlockEnumerator.h"
#include "NonrecConvEnumerator.h"
#include "EnumeratorTools.h"

namespace osuCrypto {

    template<typename I, typename R>
    I block_minimum_distance(u64 n, u64 sigma, u64 num_iters) {
        std::cout << "Computing minimum distance for the block construction..." << std::endl;

        assert(n % sigma == 0);

        // TODO consider impact of repeater

        // TODO Compute all n^2 possible block enumerators

        std::vector<Rat> temp (2, std::vector<Rat>(n));

        // First step is different
        for (size_t w = 0; w < n; w++) {
            temp[0][w] = choose_<R>(n, w);
        }

        // Remaining steps
        for (size_t iter = 0; iter < num_iters; iter++) {
            // compute temp[(iter+1) % 2]
            for (size_t h = 0; h < n; h++) {
                // TODO

            }
        }

        // Now take whichever of temp[0]/temp[1] was filled last
        // and find at which index the sum >= 1. That is the minimum distance




        return 0;
    }

    inline void minimumDistanceMain(oc::CLP& cmd) {
        u64 n = cmd.getOr("n", 10); // msg/codeword length
        u64 sigma = cmd.getOr("sigma", 2); // window size
        u64 num_iters = cmd.getOr("iters", 1); // number of permute & [multiply] iterations
        // TODO add repeater as the parameter

        std::cout << "n: " << n << std::endl;
        std::cout << "sigma: " << sigma << std::endl;

        assert(sigma <= n);
        assert(num_iters >= 1);

        if (cmd.isSet("block")) {
            Int block_minimum_distance = block_minimum_distance<Int, Rat>(n, sigma, num_iters);
            std::cout << "Block Minimum Distance: " << block_minimum_distance << std::endl;
        } else if (cmd.isSet("nonrecConv")) {
            // TODO
        }
    }
}


#endif //LIBOTE_MINIMUMDISTANCE_H

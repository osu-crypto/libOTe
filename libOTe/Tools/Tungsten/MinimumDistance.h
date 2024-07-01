#ifndef LIBOTE_MINIMUMDISTANCE_H
#define LIBOTE_MINIMUMDISTANCE_H

#include <vector>

#include "BlockEnumerator.h"
#include "NonrecConvEnumerator.h"
#include "EnumeratorTools.h"

namespace osuCrypto {

    template<typename I, typename R>
    u64 minimum_distance(u64 expander, u64 multiplier, u64 num_iters,
                         u64 n, u64 k, u64 sigma) {
        std::cout << "Computing minimum distance..." << std::endl;

        assert(sigma <= n);
        assert(num_iters >= 1);
        assert(k > 1); // need to be expanding
        assert(n % sigma == 0);

        // Compute all n^2 possible block enumerators
        // n^2 space... but it is reused at each iteration
        std::vector<std::vector<Rat>> block_enumerators(n, std::vector<Rat>(n));
        for (size_t w = 0; w < n; w++) {
            for (size_t h = 0; h < n; h++) {
                block_enumerators[w][h] = block_enum<Int, Rat>(w, h, n, sigma);
            }
        }

        // TODO consider impact of repeater

        // Save all n choose w as used at each iteration
        // n space
        std::vector<I> n_choose_w(n);
        for (size_t w = 0; w < n; w++) {
            n_choose_w[w] = choose_<I>(n, w);
        }

        // 2n space
        std::vector<std::vector<R>> temp(2, std::vector<R>(n));

        // First iteration is different
        for (size_t h = 0; h < n; h++) {
            for (size_t w = 0; w < n; w++) {
                temp[0][h] += block_enumerators[w][h];
            }
        }

        // Remaining iterations
        for (size_t iter = 1; iter < num_iters; iter++) {
            // compute temp[iter % 2]
            for (size_t h = 0; h < n; h++) {
                for (size_t w = 0; w < n; w++) {
                    temp[iter % 2][h] += temp[(iter + 1) % 2][w] / n_choose_w[w] * block_enumerators[w][h];
                }
            }
        }

        // Now take whichever of temp[0]/temp[1] was filled last
        // and find at which index the sum >= 1. That is the minimum distance
        R sum = 0;
        u64 minimum_distance = 0;
        for (size_t h = 0; h < n; h++) {
            sum += temp[(num_iters + 1) % 2][h];
            if (sum >= 1.) {
                return minimum_distance;
            }
            minimum_distance++;
        }
        return n;
    }

    inline void minimumDistanceMain(oc::CLP &cmd) {
        u64 n = cmd.getOr("n", 10); // msg/codeword length
        u64 sigma = cmd.getOr("sigma", 2); // window size
        // expander (0: repeater, 1: block expander)
        u64 expander = cmd.getOr("expander", 0);
        // multiplier (0: block, 1: non recursive convolution)
        // i.e. the enumerator we compute at each iteration
        u64 multiplier = cmd.getOr("multiplier", 0);
        u64 k = cmd.getOr("k", 2); // expansion param - how much to expand, e.g. 2x
        u64 num_iters = cmd.getOr("iters", 1); // number of permute & [multiply] iterations

        std::cout << "n: " << n << std::endl;
        std::cout << "sigma: " << sigma << std::endl;
        std::cout << "expander: " << expander << ", if 0 then repeater, "
                                                 "if 1 then block"
                  << std::endl;
        std::cout << "k (expansion parameter): " << k << std::endl;
        std::cout << "multiplier: " << multiplier << ", if 0 then block enumerator, "
                                                     "if 1 then non-recursive convolution enumerator"
                  << std::endl;

        u64 min_distance = minimum_distance<Int, Rat>(expander, multiplier,
                                                          num_iters, n, k, sigma);
        std::cout << "Minimum Distance: " << min_distance << std::endl;
    }
}

#endif //LIBOTE_MINIMUMDISTANCE_H

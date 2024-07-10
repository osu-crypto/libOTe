#ifndef LIBOTE_MINIMUMDISTANCE_H
#define LIBOTE_MINIMUMDISTANCE_H

#include <vector>

#include "BlockEnumerator.h"
#include "ExpandingBlockEnumerator.h"
#include "NonrecConvEnumerator.h"
#include "EnumeratorTools.h"
#include "RepeaterEnumerator.h"

namespace osuCrypto {

    /*
    // TODO this is version 2, v1 will be deprecated
    template<typename I, typename R>
    u64 minimum_distance_v2(u64 expander, u64 multiplier, u64 num_iters,
                            u64 k, u64 e, u64 sigma) {
        std::cout << "Computing minimum distance..." << std::endl;

        if (expander == 1) {
            // block expander at the beginning
            assert(e == 2); // TODO do we limit it to 2?
            assert(sigma <= k); // TODO should we have separate sigma for the expander?
        }

        u64 expanded_n = e * k;

        assert(sigma <= expanded_n);
        assert(num_iters >= 1);
        assert(e > 1); // need to be expanding
        assert(expanded_n % sigma == 0);

        // expander
        std::vector<R> distribution (expanded_n);
        for (size_t h1 = 0; h1 < expanded_n; h1++) {
            if (expander == 0) {
                // repeater
                distribution[h1] = repeater_enum<I>(w, h, k, e);
            } else if (expander == 1) {
                // block expander (identity + block)
                distribution[h1] = expanding_block_enum<I, R>(w, h, k, sigma);
            }

        }

        // Iterations (multipliers)
        for (size_t iter = 0; iter < num_iters; iter++) {
            distribution = std::move(compute_distribution<R>(distribution, //previous distribution
                                                             expanded_n, // middle length
                                                             expanded_n, // end length
                                                             multiplier)); // next enumerator
        }


        // Now take whichever of temp[0]/temp[1] was filled last
        // and find at which index the sum >= 1. That is the minimum distance
        R sum = 0;
        u64 minimum_distance = 0;
        for (size_t h = 0; h < expanded_n; h++) {
            sum += temp[num_iters % 2][h];
            if (sum >= 1.) {
                return minimum_distance;
            }
            minimum_distance++;
        }
        return expanded_n;
    }
    */

    template<typename I, typename R>
    u64 minimum_distance_v1(u64 expander, u64 multiplier, u64 num_iters,
                            u64 k, u64 n, u64 sigma) {
        std::cout << "Computing minimum distance..." << std::endl;

        if (expander == 1) {
            // block expander at the beginning
            assert(sigma <= k); // TODO should we have separate sigma for the expander?
        }

        u64 e = n / k;

        assert(sigma <= n);
        assert(num_iters >= 1);
        assert(n >= k);
        assert(e > 1); // need to be expanding
        assert(n % sigma == 0);

        // NOTE no longer used as k^2 space too big
        // Compute all k^2 possible block enumerators
        // k^2 space... but it is reused at each iteration
        /*
        std::vector<std::vector<R>> block_enumerators(k, std::vector<R>(k));
        for (size_t w = 0; w < k; w++) {
            for (size_t h = 0; h < k; h++) {
                block_enumerators[w][h] = block_enum<I, R>(w, h, k, sigma);
            }
        }
         */

        // Save all kn choose w as used at all iterations (but not expansion step)
        // kn space
        std::vector<I> kn_choose_w(n);
        for (size_t w = 0; w < n; w++) {
            kn_choose_w[w] = choose_<I>(n, w);
        }

        // 2 * kn space
        std::vector<std::vector<R>> temp(2, std::vector<R>(n));

        // Expansion step is slightly different from the iterations
        // as 1. we are expanding and 2. c_w = k choose w, so they divide each other
        for (size_t h = 0; h < n; h++) {
            // note that for repeater, we do NOT need this loop, but used now for modularity
            for (size_t w = 0; w < k; w++) {
                if (expander == 0) {
                    // repeater
                    temp[0][h] += repeater_enum<I>(w, h, k, e);
                } else if (expander == 1) {
                    // block expander (identity + block)
                    temp[0][h] += expanding_block_enum<I, R>(w, h, k, n, sigma);
                }
            }
        }

        // Iterations
        for (size_t iter = 0; iter < num_iters; iter++) {
            // compute temp[(iter + 1) % 2]
            for (size_t h = 0; h < n; h++) {
                for (size_t w = 0; w < n; w++) {
                    R enumerator = 0;
                    if (multiplier == 0) {
                        // block enumerator
                        enumerator = block_enum<I, R>(w, h, n, n, sigma);
                    } else if (multiplier == 1) {
                        // non-recursive convolution
                        // TODO
                        assert(false);
                    }
                    temp[(iter + 1) % 2][h] += temp[iter % 2][w] / kn_choose_w[w] * enumerator;
                }
            }
        }

        // Now take whichever of temp[0]/temp[1] was filled last
        // and find at which index the sum >= 1. That is the minimum distance
        R sum = 0;
        u64 minimum_distance = 0;
        for (size_t h = 0; h < n; h++) {
            sum += temp[num_iters % 2][h];
            if (sum >= 1.) {
                return minimum_distance;
            }
            minimum_distance++;
        }
        return n;
    }

    inline void minimumDistanceMain(oc::CLP &cmd) {
        u64 k = cmd.getOr("k", 10); // msg length
        u64 n = cmd.getOr("n", 20); // codeword length
        u64 sigma = cmd.getOr("sigma", 2); // window size
        // expander (0: repeater, 1: block expander)
        u64 expander = cmd.getOr("expander", 0);
        // multiplier (0: block, 1: non recursive convolution)
        // i.e. the enumerator we compute at each iteration
        u64 multiplier = cmd.getOr("multiplier", 0);
        u64 num_iters = cmd.getOr("iters", 1); // number of permute & [multiply] iterations

        std::cout << "k: " << k << std::endl;
        std::cout << "n: " << n << std::endl;
        std::cout << "sigma: " << sigma << std::endl;
        std::cout << "expander: " << expander << ", if 0 then repeater, "
                                                 "if 1 then block"
                  << std::endl;
        std::cout << "multiplier: " << multiplier << ", if 0 then block enumerator, "
                                                     "if 1 then non-recursive convolution enumerator"
                  << std::endl;

        u64 min_distance_v1 = minimum_distance_v1<Int, Rat>(expander, multiplier,
                                                            num_iters, k, n, sigma);
        std::cout << "Minimum Distance: " << min_distance_v1 << std::endl;
    }
}

#endif //LIBOTE_MINIMUMDISTANCE_H

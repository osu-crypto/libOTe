#ifndef LIBOTE_MINIMUMDISTANCE_H
#define LIBOTE_MINIMUMDISTANCE_H

#include <numeric>
#include <omp.h>
#include <vector>

#include "BlockEnumerator.h"
#include "ExpandingBlockEnumerator.h"
#include "NonrecConvEnumerator.h"
#include "EnumeratorTools.h"
#include "RepeaterEnumerator.h"

namespace osuCrypto {

    template<typename R>
    bool compare_distributions(const std::vector<R> &distribution1,
                               const std::vector<R> &distribution2,
                               u64 l, double tolerance) {
        assert(distribution1.size() == l);
        assert(distribution2.size() == l);
        for (size_t idx = 0; idx < l; idx++) {
            if ((distribution1[idx] - distribution2[idx]) > tolerance) {
                return false;
            }
        }
        return true;
    }

    template<typename I, typename R>
    void compute_expanding_distribution(std::vector<R> &distribution,
                                        u64 expander,
                                        u64 k,
                                        u64 n,
                                        u64 e,
                                        u64 sigma_expander) { // only for the expanding block
        assert(e == n / k);
        for (size_t h = 0; h <= n; h++) {
            // note that for repeater, we do NOT need this loop, but used now for modularity
            // NOTE we exclude w=0 from the input x as it would always result in all zeros
            for (size_t w = 1; w <= k; w++) {
                if (expander == 0) {
                    // repeater
                    distribution[h] += repeater_enum<I>(w, h, k, e);
                    assert(distribution[0] == 0);
                } else if (expander == 1) {
                    assert(sigma_expander > 0);
                    assert(sigma_expander <= k);
                    assert(k % sigma_expander == 0);
                    // block expander (identity + block)
                    distribution[h] += expanding_block_enum<I, R>(w, h, k, n, sigma_expander);
                }
            }
        }
    }

    template<typename I, typename R>
    void compute_next_distribution(const std::vector<R> &old_distribution,
                                   std::vector<R> &new_distribution,
                                   u64 multiplier,
                                   u64 n,
                                   u64 sigma) {
        std::fill(new_distribution.begin(), new_distribution.end(), R(0));

        // Precompute old_distribution[w] / R(n_choose_w) so that we do only n instead of n^2 times
        std::vector<R> count_fraction(n + 1);
        for (size_t w = 0; w <= n; w++) {
            // NOTE this n_choose_w value is not recomputed each time as the function caches the values in the Pascal triangle
            count_fraction[w] = old_distribution[w] / R(choose_<I>(n, w));
        }

#pragma omp parallel for collapse(2) reduction(+:new_distribution[:n+1])
        for (size_t h = 0; h <= n; h++) {
            for (size_t w = 0; w <= n; w++) {
                R enumerator = 0;
                if (multiplier == 0) {
                    // block enumerator
                    enumerator = block_enum<I, R>(w, h, n, n, sigma);
                } else if (multiplier == 1) {
                    // non-recursive convolution
                    // TODO
                    assert(false);
                }
//                    std::cout << "h " << h << std::endl;
//                    std::cout << "w " << w << std::endl;
//                    std::cout << "n " << n << std::endl;
//                    std::cout << "enumerator " << enumerator << std::endl;
//                    std::cout << "n choose w " <<n_choose_w[w] << std::endl;
                new_distribution[h] += (count_fraction[w] * enumerator);
            }
        }
    }

    template<typename R>
    u64 minimum_distance_from_distribution(u64 n, std::vector<R> &distribution) {
        assert(distribution.size() == (n + 1));
        R sum = 0;
        u64 minimum_distance = 0;
        for (size_t h = 0; h < n; h++) {
            sum += distribution[h];
            if (sum >= 1.) {
                return minimum_distance;
            }
            minimum_distance++;
        }
        assert(n == minimum_distance);
        return n;
    }

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
    std::vector<R> minimum_distance(u64 expander, u64 multiplier, u64 num_iters,
                                       u64 k, u64 n, u64 sigma, u64 sigma_expander) {
        // TODO Assumes G's sigma is the same for all iterations (except expanding step)
        // std::cout << "Computing minimum distance..." << std::endl;

        u64 e = n / k;

        assert(sigma <= n);
        assert(num_iters >= 1);
        assert(n >= k);
        assert(e > 1); // need to be expanding (otherwise no hope to have good minimum distance)
        assert(n % k == 0);
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

        // 2 * (n + 1) space
        std::vector<std::vector<R>> distributions(2, std::vector<R>(n + 1, 0)); // distribution for w = 0 to w = n

        // Compute distribution for the expansion step
        // Expansion step is slightly different from the iterations
        // At the beginning there are c_w = k choose w inputs of weight w<=k
        // After expansion, c_w (for w<=n) depends on what expander we use
        compute_expanding_distribution<I, R>(distributions[0], expander, k, n, e, sigma_expander);

        // Compute distributions for iterations
        for (size_t iter = 0; iter < num_iters; iter++) {
            // Compute distributions[(iter + 1) % 2]
            compute_next_distribution<I, R>(distributions[iter % 2],
                                            distributions[(iter + 1) % 2],
                                            multiplier,
                                            n, sigma);
        }

        // Now return the distribution associated with the last iteration

        // Check the sum of the final distribution is equal to the sum of the initial distribution
        R final_distribution_sum = std::reduce(distributions[num_iters % 2].begin(),
                                               distributions[num_iters % 2].end()); // distribution_sum<R>(distributions[num_iters % 2]);
        // Sum initial distribution
        R initial_distribution_sum = 0;
        for (size_t w = 1; w <= k; w++) {
            initial_distribution_sum += R(choose_<I>(k, w));
        }
        std::cout << "Initial distribution sum: " << initial_distribution_sum << std::endl;
        std::cout << "Final distribution sum: " << final_distribution_sum << std::endl;
        assert(final_distribution_sum == initial_distribution_sum);
        if (final_distribution_sum != initial_distribution_sum) throw RTE_LOC;

        return distributions[num_iters % 2];
    }

    void benchmarks() {

        // expander (0: repeater, 1: block expander), 
        // multiplier (0: block, 1: non recursive convolution), 
        // num_iters, k, n, sigma, sigma_expander (0 if repeater)

        //
        // varying iterations, everything else fixed
        //
        std::vector<std::vector<u64>> params = {
                //{0, 0, 2, 4, 8, 8, 0},
                //{0, 0, 2, 8, 16, 16, 0},
                //{0, 0, 2, 16, 32, 32, 0},
                //{0, 0, 2, 32, 64, 64, 0},
                //{0, 0, 2, 64, 128, 128, 0},
                //{0, 0, 2, 128, 256, 256, 0},
                //{0, 0, 2, 256, 512, 512, 0},
                {0, 0, 2, 512, 1024, 64, 0},
        };
        for (const auto & param : params) {
            // TODO remove when implemented
            if (param[1] != 0) assert(false);
            // Compute the distribution after the last iteration
            std::vector<Rat> expected_distribution = minimum_distance<Int, Rat>(param[0],
                                                                                   param[1],
                                                                                   param[2],
                                                                                   param[3],
                                                                                   param[4],
                                                                                   param[5],
                                                                                   param[6]);
            // Now take the distribution that was returned in the function above
            // and find at which index the sum >= 1. That is the minimum distance
            u64 expected_md = minimum_distance_from_distribution<Rat>(param[4], expected_distribution);
            /*std::cout << "expander " << param[0] << ", "
                      << "multiplier " << param[1] << ", "
                      << "num_iters " << param[2] << ", "
                      << "k " << param[3] << ", "
                      << "n " << param[4] << ", "
                      << "sigma " << param[5] << ", "
                      << "sigma_expander " << param[6]  << ", ";
            std::cout << "Expected minimum distance " << expected_md << std::endl;*/
            std::cout << expected_md << std::endl;
            std::cout << "DONE";
        }
        std::cout << "finished" << std::endl;
    }

    inline void minimumDistanceMain(oc::CLP &cmd) {
        benchmarks();

        u64 k = cmd.getOr("k", 10); // msg length
        u64 n = cmd.getOr("n", 20); // codeword length
        u64 sigma = cmd.getOr("sigma", 2); // window size
        u64 sigma_expander = cmd.getOr("sigmaexpander", 0); // window size
        // expander (0: repeater, 1: block expander)
        u64 expander = cmd.getOr("expander", 0);
        // multiplier (0: block, 1: non recursive convolution)
        // i.e. the enumerator we compute at each iteration
        u64 multiplier = cmd.getOr("multiplier", 0);
        u64 num_iters = cmd.getOr("iters", 1); // number of permute & [multiply] iterations

        std::cout << "k: " << k << std::endl;
        std::cout << "n: " << n << std::endl;
        std::cout << "sigma: " << sigma << std::endl;
        std::cout << "sigma_expander: " << sigma_expander << std::endl;
        std::cout << "expander: " << expander << ", if 0 then repeater, "
                                                 "if 1 then block"
                  << std::endl;
        std::cout << "multiplier: " << multiplier << ", if 0 then block enumerator, "
                                                     "if 1 then non-recursive convolution enumerator"
                  << std::endl;

        std::vector<Rat> distribution = minimum_distance<Int, Rat>(expander, multiplier,
                                                            num_iters, k, n,
                                                            sigma, sigma_expander);
        u64 min_distance_v1 = minimum_distance_from_distribution<Rat>(n, distribution);
        std::cout << "Minimum Distance: " << min_distance_v1 << std::endl;
    }
}

#endif //LIBOTE_MINIMUMDISTANCE_H

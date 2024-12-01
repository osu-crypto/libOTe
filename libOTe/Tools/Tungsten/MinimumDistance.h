#ifndef LIBOTE_MINIMUMDISTANCE_H
#define LIBOTE_MINIMUMDISTANCE_H

#include <chrono>
#include <numeric>
#include <stdexcept>
#include <vector>

#include "BlockEnumerator.h"
#include "ExpandingBlockEnumerator.h"
#include "NonrecConvEnumerator.h"
#include "EnumeratorTools.h"
#include "RepeaterEnumerator.h"

#include <boost/multiprecision/cpp_dec_float.hpp>

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
                                        u64 sigma_expander,
                                        std::vector<std::vector<I>> &pascal_triangle) { // only for the expanding block
        assert(e == n / k);
        for (size_t h = 0; h <= n; h++) {
            // note that for repeater, we do NOT need this loop, but used now for modularity
            // NOTE we exclude w=0 from the input x as it would always result in all zeros, so E_{w=0,h=0}=1
            // but then minimum distance would always be 0 as the distribution would be 1 in the first entry! 
            // in the following iterations we care about w=0 as non-zero input could result in h=0
            for (size_t w = 1; w <= k; w++) {
                if (expander == 0) {
                    // repeater
                    distribution[h] += repeater_enum<I>(w, h, k, e, pascal_triangle);
                    assert(distribution[0] == 0);
                } else if (expander == 1) {
                    assert(sigma_expander > 0);
                    assert(sigma_expander <= k);
                    assert(k % sigma_expander == 0);
                    // block expander (identity + block)
                    distribution[h] += expanding_block_enum<I, R>(w, h, k, n, sigma_expander, pascal_triangle);
                }
            }
        }
    }

    template<typename I, typename R>
    void distribution_thread_function_v2(u64 start_w, u64 end_w, u64 n, u64 multiplier, u64 sigma,
        u64 approximate,
        const std::vector<R>& count_fraction, std::vector<R>& thread_partial_counts,
        const std::vector<R> &block_enum_part,
        std::vector<std::vector<I>> pascal_triangle) {
        assert(multiplier == 0); // TODO only block enumerator supported now
        // (non-recursive convolution not yet supported)
       
        std::fill(thread_partial_counts.begin(), thread_partial_counts.end(), R(0));

        // Do not use the block_enum function, but unroll the function to avoid recomputing stuff
        for (u64 w = start_w; w < end_w; ++w) {
            // precompute as much from block_enum as you can as soon as possible (a lot of it is independent of h)
            std::vector<R> block_enum_part2(block_enum_part.size());
            for (size_t q = 0; q < block_enum_part.size(); q++) {
                block_enum_part2[q] = block_enum_part[q] * labeledBallBinCap<I>(w, q, sigma, pascal_triangle);
            }

            // Handle all but last h
            u64 offset = 0;
            for (u64 h = 0; h < (thread_partial_counts.size() - 1); ++h) {
                R enumerator = 0;
                for (size_t q = 0; q < block_enum_part2.size(); q++) {
                    enumerator += block_enum_part2[q] * choose_pascal<I>(sigma * q, offset, pascal_triangle);
                }
                // Safely update the shared thread_partial_counts[h] (one element per h)
                // Note no need to lock it as each thread operates on different copy of thread_partial_counts
                thread_partial_counts[h] += (count_fraction[w] * enumerator);
                offset += approximate;
            }
            // Handle last h separately (last h is the last point in the distribution and is not h * approximate but n
            R enumerator = 0;
            for (size_t q = 0; q < block_enum_part2.size(); q++) {
                enumerator += block_enum_part2[q] * choose_pascal<I>(sigma * q, n, pascal_triangle);
            }
            thread_partial_counts[thread_partial_counts.size() - 1] += (count_fraction[w] * enumerator);
        }
    }


    template<typename I, typename R>
    void distribution_thread_function_v1(u64 start_h, u64 end_h, u64 n, u64 multiplier, u64 sigma,
            const std::vector<R>& count_fraction, std::vector<R>& new_distribution,
            std::vector<std::vector<I>> pascal_triangle) {
        for (u64 h = start_h; h < end_h; ++h) {
            for (u64 w = 0; w <= n; ++w) {
                R enumerator = 0;
                if (multiplier == 0) {
                    // Use the thread-specific copy of pascal_triangle
                    enumerator = block_enum<I, R>(w, h, n, n, sigma, pascal_triangle);
                }
                else if (multiplier == 1) {
                    // TODO: non-recursive convolution
                    assert(false);
                }

                // Safely update the shared new_distribution[h] (one element per h)
                // Note no need to lock it as each thread operates on different unique index h in new_distribution
                new_distribution[h] += (count_fraction[w] * enumerator);
            }
        }
    }


    template<typename I, typename R>
    void compute_next_distribution(const std::vector<R> &old_distribution,
                                   std::vector<R> &new_distribution,
                                   u64 multiplier,
                                   u64 n,
                                   u64 sigma,
                                   u64 approximate,
                                   std::vector<std::vector<I>>& pascal_triangle) {
        assert(old_distribution.size() == n + 1);
        assert(new_distribution.size() == n + 1);

        std::fill(new_distribution.begin(), new_distribution.end(), R(0));

        // Precompute old_distribution[w] / R(n_choose_w) so that we do only n instead of n^2 times
        std::cout << "Started precomputing the fraction of counts necessary to compute the next distribution..." << std::endl;
        auto start = std::chrono::steady_clock::now();
        std::vector<R> count_fraction(n + 1);
        for (size_t w = 0; w <= n; w++) {
            // NOTE this n_choose_w value is not recomputed each time as the function caches the values in the Pascal triangle
            count_fraction[w] = old_distribution[w] / R(choose_pascal<I>(n, w, pascal_triangle));
        }
        auto end = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        std::cout << "Finished precomputing the fraction of counts necessary to compute the next distribution:" <<
            elapsed.count() << " ms" << std::endl;

        // 16 as my computer has 16 cores
        // 50 picked heuristically
        u64 num_cores = 16;
        u64 heuristic = ceil(new_distribution.size() / 50.);
        u64 num_threads = (heuristic < num_cores) ? heuristic : num_cores;
        // Calculate chunk size for each thread (in terms of w)
        u64 chunk_size = new_distribution.size() / num_threads;
        // Calculate the number of counts to compute by each thread (in terms of h) - 
        // i.e. the number of points on the distribution that is exactly computed
        u64 num_real = (n % approximate == 0) ? (n / approximate + 1) : (n / approximate + 2);
        std::vector<std::thread> threads;
        std::vector<std::vector<R>> thread_partial_counts(num_threads, std::vector<R>(num_real));

        // precompute as much from block_enum as you can as soon as possible (a lot of it is independent of w, h)
        std::cout << "Started precomputing parts of block enumerator before multithreading..." << std::endl;
        start = std::chrono::steady_clock::now();
        size_t k_over_sigma = n / sigma; // note k==n at this step
        std::vector<R> block_enum_part;
        block_enum_part.reserve(k_over_sigma + 1);
        // Precompute the base scaling factor
        I base_factor = I(1) << sigma;
        I current_factor = 1; // Start with 1 (2^0)
        for (u64 q = 0; q <= k_over_sigma; q++) {
            block_enum_part.emplace_back(1, current_factor);
            block_enum_part[q] *= choose_pascal<I>(k_over_sigma, q, pascal_triangle);
            // Incrementally compute the next power of 2
            current_factor *= base_factor;
        }
        end = std::chrono::steady_clock::now();
        elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        std::cout << "Finished precomputing parts of block enumerator before multithreading:" << 
            elapsed.count() << " ms" << std::endl;
        // ensure sigma * q choose h is precomputed in pascal_triangle for all q, h before invoking each thread
        std::cout << "Started precomputing pascal's triangle..." << std::endl;
        start = std::chrono::steady_clock::now();
        for (u64 q = 0; q <= k_over_sigma; q++) {
            u64 sigma_q = sigma * q;
            for (u64 h = 0; h < new_distribution.size(); h++) {
                choose_pascal<I>(sigma_q, h, pascal_triangle);
            }
            for (u64 i = 0; i <= q; i++) {
                choose_pascal<I>(q, i, pascal_triangle);
            }
        }
        end = std::chrono::steady_clock::now();
        elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        std::cout << "Finished precomputing pascal's triangle:" << 
            elapsed.count() << " ms" << std::endl;

        std::cout << "Started multithreading..." << std::endl;
        start = std::chrono::steady_clock::now();
        for (int t = 0; t < num_threads; ++t) {
            u64 start_w = t * chunk_size;
            u64 end_w = (t == num_threads - 1) ? new_distribution.size() : (start_w + chunk_size);

            // Start each thread with its range of `w` and thread-specific pascal_triangle
            threads.emplace_back(distribution_thread_function_v2<I, R>, start_w, end_w, n, multiplier, sigma, approximate,
                std::cref(count_fraction), std::ref(thread_partial_counts[t]), std::cref(block_enum_part), pascal_triangle);
        }

        // Join threads to ensure all complete
        for (auto& t : threads) {
            t.join();
        }
        end = std::chrono::steady_clock::now();
        elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        std::cout << "Finished multithreading:" << 
            elapsed.count() << " ms" << std::endl;

        std::cout << "Started combining results from each thread into final distribution..." << std::endl;
        start = std::chrono::steady_clock::now();
        // Add thread_partial_counts into new_distribution
       for (u64 t = 0; t < num_threads; ++t) {
            u64 offset = 0;
            for (u64 i = 0; i < (num_real - 1); ++i) {
                new_distribution[offset] += thread_partial_counts[t][i];
                offset += approximate;
            }
            // last one may be at a different offset (we ensure the first and last points of a distribution always computed)
            new_distribution[new_distribution.size() - 1] += thread_partial_counts[t][num_real - 1];
        }
        end = std::chrono::steady_clock::now();
        elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        std::cout << "Finished combining results from each thread into final distribution:" << 
            elapsed.count() << " ms" << std::endl;
        
        // Now that each 'approximate'th point of new_distribution was computed,
        // Interpolate remaining points (if approximate > 1)
        // linear spline
        if (approximate > 1) {
            std::cout << "Started interpolating remaining points in the  final distribution..." << std::endl;
            start = std::chrono::steady_clock::now();
            // handle all but last pair
            u64 offset = 0;
            for (u64 i = 0; i < num_real - 2; i++) {
                R initial = new_distribution[offset];
                R step = (new_distribution[offset + approximate] - initial) / R(approximate);
                for (u64 j = 1; j < approximate; ++j) {
                    initial += step;
                    new_distribution[offset + j] = initial;
                }
                offset += approximate;
            }
            // handle last pair separately
            R initial = new_distribution[offset];
            u64 step_size = new_distribution.size() - 1 - offset;
            R step = (new_distribution[new_distribution.size() - 1] - initial) / R(step_size);
            for (u64 j = 1; j < step_size; ++j) {
                initial += step;
                new_distribution[offset + j] = initial;
            }
            end = std::chrono::steady_clock::now();
            elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
            std::cout << "Finished interpolating remaining points in the  final distribution:" << 
                elapsed.count() << " ms" << std::endl;
        }

        /*for (size_t h = 0; h <= n; h++) {
            for (size_t w = 0; w <= n; w++) {
                R enumerator = 0;
                if (multiplier == 0) {
                    // block enumerator
                    enumerator = block_enum<I, R>(w, h, n, n, sigma, pascal_triangle);
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
        }*/
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

    // function to help with estimating a distribution f(2n) from f(n)
    template <typename T>
    void expand_and_interpolate(std::vector<T>& distribution) {
        // Check that the input vector has at least two elements for interpolation
        if (distribution.size() < 2) {
            throw std::invalid_argument("Input vector must have at least two elements.");
        }

        size_t n = distribution.size();
        distribution.resize(2 * n - 1); // Resize the vector to accommodate 2n elements

        // Shift the original elements to their new positions (end to start to avoid overwriting)
        for (size_t i = n; i > 0; --i) {
            distribution[2 * (i - 1)] = distribution[i - 1];
        }

        // Perform linear interpolation for the even indices
        for (size_t i = 0; i < n - 1; ++i) {
            distribution[2 * i + 1] = (distribution[2 * i] + distribution[2 * i + 2]) / 2;
        }
    }

    void print_distribution(std::vector<Rat> &distribution) {
        std::cout << "Printing distribution: " << std::endl;
        for (const auto& d : distribution) {
            std::cout << boost::multiprecision::cpp_dec_float_100(d) << std::endl;
        }
        std::cout << "Finished printing distribution. " << std::endl;
    }

    template<typename I, typename R>
    std::vector<R> minimum_distance(u64 expander, u64 multiplier, u64 num_iters,
                                       u64 k, u64 n, u64 sigma, u64 sigma_expander,
                                       u64 approximate) {
        // TODO Assumes G's sigma is the same for all iterations (except expanding step)
        // std::cout << "Computing minimum distance..." << std::endl;

        std::vector<std::vector<I>> pascal_triangle;

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
        compute_expanding_distribution<I, R>(distributions[0], expander, k, n, e, sigma_expander, pascal_triangle);
        // print_distribution(distributions[0]);

        // Compute distributions for iterations
        for (size_t iter = 0; iter < num_iters; iter++) {
            // Compute distributions[(iter + 1) % 2]
            compute_next_distribution<I, R>(distributions[iter % 2],
                                            distributions[(iter + 1) % 2],
                                            multiplier,
                                            n, sigma,
                                            approximate,
                                            pascal_triangle);
            // expand_and_interpolate(distributions[(iter + 1) % 2]);
            print_distribution(distributions[(iter + 1) % 2]);
        }

        // Now return the distribution associated with the last iteration

        // Check the sum of the final distribution is equal to the sum of the initial distribution
        R final_distribution_sum = std::reduce(distributions[num_iters % 2].begin(),
                                               distributions[num_iters % 2].end()); // distribution_sum<R>(distributions[num_iters % 2]);
        // Sum initial distribution
        R initial_distribution_sum = 0;
        for (size_t w = 1; w <= k; w++) {
            initial_distribution_sum += R(choose_pascal<I>(k, w, pascal_triangle));
        }
        std::cout << "Initial distribution sum: " << initial_distribution_sum << std::endl;
        std::cout << "Final distribution sum: " << final_distribution_sum << std::endl;
        assert(final_distribution_sum == initial_distribution_sum);
        if (approximate == 1 && final_distribution_sum != initial_distribution_sum) throw RTE_LOC;

        return distributions[num_iters % 2];
    }

    void benchmarks() {

        // expander (0: repeater, 1: block expander), 
        // multiplier (0: block, 1: non recursive convolution), 
        // num_iters, k, n, sigma, sigma_expander (0 if repeater),
        // approximate - 1 if exact ie compute exactly all elements in the distribution, 2 means compute every other
        //               element in the distribution and approximate the remaining, 4 means compute every 4th element
        //               and approximate the rest

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

            {0, 0, 2, 512, 1024, 64, 0, 1},
            //{0, 0, 1, 1024, 2048, 64, 0, 1},
            //{0, 0, 2, 4096, 8192, 64, 0, 1},
            //{0, 0, 2, 4096, 8192, 128, 0, 1},
            //{0, 0, 2, 4096, 8192, 256, 0, 1},
            //{0, 0, 2, 4096, 8192, 512, 0, 1},
            //{0, 0, 2, 4096, 8192, 1024, 0, 1},


            //{0, 0, 2, 8192, 16384, 16384, 0},
            //{0, 0, 2, 16384, 32768, 32768, 0},
            //{0, 0, 2, 32768, 65536, 65536, 0},
            //{0, 0, 2, 2048, 4096, 128, 0},
            //{0, 0, 2, 2048, 4096, 256, 0},
            //{0, 0, 2, 2048, 4096, 512, 0},
            //{0, 0, 2, 2048, 4096, 1024, 0},
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
                                                                                   param[6],
                                                                                   param[7]);
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
        u64 approximate = cmd.getOr("approx", 1); // compute exactly every approximate'th point in the distribution,
                                                  // approximate the rest

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
        std::cout << "approximate: " << approximate << ", if 1 then compute all points in the distribution exactly, "
            "else compute exactly every approximate'th element"
            << std::endl;

        std::vector<Rat> distribution = minimum_distance<Int, Rat>(expander, multiplier,
                                                            num_iters, k, n,
                                                            sigma, sigma_expander, approximate);
        u64 min_distance_v1 = minimum_distance_from_distribution<Rat>(n, distribution);
        std::cout << "Minimum Distance: " << min_distance_v1 << std::endl;
    }
}

#endif //LIBOTE_MINIMUMDISTANCE_H

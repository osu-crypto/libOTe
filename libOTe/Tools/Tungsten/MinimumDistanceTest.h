#ifndef LIBOTE_MINIMUMDISTANCETEST_H
#define LIBOTE_MINIMUMDISTANCETEST_H

#include <bitset>
#include <cassert>

#include "EnumeratorTools.h"
#include "MinimumDistance.h"

#define BITSET_SIZE 128

namespace osuCrypto {

    std::vector<std::bitset<BITSET_SIZE>> generate_all_gis(u64 k, u64 n, u64 sigma) {
        u64 num_gis_in_g = k / sigma;
        u64 e = n / k;
        u64 num_elements_in_one_gi = sigma * e * sigma;
        // all G_is but in the same G
        const u64 num_elements_in_all_gis = num_gis_in_g * num_elements_in_one_gi;
        // std::cout << "Bitset size: " << num_elements_in_all_gis << std::endl;
        assert(BITSET_SIZE >= num_elements_in_all_gis);
        // 2^{k/sigma * sigma * e * sigma}
        u64 num_possibilities = 1 << num_elements_in_all_gis;
        std::vector<std::bitset<BITSET_SIZE>> all_possibilities (num_possibilities);
        for (size_t idx = 0; idx < num_possibilities; idx++) {
            all_possibilities[idx] = idx;
            // std::cout << all_possibilities[idx] << std::endl;
        }
        return all_possibilities;
    }

    std::vector<std::bitset<BITSET_SIZE>> generate_all_x_of_weight_w(u64 k, u64 w) {
        assert(BITSET_SIZE >= k);
        std::vector<std::bitset<BITSET_SIZE>> all_xs;
        u64 num_possibilities = 1 << k; // 2^{k}
        for (size_t idx = 0; idx < num_possibilities; idx++) {
            std::bitset<BITSET_SIZE> possibility = idx;
            if (possibility.count() == w) {
                all_xs.push_back(possibility);
                // std::cout << possibility << std::endl;
            }
        }
        return all_xs;
    }

    std::vector<std::bitset<BITSET_SIZE>> generate_all_x(u64 k) {
        assert(BITSET_SIZE >= k);
        u64 num_possibilities = 1 << k; // 2^{k}
        std::vector<std::bitset<BITSET_SIZE>> all_xs (num_possibilities);
        for (size_t idx = 0; idx < num_possibilities; idx++) {
            all_xs[idx] = idx;
        }
        return all_xs;
    }

    std::bitset<BITSET_SIZE> multiply_x_g(const std::bitset<BITSET_SIZE> &x,
                                          const std::bitset<BITSET_SIZE> &g,
                                          u64 sigma, u64 k, u64 n) {
        assert(BITSET_SIZE >= n);
        std::bitset<BITSET_SIZE> res;
        size_t e = n / k;
        assert(k % sigma == 0 && n % sigma == 0);
        size_t num_gis = k / sigma; // number of G_i's in a single G
        for (size_t gi = 0; gi < num_gis; gi++) {
            size_t x_offset = gi * sigma;
            size_t res_offset = gi * e * sigma;
            size_t g_offset = gi * sigma * e * sigma;
            for (size_t si = 0; si < (e * sigma); si++) {
                for (size_t sj = 0; sj < sigma; sj++) {
                    res[res_offset + si]  = res[res_offset + si] ^
                                            (x[x_offset + sj] && g[g_offset + sj * e * sigma + si]);
                }
            }
        }
        return res;
    }

    template<typename R>
    u64 minimum_distance_v1_true(u64 expander,
                                 u64 multiplier,
                                 u64 num_iters,
                                 u64 k, u64 n, u64 sigma) {
        size_t e = n/k;
        // Generate all possible G_i's (the blocks in matrix G)
        // TODO Assume for now a single G for all iterations and only a repeater for the expansion
        std::vector<std::bitset<BITSET_SIZE>> gis = generate_all_gis(n, n, sigma);
        std::cout << "All " << gis.size() << " Gi's generated..." << std::endl;
        // Generate all possible input x's
        std::vector<std::bitset<BITSET_SIZE>> xs = generate_all_x(k);
        std::cout << "All " << xs.size() << " x's generated..." << std::endl;
        std::vector<Rat> count_weight_h_outputs (n + 1);
        // iterate over all G's
        for (const auto &g: gis) {
            // for each G, iterate over all x's
            for (const auto &x: xs) {
                // expander
                std::bitset<BITSET_SIZE> expanded_x;
                if (expander == 0) {
                    // repeater
                    u64 offset = 0;
                    for (size_t i = 0; i < k; i++) {
                        for (size_t j = 0; j < e; j++) {
                            expanded_x[offset++] = x[i];
                        }
                    }
                } else if (expander == 1) {
                    // expanding block
                    // TODO
                    assert(false);
                }
                // multiply x and g at each iteration
                // TODO different G at each iteration?
                std::bitset<BITSET_SIZE> xg = multiply_x_g(expanded_x, g, sigma, n, n);
                // if xg has weight h, add 1 to the enumerator
                count_weight_h_outputs[xg.count()]++;
            }
        }
        // Divide each count by the number of G's
        for (auto& count : count_weight_h_outputs) {
            count /= gis.size();
        }
        // Compute the minimum distance
        // Find at which index the sum >= 1. That is the minimum distance
        R sum = 0;
        u64 minimum_distance = 0;
        for (size_t h = 0; h < n; h++) {
            sum += count_weight_h_outputs[h];
            if (sum >= 1.) {
                return minimum_distance;
            }
            minimum_distance++;
        }
        return n;
    }

    void minimum_distance_tests() {
        // expander, multiplier, num_iters, k, n, sigma
        std::vector<std::vector<u64>> params = {
                {0, 0, 2, 100, 200, 20}, // repeater and block enumerator
                // TODO add test with >1 iteration {0, 0, 1, 6, 12, 2},
                //  TODO add more tests
                //{4,12,2},
                //{6,6,3}
        };
        for (auto & param : params) {
            u64 expected_md = minimum_distance_v1<Int, Rat>(param[0],
                                                            param[1],
                                                            param[2],
                                                            param[3],
                                                            param[4],
                                                            param[5]);
            /*u64 true_md = minimum_distance_v1_true<Rat>(param[0],
                                                        param[1],
                                                        param[2],
                                                        param[3],
                                                        param[4],
                                                        param[5]);*/
            std::cout << "Expected minimum distance: " << expected_md << std::endl;
            /*std::cout << "True minimum distance: " << true_md << std::endl;

            assert(expected_md == true_md);
            if (expected_md != true_md) {
                throw RTE_LOC;
            }*/
        }
    }

    inline void minimumDistanceTestMain(oc::CLP& cmd) {
        minimum_distance_tests();
    }
}

#endif //LIBOTE_MINIMUMDISTANCETEST_H

#ifndef LIBOTE_BLOCKENUMERATORTEST_H
#define LIBOTE_BLOCKENUMERATORTEST_H

#include <bitset>
#include <cassert>

#include "EnumeratorTools.h"
#include "BlockEnumerator.h"

#define BITSET_SIZE 64

// TODO test for expanding block

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
                            (x[x_offset + sj] & g[g_offset + sj * e * sigma + si]);
                }
            }
        }
        return res;
    }

    template<typename R>
    R block_enum_true(u64 w, u64 h, u64 k, u64 n, u64 sigma) {
        // Generate all possible G_i's (the blocks in matrix G)
        std::vector<std::bitset<BITSET_SIZE>> gis = generate_all_gis(k, n, sigma);
        std::cout << "All " << gis.size() << " Gi's generated..." << std::endl;
        // Generate all possible weight w input x's
        std::vector<std::bitset<BITSET_SIZE>> xs = generate_all_x_of_weight_w(k, w);
        std::cout << "All " << xs.size() << " x's of weight w generated..." << std::endl;
        R enumerator = 0;
        // iterate over all G's
        for (const auto &g: gis) {
            // for each G, iterate over all weight w inputs
            for (const auto &x: xs) {
                // multiply x and g
                std::bitset<BITSET_SIZE> xg = multiply_x_g(x, g, sigma, k, n);
                // if xg has weight h, add 1 to the enumerator
                if (xg.count() == h) {
                    //std::cout << "X: " << x << std::endl;
                    //std::cout << "G: " << g << std::endl;
                    //std::cout << "XG: " << xg << std::endl;
                    enumerator++;
                }
            }
        }
        // Divide the enumerator by the number of G's
        enumerator /= gis.size();
        return enumerator;
    }

    void block_enumerator_tests() {
        // w, h, k, n, sigma
        std::vector<std::vector<u64>> params = {
                {2,2,4,8,2},
                {2,3,4,12,2},
                {3,5,6,6,3}
        };
        for (auto & param : params) {
            Rat expected_enumerator = block_enum<Int, Rat>(param[0],
                                                           param[1],
                                                           param[2],
                                                           param[3],
                                                           param[4]);
            Rat true_enumerator = block_enum_true<Rat>(param[0],
                                                       param[1],
                                                       param[2],
                                                       param[3],
                                                       param[4]);
            if (expected_enumerator != true_enumerator) {
                throw RTE_LOC;
            }
        }
    }

    inline void blockEnumTestMain(oc::CLP& cmd) {
        block_enumerator_tests();

        std::cout << "Computing true and expected enumerator for the block construction..." << std::endl;

        u64 w = cmd.getOr("w", 5); // input weight
        u64 h = cmd.getOr("h", 12); // output weight
        u64 k = cmd.getOr("k", 10); // msg length
        u64 n = cmd.getOr("n", 20); // codeword length
        u64 sigma = cmd.getOr("sigma", 2); // window size

        std::cout << "w: " << w << std::endl;
        std::cout << "h: " << h << std::endl;
        std::cout << "k: " << k << std::endl;
        std::cout << "k: " << n << std::endl;
        std::cout << "sigma: " << sigma << std::endl;

        Rat expected_enumerator = block_enum<Int, Rat>(w, h, k, n, sigma);
        std::cout << "Expected Block Enumerator: " << expected_enumerator << std::endl;

        Rat true_enumerator = block_enum_true<Rat>(w, h, k, n, sigma);
        std::cout << "True Block Enumerator (test): " << true_enumerator << std::endl;

        assert(expected_enumerator == true_enumerator);

    }
}

#endif //LIBOTE_BLOCKENUMERATORTEST_H

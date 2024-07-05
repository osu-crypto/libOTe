#ifndef LIBOTE_BLOCKENUMERATORTEST_H
#define LIBOTE_BLOCKENUMERATORTEST_H

#include <bitset>
#include <cassert>

#include "EnumeratorTools.h"
#include "BlockEnumerator.h"

#define BITSET_SIZE 64


namespace osuCrypto {

    std::vector<std::bitset<BITSET_SIZE>> generate_all_gis(u64 n, u64 sigma) {
        u64 num_gis_in_g = n / sigma;
        u64 num_elements_in_one_gi = sigma * sigma;
        // all G_is but in the same G
        const u64 num_elements_in_all_gis = num_gis_in_g * num_elements_in_one_gi;
        // std::cout << "Bitset size: " << num_elements_in_all_gis << std::endl;
        assert(BITSET_SIZE >= num_elements_in_all_gis);
        // 2^{n/sigma * sigma^2}
        u64 num_possibilities = 1 << num_elements_in_all_gis;
        std::vector<std::bitset<BITSET_SIZE>> all_possibilities (num_possibilities);
        for (size_t idx = 0; idx < num_possibilities; idx++) {
            all_possibilities[idx] = idx;
            // std::cout << all_possibilities[idx] << std::endl;
        }
        return all_possibilities;
    }

    std::vector<std::bitset<BITSET_SIZE>> generate_all_x_of_weight_w(u64 n, u64 w) {
        assert(BITSET_SIZE >= n);
        std::vector<std::bitset<BITSET_SIZE>> all_xs;
        u64 num_possibilities = 1 << n; // 2^{n}
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
                                          u64 sigma, u64 n) {
        std::bitset<BITSET_SIZE> res;
        assert(n % sigma == 0);
        size_t num_gis = n / sigma; // number of G_i's in a single G
        for (size_t gi = 0; gi < num_gis; gi++) {
            size_t x_and_res_offset = gi * sigma;
            size_t g_offset = gi * sigma * sigma;
            for (size_t si = 0; si < sigma; si++) {
                for (size_t sj = 0; sj < sigma; sj++) {
                    // TODO supports only square blocks
                    res[x_and_res_offset + si]  = res[x_and_res_offset + si] ^
                            (x[x_and_res_offset + sj] & g[g_offset + sj * sigma + si]);
                }
            }
        }
        return res;
    }

    template<typename R>
    R block_enum_test(u64 w, u64 h, u64 n, u64 sigma) {
        // Generate all possible G_i's (the blocks in matrix G)
        std::vector<std::bitset<BITSET_SIZE>> gis = generate_all_gis(n, sigma);
        std::cout << "All " << gis.size() << " Gi's generated..." << std::endl;
        // Generate all possible weight w input x's
        std::vector<std::bitset<BITSET_SIZE>> xs = generate_all_x_of_weight_w(n, w);
        std::cout << "All " << xs.size() << " x's of weight w generated..." << std::endl;
        R enumerator = 0;
        // iterate over all G's
        for (const auto &g: gis) {
            // for each G, iterate over all weight w inputs
            for (const auto &x: xs) {
                // multiply x and g
                std::bitset<BITSET_SIZE> xg = multiply_x_g(x, g, sigma, n);
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


    inline void blockEnumTestMain(oc::CLP& cmd) {
        std::cout << "Computing true and expected enumerator for the block construction..." << std::endl;

        u64 w = cmd.getOr("w", 5); // input weight
        u64 h = cmd.getOr("h", 6); // output weight
        u64 n = cmd.getOr("n", 10); // msg/codeword length
        u64 sigma = cmd.getOr("sigma", 2); // window size

        std::cout << "w: " << w << std::endl;
        std::cout << "h: " << h << std::endl;
        std::cout << "n: " << n << std::endl;
        std::cout << "sigma: " << sigma << std::endl;

        Rat expected_enumerator = block_enum<Int, Rat>(w, h, n, sigma);
        std::cout << "Expected Block Enumerator: " << expected_enumerator << std::endl;

        Rat true_enumerator = block_enum_test<Rat>(w, h, n, sigma);
        std::cout << "True Block Enumerator (test): " << true_enumerator << std::endl;

    }
}

#endif //LIBOTE_BLOCKENUMERATORTEST_H

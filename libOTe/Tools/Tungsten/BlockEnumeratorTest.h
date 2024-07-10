#ifndef LIBOTE_BLOCKENUMERATORTEST_H
#define LIBOTE_BLOCKENUMERATORTEST_H

#include <bitset>
#include <cassert>

#include "EnumeratorTools.h"
#include "BlockEnumerator.h"
#include "MinimumDistanceTest.h"

namespace osuCrypto {

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
            assert(expected_enumerator == true_enumerator);
            if (expected_enumerator != true_enumerator) {
                throw RTE_LOC;
            }
        }
    }

    inline void blockEnumTestMain(oc::CLP& cmd) {
        block_enumerator_tests();

        std::cout << "Computing true and expected enumerator for the block construction..." << std::endl;

        u64 w = cmd.getOr("w", 3); // input weight
        u64 h = cmd.getOr("h", 10); // output weight
        u64 k = cmd.getOr("k", 6); // msg length
        u64 n = cmd.getOr("n", 12); // codeword length
        u64 sigma = cmd.getOr("sigma", 2); // window size

        std::cout << "w: " << w << std::endl;
        std::cout << "h: " << h << std::endl;
        std::cout << "k: " << k << std::endl;
        std::cout << "n: " << n << std::endl;
        std::cout << "sigma: " << sigma << std::endl;

        Rat expected_enumerator = block_enum<Int, Rat>(w, h, k, n, sigma);
        std::cout << "Expected Block Enumerator: " << expected_enumerator << std::endl;

        Rat true_enumerator = block_enum_true<Rat>(w, h, k, n, sigma);
        std::cout << "True Block Enumerator (test): " << true_enumerator << std::endl;

        assert(expected_enumerator == true_enumerator);

    }
}

#endif //LIBOTE_BLOCKENUMERATORTEST_H

#ifndef LIBOTE_BLOCKENUMERATORTEST_H
#define LIBOTE_BLOCKENUMERATORTEST_H

#include <bitset>

#include "EnumeratorTools.h"
#include "BlockEnumerator.h"


namespace osuCrypto {

    std::vector<std::bitset<64>> generate_all_gi(u64 n, u64 sigma) {
        u64 num_gis_in_g = n / sigma;
        u64 num_elements_in_one_gi = sigma * sigma;
        u64 num_elements_in_all_gis = num_gis_in_g * num_elements_in_one_gi;
        // 2^{n/sigma * sigma^2}
        u64 num_possibilities = 1 << num_elements_in_all_gis;
        std::vector<std::bitset<64>> all_possibilities (num_possibilities);
        for (size_t idx = 0; idx < num_possibilities; idx++) {
            all_possibilities[idx] = idx;
            std::cout << all_possibilities[idx] << std::endl;
        }
        return all_possibilities;
    }

    template<typename I>
    I block_enum_test(u64 w, u64 h, u64 n, u64 sigma) {
        std::vector<std::bitset<64>> gis = generate_all_gi(n, sigma);
        return 0;

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

        Int true_enumerator = block_enum_test<Int>(w, h, n, sigma);
        std::cout << "True Block Enumerator (test): " << true_enumerator << std::endl;

    }
}

#endif //LIBOTE_BLOCKENUMERATORTEST_H

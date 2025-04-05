#ifndef LIBOTE_EXPANDINGBLOCKENUMERATOR_H
#define LIBOTE_EXPANDINGBLOCKENUMERATOR_H

#include "BlockEnumerator.h"
#include "EnumeratorTools.h"

#include <iostream>

namespace osuCrypto {

    // G: kxk identity followed by a k x [(e-1)k] block
    // outputs the input x concatenated with the {x multiplied by the k x [(e-1)k] block}
    // NOTE deprecated - we just use block_enumerator
    template<typename I, typename R>
    R expanding_block_enum(u64 w, u64 h, u64 k, u64 n, u64 sigma, const ChooseCache<I>& pascal_triangle) {
        auto nn = n - k;
        if (nn % sigma)
            throw RTE_LOC;
        if (w > k)
            throw RTE_LOC;;

        if (h < w || h > (nn + w)) {
            return 0;
        }
        return block_enum<I, R>(w, h - w, k, nn, sigma, pascal_triangle);
    }

    inline void expanding_block_enum(oc::CLP& cmd) {
        std::cout << "Computing enumerator for the expanding block..." << std::endl;

        u64 w = cmd.getOr("w", 5); // input weight
        u64 h = cmd.getOr("h", 15); // output weight
        u64 k = cmd.getOr("k", 10); // msg length (note NOT codeword length, which is k * k)
        u64 n = cmd.getOr("n", 20);
        u64 sigma = cmd.getOr("sigma", 2); // window size

        std::cout << "w: " << w << std::endl;
        std::cout << "h: " << h << std::endl;
        std::cout << "k: " << k << std::endl;
        std::cout << "n: " << n << std::endl;
        std::cout << "sigma: " << sigma << std::endl;

        ChooseCache<Int> pascal_triangle;
        Rat expanding_block_enumerator = expanding_block_enum<Int, Rat>(w, h, k, n, sigma, pascal_triangle);
        std::cout << "Expanding Block Enumerator: " << expanding_block_enumerator << std::endl;
    }

    inline void expandingBlockEnumMain(oc::CLP& cmd) {
        // if (cmd.isSet("enum")) {
        expanding_block_enum(cmd);
        // }
    }
}

#endif //LIBOTE_EXPANDINGBLOCKENUMERATOR_H

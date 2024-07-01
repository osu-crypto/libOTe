#ifndef LIBOTE_EXPANDINGBLOCKENUMERATOR_H
#define LIBOTE_EXPANDINGBLOCKENUMERATOR_H

#include "BlockEnumerator.h"
#include "EnumeratorTools.h"

#include <iostream>

namespace osuCrypto {

    template<typename I, typename R>
    R expanding_block_enum(u64 w, u64 h, u64 n, u64 sigma) {
        u64 k = 2; // fixed

        assert(w <= n);
        assert(h <= k * n);
        assert(sigma <= k * n);

        if (h < w) {
            return 0;
        }
        return block_enum<I, R>(w, h - w, n, sigma);
    }

    inline void expanding_block_enum(oc::CLP& cmd) {
        std::cout << "Computing enumerator for the expanding block..." << std::endl;

        u64 w = cmd.getOr("w", 5); // input weight
        u64 h = cmd.getOr("h", 15); // output weight
        u64 n = cmd.getOr("n", 10); // msg length (note NOT codeword length, which is k * n)
        // Expansion factor is fixed
        // u64 k = cmd.getOr("k", 3); // # of repetitions

        std::cout << "w: " << w << std::endl;
        std::cout << "h: " << h << std::endl;
        std::cout << "n: " << n << std::endl;

        Int expanding_block_enumerator = expanding_block_enum<Int, Rat>(w, h, n);
        std::cout << "Expanding Block Enumerator: " << expanding_block_enumerator << std::endl;
    }

    inline void expandingBlockEnumMain(oc::CLP& cmd) {
        // if (cmd.isSet("enum")) {
        expanding_block_enum(cmd);
        // }
    }
}

#endif //LIBOTE_EXPANDINGBLOCKENUMERATOR_H

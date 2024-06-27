#ifndef LIBOTE_BLOCKENUMERATOR_H
#define LIBOTE_BLOCKENUMERATOR_H

#include "EnumeratorTools.h"

#include <iostream>


namespace osuCrypto {

    template<typename I, typename R>
    R block_enum(u64 w, u64 h, u64 n, u64 sigma) {
        R enumerator = 0;
        size_t n_over_sigma = n / sigma;
        for (size_t q = 0; q <= n_over_sigma; q++) {
            // Part 1: 2^{-\sigma q}
            R scale = 1.0 / (1 << (sigma * q));
            std::cerr << "scale " << scale << std::endl;

            // Part 2: E_{w,q}
            I E_wq = ballBinCap<I>(w - q, q, sigma - 1);
            std::cerr << "E_wq " << E_wq << std::endl;

            // Part 3: E_{q,h} = sigma * q choose h
            I E_qh = choose_<I>(sigma * q, h);
            std::cerr << "E_qh " << E_qh << std::endl;

            // Putting it all together
            enumerator += scale * E_wq * E_qh;
            std::cerr << "Enumerator " << enumerator << std::endl;
        }
        return enumerator;
    }

    inline void block_enum(oc::CLP& cmd) {
        std::cout << "Computing enumerator for the block construction..." << std::endl;

        u64 w = cmd.getOr("w", 5); // input weight
        u64 h = cmd.getOr("h", 5); // output weight
        u64 n = cmd.getOr("n", 10); // msg/codeword length
        u64 sigma = cmd.getOr("sigma", 2); // window size

        std::cout << "w: " << w << std::endl;
        std::cout << "h: " << h << std::endl;
        std::cout << "n: " << n << std::endl;
        std::cout << "sigma: " << sigma << std::endl;

        assert(w <= n && h <= n && sigma <= n);

        Rat block_enumerator = block_enum<Int, Rat>(w, h, n, sigma);
        std::cout << "Block Enumerator: " << block_enumerator << std::endl;

#ifdef MPZ_ENABLE
        MPZ block_enumerator = block_enum<MPZ>(w, h, n, sigma);
        std::cout << "Block Enumerator: " << block_enumerator << std::endl;
#endif
    }

    inline void blockEnumMain(oc::CLP& cmd) {
        // if (cmd.isSet("enum")) {
            block_enum(cmd);
        // }
    }
}


#endif //LIBOTE_BLOCKENUMERATOR_H

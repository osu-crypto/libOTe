#ifndef LIBOTE_BLOCKENUMERATOR_H
#define LIBOTE_BLOCKENUMERATOR_H

#include "EnumeratorTools.h"

#include <iostream>


namespace osuCrypto {

    template<typename I, typename R>
    R block_enum(u64 w, u64 h, u64 k, u64 n, u64 sigma) {
        assert(w <= k && h <= n && sigma <= k);
        assert(k% sigma == 0 && n % sigma == 0);
        assert(n % k == 0);

        R enumerator = 0;
        size_t k_over_sigma = k / sigma;
        size_t e = n / k;
        for (size_t q = 0; q <= k_over_sigma; q++) {
            // Part 1: 2^{-e\sigma q}
            R scale = 1.0 / (1 << (e * sigma * q));
            // std::cerr << "scale " << scale << std::endl;

            // Part 2: E_{w,q}
            // std::cout  << (w-q) << "," << q << "," << (sigma-1) << std::endl;
            I E_wq = choose_<I>(k_over_sigma, q) * labeledBallBinCap<I>(w, q, sigma);
            // std::cerr << "E_wq " << E_wq << std::endl;

            // Part 3: E_{q,h} = e * sigma * q choose h
            I E_qh = choose_<I>(e * sigma * q, h);
            // std::cerr << "E_qh " << E_qh << std::endl;

            // Putting it all together
            enumerator += scale * E_wq * E_qh;
            std::cerr << "Enumerator " << enumerator << std::endl;
        }
        return enumerator;
    }

    inline void block_enum(oc::CLP& cmd) {
        std::cout << "Computing enumerator for the block construction..." << std::endl;

        u64 w = cmd.getOr("w", 5); // input weight
        u64 h = cmd.getOr("h", 15); // output weight
        u64 k = cmd.getOr("k", 10); // msg length
        u64 n = cmd.getOr("n", 20); // codeword length
        u64 sigma = cmd.getOr("sigma", 2); // window size

        std::cout << "w: " << w << std::endl;
        std::cout << "h: " << h << std::endl;
        std::cout << "k: " << k << std::endl;
        std::cout << "n: " << n << std::endl;
        std::cout << "sigma: " << sigma << std::endl;

        Rat block_enumerator = block_enum<Int, Rat>(w, h, k, n, sigma);
        std::cout << "Block Enumerator: " << block_enumerator << std::endl;
    }

    inline void blockEnumMain(oc::CLP& cmd) {
        assert(ballBinCap<Int>(2, 3, 1) == 3);
        assert(choose_<Int>(-2, 2) == 0);
        // if (cmd.isSet("enum")) {
            block_enum(cmd);
        // }
    }
}


#endif //LIBOTE_BLOCKENUMERATOR_H

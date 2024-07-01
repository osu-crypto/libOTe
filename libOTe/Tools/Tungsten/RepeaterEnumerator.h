#ifndef LIBOTE_REPEATERENUMERATOR_H
#define LIBOTE_REPEATERENUMERATOR_H

#include "EnumeratorTools.h"

#include <iostream>


namespace osuCrypto {

    template<typename I>
    I repeater_enum(u64 w, u64 h, u64 n, u64 k) {
        assert(w <= n);
        assert(h <= k * n);

        if (h != w * k) {
            return 0;
        }
        return choose_<I>(n, w);
    }

    inline void repeater_enum(oc::CLP& cmd) {
        std::cout << "Computing enumerator for the repeater..." << std::endl;

        u64 w = cmd.getOr("w", 5); // input weight
        u64 h = cmd.getOr("h", 15); // output weight
        u64 n = cmd.getOr("n", 10); // msg length (note NOT codeword length, which is k * n)
        u64 k = cmd.getOr("k", 3); // # of repetitions

        std::cout << "w: " << w << std::endl;
        std::cout << "h: " << h << std::endl;
        std::cout << "n: " << n << std::endl;
        std::cout << "k: " << k << std::endl;

        Int repeater_enumerator = repeater_enum<Int>(w, h, n, k);
        std::cout << "Repeater Enumerator: " << repeater_enumerator << std::endl;

        assert(repeater_enum<Int>(5, 15, 10, 3) == 252);
        assert(repeater_enum<Int>(5, 15, 10, 2) == 0);
    }

    inline void repeaterEnumMain(oc::CLP& cmd) {
        // if (cmd.isSet("enum")) {
        repeater_enum(cmd);
        // }
    }
}

#endif //LIBOTE_REPEATERENUMERATOR_H

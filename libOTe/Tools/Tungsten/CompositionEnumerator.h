#ifndef LIBOTE_COMPOSITIONENUMERATOR_H
#define LIBOTE_COMPOSITIONENUMERATOR_H

#include "EnumeratorTools.h"

#include <iostream>

namespace osuCrypto {

    template<typename R>
    R composition_enum(u64 w, u64 h, u64 n1,
                       std::vector<Rat> &e1,
                       std::vector<Rat> &e2) {
        assert(e1.size() == (n1 + 1));
        assert(e2.size() == (n1 + 1));

        R enumerator = 0;
        for (size_t h1 = 0; h1 <= n1; h1++) {
            enumerator += (e1[h1] * e2[h1] / choose_<R>(n1, h1));
        }
        return enumerator;
    }

    inline void composition_enum(oc::CLP& cmd) {
        std::cout << "Computing enumerator for the repeater..." << std::endl;

        u64 w = 5; // input weight
        u64 h = 2; // output weight
        u64 n1 = 3; // middle msg length
        std::vector<Rat> e1 = {2,3,4,2}; // enumerator 1
        std::vector<Rat> e2 = {3,4,5,4}; // enumerator 2

        std::cout << "w: " << w << std::endl;
        std::cout << "h: " << h << std::endl;
        std::cout << "n1: " << n1 << std::endl;

        Rat composition_enumerator = composition_enum<Rat>(w, h, n1, e1, e2);
        std::cout << "Composition Enumerator: " << composition_enumerator << std::endl;

        assert(composition_enumerator == Rat(74) / 3);
    }

    inline void compositionEnumMain(oc::CLP& cmd) {
        // if (cmd.isSet("enum")) {
        composition_enum(cmd);
        // }
    }
}

#endif //LIBOTE_COMPOSITIONENUMERATOR_H

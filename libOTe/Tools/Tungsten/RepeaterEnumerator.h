#ifndef LIBOTE_REPEATERENUMERATOR_H
#define LIBOTE_REPEATERENUMERATOR_H

#include "EnumeratorTools.h"

#include <iostream>

namespace osuCrypto {

    //template<typename I>
    //I repeater_enum(u64 w, u64 h, u64 n, u64 k);

    template<typename I>
    I repeater_enum(u64 w, u64 h, u64 k, u64 e, ChooseCache<I>&pascal_triangle) {
        assert(w <= k);
        assert(h <= e * k);

        // for E_w,h to be nonzero, h must equal to w*e
        if (h != w * e) {
            return 0;
        }
        return choose_pascal<I>(k, w, pascal_triangle);
    }

    inline void repeater_enum(oc::CLP& cmd) {
        std::cout << "Computing enumerator for the repeater..." << std::endl;

        u64 w = cmd.getOr("w", 5); // input weight
        u64 h = cmd.getOr("h", 15); // output weight
        u64 k = cmd.getOr("k", 10); // msg length (note NOT codeword length, which is e * k)
        u64 e = cmd.getOr("e", 3); // # of repetitions

        std::cout << "w: " << w << std::endl;
        std::cout << "h: " << h << std::endl;
        std::cout << "k: " << k << std::endl;
        std::cout << "e: " << e << std::endl;

        ChooseCache<Int> pascal_triangle;
        Int repeater_enumerator = repeater_enum<Int>(w, h, k, e, pascal_triangle);
        std::cout << "Repeater Enumerator: " << repeater_enumerator << std::endl;

        //assert(repeater_enum<Int>(5, 15, 10, 3) == 252);
        //assert(repeater_enum<Int>(5, 15, 10, 2) == 0);
    }

    inline void repeaterEnumMain(oc::CLP& cmd) {
        // if (cmd.isSet("enum")) {
        repeater_enum(cmd);
        // }
    }
}

#endif //LIBOTE_REPEATERENUMERATOR_H

#ifndef LIBOTE_REPEATERENUMERATOR_H
#define LIBOTE_REPEATERENUMERATOR_H

#include "EnumeratorTools.h"

#include <iostream>

namespace osuCrypto {

    //template<typename I>
    //I repeaterEnumerator(u64 w, u64 h, u64 n, u64 k);

    template<typename I>
    I repeaterEnumerator(u64 w, u64 h, u64 k, u64 e, const ChooseCache<I>&pascal_triangle) {
        assert(w <= k);
        assert(h <= e * k);

        // for E_w,h to be nonzero, h must equal to w*e
        if (h != w * e) {
            return 0;
        }
        return choose_pascal<I>(k, w, pascal_triangle);
    }


	template<typename I, typename R>
	void repeaterEnumerator(
		span<R> distribution,
		u64 k,
		u64 n,
		const ChooseCache<I>& pascal_triangle) {
		auto e = n / k;
		if (distribution.size() != n + 1)
			throw RTE_LOC;
		if (k * e != n)
			throw RTE_LOC;

		// NOTE we exclude w=0 from the input x as it would always result in all zeros, so E_{w=0,h=0}=1
		// but then minimum distance would always be 0 as the distribution would be 1 in the first entry! 
		// in the following iterations we do care about w=0 as non-zero input could result in h=0
		distribution[0] = I(0);
		for (u64 h = 1; h <= n; h++) {
			u64 w = h / e; // all other w will result in 0 enumerator, only non-zero when h = w * e
			if (w * e == h) {
				distribution[h] = repeaterEnumerator<I>(w, h, k, e, pascal_triangle);
			}
			else {
				distribution[h] = I(0);
			}
		}

		/*// the method below is also correct
		for (size_t h = 0; h <= n; h++) {
			// note that for firstSubcode, we do NOT need this loop, but used now for modularity
			// NOTE we exclude w=0 from the input x as it would always result in all zeros, so E_{w=0,h=0}=1
			// but then minimum distance would always be 0 as the distribution would be 1 in the first entry!
			// in the following iterations we care about w=0 as non-zero input could result in h=0
			for (size_t w = 1; w <= k; w++) {
				distribution[h] += repeaterEnumerator<I>(w, h, k, e, pascal_triangle);
				assert(distribution[0] == 0);
			}
		}*/
	}


    //inline void repeaterEnumerator(oc::CLP& cmd) {
    //    std::cout << "Computing enumerator for the repeater..." << std::endl;

    //    u64 w = cmd.getOr("w", 5); // input weight
    //    u64 h = cmd.getOr("h", 15); // output weight
    //    u64 k = cmd.getOr("k", 10); // msg length (note NOT codeword length, which is e * k)
    //    u64 e = cmd.getOr("e", 3); // # of repetitions

    //    std::cout << "w: " << w << std::endl;
    //    std::cout << "h: " << h << std::endl;
    //    std::cout << "k: " << k << std::endl;
    //    std::cout << "e: " << e << std::endl;

    //    ChooseCache<Int> pascal_triangle;
    //    Int repeater_enumerator = repeaterEnumerator<Int>(w, h, k, e, pascal_triangle);
    //    std::cout << "Repeater Enumerator: " << repeater_enumerator << std::endl;

    //    //assert(repeaterEnumerator<Int>(5, 15, 10, 3) == 252);
    //    //assert(repeaterEnumerator<Int>(5, 15, 10, 2) == 0);
    //}

    //inline void repeaterEnumMain(oc::CLP& cmd) {
    //    // if (cmd.isSet("enum")) {
    //    repeaterEnumerator(cmd);
    //    // }
    //}
}

#endif //LIBOTE_REPEATERENUMERATOR_H

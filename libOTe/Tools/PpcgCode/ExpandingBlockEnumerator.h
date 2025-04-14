#ifndef LIBOTE_EXPANDINGBLOCKENUMERATOR_H
#define LIBOTE_EXPANDINGBLOCKENUMERATOR_H

#include "BlockEnumerator.h"
#include "EnumeratorTools.h"

#include <iostream>
#include <algorithm>
#include "SubcodeType.h"


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

		if (h < w || h >(nn + w)) {
			return 0;
		}
		return block_enum<I, R>(w, h - w, k, nn, sigma, pascal_triangle);
	}


	template<typename I, typename R>
	void expanding_block_thread_function(u64 start_h, u64 end_h, u64 k, u64 n, u64 sigma_expander,
		span<R> distribution, ChooseCache<I> pascal_triangle) {
		for (u64 h = start_h; h < end_h; ++h) {
			for (u64 w = 1; w <= k; ++w) {
				// Use the thread-specific copy of pascal_triangle
				// Safely update the shared distribution[h] (one element per h)
				// Note no need to lock it as each thread operates on different unique index h in new_distribution
				distribution[h] += expanding_block_enum<I, R>(w, h, k, n, sigma_expander, pascal_triangle);
			}

			loadBar.tick();
		}
	}

	template<typename I, typename R>
	void compute_expanding_block_distribution(
		span<R> distribution,
		u64 k,
		u64 n,
		u64 sigma,
		const ChooseCache<I>& pascal_triangle) {
		std::fill(distribution.begin(), distribution.end(), R(0));

		// NOTE the code below could be optimized as when computing the distributions in the following iterations
		// I.e. switching the h,w loops enables to precompute parts of the enumerator (if we iterate over w first)

		// 16 as my computer has 16 cores
		// 50 picked heuristically
		u64 num_cores = std::thread::hardware_concurrency();
		u64 heuristic = ceil((n + 1) / 50.);
		u64 num_threads = (heuristic < num_cores) ? heuristic : num_cores;
		// Calculate chunk size for each thread
		u64 chunk_size = (n + 1) / num_threads;
		std::vector<std::jthread> threads;

		for (int i = 0; i < num_threads; ++i) {
			// Start each thread with its range of `h` and thread-specific pascal_triangle
			threads.emplace_back(
				[&, i]() {
					u64 start_h = i * chunk_size;
					u64 end_h = (i == num_threads - 1) ? (n + 1) : (start_h + chunk_size);

					expanding_block_thread_function<I, R>(start_h, end_h, k, n, sigma,
						distribution, pascal_triangle);
				});
		}
	}



	template<typename I, typename R>
	void compute_expanding_distribution(span<R> distribution,
		SubcodeType expander,
		u64 k,
		u64 n,
		u64 sigma_expander,
		const ChooseCache<I>& pascal_triangle) { // only for the expanding block
		//if (e != (n / k) < 0) {
		//    throw std::invalid_argument("e is inconsistent with k, n");
		//}
		if (expander == SubcodeType::Repeater) {
			// firstSubcode
			repeaterEnumerator<I, R>(distribution, k, n, pascal_triangle);
		}
		else if (expander == SubcodeType::Block) {
			// expanding block
			assert(sigma_expander > 0);
			assert(sigma_expander <= k);
			assert(k % sigma_expander == 0);

			compute_expanding_block_distribution<I, R>(distribution, k, n, sigma_expander, pascal_triangle);
		}
		else {
			throw std::invalid_argument("invalid expander (currently only repeater, and expanding block supported)");
		}
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

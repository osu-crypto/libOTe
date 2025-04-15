#pragma once

#include <bitset>
#include <cassert>

#include "EnumeratorTools.h"
#include "MinimumDistance.h"

#define BITSET_SIZE 128

namespace osuCrypto {
	namespace old_
	{


		template <typename T>
		inline T choose_(i64 n, i64 k)
		{
			if (k < 0 || k > n)
				return 0;
			if (k == 0 || k == n)
				return 1;

			k = std::min<i64>(k, n - k);
			T c = 1;
			for (u64 i = 0; i < k; ++i)
				c = c * (n - i) / (i + 1);
			return c;
		}


		template<typename T>
		inline T labeledBallBinCap_old(u64 balls, u64 bins, u64 cap) {
			T d = 0;
			for (u64 i = 0; i <= bins; ++i) {
				T v = (i & 1) ? -1 : 1;
				auto mt = choose_<T>(bins, i);

				i64 bb = cap * (bins - i64(i));
				if (bb < balls || bb < 0) {
					break;
				}

				auto r = choose_<T>(bb, balls);
				//std::cout << i << " r " << r << " = C(" << bb << ", " << bins-1 << ")" << std::endl;

				//if (mt != mt)
				//    throw RTE_LOC;
				//if (r != r)
				//    throw RTE_LOC;
				d += v * mt * r;
				//std::cout << i << " d " << d << std::endl;
			}
			//std::cout << "labeledBallBinCap_old( " << balls << ", " << bins << ", " << cap << ") = " << d << std::endl;
			return d;
		}

		template<typename I, typename R>
		R block_enum_old(u64 w, u64 h, u64 k, u64 n, u64 sigma) {
			assert(w <= k && h <= n && sigma <= k);
			assert(k % sigma == 0 && n % sigma == 0);
			assert(n % k == 0);

			//std::cout << "block_enum_old " << w << " " << h << " " << k << " " << n << "  " << sigma << std::endl;
			R enumerator = 0;
			size_t k_over_sigma = k / sigma;
			size_t e = n / k;
			for (size_t q = 0; q <= k_over_sigma; q++) {
				// Part 1: 2^{-e\sigma q}
				// assert(e * sigma * q <= 64);
				R scale = R(1.0) / boost::multiprecision::pow(boost::multiprecision::cpp_int(2), e * sigma * q); // R(1 << e * sigma * q);
				//std::cout << "scale " << scale << std::endl;

				// Part 2: E_{w,q}
				// std::cout  << (w-q) << "," << q << "," << (sigma-1) << std::endl;
				I E_wq = choose_<I>(k_over_sigma, q) * labeledBallBinCap_old<I>(w, q, sigma);
				//std::cout << "E_wq " << E_wq 
				//	<< " = " << choose_<I>(k_over_sigma, q) <<
				//	" * " << labeledBallBinCap_old<I>(w, q, sigma) << std::endl;

				// Part 3: E_{q,h} = e * sigma * q choose h
				I E_qh = choose_<I>(e * sigma * q, h);
				//std::cout << "E_qh " << E_qh << std::endl;

				// Putting it all together
				enumerator += scale * E_wq * E_qh;
				//std::cout << "Enumerator " << enumerator << std::endl;
			}
			return enumerator;
		}

		template<typename I, typename R>
		R expanding_block_enum_old(u64 w, u64 h, u64 k, u64 n, u64 sigma) {
			assert(n % k == 0);
			size_t e = n / k;

			assert(w <= k);
			assert(sigma <= k);

			if (h < w || h >(k + w)) { // TODO assuming e == 2 h <= k + w
				return 0;
			}
			return block_enum_old<I, R>(w, h - w, k, (e - 1) * k, sigma);
		}


		template<typename I>
		I repeater_enum_old(u64 w, u64 h, u64 k, u64 e) {
			assert(w <= k);
			assert(h <= e * k);

			if (h != w * e) {
				return 0;
			}
			return choose_<I>(k, w);
		}

		inline u64 hamming_weight(const std::vector<short>& array) {
			u64 sum = 0;
			for (const auto& a : array) {
				sum += a;
			}
			return sum;
		}

		inline std::vector<short> decimalToBinary(uint64_t n, uint64_t bitsize) {
			assert(bitsize < 64);
			assert(n < (uint64_t(1) << bitsize));
			std::vector<short> binary(bitsize);
			if (n == 0) {
				return binary; // 0
			}

			// NOTE put in the same order as in bitset
			uint64_t i = 0; // bitsize-1;
			while (n > 0) {
				binary[i++] = static_cast<short>(n % 2);
				//binary[i--] = static_cast<short>(n % 2);
				n /= uint64_t(2);
			}
			return binary;
		}

		inline std::vector<std::bitset<BITSET_SIZE>> generate_all_gis(u64 k, u64 n, u64 sigma) {
			u64 num_gis_in_g = k / sigma;
			u64 e = n / k;
			u64 num_elements_in_one_gi = sigma * e * sigma;
			// all G_is but in the same G
			const u64 num_elements_in_all_gis = num_gis_in_g * num_elements_in_one_gi;
			// std::cout << "Bitset size: " << num_elements_in_all_gis << std::endl;
			assert(BITSET_SIZE >= num_elements_in_all_gis);
			// 2^{k/sigma * sigma * e * sigma}
			assert(num_elements_in_all_gis < 64);
			u64 num_possibilities = u64(1) << num_elements_in_all_gis;
			std::vector<std::bitset<BITSET_SIZE>> all_possibilities(num_possibilities);
			for (size_t idx = 0; idx < num_possibilities; idx++) {
				all_possibilities[idx] = idx;
				// std::cout << all_possibilities[idx] << std::endl;
			}
			return all_possibilities;
		}

		inline std::vector<std::vector<short>> generate_all_gis_bool(u64 k, u64 n, u64 sigma) {
			u64 num_gis_in_g = k / sigma;
			u64 e = n / k;
			u64 num_elements_in_one_gi = sigma * e * sigma;
			// all G_is but in the same G
			const u64 num_elements_in_all_gis = num_gis_in_g * num_elements_in_one_gi;
			// 2^{k/sigma * sigma * e * sigma}
			assert(num_elements_in_all_gis < 64);
			u64 num_possibilities = u64(1) << num_elements_in_all_gis;
			std::vector<std::vector<short>> all_possibilities;
			for (size_t idx = 0; idx < num_possibilities; idx++) {
				all_possibilities.push_back(decimalToBinary(idx, num_elements_in_all_gis));
				// std::cout << all_possibilities[idx] << std::endl;
			}
			return all_possibilities;
		}

		inline std::vector<std::bitset<BITSET_SIZE>> generate_all_x_of_weight_w(u64 k, u64 w) {
			assert(BITSET_SIZE >= k);
			std::vector<std::bitset<BITSET_SIZE>> all_xs;
			assert(k <= 63);
			u64 num_possibilities = 1 << k; // 2^{k}
			for (size_t idx = 0; idx < num_possibilities; idx++) {
				std::bitset<BITSET_SIZE> possibility = idx;
				if (possibility.count() == w) {
					all_xs.push_back(possibility);
					// std::cout << possibility << std::endl;
				}
			}
			return all_xs;
		}

		inline std::vector<std::vector<short>> generate_all_x_of_weight_w_bool(u64 k, u64 w) {
			std::vector<std::vector<short>> all_xs;
			assert(k < 64);
			u64 num_possibilities = 1 << k; // 2^{k}
			for (size_t idx = 0; idx < num_possibilities; idx++) {
				std::vector<short> possibility = decimalToBinary(idx, k);
				u64 sum = hamming_weight(possibility);
				if (sum == w) {
					all_xs.push_back(possibility);
					// std::cout << possibility << std::endl;
				}
			}
			return all_xs;
		}

		inline std::vector<std::bitset<BITSET_SIZE>> generate_all_x(u64 k) {
			assert(BITSET_SIZE >= k);
			assert(k < 64);
			u64 num_possibilities = u64(1) << k; // 2^{k}
			std::vector<std::bitset<BITSET_SIZE>> all_xs(num_possibilities);
			for (size_t idx = 0; idx < num_possibilities; idx++) {
				all_xs[idx] = idx;
			}
			return all_xs;
		}

		inline std::vector<std::vector<short>> generate_all_x_bool(u64 k) {
			assert(k < 64);
			u64 num_possibilities = u64(1) << k; // 2^{k}
			std::vector<std::vector<short>> all_xs;
			for (size_t idx = 0; idx < num_possibilities; idx++) {
				all_xs.push_back(decimalToBinary(idx, k));
			}
			return all_xs;
		}

		inline std::bitset<BITSET_SIZE> multiply_x_g(const std::bitset<BITSET_SIZE>& x,
			const std::bitset<BITSET_SIZE>& g,
			u64 sigma, u64 k, u64 n) {
			assert(BITSET_SIZE >= n);
			std::bitset<BITSET_SIZE> res;
			size_t e = n / k;
			assert(k % sigma == 0 && n % sigma == 0);
			size_t num_gis = k / sigma; // number of G_i's in a single G
			for (size_t gi = 0; gi < num_gis; gi++) {
				size_t x_offset = gi * sigma;
				size_t res_offset = gi * e * sigma;
				size_t g_offset = gi * sigma * e * sigma;
				for (size_t si = 0; si < (e * sigma); si++) {
					for (size_t sj = 0; sj < sigma; sj++) {
						res[res_offset + si] = res[res_offset + si] ^
							(x[x_offset + sj] && g[g_offset + sj * e * sigma + si]);
					}
				}
			}
			return res;
		}

		inline std::vector<short> multiply_x_g_bool(const std::vector<short>& x,
			const std::vector<short>& g,
			u64 sigma, u64 k, u64 n) {
			if (g.size() != n * sigma) throw RTE_LOC;
			if (x.size() != k) throw RTE_LOC;
			if (k % sigma != 0 || n % sigma) throw RTE_LOC;

			size_t e = n / k;
			std::vector<short> res(n);
			size_t num_gis = k / sigma; // number of G_i's in a single G
			for (size_t gi = 0; gi < num_gis; gi++) {
				size_t x_offset = gi * sigma;
				size_t res_offset = gi * e * sigma;
				size_t g_offset = gi * sigma * e * sigma;
				for (size_t si = 0; si < (e * sigma); si++) {
					//std::cout << "r" << res_offset + si << " = ";
					for (size_t sj = 0; sj < sigma; sj++) {
						//std::cout << "+ x" << x_offset + sj <<"."<< x[x_offset + sj] 
						//    << " * g" << g_offset + sj * e * sigma + si <<"."<< g[g_offset + sj * e * sigma + si];
						res[res_offset + si] = res[res_offset + si] ^
							(x[x_offset + sj] && g[g_offset + sj * e * sigma + si]);
					}
					//std::cout <<" = " << res[res_offset + si] << std::endl;
				}
			}
			return res;
		}

		inline u64 count(std::vector<short>& v) {
			return std::accumulate(v.begin(), v.end(), 0ull);
		}

		template<typename R>
		u64 minimum_distance_v1_true(u64 expander,
			u64 multiplier,
			u64 num_iters,
			u64 k, u64 n, u64 sigma) {
			size_t e = n / k;
			// Generate all possible G_i's (the blocks in matrix G)
			// TODO Assume for now a single G for all iterations and only a repeater for the expansion
			auto gis = generate_all_gis_bool(n, n, sigma);
			std::cout << "All " << gis.size() << " Gi's generated..." << std::endl;
			// Generate all possible input x's
			auto xs = generate_all_x_bool(k);
			std::cout << "All " << xs.size() << " x's generated..." << std::endl;
			std::vector<Rat> count_weight_h_outputs(n + 1);
			// iterate over all G's
			for (const auto& g : gis) {
				// for each G, iterate over all x's
				for (const auto& x : xs) {
					// expander
					std::vector<short> expanded_x(n);
					if (expander == 0) {
						// repeater
						u64 offset = 0;
						for (size_t i = 0; i < k; i++) {
							for (size_t j = 0; j < e; j++) {
								expanded_x[offset++] = x[i];
							}
						}
					}
					else if (expander == 1) {
						// expanding block
						// TODO
						throw RTE_LOC;
					}
					// multiply x and g at each iteration
					// TODO different G at each iteration?
					auto xg = multiply_x_g_bool(expanded_x, g, sigma, n, n);
					// if xg has weight h, add 1 to the enumerator
					count_weight_h_outputs[count(xg)]++;
				}
			}
			// Divide each count by the number of G's
			for (auto& count : count_weight_h_outputs) {
				count /= gis.size();
			}
			// Compute the minimum distance
			// Find at which index the sum >= 1. That is the minimum distance
			R sum = 0;
			u64 minimum_distance = 0;
			for (size_t h = 0; h < n; h++) {
				sum += count_weight_h_outputs[h];
				if (sum >= 1.) {
					return minimum_distance;
				}
				minimum_distance++;
			}
			return n;
		}


		template<typename I, typename R>
		u64 minimum_distance_v1(
			u64 expander,
			u64 multiplier,
			u64 num_iters,
			u64 k, u64 n, u64 sigma) {
			std::cout << "Computing minimum distance..." << std::endl;

			if (expander == 1) {
				// block expander at the beginning
				assert(sigma <= k); // TODO should we have separate sigma for the expander?
			}

			u64 e = n / k;

			assert(sigma <= n);
			assert(num_iters >= 1);
			assert(n >= k);
			assert(e > 1); // need to be expanding
			assert(n % k == 0);
			assert(n % sigma == 0);

			// NOTE no longer used as k^2 space too big
			// Compute all k^2 possible block enumerators
			// k^2 space... but it is reused at each iteration
			/*
			std::vector<std::vector<R>> block_enumerators(k, std::vector<R>(k));
			for (size_t w = 0; w < k; w++) {
				for (size_t h = 0; h < k; h++) {
					block_enumerators[w][h] = block_enum<I, R>(w, h, k, sigma);
				}
			}
			 */

			 // Save all n choose w as used at all iterations (but not expansion step)
			 // n + 1 space
			std::vector<I> n_choose_w(n + 1);
			for (size_t w = 0; w <= n; w++) {
				n_choose_w[w] = choose_<I>(n, w);
			}

			// 2 * (n + 1) space
			std::vector<std::vector<R>> distributions(2, std::vector<R>(n + 1, 0)); // distribution for w = 0 to w = n

			// Expansion step is slightly different from the iterations
			// as 1. we are expanding and 2. c_w = k choose w, so they divide each other
			for (size_t h = 0; h <= n; h++) {
				// note that for repeater, we do NOT need this loop, but used now for modularity
				// NOTE we exclude w=0 from the input x as it would always result in all zeros
				for (size_t w = 1; w <= k; w++) {
					if (expander == 0) {
						// repeater
						distributions[0][h] += repeater_enum_old<I>(
							w, h, k, e);
						assert(distributions[0][0] == 0);
					}
					else if (expander == 1) {
						// block expander (identity + block)
						distributions[0][h] +=
							expanding_block_enum_old<I, R>(w, h, k, n, sigma);
					}
				}
			}

			// Iterations
			for (size_t iter = 0; iter < num_iters; iter++) {
				// compute distributions[(iter + 1) % 2]
				for (size_t h = 0; h <= n; h++) {
					for (size_t w = 0; w <= n; w++) {
						R enumerator = 0;
						if (multiplier == 0) {
							// block enumerator
							enumerator = block_enum_old<I, R>(w, h, n, n, sigma);
						}
						else if (multiplier == 1) {
							// non-recursive convolution
							// TODO
							assert(false);
						}
						std::cout << "h " << h << std::endl;
						std::cout << "w " << w << std::endl;
						std::cout << "n " << n << std::endl;
						std::cout << "enumerator " << enumerator << std::endl;
						std::cout << "n choose w " << n_choose_w[w] << std::endl;
						assert(enumerator <= n_choose_w[w]);
						distributions[(iter + 1) % 2][h] += (distributions[iter % 2][w] / n_choose_w[w] * enumerator);
					}
				}
			}

			// Now take whichever of distributions[0]/distributions[1] was filled last
			// and find at which index the sum >= 1. That is the minimum distance
			R sum = 0;
			u64 minimum_distance = 0;
			for (size_t h = 0; h <= n; h++) {
				sum += distributions[num_iters % 2][h];
				if (sum >= 1.) {
					return minimum_distance;
				}
				minimum_distance++;
			}
			return n;
		}

		inline void minimum_distance_tests() {
			// expander, multiplier, num_iters, k, n, sigma
			std::vector<std::vector<u64>> params = {
				//  expander multiplier num_iters, k, n, sigma
					{0, 0, 1, 4, 8, 2}, // repeater and block enumerator
					// {0, 0, 1, 4, 8, 8}, // repeater and block enumerator
					// TODO add test with >1 iteration {0, 0, 1, 6, 12, 2},
					//  TODO add more tests with different expander multiplier
					//{4,12,2},
					//{6,6,3}
			};
			for (auto& param : params) {
				// TODO remove when ready
				if (param[0] != 0 || param[1] != 0) assert(false);
				u64 expected_md = minimum_distance_v1<Int, Rat>(param[0],
					param[1],
					param[2],
					param[3],
					param[4],
					param[5]);
				u64 true_md = minimum_distance_v1_true<Rat>(param[0],
					param[1],
					param[2],
					param[3],
					param[4],
					param[5]);
				std::cout << "Expected minimum distance: " << expected_md << std::endl;
				std::cout << "True minimum distance: " << true_md << std::endl;

				assert(expected_md == true_md);
				if (expected_md != true_md) {
					throw RTE_LOC;
				}
			}
		}



		// NOTE WORKS WITH vector<short>
		// Runtime should be faster but needs more memory
		template<typename R>
		R block_enum_true_v2(u64 w, u64 h, u64 k, u64 n, u64 sigma) {
			// Generate all possible G_i's (the blocks in matrix G)
			std::vector<std::vector<short>> gis = generate_all_gis_bool(k, n, sigma);
			std::cout << "All " << gis.size() << " Gi's generated..." << std::endl;
			// Generate all possible weight w input x's
			std::vector<std::vector<short>> xs = generate_all_x_of_weight_w_bool(k, w);
			std::cout << "All " << xs.size() << " x's of weight w generated..." << std::endl;
			R enumerator = 0;
			// iterate over all G's
			for (const auto& g : gis) {
				// for each G, iterate over all weight w inputs
				for (const auto& x : xs) {
					// multiply x and g
					std::vector<short> xg = multiply_x_g_bool(x, g, sigma, k, n);
					// if xg has weight h, add 1 to the enumerator
					if (hamming_weight(xg) == h) {
						//std::cout << "X: " << x << std::endl;
						//std::cout << "G: " << g << std::endl;
						//std::cout << "XG: " << xg << std::endl;
						enumerator++;
					}
				}
			}
			// Divide the enumerator by the number of G's
			enumerator /= gis.size();
			return enumerator;
		}

		inline void block_enumerator_tests() {
			// w, h, k, n, sigma
			std::vector<std::vector<u64>> params = {
					{0,0,4,8,2},
					{2,2,4,8,2},
					{2,3,4,12,2},
					{3,5,6,6,3}
			};
			for (auto& param : params) {
				Rat expected_enumerator = block_enum_old<Int, Rat>(param[0],
					param[1],
					param[2],
					param[3],
					param[4]);
				Rat true_enumerator = block_enum_true_v2<Rat>(param[0],
					param[1],
					param[2],
					param[3],
					param[4]);
				assert(expected_enumerator == true_enumerator);
				if (expected_enumerator != true_enumerator) {
					throw RTE_LOC;
				}
			}
		}


	}

	inline void minimumDistanceTestMain_old(const oc::CLP& cmd) {
		old_::block_enumerator_tests();
		//old_::minimum_distance_tests();
	}
}


#ifndef LIBOTE_BLOCKENUMERATOR_H
#define LIBOTE_BLOCKENUMERATOR_H

#include "EnumeratorTools.h"
#include "cryptoTools/Common/Matrix.h"
#include <iostream>
#include "cryptoTools/Common/ThreadBarrier.h"
#include "Print.h"
#include "LoadingBar.h"
#include "libOTe/Tools/LDPC/Mtx.h"
#include "oldMinDistTest.h"
#include "cryptoTools/Common/BitVector.h"
namespace osuCrypto {

	inline std::string toString(span<const u8> x)
	{
		std::stringstream ss;
		for (auto xx : x)
			ss << int(xx) << ' ';
		return ss.str();
	}

	// Given a compact representation of the block matrix G,
	// compute y = x * G.
	//
	// G should be in column major order with only sigmaK elements per column.
	// We do not express G as the full k by n matrix.
	inline void blockMtxMult(
		span<const u8> G,
		span<const u8> x,
		span<u8> y,
		u64 k, u64 n, u64 sigmaK, u64 sigmaN)
	{
		if (G.size() != sigmaK * n)
			throw RTE_LOC;
		if (G.size() != sigmaN * k)
			throw RTE_LOC;
		if (x.size() != k)
			throw RTE_LOC;
		if (y.size() != n)
			throw RTE_LOC;

		u64 blocks = n / sigmaN;

		for (u64 i = 0; i < blocks; i++)
		{
			auto xi = x.subspan(i * sigmaK, sigmaK);
			for (u64 j = 0; j < sigmaN; j++)
			{
				auto Gij = G.subspan((i * sigmaN + j) * sigmaK, sigmaK);
				y[i * sigmaN + j] = std::inner_product(Gij.begin(), Gij.end(), xi.begin(), u8{ 0 }, std::bit_xor<u8>(), std::bit_and<u8>());
				assert(y[i * sigmaN + j] <= 1);
			}
		}
	}


	// Given a bit-packed representation of the block matrix G,
	// compute y = x * G.
	//
	// G should be in column major order with only sigmaK bits per column.
	// We do not express G as the full k by n matrix.
	template<typename T>
	inline void blockMtxMultBit(
		span<const T> G,
		span<const T> x,
		span<T> y,
		u64 k, u64 n, u64 sigmaK, u64 sigmaN)
	{
		if (G.size() != n)
			throw RTE_LOC;
		if (x.size() != k / sigmaK)
			throw RTE_LOC;
		if (y.size() != n)
			throw RTE_LOC;
		if (sigmaK > sizeof(T) * 8)
			throw RTE_LOC;

		u64 blocks = n / sigmaN;
		auto Giter = G.data();
		auto yIter = y.data();
		for (u64 i = 0; i < blocks; i++)
		{
			auto xi = x[i];
			for (u64 j = 0; j < sigmaN; j++)
			{
				*yIter++ = popcount(*Giter++ & xi) % 2;
			}
		}
	}


	// Given a compact representation of the block matrix G,
	// return a printable string of it 
	//
	// G should be in column major order with only sigmaK elements per column.
	// We do not express G as the full k by n matrix.
	template<typename T>
	inline std::string blockMtxToString(std::vector<T>& G, u64 k, u64 n)
	{
		std::stringstream ss;
		if (G.size() % k)
			throw RTE_LOC;
		if (n % k)
			throw RTE_LOC;

		auto e = n / k;
		auto sigma = G.size() / k;

		if (G.size() != n * sigma)
			throw RTE_LOC;

		MatrixView<T> GG(G.data(), n, sigma);
		auto iter = G.begin();
		for (u64 i = 0; i < k; ++i)
		{
			auto b = i / sigma;
			auto jb = b * sigma * e;
			auto je = (b + 1) * sigma * e;

			for (u64 j = 0; j < jb; ++j)
				ss << '0' << ' ';
			for (u64 j = jb; j < je; ++j)
				ss << int(GG(j, i % sigma)) << ' ';
			for (u64 j = je; j < n; ++j)
				ss << '0' << ' ';
			ss << std::endl;
		}
		ss << std::endl;
		return ss.str();
	}



	template<typename I, typename R>
	R block_enum(u64 w, u64 h, u64 k, u64 n, u64 sigma, const ChooseCache<I>& pascal_triangle) {
		if (!(w <= k && h <= n && sigma <= k))
			throw RTE_LOC;
		if (k % sigma)
			throw RTE_LOC;
		if (n % k)
			throw RTE_LOC;

		//std::cout << "block_enum " << w <<" "<<h<<" " <<k <<" "<<n <<"  " <<sigma << std::endl;
		R enumerator = 0;
		size_t k_over_sigma = k / sigma;
		size_t e = n / k;
		for (size_t q = 0; q <= k_over_sigma; q++) {


			// Part 1: 2^{-e\sigma q}
			// assert(e * sigma * q <= 64);
			// R scale = R(1.0) / boost::multiprecision::pow(boost::multiprecision::cpp_int(2), e * sigma * q); // R(1 << e * sigma * q);
			//R scale(1, boost::multiprecision::cpp_int(1) << (e * sigma * q));
			R scale = R(1) / pow2_<I>(e * sigma * q);
			//std::cout << "scale " << scale << std::endl;

			// Part 2: E_{w,q}
			// std::cout  << (w-q) << "," << q << "," << (sigma-1) << std::endl;
			I E_wq = choose_pascal<I>(k_over_sigma, q, pascal_triangle) * labeledBallBinCap<I>(w, q, sigma, pascal_triangle);
			//std::cout << "E_wq " << E_wq <<" = " << choose_pascal<I>(k_over_sigma, q, pascal_triangle) <<
			   // " * " << labeledBallBinCap<I>(w, q, sigma, pascal_triangle) << std::endl;

		   // Part 3: E_{q,h} = e * sigma * q choose h
			I E_qh = choose_pascal<I>(e * sigma * q, h, pascal_triangle);
			//std::cout << "E_qh " << E_qh << std::endl;

		   // Putting it all together
			enumerator += scale * E_wq * E_qh;
			//std::cout << "Enumerator " << enumerator << std::endl;
		}
		return enumerator;
	}




	// optimized block enumerator
	// 
	// inputDist: input the input weight distribution, if empty, we assume (w choose k)
	// outputDist: output distribution.
	// systematic: replace E_{w,h} with E_{w,h-w}. This should be true
	//    for the last subcode, e.g. G = (I ||(G1 G2 G3)), then G3 is systematic...
	// k = input length (inputDist.size() - 1)
	// n = output length (outputDist.size() - 1)
	// sigma = the subblock size
	// numThreads = number of threads to use
	// pascal_triangle = pascal triangle cache for the integer/floating point type
	// pascal_triangle2 = pascal triangle cache for the integer type (required for the labeledBallBinCap)
	// full = either void and then not used, or a matrix of R and the full 
	//    enumerator is written to it.
	template<typename I, typename R, typename I2, typename Full = int>
	void blockEnumerator(
		span<const R> inputDist,
		span<R> outputDist,
		bool systematic,
		u64 k,
		u64 n,
		u64 sigma,
		u64 numThreads,
		const ChooseCache<I>& pascal_triangle,
		const ChooseCache<I2>& pascal_triangle2,
		Full&& full = {})
	{


		if (inputDist.size() != 0 && inputDist.size() != k + 1)
			throw RTE_LOC;
		if (outputDist.size() != n + 1)
			throw RTE_LOC;
		if (!sigma || !k)
			throw RTE_LOC;
		if (k % sigma)
			throw RTE_LOC;
		if (n % k)
			throw RTE_LOC;
		if (numThreads < 1)
			throw RTE_LOC;

		auto nn = systematic ? n - k : n;
		if (nn % k)
			throw RTE_LOC;

		auto e = nn / k;
		auto qMax = k / sigma;

		// v[q] = 2^{-e sigma q} * C(k/sigma, q)
		std::vector<R> v(qMax + 1);
		Matrix<R> D(numThreads - 1, outputDist.size());
		//std::vector<std::vector<R>> D(numThreads - 1); for (auto& d : D)d.resize(outputDist.size());;
		ThreadBarrier vBarrier(numThreads);
		ThreadBarrier cBarrier(numThreads);

		std::vector<R> inputFrac(inputDist.size());
		auto start = std::chrono::system_clock::now();

		// precompute 2^{-e sigma}
		R twoESigma = R(1) / pow2_<I>(e * sigma);

		std::vector<std::jthread> threads(numThreads);
		for (u64 i = 0; i < threads.size(); ++i)
		{
			threads[i] = std::jthread([&, i] {
				auto qBegin = i * v.size() / numThreads;
				auto qEnd = (i + 1) * v.size() / numThreads;
				auto wBegin = i * (k + 1) / numThreads;
				auto wEnd = (i + 1) * (k + 1) / numThreads;
				auto hBegin = i * outputDist.size() / numThreads;
				auto hEnd = (i + 1) * outputDist.size() / numThreads;

				if (inputDist.size())
				{
					for (u64 w = wBegin; w < wEnd; ++w)
					{
						inputFrac[w] = inputDist[w] / choose_pascal(k, w, pascal_triangle);
					}
				}
				//std::stringstream ss;

				span<R> Di = i == 0 ? outputDist : D[i - 1];
				auto k_over_sigma = k / sigma;
				//Int e = boost::multiprecision::pow(Int(2), power);
				//R(boost::multiprecision::pow(v, power));
				R twoESigmaQ = R(1) / pow2_<I>(e * sigma * qBegin);
				for (u64 q = qBegin; q < qEnd; ++q)
				{
					// vq = 2^{-e sigma q} * C(k/sigma, q)
					v[q] = twoESigmaQ * choose_pascal<I>(k_over_sigma, q, pascal_triangle);

					// update 2^{-e sigma q} = 2^{-e sigma {q-1}} * 2^{-e sigma}
					twoESigmaQ *= twoESigma;
				}

				vBarrier.decrementWait();
				if (i == 0 && print_timings)
				{
					auto end = std::chrono::system_clock::now();
					auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
					std::cout << "precompute v: " << elapsed.count() << "ms" << std::endl;
					start = std::chrono::system_clock::now();
				}
				std::vector<R> cqw(qMax + 1);
				for (auto w = i; w < k + 1; w += numThreads)
				{
					if (systematic && w == 0)
						continue;

					for (u64 q = 0; q <= qMax; ++q)
					{
						cqw[q] = v[q] * labeledBallBinCap(w, q, sigma, pascal_triangle2).convert_to<I>();
						//cqw[q] = v[q] * labeledBallBinCap<I>(w, q, sigma, pascal_triangle);
					}

					auto hBegin = systematic ? w : 0;
					for (u64 h_ = hBegin; h_ <= n; ++h_)
					{
						u64 h = systematic ? h_ - w : h_;

						R enumerator = 0;
						for (u64 q = 0; q <= qMax; ++q)
						{
							enumerator += cqw[q] * choose_pascal<I>(e * sigma * q, h, pascal_triangle);
						}

#ifndef NDEBUG
						auto e2 = block_enum<I, R>(w, h, k, n, sigma, pascal_triangle);
						if (enumerator != e2)
							throw RTE_LOC;
#endif

						if constexpr (std::is_same_v<Full, int> == false)
						{
							full(w, h_) = enumerator;
						}

						if (inputDist.size())
						{
							if constexpr (std::is_same_v<R, Float>)
							{

								if (boost::multiprecision::isnan(enumerator) || enumerator < 0)
								{
									std::lock_guard l(gIoStreamMtx);
									std::cout << "(w,h) = " << w << ", " << h << " abnormal " << enumerator << std::endl;
									int i = 0;
									std::cin >> i;
								}
							}
							//auto dih = Di[h_];

							Di[h_] += enumerator * inputFrac[w];


						}
						else
						{
							Di[h_] += enumerator;
						}
					}

					loadBar.tick();
				}

				cBarrier.decrementWait();

				if (i == 0 && print_timings)
				{
					auto end = std::chrono::system_clock::now();
					auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
					std::cout << "compute enumerator: " << elapsed.count() << "ms" << std::endl;
					start = std::chrono::system_clock::now();
				}

				for (u64 t = 0; t < D.rows(); ++t)
				{
					for (u64 h = hBegin; h < hEnd; ++h)
					{
						auto dh = outputDist[h];

						outputDist[h] += D(t, h);

						if constexpr (std::is_same_v<Rat, Float>)
						{
							if (isnan(outputDist[h]))
							{
								std::lock_guard l(gIoStreamMtx);
								std::cout << "outputDist[h] " << outputDist[h] << " D(t, h) " << D(t, h) << " dh " << dh << std::endl;
								int i = 0;
								std::cin >> i;

							}
						}
					}
				}

				if (i == 0 && print_timings)
				{
					auto end = std::chrono::system_clock::now();
					auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
					std::cout << "compute sums: " << elapsed.count() << "ms" << std::endl;
					start = std::chrono::system_clock::now();
				}


				});
		}

	}


	template<typename I, typename R>
	void distribution_thread_function_v2(u64 start_w, u64 end_w, u64 n, u64 multiplier, u64 sigma,
		span<const R> count_fraction, span<R> thread_partial_counts,
		span<const R> block_enum_part,
		const ChooseCache<I>pascal_triangle) {
		assert(multiplier == 0); // TODO only block enumerator supported now
		// (non-recursive convolution not yet supported)

		std::fill(thread_partial_counts.begin(), thread_partial_counts.end(), R(0));

		//std::stringstream ss;

		// Do not use the block_enum function, but unroll the function to avoid recomputing stuff
		for (u64 w = start_w; w < end_w; ++w) {
			// precompute as much from block_enum as you can 
			// as soon as possible (a lot of it is independent of h)
			std::vector<R> block_enum_part2(block_enum_part.size());
			for (size_t q = 0; q < block_enum_part.size(); q++) {
				block_enum_part2[q] =
					block_enum_part[q] *
					labeledBallBinCap<I>(w, q, sigma, pascal_triangle);
			}

			// Handle all but last h
			u64 offset = 0;
			for (u64 h = 0; h < (thread_partial_counts.size()); ++h) {
				R enumerator = 0;
				for (size_t q = 0; q < block_enum_part2.size(); q++) {
					enumerator +=
						block_enum_part2[q] *
						choose_pascal<I>(sigma * q, offset, pascal_triangle);
				}
				// Safely update the shared thread_partial_counts[h] 
				// (one element per h) Note no need to lock it as each 
				// thread operates on different copy of thread_partial_counts

				thread_partial_counts[h] += (count_fraction[w] * enumerator);
				//ss << enumerator << " " << count_fraction[w] << " ";
				//std::cout << "w " << w << " -> " << h << ": "<< thread_partial_counts[h]<<" += " << enumerator << " * " << count_fraction[w] << " ~ ";

				//auto str = ss.str();
				//RandomOracle ro(16);
				//ro.Update((u8*)str.data(), str.size());
				//block hash;
				//ro.Final<block>(hash);
				//std::cout << hash << std::endl;

				offset += 1;
			}
			//// Handle last h separately (last h is the last point in the distribution and is not h * approximate but n
			//R enumerator = 0;
			//for (size_t q = 0; q < block_enum_part2.size(); q++) {
			//	enumerator += block_enum_part2[q] * choose_pascal<I>(sigma * q, n, pascal_triangle);
			//}

			//auto h = thread_partial_counts.size() - 1;
			//thread_partial_counts[h] += (count_fraction[w] * enumerator);
			//ss << enumerator << " " << count_fraction[w] << " ";
			//std::cout << "w " << w << " -> " << h << ": " << thread_partial_counts[h] << " += " << enumerator << " * " << count_fraction[w] << std::endl;


			loadBar.tick();
		}

	}

	// the old block enumerator.
	template<typename I, typename R>
	void blockEnumeratorOld(
		span<const  R> old_distribution,
		span<R> new_distribution,
		u64 multiplier,
		u64 n,
		u64 sigma,
		u64 num_threads,
		const ChooseCache<I>& pascal_triangle) {


		assert(old_distribution.size() == n + 1);
		assert(new_distribution.size() == n + 1);

		std::fill(new_distribution.begin(), new_distribution.end(), R(0));

		// Precompute old_distribution[w] / R(n_choose_w) so that we do only n instead of n^2 times
		auto start = std::chrono::steady_clock::now();
		std::vector<R> count_fraction(n + 1);
		for (size_t w = 0; w <= n; w++) {
			// NOTE this n_choose_w value is not recomputed each time as the function caches the values in the Pascal triangle
			count_fraction[w] = old_distribution[w] / R(choose_pascal<I>(n, w, pascal_triangle));
		}
		auto end = std::chrono::steady_clock::now();
		auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
		if (print_timings)
			std::cout << "count_fraction:" <<
			elapsed.count() << " ms" << std::endl;

		// 16 as my computer has 16 cores
		// 50 picked heuristically
		// Calculate chunk size for each thread (in terms of w)
		u64 chunk_size = new_distribution.size() / num_threads;
		// Calculate the number of counts to compute by each thread (in terms of h) - 
		// i.e. the number of points on the distribution that is exactly computed
		std::vector<std::thread> threads;
		std::vector<std::vector<R>> thread_partial_counts(num_threads, std::vector<R>(new_distribution.size()));

		// precompute as much from block_enum as you can as soon as possible (a lot of it is independent of w, h)
		start = std::chrono::steady_clock::now();
		size_t k_over_sigma = n / sigma; // note k==n at this step

		// 2^{-e sigma q} * C(k/sigma, q)
		std::vector<R> block_enum_part;

		block_enum_part.reserve(k_over_sigma + 1);
		// Precompute the base scaling factor
		I base_factor = pow2_<I>(sigma);
		//I base_factor = I(1) << sigma;
		I current_factor = 1; // Start with 1 (2^0)
		for (u64 q = 0; q <= k_over_sigma; q++) {

			//block_enum_part.emplace_back(1, current_factor);
			block_enum_part.push_back(R(1) / current_factor);

			block_enum_part[q] *= choose_pascal<I>(k_over_sigma, q, pascal_triangle);
			// Incrementally compute the next power of 2
			current_factor *= base_factor;
		}
		end = std::chrono::steady_clock::now();
		elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
		if (print_timings)
			std::cout << "block_enum_part:" <<
			elapsed.count() << " ms" << std::endl;
		// ensure sigma * q choose h is precomputed in pascal_triangle for all q, h before invoking each thread
		start = std::chrono::steady_clock::now();
		for (u64 q = 0; q <= k_over_sigma; q++) {
			u64 sigma_q = sigma * q;
			for (u64 h = 0; h < new_distribution.size(); h++) {
				choose_pascal<I>(sigma_q, h, pascal_triangle);
			}
			for (u64 i = 0; i <= q; i++) {
				choose_pascal<I>(q, i, pascal_triangle);
			}
		}
		end = std::chrono::steady_clock::now();
		elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
		if (print_timings)
			std::cout << "choose_pascal:" << elapsed.count() << " ms" << std::endl;

		start = std::chrono::steady_clock::now();
		for (int t = 0; t < num_threads; ++t) {

			u64 start_w = t * chunk_size;
			u64 end_w = (t == num_threads - 1) ? new_distribution.size() : (start_w + chunk_size);

			// Start each thread with its range of `w` and thread-specific pascal_triangle
			threads.emplace_back(
				[&, t, start_w, end_w] {
					distribution_thread_function_v2<I, R>(start_w, end_w, n, multiplier, sigma,
						count_fraction, thread_partial_counts[t], block_enum_part, pascal_triangle);
				});
		}

		// Join threads to ensure all complete
		for (auto& t : threads) {
			t.join();
		}
		end = std::chrono::steady_clock::now();
		elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
		if (print_timings)
			std::cout << "Finished multithreading:" <<
			elapsed.count() << " ms" << std::endl;

		start = std::chrono::steady_clock::now();
		// Add thread_partial_counts into new_distribution
		for (u64 t = 0; t < num_threads; ++t) {
			for (u64 i = 0; i < thread_partial_counts[t].size(); ++i) {
				new_distribution[i] += thread_partial_counts[t][i];
			}
		}

		end = std::chrono::steady_clock::now();
		elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
		if (print_timings)
			std::cout << "sum:" << elapsed.count() << " ms" << std::endl;

		if (0)
		{
			std::vector<R> temp(new_distribution.size());
			throw RTE_LOC;
			//blockEnumerator<I, R>(old_distribution, temp,
			//	n, n, sigma, num_threads, pascal_triangle);

			auto similiar = true;
			for (size_t idx = 0; idx < temp.size(); idx++) {
				if ((new_distribution[idx] - temp[idx]) != 0) {
					similiar = false;
					break;
				}
			}
			if (!similiar)
			{
				std::cout << "new_distribution vs temp : " << std::endl;
				for (size_t i = 0; i < new_distribution.size(); i++) {
					if (new_distribution[i] != temp[i])
						std::cout << Color::Red;
					std::cout << new_distribution[i] << " " << temp[i] << std::endl << Color::Default;
				}
				throw std::runtime_error("Distributions do not match");
			}
		}
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

		ChooseCache<Int> pascal_triangle;
		Rat block_enumerator = block_enum<Int, Rat>(w, h, k, n, sigma, pascal_triangle);
		std::cout << "Block Enumerator: " << block_enumerator << std::endl;
	}


	//std::vector<short> decimalToBinary_(uint64_t n, uint64_t bitsize) {
	//	assert(bitsize < 64);
	//	assert(n < (uint64_t(1) << bitsize));
	//	std::vector<short> binary(bitsize);
	//	if (n == 0) {
	//		return binary; // 0
	//	}

	//	// NOTE put in the same order as in bitset
	//	uint64_t i = 0; // bitsize-1;
	//	while (n > 0) {
	//		binary[i++] = static_cast<short>(n % 2);
	//		//binary[i--] = static_cast<short>(n % 2);
	//		n /= uint64_t(2);
	//	}
	//	return binary;
	//}


	//std::vector<std::vector<short>> genAllGs(u64 k, u64 n, u64 sigma) {
	//	u64 num_gis_in_g = k / sigma;
	//	u64 e = n / k;
	//	u64 num_elements_in_one_gi = sigma * e * sigma;
	//	// all G_is but in the same G
	//	const u64 num_elements_in_all_gis = num_gis_in_g * num_elements_in_one_gi;
	//	// 2^{k/sigma * sigma * e * sigma}
	//	assert(num_elements_in_all_gis < 64);
	//	u64 num_possibilities = u64(1) << num_elements_in_all_gis;
	//	std::vector<std::vector<short>> all_possibilities;
	//	for (size_t idx = 0; idx < num_possibilities; idx++) {
	//		all_possibilities.push_back(decimalToBinary_(idx, num_elements_in_all_gis));
	//		// std::cout << all_possibilities[idx] << std::endl;
	//	}
	//	return all_possibilities;
	//}

	inline bool increment(span<u8> bv) {
		for (size_t i = 0; i < bv.size(); ++i) {
			if (bv[i] == 0) {
				bv[i] = 1;
				return 1;
			}
			else {
				bv[i] = 0;
			}
		}

		return 0;
	}

	// print a row major represetnation of the block matrix in 
	// compact form.
	template<typename T>
	inline std::string printStans(std::vector<T>& G, u64 k, u64 n)
	{
		std::stringstream ss;
		if (G.size() % k)
			throw RTE_LOC;
		if (n % k)
			throw RTE_LOC;

		auto e = n / k;
		auto sigma = G.size() / k;

		if (G.size() != n * sigma)
			throw RTE_LOC;

		auto iter = G.begin();
		for (u64 i = 0; i < k; ++i)
		{
			auto b = i / sigma;
			auto jb = b * sigma * e;
			auto je = (b + 1) * sigma * e;

			for (u64 j = 0; j < jb; ++j)
				ss << '0' << ' ';
			for (u64 j = jb; j < je; ++j)
				ss << int(*iter++) << ' ';
			for (u64 j = je; j < n; ++j)
				ss << '0' << ' ';
			ss << std::endl;
		}
		ss << std::endl;
		return ss.str();
	}


	// we will generate all G <- D and exhaustively
	// encode all c = x G and construct the enumerator.
	// We then compare this with the formula based enumerator.
	inline void blockEnum_exhaustive_Test(const CLP& cmd)
	{
		u64 v = cmd.isSet("v");
		u64 n = cmd.getOr("n", 6);
		u64 sigma = cmd.getOr("sigma", 2); // window size
		u64 numThreads = cmd.getOr("nt", std::thread::hardware_concurrency());
		std::cout << "n: " << n << std::endl;
		std::cout << "sigma: " << sigma << std::endl;
		std::vector<Rat> actIn(n + 1);
		std::vector<Rat> actOut(n + 1);
		Matrix<Rat> actEnum(n + 1, n + 1);
		Matrix<Rat> expEnum(n + 1, n + 1);
		u64 k = n;

		if (n % sigma)
			throw RTE_LOC;
		auto q = n / sigma;


		ChooseCache<Int> pas(n);
		std::vector<u8> Gbv(n * sigma);

		using T = u8;
		if (sigma > 8)
			throw std::runtime_error("we assume sigma bits it inside a T");
		std::vector<T> Gm(n);
		Matrix<T> Xs(1ull << k, k / sigma);
		T mask = (1ull << sigma) - 1;
		for (u64 i = 0; i < Xs.rows(); ++i)
		{
			for (u64 j = 0; j < Xs.cols(); ++j)
				Xs(i, j) = (i >> (j * sigma)) & mask;
		}

		blockEnumerator<Int, Rat>(actIn, actOut, false, k, n, sigma, numThreads, pas, pas, actEnum);

		//auto Gs = old_::generate_all_gis_bool(k, n, sigma);
		u64 ii = 0;
		auto z = std::vector<u8>(n);

		do
		{
			if (v)
			{
				// convert Gbv into a sparse matrix Mtx.
				// we treat each contigous sigma-bit chunks of Gbv 
				// as a column of the matrix.
				PointList points(k, n);
				for (u64 b = 0, k = 0; b < q; ++b)
				{
					// column index
					for (u64 j = 0; j < sigma; ++j)
					{
						// row index
						for (u64 i = 0; i < sigma; ++i)
						{
							if (Gbv[k++])
							{
								points.push_back(b * sigma + i, b * sigma + j);
							}
						}
					}
				}

				SparseMtx mtx(points);
				std::cout << mtx << std::endl;
				std::cout << std::endl;
			}

			for (u64 i = 0; i < n; ++i)
			{
				Gm[i] = 0;
				for (u64 j = 0; j < sigma; ++j)
					Gm[i] |= Gbv[i * sigma + j] << j;
			}

			//std::vector<u8> bv(k);
			//std::vector<short> bv2(k);
			for (u64 x = 0; x < (1ull << k); ++x)
			{
				//for (u64 j = 0; j < k; ++j)
				//{
				//	bv[j] = (x & (1ull << j)) ? 1 : 0;
				//	//bv2[j] = bv[j];
				//}

				//auto z2 = old_::multiply_x_g_bool(bv2, Gs[ii], sigma, k, n);
				//auto z2 = std::vector<u8>(n);
				//mtx.leftMultAdd(bv, z2);

				//auto z2 = std::vector<u8>(n);
				//blockMtxMult(Gbv, bv, z2, n, k, sigma, sigma);

				blockMtxMultBit<u8>(Gm, Xs[x], z, n, k, sigma, sigma);

				//if (z != z2)
				//{

				//	//std::cout << mtx << std::endl;
				//	//std::cout << std::endl;

				//	std::cout << blockMtxToString(Gbv, n, k) << std::endl;;
				//	//std::cout << blockMtxBitToString(Gm, n, k) << std::endl;;

				//	for (u64 i = 0; i < n; ++i)
				//	{
				//		auto rev = [](auto bv) {
				//			BitVector r(bv.size());
				//			for (u64 i = 0; i < bv.size(); ++i)
				//				r[i] = bv[bv.size() - 1 - i];
				//			return r;
				//			};

				//		std::cout << rev(BitVector((u8*) & Gm[i], sigma)) << std::endl;;
				//	}

				//	std::cout << "v" << std::endl;
				//	for (u64 j = 0; j < bv.size(); ++j)
				//		std::cout << int(bv[j]) << " ";
				//	std::cout << std::endl;
				//	std::cout << "z" << std::endl;
				//	for (u64 j = 0; j < z.size(); ++j)
				//		std::cout << int(z[j]) << " ";
				//	std::cout << std::endl;
				//	std::cout << "z2" << std::endl;
				//	for (u64 j = 0; j < z2.size(); ++j)
				//		std::cout << int(z2[j]) << " ";
				//	std::cout << std::endl;

				//	//blockMtxMult(Gbv, bv, z2, n, k, sigma, sigma);
				//	//std::cout << std::endl;


				//	throw RTE_LOC;
				//}

				u64 h = 0;
				for (u64 j = 0; j < n; ++j)
				{
					h += z[j];
				}
				auto w = popcount(x);
				expEnum(w, h) += 1;
			}


			++ii;
		} while (increment(Gbv));

		for (u64 i = 0; i < expEnum.size(); ++i)
			if (expEnum(i))
				expEnum(i) = expEnum(i) / (Int(1) << Gbv.size());

		if (expEnum != actEnum)
		{
			for (u64 i = 0; i < expEnum.rows(); ++i)
			{
				for (u64 j = 0; j < expEnum.cols(); ++j)
				{
					if (expEnum(i, j) != actEnum(i, j))
					{
						std::cout << Color::Red;
					}
					std::cout << "------------" << std::endl;
					//auto old = old_::block_enum_old<Int, Rat>(i, j, k, n, sigma);
					//auto v2 = block_enum<Int,Rat>(i, j, k, n, sigma, pas);
					std::cout << "exp " << expEnum(i, j) << ", act " << actEnum(i, j) << std::endl;

					if (expEnum(i, j) != actEnum(i, j))
					{
						std::cout << Color::Default;
					}
				}
			}

			throw RTE_LOC;
		}
	}

	inline void blockEnumMain(oc::CLP& cmd) {
		//assert(ballBinCap<Int>(2, 3, 1) == 3);
		//assert(choose_<Int>(-2, 2) == 0);
		// if (cmd.isSet("enum")) {
		block_enum(cmd);
		// }
	}
}


#endif //LIBOTE_BLOCKENUMERATOR_H

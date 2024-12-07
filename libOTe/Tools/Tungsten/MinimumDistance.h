#ifndef LIBOTE_MINIMUMDISTANCE_H
#define LIBOTE_MINIMUMDISTANCE_H

#include <chrono>
#include <numeric>
#include <stdexcept>
#include <vector>

#include "BlockEnumerator.h"
#include "ExpandingBlockEnumerator.h"
#include "NonrecConvEnumerator.h"
#include "EnumeratorTools.h"
#include "RepeaterEnumerator.h"
#include "cryptoTools/Common/Matrix.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/ThreadBarrier.h"

#include <boost/multiprecision/cpp_dec_float.hpp>
#include <future>

namespace osuCrypto {
	struct LoadingBar
	{
		//std::thread thrd;
		//std::stop_source stop_source;
		u64 mWidth = 25;
		std::atomic<u64> mProgress;
		std::promise<void> mProm;
		u64 mTotal;
		std::string mMessage;
		//std::chrono::time_point<std::chrono::system_clock> mStart;
		std::mutex mLock;
		bool mPrint = true;
		bool done = false;
		void cancel()
		{
			if (!done)
				mProm.set_value();
			done = true;
		}

		void start(u64 total, std::string message)
		{
			mProgress = 0;
			mTotal = total;
			mMessage = message;
			done = false;
			//mStart = std::chrono::system_clock::now();
			mProm = std::promise<void>();
		}

		void tick(u64 delta = 1)
		{
			auto res = mProgress.fetch_add(delta, std::memory_order_relaxed);
			if (res + delta == mTotal)
			{
				done = true;
				mProm.set_value();
			}
		}

		void print()
		{
			double avgRate = -1;
			u64 lastCount = 0;
			u64 leng = 0;
			auto f = mProm.get_future();
			std::chrono::milliseconds step(1000);
			std::chrono::system_clock::time_point last = std::chrono::system_clock::now();
			f.wait_for(step);// first sleep in case its fast...
			while (f.wait_for(step) == std::future_status::timeout)
			{
				auto now = std::chrono::system_clock::now();
				auto count = mProgress.load(std::memory_order_relaxed);

				auto newCount = count - lastCount;

				if (newCount == 0)
					continue;

				// seconds since start
				auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last).count() / 1000.0;


				// ticks per sec
				auto rate = double(newCount) / elapsed;
				avgRate = avgRate < 0 ? rate : avgRate * 0.9 + rate * 0.1;

				auto rem = mTotal - count;

				// time remaining in sec
				i64 eta = rem / avgRate;

				u64 numBars = double(count) * mWidth / mTotal;
				std::stringstream ss;
				ss << "\r" << mMessage << " [" << std::string(numBars, '|') << std::string(mWidth - numBars, ' ') << "] "
					<< count << "/" << mTotal << ", rate: " << u64(avgRate) << " ticks/sec,  ETA: " << eta << " sec";
				auto str = ss.str();
				std::cout << str << std::string(std::max<i64>(leng - str.size(), 0), ' ') << std::flush;
				leng = std::max(leng, str.size());


				lastCount = count;
				last = now;
			}

			std::cout << std::string(leng, ' ') << "\r" << std::flush;
		}

	};
	static LoadingBar loadBar;
	static bool print_timings = false;

	template<typename R>
	bool compare_distributions(span<const R> distribution1,
		span<const R> distribution2,
		u64 l, double tolerance) {
		assert(distribution1.size() == l);
		assert(distribution2.size() == l);
		for (size_t idx = 0; idx < l; idx++) {
			if ((distribution1[idx] - distribution2[idx]) > tolerance) {
				return false;
			}
		}
		return true;
	}

	template<typename I, typename R>
	void compute_repeater_distribution(
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
				distribution[h] = repeater_enum<I>(w, h, k, e, pascal_triangle);
			}
			else {
				distribution[h] = I(0);
			}
		}

		/*// the method below is also correct
		for (size_t h = 0; h <= n; h++) {
			// note that for repeater, we do NOT need this loop, but used now for modularity
			// NOTE we exclude w=0 from the input x as it would always result in all zeros, so E_{w=0,h=0}=1
			// but then minimum distance would always be 0 as the distribution would be 1 in the first entry!
			// in the following iterations we care about w=0 as non-zero input could result in h=0
			for (size_t w = 1; w <= k; w++) {
				distribution[h] += repeater_enum<I>(w, h, k, e, pascal_triangle);
				assert(distribution[0] == 0);
			}
		}*/
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
	void compute_block_distribution_opt(
		span<const R> inputDist,
		span<R> outputDist,
		bool sysematic,
		u64 k,
		u64 n,
		u64 sigma,
		u64 numThreads,
		const ChooseCache<I>& pascal_triangle)
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

		auto nn = sysematic ? n - k : n;
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
					if (sysematic && w == 0)
						continue;

					for (u64 q = 0; q <= qMax; ++q)
					{
						cqw[q] = v[q] * labeledBallBinCap<I>(w, q, sigma, pascal_triangle);
					}

					auto hBegin = sysematic ? w : 0;
					for (u64 h_ = hBegin; h_ <= n; ++h_)
					{
						u64 h = sysematic ? h_ - w : h_;

						R enumerator = 0;
						for (u64 q = 0; q <= qMax; ++q)
						{
							enumerator += cqw[q] * choose_pascal<I>(e * sigma * q, h, pascal_triangle);
						}

						if (inputDist.size())
						{
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
						outputDist[h] += D(t, h);
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


		if (1)
		{


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

			//auto nn = n - k;
			//std::vector<R> distribution2(nn+1);
			//compute_block_distribution_opt<I, R>(
			//	span<R>(), distribution2, k, nn, sigma, num_threads, pascal_triangle);
			//
			//for (u64 h = 0; h <= n; h++) {

			//	// how many things have weight h?
			//	// we know the first half has inputDist[h] things with weight h
			//	// the second half has distribution2[h] things with weight h
			//	// so the total is the sum of these two
			//	distribution[h] = distribution2[h] +;
			//}

		}
		else
		{

			//auto nn = n - k;
			//if (nn % sigma)
			//	throw RTE_LOC;

			//for (int i = 0; i < num_threads; ++i) {
			//	// Start each thread with its range of `h` and thread-specific pascal_triangle
			//	threads.emplace_back(
			//		[&, i]() {
			//			// Use the thread-specific copy of pascal_triangle

			//			for (u64 h = i; h <= n; h += num_threads)
			//			{
			//				R dh(0);
			//				for (u64 w = std::max<i64>(1, h - nn); w < std::min(k + 1, h); ++w) {

			//					dh += block_enum<I, R>(w, h - w, k, nn, sigma, pascal_triangle);
			//				}
			//				R dh2(0);
			//				u64 first = -1;
			//				u64 last = -1;
			//				for (u64 w = 1; w <= k; ++w) {
			//					auto nn = n - k;
			//					if (nn % sigma)
			//						throw RTE_LOC;
			//					if (w > k)
			//						throw RTE_LOC;;

			//					if (h < w || h >(nn + w)) {
			//						return 0;
			//					}
			//					last = w;
			//					if (first == -1)
			//						first = w;
			//					dh2 += block_enum<I, R>(w, h - w, k, nn, sigma, pascal_triangle);
			//				}
			//				if (dh != dh2)
			//				{
			//					std::lock_guard l(gIoStreamMtx);
			//					std::cout << "h " << h << " dh " << dh << " dh2 " << dh2 << std::endl;
			//					std::cout << "first " << first << " last " << last << std::endl;
			//					std::cout << "first " << std::max<i64>(1, h - nn) << " last " << std::min(k + 1, h)-1 << std::endl;

			//				}

			//				distribution[h] = dh;
			//				loadBar.tick();
			//			}
			//		});
			//}

		}


		// TODO simple way to do
		/*
		// compute_block_distribution<I, R>()
		for (size_t h = 0; h <= n; h++) {
			// note that for repeater, we do NOT need this loop, but used now for modularity
			// NOTE we exclude w=0 from the input x as it would always result in all zeros, so E_{w=0,h=0}=1
			// but then minimum distance would always be 0 as the distribution would be 1 in the first entry!
			// in the following iterations we care about w=0 as non-zero input could result in h=0
			for (size_t w = 1; w <= k; w++) {
				distribution[h] += expanding_block_enum<I, R>(w, h, k, n, sigma_expander, pascal_triangle);
			}
		}*/
	}

	enum class ExpandType
	{
		Repeater,
		Block
	};

	template<typename I, typename R>
	void compute_expanding_distribution(span<R> distribution,
		ExpandType expander,
		u64 k,
		u64 n,
		u64 sigma_expander,
		const ChooseCache<I>& pascal_triangle) { // only for the expanding block
		//if (e != (n / k) < 0) {
		//    throw std::invalid_argument("e is inconsistent with k, n");
		//}
		if (expander == ExpandType::Repeater) {
			// repeater
			compute_repeater_distribution<I, R>(distribution, k, n, pascal_triangle);
		}
		else if (expander == ExpandType::Block) {
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

	template<typename I, typename R>
	void distribution_thread_function_v2(u64 start_w, u64 end_w, u64 n, u64 multiplier, u64 sigma,
		span<const R> count_fraction, span<R> thread_partial_counts,
		span<const R> block_enum_part,
		const ChooseCache<I>pascal_triangle) {
		assert(multiplier == 0); // TODO only block enumerator supported now
		// (non-recursive convolution not yet supported)

		std::fill(thread_partial_counts.begin(), thread_partial_counts.end(), R(0));

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
			for (u64 h = 0; h < (thread_partial_counts.size() - 1); ++h) {
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
				offset += 1;
			}
			// Handle last h separately (last h is the last point in the distribution and is not h * approximate but n
			R enumerator = 0;
			for (size_t q = 0; q < block_enum_part2.size(); q++) {
				enumerator += block_enum_part2[q] * choose_pascal<I>(sigma * q, n, pascal_triangle);
			}
			thread_partial_counts[thread_partial_counts.size() - 1] += (count_fraction[w] * enumerator);

			loadBar.tick();
		}
	}


	//template<typename I, typename R>
	//void distribution_thread_function_v1(u64 start_h, u64 end_h, u64 n, u64 multiplier, u64 sigma,
	//	span<const R> count_fraction, span<R> new_distribution,
	//	ChooseCache<I>pascal_triangle) {
	//	for (u64 h = start_h; h < end_h; ++h) {
	//		for (u64 w = 0; w <= n; ++w) {
	//			R enumerator = 0;
	//			if (multiplier == 0) {
	//				// Use the thread-specific copy of pascal_triangle
	//				enumerator = block_enum<I, R>(w, h, n, n, sigma, pascal_triangle);
	//			}
	//			else if (multiplier == 1) {
	//				// TODO: non-recursive convolution
	//				assert(false);
	//			}

	//			// Safely update the shared new_distribution[h] (one element per h)
	//			// Note no need to lock it as each thread operates on different unique index h in new_distribution
	//			new_distribution[h] += (count_fraction[w] * enumerator);
	//		}

	//		loadBar.tick();

	//	}
	//}

	template<typename I>
	auto pow2_(u64 power)
	{
		if constexpr (std::is_same_v<I, Int>)
		{
			//Int e = boost::multiprecision::pow(Int(2), power);
			auto r = Int(1) << power;
			//if (e != r)
			//	throw RTE_LOC;
			return r;

		}
		else if constexpr (std::is_same_v<I, Float>)
		{
			Float v(2);
			return Float(boost::multiprecision::pow(v, power));

		}
		else
		{
			static_assert(std::is_same_v<I, Int> || std::is_same_v<I, Float>);
		}
	}

	template<typename I, typename R>
	void compute_block_distribution(
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
			//compute_block_distribution_opt<I, R>(old_distribution, temp,
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

	template<typename R>
	std::vector<double> minimum_distance_from_distribution(span<R> distribution, u64 count) {
		assert(distribution.size() > 0);
		auto n = distribution.size() - 1;
		R sum = 0;
		//u64 minimum_distance = 0;
		R threshold = 1;
		std::vector<double> ret;
		for (size_t h = 0; h < n; h++) {
			;
			sum += distribution[h];
			if (sum >= threshold) {
				ret.push_back((double)h / n);
				threshold *= 2;
				if (ret.size() == count)
					break;
			}
		}
		return ret;
	}


	template<typename R>
	double minimum_distance_from_distribution(span<R> distribution)
	{
		return minimum_distance_from_distribution(distribution, 1)[0];
	}



	auto log2(const Rat& v) {
		auto f = v.convert_to<Float>();
		return boost::multiprecision::log2(f);
	}


	template<typename R>
	void print_distribution(
		span<R> D1,
		span<R> D2) {
		std::cout << "Printing  count distribution: " << std::endl;
		if (D1.size() != D2.size())
			throw RTE_LOC;
		for (u64 i = 0; i < D1.size(); ++i) {
			std::cout << Float(D1[i]) << " " << Float(D2[i]) << std::endl;
		}
		std::cout << "------------" << std::endl;
	}

	template<typename R>
	void print_distribution(
		span<R> distribution,
		u64 numPoints,
		bool normalize
	) {
		auto n = distribution.size() - 1;
		//Int total = Int(0) << n;
		R total = 0;;
		if (normalize)
		{
			std::cout << "Printing log2 probability distribution: " << std::endl;
			for (size_t i = 0; i < distribution.size(); i++) {
				total += distribution[i];
			}
		}
		else
		{
			std::cout << "Printing log2 count distribution: " << std::endl;
			total = 1;
		}

		if (numPoints == 0)
		{
			for (const auto& d : distribution) {
				std::cout << log2(d / total) << std::endl;
			}
		}
		else
		{
			for (u64 i = 0; i < numPoints; ++i)
			{
				try {

					double DS = distribution.size();
					auto IPS = static_cast<double>(i) / numPoints;// in [0,1)
					auto scaled = IPS * DS; // in [0,DS)
					u64 lowIdx = std::floor(scaled); // in [0,DS)
					u64 highIdx = std::min<u64>(std::ceil(scaled), distribution.size() - 1); // in [0,DS)

					Float DL = distribution[lowIdx] != 0 ? log2(Float(distribution[lowIdx] / total)) : -99999999999;
					Float DH = log2(Float(distribution[highIdx] / total));
					auto LDS = lowIdx / DS; // in [0,1)
					auto HDS = highIdx / DS;// in [0,1)

					Float slope = 0;
					auto d = (HDS - LDS);
					if (d)
						slope = (DH - DL) / d;

					auto diff = IPS - LDS;
					auto val = DL + diff * slope;
					try {

						std::cout << Float(val) << std::endl;
					}
					catch (...)
					{
						auto p = [](auto v) {
							std::stringstream ss;
							try {
								ss << v;
							}
							catch (...)
							{
								ss << "NaN";
							}
							return ss.str();
							};
						std::cout << p(val) << " = " << p(DL) << " + " << p(diff) << " * " << p(slope)
							<< ", DL = " << p(distribution[lowIdx]) << std::endl;
					}
				}
				catch (...)
				{
					std::cout << "error" << std::endl;
				}
			}
		}
		std::cout << "------------" << std::endl;
	}
	struct OnExit
	{
		std::function<void()> mFunc;
		~OnExit() { mFunc(); }
	};
	template<typename I, typename R>
	std::vector<R> minimum_distance(
		ExpandType et, u64 multiplier, u64 num_iters,
		u64 k, u64 n, u64 sigma, u64 sigma_expander,
		u64 approximate,
		u64 num_threads,
		bool verbose, // print the distribution
		u64 numPoints,  // number of locations to print
		bool normalizes // normalize the distribution to be a probability distribution when printing
	) {
		// TODO Assumes G's sigma is the same for all iterations (except expanding step)

		if (!sigma || !k || (!sigma_expander && et == ExpandType::Block))
			throw RTE_LOC;
		if (num_threads < 1)
			throw RTE_LOC;

		ChooseCache<I> pascal_triangle(n);

		if (n == k) throw RTE_LOC;
		if (k % sigma)
		{
			auto kk = k;
			k = divCeil(k, sigma) * sigma;
			std::cout << Color::Red << "Rounding k to the next multiple of sigma. k = " << kk << " -> " << k << std::endl << Color::Default;
		}
		if (n % k)
		{
			auto nn = n;
			n = divCeil(n, k) * k;
			std::cout << Color::Red << "rounding n to the next multiple of k. n = " << nn << " -> " << n << std::endl << Color::Default;
		}

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

		 // 2 * (n + 1) space
		Matrix<R> distributions(2, n + 1);

		loadBar.start((n + 1) * (num_iters + 1), "Computing distribution");
		std::jthread printer([] {loadBar.print(); });
		OnExit oe([&]() {loadBar.cancel(); });

		if (et == ExpandType::Repeater)
		{
			// Compute distribution for the expansion step
			// Expansion step is slightly different from the iterations
			// At the beginning there are c_w = k choose w inputs of weight w<=k
			// After expansion, c_w (for w<=n) depends on what expander we use
			compute_expanding_distribution<I, R>(
				distributions[0],
				et, k, n,
				sigma_expander, pascal_triangle);
		}
		else
		{
			compute_block_distribution_opt<I, R>(
				{}, distributions[0], 1,
				k, n, sigma_expander, num_threads,
				pascal_triangle);

		}

		//print_distribution(distributions[0]);

		// Compute distributions for iterations
		for (size_t iter = 0; iter < num_iters; iter++) {

			if (0)
			{

				compute_block_distribution<I, R>(distributions[iter % 2],
					distributions[(iter + 1) % 2],
					multiplier,
					n, sigma,
					num_threads,
					pascal_triangle);
			}
			else
			{
				compute_block_distribution_opt<I, R>(
					distributions[iter % 2],
					distributions[(iter + 1) % 2],
					false,
					n,
					n,
					sigma,
					num_threads,
					pascal_triangle);
			}
			// expand_and_interpolate(distributions[(iter + 1) % 2]);

		}

		// Now return the distribution associated with the last iteration

		// Check the sum of the final distribution is equal to the sum of the initial distribution
		R final_distribution_sum = std::reduce(distributions[num_iters % 2].begin(),
			distributions[num_iters % 2].end()); // distribution_sum<R>(distributions[num_iters % 2]);

		if constexpr (std::is_same_v<R, Float>)
		{
			if (boost::multiprecision::isinf(final_distribution_sum) ||
				boost::multiprecision::isnan(final_distribution_sum))
			{
				throw std::runtime_error("NAN final sum. " LOCATION );
			}
			else
				std::cout << "final sum " << final_distribution_sum << std::endl;
		}
		// Sum initial distribution
		R initial_distribution_sum = 0;
		for (size_t w = 1; w <= k; w++) {			
			initial_distribution_sum += R(choose_pascal<I>(k, w, pascal_triangle));
		}

		if (std::is_same_v<I, Int>)
		{

			if (initial_distribution_sum != final_distribution_sum)
			{
				std::cout << Color::Red << "Initial distribution sum: " << initial_distribution_sum << std::endl;
				std::cout << "Final distribution sum: " << final_distribution_sum << std::endl << Color::Default;
			}
		}
		else
		{
			auto ratio = initial_distribution_sum / final_distribution_sum;
			if (ratio > 1.0001 || ratio < 0.9999)
			{
				std::cout << Color::Red << "Initial distribution sum: " << initial_distribution_sum << std::endl;
				std::cout << "Final distribution sum: " << final_distribution_sum << std::endl << Color::Default;
			}
		}
		//assert(final_distribution_sum == initial_distribution_sum);
		//if (approximate == 1 && final_distribution_sum != initial_distribution_sum) throw RTE_LOC;

		auto ret = distributions[num_iters % 2];

		return { ret.begin(), ret.end() };

	}

	void benchmarks(const oc::CLP& cmd) try {

		// expander (0: repeater, 1: block expander), 
		// multiplier (0: block, 1: non recursive convolution), 
		// num_iters, k, n, sigma, sigma_expander (0 if repeater),
		// approximate - 1 if exact ie compute exactly all elements in the distribution, 2 means compute every other
		//               element in the distribution and approximate the remaining, 4 means compute every 4th element
		//               and approximate the rest

		//
		// varying iterations, everything else fixed
		//
		if (cmd.isSet("help"))
		{
			std::cout << "This function benchmarks the minimum distance computation for various parameters." << std::endl;
			std::cout << "The parameters are: " << std::endl;
			std::cout << "-repeater, " << std::endl;
			std::cout << "-iters [list int] " << std::endl;
			std::cout << "-k [list int], " << std::endl;
			std::cout << "-rate double " << std::endl;
			std::cout << "-sigmas [list int] " << std::endl;
			//std::cout << "-sigma_expander [list int] " << std::endl;
			return;
		}


		auto repeater = cmd.isSet("repeater") ? ExpandType::Repeater : ExpandType::Block;
		auto conv = cmd.isSet("conv");
		auto num_iters = cmd.getManyOr("iters", std::vector<u64>{1});
		auto Ks = cmd.getManyOr("k", std::vector<u64>{512});
		auto rate = cmd.getOr("rate", 0.5);
		auto sigmas = cmd.getManyOr("sigma", std::vector<u64>{64});
		bool verbose = cmd.isSet("verbose");
		u64 numPoints = cmd.getOr("numPoints", 0);
		bool normalizes = cmd.getOr("normalize", 1);
		u64 numMD = cmd.getOr("numMD", 10);
		u64 num_threads = cmd.getOr("threads", std::thread::hardware_concurrency());
		print_timings = verbose;
		bool print_dist = cmd.isSet("printDist") || numPoints;

		//auto sigma_expander = cmd.getManyOr("sigmaexpander", std::vector<u64>{64});
		std::vector<std::vector<u64>> params;
		for (auto i : num_iters)
		{
			for (auto k : Ks)
			{
				for (auto sigma : sigmas)
				{
					//for (auto sigma_exp : sigma_expander)
					{
#if 1
						using INT = Float;
						using RAT = Float;
#else
						using INT = Int;
						using RAT = Rat;
#endif
						u64 n = k / rate;
						auto start = std::chrono::high_resolution_clock::now();
						auto dist = minimum_distance<INT, RAT>(
							repeater, conv, i, k, n, sigma, sigma, 1,
							num_threads, verbose, numPoints, normalizes);
						auto expected_md = minimum_distance_from_distribution<RAT>(dist, numMD);
						auto end = std::chrono::high_resolution_clock::now();

						if (print_dist)
						{
							print_distribution<RAT>(dist, numPoints, normalizes);
						}

						std::cout << "k: " << k << " n: " << n << " sigma: " << sigma << " iters: " << i << " rate: " << rate << " time: " << std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count() << "ms" << std::endl;

						for (auto e : expected_md)
							std::cout << e << " ";
						std::cout << std::endl;
					}
				}
			}
		}
	}
	catch (std::exception& e) {
		std::cout << e.what() << std::endl;
	}

	inline void minimumDistanceMain(oc::CLP& cmd)
	{
		benchmarks(cmd);
		return;
	}
}

#endif //LIBOTE_MINIMUMDISTANCE_H

#pragma once

#include "EnumeratorTools.h"
#include "Enumerator.h"
#include "cryptoTools/Common/Matrix.h"
#include <iostream>
#include "cryptoTools/Common/ThreadBarrier.h"
#include "Print.h"
#include "LoadingBar.h"
#include "libOTe/Tools/LDPC/Mtx.h"
//#include "oldMinDistTest.h"
#include "cryptoTools/Common/BitVector.h"

namespace osuCrypto {

	template<typename I, typename R>
	struct BlockEnumerator : Enumerator<R>
	{
		using Enumerator<R>::mK;
		using Enumerator<R>::mN;

		u64 mSigma = 0;
		u64 mNumThreads = 0;
		bool mSystematic = false;
		const ChooseCache<I>& mChoose;
		const ChooseCache<Int>& mChoose2;


		void enumerate(
			span<const R> inDist,
			span<R> outDist) override
		{
			enumerate(inDist, outDist, mSystematic,
				mK, mN, mSigma, mNumThreads, mChoose, mChoose2);
		}

		void enumerate(
			span<const R> inDist,
			span<R> outDist,
			MatrixView<R> full) override
		{
			enumerate(inDist, outDist, mSystematic,
				mK, mN, mSigma, mNumThreads, mChoose, mChoose2, full);
		}


		static R enumerate(
			u64 w, u64 h, 
			u64 k, u64 n, u64 sigma, 
			const ChooseCache<I>& pascal_triangle)
		{
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
		template<typename Full = int>
		static void enumerate(
			span<const R> inputDist,
			span<R> outputDist,
			bool systematic,
			u64 k,
			u64 n,
			u64 sigma,
			u64 numThreads,
			const ChooseCache<I>& pascal_triangle,
			const ChooseCache<Int>& pascal_triangle2,
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

			// special case the zero weight input.
			if constexpr (std::is_same_v<Full, int> == false)
				full(0, 0) = 1;
			outputDist[0] = inputDist.size() ? inputDist[0] : 1;

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
						if (w == 0)
							continue;

						for (u64 q = 0; q <= qMax; ++q)
						{
							cqw[q] = v[q] * labeledBallBinCap(w, q, sigma, pascal_triangle2).convert_to<I>();
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

	};


	// we will generate all G <- D and exhaustively
	// encode all c = x G and construct the enumerator.
	// We then compare this with the formula based enumerator.
	void blockEnum_exhaustive_Test(const CLP& cmd);

}



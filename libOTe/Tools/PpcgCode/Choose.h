
#pragma once
#include "cryptoTools/Common/Defines.h"
#include <vector>
#include "LoadingBar.h"
#include <mutex>
#include "cryptoTools/Common/Log.h"

namespace osuCrypto
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


	// Computes n choose k using an efficient iterative approach.
	// This avoids computing factorials directly, which can grow very large and cause overflow.
	template <typename T>
	inline T choose_iterative(i64 n, i64 k)
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
	struct Choose
	{
		// the upper bound of the cache size.
		u64 mN = 0;
		T mZero = 0, mOne = 1;

		Choose() = default;
		Choose(u64 n, LoadingBar* loadingBar = nullptr)
		{
			precompute(n, loadingBar);
		}
		std::vector<std::vector<T>> mRec, mStack;


		static u64 numTicks(u64 n)
		{
			return n / 2 + 1;
		}

		void precompute(u64 n, LoadingBar* loadingBar = nullptr)
		{
			mN = n;
			if (loadingBar)
				loadingBar->name("ChooseCache");
			for (u64 i = 0; i <= (n / 2); ++i)
			{
				choose_pascal_stack(n, i);
				if (loadingBar)
					loadingBar->tick();
			}
		}

		const T& operator()(u64 n, u64 k) const
		{

			if (i64(n) < 0 || k > n) return mZero;
			if (k == 0 || k == n) return mOne;
			k = std::min(k, n - k);

			if (mStack.size() > n && mStack[n].size() > k && mStack[n][k] != -1)
			{
				return mStack[n][k];
			}
			else
			{
				std::lock_guard l(gIoStreamMtx);
				std::cout << "missing n " << n << " k " << k << std::endl;
				std::cout << "size()  " << mStack.size() << std::endl;
				if (mStack.size() > n)
				{
					if (mStack[n].size() > k)
					{
						std::cout << "val " << mStack[n][k] << std::endl;
					}
					else
						std::cout << "bad k" << std::endl;
				}
				else
					std::cout << "bad n" << std::endl;

				throw RTE_LOC;
			}

		}

		/*
		NEW BINOMIAL COEFFICIENT FUNCTION BASED ON PASCAL'S TRIANGLE WITH CACHING ACROSS CALLS

		Cache: The function uses a cache, which is a std::vector of std::vector<T>, to store previously computed values of the binomial coefficient "n choose k." The cache allows the function to avoid recomputation by storing results of binomial coefficient calculations, which can be reused in future calls. The value -1 is used to denote uncomputed values within the cache.

		Dynamic Resizing: To handle any input values of "n" and "k," the function dynamically resizes the cache. If the cache has fewer rows than needed for the requested "n," it resizes to accommodate up to row "n." Similarly, if row "n" has fewer columns than required for "k," it resizes that row up to column "k." This dynamic resizing ensures that the cache can store values up to the requested "n" and "k," allowing the function to retain previously computed results.

		Symmetry Optimization: The function takes advantage of the symmetry of binomial coefficients, where "n choose k" is the same as "n choose (n - k)." By setting "k" to min(k, n - k), the function minimizes the number of multiplications needed, reducing computation time.

		Checking Cache: After resizing, the function first checks whether the required value "n choose k" is already in the cache. If the cache contains a previously computed value, the function simply returns it immediately, saving time and resources.

		1D Row Calculation: The function calculates Pascal’s Triangle values up to the "n-th" row using a single row vector of size "k + 1." Each element row[h] represents the binomial coefficient for the current row "w choose h." For each row "w," it updates row[h] from right to left (starting from min(w, k) down to 1). This update pattern ensures that each row[h] value is based on the values from the previous row of Pascal’s Triangle, but only one row is stored at a time, making the calculation efficient in terms of memory.

		Cache Storage: After calculating the desired binomial coefficient, the function stores this value in cache[n][k] before returning it. Storing the value allows any future requests for "n choose k" to retrieve the result directly from the cache, avoiding recomputation.

		This function is optimized for efficiency by using caching, symmetry reduction, and a dynamic programming approach with a 1D row calculation based on Pascal’s Triangle. It is suitable for computing binomial coefficients with moderate values of "n" and "k" and can handle repeated calls efficiently due to caching.
		*/
		T choose_pascal_recursive(int64_t n, int64_t k) {
			if (k < 0 || k > n)
				return 0;
			if (k == 0 || k == n)
				return 1;

			// Reduce the number of calculations by using symmetry: C(n, k) = C(n, n - k)
			if (k > n - k)
				k = n - k;

			// Resize the mRec if necessary
			if (mRec.size() <= n) {
				mRec.resize(n + 1);
			}

			// Resize the specific row if necessary
			if (mRec[n].size() <= k) {
				mRec[n].resize(k + 1, -1); // Use -1 to denote uncomputed values
			}

			// Return mRecd value if it exists
			if (mRec[n][k] != -1) return mRec[n][k];

			// Option 1
			// computes unnecessary values in a row even if just one k for n is needed
			// does not mRec intermediate rows
			/*
			// Use a 1D vector to store the current row of Pascal's Triangle
			std::vector<T> row(k + 1, 0);
			row[0] = 1; // C(n, 0) is always 1

			// Build up Pascal's Triangle up to the nth row
			for (int64_t w = 1; w <= n; ++w) {
				// Update row from the end to the beginning to use only one array
				for (int64_t h = std::min(w, k); h > 0; --h) {
					row[h] += row[h - 1];
				}
			}

			// Store the result in the mRec before returning
			mRec[n][k] = row[k];
			return row[k];
			*/
			// Option 2: avoids the issues in the first option
			// Recursive computation: C(n, k) = C(n-1, k-1) + C(n-1, k)
			mRec[n][k] =
				choose_pascal_recursive(n - 1, k - 1) +
				choose_pascal_recursive(n - 1, k);
			return mRec[n][k];
		}



		const T& choose_pascal_stack(int64_t n_, int64_t k_) {

			auto& cache = mStack;
			auto C = [this, &cache](u64 n, u64 k) -> T& {
				if (k == 0 || k == n)
					return mOne;
				if (k > n || n == 0)
					return mZero;

				// Reduce the number of calculations by using symmetry: C(n, k) = C(n, n - k)
				if (k > n - k)
					k = n - k;

				// Resize the cache if necessary
				if (cache.size() <= n) {
					auto oldSize = cache.size();
					cache.resize(n + 1);
					for (u64 nn = oldSize; nn <= n; ++nn)
					{
						cache[nn].resize(nn / 2 + 1, -1);
					}
				}

				// Resize the specific row if necessary
				//if (cache[n].size() <= k) {
				//	cache[n].resize(k + 1, -1); // Use -1 to denote uncomputed values
				//}

				// Return cached value if it exists
				//if (cache[n][k] != -1) 
				return cache[n][k];

				};

			k_ = std::min(k_, n_ - k_);
			auto& res = C(n_, k_);
			if (res == -1)
			{
				std::vector<std::pair<u64, u64>> NKStack{ {n_, k_} };
				while (NKStack.size())
				{
					auto [n, k] = NKStack.back();
					// Option 1
					// computes unnecessary values in a row even if just one k for n is needed
					// does not cache intermediate rows
					/*
					// Use a 1D vector to store the current row of Pascal's Triangle
					std::vector<T> row(k + 1, 0);
					row[0] = 1; // C(n, 0) is always 1

					// Build up Pascal's Triangle up to the nth row
					for (int64_t w = 1; w <= n; ++w) {
						// Update row from the end to the beginning to use only one array
						for (int64_t h = std::min(w, k); h > 0; --h) {
							row[h] += row[h - 1];
						}
					}

					// Store the result in the cache before returning
					cache[n][k] = row[k];
					return row[k];
					*/
					// Option 2: avoids the issues in the first option
					// Recursive computation: C(n, k) = C(n-1, k-1) + C(n-1, k)
					auto v0 = C(n - 1, k - 1);
					if (v0 == -1)
					{
						NKStack.emplace_back(n - 1, k - 1);
						continue;
					}

					auto v1 = C(n - 1, k);
					if (v1 == -1)
					{
						NKStack.emplace_back(n - 1, k);
						continue;
					}

					NKStack.pop_back();

					auto kk = std::min(k, n - k);
					cache[n][kk] = v0 + v1;
				}

				assert(&res == &cache[n_][k_]);
				//C(n_, k_);
			}

			assert(res != -1);

			//auto exp = choose_pascal_recursive(n_, k_);;
			//if (exp != res)
			//	throw RTE_LOC;

			return res;
		}

	};


	//template <typename T>
	//const T& choose_pascal(int64_t n, int64_t k, const Choose<T>& cache) {
	//	return cache(n, k);
	//}

	//template <typename T>
	//const T& choose_pascal(int64_t n, int64_t k, Choose<T>& cache) {
	//	auto& v1 = cache.choose_pascal_stack(n, k);

	//	if (0 && n < 1000)
	//	{

	//		auto v0 = cache.choose_pascal_recursive(n, k);

	//		if (v0 != v1 /*|| cache.mRec != cache.mStack*/)
	//		{
	//			std::lock_guard l(gIoStreamMtx);
	//			std::cout << "n  " << n << std::endl;
	//			std::cout << "k  " << k << std::endl;
	//			std::cout << "v0 " << v0 << std::endl;
	//			std::cout << "v1 " << v1 << std::endl;

	//			for (auto r : cache.mRec)
	//			{
	//				std::cout << "[";
	//				for (auto c : r)
	//				{
	//					std::cout << c << " ";
	//				}
	//				std::cout << "]" << std::endl;
	//			}
	//			std::cout << std::endl;

	//			for (auto r : cache.mStack)
	//			{
	//				std::cout << "[";
	//				for (auto c : r)
	//				{
	//					std::cout << c << " ";
	//				}
	//				std::cout << "]" << std::endl;
	//			}

	//			throw RTE_LOC;
	//		}

	//	}
	//	return v1;
	//}

}
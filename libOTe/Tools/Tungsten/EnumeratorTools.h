// balls into bins, balls into bins with capacity, etc.

#pragma once
#include "cryptoTools/Common/TestCollection.h"
#include "cryptoTools/Common/Defines.h"
#include <vector>
#include <unordered_map>
#include "cryptoTools/Common/CLP.h"
#include "cryptoTools/Common/Log.h"

#ifdef ENABLE_BOOST
#include <boost/multiprecision/cpp_bin_float.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#ifdef ENABLE_GMP
#include <boost/multiprecision/gmp.hpp>
#include "gmp.h"
#include "gmpxx.h"
#endif

namespace osuCrypto {
	template<typename T, typename R>
	T to(const R&);

	template<typename T>
	T pow2(u64 pow);

	template<typename T>
	struct RationalOf;

	template<typename T>
	T fact(u64 n);


	template <typename T>
	inline T choose(i64 n, i64 k);

	//using MPZ = mpz_class;
//#define MPZ_ENABLE
#ifdef MPZ_ENABLE
	struct MPZ
	{
		mpz_class mVal;

		MPZ() = default;
		MPZ(const MPZ&) = default;
		MPZ(MPZ&&) = default;
		MPZ& operator=(const MPZ&) = default;
		MPZ& operator=(MPZ&&) = default;

		MPZ(i64 u)
		{

#ifdef _MSC_VER
			u64 v = u < 0 ? -u : u;
			if (v >> 32)
			{
				mVal = ((u32*)&v)[1];
				mVal <<= 32;
			}
			mVal += ((u32*)&v)[0];
			if (u < 0)
				mVal = -mVal;
#else
			mVal = u;
#endif
		}


		bool operator>=(i32 v) const
		{
			return mVal >= v;
		}



		MPZ& operator*=(const MPZ& v)
		{
			mVal *= v.mVal;
			return *this;
		}

		MPZ& operator*=(i64 v)
		{
			if (u64(v) >> 32)
			{
				*this *= MPZ(v);
			}
			else
			{
				mVal *= (i32)v;
			}
			return *this;
		}

		MPZ operator*(const MPZ& v)
		{
			auto r = *this;
			r *= v;
			return r;
		}

		bool operator==(const MPZ& v) const
		{
			return mVal == v.mVal;
		}


		MPZ& operator+=(const MPZ& v)
		{
			mVal += v.mVal;
			return *this;
		}

		MPZ exactDiv(const i64& v) const
		{
			if (v < 0)
				throw RTE_LOC;

			MPZ r;
			if (u64(v) >> 32 && sizeof(unsigned long) < 8)
			{
				MPZ zz(v);
				mpz_divexact(r.mVal.get_mpz_t(), mVal.get_mpz_t(), zz.mVal.get_mpz_t());
			}
			else
			{
				mpz_divexact_ui(r.mVal.get_mpz_t(), mVal.get_mpz_t(), (unsigned long)v);
			}

			assert(r * v == *this);

			return r;
		}


		MPZ& operator/=(const MPZ& v)
		{
			mVal /= v.mVal;
			return *this;
		}

		operator mpz_ptr()
		{
			return mVal.get_mpz_t();
		}

	};

	struct MPQ
	{
		mpq_class mVal;


		MPQ() = default;
		MPQ(const MPQ&) = default;
		MPQ(MPQ&&) = default;
		MPQ& operator=(const MPQ&) = default;
		MPQ& operator=(MPQ&&) = default;

		MPQ(u32 n, u32 d = 1)
		{
			mpq_set_ui(mVal.get_mpq_t(), n, d);
		}


		MPQ& operator+=(const MPQ& q)
		{
			mVal += q.mVal;
			return *this;
		}

		operator mpq_ptr()
		{
			return mVal.get_mpq_t();
		}
	};


	template<>
	MPZ to<MPZ, MPQ>(const MPQ& v)
	{
		MPZ r; r.mVal = v.mVal.get_num();
		MPZ d; d.mVal = v.mVal.get_den();
		r /= d;
		return r;
	}
	double log2(MPZ x) {
		signed long int ex;
		const double di = mpz_get_d_2exp(&ex, x.mVal.get_mpz_t());
		return log(di) + log(2) * (double)ex;
	}

	inline std::ostream& operator<<(std::ostream& o, const MPZ& v)
	{
		o << v.mVal;
		return o;
	}

	template<>
	inline MPZ pow2<MPZ>(u64 pow)
	{
		MPZ r;
		r = 1;
		if (pow >> 32)
			throw RTE_LOC;
		mpz_ui_pow_ui(r.mVal.get_mpz_t(), 2, pow);
		//r.mVal =<< (u32)pow;
		return r;
	}

	// returns z/2^power.
	MPQ divPow2(const MPZ& v, u64 power)
	{
		MPQ vv;
		mpq_set_num(vv, v.mVal.get_mpz_t());
		mpq_set_den(vv, pow2<MPZ>(power).mVal.get_mpz_t());
		mpq_canonicalize(vv);
		return vv;
	}

	template<>
	struct RationalOf<MPZ>
	{
		using type = MPQ;
	};


	template<>
	MPZ fact<MPZ>(u64 n)
	{
		MPZ v = 1;
		for (u64 i = 2; i <= n; ++i)
			v *= i;
		return v;
	}



	template <>
	inline MPZ choose_<MPZ>(i64 n, i64 k)
	{
		//mpz_fac_ui
		//choozeZ()
		if (n < 0 || k < 0)
			return 0;
		if (k > n)
			return 0;
		if (k == 0 || k == n)
			return 1;

		if (n - k < k)
			return choose(n, n - k);

		MPZ r = (n - k + 1);
		for (u64 i = 2; i <= k; ++i)
		{
			r *= (n - k + i);
			r = r.exactDiv(i);
		}
		return r;
	}

#endif

	//using Float = boost::multiprecision::cpp_bin_float_double;
	using Float = boost::multiprecision::cpp_bin_float_quad;
	//using Float = boost::multiprecision::cpp_bin_float_oct;
#ifdef ENABLE_GMP
	using Int = boost::multiprecision::mpz_int;
	using Rat = boost::multiprecision::mpq_rational;
#else

	using Int = boost::multiprecision::cpp_int;
	using Rat = boost::multiprecision::cpp_rational;

#endif
	template<>
	Float to<Float, Float>(const Float& v)
	{
		return v;
	}

	template<>
	Int to<Int, Rat>(const Rat& v)
	{
		return v.convert_to<Int>();
	}

	// returns z/2^power.
	Float divPow2(const Float& v, u64 power)
	{
		return v / pow(Float(v), power);
	}

	Rat divPow2(const Int& v, u64 power)
	{
		Rat vv(v, Int(1) << power);
		//mpq_set_num(vv, v.mVal.get_mpz_t());
		//mpq_set_den(vv, pow2<MPZ>(power).mVal.get_mpz_t());
		//mpq_canonicalize(vv);
		vv = vv.canonical_value(vv);
		return vv;
	}


	//using Number = MPZ;

	template<>
	struct RationalOf<Float>
	{
		using type = Float;
	};

	template<>
	struct RationalOf<Int>
	{
		using type = Rat;
	};


	template<>
	Float fact<Float>(u64 n)
	{
		Float v = 1;
		for (u64 i = 2; i <= n; ++i)
			v *= i;
		return v;
	}

	template<>
	Int fact<Int>(u64 n)
	{
		Int v = 1;
		for (u64 i = 2; i <= n; ++i)
			v *= i;
		return v;
	}

	u64 log2floor(Int x)
	{
		u64 r = 0;
		while (x >= 2)
		{
			++r;
			x /= 2;
		}
		return r;
	}

	u64 log2ceil(Int x)
	{
		auto r = log2floor(x);
		if ((Int(1) << r) != x)
			++r;
		return r;
	}

	double log2(Int x) {

		if (x == 0)
		{
			return log(0);
		}
#ifdef ENABLE_GMP
		signed long int ex;
		const double di = mpz_get_d_2exp(&ex, x.backend().data());
		auto ret = log(di) / log(2) + (double)ex;
		if (log2ceil(x) < ret || log2floor(x) > ret)
		{
			std::cout << "bad log   " << x << std::endl;
			std::cout << "log floor " << log2floor(x) << std::endl;
			std::cout << "log ceil  " << log2ceil(x) << std::endl;
			throw RTE_LOC;
		}
		return ret;
#else
		double v = 0;
		while (x >= 2)
		{
			x /= 2;
			v += 1;
		}
		//std::cout << "rem " << x << std::endl;
		if (x > 0)
		{
			i64 r = x.convert_to<i64>();
			//std::cout << r << std::endl;
			v += ::log2(double(r));
		}
		return v;
#endif

	}


	inline Float stirlingApprox(u64 n)
	{
		if (n == 0)
			return 1;

		static Float pi = 3.141592653589793238462643383279502884197;
		auto v = sqrt(2 * pi * n) * pow(n / exp(Float(1)), n);
		//auto expansion_ =
		//    double(1) +
		//    double(1) / (12 * n) +
		//    double(1) / (228 * std::pow(n, 2)) +
		//    double(139) / (51840 * std::pow(n, 3)) +
		//    double(571) / (3488320 * std::pow(n, 4));

		std::array<Float, 16> dom{ {
										   1, 1, -139, -571, 163879, 5246819,
										   Float("-534703531"), Float("-4483131259"), Float("432261921612371"), Float("6232523202521089"), Float("-25834629665134204969.0"),
										   Float("-1579029138854919086429.0"), Float("746590869962651602203151.0"),Float("1511513601028097903631961.0"), Float("-8849272268392873147705987190261.0"),  Float("-142801712490607530608130701097701.0")
								   } };

		std::array<Float, 16> num{ {
										   12, 288, 51840, 2488320, 209018880,
										   Float("75246796800"), Float("902961561600"), Float("86684309913600"), Float("514904800886784000"), Float("86504006548979712000.0"),
										   Float("13494625021640835072000"), Float("9716130015581401251840000"), Float("116593560186976815022080000"), Float("2798245444487443560529920000"), Float("299692087104605205332754432000000"),
										   Float("57540880724084199423888850944000000") } };
		auto expansion = Float(1);
		for (u64 i = 0; i < 14; ++i)
			expansion += dom[i] / (num[i] * pow(Float(n), Float(i + 1)));
		return v * expansion;
	}

	// approximation of the binomial coefficient using logarithmic properties
	Float chooseApx(i64 n, i64 k)
	{
		if (k < 0 || k > n)
			return 0;
		if (k == 0 || k == n)
			return 1;
		auto b = (n - k) * log(Float(n) / (n - k)) + k * log(Float(n) / k);
		return exp(b);
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
	struct ChooseCache
	{
		T mZero = 0, mOne = 1;

		ChooseCache() = default;	
		ChooseCache(u64 n)
		{
			precompute(n);
		}
		std::vector<std::vector<T>> mRec, mStack;


		void precompute(u64 n)
		{
			for (u64 i = 0; i <= (n / 2); ++i)
			{
				choose_pascal_stack(n, i);
			}
		}


		/*
		NEW BINOMIAL COEFFICIENT FUNCTION BASED ON PASCAL'S TRIANGLE WITH CACHING ACROSS CALLS

		Cache: The function uses a cache, which is a std::vector of std::vector<T>, to store previously computed values of the binomial coefficient "n choose k." The cache allows the function to avoid recomputation by storing results of binomial coefficient calculations, which can be reused in future calls. The value -1 is used to denote uncomputed values within the cache.

		Dynamic Resizing: To handle any input values of "n" and "k," the function dynamically resizes the cache. If the cache has fewer rows than needed for the requested "n," it resizes to accommodate up to row "n." Similarly, if row "n" has fewer columns than required for "k," it resizes that row up to column "k." This dynamic resizing ensures that the cache can store values up to the requested "n" and "k," allowing the function to retain previously computed results.

		Symmetry Optimization: The function takes advantage of the symmetry of binomial coefficients, where "n choose k" is the same as "n choose (n - k)." By setting "k" to min(k, n - k), the function minimizes the number of multiplications needed, reducing computation time.

		Checking Cache: After resizing, the function first checks whether the required value "n choose k" is already in the cache. If the cache contains a previously computed value, the function simply returns it immediately, saving time and resources.

		1D Row Calculation: The function calculates Pascal’s Triangle values up to the "n-th" row using a single row vector of size "k + 1." Each element row[j] represents the binomial coefficient for the current row "i choose j." For each row "i," it updates row[j] from right to left (starting from min(i, k) down to 1). This update pattern ensures that each row[j] value is based on the values from the previous row of Pascal’s Triangle, but only one row is stored at a time, making the calculation efficient in terms of memory.

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
			for (int64_t i = 1; i <= n; ++i) {
				// Update row from the end to the beginning to use only one array
				for (int64_t j = std::min(i, k); j > 0; --j) {
					row[j] += row[j - 1];
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
					for (int64_t i = 1; i <= n; ++i) {
						// Update row from the end to the beginning to use only one array
						for (int64_t j = std::min(i, k); j > 0; --j) {
							row[j] += row[j - 1];
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


	template <typename T>
	const T& choose_pascal(int64_t n, int64_t k, const ChooseCache<T>& cache) {

		if (k > n) return cache.mZero;
		if (k == 0 || k == n) return cache.mOne;
		k = std::min(k, n - k);

		if (cache.mStack.size() > n && cache.mStack[n].size() > k && cache.mStack[n][k] != -1)
		{
			return cache.mStack[n][k];
		}
		else
		{
			std::lock_guard l(gIoStreamMtx);
			std::cout << "missing n " << n << " k " << k << std::endl;
			std::cout << "cache.size()  " << cache.mStack.size() << std::endl;
			if (cache.mStack.size() > n)
			{
				if (cache.mStack[n].size() > k)
				{
					std::cout << "val " << cache.mStack[n][k] << std::endl;
				}
				else
					std::cout << "bad k" << std::endl;
			}
			else
				std::cout << "bad n" << std::endl;

			throw RTE_LOC;
		}
	}

	template <typename T>
	const T& choose_pascal(int64_t n, int64_t k, ChooseCache<T>& cache) {
		auto& v1 = cache.choose_pascal_stack(n, k);

		if (0 && n < 1000)
		{

			auto v0 = cache.choose_pascal_recursive(n, k);

			if (v0 != v1 /*|| cache.mRec != cache.mStack*/)
			{
				std::lock_guard l(gIoStreamMtx);
				std::cout << "n  " << n << std::endl;
				std::cout << "k  " << k << std::endl;
				std::cout << "v0 " << v0 << std::endl;
				std::cout << "v1 " << v1 << std::endl;

				for (auto r : cache.mRec)
				{
					std::cout << "[";
					for (auto c : r)
					{
						std::cout << c << " ";
					}
					std::cout << "]" << std::endl;
				}
				std::cout << std::endl;

				for (auto r : cache.mStack)
				{
					std::cout << "[";
					for (auto c : r)
					{
						std::cout << c << " ";
					}
					std::cout << "]" << std::endl;
				}

				throw RTE_LOC;
			}

		}
		return v1;
	}

	inline Int ballBinCapX(u64 balls, u64 bins, u64 cap, std::vector<u64>& stack)
	{
		if (balls > bins * cap)
		{
			return 0;

		}
		//if (n == k * cap)
		//{
		//
		//    return 1;
		//}
		if (balls == 0)
		{
			//print(stack);
			return 1;
		}
		if (bins == 1)
		{
			if (balls <= cap)
			{
				stack.push_back(balls);
				//print(stack);
				stack.pop_back();
				return 1;
			}
			else
				return 0;
		}

		Int r = 0;

		for (u64 i = 0; i <= cap; ++i)
		{
			if (balls >= i)
			{
				stack.push_back(i);
				r += ballBinCapX(balls - i, bins - 1, cap, stack);
				stack.pop_back();
			}
		}
		return r;
	}

	inline Int ballBinCapX(u64 balls, u64 bins, u64 cap)
	{
		std::vector<u64> stack;
		return ballBinCapX(balls, bins, cap, stack);
	}


	//
	template<typename T>
	inline T labeledBallBinCap(u64 balls, u64 bins, u64 cap, const ChooseCache<T>& pascal_triangle) {
		T d = 0;
		for (u64 i = 0; i <= bins; ++i) {
			//T v = (i & 1) ? -1 : 1;
			auto mt = choose_pascal<T>(bins, i, pascal_triangle);

			i64 bb = cap * (bins - i64(i));
			if (bb < balls || bb < 0) {
				break;
			}

			auto r = choose_pascal<T>(bb, balls, pascal_triangle);
			//std::cout << i << " r " << r << " = C(" << bb << ", " << bins-1 << ")" << std::endl;

			//if (mt != mt)
			//    throw RTE_LOC;
			//if (r != r)
			//    throw RTE_LOC;
			if (i & 1)
				d -= mt * r;
			else
				d += mt * r;
			//std::cout << i << " d " << d << std::endl;
		}
		return d;
	}



	//// for fixed number of balls and capcity, iterate over all possible bin counts
	//// and output the balls into bins with capacity.
	//template<typename T>
	//struct BallBinCapIter
	//{
	//	T mCurrent;
	//	u64 mBalls = 0, mBins = 0, mCap = 0;
	//	BallBinCapIter() = default;
	//	BallBinCapIter(u64 balls, u64 intialBins, u64 cap)
	//		: mBalls(balls)
	//		, mBins(intialBins)
	//		, mCap(cap)
	//	{
	//		mCurrent = labeledBallBinCap(mBalls, mBins, mCap);
	//	}

	//	const T& operator->() const
	//	{
	//		return mCurrent;
	//	}

	//	void operator++()
	//	{
	//		auto i = ++mBins;
	//		T nextTerm = i&1 ? -1 : 1;
	//		nextTerm *= choose_pascal<T>(mBins, 0);

	//		auto exp = labeledBallBinCap(mBalls, mBins, mCap);
	//	}


	//};

	/* template<typename T>
	 inline T labeledBallBinCap(u64 balls, u64 bins, u64 cap) {
		 if (balls == 0)
			 return 1;

		 //if (balls * 2 > bins * cap)
		 //    balls = bins * cap - balls;

		 if (balls < bins * cap)
		 {

			 T d = 0;
			 for (u64 i = 0; i < bins; ++i)
			 {
				 T v = (i & 1) ? -1 : 1;
				 auto mt = choose_<T>(bins, i);

				 //std::cout << i << " mt " << mt << " = C("<< bins<<", " << i << ")" << std::endl;

				 i64 bb = cap * (bins - i64(i));
				 if (bb < balls || bb < 0)
					 break;

				 auto r = choose_<T>(bb, balls);
				 //std::cout << i << " r " << r << " = C(" << bb << ", " << bins-1 << ")" << std::endl;

				 //if (mt != mt)
				 //    throw RTE_LOC;
				 //if (r != r)
				 //    throw RTE_LOC;
				 d += v * mt * r;
				 //std::cout << i << " d " << d << std::endl;
			 }
			 return d;
		 }
		 else if (balls == bins * cap)
			 return 1;
		 else
			 return 0;
	 }*/


	 // TODO note this function is likely buggy
	template<typename T>
	inline T ballBinCap(u64 balls, u64 bins, u64 cap, ChooseCache<T>& pascal_triangle)
	{
		// TODO the special cases eg balls=0 are probably buggy, or at least they were in labeledballbincap
		std::cout << "debug before using" << std::endl;
		assert(false);
		if (balls == 0)
			return 1;

		if (balls * 2 > bins * cap)
			balls = bins * cap - balls;

		if (balls < bins * cap)
		{

			T d = 0;
			for (u64 i = 0; i < bins; ++i)
			{
				T v = (i & 1) ? -1 : 1;
				auto mt = choose_pascal<T>(bins, i, pascal_triangle);

				//std::cout << i << " mt " << mt << " = C("<< bins<<", " << i << ")" << std::endl;

				i64 bb = bins + balls - i64(i) * (cap + 1) - 1;
				if (bb < bins - 1 || bb < 0)
					break;

				auto r = choose_pascal<T>(bb, bins - 1, pascal_triangle);
				//std::cout << i << " r " << r << " = C(" << bb << ", " << bins-1 << ")" << std::endl;

				if (mt != mt)
					throw RTE_LOC;
				if (r != r)
					throw RTE_LOC;
				d += v * mt * r;
				//std::cout << i << " d " << d << std::endl;
			}
			return d;
		}
		else if (balls == bins * cap)
			return 1;
		else
			return 0;
	}

	inline void stirlingMain(CLP& cmd)
	{
		u64 n = cmd.getOr("n", 10);
		for (u64 i = 0; i < n; ++i)
		{
			auto I = fact<Int>(i);
			auto F = fact<Float>(i);
			auto S = stirlingApprox(i);

			std::cout << "n " << i << ": "
#ifdef MPZ_ENABLE
				<< fact<MPZ>(i) << " "
#endif
				<< I << " "
				//<< F << " "
				//<< S << " "
				<< (I - F.convert_to<Int>()).convert_to<Float>() / I.convert_to<Float>() << " "
				<< (I - S.convert_to<Int>()).convert_to<Float>() / I.convert_to<Float>()
				<< std::endl;
		}
	}


	inline void chooseMain(oc::CLP cmd)
	{

		auto n = cmd.getManyOr<u64>("n", { 10 });
		auto k = cmd.getManyOr<u64>("k", { 10 });
		ChooseCache<Float> fc;
		ChooseCache<Int> ic;

		for (auto nn : n)
		{
			for (auto kk : k)
			{
				std::cout << "n " << nn << " k " << kk << " : f ";
				auto f = choose_pascal<Float>(nn, kk, fc);
				auto fl = log2(f);
				std::cout << fl << " ~ i ";

				auto z = choose_pascal<Int>(nn, kk, ic);
				auto zl = log2(z);
				std::cout << zl << " @ ";
#ifdef MPZ_ENABLE
#endif
			}
			std::cout << std::endl;
		}
	}

	inline void ballBinCapMain(oc::CLP cmd)
	{
		auto balls = cmd.getManyOr<u64>("n", { 10 });
		auto bins = cmd.getManyOr<u64>("m", { 10 });
		u64 cap = cmd.getOr("c", 12);

		ChooseCache<Float> fc;
		ChooseCache<Int> ic;
		std::cout << "k _:";
		for (auto bin : bins)
			std::cout << bin << " ";
		std::cout << std::endl;
		for (auto ball : balls)
		{
			std::cout << "nn " << ball << ": f ";
			for (auto bin : bins)
			{
				std::vector<std::vector<Float>> pascal_triangle_float;
				auto f = ballBinCap<Float>(ball, bin, cap, fc);
				auto fl = log2(f);
				std::cout << fl << " i ";
				std::vector<std::vector<Int>> pascal_triangle_int;
				auto z = ballBinCap<Int>(ball, bin, cap, ic);
				auto zl = log2(z);
				std::cout << zl << ",  ";
#ifdef MPZ_ENABLE
#endif
			}
			std::cout << std::endl;
		}

	}

	template<typename T>
	inline T ballsBins(i64 n, i64 k, ChooseCache<T>& pascal_triangle)
	{
		return choose_pascal<T>(n + k - 1, k - 1, pascal_triangle);
	}


	inline void stirlingTest(const oc::CLP& cmd)
	{
		u64 n = cmd.getOr("n", 44);
		for (u64 i = 0; i < n; ++i)
		{
			auto I = fact<Int>(i);
			auto F = fact<Float>(i);
			auto S = stirlingApprox(i);

			auto d0 = abs((I - F.convert_to<Int>()).convert_to<Float>() / I.convert_to<Float>());
			auto d1 = abs((I - S.convert_to<Int>()).convert_to<Float>() / I.convert_to<Float>());

			if (d0 > 0.000001)
				throw RTE_LOC;
			if (d1 > 0.000001)
				throw RTE_LOC;
		}
	}

	inline void chooseTest(const oc::CLP& cmd)
	{
		u64 n = cmd.getOr("n", 44);
		u64 m = cmd.getOr("m", 44);
		std::vector<std::vector<Int>> pascal_triangle_int2;
		std::vector<std::vector<Int>> pascal_triangle_int;

		ChooseCache<Float> fc;
		ChooseCache<Int> ic;
		bool failed = false;
		for (u64 i = 0; i < n; ++i)
		{
			for (u64 j = 0; j < m; ++j)
			{
				auto I = ic.choose_pascal_recursive(i, j);
				//std::cout << I << " ";

				auto I2 = choose_pascal<Int>(i, j, ic);
				if (I != I2)
					throw RTE_LOC;

				std::vector<std::vector<Float>> pascal_triangle_float;
				auto F = fc.choose_pascal_recursive(i, j);
				//auto S = chooseApx(i, j);
				auto div = (I ? I.convert_to<Float>() : 1);
				auto d0 = abs((I - F.convert_to<Int>()).convert_to<Float>() / div);
				//auto d1 = (I - S.convert_to<Int>()).convert_to<Float>() / div;

				//std::cout << i << " " << j << ": " << d0 << " " << d1 << std::endl;
				if (d0 > 0.000001)
				{
					failed = true;
					//std::cout << d0 << std::endl;
					//throw RTE_LOC;
				}
				//if (d1 > 0.000001)
				//    throw RTE_LOC;
			}
			//std::cout << "\n";
		}

		if (failed)
			throw std::runtime_error("choose Float failed." LOCATION);
		//std::cout << "\n";
		//std::cout << "\n";
		//for (u64 i = 0; i < n; ++i)
		//{
		//    for (u64 j = 0; j < m; ++j)
		//    {
		//        auto S = chooseApx(i, j);
		//        std::cout << S << " ";
		//    }
		//    std::cout << "\n";
		//}
	}

	inline void ballbincapTest(const oc::CLP& cmd)
	{
		auto balls = cmd.getManyOr<u64>("n", { 4, 10, 100 });
		auto bins = cmd.getManyOr<u64>("m", { 4, 10, 100 });
		auto caps = cmd.getManyOr<u64>("c", { 2,4, 12 });

		ChooseCache<Float> fc;
		ChooseCache<Int> ic;
		for (auto ball : balls)
		{
			for (auto bin : bins)
			{
				for (auto cap : caps)
				{
					std::vector<std::vector<Float>> pascal_triangle_float;
					auto f = ballBinCap<Float>(ball, bin, cap, fc);
					auto fl = log2(f);
					//std::cout << fl << " i ";
					std::vector<std::vector<Int>> pascal_triangle_int;
					auto z = ballBinCap<Int>(ball, bin, cap, ic);
					auto zl = log2(z);
					//std::cout << zl << ",  ";


					auto div = (z ? z.convert_to<Float>() : 1);
					auto d0 = abs((z - f.convert_to<Int>()).convert_to<Float>() / div);
					if (d0 > 0.000001)
						throw RTE_LOC;

					if (zl < 16)
					{
						auto X = ballBinCapX(ball, bin, cap);
						//auto d1 = abs((z - X.convert_to<Int>()).convert_to<Float>() / div);
						if (X != z)
							throw RTE_LOC;
					}
				}
			}
		}

	}

	inline void test(oc::CLP& cmd)
	{
		TestCollection tests;
		tests.add("stirlingTest      ", stirlingTest);
		tests.add("chooseTest        ", chooseTest);
		//tests.add("ballbincapTest    ", ballbincapTest);

		tests.runIf(cmd);
	}


	inline void EnumToolsMain(oc::CLP& cmd)
	{
		if (cmd.isSet("u")) {
			std::cout << "testing all..." << std::endl;
			test(cmd);
		}

		if (cmd.isSet("stirling")) {
			std::cout << "testing stirling..." << std::endl;
			stirlingMain(cmd);
		}


		if (cmd.isSet("choose")) {
			std::cout << "testing choose..." << std::endl;
			chooseMain(cmd);
		}

		if (cmd.isSet("bbc")) {
			std::cout << "testing balls bins cap..." << std::endl;
			ballBinCapMain(cmd);
		}
	}
}

#endif
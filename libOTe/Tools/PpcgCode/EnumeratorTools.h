// balls into bins, balls into bins with capacity, etc.

#pragma once
#include "cryptoTools/Common/TestCollection.h"
#include "cryptoTools/Common/Defines.h"
#include <vector>
#include <unordered_map>
#include "cryptoTools/Common/CLP.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/Matrix.h"

#include <boost/multiprecision/cpp_bin_float.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#ifdef ENABLE_GMP
#include <boost/multiprecision/gmp.hpp>
#include "gmp.h"
#include "gmpxx.h"
#endif

#include "LoadingBar.h"
#include "Choose.h"

namespace osuCrypto {


	// check that each element in distribution1 is within 
	// tolerance of the corresponding element in distribution2
	template<typename R>
	bool compareDistributions(
		span<const R> distribution1,
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


	template<typename T, typename R>
	T to(const R&);

	template<typename T>
	T pow2(u64 pow);

	template<typename T>
	struct RationalOf;

	template<typename T>
	T fact(u64 n);



	//using Float = boost::multiprecision::cpp_bin_float_double;
	//using Float = boost::multiprecision::cpp_bin_float_quad;
	//using Float = boost::multiprecision::cpp_bin_float_oct;
	namespace mp = boost::multiprecision;

	// unsigned Digits, digit_base_type DigitBase, class Allocator, class Exponent, Exponent MinExponent, Exponent MaxExponent
	using Float = mp::number<
		mp::backends::cpp_bin_float<237, mp::backends::digit_base_2, void, std::int64_t, -68719476734, 68719476735>, mp::et_off>;

#ifdef ENABLE_GMP
	using Int = boost::multiprecision::mpz_int;
	using Rat = boost::multiprecision::mpq_rational;
#else

	using Int = boost::multiprecision::cpp_int;
	using Rat = boost::multiprecision::cpp_rational;

#endif
	template<>
	inline Float to<Float, Float>(const Float& v)
	{
		return v;
	}

	template<>
	inline Int to<Int, Rat>(const Rat& v)
	{
		return v.convert_to<Int>();
	}

	// returns z/2^power.
	inline Float divPow2(const Float& v, u64 power)
	{
		return v / pow(Float(v), power);
	}

	inline Rat divPow2(const Int& v, u64 power)
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
	inline Float fact<Float>(u64 n)
	{
		Float v = 1;
		for (u64 i = 2; i <= n; ++i)
			v *= i;
		return v;
	}

	template<>
	inline Int fact<Int>(u64 n)
	{
		Int v = 1;
		for (u64 i = 2; i <= n; ++i)
			v *= i;
		return v;
	}

	inline u64 log2floor(Int x)
	{
		u64 r = 0;
		while (x >= 2)
		{
			++r;
			x /= 2;
		}
		return r;
	}

	inline u64 log2ceil(Int x)
	{
		auto r = log2floor(x);
		if ((Int(1) << r) != x)
			++r;
		return r;
	}

	inline double log2(Int x) {

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

	inline auto log2_(const Rat& v) {
		auto f = v.convert_to<Float>();
		return boost::multiprecision::log2(f);
	}

	inline auto log2_(const Float& f) {
		return boost::multiprecision::log2(f);
	}


	template<typename R, typename I, typename Enum>
	inline void enumerate(Enum&& enumerator,
		span<const R> inputDist,
		span<R> outputDist,
		const Choose<I>& choose,
		LoadingBar* loadingBar = nullptr)
	{
		if (enumerator.rows() != inputDist.size())
			throw RTE_LOC;
		if (enumerator.cols() != outputDist.size())
			throw RTE_LOC;

		if (loadingBar)
			loadingBar->name("enum");

		std::fill_n(outputDist.begin(), outputDist.size(), 0);
		auto k = inputDist.size() - 1;
		for (u64 w = 0; w < enumerator.rows(); ++w)
		{
			auto& kcw = choose(k, w);
			for (u64 h = 0; h < enumerator.cols(); ++h)
			{
				//std::cout<< w<<" " << h << " ~ " << inputDist[w] << " " << enumerator(w,h) << " / " << kcw << std::endl;

				outputDist[h] += inputDist[w] * enumerator(w, h) / kcw;
			}
			if (loadingBar)
				loadingBar->tick();
		}
		if constexpr (std::is_same_v<std::remove_cvref_t<R>, Rat>)
		{
			for (u64 h = 0; h < enumerator.cols(); ++h)
				outputDist[h].backend().normalize();
		}
	}

	// given an enumerator for matrix G, return the enumerator
	// for G' = (I || G)
	template<typename R, typename Enum>
	inline Matrix<R> makeSystematic(Enum&& enumerator)
	{
		Matrix<R> r(enumerator.rows(), enumerator.cols() + enumerator.rows() - 1);
		for (u64 w = 0; w < enumerator.rows(); ++w)
		{
			for (u64 h = 0; h < enumerator.cols(); ++h)
			{
				r(w, w + h) = enumerator(w, h);
			}
		}
		return r;
	}

	// Given the matrix enumerator e1 and e2 for matrices
	// G1 and G2, compute the expected enumerator matrix E
	// for
	//
	//  G = G1 pi G2
	//
	// where pi is the permutation matrix.
	//
	// E(w, h) = sum_h1 E1(w, h1) * E2(h1, h) / choose(n1, h1)
	//
	template<typename R, typename E1, typename E2, typename I>
	Matrix<R> composeEnums(
		const E1& e1,
		const E2& e2,
		const Choose<I>& choose,
		u64 numThreads = 1,
		LoadingBar* loadingBar = nullptr)
	{
		auto k1 = e1.rows() - 1;
		auto k2 = e2.rows() - 1;
		auto n1 = e1.cols() - 1;
		auto n2 = e2.cols() - 1;


		if (n1 != k2)
			throw RTE_LOC;
		if (loadingBar)
			loadingBar->name("Compose");

		auto r = Matrix<R>(e1.rows(), e2.cols());

		if (n1 * n2 * k1 < 1000 || numThreads < 2)
		{

			for (u64 w = 0; w <= k1; ++w)
			{
				for (u64 h = 0; h <= n2; ++h)
				{
					for (u64 h1 = 0; h1 <= n1; ++h1)
					{
						r(w, h) += e1(w, h1) * e2(h1, h) / choose(n1, h1);
					}
					if constexpr (std::is_same_v<std::remove_cvref_t<R>, Rat>)
						r(w, h).backend().normalize();
					if (loadingBar)
						loadingBar->tick();
				}
			}
		}
		else
		{
			std::vector<std::jthread> thrds;
			for (u64 i = 0; i < numThreads; ++i)
			{
				thrds.emplace_back([&, i] {

					for (u64 w = i; w <= k1; w += numThreads)
					{
						for (u64 h = 0; h <= n2; ++h)
						{
							for (u64 h1 = 0; h1 <= n1; ++h1)
							{
								r(w, h) += e1(w, h1) * e2(h1, h) / choose(n1, h1);
							}
							if constexpr (std::is_same_v<std::remove_cvref_t<R>, Rat>)
								r(w, h).backend().normalize();
							if (loadingBar)
								loadingBar->tick();
						}

					}

					});
			}


		}

		//std::cout << "e1\n" << enumToString(e1) << std::endl;
		//std::cout << "e2\n" << enumToString(e2) << std::endl;
		//std::cout << "r\n" << enumToString(e2) << std::endl;
		return r;
	}

	template<typename Enum>
	std::string enumToString(Enum&& e)
	{
		std::stringstream ss;
		for (u64 i = 0; i < e.rows(); ++i)
		{
			for (u64 j = 0; j < e.cols(); ++j)
			{
				auto ee = e(i, j);
				if constexpr (std::is_same_v<std::remove_cvref_t<decltype(ee)>, Rat>)
					ee.backend().normalize();
				ss << ee << " ";
			}
			ss << std::endl;
		}
		return ss.str();
	}

	template<typename Enum>
	std::string logEnumToString(Enum&& e)
	{
		std::stringstream ss;
		for (u64 i = 0; i < e.rows(); ++i)
		{
			for (u64 j = 0; j < e.cols(); ++j)
			{
				ss << log2_(e(i, j)) << " ";
			}
			ss << std::endl;
		}
		return ss.str();
	}
}


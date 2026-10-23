#pragma once
#include "libOTe/config.h"
#include "cryptoTools/Common/block.h"
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <ostream>
#include <limits>
#include <stdexcept>
#include "libOTe/Tools/CoeffCtx.h"
#include <array>

namespace osuCrypto
{
	template<u64 modulus, typename T, typename TT = T>
	struct Fp
	{
		static_assert(std::is_unsigned_v<T>, "Fp storage must be unsigned.");
		static_assert(std::is_unsigned_v<TT>, "Fp wide storage must be unsigned.");
		static_assert(modulus >= 2, "Fp modulus must be at least two.");
		static_assert(modulus <= std::numeric_limits<T>::max(),
			"Fp modulus must fit in its storage type.");
		static constexpr T mMod = modulus;
		static_assert(log2ceil(mMod) * 2 <= 8 * sizeof(TT), "a double sized value must fit in TT ");
		static constexpr bool mNarrowAddSub =
			mMod <= std::numeric_limits<T>::max() / 2 + 1;
		T mVal;


		constexpr Fp() = default;
		constexpr Fp(u64 v) : mVal(v >= mMod ? (v % mMod) : v) {}
		constexpr Fp(const Fp&) = default;
		constexpr Fp& operator=(const Fp&) = default;


		Fp(PRNG::Any prng)
		{
			*this = prng;
		}
		Fp& operator=(PRNG::Any prng)
		{
			mVal = static_cast<T>(fieldSampling::sample(prng.mPrng, mMod));
			return *this;
		}

		static constexpr auto order() { return mMod; }

		constexpr Fp& operator+=(const Fp& o)
		{

			assert(mVal < mMod && o.mVal < mMod);
			T r;
			if constexpr (mNarrowAddSub)
			{
				r = mVal + o.mVal;
				if (r >= mMod)
					r -= mMod;
			}
			else
			{
				TT wide = TT(mVal) + TT(o.mVal);
				if (wide >= TT(mMod))
					wide -= TT(mMod);
				r = static_cast<T>(wide);
			}

			assert(r == (TT(mVal) + TT(o.mVal)) % TT(mMod));

			mVal = r;
			return *this;
		}
		constexpr Fp operator+(const Fp& o) const
		{
			assert(mVal < mMod && o.mVal < mMod);
			Fp r;
			if constexpr (mNarrowAddSub)
			{
				r.mVal = mVal + o.mVal;
				if (r.mVal >= mMod)
					r.mVal -= mMod;
			}
			else
			{
				TT wide = TT(mVal) + TT(o.mVal);
				if (wide >= TT(mMod))
					wide -= TT(mMod);
				r.mVal = static_cast<T>(wide);
			}

			assert(r.mVal == (TT(mVal) + TT(o.mVal)) % TT(mMod));
			return r;
		};

		constexpr Fp& operator-=(const Fp& o)
		{
			assert(mVal < mMod && o.mVal < mMod);
			T r;
			if constexpr (mNarrowAddSub)
			{
				r = mVal - o.mVal;
				if (r >= mMod)
					r += mMod;
			}
			else
			{
				r = mVal >= o.mVal ?
					static_cast<T>(mVal - o.mVal) :
					static_cast<T>(TT(mVal) + TT(mMod) - TT(o.mVal));
			}
			assert(r == (TT(mVal) + TT(mMod) - TT(o.mVal)) % TT(mMod));

			mVal = r;
			return *this;
		}
		constexpr Fp operator-(const Fp& o) const
		{
			assert(mVal < mMod && o.mVal < mMod);
			Fp r;
			if constexpr (mNarrowAddSub)
			{
				r.mVal = mVal - o.mVal;
				if (r.mVal >= mMod)
					r.mVal += mMod;
			}
			else
			{
				r.mVal = mVal >= o.mVal ?
					static_cast<T>(mVal - o.mVal) :
					static_cast<T>(TT(mVal) + TT(mMod) - TT(o.mVal));
			}

			assert(r.mVal == (TT(mVal) + TT(mMod) - TT(o.mVal)) % TT(mMod));

			return r;
		};

		constexpr Fp operator-() const
		{
			assert(mVal < mMod);
			Fp r = 0;
			if (mVal)
				r.mVal = mMod - mVal;

			assert(r.mVal == (mMod - TT(mVal)) % TT(mMod));

			return r;
		};

		constexpr Fp operator*(const Fp& o) const
		{
			assert(mVal < mMod && o.mVal < mMod);
			//Fp r;
			//r.mVal = (mVal * o.mVal) % mMod;
			auto r =  barrettMul(*this, o);

			return r;
		};

		constexpr Fp& operator*=(const Fp& o)
		{
			assert(mVal < mMod && o.mVal < mMod);
			*this = barrettMul(*this, o);
			return *this;
		};


		constexpr Fp operator/(const Fp& o) const
		{
			assert(mVal < mMod && o.mVal < mMod);
			if (o.mVal == 0)
				throw std::domain_error("Finite-field division by zero. " LOCATION);
			return *this * o.inverse();
		}

		constexpr Fp& operator/=(const Fp& o)
		{
			assert(mVal < mMod && o.mVal < mMod);
			if (o.mVal == 0)
				throw std::domain_error("Finite-field division by zero. " LOCATION);
			*this = *this * o.inverse();
			return *this;
		}


		// comparison operators
		constexpr bool operator<(const Fp& o) const
		{
			assert(mVal < mMod && o.mVal < mMod);
			return mVal < o.mVal;
		}
		constexpr bool operator>=(const Fp& o) const
		{
			assert(mVal < mMod && o.mVal < mMod);
			return mVal >= o.mVal;
		}

		constexpr u64 integer() const
		{
			assert(mVal < mMod);
			return mVal;
		}

		template<typename I>
			requires (std::is_integral_v<std::remove_cv_t<I>> &&
				!std::is_same_v<std::remove_cv_t<I>, bool>)
		constexpr Fp pow(I exponent) const
		{
			assert(mVal < mMod);
			using E = std::remove_cv_t<I>;
			if constexpr (std::is_signed_v<E>)
				if (exponent < 0)
					throw RTE_LOC;
			using U = std::make_unsigned_t<E>;
			U v = static_cast<U>(exponent);
			if (v == 0)
				return 1;

			Fp y = 1;
			Fp x = *this;
			while (v > 1)
			{
				if (v & 1)
				{
					y = x * y;
					v = v - 1;
				}

				x = x * x;
				v = v >> 1;
			}

			return x * y;
		}


		constexpr bool operator==(const Fp& o) const
		{
			return mVal == o.mVal;
		}

		constexpr bool operator!=(const Fp& o) const
		{
			return !(*this == o);
		}

		constexpr Fp inverse() const
		{
			// Match the vector-friendly convention used by Goldilocks. Division
			// still rejects a zero divisor explicitly.
			if (mVal == 0)
				return zero();

			// fermat's little theorem
			auto p = pow(mMod - 2);
			assert((*this * p).mVal == 1);
			return p;
		}


		constexpr static Fp barrettMul(const Fp& a, const Fp& b)
		{
			// Barrett reduction
			// https://en.wikipedia.org/wiki/Barrett_reduction
			constexpr unsigned TT_bits = std::numeric_limits<TT>::digits;
			constexpr int k = log2ceil(mMod);
			constexpr TT mu = [&]() {
				/* mu = ⌊b² / p⌋
				 *
				 * If  2k < digits(TT)  we can form b*b safely.
				 * Otherwise b² = 2^(digits(TT)) does not fit in TT,
				 * so we compute  ⌊2^(digits(TT)) / p⌋  in two steps
				 * using only values representable in TT.
				 */
				if constexpr (2 * k < TT_bits)
				{
					constexpr TT B = TT(1) << k; // b = 2^k
					return (B * B) / mMod;
				}
				else                       // borderline: k == digits(T)
				{
					TT maxVal = std::numeric_limits<TT>::max();   // 2^TT_bits − 1
					auto mu = maxVal / mMod;
					TT rem = maxVal - mu * mMod;
					if (rem + 1 >= mMod)          // did (maxVal+1)/p round up?
						++mu;                  // yes – increase by one
					return mu;
				}
				}();

			static_assert(mu != 0, "overflow detected");

			auto x = TT{ a.mVal } *TT{ b.mVal }; // x = a * b
			TT x_hi = x >> k;                  // ⌊x / 2^k⌋   ( < 2^k = b )
			TT q = (x_hi * mu) >> k;        // ⌊x_hi * μ / 2^k⌋  ≈ ⌊x/p⌋
			TT r = x - q * mMod;               // provisional remainder

			/*  r is guaranteed to lie in [0, 2p), so at most two
			 *  subtractions bring it into [0, p).
			 */
			if (r >= mMod) r -= mMod;
			if (r >= mMod) r -= mMod;

			assert(r == (TT(a.mVal) * TT(b.mVal)) % TT(mMod));


			return Fp(static_cast<T>(r));
		}


		static Fp zero() { return Fp{ 0 }; }
		static Fp one() { return Fp{ 1 }; }

	};


	struct Factor {
		Factor() = default;
		Factor(const Factor&) = default;
		Factor(u64 f, u64 e) :mFactor(f), mExp(e) {}

		u64 mFactor;
		u64 mExp;
	};
	inline std::vector<Factor> uniqueFactor(u64 x)
	{
		//std::vector<Factor> r;
		////r.push_back(1);

		//auto X = x;
		//for (u64 i = 2; i <= x / 2; ++i)
		//{
		//	if (X % i == 0)
		//	{
		//		//r.push_back(i);
		//		//u64 f = i;
		//		u64 e = 1;
		//		X /= i;
		//		while (X % i == 0)
		//		{
		//			X /= i;
		//			++e;
		//		}
		//		r.push_back({ i, e });
		//	}
		//}
		//return r;

		std::vector<Factor> r;
		u64 X = x;
		if (X < 2) return r;

		// Factor out powers of 2
		if ((X & 1) == 0)
		{
			u64 e = 0;
			do { X >>= 1; ++e; } while ((X & 1) == 0);
			r.emplace_back(2, e);
		}

		// Trial divide by odd numbers up to sqrt(X)
		for (u64 i = 3; i <= X / i; i += 2)
		{
			if (X % i == 0)
			{
				u64 e = 0;
				do { X /= i; ++e; } while (X % i == 0);
				r.emplace_back(i, e);
			}
		}

		// Any remaining factor is prime
		if (X > 1)
			r.emplace_back(X, 1);

		return r;
	}

	template<typename F>
	F findGenerator(PRNG& prng) {
		auto p = F::order();

		// we are interested in the range [2, p-2]
		auto dist = [&]() {
			F f;
			do {
				f = prng.get();
			} while (f < 2 || f >= p - 2);

			return f;
			};
		auto factors = uniqueFactor(p - 1);

		while (true) {
			F a = dist();
			bool ok = true;
			for (auto q : factors)
			{
				if (a.pow((p - 1) / q.mFactor) == 1)
				{
					ok = false;
					break;
				}
			}

			if (ok)
				return a;
		}
	}

	// returns true if u is a primitive root of unity.
	// factors should be the unique factors of n.
	template<typename F>
	inline bool isPrimRootOfUnity(span<Factor> factors, const F& u)
	{
		auto p = F::order();
		u64 n = 1;
		for (auto fe : factors)
		{
			if (fe.mFactor < 2 || fe.mExp == 0)
				throw std::invalid_argument("Root-of-unity factors must have positive exponents and factors of at least two. " LOCATION);
			for (u64 i = 0; i < fe.mExp; ++i)
			{
				if (n > std::numeric_limits<u64>::max() / fe.mFactor)
					throw std::invalid_argument("Root-of-unity order overflows. " LOCATION);
				n *= fe.mFactor;
			}
		}

		if ((p - 1) % n)
			throw std::invalid_argument("Root-of-unity order must divide the field multiplicative order. " LOCATION);

		// make suer u is in Fp*
		if (u == 0)
			return false;

		// make sure u is a root of unity.
		if (u.pow(n) != 1)
			return false;

		// check that u is a primitive root of unity.
		for (u64 i = 0; i < factors.size(); ++i)
		{
			if (u.pow(n / factors[i].mFactor) == 1)
			{
				return false;
			}
		}
		return true;
	}
	// returns true if f is a primitive root of unity.
	template<typename F>
	inline bool isPrimRootOfUnity(u64 n, const F& u)
	{
		auto factors = uniqueFactor(n);
		return isPrimRootOfUnity<F>(factors, u);
	}


	// return a primitive n-root of unity given a generator.
	template<typename F>
	inline F primRootOfUnity(u64 n, F generator)
	{
		auto p = F::order();
		if (n == 0)
			throw std::invalid_argument("Root-of-unity order must be nonzero. " LOCATION);
		auto pMinusOne = p - 1;
		if (pMinusOne % n)
			throw std::invalid_argument("Root-of-unity order must divide the field multiplicative order. " LOCATION);
		return generator.pow(static_cast<u64>(pMinusOne / n));
	}

	template<typename F>
	inline F primRootOfUnity(u64 n)
	{
		PRNG prng(CCBlock);
		F G = findGenerator<F>(prng);
		return primRootOfUnity<F>(n, G);
	}

	

	// returns true if u is an n-root of unity.
	template<typename F>
	inline bool isRootOfUnity(u64 n, const F& u)
	{
		auto p = F::order();
		if (u == 0)
			return false;
		if (u.pow(n) != 1)
			return false;
		return true;
	}

	template<typename F>
	struct ScalerOf
	{
		using type = F;
	};



	template<u64 p, typename T, typename TT>
	std::ostream& operator<<(std::ostream& o, const Fp<p, T, TT>& f)
	{
		// signed 
		//if (f.mVal >= p / 2)
		//	o << i64(f.mVal - p);
		//else
			o << f.mVal;
		return o;
	}

	// Primary template - not an Fp type
	template<typename T>
	struct FpTraits {
		static constexpr bool is_fp = false;
	};

	// Specialization for Fp types to extract template parameters
	template<u64 modulus, typename T, typename TT>
	struct FpTraits<Fp<modulus, T, TT>> {
		static constexpr bool is_fp = true;
		static constexpr u64 modulus_value = modulus;
		using value_type = T;
		using double_type = TT;
	};

	struct CoeffCtxFp : CoeffCtxInteger
	{
		template<typename F>
		constexpr double regularNoiseFactor() const
		{
			using traits = FpTraits<std::remove_cvref_t<F>>;
			static_assert(traits::is_fp, "F must be an Fp type.");
			return static_cast<double>(traits::modulus_value) /
				static_cast<double>(traits::modulus_value - 1);
		}

		template<typename F>
		OC_FORCEINLINE bool isCanonical(const F& value) const
		{
			using traits = FpTraits<std::remove_cvref_t<F>>;
			static_assert(traits::is_fp, "F must be an Fp type.");
			return value.mVal < traits::modulus_value;
		}

		// Peer-provided field encodings must be canonical. The arithmetic
		// kernels intentionally assume this invariant and only assert it.
		template<typename SrcIter, typename DstIter>
		void deserialize(SrcIter&& begin, SrcIter&& end, DstIter&& dstBegin) const
		{
			using SrcType = std::remove_cvref_t<decltype(*begin)>;
			using DstType = std::remove_cvref_t<decltype(*dstBegin)>;
			static_assert(FpTraits<DstType>::is_fp,
				"CoeffCtxFp can only deserialize into an Fp type.");

			CoeffCtxInteger::deserialize(begin, end, dstBegin);

			auto srcCount = std::distance(begin, end);
			if (srcCount)
			{
				// The base deserializer has already checked the range, byte
				// multiplication, and divisibility.
				auto bytes = static_cast<std::size_t>(srcCount) * sizeof(SrcType);
				auto dstCount = bytes / sizeof(DstType);
				for (std::size_t i = 0; i < dstCount; ++i)
				{
					if (!isCanonical(dstBegin[i]))
					{
						for (std::size_t j = 0; j < dstCount; ++j)
							dstBegin[j].mVal = 0;
						throw std::invalid_argument(
							"Noncanonical finite-field encoding. " LOCATION);
					}
				}
			}
		}

		template<typename G>
		bool characteristicTwo() const {
			static_assert(FpTraits<G>::is_fp, "G must be an Fp type.");
			return false;
		}

		// is G a field?
		template<typename G>
		OC_FORCEINLINE bool isField()const {
			static_assert(FpTraits<G>::is_fp, "G must be an Fp type.");
			return true;
		}

		template<typename G>
		constexpr u64 additiveGroupBitCount() const
		{
			using traits = FpTraits<G>;
			static_assert(traits::is_fp, "G must be an Fp type.");
			return log2ceil(traits::modulus_value);
		}

		// the bit size require to prepresent F
		// the protocol will perform binary decomposition
		// of F using this many bits
		template<typename F>
		u64 bitSize()const
		{
			using traits = FpTraits<F>;
			static_assert(traits::is_fp, "G must be an Fp type.");
			return log2ceil(traits::modulus_value);
		}

		// return the binary decomposition of x. This will be used to 
		// reconstruct x as   
		// 
		//     x = sum_{i = 0,...,n} 2^i * binaryDecomposition(x)[i]
		//
		template<typename F>
		OC_FORCEINLINE BitVector binaryDecomposition(F& x) const {
			static_assert(std::is_trivially_copyable<F>::value, "memcpy is used so must be trivially_copyable.");
			return { (u8*)&x, bitSize<F>() };
		}

		template<typename F>
		OC_FORCEINLINE void fromBlock(F& ret, const block& b) const {

			using traits = FpTraits<F>;
			static_assert(traits::is_fp, "G must be an Fp type.");
			ret.mVal = static_cast<typename traits::value_type>(
				fieldSampling::fromBlock(b, traits::modulus_value));
		}



		// given x and a masking block `mask` with value 0x0000...00 or 0xffff...ff,
		// return F(0) if `mask` is 0 and otherwise return x.
		template<typename F>
		void mask(F& ret, const F& x, const block& mask)const
		{
			using traits = FpTraits<F>;
			using value_type = traits::value_type;
			value_type y = mask.get<value_type>(0);
			ret.mVal = x.mVal & y;
		}

	};

	// OT, gf2
	template<u64 p, typename T, typename TT> 
	struct DefaultCoeffCtx_t<Fp<p,T,TT>> {
		using type = CoeffCtxFp;
	};

	using F7681 = Fp<7681, u16, u32>;
	using F12289 = Fp<12289, u16, u32>;

	// 15 * 2^27 + 1 ~= 2^31
	using Fp31 = Fp<2013265921, u32, u64>;
	static_assert(sizeof(Fp31) == 4, "expecting 32 bits");

	// Table of primitive 2^k-th roots of unity for k=0..27, suitable for NTTs over F_p.
	// Entry i is a primitive 2^i-th root. Consumers should ensure sizes are powers of two.
	static constexpr std::array<Fp31, 28> Fp31RootsOfUnity =
	{
		Fp31{1ull},
		Fp31{2013265920ull},
		Fp31{284861408ull},
		Fp31{1801542727ull},
		Fp31{567209306ull},
		Fp31{740045640ull},
		Fp31{918899846ull},
		Fp31{1881002012ull},
		Fp31{1453957774ull},
		Fp31{65325759ull},
		Fp31{1538055801ull},
		Fp31{515192888ull},
		Fp31{483885487ull},
		Fp31{1855872842ull},
		Fp31{1696032120ull},
		Fp31{411186671ull},
		Fp31{1141908750ull},
		Fp31{1428255116ull},
		Fp31{1590358139ull},
		Fp31{483847342ull},
		Fp31{581370269ull},
		Fp31{457897203ull},
		Fp31{665793983ull},
		Fp31{1444357277ull},
		Fp31{1979936065ull},
		Fp31{1718736189ull},
		Fp31{548902408ull},
		Fp31{2005737441ull}
	};


	// Fp31 specialization:
	// - n must be a power of two (n = 2^k).
	// - Returns the precomputed primitive n-th root from the table above.
	template<>
	inline Fp31 primRootOfUnity<Fp31>(u64 n)
	{
		if (n == 0)
			throw std::invalid_argument("Fp31 root-of-unity order must be nonzero. " LOCATION);
		auto ln = log2ceil(n);
		if (ln >= 64 || (1ull << ln) != n)
			throw std::invalid_argument("Fp31 root-of-unity order must be a power of two. " LOCATION);
		if (ln >= Fp31RootsOfUnity.size())
			throw std::invalid_argument("Fp31 root-of-unity order exceeds the field two-adicity. " LOCATION);
		return Fp31RootsOfUnity[ln];
	}
}

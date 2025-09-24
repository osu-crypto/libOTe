#pragma once
#include "libOTe/config.h"
#include "cryptoTools/Common/block.h"
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <ostream>
#include "libOTe/Tools/CoeffCtx.h"
#include <array>

namespace osuCrypto
{
	template<u64 modulus, typename T, typename TT = T>
	struct Fp
	{
		static constexpr T mMod = modulus;
		static_assert(log2ceil(mMod) * 2 <= 8 * sizeof(TT), "a double sized value must fit in TT ");
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
			mVal = prng.mPrng.get<u64>() % mMod;
			return *this;
		}

		static constexpr auto order() { return mMod; }

		constexpr Fp& operator+=(const Fp& o)
		{

			assert(mVal < mMod && o.mVal < mMod);
			T r = mVal + o.mVal;
			if (r >= mMod)
				r -= mMod;

			assert(r == (TT(mVal) + TT(o.mVal)) % TT(mMod));

			mVal = r;
			return *this;
		}
		constexpr Fp operator+(const Fp& o) const
		{
			assert(mVal < mMod && o.mVal < mMod);
			Fp r;
			r.mVal = mVal + o.mVal;
			if (r.mVal >= mMod)
				r.mVal -= mMod;

			assert(r.mVal == (TT(mVal) + TT(o.mVal)) % TT(mMod));
			return r;
		};

		constexpr Fp& operator-=(const Fp& o)
		{
			assert(mVal < mMod && o.mVal < mMod);
			T r = mVal - o.mVal;
			if (r >= mMod)
				r += mMod;
			assert(r == (TT(mVal) - TT(o.mVal) + mMod) % TT(mMod));

			mVal = r;
			return *this;
		}
		constexpr Fp operator-(const Fp& o) const
		{
			assert(mVal < mMod && o.mVal < mMod);
			Fp r;
			r.mVal = mVal - o.mVal;
			if (r.mVal >= mMod)
				r.mVal += mMod;

			assert(r.mVal == (TT(mVal) - TT(o.mVal) + mMod) % TT(mMod));

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
			return *this * o.inverse();
		}

		constexpr Fp& operator/=(const Fp& o)
		{
			assert(mVal < mMod && o.mVal < mMod);
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

		constexpr Fp pow(i64 v) const
		{
			assert(mVal < mMod);
			if (v < 0)
				throw RTE_LOC;
			if (v == 0)
				return 1;
			if (v > mMod)
				v = v % mMod;

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
			for (u64 i = 0; i < fe.mExp; ++i)
				n *= fe.mFactor;
		}

		if ((p - 1) % n)
			throw RTE_LOC;

		// make suer u is in Fp*
		if (u == 0 || u.integer() % p == 0)
			return false;

		// make sure u is a root of unity.
		if (u.pow(n) != 1)
			return false;

		// check that u is a primitive root of unity.
		for (u64 i = 1; i < factors.size() - 1; ++i)
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
		return generator.pow((p - 1) / n);
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
			ret.mVal = b.get<u64>(0) % traits::modulus_value;
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

	// Table of primitive 2^k-th roots of unity for k=0..32, suitable for NTTs over F_p.
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


	// Goldilocks specialization:
	// - n must be a power of two (n = 2^k).
	// - Returns the precomputed primitive n-th root from the table above.
	template<>
	inline Fp31 primRootOfUnity<Fp31>(u64 n)
	{
		auto ln = log2ceil(n);
		if (1ull << ln != n)
			throw RTE_LOC;
		return Fp31RootsOfUnity[ln];
	}
}
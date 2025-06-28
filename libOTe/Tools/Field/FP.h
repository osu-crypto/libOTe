#include "libOTe/config.h"
#include "cryptoTools/Common/block.h"
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <ostream>

namespace osuCrypto
{
	template<u64 modulus, typename T>
	struct Fp
	{
		static constexpr T mMod = modulus;
		T mVal = 0;


		Fp() = default;
		Fp(u64 v) : mVal(v >= mMod ? (v % mMod) : v) {}
		Fp(const Fp&) = default;
		Fp& operator=(const Fp&) = default;


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

		Fp& operator+=(const Fp& o)
		{
			mVal = mVal + o.mVal;
			if (mVal >= mMod)
				mVal -= mMod;
			return *this;
		}
		Fp operator+(const Fp& o) const
		{
			Fp r;
			r.mVal = mVal + o.mVal;
			if (r.mVal >= mMod)
				r.mVal -= mMod;
			return r;
		};

		Fp& operator-=(const Fp& o)
		{
			mVal = mVal - o.mVal;
			if (mVal >= mMod)
				mVal += mMod;
			return *this;
		}
		Fp operator-(const Fp& o) const
		{
			Fp r;
			r.mVal = mVal - o.mVal;
			if (r.mVal >= mMod)
				r.mVal += mMod;
			return r;
		};

		Fp operator-() const
		{
			Fp r = 0;
			if(mVal)
				r.mVal = mMod - mVal;

			return r;
		};

		Fp operator*(const Fp& o) const
		{
			Fp r;
			r.mVal = (mVal * o.mVal) % mMod;
			return r;
		};

		Fp& operator*=(const Fp& o)
		{
			mVal = (mVal * o.mVal) % mMod;
			return *this;
		};


		Fp operator/(const Fp& o) const
		{
			return *this * o.inverse();
		}

		Fp& operator/=(const Fp& o)
		{
			*this = *this * o.inverse();
			return *this;
		}


		// comparison operators
		bool operator<(const Fp& o) const
		{
			return mVal < o.mVal;
		}
		bool operator>=(const Fp& o) const
		{
			return mVal >= o.mVal;
		}

		u64 integer() const
		{
			return mVal;
		}

		Fp pow(i64 v) const
		{
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


		bool operator==(const Fp& o) const
		{
			return mVal == o.mVal;
		}

		bool operator!=(const Fp& o) const
		{
			return !(*this == o);
		}

		Fp inverse() const
		{
			// fermat's little theorem
			return pow(mMod - 2);
		}

	};


	struct Factor {
		u64 mFactor;
		u64 mExp;
	};
	inline std::vector<Factor> uniqueFactor(u64 x)
	{
		auto sqrt = std::sqrt(x);
		std::vector<Factor> r;
		//r.push_back(1);

		auto X = x;
		for (u64 i = 2; i <= x / 2; ++i)
		{
			if (X % i == 0)
			{
				//r.push_back(i);
				//u64 f = i;
				u64 e = 1;
				X /= i;
				while (X % i == 0)
				{
					X /= i;
					++e;
				}
				r.emplace_back(i, e);
			}
		}
		return r;
	}

	template<typename F>
	F findGenerator(PRNG& prng) {
		auto p = F::mMod;

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
		u64 p = F::order();
		u64 n = 1;
		for(auto fe : factors)
		{
			for(u64 i = 0; i < fe.mExp; ++i)
				n *= fe.mFactor;
		}

		if((p-1) % n)
			throw RTE_LOC;

		// make suer u is in Fp*
		if (u == 0 || u.integer() % p == 0)
			return false;

		// make sure u is a root of unity.
		if(u.pow(n) != 1)
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



	template<u64 p, typename T>
	std::ostream& operator<<(std::ostream& o, const Fp<p, T>& f)
	{
		o << f.mVal;
		return o;
	}

	using F7681 = Fp<7681, u16>;
	using F12289 = Fp<12289, u64>;
}
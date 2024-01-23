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


        Fp(PRNG::Any& prng)
        {
            *this = prng;
        }
        Fp& operator=(PRNG::Any& prng)
        {
            mVal = prng.mPrng.get<u64>() % mMod;
            return *this;
        }

        static constexpr auto order() { return mMod; }

        Fp& operator+=(const Fp& o)
        {
            mVal = mVal + o.mVal;
            if (mVal > mMod)
                mVal -= mMod;
            return *this;
        }
        Fp operator+(const Fp& o) const
        {
            Fp r;
            r.mVal = mVal + o.mVal;
            if (r.mVal > mMod)
                r.mVal -= mMod;
            return r;
        };

        Fp& operator-=(const Fp& o)
        {
            mVal = mVal - o.mVal;
            if (mVal > mMod)
                mVal += mMod;
            return *this;
        }
        Fp operator-(const Fp& o) const
        {
            Fp r;
            r.mVal = mVal - o.mVal;
            if (r.mVal > mMod)
                r.mVal += mMod;
            return r;
        };

        Fp operator-() const
        {
            Fp r;
            r.mVal = -mVal + mMod;
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

    inline std::vector<u64> uniqueFactor(u64 x)
    {
        auto sqrt = std::sqrt(x);
        std::vector<u64> r;
        r.push_back(1);

        auto X = x;
        for (u64 i = 2; i <= x/2; ++i)
        {
            if (X % i == 0)
            {
                r.push_back(i);

                X /= i;
                while (X%i == 0)
                {
                    X /= i;
                }
            }
        }
        r.push_back(x);
        return r;
    }

    // returns true if f is a primitive root of unity.
    // factors should be the unique factors of n, i.e. {1,...,n}
    template<typename F>
    inline bool isPrimRootOfUnity(span<u64> factors, const F& u)
    {
        auto n = factors.back();
        for (u64 i = 1; i < factors.size() - 1; ++i)
        {
            if (u.pow(n / factors[i]) == 1)
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

    // return a primitive root of unity.
    template<typename F>
    inline F primRootOfUnity(u64 n, PRNG& prng)
    {
        auto qq = F::mMod - 1;
        if (n > qq)
            throw RTE_LOC;
        if (qq % n != 0)
            throw RTE_LOC;

        auto r = qq / n;

        auto factors = uniqueFactor(n);

        while (true)
        {
            F x = prng.get<u64>();
            auto g = x.pow(r);
            if (isPrimRootOfUnity(factors, g));
                return g;
        }
    }


    template<u64 p, typename T>
    std::ostream& operator<<(std::ostream& o, const Fp<p,T>& f)
    {
        o << f.mVal;
        return o;
    }

    using F7681 = Fp<7681, u16>;
    using F12289 = Fp<12289, u64>;
}
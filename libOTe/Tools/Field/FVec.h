#pragma once
#include <array>
#include <initializer_list>
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Crypto/PRNG.h"

namespace osuCrypto
{
    template<typename F, size_t N>
    struct FVec
    {
        using value_type = F;
        static constexpr size_t size_static = N;

        F v[N];

        static constexpr auto order() { return F::order(); }

        // ctors
        constexpr FVec() = default;


        //constexpr FVec(u64 fill)
        //{
        //    for (auto& x : v) x = F(fill);
        //}


        //constexpr FVec(F fill)
        //{
        //    for (auto& x : v) x = fill;
        //}
        constexpr FVec(std::initializer_list<F> init)
        {
            auto it = init.begin();
            size_t i = 0;
            for (; it != init.end() && i < N; ++it, ++i)
                v[i] = *it;
            for (; i < N; ++i) v[i] = F(0);
        }



        // PRNG fill (mirrors Fp/G as convenience)
        FVec(PRNG::Any prng)
        {
            for (u64 i = 0; i < N; ++i)
                v[i] = prng;
        }

        // PRNG fill (mirrors Fp/G as convenience)
        OC_FORCEINLINE FVec& operator=(PRNG::Any prng)
        {
            for (u64 i = 0; i < N; ++i)
                v[i] = prng;
            return *this;
        }

        // span conversions
        OC_FORCEINLINE operator span<F>() { return span<F>(v, N); }
        OC_FORCEINLINE operator span<const F>() const { return span<const F>(v, N); }

        // indexing
        OC_FORCEINLINE F& operator[](size_t i) { return v[i]; }
        OC_FORCEINLINE const F& operator[](size_t i) const { return v[i]; }

        // comparisons
        OC_FORCEINLINE bool operator==(const FVec& rhs) const
        {
            for (size_t i = 0; i < N; ++i) if (v[i] != rhs.v[i]) return false;
            return true;
        }
        OC_FORCEINLINE bool operator!=(const FVec& rhs) const { return !(*this == rhs); }

        // unary minus
        OC_FORCEINLINE FVec operator-() const
        {
            FVec r;
            for (size_t i = 0; i < N; ++i) r.v[i] = -v[i];
            return r;
        }

        // component-wise arithmetic
        OC_FORCEINLINE FVec operator+(const FVec& rhs) const
        {
            FVec r;
            for (size_t i = 0; i < N; ++i) r.v[i] = v[i] + rhs.v[i];
            return r;
        }
        OC_FORCEINLINE FVec& operator+=(const FVec& rhs)
        {
            for (size_t i = 0; i < N; ++i) v[i] = v[i] + rhs.v[i];
            return *this;
        }

        OC_FORCEINLINE FVec operator-(const FVec& rhs) const
        {
            FVec r;
            for (size_t i = 0; i < N; ++i) r.v[i] = v[i] - rhs.v[i];
            return r;
        }
        OC_FORCEINLINE FVec& operator-=(const FVec& rhs)
        {
            for (size_t i = 0; i < N; ++i) v[i] = v[i] - rhs.v[i];
            return *this;
        }

        OC_FORCEINLINE FVec operator*(const FVec& rhs) const
        {
            FVec r;
            for (size_t i = 0; i < N; ++i) r.v[i] = v[i] * rhs.v[i];
            return r;
        }
        OC_FORCEINLINE FVec& operator*=(const FVec& rhs)
        {
            for (size_t i = 0; i < N; ++i) v[i] = v[i] * rhs.v[i];
            return *this;
        }

        OC_FORCEINLINE FVec operator/(const FVec& rhs) const
        {
            FVec r;
            for (size_t i = 0; i < N; ++i) r.v[i] = v[i] / rhs.v[i];
            return r;
        }
        OC_FORCEINLINE FVec& operator/=(const FVec& rhs)
        {
            for (size_t i = 0; i < N; ++i) v[i] = v[i] / rhs.v[i];
            return *this;
        }

        // scalar by element (broadcast) helpers
        OC_FORCEINLINE FVec operator+(const F& s) const
        {
            FVec r;
            for (size_t i = 0; i < N; ++i) r.v[i] = v[i] + s;
            return r;
        }
        OC_FORCEINLINE FVec& operator+=(const F& s)
        {
            for (size_t i = 0; i < N; ++i) v[i] = v[i] + s;
            return *this;
        }
        OC_FORCEINLINE FVec operator-(const F& s) const
        {
            FVec r;
            for (size_t i = 0; i < N; ++i) r.v[i] = v[i] - s;
            return r;
        }
        OC_FORCEINLINE FVec& operator-=(const F& s)
        {
            for (size_t i = 0; i < N; ++i) v[i] = v[i] - s;
            return *this;
        }
        OC_FORCEINLINE FVec operator*(const F& s) const
        {
            FVec r;
            for (size_t i = 0; i < N; ++i) r.v[i] = v[i] * s;
            return r;
        }
        OC_FORCEINLINE FVec& operator*=(const F& s)
        {
            for (size_t i = 0; i < N; ++i) v[i] = v[i] * s;
            return *this;
        }
        OC_FORCEINLINE FVec operator/(const F& s) const
        {
            FVec r;
            for (size_t i = 0; i < N; ++i) r.v[i] = v[i] / s;
            return r;
        }
        OC_FORCEINLINE FVec& operator/=(const F& s)
        {
            for (size_t i = 0; i < N; ++i) v[i] = v[i] / s;
            return *this;
        }

        // ++/-- (element-wise)
        OC_FORCEINLINE FVec& operator++()
        {
            for (auto& x : v) ++x;
            return *this;
        }
        OC_FORCEINLINE FVec operator++(int)
        {
            FVec tmp = *this;
            ++(*this);
            return tmp;
        }
        OC_FORCEINLINE FVec& operator--()
        {
            for (auto& x : v) --x;
            return *this;
        }
        OC_FORCEINLINE FVec operator--(int)
        {
            FVec tmp = *this;
            --(*this);
            return tmp;
        }

        // pow and inverse (element-wise)
        OC_FORCEINLINE FVec pow(u64 exp) const
        {
            FVec r;
            for (size_t i = 0; i < N; ++i) r.v[i] = v[i].pow(exp);
            return r;
        }
        OC_FORCEINLINE FVec inverse() const
        {
            FVec r;
            for (size_t i = 0; i < N; ++i) r.v[i] = v[i].inverse();
            return r;
        }
        
		static constexpr size_t size() { return N; }
		static constexpr FVec zero() { return FVec::allSame(F::zero()); }
		static constexpr FVec one() { return FVec::allSame(F::one()); }
        static constexpr FVec allSame(F f)
        {
            FVec r;
            for (auto& vv : r.v) 
                vv = f;
            return r;
        }
    };

    template<typename F, size_t N>
    inline std::ostream& operator<<(std::ostream& o, const FVec<F, N>& x)
    {
        o << "[ ";
        for (size_t i = 0; i < N; ++i)
        {
            o << x.v[i];
            if (i + 1 != N) o << " ";
        }
        o << " ]";
        return o;
    }


    template<typename F, size_t n>
    struct ScalerOf<FVec<F, n>>
    {
        using type = F;
    };
}
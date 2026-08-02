#pragma once
#include <array>
#include <initializer_list>
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Crypto/PRNG.h"

namespace osuCrypto
{

    // static_for<N>(f):
    // Calls f(std::integral_constant<size_t, I>{}) for I in [0..N)
    template <size_t... I, class F>
    OC_FORCEINLINE void static_for_impl(std::index_sequence<I...>, F&& f)
    {
        (f(std::integral_constant<size_t, I>{}), ...);
    }

    template <size_t N, class F>
    OC_FORCEINLINE void static_for(F&& f)
    {
        if constexpr (N == 2)
        {
            f(std::integral_constant<size_t, 0>{});
            f(std::integral_constant<size_t, 1>{});
            return;
        }
        else 
            static_for_impl(std::make_index_sequence<N>{}, std::forward<F>(f));
    }


    template<typename F, size_t N>
    struct alignas(16) FVec
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
			static_for<N>([&](auto i) { v[i] = prng; });
        }

        // PRNG fill (mirrors Fp/G as convenience)
        OC_FORCEINLINE FVec& operator=(PRNG::Any prng)
        {
            static_for<N>([&](auto i) { v[i] = prng; });
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
            static_for<N>([&](auto i) {  r.v[i] = -v[i]; });
            return r;
        }

        // component-wise arithmetic
        OC_FORCEINLINE FVec operator+(const FVec& rhs) const
        {
            FVec r;
            static_for<N>([&](auto i) {  r.v[i] = v[i] + rhs.v[i]; });
            return r;
        }
        OC_FORCEINLINE FVec& operator+=(const FVec& rhs)
        {
            static_for<N>([&](auto i) {  v[i] = v[i] + rhs.v[i]; });
            return *this;
        }

        OC_FORCEINLINE FVec operator-(const FVec& rhs) const
        {
            FVec r;
            static_for<N>([&](auto i) {  r.v[i] = v[i] - rhs.v[i]; });
            return r;
        }
        OC_FORCEINLINE FVec& operator-=(const FVec& rhs)
        {
            static_for<N>([&](auto i) {  v[i] = v[i] - rhs.v[i]; });
            return *this;
        }

        OC_FORCEINLINE FVec operator*(const FVec& rhs) const
        {
            FVec r;
            static_for<N>([&](auto i) {  r.v[i] = v[i] * rhs.v[i]; });
            return r;
        }
        OC_FORCEINLINE FVec& operator*=(const FVec& rhs)
        {
            static_for<N>([&](auto i) {  v[i] = v[i] * rhs.v[i]; });
            return *this;
        }

        OC_FORCEINLINE FVec operator/(const FVec& rhs) const
        {
            FVec r;
            static_for<N>([&](auto i) {  r.v[i] = v[i] / rhs.v[i]; });
            return r;
        }
        OC_FORCEINLINE FVec& operator/=(const FVec& rhs)
        {
            static_for<N>([&](auto i) {  v[i] = v[i] / rhs.v[i]; });
            return *this;
        }

        // scalar by element (broadcast) helpers
        OC_FORCEINLINE FVec operator+(const F& s) const
        {
            FVec r;
            static_for<N>([&](auto i) { r.v[i] = v[i] + s; });
            return r;
        }
        OC_FORCEINLINE FVec& operator+=(const F& s)
        {
            static_for<N>([&](auto i) {  v[i] = v[i] + s; });
            return *this;
        }
        OC_FORCEINLINE FVec operator-(const F& s) const
        {
            FVec r;
            static_for<N>([&](auto i) { r.v[i] = v[i] - s; });
            return r;
        }
        OC_FORCEINLINE FVec& operator-=(const F& s)
        {
            static_for<N>([&](auto i) {  v[i] = v[i] - s; });
            return *this;
        }
        OC_FORCEINLINE FVec operator*(const F& s) const
        {
            FVec r;
            static_for<N>([&](auto i) {  r.v[i] = v[i] * s; });
            return r;
        }
        OC_FORCEINLINE FVec& operator*=(const F& s)
        {
            static_for<N>([&](auto i) {  v[i] = v[i] * s; });
            return *this;
        }
        OC_FORCEINLINE FVec operator/(const F& s) const
        {
            FVec r;
            static_for<N>([&](auto i) {  r.v[i] = v[i] / s; });
            return r;
        }
        OC_FORCEINLINE FVec& operator/=(const F& s)
        {
            static_for<N>([&](auto i) {  v[i] = v[i] / s; });
            return *this;
        }

        // ++/-- (element-wise)
        OC_FORCEINLINE FVec& operator++()
        {
            static_for<N>([&](auto i) { ++v[i]; });
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
            static_for<N>([&](auto i) { --v[i]; });
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
            static_for<N>([&](auto i) {  r.v[i] = v[i].pow(exp); });
            return r;
        }
        OC_FORCEINLINE FVec inverse() const
        {
            FVec r;
            static_for<N>([&](auto i) {  r.v[i] = v[i].inverse(); });
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


    // Specialized butterfly for FVec<T,2> with scalar twiddle T.
    template<typename T, size_t n>
    OC_FORCEINLINE void butterfly(FVec<T, n>& __restrict x0, FVec<T, n>& __restrict x1, const T& w)
    {
        // extract lanes
        static_for<n>([&](auto i)
            {
                const T a0 = x0.v[i];
                const T a1 = x1.v[i];
                const T t = a1 * w;
                const T y0 = a0 + t;
                const T y1 = a0 - t;
                x0.v[i] = y0;
                x1.v[i] = y1;
			});
    }


    template<typename F, size_t n>
    struct ScalerOf<FVec<F, n>>
    {
        using type = F;
    };
}
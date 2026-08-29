#pragma once
#include <array>
#include <initializer_list>
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "libOTe/Tools/CoeffCtx.h"

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


    // Coefficient operations for a fixed-width vector of scalar coefficients.
    // The scalar context defines canonical encodings and random sampling. The
    // vector context deliberately excludes alignment padding from every wire
    // representation and binary decomposition.
    template<typename F, size_t N>
    struct CoeffCtxFVec : CoeffCtxInteger
    {
        using Vector = FVec<F, N>;
        using ScalarCtx = DefaultCoeffCtx<F>;

        ScalarCtx mScalarCtx;

    private:
        template<typename V>
        static constexpr void requireVector()
        {
            static_assert(std::is_same_v<std::remove_cvref_t<V>, Vector>,
                "Coefficient type does not match this FVec context.");
        }

        template<typename Iter>
        static std::size_t rangeSize(Iter begin, Iter end)
        {
            auto count = std::distance(begin, end);
            if constexpr (std::is_signed_v<decltype(count)>)
            {
                if (count < 0)
                    throw std::invalid_argument(
                        "Coefficient range must not be reversed. " LOCATION);
            }
            return static_cast<std::size_t>(count);
        }

        OC_FORCEINLINE bool scalarIsCanonical(const F& value) const
        {
            if constexpr (requires { mScalarCtx.isCanonical(value); })
                return mScalarCtx.isCanonical(value);
            else
                return true;
        }

		OC_FORCEINLINE bool isCanonical(const Vector& value) const
		{
			bool result = true;
            static_for<N>([&](auto i)
            {
                if (!scalarIsCanonical(value.v[i]))
					result = false;
            });
			return result;
        }

    public:
		template<typename V>
		constexpr double regularNoiseFactor() const
		{
			requireVector<V>();
			return coefficientRegularNoiseFactor<F>(mScalarCtx);
		}

		OC_FORCEINLINE bool isUnit(const Vector& value) const
		{
			bool result = true;
			static_for<N>([&](auto i)
			{
				result &= isRegularNoiseUnit(value.v[i], mScalarCtx);
			});
			return result;
		}

		OC_FORCEINLINE void sampleUnit(Vector& value, PRNG& prng) const
		{
			static_for<N>([&](auto i)
			{
				sampleRegularNoiseUnit(value.v[i], prng, mScalarCtx);
			});
		}

        template<typename V>
        bool characteristicTwo() const
        {
            requireVector<V>();
            return mScalarCtx.template characteristicTwo<F>();
        }

        // A multi-lane vector is a product ring, not a field.
        template<typename V>
        OC_FORCEINLINE bool isField() const
        {
            requireVector<V>();
            return N == 1 && mScalarCtx.template isField<F>();
        }

		template<typename V>
		constexpr u64 additiveGroupBitCount() const
		{
			requireVector<V>();
			return mScalarCtx.template additiveGroupBitCount<F>();
		}

        // Retain the scalar storage width so binary decomposition can remain
        // an allocation-free view. Unused high bits of canonical scalar
        // encodings are zero; powerOfTwoUnchecked maps those rows to zero.
        template<typename V>
        constexpr u64 bitSize() const
        {
            requireVector<V>();
            return static_cast<u64>(N) * sizeof(F) * 8;
        }

        template<typename V>
        OC_FORCEINLINE BitVector binaryDecomposition(V& value) const
        {
            requireVector<V>();
            return { reinterpret_cast<u8*>(&value), bitSize<V>() };
        }

        template<typename V>
        OC_FORCEINLINE void powerOfTwoUnchecked(V& ret, u64 power) const
        {
            requireVector<V>();
            std::memset(&ret, 0, sizeof(ret));

            constexpr u64 scalarStorageBits = sizeof(F) * 8;
            auto lane = power / scalarStorageBits;
            auto lanePower = power % scalarStorageBits;
            if (lanePower < mScalarCtx.template bitSize<F>())
            {
                if constexpr (requires { mScalarCtx.powerOfTwoUnchecked(ret.v[lane], lanePower); })
                    mScalarCtx.powerOfTwoUnchecked(ret.v[lane], lanePower);
                else
                    mScalarCtx.powerOfTwo(ret.v[lane], lanePower);
            }
        }

        template<typename V>
        OC_FORCEINLINE void powerOfTwo(V& ret, u64 power) const
        {
            requireVector<V>();
            if (power >= bitSize<V>())
                throw std::out_of_range(
                    "Power-of-two index exceeds vector coefficient storage. " LOCATION);
            powerOfTwoUnchecked(ret, power);
        }

        template<typename V>
        OC_FORCEINLINE void fromBlock(V& ret, const block& seed) const
        {
            requireVector<V>();
			std::memset(&ret, 0, sizeof(ret));

			// When the scalar is a dense Fp and all lanes fit in one block,
			// sample packed candidates with rejection. Fp31x4 accepts about
			// 77% of input blocks, so the common DPF leaf path performs no
			// additional AES work. Rejected blocks are rehashed and retried.
			if constexpr (requires { F::mMod; ret.v[0].mVal; })
			{
				constexpr u64 scalarBits = log2ceil(F::mMod);
				constexpr bool denseModulus = scalarBits >= 3 && scalarBits < 64 &&
					F::mMod >= ((u64{ 1 } << scalarBits) / 8) * 7;
				if constexpr (denseModulus && N * scalarBits <= 128)
				{
					constexpr u64 mask = (u64{ 1 } << scalarBits) - 1;
					block sample = seed;
					std::array<u64, N> candidates;
					for (;;)
					{
						auto words = sample.template get<u64>();
						bool accepted = true;
						static_for<N>([&](auto i)
						{
							constexpr u64 bitOffset = i * scalarBits;
							constexpr u64 wordIdx = bitOffset / 64;
							constexpr u64 wordOffset = bitOffset % 64;
							u64 candidate = words[wordIdx] >> wordOffset;
							if constexpr (wordOffset + scalarBits > 64)
								candidate |= words[wordIdx + 1] << (64 - wordOffset);
							candidate &= mask;
							candidates[i] = candidate;
							accepted &= candidate < F::mMod;
						});

						if (accepted)
						{
							static_for<N>([&](auto i)
							{
								ret.v[i].mVal = static_cast<decltype(ret.v[i].mVal)>(candidates[i]);
							});
							return;
						}
						sample = mAesFixedKey.hashBlock(sample);
					}
				}
			}

			// The scalar context performs exact rejection sampling. Using at least
			// eight bytes per lane lets it try both halves of each lane seed before
			// entering its negligible rehash path.
            constexpr std::size_t seedBytesPerLane =
                sizeof(F) < sizeof(u64) ? sizeof(u64) : sizeof(F);
            constexpr std::size_t seedBlocks =
                (N * seedBytesPerLane + sizeof(block) - 1) / sizeof(block);
            std::array<block, seedBlocks> expanded;

            if constexpr (seedBlocks == 1)
                expanded[0] = seed;
            else
                mAesFixedKey.ecbEncCounterMode(seed, expanded);

            auto bytes = reinterpret_cast<const u8*>(expanded.data());
            static_for<N>([&](auto i)
            {
                block laneSeed = ZeroBlock;
                constexpr auto copyBytes =
                    seedBytesPerLane < sizeof(block) ? seedBytesPerLane : sizeof(block);
                std::memcpy(&laneSeed, bytes + i * seedBytesPerLane, copyBytes);
                mScalarCtx.fromBlock(ret.v[i], laneSeed);
            });
        }

        template<typename V>
        u64 byteSize() const
        {
            requireVector<V>();
            auto scalarBytes = mScalarCtx.template byteSize<F>();
            return scalarBytes * N;
        }

        template<typename SrcIter, typename DstIter>
        void serialize(SrcIter&& begin, SrcIter&& end, DstIter&& dstBegin) const
        {
            using SrcType = std::remove_cvref_t<decltype(*begin)>;
            using DstType = std::remove_cvref_t<decltype(*dstBegin)>;
            static_assert(std::is_same_v<SrcType, Vector>);
            static_assert(sizeof(DstType) == 1);

            auto count = rangeSize(begin, end);
            if (!count)
                return;

            auto scalarBytes = mScalarCtx.template byteSize<F>();
            if (scalarBytes == sizeof(F) && sizeof(Vector) == N * sizeof(F))
            {
                CoeffCtxInteger::serialize(begin, end, dstBegin);
                return;
            }

            auto vectorBytes = byteSize<Vector>();
            for (std::size_t i = 0; i < count; ++i)
            {
                auto dst = dstBegin + i * vectorBytes;
				auto src = begin[i].v;
				auto srcEnd = src + N;
                mScalarCtx.serialize(
					src, srcEnd, dst);
            }
        }

        template<typename SrcIter, typename DstIter>
        void deserialize(SrcIter&& begin, SrcIter&& end, DstIter&& dstBegin) const
        {
            using SrcType = std::remove_cvref_t<decltype(*begin)>;
            using DstType = std::remove_cvref_t<decltype(*dstBegin)>;
            static_assert(sizeof(SrcType) == 1);
            static_assert(std::is_same_v<DstType, Vector>);

            auto srcCount = rangeSize(begin, end);
            if (!srcCount)
                return;

            auto vectorBytes = byteSize<Vector>();
            auto bytes = srcCount * sizeof(SrcType);
            if (bytes % vectorBytes)
                throw std::invalid_argument(
                    "Serialized vector coefficient byte size is invalid. " LOCATION);
            auto count = bytes / vectorBytes;
            auto scalarBytes = mScalarCtx.template byteSize<F>();

            if (scalarBytes == sizeof(F) && sizeof(Vector) == N * sizeof(F))
            {
                CoeffCtxInteger::deserialize(begin, end, dstBegin);
                for (std::size_t i = 0; i < count; ++i)
				{
					if (!isCanonical(dstBegin[i]))
					{
						for (std::size_t j = 0; j < count; ++j)
							std::memset(&dstBegin[j], 0, sizeof(Vector));
						throw std::invalid_argument(
							"Noncanonical vector coefficient encoding. " LOCATION);
					}
				}
                return;
            }

			try
            {
				for (std::size_t i = 0; i < count; ++i)
				{
					std::memset(&dstBegin[i], 0, sizeof(Vector));
					auto src = begin + i * vectorBytes;
					auto srcEnd = src + vectorBytes;
					auto dst = dstBegin[i].v;
					mScalarCtx.deserialize(
						src, srcEnd, dst);
				}
			}
			catch (...)
			{
				for (std::size_t i = 0; i < count; ++i)
					std::memset(&dstBegin[i], 0, sizeof(Vector));
				throw;
            }
        }
    };


    template<typename F, size_t N>
    struct DefaultCoeffCtx_t<FVec<F, N>, FVec<F, N>>
    {
        using type = CoeffCtxFVec<F, N>;
    };
}

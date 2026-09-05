#pragma once

#include "libOTe/config.h"
#include "libOTe/Tools/CoeffCtx.h"
#include "libOTe/Tools/Field/Fp.h"
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <iterator>
#include <ostream>
#include <stdexcept>
#include <type_traits>

namespace osuCrypto
{
	using F2 = Fp<2, u8, u16>;

	// F4 = F2[u] / (u^2 + u + 1). The low bit stores the constant
	// coefficient and the high bit stores the coefficient of u.
	struct F4
	{
		u8 mValue;

		constexpr F4() = default;
		constexpr F4(u64 value)
			: mValue(static_cast<u8>(value & 1))
		{}
		constexpr F4(F2 constant, F2 extension)
			: mValue(static_cast<u8>(constant.integer() | (extension.integer() << 1)))
		{}

		static constexpr F4 fromIndex(u8 value)
		{
			F4 result;
			result.mValue = value & 3;
			return result;
		}

		static constexpr F4 fromCoefficients(u8 constant, u8 extension)
		{
			F4 result;
			result.mValue = static_cast<u8>(constant | (extension << 1));
			return result;
		}

		static constexpr F4 zero() { return F4(0); }
		static constexpr F4 one() { return F4(1); }
		static constexpr u64 order() { return 4; }

		constexpr u8 index() const { return mValue; }
		constexpr bool isCanonical() const { return mValue < 4; }
		constexpr F2 constant() const { return F2(mValue & 1); }
		constexpr F2 extension() const { return F2(mValue >> 1); }

		constexpr F4& operator+=(const F4& rhs)
		{
			mValue ^= rhs.mValue;
			return *this;
		}

		constexpr F4& operator-=(const F4& rhs)
		{
			return *this += rhs;
		}

		constexpr F4& operator*=(const F4& rhs)
		{
			const auto a0 = mValue & 1;
			const auto a1 = mValue >> 1;
			const auto b0 = rhs.mValue & 1;
			const auto b1 = rhs.mValue >> 1;
			const auto highProduct = a1 & b1;
			mValue = static_cast<u8>(
				(a0 & b0) ^ highProduct ^
				(((a0 & b1) ^ (a1 & b0) ^ highProduct) << 1));
			return *this;
		}

		constexpr F4 operator+(const F4& rhs) const
		{
			auto result = *this;
			return result += rhs;
		}

		constexpr F4 operator-(const F4& rhs) const
		{
			auto result = *this;
			return result -= rhs;
		}

		constexpr F4 operator*(const F4& rhs) const
		{
			auto result = *this;
			return result *= rhs;
		}

		constexpr F4 operator-() const { return *this; }
		constexpr bool operator==(const F4&) const = default;

		template<typename I>
			requires (std::is_integral_v<std::remove_cv_t<I>> &&
				!std::is_same_v<std::remove_cv_t<I>, bool>)
		constexpr F4 pow(I exponent) const
		{
			using E = std::remove_cv_t<I>;
			if constexpr (std::is_signed_v<E>)
				if (exponent < 0)
					throw std::invalid_argument("F4 exponent must be nonnegative. " LOCATION);

			using U = std::make_unsigned_t<E>;
			auto e = static_cast<U>(exponent);
			F4 base = *this;
			F4 result = one();
			while (e)
			{
				if (e & 1)
					result *= base;
				e >>= 1;
				if (e)
					base *= base;
			}
			return result;
		}

		constexpr F4 inverse() const
		{
			if (*this == zero())
				return zero();
			return frobenius();
		}

		constexpr F4 operator/(const F4& rhs) const
		{
			if (rhs == zero())
				throw std::domain_error("F4 division by zero. " LOCATION);
			return *this * rhs.inverse();
		}

		constexpr F4 frobenius() const
		{
			return *this * *this;
		}

		// Tr_{F4/F2}(a+b*u) = b.
		constexpr F2 trace() const
		{
			return extension();
		}
	};

	static_assert(sizeof(F4) == 1);
	static_assert(std::is_trivially_copyable_v<F4>);

	inline std::ostream& operator<<(std::ostream& out, const F4& value)
	{
		return out << static_cast<u32>(value.mValue & 1) << "+"
			<< static_cast<u32>(value.mValue >> 1) << "u";
	}

	struct CoeffCtxF4 : CoeffCtxInteger
	{
		// Multiplication by u mixes the two F2 components. In particular, the
		// prime-subfield basis element 1 maps outside F2. Binary structured LPN
		// codes require this instead of the scalar context's identity mulConst.
		OC_FORCEINLINE void mulConst(F4& ret, const F4& value) const
		{
			ret = value * F4::fromCoefficients(0, 1);
		}

		template<typename F>
		constexpr double regularNoiseFactor() const
		{
			static_assert(std::is_same_v<std::remove_cvref_t<F>, F4>);
			return 4.0 / 3.0;
		}

		template<typename F>
		OC_FORCEINLINE bool isField() const
		{
			static_assert(std::is_same_v<std::remove_cvref_t<F>, F4>);
			return true;
		}

		template<typename F>
		constexpr u64 additiveGroupBitCount() const
		{
			static_assert(std::is_same_v<std::remove_cvref_t<F>, F4>);
			return 1;
		}

		template<typename F>
		constexpr u64 bitSize() const
		{
			static_assert(std::is_same_v<std::remove_cvref_t<F>, F4>);
			return 2;
		}

		OC_FORCEINLINE BitVector binaryDecomposition(F4& value) const
		{
			BitVector result(2);
			result[0] = value.mValue & 1;
			result[1] = value.mValue >> 1;
			return result;
		}

		template<typename F>
		OC_FORCEINLINE void powerOfTwoUnchecked(F& result, u64 power) const
		{
			static_assert(std::is_same_v<std::remove_cvref_t<F>, F4>);
			result = power ? F4::fromCoefficients(0, 1) : F4::one();
		}

		template<typename F>
		OC_FORCEINLINE void powerOfTwo(F& result, u64 power) const
		{
			if (power >= bitSize<F>())
				throw std::out_of_range("F4 additive decomposition index is out of range. " LOCATION);
			powerOfTwoUnchecked(result, power);
		}

		OC_FORCEINLINE void fromBlock(F4& result, const block& sample) const
		{
			result.mValue = sample.get<u8>(0) & 3;
		}

		template<typename SrcIter, typename DstIter>
		void deserialize(SrcIter begin, SrcIter end, DstIter dst) const
		{
			const auto bytes = std::distance(begin, end);
			if (bytes < 0)
				throw std::invalid_argument("Invalid serialized F4 coefficient length. " LOCATION);

			CoeffCtxInteger::deserialize(begin, end, dst);
			for (u64 i = 0; i < static_cast<u64>(bytes); ++i)
				if (!dst[i].isCanonical())
					throw std::invalid_argument("Received a non-canonical F4 coefficient. " LOCATION);
		}

		OC_FORCEINLINE F4 sample(PRNG& prng) const
		{
			F4 result;
			fromBlock(result, prng.get());
			return result;
		}

		OC_FORCEINLINE F4 sampleNonZero(PRNG& prng) const
		{
			F4 result;
			do
				result = sample(prng);
			while (result == F4::zero());
			return result;
		}
	};

	template<>
	struct DefaultCoeffCtx_t<F4, F4>
	{
		using type = CoeffCtxF4;
	};
}

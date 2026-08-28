#pragma once

#include "libOTe/config.h"
#include "libOTe/Tools/CoeffCtx.h"
#include "libOTe/Tools/Field/Fp.h"
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <ostream>
#include <stdexcept>
#include <type_traits>

namespace osuCrypto
{
	using F3 = Fp<3, u8, u16>;

	// F9 = F3[u] / (u^2 + 1). Elements are stored as a + b*u with
	// independently canonical F3 coefficients. The two-byte representation is
	// intentional: it keeps the arithmetic cheap and gives the DPF coefficient
	// context a canonical, padding-free serialization.
	struct F9
	{
		u8 mA;
		u8 mB;

		constexpr F9() = default;
		constexpr F9(u64 value)
			: mA(static_cast<u8>(value % 3))
			, mB(0)
		{}
		constexpr F9(F3 a, F3 b)
			: mA(static_cast<u8>(a.integer()))
			, mB(static_cast<u8>(b.integer()))
		{}

		static constexpr F9 fromIndex(u8 value)
		{
			value %= 9;
			return F9::fromCoefficients(value % 3, value / 3);
		}

		static constexpr F9 fromCoefficients(u8 a, u8 b)
		{
			F9 value;
			value.mA = a;
			value.mB = b;
			return value;
		}

		static constexpr F9 zero() { return F9(0); }
		static constexpr F9 one() { return F9(1); }
		static constexpr u64 order() { return 9; }

		constexpr u8 index() const
		{
			return static_cast<u8>(mA + 3 * mB);
		}

		constexpr bool isCanonical() const
		{
			return mA < 3 && mB < 3;
		}

		constexpr F3 base() const { return F3(mA); }
		constexpr F3 extension() const { return F3(mB); }

		constexpr F9& operator+=(const F9& rhs)
		{
			mA = add3(mA, rhs.mA);
			mB = add3(mB, rhs.mB);
			return *this;
		}

		constexpr F9& operator-=(const F9& rhs)
		{
			mA = sub3(mA, rhs.mA);
			mB = sub3(mB, rhs.mB);
			return *this;
		}

		constexpr F9& operator*=(const F9& rhs)
		{
			const auto ac = static_cast<u16>(mA) * rhs.mA;
			const auto bd = static_cast<u16>(mB) * rhs.mB;
			const auto ad = static_cast<u16>(mA) * rhs.mB;
			const auto bc = static_cast<u16>(mB) * rhs.mA;
			mA = static_cast<u8>((ac + 2 * bd) % 3);
			mB = static_cast<u8>((ad + bc) % 3);
			return *this;
		}

		constexpr F9 operator+(const F9& rhs) const
		{
			auto result = *this;
			return result += rhs;
		}

		constexpr F9 operator-(const F9& rhs) const
		{
			auto result = *this;
			return result -= rhs;
		}

		constexpr F9 operator*(const F9& rhs) const
		{
			auto result = *this;
			return result *= rhs;
		}

		constexpr F9 operator-() const
		{
			return fromCoefficients(neg3(mA), neg3(mB));
		}

		constexpr bool operator==(const F9&) const = default;

		template<typename I>
			requires (std::is_integral_v<std::remove_cv_t<I>> &&
				!std::is_same_v<std::remove_cv_t<I>, bool>)
		constexpr F9 pow(I exponent) const
		{
			using E = std::remove_cv_t<I>;
			if constexpr (std::is_signed_v<E>)
				if (exponent < 0)
					throw std::invalid_argument("F9 exponent must be nonnegative. " LOCATION);

			using U = std::make_unsigned_t<E>;
			auto e = static_cast<U>(exponent);
			F9 base = *this;
			F9 result = one();
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

		constexpr F9 inverse() const
		{
			if (*this == zero())
				return zero();
			return pow(7);
		}

		constexpr F9 operator/(const F9& rhs) const
		{
			if (rhs == zero())
				throw std::domain_error("F9 division by zero. " LOCATION);
			return *this * rhs.inverse();
		}

		// The p-power Frobenius for p=3 is conjugation: (a+b*u)^3=a-b*u.
		constexpr F9 frobenius() const
		{
			return fromCoefficients(mA, neg3(mB));
		}

		// Tr_{F9/F3}(a+b*u) = (a+b*u) + (a+b*u)^3 = 2a.
		constexpr F3 trace() const
		{
			return F3(2 * mA);
		}

	private:
		static constexpr u8 add3(u8 lhs, u8 rhs)
		{
			auto value = static_cast<u8>(lhs + rhs);
			return value >= 3 ? static_cast<u8>(value - 3) : value;
		}

		static constexpr u8 sub3(u8 lhs, u8 rhs)
		{
			return lhs >= rhs ? static_cast<u8>(lhs - rhs) :
				static_cast<u8>(lhs + 3 - rhs);
		}

		static constexpr u8 neg3(u8 value)
		{
			return value ? static_cast<u8>(3 - value) : 0;
		}
	};

	static_assert(sizeof(F9) == 2);
	static_assert(std::is_trivially_copyable_v<F9>);

	inline std::ostream& operator<<(std::ostream& out, const F9& value)
	{
		return out << static_cast<u32>(value.mA) << "+"
			<< static_cast<u32>(value.mB) << "u";
	}

	// DPF/VOLE coefficient operations for the additive group of F9. The
	// decomposition is (a_0, a_1, b_0, b_1), corresponding to the additive
	// generators (1, 2, u, 2u).
	struct CoeffCtxF9 : CoeffCtxInteger
	{
		template<typename F>
		OC_FORCEINLINE bool isField() const
		{
			static_assert(std::is_same_v<std::remove_cvref_t<F>, F9>);
			return true;
		}

		template<typename F>
		constexpr u64 additiveGroupBitCount() const
		{
			static_assert(std::is_same_v<std::remove_cvref_t<F>, F9>);
			return 2;
		}

		template<typename F>
		constexpr u64 bitSize() const
		{
			static_assert(std::is_same_v<std::remove_cvref_t<F>, F9>);
			return 4;
		}

		OC_FORCEINLINE BitVector binaryDecomposition(F9& value) const
		{
			BitVector result(4);
			result[0] = value.mA & 1;
			result[1] = value.mA >> 1;
			result[2] = value.mB & 1;
			result[3] = value.mB >> 1;
			return result;
		}

		template<typename F>
		OC_FORCEINLINE void powerOfTwoUnchecked(F& result, u64 power) const
		{
			static_assert(std::is_same_v<std::remove_cvref_t<F>, F9>);
			static constexpr F9 generators[] = {
				F9::fromCoefficients(1, 0),
				F9::fromCoefficients(2, 0),
				F9::fromCoefficients(0, 1),
				F9::fromCoefficients(0, 2)
			};
			result = generators[power];
		}

		template<typename F>
		OC_FORCEINLINE void powerOfTwo(F& result, u64 power) const
		{
			if (power >= bitSize<F>())
				throw std::out_of_range("F9 additive decomposition index is out of range. " LOCATION);
			powerOfTwoUnchecked(result, power);
		}

		OC_FORCEINLINE void fromBlock(F9& result, const block& sample) const
		{
			result.mA = static_cast<u8>(fieldSampling::fromBlock(sample, 3));
			const auto second = mAesFixedKey.hashBlock(
				sample ^ block(0x6b207478632d3946, 0x646c6569662d796e));
			result.mB = static_cast<u8>(fieldSampling::fromBlock(second, 3));
		}

		template<typename SrcIter, typename DstIter>
		void deserialize(SrcIter begin, SrcIter end, DstIter dst) const
		{
			const auto bytes = std::distance(begin, end);
			if (bytes < 0 || static_cast<u64>(bytes) % sizeof(F9))
				throw std::invalid_argument("Invalid serialized F9 coefficient length. " LOCATION);

			CoeffCtxInteger::deserialize(begin, end, dst);
			const auto count = static_cast<u64>(bytes) / sizeof(F9);
			for (u64 i = 0; i < count; ++i)
				if (!dst[i].isCanonical())
					throw std::invalid_argument("Received a non-canonical F9 coefficient. " LOCATION);
		}

		OC_FORCEINLINE F9 sample(PRNG& prng) const
		{
			F9 result;
			fromBlock(result, prng.get());
			return result;
		}

		OC_FORCEINLINE F9 sampleNonZero(PRNG& prng) const
		{
			F9 result;
			do
				result = sample(prng);
			while (result == F9::zero());
			return result;
		}
	};

	template<>
	struct DefaultCoeffCtx_t<F9, F9>
	{
		using type = CoeffCtxF9;
	};
}

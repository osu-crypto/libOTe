#pragma once

#include "libOTe/Tools/Field/F4.h"
#include "libOTe/Tools/Field/F9.h"
#include "cryptoTools/Common/Defines.h"
#include <concepts>
#include <limits>
#include <span>
#include <stdexcept>

namespace osuCrypto
{
	template<typename Ctx>
	concept AnyFieldContext = requires(
		const Ctx& ctx,
		typename Ctx::Ext ext,
		span<typename Ctx::Ext> values,
		u64 power,
		u64 dimensions)
	{
		typename Ctx::Base;
		typename Ctx::Ext;
		typename Ctx::DpfCoeffCtx;
		{ Ctx::extensionDegree } -> std::convertible_to<u64>;
		{ Ctx::baseCharacteristic } -> std::convertible_to<u64>;
		{ Ctx::coordinateSize } -> std::convertible_to<u64>;
		{ Ctx::coordinateBits } -> std::convertible_to<u64>;
		{ Ctx::fieldBits } -> std::convertible_to<u64>;
		{ Ctx::domainSize(dimensions) } -> std::same_as<u64>;
		{ ctx.dpfCoeffCtx() } -> std::same_as<typename Ctx::DpfCoeffCtx>;
		{ ctx.frobenius(ext, power) } -> std::same_as<typename Ctx::Ext>;
		{ ctx.trace(ext) } -> std::same_as<typename Ctx::Base>;
		{ ctx.traceBasis(power) } -> std::same_as<typename Ctx::Ext>;
		{ ctx.positionCoordinate(power, dimensions) } -> std::same_as<u64>;
		{ ctx.frobeniusCoordinate(power, dimensions) } -> std::same_as<u64>;
		{ ctx.transform(values, dimensions) } -> std::same_as<void>;
	};

	// Context for OLE over F3 using F9 as the QA-SD extension field. The
	// construction sees only this interface; later fields can supply their own
	// arithmetic, Frobenius, basis, coordinate conversion, and transform without
	// adding runtime dispatch to expansion.
	struct AnyFieldF9Ctx
	{
		using Base = F3;
		using Ext = F9;
		using DpfCoeffCtx = CoeffCtxF9;

		static constexpr u64 baseCharacteristic = 3;
		static constexpr u64 extensionDegree = 2;
		static constexpr u64 coordinateSize = 8;
		static constexpr u64 coordinateBits = 3;
		static constexpr u64 fieldBits = 4;

		constexpr DpfCoeffCtx dpfCoeffCtx() const { return {}; }

		constexpr Ext frobenius(Ext value, u64 power) const
		{
			return power & 1 ? value.frobenius() : value;
		}

		constexpr Base trace(Ext value) const
		{
			return value.trace();
		}

		// xi=1+u has order eight. (xi,xi^3) is the normal basis used by
		// Construction 1 of the any-field PCG.
		constexpr Ext traceBasis(u64 index) const
		{
			if (index >= extensionDegree)
				throw std::out_of_range("F9 trace-basis index is out of range. " LOCATION);
			return index == 0 ?
				Ext::fromCoefficients(1, 1) :
				Ext::fromCoefficients(1, 2);
		}

		constexpr Ext rootOfUnity() const
		{
			return Ext::fromCoefficients(1, 1);
		}

		constexpr u64 positionCoordinate(u64 position, u64 coordinate) const
		{
			return (position >> (coordinateBits * coordinate)) & (coordinateSize - 1);
		}

		constexpr u64 frobeniusCoordinate(u64 coordinate, u64 power) const
		{
			return power & 1 ? (3 * coordinate) & (coordinateSize - 1) : coordinate;
		}

		static u64 domainSize(u64 dimensions)
		{
			u64 result = 1;
			for (u64 i = 0; i < dimensions; ++i)
			{
				if (result > std::numeric_limits<u64>::max() / coordinateSize)
					throw std::length_error("Any-field domain size overflows u64. " LOCATION);
				result *= coordinateSize;
			}
			return result;
		}

		// In-place tensor product of fixed eight-point cyclic transforms. Each
		// coordinate is returned in bit-reversed frequency order. This permutation
		// is shared by every operand and therefore does not affect pointwise ring
		// multiplication or the generated OLE correlations.
		void transform(span<Ext> values, u64 dimensions) const
		{
			const auto expected = domainSize(dimensions);
			if (values.size() != expected)
				throw std::invalid_argument("F9 transform input has the wrong size. " LOCATION);

			u64 stride = 1;
			for (u64 dimension = 0; dimension < dimensions; ++dimension)
			{
				const auto groupStride = stride * coordinateSize;
				for (u64 group = 0; group < values.size(); group += groupStride)
					for (u64 offset = 0; offset < stride; ++offset)
						transform8(values.data() + group + offset, stride);
				stride = groupStride;
			}
		}

	private:
		static OC_FORCEINLINE void transform8(Ext* values, u64 stride)
		{
			const Ext omega = Ext::fromCoefficients(1, 1);
			const Ext omega2 = Ext::fromCoefficients(0, 2);
			const Ext omega3 = Ext::fromCoefficients(1, 2);

			const Ext x0 = values[0 * stride];
			const Ext x1 = values[1 * stride];
			const Ext x2 = values[2 * stride];
			const Ext x3 = values[3 * stride];
			const Ext x4 = values[4 * stride];
			const Ext x5 = values[5 * stride];
			const Ext x6 = values[6 * stride];
			const Ext x7 = values[7 * stride];

			const Ext b0 = x0 + x4;
			const Ext b1 = x1 + x5;
			const Ext b2 = x2 + x6;
			const Ext b3 = x3 + x7;
			const Ext b4 = x0 - x4;
			const Ext b5 = (x1 - x5) * omega;
			const Ext b6 = (x2 - x6) * omega2;
			const Ext b7 = (x3 - x7) * omega3;

			const Ext c0 = b0 + b2;
			const Ext c1 = b1 + b3;
			const Ext c2 = b0 - b2;
			const Ext c3 = (b1 - b3) * omega2;
			const Ext c4 = b4 + b6;
			const Ext c5 = b5 + b7;
			const Ext c6 = b4 - b6;
			const Ext c7 = (b5 - b7) * omega2;

			values[0 * stride] = c0 + c1;
			values[1 * stride] = c0 - c1;
			values[2 * stride] = c2 + c3;
			values[3 * stride] = c2 - c3;
			values[4 * stride] = c4 + c5;
			values[5 * stride] = c4 - c5;
			values[6 * stride] = c6 + c7;
			values[7 * stride] = c6 - c7;
		}
	};

	// Context for OLE over F2 using F4 as the QA-SD extension field. Its
	// coordinate group has order three, so this context exercises the general
	// modular position conversion rather than the power-of-two fast path.
	struct AnyFieldF4Ctx
	{
		using Base = F2;
		using Ext = F4;
		using DpfCoeffCtx = CoeffCtxF4;

		static constexpr u64 baseCharacteristic = 2;
		static constexpr u64 extensionDegree = 2;
		static constexpr u64 coordinateSize = 3;
		static constexpr u64 coordinateBits = 2;
		static constexpr u64 fieldBits = 2;

		constexpr DpfCoeffCtx dpfCoeffCtx() const { return {}; }

		constexpr Ext frobenius(Ext value, u64 power) const
		{
			return power & 1 ? value.frobenius() : value;
		}

		constexpr Base trace(Ext value) const
		{
			return value.trace();
		}

		// u has order three, and (u,u^2) is a normal basis of F4/F2.
		constexpr Ext traceBasis(u64 index) const
		{
			if (index >= extensionDegree)
				throw std::out_of_range("F4 trace-basis index is out of range. " LOCATION);
			return index == 0 ?
				Ext::fromCoefficients(0, 1) :
				Ext::fromCoefficients(1, 1);
		}

		constexpr Ext rootOfUnity() const
		{
			return Ext::fromCoefficients(0, 1);
		}

		constexpr u64 positionCoordinate(u64 position, u64 coordinate) const
		{
			for (u64 i = 0; i < coordinate; ++i)
				position /= coordinateSize;
			return position % coordinateSize;
		}

		constexpr u64 frobeniusCoordinate(u64 coordinate, u64 power) const
		{
			return power & 1 ? (2 * coordinate) % coordinateSize : coordinate;
		}

		static u64 domainSize(u64 dimensions)
		{
			u64 result = 1;
			for (u64 i = 0; i < dimensions; ++i)
			{
				if (result > std::numeric_limits<u64>::max() / coordinateSize)
					throw std::length_error("Any-field domain size overflows u64. " LOCATION);
				result *= coordinateSize;
			}
			return result;
		}

		void transform(span<Ext> values, u64 dimensions) const
		{
			const auto expected = domainSize(dimensions);
			if (values.size() != expected)
				throw std::invalid_argument("F4 transform input has the wrong size. " LOCATION);

			u64 stride = 1;
			for (u64 dimension = 0; dimension < dimensions; ++dimension)
			{
				const auto groupStride = stride * coordinateSize;
				for (u64 group = 0; group < values.size(); group += groupStride)
					for (u64 offset = 0; offset < stride; ++offset)
						transform3(values.data() + group + offset, stride);
				stride = groupStride;
			}
		}

	private:
		static OC_FORCEINLINE void transform3(Ext* values, u64 stride)
		{
			const Ext omega = Ext::fromCoefficients(0, 1);
			const Ext omega2 = Ext::fromCoefficients(1, 1);
			const Ext x0 = values[0 * stride];
			const Ext x1 = values[1 * stride];
			const Ext x2 = values[2 * stride];
			values[0 * stride] = x0 + x1 + x2;
			values[1 * stride] = x0 + omega * x1 + omega2 * x2;
			values[2 * stride] = x0 + omega2 * x1 + omega * x2;
		}
	};

	static_assert(AnyFieldContext<AnyFieldF9Ctx>);
	static_assert(AnyFieldContext<AnyFieldF4Ctx>);

	// The public aliases use fixed parameter policies targeting 128-bit QA-SD
	// security. These values are deliberately not exposed through
	// AnyFieldOle::init(): callers request OLEs, while the construction selects and
	// rounds its QA-SD domain internally. See ePrint 2025/169 for the original
	// estimates and ePrint 2025/892 for the evaluation/interpolation attack that
	// motivates the larger compression factors.
	struct AnyFieldF4Params128
	{
		// Nine public cosets with two points in each give generalized regular
		// weight 18. With c=8, the total syndrome weight is 144.
		static constexpr u64 compressionFactor = 8;
		static constexpr u64 blockDimensions = 2;
		static constexpr u64 pointsPerBlock = 2;
		static constexpr u64 minimumDimension = 19;
		static constexpr u64 maximumDimension = 27;
	};

	struct AnyFieldF9Params128
	{
		// One radix-eight quotient coordinate gives eight public cosets. Three
		// points per coset conservatively give total syndrome weight 192.
		static constexpr u64 compressionFactor = 8;
		static constexpr u64 blockDimensions = 1;
		static constexpr u64 pointsPerBlock = 3;
		static constexpr u64 minimumDimension = 10;
		static constexpr u64 maximumDimension = 20;
	};

	template<typename Context>
	struct AnyFieldDefaultParams;

	template<>
	struct AnyFieldDefaultParams<AnyFieldF4Ctx>
	{
		using type = AnyFieldF4Params128;
	};

	template<>
	struct AnyFieldDefaultParams<AnyFieldF9Ctx>
	{
		using type = AnyFieldF9Params128;
	};
}

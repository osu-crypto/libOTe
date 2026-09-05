#pragma once

#include "cryptoTools/Common/Defines.h"
#include <algorithm>
#include <cmath>
#include <limits>
#include <stdexcept>

namespace osuCrypto
{
	// Shared public parameter policy for the Ring-LPN, FOLEAGE, and AnyField
	// PCGs. The caller can select the syndrome compression factor c, or leave it
	// zero when a construction supports automatic cost-based selection. The
	// construction derives t, the number of noisy positions in each of the c
	// sparse polynomials, and then rounds t up to a layout it can expand
	// efficiently.
	//
	// Parameter selection combines independent checks rather than treating a
	// code-distance heuristic as a proof of security:
	//
	//  * Low-weight decoding. At rate 1 - 1/c and total weight c*t, Prange's
	//    low-weight exponent is c*t*log2(c). We require 128 bits. This curve
	//    reproduces the standard Ring-LPN points (c,t)=(2,64),(4,16), the
	//    FOLEAGE point (3,27), and the FOLEAGE folding-estimator regression
	//    (c,t,dimension)=(5,12,15).
	//
	//  * Linear-character tests. These get a separate 64-bit robustness floor.
	//    For a q-ary random row we use the pseudo relative distance
	//    delta=(c-1)(1-1/q)/c. Uniform coefficients give one-position bias
	//    1-delta; nonzero coefficients give 1-q*delta/(q-1). This is a
	//    heuristic safeguard, not a claim about the exact minimum distance of
	//    the structured code.
	//
	//  * QA-SD evaluation/interpolation. This depends on the coefficient-field
	//    cardinality q, group-coordinate radix d, and group dimension. It cannot
	//    be repaired merely by increasing t, so unsafe (c,dimension) pairs are
	//    rejected independently by qaSdHasNoExpectedEvaluationPoint().
	//
	// Folding and interpolation remain construction-specific checks. In
	// particular, this common layer must not be read as a proof that every group
	// algebra with the returned c and t is secure. New attacks should be added as
	// independent floors or structural rejection predicates.
	struct LpnParameters
	{
		u64 mCompressionFactor = 0;
		u64 mNoiseWeight = 0;
		u64 mDecodingWeight = 0;
		u64 mLinearWeight = 0;
	};

	// User-facing knob shared by the LPN-based PCGs. The implementation derives
	// the noise weight from this value and the construction's security checks.
	// Neither c nor t changes the generated arithmetic kernel, so both remain
	// runtime state.
	struct LpnParameterConfig
	{
		// Zero selects the construction's runtime cost minimum among the secure
		// candidates. A value in [2,8] requests that c explicitly.
		u64 mCompressionFactor = 0;
	};

	enum class LpnCoefficientDistribution
	{
		// Coefficients are uniform in F_q, including zero. This is the
		// stationary-noise model used by RingLPN and FOLEAGE.
		Uniform,

		// Coefficients are uniform in F_q^*. This is the generalized-regular
		// distribution currently used by AnyField.
		NonZero
	};

	namespace lpnParameters
	{
		constexpr u64 SecurityBits = 128;
		constexpr u64 LinearTestBits = 64;
		constexpr u64 FixedPointScale = u64{ 1 } << 20;

		// Conservative lower approximations to log2(c), in Q20. Restricting c
		// to the range implemented by all three constructions also keeps their
		// packed public-coefficient representations bounded.
		constexpr u64 log2CompressionQ20(u64 c)
		{
			switch (c)
			{
			case 2: return 1048576; // 1.0000000000
			case 3: return 1661953; // 1.5849625007
			case 4: return 2097152; // 2.0000000000
			case 5: return 2434718; // 2.3219280948
			case 6: return 2710529; // 2.5849625007
			case 7: return 2943724; // 2.8073549221
			case 8: return 3145728; // 3.0000000000
			default: return 0;
			}
		}

		constexpr u64 divCeil(u64 numerator, u64 denominator)
		{
			return numerator / denominator + (numerator % denominator != 0);
		}

		constexpr u64 decodingWeight128(u64 compressionFactor)
		{
			const auto logC = log2CompressionQ20(compressionFactor);
			return logC ? divCeil(
				SecurityBits * FixedPointScale,
				compressionFactor * logC) : 0;
		}

		constexpr u64 roundUpPower(u64 value, u64 radix)
		{
			if (!value || radix < 2)
				return 0;
			u64 result = 1;
			while (result < value)
			{
				if (result > std::numeric_limits<u64>::max() / radix)
					return 0;
				result *= radix;
			}
			return result;
		}

		inline u64 linearWeight(
			u64 compressionFactor,
			double coefficientFieldCardinality,
			LpnCoefficientDistribution coefficientDistribution)
		{
			if (compressionFactor < 2 || compressionFactor > 8)
				throw std::invalid_argument(
					"LPN compression factor must be in [2, 8]. " LOCATION);
			if (!(coefficientFieldCardinality >= 2.0) ||
				!std::isfinite(coefficientFieldCardinality))
				throw std::invalid_argument(
					"LPN coefficient-field cardinality must be finite and at least two. " LOCATION);

			const auto c = static_cast<double>(compressionFactor);
			const auto delta = (c - 1.0) / c *
				(1.0 - 1.0 / coefficientFieldCardinality);
			const auto hitFactor = coefficientDistribution ==
				LpnCoefficientDistribution::Uniform ? 1.0 :
				coefficientFieldCardinality /
				(coefficientFieldCardinality - 1.0);
			const auto bitsPerPosition = -std::log2(1.0 - hitFactor * delta);
			return static_cast<u64>(std::ceil(
				static_cast<double>(LinearTestBits) /
				(c * bitsPerPosition)));
		}

		inline LpnParameters select(
			u64 compressionFactor,
			double coefficientFieldCardinality,
			LpnCoefficientDistribution coefficientDistribution =
			LpnCoefficientDistribution::Uniform)
		{
			const auto decoding = decodingWeight128(compressionFactor);
			if (!decoding)
				throw std::invalid_argument(
					"LPN compression factor must be in [2, 8]. " LOCATION);
			const auto linear = linearWeight(
				compressionFactor,
				coefficientFieldCardinality,
				coefficientDistribution);
			return {
				compressionFactor,
				std::max(decoding, linear),
				decoding,
				linear
			};
		}

		// The interpolation attack first looks for evaluation points where all
		// c-1 sampled public polynomials vanish. For G=(Z_d)^dimension over F_q,
		// the expected number of usable points is approximately
		//
		//   d^(dimension-1) / q^(d(c-1)).
		//
		// A negative base-two logarithm therefore rules out even one expected
		// evaluation point. This is a structural precondition, not a 128-bit
		// probability bound; obtaining a point is only the first stage of the
		// interpolation attack.
		inline double qaSdExpectedEvaluationLog2(
			u64 compressionFactor,
			double coefficientFieldCardinality,
			u64 coordinateRadix,
			u64 dimension)
		{
			if (compressionFactor < 2 || compressionFactor > 8)
				throw std::invalid_argument(
					"QA-SD compression factor must be in [2, 8]. " LOCATION);
			if (!(coefficientFieldCardinality >= 2.0) ||
				!std::isfinite(coefficientFieldCardinality) ||
				coordinateRadix < 2 || !dimension)
				throw std::invalid_argument(
					"QA-SD interpolation parameters are invalid. " LOCATION);

			return static_cast<double>(dimension - 1) *
				std::log2(static_cast<double>(coordinateRadix)) -
				static_cast<double>(coordinateRadix) *
				static_cast<double>(compressionFactor - 1) *
				std::log2(coefficientFieldCardinality);
		}

		inline bool qaSdHasNoExpectedEvaluationPoint(
			u64 compressionFactor,
			double coefficientFieldCardinality,
			u64 coordinateRadix,
			u64 dimension)
		{
			return qaSdExpectedEvaluationLog2(
				compressionFactor,
				coefficientFieldCardinality,
				coordinateRadix,
				dimension) < 0.0;
		}
	}
}

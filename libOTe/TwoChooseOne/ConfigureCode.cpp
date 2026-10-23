#include "ConfigureCode.h"


#include "cryptoTools/Common/Range.h"
#include "libOTe/TwoChooseOne/TcoOtDefines.h"
#include "libOTe/Tools/Tools.h"
#include "libOTe/Tools/QuasiCyclicCode.h"
#include "libOTe/Tools/EACode/EACode.h"
#include "libOTe/Tools/ExConvCode/ExConvCode.h"
#include "libOTe/Tools/ExConvCode/ExConvCode.h"
#include <cmath>
namespace osuCrypto
{

    // Parameter selection deliberately combines two different safeguards.
    //
    // First, delta is only a pseudo minimum-distance estimate for these
    // structured codes. We nevertheless require 64 bits of robustness against
    // the corresponding linear-character test. For stationary noise, a hit has
    // a uniform coefficient (including zero), giving bias (1-delta)^t. For
    // regular noise over F_q, the coefficient is uniform in F_q^*, giving
    // (1-q/(q-1)*delta)^t. Binary nonzero noise and odd noise over Z_(2^k)
    // both use the q=2 factor. This is why large-field regular noise approaches
    // stationary noise rather than the binary formula. Thus the pseudo-distance
    // floor is ceil(-64/log2(1-a*delta)), where a is the applicable factor.
    //
    // Second, pseudo distance does not model the best non-linear/algebraic
    // attacks. We independently require at least secParam noise positions.
    // Current regular-LPN estimates put the small binary N=2048, t=128 case
    // below 128 bits, so binary regular-noise sizes through 2048 use
    // ceil(9*secParam/8) instead.
    //
    // For stationary noise, this floor counts the secret support positions,
    // not the nonzero coefficients in one sampled error vector. The SSD
    // algebraic analysis already models coefficients uniform in the field,
    // including zero, and its evaluated rate-one-half instances require at
    // most 107 support positions for 128-bit security. Scaling this floor by
    // the reciprocal nonzero probability would instead partially reinstate a
    // 128-bit linear-test requirement: the effect of zero coefficients on
    // linear tests (including ISD-style tests) is already captured by the
    // stationary bias (1-delta)^t above.
    //
    // These attack floors are conservative calibrations, not proofs for every
    // structured or nonbinary LPN instance. Both the floors and the pseudo
    // distances should be revisited when tighter estimators become available.
    // The selected t is the maximum of the two safeguards and the legacy
    // small-instance implementation floor, rounded up to a multiple of eight.
    u64 getRegNoiseWeight(
        double pseudoMinDistRatio,
        u64 N,
        u64 secParam,
        SdNoiseDistribution nd,
        SdNoiseSecurityModel securityModel)
    {
        constexpr u64 pseudoDistanceSecurity = 64;

        if (pseudoMinDistRatio > 0.5 || pseudoMinDistRatio <= 0)
            throw RTE_LOC;
        if (!std::isfinite(securityModel.mRegularNoiseFactor) ||
            securityModel.mRegularNoiseFactor < 1.0 ||
            securityModel.mRegularNoiseFactor > 2.0)
            throw std::invalid_argument(
                "Regular-noise character factor must be in [1, 2]. " LOCATION);

        double hitFactor;
        if (nd == SdNoiseDistribution::Regular)
            hitFactor = securityModel.mRegularNoiseFactor;
        else if (nd == SdNoiseDistribution::Stationary)
            hitFactor = 1.0;
        else
            throw RTE_LOC;

        const auto bias = 1.0 - hitFactor * pseudoMinDistRatio;
        const auto pseudoDistanceWeight = bias == 0.0 ? u64{ 1 } :
            static_cast<u64>(std::ceil(
                -double(pseudoDistanceSecurity) / std::log2(bias)));

        auto attackWeight = secParam;
        if (nd == SdNoiseDistribution::Regular &&
            securityModel.mRegularNoiseFactor == 2.0 && N <= 2048)
            attackWeight = divCeil(secParam * 9, u64{ 8 });

        auto t = std::max({ u64{ 40 }, pseudoDistanceWeight, attackWeight });
        if(N < 512)
            t = std::max<u64>(t, 64);

        return roundUpTo(t, 8);
    }


    void EAConfigure(
        MultType mMultType,
        u64& scaler,
        u64& expanderWeight,
        double& minDist
    )
    {
        scaler = 5;
        switch (mMultType)
        {
        case osuCrypto::MultType::ExAcc40:
            expanderWeight = 41;
            // Fixed-weight EA is asymptotically vulnerable to signature
            // collisions. Weight 41 is retained for practical dimensions with
            // explicit margin below the generator-row heuristic.
            minDist = 0.20;
            break;
        default:
            throw RTE_LOC;
            break;
        }
    }


    void ExConvConfigure(
        MultType mMultType,
        u64& scaler,
        u64& expanderWeight,
        u64& accumulatorWeight,
        double& minDist)
    {
        scaler = 2;

        switch (mMultType)
        {
        case osuCrypto::MultType::ExConv7x24:
            accumulatorWeight = 24;
            expanderWeight = 7;
            minDist = 0.15; // aggressive pseudo-distance estimate
            break;
        case osuCrypto::MultType::ExConv21x24:
            accumulatorWeight = 24;
            expanderWeight = 21;
            minDist = 0.20; // conservative pseudo-distance estimate
            break;
        default:
            throw RTE_LOC;
            break;
        }
    }
}

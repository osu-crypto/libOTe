#pragma once
#include "libOTe/config.h"
#include "cryptoTools/Common/Defines.h"
#include "libOTe/TwoChooseOne/TcoOtDefines.h"
#include <limits>
#include <stdexcept>

namespace osuCrypto
{

    enum class SdNoiseDistribution
    {
        Regular, // Use the regular noise generation method
        Stationary, // use the stationary noise model
    };

    // Describes the worst-case linear-character decay caused by one selected
    // regular-noise position. If delta is the codeword's relative weight, the
    // one-sample bias is 1 - mRegularNoiseFactor * delta.
    struct SdNoiseSecurityModel
    {
        double mRegularNoiseFactor = 2.0;

        static constexpr SdNoiseSecurityModel binary()
        {
            return { 2.0 };
        }
    };


    inline std::ostream& operator<<(std::ostream& o, SdNoiseDistribution m)
    {
        switch (m)
        {
        case osuCrypto::SdNoiseDistribution::Regular:
            o << "Regular";
            break;
        case osuCrypto::SdNoiseDistribution::Stationary:
            o << "Stationary";
            break;
        default:
            throw RTE_LOC;
            break;
        }
        return o;
    }


    enum class MultType
    {
        // Binary quasi-cyclic code. Supported by Silent OT; extension-field
        // Silent VOLE requires a code that mixes extension components.
        // https://eprint.iacr.org/2019/1159.pdf
        QuasiCyclic = 1,

        // https://eprint.iacr.org/2022/1014
        // Low fixed-weight EA parameters admit efficiently findable low-weight
        // codewords. Only the conservative weight-41 mode is exposed.
        ExAcc40 = 7,

        // https://eprint.iacr.org/2023/882
        ExConv7x24 = 8, //fast
        ExConv21x24 = 9, // conservative.

        // Block-Diagonal Codes: Accelerated Linear Codes for Pseudorandom Correlation Generators
        BlkAcc3x8 = 10, // fastest with known high minimum distance.
        BlkAcc3x32 = 11,// almost fastest with very high minimum distance.

        // experimental
        Tungsten = 12 // very fast, based on turbo codes. Unknown min distance. 
    };

    inline std::ostream& operator<<(std::ostream& o, MultType m)
    {
        switch (m)
        {
        case osuCrypto::MultType::QuasiCyclic:
            o << "QuasiCyclic";
            break;

        case osuCrypto::MultType::ExAcc40:
            o << "ExAcc40";
            break;
        case osuCrypto::MultType::ExConv21x24:
            o << "ExConv21x24";
            break;
        case osuCrypto::MultType::ExConv7x24:
            o << "ExConv7x24";
            break;
        case MultType::BlkAcc3x8:
            o << "BlkAcc3x8";
            break;
        case MultType::BlkAcc3x32:
            o << "BlkAcc3x32";
            break;
        case osuCrypto::MultType::Tungsten:
            o << "Tungsten";
            break;
        default:
            throw RTE_LOC;
            break;
        }

        return o;
    }

    constexpr MultType DefaultMultType = MultType::BlkAcc3x32;


    u64 getRegNoiseWeight(
        double pseudoMinDistRatio,
        u64 N,
        u64 secParam,
        SdNoiseDistribution noiseType,
        SdNoiseSecurityModel securityModel);


    class EACode;
    void EAConfigure(
        MultType mMultType,
        u64& scaler,
        u64& expanderWeight,
        double& minDist
    );

    void ExConvConfigure(
        MultType mMultType,
        u64& scaler,
        u64& expanderWeight,
        u64& accumulatorWeight,
        double& minDist
    );

    inline void QuasiCyclicConfigure(
        u64& scaler,
        double& minDist
    )
    {
        scaler = 2;
        // A generator row has relative weight close to 1/4. This is a pseudo
        // distance estimate; algebraic attacks are handled separately by
        // requiring an irreducible quasi-cyclic modulus.
        minDist = 0.25;
    }


    inline void BlkAccConfigure(
        MultType mult,
        u64& scaler,
        u64& sigma,
        u64& depth,
        double& minDist)
    {
        if (mult == MultType::BlkAcc3x8)
        {
            sigma = 8;
            depth = 3;
            // The concrete minimum distance is about 0.1. We use 0.15 as an
            // aggressive pseudo-distance estimate: finding the lowest-weight
            // words still requires exploiting the sampled global code.
            minDist = 0.15;
        }
        else if (mult == MultType::BlkAcc3x32)
        {
            sigma = 32;
            depth = 3;
            // The larger local state makes the known low-weight mechanism
            // substantially harder to search than for sigma=8.
            minDist = 0.20;
        }
        else
            throw RTE_LOC;
        scaler = 2;
    }

    inline void TungstenConfigure(
        u64& mScaler,
        double& minDist)
    {
        mScaler = 2;
        // Tungsten is experimental and has no proof. Generator-row checks are
        // consistent with a value near 1/4; retain explicit heuristic margin.
        minDist = 0.20;

    }

    struct SdConfig
    {
        // the total size of the noise vector, this will
        // be about mNumPartitions*mSizePer, might might be 
        // slightly larger. This allows it to be a power of 
        // two in size when its mNumPartitions*mSizePer. Some 
        // codes prefer this.
        u64 mNoiseVectorSize = 0;

        // The number of partitions of regular noise. This
        // can also be thought of as the weight of the 
        // regular vector.
        u64 mNumPartitions = 0;

        // The size of each partion, or unit vector in the 
        // regular case.
        u64 mSizePer = 0;
	};

    // routine for choosing SD parameters.
    //
    // * secParam is the desired computational security parameter.
    // * requestSize the compressed vector size. 
    // * multType the code to be used.
    // * noiseType the choice distribution
    // * securityModel describes the regular-noise coefficient distribution.
    inline SdConfig syndromeDecodingConfigure(
        u64 secParam,
        u64 requestSize,
        MultType multType, 
        SdNoiseDistribution noiseType,
        SdNoiseSecurityModel securityModel)
    {
		constexpr u64 maxSecurityParameter = 1024;
		constexpr u64 maxRequestSize = std::numeric_limits<u32>::max();

		if (secParam > maxSecurityParameter)
			throw std::invalid_argument("Syndrome-decoding security parameter exceeds the supported range. " LOCATION);
		if (requestSize > maxRequestSize)
			throw std::invalid_argument("Syndrome-decoding request size exceeds the supported range. " LOCATION);

        double minDist = 0;
        u64 scaler = 0;
        switch (multType)
        {
        case osuCrypto::MultType::ExAcc40:
        {
            u64 _1;
            EAConfigure(multType, scaler, _1, minDist);
            break;
        }
        case osuCrypto::MultType::ExConv7x24:
        case osuCrypto::MultType::ExConv21x24:
        {
            u64 _1, _2;
            ExConvConfigure(multType, scaler, _1, _2, minDist);
            break;
        }
        case MultType::QuasiCyclic:
            QuasiCyclicConfigure(scaler, minDist);
            break;
        case MultType::BlkAcc3x8:
        case MultType::BlkAcc3x32:
        {
            u64 sigma, depth;
            BlkAccConfigure(multType,scaler, sigma, depth, minDist);
            break;
        }
        case osuCrypto::MultType::Tungsten:
        {
            requestSize = roundUpTo(requestSize, 8);
            TungstenConfigure(scaler, minDist);
            break;
        }
        default:
            throw RTE_LOC;
            break;
        }

        SdConfig config;

        auto baseSize = roundUpTo(requestSize * scaler, 2);

        const bool preferPow2 =
			(requestSize >= 1024) && // large request size
			(baseSize && ((baseSize & (baseSize - 1)) == 0)); // power of 2

        if (preferPow2)
        {
            config.mNumPartitions = roundUpTo(getRegNoiseWeight(
                minDist, baseSize, secParam, noiseType, securityModel), 2);
            config.mSizePer = std::max<u64>(4, roundUpTo(baseSize / config.mNumPartitions, 2));
		    config.mNoiseVectorSize =  std::max(baseSize, config.mNumPartitions * config.mSizePer);

			// mNumPartitions * mSizePer could be smaller than mNoiseVectorSize by as 
			// much as (mNumPartitions - 1). This is to allow the noise vector to be a
			// power of two in size. The end should be filled with zeros in this case.
        }

		// if we are not power of two, or if the
		// chosen parameters lead to a noise vector 
		// significantly larger than baseSize, then
		// we go the non-power of two route.
        if(!preferPow2 || 
			(config.mNoiseVectorSize > (config.mNumPartitions * config.mSizePer * 1.05)))
        {
			// non power of two case. 
            config.mNumPartitions = roundUpTo(getRegNoiseWeight(
                minDist, baseSize, secParam, noiseType, securityModel), 2);
            config.mSizePer = std::max<u64>(4, roundUpTo(divCeil(baseSize, config.mNumPartitions), 2));
			config.mNoiseVectorSize = config.mNumPartitions * config.mSizePer;
        }
        return config;
    }
}

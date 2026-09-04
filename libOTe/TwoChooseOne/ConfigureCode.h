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
        // https://eprint.iacr.org/2019/1159.pdf
        QuasiCyclic = 1,

        // https://eprint.iacr.org/2022/1014
        ExAcc7 = 4, // fast
        ExAcc11 = 5,// fast but more conservative
        ExAcc21 = 6,
        ExAcc40 = 7, // conservative

        // https://eprint.iacr.org/2023/882
        ExConv7x24 = 8, //fast
        ExConv21x24 = 9, // conservative.

        // Block-Diagonal Codes: Accelerated Linear Codes for Pseudorandom Correlation Generators
        BlkAcc3x8 = 10, // fastest with known high minimum distance.
        BlkAcc3x32 = 11,// almost fastest with very high minimum distance.

        // experimental
        Tungsten = 12, // very fast, based on turbo codes. Unknown min distance.

        // Binary, two-sided-regular, rate-one-half expand-convolute code for
        // Silent OT. The expander degrees are 10/5 and the wrapped
        // convolution memory is 15.
        RegularEc10x5x15 = 13,

        // Experimental field-valued streaming expand-convolute code for
        // Silent VOLE. The expander degrees are 26/13 and the wrapped
        // convolution memory is 4. Its structured schedule is not the proved
        // ensemble.
        RegularEc26x13x4 = 14
    };

    inline std::ostream& operator<<(std::ostream& o, MultType m)
    {
        switch (m)
        {
        case osuCrypto::MultType::QuasiCyclic:
            o << "QuasiCyclic";
            break;

        case osuCrypto::MultType::ExAcc7:
            o << "ExAcc7";
            break;
        case osuCrypto::MultType::ExAcc11:
            o << "ExAcc11";
            break;
        case osuCrypto::MultType::ExAcc21:
            o << "ExAcc21";
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
        case osuCrypto::MultType::RegularEc10x5x15:
            o << "RegularEc10x5x15";
            break;
        case osuCrypto::MultType::RegularEc26x13x4:
            o << "RegularEc26x13x4";
            break;
        default:
            throw RTE_LOC;
            break;
        }

        return o;
    }

    constexpr MultType DefaultMultType = MultType::BlkAcc3x32;


    // We get e^{-2t d/N} security against linear attacks, 
    // with noise weight t and minDist d and code size N. 
    // For regular we can be slightly more accurate with
    //    (1 − 2d/N)^t
    // which implies a bit security level of
    // k = -t * log2(1 - 2d/N)
    // t = -k / log2(1 - 2d/N)
    //
    //
    // For stationary, we get
    //    (1-d/N)^t
    // 
    // minDistRatio = d / N
    // where d is the min dist and N is the code size.
    u64 getRegNoiseWeight(double minDistRatio, u64 N, u64 secParam, SdNoiseDistribution noiseType);


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
        minDist = 0.25; // estimated psuedo min dist
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
        }
        else if (mult == MultType::BlkAcc3x32)
        {
            sigma = 32;
            depth = 3;
        }
        else
            throw RTE_LOC;
        scaler = 2;
        minDist = 0.25; // estimated psuedo min dist
    }

    inline void TungstenConfigure(
        u64& mScaler,
        double& minDist)
    {
        mScaler = 2;
        minDist = 0.25; // estimated psuedo min dist

    }

    inline void RegularEcConfigure(
        u64& scaler,
        double& minDist)
    {
        scaler = 2;
        // The finite certificate at k=1,048,575 proves relative distance
        // above 0.110020. Use a rounded-down value in noise selection. Other
        // padded lengths instantiate the same experimental ensemble but need
        // their own finite certificates before being called proved parameters.
        minDist = 0.10;
    }

    inline void RegularEcFieldConfigure(
        u64& scaler,
        double& minDist)
    {
        scaler = 2;
        // The streaming schedule and its +/-1 labels are heuristic. The
        // paper-correct Goldilocks ensemble is certified through relative
        // distance 0.4843, while intended-degree streaming searches return
        // their lightest candidates near relative weight 0.49. Those searches
        // are not a lower-bound proof, so retain substantial margin. At 0.30
        // the independent 128-position
        // attack floor already dominates large-field VOLE noise selection;
        // larger pseudo-distances would not reduce the selected weight.
        minDist = 0.30;
    }

    inline u64 RegularEcPaddedMessageSize(u64 requestedSize)
    {
        // k=525 is the smallest size checked so far whose finite distance-0.10
        // certificate exceeds the 20-bit target. The current complement proof
        // uses odd k, while exact rate-half degrees 10/5 require k divisible
        // by five.
        constexpr u64 minimumCertifiedSize = 525;
        constexpr u64 maximumSize = std::numeric_limits<u32>::max() / 2;
        u64 padded = std::max(requestedSize, minimumCertifiedSize);
        if (padded > maximumSize)
            throw std::invalid_argument(
                "Regular EC message size exceeds its 32-bit index space. " LOCATION);
        padded = roundUpTo(padded, 5);
        if ((padded & 1) == 0)
            padded += 5;
        if (padded > maximumSize)
            throw std::invalid_argument(
                "Regular EC message size exceeds its 32-bit index space. " LOCATION);
        return padded;
    }

    inline u64 RegularEcFieldPaddedMessageSize(u64 requestedSize)
    {
        constexpr u64 rightDegree = 13;
        constexpr u64 maximumSize = std::numeric_limits<u32>::max() / 2;
        if (requestedSize > maximumSize)
            throw std::invalid_argument(
                "Streaming field regular EC message size exceeds its 32-bit index space. " LOCATION);
        const u64 padded = roundUpTo(requestedSize, rightDegree);
        if (padded > maximumSize)
            throw std::invalid_argument(
                "Streaming field regular EC message size exceeds its 32-bit index space. " LOCATION);
        return padded;
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
    // * groupBitCount the bit count of the subfield or smallest subgroup. 
    //   For example, Z2k should be 1 because you have the Z2 subgroup.
    inline SdConfig syndromeDecodingConfigure(
        u64 secParam,
        u64 requestSize,
        MultType multType, 
        SdNoiseDistribution noiseType,
        u64 groupBitCount)
    {
		constexpr u64 maxSecurityParameter = 1024;
		constexpr u64 maxRequestSize = std::numeric_limits<u32>::max();
		constexpr u64 maxGroupBitCount = std::numeric_limits<u16>::max();

		if (secParam > maxSecurityParameter)
			throw std::invalid_argument("Syndrome-decoding security parameter exceeds the supported range. " LOCATION);
		if (requestSize > maxRequestSize)
			throw std::invalid_argument("Syndrome-decoding request size exceeds the supported range. " LOCATION);
		if (groupBitCount > maxGroupBitCount)
			throw std::invalid_argument("Syndrome-decoding group bit count exceeds the supported range. " LOCATION);

        double minDist = 0;
        u64 scaler = 0;
        switch (multType)
        {
        case osuCrypto::MultType::ExAcc7:
        case osuCrypto::MultType::ExAcc11:
        case osuCrypto::MultType::ExAcc21:
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
        case osuCrypto::MultType::RegularEc10x5x15:
            RegularEcConfigure(scaler, minDist);
            break;
        case osuCrypto::MultType::RegularEc26x13x4:
            RegularEcFieldConfigure(scaler, minDist);
            break;
        default:
            throw RTE_LOC;
            break;
        }

        // for small fields and SD we use the conservative parameters.
        // otherwise just use the normal SD parameters. 
        if (groupBitCount > 4 && noiseType == SdNoiseDistribution::Stationary)
            noiseType = SdNoiseDistribution::Regular;

        SdConfig config;

        auto baseSize = roundUpTo(requestSize * scaler, 2);

        const bool preferPow2 =
			(requestSize >= 1024) && // large request size
			(baseSize && ((baseSize & (baseSize - 1)) == 0)); // power of 2

        if (preferPow2)
        {
            config.mNumPartitions = roundUpTo(getRegNoiseWeight(minDist, baseSize, secParam, noiseType), 2);
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
            config.mNumPartitions = roundUpTo(getRegNoiseWeight(minDist, baseSize, secParam, noiseType), 2);
            config.mSizePer = std::max<u64>(4, roundUpTo(divCeil(baseSize, config.mNumPartitions), 2));
			config.mNoiseVectorSize = config.mNumPartitions * config.mSizePer;
        }
        if (multType == MultType::RegularEc10x5x15)
        {
            const u64 minimumNoiseSize =
                2 * RegularEcPaddedMessageSize(requestSize);
            const u64 physicalNoiseSize =
                config.mNumPartitions * config.mSizePer;
            if (physicalNoiseSize < minimumNoiseSize)
            {
                config.mSizePer = roundUpTo(
                    divCeil(minimumNoiseSize, config.mNumPartitions), 2);
            }
            const u64 paddedPhysicalNoiseSize =
                config.mNumPartitions * config.mSizePer;
            const u64 minimumMessageSize = std::max(
                requestSize,
                divCeil(paddedPhysicalNoiseSize, u64{ 2 }));
            config.mNoiseVectorSize =
                2 * RegularEcPaddedMessageSize(minimumMessageSize);
        }
        else if (multType == MultType::RegularEc26x13x4)
        {
            const u64 minimumNoiseSize =
                2 * RegularEcFieldPaddedMessageSize(requestSize);
            const u64 physicalNoiseSize =
                config.mNumPartitions * config.mSizePer;
            if (physicalNoiseSize < minimumNoiseSize)
            {
                config.mSizePer = roundUpTo(
                    divCeil(minimumNoiseSize, config.mNumPartitions), 2);
            }
            const u64 paddedPhysicalNoiseSize =
                config.mNumPartitions * config.mSizePer;
            const u64 minimumMessageSize = std::max(
                requestSize,
                divCeil(paddedPhysicalNoiseSize, u64{ 2 }));
            config.mNoiseVectorSize =
                2 * RegularEcFieldPaddedMessageSize(minimumMessageSize);
        }
        return config;
    }
}

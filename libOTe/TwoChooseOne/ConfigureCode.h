#pragma once
#include "libOTe/config.h"
#include "cryptoTools/Common/Defines.h"
#include "libOTe/TwoChooseOne/TcoOtDefines.h"

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
        Tungsten = 12 // very fast, based on turbo codes. Unknown min distance. 
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

    struct SdConfig
    {
        u64 mNumPartitions = 0;
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
        default:
            throw RTE_LOC;
            break;
        }

        // for small fields and SD we use the conservative parameters.
        // otherwise just use the normal SD parameters. 
        if (groupBitCount > 4 && noiseType == SdNoiseDistribution::Stationary)
            noiseType = SdNoiseDistribution::Regular;

        SdConfig config;
        config.mNumPartitions = getRegNoiseWeight(minDist, requestSize * scaler, secParam, noiseType);
        config.mSizePer = std::max<u64>(4, roundUpTo(divCeil(requestSize * scaler, config.mNumPartitions), 2));
        return config;
    }
}
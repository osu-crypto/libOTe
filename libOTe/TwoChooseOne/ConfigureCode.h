#pragma once
#include "libOTe/config.h"
#include "cryptoTools/Common/Defines.h"


namespace osuCrypto
{

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

        // experimental
        Tungsten // very fast, based on turbo codes. Unknown min distance. 
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
        case osuCrypto::MultType::Tungsten:
            o << "Tungsten";
            break;
        default:
            throw RTE_LOC;
            break;
        }

        return o;
    }

    constexpr MultType DefaultMultType = MultType::ExConv7x24;


    // We get e^{-2t d/N} security against linear attacks, 
    // with noise weight t and minDist d and code size N. 
    // For regular we can be slightly more accurate with
    //    (1 − 2d/N)^t
    // which implies a bit security level of
    // k = -t * log2(1 - 2d/N)
    // t = -k / log2(1 - 2d/N)
    //
    // minDistRatio = d / N
    // where d is the min dist and N is the code size.
    u64 getRegNoiseWeight(double minDistRatio, u64 N, u64 secParam);


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
        minDist = 0.2; // estimated psuedo min dist
    }


    inline void TungstenConfigure(
        u64& mScaler,
        double& minDist)
    {
        mScaler = 2;
        minDist = 0.2; // estimated psuedo min dist

    }

    inline void syndromeDecodingConfigure(
        u64& mNumPartitions, u64& mSizePer, u64& mNoiseVecSize,
        u64 secParam,
        u64 mRequestSize,
        MultType mMultType)
    {

        double minDist = 0;
        u64 scaler = 0;
        switch (mMultType)
        {
        case osuCrypto::MultType::ExAcc7:
        case osuCrypto::MultType::ExAcc11:
        case osuCrypto::MultType::ExAcc21:
        case osuCrypto::MultType::ExAcc40:
        {
            u64 _1;
            EAConfigure(mMultType, scaler, _1, minDist);
        }
        case osuCrypto::MultType::ExConv7x24:
        case osuCrypto::MultType::ExConv21x24:
        {
            u64 _1, _2;
            ExConvConfigure(mMultType, scaler, _1, _2, minDist);
            break;
        }
        case MultType::QuasiCyclic:
            QuasiCyclicConfigure(scaler, minDist);
            break;
        case osuCrypto::MultType::Tungsten:
        {
            mRequestSize = roundUpTo(mRequestSize, 8);
            TungstenConfigure(scaler, minDist);
            break;
        }
        default:
            throw RTE_LOC;
            break;
        }

        mNumPartitions = getRegNoiseWeight(minDist, mRequestSize * scaler, secParam);
        mSizePer = std::max<u64>(4, roundUpTo(divCeil(mRequestSize * scaler, mNumPartitions), 2));
        mNoiseVecSize = mSizePer * mNumPartitions;
    }
}
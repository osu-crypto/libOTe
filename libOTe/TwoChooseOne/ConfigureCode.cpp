#include "ConfigureCode.h"


#include "cryptoTools/Common/Range.h"
#include "libOTe/TwoChooseOne/TcoOtDefines.h"
#include "libOTe/Tools/Tools.h"
#include "libOTe/Tools/LDPC/LdpcEncoder.h"
#include "libOTe/Tools/QuasiCyclicCode.h"
#include "libOTe/Tools/EACode/EACode.h"
#include "libOTe/Tools/ExConvCode/ExConvCode.h"
#include <cmath>
namespace osuCrypto
{
    //u64 secLevel(u64 scale, u64 n, u64 points)
    //{
    //    auto x1 = std::log2(scale * n / double(n));
    //    auto x2 = std::log2(scale * n) / 2;
    //    return static_cast<u64>(points * x1 + x2);
    //}

    //u64 getPartitions(u64 scaler, u64 n, u64 secParam)
    //{
    //    if (scaler < 2)
    //        throw std::runtime_error("scaler must be 2 or greater");

    //    u64 ret = 1;
    //    auto ss = secLevel(scaler, n, ret);
    //    while (ss < secParam)
    //    {
    //        ++ret;
    //        ss = secLevel(scaler, n, ret);
    //        if (ret > 1000)
    //            throw std::runtime_error("failed to find silent OT parameters");
    //    }
    //    return roundUpTo(ret, 8);
    //}


    // We get e^{-2td} security against linear attacks, 
    // with noise weigh t and minDist d. 
    // For regular we can be slightly more accurate with
    //    (1 − 2d)^t
    // which implies a bit security level of
    // k = -t * log2(1 - 2d)
    // t = -k / log2(1 - 2d)
    u64 getRegNoiseWeight(double minDistRatio, u64 secParam)
    {
        if (minDistRatio > 0.5 || minDistRatio <= 0)
            throw RTE_LOC;

        auto d = std::log2(1 - 2 * minDistRatio);
        auto t = std::max<u64>(128, -double(secParam) / d);

        return roundUpTo(t, 8);
    }


    void EAConfigure(
        u64 numOTs, u64 secParam,
        MultType mMultType,
        u64& mRequestedNumOTs,
        u64& mNumPartitions,
        u64& mSizePer,
        u64& mN2,
        u64& mN,
        EACode& mEncoder
    )
    {
        auto mScaler = 2;
        u64 w;
        double minDist;
        switch (mMultType)
        {
        case osuCrypto::MultType::ExAcc7:
            w = 7;
            // this is known to be high but likely overall accurate
            minDist = 0.05;
            break;
        case osuCrypto::MultType::ExAcc11:
            w = 11;
            minDist = 0.1;
            break;
        case osuCrypto::MultType::ExAcc21:
            w = 21;
            minDist = 0.1;
            break;
        case osuCrypto::MultType::ExAcc40:
            w = 40;
            minDist = 0.2;
            break;
        default:
            throw RTE_LOC;
            break;
        }

        mRequestedNumOTs = numOTs;
        mNumPartitions = getRegNoiseWeight(minDist, secParam);
        mSizePer = roundUpTo((numOTs * mScaler + mNumPartitions - 1) / mNumPartitions, 8);
        mN2 = mSizePer * mNumPartitions;
        mN = mN2 / mScaler;

        mEncoder.config(numOTs, numOTs * mScaler, w);
    }


    void ExConvConfigure(
        u64 numOTs, u64 secParam,
        MultType mMultType,
        u64& mRequestedNumOTs,
        u64& mNumPartitions,
        u64& mSizePer,
        u64& mN2,
        u64& mN,
        ExConvCode& mEncoder
    )
    {
        u64 a = 24;
        auto mScaler = 2;
        u64 w;
        double minDist;
        switch (mMultType)
        {
        case osuCrypto::MultType::ExConv7x24:
            w = 7;
            minDist = 0.1;
            break;
        case osuCrypto::MultType::ExConv21x24:
            w = 21;
            minDist = 0.15;
            break;
        default:
            throw RTE_LOC;
            break;
        }

        mRequestedNumOTs = numOTs;
        mNumPartitions = getRegNoiseWeight(minDist, secParam);
        mSizePer = roundUpTo((numOTs * mScaler + mNumPartitions - 1) / mNumPartitions, 8);
        mN2 = mSizePer * mNumPartitions;
        mN = mN2 / mScaler;

        mEncoder.config(numOTs, numOTs * mScaler, w, a, true);
    }

#ifdef ENABLE_INSECURE_SILVER

    void SilverConfigure(
        u64 numOTs, u64 secParam,
        MultType mMultType,
        u64& mRequestedNumOTs,
        u64& mNumPartitions,
        u64& mSizePer,
        u64& mN2,
        u64& mN,
        u64& gap,
        SilverEncoder& mEncoder)
    {
        // warn the user on program exit.
        struct Warned
        {
            ~Warned()
            {
                {
                    std::cout << oc::Color::Red << "WARNING: This program made use of the LPN silver encoder. "
                        << "This encoder is insecure and should not be used in production." 
                        << " It remains here for performance comparison reasons only. \n\nDo not use this encode.\n\n"
                        << LOCATION << oc::Color::Default << std::endl;
                }
            }
        };
        static Warned wardned;

        mRequestedNumOTs = numOTs;
        auto mScaler = 2;

        auto code = mMultType == MultType::slv11 ?
            SilverCode::Weight11 :
            SilverCode::Weight5;

        gap = SilverCode::gap(code);

        mNumPartitions = getRegNoiseWeight(0.2, secParam);
        mSizePer = roundUpTo((numOTs * mScaler + mNumPartitions - 1) / mNumPartitions, 8);
        mN2 = mSizePer * mNumPartitions + gap;
        mN = mN2 / mScaler;

        if (mN2 % mScaler)
            throw RTE_LOC;

        mEncoder.mL.init(mN, code);
        mEncoder.mR.init(mN, code, true);
    }
#endif

    void QuasiCyclicConfigure(
        u64 numOTs, u64 secParam,
        u64 scaler,
        MultType mMultType,
        u64& mRequestedNumOTs,
        u64& mNumPartitions,
        u64& mSizePer,
        u64& mN2,
        u64& mN,
        u64& mP,
        u64& mScaler)

    {
#ifndef ENABLE_BITPOLYMUL
        throw std::runtime_error("ENABLE_BITPOLYMUL not defined, rebuild the library with `-DENABLE_BITPOLYMUL=TRUE`. " LOCATION);
#endif

        mRequestedNumOTs = numOTs;
        mP = nextPrime(std::max<u64>(numOTs, 128 * 128));
        mNumPartitions = getRegNoiseWeight(0.2, secParam);
        auto ss = (mP * scaler + mNumPartitions - 1) / mNumPartitions;
        mSizePer = roundUpTo(ss, 8);
        mN2 = mSizePer * mNumPartitions;
        mN = mN2 / scaler;
        mScaler = scaler;
    }

}

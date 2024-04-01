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
    u64 getRegNoiseWeight(double minDistRatio, u64 N, u64 secParam)
    {
        if (minDistRatio > 0.5 || minDistRatio <= 0)
            throw RTE_LOC;

        auto d = std::log2(1 - 2 * minDistRatio);
        auto t = std::max<u64>(40, -double(secParam) / d);

        if(N < 512)
            t = std::max<u64>(t, 64);

        return roundUpTo(t, 8);
    }


    void EAConfigure(
        MultType mMultType,
        u64& expanderWeight,
        u64& scaler,
        double& minDist
    )
    {
        scaler = 5;
        switch (mMultType)
        {
        case osuCrypto::MultType::ExAcc7:
            expanderWeight = 7;
            // this is known to be high but likely overall accurate
            minDist = 0.05;
            break;
        case osuCrypto::MultType::ExAcc11:
            expanderWeight = 11;
            minDist = 0.1;
            break;
        case osuCrypto::MultType::ExAcc21:
            expanderWeight = 21;
            minDist = 0.15;
            break;
        case osuCrypto::MultType::ExAcc40:
            expanderWeight = 41;
            minDist = 0.2;
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
            minDist = 0.15; // psuedo min dist estimate
            break;
        case osuCrypto::MultType::ExConv21x24:
            accumulatorWeight = 24;
            expanderWeight = 21;
            minDist = 0.2; // psuedo min dist estimate
            break;
        default:
            throw RTE_LOC;
            break;
        }
    }
}

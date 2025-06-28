#pragma once


namespace osuCrypto
{

    enum class OTType
    {
        Random, Correlated
    };

    enum class ChoiceBitPacking
    {
        False, True
    };

    enum class SilentSecType
    {
        SemiHonest,
        Malicious,
        //MaliciousFS
    };


    inline std::ostream& operator<<(std::ostream& o, SilentSecType m)
    {
        switch (m)
        {
        case osuCrypto::SilentSecType::SemiHonest:
            o << "SemiHonest";
            break;
        case osuCrypto::SilentSecType::Malicious:
            o << "Malicious";
            break;
        default:
            throw RTE_LOC;
            break;
        }
        return o;
    }



    // the required base correlations 
    struct SilentBaseCount
    {
        // the number of random OTs that the protocol requires.
        u64 mBaseOtCount;

        // the number of VOLE/correleted OTs that are required. 
        // The correlation should be that
        // 
        //   m1 = m0 + delta
        // 
        // where m0,m1 are the sender messages and delta is the 
        // same delta value used in the main protocol.
        u64 mBaseVoleCount;
    };
}
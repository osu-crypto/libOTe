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
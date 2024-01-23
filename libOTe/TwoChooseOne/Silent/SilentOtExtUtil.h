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
}
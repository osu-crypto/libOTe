#pragma once

#include "libOTe/config.h"
#include <cryptoTools/Common/Defines.h>

#if defined(ENABLE_SODIUM) || defined(ENABLE_RELIC)

#if defined(ENABLE_SODIUM)
#include <cryptoTools/Crypto/SodiumCurve.h>
#elif defined(ENABLE_RELIC)
#include <cryptoTools/Crypto/RCurve.h>
#endif

namespace osuCrypto
{
    // Declare aliases for the default elliptic curve implementation.
    namespace DefaultCurve
    {
#if defined(ENABLE_SODIUM)
        using Point = Sodium::Rist25519;
        using Number = Sodium::Prime25519;
        // Allow declaring a Curve variable. Constructor is to suppress unused variable warnings.
        struct Curve { Curve() {} };
#elif defined(ENABLE_RELIC)
        using Curve = REllipticCurve;
        using Point = REccPoint;
        using Number = REccNumber;
#endif
    }
}

#endif

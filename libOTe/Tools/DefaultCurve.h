#pragma once
// © 2021 Peter Rindal.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


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

#pragma once

#include <cryptoTools/Crypto/Edwards25519/Ristretto255.h>

namespace osuCrypto
{
namespace MrrCurve
{
    using Point = Ristretto255::Point;
    using Point8 = Ristretto255::Point8;
    using Number = Ristretto255::Scalar;
}
}

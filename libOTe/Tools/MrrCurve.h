#pragma once

#include "libOTe/config.h"

#include <array>
#include <cstddef>
#include <cstdint>

#if defined(CRYPTOTOOLS_EDWARDS25519_IFMA) || \
    defined(CRYPTOTOOLS_EDWARDS25519_ASM) || \
    (!defined(ENABLE_SODIUM) && !defined(ENABLE_RELIC))
#include <cryptoTools/Crypto/Edwards25519/Ristretto255.h>
#elif defined(ENABLE_SODIUM)
#include <cryptoTools/Crypto/SodiumCurve.h>
#elif defined(ENABLE_RELIC)
#include <cryptoTools/Crypto/RCurve.h>
#endif

namespace osuCrypto
{
namespace MrrCurve
{
    // Compile-time priority: AVX-512 IFMA, x86-64 assembly, libsodium,
    // relic, then the portable cryptoTools implementation.
    constexpr std::size_t lanes = 8;

    enum class Backend
    {
        Avx512Ifma,
        Assembly,
        Sodium,
        Relic,
        Portable
    };

#if defined(CRYPTOTOOLS_EDWARDS25519_IFMA)
    constexpr Backend backend = Backend::Avx512Ifma;
    using Point = Ristretto255::Point;
    using Point8 = Ristretto255::Point8;
    using Number = Ristretto255::Scalar;

    inline bool fromBytes(Point& point, const std::uint8_t* encoded) noexcept
    {
        return point.fromBytes(encoded);
    }

    inline void init() noexcept {}
#elif defined(CRYPTOTOOLS_EDWARDS25519_ASM)
    constexpr Backend backend = Backend::Assembly;
    using Point = Ristretto255::Point;
    using Point8 = Ristretto255::Point8;
    using Number = Ristretto255::Scalar;

    inline bool fromBytes(Point& point, const std::uint8_t* encoded) noexcept
    {
        return point.fromBytes(encoded);
    }

    inline void init() noexcept {}
#elif defined(ENABLE_SODIUM)
    constexpr Backend backend = Backend::Sodium;
    using Point = Sodium::Rist25519;
    using Number = Sodium::Prime25519;

    inline bool fromBytes(Point& point, const std::uint8_t* encoded) noexcept
    {
        if (crypto_core_ristretto255_is_valid_point(encoded) != 1)
            return false;
        point.fromBytes(encoded);
        return true;
    }

    inline void init() noexcept {}
#elif defined(ENABLE_RELIC)
    constexpr Backend backend = Backend::Relic;
    using Point = REccPoint;
    using Number = REccNumber;

    inline bool fromBytes(Point& point, const std::uint8_t* encoded)
    {
        point.fromBytes(const_cast<std::uint8_t*>(encoded));
        return true;
    }

    inline void init()
    {
        REllipticCurve curve;
    }
#else
    constexpr Backend backend = Backend::Portable;
    using Point = Ristretto255::Point;
    using Point8 = Ristretto255::Point8;
    using Number = Ristretto255::Scalar;

    inline bool fromBytes(Point& point, const std::uint8_t* encoded) noexcept
    {
        return point.fromBytes(encoded);
    }

    inline void init() noexcept {}
#endif

#if !defined(CRYPTOTOOLS_EDWARDS25519_IFMA) && \
    !defined(CRYPTOTOOLS_EDWARDS25519_ASM) && \
    (defined(ENABLE_SODIUM) || defined(ENABLE_RELIC))
    // Fixed-width scalar adapter for the external-library fallbacks. Keeping
    // this interface identical to the native Point8 path lets McRosRoy retain
    // one allocation-free, explicitly batched hot loop.
    class Point8
    {
    public:
        static Point8 broadcast(const Point& point)
        {
            Point8 result;
            for (std::size_t i = 0; i != lanes; ++i)
                result.mPoints[i] = point;
            return result;
        }

        static Point8 fromUniformBytes(
            const std::uint8_t uniform[lanes * Point::fromHashLength])
        {
            Point8 result;
            for (std::size_t i = 0; i != lanes; ++i)
                result.mPoints[i] = Point::fromHash(
                    uniform + i * Point::fromHashLength);
            return result;
        }

        static Point8 mulGenerator(const std::array<Number, lanes>& scalars)
        {
            Point8 result;
            for (std::size_t i = 0; i != lanes; ++i)
                result.mPoints[i] = Point::mulGenerator(scalars[i]);
            return result;
        }

        Point8 mul(const Number& scalar) const
        {
            Point8 result;
            for (std::size_t i = 0; i != lanes; ++i)
                result.mPoints[i] = mPoints[i] * scalar;
            return result;
        }

        Point8 mul(const std::array<Number, lanes>& scalars) const
        {
            Point8 result;
            for (std::size_t i = 0; i != lanes; ++i)
                result.mPoints[i] = mPoints[i] * scalars[i];
            return result;
        }

        Point8 operator+(const Point8& rhs) const
        {
            Point8 result;
            for (std::size_t i = 0; i != lanes; ++i)
                result.mPoints[i] = mPoints[i] + rhs.mPoints[i];
            return result;
        }

        Point8 operator-(const Point8& rhs) const
        {
            Point8 result;
            for (std::size_t i = 0; i != lanes; ++i)
                result.mPoints[i] = mPoints[i] - rhs.mPoints[i];
            return result;
        }

        bool fromBytes(const std::uint8_t encoded[lanes * Point::size])
        {
            for (std::size_t i = 0; i != lanes; ++i)
                if (!MrrCurve::fromBytes(mPoints[i], encoded + i * Point::size))
                    return false;
            return true;
        }

        void toBytes(std::uint8_t encoded[lanes * Point::size]) const
        {
            for (std::size_t i = 0; i != lanes; ++i)
                mPoints[i].toBytes(encoded + i * Point::size);
        }

    private:
        std::array<Point, lanes> mPoints;
    };
#endif
}
}

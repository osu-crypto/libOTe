#pragma once
#include "libOTe/config.h"
#ifdef ENABLE_POPF_RISTRETTO

#include <type_traits>
#include "libOTe/TwoChooseOne/OTExtInterface.h"
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/RCurve.h>
#include <cryptoTools/Crypto/RandomOracle.h>

#if !(defined(ENABLE_SODIUM) || defined(ENABLE_RELIC))
static_assert(0, "ENABLE_SODIUM or ENABLE_RELIC must be defined to build RistrettoPopfOT");
#endif
#include "DefaultCurve.h"

namespace osuCrypto
{
    // The Popf's PopfFunc must be plain old data, PopfIn must be convertible from an integer, and
    // PopfOut must be a DefaultCurve::Point.
    template<typename DSPopf>
    class RistrettoPopfOT : public OtReceiver, public OtSender
    {
        using Curve = DefaultCurve::Curve;
        using Point = DefaultCurve::Point;
        using Number = DefaultCurve::Number;

    public:
        typedef DSPopf PopfFactory;

        RistrettoPopfOT() = default;
        RistrettoPopfOT(const PopfFactory& p) : popfFactory(p) {}
        RistrettoPopfOT(PopfFactory&& p) : popfFactory(p) {}

        void receive(
            const BitVector& choices,
            span<block> messages,
            PRNG& prng,
            Channel& chl,
            u64 numThreads)
        {
            receive(choices, messages, prng, chl);
        }

        void send(
            span<std::array<block, 2>> messages,
            PRNG& prng,
            Channel& chl,
            u64 numThreads)
        {
            send(messages, prng, chl);
        }

        void receive(
            const BitVector& choices,
            span<block> messages,
            PRNG& prng,
            Channel& chl) override;

        void send(
            span<std::array<block, 2>> messages,
            PRNG& prng,
            Channel& chl) override;

        static_assert(std::is_pod<typename PopfFactory::ConstructedPopf::PopfFunc>::value,
                      "Popf function must be Plain Old Data");
        static_assert(std::is_same<typename PopfFactory::ConstructedPopf::PopfOut, Point>::value,
                      "Popf must be programmable on elliptic curve points");

    private:
        PopfFactory popfFactory;
    };

}

#include "RistrettoPopfOT_impl.h"

#else

// Allow unit tests to use RistrettoPopfOT as a template argument.
namespace osuCrypto
{
    template<typename DSPopf>
    class RistrettoPopfOT;
}

#endif

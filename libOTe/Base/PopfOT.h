#pragma once
#include "libOTe/config.h"
#ifdef ENABLE_POPF

#include <type_traits>
#include "libOTe/TwoChooseOne/OTExtInterface.h"
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/RCurve.h>
#include <cryptoTools/Crypto/Rijndael256.h>
#include <cryptoTools/Crypto/RandomOracle.h>

#include <cryptoTools/Crypto/RCurve.h>
#ifndef ENABLE_RELIC
static_assert(0, "ENABLE_RELIC must be defined to build PopfOT");
#endif

namespace osuCrypto
{
    // C++ doesn't have traits, so it's hard to declare what a Popf should do. But Popf classes
    // should looks something like this:
    /*
    class Popf
    {
    public:
        typedef ... PopfFunc;
        typedef ... PopfIn;
        typedef ... PopfOut;

        PopfOut eval(PopfFunc f, PopfIn x) const;
        PopfFunc program(PopfIn x, PopfOut y) const;
    };
    */

    // A factory to create a Popf from a RO should look something like this:
    /*
    class RODomainSeparatedPopf: public RandomOracle
    {
        using RandomOracle::Final;
        using RandomOracle::outputLength;

    public:
        typedef ... ConstructedPopf;

        ConstructedPopf construct();
    };
    */

    // The Popf's PopfFunc must be plain old data, PopfIn must be convertible from an integer, and
    // PopfOut must be a Block256.
    template<typename DSPopf>
    class PopfOT : public OtReceiver, public OtSender
    {
    public:
        typedef DSPopf PopfFactory;

        PopfOT(const PopfFactory& p) : popfFactory(p) {}
        PopfOT(PopfFactory&& p) : popfFactory(p) {}

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
        static_assert(std::is_same<typename PopfFactory::ConstructedPopf::PopfOut, Block256>::value,
                      "Popf must be programmable on 256-bit blocks");

    private:
        PopfFactory popfFactory;

        using Curve = oc::REllipticCurve;
        using Point = oc::REccPoint;
        using Brick = oc::REccPoint;
        using Number = oc::REccNumber;

        void blockToCurve(Point& p, Block256 b);
        Block256 curveToBlock(const Point& p);
    };

}

#include "PopfOT_impl.h"

#endif

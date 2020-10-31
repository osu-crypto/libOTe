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
    // Static polymorphism isn't strictly speaking necessary here, as send and receive could just
    // call the functions anyway. But it provides a declaration of what's needed for a Popf.

    template<class Derived>
    struct PopfTraits;

    template<class Derived>
    class Popf
    {
    public:
        typedef typename PopfTraits<Derived>::PopfFunc PopfFunc;
        typedef typename PopfTraits<Derived>::PopfIn PopfIn;
        typedef typename PopfTraits<Derived>::PopfOut PopfOut;

        PopfOut eval(PopfFunc f, PopfIn x) const { return derived().eval(f, x); }
        PopfFunc program(PopfIn x, PopfOut y) const { return derived().program(x, y); }

        // Static polymorphism boilerplate.
        Derived& derived() { return *static_cast<Derived*>(this); }
        const Derived& derived() const { return *static_cast<const Derived*>(this); }
    };

    template<class Derived>
    struct RODomainSeparatedPopfTraits;

    template<class Derived>
    class RODomainSeparatedPopf: public RandomOracle
    {
        typedef RandomOracle Base;

    protected:
        using RandomOracle::Final;
        using RandomOracle::outputLength;

    public:
        using Base::Base;
        using Base::operator=;

        typedef typename RODomainSeparatedPopfTraits<Derived>::ConstructedPopf ConstructedPopf;

        ConstructedPopf construct() { return derived().construct(); }

        // Static polymorphism boilerplate.
        Derived& derived() { return *static_cast<Derived*>(this); }
        const Derived& derived() const { return *static_cast<const Derived*>(this); }
    };

    // The Popf's PopfFunc must be plain old data, PopfIn must be convertible from an integer, and
    // PopfOut must be a Block256.
    template<typename DerivedDSPopf>
    class PopfOT : public OtReceiver, public OtSender
    {
    public:
        typedef RODomainSeparatedPopf<DerivedDSPopf> PopfFactory;

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

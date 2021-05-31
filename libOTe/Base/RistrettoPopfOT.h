#pragma once
#include "libOTe/config.h"
#ifdef ENABLE_POPF_RISTRETTO

#include <type_traits>
#include "libOTe/TwoChooseOne/OTExtInterface.h"
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/RCurve.h>
#include <cryptoTools/Crypto/Rijndael256.h>
#include <cryptoTools/Crypto/RandomOracle.h>

#include <cryptoTools/Crypto/SodiumCurve.h>
#ifndef ENABLE_SODIUM
static_assert(0, "ENABLE_SODIUM must be defined to build RistrettoPopfOT");
#endif

namespace osuCrypto
{
    // The Popf's PopfFunc must be plain old data, PopfIn must be convertible from an integer, and
    // PopfOut must be a Rist25519.
    template<typename DSPopf>
    class RistrettoPopfOT : public OtReceiver, public OtSender
    {
        using Rist25519 = Sodium::Rist25519;
        using Prime25519 = Sodium::Prime25519;

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
        static_assert(std::is_same<typename PopfFactory::ConstructedPopf::PopfOut, Rist25519>::value,
                      "Popf must be programmable on 256-bit blocks");

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

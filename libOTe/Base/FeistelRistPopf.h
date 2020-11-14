#pragma once
#include "libOTe/config.h"
#ifdef ENABLE_POPF

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/RandomOracle.h>

namespace osuCrypto
{
    class FeistelRistPopf
    {
        using Rist25519 = Sodium::Rist25519;

    public:
        struct PopfFunc
        {
            Rist25519 t;
            block s[3];
        };

        typedef bool PopfIn;
        typedef Rist25519 PopfOut;

        FeistelRistPopf(const RandomOracle& ro_) : ro(ro_) {}
        FeistelRistPopf(RandomOracle&& ro_) : ro(ro_) {}

        PopfOut eval(PopfFunc f, PopfIn x) const
        {
            RandomOracle h = ro;
            h.Update(x);

            xorHPrime(f, h);
            addH(f, h, false);

            return f.t;
        }

        PopfFunc program(PopfIn x, PopfOut y, PRNG& prng) const
        {
            RandomOracle h = ro;
            h.Update(x);

            PopfFunc f;
            f.t = y;
            prng.get(f.s, 3);

            addH(f, h, true);
            xorHPrime(f, h);

            return f;
        }

    private:
        void addH(PopfFunc &f, RandomOracle h, bool negate) const
        {
            h.Update((unsigned char) 0);
            h.Update(f.s);
            Rist25519 v = Rist25519::fromHash(h);

            if (negate)
                f.t -= v;
            else
                f.t += v;
        }

        void xorHPrime(PopfFunc &f, RandomOracle hPrime) const
        {
            // Last block is unused.
            block hPrimeOut[4];
            hPrime.Update((unsigned char) 1);
            hPrime.Update(f.t);
            hPrime.Final(hPrimeOut);

            for (int i = 0; i < 3; i++)
                f.s[i] = f.s[i] ^ hPrimeOut[i];
        }

        RandomOracle ro;
    };

    class DomainSepFeistelRistPopf: public RandomOracle
    {
        using RandomOracle::Final;
        using RandomOracle::outputLength;

    public:
        typedef FeistelRistPopf ConstructedPopf;
        const static size_t hashLength = Sodium::Rist25519::fromHashLength;
        DomainSepFeistelRistPopf() : RandomOracle(hashLength) {}

        ConstructedPopf construct()
        {
            return FeistelRistPopf(*this);
        }
    };
}

#endif

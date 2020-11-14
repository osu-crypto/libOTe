#pragma once
#include "libOTe/config.h"
#ifdef ENABLE_POPF

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/RandomOracle.h>

namespace osuCrypto
{
    class FeistelMulRistPopf
    {
        using Rist25519 = Sodium::Rist25519;

    public:
        struct PopfFunc
        {
            Rist25519 t;
            Block256 s;
        };

        typedef bool PopfIn;
        typedef Rist25519 PopfOut;

        FeistelMulRistPopf(const RandomOracle& ro_) : ro(ro_) {}
        FeistelMulRistPopf(RandomOracle&& ro_) : ro(ro_) {}

        PopfOut eval(PopfFunc f, PopfIn x) const
        {
            mulXor(f, x);
            addH(f, x, false);

            return f.t;
        }

        PopfFunc program(PopfIn x, PopfOut y, PRNG& prng) const
        {
            PopfFunc f;
            f.t = y;
            prng.get(&f.s, 1);

            addH(f, x, true);
            mulXor(f, x);

            return f;
        }

    private:
        void addH(PopfFunc &f, PopfIn x, bool negate) const
        {
            RandomOracle h = ro;
            h.Update(x);
            h.Update((unsigned char) 0);
            h.Update(f.s);
            Rist25519 v = Rist25519::fromHash(h);

            if (negate)
                f.t -= v;
            else
                f.t += v;
        }

        void mulXor(PopfFunc &f, PopfIn x) const
        {
            uint64_t mask64 = -(uint64_t) x;
            block mask(mask64, mask64);

            Block256 iotaT(f.t.data);
            for (int i = 0; i < 2; i++)
                f.s[i] = f.s[i] ^ (mask & iotaT[i]);
        }

        RandomOracle ro;
    };

    class DomainSepFeistelMulRistPopf: public RandomOracle
    {
        using RandomOracle::Final;
        using RandomOracle::outputLength;

    public:
        typedef FeistelMulRistPopf ConstructedPopf;
        const static size_t hashLength = Sodium::Rist25519::fromHashLength;
        DomainSepFeistelMulRistPopf() : RandomOracle(hashLength) {}

        ConstructedPopf construct()
        {
            return FeistelMulRistPopf(*this);
        }
    };
}

#endif

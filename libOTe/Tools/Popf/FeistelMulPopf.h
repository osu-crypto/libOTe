#pragma once
#include "libOTe/config.h"
#if defined(ENABLE_MRR) || defined(ENABLE_MRR_TWIST)

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/RandomOracle.h>

namespace osuCrypto
{
    class FeistelMulPopf
    {
    public:
        struct PopfFunc
        {
            Block256 t;
            Block256 s;
        };

        typedef bool PopfIn;
        typedef Block256 PopfOut;

        FeistelMulPopf(const RandomOracle& ro_) : ro(ro_) {}
        FeistelMulPopf(RandomOracle&& ro_) : ro(ro_) {}

        PopfOut eval(PopfFunc f, PopfIn x) const
        {
            mulXor(f, x);
            xorH(f, x);

            return f.t;
        }

        PopfFunc program(PopfIn x, PopfOut y, PRNG& prng) const
        {
            PopfFunc f;
            f.t = y;
            prng.get(&f.s, 1);

            xorH(f, x);
            mulXor(f, x);

            return f;
        }

    private:
        void xorH(PopfFunc &f, PopfIn x) const
        {
            RandomOracle h = ro;
            h.Update(x);

            Block256 hOut;
            h.Update(f.s);
            h.Final(hOut);

            for (int i = 0; i < 2; i++)
                f.t[i] = f.t[i] ^ hOut[i];
        }

        void mulXor(PopfFunc &f, PopfIn x) const
        {
            uint64_t mask64 = -(uint64_t) x;
            block mask(mask64, mask64);

            for (int i = 0; i < 2; i++)
                f.s[i] = f.s[i] ^ (mask & f.t[i]);
        }

        RandomOracle ro;
    };

    class DomainSepFeistelMulPopf: public RandomOracle
    {
        using RandomOracle::Final;
        using RandomOracle::outputLength;

    public:
        typedef FeistelMulPopf ConstructedPopf;
        const static size_t hashLength = sizeof(Block256);
        DomainSepFeistelMulPopf() : RandomOracle(hashLength) {}

        ConstructedPopf construct()
        {
            return FeistelMulPopf(*this);
        }
    };
}

#else

// Allow unit tests to use DomainSepFeistelMulPopf as a template argument.
namespace osuCrypto
{
    class DomainSepFeistelMulPopf;
}

#endif

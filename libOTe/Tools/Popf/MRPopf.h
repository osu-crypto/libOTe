#pragma once
#include "libOTe/config.h"
#if defined(ENABLE_MRR) || defined(ENABLE_MRR_TWIST)

#include "libOTe/TwoChooseOne/OTExtInterface.h"
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/Rijndael256.h>
#include <cryptoTools/Crypto/RandomOracle.h>

namespace osuCrypto
{
    class MRPopf
    {
    public:
        typedef std::array<Block256, 2> PopfFunc;
        typedef bool PopfIn;
        typedef Block256 PopfOut;

        MRPopf(const RandomOracle& ro_) : ro(ro_) {}
        MRPopf(RandomOracle&& ro_) : ro(ro_) {}

        PopfOut eval(PopfFunc f, PopfIn x) const
        {
            Block256 mask;
            RandomOracle roMask = ro;
            roMask.Update(f[1-x]);
            roMask.Final(mask);

            f[x][0] = f[x][0] ^ mask[0];
            f[x][1] = f[x][1] ^ mask[1];
            return f[x];
        }

        PopfFunc program(PopfIn x, PopfOut y, PRNG& prng) const
        {
            PopfFunc r;
            prng.get(r[1-x].data(),32);

            Block256 mask;
            RandomOracle roMask = ro;
            roMask.Update(r[1-x]);
            roMask.Final(mask);

            r[x] = y;
            r[x][0] = r[x][0] ^ mask[0];
            r[x][1] = r[x][1] ^ mask[1];

            return r;
        }

    private:
        RandomOracle ro;
    };

    class DomainSepMRPopf: public RandomOracle
    {
        using RandomOracle::Final;
        using RandomOracle::outputLength;

    public:
        typedef MRPopf ConstructedPopf;
        const static size_t hashLength = sizeof(Block256);
        DomainSepMRPopf() : RandomOracle(hashLength) {}

        ConstructedPopf construct()
        {
            return MRPopf(*this);
        }
    };
}

#else

// Allow unit tests to use DomainSepMRPopf as a template argument.
namespace osuCrypto
{
    class DomainSepMRPopf;
}

#endif

#pragma once
#include "libOTe/config.h"
#if defined(ENABLE_MRR_TWIST) && defined(ENABLE_SSE)

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/Rijndael256.h>
#include <cryptoTools/Crypto/RandomOracle.h>

namespace osuCrypto
{
    class EKEPopf
    {
    public:
        typedef Block256 PopfFunc;
        typedef bool PopfIn; // TODO: Make this more general.
        typedef Block256 PopfOut;

        EKEPopf(const RandomOracle& ro_) : ro(ro_) {}
        EKEPopf(RandomOracle&& ro_) : ro(ro_) {}

        PopfOut eval(PopfFunc f, PopfIn x) const
        {
            Rijndael256Dec ic(getKey(x));
            return ic.decBlock(f);
        }

        PopfFunc program(PopfIn x, PopfOut y, PRNG& prng) const
        {
            return program(x, y);
        }

        PopfFunc program(PopfIn x, PopfOut y) const
        {
            Rijndael256Enc ic(getKey(x));
            return ic.encBlock(y);
        }

    private:
        Block256 getKey(PopfIn x) const
        {
            Block256 key;
            RandomOracle roKey = ro;
            roKey.Update(x);
            roKey.Final(key);

            return key;
        }

        RandomOracle ro;
    };
    class DomainSepEKEPopf: public RandomOracle
    {
        using RandomOracle::Final;
        using RandomOracle::outputLength;

    public:
        typedef EKEPopf ConstructedPopf;
        const static size_t hashLength = sizeof(Block256);
        DomainSepEKEPopf() : RandomOracle(hashLength) {}

        ConstructedPopf construct()
        {
            return EKEPopf(*this);
        }
    };

}


#endif

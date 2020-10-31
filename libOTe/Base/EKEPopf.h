#pragma once
#include "libOTe/config.h"
#ifdef ENABLE_POPF

#include "libOTe/TwoChooseOne/OTExtInterface.h"
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/Rijndael256.h>
#include <cryptoTools/Crypto/RandomOracle.h>

namespace osuCrypto
{
    class EKEPopf;
    class DomainSepEKEPopf;

    template<>
    struct PopfTraits<EKEPopf>
    {
        typedef Block256 PopfFunc;
        typedef bool PopfIn; // TODO: Make this more general.
        typedef Block256 PopfOut;
    };

    class EKEPopf : public Popf<EKEPopf>
    {
    public:
        EKEPopf(const RandomOracle& ro_) : ro(ro_) {}
        EKEPopf(RandomOracle&& ro_) : ro(ro_) {}

        PopfOut eval(PopfFunc f, PopfIn x) const
        {
            Rijndael256Dec ic(getKey(x));
            return ic.decBlock(f);
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

    template<>
    struct RODomainSeparatedPopfTraits<DomainSepEKEPopf>
    {
        typedef EKEPopf ConstructedPopf;
    };

    class DomainSepEKEPopf: public RODomainSeparatedPopf<DomainSepEKEPopf>
    {
        typedef RODomainSeparatedPopf<DomainSepEKEPopf> Base;

    public:
        using Base::operator=;

        const static size_t hashLength = sizeof(Block256);

        DomainSepEKEPopf() : Base(hashLength) {}

        ConstructedPopf construct()
        {
            return EKEPopf(*this);
        }
    };
}

#endif

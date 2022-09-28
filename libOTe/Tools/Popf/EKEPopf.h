#pragma once
// © 2020 Lawrence Roy.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

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

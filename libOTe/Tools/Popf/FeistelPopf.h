#pragma once
// © 2020 Lawrence Roy.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#include "libOTe/config.h"
#if defined(ENABLE_MRR) || defined(ENABLE_MRR_TWIST)

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/RandomOracle.h>

namespace osuCrypto
{
    class FeistelPopf
    {
    public:
        struct PopfFunc
        {
            Block256 t;
            block s[3];
        };

        typedef bool PopfIn;
        typedef Block256 PopfOut;

        FeistelPopf(const RandomOracle& ro_) : ro(ro_) {}
        FeistelPopf(RandomOracle&& ro_) : ro(ro_) {}

        PopfOut eval(PopfFunc f, PopfIn x) const
        {
            RandomOracle h = ro;
            h.Update(x);

            xorHPrime(f, h);
            xorH(f, h);

            return f.t;
        }

        PopfFunc program(PopfIn x, PopfOut y, PRNG& prng) const
        {
            RandomOracle h = ro;
            h.Update(x);

            PopfFunc f;
            f.t = y;
            prng.get(f.s, 3);

            xorH(f, h);
            xorHPrime(f, h);

            return f;
        }

    private:
        void xorH(PopfFunc &f, RandomOracle h) const
        {
            // Third block is unused.
            block hOut[3];
            h.Update((unsigned char) 0);
            h.Update(f.s);
            h.Final(hOut);

            for (int i = 0; i < 2; i++)
                f.t[i] = f.t[i] ^ hOut[i];
        }

        void xorHPrime(PopfFunc &f, RandomOracle hPrime) const
        {
            block hPrimeOut[3];
            hPrime.Update((unsigned char) 1);
            hPrime.Update(f.t);
            hPrime.Final(hPrimeOut);

            for (int i = 0; i < 3; i++)
                f.s[i] = f.s[i] ^ hPrimeOut[i];
        }

        RandomOracle ro;
    };

    class DomainSepFeistelPopf: public RandomOracle
    {
        using RandomOracle::Final;
        using RandomOracle::outputLength;

    public:
        typedef FeistelPopf ConstructedPopf;
        const static size_t hashLength = sizeof(block[3]);
        DomainSepFeistelPopf() : RandomOracle(hashLength) {}

        ConstructedPopf construct()
        {
            return FeistelPopf(*this);
        }
    };
}

#else

// Allow unit tests to use DomainSepFeistelPopf as a template argument.
namespace osuCrypto
{
    class DomainSepFeistelPopf;
}

#endif

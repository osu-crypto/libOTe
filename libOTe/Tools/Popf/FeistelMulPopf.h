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

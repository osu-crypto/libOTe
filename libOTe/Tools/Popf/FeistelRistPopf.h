#pragma once
// © 2020 Lawrence Roy.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#include "libOTe/config.h"
#ifdef ENABLE_MRR

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/RandomOracle.h>
#include "libOTe/Tools/DefaultCurve.h"

namespace osuCrypto
{
    class FeistelRistPopf
    {
        using Point = DefaultCurve::Point;
        friend class DomainSepFeistelRistPopf;

        const static size_t hashLength =
            Point::fromHashLength >= sizeof(block[3]) ? Point::fromHashLength : sizeof(block[3]);

    public:
        struct PopfFunc
        {
            unsigned char t[Point::size];
            block s[3];
        };

        typedef bool PopfIn;
        typedef Point PopfOut;

        FeistelRistPopf(const RandomOracle& ro_) : ro(ro_) {}
        FeistelRistPopf(RandomOracle&& ro_) : ro(ro_) {}

        PopfOut eval(PopfFunc f, PopfIn x) const
        {
            RandomOracle h = ro;
            h.Update(x);
            xorHPrime(f, h);

            Point t;
            t.fromBytes(f.t);
            addH(t, f.s, h, false);

            return t;
        }

        PopfFunc program(PopfIn x, PopfOut y, PRNG& prng) const
        {
            RandomOracle h = ro;
            h.Update(x);

            PopfFunc f;
            prng.get(f.s, 3);

            addH(y, f.s, h, true);
            y.toBytes(f.t);
            xorHPrime(f, h);

            return f;
        }

    private:
        void addH(Point& t, const block s[], RandomOracle h, bool negate) const
        {
            unsigned char hOut[hashLength];
            h.Update((unsigned char) 0);
            h.Update(s, 3);
            h.Final(hOut);

            Point v = Point::fromHash(hOut);
            if (negate)
                t -= v;
            else
                t += v;
        }

        void xorHPrime(PopfFunc &f, RandomOracle hPrime) const
        {
            block hPrimeOut[divCeil(hashLength, sizeof(block))];
            hPrime.Update((unsigned char) 1);
            hPrime.Update(f.t, Point::size);
            hPrime.Final((unsigned char*) &hPrimeOut);

            for (int i = 0; i < 3; i++)
                f.s[i] = f.s[i] ^ hPrimeOut[i];
        }

        RandomOracle ro;
    };

    class DomainSepFeistelRistPopf: public RandomOracle
    {
        using RandomOracle::Final;
        using RandomOracle::outputLength;
        using Point = DefaultCurve::Point;

    public:
        typedef FeistelRistPopf ConstructedPopf;
        const static size_t hashLength = FeistelRistPopf::hashLength;
        DomainSepFeistelRistPopf() : RandomOracle(hashLength) {}

        ConstructedPopf construct()
        {
            return FeistelRistPopf(*this);
        }
    };
}

#else

// Allow unit tests to use DomainSepFeistelRistPopf as a template argument.
namespace osuCrypto
{
    class DomainSepFeistelRistPopf;
}

#endif

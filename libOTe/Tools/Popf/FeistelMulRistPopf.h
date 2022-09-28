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
    class FeistelMulRistPopf
    {
        using Point = DefaultCurve::Point;

    public:
        struct PopfFunc
        {
            unsigned char t[Point::size];
            unsigned char s[Point::size];
        };

        typedef bool PopfIn;
        typedef Point PopfOut;

        FeistelMulRistPopf(const RandomOracle& ro_) : ro(ro_) {}
        FeistelMulRistPopf(RandomOracle&& ro_) : ro(ro_) {}

        PopfOut eval(PopfFunc f, PopfIn x) const
        {
            mulXor(f, x);

            Point t;
            t.fromBytes(f.t);
            addH(t, f.s, x, false);

            return t;
        }

        PopfFunc program(PopfIn x, PopfOut y, PRNG& prng) const
        {
            PopfFunc f;
            prng.get(f.s, Point::size);

            addH(y, f.s, x, true);
            y.toBytes(f.t);
            mulXor(f, x);

            return f;
        }

    private:
        void addH(Point& t, const unsigned char s[], PopfIn x, bool negate) const
        {
            RandomOracle h = ro;
            h.Update(x);
            h.Update(s, Point::size);
            Point v = Point::fromHash(h);

            if (negate)
                t -= v;
            else
                t += v;
        }

        void mulXor(PopfFunc &f, PopfIn x) const
        {
            unsigned char mask = -(unsigned char) x;
            for (size_t i = 0; i < Point::size; i++)
                f.s[i] ^= mask & f.t[i];
        }

        RandomOracle ro;
    };

    class DomainSepFeistelMulRistPopf: public RandomOracle
    {
        using RandomOracle::Final;
        using RandomOracle::outputLength;

    public:
        typedef FeistelMulRistPopf ConstructedPopf;
        const static size_t hashLength = DefaultCurve::Point::fromHashLength;
        DomainSepFeistelMulRistPopf() : RandomOracle(hashLength) {}

        ConstructedPopf construct()
        {
            return FeistelMulRistPopf(*this);
        }
    };
}

#else

// Allow unit tests to use DomainSepFeistelMulRistPopf as a template argument.
namespace osuCrypto
{
    class DomainSepFeistelMulRistPopf;
}

#endif

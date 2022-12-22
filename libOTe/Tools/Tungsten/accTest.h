#pragma once

#include "cryptoTools/Common/CLP.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Log.h"

namespace osuCrypto
{


    void accTest(const oc::CLP& cmd);
    void periodTest(const oc::CLP& cmd);
    void accPr(const oc::CLP& cmd);

    struct color
    {
        BitVector mBv;
        Color cc;
        char spacing;
        color(BitVector bv, Color c = Color::Green, char s = 0)
            :mBv(std::move(bv))
            , cc(c)
            ,spacing(s)
        {
        }
    };

    inline std::ostream& operator<<(std::ostream& o, const color& c)
    {

        Color cur = Color::Default;
        Color alt = c.cc;
        for (u64 i = 0; i < c.mBv.size(); ++i)
        {
            if (c.mBv[i] != (cur == c.cc))
            {
                o << alt;
                std::swap(alt, cur);
            }

            o << c.mBv[i];
            if (c.spacing)
                o << c.spacing;
        }

        //if (cur != Color::Default)
        o << Color::White;

        return o;
    }

}
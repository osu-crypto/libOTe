#include "libOTe/config.h"
#include "cryptoTools/Common/block.h"
#include "cryptoTools/Common/Defines.h"

namespace osuCrypto
{
    struct GF128
    {
        block mData;


        GF128() = default;
        GF128(u64 v) : mData(0, v) {}
        GF128(block v) : mData(v) {}
        GF128(const GF128&) = default;
        GF128& operator=(const GF128&) = default;


        GF128& operator+=(const GF128& o)
        {
            mData = mData ^ o.mData;
            return *this;
        }
        GF128 operator+(const GF128& o) const
        {
            GF128 r;
            r.mData = mData ^ o.mData;
            return r;
        };

        GF128& operator-=(const GF128& o)
        {
            mData = mData ^ o.mData;
            return *this;
        }
        GF128 operator-(const GF128& o) const
        {
            GF128 r;
            r.mData = mData ^ o.mData;
            return r;
        };

        GF128 operator-() const
        {
            return *this;
        };

        GF128 operator*(const GF128& o) const
        {
            GF128 r;
            r.mData = mData.gf128Mul(o.mData);
            return r;
        };

        GF128& operator*=(const GF128& o)
        {
            mData = mData.gf128Mul(o.mData);
            return *this;
        };


        //GF128 inverse() const
        //{
        //    // the modulus is 1<<128 + mod
        //    static const constexpr std::uint64_t mod = 0b10000111;
        //    const block modulus = block(mod);

        //    GF128 t = 0;
        //    GF128 tt = 1;
        //    GF128 r = modulus;
        //    GF128 rr = a;


        //    while (rr)
        //    {

        //        auto q = r / rr;

        //        auto r2 = r - q * rr;
        //        r = rr;
        //        rr = r2;

        //        auto t2 = t - q * tt;
        //        t = tt;
        //        tt = t2;

        //    }

        //}
        
    };
}
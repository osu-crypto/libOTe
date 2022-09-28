#include "bitpolymul.h"
#ifdef ENABLE_BITPOLYMUL
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <vector>

#include "bitpolymul/bc.h"
#include "bitpolymul/gfext_aesni.h"
#include "bitpolymul/bpmDefines.h"
#include "bitpolymul/btfy.h"
#include "bitpolymul/encode.h"

#include <cryptoTools/Common/Defines.h>

using namespace oc;
using namespace bpm;

namespace osuCrypto
{
    void FFTPoly::resize(u64 n)
    {
        if (mN == n)
            return;

        if (n == 0)
        {
            mN = 0;
            mNPow2 = 0;
            mPoly.clear();
        }
        else
        {
            mN = n;
            // round up to the next power of 2
            u64 log_n = oc::log2ceil(mN);
            mNPow2 = std::max<u64>(1ull << log_n, 256);
            mPoly.resize(2 * mNPow2);
        }
    }


    void FFTPoly::encode(span<const u64> data)
    {
        resize(data.size());

        if (!mN)
            return;

        u64 log_n = oc::log2ceil(mNPow2);


        // encode a
        aligned_vector<u64> temp;
        temp.reserve(mNPow2);
        temp.insert(temp.end(), data.begin(), data.end());
        temp.resize(mNPow2);

        bc_to_lch_2_unit256(temp.data(), mNPow2);
        encode_128_half_input_zero(mPoly.data(), temp.data(), mNPow2);
        btfy_128(mPoly.data(), mNPow2, 64 + log_n + 1);
    }


    void FFTPoly::multEq(const FFTPoly& b)
    {
        mult(*this, b);
    }
    void FFTPoly::mult(const FFTPoly& a, const FFTPoly& b)
    {
        if (a.mNPow2 != b.mNPow2)
            throw RTE_LOC;

        resize(a.mN);

        for (uint64_t i = 0; i < mNPow2; i++)
        {
            // mPoly = a.mPoly * b.mPoly
            gf2ext128_mul_sse(
                (uint8_t*)& mPoly[i * 2],
                (uint8_t*)& a.mPoly[i * 2],
                (uint8_t*)& b.mPoly[i * 2]);
        }
    }

    void FFTPoly::addEq(const FFTPoly& b)
    {
        add(*this, b);
    }

    void FFTPoly::add(const FFTPoly& a, const FFTPoly& b)
    {
        if (a.mNPow2 != b.mNPow2)
            throw RTE_LOC;

        resize(a.mN);

        for (uint64_t i = 0; i < mPoly.size(); i++)
        {
            mPoly[i] = a.mPoly[i] ^ b.mPoly[i];
        }
    }


    void FFTPoly::decode(span<u64> dest, bool destructive)
    {
        DecodeCache cache;
        decode(dest, cache, destructive);
    }

    void FFTPoly::decode(span<u64> dest, DecodeCache& cache, bool destructive)
    {
        if (static_cast<u64>(dest.size()) != 2 * mN)
            throw RTE_LOC;

        if (cache.mTemp.size() < mPoly.size())
            cache.mTemp.resize(mPoly.size());

        //aligned_vector<u64> temp1( mPoly.begin(), mPoly.end());
        u64* ptr;
        if (destructive)
        {
            ptr = mPoly.data();
        }
        else
        {
            cache.mTemp2.reserve(mPoly.size());
            cache.mTemp2.insert(cache.mTemp2.end(), mPoly.begin(), mPoly.end());
            ptr = cache.mTemp2.data();
        }


        u64 log_n = oc::log2ceil(mNPow2);
        i_btfy_128(ptr, mNPow2, 64 + log_n + 1);
        decode_128(cache.mTemp.data(), ptr, mNPow2);
        bc_to_mono_2_unit256(cache.mTemp.data(), 2 * mNPow2);

        // copy out
        memcpy(dest.data(), cache.mTemp.data(), dest.size() * sizeof(u64));


        if (destructive)
            resize(0);
    }


    void bitpolymul(uint64_t* c, const uint64_t* a, const uint64_t* b, uint64_t _n_64)
    {
        auto n = _n_64;
        FFTPoly A(span<const u64>(a, n));
        FFTPoly B(span<const u64>(b, n));

        A.multEq(B);

        A.decode({ c, 2 * n });
    }


}
#endif
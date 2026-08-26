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

        if (n > MaxSize)
            throw std::invalid_argument("bitpolymul input exceeds the supported range. " LOCATION);

        if (n == 0)
        {
            mN = 0;
            mNPow2 = 0;
            mPoly.clear();
        }
        else
        {
            // round up to the next power of 2
            const u64 log_n = oc::log2ceil(n);
            const u64 nPow2 = std::max<u64>(1ull << log_n, 256);
            mPoly.resize(2 * nPow2);
            mN = n;
            mNPow2 = nPow2;
        }
    }


    void FFTPoly::encode(span<const u64> data)
    {
        encode(data.data(), data.size());
    }

    void FFTPoly::encode(span<const block> data)
    {
        if (data.size() > MaxSize / 2)
            throw std::invalid_argument("bitpolymul input exceeds the supported range. " LOCATION);

        encode(data.data(), data.size() * 2);
    }

    void FFTPoly::encode(const void* data, u64 size64)
    {
        resize(size64);

        if (!mN)
            return;

        u64 log_n = oc::log2ceil(mNPow2);


        // encode a
        aligned_vector<u64> temp(mNPow2);
        memcpy(temp.data(), data, size64 * sizeof(u64));

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
        decode(dest.data(), dest.size() * sizeof(u64), cache, destructive);
    }

    void FFTPoly::decode(span<block> dest, bool destructive)
    {
        DecodeCache cache;
        decode(dest, cache, destructive);
    }

    void FFTPoly::decode(span<block> dest, DecodeCache& cache, bool destructive)
    {
        decode(dest.data(), dest.size() * sizeof(block), cache, destructive);
    }

    void FFTPoly::decode(void* dest, u64 sizeBytes, DecodeCache& cache, bool destructive)
    {
        if (sizeBytes != 2 * mN * sizeof(u64))
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
            cache.mTemp2.assign(mPoly.begin(), mPoly.end());
            ptr = cache.mTemp2.data();
        }


        u64 log_n = oc::log2ceil(mNPow2);
        i_btfy_128(ptr, mNPow2, 64 + log_n + 1);
        decode_128(cache.mTemp.data(), ptr, mNPow2);
        bc_to_mono_2_unit256(cache.mTemp.data(), 2 * mNPow2);

        // copy out
        memcpy(dest, cache.mTemp.data(), sizeBytes);


        if (destructive)
            resize(0);
    }


    void bitpolymul(uint64_t* c, const uint64_t* a, const uint64_t* b, uint64_t _n_64)
    {
        auto n = _n_64;
        if (n > FFTPoly::MaxSize)
            throw std::invalid_argument("bitpolymul input exceeds the supported range. " LOCATION);
        FFTPoly A(span<const u64>(a, n));
        FFTPoly B(span<const u64>(b, n));

        A.multEq(B);

        A.decode({ c, 2 * n });
    }


}
#endif

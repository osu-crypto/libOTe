#include "bitpolymul.h"
#ifdef ENABLE_SILENTOT
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

namespace bpm
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
        i64 n = i64(_n_64);
        bpm::FFTPoly A(span<const u64>(a, n));
        bpm::FFTPoly B(span<const u64>(b, n));

        A.multEq(B);

        A.decode({ c, 2 * n });
    }


    void bitpolymul_2_128(uint64_t* c, const uint64_t* a, const uint64_t* b, u64 _n_64)
    {
        if (0 == _n_64) return;
        u64 n_64 = 0;
        if (1 == _n_64)
            n_64 = _n_64;
        else {
            n_64 = 1ull << oc::log2ceil(_n_64);
        }

        if (256 > n_64) n_64 = 256;

        auto a_bc = bpm::aligned_vector<u64>(n_64);
        auto b_bc = bpm::aligned_vector<u64>(n_64);

        memcpy(a_bc.data(), a, sizeof(uint64_t) * _n_64);
        for (u64 i = _n_64; i < n_64; i++) a_bc[i] = 0;
        bc_to_lch_2_unit256(a_bc.data(), n_64);

        memcpy(b_bc.data(), b, sizeof(uint64_t) * _n_64);
        for (u64 i = _n_64; i < n_64; i++) b_bc[i] = 0;
        bc_to_lch_2_unit256(b_bc.data(), n_64);


        u64 n_terms = n_64;
        u64 log_n = __builtin_ctzll(n_terms);
        auto a_fx = bpm::aligned_vector<u64>(2 * n_terms);
        auto b_fx = bpm::aligned_vector<u64>(2 * n_terms);

        encode_128_half_input_zero(a_fx.data(), a_bc.data(), n_terms);
        encode_128_half_input_zero(b_fx.data(), b_bc.data(), n_terms);

        btfy_128(b_fx.data(), n_terms, 64 + log_n + 1);
        btfy_128(a_fx.data(), n_terms, 64 + log_n + 1);

        for (u64 i = 0; i < n_terms; i++)
        {
            gf2ext128_mul_sse(
                (uint8_t*)& a_fx[i * 2],
                (uint8_t*)& a_fx[i * 2],
                (uint8_t*)& b_fx[i * 2]);
        }

        i_btfy_128(a_fx.data(), n_terms, 64 + log_n + 1);

        decode_128(b_fx.data(), a_fx.data(), n_terms);

        bc_to_mono_2_unit256(b_fx.data(), 2 * n_64);

        for (u64 i = 0; i < (2 * _n_64); i++) {
            c[i] = b_fx[i];
        }

    }






    ///////////////////////////////////////////////////


    void bitpolymul_2_64(uint64_t* c, const uint64_t* a, const uint64_t* b, u64 _n_64)
    {
        if (0 == _n_64) return;
        if (_n_64 > (1 << 26)) { printf("un-supported length of polynomials."); exit(-1); }
        u64 n_64 = 0;
        if (1 == _n_64) n_64 = _n_64;
        else {
            n_64 = 1ull << oc::log2ceil(_n_64);
        }

        if (256 > n_64) n_64 = 256;

        auto a_bc_ = bpm::aligned_vector<u64>(n_64);
        auto b_bc_ = bpm::aligned_vector<u64>(n_64);
        uint64_t* a_bc = a_bc_.data();
        uint64_t* b_bc = b_bc_.data();

        memcpy(a_bc, a, sizeof(uint64_t) * _n_64);
        for (u64 i = _n_64; i < n_64; i++) a_bc[i] = 0;
        bc_to_lch_2_unit256(a_bc, n_64);

        memcpy(b_bc, b, sizeof(uint64_t) * _n_64);
        for (u64 i = _n_64; i < n_64; i++) b_bc[i] = 0;
        bc_to_lch_2_unit256(b_bc, n_64);


        u64 n_terms = n_64 * 2;
        u64 log_n = __builtin_ctzll(n_terms);

        auto a_fx_ = bpm::aligned_vector<u64>(n_terms);
        auto b_fx_ = bpm::aligned_vector<u64>(n_terms);
        uint64_t* a_fx = a_fx_.data();
        uint64_t* b_fx = b_fx_.data();

        encode_64_half_input_zero(a_fx, a_bc, n_terms);
        encode_64_half_input_zero(b_fx, b_bc, n_terms);

        btfy_64(b_fx, n_terms, 32 + log_n + 1);
        btfy_64(a_fx, n_terms, 32 + log_n + 1);

        for (u64 i = 0; i < n_terms; i += 4) {
            cache_prefetch(&a_fx[i + 4], _MM_HINT_T0);
            cache_prefetch(&b_fx[i + 4], _MM_HINT_T0);
            gf2ext64_mul_4x4_avx2((uint8_t*)& a_fx[i], (uint8_t*)& a_fx[i], (uint8_t*)& b_fx[i]);
        }
        i_btfy_64(a_fx, n_terms, 32 + log_n + 1);
        decode_64(b_fx, a_fx, n_terms);

        bc_to_mono_2_unit256(b_fx, n_terms);

        for (u64 i = 0; i < (2 * _n_64); i++) {
            c[i] = b_fx[i];
        }
    }

}
#endif
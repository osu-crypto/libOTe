#pragma once

#include "cryptoTools/Common/Defines.h"
#include "libOTe/Tools/LDPC/Mtx.h"
#include "cryptoTools/Common/Range.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "libOTe/Tools/LDPC/LdpcEncoder.h"

#include "libOTe/Tools/EACode/Util.h"

namespace osuCrypto
{

    // THe encoder for the generator matrix G = B * A.
    // B is the expander while A is the convolution.
    // 
    // B has mMessageSize rows and mCodeSize columns. It is sampled uniformly
    // with fixed row weight mExpanderWeight.
    //
    // A is a lower triangular n by n matrix with ones on the diagonal. The
    // mAccumulatorSize diagonals left of the main diagonal are uniformly random.
    // If mStickyAccumulator, then the first diagonal left of the main is always ones.
    class ExConvCode : public TimerAdapter
    {
    public:

        void config(
            u64 messageSize,
            u64 codeSize,
            u64 expanderWeight,
            u64 accumulatorSize,
            bool wrapping,
            block seed = block(0, 0))
        {
            mMessageSize = messageSize;
            mCodeSize = codeSize;
            mExpanderWeight = expanderWeight;
            mAccumulatorSize = accumulatorSize;
            mWrapping = wrapping;
            mSeed = seed;

        }

        // the seed that generates the code.
        block mSeed = block(0, 0);

        // The message size of the code. K.
        u64 mMessageSize = 0;

        // The codeword size of the code. n.
        u64 mCodeSize = 0;

        // The row weight of the B matrix.
        u64 mExpanderWeight = 0;

        // The size of the accumulator.
        u64 mAccumulatorSize = 0;

        bool mWrapping = false;

        bool mTrans = false;

        u64 parityRows() const { return mCodeSize - mMessageSize; }
        u64 parityCols() const { return mCodeSize; }

        u64 generatorRows() const { return mMessageSize; }
        u64 generatorCols() const { return mCodeSize; }

        // Compute w = G * e.
        template<typename T>
        void dualEncode(span<T> e, span<T> w)
        {
            if (e.size() != mCodeSize)
                throw RTE_LOC;
            if(w.size() != mMessageSize)
                throw RTE_LOC;


            setTimePoint("ExConv.encode.begin");

            accumulate<T>(e);

            setTimePoint("ExConv.encode.accumulate");

            expand<T>(e, w);
            setTimePoint("ExConv.encode.expand");
        }


        //template<typename T>
        //void dualEncode2(span<T> e0, span<T> e1, span<T> w0, span<T> w1)
        //{
        //    assert(e0.size() == mCodeSize);
        //    assert(e1.size() == mCodeSize);
        //    assert(w0.size() == mMessageSize);
        //    assert(w1.size() == mMessageSize);

        //    setTimePoint("ExConv.encode.begin");

        //    accumulate2<T>(e0,e1);

        //    setTimePoint("ExConv.encode.accumulate");

        //    expand2<T>(e0, e1, w0, w1);
        //    setTimePoint("ExConv.encode.expand");
        //}

        OC_FORCEINLINE void accOne(
            PointList& pl,
            u64 i,
            u8* __restrict& ptr,
            PRNG& prng,
            block& rnd,
            u64& q,
            u64 qe) const
        {
            u64 j = i + 1;
            pl.push_back(i, i);

            {
                if (q + mAccumulatorSize > qe)
                {

                    assert(prng.mBuffer.size() == 256);
                    //block b[8];
                    for (u64 i = 0; i < 256; i += 8)
                    {
                        //auto idx = mPrng.mBuffer[i].get<u8>();
                        block* __restrict b = prng.mBuffer.data() + i;
                        block* __restrict k = prng.mBuffer.data() + (u8)(i - 8);
                        //for (u64 j = 0; j < 8; ++j)
                        //{
                        //    b = b ^ mPrng.mBuffer.data()[idx[j]];
                        //}
                        b[0] = AES::roundEnc(b[0], k[0]);
                        b[1] = AES::roundEnc(b[1], k[1]);
                        b[2] = AES::roundEnc(b[2], k[2]);
                        b[3] = AES::roundEnc(b[3], k[3]);
                        b[4] = AES::roundEnc(b[4], k[4]);
                        b[5] = AES::roundEnc(b[5], k[5]);
                        b[6] = AES::roundEnc(b[6], k[6]);
                        b[7] = AES::roundEnc(b[7], k[7]);

                        b[0] = b[0] ^ k[0];
                        b[1] = b[1] ^ k[1];
                        b[2] = b[2] ^ k[2];
                        b[3] = b[3] ^ k[3];
                        b[4] = b[4] ^ k[4];
                        b[5] = b[5] ^ k[5];
                        b[6] = b[6] ^ k[6];
                        b[7] = b[7] ^ k[7];
                    }


                    ptr = (u8*)prng.mBuffer.data();
                    q = 0;
                }

                assert(ptr < (u8*)(prng.mBuffer.data() + prng.mBuffer.size()));
            }

            for (u64 k = 0; k < mAccumulatorSize; k += 8, q += 8, j += 8)
            {
                assert(ptr < (u8*)(prng.mBuffer.data() + prng.mBuffer.size()));
                rnd = block::allSame<u8>(*ptr);
                ++ptr;

                //std::cout << "r " << rnd << std::endl;
                auto b0 = rnd;
                auto b1 = rnd.mm_slli_epi32<1>();
                auto b2 = rnd.mm_slli_epi32<2>();
                auto b3 = rnd.mm_slli_epi32<3>();
                auto b4 = rnd.mm_slli_epi32<4>();
                auto b5 = rnd.mm_slli_epi32<5>();
                auto b6 = rnd.mm_slli_epi32<6>();
                auto b7 = rnd.mm_slli_epi32<7>();
                //rnd = rnd.mm_slli_epi32<8>();

                if (j + 0 < mCodeSize && b0.get<i32>(0) < 0) pl.push_back(j + 0, i);
                if (j + 1 < mCodeSize && b1.get<i32>(0) < 0) pl.push_back(j + 1, i);
                if (j + 2 < mCodeSize && b2.get<i32>(0) < 0) pl.push_back(j + 2, i);
                if (j + 3 < mCodeSize && b3.get<i32>(0) < 0) pl.push_back(j + 3, i);
                if (j + 4 < mCodeSize && b4.get<i32>(0) < 0) pl.push_back(j + 4, i);
                if (j + 5 < mCodeSize && b5.get<i32>(0) < 0) pl.push_back(j + 5, i);
                if (j + 6 < mCodeSize && b6.get<i32>(0) < 0) pl.push_back(j + 6, i);
                if (j + 7 < mCodeSize && b7.get<i32>(0) < 0) pl.push_back(j + 7, i);
            }


            if (mWrapping)
            {
                if (j < mCodeSize)
                    pl.push_back(j, i);
                ++j;
            }

        }


        template<typename T, bool rangeCheck, int width>
        OC_FORCEINLINE void accOneTrans(
            T* __restrict xx,
            u64 i,
            u8*& ptr,
            PRNG& prng,
            u64& q,
            u64 qe)
        {
            u64 j = i - width * 8 - 1;
            auto xi = xx + i;

            if (!rangeCheck || j < mCodeSize)
            {

                auto wrap = xx + j;
                *xi = *xi ^ *wrap;
            }
            ++j;

            if (width)
            {

                T buf[8];
                __m128 Zero = _mm_setzero_ps();

                {
                    if (q + width > qe)
                    {
                        //assert(prng.mBuffer.size() == 256);
                        //for (u64 i = 0; i < 256; ++i)
                        //{
                        //    block b = prng.mBuffer.data()[i];
                        //    block k = prng.mBuffer.data()[(u8)(i - 1)];
                        //    prng.mBuffer[i] = AES::roundEnc(b, k) ^ k;
                        //}
                        assert(prng.mBuffer.size() == 256);
                        //block b[8];
                        for (u64 i = 0; i < 256; i += 8)
                        {
                            //auto idx = mPrng.mBuffer[i].get<u8>();
                            block* __restrict b = prng.mBuffer.data() + i;
                            block* __restrict k = prng.mBuffer.data() + (u8)(i - 8);
                            //for (u64 j = 0; j < 8; ++j)
                            //{
                            //    b = b ^ mPrng.mBuffer.data()[idx[j]];
                            //}
                            b[0] = AES::roundEnc(b[0], k[0]);
                            b[1] = AES::roundEnc(b[1], k[1]);
                            b[2] = AES::roundEnc(b[2], k[2]);
                            b[3] = AES::roundEnc(b[3], k[3]);
                            b[4] = AES::roundEnc(b[4], k[4]);
                            b[5] = AES::roundEnc(b[5], k[5]);
                            b[6] = AES::roundEnc(b[6], k[6]);
                            b[7] = AES::roundEnc(b[7], k[7]);

                            b[0] = b[0] ^ k[0];
                            b[1] = b[1] ^ k[1];
                            b[2] = b[2] ^ k[2];
                            b[3] = b[3] ^ k[3];
                            b[4] = b[4] ^ k[4];
                            b[5] = b[5] ^ k[5];
                            b[6] = b[6] ^ k[6];
                            b[7] = b[7] ^ k[7];
                        }

                        ptr = (u8*)prng.mBuffer.data();
                        q = 0;
                    }
                    q += width;
                    assert(ptr < (u8*)(prng.mBuffer.data() + prng.mBuffer.size()));
                }

                for (u64 k = 0; k < width; ++k, j += 8)
                {
                    assert(ptr < (u8*)(prng.mBuffer.data() + prng.mBuffer.size()));
                    block rnd = _mm_set1_epi8(*(u8*)ptr++);

                    block b0 = rnd;
                    block b1 = _mm_slli_epi32(rnd, 1);;
                    block b2 = _mm_slli_epi32(rnd, 2);
                    block b3 = _mm_slli_epi32(rnd, 3);
                    block b4 = _mm_slli_epi32(rnd, 4);
                    block b5 = _mm_slli_epi32(rnd, 5);
                    block b6 = _mm_slli_epi32(rnd, 6);
                    block b7 = _mm_slli_epi32(rnd, 7);

                    if (!rangeCheck)
                    {


                        auto bb0 = _mm_load_ps((float*)&b0);
                        auto bb1 = _mm_load_ps((float*)&b1);
                        auto bb2 = _mm_load_ps((float*)&b2);
                        auto bb3 = _mm_load_ps((float*)&b3);
                        auto bb4 = _mm_load_ps((float*)&b4);
                        auto bb5 = _mm_load_ps((float*)&b5);
                        auto bb6 = _mm_load_ps((float*)&b6);
                        auto bb7 = _mm_load_ps((float*)&b7);

                        auto xj0 = _mm_load_ps((float*)(xx + j + 0));
                        auto xj1 = _mm_load_ps((float*)(xx + j + 1));
                        auto xj2 = _mm_load_ps((float*)(xx + j + 2));
                        auto xj3 = _mm_load_ps((float*)(xx + j + 3));
                        auto xj4 = _mm_load_ps((float*)(xx + j + 4));
                        auto xj5 = _mm_load_ps((float*)(xx + j + 5));
                        auto xj6 = _mm_load_ps((float*)(xx + j + 6));
                        auto xj7 = _mm_load_ps((float*)(xx + j + 7));




                        buf[0] = *(block*)&_mm_blendv_ps(Zero, xj0, bb0);
                        buf[1] = *(block*)&_mm_blendv_ps(Zero, xj1, bb1);
                        buf[2] = *(block*)&_mm_blendv_ps(Zero, xj2, bb2);
                        buf[3] = *(block*)&_mm_blendv_ps(Zero, xj3, bb3);
                        buf[4] = *(block*)&_mm_blendv_ps(Zero, xj4, bb4);
                        buf[5] = *(block*)&_mm_blendv_ps(Zero, xj5, bb5);
                        buf[6] = *(block*)&_mm_blendv_ps(Zero, xj6, bb6);
                        buf[7] = *(block*)&_mm_blendv_ps(Zero, xj7, bb7);

                        xx[i] = xx[i]
                            ^ buf[0]
                            ^ buf[1]
                            ^ buf[2]
                            ^ buf[3]
                            ^ buf[4]
                            ^ buf[5]
                            ^ buf[6]
                            ^ buf[7];
                    }
                    else
                    {

                        if (j + 0 < mCodeSize && b0.get<i32>(0) < 0) xx[i] = xx[i] ^ xx[j + 0];
                        if (j + 1 < mCodeSize && b1.get<i32>(0) < 0) xx[i] = xx[i] ^ xx[j + 1];
                        if (j + 2 < mCodeSize && b2.get<i32>(0) < 0) xx[i] = xx[i] ^ xx[j + 2];
                        if (j + 3 < mCodeSize && b3.get<i32>(0) < 0) xx[i] = xx[i] ^ xx[j + 3];
                        if (j + 4 < mCodeSize && b4.get<i32>(0) < 0) xx[i] = xx[i] ^ xx[j + 4];
                        if (j + 5 < mCodeSize && b5.get<i32>(0) < 0) xx[i] = xx[i] ^ xx[j + 5];
                        if (j + 6 < mCodeSize && b6.get<i32>(0) < 0) xx[i] = xx[i] ^ xx[j + 6];
                        if (j + 7 < mCodeSize && b7.get<i32>(0) < 0) xx[i] = xx[i] ^ xx[j + 7];
                    }
                }
            }
        }



        template<typename T, bool rangeCheck, int width>
        OC_FORCEINLINE void accOne(
            T* __restrict xx,
            u64 i,
            u8*& ptr,
            PRNG& prng,
            u64& q,
            u64 qe)
        {
            u64 j = i + 1;
            if (width)
            {

                T buf[8];
                __m128 Zero = _mm_setzero_ps();

                auto xii = _mm_load_ps((float*)(xx + i));

                //xi = xj;



                {
                    if (q + width > qe)
                    {
                        assert(prng.mBuffer.size() == 256);
                        //block b[8];
                        for (u64 i = 0; i < 256; i += 8)
                        {
                            //auto idx = mPrng.mBuffer[i].get<u8>();
                            block* __restrict b = prng.mBuffer.data() + i;
                            block* __restrict k = prng.mBuffer.data() + (u8)(i - 8);
                            //for (u64 j = 0; j < 8; ++j)
                            //{
                            //    b = b ^ mPrng.mBuffer.data()[idx[j]];
                            //}
                            b[0] = AES::roundEnc(b[0], k[0]);
                            b[1] = AES::roundEnc(b[1], k[1]);
                            b[2] = AES::roundEnc(b[2], k[2]);
                            b[3] = AES::roundEnc(b[3], k[3]);
                            b[4] = AES::roundEnc(b[4], k[4]);
                            b[5] = AES::roundEnc(b[5], k[5]);
                            b[6] = AES::roundEnc(b[6], k[6]);
                            b[7] = AES::roundEnc(b[7], k[7]);

                            b[0] = b[0] ^ k[0];
                            b[1] = b[1] ^ k[1];
                            b[2] = b[2] ^ k[2];
                            b[3] = b[3] ^ k[3];
                            b[4] = b[4] ^ k[4];
                            b[5] = b[5] ^ k[5];
                            b[6] = b[6] ^ k[6];
                            b[7] = b[7] ^ k[7];
                        }
                        ptr = (u8*)prng.mBuffer.data();
                        q = 0;
                    }
                    q += width;
                    assert(ptr < (u8*)(prng.mBuffer.data() + prng.mBuffer.size()));
                }

                for (u64 k = 0; k < width; ++k, j += 8)
                {
                    assert(ptr < (u8*)(prng.mBuffer.data() + prng.mBuffer.size()));
                    block rnd = _mm_set1_epi8(*(u8*)ptr++);


                    block b0 = rnd;
                    block b1 = _mm_slli_epi32(rnd, 1);;
                    block b2 = _mm_slli_epi32(rnd, 2);
                    block b3 = _mm_slli_epi32(rnd, 3);
                    block b4 = _mm_slli_epi32(rnd, 4);
                    block b5 = _mm_slli_epi32(rnd, 5);
                    block b6 = _mm_slli_epi32(rnd, 6);
                    block b7 = _mm_slli_epi32(rnd, 7);

                    if constexpr (std::is_same<block, T>::value)
                    {

                        auto bb0 = _mm_load_ps((float*)&b0);
                        auto bb1 = _mm_load_ps((float*)&b1);
                        auto bb2 = _mm_load_ps((float*)&b2);
                        auto bb3 = _mm_load_ps((float*)&b3);
                        auto bb4 = _mm_load_ps((float*)&b4);
                        auto bb5 = _mm_load_ps((float*)&b5);
                        auto bb6 = _mm_load_ps((float*)&b6);
                        auto bb7 = _mm_load_ps((float*)&b7);


                        buf[0] = *(block*)&_mm_blendv_ps(Zero, xii, bb0);
                        buf[1] = *(block*)&_mm_blendv_ps(Zero, xii, bb1);
                        buf[2] = *(block*)&_mm_blendv_ps(Zero, xii, bb2);
                        buf[3] = *(block*)&_mm_blendv_ps(Zero, xii, bb3);
                        buf[4] = *(block*)&_mm_blendv_ps(Zero, xii, bb4);
                        buf[5] = *(block*)&_mm_blendv_ps(Zero, xii, bb5);
                        buf[6] = *(block*)&_mm_blendv_ps(Zero, xii, bb6);
                        buf[7] = *(block*)&_mm_blendv_ps(Zero, xii, bb7);
                    }
                    else
                    {
                        buf[0] = xx[i] *  (b0.get<i32>(0) < 0);
                        buf[1] = xx[i] *  (b1.get<i32>(0) < 0);
                        buf[2] = xx[i] *  (b2.get<i32>(0) < 0);
                        buf[3] = xx[i] *  (b3.get<i32>(0) < 0);
                        buf[4] = xx[i] *  (b4.get<i32>(0) < 0);
                        buf[5] = xx[i] *  (b5.get<i32>(0) < 0);
                        buf[6] = xx[i] *  (b6.get<i32>(0) < 0);
                        buf[7] = xx[i] *  (b7.get<i32>(0) < 0);

                    }
                    if (!rangeCheck || j + 0 < mCodeSize) xx[j + 0] = xx[j + 0] ^ buf[0];
                    if (!rangeCheck || j + 1 < mCodeSize) xx[j + 1] = xx[j + 1] ^ buf[1];
                    if (!rangeCheck || j + 2 < mCodeSize) xx[j + 2] = xx[j + 2] ^ buf[2];
                    if (!rangeCheck || j + 3 < mCodeSize) xx[j + 3] = xx[j + 3] ^ buf[3];
                    if (!rangeCheck || j + 4 < mCodeSize) xx[j + 4] = xx[j + 4] ^ buf[4];
                    if (!rangeCheck || j + 5 < mCodeSize) xx[j + 5] = xx[j + 5] ^ buf[5];
                    if (!rangeCheck || j + 6 < mCodeSize) xx[j + 6] = xx[j + 6] ^ buf[6];
                    if (!rangeCheck || j + 7 < mCodeSize) xx[j + 7] = xx[j + 7] ^ buf[7];
                }
            }

            if (!rangeCheck || j < mCodeSize)
            {
                auto xj = xx[j] ^ xx[i];
                xx[j] = xj;
            }
        }


        template<typename T>
        void accumulate(span<T> x)
        {
            PRNG prng(mSeed ^ OneBlock);


            u64 i = 0;
            auto main = (u64)std::max<i64>(0, mCodeSize - mWrapping - mAccumulatorSize);
            block rnd;
            u8* ptr = (u8*)prng.mBuffer.data();
            auto qe = prng.mBuffer.size() * 128 / 8;
            u64 q = 0;
            T* __restrict xx = x.data();


            if (mAccumulatorSize % 8)
                throw RTE_LOC;


            //block xi = xx[0];
//            if (mTrans)
//            {
//
//
//#define CASE(I) case I:\
//                for (; i < mAccumulatorSize; ++i)\
//                    accOneTrans<T, true, I>(xx, i, ptr, prng, q, qe);\
//                for (; i < mCodeSize; ++i)\
//                    accOneTrans<T, false, I>(xx, i, ptr, prng, q, qe);\
//                break
//
//                switch (mAccumulatorSize / 8)
//                {
//                    CASE(0);
//                    CASE(1);
//                    CASE(2);
//                    CASE(3);
//                    CASE(4);
//                default:
//                    throw RTE_LOC;
//                    break;
//                }
//#undef CASE
//            }
//            else
            {

#define CASE(I) case I:\
                for (; i < main; ++i)\
                    accOne<T, false, I>(xx, i, ptr, prng, q, qe);\
                for (; i < mCodeSize; ++i)\
                    accOne<T, true, I>(xx, i, ptr, prng, q, qe);\
                break

                switch (mAccumulatorSize / 8)
                {
                    CASE(0);
                    CASE(1);
                    CASE(2);
                    CASE(3);
                    CASE(4);
                default:
                    throw RTE_LOC;
                    break;
                }
#undef CASE
            }
        }

        template<typename T, u64 count>
        OC_FORCEINLINE typename std::enable_if<(count > 1), T>::type
            expandOne(const T* __restrict ee, detail::ExpanderModd& prng)const
        {
            if constexpr (count == 8)
            {
                u64 rr[8];
                rr[0] = prng.get();
                rr[1] = prng.get();
                rr[2] = prng.get();
                rr[3] = prng.get();
                rr[4] = prng.get();
                rr[5] = prng.get();
                rr[6] = prng.get();
                rr[7] = prng.get();

                T w[8];
                w[0] = ee[rr[0]];
                w[1] = ee[rr[1]];
                w[2] = ee[rr[2]];
                w[3] = ee[rr[3]];
                w[4] = ee[rr[4]];
                w[5] = ee[rr[5]];
                w[6] = ee[rr[6]];
                w[7] = ee[rr[7]];

                return
                    w[0] ^
                    w[1] ^
                    w[2] ^
                    w[3] ^
                    w[4] ^
                    w[5] ^
                    w[6] ^
                    w[7];
            }
            else if constexpr (count == 7)
            {
                u64 rr[8];
                rr[0] = prng.get();
                rr[1] = prng.get();
                rr[2] = prng.get();
                rr[3] = prng.get();
                rr[4] = prng.get();
                rr[5] = prng.get();
                rr[6] = prng.get();

                T w[8];
                w[0] = ee[rr[0]];
                w[1] = ee[rr[1]];
                w[2] = ee[rr[2]];
                w[3] = ee[rr[3]];
                w[4] = ee[rr[4]];
                w[5] = ee[rr[5]];
                w[6] = ee[rr[6]];

                return
                    w[0] ^
                    w[1] ^
                    w[2] ^
                    w[3] ^
                    w[4] ^
                    w[5] ^
                    w[6];
            }
            else if constexpr (count == 5)
            {
                u64 rr[8];
                rr[0] = prng.get();
                rr[1] = prng.get();
                rr[2] = prng.get();
                rr[3] = prng.get();
                rr[4] = prng.get();

                T w[8];
                w[0] = ee[rr[0]];
                w[1] = ee[rr[1]];
                w[2] = ee[rr[2]];
                w[3] = ee[rr[3]];
                w[4] = ee[rr[4]];

                return
                    w[0] ^
                    w[1] ^
                    w[2] ^
                    w[3] ^
                    w[4];
            }
            else
            {
                auto r = prng.get();
                //std::cout << r << " ";
                return expandOne<T, count - 1>(ee, prng) ^ ee[r];
            }
        }



        template<typename T, u64 count>
        OC_FORCEINLINE typename std::enable_if<count == 1, T>::type
            expandOne(const T* __restrict ee, detail::ExpanderModd& prng) const
        {
            auto r = prng.get();
            //std::cout << r << " ";
            return ee[r];
        }

        template<typename T>
        void expand(span<const T> e, span<T> w) const
        {
            assert(w.size() == mMessageSize);
            assert(e.size() == mCodeSize);
            detail::ExpanderModd prng(mSeed, mCodeSize);

            std::vector<u64> row(mExpanderWeight);
            u64* __restrict rr = row.data();
            std::vector<T> rowVal(mExpanderWeight);
            const T* __restrict  ee = e.data();
            T* __restrict  ww = w.data();

            auto main = mMessageSize / 8 * 8;
            u64 i = 0;

            for (; i < main; i += 8)
            {

                switch (mExpanderWeight)
                {
                case 5:
                    ww[i + 0] = expandOne<T, 5>(ee, prng);
                    ww[i + 1] = expandOne<T, 5>(ee, prng);
                    ww[i + 2] = expandOne<T, 5>(ee, prng);
                    ww[i + 3] = expandOne<T, 5>(ee, prng);
                    ww[i + 4] = expandOne<T, 5>(ee, prng);
                    ww[i + 5] = expandOne<T, 5>(ee, prng);
                    ww[i + 6] = expandOne<T, 5>(ee, prng);
                    ww[i + 7] = expandOne<T, 5>(ee, prng);
                    break;
                case 7:
                    ww[i + 0] = expandOne<T, 7>(ee, prng);
                    ww[i + 1] = expandOne<T, 7>(ee, prng);
                    ww[i + 2] = expandOne<T, 7>(ee, prng);
                    ww[i + 3] = expandOne<T, 7>(ee, prng);
                    ww[i + 4] = expandOne<T, 7>(ee, prng);
                    ww[i + 5] = expandOne<T, 7>(ee, prng);
                    ww[i + 6] = expandOne<T, 7>(ee, prng);
                    ww[i + 7] = expandOne<T, 7>(ee, prng);
                    break;
                case 40:
                {
                    for (u64 j = 0; j < 8; ++j)
                    {
                        auto w = expandOne<T, 8>(ee, prng);
                        w = w ^ expandOne<T, 8>(ee, prng);
                        w = w ^ expandOne<T, 8>(ee, prng);
                        w = w ^ expandOne<T, 8>(ee, prng);
                        w = w ^ expandOne<T, 8>(ee, prng);
                        ww[i + j] = w;
                    }
                    break;
                }
                default:
                {

                    for (u64 jj = 0; jj < 8; ++jj)
                    {
                        rr[0] = prng.get();
                        auto wv = ee[rr[0]];

                        for (auto j = 1ull; j < mExpanderWeight; ++j)
                        {
                            do {
                                rr[j] = prng.get();
                            } while (0);

                            wv = wv ^ ee[rr[j]];
                        }
                        ww[i + jj] = wv;
                    }
                }
                }
            }

            for (; i < mMessageSize; ++i)
            {

                switch (mExpanderWeight)
                {
                case 5:
                    ww[i] = expandOne<T, 5>(ee, prng);
                    break;
                case 7:
                    ww[i] = expandOne<T, 7>(ee, prng);

                    break;
                case 40:
                {

                    auto w = expandOne<T, 8>(ee, prng);
                    w = w ^ expandOne<T, 8>(ee, prng);
                    w = w ^ expandOne<T, 8>(ee, prng);
                    w = w ^ expandOne<T, 8>(ee, prng);
                    w = w ^ expandOne<T, 8>(ee, prng);
                    ww[i] = w;
                    break;
                }
                default:
                {

                    rr[0] = prng.get();
                    auto wv = ee[rr[0]];

                    for (auto j = 1ull; j < mExpanderWeight; ++j)
                    {
                        do {
                            rr[j] = prng.get();
                        } while (0);

                        wv = wv ^ ee[rr[j]];
                    }
                    ww[i] = wv;
                }
                }
            }
        }


        SparseMtx getB() const
        {
            //PRNG prng(mSeed);
            detail::ExpanderModd prng(mSeed, mCodeSize);
            PointList points(mMessageSize, mCodeSize);

            std::vector<u64> row(mExpanderWeight);

            {

                for (auto i : rng(mMessageSize))
                {
                    row[0] = prng.get();
                    //points.push_back(i, row[0]);
                    for (auto j : rng(1, mExpanderWeight))
                    {
                        //do {
                        row[j] = prng.get();
                        //} while
                        auto iter = std::find(row.data(), row.data() + j, row[j]);
                        if (iter != row.data() + j)
                        {
                            row[j] = -1;
                            *iter = -1;
                        }
                        //throw RTE_LOC;

                    }
                    for (auto j : rng(mExpanderWeight))
                    {

                        if (row[j] != -1)
                        {
                            //std::cout << row[j] << " ";
                            points.push_back(i, row[j]);
                        }
                        else
                        {
                            //std::cout << "* ";
                        }
                    }
                    //std::cout << std::endl;
                }
            }

            return points;
        }

        // Get the parity check version of the accumulator
        SparseMtx getAPar() const
        {
            PRNG prng(mSeed ^ OneBlock);

            PointList AP(mCodeSize, mCodeSize);;
            DenseMtx A = DenseMtx::Identity(mCodeSize);

            block rnd;
            u8* __restrict ptr = (u8*)prng.mBuffer.data();
            auto qe = prng.mBuffer.size() * 128;
            u64 q = 0;

            for (i64 i = 0; i < mCodeSize; ++i)
            {
                accOne(AP, i, ptr, prng, rnd, q, qe);
            }
            return AP;
        }

        SparseMtx getA() const
        {
            auto APar = getAPar();

            auto A = DenseMtx::Identity(mCodeSize);

            for (u64 i = 0; i < mCodeSize; ++i)
            {
                for (auto y : APar.col(i))
                {
                    //std::cout << y << " ";
                    if (y != i)
                    {
                        auto ay = A.row(y);
                        auto ai = A.row(i);
                        ay ^= ai;

                    }
                }

                //std::cout << "\n" << A << std::endl;
            }

            return A.sparse();
        }
    };
}

#include "ExConvCodeOld.h"

#ifdef LIBOTE_ENABLE_OLD_EXCONV

namespace osuCrypto
{
#ifdef ENABLE_SSE

    using My__m128 = __m128;

#else
    using My__m128 = block;

    inline My__m128 _mm_load_ps(float* b) { return *(block*)b; }

    // https://www.intel.com/content/www/us/en/docs/intrinsics-guide/index.html#text=_mm_blendv_ps&ig_expand=557
    inline My__m128 _mm_blendv_ps(My__m128 a, My__m128 b, My__m128 mask)
    {
        My__m128 dst;
        for (u64 j = 0; j < 4; ++j)
        {
            if (mask.get<i32>(j) < 0)
                dst.set<u32>(j, b.get<u32>(j));
            else
                dst.set<u32>(j, a.get<u32>(j));
        }
        return dst;
    }


    inline My__m128 _mm_setzero_ps() { return ZeroBlock; }
#endif

    // Compute e = G * e.
    template<typename T>
    void ExConvCodeOld::dualEncode(span<T> e)
    {
        if (e.size() != mCodeSize)
            throw RTE_LOC;

        if (mSystematic)
        {
            auto d = e.subspan(mMessageSize);
            setTimePoint("ExConv.encode.begin");
            accumulate<T>(d);
            setTimePoint("ExConv.encode.accumulate");
            mExpander.expand<T, true>(d, e.subspan(0, mMessageSize));
            setTimePoint("ExConv.encode.expand");
        }
        else
        {
            oc::AlignedUnVector<T> w(mMessageSize);
            dualEncode<T>(e, w);
            memcpy(e.data(), w.data(), w.size() * sizeof(T));
            setTimePoint("ExConv.encode.memcpy");

        }
    }


    // Compute e = G * e.
    template<typename T0, typename T1>
    void ExConvCodeOld::dualEncode2(span<T0> e0, span<T1> e1)
    {
        if (e0.size() != mCodeSize)
            throw RTE_LOC;
        if (e1.size() != mCodeSize)
            throw RTE_LOC;

        if (mSystematic)
        {
            auto d0 = e0.subspan(mMessageSize);
            auto d1 = e1.subspan(mMessageSize);
            setTimePoint("ExConv.encode.begin");
            accumulate<T0, T1>(d0, d1);
            setTimePoint("ExConv.encode.accumulate");
            mExpander.expand<T0, T1, true>(
                d0, d1,
                e0.subspan(0, mMessageSize),
                e1.subspan(0, mMessageSize));
            setTimePoint("ExConv.encode.expand");
        }
        else
        {
            //oc::AlignedUnVector<T0> w0(mMessageSize);
            //dualEncode<T0, T1>(e, w);
            //memcpy(e.data(), w.data(), w.size() * sizeof(T));
            //setTimePoint("ExConv.encode.memcpy");

            // not impl.
            throw RTE_LOC;

        }
    }

    // Compute w = G * e.
    template<typename T>
    void ExConvCodeOld::dualEncode(span<T> e, span<T> w)
    {
        if (e.size() != mCodeSize)
            throw RTE_LOC;

        if (w.size() != mMessageSize)
            throw RTE_LOC;

        if (mSystematic)
        {
            dualEncode<T>(e);
            memcpy(w.data(), e.data(), w.size() * sizeof(T));
            setTimePoint("ExConv.encode.memcpy");
        }
        else
        {

            setTimePoint("ExConv.encode.begin");

            accumulate<T>(e);

            setTimePoint("ExConv.encode.accumulate");

            mExpander.expand<T, false>(e, w);
            setTimePoint("ExConv.encode.expand");
        }
    }

    inline void refill(PRNG& prng)
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
    }

#ifndef EXCONVCODE_INSTANTIATIONS

    void ExConvCodeOld::accOne(
        PointList& pl,
        u64 i,
        u8* __restrict& ptr,
        PRNG& prng,
        block& rnd,
        u64& q,
        u64 qe,
        u64 size) const
    {
        u64 j = i + 1;
        pl.push_back(i, i);


        if (q + mAccumulatorSize > qe)
        {
            refill(prng);
            ptr = (u8*)prng.mBuffer.data();
            q = 0;
        }


        for (u64 k = 0; k < mAccumulatorSize; k += 8, q += 8, j += 8)
        {
            assert(ptr < (u8*)(prng.mBuffer.data() + prng.mBuffer.size()));
            rnd = block::allSame<u8>(*ptr);
            ++ptr;

            //std::cout << "r " << rnd << std::endl;
            auto b0 = rnd;
            auto b1 = rnd.slli_epi32<1>();
            auto b2 = rnd.slli_epi32<2>();
            auto b3 = rnd.slli_epi32<3>();
            auto b4 = rnd.slli_epi32<4>();
            auto b5 = rnd.slli_epi32<5>();
            auto b6 = rnd.slli_epi32<6>();
            auto b7 = rnd.slli_epi32<7>();
            //rnd = rnd.mm_slli_epi32<8>();

            if (j + 0 < size && b0.get<i32>(0) < 0) pl.push_back(j + 0, i);
            if (j + 1 < size && b1.get<i32>(0) < 0) pl.push_back(j + 1, i);
            if (j + 2 < size && b2.get<i32>(0) < 0) pl.push_back(j + 2, i);
            if (j + 3 < size && b3.get<i32>(0) < 0) pl.push_back(j + 3, i);
            if (j + 4 < size && b4.get<i32>(0) < 0) pl.push_back(j + 4, i);
            if (j + 5 < size && b5.get<i32>(0) < 0) pl.push_back(j + 5, i);
            if (j + 6 < size && b6.get<i32>(0) < 0) pl.push_back(j + 6, i);
            if (j + 7 < size && b7.get<i32>(0) < 0) pl.push_back(j + 7, i);
        }

        //if (mWrapping)
        {
            if (j < size)
                pl.push_back(j, i);
            ++j;
        }

    }
#endif


    template<typename T, bool rangeCheck>
    OC_FORCEINLINE void accOneHelper(
        T* __restrict xx,
        My__m128 xii,
        u64 j, u64 i, u64 size,
        block* b
    )
    {
        My__m128 Zero = _mm_setzero_ps();

        if constexpr (std::is_same<block, T>::value)
        {
            My__m128 bb[8];
            bb[0] = _mm_load_ps((float*)&b[0]);
            bb[1] = _mm_load_ps((float*)&b[1]);
            bb[2] = _mm_load_ps((float*)&b[2]);
            bb[3] = _mm_load_ps((float*)&b[3]);
            bb[4] = _mm_load_ps((float*)&b[4]);
            bb[5] = _mm_load_ps((float*)&b[5]);
            bb[6] = _mm_load_ps((float*)&b[6]);
            bb[7] = _mm_load_ps((float*)&b[7]);


            bb[0] = _mm_blendv_ps(Zero, xii, bb[0]);
            bb[1] = _mm_blendv_ps(Zero, xii, bb[1]);
            bb[2] = _mm_blendv_ps(Zero, xii, bb[2]);
            bb[3] = _mm_blendv_ps(Zero, xii, bb[3]);
            bb[4] = _mm_blendv_ps(Zero, xii, bb[4]);
            bb[5] = _mm_blendv_ps(Zero, xii, bb[5]);
            bb[6] = _mm_blendv_ps(Zero, xii, bb[6]);
            bb[7] = _mm_blendv_ps(Zero, xii, bb[7]);

            block tt[8];
            memcpy(tt, bb, 8 * 16);

            if (!rangeCheck || j + 0 < size) xx[j + 0] = xx[j + 0] ^ tt[0];
            if (!rangeCheck || j + 1 < size) xx[j + 1] = xx[j + 1] ^ tt[1];
            if (!rangeCheck || j + 2 < size) xx[j + 2] = xx[j + 2] ^ tt[2];
            if (!rangeCheck || j + 3 < size) xx[j + 3] = xx[j + 3] ^ tt[3];
            if (!rangeCheck || j + 4 < size) xx[j + 4] = xx[j + 4] ^ tt[4];
            if (!rangeCheck || j + 5 < size) xx[j + 5] = xx[j + 5] ^ tt[5];
            if (!rangeCheck || j + 6 < size) xx[j + 6] = xx[j + 6] ^ tt[6];
            if (!rangeCheck || j + 7 < size) xx[j + 7] = xx[j + 7] ^ tt[7];
        }
        else
        {
            auto bb0 = xx[i] * (b[0].get<i32>(0) < 0);
            auto bb1 = xx[i] * (b[1].get<i32>(0) < 0);
            auto bb2 = xx[i] * (b[2].get<i32>(0) < 0);
            auto bb3 = xx[i] * (b[3].get<i32>(0) < 0);
            auto bb4 = xx[i] * (b[4].get<i32>(0) < 0);
            auto bb5 = xx[i] * (b[5].get<i32>(0) < 0);
            auto bb6 = xx[i] * (b[6].get<i32>(0) < 0);
            auto bb7 = xx[i] * (b[7].get<i32>(0) < 0);

            if (!rangeCheck || j + 0 < size) xx[j + 0] = xx[j + 0] ^ bb0;
            if (!rangeCheck || j + 1 < size) xx[j + 1] = xx[j + 1] ^ bb1;
            if (!rangeCheck || j + 2 < size) xx[j + 2] = xx[j + 2] ^ bb2;
            if (!rangeCheck || j + 3 < size) xx[j + 3] = xx[j + 3] ^ bb3;
            if (!rangeCheck || j + 4 < size) xx[j + 4] = xx[j + 4] ^ bb4;
            if (!rangeCheck || j + 5 < size) xx[j + 5] = xx[j + 5] ^ bb5;
            if (!rangeCheck || j + 6 < size) xx[j + 6] = xx[j + 6] ^ bb6;
            if (!rangeCheck || j + 7 < size) xx[j + 7] = xx[j + 7] ^ bb7;
        }
    }


    template<typename T, bool rangeCheck, int width>
    OC_FORCEINLINE void ExConvCodeOld::accOne(
        T* __restrict xx,
        u64 i,
        u8*& ptr,
        PRNG& prng,
        u64& q,
        u64 qe,
        u64 size)
    {
        u64 j = i + 1;
        if (width)
        {
            auto xii = _mm_load_ps((float*)(xx + i));



            if (q + width > qe)
            {
                refill(prng);
                ptr = (u8*)prng.mBuffer.data();
                q = 0;

            }
            q += width;

            for (u64 k = 0; k < width; ++k, j += 8)
            {
                assert(ptr < (u8*)(prng.mBuffer.data() + prng.mBuffer.size()));
                block rnd = block::allSame<u8>(*(u8*)ptr++);


                block b[8];
                b[0] = rnd;
                b[1] = rnd.slli_epi32<1>();
                b[2] = rnd.slli_epi32<2>();
                b[3] = rnd.slli_epi32<3>();
                b[4] = rnd.slli_epi32<4>();
                b[5] = rnd.slli_epi32<5>();
                b[6] = rnd.slli_epi32<6>();
                b[7] = rnd.slli_epi32<7>();

                accOneHelper<T, rangeCheck>(xx, xii, j, i, size, b);
            }

            if (!rangeCheck || j < size)
            {
                auto xj = xx[j] ^ xx[i];
                xx[j] = xj;
                ++j;
            }

        }

    }

    template<typename T0, typename T1, bool rangeCheck, int width>
    OC_FORCEINLINE void ExConvCodeOld::accOne(
        T0* __restrict xx0,
        T1* __restrict xx1,
        u64 i,
        u8*& ptr,
        PRNG& prng,
        u64& q,
        u64 qe,
        u64 size)
    {
        u64 j = i + 1;
        if (width)
        {
            auto xii0 = _mm_load_ps((float*)(xx0 + i));
            auto xii1 = _mm_load_ps((float*)(xx1 + i));

            if (q + width > qe)
            {
                refill(prng);
                ptr = (u8*)prng.mBuffer.data();
                q = 0;

            }
            q += width;

            for (u64 k = 0; k < width; ++k, j += 8)
            {
                assert(ptr < (u8*)(prng.mBuffer.data() + prng.mBuffer.size()));
                block rnd = block::allSame<u8>(*(u8*)ptr++);

                block b[8];
                b[0] = rnd;
                b[1] = rnd.slli_epi32<1>();
                b[2] = rnd.slli_epi32<2>();
                b[3] = rnd.slli_epi32<3>();
                b[4] = rnd.slli_epi32<4>();
                b[5] = rnd.slli_epi32<5>();
                b[6] = rnd.slli_epi32<6>();
                b[7] = rnd.slli_epi32<7>();

                accOneHelper<T0, rangeCheck>(xx0, xii0, j, i, size, b);
                accOneHelper<T1, rangeCheck>(xx1, xii1, j, i, size, b);
            }

            if (!rangeCheck || j < size)
            {
                auto xj0 = xx0[j] ^ xx0[i];
                auto xj1 = xx1[j] ^ xx1[i];
                xx0[j] = xj0;
                xx1[j] = xj1;
                ++j;
            }

        }


    }



    template<typename T>
    void ExConvCodeOld::accumulate(span<T> x)
    {
        PRNG prng(mSeed ^ OneBlock);

        u64 i = 0;
        auto size = x.size();
        auto main = (u64)std::max<i64>(0, size - 1 - mAccumulatorSize);
        u8* ptr = (u8*)prng.mBuffer.data();
        auto qe = prng.mBuffer.size() * 128 / 8;
        u64 q = 0;
        T* __restrict xx = x.data();

        {

#define CASE(I) case I:\
                for (; i < main; ++i)\
                    accOne<T, false, I>(xx, i, ptr, prng, q, qe, size);\
                for (; i < size; ++i)\
                    accOne<T, true, I>(xx, i, ptr, prng, q, qe, size);\
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


    template<typename T0, typename T1>
    void ExConvCodeOld::accumulate(span<T0> x0, span<T1> x1)
    {
        PRNG prng(mSeed ^ OneBlock);

        u64 i = 0;
        auto size = x0.size();
        auto main = (u64)std::max<i64>(0, size - 1 - mAccumulatorSize);
        u8* ptr = (u8*)prng.mBuffer.data();
        auto qe = prng.mBuffer.size() * 128 / 8;
        u64 q = 0;
        T0* __restrict xx0 = x0.data();
        T1* __restrict xx1 = x1.data();

        {

#define CASE(I) case I:\
                for (; i < main; ++i)\
                    accOne<T0, T1, false, I>(xx0,xx1, i, ptr, prng, q, qe, size);\
                for (; i < size; ++i)\
                    accOne<T0, T1, true, I>(xx0, xx1, i, ptr, prng, q, qe, size);\
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


#ifndef EXCONVCODE_INSTANTIATIONS

    SparseMtx ExConvCodeOld::getB() const
    {
        if (mSystematic)
        {
            PointList R(mMessageSize, mCodeSize);
            auto B = mExpander.getB().points();

            for (auto p : B)
            {
                R.push_back(p.mRow, mMessageSize + p.mCol);
            }
            for (u64 i = 0; i < mMessageSize; ++i)
                R.push_back(i, i);

            return R;
        }
        else
        {
            return mExpander.getB();
        }

    }

    // Get the parity check version of the accumulator
    SparseMtx ExConvCodeOld::getAPar() const
    {
        PRNG prng(mSeed ^ OneBlock);

        auto n = mCodeSize - mSystematic * mMessageSize;

        PointList AP(n, n);;
        DenseMtx A = DenseMtx::Identity(n);

        block rnd;
        u8* __restrict ptr = (u8*)prng.mBuffer.data();
        auto qe = prng.mBuffer.size() * 128;
        u64 q = 0;

        for (u64 i = 0; i < n; ++i)
        {
            accOne(AP, i, ptr, prng, rnd, q, qe, n);
        }
        return AP;
    }

    SparseMtx ExConvCodeOld::getA() const
    {
        auto APar = getAPar();

        auto A = DenseMtx::Identity(mCodeSize);

        u64 offset = mSystematic ? mMessageSize : 0ull;

        for (u64 i = 0; i < APar.rows(); ++i)
        {
            for (auto y : APar.col(i))
            {
                //std::cout << y << " ";
                if (y != i)
                {
                    auto ay = A.row(y + offset);
                    auto ai = A.row(i + offset);
                    ay ^= ai;
                }
            }

            //std::cout << "\n" << A << std::endl;
        }

        return A.sparse();
    }
#endif
}

#endif
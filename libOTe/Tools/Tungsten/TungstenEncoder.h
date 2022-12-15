#include "cryptoTools/Common/Defines.h"
#include "libOTe/Tools/LDPC/Mtx.h"
#include "cryptoTools/Common/Range.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "libOTe/Tools/LDPC/LdpcEncoder.h"
#include "Xoshiro256Plus.h"
#ifdef ENABLE_AVX
#define LIBDIVIDE_AVX2
#elif ENABLE_SSE
#define LIBDIVIDE_SSE2
#endif
#include "SqrtPerm.h"
#include "libdivide.h"
#include "TungstenData.h"

namespace osuCrypto
{

    SparseMtx getLinearSums(u64 n, u64 weight)
    {

        auto mCodeSize = n;
        auto mMessageSize = n / 2;

        PointList ret(mMessageSize, mCodeSize);

        details::SilverLeftEncoder L;

        if (weight == 5)
            L.init(mCodeSize, SilverCode::code::Weight5);
        else if (weight == 11)
        {
            L.init(mCodeSize, SilverCode::code::Weight11);
        }
        else
        {
            std::vector<double> s; s.push_back(0);
            while (s.size() != weight)
            {
                s.push_back((rand() % mCodeSize) / double(mCodeSize));
            }
            L.init(mCodeSize, s);
        }
        auto mWeight = L.mWeight;
        auto mYs = L.mYs;

        auto v = mYs;

        for (u64 i = 0; i < mMessageSize; )
        {
            auto end = mMessageSize;
            for (u64 j = 0; j < mWeight; ++j)
            {
                if (v[j] == mCodeSize)
                    v[j] = 0;

                auto jEnd = mCodeSize - v[j] + i;
                end = std::min<u64>(end, jEnd);
            }

            while (i != end)
            {
                for (u64 j = 0; j < mWeight; ++j)
                {
                    ret.push_back({ i, v[j]++ });
                }
                ++i;
            }

        }
        return ret;
    }

    template<typename T>
    void linearSums(span<T> e, span<T> w, u64 mExpanderWeight)
    {
        auto mCodeSize = e.size();
        auto mMessageSize = w.size();

        details::SilverLeftEncoder L;

        if (mExpanderWeight == 5)
            L.init(mCodeSize, SilverCode::code::Weight5);
        else if (mExpanderWeight == 11)
        {
            L.init(mCodeSize, SilverCode::code::Weight11);
        }
        else
        {
            std::vector<double> s; s.push_back(0);
            while (s.size() != mExpanderWeight)
            {
                s.push_back((rand() % mCodeSize) / double(mCodeSize));
            }
            L.init(mCodeSize, s);
        }
        auto mWeight = L.mWeight;
        auto mYs = L.mYs;

        auto v = mYs;
        T* __restrict pp = w.data();
        const T* __restrict m = e.data();

        for (u64 i = 0; i < mMessageSize; )
        {
            auto end = mMessageSize;
            for (u64 j = 0; j < mWeight; ++j)
            {
                if (v[j] == mCodeSize)
                    v[j] = 0;

                auto jEnd = mCodeSize - v[j] + i;
                end = std::min<u64>(end, jEnd);
            }
            T* __restrict P = &pp[i];
            T* __restrict PE = &pp[end];
            T* __restrict PE8 = &pp[(end - i) / 8 * 8 + i];

            switch (mWeight)
            {
            case 5:
            {
                const T* __restrict M0 = &m[v[0]];
                const T* __restrict M1 = &m[v[1]];
                const T* __restrict M2 = &m[v[2]];
                const T* __restrict M3 = &m[v[3]];
                const T* __restrict M4 = &m[v[4]];

                v[0] += end - i;
                v[1] += end - i;
                v[2] += end - i;
                v[3] += end - i;
                v[4] += end - i;
                i = end;

                while (P != PE)
                {
                    T t = *M0
                        ^ *M1
                        ^ *M2
                        ^ *M3
                        ^ *M4
                        ;

                    if constexpr (std::is_same<block, T>::value)
                        _mm_stream_si128((__m128i*)P, (__m128i)t);
                    else
                        *P = t;

                    ++M0;
                    ++M1;
                    ++M2;
                    ++M3;
                    ++M4;
                    ++P;
                }


                break;
            }
            case 11:
            {

                const T* __restrict M0 = &m[v[0]];
                const T* __restrict M1 = &m[v[1]];
                const T* __restrict M2 = &m[v[2]];
                const T* __restrict M3 = &m[v[3]];
                const T* __restrict M4 = &m[v[4]];
                const T* __restrict M5 = &m[v[5]];
                const T* __restrict M6 = &m[v[6]];
                const T* __restrict M7 = &m[v[7]];
                const T* __restrict M8 = &m[v[8]];
                const T* __restrict M9 = &m[v[9]];
                const T* __restrict M10 = &m[v[10]];

                v[0] += end - i;
                v[1] += end - i;
                v[2] += end - i;
                v[3] += end - i;
                v[4] += end - i;
                v[5] += end - i;
                v[6] += end - i;
                v[7] += end - i;
                v[8] += end - i;
                v[9] += end - i;
                v[10] += end - i;
                i = end;

                while (P != PE)
                {
                    *P = *M0
                        ^ *M1
                        ^ *M2
                        ^ *M3
                        ^ *M4
                        ^ *M5
                        ^ *M6
                        ^ *M7
                        ^ *M8
                        ^ *M9
                        ^ *M10
                        ;

                    ++M0;
                    ++M1;
                    ++M2;
                    ++M3;
                    ++M4;
                    ++M5;
                    ++M6;
                    ++M7;
                    ++M8;
                    ++M9;
                    ++M10;
                    ++P;
                }

                break;
            }
            default:
                while (i != end)
                {
                    {
                        auto row = v[0];
                        pp[i] = m[row];
                        ++v[0];
                    }

                    for (u64 j = 1; j < mWeight; ++j)
                    {
                        auto row = v[j];
                        pp[i] = pp[i] ^ m[row];
                        ++v[j];
                    }
                    ++i;
                }
                break;
            }

        }
    }

    // THe encoder for the generator matrix G = B * A.
    // B is the expander while A is the accumulator.
    // 
    // B has mMessageSize rows and mCodeSize columns. It is sampled uniformly
    // with fixed row weight mExpanderWeight.
    //
    // A is a lower triangular n by n matrix with ones on the diagonal. The
    // mAccumulatorSize diagonals left of the main diagonal are uniformly random.
    // If mStickyAccumulator, then the first diagonal left of the main is always ones.
    class Tungsten : public TimerAdapter
    {
    public:

        enum class RNG
        {
            prng = 0,
            gf128mul = 1,
            xoshiro256Plus = 2,
            aeslite = 3
        };



        void config(
            u64 messageSize,
            u64 codeSize,
            u64 expanderWeight,
            u64 accumulatorSize,
            //u64 accumulatorWeight,
            RNG reuse,
            u64 permute,
            u64 stickyAccumulator,
            block seed = block(0, 0))
        {
            mMessageSize = messageSize;
            mCodeSize = codeSize;
            mExpanderWeight = expanderWeight;
            mAccumulatorSize = accumulatorSize;
            mAccumulatorWeight = 0;// accumulatorWeight;
            mStickyAccumulator = stickyAccumulator;
            mReuse = reuse;
            mPermute = permute;
            assert(mStickyAccumulator <= mAccumulatorSize);
            mSeed = seed;

            if (permute)
            {
                PRNG prng(seed ^ block(34231, 123412));
                mSqrtPerm.init(mCodeSize, 1ull << permute, prng);
                mPerm.init(mCodeSize, prng);
            }
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

        u64 mAccumulatorWeight = 0;

        u64 mStickyAccumulator = 1;

        RNG mReuse = RNG::prng;

        u64 mPermute = 0;

        Perm mPerm;
        SqrtPerm mSqrtPerm;

        u64 mExtraDiag = 0;
        //std::vector<u64> mPerm;

        u64 parityRows() const { return mCodeSize - mMessageSize; }
        u64 parityCols() const { return mCodeSize; }

        u64 generatorRows() const { return mMessageSize; }
        u64 generatorCols() const { return mCodeSize; }

        // Compute w = G * e.
        template<typename T>
        void cirTransEncode(span<T> e, span<T> w)
        {
            assert(e.size() == mCodeSize);
            assert(w.size() == mMessageSize);

            setTimePoint("tungsten.encode.begin");
            if (mAccumulatorWeight)
                fixedAccumulate<T>(e);
            else
                uniformAccumulate<T>(e);

            setTimePoint("tungsten.encode.accumulate");

            if (mPermute)
                permExpand<T>(e, w);
            else
                expand<T>(e, w);
            setTimePoint("tungsten.encode.expand");
        }

        template<typename T>
        void xorAdd(span<T> x, span<T> y)const
        {
            for (u64 i = 0; i < x.size(); ++i)
                x[i] = x[i] ^ y[i];
        }


        struct BitStream
        {
            PRNG mPrng;
            details::Xoshiro256Plus mXoshiro256Plus;
            AlignedUnVector<block> mBuff;
            u64 mIdx, mEnd, mSize;
            RNG mReuse;

            BitStream(block seed, u64 size, RNG reuse)
                : mPrng(seed)
                , mXoshiro256Plus(seed)
                , mSize(size)
                , mReuse(reuse)
            {
                mBuff.resize(mPrng.mBuffer.size() * 8);
                mEnd = (mBuff.size() * sizeof(block) / size) * mSize;
                if (!mEnd)
                    throw RTE_LOC;

                refill();
            }

            void refill()
            {
                mIdx = 0;

                if (mReuse == RNG::gf128mul)
                {
                    for (auto& v : mPrng.mBuffer)
                        v = v.gf128Mul(v);
                }
                else if (mReuse == RNG::prng)
                {
                    mPrng.getBufferSpan(-1);
                }
                else if (mReuse == RNG::aeslite)
                {
                    assert(mPrng.mBuffer.size() == 256);
                    for (u64 i = 0; i < 256; ++i)
                    {
                        //auto idx = mPrng.mBuffer[i].get<u8>();
                        block b = mPrng.mBuffer[i];
                        block k = mPrng.mBuffer[(u8)(i - 1)];
                        //for (u64 j = 0; j < 8; ++j)
                        //{
                        //    b = b ^ mPrng.mBuffer.data()[idx[j]];
                        //}
                        mPrng.mBuffer[i] = AES::roundEnc(b, k) ^ k;
                    }
                }
                else
                {
                    span<u64> vals((u64*)mPrng.mBuffer.data(), mPrng.mBuffer.size() * 2);
                    for (u64 i = 0; i < vals.size(); ++i)
                        vals[i] = mXoshiro256Plus.next();
                }


                block mask = block(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1);

                // now expand each of these bits into its own byte. This is done with the
                // right shift instruction _mm_srai_epi16. and then we mask to get only
                // the bottom bit. Doing the 8 times gets us each bit in its own byte.
                for (u64 i = 0; i < mPrng.mBuffer.size(); ++i)
                {
                    assert(i * 8 + 7 < mBuff.size());
                    mBuff[i * 8 + 0] = mPrng.mBuffer[i].srai_epi16(0);
                    mBuff[i * 8 + 1] = mPrng.mBuffer[i].srai_epi16(1);
                    mBuff[i * 8 + 2] = mPrng.mBuffer[i].srai_epi16(2);
                    mBuff[i * 8 + 3] = mPrng.mBuffer[i].srai_epi16(3);
                    mBuff[i * 8 + 4] = mPrng.mBuffer[i].srai_epi16(4);
                    mBuff[i * 8 + 5] = mPrng.mBuffer[i].srai_epi16(5);
                    mBuff[i * 8 + 6] = mPrng.mBuffer[i].srai_epi16(6);
                    mBuff[i * 8 + 7] = mPrng.mBuffer[i].srai_epi16(7);
                    mBuff[i * 8 + 0] = mBuff[i * 8 + 0] & mask;
                    mBuff[i * 8 + 1] = mBuff[i * 8 + 1] & mask;
                    mBuff[i * 8 + 2] = mBuff[i * 8 + 2] & mask;
                    mBuff[i * 8 + 3] = mBuff[i * 8 + 3] & mask;
                    mBuff[i * 8 + 4] = mBuff[i * 8 + 4] & mask;
                    mBuff[i * 8 + 5] = mBuff[i * 8 + 5] & mask;
                    mBuff[i * 8 + 6] = mBuff[i * 8 + 6] & mask;
                    mBuff[i * 8 + 7] = mBuff[i * 8 + 7] & mask;
                }
            }

            u8* get()
            {
                if (mIdx == mEnd)
                    refill();
                auto i = mIdx;
                mIdx += mSize;

                return (u8*)mBuff.data() + i;
            }

        };

        template<typename T, u64 rows, u64 weight>
        void fixedAccumulate(
            u64 main,
            span<T> x,
            const std::array<std::array<u8, weight>, rows>& TABLE)
        {
            auto xx = x.data();
            for (u64 i = main, j = 0; i < x.size(); ++i, ++j)
            {

                T* __restrict xi = xx + i;

                if (i + 1 < x.size())
                    xi[1] = xi[1] ^ xi[0];

                for (u64 k = 0; k < TABLE[0].size(); ++k)
                {
                    if (i + TABLE[j][k] < x.size())
                    {
                        T* __restrict xk = xi + TABLE[j][k];
                        *xk = *xi ^ *xk;
                    }
                }
            }
        }

        template<typename T>
        void fixedAccumulate(span<T> x)
        {

            //#define TABLE tunsten_diagMtx_128x4
            auto xx = x.data();

            if (mAccumulatorWeight == 4)
            {
#define TABLE TableTungsten128x4::data
                auto main = x.size() / TABLE.size();
                main = main ? (main - 1) * TABLE.size() : 0;

                for (u64 i = 0; i < main; )
                {
                    for (u64 j = 0; j < TABLE.size(); ++j, ++i)
                    {
                        _mm_prefetch((char*)(xx + i + 2 * TABLE.size()), _MM_HINT_T0);
                        T* __restrict xi = xx + i;
                        T* __restrict xs = xi + 1;
                        T* __restrict x0 = xi + TABLE[j][0];
                        T* __restrict x1 = xi + TABLE[j][1];
                        T* __restrict x2 = xi + TABLE[j][2];
                        T* __restrict x3 = xi + TABLE[j][3];


                        *xs = *xs ^ *xi;
                        *x0 = *x0 ^ *xi;
                        *x1 = *x1 ^ *xi;
                        *x2 = *x2 ^ *xi;
                        *x3 = *x3 ^ *xi;
                    }
                }

                fixedAccumulate(main, x, TABLE);
            }
#undef TABLE
            else if (mAccumulatorWeight == 10)
            {
#define TABLE tunsten_diagMtx_128x10
                auto main = x.size() / TABLE.size();
                main = main ? (main - 1) * TABLE.size() : 0;

                for (u64 i = 0; i < main; )
                {

                    for (u64 j = 0; j < TABLE.size(); ++j, ++i)
                    {
                        _mm_prefetch((char*)(xx + i + 2 * TABLE.size()), _MM_HINT_T0);
                        T* __restrict xi = xx + i;
                        T* __restrict xs = xi + 1;
                        T* __restrict x0 = xi + TABLE[j][0];
                        T* __restrict x1 = xi + TABLE[j][1];
                        T* __restrict x2 = xi + TABLE[j][2];
                        T* __restrict x3 = xi + TABLE[j][3];
                        T* __restrict x4 = xi + TABLE[j][4];
                        T* __restrict x5 = xi + TABLE[j][5];
                        T* __restrict x6 = xi + TABLE[j][6];
                        T* __restrict x7 = xi + TABLE[j][7];
                        T* __restrict x8 = xi + TABLE[j][8];
                        T* __restrict x9 = xi + TABLE[j][9];


                        *xs = *xs ^ *xi;
                        *x0 = *x0 ^ *xi;
                        *x1 = *x1 ^ *xi;
                        *x2 = *x2 ^ *xi;
                        *x3 = *x3 ^ *xi;
                        *x4 = *x4 ^ *xi;
                        *x5 = *x5 ^ *xi;
                        *x6 = *x6 ^ *xi;
                        *x7 = *x7 ^ *xi;
                        *x8 = *x8 ^ *xi;
                        *x9 = *x9 ^ *xi;

                    }
                }

                fixedAccumulate(main, x, TABLE);
            }
            else
            {
                throw RTE_LOC;
            }
#undef TABLE
        }


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

            if (mStickyAccumulator)
            {
                if (j < mCodeSize)
                    pl.push_back(j, i);
                ++j;
            }

            {
                if (q + mAccumulatorSize > qe)
                {
                    //assert(ptr == (u8*)(prng.mBuffer.data() + prng.mBuffer.size()));

                    assert(prng.mBuffer.size() == 256);
                    for (u64 i = 0; i < 256; ++i)
                    {
                        block b = prng.mBuffer.data()[i];
                        block k = prng.mBuffer.data()[(u8)(i - 1)];
                        prng.mBuffer[i] = AES::roundEnc(b, k) ^ k;
                    }

                    ptr = (u8*)prng.mBuffer.data();
                    q = 0;
                }

                assert(ptr < (u8*)(prng.mBuffer.data() + prng.mBuffer.size()));
            }

            for (u64 k = 0; k < mAccumulatorSize; k += 8, q += 8, j += 8)
            {
                //if (q % 32 == 0)
                //{
                //    if (q == qe)
                //    {
                //        assert(ptr == (u8*)(prng.mBuffer.data() + prng.mBuffer.size()));

                //        assert(prng.mBuffer.size() == 256);
                //        for (u64 i = 0; i < 256; ++i)
                //        {
                //            block b = prng.mBuffer.data()[i];
                //            block k = prng.mBuffer.data()[(u8)(i - 1)];
                //            prng.mBuffer[i] = AES::roundEnc(b, k) ^ k;
                //        }

                //        ptr = (u8*)prng.mBuffer.data();
                //        q = 0;
                //    }

                //}
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

            if (j + mExtraDiag - 1 < mCodeSize && mExtraDiag)
                pl.push_back(j + mExtraDiag - 1, i);
            //if (q % 4 == 0)

        }


        template<typename T, bool rangeCheck, int width>
        OC_FORCEINLINE void accOne(
            T* __restrict xx,
            T& xi,
            u64 i,
            u8*& ptr,
            PRNG& prng,
            u64& q,
            u64 qe)
        {
            T buf[8];
            __m128 Zero = _mm_setzero_ps();

            auto xii = _mm_load_ps((float*)&xi);

            u64 j = i + 1;

            if (!rangeCheck || j < mCodeSize)
            {
                auto xj = xx[j] ^ xi;
                xi = xj;
                xx[j] = xj;
            }
            ++j;

            {
                if (q + width > qe)
                {
                    assert(prng.mBuffer.size() == 256);
                    for (u64 i = 0; i < 256; ++i)
                    {
                        block b = prng.mBuffer.data()[i];
                        block k = prng.mBuffer.data()[(u8)(i - 1)];
                        prng.mBuffer[i] = AES::roundEnc(b, k) ^ k;
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


                auto b0 = rnd;
                auto b1 = _mm_slli_epi32(rnd, 1);;
                auto b2 = _mm_slli_epi32(rnd, 2);
                auto b3 = _mm_slli_epi32(rnd, 3);
                auto b4 = _mm_slli_epi32(rnd, 4);
                auto b5 = _mm_slli_epi32(rnd, 5);
                auto b6 = _mm_slli_epi32(rnd, 6);
                auto b7 = _mm_slli_epi32(rnd, 7);

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

                if (!rangeCheck || j + 0 < mCodeSize) xx[j + 0] = _mm_xor_si128(xx[j + 0], buf[0]);
                if (!rangeCheck || j + 1 < mCodeSize) xx[j + 1] = _mm_xor_si128(xx[j + 1], buf[1]);
                if (!rangeCheck || j + 2 < mCodeSize) xx[j + 2] = _mm_xor_si128(xx[j + 2], buf[2]);
                if (!rangeCheck || j + 3 < mCodeSize) xx[j + 3] = _mm_xor_si128(xx[j + 3], buf[3]);
                if (!rangeCheck || j + 4 < mCodeSize) xx[j + 4] = _mm_xor_si128(xx[j + 4], buf[4]);
                if (!rangeCheck || j + 5 < mCodeSize) xx[j + 5] = _mm_xor_si128(xx[j + 5], buf[5]);
                if (!rangeCheck || j + 6 < mCodeSize) xx[j + 6] = _mm_xor_si128(xx[j + 6], buf[6]);
                if (!rangeCheck || j + 7 < mCodeSize) xx[j + 7] = _mm_xor_si128(xx[j + 7], buf[7]);
            }


            if (j + mExtraDiag - 1 < mCodeSize && mExtraDiag)
            {
                xx[j + mExtraDiag - 1] = _mm_xor_si128(xx[j + mExtraDiag - 1], xi);
            }
        }


        template<typename T>
        void uniformAccumulate(span<T> x)
        {
            PRNG prng(mSeed ^ OneBlock);


            u64 i = 0;
            auto main = (u64)std::max<i64>(0, mCodeSize - mStickyAccumulator - mAccumulatorSize);
            block rnd;
            u8* ptr = (u8*)prng.mBuffer.data();
            u8* ptr2 = (u8*)prng.mBuffer.data();
            auto qe = prng.mBuffer.size() * 128 / 8;
            u64 q = 0;
            T* __restrict xx = x.data();


            if (mAccumulatorSize % 8)
                throw RTE_LOC;


            block xi = xx[0];

#define CASE(I) case I:\
            for (; i < main; ++i)\
                accOne<T, false, I>(xx, xi, i, ptr, prng, q, qe);\
            for (; i < mCodeSize; ++i)\
                accOne<T, true, I>(xx, xi, i, ptr, prng, q, qe);\
            break

            switch (mAccumulatorSize / 8)
            {
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


        struct Modd
        {
            PRNG prng;
            details::Xoshiro256Plus mXoshiro256Plus;
            u64 modVal, idx;
            span<u64> vals;
            libdivide::libdivide_u64_t mod;
            RNG mReuse;
            bool mIsPow2;
            std::vector<u64> mPow2Vals;
            u64 mPow2, mPow2Mask, mPow2Step;

            Modd(block seed, u64 m, RNG reuse)
                : prng(seed)
                , mXoshiro256Plus(seed)
                , modVal(m)
                , mod(libdivide::libdivide_u64_gen(m))
                , mReuse(reuse)
            {
                mPow2 = log2ceil(modVal);
                mIsPow2 = mPow2 == log2floor(modVal);
                if (mIsPow2)
                {
                    mPow2Mask = modVal - 1;
                    mPow2Step = divCeil(mPow2, 8);
                    mPow2Vals.resize(prng.mBufferByteCapacity / mPow2Step);
                    vals = mPow2Vals;
                }
                else
                {
                    vals = span<u64>((u64*)prng.mBuffer.data(), prng.mBuffer.size() * 2);
                }
                refill();
            }

            void refill()
            {
                idx = 0;
                if (mReuse == RNG::gf128mul)
                {
                    for (auto& v : prng.mBuffer)
                        v = v.gf128Mul(v);
                }
                else if (mReuse == RNG::prng)
                {
                    prng.getBufferSpan(-1);
                }
                else if (mReuse == RNG::aeslite)
                {

                    assert(prng.mBuffer.size() == 256);
                    for (u64 i = 0; i < 256; ++i)
                    {
                        //auto idx = mPrng.mBuffer[i].get<u8>();
                        block b = prng.mBuffer.data()[i];
                        block k = prng.mBuffer.data()[(u8)(i - 1)];
                        //for (u64 j = 0; j < 8; ++j)
                        //{
                        //    b = b ^ mPrng.mBuffer.data()[idx[j]];
                        //}
                        prng.mBuffer[i] = AES::roundEnc(b, k) ^ k;
                    }
                }
                else
                {
                    for (u64 i = 0; i < vals.size(); ++i)
                        vals[i] = mXoshiro256Plus.next();
                }

                if (mPow2)
                {
                    u8* ptr = (u8*)prng.mBuffer.data();
                    for (u64 i = 0; i < vals.size(); ++i)
                    {
                        vals.data()[i] = *(u64*)ptr & mPow2Mask;
                        ptr += mPow2Step;
                    }
                }
                else
                {


                    assert(vals.size() % 32 == 0);
                    for (u64 i = 0; i < vals.size(); i += 32)
                        doMod32(vals.data() + i, &mod, modVal);
                }
            }

            OC_FORCEINLINE u64 get()
            {
                if (idx == vals.size())
                    refill();

                return vals.data()[idx++];
            }


#ifdef ENABLE_AVX
            using block256 = __m256i;
            static inline block256 my_libdivide_u64_do_vec256(const block256& x, const libdivide::libdivide_u64_t* divider)
            {
                return libdivide::libdivide_u64_do_vec256(x, divider);
            }
#else
            using block256 = std::array<block, 2>;

            static inline block256 _mm256_loadu_si256(block256* p) { return *p; }

            static inline block256 my_libdivide_u64_do_vec256(const block256& x, const libdivide::libdivide_u64_t* divider)
            {
                block256 y;
                auto x64 = (u64*)&x;
                auto y64 = (u64*)&y;
                for (u64 i = 0; i < 4; ++i)
                {
                    y64[i] = libdivide::libdivide_u64_do(x64[i], divider);
                }

                return y;
            }
#endif


            static inline void doMod32(u64* vals, const libdivide::libdivide_u64_t* divider, const u64& modVal)
            {
                {
                    u64 i = 0;
                    block256 row256a = _mm256_loadu_si256((block256*)&vals[i]);
                    block256 row256b = _mm256_loadu_si256((block256*)&vals[i + 4]);
                    block256 row256c = _mm256_loadu_si256((block256*)&vals[i + 8]);
                    block256 row256d = _mm256_loadu_si256((block256*)&vals[i + 12]);
                    block256 row256e = _mm256_loadu_si256((block256*)&vals[i + 16]);
                    block256 row256f = _mm256_loadu_si256((block256*)&vals[i + 20]);
                    block256 row256g = _mm256_loadu_si256((block256*)&vals[i + 24]);
                    block256 row256h = _mm256_loadu_si256((block256*)&vals[i + 28]);
                    auto tempa = my_libdivide_u64_do_vec256(row256a, divider);
                    auto tempb = my_libdivide_u64_do_vec256(row256b, divider);
                    auto tempc = my_libdivide_u64_do_vec256(row256c, divider);
                    auto tempd = my_libdivide_u64_do_vec256(row256d, divider);
                    auto tempe = my_libdivide_u64_do_vec256(row256e, divider);
                    auto tempf = my_libdivide_u64_do_vec256(row256f, divider);
                    auto tempg = my_libdivide_u64_do_vec256(row256g, divider);
                    auto temph = my_libdivide_u64_do_vec256(row256h, divider);
                    //auto temp = libdivide::libdivide_u64_branchfree_do_vec256(row256, divider);
                    auto temp64a = (u64*)&tempa;
                    auto temp64b = (u64*)&tempb;
                    auto temp64c = (u64*)&tempc;
                    auto temp64d = (u64*)&tempd;
                    auto temp64e = (u64*)&tempe;
                    auto temp64f = (u64*)&tempf;
                    auto temp64g = (u64*)&tempg;
                    auto temp64h = (u64*)&temph;
                    vals[i + 0] -= temp64a[0] * modVal;
                    vals[i + 1] -= temp64a[1] * modVal;
                    vals[i + 2] -= temp64a[2] * modVal;
                    vals[i + 3] -= temp64a[3] * modVal;
                    vals[i + 4] -= temp64b[0] * modVal;
                    vals[i + 5] -= temp64b[1] * modVal;
                    vals[i + 6] -= temp64b[2] * modVal;
                    vals[i + 7] -= temp64b[3] * modVal;
                    vals[i + 8] -= temp64c[0] * modVal;
                    vals[i + 9] -= temp64c[1] * modVal;
                    vals[i + 10] -= temp64c[2] * modVal;
                    vals[i + 11] -= temp64c[3] * modVal;
                    vals[i + 12] -= temp64d[0] * modVal;
                    vals[i + 13] -= temp64d[1] * modVal;
                    vals[i + 14] -= temp64d[2] * modVal;
                    vals[i + 15] -= temp64d[3] * modVal;
                    vals[i + 16] -= temp64e[0] * modVal;
                    vals[i + 17] -= temp64e[1] * modVal;
                    vals[i + 18] -= temp64e[2] * modVal;
                    vals[i + 19] -= temp64e[3] * modVal;
                    vals[i + 20] -= temp64f[0] * modVal;
                    vals[i + 21] -= temp64f[1] * modVal;
                    vals[i + 22] -= temp64f[2] * modVal;
                    vals[i + 23] -= temp64f[3] * modVal;
                    vals[i + 24] -= temp64g[0] * modVal;
                    vals[i + 25] -= temp64g[1] * modVal;
                    vals[i + 26] -= temp64g[2] * modVal;
                    vals[i + 27] -= temp64g[3] * modVal;
                    vals[i + 28] -= temp64h[0] * modVal;
                    vals[i + 29] -= temp64h[1] * modVal;
                    vals[i + 30] -= temp64h[2] * modVal;
                    vals[i + 31] -= temp64h[3] * modVal;
                }
            }
        };


        template<typename T, u64 count>
        OC_FORCEINLINE typename std::enable_if<(count > 1), T>::type
            expandOne(const T* __restrict ee, Modd& prng)const
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
            else
            {
                auto r = prng.get();
                //std::cout << r << " ";
                return expandOne<T, count - 1>(ee, prng) ^ ee[r];
            }
        }



        template<typename T, u64 count>
        OC_FORCEINLINE typename std::enable_if<count == 1, T>::type
            expandOne(const T* __restrict ee, Modd& prng) const
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
            Modd prng(mSeed, mCodeSize, mReuse);

            std::vector<u64> row(mExpanderWeight);
            u64* __restrict rr = row.data();
            std::vector<T> rowVal(mExpanderWeight);
            const T* __restrict  ee = e.data();
            T* __restrict  ww = w.data();

            for (auto i = 0ull; i < mMessageSize; ++i)
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


        template<typename T>
        void permExpand(span<T> e, span<T> w)
        {
            if (mPermute == 1)
            {
                setTimePoint("permute ");
                mPerm.apply(e);
            }
            else
            {

                mSqrtPerm.apply(e);
                setTimePoint("permute " /*+ std::to_string(mSqrtPerm.mPerms.size())*/);
                //setTimePoint("permute " + std::to_string(mSqrtPerm.mPerms.size()));
            }


            linearSums(e, w, mExpanderWeight);
        }

        SparseMtx getB() const
        {
            //PRNG prng(mSeed);
            Modd prng(mSeed, mCodeSize, mReuse);
            PointList points(mMessageSize, mCodeSize);

            std::vector<u64> row(mExpanderWeight);

            if (mPermute)
            {
                throw RTE_LOC;
            }
            else
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

            if (mAccumulatorWeight)
            {
                throw RTE_LOC;
            }
            else
            {
                for (i64 i = 0; i < mCodeSize; ++i)
                {
                    accOne(AP, i, ptr, prng, rnd, q, qe);
                }
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


    template<
        typename Table>
        OC_FORCEINLINE SparseMtx getAccPar(u64 n)
    {

        PointList AP(n, n);;

        for (i64 i = 0; i < n; ++i)
        {
            //std::cout << "x[" << i << "] += x[" << i + 1;
            AP.push_back(i, i);

            if (i + 1 < n)
                AP.push_back(i + 1, i);

            auto col = Table::data[i % Table::data.size()];
            for (auto x : col)
            {
                //std::cout << " " << x + i;
                if (x + i < n)
                    AP.push_back(x + i, i);
            }

            //std::cout << std::endl;
        }

        return AP;
    }

    template<typename Table>
    DenseMtx getAcc(u64 n)
    {
        auto APar = getAccPar<Table>(n);
        auto A = DenseMtx::Identity(n);

        //std::cout << A << std::endl << std::endl;

        for (u64 i = 0; i < n; ++i)
        {
            for (auto y : APar.col(i))
            {
                if (y != i)
                {
                    auto ay = A.row(y);
                    auto ai = A.row(i);
                    ay ^= ai;
                }


            }
            //std::cout << i << "\n";
            //std::cout << A << std::endl << std::endl;
        }

        return A;
    }


    template<

        typename Table,
        typename Perm,
        typename T,
        bool rangeCheck,
        bool flush = false,
        bool verbose = false>
        OC_FORCEINLINE void accumulateBlock(T* xx, T* end, Perm& perm)
    {
        //auto& perm = mPerm;
        static constexpr int chunkSize = Perm::chunkSize;

        static_assert(Table::data.size() % chunkSize == 0, "");
        auto tIter = Table::data.data();
        for (u64 j = 0; j < Table::data.size();)
        {

            _mm_prefetch((char*)(xx + j + Table::data.size()), _MM_HINT_T0);
            for (u64 k = 0; k < chunkSize; ++k, ++j)
            {

                T* __restrict xi = xx + j;
                T* __restrict xs = xi + 1;

                if constexpr (Table::data[0].size() == 4)
                {
                    T* __restrict x0 = xi + tIter[j].data()[0];
                    T* __restrict x1 = xi + tIter[j].data()[1];
                    T* __restrict x2 = xi + tIter[j].data()[2];
                    T* __restrict x3 = xi + tIter[j].data()[3];

                    //std::cout << "x[" << j << "] += x[" << j + 1
                    //    << " + " << j + (int)tIter[j].data()[0]
                    //    << " + " << j + (int)tIter[j].data()[1]
                    //    << " + " << j + (int)tIter[j].data()[2]
                    //    << " + " << j + (int)tIter[j].data()[3] << std::endl;

                    if constexpr (rangeCheck)
                    {
                        if (xs < end) *xs = *xs ^ *xi;
                        if (x0 < end) *x0 = *x0 ^ *xi;
                        if (x1 < end) *x1 = *x1 ^ *xi;
                        if (x2 < end) *x2 = *x2 ^ *xi;
                        if (x3 < end) *x3 = *x3 ^ *xi;
                    }
                    else
                    {

                        auto xxs = *xs ^ *xi;
                        auto xx0 = *x0 ^ *xi;
                        auto xx1 = *x1 ^ *xi;
                        auto xx2 = *x2 ^ *xi;
                        auto xx3 = *x3 ^ *xi;

                        assert(x3 < end);
                        *xs = xxs;
                        *x0 = xx0;
                        *x1 = xx1;
                        *x2 = xx2;
                        *x3 = xx3;

                    }
                }
                else if constexpr (Table::data[0].size() == 7)
                {
                    T* __restrict x0 = xi + Table::data[j][0];
                    T* __restrict x1 = xi + Table::data[j][1];
                    T* __restrict x2 = xi + Table::data[j][2];
                    T* __restrict x3 = xi + Table::data[j][3];
                    T* __restrict x4 = xi + Table::data[j][4];
                    T* __restrict x5 = xi + Table::data[j][5];
                    T* __restrict x6 = xi + Table::data[j][6];

                    if constexpr (rangeCheck)
                    {
                        if (xs < end) *xs = *xs ^ *xi;
                        if (x0 < end) *x0 = *x0 ^ *xi;
                        if (x1 < end) *x1 = *x1 ^ *xi;
                        if (x2 < end) *x2 = *x2 ^ *xi;
                        if (x3 < end) *x3 = *x3 ^ *xi;
                        if (x4 < end) *x4 = *x3 ^ *xi;
                        if (x5 < end) *x5 = *x5 ^ *xi;
                        if (x6 < end) *x6 = *x6 ^ *xi;
                    }
                    else
                    {
                        auto xxs = *xs ^ *xi;
                        auto xx0 = *x0 ^ *xi;
                        auto xx1 = *x1 ^ *xi;
                        auto xx2 = *x2 ^ *xi;
                        auto xx3 = *x3 ^ *xi;
                        auto xx4 = *x4 ^ *xi;
                        auto xx5 = *x5 ^ *xi;
                        auto xx6 = *x6 ^ *xi;

                        *xs = xxs;
                        *x0 = xx0;
                        *x1 = xx1;
                        *x2 = xx2;
                        *x3 = xx3;
                        *x4 = xx4;
                        *x5 = xx5;
                        *x6 = xx6;
                    }
                }
                else
                {
                    throw RTE_LOC;
                }

                perm.apply(xi, k);
                //if constexpr (!eagerPermute)
                //{
                //    *(T * __restrict)perm[k] = *xi;
                //    ++perm[k];
                //}

                if constexpr (verbose)
                {
                    BitVector state;
                    state.reserve(Table::data.size());
                    auto base = (int)*(u8*)&xx[j] & 1;
                    for (u64 i : rng(Table::data.size()))
                    {
                        auto bit = (int)*(u8*)&xx[j + i] & 1;
                        if (i == 1 || std::find(Table::data[j].begin(), Table::data[j].end(), i) != Table::data[j].end())
                        {
                            std::cout << state << (base ? Color::Green : Color::Red) << bit << Color::Default;
                            state.resize(0);
                        }
                        else
                            state.pushBack(bit);
                    }
                    if (state.size())
                        std::cout << state;
                    std::cout << std::endl;
                }
            }

            perm.template applyChunk<flush>(xx + j - chunkSize);
            //if constexpr (eagerPermute)
            //{
            //    //if (rangeCheck == false || perm != permEnd)
            //    //{
            //    //    std::array<T, permSize>* __restrict xi8 = (std::array<T, permSize>*)(xx + j - 8);
            //    //    memcpy(&dst[*(u32 * __restrict)perm], xi8, sizeof(xi8));
            //    //    ++perm;
            //    //}
            //}
        }
    }


    template<

        typename Table,
        typename Perm,
        typename T,
        bool rangeCheck,
        bool verbose = false>
        OC_FORCEINLINE void accumulateBlock2(T* xx, T* b, T* e, Perm& perm)
    {
        //auto& perm = mPerm;
        static constexpr int chunkSize = Perm::chunkSize;
        //auto e = xx - Table::data.size();
        static_assert(Table::data.size() % chunkSize == 0, "");
        auto tIter = Table::data.data();
        for (u64 j = 0; j < Table::data.size();)
        {

            _mm_prefetch((char*)(xx + j + Table::data.size() * 2), _MM_HINT_T0);
            for (u64 k = 0; k < chunkSize; ++k, ++j)
            {

                T* __restrict xb = xx + j;
                T* __restrict xi = xb + Table::data.size();
                T* __restrict xs = xi - 1;

                if constexpr (Table::data[0].size() == 4)
                {
                    T* __restrict x0 = xb + tIter[j].data()[0];
                    T* __restrict x1 = xb + tIter[j].data()[1];
                    T* __restrict x2 = xb + tIter[j].data()[2];
                    T* __restrict x3 = xb + tIter[j].data()[3];

                    //std::cout << "x[" << j << "] += x[" << j + 1
                    //    << " + " << j + (int)tIter[j].data()[0]
                    //    << " + " << j + (int)tIter[j].data()[1]
                    //    << " + " << j + (int)tIter[j].data()[2]
                    //    << " + " << j + (int)tIter[j].data()[3] << std::endl;

                    assert(x3 < e);
                    assert(xi < e);

                    if constexpr (rangeCheck)
                    {
                        if (xs >= b) *xi = *xs ^ *xi;
                        if (x0 >= b) *xi = *x0 ^ *xi;
                        if (x1 >= b) *xi = *x1 ^ *xi;
                        if (x2 >= b) *xi = *x2 ^ *xi;
                        if (x3 >= b) *xi = *x3 ^ *xi;
                    }
                    else
                    {
                        assert(x0 >= b);

                        *xi = *xi
                            ^ *xs
                            ^ *x0
                            ^ *x1
                            ^ *x2
                            ^ *x3;
                    }
                }
                else if constexpr (Table::data[0].size() == 7)
                {
                    T* __restrict x0 = xb + Table::data[j][0];
                    T* __restrict x1 = xb + Table::data[j][1];
                    T* __restrict x2 = xb + Table::data[j][2];
                    T* __restrict x3 = xb + Table::data[j][3];
                    T* __restrict x4 = xb + Table::data[j][4];
                    T* __restrict x5 = xb + Table::data[j][5];
                    T* __restrict x6 = xb + Table::data[j][6];

                    if constexpr (rangeCheck)
                    {
                        if (xs >= e) *xi = *xs ^ *xi;
                        if (x0 >= e) *xi = *x0 ^ *xi;
                        if (x1 >= e) *xi = *x1 ^ *xi;
                        if (x2 >= e) *xi = *x2 ^ *xi;
                        if (x3 >= e) *xi = *x3 ^ *xi;
                        if (x4 >= e) *xi = *x3 ^ *xi;
                        if (x5 >= e) *xi = *x5 ^ *xi;
                        if (x6 >= e) *xi = *x6 ^ *xi;
                    }
                    else
                    {
                        *xi = *xi
                            ^ *xs
                            ^ *x0
                            ^ *x1
                            ^ *x2
                            ^ *x3
                            ^ *x4
                            ^ *x5
                            ^ *x6;
                    }
                }
                else
                {
                    throw RTE_LOC;
                }

                perm.apply(xi, k);
                //if constexpr (!eagerPermute)
                //{
                //    *(T * __restrict)perm[k] = *xi;
                //    ++perm[k];
                //}

                if constexpr (verbose)
                {
                    BitVector state;
                    state.reserve(Table::data.size());
                    auto base = (int)*(u8*)&xx[j] & 1;
                    for (u64 i : rng(Table::data.size()))
                    {
                        auto bit = (int)*(u8*)&xx[j + i] & 1;
                        if (i == 1 || std::find(Table::data[j].begin(), Table::data[j].end(), i) != Table::data[j].end())
                        {
                            std::cout << state << (base ? Color::Green : Color::Red) << bit << Color::Default;
                            state.resize(0);
                        }
                        else
                            state.pushBack(bit);
                    }
                    if (state.size())
                        std::cout << state;
                    std::cout << std::endl;
                }
            }

            perm.template applyChunk<false> (xx + j - chunkSize);
            //if constexpr (eagerPermute)
            //{
            //    //if (rangeCheck == false || perm != permEnd)
            //    //{
            //    //    std::array<T, permSize>* __restrict xi8 = (std::array<T, permSize>*)(xx + j - 8);
            //    //    memcpy(&dst[*(u32 * __restrict)perm], xi8, sizeof(xi8));
            //    //    ++perm;
            //    //}
            //}
        }
    }


    // this expander/permuter first maps items into bins, every (i + j * NumBins)'th item 
    // is mapped to the i'th bin. These bins are then permuted
    // uniformly. The final expander is obtained by doing linear sums.
    template<typename T, int NumBins>
    struct TungstenBinPerm
    {
        static constexpr int c2 = 16;
        static constexpr int chunkSize = NumBins * c2;

        std::array<Perm, NumBins> mPerm;
        AlignedUnVector<T> mBuffer;
        std::array<T* __restrict, NumBins> mBins;

        void reset()
        {
            for (u64 i = 0; i < NumBins; ++i)
            {
                mBins[i] = mBuffer.data() + i * mPerm[i].mPerm.size();
            }
        }

        TungstenBinPerm(u64 size)
            : mBuffer(size)
        {
            if (size % NumBins)
                throw RTE_LOC;
            auto s = mBuffer.size() / NumBins;
            PRNG prng(CCBlock);
            for (u64 i = 0; i < NumBins; ++i)
            {
                mPerm[i].init(s, prng);
            }
            reset();
        }

        OC_FORCEINLINE void apply(T* __restrict xi, u64 k)
        {
            //assert(k < NumBins);
            //assert(mBins[k] < (k + 1) * mPerm[0].mPerm.size() + mBuffer.data());
            //*(T * __restrict)mBins[k] = *xi;
            //++mBins[k];
        }


        template<bool flush>
        OC_FORCEINLINE void applyChunk(T* __restrict x)
        {
            for (u64 i = 0; i < c2; ++i, ++x)
            {
                if (flush)
                {

                    if constexpr (NumBins == 8)
                    {
                        _mm_stream_si128((__m128i*)mBins[0]++, x[0]);
                        _mm_stream_si128((__m128i*)mBins[1]++, x[8]);
                        _mm_stream_si128((__m128i*)mBins[2]++, x[16]);
                        _mm_stream_si128((__m128i*)mBins[3]++, x[24]);
                        _mm_stream_si128((__m128i*)mBins[4]++, x[32]);
                        _mm_stream_si128((__m128i*)mBins[5]++, x[40]);
                        _mm_stream_si128((__m128i*)mBins[6]++, x[48]);
                        _mm_stream_si128((__m128i*)mBins[7]++, x[56]);
                    }
                    else if constexpr (NumBins == 16)
                    {

                        _mm_stream_si128((__m128i*)mBins[0]++, x[0]);
                        _mm_stream_si128((__m128i*)mBins[1]++, x[8]);
                        _mm_stream_si128((__m128i*)mBins[2]++, x[16]);
                        _mm_stream_si128((__m128i*)mBins[3]++, x[24]);
                        _mm_stream_si128((__m128i*)mBins[4]++, x[32]);
                        _mm_stream_si128((__m128i*)mBins[5]++, x[40]);
                        _mm_stream_si128((__m128i*)mBins[6]++, x[48]);
                        _mm_stream_si128((__m128i*)mBins[7]++, x[56]);

                        _mm_stream_si128((__m128i*)mBins[8 + 0]++, x[64 + 0]);
                        _mm_stream_si128((__m128i*)mBins[8 + 1]++, x[64 + 8]);
                        _mm_stream_si128((__m128i*)mBins[8 + 2]++, x[64 + 16]);
                        _mm_stream_si128((__m128i*)mBins[8 + 3]++, x[64 + 24]);
                        _mm_stream_si128((__m128i*)mBins[8 + 4]++, x[64 + 32]);
                        _mm_stream_si128((__m128i*)mBins[8 + 5]++, x[64 + 40]);
                        _mm_stream_si128((__m128i*)mBins[8 + 6]++, x[64 + 48]);
                        _mm_stream_si128((__m128i*)mBins[8 + 7]++, x[64 + 56]);
                    }
                    else
                    {
                        throw RTE_LOC;
                    }
                }
                else
                {

                    if constexpr (NumBins == 8)
                    {
                        *mBins[0]++ = x[0];
                        *mBins[1]++ = x[8];
                        *mBins[2]++ = x[16];
                        *mBins[3]++ = x[24];
                        *mBins[4]++ = x[32];
                        *mBins[5]++ = x[40];
                        *mBins[6]++ = x[48];
                        *mBins[7]++ = x[56];
                    }
                    else if constexpr (NumBins == 16)
                    {

                        *mBins[0]++ = x[0];
                        *mBins[1]++ = x[8];
                        *mBins[2]++ = x[16];
                        *mBins[3]++ = x[24];
                        *mBins[4]++ = x[32];
                        *mBins[5]++ = x[40];
                        *mBins[6]++ = x[48];
                        *mBins[7]++ = x[56];
                        *
                            *mBins[8 + 0]++ = x[64 + 0];
                        *mBins[8 + 1]++ = x[64 + 8];
                        *mBins[8 + 2]++ = x[64 + 16];
                        *mBins[8 + 3]++ = x[64 + 24];
                        *mBins[8 + 4]++ = x[64 + 32];
                        *mBins[8 + 5]++ = x[64 + 40];
                        *mBins[8 + 6]++ = x[64 + 48];
                        *mBins[8 + 7]++ = x[64 + 56];
                    }
                    else
                    {
                        throw RTE_LOC;
                    }
                }
            }
        }

        void finalize()
        {
            auto s = mBuffer.size() / NumBins;
            for (u64 j = 0; j < NumBins; ++j)
            {
                auto sub = mBuffer.subspan(s * j, s);
                mPerm[j].apply(sub);
            }
        }
    };

    // this expander/permuter maps chunks of inputs uniformly. The final expander is obtained by doing linear sums.
    template<typename T, int chunkSize_>
    struct TungstenPerm
    {
        static constexpr int chunkSize = chunkSize_;
        Perm mPerm;
        AlignedUnVector<T> mBuffer;
        u32* mPermIter;

        void reset()
        {
            mPermIter = mPerm.mPerm.data();
        }

        TungstenPerm(u64 size)
            : mBuffer(size)
        {
            if (size % chunkSize)
                throw RTE_LOC;
            PRNG prng(CCBlock);
            if (mPerm.mPerm.size() == 0)
                mPerm.init(mBuffer.size() / chunkSize, prng, true);
            reset();
        }

        void finalize()
        {
        }

        OC_FORCEINLINE void apply(T* __restrict x, u64 k)
        {}

        template<bool flush>
        OC_FORCEINLINE void applyChunk(T* __restrict x)
        {
            assert(mPermIter < mPerm.mPerm.data() + mPerm.mPerm.size());

            T* __restrict dst = &mBuffer.data()[*(u32 * __restrict)mPermIter * chunkSize];

            //for (u64 i = 0; i < chunkSize; ++i)
            //{
            //    std::cout << ">" << mIdx++ <<" -> " << 
            //}
            //std::cout<< ">" << *mPermIter << std::endl;
            ++mPermIter;

            //if constexpr (std::is_same_v<T, block> && flush)
            //{
            //    if constexpr (chunkSize == 8)
            //    {
            //        _mm_stream_si128((__m128i*)dst + 0, x[0]);
            //        _mm_stream_si128((__m128i*)dst + 1, x[1]);
            //        _mm_stream_si128((__m128i*)dst + 2, x[2]);
            //        _mm_stream_si128((__m128i*)dst + 3, x[3]);
            //        _mm_stream_si128((__m128i*)dst + 4, x[4]);
            //        _mm_stream_si128((__m128i*)dst + 5, x[5]);
            //        _mm_stream_si128((__m128i*)dst + 6, x[6]);
            //        _mm_stream_si128((__m128i*)dst + 7, x[7]);

            //    }
            //    else
            //        for (u64 i = 0; i < chunkSize; ++i)
            //            _mm_stream_si128((__m128i*)dst + i, x[i]);
            //}
            //else
            memcpy(dst, x, sizeof(*x) * chunkSize);
        }

        SparseMtx getMatrix() const
        {
            auto n = mPerm.mPerm.size() * chunkSize;
            PointList ret(n, n);

            u64 r = 0;
            for (auto p : mPerm.mPerm)
            {
                //std::cout << "<" << p << std::endl;

                for (u64 i = 0; i < chunkSize; ++i, ++r)
                {
                    ret.push_back({ p * chunkSize + i , r });
                }
            }
            return ret;
        }
    };

    // this exapnder/permuter does nothing.
    struct NoopPerm
    {
        static constexpr int chunkSize = 1;

        NoopPerm() = default;
        NoopPerm(u64 n) {}

        void reset()
        {
        }


        void finalize()
        {
        }

        template<typename T>
        OC_FORCEINLINE void apply(T* __restrict x, u64 k)
        {}

        template<bool, typename T>
        OC_FORCEINLINE void applyChunk(T* __restrict x)
        {
        }
    };


    template<typename T_ = block, typename Next_ = TungstenPerm<T_, 8>, typename Table_ = TableTungsten1024x4>
    struct Tungsten2 : public TimerAdapter
    {
        using T = T_;
        using Perm = Next_;
        using Table = Table_;

        static constexpr bool accTwice = true;
        static constexpr int chunkSize = Perm::chunkSize;
        //using Perm = TungstenBinPerm<T, chunkSize>;
        //using Perm = TungstenPerm<T, chunkSize>;
        //using Table = TableTungsten128x4;
        //using Table = TableTungsten8x4;

        bool mFirst = true;
        u64 mExpanderWeight = 0;
        Perm mPerm;
        std::array<T, Table::data.size() * 2> mBuffer;


        Tungsten2(u64 size, u64 expanderWeight)
            : mPerm(size)
            , mExpanderWeight(expanderWeight)
        {
            reset();
        }

        void reset()
        {
            mFirst = true;
            mPerm.reset();
        }

        template<bool rangeCheck = false, bool flush = false>
        OC_FORCEINLINE void processBlock(T* xx, T* end)
        {

            accumulateBlock<Table, Perm, T, rangeCheck, flush>(xx, end, mPerm);
        }

        void update(span<T> x)
        {
            if (x.size() == 0 || (x.size() % Table::data.size()))
                throw RTE_LOC;
            auto xx_ = x.data();
            auto rem = x.size() - Table::data.size();

            if (mFirst)
            {
                if (rem)
                {
                    for (u64 i = 0; i < rem; )
                    {
                        processBlock<false, true>(xx_ + i, x.data() + x.size());
                        i += Table::data.size();
                    }
                }

                memcpy(mBuffer.data(), x.data() + rem, Table::data.size() * sizeof(T));
            }
            else
            {
                memcpy(mBuffer.data() + Table::data.size(), x.data(), Table::data.size() * sizeof(T));
                processBlock(mBuffer.data(), mBuffer.data() + mBuffer.size());

                T* src;
                if (rem)
                {
                    for (u64 i = 0; i < rem; )
                    {
                        processBlock<false, true>(xx_ + i, x.data() + x.size());
                        i += Table::data.size();
                    }

                    src = x.data() + rem;
                }
                else
                    src = mBuffer.data() + Table::data.size();

                memcpy(mBuffer.data(), src, Table::data.size() * sizeof(T));
            }

            mFirst = false;
        }

        template<bool rangeCheck = false>
        OC_FORCEINLINE void processBlock2(T* x, T* xb, T* xe)
        {
            accumulateBlock2<Table, Perm, T, rangeCheck>(x, xb,xe, mPerm);
        }


        void update2(span<T> x)
        {
            assert(x.size() && (x.size() % Table::data.size() == 0));

            auto xx_ = x.data();
            auto rem = x.size() - Table::data.size();
            auto e = x.data() + x.size();

            if (mFirst)
            {
                processBlock2<true>(xx_, xx_, e);

                for (u64 i = Table::data.size(); i < rem; i += Table::data.size())
                {
                    processBlock2(xx_ + i, xx_, e);
                }

                memcpy(mBuffer.data(), x.data() + rem, Table::data.size() * sizeof(T));
            }
            else
            {
                memcpy(mBuffer.data() + Table::data.size(), x.data(), Table::data.size() * sizeof(T));
                processBlock2(mBuffer.data(), mBuffer.data(), mBuffer.data() + mBuffer.size());

                T* src;
                if (rem)
                {
                    memcpy(
                        x.data(),
                        mBuffer.data() + Table::data.size(),
                        Table::data.size() * sizeof(T));

                    for (u64 i = Table::data.size(); i < rem; i += Table::data.size())
                    {
                        processBlock2(xx_ + i, xx_, e);
                    }

                    src = x.data() + rem;
                }
                else
                    src = mBuffer.data() + Table::data.size();

                memcpy(mBuffer.data(), src, Table::data.size() * sizeof(T));
            }

            mFirst = false;
        }

        void finalize(span<T> w)
        {
            processBlock<true>(mBuffer.data(), mBuffer.data() + mBuffer.size());
            finalize2(w);
        }

        void finalize2(span<T> w)
        {
            mPerm.finalize();

            if constexpr (std::is_same<Perm, TungstenBinPerm<T, chunkSize>>::value)
                setTimePoint("permFinalize");



            if constexpr (accTwice)
            {
                T* __restrict xx = mPerm.mBuffer.data();
                auto end = mPerm.mBuffer.data() + mPerm.mBuffer.size();
                NoopPerm noop;

                for (u64 i = 0; i < mPerm.mBuffer.size() - Table::data.size(); i += Table::data.size())
                {
                    accumulateBlock<Table, NoopPerm, T, false, true>(xx + i, end, noop);
                    //processBlock<false>(xx + i, end);
                }

                accumulateBlock<Table, NoopPerm, T, true>(end - Table::data.size(), end, noop);
                setTimePoint("acc2");
            }


            linearSums<T>(mPerm.mBuffer, w, mExpanderWeight);

        }


        SparseMtx getAPar()
        {
            return getAccPar<Table>(mPerm.mBuffer.size());
        }
        DenseMtx getA()
        {
            return getAcc<Table>(mPerm.mBuffer.size());
        }

        SparseMtx getP()
        {
            return mPerm.getMatrix();
        }

        SparseMtx getS()
        {
            return getLinearSums(mPerm.mBuffer.size(), mExpanderWeight);
        }
    };


    template<typename T>
    struct TunstenExpander
    {
        AlignedVector<T> mBuffer;
        AlignedUnVector<u32> mMapping;
        AlignedVector<u32> mCounts;

        u32* mSizeIter;
        u32* mDstIter;
        u32 mSize;
        static constexpr int chunkSize = 8;

        void reset()
        {
            mDstIter = mMapping.data();
            mSizeIter = mCounts.data();
            if (mBuffer.size())
                memset(mBuffer.data(), 0, mBuffer.size() * sizeof(T));
            else
                mBuffer.resize(mSize);
        }

        TunstenExpander(u64 size, u64 weight)
            : mBuffer(size)
            , mSize(size)
        {
            PRNG prng(CCBlock);
            mCounts.resize(size);
            AlignedUnVector<u32> binIdx(size);
            Matrix<u32> vals(size / 2, weight);
            mMapping.resize(size / 2 * weight);
            auto iter = vals.data();

            for (u64 j = 0; j < vals.size(); ++j)
            {
                *iter = prng.get<u64>() % size;
                ++mCounts[*iter];
                ++iter;
            }

            binIdx[0] = 0;
            for (u64 i = 1; i < size; ++i)
                binIdx[i] = binIdx[i - 1] + mCounts[i - 1];

            for (u64 i = 0; i < vals.size(); ++i)
            {
                auto s = vals(i);
                auto d = i / weight;

                auto p = binIdx[s]++;
                mMapping[p] = d;
            }

            reset();
        }

        OC_FORCEINLINE void apply(T* __restrict xi, u64 k)
        {
        }


        template<bool flush>
        OC_FORCEINLINE void applyChunk(T* __restrict x)
        {
            for (u64 i = 0; i < chunkSize; ++i, ++mSizeIter)
            {
                for (u64 j = 0; j < *mSizeIter; ++j)
                {
                    auto& p = mBuffer.data()[*mDstIter++];
                    p = p ^ x[i];
                }
                assert(mDstIter <= mMapping.data() + mMapping.size());
            }
        }
    };


    template<typename T>
    struct TunstenRegularExpander
    {
        AlignedVector<T> mBuffer;
        Matrix<u32> mMapping;
        u32* mIter;
        static constexpr int chunkSize = 8;
        const int mD;

        void reset()
        {
            mIter = mMapping.data();
            if (mBuffer.size())
                memset(mBuffer.data(), 0, mBuffer.size() * sizeof(T));
            else
                mBuffer.resize(mMapping.rows());
        }

        TunstenRegularExpander(u64 size, u64 weight)
            : mBuffer(size)
            , mD(weight / 2)
        {
            if (weight % 2)
                throw RTE_LOC;
            PRNG prng(CCBlock);
            mMapping.resize(size, mD);

            AlignedUnVector<u32> mPerm(size);
            std::iota(mPerm.begin(), mPerm.end(), 0);

            for (u64 j = 0; j < mMapping.cols(); ++j)
            {
                for (u64 i = 0; i < size; ++i)
                {
                    span<u32> bin;
                    u32 d, s;
                    bool collision;
                    do {
                        auto k = prng.get<u32>() % (size - i) + i;
                        std::swap(mPerm.data()[i], mPerm.data()[k]);
                        d = i / 2;
                        s = mPerm[i];
                        bin = mMapping[s];
                        auto e = bin.begin() + j;
                        collision = std::find(bin.begin(), e, d) != e;
                    } while (collision);

                    bin[j] = d;
                }
            }

            reset();
        }

        OC_FORCEINLINE void apply(T* __restrict xi, u64 k)
        {
        }


        template<bool flush>
        OC_FORCEINLINE void applyChunk(T* __restrict x)
        {
            auto d = mD;
            for (u64 i = 0; i < chunkSize; ++i)
            {
                //T* __restrict p0 = mBuffer.data() + *mIter++;
                //T* __restrict p1 = mBuffer.data() + *mIter++;
                //T* __restrict p2 = mBuffer.data() + *mIter++;

                //auto v0 = *p0 ^ x[i];
                //auto v1 = *p1 ^ x[i];
                //auto v2 = *p2 ^ x[i];


                //*p0 = v0;
                //*p1 = v1;
                //*p2 = v2;
                for (u64 j = 0; j < d; ++j)
                {
                    auto& p = mBuffer.data()[*mIter++];
                    p = p ^ x[i];
                }
                assert(mIter <= mMapping.data() + mMapping.size());
            }
        }
    };

    struct TungstanClassic : public TimerAdapter
    {
        using T = block;

        //using Perm = TunstenRegularExpander<T>;
        using Perm = TunstenExpander<T>;
        using Table = TableTungsten128x4;
        std::array<T, Table::data.size() * 2> mBuffer;
        bool mFirst = true;
        Perm mPerm;

        TungstanClassic(u64 size, u64 weight)
            : mPerm(size, weight)
        {
        }

        void reset()
        {
            mPerm.reset();
        }

        template<bool rangeCheck = false, bool flush = false>
        OC_FORCEINLINE void processBlock(T* xx, T* end)
        {
            accumulateBlock<Table, Perm, T, rangeCheck, flush>(xx, end, mPerm);
        }

        void update(span<T> x)
        {
            if (x.size() == 0 && x.size() % Table::data.size())
                throw RTE_LOC;
            auto xx_ = x.data();
            auto rem = x.size() - Table::data.size();

            if (mFirst)
            {
                for (u64 i = 0; i < rem; i += Table::data.size())
                    processBlock<false, true>(xx_ + i, x.data() + x.size());

                memcpy(mBuffer.data(), x.data() + rem, Table::data.size() * sizeof(T));
            }
            else
            {
                memcpy(mBuffer.data() + Table::data.size(), x.data(), Table::data.size() * sizeof(T));
                processBlock(mBuffer.data(), mBuffer.data() + mBuffer.size());

                for (u64 i = 0; i < rem; i += Table::data.size())
                    processBlock<false, true>(xx_ + i, x.data() + x.size());

                T* src = rem ?
                    x.data() + rem :
                    mBuffer.data() + Table::data.size();

                memcpy(mBuffer.data(), src, Table::data.size() * sizeof(T));
            }
            mFirst = false;
        }

        void finalize(span<T>)
        {

        }
    };
}

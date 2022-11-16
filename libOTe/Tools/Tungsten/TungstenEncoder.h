#include "cryptoTools/Common/Defines.h"
#include "libOTe/Tools/LDPC/Mtx.h"
#include "cryptoTools/Common/Range.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Crypto/Prng.h"
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
            xoshiro256Plus = 2
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



        template<typename T>
        void fixedAccumulate(span<T> x)
        {
#define TABLE tunsten_diagMtx_128x4
            auto main = x.size() / TABLE.size();
            main = main ?  (main - 1) * TABLE.size() : 0;

            auto xx = x.data();

            if (TABLE[0].size() == 4)
            {

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

            }
            else if (TABLE[0].size() == 10)
            {

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
            }

            for (u64 i = main, j= 0; i < x.size(); ++i, ++j)
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
        void uniformAccumulate(span<T> x)
        {
            //PRNG prng(mSeed ^ OneBlock);
            BitStream prng(mSeed ^ OneBlock, mAccumulatorSize, mReuse);
            //auto AP = getAPar();

            //std::vector<u64> buff(divCeil(mAccumulatorSize, 64));
            auto a8 = divCeil(mAccumulatorSize, 8);

            T zeroOne[2];
            memset(zeroOne, 0, sizeof(T));
            memset(zeroOne + 1, ~0, sizeof(T));
            //DenseMtx A = DenseMtx::Identity(mCodeSize);

            u64 i = 0;
            auto main = (u64)std::min<i64>(0, mCodeSize - mStickyAccumulator - mAccumulatorSize);

            for (; i < main; ++i)
            {
                auto j = i + 1;

                if (mStickyAccumulator)
                {
                    j = j + mStickyAccumulator;
                    auto jj = j - 1;
                    x[jj] = x[jj] ^ x[i];
                    //A.row(jj) ^= A.row(i);
                }

                //prng.get((u8*)buff.data(), a8);
                //auto bb = buff.data();
                auto vv = prng.get();
                auto e = j + mAccumulatorSize;
                auto xi = x[i];
                for (; j < e;)
                {
                    auto rem = e - j;
                    //auto v = *bb++;
                    auto ek = std::min<u64>(64, rem);

                    for (u64 k = 0; k < ek; ++k, ++j)
                    {
                        auto v = vv[k];
                        assert(v < 2);
                        x[j] = x[j] ^ (xi & zeroOne[v]);

                        //v = v / 2;
                    }
                }
            }

            auto xx = x.data();
            for (; i < mCodeSize; ++i)
            {
                //auto row = AP.row(i);
                //auto rIter = row.rbegin();
                //assert(*rIter++ == i);


                auto xi = xx[i];

                i64 j = i + 1;
                auto s = std::min<i64>(mCodeSize, j + mStickyAccumulator);
                auto e = std::min<i64>(mCodeSize, s + mAccumulatorSize);


                if (mStickyAccumulator)
                {
                    j = j + mStickyAccumulator;
                    if (j <= mCodeSize)
                    {
                        auto jj = j - 1;
                        xx[jj] = xx[jj] ^ xi;
                        //A.row(jj) ^= A.row(i);
                        //AP.push_back(j - 1, i);
                    }
                }

                //for (; j < s; ++j)
                //{
                //    x[j] = x[j] ^ x[i];
                //    A.row(j) ^= A.row(i);
                //}

                auto vv = prng.get();
                T buf[8];

                for (; j < e;)
                {
                    auto rem = e - j;
                    auto ek = std::min<u64>(64, rem);
                    auto ek8 = ek / 8 * 8;
                    u64 k = 0;

                    for (; k < ek8; k += 8, j += 8, vv += 8)
                    {
                        buf[0] = zeroOne[vv[0]];
                        buf[1] = zeroOne[vv[1]];
                        buf[2] = zeroOne[vv[2]];
                        buf[3] = zeroOne[vv[3]];
                        buf[4] = zeroOne[vv[4]];
                        buf[5] = zeroOne[vv[5]];
                        buf[6] = zeroOne[vv[6]];
                        buf[7] = zeroOne[vv[7]];

                        buf[0] = xi & buf[0];
                        buf[1] = xi & buf[1];
                        buf[2] = xi & buf[2];
                        buf[3] = xi & buf[3];
                        buf[4] = xi & buf[4];
                        buf[5] = xi & buf[5];
                        buf[6] = xi & buf[6];
                        buf[7] = xi & buf[7];


                        xx[j + 0] = xx[j + 0] ^ buf[0];
                        xx[j + 1] = xx[j + 1] ^ buf[1];
                        xx[j + 2] = xx[j + 2] ^ buf[2];
                        xx[j + 3] = xx[j + 3] ^ buf[3];
                        xx[j + 4] = xx[j + 4] ^ buf[4];
                        xx[j + 5] = xx[j + 5] ^ buf[5];
                        xx[j + 6] = xx[j + 6] ^ buf[6];
                        xx[j + 7] = xx[j + 7] ^ buf[7];
                    }


                    for (; k < ek; ++k, ++j)
                    {
                        //if (v & 1)
                        //{
                        //    x[j] = x[j] ^ x[i];
                        //    //A.row(j) ^= A.row(i);
                        //    //assert(*rIter++ == j);
                        //}

                        xx[j] = xx[j] ^ (xi & zeroOne[*vv++]);

                    }
                    assert(j <= x.size());
                }
                //assert(rIter == row.rend());
            }

        }

        struct Modd
        {
            PRNG prng;
            details::Xoshiro256Plus mXoshiro256Plus;
            u64 modVal, idx;
            span<u64> vals;
            libdivide::libdivide_u64_t mod;
            RNG mReuse;
            bool mPow2;
            std::vector<u64> mPow2Vals;
            u64 mPow2Mask, mPow2Step;

            Modd(block seed, u64 m, RNG reuse)
                : prng(seed)
                , mXoshiro256Plus(seed)
                , modVal(m)
                , mod(libdivide::libdivide_u64_gen(m))
                , mReuse(reuse)
            {
                mPow2 = log2ceil(modVal) == log2floor(modVal);
                if (mPow2)
                {
                    mPow2Mask = (1ull << (mPow2)) - 1;
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

                return vals[idx++];
            }


#ifdef ENABLE_SSE
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
        OC_FORCEINLINE typename std::enable_if<count, T>::type
            expandOne(const T* __restrict ee, Modd& prng)
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
                return expandOne<T, count - 1>(ee, prng) ^ ee[r];
            }
        }



        template<typename T, u64 count>
        OC_FORCEINLINE typename std::enable_if<!count, T>::type
            expandOne(const T* __restrict ee, Modd& prng)
        {
            auto r = prng.get();
            return ee[r];
        }

        template<typename T>
        void expand(span<const T> e, span<T> w)
        {
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
                mPerm.apply(e);
            else
                mSqrtPerm.apply(e);

            setTimePoint("permute");

            linearSums(e, w);
        }

        template<typename T>
        void linearSums(span<T> e, span<T> w)
        {

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
                        *P = *M0
                            ^ *M1
                            ^ *M2
                            ^ *M3
                            ^ *M4
                            ;

                        ++M0;
                        ++M1;
                        ++M2;
                        ++M3;
                        ++M4;
                        ++P;

                        assert(P <= w.data() + w.size());
                        assert(M0 <= e.data() + e.size());
                        assert(M1 <= e.data() + e.size());
                        assert(M2 <= e.data() + e.size());
                        assert(M3 <= e.data() + e.size());
                        assert(M4 <= e.data() + e.size());
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

        SparseMtx getB() const
        {
            //PRNG prng(mSeed);
            Modd prng(mSeed, mCodeSize, mReuse);
            PointList points(mMessageSize, mCodeSize);

            std::vector<u64> row(mExpanderWeight);
            for (auto i : rng(mMessageSize))
            {
                row[0] = prng.get();
                points.push_back(i, row[0]);
                for (auto j : rng(1, mExpanderWeight))
                {
                    do {
                        row[j] = prng.get();
                    } while (std::find(row.data(), row.data() + j, row[j]) != row.data() + j);

                    points.push_back(i, row[j]);
                }
            }

            return points;
        }

        // Get the parity check version of the accumulator
        SparseMtx getAPar() const
        {
            BitStream prng(mSeed ^ OneBlock, mAccumulatorSize, mReuse);

            PointList AP(mCodeSize, mCodeSize);;

            auto a8 = divCeil(mAccumulatorSize, 8);

            DenseMtx A = DenseMtx::Identity(mCodeSize);
            for (i64 i = 0; i < mCodeSize; ++i)
            {
                i64 j = i + 1;
                auto s = std::min<i64>(mCodeSize, j + mStickyAccumulator);
                auto e = std::min<i64>(mCodeSize, s + mAccumulatorSize);
                AP.push_back(i, i);

                if (mStickyAccumulator)
                {
                    j = j + mStickyAccumulator;
                    if (j <= mCodeSize)
                        AP.push_back(j - 1, i);
                }

                auto vv = prng.get();
                for (; j < e;)
                {
                    auto rem = e - j;
                    auto ek = std::min<u64>(64, rem);

                    for (u64 k = 0; k < ek; ++k, ++j)
                    {
                        if (vv[k])
                        {
                            AP.push_back(j, i);
                        }
                    }
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
                    if (y != i)
                    {
                        auto ay = A.row(y);
                        auto ai = A.row(i);
                        ay ^= ai;

                    }

                }

            }

            return A.sparse();
        }
};


    //Matrix<u32> sampleDiag(u64 size, u64 weight, u64 length, PRNG& prng)
    //{

    //    Matrix<u32> ss(length, size);

    //    std::vector<u32> weights(length);


    //    for (u64 i = 0; i < length; ++i)
    //    {
    //        u32 dd = 0;
    //        std::vector<u32> dist(size);
    //        for (u64 j = 0; j < size; ++j)
    //        {

    //        }
    //    }
    //}
}
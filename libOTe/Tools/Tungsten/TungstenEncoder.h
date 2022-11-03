#include "cryptoTools/Common/Defines.h"
#include "libOTe/Tools/LDPC/Mtx.h"
#include "cryptoTools/Common/Range.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Crypto/Prng.h"

#ifdef ENABLE_AVX
#define LIBDIVIDE_AVX2
#elif ENABLE_SSE
#define LIBDIVIDE_SSE2
#endif

#include "libdivide.h"

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

        void config(
            u64 messageSize,
            u64 codeSize,
            u64 expanderWeight,
            u64 accumulatorSize,
            u64 reuse,
            u64 stickyAccumulator = 1,
            block seed = block(0, 0))
        {
            mMessageSize = messageSize;
            mCodeSize = codeSize;
            mExpanderWeight = expanderWeight;
            mAccumulatorSize = accumulatorSize;
            mStickyAccumulator = stickyAccumulator;
            mReuse = reuse;
            assert(mStickyAccumulator <= mAccumulatorSize);
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

        u64 mStickyAccumulator = 1;

        bool mReuse = false;

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
            accumulate<T>(e);
            setTimePoint("tungsten.encode.accumulate");
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
            AlignedUnVector<block> mBuff;
            u64 mIdx, mEnd, mSize;
            bool mReuse;

            BitStream(block seed, u64 size, bool reuse)
                : mPrng(seed)
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
                mPrng.getBufferSpan(-1);
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
                return (u8*)mBuff.data() + mIdx;
            }

        };

        template<typename T>
        void accumulate(span<T> x)
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

            //std::cout << "A* " << A << std::endl;
        }

        struct Modd
        {
            PRNG prng;
            u64 modVal, idx;
            span<u64> vals;
            libdivide::libdivide_u64_t mod;
            u64 mReuse;
            Modd(block seed, u64 m, bool reuse)
                : prng(seed)
                , modVal(m)
                , mod(libdivide::libdivide_u64_gen(m))
                , mReuse(reuse)
            {
                vals = span<u64>((u64*)prng.mBuffer.data(), prng.mBuffer.size() * 2);
                refill();
            }

            void refill()
            {
                idx = 0;
                if (mReuse)
                {
                    ++mReuse;
                    for (auto& v : prng.mBuffer)
                        v = v.gf128Mul(v);
                }
                else
                    prng.getBufferSpan(-1);

                assert(vals.size() % 32 == 0);
                for (u64 i = 0; i < vals.size(); i += 32)
                    doMod32(vals.data() + i, &mod, modVal);
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
            if constexpr (count == 0)
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
                    ww[i] = expandOne<T,5>(ee, prng);
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
                        //if (std::find(row.data(), row.data() + j, row[j]) != row.data() + j)
                        //{
                        //    std::cout << i << std::endl;
                        //}

                        wv = wv ^ ee[rr[j]];
                    }
                    ww[i] = wv;
                }
                }
                //for (auto j = 1ull; j < mExpanderWeight; ++j)
                //{
                //    rowVal[0] = rowVal[0] ^ rowVal[j];
                //}

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
                //for (; j < s; ++j)
                //    AP.push_back(j, i);

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
                            //x[j] = x[j] ^ x[i];
                            //xorAdd(A.col(j), A.col(i));
                            //assert(*rIter++ == j);
                        }
                        //x[j] = x[j] ^ (x[i] & zeroOne[v & 1]);
                    }
                }
                //assert(rIter == row.rend());

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

}
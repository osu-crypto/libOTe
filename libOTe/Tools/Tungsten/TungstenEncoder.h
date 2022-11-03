#include "cryptoTools/Common/Defines.h"
#include "libOTe/Tools/LDPC/Mtx.h"
#include "cryptoTools/Common/Range.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Crypto/Prng.h"

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
            u64 stickyAccumulator = 1,
            block seed = block(0, 0))
        {
            mMessageSize = messageSize;
            mCodeSize = codeSize;
            mExpanderWeight = expanderWeight;
            mAccumulatorSize = accumulatorSize;
            mStickyAccumulator = stickyAccumulator;

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

        template<typename T>
        void accumulate(span<T> x)
        {
            PRNG prng(mSeed ^ OneBlock);

            //auto AP = getAPar();

            std::vector<u64> buff(divCeil(mAccumulatorSize, 64));
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

                prng.get((u8*)buff.data(), a8);
                auto bb = buff.data();
                auto e = j + mAccumulatorSize;

                for (; j < e;)
                {
                    auto rem = e - j;
                    auto v = *bb++;
                    auto ek = std::min<u64>(64, rem);

                    for (u64 k = 0; k < ek; ++k, ++j)
                    {
                        x[j] = x[j] ^ (x[i] & zeroOne[v & 1]);

                        v = v / 2;
                    }
                }
            }

            for (; i < mCodeSize; ++i)
            {
                //auto row = AP.row(i);
                //auto rIter = row.rbegin();
                //assert(*rIter++ == i);


                prng.get((u8*)buff.data(), a8);


                i64 j = i + 1;
                auto s = std::min<i64>(mCodeSize, j + mStickyAccumulator);
                auto e = std::min<i64>(mCodeSize, s + mAccumulatorSize);


                if (mStickyAccumulator)
                {
                    j = j + mStickyAccumulator;
                    if (j <= mCodeSize)
                    {
                        auto jj = j - 1;
                        x[jj] = x[jj] ^ x[i];
                        //A.row(jj) ^= A.row(i);
                        //AP.push_back(j - 1, i);
                    }
                }

                //for (; j < s; ++j)
                //{
                //    x[j] = x[j] ^ x[i];
                //    A.row(j) ^= A.row(i);
                //}

                auto bb = buff.data();

                for (; j < e;)
                {
                    auto rem = e - j;
                    auto v = *bb++;
                    auto ek = std::min<u64>(64, rem);

                    for (u64 k = 0; k < ek; ++k, ++j)
                    {
                        //if (v & 1)
                        //{
                        //    x[j] = x[j] ^ x[i];
                        //    //A.row(j) ^= A.row(i);
                        //    //assert(*rIter++ == j);
                        //}
                        x[j] = x[j] ^ (x[i] & zeroOne[v & 1]);

                        v = v / 2;
                    }
                }
                //assert(rIter == row.rend());
            }

            //std::cout << "A* " << A << std::endl;
        }

        struct Modd
        {
            PRNG prng;
            u64 mod, i;
            span<u64> vals;

            Modd(block seed, u64 m)
                :prng(seed)
                ,mod(m)
            {
                refill();
            }

            void refill()
            {

                auto s = prng.getBufferSpan(-1);
                vals = span<u64>((u64*)s.data(), s.size() / sizeof(u64));
            }

            u64 get()
            {

            }
        };

        template<typename T>
        void expand(span<const T> e, span<T> w)
        {
            PRNG prng(mSeed);

            std::vector<u64> row(mExpanderWeight);
            for (auto i : rng(mMessageSize))
            {
                row[0] = prng.get<u64>() % mCodeSize;
                w[i] = e[row[0]];
                for (auto j : rng(1, mExpanderWeight))
                {
                    do {
                        row[j] = prng.get<u64>() % mCodeSize;
                    } while (std::find(row.data(), row.data() + j, row[j]) != row.data() + j);

                    w[i] = w[i] ^ e[row[j]];
                }
            }
        }

        SparseMtx getB() const
        {
            PRNG prng(mSeed);
            PointList points(mMessageSize, mCodeSize);

            std::vector<u64> row(mExpanderWeight);
            for (auto i : rng(mMessageSize))
            {
                row[0] = prng.get<u64>() % mCodeSize;
                points.push_back(i, row[0]);
                for (auto j : rng(1, mExpanderWeight))
                {
                    do {
                        row[j] = prng.get<u64>() % mCodeSize;
                    } while (std::find(row.data(), row.data() + j, row[j]) != row.data() + j);

                    points.push_back(i, row[j]);
                }
            }

            return points;
        }

        // Get the parity check version of the accumulator
        SparseMtx getAPar() const
        {
            PRNG prng(mSeed ^ OneBlock);

            PointList AP(mCodeSize, mCodeSize);;

            std::vector<u64> buff(divCeil(mAccumulatorSize, 64));
            auto a8 = divCeil(mAccumulatorSize, 8);

            DenseMtx A = DenseMtx::Identity(mCodeSize);
            for (i64 i = 0; i < mCodeSize; ++i)
            {
                prng.get((u8*)buff.data(), a8);

                i64 j = i + 1;
                auto s = std::min<i64>(mCodeSize, j + mStickyAccumulator);
                auto e = std::min<i64>(mCodeSize, s + mAccumulatorSize);
                AP.push_back(i, i);

                if (mStickyAccumulator)
                {
                    j = j + mStickyAccumulator;
                    if(j <= mCodeSize)
                        AP.push_back(j-1, i);
                }
                //for (; j < s; ++j)
                //    AP.push_back(j, i);

                auto bb = buff.data();

                for (; j < e;)
                {
                    auto rem = e - j;
                    auto v = *bb++;
                    auto ek = std::min<u64>(64, rem);

                    for (u64 k = 0; k < ek; ++k, ++j)
                    {
                        if (v & 1)
                        {
                            AP.push_back(j, i);
                            //x[j] = x[j] ^ x[i];
                            //xorAdd(A.col(j), A.col(i));
                            //assert(*rIter++ == j);
                        }
                        //x[j] = x[j] ^ (x[i] & zeroOne[v & 1]);

                        v = v / 2;
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
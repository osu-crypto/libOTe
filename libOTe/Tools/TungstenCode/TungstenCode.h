#pragma once


#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Aligned.h"
#include "libOTe/Tools/Tungsten/TungstenData.h"
#include <numeric>

namespace osuCrypto {
    namespace experimental {
        
        // this expander/permuter maps chunks of inputs uniformly. The final expander is obtained by doing linear sums.
        template<int chunkSize_>
        struct TungstenPerm
        {
            static constexpr int chunkSize = chunkSize_;
            AlignedUnVector<u32> mPerm;
            u32* mPermIter = nullptr;

            void reset()
            {
                mPermIter = mPerm.data();
            }

            void init(u64 size, block seed)
            {

                u64 n = divCeil(size, chunkSize);
                mPerm.resize(n);
                std::iota(mPerm.begin(), mPerm.end(), 0);

                PRNG prng(seed);
                for (u64 i = 0; i < n; ++i)
                {
                    auto j = prng.get<u32>() % (n - i) + i;
                    std::swap(mPerm[i], mPerm[j]);
                }
                reset();
            }

            void finalize()
            {
                assert(mPermIter == mPerm.mPerm.data() + mPerm.mPerm.size());
            }

            template<typename T>
            OC_FORCEINLINE void applyChunk(
                T* __restrict output,
                T* __restrict x)
            {
                assert(mPermIter < mPerm.data() + mPerm.size());
                T* __restrict dst = &output[*(u32 * __restrict)mPermIter * chunkSize];
                ++mPermIter;

                memcpy(dst, x, sizeof(*x) * chunkSize);
            }
        };


        template<int chunkSize_>
        struct TungstenAdder
        {
            static constexpr int chunkSize = chunkSize_;
            u64 mIdx = 0;


            template<typename T>
            OC_FORCEINLINE void applyChunk(
                T* __restrict output,
                T* __restrict x)
            {
                T* __restrict dst = output + mIdx;
                mIdx += chunkSize;

                if constexpr (chunkSize == 8)
                {
                    dst[0] ^= x[0];
                    dst[1] ^= x[1];
                    dst[2] ^= x[2];
                    dst[3] ^= x[3];
                    dst[4] ^= x[4];
                    dst[5] ^= x[5];
                    dst[6] ^= x[6];
                    dst[7] ^= x[7];
                }
                else
                {
                    for (u64 j = 0; j < chunkSize; ++j)
                        dst[j] ^= x[j];
                }
            }
        };

        struct TungstenCode
        {
            static const u64 ChunkSize = 8;
            TungstenPerm<ChunkSize> mPerm;

            u64 mMessageSize = 0;

            u64 mCodeSize = 0;

            u64 mNumIter = 2;

            void config(u64 messageSize, u64 codeSize, block seed = block(452345234,6756754363))
            {
                mMessageSize = messageSize;
                mCodeSize = codeSize;
                mPerm.init(mCodeSize - mMessageSize, seed);
            }

            template<typename T>
            void dualEncode(T* input)
            {
                AlignedUnVector<T> temp(roundUpTo(mCodeSize - mMessageSize, ChunkSize));

                if (temp.size() / ChunkSize != mPerm.mPerm.size())
                    throw RTE_LOC;

                std::array<T*, 2> buffs{ 
                    input + (mCodeSize - temp.size()),
                    temp.data()
                };

                for (u64 i = 0; i < mNumIter; ++i)
                {
                    accumulate<T>(
                        buffs[0],
                        buffs[1],
                        mCodeSize - mMessageSize, mPerm);

                    mPerm.reset();
                    std::swap(buffs[0], buffs[1]);
                }
                if (mMessageSize > temp.size())
                    throw RTE_LOC;// not impl

                TungstenAdder<ChunkSize> adder;
                accumulate<T>(
                    buffs[0],
                    input,
                    mMessageSize, 
                    adder);
            }

            template<
                typename Table,
                typename T,
                typename OutputMap,
                bool rangeCheck>
            OC_FORCEINLINE void accumulateBlock(
                T* __restrict xi,
                T* __restrict dst, 
                u64 remSize,
                OutputMap& output)
            {
                auto end = xi + remSize;

                //static constexpr int chunkSize = OutputMap::chunkSize;
                static_assert(Table::data.size() % ChunkSize == 0);
                auto table = Table::data.data();

                for (u64 j = 0; j < Table::data.size();)
                {
                    _mm_prefetch((char*)(xi + Table::data.size() * 2), _MM_HINT_T0);

                    for (u64 k = 0; k < ChunkSize; ++k, ++j, ++xi)
                    {
                        if constexpr (Table::data[0].size() == 4)
                        {
                            T* __restrict xs = xi + 1;
                            T* __restrict x0 = xi + table[j].data()[0];
                            T* __restrict x1 = xi + table[j].data()[1];
                            T* __restrict x2 = xi + table[j].data()[2];
                            T* __restrict x3 = xi + table[j].data()[3];

                            if (rangeCheck == false || xs < end) *xs = *xs ^ *xi;
                            if (rangeCheck == false || x0 < end) *x0 = *x0 ^ *xi;
                            if (rangeCheck == false || x1 < end) *x1 = *x1 ^ *xi;
                            if (rangeCheck == false || x2 < end) *x2 = *x2 ^ *xi;
                            if (rangeCheck == false || x3 < end) *x3 = *x3 ^ *xi;
                        }
                        else
                        {
                            throw RTE_LOC;
                        }
                    }

                    output.applyChunk(dst, xi - ChunkSize);

                    if (rangeCheck && xi >= end)
                        break;
                }
            }

            template<typename T, typename OutputMap>
            void accumulate(
                T* __restrict input,
                T*__restrict output,
                u64 size,
                OutputMap& map)
            {
                //using Table = TableTungsten128x4;
                using Table = TableTungsten1024x4;

                u64 main = std::max<i64>(size / Table::data.size() - 1, 0);

                for (u64 i = 0; i < main; ++i)
                {
                    auto rem = size - i * Table::data.size();
                    accumulateBlock<Table, T, OutputMap, false>(input, output, rem, map);
                    input += Table::data.size();
                }

                // last two iterations require range checking.
                u64 i = main;
                while(true)
                {
                    u64 rem = std::max<i64>(size - i * Table::data.size(), 0);
                    if (rem == 0)
                        return;

                    accumulateBlock<Table, T, OutputMap, true>(input, output, rem, map);

                    ++i;
                    input += Table::data.size();
                }
            }

        };

    }
}
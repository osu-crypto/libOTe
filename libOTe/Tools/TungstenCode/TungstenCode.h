#pragma once


#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Aligned.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "libOTe/Tools/TungstenCode/TungstenData.h"
#include <numeric>

namespace osuCrypto {
    namespace experimental {


        struct TungstenNoop
        {
            template<typename T, typename Ctx>
            OC_FORCEINLINE void applyChunk(T*, T*, Ctx&) {}

            void skip(u64) {}
            void reset() {}
        };

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

            template<typename T, typename Ctx, typename Iter>
            OC_FORCEINLINE void applyChunk(
                Iter output,
                Iter x,
                Ctx& ctx
            )
            {
                assert(mPermIter < mPerm.data() + mPerm.size());
                auto dst = output + (*(u32 * __restrict)mPermIter * chunkSize);
                ++mPermIter;

                ctx.copy(x, x + chunkSize, dst);
            }


            void skip(u64 i) 
            {
                assert(i % chunkSize == 0);
                mPermIter += i / chunkSize;
            }
        };


        template<int chunkSize_>
        struct TungstenAdder
        {
            static constexpr int chunkSize = chunkSize_;
            u64 mIdx = 0;

            void reset()
            {
                mIdx = 0;
            }

            template<typename T, typename Ctx, typename Iter>
            OC_FORCEINLINE void applyChunk(
                Iter output,
                Iter x,
                Ctx& ctx
            )
            {
                T* __restrict dst = output + mIdx;
                mIdx += chunkSize;

                if constexpr (chunkSize == 8)
                {
                    ctx.plus(*(dst + 0), *(dst + 0), *(x + 0));
                    ctx.plus(*(dst + 1), *(dst + 1), *(x + 1));
                    ctx.plus(*(dst + 2), *(dst + 2), *(x + 2));
                    ctx.plus(*(dst + 3), *(dst + 3), *(x + 3));
                    ctx.plus(*(dst + 4), *(dst + 4), *(x + 4));
                    ctx.plus(*(dst + 5), *(dst + 5), *(x + 5));
                    ctx.plus(*(dst + 6), *(dst + 6), *(x + 6));
                    ctx.plus(*(dst + 7), *(dst + 7), *(x + 7));
                }
                else
                {
                    for (u64 j = 0; j < chunkSize; ++j)
                        ctx.plus(*(dst + j), *(dst + j), *(x + j));
                }
            }

            void skip(u64 i)
            {
                assert(i % chunkSize == 0);
                mIdx += i;
            }
        };

        struct TungstenCode
        {
            static const u64 ChunkSize = 8;
            TungstenPerm<ChunkSize> mPerm;

            u64 mMessageSize = 0;

            u64 mCodeSize = 0;

            u64 mNumIter = 2;

            void config(u64 messageSize, u64 codeSize, block seed = block(452345234, 6756754363))
            {
                if (messageSize % ChunkSize)
                    throw std::runtime_error("messageSize must be a multiple of ChunkSize. " LOCATION);
                if (codeSize % ChunkSize)
                    throw std::runtime_error("codeSize must be a multiple of ChunkSize. " LOCATION);

                mMessageSize = messageSize;
                mCodeSize = codeSize;
                mPerm.init(mCodeSize - mMessageSize, seed);
            }

            template<
                typename F,
                typename CoeffCtx,
                typename Iter
            >
            void dualEncode(Iter&& e, CoeffCtx ctx)
            {
                using VecF = typename CoeffCtx::template Vec<F>;

                VecF temp(mCodeSize - mMessageSize);

                if (temp.size() / ChunkSize != mPerm.mPerm.size())
                    throw RTE_LOC;

                using RestrictIter = decltype(ctx.template restrictPtr<F>(e));

                std::array<RestrictIter, 2> buffs{
                    ctx.template restrictPtr<F>(e + (mCodeSize - temp.size())),
                    ctx.template restrictPtr<F>(temp.begin())
                };

                for (u64 i = 0; i < mNumIter; ++i)
                {
                    accumulate<F>(
                        buffs[0],
                        buffs[1],
                        mCodeSize - mMessageSize,
                        mPerm,
                        ctx);

                    std::swap(buffs[0], buffs[1]);
                }

                if (mMessageSize > temp.size())
                    throw RTE_LOC;// not impl

                TungstenAdder<ChunkSize> adder;
                accumulate<F>(
                    buffs[0],
                    ctx.template restrictPtr<F>(e),
                    mMessageSize,
                    adder,
                    ctx);
            }

            template<
                typename Table,
                typename F,
                bool rangeCheck,
                typename OutputMap,
                typename CoeffCtx,
                typename Iter
            >
            void accumulateBlock(
                Iter x,
                u64 i,
                Iter dst,
                u64 size,
                OutputMap& output,
                CoeffCtx& ctx)
            {

                //static constexpr int chunkSize = OutputMap::chunkSize;
                static_assert(Table::data.size() % ChunkSize == 0);
                auto table = Table::data.data();

                for (u64 j = 0; j < Table::data.size();)
                {
                    if (rangeCheck == false || i + Table::data.size() * 2 < size)
                        _mm_prefetch((char*)(x + i + Table::data.size() * 2), _MM_HINT_T0);

                    for (u64 k = 0; k < ChunkSize; ++k, ++j, ++i)
                    {

                        if constexpr (Table::data[0].size() == 4)
                        {
                            if constexpr (rangeCheck)
                            {
                                if (i == size)
                                    return;

                                auto xi = x + i;
                                auto xs = x + ((i + 1) % size);
                                ctx.plus(*xs, *xs, *xi);

                                for (u64 p = 0; p < Table::data[0].size(); ++p)
                                {
                                    auto idx = (i + table[j].data()[p]) % size;
                                    if (idx != i)
                                    {
                                        auto xi = x + i;
                                        auto xp = x + idx;
                                        ctx.plus(*xp, *xp, *xi);
                                    }
                                }
                            }
                            else
                            {
                                auto xi = x + i;

                                auto xs = xi + 1;
                                auto x0 = xi + table[j].data()[0];
                                auto x1 = xi + table[j].data()[1];
                                auto x2 = xi + table[j].data()[2];
                                auto x3 = xi + table[j].data()[3];

                                ctx.plus(*xs, *xs, *xi);
                                ctx.plus(*x0, *x0, *xi);
                                ctx.plus(*x1, *x1, *xi);
                                ctx.plus(*x2, *x2, *xi);
                                ctx.plus(*x3, *x3, *xi);

                            }
                        }
                        else
                        {
                            throw RTE_LOC;
                        }
                    }

                    output.template applyChunk<F>(dst, x + (i - ChunkSize), ctx);

                    if (rangeCheck && i >= size)
                        break;
                }
            }


            template<typename F,
                typename OutputMap,
                typename CoeffCtx,
                typename Iter>
            void accumulate(
                Iter input,
                Iter output,
                u64 size,
                OutputMap& map,
                CoeffCtx& ctx)
            {

                using Table = TableTungsten1024x4;

                u64 main = std::max<i64>(size / Table::data.size() - 1, 0) * Table::data.size();
                u64 i = 0;
                map.reset();

                // for the first iteration, the last accumulateBlock
                // will wrap anmd change its value. We therefore can't
                // yet map the output for this part. We do this at the end.
                while (i < Table::max)
                {
                    TungstenNoop noop;
                    if (i < main)
                        accumulateBlock<Table, F, false>(input, i, output, size, noop, ctx);
                    else
                        accumulateBlock<Table, F, true>(input, i, output, size, noop, ctx);
                    i += Table::data.size();
                }
                map.skip(i);

                // accumulate and map. no range check required.
                for (; i < main; i += Table::data.size())
                {
                    accumulateBlock<Table, F, false>(input, i, output, size, map, ctx);
                }

                // last iteration or two requires range checking.
                for (; i < size; i += Table::data.size())
                {
                    accumulateBlock<Table, F, true>(input, i, output, size, map, ctx);
                }

                // map the missing blocks at the start.
                map.reset();
                i = 0;
                auto end = std::min<u64>(Table::max, size);
                while (i < end)
                {
                    map.template applyChunk<F>(output, input + i, ctx);
                    i += ChunkSize;
                }
            }

        };

    }
}
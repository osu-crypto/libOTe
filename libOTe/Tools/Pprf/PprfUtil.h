#pragma once
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Aligned.h"
#include <mutex>
#include <list>

namespace osuCrypto
{


    // the various formats that the output of the
    // Pprf can be generated. 
    enum class PprfOutputFormat
    {
        // The i'th row holds the i'th leaf for all trees. 
        // The j'th tree is in the j'th column.
        ByLeafIndex,

        // The i'th row holds the i'th tree. 
        // The j'th leaf is in the j'th column.
        ByTreeIndex,

        // The native output mode. The output will be 
        // a single row with all leaf values.
        // Every 8 trees are mixed together where the 
        // i'th leaf for each of the 8 tree will be next 
        // to each other. For example, let tij be the j'th 
        // leaf of the i'th tree. If we have m leaves, then
        // 
        // t00 t10 ... t70       t01 t11 ... t71      ...  t0m t1m ... t7m
        // t80 t90 ... t_{15,0}  t81 t91 ... t_{15,1} ...  t8m t9m ... t_{15,m}
        // ...
        // 
        // These are all flattened into a single row.
        Interleaved,

        // call the user's callback. The leaves will be in
        // Interleaved format.
        Callback
    };



    namespace pprf
    {

        template<typename VecF, typename CoeffCtx>
        void copyOut(
            VecF& leaf,
            VecF& output,
            u64 totalTrees,
            u64 treeIndex,
            PprfOutputFormat oFormat,
            std::function<void(u64 treeIdx, VecF& lvl)>& callback)
        {
            auto curSize = std::min<u64>(totalTrees - treeIndex, 8);
            auto domain = leaf.size() / 8;
            if (oFormat == PprfOutputFormat::ByLeafIndex)
            {
                if (curSize == 8)
                {
                    for (u64 leafIndex = 0; leafIndex < domain; ++leafIndex)
                    {
                        auto oIdx = totalTrees * leafIndex + treeIndex;
                        auto iIdx = leafIndex * 8;
                        output[oIdx + 0] = leaf[iIdx + 0];
                        output[oIdx + 1] = leaf[iIdx + 1];
                        output[oIdx + 2] = leaf[iIdx + 2];
                        output[oIdx + 3] = leaf[iIdx + 3];
                        output[oIdx + 4] = leaf[iIdx + 4];
                        output[oIdx + 5] = leaf[iIdx + 5];
                        output[oIdx + 6] = leaf[iIdx + 6];
                        output[oIdx + 7] = leaf[iIdx + 7];
                    }
                }
                else
                {
                    for (u64 leafIndex = 0; leafIndex < domain; ++leafIndex)
                    {
                        //auto oi = output[leafIndex].subspan(treeIndex, curSize);
                        //auto& ii = leaf[leafIndex];
                        auto oIdx = totalTrees * leafIndex + treeIndex;
                        auto iIdx = leafIndex * 8;
                        for (u64 j = 0; j < curSize; ++j)
                            output[oIdx + j] = leaf[iIdx + j];
                    }
                }

            }
            else if (oFormat == PprfOutputFormat::ByTreeIndex)
            {

                if (curSize == 8)
                {
                    for (u64 leafIndex = 0; leafIndex < domain; ++leafIndex)
                    {
                        auto iIdx = leafIndex * 8;

                        output[(treeIndex + 0) * domain + leafIndex] = leaf[iIdx + 0];
                        output[(treeIndex + 1) * domain + leafIndex] = leaf[iIdx + 1];
                        output[(treeIndex + 2) * domain + leafIndex] = leaf[iIdx + 2];
                        output[(treeIndex + 3) * domain + leafIndex] = leaf[iIdx + 3];
                        output[(treeIndex + 4) * domain + leafIndex] = leaf[iIdx + 4];
                        output[(treeIndex + 5) * domain + leafIndex] = leaf[iIdx + 5];
                        output[(treeIndex + 6) * domain + leafIndex] = leaf[iIdx + 6];
                        output[(treeIndex + 7) * domain + leafIndex] = leaf[iIdx + 7];
                    }
                }
                else
                {
                    for (u64 leafIndex = 0; leafIndex < domain; ++leafIndex)
                    {
                        auto iIdx = leafIndex * 8;
                        for (u64 j = 0; j < curSize; ++j)
                            output[(treeIndex + j) * domain + leafIndex] = leaf[iIdx + j];
                    }
                }

            }
            else if (oFormat == PprfOutputFormat::Callback)
                callback(treeIndex, leaf);
            else
                throw RTE_LOC;
        }

        template<typename F, typename CoeffCtx>
        void allocateExpandBuffer(
            u64 depth,
            u64 numTrees,
            bool programPuncturedPoint,
            std::vector<u8>& buff,
            span<std::array<block, 2>>& sums,
            span<u8>& leaf,
            CoeffCtx& ctx)
        {

            u64 elementSize = ctx.template byteSize<F>();

            // num of bytes they will take up.
            u64 numBytes =
                depth * numTrees * sizeof(std::array<block,2>) +  // each internal level of the tree has two sums
                elementSize * numTrees * 2 +          // we must program numTrees inactive F leaves
                elementSize * numTrees * 2 * programPuncturedPoint; // if we are programing the active lead, then we have numTrees more.

            // allocate the buffer and partition them.
            buff.resize(numBytes);
            sums = span<std::array<block, 2>>((std::array<block,2>*)buff.data(), depth * numTrees);
            leaf = span<u8>((u8*)(sums.data() + sums.size()),
                elementSize * numTrees * 2 +
                elementSize * numTrees * 2 * programPuncturedPoint
            );

            void* sEnd = sums.data() + sums.size();
            void* lEnd = leaf.data() + leaf.size();
            void* end = buff.data() + buff.size();
            if (sEnd > end || lEnd != end)
                throw RTE_LOC;
        }

        template<typename VecF>
        void validateExpandFormat(
            PprfOutputFormat oFormat,
            VecF& output,
            u64 domain,
            u64 pntCount)
        {
            if (oFormat == PprfOutputFormat::Interleaved && pntCount % 8)
                throw std::runtime_error("For Interleaved output format, pointCount must be a multiple of 8 (general case not impl). " LOCATION);


            switch (oFormat)
            {
            case osuCrypto::PprfOutputFormat::ByLeafIndex:
            case osuCrypto::PprfOutputFormat::ByTreeIndex:
            case osuCrypto::PprfOutputFormat::Interleaved:
                if (output.size() != domain * pntCount)
                    throw RTE_LOC;
                break;
            case osuCrypto::PprfOutputFormat::Callback:
                if (output.size())
                    throw RTE_LOC;
                break;
            default:
                throw RTE_LOC;
                break;
            }

        }


        struct TreeAllocator
        {
            TreeAllocator() = default;
            TreeAllocator(const TreeAllocator&) = delete;
            TreeAllocator(TreeAllocator&&) = default;

            using ValueType = AlignedArray<block, 8>;
            std::list<AlignedUnVector<ValueType>> mTrees;
            std::vector<span<ValueType>> mFreeTrees;
            //std::mutex mMutex;
            u64 mTreeSize = 0, mNumTrees = 0;

            void reserve(u64 num, u64 size)
            {
                //std::lock_guard<std::mutex> lock(mMutex);
                mTreeSize = size;
                mNumTrees += num;
                mTrees.clear();
                mFreeTrees.clear();
                mTrees.emplace_back(num * size);
                auto iter = mTrees.back().data();
                for (u64 i = 0; i < num; ++i)
                {
                    mFreeTrees.push_back(span<ValueType>(iter, size));
                    assert((u64)mFreeTrees.back().data() % 32 == 0);
                    iter += size;
                }
            }

            span<ValueType> get()
            {
                //std::lock_guard<std::mutex> lock(mMutex);
                if (mFreeTrees.size() == 0)
                {
                    assert(mTreeSize);
                    mTrees.emplace_back(mTreeSize);
                    mFreeTrees.push_back(span<ValueType>(mTrees.back().data(), mTreeSize));
                    assert((u64)mFreeTrees.back().data() % 32 == 0);
                    ++mNumTrees;
                }

                auto ret = mFreeTrees.back();
                mFreeTrees.pop_back();
                return ret;
            }

            void clear()
            {
                mTrees = {};
                mFreeTrees = {};
                mTreeSize = 0;
                mNumTrees = 0;
            }
        };


        inline void allocateExpandTree(
            TreeAllocator& alloc,
            std::vector<span<AlignedArray<block, 8>>>& levels)
        {
            span<AlignedArray<block, 8>> tree = alloc.get();
            assert((u64)tree.data() % 32 == 0);
            levels[0] = tree.subspan(0, 1);
            auto rem = tree.subspan(2);
            for (auto i = 1ull; i <  levels.size(); ++i)
            {
                levels[i] = rem.subspan(0, levels[i - 1].size() * 2);
                assert((u64)levels[i].data() % 32 == 0);
                rem = rem.subspan(levels[i].size());
            }
        }


    }

}
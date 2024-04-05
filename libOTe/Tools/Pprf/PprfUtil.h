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
                depth * numTrees * sizeof(std::array<block, 2>) +  // each internal level of the tree has two sums
                elementSize * numTrees * 2 +          // we must program numTrees inactive F leaves
                elementSize * numTrees * 2 * programPuncturedPoint; // if we are programing the active lead, then we have numTrees more.

            // allocate the buffer and partition them.
            buff.resize(numBytes);
            sums = span<std::array<block, 2>>((std::array<block, 2>*)buff.data(), depth * numTrees);
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


        inline void allocateExpandTree(
            u64 domainSize,
            AlignedUnVector<block>& alloc,
            std::vector<span<AlignedArray<block, 8>>>& levels,
            bool reuseLevel = true)
        {
            auto depth = log2ceil(domainSize);
            levels.resize(depth + 1);

            if (reuseLevel)
            {
                auto secondLast = roundUpTo((domainSize + 1) / 2,2);
                auto size = roundUpTo((domainSize + secondLast),2);

                // we will allocate the last twoo levels of the tree. 
                // these levels will be used for the smaller levels as
                // well. We will alternate between the two.
                alloc.clear();
                alloc.resize(size * 8);

                std::array<span<AlignedArray<block, 8>>, 2>  buffs;
                buffs[0] = { (AlignedArray<block, 8>*)alloc.data(), secondLast };
                buffs[1] = { (AlignedArray<block, 8>*)alloc.data() + secondLast , domainSize };

                // give the last level the big buffer.
                levels.back() = buffs[1].subspan(0, domainSize);
                for (u64 i = levels.size() - 2, j = 0ull; i < levels.size(); --i, ++j)
                {
                    auto width = divCeil(domainSize, 1ull << (depth - i));
                    assert(
                        levels[i + 1].size() == 2 * width || 
                        levels[i + 1].size() == 2 * width - 1);

                    if (width > 1)
                        width = roundUpTo(width, 2);

                    // each level will be half the size of the next level.
                    // we alternate which buffer we use.
                    levels[i] = buffs[j % 2].subspan(0, width);
                }
            }
            else
            {
                u64 totalSize = 0;
                for (u64 i = 0; i < levels.size(); ++i)
                {
                    auto width = divCeil(domainSize, 1ull << (depth - i));
                    totalSize += roundUpTo(width, 2);
                }

                alloc.clear();
                alloc.resize(totalSize * 8);
                span<AlignedArray<block, 8>> buff((AlignedArray<block, 8>*)alloc.data(), totalSize);

                levels.back() = buff.subspan(0, domainSize);
                buff = buff.subspan(domainSize);
                for (u64 i = levels.size() - 2, j = 0ull; i < levels.size(); --i, ++j)
                {
                    // each level will be half the size of the next level.
                    auto width = divCeil(domainSize, 1ull << (depth - i));
                    assert(
                        levels[i + 1].size() == 2 * width ||
                        levels[i + 1].size() == 2 * width - 1);

                    if(width > 1)
                        width = roundUpTo(width, 2);

                    levels[i] = buff.subspan(0, width);
                    buff = buff.subspan(levels[i].size());
                }
            }

            if (levels[0].size() != 1)
                throw RTE_LOC;
        }


    }

}
#pragma once
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Aligned.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <mutex>
#include <list>
#include <limits>

#if defined(_MSC_VER) && defined(_M_X64)
#include <intrin.h>
#endif

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

    template<
        typename F,
        typename CoeffCtx = DefaultCoeffCtx<F>
    >
    struct PprfSender : public TimerAdapter 
    {
		virtual ~PprfSender() = default;

        using VecF = typename CoeffCtx::template Vec<F>;

        virtual  void configure(u64 domainSize, u64 pointCount) = 0;

        // the number of base OTs that should be set.
        virtual u64 baseOtCount() const = 0;

        // returns true if the base OTs are currently set.
        virtual bool hasBaseOts() const = 0;


        virtual void setBase(span<const std::array<block, 2>> baseMessages) = 0;

        virtual task<> expand(
            Socket& chl,
            const VecF& value,
            block seed,
            VecF& output,
            PprfOutputFormat oFormat,
            bool programPuncturedPoint,
            u64 numThreads,
            CoeffCtx ctx) = 0;

        virtual void clear() = 0;
    };


    template<
        typename F,
        typename CoeffCtx = DefaultCoeffCtx<F>
    >
    struct PprfReceiver: public TimerAdapter
    {
        using VecF = typename CoeffCtx::template Vec<F>;

		virtual ~PprfReceiver() = default;

        virtual void configure(u64 domainSize, u64 pointCount) = 0;


        // this function sample mPntCount integers in the range
        // [0,domain) and returns these as the choice bits.
        virtual BitVector sampleChoiceBits(PRNG& prng) = 0;

        // choices is in the same format as the output from sampleChoiceBits.
        virtual void setChoiceBits(const BitVector& choices) = 0;


        // the number of base OTs that should be set.
        virtual  u64 baseOtCount() const = 0; 

        // returns true if the base OTs are currently set.
        virtual  bool hasBaseOts() const = 0;


        virtual void setBase(span<const block> baseMessages) = 0;

        virtual std::vector<u64> getPoints(PprfOutputFormat format) const = 0;

        virtual void getPoints(span<u64> points, PprfOutputFormat format) const = 0;

        // programPuncturedPoint says whether the sender is trying to program the
        // active child to be its correct value XOR delta. If it is not, the
        // active child will just take a random value.
        virtual task<> expand(
            Socket& chl,
            VecF& output,
            PprfOutputFormat oFormat,
            bool programPuncturedPoint,
            u64 numThreads,
            CoeffCtx ctx) = 0;

        virtual void clear() = 0;

    };


    namespace pprf
    {
        using ExpandTreeNode = AlignedArray<block, 8>;
        using ExpandTreeBuffer = AlignedUnVector<ExpandTreeNode>;
        static_assert(sizeof(ExpandTreeNode) == 8 * sizeof(block));


        inline u64 checkedAdd(u64 a, u64 b)
        {
            if (b > std::numeric_limits<u64>::max() - a)
                throw std::invalid_argument("PPRF dimension addition overflow. " LOCATION);
            return a + b;
        }

        inline u64 checkedMul(u64 a, u64 b)
        {
            if (a && b > std::numeric_limits<u64>::max() / a)
                throw std::invalid_argument("PPRF dimension multiplication overflow. " LOCATION);
            return a * b;
        }

        inline u64 checkedRoundUpTo(u64 value, u64 step)
        {
            if (step == 0)
                throw std::invalid_argument("PPRF round-up step must be nonzero. " LOCATION);

            auto remainder = value % step;
            return remainder ? checkedAdd(value, step - remainder) : value;
        }

        inline std::size_t checkedSize(u64 value)
        {
            if (value > std::numeric_limits<std::size_t>::max())
                throw std::invalid_argument("PPRF allocation exceeds size_t. " LOCATION);
            return static_cast<std::size_t>(value);
        }

        inline u64 validateConfigure(u64 domainSize, u64 pointCount)
        {
            if (domainSize & 1)
                throw std::invalid_argument("PPRF domain must be even. " LOCATION);
            if (domainSize < 2)
                throw std::invalid_argument("PPRF domain must be at least 2. " LOCATION);
            if (pointCount == 0)
                throw std::invalid_argument("PPRF point count must be nonzero. " LOCATION);

            auto depth = log2ceil(domainSize);
            if (depth >= 64)
                throw std::invalid_argument("PPRF domain depth must be less than 64. " LOCATION);

            checkedSize(checkedMul(domainSize, pointCount));
            checkedSize(checkedMul(depth, pointCount));
            checkedRoundUpTo(pointCount, 8);
            return depth;
        }

        inline u64 reduce128Mod(u64 low, u64 high, u64 modulus)
        {
            if (modulus == 0)
                throw std::invalid_argument("PPRF sampling modulus must be nonzero. " LOCATION);

#if defined(__SIZEOF_INT128__)
            using uint128 = unsigned __int128;
            auto value = (static_cast<uint128>(high) << 64) | low;
            return static_cast<u64>(value % modulus);
#elif defined(_MSC_VER) && defined(_M_X64)
            u64 remainder = 0;
            auto reducedHigh = high % modulus;
            (void)_udiv128(reducedHigh, low, modulus, &remainder);
            return remainder;
#else
            // Portable fixed-work reduction of a two-limb integer. The
            // conditional subtraction form avoids overflowing a u64 when
            // doubling the current remainder.
            u64 remainder = 0;
            for (u64 i = 128; i-- > 0;)
            {
                auto bit = i < 64 ? ((low >> i) & 1) : ((high >> (i - 64)) & 1);
                if (remainder >= modulus - remainder)
                    remainder -= modulus - remainder;
                else
                    remainder += remainder;

                if (bit)
                    remainder = remainder == modulus - 1 ? 0 : remainder + 1;
            }
            return remainder;
#endif
        }

        inline u64 sampleMod(PRNG& prng, u64 modulus)
        {
            auto sample = prng.get<std::array<u64, 2>>();
            return reduce128Mod(sample[0], sample[1], modulus);
        }

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
            auto sumCount = checkedMul(depth, numTrees);
            auto sumBytes = checkedMul(sumCount, sizeof(std::array<block, 2>));
            auto leafFactor = 2 + 2 * static_cast<u64>(programPuncturedPoint);
            auto leafBytes = checkedMul(checkedMul(elementSize, numTrees), leafFactor);
            auto numBytes = checkedAdd(sumBytes, leafBytes);

            // allocate the buffer and partition them.
            buff.resize(checkedSize(numBytes));
            sums = span<std::array<block, 2>>((std::array<block, 2>*)buff.data(), sumCount);
            leaf = span<u8>((u8*)(sums.data() + sums.size()),
                leafBytes
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
                if (output.size() != checkedMul(domain, pntCount))
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
            ExpandTreeBuffer& alloc,
            std::vector<span<AlignedArray<block, 8>>>& levels,
            bool reuseLevel = true)
        {
            if (domainSize == 0)
                throw std::invalid_argument("Invalid PPRF expansion-tree domain. " LOCATION);
            auto depth = log2ceil(domainSize);
            if (depth >= 64)
                throw std::invalid_argument("Invalid PPRF expansion-tree domain. " LOCATION);
            levels.resize(depth + 1);

            if (reuseLevel)
            {
                auto secondLast = checkedRoundUpTo(checkedAdd(domainSize, 1) / 2, 2);
                auto size = checkedRoundUpTo(checkedAdd(domainSize, secondLast), 2);

                // we will allocate the last twoo levels of the tree. 
                // these levels will be used for the smaller levels as
                // well. We will alternate between the two.
                alloc.clear();
                auto blockCount = checkedMul(size, 8);
                alloc.resize(checkedSize(blockCount / 8));

                std::array<span<AlignedArray<block, 8>>, 2>  buffs;
                buffs[0] = { alloc.data(), secondLast };
                buffs[1] = { alloc.data() + secondLast, domainSize };

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
                    totalSize = checkedAdd(totalSize, checkedRoundUpTo(width, 2));
                }

                alloc.clear();
                auto blockCount = checkedMul(totalSize, 8);
                alloc.resize(checkedSize(blockCount / 8));
                span<AlignedArray<block, 8>> buff(alloc.data(), totalSize);

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

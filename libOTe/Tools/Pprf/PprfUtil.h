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

        // The native one-tree-at-a-time layout. Each tree is contiguous. Within
        // a tree, eight physical lanes are eight public subtrees. Invalid padded
        // leaves are omitted for non-power-of-two domains.
        ByPhysicalIndex,

        // Call the user's callback once per tree. Leaves use ByPhysicalIndex.
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

        inline u64 paddedDomain(u64 domain)
        {
            return u64{ 1 } << log2ceil(domain);
        }

        // Convert a logical leaf to its compact native index. The conceptual
        // padded tree is split into up to eight public subtrees. Physical order
        // visits one local leaf across the valid subtrees before the next local
        // leaf, while omitting padded leaves.
        inline u64 physicalLeafIndex(u64 domain, u64 logicalLeaf)
        {
            if (logicalLeaf >= domain)
                throw std::invalid_argument("PPRF logical leaf is outside the domain. " LOCATION);
            const auto padded = paddedDomain(domain);
            const auto laneCount = std::min<u64>(8, padded);
            const auto subtreeDomain = padded / laneCount;
            const auto fullLanes = domain / subtreeDomain;
            const auto partialLaneSize = domain % subtreeDomain;
            const auto lane = logicalLeaf / subtreeDomain;
            const auto localLeaf = logicalLeaf % subtreeDomain;
            return localLeaf * fullLanes +
                std::min(localLeaf, partialLaneSize) + lane;
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
            switch (oFormat)
            {
            case osuCrypto::PprfOutputFormat::ByLeafIndex:
            case osuCrypto::PprfOutputFormat::ByTreeIndex:
            case osuCrypto::PprfOutputFormat::ByPhysicalIndex:
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
            std::vector<span<AlignedArray<block, 8>>>& levels)
        {
            if (domainSize == 0)
                throw std::invalid_argument("Invalid PPRF expansion-tree domain. " LOCATION);
            const auto depth = log2ceil(domainSize);
            if (depth >= 64)
                throw std::invalid_argument("Invalid PPRF expansion-tree domain. " LOCATION);
            levels.resize(depth + 1);

            const auto secondLast =
                checkedRoundUpTo(checkedAdd(domainSize, 1) / 2, 2);
            const auto size =
                checkedRoundUpTo(checkedAdd(domainSize, secondLast), 2);

            // The largest two physical levels alternate as scratch for all
            // preceding levels.
            alloc.clear();
            alloc.resize(checkedSize(size));
            std::array<span<AlignedArray<block, 8>>, 2> buffers{
                span<AlignedArray<block, 8>>(alloc.data(), secondLast),
                span<AlignedArray<block, 8>>(alloc.data() + secondLast, domainSize)
            };

            levels.back() = buffers[1].subspan(0, domainSize);
            for (u64 i = levels.size() - 2, j = 0; i < levels.size(); --i, ++j)
            {
                auto width = divCeil(domainSize, u64{ 1 } << (depth - i));
                if (width > 1)
                    width = roundUpTo(width, 2);
                levels[i] = buffers[j & 1].subspan(0, width);
            }

            if (levels[0].size() != 1)
                throw RTE_LOC;
        }


    }

}

#pragma once
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Matrix.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Common/Aligned.h"
#include "cryptoTools/Common/Range.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "libOTe/Tools/Coproto.h"
#include "libOTe/Tools/SilentPprf.h"
#include "SubfieldPprf.h"
#include <array>
#include "libOTe/Tools/Subfield/Subfield.h"

namespace osuCrypto
{

    extern const std::array<AES, 2> gGgmAes;

    inline void allocateExpandTree(
        TreeAllocator& alloc,
        span<AlignedArray<block, 8>>& tree,
        std::vector<span<AlignedArray<block, 8>>>& levels)
    {
        tree = alloc.get();
        assert((u64)tree.data() % 32 == 0);
        levels[0] = tree.subspan(0, 1);
        auto rem = tree.subspan(2);
        for (auto i : rng(1ull, levels.size()))
        {
            levels[i] = rem.subspan(0, levels[i - 1].size() * 2);
            assert((u64)levels[i].data() % 32 == 0);
            rem = rem.subspan(levels[i].size());
        }
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
        bool programPuncturedPoint,
        std::vector<u8>& buff,
        span<std::array<std::array<block, 8>, 2>>& sums,
        span<u8>& leaf,
        CoeffCtx& ctx)
    {

        u64 elementSize = ctx.byteSize<F>();

        using SumType = std::array<std::array<block, 8>, 2>;
        // num of bytes they will take up.
        u64 numBytes =
            depth * sizeof(SumType) +  // each internal level of the tree has a sum
            elementSize * 8 * 2 +          // we must program 8 inactive F leaves
            elementSize * 8 * 2 * programPuncturedPoint; // if we are programing the active lead, then we have 8 more.

        // allocate the buffer and partition them.
        buff.resize(numBytes);
        sums = span<SumType>((SumType*)buff.data(), depth);
        leaf = span<u8>((u8*)(sums.data() + sums.size()),
            elementSize * 8 * 2 +
            elementSize * 8 * 2 * programPuncturedPoint
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

    template<
        typename F,
        typename G = F,
        typename CoeffCtx = DefaultCoeffCtx<F, G>
    >
    class SilentSubfieldPprfSender : public TimerAdapter {
    public:
        u64 mDomain = 0, mDepth = 0, mPntCount = 0;
        std::vector<F> mValue;
        TreeAllocator mTreeAlloc;
        Matrix<std::array<block, 2>> mBaseOTs;

        using VecF = typename CoeffCtx::template Vec<F>;
        using VecG = typename CoeffCtx::template Vec<G>;

        std::function<void(u64 treeIdx, VecF& leaf)> mOutputFn;


        SilentSubfieldPprfSender() = default;

        SilentSubfieldPprfSender(const SilentSubfieldPprfSender&) = delete;

        SilentSubfieldPprfSender(SilentSubfieldPprfSender&&) = delete;

        SilentSubfieldPprfSender(u64 domainSize, u64 pointCount) {
            configure(domainSize, pointCount);
        }

        void configure(u64 domainSize, u64 pointCount)
        {
            if (domainSize & 1)
                throw std::runtime_error("Pprf domain must be even. " LOCATION);
            if (domainSize < 4)
                throw std::runtime_error("Pprf domain must must be at least 4. " LOCATION);
            if (mPntCount % 8)
                throw std::runtime_error("pointCount must be a multiple of 8 (general case not impl). " LOCATION);

            mDomain = domainSize;
            mDepth = log2ceil(mDomain);
            mPntCount = pointCount;
            //mPntCount8 = roundUpTo(pointCount, 8);

            mBaseOTs.resize(0, 0);
        }


        // the number of base OTs that should be set.
        u64 baseOtCount() const {
            return mDepth * mPntCount;
        }

        // returns true if the base OTs are currently set.
        bool hasBaseOts() const {
            return mBaseOTs.size();
        }


        void setBase(span<const std::array<block, 2>> baseMessages) {
            if (baseOtCount() != static_cast<u64>(baseMessages.size()))
                throw RTE_LOC;

            mBaseOTs.resize(mPntCount, mDepth);
            for (u64 i = 0; i < static_cast<u64>(mBaseOTs.size()); ++i)
                mBaseOTs(i) = baseMessages[i];
        }

        //task<> expand(Socket& chls, span<const F> value, block seed, span <F> output, PprfOutputFormat oFormat,
        //    bool programPuncturedPoint, u64 numThreads) {
        //    MatrixView<F> o(output.data(), output.size(), 1);
        //    return expand(chls, value, seed, o, oFormat, programPuncturedPoint, numThreads);
        //}
        task<> expand(
            Socket& chl,
            const VecF& value,
            block seed,
            VecF& output,
            PprfOutputFormat oFormat,
            bool programPuncturedPoint,
            u64 numThreads,
            CoeffCtx ctx = {})
        {
            if (programPuncturedPoint)
                setValue(value);

            setTimePoint("SilentMultiPprfSender.start");

            validateExpandFormat(oFormat, output, mDomain, mPntCount);

            MC_BEGIN(task<>, this, numThreads, oFormat, &output, seed, &chl, programPuncturedPoint, ctx,
                treeIndex = u64{},
                tree = span<AlignedArray<block, 8>>{},
                levels = std::vector<span<AlignedArray<block, 8>> >{},
                leafIndex = u64{},
                leafLevelPtr = (VecF*)nullptr,
                leafLevel = VecF{},
                buff = std::vector<u8>{},
                encSums = span<std::array<std::array<block, 8>, 2>>{},
                leafMsgs = span<u8>{}
            );

            mTreeAlloc.reserve(numThreads, (1ull << mDepth) + 2);
            setTimePoint("SilentMultiPprfSender.reserve");

            levels.resize(mDepth);
            allocateExpandTree(mTreeAlloc, tree, levels);

            for (treeIndex = 0; treeIndex < mPntCount; treeIndex += 8)
            {
                // for interleaved format, the leaf level of the tree
                // is simply the output.
                if (oFormat == PprfOutputFormat::Interleaved)
                {
                    leafIndex = treeIndex * mDomain;
                    leafLevelPtr = &output;
                }
                else
                {
                    // we will use leaf level as a buffer before
                    // copying the result to the output.
                    leafIndex = 0;
                    ctx.resize(leafLevel, mDomain * 8);
                    leafLevelPtr = &leafLevel;
                }

                // allocate the send buffer and partition it.
                allocateExpandBuffer<F>(mDepth - 1, programPuncturedPoint, buff, encSums, leafMsgs, ctx);

                // exapnd the tree
                expandOne(seed, treeIndex, programPuncturedPoint, levels, *leafLevelPtr, leafIndex, encSums, leafMsgs, ctx);

                MC_AWAIT(chl.send(std::move(buff)));

                // if we aren't interleaved, we need to copy the
                // leaf layer to the output.
                if (oFormat != PprfOutputFormat::Interleaved)
                    copyOut<VecF, CoeffCtx>(leafLevel, output, mPntCount, treeIndex, oFormat, mOutputFn);

            }

            mBaseOTs = {};
            mTreeAlloc.del(tree);
            mTreeAlloc.clear();

            setTimePoint("SilentMultiPprfSender.de-alloc");

            MC_END();
        }

        void setValue(span<const F> value) {

            mValue.resize(mPntCount);

            if (value.size() == 1) {
                std::fill(mValue.begin(), mValue.end(), value[0]);
            }
            else {
                if ((u64)value.size() != mPntCount)
                    throw RTE_LOC;

                std::copy(value.begin(), value.end(), mValue.begin());
            }
        }

        void clear() {
            mBaseOTs.resize(0, 0);
            mDomain = 0;
            mDepth = 0;
            mPntCount = 0;
        }

        void expandOne(
            block aesSeed,
            u64 treeIdx,
            bool programPuncturedPoint,
            span<span<AlignedArray<block, 8>>> levels,
            VecF& leafLevel,
            const u64 leafOffset,
            span<std::array<std::array<block, 8>, 2>>  encSums,
            span<u8> leafMsgs,
            CoeffCtx ctx)
        {

            // the first level should be size 1, the root of the tree.
            // we will populate it with random seeds using aesSeed in counter mode
            // based on the tree index.
            assert(levels[0].size() == 1);
            mAesFixedKey.ecbEncCounterMode(aesSeed ^ block(treeIdx), levels[0][0]);

            assert(encSums.size() == mDepth - 1);

            // space for our sums of each level. Should always be less then
            // 24 levels... If not increase the limit or make it a vector.
            std::array<std::array<block, 8>, 2> sums;

            // use the optimized approach for intern nodes of the tree
            // For each level perform the following.
            for (u64 d = 0; d < mDepth - 1; ++d)
            {
                // clear the sums
                memset(&sums, 0, sizeof(sums));

                // The total number of parents in this level.
                auto width = divCeil(mDomain, 1ull << (mDepth - d));

                // The previous level of the GGM tree.
                auto parents = levels[d];

                // The next level of theGGM tree that we are populating.
                auto children = levels[d + 1];

                // For each child, populate the child by expanding the parent.
                for (u64 parentIdx = 0, childIdx = 0; parentIdx < width; ++parentIdx, childIdx += 2)
                {
                    // The value of the parent.
                    auto& parent = parents.data()[parentIdx];

                    auto& child0 = children.data()[childIdx];
                    auto& child1 = children.data()[childIdx + 1];
                    mAesFixedKey.ecbEncBlocks<8>(parent.data(), child1.data());

                    // inspired by the Expand Accumualte idea to
                    // use 
                    // 
                    // child0 = AES(parent) ^ parent
                    // child1 = AES(parent) + parent
                    //
                    // but instead we are a bit more conservative and
                    // compute 
                    //
                    // child0 = AES:Round(AES(parent),      parent)
                    //        = AES:Round(AES(parent), 0) ^ parent
                    // child1 =           AES(parent)     + parent
                    //
                    // That is, we applies an additional AES round function
                    // to the first child before XORing it with parent.
                    child0[0] = AES::roundEnc(child1[0], parent[0]);
                    child0[1] = AES::roundEnc(child1[1], parent[1]);
                    child0[2] = AES::roundEnc(child1[2], parent[2]);
                    child0[3] = AES::roundEnc(child1[3], parent[3]);
                    child0[4] = AES::roundEnc(child1[4], parent[4]);
                    child0[5] = AES::roundEnc(child1[5], parent[5]);
                    child0[6] = AES::roundEnc(child1[6], parent[6]);
                    child0[7] = AES::roundEnc(child1[7], parent[7]);

                    // Update the running sums for this level. We keep
                    // a left and right totals for each level.
                    sums[0][0] = sums[0][0] ^ child0[0];
                    sums[0][1] = sums[0][1] ^ child0[1];
                    sums[0][2] = sums[0][2] ^ child0[2];
                    sums[0][3] = sums[0][3] ^ child0[3];
                    sums[0][4] = sums[0][4] ^ child0[4];
                    sums[0][5] = sums[0][5] ^ child0[5];
                    sums[0][6] = sums[0][6] ^ child0[6];
                    sums[0][7] = sums[0][7] ^ child0[7];

                    // child1 = AES(parent) + parent
                    child1[0] = child1[0] + parent[0];
                    child1[1] = child1[1] + parent[1];
                    child1[2] = child1[2] + parent[2];
                    child1[3] = child1[3] + parent[3];
                    child1[4] = child1[4] + parent[4];
                    child1[5] = child1[5] + parent[5];
                    child1[6] = child1[6] + parent[6];
                    child1[7] = child1[7] + parent[7];

                    sums[1][0] = sums[1][0] ^ child1[0];
                    sums[1][1] = sums[1][1] ^ child1[1];
                    sums[1][2] = sums[1][2] ^ child1[2];
                    sums[1][3] = sums[1][3] ^ child1[3];
                    sums[1][4] = sums[1][4] ^ child1[4];
                    sums[1][5] = sums[1][5] ^ child1[5];
                    sums[1][6] = sums[1][6] ^ child1[6];
                    sums[1][7] = sums[1][7] ^ child1[7];

                }

                // encrypt the sums and write them to the output.
                for (u64 j = 0; j < 8; ++j)
                {
                    encSums[d][0][j] = sums[0][j] ^ mBaseOTs[treeIdx + j][mDepth - 1 - d][1];
                    encSums[d][1][j] = sums[1][j] ^ mBaseOTs[treeIdx + j][mDepth - 1 - d][0];
                }
            }


            auto d = mDepth - 1;

            // The previous level of the GGM tree.
            auto level0 = levels[d];

            // The total number of parents in this level.
            auto width = divCeil(mDomain, 1ull << (mDepth - d));

            // The next level of theGGM tree that we are populating.
            std::array<block, 8> child;

            // clear the sums
            std::array<CoeffCtx::template Vec<F>, 2> leafSums;
            ctx.resize(leafSums[0], 8);
            ctx.resize(leafSums[1], 8);
            ctx.zero(leafSums[0].begin(), leafSums[0].end());
            ctx.zero(leafSums[1].begin(), leafSums[1].end());

            // for the leaf nodes we need to hash both children.
            for (u64 parentIdx = 0, outIdx = leafOffset, childIdx = 0; parentIdx < width; ++parentIdx)
            {
                // The value of the parent.
                auto& parent = level0.data()[parentIdx];

                // The bit that indicates if we are on the left child (0)
                // or on the right child (1).
                for (u64 keep = 0; keep < 2; ++keep, ++childIdx, outIdx += 8)
                {
                    // The child that we will write in this iteration.

                    // Each parent is expanded into the left and right children
                    // using a different AES fixed-key. Therefore our OWF is:
                    //
                    //    H(x) = (AES(k0, x) + x) || (AES(k1, x) + x);
                    //
                    // where each half defines one of the children.
                    gGgmAes[keep].hashBlocks<8>(parent.data(), child.data());

                    ctx.fromBlock(leafLevel[outIdx + 0], child[0]);
                    ctx.fromBlock(leafLevel[outIdx + 1], child[1]);
                    ctx.fromBlock(leafLevel[outIdx + 2], child[2]);
                    ctx.fromBlock(leafLevel[outIdx + 3], child[3]);
                    ctx.fromBlock(leafLevel[outIdx + 4], child[4]);
                    ctx.fromBlock(leafLevel[outIdx + 5], child[5]);
                    ctx.fromBlock(leafLevel[outIdx + 6], child[6]);
                    ctx.fromBlock(leafLevel[outIdx + 7], child[7]);

                    // leafSum += child
                    auto& leafSum = leafSums[keep];
                    ctx.plus(leafSum[0], leafSum[0], leafLevel[outIdx + 0]);
                    ctx.plus(leafSum[1], leafSum[1], leafLevel[outIdx + 1]);
                    ctx.plus(leafSum[2], leafSum[2], leafLevel[outIdx + 2]);
                    ctx.plus(leafSum[3], leafSum[3], leafLevel[outIdx + 3]);
                    ctx.plus(leafSum[4], leafSum[4], leafLevel[outIdx + 4]);
                    ctx.plus(leafSum[5], leafSum[5], leafLevel[outIdx + 5]);
                    ctx.plus(leafSum[6], leafSum[6], leafLevel[outIdx + 6]);
                    ctx.plus(leafSum[7], leafSum[7], leafLevel[outIdx + 7]);
                }

            }

            if (programPuncturedPoint)
            {
                // For the leaf level, we are going to do something special.
                // The other party is currently missing both leaf children of
                // the active parent. Since this is the leaf level, we want
                // the inactive child to just be the normal value but the
                // active child should be the correct value XOR the delta.
                // This will be done by sending the sums and the sums plus
                // delta and ensure that they can only decrypt the correct ones.
                CoeffCtx::template Vec<F> leafOts;
                ctx.resize(leafOts, 2);
                PRNG otMasker;

                for (u64 j = 0; j < 8; ++j)
                {
                    // we will construct two OT strings. Let
                    // s0, s1 be the left and right child sums.
                    // 
                    // m0 = (s0      , s1 + val)
                    // m1 = (s0 + val, s1      )
                    //
                    // these will be encrypted by the OT keys 
                    for (u64 k = 0; k < 2; ++k)
                    {
                        if (k == 0)
                        {
                            // m0 = (s0, s1 + val)
                            ctx.copy(leafOts[0], leafSums[0][j]);
                            ctx.plus(leafOts[1], leafSums[1][j], mValue[treeIdx + j]);
                        }
                        else
                        {
                            // m1 = (s0+val, s1)
                            ctx.plus(leafOts[0], leafSums[0][j], mValue[treeIdx + j]);
                            ctx.copy(leafOts[1], leafSums[1][j]);
                        }

                        // copy m0 into the output buffer.
                        span<u8> buff = leafMsgs.subspan(0, 2 * ctx.byteSize<F>());
                        leafMsgs = leafMsgs.subspan(buff.size());
                        ctx.serialize(leafOts.begin(), leafOts.end(), buff.begin());

                        // encrypt the output buffer.
                        otMasker.SetSeed(mBaseOTs[treeIdx + j][0][1 ^ k], divCeil(buff.size(), sizeof(block)));
                        for (u64 i = 0; i < buff.size(); ++i)
                            buff[i] ^= otMasker.get<u8>();

                    }
                }
            }
            else
            {
                CoeffCtx::template Vec<F> leafOts;
                ctx.resize(leafOts, 1);
                PRNG otMasker;

                for (u64 j = 0; j < 8; ++j)
                {
                    for (u64 k = 0; k < 2; ++k)
                    {
                        // copy the sum k into the output buffer.
                        ctx.copy(leafOts[0], leafSums[k][j]);
                        span<u8> buff = leafMsgs.subspan(0, ctx.byteSize<F>());
                        leafMsgs = leafMsgs.subspan(buff.size());
                        ctx.serialize(leafOts.begin(), leafOts.end(), buff.begin());

                        // encrypt the output buffer.
                        otMasker.SetSeed(mBaseOTs[treeIdx + j][0][1 ^ k], divCeil(buff.size(), sizeof(block)));
                        for (u64 i = 0; i < buff.size(); ++i)
                            buff[i] ^= otMasker.get<u8>();

                    }
                }
            }

            assert(leafMsgs.size() == 0);
        }


    };


    template<
        typename F,
        typename G = F,
        typename CoeffCtx = DefaultCoeffCtx<F, G>
    >
    class SilentSubfieldPprfReceiver : public TimerAdapter
    {
    public:
        u64 mDomain = 0, mDepth = 0, mPntCount = 0;
        using VecF = typename CoeffCtx::template Vec<F>;
        using VecG = typename CoeffCtx::template Vec<G>;

        std::vector<u64> mPoints;

        Matrix<block> mBaseOTs;

        Matrix<u8> mBaseChoices;

        TreeAllocator mTreeAlloc;

        std::function<void(u64 treeIdx, VecF& leafs)> mOutputFn;

        SilentSubfieldPprfReceiver() = default;
        SilentSubfieldPprfReceiver(const SilentSubfieldPprfReceiver&) = delete;
        SilentSubfieldPprfReceiver(SilentSubfieldPprfReceiver&&) = delete;

        void configure(u64 domainSize, u64 pointCount)
        {
            if (domainSize & 1)
                throw std::runtime_error("Pprf domain must be even. " LOCATION);
            if (domainSize < 4)
                throw std::runtime_error("Pprf domain must must be at least 4. " LOCATION);
            if (mPntCount % 8)
                throw std::runtime_error("pointCount must be a multiple of 8 (general case not impl). " LOCATION);

            mDomain = domainSize;
            mDepth = log2ceil(mDomain);
            mPntCount = pointCount;

            mBaseOTs.resize(0, 0);
        }


        // this function sample mPntCount integers in the range
        // [0,domain) and returns these as the choice bits.
        BitVector sampleChoiceBits(PRNG& prng)
        {
            BitVector choices(mPntCount * mDepth);

            // The points are read in blocks of 8, so make sure that there is a
            // whole number of blocks.
            mBaseChoices.resize(mPntCount, mDepth);
            for (u64 i = 0; i < mPntCount; ++i)
            {
                u64 idx = prng.get<u64>() % mDomain;
                for (u64 j = 0; j < mDepth; ++j)
                    mBaseChoices(i, j) = *BitIterator((u8*)&idx, j);
            }

            for (u64 i = 0; i < mBaseChoices.size(); ++i)
            {
                choices[i] = mBaseChoices(i);
            }

            return choices;
        }

        // choices is in the same format as the output from sampleChoiceBits.
        void setChoiceBits(const BitVector& choices)
        {
            // Make sure we're given the right number of OTs.
            if (choices.size() != baseOtCount())
                throw RTE_LOC;

            mBaseChoices.resize(mPntCount, mDepth);
            for (u64 i = 0; i < mPntCount; ++i)
            {
                u64 idx = 0;
                for (u64 j = 0; j < mDepth; ++j)
                {
                    mBaseChoices(i, j) = choices[mDepth * i + j];
                    idx |= u64(choices[mDepth * i + j]) << j;
                }

                if (idx >= mDomain)
                    throw std::runtime_error("provided choice bits index outside of the domain." LOCATION);
            }
        }


        // the number of base OTs that should be set.
        u64 baseOtCount() const
        {
            return mDepth * mPntCount;
        }

        // returns true if the base OTs are currently set.
        bool hasBaseOts() const
        {
            return mBaseOTs.size();
        }


        void setBase(span<const block> baseMessages)
        {
            if (baseOtCount() != static_cast<u64>(baseMessages.size()))
                throw RTE_LOC;

            // The OTs are used in blocks of 8, so make sure that there is a whole
            // number of blocks.
            mBaseOTs.resize(roundUpTo(mPntCount, 8), mDepth);
            memcpy(mBaseOTs.data(), baseMessages.data(), baseMessages.size() * sizeof(block));
        }

        std::vector<u64> getPoints(PprfOutputFormat format)
        {
            std::vector<u64> pnts(mPntCount);
            getPoints(pnts, format);
            return pnts;
        }
        void getPoints(span<u64> points, PprfOutputFormat format)
        {
            if ((u64)points.size() != mPntCount)
                throw RTE_LOC;

            switch (format)
            {
            case PprfOutputFormat::ByLeafIndex:
            case PprfOutputFormat::ByTreeIndex:

                memset(points.data(), 0, points.size() * sizeof(u64));
                for (u64 j = 0; j < mPntCount; ++j)
                {
                    for (u64 k = 0; k < mDepth; ++k)
                        points[j] |= u64(mBaseChoices(j, k)) << k;

                    assert(points[j] < mDomain);
                }


                break;
            case PprfOutputFormat::Interleaved:
            case PprfOutputFormat::Callback:

                getPoints(points, PprfOutputFormat::ByLeafIndex);

                // in interleaved mode we generate 8 trees in a batch.
                // the i'th leaf of these 8 trees are next to eachother.
                for (u64 j = 0; j < points.size(); ++j)
                {
                    auto subTree = j % 8;
                    auto batch = j / 8;
                    points[j] =  (batch * mDomain + points[j]) * 8 + subTree;
                }

                //interleavedPoints(points, mDomain, format);

                break;
            default:
                throw RTE_LOC;
                break;
            }
        }

        // programPuncturedPoint says whether the sender is trying to program the
        // active child to be its correct value XOR delta. If it is not, the
        // active child will just take a random value.
        task<> expand(
            Socket& chl,
            VecF& output,
            PprfOutputFormat oFormat,
            bool programPuncturedPoint,
            u64 numThreads,
            CoeffCtx ctx = {})
        {
            validateExpandFormat(oFormat, output, mDomain, mPntCount);

            MC_BEGIN(task<>, this, oFormat, &output, &chl, programPuncturedPoint, ctx,
                treeIndex = u64{},
                tree = span<AlignedArray<block, 8>>{},
                levels = std::vector<span<AlignedArray<block, 8>>>{},
                leafIndex = u64{},
                leafLevelPtr = (VecF*)nullptr,
                leafLevel = VecF{},
                buff = std::vector<u8>{},
                encSums = span<std::array<std::array<block, 8>, 2>>{},
                leafMsgs = span<u8>{}
            );

            setTimePoint("SilentMultiPprfReceiver.start");
            mPoints.resize(roundUpTo(mPntCount, 8));
            getPoints(mPoints, PprfOutputFormat::ByLeafIndex);

            mTreeAlloc.reserve(1, (1ull << mDepth) + 2);
            setTimePoint("SilentMultiPprfSender.reserve");

            levels.resize(mDepth);
            allocateExpandTree(mDepth, mTreeAlloc, tree, levels);

            for (treeIndex = 0; treeIndex < mPntCount; treeIndex += 8)
            {
                // for interleaved format, the leaf level of the tree
                // is simply the output.
                if (oFormat == PprfOutputFormat::Interleaved)
                {
                    leafIndex = treeIndex * mDomain;
                    leafLevelPtr = &output;
                }
                else
                {
                    // we will use leaf level as a buffer before
                    // copying the result to the output.
                    leafIndex = 0;
                    ctx.resize(leafLevel, mDomain * 8);
                    leafLevelPtr = &leafLevel;
                }

                // allocate the send buffer and partition it.
                allocateExpandBuffer<F>(mDepth - 1, programPuncturedPoint, buff, encSums, leafMsgs, ctx);

                MC_AWAIT(chl.recv(buff));

                // exapnd the tree
                expandOne(treeIndex, programPuncturedPoint, levels, *leafLevelPtr, leafIndex, encSums, leafMsgs, ctx);

                // if we aren't interleaved, we need to copy the
                // leaf layer to the output.
                if (oFormat != PprfOutputFormat::Interleaved)
                    copyOut<VecF, CoeffCtx>(leafLevel, output, mPntCount, treeIndex, oFormat, mOutputFn);
            }

            setTimePoint("SilentMultiPprfReceiver.join");

            mBaseOTs = {};
            mTreeAlloc.del(tree);
            mTreeAlloc.clear();

            setTimePoint("SilentMultiPprfReceiver.de-alloc");

            MC_END();
        }

        void clear()
        {
            mBaseOTs.resize(0, 0);
            mBaseChoices.resize(0, 0);
            mDomain = 0;
            mDepth = 0;
            mPntCount = 0;
        }

        //treeIndex, programPuncturedPoint, levels, *leafLevelPtr, leafIndex, encSums, leafMsgs
        void expandOne(
            u64 treeIdx,
            bool programPuncturedPoint,
            span<span<AlignedArray<block, 8>>> levels,
            VecF& leafLevel,
            const u64 outputOffset,
            span<std::array<std::array<block, 8>, 2>> theirSums,
            span<u8> leafMsg,
            CoeffCtx ctx)
        {
            // We will process 8 trees at a time.

            // special case for the first level.
            auto l1 = levels[1];
            for (u64 i = 0; i < 8; ++i)
            {
                // For the non-active path, set the child of the root node
                // as the OT message XOR'ed with the correction sum.

                int active = mBaseChoices[i + treeIdx].back();
                l1[active ^ 1][i] = mBaseOTs[i + treeIdx].back() ^ theirSums[0][active ^ 1][i];
                l1[active][i] = ZeroBlock;
                //if (!i)
                //    std::cout << " unmask " 
                //    << mBaseOTs[i + treeIdx].back() << " ^ "
                //    << theirSums[0][active ^ 1][i] << " = "
                //    << l1[active ^ 1][i] << std::endl;

            }

            // space for our sums of each level.
            std::array<std::array<block, 8>, 2> mySums;

            // this will be the value of both children of active an parent
            // before the active child is updated. We will need to subtract 
            // this value as the main loop does not distinguish active parents.
            std::array<block, 2> inactiveChildValues;
            inactiveChildValues[0] = AES::roundEnc(mAesFixedKey.ecbEncBlock(ZeroBlock), ZeroBlock);
            inactiveChildValues[1] = mAesFixedKey.ecbEncBlock(ZeroBlock);

            // For all other levels, expand the GGM tree and add in
            // the correction along the active path.
            for (u64 d = 1; d < mDepth - 1; ++d)
            {
                // initialized the sums with inactiveChildValue so that
                // it will cancel when we expand the actual inactive child.
                std::fill(mySums[0].begin(), mySums[0].end(), inactiveChildValues[0]);
                std::fill(mySums[1].begin(), mySums[1].end(), inactiveChildValues[1]);

                // We will iterate over each node on this level and
                // expand it into it's two children. Note that the
                // active node will also be expanded. Later we will just
                // overwrite whatever the value was. This is an optimization.
                auto width = divCeil(mDomain, 1ull << (mDepth - d));

                // The already constructed level. Only missing the
                // GGM tree node value along the active path.
                auto level0 = levels[d];

                // The next level that we want to construct.
                auto level1 = levels[d + 1];

                for (u64 parentIdx = 0, childIdx = 0; parentIdx < width; ++parentIdx, childIdx += 2)
                {
                    // The value of the parent.
                    auto parent = level0[parentIdx];

                    auto& child0 = level1.data()[childIdx];
                    auto& child1 = level1.data()[childIdx + 1];
                    mAesFixedKey.ecbEncBlocks<8>(parent.data(), child1.data());

                    // inspired by the Expand Accumualte idea to
                    // use 
                    // 
                    // child0 = AES(parent) ^ parent
                    // child1 = AES(parent) + parent
                    //
                    // but instead we are a bit more conservative and
                    // compute 
                    //
                    // child0 = AES:Round(AES(parent),      parent)
                    //        = AES:Round(AES(parent), 0) ^ parent
                    // child1 =           AES(parent)     + parent
                    //
                    // That is, we applies an additional AES round function
                    // to the first child before XORing it with parent.
                    child0[0] = AES::roundEnc(child1[0], parent[0]);
                    child0[1] = AES::roundEnc(child1[1], parent[1]);
                    child0[2] = AES::roundEnc(child1[2], parent[2]);
                    child0[3] = AES::roundEnc(child1[3], parent[3]);
                    child0[4] = AES::roundEnc(child1[4], parent[4]);
                    child0[5] = AES::roundEnc(child1[5], parent[5]);
                    child0[6] = AES::roundEnc(child1[6], parent[6]);
                    child0[7] = AES::roundEnc(child1[7], parent[7]);

                    // Update the running sums for this level. We keep
                    // a left and right totals for each level. Note that
                    // we are actually XOR in the incorrect value of the
                    // children of the active parent but this will cancel 
                    // with inactiveChildValue thats already there.
                    mySums[0][0] = mySums[0][0] ^ child0[0];
                    mySums[0][1] = mySums[0][1] ^ child0[1];
                    mySums[0][2] = mySums[0][2] ^ child0[2];
                    mySums[0][3] = mySums[0][3] ^ child0[3];
                    mySums[0][4] = mySums[0][4] ^ child0[4];
                    mySums[0][5] = mySums[0][5] ^ child0[5];
                    mySums[0][6] = mySums[0][6] ^ child0[6];
                    mySums[0][7] = mySums[0][7] ^ child0[7];

                    // child1 = AES(parent) + parent
                    child1[0] = child1[0] + parent[0];
                    child1[1] = child1[1] + parent[1];
                    child1[2] = child1[2] + parent[2];
                    child1[3] = child1[3] + parent[3];
                    child1[4] = child1[4] + parent[4];
                    child1[5] = child1[5] + parent[5];
                    child1[6] = child1[6] + parent[6];
                    child1[7] = child1[7] + parent[7];

                    mySums[1][0] = mySums[1][0] ^ child1[0];
                    mySums[1][1] = mySums[1][1] ^ child1[1];
                    mySums[1][2] = mySums[1][2] ^ child1[2];
                    mySums[1][3] = mySums[1][3] ^ child1[3];
                    mySums[1][4] = mySums[1][4] ^ child1[4];
                    mySums[1][5] = mySums[1][5] ^ child1[5];
                    mySums[1][6] = mySums[1][6] ^ child1[6];
                    mySums[1][7] = mySums[1][7] ^ child1[7];

                }


                // we have to update the non-active child of the active parent.
                for (u64 i = 0; i < 8; ++i)
                {
                    // the index of the leaf node that is active.
                    auto leafIdx = mPoints[i + treeIdx];

                    // The index of the active (missing) child node.
                    auto missingChildIdx = leafIdx >> (mDepth - 1 - d);

                    // The index of the active child node sibling.
                    auto siblingIdx = missingChildIdx ^ 1;

                    // The indicator as to the left or right child is inactive
                    auto notAi = siblingIdx & 1;

                    // our sums & OTs cancel and we are leaf with the 
                    // correct value for the inactive child.
                    level1[siblingIdx][i] =
                        theirSums[d][notAi][i] ^
                        mySums[notAi][i] ^
                        mBaseOTs[i + treeIdx][mDepth - 1 - d];

                    // we have to set the active child to zero so 
                    // the next children are predictable.
                    level1[missingChildIdx][i] = ZeroBlock;
                }
            }


            auto d = mDepth - 1;
            // The already constructed level. Only missing the
            // GGM tree node value along the active path.
            auto level0 = levels[d];

            // The next level of theGGM tree that we are populating.
            std::array<block, 8> child;

            // We will iterate over each node on this level and
            // expand it into it's two children. Note that the
            // active node will also be expanded. Later we will just
            // overwrite whatever the value was. This is an optimization.
            auto width = divCeil(mDomain, 1ull << (mDepth - d));

            // We change the hash function for the leaf so lets update  
            // inactiveChildValues to use the new hash and subtract
            // these from the leafSums
            CoeffCtx::template Vec<F> temp;
            ctx.resize(temp, 2);
            std::array<CoeffCtx::template Vec<F>, 2> leafSums;
            for (u64 k = 0; k < 2; ++k)
            {
                inactiveChildValues[k] = gGgmAes[k].hashBlock(ZeroBlock);
                ctx.fromBlock(temp[k], inactiveChildValues[k]);



                // leafSum = -inactiveChildValues
                ctx.resize(leafSums[k], 8);
                ctx.zero(leafSums[k].begin(), leafSums[k].end());
                ctx.minus(leafSums[k][0], leafSums[k][0], temp[k]);
                for (u64 i = 1; i < 8; ++i)
                    ctx.copy(leafSums[k][i], leafSums[k][0]);
            }

            // for leaf nodes both children should be hashed.
            for (u64 parentIdx = 0, childIdx = 0, outputIdx = outputOffset; parentIdx < width; ++parentIdx)
            {
                // The value of the parent.
                auto parent = level0[parentIdx];

                for (u64 keep = 0; keep < 2; ++keep, ++childIdx, outputIdx += 8)
                {
                    // Each parent is expanded into the left and right children
                    // using a different AES fixed-key. Therefore our OWF is:
                    //
                    //    H(x) = (AES(k0, x) + x) || (AES(k1, x) + x);
                    //
                    // where each half defines one of the children.
                    gGgmAes[keep].hashBlocks<8>(parent.data(), child.data());

                    ctx.fromBlock(leafLevel[outputIdx + 0], child[0]);
                    ctx.fromBlock(leafLevel[outputIdx + 1], child[1]);
                    ctx.fromBlock(leafLevel[outputIdx + 2], child[2]);
                    ctx.fromBlock(leafLevel[outputIdx + 3], child[3]);
                    ctx.fromBlock(leafLevel[outputIdx + 4], child[4]);
                    ctx.fromBlock(leafLevel[outputIdx + 5], child[5]);
                    ctx.fromBlock(leafLevel[outputIdx + 6], child[6]);
                    ctx.fromBlock(leafLevel[outputIdx + 7], child[7]);



                    auto& leafSum = leafSums[keep];
                    ctx.plus(leafSum[0], leafSum[0], leafLevel[outputIdx + 0]);
                    ctx.plus(leafSum[1], leafSum[1], leafLevel[outputIdx + 1]);
                    ctx.plus(leafSum[2], leafSum[2], leafLevel[outputIdx + 2]);
                    ctx.plus(leafSum[3], leafSum[3], leafLevel[outputIdx + 3]);
                    ctx.plus(leafSum[4], leafSum[4], leafLevel[outputIdx + 4]);
                    ctx.plus(leafSum[5], leafSum[5], leafLevel[outputIdx + 5]);
                    ctx.plus(leafSum[6], leafSum[6], leafLevel[outputIdx + 6]);
                    ctx.plus(leafSum[7], leafSum[7], leafLevel[outputIdx + 7]);
                }
            }

            // leaf level.
            if (programPuncturedPoint)
            {
                // Now processes the leaf level. This one is special
                // because we must XOR in the correction value as
                // before but we must also fixed the child value for
                // the active child. To do this, we will receive 4
                // values. Two for each case (left active or right active).
                //timer.setTimePoint("recv.recvleaf");
                VecF leafOts;
                ctx.resize(leafOts, 2);
                PRNG otMasker;

                for (u64 j = 0; j < 8; ++j)
                {

                    // The index of the child on the active path.
                    auto activeChildIdx = mPoints[j + treeIdx];

                    // The index of the other (inactive) child.
                    auto inactiveChildIdx = activeChildIdx ^ 1;

                    // The indicator as to the left or right child is inactive
                    auto notAi = inactiveChildIdx & 1;

                    // offset to the first or second ot message, based on the one we want
                    auto offset = CoeffCtx::template byteSize<F>() * 2 * notAi;


                    // decrypt the ot string
                    span<u8> buff = leafMsg.subspan(offset, ctx.byteSize<F>() * 2);
                    leafMsg = leafMsg.subspan(buff.size() * 2);
                    otMasker.SetSeed(mBaseOTs[j + treeIdx][0], divCeil(buff.size(), sizeof(block)));
                    for (u64 i = 0; i < buff.size(); ++i)
                        buff[i] ^= otMasker.get<u8>();

                    ctx.deserialize(buff.begin(), buff.end(), leafOts.begin());

                    auto out0 = (activeChildIdx & ~1ull) * 8 + j + outputOffset;
                    auto out1 = (activeChildIdx | 1ull) * 8 + j + outputOffset;

                    ctx.minus(leafLevel[out0], leafOts[0], leafSums[0][j]);
                    ctx.minus(leafLevel[out1], leafOts[1], leafSums[1][j]);
                }
            }
            else
            {
                VecF leafOts;
                ctx.resize(leafOts, 1);
                PRNG otMasker;

                for (u64 j = 0; j < 8; ++j)
                {
                    // The index of the child on the active path.
                    auto activeChildIdx = mPoints[j + treeIdx];

                    // The index of the other (inactive) child.
                    auto inactiveChildIdx = activeChildIdx ^ 1;

                    // The indicator as to the left or right child is inactive
                    auto notAi = inactiveChildIdx & 1;

                    // offset to the first or second ot message, based on the one we want
                    auto offset = CoeffCtx::template byteSize<F>() * notAi;

                    // decrypt the ot string
                    span<u8> buff = leafMsg.subspan(offset, ctx.byteSize<F>());
                    leafMsg = leafMsg.subspan(buff.size() * 2);
                    otMasker.SetSeed(mBaseOTs[j + treeIdx][0], divCeil(buff.size(), sizeof(block)));
                    for (u64 i = 0; i < buff.size(); ++i)
                        buff[i] ^= otMasker.get<u8>();

                    ctx.deserialize(buff.begin(), buff.end(), leafOts.begin());

                    std::array<u64, 2> out{
                        (activeChildIdx & ~1ull) * 8 + j + outputOffset,
                        (activeChildIdx | 1ull) * 8 + j + outputOffset
                    };

                    auto keep = leafLevel.begin() + out[notAi];
                    auto zero = leafLevel.begin() + out[notAi ^ 1];

                    ctx.minus(*keep, leafOts[0], leafSums[notAi][j]);
                    ctx.zero(zero, zero + 1);
                }
            }
        }
    };
}
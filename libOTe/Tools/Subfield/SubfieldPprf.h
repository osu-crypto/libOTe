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

namespace osuCrypto::Subfield
{
    template<typename F>
    void copyOut(
        span<AlignedArray<F, 8>> lvl,
        MatrixView<F> output,
        u64 totalTrees,
        u64 tIdx,
        PprfOutputFormat oFormat,
        std::function<void(u64 treeIdx, span<AlignedArray<F, 8>> lvl)>& callback)
    {

        if (oFormat == PprfOutputFormat::InterleavedTransposed)
        {
            // not having an even (8) number of trees is not supported.
            if (totalTrees % 8)
                throw RTE_LOC;
            if (lvl.size() % 16)
                throw RTE_LOC;

            //
            //auto rowsPer = 16;
            //auto step = lvl.size()

            //auto sectionSize =

            if (lvl.size() < 16)
                throw RTE_LOC;


            auto setIdx = tIdx / 8;
            auto blocksPerSet = lvl.size() * 8 / 128;



            auto numSets = totalTrees / 8;
            auto begin = setIdx;
            auto step = numSets;

            if (oFormat == PprfOutputFormat::InterleavedTransposed)
            {
                // todo
                throw RTE_LOC;
                // auto end = std::min<u64>(begin + step * blocksPerSet, output.cols());

                // for (u64 i = begin, k = 0; i < end; i += step, ++k)
                // {
                //     auto& io = *(std::array<block, 128>*)(&lvl[k * 16]);
                //     transpose128(io.data());
                //     for (u64 j = 0; j < 128; ++j)
                //         output(j, i) = io[j];
                // }
            }
            else
            {
                // no op
            }


        }
        else if (oFormat == PprfOutputFormat::Plain)
        {

            auto curSize = std::min<u64>(totalTrees - tIdx, 8);
            if (curSize == 8)
            {

                for (u64 i = 0; i < output.rows(); ++i)
                {
                    auto oi = output[i].subspan(tIdx, 8);
                    auto& ii = lvl[i];
                    oi[0] = ii[0];
                    oi[1] = ii[1];
                    oi[2] = ii[2];
                    oi[3] = ii[3];
                    oi[4] = ii[4];
                    oi[5] = ii[5];
                    oi[6] = ii[6];
                    oi[7] = ii[7];
                }
            }
            else
            {
                for (u64 i = 0; i < output.rows(); ++i)
                {
                    auto oi = output[i].subspan(tIdx, curSize);
                    auto& ii = lvl[i];
                    for (u64 j = 0; j < curSize; ++j)
                        oi[j] = ii[j];
                }
            }

        }
        else if (oFormat == PprfOutputFormat::BlockTransposed)
        {

            auto curSize = std::min<u64>(totalTrees - tIdx, 8);
            if (curSize == 8)
            {
                for (u64 i = 0; i < output.cols(); ++i)
                {
                    auto& ii = lvl[i];
                    output(tIdx + 0, i) = ii[0];
                    output(tIdx + 1, i) = ii[1];
                    output(tIdx + 2, i) = ii[2];
                    output(tIdx + 3, i) = ii[3];
                    output(tIdx + 4, i) = ii[4];
                    output(tIdx + 5, i) = ii[5];
                    output(tIdx + 6, i) = ii[6];
                    output(tIdx + 7, i) = ii[7];
                }
            }
            else
            {
                for (u64 i = 0; i < output.cols(); ++i)
                {
                    auto& ii = lvl[i];
                    for (u64 j = 0; j < curSize; ++j)
                        output(tIdx + j, i) = ii[j];
                }
            }

        }
        else if (oFormat == PprfOutputFormat::Interleaved)
        {
            // no op
        }
        else if (oFormat == PprfOutputFormat::Callback)
            callback(tIdx, lvl);
        else
            throw RTE_LOC;
    }

    template<typename TypeTrait>
    class SilentSubfieldPprfSender : public TimerAdapter
    {
    public:
        using F = typename TypeTrait::F;
        u64 mDomain = 0, mDepth = 0, mPntCount = 0;
        std::vector<typename TypeTrait::F> mValue;
        bool mPrint = false;
        TreeAllocator mTreeAlloc;
        Matrix<std::array<block, 2>> mBaseOTs;
        
        std::function<void(u64 treeIdx, span<AlignedArray<F, 8>>)> mOutputFn;


        SilentSubfieldPprfSender() = default;
        SilentSubfieldPprfSender(const SilentSubfieldPprfSender&) = delete;
        SilentSubfieldPprfSender(SilentSubfieldPprfSender&&) = delete;

        SilentSubfieldPprfSender(u64 domainSize, u64 pointCount)
        {
            configure(domainSize, pointCount);
        }

        void configure(u64 domainSize, u64 pointCount)
        {
            mDomain = domainSize;
            mDepth = log2ceil(mDomain);
            mPntCount = pointCount;
            //mPntCount8 = roundUpTo(pointCount, 8);

            mBaseOTs.resize(0, 0);
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


        void setBase(span<const std::array<block, 2>> baseMessages) {
            if (baseOtCount() != static_cast<u64>(baseMessages.size()))
                throw RTE_LOC;

            mBaseOTs.resize(mPntCount, mDepth);
            for (u64 i = 0; i < static_cast<u64>(mBaseOTs.size()); ++i)
                mBaseOTs(i) = baseMessages[i];
        }

        task<> expand(Socket& chls, span<const F> value, PRNG& prng, span<F> output, PprfOutputFormat oFormat, bool activeChildXorDelta, u64 numThreads)
        {
            MatrixView<F> o(output.data(), output.size(), 1);
            return expand(chls, value, prng, o, oFormat, activeChildXorDelta, numThreads);
        }

        task<> expand(
            Socket& chl, 
            span<const F> value,
            PRNG& prng, 
            MatrixView<F> output, 
            PprfOutputFormat oFormat,
            bool activeChildXorDelta,
            u64 numThreads)
        {
            if (activeChildXorDelta)
                setValue(value);
            setTimePoint("SilentMultiPprfSender.start");
            //gTimer.setTimePoint("send.enter");



            if (oFormat == PprfOutputFormat::Plain)
            {
                if (output.rows() != mDomain)
                    throw RTE_LOC;

                if (output.cols() != mPntCount)
                    throw RTE_LOC;
            }
            else if (oFormat == PprfOutputFormat::BlockTransposed)
            {
                if (output.cols() != mDomain)
                    throw RTE_LOC;

                if (output.rows() != mPntCount)
                    throw RTE_LOC;
            }
            else if (oFormat == PprfOutputFormat::InterleavedTransposed)
            {
                if (output.rows() != 128)
                    throw RTE_LOC;

                //if (output.cols() > (mDomain * mPntCount + 127) / 128)
                //    throw RTE_LOC;

                if (mPntCount & 7)
                    throw RTE_LOC;
            }
            else if
                (oFormat == PprfOutputFormat::Interleaved)
            {
                if (output.cols() != 1)
                    throw RTE_LOC;
                if (mDomain & 1)
                    throw RTE_LOC;

                auto rows = output.rows();
                if (rows > (mDomain * mPntCount) ||
                    rows / 128 != (mDomain * mPntCount) / 128)
                    throw RTE_LOC;
                if (mPntCount & 7)
                    throw RTE_LOC;
            }
            else if (oFormat == PprfOutputFormat::Callback)
            {
                if (mDomain & 1)
                    throw RTE_LOC;
                if (mPntCount & 7)
                    throw RTE_LOC;
            }
            else
            {
                throw RTE_LOC;
            }


            MC_BEGIN(task<>, this, numThreads, oFormat, output, &prng, &chl, activeChildXorDelta,
                i = u64{},
                dd = u64{}
            );


            if (oFormat == PprfOutputFormat::Callback && numThreads > 1)
                throw RTE_LOC;

            dd = mDepth + (oFormat == PprfOutputFormat::Interleaved ? 0 : 1);
            mTreeAlloc.reserve(numThreads, (1ull << (dd + 1)) + (32 * (dd+1)));
            setTimePoint("SilentMultiPprfSender.reserve");

            mExps.clear(); mExps.reserve(divCeil(mPntCount, 8));
            for (i = 0; i < mPntCount; i += 8)
            {
                mExps.emplace_back(*this, prng.get(), i, oFormat, output, activeChildXorDelta, chl.fork());
                mExps.back().mFuture = macoro::make_eager(mExps.back().run());
                //MC_AWAIT(mExps.back().run());
            }

            for (i = 0; i < mExps.size(); ++i)
                MC_AWAIT(mExps[i].mFuture);

            mExps.clear();
            setTimePoint("SilentMultiPprfSender.join");

            mBaseOTs = {};
            //mTreeAlloc.clear();
            setTimePoint("SilentMultiPprfSender.de-alloc");

            MC_END();


        }

        void setValue(span<const F> value)
        {

            mValue.resize(mPntCount);

            if (value.size() == 1)
            {
                std::fill(mValue.begin(), mValue.end(), value[0]);
            }
            else
            {
                if ((u64)value.size() != mPntCount)
                    throw RTE_LOC;

                std::copy(value.begin(), value.end(), mValue.begin());
            }
        }

        void clear()
        {
            mBaseOTs.resize(0, 0);
            mDomain = 0;
            mDepth = 0;
            mPntCount = 0;
        }

        struct Expander
        {
            SilentSubfieldPprfSender& pprf;
            Socket chl;
            std::array<AES, 2> aes;
            PRNG prng;
            u64 dd, treeIdx, min, d;
            bool mActiveChildXorDelta = true;

            macoro::eager_task<void> mFuture;
            std::vector<span<AlignedArray<block,8>>> mLevels;

            //std::unique_ptr<block[]> uPtr_;

            // tree will hold the full GGM tree. Note that there are 8 
            // indepenendent trees that are being processed together. 
            // The trees are flattenned to that the children of j are
            // located at 2*j  and 2*j+1. 
            span<AlignedArray<block, 8>> tree;

            // sums will hold the left and right GGM tree sums
            // for each level. For example sums[0][i][5]  will
            // hold the sum of the left children for level i of 
            // the 5th tree. 
            std::array<std::vector<std::array<block, 8>>, 2> sums;
            // sums for the last level
            std::array<std::array<F, 8>, 2> lastSums;
            std::vector<std::array<F, 4>> lastOts;

            PprfOutputFormat oFormat;

            MatrixView<F> output;

            // The number of real trees for this iteration.
            // Returns the i'th level of the current 8 trees. The 
            // children of node j on level i are located at 2*j and
            // 2*j+1  on level i+1. 
            span<AlignedArray<block, 8>> getLevel(u64 i, u64 g)
            {
                return mLevels[i];
            };

            span<AlignedArray<F, 8>> getLastLevel(u64 i, u64 g) {
                if (oFormat == PprfOutputFormat::Interleaved && i == pprf.mDepth)
                {
                    auto b = (AlignedArray<F, 8>*)output.data();
                    auto forest = g / 8;
                    assert(g % 8 == 0);
                    b += forest * pprf.mDomain;
                    return span<AlignedArray<F, 8>>(b, pprf.mDomain);
                }

              throw RTE_LOC;
            }

            Expander(SilentSubfieldPprfSender& p, block seed, u64 treeIdx_,
                PprfOutputFormat of, MatrixView<F>o, bool activeChildXorDelta, Socket&& s)
                : pprf(p)
                , chl(std::move(s))
                , mActiveChildXorDelta(activeChildXorDelta)
            {
                treeIdx = treeIdx_;
                assert((treeIdx & 7) == 0);
                output = o;
                oFormat = of;
                // A public PRF/PRG that we will use for deriving the GGM tree.
                aes[0].setKey(toBlock(3242342));
                aes[1].setKey(toBlock(8993849));
                prng.SetSeed(seed);
                dd = pprf.mDepth + (oFormat == PprfOutputFormat::Interleaved ? 0 : 1);
            }

            task<> run()
            {
                MC_BEGIN(task<>, this);


                #ifdef DEBUG_PRINT_PPRF
                        chl.asyncSendCopy(mValue);
                #endif
                // pprf.setTimePoint("SilentMultiPprfSender.begin " + std::to_string(treeIdx));
                {
                    tree = pprf.mTreeAlloc.get();
                    assert(tree.size() >= 1ull << (dd));
                    assert((u64)tree.data() % 32 == 0);
                    mLevels.resize(dd+1);
                    mLevels[0] = tree.subspan(0, 1);
                    auto rem = tree.subspan(mLevels[0].size());
                    for (u64 i = 1; i < dd + 1; i++)
                    {
                        while ((u64)rem.data() % 32)
                            rem = rem.subspan(1);

                        mLevels[i] = rem.subspan(0, mLevels[i - 1].size() * 2);
                        rem = rem.subspan(mLevels[i].size());
                    }
                }
                // pprf.setTimePoint("SilentMultiPprfSender.alloc " + std::to_string(treeIdx));

                // This thread will process 8 trees at a time. It will interlace
                // the sets of trees are processed with the other threads. 
                {
                  memset(lastSums[0].data(), 0, lastSums[0].size() * sizeof(F));
                  memset(lastSums[1].data(), 0, lastSums[1].size() * sizeof(F));

                    // The number of real trees for this iteration.
                    min = std::min<u64>(8, pprf.mPntCount - treeIdx);
                    //gTimer.setTimePoint("send.start" + std::to_string(treeIdx));

                    // Populate the zeroth level of the GGM tree with random seeds.
                    prng.get(getLevel(0, treeIdx));

                    // Allocate space for our sums of each level.
                    sums[0].resize(pprf.mDepth);
                    sums[1].resize(pprf.mDepth);

                    // For each level perform the following.
                    for (u64 d = 0; d < pprf.mDepth; ++d)
                    {
                        // The previous level of the GGM tree.
                        auto level0 = getLevel(d, treeIdx);

                        // The next level of theGGM tree that we are populating.
                        auto level1 = getLevel(d + 1, treeIdx);

                        // The total number of children in this level.
                        auto width = static_cast<u64>(level1.size());

                        // For each child, populate the child by expanding the parent.
                        for (u64 childIdx = 0; childIdx < width; )
                        {
                            // Index of the parent in the previous level.
                            auto parentIdx = childIdx >> 1;

                            // The value of the parent.
                            auto& parent = level0[parentIdx];

                            // The bit that indicates if we are on the left child (0)
                            // or on the right child (1).
                            for (u64 keep = 0; keep < 2; ++keep, ++childIdx)
                            {
                                // The child that we will write in this iteration.
                                auto& child = level1[childIdx];

                                // The sum that this child node belongs to.
                                auto& sum = sums[keep][d];

                                // Each parent is expanded into the left and right children 
                                // using a different AES fixed-key. Therefore our OWF is:
                                //
                                //    H(x) = (AES(k0, x) + x) || (AES(k1, x) + x);
                                //
                                // where each half defines one of the children.
                                aes[keep].template hashBlocks<8>(parent.data(), child.data());

                                if (d < pprf.mDepth - 1) {
                                    // for intermediate levels, same as before
                                    // Update the running sums for this level. We keep 
                                    // a left and right totals for each level.
                                    sum[0] = sum[0] ^ child[0];
                                    sum[1] = sum[1] ^ child[1];
                                    sum[2] = sum[2] ^ child[2];
                                    sum[3] = sum[3] ^ child[3];
                                    sum[4] = sum[4] ^ child[4];
                                    sum[5] = sum[5] ^ child[5];
                                    sum[6] = sum[6] ^ child[6];
                                    sum[7] = sum[7] ^ child[7];
                                } else {
                                    if (getLastLevel(pprf.mDepth, treeIdx).size() <= childIdx) {
                                        childIdx = width;
                                        break;
                                    }
                                    auto& realChild = getLastLevel(pprf.mDepth, treeIdx)[childIdx];
                                    auto& lastSum = lastSums[keep];
                                    realChild[0] = TypeTrait::fromBlock(child[0]);
                                    lastSum[0] = TypeTrait::plus(lastSum[0], realChild[0]);
                                    realChild[1] = TypeTrait::fromBlock(child[1]);
                                    lastSum[1] = TypeTrait::plus(lastSum[1], realChild[1]);
                                    realChild[2] = TypeTrait::fromBlock(child[2]);
                                    lastSum[2] = TypeTrait::plus(lastSum[2], realChild[2]);
                                    realChild[3] = TypeTrait::fromBlock(child[3]);
                                    lastSum[3] = TypeTrait::plus(lastSum[3], realChild[3]);
                                    realChild[4] = TypeTrait::fromBlock(child[4]);
                                    lastSum[4] = TypeTrait::plus(lastSum[4], realChild[4]);
                                    realChild[5] = TypeTrait::fromBlock(child[5]);
                                    lastSum[5] = TypeTrait::plus(lastSum[5], realChild[5]);
                                    realChild[6] = TypeTrait::fromBlock(child[6]);
                                    lastSum[6] = TypeTrait::plus(lastSum[6], realChild[6]);
                                    realChild[7] = TypeTrait::fromBlock(child[7]);
                                    lastSum[7] = TypeTrait::plus(lastSum[7], realChild[7]);
                                }
                            }
                        }
                    }


        #ifdef DEBUG_PRINT_PPRF
                    // If we are debugging, then send over the full tree 
                    // to make sure its correct on the other side.
                    chl.asyncSendCopy(tree);
        #endif

                    // For all but the last level, mask the sums with the
                    // OT strings and send them over. 
                    for (u64 d = 0; d < pprf.mDepth - mActiveChildXorDelta; ++d)
                    {
                        for (u64 j = 0; j < min; ++j)
                        {
        #ifdef DEBUG_PRINT_PPRF
                            if (mPrint)
                            {
                                std::cout << "c[" << treeIdx + j << "][" << d << "][0] " << sums[0][d][j] << " " << mBaseOTs[treeIdx + j][d][0] << std::endl;;
                                std::cout << "c[" << treeIdx + j << "][" << d << "][1] " << sums[1][d][j] << " " << mBaseOTs[treeIdx + j][d][1] << std::endl;;
                            }
        #endif													  
                            sums[0][d][j] = sums[0][d][j] ^ pprf.mBaseOTs[treeIdx + j][d][0];
                            sums[1][d][j] = sums[1][d][j] ^ pprf.mBaseOTs[treeIdx + j][d][1];
                        }
                    }
                    // pprf.setTimePoint("SilentMultiPprfSender.expand " + std::to_string(treeIdx));

                    if (mActiveChildXorDelta)
                    {
                        // For the last level, we are going to do something special. 
                        // The other party is currently missing both leaf children of 
                        // the active parent. Since this is the last level, we want
                        // the inactive child to just be the normal value but the 
                        // active child should be the correct value XOR the delta.
                        // This will be done by sending the sums and the sums plus 
                        // delta and ensure that they can only decrypt the correct ones.
                        d = pprf.mDepth - 1;
                        //std::vector<std::array<block, 4>>& lastOts = lastOts;
                        lastOts.resize(min);
                        for (u64 j = 0; j < min; ++j)
                        {
                            // Construct the sums where we will allow the delta (mValue)
                            // to either be on the left child or right child depending 
                            // on which has the active path.
                            lastOts[j][0] = lastSums[0][j];
                            lastOts[j][1] = TypeTrait::plus(lastSums[1][j], pprf.mValue[treeIdx + j]);
                            lastOts[j][2] = lastSums[1][j];
                            lastOts[j][3] = TypeTrait::plus(lastSums[0][j], pprf.mValue[treeIdx + j]);

                            // We are going to expand the 128 bit OT string
                            // into a 256 bit OT string using AES.
                            std::array<block, 4> masks, maskIn;
                            maskIn[0] = pprf.mBaseOTs[treeIdx + j][d][0];
                            maskIn[1] = pprf.mBaseOTs[treeIdx + j][d][0] ^ AllOneBlock;
                            maskIn[2] = pprf.mBaseOTs[treeIdx + j][d][1];
                            maskIn[3] = pprf.mBaseOTs[treeIdx + j][d][1] ^ AllOneBlock;
                            mAesFixedKey.hashBlocks<4>(maskIn.data(), masks.data());

        #ifdef DEBUG_PRINT_PPRF
                            if (mPrint) {
                                std::cout << "c[" << treeIdx + j << "][" << d << "][0] " << sums[0][d][j] << " " << mBaseOTs[treeIdx + j][d][0] << std::endl;;
                                std::cout << "c[" << treeIdx + j << "][" << d << "][1] " << sums[1][d][j] << " " << mBaseOTs[treeIdx + j][d][1] << std::endl;;
                            }
        #endif							

                            // Add the OT masks to the sums and send them over.
                            lastOts[j][0] = TypeTrait::plus(lastOts[j][0], TypeTrait::fromBlock(masks[0]));
                            lastOts[j][1] = TypeTrait::plus(lastOts[j][1], TypeTrait::fromBlock(masks[1]));
                            lastOts[j][2] = TypeTrait::plus(lastOts[j][2], TypeTrait::fromBlock(masks[2]));
                            lastOts[j][3] = TypeTrait::plus(lastOts[j][3], TypeTrait::fromBlock(masks[3]));
                            }

                        // pprf.setTimePoint("SilentMultiPprfSender.last " + std::to_string(treeIdx));

                        // Resize the sums to that they dont include
                        // the unmasked sums on the last level!
                        sums[0].resize(pprf.mDepth - 1);
                        sums[1].resize(pprf.mDepth - 1);
                        }

                    // Send the sums to the other party.
                    //sendOne(treeGrp);
                    //chl.asyncSend(std::move(sums[0]));
                    //chl.asyncSend(std::move(sums[1]));

                    MC_AWAIT(chl.send(std::move(sums[0])));
                    MC_AWAIT(chl.send(std::move(sums[1])));

                    if (mActiveChildXorDelta)
                        MC_AWAIT(chl.send(std::move(lastOts)));


                    //// send the special OT messages for the last level.
                    //chl.asyncSend(std::move(lastOts));
                    //gTimer.setTimePoint("send.expand_send");

                    // copy the last level to the output. If desired, this is 
                    // where the transpose is performed. 
                    auto lvl = getLastLevel(pprf.mDepth, treeIdx);

                    // s is a checksum that is used for malicious security. 
                    copyOut<F>(lvl, output, pprf.mPntCount, treeIdx, oFormat, pprf.mOutputFn);

                    // pprf.setTimePoint("SilentMultiPprfSender.copyOut " + std::to_string(treeIdx));

                    }

                //uPtr_ = {};
                //tree = {};
                pprf.mTreeAlloc.del(tree);
                // pprf.setTimePoint("SilentMultiPprfSender.delete " + std::to_string(treeIdx));

                MC_END();
            }
        };

        std::vector<Expander> mExps;
    };


    template<typename TypeTrait>
    class SilentSubfieldPprfReceiver : public TimerAdapter
    {
    public:
        using F = typename TypeTrait::F;
        u64 mDomain = 0, mDepth = 0, mPntCount = 0;

        std::vector<u64> mPoints;

        Matrix<block> mBaseOTs;
        Matrix<u8> mBaseChoices;
        bool mPrint = false;
        TreeAllocator mTreeAlloc;
        block mDebugValue;
        std::function<void(u64 treeIdx, span<AlignedArray<F, 8>>)> mOutputFn;
        std::function<F(const block& b)> fromBlock;

        SilentSubfieldPprfReceiver() = default;
        SilentSubfieldPprfReceiver(const SilentSubfieldPprfReceiver&) = delete;
        SilentSubfieldPprfReceiver(SilentSubfieldPprfReceiver&&) = delete;

        void configure(u64 domainSize, u64 pointCount)
        {
            mDomain = domainSize;
            mDepth = log2ceil(mDomain);
            mPntCount = pointCount;

            mBaseOTs.resize(0, 0);
        }


        // For output format Plain or BlockTransposed, the choice bits it
        // samples are in blocks of mDepth, with mPntCount blocks total (one for
        // each punctured point). For Plain these blocks encode the punctured
        // leaf index in big endian, while for BlockTransposed they are in
        // little endian.
        BitVector sampleChoiceBits(u64 modulus, PprfOutputFormat format, PRNG& prng)
        {
            BitVector choices(mPntCount * mDepth);

            // The points are read in blocks of 8, so make sure that there is a
            // whole number of blocks.
            mBaseChoices.resize(roundUpTo(mPntCount, 8), mDepth);
            for (u64 i = 0; i < mPntCount; ++i)
            {
                u64 idx;
                switch (format)
                {
                case osuCrypto::PprfOutputFormat::Plain:
                case osuCrypto::PprfOutputFormat::BlockTransposed:
                    do {
                        for (u64 j = 0; j < mDepth; ++j)
                            mBaseChoices(i, j) = prng.getBit();
                        idx = getActivePath(mBaseChoices[i]);
                    } while (idx >= modulus);

                    break;
                case osuCrypto::PprfOutputFormat::Interleaved:
                case osuCrypto::PprfOutputFormat::InterleavedTransposed:
                case osuCrypto::PprfOutputFormat::Callback:

                    // make sure that at least the first element of this tree
                    // is within the modulus.
                    idx = interleavedPoint(0, i, mPntCount, mDomain, format);
                    if (idx >= modulus)
                        throw RTE_LOC;


                    do {
                        for (u64 j = 0; j < mDepth; ++j)
                            mBaseChoices(i, j) = prng.getBit();
                        idx = getActivePath(mBaseChoices[i]);

                        idx = interleavedPoint(idx, i, mPntCount, mDomain, format);
                    } while (idx >= modulus);


                    break;
                default:
                    throw RTE_LOC;
                    break;
                }

            }

            for (u64 i = 0; i < mBaseChoices.size(); ++i)
            {
                choices[i] = mBaseChoices(i);
            }

            return choices;
        }

        // choices is in the same format as the output from sampleChoiceBits.
        void setChoiceBits(PprfOutputFormat format, BitVector choices)
        {
            // Make sure we're given the right number of OTs.
            if (choices.size() != baseOtCount())
                throw RTE_LOC;

            mBaseChoices.resize(roundUpTo(mPntCount, 8), mDepth);
            for (u64 i = 0; i < mPntCount; ++i)
            {
                switch (format)
                {
                case osuCrypto::PprfOutputFormat::Plain:
                case osuCrypto::PprfOutputFormat::BlockTransposed:
                    for (u64 j = 0; j < mDepth; ++j)
                        mBaseChoices(i, j) = choices[mDepth * i + j];
                    break;

                    // Not sure what ordering would be good for Interleaved or
                    // InterleavedTransposed.

                default:
                    throw RTE_LOC;
                    break;
                }

                if (getActivePath(mBaseChoices[i]) >= mDomain)
                    throw RTE_LOC;
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
            switch (format)
            {
            case PprfOutputFormat::Plain:
            case PprfOutputFormat::BlockTransposed:

                memset(points.data(), 0, points.size() * sizeof(u64));
                for (u64 j = 0; j < mPntCount; ++j)
                {
                    points[j] = getActivePath(mBaseChoices[j]);
                }

                break;
            case PprfOutputFormat::InterleavedTransposed:
            case PprfOutputFormat::Interleaved:
            case PprfOutputFormat::Callback:

                if ((u64)points.size() != mPntCount)
                    throw RTE_LOC;
                if (points.size() % 8)
                    throw RTE_LOC;

                getPoints(points, PprfOutputFormat::Plain);
                interleavedPoints(points, mDomain, format);

                break;
            default:
                throw RTE_LOC;
                break;
            }
        }

        task<> expand(Socket& chl, PRNG& prng, span<F> output, PprfOutputFormat oFormat, bool activeChildXorDelta, u64 numThreads)
        {
            MatrixView<F> o(output.data(), output.size(), 1);
            return expand(chl, prng, o, oFormat, activeChildXorDelta, numThreads);
        }

        // activeChildXorDelta says whether the sender is trying to program the
        // active child to be its correct value XOR delta. If it is not, the
        // active child will just take a random value.
        task<> expand(Socket& chl, PRNG& prng, MatrixView<F> output, PprfOutputFormat oFormat, bool activeChildXorDelta, u64 numThreads)
        {
            setTimePoint("SilentMultiPprfReceiver.start");

            //lout << " d " << mDomain << " p " << mPntCount << " do " << mDepth << std::endl;

            if (oFormat == PprfOutputFormat::Plain)
            {
                if (output.rows() != mDomain)
                    throw RTE_LOC;

                if (output.cols() != mPntCount)
                    throw RTE_LOC;
            }
            else if (oFormat == PprfOutputFormat::BlockTransposed)
            {
                if (output.cols() != mDomain)
                    throw RTE_LOC;

                if (output.rows() != mPntCount)
                    throw RTE_LOC;
            }
            else if (oFormat == PprfOutputFormat::InterleavedTransposed)
            {
                if (output.rows() != 128)
                    throw RTE_LOC;

                //if (output.cols() > (mDomain * mPntCount + 127) / 128)
                //    throw RTE_LOC;

                if (mPntCount & 7)
                    throw RTE_LOC;
            }
            else if (oFormat == PprfOutputFormat::Interleaved)
            {
                if (output.cols() != 1)
                    throw RTE_LOC;
                if (mDomain & 1)
                    throw RTE_LOC;
                auto rows = output.rows();
                if (rows > (mDomain * mPntCount) ||
                    rows / 128 != (mDomain * mPntCount) / 128)
                    throw RTE_LOC;
                if (mPntCount & 7)
                    throw RTE_LOC;
            }
            else if (oFormat == PprfOutputFormat::Callback)
            {
                if (mDomain & 1)
                    throw RTE_LOC;
                if (mPntCount & 7)
                    throw RTE_LOC;
            }
            else
            {
                throw RTE_LOC;
            }

            mPoints.resize(roundUpTo(mPntCount, 8));
            getPoints(mPoints, PprfOutputFormat::Plain);


            MC_BEGIN(task<>, this, numThreads, oFormat, output, &chl, activeChildXorDelta,
                i = u64{},
                dd = u64{}
            );


            dd = mDepth + (oFormat == PprfOutputFormat::Interleaved ? 0 : 1);
            mTreeAlloc.reserve(numThreads, (1ull << (dd+1)) + (32 * (dd+1)));
            setTimePoint("SilentMultiPprfReceiver.reserve");

            mExps.clear(); mExps.reserve(divCeil(mPntCount, 8));
            for (i = 0; i < mPntCount; i += 8)
            {
                mExps.emplace_back(*this, chl.fork(), oFormat, output, activeChildXorDelta, i);
                mExps.back().mFuture = macoro::make_eager(mExps.back().run());

                //MC_AWAIT(mExps.back().run());
            }

            for (i = 0; i < mExps.size(); ++i)
                MC_AWAIT(mExps[i].mFuture);
            setTimePoint("SilentMultiPprfReceiver.join");

            mBaseOTs = {};
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



        struct Expander
        {
            SilentSubfieldPprfReceiver& pprf;
            Socket chl;

            bool mActiveChildXorDelta = false;
            std::array<AES, 2> aes;

            PprfOutputFormat oFormat;
            MatrixView<F> output;

            macoro::eager_task<void> mFuture;

            std::vector<span<AlignedArray<block, 8>>> mLevels;

            // mySums will hold the left and right GGM tree sums
             // for each level. For example mySums[5][0]  will
             // hold the sum of the left children for the 5th tree. This
             // sum will be "missing" the children of the active parent.
             // The sender will give of one of the full somes so we can
             // compute the missing inactive child.
            std::array<std::array<block, 8>, 2> mySums;

            // sums for the last level
            std::array<std::array<F, 8>, 2> lastSums;
            std::vector<std::array<F, 4>> lastOts;

            // A buffer for receiving the sums from the other party.
            // These will be masked by the OT strings. 
            std::array<std::vector<std::array<block, 8>>, 2> theirSums;

            u64 dd, treeIdx;
            // tree will hold the full GGM tree. Not that there are 8 
            // indepenendent trees that are being processed together. 
            // The trees are flattenned to that the children of j are
            // located at 2*j  and 2*j+1. 
            //std::unique_ptr<block[]> uPtr_;
            span<AlignedArray<block, 8>> tree;

            // Returns the i'th level of the current 8 trees. The 
            // children of node j on level i are located at 2*j and
            // 2*j+1  on level i+1. 
            span<AlignedArray<block, 8>> getLevel(u64 i, u64 g, bool f = false)
            {
                //auto size = (1ull << i);
        #ifdef DEBUG_PRINT_PPRF
                //auto offset = (size - 1);
                //auto b = (f ? ftree.begin() : tree.begin()) + offset;
        #else
                return mLevels[i];
        #endif
                //return span<std::array<block, 8>>(b,e);
            };

        span<AlignedArray<F, 8>> getLastLevel(u64 i, u64 g, bool f = false)
            {
                //auto size = (1ull << i);
        #ifdef DEBUG_PRINT_PPRF
                //auto offset = (size - 1);
                //auto b = (f ? ftree.begin() : tree.begin()) + offset;
        #else
                if (oFormat == PprfOutputFormat::Interleaved && i == pprf.mDepth)
                {
                    auto b = (AlignedArray<F, 8>*)output.data();
                    auto forest = g / 8;
                    assert(g % 8 == 0);
                    b += forest * pprf.mDomain;
                    auto zone = span<AlignedArray<F, 8>>(b, pprf.mDomain);
                    return zone;
                }

                //assert(tree.size());
                //auto b = tree.begin() + offset;

                throw RTE_LOC;
        #endif
                //return span<std::array<block, 8>>(b,e);
            };


            Expander(SilentSubfieldPprfReceiver& p, Socket&& s, PprfOutputFormat of, MatrixView<F> o, bool activeChildXorDelta, u64 ti)
                : pprf(p)
                , chl(std::move(s))
                , mActiveChildXorDelta(activeChildXorDelta)
                , oFormat(of)
                , output(o)
                , treeIdx(ti)
                //, threadIdx(tIdx)
            {
                assert((treeIdx & 7) == 0);
                // A public PRF/PRG that we will use for deriving the GGM tree.
                aes[0].setKey(toBlock(3242342));
                aes[1].setKey(toBlock(8993849));


                theirSums[0].resize(p.mDepth - mActiveChildXorDelta);
                theirSums[1].resize(p.mDepth - mActiveChildXorDelta);

                dd = p.mDepth + (oFormat == PprfOutputFormat::Interleaved ? 0 : 1);

            }
            task<> run()
            {

            MC_BEGIN(task<>, this);


            {
                tree = pprf.mTreeAlloc.get();
                assert(tree.size() >= 1ull << (dd));
                mLevels.resize(dd+1); // todo: last level block are kept
                mLevels[0] = tree.subspan(0, 1);
                auto rem = tree.subspan(1);
                for (u64 i = 1; i < dd + 1; i++)
                {
                    while ((u64)rem.data() % 32)
                        rem = rem.subspan(1);

                    mLevels[i] = rem.subspan(0, mLevels[i - 1].size() * 2);
                    rem = rem.subspan(mLevels[i].size());
                }
            }


    #ifdef DEBUG_PRINT_PPRF
            // This will be the full tree and is sent by the receiver to help debug. 
            std::vector<std::array<block, 8>> ftree(1ull << (mDepth + 1));

            // The delta value on the active path.
            //block deltaValue;
            chl.recv(mDebugValue);
    #endif



    #ifdef DEBUG_PRINT_PPRF
            // prints out the contents of the d'th level.
            auto printLevel = [&](u64 d)
            {

                auto level0 = getLevel(d);
                auto flevel0 = getLevel(d, true);

                std::cout
                    << "---------------------\nlevel " << d
                    << "\n---------------------" << std::endl;

                std::array<block, 2> sums{ ZeroBlock ,ZeroBlock };
                for (i64 i = 0; i < level0.size(); ++i)
                {
                    for (u64 j = 0; j < 8; ++j)
                    {

                        if (neq(level0[i][j], flevel0[i][j]))
                            std::cout << Color::Red;

                        std::cout << "p[" << i << "][" << j << "] "
                            << level0[i][j] << " " << flevel0[i][j] << std::endl << Color::Default;

                        if (i == 0 && j == 0)
                            sums[i & 1] = sums[i & 1] ^ flevel0[i][j];
                    }
                }

                std::cout << "sums[0] = " << sums[0] << " " << sums[1] << std::endl;
            };
    #endif


            // The number of real trees for this iteration.
            memset(lastSums[0].data(), 0, lastSums[0].size() * sizeof(F));
            memset(lastSums[1].data(), 0, lastSums[1].size() * sizeof(F));
            memset(mySums[0].data(), 0, mySums[0].size() * sizeof(F));
            memset(mySums[1].data(), 0, mySums[1].size() * sizeof(F));
            lastOts.resize(8);

            // This thread will process 8 trees at a time. It will interlace
            // the sets of trees are processed with the other threads. 
            {
    #ifdef DEBUG_PRINT_PPRF
                chl.recv(ftree);
                auto l1f = getLevel(1, true);
    #endif

                //timer.setTimePoint("recv.start" + std::to_string(treeIdx));
                // Receive their full set of sums for these 8 trees.
                MC_AWAIT(chl.recv(theirSums[0]));
                MC_AWAIT(chl.recv(theirSums[1]));

                if (mActiveChildXorDelta)
                    MC_AWAIT(chl.recv(lastOts));
                // pprf.setTimePoint("SilentMultiPprfReceiver.recv " + std::to_string(treeIdx));

                tree = pprf.mTreeAlloc.get();
                assert(tree.size() >= 1ull << (dd));
                assert((u64)tree.data() % 32 == 0);

                // pprf.setTimePoint("SilentMultiPprfReceiver.alloc " + std::to_string(treeIdx));

                auto l1 = getLevel(1, treeIdx);

                for (u64 i = 0; i < 8; ++i)
                {
                    // For the non-active path, set the child of the root node
                    // as the OT message XOR'ed with the correction sum.
                    int notAi = pprf.mBaseChoices[i + treeIdx][0];
                    l1[notAi][i] = pprf.mBaseOTs[i + treeIdx][0] ^ theirSums[notAi][0][i];
                    l1[notAi ^ 1][i] = ZeroBlock;

    #ifdef DEBUG_PRINT_PPRF
                    if (neq(l1[notAi][i], l1f[notAi][i])) {
                        std::cout << "l1[" << notAi << "][" << i << "] " << l1[notAi][i] << " = "
                            << (mBaseOTs[i + treeIdx][0]) << " ^ "
                            << theirSums[notAi][0][i] << " vs " << l1f[notAi][i] << std::endl;
                    }
    #endif
                }

    #ifdef DEBUG_PRINT_PPRF
                if (mPrint)
                    printLevel(1);
    #endif

                // For all other levels, expand the GGM tree and add in 
                // the correction along the active path. 
                for (u64 d = 1; d < pprf.mDepth; ++d)
                {
                    // The already constructed level. Only missing the
                    // GGM tree node value along the active path. 
                    auto level0 = getLevel(d, treeIdx);

                    // The next level that we want to construct. 
                    auto level1 = getLevel(d + 1, treeIdx);

                    // Zero out the previous sums.
                    memset(mySums[0].data(), 0, mySums[0].size() * sizeof(block));
                    memset(mySums[1].data(), 0, mySums[1].size() * sizeof(block));

                    // We will iterate over each node on this level and
                    // expand it into it's two children. Note that the
                    // active node will also be expanded. Later we will just
                    // overwrite whatever the value was. This is an optimization.
                    auto width = static_cast<u64>(level1.size());
                    for (u64 childIdx = 0; childIdx < width; )
                    {

                        // Index of the parent in the previous level.
                        auto parentIdx = childIdx >> 1;

                        // The value of the parent.
                        auto parent = level0[parentIdx];

                        for (u64 keep = 0; keep < 2; ++keep, ++childIdx)
                        {

                            //// The bit that indicates if we are on the left child (0)
                            //// or on the right child (1).
                            //u8 keep = childIdx & 1;


                            // The child that we will write in this iteration.
                            auto& child = level1[childIdx];

                            // Each parent is expanded into the left and right children 
                            // using a different AES fixed-key. Therefore our OWF is:
                            //
                            //    H(x) = (AES(k0, x) + x) || (AES(k1, x) + x);
                            //
                            // where each half defines one of the children.
                            aes[keep].template hashBlocks<8>(parent.data(), child.data());



    #ifdef DEBUG_PRINT_PPRF
                            // For debugging, set the active path to zero.
                            for (u64 i = 0; i < 8; ++i)
                                if (eq(parent[i], ZeroBlock))
                                    child[i] = ZeroBlock;
    #endif

                            if (d < pprf.mDepth - 1) {
                                // Same as before
                                // Update the running sums for this level. We keep 
                                // a left and right totals for each level. Note that
                                // we are actually XOR in the incorrect value of the 
                                // children of the active parent (assuming !DEBUG_PRINT_PPRF).
                                // This is ok since we will later XOR off these incorrect values.
                                auto& sum = mySums[keep];
                                sum[0] = sum[0] ^ child[0];
                                sum[1] = sum[1] ^ child[1];
                                sum[2] = sum[2] ^ child[2];
                                sum[3] = sum[3] ^ child[3];
                                sum[4] = sum[4] ^ child[4];
                                sum[5] = sum[5] ^ child[5];
                                sum[6] = sum[6] ^ child[6];
                                sum[7] = sum[7] ^ child[7];
                            } else {
                                if (getLastLevel(pprf.mDepth, treeIdx).size() <= childIdx) {
                                    childIdx = width;
                                    break;
                                }
                                auto& realChild = getLastLevel(pprf.mDepth, treeIdx)[childIdx];
                                auto& lastSum = lastSums[keep];
                                realChild[0] = TypeTrait::fromBlock(child[0]);
                                lastSum[0] = TypeTrait::plus(lastSum[0], realChild[0]);
                                realChild[1] = TypeTrait::fromBlock(child[1]);
                                lastSum[1] = TypeTrait::plus(lastSum[1], realChild[1]);
                                realChild[2] = TypeTrait::fromBlock(child[2]);
                                lastSum[2] = TypeTrait::plus(lastSum[2], realChild[2]);
                                realChild[3] = TypeTrait::fromBlock(child[3]);
                                lastSum[3] = TypeTrait::plus(lastSum[3], realChild[3]);
                                realChild[4] = TypeTrait::fromBlock(child[4]);
                                lastSum[4] = TypeTrait::plus(lastSum[4], realChild[4]);
                                realChild[5] = TypeTrait::fromBlock(child[5]);
                                lastSum[5] = TypeTrait::plus(lastSum[5], realChild[5]);
                                realChild[6] = TypeTrait::fromBlock(child[6]);
                                lastSum[6] = TypeTrait::plus(lastSum[6], realChild[6]);
                                realChild[7] = TypeTrait::fromBlock(child[7]);
                                lastSum[7] = TypeTrait::plus(lastSum[7], realChild[7]);
                            }
                        }
                    }

                    // For everything but the last level we have to
                    // 1) fix our sums so they dont include the incorrect
                    //    values that are the children of the active parent
                    // 2) Update the non-active child of the active parent. 
                    if (!mActiveChildXorDelta || d != pprf.mDepth - 1)
                    {

                        for (u64 i = 0; i < 8; ++i)
                        {
                            // the index of the leaf node that is active.
                            auto leafIdx = pprf.mPoints[i + treeIdx];

                            // The index of the active child node.
                            auto activeChildIdx = leafIdx >> (pprf.mDepth - 1 - d);

                            // The index of the active child node sibling.
                            auto inactiveChildIdx = activeChildIdx ^ 1;

                            // The indicator as to the left or right child is inactive
                            auto notAi = inactiveChildIdx & 1;
    #ifdef DEBUG_PRINT_PPRF
                            auto prev = level1[inactiveChildIdx][i];
    #endif

                            auto& inactiveChild = level1[inactiveChildIdx][i];


                            // correct the sum value by XORing off the incorrect
                            auto correctSum =
                                inactiveChild ^
                                theirSums[notAi][d][i];

                            inactiveChild =
                                correctSum ^
                                mySums[notAi][i] ^
                                pprf.mBaseOTs[i + treeIdx][d];

    #ifdef DEBUG_PRINT_PPRF
                            if (mPrint)
                                std::cout << "up[" << i << "] = level1[" << inactiveChildIdx << "][" << i << "] "
                                << prev << " -> " << level1[inactiveChildIdx][i] << " " << activeChildIdx << " " << inactiveChildIdx << " ~~ "
                                << mBaseOTs[i + treeIdx][d] << " " << theirSums[notAi][d][i] << " @ " << (i + treeIdx) << " " << d << std::endl;

                            auto fLevel1 = getLevel(d + 1, true);
                            if (neq(fLevel1[inactiveChildIdx][i], inactiveChild))
                                throw RTE_LOC;
    #endif
                        }
                        }
    #ifdef DEBUG_PRINT_PPRF
                    if (mPrint)
                        printLevel(d + 1);
    #endif

                    }

                // pprf.setTimePoint("SilentMultiPprfReceiver.expand " + std::to_string(treeIdx));

                //timer.setTimePoint("recv.expanded");


                // copy the last level to the output. If desired, this is 
                // where the transpose is performed. 
                auto lvl = getLastLevel(pprf.mDepth, treeIdx);

                if (mActiveChildXorDelta)
                {
                    // Now processes the last level. This one is special 
                    // because we must XOR in the correction value as 
                    // before but we must also fixed the child value for 
                    // the active child. To do this, we will receive 4 
                    // values. Two for each case (left active or right active).
                    //timer.setTimePoint("recv.recvLast");

                    auto d = pprf.mDepth - 1;
                    for (u64 j = 0; j < 8; ++j)
                    {
                        // The index of the child on the active path. 
                        auto activeChildIdx = pprf.mPoints[j + treeIdx];

                        // The index of the other (inactive) child.
                        auto inactiveChildIdx = activeChildIdx ^ 1;

                        // The indicator as to the left or right child is inactive
                        auto notAi = inactiveChildIdx & 1;

                        std::array<block, 2> masks, maskIn;

                        // We are going to expand the 128 bit OT string
                        // into a 256 bit OT string using AES.
                        maskIn[0] = pprf.mBaseOTs[j + treeIdx][d];
                        maskIn[1] = pprf.mBaseOTs[j + treeIdx][d] ^ AllOneBlock;
                        mAesFixedKey.template hashBlocks<2>(maskIn.data(), masks.data());

                        // now get the chosen message OT strings by XORing
                        // the expended (random) OT strings with the lastOts values.
                        auto& ot0 = lastOts[j][2 * notAi + 0];
                        auto& ot1 = lastOts[j][2 * notAi + 1];
                        ot0 = TypeTrait::minus(ot0, TypeTrait::fromBlock(masks[0]));
                        ot1 = TypeTrait::minus(ot1, TypeTrait::fromBlock(masks[1]));

    #ifdef DEBUG_PRINT_PPRF
                        auto prev = level[inactiveChildIdx][j];
    #endif

                        auto& inactiveChild = lvl[inactiveChildIdx][j];
                        auto& activeChild = lvl[activeChildIdx][j];

                        // Fix the sums we computed previously to not include the
                        // incorrect child values. 
                        auto inactiveSum = TypeTrait::minus(lastSums[notAi][j], inactiveChild);
                        auto activeSum = TypeTrait::minus(lastSums[notAi ^ 1][j], activeChild);

                        // Update the inactive and active child to have to correct 
                        // value by XORing their full sum with out partial sum, which
                        // gives us exactly the value we are missing.
                        inactiveChild = TypeTrait::minus(ot0, inactiveSum);
                        activeChild = TypeTrait::minus(ot1, activeSum);

    #ifdef DEBUG_PRINT_PPRF
                        auto fLevel1 = getLevel(d + 1, true);
                        if (neq(fLevel1[inactiveChildIdx][j], inactiveChild))
                            throw RTE_LOC;
                        if (neq(fLevel1[activeChildIdx][j], activeChild ^ mDebugValue))
                            throw RTE_LOC;

                        if (mPrint)
                            std::cout << "up[" << d << "] = level1[" << (inactiveChildIdx / mPntCount) << "][" << (inactiveChildIdx % mPntCount) << " "
                            << prev << " -> " << level[inactiveChildIdx][j] << " ~~ "
                            << mBaseOTs[j + treeIdx][d] << " " << ot0 << " @ " << (j + treeIdx) << " " << d << std::endl;
    #endif
                    }
                    // pprf.setTimePoint("SilentMultiPprfReceiver.last " + std::to_string(treeIdx));

                    //timer.setTimePoint("recv.expandLast");
                    }
                else
                {
                    for (auto j : rng(std::min<u64>(8, pprf.mPntCount - treeIdx)))
                    {

                        // The index of the child on the active path.
                        auto activeChildIdx = pprf.mPoints[j + treeIdx];
                        lvl[activeChildIdx][j] = F{};
                    }
                }

                // s is a checksum that is used for malicious security.
                copyOut<F>(lvl, output, pprf.mPntCount, treeIdx, oFormat, pprf.mOutputFn);

                // pprf.setTimePoint("SilentMultiPprfReceiver.copy " + std::to_string(treeIdx));

                //uPtr_ = {};
                //tree = {};
                pprf.mTreeAlloc.del(tree);

                // pprf.setTimePoint("SilentMultiPprfReceiver.delete " + std::to_string(treeIdx));

                }

            MC_END();
                }
        };

        std::vector<Expander> mExps;
    };
}
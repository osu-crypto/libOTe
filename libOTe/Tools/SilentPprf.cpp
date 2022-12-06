#include "SilentPprf.h"
#if defined(ENABLE_SILENTOT) || defined(ENABLE_SILENT_VOLE)

#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/Aligned.h>
#include <cryptoTools/Common/Range.h>
#include <cryptoTools/Crypto/RandomOracle.h>
#include <libOTe/Tools/Tools.h>

namespace osuCrypto
{

    void SilentMultiPprfSender::setBase(span<const std::array<block, 2>> baseMessages)
    {
        if (baseOtCount() != static_cast<u64>(baseMessages.size()))
            throw RTE_LOC;

        mBaseOTs.resize(mPntCount, mDepth);
        for (u64 i = 0; i < static_cast<u64>(mBaseOTs.size()); ++i)
            mBaseOTs(i) = baseMessages[i];
    }

    void SilentMultiPprfReceiver::setBase(span<const block> baseMessages)
    {
        if (baseOtCount() != static_cast<u64>(baseMessages.size()))
            throw RTE_LOC;

        // The OTs are used in blocks of 8, so make sure that there is a whole
        // number of blocks.
        mBaseOTs.resize(roundUpTo(mPntCount, 8), mDepth);
        memcpy(mBaseOTs.data(), baseMessages.data(), baseMessages.size() * sizeof(block));
    }

    // This function copies the leaf values of the GGM tree
    // to the output location. There are two modes for this
    // function. If interleaved == false, then each tree is
    // copied to a different contiguous regions of the output.
    // If interleaved == true, then trees are interleaved such that ....
    // @lvl         - the GGM tree leafs.
    // @output      - the location that the GGM leafs should be written to.
    // @numTrees    - How many trees there are in total.
    // @tIdx        - the index of the first tree.
    // @oFormat     - do we interleave the output?
    // @mal         - ...
    void copyOut(
        span<AlignedArray<block, 8>> lvl,
        MatrixView<block> output,
        u64 totalTrees,
        u64 tIdx,
        PprfOutputFormat oFormat,
        std::function<void(u64 treeIdx, span<AlignedArray<block, 8>> lvl)>& callback)
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
                auto end = std::min<u64>(begin + step * blocksPerSet, output.cols());

                for (u64 i = begin, k = 0; i < end; i += step, ++k)
                {
                    auto& io = *(std::array<block, 128>*)(&lvl[k * 16]);
                    transpose128(io.data());
                    for (u64 j = 0; j < 128; ++j)
                        output(j, i) = io[j];
                }
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

    u64 interleavedPoint(u64 point, u64 treeIdx, u64 totalTrees, u64 domain, PprfOutputFormat format)
    {


        switch (format)
        {
        case osuCrypto::PprfOutputFormat::Interleaved:
        case osuCrypto::PprfOutputFormat::Callback:
        {

            if (domain <= point)
                return ~u64(0);

            auto subTree = treeIdx % 8;
            auto forest = treeIdx / 8;

            return (forest * domain + point) * 8 + subTree;
        }
        break;
        case osuCrypto::PprfOutputFormat::InterleavedTransposed:
        {
            auto numSets = totalTrees / 8;

            auto setIdx = treeIdx / 8;
            auto subIdx = treeIdx % 8;

            auto sectionIdx = point / 16;
            auto posIdx = point % 16;


            auto setOffset = setIdx * 128;
            auto subOffset = subIdx + 8 * posIdx;
            auto secOffset = sectionIdx * numSets * 128;

            return setOffset + subOffset + secOffset;
        }
        default:
            throw RTE_LOC;
            break;
        }
        //auto totalTrees = points.size();

    }

    void interleavedPoints(span<u64> points, u64 domain, PprfOutputFormat format)
    {

        for (u64 i = 0; i < points.size(); ++i)
        {
            points[i] = interleavedPoint(points[i], i, points.size(), domain, format);
        }
    }

    u64 getActivePath(const span<u8>& choiceBits)
    {
        u64 point = 0;
        for (u64 i = 0; i < choiceBits.size(); ++i)
        {
            auto shift = choiceBits.size() - i - 1;

            point |= u64(1 ^ choiceBits[i]) << shift;
        }
        return point;
    }

    void SilentMultiPprfReceiver::getPoints(span<u64> points, PprfOutputFormat format)
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


    BitVector SilentMultiPprfReceiver::sampleChoiceBits(u64 modulus, PprfOutputFormat format, PRNG& prng)
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

    void SilentMultiPprfReceiver::setChoiceBits(PprfOutputFormat format, BitVector choices)
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

    //task<> SilentMultiPprfSender::expand(
    //    Socket& chls,
    //    block value,
    //    PRNG& prng,
    //    MatrixView<block> output,
    //    PprfOutputFormat oFormat,
    //    u64 numThreads)
    //{
    //    return expand(chls, { &value, 1 }, prng, output, oFormat, numThreads);
    //}


    // Returns the i'th level of the current 8 trees. The 
    // children of node j on level i are located at 2*j and
    // 2*j+1  on level i+1. 
    span<AlignedArray<block, 8>> SilentMultiPprfSender::Expander::getLevel(u64 i, u64 g)
    {

        if (oFormat == PprfOutputFormat::Interleaved && i == pprf.mDepth)
        {
            auto b = (AlignedArray<block, 8>*)output.data();
            auto forest = g / 8;
            assert(g % 8 == 0);
            b += forest * pprf.mDomain;
            return span<AlignedArray<block, 8>>(b, pprf.mDomain);
        }

        return mLevels[i];
    };

    SilentMultiPprfSender::Expander::Expander(SilentMultiPprfSender& p, block seed, u64 treeIdx_,
        PprfOutputFormat of, MatrixView<block>o, bool activeChildXorDelta, Socket&& s)
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


    task<> SilentMultiPprfSender::Expander::run()
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
            mLevels.resize(dd);
            mLevels[0] = tree.subspan(0, 1);
            auto rem = tree.subspan(mLevels[0].size());
            for (auto i : rng(1ull, dd))
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
                        aes[keep].hashBlocks<8>(parent.data(), child.data());

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
                    lastOts[j][0] = sums[0][d][j];
                    lastOts[j][1] = sums[1][d][j] ^ pprf.mValue[treeIdx + j];
                    lastOts[j][2] = sums[1][d][j];
                    lastOts[j][3] = sums[0][d][j] ^ pprf.mValue[treeIdx + j];

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
                    lastOts[j][0] = lastOts[j][0] ^ masks[0];
                    lastOts[j][1] = lastOts[j][1] ^ masks[1];
                    lastOts[j][2] = lastOts[j][2] ^ masks[2];
                    lastOts[j][3] = lastOts[j][3] ^ masks[3];
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
            auto lvl = getLevel(pprf.mDepth, treeIdx);

            // s is a checksum that is used for malicious security. 
            copyOut(lvl, output, pprf.mPntCount, treeIdx, oFormat, pprf.mOutputFn);

            // pprf.setTimePoint("SilentMultiPprfSender.copyOut " + std::to_string(treeIdx));

            }

        //uPtr_ = {};
        //tree = {};
        pprf.mTreeAlloc.del(tree);
        // pprf.setTimePoint("SilentMultiPprfSender.delete " + std::to_string(treeIdx));

        MC_END();
        }


    //task<> expand(
    //    Socket& chl,
    //    span<const block> value,
    //    PRNG& prng,
    //    MatrixView<block> output,
    //    PprfOutputFormat oFormat,
    //    bool activeChildXorDelta,
    //    u64 numThreads);


    task<> SilentMultiPprfSender::expand(
        Socket& chl,
        span<const block> value,
        PRNG& prng,
        MatrixView<block> output,
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
        mTreeAlloc.reserve(numThreads, (1ull << dd) + (32 * dd));
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

    void SilentMultiPprfSender::setValue(span<const block> value)
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

    void SilentMultiPprfSender::clear()
    {
        mBaseOTs.resize(0, 0);
        mDomain = 0;
        mDepth = 0;
        mPntCount = 0;
    }


    // Returns the i'th level of the current 8 trees. The 
    // children of node j on level i are located at 2*j and
    // 2*j+1  on level i+1. 
    span<AlignedArray<block, 8>> SilentMultiPprfReceiver::Expander::getLevel(u64 i, u64 g, bool f)
    {
        //auto size = (1ull << i);
#ifdef DEBUG_PRINT_PPRF
        //auto offset = (size - 1);
        //auto b = (f ? ftree.begin() : tree.begin()) + offset;
#else
        if (oFormat == PprfOutputFormat::Interleaved && i == pprf.mDepth)
        {
            auto b = (AlignedArray<block, 8>*)output.data();
            auto forest = g / 8;
            assert(g % 8 == 0);
            b += forest * pprf.mDomain;
            auto zone = span<AlignedArray<block, 8>>(b, pprf.mDomain);
            return zone;
        }

        //assert(tree.size());
        //auto b = tree.begin() + offset;

        return mLevels[i];
#endif
        //return span<std::array<block, 8>>(b,e);
    };


    SilentMultiPprfReceiver::Expander::Expander(SilentMultiPprfReceiver& p, Socket&& s, PprfOutputFormat of, MatrixView<block> o, bool activeChildXorDelta, u64 ti)
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

    task<> SilentMultiPprfReceiver::Expander::run()
    {

        MC_BEGIN(task<>, this);


        {
            tree = pprf.mTreeAlloc.get();
            assert(tree.size() >= 1ull << (dd));
            mLevels.resize(dd);
            mLevels[0] = tree.subspan(0, 1);
            auto rem = tree.subspan(1);
            for (auto i : rng(1ull, dd))
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
                        aes[keep].hashBlocks<8>(parent.data(), child.data());



#ifdef DEBUG_PRINT_PPRF
                        // For debugging, set the active path to zero.
                        for (u64 i = 0; i < 8; ++i)
                            if (eq(parent[i], ZeroBlock))
                                child[i] = ZeroBlock;
#endif
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
            auto lvl = getLevel(pprf.mDepth, treeIdx);

            if (mActiveChildXorDelta)
            {
                // Now processes the last level. This one is special 
                // because we must XOR in the correction value as 
                // before but we must also fixed the child value for 
                // the active child. To do this, we will receive 4 
                // values. Two for each case (left active or right active).
                //timer.setTimePoint("recv.recvLast");

                auto level = getLevel(pprf.mDepth, treeIdx);
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
                    mAesFixedKey.hashBlocks<2>(maskIn.data(), masks.data());

                    // now get the chosen message OT strings by XORing
                    // the expended (random) OT strings with the lastOts values.
                    auto& ot0 = lastOts[j][2 * notAi + 0];
                    auto& ot1 = lastOts[j][2 * notAi + 1];
                    ot0 = ot0 ^ masks[0];
                    ot1 = ot1 ^ masks[1];

#ifdef DEBUG_PRINT_PPRF
                    auto prev = level[inactiveChildIdx][j];
#endif

                    auto& inactiveChild = level[inactiveChildIdx][j];
                    auto& activeChild = level[activeChildIdx][j];

                    // Fix the sums we computed previously to not include the
                    // incorrect child values. 
                    auto inactiveSum = mySums[notAi][j] ^ inactiveChild;
                    auto activeSum = mySums[notAi ^ 1][j] ^ activeChild;

                    // Update the inactive and active child to have to correct 
                    // value by XORing their full sum with out partial sum, which
                    // gives us exactly the value we are missing.
                    inactiveChild = ot0 ^ inactiveSum;
                    activeChild = ot1 ^ activeSum;

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
                    lvl[activeChildIdx][j] = ZeroBlock;
                }
            }

            // s is a checksum that is used for malicious security. 
            copyOut(lvl, output, pprf.mPntCount, treeIdx, oFormat, pprf.mOutputFn);

            // pprf.setTimePoint("SilentMultiPprfReceiver.copy " + std::to_string(treeIdx));

            //uPtr_ = {};
            //tree = {};
            pprf.mTreeAlloc.del(tree);

            // pprf.setTimePoint("SilentMultiPprfReceiver.delete " + std::to_string(treeIdx));

            }

        MC_END();
            }



    task<> SilentMultiPprfReceiver::expand(Socket& chl, PRNG& prng, MatrixView<block> output,
        PprfOutputFormat oFormat,
        bool activeChildXorDelta,
        u64 numThreads)
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
        mTreeAlloc.reserve(numThreads, (1ull << (dd)) + (32 * dd));
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

                }

#endif

#pragma once
// © 2020 Peter Rindal.
// © 2022 Visa.
// © 2022 Lawrence Roy.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#include <libOTe/config.h>
#if defined(ENABLE_SILENTOT) || defined(ENABLE_SILENT_VOLE)

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Matrix.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Common/Aligned.h>
#include <cryptoTools/Crypto/PRNG.h>
#include "libOTe/Tools/Coproto.h"
#include <array>
//#define DEBUG_PRINT_PPRF

namespace osuCrypto
{

    enum class PprfOutputFormat
    {
        Plain,                // One column per tree, one row per leaf
        BlockTransposed,      // One row per tree, one column per leaf
        Interleaved,
        InterleavedTransposed, // Bit transposed
        Callback               // call the user's callback

    };

    enum class OTType
    {
        Random, Correlated
    };

    enum class ChoiceBitPacking
    {
        False, True
    };

    enum class SilentSecType
    {
        SemiHonest,
        Malicious,
        //MaliciousFS
    };

    struct TreeAllocator
    {
        TreeAllocator() = default;
        TreeAllocator(const TreeAllocator&) = delete;
        TreeAllocator(TreeAllocator&&) = delete;

        using ValueType = AlignedArray<block, 8>;
        std::list<AlignedUnVector<ValueType>> mTrees;
        std::vector<span<ValueType>> mFreeTrees;
        std::mutex mMutex;
        u64 mTreeSize = 0, mNumTrees = 0;

        void reserve(u64 num, u64 size)
        {
            std::lock_guard<std::mutex> lock(mMutex);
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
            std::lock_guard<std::mutex> lock(mMutex);
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

        void del(span<ValueType> uPtr)
        {
            std::lock_guard<std::mutex> lock(mMutex);
            mFreeTrees.push_back(uPtr);
        }

        void clear()
        {
            assert(mNumTrees == mFreeTrees.size());
            mTrees.clear();
            mFreeTrees = {};
            mTreeSize = {};
        }
    };

    class SilentMultiPprfSender : public TimerAdapter
    {
    public:
        u64 mDomain = 0, mDepth = 0, mPntCount = 0;
        std::vector<block> mValue;
        bool mPrint = false;
        TreeAllocator mTreeAlloc;
        Matrix<std::array<block, 2>> mBaseOTs;
        
        std::function<void(u64 treeIdx, span<AlignedArray<block, 8>>)> mOutputFn;

        SilentMultiPprfSender() = default;
        SilentMultiPprfSender(const SilentMultiPprfSender&) = delete;
        SilentMultiPprfSender(SilentMultiPprfSender&&) = delete;

        SilentMultiPprfSender(u64 domainSize, u64 pointCount)
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


        void setBase(span<const std::array<block, 2>> baseMessages);

        // expand the whole PPRF and store the result in output
        //task<> expand(Socket& chl, block value, PRNG& prng, span<block> output, PprfOutputFormat oFormat, u64 numThreads)
        //{
        //    MatrixView<block> o(output.data(), output.size(), 1);
        //    return expand(chl, value, prng, o, oFormat, numThreads);
        //}


        //task<> expand(
        //    Socket& chl, 
        //    block value, 
        //    PRNG& prng, 
        //    MatrixView<block> output, 
        //    PprfOutputFormat oFormat, 
        //    bool activeChildXorDelta,
        //    u64 numThreads);

        
        task<> expand(Socket& chls, span<const block> value, PRNG& prng, span<block> output, PprfOutputFormat oFormat, bool activeChildXorDelta, u64 numThreads)
        {
            MatrixView<block> o(output.data(), output.size(), 1);
            return expand(chls, value, prng, o, oFormat, activeChildXorDelta, numThreads);
        }

        task<> expand(
            Socket& chl, 
            span<const block> value, 
            PRNG& prng, 
            MatrixView<block> output, 
            PprfOutputFormat oFormat,
            bool activeChildXorDelta,
            u64 numThreads);

        void setValue(span<const block> value);

        void clear();

        struct Expander
        {
            SilentMultiPprfSender& pprf;
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
            std::vector<std::array<block, 4>> lastOts;

            PprfOutputFormat oFormat;

            MatrixView<block> output;

            // The number of real trees for this iteration.
            // Returns the i'th level of the current 8 trees. The 
            // children of node j on level i are located at 2*j and
            // 2*j+1  on level i+1. 
            span<AlignedArray<block, 8>> getLevel(u64 i, u64 g);

            Expander(SilentMultiPprfSender& p, block seed, u64 treeIdx,
                PprfOutputFormat of, MatrixView<block>o, bool activeChildXorDelta, Socket&& s);

            task<> run();
        };

        std::vector<Expander> mExps;
    };


    class SilentMultiPprfReceiver : public TimerAdapter
    {
    public:
        u64 mDomain = 0, mDepth = 0, mPntCount = 0;

        std::vector<u64> mPoints;

        Matrix<block> mBaseOTs;
        Matrix<u8> mBaseChoices;
        bool mPrint = false;
        TreeAllocator mTreeAlloc;
        block mDebugValue;
        std::function<void(u64 treeIdx, span<AlignedArray<block, 8>>)> mOutputFn;

        SilentMultiPprfReceiver() = default;
        SilentMultiPprfReceiver(const SilentMultiPprfReceiver&) = delete;
        SilentMultiPprfReceiver(SilentMultiPprfReceiver&&) = delete;
        //SilentMultiPprfReceiver(u64 domainSize, u64 pointCount);

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
        BitVector sampleChoiceBits(u64 modulus, PprfOutputFormat format, PRNG& prng);

        // choices is in the same format as the output from sampleChoiceBits.
        void setChoiceBits(PprfOutputFormat format, BitVector choices);

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


        void setBase(span<const block> baseMessages);

        std::vector<u64> getPoints(PprfOutputFormat format)
        {
            std::vector<u64> pnts(mPntCount);
            getPoints(pnts, format);
            return pnts;
        }
        void getPoints(span<u64> points, PprfOutputFormat format);

        task<> expand(Socket& chl, PRNG& prng, span<block> output, PprfOutputFormat oFormat, bool activeChildXorDelta, u64 numThreads)
        {
            MatrixView<block> o(output.data(), output.size(), 1);
            return expand(chl, prng, o, oFormat, activeChildXorDelta, numThreads);
        }

        // activeChildXorDelta says whether the sender is trying to program the
        // active child to be its correct value XOR delta. If it is not, the
        // active child will just take a random value.
        task<> expand(Socket& chl, PRNG& prng, MatrixView<block> output, PprfOutputFormat oFormat, bool activeChildXorDelta, u64 numThreads);

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
            SilentMultiPprfReceiver& pprf;
            Socket chl;

            bool mActiveChildXorDelta = false;
            std::array<AES, 2> aes;

            PprfOutputFormat oFormat;
            MatrixView<block> output;

            macoro::eager_task<void> mFuture;

            std::vector<span<AlignedArray<block, 8>>> mLevels;

            // mySums will hold the left and right GGM tree sums
             // for each level. For example mySums[5][0]  will
             // hold the sum of the left children for the 5th tree. This
             // sum will be "missing" the children of the active parent.
             // The sender will give of one of the full somes so we can
             // compute the missing inactive child.
            std::array<std::array<block, 8>, 2> mySums;

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

            std::vector<std::array<block, 4>> lastOts;


            // Returns the i'th level of the current 8 trees. The 
            // children of node j on level i are located at 2*j and
            // 2*j+1  on level i+1. 
            span<AlignedArray<block, 8>> getLevel(u64 i, u64 g, bool f = false);


            Expander(SilentMultiPprfReceiver& p, Socket&& s, PprfOutputFormat of, MatrixView<block> o, bool activeChildXorDelta, u64 treeIdx);
            task<> run();
        };

        std::vector<Expander> mExps;
    };
}
#endif

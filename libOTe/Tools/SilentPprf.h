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
            mTrees = {};
            mFreeTrees = {};
            mTreeSize = 0;
            mNumTrees = 0;
        }
    };


    void allocateExpandBuffer(
        u64 depth,
        u64 activeChildXorDelta,
        std::vector<block>& buff,
        span< std::array<std::array<block, 8>, 2>>& sums,
        span< std::array<block, 4>>& last);

    void allocateExpandTree(
        u64 dpeth,
        TreeAllocator& alloc,
        span<AlignedArray<block, 8>>& tree,
        std::vector<span<AlignedArray<block, 8>>>& levels);

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
        
        task<> expand(Socket& chls, span<const block> value, block seed, span<block> output, PprfOutputFormat oFormat, bool activeChildXorDelta, u64 numThreads)
        {
            MatrixView<block> o(output.data(), output.size(), 1);
            return expand(chls, value, seed, o, oFormat, activeChildXorDelta, numThreads);
        }

        task<> expand(
            Socket& chl, 
            span<const block> value, 
            block seed,
            MatrixView<block> output, 
            PprfOutputFormat oFormat,
            bool activeChildXorDelta,
            u64 numThreads);

        void setValue(span<const block> value);

        void clear();

        void expandOne(
            block aesSeed,
            u64 treeIdx,
            bool activeChildXorDelta,
            span<span<AlignedArray<block, 8>>> levels,
            span<std::array<std::array<block, 8>, 2>> sums,
            span<std::array<block, 4>> lastOts
        );
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

        void configure(u64 domainSize, u64 pointCount)
        {
            mDomain = domainSize;
            mDepth = log2ceil(mDomain);
            mPntCount = pointCount;

            mBaseOTs.resize(0, 0);
        }

        // For output format ByLeafIndex or ByTreeIndex, the choice bits it
        // samples are in blocks of mDepth, with mPntCount blocks total (one for
        // each punctured point). For ByLeafIndex these blocks encode the punctured
        // leaf index in big endian, while for ByTreeIndex they are in
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

        task<> expand(Socket& chl, span<block> output, PprfOutputFormat oFormat, bool activeChildXorDelta, u64 numThreads)
        {
            MatrixView<block> o(output.data(), output.size(), 1);
            return expand(chl, o, oFormat, activeChildXorDelta, numThreads);
        }

        // activeChildXorDelta says whether the sender is trying to program the
        // active child to be its correct value XOR delta. If it is not, the
        // active child will just take a random value.
        task<> expand(Socket& chl, MatrixView<block> output, PprfOutputFormat oFormat, bool activeChildXorDelta, u64 numThreads);

        void clear()
        {
            mBaseOTs.resize(0, 0);
            mBaseChoices.resize(0, 0);
            mDomain = 0;
            mDepth = 0;
            mPntCount = 0;
        }

        void expandOne(
            u64 treeIdx,
            bool programActivePath,
            span<span<AlignedArray<block, 8>>> levels,
            span<std::array<std::array<block, 8>, 2>> encSums,
            span<std::array<block, 4>> lastOts);
    };
}
#endif

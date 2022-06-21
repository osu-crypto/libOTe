#pragma once
#include <libOTe/config.h>
#ifdef ENABLE_SILENTOT

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Matrix.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Network/Channel.h>
//#define DEBUG_PRINT_PPRF

namespace osuCrypto
{

    enum class PprfOutputFormat
    {
        Plain,                // One column per tree, one row per leaf
        BlockTransposed,      // One row per tree, one column per leaf
        Interleaved,
        InterleavedTransposed // Bit transposed
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

    class SilentMultiPprfSender : public TimerAdapter
    {
    public:
        u64 mDomain = 0, mDepth = 0, mPntCount = 0;// , mPntCount8;
        std::vector<block> mValue;
        bool mPrint = false;

        std::vector<block> mBuffer;

        Matrix<std::array<block, 2>> mBaseOTs;

        SilentMultiPprfSender() = default;
        SilentMultiPprfSender(const SilentMultiPprfSender&) = delete;
        SilentMultiPprfSender(SilentMultiPprfSender&&) = default;

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
        void expand(Channel& chl, block value, PRNG& prng, span<block> output, PprfOutputFormat oFormat, u64 numThreads)
        {
            MatrixView<block> o(output.data(), output.size(), 1);
            expand(chl, value, prng, o, oFormat, numThreads);
        }


        void expand(Channel& chl, block value, PRNG& prng, MatrixView<block> output, PprfOutputFormat oFormat, u64 numThreads);

        void expand(Channel& chls, span<const block> value, PRNG& prng, span<block> output, PprfOutputFormat oFormat, u64 numThreads)
        {
            MatrixView<block> o(output.data(), output.size(), 1);
            expand(chls, value, prng, o, oFormat, numThreads);
        }
        void expand(Channel& chl, span<const block> value, PRNG& prng, MatrixView<block> output, PprfOutputFormat oFormat, u64 numThreads);


        void setValue(span<const block> value);


        void clear();
    };


    class SilentMultiPprfReceiver : public TimerAdapter
    {
    public:
        u64 mDomain = 0, mDepth = 0, mPntCount = 0;

        Matrix<block> mBaseOTs;
        Matrix<u8> mBaseChoices;
        bool mPrint = false;
        block mDebugValue;

        SilentMultiPprfReceiver() = default;
        SilentMultiPprfReceiver(const SilentMultiPprfReceiver&) = delete;
        SilentMultiPprfReceiver(SilentMultiPprfReceiver&&) = default;
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


        void getPoints(span<u64> points, PprfOutputFormat format);

        void expand(Channel& chl, PRNG& prng, span<block> output, PprfOutputFormat oFormat, u64 numThreads)
        {
            MatrixView<block> o(output.data(), output.size(), 1);
            return expand(chl, prng, o, oFormat, numThreads);
        }
        void expand(Channel& chl, PRNG& prng, MatrixView<block> output, PprfOutputFormat oFormat, u64 numThreads)
        {
            return expand(chl, prng, output, oFormat, true, numThreads);
        }

        // activeChildXorDelta says whether the sender is trying to program the
        // active child to be its correct value XOR delta. If it is not, the
        // active child will just take a random value.
        void expand(Channel& chl, PRNG& prng, MatrixView<block> output, PprfOutputFormat oFormat, bool activeChildXorDelta, u64 numThreads);

        void clear()
        {
            mBaseOTs.resize(0, 0);
            mBaseChoices.resize(0, 0);
            mDomain = 0;
            mDepth = 0;
            mPntCount = 0;
        }

        //void setPoints(span<u64> points);

        //void yeild(Channel& chl, PRNG& prng, span<block> output);
    };
}
#endif

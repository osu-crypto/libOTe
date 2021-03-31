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
        Plain,
        Interleaved,
        InterleavedTransposed
    };

    enum class OTType
    {
        Random, Correlated
    };

    enum class ChoiceBitPacking
    {
        False, True
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

        SilentMultiPprfSender(u64 domainSize, u64 pointCount);

        void configure(u64 domainSize, u64 pointCount);

        
        // the number of base OTs that should be set.
        u64 baseOtCount() const;

        // returns true if the base OTs are currently set.
        bool hasBaseOts() const; 
        

        void setBase(span<std::array<block, 2>> baseMessages);

        // expand the whole PPRF and store the result in output
        block expand(Channel& chl, block value, PRNG& prng, span<block> output, PprfOutputFormat oFormat, bool mal, u64 numThreads)
        {
            MatrixView<block> o(output.data(), output.size(), 1);
            return expand(chl, value, prng, o, oFormat, mal, numThreads);
        }


        block expand(Channel& chl, block value, PRNG& prng, MatrixView<block> output, PprfOutputFormat oFormat, bool mal, u64 numThreads);
        //block expand(span<Channel> chls, block value, PRNG& prng, MatrixView<block> output, PprfOutputFormat oFormat, bool mal);

        block expand(Channel& chls, span<block> value, PRNG& prng, span<block> output, PprfOutputFormat oFormat, bool mal, u64 numThreads)
        {
            MatrixView<block> o(output.data(), output.size(), 1);
            return expand(chls, value, prng, o, oFormat, mal, numThreads);
        }
        block expand(Channel& chl, span<block> value, PRNG& prng, MatrixView<block> output, PprfOutputFormat oFormat, bool mal, u64 numThreads);


        void setValue(span<block> value);

        // expand the next output.size() number of outputs and store the result in output.
        //void yeild(Channel& chl, PRNG& prng, span<block> output);

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

        void configure(u64 domainSize, u64 pointCount);


        BitVector sampleChoiceBits(u64 modulus, PprfOutputFormat format, PRNG& prng);

        // the number of base OTs that should be set.
        u64 baseOtCount() const;

        // returns true if the base OTs are currently set.
        bool hasBaseOts() const;


        void setBase(span<block> baseMessages);


        void getPoints(span<u64> points, PprfOutputFormat format);
		//void getInterleavedPoints(span<u64> points);

        block expand(Channel& chl, PRNG& prng, span<block> output, PprfOutputFormat oFormat, bool mal, u64 numThreads)
        {
            MatrixView<block> o(output.data(), output.size(), 1);
            return expand(chl, prng, o, oFormat, mal, numThreads);
        }
        block expand(Channel& chl, PRNG& prng, MatrixView<block> output, PprfOutputFormat oFormat, bool mal, u64 numThreads);
		//block expand(Channel& chl, PRNG& prng, MatrixView<block> output, PprfOutputFormat oFormat, bool mal);

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
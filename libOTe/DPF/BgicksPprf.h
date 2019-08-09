#pragma once

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Matrix.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Network/Channel.h>
#define DEBUG_PRINT_PPRF

namespace osuCrypto
{
    class BgicksMultiPprfSender : public TimerAdapter
    {
    public:
        u64 mDomain = 0, mDepth = 0, mPntCount = 0;// , mPntCount8;
        block mValue;
        bool mPrint = false;

        
        std::vector<block> mBuffer;

        Matrix<std::array<block, 2>> mBaseOTs;

        BgicksMultiPprfSender() = default;
        BgicksMultiPprfSender(const BgicksMultiPprfSender&) = delete;
        BgicksMultiPprfSender(BgicksMultiPprfSender&&) = default;

        BgicksMultiPprfSender(u64 domainSize, u64 pointCount);

        void configure(u64 domainSize, u64 pointCount);

        
        // the number of base OTs that should be set.
        u64 baseOtCount() const;

        // returns true if the base OTs are currently set.
        bool hasBaseOts() const; 
        

        void setBase(span<std::array<block, 2>> baseMessages);

        // expand the whole PPRF and store the result in output
		block expand(Channel& chl, block value, PRNG& prng, MatrixView<block> output, bool transpose, bool mal);
		block expand(span<Channel> chls, block value, PRNG& prng, MatrixView<block> output, bool transpose, bool mal);


        void setValue(block value);

        // expand the next output.size() number of outputs and store the result in output.
        //void yeild(Channel& chl, PRNG& prng, span<block> output);

    };


    class BgicksMultiPprfReceiver : public TimerAdapter
    {
    public:
        u64 mDomain = 0, mDepth = 0, mPntCount = 0;//, mPntCount8;

        Matrix<block> mBaseOTs;
        Matrix<u8> mBaseChoices;
        bool mPrint = false;
        block mDebugValue;

        BgicksMultiPprfReceiver() = default;
        BgicksMultiPprfReceiver(const BgicksMultiPprfReceiver&) = delete;
        BgicksMultiPprfReceiver(BgicksMultiPprfReceiver&&) = default;
        //BgicksMultiPprfReceiver(u64 domainSize, u64 pointCount);

        void configure(u64 domainSize, u64 pointCount);


        BitVector sampleChoiceBits(u64 modulus, bool tranposed, PRNG& prng);

        // the number of base OTs that should be set.
        u64 baseOtCount() const;

        // returns true if the base OTs are currently set.
        bool hasBaseOts() const;


        void setBase(span<block> baseMessages);


        void getPoints(span<u64> points);
		void getTransposedPoints(span<u64> points);

		block expand(Channel& chl, PRNG& prng, MatrixView<block> output, bool transpose, bool mal);
		block expand(span<Channel> chl, PRNG& prng, MatrixView<block> output, bool transpose, bool mal);


        //void setPoints(span<u64> points);

        //void yeild(Channel& chl, PRNG& prng, span<block> output);
    };
}
#pragma once
#include <libOTe/config.h>
#ifdef ENABLE_SILENT_VOLE

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Common/Timer.h>
#include <libOTe/Tools/Tools.h>
#include <libOTe/Tools/SilentPprf.h>
#include <libOTe/TwoChooseOne/TcoOtDefines.h>
#include <libOTe/TwoChooseOne/OTExtInterface.h>
#include <libOTe/TwoChooseOne/KosOtExtReceiver.h>
#include <libOTe/TwoChooseOne/KosOtExtSender.h>
#include <libOTe/Tools/LDPC/LdpcEncoder.h>

namespace osuCrypto
{


    // For more documentation see SilentOtExtSender.
    class SilentVoleReceiver : public TimerAdapter
    {
    public:
        static constexpr u64 mScaler = 2;

        enum class State
        {
            Default,
            Configured,
            HasBase
        };

        // The current state of the protocol
        State mState = State::Default;

        // The number of OTs the user requested.
        u64 mRequestedNumOTs = 0;

        // The number of OTs actually produced (at least the number requested).
        u64 mN = 0;
        
        // The length of the noisy vectors (2 * mN for the silver codes).
        u64 mN2 = 0;
        
        // We perform regular LPN, so this is the
        // size of the each chunk. 
        u64 mSizePer = 0;

        u64 mNumPartitions = 0;

        // The noisy coordinates.
        std::vector<u64> mS;

        // What type of Base OTs should be performed.
        SilentBaseType mBaseType;

        // The matrix multiplication type which compresses 
        // the sparse vector.
        MultType mMultType = MultType::slv5;

        // The silver encoder.
        SilverEncoder mEncoder;

        // The multi-point punctured PRF for generating
        // the sparse vectors.
        SilentMultiPprfReceiver mGen;

        // The internal buffers for holding the expanded vectors.
        // mA + mB = mC * mD
        span<block> mA;

        std::vector<block> mC;


        std::vector<block> mGapOts;

        u64 mBackingSize = 0;
        std::unique_ptr<block[]> mBacking;

        u64 mNumThreads = 1;

        bool mDebug = false;

        BitVector mIknpSendBaseChoice, mGapBaseChoice;

        SilentSecType mMalType  = SilentSecType::SemiHonest;

        block mMalCheckSeed, mMalCheckX;

#ifdef ENABLE_KOS
        KosOtExtReceiver mKosRecver;
        KosOtExtSender mKosSender;
#endif

        // sets the Iknp base OTs that are then used to extend
        void setBaseOts(
            span<std::array<block, 2>> baseSendOts);

        // return the number of base OTs IKNP needs
        u64 baseOtCount() const;

        // returns true if the IKNP base OTs are currently set.
        bool hasBaseOts() const;

        // returns true if the silent base OTs are set.
        bool hasSilentBaseOts() const {
            return mGen.hasBaseOts();
        };

        // Generate the IKNP base OTs
        void genBaseOts(PRNG& prng, Channel& chl) ;

        // Generate the silent base OTs. If the Iknp 
        // base OTs are set then we do an IKNP extend,
        // otherwise we perform a base OT protocol to
        // generate the needed OTs.
        void genSilentBaseOts(PRNG& prng, Channel& chl);
        
        // configure the silent OT extension. This sets
        // the parameters and figures out how many base OT
        // will be needed. These can then be ganerated for
        // a different OT extension or using a base OT protocol.
        void configure(
            u64 n, 
            u64 secParam = 128);

        // return true if this instance has been configured.
        bool isConfigured() const { return mState != State::Default; }

        // Returns how many base OTs the silent OT extension
        // protocol will needs.
        u64 silentBaseOtCount() const;

        // The silent base OTs must have specially set base OTs.
        // This returns the choice bits that should be used.
        // Call this is you want to use a specific base OT protocol
        // and then pass the OT messages back using setSilentBaseOts(...).
        BitVector sampleBaseChoiceBits(PRNG& prng);

        // Set the externally generated base OTs. This choice
        // bits must be the one return by sampleBaseChoiceBits(...).
        void setSilentBaseOts(span<block> recvBaseOts);

        // Perform the actual OT extension. If silent
        // base OTs have been generated or set, then
        // this function is non-interactive. Otherwise
        // the silent base OTs will automatically be performed.
        void silentReceive(
            span<block> c,
            span<block> a,
            PRNG & prng,
            Channel & chl);

        // Perform the actual OT extension. If silent
        // base OTs have been generated or set, then
        // this function is non-interactive. Otherwise
        // the silent base OTs will automatically be performed.
        void silentReceiveInplace(
            u64 n,
            PRNG& prng,
            Channel& chl);



        // internal.
        void checkRT(Channel& chls) const;

        void ferretMalCheck(
            Channel& chl, 
            block deltaShare,
            span<block> y);

        PprfOutputFormat getPprfFormat()
        {
            return PprfOutputFormat::Interleaved;
        }

        void clear();
    };
}
#endif
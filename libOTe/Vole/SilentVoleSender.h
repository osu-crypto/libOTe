#pragma once
#include <libOTe/config.h>
#ifdef ENABLE_SILENT_VOLE

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Common/Timer.h>
#include <libOTe/Tools/SilentPprf.h>
#include <libOTe/TwoChooseOne/TcoOtDefines.h>
#include <libOTe/TwoChooseOne/KosOtExtSender.h>
#include <libOTe/TwoChooseOne/KosOtExtReceiver.h>
#include <libOTe/TwoChooseOne/OTExtInterface.h>
#include <libOTe/Tools/LDPC/LdpcEncoder.h>
//#define NO_HASH

namespace osuCrypto
{

    class SilentVoleSender : public TimerAdapter
    {
    public:
        static constexpr u64 mScaler = 2;

        enum class State
        {
            Default,
            Configured,
            HasBase
        };


        State mState = State::Default;

        SilentMultiPprfSender mGen;

        u64 mRequestedNumOTs = 0;
        u64 mN2 = 0;
        u64 mN = 0;
        u64 mNumPartitions = 0;
        u64 mSizePer = 0;
        u64 mNumThreads = 1;
        std::vector<std::array<block, 2>> mGapOts;

        block mDelta;

        SilentSecType mMalType = SilentSecType::SemiHonest;

#ifdef ENABLE_KOS
        KosOtExtSender mKosSender;
        KosOtExtReceiver mKosRecver;
#endif
        MultType mMultType = MultType::slv5;
        SilverEncoder mEncoder;


        span<block> mB;

        u64 mBackingSize = 0;
        std::unique_ptr<block[]> mBacking;

        /////////////////////////////////////////////////////
        // The standard OT extension interface
        /////////////////////////////////////////////////////

        // the number of IKNP base OTs that should be set.
        u64 baseOtCount() const;

        // returns true if the IKNP base OTs are currently set.
        bool hasBaseOts() const;

        // sets the IKNP base OTs that are then used to extend
        void setBaseOts(
            span<block> baseRecvOts,
            const BitVector& choices);

        // use the default base OT class to generate the
        // IKNP base OTs that are required.
        void genBaseOts(PRNG& prng, Channel& chl)
        {
            mKosSender.genBaseOts(prng, chl);
        }


        /////////////////////////////////////////////////////
        // The native silent OT extension interface
        /////////////////////////////////////////////////////

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

        // Set the externally generated base OTs. This choice
        // bits must be the one return by sampleBaseChoiceBits(...).
        void setSilentBaseOts(span<std::array<block, 2>> sendBaseOts);

        // The native OT extension interface of silent
        // OT. The receiver does not get to specify 
        // which OT message they receiver. Instead
        // the protocol picks them at random. Use the 
        // send(...) interface for the normal behavior.
        void silentSend(
            block delta,
            span<block> b,
            PRNG& prng,
            Channel& chls);

        // The native OT extension interface of silent
        // OT. The receiver does not get to specify 
        // which OT message they receiver. Instead
        // the protocol picks them at random. Use the 
        // send(...) interface for the normal behavior.
        void silentSendInplace(
            block delta,
            u64 n,
            PRNG& prng,
            Channel& chls);

        bool mDebug = false;

        void checkRT(Channel& chl, span<block> beta) const;

        void ferretMalCheck(Channel& chl, block deltaShare);

        void clear();
    };

}

#endif
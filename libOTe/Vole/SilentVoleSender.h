#pragma once
#include <libOTe/config.h>
#ifdef ENABLE_SILENTOT

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Common/Timer.h>
#include <libOTe/Tools/SilentPprf.h>
#include <libOTe/TwoChooseOne/TcoOtDefines.h>
#include <libOTe/TwoChooseOne/IknpOtExtSender.h>
#include <libOTe/TwoChooseOne/IknpOtExtReceiver.h>
#include <libOTe/TwoChooseOne/OTExtInterface.h>
#include <libOTe/Tools/LDPC/LdpcEncoder.h>
//#define NO_HASH

namespace osuCrypto
{

    class SilentVoleSender : public TimerAdapter
    {
    public:

        SilentMultiPprfSender mGen;
        u64 mP, mN2, mN = 0, mNumPartitions, mScaler, mSizePer, mNumThreads;
#ifdef ENABLE_IKNP
        IknpOtExtSender mIknpSender;
        IknpOtExtReceiver mIknpRecver;
#endif
        //MultType mMultType = MultType::ldpc;
        S1DiagRegRepEncoder mEncoder;
        //LdpcEncoder mLdpcEncoder;
        Matrix<block> rT;

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
            const BitVector& choices,
            Channel& chl)
        {
#ifdef ENABLE_IKNP
            mIknpSender.setBaseOts(baseRecvOts, choices, chl);
#else
            throw std::runtime_error("IKNP must be enabled");
#endif
        }

        // Returns an indpendent copy of this extender.
        std::unique_ptr<OtExtSender> split()
        {
            throw std::runtime_error("not impl");
        }

        // use the default base OT class to generate the
        // IKNP base OTs that are required.
        void genBaseOts(PRNG& prng, Channel& chl)
        {
#ifdef ENABLE_IKNP
            mIknpSender.genBaseOts(prng, chl);
#else
            throw std::runtime_error("IKNP must be enabled");
#endif
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
            u64 scaler = 2,
            u64 secParam = 128,
            u64 numThreads = 1);

        // return true if this instance has been configured.
        bool isConfigured() const { return mN > 0; }

        // Returns how many base OTs the silent OT extension
        // protocol will needs.
        u64 silentBaseOtCount() const;

        // Set the externally generated base OTs. This choice
        // bits must be the one return by sampleBaseChoiceBits(...).
        void setSlientBaseOts(span<std::array<block,2>> sendBaseOts);

        // This is an "all-in-one" function that generates the base
        // OTs in various ways.
        void genBase(
            u64 n, Channel& chl, PRNG& prng,
            u64 scaler = 2, u64 secParam = 128,
            SilentBaseType base = SilentBaseType::BaseExtend,
            u64 threads = 1);

        // The native OT extension interface of silent
        // OT. The receiver does not get to specify 
        // which OT message they receiver. Instead
        // the protocol picks them at random. Use the 
        // send(...) interface for the normal behavior.
        //void silentSend(
        //    span<std::array<block, 2>> messages,
        //    PRNG& prng,
        //    Channel& chl);

        // A parallel exection version of the other
        // silentSend(...) function. 
		void silentSend(
            block delta,
            span<block> messages,
			PRNG& prng,
			span<Channel> chls);


        // interal functions

        void ldpcMult(
            block delta,
            Matrix<block>& rT, span<block>& messages, u64 threads);

        bool mDebug = false;
        void checkRT(span<Channel> chls, Matrix<block>& rT);

        void clear();
    };

}

#endif
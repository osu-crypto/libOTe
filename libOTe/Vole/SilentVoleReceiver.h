#pragma once
#include <libOTe/config.h>
#ifdef ENABLE_SILENTOT

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Common/Timer.h>
#include <libOTe/Tools/Tools.h>
#include <libOTe/Tools/SilentPprf.h>
#include <libOTe/TwoChooseOne/TcoOtDefines.h>
#include <libOTe/TwoChooseOne/OTExtInterface.h>
#include <libOTe/TwoChooseOne/IknpOtExtReceiver.h>
#include <libOTe/TwoChooseOne/IknpOtExtSender.h>
#include <libOTe/Tools/LDPC/LdpcEncoder.h>

namespace osuCrypto
{


    // For more documentation see SilentOtExtSender.
    class SilentVoleReceiver : public TimerAdapter
    {
    public:

        u64 mP, mN = 0, mN2, mScaler, mSizePer;
        std::vector<u64> mS;
        block mDelta, mSum;
        SilentBaseType mBaseType;
        bool mDebug = false;
        u64 mNumThreads;
        MultType mMultType = MultType::slv5;

#ifdef ENABLE_IKNP
        IknpOtExtReceiver mIknpRecver;
        IknpOtExtSender mIknpSender;
#endif
        SilentMultiPprfReceiver mGen;

        Matrix<block> rT;

        S1DiagRegRepEncoder mEncoder;

        // sets the Iknp base OTs that are then used to extend
        void setBaseOts(
            span<std::array<block, 2>> baseSendOts,
            PRNG& prng,
            Channel& chl) {
#ifdef ENABLE_IKNP
            mIknpRecver.setBaseOts(baseSendOts, prng, chl);
#else
            throw std::runtime_error("IKNP must be enabled");
#endif
        }

        // return the number of base OTs IKNP needs
        u64 baseOtCount() const {
#ifdef ENABLE_IKNP
            return mIknpRecver.baseOtCount();
#else
            throw std::runtime_error("IKNP must be enabled");
#endif
        }

        // returns true if the IKNP base OTs are currently set.
        bool hasBaseOts() const {
#ifdef ENABLE_IKNP
            return mIknpRecver.hasBaseOts(); 
#else
            throw std::runtime_error("IKNP must be enabled");
#endif
        };

        // Returns an indpendent copy of this extender.
        virtual std::unique_ptr<OtExtReceiver> split() { 
            throw std::runtime_error("not implemented"); };

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
            u64 scaler = 2, 
            u64 secParam = 128,
            u64 numThreads = 1);

        // return true if this instance has been configured.
        bool isConfigured() const { return mN > 0; }

        // Returns how many base OTs the silent OT extension
        // protocol will needs.
        u64 silentBaseOtCount() const;

        // The silent base OTs must have specially set base OTs.
        // This returns the choice bits that should be used.
        // Call this is you want to use a specific base OT protocol
        // and then pass the OT messages back using setSlientBaseOts(...).
        BitVector sampleBaseChoiceBits(PRNG& prng) {
            if (isConfigured() == false)
                throw std::runtime_error("configure(...) must be called first");

            return mGen.sampleChoiceBits(mN2, getPprfFormat(), prng);
        }

        // Set the externally generated base OTs. This choice
        // bits must be the one return by sampleBaseChoiceBits(...).
        void setSlientBaseOts(span<block> recvBaseOts);

        // An "all-in-one" function that generates the silent 
        // base OTs under various parameters. 
        void genBase(u64 n, Channel& chl, PRNG& prng,
            u64 scaler = 2, u64 secParam = 80,
            SilentBaseType base = SilentBaseType::BaseExtend,
            u64 threads = 1);

        // Perform the actual OT extension. If silent
        // base OTs have been generated or set, then
        // this function is non-interactive. Otherwise
        // the silent base OTs will automaticly be performed.
        void silentReceive(
            span<block> choices,
            span<block> messages,
            PRNG & prng,
            Channel & chl);

        // A parallel version of the other silentReceive(...)
        // function.
		void silentReceive(
            span<block> choices,
			span<block> messages,
			PRNG& prng,
			span<Channel> chls);

        // internal.

        void checkRT(span<Channel> chls, Matrix<block> &rT);
        void ldpcMult(Matrix<block> &rT, span<block> &messages, 
            span<block> y, span<block>& choices);
        
        PprfOutputFormat getPprfFormat()
        {
                return PprfOutputFormat::Interleaved;
            /*switch (mMultType)
            {
            case osuCrypto::MultType::Naive:
            case osuCrypto::MultType::QuasiCyclic:
                return PprfOutputFormat::InterleavedTransposed;
                break;
            case osuCrypto::MultType::ldpc:
                break;
            default:
                throw RTE_LOC;
                break;
            }*/
        }

        void clear();
    };

    //Matrix<block> expandTranspose(BgiEvaluator::MultiKey & gen, u64 n);

}
#endif
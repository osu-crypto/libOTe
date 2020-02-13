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

namespace osuCrypto
{

    // Silent OT works a bit different than normal OT extension
    // This stems from that fact that is needs many base OTs which are
    // of chosen message and choosen choice. Normal OT extension 
    // requires about 128 random OTs. 
    // 
    // This is further complicated by the fact that that silent OT
    // naturally samples the choice bits at random while normal OT
    // lets you choose them. Due to this we give two interfaces.
    //
    // The first satisfies the original OT extension interface. That is
    // you can call genBaseOts(...) or setBaseOts(...) just as before
    // and interanlly the implementation will transform these into
    // the required base OTs. You can also directly call send(...) or receive(...)
    // just as before and the receiver can specify the OT messages
    // that they wish to receive. However, using this interface results 
    // in slightly more communication and rounds than are strickly required.
    //
    // The second interface in the "native" silent OT interface.
    // The simplest way to use this interface is to call silentSend(...)
    // and silentReceive(...). This internally will perform all of the 
    // base OTs and output the random OT messages and random OT
    // choice bits. 
    //
    // In particular, 128 base OTs will be performed using the DefaultBaseOT
    // protocol and then these will be extended using IKNP into ~400
    // chosen message OTs which silent OT will then expend into the
    // final OTs. If desired, the caller can actually compute the 
    // base OTs manually. First they must call configure(...) and then
    // silentBaseOtCount() will return the desired number of base OTs.
    // On the receiver side they should use the choice bits returned
    // by sampleBaseChoiceBits(). The base OTs can then be passed back
    // using the setSilentBaseOts(...). silentSend(...) and silentReceive(...)
    // can then be called which results in one message being sent
    // from the sender to the receiver. 
    //
    // Also note that genSilentBaseOts(...) can be called which generates 
    // them. This has two behaviors. If the normal base OTs have previously
    // been set, i.e. the normal OT Ext interface, then and IKNP OT extension
    // is performed to generated the needed ~400 base OTs. If they have not
    // been set then the ~400 base OTs are computed directly using the 
    // DefaultBaseOT protocol. This is much more computationally expensive 
    // but requires fewer rounds than IKNP. 
    class SilentOtExtSender : public OtExtSender, public TimerAdapter
    {
    public:

        SilentMultiPprfSender mGen;
        u64 mP, mN2, mN = 0, mNumPartitions, mScaler, mSizePer, mNumThreads;
        IknpOtExtSender mIknpSender;

        /////////////////////////////////////////////////////
        // The standard OT extension interface
        /////////////////////////////////////////////////////

        // the number of IKNP base OTs that should be set.
        u64 baseOtCount() const override;

        // returns true if the IKNP base OTs are currently set.
        bool hasBaseOts() const override;

        // sets the IKNP base OTs that are then used to extend
        void setBaseOts(
            span<block> baseRecvOts,
            const BitVector& choices,
            Channel& chl) override
        {
            mIknpSender.setBaseOts(baseRecvOts, choices, chl);
        }

        // Returns an indpendent copy of this extender.
        std::unique_ptr<OtExtSender> split() override
        {
            throw std::runtime_error("not impl");
        }

        // use the default base OT class to generate the
        // IKNP base OTs that are required.
        void genBaseOts(PRNG& prng, Channel& chl) override
        {
            mIknpSender.genBaseOts(prng, chl);
        }

        // Perform OT extension of random OT messages but
        // allow the receiver to specify the choice bits.
        void send(
            span<std::array<block, 2>> messages,
            PRNG& prng,
            Channel& chl) override;


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
        void silentSend(
            span<std::array<block, 2>> messages,
            PRNG& prng,
            Channel& chl);

        // A parallel exection version of the other
        // silentSend(...) function. 
		void silentSend(
			span<std::array<block, 2>> messages,
			PRNG& prng,
			span<Channel> chls);


        // interal functions

        void randMulNaive(Matrix<block>& rT, span<std::array<block, 2>>& messages);
        void randMulQuasiCyclic(Matrix<block>& rT, span<std::array<block, 2>>& messages, u64 threads);

        bool mDebug = false;
        void checkRT(span<Channel> chls, Matrix<block>& rT);

        void clear();
    };

    void bitShiftXor(span<block> dest, span<block> in, u8 bitShift);
    void modp(span<block> dest, span<block> in, u64 p);

}

#endif
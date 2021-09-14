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
#include <libOTe/TwoChooseOne/KosOtExtSender.h>
#include <libOTe/TwoChooseOne/KosOtExtReceiver.h>
#include <libOTe/TwoChooseOne/OTExtInterface.h>
#include <libOTe/Tools/LDPC/LdpcEncoder.h>

namespace osuCrypto
{

    // Silent OT works a bit different than normal OT extension
    // This stems from that fact that is needs many base OTs which are
    // of chosen message and chosen choice. Normal OT extension 
    // requires about 128 random OTs. 
    // 
    // This is further complicated by the fact that silent OT
    // naturally samples the choice bits at random while normal OT
    // lets you choose them. Due to this we give two interfaces.
    //
    // The first satisfies the original OT extension interface. That is
    // you can call genBaseOts(...) or setBaseOts(...) just as before
    // and internally the implementation will transform these into
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


        // the number of OTs being requested.
        u64 mRequestNumOts = 0;

        // The prime for QuasiCycic encoding
        u64 mP = 0;

        // The sparse vector size, this will be mN * mScaler.
        u64 mN2 = 0;
        
        // The dense vector size, this will be at least as big as mRequestedNumOts.
        u64 mN = 0;
        
        // The number of regular section of the sparse vector.
        u64 mNumPartitions = 0;
        
        // The size of each regular section of the sparse vector.
        u64 mSizePer = 0;
        
        // The scaling factor that the sparse vector will be compressed by.
        u64 mScaler = 2;

        // The B vector in the relation A + B = C * delta
        span<block> mB;

        // The delta scaler in the relation A + B = C * delta
        block mDelta;

        // The number of threads that should be used (when applicable).
        u64 mNumThreads = 1;

#ifdef ENABLE_KOS
        // Kos instance used to generate the base OTs.
        KosOtExtSender mKosSender;
#endif

        // The ggm tree thats used to generate the sparse vectors.
        SilentMultiPprfSender mGen;

        // The type of compress we will use to generate the
        // dense vectors from the sparse vectors.
        MultType mMultType = MultType::slv5;

        // The flag which controls whether the malicious check is performed.
        SilentSecType mMalType = SilentSecType::SemiHonest;

        // The Silver encoder for MultType::slv5, MultType::slv11
        SilverEncoder mEncoder;

        // The OTs send msgs which will be used to flood the
        // last gap bits of the noisy vector for the slv code.
        std::vector<std::array<block, 2>> mGapOts;

        // The OTs send msgs which will be used to create the 
        // secret share of xa * delta as described in ferret.
        std::vector<std::array<block, 2>> mMalCheckOts;

        // The memory backing mB
        std::unique_ptr<block[]> mBacking;

        // The size of the memory backing mB
        u64 mBackingSize = 0;

        // A flag that helps debug
        bool mDebug = false;


        virtual ~SilentOtExtSender() = default;

        /////////////////////////////////////////////////////
        // The standard OT extension interface
        /////////////////////////////////////////////////////

        // the number of IKNP base OTs that should be set.
        u64 baseOtCount() const override;

        // returns true if the IKNP base OTs are currently set.
        bool hasBaseOts() const override;

        void setBaseOts(
            span<block> baseRecvOts,
            const BitVector& choices);

        // sets the IKNP base OTs that are then used to extend
        void setBaseOts(
            span<block> baseRecvOts,
            const BitVector& choices,
            Channel& chl);

        void setBaseOts(
            span<block> baseRecvOts,
            const BitVector& choices,
            PRNG& prng,
            Channel& chl) override
        {
            setBaseOts(baseRecvOts, choices, chl);
        }

        // Returns an independent copy of this extender.
        std::unique_ptr<OtExtSender> split() override;

        // use the default base OT class to generate the
        // IKNP base OTs that are required.
        void genBaseOts(PRNG& prng, Channel& chl) override;

        // Perform OT extension of random OT messages but
        // allow the receiver to specify the choice bits.
        void send(
            span<std::array<block, 2>> messages,
            PRNG& prng,
            Channel& chl) override;


        /////////////////////////////////////////////////////
        // The native silent OT extension interface
        /////////////////////////////////////////////////////


        bool hasSilentBaseOts() const
        {
            return mGen.hasBaseOts();
        }

        // Generate the silent base OTs. If the Iknp 
        // base OTs are set then we do an IKNP extend,
        // otherwise we perform a base OT protocol to
        // generate the needed OTs.
        void genSilentBaseOts(PRNG& prng, Channel& chl);

        // configure the silent OT extension. This sets
        // the parameters and figures out how many base OT
        // will be needed. These can then be ganerated for
        // a different OT extension or using a base OT protocol.
        // @n        [in] - the number of OTs.
        // @scaler   [in] - the compression factor.
        // @nThreads [in] - the number of threads.
        // @mal      [in] - whether the malicious check is performed.
        void configure(
            u64 n,
            u64 scaler = 2,
            u64 numThreads = 1,
            SilentSecType malType = SilentSecType::SemiHonest);

        // return true if this instance has been configured.
        bool isConfigured() const { return mN > 0; }

        // Returns how many base OTs the silent OT extension
        // protocol will needs.
        u64 silentBaseOtCount() const;

        // Set the externally generated base OTs. This choice
        // bits must be the one return by sampleBaseChoiceBits(...).
        void setSilentBaseOts(span<std::array<block,2>> sendBaseOts);


        // Runs the silent random OT protocol and outputs b.
        // Then this will generate random OTs, where c is a random 
        // bit vector and a[i] = b[i][c[i]].
        // @ b   [out] - the random ot message.
        // @prng  [in] - randomness source.
        // @chl   [in] - the comm channel
        void silentSend(
            span<std::array<block, 2>> b,
            PRNG& prng,
            Channel& chl);

        // Runs the silent correlated OT protocol and outputs b.
        // The protocol takes as input the desired delta value.
        // The outputs will have the relation:
        //      a[i] = b[i] + c[i] * delta.
        // @ d    [in] - the delta used in the correlated OT
        // @ b   [out] - the correlated ot message.
        // @prng  [in] - randomness source.
        // @chl   [in] - the comm channel
        void silentSend(
            block d,
            span<block> b,
            PRNG& prng,
            Channel& chl);

        // Runs the silent correlated OT protocol and store
        // the b vector internally as mB. The protocol takes 
        // as input the desired delta value. The outputs will 
        // have the relation:
        //     a[i] = b[i] + c[i] * delta.
        // @ d    [in] - the delta used in the correlated OT
        // @ n    [in] - the number of correlated ot message.
        // @prng  [in] - randomness source.
        // @chl   [in] - the comm channel
        void silentSendInplace(
            block d,
            u64 n,
            PRNG& prng,
            Channel& chl);

        // internal functions


        // Runs the malicious consistency check as described 
        // by the ferret paper. We only run the batch check and
        // not the cuckoo hashing part.
        void ferretMalCheck(Channel& chl, PRNG& prng);

        // the QuasiCyclic compression routine.
        void randMulQuasiCyclic();

        // the Silver compress routine.
        void ldpcMult();

        void hash(span<std::array<block, 2>> messages, ChoiceBitPacking type);

        // a debugging check on the sparse vector. Insecure to use.
        void checkRT(Channel& chls);

        // clears the internal buffers.
        void clear();
    };


}

#endif

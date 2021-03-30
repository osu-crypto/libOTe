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
#include <libOTe/Tools/LDPC/LdpcEncoder.h>

namespace osuCrypto
{


    // For more documentation see SilentOtExtSender.
    class SilentOtExtReceiver : public OtExtReceiver, public TimerAdapter
    {
    public:
        // The prime for QuasiCycic encoding
        u64 mP = 0;

        // the number of OTs being requested.
        u64 mRequestedNumOts = 0;

        // The dense vector size, this will be at least as big as mRequestedNumOts.
        u64 mN = 0;

        // The sparse vector size, this will be mN * mScaler.
        u64 mN2 = 0;

        // The scaling factor that the sparse vector will be compressed by.
        u64 mScaler = 2;

        // The size of each regular section of the sparse vector.
        u64 mSizePer = 0;

        // The indices of the noisy locations in the sparse vector.
        std::vector<u64> mS;

        // The delta that will be used in the relation A + B = C * delta
        block mDelta;

        // The A vector in the relation A + B = C * delta
        span<block> mA;

        // The C vector in the relation A + B = C * delta
        span<u8> mC;

        // The number of threads that should be used (when applicable).
        u64 mNumThreads;

        // The memory backing mC
        std::unique_ptr<u8[]> mChoicePtr;

        // The size of the memory backing mC
        u64 mChoiceSpanSize = 0;

        // The memory backing mA
        std::unique_ptr<block[]> mBacking;

        // The size of the memory backing mA
        u64 mBackingSize = 0;

#ifdef ENABLE_IKNP

        // Iknp instance used to generate the base OTs.
        IknpOtExtReceiver mIknpRecver;
#endif

        // The ggm tree thats used to generate the sparse vectors.
        SilentMultiPprfReceiver mGen;

        // The type of compress we will use to generate the
        // dense vectors from the sparse vectors.
        MultType mMultType = MultType::slv5;

        // The Silver encoder for MultType::slv5, MultType::slv11
        S1DiagRegRepEncoder mEncoder;
        
        // A flag that helps debug
        bool mDebug = false;

        /////////////////////////////////////////////////////
        // The standard OT extension interface
        /////////////////////////////////////////////////////

        // sets the Iknp base OTs that are then used to extend
        void setBaseOts(
            span<std::array<block, 2>> baseSendOts,
            PRNG& prng,
            Channel& chl) override;

        // return the number of base OTs IKNP needs
        u64 baseOtCount() const override;

        // returns true if the IKNP base OTs are currently set.
        bool hasBaseOts() const override;

        // Generate the IKNP base OTs
        void genBaseOts(PRNG& prng, Channel& chl) override;

        // Returns an indpendent copy of this extender.
        std::unique_ptr<OtExtReceiver> split() override {

            auto ptr = new SilentOtExtReceiver;
            auto ret = std::unique_ptr<OtExtReceiver>(ptr);
            ptr->mIknpRecver = mIknpRecver.splitBase();
            return ret;
        };


        // The default API for OT ext allows the 
        // caller to choose the choice bits. But
        // silent OT picks the choice bits at random.
        // To meet the original API we add communication
        // and correct the random choice bits to the 
        // provided ones... Use silentReceive(...) for 
        // the silent OT API.
        void receive(
            const BitVector& choices,
            span<block> messages,
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


        // Runs the silent OT protocol and outputs c, a.
        // If type == OTType::random, then this will generate
        // random OTs, where c is a random bit vector
        // and a[i] = H(b[i] + c[i] * delta).
        // If type ==OTType::Correlated, then 
        // a[i] = b[i] + c[i] * delta.
        void silentReceive(
            BitVector& c,
            span<block> a,
            PRNG& prng,
            Channel& chl,
            OTType type = OTType::Random);

        // Runs the silent OT protocol and store the a,c
        // vectors internally as mA, mC. Hashing is not applied
        // and therefore we have mA + mB = mC * delta.
        // If type = ChoiceBitPacking::True, then mC will not 
        // be generated. Instead the least significant bit of mA
        // will hold the choice bits. 
        void silentReceiveInplace(
            u64 n,
            PRNG& prng,
            Channel& chls,
            ChoiceBitPacking type = ChoiceBitPacking::False);


        // hash the internal vectors and store the results
        // in choices, messages.
        void hash(
            BitVector& choices,
            span<block> messages,
            ChoiceBitPacking type);

        // internal.
        void checkRT(Channel& chl, MatrixView<block> rT);
        void randMulQuasiCyclic(ChoiceBitPacking packing);
        void ldpcMult(ChoiceBitPacking packing);     
        PprfOutputFormat getPprfFormat()
        {
            switch (mMultType)
            {
            case osuCrypto::MultType::QuasiCyclic:
                return PprfOutputFormat::InterleavedTransposed;
                break;
            case osuCrypto::MultType::slv5:
            case osuCrypto::MultType::slv11:
                return PprfOutputFormat::Interleaved;
                break;
            default:
                throw RTE_LOC;
                break;
            }
        }

        // clears the internal buffers.
        void clear();
    };

    inline u8 parity(block b)
    {
        b = b ^ (b >> 1);
        b = b ^ (b >> 2);
        b = b ^ (b >> 4);
        b = b ^ (b >> 8);
        b = b ^ (b >> 16);
        b = b ^ (b >> 32);

        union blocku64
        {
            block b;
            u64 u[2];
        };
        auto bb = reinterpret_cast<u64*>(&b);
        return (bb[0] ^ bb[1]) & 1;
    }

    inline     void transpose(span<block> s, MatrixView<block> r)
    {
        MatrixView<u8> ss((u8*)s.data(), s.size(), sizeof(block));
        MatrixView<u8> rr((u8*)r.data(), r.rows(), r.cols() * sizeof(block));

        transpose(ss, rr);
    }

}
#endif
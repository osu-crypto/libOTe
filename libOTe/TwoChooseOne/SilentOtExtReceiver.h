#pragma once
#include <libOTe/config.h>
#ifdef ENABLE_SILENTOT

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Common/Timer.h>
#include <libOTe/Tools/Tools.h>
#include <libOTe/Tools/SilentPprf.h>
#include <libOTe/TwoChooseOne/TcoOtDefines.h>
#include <libOTe/TwoChooseOne/IknpOtExtReceiver.h>

namespace osuCrypto
{
    enum class MultType
    {
        Naive,
        QuasiCyclic
    };

    // For more documentation see SilentOtExtSender.
    class SilentOtExtReceiver : public OtExtReceiver, public TimerAdapter
    {
    public:

        u64 mP, mN = 0, mN2, mScaler, mSizePer;
        std::vector<u64> mS;
        block mDelta, mSum;
        SilentBaseType mBaseType;
        bool mDebug = false;
        u64 mNumThreads;
        IknpOtExtReceiver mIknpRecver;
        SilentMultiPprfReceiver mGen;

        // sets the Iknp base OTs that are then used to extend
        void setBaseOts(
            span<std::array<block, 2>> baseSendOts,
            PRNG& prng,
            Channel& chl) override {
            mIknpRecver.setBaseOts(baseSendOts, prng, chl);
        }

        // return the number of base OTs IKNP needs
        u64 baseOtCount() const override {
            return mIknpRecver.baseOtCount();
        }

        // returns true if the IKNP base OTs are currently set.
        bool hasBaseOts() const override { 
            return mIknpRecver.hasBaseOts(); 
        };

        // Returns an indpendent copy of this extender.
        virtual std::unique_ptr<OtExtReceiver> split() { 
            throw std::runtime_error("not implemented"); };

        // Generate the IKNP base OTs
        void genBaseOts(PRNG& prng, Channel& chl) override;

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
            return mGen.sampleChoiceBits(mN2, true, prng);
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

        // The default API for OT ext allows the 
        // caller to choose the choice bits. But
        // silent OT picks the choice bits at random.
        // To meet the original API we add communicatio
        // and correct the random choice bits to the 
        // provided ones... Use silentReceive(...) for 
        // the silent OT API.
        void receive(
            const BitVector& choices,
            span<block> messages,
            PRNG& prng,
            Channel& chl) override;

        // Perform the actual OT extension. If silent
        // base OTs have been generated or set, then
        // this function is non-interactive. Otherwise
        // the silent base OTs will automaticly be performed.
        void silentReceive(
            BitVector& choices,
            span<block> messages,
            PRNG & prng,
            Channel & chl);

        // A parallel version of the other silentReceive(...)
        // function.
		void silentReceive(
            BitVector& choices,
			span<block> messages,
			PRNG& prng,
			span<Channel> chls);

        // internal.

        void checkRT(span<Channel> chls, Matrix<block> &rT);
        void randMulNaive(Matrix<block> &rT, span<block> &messages);
        void randMulQuasiCyclic(Matrix<block> &rT, span<block> &messages, BitVector& choices, u64 threads);
        
        void clear();
    };

    //Matrix<block> expandTranspose(BgiEvaluator::MultiKey & gen, u64 n);


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

    inline void mulRand(PRNG &pubPrng, span<block> mtxColumn, Matrix<block> &rT, BitIterator iter)
    {
        pubPrng.get(mtxColumn.data(), mtxColumn.size());

        //convertCol(mtx, i, mtxColumn);
        std::array<block, 8> sum, t;
        auto end = (rT.cols() / 8) * 8;

        for (u64 j = 0; j < 128; ++j)
        {
            auto row = rT[j];

            sum[0] = sum[0] ^ sum[0];
            sum[1] = sum[1] ^ sum[1];
            sum[2] = sum[2] ^ sum[2];
            sum[3] = sum[3] ^ sum[3];
            sum[4] = sum[4] ^ sum[4];
            sum[5] = sum[5] ^ sum[5];
            sum[6] = sum[6] ^ sum[6];
            sum[7] = sum[7] ^ sum[7];

            if (true)
            {

                for (u64 k = 0; k < end; k += 8)
                {
                    t[0] = row[k + 0] & mtxColumn[k + 0];
                    t[1] = row[k + 1] & mtxColumn[k + 1];
                    t[2] = row[k + 2] & mtxColumn[k + 2];
                    t[3] = row[k + 3] & mtxColumn[k + 3];
                    t[4] = row[k + 4] & mtxColumn[k + 4];
                    t[5] = row[k + 5] & mtxColumn[k + 5];
                    t[6] = row[k + 6] & mtxColumn[k + 6];
                    t[7] = row[k + 7] & mtxColumn[k + 7];


                    sum[0] = sum[0] ^ t[0];
                    sum[1] = sum[1] ^ t[1];
                    sum[2] = sum[2] ^ t[2];
                    sum[3] = sum[3] ^ t[3];
                    sum[4] = sum[4] ^ t[4];
                    sum[5] = sum[5] ^ t[5];
                    sum[6] = sum[6] ^ t[6];
                    sum[7] = sum[7] ^ t[7];

                }

                for (i64 k = end; k < row.size(); ++k)
                    sum[0] = sum[0] ^ (row[k] & mtxColumn[k]);

                sum[0] = sum[0] ^ sum[1];
                sum[2] = sum[2] ^ sum[3];
                sum[4] = sum[4] ^ sum[5];
                sum[6] = sum[6] ^ sum[7];

                sum[0] = sum[0] ^ sum[2];
                sum[4] = sum[4] ^ sum[6];

                sum[0] = sum[0] ^ sum[4];
            }
            else
            {
                for (i64 k = 0; k < row.size(); ++k)
                    sum[0] = sum[0] ^ (row[k] & mtxColumn[k]);
            }

            *iter = parity(sum[0]);
            ++iter;
        }
    }

    inline     void sse_transpose(span<block> s, Matrix<block>& r)
    {
        MatrixView<u8> ss((u8*)s.data(), s.size(), sizeof(block));
        MatrixView<u8> rr((u8*)r.data(), r.rows(), r.cols() * sizeof(block));

        sse_transpose(ss, rr);
    }

}
#endif
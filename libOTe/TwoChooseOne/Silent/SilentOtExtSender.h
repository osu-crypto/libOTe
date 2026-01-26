#pragma once
// © 2020 Peter Rindal.
// © 2022 Visa.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// This code implements features described in [Silver: Silent VOLE and Oblivious Transfer from Hardness of Decoding Structured LDPC Codes, https://eprint.iacr.org/2021/1150]; the paper is licensed under Creative Commons Attribution 4.0 International Public License (https://creativecommons.org/licenses/by/4.0/legalcode).

#include <libOTe/config.h>
#ifdef ENABLE_SILENTOT

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Common/Timer.h>
#include <libOTe/Tools/Pprf/StationaryPprf.h>
#include <libOTe/TwoChooseOne/TcoOtDefines.h>
#include <libOTe/TwoChooseOne/SoftSpokenOT/SoftSpokenMalOtExt.h>
#include <libOTe/TwoChooseOne/OTExtInterface.h>
#include <libOTe/Tools/Coproto.h>
#include "libOTe/Tools/EACode/EACode.h"
#include "libOTe/Tools/ExConvCode/ExConvCode.h"
#include "SilentOtExtUtil.h"

namespace osuCrypto
{
    /**
     * @brief Sender implementation for Silent OT Extension protocol.
     *
     * Silent OT works differently than traditional OT extension protocols.
     * While traditional OT extension requires ~128 random base OTs, Silent OT
     * needs many base OTs with chosen messages and choice bits.
     *
     * This is further complicated by the fact that silent OT
     * naturally samples the choice bits at random while normal OT
     * lets you choose them. Due to this we give two interfaces:
     * 1. Standard OT extension interface (inherited from OtExtSender)
     * 2. Native Silent OT interface with specialized methods
     *
     * The first satisfies the original OT extension interface. That is
     * you can call genBaseOts(...) or setBaseOts(...) just as before
     * and internally the implementation will transform these into
     * the required base OTs. You can also directly call send(...) or receive(...)
     * just as before and the receiver can specify the OT mMessages
     * that they wish to receive. However, using this interface results 
     * in slightly more communication and rounds than are strictly required.
     * 
     * The second interface in the "native" silent OT interface.
     * The simplest way to use this interface is to call silentSend(...)
     * and silentReceive(...). This internally will perform all of the 
     * base OTs and output the random OT mMessages and random OT
     * choice bits. 
     * 
     * In particular, 128 base OTs will be performed using the DefaultBaseOT
     * protocol and then these will be extended using Softspoken into ~400
     * chosen message OTs which silent OT will then expend into the
     * final OTs. If desired, the caller can compute the 
     * base OTs manually and set them via setBaseCors. First they must call 
     * configure(...) and then baseCount() will return the desired number of 
     * base OTs and base VOLEs if stationary is used.
     * 
     * On the receiver side they should use the choice bits returned
     * by sampleBaseChoiceBits(). The base OTs can then be passed back
     * using the setBaseCors(...). silentSend(...) and silentReceive(...)
     * can then be called which results in one message being sent
     * from the sender to the receiver. 
     *
     * Also note that genBaseCors(...) can be called which generates 
     * them. This has two behaviors. If the normal base OTs have previously
     * been set, i.e. the normal OT Ext interface, then and IKNP OT extension
     * is performed to generated the needed ~400 base OTs. If they have not
     * been set then the ~400 base OTs are computed directly using the 
     * DefaultBaseOT protocol. This is much more computationally expensive 
     * but requires fewer rounds than IKNP. 
     * 
     * This implementation supports two noise distribution models:
     * 1. Regular noise - Base OTs are used for each execution
     * 2. Stationary noise - Base OTs and VOLEs can be reused across executions
     *    with the same delta value
     *
     * For most efficient usage with stationary noise distribution, the protocol
     * requires base VOLE correlations of the form:
     *    baseA = baseB + baseC * delta
     * where delta is the same value used throughout the protocol.
     * 
	 * See frontend/ExampleSilent.cpp for an example of how to use this class.
     * 
     */
    class SilentOtExtSender : public OtExtSender, public TimerAdapter
    {
    public:


        // the number of OTs being requested.
        u64 mRequestNumOts = 0;

        // The sparse vector size, this will be ~ mN * mScaler.
        u64 mNoiseVecSize = 0;
        
        // The number of regular section of the sparse vector.
        u64 mNumPartitions = 0;
        
        // The size of each regular section of the sparse vector.
        u64 mSizePer = 0;
        
        // The B vector in the relation A + B = C * delta
        AlignedUnVector<block> mB;

        // The delta scaler in the relation A + B = C * delta
        std::optional<block> mDelta;

        // The number of threads that should be used (when applicable).
        u64 mNumThreads = 1;

#ifdef ENABLE_SOFTSPOKEN_OT
        // ot extension instance used to generate the base OTs.
        macoro::optional<SoftSpokenMalOtSender> mOtExtSender;
#endif


        // The PPRF used to generate the noise vector
        // Variant allows selecting between Regular and Stationary PPRF
        std::variant<
            RegularPprfSender<block, CoeffCtxGF2>,
            StationaryPprfSender<block, CoeffCtxGF2>
        > mGenVar;

        // The type of compress we will use to generate the
        // dense vectors from the sparse vectors.
        MultType mLpnMultType = DefaultMultType;

        // The flag which controls whether the malicious check is performed.
        SilentSecType mSecurityType = SilentSecType::SemiHonest;

        SdNoiseDistribution mNoiseDist = SdNoiseDistribution::Regular;

        PprfOutputFormat mPprfFormat = PprfOutputFormat::ByTreeIndex;

        block mCodeSeed = ZeroBlock; 

        // The OTs send msgs which will be used to create the 
        // secret share of xa * delta as described in ferret.
        std::vector<std::array<block, 2>> mMalCheckOts;

        // An temporary buffer used during LPN encoding.
        AlignedUnVector<block> mEncodeTemp;

        // for stationary, this is used to store the B vector.
        AlignedUnVector<block> mBaseB;

        // A flag that helps debug
        bool mDebug = false;

        virtual ~SilentOtExtSender() = default;

        /////////////////////////////////////////////////////
        // The standard OT extension interface
        /////////////////////////////////////////////////////

        /**
         * @brief Returns the number of "softspoken base OTs" required.
         *
         * @return Number of base OTs needed
         */
        u64 baseOtCount() const override;

        /**
         * @brief Checks if the required "softspoken base OTs" are set.
         *
         * @return True if base OTs are set, false otherwise
         */
        bool hasBaseOts() const override;

        /**
         * @brief Sets the base OTs for IKNP OT extension.
         *
         * @param baseRecvOts The base OT messages received
         * @param choices The choice bits used for the base OTs
         */
        void setBaseOts(
            span<block> baseRecvOts,
            const BitVector& choices)override;

        /**
         * @brief Creates an independent copy of this extender.
         *
         * @return Unique pointer to the new OT extender
         */
        std::unique_ptr<OtExtSender> split() override;

        /**
         * @brief Generates the required IKNP base OTs.
         *
         * Uses the default base OT protocol to generate base OTs.
         *
         * @param prng Source of randomness
         * @param chl Communication channel
         * @return Task that completes when base OTs are generated
         */
        task<> genBaseOts(PRNG& prng, Socket& chl) override;

        /**
         * @brief Performs OT extension with receiver-specified choice bits.
         *
         * @param messages Output buffer for the OT messages
         * @param prng Source of randomness
         * @param chl Communication channel
         * @return Task that completes when OT extension is done
         */
        task<> send(
            span<std::array<block, 2>> messages,
            PRNG& prng,
            Socket& chl) override;


        /////////////////////////////////////////////////////
        // The native silent OT extension interface
        /////////////////////////////////////////////////////


        /**
         * @brief Checks if the required base correlations are available.
         *
         * For regular noise, only checks base OTs.
         * For stationary noise, checks both base OTs and base VOLEs.
         *
         * @return True if required base correlations are set
         */
        bool hasBaseCors() const
        {
            return gen().hasBaseOts() &&
                (mNoiseDist == SdNoiseDistribution::Regular || 
                    mBaseB.size() == mNumPartitions);
        }

        /**
         * @brief Generates base correlations (OTs and VOLEs) for Silent OT.
         *
         * When using stationary noise, this generates base VOLE correlations
         * using the provided delta value, which must be consistent across
         * multiple protocol executions.
         *
         * @param delta The delta value for VOLE correlations (optional)
         * @param prng Source of randomness
         * @param chl Communication channel
         * @param useOtExtension Whether to use OT extension for base OTs
         * @return Task that completes when base correlations are generated
         */
        task<> genBaseCors(std::optional<block> delta, PRNG& prng, Socket& chl, bool useOtExtension = true);

        /**
         * @brief Configures the Silent OT extension parameters.
         *
         * Sets up parameters and determines how many base correlations will be needed.
         * These base correlations can be generated through various means and then
         * passed back via setBaseCors().
         *
         * @param n Number of OTs to generate
         * @param scaler Compression factor (default 2)
         * @param numThreads Number of threads to use (default 1)
         * @param malType Security type (default SemiHonest)
         * @param noise Noise distribution type (default Regular)
		 * @param compressionMatrix Compression matrix type (default DefaultMultType)
         */
        void configure(
            u64 n,
            u64 scaler = 2,
            u64 numThreads = 1,
            SilentSecType malType = SilentSecType::SemiHonest,
            SdNoiseDistribution noise = SdNoiseDistribution::Regular,
            MultType compressionMatrix = DefaultMultType);

        /**
         * @brief Checks if this instance has been configured.
         *
         * @return True if configured, false otherwise
         */
        bool isConfigured() const { return mRequestNumOts > 0; }

        /**
         * @brief Returns the number of base correlations needed.
         *
         * @return SilentBaseCount struct containing counts for base OTs and VOLEs
         */
        SilentBaseCount baseCount() const;

        /**
         * @brief Sets externally generated base OTs and VOLEs.
         *
         * For stationary noise, baseB represents the B vector in the base VOLE correlation:
         *    baseA = baseB + baseC * delta
         *
         * where delta should match the same value used throughout the protocol.
         *
         * @param sendBaseOts Base OT messages to send
         * @param baseB B values of base VOLE correlations (for stationary noise)
         * @param delta The delta value used for VOLE correlations
         */
        void setBaseCors(
            span<const std::array<block,2>> sendBaseOts,
            span<const block> baseB,
            block delta);


        /**
         * @brief Performs Silent random OT protocol and outputs messages.
         *
         * Generates random OTs where the receiver gets random choice bits c
         * and messages a[i] = b[i][c[i]].
         *
         * @param b Output buffer for the random OT messages
         * @param prng Source of randomness
         * @param chl Communication channel
         * @return Task that completes when OT is done
         */
        task<> silentSend(
            span<std::array<block, 2>> b,
            PRNG& prng,
            Socket& chl);

        /**
         * @brief Performs Silent correlated OT protocol and outputs messages.
         *
         * Generates correlated OTs with the relation:
         *    a[i] = b[i] + c[i] * delta
         *
         * @param d The delta correlation value (optional)
         * @param b Output buffer for correlated OT messages
         * @param prng Source of randomness
         * @param chl Communication channel
         * @return Task that completes when OT is done
         */
		task<> silentSend(
            std::optional<block> d,
			span<block> b,
			PRNG& prng,
			Socket& chl);

        /**
         * @brief Performs Silent correlated OT protocol with internal storage.
         *
         * Similar to silentSend, but stores the b vector internally as mB.
         * Messages follow the relation:
         *    a[i] = b[i] + c[i] * delta
         *
         * @param d The delta correlation value (optional)
         * @param n Number of OTs to generate
         * @param prng Source of randomness
         * @param chl Communication channel
         * @return Task that completes when OT is done
         */
        task<> silentSendInplace(
            std::optional<block> d,
            u64 n,
            PRNG& prng,
            Socket& chl);

        //////////////////////////////////////////
        // Internal functions
        //////////////////////////////////////////

        /**
         * @brief Performs malicious consistency check as described in Ferret paper.
         *
         * Implements the batch check for malicious security.
         *
         * @param chl Communication channel
         * @param prng Source of randomness
         * @return Task that completes when check is done
         */
        task<> ferretMalCheck(Socket& chl, PRNG& prng);

        /**
         * @brief Compresses the sparse vectors to generate dense vectors.
         *
         * Uses the configured compression method (QuasiCyclic, ExAcc, etc.)
         */
        void compress();

        /**
         * @brief Hashes the OT messages for security.
         *
         * @param messages Output buffer for the hashed messages
         * @param type The choice bit packing format
         */
        void hash(span<std::array<block, 2>> messages, ChoiceBitPacking type);

        /**
         * @brief Debugging check on the sparse vector (insecure for production).
         *
         * @param chls Communication channel
         * @return Task that completes when check is done
         */
        task<> checkRT(Socket& chls);

        /**
         * @brief Clears internal buffers.
         */
        void clear();


        /**
         * @brief Helper function to access the PPRF generator.
         *
         * Returns the appropriate PPRF sender based on noise distribution.
         *
         * @return Reference to the PPRF sender
         */
        PprfSender<block, CoeffCtxGF2>& gen() {
            if (isConfigured() == false)
                throw std::runtime_error("configure(...) must be called first.");
            return std::visit([](auto& v) -> PprfSender<block, CoeffCtxGF2>&{ return v; }, mGenVar);
        }

        /**
         * @brief Const version of the PPRF generator accessor.
         *
         * @return Const reference to the PPRF sender
         */
        const PprfSender<block, CoeffCtxGF2>& gen() const {
            if (isConfigured() == false)
                throw std::runtime_error("configure(...) must be called first.");
            return std::visit([](auto& v) -> const PprfSender<block, CoeffCtxGF2>&{ return v; }, mGenVar);
        }

        template<typename... Args>
        struct always_false { static constexpr bool value = false; };


        // this function has been deleted. 
        template<typename... Args>
        void hasSilentBaseOts(Args...) const {
            static_assert(always_false<Args...>::value, "this function has been removed, use hasBaseCors() instead. The interface has been changed to support stationary SD.");
        }

        // this function has been deleted. 
        template<typename... Args>
        task<> genSilentBaseOts(Args...) {
            static_assert(always_false<Args...>::value, "this function has been removed, use genBaseCors() instead. The interface has been changed to support stationary SD.");
            throw RTE_LOC;
        }

        // this function has been deleted. 
        template<typename... Args>
        u64 silentBaseOtCount(Args...) const {
            static_assert(always_false<Args...>::value, "this function has been removed, use baseCount() instead. The interface has been changed to support stationary SD.");
            throw RTE_LOC;
        }

        // this function has been deleted. 
        template<typename... Args>
        void setSilentBaseOts(Args...) {
            static_assert(always_false<Args...>::value, "this function has been removed, use setBaseCors() instead. The interface has been changed to support stationary SD.");
		}

    };

}

#endif

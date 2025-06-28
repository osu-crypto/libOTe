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
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Common/Aligned.h>
#include <libOTe/Tools/Tools.h>
#include <libOTe/Tools/Pprf/StationaryPprf.h>
#include <libOTe/TwoChooseOne/TcoOtDefines.h>
#include <libOTe/TwoChooseOne/SoftSpokenOT/SoftSpokenMalOtExt.h>
#include <libOTe/Tools/Coproto.h>
#include <libOTe/TwoChooseOne/OTExtInterface.h>
#include "libOTe/Tools/EACode/EACode.h"
#include "libOTe/Tools/ExConvCode/ExConvCode.h"
#include "SilentOtExtUtil.h"

namespace osuCrypto
{

	/**
	 * @brief Receiver implementation for Silent OT Extension protocol.
	 * 
	 * Silent OT works differently than traditional OT extension protocols.
	 * While traditional OT extension requires ~128 random base OTs, Silent OT
	 * needs many base OTs with chosen messages and choice bits.
	 * 
	 * This is further complicated by the fact that silent OT
	 * naturally samples the choice bits at random while normal OT
	 * lets you choose them. Due to this we give two interfaces:
	 * 1. Standard OT extension interface (inherited from OtExtReceiver)
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
	class SilentOtExtReceiver : public OtExtReceiver, public TimerAdapter
	{
	public:
		// the number of OTs being requested.
		u64 mRequestNumOts = 0;

		// The sparse vector size, this will be ~ mN * mScaler.
		u64 mNoiseVecSize = 0;

		// The size of each regular section of the sparse vector.
		u64 mSizePer = 0;

		// The number of regular section of the sparse vector.
		u64 mNumPartitions = 0;

		// The A vector in the relation A + B = C * delta
		AlignedUnVector<block> mA;

		// The C vector in the relation A + B = C * delta
		AlignedUnVector<u8> mC;

		// The number of threads that should be used (when applicable).
		u64 mNumThreads = 1;

#ifdef ENABLE_SOFTSPOKEN_OT
		// the instance used to generate the base OTs.
		macoro::optional<SoftSpokenMalOtReceiver> mOtExtRecver;
#endif

		// The OTs recv msgs which will be used to create the 
		// secret share of xa * delta as described in ferret.
		AlignedUnVector<block> mMalCheckOts;

		// The OTs recv choices which will be used to create the 
		// secret share of xa * delta as described in ferret.
		BitVector mMalCheckChoice;

		// The seed used to generate the malicious check coefficients
		// for the ferret protocol.
		//block mMalCheckSeed = ZeroBlock;

		// The summation of the malicious check coefficients which
		// correspond to the mS indicces.
		//block mMalCheckX = ZeroBlock;

		// Seed used for the encoding matrix
		block mCodeSeed = ZeroBlock;

		// The PPRF used to generate the noise vector
		// Variant allows selecting between Regular and Stationary PPRF
		std::variant<
			RegularPprfReceiver<block, CoeffCtxGF2>,
			StationaryPprfReceiver<block, CoeffCtxGF2>
		> mGenVar;

		// The type of compress we will use to generate the
		// dense vectors from the sparse vectors.
		MultType mLpnMultType = DefaultMultType;

		// The flag which controls whether the malicious check is performed.
		SilentSecType mSecurityType = SilentSecType::SemiHonest;

		 // The noise distribution model (Regular or Stationary)
		SdNoiseDistribution mNoiseDist = SdNoiseDistribution::Regular;

		// Format for PPRF output organization
		PprfOutputFormat mPprfFormat = PprfOutputFormat::ByTreeIndex;

		// An temporary buffer used during LPN encoding.
		AlignedUnVector<block> mEncodeTemp;

		// For stationary noise, this stores the A vector of the base VOLE correlation.
		std::vector<block> mBaseA;

		// For stationary noise, this stores the C vector of the base VOLE correlation.
		BitVector mBaseC;

		// A flag that helps debug
		bool mDebug = false;

		virtual ~SilentOtExtReceiver() = default;

		/////////////////////////////////////////////////////
		// The standard OT extension interface
		/////////////////////////////////////////////////////

		/**
		 * @brief Sets the base OTs for IKNP/SoftSpoken OT extension.
		 *
		 * @param baseSendOts The base OT messages to send
		 */
		void setBaseOts(
			span<std::array<block, 2>> baseSendOts) override;

		/**
		 * @brief Returns the number of IKNP/SoftSpoken base OTs required.
		 *
		 * @return Number of base OTs needed
		 */
		u64 baseOtCount() const override;

		/**
		 * @brief Checks if the required IKNP/SoftSpoken base OTs are set.
		 *
		 * @return True if base OTs are set, false otherwise
		 */
		bool hasBaseOts() const override;

		/**
		 * @brief Generates the required IKNP/SoftSpoken base OTs.
		 *
		 * Uses the default base OT protocol to generate base OTs.
		 *
		 * @param prng Source of randomness
		 * @param chl Communication channel
		 * @return Task that completes when base OTs are generated
		 */
		task<> genBaseOts(PRNG& prng, Socket& chl) override;

		/**
		 * @brief Creates an independent copy of this extender.
		 *
		 * @return Unique pointer to the new OT extender
		 */
		std::unique_ptr<OtExtReceiver> split() override;

		/**
		 * @brief Performs OT extension with specified choice bits.
		 * 
		 * The standard OT extension interface allows the caller to choose
		 * the choice bits. Since Silent OT naturally generates random choice bits,
		 * this implementation adds communication to correct the random choice
		 * bits to match the provided ones.
		 *
		 * @param choices Choice bits for the OTs
		 * @param messages Output buffer for received messages
		 * @param prng Source of randomness
		 * @param chl Communication channel
		 * @return Task that completes when OT extension is done
		 */
		task<> receive(
			const BitVector& choices,
			span<block> messages,
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
		bool hasBaseCors() const;

		/**
		 * @brief Generates base correlations (OTs and VOLEs) for Silent OT.
		 *
		 * When using stationary noise, this also generates base VOLE correlations
		 * which can are consumed in each execution.
		 *
		 * @param prng Source of randomness
		 * @param chl Communication channel
		 * @param useOtExtension Whether to use OT extension for base OTs
		 * @return Task that completes when base correlations are generated
		 */
		task<> genBaseCors(PRNG& prng, Socket& chl, bool useOtExtension = true);

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
			u64 nThreads = 1,
			SilentSecType mal = SilentSecType::SemiHonest,
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
		 * @brief Samples the choice bits for base OTs.
		 *
		 * The base OT used to encode the location of the noise
		 * must have specific choice bits.
		 * This returns the choice bits that should be used.
		 * Call this if you want to use a specific base OT protocol
		 * and then pass the OT messages back using setBaseCors(...).
		 * 
		 * Note that setBaseCors may require additional OTs with arbirary 
		 * choice bits.
		 *
		 * @param prng Source of randomness
		 * @return BitVector containing the choice bits
		 */
		BitVector sampleBaseChoiceBits(PRNG& prng);

		/**
		 * @brief Sets externally generated base OTs and VOLEs.
		 *
		 * For stationary noise, baseA and baseC represent the VOLE correlation:
		 *    baseA = baseB + baseC * delta
		 *
		 * where delta should match the same value used throughout the protocol.
		 * The choice bits must be the ones returned by sampleBaseChoiceBits(...).
		 *
		 * @param recvBaseOts Base OT messages received
		 * @param choices Choice bits used for the base OTs. The first set of bits
		 * should be the same as what is returned by sampleBaseChoiceBits(...).
		 * @param baseA A values of base VOLE correlations (for stationary noise)
		 * @param baseC C values of base VOLE correlations (for stationary noise)
		 */
		void setBaseCors(
			span<const block> recvBaseOts,
			const BitVector& choices,
			span<const block> baseA,
			const BitVector& baseC);

		/**
		 * @brief Performs Silent OT protocol and outputs choice bits and messages.
		 *
		 * If type == OTType::Random, generates random OTs where c is a random
		 * bit vector and a[i] = H(b[i] + c[i] * delta).
		 *
		 * If type == OTType::Correlated, generates correlated OTs with
		 * a[i] = b[i] + c[i] * delta.
		 *
		 * @param c Output buffer for choice bits
		 * @param a Output buffer for received OT messages
		 * @param prng Source of randomness
		 * @param chl Communication channel
		 * @param type Whether to generate random or correlated OTs
		 * @return Task that completes when OT is done
		 */
		task<> silentReceive(
			BitVector& c,
			span<block> a,
			PRNG& prng,
			Socket& chl,
			OTType type = OTType::Random);

		/**
		 * @brief Performs Silent OT protocol with internal storage.
		 *
		 * Stores the vectors internally as mA, mC. If type = ChoiceBitPacking::True,
		 * mC will not be generated. Instead the least significant bit of mA
		 * will hold the choice bits.
		 *
		 * @param n Number of OTs to generate
		 * @param prng Source of randomness
		 * @param chl Communication channel
		 * @param type Whether to pack choice bits in LSB of mA
		 * @return Task that completes when OT is done
		 */
		task<> silentReceiveInplace(
			u64 n,
			PRNG& prng,
			Socket& chls,
			ChoiceBitPacking type = ChoiceBitPacking::False);


		//////////////////////////////////////////
		// Internal functions
		//////////////////////////////////////////

		/**
		 * @brief Hashes the internal vectors and stores results in output buffers.
		 *
		 * @param choices Output buffer for choice bits
		 * @param messages Output buffer for hashed messages
		 * @param type The choice bit packing format
		 */
		void hash(
			BitVector& choices,
			span<block> messages,
			ChoiceBitPacking type);

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
		 * @brief Debugging check on the sparse vector (insecure for production).
		 *
		 * @param chl Communication channel
		 * @param rT Matrix view of the sparse vector
		 * @return Task that completes when check is done
		 */
		task<> checkRT(Socket& chl, MatrixView<block> rT);

		/**
		 * @brief Compresses the sparse vectors to generate dense vectors.
		 *
		 * Uses the configured compression method (QuasiCyclic, ExAcc, etc.)
		 *
		 * @param packing The choice bit packing format
		 */
		void compress(ChoiceBitPacking packing);

		/**
		 * @brief Returns the PPRF output format used.
		 *
		 * @return The configured PPRF output format
		 */
		PprfOutputFormat getPprfFormat()
		{
			return mPprfFormat;
		}

		/**
		 * @brief Clears internal buffers.
		 */
		void clear();


		// Helper function to access the PPRF generator
		PprfReceiver<block, CoeffCtxGF2>& gen() {
			if (isConfigured() == false)
				throw std::runtime_error("configure(...) must be called first.");
			return std::visit([](auto& v) -> PprfReceiver<block, CoeffCtxGF2>&{ return v; }, mGenVar);
		}

		// Const version of the PPRF generator accessor
		const PprfReceiver<block, CoeffCtxGF2>& gen() const {
			if (isConfigured() == false)
				throw std::runtime_error("configure(...) must be called first.");
			return std::visit([](auto& v) -> const PprfReceiver<block, CoeffCtxGF2>&{ return v; }, mGenVar);
		}

		std::vector<u64> getPoints() const
		{
			// Get the points where the noisy values should be placed
			std::vector<u64> points = gen().getPoints(mPprfFormat);

			// if ByTreeIndex, we need to adjust the points
			// to the global index space instead of per-partition.
			if (mPprfFormat == PprfOutputFormat::ByTreeIndex)
				for (u64 i = 0; i < mNumPartitions; ++i)
					points[i] += i * mSizePer;
			return points;
		}


		template<typename... Args>
		struct always_false
		{
			static constexpr bool value = false;
		};

		// this function has been deleted.
		template<typename... Args>
		task<> genSilentBaseOts(Args...)
		{
			static_assert(always_false<Args...>::value, "this function has been removed, use genBaseCors() instead. The interface has been changed to support stationary SD.");
			throw RTE_LOC;
		}

		// this function has been deleted.
		template<typename... Args>
		u64 silentBaseOtCount(Args...) const
		{
			static_assert(always_false<Args...>::value, "this function has been removed, use baseCount() instead. The interface has been changed to support stationary SD.");
			throw RTE_LOC;
		}

		// this function has been deleted.
		template<typename... Args>
		void setSilentBaseOts(Args...)
		{
			static_assert(always_false<Args...>::value, "this function has been removed, use setBaseCors() instead. The interface has been changed to support stationary SD.");
		}


	};

	inline u8 parity(block b)
	{
		b = b ^ b.srli_epi64(1);
		b = b ^ b.srli_epi64(2);
		b = b ^ b.srli_epi64(4);
		b = b ^ b.srli_epi64(8);
		b = b ^ b.srli_epi64(16);
		b = b ^ b.srli_epi64(32);

		union blocku64
		{
			block b;
			u64 u[2];
		};
		auto bb = reinterpret_cast<u64*>(&b);
		return (bb[0] ^ bb[1]) & 1;
	}


}
#endif

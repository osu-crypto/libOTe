#pragma once
// © 2022 Visa.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

// This code implements features described in [Silver: Silent VOLE and Oblivious Transfer from Hardness of Decoding Structured LDPC Codes, https://eprint.iacr.org/2021/1150]; the paper is licensed under Creative Commons Attribution 4.0 International Public License (https://creativecommons.org/licenses/by/4.0/legalcode).

#include <libOTe/config.h>
#ifdef ENABLE_SILENT_VOLE

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/Timer.h>
#include <libOTe/Tools/Tools.h>
#include "libOTe/Tools/Pprf/RegularPprf.h"
#include "libOTe/Tools/Pprf/StationaryPprf.h"
#include <libOTe/TwoChooseOne/TcoOtDefines.h>
#include <libOTe/TwoChooseOne/OTExtInterface.h>
#include <libOTe/TwoChooseOne/SoftSpokenOT/SoftSpokenMalOtExt.h>
#include <libOTe/Tools/Coproto.h>
#include <libOTe/Tools/ExConvCode/ExConvCode.h>
#include <libOTe/Base/BaseOT.h>
#include <libOTe/Vole/Noisy/NoisyVoleReceiver.h>
#include <libOTe/Vole/Noisy/NoisyVoleSender.h>
#include <numeric>
#include "libOTe/Tools/QuasiCyclicCode.h"
#include "libOTe/TwoChooseOne/Silent/SilentOtExtUtil.h"
#include <libOTe/Tools/TungstenCode/TungstenCode.h>
#include <libOTe/Vole/VoleUtil.h>
#include <libOTe/Tools/BlkAccCode/BlkAccCode.h>

namespace osuCrypto
{

	/**
	 * @file SilentVoleReceiver.h
	 * @brief Implements the SilentVOLE receiver functionality.
	 *
	 * This class implements the receiver side of the Silent Vector Oblivious Linear Evaluation (VOLE) protocol,
	 * as described in the paper "Silver: Silent VOLE and Oblivious Transfer from Hardness of Decoding Structured LDPC Codes"
	 * (https://eprint.iacr.org/2021/1150). The protocol allows two parties (sender and receiver) to generate correlated
	 * random vectors a, b, and c such that a = b + c * delta, where the receiver learns a and c, and the sender learns b and delta.
	 * This is done with minimal communication after an initial setup, making it suitable for high-performance applications.
	 *
	 * @tparam F The type of the field element for the VOLE values (a, b). Common choices are `block` (GF(2^128)), `u64` (integers).
	 * @tparam G The type of the subfield element for the VOLE values (c). It can be the same as F or a subfield, eg G=GF2,F=(GF(2^128)).
	 * @tparam Ctx The context class that provides arithmetic operations for F and G.
	 *             Examples: `CoeffCtxGF128` (for GF(2^128)), `CoeffCtxInteger` (for integers), `CoeffCtxGF2` (for GF(2)), `CoeffCtxArray`.
	 *
	 * Usage:
	 * 1.  Include the header: `#include <libOTe/Vole/Silent/SilentVoleReceiver.h>`
	 * 2.  Instantiate the `SilentVoleReceiver` class with the desired field types and context:
	 *     `SilentVoleReceiver<block, block, CoeffCtxGF128> receiver;`
	 * 3.  Configure the receiver with the desired parameters:
	 *     - `requestSize`: The number of VOLE correlations to generate.
	 *     - `baseType`: The type of base OT to use (e.g., `SilentBaseType::BaseExtend`).
	 *     - `noiseType`: The distribution of the noise vector (e.g., `SdNoiseDistribution::Regular`).
	 *       if SdNoiseDistribution::Stationary is used, the base OTs only need to be set once.
	 *     - `secParam`: The security parameter (e.g., 128).
	 *     - `ctx`: The coefficient context object.
	 *     `receiver.configure(requestSize, baseType, noiseType, secParam, ctx);`
	 * 4.  Establish base correlations by generating base OTs and VOLE correlations:
	 *     - Call `genBaseCors()` to generate the base correlations. This requires a PRNG and a communication channel (Socket).
	 *     `receiver.genBaseCors(prng, chl);`
	 *     - Alternatively, one can manually generate these and set the base correlations using
	 *       setBaseCors(...). Use baseCount() to determine the required number of base correlations and
	 *       sampleBaseChoiceBits(...) to get the required choice bits.
	 * 5.  Perform the silent VOLE by calling `silentReceive()` or `silentReceiveInplace()`:
	 *     - `silentReceive()` copies the result to a provided vector.
	 *     - `silentReceiveInplace()` stores the result internally, which can be more efficient.
	 *     `receiver.silentReceive(c, a, prng, chl);`
	 *
	 * Important notes:
	 * - The `Socket` class is used for communication. You need to provide a concrete implementation for your networking environment.
	 * - Error handling is done via exceptions. Wrap your VOLE calls in `try...catch` blocks.
	 * - The `MultType` parameter selects the linear code used for compressing the noisy vector.
	 * - The `clear()` method releases memory and resets the state.
	 * - VecF, VecG are vector like types for F,G that are specified by the context object.
	 *    These can be customized.
	 */
	template<
		typename F,
		typename G = F,
		typename Ctx = DefaultCoeffCtx<F, G>
	>
	class SilentVoleReceiver : public TimerAdapter
	{
	public:

		// Indicates whether malicious security is supported for the given types
		// Currently only supported for block types in GF(2^128)
		static constexpr bool MaliciousSupported =
			std::is_same_v<F, block>&& std::is_same_v<Ctx, CoeffCtxGF128>;

		// The current state of the protocol
		enum class State
		{
			Default,     // Initial state or after completion
			Configured,  // After configure() has been called
			HasBase      // After base correlations have been set
		};


		// Type aliases for vector types that hold F and G elements
		using VecF = typename Ctx::template Vec<F>;
		using VecG = typename Ctx::template Vec<G>;

		// The current state of the protocol
		State mState = State::Default;

		// The context used to perform arithmetic operations on F and G elements
		Ctx mCtx;

		// The number of correlations the user requested.
		u64 mRequestSize = 0;

		// the LPN security parameter
		u64 mSecParam = 0;

		// The length of the noisy vectors (typically 2 * mRequestSize but possibly slightly larger)
		u64 mNoiseVecSize = 0;

		// Size of each chunk in the regular LPN construction
		u64 mSizePer = 0;

		// The number of noisy positions (weight of the sparse vector)
		u64 mNumPartitions = 0;

		// What type of Base OTs should be performed.
		SilentBaseType mBaseType;

		// The matrix multiplication type which compresses the sparse vector
		MultType mLpnMultType = DefaultMultType;

		// The multi-point punctured PRF for generating the sparse vectors
		// Variant allows selecting between Regular and Stationary PPRF
		std::variant<
			RegularPprfReceiver<F, Ctx>,
			StationaryPprfReceiver<F, Ctx>
		> mGenVar;

		// The receiver's share of the VOLE correlation (a = b + c * delta)
		VecF mA;

		// The receiver's multiplication vector in the VOLE correlation
		VecG mC;

		// Seed for syndrome decoding
		block mCodeSeed = ZeroBlock;

		// Number of threads to use for parallel operations (default: 1)
		// this does not actually create multiple threads but determines how 
		// many PPRFs are performed at once.
		u64 mNumThreads = 1;

		// Enable debugging output and consistency checks when true (insecure).
		bool mDebug = false;

		// Security type: SemiHonest or Malicious
		SilentSecType mSecurityType = SilentSecType::SemiHonest;

		// Format used for PPRF output organization 
		PprfOutputFormat mPprfFormat = PprfOutputFormat::ByTreeIndex;

		// Seed for malicious security checks
		std::optional<block> mMalCheckSeed;

		// True if we need to derandomize the last mBaseC value for the malicious security check
		bool mDerandomizeMalCheck = false;

		// Base VOLE correlation vectors
		VecF mBaseA;  // Receiver's base VOLE share
		VecG mBaseC;  // Receiver's base VOLE multiplication vector

#ifdef ENABLE_SOFTSPOKEN_OT
		// SoftSpoken OT instances for base OT extension
		macoro::optional<SoftSpokenMalOtSender> mOtExtSender;
		macoro::optional<SoftSpokenMalOtReceiver> mOtExtRecver;
#endif


		/**
		 * @brief Configure the silent VOLE protocol (optional).
		 *
		 * This sets the parameters and computes derived values needed for the protocol.
		 * Must be called before generating base correlations but is optional for performing
		 * the protocol.
		 *
		 * @param requestSize Number of VOLE correlations to generate
		 * @param malType Security type (SemiHonest or Malicious)
		 * @param type Type of base OT to use (BaseExtend or Base)
		 * @param noiseType Distribution of the noise vector (Regular or Stationary)
		 * if stationary is used, the base OTs are reusable.
		 * @param secParam Security parameter (typically 128)
		 * @param ctx Context object for F, G operations (default constructed if not provided)
		 * @param mult Type of matrix multiplication to use for compressing the sparse vector
		 */
		void configure(
			u64 requestSize,
			SilentSecType malType = SilentSecType::SemiHonest,
			MultType mult = DefaultMultType,
			SilentBaseType type = SilentBaseType::BaseExtend,
			SdNoiseDistribution noiseType = SdNoiseDistribution::Regular,
			u64 secParam = 128,
			Ctx ctx = {}
		);


		/**
		 * @brief Perform the silent VOLE protocol, copying results to provided vectors.
		 *
		 * This function produces vectors c and a such that a = b + c * delta,
		 * where b and delta are held by the sender.
		 * The results are copied to the provided vectors.
		 *
		 * @param c Output vector to store the multiplication values
		 * @param a Output vector to store the receiver's share
		 * @param prng Pseudorandom number generator
		 * @param chl Communication channel to the sender
		 * @return Coroutine task
		 */
		task<> silentReceive(
			VecG& c,
			VecF& a,
			PRNG& prng,
			Socket& chl);

		/**
		 * @brief Perform the silent VOLE protocol, storing results internally.
		 *
		 * Same as silentReceive() but the results are stored in mC and mA.
		 * This is more efficient when the results will be used directly from
		 * the SilentVoleReceiver object.
		 *
		 * @param n Number of VOLE correlations to generate
		 * @param prng Pseudorandom number generator
		 * @param chl Communication channel to the sender
		 * @return Coroutine task
		 */
		task<> silentReceiveInplace(
			u64 n,
			PRNG& prng,
			Socket& chl);

		/**
		 * @brief Check if base correlations have been set.
		 *
		 * Returns true if both the base OTs and the base VOLE correlations are set.
		 *
		 * @return True if base correlations are set, false otherwise
		 */
		bool hasBaseCors() const;

		/**
		 * @brief Generate the base correlations needed for the protocol.
		 *
		 * This performs base OTs and generates base VOLE correlations.
		 * If the chosen method is BaseExtend, it will use SoftSpoken OT extension.
		 * The vole correlation is generated using NoisyVole.
		 *
		 * @param prng Pseudorandom number generator
		 * @param chl Communication channel to the sender
		 * @return Coroutine task
		 */
		task<> genBaseCors(PRNG& prng, Socket& chl);

		/**
		 * @brief Check if the receiver has been configured.
		 *
		 * @return True if configure() has been called, false otherwise
		 */
		bool isConfigured() const;

		/**
		 * @brief Get the number of base OTs and VOLEs required.
		 *
		 * @return A VoleBaseCount struct with mBaseOtCount and mBaseVoleCount
		 */
		VoleBaseCount baseCount() const;

		/**
		 * @brief Sample the choice bits needed for base OTs.
		 *
		 * These choice bits determine which base OT messages the receiver gets.
		 * Call this if you want to use a specific base OT protocol
		 * and then pass the OT messages back using setBaseCors(...).
		 *
		 * @param prng Pseudorandom number generator
		 * @return BitVector of choice bits
		 */
		BitVector sampleBaseChoiceBits(PRNG& prng);

		/**
		 * @brief Set externally generated base correlations.
		 *
		 * This allows manually setting the base OTs and VOLE correlations
		 * instead of using genBaseCors().
		 *
		 * @param choice The choice bits used for base OTs (from sampleBaseChoiceBits)
		 * @param recvBaseOts The received base OT messages
		 * @param baseA The receiver's base VOLE shares. should be a vector like type of Fs
		 * @param baseC The receiver's base VOLE multiplication values. should be a vector like type of Gs
		 */
		void setBaseCors(
			const BitVector& choice,
			span<block> recvBaseOts,
			const auto& baseA,
			const auto& baseC);

		/**
		 * @brief Clear internal state and free memory.
		 *
		 * Releases memory used by vectors and resets the generator.
		 */
		void clear();


		/**
		 * @brief Internal debug function to verify protocol correctness.
		 *
		 * @param chl Communication channel to the sender
		 * @return Coroutine task
		 */
		task<> checkRT(Socket& chl);

		/**
		 * @brief Compute the hash for malicious security check.
		 *
		 * @return 32-byte hash array
		 */
		std::array<u8, 32> ferretMalCheck();


		/**
		 * @brief Compute the malicious security checksum.
		 *
		 * This computes a checksum of the base correlations for malicious security.
		 * the checksum is computed as a linear combination of the base VOLE multiplication values
		 * and is written to the last position of baseC.
		 *
		 * @param prng Pseudorandom number generator
		 * @param baseC The base VOLE multiplication values to modify
		 */
		void malChecksum(PRNG& prng, VecG& baseC)
		{
			if (mSecurityType == SilentSecType::SemiHonest)
				throw RTE_LOC;
			if constexpr (!MaliciousSupported)
				throw std::runtime_error("malicious is currently only supported for GF128 block. " LOCATION);

			auto points = gen().getPoints(mPprfFormat);
			if (mPprfFormat == PprfOutputFormat::ByTreeIndex)
				for (u64 i = 0; i < mNumPartitions; ++i)
					points[i] += i * mSizePer;

			mMalCheckSeed = prng.get();
			auto yIter = baseC.begin();
			block sum = ZeroBlock;


			for (u64 i = 0; i < mNumPartitions; ++i)
			{
				auto s = points[i];
				auto xs = mMalCheckSeed->gf128Pow(s + 1);
				sum = sum ^ xs.gf128Mul(*yIter);
				++yIter;
			}

			baseC[mNumPartitions] = sum;
		}


		// Helper function to access the PPRF generator
		PprfReceiver<F, Ctx>& gen() {
			if (isConfigured() == false)
				throw std::runtime_error("configure(...) must be called first.");
			return std::visit([](auto& v) -> PprfReceiver<F, Ctx>&{ return v; }, mGenVar);
		}

		// Const version of the PPRF generator accessor
		const PprfReceiver<F, Ctx>& gen() const {
			if (isConfigured() == false)
				throw std::runtime_error("configure(...) must be called first.");
			return std::visit([](auto& v) -> const PprfReceiver<F, Ctx>&{ return v; }, mGenVar);
		}

	};























	template< typename F, typename G, typename Ctx >
	bool SilentVoleReceiver<F, G, Ctx>::hasBaseCors() const
	{
		return
			isConfigured() &&
			gen().hasBaseOts() &&
			mBaseA.size() == baseCount().mBaseVoleCount;
	}



	template< typename F, typename G, typename Ctx >
	VoleBaseCount SilentVoleReceiver<F, G, Ctx>::baseCount() const
	{
		VoleBaseCount c;
		c.mBaseOtCount = gen().baseOtCount();
		c.mBaseVoleCount = mNumPartitions + 1 * (mSecurityType == SilentSecType::Malicious);
		return c;
	}

	template< typename F, typename G, typename Ctx >
	task<> SilentVoleReceiver<F, G, Ctx>::genBaseCors(PRNG& prng, Socket& chl)
	{
		MACORO_TRY{

#ifdef LIBOTE_HAS_BASE_OT

#if defined ENABLE_MRR_TWIST && defined ENABLE_SSE
			using BaseOT = McRosRoyTwist;
#elif defined ENABLE_MR
			using BaseOT = MasnyRindal;
#elif defined ENABLE_MRR
			using BaseOT = McRosRoy;
#elif defined ENABLE_MR_KYBER
			using BaseOT = MasnyRindalKyber;
#else
			using BaseOT = DefaultBaseOT;
#endif
			setTimePoint("SilentVoleReceiver.genSilent.begin");
			if (isConfigured() == false)
				throw std::runtime_error("configure must be called first");

			auto count = baseCount();
			BitVector choiceBits;
			if(count.mBaseOtCount)
				choiceBits = sampleBaseChoiceBits(prng);
			AlignedUnVector<block> msg(count.mBaseOtCount);



			// Sample the base VOLE values
			// We will compute a noisy vector:
			//  C = (000 noiseVals[0] 0000 ... 000 noiseVals[p] 000)
			// and then generate secret shares of C * delta
			VecF baseA;
			VecG baseC;
			mCtx.resize(baseA, count.mBaseVoleCount);
			mCtx.resize(baseC, count.mBaseVoleCount);
			for (u64 i = 0; i < count.mBaseVoleCount; ++i)
				mCtx.fromBlock(baseC[i], prng.get<block>());


			// For malicious security, compute checksum in the last position
			if (mSecurityType == SilentSecType::Malicious)
			{
				if constexpr (MaliciousSupported)
				{
					malChecksum(prng, baseC);
					mDerandomizeMalCheck = false;
				}
				else
					throw RTE_LOC;
			}

			auto nv = NoisyVoleReceiver<F, G, Ctx>{};
			if (mTimer)
				nv.setTimer(*mTimer);

			// Use OT extension for the base OTs if specified
			if (mBaseType == SilentBaseType::BaseExtend)
			{
#ifdef ENABLE_SOFTSPOKEN_OT
				if (!mOtExtRecver)
					mOtExtRecver.emplace();

				if (!mOtExtSender)
					mOtExtSender.emplace();

				// If we don't have base OTs for the OT extension, generate them first
				if (mOtExtSender->hasBaseOts() == false)
				{
					// Resize to accommodate additional base OTs for SoftSpoken
					msg.resize(msg.size() + mOtExtSender->baseOtCount());
					auto bb = BitVector{ mOtExtSender->baseOtCount() };
					bb.randomize(prng);
					choiceBits.append(bb);

					// Receive base OTs
					co_await mOtExtRecver->receive(choiceBits, msg, prng, chl);

					// Set the base OTs for the sender
					mOtExtSender->setBaseOts(
						span<block>(msg).subspan(
							msg.size() - mOtExtSender->baseOtCount(),
							mOtExtSender->baseOtCount()),
						bb);

					// Resize back and perform noisy VOLE
					choiceBits.resize(choiceBits.size() - bb.size());
					msg.resize(msg.size() - mOtExtSender->baseOtCount());
					co_await nv.receive(baseC, baseA, prng, *mOtExtSender, chl, mCtx);
				}
				else
				{
					// If we already have base OTs, run both operations in parallel
					auto chl2 = chl.fork();
					auto prng2 = prng.fork();

					if (choiceBits.size())
					{
						co_await
							macoro::when_all_ready(
								nv.receive(baseC, baseA, prng2, *mOtExtSender, chl2, mCtx),
								mOtExtRecver->receive(choiceBits, msg, prng, chl)
							);
					}
					else
						co_await nv.receive(baseC, baseA, prng2, *mOtExtSender, chl2, mCtx);
				}
#else
				throw std::runtime_error("soft spoken must be enabled");
#endif
			}
			else
			{
				// Use base OT protocol directly
				auto chl2 = chl.fork();
				auto prng2 = prng.fork();
				BaseOT baseOt;
				if (choiceBits.size())
				{
					co_await
						macoro::when_all_ready(
							baseOt.receive(choiceBits, msg, prng, chl),
							nv.receive(baseC, baseA, prng2, baseOt, chl2, mCtx));
				}
				else
					co_await nv.receive(baseC, baseA, prng2, baseOt, chl2, mCtx);

			}

			// Set the base correlations
			setBaseCors(choiceBits, msg, baseA, baseC);

			if (mSecurityType == SilentSecType::Malicious)
				mDerandomizeMalCheck = false;

			setTimePoint("SilentVoleReceiver.genSilent.done");
#else
			throw std::runtime_error("LIBOTE_HAS_BASE_OT = false, must enable relic, sodium or simplest ot asm." LOCATION);
			co_return;
#endif

		} MACORO_CATCH(eptr) {
			co_await chl.close();
			std::rethrow_exception(eptr);
		}
	}

	// configure the silent OT extension. This sets
	// the parameters and figures out how many base OT
	// will be needed. These can then be ganerated for
	// a different OT extension or using a base OT protocol.
	template< typename F, typename G, typename Ctx >
	void SilentVoleReceiver<F, G, Ctx>::configure(
		u64 requestSize,
		SilentSecType malType,
		MultType mult,
		SilentBaseType type,
		SdNoiseDistribution noiseType,
		u64 secParam,
		Ctx ctx)
	{
		mCtx = std::move(ctx);
		mSecParam = secParam;
		mRequestSize = requestSize;
		mBaseType = type;
		mLpnMultType = mult;
		mSecurityType = malType;

		// Calculate the bit size for the subfield elements
		// for non-fields we assume 1 which gives worse parameters for stationary.
		u64 bitCount = 1;
		if (mCtx.template isField<F>())
			bitCount = mCtx.template bitSize<G>();

		// Configure parameters for syndrome decoding
		auto param = syndromeDecodingConfigure(secParam, requestSize, mLpnMultType, noiseType, bitCount);
		mNumPartitions = param.mNumPartitions;
		mSizePer = param.mSizePer;
		mNoiseVecSize = param.mNumPartitions * param.mSizePer;
		mCodeSeed = block(12528943721987127, 98743297823479812);


		// Initialize the appropriate PPRF based on noise distribution
		if (noiseType == SdNoiseDistribution::Regular)
		{
			mGenVar.template emplace<0>();// = RegularPprfReceiver<F, Ctx>{};
			mPprfFormat = PprfOutputFormat::Interleaved;
		}
		else if (noiseType == SdNoiseDistribution::Stationary)
		{
			mGenVar.template emplace<1>();// = StationaryPprfReceiver<F, Ctx>{};
			mPprfFormat = PprfOutputFormat::ByTreeIndex;
		}
		else
		{
			throw std::runtime_error("Unknown noise type. " LOCATION);
		}

		mState = State::Configured;
		gen().configure(mSizePer, mNumPartitions);
	}

	template< typename F, typename G, typename Ctx >
	bool SilentVoleReceiver<F, G, Ctx>::isConfigured() const { return mState != State::Default; }

	template< typename F, typename G, typename Ctx >
	auto SilentVoleReceiver<F, G, Ctx>::sampleBaseChoiceBits(PRNG& prng) -> BitVector {

		if (isConfigured() == false)
			throw std::runtime_error("configure(...) must be called first");
		if (baseCount().mBaseOtCount)
			return gen().sampleChoiceBits(prng);
		else
			return {};
	}

	// Set the externally generated base OTs. This choice
	// bits must be the one return by sampleBaseChoiceBits(...).
	template< typename F, typename G, typename Ctx >
	void SilentVoleReceiver<F, G, Ctx>::setBaseCors(
		BitVector const& choice,
		span<block> recvBaseOts,
		const auto& baseA,
		const auto& baseC)
	{
		auto count = baseCount();
		if (isConfigured() == false)
			throw std::runtime_error("configure(...) must be called first.");

		if (static_cast<u64>(recvBaseOts.size()) != count.mBaseOtCount)
			throw std::runtime_error("wrong number of silent base OTs");

		if (baseA.size() != count.mBaseVoleCount)
			throw std::runtime_error("wrong number of silent base Vole values." LOCATION);
		if (baseC.size() != count.mBaseVoleCount)
			throw std::runtime_error("wrong number of silent base Vole values." LOCATION);

		if (choice.size())
		{
			gen().setChoiceBits(choice);
			gen().setBase(recvBaseOts);
		}

		// For malicious security, we'll need to derandomize
		if (mSecurityType == SilentSecType::Malicious)
			mDerandomizeMalCheck = true;

		mCtx.resize(mBaseA, baseA.size());
		mCtx.resize(mBaseC, baseC.size());
		mCtx.copy(baseA.begin(), baseA.end(), mBaseA.begin());
		mCtx.copy(baseC.begin(), baseC.end(), mBaseC.begin());
		mState = State::HasBase;
	}

	template< typename F, typename G, typename Ctx >
	task<> SilentVoleReceiver<F, G, Ctx>::silentReceive(
		VecG& c,
		VecF& a,
		PRNG& prng,
		Socket& chl)
	{
		MACORO_TRY{

			// Validate input sizes match
			if (c.size() != a.size())
				throw std::runtime_error("input sizes do not match." LOCATION);

		// Run the main protocol
		co_await silentReceiveInplace(c.size(), prng, chl);

		// Copy results to the output vectors
		mCtx.copy(mC.begin(), mC.begin() + c.size(), c.begin());
		mCtx.copy(mA.begin(), mA.begin() + a.size(), a.begin());

		// Free resources if we are using the regular PPRF
		if (mGenVar.index() == 0)
			clear();

		} MACORO_CATCH(eptr) {
			co_await chl.close();
			std::rethrow_exception(eptr);
		}
	}

	template< typename F, typename G, typename Ctx >
	task<> SilentVoleReceiver<F, G, Ctx>::silentReceiveInplace(
		u64 n,
		PRNG& prng,
		Socket& chl)
	{
		MACORO_TRY{
		auto myHash = std::array<u8, 32>{};
		auto theirHash = std::array<u8, 32>{};
		gTimer.setTimePoint("SilentVoleReceiver.ot.enter");

		// Configure if not already done
		if (isConfigured() == false)
			configure(n, mSecurityType, mLpnMultType, SilentBaseType::BaseExtend);

		// Validate requested size
		if (mRequestSize < n)
			throw std::invalid_argument("n does not match the requested number of OTs via configure(...). " LOCATION);

		// Generate base correlations if needed
		if (hasBaseCors() == false)
			co_await genBaseCors(prng, chl);

		// For malicious security, handle derandomization of the checksum
		if (mSecurityType == SilentSecType::Malicious && mDerandomizeMalCheck)
		{
			if constexpr (MaliciousSupported)
			{
				// Create a copy to compute proper checksum
				VecG  baseC = mBaseC;
				malChecksum(prng, baseC);

				// Calculate and send the difference
				// currently have a = b + c' * d
				// but want       a = b + c  * d
				// lets send  (c' - c)
				mCtx.minus(baseC[mNumPartitions], mBaseC[mNumPartitions], baseC[mNumPartitions]);
				std::vector<u8> buffer(mCtx.template byteSize<G>());
				mCtx.serialize(baseC.begin() + mNumPartitions, baseC.end(), buffer.begin());
				co_await chl.send(std::move(buffer));
			}
			else throw RTE_LOC;
		}


		// Allocate and initialize mA
		mCtx.resize(mA, 0);
		mCtx.resize(mA, mNoiseVecSize);
		setTimePoint("SilentVoleReceiver.alloc");

		// Allocate and zero-initialize mC
		mCtx.resize(mC, 0);
		mCtx.resize(mC, mNoiseVecSize);
		mCtx.zero(mC.begin(), mC.end());
		setTimePoint("SilentVoleReceiver.alloc.zero");

		if (mTimer)
			gen().setTimer(*mTimer);

		// PPRF expansion to generate share of mC * delta
		// As part of the setup, we have generated 
		//  
		//  mBaseA + mBaseB = mBaseC * mDelta
		// 
		// We have   mBaseA, mBaseC, 
		// they have mBaseB, mDelta
		// 
		// The PPRF expands this to full-sized vectors:
		//   
		//    mA' = mB + points(mBaseB)
		//        = mB + points(mBaseC * mDelta - mBaseA)
		//        = mB + points(mBaseC * mDelta) - points(mBaseA) 
		// 
		// We add points(mBaseA) to mA' to get:
		// 
		//    mA = mB + points(mBaseC * mDelta)
		//
		co_await gen().expand(chl, mA, mPprfFormat, true, mNumThreads, mCtx);

		setTimePoint("SilentVoleReceiver.expand.pprf_transpose");

		// Get the points where the noisy values should be placed
		std::vector<u64> points = gen().getPoints(mPprfFormat);

		// if ByTreeIndex, we need to adjust the points
		// to the global index space instead of per-partition.
		if (mPprfFormat == PprfOutputFormat::ByTreeIndex)
			for (u64 i = 0; i < mNumPartitions; ++i)
				points[i] += i * mSizePer;

		// populate the noisy coordinates of mC and
		// update mA to be a secret share of mC * delta
		for (u64 i = 0; i < mNumPartitions; ++i)
		{
			auto pnt = points[i];
			mCtx.copy(mC[pnt], mBaseC[i]);
			mCtx.plus(mA[pnt], mA[pnt], mBaseA[i]);
		}

		// Debug consistency check
		if (mDebug)
		{
			co_await checkRT(chl);
			setTimePoint("SilentVoleReceiver.expand.checkRT");
		}

		// Malicious security check
		if (mSecurityType == SilentSecType::Malicious)
		{
			// Send the seed for malicious check
			co_await chl.send(std::move(*mMalCheckSeed));

			// Compute our hash
			if constexpr (MaliciousSupported)
				myHash = ferretMalCheck();
			else {
				throw std::runtime_error("malicious is currently only supported for GF128 block. " LOCATION);
			}

			// Receive and verify the sender's hash
			co_await chl.recv(theirHash);
			if (theirHash != myHash)
				throw std::runtime_error("malicious security check failed. " LOCATION);
		}


		// Apply the appropriate linear code to compress the sparse vectors
		switch (mLpnMultType)
		{
		case osuCrypto::MultType::ExConv7x24:
		case osuCrypto::MultType::ExConv21x24:
		{
			// Configure the expander code
			u64 expanderWeight, accumulatorWeight, scaler;
			double minDist;
			ExConvConfigure(mLpnMultType, scaler, expanderWeight, accumulatorWeight, minDist);
			ExConvCode encoder;
			assert(scaler == 2 && minDist < 1 && minDist > 0);
			encoder.config(mRequestSize, mNoiseVecSize,
				expanderWeight, accumulatorWeight, true, true, mCodeSeed);

			if (mTimer)
				encoder.setTimer(getTimer());

			// Apply the dual encoding to both vectors
			encoder.dualEncode2<F, G, Ctx>(
				mA.begin(),
				mC.begin(),
				{}
			);
			break;
		}
		case MultType::BlkAcc3x8:
		case MultType::BlkAcc3x32:
		{
			u64 depth, sigma, scaler;
			double md;
			BlkAccConfigure(mLpnMultType, scaler, sigma, depth, md);
			BlkAccCode code;
			code.init(mRequestSize, mNoiseVecSize, sigma, depth, mCodeSeed);
			code.dualEncode<F, Ctx>(mA.begin(), mCtx);
			code.dualEncode<G, Ctx>(mC.begin(), mCtx);


			break;
		}
		case osuCrypto::MultType::QuasiCyclic:
		{
#ifdef ENABLE_BITPOLYMUL
			// QuasiCyclic code is only supported for GF(2^128)
			if constexpr (
				std::is_same_v<F, block> &&
				std::is_same_v<G, block> &&
				std::is_same_v<Ctx, CoeffCtxGF128>)
			{
				QuasiCyclicCode encoder;
				encoder.init2(mRequestSize, mNoiseVecSize, mCodeSeed);
				encoder.dualEncode(mA);
				encoder.dualEncode(mC);
			}
			else
			{
				throw std::runtime_error("QuasiCyclic is only supported for GF128, i.e. block. " LOCATION);
			}
#else
			throw std::runtime_error("QuasiCyclic requires ENABLE_BITPOLYMUL = true. " LOCATION);
#endif
			break;
		}
		case osuCrypto::MultType::Tungsten:
		{
			experimental::TungstenCode encoder;
			encoder.config(oc::roundUpTo(mRequestSize, 8), mNoiseVecSize, mCodeSeed);
			encoder.dualEncode<F, Ctx>(mA.begin(), mCtx);
			encoder.dualEncode<G, Ctx>(mC.begin(), mCtx);
			break;
		}
		default:
			throw std::runtime_error("Code is not supported. " LOCATION);
			break;
		}

		mCodeSeed = mAesFixedKey.hashBlock(mCodeSeed);

		// resize the buffers down to only contain the real elements.
		mCtx.resize(mA, mRequestSize);
		mCtx.resize(mC, mRequestSize);

		// clear the base VOLE correlations.
		mBaseC = {};
		mBaseA = {};

		// for regular we completely reset but
		// for stationary we are configured and ready 
		// to expand again given a new base VOLE.
		if (mGenVar.index() == 0)
			mState = State::Default;
		else
			mState = State::Configured;


		} MACORO_CATCH(eptr) {
			co_await chl.close();
			std::rethrow_exception(eptr);
		}
	}


	// internal.
	template< typename F, typename G, typename Ctx >
	task<> SilentVoleReceiver<F, G, Ctx>::checkRT(Socket& chl)
	{
		auto B = VecF{};
		auto sparseNoiseDelta = VecF{};
		auto baseB = VecF{};
		auto delta = VecF{};
		auto tempF = VecF{};
		auto tempG = VecG{};
		auto buffer = std::vector<u8>{};

		// recv delta
		buffer.resize(mCtx.template byteSize<F>());
		mCtx.resize(delta, 1);
		co_await chl.recv(buffer);
		mCtx.deserialize(buffer.begin(), buffer.end(), delta.begin());

		// recv B
		buffer.resize(mCtx.template byteSize<F>() * mA.size());
		mCtx.resize(B, mA.size());
		co_await chl.recv(buffer);
		mCtx.deserialize(buffer.begin(), buffer.end(), B.begin());

		// recv the noisy values.
		buffer.resize(mCtx.template byteSize<F>() * mBaseA.size());
		mCtx.resize(baseB, mBaseA.size());
		co_await chl.recvResize(buffer);
		mCtx.deserialize(buffer.begin(), buffer.end(), baseB.begin());

		auto points = gen().getPoints(mPprfFormat);
		if (mPprfFormat == PprfOutputFormat::ByTreeIndex)
			for (u64 i = 0; i < mNumPartitions; ++i)
				points[i] += i * mSizePer;


		// it should hold that 
		// 
		// mBaseA = baseB + mBaseC * mDelta
		//
		// and
		// 
		//  mA = mB + mC * mDelta
		//
		bool verbose = false;
		bool failed = false;
		std::vector<std::size_t> index(points.size());
		std::iota(index.begin(), index.end(), 0);
		std::sort(index.begin(), index.end(),
			[&](std::size_t i, std::size_t j) { return points[i] < points[j]; });

		mCtx.resize(tempF, 2);
		mCtx.resize(tempG, 1);
		mCtx.zero(tempG.begin(), tempG.end());


		// check the correlation that
		//
		//  mBaseA + mBaseB = mBaseC * mDelta
		for (auto i : rng(mBaseA.size()))
		{
			// temp[0] = baseB[i] + mBaseA[i]
			mCtx.plus(tempF[0], baseB[i], mBaseA[i]);

			// temp[1] =  mBaseC[i] * delta[0]
			mCtx.mul(tempF[1], delta[0], mBaseC[i]);

			if (!mCtx.eq(tempF[0], tempF[1]))
				throw RTE_LOC;

			if (i < mNumPartitions)
			{
				//auto idx = index[i];
				auto point = points[i];
				if (!mCtx.eq(mBaseC[i], mC[point]))
					throw RTE_LOC;

				if (i && points[index[i - 1]] >= points[index[i]])
					throw RTE_LOC;
			}
		}


		auto iIter = index.begin();
		auto leafIdx = points[*iIter];
		F act = tempF[0];
		G zero = tempG[0];
		mCtx.zero(tempG.begin(), tempG.end());

		for (u64 j = 0; j < mA.size(); ++j)
		{
			mCtx.mul(act, delta[0], mC[j]);
			mCtx.plus(act, act, B[j]);

			bool active = false;
			if (j == leafIdx)
			{
				active = true;
			}
			else if (!mCtx.eq(zero, mC[j]))
				throw RTE_LOC;

			if (mA[j] != act)
			{
				failed = true;
				if (verbose)
					std::cout << Color::Red;
			}

			if (verbose)
			{
				std::cout << j << " act " << mCtx.str(act)
					<< " a " << mCtx.str(mA[j]) << " b " << mCtx.str(B[j]);

				if (active)
					std::cout << " < " << mCtx.str(delta[0]);

				std::cout << std::endl << Color::Default;
			}

			if (j == leafIdx)
			{
				++iIter;
				if (iIter != index.end())
				{
					leafIdx = points[*iIter];
				}
			}
		}

		if (failed)
			throw RTE_LOC;

	}

	template< typename F, typename G, typename Ctx >
	std::array<u8, 32> SilentVoleReceiver<F, G, Ctx>::ferretMalCheck()
	{
		auto seed = *mMalCheckSeed;
		block xx = seed;
		block sum0 = ZeroBlock;
		block sum1 = ZeroBlock;


		for (u64 i = 0; i < (u64)mA.size(); ++i)
		{
			block low, high;
			xx.gf128Mul(mA[i], low, high);
			sum0 = sum0 ^ low;
			sum1 = sum1 ^ high;

			// xx = mMalCheckSeed^{i+1}
			xx = xx.gf128Mul(seed);
		}

		// <A,X> = <
		block mySum = sum0.gf128Reduce(sum1);

		std::array<u8, 32> myHash;
		RandomOracle ro(32);
		ro.Update(mySum ^ mBaseA.back());
		ro.Final(myHash);
		return myHash;
	}

	template< typename F, typename G, typename Ctx >
	void SilentVoleReceiver<F, G, Ctx>::clear()
	{
		mA = {};
		mC = {};
		mBaseA = {};
		mBaseC = {};
		std::visit([](auto& gen) {gen.clear(); }, mGenVar);
	}

}
#endif
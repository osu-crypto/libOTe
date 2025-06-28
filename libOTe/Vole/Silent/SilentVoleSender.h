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
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Common/Aligned.h>
#include "libOTe/Tools/Pprf/RegularPprf.h"
#include <libOTe/TwoChooseOne/TcoOtDefines.h>
#include <libOTe/TwoChooseOne/OTExtInterface.h>
#include <libOTe/TwoChooseOne/SoftSpokenOT/SoftSpokenMalOtExt.h>
#include <libOTe/Tools/ExConvCode/ExConvCode.h>
#include <libOTe/Base/BaseOT.h>
#include <libOTe/Vole/Noisy/NoisyVoleReceiver.h>
#include <libOTe/Vole/Noisy/NoisyVoleSender.h>
#include <libOTe/TwoChooseOne/Silent/SilentOtExtUtil.h>
#include <libOTe/Tools/QuasiCyclicCode.h>
#include <libOTe/Tools/TungstenCode/TungstenCode.h>
#include <libOTe/Tools/Pprf/StationaryPprf.h>
#include <libOTe/Vole/VoleUtil.h>
#include <libOTe/Tools/BlkAccCode/BlkAccCode.h>

namespace osuCrypto
{

	/**
	 * @file SilentVoleSender.h
	 * @brief Implements the SilentVOLE sender functionality.
	 *
	 * This class implements the sender side of the Silent Vector Oblivious Linear Evaluation (VOLE) protocol,
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
	 * 1.  Include the header: `#include <libOTe/Vole/Silent/SilentVoleSender.h>`
	 * 2.  Instantiate the `SilentVoleSender` class with the desired field types and context:
	 *     `SilentVoleSender<block, block, CoeffCtxGF128> sender;`
	 * 3.  Configure the sender with the desired parameters:
	 *     - `requestSize`: The number of VOLE correlations to generate.
	 *     - `baseType`: The type of base OT to use (e.g., `SilentBaseType::BaseExtend`).
	 *     - `noiseType`: The distribution of the noise vector (e.g., `SdNoiseDistribution::Regular`).
	 *       if SdNoiseDistribution::Stationary is used, the base OTs only need to be set once.
	 *     - `secParam`: The security parameter (e.g., 128).
	 *     - `ctx`: The coefficient context object.
	 *     `sender.configure(requestSize, baseType, noiseType, secParam, ctx);`
	 * 4.  optionally establish base correlations by generating base OTs and VOLE correlations:
	 *     - Call `genBaseCors()` to generate the base correlations. This requires a PRNG and a communication channel (Socket).
	 *     `sender.genBaseCors(prng, chl, delta);`
	 *     - Alternatively, one can manually generate these and set the base correlations using 
	 *       setBaseCors(...). Use baseCount() to determine the required number of base correlations.
	 * 5.  Perform the silent VOLE by calling `silentSend()` or `silentSendInplace()`:
	 *     - `silentSend()` copies the result to a provided vector.
	 *     - `silentSendInplace()` stores the result internally, which can be more efficient.
	 *     `sender.silentSend(delta, b, prng, chl);`
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
	class SilentVoleSender : public TimerAdapter
	{
	public:
		// The expansion factor used in the protocol (typically 2)
		static constexpr u64 mScaler = 2;

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

		// The PPRF used to generate the noise vector
		// Variant allows selecting between Regular and Stationary PPRF
		std::variant<
			RegularPprfSender<F, Ctx>,
			StationaryPprfSender<F, Ctx>
		> mGenVar;

		 // The number of correlations the user requested
		u64 mRequestSize = 0;

		// The length of the noisy vectors (typically 2 * mRequestSize for most codes)
		u64 mNoiseVecSize = 0;

		// The number of noisy positions (weight of the sparse vector)
		u64 mNumPartitions = 0;

		// Size of each chunk in the regular LPN construction
		u64 mSizePer = 0;

		// The LPN security parameter (e.g., 128)
		u64 mSecParam = 0;

		// What type of Base OTs should be performed
		// BaseExtend requires less compute but more rounds
		SilentBaseType mBaseType = SilentBaseType::BaseExtend;

		// Seed for syndrome decoding
		block mCodeSeed = ZeroBlock; 

		// The base VOLE correlation vector (sender's share)
		// Used to initialize the non-zeros of the noisy vector
		VecF mBaseB;

		// The sender's share of the VOLE correlation (a = b + c * delta)
		VecF mB;

		// Security type: SemiHonest or Malicious
		SilentSecType mSecurityType = SilentSecType::SemiHonest;

		// The matrix multiplication type which compresses the sparse vector
		MultType mLpnMultType = DefaultMultType;

		// Format used for PPRF output organization
		PprfOutputFormat mPprfFormat = PprfOutputFormat::ByTreeIndex;

		// True if we need to derandomize the last mBaseC value for the malicious security check
		bool mDerandomizeMalCheck = false;

		// Enable debugging output and consistency checks when true
		bool mDebug = false;

#ifdef ENABLE_SOFTSPOKEN_OT
		// SoftSpoken OT instances for base OT extension
		macoro::optional<SoftSpokenMalOtSender> mOtExtSender;
		macoro::optional<SoftSpokenMalOtReceiver> mOtExtRecver;
#endif

		/**
		 * @brief Check if base correlations have been set.
		 *
		 * Returns true if both the base OTs and the base VOLE correlations are set.
		 *
		 * @return True if base correlations are set, false otherwise
		 */
		bool hasBaseCors() const;

		/**
		 * @brief Get the number of base OTs and VOLEs required.
		 *
		 * @return A VoleBaseCount struct with mBaseOtCount and mBaseVoleCount
		 */
		VoleBaseCount baseCount() const;

		/**
		 * @brief Generate the base correlations needed for the protocol.
		 *
		 * This performs base OTs and generates base VOLE correlations.
		 * If the chosen method is BaseExtend, it will use SoftSpoken OT extension.
		 *
		 * @param prng Pseudorandom number generator
		 * @param chl Communication channel to the receiver
		 * @param delta The sender's delta value for the VOLE correlation
		 * @return Coroutine task
		 */
		task<> genBaseCors(PRNG& prng, Socket& chl, F delta);

		/**
		 * @brief Set externally generated base correlations.
		 *
		 * This allows manually setting the base OTs and VOLE correlations
		 * instead of using genBaseCors().
		 *
		 * @param sendBaseOts The base OT messages (sender's view)
		 * @param b The sender's base VOLE shares. Should be a vector like type of Fs
		 */
		void setBaseCors(
			span<std::array<block, 2>> sendBaseOts,
			const auto& b);

		/**
		 * @brief Configure the silent VOLE protocol.
		 * 
		 * This sets the parameters and computes derived values needed for the protocol.
		 * Must be called before generating base correlations or performing the protocol.
		 *
		 * @param requestSize Number of VOLE correlations to generate
		 * @param malType Security type (SemiHonest or Malicious)
		 * @param type Type of base OT to use (BaseExtend or Base)
		 * @param noiseType Distribution of the noise vector (Regular or Stationary)
		 * @param secParam Security parameter (typically 128)
		 * @param ctx Context object for F, G operations (default constructed if not provided)
		 * @param mult the lpn compression matrix type to use (default DefaultMultType)
		 */
		void configure(
			u64 requestSize,
			SilentSecType malType = SilentSecType::SemiHonest,
			MultType mult = DefaultMultType,
			SilentBaseType type = SilentBaseType::BaseExtend,
			SdNoiseDistribution noiseType = SdNoiseDistribution::Regular,
			u64 secParam = 128,
			Ctx ctx = {});

		/**
		 * @brief Check if the sender has been configured.
		 *
		 * @return True if configure() has been called, false otherwise
		 */
		bool isConfigured() const;

		/**
		 * @brief Perform the silent VOLE protocol, copying results to provided vector.
		 *
		 * This function produces vector b such that a = b + c * delta,
		 * where a and c are held by the receiver.
		 * The results are copied to the provided vector.
		 *
		 * @param delta The sender's delta value for the VOLE correlation
		 * @param b Output vector to store the sender's share
		 * @param prng Pseudorandom number generator
		 * @param chl Communication channel to the receiver
		 * @return Coroutine task
		 */
		task<> silentSend(
			F delta,
			VecF& b,
			PRNG& prng,
			Socket& chl);

		/**
		 * @brief Perform the silent VOLE protocol, storing results internally.
		 *
		 * Same as silentSend() but the results are stored in mB.
		 * This is more efficient when the results will be used directly from 
		 * the SilentVoleSender object.
		 *
		 * @param delta The sender's delta value for the VOLE correlation
		 * @param n Number of VOLE correlations to generate
		 * @param prng Pseudorandom number generator
		 * @param chl Communication channel to the receiver
		 * @return Coroutine task
		 */
		task<> silentSendInplace(
			F delta,
			u64 n,
			PRNG& prng,
			Socket& chl);

		/**
		 * @brief Clear internal state and free memory.
		 * 
		 * Releases memory used by vectors and resets the generator.
		 */
		void clear();

		/**
		 * @brief Internal debug function to verify protocol correctness.
		 *
		 * @param chl Communication channel to the receiver
		 * @param delta The sender's delta value
		 * @return Coroutine task
		 */
		task<> checkRT(Socket& chl, F delta) const;

		/**
		 * @brief Compute the hash for malicious security check.
		 *
		 * @param X The challenge value from the receiver
		 * @return 32-byte hash array
		 */
		std::array<u8, 32> ferretMalCheck(block X);

		/**
		 * @brief Helper function to access the PPRF generator.
		 * 
		 * @return Reference to the PPRF sender
		 */
		PprfSender<F, Ctx>& gen() {
			if (isConfigured() == false)
				throw std::runtime_error("configure(...) must be called first.");
			return std::visit([](auto& v) -> PprfSender<F, Ctx>&{ return v; }, mGenVar);
			}
		
		/**
		 * @brief Const version of the PPRF generator accessor.
		 * 
		 * @return Const reference to the PPRF sender
		 */
		const PprfSender<F, Ctx>& gen() const {
			if (isConfigured() == false)
				throw std::runtime_error("configure(...) must be called first.");
			return std::visit([](auto& v) -> const PprfSender<F, Ctx>&{ return v; }, mGenVar);
		}
	};






















	template<typename F, typename G, typename Ctx>
	VoleBaseCount SilentVoleSender<F, G, Ctx>::baseCount() const
	{
		if (isConfigured() == false)
			throw std::runtime_error("configure must be called first");

		auto ot = gen().baseOtCount();
		auto vole = mNumPartitions + 1 * (mSecurityType == SilentSecType::Malicious);
		return { ot, vole };
	}

	template<typename F, typename G, typename Ctx>
	bool SilentVoleSender<F, G, Ctx>::hasBaseCors() const
	{
		return 
			isConfigured() && 
			gen().hasBaseOts() && 
			mBaseB.size() == baseCount().mBaseVoleCount;
	}

	template<typename F, typename G, typename Ctx>
	task<> SilentVoleSender<F, G, Ctx>::genBaseCors(PRNG& prng, Socket& chl, F delta)
	{
		MACORO_TRY{
#ifdef LIBOTE_HAS_BASE_OT
			// Determine which base OT implementation to use based on compile flags
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
			setTimePoint("SilentVoleSender.genSilent.begin");

			if (isConfigured() == false)
			{
				throw std::runtime_error("configure must be called first");
			}

			auto count = baseCount();

			// Compute the correlation for the noisy coordinates
			auto b = VecF{};
			mCtx.resize(b, count.mBaseVoleCount);
			auto xx = mCtx.template binaryDecomposition<F>(delta);
			auto msg = AlignedUnVector<std::array<block, 2>>(count.mBaseOtCount);
			auto nv = NoisyVoleSender<F, G, Ctx>{};

			// Use OT extension for the base OTs if specified
			if (mBaseType == SilentBaseType::BaseExtend)
			{
#ifdef ENABLE_SOFTSPOKEN_OT
				// Initialize OT extension objects if they don't exist
				if (!mOtExtSender)
					mOtExtSender = SoftSpokenMalOtSender{};
				if (!mOtExtRecver)
					mOtExtRecver = SoftSpokenMalOtReceiver{};

				// If we don't have base OTs for the OT extension, generate them first
				if (mOtExtRecver->hasBaseOts() == false)
				{
					// Resize to accommodate additional base OTs for SoftSpoken
					msg.resize(msg.size() + mOtExtRecver->baseOtCount());
					co_await mOtExtSender->send(msg, prng, chl);

					// Set the base OTs for the receiver
					mOtExtRecver->setBaseOts(
						span<std::array<block, 2>>(msg).subspan(
							msg.size() - mOtExtRecver->baseOtCount(),
							mOtExtRecver->baseOtCount()));
					msg.resize(msg.size() - mOtExtRecver->baseOtCount());

					// Perform noisy VOLE
					co_await nv.send(delta, b, prng, *mOtExtRecver, chl, mCtx);
				}
				else
				{
					// If we already have base OTs, run both operations in parallel
					auto chl2 = chl.fork();
					auto prng2 = prng.fork();

					if (msg.size())
					{
						co_await
							macoro::when_all_ready(
								nv.send(delta, b, prng2, *mOtExtRecver, chl2, mCtx),
								mOtExtSender->send(msg, prng, chl));
					}
					else
						co_await nv.send(delta, b, prng2, *mOtExtRecver, chl2, mCtx);
				}
#else
				throw std::runtime_error("ENABLE_SOFTSPOKEN_OT = false, must enable soft spoken ." LOCATION);
#endif
			}
			else
			{
				// Use base OT protocol directly
				auto chl2 = chl.fork();
				auto prng2 = prng.fork();
				auto baseOt = BaseOT{};

				if(msg.size())
					co_await
						macoro::when_all_ready(
							baseOt.send(msg, prng, chl),
							nv.send(delta, b, prng2, baseOt, chl2, mCtx));
				else
					co_await nv.send(delta, b, prng2, baseOt, chl2, mCtx);
			}

			// Set the base correlations
			setBaseCors(msg, b);
			if (mSecurityType == SilentSecType::Malicious)
				mDerandomizeMalCheck = false;

			setTimePoint("SilentVoleSender.genSilent.done");
#else
			throw std::runtime_error("LIBOTE_HAS_BASE_OT = false, must enable relic, sodium or simplest ot asm." LOCATION);
			co_return;
#endif

		} MACORO_CATCH(eptr) {
			co_await chl.close();
			std::rethrow_exception(eptr);
		}
	}

	template<typename F, typename G, typename Ctx>
	void SilentVoleSender<F, G, Ctx>::configure(
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

		// Calculate the bit size for the field elements
		u64 bitCount = 1;
		if (mCtx.template isField<F>())
			bitCount = mCtx.template bitSize<G>();

		// Configure parameters for syndrome decoding
		auto config = syndromeDecodingConfigure(
			mSecParam, mRequestSize, mLpnMultType, noiseType, bitCount);
		mNumPartitions = config.mNumPartitions;
		mSizePer = config.mSizePer;
		mNoiseVecSize = mNumPartitions * mSizePer;
		mCodeSeed = block(12528943721987127, 98743297823479812);

		// Initialize the appropriate PPRF based on noise distribution
		if (SdNoiseDistribution::Regular == noiseType)
		{
			mGenVar.template emplace<0>();  // Use RegularPprfSender
			mPprfFormat = PprfOutputFormat::Interleaved;
		}
		else if (SdNoiseDistribution::Stationary == noiseType)
		{
			mGenVar.template emplace<1>();  // Use StationaryPprfSender
			mPprfFormat = PprfOutputFormat::ByTreeIndex;
		}
		else
		{
			throw std::invalid_argument("SilentNoiseType not supported. " LOCATION);
		}

		mState = State::Configured;
		gen().configure(mSizePer, mNumPartitions);
	}

	template<typename F, typename G, typename Ctx>
	bool SilentVoleSender<F, G, Ctx>::isConfigured() const { 
		return mState != State::Default; 
	}

	template<typename F, typename G, typename Ctx>
	void SilentVoleSender<F, G, Ctx>::setBaseCors(
		span<std::array<block, 2>> sendBaseOts,
		const auto& b)
	{
		if (!isConfigured())
			throw RTE_LOC;

		// Validate input sizes
		if ((u64)sendBaseOts.size() != baseCount().mBaseOtCount)
			throw RTE_LOC;

		if (b.size() != baseCount().mBaseVoleCount)
			throw RTE_LOC;

		if (sendBaseOts.size())
		{
			// Set base OTs in the PPRF
			gen().setBase(sendBaseOts);
		}

		// We store the negative of b. This is because we need the correlation
		// 
		//  mBaseA + mBaseB = mBaseC * delta
		// 
		// for the pprf to expand correctly but the input correlation is a vole:
		//
		//  mBaseA = b + mBaseC * delta
		// 
		mCtx.resize(mBaseB, b.size());
		mCtx.zero(mBaseB.begin(), mBaseB.end());
		for (u64 i = 0; i < mBaseB.size(); ++i)
			mCtx.minus(mBaseB[i], mBaseB[i], b[i]);

		// For malicious security, we'll need to derandomize
		if(mSecurityType == SilentSecType::Malicious)
			mDerandomizeMalCheck = true;
	}

	template<typename F, typename G, typename Ctx>
	task<> SilentVoleSender<F, G, Ctx>::silentSend(
		F delta,
		VecF& b,
		PRNG& prng,
		Socket& chl)
	{
		// Run the main protocol
		co_await silentSendInplace(delta, b.size(), prng, chl);

		// Copy results to the output vector
		mCtx.copy(mB.begin(), mB.begin() + b.size(), b.begin());


		if(mGenVar.index() == 0)
			clear();

		setTimePoint("SilentVoleSender.expand.ldpc.msgCpy");
	}

	template<typename F, typename G, typename Ctx>
	task<> SilentVoleSender<F, G, Ctx>::silentSendInplace(
		F delta,
		u64 n,
		PRNG& prng,
		Socket& chl)
	{
		MACORO_TRY{
			auto X = block{};
			auto hash = std::array<u8, 32>{};
			auto baseB = VecF{};
			setTimePoint("SilentVoleSender.ot.enter");

			// Configure if not already done
			if (isConfigured() == false)
			{
				configure(n, mSecurityType, mLpnMultType, SilentBaseType::BaseExtend);
			}

			// Validate requested size
			if (mRequestSize < n)
				throw std::invalid_argument("n does not match the requested number of OTs via configure(...). " LOCATION);

			// Generate base correlations if needed
			if (hasBaseCors() == false)
			{
				co_await genBaseCors(prng, chl, delta);
			}

			// For malicious security, handle derandomization
			if (mSecurityType == SilentSecType::Malicious && mDerandomizeMalCheck)
			{
				if constexpr (MaliciousSupported)
				{
					// Receive the difference value from receiver
					std::vector<u8> buffer(mCtx.template byteSize<G>());
					co_await chl.recv(buffer);
					VecG diff;
					mCtx.resize(diff, 1);
					mCtx.deserialize(buffer.begin(), buffer.end(), diff.begin());

					// The parties currently have a = b' + c' * d
					// but want                   a = b  + c  * d
					// The receiver sent us diff = (c'-c)
					// We will update b' as b = b' + (c'-c) * d and therefore we get
					//
					// b' = a - c' * d
					// b  = b' + (c'-c) * d
					//    = a - c' * d + (c'-c) * d
					//    = a - c' * d + c' * d - c * d
					//    = a - c * d
					// a  = b + c * d
					// 
					mCtx.plus(mBaseB[mNumPartitions], mBaseB[mNumPartitions], diff[0]);
				}
				else throw RTE_LOC;
			}

			setTimePoint("SilentVoleSender.start");

			// Allocate and initialize mB
			mCtx.resize(mB, 0);
			mCtx.resize(mB, mNoiseVecSize);

			if (mTimer)
				gen().setTimer(*mTimer);

			// Extract just the first mNumPartitions value of mBaseB
			// The last position is for the malicious check (if present)
			mCtx.resize(baseB, mNumPartitions);
			mCtx.copy(mBaseB.begin(), mBaseB.begin() + mNumPartitions, baseB.begin());

			// Program the output of the PPRF to be secret shares of
			// our secret share of delta * noiseVals. The receiver
			// can then manually add their shares of this to the
			// output of the PPRF at the correct locations.
			co_await gen().expand(chl, baseB, prng.get(), mB,
				mPprfFormat, true, 1, mCtx);
			setTimePoint("SilentVoleSender.expand.pprf");

			// Debug consistency check
			if (mDebug)
			{
				co_await checkRT(chl, delta);
				setTimePoint("SilentVoleSender.expand.checkRT");
			}

			// Malicious security check
			if (mSecurityType == SilentSecType::Malicious)
			{
				// Receive challenge from receiver
				co_await chl.recv(X);

				// Compute our hash
				if constexpr (MaliciousSupported)
					hash = ferretMalCheck(X);
				else
					throw std::runtime_error("malicious is currently only supported for GF128 block. " LOCATION);

				// Send our hash to the receiver
				co_await chl.send(std::move(hash));
			}

			// Apply the appropriate linear code to compress the sparse vector
			switch (mLpnMultType)
			{
			case osuCrypto::MultType::ExConv7x24:
			case osuCrypto::MultType::ExConv21x24:
			{
				// Configure the expander code
				ExConvCode encoder;
				u64 expanderWeight, accumulatorWeight, scaler;
				double minDist;
				ExConvConfigure(mLpnMultType, scaler, expanderWeight, accumulatorWeight, minDist);
				assert(scaler == 2 && minDist < 1 && minDist > 0);

				encoder.config(mRequestSize, mNoiseVecSize, 
					expanderWeight, accumulatorWeight, true, true,
					mCodeSeed);

				if (mTimer)
					encoder.setTimer(getTimer());
				encoder.dualEncode<F, Ctx>(mB.begin(), mCtx);
				break;
			}
			case MultType::BlkAcc3x8:
			case MultType::BlkAcc3x32:
			{
				u64 depth, sigma,scaler;
				double md;
				BlkAccConfigure(mLpnMultType, scaler,sigma, depth, md);
				BlkAccCode code;
				code.init(mRequestSize, mNoiseVecSize, sigma, depth, mCodeSeed);
				code.dualEncode<F, Ctx>(mB.begin(), mCtx);


				break;
			}
			case MultType::QuasiCyclic:
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
					encoder.dualEncode(mB);
				}
				else
					throw std::runtime_error("QuasiCyclic is only supported for GF128, i.e. block. " LOCATION);
#else
				throw std::runtime_error("QuasiCyclic requires ENABLE_BITPOLYMUL = true. " LOCATION);
#endif
				break;
			}
			case osuCrypto::MultType::Tungsten:
			{
				experimental::TungstenCode encoder;
				encoder.config(
					oc::roundUpTo(mRequestSize, 8),
					mNoiseVecSize, mCodeSeed);
				encoder.dualEncode<F, Ctx>(mB.begin(), mCtx);
				break;
			}
			default:
				throw std::runtime_error("Code is not supported. " LOCATION);
				break;
			}

			mCodeSeed = mAesFixedKey.hashBlock(mCodeSeed);

			// Resize the buffer to only contain the requested elements
			mCtx.resize(mB, mRequestSize);

			// Protocol complete, reset state
			mBaseB.clear();
			if(mGenVar.index() == 0)
				mState = State::Default;
			else
				mState = State::Configured;

		} MACORO_CATCH(eptr) {
			co_await chl.close();
			std::rethrow_exception(eptr);
		}
	}

	template<typename F, typename G, typename Ctx>
	task<> SilentVoleSender<F, G, Ctx>::checkRT(Socket& chl, F delta) const
	{
		// Send debugging information to the receiver
		co_await chl.send(delta);
		co_await chl.send(mB);
		co_await chl.send(mBaseB);
	}

	template<typename F, typename G, typename Ctx>
	std::array<u8, 32> SilentVoleSender<F, G, Ctx>::ferretMalCheck(block X)
	{
		// Compute sum of X^i * B_i for all positions
		auto xx = X;
		block sum0 = ZeroBlock;
		block sum1 = ZeroBlock;
		for (u64 i = 0; i < (u64)mB.size(); ++i)
		{
			// Compute X^i * B_i using GF(2^128) multiplication
			block low, high;
			xx.gf128Mul(mB[i], low, high);
			sum0 = sum0 ^ low;
			sum1 = sum1 ^ high;

			// Update X^i to X^(i+1)
			xx = xx.gf128Mul(X);
		}

		// Final reduction of 256-bit sum to 128 bits
		block mySum = sum0.gf128Reduce(sum1);

		// Hash the result with the base correlation
		std::array<u8, 32> myHash;
		RandomOracle ro(32);
		ro.Update(mySum ^ mBaseB.back());
		ro.Final(myHash);

		return myHash;
	}

	template<typename F, typename G, typename Ctx>
	void SilentVoleSender<F, G, Ctx>::clear()
	{
		// Free all memory and reset the generator
		mB = {};
		std::visit([](auto& gen) {gen.clear(); }, mGenVar);
	}

}

#endif
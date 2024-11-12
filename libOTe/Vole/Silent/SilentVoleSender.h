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

namespace osuCrypto
{
	template<
		typename F,
		typename G = F,
		typename Ctx = DefaultCoeffCtx<F, G>
	>
	class SilentVoleSender : public TimerAdapter
	{
	public:
		bool mDebug = false;

		static constexpr u64 mScaler = 2;

		static constexpr bool MaliciousSupported =
			std::is_same_v<F, block>&& std::is_same_v<Ctx, CoeffCtxGF128>;

		enum class State
		{
			Default,
			Configured,
			HasBase
		};

		using VecF = typename Ctx::template Vec<F>;
		using VecG = typename Ctx::template Vec<G>;

		State mState = State::Default;

		// the context used to perform F, G operations
		Ctx mCtx;

		// the pprf used to generate the noise vector.
		RegularPprfSender<F, G, Ctx> mGen;

		// the number of correlations requested.
		u64 mRequestSize = 0;

		// the length of the noisy vector.
		u64 mNoiseVecSize = 0;

		// the weight of the nosy vector
		u64 mNumPartitions = 0;

		// the size of each regular, weight 1, subvector
		// of the noisy vector. mNoiseVecSize = mNumPartions * mSizePer
		u64 mSizePer = 0;

		// the lpn security parameters
		u64 mSecParam = 0;

		// the type of base OT OT that should be performed.
		// Base requires more work but less communication.
		SilentBaseType mBaseType = SilentBaseType::BaseExtend;

		// the base Vole correlation. To generate the silent vole,
		// we must first create a small vole 
		//   mBaseA + mBaseB = mBaseC * mDelta.
		// These will be used to initialize the non-zeros of the noisy 
		// vector. mBaseB is the b in this corrlations.
		VecF mBaseB;

		// the full sized noisy vector. This will initalially be 
		// sparse with the corrlations
		//   mA = mB + mC * mDelta
		// before it is compressed. 
		VecF mB;

		// determines if the malicious checks are performed.
		SilentSecType mMalType = SilentSecType::SemiHonest;

		// A flag to specify the linear code to use
		MultType mMultType = DefaultMultType;


		block mDeltaShare;

#ifdef ENABLE_SOFTSPOKEN_OT
		macoro::optional<SoftSpokenMalOtSender> mOtExtSender;
		macoro::optional<SoftSpokenMalOtReceiver> mOtExtRecver;
#endif

		bool hasSilentBaseOts()const
		{
			return mGen.hasBaseOts();
		}


		u64 baseVoleCount() const
		{
			return mNumPartitions + 1 * (mMalType == SilentSecType::Malicious);
		}

		// Generate the silent base OTs. If the Iknp 
		// base OTs are set then we do an IKNP extend,
		// otherwise we perform a base OT protocol to
		// generate the needed OTs.
		task<> genSilentBaseOts(PRNG& prng, Socket& chl, F delta)
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
			setTimePoint("SilentVoleSender.genSilent.begin");

			if (isConfigured() == false)
			{
				throw std::runtime_error("configure must be called first");
			}

			// compute the correlation for the noisy coordinates.
			auto b = VecF{};
			mCtx.resize(b, baseVoleCount());
			auto xx = mCtx.template binaryDecomposition<F>(delta);
			auto msg = AlignedUnVector<std::array<block, 2>>(silentBaseOtCount());
			auto nv = NoisyVoleSender<F, G, Ctx>{};

			if (mBaseType == SilentBaseType::BaseExtend)
			{
#ifdef ENABLE_SOFTSPOKEN_OT

				if (!mOtExtSender)
					mOtExtSender = SoftSpokenMalOtSender{};
				if (!mOtExtRecver)
					mOtExtRecver = SoftSpokenMalOtReceiver{};

				if (mOtExtRecver->hasBaseOts() == false)
				{
					msg.resize(msg.size() + mOtExtRecver->baseOtCount());
					co_await(mOtExtSender->send(msg, prng, chl));

					mOtExtRecver->setBaseOts(
						span<std::array<block, 2>>(msg).subspan(
							msg.size() - mOtExtRecver->baseOtCount(),
							mOtExtRecver->baseOtCount()));
					msg.resize(msg.size() - mOtExtRecver->baseOtCount());
					
					co_await(nv.send(delta, b, prng, *mOtExtRecver, chl, mCtx));
				}
				else
				{
					auto chl2 = chl.fork();
					auto prng2 = prng.fork();
					
					co_await(
						macoro::when_all_ready(
							nv.send(delta, b, prng2, *mOtExtRecver, chl2, mCtx),
							mOtExtSender->send(msg, prng, chl)));
				}
#else
				throw std::runtime_error("ENABLE_SOFTSPOKEN_OT = false, must enable soft spoken ." LOCATION);
#endif
			}
			else
			{
				auto chl2 = chl.fork();
				auto prng2 = prng.fork();
				auto baseOt = BaseOT{};
				
				co_await(
					macoro::when_all_ready(
						baseOt.send(msg, prng, chl),
						nv.send(delta, b, prng2, baseOt, chl2, mCtx)));
			}

			setSilentBaseOts(msg, b);
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

		// configure the silent OT extension. This sets
		// the parameters and figures out how many base OT
		// will be needed. These can then be ganerated for
		// a different OT extension or using a base OT protocol.
		void configure(
			u64 requestSize,
			SilentBaseType type = SilentBaseType::BaseExtend,
			u64 secParam = 128,
			Ctx ctx = {})
		{
			mCtx = std::move(ctx);
			mSecParam = secParam;
			mRequestSize = requestSize;
			mState = State::Configured;
			mBaseType = type;

			syndromeDecodingConfigure(
				mNumPartitions, mSizePer, mNoiseVecSize,
				mSecParam, mRequestSize, mMultType);

			mGen.configure(mSizePer, mNumPartitions);
		}

		// return true if this instance has been configured.
		bool isConfigured() const { return mState != State::Default; }

		// Returns how many base OTs the silent OT extension
		// protocol will needs.
		u64 silentBaseOtCount() const
		{
			if (isConfigured() == false)
				throw std::runtime_error("configure must be called first");

			return mGen.baseOtCount();
		}

		// Set the externally generated base OTs. This choice
		// bits must be the one return by sampleBaseChoiceBits(...).
		void setSilentBaseOts(
			span<std::array<block, 2>> sendBaseOts,
			const VecF& b)
		{
			if ((u64)sendBaseOts.size() != silentBaseOtCount())
				throw RTE_LOC;

			if (b.size() != baseVoleCount())
				throw RTE_LOC;

			mGen.setBase(sendBaseOts);

			// we store the negative of b. This is because
			// we need the correlation
			// 
			//  mBaseA + mBaseB = mBaseC * delta
			// 
			// for the pprf to expand correctly but the 
			// input correlation is a vole:
			//
			//  mBaseA = b + mBaseC * delta
			// 
			mCtx.resize(mBaseB, b.size());
			mCtx.zero(mBaseB.begin(), mBaseB.end());
			for (u64 i = 0; i < mBaseB.size(); ++i)
				mCtx.minus(mBaseB[i], mBaseB[i], b[i]);
		}

		// The native OT extension interface of silent
		// OT. The receiver does not get to specify 
		// which OT message they receiver. Instead
		// the protocol picks them at random. Use the 
		// send(...) interface for the normal behavior.
		task<> silentSend(
			F delta,
			VecF& b,
			PRNG& prng,
			Socket& chl)
		{
			co_await(silentSendInplace(delta, b.size(), prng, chl));

			mCtx.copy(mB.begin(), mB.begin() + b.size(), b.begin());
			clear();

			setTimePoint("SilentVoleSender.expand.ldpc.msgCpy");
		}

		// The native OT extension interface of silent
		// OT. The receiver does not get to specify 
		// which OT message they receiver. Instead
		// the protocol picks them at random. Use the 
		// send(...) interface for the normal behavior.
		task<> silentSendInplace(
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


			if (isConfigured() == false)
			{
				// first generate 128 normal base OTs
				configure(n, SilentBaseType::BaseExtend);
			}

			if (mRequestSize < n)
				throw std::invalid_argument("n does not match the requested number of OTs via configure(...). " LOCATION);

			if (mGen.hasBaseOts() == false)
			{
				// recvs data
				co_await(genSilentBaseOts(prng, chl, delta));
			}

			setTimePoint("SilentVoleSender.start");
			//gTimer.setTimePoint("SilentVoleSender.iknp.base2");

			// allocate B
			mCtx.resize(mB, 0);
			mCtx.resize(mB, mNoiseVecSize);

			if (mTimer)
				mGen.setTimer(*mTimer);

			// extract just the first mNumPartitions value of mBaseB. 
			// the last is for the malicious check (if present).
			mCtx.resize(baseB, mNumPartitions);
			mCtx.copy(mBaseB.begin(), mBaseB.begin() + mNumPartitions, baseB.begin());

			// program the output the PPRF to be secret shares of
			// our secret share of delta * noiseVals. The receiver
			// can then manually add their shares of this to the
			// output of the PPRF at the correct locations.
			co_await(mGen.expand(chl, baseB, prng.get(), mB,
				PprfOutputFormat::Interleaved, true, 1));
			setTimePoint("SilentVoleSender.expand.pprf");

			if (mDebug)
			{
				co_await(checkRT(chl, delta));
				setTimePoint("SilentVoleSender.expand.checkRT");
			}

			if (mMalType == SilentSecType::Malicious)
			{
				co_await(chl.recv(X));

				if constexpr (MaliciousSupported)
					hash = ferretMalCheck(X);
				else
					throw std::runtime_error("malicious is currently only supported for GF128 block. " LOCATION);

				co_await(chl.send(std::move(hash)));
			}

			switch (mMultType)
			{
			case osuCrypto::MultType::ExConv7x24:
			case osuCrypto::MultType::ExConv21x24:
			{
				ExConvCode encoder;
				u64 expanderWeight, accumulatorWeight, scaler;
				double minDist;
				ExConvConfigure(mMultType, scaler, expanderWeight, accumulatorWeight, minDist);
				assert(scaler == 2 && minDist < 1 && minDist > 0);

				encoder.config(mRequestSize, mNoiseVecSize, expanderWeight, accumulatorWeight);
				if (mTimer)
					encoder.setTimer(getTimer());
				encoder.dualEncode<F, Ctx>(mB.begin(), mCtx);
				break;
			}
			case MultType::QuasiCyclic:
			{
#ifdef ENABLE_BITPOLYMUL
				if constexpr (
					std::is_same_v<F, block> &&
					std::is_same_v<G, block> &&
					std::is_same_v<Ctx, CoeffCtxGF128>)
				{
					QuasiCyclicCode encoder;
					encoder.init2(mRequestSize, mNoiseVecSize);
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
				encoder.config(oc::roundUpTo(mRequestSize, 8), mNoiseVecSize);
				encoder.dualEncode<F, Ctx>(mB.begin(), mCtx);
				break;
			}
			default:
				throw std::runtime_error("Code is not supported. " LOCATION);
				break;
			}

			mCtx.resize(mB, mRequestSize);

			mState = State::Default;
			mBaseB.clear();


			} MACORO_CATCH(eptr) {
				co_await chl.close();
				std::rethrow_exception(eptr);
			}
		}

		task<> checkRT(Socket& chl, F delta) const
		{
			co_await(chl.send(delta));
			co_await(chl.send(mB));
			co_await(chl.send(mBaseB));
		}

		std::array<u8, 32> ferretMalCheck(block X)
		{

			auto xx = X;
			block sum0 = ZeroBlock;
			block sum1 = ZeroBlock;
			for (u64 i = 0; i < (u64)mB.size(); ++i)
			{
				block low, high;
				xx.gf128Mul(mB[i], low, high);
				sum0 = sum0 ^ low;
				sum1 = sum1 ^ high;

				xx = xx.gf128Mul(X);
			}

			block mySum = sum0.gf128Reduce(sum1);

			std::array<u8, 32> myHash;
			RandomOracle ro(32);
			ro.Update(mySum ^ mBaseB.back());
			ro.Final(myHash);

			return myHash;
		}

		void clear()
		{
			mB = {};
			mGen.clear();
		}
	};

}

#endif
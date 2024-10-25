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
#include <libOTe/Tools/QuasiCyclicCode.h>
#include <libOTe/Tools/TungstenCode/TungstenCode.h>

namespace osuCrypto
{


	template<
		typename F,
		typename G = F,
		typename Ctx = DefaultCoeffCtx<F, G>
	>
	class SilentVoleReceiver : public TimerAdapter
	{
	public:
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

		// The current state of the protocol
		State mState = State::Default;

		// the context used to perform F, G operations
		Ctx mCtx;

		// The number of correlations the user requested.
		u64 mRequestSize = 0;

		// the LPN security parameter
		u64 mSecParam = 0;

		// The length of the noisy vectors (2 * mN for the most codes).
		u64 mNoiseVecSize = 0;

		// We perform regular LPN, so this is the
		// size of the each chunk. 
		u64 mSizePer = 0;

		// the number of noisy positions
		u64 mNumPartitions = 0;

		// The noisy coordinates.
		std::vector<u64> mS;

		// What type of Base OTs should be performed.
		SilentBaseType mBaseType;

		// The matrix multiplication type which compresses 
		// the sparse vector.
		MultType mMultType = DefaultMultType;

		// The multi-point punctured PRF for generating
		// the sparse vectors.
		RegularPprfReceiver<F, G, Ctx> mGen;

		// The internal buffers for holding the expanded vectors.
		// mA  = mB + mC * delta
		VecF mA;

		// mA = mB + mC * delta
		VecG mC;

		u64 mNumThreads = 1;

		bool mDebug = false;

		BitVector mIknpSendBaseChoice;

		SilentSecType mMalType = SilentSecType::SemiHonest;

		block mMalCheckSeed, mMalCheckX, mMalBaseA;

		// we 
		VecF mBaseA;
		VecG mBaseC;


#ifdef ENABLE_SOFTSPOKEN_OT
		macoro::optional<SoftSpokenMalOtSender> mOtExtSender;
		macoro::optional<SoftSpokenMalOtReceiver> mOtExtRecver;
#endif

		u64 baseVoleCount() const
		{
			return mNumPartitions + 1 * (mMalType == SilentSecType::Malicious);
		}

		// returns true if the silent base OTs are set.
		bool hasSilentBaseOts() const {
			return mGen.hasBaseOts();
		};

		// Generate the silent base OTs. If the Iknp 
		// base OTs are set then we do an IKNP extend,
		// otherwise we perform a base OT protocol to
		// generate the needed OTs.
		task<> genSilentBaseOts(PRNG& prng, Socket& chl)
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

			auto choice = sampleBaseChoiceBits(prng);
			AlignedUnVector<block> msg(choice.size());

			// sample the noise vector noiseVals such that we will compute
			//
			//  C = (000 noiseVals[0] 0000 ... 000 noiseVals[p] 000)
			//
			// and then we want secret shares of C * delta. As a first step
			// we will compute secret shares of
			//
			// delta * noiseVals
			//
			// and store our share in voleDeltaShares. This party will then
			// compute their share of delta * C as what comes out of the PPRF
			// plus voleDeltaShares[i] added to the appreciate spot. Similarly, the
			// other party will program the PPRF to output their share of delta * noiseVals.
			//
			auto noiseVals = sampleBaseVoleVals(prng);
			auto baseAs = VecF{};
			mCtx.resize(baseAs, noiseVals.size());

			auto nv = NoisyVoleReceiver<F, G, Ctx>{};
			if (mTimer)
				nv.setTimer(*mTimer);

			if (mBaseType == SilentBaseType::BaseExtend)
			{
#ifdef ENABLE_SOFTSPOKEN_OT
				if (!mOtExtRecver)
					mOtExtRecver.emplace();

				if (!mOtExtSender)
					mOtExtSender.emplace();

				if (mOtExtSender->hasBaseOts() == false)
				{
					msg.resize(msg.size() + mOtExtSender->baseOtCount());
					auto bb = BitVector{ mOtExtSender->baseOtCount() };
					bb.randomize(prng);
					choice.append(bb);

					co_await mOtExtRecver->receive(choice, msg, prng, chl);

					mOtExtSender->setBaseOts(
						span<block>(msg).subspan(
							msg.size() - mOtExtSender->baseOtCount(),
							mOtExtSender->baseOtCount()),
						bb);

					msg.resize(msg.size() - mOtExtSender->baseOtCount());
					co_await nv.receive(noiseVals, baseAs, prng, *mOtExtSender, chl, mCtx);
				}
				else
				{
					auto chl2 = chl.fork();
					auto prng2 = prng.fork();

					co_await
						macoro::when_all_ready(
							nv.receive(noiseVals, baseAs, prng2, *mOtExtSender, chl2, mCtx),
							mOtExtRecver->receive(choice, msg, prng, chl)
						);
				}
#else
				throw std::runtime_error("soft spoken must be enabled");
#endif
			}
			else
			{
				auto chl2 = chl.fork();
				auto prng2 = prng.fork();
				BaseOT baseOt;

				co_await
					macoro::when_all_ready(
						baseOt.receive(choice, msg, prng, chl),
						nv.receive(noiseVals, baseAs, prng2, baseOt, chl2, mCtx))
					;

			}

			setSilentBaseOts(msg, baseAs);
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

			syndromeDecodingConfigure(mNumPartitions, mSizePer, mNoiseVecSize, mSecParam, mRequestSize, mMultType);

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

		// The silent base OTs must have specially set base OTs.
		// This returns the choice bits that should be used.
		// Call this is you want to use a specific base OT protocol
		// and then pass the OT messages back using setSilentBaseOts(...).
		BitVector sampleBaseChoiceBits(PRNG& prng) {

			if (isConfigured() == false)
				throw std::runtime_error("configure(...) must be called first");

			auto choice = mGen.sampleChoiceBits(prng);

			return choice;
		}

		VecG sampleBaseVoleVals(PRNG& prng)
		{
			if (isConfigured() == false)
				throw std::runtime_error("configure must be called first. " LOCATION);

			// sample the values of the noisy coordinate of c
			// and perform a noicy vole to get a = b + mD * c


			mCtx.resize(mBaseC, mNumPartitions + (mMalType == SilentSecType::Malicious));

			if (mCtx.template bitSize<G>() == 1)
			{
				mCtx.one(mBaseC.begin(), mBaseC.begin() + mNumPartitions);
			}
			else
			{
				VecG zero, one;
				mCtx.resize(zero, 1);
				mCtx.resize(one, 1);
				mCtx.zero(zero.begin(), zero.end());
				mCtx.one(one.begin(), one.end());
				for (size_t i = 0; i < mNumPartitions; i++)
				{
					mCtx.fromBlock(mBaseC[i], prng.get<block>());

					// must not be zero.
					while (mCtx.eq(zero[0], mBaseC[i]))
						mCtx.fromBlock(mBaseC[i], prng.get<block>());

					// if we are not a field, then the noise should be odd.
					if (mCtx.template isField<F>() == false)
					{
						u8 odd = mCtx.binaryDecomposition(mBaseC[i])[0];
						if (odd)
							mCtx.plus(mBaseC[i], mBaseC[i], one[0]);
					}
				}
			}


			mS.resize(mNumPartitions);
			mGen.getPoints(mS, PprfOutputFormat::Interleaved);

			if (mMalType == SilentSecType::Malicious)
			{
				if constexpr (MaliciousSupported)
				{
					mMalCheckSeed = prng.get();

					auto yIter = mBaseC.begin();
					mCtx.zero(mBaseC.end() - 1, mBaseC.end());
					for (u64 i = 0; i < mNumPartitions; ++i)
					{
						auto s = mS[i];
						auto xs = mMalCheckSeed.gf128Pow(s + 1);
						mBaseC[mNumPartitions] = mBaseC[mNumPartitions] ^ xs.gf128Mul(*yIter);
						++yIter;
					}
				}
				else
				{
					throw std::runtime_error("malicious is currently only supported for GF128 block. " LOCATION);
				}
			}

			return mBaseC;
		}

		// Set the externally generated base OTs. This choice
		// bits must be the one return by sampleBaseChoiceBits(...).
		void setSilentBaseOts(
			span<block> recvBaseOts,
			VecF& baseA)
		{
			if (isConfigured() == false)
				throw std::runtime_error("configure(...) must be called first.");

			if (static_cast<u64>(recvBaseOts.size()) != silentBaseOtCount())
				throw std::runtime_error("wrong number of silent base OTs");

			mGen.setBase(recvBaseOts);

			mCtx.resize(mBaseA, baseA.size());
			mCtx.copy(baseA.begin(), baseA.end(), mBaseA.begin());
			mState = State::HasBase;
		}

		// Perform the actual OT extension. If silent
		// base OTs have been generated or set, then
		// this function is non-interactive. Otherwise
		// the silent base OTs will automatically be performed.
		task<> silentReceive(
			VecG& c,
			VecF& a,
			PRNG& prng,
			Socket& chl)
		{
			MACORO_TRY{
			
			if (c.size() != a.size())
				throw std::runtime_error("input sizes do not match." LOCATION);

			co_await silentReceiveInplace(c.size(), prng, chl);

			mCtx.copy(mC.begin(), mC.begin() + c.size(), c.begin());
			mCtx.copy(mA.begin(), mA.begin() + a.size(), a.begin());

			clear();

		} MACORO_CATCH(eptr) {
			co_await chl.close();
			std::rethrow_exception(eptr);
		}
		}
		// Perform the actual OT extension. If silent
		// base OTs have been generated or set, then
		// this function is non-interactive. Otherwise
		// the silent base OTs will automatically be performed.
		task<> silentReceiveInplace(
			u64 n,
			PRNG& prng,
			Socket& chl)
		{
			MACORO_TRY{
			auto myHash = std::array<u8, 32>{};
			auto theirHash = std::array<u8, 32>{};
			gTimer.setTimePoint("SilentVoleReceiver.ot.enter");
			if (isConfigured() == false)
			{
				// first generate 128 normal base OTs
				configure(n, SilentBaseType::BaseExtend);
			}

			if (mRequestSize < n)
				throw std::invalid_argument("n does not match the requested number of OTs via configure(...). " LOCATION);


			if (hasSilentBaseOts() == false)
			{
				co_await genSilentBaseOts(prng, chl);
			}

			// allocate mA
			mCtx.resize(mA, 0);
			mCtx.resize(mA, mNoiseVecSize);

			setTimePoint("SilentVoleReceiver.alloc");

			// allocate the space for mC
			mCtx.resize(mC, 0);
			mCtx.resize(mC, mNoiseVecSize);
			mCtx.zero(mC.begin(), mC.end());
			setTimePoint("SilentVoleReceiver.alloc.zero");

			if (mTimer)
				mGen.setTimer(*mTimer);

			// As part of the setup, we have generated 
			//  
			//  mBaseA + mBaseB = mBaseC * mDelta
			// 
			// We have   mBaseA, mBaseC, 
			// they have mBaseB, mDelta
			// This was done with a small (noisy) vole.
			// 
			// We use the Pprf to expand as
			//   
			//    mA' = mB + mS(mBaseB)
			//        = mB + mS(mBaseC * mDelta - mBaseA)
			//        = mB + mS(mBaseC * mDelta) - mS(mBaseA) 
			// 
			// Therefore if we add mS(mBaseA) to mA' we will get
			// 
			//    mA = mB + mS(mBaseC * mDelta)
			//
			co_await mGen.expand(chl, mA, PprfOutputFormat::Interleaved, true, mNumThreads);

			setTimePoint("SilentVoleReceiver.expand.pprf_transpose");

			// populate the noisy coordinates of mC and
			// update mA to be a secret share of mC * delta
			for (u64 i = 0; i < mNumPartitions; ++i)
			{
				auto pnt = mS[i];
				mCtx.copy(mC[pnt], mBaseC[i]);
				mCtx.plus(mA[pnt], mA[pnt], mBaseA[i]);
			}

			if (mDebug)
			{
				co_await checkRT(chl);
				setTimePoint("SilentVoleReceiver.expand.checkRT");
			}


			if (mMalType == SilentSecType::Malicious)
			{
				co_await chl.send(std::move(mMalCheckSeed));

				if constexpr (MaliciousSupported)
					myHash = ferretMalCheck();
				else {
					throw std::runtime_error("malicious is currently only supported for GF128 block. " LOCATION);
				}

				co_await chl.recv(theirHash);

				if (theirHash != myHash)
				{
					throw std::runtime_error("malcicious security check failed. " LOCATION);
				}
			}


			switch (mMultType)
			{
			case osuCrypto::MultType::ExConv7x24:
			case osuCrypto::MultType::ExConv21x24:
			{
				u64 expanderWeight, accumulatorWeight, scaler;
				double minDist;
				ExConvConfigure(mMultType, scaler, expanderWeight, accumulatorWeight, minDist);
				ExConvCode encoder;
				assert(scaler == 2 && minDist < 1 && minDist > 0);
				encoder.config(mRequestSize, mNoiseVecSize, expanderWeight, accumulatorWeight);

				if (mTimer)
					encoder.setTimer(getTimer());

				encoder.dualEncode2<F, G, Ctx>(
					mA.begin(),
					mC.begin(),
					{}
				);
				break;
			}
			case osuCrypto::MultType::QuasiCyclic:
			{
#ifdef ENABLE_BITPOLYMUL
				if constexpr (
					std::is_same_v<F, block> &&
					std::is_same_v<G, block> &&
					std::is_same_v<Ctx, CoeffCtxGF128>)
				{
					QuasiCyclicCode encoder;
					encoder.init2(mRequestSize, mNoiseVecSize);
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
				encoder.config(oc::roundUpTo(mRequestSize, 8), mNoiseVecSize);
				encoder.dualEncode<F, Ctx>(mA.begin(), mCtx);
				encoder.dualEncode<G, Ctx>(mC.begin(), mCtx);
				break;
			}
			default:
				throw std::runtime_error("Code is not supported. " LOCATION);
				break;
			}

			// resize the buffers down to only contain the real elements.
			mCtx.resize(mA, mRequestSize);
			mCtx.resize(mC, mRequestSize);

			mBaseC = {};
			mBaseA = {};

			// make the protocol as done and that
			// mA,mC are ready to be consumed.
			mState = State::Default;

			} MACORO_CATCH(eptr) {
				co_await chl.close();
				std::rethrow_exception(eptr);
			}
		}


		// internal.
		task<> checkRT(Socket& chl)
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

			// it shoudl hold that 
			// 
			// mBaseA = baseB + mBaseC * mDelta
			//
			// and
			// 
			//  mA = mB + mC * mDelta
			//
			bool verbose = false;
			bool failed = false;
			std::vector<std::size_t> index(mS.size());
			std::iota(index.begin(), index.end(), 0);
			std::sort(index.begin(), index.end(),
				[&](std::size_t i, std::size_t j) { return mS[i] < mS[j]; });

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
					auto point = mS[i];
					if (!mCtx.eq(mBaseC[i], mC[point]))
						throw RTE_LOC;

					if (i && mS[index[i - 1]] >= mS[index[i]])
						throw RTE_LOC;
				}
			}


			auto iIter = index.begin();
			auto leafIdx = mS[*iIter];
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
						leafIdx = mS[*iIter];
					}
				}
			}

			if (failed)
				throw RTE_LOC;

		}

		std::array<u8, 32> ferretMalCheck()
		{

			block xx = mMalCheckSeed;
			block sum0 = ZeroBlock;
			block sum1 = ZeroBlock;


			for (u64 i = 0; i < (u64)mA.size(); ++i)
			{
				block low, high;
				xx.gf128Mul(mA[i], low, high);
				sum0 = sum0 ^ low;
				sum1 = sum1 ^ high;
				//mySum = mySum ^ xx.gf128Mul(mA[i]);

				// xx = mMalCheckSeed^{i+1}
				xx = xx.gf128Mul(mMalCheckSeed);
			}

			// <A,X> = <
			block mySum = sum0.gf128Reduce(sum1);

			std::array<u8, 32> myHash;
			RandomOracle ro(32);
			ro.Update(mySum ^ mBaseA.back());
			ro.Final(myHash);
			return myHash;
		}

		void clear()
		{
			mS = {};
			mA = {};
			mC = {};
			mGen.clear();
		}
	};
}
#endif
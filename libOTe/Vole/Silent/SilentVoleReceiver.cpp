#include "libOTe/Vole/Silent/SilentVoleReceiver.h"

#ifdef ENABLE_SILENT_VOLE
#include "libOTe/Vole/Silent/SilentVoleSender.h"
#include "libOTe/Vole/Noisy/NoisyVoleReceiver.h"
#include <libOTe/Base/BaseOT.h>
#include <libOTe/Tools/LDPC/LdpcSampler.h>

#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/RandomOracle.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/Range.h>
#include <cryptoTools/Common/Aligned.h>

namespace osuCrypto
{


	//u64 getPartitions(u64 scaler, u64 p, u64 secParam);



	// sets the Iknp base OTs that are then used to extend
	void SilentVoleReceiver::setBaseOts(
		span<std::array<block, 2>> baseSendOts)
	{
#ifdef ENABLE_SOFTSPOKEN_OT
		mOtExtRecver.setBaseOts(baseSendOts);
#else
		throw std::runtime_error("soft spoken must be enabled");
#endif
	}

	// return the number of base OTs soft spoken needs
	u64 SilentVoleReceiver::baseOtCount() const {
#ifdef ENABLE_SOFTSPOKEN_OT
		return mOtExtRecver.baseOtCount();
#else
		throw std::runtime_error("soft spoken must be enabled");
#endif
	}

	// returns true if the soft spoken base OTs are currently set.
	bool SilentVoleReceiver::hasBaseOts() const {
#ifdef ENABLE_SOFTSPOKEN_OT
		return mOtExtRecver.hasBaseOts();
#else
		throw std::runtime_error("soft spoken must be enabled");
#endif
	};


	BitVector SilentVoleReceiver::sampleBaseChoiceBits(PRNG& prng) {

		if (isConfigured() == false)
			throw std::runtime_error("configure(...) must be called first");

		auto choice = mGen.sampleChoiceBits(mN2, getPprfFormat(), prng);

		mGapBaseChoice.resize(mGapOts.size());
		mGapBaseChoice.randomize(prng);
		choice.append(mGapBaseChoice);

		return choice;
	}

	std::vector<block> SilentVoleReceiver::sampleBaseVoleVals(PRNG& prng)
	{
		if (isConfigured() == false)
			throw RTE_LOC;
		if (mGapBaseChoice.size() != mGapOts.size())
			throw std::runtime_error("sampleBaseChoiceBits must be called before sampleBaseVoleVals. " LOCATION);

		// sample the values of the noisy coordinate of c
		// and perform a noicy vole to get x+y = mD * c
		auto w = mNumPartitions + mGapOts.size();
		//std::vector<block> y(w);
		mNoiseValues.resize(w);
		prng.get<block>(mNoiseValues);

		mS.resize(mNumPartitions);
		mGen.getPoints(mS, getPprfFormat());

		auto j = mNumPartitions * mSizePer;

		for (u64 i = 0; i < (u64)mGapBaseChoice.size(); ++i)
		{
			if (mGapBaseChoice[i])
			{
				mS.push_back(j + i);
			}
		}

		if (mMalType == SilentSecType::Malicious)
		{

			mMalCheckSeed = prng.get();
			mMalCheckX = ZeroBlock;
			auto yIter = mNoiseValues.begin();

			for (u64 i = 0; i < mNumPartitions; ++i)
			{
				auto s = mS[i];
				auto xs = mMalCheckSeed.gf128Pow(s + 1);
				mMalCheckX = mMalCheckX ^ xs.gf128Mul(*yIter);
				++yIter;
			}

			auto sIter = mS.begin() + mNumPartitions;
			for (u64 i = 0; i < mGapBaseChoice.size(); ++i)
			{
				if (mGapBaseChoice[i])
				{
					auto s = *sIter;
					auto xs = mMalCheckSeed.gf128Pow(s + 1);
					mMalCheckX = mMalCheckX ^ xs.gf128Mul(*yIter);
					++sIter;
				}
				++yIter;
			}


			std::vector<block> y(mNoiseValues.begin(), mNoiseValues.end());
			y.push_back(mMalCheckX);
			return y;
		}

		return std::vector<block>(mNoiseValues.begin(), mNoiseValues.end());
	}

	task<> SilentVoleReceiver::genBaseOts(
		PRNG& prng,
		Socket& chl)
	{
		setTimePoint("SilentVoleReceiver.gen.start");
#ifdef ENABLE_SOFTSPOKEN_OT
		return mOtExtRecver.genBaseOts(prng, chl);
		//mIknpSender.genBaseOts(mIknpRecver, prng, chl);
#else
		throw std::runtime_error("soft spoken must be enabled");
#endif
	}

	void SilentVoleReceiver::configure(
		u64 numOTs,
		SilentBaseType type,
		u64 secParam)
	{
		mState = State::Configured;
		u64 gap = 0;
		mBaseType = type;

		switch (mMultType)
		{
		case osuCrypto::MultType::QuasiCyclic:
		{
			u64 p, s;
			QuasiCyclicConfigure(numOTs, secParam,
				2,
				mMultType,
				mRequestedNumOTs,
				mNumPartitions,
				mSizePer,
				mN2,
				mN,
				p,
				s
			);
#ifdef ENABLE_BITPOLYMUL
			mQuasiCyclicEncoder.init(p, s);
#else
			throw std::runtime_error("ENABLE_BITPOLYMUL not defined.");
#endif
			break;
		}
#ifdef ENABLE_INSECURE_SILVER
		case osuCrypto::MultType::slv5:
		case osuCrypto::MultType::slv11:

			SilverConfigure(numOTs, secParam,
				mMultType,
				mRequestedNumOTs,
				mNumPartitions,
				mSizePer,
				mN2,
				mN,
				gap,
				mEncoder);

			break;
#endif
		case osuCrypto::MultType::ExAcc7:
		case osuCrypto::MultType::ExAcc11:
		case osuCrypto::MultType::ExAcc21:
		case osuCrypto::MultType::ExAcc40:
			EAConfigure(numOTs, secParam, 
				mMultType, 
				mRequestedNumOTs, 
				mNumPartitions, 
				mSizePer, 
				mN2, 
				mN, 
				mEAEncoder);

			break;
		case osuCrypto::MultType::ExConv7x24:
		case osuCrypto::MultType::ExConv21x24:

			ExConvConfigure(numOTs, 128, mMultType, mRequestedNumOTs, mNumPartitions, mSizePer, mN2, mN, mExConvEncoder);
			break;
		default:
			throw RTE_LOC;
			break;
		}

		mGapOts.resize(gap);
		mGen.configure(mSizePer, mNumPartitions);
	}


	task<> SilentVoleReceiver::genSilentBaseOts(
		PRNG& prng,
		Socket& chl)
	{
#if defined ENABLE_MRR_TWIST && defined ENABLE_SSE
using BaseOT = McRosRoyTwist;
#elif defined ENABLE_MR
using BaseOT = MasnyRindal;
#elif defined ENABLE_MRR
using BaseOT = McRosRoy;
#else
using BaseOT = DefaultBaseOT;
#endif

		MC_BEGIN(task<>, this, &prng, &chl,
			choice = BitVector{},
			bb = BitVector{},
			msg = AlignedUnVector<block>{},
			baseVole = std::vector<block>{},
			baseOt = BaseOT{},
			chl2 = Socket{},
			prng2 = std::move(PRNG{}),
			noiseVals = std::vector<block>{},
			noiseDeltaShares = std::vector<block>{},
			nv = NoisyVoleReceiver{}

		);

		setTimePoint("SilentVoleReceiver.genSilent.begin");
		if (isConfigured() == false)
			throw std::runtime_error("configure must be called first");

		choice = sampleBaseChoiceBits(prng);
		msg.resize(choice.size());

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
		noiseVals = sampleBaseVoleVals(prng);
		noiseDeltaShares.resize(noiseVals.size());
		if (mTimer)
			nv.setTimer(*mTimer);

		if (mBaseType == SilentBaseType::BaseExtend)
		{
#ifdef ENABLE_SOFTSPOKEN_OT

			if (mOtExtSender.hasBaseOts() == false)
			{
				msg.resize(msg.size() + mOtExtSender.baseOtCount());
				bb.resize(mOtExtSender.baseOtCount());
				bb.randomize(prng);
				choice.append(bb);

				MC_AWAIT(mOtExtRecver.receive(choice, msg, prng, chl));

				mOtExtSender.setBaseOts(
					span<block>(msg).subspan(
						msg.size() - mOtExtSender.baseOtCount(),
						mOtExtSender.baseOtCount()),
					bb);

				msg.resize(msg.size() - mOtExtSender.baseOtCount());
				MC_AWAIT(nv.receive(noiseVals, noiseDeltaShares, prng, mOtExtSender, chl));
			}
			else
			{
				chl2 = chl.fork();
				prng2.SetSeed(prng.get());
	

				MC_AWAIT(
					macoro::when_all_ready(
						nv.receive(noiseVals, noiseDeltaShares, prng2, mOtExtSender, chl2),
						mOtExtRecver.receive(choice, msg, prng, chl)
					));
			}
#else
			throw std::runtime_error("soft spoken must be enabled");
#endif
		}
		else
		{
			chl2 = chl.fork();
			prng2.SetSeed(prng.get());
			
			MC_AWAIT(
				macoro::when_all_ready(
					nv.receive(noiseVals, noiseDeltaShares, prng2, baseOt, chl2),
					baseOt.receive(choice, msg, prng, chl)
				));
		}




		setSilentBaseOts(msg, noiseDeltaShares);

		setTimePoint("SilentVoleReceiver.genSilent.done");

		MC_END();
	};

	void SilentVoleReceiver::setSilentBaseOts(
		span<block> recvBaseOts,
		span<block> noiseDeltaShare)
	{
		if (isConfigured() == false)
			throw std::runtime_error("configure(...) must be called first.");

		if (static_cast<u64>(recvBaseOts.size()) != silentBaseOtCount())
			throw std::runtime_error("wrong number of silent base OTs");

		auto genOts = recvBaseOts.subspan(0, mGen.baseOtCount());
		auto gapOts = recvBaseOts.subspan(mGen.baseOtCount(), mGapOts.size());

		mGen.setBase(genOts);
		std::copy(gapOts.begin(), gapOts.end(), mGapOts.begin());

		if (mMalType == SilentSecType::Malicious)
		{
			mDeltaShare = noiseDeltaShare.back();
			noiseDeltaShare = noiseDeltaShare.subspan(0, noiseDeltaShare.size() - 1);
		}

		mNoiseDeltaShare = AlignedVector<block>(noiseDeltaShare.begin(), noiseDeltaShare.end());

		mState = State::HasBase;
	}



	//sigma = 0   Receiver
	//
	//    u_i is the choice bit
	//    v_i = w_i + u_i * x
	//
	//    ------------------------ -
	//    u' =   0000001000000000001000000000100000...00000,   u_i = 1 iff i \in S 
	//
	//    v' = r + (x . u') = DPF(k0)
	//       = r + (000000x00000000000x000000000x00000...00000)
	//
	//    u = u' * H             bit-vector * H. Mapping n'->n bits
	//    v = v' * H		   block-vector * H. Mapping n'->n block
	//
	//sigma = 1   Sender
	//
	//    x   is the delta
	//    w_i is the zero message
	//
	//    m_i0 = w_i
	//    m_i1 = w_i + x
	//
	//    ------------------------
	//    x
	//    r = DPF(k1)
	//
	//    w = r * H
	task<> SilentVoleReceiver::silentReceive(
		span<block> c,
		span<block> b,
		PRNG& prng,
		Socket& chl)
	{
		MC_BEGIN(task<>, this, c, b, &prng, &chl);
		if (c.size() != b.size())
			throw RTE_LOC;

		MC_AWAIT(silentReceiveInplace(c.size(), prng, chl));

		std::memcpy(c.data(), mC.data(), c.size() * sizeof(block));
		std::memcpy(b.data(), mA.data(), b.size() * sizeof(block));
		clear();
		MC_END();
	}

	task<> SilentVoleReceiver::silentReceiveInplace(
		u64 n,
		PRNG& prng,
		Socket& chl)
	{
		MC_BEGIN(task<>, this, n, &prng, &chl,
			gapVals = std::vector<block>{},
			myHash = std::array<u8, 32>{},
			theirHash = std::array<u8, 32>{}

		);
		gTimer.setTimePoint("SilentVoleReceiver.ot.enter");

		if (isConfigured() == false)
		{
			// first generate 128 normal base OTs
			configure(n, SilentBaseType::BaseExtend);
		}

		if (mRequestedNumOTs != n)
			throw std::invalid_argument("n does not match the requested number of OTs via configure(...). " LOCATION);

		if (hasSilentBaseOts() == false)
		{
			MC_AWAIT(genSilentBaseOts(prng, chl));
		}

		// allocate mA
		mA.resize(0);
		mA.resize(mN2);

		setTimePoint("SilentVoleReceiver.alloc");

		// allocate the space for mC
		mC.resize(0);
		mC.resize(mN2, AllocType::Zeroed);
		setTimePoint("SilentVoleReceiver.alloc.zero");

		// derandomize the random OTs for the gap 
		// to have the desired correlation.
		gapVals.resize(mGapOts.size());

		if(gapVals.size())
			MC_AWAIT(chl.recv(gapVals));

		for (auto g : rng(mGapOts.size()))
		{
			auto aa = mA.subspan(mNumPartitions * mSizePer);
			auto cc = mC.subspan(mNumPartitions * mSizePer);

			auto noise = mNoiseValues.subspan(mNumPartitions);
			auto noiseShares = mNoiseDeltaShare.subspan(mNumPartitions);

			if (mGapBaseChoice[g])
			{
				cc[g] = noise[g];
				aa[g] = AES(mGapOts[g]).ecbEncBlock(ZeroBlock) ^
					gapVals[g] ^
					noiseShares[g];
			}
			else
				aa[g] = mGapOts[g];
		}

		setTimePoint("SilentVoleReceiver.recvGap");



		if (mTimer)
			mGen.setTimer(*mTimer);
		// expand the seeds into mA
		MC_AWAIT(mGen.expand(chl, prng, mA.subspan(0, mNumPartitions * mSizePer), PprfOutputFormat::Interleaved, true, mNumThreads));

		setTimePoint("SilentVoleReceiver.expand.pprf_transpose");

		// populate the noisy coordinates of mC and 
		// update mA to be a secret share of mC * delta
		for (u64 i = 0; i < mNumPartitions; ++i)
		{
			auto pnt = mS[i];
			mC[pnt] = mNoiseValues[i];
			mA[pnt] = mA[pnt] ^ mNoiseDeltaShare[i];
		}


		if (mDebug)
		{
			MC_AWAIT(checkRT(chl));
			setTimePoint("SilentVoleReceiver.expand.checkRT");
		}


		if (mMalType == SilentSecType::Malicious)
		{
			MC_AWAIT(chl.send(std::move(mMalCheckSeed)));

			myHash = ferretMalCheck(mDeltaShare, mNoiseValues);

			MC_AWAIT(chl.recv(theirHash));

			if (theirHash != myHash)
				throw RTE_LOC;
		}

		switch (mMultType)
		{
		case osuCrypto::MultType::QuasiCyclic:

#ifdef ENABLE_BITPOLYMUL
			if (mTimer)
				mQuasiCyclicEncoder.setTimer(getTimer());

			// compress both mA and mC in place.
			mQuasiCyclicEncoder.dualEncode(mA.subspan(0, mQuasiCyclicEncoder.size()));
			mQuasiCyclicEncoder.dualEncode(mC.subspan(0, mQuasiCyclicEncoder.size()));
#else
			throw std::runtime_error("ENABLE_BITPOLYMUL not defined.");
#endif

			setTimePoint("SilentVoleReceiver.expand.mQuasiCyclicEncoder.a");
			break;
#ifdef ENABLE_INSECURE_SILVER
		case osuCrypto::MultType::slv5:
		case osuCrypto::MultType::slv11:
			if (mTimer)
				mEncoder.setTimer(getTimer());

			// compress both mA and mC in place.
			mEncoder.dualEncode2<block, block>(mA, mC);
			setTimePoint("SilentVoleReceiver.expand.cirTransEncode.a");
			break;
#endif
		case osuCrypto::MultType::ExAcc7:
		case osuCrypto::MultType::ExAcc11:
		case osuCrypto::MultType::ExAcc21:
		case osuCrypto::MultType::ExAcc40:
		{
			if (mTimer)
				mEAEncoder.setTimer(getTimer());

			AlignedUnVector<block>
				A2(mEAEncoder.mMessageSize),
				C2(mEAEncoder.mMessageSize);

			// compress both mA and mC in place.
			mEAEncoder.dualEncode2<block, block>(
				mA.subspan(0, mEAEncoder.mCodeSize), A2,
				mC.subspan(0, mEAEncoder.mCodeSize), C2);

			std::swap(mA, A2);
			std::swap(mC, C2);

			setTimePoint("SilentVoleReceiver.expand.cirTransEncode.a");
			break;
		}
		case osuCrypto::MultType::ExConv7x24:
		case osuCrypto::MultType::ExConv21x24:
			if (mTimer)
				mExConvEncoder.setTimer(getTimer());
			mExConvEncoder.dualEncode2<block, block>(
				mA.subspan(0, mExConvEncoder.mCodeSize),
				mC.subspan(0, mExConvEncoder.mCodeSize)
				);
			break;
		default:
			throw RTE_LOC;
			break;
		}

		// resize the buffers down to only contain the real elements.
		mA.resize(mRequestedNumOTs);
		mC.resize(mRequestedNumOTs);

		mNoiseValues = {};
		mNoiseDeltaShare = {};

		// make the protocol as done and that
		// mA,mC are ready to be consumed.
		mState = State::Default;

		MC_END();
	}


	std::array<u8, 32> SilentVoleReceiver::ferretMalCheck(
		block deltaShare,
		span<block> yy)
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
		block mySum = sum0.gf128Reduce(sum1);

		std::array<u8, 32> myHash;
		RandomOracle ro(32);
		ro.Update(mySum ^ deltaShare);
		ro.Final(myHash);
		return myHash;
	}


	u64 SilentVoleReceiver::silentBaseOtCount() const
	{
		if (isConfigured() == false)
			throw std::runtime_error("configure must be called first");

		return mGen.baseOtCount() + mGapOts.size();

	}

	task<> SilentVoleReceiver::checkRT(Socket& chl) const
	{
		MC_BEGIN(task<>, this, &chl,
			B = AlignedVector<block>(mA.size()),
			sparseNoiseDelta = std::vector<block>(mA.size()),
			noiseDeltaShare2 = std::vector<block>(),
			delta = block{}
		);
		//std::vector<block> mB(mA.size());
		MC_AWAIT(chl.recv(delta));
		MC_AWAIT(chl.recv(B));
		MC_AWAIT(chl.recvResize(noiseDeltaShare2));

		//check that at locations  mS[0],...,mS[..]
		// that we hold a sharing mA, mB of
		//
		//  delta * mC = delta * (00000 noiseDeltaShare2[0] 0000 .... 0000 noiseDeltaShare2[m] 0000)
		//
		// where noiseDeltaShare2[i] is at position mS[i] of mC
		// 
		// That is, I hold mA, mC s.t.
		// 
		//  delta * mC = mA + mB
		//

		if (noiseDeltaShare2.size() != mNoiseDeltaShare.size())
			throw RTE_LOC;

		for (auto i : rng(mNoiseDeltaShare.size()))
		{
			if ((mNoiseDeltaShare[i] ^ noiseDeltaShare2[i]) != mNoiseValues[i].gf128Mul(delta))
				throw RTE_LOC;
		}

		{

			for (auto i : rng(mNumPartitions* mSizePer))
			{
				auto iter = std::find(mS.begin(), mS.end(), i);
				if (iter != mS.end())
				{
					auto d = iter - mS.begin();

					if (mC[i] != mNoiseValues[d])
						throw RTE_LOC;

					if (mNoiseValues[d].gf128Mul(delta) != (mA[i] ^ B[i]))
					{
						std::cout << "bad vole base correlation, mA[i] + mB[i] != mC[i] * delta" << std::endl;
						std::cout << "i     " << i << std::endl;
						std::cout << "mA[i] " << mA[i] << std::endl;
						std::cout << "mB[i] " << B[i] << std::endl;
						std::cout << "mC[i] " << mC[i] << std::endl;
						std::cout << "delta " << delta << std::endl;
						std::cout << "mA[i] + mB[i] " << (mA[i] ^ B[i]) << std::endl;
						std::cout << "mC[i] * delta " << (mC[i].gf128Mul(delta)) << std::endl;

						throw RTE_LOC;
					}
				}
				else
				{
					if (mA[i] != B[i])
					{
						std::cout << mA[i] << " " << B[i] << std::endl;
						throw RTE_LOC;
					}

					if (mC[i] != oc::ZeroBlock)
						throw RTE_LOC;
				}
			}

			u64 d = mNumPartitions;
			for (auto j : rng(mGapBaseChoice.size()))
			{
				auto idx = j + mNumPartitions * mSizePer;
				auto aa = mA.subspan(mNumPartitions * mSizePer);
				auto bb = B.subspan(mNumPartitions * mSizePer);
				auto cc = mC.subspan(mNumPartitions * mSizePer);
				auto noise = mNoiseValues.subspan(mNumPartitions);
				//auto noiseShare = mNoiseValues.subspan(mNumPartitions);
				if (mGapBaseChoice[j])
				{
					if (mS[d++] != idx)
						throw RTE_LOC;

					if (cc[j] != noise[j])
					{
						std::cout << "sparse noise vector mC is not the expected value" << std::endl;
						std::cout << "i j      " << idx << " " << j << std::endl;
						std::cout << "mC[i]    " << cc[j] << std::endl;
						std::cout << "noise[j] " << noise[j] << std::endl;
						throw RTE_LOC;
					}

					if (noise[j].gf128Mul(delta) != (aa[j] ^ bb[j]))
					{

						std::cout << "bad vole base GAP correlation, mA[i] + mB[i] != mC[i] * delta" << std::endl;
						std::cout << "i     " << idx << std::endl;
						std::cout << "mA[i] " << aa[j] << std::endl;
						std::cout << "mB[i] " << bb[j] << std::endl;
						std::cout << "mC[i] " << cc[j] << std::endl;
						std::cout << "delta " << delta << std::endl;
						std::cout << "mA[i] + mB[i] " << (aa[j] ^ bb[j]) << std::endl;
						std::cout << "mC[i] * delta " << (cc[j].gf128Mul(delta)) << std::endl;
						std::cout << "noise * delta " << (noise[j].gf128Mul(delta)) << std::endl;
						throw RTE_LOC;
					}

				}
				else
				{
					if (aa[j] != bb[j])
						throw RTE_LOC;

					if (cc[j] != oc::ZeroBlock)
						throw RTE_LOC;
				}
			}

			if (d != mS.size())
				throw RTE_LOC;
		}


		//{

		//	auto cDelta = B;
		//	for (u64 i = 0; i < cDelta.size(); ++i)
		//		cDelta[i] = cDelta[i] ^ mA[i];

		//	std::vector<block> exp(mN2);
		//	for (u64 i = 0; i < mNumPartitions; ++i)
		//	{
		//		auto j = mS[i];
		//		exp[j] = noiseDeltaShare2[i];
		//	}

		//	auto iter = mS.begin() + mNumPartitions;
		//	for (u64 i = 0, j = mNumPartitions * mSizePer; i < mGapOts.size(); ++i, ++j)
		//	{
		//		if (mGapBaseChoice[i])
		//		{
		//			if (*iter != j)
		//				throw RTE_LOC;
		//			++iter;

		//			exp[j] = noiseDeltaShare2[mNumPartitions + i];
		//		}
		//	}

		//	if (iter != mS.end())
		//		throw RTE_LOC;

		//	bool failed = false;
		//	for (u64 i = 0; i < mN2; ++i)
		//	{
		//		if (neq(cDelta[i], exp[i]))
		//		{
		//			std::cout << i << " / " << mN2 <<
		//				" cd = " << cDelta[i] <<
		//				" exp= " << exp[i] << std::endl;
		//			failed = true;
		//		}
		//	}

		//	if (failed)
		//		throw RTE_LOC;

		//	std::cout << "debug check ok" << std::endl;
		//}

		MC_END();
	}


	void SilentVoleReceiver::clear()
	{
		mS = {};
		mA = {};
		mC = {};
		mGen.clear();
		mGapBaseChoice = {};
	}


}
#endif
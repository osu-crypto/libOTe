#include "libOTe/TwoChooseOne/Silent/SilentOtExtReceiver.h"
#ifdef ENABLE_SILENTOT

#include "libOTe/TwoChooseOne/Silent/SilentOtExtSender.h"
#include <libOTe/Tools/bitpolymul.h>
#include <libOTe/Vole/Noisy/NoisyVoleSender.h>
#include <libOTe/Base/BaseOT.h>

#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/RandomOracle.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/Range.h>
#include <cryptoTools/Common/ThreadBarrier.h>
#include "libOTe/Tools/QuasiCyclicCode.h"
#include "libOTe/Tools/CoeffCtx.h"
#include "libOTe/Tools/TungstenCode/TungstenCode.h"

namespace osuCrypto
{

	// sets the KOS base OTs that are then used to extend
	void SilentOtExtReceiver::setBaseOts(
		span<std::array<block, 2>> baseSendOts) {
#ifdef ENABLE_SOFTSPOKEN_OT
		if (!mOtExtRecver)
			mOtExtRecver.emplace();
		mOtExtRecver->setBaseOts(baseSendOts);
#else
		throw std::runtime_error("softSpoken ot must be enabled. " LOCATION);
#endif
	}


	// return the number of base OTs soft spoken ot needs
	u64 SilentOtExtReceiver::baseOtCount() const {
#ifdef ENABLE_SOFTSPOKEN_OT
		if (!mOtExtRecver)
		{
			const_cast<macoro::optional<SoftSpokenMalOtReceiver>*>(&mOtExtRecver)
				->emplace();
		}
		return  mOtExtRecver->baseOtCount();
#else
		throw std::runtime_error("softSpoken ot must be enabled. " LOCATION);
#endif
	}

	// returns true if the soft spoken ot base OTs are currently set.
	bool SilentOtExtReceiver::hasBaseOts() const {
#ifdef ENABLE_SOFTSPOKEN_OT
		if (!mOtExtRecver)
			return false;
		return mOtExtRecver->hasBaseOts();
#else
		throw std::runtime_error("softSpoken ot must be enabled. " LOCATION);
#endif
	};

	void SilentOtExtReceiver::setSilentBaseOts(span<const block> recvBaseOts)
	{
		if (isConfigured() == false)
			throw std::runtime_error("configure(...) must be called first.");

		if (static_cast<u64>(recvBaseOts.size()) != silentBaseOtCount())
			throw std::runtime_error("wrong number of silent base OTs");

		auto genOts = recvBaseOts.subspan(0, mGen.baseOtCount());
		auto malOts = recvBaseOts.subspan(genOts.size());

		mGen.setBase(genOts);
		std::copy(malOts.begin(), malOts.end(), mMalCheckOts.begin());
	}

	task<> SilentOtExtReceiver::genBaseOts(
		PRNG& prng,
		Socket& chl)
	{
		setTimePoint("recver.gen.start");
#ifdef ENABLE_SOFTSPOKEN_OT
		if (!mOtExtRecver)
			mOtExtRecver.emplace();
		co_await mOtExtRecver->genBaseOts(prng, chl);
#else
		throw std::runtime_error("softSpoken ot must be enabled. " LOCATION);
		co_return;
#endif
	}

	// Returns an independent copy of this extender.
	std::unique_ptr<OtExtReceiver> SilentOtExtReceiver::split() {

#ifdef ENABLE_SOFTSPOKEN_OT
		auto ptr = new SilentOtExtReceiver;
		auto ret = std::unique_ptr<OtExtReceiver>(ptr);

		if (!mOtExtRecver)
			throw RTE_LOC;
		ptr->mOtExtRecver = mOtExtRecver->splitBase();
		return ret;
#else
		throw std::runtime_error("softSpoken ot must be enabled. " LOCATION);
#endif
	};


	BitVector SilentOtExtReceiver::sampleBaseChoiceBits(PRNG& prng) {
		if (isConfigured() == false)
			throw std::runtime_error("configure(...) must be called first");

		auto choice = mGen.sampleChoiceBits(prng);

		mS.resize(mNumPartitions);
		mGen.getPoints(mS, getPprfFormat());
		auto main = mNumPartitions * mSizePer;
		for (u64 i = 0; i < mGapBaseChoice.size(); ++i)
		{
			if (mGapBaseChoice[i])
			{
				mS.push_back(main + i);
			}
		}

		if (mMalType == SilentSecType::Malicious)
		{
			mMalCheckSeed = prng.get();
			mMalCheckX = ZeroBlock;

			for (auto s : mS)
			{
				auto xs = mMalCheckSeed.gf128Pow(s + 1);
				mMalCheckX = mMalCheckX ^ xs;
			}

			mMalCheckChoice.resize(0);
			mMalCheckChoice.append((u8*)&mMalCheckX, 128);

			mMalCheckOts.resize(128);
			choice.append(mMalCheckChoice);
		}

		return choice;
	}


	task<> SilentOtExtReceiver::genSilentBaseOts(
		PRNG& prng,
		Socket& chl,
		bool useOtExtension)
	{
		MACORO_TRY{
		auto choice = sampleBaseChoiceBits(prng);
		auto msg = AlignedUnVector<block>{};

		if (isConfigured() == false)
			throw std::runtime_error("configure must be called first");

		msg.resize(choice.size());

		// If we have soft spoken ot base OTs, use them
		// to extend to get the silent base OTs.

#if defined(ENABLE_SOFTSPOKEN_OT) && defined(LIBOTE_HAS_BASE_OT)

#ifdef ENABLE_SOFTSPOKEN_OT
		if (useOtExtension)
		{
			//mKosRecver.mFiatShamir = true;
			if (!mOtExtRecver)
				mOtExtRecver.emplace();
			co_await(mOtExtRecver->receive(choice, msg, prng, chl));
		}
		else
#endif
		{
			auto base = DefaultBaseOT{};

			// otherwise just generate the silent 
			// base OTs directly.
			co_await(base.receive(choice, msg, prng, chl));
			setTimePoint("recver.gen.baseOT");
		}

#else
		throw std::runtime_error("soft spoken ot or base OTs must be enabled");
#endif
		setSilentBaseOts(msg);
		setTimePoint("recver.gen.done");

		} MACORO_CATCH(eptr) {
			if (!chl.closed()) co_await chl.close();
			std::rethrow_exception(eptr);
		}
	}

	u64 SilentOtExtReceiver::silentBaseOtCount() const
	{
		if (isConfigured() == false)
			throw std::runtime_error("configure must be called first");
		return
			mGen.baseOtCount() +
			(mMalType == SilentSecType::Malicious) * 128;
	}


	void SilentOtExtReceiver::configure(
		u64 numOTs,
		u64 scaler,
		u64 numThreads,
		SilentSecType malType)
	{
		mMalType = malType;
		mNumThreads = numThreads;
		u64 secParam = 128;
		mRequestNumOts = numOTs;

		syndromeDecodingConfigure(mNumPartitions, mSizePer, mNoiseVecSize, secParam, mRequestNumOts, mMultType);

		mS.resize(mNumPartitions);
		mGen.configure(mSizePer, mS.size());
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


	task<> SilentOtExtReceiver::checkRT(Socket& chl, MatrixView<block> rT1)
	{
		auto rT2 = Matrix<block>(rT1.rows(), rT1.cols(), AllocType::Uninitialized);
		auto delta = block{};
		auto i = u64{};
		auto R = Matrix<block>{};
		auto exp = Matrix<block>{};
		auto failed = false;

		co_await chl.recv(rT2);
		co_await chl.recv(delta);

		for (i = 0; i < rT1.size(); ++i)
			rT2(i) = rT2(i) ^ rT1(i);

		if (rT1.cols() != 1)
			throw RTE_LOC;
		R = rT2;

		exp.resize(R.rows(), R.cols(), AllocType::Zeroed);
		for (i = 0; i < mS.size(); ++i)
		{
			exp(mS[i]) = delta;
		}

		for (i = 0; i < R.rows(); ++i)
		{
			if (neq(R(i), exp(i)))
			{
				std::cout << i << " / " << R.rows() << " R= " << R(i) << " exp= " << exp(i) << std::endl;
				failed = true;
			}
		}

		if (failed)
			throw RTE_LOC;

		std::cout << "debug check ok" << std::endl;

		setTimePoint("recver.expand.checkRT");
	}

	task<> SilentOtExtReceiver::receive(
		const BitVector& choices,
		span<block> messages,
		PRNG& prng,
		Socket& chl)
	{
		MACORO_TRY{
		auto randChoice = BitVector(messages.size());
		co_await silentReceive(randChoice, messages, prng, chl, OTType::Random);
		randChoice ^= choices;
		co_await chl.send(std::move(randChoice));

	} MACORO_CATCH(eptr) {
		if (!chl.closed()) co_await chl.close();
		std::rethrow_exception(eptr);
	}
	}

	task<> SilentOtExtReceiver::silentReceive(
		BitVector& choices,
		span<block> messages,
		PRNG& prng,
		Socket& chl,
		OTType type)
	{
		MACORO_TRY{
		auto packing = (type == OTType::Random) ?
			ChoiceBitPacking::True :
			ChoiceBitPacking::False;

		if (choices.size() != (u64)messages.size())
			throw RTE_LOC;

		co_await silentReceiveInplace(messages.size(), prng, chl, packing);

		if (type == OTType::Random)
		{
			hash(choices, messages, packing);
		}
		else
		{
			std::memcpy(messages.data(), mA.data(), messages.size() * sizeof(block));
			setTimePoint("recver.expand.ldpc.copy");

			auto cIter = choices.begin();
			for (u64 i = 0; i < choices.size(); ++i)
			{
				*cIter = mC[i];
				++cIter;
			}
			setTimePoint("recver.expand.ldpc.copyBits");
		}

		clear();

		} MACORO_CATCH(eptr) {
			if (!chl.closed()) co_await chl.close();
			std::rethrow_exception(eptr);
		}
	}

	task<> SilentOtExtReceiver::silentReceiveInplace(
		u64 n,
		PRNG& prng,
		Socket& chl,
		ChoiceBitPacking type)
	{
		MACORO_TRY{
		auto gapVals = std::vector<block>{};
		auto rT = MatrixView<block>{};

		setTimePoint("recver.expand.enter");

		if (isConfigured() == false)
		{
			// first generate 128 normal base OTs
			configure(n, 2, mNumThreads, mMalType);
		}

		if (n != mRequestNumOts)
			throw std::invalid_argument("messages.size() > n");

		if (mGen.hasBaseOts() == false)
		{
			// recvs data
			co_await(genSilentBaseOts(prng, chl));
		}

		setTimePoint("recver.expand.start");
		mA.resize(mNoiseVecSize);
		mC.resize(0);

		co_await(mGen.expand(chl, mA, PprfOutputFormat::Interleaved, true, mNumThreads));
		setTimePoint("recver.expand.pprf");

		if (mMalType == SilentSecType::Malicious)
		{
			co_await(ferretMalCheck(chl, prng));
			setTimePoint("recver.expand.malCheck");
		}
		if (mDebug)
		{
			rT = MatrixView<block>(mA.data(), mNoiseVecSize, 1);
			co_await(checkRT(chl, rT));
		}

		compress(type);
		setTimePoint("recver.expand.dualEncode");

		mA.resize(mRequestNumOts);

		if (mC.size())
			mC.resize(mRequestNumOts);

		} MACORO_CATCH(eptr) {
			if (!chl.closed()) co_await chl.close();
			std::rethrow_exception(eptr);
		}
	}

	task<> SilentOtExtReceiver::ferretMalCheck(Socket& chl, PRNG& prng)
	{
		auto xx = block{};
		auto sum0 = block{};
		auto sum1 = block{};
		auto mySum = block{};
		auto b = AlignedUnVector<block>(1);
		auto i = u64{};
		auto sender = NoisyVoleSender<block, block, CoeffCtxGF128>{};
		auto theirHash = std::array<u8, 32>{};
		auto myHash = std::array<u8, 32>{};
		auto ro = RandomOracle(32);

		co_await chl.send(std::move(mMalCheckSeed));

		xx = mMalCheckSeed;
		sum0 = ZeroBlock;
		sum1 = ZeroBlock;

		for (i = 0; i < (u64)mA.size(); ++i)
		{
			block low, high;
			xx.gf128Mul(mA[i], low, high);
			sum0 = sum0 ^ low;
			sum1 = sum1 ^ high;
			xx = xx.gf128Mul(mMalCheckSeed);
		}
		mySum = sum0.gf128Reduce(sum1);

		co_await(sender.send(mMalCheckX, b, prng, mMalCheckOts, chl, {}));
		ro.Update(mySum ^ b[0]);
		ro.Final(myHash);

		co_await(chl.recv(theirHash));

		if (theirHash != myHash)
			throw RTE_LOC;
	}

	void SilentOtExtReceiver::hash(
		BitVector& choices,
		span<block> messages,
		ChoiceBitPacking type)
	{
		if (choices.size() != mRequestNumOts)
			throw RTE_LOC;
		if ((u64)messages.size() != mRequestNumOts)
			throw RTE_LOC;

		auto cIter = choices.begin();

		auto n8 = mRequestNumOts / 8 * 8;
		auto m = &messages[0];
		auto r = &mA[0];

		if (type == ChoiceBitPacking::True)
		{

			block mask = OneBlock ^ AllOneBlock;

			for (u64 i = 0; i < n8; i += 8)
			{
				// extract the choice bit from the LSB of r
				u32 b0 = r[0].testc(OneBlock);
				u32 b1 = r[1].testc(OneBlock);
				u32 b2 = r[2].testc(OneBlock);
				u32 b3 = r[3].testc(OneBlock);
				u32 b4 = r[4].testc(OneBlock);
				u32 b5 = r[5].testc(OneBlock);
				u32 b6 = r[6].testc(OneBlock);
				u32 b7 = r[7].testc(OneBlock);

				// pack the choice bits.
				choices.data()[i / 8] =
					b0 ^
					(b1 << 1) ^
					(b2 << 2) ^
					(b3 << 3) ^
					(b4 << 4) ^
					(b5 << 5) ^
					(b6 << 6) ^
					(b7 << 7);

				// mask of the choice bit which is stored in the LSB
				m[0] = r[0] & mask;
				m[1] = r[1] & mask;
				m[2] = r[2] & mask;
				m[3] = r[3] & mask;
				m[4] = r[4] & mask;
				m[5] = r[5] & mask;
				m[6] = r[6] & mask;
				m[7] = r[7] & mask;

				mAesFixedKey.hashBlocks<8>(m, m);

				m += 8;
				r += 8;
			}

			cIter = cIter + n8;
			for (u64 i = n8; i < (u64)messages.size(); ++i)
			{
				auto m = &messages[i];
				auto r = &mA[i];
				m[0] = r[0] & mask;

				m[0] = mAesFixedKey.hashBlock(m[0]);

				*cIter = r[0].testc(OneBlock);
				++cIter;
			}
		}
		else
		{
			// not implemented.
			throw RTE_LOC;
		}
		setTimePoint("recver.expand.CopyHash");

	}

	void SilentOtExtReceiver::compress(ChoiceBitPacking packing)// )
	{

		if (packing == ChoiceBitPacking::True)
		{
			// zero out the lsb of mA. We will store mC there.
			block mask = OneBlock ^ AllOneBlock;
			auto m8 = mNoiseVecSize / 8 * 8;
			auto r = mA.data();
			for (u64 i = 0; i < m8; i += 8)
			{
				r[0] = r[0] & mask;
				r[1] = r[1] & mask;
				r[2] = r[2] & mask;
				r[3] = r[3] & mask;
				r[4] = r[4] & mask;
				r[5] = r[5] & mask;
				r[6] = r[6] & mask;
				r[7] = r[7] & mask;
				r += 8;
			}
			for (u64 i = m8; i < mNoiseVecSize; ++i)
			{
				mA[i] = mA[i] & mask;
			}

			// set the lsb of mA to be mC.
			for (auto p : mS)
				mA[p] = mA[p] | OneBlock;

			setTimePoint("recver.expand.bitPacking");

			switch (mMultType)
			{
			case osuCrypto::MultType::QuasiCyclic:
			{
#ifdef ENABLE_BITPOLYMUL
				QuasiCyclicCode code;
				u64 scaler;
				double _;
				QuasiCyclicConfigure(scaler, _);
				code.init2(mRequestNumOts, mNoiseVecSize);
				code.dualEncode(mA);
#else
				throw std::runtime_error("ENABLE_BITPOLYMUL not defined.");
#endif
			}
			break;
			case osuCrypto::MultType::ExAcc7:
			case osuCrypto::MultType::ExAcc11:
			case osuCrypto::MultType::ExAcc21:
			case osuCrypto::MultType::ExAcc40:
			{
				EACode mEAEncoder;
				u64 expanderWeight = 0, _1;
				double _2;
				EAConfigure(mMultType, _1, expanderWeight, _2);
				mEAEncoder.config(mRequestNumOts, mNoiseVecSize, expanderWeight);
				AlignedUnVector<block> A2(mEAEncoder.mMessageSize);
				mEAEncoder.dualEncode<block, CoeffCtxGF2>(mA, A2, {});
				std::swap(mA, A2);
				break;
			}
			case osuCrypto::MultType::ExConv7x24:
			case osuCrypto::MultType::ExConv21x24:
			{

				u64 expanderWeight = 0, accWeight = 0, _1;
				double _2;
				ExConvConfigure(mMultType, _1, expanderWeight, accWeight, _2);

				ExConvCode exConvEncoder;
				exConvEncoder.config(mRequestNumOts, mNoiseVecSize, expanderWeight, accWeight);
				exConvEncoder.dualEncode<block, CoeffCtxGF2>(mA.begin(), {});
				break;
			}
			case osuCrypto::MultType::Tungsten:
			{

				experimental::TungstenCode encoder;
				encoder.config(oc::roundUpTo(mRequestNumOts, 8), mNoiseVecSize);
				encoder.dualEncode<block, CoeffCtxGF2>(mA.begin(), {}, mEncodeTemp);
				break;
			}
			default:
				throw RTE_LOC;
				break;
			}

			setTimePoint("recver.expand.dualEncode");

		}
		else
		{
			mC.resize(mNoiseVecSize);
			std::memset(mC.data(), 0, mNoiseVecSize);
			auto cc = mC.data();
			for (auto p : mS)
				cc[p] = 1;


			switch (mMultType)
			{
			case osuCrypto::MultType::QuasiCyclic:
			{
#ifdef ENABLE_BITPOLYMUL
				QuasiCyclicCode code;
				u64 scaler;
				double _;
				QuasiCyclicConfigure(scaler, _);
				code.init2(mRequestNumOts, mNoiseVecSize);

				code.dualEncode(mA);
				code.dualEncode(mC);
#else
				throw std::runtime_error("ENABLE_BITPOLYMUL not defined.");
#endif
			}
			break;
			case osuCrypto::MultType::ExAcc7:
			case osuCrypto::MultType::ExAcc11:
			case osuCrypto::MultType::ExAcc21:
			case osuCrypto::MultType::ExAcc40:
			{
				EACode mEAEncoder;
				u64 expanderWeight = 0, _1;
				double _2;
				EAConfigure(mMultType, _1, expanderWeight, _2);
				mEAEncoder.config(mRequestNumOts, mNoiseVecSize, expanderWeight);

				AlignedUnVector<block> A2(mEAEncoder.mMessageSize);
				AlignedUnVector<u8> C2(mEAEncoder.mMessageSize);
				mEAEncoder.dualEncode2<block, u8, CoeffCtxGF2>(
					mA, A2,
					mC, C2,
					{});

				std::swap(mA, A2);
				std::swap(mC, C2);

				break;
			}
			case osuCrypto::MultType::ExConv7x24:
			case osuCrypto::MultType::ExConv21x24:
			{
				u64 expanderWeight = 0, accWeight = 0, _1;
				double _2;
				ExConvConfigure(mMultType, _1, expanderWeight, accWeight, _2);

				ExConvCode exConvEncoder;
				exConvEncoder.config(mRequestNumOts, mNoiseVecSize, expanderWeight, accWeight);

				exConvEncoder.dualEncode2<block, u8, CoeffCtxGF2>(
					mA.begin(),
					mC.begin(),
					{});

				break;
			}
			case osuCrypto::MultType::Tungsten:
			{
				experimental::TungstenCode encoder;
				encoder.config(roundUpTo(mRequestNumOts, 8), mNoiseVecSize);
				encoder.dualEncode<block, CoeffCtxGF2>(mA.begin(), {}, mEncodeTemp);
				encoder.dualEncode<u8, CoeffCtxGF2>(mC.begin(), {});
				break;
			}
			default:
				throw RTE_LOC;
				break;
			}

			setTimePoint("recver.expand.dualEncode2");
		}
	}

	void SilentOtExtReceiver::clear()
	{
		mNoiseVecSize = 0;
		mRequestNumOts = 0;
		mSizePer = 0;

		mC = {};
		mA = {};

		mGen.clear();

		mS = {};
	}


}
#endif
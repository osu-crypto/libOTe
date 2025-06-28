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
#include "libOTe/Tools/BlkAccCode/BlkAccCode.h"
namespace osuCrypto
{

	//--------------------------------------------------------------
	// Standard OT Extension Interface Implementation
	//--------------------------------------------------------------

	// Sets the IKNP/SoftSpoken base OTs used for OT extension
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

	// Returns the number of base OTs required for the IKNP/SoftSpoken protocol
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

	// Checks if the required IKNP/SoftSpoken base OTs are set
	bool SilentOtExtReceiver::hasBaseOts() const {
#ifdef ENABLE_SOFTSPOKEN_OT
		if (!mOtExtRecver)
			return false;
		return mOtExtRecver->hasBaseOts();
#else
		throw std::runtime_error("softSpoken ot must be enabled. " LOCATION);
#endif
	};

	// Sets externally generated base OTs and VOLEs
	void SilentOtExtReceiver::setBaseCors(
		span<const block> recvBaseOts,
		const BitVector& choices,
		span<const block> baseA,
		const BitVector& baseC)
	{
		if (isConfigured() == false)
			throw std::runtime_error("configure(...) must be called first.");

		// Validate input sizes
		if (static_cast<u64>(recvBaseOts.size()) != baseCount().mBaseOtCount)
			throw std::runtime_error("wrong number of silent base OTs");

		if (baseA.size() != baseCount().mBaseVoleCount || baseC.size() != baseCount().mBaseVoleCount)
			throw std::runtime_error("wrong number of silent base VOLEs");

		// Split base OTs into PPRF OTs and malicious check OTs
		auto genOts = recvBaseOts.subspan(0, gen().baseOtCount());
		auto malOts = recvBaseOts.subspan(genOts.size());

		// Set PPRF base OTs
		if (genOts.size())
		{
			auto c = choices.subvec(0, genOts.size());
			gen().setChoiceBits(c);
			gen().setBase(genOts);
		}

		// Set malicious check OTs
		mMalCheckChoice = choices.subvec(genOts.size(), malOts.size());
		mMalCheckOts.resize(malOts.size());
		std::copy(malOts.begin(), malOts.end(), mMalCheckOts.begin());

		// Set base VOLE values
		mBaseA.assign(baseA.begin(), baseA.end());
		mBaseC = baseC;
	}

	// Generates the required IKNP/SoftSpoken base OTs
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

	// Creates an independent copy of this extender with shared base OTs
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

	//--------------------------------------------------------------
	// Native Silent OT Extension Interface Implementation
	//--------------------------------------------------------------

	// Checks if the required base correlations are available
	bool SilentOtExtReceiver::hasBaseCors() const
	{
		return gen().hasBaseOts() && mBaseA.size() == baseCount().mBaseVoleCount;
	}

	// Samples the choice bits for base OTs
	BitVector SilentOtExtReceiver::sampleBaseChoiceBits(PRNG& prng) {
		if (isConfigured() == false)
			throw std::runtime_error("configure(...) must be called first");

		// Get choice bits for PPRF base OTs
		if (gen().hasBaseOts() == false)
			return gen().sampleChoiceBits(prng);
		else
			return {};
	}

	// Generates base correlations (OTs and VOLEs) for Silent OT
	task<> SilentOtExtReceiver::genBaseCors(
		PRNG& prng,
		Socket& chl,
		bool useOtExtension)
	{
		MACORO_TRY{

		if (isConfigured() == false)
			throw std::runtime_error("configure must be called first");

		// Determine how many base OTs and base VOLEs we need
		auto count = baseCount();
		auto choice = sampleBaseChoiceBits(prng);
		while (choice.size() < count.mBaseOtCount)
			choice.pushBack(prng.getBit());

		// Generate random bits for base VOLE C values
		BitVector baseC(count.mBaseVoleCount);
		baseC.randomize(prng);

		// Combine all choice bits
		choice.append(baseC);
		AlignedUnVector<block> msg(choice.size());
		std::vector<block> baseA(count.mBaseVoleCount);

#if defined(LIBOTE_HAS_BASE_OT)
#if defined(ENABLE_SOFTSPOKEN_OT) 
		if (useOtExtension)
		{
			// Initialize OT extension if needed
			if (!mOtExtRecver)
			{
				mOtExtRecver.emplace();
				// false -> no hashing, delta OTs / VOLEs
				mOtExtRecver->init(2, false);
				auto baseCount = mOtExtRecver->baseOtCount();
				DefaultBaseOT base;
				std::vector<std::array<block, 2>> baseMsg(baseCount);
				co_await base.send(baseMsg, prng, chl);
				mOtExtRecver->setBaseOts(baseMsg);
			}

			// Use OT extension to generate the base OTs
			co_await mOtExtRecver->receive(choice, msg, prng, chl);

			// Extract base VOLE A values
			std::copy(msg.begin() + msg.size() - baseA.size(), msg.end(), baseA.begin());
			msg.resize(msg.size() - baseA.size());
			choice.resize(msg.size());

			// Convert messages to random OTs by hashing
			mOtExtRecver->mBase.mAesMgr.useAES(msg.size()).hashBlocks(msg, msg);
		}
		else
#endif
		{
			// Use base OT protocol directly (more expensive but fewer rounds)
			auto base = DefaultBaseOT{};
			co_await base.receive(choice, msg, prng, chl);

			// Extract base VOLE A values
			std::copy(msg.begin() + msg.size() - baseA.size(), msg.end(), baseA.begin());
			msg.resize(msg.size() - baseA.size());

			// For stationary noise, we need to generate base VOLEs
			if (baseA.size())
			{
				// Derandomize the VOLEs to ensure they follow the correlation:
				// baseA = baseB + baseC * delta
				std::vector<block> offsets(baseA.size());
				co_await chl.recv(offsets);
				for (u64 i = 0; i < baseA.size(); ++i)
				{
					baseA[i] = baseA[i] ^ (baseC[i] ? offsets[i] : ZeroBlock);
				}
			}

			setTimePoint("recver.gen.baseOT");
		}
#else
		throw std::runtime_error("soft spoken ot or base OTs must be enabled");
#endif
		// Set the generated base correlations
		setBaseCors(msg, choice, baseA, baseC);
		setTimePoint("recver.gen.done");

		} MACORO_CATCH(eptr) {
			if (!chl.closed()) co_await chl.close();
			std::rethrow_exception(eptr);
		}
	}

	// Returns how many base OTs and VOLEs are needed
	SilentBaseCount SilentOtExtReceiver::baseCount() const
	{
		if (isConfigured() == false)
			throw std::runtime_error("configure must be called first");

		return
		{
			gen().baseOtCount() + (mSecurityType == SilentSecType::Malicious) * 128,
			(mNoiseDist == SdNoiseDistribution::Stationary) * mNumPartitions
		};
	}

	// Configures the Silent OT extension parameters
	void SilentOtExtReceiver::configure(
		u64 numOTs,
		u64 scaler,
		u64 numThreads,
		SilentSecType malType,
		SdNoiseDistribution noiseType,
		MultType multType)
	{
		mLpnMultType = multType;
		mSecurityType = malType;
		mNumThreads = numThreads;
		u64 secParam = 128;
		mRequestNumOts = numOTs;
		mNoiseDist = noiseType;

		// Configure based on syndrome decoding parameters
		auto param = syndromeDecodingConfigure(secParam, mRequestNumOts, mLpnMultType, noiseType, 1);
		mNumPartitions = param.mNumPartitions;
		mSizePer = param.mSizePer;
		mNoiseVecSize = param.mNumPartitions * param.mSizePer;
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

		// Configure the PPRF generator
		gen().configure(mSizePer, mNumPartitions);
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

	// Debug function to verify correctness with sender
	task<> SilentOtExtReceiver::checkRT(Socket& chl, MatrixView<block> rT1)
	{
		auto rT2 = Matrix<block>(rT1.rows(), rT1.cols(), AllocType::Uninitialized);
		auto delta = block{};
		auto i = u64{};
		auto R = Matrix<block>{};
		auto exp = Matrix<block>{};
		auto failed = false;

		// Receive B vector and delta from sender
		co_await chl.recv(rT2);
		co_await chl.recv(delta);

		// XOR to get A + B = C * delta
		for (i = 0; i < rT1.size(); ++i)
			rT2(i) = rT2(i) ^ rT1(i);

		if (rT1.cols() != 1)
			throw RTE_LOC;
		R = rT2;

		// Compute expected values at sparse coordinates
		exp.resize(R.rows(), R.cols(), AllocType::Zeroed);
		auto points = getPoints();
		for (i = 0; i < points.size(); ++i)
		{
			if (mBaseC.size() == 0 || mBaseC[i])
				exp(points[i]) = delta;
		}

		// Verify all values match expected
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

	// Standard OT extension interface - implement chosen choice bits
	task<> SilentOtExtReceiver::receive(
		const BitVector& choices,
		span<block> messages,
		PRNG& prng,
		Socket& chl)
	{
		MACORO_TRY{
			// First perform random OT
			auto randChoice = BitVector(messages.size());
			co_await silentReceive(randChoice, messages, prng, chl, OTType::Random);

			// Compute correction bits and send to sender
			randChoice ^= choices;
			co_await chl.send(std::move(randChoice));

		} MACORO_CATCH(eptr) {
			if (!chl.closed()) co_await chl.close();
			std::rethrow_exception(eptr);
		}
	}

	// Performs Silent OT protocol and outputs choice bits and messages
	task<> SilentOtExtReceiver::silentReceive(
		BitVector& choices,
		span<block> messages,
		PRNG& prng,
		Socket& chl,
		OTType type)
	{
		MACORO_TRY{
			// Determine choice bit packing based on OT type
			auto packing = (type == OTType::Random) ?
				ChoiceBitPacking::True :
				ChoiceBitPacking::False;

			if (choices.size() != (u64)messages.size())
				throw RTE_LOC;

			// Generate OTs using inplace function
			co_await silentReceiveInplace(messages.size(), prng, chl, packing);

			if (type == OTType::Random)
			{
				// Hash the messages and extract choice bits
				hash(choices, messages, packing);
			}
			else
			{
				// For correlated OT, just copy the values directly
				std::memcpy(messages.data(), mA.data(), messages.size() * sizeof(block));
				setTimePoint("recver.expand.ldpc.copy");

				// Extract choice bits
				auto cIter = choices.begin();
				for (u64 i = 0; i < choices.size(); ++i)
				{
					*cIter = mC[i];
					++cIter;
				}
				setTimePoint("recver.expand.ldpc.copyBits");
			}

			// For regular noise, we can clear state after each use
			// (Stationary noise allows reusing state)
			if (mGenVar.index() == 0)
				clear();

		} MACORO_CATCH(eptr) {
			if (!chl.closed()) co_await chl.close();
			std::rethrow_exception(eptr);
		}
	}

	// Performs Silent OT protocol with internal storage
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

		// Auto-configure if needed
		if (isConfigured() == false)
		{
			configure(n, 2, mNumThreads, mSecurityType);
		}

		if (n != mRequestNumOts)
			throw std::invalid_argument("messages.size() > n");

		// Generate base correlations if not already available
		if (hasBaseCors() == false)
		{
			co_await genBaseCors(prng, chl);
		}

		setTimePoint("recver.expand.start");
		mA.resize(mNoiseVecSize);
		mC.resize(0);

		// Expand PPRF to generate sparse vector
		co_await gen().expand(chl, mA, mPprfFormat, true, mNumThreads, {});

		setTimePoint("recver.expand.pprf");

		// For stationary noise, incorporate base VOLE correlations
		if (mBaseA.size())
		{
			// Get the points where the noisy values should be placed
			std::vector<u64> points = getPoints();

			// Update mA with base VOLE A values at the noisy coordinates
			for (u64 i = 0; i < mNumPartitions; ++i)
			{
				auto pnt = points[i];
				mA[pnt] = mA[pnt] ^ mBaseA[i];
			}
		}

		// Perform malicious security check if needed
		if (mSecurityType == SilentSecType::Malicious)
		{
			co_await ferretMalCheck(chl, prng);
			setTimePoint("recver.expand.malCheck");
		}

		// Debug validation if enabled
		if (mDebug)
		{
			rT = MatrixView<block>(mA.data(), mNoiseVecSize, 1);
			co_await checkRT(chl, rT);
		}

		// Apply compression to convert sparse to dense vector
		compress(type);
		setTimePoint("recver.expand.dualEncode");

		// Clean up base correlations and resize to requested size
		mBaseA.resize(0);
		mBaseC.resize(0);

		mA.resize(mRequestNumOts);

		if (mC.size())
			mC.resize(mRequestNumOts);

		} MACORO_CATCH(eptr) {
			if (!chl.closed()) co_await chl.close();
			std::rethrow_exception(eptr);
		}
	}

	// Performs malicious consistency check based on the Ferret paper
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

		// Generate random seed for malicious check
		block malCheckSeed = prng.get();
		block malCheckX = ZeroBlock;

		// Compute the challenge vector X using the sparse vector points
		auto points = getPoints();
		for (u64 i = 0; i < points.size(); ++i)
		{
			if (mNoiseDist == SdNoiseDistribution::Regular || mBaseC[i])
			{
				auto s = points[i];
				auto xs = malCheckSeed.gf128Pow(s + 1);
				malCheckX = malCheckX ^ xs;
			}
		}
		auto diff = malCheckX ^ mMalCheckChoice.getSpan<block>()[0];

		// Send the random challenge seed
		co_await chl.send(std::array<block, 2>{malCheckSeed, diff});

		// Compute polynomial evaluation at seed
		xx = malCheckSeed;
		sum0 = ZeroBlock;
		sum1 = ZeroBlock;

		for (i = 0; i < (u64)mA.size(); ++i)
		{
			block low, high;
			xx.gf128Mul(mA[i], low, high);
			sum0 = sum0 ^ low;
			sum1 = sum1 ^ high;
			xx = xx.gf128Mul(malCheckSeed);
		}
		mySum = sum0.gf128Reduce(sum1);

		// Perform VOLE to obtain check value
		co_await sender.send(malCheckX, b, prng, mMalCheckOts, chl, {});

		// Hash the result for verification
		ro.Update(mySum ^ b[0]);
		ro.Final(myHash);

		// Receive hash from sender and validate
		co_await chl.recv(theirHash);

		if (theirHash != myHash)
			throw RTE_LOC;
	}

	// Hashes the OT messages for security and extracts choice bits
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
			// Mask to clear the least significant bit (used for choice bit)
			block mask = OneBlock ^ AllOneBlock;

			// Process in blocks of 8 for efficiency
			for (u64 i = 0; i < n8; i += 8)
			{
				// Extract the choice bits from the LSB of each block
				u32 b0 = r[0].testc(OneBlock);
				u32 b1 = r[1].testc(OneBlock);
				u32 b2 = r[2].testc(OneBlock);
				u32 b3 = r[3].testc(OneBlock);
				u32 b4 = r[4].testc(OneBlock);
				u32 b5 = r[5].testc(OneBlock);
				u32 b6 = r[6].testc(OneBlock);
				u32 b7 = r[7].testc(OneBlock);

				// Pack the choice bits into a byte
				choices.data()[i / 8] =
					b0 ^
					(b1 << 1) ^
					(b2 << 2) ^
					(b3 << 3) ^
					(b4 << 4) ^
					(b5 << 5) ^
					(b6 << 6) ^
					(b7 << 7);

				// Clear the LSB which contained the choice bit
				m[0] = r[0] & mask;
				m[1] = r[1] & mask;
				m[2] = r[2] & mask;
				m[3] = r[3] & mask;
				m[4] = r[4] & mask;
				m[5] = r[5] & mask;
				m[6] = r[6] & mask;
				m[7] = r[7] & mask;

				// Hash the messages for security
				mAesFixedKey.hashBlocks<8>(m, m);

				m += 8;
				r += 8;
			}

			// Process any remaining messages
			cIter = cIter + n8;
			for (u64 i = n8; i < (u64)messages.size(); ++i)
			{
				auto m = &messages[i];
				auto r = &mA[i];

				// Clear the LSB which contained the choice bit
				m[0] = r[0] & mask;

				// Hash the message for security
				m[0] = mAesFixedKey.hashBlock(m[0]);

				// Extract the choice bit
				*cIter = r[0].testc(OneBlock);
				++cIter;
			}
		}
		else
		{
			// Not implemented for other packing types
			throw RTE_LOC;
		}
		setTimePoint("recver.expand.CopyHash");
	}

	// Compresses the sparse vector to generate dense vector
	void SilentOtExtReceiver::compress(ChoiceBitPacking packing)
	{
		auto points = getPoints();

		if (packing == ChoiceBitPacking::True)
		{
			// Zero out the LSB of mA to prepare for storing choice bits
			block mask = OneBlock ^ AllOneBlock;
			auto m8 = mNoiseVecSize / 8 * 8;
			auto r = mA.data();

			// Process in blocks of 8 for efficiency
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

			// Process any remaining values
			for (u64 i = m8; i < mNoiseVecSize; ++i)
			{
				mA[i] = mA[i] & mask;
			}

			// Set the LSB of mA at noise points to be the choice bit
			for (u64 i = 0; i < points.size(); ++i)
			{
				auto ci = mBaseC.size() ? block(mBaseC[i]) : OneBlock;
				mA[points[i]] = mA[points[i]] | ci;
			}

			setTimePoint("recver.expand.bitPacking");

			// Apply appropriate compression method based on configuration
			switch (mLpnMultType)
			{
			case osuCrypto::MultType::QuasiCyclic:
			{
#ifdef ENABLE_BITPOLYMUL
				QuasiCyclicCode code;
				u64 scaler;
				double _;
				QuasiCyclicConfigure(scaler, _);
				code.init2(mRequestNumOts, mNoiseVecSize, mCodeSeed);
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
				// Use Expander-Accumulator code for compression
				EACode mEAEncoder;
				u64 expanderWeight = 0, _1;
				double _2;
				EAConfigure(mLpnMultType, _1, expanderWeight, _2);
				mEAEncoder.config(mRequestNumOts, mNoiseVecSize, expanderWeight, mCodeSeed);
				AlignedUnVector<block> A2(mEAEncoder.mMessageSize);
				mEAEncoder.dualEncode<block, CoeffCtxGF2>(mA, A2, {});
				std::swap(mA, A2);
				break;
			}
			case osuCrypto::MultType::ExConv7x24:
			case osuCrypto::MultType::ExConv21x24:
			{
				// Use Expander-Convolutional code for compression
				u64 expanderWeight = 0, accWeight = 0, _1;
				double _2;
				ExConvConfigure(mLpnMultType, _1, expanderWeight, accWeight, _2);

				ExConvCode exConvEncoder;
				exConvEncoder.config(mRequestNumOts, mNoiseVecSize, expanderWeight, accWeight, true, true, mCodeSeed);
				exConvEncoder.dualEncode<block, CoeffCtxGF2>(mA.begin(), {});
				break;
			}
			case MultType::BlkAcc3x8:
			case MultType::BlkAcc3x32:
			{
				// Use Block-Accumulator code for compression
				u64 depth, sigma, scaler;
				double md;
				BlkAccConfigure(mLpnMultType, scaler, sigma, depth, md);
				BlkAccCode code;
				code.init(mRequestNumOts, mNoiseVecSize, sigma, depth, mCodeSeed);
				code.dualEncode<block, CoeffCtxGF2>(mA.begin(), {});
				break;
			}
			case osuCrypto::MultType::Tungsten:
			{
				// Use Tungsten code for compression
				experimental::TungstenCode encoder;
				encoder.config(oc::roundUpTo(mRequestNumOts, 8), mNoiseVecSize, mCodeSeed);
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
			// For separate choice bits, create mC vector
			mC.resize(mNoiseVecSize);
			std::memset(mC.data(), 0, mNoiseVecSize);

			// Set choice bits at noise points
			for (u64 i = 0; i < points.size(); ++i)
				mC[points[i]] = mBaseC.size() ? mBaseC[i] : 1;

			// Apply appropriate compression method based on configuration
			switch (mLpnMultType)
			{
			case osuCrypto::MultType::QuasiCyclic:
			{
#ifdef ENABLE_BITPOLYMUL
				QuasiCyclicCode code;
				u64 scaler;
				double _;
				QuasiCyclicConfigure(scaler, _);
				code.init2(mRequestNumOts, mNoiseVecSize, mCodeSeed);

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
				// Use Expander-Accumulator code for both A and C
				EACode mEAEncoder;
				u64 expanderWeight = 0, _1;
				double _2;
				EAConfigure(mLpnMultType, _1, expanderWeight, _2);
				mEAEncoder.config(mRequestNumOts, mNoiseVecSize, expanderWeight, mCodeSeed);

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
				// Use Expander-Convolutional code for both A and C
				u64 expanderWeight = 0, accWeight = 0, _1;
				double _2;
				ExConvConfigure(mLpnMultType, _1, expanderWeight, accWeight, _2);

				ExConvCode exConvEncoder;
				exConvEncoder.config(mRequestNumOts, mNoiseVecSize, expanderWeight, accWeight, true, true, mCodeSeed);

				exConvEncoder.dualEncode2<block, u8, CoeffCtxGF2>(
					mA.begin(),
					mC.begin(),
					{});

				break;
			}
			case MultType::BlkAcc3x8:
			case MultType::BlkAcc3x32:
			{
				// Use Block-Accumulator code for both A and C
				u64 depth, sigma, scaler;
				double md;
				BlkAccConfigure(mLpnMultType, scaler, sigma, depth, md);
				BlkAccCode code;
				code.init(mRequestNumOts, mNoiseVecSize, sigma, depth, mCodeSeed);
				code.dualEncode2<block, u8, CoeffCtxGF2>(mA.begin(), mC.begin(), {});
				break;
			}
			case osuCrypto::MultType::Tungsten:
			{
				// Use Tungsten code for both A and C
				experimental::TungstenCode encoder;
				encoder.config(roundUpTo(mRequestNumOts, 8), mNoiseVecSize, mCodeSeed);
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

		// Update code seed for next use
		mCodeSeed = mAesFixedKey.hashBlock(mCodeSeed);
	}

	// Clears internal buffers and state
	void SilentOtExtReceiver::clear()
	{
		mNoiseVecSize = 0;
		mRequestNumOts = 0;
		mSizePer = 0;

		mC = {};
		mA = {};

		if (isConfigured())
			gen().clear();
	}
}
#endif
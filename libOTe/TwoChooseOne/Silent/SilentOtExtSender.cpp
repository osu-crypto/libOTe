#include "libOTe/TwoChooseOne/Silent/SilentOtExtSender.h"

#ifdef ENABLE_SILENTOT

#include "libOTe/Tools/Tools.h"
#include "libOTe/TwoChooseOne/Silent/SilentOtExtReceiver.h"
#include <libOTe/Tools/bitpolymul.h>
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/ThreadBarrier.h"
#include "libOTe/Base/BaseOT.h"
#include <cryptoTools/Crypto/RandomOracle.h>
#include "libOTe/Vole/Noisy/NoisyVoleReceiver.h"
#include "libOTe/Tools/QuasiCyclicCode.h"
#include "libOTe/Tools/TungstenCode/TungstenCode.h"
#include "libOTe/Tools/BlkAccCode/BlkAccCode.h"

namespace osuCrypto
{

	//--------------------------------------------------------------
	// Standard OT Extension Interface Implementation
	//--------------------------------------------------------------

	// Sets the IKNP/SoftSpoken base OTs used for OT extension
	void SilentOtExtSender::setBaseOts(
		span<block> baseRecvOts,
		const BitVector& choices)
	{
#ifdef ENABLE_SOFTSPOKEN_OT
		if (!mOtExtSender)
			mOtExtSender.emplace();

		mOtExtSender->setBaseOts(baseRecvOts, choices);
#else
		throw std::runtime_error("softspoken must be enabled. " LOCATION);
#endif
	}

	// Creates an independent copy of this extender with shared base OTs
	std::unique_ptr<OtExtSender> SilentOtExtSender::split()
	{
#ifdef ENABLE_SOFTSPOKEN_OT
		auto ptr = new SilentOtExtSender;
		auto ret = std::unique_ptr<OtExtSender>(ptr);
		if (!mOtExtSender)
			throw RTE_LOC;
		ptr->mOtExtSender = mOtExtSender->splitBase();
		ptr->mNumThreads = mNumThreads;
		ptr->mLpnMultType = mLpnMultType;
		ptr->mSecurityType = mSecurityType;
		ptr->mNoiseDist = mNoiseDist;
		ptr->mDebug = mDebug;
		return ret;
#else
		throw std::runtime_error("softspoken must be enabled. " LOCATION);
#endif
	}

	// Generates the required IKNP/SoftSpoken base OTs
	task<> SilentOtExtSender::genBaseOts(PRNG& prng, Socket& chl)
	{
#ifdef ENABLE_SOFTSPOKEN_OT
		if (!mOtExtSender)
			mOtExtSender.emplace();
		return mOtExtSender->genBaseOts(prng, chl);
#else
		throw std::runtime_error("softspoken must be enabled. " LOCATION);
#endif
	}

	// Returns the number of base OTs required for the IKNP/SoftSpoken protocol
	u64 SilentOtExtSender::baseOtCount() const
	{
#ifdef ENABLE_SOFTSPOKEN_OT
		if (!mOtExtSender)
		{
			const_cast<macoro::optional<SoftSpokenMalOtSender>*>(&mOtExtSender)
				->emplace();
		}
		return mOtExtSender->baseOtCount();
#else
		throw std::runtime_error("softspoken must be enabled. " LOCATION);
#endif
	}

	// Checks if the required IKNP/SoftSpoken base OTs are set
	bool SilentOtExtSender::hasBaseOts() const
	{
#ifdef ENABLE_SOFTSPOKEN_OT
		if (!mOtExtSender)
			return false;
		return mOtExtSender->hasBaseOts();
#else
		throw std::runtime_error("softspoken must be enabled. " LOCATION);
#endif
	}

	//--------------------------------------------------------------
	// Native Silent OT Extension Interface Implementation
	//--------------------------------------------------------------

	// Generates the base correlations (OTs and VOLEs) required for Silent OT
	task<> SilentOtExtSender::genBaseCors(std::optional<block> delta, PRNG& prng, Socket& chl, bool useOtExtension)
	{
		MACORO_TRY{

		// If delta is not provided, use existing delta or generate a new one
		delta = delta.value_or(mDelta.value_or(prng.get()));

		// Determine how many base OTs and base VOLEs we need
		auto count = baseCount();
		auto msg = AlignedUnVector<std::array<block, 2>>(count.mBaseOtCount + count.mBaseVoleCount);
		auto baseB = AlignedUnVector<block>(count.mBaseVoleCount);
		
		if (isConfigured() == false)
			throw std::runtime_error("configure must be called first");

#if defined(ENABLE_SOFTSPOKEN_OT) && defined(LIBOTE_HAS_BASE_OT)

#ifdef ENABLE_SOFTSPOKEN_OT
		if (useOtExtension)
		{
			// Set up choice bits for the base OTs - use delta as the choice bits
			BitVector choice;
			choice.append((u8*)&*delta, 128);

			// Initialize OT extension if needed
			if (!mOtExtSender)
			{
				mOtExtSender.emplace();
				// false -> no hashing, delta OTs / VOLEs
				mOtExtSender->init(2, false);
				auto baseCount = mOtExtSender->baseOtCount();
				DefaultBaseOT base;
				std::vector<block> baseMsg(baseCount);
				co_await base.receive(choice, baseMsg, prng, chl);
				mOtExtSender->setBaseOts(baseMsg, choice);
			}

			// Check if the existing delta matches what we need
			// This is critical for stationary noise which requires consistent delta values
			if (mOtExtSender->mBase.mSubVole.mVole.mDelta != choice && count.mBaseVoleCount)
				throw std::runtime_error("genBaseCors does not implement the logic to generate the BaseCors for a different delta value. Caller must do this manually. " LOCATION);

			// Use OT extension to generate the base OTs
			co_await mOtExtSender->send(msg, prng, chl);

			// Extract base VOLE B values
			for (u64 i = 0; i < baseB.size(); ++i)
				baseB[i] = msg[i + count.mBaseOtCount][0];
			msg.resize(msg.size() - baseB.size());

			// Convert messages to random OTs by hashing
			auto hasher = mOtExtSender->mBase.mAesMgr.useAES(msg.size());
			for (auto& m : msg)
				hasher.hashBlocks(m, m);
		}
		else
#endif
		{
			// Use base OT protocol directly (more expensive but fewer rounds)
			auto base = DefaultBaseOT{};
			co_await base.send(msg, prng, chl);

			// For stationary noise, we need to generate base VOLEs
			if (baseB.size())
			{
				// Derandomize the VOLEs to ensure they follow the correlation:
				// baseA = baseB + baseC * delta
				std::vector<block> offsets(baseB.size());
				for (u64 i = 0; i < baseB.size(); ++i)
				{
					baseB[i] = msg[i + count.mBaseOtCount][0];
					offsets[i] = msg[i + count.mBaseOtCount][0] ^ msg[i + count.mBaseOtCount][1] ^ *delta;
				}
				co_await chl.send(std::move(offsets));

				// Remove VOLE messages from the OT array
				msg.resize(msg.size() - baseB.size());
			}

			setTimePoint("sender.gen.baseOT");
		}
#else
		throw std::runtime_error("KOS or base OTs must be enabled");
#endif

		// Set the generated base correlations
		setBaseCors(msg, baseB, *delta);

		setTimePoint("sender.gen.done");

		} MACORO_CATCH(eptr) {
			if (!chl.closed()) co_await chl.close();
			std::rethrow_exception(eptr);
		}
	}

	// Returns how many base OTs and VOLEs are needed
	SilentBaseCount SilentOtExtSender::baseCount() const
	{
		if (isConfigured() == false)
			throw std::runtime_error("configure must be called first");

		// Get number of base OTs needed for the PPRF
		auto n = gen().baseOtCount();

		// Add additional OTs for malicious security if needed
		if (mSecurityType == SilentSecType::Malicious)
			n += 128;

		// For stationary noise, we need base VOLEs (one per partition)
		auto v = mNoiseDist == SdNoiseDistribution::Stationary ? mNumPartitions : 0;

		return { n, v };
	}

	// Sets externally generated base OTs and VOLEs
	void SilentOtExtSender::setBaseCors(
		span<const std::array<block, 2>> sendBaseOts,
		span<const block> baseB,
		block delta)
	{
		// Validate input sizes
		if ((u64)sendBaseOts.size() != baseCount().mBaseOtCount)
			throw RTE_LOC;
		if ((u64)baseB.size() != baseCount().mBaseVoleCount)
			throw RTE_LOC;

		// Split base OTs into PPRF OTs and malicious check OTs
		auto genOt = sendBaseOts.subspan(0, gen().baseOtCount());
		auto malOt = sendBaseOts.subspan(genOt.size());
		mMalCheckOts.resize((mSecurityType == SilentSecType::Malicious) * 128);

		// Set PPRF base OTs
		if (genOt.size())
			gen().setBase(genOt);

		// Set malicious check OTs
		std::copy(malOt.begin(), malOt.end(), mMalCheckOts.begin());

		// Set base VOLE B values and delta
		mBaseB.resize(baseB.size());
		std::copy(baseB.begin(), baseB.end(), mBaseB.begin());
		mDelta = delta;
	}

	// Configures the Silent OT extension parameters
	void SilentOtExtSender::configure(
		u64 numOTs, u64 scaler, u64 numThreads,
		SilentSecType malType,
		SdNoiseDistribution noiseType,
		MultType mult)
	{
		if (numOTs == 0)
			throw std::invalid_argument("Silent OT count must be nonzero. " LOCATION);

		(void)scaler;
		if (malType != SilentSecType::SemiHonest &&
			malType != SilentSecType::Malicious)
			throw std::invalid_argument("Silent security type not supported. " LOCATION);

		constexpr u64 secParam = 128;
		auto param = syndromeDecodingConfigure(secParam, numOTs, mult, noiseType, 1);
		auto format = PprfOutputFormat{};

		if (SdNoiseDistribution::Regular == noiseType)
		{
			format = PprfOutputFormat::ByPhysicalIndex;
		}
		else if (SdNoiseDistribution::Stationary == noiseType)
		{
			format = PprfOutputFormat::ByTreeIndex;
		}
		else
		{
			throw std::invalid_argument("SilentNoiseType not supported. " LOCATION);
		}
		pprf::validateConfigure(param.mSizePer, param.mNumPartitions);

		if (SdNoiseDistribution::Regular == noiseType)
			mGenVar.template emplace<0>();
		else
			mGenVar.template emplace<1>();
		std::visit([&](auto& gen) {
			gen.configure(param.mSizePer, param.mNumPartitions);
			}, mGenVar);
		mLpnMultType = mult;
		mSecurityType = malType;
		mNumThreads = numThreads;
		mRequestNumOts = numOTs;
		mNoiseDist = noiseType;
		mNumPartitions = param.mNumPartitions;
		mSizePer = param.mSizePer;
		mNoiseVecSize = param.mNoiseVectorSize;
		mPprfFormat = format;
		mCodeSeed = block(12528943721987127, 98743297823479812);
		mB = {};
		mEncodeTemp = {};
		mDelta.reset();
		mMalCheckOts = {};
		mBaseB = {};
	}

	// Debug function to verify correctness with receiver
	task<> SilentOtExtSender::checkRT(Socket& chl)
	{
		co_await chl.send(mB);
		co_await chl.send(*mDelta);

		setTimePoint("sender.expand.checkRT");
	}

	// Clears internal buffers and state
	void SilentOtExtSender::clear()
	{
		std::visit([](auto& gen) { gen.clear(); }, mGenVar);
		mNoiseVecSize = 0;
		mRequestNumOts = 0;
		mSizePer = 0;
		mNumPartitions = 0;
		mB = {};
		mEncodeTemp = {};
		mDelta.reset();
		mMalCheckOts = {};
		mBaseB = {};
		mCodeSeed = ZeroBlock;
	}

	// Standard OT extension interface - receiver specifies choice bits
	task<> SilentOtExtSender::send(
		span<std::array<block, 2>> messages,
		PRNG& prng,
		Socket& chl)
	{
		MACORO_TRY{
		// First perform random OT
		auto correction = BitVector(messages.size());
		auto iter = BitIterator{};
		auto i = u64{};

		co_await silentSend(messages, prng, chl);
		
		// Receive correction bits from receiver and apply them
		co_await chl.recv(correction);
		iter = correction.begin();

		for (i = 0; i < static_cast<u64>(messages.size()); ++i)
		{
			u8 bit = *iter; ++iter;
			auto temp = messages[i];
			messages[i][0] = temp[bit];
			messages[i][1] = temp[bit ^ 1];
		}

		} MACORO_CATCH(eptr) {
			if (!chl.closed()) co_await chl.close();
			std::rethrow_exception(eptr);
		}
	}

	// Performs Silent random OT protocol
	task<> SilentOtExtSender::silentSend(
		span<std::array<block, 2>> messages,
		PRNG& prng,
		Socket& chl)
	{
		MACORO_TRY{

		// Generate random OTs using inplace function
		co_await silentSendInplace(mDelta, messages.size(), prng, chl);
		
		// Hash the OT messages for security
		hash(messages, ChoiceBitPacking::True);

		// For regular noise, we can clear state after each use
		// (Stationary noise allows reusing state)
		if (mGenVar.index() == 0)
			clear();

		} MACORO_CATCH(eptr) {
			if (!chl.closed()) co_await chl.close();
			std::rethrow_exception(eptr);
		}
	}

	// Hashes the OT messages for security
	void SilentOtExtSender::hash(
		span<std::array<block, 2>> messages,
		ChoiceBitPacking type)
	{
		if (type == ChoiceBitPacking::True)
		{
			if ((u64)messages.size() != mRequestNumOts)
				throw RTE_LOC;
			if ((u64)mB.size() != mRequestNumOts || !mDelta)
				throw std::logic_error("Silent OT sender hash state is not ready. " LOCATION);

			// Mask to clear the least significant bit (used for choice bit)
			block mask = OneBlock ^ AllOneBlock;
			auto d = *mDelta & mask;

			auto n8 = (u64)messages.size() / 8 * 8;
			std::array<block, 16> hashBatch;

			std::array<block, 2>* m = messages.data();
			auto r = mB.data();

			// Process in blocks of 8 for efficiency
			for (u64 i = 0; i < n8; i += 8)
			{
				// Clear the LSB from each value
				r[0] = r[0] & mask;
				r[1] = r[1] & mask;
				r[2] = r[2] & mask;
				r[3] = r[3] & mask;
				r[4] = r[4] & mask;
				r[5] = r[5] & mask;
				r[6] = r[6] & mask;
				r[7] = r[7] & mask;

				// Keep the fixed-width AES batching without flattening the nested
				// std::array<block, 2> output objects.
				for (u64 j = 0; j < 8; ++j)
				{
					hashBatch[2 * j] = r[j];
					hashBatch[2 * j + 1] = r[j] ^ d;
				}
				mAesFixedKey.hashBlocks<8>(hashBatch.data(), hashBatch.data());
				mAesFixedKey.hashBlocks<8>(hashBatch.data() + 8, hashBatch.data() + 8);
				for (u64 j = 0; j < 8; ++j)
				{
					m[j][0] = hashBatch[2 * j];
					m[j][1] = hashBatch[2 * j + 1];
				}

				m += 8;
				r += 8;
			}
			
			// Process any remaining messages
			for (u64 i = n8; i < (u64)messages.size(); ++i)
			{
				messages[i][0] = (mB[i]) & mask;
				messages[i][1] = (mB[i] ^ d) & mask;

				messages[i][0] = mAesFixedKey.hashBlock(messages[i][0]);
				messages[i][1] = mAesFixedKey.hashBlock(messages[i][1]);
			}
		}
		else
		{
			throw RTE_LOC;
		}

		setTimePoint("sender.expand.ldpc.mHash");
	}

	// Performs Silent correlated OT protocol
	task<> SilentOtExtSender::silentSend(
		std::optional<block> d,
		span<block> b,
		PRNG& prng,
		Socket& chl)
	{
		// Generate correlated OTs using inplace function
		co_await silentSendInplace(d, b.size(), prng, chl);

		// Copy the results to the output buffer
		std::memcpy(b.data(), mB.data(), b.size() * sizeof(block));
		setTimePoint("sender.expand.ldpc.copy");
		clear();
	}

	// Performs Silent correlated OT protocol with internal storage
	task<> SilentOtExtSender::silentSendInplace(
		std::optional<block> d,
		u64 n,
		PRNG& prng,
		Socket& chl)
	{
		MACORO_TRY{

		setTimePoint("sender.expand.enter");

		// Auto-configure if needed
		if (isConfigured() == false)
			configure(n, 2, mNumThreads, mSecurityType, mNoiseDist, mLpnMultType);

		if (n != mRequestNumOts)
			throw std::invalid_argument("n != mRequestNumOts " LOCATION);

		// Generate base correlations if not already available
		if (hasBaseCors() == false)
			co_await genBaseCors(d, prng, chl);

		setTimePoint("sender.expand.start");

		// Handle delta value according to noise distribution
		if (mNoiseDist == SdNoiseDistribution::Stationary)
		{
			// For stationary noise, delta must be consistent
			if (d.has_value() && d != mDelta)
			{
				throw std::runtime_error("SilentOtExtSender: delta must match the same value that was used in"
					"setup when using stationary. It is possible to change delta but requires"
					"computing a new base VOLE correlation and setting the base correlations. "
					LOCATION);
			}
		}
		else
		{
			// For regular noise, we can set delta dynamically
			if(d.has_value())
				mDelta = d;

			if(!mDelta.has_value())
				mDelta = prng.get<block>();
		}

		// Prepare delta value(s) for PPRF expansion
		auto delta = AlignedUnVector<block>{};
		if (mBaseB.size())
		{
			// For stationary noise, use base VOLE B values
			delta.resize(mBaseB.size());
			std::copy(mBaseB.begin(), mBaseB.end(), delta.begin());
		}
		else
		{
			// For regular noise, use single delta value
			delta.resize(1);
			delta[0] = *mDelta;
		}

		if(mTimer)
			gen().setTimer(getTimer());

		// Allocate and expand the B vector
		mB.resize(mNoiseVecSize);
		co_await gen().expand(chl, delta, prng.get(), mB, mPprfFormat, true, mNumThreads, CoeffCtxGF2{});

		// fill remaining with zeros
		for (u64 i = mNumPartitions * mSizePer; i < mB.size(); ++i)
			mB[i] = ZeroBlock;

		setTimePoint("sender.expand.pprf");

		// Perform malicious security check if needed
		if (mSecurityType == SilentSecType::Malicious)
		{
			co_await ferretMalCheck(chl, prng);
			setTimePoint("sender.expand.malcheck");
		}

		// Debug validation if enabled
		if (mDebug)
			co_await checkRT(chl);

		// Apply compression to convert sparse to dense vector
		compress();
		setTimePoint("sender.expand.dualEncode");

		// Resize to requested size and clear base VOLEs
		mB.resize(mRequestNumOts);
		mBaseB.resize(0);

		} MACORO_CATCH(eptr) {
			clear();
			if (!chl.closed()) co_await chl.close();
			std::rethrow_exception(eptr);
		}
	}

	// Performs malicious consistency check based on the Ferret paper
	task<> SilentOtExtSender::ferretMalCheck(Socket& chl, PRNG& prng)
	{
		// Receive the random challenge X and OT derandomization
		std::array<block, 2> buff;
		co_await chl.recv(buff);
		auto X = buff[0];
		auto d = buff[1];
		for (u64 i = 0; i < 128; ++i)
			if (bit(d, i))
				std::swap(mMalCheckOts[i][0], mMalCheckOts[i][1]);

		// Compute polynomial evaluation at X
		auto xx = X;
		auto sum0 = ZeroBlock;
		auto sum1 = ZeroBlock;
		for (u64 i = 0; i < (u64)mB.size(); ++i)
		{
			block low, high;
			xx.gf128Mul(mB[i], low, high);
			sum0 = sum0 ^ low;
			sum1 = sum1 ^ high;
			xx = xx.gf128Mul(X);
		}
		auto mySum = sum0.gf128Reduce(sum1);

		// compute mDelta * sum_i e_i * mA_i * xi
		auto a = AlignedUnVector<block>(1);
		auto c = AlignedUnVector<block>(1);
		c[0] = *mDelta;
		auto recver = NoisyVoleReceiver<block, block, CoeffCtxGF128>{};
		co_await recver.receive(c, a, prng, mMalCheckOts, chl, {});

		// Hash the result for verification
		auto ro = RandomOracle(32);
		auto myHash = std::array<u8, 32>{};
		ro.Update(mySum ^ a[0]);
		ro.Final(myHash);

		// Send hash to receiver for validation
		co_await chl.send(std::move(myHash));
	}

	// Compresses the sparse vector to generate dense vector
	void SilentOtExtSender::compress()
	{
		// Apply appropriate compression method based on configuration
		switch (mLpnMultType)
		{
		case osuCrypto::MultType::QuasiCyclic:
		{
#ifdef ENABLE_BITPOLYMUL
			// Use QuasiCyclic code for compression
			QuasiCyclicCode code;
			code.init2(mRequestNumOts, mNoiseVecSize, mCodeSeed);
			code.dualEncode(mB.subspan(0, code.size()));
#else
			throw std::runtime_error("ENABLE_BITPOLYMUL");
#endif
		}
		break;
		case osuCrypto::MultType::ExAcc7:
		case osuCrypto::MultType::ExAcc11:
		case osuCrypto::MultType::ExAcc21:
		case osuCrypto::MultType::ExAcc40:
		{
			// Use Expander-Accumulator code for compression
			EACode encoder;
			u64 expanderWeight = 0, _1;
			double _2;
			EAConfigure(mLpnMultType, _1, expanderWeight, _2);
			encoder.config(mRequestNumOts, mNoiseVecSize, expanderWeight, mCodeSeed);

			AlignedUnVector<block> B2(encoder.mMessageSize);
			encoder.dualEncode<block, CoeffCtxGF2>(mB, B2, {});
			std::swap(mB, B2);
			break;
		}
		case osuCrypto::MultType::ExConv7x24:
		case osuCrypto::MultType::ExConv21x24:
		{
			// Use Expander-Convolutional code for compression
			u64 expanderWeight = 0, accWeight = 0, scaler = 0;
			double minDist = 0;
			ExConvConfigure(mLpnMultType, scaler, expanderWeight, accWeight, minDist);
			assert(scaler == 2 && minDist > 0 && minDist < 1);

			ExConvCode exConvEncoder;
			exConvEncoder.config(mRequestNumOts, mNoiseVecSize, expanderWeight, accWeight, true, true, mCodeSeed);

			exConvEncoder.dualEncode<block, CoeffCtxGF2>(mB.begin(), {});
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
			code.dualEncode<block, CoeffCtxGF2>(mB.begin(), {});
			break;
		}
		case osuCrypto::MultType::Tungsten:
		{
			// Use Tungsten code for compression
			experimental::TungstenCode encoder;
			encoder.config(oc::roundUpTo(mRequestNumOts, 8), mNoiseVecSize, mCodeSeed);

			encoder.dualEncode<block, CoeffCtxGF2>(mB.begin(), {}, mEncodeTemp);
			break;
		}
		default:
			throw RTE_LOC;
			break;
		}

		// Update code seed for future use
		mCodeSeed = mAesFixedKey.hashBlock(mCodeSeed);
	}
}

#endif

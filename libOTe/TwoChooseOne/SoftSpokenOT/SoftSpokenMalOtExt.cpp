#include "SoftSpokenMalOtExt.h"
#ifdef ENABLE_SOFTSPOKEN_OT

//#include "SoftSpokenMalLeakyDotExt.h"
//#include "SoftSpokenMalOtExt.h"

namespace osuCrypto
{


	constexpr u64 SubspaceVoleMaliciousBase::gfMods[];

	task<> SoftSpokenMalOtSender::send(
		span<std::array<block, 2>> messages, PRNG& prng, Socket& chl)
	{
		MACORO_TRY{
		if ((u64)messages.data() % 32)
			throw std::runtime_error("soft spoken requires the messages to by 32 byte aligned. Consider using AlignedUnVector or AlignedVector." LOCATION);

		if (messages.size() == 0)
			throw std::runtime_error("soft spoken must be called with at least 1 messag." LOCATION);

		auto nChunks = u64{};
		auto messagesFullChunks = u64{};
		auto numExtra = u64{};
		auto scratch = span<block>{};
		auto scratchBacking = AlignedUnVector<block>{};
		auto seed = block{};
		auto mHasher = Hasher{};


		if (!hasBaseOts())
			co_await(genBaseOts(prng, chl));

		if (mBase.mSubVole.hasSeed() == 0)
		{
			seed = prng.get<block>();
			mBase.mAesMgr.setSeed(seed);
			co_await(chl.send(std::move(seed)));
			co_await(mBase.mSubVole.expand(chl, prng, mBase.mNumThreads));
		}

		nChunks = divCeil(messages.size() + 64, 128);
		messagesFullChunks = messages.size() / 128;
		numExtra = nChunks - messagesFullChunks; // Always 1 or 2
		scratch = span<block>(messages[0].data(), messages.size() * 2);
		if (mBase.wSize() > 2 * 128)
		{
			scratchBacking.resize(messagesFullChunks * chunkSize() + paddingSize());
			scratch = scratchBacking;
		}

		scratch[0] = ZeroBlock;
		co_await(runBatch(chl, scratch.subspan(0, messagesFullChunks * chunkSize())));
		assert(messagesFullChunks == 0 || scratch[0] != ZeroBlock);

		// Extra blocks
		co_await(runBatch(chl, mExtraW.subspan(0, numExtra * chunkSize())));
		co_await(mBase.mSubVole.sendChallenge(prng, chl));
		if (mBase.mRandomOt)
			co_await(mHasher.send(prng, chl));

		mHasher.runBatch(messages.subspan(0, messagesFullChunks * 128), this, scratch);
		mHasher.runBatch(messages.subspan(messagesFullChunks * 128), this, mExtraW);

		// Hash the last extra block if there was one with no used mMessages in it at all.
		if (numExtra == 2 || messages.size() % 128 == 0)
			mBase.mSubVole.hash(mExtraW.subspan(chunkSize() * (numExtra - 1), mBase.wPadded()));

		co_await(mBase.mSubVole.checkResponse(chl));

	} MACORO_CATCH(eptr) {
		co_await chl.close();
		std::rethrow_exception(eptr);
	}
	}

	task<> SoftSpokenMalOtSender::runBatch(Socket& chl, span<block> messages)
	{
		auto numInstances = u64{};
		auto numChunks = u64{};
		auto chunkSize_ = u64{};
		auto minInstances = u64{};
		auto nChunk = u64{};
		auto nInstance = u64{};
		auto numUsed = u64{};
		auto temp = AlignedUnVector<block>();

		numInstances = messages.size();
		numChunks = divCeil(numInstances, chunkSize());
		chunkSize_ = chunkSize();
		minInstances = chunkSize_ + paddingSize();

		// The bulk of the instances can work directly on the input / output data.
		nChunk = 0;
		nInstance = 0;
		for (; nInstance + minInstances <= numInstances; ++nChunk, nInstance += chunkSize_)
		{
			if (nChunk % mBase.commSize == 0)
				co_await(mBase.recvBuffer(chl, std::min<u64>(numChunks - nChunk, mBase.commSize)));

			processChunk(
				nChunk, chunkSize_,
				messages.subspan(nInstance, minInstances));
		}


		// The last few (probably only 1) need an intermediate buffer.
		temp.resize(minInstances * (nInstance < numInstances));
		for (; nInstance < numInstances; ++nChunk, nInstance += chunkSize_)
		{
			if (nChunk % mBase.commSize == 0)
				co_await(mBase.recvBuffer(chl, std::min<u64>(numChunks - nChunk, mBase.commSize)));

			numUsed = std::min<u64>(numInstances - nInstance, chunkSize_);

			processPartialChunk(
				nChunk, numUsed,
				messages.subspan(nInstance, numUsed),
				temp);
		}
	}

	void SoftSpokenMalOtSender::processChunk(u64 nChunk, u64 numUsed, span<block> messages)
	{
		u64 blockIdx = mBase.mBlockIdx++;
		mBase.mSubVole.generateChosen(
			blockIdx,
			mBase.mAesMgr.useAES(mBase.mSubVole.mVole.mNumVoles),
			messages.subspan(0, mBase.wPadded()));
	}

	OC_FORCEINLINE void SoftSpokenMalOtSender::processPartialChunk(
		u64 nChunk, u64 numUsed,
		span<block> messages, span<block> temp)
	{
		assert(temp.size() > messages.size());
		memcpy(temp.data(), messages.data(), sizeof(block) * numUsed);

		processChunk(nChunk, numUsed, temp);

		memcpy(messages.data(), temp.data(), sizeof(block) * numUsed);
	}


	inline void SoftSpokenMalOtSender::Hasher::runBatch(
		span<std::array<block, 2>> messages,
		SoftSpokenMalOtSender* parent,
		span<block> extras)
	{


		u64 numInstances = messages.size();

		const u64 minInstances = chunkSize();

		// The bulk of the instances can work directly on the input / output data.
		u64 nChunk = 0;
		u64 nInstance = 0;
		for (; nInstance + minInstances <= numInstances; ++nChunk, nInstance += chunkSize())
			processChunk(
				nChunk, chunkSize(),
				messages.subspan(nInstance, minInstances), parent,
				extras.subspan(nChunk * parent->chunkSize(), parent->mBase.wPadded()));

		std::array<std::array<block, 2>, 128> temps;

		// The last few (probably only 1) need an intermediate buffer.
		for (; nInstance < numInstances; ++nChunk, nInstance += chunkSize())
		{
			u64 numUsed = std::min<u64>(numInstances - nInstance, chunkSize());
			memcpy(temps.data(), &messages[nInstance], numUsed * sizeof(block) * 2);
			memset(temps.data() + numUsed, 0, (temps.size() - numUsed) * sizeof(block) * 2);

			processChunk(nChunk, numUsed, temps, parent,
				extras.subspan(nChunk * parent->chunkSize(), parent->mBase.wPadded()));

			memcpy(&messages[nInstance], temps.data(), numUsed * sizeof(block) * 2);

			//processPartialChunk(
			//	nChunk, numUsed, minInstances,
			//	span<InstParams>(instParams.data() + nInstance, minInstances)...,
			//	std::forward<ChunkParams>(chunkParams[nChunk])...);
		}
	}

	void SoftSpokenMalOtSender::Hasher::processChunk(
		u64 nChunk, u64 numUsed,
		span<std::array<block, 2>> messages,
		SoftSpokenMalOtSender* parent,
		span<block> inputW)
	{
		parent->mBase.mSubVole.hash(inputW);

		assert(inputW.size() >= 128);
		transpose128(inputW.data());

		if (parent->mBase.mRandomOt)
		{
			rtcr.useAES(numUsed);
			Base::xorAndHashMessages(
				numUsed, parent->mBase.delta(), (block*)messages.data(), inputW.data(), rtcr);
		}
		else
		{
			parent->mBase.xorMessages(numUsed, (block*)messages.data(), inputW.data());
		}
	}


	inline void SoftSpokenMalOtReceiver::Hasher::runBatch(
		span<block> messages,
		span<block> choices,
		SoftSpokenMalOtReceiver* parent,
		block* inputV)
	{
		u64 numInstances = messages.size();
		const u64 minInstances = chunkSize();

		// The bulk of the instances can work directly on the input / output data.
		u64 nChunk = 0;
		u64 nInstance = 0;
		for (; nInstance + minInstances <= numInstances; ++nChunk, nInstance += chunkSize())
			processChunk(
				nChunk, chunkSize(),
				messages.subspan(nInstance, minInstances),
				choices[nChunk], parent, inputV);

		std::array<block, 128> temps;

		// The last few (probably only 1) need an intermediate buffer.
		for (; nInstance < numInstances; ++nChunk, nInstance += chunkSize())
		{
			u64 numUsed = std::min<u64>(numInstances - nInstance, chunkSize());
			memcpy(temps.data(), &messages[nInstance], numUsed * sizeof(block));
			memset(temps.data() + numUsed, 0, (temps.size() - numUsed) * sizeof(block));

			processChunk(nChunk, numUsed, temps, choices[nChunk], parent, inputV);

			memcpy(&messages[nInstance], temps.data(), numUsed * sizeof(block));
		}
	}


	void SoftSpokenMalOtReceiver::Hasher::processChunk(
		u64 nChunk, u64 numUsed,
		span<block> messages,
		block choices,
		SoftSpokenMalOtReceiver* parent,
		block* inputV)
	{
		inputV = inputV + nChunk * parent->chunkSize();
		parent->mBase.mSubVole.hash(span<block>(&choices, 1), span<const block>(inputV, parent->mBase.vPadded()));
		transpose128(inputV);

		if (parent->mBase.mRandomOt == false)
		{
			if (messages.data() != inputV)
				memcpy(messages.data(), inputV, numUsed * sizeof(block));
		}
		else
		{
			rtcr.useAES(numUsed);
			block* messagesOut = messages.data();

			// Go backwards to match the sender.
			u64 i = numUsed;
			while (i >= superBlkSize)
			{
				i -= superBlkSize;
				rtcr.template hashBlocks<superBlkSize>(inputV + i, messagesOut + i);
			}

			// Finish up. Other side hashes in blocks of superBlkSize / 2.
			if (i >= superBlkSize / 2)
			{
				i -= superBlkSize / 2;
				rtcr.hashBlocks<superBlkSize / 2>(inputV + i, messagesOut + i);
			}

			u64 remainingIters = i;
			for (u64 j = 0; j < remainingIters; ++j)
			{
				i = remainingIters - j - 1;
				rtcr.hashBlocks<1>(inputV + i, messagesOut + i);
			}
		}
	}


	task<> SoftSpokenMalOtReceiver::receive(
		const BitVector& choices, span<block> messages, PRNG& prng, Socket& chl)
	{
		MACORO_TRY{

		if ((u64)messages.data() % 32)
			throw std::runtime_error("soft spoken requires the messages to by 32 byte aligned. Consider using AlignedUnVector or AlignedVector." LOCATION);

		auto nChunks = u64{};
		auto messagesFullChunks = u64{};
		auto numExtra = u64{};
		auto scratch = (block*)nullptr;
		auto scratchBacking = AlignedUnVector<block>{};
		auto extraChoicesU64 = std::array<u64, 4>{};
		auto sacrificialChoices = u64{};
		auto bit = u64{};
		auto bit64 = u64{};
		auto word = u64{};
		auto mask = u64{};
		auto extraChoices = std::array<block, 2>{};
		auto challenge = block{};
		auto seed = block{};
		auto mHasher = Hasher{};

		if (!hasBaseOts())
			co_await(genBaseOts(prng, chl));

		if (mBase.mSubVole.hasSeed() == false)
		{
			co_await(chl.recv(seed));
			mBase.mAesMgr.setSeed(seed);
			co_await(mBase.mSubVole.expand(chl, prng, mBase.mNumThreads));
		}

		nChunks = divCeil(messages.size() + 64, 128);
		messagesFullChunks = messages.size() / 128;
		scratch = (block*)messages.data();
		if (mBase.vSize() > 128)
		{
			scratchBacking.resize(messagesFullChunks * chunkSize() + paddingSize());
			scratch = scratchBacking.data();
		}

		co_await(runBatch(chl,
			span<block>(scratch, messagesFullChunks * chunkSize()),
			span<block>(choices.blocks(), messagesFullChunks)));

		// Extra blocks
		numExtra = nChunks - messagesFullChunks; // Always 1 or 2
		assert(numExtra == 1 || numExtra == 2);
		extraChoicesU64 = { 0 };
		sacrificialChoices = prng.get<u64>();
		bit = messages.size() % 128;
		if (bit)
			memcpy(extraChoicesU64.data(), choices.blocks() + messagesFullChunks, sizeof(block));

		bit64 = bit % 64;
		word = bit / 64;
		mask = ((u64)1 << bit64) - 1;
		extraChoicesU64[word] &= mask;
		extraChoicesU64[word] |= sacrificialChoices << bit64;
		// Shift twice so that it becomes zero if bit64 = 0 (shift by 64 is undefined).
		extraChoicesU64[word + 1] = sacrificialChoices >> (63 - bit64) >> 1;

		extraChoices = { toBlock(0,0), toBlock(0,0) };
		memcpy(extraChoices.data(), extraChoicesU64.data(), 2 * sizeof(block));
		co_await(runBatch(chl,
			mExtraV.subspan(0, numExtra * chunkSize()),
			span<block>(extraChoices.data(), numExtra)));

		co_await(chl.recv(challenge));
		mBase.mSubVole.setChallenge(challenge);
		if (mBase.mRandomOt)
			co_await(mHasher.recv(chl));

		mHasher.runBatch(
			messages.subspan(0, messagesFullChunks * 128),
			span<block>(choices.blocks(), messagesFullChunks),
			this, scratch);

		//hasher.setGlobalParams();
		mHasher.runBatch(
			messages.subspan(messagesFullChunks * 128),
			span<block>(extraChoices.data(), messages.size() % 128 != 0),
			this, mExtraV.data());

		// Hash the last extra block if there was one with no used mMessages in it at all.
		if (numExtra == 2 || messages.size() % 128 == 0)
			mBase.mSubVole.hash(
				span<block>(&extraChoices[numExtra - 1], 1),
				mExtraV.subspan(chunkSize() * (numExtra - 1), mBase.vPadded()));

		co_await(mBase.mSubVole.sendResponse(chl));

	} MACORO_CATCH(eptr) {
		co_await chl.close();
		std::rethrow_exception(eptr);
	}
	}

	task<> SoftSpokenMalOtReceiver::runBatch(Socket& chl, span<block> messages, span<block> choices)
	{
		auto numChunks = u64{};
		auto numInstances = messages.size();
		auto nChunk = u64{ 0 };
		auto nInstance = u64{ 0 };
		auto numUsed = u64{};
		auto minInstances = u64{};
		auto temp = AlignedUnVector<block>();

		minInstances = chunkSize() + paddingSize();
		mBase.reserveSendBuffer(std::min<u64>(numChunks, mBase.commSize));

		while (nInstance + minInstances <= numInstances)
		{
			processChunk(
				nChunk, chunkSize(),
				messages.subspan(nInstance, minInstances),
				choices[nChunk]);

			++nChunk;
			nInstance += chunkSize();
			if (nInstance + minInstances > numInstances)
				break;

			if (nChunk % mBase.commSize == 0)
			{
				co_await(mBase.sendBuffer(chl));
				mBase.reserveSendBuffer(std::min<u64>(numChunks - nChunk, mBase.commSize));
			}
		}

		temp.resize(minInstances * (nInstance < numInstances));
		for (; nInstance < numInstances; ++nChunk, nInstance += chunkSize())
		{
			if (nChunk && nChunk % mBase.commSize == 0)
			{
				co_await(mBase.sendBuffer(chl));
				mBase.reserveSendBuffer(std::min<u64>(numChunks - nChunk, mBase.commSize));
			}

			numUsed = std::min<u64>(numInstances - nInstance, chunkSize());
			processPartialChunk(
				nChunk, numUsed,
				messages.subspan(nInstance, numUsed),
				choices[nChunk],
				temp);
		}

		if (mBase.hasSendBuffer())
			co_await(mBase.sendBuffer(chl));
	}

	OC_FORCEINLINE void SoftSpokenMalOtReceiver::processPartialChunk(
		u64 nChunk, u64 numUsed,
		span<block> messages, block choice, span<block> temp)
	{
		assert(temp.size() > messages.size());
		memcpy(temp.data(), messages.data(), sizeof(block) * numUsed);

		processChunk(nChunk, numUsed, temp, choice);

		memcpy(messages.data(), temp.data(), sizeof(block) * numUsed);
	}


	void SoftSpokenMalOtReceiver::processChunk(
		u64 nChunk, u64 numUsed, span<block> messages, block choices)
	{
		u64 blockIdx = mBase.mBlockIdx++;
		mBase.mSubVole.generateChosen(
			blockIdx,
			mBase.mAesMgr.useAES(mBase.mSubVole.mVole.mNumVoles),
			span<block>(&choices, 1),
			messages.subspan(0, mBase.vPadded()));
	}
}

#endif

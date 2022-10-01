#include "SoftSpokenMalOtExt.h"
#ifdef ENABLE_SOFTSPOKEN_OT

//#include "SoftSpokenMalLeakyDotExt.h"
//#include "SoftSpokenMalOtExt.h"

namespace osuCrypto
{


	constexpr u64 SubspaceVoleMaliciousBase::gfMods[];

	task<> SoftSpokenMalLeakyDotSender::send(
		span<std::array<block, 2>> messages, PRNG& prng, Socket& chl)
	{
		MC_BEGIN(task<>, this, messages, &prng, &chl, 
			nChunks = u64{},
			messagesFullChunks = u64{},
			numExtra = u64{},
			scratch = span<block>{},
			scratchBacking = AlignedUnVector<block>{},
			seed = block{}
		);


		if (!hasBaseOts())
			MC_AWAIT(genBaseOts(prng, chl));

		if (mBlockIdx == 0)
		{
			seed = prng.get<block>();
			mAesMgr.setSeed(seed);
			MC_AWAIT(chl.send(std::move(seed)));
		}

		MC_AWAIT(mSubVole.expand(chl, prng, mNumThreads));

		nChunks = divCeil(messages.size() + 64, 128);
		messagesFullChunks = messages.size() / 128;
		numExtra = nChunks - messagesFullChunks; // Always 1 or 2

		scratch = span<block>(messages[0].data(), messages.size() * 2);
		if (wSize() > 2 * 128)
		{
			scratchBacking.resize(messagesFullChunks * chunkSize() + paddingSize());
			scratch = scratchBacking;
		}



		MC_AWAIT(runBatch(chl, scratch.subspan(0, messagesFullChunks * chunkSize())));

		// Extra blocks
		MC_AWAIT(runBatch(chl, mExtraW.subspan(0, numExtra * chunkSize())));


		MC_AWAIT(mSubVole.sendChallenge(prng, chl));

		if(mRandomOt)
			MC_AWAIT(mHasher.send(prng, chl));

		//hasher.setGlobalParams(this, scratch);
		//hasher.runBatch(messages.subspan(0, messagesFullChunks * 128));
		mHasher.runBatch(messages.subspan(0, messagesFullChunks * 128), this, scratch);
		//hasher.setGlobalParams();
		mHasher.runBatch(messages.subspan(messagesFullChunks * 128), this, mExtraW);

		// Hash the last extra block if there was one with no used mMessages in it at all.
		if (numExtra == 2 || messages.size() % 128 == 0)
			mSubVole.hash(mExtraW.subspan(chunkSize() * (numExtra - 1), wPadded()));

		MC_AWAIT(mSubVole.checkResponse(chl));

		MC_END();
	}

	task<> SoftSpokenMalLeakyDotSender::runBatch(Socket& chl, span<block> messages)
	{
		MC_BEGIN(task<>, this, messages, &chl,
			numInstances = u64{},
			numChunks = u64{},
			chunkSize_ = u64{},
			minInstances = u64{},
			nChunk = u64{},
			nInstance = u64{},
			numUsed = u64{},
			temp = AlignedUnVector<block>()
		);

		numInstances = messages.size();
		numChunks = divCeil(numInstances, chunkSize());

		chunkSize_ = chunkSize();
		minInstances = chunkSize_ + paddingSize();

		// The bulk of the instances can work directly on the input / output data.
		nChunk = 0;
		nInstance = 0;
		for (; nInstance + minInstances <= numInstances; ++nChunk, nInstance += chunkSize_)
		{
			if (nChunk % commSize == 0)
				MC_AWAIT(recvBuffer(chl, std::min<u64>(numChunks - nChunk, commSize)));

			processChunk(
				nChunk, chunkSize_,
				messages.subspan(nInstance, minInstances));
		}


		// The last few (probably only 1) need an intermediate buffer.
		temp.resize(minInstances * (nInstance < numInstances));

		for (; nInstance < numInstances; ++nChunk, nInstance += chunkSize_)
		{
			if (nChunk % commSize == 0)
				MC_AWAIT(recvBuffer(chl, std::min<u64>(numChunks - nChunk, commSize)));

			numUsed = std::min<u64>(numInstances - nInstance, chunkSize_);

			processPartialChunk(
				nChunk, numUsed,
				messages.subspan(nInstance, numUsed),
				temp);
		}

		MC_END();
	}

	void SoftSpokenMalLeakyDotSender::processChunk(u64 nChunk, u64 numUsed, span<block> messages)
	{
		u64 blockIdx = mBlockIdx++;
		mSubVole.generateChosen(blockIdx, mAesMgr.useAES(mSubVole.mVole.mNumVoles), messages.subspan(0, wPadded()));
	}

	OC_FORCEINLINE void SoftSpokenMalLeakyDotSender::processPartialChunk(
		u64 nChunk, u64 numUsed, 
		span<block> messages, span<block> temp)
	{
		assert(temp.size() > messages.size());
		memcpy(temp.data(), messages.data(), sizeof(block) * numUsed);

		processChunk(nChunk, numUsed, temp);

		memcpy(messages.data(), temp.data(), sizeof(block) * numUsed);
	}


	inline void SoftSpokenMalLeakyDotSender::Hasher::runBatch(
		span<std::array<block,2>> messages,
		SoftSpokenMalLeakyDotSender* parent,
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
				extras.subspan(nChunk * parent->chunkSize(), parent->wPadded()));

		std::array<std::array<block,2>, 128> temps;

		// The last few (probably only 1) need an intermediate buffer.
		for (; nInstance < numInstances; ++nChunk, nInstance += chunkSize())
		{
			u64 numUsed = std::min<u64>(numInstances - nInstance, chunkSize());
			memcpy(temps.data(), &messages[nInstance], numUsed * sizeof(block) * 2);
			memset(temps.data() + numUsed, 0, (temps.size() - numUsed) * sizeof(block) * 2);

			processChunk(nChunk, numUsed, temps, parent, 
				extras.subspan(nChunk * parent->chunkSize(), parent->wPadded()));

			memcpy(&messages[nInstance], temps.data(), numUsed * sizeof(block) * 2);

			//processPartialChunk(
			//	nChunk, numUsed, minInstances,
			//	span<InstParams>(instParams.data() + nInstance, minInstances)...,
			//	std::forward<ChunkParams>(chunkParams[nChunk])...);
		}
	}

	void SoftSpokenMalLeakyDotSender::Hasher::processChunk(
		u64 nChunk, u64 numUsed,
		span<std::array<block, 2>> messages,
		SoftSpokenMalLeakyDotSender* parent,
		span<block> inputW)
	{

		parent->mSubVole.hash(inputW);

		assert(inputW.size() >= 128);
		transpose128(inputW.data());

		if (parent->mRandomOt)
		{
			rtcr.useAES(numUsed);
			SoftSpokenShOtSender::xorAndHashMessages(
				numUsed, parent->delta(), (block*)messages.data(), inputW.data(), rtcr);
		}
		else
		{
			parent->xorMessages(numUsed, (block*)messages.data(), inputW.data());
		}
	}


	inline void SoftSpokenMalOtReceiver::Hasher::runBatch(
		span<block> messages,
		span<block> choices,
		SoftSpokenMalOtReceiver* parent,
		block* inputV)
	{
		//setParams(parent, inputV);

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

		//auto inputV = mInputV + nChunk * mParent->chunkSize();
		parent->mSubVole.hash(span<block>(&choices, 1), span<const block>(inputV, parent->vPadded()));
		transpose128(inputV);

		if (parent->mRandomOt == false)
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
		MC_BEGIN(task<>, this, &choices, messages, &prng, &chl, 
			nChunks = u64{},
			messagesFullChunks = u64{},
			numExtra = u64{},
			scratch = (block*)nullptr,
			scratchBacking = AlignedUnVector<block>{},
			extraChoicesU64 = std::array<u64, 4>{},
			sacrificialChoices = u64{},
			bit = u64{},
			bit64 = u64{},
			word = u64{},
			mask = u64{},
			extraChoices = std::array<block, 2>{},
			challenge = block{},
			seed = block{}
		);

		if (!hasBaseOts())
			MC_AWAIT(genBaseOts(prng, chl));

		if (mBlockIdx == 0)
		{
			MC_AWAIT(chl.recv(seed));
			mAesMgr.setSeed(seed);
		}

		MC_AWAIT(mSubVole.expand(chl, prng, mNumThreads));
		
		nChunks = divCeil(messages.size() + 64, 128);
		messagesFullChunks = messages.size() / 128;

		scratch = (block*)messages.data();
		if (vSize() > 128)
		{
			scratchBacking.resize(messagesFullChunks * chunkSize() + paddingSize());
			scratch = scratchBacking.data();
		}

		MC_AWAIT(runBatch(chl, 
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

		MC_AWAIT(runBatch(chl, 
			mExtraV.subspan(0, numExtra * chunkSize()),
			span<block>(extraChoices.data(), numExtra)));

		MC_AWAIT(chl.recv(challenge));
		mSubVole.setChallenge(challenge);

		if(mRandomOt)
			MC_AWAIT(mHasher.recv(chl));

		//void runBatch(
		//	span<block> messages, span<block> choice,
		//	SoftSpokenMalOtReceiver * parent,
		//	block * tt);

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
			mSubVole.hash(
				span<block>(&extraChoices[numExtra - 1], 1),
				mExtraV.subspan(chunkSize() * (numExtra - 1), vPadded()));

		MC_AWAIT(mSubVole.sendResponse(chl));

		MC_END();
	}

	task<> SoftSpokenMalOtReceiver::runBatch(Socket& chl, span<block> messages, span<block> choices)
	{
		MC_BEGIN(task<>, this, &chl, messages, choices,
			numChunks = u64{},
			numInstances = messages.size(),
			nChunk = u64{ 0 },
			nInstance = u64{0},
			numUsed = u64{},
			minInstances = u64{},
			temp = AlignedUnVector<block>()
		);

		minInstances = chunkSize() + paddingSize();
		reserveSendBuffer(std::min<u64>(numChunks, commSize));

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

			if (nChunk % commSize == 0)
			{
				MC_AWAIT(sendBuffer(chl));
				reserveSendBuffer(std::min<u64>(numChunks - nChunk, commSize));
			}
		}

		temp.resize(minInstances * (nInstance < numInstances));
		for (; nInstance < numInstances; ++nChunk, nInstance += chunkSize())
		{
			if (nChunk && nChunk % commSize == 0)
			{
				MC_AWAIT(sendBuffer(chl));
				reserveSendBuffer(std::min<u64>(numChunks - nChunk, commSize));
			}

			numUsed = std::min<u64>(numInstances - nInstance, chunkSize());
			processPartialChunk(
				nChunk, numUsed, 
				messages.subspan(nInstance, numUsed),
				choices[nChunk],
				temp);
		}

		if(hasSendBuffer())
			MC_AWAIT(sendBuffer(chl));

		MC_END();
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
		u64 blockIdx = mBlockIdx++;
		mSubVole.generateChosen(
			blockIdx, mAesMgr.useAES(mSubVole.mVole.mNumVoles),
			span<block>(&choices, 1), messages.subspan(0, vPadded()));
	}

	//template task<> SoftSpokenMalLeakyDotSender::sendImpl(
	//	span<std::array<block, 2>> messages, PRNG& prng, Socket& chl,
	//	SoftSpokenMalLeakyDotSender::Hasher& hasher);
	//template task<> SoftSpokenMalOtReceiver::receiveImpl(
	//	const BitVector& choices, span<block> messages, PRNG& prng, Socket& chl,
	//	SoftSpokenMalOtReceiver::Hasher& hasher);

	//template task<> SoftSpokenMalLeakyDotSender::sendImpl(
	//	span<std::array<block, 2>> messages, PRNG& prng, Socket& chl,
	//	SoftSpokenMalOtSender::Hasher& hasher);
	//template task<> SoftSpokenMalOtReceiver::receiveImpl(
	//	const BitVector& choices, span<block> messages, PRNG& prng, Socket& chl,
	//	SoftSpokenMalOtReceiver::Hasher& hasher);



}

#endif

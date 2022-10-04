#include "SoftSpokenShOtExt.h"
#ifdef ENABLE_SOFTSPOKEN_OT

#include "libOTe/Vole/SoftSpokenOT/SubspaceVoleMaliciousLeaky.h"

namespace osuCrypto
{

	template<typename SubspaceVole>
	const u64 SoftSpokenShOtSender<SubspaceVole>::commSize;
	template<typename SubspaceVole>
	const u64 SoftSpokenShOtReceiver<SubspaceVole>::commSize;


	template<typename SubspaceVole>
	void SoftSpokenShOtSender<SubspaceVole>::setBaseOts(
		span<block> baseRecvOts,
		const BitVector& choices)
	{
		mSubVole.setBaseOts(baseRecvOts, choices);
		mBlockIdx = 0;
	}

	template<typename SubspaceVole>
	void SoftSpokenShOtReceiver<SubspaceVole>::setBaseOts(
		span<std::array<block, 2>> baseSendOts)
	{
		mBlockIdx = 0;
		mSubVole.setBaseOts(baseSendOts);
	}


	template<typename SubspaceVole>
	task<> SoftSpokenShOtSender<SubspaceVole>::send(
		span<std::array<block, 2>> messages, PRNG& prng, Socket& chl)
	{
		MC_BEGIN(task<>, this, messages, &prng, &chl,
			numInstances = u64{},
			numChunks = u64{},
			chunkSize_ = u64{},
			minInstances = u64{},
			nChunk = u64{},
			nInstance = u64{},
			numUsed = u64{},
			temp = AlignedUnVector<std::array<block,2>>(),
			seed = block{}
			);

		if (!hasBaseOts())
			MC_AWAIT(genBaseOts(prng, chl));

		if (mSubVole.hasSeed() == false)
		{
			seed = prng.get<block>();
			mAesMgr.setSeed(seed);
			MC_AWAIT(chl.send(std::move(seed)));
			MC_AWAIT(mSubVole.expand(chl, prng, mNumThreads));
		}



		//MC_AWAIT(runBatch(chl, messages));
		//auto nums = checkSpanLengths(instParams..., chunkParams...);
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

	template<typename SubspaceVole>
	void SoftSpokenShOtSender<SubspaceVole>::processChunk(
		u64 nChunk, u64 numUsed, span<std::array<block, 2>> messages)
	{
		u64 blockIdx = mBlockIdx++;

		block* messagesPtr = (block*)messages.data();

		// Only 1 AES evaluation per VOLE is on a secret seed.
		auto& aes = mAesMgr.useAES(mSubVole.mVole.mNumVoles);
		generateChosen(blockIdx, aes, span<block>(messagesPtr, wPadded()));

		if (mRandomOt)
			xorAndHashMessages(numUsed, delta(), messagesPtr, messagesPtr, aes);
		else
			xorMessages(numUsed, messagesPtr, messagesPtr);
	}



	// Use temporaries to make processChunk work on a partial chunk.
	template<typename SubspaceVole>
	void SoftSpokenShOtSender<SubspaceVole>::processPartialChunk(
		u64 chunkIdx, u64 numUsed,
		span<std::array<block, 2>> messages, 
		span<std::array<block, 2>> temp)
	{
		assert(temp.size() > messages.size());

		memcpy(temp.data(), messages.data(), sizeof(messages[0]) * numUsed);

		processChunk(
			chunkIdx, numUsed,
			temp);

		memcpy(messages.data(), temp.data(), sizeof(messages[0]) * numUsed);
	}



	// messagesOut and messagesIn must either be equal or non-overlapping.
	template<typename SubspaceVole>
	void SoftSpokenShOtSender<SubspaceVole>::xorMessages(
		u64 numUsed, block* messagesOut, const block* messagesIn) const
	{
		block deltaBlock = delta();

		// Loop backwards to avoid tripping over other iterations, as the loop is essentially mapping
		// index i to index 2*i and messagesOut might be messagesIn.
		u64 i = numUsed;
		while (i >= superBlkSize / 2)
		{
			i -= superBlkSize / 2;

			// Temporary array, so I (and the compiler) don't have to worry so much about aliasing.
			block superBlk[superBlkSize];
			for (u64 j = 0; j < superBlkSize / 2; ++j)
			{
				superBlk[2 * j] = messagesIn[i + j];
				superBlk[2 * j + 1] = messagesIn[i + j] ^ deltaBlock;
			}
			std::copy_n(superBlk, superBlkSize, messagesOut + 2 * i);
		}

		// Finish up. The more straightforward while (i--) unfortunately gives a (spurious AFAICT)
		// compiler warning about undefined behavior at iteration 0xfffffffffffffff, so use a for loop.
		u64 remainingIters = i;
		for (u64 j = 0; j < remainingIters; ++j)
		{
			i = remainingIters - j - 1;

			block v = messagesIn[i];
			messagesOut[2 * i] = v;
			messagesOut[2 * i + 1] = v ^ deltaBlock;
		}
	}


	template<typename SubspaceVole>
	task<> SoftSpokenShOtReceiver<SubspaceVole>::receive(
		const BitVector& choices, span<block> messages, PRNG& prng, Socket& chl)
	{
		MC_BEGIN(task<>, this, &choices, messages, &prng, &chl,
			numInstances = u64{},
			numChunks = u64{},
			nChunk = u64{},
			nInstance = u64{},
			minInstances = u64{},
			numUsed = u64{},
			temp = AlignedUnVector<block>(),
			seed = block{}
		);

		if (!hasBaseOts())
			MC_AWAIT(genBaseOts(prng, chl));

		if (mSubVole.hasSeed() == false)
		{
			MC_AWAIT(chl.recv(seed));
			mAesMgr.setSeed(seed);
			MC_AWAIT(mSubVole.expand(chl, prng, mNumThreads));
		}

		numInstances = messages.size();
		numChunks = divCeil(numInstances, chunkSize());
		minInstances = chunkSize() + paddingSize();
		nChunk = 0;
		nInstance = 0;

		reserveSendBuffer(std::min<u64>(numChunks, commSize));
		while (nInstance + minInstances <= numInstances)
		{
			processChunk(
				nChunk, chunkSize(),
				messages.subspan(nInstance, minInstances),
				choices.blocks()[nChunk]);

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
			if (nChunk % commSize == 0)
			{
				if(hasSendBuffer())
					MC_AWAIT(sendBuffer(chl));

				reserveSendBuffer(std::min<u64>(numChunks - nChunk, commSize));
			}

			numUsed = std::min<u64>(numInstances - nInstance, chunkSize());
			processPartialChunk(
				nChunk,
				messages.subspan(nInstance, numUsed),
				choices.blocks()[nChunk],
				temp);		
		}

		if(hasSendBuffer())
			MC_AWAIT(sendBuffer(chl));

		MC_END();
	}

	
	template<typename SubspaceVole>
	void SoftSpokenShOtReceiver<SubspaceVole>::processChunk(
		u64 nChunk, u64 numUsed, span<block> messages, block choices)
	{
		u64 blockIdx = mBlockIdx++;

		// Only 1 AES evaluation per VOLE is on a secret seed.
		generateChosen(blockIdx, mAesMgr.useAES(mSubVole.mVole.mNumVoles), choices, messages);
	}

	template<typename SubspaceVole>
	void SoftSpokenShOtReceiver<SubspaceVole>::processPartialChunk(
		u64 nChunk, 
		span<block> messages, 
		block choice, 
		span<block> temp)
	{
		assert(temp.size() > messages.size());
		memcpy(temp.data(), messages.data(), messages.size() * sizeof(block));

		processChunk(nChunk, messages.size(), temp, choice);

		memcpy(messages.data(), temp.data(), messages.size() * sizeof(block));
	}

	template class SoftSpokenShOtSender<SubspaceVoleReceiver<RepetitionCode>>;
	template class SoftSpokenShOtReceiver<SubspaceVoleSender<RepetitionCode>>;

	template class SoftSpokenShOtSender<SubspaceVoleMaliciousReceiver<RepetitionCode>>;
	template class SoftSpokenShOtReceiver<SubspaceVoleMaliciousSender<RepetitionCode>>;
}

#endif

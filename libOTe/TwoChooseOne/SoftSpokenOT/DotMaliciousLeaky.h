#pragma once
#include <libOTe/config.h>
#ifdef ENABLE_SOFTSPOKEN_OT

#include "DotSemiHonest.h"
#include "libOTe/Vole/SoftSpokenOT/SubspaceVoleMaliciousLeaky.h"

namespace osuCrypto
{
namespace SoftSpokenOT
{

// Uses SubspaceVoleMalicious as a Delta OT.

class DotMaliciousLeakySender :
	public DotSemiHonestSenderWithVole<SubspaceVoleMaliciousReceiver<RepetitionCode>>,
	private ChunkedReceiver<
		DotMaliciousLeakySender,
		std::tuple<block>
	>
{
public:
	using Base = DotSemiHonestSenderWithVole<SubspaceVoleMaliciousReceiver<RepetitionCode>>;

	AlignedBlockPtr extraW;

	struct Hasher :
		public Chunker<
			Hasher,
			std::tuple<std::array<block, 2>>,
			std::tuple<AlignedBlockPtrT<std::array<block, 2>>>
		>
	{
		using ChunkerBase = Chunker<
			Hasher,
			std::tuple<std::array<block, 2>>,
			std::tuple<AlignedBlockPtrT<std::array<block, 2>>>
		>;
		friend ChunkerBase;

		Hasher() : ChunkerBase(this) {}

		size_t chunkSize() const { return 128; }
		size_t paddingSize() const { return 0; }
		TRY_FORCEINLINE void processChunk(
			size_t nChunk, size_t numUsed,
			span<std::array<block, 2>> messages,
			DotMaliciousLeakySender* parent, block* inputW);
	};

	Hasher hasher;

	DotMaliciousLeakySender(size_t fieldBits, size_t numThreads_ = 1) :
		Base(fieldBits, numThreads_),
		ChunkerBase(this)
	{}

	DotMaliciousLeakySender splitBase()
	{
		throw RTE_LOC; // TODO: unimplemented.
	}

	std::unique_ptr<OtExtSender> split() override
	{
		return std::make_unique<DotMaliciousLeakySender>(splitBase());
	}

	virtual void initTemporaryStorage()
	{
		ChunkerBase::initTemporaryStorage();
		extraW = allocAlignedBlockArray(2 * chunkSize() + paddingSize());
		hasher.initTemporaryStorage();
	}

	void send(span<std::array<block, 2>> messages, PRNG& prng, Channel& chl) override;

	// Low level functions.

	TRY_FORCEINLINE void processChunk(
		size_t nChunk, size_t numUsed, span<block> messages);

private:
	// These functions don't keep information around to compute the hashes.
	using Base::generateRandom;
	using Base::generateChosen;

protected:
	using ChunkerBase = ChunkedReceiver<
		DotMaliciousLeakySender,
		std::tuple<block>
	>;
	friend ChunkerBase;
	friend ChunkerBase::Base;

	size_t chunkSize() const { return std::max(roundUpTo(wSize(), 2), (size_t) 2 * 128); }
	size_t paddingSize() const { return std::max(chunkSize(), wPadded()) - chunkSize(); }
};

class DotMaliciousLeakyReceiver :
	public DotSemiHonestReceiverWithVole<SubspaceVoleMaliciousSender<RepetitionCode>>,
	private ChunkedSender<
		DotMaliciousLeakyReceiver,
		std::tuple<block>
	>
{
public:
	using Base = DotSemiHonestReceiverWithVole<SubspaceVoleMaliciousSender<RepetitionCode>>;

	AlignedBlockPtr extraV;

	struct Hasher :
		public Chunker<
			Hasher,
			std::tuple<block>,
			std::tuple<AlignedBlockPtr>
		>
	{
		using ChunkerBase = Chunker<
			Hasher,
			std::tuple<block>,
			std::tuple<AlignedBlockPtr>
		>;
		friend ChunkerBase;

		Hasher() : ChunkerBase(this) {}

		size_t chunkSize() const { return 128; }
		size_t paddingSize() const { return 0; }
		TRY_FORCEINLINE void processChunk(
			size_t nChunk, size_t numUsed,
			span<block> messages, block choices,
			DotMaliciousLeakyReceiver* parent, block* inputV);
	};

	Hasher hasher;

	DotMaliciousLeakyReceiver(size_t fieldBits, size_t numThreads_ = 1) :
		Base(fieldBits, numThreads_),
		ChunkerBase(this)
	{}

	DotMaliciousLeakyReceiver splitBase()
	{
		throw RTE_LOC; // TODO: unimplemented.
	}

	std::unique_ptr<OtExtReceiver> split() override
	{
		return std::make_unique<DotMaliciousLeakyReceiver>(splitBase());
	}

	virtual void initTemporaryStorage()
	{
		ChunkerBase::initTemporaryStorage();
		extraV = allocAlignedBlockArray(2 * chunkSize() + paddingSize());
		hasher.initTemporaryStorage();
	}

	void receive(const BitVector& choices, span<block> messages, PRNG& prng, Channel& chl) override;

	// Low level functions.

	TRY_FORCEINLINE void processChunk(
		size_t nChunk, size_t numUsed, span<block> messages, block choices);

private:
	// These functions don't keep information around to compute the hashes.
	using Base::generateRandom;
	using Base::generateChosen;

protected:
	using ChunkerBase = ChunkedSender<
		DotMaliciousLeakyReceiver,
		std::tuple<block>
	>;
	friend ChunkerBase;
	friend ChunkerBase::Base;

	size_t chunkSize() const { return roundUpTo(vSize(), 2); }
	size_t paddingSize() const { return vPadded() - chunkSize(); }
};

}
}

#endif

#pragma once
#include <libOTe/config.h>
#ifdef ENABLE_SOFTSPOKEN_OT

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/Channel.h>
#include "DotMaliciousLeaky.h"
#include "TwoOneSemiHonest.h"

namespace osuCrypto
{
namespace SoftSpokenOT
{

// Hash DotMaliciousLeaky to get a random OT.

class TwoOneMaliciousSender : public DotMaliciousLeakySender
{
public:
	using Base = DotMaliciousLeakySender;

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

	TwoOneMaliciousSender(size_t fieldBits, size_t numThreads_ = 1) :
		Base(fieldBits, numThreads_) {}

	TwoOneMaliciousSender splitBase()
	{
		throw RTE_LOC; // TODO: unimplemented.
	}

	std::unique_ptr<OtExtSender> split() override
	{
		return std::make_unique<TwoOneMaliciousSender>(splitBase());
	}

	virtual void initTemporaryStorage()
	{
		Base::initTemporaryStorage();
		hasher.initTemporaryStorage();
	}

	void send(span<std::array<block, 2>> messages, PRNG& prng, Channel& chl) override
	{
		sendImpl(messages, prng, chl, hasher);
	}
};

class TwoOneMaliciousReceiver : public DotMaliciousLeakyReceiver
{
public:
	using Base = DotMaliciousLeakyReceiver;

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

	TwoOneMaliciousReceiver(size_t fieldBits, size_t numThreads_ = 1) :
		Base(fieldBits, numThreads_) {}

	TwoOneMaliciousReceiver splitBase()
	{
		throw RTE_LOC; // TODO: unimplemented.
	}

	std::unique_ptr<OtExtReceiver> split() override
	{
		return std::make_unique<TwoOneMaliciousReceiver>(splitBase());
	}

	virtual void initTemporaryStorage()
	{
		Base::initTemporaryStorage();
		hasher.initTemporaryStorage();
	}

	void receive(const BitVector& choices, span<block> messages, PRNG& prng, Channel& chl) override
	{
		receiveImpl(choices, messages, prng, chl, hasher);
	}
};

void TwoOneMaliciousSender::Hasher::processChunk(
	size_t nChunk, size_t numUsed,
	span<std::array<block, 2>> messages,
	DotMaliciousLeakySender* parent, block* inputW)
{
	TwoOneMaliciousSender* parent_ = static_cast<TwoOneMaliciousSender*>(parent);
	inputW += nChunk * parent_->chunkSize();
	parent_->vole->hash(span<const block>(inputW, parent_->wPadded()));

	transpose128(inputW);
	TwoOneSemiHonestSender::xorAndHashMessages(
		numUsed, parent_->delta(), (block*) messages.data(), inputW);
}

void TwoOneMaliciousReceiver::Hasher::processChunk(
	size_t nChunk, size_t numUsed,
	span<block> messages, block choices,
	DotMaliciousLeakyReceiver* parent, block* inputV)
{
	TwoOneMaliciousReceiver* parent_ = static_cast<TwoOneMaliciousReceiver*>(parent);
	inputV += nChunk * parent_->chunkSize();
	parent_->vole->hash(span<block>(&choices, 1), span<const block>(inputV, parent_->vPadded()));

	transpose128(inputV);
	mAesFixedKey.hashBlocks(inputV, numUsed, messages.data());
}

}
}
#endif

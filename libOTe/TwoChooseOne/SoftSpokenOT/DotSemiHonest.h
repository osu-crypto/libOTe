#pragma once
#include <libOTe/config.h>
#ifdef ENABLE_SOFTSPOKEN_OT

#include <boost/optional.hpp>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Network/Channel.h>
#include "libOTe/TwoChooseOne/OTExtInterface.h"
#include "libOTe/Tools/Chunker.h"
#include "libOTe/Tools/RepetitionCode.h"
#include "libOTe/Tools/Tools.h"
#include "libOTe/Vole/SoftSpokenOT/SmallFieldVole.h"
#include "libOTe/Vole/SoftSpokenOT/SubspaceVole.h"

namespace osuCrypto
{
namespace SoftSpokenOT
{

// Builds a Delta OT out of SubspaceVole.

template<typename SubspaceVole = SubspaceVoleReceiver<RepetitionCode>>
class DotSemiHonestSenderWithVole :
	public OtExtSender,
	public TimerAdapter,
	private ChunkedReceiver<
		DotSemiHonestSenderWithVole<SubspaceVole>,
		std::tuple<std::array<block, 2>>,
		std::tuple<AlignedBlockPtrT<std::array<block, 2>>>
	>
{
public:
	// Present once base OTs have finished.
	boost::optional<SubspaceVole> vole;

	size_t fieldBitsThenBlockIdx; // fieldBits before initialization, blockIdx after.
	size_t numThreads;

	DotSemiHonestSenderWithVole(size_t fieldBits, size_t numThreads_ = 1) :
		ChunkerBase(this),
		fieldBitsThenBlockIdx(fieldBits),
		numThreads(numThreads_)
	{
		if (fieldBits == 0)
			throw std::invalid_argument("There is no field with cardinality 2^0 = 1.");
	}

	size_t fieldBits() const
	{
		return vole ? vole->vole.fieldBits : fieldBitsThenBlockIdx;
	}

	size_t wSize() const { return vole->wSize(); }
	size_t wPadded() const { return vole->wPadded(); }

	block delta() const
	{
		block d;
		memcpy(&d, vole.value().vole.delta.data(), sizeof(block));
		return d;
	}

	u64 baseOtCount() const override final
	{
		// Can only use base OTs in groups of fieldBits.
		return roundUpTo(gOtExtBaseOtCount, fieldBits());
	}

	bool hasBaseOts() const override final
	{
		return vole.has_value();
	}

	DotSemiHonestSenderWithVole splitBase()
	{
		throw RTE_LOC; // TODO: unimplemented.
	}

	std::unique_ptr<OtExtSender> split() override
	{
		return std::make_unique<DotSemiHonestSenderWithVole>(splitBase());
	}

	void setBaseOts(
		span<block> baseRecvOts,
		const BitVector& choices,
		PRNG& prng,
		Channel& chl) override;

	virtual void initTemporaryStorage() { ChunkerBase::initTemporaryStorage(); }

	void send(span<std::array<block, 2>> messages, PRNG& prng, Channel& chl) override;

	// Low level functions.

	// Perform 128 random VOLEs (assuming that the messages have been received from the receiver),
	// and output the msg_0s. msg_1 will be msg_0 ^ delta. The output is not bitsliced, i.e. it is
	// transposed from what the SubspaceVole outputs. outW must have length wPadded() (which may be
	// greater than 128). The extra blocks are treated as padding and may be overwritten, either
	// with unneeded extra VOLE bits or padding from the VOLE. Also, outW must be given the
	// alignment of an AlignedBlockArray.
	void generateRandom(size_t blockIdx, span<block> outW)
	{
		vole->generateRandom(blockIdx, outW);
		transpose128(outW.data());
	}

	void generateChosen(size_t blockIdx, span<block> outW)
	{
		vole->generateChosen(blockIdx, outW);
		transpose128(outW.data());
	}

	void xorMessages(size_t numUsed, block* messagesOut, const block* messagesIn) const;

protected:
	using ChunkerBase = ChunkedReceiver<
		DotSemiHonestSenderWithVole<SubspaceVole>,
		std::tuple<std::array<block, 2>>,
		std::tuple<AlignedBlockPtrT<std::array<block, 2>>>
	>;
	friend ChunkerBase;
	friend typename ChunkerBase::Base;

	static const size_t commSize = commStepSize * superBlkSize; // picked to match the other OTs.
	size_t chunkSize() const { return 128; }
	size_t paddingSize() const { return std::max(divCeil(wPadded(), 2), chunkSize()) - chunkSize(); }

	void recvBuffer(Channel& chl, size_t batchSize) { vole->recv(chl, 0, batchSize); }
	TRY_FORCEINLINE void processChunk(
		size_t nChunk, size_t numUsed, span<std::array<block, 2>> messages);
};

template<typename SubspaceVole = SubspaceVoleSender<RepetitionCode>>
class DotSemiHonestReceiverWithVole :
	public OtExtReceiver,
	public TimerAdapter,
	private ChunkedSender<
		DotSemiHonestReceiverWithVole<SubspaceVole>,
		std::tuple<block>,
		std::tuple<AlignedBlockPtr>
	>
{
public:
	// Present once base OTs have finished.
	boost::optional<SubspaceVole> vole;

	size_t fieldBitsThenBlockIdx; // fieldBits before initialization, blockIdx after.
	size_t numThreads;

	DotSemiHonestReceiverWithVole(size_t fieldBits, size_t numThreads_ = 1) :
		ChunkerBase(this),
		fieldBitsThenBlockIdx(fieldBits),
		numThreads(numThreads_)
	{
		if (fieldBits == 0)
			throw std::invalid_argument("There is no field with cardinality 2^0 = 1.");
	}

	size_t fieldBits() const
	{
		return vole ? vole->vole.fieldBits : fieldBitsThenBlockIdx;
	}

	size_t vSize() const { return vole->vSize(); }
	size_t vPadded() const { return vole->vPadded(); }

	u64 baseOtCount() const override final
	{
		// Can only use base OTs in groups of fieldBits.
		return roundUpTo(gOtExtBaseOtCount, fieldBits());
	}

	bool hasBaseOts() const override final
	{
		return vole.has_value();
	}

	DotSemiHonestReceiverWithVole splitBase()
	{
		throw RTE_LOC; // TODO: unimplemented.
	}

	std::unique_ptr<OtExtReceiver> split() override
	{
		return std::make_unique<DotSemiHonestReceiverWithVole>(splitBase());
	}

	void setBaseOts(
		span<std::array<block, 2>> baseSendOts,
		PRNG& prng, Channel& chl) override;

	virtual void initTemporaryStorage() { ChunkerBase::initTemporaryStorage(); }

	void receive(const BitVector& choices, span<block> messages, PRNG& prng, Channel& chl) override;

	// Low level functions.

	// Perform 128 random VOLEs (saving the messages up to send to the sender), and output the
	// choice bits (packed into a 128 bit block) and the chosen messages. The output is not
	// bitsliced, i.e. it is transposed from what the SubspaceVole outputs. outV must have length
	// vPadded() (which may be greater than 128). The extra blocks are treated as padding and may be
	// overwritten. Also, outW must be given the alignment of an AlignedBlockArray.
	void generateRandom(size_t blockIdx, block& randomU, span<block> outV)
	{
		vole->generateRandom(blockIdx, span<block>(&randomU, 1), outV);
		transpose128(outV.data());
	}

	void generateChosen(size_t blockIdx, block chosenU, span<block> outV)
	{
		vole->generateChosen(blockIdx, span<block>(&chosenU, 1), outV);
		transpose128(outV.data());
	}

protected:
	using ChunkerBase = ChunkedSender<
		DotSemiHonestReceiverWithVole<SubspaceVole>,
		std::tuple<block>,
		std::tuple<AlignedBlockPtr>
	>;
	friend ChunkerBase;
	friend typename ChunkerBase::Base;

	static const size_t commSize = commStepSize * superBlkSize; // picked to match the other OTs.
	size_t chunkSize() const { return 128; }
	size_t paddingSize() const { return vPadded() - chunkSize(); }

	void reserveSendBuffer(size_t batchSize) { vole->reserveMessages(0, batchSize); }
	void sendBuffer(Channel& chl) { vole->send(chl); }
	TRY_FORCEINLINE void processChunk(
		size_t nChunk, size_t numUsed, span<block> messages, block chioces);
};

using DotSemiHonestSender = DotSemiHonestSenderWithVole<>;
using DotSemiHonestReceiver = DotSemiHonestReceiverWithVole<>;

}
}
#endif

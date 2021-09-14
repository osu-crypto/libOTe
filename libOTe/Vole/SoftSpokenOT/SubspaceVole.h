#pragma once
#include <libOTe/config.h>
#ifdef ENABLE_SOFTSPOKEN_OT

#include <type_traits>
#include <vector>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/Channel.h>
#include "libOTe/Tools/GenericLinearCode.h"
#include "SmallFieldVole.h"

namespace osuCrypto
{
namespace SoftSpokenOT
{

// Semi-honest security subspace VOLE from Sec. 3.3 and 3.4 of SoftSpokenOT paper. Includes
// functions for both random U and chosen U.

template<typename Code>
struct SubspaceVoleBase
{
	Code mCode;
	static_assert(std::is_base_of<GenericLinearCode<Code>, Code>::value, "Code must be a linear code.");

	SubspaceVoleBase(Code code) : mCode(std::move(code)) {}

	const GenericLinearCode<Code>& code() const { return mCode; }
	GenericLinearCode<Code>& code() { return mCode; }
};

template<typename Code>
class SubspaceVoleSender : public SubspaceVoleBase<Code>
{
public:
	SmallFieldVoleSender vole;

	std::vector<block> messages;

	using Base = SubspaceVoleBase<Code>;
	using Base::code;

	SubspaceVoleSender(SmallFieldVoleSender vole_, Code code_) :
		Base(std::move(code_)),
		vole(std::move(vole_))
	{
		if (vole.numVoles != code().length())
			throw RTE_LOC;
	}

	// Reserve room for blocks blocks in the send buffer.
	void reserveMessages(size_t blocks)
	{
		// The extra added on is because some extra memory is used temporarily in generateRandom and
		// generateChosen.
		messages.reserve(blocks * code().length() + vole.uPadded() - code().codimension());
	}

	// Reserve room for the given numbers of random and chosen u subspace VOLEs.
	void reserveMessages(size_t random, size_t chosen)
	{
		reserveMessages(code().codimension() * random + code().length() * chosen);
	}

	// Extend messages by blocks blocks, and return the span of added blocks.
	span<block> extendMessages(size_t blocks)
	{
		size_t currentEnd = messages.size();
		messages.resize(currentEnd + blocks);
		return gsl::make_span(messages).subspan(currentEnd);
	}

	// Asynchronous
	void send(Channel& chl)
	{
		if (messages.size())
		{
			chl.asyncSend(std::move(messages));
			messages.clear();
		}
	}

	size_t uSize() const { return code().dimension(); }
	size_t vSize() const { return vole.vSize(); }
	size_t uPadded() const { return code().dimension(); }
	size_t vPadded() const { return vole.vPadded(); }

	void generateRandom(size_t blockIdx, span<block> randomU, span<block> outV)
	{
		span<block> tmpU = extendMessages(vole.uPadded());

		vole.generate(blockIdx, tmpU, outV);
		span<block> syndrome = code().decodeInPlace(tmpU.subspan(0, code().length()), randomU);

		// Remove padding
		messages.resize(messages.size() - (vole.uPadded() - syndrome.size()));
	}

	void generateChosen(size_t blockIdx, span<const block> chosenU, span<block> outV)
	{
		span<block> correction = extendMessages(vole.uPadded());

		vole.generate(blockIdx, correction, outV);
		code().encodeXor(chosenU, correction.subspan(0, code().length()));

		// Remove padding
		messages.resize(messages.size() - (vole.uPadded() - code().length()));
	}
};

template<typename Code>
class SubspaceVoleReceiver : public SubspaceVoleBase<Code>
{
public:
	SmallFieldVoleReceiver vole;
	std::unique_ptr<block[]> correctionU;

	std::vector<block> messages;
	size_t readIndex = 0;

	using Base = SubspaceVoleBase<Code>;
	using Base::code;

	SubspaceVoleReceiver(SmallFieldVoleReceiver vole_, Code code_) :
		Base(std::move(code_)),
		vole(std::move(vole_)),
		correctionU(new block[code().length()])
	{
		if (vole.numVoles != code().length())
			throw RTE_LOC;
	}

	// Synchronous.
	void recv(Channel& chl, size_t blocks)
	{
		// To avoid needing a queue, this assumes that all messages are used up before more are
		// read.
#ifndef NDEBUG
		if (messages.size() != readIndex)
			throw RTE_LOC;
#endif
		clear();

		size_t currentEnd = messages.size();
		messages.resize(currentEnd + blocks);
		chl.recv(&messages[currentEnd], blocks);
	}

	// Receive exactly enough blocks for the given numbers of random and chosen u subspace VOLEs.
	void recv(Channel& chl, size_t random, size_t chosen)
	{
		recv(chl, code().codimension() * random + code().length() * chosen);
	}

	// Get a message from the receive buffer that is blocks blocks long.
	span<block> getMessage(size_t blocks)
	{
#ifndef NDEBUG
		if (readIndex + blocks > messages.size())
			throw RTE_LOC;
#endif

		auto output = gsl::make_span(messages).subspan(readIndex, blocks);
		readIndex += blocks;
		return output;
	}

	void clear()
	{
		messages.clear();
		readIndex = 0;
	}

	span<block> correctionUSpan() const
	{
		return span<block>(correctionU.get(), code().length());
	}

	size_t wSize() const { return vole.wSize(); }
	size_t wPadded() const { return vole.wPadded(); }

	void generateRandom(size_t blockIdx, span<block> outW)
	{
		span<block> syndrome = getMessage(code().codimension());

		vole.generate(blockIdx, outW);
		// TODO: at least for some codes this is kind of a nop, so maybe could avoid a copy.
		code().encodeSyndrome(syndrome, correctionUSpan());
		vole.sharedFunctionXor(correctionUSpan(), outW);
	}

	void generateChosen(size_t blockIdx, span<block> outW)
	{
		span<block> correctionU = getMessage(code().length());

		vole.generate(blockIdx, outW);
		vole.sharedFunctionXor(correctionU, outW);
	}

	void sharedFunctionXor(span<const block> u, span<block> product)
	{
		code().encode(u, correctionUSpan());
		vole.sharedFunctionXor(correctionUSpan(), product);
	}
};

}
}
#endif

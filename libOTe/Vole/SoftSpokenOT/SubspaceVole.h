#pragma once
#include <libOTe/config.h>
#ifdef ENABLE_SOFTSPOKEN_OT

#include <type_traits>
#include <boost/container/vector.hpp>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/Channel.h>
#include "libOTe/Tools/GenericLinearCode.h"
#include "SmallFieldVole.h"

namespace osuCrypto
{
namespace SoftSpokenOT
{

// Semi-honest security subspace VOLE from Sec. 3.2 of SoftSpokenOT paper. Includes functions for
// both random U and chosen U.

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

	// Use boost's vector implementation because it allows resizing without initialization.
	boost::container::vector<block> messages;

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
		messages.resize(currentEnd + blocks, boost::container::default_init_t{});
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

	void generateRandom(size_t blockIdx, const AES& aes, span<block> randomU, span<block> outV)
	{
		span<block> tmpU = extendMessages(vole.uPadded());

		vole.generate(blockIdx, aes, tmpU, outV);
		span<block> syndrome = code().decodeInPlace(tmpU.subspan(0, code().length()), randomU);

		// Remove padding
		messages.resize(messages.size() - (vole.uPadded() - syndrome.size()));
	}

	void generateChosen(size_t blockIdx, const AES& aes, span<const block> chosenU, span<block> outV)
	{
		span<block> correction = extendMessages(vole.uPadded());

		vole.generate(blockIdx, aes, correction, outV);
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

	// Use boost's vector implementation because it allows resizing without initialization.
	boost::container::vector<block> messages;
	size_t readIndex = 0;

	using Base = SubspaceVoleBase<Code>;
	using Base::code;

	SubspaceVoleReceiver(SmallFieldVoleReceiver vole_, Code code_) :
		Base(std::move(code_)),
		vole(std::move(vole_)),
		correctionU(new block[uPadded()])
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
		if (!messages.empty() && messages.size() != readIndex + uPadded() - uSize())
			throw RTE_LOC;
#endif
		clear();

		//size_t currentEnd = messages.size();
		messages.resize(blocks + uPadded() - uSize(), boost::container::default_init_t{});
		chl.recv(&messages[0], blocks);
	}

	// Receive exactly enough blocks for the given numbers of random and chosen u subspace VOLEs.
	void recv(Channel& chl, size_t random, size_t chosen)
	{
		recv(chl, code().codimension() * random + code().length() * chosen);
	}

	// Get a message from the receive buffer that is blocks blocks long, with paddedLen extra blocks
	// on the end that should be ignored.
	span<block> getMessage(size_t blocks, size_t paddedLen)
	{
#ifndef NDEBUG
		if (readIndex + paddedLen > messages.size())
			throw RTE_LOC;
#endif

		auto output = gsl::make_span(messages).subspan(readIndex, paddedLen);
		readIndex += blocks;
		return output;
	}

	span<block> getMessage(size_t blocks)
	{
		return getMessage(blocks, blocks);
	}

	void clear()
	{
		messages.clear();
		readIndex = 0;
	}

	span<block> correctionUSpan() const
	{
		return span<block>(correctionU.get(), wPadded());
	}

	size_t wSize() const { return vole.wSize(); }
	size_t wPadded() const { return vole.wPadded(); }
	size_t uSize() const { return vole.uSize(); }
	size_t uPadded() const { return vole.uPadded(); }

	void generateRandom(size_t blockIdx, const AES& aes, span<block> outW)
	{
		span<block> syndrome = getMessage(code().codimension());

		// TODO: at least for some codes this is kind of a nop, so maybe could avoid a copy.
		code().encodeSyndrome(syndrome, correctionUSpan());
		vole.generate(blockIdx, aes, outW, correctionUSpan());
	}

	void generateChosen(size_t blockIdx, const AES& aes, span<block> outW)
	{
		span<block> correctionU = getMessage(uSize(), uPadded());
		vole.generate(blockIdx, aes, outW, correctionU);
	}

	// product must be padded to length wPadded().
	void sharedFunctionXor(span<const block> u, span<block> product)
	{
		code().encode(u, correctionUSpan());
		vole.sharedFunctionXor(correctionUSpan(), product);
	}
};

}
}
#endif

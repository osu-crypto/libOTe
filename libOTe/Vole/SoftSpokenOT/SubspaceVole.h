#pragma once
// © 2022 Lawrence Roy.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#include <libOTe/config.h>
#ifdef ENABLE_SOFTSPOKEN_OT

#include <type_traits>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/Channel.h>
#include "libOTe/Tools/GenericLinearCode.h"
#include "SmallFieldVole.h"

namespace osuCrypto
{

	// Semi-honest security subspace VOLE from Sec. 3.2 of SoftSpokenOT paper. Includes functions for
	// both random U and chosen U.

	template<typename Code>
	struct SubspaceVoleBase
	{
		static constexpr bool mMalicious = false;


		Code mCode;
		static_assert(std::is_base_of<GenericLinearCode<Code>, Code>::value, "Code must be a linear code.");

		SubspaceVoleBase() = default;
		SubspaceVoleBase(SubspaceVoleBase&& o) = default;
		SubspaceVoleBase&operator=(SubspaceVoleBase&& o) = default;

		const GenericLinearCode<Code>& code() const { return mCode; }
		GenericLinearCode<Code>& code() { return mCode; }
	};

	template<typename Code>
	class SubspaceVoleSender : public SubspaceVoleBase<Code>
	{
	public:
		SmallFieldVoleSender mVole;

		AlignedUnVector<block> mMessages;

		using Base = SubspaceVoleBase<Code>;
		using Base::code;

		SubspaceVoleSender() = default;
		SubspaceVoleSender(const SubspaceVoleSender&) = delete;
		SubspaceVoleSender(SubspaceVoleSender && o)
			: Base(std::move(o))
			, mVole(std::move(o.mVole))
		{}

		SubspaceVoleSender& operator=(SubspaceVoleSender&& o)
		{
			*(Base*)this = (std::move(o));
			mVole = (std::move(o.mVole));
			return *this;
		}

		// return a copy of this subspace vole with the same correlated randomness...
		SubspaceVoleSender copy() const
		{
			SubspaceVoleSender r;
			r.mCode = this->mCode;
			assert(r.code().length() == code().length() && r.code().codimension() == code().codimension());
			r.mVole = mVole.copy();
			return r;
		}

		void init(u64 fieldBits, u64 numVoles)
		{
			this->mCode = Code(divCeil(gOtExtBaseOtCount, fieldBits));
			mVole.init(fieldBits, numVoles, false);

			if (mVole.mNumVoles != code().length())
				throw RTE_LOC;
		}


		bool hasSeed() const
		{
			return mVole.hasSeed();
		}

		bool hasBaseOts() const
		{
			return mVole.hasBaseOts();
		}

		void setBaseOts(
			span<std::array<block,2>> baseSendOts)
		{
			mVole.setBaseOts(baseSendOts);
		}

		task<> expand(Socket& chl, PRNG& prng, u64 numThreads)
		{
			return mVole.expand(chl, prng, numThreads);
		}


		u64 fieldBits() const
		{
			return mVole.fieldBits();
		}

		// Reserve room for blocks blocks in the send buffer.
		void reserveMessages(u64 blocks)
		{
			// The extra added on is because some extra memory is used temporarily in generateRandom and
			// generateChosen.
			mMessages.reserve(blocks * code().length() + mVole.uPadded() - code().codimension());
		}

		// Reserve room for the given numbers of random and chosen u subspace VOLEs.
		void reserveMessages(u64 random, u64 chosen)
		{
			reserveMessages(code().codimension() * random + code().length() * chosen);
		}

		// Extend mMessages by blocks blocks, and return the span of added blocks.
		span<block> extendMessages(u64 blocks)
		{
			u64 currentEnd = mMessages.size();
			mMessages.resize(currentEnd + blocks);
			return mMessages.subspan(currentEnd);
		}

		bool hasSendBuffer() const { return mMessages.size(); }

		// Asynchronous
		auto send(Socket& chl)
		{
			return chl.send(std::move(mMessages));
		}

		u64 uSize() const { return code().dimension(); }
		u64 vSize() const { return mVole.vSize(); }
		u64 uPadded() const { return code().dimension(); }
		u64 vPadded() const { return mVole.vPadded(); }

		void generateRandom(u64 blockIdx, const AES& aes, span<block> randomU, span<block> outV)
		{
			span<block> tmpU = extendMessages(mVole.uPadded());

			mVole.generate(blockIdx, aes, tmpU, outV);
			span<block> syndrome = code().decodeInPlace(tmpU.subspan(0, code().length()), randomU);

			// Remove padding
			mMessages.resize(mMessages.size() - (mVole.uPadded() - syndrome.size()));
		}

		void generateChosen(u64 blockIdx, const AES& aes, span<const block> chosenU, span<block> outV)
		{
			span<block> correction = extendMessages(mVole.uPadded());

			mVole.generate(blockIdx, aes, correction, outV);
			code().encodeXor(chosenU, correction.subspan(0, code().length()));

			// Remove padding
			mMessages.resize(mMessages.size() - (mVole.uPadded() - code().length()));
		}
	};

	template<typename Code>
	class SubspaceVoleReceiver : public SubspaceVoleBase<Code>
	{

	public:
		SmallFieldVoleReceiver mVole;
		AlignedUnVector<block> mCorrectionU;

		// Use boost's vector implementation because it allows resizing without initialization.
		AlignedUnVector<block> mMessages;
		u64 mReadIndex = 0;

		using Base = SubspaceVoleBase<Code>;
		using Base::code;

		SubspaceVoleReceiver() = default;

		SubspaceVoleReceiver(SubspaceVoleReceiver&& o)
			: Base(std::move(o))
			, mVole(std::move(o.mVole))
			, mCorrectionU(std::move(o.mCorrectionU))
			, mMessages(std::move(o.mMessages))
			, mReadIndex(std::exchange(o.mReadIndex, 0))
		{}

		SubspaceVoleReceiver& operator=(SubspaceVoleReceiver&& o)
		{
			*(Base*)this = (std::move(o));
			mVole = (std::move(o.mVole));
			mCorrectionU = (std::move(o.mCorrectionU));
			mMessages = (std::move(o.mMessages));
			mReadIndex = (std::exchange(o.mReadIndex, 0));
			return *this;
		}

		// return a copy of this subspace vole with the same correlated randomness...
		SubspaceVoleReceiver copy() const
		{
			SubspaceVoleReceiver r;
			r.mCode = this->mCode;
			r.mVole = mVole.copy();
			return r;
		}

		void init(u64 fieldBits_, u64 numVoles_)
		{
			this->mCode = Code(divCeil(gOtExtBaseOtCount, fieldBits_));
			mVole.init(fieldBits_, numVoles_, false);
			mCorrectionU.resize(uPadded());

			if (mVole.mNumVoles != code().length())
				throw RTE_LOC;
		}

		void setBaseOts(
			span<block> baseRecvOts,
			const BitVector& choices)
		{
			mVole.setBaseOts(baseRecvOts, choices);
		}

		bool hasSeed() const
		{
			return mVole.hasSeed();
		}

		bool hasBaseOts() const
		{
			return mVole.hasBaseOts();
		}

		u64 fieldBits() const
		{
			return mVole.fieldBits();
		}

		const BitVector& getDelta() const { return mVole.getDelta(); }

		task<> expand(Socket& chl, PRNG& prng, u64 numThreads)
		{
			return mVole.expand(chl, prng, numThreads);
		}



		// await the result to perform the receive.
		[[nodiscard]]
		auto recv(Socket& chl, u64 blocks)
		{
			// To avoid needing a queue, this assumes that all mMessages are used up before more are
			// read.
#ifndef NDEBUG
			if (!mMessages.empty() && mMessages.size() != mReadIndex + uPadded() - uSize())
				throw RTE_LOC;
#endif
			clear();

			//u64 currentEnd = mMessages.size();
			mMessages.resize(blocks + uPadded() - uSize());
			return chl.recv(span<block>{ mMessages.data(), blocks });
		}

		// Receive exactly enough blocks for the given numbers of random and chosen u subspace VOLEs.
		// await the result to perform the receive.
		auto recv(Socket& socket, u64 random, u64 chosen)
		{
			return recv(socket, code().codimension() * random + code().length() * chosen);
		}

		// Get a message from the receive buffer that is blocks blocks long, with paddedLen extra blocks
		// on the end that should be ignored.
		span<block> getMessage(u64 blocks, u64 paddedLen)
		{
#ifndef NDEBUG
			if (mReadIndex + paddedLen > mMessages.size())
				throw RTE_LOC;
#endif

			auto output = mMessages.subspan(mReadIndex, paddedLen);
			mReadIndex += blocks;
			return output;
		}

		span<block> getMessage(u64 blocks)
		{
			return getMessage(blocks, blocks);
		}

		void clear()
		{
			mMessages.clear();
			mReadIndex = 0;
		}

		//span<block> correctionUSpan() const
		//{
		//	return span<block>(mCorrectionU.get(), wPadded());
		//}

		u64 wSize() const { return mVole.wSize(); }
		u64 wPadded() const { return mVole.wPadded(); }
		u64 uSize() const { return mVole.uSize(); }
		u64 uPadded() const { return mVole.uPadded(); }

		void generateRandom(u64 blockIdx, const AES& aes, span<block> outW)
		{
			span<block> syndrome = getMessage(code().codimension());

			// TODO: at least for some codes this is kind of a nop, so maybe could avoid a copy.
			code().encodeSyndrome(syndrome, mCorrectionU);
			mVole.generate(blockIdx, aes, outW, mCorrectionU);
		}

		void generateChosen(u64 blockIdx, const AES& aes, span<block> outW)
		{
			span<block> correctionU = getMessage(uSize(), uPadded());
			mVole.generate(blockIdx, aes, outW, correctionU);
		}

		// product must be padded to length wPadded().
		void sharedFunctionXor(span<const block> u, span<block> product)
		{
			code().encode(u, mCorrectionU);
			mVole.sharedFunctionXor<block>(mCorrectionU, product);
		}
	};

}
#endif

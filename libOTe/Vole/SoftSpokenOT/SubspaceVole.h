#pragma once
#include <libOTe/config.h>
#ifdef ENABLE_SOFTSPOKEN_OT

#include <type_traits>
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
			SmallFieldVoleSender mVole;

			AlignedUnVector<block> mMessages;

			using Base = SubspaceVoleBase<Code>;
			using Base::code;

			SubspaceVoleSender(SmallFieldVoleSender vole_, Code code_) :
				Base(std::move(code_)),
				mVole(std::move(vole_))
			{
				if (mVole.mNumVoles != code().length())
					throw RTE_LOC;
			}

			// Reserve room for blocks blocks in the send buffer.
			void reserveMessages(size_t blocks)
			{
				// The extra added on is because some extra memory is used temporarily in generateRandom and
				// generateChosen.
				mMessages.reserve(blocks * code().length() + mVole.uPadded() - code().codimension());
			}

			// Reserve room for the given numbers of random and chosen u subspace VOLEs.
			void reserveMessages(size_t random, size_t chosen)
			{
				reserveMessages(code().codimension() * random + code().length() * chosen);
			}

			// Extend mMessages by blocks blocks, and return the span of added blocks.
			span<block> extendMessages(size_t blocks)
			{
				size_t currentEnd = mMessages.size();
				mMessages.resize(currentEnd + blocks);
				return mMessages.subspan(currentEnd);
			}

			// Asynchronous
			void send(Channel& chl)
			{
				if (mMessages.size())
				{
					chl.asyncSend(std::move(mMessages));
					mMessages.clear();
				}
			}

			size_t uSize() const { return code().dimension(); }
			size_t vSize() const { return mVole.vSize(); }
			size_t uPadded() const { return code().dimension(); }
			size_t vPadded() const { return mVole.vPadded(); }

			void generateRandom(size_t blockIdx, const AES& aes, span<block> randomU, span<block> outV)
			{
				span<block> tmpU = extendMessages(mVole.uPadded());

				mVole.generate(blockIdx, aes, tmpU, outV);
				span<block> syndrome = code().decodeInPlace(tmpU.subspan(0, code().length()), randomU);

				// Remove padding
				mMessages.resize(mMessages.size() - (mVole.uPadded() - syndrome.size()));
			}

			void generateChosen(size_t blockIdx, const AES& aes, span<const block> chosenU, span<block> outV)
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
			size_t mReadIndex = 0;

			using Base = SubspaceVoleBase<Code>;
			using Base::code;

			SubspaceVoleReceiver(SubspaceVoleReceiver&& o)
				: Base(std::move(o))
				, mVole(std::move(o.mVole))
				, mCorrectionU(std::move(o.mCorrectionU))
				, mMessages(std::move(o.mMessages))
				, mReadIndex(std::exchange(o.mReadIndex, 0))
			{}

			SubspaceVoleReceiver(SmallFieldVoleReceiver vole_, Code code_) :
				Base(std::move(code_)),
				mVole(std::move(vole_)),
				mCorrectionU(uPadded())
			{
				if (mVole.mNumVoles != code().length())
					throw RTE_LOC;
			}

			// Synchronous.
			void recv(Channel& chl, size_t blocks)
			{
				// To avoid needing a queue, this assumes that all mMessages are used up before more are
				// read.
#ifndef NDEBUG
				if (!mMessages.empty() && mMessages.size() != mReadIndex + uPadded() - uSize())
					throw RTE_LOC;
#endif
				clear();

				//size_t currentEnd = mMessages.size();
				mMessages.resize(blocks + uPadded() - uSize());
				chl.recv(mMessages.data(), blocks);
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
				if (mReadIndex + paddedLen > mMessages.size())
					throw RTE_LOC;
#endif

				auto output = mMessages.subspan(mReadIndex, paddedLen);
				mReadIndex += blocks;
				return output;
			}

			span<block> getMessage(size_t blocks)
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

			size_t wSize() const { return mVole.wSize(); }
			size_t wPadded() const { return mVole.wPadded(); }
			size_t uSize() const { return mVole.uSize(); }
			size_t uPadded() const { return mVole.uPadded(); }

			void generateRandom(size_t blockIdx, const AES& aes, span<block> outW)
			{
				span<block> syndrome = getMessage(code().codimension());

				// TODO: at least for some codes this is kind of a nop, so maybe could avoid a copy.
				code().encodeSyndrome(syndrome, mCorrectionU);
				mVole.generate(blockIdx, aes, outW, mCorrectionU);
			}

			void generateChosen(size_t blockIdx, const AES& aes, span<block> outW)
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
}
#endif

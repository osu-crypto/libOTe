#pragma once
#include <libOTe/config.h>
#ifdef ENABLE_SOFTSPOKEN_OT

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

		struct AESRekeyManager
		{
			AESStream mAESs;

			// Maximum number of times an AES key can be used on secret data before being replaced. This is
			// a computation / security tradeoff.
			static constexpr size_t maxAESKeyUsage = 1024;
			size_t aesKeyUseCount = 0;

			// Prepare for using AES n times.
			const AES& useAES(size_t n)
			{
				aesKeyUseCount += n;
				if (aesKeyUseCount > maxAESKeyUsage)
				{
					aesKeyUseCount = 0;
					mAESs.next();
				}

				return mAESs.get();
			}
		};

		// Builds a Delta OT out of SubspaceVole.

		template<typename SubspaceVole = SubspaceVoleReceiver<RepetitionCode>>
		class DotSemiHonestSenderWithVole :
			public OtExtSender,
			public TimerAdapter,
			public AESRekeyManager,
			private ChunkedReceiver<
			DotSemiHonestSenderWithVole<SubspaceVole>,
			std::tuple<std::array<block, 2>>,
			std::tuple<AlignedUnVector<std::array<block, 2>>>
			>
		{
		public:
			// Present once base OTs have finished.
			std::unique_ptr<SubspaceVole> mVole;

			size_t mFieldBitsThenBlockIdx; // mFieldBits before initialization, blockIdx after.
			size_t mNumThreads;

			DotSemiHonestSenderWithVole(size_t fieldBits = 2, size_t numThreads_ = 1) :
				ChunkerBase(this),
				mFieldBitsThenBlockIdx(fieldBits),
				mNumThreads(numThreads_)
			{
				if (fieldBits == 0)
					throw std::invalid_argument("There is no field with cardinality 2^0 = 1.");
			}

			size_t fieldBits() const
			{
				return mVole ? mVole->mVole.mFieldBits : mFieldBitsThenBlockIdx;
			}

			size_t wSize() const { return mVole->wSize(); }
			size_t wPadded() const { return mVole->wPadded(); }

			block delta() const
			{
				block d;
				memcpy(&d, mVole->mVole.delta.data(), sizeof(block));
				return d;
			}

			u64 baseOtCount() const override final
			{
				// Can only use base OTs in groups of mFieldBits.
				return roundUpTo(gOtExtBaseOtCount, fieldBits());
			}

			bool hasBaseOts() const override final
			{
				return mVole.get() != nullptr;
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
				Channel& chl) override
			{
				setBaseOts(baseRecvOts, choices, prng, chl, false);
			}

			virtual void initTemporaryStorage() { ChunkerBase::initTemporaryStorage(); }

			void send(span<std::array<block, 2>> messages, PRNG& prng, Channel& chl) override;

			// Low level functions.

			// Perform 128 random VOLEs (assuming that the mMessages have been received from the receiver),
			// and output the msg_0s. msg_1 will be msg_0 ^ delta. The output is not bitsliced, i.e. it is
			// transposed from what the SubspaceVole outputs. outW must have length wPadded() (which may be
			// greater than 128). The extra blocks are treated as padding and may be overwritten, either
			// with unneeded extra VOLE bits or padding from the VOLE. Also, outW must be given the
			// alignment of an AlignedBlockArray.
			void generateRandom(size_t blockIdx, const AES& aes, span<block> outW)
			{
				mVole->generateRandom(blockIdx, aes, outW);
				transpose128(outW.data());
			}

			void generateChosen(size_t blockIdx, const AES& aes, span<block> outW)
			{
				mVole->generateChosen(blockIdx, aes, outW);
				transpose128(outW.data());
			}

			void xorMessages(size_t numUsed, block* messagesOut, const block* messagesIn) const;

		protected:
			void setBaseOts(
				span<block> baseRecvOts,
				const BitVector& choices,
				PRNG& prng,
				Channel& chl,
				bool malicious);

			using ChunkerBase = ChunkedReceiver<
				DotSemiHonestSenderWithVole<SubspaceVole>,
				std::tuple<std::array<block, 2>>,
				std::tuple<AlignedUnVector<std::array<block, 2>>>
			>;
			friend ChunkerBase;
			friend typename ChunkerBase::Base;

			static const size_t commSize = commStepSize * superBlkSize; // picked to match the other OTs.
			size_t chunkSize() const { return 128; }
			size_t paddingSize() const { return std::max(divCeil(wPadded(), 2), chunkSize()) - chunkSize(); }

			void recvBuffer(Channel& chl, size_t batchSize) { mVole->recv(chl, 0, batchSize); }
			OC_FORCEINLINE void processChunk(
				size_t nChunk, size_t numUsed, span<std::array<block, 2>> messages);
		};

		template<typename SubspaceVole = SubspaceVoleSender<RepetitionCode>>
		class DotSemiHonestReceiverWithVole :
			public OtExtReceiver,
			public TimerAdapter,
			public AESRekeyManager,
			private ChunkedSender<
			DotSemiHonestReceiverWithVole<SubspaceVole>,
			std::tuple<block>,
			std::tuple<AlignedUnVector<block>>
			>
		{
		public:
			// Present once base OTs have finished.
			std::unique_ptr<SubspaceVole> mVole;

			size_t mFieldBitsThenBlockIdx; // mFieldBits before initialization, blockIdx after.
			size_t mNumThreads;

			DotSemiHonestReceiverWithVole(size_t fieldBits = 2, size_t numThreads_ = 1) :
				ChunkerBase(this),
				mFieldBitsThenBlockIdx(fieldBits),
				mNumThreads(numThreads_)
			{
				if (fieldBits == 0)
					throw std::invalid_argument("There is no field with cardinality 2^0 = 1.");
			}

			size_t fieldBits() const
			{
				return mVole ? mVole->mVole.mFieldBits : mFieldBitsThenBlockIdx;
			}

			size_t vSize() const { return mVole->vSize(); }
			size_t vPadded() const { return mVole->vPadded(); }

			u64 baseOtCount() const override final
			{
				// Can only use base OTs in groups of mFieldBits.
				return roundUpTo(gOtExtBaseOtCount, fieldBits());
			}

			bool hasBaseOts() const override final
			{
				return mVole.get() != nullptr;
			}

			DotSemiHonestReceiverWithVole splitBase()
			{
				throw RTE_LOC; // TODO: unimplemented.
			}

			std::unique_ptr<OtExtReceiver> split() override
			{
				return std::make_unique<DotSemiHonestReceiverWithVole>(splitBase());
			}

			void setBaseOts(span<std::array<block, 2>> baseSendOts, PRNG& prng, Channel& chl) override
			{
				setBaseOts(baseSendOts, prng, chl, false);
			}

			virtual void initTemporaryStorage() { ChunkerBase::initTemporaryStorage(); }

			void receive(const BitVector& choices, span<block> messages, PRNG& prng, Channel& chl) override;

			// Low level functions.

			// Perform 128 random VOLEs (saving the mMessages up to send to the sender), and output the
			// choice bits (packed into a 128 bit block) and the chosen mMessages. The output is not
			// bitsliced, i.e. it is transposed from what the SubspaceVole outputs. outV must have length
			// vPadded() (which may be greater than 128). The extra blocks are treated as padding and may be
			// overwritten. Also, outW must be given the alignment of an AlignedBlockArray.
			void generateRandom(size_t blockIdx, const AES& aes, block& randomU, span<block> outV)
			{
				mVole->generateRandom(blockIdx, aes, span<block>(&randomU, 1), outV);
				transpose128(outV.data());
			}

			void generateChosen(size_t blockIdx, const AES& aes, block chosenU, span<block> outV)
			{
				mVole->generateChosen(blockIdx, aes, span<block>(&chosenU, 1), outV);
				transpose128(outV.data());
			}

		protected:
			void setBaseOts(
				span<std::array<block, 2>> baseSendOts,
				PRNG& prng, Channel& chl, bool malicious);

			using ChunkerBase = ChunkedSender<
				DotSemiHonestReceiverWithVole<SubspaceVole>,
				std::tuple<block>,
				std::tuple<AlignedUnVector<block>>
			>;
			friend ChunkerBase;
			friend typename ChunkerBase::Base;

			static const size_t commSize = commStepSize * superBlkSize; // picked to match the other OTs.
			size_t chunkSize() const { return 128; }
			size_t paddingSize() const { return vPadded() - chunkSize(); }

			void reserveSendBuffer(size_t batchSize) { mVole->reserveMessages(0, batchSize); }
			void sendBuffer(Channel& chl) { mVole->send(chl); }
			OC_FORCEINLINE void processChunk(
				size_t nChunk, size_t numUsed, span<block> messages, block chioces);
		};

		using DotSemiHonestSender = DotSemiHonestSenderWithVole<>;
		using DotSemiHonestReceiver = DotSemiHonestReceiverWithVole<>;

	}
}
#endif

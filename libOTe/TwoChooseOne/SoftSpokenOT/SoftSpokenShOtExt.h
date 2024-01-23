#pragma once
// © 2022 Lawrence Roy.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#include <libOTe/config.h>
#ifdef ENABLE_SOFTSPOKEN_OT

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Network/Channel.h>
#include "libOTe/TwoChooseOne/OTExtInterface.h"
#include "libOTe/Tools/RepetitionCode.h"
#include "libOTe/Tools/Tools.h"
#include "libOTe/Vole/SoftSpokenOT/SmallFieldVole.h"
#include "libOTe/Vole/SoftSpokenOT/SubspaceVole.h"
//#include "libOTe/Tools/Chunker.h"

namespace osuCrypto
{
		struct AESRekeyManager
		{
			// Maximum number of times an AES key can be used on secret data before being replaced. This is
			// a computation / security tradeoff.
			static constexpr u64 maxAESKeyUsage = 1024;
		private:
			u64 mAesKeyUseCount = ~0ull;
			AESStream mAESs;
		public:

			AESRekeyManager() = default;
			AESRekeyManager(AESRekeyManager&&o) 
				: mAesKeyUseCount(std::exchange(o.mAesKeyUseCount, ~0ull))
				, mAESs(std::move(o.mAESs))
			{}

			AESRekeyManager& operator=(AESRekeyManager&& o)
			{
				mAesKeyUseCount = (std::exchange(o.mAesKeyUseCount, ~0ull));
				mAESs = (std::move(o.mAESs));
				return *this;
			}

			// Prepare for using AES n times.
			const AES& useAES(u64 n)
			{
				if (mAesKeyUseCount == ~0ull)
					throw RTE_LOC;

				mAesKeyUseCount += n;
				if (mAesKeyUseCount > maxAESKeyUsage)
				{
					mAesKeyUseCount = 0;
					mAESs.next();
				}

				return mAESs.get();
			}

			void setSeed(block seed)
			{
				mAESs.setSeed(seed);
				mAesKeyUseCount = 0;
			}

			// returns a new AES stream that is derived from this one.
			// Both can be used independently.
			AESRekeyManager split()
			{
				AESRekeyManager r;
				r.mAESs = mAESs.split();
				r.mAesKeyUseCount = 0;
				return r;
			}

		protected:
			const AES& get()
			{
				return mAESs.get();
			}
		};

		// Builds a Delta OT out of SubspaceVole.
		template<typename SubspaceVole = SubspaceVoleReceiver<RepetitionCode>>
		class SoftSpokenShOtSender :
			public OtExtSender,
			public TimerAdapter
		{
		public:
			SubspaceVole mSubVole;
			u64 mBlockIdx = 0; // mFieldBits before initialization, blockIdx after.
			u64 mNumThreads = 0;
			bool mRandomOt = false;
			AESRekeyManager  mAesMgr;

			SoftSpokenShOtSender()
			{
				init();
			}

			SoftSpokenShOtSender(u64 fieldBits)
			{
				init(fieldBits);
			}

			SoftSpokenShOtSender(SoftSpokenShOtSender&& o)
				: mSubVole(std::move(o.mSubVole))
				, mBlockIdx(std::exchange(o.mBlockIdx, 0))
				, mNumThreads(std::exchange(o.mNumThreads, 0))
				, mRandomOt(std::exchange(o.mRandomOt, 0))
				, mAesMgr(std::move(o.mAesMgr))
			{}

			SoftSpokenShOtSender& operator=(SoftSpokenShOtSender&& o)
			{
				mSubVole = (std::move(o.mSubVole));
				mBlockIdx = (std::exchange(o.mBlockIdx, 0));
				mNumThreads = (std::exchange(o.mNumThreads, 0));
				mRandomOt = (std::exchange(o.mRandomOt, 0));
				mAesMgr = (std::move(o.mAesMgr));
				return *this;
			}


			void init(u64 fieldBits = 2, bool randomOts = true, u64 numThreads = 1)
			{
				if (fieldBits == 0)
					throw std::invalid_argument("There is no field with cardinality 2^0 = 1.");
				mNumThreads = numThreads;
				mBlockIdx = 0;
				auto numSubVoles = divCeil(gOtExtBaseOtCount, fieldBits);
				mSubVole.init(fieldBits, numSubVoles);
				mRandomOt = randomOts;
			}

			u64 fieldBits() const
			{
				return mSubVole.fieldBits();
			}

			u64 wSize() const { return mSubVole.wSize(); }
			u64 wPadded() const { return mSubVole.wPadded(); }

			block delta() const
			{
				return mSubVole.getDelta().template getSpan<block>()[0];
			}

			u64 baseOtCount() const override 
			{
				assert(fieldBits() && "init() must be called first");
				// Can only use base OTs in groups of mFieldBits.
				return roundUpTo(gOtExtBaseOtCount, fieldBits());
			}

			bool hasBaseOts() const override 
			{
				return mSubVole.hasBaseOts();
			}

			SoftSpokenShOtSender splitBase()
			{
				SoftSpokenShOtSender r;
				r.mSubVole = mSubVole.copy();
				r.mRandomOt = mRandomOt;
				r.mNumThreads = mNumThreads;
				r.mAesMgr = mAesMgr.split();
				return r;
			}

			std::unique_ptr<OtExtSender> split() override
			{
				return std::make_unique<SoftSpokenShOtSender>(splitBase());
			}


			void setBaseOts(
				span<block> baseRecvOts,
				const BitVector& choices) override;

			//virtual void initTemporaryStorage() { ChunkerBase::initTemporaryStorage(); }

			task<> send(span<std::array<block, 2>> messages, PRNG& prng, Socket& chl) override;

			// Low level functions.

			// Perform 128 random VOLEs (assuming that the mMessages have been received from the receiver),
			// and output the msg_0s. msg_1 will be msg_0 ^ delta. The output is not bitsliced, i.e. it is
			// transposed from what the SubspaceVole outputs. outW must have length wPadded() (which may be
			// greater than 128). The extra blocks are treated as padding and may be overwritten, either
			// with unneeded extra VOLE bits or padding from the VOLE. Also, outW must be given the
			// alignment of an AlignedBlockArray.
			void generateRandom(u64 blockIdx, const AES& aes, span<block> outW)
			{
				if (mRandomOt)
					throw RTE_LOC; // hashing to random has not been implemented.

				mSubVole.generateRandom(blockIdx, aes, outW);
				transpose128(outW.data());
			}

			void generateChosen(u64 blockIdx, const AES& aes, span<block> outW)
			{
				mSubVole.generateChosen(blockIdx, aes, outW);
				transpose128(outW.data());
			}

			void xorMessages(u64 numUsed, block* messagesOut, const block* messagesIn) const;


			// messagesOut and messagesIn must either be equal or non-overlapping.
			template<typename Enc>
			static OC_FORCEINLINE void xorAndHashMessages(
				u64 numUsed, block deltaBlock, block* messagesOut, const block* messagesIn, Enc& enc)
			{
				// Loop backwards, similarly to DotSemiHonest.
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

					enc.template hashBlocks<superBlkSize>(superBlk, messagesOut + 2 * i);
				}

				// Finish up. The more straightforward while (i--) unfortunately gives a (spurious AFAICT)
				// compiler warning about undefined behavior at iteration 0xfffffffffffffff, so use a for loop.
				u64 remainingIters = i;
				for (u64 j = 0; j < remainingIters; ++j)
				{
					i = remainingIters - j - 1;

					block msgs[2];
					msgs[0] = messagesIn[i];
					msgs[1] = msgs[0] ^ deltaBlock;
					enc.template hashBlocks<2>(msgs, messagesOut + 2 * i);
				}

				// Note: probably need a stronger hash for malicious secure version.
			}

		//protected:


			static constexpr u64 commSize = commStepSize * superBlkSize; // picked to match the other OTs.
			constexpr u64 chunkSize() const { return 128; }
			u64 paddingSize() const { return std::max<u64>(divCeil(wPadded(), 2), chunkSize()) - chunkSize(); }

			auto recvBuffer(Socket& chl, u64 batchSize) { return mSubVole.recv(chl, 0, batchSize); }

			OC_FORCEINLINE void processChunk(
				u64 nChunk, u64 numUsed, span<std::array<block, 2>> messages);

			OC_FORCEINLINE void processPartialChunk(
				u64 chunkIdx, u64 numUsed, 
				span<std::array<block, 2>> messages,
				span<std::array<block, 2>> temp);
		};

		template<typename SubspaceVole = SubspaceVoleSender<RepetitionCode>>
		class SoftSpokenShOtReceiver :
			public OtExtReceiver,
			public TimerAdapter
		{
		public:
			// Present once base OTs have finished.
			SubspaceVole mSubVole;

			u64 mBlockIdx = 0; 
			u64 mNumThreads = 0;
			bool mRandomOt = false;
			AESRekeyManager mAesMgr;


			SoftSpokenShOtReceiver()
			{
				init();
			}

			SoftSpokenShOtReceiver(u64 fieldBits)
			{
				init(fieldBits);
			}
			
			SoftSpokenShOtReceiver(const SoftSpokenShOtReceiver&) = delete;
			SoftSpokenShOtReceiver(SoftSpokenShOtReceiver&& o) 
				: mSubVole(std::move(o.mSubVole))
				, mBlockIdx(std::exchange(o.mBlockIdx, 0))
				, mNumThreads(std::exchange(o.mNumThreads, 0))
				, mRandomOt(std::exchange(o.mRandomOt, false))
				, mAesMgr(std::move(o.mAesMgr))
			{}

			SoftSpokenShOtReceiver& operator=(SoftSpokenShOtReceiver&& o)
			{
				mSubVole = (std::move(o.mSubVole));
				mBlockIdx = (std::exchange(o.mBlockIdx, 0));
				mNumThreads = (std::exchange(o.mNumThreads, 0));
				mRandomOt = (std::exchange(o.mRandomOt, false));
				mAesMgr = (std::move(o.mAesMgr));
				return *this;
			}



			void init(u64 fieldBits = 2, bool randomOts = true, u64 numThreads = 1)
			{
				if (fieldBits == 0)
					throw std::invalid_argument("There is no field with cardinality 2^0 = 1.");

				mBlockIdx = (0);
				mNumThreads = (numThreads);
				auto numSubVoles = divCeil(gOtExtBaseOtCount, fieldBits);
				mSubVole.init(fieldBits, numSubVoles);
				mRandomOt = randomOts;
			}

			u64 fieldBits() const
			{
				return mSubVole.fieldBits();
			}

			u64 vSize() const { return mSubVole.vSize(); }
			u64 vPadded() const { return mSubVole.vPadded(); }

			u64 baseOtCount() const override 
			{
				assert(fieldBits() && "init() must be called first");
				// Can only use base OTs in groups of mFieldBits.
				return roundUpTo(gOtExtBaseOtCount, fieldBits());
			}

			bool hasBaseOts() const override 
			{
				return mSubVole.hasBaseOts();
			}

			SoftSpokenShOtReceiver splitBase()
			{
				SoftSpokenShOtReceiver r;
				r.mSubVole = mSubVole.copy();
				r.mRandomOt = mRandomOt;
				r.mNumThreads = mNumThreads;
				r.mAesMgr = mAesMgr.split();
				return r;
			}

			std::unique_ptr<OtExtReceiver> split() override
			{
				//throw RTE_LOC; // TODO: unimplemented.
				return std::make_unique<SoftSpokenShOtReceiver>(splitBase());
			}

			void setBaseOts(
				span<std::array<block, 2>> baseSendOts) override;


			task<> receive(const BitVector& choices, span<block> messages, PRNG& prng, Socket& chl) override;

			// Low level functions.

			// Perform 128 random VOLEs (saving the mMessages up to send to the sender), and output the
			// choice bits (packed into a 128 bit block) and the chosen mMessages. The output is not
			// bitsliced, i.e. it is transposed from what the SubspaceVole outputs. outV must have length
			// vPadded() (which may be greater than 128). The extra blocks are treated as padding and may be
			// overwritten. Also, outW must be given the alignment of an AlignedBlockArray.
			void generateRandom(u64 blockIdx, const AES& aes, block& randomU, span<block> outV)
			{
				mSubVole.generateRandom(blockIdx, aes, span<block>(&randomU, 1), outV);
				transpose128(outV.data());
				if(mRandomOt)
					aes.hashBlocks(outV.data(), 128, outV.data());
			}

			void generateChosen(u64 blockIdx, const AES& aes, block chosenU, span<block> outV)
			{
				mSubVole.generateChosen(blockIdx, aes, span<block>(&chosenU, 1), outV);
				transpose128(outV.data());

				if(mRandomOt) 
					aes.hashBlocks(outV.data(), 128, outV.data());

			}




			static const u64 commSize = commStepSize * superBlkSize; // picked to match the other OTs.
			u64 chunkSize() const { return 128; }
			u64 paddingSize() const { return vPadded() - chunkSize(); }

			void reserveSendBuffer(u64 batchSize) { mSubVole.reserveMessages(0, batchSize); }
			auto sendBuffer(Socket& chl) { return mSubVole.send(chl); }

			bool hasSendBuffer() const { return mSubVole.hasSendBuffer(); }

			OC_FORCEINLINE void processChunk(
				u64 nChunk, u64 numUsed, span<block> messages, block chioces);

			void processPartialChunk(
				u64 nChunk,
				span<block> messages,
				block choice,
				span<block> temp);
		};


	//using SoftSpokenShOtSender = SoftSpokenShOtSender<>;
	//using SoftSpokenShOtReceiver = SoftSpokenShOtReceiverWithVole<>;
}
#endif

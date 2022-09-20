#pragma once
// © 2022 Lawrence Roy.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#include <libOTe/config.h>
#ifdef ENABLE_SOFTSPOKEN_OT

#include "SoftSpokenShOtExt.h"
#include "libOTe/Vole/SoftSpokenOT/SubspaceVoleMaliciousLeaky.h"
#include <cryptoTools/Common/Aligned.h>
namespace osuCrypto
{

	// Uses SubspaceVoleMalicious as a Delta OT.

	template<u64 blocksPerTweak>
	struct TwoOneRTCR : AESRekeyManager
	{
		block hashKeys[64];

		static constexpr std::uint32_t mod = 0b10000111;

		static block mul2(block x)
		{
			block wordsRotated = x.shuffle_epi32<0b10010011>();
			block mask(std::array<u32, 4>{mod, 1, 1, 1});
			block output = x.slli_epi32<1>();
			output ^= wordsRotated.srai_epi32<31>() & mask;
			return output;
		}

		u64 tweak = 0;
		block tweakMul = block(0ull);

		TwoOneRTCR() = default;
		TwoOneRTCR(block hashKey, block seed)
		{
			setKey(hashKey, seed);
		}

		void setKey(block hashKey, block seed)
		{
			mAESs.setSeed(seed);
			hashKeys[0] = hashKey;
			for (u64 i = 0; i < 63; ++i)
				hashKeys[i + 1] = mul2(hashKeys[i]);

			// Now hashKeys[i] = 2**i * hashKey

			for (u64 i = 0; i < 63; ++i)
				hashKeys[i + 1] ^= hashKeys[i];

			// Now hashKeys[i] = 2**i * hashKey + 2**(i - 1) * hashKey + ... + hashKey.
		}

		template<u64 numBlocks>
		void hashBlocks(const block* plaintext, block* ciphertext)
		{
			static_assert(numBlocks % blocksPerTweak == 0, "can't partially use tweak");
			u64 tweakIncrease = numBlocks / blocksPerTweak;

			// Assumes that tweak is always divisible by tweakIncrease (i.e. that the tweaks are
			// naturally aligned).

			block tmp[numBlocks];
			block tweakMulLocal = tweakMul; // Avoid aliasing concerns.
#ifdef __GNUC__
#pragma GCC unroll 16
#endif
			for (u64 i = 0; i < numBlocks / blocksPerTweak; ++i)
			{
				for (u64 j = 0; j < blocksPerTweak; ++j)
				{
					// Go backwards so that it works well with everything else going backwards.
					u64 idx = numBlocks - 1 - (i * blocksPerTweak + j);
					tmp[idx] = tweakMulLocal ^ plaintext[idx];
				}

				if (i < numBlocks / blocksPerTweak - 1)
					tweakMulLocal ^= hashKeys[log2floor(i ^ (i + 1))];
			}

			tweak += tweakIncrease;
			tweakMul = tweakMulLocal ^ hashKeys[log2floor((tweak - 1) ^ tweak)];

			mAESs.get().template hashBlocks<numBlocks>(tmp, ciphertext);
		}
	};


	class SoftSpokenMalLeakyDotSender :
		public SoftSpokenShOtSender<SubspaceVoleMaliciousReceiver<RepetitionCode>>

	{
	public:
		using Base = SoftSpokenShOtSender<SubspaceVoleMaliciousReceiver<RepetitionCode>>;

		AlignedUnVector<block> mExtraW;

		struct Hasher 
		{
			Hasher() {}
			TwoOneRTCR<2> rtcr;
			//macoro::suspend_never send(PRNG& prng, Socket& chl) { return{}; }

			auto send(PRNG& prng, Socket& chl)
			{
				std::array<block, 2> keyAndSeed = prng.get();
				rtcr.setKey(keyAndSeed[0], keyAndSeed[1]);
				return chl.send(std::move(keyAndSeed));
			}

			constexpr inline u64 chunkSize() const { return 128; }

			void runBatch(
				span<std::array<block, 2>> messages, 
				SoftSpokenMalLeakyDotSender* parent, 
				span<block> inputW_);


			OC_FORCEINLINE void processChunk(
				u64 nChunk, u64 numUsed,
				span<std::array<block, 2>> messages,
				SoftSpokenMalLeakyDotSender* parent_, span<block> inputW_);
		};

		Hasher mHasher;

		SoftSpokenMalLeakyDotSender()
		{
		}

		void init(u64 fieldBits = 2, bool randomOt = true, u64 numThreads = 1)
		{
			Base::init(fieldBits, randomOt, numThreads);
			mExtraW.resize(2 * chunkSize() + paddingSize());
		}

		SoftSpokenMalLeakyDotSender splitBase()
		{
			throw RTE_LOC; // TODO: unimplemented.
		}

		std::unique_ptr<OtExtSender> split() override
		{
			throw RTE_LOC; // TODO: unimplemented.
			//return std::make_unique<SoftSpokenMalLeakyDotSender>(splitBase());
		}


		void setBaseOts(
			span<block> baseRecvOts,
			const BitVector& choices) 
		{
			return Base::setBaseOts(baseRecvOts, choices);
		}

		task<> setBaseOts(
			span<block> baseRecvOts,
			const BitVector& choices,
			Socket& chl) override
		{
			return Base::setBaseOts(baseRecvOts, choices, chl);
		}

		task<> send(span<std::array<block, 2>> messages, PRNG& prng, Socket& chl) override;
		// Low level functions.

		//template<typename Hasher1>
		//task<> sendImpl(span<std::array<block, 2>> messages, PRNG& prng, Socket& chl, Hasher1& hasher);

		task<> runBatch(Socket& chl, span<block>);


		OC_FORCEINLINE void processChunk(
			u64 nChunk, u64 numUsed, span<block> messages);


		OC_FORCEINLINE void processPartialChunk(
			u64 nChunk, u64 numUsed,
			span<block> messages,
			span<block> temp);

	private:
		// These functions don't keep information around to compute the hashes.
		using Base::generateRandom;
		using Base::generateChosen;

	protected:
		//using ChunkerBase = ChunkedReceiver<
		//	SoftSpokenMalLeakyDotSender,
		//	std::tuple<block>
		//>;
		//friend ChunkerBase;
		//friend ChunkerBase::Base;

		u64 chunkSize() const { return std::max<u64>(roundUpTo(wSize(), 2), (u64)2 * 128); }
		u64 paddingSize() const { return std::max<u64>(chunkSize(), wPadded()) - chunkSize(); }
	};

	class SoftSpokenMalOtReceiver :
		public SoftSpokenShOtReceiver<SubspaceVoleMaliciousSender<RepetitionCode>>
	{
	public:
		using Base = SoftSpokenShOtReceiver<SubspaceVoleMaliciousSender<RepetitionCode>>;

		AlignedUnVector<block> mExtraV;

		struct Hasher 
		{
			Hasher() {}

			TwoOneRTCR<1> rtcr;

			task<> recv(Socket& chl)
			{
				MC_BEGIN(task<>, this, &chl,
					keyAndSeed = std::array<block, 2>{}
				);
				MC_AWAIT(chl.recv(keyAndSeed));
				rtcr.setKey(keyAndSeed[0], keyAndSeed[1]);
				MC_END();
			}


			constexpr inline u64 chunkSize() const { return 128; }

			void runBatch(
				span<block> messages, span<block> choice,
				SoftSpokenMalOtReceiver* parent, 
				block* inputV);


			OC_FORCEINLINE void processChunk(
				u64 nChunk, u64 numUsed,
				span<block> messages, block choices,
				SoftSpokenMalOtReceiver* parent,
				block* inputV);
		};

		Hasher mHasher;

		SoftSpokenMalOtReceiver()
		{
		}


		void init(u64 fieldBits = 2, bool randomOt = true,  u64 numThreads = 1)
		{
			Base::init(fieldBits, randomOt, numThreads);
			mExtraV.resize(2 * chunkSize() + paddingSize());
		}

		SoftSpokenMalOtReceiver splitBase()
		{
			throw RTE_LOC; // TODO: unimplemented.
		}

		std::unique_ptr<OtExtReceiver> split() override
		{
			throw RTE_LOC; // TODO: unimplemented.
		}

		void setBaseOts(span<std::array<block, 2>> baseSendOts) 
		{
			return Base::setBaseOts(baseSendOts);
		}

		task<> setBaseOts(span<std::array<block, 2>> baseSendOts, PRNG& prng, Socket& chl) override
		{
			return Base::setBaseOts(baseSendOts, prng, chl);
		}


		task<> receive(const BitVector& choices, span<block> messages, PRNG& prng, Socket& chl) override;
		// Low level functions.


		task<> runBatch(Socket& chl, span<block>messages, span<block> choices);


		OC_FORCEINLINE void processPartialChunk(
			u64 nChunk, u64 numUsed,
			span<block> messages, block choice, span<block> temp);

		OC_FORCEINLINE void processChunk(
			u64 nChunk, u64 numUsed, span<block> messages, block choices);

	private:
		// These functions don't keep information around to compute the hashes.
		using Base::generateRandom;
		using Base::generateChosen;

	protected:


		u64 chunkSize() const { return roundUpTo(vSize(), 2); }
		u64 paddingSize() const { return vPadded() - chunkSize(); }
	};


}

#endif

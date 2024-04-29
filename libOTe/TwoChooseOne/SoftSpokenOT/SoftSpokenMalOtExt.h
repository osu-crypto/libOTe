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

	template<u64 blocksPerTweak>
	struct TwoOneRTCR : AESRekeyManager
	{
		static constexpr std::uint32_t mod = 0b10000111;

		static block mul2(block x)
		{
			block wordsRotated = x.shuffle_epi32<0b10010011>();
			block mask(std::array<u32, 4>{mod, 1, 1, 1});
			block output = x.slli_epi32<1>();
			output ^= wordsRotated.srai_epi32<31>() & mask;
			return output;
		}

		std::array<block,64> mHashKeys;
		u64 mTweak = -1;
		block mTweakMul = block(0ull);

		TwoOneRTCR() = default;
		TwoOneRTCR(TwoOneRTCR&& o)
			: mHashKeys(std::exchange(o.mHashKeys, {}))
			, mTweak(std::exchange(o.mTweak, -1))
			, mTweakMul(std::exchange(o.mTweakMul, block(0ull)))
		{}

		TwoOneRTCR& operator=(TwoOneRTCR&& o)
		{
			mHashKeys = (std::exchange(o.mHashKeys, {}));
			mTweak = (std::exchange(o.mTweak, -1));
			mTweakMul = (std::exchange(o.mTweakMul, block(0ull)));
			return *this;

		}


		TwoOneRTCR(block hashKey, block seed)
		{
			setKey(hashKey, seed);
		}

		void setKey(block hashKey, block seed)
		{
			mTweak = 0;
			mTweakMul = block(0ull);
			AESRekeyManager::setSeed(seed);
			mHashKeys[0] = hashKey;
			for (u64 i = 0; i < 63; ++i)
				mHashKeys[i + 1] = mul2(mHashKeys[i]);

			// Now mHashKeys[i] = 2**i * hashKey

			for (u64 i = 0; i < 63; ++i)
				mHashKeys[i + 1] ^= mHashKeys[i];

			// Now mHashKeys[i] = 2**i * hashKey + 2**(i - 1) * hashKey + ... + hashKey.
		}

		template<u64 numBlocks>
		void hashBlocks(const block* plaintext, block* ciphertext)
		{
			assert(mTweak != (u64)-1);

			static_assert(numBlocks % blocksPerTweak == 0, "can't partially use tweak");
			u64 tweakIncrease = numBlocks / blocksPerTweak;

			// Assumes that mTweak is always divisible by tweakIncrease (i.e. that the tweaks are
			// naturally aligned).

			block tmp[numBlocks];
			block tweakMulLocal = mTweakMul; // Avoid aliasing concerns.
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
					tweakMulLocal ^= mHashKeys[log2floor(i ^ (i + 1))];
			}

			mTweak += tweakIncrease;
			mTweakMul = tweakMulLocal ^ mHashKeys[log2floor((mTweak - 1) ^ mTweak)];


			AESRekeyManager::get().template hashBlocks<numBlocks>(tmp, ciphertext);
		}
	};


	class SoftSpokenMalOtSender :
		public OtExtSender

	{
	public:
		using Base = SoftSpokenShOtSender<SubspaceVoleMaliciousReceiver<RepetitionCode>>;

		struct Hasher 
		{
			Hasher() = default;
			Hasher(Hasher&&) = default;
			Hasher&operator=(Hasher&&) = default;

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
				SoftSpokenMalOtSender* parent, 
				span<block> inputW_);


			OC_FORCEINLINE void processChunk(
				u64 nChunk, u64 numUsed,
				span<std::array<block, 2>> messages,
				SoftSpokenMalOtSender* parent_, span<block> inputW_);
		};

		Base mBase;
		AlignedUnVector<block> mExtraW;

		SoftSpokenMalOtSender() {
			init();
		}

		SoftSpokenMalOtSender(u64 fieldBits)
		{
			init(fieldBits);
		}
		
		SoftSpokenMalOtSender(SoftSpokenMalOtSender&& o) = default;
		SoftSpokenMalOtSender& operator=(SoftSpokenMalOtSender&& o) = default;

		void init(u64 fieldBits = 2, bool randomOt = true, u64 numThreads = 1)
		{
			mBase.init(fieldBits, randomOt, numThreads);
			mExtraW.resize(2 * chunkSize() + paddingSize());
		}

		bool hasBaseOts() const override
		{
			return mBase.hasBaseOts();
		}
		u64 baseOtCount() const override
		{
			return mBase.baseOtCount();
		}

		void setBaseOts(
			span<block> baseRecvOts,
			const BitVector& choices)  override
		{
			mBase.setBaseOts(
				baseRecvOts,
				choices);
		}

		block delta() { return mBase.delta(); }

		SoftSpokenMalOtSender splitBase()
		{
			SoftSpokenMalOtSender r;
			r.mBase = mBase.splitBase();
			r.mExtraW.resize(mExtraW.size());
			return r;
		}

		std::unique_ptr<OtExtSender> split() override
		{
			return std::make_unique<SoftSpokenMalOtSender>(splitBase());
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

	protected:

		u64 chunkSize() const { return std::max<u64>(roundUpTo(mBase.wSize(), 2), (u64)2 * 128); }
		u64 paddingSize() const { return std::max<u64>(chunkSize(), mBase.wPadded()) - chunkSize(); }
	};

	class SoftSpokenMalOtReceiver :
		public OtExtReceiver
	{
	public:
		using Base = SoftSpokenShOtReceiver<SubspaceVoleMaliciousSender<RepetitionCode>>;

		struct Hasher 
		{
			Hasher() {}
			Hasher(Hasher&& o) 
				: rtcr(std::move(o.rtcr))
			{}

			Hasher& operator=(Hasher&& o)
			{
				rtcr = (std::move(o.rtcr));
				return *this;
			}

			TwoOneRTCR<1> rtcr;

			task<> recv(Socket& chl)
			{
				auto keyAndSeed = std::array<block, 2>{};
				co_await chl.recv(keyAndSeed);
				rtcr.setKey(keyAndSeed[0], keyAndSeed[1]);
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

		Base mBase;
		AlignedUnVector<block> mExtraV;

		SoftSpokenMalOtReceiver()
		{
			init();
		}

		SoftSpokenMalOtReceiver(u64 fieldBits)
		{
			init(fieldBits);
		}


		SoftSpokenMalOtReceiver(SoftSpokenMalOtReceiver&& o) 
			:mBase(std::move(o.mBase))
			,mExtraV(std::move(o.mExtraV))
		{}

		SoftSpokenMalOtReceiver& operator=(SoftSpokenMalOtReceiver&& o)
		{
			mBase = (std::move(o.mBase));
			mExtraV = (std::move(o.mExtraV));
			return *this;
		}

		void init(u64 fieldBits = 2, bool randomOt = true,  u64 numThreads = 1)
		{
			mBase.init(fieldBits, randomOt, numThreads);
			mExtraV.resize(2 * chunkSize() + paddingSize());
		}

		bool hasBaseOts() const override
		{
			return mBase.hasBaseOts();
		}
		u64 baseOtCount() const override
		{
			return mBase.baseOtCount();
		}

		void setBaseOts(span<std::array<block, 2>> baseSendOts) override
		{
			return mBase.setBaseOts(baseSendOts);
		}


		SoftSpokenMalOtReceiver splitBase()
		{
			SoftSpokenMalOtReceiver r;
			r.mBase = mBase.splitBase();
			r.mExtraV.resize(mExtraV.size());
			return r;
		}

		std::unique_ptr<OtExtReceiver> split() override
		{
			return std::unique_ptr<OtExtReceiver>(new SoftSpokenMalOtReceiver(splitBase()));
		}

		task<> receive(const BitVector& choices, span<block> messages, PRNG& prng, Socket& chl) override;
		// Low level functions.

		task<> runBatch(Socket& chl, span<block>messages, span<block> choices);


		OC_FORCEINLINE void processPartialChunk(
			u64 nChunk, u64 numUsed,
			span<block> messages, block choice, span<block> temp);

		OC_FORCEINLINE void processChunk(
			u64 nChunk, u64 numUsed, span<block> messages, block choices);

	protected:

		u64 chunkSize() const { return roundUpTo(mBase.vSize(), 2); }
		u64 paddingSize() const { return mBase.vPadded() - chunkSize(); }
	};


	static_assert(std::is_move_constructible<SoftSpokenMalOtReceiver>::value, "");
	static_assert(std::is_move_assignable<SoftSpokenMalOtReceiver>::value, "");

}

#endif

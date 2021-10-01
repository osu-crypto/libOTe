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

template<size_t blocksPerTweak>
struct TwoOneRTCR
{
	block hashKeys[64];
	const AES* aes;

	static constexpr std::uint32_t mod = 0b10000111;

	static block mul2(block x)
	{
		block wordsRotated = _mm_shuffle_epi32(x, 0b10010011);
		block mask(std::array<u32, 4>{mod, 1, 1, 1});
		block output = _mm_slli_epi32(x, 1);
		output ^= block(_mm_srai_epi32(wordsRotated, 31)) & mask;
		return output;
	}

	u64 tweak = 0;
	block tweakMul = block(0ul);

	TwoOneRTCR() = default;
	TwoOneRTCR(block hashKey, const AES* aes_ = &mAesFixedKey) :
		aes(aes_)
	{
		hashKeys[0] = hashKey;
		for (size_t i = 0; i < 63; ++i)
			hashKeys[i + 1] = mul2(hashKeys[i]);

		// Now hashKeys[i] = 2**i * hashKey

		for (size_t i = 0; i < 63; ++i)
			hashKeys[i + 1] ^= hashKeys[i];

		// Now hashKeys[i] = 2**i * hashKey + 2**(i - 1) * hashKey + ... + hashKey.
	}

	template<size_t numBlocks>
	void hashBlocks(const block* plaintext, block* ciphertext)
	{
		static_assert(numBlocks % blocksPerTweak == 0, "can't partially use tweak");
		u64 tweakIncrease = numBlocks / blocksPerTweak;

		// Assumes that tweak is always divisible by tweakIncrease (i.e. that the tweaks are
		// naturally aligned).

		block tmp[numBlocks];
		#ifdef __GNUC__
		#pragma GCC unroll 16
		#endif
		for (size_t i = 0; i < numBlocks / blocksPerTweak; ++i)
		{
			for (size_t j = 0; j < blocksPerTweak; ++j)
			{
				// Go backwards so that it works well with everything else going backwards.
				size_t idx = numBlocks - 1 - (i * blocksPerTweak + j);
				tmp[idx] = tweakMul ^ plaintext[idx];
			}

			if (i < numBlocks / blocksPerTweak - 1)
				tweakMul ^= hashKeys[log2floor(i ^ (i + 1))];
		}

		tweak += tweakIncrease;
		tweakMul ^= hashKeys[log2floor((tweak - 1) ^ tweak)];

		aes->hashBlocks<numBlocks>(tmp, ciphertext);
	}
};

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

		TwoOneRTCR<2> rtcr;

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
		block hashKey = prng.get<block>();
		hasher.rtcr = TwoOneRTCR<2>(hashKey, &mAesFixedKey);
		sendImpl(messages, prng, chl, hasher);
		chl.asyncSend(hashKey);
	}
};

class TwoOneMaliciousReceiver : public DotMaliciousLeakyReceiver
{
public:
	using Base = DotMaliciousLeakyReceiver;

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

	void receive(const BitVector& choices, span<block> messages, PRNG& prng, Channel& chl) override
	{
		Base::receive(choices, messages, prng, chl);

		block hashKey;
		chl.recv(&hashKey, 1);
		TwoOneRTCR<1> rtcr(hashKey, &mAesFixedKey);

		size_t i;
		for (i = 0; i + 128 <= (size_t) messages.size(); i += 128)
		{
			for (size_t j = 0; j < 128; j += superBlkSize)
			{
				size_t idx = i + 128 - superBlkSize - j; // Go backwards to match the sender.
				rtcr.hashBlocks<superBlkSize>(messages.data() + idx, messages.data() + idx);
			}
		}

		// Finish up
		size_t remaining = messages.size() - i;
		for (i = 0; i + superBlkSize <= remaining; i += superBlkSize)
		{
			size_t idx = messages.size() - superBlkSize - i;
			rtcr.hashBlocks<superBlkSize>(messages.data() + idx, messages.data() + idx);
		}

		// Other side hashes in blocks of superBlkSize / 2.
		if (i + superBlkSize / 2 <= remaining)
		{
			size_t idx = messages.size() - (superBlkSize / 2) - i;
			rtcr.hashBlocks<superBlkSize / 2>(messages.data() + idx, messages.data() + idx);
			i += superBlkSize / 2;
		}

		for (; i < remaining; ++i)
		{
			size_t idx = messages.size() - 1 - i;
			rtcr.hashBlocks<1>(messages.data() + idx, messages.data() + idx);
		}
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
		numUsed, parent_->delta(), (block*) messages.data(), inputW, rtcr);
}

}
}
#endif

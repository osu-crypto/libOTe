#pragma once

#include "cryptoTools/Crypto/AES.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "coproto/Socket/Socket.h"
#include <optional>

namespace osuCrypto::details
{
	// One parent producing two children consumes one counter position.
	// Own this object in aligned storage, or in a non-inlined non-coroutine
	// helper. In particular, do not put AES scratch in a coroutine frame.
	class DpfTreeHash
	{
		::osuCrypto::AES mOuter;
		::osuCrypto::AES mAes;
		u64 mChunk = ~u64(0);

	public:
		static constexpr u64 Interval = 1024;
		u64 mCounter = 0;

		explicit DpfTreeHash(block seed) : mOuter(seed) {}

		const ::osuCrypto::AES& at(u64 counter)
		{
			const auto chunk = counter / Interval;
			if (chunk != mChunk)
			{
				mAes.setKey(mOuter.ecbEncBlock(block(chunk, 0x445046545245454bull)));
				mChunk = chunk;
			}
			return mAes;
		}

		u64 remaining() const { return Interval - mCounter % Interval; }

#if defined(_MSC_VER)
		__declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
		__attribute__((noinline))
#endif
		void children(block seed, block* output)
		{
			const auto& aes = at(mCounter++);
			output[0] = aes.hashBlock(seed);
			output[1] = aes.hashBlock(seed ^ OneBlock);
		}

		// Dense traversal reserves one padded-domain counter range per tree.
		// Levels occupy [2^level, 2^(level+1)); slots 0 and 1 are unused.
		// This keeps eight-node packets aligned, even across tree boundaries.
		static u64 denseStart(u64 tree, u64 depth, u64 level)
		{
			return (tree << depth) + (u64(1) << level);
		}

		// Convert a logical path prefix to the eight-subtree physical order.
		static u64 physicalIndex(u64 prefix, u64 level)
		{
			if (level < 3) return prefix;
			const auto width = u64(1) << (level - 3);
			return (prefix % width) * 8 + prefix / width;
		}
	};

#if defined(_MSC_VER)
	__declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
	__attribute__((noinline))
#endif
	inline block dpfTreeRoot(block seed, u64 purpose)
	{
		return ::osuCrypto::AES(seed).ecbEncBlock(block(purpose, 0x494e5445524e414cull));
	}

	// An enclosing protocol can supply its already-agreed public coins once.
	// Standalone calls agree fresh coins. Neither branch uses secret path bits.
	// Both parties must supply the same seed, or both must leave it unset.
	inline macoro::task<block> takeDpfTreeSeed(
		std::optional<block>& supplied, PRNG& prng, coproto::Socket& socket)
	{
		if (supplied)
		{
			const auto seed = *supplied;
			supplied.reset();
			co_return seed;
		}
		const auto local = prng.get<block>();
		block remote;
		co_await socket.send(coproto::copy(local));
		co_await socket.recv(remote);
		co_return local ^ remote;
	}
}

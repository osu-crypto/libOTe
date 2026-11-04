#include "BadMasMuk.h"

#ifdef ENABLE_BMM

#include "libOTe/Tools/Coproto.h"

#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Crypto/Edwards25519/Curve25519Backend.h>
#include <cryptoTools/Crypto/RandomOracle.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <stdexcept>
#include <vector>

#ifdef _MSC_VER
#define LIBOTE_NOINLINE __declspec(noinline)
#else
#define LIBOTE_NOINLINE __attribute__((noinline))
#endif

namespace osuCrypto
{
	namespace
	{
		using Edwards25519::Backend::Point;
		using Edwards25519::Backend::Point8;
		using Edwards25519::Backend::Scalar;
		using Edwards25519::Backend::FixedPointTable;

		constexpr u64 lanes = Edwards25519::Backend::lanes;
		constexpr u64 pointSize = Edwards25519::Backend::encodedSize;

		// Byte length of the c / chat strings and of the H_i outputs (lambda in
		// the paper). See the header for the security discussion.
		constexpr u64 tagSize = 16;
		static_assert(tagSize <= RandomOracle::MaxHashSize, "tag exceeds Blake2b output");
		using Tag = std::array<u8, tagSize>;

		// Receiver wire format per OT: r || c0 || c1.
		constexpr u64 otMsgSize = pointSize + 2 * tagSize;

		// Hhat_i(chat) is hashed as the message (i || chat).
		constexpr u64 hhatMsgSize = 1 + tagSize;

		constexpr u64 step = 16;
		// Bump the version whenever tagSize or the wire format changes so
		// mismatched builds cannot agree on keys.
		constexpr char hhatDomain[] = "libOTe-BMM22-v1-Hhat";
		constexpr char hDomain[] = "libOTe-BMM22-v1-Htag";
		constexpr char kdfDomain[] = "libOTe-BMM22-v1-KDF";

		using BatchEncoding = std::array<u8, lanes * pointSize>;
		using HhatBatch = std::array<u8, lanes * hhatMsgSize>;

		Scalar randomScalar(PRNG& prng)
		{
			std::array<u8, pointSize> bytes;
			prng.get(bytes.data(), bytes.size());
			return Scalar(bytes.data());
		}

		// out = mask ^ H_i(r, c), where H_i : G x {0,1}^lambda -> {0,1}^lambda.
		void xorHashTag(u8* out, const u8* mask, u8 branch, const u8* r, const u8* c)
		{
			RandomOracle hash(tagSize);
			hash.Update(hDomain, sizeof(hDomain) - 1);
			hash.Update(&branch, 1);
			hash.Update(r, pointSize);
			hash.Update(c, tagSize);
			Tag h;
			hash.Final(h.data());
			for (u64 k = 0; k != tagSize; ++k)
				out[k] = mask[k] ^ h[k];
		}

		void deriveKey(
			block& output,
			const u8 point[pointSize],
			u64 otIndex,
			u8 branch)
		{
			std::array<u8, sizeof(u64)> indexBytes;
			for (u64 i = 0; i != indexBytes.size(); ++i)
				indexBytes[i] = static_cast<u8>(otIndex >> (8 * i));

			RandomOracle hash(sizeof(block));
			hash.Update(kdfDomain, sizeof(kdfDomain) - 1);
			hash.Update(indexBytes.data(), indexBytes.size());
			hash.Update(&branch, 1);
			hash.Update(point, pointSize);
			hash.Final(output);
		}

		Point8 hashHhat(const HhatBatch& msgs)
		{
			return Point8::hashToCurveElligator2(
				msgs.data(), hhatMsgSize,
				reinterpret_cast<const u8*>(hhatDomain), sizeof(hhatDomain) - 1);
		}

		BatchEncoding neutralBatchEncoding()
		{
			std::array<u8, pointSize> neutral;
			Point{}.toBytes(neutral.data());
			BatchEncoding batch;
			for (u64 lane = 0; lane != lanes; ++lane)
				std::memcpy(batch.data() + lane * pointSize,
					neutral.data(), neutral.size());
			return batch;
		}

		// Point8 is over-aligned by the vector backends. Keep it out of
		// coroutine frames by doing all point arithmetic in noinline helpers.
		//
		// Fills `out` (lanes * otMsgSize bytes, lane-major) with the receiver
		// messages and `secretKeys` with x for each lane.
		LIBOTE_NOINLINE void makeReceiverBatch(
			PRNG& prng,
			const std::array<u8, lanes>& choice,
			std::array<Scalar, lanes>& secretKeys,
			u8* out)
		{
			// chat_b and c_b for each lane.
			std::array<std::array<Tag, 2>, lanes> rand;
			prng.get(rand.data(), rand.size());
			for (u64 lane = 0; lane != lanes; ++lane)
				secretKeys[lane] = randomScalar(prng);

			HhatBatch hhatMsgs;
			for (u64 lane = 0; lane != lanes; ++lane)
			{
				auto* m = hhatMsgs.data() + lane * hhatMsgSize;
				m[0] = choice[lane];
				std::memcpy(m + 1, rand[lane][0].data(), tagSize);
			}

			// r = x * G - Hhat_b(chat_b)
			const auto r = Point8::mulGenerator(secretKeys) - hashHhat(hhatMsgs);
			BatchEncoding rEncoded;
			r.toBytes(rEncoded.data());

			for (u64 lane = 0; lane != lanes; ++lane)
			{
				const auto b = choice[lane];
				const auto* rBytes = rEncoded.data() + lane * pointSize;
				const auto& chat = rand[lane][0];
				const auto& cb = rand[lane][1];

				auto* dst = out + lane * otMsgSize;
				std::memcpy(dst, rBytes, pointSize);
				std::memcpy(dst + pointSize + b * tagSize, cb.data(), tagSize);
				// c_{1-b} = chat_b ^ H_b(r, c_b)
				xorHashTag(dst + pointSize + (b ^ 1) * tagSize,
					chat.data(), b, rBytes, cb.data());
			}
		}

		LIBOTE_NOINLINE BatchEncoding makeReceiverSharedBatch(
			const FixedPointTable& senderTable,
			const std::array<Scalar, lanes>& scalars)
		{
			BatchEncoding encoded;
			senderTable.mul(scalars).toBytes(encoded.data());
			return encoded;
		}

		struct SenderBatch
		{
			BatchEncoding shared0;
			BatchEncoding shared1;
		};

		// `rEncoded` holds the lanes' r values; `hhat0` / `hhat1` hold the
		// recomputed (i || chat_i) messages.
		LIBOTE_NOINLINE SenderBatch makeSenderBatch(
			const BatchEncoding& rEncoded,
			const HhatBatch& hhat0,
			const HhatBatch& hhat1,
			const Scalar& secretKey)
		{
			Point8 r;
			if (!r.fromBytes(rEncoded.data()))
				throw std::runtime_error(
					"BadMasMuk received an invalid receiver point");

			const auto pk0 = r + hashHhat(hhat0);
			const auto pk1 = r + hashHhat(hhat1);

			SenderBatch output;
			pk0.clearCofactor().mul(secretKey).toBytes(output.shared0.data());
			pk1.clearCofactor().mul(secretKey).toBytes(output.shared1.data());
			return output;
		}
	}

	task<> BadMasMuk::receive(
		const BitVector& choices,
		span<block> messages,
		PRNG& prng,
		Socket& chl)
	{
		MACORO_TRY{
		Edwards25519::Backend::init();
		if (messages.size() != choices.size())
			throw std::invalid_argument(
				"BadMasMuk receiver choices and messages have different sizes");

		const auto n = static_cast<u64>(choices.size());
		auto buff = std::vector<u8>{};
		auto secretKeys = std::vector<Scalar>(n);
		// Rounded up to a full batch so makeReceiverBatch can write all lanes.
		auto laneBuff = std::vector<u8>(lanes * otMsgSize);

		for (u64 i = 0; i < n;)
		{
			const auto curStep = std::min<u64>(n - i, step);
			buff.resize(otMsgSize * curStep);

			for (u64 batch = 0; batch < curStep; batch += lanes)
			{
				const auto active = std::min<u64>(lanes, curStep - batch);
				std::array<u8, lanes> choice{};
				for (u64 lane = 0; lane != active; ++lane)
					choice[lane] = static_cast<u8>(choices[i + batch + lane]);

				std::array<Scalar, lanes> keys;
				makeReceiverBatch(prng, choice, keys, laneBuff.data());

				for (u64 lane = 0; lane != active; ++lane)
					secretKeys[i + batch + lane] = keys[lane];
				std::memcpy(buff.data() + batch * otMsgSize,
					laneBuff.data(), active * otMsgSize);
			}

			i += curStep;
			co_await chl.send(std::move(buff));
		}

		buff.resize(pointSize);
		co_await chl.recv(buff);
		Edwards25519::Backend::init();
		Point senderPoint;
		if (!senderPoint.fromBytes(buff.data()))
			throw std::runtime_error(
				"BadMasMuk received an invalid sender point");
		senderPoint = senderPoint.clearCofactor();
		const FixedPointTable senderTable(senderPoint);

		for (u64 i = 0; i < n; i += lanes)
		{
			const auto active = std::min<u64>(lanes, n - i);
			std::array<Scalar, lanes> scalars;
			for (u64 lane = 0; lane != lanes; ++lane)
				scalars[lane] = secretKeys[i + std::min<u64>(lane, active - 1)];

			const auto shared = makeReceiverSharedBatch(senderTable, scalars);
			for (u64 lane = 0; lane != active; ++lane)
				deriveKey(
					messages[i + lane],
					shared.data() + lane * pointSize,
					i + lane,
					static_cast<u8>(choices[i + lane]));
		}

		} MACORO_CATCH(eptr) {
			co_await chl.close();
			std::rethrow_exception(eptr);
		}
	}

	task<> BadMasMuk::send(
		span<std::array<block, 2>> messages,
		PRNG& prng,
		Socket& chl)
	{
		MACORO_TRY{
		Edwards25519::Backend::init();
		const auto n = static_cast<u64>(messages.size());
		const auto secretKey = randomScalar(prng);

		auto buff = std::vector<u8>(pointSize);
		Point::mulGenerator(secretKey).toBytes(buff.data());
		co_await chl.send(std::move(buff));

		const auto neutral = neutralBatchEncoding();
		for (u64 i = 0; i < n;)
		{
			const auto curStep = std::min<u64>(n - i, step);
			buff.resize(otMsgSize * curStep);
			co_await chl.recv(buff);
			Edwards25519::Backend::init();

			for (u64 batch = 0; batch < curStep; batch += lanes)
			{
				const auto active = std::min<u64>(lanes, curStep - batch);
				auto rEncoded = neutral;
				HhatBatch hhat0{}, hhat1{};
				for (u64 lane = 0; lane != lanes; ++lane)
				{
					hhat0[lane * hhatMsgSize] = 0;
					hhat1[lane * hhatMsgSize] = 1;
				}

				for (u64 lane = 0; lane != active; ++lane)
				{
					const auto* msg = buff.data() + (batch + lane) * otMsgSize;
					const auto* rBytes = msg;
					const auto* c0 = msg + pointSize;
					const auto* c1 = c0 + tagSize;
					std::memcpy(rEncoded.data() + lane * pointSize, rBytes, pointSize);

					// chat_0 = c_1 ^ H_0(r, c_0), chat_1 = c_0 ^ H_1(r, c_1)
					xorHashTag(hhat0.data() + lane * hhatMsgSize + 1, c1, 0, rBytes, c0);
					xorHashTag(hhat1.data() + lane * hhatMsgSize + 1, c0, 1, rBytes, c1);
				}

				const auto shared = makeSenderBatch(rEncoded, hhat0, hhat1, secretKey);

				for (u64 lane = 0; lane != active; ++lane)
				{
					const auto ot = i + batch + lane;
					deriveKey(messages[ot][0],
						shared.shared0.data() + lane * pointSize, ot, 0);
					deriveKey(messages[ot][1],
						shared.shared1.data() + lane * pointSize, ot, 1);
				}
			}
			i += curStep;
		}

		} MACORO_CATCH(eptr) {
			co_await chl.close();
			std::rethrow_exception(eptr);
		}
	}
}
#endif

#undef LIBOTE_NOINLINE

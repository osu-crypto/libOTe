#include "MasnyRindal.h"

#ifdef ENABLE_MR

#include "libOTe/Tools/Coproto.h"

#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Crypto/Edwards25519/Edwards25519.h>
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
		using Edwards25519::Point;
		using Edwards25519::Point8;
		using Edwards25519::Scalar;

		constexpr u64 step = 16;
		constexpr char hashDomain[] = "libOTe-MasnyRindal-v1";
		constexpr char kdfDomain[] = "libOTe-MasnyRindal-v1-KDF";
		using BatchEncoding =
			std::array<u8, Edwards25519::lanes * Edwards25519::encodedSize>;

		Scalar randomScalar(PRNG& prng)
		{
			std::array<u8, Edwards25519::encodedSize> bytes;
			prng.get(bytes.data(), bytes.size());
			return Scalar(bytes.data());
		}

		// Edwards25519 has cofactor 8. Clear it explicitly whenever a point
		// enters through the protocol wire so torsion cannot affect the key.
		Point clearCofactor(Point point) noexcept
		{
			point = point.doubled();
			point = point.doubled();
			return point.doubled();
		}

		Point8 clearCofactor(Point8 points) noexcept
		{
			points = points.doubled();
			points = points.doubled();
			return points.doubled();
		}

		void deriveKey(
			block& output,
			const u8 point[Edwards25519::encodedSize],
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
			hash.Update(point, Edwards25519::encodedSize);
			hash.Final(output);
		}

		std::array<u8, Edwards25519::lanes * Edwards25519::encodedSize>
		neutralBatchEncoding()
		{
			std::array<u8, Edwards25519::encodedSize> neutral;
			Point{}.toBytes(neutral.data());

			std::array<u8, Edwards25519::lanes * Edwards25519::encodedSize> batch;
			for (u64 lane = 0; lane != Edwards25519::lanes; ++lane)
				std::memcpy(
					batch.data() + lane * Edwards25519::encodedSize,
					neutral.data(), neutral.size());
			return batch;
		}

		struct ReceiverBatch
		{
			std::array<Scalar, Edwards25519::lanes> choiceScalars;
			BatchEncoding notEncoded;
			BatchEncoding choiceEncoded;
		};

		// Point8 is 32-byte aligned in the assembly backend. Keep it out of
		// coroutine frames, whose allocation is not guaranteed to preserve that
		// alignment on every compiler, by placing each batch on a normal stack.
		LIBOTE_NOINLINE ReceiverBatch makeReceiverBatch(PRNG& prng)
		{
			ReceiverBatch output;
			std::array<Scalar, Edwards25519::lanes> notScalars;
			for (u64 lane = 0; lane != Edwards25519::lanes; ++lane)
			{
				notScalars[lane] = randomScalar(prng);
				output.choiceScalars[lane] = randomScalar(prng);
			}

			const auto notPoints = Point8::mulGenerator(notScalars);
			notPoints.toBytes(output.notEncoded.data());
			const auto hashed = Point8::hashToCurveElligator2(
				output.notEncoded.data(), Edwards25519::encodedSize,
				reinterpret_cast<const u8*>(hashDomain), sizeof(hashDomain) - 1);
			const auto choicePoints =
				Point8::mulGenerator(output.choiceScalars) - hashed;
			choicePoints.toBytes(output.choiceEncoded.data());
			return output;
		}

		LIBOTE_NOINLINE BatchEncoding makeReceiverSharedBatch(
			const Point& senderPoint,
			const std::array<Scalar, Edwards25519::lanes>& scalars)
		{
			BatchEncoding encoded;
			Point8::broadcast(senderPoint).mul(scalars).toBytes(encoded.data());
			return encoded;
		}

		struct SenderBatch
		{
			BatchEncoding sharedEncoded0;
			BatchEncoding sharedEncoded1;
		};

		LIBOTE_NOINLINE SenderBatch makeSenderBatch(
			const BatchEncoding& encoded0,
			const BatchEncoding& encoded1,
			const Scalar& secretKey)
		{
			Point8 points0, points1;
			if (!points0.fromBytes(encoded0.data()) ||
				!points1.fromBytes(encoded1.data()))
				throw std::runtime_error(
					"MasnyRindal received an invalid receiver point");

			const auto hash0 = Point8::hashToCurveElligator2(
				encoded1.data(), Edwards25519::encodedSize,
				reinterpret_cast<const u8*>(hashDomain), sizeof(hashDomain) - 1);
			const auto hash1 = Point8::hashToCurveElligator2(
				encoded0.data(), Edwards25519::encodedSize,
				reinterpret_cast<const u8*>(hashDomain), sizeof(hashDomain) - 1);
			const auto shared0 = clearCofactor(points0 + hash0).mul(secretKey);
			const auto shared1 = clearCofactor(points1 + hash1).mul(secretKey);

			SenderBatch output;
			shared0.toBytes(output.sharedEncoded0.data());
			shared1.toBytes(output.sharedEncoded1.data());
			return output;
		}
	}

	task<> MasnyRindal::receive(
		const BitVector& choices,
		span<block> messages,
		PRNG& prng,
		Socket& chl)
	{
		MACORO_TRY{
		if (messages.size() != choices.size())
			throw std::invalid_argument(
				"MasnyRindal receiver choices and messages have different sizes");

		const auto n = static_cast<u64>(choices.size());
		auto buff = std::vector<u8>{};
		auto secretKeys = std::vector<Scalar>{};
		secretKeys.reserve(n);

		for (u64 i = 0; i < n;)
		{
			const auto curStep = std::min<u64>(n - i, step);
			buff.resize(Edwards25519::encodedSize * 2 * curStep);

			for (u64 batch = 0; batch < curStep; batch += Edwards25519::lanes)
			{
				const auto active = std::min<u64>(
					Edwards25519::lanes, curStep - batch);
				const auto points = makeReceiverBatch(prng);
				for (u64 lane = 0; lane != active; ++lane)
					secretKeys.emplace_back(points.choiceScalars[lane]);

				for (u64 lane = 0; lane != active; ++lane)
				{
					const auto ot = i + batch + lane;
					const auto choice = static_cast<u64>(choices[ot]);
					auto* pair = buff.data() +
						2 * (batch + lane) * Edwards25519::encodedSize;
					std::memcpy(
						pair + (choice ^ 1) * Edwards25519::encodedSize,
						points.notEncoded.data() + lane * Edwards25519::encodedSize,
						Edwards25519::encodedSize);
					std::memcpy(
						pair + choice * Edwards25519::encodedSize,
						points.choiceEncoded.data() + lane * Edwards25519::encodedSize,
						Edwards25519::encodedSize);
				}
			}

			i += curStep;
			co_await chl.send(std::move(buff));
		}

		buff.resize(Edwards25519::encodedSize);
		co_await chl.recv(buff);
		Point senderPoint;
		if (!senderPoint.fromBytes(buff.data()))
			throw std::runtime_error("MasnyRindal received an invalid sender point");
		senderPoint = clearCofactor(senderPoint);

		for (u64 i = 0; i < n; i += Edwards25519::lanes)
		{
			const auto active = std::min<u64>(Edwards25519::lanes, n - i);
			std::array<Scalar, Edwards25519::lanes> scalars;
			for (u64 lane = 0; lane != Edwards25519::lanes; ++lane)
				scalars[lane] = secretKeys[i + std::min<u64>(lane, active - 1)];

			const auto sharedEncoded =
				makeReceiverSharedBatch(senderPoint, scalars);
			for (u64 lane = 0; lane != active; ++lane)
				deriveKey(
					messages[i + lane],
					sharedEncoded.data() + lane * Edwards25519::encodedSize,
					i + lane,
					static_cast<u8>(choices[i + lane]));
		}

		} MACORO_CATCH(eptr) {
			co_await chl.close();
			std::rethrow_exception(eptr);
		}
	}

	task<> MasnyRindal::send(
		span<std::array<block, 2>> messages,
		PRNG& prng,
		Socket& chl)
	{
		MACORO_TRY{
		const auto n = static_cast<u64>(messages.size());
		const auto secretKey = randomScalar(prng);

		auto buff = std::vector<u8>(Edwards25519::encodedSize);
		Point::mulGenerator(secretKey).toBytes(buff.data());
		co_await chl.send(std::move(buff));

		const auto neutral = neutralBatchEncoding();
		for (u64 i = 0; i < n;)
		{
			const auto curStep = std::min<u64>(n - i, step);
			buff.resize(Edwards25519::encodedSize * 2 * curStep);
			co_await chl.recv(buff);

			for (u64 batch = 0; batch < curStep; batch += Edwards25519::lanes)
			{
				const auto active = std::min<u64>(
					Edwards25519::lanes, curStep - batch);
				auto encoded0 = neutral;
				auto encoded1 = neutral;
				for (u64 lane = 0; lane != active; ++lane)
				{
					const auto* pair = buff.data() +
						2 * (batch + lane) * Edwards25519::encodedSize;
					std::memcpy(
						encoded0.data() + lane * Edwards25519::encodedSize,
						pair, Edwards25519::encodedSize);
					std::memcpy(
						encoded1.data() + lane * Edwards25519::encodedSize,
						pair + Edwards25519::encodedSize,
						Edwards25519::encodedSize);
				}

				const auto shared =
					makeSenderBatch(encoded0, encoded1, secretKey);

				for (u64 lane = 0; lane != active; ++lane)
				{
					const auto ot = i + batch + lane;
					deriveKey(
						messages[ot][0],
						shared.sharedEncoded0.data() + lane * Edwards25519::encodedSize,
						ot, 0);
					deriveKey(
						messages[ot][1],
						shared.sharedEncoded1.data() + lane * Edwards25519::encodedSize,
						ot, 1);
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

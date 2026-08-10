#include "SimplestOT.h"

#ifdef ENABLE_SIMPLESTOT

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
		using Edwards25519::Backend::FixedPointTable;
		using Edwards25519::Backend::Point;
		using Edwards25519::Backend::Point8;
		using Edwards25519::Backend::Scalar;

		constexpr u64 lanes = Edwards25519::Backend::lanes;
		constexpr u64 pointSize = Edwards25519::Backend::encodedSize;
		constexpr char kdfDomain[] = "libOTe-SimplestOT-v1";
		using BatchEncoding = std::array<u8, lanes * pointSize>;

		Scalar randomScalar(PRNG& prng)
		{
			std::array<u8, pointSize> bytes;
			prng.get(bytes.data(), bytes.size());
			return Scalar(bytes.data());
		}

		void deriveKey(
			block& output,
			const u8 senderPoint[pointSize],
			const u8 receiverPoint[pointSize],
			const u8 sharedPoint[pointSize],
			u64 otIndex,
			u8 branch,
			const block* seed)
		{
			std::array<u8, sizeof(u64)> indexBytes;
			for (u64 i = 0; i != indexBytes.size(); ++i)
				indexBytes[i] = static_cast<u8>(otIndex >> (8 * i));

			RandomOracle hash(sizeof(block));
			hash.Update(kdfDomain, sizeof(kdfDomain) - 1);
			hash.Update(senderPoint, pointSize);
			hash.Update(receiverPoint, pointSize);
			hash.Update(sharedPoint, pointSize);
			hash.Update(indexBytes.data(), indexBytes.size());
			hash.Update(&branch, 1);
			if (seed)
				hash.Update(*seed);
			hash.Final(output);
		}

		struct ReceiverBatch
		{
			BatchEncoding selected;
			BatchEncoding clearedSelected;
			BatchEncoding shared;
		};

		// Point8 can be over-aligned. Keep it out of coroutine frames by doing
		// each complete batch in a normal, non-inlined stack frame.
		LIBOTE_NOINLINE ReceiverBatch makeReceiverBatch(
			const Point& senderPoint,
			const FixedPointTable& senderTable,
			const std::array<u8, lanes>& choices,
			PRNG& prng)
		{
			std::array<Scalar, lanes> scalars;
			for (auto& scalar : scalars)
				scalar = randomScalar(prng);

			auto selected = Point8::mulGenerator(scalars);
			const auto choiceOne =
				Point8::broadcast(senderPoint) - selected;
			selected.conditionalMove(choiceOne, choices);

			ReceiverBatch output;
			selected.toBytes(output.selected.data());
			selected.clearCofactor().toBytes(output.clearedSelected.data());
			senderTable.mul(scalars).toBytes(output.shared.data());
			return output;
		}

		struct SenderBatch
		{
			BatchEncoding clearedResponse;
			BatchEncoding shared0;
			BatchEncoding shared1;
		};

		LIBOTE_NOINLINE SenderBatch makeSenderBatch(
			const BatchEncoding& encoded,
			const Scalar& secretKey,
			const Point& correctionPoint)
		{
			Point8 points;
			if (!points.fromBytes(encoded.data()))
				throw std::runtime_error(
					"SimplestOT received an invalid receiver point");

			points = points.clearCofactor();
			const auto shared0 = points.mul(secretKey);
			const auto shared1 =
				Point8::broadcast(correctionPoint) - shared0;
			SenderBatch output;
			points.toBytes(output.clearedResponse.data());
			shared0.toBytes(output.shared0.data());
			shared1.toBytes(output.shared1.data());
			return output;
		}

		BatchEncoding neutralBatchEncoding()
		{
			std::array<u8, pointSize> neutral;
			Point{}.toBytes(neutral.data());
			BatchEncoding batch;
			for (u64 lane = 0; lane != lanes; ++lane)
				std::memcpy(batch.data() + lane * pointSize,
					neutral.data(), pointSize);
			return batch;
		}
	}

	task<> SimplestOT::receive(
		const BitVector& choices,
		span<block> messages,
		PRNG& prng,
		Socket& chl)
	{
		MACORO_TRY{
		Edwards25519::Backend::init();
		if (messages.size() != choices.size())
			throw std::invalid_argument(
				"SimplestOT receiver choices and messages have different sizes");
		const auto n = static_cast<u64>(messages.size());
		if (n == 0)
			co_return;

		auto setup = std::vector<u8>(
			pointSize + RandomOracle::HashSize * mUniformOTs);
		co_await chl.recv(setup);

		Point senderPoint;
		if (!senderPoint.fromBytes(setup.data()))
			throw std::runtime_error(
				"SimplestOT received an invalid sender point");
		senderPoint = senderPoint.clearCofactor();
		if (senderPoint.isNeutral())
			throw std::runtime_error(
				"SimplestOT received a small-order sender point");
		std::array<u8, pointSize> senderPointEncoding;
		senderPoint.toBytes(senderPointEncoding.data());
		const FixedPointTable senderTable(senderPoint);

		std::array<u8, RandomOracle::HashSize> commitment;
		if (mUniformOTs)
			std::memcpy(commitment.data(), setup.data() + pointSize,
				commitment.size());

		auto selected = std::vector<u8>(n * pointSize);
		auto clearedSelected = std::vector<u8>(n * pointSize);
		auto shared = std::vector<u8>(n * pointSize);
		for (u64 base = 0; base < n; base += lanes)
		{
			const auto active = std::min<u64>(lanes, n - base);
			std::array<u8, lanes> batchChoices{};
			for (u64 lane = 0; lane != active; ++lane)
				batchChoices[lane] = choices[base + lane];
			const auto batch = makeReceiverBatch(
				senderPoint, senderTable, batchChoices, prng);
			std::memcpy(selected.data() + base * pointSize,
				batch.selected.data(), active * pointSize);
			std::memcpy(clearedSelected.data() + base * pointSize,
				batch.clearedSelected.data(), active * pointSize);
			std::memcpy(shared.data() + base * pointSize,
				batch.shared.data(), active * pointSize);
		}

		co_await chl.send(std::move(selected));

		block seed;
		const block* seedPtr = nullptr;
		if (mUniformOTs)
		{
			co_await chl.recv(seed);
			RandomOracle hash;
			std::array<u8, RandomOracle::HashSize> opening;
			hash.Update(seed);
			hash.Final(opening);
			if (commitment != opening)
				throw std::runtime_error(
					"SimplestOT received a bad seed decommitment");
			seedPtr = &seed;
		}

		for (u64 i = 0; i != n; ++i)
			deriveKey(messages[i], senderPointEncoding.data(),
				clearedSelected.data() + i * pointSize,
				shared.data() + i * pointSize, i,
				static_cast<u8>(choices[i]), seedPtr);

		} MACORO_CATCH(eptr) {
			if (!chl.closed()) co_await chl.close();
			std::rethrow_exception(eptr);
		}
	}

	task<> SimplestOT::send(
		span<std::array<block, 2>> messages,
		PRNG& prng,
		Socket& chl)
	{
		MACORO_TRY{
		Edwards25519::Backend::init();
		const auto n = static_cast<u64>(messages.size());
		if (n == 0)
			co_return;

		const auto secretKey = randomScalar(prng);
		const auto wireSenderPoint = Point::mulGenerator(secretKey);
		auto setup = std::vector<u8>(
			pointSize + RandomOracle::HashSize * mUniformOTs);
		wireSenderPoint.toBytes(setup.data());
		const auto senderPoint = wireSenderPoint.clearCofactor();
		std::array<u8, pointSize> senderPointEncoding;
		senderPoint.toBytes(senderPointEncoding.data());

		block seed;
		const block* seedPtr = nullptr;
		if (mUniformOTs)
		{
			seed = prng.get<block>();
			RandomOracle hash;
			std::array<u8, RandomOracle::HashSize> commitment;
			hash.Update(seed);
			hash.Final(commitment);
			std::memcpy(setup.data() + pointSize,
				commitment.data(), commitment.size());
			seedPtr = &seed;
		}

		const auto correctionPoint =
			senderPoint.mul(secretKey).clearCofactor();
		co_await chl.send(std::move(setup));

		auto received = std::vector<u8>(n * pointSize);
		co_await chl.recv(received);
		if (mUniformOTs)
			co_await chl.send(seed);

		const auto neutral = neutralBatchEncoding();
		for (u64 base = 0; base < n; base += lanes)
		{
			const auto active = std::min<u64>(lanes, n - base);
			auto encoded = neutral;
			std::memcpy(encoded.data(), received.data() + base * pointSize,
				active * pointSize);
			const auto batch = makeSenderBatch(
				encoded, secretKey, correctionPoint);
			for (u64 lane = 0; lane != active; ++lane)
			{
				const auto i = base + lane;
				const auto* response =
					batch.clearedResponse.data() + lane * pointSize;
				deriveKey(messages[i][0], senderPointEncoding.data(),
					response, batch.shared0.data() + lane * pointSize,
					i, 0, seedPtr);
				deriveKey(messages[i][1], senderPointEncoding.data(),
					response, batch.shared1.data() + lane * pointSize,
					i, 1, seedPtr);
			}
		}

		} MACORO_CATCH(eptr) {
			if (!chl.closed()) co_await chl.close();
			std::rethrow_exception(eptr);
		}
	}
}

#undef LIBOTE_NOINLINE

#endif

#pragma once
// © 2020 Lawrence Roy.
// © 2022 Visa.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#include "libOTe/config.h"
#ifdef ENABLE_MRR

#include <algorithm>
#include <array>
#include <cstring>
#include <stdexcept>
#include <type_traits>
#include "libOTe/TwoChooseOne/OTExtInterface.h"
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/RandomOracle.h>

#include "libOTe/Tools/Popf/FeistelRistPopf.h"
#include "libOTe/Tools/Popf/FeistelMulRistPopf.h"

#include "libOTe/Tools/MrrCurve.h"

namespace osuCrypto
{
	namespace details
	{
		namespace mrr
		{
			using BatchEncoding = std::array<u8,
				MrrCurve::lanes * MrrCurve::Point::size>;
			using UniformBatch = std::array<u8,
				MrrCurve::lanes * MrrCurve::Point::fromHashLength>;

			inline BatchEncoding programPoints(
				const std::array<MrrCurve::Number, MrrCurve::lanes>& scalars,
				const UniformBatch& uniform)
			{
				BatchEncoding encoded;
				const auto points = MrrCurve::Point8::mulGenerator(scalars) -
					MrrCurve::Point8::fromUniformBytes(uniform.data());
				points.toBytes(encoded.data());
				return encoded;
			}

			inline BatchEncoding sharedPoints(
				const MrrCurve::Point& point,
				const std::array<MrrCurve::Number, MrrCurve::lanes>& scalars)
			{
				BatchEncoding encoded;
				MrrCurve::Point8::broadcast(point).mul(scalars).toBytes(encoded.data());
				return encoded;
			}

			inline BatchEncoding evaluatePoints(
				const BatchEncoding& encodedPoints,
				const UniformBatch& uniform,
				const MrrCurve::Number& scalar)
			{
				MrrCurve::Point8 points;
				if (!points.fromBytes(encodedPoints.data()))
					throw std::runtime_error("invalid McRosRoy POPF point " LOCATION);
				BatchEncoding result;
				(points + MrrCurve::Point8::fromUniformBytes(uniform.data()))
					.mul(scalar).toBytes(result.data());
				return result;
			}
		}

		// The Popf's PopfFunc must be plain old data, PopfIn must be convertible from an integer, and
		// PopfOut must be a MrrCurve::Point.
		template<typename DSPopf>
		class McRosRoy : public OtReceiver, public OtSender
		{
			using Point = MrrCurve::Point;
			using Number = MrrCurve::Number;

		public:
			typedef DSPopf PopfFactory;

			McRosRoy() = default;
			McRosRoy(const PopfFactory& p) : popfFactory(p) {}
			McRosRoy(PopfFactory&& p) : popfFactory(p) {}

			task<> receive(
				const BitVector& choices,
				span<block> messages,
				PRNG& prng,
				Socket& chl,
				u64 numThreads)
			{
				return receive(choices, messages, prng, chl);
			}

			task<> send(
				span<std::array<block, 2>> messages,
				PRNG& prng,
				Socket& chl,
				u64 numThreads)
			{
				return send(messages, prng, chl);
			}

			task<> receive(
				const BitVector& choices,
				span<block> messages,
				PRNG& prng,
				Socket& chl) override;

			task<> send(
				span<std::array<block, 2>> messages,
				PRNG& prng,
				Socket& chl) override;

			using T = typename PopfFactory::ConstructedPopf::PopfFunc;


			static_assert(
				std::is_standard_layout<T>::value&&
				std::is_trivial<T>::value,
				"Popf function must be Plain Old Data");
			static_assert(std::is_same<typename PopfFactory::ConstructedPopf::PopfOut, Point>::value,
				"Popf must be programmable on elliptic curve points");

		private:
			PopfFactory popfFactory;
		};


	}

	// The McQuoid--Rosulek--Roy OT protocol over Ristretto255
	// with the Feistel Popf impl. See https://eprint.iacr.org/2021/682
	using McRosRoy = details::McRosRoy<DomainSepFeistelRistPopf>;

	// The streamlined McQuoid--Rosulek--Roy OT protocol over Ristretto255
	// with the streamlined Feistel Popf impl. See https://eprint.iacr.org/2021/682
	using McRosRoyMul = details::McRosRoy<DomainSepFeistelMulRistPopf>;


	///////////////////////////////////////////////////////////////////////////////
	/// impl 
	///////////////////////////////////////////////////////////////////////////////

	namespace details
	{


		template<typename DSPopf>
		task<> McRosRoy<DSPopf>::receive(
			const BitVector& choices,
			span<block> messages,
			PRNG& prng,
			Socket& chl)
		{
			MACORO_TRY{

			MrrCurve::init();
			auto A = Point{};
			auto sk = std::vector<Number>{};
			auto buff = std::vector<u8>(Point::size);
			auto sendBuff = std::vector<typename PopfFactory::ConstructedPopf::PopfFunc>{ };
			auto n = choices.size();
			if (n == 0)
				co_return;
			sk.resize(n);
			sendBuff.resize(n);

			for (u64 base = 0; base < n; base += MrrCurve::lanes)
			{
				const auto count = std::min<u64>(MrrCurve::lanes, n - base);
				std::array<Number, MrrCurve::lanes> scalars;
				std::array<u8, MrrCurve::lanes * Point::fromHashLength> uniform{};
				for (u64 lane = 0; lane != MrrCurve::lanes; ++lane)
				{
					scalars[lane].randomize(prng);
					if (lane >= count)
						continue;
					sk[base + lane] = scalars[lane];
					auto factory = popfFactory;
					factory.Update(base + lane);
					auto popf = factory.construct();
					auto& f = sendBuff[base + lane];
					popf.batchProgramBegin(f, choices[base + lane], prng);
					popf.batchHashPoint(f, choices[base + lane],
						uniform.data() + lane * Point::fromHashLength);
				}

				const auto encoded = mrr::programPoints(scalars, uniform);
				for (u64 lane = 0; lane != count; ++lane)
				{
					auto factory = popfFactory;
					factory.Update(base + lane);
					auto popf = factory.construct();
					auto& f = sendBuff[base + lane];
					std::memcpy(f.t, encoded.data() + lane * Point::size, Point::size);
					popf.batchProgramEnd(f, choices[base + lane]);
				}
			}

			co_await chl.send(std::move(sendBuff));

			co_await chl.recv(buff);
			MrrCurve::init();
			if (!MrrCurve::fromBytes(A, buff.data()))
				throw std::runtime_error("invalid McRosRoy sender point " LOCATION);

			for (u64 base = 0; base < n; base += MrrCurve::lanes)
			{
				const auto count = std::min<u64>(MrrCurve::lanes, n - base);
				std::array<Number, MrrCurve::lanes> scalars;
				for (u64 lane = 0; lane != MrrCurve::lanes; ++lane)
					scalars[lane] = sk[base];
				for (u64 lane = 0; lane != count; ++lane)
					scalars[lane] = sk[base + lane];
				const auto encoded = mrr::sharedPoints(A, scalars);
				for (u64 lane = 0; lane != count; ++lane)
				{
					RandomOracle ro(sizeof(block));
					ro.Update(encoded.data() + lane * Point::size, Point::size);
					ro.Update(base + lane);
					ro.Update((bool)choices[base + lane]);
					ro.Final(messages[base + lane]);
				}
			}

			} MACORO_CATCH(eptr) {
				co_await chl.close();
				std::rethrow_exception(eptr);
			}
		}

		template<typename DSPopf>
		task<> McRosRoy<DSPopf>::send(
			span<std::array<block, 2>> msg,
			PRNG& prng,
			Socket& chl)
		{
			MACORO_TRY{

			MrrCurve::init();
			auto A = Point{};
			auto sk = Number{};
			auto buff = std::vector<u8>(Point::size);
			auto recvBuff = std::vector<typename PopfFactory::ConstructedPopf::PopfFunc>{};

			auto n = static_cast<u64>(msg.size());
			if (n == 0)
				co_return;
			sk.randomize(prng);
			A = Point::mulGenerator(sk);

			assert(buff.size() == A.sizeBytes());
			A.toBytes(buff.data());

			co_await chl.send(std::move(buff));

			recvBuff.resize(n);
			co_await chl.recv(recvBuff);
			MrrCurve::init();
			for (u64 base = 0; base < n; base += MrrCurve::lanes)
			{
				const auto count = std::min<u64>(MrrCurve::lanes, n - base);
				for (u8 branch = 0; branch != 2; ++branch)
				{
					mrr::UniformBatch uniform{};
					mrr::BatchEncoding encoded{};
					for (u64 lane = 0; lane != count; ++lane)
					{
						auto factory = popfFactory;
						factory.Update(base + lane);
						auto popf = factory.construct();
						auto f = recvBuff[base + lane];
						popf.batchEvalBegin(f, branch != 0);
						std::memcpy(encoded.data() + lane * Point::size, f.t, Point::size);
						popf.batchHashPoint(f, branch != 0,
							uniform.data() + lane * Point::fromHashLength);
					}
					for (u64 lane = count; lane != MrrCurve::lanes; ++lane)
					{
						std::memcpy(encoded.data() + lane * Point::size,
							encoded.data(), Point::size);
						std::memcpy(uniform.data() + lane * Point::fromHashLength,
							uniform.data(), Point::fromHashLength);
					}
					encoded = mrr::evaluatePoints(encoded, uniform, sk);
					for (u64 lane = 0; lane != count; ++lane)
					{
						RandomOracle ro(sizeof(block));
						ro.Update(encoded.data() + lane * Point::size, Point::size);
						ro.Update(base + lane);
						ro.Update(branch != 0);
						ro.Final(msg[base + lane][branch]);
					}
				}
			}

			} MACORO_CATCH(eptr) {
				co_await chl.close();
				std::rethrow_exception(eptr);
			}
		}
	}
}

#endif

#pragma once
// © 2020 Lawrence Roy.
// © 2022 Visa.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#include "libOTe/config.h"
#ifdef ENABLE_MRR_TWIST

#include <type_traits>
#include "libOTe/TwoChooseOne/OTExtInterface.h"
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/Montgomery25519/Montgomery25519.h>
#include <cryptoTools/Crypto/Rijndael256.h>
#include <cryptoTools/Crypto/RandomOracle.h>

#include "libOTe/Tools/Popf/EKEPopf.h"
#include "libOTe/Tools/Popf/FeistelMulPopf.h"
#include "libOTe/Tools/Popf/FeistelPopf.h"
#include "libOTe/Tools/Popf/MRPopf.h"
#include "libOTe/Tools/Coproto.h"

namespace osuCrypto
{
	namespace details
	{
		// Popf classes should looks something like this:
		/*
		class Popf
		{
		public:
			typedef ... PopfFunc;
			typedef ... PopfIn;
			typedef ... PopfOut;

			PopfOut eval(PopfFunc f, PopfIn x) const;
			PopfFunc program(PopfIn x, PopfOut y, PRNG& prng) const;
			PopfFunc program(PopfIn x, PopfOut y) const; // If program is possible without prng.
		};
		*/

		// A factory to create a Popf from a RO should look something like this:
		/*
		class RODomainSeparatedPopf: public RandomOracle
		{
			using RandomOracle::Final;
			using RandomOracle::outputLength;

		public:
			typedef ... ConstructedPopf;

			ConstructedPopf construct();
		};
		*/

		// The Popf's PopfFunc must be plain old data, PopfIn must be convertible from an integer, and
		// PopfOut must be a Block256.
		template<typename DSPopf>
		class McRosRoyTwist : public OtReceiver, public OtSender
		{
		public:
			typedef DSPopf PopfFactory;

			McRosRoyTwist() = default;
			McRosRoyTwist(const PopfFactory& p) : popfFactory(p) {}
			McRosRoyTwist(PopfFactory&& p) : popfFactory(p) {}

			task<> receive(
				const BitVector& choices,
				span<block> messages,
				PRNG& prng,
				Socket& chl) override;

			task<> send(
				span<std::array<block, 2>> messages,
				PRNG& prng,
				Socket& chl) override;


			static_assert(std::is_trivial<typename PopfFactory::ConstructedPopf::PopfFunc>::value,
				"Popf function must be Plain Old Data");
			static_assert(std::is_same<typename PopfFactory::ConstructedPopf::PopfOut, Block256>::value,
				"Popf must be programmable on 256-bit blocks");

		private:
			PopfFactory popfFactory;

			using Monty25519 = Montgomery25519::Backend::Point;
			using Monty25519x8 = Montgomery25519::Backend::Point8;
			using Scalar25519 = Montgomery25519::Backend::Scalar;

			Monty25519 blockToCurve(Block256 b);
			Block256 curveToBlock(Monty25519 p, PRNG& prng);
		};
	}
	//DomainSepEKEPopf requires SSE
#ifdef ENABLE_SSE
	// The McQuoid Rosulek Roy OT protocol over the main and twisted curve 
	// with the EKE Popf impl. See https://eprint.iacr.org/2021/682
	using McRosRoyTwist = details::McRosRoyTwist<DomainSepEKEPopf>;
#endif

	// The McQuoid Rosulek Roy OT protocol over the main and twisted curve 
	// with the Feistel Popf impl. See https://eprint.iacr.org/2021/682
	using McRosRoyTwistFeistel = details::McRosRoyTwist<DomainSepFeistelPopf>;

	// The McQuoid Rosulek Roy OT protocol over the main and twisted curve 
	// with the streamlined Feistel Popf impl. See https://eprint.iacr.org/2021/682
	using McRosRoyTwistMul = details::McRosRoyTwist<DomainSepFeistelMulPopf>;

	// The McQuoid Rosulek Roy OT protocol over the main and twisted curve 
	// with the Masney Rindal Popf impl. See https://eprint.iacr.org/2021/682
	using McRosRoyTwistMR = details::McRosRoyTwist<DomainSepMRPopf>;






	///////////////////////////////////////////////////////////////////////////////
	/// impl 
	///////////////////////////////////////////////////////////////////////////////


	namespace details
	{

		template<typename DSPopf>
		inline task<> McRosRoyTwist<DSPopf>::receive(const BitVector& choices, span<block> messages, PRNG& prng, Socket& chl)
		{
			MACORO_TRY{
			Montgomery25519::Backend::init();
			auto n = choices.size();
			if (n == 0)
				co_return;
			auto sk = std::vector<Scalar25519>{};
			auto curveChoice = std::vector<u8>{};
			auto A = std::array<Monty25519, 2>{};
			auto aBytes = std::array<u8, 2 * Monty25519::size>{};
			auto sendBuff = std::vector<typename PopfFactory::ConstructedPopf::PopfFunc>{};

			sk.resize(n);
			curveChoice.resize(n);
			sendBuff.resize(n);

			for (u64 base = 0; base < n; base += Montgomery25519::Backend::lanes)
			{
				const auto count = std::min<u64>(
					Montgomery25519::Backend::lanes, n - base);
				std::array<Scalar25519, Montgomery25519::Backend::lanes> scalars;
				std::array<Monty25519, Montgomery25519::Backend::lanes> generators;
				for (u64 lane = 0; lane != count; ++lane)
				{
					curveChoice[base + lane] = prng.getBit();
					scalars[lane].randomize(prng);
					sk[base + lane] = scalars[lane];
					generators[lane] = curveChoice[base + lane] == 0 ?
						Monty25519::wholeGroupGenerator :
						Monty25519::wholeTwistGroupGenerator;
				}
				for (u64 lane = count; lane != Montgomery25519::Backend::lanes; ++lane)
				{
					scalars[lane] = scalars[0];
					generators[lane] = generators[0];
				}
				auto points = Monty25519x8::fromPoints(generators).mul(scalars);
				std::array<u8, Montgomery25519::Backend::lanes * Monty25519::size> encoded;
				points.toBytes(encoded.data());
				for (u64 lane = 0; lane != count; ++lane)
				{
					auto factory = popfFactory;
					factory.Update(base + lane);
					auto popf = factory.construct();
					sendBuff[base + lane] = popf.program(
						choices[base + lane],
						curveToBlock(Monty25519(
							encoded.data() + lane * Monty25519::size), prng),
						prng);
				}
			}

			co_await chl.send(std::move(sendBuff));

			co_await chl.recv(aBytes);
			A[0].fromBytes(aBytes.data());
			A[1].fromBytes(aBytes.data() + Monty25519::size);

			for (u64 base = 0; base < n; base += Montgomery25519::Backend::lanes)
			{
				const auto count = std::min<u64>(
					Montgomery25519::Backend::lanes, n - base);
				std::array<Scalar25519, Montgomery25519::Backend::lanes> scalars;
				std::array<Monty25519, Montgomery25519::Backend::lanes> points;
				for (u64 lane = 0; lane != count; ++lane)
				{
					scalars[lane] = sk[base + lane];
					points[lane] = A[curveChoice[base + lane]];
				}
				for (u64 lane = count; lane != Montgomery25519::Backend::lanes; ++lane)
				{
					scalars[lane] = scalars[0];
					points[lane] = points[0];
				}
				auto shared = Monty25519x8::fromPoints(points).mul(scalars);
				std::array<u8, Montgomery25519::Backend::lanes * Monty25519::size> encoded;
				shared.toBytes(encoded.data());
				for (u64 lane = 0; lane != count; ++lane)
				{
					RandomOracle ro(sizeof(block));
					ro.Update(encoded.data() + lane * Monty25519::size,
						Monty25519::size);
					ro.Update(base + lane);
					ro.Update((bool)choices[base + lane]);
					ro.Final(messages[base + lane]);
				}
			}

			} MACORO_CATCH(eptr) {
				if (!chl.closed()) co_await chl.close();
				std::rethrow_exception(eptr);
			}
		}


		template<typename DSPopf>
		inline task<> McRosRoyTwist<DSPopf>::send(span<std::array<block, 2>> msg, PRNG& prng, Socket& chl)
		{
			MACORO_TRY{

			Montgomery25519::Backend::init();
			auto n = static_cast<u64>(msg.size());
			if (n == 0)
				co_return;
			auto sk = Scalar25519(prng);
			auto recvBuff = std::vector<typename PopfFactory::ConstructedPopf::PopfFunc>{};

			std::array<Monty25519, Montgomery25519::Backend::lanes> generators;
			generators.fill(Monty25519::wholeGroupGenerator);
			generators[1] = Monty25519::wholeTwistGroupGenerator;
			auto setup = Monty25519x8::fromPoints(generators).mul(sk);
			std::array<u8, Montgomery25519::Backend::lanes * Monty25519::size> setupBytes;
			setup.toBytes(setupBytes.data());
			std::array<u8, 2 * Monty25519::size> A;
			std::memcpy(A.data(), setupBytes.data(), Monty25519::size);
			std::memcpy(A.data() + Monty25519::size,
				setupBytes.data() + Monty25519::size, Monty25519::size);

			co_await chl.send(std::move(A));

			recvBuff.resize(n);
			co_await chl.recv(recvBuff);


			for (u64 base = 0; base < n; base += Montgomery25519::Backend::lanes)
			{
				const auto count = std::min<u64>(
					Montgomery25519::Backend::lanes, n - base);
				for (u8 branch = 0; branch != 2; ++branch)
				{
					std::array<u8, Montgomery25519::Backend::lanes * Monty25519::size> encoded;
					for (u64 lane = 0; lane != count; ++lane)
					{
						auto factory = popfFactory;
						factory.Update(base + lane);
						auto popf = factory.construct();
						auto point = popf.eval(recvBuff[base + lane], branch != 0);
						std::memcpy(encoded.data() + lane * Monty25519::size,
							point.data(), Monty25519::size);
					}
					for (u64 lane = count; lane != Montgomery25519::Backend::lanes; ++lane)
						std::memcpy(encoded.data() + lane * Monty25519::size,
							encoded.data(), Monty25519::size);
					Monty25519x8 points;
					points.fromBytes(encoded.data());
					points = points.mul(sk);
					points.toBytes(encoded.data());
					for (u64 lane = 0; lane != count; ++lane)
					{
						RandomOracle ro(sizeof(block));
						ro.Update(encoded.data() + lane * Monty25519::size,
							Monty25519::size);
						ro.Update(base + lane);
						ro.Update(branch != 0);
						ro.Final(msg[base + lane][branch]);
					}
				}
			}

			} MACORO_CATCH(eptr) {
				if (!chl.closed()) co_await chl.close();
				std::rethrow_exception(eptr);
			}
		}

		template<typename DSPopf>
		inline typename McRosRoyTwist<DSPopf>::Monty25519 McRosRoyTwist<DSPopf>::blockToCurve(Block256 b)
		{
			static_assert(Monty25519::size == sizeof(Block256), "");
			return Monty25519(b.data());
		}
		template<typename DSPopf>
		inline Block256 McRosRoyTwist<DSPopf>::curveToBlock(Monty25519 p, PRNG& prng)
		{
			Block256 result;
			p.toBytes(result.data());
			result.data()[Monty25519::size - 1] ^= prng.getBit() << 7;
			static_assert(Monty25519::size == sizeof(Block256), "");
			return result;
		}
	}





}

#endif

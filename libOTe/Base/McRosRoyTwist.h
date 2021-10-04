#pragma once
#include "libOTe/config.h"
#ifdef ENABLE_MRR_TWIST

#include <type_traits>
#include "libOTe/TwoChooseOne/OTExtInterface.h"
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/RCurve.h>
#include <cryptoTools/Crypto/Rijndael256.h>
#include <cryptoTools/Crypto/RandomOracle.h>

#include "libOTe/Tools/Popf/EKEPopf.h"
#include "libOTe/Tools/Popf/FeistelMulPopf.h"
#include "libOTe/Tools/Popf/FeistelPopf.h"
#include "libOTe/Tools/Popf/MRPopf.h"

#include <cryptoTools/Crypto/SodiumCurve.h>
#ifndef ENABLE_SODIUM
static_assert(0, "ENABLE_SODIUM must be defined to build McRosRoyTwist");
#endif
#ifndef SODIUM_MONTGOMERY
static_assert(0, "SODIUM_MONTGOMERY must be defined to build McRosRoyTwist");
#endif

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

			void receive(
				const BitVector& choices,
				span<block> messages,
				PRNG& prng,
				Channel& chl,
				u64 numThreads);

			void send(
				span<std::array<block, 2>> messages,
				PRNG& prng,
				Channel& chl,
				u64 numThreads);

			void receive(
				const BitVector& choices,
				span<block> messages,
				PRNG& prng,
				Channel& chl) override;

			void send(
				span<std::array<block, 2>> messages,
				PRNG& prng,
				Channel& chl) override;

			static_assert(std::is_pod<typename PopfFactory::ConstructedPopf::PopfFunc>::value,
				"Popf function must be Plain Old Data");
			static_assert(std::is_same<typename PopfFactory::ConstructedPopf::PopfOut, Block256>::value,
				"Popf must be programmable on 256-bit blocks");

		private:
			PopfFactory popfFactory;

			using Monty25519 = Sodium::Monty25519;
			using Scalar25519 = Sodium::Scalar25519;

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
		inline void McRosRoyTwist<DSPopf>::receive(const BitVector& choices, span<block> messages, PRNG& prng, Channel& chl, u64 numThreads)
		{
			receive(choices, messages, prng, chl);
		}

		template<typename DSPopf>
		inline void McRosRoyTwist<DSPopf>::send(span<std::array<block, 2>> messages, PRNG& prng, Channel& chl, u64 numThreads)
		{
			send(messages, prng, chl);
		}

		template<typename DSPopf>
		inline void McRosRoyTwist<DSPopf>::receive(const BitVector& choices, span<block> messages, PRNG& prng, Channel& chl)
		{
			u64 n = choices.size();

			std::vector<Scalar25519> sk; sk.reserve(n);
			std::vector<u8> curveChoice; curveChoice.reserve(n);

			Monty25519 A[2];
			auto recvDone = chl.asyncRecv(A, 2);

			std::vector<typename PopfFactory::ConstructedPopf::PopfFunc> sendBuff(n);

			for (u64 i = 0; i < n; ++i)
			{
				auto factory = popfFactory;
				factory.Update(i);
				auto popf = factory.construct();

				curveChoice.emplace_back(prng.getBit());
				sk.emplace_back(prng, false);
				Monty25519 g = (curveChoice[i] == 0) ?
					Monty25519::wholeGroupGenerator : Monty25519::wholeTwistGroupGenerator;
				Monty25519 B = g * sk[i];

				sendBuff[i] = popf.program(choices[i], curveToBlock(B, prng), prng);
			}

			chl.asyncSend(std::move(sendBuff));

			recvDone.wait();

			for (u64 i = 0; i < n; ++i)
			{
				Monty25519 B = A[curveChoice[i]] * sk[i];

				RandomOracle ro(sizeof(block));
				ro.Update(B);
				ro.Update(i);
				ro.Update((bool)choices[i]);
				ro.Final(messages[i]);
			}
		}

		template<typename DSPopf>
		inline void McRosRoyTwist<DSPopf>::send(span<std::array<block, 2>> msg, PRNG& prng, Channel& chl)
		{
			u64 n = static_cast<u64>(msg.size());

			Scalar25519 sk(prng);
			Monty25519 A[2] = {
				Monty25519::wholeGroupGenerator * sk, Monty25519::wholeTwistGroupGenerator * sk };

			chl.asyncSend(A, 2);

			std::vector<typename PopfFactory::ConstructedPopf::PopfFunc> recvBuff(n);
			chl.recv(recvBuff.data(), recvBuff.size());


			Monty25519 Bz, Bo;
			for (u64 i = 0; i < n; ++i)
			{
				auto factory = popfFactory;
				factory.Update(i);
				auto popf = factory.construct();

				Bz = blockToCurve(popf.eval(recvBuff[i], 0));
				Bo = blockToCurve(popf.eval(recvBuff[i], 1));

				// We don't need to check which curve we're on since we use the same secret for both.
				Bz *= sk;
				Bo *= sk;

				RandomOracle ro(sizeof(block));
				ro.Update(Bz);
				ro.Update(i);
				ro.Update((bool)0);
				ro.Final(msg[i][0]);

				ro.Reset();
				ro.Update(Bo);
				ro.Update(i);
				ro.Update((bool)1);
				ro.Final(msg[i][1]);
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
			p.data[Monty25519::size - 1] ^= prng.getBit() << 7;

			static_assert(Monty25519::size == sizeof(Block256), "");
			return Block256(p.data);
		}
	}





}

#endif

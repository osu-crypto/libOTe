#pragma once
#include "libOTe/config.h"
#ifdef ENABLE_MRR

#include <type_traits>
#include "libOTe/TwoChooseOne/OTExtInterface.h"
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/RCurve.h>
#include <cryptoTools/Crypto/RandomOracle.h>

#include "libOTe/Tools/Popf/FeistelRistPopf.h"
#include "libOTe/Tools/Popf/FeistelMulRistPopf.h"

#if !(defined(ENABLE_SODIUM) || defined(ENABLE_RELIC))
static_assert(0, "ENABLE_SODIUM or ENABLE_RELIC must be defined to build McRosRoy");
#endif
#include "libOTe/Tools/DefaultCurve.h"

namespace osuCrypto
{
    namespace details
    {
        // The Popf's PopfFunc must be plain old data, PopfIn must be convertible from an integer, and
        // PopfOut must be a DefaultCurve::Point.
        template<typename DSPopf>
        class McRosRoy : public OtReceiver, public OtSender
        {
            using Curve = DefaultCurve::Curve;
            using Point = DefaultCurve::Point;
            using Number = DefaultCurve::Number;

        public:
            typedef DSPopf PopfFactory;

            McRosRoy() = default;
            McRosRoy(const PopfFactory& p) : popfFactory(p) {}
            McRosRoy(PopfFactory&& p) : popfFactory(p) {}

            void receive(
                const BitVector& choices,
                span<block> messages,
                PRNG& prng,
                Channel& chl,
                u64 numThreads)
            {
                receive(choices, messages, prng, chl);
            }

            void send(
                span<std::array<block, 2>> messages,
                PRNG& prng,
                Channel& chl,
                u64 numThreads)
            {
                send(messages, prng, chl);
            }

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
            static_assert(std::is_same<typename PopfFactory::ConstructedPopf::PopfOut, Point>::value,
                "Popf must be programmable on elliptic curve points");

        private:
            PopfFactory popfFactory;
        };


    }

    // The McQuoid Rosulek Roy OT protocol over the main and twisted curve 
    // with the Feistel Popf impl. See https://eprint.iacr.org/2021/682
    using McRosRoy = details::McRosRoy<DomainSepFeistelRistPopf>;

    // The McQuoid Rosulek Roy OT protocol over the main and twisted curve 
    // with the streamlined Feistel Popf impl. See https://eprint.iacr.org/2021/682
    using McRosRoyMul = details::McRosRoy<DomainSepFeistelMulRistPopf>;


    ///////////////////////////////////////////////////////////////////////////////
    /// impl 
    ///////////////////////////////////////////////////////////////////////////////

    namespace details
    {


        template<typename DSPopf>
        void McRosRoy<DSPopf>::receive(
            const BitVector& choices,
            span<block> messages,
            PRNG& prng,
            Channel& chl)
        {
            Curve curve;

            u64 n = choices.size();
            std::vector<Number> sk; sk.reserve(n);

            unsigned char recvBuff[Point::size];
            auto recvDone = chl.asyncRecv(recvBuff, Point::size);

            std::vector<typename PopfFactory::ConstructedPopf::PopfFunc> sendBuff(n);

            for (u64 i = 0; i < n; ++i)
            {
                auto factory = popfFactory;
                factory.Update(i);
                auto popf = factory.construct();

                sk.emplace_back(prng);
                Point B = Point::mulGenerator(sk[i]);

                sendBuff[i] = popf.program(choices[i], std::move(B), prng);
            }

            chl.asyncSend(std::move(sendBuff));

            recvDone.wait();
            Point A;
            A.fromBytes(recvBuff);

            for (u64 i = 0; i < n; ++i)
            {
                Point B = A * sk[i];

                RandomOracle ro(sizeof(block));
                ro.Update(B);
                ro.Update(i);
                ro.Update((bool)choices[i]);
                ro.Final(messages[i]);
            }
        }

        template<typename DSPopf>
        void McRosRoy<DSPopf>::send(
            span<std::array<block, 2>> msg,
            PRNG& prng,
            Channel& chl)
        {
            Curve curve;

            u64 n = static_cast<u64>(msg.size());

            Number sk(prng);
            Point A = Point::mulGenerator(sk);

            unsigned char sendBuff[Point::size];
            A.toBytes(sendBuff);
            chl.asyncSend(sendBuff, Point::size);

            std::vector<typename PopfFactory::ConstructedPopf::PopfFunc> recvBuff(n);
            chl.recv(recvBuff.data(), recvBuff.size());

            for (u64 i = 0; i < n; ++i)
            {
                auto factory = popfFactory;
                factory.Update(i);
                auto popf = factory.construct();

                Point Bz = popf.eval(recvBuff[i], 0);
                Point Bo = popf.eval(recvBuff[i], 1);

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
    }
}

#endif

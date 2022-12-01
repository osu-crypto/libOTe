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
        task<> McRosRoy<DSPopf>::receive(
            const BitVector& choices,
            span<block> messages,
            PRNG& prng,
            Socket& chl)
        {
            MC_BEGIN(task<>,this, &choices, messages, &prng, &chl,
                n = u64{},
                A = Point{},
                sk = std::vector<Number>{},
                buff = std::vector<u8>(Point::size),
                sendBuff = std::vector<typename PopfFactory::ConstructedPopf::PopfFunc>{}
            );

            Curve{};
            n = choices.size();
            sk.reserve(n);
            sendBuff.resize(n);

            for (u64 i = 0; i < n; ++i)
            {
                auto factory = popfFactory;
                factory.Update(i);
                auto popf = factory.construct();

                sk.emplace_back(prng);
                Point B = Point::mulGenerator(sk[i]);

                sendBuff[i] = popf.program(choices[i], std::move(B), prng);
            }

            MC_AWAIT(chl.send(std::move(sendBuff)));

            MC_AWAIT(chl.recv(buff));
            Curve{};

            A.fromBytes(buff.data());

            for (u64 i = 0; i < n; ++i)
            {
                Point B = A * sk[i];

                RandomOracle ro(sizeof(block));
                ro.Update(B);
                ro.Update(i);
                ro.Update((bool)choices[i]);
                ro.Final(messages[i]);
            }

            MC_END();
        }

        template<typename DSPopf>
        task<> McRosRoy<DSPopf>::send(
            span<std::array<block, 2>> msg,
            PRNG& prng,
            Socket& chl)
        {
            MC_BEGIN(task<>,this, msg, &prng, &chl,
                curve = Curve{},
                n = u64{},
                A = Point{},
                sk = Number{},
                buff = std::vector<u8>( Point::size ),
                recvBuff = std::vector<typename PopfFactory::ConstructedPopf::PopfFunc>{}
            );

            n = static_cast<u64>(msg.size());
            sk.randomize(prng);
            A = Point::mulGenerator(sk);

            assert(buff.size() == A.sizeBytes());
            A.toBytes(buff.data());

            MC_AWAIT(chl.send(std::move(buff)));

            recvBuff.resize(n);
            MC_AWAIT(chl.recv(recvBuff));
            Curve{};

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

            MC_END();
        }
    }
}

#endif

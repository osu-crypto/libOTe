// Everyone knows two curves Curve25519 and its twist.
// Everyone knows base points for the two curves P for the curve and P` for the twist.

// Sender gives two points A = aP and A` = a`P` to the receiver (Elligator paper suggests a = a`. Is it secure?)

// The receiver generates a list of choice bits {c_i}, a list of private keys {b_i}, and a curve choice {P_i} 
// The receiver gives {B_i = IC(c_i, x-coord(b_iP_i))} to the sender.
// The receiver outputs H(b_iA_i) as its output from the OT where A_i is either A or A` corresponding to P_i.

// The sender computes B_{i0} = IC^-1(0,B_i) and B_{i1} = IC^-1(1,B_i) and checks which curve each is on.
// The sender then outputs a_{i0}B_{i0} and a_{i1}B_{i1} where the a_{ic} chosen corresponds to which curve the B_{ic} is on. 


#include "PopfOT.h"

#ifdef ENABLE_POPF

#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Crypto/RandomOracle.h>
#include <cryptoTools/Crypto/Rijndael256.h>
#include <cryptoTools/Network/Channel.h>

#include <cryptoTools/Crypto/RCurve.h>
#ifndef ENABLE_RELIC
static_assert(0, "ENABLE_RELIC must be defined to build PopfOT");
#endif

using Curve = oc::REllipticCurve;
using Point = oc::REccPoint;
using Brick = oc::REccPoint;
using Number = oc::REccNumber;

namespace osuCrypto
{

    void PopfOT::receive(
        const BitVector & choices,
        span<block> messages,
        PRNG & prng,
        Channel & chl)
    {
        Curve curve;
        Point g = curve.getGenerator();
        Point gprime = curve.getGenerator();
        u64 pointSize = g.sizeBytes();
        u64 n = choices.size();

        std::array<Rijndael256Enc, 2> IC;
        IC[0].setKey({toBlock(0,0),toBlock(0,0)});
        IC[1].setKey({toBlock(0,0),toBlock(1ull)});

        auto aesBlocks = (pointSize + 31) / 32;
        auto popfSize = aesBlocks * sizeof(Rijndael256Enc::Block);
        std::vector<u8> pointBuff(pointSize);
        std::vector<u8> hashBuff(roundUpTo(pointSize, 16));
        std::vector<Number> sk; sk.reserve(n);
        std::vector<u8> curveChoice; curveChoice.reserve(n);

        std::vector<u8> recvBuff(2*pointSize);
        chl.asyncRecv(recvBuff.data(), 2*pointSize);

        std::vector<u8> sendBuff(n * popfSize);
        auto sendBuffIter = sendBuff.data();

        Point B(curve);
        for (u64 i = 0; i < n; ++i)
        {
            curveChoice.emplace_back(prng.getBit());
            sk.emplace_back(curve, prng);
            if (curveChoice[i] == 0)
            {
                B = g * sk[i];
            } else
            {
                B = gprime * sk[i];
            }

            B.toBytes(pointBuff.data());
            auto p = (Rijndael256Enc::Block*)pointBuff.data();
            IC[choices[i]].encBlocks(p, aesBlocks, (Rijndael256Enc::Block*)sendBuffIter);
            sendBuffIter += popfSize;
        }

        chl.asyncSend(std::move(sendBuff));

        RandomOracle ro(sizeof(block));
        auto recvBuffIter = recvBuff.data();
        Point A(curve);
        A.fromBytes(recvBuffIter); recvBuffIter += pointSize;
        Point Aprime(curve);
        Aprime.fromBytes(recvBuffIter);
        for (u64 i = 0; i < n; ++i)
        {
            if (curveChoice[i] == 0)
            {
                B = A * sk[i];
            } else
            {
                B = Aprime * sk[i];
            }
            B.toBytes(hashBuff.data());
            RandomOracle ro(sizeof(block));
            ro.Update(hashBuff.data(), hashBuff.size());
            ro.Final(messages[i]);
        }
    }

    void PopfOT::send(
        span<std::array<block, 2>> msg,
        PRNG& prng,
        Channel& chl)
    {
        Curve curve;
        Point g = curve.getGenerator();
        Point gprime = curve.getGenerator();
        u64 pointSize = g.sizeBytes();
        u64 n = static_cast<u64>(msg.size());
        RandomOracle ro(sizeof(block));

        std::array<Rijndael256Dec, 2> ICinv;
        ICinv[0].setKey({toBlock(0,0),toBlock(0,0)});
        ICinv[1].setKey({toBlock(0,0),toBlock(1ull)});

        auto aesBlocks = (pointSize + 31) / 32;
        auto popfSize = aesBlocks * sizeof(Rijndael256Enc::Block);
        std::vector<u8> sendBuff(2*pointSize);
        std::vector<u8> popfBuff(popfSize);
        std::vector<u8> hashBuff(roundUpTo(pointSize, 16));

        Number sk(curve, prng);
        auto sendBuffIter = sendBuff.data();
        Point A = g * sk;
        Point Aprime = gprime * sk;
        A.toBytes(sendBuffIter); sendBuffIter += pointSize;
        Aprime.toBytes(sendBuffIter);

        chl.asyncSend(std::move(sendBuff));

        std::vector<u8> recvBuff(n * popfSize);
        chl.recv(recvBuff.data(), recvBuff.size());

        auto buffIter = recvBuff.data();

        Point Bz(curve), Bo(curve);
        for (u64 i = 0; i < n; ++i)
        {
            auto phi = (Rijndael256Enc::Block*)buffIter;
            // Bz = POPF.Eval(0,phi);
            ICinv[0].decBlocks(phi, aesBlocks, (Rijndael256Enc::Block*)popfBuff.data());
            Bz.fromBytes(popfBuff.data()); // Hope this isn't destructive.
            // Bo = pPOPF.Eval(1,phi);
            ICinv[1].decBlocks(phi, aesBlocks, (Rijndael256Enc::Block*)popfBuff.data());
            Bo.fromBytes(popfBuff.data());
            buffIter += popfSize;

            // We don't need to check which curve we're on since we use the same secret for both.
            Bz *= sk;
            Bz.toBytes(hashBuff.data());
            RandomOracle ro(sizeof(block));
            ro.Update(hashBuff.data(), hashBuff.size());
            ro.Final(msg[i][0]);

            Bo *= sk;
            Bo.toBytes(hashBuff.data());
            ro.Reset();
            ro.Update(hashBuff.data(), hashBuff.size());
            ro.Final(msg[i][1]);
        }
    }
}
#endif



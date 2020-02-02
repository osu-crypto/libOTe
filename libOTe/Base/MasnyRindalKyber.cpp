#include "MasnyRindalKyber.h"
#ifdef ENABLE_MR_KYBER

#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Network/Channel.h>

namespace osuCrypto
{

    void MasnyRindalKyber::receive(
        const BitVector & choices, 
        span<block> messages, 
        PRNG & prng, 
        Channel & chl)
    {
        u64 n = choices.size();

        std::vector<KyberOTRecver> ot(n);

        static_assert(std::is_pod<KyberOtRecvPKs>::value, "");
        std::vector<KyberOtRecvPKs> pkBuff(n);

        auto iter = pkBuff.data();

        for (u64 i = 0; i < n; ++i)
        {
            ot[i].b = choices[i];

            //get receivers message and secret coins
            KyberReceiverMessage(&ot[i], iter++);
        }

        chl.asyncSend(std::move(pkBuff));


        static_assert(std::is_pod<KyberOTCtxt>::value, "");
        std::vector<KyberOTCtxt> ctxts(n);

        chl.recv(ctxts.data(), ctxts.size());

        for (u64 i = 0; i < n; ++i)
        {
            KyberReceiverStrings(&ot[i], &ctxts[i]);
            memcpy(&messages[i], ot[i].rot, sizeof(block));
        }
    }

    void MasnyRindalKyber::send(
        span<std::array<block, 2>> messages, 
        PRNG & prng, 
        Channel & chl)
    {
        u64 n = messages.size();
        std::vector<KyberOtRecvPKs> pkBuff(n);
        std::vector<KyberOTCtxt> ctxts(n);


        prng.get(messages.data(), messages.size());


        chl.recv(pkBuff);
        KyberOTPtxt ptxt;

        for (u64 i = 0; i < n; ++i)
        {
            memcpy(ptxt.sot[0], &messages[i][0], sizeof(block));
            memset(ptxt.sot[0] + sizeof(block), 0, sizeof(ptxt.sot[0]) - sizeof(block));

            memcpy(ptxt.sot[1], &messages[i][1], sizeof(block));
            memset(ptxt.sot[1] + sizeof(block), 0, sizeof(ptxt.sot[1]) - sizeof(block));

            //get senders message, secret coins and ot strings
            KyberSenderMessage(&ctxts[i], &ptxt, &pkBuff[i]);
        }

        chl.asyncSend(std::move(ctxts));
    }
}
#endif
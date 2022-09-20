#include "MasnyRindalKyber.h"
#ifdef ENABLE_MR_KYBER

#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Crypto/PRNG.h>

namespace osuCrypto
{

    task<> MasnyRindalKyber::receive(
        const BitVector & choices, 
        span<block> messages, 
        PRNG & prng, 
        Socket & chl)
    {
        MC_BEGIN(task<>,this, &choices, messages, &prng, &chl,
            n = u64{},
            ot = std::vector<KyberOTRecver>{},
            pkBuff = std::vector<KyberOtRecvPKs>{},
            ctxts = std::vector<KyberOTCtxt>{}
        );
        static_assert(std::is_trivial<KyberOtRecvPKs>::value, "");
        static_assert(std::is_pod<KyberOTCtxt>::value, "");

        n = choices.size();
        ot.resize(n);
        pkBuff.resize(n);
        ctxts.resize(n);

        for (u64 i = 0; i < n; ++i)
        {
            ot[i].b = choices[i];

            //get receivers message and secret coins
            KyberReceiverMessage(&ot[i], &pkBuff[i]);
        }

        MC_AWAIT(chl.send(std::move(pkBuff)));
        MC_AWAIT(chl.recv(ctxts));

        for (u64 i = 0; i < n; ++i)
        {
            KyberReceiverStrings(&ot[i], &ctxts[i]);
            memcpy(&messages[i], ot[i].rot, sizeof(block));
        }

        MC_END();
    }

    task<> MasnyRindalKyber::send(
        span<std::array<block, 2>> messages, 
        PRNG & prng, 
        Socket & chl)
    {
        MC_BEGIN(task<>,this, messages, &prng, &chl,
            n = u64{},
            pkBuff = std::vector<KyberOtRecvPKs>{},
            ctxts = std::vector<KyberOTCtxt>{},
            ptxt = KyberOTPtxt{}
        );
        n = messages.size();
        pkBuff.resize(n);
        ctxts.resize(n);

        prng.get(messages.data(), messages.size());

        MC_AWAIT(chl.recv(pkBuff));

        for (u64 i = 0; i < n; ++i)
        {
            memcpy(ptxt.sot[0], &messages[i][0], sizeof(block));
            memset(ptxt.sot[0] + sizeof(block), 0, sizeof(ptxt.sot[0]) - sizeof(block));

            memcpy(ptxt.sot[1], &messages[i][1], sizeof(block));
            memset(ptxt.sot[1] + sizeof(block), 0, sizeof(ptxt.sot[1]) - sizeof(block));

            //get senders message, secret coins and ot strings
            KyberSenderMessage(&ctxts[i], &ptxt, &pkBuff[i]);
        }

        MC_AWAIT(chl.send(std::move(ctxts)));

        MC_END();
    }
}
#endif
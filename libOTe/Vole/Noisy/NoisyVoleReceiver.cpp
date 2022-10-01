#include "NoisyVoleReceiver.h"

#if defined(ENABLE_SILENT_VOLE) || defined(ENABLE_SILENTOT)
#include "cryptoTools/Common/BitIterator.h"
#include "cryptoTools/Common/Matrix.h"


namespace osuCrypto
{

    task<> NoisyVoleReceiver::receive(span<block> y, span<block> z, PRNG& prng,
        OtSender& ot, Socket& chl)
    {
        MC_BEGIN(task<>,this, y,z, &prng, &ot, &chl,
            otMsg = AlignedUnVector<std::array<block, 2>>{ 128 }
            );

        setTimePoint("NoisyVoleReceiver.ot.begin");

        MC_AWAIT(ot.send(otMsg, prng, chl));
        
        setTimePoint("NoisyVoleReceiver.ot.end");

        MC_AWAIT(receive(y, z, prng, otMsg, chl));

        MC_END();
    }

    task<> NoisyVoleReceiver::receive(
        span<block> y, span<block> z, 
        PRNG& _, span<std::array<block, 2>> otMsg, 
        Socket& chl)
    {
        MC_BEGIN(task<>,this, y,z, otMsg, &chl,
            msg = Matrix<block>{},
            prng = std::move(PRNG{})
            //buffer = std::vector<block>{}
        );

        setTimePoint("NoisyVoleReceiver.begin");
        if (otMsg.size() != 128)
            throw RTE_LOC;
        if (y.size() != z.size())
            throw RTE_LOC;
        if (z.size() == 0)
            throw RTE_LOC;

        memset(z.data(), 0, sizeof(block) * z.size());
        msg.resize(otMsg.size(), y.size());

        //buffer.resize(z.size());

        for (u64 ii = 0; ii < (u64)otMsg.size(); ++ii)
        {
            //PRNG p0(otMsg[ii][0]);
            //PRNG p1(otMsg[ii][1]);
            prng.SetSeed(otMsg[ii][0], z.size());
            auto& buffer = prng.mBuffer;

            for (u64 j = 0; j < (u64)y.size(); ++j)
            {
                z[j] = z[j] ^ buffer[j];

                block twoPowI = ZeroBlock;
                *BitIterator((u8*)&twoPowI, ii) = 1;

                auto yy = y[j].gf128Mul(twoPowI);

                msg(ii, j) = yy ^ buffer[j];
            }

            prng.SetSeed(otMsg[ii][1], z.size());

           for (u64 j = 0; j < (u64)y.size(); ++j)
            { 
                // enc one message under the OT msg.
                msg(ii, j) = msg(ii, j) ^ buffer[j];
            }
        }

        MC_AWAIT(chl.send(std::move(msg)));
        //chl.asyncSend(std::move(msg));
        setTimePoint("NoisyVoleReceiver.done");

        MC_END();
    }
}
#endif
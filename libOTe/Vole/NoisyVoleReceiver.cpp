#include "NoisyVoleReceiver.h"

#if defined(ENABLE_SILENT_VOLE) || defined(ENABLE_SILENTOT)
#include "cryptoTools/Common/BitIterator.h"
#include "cryptoTools/Common/Matrix.h"


namespace osuCrypto
{

    void NoisyVoleReceiver::receive(span<block> y, span<block> z, PRNG& prng, OtSender& ot, Channel& chl)
    {
        setTimePoint("recvOT");

        AlignedBlockArray<128, std::array<block, 2>> otMsg;
        ot.send(otMsg, prng, chl);

        return receive(y, z, prng, otMsg, chl);
    }
    void NoisyVoleReceiver::receive(span<block> y, span<block> z, PRNG& prng, span<std::array<block, 2>> otMsg, Channel& chl)
    {
        if (otMsg.size() != 128)
            throw RTE_LOC;
        if (y.size() != z.size())
            throw RTE_LOC;

        memset(z.data(), 0, sizeof(block) * z.size());
        setTimePoint("recvMain");
        Matrix<block> msg(otMsg.size(), y.size());

        std::vector<block> buffer(z.size());

        for (u64 ii = 0; ii < (u64)otMsg.size(); ++ii)
        {
            PRNG p0(otMsg[ii][0]);
            PRNG p1(otMsg[ii][1]);

            p0.get<block>(buffer);
            //if (ii < 2)
            //    std::cout << "zero" << ii << " ";
            for (u64 j = 0; j < (u64)y.size(); ++j)
            {
                // zj -= m0[i][j]
                z[j] = z[j] ^ buffer[j];

                //if (ii < 2 && j < 2)
                //    std::cout << buffer[j] << " ";

                block twoPowI = ZeroBlock;
                *BitIterator((u8*)&twoPowI, ii) = 1;

                auto yy = y[j].gf128Mul(twoPowI);

                // mij = yj * 2^i + m0[i][j]
                msg(ii, j) = yy ^ buffer[j];
            }

            p1.get<block>(buffer);


            //if (ii < 2)
            //    std::cout << std::endl;
            //if (ii < 2)
            //    std::cout << "one" << ii << "  ";

            for (u64 j = 0; j < (u64)y.size(); ++j)
            { 
                //if (ii < 2 && j < 2)
                //    std::cout << buffer[j] << " ";

                // enc one message under the OT msg.
                msg(ii, j) = msg(ii, j) ^ buffer[j];
            }
            //if (ii < 2)
            //    std::cout << std::endl;

        }
        setTimePoint("recvSendMsg");

        chl.asyncSend(std::move(msg));
    }
}
#endif

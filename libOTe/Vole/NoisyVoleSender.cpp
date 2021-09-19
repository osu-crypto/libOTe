#include "NoisyVoleSender.h"

#if defined(ENABLE_SILENT_VOLE) || defined(ENABLE_SILENTOT)
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Matrix.h"

namespace osuCrypto
{
    void NoisyVoleSender::send(block x, span<block> z, PRNG& prng, OtReceiver& ot, Channel& chl)
    {
        setTimePoint("recvOT");

        BitVector bv((u8*)&x, 128);
        AlignedBlockArray<128> otMsg;
        ot.receive(bv, otMsg, prng, chl);

        return send(x, z, prng, otMsg, chl);
    }

    void NoisyVoleSender::send(block x, span<block> z, PRNG& prng, span<block> otMsg, Channel& chl)
    {
        if (otMsg.size() != 128)
            throw RTE_LOC;
        setTimePoint("recvMain");

        Matrix<block> msg(otMsg.size(), z.size());
        memset(z.data(), 0, sizeof(block) * z.size());
        chl.recv(msg.data(), msg.size());
        setTimePoint("recvMsg");
        std::vector<block> buffer(z.size());

        auto xIter = BitIterator((u8*)&x);

        for (u64 i = 0; i < otMsg.usize(); ++i, ++xIter)
        {
            PRNG pi(otMsg[i]);
            pi.get<block>(buffer);


            if (*xIter)
            {

                //if (i < 2)
                //    std::cout << "One" << i << "  ";

                for (u64 j = 0; j < z.usize(); ++j)
                {

                    //if (i < 2 && j < 2)
                    //    std::cout << buffer[j] << " ";

                    buffer[j] = msg(i, j) ^ buffer[j];
                }
            }
            //else
            //{
            //    if (i < 2)
            //        std::cout << "Zero" << i << " ";

            //    for (u64 j = 0; j < z.size(); ++j)
            //    {

            //        if (i < 2 && j < 2)
            //            std::cout << buffer[j] << " ";
            //    }
            //}
            //  

            //if (i < 2)
            //    std::cout << std::endl;

            for (u64 j = 0; j < (u64)z.size(); ++j)
            {


                z[j] = z[j] ^ buffer[j];
            }
        }
        setTimePoint("recvDone");

    }

}
#endif

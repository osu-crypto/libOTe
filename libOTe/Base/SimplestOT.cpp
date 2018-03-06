#include "SimplestOT.h"

#ifdef ENABLE_SIMPLEST_OT


extern "C"
{
#include "../SimplestOT/ot_sender.h"
#include "../SimplestOT/ot_receiver.h"
#include "../SimplestOT/ot_config.h"
#include "../SimplestOT/cpucycles.h"
#include "../SimplestOT/randombytes.h"
}

#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Common/BitVector.h>

namespace osuCrypto
{
    rand_source makeRandSource(PRNG& prng)
    {
        rand_source rand;
        rand.get = [](void* ctx, unsigned char* dest, unsigned long long length) {
            PRNG& prng = *(PRNG*)ctx;
            prng.get(dest, length);
        };
        rand.ctx = &prng;

        return rand;
    }

    void SimplestOT::receive(
        const BitVector& choices,
        span<block> msg,
        PRNG& prng,
        Channel& chl)
    {

        RECEIVER receiver;

        u8 Rs_pack[4 * SIMPLEST_OT_PACK_BYTES];
        u8 keys[4][SIMPLEST_OT_HASHBYTES];
        u8 cs[4];


        chl.recv(receiver.S_pack, sizeof(receiver.S_pack));

        receiver_procS(&receiver);

        //

        receiver_maketable(&receiver);
        auto rand = makeRandSource(prng);

        for (u32 i = 0; i < msg.size(); i += 4)
        {
            auto min = std::min<u32>(4, msg.size() - i);

            for (u32 j = 0; j < min; j++)
            {
                cs[j] = choices[i + j];
            }

            receiver_rsgen(&receiver, Rs_pack, cs, rand);

            chl.asyncSendCopy(Rs_pack, sizeof(Rs_pack));

            receiver_keygen(&receiver, keys);


            for (u32 j = 0; j < min; j++)
            {
                memcpy(&msg[i + j], keys[j], sizeof(block));

                //ostreamLock(std::cout)
                //    << "r[" << i + j << "][" << int(cs[j]) << "] = " << msg[i + j] << "\n";
            }
        }
    }


    void SimplestOT::send(
        span<std::array<block, 2>> msg,
        PRNG& prng,
        Channel& chl)
    {

        SENDER sender;

        u8 S_pack[SIMPLEST_OT_PACK_BYTES];
        u8 Rs_pack[4 * SIMPLEST_OT_PACK_BYTES];
        u8 keys[2][4][SIMPLEST_OT_HASHBYTES];


        auto rand = makeRandSource(prng);

        //std::cout << "s1 " << std::endl;
        sender_genS(&sender, S_pack, rand);
        //std::cout << "s2 " << std::endl;

        chl.asyncSend(S_pack, sizeof(S_pack));
        //std::cout << "s3 " << std::endl;

        for (u32 i = 0; i < msg.size(); i += 4)
        {
            chl.recv(Rs_pack, sizeof(Rs_pack));
            //std::cout << "s4 " << i << std::endl;

            sender_keygen(&sender, Rs_pack, keys);

            //std::cout << "s5 " << i << std::endl;
            //

            auto min = std::min<u32>(4, msg.size() - i);
            for (u32 j = 0; j < min; j++)
            {
                memcpy(&msg[i + j][0], keys[0][j], sizeof(block));
                memcpy(&msg[i + j][1], keys[1][j], sizeof(block));


                //ostreamLock(std::cout)
                //    << "m[" << i + j << "][0] = " << msg[i + j][0] << "\n"
                //    << "m[" << i + j << "][1] = " << msg[i + j][1] << "\n";

                //if (SIMPLEST_OT_VERBOSE)
                //{
                //    printf("%4d-th sender keys:", i + j);

                //    for (k = 0; k < SIMPLEST_OT_HASHBYTES; k++) printf("%.2X", keys[0][j][k]);
                //    printf(" ");
                //    for (k = 0; k < SIMPLEST_OT_HASHBYTES; k++) printf("%.2X", keys[1][j][k]);
                //    printf("\n");
                //}

            }
        }
    }


}
#endif



#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

extern "C"
{
#include "ot_sender.h"
#include "ot_receiver.h"

#include "ot_config.h"
#include "cpucycles.h"
#include "randombytes.h"
}

#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Common/CLP.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Crypto/PRNG.h>

using namespace oc;

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

void ot_sender_test(Channel& chl, span<std::array<block, 2>> msg, PRNG& prng)
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


            ostreamLock(std::cout) 
                << "m[" << i + j << "][0] = " << msg[i + j][0] << "\n"
                << "m[" << i + j << "][1] = " << msg[i + j][1] << "\n";

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

int simple_main_sender()
{
    long long t = 0;

    IOService ios;
    Session session(ios, "localhost:1212", SessionMode::Server);
    Channel chl = session.addChannel();

    //t -= cpucycles_amd64cpuinfo();
    std::vector<std::array<block, 2>> msg(128);
    PRNG prng(OneBlock);
    ot_sender_test(chl, msg, prng);

    //t += cpucycles_amd64cpuinfo();

    //

    if (!SIMPLEST_OT_VERBOSE)
        printf("[n=%d] Elapsed time:  %lld cycles\n",
            128, t);

    //shutdown(newsockfd, 2);
    //shutdown(sockfd, 2);

    //

    return 0;
}



void ot_receiver_test(Channel& chl, BitVector& choices, span<block> msg, PRNG& prng)
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
            cs[j] = choices[i+j];
        }

        receiver_rsgen(&receiver, Rs_pack, cs, rand);

        chl.asyncSendCopy(Rs_pack, sizeof(Rs_pack));

        receiver_keygen(&receiver, keys);


        for (u32 j = 0; j < min; j++)
        {
            memcpy(&msg[i + j], keys[j], sizeof(block));

            ostreamLock(std::cout)
                << "r[" << i + j << "]["<<int(cs[j]) <<"] = " << msg[i + j] << "\n";
        }
    }
}


int simple_main_recv()
{
    long long t = 0;

    //


    //
    const char* host = "localhost";
    int port = 1212;

    IOService ios;
    Session session(ios, "localhost:1212", SessionMode::Client);
    Channel chl = session.addChannel();

    //if( setsockopt(sockfd,  SOL_SOCKET,   SO_SNDBUF, &sndbuf, sizeof(int)) != 0 ) { perror("ERROR setsockopt"); exit(-1); }
    //if( setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY,   &flag, sizeof(int)) != 0 ) { perror("ERROR setsockopt"); exit(-1); }

    //t -= cpucycles_amd64cpuinfo();
    std::vector<block> msg(128);
    BitVector choices(128);
    PRNG prng(ZeroBlock);
    choices.randomize(prng);

    ot_receiver_test(chl, choices, msg, prng);

    //t += cpucycles_amd64cpuinfo();

    //

    if (!SIMPLEST_OT_VERBOSE)
        printf("[n=%d] Elapsed time:  %lld cycles\n",
            128, t);

    //shutdown(sockfd, 2);

    //

    return 0;
}



int main(int argc, char** argv)
{
    CLP cmd(argc, argv);

    if (cmd.hasValue("r"))
    {
        if (cmd.get<int>("r"))
            simple_main_recv();
        else
            simple_main_sender();
    }
    else
    {

        auto a = std::async(simple_main_recv);
        simple_main_sender();

        a.get();
    }
    return 0;
}

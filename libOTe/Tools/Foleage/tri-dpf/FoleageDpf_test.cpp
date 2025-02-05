//#include <openssl/rand.h>
//#include <openssl/conf.h>
//#include <openssl/evp.h>
//#include <openssl/err.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#include "libOTe/Tools/Foleage/tri-dpf/FoleageDpf.h"
//#include "libOTe/Tools/Foleage/tri-dpf/FoleageHalfDpf.h"
#include <cryptoTools/Common/block.h>

#define FULLEVALDOMAIN 14
#define MESSAGESIZE 2
#define MAXRANDINDEX ipow(3, FULLEVALDOMAIN)
namespace osuCrypto
{
    size_t randIndex(PRNG& prng)
    {
        return prng.get<size_t>() % (size_t)MAXRANDINDEX;
    }
    //using int128_t = uint128_t;
    uint128_t randMsg(PRNG& prng)
    {
        return prng.get();
        //uint128_t msg;
        //RAND_bytes((uint8_t*)&msg, sizeof(uint128_t));
        //return msg;
    }

    double benchmark_dpfGen()
    {
        size_t num_leaves = ipow(3, FULLEVALDOMAIN);
        size_t size = FULLEVALDOMAIN; // evaluation will result in 3^size points
        PRNG prng(block(3423423));
        size_t secret_index = randIndex(prng);
        uint128_t secret_msg = randMsg(prng);
        size_t msg_len = 1;

        PRFKeys prf_keys;
        prf_keys.gen(prng);

        DPFKey kA;
        DPFKey kB;

        clock_t t;
        t = clock();
        DPFGen(prf_keys, size, secret_index, span<uint128_t>(&secret_msg,1), msg_len, kA, kB, prng);
        t = clock() - t;
        double time_taken = ((double)t) / (CLOCKS_PER_SEC / 1000.0); // ms

        printf("Time %f ms\n", time_taken);

        return time_taken;
    }

    double benchmark_dpfAES()
    {
        size_t num_leaves = ipow(3, FULLEVALDOMAIN);
        size_t size = FULLEVALDOMAIN;

        PRNG prng(block(3423423));
        PRFKeys prf_keys;
        prf_keys.gen(prng);

        AlignedUnVector<uint128_t> data_in(num_leaves * MESSAGESIZE);
        AlignedUnVector<uint128_t> data_out(num_leaves * MESSAGESIZE);
        AlignedUnVector<uint128_t> data_tmp(num_leaves * MESSAGESIZE);
        AlignedUnVector<uint128_t> tmp;

        // fill with unique data
        for (size_t i = 0; i < num_leaves * MESSAGESIZE; i++)
            data_tmp[i] = (uint128_t)i;

        // make the input data pseudorandom for correct timing
        PRFBatchEval(prf_keys.prf_key0, data_tmp, data_in, num_leaves * MESSAGESIZE);

        //************************************************
        // Benchmark AES encryption time required in DPF loop
        //************************************************

        clock_t t;
        t = clock();
        size_t num_nodes = 1;
        for (size_t i = 0; i < size; i++)
        {
            PRFBatchEval(prf_keys.prf_key0, data_in, data_out, num_nodes);
            PRFBatchEval(prf_keys.prf_key1, data_in, data_out.subspan(num_nodes), num_nodes);
            PRFBatchEval(prf_keys.prf_key2, data_in, data_out.subspan(num_nodes * 2), num_nodes);

            tmp = data_out;
            data_out = data_in;
            data_in = tmp;

            num_nodes *= 3;
        }

        // compute AES part of output extension
        PRFBatchEval(prf_keys.prf_key0, data_in, data_out, num_nodes * MESSAGESIZE);

        t = clock() - t;
        double time_taken = ((double)t) / (CLOCKS_PER_SEC / 1000.0); // ms

        printf("Time %f ms\n", time_taken);

        return time_taken;
    }

    int main_test_tridpf(int argc, char** argv)
    {

        double time = 0;
        int testTrials = 3;

        //printf("******************************************\n");
        //printf("Testing DPF.FullEval\n");
        //for (int i = 0; i < testTrials; i++)
        //{
        //    time += foliage_dpf_test();
        //    printf("Done with trial %i of %i\n", i + 1, testTrials);
        //}
        //printf("******************************************\n");
        //printf("PASS\n");
        //printf("DPF.FullEval: (avg time) %0.2f ms\n", time / testTrials);
        //printf("******************************************\n\n");

        //time = 0;
        //printf("******************************************\n");
        //printf("Testing HalfDPF.FullEval\n");
        //for (int i = 0; i < testTrials; i++)
        //{
        //    time += foliage_Halfdpf_test();
        //    printf("Done with trial %i of %i\n", i + 1, testTrials);
        //}
        //printf("******************************************\n");
        //printf("PASS\n");
        //printf("HalfDPF.FullEval: (avg time) %0.2f ms\n", time / testTrials);
        //printf("******************************************\n\n");

        time = 0;
        printf("******************************************\n");
        printf("Benchmarking DPF.Gen\n");
        for (int i = 0; i < testTrials; i++)
        {
            time += benchmark_dpfGen();
            printf("Done with trial %i of %i\n", i + 1, testTrials);
        }
        printf("******************************************\n");
        printf("Avg time: %0.4f ms\n", time / testTrials);
        printf("******************************************\n\n");

        time = 0;
        printf("******************************************\n");
        printf("Benchmarking AES\n");
        for (int i = 0; i < testTrials; i++)
        {
            time += benchmark_dpfAES();
            printf("Done with trial %i of %i\n", i + 1, testTrials);
        }
        printf("******************************************\n");
        printf("Avg time: %0.2f ms\n", time / testTrials);
        printf("******************************************\n\n");

        return 0;
    }
}
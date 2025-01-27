#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#include "libOTe/Tools/Foliage/tri-dpf/FoliageDpf.h"
#include "FoliageUtils.h"

#define SUMT 730 // sum of T DPFs

#define FULLEVALDOMAIN 10
#define MESSAGESIZE 8
#define MAXRANDINDEX ipow(3, FULLEVALDOMAIN)
namespace osuCrypto
{

    //size_t randIndex()
    //{
    //    srand(time(NULL));
    //    return ((size_t)rand()) % ((size_t)MAXRANDINDEX);
    //}

    //uint128_t randMsg()
    //{
    //    uint128_t msg;
    //    RAND_bytes((uint8_t*)&msg, sizeof(uint128_t));
    //    return msg;
    //}

    double benchmark_spfss()
    {
        size_t num_leaves = ipow(3, FULLEVALDOMAIN);
        size_t size = FULLEVALDOMAIN; // evaluation will result in 3^size points
        PRNG prng(block(3423423));

        size_t secret_index = prng.get<u64>() % MAXRANDINDEX;
        uint128_t secret_msg = prng.get();
        size_t msg_len = MESSAGESIZE;

        PRFKeys prf_keys;
        prf_keys.gen(prng);

        std::vector<DPFKey> kA(SUMT);
        std::vector<DPFKey> kB(SUMT);

        clock_t t;
        t = clock();

        for (size_t i = 0; i < SUMT; i++)
            DPFGen(prf_keys, size, secret_index, span<uint128_t>(&secret_msg,1), msg_len, kA[i], kB[i], prng);

        t = clock() - t;
        double time_taken = ((double)t) / (CLOCKS_PER_SEC / 1000.0); // ms

        printf("Time %f ms\n", time_taken);

        return time_taken;
    }

    double benchmarkAES()
    {
        size_t num_leaves = ipow(3, FULLEVALDOMAIN);
        size_t size = FULLEVALDOMAIN;
        PRNG prng(block(3423423));

        PRFKeys prf_keys;
        prf_keys.gen(prng);

        AlignedUnVector<uint128_t> data_in (num_leaves * MESSAGESIZE);
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

        for (size_t n = 0; n < SUMT; n++)
        {
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
        }

        t = clock() - t;
        double time_taken = ((double)t) / (CLOCKS_PER_SEC / 1000.0); // ms

        printf("Time %f ms\n", time_taken);

        return time_taken;
    }

    int mainSpfss(int argc, char** argv)
    {

        double time = 0;
        int testTrials = 10;

        //printf("******************************************\n");
        //printf("Testing DPF.FullEval\n");
        //for (int i = 0; i < testTrials; i++)
        //{
        //    time += foliage_spfss_test();
        //    printf("Done with trial %i of %i\n", i + 1, testTrials);
        //}
        //printf("******************************************\n");
        //printf("PASS\n");
        //printf("DPF.FullEval: (avg time) %0.2f ms\n", time / testTrials);
        //printf("******************************************\n\n");

        time = 0;
        printf("******************************************\n");
        printf("Benchmarking DPF.Gen\n");
        for (int i = 0; i < testTrials; i++)
        {
            time += benchmark_spfss();
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
            time += benchmarkAES();
            printf("Done with trial %i of %i\n", i + 1, testTrials);
        }
        printf("******************************************\n");
        printf("Avg time: %0.2f ms\n", time / testTrials);
        printf("******************************************\n\n");

        return 0;
    }
}
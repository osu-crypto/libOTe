//#include <stdint.h>
//#include <stdlib.h>
//#include <time.h>
//
//#include "libOTe/Tools/Foleage/tri-dpf/FoleageDpf.h"
//#include "FoleageUtils.h"
//
//#define SUMT 730 // sum of T DPFs
//
//#define FULLEVALDOMAIN 10
//#define MESSAGESIZE 8
//#define MAXRANDINDEX ipow(3, FULLEVALDOMAIN)
//namespace osuCrypto
//{
//
//    double benchmarkAES()
//    {
//        size_t num_leaves = ipow(3, FULLEVALDOMAIN);
//        size_t size = FULLEVALDOMAIN;
//        PRNG prng(block(3423423));
//
//        PRFKeys prf_keys;
//        prf_keys.gen(prng);
//
//        AlignedUnVector<block> data_in (num_leaves * MESSAGESIZE);
//        AlignedUnVector<block> data_out(num_leaves * MESSAGESIZE);
//        AlignedUnVector<block> data_tmp(num_leaves * MESSAGESIZE);
//        AlignedUnVector<block> tmp;
//
//        // fill with unique data
//        for (size_t i = 0; i < num_leaves * MESSAGESIZE; i++)
//            data_tmp[i] = block(i);
//
//        // make the input data pseudorandom for correct timing
//        PRFBatchEval(prf_keys.prf_key0, data_tmp, data_in, num_leaves * MESSAGESIZE);
//
//        //************************************************
//        // Benchmark AES encryption time required in DPF loop
//        //************************************************
//
//        clock_t t;
//        t = clock();
//
//        for (size_t n = 0; n < SUMT; n++)
//        {
//            size_t num_nodes = 1;
//            for (size_t i = 0; i < size; i++)
//            {
//                PRFBatchEval(prf_keys.prf_key0, data_in, data_out, num_nodes);
//                PRFBatchEval(prf_keys.prf_key1, data_in, data_out.subspan(num_nodes), num_nodes);
//                PRFBatchEval(prf_keys.prf_key2, data_in, data_out.subspan(num_nodes * 2), num_nodes);
//
//                tmp = data_out;
//                data_out = data_in;
//                data_in = tmp;
//
//                num_nodes *= 3;
//            }
//            // compute AES part of output extension
//            PRFBatchEval(prf_keys.prf_key0, data_in, data_out, num_nodes * MESSAGESIZE);
//        }
//
//        t = clock() - t;
//        double time_taken = ((double)t) / (CLOCKS_PER_SEC / 1000.0); // ms
//
//        printf("Time %f ms\n", time_taken);
//
//        return time_taken;
//    }
//
//    int mainSpfss(int argc, char** argv)
//    {
//
//        double time = 0;
//        int testTrials = 10;
//
//        //printf("******************************************\n");
//        //printf("Testing DPF.FullEval\n");
//        //for (int i = 0; i < testTrials; i++)
//        //{
//        //    time += foliage_spfss_test();
//        //    printf("Done with trial %i of %i\n", i + 1, testTrials);
//        //}
//        //printf("******************************************\n");
//        //printf("PASS\n");
//        //printf("DPF.FullEval: (avg time) %0.2f ms\n", time / testTrials);
//        //printf("******************************************\n\n");
//
//        time = 0;
//        //printf("******************************************\n");
//        //printf("Benchmarking DPF.Gen\n");
//        //for (int i = 0; i < testTrials; i++)
//        //{
//        //    time += benchmark_spfss();
//        //    printf("Done with trial %i of %i\n", i + 1, testTrials);
//        //}
//        //printf("******************************************\n");
//        //printf("Avg time: %0.4f ms\n", time / testTrials);
//        //printf("******************************************\n\n");
//
//        time = 0;
//        printf("******************************************\n");
//        printf("Benchmarking AES\n");
//        for (int i = 0; i < testTrials; i++)
//        {
//            time += benchmarkAES();
//            printf("Done with trial %i of %i\n", i + 1, testTrials);
//        }
//        printf("******************************************\n");
//        printf("Avg time: %0.2f ms\n", time / testTrials);
//        printf("******************************************\n\n");
//
//        return 0;
//    }
//}
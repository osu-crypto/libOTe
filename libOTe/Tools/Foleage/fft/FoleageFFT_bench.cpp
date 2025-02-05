//#include <openssl/rand.h>
//#include <openssl/conf.h>
//#include <openssl/evp.h>
//#include <openssl/err.h>

#include <stdlib.h>
#include <time.h>

#include "libOTe/Tools/Foleage/fft/FoleageFft.h"
#include "cryptoTools/Common/Aligned.h"
#include "cryptoTools/Crypto/PRNG.h"

#include "libOTe/Tools/Foleage/FoleageUtils.h"

#define NUMVARS 16

namespace osuCrypto
{


    double Foleage_FFT64_bench()
    {
        size_t num_vars = NUMVARS;
        size_t num_coeffs = ipow(3, num_vars);
        AlignedUnVector<uint64_t> coeffs (num_coeffs);
        PRNG prng(block(342));
        prng.get(coeffs.data(), num_coeffs);

        //************************************************
        printf("Benchmarking FFT evaluation with uint64_t packing \n");
        //************************************************

        clock_t t;
        t = clock();
        fft_recursive_uint64(coeffs, num_vars, num_coeffs / 3);
        t = clock() - t;
        double time_taken = ((double)t) / (CLOCKS_PER_SEC / 1000.0); // ms

        printf("FFT (uint64) eval time (total) %f ms\n", time_taken);

        return time_taken;
    }

    double Foleage_FFT32_bench()
    {
        size_t num_vars = NUMVARS;
        size_t num_coeffs = ipow(3, num_vars);

        AlignedUnVector < uint32_t> coeffs(num_coeffs);
        PRNG prng(block(342));
        prng.get(coeffs.data(), num_coeffs);

        //************************************************
        printf("Benchmarking FFT evaluation with uint32_t packing \n");
        //************************************************

        clock_t t;
        t = clock();
        fft_recursive_uint32(coeffs, num_vars, num_coeffs / 3);
        t = clock() - t;
        double time_taken = ((double)t) / (CLOCKS_PER_SEC / 1000.0); // ms

        printf("FFT (uint32) eval time (total) %f ms\n", time_taken);


        return time_taken;
    }

    double Foleage_FFT8_bench()
    {
        size_t num_vars = NUMVARS;
        size_t num_coeffs = ipow(3, num_vars);
        AlignedUnVector<uint8_t> coeffs (num_coeffs);
        PRNG prng(block(342));
        prng.get(coeffs.data(), num_coeffs);

        //************************************************
        printf("Benchmarking FFT evaluation without packing \n");
        //************************************************

        clock_t t;
        t = clock();
        fft_recursive_uint8(coeffs, num_vars, num_coeffs / 3);
        t = clock() - t;
        double time_taken = ((double)t) / (CLOCKS_PER_SEC / 1000.0); // ms

        printf("FFT (uint8) eval time (total) %f ms\n", time_taken);

        //free(coeffs);

        return time_taken;
    }

    int mainFFT(int argc, char** argv)
    {
        double time = 0;
        int testTrials = 5;

        printf("******************************************\n");
        printf("Testing FFT (uint8 packing)\n");
        for (int i = 0; i < testTrials; i++)
        {
            time += Foleage_FFT8_bench();
            printf("Done with trial %i of %i\n", i + 1, testTrials);
        }
        printf("******************************************\n");
        printf("DONE\n");
        printf("Avg time: %0.2f\n", time / testTrials);
        printf("******************************************\n\n");

        printf("******************************************\n");
        printf("Testing FFT (uint32 packing) \n");
        time = 0;
        for (int i = 0; i < testTrials; i++)
        {
            time += Foleage_FFT32_bench();
            printf("Done with trial %i of %i\n", i + 1, testTrials);
        }
        printf("******************************************\n");
        printf("DONE\n");
        printf("Avg time: %0.2f\n", time / testTrials);
        printf("******************************************\n\n");

        printf("******************************************\n");
        printf("Testing FFT (uint64 packing) \n");
        time = 0;
        for (int i = 0; i < testTrials; i++)
        {
            time += Foleage_FFT64_bench();
            printf("Done with trial %i of %i\n", i + 1, testTrials);
        }
        printf("******************************************\n");
        printf("DONE\n");
        printf("Avg time: %0.2f\n", time / testTrials);
        printf("******************************************\n\n");
        return 0;
    }
}
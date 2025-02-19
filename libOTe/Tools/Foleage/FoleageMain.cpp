#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "libOTe/Tools/Foleage/F4Ops.h"
#include "libOTe/Tools/Foleage/fft/FoleageFft.h"

#include "libOTe/Tools/Foleage/tri-dpf/FoleageDpf.h"
#include "libOTe/Tools/Foleage/tri-dpf/FoleagePrf.h"

#define MAX(a, b) ((a) > (b) ? (a) : (b))

// Benchmarks are less documented compared to test.c; see test.c to
// better understand what is done here for timing purposes.

#define DPF_MSG_SIZE 8
namespace osuCrypto
{


	double bench_pcg(size_t n, size_t c, size_t t)
	{
		if (c > 4)
		{
			printf("ERROR: currently only implemented for c <= 4");
			exit(0);
		}

		const size_t poly_size = ipow(3, n);
		PRNG prng(block(342));

		//************************************************************************
		// Step 0: Sample the global (1, a1 ... a_c-1) polynomials
		//************************************************************************
		AlignedUnVector<uint8_t> fft_a(poly_size);
		AlignedUnVector<uint32_t> fft_a2(poly_size);
		sample_a_and_a2(fft_a, fft_a2, poly_size, c, prng);

		//************************************************************************
		// Step 1: Sample DPF keys for the cross product.
		// For benchmarking purposes, we sample random DPF functions for a
		// sufficiently large domain size to express a block of coefficients.
		//************************************************************************
		size_t dpf_domain_bits = ceil(log_base(poly_size / (t * DPF_MSG_SIZE * 64), 3));
		printf("dpf_domain_bits = %zu \n", dpf_domain_bits);

		size_t seed_size_bits = (128 * (dpf_domain_bits * 3 + 1) + DPF_MSG_SIZE * 128) * c * c * t * t;
		printf("PCG seed size: %.2f MB\n", seed_size_bits / 8000000.0);

		size_t dpf_block_size = DPF_MSG_SIZE * ipow(3, dpf_domain_bits);
		size_t block_size = ceil(poly_size / t);

		printf("block_size = %zu \n", block_size);

		std::vector<DPFKey>dpf_keys_A(c * c * t * t);
		std::vector<DPFKey>dpf_keys_B(c * c * t * t);

		// Sample PRF keys for the DPFs
		PRFKeys prf_keys;
		prf_keys.gen(prng);

		// Sample DPF keys for each of the t errors in the t blocks
		for (size_t i = 0; i < c; i++)
		{
			for (size_t j = 0; j < c; j++)
			{
				for (size_t k = 0; k < t; k++)
				{
					for (size_t l = 0; l < t; l++)
					{
						size_t index = i * c * t * t + j * t * t + k * t + l;

						// Pick a random index for benchmarking purposes
						size_t alpha = random_index(block_size, prng);

						// Pick a random output message for benchmarking purposes
						block beta[DPF_MSG_SIZE];
						prng.get(beta, DPF_MSG_SIZE);

						// Message (beta) is of size 8 blocks of 128 bits
						DPFGen(prf_keys, dpf_domain_bits, alpha, beta, DPF_MSG_SIZE, dpf_keys_A[index], dpf_keys_B[index], prng);
					}
				}
			}
		}

		//************************************************
		printf("Benchmarking PCG evaluation \n");
		//************************************************

		// Allocate memory for the DPF outputs (this is reused for each evaluation)
		AlignedUnVector<block> shares(dpf_block_size);
		AlignedUnVector<block> cache(dpf_block_size);

		// Allocate memory for the concatenated DPF outputs
		const size_t packed_block_size = ceil(block_size / 64.0);
		const size_t packed_poly_size = t * packed_block_size;
		AlignedUnVector<block> packed_polys(c * c * packed_poly_size);

		// Allocate memory for the output FFT
		AlignedUnVector<uint32_t> fft_u(poly_size);

		// Allocate memory for the final inner product
		AlignedUnVector<uint8_t> z_poly(poly_size);
		AlignedUnVector<uint32_t> res_poly_mat(poly_size);

		//************************************************************************
		// Step 3: Evaluate all the DPFs to recover shares of the c*c polynomials.
		//************************************************************************

		clock_t time;
		time = clock();

		size_t key_index;
		block* poly_block;
		size_t i, j, k, l, w;
		for (i = 0; i < c; i++)
		{
			for (j = 0; j < c; j++)
			{
				const size_t poly_index = i * c + j;
				block* packed_poly = &packed_polys[poly_index * packed_poly_size];

				for (k = 0; k < t; k++)
				{
					poly_block = &packed_poly[k * packed_block_size];

					for (l = 0; l < t; l++)
					{
						key_index = i * c * t * t + j * t * t + k * t + l;

						DPFFullDomainEval(dpf_keys_A[key_index], cache, shares);

						for (w = 0; w < packed_block_size; w++)
							poly_block[w] ^= shares[w];
					}
				}
			}
		}

		//************************************************************************
		// Step 3: Compute the transpose of the polynomials to pack them into
		// the parallel FFT format.
		//
		// TODO: this is the bottleneck of the computation and can be improved
		// using SIMD operations for performing matrix transposes (see TODO in test.c).
		//************************************************************************
		for (size_t i = 0; i < c * c; i++)
		{
			size_t poly_index = i * packed_poly_size;
			const block* poly = &packed_polys[poly_index];

#ifdef ENABLE_SSE
			_mm_prefetch((char*)poly, _MM_HINT_T2);
#endif // ENABLE_SSE

			size_t block_idx, packed_coeff_idx, coeff_idx;
			//uint8_t packed_bit_idx;
			block packed_coeff;

			block_idx = 0;
			packed_coeff_idx = 0;
			coeff_idx = 0;

			for (size_t k = 0; k < poly_size - 64; k += 64)
			{
				packed_coeff = poly[block_idx * packed_block_size + packed_coeff_idx];

#ifdef ENABLE_SSE
				_mm_prefetch((char*)&fft_u[k], _MM_HINT_T2);
#endif // ENABLE_SSE
				//__builtin_prefetch(&fft_u[k], 0, 0);
				//__builtin_prefetch(&fft_u[k], 1, 0);

				for (size_t l = 0; l < 64; l++)
				{
					packed_coeff = packed_coeff >> 2;
					fft_u[k + l] |= static_cast<u8>(packed_coeff.get<u8>(0)) & 0b11;
					fft_u[k + l] = fft_u[k + l] << 2;
				}

				packed_coeff_idx++;
				coeff_idx += 64;

				if (coeff_idx > block_size)
				{
					coeff_idx = 0;
					block_idx++;
					packed_coeff_idx = 0;

#ifdef ENABLE_SSE
					_mm_prefetch((char*)&poly[block_idx * packed_block_size], _MM_HINT_T2);
					//__builtin_prefetch(&poly[block_idx * packed_block_size], 0, 2);
#endif // ENABLE_SSE
				}
			}

			packed_coeff = poly[block_idx * packed_block_size + packed_coeff_idx];
			for (size_t k = poly_size - 64 + 1; k < poly_size; k++)
			{
				packed_coeff = packed_coeff >> 2;
				fft_u[k] |= static_cast<u8>(packed_coeff.get<u8>(0)) & 0b11 ;
				fft_u[k] = fft_u[k] << 2;
			}
		}

		fft_recursive_uint32(fft_u, n, poly_size / 3);
		multiply_fft_32(fft_a2, fft_u, res_poly_mat, poly_size);

		// Perform column-wise XORs to get the result
		for (size_t i = 0; i < poly_size; i++)
		{
			// XOR the (packed) columns into the accumulator
			for (size_t j = 0; j < c * c; j++)
			{
				z_poly[i] ^= res_poly_mat[i] & 0b11;
				res_poly_mat[i] = res_poly_mat[i] >> 2;
			}
		}

		time = clock() - time;
		double time_taken = ((double)time) / (CLOCKS_PER_SEC / 1000.0); // ms

		printf("Eval time (total) %f ms\n", time_taken);
		printf("DONE\n\n");

		//DestroyPRFKey(prf_keys);
		//free(fft_a);
		//free(fft_a2);
		//free(dpf_keys_A);
		//free(dpf_keys_B);
		//free(shares);
		//free(cache);
		//free(fft_u);
		//free(packed_polys);
		//free(res_poly_mat);
		//free(z_poly);

		return time_taken;
	}
	
	void printUsage()
    {
        printf("Usage: ./pcg [OPTIONS]\n");
        printf("Options:\n");
        printf("  --test\tTests correctness of the PCG.\n");
        printf("  --bench\tBenchmarks the PCG on conservative and aggressive parameters.\n");
    }

    void runBenchmarks(size_t n, size_t c, size_t t, int num_trials)
    {
        double time = 0;

        for (int i = 0; i < num_trials; i++)
        {
            time += bench_pcg(n, c, t);
            printf("Done with trial %i of %i\n", i + 1, num_trials);
        }
        printf("******************************************\n");
        printf("Avg time (N=3^%zu, c=%zu, t=%zu): %0.4f ms\n", n, c, t, time / num_trials);
        printf("******************************************\n\n");
    }

    int main_foliage(int argc, char** argv)
    {
        int num_trials = 5;

        for (int i = 1; i < argc; i++)
        {
            if (strcmp(argv[i], "--bench") == 0)
            {
                printf("******************************************\n");
                printf("Benchmarking PCG with conservative parameters (c=4, t=27)\n");
                runBenchmarks(14, 4, 27, num_trials);
                runBenchmarks(16, 4, 27, num_trials);
                runBenchmarks(18, 4, 27, num_trials);

                printf("******************************************\n");
                printf("Benchmarking PCG with aggressive parameters (c=3, t=27)\n");
                runBenchmarks(14, 3, 27, num_trials);
                runBenchmarks(16, 3, 27, num_trials);
                runBenchmarks(18, 3, 27, num_trials);
            }
            //else if (strcmp(argv[i], "--test") == 0)
            //{
            //    printf("******************************************\n");
            //    printf("Testing PCG\n");
            //    foliage_pcg_test();
            //    printf("******************************************\n");
            //    printf("PASS\n");
            //    printf("******************************************\n\n");
            //}
            else
            {
                printUsage();
            }
        }

        if (argc == 1)
            printUsage();

        return 0;
    }
}

#include "Foliage_Tests.h"
#include "libOTe/Tools/Foliage/tri-dpf/FoliageDpf.h"
#include "libOTe/Tools/Foliage/fft/FoliageFft.h"
//#include "libOTe/Tools/Foliage/tri-dpf/FoliageHalfDpf.h"
#include "libOTe/Tools/Foliage/F4Ops.h"
#include "cryptoTools/Common/Matrix.h"
namespace osuCrypto
{
	//u8 extractF4(const uint128_t& val, u8 idx)
	//{
	//	auto byteIdx = idx / 4;
	//	auto bitIdx = idx % 4;
	//	auto byte = ((u8*)&val)[byteIdx];
	//	return (byte >> (bitIdx * 2)) & 0b11;
	//}
	int popcount(uint128_t x)
	{
		std::array<u64, 2> xArr;
		memcpy(xArr.data(), &x, 16);
		return popcount(xArr[0]) + popcount(xArr[1]);
	}

	std::array<u8, 64> extractF4(const uint128_t& val)
	{
		std::array<u8, 64> ret;
		const char* ptr = (const char*)&val;
		for (u8 i = 0; i < 16; ++i)
		{
			ret[i * 4 + 0] = (ptr[i] >> 0) & 3;
			ret[i * 4 + 1] = (ptr[i] >> 2) & 3;
			ret[i * 4 + 2] = (ptr[i] >> 4) & 3;
			ret[i * 4 + 3] = (ptr[i] >> 6) & 3;;
		}
		return ret;
	}

	void testOutputCorrectness(
		span<uint128_t> shares0,
		span<uint128_t> shares1,
		size_t num_outputs,
		size_t secret_index,
		span<uint128_t> secret_msg,
		size_t msg_len)
	{
		for (size_t i = 0; i < msg_len; i++)
		{
			uint128_t shareA = shares0[secret_index * msg_len + i];
			uint128_t shareB = shares1[secret_index * msg_len + i];
			uint128_t res = shareA ^ shareB;

			if (res != secret_msg[i])
			{
				printf("FAIL (wrong message)\n");
				exit(0);
			}
		}

		for (size_t i = 0; i < num_outputs; i++)
		{
			if (i == secret_index)
				continue;

			for (size_t j = 0; j < msg_len; j++)
			{
				uint128_t shareA = shares0[i * msg_len + j];
				uint128_t shareB = shares1[i * msg_len + j];
				uint128_t res = shareA ^ shareB;

				if (res != 0)
				{
					printf("FAIL (non-zero) %zu\n", i);
					printBytes(&shareA, 16);
					printBytes(&shareB, 16);

					exit(0);
				}
			}
		}
	}

	void printOutputShares(
		uint128_t* shares0,
		uint128_t* shares1,
		size_t num_outputs,
		size_t msg_len)
	{
		for (size_t i = 0; i < num_outputs; i++)
		{
			for (size_t j = 0; j < msg_len; j++)
			{
				uint128_t shareA = shares0[i * msg_len + j];
				uint128_t shareB = shares1[i * msg_len + j];
				//uint128_t res = shareA ^ shareB;

				printf("(%zu, %zu) %zu\n", i, j, msg_len);
				printBytes(&shareA, 16);
				printBytes(&shareB, 16);
			}
		}
	}



	void testOutputCorrectness_spf(
		span<uint128_t> shares0,
		span<uint128_t> shares1,
		size_t num_outputs,
		size_t secret_index,
		span<uint128_t> secret_msg,
		size_t msg_len)
	{
		for (size_t i = 0; i < msg_len; i++)
		{
			uint128_t shareA = shares0[secret_index * msg_len + i];
			uint128_t shareB = shares1[secret_index * msg_len + i];
			uint128_t res = shareA ^ shareB;

			if (res != secret_msg[i])
			{
				printf("FAIL (wrong message)\n");
				throw RTE_LOC;
			}
		}

		for (size_t i = 0; i < num_outputs; i++)
		{
			if (i == secret_index)
				continue;

			for (size_t j = 0; j < msg_len; j++)
			{
				uint128_t shareA = shares0[i * msg_len + j];
				uint128_t shareB = shares1[i * msg_len + j];
				uint128_t res = shareA ^ shareB;

				if (res != 0)
				{
					printf("FAIL (non-zero) %zu\n", i);
					printBytes(&shareA, 16);
					printBytes(&shareB, 16);
					throw RTE_LOC;
					//exit(0);
				}
			}
		}
	}

	void printOutputShares_spf(
		uint128_t* shares0,
		uint128_t* shares1,
		size_t num_outputs,
		size_t msg_len)
	{
		for (size_t i = 0; i < num_outputs; i++)
		{
			for (size_t j = 0; j < msg_len; j++)
			{
				uint128_t shareA = shares0[i * msg_len + j];
				uint128_t shareB = shares1[i * msg_len + j];
				//uint128_t res = shareA ^ shareB;	  

				printf("(%zu, %zu) %zu\n", i, j, msg_len);
				printBytes(&shareA, 16);
				printBytes(&shareB, 16);
			}
		}
	}

	void foliage_spfss_test()
	{

		size_t SUMT = 730;// sum of T DPFs
		size_t FULLEVALDOMAIN = 10;
		size_t MESSAGESIZE = 8;
		size_t MAXRANDINDEX = ipow(3, FULLEVALDOMAIN);

		const size_t size = FULLEVALDOMAIN; // evaluation will result in 3^size points
		const size_t msg_len = MESSAGESIZE;
		PRNG prng(block(3423423));

		size_t num_leaves = ipow(3, size);

		size_t secret_index = prng.get<u64>() % MAXRANDINDEX;

		// sample a random message of size msg_len
		std::vector<uint128_t> secret_msg(msg_len);
		for (size_t i = 0; i < msg_len; i++)
			secret_msg[i] = prng.get<uint128_t>();

		PRFKeys prf_keys;
		prf_keys.gen(prng);

		std::vector<DPFKey> kA(SUMT);
		std::vector<DPFKey> kB(SUMT);

		for (size_t i = 0; i < SUMT; i++)
			DPFGen(prf_keys, size, secret_index, secret_msg, msg_len, kA[i], kB[i], prng);

		std::vector<uint128_t> shares0(num_leaves * msg_len);
		std::vector<uint128_t> shares1(num_leaves * msg_len);
		std::vector<uint128_t> cache(num_leaves * msg_len);

		//************************************************
		// Test full domain evaluation
		//************************************************

		for (size_t i = 0; i < SUMT; i++)
			DPFFullDomainEval(kA[i], cache, shares0);

		clock_t t;
		t = clock();

		for (size_t i = 0; i < SUMT; i++)
			DPFFullDomainEval(kB[i], cache, shares1); // we can reuse the same shares and cache

		t = clock() - t;
		double time_taken = ((double)t) / (CLOCKS_PER_SEC / 1000.0); // ms

		printf("Time %f ms\n", time_taken);

		// printOutputShares(shares0, shares1, num_leaves, msg_len);

		testOutputCorrectness_spf(
			shares0,
			shares1,
			num_leaves,
			secret_index,
			secret_msg,
			msg_len);

		//DestroyPRFKey(prf_keys);
		//free(kA);
		//free(kB);
		//free(shares0);
		//free(shares1);
		//free(cache);

	}


	void foliage_dpf_test()
	{
		const size_t size = 14; // evaluation will result in 3^size points
		const size_t msg_len = 2;
		PRNG prng(block(342134));

		size_t num_leaves = ipow(3, size);

		size_t secret_index = prng.get<size_t>() % ipow(3, size);

		// sample a random message of size msg_len
		std::vector<uint128_t> secret_msg(msg_len);
		for (size_t i = 0; i < msg_len; i++)
			secret_msg[i] = prng.get<uint128_t>();

		PRFKeys prf_keys;
		prf_keys.gen(prng);

		DPFKey kA;
		DPFKey kB;

		DPFGen(prf_keys, size, secret_index, secret_msg, msg_len, kA, kB, prng);

		std::vector<uint128_t> shares0(num_leaves * msg_len);
		std::vector<uint128_t> shares1(num_leaves * msg_len);
		std::vector<uint128_t> cache(num_leaves * msg_len);

		//************************************************
		// Test full domain evaluation
		//************************************************

		DPFFullDomainEval(kA, cache, shares0);

		clock_t t;
		t = clock();
		DPFFullDomainEval(kB, cache, shares1);
		t = clock() - t;
		double time_taken = ((double)t) / (CLOCKS_PER_SEC / 1000.0); // ms

		printf("Time %f ms\n", time_taken);

		// printOutputShares(shares0, shares1, num_leaves, msg_len);

		testOutputCorrectness(
			shares0,
			shares1,
			num_leaves,
			secret_index,
			secret_msg,
			msg_len);

	}



	// This test case implements Figure 1 from https://eprint.iacr.org/2024/429.pdf.
	// It uses /libs/fft and libs/tri-dpf extensively.
	// Several simplifying design choices are made:
	// 1. We assume that c*c <= 16 so that we can use a parallel FFT packing of F4
	// elements using a uint32_t type.
	// 2. We assume that t is a power of 3 so that the block size of each error
	// vector divides the size of the polynomial. This makes the code significantly
	// more readable and easier to understand.

	// TODO[feature]: The current implementation assumes that C*C <= 16 in order
	// to parallelize the FFTs and other components. Making the code work with
	// arbitrary values of C is left for future work.

	// TODO[feature]: modularize the different components of the test case and
	// design more unit tests.

	u64 log3Ceil(u64 x)
	{
		if (x == 0) return 0;
		u64 i = 0;
		u64 v = 1;
		while (v < x)
		{
			v *= 3;
			i++;
		}
		assert(i == ceil(log_base(x, 3)));

		return i;
	}

	// This test evaluates the full PCG.Expand for both parties and
	// checks correctness of the resulting OLE correlation.
	void foliage_pcg_test(const CLP& cmd)
	{
		bool check = !cmd.isSet("noCheck");
		auto N = 14; // 3^N number of OLEs generated in total

		// The C and T parameters are computed using the SageMath script that can be
		// found in https://github.com/mbombar/estimator_folding

		auto C = 4;// compression factor
		auto T = 27;// noise weight


		clock_t time;
		time = clock();
		PRNG prng(block(54233453245));

		const size_t n = N;
		const size_t c = C;
		const size_t t = T;

		// 3^n
		const size_t poly_size = ipow(3, n);

		//************************************************************************
		// Step 0: Sample the global (1, a1 ... a_c-1) polynomials
		//************************************************************************
		std::vector<uint8_t> fft_a(poly_size);
		std::vector<uint32_t> fft_a2(poly_size);
		sample_a_and_a2(fft_a, fft_a2, poly_size, c, prng);

		//************************************************************************
		// Here, we figure out a good block size for the error vectors such that
		// t*block_size = 3^n and block_size/L*128 is close to a power of 3.
		// We pack L=256 coefficients of F4 into each DPF output (note that larger
		// packing values are also okay, but they will do increase key size).
		//************************************************************************
		size_t dpf_domain_bits = log3Ceil(divCeil(poly_size, t * 256.0));
		if (dpf_domain_bits == 0)
			dpf_domain_bits = 1;

		printf("DPF domain bits %zu \n", dpf_domain_bits);

		// 4*128 ==> 256 coefficients in F4
		size_t dpf_block_size = 4 * ipow(3, dpf_domain_bits);

		printf("dpf_block_size = %zu\n", dpf_block_size);

		// Note: We assume that t is a power of 3 and so it divides poly_size
		assert(poly_size % t == 0);

		// the size of a single regular block. We have t blocks in each polynomial
		// poly_size = 2^n / t = 3^{n-3}
		size_t block_size = poly_size / t;

		printf("block_size = %zu \n", block_size);

		printf("[       ]Done with Step 0 (sampling the public values)\n");

		//************************************************************************
		// Step 1: Sample error polynomials eA and eB (c polynomials in total)
		// each polynomial is t-sparse and has degree (t * block_size) = poly_size.
		//************************************************************************
		std::vector<uint8_t> err_polys_A(c * poly_size);
		std::vector<uint8_t> err_polys_B(c * poly_size);

		// coefficients associated with each error vector
		std::vector<uint8_t> err_poly_coeffs_A(c * t);
		std::vector<uint8_t> err_poly_coeffs_B(c * t);

		// positions of the T errors in each error vector
		std::vector<size_t> err_poly_positions_A(c * t);
		std::vector<size_t> err_poly_positions_B(c * t);

		for (size_t i = 0; i < c; i++)
		{
			for (size_t j = 0; j < t; j++)
			{
				size_t offset = i * t + j;

				// random *non-zero* coefficients in F4
				uint8_t a = rand_f4x(prng);
				uint8_t b = rand_f4x(prng);
				err_poly_coeffs_A[offset] = a;
				err_poly_coeffs_B[offset] = b;

				// random index within the block
				size_t pos_A = random_index(block_size - 1, prng);
				size_t pos_B = random_index(block_size - 1, prng);

				if (pos_A >= block_size || pos_B >= block_size)
				{
					printf("FAIL: position > block_size: %zu, %zu\n", pos_A, pos_B);
					throw RTE_LOC;
					//exit(0);
				}

				err_poly_positions_A[offset] = pos_A;
				err_poly_positions_B[offset] = pos_B;

				// set the coefficient at the error position to the error value
				err_polys_A[i * poly_size + j * block_size + pos_A] = a;
				err_polys_B[i * poly_size + j * block_size + pos_B] = b;
			}
		}

		// Compute FFT of eA and eB in packed form.
		// Note that because c = 4, we can pack 4 FFTs into a uint8_t
		std::vector<uint8_t> fft_eA(poly_size);
		std::vector<uint8_t> fft_eB(poly_size);
		uint8_t coeff_A, coeff_B;

		// This loop essentially computes a transpose to pack the coefficients
		// of each polynomial into one "row" of the parallel FFT matrix
		for (size_t j = 0; j < c; j++)
		{
			for (size_t i = 0; i < poly_size; i++)
			{
				// extract the i-th coefficient of the j-th error polynomial
				coeff_A = err_polys_A[j * poly_size + i];
				coeff_B = err_polys_B[j * poly_size + i];

				// pack the extracted coefficient into the j-th FFT slot
				fft_eA[i] |= (coeff_A << (2 * j));
				fft_eB[i] |= (coeff_B << (2 * j));
			}
		}

		// Evaluate the FFTs on the error polynomials eA and eB
		fft_recursive_uint8(fft_eA, n, poly_size / 3);
		fft_recursive_uint8(fft_eB, n, poly_size / 3);

		printf("[.      ]Done with Step 1 (sampling error vectors)\n");

		//************************************************************************
		// Step 2: compute the inner product xA = <a, eA> and xB = <a, eB>
		//************************************************************************

		// Initialize polynomials to zero (accumulators for inner product)
		std::vector<uint8_t> x_poly_A(poly_size);
		std::vector<uint8_t> x_poly_B(poly_size);

		// Compute the coordinate-wise multiplication over the packed FFT result
		std::vector<uint8_t> res_poly_A(poly_size);
		std::vector<uint8_t> res_poly_B(poly_size);
		multiply_fft_8(fft_a, fft_eA, res_poly_A, poly_size); // a*eA
		multiply_fft_8(fft_a, fft_eB, res_poly_B, poly_size); // a*eB

		// XOR the result into the accumulator.
		// Specifically, we XOR all the columns of the FFT result to get a
		// vector of size poly_size.
		for (size_t j = 0; j < c; j++)
		{
			for (size_t i = 0; i < poly_size; i++)
			{
				x_poly_A[i] ^= (res_poly_A[i] >> (2 * j)) & 0b11;
				x_poly_B[i] ^= (res_poly_B[i] >> (2 * j)) & 0b11;
			}
		}

		printf("[..     ]Done with Step 2 (computing the local vectors)\n");

		//************************************************************************
		// Step 3: Compute cross product (eA x eB) using the position vectors
		//************************************************************************
		std::vector<uint8_t> err_poly_cross_coeffs(c * c * t * t);
		std::vector<size_t> err_poly_cross_positions(c * c * t * t);
		std::vector<uint8_t> err_polys_cross(c * c * poly_size);
		std::vector<uint8_t> trit_decomp_A(n);
		std::vector<uint8_t> trit_decomp_B(n);
		std::vector<uint8_t> trit_decomp(n);

		for (size_t iA = 0; iA < c; iA++)
		{
			for (size_t iB = 0; iB < c; iB++)
			{
				size_t poly_index = iA * c * t * t + iB * t * t;
				std::vector<uint8_t> next_idx(t);

				for (size_t jA = 0; jA < t; jA++)
				{
					for (size_t jB = 0; jB < t; jB++)
					{
						// jA-th coefficient value of the iA-th polynomial
						uint8_t vA = err_poly_coeffs_A[iA * t + jA];

						// jB-th coefficient value of the iB-th polynomial
						uint8_t vB = err_poly_coeffs_B[iB * t + jB];

						// Resulting cross-product coefficient
						uint8_t v = mult_f4(vA, vB);

						// Compute the position (in the full polynomial)
						size_t posA = jA * block_size + err_poly_positions_A[iA * t + jA];
						size_t posB = jB * block_size + err_poly_positions_B[iB * t + jB];

						if (err_polys_A[iA * poly_size + posA] == 0)
						{
							printf("FAIL: Incorrect position recovered\n");
							throw RTE_LOC;
							//exit(0);
						}

						if (err_polys_B[iB * poly_size + posB] == 0)
						{
							printf("FAIL: Incorrect position recovered\n");
							throw RTE_LOC;
						}

						// Decompose the position into the ternary basis
						int_to_trits(posA, trit_decomp_A, n);
						int_to_trits(posB, trit_decomp_B, n);

						// printf("[DEBUG]: posA=%zu, posB=%zu\n", posA, posB);

						// Sum ternary decomposition coordinate-wise to
						// get the new position (in ternary).
						for (size_t k = 0; k < n; k++)
						{
							// printf("[DEBUG]: trits_A[%zu]=%i, trits_B[%zu]=%i\n",
							//    k, trit_decomp_A[k], k, trit_decomp_B[k]);
							trit_decomp[k] = (trit_decomp_A[k] + trit_decomp_B[k]) % 3;
						}

						// Get back the resulting cross-product position as an integer
						size_t pos = trits_to_int(trit_decomp, n);
						size_t block_idx = floor(pos / block_size); // block index in polynomial
						//size_t in_block_idx = pos % block_size;     // index within the block

						err_polys_cross[(iA * c + iB) * poly_size + pos] ^= v;

						size_t idx = next_idx[block_idx];
						next_idx[block_idx]++;

						// printf("[DEBUG]: pos=%zu, block_idx=%zu, idx=%zu\n", pos, block_idx, idx);
						err_poly_cross_coeffs[poly_index + block_idx * t + idx] = v;
						err_poly_cross_positions[poly_index + block_idx * t + idx] = pos % block_size;
					}
				}

				for (size_t k = 0; k < t; k++)
				{
					if (next_idx[k] > t)
					{
						std::cout << "FAIL: next_idx > t at the end: " << next_idx[k] << std::endl;
						throw RTE_LOC;
					}
				}

				//free(next_idx);
			}
		}

		// cleanup temporary values
		//free(trit_decomp);
		//free(trit_decomp_A);
		//free(trit_decomp_B);

		printf("[...    ]Done with Step 3 (computing the cross product)\n");

		//************************************************************************
		// Step 4: Sample the DPF keys for the cross product (eA x eB)
		//************************************************************************

		std::vector<DPFKey> dpf_keys_A(c * c * t * t);
		std::vector<DPFKey> dpf_keys_B(c * c * t * t);

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

						// Parse the index into the right format
						size_t alpha = err_poly_cross_positions[index];

						// Output message index in the DPF output space
						// which consists of 256 F4 elements
						size_t alpha_0 = floor(alpha / 256.0);

						// Coeff index in the block of 256 coefficients
						size_t alpha_1 = alpha % 256;

						// Coeff index in the uint128_t output (64 elements of F4)
						size_t packed_idx = floor(alpha_1 / 64.0);

						// Bit index in the uint128_t ouput
						size_t bit_idx = alpha_1 % 64;

						// Set the DPF message to the coefficient
						uint128_t coeff = uint128_t(err_poly_cross_coeffs[index]);

						// Position coefficient into the block
						std::array<uint128_t, 4> beta; // init to zero
						setBytes(beta, 0);
						beta[packed_idx] = coeff << (2 * (63 - bit_idx));

						// Message (beta) is of size 4 blocks of 128 bits
						DPFGen(prf_keys, dpf_domain_bits, alpha_0, beta, 4, dpf_keys_A[index], dpf_keys_B[index], prng);
					}
				}
			}
		}

		printf("[....   ]Done with Step 4 (sampling DPF keys)\n");

		//************************************************************************
		// Step 5: Evaluate the DPFs to compute shares of (eA x eB)
		//************************************************************************

		// Allocate memory for the DPF outputs (this is reused for each evaluation)
		std::vector<uint128_t> shares_A(dpf_block_size);
		std::vector<uint128_t> shares_B(dpf_block_size);
		std::vector<uint128_t> cache(dpf_block_size);

		// Allocate memory for the concatenated DPF outputs
		size_t packed_block_size = divCeil(block_size, 64);
		size_t packed_poly_size = t * packed_block_size;

		// printf("[DEBUG]: packed_block_size = %zu\n", packed_block_size);
		// printf("[DEBUG]: packed_poly_size = %zu\n", packed_poly_size);
		// 
		// each row is a block. every t rows is a polynomial.
		Matrix<uint128_t> packed_polys_A_(c * c * t, packed_block_size);
		Matrix<uint128_t> packed_polys_B_(c * c * t, packed_block_size);
		//std::vector<uint128_t> packed_polys_A(c * c * packed_poly_size);
		//std::vector<uint128_t> packed_polys_B(c * c * packed_poly_size);

		// Allocate memory for the output FFT
		std::vector<uint32_t>fft_uA(poly_size);
		std::vector<uint32_t>fft_uB(poly_size);
		//std::vector<uint32_t>fft_uA2(poly_size);
		//std::vector<uint32_t>fft_uB2(poly_size);

		// Allocate memory for the final inner product
		std::vector<uint8_t> z_poly_A(poly_size);
		std::vector<uint8_t> z_poly_B(poly_size);
		std::vector<uint32_t> res_poly_mat_A(poly_size);
		std::vector<uint32_t> res_poly_mat_B(poly_size);

		auto dpf_keys_A_iter = dpf_keys_A.begin();
		auto dpf_keys_B_iter = dpf_keys_B.begin();

		for (size_t i = 0; i < c; i++)
		{
			for (size_t j = 0; j < c; j++)
			{
				const size_t poly_index = i * c + j;

				oc::MatrixView<uint128_t> packed_polyA_(packed_polys_A_.data(poly_index * t), t, packed_block_size);
				oc::MatrixView<uint128_t> packed_polyB_(packed_polys_B_.data(poly_index * t), t, packed_block_size);
				//uint128_t* packed_polyA = &packed_polys_A[poly_index * packed_poly_size];
				//uint128_t* packed_polyB = &packed_polys_B[poly_index * packed_poly_size];

				for (size_t k = 0; k < t; k++)
				{
					span<uint128_t> poly_blockA = packed_polyA_[k];
					span<uint128_t> poly_blockB = packed_polyB_[k];

					for (size_t l = 0; l < t; l++)
					{

						DPFKey& dpf_keyA = *dpf_keys_A_iter++;
						DPFKey& dpf_keyB = *dpf_keys_B_iter++;

						DPFFullDomainEval(dpf_keyA, cache, shares_A);
						DPFFullDomainEval(dpf_keyB, cache, shares_B);

						// Sum all the DPFs for the current block together
						// note that there is some extra "garbage" in the last
						// block of uint128_t since 64 does not divide block_size.
						// We deal with this slack later when packing the outputs
						// into the parallel FFT matrix.
						for (size_t w = 0; w < packed_block_size; w++)
						{
							poly_blockA[w] ^= shares_A[w];
							poly_blockB[w] ^= shares_B[w];
						}
					}
				}
			}
		}


		if (check)
		{

			// Here, we test to make sure all polynomials have at most t^2 errors
			// and fail the test otherwise.
			for (size_t i = 0; i < c; i++)
			{
				for (size_t j = 0; j < c; j++)
				{
					size_t err_count = 0;
					size_t poly_index = i * c + j;

					oc::MatrixView<uint128_t> packed_polyA_(packed_polys_A_.data(poly_index * t), t, packed_block_size);
					oc::MatrixView<uint128_t> packed_polyB_(packed_polys_B_.data(poly_index * t), t, packed_block_size);
					//uint128_t* poly_A = &packed_polys_A[poly_index * packed_poly_size];
					//uint128_t* poly_B = &packed_polys_B[poly_index * packed_poly_size];

					for (size_t p = 0; p < packed_poly_size; p++)
					{
						uint128_t res = packed_polyA_(p) ^ packed_polyB_(p);
						if (res)
						{
							auto e = extractF4(res);
							for (size_t l = 0; l < 64; l++)
							{
								//if (((res >> (2 * (63 - l))) & uint128_t(0b11)) != uint128_t(0))
								err_count += (e[l] | (e[l] >> 1)) & 1;
								//if (e[l])
								//	err_count++;
							}
						}
					}

					// printf("[DEBUG]: Number of non-zero coefficients in poly (%zu,%zu) is %zu\n", i, j, err_count);

					if (err_count > t * t)
					{
						printf("FAIL: Number of non-zero coefficients is %zu > t*t\n", err_count);
						throw RTE_LOC;
					}
					else if (err_count == 0)
					{
						printf("FAIL: Number of non-zero coefficients in poly (%zu,%zu) is %zu\n", i, j, err_count);
						throw RTE_LOC;
					}
				}
			}
		}
		printf("[.....  ]Done with Step 5 (evaluating all DPFs)\n");

		//************************************************************************
		// Step 6: Compute an FFT over the shares of (eA x eB)
		//************************************************************************

		// Pack the coefficients into FFT blocks
		//
		// TODO[optimization]: use AVX and fast matrix transposition algorithms.
		// The transpose is the bottleneck of the current implementation and
		// therefore improving this step can result in significant performance gains.

		if (check)
		{

			for (size_t j = 0; j < c; j++)
			{
				for (size_t k = 0; k < c; k++)
				{
					std::vector<uint8_t> test_poly_A(poly_size);
					std::vector<uint8_t> test_poly_B(poly_size);

					size_t poly_index = j * c + k;

					oc::MatrixView<uint128_t> poly_A(packed_polys_A_.data(poly_index * t), t, packed_block_size);
					oc::MatrixView<uint128_t> poly_B(packed_polys_B_.data(poly_index * t), t, packed_block_size);

					//uint128_t* poly_A = &packed_polys_A[poly_index * packed_poly_size];
					//uint128_t* poly_B = &packed_polys_B[poly_index * packed_poly_size];

					u64 i = 0;
					for (u64 block_idx = 0; block_idx < t; ++block_idx)
					{
						for (u64 packed_idx = 0; packed_idx < packed_block_size; ++packed_idx)
						{
							auto coeffA = extractF4(poly_A(block_idx, packed_idx));
							auto coeffB = extractF4(poly_B(block_idx, packed_idx));

							//auto idx = j * c + k;
							//if (idx >= 16)
							//	throw RTE_LOC;
							auto e = std::min<u64>(block_size - packed_idx * 64, 64);
							for (u64 element_idx = 0; element_idx < e; ++element_idx)
							{
								test_poly_A[i] = coeffA[63 - element_idx];
								test_poly_B[i] = coeffB[63 - element_idx];
								++i;
							}
						}
					}

					for (size_t i = 0; i < poly_size; i++)
					{
						uint8_t exp_coeff = err_polys_cross[j * c * poly_size + k * poly_size + i];
						uint8_t got_coeff = test_poly_A[i] ^ test_poly_B[i];

						if (got_coeff != exp_coeff)
						{
							printf("FAIL: incorrect cross coefficient at index %zu (%i =/= %i)\n", i, got_coeff, exp_coeff);
							throw RTE_LOC;
						}
					}

				}
			}
		}

		// TODO[optimization]: for arbitrary values of C, we only need to perform
		// C*(C+1)/2 FFTs which can lead to a more efficient implementation.
		// Because we assume C=4, we have C*C = 16 which fits perfectly into a
		// uint32 packing.

		for (size_t j = 0; j < c; j++)
		{
			for (size_t k = 0; k < c; k++)
			{
				size_t poly_index = (j * c + k);// *packed_poly_size;

				oc::MatrixView<uint128_t> polyA(packed_polys_A_.data(poly_index * t), t, packed_block_size);
				oc::MatrixView<uint128_t> polyB(packed_polys_B_.data(poly_index * t), t, packed_block_size);

				u64 i = 0;
				for (u64 block_idx = 0; block_idx < t; ++block_idx)
				{
					for (u64 packed_idx = 0; packed_idx < packed_block_size; ++packed_idx)
					{
						auto coeffA = extractF4(polyA(block_idx, packed_idx));
						auto coeffB = extractF4(polyB(block_idx, packed_idx));

						//auto idx = j * c + k;
						//if (idx >= 16)
						//	throw RTE_LOC;
						auto e = std::min<u64>(block_size - packed_idx * 64, 64);

						for (u64 element_idx = 0; element_idx < e; ++element_idx)
						{
							fft_uA[i] |= u32{ coeffA[63 - element_idx] } << (2 * poly_index);
							fft_uB[i] |= u32{ coeffB[63 - element_idx] } << (2 * poly_index);
							++i;
						}
					}
				}
			}
		}

		fft_recursive_uint32(fft_uA, n, poly_size / 3);
		fft_recursive_uint32(fft_uB, n, poly_size / 3);

		printf("[...... ]Done with Step 6 (computing FFTs)\n");

		//************************************************************************
		// Step 7: Compute shares of z = <axa, u>
		//************************************************************************
		multiply_fft_32(fft_a2, fft_uA, res_poly_mat_A, poly_size);
		multiply_fft_32(fft_a2, fft_uB, res_poly_mat_B, poly_size);

		//size_t num_ffts = c * c;

		// XOR the (packed) columns into the accumulator.
		// Specifically, we perform column-wise XORs to get the result.
		uint128_t lsbMask, msbMask;
		setBytes(lsbMask, 0b01010101);
		setBytes(msbMask, 0b10101010);
		for (size_t i = 0; i < poly_size; i++)
		{
			//auto resA = extractF4(res_poly_mat_A[i]);
			//auto resB = extractF4(res_poly_mat_B[i]);

			z_poly_A[i] =
				popcount(res_poly_mat_A[i] & lsbMask) & 1 |
				(popcount(res_poly_mat_A[i] & msbMask) & 1) << 1;

			z_poly_B[i] =
				popcount(res_poly_mat_B[i] & lsbMask) & 1 |
				(popcount(res_poly_mat_B[i] & msbMask) & 1) << 1;

			//u8 aSum = 0;

			//for (size_t j = 0; j < c * c; j++)
			//{
			//	aSum ^= resA[j];
			//}

			//if ((aSum & 1) != aLsb)
			//	throw RTE_LOC;
			//if (((aSum>>1) & 1) != aMsb)
			//	throw RTE_LOC;

			//for (size_t j = 0; j < c * c; j++)
			//{
			//	z_poly_A[i] ^= resA[j];
			//	z_poly_B[i] ^= resB[j];
			//}
		}

		// Now we check that we got the correct OLE correlations and fail
		// the test otherwise.
		for (size_t i = 0; i < poly_size; i++)
		{
			uint8_t res = z_poly_A[i] ^ z_poly_B[i];
			uint8_t exp = mult_f4(x_poly_A[i], x_poly_B[i]);

			// printf("[DEBUG]: Got: (%i,%i), Expected: (%i, %i)\n",
			//        (res >> 1) & 1, res & 1, (exp >> 1) & 1, exp & 1);

			if (res != exp)
			{
				printf("FAIL: Incorrect correlation output at index %zu\n", i);
				printf("Got: (%i,%i), Expected: (%i, %i)\n",
					(res >> 1) & 1, res & 1, (exp >> 1) & 1, exp & 1);
				throw RTE_LOC;

			}
		}

		time = clock() - time;
		double time_taken = ((double)time) / (CLOCKS_PER_SEC / 1000.0); // ms

		printf("[.......]Done with Step 7 (recovering shares)\n\n");

		printf("Time elapsed %f ms\n", time_taken);

	}

}
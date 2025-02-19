#pragma once


#include <stdint.h>
#include "cryptoTools/Crypto/AES.h"
//#include "utils.h"
#include "libOTe/Tools/Foleage/FoleageUtils.h"

namespace osuCrypto
{


	using EVP_CIPHER_CTX = oc::AES;
	struct PRFKeys
	{
		PRFKeys() = default;
		

		void gen(PRNG& prng)
		{
			prf_key0.setKey(prng.get());
			prf_key1.setKey(prng.get());
			prf_key2.setKey(prng.get());
			prf_key_ext.setKey(prng.get());
		}



		EVP_CIPHER_CTX prf_key0;
		EVP_CIPHER_CTX prf_key1;
		EVP_CIPHER_CTX prf_key2;
		EVP_CIPHER_CTX prf_key_ext;
	};

	//void PRFKeyGen(struct PRFKeys* prf_keys);
	//void DestroyPRFKey(struct PRFKeys* prf_keys);

	// XOR with input to prevent inversion using Davies–Meyer construction
	inline void PRFEval(EVP_CIPHER_CTX& ctx, block& input, block& outputs)
	{
		outputs = ctx.hashBlock(input);
	}

	// PRF used to expand the DPF tree. Just a call to AES-ECB.
	// Note: we use ECB-mode (instead of CTR) as we want to manage each block separately.
	// XOR with input to prevent inversion using Davies–Meyer construction
	inline void PRFBatchEval(EVP_CIPHER_CTX& ctx, span<block> input, span<block> outputs, u64 num_blocks)
	{
		if (num_blocks > input.size())
			throw RTE_LOC;
		if (num_blocks > outputs.size())
			throw RTE_LOC;
		ctx.hashBlocks((block*)input.data(), num_blocks, (block*)outputs.data());
	}

	// extends the output by the provided factor using the PRG
	inline void ExtendOutput(
		PRFKeys& prf_keys,
		span<block> output,
		span<block> cache,
		const size_t output_size,
		const size_t new_output_size)
	{

		if (new_output_size % output_size != 0)
			throw std::runtime_error("ERROR: new_output_size needs to be a multiple of output_size. " LOCATION);
		if (new_output_size < output_size)
			throw std::runtime_error("ERROR: new_output_size < output_size" LOCATION);

		size_t factor = new_output_size / output_size;

		for (size_t i = 0; i < output_size; i++)
		{
			for (size_t j = 0; j < factor; j++)
				cache[i * factor + j] = output[i] ^ block(0, j);
		}

		PRFBatchEval(prf_keys.prf_key_ext, cache, output, new_output_size);
	}
}


#include "FoleageDpf.h"

#include "libOTe/Tools/Foleage/tri-dpf/TriDpfUtils.h"


//#include <openssl/rand.h>

#define LOG_BATCH_SIZE 6 // operate in smallish batches to maximize cache hits
namespace osuCrypto
{

	// Naming conventions:
	// - A,B refer to shares given to parties A and B
	// - 0,1,2 refer to the branch index in the ternary tree
	void DPFGen(
		PRFKeys& prf_keys,
		size_t domain_size,
		size_t index,
		span<block> msg_blocks,
		size_t msg_block_len,
		DPFKey& k0,
		DPFKey& k1,
		PRNG& prng)
	{

		// starting seeds given to each party
		block seedA = prng.get();
		block seedB = prng.get();

		// correction word provided to both parties
		// (one correction word per level)
		std::vector<block> sCW0(domain_size);
		std::vector<block> sCW1(domain_size);
		std::vector<block> sCW2(domain_size);

		// variables for the intermediate values
		block parent, parentA, parentB, sA0, sA1, sA2, sB0, sB1, sB2;

		// current parent value (xor of the two seeds)
		parent = seedA ^ seedB;

		// control bit of the parent on the special path must always be set to 1
		// so as to apply the corresponding correction word
		if (get_lsb(parent) == ZeroBlock)
			seedA = flip_lsb(seedA);

		parentA = seedA;
		parentB = seedB;

		block prev_control_bit_A, prev_control_bit_B;

		for (size_t i = 0; i < domain_size; i++)
		{
			prev_control_bit_A = get_lsb(parentA);
			prev_control_bit_B = get_lsb(parentB);

			// expand the starting seeds of each party
			PRFEval(prf_keys.prf_key0, parentA, sA0);
			PRFEval(prf_keys.prf_key1, parentA, sA1);
			PRFEval(prf_keys.prf_key2, parentA, sA2);
			PRFEval(prf_keys.prf_key0, parentB, sB0);
			PRFEval(prf_keys.prf_key1, parentB, sB1);
			PRFEval(prf_keys.prf_key2, parentB, sB2);

			// on-path correction word is set to random
			// so as to be indistinguishable from the real correction words
			block r = prng.get();

			// get the current trit (ternary bit) of the special index
			uint8_t trit = get_trit(index, domain_size, i);

			switch (trit)
			{
			case 0:
				parent = sA0 ^ sB0 ^ r;
				if (get_lsb(parent) == ZeroBlock)
					r = flip_lsb(r);

				sCW0[i] = r;
				sCW1[i] = sA1 ^ sB1;
				sCW2[i] = sA2 ^ sB2;

				if (get_lsb(parentA) == AllOneBlock)
				{
					parentA = sA0 ^ r;
					parentB = sB0;
				}
				else
				{
					parentA = sA0;
					parentB = sB0 ^ r;
				}

				break;

			case 1:
				parent = sA1 ^ sB1 ^ r;
				if (get_lsb(parent) == ZeroBlock)
					r = flip_lsb(r);

				sCW0[i] = sA0 ^ sB0;
				sCW1[i] = r;
				sCW2[i] = sA2 ^ sB2;

				if (get_lsb(parentA) == AllOneBlock)
				{
					parentA = sA1 ^ r;
					parentB = sB1;
				}
				else
				{
					parentA = sA1;
					parentB = sB1 ^ r;
				}

				break;

			case 2:
				parent = sA2 ^ sB2 ^ r;
				if (get_lsb(parent) == ZeroBlock)
					r = flip_lsb(r);

				sCW0[i] = sA0 ^ sB0;
				sCW1[i] = sA1 ^ sB1;
				sCW2[i] = r;

				if (get_lsb(parentA) == AllOneBlock)
				{
					parentA = sA2 ^ r;
					parentB = sB2;
				}
				else
				{
					parentA = sA2;
					parentB = sB2 ^ r;
				}

				break;

			default:
				printf("error: not a ternary digit!\n");
				exit(0);
			}
		}

		// set the last correction word to correct the output to msg
		block leaf_seedA, leaf_seedB;
		uint8_t last_trit = get_trit(index, domain_size, domain_size - 1);
		if (last_trit == 0)
		{
			leaf_seedA = sA0 ^ prev_control_bit_A & sCW0[domain_size - 1];
			leaf_seedB = sB0 ^ prev_control_bit_B & sCW0[domain_size - 1];
		}
		else if (last_trit == 1)
		{
			leaf_seedA = sA1 ^ prev_control_bit_A & sCW1[domain_size - 1];
			leaf_seedB = sB1 ^ prev_control_bit_B & sCW1[domain_size - 1];
		}					   

		else if (last_trit == 2)
		{
			leaf_seedA = sA2 ^ prev_control_bit_A & sCW2[domain_size - 1];
			leaf_seedB = sB2 ^ prev_control_bit_B & sCW2[domain_size - 1];
		}

		AlignedUnVector<block> outputA(msg_block_len);
		AlignedUnVector<block> outputB(msg_block_len);
		AlignedUnVector<block> cache(msg_block_len);
		AlignedUnVector<block> outputCW(msg_block_len);

		outputA[0] = leaf_seedA;
		outputB[0] = leaf_seedB;

		ExtendOutput(prf_keys, outputA, cache, 1, msg_block_len);
		ExtendOutput(prf_keys, outputB, cache, 1, msg_block_len);

		for (size_t i = 0; i < msg_block_len; i++)
			outputCW[i] = outputA[i] ^ outputB[i] ^ msg_blocks[i];

		// memcpy all the generated values into two keys
		// 16 = sizeof(uint128_t)
		size_t key_size = sizeof(block);			 // initial seed size;
		key_size += 3 * domain_size * sizeof(block); // correction words
		key_size += sizeof(block) * msg_block_len;	 // output correction word

		k0.prf_keys = &prf_keys;
		k0.k.resize(key_size);
		k0.size = domain_size;
		k0.msg_len = msg_block_len;
		memcpy(&k0.k[0], &seedA, 16);
		memcpy(&k0.k[16], &sCW0[0], domain_size * 16);
		memcpy(&k0.k[16 * domain_size + 16], &sCW1[0], domain_size * 16);
		memcpy(&k0.k[16 * 2 * domain_size + 16], &sCW2[0], domain_size * 16);
		memcpy(&k0.k[16 * 3 * domain_size + 16], &outputCW[0], msg_block_len * 16);

		k1.prf_keys = &prf_keys;
		k1.k.resize(key_size);
		k1.size = domain_size;
		k1.msg_len = msg_block_len;
		memcpy(&k1.k[0], &seedB, 16);
		memcpy(&k1.k[16], &sCW0[0], domain_size * 16);
		memcpy(&k1.k[16 * domain_size + 16], &sCW1[0], domain_size * 16);
		memcpy(&k1.k[16 * 2 * domain_size + 16], &sCW2[0], domain_size * 16);
		memcpy(&k1.k[16 * 3 * domain_size + 16], &outputCW[0], msg_block_len * 16);

		//free(outputA);
		//free(outputB);
		//free(cache);
		//free(outputCW);
	}

	// evaluates the full DPF domain; much faster than
	// batching the evaluation points since each level of the DPF tree
	// is only expanded once.
	void DPFFullDomainEval(
		DPFKey& key,
		span<block> cache,
		span<block> output)
	{
		size_t size = key.size;
		span<u8> k = key.k;
		PRFKeys& prf_keys = *key.prf_keys;

		if (size % 2 == 1)
		{
			auto tmp = cache;
			cache = output;
			output = tmp;
		}

		// full_eval_size = pow(3, size);
		const size_t num_leaves = ipow(3, size);

		memcpy(&output[0], &k[0], 16); // output[0] is the start seed
		const block* sCW0 = (block*)&k[16];
		const block* sCW1 = (block*)&k[16 * size + 16];
		const block* sCW2 = (block*)&k[16 * 2 * size + 16];

		// inner loop variables related to node expansion
		// and correction word application
		span<block> tmp;
		size_t idx0, idx1, idx2;
		block cb = ZeroBlock;

		// batching variables related to chunking of inner loop processing
		// for the purpose of maximizing cache hits
		size_t max_batch_size = ipow(3, LOG_BATCH_SIZE);
		size_t batch, num_batches, batch_size, offset;

		size_t num_nodes = 1;
		for (uint8_t i = 0; i < size; i++)
		{
			if (i < LOG_BATCH_SIZE)
			{
				batch_size = num_nodes;
				num_batches = 1;
			}
			else
			{
				batch_size = max_batch_size;
				num_batches = num_nodes / max_batch_size;
			}

			offset = 0;
			for (batch = 0; batch < num_batches; batch++)
			{
				PRFBatchEval(prf_keys.prf_key0, output.subspan(offset), cache.subspan(offset), batch_size);
				PRFBatchEval(prf_keys.prf_key1, output.subspan(offset), cache.subspan(num_nodes + offset), batch_size);
				PRFBatchEval(prf_keys.prf_key2, output.subspan(offset), cache.subspan((num_nodes * 2) + offset), batch_size);

				idx0 = offset;
				idx1 = num_nodes + offset;
				idx2 = (num_nodes * 2) + offset;

				while (idx0 < offset + batch_size)
				{
					cb = get_lsb(output[idx0]); // gets the LSB of the parent
					cache[idx0] ^= (cb & sCW0[i]);
					cache[idx1] ^= (cb & sCW1[i]);
					cache[idx2] ^= (cb & sCW2[i]);

					idx0++;
					idx1++;
					idx2++;
				}

				offset += batch_size;
			}

			tmp = output;
			output = cache;
			cache = tmp;

			num_nodes *= 3;
		}

		const size_t output_length = key.msg_len * num_leaves;
		const size_t msg_len = key.msg_len;
		block* outputCW = (block*)&k[16 * 3 * size + 16];
		ExtendOutput(prf_keys, output, cache, num_leaves, output_length);

		size_t j = 0;
		for (size_t i = 0; i < num_leaves; i++)
		{
			// TODO: a bit hacky, assumes that cache[i*msg_len] = old_output[i]
			// which is the case internally in ExtendOutput. It would be good
			// to remove this assumption however using memcpy is costly...

			if (get_lsb(cache[i * msg_len]) != ZeroBlock) // parent control bit
			{
				for (j = 0; j < msg_len; j++)
					output[i * msg_len + j] ^= outputCW[j];
			}
		}
	}
}
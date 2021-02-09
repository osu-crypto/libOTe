#ifndef __LDPC_ENCODER_H
#define __LDPC_ENCODER_H
#include "LDPC_generator.h"
#include "simple_bitarray.h"
#include <vector>

//encode an LDPC code from a given parity check matrix/Tanner graph
class LDPC_encoder{
private:
	int code_len;
	int msg_len;

	std::vector<int> parity_nodes;
	
	std::vector<std::vector<int>> parities;
public:
	LDPC_encoder(int code_len, int msg_len);
	~LDPC_encoder();

	//init by a generator
	bool init(LDPC_generator* generator, int& actual_msg_len);
	//init by a buffered matrix saved to filename
	//bool init(const char* filename);
	//save the generated matrix to filename
	//bool save_parities_to(const char* filename);

	//encode a bit array
	void encode(const bit_array_t& bitarr, bit_array_t& dest);
	//encode an arbitary array
	template<typename T>
	void encode(const T* arr, int arrsize, T* dest){
		int size = parity_nodes.size();
		for (int i = 0, it = 0; i < code_len; i++){
			if (it < size && parity_nodes[it] == i)it++;
			else if (i - it < arrsize){
				dest[i] = arr[i - it];
			}
		}

		for (int i = parities.size() - 1; i >= 0; i--){
			auto& parity = parities[i];
			for (int i = parity.size() - 1; i > 0; i--)
				dest[parity[0]] ^= dest[parity[i]];
		}
	}
};
#endif
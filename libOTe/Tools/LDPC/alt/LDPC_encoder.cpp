#include "LDPC_encoder.h"
#include <algorithm>
#define INF 10000000
LDPC_encoder::LDPC_encoder(int _code_len,int _msg_len):
	code_len(_code_len),
	msg_len(_msg_len){}

static void print_bitarr(const bit_array_t& src){
	for (int i = 0; i < src.size(); i++)
		printf(src[i] ? "1" : "0");
	printf("\n");
}
static void print_matrix(const binary_matrix& mat){
	for (int i = 0; i < mat.height(); i++){
		auto bitarr = mat[i];
		print_bitarr(bitarr);
	}
	printf("\n");
}
bool LDPC_encoder::init(LDPC_generator* generator, int& actual_msg_len){
	auto res = generator->init(code_len, msg_len);
	int check_len = code_len - msg_len;
	if ((res&LDPC_generator::GENERATOR_PROPERTY::UPPER_TRIANGLE) == LDPC_generator::GENERATOR_PROPERTY::UPPER_TRIANGLE){
		//directly map it
		auto graph = generator->as_Tanner_graph();
		if ((res&LDPC_generator::GENERATOR_PROPERTY::FULL_RANK) == 0){
			while (graph->get_check_node(check_len - 1).size() == 0)check_len--;
		}
		parities.reserve(check_len);

		for (int i = 0; i < check_len; i++)parity_nodes.push_back(i);
		for (int i = 0; i < check_len; i++){
			std::vector<int> parity;
			parities.push_back(parity);
			auto& parity_ref = parities[parities.size() - 1];

			auto& covered = graph->get_check_node(i);
			parity_ref.reserve(covered.size());
			for (auto it : covered){
				parity_ref.push_back(it);
			}
		}
		actual_msg_len = code_len - check_len;
		return true;
	}
	else if ((res&LDPC_generator::GENERATOR_PROPERTY::PSEUDO_UPPER_TRIANGLE) == LDPC_generator::GENERATOR_PROPERTY::PSEUDO_UPPER_TRIANGLE){
		//find the steps
		auto graph = generator->as_Tanner_graph();
		if ((res&LDPC_generator::GENERATOR_PROPERTY::FULL_RANK) == 0){
			while (graph->get_check_node(check_len - 1).size() == 0)check_len--;
		}
		parities.reserve(check_len);
		for (int i = 0; i < check_len; i++){
			auto& covered = graph->get_check_node(i);
			parity_nodes.push_back(covered[0]);
		}
		
		for (int i = 0; i < check_len; i++){
			auto& covered = graph->get_check_node(i);
			parities.push_back(std::vector<int>());
			auto& parity_ref = parities[parities.size() - 1];
			parity_ref.reserve(covered.size());
			for (auto it : covered)parity_ref.push_back(it);
		}
		actual_msg_len = code_len - check_len;
		return true;
	}
	else {
		//the default algo
		//first: initialize states
		auto graph = generator->as_Tanner_graph();

		for (int i = 0; i < code_len; i++){
			printf("encoder init: %d/%d checks\n", i, check_len);
			auto& data_node = graph->get_data_node(i);
			int degree = (int)data_node.size();
			if (degree == 0)continue;
			else if (degree != 1){
				//first: choose the best one
				int smallest_degree = INF;
				int smallest_check = 0;
				for (auto it : data_node){
					int _size;
					if ((_size = (int)graph->get_check_node(it).size()) < smallest_degree){
						smallest_degree = _size;
						smallest_check = it;
					}
				}

				//second: modify each
				auto smallest_node = graph->get_check_node(smallest_check);
				auto data_node_copy = data_node;
				for (auto it : data_node_copy){
					if (it == smallest_check)continue;

					std::vector<int> newrow;
					auto& check_node = graph->get_check_node(it);

					int t = 0, t2 = 0;
					for (; t2 < (int)(check_node.size()) && t < (int)(smallest_node.size());){
						if (smallest_node[t] == check_node[t2]){
							auto& _data_node = graph->get_data_node(smallest_node[t]);
							_data_node.erase(std::remove(_data_node.begin(), _data_node.end(), it), _data_node.end());
							t++; t2++;
						}
						else if (smallest_node[t] < check_node[t2]){
							newrow.push_back(smallest_node[t]);
							graph->get_data_node(smallest_node[t]).push_back(it);
							t++;
						}
						else{
							newrow.push_back(check_node[t2]);
							t2++;
						}
					}
					for (; t < (int)(smallest_node.size()); t++){
						newrow.push_back(smallest_node[t]);
						graph->get_data_node(smallest_node[t]).push_back(it);
					}
					for (; t2 < (int)(check_node.size()); t2++)newrow.push_back(check_node[t2]);

					graph->get_check_node(it) = newrow;
				}
			}
			//third: mark
			//select this node as parity
			//and remove this check node
			parity_nodes.push_back(i);
			assert(data_node.size() == 1);
			auto check_id = data_node[0];
			auto& check_node = graph->get_check_node(check_id);
			parities.push_back(check_node);
			for (auto it : check_node){
				auto& _data_node = graph->get_data_node(it);
				_data_node.erase(std::remove(_data_node.begin(), _data_node.end(), check_id), _data_node.end());

			}
		}

		actual_msg_len =(int)(code_len - parities.size());
		//save_parities_to("parities.txt");
		return true;
	}
}
//bool LDPC_encoder::init(const char* filename){
//	FILE* fp;
//	fopen_s(&fp, filename, "r");
//	int size;
//	fscanf_s(fp, "%d %d %d", &code_len, &msg_len, &size);
//	parity_nodes.reserve(size);
//	for (int i = 0; i < size; i++){
//		int t;
//		fscanf_s(fp, "%d", &t);
//		parity_nodes.push_back(t);
//	}
//	parities.reserve(size);
//	for (int i = 0; i < size; i++){
//		parities.push_back(std::vector<int>());
//		parities[i].clear();
//		int len;
//		fscanf_s(fp, "%d", &len);
//		parities[i].reserve(len);
//		int t;
//		for (int j = 0; j < len; j++){
//			fscanf_s(fp, "%d", &t);
//			parities[i].push_back(t);
//		}
//	}
//	return true;
//}
//bool LDPC_encoder::save_parities_to(const char* filename){
//	FILE* fp;
//	fopen_s(&fp, filename, "w");
//	fprintf(fp, "%d %d %d\n", code_len, msg_len, parity_nodes.size());
//	for (unsigned int i = 0; i < parity_nodes.size();i++){
//		fprintf(fp, "%d\n", parity_nodes[i]);
//	}
//	for (unsigned int i = 0; i < parities.size(); i++){
//		auto& parity = parities[i];
//		fprintf(fp, "%d", parity.size());
//		for (unsigned int i = 0; i < parity.size(); i++)
//			fprintf(fp, " %d", parity[i]);
//		fprintf(fp, "\n");
//	}
//	fclose(fp);
//	return true;
//}

void LDPC_encoder::encode(const bit_array_t& bitarr,bit_array_t& dest){
	assert(dest.size() == code_len);
	dest.clear();
	int size = (int)parity_nodes.size();
	for (int i = 0, it = 0; i < code_len; i++){
		if (it < size && parity_nodes[it] == i)it++;
		else if (i - it < bitarr.size()){
			dest.set(i, bitarr[i - it]);
		}
	}

	for (int i = (int)parities.size() - 1; i >= 0;i--){
		auto& parity = parities[i];
		for (int i = (int)parity.size() - 1; i > 0; i--)
			dest.Xor(parity[0], dest[parity[i]]);
	}
}
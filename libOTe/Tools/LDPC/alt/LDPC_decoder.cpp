#include "LDPC_decoder.h"
#include <math.h>
#include <chrono>
using namespace std;

static chrono::high_resolution_clock::time_point get_tick(){
	return chrono::high_resolution_clock::now();
}
static double get_duration(chrono::high_resolution_clock::time_point& t1, chrono::high_resolution_clock::time_point& t2){
	std::chrono::duration<double> time_span = std::chrono::duration_cast<std::chrono::duration<double>>(t2 - t1);
	return time_span.count();
}

LDPC_bp_decoder::LDPC_bp_decoder(int _code_len, int _msg_len) :
code_len(_code_len), msg_len(_msg_len),
messages(NULL), data_nodes(NULL), msg_sign(NULL), error(NULL),
check_to_data(NULL), check_to_data_id(NULL), check_to_data_id_mem(NULL), check_to_data_mem(NULL), check_degree(NULL),
data_to_check(NULL),data_to_check_mem(NULL),data_degree(NULL) {}

LDPC_bp_decoder::~LDPC_bp_decoder(){
	if (messages)delete[] messages;
	if (data_nodes) delete[] data_nodes;
	if (error) delete[] error;
	if (msg_sign) delete[] msg_sign;
	if (check_to_data) delete[] check_to_data;
	if (check_to_data_mem) delete[] check_to_data_mem;
	if (check_to_data_id) delete[] check_to_data_id;
	if (check_to_data_id_mem) delete[] check_to_data_id_mem;
	if (check_degree) delete[] check_degree;
	if (data_degree) delete[] data_degree;
	if (data_to_check)delete[] data_to_check;
	if (data_to_check_mem)delete[] data_to_check_mem;
}



bool LDPC_bp_decoder::init(LDPC_generator* gen){
	auto res = gen->init(code_len, msg_len);
	if (res == LDPC_generator::GENERATOR_PROPERTY::INVALID)return false;
	
	auto g = gen->as_Tanner_graph();
	
	//first: calc all the degrees
	int total = 0;
	int *p = new int[code_len + 1];
	p[0] = 0;
	for (int i = 0; i < code_len; i++){
		total += g->get_data_node(i).size();
		p[i + 1] = total;
	}
	check_to_data = new int* [code_len - msg_len];
	check_to_data_mem = new int[total];
	check_degree = new int[code_len - msg_len];

	data_to_check = new int* [code_len];
	data_to_check_mem = new int[total];
	data_degree = new int[code_len];

	msg_sign = new bool[code_len];

	messages = new double[total];

	check_to_data_id_mem = new int[total];
	check_to_data_id = new int*[code_len - msg_len];

	for (int i = 0; i < code_len; i++){
		data_to_check[i] = data_to_check_mem + p[i];
		auto& nodes = g->get_data_node(i);
		data_degree[i] = nodes.size();
		for (int j = 0; j < data_degree[i]; j++){
			data_to_check[i][j] = p[i] + j;
		}
	}

	int total2 = 0;
	int check_len = code_len - msg_len;
	int* p2 = new int[check_len + 1];
	check_to_data[0] = check_to_data_mem;
	check_to_data_id[0] = check_to_data_id_mem;
	for (int i = 0; i < check_len; i++){
		auto& nodes = g->get_check_node(i);
		total2 += nodes.size();
		if (i != check_len - 1){
			p2[i + 1] = total2;
			check_to_data[i + 1] = check_to_data_mem + total2;
			check_to_data_id[i + 1] = check_to_data_id_mem + total2;
		}
		else assert(total2 == total);

		check_degree[i] = nodes.size();
		for (int j = 0; j < check_degree[i]; j++){
			check_to_data_id[i][j] = nodes[j];
			auto& n2 = g->get_data_node(nodes[j]);
			int id = std::find(n2.begin(), n2.end(), i) - n2.begin();
			check_to_data[i][j] = data_to_check[nodes[j]][id];
		}
	}
	
	data_nodes = new double[code_len];
	error = new double[code_len];

	return true;
}

/*bool LDPC_bp_decoder::save_parities_to(const char* filename){
	FILE* fp;
	fopen_s(&fp, filename, "w");
	fprintf(fp, "%d %d\n", code_len, msg_len);

}*/
//bool LDPC_bp_decoder::init(const char* filename){
//	FILE* fp;
//	fopen_s(&fp, filename, "rt");
//	int m;
//	fscanf_s(fp, "%d%d", &code_len, &m);
//	msg_len = code_len - m;
//	
//	//unused
//	int cmax, rmax;
//	fscanf_s(fp, "%d%d", &cmax, &rmax);
//
//	check_degree = new int[code_len - msg_len];
//	data_degree = new int[code_len];
//
//	int* col_weight = new int[code_len+1];
//	col_weight[0] = 0;
//	for (int i = 0; i < code_len; i++) {
//		fscanf_s(fp, "%d", &data_degree[i]);
//		col_weight[i + 1] = col_weight[i] + data_degree[i];
//	}
//	int* row_weight = new int[m + 1];
//	row_weight[0] = 0;
//	for (int j = 0; j < m; j++){
//		fscanf_s(fp, "%d", &check_degree[j]);
//		row_weight[j + 1] = row_weight[j] + check_degree[j];
//	}
//	
//	assert(col_weight[code_len] == row_weight[m]);
//	int total = col_weight[code_len];
//
//	check_to_data = new int*[code_len - msg_len];
//	check_to_data_mem = new int[total];
//
//	data_to_check = new int*[code_len];
//	data_to_check_mem = new int[total];
//
//	msg_sign = new bool[code_len];
//
//	messages = new double[total];
//
//	check_to_data_id_mem = new int[total];
//	check_to_data_id = new int*[code_len - msg_len];
//
//	data_nodes = new double[code_len];
//	error = new double[code_len];
//
//	int** data_to_check_id = new int*[code_len];
//	int* data_to_check_id_mem = new int[total];
//
//	for (int i = 0; i < code_len; i++){
//		data_to_check[i] = data_to_check_mem + col_weight[i];
//		data_to_check_id[i] = data_to_check_id_mem + col_weight[i];
//		data_degree[i] = col_weight[i + 1] - col_weight[i];
//		int j;
//		for (j = 0; j < data_degree[i]; j++){
//			data_to_check[i][j] = col_weight[i] + j;
//			fscanf_s(fp, "%d", &(data_to_check_id[i][j]));
//			data_to_check_id[i][j]--;
//		}
//
//		for (; j < cmax; j++) {
//			fscanf_s(fp, "%*d"); // skip the 0s (fillers)
//		}
//	}
//
//	check_to_data[0] = check_to_data_mem;
//	check_to_data_id[0] = check_to_data_id_mem;
//	for (int i = 0; i < m; i++){
//		check_to_data[i] = check_to_data_mem + row_weight[i];
//		check_to_data_id[i] = check_to_data_id_mem + row_weight[i];
//
//		check_degree[i] = row_weight[i + 1] - row_weight[i];
//		int j;
//		for (j = 0; j < check_degree[i]; j++){
//			fscanf_s(fp, "%d", &(check_to_data_id[i][j]));
//			check_to_data_id[i][j]--;
//			auto& n2 = data_to_check_id[check_to_data_id[i][j]];
//			int id = std::find(n2, n2+data_degree[check_to_data_id[i][j]], i) - n2;
//			check_to_data[i][j] = data_to_check[check_to_data_id[i][j]][id];
//		}
//
//		for (; j < rmax; j++) {
//			fscanf_s(fp, "%*d"); // skip the 0s (fillers)
//		}
//	}
//
//	delete[] data_to_check_id;
//	delete[] data_to_check_id_mem;
//	return true;
//}

bool LDPC_bp_decoder::init(oc::SparseMtx& H)
{
	MyGen gen;  
	gen.init(H);
	return init(&gen); 
}

static inline double LLR(double d){
	return log(d / (1 - d));
}
bool LDPC_bp_decoder::check(const bit_array_t& data){
	for (int i = 0; i < code_len - msg_len; i++){
		auto check_node = check_to_data_id[i];
		bool res = false;
		for (int j = 0; j < check_degree[i]; j++)
			res ^= data[check_node[j]];
		if (res)return false;
	}
	return true;
}

bool LDPC_bp_decoder::decode_BSC(bit_array_t& data, double error_prob, int iterations){
	for (int i = 0; i < code_len; i++)
	{
		error[i] = data[i] ? (1 - error_prob) : error_prob;
	}
	bool result = decode_BSC(data, error, iterations);
	return result;
}
//
//bool LDPC_bp_decoder::decode_BEC(bit_array_t& data, bit_array_t& mask){
//	//first: initialize
//	bool found = false;
//	bool no_erasure = false;
//
//	do{
//		found = false;
//		no_erasure = true;
//		for (int i = 0; i < code_len - msg_len; i++){
//			auto check_node = check_to_data_id[i];
//			int erasure_count = 0;
//			int erasure_id = 0;
//			bool other_xor = false;
//			for (int j = 0; j < check_degree[i];j++){
//				if (!mask[check_node[j]]){
//					erasure_count++;
//					erasure_id = check_node[j];
//				}
//				else other_xor ^= data[check_node[j]];
//			}
//			if (erasure_count > 0)
//				no_erasure = false;
//			if (erasure_count == 1){
//				data.set(erasure_id, other_xor);
//				mask.set(erasure_id, true);
//				found = true;
//			}
//		}
//	} while (found&&!no_erasure);
//	return no_erasure;
//}

//just for test
static void print_bitarr(const bit_array_t& src){
	for (int i = 0; i < src.size(); i++)
		printf(src[i] ? "1" : "0");
	printf("\n");
}

inline double atanh2(double f){
	return log((1 + f) / (1 - f));
}
inline double trunc_atanh(double f){
	if (-0.9999 < f && f < 0.9999)return atanh(f);
	else if (f < -0.9999)return -5;
	else return 5;
}
bool LDPC_bp_decoder::decode_BSC(bit_array_t& result, const double* data_prob, int iterations){
	//first: initialze
	for (int i = 0; i < code_len; i++){
		data_nodes[i] = LLR(data_prob[i]);
		//std::cout << "LLR " << i << " " << data_nodes[i] << " " << data_prob[i] << std::endl;

		auto data_node = data_to_check[i];
		for (int j = 0; j < data_degree[i]; j++)
			messages[data_node[j]] = data_nodes[i];
	}
	//second: bp
	for (int iter = 0; iter < iterations; iter++){
		int m = code_len - msg_len;
		for (int i = 0; i < m; i++){

			double total_msg = 0.0;
			bool sign = false;
			auto check_node = check_to_data[i];
			for (int j = 0; j < check_degree[i];j++){
				double t = tanh(messages[check_node[j]]*0.5);
				//std::cout << i << "," << j << " t: " << t << " " << messages[check_node[j]] << std::endl;

				messages[check_node[j]] = log(fabs(t));
				msg_sign[j] = t >= 0;
				sign ^= msg_sign[j];
				total_msg += messages[check_node[j]];
			}
			for (int j = 0; j < check_degree[i];j++){

				auto m = messages[check_node[j]];
				auto e = exp(total_msg - m);
				auto s = ((sign ^ msg_sign[j]) ? -1 : 1);

				messages[check_node[j]] = -atanh2(e*s);
				//std::cout <<i << "," <<j <<" m: " << messages[check_node[j]] << " " << e << " " << s << " " << m << std::endl;
			}

		}
		
		for (int i = 0; i < code_len; i++){
			double total_LLR = data_nodes[i];
			auto data_node = data_to_check[i];
			for (int j = 0; j < data_degree[i];j++){
				total_LLR += messages[data_node[j]];
			}
			
			for (int j = 0; j < data_degree[i];j++){
				messages[data_node[j]] = total_LLR - messages[data_node[j]];
			}
			//std::cout << i << " ll " << total_LLR << std::endl;
			result.set(i, total_LLR>=0);
		}
		return {};
		//check
		if (check(result)){
			for (int i = 0; i < code_len; i++) 
			{
				double total_LLR = data_nodes[i];
				auto data_node = data_to_check[i];
				for (int j = 0; j < data_degree[i]; j++) {
					total_LLR += messages[data_node[j]];
				}
				std::cout << i << " ll " << total_LLR << std::endl;
			}
			return true;
		}
	}

	return false;
}
bool LDPC_bp_decoder::decode_BSC(bit_array_t& data, int iterations){
	//first: initialze
	bool* data_nodes_bin = (bool*)data_nodes;
	bool* messages_bin = (bool*)messages;

	for (int i = 0; i < code_len; i++){
		data_nodes_bin[i] = data[i];
		auto data_node = data_to_check[i];
		for (int j = 0; j < data_degree[i];j++)
			messages_bin[data_node[j]] = data_nodes_bin[i];
	}
	//second: bp
	for (int iter = 0; iter < iterations; iter++){
		for (int i = 0; i < code_len - msg_len; i++){
			bool msg_sum = false;
			auto check_node = check_to_data[i];
			for (int j = 0; j < check_degree[i]; j++){
				msg_sum ^= messages_bin[check_node[j]];
			}
			for (int j = 0; j < check_degree[i]; j++){
				messages_bin[check_node[j]] = msg_sum^messages_bin[check_node[j]];
			}
		}
		for (int i = 0; i < code_len; i++){
			auto data_node = data_to_check[i];
			int pos = 0, neg = 0;
			for (int j = 0; j < data_degree[i];j++){
				if (messages_bin[data_node[j]])pos++;
				else neg++;
			}

			int t = pos - neg + (data_nodes_bin[i] ? 1 : -1);
			for (int j = 0; j < data_degree[i];j++){
				int tt = messages_bin[data_node[j]] ? (t - 1) : (t + 1);
				messages_bin[data_node[j]] = (tt == 0) ? data_nodes_bin[i] : (tt > 0);
			}
			data.set(i, t == 0 ? data_nodes_bin[i] : t > 0);
		}
		//check
		if (check(data)){
			return true;
		}
	}

	return false;
}
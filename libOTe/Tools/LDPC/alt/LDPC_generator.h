#ifndef __LDPC_GENERATOR_H
#define __LDPC_GENERATOR_H
#include <iostream>
#include <memory>
#include <vector>
#include "simple_bitarray.h"
#include "libOTe/Tools/LDPC/Mtx.h"

//the structure of Tanner Graph
class Tanner_graph{
private:
	//no copy
	Tanner_graph(const Tanner_graph& graph);
	Tanner_graph& operator =(const Tanner_graph& graph);
public:
	Tanner_graph(int _data_num, int _check_num) :
		data_nodes(_data_num),
		check_nodes(_check_num)
	{ }

	std::vector<std::vector<int>> data_nodes;
	std::vector<std::vector<int>> check_nodes;

	//insert an duplex edge between data node and check node. 
	void insert_duplex_edge(int data_id, int check_id){
		data_nodes[data_id].push_back(check_id);
		check_nodes[check_id].push_back(data_id);
	}
	//get the data node given node index
	std::vector<int>& get_data_node(int id){
		return data_nodes[id];
	}
	//get the check node given node index
	std::vector<int>& get_check_node(int id){
		return check_nodes[id];
	}
	int get_code_len() const{ return (int)data_nodes.size(); }
	int get_check_len() const{ return (int)check_nodes.size(); }
};

//binary matrix, to present parity matrix
class binary_matrix{
private:
	int w;
	int h;
	bit_array_t* bit_array;
public:
	binary_matrix(int _w, int _h) :
		w(_w), h(_h),
		bit_array(new bit_array_t[_h]){
		for (int i = 0; i < h; i++){
			bit_array[i] = bit_array_t(w);
			bit_array[i].clear(false);
		}
	}
	~binary_matrix(){
		delete[] bit_array;
	}
	bit_array_t& operator [](int j) const{
		return bit_array[j];
	}
	inline int width() const{ return w; }
	inline int height() const{ return h; }
};
static std::unique_ptr<binary_matrix> to_binary_matrix(const std::unique_ptr<Tanner_graph>& graph, int code_len, int msg_len){
	std::unique_ptr<binary_matrix> res(new binary_matrix(code_len, code_len - msg_len));
	for (int i = 0; i < code_len - msg_len; i++){
		auto& row = res->operator[](i);
		auto list = graph->get_check_node(i);
		for (auto it : list)
			row.set(it, true);
	}
	return res;
}
static std::unique_ptr<Tanner_graph> to_Tanner_graph(const std::unique_ptr<binary_matrix> mat, int code_len, int msg_len){
	int h = code_len - msg_len;
	std::unique_ptr<Tanner_graph> res;
	for (int i = 0; i < h; i++)
		for (int j = 0; j < code_len; j++)
			if (mat->operator[](i)[j])
				res->insert_duplex_edge(j, i);
	return res;
}

//generating parity check matrix/Tanner graph
class LDPC_generator{
public:
	enum GENERATOR_PROPERTY{
		INVALID = 0,
		VALID=1,
		WR_REGULAR = 3,
		WC_REGULAR = 5,
		REGULAR = 7,
		UPPER_TRIANGLE = 57,
		PSEUDO_UPPER_TRIANGLE = 41,
		FULL_RANK = 33,
		GIRTH_6 = 65
	};
	virtual GENERATOR_PROPERTY init(int code_len, int msg_len) = 0;
	virtual std::unique_ptr<Tanner_graph> as_Tanner_graph() = 0;
	virtual std::unique_ptr<binary_matrix> as_binary_matrix() = 0;
	bool save_to_plist(const char* filename);
};


class MyGen : public LDPC_generator
{
public:
	oc::SparseMtx* mH;

	void init(oc::SparseMtx& H)
	{
		mH = &H;
	}


	GENERATOR_PROPERTY init(int code_len, int msg_len) override
	{
		if (code_len == mH->cols() && msg_len == mH->cols() - mH->rows())
			return GENERATOR_PROPERTY::VALID;
		else
			return GENERATOR_PROPERTY::INVALID;
	}
	std::unique_ptr<Tanner_graph> as_Tanner_graph() override
	{
		auto ret = std::make_unique<Tanner_graph>((int)mH->cols(), (int)mH->rows());

		for (auto i = 0ull; i < mH->rows(); ++i)
		{
			//ret->check_nodes[i].insert(
			//	ret->check_nodes[i].begin(),
			//	mH->mRows[i].begin(),
			//	mH->mRows[i].end());

			for (auto cc : mH->mRows[i])
				ret->check_nodes[i].push_back((int)cc);
		}
		for (auto i = 0ull; i < mH->cols(); ++i)
		{
			//ret->data_nodes[i].insert(
			//	ret->data_nodes[i].begin(),
			//	mH->mCols[i].begin(),
			//	mH->mCols[i].end());

			for (auto cc : mH->mCols[i])
				ret->data_nodes[i].push_back((int)cc);
		}
		return ret;
	}
	std::unique_ptr<binary_matrix> as_binary_matrix()override
	{
		assert(0);
		return {};
	}
};

//read from an existing plist file
//class LDPC_plist_generator : public LDPC_generator{
//private:
//	int code_len, msg_len;
//	char* const filename;
//public:
//	LDPC_plist_generator(const char* filename);
//	~LDPC_plist_generator(){ if (filename) delete[] filename; }
//	virtual GENERATOR_PROPERTY init(int code_len, int msg_len);
//	virtual std::unique_ptr<Tanner_graph> as_Tanner_graph();
//	virtual std::unique_ptr<binary_matrix> as_binary_matrix();
//};
class LDPC_Gallager_generator :public LDPC_generator{
private:
	int code_len, msg_len;
	const int Wr, Wc;
	const int seed;
	const bool check_cycle;

	std::unique_ptr<Tanner_graph> wocycle_as_Tanner_graph();
	std::unique_ptr<binary_matrix> wcycle_as_binary_matrix();
public:
	LDPC_Gallager_generator(int Wr, int Wc, int seed, bool _check_cycle);
	virtual GENERATOR_PROPERTY init(int code_len, int msg_len);
	virtual std::unique_ptr<Tanner_graph> as_Tanner_graph();
	virtual std::unique_ptr<binary_matrix> as_binary_matrix();
};

//quasi-cyclic code
class LDPC_QuasiCyclic_generator:public LDPC_generator{
private:
	int code_len,msg_len;
	const int Wr,Wc;
	const int seed;
public:
	LDPC_QuasiCyclic_generator(int Wr,int Wc,int seed);
	virtual GENERATOR_PROPERTY init(int code_len,int msg_len);
	virtual std::unique_ptr<Tanner_graph> as_Tanner_graph();
	virtual std::unique_ptr<binary_matrix> as_binary_matrix();
};

//array code
class LDPC_array_generator :public LDPC_generator{
private:
	int code_len, msg_len;
	const int Wr, Wc;
	const bool upper_tri;
public:
	LDPC_array_generator(int Wr, int Wc, bool upper_tri);
	virtual GENERATOR_PROPERTY init(int code_len, int msg_len);
	virtual std::unique_ptr<Tanner_graph> as_Tanner_graph();
	virtual std::unique_ptr<binary_matrix> as_binary_matrix();
};

/*
class LDPC_random_generator:public LDPC_generator{
private:
	int code_len,msg_len;
public:
	LDPC_random_generator(int Wr, int Wc, int seed);
	virtual GENERATOR_PROPERTY init(int code_len,int msg_len);
	virtual std::unique_ptr<Tanner_graph<int>> as_Tanner_graph();
	virtual std::unique_ptr<binary_matrix> as_binary_matrix();
};
*/
#endif

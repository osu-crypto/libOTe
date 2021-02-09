#include "LDPC_generator.h"
#include <random>
using namespace std;

///////////////////////////
// miscellaneous         //
//                       //
///////////////////////////
//enum OR operator
inline LDPC_generator::GENERATOR_PROPERTY operator | (LDPC_generator::GENERATOR_PROPERTY p1,LDPC_generator::GENERATOR_PROPERTY p2){
	return static_cast<LDPC_generator::GENERATOR_PROPERTY>(static_cast<int>(p1)|static_cast<int>(p2));

}
inline LDPC_generator::GENERATOR_PROPERTY operator | (int p1, LDPC_generator::GENERATOR_PROPERTY p2){
	return static_cast<LDPC_generator::GENERATOR_PROPERTY>(p1 | static_cast<int>(p2));
}
static void init_rand(int seed){
	srand(seed);
}
static inline int rand_next(int max){
	return rand()%max;
}

static inline bool choose(int fz,int fm){
	return rand_next(fm)<fz;
}
static inline void swap(int& a, int& b){
	a=a^b;
	b=a^b;
	a=a^b;
}
static void perm_gen(int* arr, int len){
	for(int i=0;i<len;i++)arr[i]=i;
	for(int i=0;i<len;i++){
		int r=rand_next(len-i);
		swap(arr[i],arr[r]);
	}
}

//bool LDPC_generator::save_to_plist(const char* filename){
//	auto t = this->as_Tanner_graph();
//	FILE* fp;
//	fopen_s(&fp, filename, "w");
//	if (fp == NULL){
//		fprintf(stderr, "cannot open %s\n", filename);
//		return false;
//	}
//	
//	fprintf_s(fp, "%d %d\n", t->get_code_len(), t->get_check_len());
//
//	//get rmax and cmax
//	unsigned int rmax = 0, cmax = 0;
//	for (int i = 0; i < t->get_code_len(); i++){
//		auto& n = t->get_data_node(i);
//		if (n.size()>cmax)cmax = n.size();
//	}
//	for (int i = 0; i < t->get_check_len(); i++){
//		auto& n = t->get_check_node(i);
//		if (n.size()>rmax)rmax = n.size();
//	}
//	
//	fprintf_s(fp, "%d %d\n", cmax, rmax);
//
//	//output col weights and row weights
//	for (int i = 0; i < t->get_code_len(); i++){
//		fprintf(fp, "%d ", t->get_data_node(i).size());
//	}
//	fprintf(fp, "\n");
//	for (int i = 0; i < t->get_check_len(); i++){
//		fprintf(fp, "%d ", t->get_check_node(i).size());
//	}
//	fprintf(fp, "\n");
//
//	//output links
//	for (int i = 0; i < t->get_code_len(); i++){
//		auto& n = t->get_data_node(i);
//		for (auto j : n)
//			fprintf(fp, "%d ", j+1);
//		for (int j = n.size(); j < cmax; j++)fprintf(fp, "0 ");
//		fprintf(fp, "\n");
//	}
//	for (int i = 0; i < t->get_check_len(); i++){
//		auto& n = t->get_check_node(i);
//		for (auto j : n)
//			fprintf(fp, "%d ", j+1);
//		for (int j = n.size(); j < rmax; j++)fprintf(fp, "0 ");
//		fprintf(fp, "\n");
//	}
//	fclose(fp);
//	return true;
//}

///////////////////////////
// Generator from plist  //
//                       //
///////////////////////////
//
//LDPC_plist_generator::LDPC_plist_generator(const char* _filename) :code_len(0), msg_len(0), filename(new char[strlen(_filename) + 1]){
//	strcpy_s(filename, strlen(_filename)+1, _filename);
//}
//LDPC_generator::GENERATOR_PROPERTY LDPC_plist_generator::init(int _code_len, int _msg_len){
//	FILE* fp;
//	fopen_s(&fp, filename, "rt");
//	if (fp == NULL) {
//		fprintf(stderr, "cannot open %s\n", filename);
//		return LDPC_generator::GENERATOR_PROPERTY::INVALID;
//	}
//	int m;
//	fscanf_s(fp, "%d%d", &code_len, &m);
//	msg_len = code_len - m;
//	fclose(fp);
//	if (code_len == _code_len && msg_len == _msg_len) 
//		return LDPC_generator::GENERATOR_PROPERTY::VALID;
//	return LDPC_generator::GENERATOR_PROPERTY::INVALID;
//}
//unique_ptr<Tanner_graph> LDPC_plist_generator::as_Tanner_graph(){
//	FILE* fp;
//	fopen_s(&fp, filename, "rt");
//	if (fp == NULL) {
//		fprintf(stderr, "cannot open %s\n", filename);
//		exit(-2);
//	}
//	int m;
//	fscanf_s(fp, "%d%d", &code_len, &m);
//	msg_len = code_len - m;
//
//	//unused
//	int cmax, rmax;
//	fscanf_s(fp, "%d%d", &cmax, &rmax);
//
//	int* col_weight = new int[code_len];
//	for (int i = 0; i < code_len; i++) {
//		fscanf_s(fp, "%d", &col_weight[i]);
//	}
//	int* row_weight = new int[m];
//	for (int j = 0; j < m; j++)
//		fscanf_s(fp, "%d", &row_weight[j]);
//
//	//skip n lines
//	for (int i = 0; i < code_len; i++) {
//		for (int j = 0; j < cmax; j++)
//			fscanf_s(fp, "%*d");
//	}
//
//	unique_ptr<Tanner_graph> res(new Tanner_graph(code_len, m));
//
//	for (int j = 0; j < m; j++) {
//		int i = 0;
//		for (i = 0; i < row_weight[j]; i++) {
//			int v;
//			fscanf_s(fp, "%d", &v);
//			res->insert_duplex_edge(v - 1, j);
//		}
//		for (; i < rmax; i++) {
//			fscanf_s(fp, "%*d"); // skip the 0s (fillers)
//		}
//	}
//	fclose(fp);
//	delete[] col_weight;
//	delete[] row_weight;
//	return res;
//}

//unique_ptr<binary_matrix> LDPC_plist_generator::as_binary_matrix(){
//	return to_binary_matrix(as_Tanner_graph(), code_len, msg_len);
//}

///////////////////////////
// Gallager generator    //
//                       //
///////////////////////////
LDPC_Gallager_generator::LDPC_Gallager_generator(int _Wr,int _Wc,int _seed, bool _check_cycle):
	Wr(_Wr),Wc(_Wc),seed(_seed),check_cycle(_check_cycle){
	init_rand(seed);
	}
LDPC_generator::GENERATOR_PROPERTY LDPC_Gallager_generator::init(int _code_len,int _msg_len){
	int r=_code_len-_msg_len;
	if(
		_code_len%Wr!=0|| //not regular row
		(r%Wc!=0)|| //not regular column
		(r/(_code_len/Wr)!=Wc)) //LDPC constraint
		return GENERATOR_PROPERTY::INVALID;
	if(check_cycle&&code_len/Wr<Wr) //there must be 2-cycle
		return GENERATOR_PROPERTY::INVALID;
	this->code_len=_code_len;
	this->msg_len=_msg_len;
	return GENERATOR_PROPERTY::REGULAR;
}

struct __map_state_t{
private:
	int W,Wr;
	bit_array_t bitmap;
	int* count;

	__map_state_t(const __map_state_t&);
public:
	__map_state_t(int _Wr,int _W):W(_W),Wr(_Wr),bitmap(_W),count(new int[_Wr]){
		bitmap.clear(false);
		memset(count,0,sizeof(int)*Wr);
	}
	~__map_state_t(){
		delete[] count;
	}

	__map_state_t& operator=(const __map_state_t& state){
		this->bitmap=state.bitmap;
		memcpy(this->count,state.count,sizeof(int)*Wr);
		return *this;
	}
	
	inline void insert(int pos){
		if(bitmap[pos])return;
		bitmap.set(pos,true);
		count[pos/(W/Wr)]++;
	}
	inline bool operator [] (int index){
		return bitmap[index];
	}
	inline int get_count(int x){
		return count[x];
	}
	inline void clear(){
		bitmap.clear(false);
		memset(count,0,sizeof(int)*Wr);
	}
};

unique_ptr<Tanner_graph> LDPC_Gallager_generator::wocycle_as_Tanner_graph(){
	unique_ptr<Tanner_graph> res(new Tanner_graph(code_len,code_len-msg_len));
	//first: mark the first submatrix
	int slice=code_len/Wr;
	for(int i=0;i<slice;i++)
		for(int j=0;j<Wr;j++)
			res->insert_duplex_edge(j+i*slice,i);

	//second: randomly choose each subsubmatrices
	
	binary_matrix bitmap(code_len,slice);
	int* onecount=new int[Wr];
	memset(onecount,0,sizeof(int)*Wr);
	
	__map_state_t mark(code_len,Wr);
	__map_state_t current(code_len,Wr);

	for(int i=0;i<Wc;i++){
		mark.clear();
		for(int j=0;j<slice;j++){
			current=mark;
			for(int k=0;k<Wr;k++){
				int curr=0;
				for(int x=0;x<slice;x++){
					if(current[x+k*slice])continue;
					if(!current[x+k*slice] && choose(1,slice-current.get_count(k)-curr)){
						//iterate
						auto check=res->get_check_node(i*slice+j);
						for(auto it:check){
							current.insert(it);
						}
						//choose this
						mark.insert(x+k*slice);
						res->insert_duplex_edge(x+k*slice,i*slice+j);
	
						break;
					}
					curr++;
				}
			}
		}
	}
	return res;
}
unique_ptr<binary_matrix> LDPC_Gallager_generator::wcycle_as_binary_matrix(){
	//first: generate one slice
	unique_ptr<binary_matrix> res(new binary_matrix(code_len,msg_len));
	for(int i=0;i<code_len;i++)
		res->operator[](i/Wr).set(i,true);

	//second: permutation
	int slice_len=code_len/Wr;
	int* perm=new int[code_len];
	for(int i=1;i<Wc;i++){
		perm_gen(perm,code_len);
		for(int j=1;j<slice_len;j++)
			for(int k=0;k<code_len;k++){
				res->operator[](i*slice_len+j).set(k,res->operator[](j)[perm[k]]);
			}
	}
	delete[] perm;
	return res;
}
unique_ptr<binary_matrix> LDPC_Gallager_generator::as_binary_matrix(){
	if(!check_cycle)return wcycle_as_binary_matrix();
	auto graph=wocycle_as_Tanner_graph();
	return to_binary_matrix(graph,code_len,msg_len);
}
unique_ptr<Tanner_graph> LDPC_Gallager_generator::as_Tanner_graph(){
	if(!check_cycle){
		auto matrix=as_binary_matrix();
		unique_ptr<Tanner_graph> res(new Tanner_graph(code_len,code_len-msg_len));

		for(int j=0;j<code_len-msg_len;j++){
			int rest=Wr;
			for(int i=0;rest!=0&&i<code_len;i++){
				if(matrix->operator[](j)[i]){
					res->insert_duplex_edge(i,j);
					rest--;
				}
			}
		}
		return res;
	}
	return to_Tanner_graph(wcycle_as_binary_matrix(),code_len,msg_len);
}

///////////////////////////
// Quasi-Cyclic generator//
//                       //
///////////////////////////
LDPC_QuasiCyclic_generator::LDPC_QuasiCyclic_generator(int _Wr,int _Wc,int _seed):
	Wr(_Wr),
	Wc(_Wc),
	seed(_seed){}

LDPC_generator::GENERATOR_PROPERTY LDPC_QuasiCyclic_generator::init(int _code_len,int _msg_len){
	if(_code_len%Wr!=0||(_code_len-_msg_len)%Wc!=0||
		(_code_len/Wr!=(_code_len-_msg_len)/Wc))
		return GENERATOR_PROPERTY::INVALID;
	this->code_len=_code_len;
	this->msg_len=_msg_len;
	return GENERATOR_PROPERTY::REGULAR;
}
unique_ptr<Tanner_graph> LDPC_QuasiCyclic_generator::as_Tanner_graph(){
	unique_ptr<Tanner_graph> res(new Tanner_graph(code_len,code_len-msg_len));
	int sidelen=code_len/Wr;

	init_rand(seed);

	for(int i=0;i<Wc;i++)
		for(int j=0;j<Wr;j++){
			int ran=rand_next(sidelen);
			for(int k=0;k<sidelen;k++)
				res->insert_duplex_edge(j*sidelen+(k+ran)%sidelen,i*sidelen+k);
		}
	return res;
}
unique_ptr<binary_matrix> LDPC_QuasiCyclic_generator::as_binary_matrix(){
	unique_ptr<binary_matrix> res(new binary_matrix(code_len,code_len-msg_len));
	int sidelen=code_len/Wr;

	init_rand(seed);

	for(int i=0;i<Wc;i++)
		for(int j=0;j<Wr;j++){
			int ran=rand_next(sidelen);
			for(int k=0;k<sidelen;k++)
				res->operator[](i*sidelen+k).set(j*sidelen+(k+ran)%sidelen,true);
		}
	return res;
}

LDPC_array_generator::LDPC_array_generator(int _Wr,int _Wc,bool _upper_tri):
	Wr(_Wr),
	Wc(_Wc),
	upper_tri(_upper_tri){}

LDPC_generator::GENERATOR_PROPERTY LDPC_array_generator::init(int _code_len, int _msg_len){
	if (_code_len%Wr != 0 || (_code_len - _msg_len) % Wc != 0 ||
		(_code_len / Wr != (_code_len - _msg_len) / Wc))
		return GENERATOR_PROPERTY::INVALID;

	if (Wr>_code_len / Wr)return GENERATOR_PROPERTY::INVALID;

	this->code_len = _code_len;
	this->msg_len = _msg_len;


	if (upper_tri)return (Wr <= 3 ? 0 : GENERATOR_PROPERTY::GIRTH_6) | GENERATOR_PROPERTY::UPPER_TRIANGLE | GENERATOR_PROPERTY::FULL_RANK;
	else return (Wr <= 3 ? 0 : GENERATOR_PROPERTY::GIRTH_6) | GENERATOR_PROPERTY::FULL_RANK | GENERATOR_PROPERTY::REGULAR;
}

std::unique_ptr<Tanner_graph> LDPC_array_generator::as_Tanner_graph(){
	unique_ptr<Tanner_graph> res(new Tanner_graph(code_len,code_len-msg_len));
	int sidelen=code_len/Wr;
	for(int i=0;i<Wr;i++)
		for(int j=0;j<Wc;j++){
			if(!upper_tri){
				int power=i*j;
				int xoffset=i*sidelen;
				int yoffset=j*sidelen;
				for(int k=0;k<sidelen;k++)
					res->insert_duplex_edge(xoffset+(power+k)%sidelen,yoffset+k);
			}
			else{
				if(i<j)continue;
				int power=(i-j)*j;
				int xoffset=i*sidelen;
				int yoffset=j*sidelen;
				for(int k=0;k<sidelen;k++)
					res->insert_duplex_edge(xoffset+(power+k)%sidelen,yoffset+k);
			}
		}
	return res;
}
std::unique_ptr<binary_matrix> LDPC_array_generator::as_binary_matrix(){
	return to_binary_matrix(as_Tanner_graph(),code_len,msg_len);
}



#include "libOTe/Tools/BlkAccCode/ChosenBaaCode.h"
#include <chrono>
#include <algorithm>
#include <iostream>
using namespace osuCrypto;
template<u64 K> void bench(u64 n) {
    PRNG p(block(12,34));
    AlignedUnVector<block> original(n), a(n), b(n);
    p.get(original.data(), n);
    std::vector<double> setup, single, pair;
    block check=ZeroBlock;
    for(int i=0;i<6;++i) {
        ChosenBaaCode<K> code;
        auto t0=std::chrono::steady_clock::now(); code.config(n, block(56,78));
        auto t1=std::chrono::steady_clock::now();
        a=original; b=original;
        auto t2=std::chrono::steady_clock::now(); code.dualEncode(a);
        auto t3=std::chrono::steady_clock::now();
        auto expected=a;
        a=original;
        auto t4=std::chrono::steady_clock::now(); code.dualEncode2(a,b);
        auto t5=std::chrono::steady_clock::now();
        check=ZeroBlock;
        for(u64 j=0;j<code.outputSize();++j) {
            if(a[j]!=expected[j] || b[j]!=expected[j]) throw std::runtime_error("mismatch");
            check^=a[j];
        }
        if(i) {
            setup.push_back(std::chrono::duration<double,std::milli>(t1-t0).count());
            single.push_back(std::chrono::duration<double,std::milli>(t3-t2).count());
            pair.push_back(std::chrono::duration<double,std::milli>(t5-t4).count());
        }
    }
    for(auto* x:{&setup,&single,&pair})std::sort(x->begin(),x->end());
    std::cout<<K<<","<<n<<","<<setup[2]<<","<<single[2]<<","<<pair[2]<<","<<check<<std::endl;
}
int main(int argc, char** argv)
{
    const u64 n = argc > 1 ? std::stoull(argv[1]) : 65536;
    if (!n || n % 16 || n > std::numeric_limits<u32>::max())
        throw std::invalid_argument("Length must be a positive multiple of 16 fitting u32.");
    std::cout << "K,n,config_ms,single_ms,pair_ms,checksum\n";
    bench<8>(n);
    bench<4>(n);
}

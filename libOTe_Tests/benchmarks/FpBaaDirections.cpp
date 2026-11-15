// Standalone comparison with gen-BAA's optimized prime-field reference.
// Build with its bench directory on the include path; see ChosenBaaDirections.md.
#include "width_one_small_q_shared.inc"

namespace fp128 {
template<unsigned T> inline void transpose_newton_steps(Batch43 (&v)[8], const Batch43* in) {
    v[0]=batch_add(v[0],in[T]);
    constexpr unsigned count=(15-T<7)?15-T:7;
    #pragma GCC unroll 7
    for(unsigned j=count;j-- >0;)v[j+1]=batch_add(v[j+1],v[j]);
    if constexpr(T>1)transpose_newton_steps<T-1>(v,in);
}
inline void transpose_newton_batch8(const F* input,F* output) {
    Batch43 raw[16];
    #pragma GCC unroll 4
    for(unsigned c=0;c<16;c+=4) {
        __m512i a,b,d,e,f,g,h,j;
        transpose128(_mm512_loadu_si512(input+c),_mm512_loadu_si512(input+16+c),
                     _mm512_loadu_si512(input+32+c),_mm512_loadu_si512(input+48+c),a,b,d,e);
        transpose128(_mm512_loadu_si512(input+64+c),_mm512_loadu_si512(input+80+c),
                     _mm512_loadu_si512(input+96+c),_mm512_loadu_si512(input+112+c),f,g,h,j);
        raw[c]=batch_unpack(a,f);raw[c+1]=batch_unpack(b,g);
        raw[c+2]=batch_unpack(d,h);raw[c+3]=batch_unpack(e,j);
    }
    Batch43 v[8]{};v[7]=raw[15];transpose_newton_steps<14>(v,raw);v[0]=batch_add(v[0],raw[0]);
    // Transposed coefficient sums are at most 6436, so the same unreduced
    // three-limb representation stays below 2^57. Reduce each output once.
    BatchPair values[8];
    #pragma GCC unroll 8
    for(unsigned j=0;j<8;++j)values[j]=batch_reduce(v[j]);
    #pragma GCC unroll 2
    for(unsigned group=0;group<2;++group) {
        const __m512i indices=group?_mm512_setr_epi64(4,12,5,13,6,14,7,15):_mm512_setr_epi64(0,8,1,9,2,10,3,11);
        #pragma GCC unroll 2
        for(unsigned c=0;c<8;c+=4) {
            const __m512i a=_mm512_permutex2var_epi64(values[c].low,indices,values[c].high);
            const __m512i b=_mm512_permutex2var_epi64(values[c+1].low,indices,values[c+1].high);
            const __m512i d=_mm512_permutex2var_epi64(values[c+2].low,indices,values[c+2].high);
            const __m512i e=_mm512_permutex2var_epi64(values[c+3].low,indices,values[c+3].high);
            __m512i r0,r1,r2,r3;transpose128(a,b,d,e,r0,r1,r2,r3);
            F* dest=output+group*32+c;
            _mm512_storeu_si512(dest,r0);_mm512_storeu_si512(dest+8,r1);
            _mm512_storeu_si512(dest+16,r2);_mm512_storeu_si512(dest+24,r3);
        }
    }
}
inline void transpose_newton(const F* input,F* output,size_t n) {
    size_t i=0;
    for(;i+128<=n;i+=128)transpose_newton_batch8(input+i,output+i/2);
    for(;i<n;i+=16) {
        Lazy128 v[8]{};v[7]={input[i+15],0};
        for(unsigned t=14;t>0;--t) {
            v[0]=lazy_add(v[0],{input[i+t],0});
            for(unsigned j=std::min(7u,15-t);j-- >0;)v[j+1]=lazy_add(v[j+1],v[j]);
        }
        v[0]=lazy_add(v[0],{input[i],0});
        for(unsigned j=0;j<8;++j)output[i/2+j]=lazy_reduce(v[j]);
    }
}
template<bool AllOne> inline void transpose_scan(const F* input,F* output,const uint32_t* meta,size_t n) {
    F sum=0;uint32_t coefficient=1;
    for(size_t end=n;end;end-=16) {
        const size_t i=end-16;
        if(i>=64) {
            #pragma GCC unroll 16
            for(unsigned j=0;j<16;++j)__builtin_prefetch(output+(meta[i-64+j]&MASK21),0,1);
        }
        #pragma GCC unroll 16
        for(unsigned j=16;j-- >0;) {
            if constexpr(AllOne)sum=add_asm(sum,input[i+j]);
            else sum=madd_small(sum,coefficient,input[i+j]);
            coefficient=(meta[i+j]>>21)+1;
            output[meta[i+j]&MASK21]=sum;
        }
    }
}
}

template<int Id> void directions(size_t n,uint64_t seed,int iterations) {
    using C=CertifiedConfig<Id>;
    const size_t k=n/2;
    auto stages=certified_setup<Id>(n,seed);
    Rng random{seed};std::vector<F> message(k),original(n),output(n),scratch(n),dual(n),expected(n);
    for(auto& x:message)x=random.field();for(auto& x:original)x=random.field();
    auto forward=[&] {
        fp128::encode_block8_16(message.data(),output.data(),k);
        C::scan(output.data(),scratch.data(),stages[0].data(),n);
        C::scan(scratch.data(),output.data(),stages[1].data(),n);
    };
    // Independent full-vector forward reference before measurement.
    certified_local_reference(message.data(),expected.data(),k);
    certified_reference<Id>(expected.data(),scratch.data(),stages[0].data(),n);
    certified_reference<Id>(scratch.data(),expected.data(),stages[1].data(),n);
    std::vector<double> ft,tt;uint64_t check=0;
    for(int i=0;i<iterations+2;++i) {
        auto start=std::chrono::steady_clock::now();forward();
        double ms=std::chrono::duration<double,std::milli>(std::chrono::steady_clock::now()-start).count();
        if(i>=2)ft.push_back(ms);check^=uint64_t(output[i%n]);
    }
    if(output!=expected)throw std::runtime_error("Fp forward reference mismatch");
    for(int i=0;i<iterations+2;++i) {
        dual=original;
        auto start=std::chrono::steady_clock::now();
        fp128::transpose_scan<C::q==1>(dual.data(),scratch.data(),stages[1].data(),n);
        fp128::transpose_scan<C::q==1>(scratch.data(),dual.data(),stages[0].data(),n);
        fp128::transpose_newton(dual.data(),dual.data(),n);
        double ms=std::chrono::duration<double,std::milli>(std::chrono::steady_clock::now()-start).count();
        if(i>=2)tt.push_back(ms);check^=uint64_t(dual[i%k]);
    }
    F lhs=0,rhs=0;
    for(size_t i=0;i<n;++i)lhs=fp128::add(lhs,fp128::mul(original[i],output[i]));
    for(size_t i=0;i<k;++i)rhs=fp128::add(rhs,fp128::mul(message[i],dual[i]));
    if(lhs!=rhs)throw std::runtime_error("Fp transpose identity mismatch");
    std::sort(ft.begin(),ft.end());std::sort(tt.begin(),tt.end());
    std::cout<<"fp_q"<<C::q<<','<<k<<','<<n<<','<<seed<<','<<ft[iterations/2]<<','<<tt[iterations/2]<<','<<check<<std::endl;
}
void test_transpose() {
    Rng rng{918273};
    for(size_t n:{16u,32u,48u,128u,144u,256u}) {
        std::vector<F> input(n),out(n/2),reference(n/2);
        for(unsigned pattern=0;pattern<19;++pattern) {
            for(size_t i=0;i<n;++i)input[i]=pattern<16?F(i%16==pattern):pattern==16?P-1:pattern==17?0:rng.field();
            for(size_t b=0;b<n/16;++b)for(unsigned j=0;j<8;++j) {
                F sum=j==7?input[b*16+15]:0;
                for(unsigned t=0;t<15;++t)sum=ref_add(sum,fp128::mul(input[b*16+t],choose(t,j)));
                reference[b*8+j]=sum;
            }
            fp128::transpose_newton(input.data(),out.data(),n);
            if(out!=reference)throw std::runtime_error("Newton transpose oracle mismatch");
            auto inplace=input;fp128::transpose_newton(inplace.data(),inplace.data(),n);
            if(!std::equal(reference.begin(),reference.end(),inplace.begin()))throw std::runtime_error("Newton transpose alias mismatch");
        }
    }
}
int main(int argc,char** argv) {
    for(const char* path:{"/tmp/prindal-addition-encoder-benchmark.lock","/tmp/bare-spin-benchmark.lock","/tmp/hypercat-benchmark.lock"}) {
        int fd=open(path,O_CREAT|O_RDWR,0600);
        if(fd<0||flock(fd,LOCK_EX|LOCK_NB))throw std::runtime_error("benchmark lock unavailable");
    }
    if(argc==2 && std::string(argv[1])=="--test") {
        small_q_arithmetic_test();test_transpose();
        std::cout<<"Fp arithmetic and transpose tests passed\n";return 0;
    }
    const size_t n=argc>1?std::stoull(argv[1]):1u<<21;
    const int it=argc>2?std::stoi(argv[2]):15;
    const uint64_t seed=argc>3?std::stoull(argv[3]):1;
    if(!n||n%16||n>(1u<<21)||it<1)throw std::invalid_argument("Fp benchmark arguments");
    std::cout<<"code,k,n,seed,forward_ms,transpose_ms,checksum\n";
    directions<4>(n,seed,it);directions<0>(n,seed,it);
}

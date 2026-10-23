// Diagnostic only: select the old fixed-key child generator or the current
// schedule in one executable. Production headers and online code are unchanged.
#define DpfTreeHash RekeyedDpfTreeHash
#include "libOTe/Dpf/DpfTreeHash.h"
#undef DpfTreeHash
namespace osuCrypto::details
{
    inline bool probeRekey = true;
    class DpfTreeHash : public RekeyedDpfTreeHash
    {
    public:
        using RekeyedDpfTreeHash::RekeyedDpfTreeHash;
        const ::osuCrypto::AES& at(u64 counter)
        {
            return probeRekey ? RekeyedDpfTreeHash::at(counter) : mAesFixedKey;
        }
        __attribute__((noinline)) void children(block seed, block* output)
        {
            const auto& aes = at(mCounter++);
            output[0] = aes.hashBlock(seed);
            output[1] = aes.hashBlock(seed ^ OneBlock);
        }
    };
}
#define DMPF_BENCHMARK_NO_MAIN
#include "cached_leaf_e2e_benchmark.cpp"
#undef DMPF_BENCHMARK_NO_MAIN
#include <sched.h>
bool probeLayout = false;

double median(std::vector<double> x)
{
    std::sort(x.begin(), x.end());
    return x[x.size()/2];
}

template<typename Protocol>
void probe(const std::string& profile, bool rekey, u64 trial, auto init)
{
    details::probeRekey = rekey;
    constexpr u64 n = 1ull << 20, t = 16;
    PRNG data(block(789,456)), coins0(block(456,987)), coins1(block(654,123));
    PRNG base(block(345,876));
    std::array<Protocol,2> dpf;
    for (u64 p=0; p<2; ++p) init(dpf[p],p,n);
    setBase(dpf,base);
    Matrix<u64> a0(1,t), a1(1,t);
    std::array<u64,t> points;
    for(u64 i=0;i<t;++i)
    {
        points[i]=(i*65537+137)%n;
        a0(i)=data.get<u64>() & (2*n-1);
        a1(i)=a0(i)^points[i];
    }
    auto socks=coproto::LocalAsyncSocket::makePair();
    const auto start=Clock::now();
    auto setup=macoro::sync_wait(macoro::when_all_ready(
        dpf[0].setPoints(a0,coins0,socks[0]),dpf[1].setPoints(a1,coins1,socks[1])));
    std::get<0>(setup).result(); std::get<1>(setup).result();
    const auto setupMs=elapsed(start);
    std::array<Timer,2> timers;
    for(u64 p=0;p<2;++p) dpf[p].setTimer(timers[p]);
    std::array<std::vector<u64>,2> out{std::vector<u64>(n),std::vector<u64>(n)};
    std::vector<u64> expected(n), b0(t), b1(t);
    std::vector<double> total, leaves, updates, other;
    for(u64 round=0;round<28;++round)
    {
        std::fill(expected.begin(),expected.end(),0);
        for(u64 i=0;i<t;++i)
        {
            b0[i]=data.get<u64>(); b1[i]=data.get<u64>();
            expected[points[i]]+=b0[i]+b1[i];
        }
        for(auto& timer:timers) timer.reset();
        const auto begin=Clock::now();
        auto result=macoro::sync_wait(macoro::when_all_ready(
            dpf[0].expand(b0,coins0,socks[0],[&](u64,u64 x,u64 v){out[0][x]=v;},CoeffCtxInteger{}),
            dpf[1].expand(b1,coins1,socks[1],[&](u64,u64 x,u64 v){out[1][x]=v;},CoeffCtxInteger{})));
        std::get<0>(result).result(); std::get<1>(result).result();
        const auto ms=elapsed(begin);
        double leafMs=0, updateMs=0;
        for(auto& timer:timers)
        {
            const auto delta=[&](const char* a,const char* b){
                return std::chrono::duration<double,std::milli>(timer[b]-timer[a]).count();};
            if constexpr(requires {dpf[0].mHashSeed;})
            {
                leafMs+=delta("perm done","expandLeaves done");
                updateMs+=delta("gamma done","update done");
            }
            else
            {
                leafMs+=delta("value scatter done","leaf expansion done");
                updateMs+=delta("gamma done","expand done");
            }
        }
        for(u64 x=0;x<n;++x)
            if(out[0][x]+out[1][x]!=expected[x]) throw std::runtime_error("Incorrect probe output");
        if(round>=4)
        {
            total.push_back(ms); leaves.push_back(leafMs); updates.push_back(updateMs);
            other.push_back(ms-leafMs-updateMs);
        }
    }
    std::cout<<"stages,"<<profile<<','<<trial<<','<<(rekey?"rekey":"fixed")<<','
        <<setupMs<<','<<median(total)<<','<<median(leaves)<<','<<median(updates)<<','
        <<median(other)<<",checked"<<std::endl;

    // Same values and same output buffers; vary only the input buffer offset.
    // This tests layout sensitivity, not an old/new protocol comparison.
    if(profile!="rev3" || !probeLayout || !rekey) return;
    auto& source=dpf[0];
    u64 count=0;
    for(auto row:source.mLeafShares) count+=row.size();
    std::vector<block> storage(count+512);
    auto* aligned=reinterpret_cast<block*>(
        (reinterpret_cast<uintptr_t>(storage.data())+4095)&~uintptr_t(4095));
    std::vector<std::span<block>> rows(source.mLeafShares.size());
    std::vector<AlignedUnVector<u64>> expanded;
    AlignedUnVector<u64> sums;
    std::array<std::vector<double>,4> timings;
    const std::array<u64,4> offsets{0,64,512,2048};
    std::vector<AlignedUnVector<u64>> reference;
    for(u64 repetition=0;repetition<32;++repetition)
        for(u64 visit=0;visit<4;++visit)
        {
            const auto variant=(repetition%2) ? 3-visit:visit;
            auto* dest=aligned+offsets[variant]/sizeof(block);
            for(u64 row=0;row<rows.size();++row)
            {
                rows[row]={dest,source.mLeafShares[row].size()};
                std::copy(source.mLeafShares[row].begin(),source.mLeafShares[row].end(),dest);
                dest+=rows[row].size();
            }
            block seed(123,456);
            const auto begin=Clock::now();
            details::expandCachedDpfLeaves<u64>(0,source.mSparseSets,rows,expanded,sums,seed,CoeffCtxInteger{});
            const auto ms=elapsed(begin);
            if(reference.empty()) reference=expanded;
            for(u64 row=0;row<rows.size();++row)
                if(!std::equal(expanded[row].begin(),expanded[row].end(),reference[row].begin()))
                    throw std::runtime_error("Layout replay mismatch");
            if(repetition>=4) timings[variant].push_back(ms);
        }
    for(u64 variant=0;variant<4;++variant)
        std::cout<<"layout,rev3,"<<offsets[variant]<<','<<median(timings[variant])
            <<",output_offset="<<(reinterpret_cast<uintptr_t>(expanded[0].data())%4096)<<",checked"<<std::endl;
}

int main(int argc,char** argv)
{
    try
    {
        const std::string profile=argc>1?argv[1]:"rev3";
        const int cpu=argc>2?std::stoi(argv[2]):-1;
        probeLayout=argc>3 && std::string(argv[3])=="layout";
        if(profile!="rev3" && profile!="waterfall3" && profile!="waterfall4")
            throw std::runtime_error("Unknown profile");
        if(cpu>=0)
        {
            cpu_set_t set; CPU_ZERO(&set); CPU_SET(cpu,&set);
            if(sched_setaffinity(0,sizeof(set),&set)) throw std::runtime_error("CPU affinity failed");
        }
        std::cout<<std::fixed<<std::setprecision(4);
        // Warm up one setup per mode, then ABBA followed by BAAB.
        // Layout replay is a separate invocation, never between stage trials.
        for(u64 trial=0;trial<(probeLayout?1:10);++trial)
        {
            const bool rekey=std::array<bool,10>{true,false,true,false,false,true,false,true,true,false}[trial];
            if(profile=="rev3")
                probe<RevCuckooDmpf<u64>>(profile,rekey,trial,
                    [](auto& p,u64 party,u64 n){p.init(party,16,1,n,3,40,40,false);});
            else
                probe<WaterfallDmpf<u64>>(profile,rekey,trial,
                    [&](auto& p,u64 party,u64 n){p.init(party,16,1,n,
                        profile=="waterfall4"?WaterfallConfig::compact4N():WaterfallConfig::compact3N(),false);});
        }
    }
    catch(const std::exception& e){std::cerr<<e.what()<<std::endl;return 1;}
}

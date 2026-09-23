// Stationary or regular-noise Silent OT, one party at a time. No network timing.
#include "libOTe/TwoChooseOne/Silent/SilentOtExtSender.h"
#include "libOTe/TwoChooseOne/Silent/SilentOtExtReceiver.h"
#include "libOTe/Tools/Pprf/StationaryPprf.h"
#include "coproto/Socket/BufferingSocket.h"
#include "Common.h"
#include <algorithm>
#include <chrono>
#include <iomanip>
#include <iostream>
using namespace osuCrypto;
using Clock = std::chrono::steady_clock;
static void require(bool ok) { if(!ok) throw std::runtime_error("SPIN OT benchmark check failed"); }
static void base(SilentOtExtSender& s, SilentOtExtReceiver& r, PRNG& rng, block delta) {
    const auto count=s.baseCount();
    std::vector<std::array<block,2>> pairs(count.mBaseOtCount);
    for(auto& p:pairs) {p[0]=rng.get();p[1]=rng.get();}
    std::vector<block> a(count.mBaseVoleCount),b(a.size());
    BitVector c(a.size()); c.randomize(rng);
    for(u64 i=0;i<a.size();++i) {b[i]=rng.get();a[i]=b[i]^(c[i]?delta:ZeroBlock);}
    s.setBaseCors(pairs,b,delta);
    auto choices=r.sampleBaseChoiceBits(rng);
    require(choices.size()==pairs.size());
    std::vector<block> selected(choices.size());
    for(u64 i=0;i<selected.size();++i) selected[i]=pairs[i][choices[i]];
    r.setBaseCors(selected,choices,a,c);
}
static double ms(Clock::time_point a,Clock::time_point b) {
    return std::chrono::duration<double,std::milli>(b-a).count();
}
static double stage(const Timer& t,const std::string& a,const std::string& b) {
    return std::chrono::duration<double,std::milli>(t[b]-t[a]).count();
}
static volatile u64 consumed;
// Read every output byte; no per-block volatile accesses in the scan.
static void consume(span<const std::array<block,2>> messages) {
    block a=ZeroBlock,b=ZeroBlock;
    for(const auto& pair:messages) {a^=pair[0];b^=pair[1];}
    const auto sum=a^b;
    consumed=sum.get<u64>(0)^sum.get<u64>(1);
}
struct Sample {double leaves,compress,hash,total,consume=0;};
static void report(const char* role,u64 k,const std::vector<Sample>& samples,bool regular) {
    auto median=[&](auto field) {std::vector<double> v;for(auto x:samples)v.push_back(x.*field);
        std::sort(v.begin(),v.end());return v[v.size()/2];};
    const auto total=median(&Sample::total);
    std::cout<<std::setprecision(9)<<"{\"party\":\""<<role<<"\",\"K\":"<<k
        <<(regular?",\"expansion_ms\":" : ",\"leaves_ms\":")<<median(&Sample::leaves)
        <<(regular?",\"compress_ms\":" : ",\"compress_refresh_ms\":")<<median(&Sample::compress)
        <<",\"hash_ms\":"<<median(&Sample::hash)<<",\"total_ms\":"<<total
        <<",\"consume_ms\":"<<median(&Sample::consume)
        <<",\"million_ot_per_s\":"<<k/(total*1000)<<",\"samples\":[";
    for(size_t i=0;i<samples.size();++i) {if(i)std::cout<<',';auto x=samples[i];
        std::cout<<'['<<x.leaves<<','<<x.compress<<','<<x.hash<<','<<x.total<<','<<x.consume<<']';}
    std::cout<<"]}\n";
}
int main(int argc,char** argv) {try {
    const unsigned exponent=argc>1?std::stoul(argv[1]):18;
    const unsigned trials=argc>2?std::stoul(argv[2]):31;
    bool paired=false,streaming=false,readOutput=false,regular=false;
    for(int i=3;i<argc;++i) {
        const std::string flag=argv[i];
        if(flag=="paired") paired=true;
        else if(flag=="nt") streaming=true;
        else if(flag=="consume") readOutput=true;
        else if(flag=="regular") regular=true;
        else throw std::invalid_argument("unknown benchmark flag");
    }
    if(exponent<13 || exponent>24 || !trials || !(trials&1))
        throw std::invalid_argument("usage: spin_stationary_bench [exponent 13..24] [odd trials] [paired] [nt] [consume] [regular]");
    const u64 k=1ull<<exponent;
    SilentOtExtSender s; SilentOtExtReceiver r;
    PRNG ps(block(1,4)),pr(block(3,7)),bases(block(17,19));
    const block delta=block(345,679);
    const auto noise=regular?SdNoiseDistribution::Regular:SdNoiseDistribution::Stationary;
    s.configure(k,2,1,SilentSecType::SemiHonest,noise,MultType::Spin);
    r.configure(k,2,1,SilentSecType::SemiHonest,noise,MultType::Spin);
    s.mSpin=std::make_unique<SpinOtState>(k,s.mCodeSeed,false,s.mNoiseDist);
    r.mSpin=std::make_unique<SpinOtState>(k,r.mCodeSeed,true,r.mNoiseDist);
    s.mB.reserve(s.mNoiseVecSize);r.mA.reserve(r.mNoiseVecSize);
    std::vector<std::array<block,2>> sent(k);std::vector<block> received(k);BitVector choices(k);
    // Untimed initial correctness check. Stationary mode also caches tree seeds;
    // regular mode must still perform complete tree expansion in every timed batch.
    auto sockets=cp::LocalAsyncSocket::makePair();
    base(s,r,bases,delta);
    auto ts=s.silentSendInplace(delta,k,ps,sockets[0]);
    auto tr=r.silentReceiveInplace(k,pr,sockets[1],ChoiceBitPacking::True);
    tests_libOTe::eval(ts,tr);
    auto* sg=regular?nullptr:dynamic_cast<StationaryPprfSender<block,CoeffCtxGF2>*>(&s.gen());
    auto* rg=regular?nullptr:dynamic_cast<StationaryPprfReceiver<block,CoeffCtxGF2>*>(&r.gen());
    require(regular || (sg && rg && sg->mExpanded && rg->mExpanded));
    require(s.mSpin->code.code().setup_options().mode==
        (regular?spin::SetupMode::Full:spin::SetupMode::BankedHeuristic));
    s.hash(sent,ChoiceBitPacking::True,streaming);r.hash(choices,received,ChoiceBitPacking::True);
    for(u64 i=0;i<k;++i) require(received[i]==sent[i][choices[i]]);
    const auto* ss=sg?sg->mShare.data():nullptr;const auto* rs=rg?rg->mShare.data():nullptr;
    const auto* sw=s.mSpin.get();const auto* rw=r.mSpin.get();
    const auto fixedDescriptor=s.mSpin->code.descriptor();
    std::cout<<"{\"geometry\":true,\"K\":"<<k<<",\"N\":"<<s.mNoiseVecSize
        <<",\"noise\":\""<<(regular?"regular":"stationary")<<"\""
        <<",\"partitions\":"<<s.mNumPartitions<<",\"tree_size\":"<<s.mSizePer
        <<",\"cached_leaf_bytes_per_party\":"<<(sg?sg->mShare.size()*sizeof(block):0)
        <<",\"paired_resident\":"<<(paired?"true":"false")
        <<",\"streaming_stores\":"<<(streaming?"true":"false")
        <<",\"consume_output\":"<<(readOutput?"true":"false")
        <<",\"base_ot_per_batch\":"<<s.baseCount().mBaseOtCount
        <<",\"base_vole_per_batch\":"<<s.baseCount().mBaseVoleCount<<"}\n";
    // Sender-only measurement: discard peer caches, routing, and workspace.
    // The initial complete hashed-OT check above establishes protocol agreement;
    // paired mode additionally checks every later batch with the peer resident.
    if(!paired) {r.clear();std::vector<block>().swap(received);choices.resize(0);}
    cp::BufferingSocket sendSocket,recvSocket;
    Timer st,rt; s.setTimer(st);r.setTimer(rt);
    std::vector<Sample> sender,receiver;
    for(unsigned round=0;round<trials+5;++round) {
        require(regular || s.baseCount().mBaseOtCount==0);
        if(paired) base(s,r,bases,delta);
        else {
            std::vector<std::array<block,2>> pairs(s.baseCount().mBaseOtCount);
            for(auto& p:pairs) {p[0]=bases.get();p[1]=bases.get();}
            std::vector<block> b(s.baseCount().mBaseVoleCount);
            for(auto& x:b)x=bases.get();
            s.setBaseCors(pairs,b,delta);
        } // Fresh base correlations supplied, not generated in timer.
        const auto seed=s.mCodeSeed;
        const auto counter=sg?sg->mExpandCounter:0;
        st.reset();rt.reset();
        // Sender completes before receiver starts. Buffered transport introduces
        // no network wait or concurrent peer compute into either interval.
        auto begin=Clock::now();
        macoro::sync_wait(s.silentSendInplace(delta,k,ps,sendSocket));
        auto encoded=Clock::now();
        s.hash(sent,ChoiceBitPacking::True,streaming);
        auto hashed=Clock::now();
        if(readOutput) consume(sent);
        auto end=Clock::now();
        Sample a{stage(st,"sender.expand.start","sender.expand.pprf"),
                 stage(st,"sender.expand.pprf","sender.expand.dualEncode"),ms(encoded,hashed),ms(begin,end),ms(hashed,end)};
        macoro::sync_wait(sendSocket.flush());
        auto wire=sendSocket.getOutbound();require(bool(wire));
        if(!paired) {
            require(s.mCodeSeed==(regular?seed:mAesFixedKey.hashBlock(seed)));
            require(sw==s.mSpin.get());
            if(regular) require(s.mSpin->code.descriptor()==fixedDescriptor);
            else require(sg->mExpandCounter==counter+1 && ss==sg->mShare.data());
            if(round>=5)sender.push_back(a);
            continue;
        }
        recvSocket.processInbound(*wire);
        begin=Clock::now();
        macoro::sync_wait(r.silentReceiveInplace(k,pr,recvSocket,ChoiceBitPacking::True));
        encoded=Clock::now();
        r.hash(choices,received,ChoiceBitPacking::True);
        end=Clock::now();
        Sample b{stage(rt,"recver.expand.start","recver.expand.pprf"),
                 stage(rt,"recver.expand.pprf","recver.expand.dualEncode"),ms(encoded,end),ms(begin,end)};
        require(s.mCodeSeed==r.mCodeSeed && s.mCodeSeed==(regular?seed:mAesFixedKey.hashBlock(seed)));
        require(sw==s.mSpin.get() && rw==r.mSpin.get());
        if(regular) require(s.mSpin->code.descriptor()==fixedDescriptor && r.mSpin->code.descriptor()==fixedDescriptor);
        else {
            require(sg->mExpandCounter==counter+1 && rg->mExpandCounter==sg->mExpandCounter);
            require(ss==sg->mShare.data() && rs==rg->mShare.data());
        }
        for(u64 i=0;i<k;++i) require(received[i]==sent[i][choices[i]]);
        if(round>=5) {sender.push_back(a);receiver.push_back(b);}
    }
    report("sender",k,sender,regular);if(paired)report("receiver",k,receiver,regular);
    std::cout<<"{\"initial_hashed_ots_verified\":true,\"all_batches_verified\":"<<(paired?"true":"false")
        <<",\"cached_leaves_reused\":"<<(regular?"false":"true")
        <<",\"fresh_code_each_batch\":"<<(regular?"false":"true")
        <<",\"fixed_full_code_reused\":"<<(regular?"true":"false")<<"}\n";
}catch(const std::exception& e) {std::cerr<<e.what()<<'\n';return 1;}}

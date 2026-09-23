// Diagnostic only: cached seeds are synthetic. Uses the production leaf,
// SPIN adapter, and sender-hash paths; this is not a full OT benchmark.
#include "SpinBench.h"
#include "libOTe/config.h"
#include <iostream>
#if defined(ENABLE_SPIN) && defined(ENABLE_SILENTOT)
#include "libOTe/TwoChooseOne/Silent/SilentOtExtSender.h"
#include "libOTe/Tools/Pprf/StationaryPprf.h"
#include "coproto/Socket/BufferingSocket.h"
#include <algorithm>
#include <chrono>
#include <iomanip>
#include <iostream>
using namespace osuCrypto;
namespace {
using Clock=std::chrono::steady_clock;
static double ms(Clock::time_point a,Clock::time_point b) {
    return std::chrono::duration<double,std::milli>(b-a).count();
}
} // namespace
int spinCompressionBenchmark(CLP& cmd) {try {
    const auto family=cmd.getOr<std::string>("family","fixed");
    const auto context=cmd.getOr<std::string>("context","bare");
    const unsigned trials=cmd.getOr<unsigned>("trials",31);
    if((family!="fixed" && family!="frozen" && family!="fresh") ||
       (context!="bare" && context!="copy" && context!="leaves" && context!="resident" && context!="stream" && context!="stream-nt" && context!="pipeline") || !trials)
        throw std::invalid_argument("invalid diagnostic mode");
    const bool generate=context!="bare" && context!="copy";
    const bool output=context=="resident" || context=="stream" || context=="stream-nt" || context=="pipeline";
    constexpr u64 k=1ull<<18;
    const auto noise=family=="fixed"?SdNoiseDistribution::Regular:SdNoiseDistribution::Stationary;
    SilentOtExtSender s;
    // Hold stationary geometry fixed even when the encoder uses full setup.
    s.configure(k,2,1,SilentSecType::SemiHonest,SdNoiseDistribution::Stationary,MultType::Spin);
    s.mSpin=std::make_unique<SpinOtState>(k,s.mCodeSeed,false,noise);
    s.mB.resize(s.mNoiseVecSize);
    s.mDelta=block(345,679);
    StationaryPprfSender<block,CoeffCtxGF2> leaves;
    leaves.configure(s.mSizePer,s.mNumPartitions);
    const auto active=s.mSizePer*s.mNumPartitions;
    leaves.mShare.resize(active);
    PRNG rng(block(123,456));
    for(auto& b:leaves.mShare) b=rng.get();
    for(auto& b:s.mB) b=rng.get();
    leaves.mExpanded=true;
    decltype(leaves)::VecF values(s.mNumPartitions);
    for(auto& b:values) b=rng.get();
    std::vector<std::array<block,2>> messages(output?k:0);
    cp::BufferingSocket socket;
    std::vector<std::array<double,4>> samples;
    for(unsigned r=0;r<trials+15;++r) {
        s.mB.resize(s.mNoiseVecSize);
        auto a=Clock::now();
        if(context=="copy") std::copy(leaves.mShare.begin(),leaves.mShare.end(),s.mB.begin());
        if(generate) {
            s.mB.resize(active);
            macoro::sync_wait(leaves.expand(socket,values,ZeroBlock,s.mB,PprfOutputFormat::ByTreeIndex,true,1,{}));
            s.mB.resize(s.mNoiseVecSize);
        }
        if(context!="bare") std::fill(s.mB.begin()+active,s.mB.end(),ZeroBlock);
        auto b=Clock::now();
        prepareSpin(s.mSpin,k,s.mCodeSeed,false,noise);
        auto c=Clock::now();
        s.mSpin->transpose(s.mB);
        auto d=Clock::now();
        if(family=="fresh") s.mCodeSeed=mAesFixedKey.hashBlock(s.mCodeSeed);
        if(context=="pipeline") {
            s.mB.resize(k);
            s.hash(messages,ChoiceBitPacking::True);
        }
        if(context=="stream") for(u64 i=0;i<k;++i) messages[i]={s.mB[i],s.mB[i]};
        if(context=="stream-nt") {
#ifdef OC_ENABLE_SSE2
            for(u64 i=0;i<k;++i) {
                _mm_stream_si128(&messages[i][0].mData,s.mB[i].mData);
                _mm_stream_si128(&messages[i][1].mData,s.mB[i].mData);
            }
            _mm_sfence();
#else
            throw std::runtime_error("stream-nt requires SSE2");
#endif
        }
        auto e=Clock::now();
        if(generate) {
            macoro::sync_wait(socket.flush());
            if(!socket.getOutbound()) throw std::runtime_error("missing leaf correction");
        }
        if(r>=15) samples.push_back({ms(a,b),ms(b,c),ms(c,d),ms(d,e)});
    }
    auto median=[&](int column){std::vector<double> v;for(auto x:samples)v.push_back(x[column]);
        std::sort(v.begin(),v.end());return v[v.size()/2];};
    if(context=="stream" || context=="stream-nt")
        for(u64 i=0;i<k;++i)
            if(messages[i][0]!=s.mB[i] || messages[i][1]!=s.mB[i])
                throw std::runtime_error("output-store check failed");
    std::cout<<std::setprecision(9)<<"{\"family\":\""<<family<<"\",\"context\":\""<<context
        <<"\",\"K\":"<<k<<",\"setup_bytes\":"<<s.mSpin->code.code().setup_bytes()
        <<",\"workspace_bytes\":"<<s.mSpin->blocks.bytes()
        <<",\"stimulus_ms\":"<<median(0)<<",\"prepare_ms\":"<<median(1)
        <<",\"encode_ms\":"<<median(2)<<",\"post_ms\":"<<median(3)
        <<",\"checksum\":"<<(s.mB[0].get<u64>(0)^(output?messages[0][0].get<u64>(0):0))<<",\"samples\":[";
    for(size_t i=0;i<samples.size();++i) {if(i)std::cout<<',';auto x=samples[i];
        std::cout<<'['<<x[0]<<','<<x[1]<<','<<x[2]<<','<<x[3]<<']';}
    std::cout<<"]}\n";
    return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
#else
int spinCompressionBenchmark(osuCrypto::CLP&) {
    std::cerr<<"SPIN compression benchmark requires ENABLE_SPIN and ENABLE_SILENTOT\n";return 1;
}
#endif

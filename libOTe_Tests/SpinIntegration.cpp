#include "SpinIntegration.h"
#include "libOTe/config.h"
#include <cryptoTools/Common/TestCollection.h>

#if defined(ENABLE_SPIN) && defined(ENABLE_SILENTOT)
#include "libOTe/Tools/Spin/SpinCode.h"
#include "libOTe/TwoChooseOne/Silent/SilentOtExtSender.h"
#include "libOTe/TwoChooseOne/Silent/SilentOtExtReceiver.h"
#include "Common.h"
#include <cmath>
#include <source_location>
using namespace osuCrypto;
namespace {
static void require(bool b,const std::source_location where=std::source_location::current()) {
    if(!b) throw std::runtime_error(std::string(where.file_name())+":"+
        std::to_string(where.line())+": SPIN integration assertion failed");
}
template<class Fn> static void rejects(Fn f) {
    bool caught=false;try {f();} catch(const std::invalid_argument&) {caught=true;} require(caught);
}
// No operator^, nontrivial value type, stateful context. The context supplies all addition.
struct Value {u64 v=0; Value(){} explicit Value(u64 x):v(x){} };
struct Context {
    u64* calls;
    template<class F> bool characteristicTwo() const {return true;}
    template<class F> F make() const {return F{};}
    void plus(Value& r,const Value& a,const Value& b) const {++*calls;r.v=a.v^b.v;}
};
static void arithmetic() {
    for(auto mode:{spin::SetupMode::Full,spin::SetupMode::BankedHeuristic})
    for(auto p:{spin::Parameters::T128S19,spin::Parameters::T64S12,spin::Parameters::T64S12R2}) {
        const auto k=3*spin::message_alignment(p),n=2*k;
        SpinCode code({k,p,17,29},{},{mode});
        auto wb=code.make_workspace<block>(); auto wu=code.make_workspace<u64>();
        auto wy=code.make_workspace<u8>(); u64 calls=0;
        auto wc=code.make_workspace<Value>(Context{&calls});
        auto wf=code.make_workspace<block>(CoeffCtxGF128{});
        std::vector<block> b(n),f(n);std::vector<u64> u(n);
        std::vector<u8> y(n);std::vector<Value> c(n);
        PRNG rng(block(0,45));
        for(u64 i=0;i<n;++i) {u[i]=rng.get<u64>();b[i]=block(0,u[i]);f[i]=b[i];y[i]=u[i]&255;c[i].v=u[i];}
        code.transpose_inplace<block>(b,wb);
        code.transpose_inplace<block,CoeffCtxGF128>(f,wf);
        code.transpose_inplace<u64>(u,wu);code.transpose_inplace<u8>(y,wy);
        code.transpose_inplace<Value,Context>(c,wc);
        for(u64 i=0;i<n;++i) {require(b[i]==f[i]);require(b[i].get<u64>(0)==u[i]);require((u[i]&255)==y[i]);require(c[i].v==u[i]);}
        require(calls>0);
        rejects([&] {auto w=code.make_workspace<u64>(CoeffCtxInteger{});(void)w;});
        SpinCode other({k,p,18,29},{},{mode});
        rejects([&] {other.transpose_inplace<u64>(u,wu);});
        auto moved=std::move(wu);
        rejects([&] {code.transpose_inplace<u64>(u,wu);});
        code.transpose_inplace<u64>(u,moved);
    }
}
static void base(SilentOtExtSender& s,SilentOtExtReceiver& r,PRNG& prng,block d) {
    const auto count=s.baseCount();
    std::vector<std::array<block,2>> msgs(count.mBaseOtCount);
    for(auto& m:msgs) {m[0]=prng.get();m[1]=prng.get();}
    std::vector<block> a(count.mBaseVoleCount),b(a.size());BitVector c(a.size());c.randomize(prng);
    for(u64 i=0;i<a.size();++i) {b[i]=prng.get();a[i]=b[i]^(c[i]?d:ZeroBlock);}
    s.setBaseCors(msgs,b,d);
    auto choices=r.sampleBaseChoiceBits(prng);
    while(choices.size()<count.mBaseOtCount) choices.pushBack(prng.getBit());
    std::vector<block> recv(choices.size());
    for(u64 i=0;i<recv.size();++i) recv[i]=msgs[i][choices[i]];
    r.setBaseCors(recv,choices,a,c);
}
static void lifecycle() {
    std::unique_ptr<SpinOtState> state;
    const auto seed=block(17,29);
    prepareSpin(state,1,seed,false);
    const auto* original=state.get();
    prepareSpin(state,8192,seed,false);
    require(state.get()==original); // Same realized code reuses its scratch.
    prepareSpin(state,8193,seed,false);
    require(state->code.messageSize()==16384 && !state->choices);
    prepareSpin(state,8193,seed,true);
    require(state->choices.has_value());
    prepareSpin(state,65537,seed,true);
    require(state->code.code().specification().parameters==spin::Parameters::T128S19);
    require(state->code.messageSize()==81920);
    const auto oldDescriptor=state->code.descriptor();
    prepareSpin(state,65537,block(31,47),true);
    require(state->code.descriptor()!=oldDescriptor);
    const auto* valid=state.get();
    rejects([&]{prepareSpin(state,0,seed,true);});
    require(state.get()==valid);

    SilentOtExtSender s; SilentOtExtReceiver r;
    for(auto mult:{MultType::Spin,MultType::BlkAcc3x32,MultType::Spin}) {
        s.configure(4096,2,1,SilentSecType::SemiHonest,SdNoiseDistribution::Regular,mult);
        r.configure(4096,2,1,SilentSecType::SemiHonest,SdNoiseDistribution::Regular,mult);
        require(!s.mSpin && !r.mSpin);
        require(s.mB.capacity()==0 && r.mA.capacity()==0 && r.mC.capacity()==0);
        if(mult==MultType::Spin) {
            s.mSpin=std::make_unique<SpinOtState>(s.mRequestNumOts,s.mCodeSeed,false);
            r.mSpin=std::make_unique<SpinOtState>(r.mRequestNumOts,r.mCodeSeed,true);
            require(s.mSpin->code.descriptor()==r.mSpin->code.descriptor());
        }
        s.mB.reserve(s.mNoiseVecSize);r.mA.reserve(r.mNoiseVecSize);r.mC.reserve(r.mNoiseVecSize);
    }
    s.clear();r.clear();require(!s.mSpin && !r.mSpin);
    require(s.mB.capacity()==0 && r.mA.capacity()==0 && r.mC.capacity()==0);
    // configure() must not construct a huge encoder or its scratch.
    s.configure(1ull<<26,2,1,SilentSecType::SemiHonest,SdNoiseDistribution::Regular,MultType::Spin);
    r.configure(1ull<<26,2,1,SilentSecType::SemiHonest,SdNoiseDistribution::Regular,MultType::Spin);
    require(!s.mSpin && !r.mSpin && s.mB.capacity()==0 && r.mA.capacity()==0);
    s.clear();r.clear();
}
static void protocol(u64 requested,SdNoiseDistribution noise,ChoiceBitPacking packed,SilentSecType security) {
    auto sockets=cp::LocalAsyncSocket::makePair();
    SilentOtExtSender s;SilentOtExtReceiver r; PRNG ps(block(1,4)),pr(block(3,7));
    s.configure(requested,2,1,security,noise,MultType::Spin);
    r.configure(requested,2,1,security,noise,MultType::Spin);
    const auto spec=detail::spinProfile(requested);
    const auto k=spec.message_size;
    const auto p=spec.parameters;
    require(k>=requested && k-requested<spin::message_alignment(p));
    require(!s.mSpin && !r.mSpin);
    // Exercise both ordinary lazy setup and explicit member preparation.
    const bool prepared=packed==ChoiceBitPacking::False;
    if(prepared) {
        s.mCodeSeed=r.mCodeSeed=block(41,59);
        s.mSpin=std::make_unique<SpinOtState>(requested,s.mCodeSeed,false,noise);
        r.mSpin=std::make_unique<SpinOtState>(requested,r.mCodeSeed,true,noise);
    }
    // Owned allocations can be moved in or reserved directly after configure.
    AlignedUnVector<block> supplied;supplied.reserve(s.mNoiseVecSize);
    const auto* suppliedPtr=supplied.data();
    s.mB=std::move(supplied);
    require(s.mB.data()==suppliedPtr);
    r.mA.reserve(r.mNoiseVecSize);r.mC.reserve(r.mNoiseVecSize);
    const auto* aPtr=r.mA.data();const auto* cPtr=r.mC.data();
    const auto bCapacity=s.mB.capacity(),aCapacity=r.mA.capacity(),cCapacity=r.mC.capacity();
    require(s.mNoiseVecSize==2*k && s.mNumPartitions*s.mSizePer<=2*k);
    const auto pad=2*k-s.mNumPartitions*s.mSizePer;
    // Check the heuristic configuration formula, not a distance certificate.
    const double effective=(std::floor(0.25*2*k)-pad)/(2*k-pad);
    require(-double(s.mNumPartitions)*std::log2(1-(noise==SdNoiseDistribution::Regular?2:1)*effective)>=128);
    if(noise==SdNoiseDistribution::Regular) require(s.mNumPartitions==128 && pad==0);
    decltype(s.mSpin->code.descriptor()) previous{};
    for(unsigned batch=0;batch<3;++batch) {
        if(batch==2) s.mCodeSeed=r.mCodeSeed=block(987,654);
        const auto currentSeed=s.mCodeSeed;
        const auto* preparedSender=s.mSpin.get();const auto* preparedReceiver=r.mSpin.get();
        require(currentSeed==r.mCodeSeed);
        const block d=block(345,678)|OneBlock;
        base(s,r,ps,d);
        auto ts=s.silentSendInplace(d,requested,ps,sockets[0]);
        auto tr=r.silentReceiveInplace(requested,pr,sockets[1],packed);
        tests_libOTe::eval(ts,tr);
        require(s.mB.size()==requested && r.mA.size()==requested);
        require(s.mCodeSeed==(noise==SdNoiseDistribution::Stationary?mAesFixedKey.hashBlock(currentSeed):currentSeed));
        require(s.mB.data()==suppliedPtr && r.mA.data()==aPtr && r.mC.data()==cPtr);
        require(s.mB.capacity()==bCapacity && r.mA.capacity()==aCapacity && r.mC.capacity()==cCapacity);
        if(preparedSender) {
            require(s.mSpin.get()==preparedSender && r.mSpin.get()==preparedReceiver);
        }
        require(s.mSpin->code.code().setup_options().mode==
            (noise==SdNoiseDistribution::Stationary?spin::SetupMode::BankedHeuristic:spin::SetupMode::Full));
        require(s.mCodeSeed==r.mCodeSeed);
        require(s.mSpin->seed==currentSeed && r.mSpin->seed==currentSeed);
        require(s.mSpin->code.descriptor()==r.mSpin->code.descriptor());
        const auto realized=s.mSpin->code.code().specification();
        require(realized.route_seed==currentSeed.get<u64>(0));
        require(realized.inner_seed==currentSeed.get<u64>(1));
        if(batch) require((previous!=s.mSpin->code.descriptor())==
            (noise==SdNoiseDistribution::Stationary || batch==2));
        previous=s.mSpin->code.descriptor();
        for(u64 i=0;i<requested;++i) {
            auto c=packed==ChoiceBitPacking::True?(r.mA[i].get<u64>(0)&1):r.mC[i];
            auto a=r.mA[i],b=s.mB[i]^(c?d:ZeroBlock);
            if(packed==ChoiceBitPacking::True) {a=a&(AllOneBlock^OneBlock);b=b&(AllOneBlock^OneBlock);}
            require(a==b);
        }
    }
    if(k==65536 && noise==SdNoiseDistribution::Regular &&
       packed==ChoiceBitPacking::True && security==SilentSecType::SemiHonest) {
        base(s,r,ps,block(345,679));
        std::vector<std::array<block,2>> pairs(requested);
        std::vector<block> received(requested);BitVector choices(requested);
        auto ts=s.silentSend(pairs,ps,sockets[0]);
        auto tr=r.silentReceive(choices,received,pr,sockets[1]);
        tests_libOTe::eval(ts,tr);
        for(u64 i=0;i<requested;++i) require(received[i]==pairs[i][choices[i]]);
    }
    s.clear();r.clear();require(!s.mSpin && !r.mSpin);
    require(s.mB.capacity()==0 && r.mA.capacity()==0 && r.mC.capacity()==0);
}
static void hashStoreModes() {
    // Force a 16-byte offset from 32-byte alignment and cover every tail.
    struct alignas(32) Output {block guard;std::array<block,2> data[34];};
    Output output{};
    require(reinterpret_cast<std::uintptr_t>(output.data)%32==16);
    for(u64 n=0;n<=33;++n) for(bool streaming:{false,true}) {
        SilentOtExtSender s;
        s.mRequestNumOts=n;s.mDelta=block(345,679);s.mB.resize(n);
        output.guard=block(123);output.data[n]={block(123),block(456)};
        for(u64 i=0;i<n;++i)s.mB[i]=block(7*i+1,13*i+4);
        s.hash({output.data,n},ChoiceBitPacking::True,streaming);
        const auto mask=AllOneBlock^OneBlock;
        for(u64 i=0;i<n;++i) {
            const auto x=block(7*i+1,13*i+4);
            require(output.data[i][0]==mAesFixedKey.hashBlock(x&mask));
            require(output.data[i][1]==mAesFixedKey.hashBlock((x^*s.mDelta)&mask));
        }
        require(output.guard==block(123) && output.data[n][0]==block(123) && output.data[n][1]==block(456));
    }
}
} // namespace

void tests_libOTe::Spin_Integration_Test() {
    hashStoreModes();
    if(!spin::capabilities().avx2) throw UnitTestSkipped("SPIN requires AVX2");
    arithmetic();
    lifecycle();
    rejects([&]{detail::spinProfile(0);});
    rejects([&]{detail::spinProfile(u64(1)<<31);});
    for(u64 requested:{1ull,4096ull,8191ull,8192ull,8193ull}) {
        const auto spec=detail::spinProfile(requested);
        require(spec.message_size==(requested<=8192?8192:16384));
        require(spec.parameters==spin::Parameters::T64S12R2);
    }
    for(u64 requested:{1ull,4096ull,8191ull,8192ull,8193ull,24539ull,65499ull,65537ull,131072ull,262107ull})
        for(auto packed:{ChoiceBitPacking::False,ChoiceBitPacking::True})
            protocol(requested,SdNoiseDistribution::Regular,packed,SilentSecType::SemiHonest);
    // Large configuration tests do not allocate encoder buffers.
    for(u64 requested:{1ull,4096ull,8191ull,8192ull,8193ull,24539ull,65536ull,65537ull,(1ull<<24)+1,1ull<<26,(1ull<<31)-16384}) {
        const auto spec=detail::spinProfile(requested);
        for(auto noise:{SdNoiseDistribution::Regular,SdNoiseDistribution::Stationary}) {
            auto cfg=syndromeDecodingConfigure(128,requested,MultType::Spin,noise,1);
            const auto n=cfg.mNoiseVectorSize,active=cfg.mNumPartitions*cfg.mSizePer;
            require(n==2*spec.message_size && active<=n && active>0);
            const double effective=(double(n/4)-double(n-active))/double(active);
            require(effective>0 && effective<0.5);
            require(-double(cfg.mNumPartitions)*std::log2(1-(noise==SdNoiseDistribution::Regular?2:1)*effective)>=128);
            if(noise==SdNoiseDistribution::Regular) require(cfg.mNumPartitions==128 && active==n);
        }
    }
    for(auto packed:{ChoiceBitPacking::False,ChoiceBitPacking::True}) {
        protocol(65536,SdNoiseDistribution::Stationary,packed,SilentSecType::SemiHonest);
        for(u64 requested:{1ull,8193ull,65537ull,262107ull})
            protocol(requested,SdNoiseDistribution::Stationary,packed,SilentSecType::SemiHonest);
        protocol(65537,SdNoiseDistribution::Stationary,packed,SilentSecType::Malicious);
        protocol(65536,SdNoiseDistribution::Regular,packed,SilentSecType::Malicious);
    }
}
#else
void tests_libOTe::Spin_Integration_Test() {
    throw osuCrypto::UnitTestSkipped("SPIN or Silent OT is disabled");
}
#endif

#include "SpinOt.h"
#ifdef ENABLE_SPIN
#include <algorithm>
#include <cmath>
#include <cstring>
#if defined(__BMI2__)
#include <immintrin.h>
#endif
namespace osuCrypto {
namespace detail {
spin::CodeSpec spinProfile(u64 requested,block seed) {
    // Turbo SPIN at every natural size (a positive multiple of 128); requests
    // round up to the next one. Small requests share K=8192 so the noise
    // configuration has room for its partitions; this floor is not tied to
    // any distance certificate. Truncate only after encoding.
    constexpr u64 minimumK=8192;
    constexpr auto parameters=spin::Parameters::PacketRs8T64;
    const u64 alignment=spin::message_alignment(parameters);
    if(!requested || requested>(u64(1)<<40))
        throw std::invalid_argument("SPIN OT request exceeds the largest Turbo code");
    const u64 k=roundUpTo(std::max(requested,minimumK),alignment);
    if(!spin::valid_message_size(parameters,k))
        throw std::invalid_argument("SPIN OT request exceeds the largest Turbo code");
    return {k,parameters,seed.get<u64>(0),seed.get<u64>(1)};
}
}

SdConfig SpinConfigure(u64 secParam,u64 requested,SdNoiseDistribution noise) {
    const u64 n=2*detail::spinProfile(requested).message_size;
    if(secParam>1024 || (noise!=SdNoiseDistribution::Regular && noise!=SdNoiseDistribution::Stationary))
        throw std::invalid_argument("Invalid SPIN noise configuration");
    // Same effective linear-attack tuning value as BAA. This is not a claim
    // of 25% minimum distance; the N/10 certificates are separate evidence.
    constexpr double linearAttackTuning=0.25;
    const double fullEffectiveWeight=std::floor(linearAttackTuning*double(n));
    const double multiplier=noise==SdNoiseDistribution::Regular?2:1;
    const double minimumParts=std::ceil(double(secParam)/-std::log2(1-multiplier*fullEffectiveWeight/n));
    const u64 first=std::max<u64>(40,roundUpTo(u64(minimumParts),8));
    const u64 last=std::min<u64>(n/4,first+8192);
    // Retain a conservative tail adjustment within this heuristic model.
    for(u64 parts=first;parts<=last;parts+=8) {
        const u64 per=(n/parts)&~u64(1),active=parts*per,pad=n-active;
        const double effectiveWeight=fullEffectiveWeight-double(pad);
        if(effectiveWeight<=0) continue;
        const double ratio=effectiveWeight/double(active);
        if(ratio>=0.5) continue;
        if(-double(parts)*std::log2(1-multiplier*ratio)>=secParam)
            return {n,parts,per};
    }
    throw std::invalid_argument("SPIN noise configuration has no supported solution");
}

static spin::SetupOptions spinSetup(SdNoiseDistribution noise) {
    if(noise!=SdNoiseDistribution::Regular && noise!=SdNoiseDistribution::Stationary)
        throw std::invalid_argument("Invalid SPIN noise configuration");
    return {noise==SdNoiseDistribution::Stationary?spin::SetupMode::BankedHeuristic:spin::SetupMode::Full};
}
SpinOtState::SpinOtState(u64 requested,block codeSeed,bool receiver,SdNoiseDistribution noise)
    :seed(codeSeed),code(detail::spinProfile(requested,codeSeed),{},spinSetup(noise)),blocks(code.make_workspace<block>()) {
    if(receiver) choices.emplace(code.code().make_bit_workspace());
}
void prepareSpin(std::unique_ptr<SpinOtState>& state,u64 requested,block seed,bool receiver,SdNoiseDistribution noise) {
    const auto spec=detail::spinProfile(requested,seed);
    const auto mode=spinSetup(noise).mode;
    if(!state || state->code.messageSize()!=spec.message_size ||
       state->code.code().specification().parameters!=spec.parameters ||
       state->code.code().setup_options().mode!=mode || state->choices.has_value()!=receiver)
        state=std::make_unique<SpinOtState>(requested,seed,receiver,noise);
    else {state->code.setCodeSeed(seed);state->seed=seed;}
}
void SpinOtState::transpose(span<block> x) {code.transpose_inplace<block>(x,blocks);}
namespace {
// Gather bit p of eight bytes into one byte, and spread it back.
inline u64 gather8(u64 v,unsigned p) {
#if defined(__BMI2__)
    return _pext_u64(v,0x0101010101010101ull<<p);
#else
    u64 r=0;for(unsigned j=0;j<8;++j) r|=((v>>(8*j+p))&1)<<j;return r;
#endif
}
inline u64 spread8(u64 bits,unsigned p) {
#if defined(__BMI2__)
    return _pdep_u64(bits,0x0101010101010101ull)<<p;
#else
    u64 r=0;for(unsigned j=0;j<8;++j) r|=((bits>>j)&1)<<(8*j+p);return r;
#endif
}
}
void SpinOtState::transpose(span<u8> x) {
    if(!choices) throw std::logic_error("SPIN choice workspace was not prepared");
    const auto& enc=code.code();
    const u64 n=enc.code_size(),k=enc.message_size(),inWords=n/64,outWords=k/64;
    if(x.size()!=n) throw std::invalid_argument("SPIN choice transpose needs 2K bytes");
    // Each byte is eight independent bit lanes of the binary map. Only the bit
    // planes present are transposed; 0/1 choice bytes need one bit transpose.
    u8 any=0;
    for(u64 i=0;i<n;++i) any|=x[i];
    unsigned planes[8],count=0;
    for(unsigned p=0;p<8;++p) if((any>>p)&1U) planes[count++]=p;
    // Reuses its capacity across batches; allocates only on first use or growth.
    choiceIn.resize(count*inWords);choiceOut.resize(count*outWords);
    for(u64 w=0;w<inWords;++w)
        for(unsigned c=0;c<8;++c) {
            u64 v;std::memcpy(&v,x.data()+64*w+8*c,8);
            for(unsigned q=0;q<count;++q) {
                auto& word=choiceIn[q*inWords+w];
                if(!c) word=0;
                word|=gather8(v,planes[q])<<(8*c);
            }
        }
    for(unsigned q=0;q<count;++q)
        enc.transpose_bits(span<const u64>(choiceIn.data()+q*inWords,inWords),
                           span<u64>(choiceOut.data()+q*outWords,outWords),*choices);
    // In-place contract: the first K entries receive the result, the rest are unchanged.
    for(u64 i=0;i<k;i+=8) {
        u64 v=0;
        for(unsigned q=0;q<count;++q)
            v|=spread8((choiceOut[q*outWords+i/64]>>(i%64))&255U,planes[q]);
        std::memcpy(x.data()+i,&v,8);
    }
}
}
#endif

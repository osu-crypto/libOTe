#include "SpinOt.h"
#ifdef ENABLE_SPIN
#include <algorithm>
#include <cmath>
namespace osuCrypto {
namespace detail {
spin::CodeSpec spinProfile(u64 requested,block seed) {
    // Small requests share the smallest natural code; truncate only after encoding.
    constexpr u64 minimumK=8192;
    // Separate distance certificates at 10%: K16, margin >=49.32 bits.
    // K18/20/22/24: T128S19, margins >=50.18/50.06/48.39/46.45 bits.
    // Other natural lengths are allowed without a size-specific certificate.
    const auto parameters=requested<=(u64(1)<<16)?
        spin::Parameters::T64S12R2:spin::Parameters::T128S19;
    const u64 alignment=spin::message_alignment(parameters);
    const u64 maxK=((u64(1)<<31)-1)/alignment*alignment;
    if(!requested || requested>maxK)
        throw std::invalid_argument("SPIN OT request exceeds the routing representation");
    return {roundUpTo(std::max(requested,minimumK),alignment),parameters,seed.get<u64>(0),seed.get<u64>(1)};
}
}

SdConfig SpinConfigure(u64 secParam,u64 requested,SdNoiseDistribution noise) {
    const u64 n=2*detail::spinProfile(requested).message_size;
    if(secParam>1024 || (noise!=SdNoiseDistribution::Regular && noise!=SdNoiseDistribution::Stationary))
        throw std::invalid_argument("Invalid SPIN noise configuration");
    // Same effective linear-attack tuning value as BAA. This is not a claim
    // of 25% minimum distance; the 10% certificates are separate evidence.
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

SpinOtState::SpinOtState(u64 requested,block codeSeed,bool receiver)
    :seed(codeSeed),code(detail::spinProfile(requested,codeSeed)),blocks(code.make_workspace<block>()) {
    if(receiver) choices.emplace(code.make_workspace<u8>());
}
void prepareSpin(std::unique_ptr<SpinOtState>& state,u64 requested,block seed,bool receiver) {
    const auto spec=detail::spinProfile(requested,seed);
    if(!state || state->seed!=seed || state->code.messageSize()!=spec.message_size ||
       state->code.code().specification().parameters!=spec.parameters ||
       state->choices.has_value()!=receiver)
        state=std::make_unique<SpinOtState>(requested,seed,receiver);
}
void SpinOtState::transpose(span<block> x) {code.transpose_inplace<block>(x,blocks);}
void SpinOtState::transpose(span<u8> x) {
    if(!choices) throw std::logic_error("SPIN choice workspace was not prepared");
    code.transpose_inplace<u8>(x,*choices);
}
}
#endif

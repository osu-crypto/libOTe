#include "SpinOt.h"
#ifdef ENABLE_SPIN
#include <algorithm>
#include <cmath>
namespace osuCrypto {
namespace detail {
spin::CodeSpec spinProfile(u64 requested,block seed) {
    // Turbo SPIN. Under uniform setup its minimum distance exceeds N/10 at
    // K=2^14,2^16,...,2^26 (Lean-certified; setup-failure margins 64.25 to
    // 52.32 bits). Small requests share the smallest certified code; others
    // round up to the next natural size (a multiple of 128), which has no
    // size-specific certificate. Truncate only after encoding.
    constexpr u64 minimumK=u64(1)<<14;
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
    if(receiver) choices.emplace(code.make_workspace<block>());
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
void SpinOtState::transpose(span<u8> x) {
    if(!choices) throw std::logic_error("SPIN choice workspace was not prepared");
    // Reuses its capacity across batches; allocates only on first use or growth.
    choiceLift.resize(x.size());
    for(u64 i=0;i<x.size();++i) choiceLift[i]=block(0,x[i]);
    code.transpose_inplace<block>(choiceLift,*choices);
    // In-place contract: the first K entries receive the result, the rest are unchanged.
    for(u64 i=0,k=code.messageSize();i<k;++i) x[i]=choiceLift[i].get<u8>(0);
}
}
#endif

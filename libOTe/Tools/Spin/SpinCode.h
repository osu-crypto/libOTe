#pragma once
#include "libOTe/config.h"
#ifdef ENABLE_SPIN
#include "libOTe/Tools/CoeffCtx.h"
#include <spin/Code.h>
#include <spin/PreparedEncoder.h>
#include <type_traits>

namespace osuCrypto {
// Binary SPIN map, with libOTe coefficient contexts at the arithmetic boundary.
// No field multiplication or weighting is performed by this encoder.
class SpinCode {
    spin::PreparedEncoder mCode;
    template<class F,class Ctx> static constexpr bool native =
        std::is_same_v<F,block> && (std::is_same_v<Ctx,CoeffCtxGF2> ||
                                   std::is_same_v<Ctx,CoeffCtxGF128>);
public:
    explicit SpinCode(spin::CodeSpec spec,spin::ExecutionOptions options={},spin::SetupOptions setup={}) : mCode(spec,setup,options) {}
    void setCodeSeed(block seed) {mCode.setCodeSeed({seed.get<u64>(0),seed.get<u64>(1)});}
    u64 messageSize() const {return mCode.message_size();}
    u64 codeSize() const {return mCode.code_size();}
    auto descriptor() const {return mCode.descriptor();}
    const spin::PreparedEncoder& code() const {return mCode;}

    // Turbo SPIN transposes 128-bit records only. Other element types and
    // coefficient contexts are rejected at runtime (std::invalid_argument);
    // narrower binary values can travel in the low bits of a block.
    template<class F,class Ctx=CoeffCtxGF2>
    using Workspace = spin::PreparedEncoder::Workspace;

    template<class F,class Ctx=CoeffCtxGF2> Workspace<F,Ctx> make_workspace(Ctx ctx={}) const {
        if(!ctx.template characteristicTwo<F>())
            throw std::invalid_argument("SPIN requires characteristic-two addition");
        if constexpr(native<F,Ctx>) return mCode.make_workspace();
        else throw std::invalid_argument("SPIN transposes 128-bit block records only");
    }
    template<class F,class Ctx=CoeffCtxGF2>
    void transpose_inplace(span<F> buffer,Workspace<F,Ctx>& w) const {
        static_assert(native<F,Ctx>,"SPIN transposes 128-bit block records only");
        mCode.transpose_inplace<F>(std::span<F>(buffer.data(),buffer.size()),w);
    }
};
}
#endif

#pragma once
#include "libOTe/config.h"
#ifdef ENABLE_SPIN
#include "libOTe/Tools/CoeffCtx.h"
#include <spin/Code.h>
#include <spin/Generic.h>
#include <type_traits>

namespace osuCrypto {
// Binary SPIN map, with libOTe coefficient contexts at the arithmetic boundary.
// No field multiplication or weighting is performed by this encoder.
class SpinCode {
    spin::Code mCode;
    template<class F,class Ctx> static constexpr bool native =
        std::is_same_v<F,block> && (std::is_same_v<Ctx,CoeffCtxGF2> ||
                                   std::is_same_v<Ctx,CoeffCtxGF128>);
public:
    explicit SpinCode(spin::CodeSpec spec,spin::ExecutionOptions options={}) : mCode(spec,options) {}
    u64 messageSize() const {return mCode.message_size();}
    u64 codeSize() const {return mCode.code_size();}
    auto descriptor() const {return mCode.descriptor();}
    const spin::Code& code() const {return mCode;}

    template<class F,class Ctx> class GenericWorkspace {
        friend class SpinCode;
        Ctx ctx;
        std::array<std::byte,40> descriptor;
        spin::GenericTranspose plan;
        spin::GenericTranspose::Workspace<F> scratch;
        GenericWorkspace(const spin::Code& code,Ctx c)
            :ctx(std::move(c)),descriptor(code.descriptor()),plan(code.generic_transpose()),scratch(plan.template make_workspace<F>()) {}
    public:
        GenericWorkspace(GenericWorkspace&& other)
            :ctx(std::move(other.ctx)),descriptor(other.descriptor),
             plan(other.plan),scratch(std::move(other.scratch)) {}
        GenericWorkspace& operator=(GenericWorkspace&& other) {
            if(this!=&other) {
                ctx=std::move(other.ctx);descriptor=other.descriptor;
                plan=other.plan;scratch=std::move(other.scratch);
            }
            return *this;
        }
        GenericWorkspace(const GenericWorkspace&)=delete;
    };
    template<class F,class Ctx=CoeffCtxGF2>
    using Workspace = std::conditional_t<native<F,Ctx>,spin::Workspace,GenericWorkspace<F,Ctx>>;

    template<class F,class Ctx=CoeffCtxGF2> Workspace<F,Ctx> make_workspace(Ctx ctx={}) const {
        if(!ctx.template characteristicTwo<F>())
            throw std::invalid_argument("SPIN requires characteristic-two addition");
        if constexpr(native<F,Ctx>) return mCode.make_workspace();
        else return GenericWorkspace<F,Ctx>(mCode,std::move(ctx));
    }
    template<class F,class Ctx=CoeffCtxGF2>
    void transpose_inplace(span<F> buffer,Workspace<F,Ctx>& w) const {
        if constexpr(native<F,Ctx>)
            mCode.transpose_inplace<F>(std::span<F>(buffer.data(),buffer.size()),w);
        else {
            if(w.plan.message_size()!=messageSize() || w.descriptor!=descriptor())
                throw std::invalid_argument("SPIN coefficient workspace belongs to another map");
            auto plus=[&](const F& a,const F& b) {
                auto r=w.ctx.template make<F>(); w.ctx.plus(r,a,b); return r;
            };
            w.plan.template transpose_inplace<F>(std::span<F>(buffer.data(),buffer.size()),w.scratch,plus);
        }
    }
};
}
#endif

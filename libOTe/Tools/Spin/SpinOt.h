#pragma once
#include "libOTe/Tools/Spin/SpinCode.h"
#include "libOTe/TwoChooseOne/ConfigureCode.h"
#ifdef ENABLE_SPIN
#include <memory>
#include <optional>
namespace osuCrypto {
namespace detail {
// Internal parameter policy; not an additional caller configuration.
spin::CodeSpec spinProfile(u64 requested,block seed=ZeroBlock);
}

// Own scratch outside protocol coroutine frames. Rebuild when setup changes.
struct SpinOtState {
    block seed;
    SpinCode code;
    SpinCode::Workspace<block> blocks;
    std::optional<SpinCode::Workspace<u8>> choices;
    SpinOtState(u64 requested,block codeSeed,bool receiver);
    void transpose(span<block> x);
    void transpose(span<u8> x);
};
void prepareSpin(std::unique_ptr<SpinOtState>& state,u64 requested,block seed,bool receiver);
}
#endif

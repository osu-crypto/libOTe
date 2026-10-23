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

// Optional caller-prepared member state. Construct after configure(), using
// the same mCodeSeed on both parties. Own scratch outside coroutine frames.
// prepareSpin reuses this object when its geometry, setup mode and role match.
// clear() releases it; no process-wide cache retains setup or allocations.
struct SpinOtState {
    block seed;
    SpinCode code;
    SpinCode::Workspace<block> blocks;
    std::optional<SpinCode::Workspace<u8>> choices;
    SpinOtState(u64 requested,block codeSeed,bool receiver,
        SdNoiseDistribution noise=SdNoiseDistribution::Regular);
    void transpose(span<block> x);
    void transpose(span<u8> x);
};
void prepareSpin(std::unique_ptr<SpinOtState>& state,u64 requested,block seed,bool receiver,
    SdNoiseDistribution noise=SdNoiseDistribution::Regular);
}
#endif

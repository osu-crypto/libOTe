#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Matrix.h"

namespace ldpc
{

    using u64 = oc::u64;
    using u32 = oc::u32;
    using u16 = oc::u16;
    using u8 = oc::u8;
    using i64 = oc::i64;
    using i32 = oc::i32;
    using i16 = oc::i16;
    using i8 = oc::i8;

    template<typename T> using span = gsl::span<T>;
    template<typename T> using Matrix = oc::Matrix<T>;

    using block = oc::block;
#ifdef ENABLE_RELIC
    static_assert(0, "relic not supported");
#endif

}
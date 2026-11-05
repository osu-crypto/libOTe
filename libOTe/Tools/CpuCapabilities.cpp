#include "libOTe/Tools/CpuCapabilities.h"
#include "cryptoTools/Common/config.h"

namespace osuCrypto
{
    CpuCapabilities::CpuCapabilities(Mode mode)
    {
#if defined(OC_ENABLE_AVX512_IFMA) && defined(OC_COMPILER_HAS_AVX512_IFMA_DISPATCH)
        if (mode == Mode::Automatic)
        {
            mAvx512 = __builtin_cpu_supports("avx512f") &&
                __builtin_cpu_supports("avx512dq");
            mIfma = mAvx512 && __builtin_cpu_supports("avx512ifma");
        }
#else
        (void)mode;
#endif
    }
}

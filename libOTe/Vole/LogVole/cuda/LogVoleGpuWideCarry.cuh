#pragma once

#include <cuda_runtime.h>
#include "libOTe/Vole/LogVole/cuda/LogVoleGpuArith.cuh"

namespace osuCrypto::LogVole::gpu
{
    // Exact modulo-2^128 carry chains. Temporary PTX registers ensure neither
    // output can overwrite a still-live input under inline-asm allocation.
    __device__ __forceinline__ Wide wideAddCarry(Wide a, Wide b)
    {
        Wide r;
        asm("{ .reg .u64 lo, hi;\n"
            "add.cc.u64 lo, %2, %4;\n"
            "addc.u64 hi, %3, %5;\n"
            "mov.u64 %0, lo; mov.u64 %1, hi; }"
            : "=l"(r.mLo), "=l"(r.mHi)
            : "l"(a.mLo), "l"(a.mHi), "l"(b.mLo), "l"(b.mHi));
        return r;
    }

    __device__ __forceinline__ Wide wideSubCarry(Wide a, Wide b)
    {
        Wide r;
        asm("{ .reg .u64 lo, hi;\n"
            "sub.cc.u64 lo, %2, %4;\n"
            "subc.u64 hi, %3, %5;\n"
            "mov.u64 %0, lo; mov.u64 %1, hi; }"
            : "=l"(r.mLo), "=l"(r.mHi)
            : "l"(a.mLo), "l"(a.mHi), "l"(b.mLo), "l"(b.mHi));
        return r;
    }
}
